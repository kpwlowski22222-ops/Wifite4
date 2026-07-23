#!/usr/bin/env python3
"""
Enhanced BLE Scanner
=====================
Real Bluetooth Low Energy scanning optimised for **maximum discovery range**.

Backends (results are **merged**, not fail-over-only):
  1. ``bleak`` — preferred (RSSI + service UUIDs + active scan)
  2. ``bluetoothctl`` — BlueZ interactive scan
  3. ``hcitool lescan --duplicates`` — legacy fallback

If no BLE tooling is available, returns an empty result with an explicit
error — never random fake devices.

Before each scan, best-effort adapter prep:
  * rfkill unblock
  * power on / LE on
  * LE Coded PHY when the controller supports it (long-range)
  * 100% duty-cycle LE scan parameters (window = interval = 0x4000)

AI risk assessment is intentionally NOT done here. The owning screen routes
device descriptions through ``AIBackend.query("ble", ...)`` when asked.
"""

from __future__ import annotations

import logging
import re
import shutil
import subprocess
import time
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


def _norm_addr(addr: str) -> str:
    return (addr or "").strip().upper()


def _merge_device(
    catalog: Dict[str, Dict[str, Any]], entry: Dict[str, Any]
) -> None:
    """Merge a discovery into *catalog* keeping strongest RSSI + best name."""
    addr = _norm_addr(entry.get("address") or "")
    if not addr or len(addr) < 11:
        return
    entry = dict(entry)
    entry["address"] = addr
    # Seed seen_by from backend on first insert
    backends0 = set(entry.get("seen_by") or [])
    if entry.get("backend"):
        backends0.add(entry["backend"])
    entry["seen_by"] = sorted(backends0) if backends0 else []
    prev = catalog.get(addr)
    if prev is None:
        catalog[addr] = entry
        return
    # Strongest RSSI wins for the primary observation
    pr = prev.get("rssi")
    nr = entry.get("rssi")
    if nr is not None and (pr is None or nr > pr):
        prev["rssi"] = nr
    # Prefer real names over Unknown
    nname = entry.get("name") or ""
    pname = prev.get("name") or ""
    if nname and nname != "Unknown" and (
        not pname or pname == "Unknown"
    ):
        prev["name"] = nname
    # Union service UUIDs
    services = list(prev.get("services") or [])
    for s in entry.get("services") or []:
        if s not in services:
            services.append(s)
    prev["services"] = services
    # Prefer non-empty manufacturer / tx_power / address_type
    for k in ("manufacturer_data", "tx_power", "address_type", "device_id"):
        if entry.get(k) not in (None, "", [], {}) and not prev.get(k):
            prev[k] = entry[k]
    # Track which backends heard this device
    backends = set(prev.get("seen_by") or [])
    for b in entry.get("seen_by") or []:
        backends.add(b)
    if entry.get("backend"):
        backends.add(entry["backend"])
    prev["seen_by"] = sorted(backends)


class EnhancedBLEScanner:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.is_initialized = False
        self.scan_results: Dict[str, Any] = {}
        self.active_scans: Dict[str, Any] = {}

    def initialize(self):
        self.is_initialized = True
        return True

    # ------------------------------------------------------------------
    # Scan — real backends, no fake devices
    # ------------------------------------------------------------------
    def scan(
        self,
        duration: int = None,
        adapter: str = None,
        *,
        prep: bool = True,
    ) -> Dict[str, Any]:
        """Long-range BLE discovery scan with multi-backend merge.

        Duration defaults to ``DEFAULT_BLE_SCAN_S`` (300s), ceiling
        ``MAX_SCAN_S`` (3600s). Before scanning, best-effort adapter
        prep maximises RX sensitivity and duty cycle unless
        ``prep=False`` (live TUI re-pulses skip re-prep).
        """
        from core.scanners.scan_limits import ble_scan_s

        if not self.is_initialized:
            return {"error": "BLE scanner not initialized"}

        scan_id = f"ble_scan_{int(time.time())}"
        cap = ble_scan_s(duration)
        self.logger.info("BLE long-range scan %s for %ss", scan_id, cap)
        prep_notes: List[str] = []
        if prep:
            prep_notes = self._prep_adapter_long_range(adapter)

        catalog: Dict[str, Dict[str, Any]] = {}
        attempted: List[str] = []
        backend_errors: Dict[str, str] = {}

        # Backend budget: primary (bleak if present, else bluetoothctl)
        # gets the full *cap*. Secondary backends get a short merge pass
        # that never exceeds remaining time so short pulses stay snappy
        # (external live TUI) while long scans still multi-merge.
        has_bleak = self._bleak_available()
        has_btctl = bool(shutil.which("bluetoothctl"))
        has_hci = bool(shutil.which("hcitool"))

        # Secondary pass length: up to 1/3 of cap, floored for usefulness
        # on long scans, but never larger than *cap* itself.
        def _secondary(frac: float, floor: int) -> int:
            if cap <= 4:
                return max(2, min(cap, 3))  # short pulse: tiny merge window
            return max(floor, min(cap, int(cap * frac)))

        btctl_s = _secondary(0.35, 8) if has_btctl else 0
        hci_s = _secondary(0.25, 6) if has_hci else 0

        # 1) bleak (preferred — RSSI + service UUIDs + active mode)
        if has_bleak:
            try:
                dev, back = self._bleak_scan(cap, adapter)
                if back and not str(back).endswith("unavailable"):
                    attempted.append(back)
                if back and str(back).endswith("error"):
                    backend_errors["bleak"] = "runtime error"
                for d in dev or []:
                    d = dict(d)
                    d["backend"] = "bleak"
                    d["seen_by"] = ["bleak"]
                    _merge_device(catalog, d)
            except Exception as e:
                self.logger.debug("bleak scan failed: %s", e)
                attempted.append("bleak")
                backend_errors["bleak"] = str(e)[:160]

        # 2) bluetoothctl — primary if no bleak, else secondary merge pass
        if has_btctl:
            use_s = cap if not has_bleak else (btctl_s if catalog else min(cap, btctl_s or cap))
            # No bleak + empty: full window. With bleak: short merge.
            if not has_bleak:
                use_s = cap
            else:
                use_s = min(cap, max(2, btctl_s))
            try:
                dev, back = self._bluetoothctl_scan(use_s, adapter)
                if back and not str(back).endswith("unavailable"):
                    attempted.append(back)
                if back and str(back).endswith("error"):
                    backend_errors["bluetoothctl"] = "runtime error"
                for d in dev or []:
                    d = dict(d)
                    d["backend"] = "bluetoothctl"
                    d["seen_by"] = ["bluetoothctl"]
                    _merge_device(catalog, d)
            except Exception as e:
                self.logger.debug("bluetoothctl scan failed: %s", e)
                attempted.append("bluetoothctl")
                backend_errors["bluetoothctl"] = str(e)[:160]

        # 3) hcitool lescan — merge weak/legacy ads (always short secondary)
        if has_hci:
            # Only spend full cap on hcitool when it's the sole backend
            if not has_bleak and not has_btctl:
                use_s = cap
            else:
                use_s = min(cap, max(2, hci_s))
            try:
                dev, back = self._hcitool_scan(use_s, adapter)
                if back and not str(back).endswith("unavailable"):
                    attempted.append(back)
                if back and str(back).endswith("error"):
                    backend_errors["hcitool"] = "runtime error"
                for d in dev or []:
                    d = dict(d)
                    d["backend"] = "hcitool"
                    d["seen_by"] = ["hcitool"]
                    _merge_device(catalog, d)
            except Exception as e:
                self.logger.debug("hcitool scan failed: %s", e)
                attempted.append("hcitool")
                backend_errors["hcitool"] = str(e)[:160]

        # Clean attempted list
        _clean = {
            "bleak": "bleak", "bleak-error": "bleak",
            "bleak-unavailable": None,
            "bluetoothctl": "bluetoothctl", "bluetoothctl-error": "bluetoothctl",
            "bluetoothctl-unavailable": None,
            "hcitool": "hcitool", "hcitool-error": "hcitool",
            "hcitool-unavailable": None,
        }
        cleaned: List[str] = []
        seen_b: set = set()
        for b in attempted:
            name = _clean.get(b, b)
            if name and name not in seen_b:
                seen_b.add(name)
                cleaned.append(name)
        attempted = cleaned

        devices = sorted(
            catalog.values(),
            key=lambda x: -(x.get("rssi") if x.get("rssi") is not None else -999),
        )
        # Primary backend label: first that contributed
        backend = "none"
        for d in devices:
            if d.get("backend"):
                backend = d["backend"]
                break
        if devices and len(attempted) > 1:
            backend = "merged:" + "+".join(attempted)

        result: Dict[str, Any] = {
            "timestamp": self._get_timestamp(),
            "duration": cap,
            "devices": devices,
            "total_found": len(devices),
            "backend": backend,
            "backends_tried": attempted,
            "adapter": adapter,
            "prep_notes": prep_notes,
        }
        if backend_errors:
            result["backend_errors"] = backend_errors
        if not devices:
            if attempted:
                result["error"] = (
                    f"no BLE devices found in {cap}s "
                    f"(backends tried: {', '.join(attempted)}). "
                    f"Is a Bluetooth controller powered on and in range?"
                )
            else:
                result["error"] = (
                    "no BLE tooling available — install bleak "
                    "(`pip install bleak`) or bluez (bluetoothctl/hcitool)"
                )
        self.scan_results[scan_id] = result
        return result

    def scan_once(
        self, duration: int = 6, adapter: str = None
    ) -> Dict[str, Any]:
        """Short discovery pulse for live external TUI loops.

        Still runs adapter prep and multi-backend merge, but uses a short
        duration so the UI can refresh frequently.
        """
        return self.scan(duration=max(2, int(duration)), adapter=adapter)

    # ------------------------------------------------------------------
    # Adapter long-range prep
    # ------------------------------------------------------------------
    @staticmethod
    def _run_quick(cmd: List[str], timeout_s: float = 2.0) -> int:
        """Run *cmd* with a hard wall-clock timeout (never hang the TUI).

        Prefers the system ``timeout`` binary so stuck BlueZ tools
        (``btmgmt advertising off`` has been observed to block forever
        waiting on D-Bus) are SIGKILL'd even if Python's
        ``subprocess`` timeout is slow to fire.
        """
        try:
            if shutil.which("timeout"):
                # --signal=KILL after grace; -k 1s after TERM
                wrapped = [
                    "timeout", "-k", "1s", f"{max(1, int(timeout_s))}s",
                ] + list(cmd)
                p = subprocess.run(
                    wrapped, capture_output=True, text=True,
                    timeout=timeout_s + 2,
                )
            else:
                p = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=timeout_s,
                )
            return int(p.returncode)
        except Exception:  # noqa: BLE001
            return -1

    def _prep_adapter_long_range(self, adapter: str = None) -> List[str]:
        """Best-effort: unblock + power + LE + Coded PHY + max scan duty.

        Soft-blocked Bluetooth (common after laptop suspend / airplane
        mode) makes every backend return empty. Failures are silent —
        backends still try their normal paths. Returns operator-facing notes.

        Every external command is hard-capped so prep never blocks a
        live TUI pulse for more than a few seconds total.
        """
        notes: List[str] = []

        # Unblock soft rfkill on Bluetooth.
        if shutil.which("rfkill"):
            for what in ("bluetooth", "hci"):
                self._run_quick(["rfkill", "unblock", what], 2)
            try:
                p = subprocess.run(
                    ["timeout", "2s", "rfkill", "list"],
                    capture_output=True, text=True, timeout=3,
                ) if shutil.which("timeout") else subprocess.run(
                    ["rfkill", "list"],
                    capture_output=True, text=True, timeout=2,
                )
                for line in (p.stdout or "").splitlines():
                    if "Bluetooth" in line or "hci" in line.lower():
                        idx = line.split(":", 1)[0].strip()
                        if idx.isdigit():
                            self._run_quick(["rfkill", "unblock", idx], 2)
                notes.append("rfkill: bluetooth unblocked")
            except Exception:  # noqa: BLE001
                pass

        # bluetoothctl power on (short) — most reliable non-root path
        if shutil.which("bluetoothctl"):
            rc = self._run_quick(["bluetoothctl", "power", "on"], 2)
            if rc == 0:
                notes.append("bluetoothctl power on")

        # btmgmt: keep this lean. On many hosts every btmgmt call blocks
        # the full timeout waiting on D-Bus, so we only attempt power+le
        # once and a single Coded-PHY probe (1s each).
        if shutil.which("btmgmt"):
            idx_args: List[str] = []
            if adapter:
                num = "".join(c for c in adapter if c.isdigit())
                if num:
                    idx_args = ["--index", num]
            self._run_quick(["btmgmt"] + idx_args + ["power", "on"], 1)
            self._run_quick(["btmgmt"] + idx_args + ["le", "on"], 1)
            # LE Coded PHY for long-range (best-effort, single try)
            rc = self._run_quick(
                ["btmgmt"] + idx_args + ["phy", "le1m", "le2m", "lecoded"], 1,
            )
            if rc == 0:
                notes.append("btmgmt: LE PHY long-range enabled")
            else:
                notes.append("btmgmt: LE prep attempted")

        # hciconfig up
        if shutil.which("hciconfig"):
            iface = adapter or "hci0"
            rc = self._run_quick(["hciconfig", iface, "up"], 1)
            if rc == 0:
                notes.append(f"hciconfig {iface} up")

        # HCI LE Set Scan Parameters: active scan, interval=window=0x4000
        # (10.24s) → ~100% RX duty cycle for maximum range. Needs CAP_NET_RAW.
        if shutil.which("hcitool"):
            cmd = ["hcitool"]
            if adapter:
                cmd += ["-i", adapter]
            cmd += [
                "cmd", "0x08", "0x000B",
                "01", "00", "40", "00", "40", "00", "00", "00",
            ]
            rc = self._run_quick(cmd, 1)
            if rc == 0:
                notes.append("HCI LE scan params: max duty cycle (0x4000)")

        return notes

    @staticmethod
    def _bleak_available() -> bool:
        try:
            from bleak import BleakScanner  # type: ignore  # noqa: F401
            return True
        except Exception:
            return False

    def _bleak_scan(
        self, duration: int, adapter: str = None
    ) -> Tuple[List[Dict[str, Any]], str]:
        try:
            from bleak import BleakScanner  # type: ignore
        except Exception:
            return [], "bleak-unavailable"

        async def _do():
            found: List[Dict[str, Any]] = []
            best_rssi: Dict[str, int] = {}

            def cb(dev, adv):
                addr = _norm_addr(getattr(dev, "address", "") or "")
                if not addr:
                    return
                rssi = getattr(adv, "rssi", None)
                prev = best_rssi.get(addr)
                if prev is not None and rssi is not None and rssi < prev:
                    pass
                else:
                    if rssi is not None:
                        best_rssi[addr] = rssi

                # manufacturer_data as hex summary (never fake)
                mfg = ""
                try:
                    md = getattr(adv, "manufacturer_data", None) or {}
                    if md:
                        parts = []
                        for k, v in list(md.items())[:3]:
                            if isinstance(v, (bytes, bytearray)):
                                parts.append(f"{k:04x}:{v[:8].hex()}")
                            else:
                                parts.append(f"{k:04x}")
                        mfg = ",".join(parts)
                except Exception:
                    mfg = ""

                addr_type = "public"
                try:
                    details = getattr(dev, "details", None)
                    if isinstance(details, dict):
                        addr_type = details.get("addr_type") or details.get(
                            "AddressType", "public"
                        )
                    elif details is not None:
                        addr_type = (
                            getattr(details, "addr_type", None)
                            or getattr(details, "AddressType", None)
                            or "public"
                        )
                except Exception:
                    addr_type = "public"

                entry = {
                    "device_id": (
                        str(adv.handle) if hasattr(adv, "handle") else ""
                    ),
                    "name": dev.name or "Unknown",
                    "address": addr,
                    "address_type": str(addr_type),
                    "rssi": rssi if rssi is not None else -100,
                    "services": [
                        str(s)
                        for s in (getattr(adv, "service_uuids", None) or [])
                    ],
                    "manufacturer_data": mfg,
                    "tx_power": getattr(adv, "tx_power", None),
                }
                for i, d in enumerate(found):
                    if d["address"] == addr:
                        if (
                            rssi is not None
                            and (
                                d.get("rssi") is None
                                or d.get("rssi", -999) < rssi
                            )
                        ):
                            found[i] = entry
                        elif not d.get("name") or d.get("name") == "Unknown":
                            if entry["name"] and entry["name"] != "Unknown":
                                found[i]["name"] = entry["name"]
                        # always union services
                        svcs = list(d.get("services") or [])
                        for s in entry["services"]:
                            if s not in svcs:
                                svcs.append(s)
                        found[i]["services"] = svcs
                        return
                found.append(entry)

            # Active scanning, no service filter = max discovery range
            scanner = None
            # Prefer BlueZ adapter kwargs when available
            bluez_kwargs: Dict[str, Any] = {}
            if adapter:
                try:
                    from bleak.backends.bluezdbus.scanner import (  # type: ignore
                        BlueZScannerArgs,
                    )
                    bluez_kwargs["bluez"] = BlueZScannerArgs()
                except Exception:
                    pass

            try:
                scanner = BleakScanner(
                    detection_callback=cb,
                    scanning_mode="active",
                    adapter=adapter if adapter else None,
                    **bluez_kwargs,
                )
            except TypeError:
                try:
                    scanner = BleakScanner(
                        detection_callback=cb, scanning_mode="active",
                    )
                except TypeError:
                    try:
                        scanner = BleakScanner(detection_callback=cb)
                    except TypeError:
                        scanner = BleakScanner(cb)

            await scanner.start()
            await asyncio_sleep(duration)
            await scanner.stop()

            seen, uniq = set(), []
            for d in sorted(
                found, key=lambda x: -(x.get("rssi") or -999)
            ):
                if d["address"] in seen:
                    continue
                seen.add(d["address"])
                uniq.append(d)
            return uniq

        import asyncio as _asyncio
        try:
            loop = _asyncio.new_event_loop()
            try:
                devices = loop.run_until_complete(_do())
            finally:
                loop.close()
            return devices, "bleak"
        except Exception as e:
            logger.debug("bleak run failed: %s", e)
            return [], "bleak-error"

    def _bluetoothctl_scan(
        self, duration: int, adapter: str = None
    ) -> Tuple[List[Dict[str, Any]], str]:
        if not shutil.which("bluetoothctl"):
            return [], "bluetoothctl-unavailable"
        duration = max(2, int(duration))
        # Non-interactive script + hard wall-clock kill. Keep the outer
        # budget tight (duration + 3s) so live TUI pulses stay snappy.
        script = (
            "power on\n"
            "menu scan\n"
            "transport le\n"
            "duplicate-data on\n"
            "back\n"
            "scan on\n"
        )
        outer = duration + 3
        try:
            shell = (
                f"bluetoothctl <<'EOF'\n{script}EOF\n"
                f"sleep {duration}\n"
                "bluetoothctl scan off >/dev/null 2>&1 || true\n"
                "bluetoothctl devices\n"
            )
            p = subprocess.run(
                ["timeout", "-k", "1s", f"{outer}s", "bash", "-c", shell],
                capture_output=True, text=True, timeout=outer + 2,
            )
            out = (p.stdout or "") + "\n" + (p.stderr or "")
        except subprocess.TimeoutExpired as e:
            out = (e.stdout or "") if isinstance(e.stdout, str) else ""
            logger.debug("bluetoothctl timeout after %ss", outer)
        except Exception as e:
            logger.debug("bluetoothctl error: %s", e)
            return [], "bluetoothctl-error"

        devices: List[Dict[str, Any]] = []
        seen = set()
        for line in (out or "").splitlines():
            m = re.search(
                r"Device\s+([0-9A-Fa-f:]{17})\s+(.*)", line
            )
            if not m:
                continue
            addr = _norm_addr(m.group(1))
            if addr in seen:
                continue
            seen.add(addr)
            name = m.group(2).strip()
            rssi = -100
            rm = re.search(r"RSSI:\s*(-?\d+)", name)
            if rm:
                try:
                    rssi = int(rm.group(1))
                except ValueError:
                    pass
            name = re.sub(r"\s+RSSI:.*$", "", name).strip() or "Unknown"
            if name.lower() in (
                "not available", "chiptype", "modalias", "uuids:",
            ):
                name = "Unknown"
            devices.append({
                "device_id": "",
                "name": name,
                "address": addr,
                "address_type": "public",
                "rssi": rssi,
                "services": [],
                "manufacturer_data": "",
            })
        return devices, "bluetoothctl"

    def _hcitool_scan(
        self, duration: int, adapter: str = None
    ) -> Tuple[List[Dict[str, Any]], str]:
        if not shutil.which("hcitool"):
            return [], "hcitool-unavailable"
        try:
            # --duplicates keeps re-hearing weak ads over long windows
            if adapter:
                cmd = [
                    "timeout", str(max(1, int(duration))),
                    "hcitool", "-i", adapter, "lescan", "--duplicates",
                ]
            else:
                cmd = [
                    "timeout", str(max(1, int(duration))),
                    "hcitool", "lescan", "--duplicates",
                ]
            p = subprocess.run(
                cmd, capture_output=True, text=True, timeout=duration + 8,
            )
        except Exception:
            return [], "hcitool-error"
        devices: List[Dict[str, Any]] = []
        seen = set()
        for line in (p.stdout or "").splitlines():
            m = re.match(r"([0-9A-Fa-f:]{17})\s+(.*)", line.strip())
            if m and _norm_addr(m.group(1)) not in seen:
                addr = _norm_addr(m.group(1))
                seen.add(addr)
                devices.append({
                    "device_id": "",
                    "name": m.group(2).strip() or "Unknown",
                    "address": addr,
                    "address_type": "public",
                    "rssi": -100,
                    "services": [],
                    "manufacturer_data": "",
                })
        return devices, "hcitool"

    # ------------------------------------------------------------------
    # Real connect / enumerate via gatttool (no fake services)
    # ------------------------------------------------------------------
    def enumerate_services(
        self, device_address: str, timeout: int = 15
    ) -> Dict[str, Any]:
        if not shutil.which("gatttool"):
            return {"error": "gatttool not installed"}
        try:
            p = subprocess.run(
                ["gatttool", "-b", device_address, "--primary"],
                capture_output=True, text=True, timeout=timeout,
            )
            services = []
            for line in (p.stdout or "").splitlines():
                m = re.search(
                    r"handle = (0x[0-9a-fA-F]+),\s*"
                    r"end handle = (0x[0-9a-fA-F]+),\s*"
                    r"uuid = ([0-9a-fA-F-]+)",
                    line,
                )
                if m:
                    services.append({
                        "uuid": m.group(3),
                        "start_handle": m.group(1),
                        "end_handle": m.group(2),
                    })
            return {
                "device_address": device_address,
                "services": services,
                "rc": p.returncode,
                "stderr": (p.stderr or "")[-500:],
                "timestamp": self._get_timestamp(),
            }
        except Exception as e:
            return {"error": str(e)}

    def get_scan_history(self) -> Dict[str, Any]:
        return self.scan_results

    def _get_timestamp(self) -> str:
        from datetime import datetime
        return datetime.now().isoformat()

    def cleanup(self):
        self.scan_results.clear()
        self.active_scans.clear()
        self.is_initialized = False


# Avoid importing asyncio at top level (only needed for the bleak path).
def asyncio_sleep(seconds):
    import asyncio
    return asyncio.sleep(seconds)
