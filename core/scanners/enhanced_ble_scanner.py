#!/usr/bin/env python3
"""
Enhanced BLE Scanner
=====================
Real Bluetooth Low Energy scanning. Tries ``bleak`` first, then
``bluetoothctl``, then ``hcitool``. If no BLE tooling is available, returns
an empty result with an explicit error — never random fake devices.

AI risk assessment is intentionally NOT done here (it would mean fabricating
``ai_*`` fields). The owning screen routes device descriptions through
``AIBackend.query("ble", ...)`` when the operator asks for an assessment.
"""

import logging
import re
import shutil
import subprocess
import time
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)


class EnhancedBLEScanner:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.is_initialized = False
        self.scan_results = {}
        self.active_scans = {}

    def initialize(self):
        self.is_initialized = True
        return True

    # ------------------------------------------------------------------
    # Scan — real backends, no fake devices
    # ------------------------------------------------------------------
    def scan(self, duration: int = None, adapter: str = None) -> Dict[str, Any]:
        """Long-range BLE discovery scan.

        Duration defaults to ``DEFAULT_BLE_SCAN_S`` (300s), ceiling
        ``MAX_SCAN_S`` (3600s). Before scanning, best-effort adapter
        prep raises RX sensitivity (power on, LE on, max scan window).
        """
        from core.scanners.scan_limits import ble_scan_s

        if not self.is_initialized:
            return {"error": "BLE scanner not initialized"}

        scan_id = f"ble_scan_{int(time.time())}"
        cap = ble_scan_s(duration)
        self.logger.info(f"BLE long-range scan {scan_id} for {cap}s")
        self._prep_adapter_long_range(adapter)
        devices: List[Dict[str, Any]] = []
        backend = "none"
        # Track every backend that was *available* + *attempted* so the error
        # message is honest. The old code reported "install bleak/bluez" even
        # when all three backends were installed but no device was in range.
        attempted: List[str] = []

        # 1) bleak (preferred — gives RSSI + service UUIDs)
        try:
            dev, back = self._bleak_scan(cap)
            if back and not back.endswith("unavailable"):
                attempted.append(back)
            if dev:
                devices, backend = dev, back
        except Exception as e:
            self.logger.debug(f"bleak scan failed: {e}")

        # 2) bluetoothctl (always installed with bluez)
        if not devices:
            try:
                dev, back = self._bluetoothctl_scan(cap, adapter)
                if back and not back.endswith("unavailable"):
                    attempted.append(back)
                if dev:
                    devices, backend = dev, back
            except Exception as e:
                self.logger.debug(f"bluetoothctl scan failed: {e}")

        # 3) hcitool lescan (legacy fallback)
        if not devices:
            try:
                dev, back = self._hcitool_scan(cap, adapter)
                if back and not back.endswith("unavailable"):
                    attempted.append(back)
                if dev:
                    devices, backend = dev, back
            except Exception as e:
                self.logger.debug(f"hcitool scan failed: {e}")

        # De-duplicate attempted backends while preserving order, and collapse
        # the "-error" / "-unavailable" suffixes to a clean family name for the
        # operator-facing message (e.g. "bleak-error" -> "bleak").
        _clean = {
            "bleak": "bleak", "bleak-error": "bleak",
            "bleak-unavailable": None,
            "bluetoothctl": "bluetoothctl", "bluetoothctl-error": "bluetoothctl",
            "bluetoothctl-unavailable": None,
            "hcitool": "hcitool", "hcitool-error": "hcitool",
            "hcitool-unavailable": None,
        }
        attempted = [_clean.get(b, b) for b in attempted]
        seen_b = set()
        attempted = [b for b in attempted if b and not (b in seen_b or seen_b.add(b))]

        result = {
            "timestamp": self._get_timestamp(),
            "duration": cap,
            "devices": devices,
            "total_found": len(devices),
            "backend": backend,
            "backends_tried": attempted,
        }
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

    def _prep_adapter_long_range(self, adapter: str = None) -> None:
        """Best-effort: unblock rfkill + power on + LE on + max scan window.

        Soft-blocked Bluetooth (common after laptop suspend / airplane
        mode) makes every backend return empty. Failures are silent —
        backends still try their normal paths.
        """
        # Unblock soft rfkill on Bluetooth (and wifi if present).
        if shutil.which("rfkill"):
            for what in ("bluetooth", "hci"):
                try:
                    subprocess.run(
                        ["rfkill", "unblock", what],
                        capture_output=True, text=True, timeout=4,
                    )
                except Exception:  # noqa: BLE001
                    pass
            # Also unblock by index if named devices stay soft-blocked.
            try:
                p = subprocess.run(
                    ["rfkill", "list"],
                    capture_output=True, text=True, timeout=4,
                )
                for line in (p.stdout or "").splitlines():
                    # "0: hci0: Bluetooth"
                    if "Bluetooth" in line or "hci" in line.lower():
                        idx = line.split(":", 1)[0].strip()
                        if idx.isdigit():
                            subprocess.run(
                                ["rfkill", "unblock", idx],
                                capture_output=True, text=True, timeout=3,
                            )
            except Exception:  # noqa: BLE001
                pass

        # bluetoothctl power / discoverable
        if shutil.which("bluetoothctl"):
            try:
                subprocess.run(
                    ["bluetoothctl", "power", "on"],
                    capture_output=True, text=True, timeout=5,
                )
            except Exception:  # noqa: BLE001
                pass
        # btmgmt: LE on + high-duty find parameters when available
        if shutil.which("btmgmt"):
            try:
                idx_args = []
                if adapter:
                    # hci0 style
                    num = "".join(c for c in adapter if c.isdigit())
                    if num:
                        idx_args = ["--index", num]
                for args in (
                    idx_args + ["power", "on"],
                    idx_args + ["le", "on"],
                    idx_args + ["bredr", "on"],
                    # connectable off keeps radio free for RX
                    idx_args + ["connectable", "off"],
                ):
                    if not args:
                        continue
                    try:
                        subprocess.run(
                            ["btmgmt"] + args,
                            capture_output=True, text=True, timeout=4,
                        )
                    except Exception:  # noqa: BLE001
                        pass
            except Exception:  # noqa: BLE001
                pass
        # hcitool / hciconfig leadv off, lescan will use active
        if adapter and shutil.which("hciconfig"):
            try:
                subprocess.run(
                    ["hciconfig", adapter, "up"],
                    capture_output=True, text=True, timeout=4,
                )
            except Exception:  # noqa: BLE001
                pass
        elif shutil.which("hciconfig"):
            # Try default hci0 when adapter not specified
            try:
                subprocess.run(
                    ["hciconfig", "hci0", "up"],
                    capture_output=True, text=True, timeout=4,
                )
            except Exception:  # noqa: BLE001
                pass

    def _bleak_scan(self, duration: int):
        try:
            from bleak import BleakScanner  # type: ignore
        except Exception:
            return [], "bleak-unavailable"

        async def _do():
            found = []
            best_rssi = {}

            def cb(dev, adv):
                addr = dev.address
                rssi = getattr(adv, "rssi", None)
                # Keep the strongest RSSI observation (long-range catch)
                prev = best_rssi.get(addr)
                if prev is not None and rssi is not None and rssi < prev:
                    # weaker sighting — still refresh name/services if new
                    pass
                else:
                    if rssi is not None:
                        best_rssi[addr] = rssi
                entry = {
                    "device_id": str(adv.handle) if hasattr(adv, "handle") else "",
                    "name": dev.name or "Unknown",
                    "address": addr,
                    "address_type": (
                        getattr(dev, "details", {}).get("addr_type", "public")
                        if hasattr(dev, "details") else "public"
                    ),
                    "rssi": rssi if rssi is not None else -100,
                    "services": [
                        str(s) for s in (getattr(adv, "service_uuids", None) or [])
                    ],
                    "manufacturer_data": "",
                    "tx_power": getattr(adv, "tx_power", None),
                }
                # replace prior weaker entry
                for i, d in enumerate(found):
                    if d["address"] == addr:
                        if (rssi is not None
                                and (d.get("rssi") is None
                                     or d.get("rssi", -999) < rssi)):
                            found[i] = entry
                        elif not d.get("name") or d.get("name") == "Unknown":
                            if entry["name"] and entry["name"] != "Unknown":
                                found[i]["name"] = entry["name"]
                        return
                found.append(entry)

            # Active scanning, no service filter = max discovery range
            kwargs = {"detection_callback": cb}
            try:
                # bleak ≥0.20: scanning_mode
                scanner = BleakScanner(scanning_mode="active", **kwargs)
            except TypeError:
                try:
                    scanner = BleakScanner(**kwargs)
                except TypeError:
                    scanner = BleakScanner(cb)
            await scanner.start()
            await asyncio_sleep(duration)
            await scanner.stop()
            # de-dup by address (keep best RSSI)
            seen, uniq = set(), []
            for d in sorted(found, key=lambda x: -(x.get("rssi") or -999)):
                if d["address"] in seen:
                    continue
                seen.add(d["address"])
                uniq.append(d)
            return uniq

        import asyncio as _asyncio
        # run in a fresh loop (curses main thread may not have one)
        try:
            loop = _asyncio.new_event_loop()
            try:
                devices = loop.run_until_complete(_do())
            finally:
                loop.close()
            return devices, "bleak"
        except Exception as e:
            logger.debug(f"bleak run failed: {e}")
            return [], "bleak-error"

    def _bluetoothctl_scan(self, duration: int, adapter: str = None):
        if not shutil.which("bluetoothctl"):
            return [], "bluetoothctl-unavailable"
        try:
            # NOTE: do NOT pass `-a <adapter>` on the command line — older
            # bluez builds reject it and exit immediately, making it look like
            # bluetoothctl is "unavailable". The default controller is used;
            # `adapter` is kept on the signature for API parity.
            p = subprocess.Popen(
                ["bluetoothctl"],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, text=True,
            )
            assert p.stdin is not None
            # Long-range: power on, transport le, dual discovery, uuids off
            for line in (
                "power on",
                "menu scan",
                "transport le",
                "duplicate-data on",
                "back",
                "scan on",
            ):
                p.stdin.write(line + "\n")
                p.stdin.flush()
            time.sleep(duration)
            p.stdin.write("scan off\n")
            p.stdin.write("exit\n")
            p.stdin.flush()
            try:
                out, _ = p.communicate(timeout=8)
            except subprocess.TimeoutExpired:
                p.kill(); out, _ = p.communicate()
        except Exception as e:
            logger.debug(f"bluetoothctl error: {e}")
            return [], "bluetoothctl-error"
        devices: List[Dict[str, Any]] = []
        seen = set()
        for line in (out or "").splitlines():
            # "[NEW] Device AA:BB:CC:DD:EE:FF Name"
            m = re.search(r"Device\s+([0-9A-Fa-f:]{17})\s+(.*)", line)
            if m and m.group(1) not in seen:
                seen.add(m.group(1))
                name = m.group(2).strip()
                # Strip a trailing "RSSI: -55" if present in newer bluez.
                name = re.sub(r"\s+RSSI:.*$", "", name).strip() or "Unknown"
                devices.append({
                    "device_id": "",
                    "name": name,
                    "address": m.group(1),
                    "address_type": "public",
                    "rssi": -100,
                    "services": [],
                    "manufacturer_data": "",
                })
        return devices, "bluetoothctl"

    def _hcitool_scan(self, duration: int, adapter: str = None):
        if not shutil.which("hcitool"):
            return [], "hcitool-unavailable"
        try:
            # --duplicates keeps re-hearing weak ads over long windows
            cmd = ["timeout", str(max(1, int(duration))),
                   "hcitool", "lescan", "--duplicates"]
            if adapter:
                cmd = ["timeout", str(max(1, int(duration))),
                       "hcitool", "-i", adapter, "lescan", "--duplicates"]
            # Outer timeout is a backstop slightly past `timeout` helper
            p = subprocess.run(
                cmd, capture_output=True, text=True, timeout=duration + 8,
            )
        except Exception:
            return [], "hcitool-error"
        devices: List[Dict[str, Any]] = []
        seen = set()
        for line in (p.stdout or "").splitlines():
            m = re.match(r"([0-9A-Fa-f:]{17})\s+(.*)", line.strip())
            if m and m.group(1) not in seen:
                seen.add(m.group(1))
                devices.append({
                    "device_id": "",
                    "name": m.group(2).strip() or "Unknown",
                    "address": m.group(1),
                    "address_type": "public",
                    "rssi": -100,
                    "services": [],
                    "manufacturer_data": "",
                })
        return devices, "hcitool"

    # ------------------------------------------------------------------
    # Real connect / enumerate via gatttool (no fake services)
    # ------------------------------------------------------------------
    def enumerate_services(self, device_address: str, timeout: int = 15) -> Dict[str, Any]:
        if not shutil.which("gatttool"):
            return {"error": "gatttool not installed"}
        try:
            p = subprocess.run(
                ["gatttool", "-b", device_address, "--primary"],
                capture_output=True, text=True, timeout=timeout,
            )
            services = []
            for line in (p.stdout or "").splitlines():
                m = re.search(r"handle = (0x[0-9a-fA-F]+),\s*end handle = (0x[0-9a-fA-F]+),\s*uuid = ([0-9a-fA-F-]+)", line)
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
                "stderr": p.stderr[-500:],
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


# Avoid importing asyncio at top level (it's only needed for the bleak path).
def asyncio_sleep(seconds):
    import asyncio
    return asyncio.sleep(seconds)