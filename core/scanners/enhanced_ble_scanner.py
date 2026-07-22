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
    def scan(self, duration: int = 30, adapter: str = None) -> Dict[str, Any]:
        if not self.is_initialized:
            return {"error": "BLE scanner not initialized"}

        scan_id = f"ble_scan_{int(time.time())}"
        cap = min(max(duration, 2), 60)
        self.logger.info(f"BLE scan {scan_id} for {cap}s")

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

    def _bleak_scan(self, duration: int):
        try:
            from bleak import BleakScanner  # type: ignore
        except Exception:
            return [], "bleak-unavailable"

        async def _do():
            found = []
            def cb(dev, adv):
                found.append({
                    "device_id": str(adv.handle) if hasattr(adv, "handle") else "",
                    "name": dev.name or "Unknown",
                    "address": dev.address,
                    "address_type": getattr(dev, "details", {}).get("addr_type", "public") if hasattr(dev, "details") else "public",
                    "rssi": adv.rssi,
                    "services": [str(s) for s in getattr(adv, "service_uuids", []) or []],
                    "manufacturer_data": "",
                    "tx_power": getattr(adv, "tx_power", None),
                })
            scanner = BleakScanner(detection_callback=cb)
            await scanner.start()
            await asyncio_sleep(duration)
            await scanner.stop()
            # de-dup by address
            seen, uniq = set(), []
            for d in found:
                if d["address"] in seen:
                    continue
                seen.add(d["address"]); uniq.append(d)
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
            p.stdin.write("power on\n"); p.stdin.flush()
            p.stdin.write("scan on\n"); p.stdin.flush()
            time.sleep(duration)
            p.stdin.write("scan off\n"); p.stdin.write("exit\n"); p.stdin.flush()
            try:
                out, _ = p.communicate(timeout=5)
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
            cmd = ["hcitool", "lescan", "--duplicates"]
            if adapter:
                cmd = ["hcitool", "-i", adapter, "lescan", "--duplicates"]
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=duration + 3)
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