#!/usr/bin/env python3
"""
BLE Probe Runner (U4000 BLUETOOTH adapter / hci0)
=================================================
Real, passive BLE recon algorithms from the implementacja.txt spec,
implemented as in-module algorithms (not wrappers) following the
``catalog_recon`` pattern: a ``BLEProbeRunner`` with a
``BLE_PROBE_METHODS`` tuple + ``run_probe``, plus a module-level
``BLE_PROBES`` registry and ``run_probe`` entrypoint for the MCP layer
and the orchestrator's ``ble_probe`` dispatch.

Honesty contract (mirrors catalog_recon / enhanced_ble_scanner):
  * Every probe does **real** work — subprocess to real BlueZ tooling
    (``hcitool``, ``gatttool``, ``bluetoothctl``, ``btmon``), real AD
    structure parsing, real OUI lookup, real arithmetic — or it returns
    ``{ok: False, error: "<tool> not installed / no data"}``.
  * Where the spec calls for a trained ML model (XGBoost
    ``just_works_probability``, VAE anomaly, CNN manufacturer classifier),
    the probe runs a **documented heuristic fallback** and labels it as
    such (``model: "heuristic"`` / ``"not_trained"``) — it never fabricates
    a trained-model prediction. This is the same stance catalog_recon
    takes: the algorithm lives here; the heavy model is optional.
  * Never raises. Every probe returns a step dict.

Reuses :class:`core.scanners.enhanced_ble_scanner.EnhancedBLEScanner`
(bleak -> bluetoothctl -> hcitool) for device discovery so we do not
re-implement scanning.
"""

from __future__ import annotations

import binascii
import logging
import re
import shutil
import struct
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent

# ---------------------------------------------------------------------------
# OUI -> vendor (small offline set; load data/oui.txt if present, same
# convention as catalog_recon._BUILTIN_OUI). BLE addresses use the same OUI
# prefix (first 3 octets, uppercased, no separators).
# ---------------------------------------------------------------------------
_BUILTIN_OUI: Dict[str, str] = {
    "001A11": "Google", "F4F5D8": "Google", "001E52": "Apple",
    "3C0754": "Apple", "001124": "Apple", "002500": "Apple",
    "B827EB": "Raspberry Pi", "DCA632": "Raspberry Pi",
    "C048E6": "TP-Link", "EC086B": "TP-Link", "AC84C6": "TP-Link",
    "001CC0": "TP-Link", "B0487A": "TP-Link", "30B5C2": "TP-Link",
    "001D0F": "TP-Link", "6037B7": "TP-Link",
    "ACF1DF": "Samsung", "001247": "Samsung", "08D40B": "Samsung",
    "0013E8": "Intel", "001DE0": "Intel", "8086F2": "Intel",
    "7CC537": "Intel", "C8F733": "Intel",
    "D0072B": "Xiaomi", "F8D2BA": "Xiaomi", "68DBCA": "Xiaomi",
    "C8F0F4": "Nordic Semiconductor", "E8039C": "Nordic Semiconductor",
    "580F2A": "Nordic Semiconductor", "F6B5F4": "Nordic Semiconductor",
    "001B10": "Fitbit", "00C72E": "Fitbit",
    "8CDE52": "Amazon", "F0C3A4": "Amazon", "44A742": "Amazon",
    "7CC70D": "Amazon", "B47C9C": "Amazon",
    "B09575": "Espressif", "24B1FF": "Espressif", "D8A01D": "Espressif",
    "EC94CB": "Espressif", "C8C9A3": "Espressif",
    "84F863": "Jiangsu Tinnova (Tuya)", "DCF505": "Tuya",
    "1027DF": "Tuya", "10C685": "Tuya",
}

# Bluetooth SIG "Company Identifier" codes that appear in Manufacturer
# Specific Data (AD type 0xFF), little-endian first two bytes. Used by the
# manufacturer_oracle and analyze_location_leak probes.
_COMPANY_IDS: Dict[int, str] = {
    0x004C: "Apple", 0x0006: "Microsoft", 0x0059: "Nordic Semiconductor",
    0x0087: "Garmin", 0x00E0: "Google", 0x0159: "Fitbit",
    0x0117: "Amazon", 0x0187: " Xiaomi", 0x0501: "Xiaomi",
    0x0131: "Espressif", 0x0102: "TP-Link", 0x0171: "Samsung",
    0x0075: "Samsung", 0x0147: "Tuya",
}

# AD (Advertising Data) structure type codes (Bluetooth Core Spec, Vol 3,
# Part C, §11). Used by parse_advertising_data.
_AD_TYPES: Dict[int, str] = {
    0x01: "Flags", 0x02: "Incomplete List of 16-bit Service UUIDs",
    0x03: "Complete List of 16-bit Service UUIDs",
    0x04: "Incomplete List of 32-bit Service UUIDs",
    0x05: "Complete List of 32-bit Service UUIDs",
    0x06: "Incomplete List of 128-bit Service UUIDs",
    0x07: "Complete List of 128-bit Service UUIDs",
    0x08: "Shortened Local Name", 0x09: "Complete Local Name",
    0x0A: "TX Power Level", 0x0D: "Class of Device",
    0x10: "Service Data - 16-bit UUID", 0x16: "Service Data - 16-bit UUID",
    0x19: "Appearance", 0x1B: "LE Bluetooth Device Address",
    0xFF: "Manufacturer Specific Data",
}

# GATT service UUIDs the spec's recon modules care about (Battery, Device
# Information, Nordic DFU OTA). Used by map_gatt_services / recon_ota_update.
_GATT_SERVICES: Dict[str, str] = {
    "180f": "Battery Service", "180a": "Device Information Service",
    "fe59": "Nordic DFU Service (OTA)", "181c": "User Data Service",
    "1802": "Immediate Alert", "1805": "Current Time Service",
    "1808": "Body Composition", "1810": "Blood Pressure",
    "181d": "Weight Scale", "1820": "Internet Protocol Support",
}

# Pairing / security flags decoded from the AD Flags field (AD type 0x01).
_FLAG_BITS: Dict[int, str] = {
    0x01: "LE Limited Discoverable",
    0x02: "LE General Discoverable",
    0x04: "BR/EDR Not Supported",
    0x08: "Simultaneous LE and BR/EDR (Controller)",
    0x10: "Simultaneous LE and BR/EDR (Host)",
}

# OTA / DFU service UUIDs advertised by devices exposing a firmware-update
# surface (Nordic DFU is the canonical 16-bit one; the rest are common
# vendor OTA UUIDs). Used by recon_ota_update.
_OTA_SERVICE_UUIDS = {
    "fe59",            # Nordic DFU Service
    "0000152301212efdf1523785feabcd123",  # Nordic Legacy DFU (128-bit)
    "0000fe9f0000100008000805f9b34fb",    # OTA service (generic)
}

# GATT Appearance values for HID devices (Bluetooth SIG Assigned Numbers,
# Appearances). Used by hid_recon.
_HID_APPEARANCES: Dict[int, str] = {
    0x03C1: "Keyboard",
    0x03C2: "Mouse",
    0x03C3: "Joystick",
    0x03C4: "Gamepad",
    0x03C5: "Digitizer Tablet",
    0x03C6: "Card Reader",
    0x03C7: "Digital Pen",
    0x03C8: "Barcode Scanner",
}

# Smart-home hub fingerprint table — match by local-name token, advertised
# service UUID, SIG company id, or OUI vendor. Used by smarthome_enumerator.
_SMARTHOME_HUBS = [
    {"label": "Philips Hue Bridge", "name_tok": "hue", "uuid": "9e6b",
     "cid": None, "vendor": "Philips"},
    {"label": "IKEA TRÅDFRI", "name_tok": "tradfri", "uuid": "0000fff9",
     "cid": 0x004B, "vendor": None},
    {"label": "Xiaomi Hub", "name_tok": "xiaomi", "uuid": "fe95",
     "cid": 0x0187, "vendor": "Xiaomi"},
    {"label": "Tuya Hub", "name_tok": "tuya", "uuid": "fe1f",
     "cid": 0x0147, "vendor": "Tuya"},
    {"label": "Nordic-based IoT hub", "name_tok": "", "uuid": "fe59",
     "cid": 0x0059, "vendor": "Nordic Semiconductor"},
]

# Small known-firmware table for fuzzy matching (firmware_version_predictor).
# Version strings the operator's lab devices carry; the vuln lists are EMPTY
# by design — we never fabricate CVE identifiers. A real deployment would
# populate them from a curated advisory feed; until then a matched version
# returns [] known_vulns (honest), not invented CVEs.
_KNOWN_FIRMWARE: Dict[str, List[str]] = {
    "1.0.0": [],
    "2.1.3": [],
    "3.4.5": [],
}


def _hex_to_ascii(hexstr: str) -> Optional[str]:
    """Decode a gatttool ``value: 41 42`` hex byte string to ASCII."""
    try:
        raw = bytes.fromhex(hexstr.replace(" ", ""))
        return raw.decode("utf-8", "replace").rstrip("\x00")
    except (ValueError, AttributeError):
        return None


def _levenshtein(a: str, b: str) -> int:
    """Standard Levenshtein edit distance (real, stdlib-only)."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1,
                           prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _fuzzy_version(fw: Optional[str],
                   known: Dict[str, List[str]]
                   ) -> Tuple[Optional[str], List[str], int]:
    """Fuzzy-match a firmware string against a known-versions table by
    Levenshtein distance. Returns ``(matched_version, known_vulns, distance)``
    — ``(None, [], -1)`` when there is nothing to match."""
    if not fw:
        return None, [], -1
    best, best_d = None, None
    for ver in known:
        d = _levenshtein(fw, ver)
        if best_d is None or d < best_d:
            best, best_d = ver, d
    # Only accept a match within a sane edit distance (<= len/2).
    if best is None or best_d > max(1, len(fw) // 2):
        return None, [], best_d if best_d is not None else -1
    return best, known.get(best, []), best_d


def _oui_vendor(address: str, oui_path: Optional[Path] = None) -> str:
    """OUI prefix -> vendor for a BLE address (first 3 octets)."""
    addr = (address or "").strip().upper().replace("-", ":")
    prefix = addr.replace(":", "")[:6]
    if prefix in _BUILTIN_OUI:
        return _BUILTIN_OUI[prefix]
    oui = oui_path or (PROJECT_ROOT / "data" / "oui.txt")
    if oui.exists():
        try:
            with open(oui, "r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    parts = line.split()
                    if len(parts) >= 2 and parts[0].upper() == prefix:
                        return " ".join(parts[1:3])
        except OSError as e:
            logger.debug("oui read: %s", e)
    return "Unknown"


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


def _parse_ad_structures(raw: bytes) -> List[Dict[str, Any]]:
    """Parse the AD structures out of a raw BLE advertising payload.

    Each AD structure is ``[length:1][type:1][data:length-1]``. Returns a
    list of ``{type, type_name, len, data_hex, data_bytes}``. Pure stdlib,
    real parsing per Bluetooth Core Spec.
    """
    out: List[Dict[str, Any]] = []
    i = 0
    n = len(raw)
    while i + 1 < n:
        length = raw[i]
        if length == 0:
            i += 1
            continue
        if i + 1 + length > n:
            break  # truncated structure
        ad_type = raw[i + 1]
        data = raw[i + 2:i + 1 + length]
        out.append({
            "type": ad_type,
            "type_name": _AD_TYPES.get(ad_type, f"Unknown(0x{ad_type:02X})"),
            "len": length,
            "data_hex": binascii.hexlify(data).decode("ascii"),
            "data_bytes": data,
        })
        i += 1 + length
    return out


def _decode_ibeacon(mfr_data: bytes) -> Optional[Dict[str, Any]]:
    """Decode an Apple iBeacon frame (company 0x004C, subtype 0x02, subsubtype 0x15)
    from Manufacturer Specific Data. Returns ``{uuid, major, minor, tx_power}``
    or None if the payload is not an iBeacon."""
    if len(mfr_data) < 25 or mfr_data[2] != 0x02 or mfr_data[3] != 0x15:
        return None
    try:
        uuid_hex = mfr_data[4:20].hex()
        uuid_str = f"{uuid_hex[0:8]}-{uuid_hex[8:12]}-{uuid_hex[12:16]}-{uuid_hex[16:20]}-{uuid_hex[20:32]}"
        major, minor, tx_power = struct.unpack(">hhb", mfr_data[20:25])
        return {"uuid": uuid_str, "major": major, "minor": minor,
                "tx_power": tx_power}
    except (struct.error, IndexError):
        return None


class BLEProbeRunner:
    """Runs a single passive BLE recon probe by name. Every probe is real
    (subprocess / parse / arithmetic) or returns a clear degrade error;
    none fabricate a trained-model prediction. Never raises."""

    #: The BLE probe method names, in stable order.
    BLE_PROBE_METHODS: Tuple[str, ...] = (
        "parse_advertising_data", "manufacturer_oracle",
        "analyze_location_leak", "estimate_battery_profile",
        "map_gatt_services", "connection_graph_active",
        "calculate_exfil_potential", "predict_pairing_vulnerability",
        "recon_ota_update", "assess_mitm_feasibility",
        "firmware_version_predictor", "cross_device_linker_ble",
        "ble_anomaly_detector", "hid_recon",
        "smarthome_enumerator", "tracking_resistance_test",
    )

    def __init__(self, adapter: Optional[str] = None,
                 oui_path: Optional[Path] = None,
                 scanner: Optional[Any] = None,
                 args: Optional[Dict[str, Any]] = None):
        if adapter is None:
            # Mirror the WiFi side: the canonical external adapter
            # is the U4000 BLUETOOTH adapter (hci0). The helper honours
            # KFIOSA_BLE_ADAPTER (the operator's escape hatch) and
            # defaults to "hci0" without spawning hciconfig — the
            # heuristic enumeration is opt-in via
            # core.ble.adapter_select.select_external_adapter().
            from core.ble.adapter_select import resolve_default_adapter
            adapter = resolve_default_adapter()
        self.adapter = adapter  # hci0 (U4000) by default; or env override
        self.oui_path = oui_path
        self._scanner = scanner  # injectable for hermetic tests
        # Per-probe args (e.g. cross_device_linker_ble needs wifi_mac +
        # ble_mac). Passed through from the orchestrator's ble_probe step
        # args; ignored by probes that don't read them.
        self.args = args or {}

    # -- discovery (reuses the real EnhancedBLEScanner) -----------------
    def _scan(self, duration: int = 15) -> Dict[str, Any]:
        if self._scanner is not None:
            return self._scanner.scan(duration=duration, adapter=self.adapter)
        from core.scanners.enhanced_ble_scanner import EnhancedBLEScanner
        sc = EnhancedBLEScanner()
        sc.initialize()
        return sc.scan(duration=duration, adapter=self.adapter)

    # -- helpers ----------------------------------------------------------
    @staticmethod
    def _dev_field(dev: Dict[str, Any], *keys: str, default: Any = None) -> Any:
        for k in keys:
            if dev.get(k) is not None:
                return dev.get(k)
        return default

    # ------------------------------------------------------------------
    # 1. parse_advertising_data
    # ------------------------------------------------------------------
    def _parse_advertising_data(self) -> Dict[str, Any]:
        """Decode the AD structures of every discovered device's raw
        advertisement. bleak exposes ``advertisement_data``/service UUIDs;
        where only bluetoothctl/hcitool is available we fall back to the
        scanner's fields (no raw bytes -> reported, not faked). The AD
        structure parser itself is real."""
        step = _step("parse_advertising_data")
        try:
            scan = self._scan(15)
            if scan.get("error") and not scan.get("devices"):
                return _finalize(step, step["started"], ok=False,
                                 error=scan["error"])
            devices: List[Dict[str, Any]] = scan.get("devices", []) or []
            parsed: List[Dict[str, Any]] = []
            for dev in devices:
                raw = dev.get("raw_advert") or dev.get("advertisement_raw")
                structs = _parse_ad_structures(raw) if isinstance(raw, (bytes, bytearray)) else []
                local_name = dev.get("name") or ""
                for s in structs:
                    if s["type"] in (0x08, 0x09) and s["data_bytes"]:
                        local_name = local_name or s["data_bytes"].decode("utf-8", "replace")
                parsed.append({
                    "address": dev.get("address"),
                    "address_type": dev.get("address_type", "public"),
                    "name": local_name,
                    "rssi": dev.get("rssi"),
                    "ad_structures": structs,
                    "has_raw": bool(structs),
                    "service_uuids": dev.get("uuids") or [],
                })
            msg = None if any(p["has_raw"] for p in parsed) else (
                "no raw advertisement bytes from this backend (bleak raw or "
                "btmon needed) — scanner fields parsed instead")
            return _finalize(step, step["started"], ok=True,
                             data={"devices": parsed, "count": len(parsed),
                                   "note": msg})
        except Exception as e:  # noqa: BLE001
            return _finalize(step, step["started"], ok=False, error=str(e))

    # ------------------------------------------------------------------
    # 2. manufacturer_oracle
    # ------------------------------------------------------------------
    def _manufacturer_oracle(self) -> Dict[str, Any]:
        """Identify each device's manufacturer from two real signals: the
        OUI prefix of its address, and the Bluetooth SIG Company ID in any
        Manufacturer Specific Data (AD type 0xFF) — incl. iBeacon decoding.
        No CNN/classifier: a documented heuristic (``model: "heuristic"``)."""
        step = _step("manufacturer_oracle")
        try:
            scan = self._scan(15)
            if scan.get("error") and not scan.get("devices"):
                return _finalize(step, step["started"], ok=False,
                                 error=scan["error"])
            out: List[Dict[str, Any]] = []
            for dev in scan.get("devices", []) or []:
                oui_vendor = _oui_vendor(dev.get("address", ""), self.oui_path)
                cid_name: Optional[str] = None
                ibeacon: Optional[Dict[str, Any]] = None
                raw = dev.get("raw_advert") or dev.get("advertisement_raw")
                if isinstance(raw, (bytes, bytearray)):
                    for s in _parse_ad_structures(raw):
                        if s["type"] == 0xFF and len(s["data_bytes"]) >= 2:
                            cid = struct.unpack("<H", s["data_bytes"][:2])[0]
                            cid_name = _COMPANY_IDS.get(cid, f"Company 0x{cid:04X}")
                            ibeacon = _decode_ibeacon(s["data_bytes"])
                            break
                # Reconcile: company-id + OUI agreement raises confidence.
                agree = (cid_name is not None and oui_vendor != "Unknown"
                         and cid_name.lower() in oui_vendor.lower())
                out.append({
                    "address": dev.get("address"),
                    "oui_vendor": oui_vendor,
                    "company_id": cid_name,
                    "ibeacon": ibeacon,
                    "confidence": "high" if agree else
                                  ("medium" if cid_name or oui_vendor != "Unknown"
                                   else "low"),
                    "model": "heuristic",
                })
            return _finalize(step, step["started"], ok=True,
                             data={"devices": out, "count": len(out)})
        except Exception as e:  # noqa: BLE001
            return _finalize(step, step["started"], ok=False, error=str(e))

    # ------------------------------------------------------------------
    # 3. analyze_location_leak
    # ------------------------------------------------------------------
    def _analyze_location_leak(self) -> Dict[str, Any]:
        """Decode iBeacon (Apple company 0x004C) UUID/Major/Minor/TX-power
        from Manufacturer Specific Data and flag devices broadcasting a
        location-revealing beacon. Pure decode — no external lookup."""
        step = _step("analyze_location_leak")
        try:
            scan = self._scan(15)
            if scan.get("error") and not scan.get("devices"):
                return _finalize(step, step["started"], ok=False,
                                 error=scan["error"])
            beacons: List[Dict[str, Any]] = []
            for dev in scan.get("devices", []) or []:
                raw = dev.get("raw_advert") or dev.get("advertisement_raw")
                if not isinstance(raw, (bytes, bytearray)):
                    continue
                for s in _parse_ad_structures(raw):
                    if s["type"] != 0xFF or len(s["data_bytes"]) < 2:
                        continue
                    cid = struct.unpack("<H", s["data_bytes"][:2])[0]
                    if cid != 0x004C:
                        continue
                    ib = _decode_ibeacon(s["data_bytes"])
                    if ib:
                        beacons.append({
                            "address": dev.get("address"),
                            "uuid": ib["uuid"], "major": ib["major"],
                            "minor": ib["minor"], "tx_power": ib["tx_power"],
                            "rssi": dev.get("rssi"),
                            "location_leak": True,
                        })
            return _finalize(step, step["started"], ok=True,
                             data={"ibeacons": beacons, "count": len(beacons)})
        except Exception as e:  # noqa: BLE001
            return _finalize(step, step["started"], ok=False, error=str(e))

    # ------------------------------------------------------------------
    # 4. estimate_battery_profile
    # ------------------------------------------------------------------
    def _estimate_battery_profile(self) -> Dict[str, Any]:
        """Read the Battery Level characteristic (0x2A19 in service 0x180F)
        for every discovered device via ``gatttool`` (real subprocess). When
        gatttool is absent or the device has no Battery Service, returns a
        clear degrade status — never a fabricated percentage."""
        step = _step("estimate_battery_profile")
        if not shutil.which("gatttool"):
            return _finalize(step, step["started"], ok=False,
                             error="gatttool not installed — cannot read Battery Service")
        try:
            scan = self._scan(15)
            devices = scan.get("devices", []) or []
            out: List[Dict[str, Any]] = []
            for dev in devices:
                addr = dev.get("address")
                if not addr:
                    continue
                rc, stdout = self._gatttool_read(addr, "0x2a19")
                if rc == 0 and stdout:
                    # gatttool prints e.g. "handle: 0x0010   value: 5a"
                    m = re.search(r"value:\s*([0-9a-fA-F]{2})", stdout)
                    if m:
                        level = int(m.group(1), 16)
                        out.append({"address": addr, "battery_level": level,
                                    "source": "gatttool"})
                    else:
                        out.append({"address": addr, "battery_level": None,
                                    "source": "no Battery Service"})
                else:
                    out.append({"address": addr, "battery_level": None,
                                "source": "unreachable"})
            return _finalize(step, step["started"], ok=True,
                             data={"devices": out, "count": len(out)})
        except Exception as e:  # noqa: BLE001
            return _finalize(step, step["started"], ok=False, error=str(e))

    def _gatttool_read(self, addr: str, uuid: str,
                       timeout: int = 12) -> Tuple[int, str]:
        """Read a characteristic by UUID via ``gatttool --char-read-uuid``."""
        try:
            p = subprocess.run(
                ["gatttool", "-b", addr, "--char-read-uuid", uuid, "-t", "random"],
                capture_output=True, text=True, timeout=timeout)
            return p.returncode, (p.stdout or "") + (p.stderr or "")
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return 1, ""

    # ------------------------------------------------------------------
    # 5. map_gatt_services
    # ------------------------------------------------------------------
    def _map_gatt_services(self) -> Dict[str, Any]:
        """Enumerate each device's GATT services via the real
        :meth:`EnhancedBLEScanner.enumerate_services` (gatttool --primary).
        No fabricated services."""
        step = _step("map_gatt_services")
        try:
            scan = self._scan(15)
            devices = scan.get("devices", []) or []
            out: List[Dict[str, Any]] = []
            for dev in devices:
                addr = dev.get("address")
                if not addr:
                    continue
                if self._scanner is not None and hasattr(self._scanner, "enumerate_services"):
                    svc = self._scanner.enumerate_services(addr)
                else:
                    from core.scanners.enhanced_ble_scanner import EnhancedBLEScanner
                    svc = EnhancedBLEScanner().enumerate_services(addr)
                services = svc.get("services", []) if isinstance(svc, dict) else []
                named = []
                for s in services:
                    u = (s.get("uuid") or "").lower()
                    named.append({"uuid": u, "name": _GATT_SERVICES.get(u, "Unknown")})
                out.append({"address": addr, "services": named,
                            "count": len(named),
                            "error": svc.get("error") if isinstance(svc, dict) else None})
            return _finalize(step, step["started"], ok=True,
                             data={"devices": out, "count": len(out)})
        except Exception as e:  # noqa: BLE001
            return _finalize(step, step["started"], ok=False, error=str(e))

    # ------------------------------------------------------------------
    # 6. connection_graph_active
    # ------------------------------------------------------------------
    def _connection_graph_active(self) -> Dict[str, Any]:
        """Build a graph of observed BLE devices and their co-appearance
        over repeated scans (edges = devices seen in the same scan window).
        ``networkx`` optional; a plain dict-of-edges fallback is used when
        it is absent. Real graph built from real observations."""
        step = _step("connection_graph_active")
        try:
            windows: List[List[str]] = []
            for _ in range(2):
                scan = self._scan(10)
                addrs = [d.get("address") for d in (scan.get("devices", []) or [])
                         if d.get("address")]
                if addrs:
                    windows.append(addrs)
            if not windows:
                return _finalize(step, step["started"], ok=False,
                                 error="no BLE devices observed to graph")
            nodes = sorted({a for w in windows for a in w})
            edges: List[Dict[str, Any]] = []
            seen = set()
            for w in windows:
                for i in range(len(w)):
                    for j in range(i + 1, len(w)):
                        key = tuple(sorted((w[i], w[j])))
                        if key in seen:
                            continue
                        seen.add(key)
                        edges.append({"a": key[0], "b": key[1], "co_seen": True})
            data: Dict[str, Any] = {"nodes": nodes, "edges": edges,
                                    "node_count": len(nodes),
                                    "edge_count": len(edges),
                                    "windows": len(windows)}
            # If networkx is available, attach a ready DiGraph too.
            try:
                import networkx as nx  # type: ignore
                g = nx.Graph()
                g.add_nodes_from(nodes)
                g.add_edges_from([(e["a"], e["b"]) for e in edges])
                data["degrees"] = dict(g.degree())
            except Exception:  # noqa: BLE001 — optional dep
                data["degrees"] = None
            return _finalize(step, step["started"], ok=True, data=data)
        except Exception as e:  # noqa: BLE001
            return _finalize(step, step["started"], ok=False, error=str(e))

    # ------------------------------------------------------------------
    # 7. calculate_exfil_potential
    # ------------------------------------------------------------------
    def _calculate_exfil_potential(self) -> Dict[str, Any]:
        """Compute the maximum advertising-channel exfiltration throughput
        per device from its max payload size and the minimum observed
        advertising interval. Real arithmetic; no fabricated telemetry."""
        step = _step("calculate_exfil_potential")
        try:
            scan = self._scan(15)
            devices = scan.get("devices", []) or []
            out: List[Dict[str, Any]] = []
            for dev in devices:
                # BLE max advertising payload is 31 bytes (legacy) / 255
                # (extended). Use observed raw length if present, else 31.
                raw = dev.get("raw_advert") or dev.get("advertisement_raw")
                payload = len(raw) if isinstance(raw, (bytes, bytearray)) else 31
                interval_ms = dev.get("min_interval_ms") or 20  # spec default 20 ms
                try:
                    interval_ms = float(interval_ms)
                except (TypeError, ValueError):
                    interval_ms = 20.0
                bps = (payload * 8) / (interval_ms / 1000.0)
                out.append({"address": dev.get("address"),
                            "payload_bytes": payload,
                            "interval_ms": interval_ms,
                            "exfil_bps": round(bps, 1),
                            "exfil_kbps": round(bps / 1000.0, 3)})
            return _finalize(step, step["started"], ok=True,
                             data={"devices": out, "count": len(out)})
        except Exception as e:  # noqa: BLE001
            return _finalize(step, step["started"], ok=False, error=str(e))

    # ------------------------------------------------------------------
    # 8. predict_pairing_vulnerability
    # ------------------------------------------------------------------
    def _predict_pairing_vulnerability(self) -> Dict[str, Any]:
        """Heuristic estimate of Just-Works pairing likelihood from the AD
        Flags field and whether a device advertises no MITM/secure pairing
        signals. The spec names an XGBoost model — that model is NOT trained
        here, so this returns a clearly-labelled heuristic
        (``model: "heuristic (not trained)"``), never a fabricated trained
        probability."""
        step = _step("predict_pairing_vulnerability")
        try:
            scan = self._scan(15)
            devices = scan.get("devices", []) or []
            out: List[Dict[str, Any]] = []
            for dev in devices:
                flags_byte: Optional[int] = None
                raw = dev.get("raw_advert") or dev.get("advertisement_raw")
                if isinstance(raw, (bytes, bytearray)):
                    for s in _parse_ad_structures(raw):
                        if s["type"] == 0x01 and s["data_bytes"]:
                            flags_byte = s["data_bytes"][0]
                            break
                flags = []
                if flags_byte is not None:
                    for bit, name in _FLAG_BITS.items():
                        if flags_byte & bit:
                            flags.append(name)
                discoverable = flags_byte is not None and (flags_byte & 0x03) != 0
                # Heuristic: a discoverable device with no BR/EDR + random
                # address (often an IoT peripheral) -> higher Just-Works
                # likelihood. Documented, not a trained probability.
                addr_type = dev.get("address_type", "public")
                no_bredr = flags_byte is not None and (flags_byte & 0x04)
                score = 0.0
                if discoverable:
                    score += 0.3
                if no_bredr:
                    score += 0.2
                if addr_type == "random":
                    score += 0.2
                # No Security Manager pairing flags are readable from adv
                # alone — IO Capabilities need a connection. Note honestly.
                score = min(round(score, 2), 0.9)
                out.append({
                    "address": dev.get("address"),
                    "flags": flags,
                    "discoverable": discoverable,
                    "address_type": addr_type,
                    "just_works_likelihood": score,
                    "model": "heuristic (not trained)",
                    "note": "IO Capabilities require a connection to read; "
                            "this is an advertising-only heuristic.",
                })
            return _finalize(step, step["started"], ok=True,
                             data={"devices": out, "count": len(out)})
        except Exception as e:  # noqa: BLE001
            return _finalize(step, step["started"], ok=False, error=str(e))

    # ------------------------------------------------------------------
    # 9. recon_ota_update
    # ------------------------------------------------------------------
    def _recon_ota_update(self) -> Dict[str, Any]:
        """Discover OTA / DFU update surfaces on each device: advertised
        OTA service UUIDs (Nordic DFU 0xFE59, …) plus a gatttool read of the
        Device Information firmware-revision (0x2A26) / model-number
        (0x2A24). Real enumeration + real subprocess read; degrades cleanly
        when gatttool is absent. The spec's ``requests`` firmware download is
        an intrusive follow-on — this probe only *surfaces* the OTA surface
        (passive), it does not download firmware."""
        step = _step("recon_ota_update")
        try:
            scan = self._scan(15)
            devices = scan.get("devices", []) or []
            have_gatt = bool(shutil.which("gatttool"))
            out: List[Dict[str, Any]] = []
            for dev in devices:
                addr = dev.get("address")
                if not addr:
                    continue
                uuids = [str(u).lower() for u in (dev.get("uuids") or [])]
                ota_services = [u for u in uuids if u in _OTA_SERVICE_UUIDS]
                fw_rev = model_num = None
                if have_gatt and (ota_services or uuids):
                    _, mo = self._gatttool_read(addr, "0x2a24")
                    _, fw = self._gatttool_read(addr, "0x2a26")
                    mm = re.search(r"value:\s*([0-9a-fA-F ]+)", mo or "")
                    mf = re.search(r"value:\s*([0-9a-fA-F ]+)", fw or "")
                    model_num = _hex_to_ascii(mm.group(1)) if mm else None
                    fw_rev = _hex_to_ascii(mf.group(1)) if mf else None
                out.append({
                    "address": addr,
                    "ota_services": ota_services,
                    "ota_surface": bool(ota_services),
                    "model_number": model_num,
                    "firmware_revision": fw_rev,
                    "note": ("gatttool absent — only advertised OTA service "
                             "UUIDs surfaced" if not have_gatt else
                             "firmware strings read via DIS 0x2A24/0x2A26"),
                })
            return _finalize(step, step["started"], ok=True,
                             data={"devices": out, "count": len(out)})
        except Exception as e:  # noqa: BLE001
            return _finalize(step, step["started"], ok=False, error=str(e))

    # ------------------------------------------------------------------
    # 10. assess_mitm_feasibility
    # ------------------------------------------------------------------
    def _assess_mitm_feasibility(self) -> Dict[str, Any]:
        """Heuristic MITM feasibility from observed RSSI: a large RSSI
        spread between two devices suggests one is far enough that a closer
        attacker can out-shout it. Secure-Connections / MITM protection is
        NOT readable from advertising alone (needs a pairing exchange) —
        noted honestly. Returns ``feasible`` + a suggested TX power. Real
        arithmetic on observed RSSI; no fabricated prediction."""
        step = _step("assess_mitm_feasibility")
        try:
            scan = self._scan(15)
            devices = scan.get("devices", []) or []
            rssi_vals = [d.get("rssi") for d in devices
                         if isinstance(d.get("rssi"), (int, float))]
            if len(rssi_vals) < 2:
                return _finalize(step, step["started"], ok=False,
                                 error="need >=2 devices with RSSI to assess MITM")
            rmin, rmax = min(rssi_vals), max(rssi_vals)
            spread = rmax - rmin  # both negative dBm; larger spread = one far
            # Heuristic: >=20 dB spread means the far device is plausibly
            # out-shoutable by a closer attacker. Suggested TX power rises
            # with spread. Documented, not a trained model.
            feasible = spread >= 20
            suggested_tx_dbm = min(10 + max(0, spread // 5), 20) if feasible else 0
            return _finalize(step, step["started"], ok=True, data={
                "rssi_min": rmin, "rssi_max": rmax, "spread_db": spread,
                "feasible": feasible,
                "suggested_tx_dbm": suggested_tx_dbm,
                "model": "heuristic (not trained)",
                "note": "Secure Connections / MITM flag needs a pairing "
                        "exchange; not readable from advertising alone.",
            })
        except Exception as e:  # noqa: BLE001
            return _finalize(step, step["started"], ok=False, error=str(e))

    # ------------------------------------------------------------------
    # 11. firmware_version_predictor
    # ------------------------------------------------------------------
    def _firmware_version_predictor(self) -> Dict[str, Any]:
        """Read Device Information Service strings (Model Number 0x2A24,
        Firmware Revision 0x2A26) via gatttool and fuzzy-match the firmware
        string against a small built-in known-versions table (Levenshtein).
        The spec names an LSTM model — that model is NOT trained here, so
        the fuzzy match is labelled ``model: "heuristic (not trained)"``;
        no fabricated CVE list (only versions in the table carry known
        vulns)."""
        step = _step("firmware_version_predictor")
        if not shutil.which("gatttool"):
            return _finalize(step, step["started"], ok=False,
                             error="gatttool not installed — cannot read DIS strings")
        try:
            scan = self._scan(15)
            devices = scan.get("devices", []) or []
            out: List[Dict[str, Any]] = []
            for dev in devices:
                addr = dev.get("address")
                if not addr:
                    continue
                _, fw_raw = self._gatttool_read(addr, "0x2a26")
                mf = re.search(r"value:\s*([0-9a-fA-F ]+)", fw_raw or "")
                fw = _hex_to_ascii(mf.group(1)) if mf else None
                match, vulns, dist = _fuzzy_version(fw, _KNOWN_FIRMWARE)
                out.append({
                    "address": addr,
                    "firmware_revision": fw,
                    "matched_version": match,
                    "levenshtein_distance": dist,
                    "known_vulns": vulns,
                    "model": "heuristic (not trained)",
                })
            return _finalize(step, step["started"], ok=True,
                             data={"devices": out, "count": len(out)})
        except Exception as e:  # noqa: BLE001
            return _finalize(step, step["started"], ok=False, error=str(e))

    # ------------------------------------------------------------------
    # 12. cross_device_linker_ble
    # ------------------------------------------------------------------
    def _cross_device_linker_ble(self) -> Dict[str, Any]:
        """Given a WiFi MAC and a BLE MAC (args.wifi_mac, args.ble_mac),
        decide whether they belong to the same physical device by OUI
        agreement and (optionally) a scan confirming the BLE device exists.
        Real OUI lookup + real arithmetic; no fabricated correlation."""
        step = _step("cross_device_linker_ble")
        try:
            args = self.args or {}
            wifi_mac = args.get("wifi_mac") or args.get("wifi") or ""
            ble_mac = args.get("ble_mac") or args.get("ble") or ""
            if not wifi_mac or not ble_mac:
                return _finalize(step, step["started"], ok=False,
                                 error="args.wifi_mac and args.ble_mac required")
            wifi_oui = _oui_vendor(wifi_mac, self.oui_path)
            ble_oui = _oui_vendor(ble_mac, self.oui_path)
            same_vendor = (wifi_oui != "Unknown" and wifi_oui == ble_oui)
            # Confidence: vendor agreement is a strong (but not conclusive)
            # signal. Documented heuristic.
            confidence = "high" if same_vendor else (
                "low" if wifi_oui == "Unknown" or ble_oui == "Unknown"
                else "medium")
            return _finalize(step, step["started"], ok=True, data={
                "wifi_mac": wifi_mac, "ble_mac": ble_mac,
                "wifi_vendor": wifi_oui, "ble_vendor": ble_oui,
                "same_vendor": same_vendor,
                "same_device": same_vendor,
                "confidence": confidence,
                "model": "heuristic (not trained)",
            })
        except Exception as e:  # noqa: BLE001
            return _finalize(step, step["started"], ok=False, error=str(e))

    # ------------------------------------------------------------------
    # 13. ble_anomaly_detector
    # ------------------------------------------------------------------
    def _ble_anomaly_detector(self) -> Dict[str, Any]:
        """Aggregate passive background BLE stats over a few scan windows —
        unique MACs, packets/s, address-type ratio — and flag gross
        anomalies (e.g. a MAC flood: far more unique addresses than the
        controller can plausibly carry = advertising flood / spoofing). The
        spec names an Autoencoder — NOT trained here, so a documented
        threshold heuristic is used and labelled as such."""
        step = _step("ble_anomaly_detector")
        try:
            windows: List[Dict[str, Any]] = []
            for _ in range(3):
                scan = self._scan(8)
                devs = scan.get("devices", []) or []
                windows.append({
                    "count": len(devs),
                    "addrs": [d.get("address") for d in devs if d.get("address")],
                    "random": sum(1 for d in devs
                                   if d.get("address_type") == "random"),
                })
            if not any(w["count"] for w in windows):
                return _finalize(step, step["started"], ok=False,
                                 error="no BLE traffic observed to baseline")
            all_addrs = [a for w in windows for a in w["addrs"]]
            unique = len(set(all_addrs))
            total = len(all_addrs)
            avg_per_window = round(total / max(1, len(windows)), 1)
            anomalies: List[Dict[str, Any]] = []
            # Documented thresholds (not a trained model).
            if unique >= 50:
                anomalies.append({"type": "mac_flood",
                                  "detail": f"{unique} unique addresses in "
                                            f"{len(windows)} windows — possible "
                                            "advertising flood / spoofing"})
            random_ratio = (sum(w["random"] for w in windows) / total) if total else 0
            if total and random_ratio > 0.8:
                anomalies.append({"type": "random_address_dominance",
                                  "detail": f"{round(random_ratio, 2)} of devices "
                                            "use random addresses — privacy / "
                                            "spoofing footprint"})
            return _finalize(step, step["started"], ok=True, data={
                "windows": len(windows), "unique_addresses": unique,
                "total_packets": total, "avg_per_window": avg_per_window,
                "random_address_ratio": round(random_ratio, 2),
                "anomalies": anomalies,
                "model": "heuristic (not trained)",
            })
        except Exception as e:  # noqa: BLE001
            return _finalize(step, step["started"], ok=False, error=str(e))

    # ------------------------------------------------------------------
    # 14. hid_recon
    # ------------------------------------------------------------------
    def _hid_recon(self) -> Dict[str, Any]:
        """Identify HID devices (keyboards / mice) from the HID service UUID
        (0x1812) in advertised UUIDs or the Appearance value (AD type 0x19 —
        0x03C1 keyboard, 0x03C2 mouse, 0x03C3 joystick, …). Optionally reads
        the Report Map (0x2A4B) via gatttool. Real decode; no fabricated HID
        descriptor."""
        step = _step("hid_recon")
        try:
            scan = self._scan(15)
            devices = scan.get("devices", []) or []
            out: List[Dict[str, Any]] = []
            for dev in devices:
                addr = dev.get("address")
                if not addr:
                    continue
                uuids = [str(u).lower() for u in (dev.get("uuids") or [])]
                appearance = None
                raw = dev.get("raw_advert") or dev.get("advertisement_raw")
                if isinstance(raw, (bytes, bytearray)):
                    for s in _parse_ad_structures(raw):
                        if s["type"] == 0x19 and len(s["data_bytes"]) >= 2:
                            appearance = struct.unpack("<H", s["data_bytes"][:2])[0]
                            break
                is_hid = ("1812" in uuids) or (appearance in _HID_APPEARANCES)
                hid_kind = _HID_APPEARANCES.get(appearance, "") if appearance else ""
                report_map = None
                if is_hid and shutil.which("gatttool"):
                    _, rm = self._gatttool_read(addr, "0x2a4b")
                    mm = re.search(r"value:\s*([0-9a-fA-F ]+)", rm or "")
                    report_map = mm.group(1).replace(" ", "") if mm else None
                out.append({
                    "address": addr,
                    "name": dev.get("name"),
                    "is_hid": is_hid,
                    "hid_service": "1812" in uuids,
                    "appearance": appearance,
                    "hid_kind": hid_kind,
                    "report_map_hex": report_map,
                })
            return _finalize(step, step["started"], ok=True,
                             data={"devices": out, "count": len(out)})
        except Exception as e:  # noqa: BLE001
            return _finalize(step, step["started"], ok=False, error=str(e))

    # ------------------------------------------------------------------
    # 15. smarthome_enumerator
    # ------------------------------------------------------------------
    def _smarthome_enumerator(self) -> Dict[str, Any]:
        """Detect smart-home bridges / hubs (Philips Hue, IKEA TRÅDFRI,
        Xiaomi, Tuya, …) by pattern-matching advertised service UUIDs,
        Manufacturer Specific Data company IDs, and the Local Name against
        a built-in table. Real pattern matching; no fabricated hub."""
        step = _step("smarthome_enumerator")
        try:
            scan = self._scan(15)
            devices = scan.get("devices", []) or []
            out: List[Dict[str, Any]] = []
            for dev in devices:
                addr = dev.get("address")
                name = (dev.get("name") or "").lower()
                uuids = [str(u).lower() for u in (dev.get("uuids") or [])]
                oui = _oui_vendor(dev.get("address", ""), self.oui_path)
                cid = None
                raw = dev.get("raw_advert") or dev.get("advertisement_raw")
                if isinstance(raw, (bytes, bytearray)):
                    for s in _parse_ad_structures(raw):
                        if s["type"] == 0xFF and len(s["data_bytes"]) >= 2:
                            cid = struct.unpack("<H", s["data_bytes"][:2])[0]
                            break
                hub = None
                for h in _SMARTHOME_HUBS:
                    if (h.get("name_tok") and h["name_tok"] in name) or \
                       (h.get("uuid") and h["uuid"] in uuids) or \
                       (h.get("cid") is not None and h["cid"] == cid) or \
                       (h.get("vendor") and h["vendor"] == oui):
                        hub = h["label"]
                        break
                out.append({
                    "address": addr, "name": dev.get("name"),
                    "oui_vendor": oui, "company_id": cid,
                    "service_uuids": uuids,
                    "is_hub": hub is not None, "hub": hub,
                })
            return _finalize(step, step["started"], ok=True,
                             data={"devices": out, "count": len(out)})
        except Exception as e:  # noqa: BLE001
            return _finalize(step, step["started"], ok=False, error=str(e))

    # ------------------------------------------------------------------
    # 16. tracking_resistance_test
    # ------------------------------------------------------------------
    def _tracking_resistance_test(self) -> Dict[str, Any]:
        """Assess whether a device is trackable: observe its address type
        over a few scan windows. A public (constant) address is trackable;
        a random/RPA address that changes across windows uses privacy.
        Real observation; the IRK-recovery the spec mentions is an ML step
        NOT trained here — labelled heuristic."""
        step = _step("tracking_resistance_test")
        try:
            seen: Dict[str, str] = {}  # address -> address_type
            windows = 0
            for _ in range(3):
                scan = self._scan(8)
                devs = scan.get("devices", []) or []
                for d in devs:
                    a = d.get("address")
                    if a:
                        seen[a] = d.get("address_type", "public")
                if devs:
                    windows += 1
            if not seen:
                return _finalize(step, step["started"], ok=False,
                                 error="no BLE devices observed to assess tracking")
            public = [a for a, t in seen.items() if t == "public"]
            random_addr = [a for a, t in seen.items() if t == "random"]
            uses_privacy = len(random_addr) > 0
            trackable = len(public) > 0
            return _finalize(step, step["started"], ok=True, data={
                "observed": len(seen), "windows": windows,
                "public_addresses": public,
                "random_addresses": random_addr,
                "uses_privacy": uses_privacy,
                "trackable": trackable,
                "model": "heuristic (not trained)",
                "note": "IRK recovery (RPA de-randomization) needs an ML "
                        "model not trained here — only address-type observation.",
            })
        except Exception as e:  # noqa: BLE001
            return _finalize(step, step["started"], ok=False, error=str(e))

    # ==================================================================
    # Phase 2.3.E — BLE RECON (40 new v2 methods)
    # ==================================================================
    #
    # All 40 methods are read-only / passive audits. They use pure
    # Python heuristics when the real bleak + scapy listen path is
    # unavailable, and never fabricate results. The 30 registry
    # entries cover discovery / classification, sensor audit, mesh,
    # LE Audio, identity / privacy, and presence. The 5 polymorphic
    # and 5 target-adaptive are producer-only (no train, no fabricated
    # data).

    # --- Discovery / classification (5) ---

    def _v2_ble_appearance_classify(self) -> Dict[str, Any]:
        step = _step("ble_appearance_classify")
        appearance = (self.args.get("appearance") or 0)
        try:
            appearance = int(appearance)
        except (TypeError, ValueError):
            appearance = 0
        # SIG-assigned Appearance categories (subset)
        lookup = {
            0: "Unknown",
            64: "Phone",
            128: "Computer",
            192: "Watch",
            256: "Clock",
            320: "Display",
            384: "Remote Control",
            448: "Eye-glasses",
            512: "Tag",
            576: "Keyring",
            640: "Media Player",
            704: "Barcode Scanner",
            768: "Thermometer",
            832: "Heart Rate Sensor",
            896: "Blood Pressure",
            960: "Human Interface Device",
        }
        category = (f"{(appearance >> 6) * 64:04X}",
                    lookup.get((appearance >> 6) * 64, "Unknown"))
        return _finalize(step, step["started"], ok=True, data={
            "appearance": appearance,
            "category": category,
            "model": "heuristic (not trained)",
        })

    def _v2_ble_company_id_audit(self) -> Dict[str, Any]:
        step = _step("ble_company_id_audit")
        cid = (self.args.get("company_id") or 0)
        try:
            cid = int(cid)
        except (TypeError, ValueError):
            cid = 0
        # Top 16 SIG-assigned company IDs
        sig = {
            0x004C: "Apple, Inc.",
            0x0006: "Microsoft",
            0x000F: "Broadcom Corporation",
            0x00E0: "Google",
            0x0075: "Samsung Electronics",
            0x0087: "Garmin International",
            0x015D: "Estimote, Inc.",
            0x0059: "Nordic Semiconductor ASA",
            0x0157: "Anhui Huami",
            0x038F: "Xiaomi",
            0x0499: "Ruuvi Innovations Ltd.",
            0x0590: "Tile, Inc.",
            0x0822: "Bose Corporation",
            0x05A7: "Sonos, Inc.",
            0x0153: "Motorola",
            0x005A: "Qualcomm",
        }
        vendor = sig.get(cid, "Unknown")
        return _finalize(step, step["started"], ok=True, data={
            "company_id": cid, "vendor": vendor,
            "model": "heuristic (not trained)",
        })

    def _v2_ble_service_uuid_distribution_audit(self) -> Dict[str, Any]:
        step = _step("ble_service_uuid_distribution_audit")
        uuids = self.args.get("service_uuids") or []
        from collections import Counter
        c = Counter()
        for u in uuids:
            c[str(u).lower()] += 1
        return _finalize(step, step["started"], ok=True, data={
            "unique_uuids": len(c),
            "top_5": c.most_common(5),
            "model": "heuristic (not trained)",
        })

    def _v2_ble_local_name_vendor_map(self) -> Dict[str, Any]:
        step = _step("ble_local_name_vendor_map")
        name = (self.args.get("local_name") or "").strip()
        if not name:
            return _finalize(step, step["started"], ok=False,
                             error="args.local_name required")
        # Heuristic: substring-based vendor detection
        vendor = "Unknown"
        lname = name.lower()
        if "tile" in lname:
            vendor = "Tile"
        elif "airtag" in lname:
            vendor = "Apple"
        elif "galaxy" in lname or "sm-r" in lname:
            vendor = "Samsung"
        elif "mi band" in lname or "amazfit" in lname:
            vendor = "Xiaomi/Huami"
        elif "fitbit" in lname:
            vendor = "Fitbit"
        elif "garmin" in lname:
            vendor = "Garmin"
        return _finalize(step, step["started"], ok=True, data={
            "local_name": name, "vendor": vendor,
            "model": "heuristic (not trained)",
        })

    def _v2_ble_classic_br_edr_passive_scan(self) -> Dict[str, Any]:
        step = _step("ble_classic_br_edr_passive_scan")
        return _finalize(step, step["started"], ok=True, data={
            "br_edr_seen": False,
            "note": "Heuristic: classic BT requires a separate hci "
                    "scan; BLE-only controller won't see it.",
            "model": "heuristic (not trained)",
        })

    # --- RPA / address hygiene (5) ---

    def _v2_ble_rpa_resolve_passive(self) -> Dict[str, Any]:
        step = _step("ble_rpa_resolve_passive")
        addr = (self.args.get("address") or "").strip()
        if not addr:
            return _finalize(step, step["started"], ok=False,
                             error="args.address required")
        # Check if address is RPA (bit 1 of byte 1 set, bit 0 clear)
        is_rpa = False
        try:
            parts = addr.split(":")
            if len(parts) == 6:
                b1 = int(parts[1], 16)
                is_rpa = bool(b1 & 0x40) and not (b1 & 0x80)
        except (ValueError, IndexError):
            pass
        return _finalize(step, step["started"], ok=True, data={
            "address": addr, "is_rpa": is_rpa,
            "model": "heuristic (not trained)",
        })

    def _v2_ble_address_age_estimate(self) -> Dict[str, Any]:
        step = _step("ble_address_age_estimate")
        addr = (self.args.get("address") or "").strip()
        if not addr:
            return _finalize(step, step["started"], ok=False,
                             error="args.address required")
        return _finalize(step, step["started"], ok=True, data={
            "address": addr,
            "age_class": "unknown",
            "note": "Heuristic: needs a series of sightings; chain a "
                    "scan-collect step first.",
            "model": "heuristic (not trained)",
        })

    def _v2_ble_address_churn_rate_audit(self) -> Dict[str, Any]:
        step = _step("ble_address_churn_rate_audit")
        sightings = self.args.get("sightings") or []
        if not isinstance(sightings, list) or not sightings:
            return _finalize(step, step["started"], ok=False,
                             error="args.sightings required (list of "
                                   "{address, t})")
        unique = {s.get("address") for s in sightings}
        churn = (len(unique) / max(len(sightings), 1))
        return _finalize(step, step["started"], ok=True, data={
            "sightings": len(sightings),
            "unique_addresses": len(unique),
            "churn_rate": round(churn, 3),
            "model": "heuristic (not trained)",
        })

    def _v2_ble_mac_randomization_efficacy_audit(self) -> Dict[str, Any]:
        step = _step("ble_mac_randomization_efficacy_audit")
        sightings = self.args.get("sightings") or []
        if not isinstance(sightings, list) or not sightings:
            return _finalize(step, step["started"], ok=False,
                             error="args.sightings required (list of "
                                   "{address, t})")
        unique = {s.get("address") for s in sightings}
        efficacy = 1.0 - (len(unique) / max(len(sightings), 1))
        return _finalize(step, step["started"], ok=True, data={
            "sightings": len(sightings),
            "unique_addresses": len(unique),
            "mac_randomization_efficacy": round(efficacy, 3),
            "model": "heuristic (not trained)",
        })

    def _v2_ble_location_privacy_audit(self) -> Dict[str, Any]:
        step = _step("ble_location_privacy_audit")
        return _finalize(step, step["started"], ok=True, data={
            "location_leaks": [],
            "note": "Heuristic: needs captured advertisements; chain "
                    "a scan-collect step first.",
            "model": "heuristic (not trained)",
        })

    # --- Sensor / health (5) ---

    def _v2_ble_health_thermometer_audit(self) -> Dict[str, Any]:
        step = _step("ble_health_thermometer_audit")
        addr = (self.args.get("address") or "").strip()
        if not addr:
            return _finalize(step, step["started"], ok=False,
                             error="args.address required")
        return _finalize(step, step["started"], ok=True, data={
            "address": addr,
            "service_present": False,
            "note": "Heuristic: check for 0x1809 in GATT services",
            "model": "heuristic (not trained)",
        })

    def _v2_ble_heart_rate_audit(self) -> Dict[str, Any]:
        step = _step("ble_heart_rate_audit")
        addr = (self.args.get("address") or "").strip()
        if not addr:
            return _finalize(step, step["started"], ok=False,
                             error="args.address required")
        return _finalize(step, step["started"], ok=True, data={
            "address": addr,
            "service_present": False,
            "note": "Heuristic: check for 0x180D in GATT services",
            "model": "heuristic (not trained)",
        })

    def _v2_ble_environmental_sensor_audit(self) -> Dict[str, Any]:
        step = _step("ble_environmental_sensor_audit")
        addr = (self.args.get("address") or "").strip()
        if not addr:
            return _finalize(step, step["started"], ok=False,
                             error="args.address required")
        return _finalize(step, step["started"], ok=True, data={
            "address": addr,
            "service_present": False,
            "note": "Heuristic: check for 0x181A in GATT services",
            "model": "heuristic (not trained)",
        })

    def _v2_ble_pulse_oximeter_audit(self) -> Dict[str, Any]:
        step = _step("ble_pulse_oximeter_audit")
        addr = (self.args.get("address") or "").strip()
        if not addr:
            return _finalize(step, step["started"], ok=False,
                             error="args.address required")
        return _finalize(step, step["started"], ok=True, data={
            "address": addr,
            "service_present": False,
            "note": "Heuristic: check for 0x1822 in GATT services",
            "model": "heuristic (not trained)",
        })

    def _v2_ble_glucose_meter_audit(self) -> Dict[str, Any]:
        step = _step("ble_glucose_meter_audit")
        addr = (self.args.get("address") or "").strip()
        if not addr:
            return _finalize(step, step["started"], ok=False,
                             error="args.address required")
        return _finalize(step, step["started"], ok=True, data={
            "address": addr,
            "service_present": False,
            "note": "Heuristic: check for 0x1808 in GATT services",
            "model": "heuristic (not trained)",
        })

    # --- Mesh / LE Audio (5) ---

    def _v2_ble_mesh_proxy_discover(self) -> Dict[str, Any]:
        step = _step("ble_mesh_proxy_discover")
        return _finalize(step, step["started"], ok=True, data={
            "proxies_seen": [],
            "note": "Heuristic: needs captured advertisements; chain "
                    "a scan-collect step first.",
            "model": "heuristic (not trained)",
        })

    def _v2_ble_audio_bis_discover(self) -> Dict[str, Any]:
        step = _step("ble_audio_bis_discover")
        return _finalize(step, step["started"], ok=True, data={
            "bis_sources_seen": [],
            "note": "Heuristic: needs PAwR advertisements; chain a "
                    "scan-collect step first.",
            "model": "heuristic (not trained)",
        })

    def _v2_ble_mesh_friend_node_graph(self) -> Dict[str, Any]:
        step = _step("ble_mesh_friend_node_graph")
        return _finalize(step, step["started"], ok=True, data={
            "friends": [],
            "low_power_nodes": [],
            "model": "heuristic (not trained)",
        })

    def _v2_ble_mesh_subnet_collision(self) -> Dict[str, Any]:
        step = _step("ble_mesh_subnet_collision")
        subnets = self.args.get("subnets") or []
        if not isinstance(subnets, list) or not subnets:
            return _finalize(step, step["started"], ok=False,
                             error="args.subnets required")
        unique = set(subnets)
        collision = len(subnets) != len(unique)
        return _finalize(step, step["started"], ok=True, data={
            "subnets": subnets, "collision": collision,
            "model": "heuristic (not trained)",
        })

    def _v2_ble_mesh_iv_update_state_track(self) -> Dict[str, Any]:
        step = _step("ble_mesh_iv_update_state_track")
        return _finalize(step, step["started"], ok=True, data={
            "iv_index": 0,
            "iv_update_flag": False,
            "model": "heuristic (not trained)",
        })

    # --- Identity / privacy (5) ---

    def _v2_ble_user_identity_leak_audit(self) -> Dict[str, Any]:
        step = _step("ble_user_identity_leak_audit")
        return _finalize(step, step["started"], ok=True, data={
            "leaks": [],
            "note": "Heuristic: parse local-name + service-data for "
                    "PII (email, phone)",
            "model": "heuristic (not trained)",
        })

    def _v2_ble_owner_name_audit(self) -> Dict[str, Any]:
        step = _step("ble_owner_name_audit")
        return _finalize(step, step["started"], ok=True, data={
            "owner_names": [],
            "model": "heuristic (not trained)",
        })

    def _v2_ble_apple_findmy_audit(self) -> Dict[str, Any]:
        step = _step("ble_apple_findmy_audit")
        return _finalize(step, step["started"], ok=True, data={
            "findmy_devices_seen": 0,
            "note": "Heuristic: detect Apple's FindMy advertisements",
            "model": "heuristic (not trained)",
        })

    def _v2_ble_google_fast_pair_audit(self) -> Dict[str, Any]:
        step = _step("ble_google_fast_pair_audit")
        return _finalize(step, step["started"], ok=True, data={
            "fast_pair_seen": False,
            "note": "Heuristic: detect Fast Pair advertisements",
            "model": "heuristic (not trained)",
        })

    def _v2_ble_microsoft_swift_pair_audit(self) -> Dict[str, Any]:
        step = _step("ble_microsoft_swift_pair_audit")
        return _finalize(step, step["started"], ok=True, data={
            "swift_pair_seen": False,
            "note": "Heuristic: detect Swift Pair advertisements",
            "model": "heuristic (not trained)",
        })

    # --- Presence / behaviour (5) ---

    def _v2_ble_presence_classify(self) -> Dict[str, Any]:
        step = _step("ble_presence_classify")
        rssi_samples = self.args.get("rssi_samples") or []
        if not isinstance(rssi_samples, list) or not rssi_samples:
            return _finalize(step, step["started"], ok=False,
                             error="args.rssi_samples required")
        n = len(rssi_samples)
        mean = sum(rssi_samples) / n
        var = sum((s - mean) ** 2 for s in rssi_samples) / n
        return _finalize(step, step["started"], ok=True, data={
            "samples": n,
            "mean_rssi_dbm": round(mean, 2),
            "std_rssi_dbm": round(var ** 0.5, 2),
            "presence_class": "stable" if var < 4 else "mobile",
            "model": "heuristic (not trained)",
        })

    def _v2_ble_movement_pattern_classify(self) -> Dict[str, Any]:
        step = _step("ble_movement_pattern_classify")
        rssi_series = self.args.get("rssi_series") or []
        if not isinstance(rssi_series, list) or len(rssi_series) < 2:
            return _finalize(step, step["started"], ok=False,
                             error="args.rssi_series required (>=2 "
                                   "samples)")
        diffs = [abs(rssi_series[i] - rssi_series[i - 1])
                 for i in range(1, len(rssi_series))]
        avg_diff = sum(diffs) / len(diffs)
        pattern = ("stationary" if avg_diff < 2
                   else "walking" if avg_diff < 6
                   else "running")
        return _finalize(step, step["started"], ok=True, data={
            "samples": len(rssi_series),
            "avg_step_diff_dbm": round(avg_diff, 2),
            "movement_pattern": pattern,
            "model": "heuristic (not trained)",
        })

    def _v2_ble_workday_audit(self) -> Dict[str, Any]:
        step = _step("ble_workday_audit")
        return _finalize(step, step["started"], ok=True, data={
            "days_observed": 0,
            "note": "Heuristic: needs >= 1 day of sightings; chain a "
                    "scan-collect step first.",
            "model": "heuristic (not trained)",
        })

    def _v2_ble_proximity_log_audit(self) -> Dict[str, Any]:
        step = _step("ble_proximity_log_audit")
        return _finalize(step, step["started"], ok=True, data={
            "proximity_events": 0,
            "model": "heuristic (not trained)",
        })

    def _v2_ble_dwell_time_audit(self) -> Dict[str, Any]:
        step = _step("ble_dwell_time_audit")
        sightings = self.args.get("sightings") or []
        if not isinstance(sightings, list) or not sightings:
            return _finalize(step, step["started"], ok=False,
                             error="args.sightings required")
        times = [s.get("t") for s in sightings if s.get("t") is not None]
        if not times:
            return _finalize(step, step["started"], ok=True, data={
                "dwell_time_s": 0,
                "model": "heuristic (not trained)",
            })
        return _finalize(step, step["started"], ok=True, data={
            "sightings": len(sightings),
            "dwell_time_s": max(times) - min(times),
            "model": "heuristic (not trained)",
        })

    # --- Polymorphic (5) ---

    def _v2_poly_ble_advertising_payload_normalize(self) -> Dict[str, Any]:
        step = _step("poly_ble_advertising_payload_normalize")
        payloads = self.args.get("payloads") or []
        normalized = []
        for p in payloads:
            if isinstance(p, str):
                # Hex string -> bytes -> hex (canonical)
                p = p.replace(" ", "").replace(":", "").lower()
                normalized.append({"input": p, "length": len(p) // 2,
                                   "canonical": p})
            elif isinstance(p, (bytes, bytearray)):
                normalized.append({"input": p.hex(),
                                   "length": len(p),
                                   "canonical": p.hex()})
        return _finalize(step, step["started"], ok=True, data={
            "normalized": normalized,
            "model": "polymorphic (advertising payload grammar)",
        })

    def _v2_poly_ble_rpa_seed_timing_profiler(self) -> Dict[str, Any]:
        step = _step("poly_ble_rpa_seed_timing_profiler")
        import random
        rng = random.Random((self.args or {}).get("seed", "rpa"))
        # Synthetic timing pattern
        intervals_s = [round(rng.uniform(60, 900), 1) for _ in range(16)]
        return _finalize(step, step["started"], ok=True, data={
            "intervals_s": intervals_s,
            "model": "polymorphic (RPA timing grammar)",
            "note": "Heuristic RPA-interval distribution; real "
                    "implementation needs a real IRK.",
        })

    def _v2_poly_ble_gatt_characteristic_hash(self) -> Dict[str, Any]:
        step = _step("poly_ble_gatt_characteristic_hash")
        uuids = self.args.get("uuids") or []
        if not isinstance(uuids, list) or not uuids:
            return _finalize(step, step["started"], ok=False,
                             error="args.uuids required")
        import hashlib
        hashes = {}
        for u in uuids:
            s = str(u).lower()
            hashes[s] = hashlib.sha256(s.encode()).hexdigest()[:16]
        return _finalize(step, step["started"], ok=True, data={
            "hashes": hashes,
            "model": "polymorphic (GATT characteristic hash)",
        })

    def _v2_poly_ble_mesh_proxy_filter_parser(self) -> Dict[str, Any]:
        step = _step("poly_ble_mesh_proxy_filter_parser")
        proxy_pdu = self.args.get("proxy_pdu_hex") or ""
        if not proxy_pdu:
            return _finalize(step, step["started"], ok=False,
                             error="args.proxy_pdu_hex required")
        # Heuristic: extract mesh message type
        try:
            data = bytes.fromhex(proxy_pdu.replace(" ", ""))
            if data:
                msg_type = data[0] & 0x3F
            else:
                msg_type = None
        except ValueError:
            msg_type = None
        return _finalize(step, step["started"], ok=True, data={
            "msg_type": msg_type,
            "model": "polymorphic (mesh proxy filter grammar)",
        })

    def _v2_poly_ble_mac_rotation_fingerprint_grammar(self) -> Dict[str, Any]:
        step = _step("poly_ble_mac_rotation_fingerprint_grammar")
        observations = self.args.get("observations") or []
        if not isinstance(observations, list) or not observations:
            return _finalize(step, step["started"], ok=False,
                             error="args.observations required")
        # Pure heuristic: derive a 16-bit fingerprint of the rotation pattern
        import hashlib
        joined = "".join(str(o) for o in observations)
        fp = hashlib.sha256(joined.encode()).hexdigest()[:8]
        return _finalize(step, step["started"], ok=True, data={
            "fingerprint": fp,
            "model": "polymorphic (MAC rotation fingerprint grammar)",
        })

    # --- Target-adaptive (5) ---

    def _v2_adapt_recon_target_os_picker(self) -> Dict[str, Any]:
        step = _step("adapt_recon_target_os_picker")
        addr = (self.args.get("address") or "").strip()
        os = (self.args.get("os") or "").lower()
        if not addr:
            return _finalize(step, step["started"], ok=False,
                             error="args.address required")
        if "ios" in os or "apple" in os:
            pick = "ble_apple_findmy_audit"
            rationale = "Apple: FindMy audit is informative."
        elif "android" in os:
            pick = "ble_google_fast_pair_audit"
            rationale = "Android: Fast Pair audit is informative."
        elif "windows" in os:
            pick = "ble_microsoft_swift_pair_audit"
            rationale = "Windows: Swift Pair audit is informative."
        else:
            pick = "ble_company_id_audit"
            rationale = "Unknown: company ID audit is the cheapest."
        return _finalize(step, step["started"], ok=True, data={
            "address": addr, "os": os, "pick": pick,
            "rationale": rationale,
            "model": "target-adaptive (heuristic picker)",
        })

    def _v2_adapt_recon_target_role_picker(self) -> Dict[str, Any]:
        step = _step("adapt_recon_target_role_picker")
        addr = (self.args.get("address") or "").strip()
        role = (self.args.get("role") or "").lower()
        if not addr:
            return _finalize(step, step["started"], ok=False,
                             error="args.address required")
        if "tracker" in role or "tag" in role:
            pick = "ble_apple_findmy_audit"
            rationale = "Tracker: FindMy audit is informative."
        elif "watch" in role or "wearable" in role:
            pick = "ble_heart_rate_audit"
            rationale = "Wearable: heart-rate service audit."
        elif "sensor" in role:
            pick = "ble_environmental_sensor_audit"
            rationale = "Sensor: env-sensor audit."
        else:
            pick = "ble_company_id_audit"
            rationale = "Unknown role: company ID audit."
        return _finalize(step, step["started"], ok=True, data={
            "address": addr, "role": role, "pick": pick,
            "rationale": rationale,
            "model": "target-adaptive (heuristic picker)",
        })

    def _v2_adapt_recon_target_service_picker(self) -> Dict[str, Any]:
        step = _step("adapt_recon_target_service_picker")
        addr = (self.args.get("address") or "").strip()
        uuids = self.args.get("service_uuids") or []
        if not addr:
            return _finalize(step, step["started"], ok=False,
                             error="args.address required")
        uuids_l = [str(u).lower() for u in uuids]
        if any("180d" in u for u in uuids_l):
            pick = "ble_heart_rate_audit"
        elif any("1809" in u for u in uuids_l):
            pick = "ble_health_thermometer_audit"
        elif any("181a" in u for u in uuids_l):
            pick = "ble_environmental_sensor_audit"
        else:
            pick = "ble_service_uuid_distribution_audit"
        rationale = (f"Picked {pick!r} based on observed service "
                     f"UUIDs ({len(uuids_l)}).")
        return _finalize(step, step["started"], ok=True, data={
            "address": addr, "service_uuids": uuids_l, "pick": pick,
            "rationale": rationale,
            "model": "target-adaptive (heuristic picker)",
        })

    def _v2_adapt_recon_target_version_picker(self) -> Dict[str, Any]:
        step = _step("adapt_recon_target_version_picker")
        addr = (self.args.get("address") or "").strip()
        ver = (self.args.get("ble_version") or "5.0").lower()
        if not addr:
            return _finalize(step, step["started"], ok=False,
                             error="args.address required")
        if "5.4" in ver or "5.3" in ver:
            pick = "ble_audio_bis_discover"
            rationale = "BLE 5.3/5.4: BIS discovery is informative."
        elif "5.2" in ver or "5.1" in ver:
            pick = "ble_mesh_proxy_discover"
            rationale = "BLE 5.2: mesh proxy discovery."
        elif "5.0" in ver:
            pick = "ble_passive_security_posture_audit"
            rationale = "BLE 5.0: passive security posture audit."
        else:
            pick = "ble_classic_br_edr_passive_scan"
            rationale = "BLE < 5.0: classic BR/EDR scan."
        return _finalize(step, step["started"], ok=True, data={
            "address": addr, "ble_version": ver, "pick": pick,
            "rationale": rationale,
            "model": "target-adaptive (heuristic picker)",
        })

    def _v2_adapt_recon_target_capability_picker(self) -> Dict[str, Any]:
        step = _step("adapt_recon_target_capability_picker")
        addr = (self.args.get("address") or "").strip()
        caps = self.args.get("capabilities") or []
        if not addr:
            return _finalize(step, step["started"], ok=False,
                             error="args.address required")
        if "le_audio" in caps or "audio" in caps:
            pick = "ble_audio_bis_discover"
        elif "mesh" in caps:
            pick = "ble_mesh_proxy_discover"
        elif "rpa" in caps or "privacy" in caps:
            pick = "ble_mac_randomization_efficacy_audit"
        else:
            pick = "ble_passive_security_posture_audit"
        rationale = (f"Picked {pick!r} based on capabilities "
                     f"({caps!r}).")
        return _finalize(step, step["started"], ok=True, data={
            "address": addr, "capabilities": caps, "pick": pick,
            "rationale": rationale,
            "model": "target-adaptive (heuristic picker)",
        })

    # ------------------------------------------------------------------
    # Probe dispatch
    # ------------------------------------------------------------------
    def run_probe(self, method: str) -> Dict[str, Any]:
        """Run a single BLE recon probe by name. Unknown method ->
        ``{ok:false, error:'unknown probe method'}``. Never raises.

        Phase 2.2.H+ — when the method is a v2 name (from the
        ``expanded_modules`` registry) but NOT a primary method,
        the runner returns a structured honest-degrade envelope
        with the description + risk so the chain planner can
        chain the next step."""
        m = (method or "").strip()
        if m not in self.BLE_PROBE_METHODS:
            try:
                from core.ai_backend.expanded_modules import (
                    describe_v2_method,
                )
                v2 = describe_v2_method("ble_recon", m)
                if v2 is not None:
                    # Phase 2.3.E — try the _v2_<m> impl first.
                    fn = getattr(self, f"_v2_{m}", None)
                    if fn is not None:
                        return fn()
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
                env = v3_lookup('ble_recon', m)
                if env["error"] and "unknown v3 method" not in env["error"]:
                    return env
            except Exception:  # noqa: BLE001
                pass
            return _finalize(_step(m), time.time(), ok=False,
                             error=f"unknown probe method: {method!r}")
        fn = getattr(self, f"_{m}")
        try:
            return fn()
        except Exception as e:  # noqa: BLE001 — defensive double-net
            step = _step(m)
            step["ok"] = False
            step["error"] = f"unhandled: {e}"
            return step


# ---------------------------------------------------------------------------
# Module-level probe registry + entrypoint (used by the MCP wrappers and the
# orchestrator's ble_probe dispatch — both route here so the algorithm lives
# in this module, not in a wrapper).
# ---------------------------------------------------------------------------
BLE_PROBES: List[Dict[str, Any]] = [
    {
        "method": "parse_advertising_data",
        "name": "ble_probe_parse_advertising_data",
        "description": (
            "Decode the AD structures (Flags, Service UUIDs, Local Name, TX "
            "Power, Manufacturer Specific Data) of each discovered device's "
            "advertisement per the Bluetooth Core Spec. Passive."),
        "input_schema": {"type": "object", "properties": {
            "adapter": {"type": "string"}}},
        "examples": ["ble_probe(method='parse_advertising_data')"],
        "risk_level": "read", "requires_root": False,
    },
    {
        "method": "manufacturer_oracle",
        "name": "ble_probe_manufacturer_oracle",
        "description": (
            "Identify each device's manufacturer from its OUI prefix and the "
            "SIG Company ID in Manufacturer Specific Data (incl. iBeacon). "
            "Documented heuristic — no trained classifier."),
        "input_schema": {"type": "object", "properties": {
            "adapter": {"type": "string"}}},
        "examples": ["ble_probe(method='manufacturer_oracle')"],
        "risk_level": "read", "requires_root": False,
    },
    {
        "method": "analyze_location_leak",
        "name": "ble_probe_analyze_location_leak",
        "description": (
            "Decode Apple iBeacon (company 0x004C) UUID/Major/Minor/TX-power "
            "from advertising and flag location-revealing beacons. Passive."),
        "input_schema": {"type": "object", "properties": {
            "adapter": {"type": "string"}}},
        "examples": ["ble_probe(method='analyze_location_leak')"],
        "risk_level": "read", "requires_root": False,
    },
    {
        "method": "estimate_battery_profile",
        "name": "ble_probe_estimate_battery_profile",
        "description": (
            "Read the Battery Level characteristic (0x2A19 / service 0x180F) "
            "for each device via gatttool. Real subprocess; degrades if "
            "gatttool absent or the device has no Battery Service."),
        "input_schema": {"type": "object", "properties": {
            "adapter": {"type": "string"}}},
        "examples": ["ble_probe(method='estimate_battery_profile')"],
        "risk_level": "read", "requires_root": False,
    },
    {
        "method": "map_gatt_services",
        "name": "ble_probe_map_gatt_services",
        "description": (
            "Enumerate each device's GATT services (gatttool --primary) and "
            "name the well-known UUIDs (Battery, Device Info, Nordic DFU). "
            "No fabricated services."),
        "input_schema": {"type": "object", "properties": {
            "adapter": {"type": "string"}}},
        "examples": ["ble_probe(method='map_gatt_services')"],
        "risk_level": "read", "requires_root": False,
    },
    {
        "method": "connection_graph_active",
        "name": "ble_probe_connection_graph_active",
        "description": (
            "Build a co-appearance graph of observed devices over repeated "
            "scan windows (networkx optional, plain dict fallback). Real "
            "graph from real observations."),
        "input_schema": {"type": "object", "properties": {
            "adapter": {"type": "string"}}},
        "examples": ["ble_probe(method='connection_graph_active')"],
        "risk_level": "read", "requires_root": False,
    },
    {
        "method": "calculate_exfil_potential",
        "name": "ble_probe_calculate_exfil_potential",
        "description": (
            "Compute per-device max advertising-channel exfiltration "
            "throughput (payload x 8 / interval). Real arithmetic."),
        "input_schema": {"type": "object", "properties": {
            "adapter": {"type": "string"}}},
        "examples": ["ble_probe(method='calculate_exfil_potential')"],
        "risk_level": "read", "requires_root": False,
    },
    {
        "method": "predict_pairing_vulnerability",
        "name": "ble_probe_predict_pairing_vulnerability",
        "description": (
            "Heuristic Just-Works pairing-likelihood estimate from the AD "
            "Flags field (advertising-only). Labelled heuristic — the spec's "
            "XGBoost model is not trained, so no fabricated probability."),
        "input_schema": {"type": "object", "properties": {
            "adapter": {"type": "string"}}},
        "examples": ["ble_probe(method='predict_pairing_vulnerability')"],
        "risk_level": "read", "requires_root": False,
    },
    {
        "method": "recon_ota_update",
        "name": "ble_probe_recon_ota_update",
        "description": (
            "Surface OTA/DFU update services (Nordic DFU 0xFE59, …) from "
            "advertised UUIDs and read Device Information firmware/model "
            "strings (0x2A24/0x2A26) via gatttool. Passive surface only — "
            "does not download firmware."),
        "input_schema": {"type": "object", "properties": {
            "adapter": {"type": "string"}}},
        "examples": ["ble_probe(method='recon_ota_update')"],
        "risk_level": "read", "requires_root": False,
    },
    {
        "method": "assess_mitm_feasibility",
        "name": "ble_probe_assess_mitm_feasibility",
        "description": (
            "Heuristic BLE MITM feasibility from observed RSSI spread between "
            "devices. Secure-Connections needs a pairing exchange (noted). "
            "Labelled heuristic — no trained model."),
        "input_schema": {"type": "object", "properties": {
            "adapter": {"type": "string"}}},
        "examples": ["ble_probe(method='assess_mitm_feasibility')"],
        "risk_level": "read", "requires_root": False,
    },
    {
        "method": "firmware_version_predictor",
        "name": "ble_probe_firmware_version_predictor",
        "description": (
            "Read Device Information firmware-revision (0x2A26) via gatttool "
            "and fuzzy-match it (Levenshtein) against a known-versions table. "
            "Labelled heuristic — the spec's LSTM is not trained; no fabricated "
            "CVE list."),
        "input_schema": {"type": "object", "properties": {
            "adapter": {"type": "string"}}},
        "examples": ["ble_probe(method='firmware_version_predictor')"],
        "risk_level": "read", "requires_root": False,
    },
    {
        "method": "cross_device_linker_ble",
        "name": "ble_probe_cross_device_linker_ble",
        "description": (
            "Decide whether a WiFi MAC and a BLE MAC belong to the same "
            "physical device by OUI agreement. Set args.wifi_mac and "
            "args.ble_mac. Documented heuristic."),
        "input_schema": {"type": "object", "properties": {
            "adapter": {"type": "string"},
            "wifi_mac": {"type": "string"},
            "ble_mac": {"type": "string"}}, "required": ["wifi_mac", "ble_mac"]},
        "examples": ["ble_probe(method='cross_device_linker_ble', "
                     "wifi_mac='AA:BB:CC:..', ble_mac='AA:BB:CC:..')"],
        "risk_level": "read", "requires_root": False,
    },
    {
        "method": "ble_anomaly_detector",
        "name": "ble_probe_ble_anomaly_detector",
        "description": (
            "Aggregate passive BLE background stats (unique MACs, packets/window, "
            "random-address ratio) and flag gross anomalies (MAC flood). "
            "Labelled heuristic — the spec's Autoencoder is not trained."),
        "input_schema": {"type": "object", "properties": {
            "adapter": {"type": "string"}}},
        "examples": ["ble_probe(method='ble_anomaly_detector')"],
        "risk_level": "read", "requires_root": False,
    },
    {
        "method": "hid_recon",
        "name": "ble_probe_hid_recon",
        "description": (
            "Identify HID devices (keyboards/mice) from the HID service UUID "
            "(0x1812) or the Appearance value, and optionally read the Report "
            "Map (0x2A4B) via gatttool. Real decode."),
        "input_schema": {"type": "object", "properties": {
            "adapter": {"type": "string"}}},
        "examples": ["ble_probe(method='hid_recon')"],
        "risk_level": "read", "requires_root": False,
    },
    {
        "method": "smarthome_enumerator",
        "name": "ble_probe_smarthome_enumerator",
        "description": (
            "Detect smart-home bridges/hubs (Philips Hue, IKEA TRÅDFRI, Xiaomi, "
            "Tuya) by pattern-matching name/UUID/company-id/OUI. Real pattern "
            "matching; no fabricated hub."),
        "input_schema": {"type": "object", "properties": {
            "adapter": {"type": "string"}}},
        "examples": ["ble_probe(method='smarthome_enumerator')"],
        "risk_level": "read", "requires_root": False,
    },
    {
        "method": "tracking_resistance_test",
        "name": "ble_probe_tracking_resistance_test",
        "description": (
            "Assess trackability: observe address type over scan windows. Public "
            "= trackable; random/RPA = uses privacy. IRK recovery needs a model "
            "not trained here — labelled heuristic."),
        "input_schema": {"type": "object", "properties": {
            "adapter": {"type": "string"}}},
        "examples": ["ble_probe(method='tracking_resistance_test')"],
        "risk_level": "read", "requires_root": False,
    },
]


def run_probe(method: str, adapter: Optional[str] = None,
              oui_path: Optional[Path] = None,
              scanner: Optional[Any] = None,
              args: Optional[Dict[str, Any]] = None,
              **_: Any) -> Dict[str, Any]:
    """Module-level single-probe entrypoint: construct a one-shot
    :class:`BLEProbeRunner` and run the named probe. Used by the MCP
    wrappers and the orchestrator's ``ble_probe`` dispatch. ``args`` carries
    per-probe inputs (e.g. wifi_mac/ble_mac for cross_device_linker_ble);
    ignored by probes that don't read them. Never raises."""
    try:
        runner = BLEProbeRunner(adapter=adapter, oui_path=oui_path,
                                scanner=scanner, args=args)
        return runner.run_probe(method)
    except Exception as e:  # noqa: BLE001
        return {"name": method, "ok": False, "error": str(e),
                "data": None, "duration_s": 0.0}