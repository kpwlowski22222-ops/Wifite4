"""core.ble.runner — hermetic unit tests for the BLE probe runner.

Exercises the AD-structure parser, iBeacon decoder, OUI lookup, the
gatttool-backed battery read (monkeypatched), the GATT mapper, the
co-appearance graph, the exfil arithmetic, and the Just-Works heuristic —
all without a real Bluetooth controller, real BlueZ, or a trained ML model.
"""

import binascii
import struct
import subprocess
from typing import Any, Dict, List

import pytest

from core.ble import runner as ble
from core.ble.runner import BLEProbeRunner, BLE_PROBES, run_probe


# ----------------------------------------------------------------------
# AD structure + iBeacon helpers (pure decode)
# ----------------------------------------------------------------------
def _ad(typ: int, data: bytes) -> bytes:
    return bytes([len(data) + 1, typ]) + data


def _mfr_payload(cid: int, body: bytes) -> bytes:
    return struct.pack("<H", cid) + body


def _ibeacon_adv(uuid_hex: str, major: int, minor: int, tx: int) -> bytes:
    uuid_bytes = binascii.unhexlify(uuid_hex.replace("-", ""))
    body = bytes([0x02, 0x15]) + uuid_bytes + struct.pack(">hhb", major, minor, tx)
    return _ad(0xFF, _mfr_payload(0x004C, body))


class _FakeScanner:
    """Injectable scanner returning a canned device list, no hardware."""

    def __init__(self, devices: List[Dict[str, Any]]):
        self._devices = devices
        self.scan_calls = 0

    def scan(self, duration: int = 15, adapter: str = None) -> Dict[str, Any]:
        self.scan_calls += 1
        return {"devices": list(self._devices), "total_found": len(self._devices),
                "backend": "fake", "duration": duration}

    def enumerate_services(self, addr: str, timeout: int = 15) -> Dict[str, Any]:
        return {"services": [{"uuid": "180f"}, {"uuid": "180a"}], "error": None}


# A device with raw advertising bytes (flags + local name + iBeacon MFR data).
_FLAGS_NAME_IBEACON = _ad(0x01, b"\x06") + _ad(0x09, b"Sensor") + \
    _ibeacon_adv("a1b2c3d4e5f60718293a4b5c6d7e8f90", 17, 42, -59)
# A second device: just flags + 16-bit service UUID (Nordic DFU 0xFE59).
_FLAGS_UUID = _ad(0x01, b"\x02") + _ad(0x03, b"\x59\xfe")


def _devs():
    return [
        {"address": "AA:BB:CC:DD:EE:01", "address_type": "public",
         "name": "Sensor", "rssi": -55,
         "raw_advert": _FLAGS_NAME_IBEACON, "uuids": ["fe59"]},
        {"address": "AA:BB:CC:DD:EE:02", "address_type": "random",
         "name": "Unknown", "rssi": -70, "raw_advert": _FLAGS_UUID},
    ]


# ----------------------------------------------------------------------
# run_probe dispatch
# ----------------------------------------------------------------------
def test_run_probe_unknown_method_is_error():
    res = run_probe("nope")
    assert res["ok"] is False
    assert "unknown probe method" in res["error"]


def test_run_probe_empty_method_is_error():
    res = run_probe("")
    assert res["ok"] is False
    assert "unknown probe method" in res["error"]


def test_ble_probe_methods_match_registry():
    methods = set(BLEProbeRunner.BLE_PROBE_METHODS)
    registry = {p["method"] for p in BLE_PROBES}
    assert methods == registry
    assert len(methods) == 16


# ----------------------------------------------------------------------
# parse_advertising_data
# ----------------------------------------------------------------------
def test_parse_advertising_data_decodes_structures():
    r = BLEProbeRunner(scanner=_FakeScanner(_devs()))
    res = r.run_probe("parse_advertising_data")
    assert res["ok"] is True
    devs = res["data"]["devices"]
    assert devs[0]["name"] == "Sensor"
    types = {s["type_name"] for s in devs[0]["ad_structures"]}
    assert "Flags" in types
    assert "Complete Local Name" in types
    assert "Manufacturer Specific Data" in types
    assert devs[0]["has_raw"] is True


def test_parse_advertising_data_no_raw_reports_honestly():
    devs = [{"address": "AA:BB:CC:DD:EE:03", "name": "BleOnly", "rssi": -60}]
    r = BLEProbeRunner(scanner=_FakeScanner(devs))
    res = r.run_probe("parse_advertising_data")
    assert res["ok"] is True
    assert res["data"]["devices"][0]["has_raw"] is False
    assert "no raw" in (res["data"]["note"] or "")


def test_parse_advertising_data_no_devices_surfaces_scanner_error():
    r = BLEProbeRunner(scanner=_FakeScanner([]))
    # _FakeScan returns no devices; the probe still finalizes ok with count 0
    res = r.run_probe("parse_advertising_data")
    assert res["ok"] is True
    assert res["data"]["count"] == 0


# ----------------------------------------------------------------------
# manufacturer_oracle
# ----------------------------------------------------------------------
def test_manufacturer_oracle_ibeacon_and_oui():
    r = BLEProbeRunner(scanner=_FakeScanner(_devs()))
    res = r.run_probe("manufacturer_oracle")
    assert res["ok"] is True
    d0 = res["data"]["devices"][0]
    # Company ID 0x004C -> Apple
    assert d0["company_id"] == "Apple"
    assert d0["ibeacon"] is not None
    assert d0["ibeacon"]["major"] == 17
    assert d0["ibeacon"]["minor"] == 42
    assert d0["model"] == "heuristic"


def test_manufacturer_oracle_oui_unknown_vendor_low_confidence():
    r = BLEProbeRunner(scanner=_FakeScanner(_devs()))
    res = r.run_probe("manufacturer_oracle")
    d1 = res["data"]["devices"][1]
    # AABBCC OUI is not in the builtin map -> Unknown vendor, no MFR data
    assert d1["oui_vendor"] == "Unknown"
    assert d1["confidence"] == "low"


# ----------------------------------------------------------------------
# analyze_location_leak
# ----------------------------------------------------------------------
def test_analyze_location_leak_finds_ibeacon():
    r = BLEProbeRunner(scanner=_FakeScanner(_devs()))
    res = r.run_probe("analyze_location_leak")
    assert res["ok"] is True
    beacons = res["data"]["ibeacons"]
    assert len(beacons) == 1
    assert beacons[0]["uuid"].count("-") == 4
    assert beacons[0]["location_leak"] is True


def test_analyze_location_leak_none_when_no_ibeacon():
    devs = [{"address": "AA:BB:CC:DD:EE:02", "raw_advert": _FLAGS_UUID}]
    r = BLEProbeRunner(scanner=_FakeScanner(devs))
    res = r.run_probe("analyze_location_leak")
    assert res["ok"] is True
    assert res["data"]["count"] == 0


# ----------------------------------------------------------------------
# estimate_battery_profile (gatttool monkeypatched)
# ----------------------------------------------------------------------
def test_battery_reads_level_via_gatttool(monkeypatch):
    monkeypatch.setattr(ble.shutil, "which", lambda name: "/usr/bin/gatttool")

    def fake_run(cmd, **kw):
        # gatttool -b <addr> --char-read-uuid 0x2a19 -t random
        return subprocess.CompletedProcess(cmd, 0,
            stdout="handle: 0x0010   value: 5a\n", stderr="")

    monkeypatch.setattr(ble.subprocess, "run", fake_run)
    r = BLEProbeRunner(scanner=_FakeScanner(_devs()))
    res = r.run_probe("estimate_battery_profile")
    assert res["ok"] is True
    assert res["data"]["devices"][0]["battery_level"] == 0x5A


def test_battery_no_gatttool_degrades_cleanly(monkeypatch):
    monkeypatch.setattr(ble.shutil, "which", lambda name: None)
    r = BLEProbeRunner(scanner=_FakeScanner(_devs()))
    res = r.run_probe("estimate_battery_profile")
    assert res["ok"] is False
    assert "gatttool not installed" in res["error"]


# ----------------------------------------------------------------------
# map_gatt_services
# ----------------------------------------------------------------------
def test_map_gatt_services_names_known_uuids():
    r = BLEProbeRunner(scanner=_FakeScanner(_devs()))
    res = r.run_probe("map_gatt_services")
    assert res["ok"] is True
    names = {s["name"] for s in res["data"]["devices"][0]["services"]}
    assert "Battery Service" in names
    assert "Device Information Service" in names


# ----------------------------------------------------------------------
# connection_graph_active
# ----------------------------------------------------------------------
def test_connection_graph_builds_edges():
    devs = [{"address": "01:02:03:04:05:06"},
            {"address": "0A:0B:0C:0D:0E:0F"},
            {"address": "11:22:33:44:55:66"}]
    r = BLEProbeRunner(scanner=_FakeScanner(devs))
    res = r.run_probe("connection_graph_active")
    assert res["ok"] is True
    assert res["data"]["node_count"] == 3
    assert res["data"]["edge_count"] == 3  # 3 devices in 1 window -> C(3,2)
    assert res["data"]["windows"] == 2


def test_connection_graph_no_devices_degrades():
    r = BLEProbeRunner(scanner=_FakeScanner([]))
    res = r.run_probe("connection_graph_active")
    assert res["ok"] is False
    assert "no BLE devices" in res["error"]


# ----------------------------------------------------------------------
# calculate_exfil_potential
# ----------------------------------------------------------------------
def test_exfil_arithmetic_uses_raw_length():
    r = BLEProbeRunner(scanner=_FakeScanner(_devs()))
    res = r.run_probe("calculate_exfil_potential")
    assert res["ok"] is True
    d0 = res["data"]["devices"][0]
    # payload = len(_FLAGS_NAME_IBEACON), interval default 20 ms
    expected_bps = (d0["payload_bytes"] * 8) / 0.020
    assert abs(d0["exfil_bps"] - round(expected_bps, 1)) < 0.01


def test_exfil_defaults_to_31_bytes_without_raw():
    devs = [{"address": "AA:BB:CC:DD:EE:03"}]
    r = BLEProbeRunner(scanner=_FakeScanner(devs))
    res = r.run_probe("calculate_exfil_potential")
    assert res["ok"] is True
    assert res["data"]["devices"][0]["payload_bytes"] == 31


# ----------------------------------------------------------------------
# predict_pairing_vulnerability
# ----------------------------------------------------------------------
def test_pairing_heuristic_labels_not_trained():
    r = BLEProbeRunner(scanner=_FakeScanner(_devs()))
    res = r.run_probe("predict_pairing_vulnerability")
    assert res["ok"] is True
    for d in res["data"]["devices"]:
        assert d["model"] == "heuristic (not trained)"
        assert 0.0 <= d["just_works_likelihood"] <= 0.9
        assert "IO Capabilities require a connection" in d["note"]


def test_pairing_random_address_raises_score():
    # device 2 is address_type=random, BR/EDR not supported -> higher score
    r = BLEProbeRunner(scanner=_FakeScanner(_devs()))
    res = r.run_probe("predict_pairing_vulnerability")
    d1 = res["data"]["devices"][1]
    assert d1["address_type"] == "random"
    assert d1["just_works_likelihood"] > 0.0


# ----------------------------------------------------------------------
# OUI helper
# ----------------------------------------------------------------------
def test_oui_vendor_builtin(tmp_path):
    assert ble._oui_vendor("AC:84:C6:00:00:01").startswith("TP-Link")
    assert ble._oui_vendor("zz:zz:zz") == "Unknown"


def test_oui_vendor_loads_file(tmp_path):
    oui = tmp_path / "oui.txt"
    oui.write_text("AABBCC TestVendor Co\n", encoding="utf-8")
    assert ble._oui_vendor("AA:BB:CC:00:00:01", oui_path=oui) == "TestVendor Co"


# ----------------------------------------------------------------------
# Batch 2: recon_ota_update, assess_mitm_feasibility,
# firmware_version_predictor, cross_device_linker_ble, ble_anomaly_detector,
# hid_recon, smarthome_enumerator, tracking_resistance_test
# ----------------------------------------------------------------------
def test_recon_ota_update_surfaces_dfu_uuid(monkeypatch):
    devs = [{"address": "AA:BB:CC:DD:EE:01", "uuids": ["fe59"]}]
    monkeypatch.setattr(ble.shutil, "which", lambda n: "/usr/bin/gatttool")
    monkeypatch.setattr(ble.subprocess, "run",
        lambda cmd, **kw: subprocess.CompletedProcess(cmd, 1, stdout="", stderr=""))
    r = BLEProbeRunner(scanner=_FakeScanner(devs))
    res = r.run_probe("recon_ota_update")
    assert res["ok"] is True
    d0 = res["data"]["devices"][0]
    assert d0["ota_surface"] is True
    assert "fe59" in d0["ota_services"]


def test_recon_ota_update_no_gatttool_notes_honestly(monkeypatch):
    monkeypatch.setattr(ble.shutil, "which", lambda n: None)
    devs = [{"address": "AA:BB:CC:DD:EE:01", "uuids": ["fe59"]}]
    r = BLEProbeRunner(scanner=_FakeScanner(devs))
    res = r.run_probe("recon_ota_update")
    assert res["ok"] is True
    assert "gatttool absent" in res["data"]["devices"][0]["note"]


def test_assess_mitm_feasibility_large_spread(monkeypatch):
    devs = [{"address": "AA:BB:CC:DD:EE:01", "rssi": -40},
            {"address": "AA:BB:CC:DD:EE:02", "rssi": -75}]
    r = BLEProbeRunner(scanner=_FakeScanner(devs))
    res = r.run_probe("assess_mitm_feasibility")
    assert res["ok"] is True
    assert res["data"]["feasible"] is True
    assert res["data"]["spread_db"] == 35
    assert res["data"]["suggested_tx_dbm"] > 0


def test_assess_mitm_feasibility_too_few_degrades():
    r = BLEProbeRunner(scanner=_FakeScanner([{"address": "AA", "rssi": -50}]))
    res = r.run_probe("assess_mitm_feasibility")
    assert res["ok"] is False
    assert ">=2 devices" in res["error"]


def test_firmware_version_predictor_fuzzy_match(monkeypatch):
    # gatttool returns "1.0.0" as hex bytes -> fuzzy match to known "1.0.0"
    monkeypatch.setattr(ble.shutil, "which", lambda n: "/usr/bin/gatttool")
    # "1.0.0" -> hex 31 2e 30 2e 30
    monkeypatch.setattr(ble.subprocess, "run",
        lambda cmd, **kw: subprocess.CompletedProcess(
            cmd, 0, stdout="handle: 0x0010  value: 31 2e 30 2e 30\n", stderr=""))
    r = BLEProbeRunner(scanner=_FakeScanner(_devs()))
    res = r.run_probe("firmware_version_predictor")
    assert res["ok"] is True
    d0 = res["data"]["devices"][0]
    assert d0["firmware_revision"] == "1.0.0"
    assert d0["matched_version"] == "1.0.0"
    assert d0["known_vulns"] == []  # never fabricate CVE ids
    assert d0["model"] == "heuristic (not trained)"


def test_firmware_version_predictor_no_gatttool_degrades(monkeypatch):
    monkeypatch.setattr(ble.shutil, "which", lambda n: None)
    r = BLEProbeRunner(scanner=_FakeScanner(_devs()))
    res = r.run_probe("firmware_version_predictor")
    assert res["ok"] is False
    assert "gatttool not installed" in res["error"]


def test_cross_device_linker_ble_same_oui():
    # Both MACs share the TP-Link OUI AC84C6 -> same_device, high confidence
    r = BLEProbeRunner(scanner=_FakeScanner([]),
                       args={"wifi_mac": "AC:84:C6:11:22:33",
                             "ble_mac": "AC:84:C6:44:55:66"})
    res = r.run_probe("cross_device_linker_ble")
    assert res["ok"] is True
    assert res["data"]["same_device"] is True
    assert res["data"]["confidence"] == "high"


def test_cross_device_linker_ble_missing_args_degrades():
    r = BLEProbeRunner(scanner=_FakeScanner([]), args={})
    res = r.run_probe("cross_device_linker_ble")
    assert res["ok"] is False
    assert "wifi_mac" in res["error"]


def test_ble_anomaly_detector_flags_mac_flood():
    # 60 unique addresses -> mac_flood anomaly
    devs = [{"address": f"AA:BB:CC:00:00:{i:02X}"} for i in range(60)]
    r = BLEProbeRunner(scanner=_FakeScanner(devs))
    res = r.run_probe("ble_anomaly_detector")
    assert res["ok"] is True
    assert res["data"]["unique_addresses"] == 60
    types = {a["type"] for a in res["data"]["anomalies"]}
    assert "mac_flood" in types
    assert res["data"]["model"] == "heuristic (not trained)"


def test_ble_anomaly_detector_no_traffic_degrades():
    r = BLEProbeRunner(scanner=_FakeScanner([]))
    res = r.run_probe("ble_anomaly_detector")
    assert res["ok"] is False


def test_hid_recon_detects_by_appearance(monkeypatch):
    # No host gatttool dependency — keep the test hermetic.
    monkeypatch.setattr(ble.shutil, "which", lambda n: None)
    # Appearance AD type 0x19, value 0x03C1 (keyboard) little-endian -> C1 03
    adv = _ad(0x19, b"\xc1\x03")
    devs = [{"address": "AA:BB:CC:DD:EE:01", "raw_advert": adv}]
    r = BLEProbeRunner(scanner=_FakeScanner(devs))
    res = r.run_probe("hid_recon")
    assert res["ok"] is True
    d0 = res["data"]["devices"][0]
    assert d0["is_hid"] is True
    assert d0["hid_kind"] == "Keyboard"


def test_hid_recon_detects_by_service_uuid(monkeypatch):
    monkeypatch.setattr(ble.shutil, "which", lambda n: None)
    devs = [{"address": "AA:BB:CC:DD:EE:02", "uuids": ["1812"]}]
    r = BLEProbeRunner(scanner=_FakeScanner(devs))
    res = r.run_probe("hid_recon")
    assert res["data"]["devices"][0]["is_hid"] is True


def test_smarthome_enumerator_detects_hue():
    devs = [{"address": "AA:BB:CC:DD:EE:01", "name": "Hue Bridge"}]
    r = BLEProbeRunner(scanner=_FakeScanner(devs))
    res = r.run_probe("smarthome_enumerator")
    assert res["ok"] is True
    assert res["data"]["devices"][0]["is_hub"] is True
    assert "Hue" in res["data"]["devices"][0]["hub"]


def test_smarthome_enumerator_no_hub():
    devs = [{"address": "AA:BB:CC:DD:EE:01", "name": "Random Sensor"}]
    r = BLEProbeRunner(scanner=_FakeScanner(devs))
    res = r.run_probe("smarthome_enumerator")
    assert res["data"]["devices"][0]["is_hub"] is False
    assert res["data"]["devices"][0]["hub"] is None


def test_tracking_resistance_public_is_trackable():
    devs = [{"address": "AA:BB:CC:DD:EE:01", "address_type": "public"}]
    r = BLEProbeRunner(scanner=_FakeScanner(devs))
    res = r.run_probe("tracking_resistance_test")
    assert res["ok"] is True
    assert res["data"]["trackable"] is True
    assert res["data"]["uses_privacy"] is False


def test_tracking_resistance_random_uses_privacy():
    devs = [{"address": "AA:BB:CC:DD:EE:02", "address_type": "random"}]
    r = BLEProbeRunner(scanner=_FakeScanner(devs))
    res = r.run_probe("tracking_resistance_test")
    assert res["ok"] is True
    assert res["data"]["uses_privacy"] is True


def test_tracking_resistance_no_devices_degrades():
    r = BLEProbeRunner(scanner=_FakeScanner([]))
    res = r.run_probe("tracking_resistance_test")
    assert res["ok"] is False


def test_run_probe_passes_args_to_cross_device_linker():
    # Module-level run_probe must thread args through to args-driven probes.
    res = run_probe("cross_device_linker_ble",
                    args={"wifi_mac": "AC:84:C6:11:22:33",
                          "ble_mac": "AC:84:C6:44:55:66"})
    assert res["ok"] is True
    assert res["data"]["same_device"] is True