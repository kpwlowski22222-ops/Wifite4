#!/usr/bin/env python3
"""Tests for core.tui.ble_scan_external (live BLE tables + selection)."""
import json
import time
from pathlib import Path

from core.tui.ble_scan_external import (
    LiveBLEScanner,
    _get_oui_vendor,
    _pick_text_dev,
    _write_selection,
)


def test_oui_vendor_lookup():
    assert _get_oui_vendor("B8:27:EB:11:22:33") == "Raspberry Pi"
    assert _get_oui_vendor("00:00:00:00:00:00") == "Unknown OUI"
    assert _get_oui_vendor("") == "Unknown"


def test_live_scanner_online_and_disappeared():
    scanner = LiveBLEScanner(adapter="hci0", disappeared_timeout=2.0, pulse_s=3)
    now = time.time()

    online_dev = {
        "address": "AA:BB:CC:DD:EE:F1",
        "name": "Bandage-1",
        "rssi": -55,
        "services": ["1800"],
        "address_type": "public",
    }
    gone_dev = {
        "address": "11:22:33:44:55:66",
        "name": "Ghost",
        "rssi": -80,
        "services": [],
        "address_type": "random",
    }

    scanner._merge_device("AA:BB:CC:DD:EE:F1", online_dev, now)
    scanner._merge_device("11:22:33:44:55:66", gone_dev, now - 10.0)

    online, disappeared = scanner.poll()

    assert len(online) == 1
    assert online[0]["name"] == "Bandage-1"
    assert online[0]["address"] == "AA:BB:CC:DD:EE:F1"

    assert len(disappeared) == 1
    assert disappeared[0]["name"] == "Ghost"
    assert "last_seen_ago" in disappeared[0]["recon_info"]


def test_merge_keeps_strongest_rssi():
    scanner = LiveBLEScanner(pulse_s=3)
    now = time.time()
    scanner._merge_device(
        "AA:BB:CC:00:00:01",
        {"address": "AA:BB:CC:00:00:01", "name": "Unknown", "rssi": -90},
        now,
    )
    scanner._merge_device(
        "AA:BB:CC:00:00:01",
        {"address": "AA:BB:CC:00:00:01", "name": "Sensor", "rssi": -60,
         "services": ["180F"]},
        now,
    )
    online, _ = scanner.poll()
    assert len(online) == 1
    assert online[0]["rssi"] == -60
    assert online[0]["name"] == "Sensor"
    assert "180F" in online[0]["services"]


def test_write_selection(tmp_path):
    out_file = tmp_path / "ble_scan_selection.json"
    target = {"address": "AA:BB:CC:DD:EE:F1", "name": "TargetBLE"}
    online = [target]
    disappeared = [{"address": "11:22:33:44:55:66", "name": "Gone"}]

    _write_selection(
        out_file, target, aio=True,
        devices=online, disappeared_devices=disappeared,
    )

    assert out_file.is_file()
    data = json.loads(out_file.read_text(encoding="utf-8"))
    assert data["selected"]["address"] == "AA:BB:CC:DD:EE:F1"
    assert data["aio_attack"] is True
    assert len(data["devices"]) == 1
    assert len(data["disappeared_devices"]) == 1


def test_pick_text_dev():
    online = [{"address": "AA:00:00:00:00:01", "name": "A"}]
    disappeared = [{"address": "BB:00:00:00:00:02", "name": "B"}]
    assert _pick_text_dev("1", online, disappeared)["name"] == "A"
    assert _pick_text_dev("D1", online, disappeared)["name"] == "B"
    assert _pick_text_dev("99", online, disappeared) is None


def test_ble_main_long_range_threads_long_timeout(monkeypatch, tmp_path):
    import core.tui.ble_scan_external as bse
    cap = {}

    class FakeScanner:
        def __init__(self, adapter=None, disappeared_timeout=20.0,
                     pulse_s=8):
            cap["timeout"] = float(disappeared_timeout)
            self.adapter = adapter
            self.prep_notes = []
            self.backends_tried = []
            self.last_error = ""

        def start(self):
            pass

        def stop(self):
            pass

        def poll(self):
            return [], []

    monkeypatch.setattr(bse, "LiveBLEScanner", FakeScanner)
    monkeypatch.setattr(bse.time, "sleep", lambda *a, **k: None)
    monkeypatch.setattr("builtins.input", lambda *a, **k: "q")
    out = tmp_path / "sel.json"
    rc = bse.main(["--adapter", "", "--out", str(out),
                  "--text", "--seconds", "1", "--pulse", "4", "--long-range"])
    assert rc == 0
    assert cap["timeout"] == 90.0  # long-range keeps BLE devices longer


def test_ble_main_default_timeout(monkeypatch, tmp_path):
    import core.tui.ble_scan_external as bse
    cap = {}

    class FakeScanner:
        def __init__(self, adapter=None, disappeared_timeout=20.0,
                     pulse_s=8):
            cap["timeout"] = float(disappeared_timeout)
            self.adapter = adapter
            self.prep_notes = []
            self.backends_tried = []
            self.last_error = ""

        def start(self):
            pass

        def stop(self):
            pass

        def poll(self):
            return [], []

    monkeypatch.setattr(bse, "LiveBLEScanner", FakeScanner)
    monkeypatch.setattr(bse.time, "sleep", lambda *a, **k: None)
    monkeypatch.setattr("builtins.input", lambda *a, **k: "q")
    out = tmp_path / "sel.json"
    rc = bse.main(["--adapter", "", "--out", str(out),
                  "--text", "--seconds", "1", "--pulse", "4"])
    assert rc == 0
    assert cap["timeout"] == 30.0  # default (was 20.0 before long-range work)


def test_ble_text_ui_info_command(capsys, monkeypatch, tmp_path):
    import core.tui.ble_scan_external as bse

    fake_dev = {
        "address": "AA:BB:CC:DD:EE:F1",
        "name": "Gadget",
        "rssi": -62,
        "services": ["1800", "180F", "2A19"],
        "address_type": "public",
        "tx_power": 4,
        "vendor": "Acme Inc.",
        "manufacturer_data": {"0x004C": "Apple payload"},
        "seen_by": ["bluepy"],
    }

    class FakeScanner:
        def __init__(self, *a, **k):
            self.adapter = "hci0"
            self.prep_notes = []
            self.backends_tried = ["bluepy"]
            self.last_error = ""

        def start(self):
            pass

        def stop(self):
            pass

        def poll(self):
            return [dict(fake_dev)], []

    inputs = iter(["i 1", "q"])
    monkeypatch.setattr(bse, "LiveBLEScanner", FakeScanner)
    monkeypatch.setattr(bse.time, "sleep", lambda *a, **k: None)
    monkeypatch.setattr("builtins.input", lambda *a, **k: next(inputs))
    out = tmp_path / "sel.json"

    rc = bse.run_text_ui(adapter="hci0", out_path=out, seconds=1, pulse_s=1)
    captured = capsys.readouterr()
    assert rc == 0
    assert "Device info (online): Gadget" in captured.out
    assert "180F" in captured.out
    assert "Apple payload" in captured.out
    assert "Acme Inc." in captured.out
