"""Hermetic tests for WiFi/BLE scan bus + geometry helpers."""
from __future__ import annotations

import json
import time
from pathlib import Path

from core.tui import wifi_scan_bus as wbus
from core.tui import ble_scan_bus as bbus
from core.utils.external_terminal import (
    geometry_string,
    screen_layout_rects,
)


def test_wifi_bus_selection_before_quit(tmp_path):
    bus = wbus.new_bus_dir(tmp_path)
    assert bus.is_dir()
    ap = {"bssid": "AA:BB:CC:DD:EE:FF", "ssid": "lab", "channel": 6}
    wbus.set_selection(bus, ap)
    wbus.request_quit(bus)
    sel = wbus.wait_for_selection(bus, timeout_s=2.0, poll_s=0.05)
    assert sel is not None
    assert sel["bssid"] == "AA:BB:CC:DD:EE:FF"


def test_wifi_bus_update_state_atomic(tmp_path):
    bus = wbus.new_bus_dir(tmp_path)
    wbus.update_state(bus, online=[{"bssid": "11:22:33:44:55:66"}], iface="wlan0mon")
    st = wbus.read_json(bus / "state.json")
    assert len(st["online"]) == 1
    assert st["iface"] == "wlan0mon"
    assert "updated_at" in st


def test_ble_bus_roundtrip(tmp_path):
    bus = bbus.new_bus_dir(tmp_path)
    dev = {"address": "AA:BB:CC:00:11:22", "name": "sensor", "rssi": -55}
    bbus.set_selection(bus, dev)
    assert bbus.get_selection(bus)["name"] == "sensor"
    bbus.request_quit(bus)
    assert bbus.should_quit(bus)


def test_screen_layout_rects_cover_three_slots():
    rects = screen_layout_rects()
    for k in ("topleft", "topright", "bottomright"):
        assert k in rects
        r = rects[k]
        assert r["w"] > 0 and r["h"] > 0
    g = geometry_string("topleft")
    assert "x" in g.lower() or "+" in g


def test_launch_triple_wifi_windows_places_three_slots(monkeypatch, tmp_path):
    """Triple WiFi scan must call launch_placed once per UL/UR/BR slot."""
    calls = []

    def fake_launch_placed(cmd, log, **kw):
        calls.append({"cmd": cmd, "log": log, **kw})
        class _P:
            pid = len(calls)
        return _P()

    import core.tui.wifi_scan_bus as wsb
    monkeypatch.setattr(
        "core.utils.external_terminal.launch_placed", fake_launch_placed
    )
    out = wsb.launch_triple_wifi_windows("wlan0mon", bus_dir=tmp_path / "bus", font_scale=2.0)
    assert out["ok"] is True
    assert set(out["procs"]) >= {"topleft", "topright", "bottomright"}
    assert len(calls) == 3
    positions = {c["position"] for c in calls}
    assert positions == {"topleft", "topright", "bottomright"}
    assert all(c.get("font_scale") == 2.0 for c in calls)


def test_launch_triple_ble_windows_places_three_slots(monkeypatch, tmp_path):
    calls = []

    def fake_launch_placed(cmd, log, **kw):
        calls.append({"cmd": cmd, "log": log, **kw})
        class _P:
            pid = len(calls)
        return _P()

    import core.tui.ble_scan_bus as bsb
    monkeypatch.setattr(
        "core.utils.external_terminal.launch_placed", fake_launch_placed
    )
    out = bsb.launch_triple_ble_windows("hci0", bus_dir=tmp_path / "bus", font_scale=1.5)
    assert out.get("ok") is True or "procs" in out
    assert len(calls) == 3
    assert {c["position"] for c in calls} == {
        "topleft", "topright", "bottomright",
    }
    assert all(c.get("font_scale") == 1.5 for c in calls)
