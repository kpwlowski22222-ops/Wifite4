"""Unified external scan window keys + formatters."""
from __future__ import annotations

import curses

from core.tui.scan_window_shell import (
    clamp_idx,
    detail_for_item,
    format_ble_offline,
    format_ble_online,
    format_wifi_offline,
    format_wifi_online,
    handle_nav_key,
)


def test_clamp_idx():
    assert clamp_idx(5, 0) == 0
    assert clamp_idx(-1, 3) == 0
    assert clamp_idx(9, 3) == 2


def test_handle_nav_keys_match_main_tui():
    idx, act = handle_nav_key(curses.KEY_UP, 2, 5)
    assert idx == 1 and act is None
    idx, act = handle_nav_key(curses.KEY_DOWN, 2, 5)
    assert idx == 3 and act is None
    idx, act = handle_nav_key(10, 1, 5)  # enter
    assert act == "select"
    idx, act = handle_nav_key(ord(" "), 1, 5)
    assert act == "select"
    idx, act = handle_nav_key(curses.KEY_BACKSPACE, 1, 5)
    assert act == "back"
    idx, act = handle_nav_key(127, 1, 5)
    assert act == "back"
    idx, act = handle_nav_key(ord("q"), 1, 5)
    assert act == "quit"
    idx, act = handle_nav_key(27, 1, 5)
    assert act == "quit"


def test_format_wifi_offline_includes_history():
    line = format_wifi_offline({
        "bssid": "AA:BB:CC:DD:EE:FF",
        "ssid": "lab",
        "last_seen_ts": 1700000000,
        "first_seen_ts": 1699999000,
        "encryption": "WPA2",
        "channel": 6,
    })
    assert "AA:BB:CC:DD:EE:FF" in line
    assert "lab" in line
    assert "last=" in line


def test_format_ble_online():
    line = format_ble_online({
        "address": "11:22:33:44:55:66",
        "name": "sensor",
        "rssi": -55,
        "connectable": True,
    })
    assert "11:22:33:44:55:66" in line
    assert "sensor" in line


def test_detail_strip():
    d = detail_for_item({"bssid": "AA", "ssid": "x", "pmf": True}, "wifi")
    assert "bssid=AA" in d and "pmf=" in d


def test_format_client_and_kv():
    from core.tui.scan_window_shell import format_client_row, format_kv_row
    line = format_client_row({"mac": "AA:BB:CC:DD:EE:01", "power": -50})
    assert "AA:BB:CC:DD:EE:01" in line
    kv = format_kv_row({"key": "rssi", "value": "-42"})
    assert kv.startswith("rssi:")
