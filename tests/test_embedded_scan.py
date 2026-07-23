"""In-TUI embedded scan prefers main-dashboard aesthetics."""
from __future__ import annotations

import os


def test_prefer_embedded_by_default(monkeypatch):
    monkeypatch.delenv("KFIOSA_EXTERNAL_SCAN", raising=False)
    from core.tui.embedded_scan import prefer_embedded_scan
    assert prefer_embedded_scan() is True


def test_prefer_external_when_env_set(monkeypatch):
    monkeypatch.setenv("KFIOSA_EXTERNAL_SCAN", "1")
    from core.tui.embedded_scan import prefer_embedded_scan
    assert prefer_embedded_scan() is False
    monkeypatch.setenv("KFIOSA_EXTERNAL_SCAN", "external")
    assert prefer_embedded_scan() is False


def test_wifi_scan_uses_embedded_when_stdscr(monkeypatch):
    """scan_networks calls embedded path when stdscr present (no real scan)."""
    from core.tui.wifi_screen import WiFiScreen

    calls = {}

    def fake_embedded(stdscr, *, iface, out_path, activity_log):
        calls["iface"] = iface
        calls["out"] = out_path
        return {
            "bssid": "AA:BB:CC:DD:EE:FF",
            "ssid": "lab",
            "channel": 6,
            "encryption": "WPA2",
        }

    monkeypatch.setattr(
        "core.tui.embedded_scan.run_embedded_wifi_scan", fake_embedded,
    )
    monkeypatch.setattr(
        "core.tui.embedded_scan.prefer_embedded_scan", lambda: True,
    )
    monkeypatch.delenv("KFIOSA_EXTERNAL_SCAN", raising=False)

    class FakeScr:
        def getmaxyx(self):
            return 24, 80

    log = []
    # Minimal screen without full dashboard init
    scr = object.__new__(WiFiScreen)
    scr.stdscr = FakeScr()
    scr.activity_log = log
    scr.interface = "wlan0mon"
    scr.scanner_cls = None
    scr.selected_target = None
    scr.scan_results = []
    scr.targets = []
    scr.external_terminal = None
    scr.settings_manager = None
    aio = []
    scr.aio_attack = lambda: aio.append(True)

    scr.scan_networks()
    assert calls.get("iface") == "wlan0mon"
    assert scr.selected_target and scr.selected_target["bssid"] == "AA:BB:CC:DD:EE:FF"
    assert aio == [True]
    assert any("In-TUI" in x or "Selected AP" in x for x in log)


def test_ble_scan_uses_embedded(monkeypatch):
    from core.tui.ble_screen import BLEScreen

    def fake_embedded(stdscr, *, adapter, out_path, activity_log):
        return {"address": "11:22:33:44:55:66", "name": "sensor", "rssi": -50}

    monkeypatch.setattr(
        "core.tui.embedded_scan.run_embedded_ble_scan", fake_embedded,
    )
    monkeypatch.setattr(
        "core.tui.embedded_scan.prefer_embedded_scan", lambda: True,
    )
    monkeypatch.delenv("KFIOSA_EXTERNAL_SCAN", raising=False)

    class FakeScr:
        def getmaxyx(self):
            return 24, 80

    log = []
    scr = object.__new__(BLEScreen)
    scr.stdscr = FakeScr()
    scr.activity_log = log
    scr.interface = "hci0"
    scr.scanner_cls = None
    scr.selected_device = None
    scr.selected_target = None
    scr.ble_devices = []
    scr.targets = []
    scr.external_terminal = None
    scr.settings_manager = None
    aio = []
    scr.aio_attack = lambda: aio.append(True)

    scr.scan_ble_devices()
    assert scr.selected_target["address"] == "11:22:33:44:55:66"
    assert aio == [True]


def test_draw_scan_window_theme_smoke():
    """draw_scan_window does not raise with a fake stdscr."""
    from core.tui.scan_window_shell import ScanWindowState, draw_scan_window

    class Fake:
        def __init__(self):
            self.lines = []

        def erase(self):
            pass

        def getmaxyx(self):
            return 20, 80

        def addnstr(self, *a, **k):
            self.lines.append(a)

        def refresh(self):
            pass

    st = ScanWindowState(
        title="TEST",
        items=[{"bssid": "AA", "ssid": "x", "channel": 1, "encryption": "WPA2"}],
        idx=0,
        msg="ok",
        detail="bssid=AA",
    )
    draw_scan_window(Fake(), st, row_fmt=lambda i: f"{i.get('ssid')}")


def test_move_idx_wraps():
    from core.tui.embedded_scan import _move_idx
    assert _move_idx(0, 5, -1) == 4
    assert _move_idx(4, 5, +1) == 0
    assert _move_idx(2, 5, +1) == 3
    assert _move_idx(0, 0, +1) == 0


def test_handle_nav_arrows_still_work():
    import curses
    from core.tui.scan_window_shell import handle_nav_key
    idx, act = handle_nav_key(curses.KEY_DOWN, 0, 10)
    assert idx == 1 and act is None
    idx, act = handle_nav_key(curses.KEY_UP, 0, 10)
    assert idx == 0 and act is None
