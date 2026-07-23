"""In-TUI embedded scan prefers main-dashboard aesthetics."""
from __future__ import annotations

import json
import os
from pathlib import Path


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


def test_wifi_scan_uses_embedded_when_stdscr(monkeypatch, tmp_path):
    """scan_networks calls embedded path; AIO only when aio_attack set."""
    from core.tui.wifi_screen import WiFiScreen

    calls = {}
    out = tmp_path / "wifi_scan_selection.json"

    def fake_embedded(stdscr, *, iface, out_path, activity_log):
        calls["iface"] = iface
        calls["out"] = out_path
        sel = {
            "bssid": "AA:BB:CC:DD:EE:FF",
            "ssid": "lab",
            "channel": 6,
            "encryption": "WPA2",
            "aio_attack": True,
        }
        Path(out_path).parent.mkdir(parents=True, exist_ok=True)
        Path(out_path).write_text(
            json.dumps({
                "selected": sel,
                "aio_attack": True,
                "networks": [
                    sel,
                    {"bssid": "11:22:33:44:55:66", "ssid": "other"},
                ],
            }),
            encoding="utf-8",
        )
        return sel

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
    scr.menu_items = []
    scr.menu_index = 0
    scr.flow_state = "menu"
    scr.primary_items = []
    aio = []
    scr.aio_attack = lambda: aio.append(True)

    # Force out_path under tmp by patching scan body via cwd logs/
    # scan_networks uses logs/wifi_scan_selection.json — ensure writable
    monkeypatch.chdir(tmp_path)

    scr.scan_networks()
    assert calls.get("iface") == "wlan0mon"
    assert scr.selected_target and scr.selected_target["bssid"] == "AA:BB:CC:DD:EE:FF"
    assert aio == [True]
    assert len(scr.targets) >= 1
    assert any("In-TUI" in x or "Selected AP" in x for x in log)


def test_wifi_scan_mark_without_aio_opens_targets(monkeypatch, tmp_path):
    """ENTER-mark (no AIO) should NOT auto-start engagement; open targets."""
    from core.tui.wifi_screen import WiFiScreen

    def fake_embedded(stdscr, *, iface, out_path, activity_log):
        sel = {
            "bssid": "AA:BB:CC:DD:EE:FF",
            "ssid": "lab",
            "aio_attack": False,
        }
        Path(out_path).parent.mkdir(parents=True, exist_ok=True)
        Path(out_path).write_text(
            json.dumps({
                "selected": sel,
                "aio_attack": False,
                "networks": [
                    sel,
                    {"bssid": "BB:BB:BB:BB:BB:BB", "ssid": "other"},
                ],
            }),
            encoding="utf-8",
        )
        return sel

    monkeypatch.setattr(
        "core.tui.embedded_scan.run_embedded_wifi_scan", fake_embedded,
    )
    monkeypatch.setattr(
        "core.tui.embedded_scan.prefer_embedded_scan", lambda: True,
    )
    monkeypatch.delenv("KFIOSA_EXTERNAL_SCAN", raising=False)
    monkeypatch.chdir(tmp_path)

    class FakeScr:
        def getmaxyx(self):
            return 24, 80

    scr = object.__new__(WiFiScreen)
    scr.stdscr = FakeScr()
    scr.activity_log = []
    scr.interface = "wlan0mon"
    scr.scanner_cls = None
    scr.selected_target = None
    scr.scan_results = []
    scr.targets = []
    scr.external_terminal = None
    scr.settings_manager = None
    scr.menu_items = []
    scr.menu_index = 0
    scr.flow_state = "menu"
    scr.primary_items = []
    aio = []
    scr.aio_attack = lambda: aio.append(True)

    scr.scan_networks()
    assert aio == []
    assert len(scr.targets) == 2
    assert scr.flow_state == "targets"


def test_ble_scan_uses_embedded(monkeypatch, tmp_path):
    from core.tui.ble_screen import BLEScreen

    def fake_embedded(stdscr, *, adapter, out_path, activity_log):
        sel = {
            "address": "11:22:33:44:55:66",
            "name": "sensor",
            "rssi": -50,
            "aio_attack": True,
        }
        Path(out_path).parent.mkdir(parents=True, exist_ok=True)
        Path(out_path).write_text(
            json.dumps({
                "selected": sel,
                "aio_attack": True,
                "devices": [sel],
            }),
            encoding="utf-8",
        )
        return sel

    monkeypatch.setattr(
        "core.tui.embedded_scan.run_embedded_ble_scan", fake_embedded,
    )
    monkeypatch.setattr(
        "core.tui.embedded_scan.prefer_embedded_scan", lambda: True,
    )
    monkeypatch.delenv("KFIOSA_EXTERNAL_SCAN", raising=False)
    monkeypatch.chdir(tmp_path)

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
    scr.menu_items = []
    scr.menu_index = 0
    scr.flow_state = "menu"
    scr.primary_items = []
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


def test_idx_for_id_stable_across_reorder():
    from core.tui.embedded_scan import _idx_for_id, _item_id
    items = [
        {"bssid": "AA:AA:AA:AA:AA:AA", "ssid": "a"},
        {"bssid": "BB:BB:BB:BB:BB:BB", "ssid": "b"},
        {"bssid": "CC:CC:CC:CC:CC:CC", "ssid": "c"},
    ]
    bid = _item_id(items[1])
    # reorder
    reordered = [items[2], items[0], items[1]]
    assert _idx_for_id(reordered, bid, 0) == 2


def test_clients_follow_focus_not_enter():
    """Clients panel is derived from focused AP without ENTER mark."""
    from core.tui.embedded_scan import _clients_from_ap
    ap = {
        "bssid": "AA:BB:CC:DD:EE:FF",
        "clients": ["11:22:33:44:55:66", {"mac": "AA:00:00:00:00:01"}],
    }
    cli = _clients_from_ap(ap)
    assert len(cli) == 2
    assert cli[0]["mac"] == "11:22:33:44:55:66"
    assert _clients_from_ap(None) == []


def test_ble_detail_rows_from_focus():
    from core.tui.embedded_scan import _ble_detail_rows
    rows = _ble_detail_rows({
        "name": "sensor",
        "address": "AA:BB:CC:DD:EE:FF",
        "rssi": -55,
        "services": ["HeartRate", "Battery"],
        "vendor": "Test",
    })
    keys = {r["key"] for r in rows}
    assert "name" in keys and "svc" in keys


def test_wifi_stable_sort_mode():
    import time
    from core.tui.wifi_scan_external import LiveScanner
    sc = LiveScanner("wlan0mon", disappeared_timeout=30.0)
    sc.sort_mode = "stable"
    now = time.time()
    # stronger signal added second — stable order keeps first_seen
    sc._merge_ap("AA:AA:AA:AA:AA:01", {
        "bssid": "AA:AA:AA:AA:AA:01", "ssid": "weak", "power": -80,
        "encryption": "WPA2", "clients": [], "clients_count": 0,
    }, now)
    sc._merge_ap("AA:AA:AA:AA:AA:02", {
        "bssid": "AA:AA:AA:AA:AA:02", "ssid": "strong", "power": -30,
        "encryption": "WPA2", "clients": [], "clients_count": 0,
    }, now + 0.01)
    online, _ = sc.poll()
    assert online[0]["bssid"] == "AA:AA:AA:AA:AA:01"
    sc.sort_mode = "power"
    sc._poll_cache = None
    online2, _ = sc.poll()
    assert online2[0]["bssid"] == "AA:AA:AA:AA:AA:02"


def test_poll_interval_slow():
    from core.tui.embedded_scan import WIFI_POLL_S, BLE_POLL_S
    assert WIFI_POLL_S >= 1.0
    assert BLE_POLL_S >= 1.0


def test_handle_nav_arrows_still_work():
    import curses
    from core.tui.scan_window_shell import handle_nav_key
    idx, act = handle_nav_key(curses.KEY_DOWN, 0, 10)
    assert idx == 1 and act is None
    idx, act = handle_nav_key(curses.KEY_UP, 0, 10)
    assert idx == 0 and act is None


def test_0day_bg_skips_build_without_concept():
    """engagement_engine must not pass seed dict to builder.build()."""
    from core.orchestrator.engagement_engine import EngagementEngine

    logs = []

    class FakeOrch:
        zero_day_proposer = None
        zero_day_exploit_builder = type("B", (), {
            "build": staticmethod(lambda concept: (_ for _ in ()).throw(
                AssertionError("build must not be called without concept")
            )),
        })()

    eng = EngagementEngine(FakeOrch(), on_event=logs.append)
    out = eng._start_bg_zero_day({"ssid": "x"}, "wifi")
    assert out.get("started") is True
    # Wait briefly for daemon thread
    import time
    time.sleep(0.15)
    assert any("build skip" in m or "docker_sim" in m for m in logs)


def test_append_log_dedup_and_cap():
    from core.tui.activity_log_view import append_log, MAX_ACTIVITY_LINES
    log: list = []
    append_log(log, "[*] same", timestamp=False)
    append_log(log, "[*] same", timestamp=False)  # deduped
    assert len(log) == 1
    for i in range(MAX_ACTIVITY_LINES + 50):
        append_log(log, f"[*] line {i}", timestamp=False)
    assert len(log) <= MAX_ACTIVITY_LINES


def test_ble_poll_cache_fast():
    import time
    from core.tui.ble_scan_external import LiveBLEScanner
    sc = LiveBLEScanner(adapter="hci0", disappeared_timeout=30.0, pulse_s=3)
    with sc._lock:
        for i in range(40):
            sc._merge_device(
                f"AA:BB:CC:DD:EE:{i:02X}",
                {"address": f"AA:BB:CC:DD:EE:{i:02X}", "name": f"d{i}", "rssi": -50},
                time.time(),
            )
    t0 = time.perf_counter()
    for _ in range(50):
        sc.poll()
    # Cached partition should be very cheap
    assert (time.perf_counter() - t0) < 0.5
