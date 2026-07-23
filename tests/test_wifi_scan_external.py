#!/usr/bin/env python3
"""Tests for core.tui.wifi_scan_external (live scanning and dual AP tables)."""
import json
import time
from pathlib import Path
import pytest

from core.tui.wifi_scan_external import (
    LiveScanner,
    _get_oui_vendor,
    _parse_airodump_csv_live,
    _pick_text_ap,
    _write_selection,
)


def test_oui_vendor_lookup():
    assert _get_oui_vendor("00:1A:E9:11:22:33") == "TP-Link"
    assert _get_oui_vendor("00:14:D1:AA:BB:CC") == "Netgear"
    assert _get_oui_vendor("00:CD:FE:12:34:56") == "Apple"
    assert _get_oui_vendor("00:00:00:00:00:00") == "Unknown OUI"


def test_parse_airodump_csv_live():
    sample_csv = """BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key
00:1A:E9:AA:BB:CC, 2026-07-23 01:00:00, 2026-07-23 01:00:10, 6, 54, WPA2, CCMP, PSK, -55, 120, 0, 0.0.0.0, 7, TestNet, 
00:14:D1:11:22:33, 2026-07-23 01:00:00, 2026-07-23 01:00:10, 11, 54, WPA2, CCMP, PSK, -80, 45, 0, 0.0.0.0, 8, OtherNet, 

Station MAC, First time seen, Last time seen, Power, # packets, BSSID, Probed ESSIDs
AA:BB:CC:11:22:33, 2026-07-23 01:00:05, 2026-07-23 01:00:10, -60, 20, 00:1A:E9:AA:BB:CC, TestNet
DD:EE:FF:44:55:66, 2026-07-23 01:00:05, 2026-07-23 01:00:10, -70, 15, 00:1A:E9:AA:BB:CC, 
"""
    aps, clients = _parse_airodump_csv_live(sample_csv)

    assert "00:1A:E9:AA:BB:CC" in aps
    assert aps["00:1A:E9:AA:BB:CC"]["ssid"] == "TestNet"
    assert aps["00:1A:E9:AA:BB:CC"]["channel"] == 6
    assert aps["00:1A:E9:AA:BB:CC"]["power"] == -55

    assert "00:1A:E9:AA:BB:CC" in clients
    assert len(clients["00:1A:E9:AA:BB:CC"]) == 2
    assert "AA:BB:CC:11:22:33" in clients["00:1A:E9:AA:BB:CC"]


def test_live_scanner_online_and_disappeared(tmp_path):
    scanner = LiveScanner(iface="wlan0mon", disappeared_timeout=2.0)
    now = time.time()

    # Manually populate AP catalog with recent and stale APs
    ap_online = {
        "bssid": "00:1A:E9:11:22:33",
        "ssid": "ActiveAP",
        "channel": 6,
        "power": -50,
        "encryption": "WPA2",
        "beacons": 100,
        "clients": ["AA:BB:CC:00:11:22"],
        "clients_count": 1,
    }
    ap_disappeared = {
        "bssid": "00:14:D1:44:55:66",
        "ssid": "DisappearedAP",
        "channel": 11,
        "power": -75,
        "encryption": "WPA2",
        "beacons": 30,
        "clients": [],
        "clients_count": 0,
    }

    scanner._merge_ap("00:1A:E9:11:22:33", ap_online, now)
    scanner._merge_ap("00:14:D1:44:55:66", ap_disappeared, now - 10.0)

    online, disappeared = scanner.poll()

    assert len(online) == 1
    assert online[0]["ssid"] == "ActiveAP"
    assert online[0]["vendor"] == "TP-Link"

    assert len(disappeared) == 1
    assert disappeared[0]["ssid"] == "DisappearedAP"
    assert disappeared[0]["vendor"] == "Netgear"
    assert disappeared[0]["recon_info"]["vendor"] == "Netgear"
    assert "last_seen_ago" in disappeared[0]["recon_info"]


def test_write_selection(tmp_path):
    out_file = tmp_path / "wifi_scan_selection.json"
    target = {"bssid": "00:1A:E9:11:22:33", "ssid": "TargetAP"}
    online = [target]
    disappeared = [{"bssid": "00:14:D1:44:55:66", "ssid": "GoneAP"}]

    _write_selection(out_file, target, aio=True, networks=online, disappeared_networks=disappeared)

    assert out_file.is_file()
    data = json.loads(out_file.read_text(encoding="utf-8"))
    assert data["selected"]["bssid"] == "00:1A:E9:11:22:33"
    assert data["aio_attack"] is True
    assert len(data["networks"]) == 1
    assert len(data["disappeared_networks"]) == 1


def test_pick_text_ap():
    online = [{"bssid": "11:11:11:11:11:11", "ssid": "On1"}]
    disappeared = [{"bssid": "22:22:22:22:22:22", "ssid": "Dis1"}]

    assert _pick_text_ap("1", online, disappeared)["ssid"] == "On1"
    assert _pick_text_ap("D1", online, disappeared)["ssid"] == "Dis1"
    assert _pick_text_ap("d1", online, disappeared)["ssid"] == "Dis1"
    assert _pick_text_ap("99", online, disappeared) is None


def test_read_curses_key_arrow_sequences():
    import curses
    from core.tui.base_screen import read_curses_key

    class DummyStdscr:
        def __init__(self, key_seq):
            self.seq = list(key_seq)
            self.timeouts = []

        def getch(self):
            if self.seq:
                return self.seq.pop(0)
            return -1

        def timeout(self, ms):
            self.timeouts.append(ms)

        def nodelay(self, flag):
            pass

    dummy_up = DummyStdscr([27, ord("["), ord("A")])
    assert read_curses_key(dummy_up) == curses.KEY_UP

    dummy_down = DummyStdscr([27, ord("["), ord("B")])
    assert read_curses_key(dummy_down) == curses.KEY_DOWN

    dummy_right = DummyStdscr([27, ord("["), ord("C")])
    assert read_curses_key(dummy_right) == curses.KEY_RIGHT

    dummy_left = DummyStdscr([27, ord("["), ord("D")])
    assert read_curses_key(dummy_left) == curses.KEY_LEFT

    dummy_esc = DummyStdscr([27])
    assert read_curses_key(dummy_esc) == 27



def _install_fake_live_scanner(monkeypatch, cap):
    import core.tui.wifi_scan_external as wse

    class FakeScanner:
        def __init__(self, iface, disappeared_timeout=6.0):
            cap["timeout"] = float(disappeared_timeout)
            self.iface = iface
            self.prep_notes = []
            self.backends_tried = []
            self.last_error = ""

        def start(self):
            pass

        def stop(self):
            pass

        def poll(self):
            return [], []

    monkeypatch.setattr(wse, "LiveScanner", FakeScanner)
    monkeypatch.setattr(wse.time, "sleep", lambda *a, **k: None)
    # Avoid any real airodump/iw subprocess on the empty-catalog retry path.
    monkeypatch.setattr(wse, "_scan_airodump_oneshot", lambda *a, **k: [])
    monkeypatch.setattr(wse, "_scan_fallback", lambda *a, **k: [])
    monkeypatch.setattr("builtins.input", lambda *a, **k: "q")


def test_wifi_main_long_range_threads_long_timeout(monkeypatch, tmp_path):
    import core.tui.wifi_scan_external as wse
    cap = {}
    _install_fake_live_scanner(monkeypatch, cap)
    out = tmp_path / "sel.json"
    rc = wse.main(["--iface", "wlan0mon", "--out", str(out),
                   "--text", "--seconds", "1", "--long-range"])
    assert rc == 0
    # Infinite live scan: long-range keeps disappeared APs on screen longer
    assert cap["timeout"] == 120.0


def test_wifi_main_default_timeout_is_longer_now(monkeypatch, tmp_path):
    import core.tui.wifi_scan_external as wse
    cap = {}
    _install_fake_live_scanner(monkeypatch, cap)
    out = tmp_path / "sel.json"
    rc = wse.main(["--iface", "wlan0mon", "--out", str(out),
                   "--text", "--seconds", "1"])
    assert rc == 0
    # Default text UI: long disappeared window so findings stay browsable
    assert cap["timeout"] == 90.0


def test_wifi_clients_expand_key_shows_associated_clients():
    """The `c` key path: a focused AP with clients surfaces its client MACs.
    We exercise the data path the panel renders from (ap['clients'])."""
    from core.tui.wifi_scan_external import LiveScanner
    scanner = LiveScanner(iface="wlan0mon", disappeared_timeout=2.0)
    ap = {
        "bssid": "00:1A:E9:AA:BB:CC", "ssid": "TestNet", "channel": 6,
        "power": -55, "encryption": "WPA2", "beacons": 100,
        "clients": ["AA:BB:CC:11:22:33", "DD:EE:FF:44:55:66"],
        "clients_count": 2,
    }
    scanner._merge_ap("00:1A:E9:AA:BB:CC", ap, time.time())
    online, _ = scanner.poll()
    assert online[0]["bssid"] == "00:1A:E9:AA:BB:CC"
    assert online[0]["clients_count"] == 2
    # Panel accepts MAC strings or {mac: ...} dicts (live_enrich normalizes).
    def _mac(c):
        if isinstance(c, str):
            return c
        if isinstance(c, dict):
            return str(c.get("mac") or c.get("station") or "")
        return str(c)
    assert all(":" in _mac(m) for m in online[0]["clients"])


def test_wifi_text_ui_client_view_command(monkeypatch, tmp_path, capsys):
    """Text-mode `c 1` prints the associated client MACs for the first AP."""
    import core.tui.wifi_scan_external as wse

    class FakeScannerWithClients:
        def __init__(self, iface, disappeared_timeout=6.0):
            self.iface = iface
            self.prep_notes = []

        def start(self):
            pass

        def stop(self):
            pass

        def poll(self):
            ap = {
                "bssid": "00:1A:E9:AA:BB:CC", "ssid": "TestNet",
                "channel": 6, "power": -55, "encryption": "WPA2",
                "clients": ["AA:BB:CC:11:22:33", "DD:EE:FF:44:55:66"],
                "clients_count": 2,
            }
            return [ap], []

    monkeypatch.setattr(wse, "LiveScanner", FakeScannerWithClients)
    monkeypatch.setattr(wse.time, "sleep", lambda *a, **k: None)
    monkeypatch.setattr(wse, "_scan_airodump_oneshot", lambda *a, **k: [])
    monkeypatch.setattr(wse, "_scan_fallback", lambda *a, **k: [])

    inputs = iter(["c 1", "q"])
    monkeypatch.setattr("builtins.input", lambda *a, **k: next(inputs))

    out = tmp_path / "sel.json"
    rc = wse.main(["--iface", "wlan0mon", "--out", str(out),
                   "--text", "--seconds", "1"])
    assert rc == 0
    captured = capsys.readouterr().out
    assert "Clients for TestNet [00:1A:E9:AA:BB:CC]" in captured
    assert "AA:BB:CC:11:22:33" in captured
    assert "DD:EE:FF:44:55:66" in captured
