"""Device picker (airgeddon-style) — collect_devices + pick_device."""

import pytest

from core.tui.device_screen import collect_devices, pick_device


def _fake_stdscr(keyseq):
    """Minimal curses stdscr double that replays ``keyseq`` from getch()."""
    class _Std:
        def __init__(self):
            self.keys = list(keyseq)
            self.lines = []
        def erase(self):
            pass
        def getmaxyx(self):
            return (24, 80)
        def addstr(self, y, x, s, *a):
            self.lines.append(s)
        def attron(self, *a):
            pass
        def attroff(self, *a):
            pass
        def refresh(self):
            pass
        def getch(self):
            return self.keys.pop(0) if self.keys else -1
    return _Std()


KEY_DOWN = 258
KEY_UP = 259
KEY_ENTER = 10


def test_collect_devices_from_recon():
    recon = {"clients": {"data": {"count": 2, "clients": [
        {"mac": "AA:BB:CC:00:00:01", "power": "-42", "probes": "HOME",
         "packets": "12", "bssid": "AA:BB:CC:DD:EE:01"},
        {"mac": "AA:BB:CC:00:00:02", "power": "-70", "probes": "",
         "packets": "3", "bssid": "AA:BB:CC:DD:EE:01"},
    ]}}}
    devices = collect_devices(recon)
    assert len(devices) == 2
    assert devices[0]["mac"] == "AA:BB:CC:00:00:01"


def test_collect_devices_tolerates_missing():
    assert collect_devices(None) == []
    assert collect_devices({}) == []
    assert collect_devices({"clients": {}}) == []


def test_pick_device_returns_selected_mac():
    devices = collect_devices({"clients": {"data": {"count": 2, "clients": [
        {"mac": "AA:BB:CC:00:00:01"}, {"mac": "AA:BB:CC:00:00:02"},
    ]}}})
    log = []
    std = _fake_stdscr([KEY_DOWN, KEY_ENTER])  # move to 2nd, select
    mac = pick_device(std, log, devices)
    assert mac == "AA:BB:CC:00:00:02"
    assert any("Selected device" in l for l in log)


def test_pick_device_cancel_returns_none():
    devices = [{"mac": "AA:BB:CC:00:00:01"}]
    log = []
    std = _fake_stdscr([ord("q")])
    assert pick_device(std, log, devices) is None
    assert any("cancelled" in l for l in log)


def test_pick_device_empty_logs_and_returns_none():
    log = []
    std = _fake_stdscr([])
    assert pick_device(std, log, []) is None
    assert any("No devices" in l for l in log)