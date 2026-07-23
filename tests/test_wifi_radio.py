"""Tests for WiFi radio pre-flight helpers (no root required for unit path)."""
from __future__ import annotations

from core.scanners import wifi_radio as wr


def test_airodump_cmd_prefers_multi_band():
    variants = wr.airodump_cmd("wlan0mon", "/tmp/x", berlin=200, multi_band=True)
    assert len(variants) >= 2
    assert "--band" in variants[0]
    assert "abg" in variants[0]
    assert "--berlin" in variants[0]
    assert "200" in variants[0] or "120" in variants[0]


def test_airodump_cmd_berlin_floor():
    variants = wr.airodump_cmd("wlan0", "/tmp/y", berlin=10, multi_band=False)
    assert len(variants) == 1
    # berlin floor is 120
    assert "120" in variants[0]


def test_pick_best_scan_iface_handles_empty(monkeypatch):
    monkeypatch.setattr(wr, "list_wireless_ifaces", lambda: [])
    assert wr.pick_best_scan_iface(None) is None
    assert wr.pick_best_scan_iface("wlan0") == "wlan0"


def test_pick_best_scan_iface_prefers_monitor(monkeypatch):
    monkeypatch.setattr(wr, "list_wireless_ifaces", lambda: ["wlan0", "wlan0mon"])
    monkeypatch.setattr(
        wr, "iface_mode",
        lambda n: "monitor" if n.endswith("mon") else "managed",
    )
    assert wr.pick_best_scan_iface("wlan0") == "wlan0mon"
    assert wr.pick_best_scan_iface("wlan0mon") == "wlan0mon"


def test_prep_no_ifaces(monkeypatch):
    monkeypatch.setattr(wr, "list_wireless_ifaces", lambda: [])
    monkeypatch.setattr(wr, "pick_best_scan_iface", lambda r=None: None)
    out = wr.prep_for_wifi_scan(None, kill_interferers=False, collapse_dups=False)
    assert out["ok"] is False
    assert "no wireless" in (out.get("error") or "").lower()


def test_ensure_iface_up_monitor_already(monkeypatch):
    monkeypatch.setattr(wr, "iface_mode", lambda n: "monitor")
    monkeypatch.setattr(wr, "is_root", lambda: False)
    out = wr.ensure_iface_up_monitor("wlan0mon")
    assert out.get("ok") is True
    assert out.get("interface") == "wlan0mon"


def test_ensure_iface_up_monitor_needs_root(monkeypatch):
    monkeypatch.setattr(wr, "iface_mode", lambda n: "managed")
    monkeypatch.setattr(wr, "is_root", lambda: False)
    out = wr.ensure_iface_up_monitor("wlan0")
    assert "error" in out
    assert "root" in out["error"].lower() or "monitor" in out["error"].lower()
