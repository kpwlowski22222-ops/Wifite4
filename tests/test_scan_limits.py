"""Tests for long-range WiFi / BLE scan limit helpers."""
from __future__ import annotations

import core.scanners.scan_limits as sl


def test_wifi_default_is_long():
    assert sl.DEFAULT_WIFI_SCAN_S >= 300
    assert sl.wifi_scan_s(None) >= 300


def test_ble_default_is_long():
    assert sl.DEFAULT_BLE_SCAN_S >= 300
    assert sl.ble_scan_s(None) >= 300


def test_max_ceiling():
    assert sl.MAX_SCAN_S >= 3600
    assert sl.wifi_scan_s(999999) == sl.max_scan_s()
    assert sl.ble_scan_s(999999) == sl.max_scan_s()


def test_min_floor():
    assert sl.wifi_scan_s(0) >= sl.MIN_SCAN_S
    assert sl.ble_scan_s(1) >= sl.MIN_SCAN_S


def test_env_override(monkeypatch):
    monkeypatch.setenv("KFIOSA_WIFI_SCAN_S", "120")
    monkeypatch.setenv("KFIOSA_BLE_SCAN_S", "90")
    assert sl.wifi_scan_s(None) == 120
    assert sl.ble_scan_s(None) == 90


def test_env_max_ceiling(monkeypatch):
    monkeypatch.setenv("KFIOSA_MAX_SCAN_S", "600")
    assert sl.wifi_scan_s(900) == 600
