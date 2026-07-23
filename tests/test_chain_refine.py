"""Tests for refine_chain_steps precision pass."""
from __future__ import annotations

from core.ai_backend.chain import refine_chain_steps


def test_fills_bssid_from_target():
    steps = [{"action": "crack", "tool": "aircrack-ng", "args": {}}]
    out = refine_chain_steps(
        steps, "wifi",
        {"bssid": "AA:BB:CC:DD:EE:FF", "channel": 6, "interface": "wlan0mon"},
    )
    assert out[0]["args"]["bssid"] == "AA:BB:CC:DD:EE:FF"
    assert out[0]["args"]["channel"] == 6


def test_drops_deauth_when_pmf():
    steps = [
        {"action": "mcp_call", "tool": "airodump-ng", "args": {}},
        {"action": "deauth", "tool": "aireplay-ng", "args": {}},
        {"action": "crack", "tool": "aircrack-ng", "args": {}},
    ]
    out = refine_chain_steps(
        steps, "wifi",
        {"bssid": "AA", "pmf_supported": True, "client_count": 3,
         "encryption": "WPA2"},
    )
    assert "deauth" not in [s["action"] for s in out]
    assert "crack" in [s["action"] for s in out]


def test_caps_gpu_masks():
    steps = [
        {"action": "crack_gpu", "tool": "hashcat",
         "args": {"mask": "?d" * 8}},
        {"action": "crack_gpu", "tool": "hashcat",
         "args": {"mask": "?d" * 10}},
        {"action": "crack_gpu", "tool": "hashcat",
         "args": {"mask": "?l" * 8}},
    ]
    out = refine_chain_steps(
        steps, "wifi",
        {"bssid": "AA", "encryption": "WPA2", "wordlist": "/tmp/wl.txt"},
    )
    assert len([s for s in out if s["action"] == "crack_gpu"]) <= 1


def test_dedupes_identical_steps():
    steps = [
        {"action": "pmkid", "tool": "hashcat", "args": {}},
        {"action": "pmkid", "tool": "hashcat", "args": {}},
    ]
    out = refine_chain_steps(steps, "wifi", {"bssid": "AA", "encryption": "WPA2"})
    assert len(out) == 1


def test_ble_legacy_tool_aliases_mapped():
    """Shell binary tool names must become real BLE method names."""
    steps = [
        {"action": "ble_probe", "tool": "bluetoothctl", "args": {}},
        {"action": "ble_probe", "tool": "gatttool", "args": {}},
        {"action": "ble_attack", "tool": "bettercap", "args": {}},
    ]
    out = refine_chain_steps(
        steps, "ble",
        {"address": "AA:BB:CC:DD:EE:01", "adapter": "hci0"},
    )
    methods = [(s.get("args") or {}).get("method") for s in out]
    assert "parse_advertising_data" in methods
    assert "map_gatt_services" in methods
    assert "ble_long_range_scan" in methods
    for s in out:
        assert (s.get("args") or {}).get("address") == "AA:BB:CC:DD:EE:01"
        assert (s.get("args") or {}).get("adapter") == "hci0"


def test_explicit_client_count_zero_drops_deauth():
    """When the caller explicitly says there are no clients, deauth is dropped."""
    steps = [
        {"action": "mcp_call", "tool": "airodump-ng", "args": {}},
        {"action": "deauth", "tool": "aireplay-ng", "args": {}},
        {"action": "pmkid", "tool": "hashcat", "args": {}},
    ]
    out = refine_chain_steps(
        steps, "wifi",
        {"bssid": "AA", "encryption": "WPA2", "client_count": 0},
    )
    assert "deauth" not in [s["action"] for s in out]
    assert "pmkid" in [s["action"] for s in out]


def test_failed_client_recon_keeps_deauth():
    """Defaulted client_count from a failed recon is not evidence — keep gated deauth."""
    steps = [
        {"action": "mcp_call", "tool": "airodump-ng", "args": {}},
        {"action": "deauth", "tool": "aireplay-ng", "args": {}},
        {"action": "pmkid", "tool": "hashcat", "args": {}},
    ]
    out = refine_chain_steps(
        steps, "wifi",
        {
            # No explicit client_count; only a failed recon.
            "bssid": "AA", "encryption": "WPA2",
            "recon": {"clients": {"ok": False, "data": None}},
        },
    )
    assert "deauth" in [s["action"] for s in out]


def test_replan_dedup_respects_different_methods():
    """Re-plan filter must not drop a step just because (action,tool) ran with
    a different method."""
    from core.ai_backend.chain import AIChainPlanner
    planner = AIChainPlanner(ai_backend=None)
    prior = [
        {"action": "ble_probe", "tool": "ble_runner",
         "args": {"method": "parse_advertising_data"}, "ok": True},
    ]
    steps = [
        {"action": "ble_probe", "tool": "ble_runner",
         "args": {"method": "parse_advertising_data"}},
        {"action": "ble_probe", "tool": "ble_runner",
         "args": {"method": "map_gatt_services"}},
    ]
    filtered = planner._filter_already_executed(steps, prior) \
        if hasattr(planner, "_filter_already_executed") else steps
    # The public re-plan path exercises this via plan(prior_results=...)
    result = planner.plan(
        domain="ble",
        target={"address": "AA:BB:CC:DD:EE:01", "encryption": "LE"},
        prior_results=prior,
    )
    actions = [(s.get("action"), (s.get("args") or {}).get("method")) for s in result]
    assert ("ble_probe", "map_gatt_services") in actions
