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
