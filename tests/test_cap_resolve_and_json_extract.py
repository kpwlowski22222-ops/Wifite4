"""Regression: capture-file resolution + LLM JSON extraction for chains."""
from __future__ import annotations

from pathlib import Path

import pytest


def test_extract_json_from_prose():
    from core.ai_backend.chain import _parse_chain_json

    prose = (
        'Here is a plan for you:\n'
        '{"chain":[{"action":"deauth","tool":"aireplay-ng","args":{},'
        '"rationale":"force reauth","expected_outcome":"eapol",'
        '"risk_level":"destructive","expected_runtime_seconds":10}]}\n'
        'Good luck!'
    )
    steps = _parse_chain_json(prose)
    assert steps[0]["action"] == "deauth"


def test_heuristic_wifi_includes_deauth_pmkid_crack():
    from core.ai_backend.chain import _heuristic_for_domain

    steps = _heuristic_for_domain(
        "wifi",
        {"bssid": "AA:BB:CC:DD:EE:FF", "channel": 6,
         "interface": "wlan0mon", "ssid": "lab"},
    )
    actions = [s["action"] for s in steps]
    assert "deauth" in actions
    assert "pmkid" in actions
    assert "crack" in actions


def test_resolve_cap_file_prefers_existing_on_disk(tmp_path):
    from core.orchestrator.autonomous_orchestrator import AutonomousOrchestrator

    cap = tmp_path / "hand.cap"
    cap.write_bytes(b"\x00" * 16)
    o = AutonomousOrchestrator.__new__(AutonomousOrchestrator)
    seed = {"bssid": "AA:BB", "cap_file": str(cap)}
    assert o._resolve_cap_file({"action": "crack"}, seed) == str(cap)


def test_resolve_cap_file_from_recon_harvest(tmp_path):
    from core.orchestrator.autonomous_orchestrator import AutonomousOrchestrator

    cap = tmp_path / "recon.cap"
    cap.write_bytes(b"\x00" * 16)
    o = AutonomousOrchestrator.__new__(AutonomousOrchestrator)
    seed = {
        "bssid": "AA:BB",
        "recon": {
            "handshake_harvest": {"data": {"pcap": str(cap)}},
        },
    }
    assert o._resolve_cap_file({}, seed) == str(cap)


def test_stamp_cap_from_airodump_args(tmp_path, monkeypatch):
    from core.orchestrator.autonomous_orchestrator import AutonomousOrchestrator

    write = tmp_path / "kfiosa-AABB"
    cap = Path(str(write) + "-01.cap")
    cap.write_bytes(b"\x00" * 16)
    o = AutonomousOrchestrator.__new__(AutonomousOrchestrator)
    o._emit = lambda m: None  # type: ignore[attr-defined]
    seed: dict = {"bssid": "AA:BB"}
    o._stamp_cap_from_airodump_args(
        {"write": str(write), "bssid": "AA:BB"}, seed)
    assert seed.get("cap_file") == str(cap)


def test_ai_deauth_action_is_executed_not_info_only():
    """Heuristic emits action=deauth; must NOT fall through to info-only."""
    from core.orchestrator.autonomous_orchestrator import AutonomousOrchestrator

    events = []
    o = AutonomousOrchestrator(
        confirm_fn=lambda p: True, on_event=events.append,
    )
    o._deauth = lambda *a, **k: "deauth: ok method=mock"  # type: ignore[method-assign]
    seed = {"bssid": "AA:BB:CC:DD:EE:FF", "channel": 6, "interface": "wlan0mon"}
    report = {
        "executed": [], "skipped": [], "optional_declined": [],
        "access": {"achieved": False},
    }
    o._walk_ai_step(
        {
            "action": "deauth",
            "tool": "aireplay-ng",
            "args": {"bssid": "AA:BB:CC:DD:EE:FF", "interface": "wlan0mon"},
            "risk_level": "destructive",
            "rationale": "force handshake",
            "expected_outcome": "eapol",
            "expected_runtime_seconds": 10,
        },
        seed, report, autonomous=True,
    )
    assert report["executed"], "deauth must append an executed entry"
    res = report["executed"][-1]["result"]
    assert "info, not executed" not in str(res)
    assert "deauth: ok" in str(res)


def test_ai_airodump_action_is_executed_not_info_only():
    from core.orchestrator.autonomous_orchestrator import AutonomousOrchestrator

    o = AutonomousOrchestrator(
        confirm_fn=lambda p: True, on_event=lambda m: None,
    )
    o._execute_step = (  # type: ignore[method-assign]
        lambda s, seed: {"ok": True, "method": "airodump-ng",
                         "cap_file": "/tmp/x-01.cap"}
    )
    seed = {"bssid": "AA:BB:CC:DD:EE:FF", "channel": 6, "interface": "wlan0mon"}
    report = {
        "executed": [], "skipped": [], "optional_declined": [],
        "access": {"achieved": False},
    }
    o._walk_ai_step(
        {
            "action": "airodump",
            "tool": "airodump-ng",
            "args": {"bssid": "AA:BB:CC:DD:EE:FF", "interface": "wlan0mon",
                     "write": "/tmp/x"},
            "risk_level": "intrusive",
            "rationale": "capture",
            "expected_outcome": "cap",
            "expected_runtime_seconds": 30,
        },
        seed, report, autonomous=True,
    )
    res = report["executed"][-1]["result"]
    assert isinstance(res, dict) and res.get("ok") is True
