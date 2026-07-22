"""Acceptance: plan + execute WiFi AI chains (goal criteria 1–4).

Drives the *shipped* ``AIChainPlanner.plan`` and
``AutonomousOrchestrator.run(..., use_ai_chain=True)`` paths — not a
reimplementation. Subprocess/RF tools are stubbed; the walk and planner
APIs are real.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest


def _seed_with_recon(tmp_path: Optional[Path] = None) -> Dict[str, Any]:
    from core.modules.catalog_recon import CatalogRecon

    seed: Dict[str, Any] = {
        "bssid": "AA:BB:CC:DD:EE:FF",
        "ssid": "lab-ap",
        "channel": 6,
        "interface": "wlan0mon",
        "encryption": "WPA2 CCMP PSK",
        "aio": True,
    }
    recon = CatalogRecon(seed)
    seed["recon"] = recon.recon
    if tmp_path is not None:
        cap = tmp_path / "hand.cap"
        cap.write_bytes(b"\x00" * 32)
        seed["cap_file"] = str(cap)
        seed["pcap"] = str(cap)
        seed["recon"] = dict(seed["recon"])
        seed["recon"]["handshake_harvest"] = {
            "ok": True,
            "data": {"pcap": str(cap), "handshake_complete": False},
        }
    return seed


def test_plan_with_recon_merged_seed_is_nonempty_and_serializable():
    """Criterion 1: plan succeeds with recon on seed; no circular dump."""
    import json

    from core.ai_backend.chain import AIChainPlanner

    seed = _seed_with_recon()
    # Must not raise Circular reference
    json.dumps(seed, default=str)

    events: List[str] = []
    planner = AIChainPlanner(ai_backend=None, on_event=events.append)
    steps = planner.plan(domain="wifi", target=seed, cves=[], kb_tools=[])
    assert steps, "planner must emit a non-empty step list"
    actions = [s.get("action") for s in steps]
    assert "deauth" in actions
    assert any(a in actions for a in ("mcp_call", "airodump", "crack", "pmkid"))
    assert planner._last_context.get("chain_source") in (
        "heuristic", "llm", "uncensored_swap",
    )
    assert not any("Circular" in e for e in events)


def test_plan_survives_classic_recon_target_cycle():
    """Criterion 1: even a hostile seed cycle still plans."""
    from core.ai_backend.chain import AIChainPlanner

    seed: Dict[str, Any] = {
        "bssid": "11:22:33:44:55:66",
        "ssid": "cyc",
        "channel": 1,
        "interface": "wlan0mon",
    }
    seed["recon"] = {"target": seed, "wps": {"ok": False}}
    planner = AIChainPlanner(ai_backend=None)
    steps = planner.plan(
        domain="wifi",
        target=seed,
        prior_results=[{"action": "x", "result": seed}],
    )
    assert len(steps) >= 1


def test_ai_walk_executes_deauth_and_capture_family_not_info_only(tmp_path):
    """Criterion 2: deauth + capture/crack-family are real work under autonomous."""
    from core.ai_backend.chain import AIChainPlanner
    from core.orchestrator.autonomous_orchestrator import AutonomousOrchestrator

    seed = _seed_with_recon(tmp_path)
    events: List[str] = []
    planner = AIChainPlanner(ai_backend=None, on_event=lambda m: events.append(m))

    # Bound re-plans so the test stays fast
    import core.replan as rpkg
    import core.replan.max_replans as mr
    old_a, old_b = rpkg.MAX_REPLANS, mr.MAX_REPLANS
    rpkg.MAX_REPLANS = 3
    mr.MAX_REPLANS = 3

    o = AutonomousOrchestrator(
        confirm_fn=lambda p: True,
        on_event=lambda m: events.append(m),
        chain_planner=planner,
    )
    o._deauth = lambda *a, **k: "deauth: ok method=stub"  # type: ignore[method-assign]
    o._crack_with_aircrack = (  # type: ignore[method-assign]
        lambda *a, **k: {"ok": False, "method": "aircrack-ng", "error": "stub-no-hs"}
    )
    o._crack_with_hashcat = (  # type: ignore[method-assign]
        lambda *a, **k: {"ok": False, "method": "hashcat", "error": "stub-no-hs"}
    )
    o._pcap_to_hc22000 = lambda p: None  # type: ignore[method-assign]
    o._capture_pmkid_pcap = (  # type: ignore[method-assign]
        lambda **k: seed.get("cap_file")
    )
    o._resolve_wordlist = lambda *a, **k: str(tmp_path / "wl.txt")  # type: ignore[method-assign]
    (tmp_path / "wl.txt").write_text("password\n", encoding="utf-8")

    import core.mcp.tools as mt
    orig = mt.call_mcp_tool

    def fake_mcp(name, args, timeout=30):
        if "airo" in (name or ""):
            return {"ok": True, "stdout": "capturing", "returncode": 0}
        return {"ok": False, "error": f"stub {name}"}

    mt.call_mcp_tool = fake_mcp  # type: ignore[assignment]
    try:
        rep = o.run("wifi", seed, use_ai_chain=True, autonomous=True)
    finally:
        mt.call_mcp_tool = orig  # type: ignore[assignment]
        rpkg.MAX_REPLANS = old_a
        mr.MAX_REPLANS = old_b

    assert rep.get("ai_chain") or rep.get("ai_chain_source")
    actions = [e.get("action") for e in rep["executed"]]
    assert "deauth" in actions, f"deauth missing from {actions}"
    assert any(
        a in actions for a in ("mcp_call", "airodump", "pmkid", "crack", "crack_gpu")
    ), f"capture/crack family missing from {actions}"

    info_only = [
        e for e in rep["executed"]
        if "info, not executed" in str(e.get("result"))
        and e.get("action") in (
            "deauth", "airodump", "mcp_call", "pmkid", "crack", "crack_gpu",
        )
    ]
    assert not info_only, f"real steps were info-only: {info_only}"
    assert not any("Circular" in m for m in events)


def test_crack_resolves_cap_from_seed_not_bare_missing(tmp_path):
    """Criterion 3: crack uses seed/recon cap path when present on disk."""
    from core.orchestrator.autonomous_orchestrator import AutonomousOrchestrator

    cap = tmp_path / "from_recon.cap"
    cap.write_bytes(b"\x00" * 24)
    seed = {
        "bssid": "AA:BB:CC:DD:EE:FF",
        "interface": "wlan0mon",
        "recon": {
            "handshake_harvest": {"data": {"pcap": str(cap)}},
        },
    }
    o = AutonomousOrchestrator(
        confirm_fn=lambda p: True, on_event=lambda m: None,
    )
    resolved = o._resolve_cap_file({"action": "crack", "args": {}}, seed)
    assert resolved == str(cap)

    called = {}

    def fake_crack(pcap, wordlist, bssid=None, wep=False):
        called["pcap"] = pcap
        return {"ok": False, "method": "aircrack-ng", "error": "no handshake"}

    o._crack_with_aircrack = fake_crack  # type: ignore[method-assign]
    o._resolve_wordlist = lambda *a, **k: str(tmp_path / "w.txt")  # type: ignore[method-assign]
    (tmp_path / "w.txt").write_text("x\n", encoding="utf-8")
    rep = {
        "executed": [], "skipped": [], "optional_declined": [],
        "access": {"achieved": False},
    }
    o._walk_ai_step(
        {
            "action": "crack",
            "tool": "aircrack-ng",
            "args": {},  # no cap_file in step — must come from seed/recon
            "risk_level": "intrusive",
            "rationale": "crack",
            "expected_outcome": "psk",
            "expected_runtime_seconds": 30,
        },
        seed, rep, autonomous=True,
    )
    assert called.get("pcap") == str(cap)
    assert rep["executed"], "crack must record executed entry"
    err = str(rep["executed"][-1].get("result"))
    assert "no cap_file" not in err or called.get("pcap")


def test_replan_filters_done_and_keeps_remaining_attack_steps(monkeypatch):
    """Criterion 4: re-plan drops done pairs and does not wipe remaining chain."""
    from core.orchestrator.autonomous_orchestrator import AutonomousOrchestrator

    class Planner:
        def __init__(self):
            self._last_context = {"chain_source": "heuristic"}
            self.calls = 0

        def plan(self, domain, target, cves=None, kb_tools=None,
                 prior_results=None, attach_zero_day=False, **kw):
            self.calls += 1
            if not prior_results:
                # Initial: capture + deauth + pmkid + crack
                return [
                    {"action": "mcp_call", "tool": "airodump-ng", "args": {},
                     "risk_level": "intrusive", "rationale": "cap",
                     "expected_outcome": "cap", "expected_runtime_seconds": 5},
                    {"action": "deauth", "tool": "aireplay-ng", "args": {},
                     "risk_level": "destructive", "rationale": "d",
                     "expected_outcome": "eapol", "expected_runtime_seconds": 5},
                    {"action": "pmkid", "tool": "hashcat", "args": {},
                     "risk_level": "intrusive", "rationale": "p",
                     "expected_outcome": "psk", "expected_runtime_seconds": 5},
                    {"action": "crack", "tool": "aircrack-ng", "args": {},
                     "risk_level": "intrusive", "rationale": "c",
                     "expected_outcome": "psk", "expected_runtime_seconds": 5},
                ]
            # Short re-plan after first step: only deauth (missing pmkid/crack)
            return [
                {"action": "deauth", "tool": "aireplay-ng", "args": {},
                 "risk_level": "destructive", "rationale": "d",
                 "expected_outcome": "eapol", "expected_runtime_seconds": 5},
            ]

    planner = Planner()
    o = AutonomousOrchestrator(
        confirm_fn=lambda p: True,
        on_event=lambda m: None,
        chain_planner=planner,
    )
    o._deauth = lambda *a, **k: "deauth: ok"  # type: ignore[method-assign]
    o._crack_with_aircrack = (  # type: ignore[method-assign]
        lambda *a, **k: {"ok": False, "error": "stub"}
    )
    o._crack_with_hashcat = (  # type: ignore[method-assign]
        lambda *a, **k: {"ok": False, "error": "stub"}
    )
    o._pcap_to_hc22000 = lambda p: None  # type: ignore[method-assign]
    o._capture_pmkid_pcap = lambda **k: None  # type: ignore[method-assign]
    o._resolve_wordlist = lambda *a, **k: "/tmp/wl.txt"  # type: ignore[method-assign]

    import core.mcp.tools as mt
    orig = mt.call_mcp_tool
    mt.call_mcp_tool = (  # type: ignore[assignment]
        lambda n, a, timeout=30: {"ok": True, "tool": n}
    )
    import core.replan as rpkg
    import core.replan.max_replans as mr
    old_a, old_b = rpkg.MAX_REPLANS, mr.MAX_REPLANS
    rpkg.MAX_REPLANS = 2
    mr.MAX_REPLANS = 2
    try:
        rep = o.run(
            "wifi",
            {"bssid": "AA:BB:CC:DD:EE:FF", "channel": 6, "interface": "wlan0mon"},
            use_ai_chain=True, autonomous=True,
        )
    finally:
        mt.call_mcp_tool = orig  # type: ignore[assignment]
        rpkg.MAX_REPLANS = old_a
        mr.MAX_REPLANS = old_b

    actions = [e.get("action") for e in rep["executed"]]
    # Short re-plan must NOT drop pmkid/crack from the original tail.
    assert "mcp_call" in actions or "airodump" in actions
    assert "deauth" in actions
    assert "pmkid" in actions or "crack" in actions, (
        f"remaining attack steps lost after short re-plan: {actions}"
    )
    assert rep["replans"] >= 1
    assert not any(
        "info, not executed" in str(e.get("result")) and e.get("action") == "deauth"
        for e in rep["executed"]
    )


def test_planner_replan_filter_drops_executed_action_tool():
    """Planner-side filter (prior_results) drops already-run pairs."""
    from core.ai_backend.chain import AIChainPlanner

    seed = _seed_with_recon()
    planner = AIChainPlanner(ai_backend=None)
    prior = [
        {"action": "mcp_call", "tool": "airodump-ng", "result": "ok"},
        {"action": "deauth", "tool": "aireplay-ng", "result": "ok"},
    ]
    steps = planner.plan(
        domain="wifi", target=seed, prior_results=prior,
    )
    pairs = {(s.get("action"), s.get("tool") or "") for s in steps}
    assert ("mcp_call", "airodump-ng") not in pairs
    assert ("deauth", "aireplay-ng") not in pairs
    assert any(s.get("action") in ("pmkid", "crack", "crack_gpu") for s in steps)
