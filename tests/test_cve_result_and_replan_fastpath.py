"""Fixes from live adaptive log: CVE result dict + replan LLM thrash."""
from __future__ import annotations


def test_cve_to_exploit_result_to_dict_reports_real_nvd_error():
    from core.cve_to_exploit import cve_to_exploit_pipeline
    from core.orchestrator.autonomous_orchestrator import AutonomousOrchestrator

    r = cve_to_exploit_pipeline("CVE-2017-13077")
    d = r.to_dict()
    assert d["ok"] is False
    assert "NVD key" in (d.get("error") or "")

    o = AutonomousOrchestrator(confirm_fn=lambda p: True, on_event=lambda m: None)
    rep = {"executed": [], "skipped": []}
    seed: dict = {}
    o._dispatch_cve_to_exploit(
        {"action": "cve_to_exploit", "args": {"cve_id": "CVE-2017-13077"}},
        seed, rep,
    )
    assert rep["executed"]
    err = rep["executed"][-1]["result"].get("error") or ""
    assert "non-dict" not in err
    assert "NVD key" in err


def test_parse_rejects_json_schema_not_chain():
    from core.ai_backend.chain import _parse_chain_json, ChainPlanError
    import pytest

    schema = {
        "type": "object",
        "properties": {"chain": {"type": "array"}},
        "required": ["chain"],
    }
    with pytest.raises(ChainPlanError, match="schema"):
        _parse_chain_json(__import__("json").dumps(schema))


def test_parse_accepts_steps_alias():
    from core.ai_backend.chain import _parse_chain_json

    raw = (
        '{"steps":[{"action":"deauth","tool":"aireplay-ng","args":{},'
        '"rationale":"r","expected_outcome":"o","risk_level":"destructive",'
        '"expected_runtime_seconds":5}]}'
    )
    steps = _parse_chain_json(raw)
    assert steps[0]["action"] == "deauth"


def test_replan_skips_llm_after_ai_json_unavailable():
    from core.ai_backend.chain import AIChainPlanner

    events = []
    pl = AIChainPlanner(ai_backend=None, on_event=events.append)
    pl._ai_json_unavailable = True
    steps = pl.plan(
        domain="wifi",
        target={"bssid": "AA:BB", "channel": 1, "interface": "wlan0mon"},
        prior_results=[{"action": "mcp_call", "tool": "airodump-ng"}],
    )
    assert steps
    assert any("re-plan via heuristic" in e for e in events)
    # Should not attempt multi-model crawl messages
    assert not any("retrying chain JSON with model" in e for e in events)
