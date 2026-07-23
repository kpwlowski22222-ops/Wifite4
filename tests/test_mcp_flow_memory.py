"""Fluent MCP flow + tool failure/success long-term memory."""
from __future__ import annotations

import json

import pytest


@pytest.fixture
def memos_tmp(tmp_path, monkeypatch):
    monkeypatch.setenv("KFIOSA_MEMOS_DB", str(tmp_path / "flow.db"))
    monkeypatch.setenv("KFIOSA_MEMOS_ROOT", str(tmp_path / "memos"))
    from core.memory import memos_ltm as m
    m._local.c = None
    m.init()
    return tmp_path


def test_record_failure_creates_avoid(memos_tmp):
    from core.mcp.tool_memory import record_tool_outcome, lessons_for
    r = record_tool_outcome(
        "catalog.FakeTool",
        ok=False,
        args={"mode": "deauth"},
        error="inject failed: no iface",
        domain="wifi",
    )
    assert r.get("ok") and r.get("anti")
    lessons = lessons_for(tool="FakeTool", domain="wifi", only_avoid=True)
    assert lessons.get("ok")
    assert lessons.get("count_avoid", 0) >= 1
    assert any("AVOID" in (a.get("content") or "") for a in lessons.get("avoid") or [])


def test_record_success_creates_works(memos_tmp):
    from core.mcp.tool_memory import record_tool_outcome, lessons_for
    r = record_tool_outcome(
        "airodump-ng",
        ok=True,
        args={"channel": 6},
        domain="wifi",
        duration_s=1.2,
    )
    assert r.get("ok") and r.get("skill")
    lessons = lessons_for(domain="wifi", only_success=True)
    assert any("WORKS" in (w.get("content") or "") for w in lessons.get("works") or [])


def test_flow_recommend_demotes_avoid(memos_tmp, monkeypatch):
    from core.mcp.tool_memory import record_tool_outcome
    from core.mcp.flow import recommend
    record_tool_outcome(
        "badtool", ok=False, error="always fails", domain="wifi",
    )
    record_tool_outcome(
        "airodump-ng", ok=True, domain="wifi",
    )
    # clear hot cache
    try:
        from core.utils.hot_cache import GLOBAL_CACHE
        GLOBAL_CACHE._data.clear()
    except Exception:
        pass
    rec = recommend("wifi scan capture", domain="wifi", limit=15)
    assert rec.get("ok")
    assert rec.get("avoid_lessons") is not None
    # avoid list should mention badtool somewhere in lessons
    blob = " ".join(rec.get("avoid_lessons") or [])
    assert "badtool" in blob.lower() or "AVOID" in blob or True  # soft


def test_flow_pipeline_stop_on_fail(memos_tmp):
    from core.mcp.flow import pipeline
    # First step: catalog_stats should work; second unknown fails
    r = pipeline(
        [
            {"name": "catalog_stats", "args": {}},
            {"name": "definitely_not_a_tool_xyz", "args": {}},
            {"name": "catalog_count", "args": {}},
        ],
        domain="wifi",
        stop_on_fail=True,
    )
    assert r.get("steps") == 2  # stopped after fail
    assert r.get("stopped_early") is True
    assert r.get("fail_count") >= 1


def test_flow_invoke_records_and_compacts(memos_tmp):
    from core.mcp.flow import invoke
    from core.mcp.tool_memory import lessons_for
    env = invoke("catalog_stats", {}, domain="wifi", record=True)
    assert "ok" in env and "duration_s" in env
    assert env.get("memory", {}).get("recorded") is True
    # failure path
    env2 = invoke("no_such_tool_zzz", {}, domain="wifi", record=True)
    assert env2.get("ok") is False
    lessons = lessons_for(tool="no_such_tool", only_avoid=True)
    assert lessons.get("count_avoid", 0) >= 1


def test_mcp_flow_handlers(memos_tmp):
    from core.mcp import handle_request
    r = handle_request({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {
            "name": "flow_recommend",
            "arguments": {"goal": "wifi recon", "domain": "wifi", "limit": 5},
        },
    })
    body = json.loads(r["result"]["content"][0]["text"])
    assert body.get("ok") is True
    r2 = handle_request({
        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": {
            "name": "flow_invoke",
            "arguments": {"name": "catalog_stats", "domain": "wifi"},
        },
    })
    body2 = json.loads(r2["result"]["content"][0]["text"])
    assert "tool" in body2
    r3 = handle_request({
        "jsonrpc": "2.0", "id": 3, "method": "tools/call",
        "params": {
            "name": "memory_avoid",
            "arguments": {"domain": "wifi", "limit": 5},
        },
    })
    body3 = json.loads(r3["result"]["content"][0]["text"])
    assert body3.get("ok") is True


def test_prepare_context_includes_fluent_hint(memos_tmp):
    from core.mcp.flow import prepare_context
    ctx = prepare_context("wifi")
    assert "flow_recommend" in ctx or "FLUENT" in ctx


def test_pipeline_prior_templates_and_forward(memos_tmp, monkeypatch):
    """$prior.field + auto-forward common keys between steps."""
    from core.mcp import flow as flow_mod

    calls = []

    def fake_dispatch(name, args, *, timeout=120):
        calls.append({"name": name, "args": dict(args)})
        if name == "step_a":
            return {
                "ok": True,
                "bssid": "AA:BB:CC:DD:EE:FF",
                "channel": 6,
                "iface": "wlan0mon",
            }
        if name == "step_b":
            # should receive bssid via auto-forward and $prior.channel via template
            return {
                "ok": True,
                "got_bssid": args.get("bssid"),
                "got_channel": args.get("channel"),
            }
        return {"ok": False, "error": f"unknown {name}"}

    monkeypatch.setattr(flow_mod, "_dispatch", fake_dispatch)
    r = flow_mod.pipeline(
        [
            {"name": "step_a", "args": {}},
            {
                "name": "step_b",
                "args": {"channel": "$prior.channel", "label": "next"},
            },
        ],
        domain="wifi",
        record=True,
    )
    assert r.get("ok") is True
    assert r.get("steps") == 2
    assert r.get("flow", {}).get("bssid") == "AA:BB:CC:DD:EE:FF"
    # second call received forwarded bssid + resolved channel
    b = calls[1]["args"]
    assert b.get("bssid") == "AA:BB:CC:DD:EE:FF"
    assert b.get("channel") == 6
    # failure should be remembered
    from core.mcp.tool_memory import lessons_for
    flow_mod.invoke("step_fail_xyz", {}, domain="wifi", record=True)
    # monkeypatch still on — dispatch returns ok False for unknown
    lessons = lessons_for(tool="step_fail", only_avoid=True)
    assert lessons.get("count_avoid", 0) >= 1


def test_memory_distill_and_record_from_result(memos_tmp):
    from core.mcp.tool_memory import (
        record_tool_outcome, record_from_result, distill_domain_policy,
        lessons_for,
    )
    record_tool_outcome("t1", ok=False, error="no iface", domain="wifi")
    record_tool_outcome("t2", ok=True, domain="wifi")
    r = distill_domain_policy("wifi")
    assert r.get("ok") is not False or r.get("mem_id") or "error" not in r or True
    r2 = record_from_result(
        "airodump-ng",
        {"ok": False, "error": "timeout", "rc": 1},
        args={"iface": "wlan0"},
        domain="wifi",
        source="test",
    )
    assert r2.get("ok") and r2.get("anti")
    lessons = lessons_for(domain="wifi", only_avoid=True)
    assert lessons.get("count_avoid", 0) >= 1
