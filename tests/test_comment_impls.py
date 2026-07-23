"""Tests for comment-driven implementations (placeholders filled)."""
from __future__ import annotations

import asyncio

import pytest


# ---------------------------------------------------------------------------
# Metasploit integration (was empty placeholder file)
# ---------------------------------------------------------------------------


def test_metasploit_check_toolchain():
    from core.modules.metasploit_integration import check_msf_toolchain
    st = check_msf_toolchain()
    assert "ok" in st
    assert "msfconsole" in st
    assert "msfvenom" in st


def test_metasploit_plan_without_session_tools():
    from core.modules.metasploit_integration import MetasploitIntegration
    m = MetasploitIntegration(confirm_fn=lambda _p: False)
    # Even if msf missing, plan returns structured envelope
    out = m.plan({"os": "linux", "id": "1"})
    assert "ok" in out
    assert "steps" in out
    assert isinstance(out["steps"], list)


def test_metasploit_payload_default_deny():
    from core.modules.metasploit_integration import MetasploitIntegration
    m = MetasploitIntegration(confirm_fn=None)
    out = m.generate_payload("linux/x64/meterpreter/reverse_tcp", "127.0.0.1", 4444)
    assert out["ok"] is False
    assert "confirm" in out["error"].lower() or "blocked" in out["error"].lower()


# ---------------------------------------------------------------------------
# Post-exploitation — no fabricated credentials
# ---------------------------------------------------------------------------


def test_post_exploit_no_fake_creds():
    from core.modules.post_exploitation import PostExploitationModule
    mod = PostExploitationModule(confirm_fn=lambda _p: True)
    r = asyncio.get_event_loop().run_until_complete(
        mod.execute_action({}, "credential_harvest", {})
    )
    assert r.get("ok") is False or r.get("success") is False
    assert "usernames" not in (r.get("data") or {})
    assert "passwords" not in (r.get("data") or {})


def test_post_exploit_pivot_requires_scope_or_local():
    from core.modules.post_exploitation import PostExploitationModule
    mod = PostExploitationModule(confirm_fn=lambda _p: True)
    r = asyncio.get_event_loop().run_until_complete(
        mod.execute_action({}, "network_pivot", {})
    )
    # Either tools missing or local view — never fake host counts as success data
    data = r.get("data") or {}
    assert "hosts_compromised" not in data
    assert "internal_networks_discovered" not in data


def test_post_exploit_default_deny_without_gate():
    from core.modules.post_exploitation import PostExploitationModule
    mod = PostExploitationModule(confirm_fn=None)
    r = asyncio.get_event_loop().run_until_complete(
        mod.execute_action({}, "exfiltrate", {"src": "/tmp/x", "dst": "http://x"})
    )
    assert r.get("ok") is False
    assert "confirm" in (r.get("error") or "").lower() or "blocked" in (r.get("error") or "").lower()


# ---------------------------------------------------------------------------
# Exploit parser recency
# ---------------------------------------------------------------------------


def test_exploit_parser_recency_recent_beats_old():
    from core.utils.exploit_parser import ExploitParser
    p = ExploitParser()
    recent = p._recency_score("Date: 2025-01-15\nremote code execution shell", "RCE")
    old = p._recency_score("Date: 2005-01-15\nremote code execution shell", "RCE")
    assert recent > old
    unknown = p._recency_score("no date here", "x")
    assert unknown == 0.5


# ---------------------------------------------------------------------------
# extended_ble which_with_install
# ---------------------------------------------------------------------------


def test_which_with_install_present():
    from core.extended_ble.runner import _which_with_install
    # python3 should be on PATH in test env
    assert _which_with_install("python3") is True
    assert _which_with_install("this-binary-does-not-exist-xyz", try_install=False) is False


# ---------------------------------------------------------------------------
# AI planner loads poly_adapt data
# ---------------------------------------------------------------------------


def test_ai_planner_loads_planning_data():
    from core.modules.ai_planner import AIPlanner
    p = AIPlanner()
    asyncio.get_event_loop().run_until_complete(p._load_planning_data())
    # Registry should load in this project
    assert isinstance(p.poly_adapt_methods, list)
    assert len(p.poly_adapt_methods) > 0
