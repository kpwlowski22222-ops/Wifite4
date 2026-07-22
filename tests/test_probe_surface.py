#!/usr/bin/env python3
"""
Surface tests for osint_probe and post_exploit_probe actions:
- Orchestrator _execute_step routing (accept + cancel gates)
- Chain prompt mentions new actions
"""
import socket

import pytest

from core.orchestrator.autonomous_orchestrator import AutonomousOrchestrator
from core.ai_backend.chain import _SYSTEM_PROMPT, _CHAIN_STEP_SCHEMA_HINT


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def block_network(monkeypatch):
    """Block all socket connections so no real network calls happen."""
    def _blocked(*args, **kwargs):
        raise RuntimeError("Network blocked in tests")
    monkeypatch.setattr(socket.socket, "connect", _blocked)


def _make_orchestrator(confirm_result=True):
    prompts = []
    return AutonomousOrchestrator(
        confirm_fn=lambda p: (prompts.append(p) or confirm_result),
        on_event=lambda m: None,
    ), prompts


# ---------------------------------------------------------------------------
# Chain prompt tests
# ---------------------------------------------------------------------------

def test_chain_prompt_has_osint_probe_action():
    """_CHAIN_STEP_SCHEMA_HINT lists osint_probe as a valid action."""
    assert "osint_probe" in _CHAIN_STEP_SCHEMA_HINT


def test_chain_prompt_has_post_exploit_probe_action():
    """_CHAIN_STEP_SCHEMA_HINT lists post_exploit_probe as a valid action."""
    assert "post_exploit_probe" in _CHAIN_STEP_SCHEMA_HINT


def test_system_prompt_documents_osint_probe_methods():
    """_SYSTEM_PROMPT names all 4 OSINT probe methods for the LLM."""
    for method in ("username_patterns", "breach_correlate",
                   "phone_carrier", "social_graph"):
        assert method in _SYSTEM_PROMPT, (
            f"OSINT probe method '{method}' not found in _SYSTEM_PROMPT"
        )


def test_system_prompt_documents_post_exploit_probe_methods():
    """_SYSTEM_PROMPT names all 4 post-exploit probe methods for the LLM."""
    for method in ("priv_esc_check", "cred_enumerate",
                   "lateral_movement", "persistence_id"):
        assert method in _SYSTEM_PROMPT, (
            f"Post-exploit method '{method}' not found in _SYSTEM_PROMPT"
        )


def test_system_prompt_documents_mcp_probe_names():
    """_SYSTEM_PROMPT references MCP names for the new probes."""
    assert "osint_probe_username_patterns" in _SYSTEM_PROMPT
    assert "post_exploit_probe_priv_esc_check" in _SYSTEM_PROMPT


# ---------------------------------------------------------------------------
# Orchestrator osint_probe routing tests
# ---------------------------------------------------------------------------

def test_execute_step_osint_probe_unknown_method_returns_error():
    """osint_probe with an unregistered method returns an error dict."""
    orch, _ = _make_orchestrator(confirm_result=True)
    result = orch._execute_step(
        {"action": "osint_probe", "method": "nonexistent_algo", "target": "foo"},
        {}
    )
    assert "error" in result
    assert "nonexistent_algo" in result["error"]


def test_execute_step_osint_probe_blocked_by_confirm_fn():
    """osint_probe is blocked when confirm_fn returns False."""
    orch, prompts = _make_orchestrator(confirm_result=False)
    result = orch._execute_step(
        {"action": "osint_probe", "method": "username_patterns",
         "target": "testuser"},
        {}
    )
    # Prompt was offered
    assert any("osint_probe" in p or "username_patterns" in p for p in prompts)
    # Step was blocked
    assert result.get("ok") is False
    assert "blocked by confirm_fn" in result.get("error", "")


def test_execute_step_osint_probe_username_patterns_accepted():
    """osint_probe runs username_patterns when confirm_fn returns True."""
    orch, _ = _make_orchestrator(confirm_result=True)
    result = orch._execute_step(
        {"action": "osint_probe", "method": "username_patterns",
         "target": "admin_user"},
        {}
    )
    # Should return a dict with value (not an error)
    assert isinstance(result, dict)
    assert "error" not in result or result.get("error") is None


def test_execute_step_osint_probe_uses_seed_target_when_step_target_missing():
    """osint_probe falls back to seed['target'] when step has no target key."""
    orch, _ = _make_orchestrator(confirm_result=True)
    result = orch._execute_step(
        {"action": "osint_probe", "method": "username_patterns"},
        {"target": "seeduser"}
    )
    assert isinstance(result, dict)


# ---------------------------------------------------------------------------
# Orchestrator post_exploit_probe routing tests
# ---------------------------------------------------------------------------

def test_execute_step_post_exploit_probe_blocked_by_confirm_fn():
    """post_exploit_probe is blocked when confirm_fn returns False."""
    orch, prompts = _make_orchestrator(confirm_result=False)
    result = orch._execute_step(
        {"action": "post_exploit_probe", "method": "priv_esc_check",
         "target_info": {}},
        {}
    )
    assert any("post_exploit_probe" in p or "priv_esc_check" in p for p in prompts)
    assert result.get("ok") is False
    assert "blocked by confirm_fn" in result.get("error", "")


def test_execute_step_post_exploit_probe_unknown_method_returns_error():
    """post_exploit_probe with an unknown method returns an error dict."""
    orch, _ = _make_orchestrator(confirm_result=True)
    result = orch._execute_step(
        {"action": "post_exploit_probe", "method": "nonexistent_method",
         "target_info": {}},
        {}
    )
    assert "error" in result
    assert "nonexistent_method" in result["error"]


def test_execute_step_post_exploit_probe_priv_esc_accepted():
    """post_exploit_probe runs priv_esc_check when accepted."""
    orch, _ = _make_orchestrator(confirm_result=True)
    target_info = {
        "details": {"os": "Linux", "services": [], "shares": [],
                    "remote_management": [], "trusts": []}
    }
    result = orch._execute_step(
        {"action": "post_exploit_probe", "method": "priv_esc_check",
         "target_info": target_info},
        {}
    )
    assert isinstance(result, dict)


def test_execute_step_post_exploit_probe_all_four_methods():
    """All 4 post-exploit probes execute without raising."""
    orch, _ = _make_orchestrator(confirm_result=True)
    target_info = {"details": {"os": "Windows", "services": [],
                               "shares": [], "remote_management": [],
                               "trusts": []}}
    for method in ("priv_esc_check", "cred_enumerate",
                   "lateral_movement", "persistence_id"):
        result = orch._execute_step(
            {"action": "post_exploit_probe", "method": method,
             "target_info": target_info},
            {}
        )
        assert isinstance(result, dict), (
            f"post_exploit_probe/{method} did not return a dict"
        )
