"""Hermetic tests for core.replan — failure-context visibility, prompt format, MAX_REPLANS."""
from __future__ import annotations

import json
from pathlib import Path

import pytest


# ---------------------------------------------------------------------------
# MAX_REPLANS
# ---------------------------------------------------------------------------

def test_max_replans_is_50():
    from core.replan import MAX_REPLANS
    assert MAX_REPLANS == 50


# ---------------------------------------------------------------------------
# gather_failure_context
# ---------------------------------------------------------------------------

class TestFailureContext:
    def test_minimal_step(self):
        from core.replan import gather_failure_context
        ctx = gather_failure_context(
            step={"action": "wifi_attack", "method": "_evil_twin_automated", "args": {}},
            runner_module="core.wifi_attack.runner",
            method_name="_evil_twin_automated",
            result={"ok": False, "error": "no client"},
        )
        assert "failed_step" in ctx
        assert ctx["method_name"] == "_evil_twin_automated"
        assert ctx["runner_module"] == "core.wifi_attack.runner"
        assert ctx["source_path"] is not None
        assert ctx["source_sha256"] is not None
        assert "add_logging" in ctx["available_patches"]
        assert isinstance(ctx["missing_tools"], list)

    def test_explicit_missing_tools(self):
        from core.replan import gather_failure_context
        ctx = gather_failure_context(
            step={"action": "x"},
            runner_module="core.wifi_attack.runner",
            method_name="_evil_twin_automated",
            result={"ok": False},
            missing_tools=["gatttool", "hashcat"],
        )
        assert "gatttool" in ctx["missing_tools"]
        assert "hashcat" in ctx["missing_tools"]

    def test_unknown_runner(self):
        from core.replan import gather_failure_context
        ctx = gather_failure_context(
            step={},
            runner_module="core.no_such_runner",
            method_name="_foo",
        )
        # Should not raise; returns empty context
        assert ctx["source_path"] is None
        assert ctx["source_sha256"] is None

    def test_unknown_method_on_known_runner(self):
        from core.replan import gather_failure_context
        ctx = gather_failure_context(
            step={},
            runner_module="core.wifi_attack.runner",
            method_name="_no_such_method",
        )
        assert ctx["source_path"] is not None
        assert ctx["source_sha256"] is None
        assert ctx["method_source_excerpt"] is None

    def test_result_with_explicit_missing_tools_field(self):
        from core.replan import gather_failure_context
        ctx = gather_failure_context(
            step={},
            runner_module="core.wifi_attack.runner",
            method_name="_evil_twin_automated",
            result={"ok": False, "missing_tools": ["bully"]},
        )
        assert "bully" in ctx["missing_tools"]

    def test_method_source_excerpt_is_string(self):
        from core.replan import gather_failure_context
        ctx = gather_failure_context(
            step={},
            runner_module="core.wifi_attack.runner",
            method_name="_evil_twin_automated",
        )
        # may be None if the runner has no such method, or a string
        assert ctx["method_source_excerpt"] is None or isinstance(ctx["method_source_excerpt"], str)

    def test_sha_is_64_hex(self):
        from core.replan import gather_failure_context
        ctx = gather_failure_context(
            step={},
            runner_module="core.wifi_attack.runner",
            method_name="_evil_twin_automated",
        )
        sha = ctx["source_sha256"]
        if sha is not None:
            assert len(sha) == 64
            int(sha, 16)  # is hex


# ---------------------------------------------------------------------------
# format_replan_prompt
# ---------------------------------------------------------------------------

class TestReplanPrompt:
    def test_includes_failure_section(self):
        from core.replan import format_replan_prompt

        prompt = format_replan_prompt(
            step={"action": "wifi_attack", "method": "_evil_twin_automated", "args": {}},
            runner_module="core.wifi_attack.runner",
            method_name="_evil_twin_automated",
            result={"ok": False, "error": "no client"},
        )
        assert "REPLAN ON FAILURE" in prompt
        assert "_evil_twin_automated" in prompt
        assert "available_patches" in prompt.lower() or "Available safe-patches" in prompt
        # the prompt mentions the four options
        for opt in ("live_edit", "tool_install", "fresh step", "modified args"):
            assert opt in prompt

    def test_includes_missing_tools(self):
        from core.replan import format_replan_prompt
        prompt = format_replan_prompt(
            step={},
            runner_module="core.wifi_attack.runner",
            method_name="_evil_twin_automated",
            missing_tools=["gatttool"],
        )
        assert "gatttool" in prompt


# ---------------------------------------------------------------------------
# Integration with the chain planner prompt builder
# ---------------------------------------------------------------------------

def test_chain_prompt_can_include_replan_fragment():
    """The chain.py _SYSTEM_PROMPT should be extensible; check that the
    fragment doesn't break anything when we add it."""
    from core.replan import REPLAN_FAILURE_PROMPT_TEMPLATE
    assert "REPLAN ON FAILURE" in REPLAN_FAILURE_PROMPT_TEMPLATE
    assert "{runner_module}" in REPLAN_FAILURE_PROMPT_TEMPLATE
    assert "{method_name}" in REPLAN_FAILURE_PROMPT_TEMPLATE
