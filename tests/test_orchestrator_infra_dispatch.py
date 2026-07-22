"""Tests for the live_edit and tool_install dispatchers in the orchestrator.

The single-gate invariant applies: the per-step ACCEPT already fired in
``_walk_ai_step``; the dispatcher itself must NOT call confirm_fn or
self.confirm.
"""
from __future__ import annotations

import inspect

import pytest


# ---------------------------------------------------------------------------
# Single-gate invariant for live_edit and tool_install dispatchers
# ---------------------------------------------------------------------------

class TestSingleGate:
    def _body(self, name):
        from core.orchestrator import autonomous_orchestrator as mod

        src = inspect.getsource(mod)
        i = src.find(f"def {name}")
        j = src.find("\n    def ", i + 1)
        if j < 0:
            j = len(src)
        return src[i:j]

    def _has_reconfirm(self, body):
        """The dispatcher must not CALL confirm_fn or self.confirm.

        Argument `confirm_fn=None` in a function call (like
        `apply_patch(spec, confirm_fn=None)`) is NOT a re-confirm — the
        patch path's own gate. We exclude argument references.
        """
        import re
        # strip `confirm_fn=None` keyword argument references
        cleaned = re.sub(r"confirm_fn\s*=\s*[^,)\s]+", "", body)
        return "confirm_fn" in cleaned or "self.confirm" in cleaned

    def test_dispatch_live_edit_no_reconfirm(self):
        body = self._body("_dispatch_live_edit")
        assert not self._has_reconfirm(body), (
            f"dispatcher body re-confirms: {body[:200]}...")

    def test_dispatch_tool_install_no_reconfirm(self):
        body = self._body("_dispatch_tool_install")
        assert not self._has_reconfirm(body), (
            f"dispatcher body re-confirms: {body[:200]}...")


# ---------------------------------------------------------------------------
# End-to-end (faked planner + FakeConfirmFn)
# ---------------------------------------------------------------------------

class TestLiveEditDispatch:
    def test_dispatch_live_edit_records_step(self):
        from core.orchestrator.autonomous_orchestrator import AutonomousOrchestrator
        from tests.fakes import FakeAIBackend

        events = []
        o = AutonomousOrchestrator(
            ai_backend=FakeAIBackend(),
            confirm_fn=lambda p: True,  # per-step gate accepts
            on_event=lambda m: events.append(m),
        )
        seed = {}
        report = {"executed": [], "skipped": [], "optional_declined": []}
        step = {
            "action": "live_edit",
            "args": {
                "patch_id": "add_logging",
                "target_runner": "core.wifi_attack.runner",
                "target_method": "_evil_twin_automated",
                "params": {},
            },
            "rationale": "bump logging on evil twin for the failing case",
        }
        o._dispatch_live_edit(step, seed, report)
        assert len(report["executed"]) == 1
        e = report["executed"][0]
        assert e["action"] == "live_edit"
        assert e["result"]["ok"] is True
        assert e["result"]["patch_id"] == "add_logging"
        # recorded in seed
        assert len(seed["live_edits"]) == 1
        assert seed["live_edits"][0]["patch_id"] == "add_logging"

    def test_dispatch_live_edit_missing_args(self):
        from core.orchestrator.autonomous_orchestrator import AutonomousOrchestrator
        from tests.fakes import FakeAIBackend

        o = AutonomousOrchestrator(
            ai_backend=FakeAIBackend(),
            confirm_fn=lambda p: True,
            on_event=lambda m: None,
        )
        seed = {}
        report = {"executed": [], "skipped": [], "optional_declined": []}
        step = {"action": "live_edit", "args": {}, "rationale": "x"}
        o._dispatch_live_edit(step, seed, report)
        assert len(report["executed"]) == 0
        assert any("missing" in s for s in report["skipped"])

    def test_dispatch_live_edit_validation_refuses(self):
        from core.orchestrator.autonomous_orchestrator import AutonomousOrchestrator
        from tests.fakes import FakeAIBackend

        o = AutonomousOrchestrator(
            ai_backend=FakeAIBackend(),
            confirm_fn=lambda p: True,
            on_event=lambda m: None,
        )
        seed = {}
        report = {"executed": [], "skipped": [], "optional_declined": []}
        step = {
            "action": "live_edit",
            "args": {
                "patch_id": "add_logging",
                "target_runner": "core.wifi_attack.runner",
                "target_method": "_does_not_exist",
                "params": {},
            },
            "rationale": "x",
        }
        o._dispatch_live_edit(step, seed, report)
        # refused
        assert len(report["executed"]) == 0
        assert any("live_edit" in s for s in report["skipped"])


class TestToolInstallDispatch:
    def test_dispatch_tool_install_records_step(self, monkeypatch):
        from core.orchestrator.autonomous_orchestrator import AutonomousOrchestrator
        from tests.fakes import FakeAIBackend

        # Pretend hashcat is in PATH after install
        import shutil
        monkeypatch.setattr(shutil, "which", lambda t: "/usr/bin/hashcat" if t == "hashcat" else None)
        monkeypatch.setattr("subprocess.run", lambda *a, **kw: type("P", (), {"returncode": 0, "stdout": "", "stderr": ""})())

        o = AutonomousOrchestrator(
            ai_backend=FakeAIBackend(),
            confirm_fn=lambda p: True,
            on_event=lambda m: None,
        )
        seed = {}
        report = {"executed": [], "skipped": [], "optional_declined": []}
        # `auto=True` bypasses the per-install confirm gate (the per-step
        # ACCEPT in _walk_ai_step is the operator's gate; auto=True means
        # the step was approved with auto-install included).
        step = {"action": "tool_install", "args": {"tool": "hashcat", "auto": True}, "rationale": "x"}
        o._dispatch_tool_install(step, seed, report)
        assert len(report["executed"]) == 1
        e = report["executed"][0]
        assert e["action"] == "tool_install"
        assert e["result"]["ok"] is True
        assert e["result"]["tool"] == "hashcat"
        assert len(seed["tool_installs"]) == 1

    def test_dispatch_tool_install_missing_tool(self):
        from core.orchestrator.autonomous_orchestrator import AutonomousOrchestrator
        from tests.fakes import FakeAIBackend

        o = AutonomousOrchestrator(
            ai_backend=FakeAIBackend(),
            confirm_fn=lambda p: True,
            on_event=lambda m: None,
        )
        seed = {}
        report = {"executed": [], "skipped": [], "optional_declined": []}
        step = {"action": "tool_install", "args": {}, "rationale": "x"}
        o._dispatch_tool_install(step, seed, report)
        assert len(report["executed"]) == 0
        assert any("tool_install" in s for s in report["skipped"])

    def test_dispatch_tool_install_unknown_tool(self):
        from core.orchestrator.autonomous_orchestrator import AutonomousOrchestrator
        from tests.fakes import FakeAIBackend

        o = AutonomousOrchestrator(
            ai_backend=FakeAIBackend(),
            confirm_fn=lambda p: True,
            on_event=lambda m: None,
        )
        seed = {}
        report = {"executed": [], "skipped": [], "optional_declined": []}
        step = {"action": "tool_install", "args": {"tool": "not_in_catalog_xx"}, "rationale": "x"}
        o._dispatch_tool_install(step, seed, report)
        assert len(report["executed"]) == 0
        assert any("not in catalog" in s for s in report["skipped"])

    def test_dispatch_tool_install_install_fails_honest(self, monkeypatch):
        from core.orchestrator.autonomous_orchestrator import AutonomousOrchestrator
        from tests.fakes import FakeAIBackend

        import shutil
        monkeypatch.setattr(shutil, "which", lambda t: None)  # never present
        monkeypatch.setattr("subprocess.run", lambda *a, **kw: type("P", (), {"returncode": 1, "stdout": "", "stderr": "fail"})())

        o = AutonomousOrchestrator(
            ai_backend=FakeAIBackend(),
            confirm_fn=lambda p: True,
            on_event=lambda m: None,
        )
        seed = {}
        report = {"executed": [], "skipped": [], "optional_declined": []}
        step = {"action": "tool_install", "args": {"tool": "hashcat"}, "rationale": "x"}
        o._dispatch_tool_install(step, seed, report)
        # recorded (with ok=False) — never fake success
        assert len(report["executed"]) == 1
        e = report["executed"][0]
        assert e["result"]["ok"] is False
        assert seed["tool_installs"][0]["ok"] is False


# ---------------------------------------------------------------------------
# End-to-end routing through _walk_ai_step (single-gate invariant)
# ---------------------------------------------------------------------------

class TestWalkAIStepRoutes:
    def test_walk_ai_step_routes_live_edit_and_fires_gate_once(self):
        from core.orchestrator.autonomous_orchestrator import AutonomousOrchestrator
        from tests.fakes import FakeAIBackend

        gate_calls = []
        def gate(prompt):
            gate_calls.append(prompt)
            return True

        o = AutonomousOrchestrator(
            ai_backend=FakeAIBackend(),
            confirm_fn=gate,
            on_event=lambda m: None,
        )
        seed = {}
        report = {"executed": [], "skipped": [], "optional_declined": []}
        step = {
            "action": "live_edit",
            "args": {
                "patch_id": "add_logging",
                "target_runner": "core.wifi_attack.runner",
                "target_method": "_evil_twin_automated",
                "params": {},
            },
            "rationale": "bump logging for failure case",
        }
        o._walk_ai_step(step, seed, report, autonomous=False)
        # The per-step gate fires EXACTLY ONCE (not re-fired by the
        # dispatcher; that's the single-gate invariant).
        assert len(gate_calls) == 1
        # The dispatch actually executed (or recorded the step)
        # Note: validation may pass or fail depending on which runner
        # method, but the step is at least attempted
        assert len(report["executed"]) + len(report["skipped"]) == 1

    def test_walk_ai_step_routes_tool_install_and_fires_gate_once(self, monkeypatch):
        from core.orchestrator.autonomous_orchestrator import AutonomousOrchestrator
        from tests.fakes import FakeAIBackend

        import shutil
        monkeypatch.setattr(shutil, "which", lambda t: "/usr/bin/x" if t == "hashcat" else None)
        monkeypatch.setattr("subprocess.run", lambda *a, **kw: type("P", (), {"returncode": 0, "stdout": "", "stderr": ""})())

        gate_calls = []
        def gate(prompt):
            gate_calls.append(prompt)
            return True

        o = AutonomousOrchestrator(
            ai_backend=FakeAIBackend(),
            confirm_fn=gate,
            on_event=lambda m: None,
        )
        seed = {}
        report = {"executed": [], "skipped": [], "optional_declined": []}
        step = {
            "action": "tool_install",
            "args": {"tool": "hashcat", "auto": True},
            "rationale": "x",
        }
        o._walk_ai_step(step, seed, report, autonomous=False)
        # Per-step gate fires EXACTLY ONCE
        assert len(gate_calls) == 1
        # The step recorded
        assert len(report["executed"]) == 1
        assert report["executed"][0]["action"] == "tool_install"

    def test_walk_ai_step_cancelled_skips_both_dispatchers(self, monkeypatch):
        from core.orchestrator.autonomous_orchestrator import AutonomousOrchestrator
        from tests.fakes import FakeAIBackend

        gate_calls = []
        def gate(prompt):
            gate_calls.append(prompt)
            return False  # CANCEL

        o = AutonomousOrchestrator(
            ai_backend=FakeAIBackend(),
            confirm_fn=gate,
            on_event=lambda m: None,
        )
        seed = {}
        report = {"executed": [], "skipped": [], "optional_declined": []}
        step = {
            "action": "tool_install",
            "args": {"tool": "hashcat"},
            "rationale": "x",
        }
        o._walk_ai_step(step, seed, report, autonomous=False)
        # Gate fired once; CANCEL means the dispatcher did not run
        assert len(gate_calls) == 1
        # No executed entry
        assert len(report["executed"]) == 0
        # Skipped was recorded
        assert len(report["skipped"]) == 1
