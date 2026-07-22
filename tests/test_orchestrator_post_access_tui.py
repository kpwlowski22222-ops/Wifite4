"""Tests for the post-access TUI orchestrator wiring.

Covers:
  * the AI-driven ``open_post_access_tui`` action in
    ``_walk_ai_step`` (single-gate invariant + dispatch)
  * the auto-open hook in ``_maybe_run_gain_access_hooks`` (one-shot
    sentinel + operator-gated in non-autonomous mode)
  * the MCP wrapper ``open_post_access_tui`` exists + is registered
    + routes through the spawner
"""
from __future__ import annotations

import base64
import inspect
import re

import pytest


# ---------------------------------------------------------------------------
# Single-gate invariant for the post-access TUI dispatcher
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
        cleaned = re.sub(r"confirm_fn\s*=\s*[^,)\s]+", "", body)
        return "confirm_fn" in cleaned or "self.confirm" in cleaned

    def test_dispatch_open_post_access_tui_no_reconfirm(self):
        body = self._body("_dispatch_open_post_access_tui")
        assert not self._has_reconfirm(body), (
            f"dispatcher body re-confirms: {body[:200]}..."
        )

    def test_maybe_spawn_post_access_tui_calls_confirm_in_non_autonomous(self):
        # The auto-open hook is operator-gated in non-autonomous mode.
        # It does call self.confirm_fn(...) — but ONLY in the non-autonomous
        # branch and ONLY for the auto-open path. The AI-driven dispatcher
        # (test above) must not re-confirm.
        body = self._body("_maybe_spawn_post_access_tui")
        # The non-autonomous gate IS expected here.
        assert "if not autonomous:" in body
        assert "self.confirm_fn(" in body
        # And the AI-driven auto-open path is one-shot.
        assert "tui_opened" in body


# ---------------------------------------------------------------------------
# End-to-end (faked planner + FakeConfirmFn)
# ---------------------------------------------------------------------------

def _report_with_session(sid: str = "1", target: str = "10.0.0.5"):
    return {
        "executed": [],
        "skipped": [],
        "optional_declined": [],
        "target": target,
        "access": {
            "achieved": True,
            "session_id": sid,
            "transport": "msf",
            "creds": {"user": "root", "host": target, "password": "x"},
            "tui_opened": False,
        },
    }


class TestAutoOpen:
    def test_maybe_spawn_post_access_tui_one_shot(self, monkeypatch):
        """Auto-open spawns at most once per chain (sentinel)."""
        from core.orchestrator.autonomous_orchestrator import AutonomousOrchestrator
        from tests.fakes import FakeAIBackend

        calls = {"n": 0}
        def fake_spawn(report, external_terminal):
            calls["n"] += 1
            # Simulate the spawner writing the sentinel.
            report.setdefault("access", {})["tui_opened"] = True
            return {"ok": True, "pid": 1234}

        import core.post_access_tui.spawner as spawner_mod
        monkeypatch.setattr(spawner_mod, "spawn_post_access_tui", fake_spawn)

        o = AutonomousOrchestrator(
            ai_backend=FakeAIBackend(),
            confirm_fn=lambda p: True,
            on_event=lambda m: None,
        )
        report = _report_with_session()
        # First call: should spawn.
        o._maybe_spawn_post_access_tui(report, autonomous=True)
        # Second call: sentinel kicks in, no spawn.
        o._maybe_spawn_post_access_tui(report, autonomous=True)
        assert calls["n"] == 1
        assert report["access"]["tui_opened"] is True

    def test_maybe_spawn_post_access_tui_no_access(self, monkeypatch):
        """When access is not achieved, hook is a no-op."""
        from core.orchestrator.autonomous_orchestrator import AutonomousOrchestrator
        from tests.fakes import FakeAIBackend

        calls = {"n": 0}
        def fake_spawn(report, external_terminal):
            calls["n"] += 1
            return {"ok": True, "pid": 1234}

        import core.post_access_tui.spawner as spawner_mod
        monkeypatch.setattr(spawner_mod, "spawn_post_access_tui", fake_spawn)

        o = AutonomousOrchestrator(
            ai_backend=FakeAIBackend(),
            confirm_fn=lambda p: True,
            on_event=lambda m: None,
        )
        report = {"executed": [], "skipped": [], "access": {"achieved": False}}
        o._maybe_spawn_post_access_tui(report, autonomous=True)
        assert calls["n"] == 0

    def test_maybe_spawn_post_access_tui_cancelled(self, monkeypatch):
        """Non-autonomous + CANCEL → no spawn, no sentinel flip."""
        from core.orchestrator.autonomous_orchestrator import AutonomousOrchestrator
        from tests.fakes import FakeAIBackend

        calls = {"n": 0}
        def fake_spawn(report, external_terminal):
            calls["n"] += 1
            return {"ok": True, "pid": 1234}

        import core.post_access_tui.spawner as spawner_mod
        monkeypatch.setattr(spawner_mod, "spawn_post_access_tui", fake_spawn)

        o = AutonomousOrchestrator(
            ai_backend=FakeAIBackend(),
            confirm_fn=lambda p: False,  # operator CANCEL
            on_event=lambda m: None,
        )
        report = _report_with_session()
        o._maybe_spawn_post_access_tui(report, autonomous=False)
        assert calls["n"] == 0
        # Sentinel NOT flipped on CANCEL.
        assert report["access"].get("tui_opened") is False


class TestAIDispatch:
    def test_dispatch_open_post_access_tui_records_step(self, monkeypatch):
        from core.orchestrator.autonomous_orchestrator import AutonomousOrchestrator
        from tests.fakes import FakeAIBackend

        def fake_spawn(report, external_terminal):
            return {"ok": True, "pid": 5678}

        import core.post_access_tui.spawner as spawner_mod
        monkeypatch.setattr(spawner_mod, "spawn_post_access_tui", fake_spawn)

        o = AutonomousOrchestrator(
            ai_backend=FakeAIBackend(),
            confirm_fn=lambda p: True,
            on_event=lambda m: None,
        )
        seed = {}
        report = _report_with_session()
        step = {"action": "open_post_access_tui", "args": {}}
        o._dispatch_open_post_access_tui(step, seed, report)
        assert len(report["executed"]) == 1
        e = report["executed"][0]
        assert e["action"] == "open_post_access_tui"
        assert e["result"]["ok"] is True
        assert e["result"]["pid"] == 5678

    def test_dispatch_open_post_access_tui_spawn_failure(self, monkeypatch):
        from core.orchestrator.autonomous_orchestrator import AutonomousOrchestrator
        from tests.fakes import FakeAIBackend

        def fake_spawn(report, external_terminal):
            return {"ok": False, "error": "no real terminal backend",
                    "manual": "python -m core.post_access_tui --state-b64 .."}

        import core.post_access_tui.spawner as spawner_mod
        monkeypatch.setattr(spawner_mod, "spawn_post_access_tui", fake_spawn)

        o = AutonomousOrchestrator(
            ai_backend=FakeAIBackend(),
            confirm_fn=lambda p: True,
            on_event=lambda m: None,
        )
        seed = {}
        report = _report_with_session()
        step = {"action": "open_post_access_tui", "args": {}}
        o._dispatch_open_post_access_tui(step, seed, report)
        # Even on failure, the step is recorded (honest degradation).
        assert len(report["executed"]) == 1
        e = report["executed"][0]
        assert e["action"] == "open_post_access_tui"
        assert e["result"]["ok"] is False
        assert "no real terminal backend" in e["result"]["error"]


class TestWalkAIStep:
    def test_walk_ai_step_routes_open_post_access_tui(self, monkeypatch):
        """``_walk_ai_step`` dispatches ``open_post_access_tui`` action
        via the dedicated dispatcher (single-gate)."""
        from core.orchestrator.autonomous_orchestrator import AutonomousOrchestrator
        from tests.fakes import FakeAIBackend

        def fake_spawn(report, external_terminal):
            return {"ok": True, "pid": 9999}

        import core.post_access_tui.spawner as spawner_mod
        monkeypatch.setattr(spawner_mod, "spawn_post_access_tui", fake_spawn)

        o = AutonomousOrchestrator(
            ai_backend=FakeAIBackend(),
            confirm_fn=lambda p: True,
            on_event=lambda m: None,
        )
        seed = {"target": "10.0.0.5"}
        report = _report_with_session()
        # Pass the step directly (the planner is faked); _walk_ai_step
        # should route to _dispatch_open_post_access_tui.
        o._walk_ai_step(
            {"action": "open_post_access_tui", "args": {}},
            seed, report, autonomous=True,
        )
        # The dispatcher ran; the step is in executed.
        assert any(
            e.get("action") == "open_post_access_tui"
            for e in report["executed"]
        )


# ---------------------------------------------------------------------------
# MCP wrapper
# ---------------------------------------------------------------------------

class TestMCPWrapper:
    def test_open_post_access_tui_in_wrappers(self):
        from core.mcp.tools import KALI_TOOL_WRAPPERS
        assert "open_post_access_tui" in KALI_TOOL_WRAPPERS

    def test_open_post_access_tui_in_mcp_record(self):
        from core.mcp.tools import list_mcp_tools
        records = list_mcp_tools()
        rec = next((r for r in records if r["name"] == "open_post_access_tui"), None)
        assert rec is not None
        assert rec["domain"] == "post_exploitation"
        # Single-gate: schema does NOT include a 'confirm' field.
        assert "confirm" not in str(rec.get("input_schema", {}))

    def test_open_post_access_tui_routes_through_spawner(self, monkeypatch):
        from core.mcp import tools

        called = {"n": 0}
        def fake_spawn(report, external_terminal):
            called["n"] += 1
            return {"ok": True, "pid": 42}

        import core.post_access_tui.spawner as spawner_mod
        monkeypatch.setattr(spawner_mod, "spawn_post_access_tui", fake_spawn)

        # Build a report with the required session fields.
        report = _report_with_session()
        # The MCP wrapper expects a base64 of creds.
        creds_b64 = base64.b64encode(b"hunter2").decode("ascii")
        report["access"]["creds_b64"] = creds_b64

        runner = tools.KALI_TOOL_WRAPPERS["open_post_access_tui"]._runner
        out = runner({"report": report})
        assert called["n"] == 1
        assert out["ok"] is True
        assert out["pid"] == 42

    def test_open_post_access_tui_rejects_non_dict_report(self):
        from core.mcp.tools import KALI_TOOL_WRAPPERS
        runner = KALI_TOOL_WRAPPERS["open_post_access_tui"]._runner
        out = runner({"report": "not a dict"})
        assert out["ok"] is False
        assert "must be a dict" in out["error"]


# ---------------------------------------------------------------------------
# Dashboard pill
# ---------------------------------------------------------------------------

class TestDashboardPill:
    def test_dashboard_pill_no_access(self):
        from core.tui.dashboard import KfiosaDashboard
        d = KfiosaDashboard.__new__(KfiosaDashboard)
        d.post_access_status = {}
        assert d._status_post_access() == ""

    def test_dashboard_pill_ready(self):
        from core.tui.dashboard import KfiosaDashboard
        d = KfiosaDashboard.__new__(KfiosaDashboard)
        d.post_access_status = {
            "achieved": True, "session_id": "3", "transport": "msf",
        }
        out = d._status_post_access()
        assert "POST-ACCESS TUI" in out
        assert "ready" in out
        assert "sid=3" in out

    def test_dashboard_pill_open(self):
        from core.tui.dashboard import KfiosaDashboard
        d = KfiosaDashboard.__new__(KfiosaDashboard)
        d.post_access_status = {
            "achieved": True, "session_id": "1", "transport": "ssh",
            "tui_opened": True,
        }
        out = d._status_post_access()
        assert "open" in out
        assert "sid=1" in out
        assert "ssh" in out

    def test_dashboard_pill_no_sid(self):
        """A creds-only chain (no session_id) still surfaces the pill."""
        from core.tui.dashboard import KfiosaDashboard
        d = KfiosaDashboard.__new__(KfiosaDashboard)
        d.post_access_status = {"achieved": True, "creds": "x"}
        out = d._status_post_access()
        assert "POST-ACCESS TUI" in out
        assert "no-sid" in out

    def test_orchestrator_pushes_status_to_dashboard(self, monkeypatch):
        from core.orchestrator.autonomous_orchestrator import AutonomousOrchestrator
        from tests.fakes import FakeAIBackend

        # Wire a fake dashboard.
        class FakeDashboard:
            def __init__(self):
                self.post_access_status = {}

        def fake_spawn(report, external_terminal):
            # Simulate the spawner flipping the sentinel.
            report.setdefault("access", {})["tui_opened"] = True
            return {"ok": True, "pid": 11}

        import core.post_access_tui.spawner as spawner_mod
        monkeypatch.setattr(spawner_mod, "spawn_post_access_tui", fake_spawn)

        d = FakeDashboard()
        o = AutonomousOrchestrator(
            ai_backend=FakeAIBackend(),
            confirm_fn=lambda p: True,
            on_event=lambda m: None,
            dashboard=d,
        )
        report = _report_with_session()
        o._maybe_spawn_post_access_tui(report, autonomous=True)
        # Dashboard was pushed.
        assert d.post_access_status.get("achieved") is True
        assert d.post_access_status.get("session_id") == "1"
        assert d.post_access_status.get("tui_opened") is True

    def test_orchestrator_no_dashboard_no_crash(self, monkeypatch):
        """When dashboard is not wired, _push_dashboard_post_access
        is a no-op (no AttributeError)."""
        from core.orchestrator.autonomous_orchestrator import AutonomousOrchestrator
        from tests.fakes import FakeAIBackend

        def fake_spawn(report, external_terminal):
            return {"ok": True, "pid": 12}

        import core.post_access_tui.spawner as spawner_mod
        monkeypatch.setattr(spawner_mod, "spawn_post_access_tui", fake_spawn)

        o = AutonomousOrchestrator(
            ai_backend=FakeAIBackend(),
            confirm_fn=lambda p: True,
            on_event=lambda m: None,
            # no dashboard= arg
        )
        report = _report_with_session()
        # Should not raise.
        o._maybe_spawn_post_access_tui(report, autonomous=True)
        # Push helper is a no-op (self.dashboard doesn't exist).
        o._push_dashboard_post_access(report.get("access", {}))
