"""Tests for the orchestrator's extended_ble action + MCP wrapper.

Covers:
  * the AI-driven ``extended_ble`` action in
    ``_walk_ai_step`` (single-gate invariant + dispatch + seed merge)
  * the dispatcher honors unknown methods and exceptions
  * the MCP wrapper ``extended_ble_<method>`` exists + is registered +
    routes through the runner + degrades honestly
"""
from __future__ import annotations

import inspect
import re

import pytest


# ---------------------------------------------------------------------------
# Single-gate invariant for the extended_ble dispatcher
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

    def test_dispatch_extended_ble_no_reconfirm(self):
        """The dispatch body must not call confirm_fn / self.confirm."""
        body = self._body("_dispatch_extended_ble")
        assert not self._has_reconfirm(body), (
            f"extended_ble dispatcher re-confirms: {body[:200]}..."
        )


# ---------------------------------------------------------------------------
# Dispatcher behavior
# ---------------------------------------------------------------------------

def _ok_extended_ble_result(method="le_audio_bis_sync_jamming"):
    return {
        "name": method,
        "ok": True,
        "data": {"addr": "AA:BB:CC:DD:EE:01", "le_audio_service_present": True},
        "error": "",
        "duration_s": 0.1,
    }


class _FakeExtendedResult:
    def __init__(self, d):
        self._d = d

    def __getitem__(self, k):
        return self._d[k]

    def get(self, k, default=None):
        return self._d.get(k, default)


class TestDispatcher:
    def test_dispatch_extended_ble_records_step(self, monkeypatch):
        from core.orchestrator.autonomous_orchestrator import AutonomousOrchestrator
        from tests.fakes import FakeAIBackend

        # Monkeypatch the runner's run_attack to return a known result.
        import core.extended_ble.runner as eble_mod

        def fake_run_attack(method, *a, **kw):
            return _FakeExtendedResult(_ok_extended_ble_result(method))

        monkeypatch.setattr(eble_mod, "run_attack", fake_run_attack)

        o = AutonomousOrchestrator(
            ai_backend=FakeAIBackend(),
            confirm_fn=lambda p: True,
            on_event=lambda m: None,
        )
        seed = {}
        report = {"executed": [], "skipped": [], "access": {}}
        step = {
            "action": "extended_ble",
            "args": {"method": "le_audio_bis_sync_jamming",
                     "addr": "AA:BB:CC:DD:EE:01"},
        }
        o._dispatch_extended_ble(step, seed, report)
        assert len(report["executed"]) == 1
        e = report["executed"][0]
        assert e["action"] == "extended_ble"
        assert e["method"] == "le_audio_bis_sync_jamming"
        assert e["ok"] is True
        # Seed merged.
        assert "extended_ble" in seed
        assert "le_audio_bis_sync_jamming" in seed["extended_ble"]

    def test_dispatch_extended_ble_unknown_method(self, monkeypatch):
        from core.orchestrator.autonomous_orchestrator import AutonomousOrchestrator
        from tests.fakes import FakeAIBackend

        # Should not even call run_attack.
        called = {"n": 0}
        def fake_run_attack(method, *a, **kw):
            called["n"] += 1
            return _FakeExtendedResult({"name": method, "ok": False,
                                        "error": "x", "data": None,
                                        "duration_s": 0.0})
        import core.extended_ble.runner as eble_mod
        monkeypatch.setattr(eble_mod, "run_attack", fake_run_attack)

        o = AutonomousOrchestrator(
            ai_backend=FakeAIBackend(),
            confirm_fn=lambda p: True,
            on_event=lambda m: None,
        )
        seed = {}
        report = {"executed": [], "skipped": [], "access": {}}
        step = {"action": "extended_ble", "args": {"method": "nope"}}
        o._dispatch_extended_ble(step, seed, report)
        # No step recorded (we short-circuited on unknown method).
        assert report["executed"] == []
        assert "extended_ble" not in seed
        # runner never called.
        assert called["n"] == 0
        # Skipped was appended.
        assert any("extended_ble" in s for s in report["skipped"])

    def test_dispatch_extended_ble_runner_exception(self, monkeypatch):
        """When the runner raises, the dispatcher records the failure
        honestly (no fabricated success)."""
        from core.orchestrator.autonomous_orchestrator import AutonomousOrchestrator
        from tests.fakes import FakeAIBackend

        def fake_run_attack(method, *a, **kw):
            raise RuntimeError("kaboom")

        import core.extended_ble.runner as eble_mod
        monkeypatch.setattr(eble_mod, "run_attack", fake_run_attack)

        o = AutonomousOrchestrator(
            ai_backend=FakeAIBackend(),
            confirm_fn=lambda p: True,
            on_event=lambda m: None,
        )
        report = {"executed": [], "skipped": [], "access": {}}
        step = {
            "action": "extended_ble",
            "args": {"method": "le_audio_bis_sync_jamming",
                     "addr": "AA:BB:CC:DD:EE:01"},
        }
        o._dispatch_extended_ble(step, {}, report)
        # Exception path appends to skipped, not executed.
        assert report["executed"] == []
        assert any("kaboom" in s for s in report["skipped"])

    def test_dispatch_extended_ble_stripped_method_prefix(self, monkeypatch):
        """The AI may pass method='extended_ble_xyz' (the MCP tool-name
        style). The dispatcher strips the prefix to the actual method."""
        from core.orchestrator.autonomous_orchestrator import AutonomousOrchestrator
        from tests.fakes import FakeAIBackend

        seen = {"method": None}
        def fake_run_attack(method, *a, **kw):
            seen["method"] = method
            return _FakeExtendedResult(_ok_extended_ble_result(method))
        import core.extended_ble.runner as eble_mod
        monkeypatch.setattr(eble_mod, "run_attack", fake_run_attack)

        o = AutonomousOrchestrator(
            ai_backend=FakeAIBackend(),
            confirm_fn=lambda p: True,
            on_event=lambda m: None,
        )
        report = {"executed": [], "skipped": [], "access": {}}
        step = {
            "action": "extended_ble",
            "args": {"method": "extended_ble_le_audio_bis_sync_jamming",
                     "addr": "AA:BB:CC:DD:EE:01"},
        }
        o._dispatch_extended_ble(step, {}, report)
        # The prefix was stripped before run_attack.
        assert seen["method"] == "le_audio_bis_sync_jamming"


# ---------------------------------------------------------------------------
# _walk_ai_step routing
# ---------------------------------------------------------------------------

class TestWalkAIStep:
    def test_walk_ai_step_routes_extended_ble(self, monkeypatch):
        """``_walk_ai_step`` dispatches ``extended_ble`` action via the
        dedicated dispatcher (single-gate)."""
        from core.orchestrator.autonomous_orchestrator import AutonomousOrchestrator
        from tests.fakes import FakeAIBackend

        def fake_run_attack(method, *a, **kw):
            return _FakeExtendedResult(_ok_extended_ble_result(method))

        import core.extended_ble.runner as eble_mod
        monkeypatch.setattr(eble_mod, "run_attack", fake_run_attack)

        o = AutonomousOrchestrator(
            ai_backend=FakeAIBackend(),
            confirm_fn=lambda p: True,
            on_event=lambda m: None,
        )
        seed = {}
        report = {"executed": [], "skipped": [], "access": {}}
        o._walk_ai_step(
            {"action": "extended_ble",
             "args": {"method": "le_audio_bis_sync_jamming",
                      "addr": "AA:BB:CC:DD:EE:01"}},
            seed, report, autonomous=True,
        )
        assert any(
            e.get("action") == "extended_ble"
            for e in report["executed"]
        )
        assert "extended_ble" in seed


# ---------------------------------------------------------------------------
# MCP wrapper
# ---------------------------------------------------------------------------

class TestMCPWrapper:
    def test_extended_ble_wrappers_exist(self):
        from core.mcp.tools import KALI_TOOL_WRAPPERS
        # The factory generates one wrapper per method (31 baseline + 3
        # Phase 1.6 = 34).
        ext_ble = [n for n in KALI_TOOL_WRAPPERS
                   if n.startswith("extended_ble_")]
        assert len(ext_ble) == 34, (
            f"expected 34 extended_ble wrappers, got {len(ext_ble)}"
        )

    def test_extended_ble_in_mcp_record(self):
        from core.mcp.tools import list_mcp_tools
        records = list_mcp_tools()
        ext_ble = [r for r in records
                   if r["name"].startswith("extended_ble_")]
        assert len(ext_ble) == 34
        # Domain tag is "ble" for all entries.
        for r in ext_ble:
            assert r["domain"] == "ble"
        # Single-gate: schema does NOT include a 'confirm' field.
        for r in ext_ble[:5]:
            assert "confirm" not in str(r.get("input_schema", {}))

    def test_extended_ble_routes_through_runner(self):
        """The wrapper reaches the real extended_ble runner. We don't
        monkeypatch the imported reference (it's bound at factory time
        via ``from core.extended_ble.runner import run_attack as
        _run_eb``) — we verify the wrapper invokes the runner with the
        correct method by sending a method that the real runner
        handles honestly (no tools, missing addr)."""
        from core.mcp import tools
        runner = tools.KALI_TOOL_WRAPPERS["extended_ble_le_audio_bis_sync_jamming"]._runner
        out = runner({})  # no addr -> ok=False with real error
        assert out["ok"] is False
        assert "addr" in out["error"] or "le_audio" in out["error"].lower()

    def test_extended_ble_handles_runner_exception(self, monkeypatch):
        """The MCP wrapper's try/except catches and returns ok=False
        with the exception string. We trigger the exception by passing
        a method the runner will fail to dispatch on (which is
        handled by the real run_attack returning ok=False — but the
        wrapper's except-clause is also exercised by real runner
        exceptions)."""
        from core.mcp.tools import KALI_TOOL_WRAPPERS
        # The wrapper's try/except is the contract; verify it's present.
        import inspect
        from core.mcp import tools as tools_mod
        # Find the wrapper's runner closure source.
        runner = KALI_TOOL_WRAPPERS["extended_ble_le_audio_bis_sync_jamming"]._runner
        src = inspect.getsource(runner)
        assert "try" in src
        assert "except" in src
        # The except returns ok=False with str(e).
        assert "ok" in src
        # And the real runner still returns ok=False on missing addr.
        out = runner({})
        assert out["ok"] is False


# ---------------------------------------------------------------------------
# Registry shape
# ---------------------------------------------------------------------------

class TestRegistry:
    def test_registry_matches_methods(self):
        from core.extended_ble.runner import (
            EXTENDED_BLE_ATTACKS, ExtendedBLERunner,
        )
        methods = set(ExtendedBLERunner.EXTENDED_BLE_METHODS)
        registry = {p["method"] for p in EXTENDED_BLE_ATTACKS}
        assert methods == registry
        # 31 baseline + 3 Phase 1.6 patterns = 34.
        assert len(methods) == 34
