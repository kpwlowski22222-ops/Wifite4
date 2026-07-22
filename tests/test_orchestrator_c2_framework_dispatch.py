"""Tests for the c2_framework dispatcher in the orchestrator.

The single-gate invariant applies: the per-step ACCEPT already fired
in ``_walk_ai_step``; the dispatcher itself must NOT call confirm_fn
or self.confirm.
"""
from __future__ import annotations

import inspect

import pytest


# ---------------------------------------------------------------------------
# Single-gate invariant for c2_framework dispatcher
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
        """The dispatcher must not CALL confirm_fn or self.confirm."""
        import re
        cleaned = re.sub(r"confirm_fn\s*=\s*[^,)\s]+", "", body)
        return "confirm_fn" in cleaned or "self.confirm" in cleaned

    def test_dispatch_c2_framework_no_reconfirm(self):
        body = self._body("_dispatch_c2_framework")
        assert not self._has_reconfirm(body), (
            f"dispatcher body re-confirms: {body[:200]}...")


# ---------------------------------------------------------------------------
# Dispatcher behavior
# ---------------------------------------------------------------------------

class TestDispatchC2Framework:
    def _orchestrator(self, monkeypatch):
        from core.orchestrator.autonomous_orchestrator import (
            AutonomousOrchestrator,
        )
        # The orchestrator takes optional DI; we instantiate with no
        # args, which gives us a fully-isolated unit (the dispatcher's
        # only external dep is the executor, which we monkeypatch).
        return AutonomousOrchestrator()

    def test_dispatch_c2_framework_missing_framework(self, monkeypatch):
        orch = self._orchestrator(monkeypatch)
        report = {"executed": []}
        step = {"action": "c2_framework", "args": {}}
        orch._dispatch_c2_framework(step, {}, report)
        assert len(report["executed"]) == 1
        entry = report["executed"][0]
        assert entry["action"] == "c2_framework"
        assert entry["result"]["ok"] is False
        assert "framework" in entry["result"]["error"]

    def test_dispatch_c2_framework_unknown_framework(self, monkeypatch):
        """An unknown framework name must return ok=False from the
        executor (NEVER a fabricated session)."""
        orch = self._orchestrator(monkeypatch)
        report = {"executed": []}
        step = {"action": "c2_framework",
                "args": {"framework": "not_a_real_c2_framework"}}
        orch._dispatch_c2_framework(step, {}, report)
        assert len(report["executed"]) == 1
        entry = report["executed"][0]
        # The executor returns ok=False for unknown frameworks.
        assert entry["result"]["ok"] is False
        assert "unknown C2 framework" in entry["result"]["error"]

    def test_dispatch_c2_framework_executor_exception(self, monkeypatch):
        """If the executor raises, the dispatcher must catch it and
        return ok=False (NEVER fabricate a result)."""
        orch = self._orchestrator(monkeypatch)

        def boom(*_a, **_kw):
            raise RuntimeError("simulated executor crash")

        from core.c2 import executor as ex_mod
        monkeypatch.setattr(ex_mod, "run_c2_framework", boom)

        report = {"executed": []}
        step = {"action": "c2_framework",
                "args": {"framework": "sliver"}}
        orch._dispatch_c2_framework(step, {}, report)
        assert len(report["executed"]) == 1
        entry = report["executed"][0]
        assert entry["result"]["ok"] is False
        assert "executor raised" in entry["result"]["error"]

    def test_dispatch_c2_framework_passes_env_not_argv(self, monkeypatch):
        """The never-inline ground rule: harvested credential values
        must be passed via env vars, never as argv tokens."""
        orch = self._orchestrator(monkeypatch)

        captured = {}

        def fake_run(framework, *, commands=None, extra_argv=None,
                     env=None, timeout_seconds=30.0):
            captured["framework"] = framework
            captured["commands"] = commands
            captured["extra_argv"] = extra_argv
            captured["env"] = env
            captured["timeout_seconds"] = timeout_seconds
            return {"ok": True, "framework": framework,
                    "results": [], "close": {"ok": True}}

        from core.c2 import executor as ex_mod
        monkeypatch.setattr(ex_mod, "run_c2_framework", fake_run)

        report = {"executed": []}
        step = {
            "action": "c2_framework",
            "args": {
                "framework": "sliver",
                "commands": ["help"],
                "env": {"KFIOSA_PASSWORD": "secret_pwd_value"},
                "timeout_seconds": 60.0,
            },
        }
        orch._dispatch_c2_framework(step, {}, report)
        # env was passed through verbatim
        assert captured["env"]["KFIOSA_PASSWORD"] == "secret_pwd_value"
        # extra_argv (NOT argv) was empty — the dispatcher never inlines
        # credentials into argv.
        assert captured.get("extra_argv") == [] or \
            captured.get("extra_argv") is None
        assert report["executed"][0]["result"]["ok"] is True


# ---------------------------------------------------------------------------
# Ladder: c2_framework is recognized in _walk_ai_step
# ---------------------------------------------------------------------------

def test_walk_ai_step_routes_c2_framework(monkeypatch):
    """The dispatch ladder in ``_walk_ai_step`` must route
    ``c2_framework`` to ``_dispatch_c2_framework``."""
    from core.orchestrator import autonomous_orchestrator as mod
    src = inspect.getsource(mod)
    assert '"c2_framework"' in src, \
        "c2_framework not present in orchestrator source"
    assert "_dispatch_c2_framework" in src, \
        "_dispatch_c2_framework not present in orchestrator source"
    # And it must be in the action == ladder
    i = src.find('action == "c2_framework"')
    assert i > 0, "c2_framework not in action == ladder"
