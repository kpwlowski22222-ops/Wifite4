"""Tests for the AI-driven ``open_ble_tui`` and ``open_network_tui``
chain step dispatchers.

The chain schema (in ``core.ai_backend.chain._CHAIN_STEP_SCHEMA_HINT``)
and the prompt stanza ``POST_ACCESS_TUI_MODES_PROMPT_STANZA`` both
advertise the ``open_ble_tui`` and ``open_network_tui`` actions, but
prior to this commit the orchestrator had no dispatcher for them. This
file:

  * verifies the single-gate invariant on the new dispatchers
    (no re-confirm in the body — the per-step ACCEPT/CANCEL in
    :meth:`AutonomousOrchestrator._walk_ai_step` is the only gate),
  * verifies the dispatchers route through
    :func:`core.post_access_tui.spawner.spawn_post_access_tui` with
    the correct ``tui_mode`` (``ble`` / ``network``),
  * verifies the one-shot sentinel (each panel is spawned at most
    once per chain),
  * verifies ``_walk_ai_step`` routes the two new actions to their
    dedicated dispatchers,
  * verifies the chain schema + prompt stanza agree on the action
    names.

The tests are hermetic: ``spawn_post_access_tui`` is monkeypatched,
no subprocess is spawned, no curses is required.
"""
from __future__ import annotations

import inspect
import re

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _body(name: str) -> str:
    """Return the source of ``AutonomousOrchestrator.<name>``."""
    from core.orchestrator import autonomous_orchestrator as mod

    src = inspect.getsource(mod)
    i = src.find(f"def {name}")
    if i < 0:
        raise AssertionError(f"method {name!r} not found in orchestrator")
    j = src.find("\n    def ", i + 1)
    if j < 0:
        j = len(src)
    return src[i:j]


def _has_reconfirm(body: str) -> bool:
    """True if the dispatcher body calls ``confirm_fn`` or
    ``self.confirm`` itself (single-gate invariant violation)."""
    cleaned = re.sub(r"confirm_fn\s*=\s*[^,)\s]+", "", body)
    return "confirm_fn" in cleaned or "self.confirm" in cleaned


def _report_with_target(target: str = "AA:BB:CC:DD:EE:FF",
                        session_id: str = "s1") -> dict:
    return {
        "executed": [],
        "skipped": [],
        "optional_declined": [],
        "target": target,
        "seed": {"bssid": target},
        "access": {
            "achieved": True,
            "session_id": session_id,
            "transport": "ble",
            "creds": None,
        },
    }


# ---------------------------------------------------------------------------
# Single-gate invariant
# ---------------------------------------------------------------------------

class TestSingleGate:
    def test_dispatch_open_ble_tui_no_reconfirm(self):
        body = _body("_dispatch_open_ble_tui")
        assert not _has_reconfirm(body), (
            f"_dispatch_open_ble_tui re-confirms in its body: {body[:200]}..."
        )

    def test_dispatch_open_network_tui_no_reconfirm(self):
        body = _body("_dispatch_open_network_tui")
        assert not _has_reconfirm(body), (
            f"_dispatch_open_network_tui re-confirms in its body: {body[:200]}..."
        )


# ---------------------------------------------------------------------------
# Dispatcher: routes to spawn_post_access_tui with correct tui_mode
# ---------------------------------------------------------------------------

class TestAIDispatch:
    def test_dispatch_open_ble_tui_routes_with_tui_mode_ble(self, monkeypatch):
        from core.orchestrator.autonomous_orchestrator import AutonomousOrchestrator
        from tests.fakes import FakeAIBackend

        captured = {"n": 0, "calls": []}

        def fake_spawn(report, external_terminal, *,
                      tui_mode=None,
                      ble_device_path=None,
                      net_session_filter=None):
            captured["n"] += 1
            captured["calls"].append({
                "tui_mode": tui_mode,
                "ble_device_path": ble_device_path,
                "net_session_filter": net_session_filter,
            })
            report.setdefault("access", {})["tui_opened"] = True
            return {"ok": True, "pid": 7777}

        import core.post_access_tui.spawner as spawner_mod
        monkeypatch.setattr(spawner_mod, "spawn_post_access_tui", fake_spawn)

        o = AutonomousOrchestrator(
            ai_backend=FakeAIBackend(),
            confirm_fn=lambda p: True,
            on_event=lambda m: None,
        )
        seed = {"bssid": "AA:BB:CC:DD:EE:FF"}
        report = _report_with_target()
        step = {
            "action": "open_ble_tui",
            "args": {"device_path": "/dev/bluetooth/hci0"},
        }
        o._dispatch_open_ble_tui(step, seed, report)

        # The spawner was called once.
        assert captured["n"] == 1
        # With tui_mode="ble" and the device path forwarded.
        assert captured["calls"][0]["tui_mode"] == "ble"
        assert captured["calls"][0]["ble_device_path"] == "/dev/bluetooth/hci0"
        # The step is recorded honestly.
        assert len(report["executed"]) == 1
        e = report["executed"][0]
        assert e["action"] == "open_ble_tui"
        assert e["result"]["ok"] is True
        assert e["result"]["pid"] == 7777

    def test_dispatch_open_network_tui_routes_with_tui_mode_network(self, monkeypatch):
        from core.orchestrator.autonomous_orchestrator import AutonomousOrchestrator
        from tests.fakes import FakeAIBackend

        captured = {"n": 0, "calls": []}

        def fake_spawn(report, external_terminal, *,
                      tui_mode=None,
                      ble_device_path=None,
                      net_session_filter=None):
            captured["n"] += 1
            captured["calls"].append({
                "tui_mode": tui_mode,
                "net_session_filter": net_session_filter,
            })
            return {"ok": True, "pid": 8888}

        import core.post_access_tui.spawner as spawner_mod
        monkeypatch.setattr(spawner_mod, "spawn_post_access_tui", fake_spawn)

        o = AutonomousOrchestrator(
            ai_backend=FakeAIBackend(),
            confirm_fn=lambda p: True,
            on_event=lambda m: None,
        )
        seed = {"bssid": "AA:BB:CC:DD:EE:FF"}
        report = _report_with_target(session_id="net-s1")
        step = {
            "action": "open_network_tui",
            "args": {"net_session_filter": "ssh"},
        }
        o._dispatch_open_network_tui(step, seed, report)

        assert captured["n"] == 1
        assert captured["calls"][0]["tui_mode"] == "network"
        assert captured["calls"][0]["net_session_filter"] == "ssh"
        assert len(report["executed"]) == 1
        e = report["executed"][0]
        assert e["action"] == "open_network_tui"
        assert e["result"]["ok"] is True
        assert e["result"]["pid"] == 8888

    def test_dispatch_open_ble_tui_spawn_failure_recorded(self, monkeypatch):
        """A spawn refusal is recorded honestly (ok=False) — no fake success."""
        from core.orchestrator.autonomous_orchestrator import AutonomousOrchestrator
        from tests.fakes import FakeAIBackend

        def fake_spawn(report, external_terminal, **_):
            return {
                "ok": False,
                "error": "no real terminal backend wired",
                "manual": "python -m core.post_access_tui --tui-mode ble",
            }

        import core.post_access_tui.spawner as spawner_mod
        monkeypatch.setattr(spawner_mod, "spawn_post_access_tui", fake_spawn)

        o = AutonomousOrchestrator(
            ai_backend=FakeAIBackend(),
            confirm_fn=lambda p: True,
            on_event=lambda m: None,
        )
        report = _report_with_target()
        o._dispatch_open_ble_tui(
            {"action": "open_ble_tui", "args": {}}, {}, report
        )
        assert len(report["executed"]) == 1
        e = report["executed"][0]
        assert e["action"] == "open_ble_tui"
        assert e["result"]["ok"] is False
        assert "no real terminal backend" in e["result"]["error"]

    def test_dispatch_open_network_tui_spawn_failure_recorded(self, monkeypatch):
        from core.orchestrator.autonomous_orchestrator import AutonomousOrchestrator
        from tests.fakes import FakeAIBackend

        def fake_spawn(report, external_terminal, **_):
            return {
                "ok": False,
                "error": "no real terminal backend wired",
                "manual": "python -m core.post_access_tui --tui-mode network",
            }

        import core.post_access_tui.spawner as spawner_mod
        monkeypatch.setattr(spawner_mod, "spawn_post_access_tui", fake_spawn)

        o = AutonomousOrchestrator(
            ai_backend=FakeAIBackend(),
            confirm_fn=lambda p: True,
            on_event=lambda m: None,
        )
        report = _report_with_target()
        o._dispatch_open_network_tui(
            {"action": "open_network_tui", "args": {}}, {}, report
        )
        assert len(report["executed"]) == 1
        e = report["executed"][0]
        assert e["action"] == "open_network_tui"
        assert e["result"]["ok"] is False


# ---------------------------------------------------------------------------
# One-shot sentinel: each panel spawned at most once per chain
# ---------------------------------------------------------------------------

class TestOneShotSentinel:
    def test_open_ble_tui_spawns_at_most_once(self, monkeypatch):
        from core.orchestrator.autonomous_orchestrator import AutonomousOrchestrator
        from tests.fakes import FakeAIBackend

        calls = {"n": 0}

        def fake_spawn(report, external_terminal, **_):
            calls["n"] += 1
            return {"ok": True, "pid": 1}

        import core.post_access_tui.spawner as spawner_mod
        monkeypatch.setattr(spawner_mod, "spawn_post_access_tui", fake_spawn)

        o = AutonomousOrchestrator(
            ai_backend=FakeAIBackend(),
            confirm_fn=lambda p: True,
            on_event=lambda m: None,
        )
        report = _report_with_target()
        o._dispatch_open_ble_tui(
            {"action": "open_ble_tui", "args": {}}, {}, report
        )
        o._dispatch_open_ble_tui(
            {"action": "open_ble_tui", "args": {}}, {}, report
        )
        assert calls["n"] == 1
        # The sentinel flipped.
        assert report["access"].get("ble_tui_opened") is True
        # The 2nd call is recorded in skipped.
        assert any("open_ble_tui" in s for s in report["skipped"])

    def test_open_network_tui_spawns_at_most_once(self, monkeypatch):
        from core.orchestrator.autonomous_orchestrator import AutonomousOrchestrator
        from tests.fakes import FakeAIBackend

        calls = {"n": 0}

        def fake_spawn(report, external_terminal, **_):
            calls["n"] += 1
            return {"ok": True, "pid": 2}

        import core.post_access_tui.spawner as spawner_mod
        monkeypatch.setattr(spawner_mod, "spawn_post_access_tui", fake_spawn)

        o = AutonomousOrchestrator(
            ai_backend=FakeAIBackend(),
            confirm_fn=lambda p: True,
            on_event=lambda m: None,
        )
        report = _report_with_target()
        o._dispatch_open_network_tui(
            {"action": "open_network_tui", "args": {}}, {}, report
        )
        o._dispatch_open_network_tui(
            {"action": "open_network_tui", "args": {}}, {}, report
        )
        assert calls["n"] == 1
        assert report["access"].get("network_tui_opened") is True
        assert any("open_network_tui" in s for s in report["skipped"])

    def test_open_ble_and_open_network_are_independent_sentinels(self, monkeypatch):
        """The BLE sentinel must not block the Network one (and vice versa)."""
        from core.orchestrator.autonomous_orchestrator import AutonomousOrchestrator
        from tests.fakes import FakeAIBackend

        calls = {"n": 0}

        def fake_spawn(report, external_terminal, **_):
            calls["n"] += 1
            return {"ok": True, "pid": calls["n"]}

        import core.post_access_tui.spawner as spawner_mod
        monkeypatch.setattr(spawner_mod, "spawn_post_access_tui", fake_spawn)

        o = AutonomousOrchestrator(
            ai_backend=FakeAIBackend(),
            confirm_fn=lambda p: True,
            on_event=lambda m: None,
        )
        report = _report_with_target()
        o._dispatch_open_ble_tui(
            {"action": "open_ble_tui", "args": {}}, {}, report
        )
        o._dispatch_open_network_tui(
            {"action": "open_network_tui", "args": {}}, {}, report
        )
        assert calls["n"] == 2


# ---------------------------------------------------------------------------
# _walk_ai_step routing
# ---------------------------------------------------------------------------

class TestWalkAIStep:
    def test_walk_ai_step_routes_open_ble_tui(self, monkeypatch):
        from core.orchestrator.autonomous_orchestrator import AutonomousOrchestrator
        from tests.fakes import FakeAIBackend

        def fake_spawn(report, external_terminal, **_):
            return {"ok": True, "pid": 100}

        import core.post_access_tui.spawner as spawner_mod
        monkeypatch.setattr(spawner_mod, "spawn_post_access_tui", fake_spawn)

        o = AutonomousOrchestrator(
            ai_backend=FakeAIBackend(),
            confirm_fn=lambda p: True,
            on_event=lambda m: None,
        )
        report = _report_with_target()
        o._walk_ai_step(
            {"action": "open_ble_tui", "args": {}},
            {"bssid": "AA:BB:CC:DD:EE:FF"}, report, autonomous=True,
        )
        assert any(
            e.get("action") == "open_ble_tui" for e in report["executed"]
        )

    def test_walk_ai_step_routes_open_network_tui(self, monkeypatch):
        from core.orchestrator.autonomous_orchestrator import AutonomousOrchestrator
        from tests.fakes import FakeAIBackend

        def fake_spawn(report, external_terminal, **_):
            return {"ok": True, "pid": 200}

        import core.post_access_tui.spawner as spawner_mod
        monkeypatch.setattr(spawner_mod, "spawn_post_access_tui", fake_spawn)

        o = AutonomousOrchestrator(
            ai_backend=FakeAIBackend(),
            confirm_fn=lambda p: True,
            on_event=lambda m: None,
        )
        report = _report_with_target()
        o._walk_ai_step(
            {"action": "open_network_tui", "args": {"net_session_filter": "msfconsole"}},
            {"bssid": "AA:BB:CC:DD:EE:FF"}, report, autonomous=True,
        )
        assert any(
            e.get("action") == "open_network_tui" for e in report["executed"]
        )


# ---------------------------------------------------------------------------
# Schema + prompt stanza
# ---------------------------------------------------------------------------

class TestChainSchema:
    def test_schema_lists_open_ble_tui_and_open_network_tui(self):
        from core.ai_backend.chain import _CHAIN_STEP_SCHEMA_HINT
        assert "open_ble_tui" in _CHAIN_STEP_SCHEMA_HINT
        assert "open_network_tui" in _CHAIN_STEP_SCHEMA_HINT

    def test_prompt_stanza_teaches_open_ble_tui(self):
        from core.ai_backend.chain import _SYSTEM_PROMPT
        from core.ai_backend.chain import POST_ACCESS_TUI_MODES_PROMPT_STANZA
        assert "open_ble_tui" in POST_ACCESS_TUI_MODES_PROMPT_STANZA
        assert "open_network_tui" in POST_ACCESS_TUI_MODES_PROMPT_STANZA
        # And the stanza is actually wired into the system prompt.
        assert "open_ble_tui" in _SYSTEM_PROMPT
        assert "open_network_tui" in _SYSTEM_PROMPT

    def test_walk_ai_step_source_contains_both_actions(self):
        """Source-level invariant: the orchestrator's _walk_ai_step
        ladder must include branches for both new actions — no silent
        fall-through to "unknown action"."""
        from core.orchestrator import autonomous_orchestrator as mod

        src = inspect.getsource(mod)
        # Find the body of _walk_ai_step.
        i = src.find("def _walk_ai_step(")
        assert i >= 0
        j = src.find("\n    def ", i + 1)
        if j < 0:
            j = len(src)
        body = src[i:j]
        assert 'action == "open_ble_tui"' in body
        assert 'action == "open_network_tui"' in body


# ---------------------------------------------------------------------------
# Honest-degrade: no fabricated spawn result on import failure
# ---------------------------------------------------------------------------

class TestImportFailure:
    def test_ble_dispatch_survives_spawner_import_error(self, monkeypatch):
        from core.orchestrator.autonomous_orchestrator import AutonomousOrchestrator
        from tests.fakes import FakeAIBackend

        # Force the lazy import inside _dispatch_open_ble_tui to fail.
        import core.post_access_tui.spawner as spawner_mod
        # We can't make `from spawner import spawn_post_access_tui` fail
        # without breaking the whole module, so we delete the symbol.
        monkeypatch.delattr(
            spawner_mod, "spawn_post_access_tui", raising=False
        )

        o = AutonomousOrchestrator(
            ai_backend=FakeAIBackend(),
            confirm_fn=lambda p: True,
            on_event=lambda m: None,
        )
        report = _report_with_target()
        # Should not raise.
        o._dispatch_open_ble_tui(
            {"action": "open_ble_tui", "args": {}}, {}, report
        )
        # Step is in skipped, NOT in executed (honest degradation).
        assert any("open_ble_tui" in s for s in report["skipped"])
        assert not any(
            e.get("action") == "open_ble_tui" for e in report["executed"]
        )

    def test_network_dispatch_survives_spawner_import_error(self, monkeypatch):
        from core.orchestrator.autonomous_orchestrator import AutonomousOrchestrator
        from tests.fakes import FakeAIBackend

        import core.post_access_tui.spawner as spawner_mod
        monkeypatch.delattr(
            spawner_mod, "spawn_post_access_tui", raising=False
        )

        o = AutonomousOrchestrator(
            ai_backend=FakeAIBackend(),
            confirm_fn=lambda p: True,
            on_event=lambda m: None,
        )
        report = _report_with_target()
        o._dispatch_open_network_tui(
            {"action": "open_network_tui", "args": {}}, {}, report
        )
        assert any("open_network_tui" in s for s in report["skipped"])
        assert not any(
            e.get("action") == "open_network_tui" for e in report["executed"]
        )
