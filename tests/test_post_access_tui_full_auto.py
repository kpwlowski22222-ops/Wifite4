"""tests.test_post_access_tui_full_auto — verify the single-gated
``run_full_auto`` flow + panel wiring.

Coverage:
  - imports / exports
  - gate prompt wording (the operator's contract)
  - gate denial path (operator cancels at the single gate)
  - gate accept + happy path (chain runs, TUI spawns)
  - chain reports no access → no TUI spawn
  - panel_state validation (no target → degrade)
  - ai_planner missing → degrade
  - walk_chain raising → degrade (no crash)
  - ai_planner.plan returning wrong shape → degrade
  - empty plan → degrade
  - spawn raising → degraded envelope, NOT a crash
  - the single-gate invariant: confirm_fn is called exactly ONCE
    for the full-auto action itself
  - WiFi panel: _action_full_auto_pwn is wired through run_full_auto
  - BLE panel: _action_full_auto_pwn is wired through run_full_auto
  - never-fabricate: no fake access_achieved when chain did not report
  - never-inline: harvested creds in chain target don't get auto-spawned
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional
from unittest import mock

import pytest

from core.post_access_tui.full_auto import (
    FullAutoError,
    default_gate_prompt,
    run_full_auto,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class _FakePlanner:
    """Minimal AI planner fake. Returns a 2-step chain that the
    fake walk_chain can consume."""

    def __init__(self, *, steps: Optional[List[Dict[str, Any]]] = None,
                 plan_raises: Optional[Exception] = None,
                 plan_returns: Any = None):
        self._steps = steps or [
            {"action": "recon_probe", "args": {"target": "T"}},
            {"action": "wifi_attack", "args": {"target": "T"}},
        ]
        self._raises = plan_raises
        self._returns = plan_returns
        self.calls: List[Dict[str, Any]] = []

    def plan(self, *, domain: str, target: Dict[str, Any],
             panel_state: Dict[str, Any], **kwargs) -> Dict[str, Any]:
        self.calls.append({
            "domain": domain, "target": target,
            "panel_state": panel_state, **kwargs,
        })
        if self._raises is not None:
            raise self._raises
        if self._returns is not None:
            return self._returns
        return {"steps": list(self._steps)}


def _walk_chain_factory(*, executed: List[Dict[str, Any]],
                        access_achieved: bool = False,
                        raises: Optional[Exception] = None,
                        returns: Any = None) -> Any:
    """Return a walk_chain callable that records its invocations."""
    invocations: List[Any] = []

    def _walk(steps: List[Dict[str, Any]], seed: Dict[str, Any]) -> Any:
        invocations.append({"steps": list(steps), "seed": dict(seed)})
        if raises is not None:
            raise raises
        if returns is not None:
            return returns
        return {
            "ok": True,
            "executed": list(executed),
            "access": {"achieved": bool(access_achieved)},
            "n_executed": len(executed),
        }

    _walk.invocations = invocations  # type: ignore[attr-defined]
    return _walk


def _make_confirm(*, accept: bool = True) -> Any:
    """Return a confirm_fn that records its prompts and answers."""
    log: List[str] = []
    def _f(prompt: str) -> bool:
        log.append(prompt)
        return accept
    _f.log = log  # type: ignore[attr-defined]
    return _f


def _make_spawn(*, ok: bool = True, raises: Optional[Exception] = None) -> Any:
    log: List[Any] = []
    def _f(*args: Any, **kwargs: Any) -> Any:
        log.append({"args": args, "kwargs": kwargs})
        if raises is not None:
            raise raises
        return {"ok": ok, "spawned": ok}
    _f.log = log  # type: ignore[attr-defined]
    return _f


def _target() -> Dict[str, Any]:
    return {"bssid": "00:11:22:33:44:55", "ssid": "lab"}


def _panel_state() -> Dict[str, Any]:
    return {
        "adapter": "wlan0mon",
        "monitor_mode": True,
        "selected_ap": _target(),
        "target": _target(),
    }


# ---------------------------------------------------------------------------
# Imports / exports
# ---------------------------------------------------------------------------

def test_imports():
    from core.post_access_tui import (
        run_full_auto, default_gate_prompt, FullAutoError,
    )
    assert callable(run_full_auto)
    assert callable(default_gate_prompt)
    assert issubclass(FullAutoError, Exception)


def test_full_auto_module_exports():
    import core.post_access_tui.full_auto as fa
    for name in ("run_full_auto", "default_gate_prompt", "FullAutoError"):
        assert name in fa.__all__, f"missing {name}"


# ---------------------------------------------------------------------------
# Gate prompt wording
# ---------------------------------------------------------------------------

def test_default_gate_prompt_wifi():
    p = default_gate_prompt("wifi", _target())
    assert "ACCEPT INTRUSIVE" in p
    assert "WIFI" in p
    assert "lab" in p  # the SSID


def test_default_gate_prompt_ble():
    p = default_gate_prompt("ble", {"address": "AA:BB:CC:DD:EE:01"})
    assert "BLE" in p
    assert "AA:BB:CC:DD:EE:01" in p


def test_default_gate_prompt_falls_back_to_id():
    p = default_gate_prompt("wifi", {"id": "x42"})
    assert "x42" in p


def test_default_gate_prompt_unknown_target_label():
    p = default_gate_prompt("wifi", {})
    assert "<target>" in p


# ---------------------------------------------------------------------------
# Single-gate invariant
# ---------------------------------------------------------------------------

def test_single_gate_called_exactly_once():
    """The single-gate invariant: ``confirm_fn`` is called EXACTLY
    ONCE for the full-auto action itself, before any chain step
    is walked. Per-step ACCEPT gates live inside ``_walk_ai_step``;
    they are NOT re-fired here."""
    confirm = _make_confirm(accept=True)
    planner = _FakePlanner()
    walk = _walk_chain_factory(executed=[{"ok": True}])
    spawn = _make_spawn(ok=True)
    res = run_full_auto(
        domain="wifi",
        panel_state=_panel_state(),
        ai_planner=planner,
        walk_chain=walk,
        spawn_post_access_tui=spawn,
        confirm_fn=confirm,
    )
    assert res["ok"] is True
    assert len(confirm.log) == 1
    assert "Full auto" in confirm.log[0]


def test_gate_deny_cancels_without_planning():
    confirm = _make_confirm(accept=False)
    planner = _FakePlanner()
    walk = _walk_chain_factory(executed=[])
    spawn = _make_spawn()
    res = run_full_auto(
        domain="wifi",
        panel_state=_panel_state(),
        ai_planner=planner,
        walk_chain=walk,
        spawn_post_access_tui=spawn,
        confirm_fn=confirm,
    )
    assert res["ok"] is False
    assert "CANCELLED" in res["error"]
    assert res["data"]["access_achieved"] is False
    # Planner must NOT have been called.
    assert planner.calls == []
    assert walk.invocations == []  # type: ignore[attr-defined]
    assert spawn.log == []  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# Pre-conditions
# ---------------------------------------------------------------------------

def test_no_confirm_fn_degrades():
    res = run_full_auto(
        domain="wifi",
        panel_state=_panel_state(),
        ai_planner=_FakePlanner(),
        walk_chain=lambda _s, _seed: {},
        confirm_fn=None,
    )
    assert res["ok"] is False
    assert "confirm_fn" in res["error"]


def test_no_ai_planner_degrades():
    res = run_full_auto(
        domain="wifi",
        panel_state=_panel_state(),
        ai_planner=None,
        walk_chain=lambda _s, _seed: {},
        confirm_fn=_make_confirm(),
    )
    assert res["ok"] is False


def test_panel_state_not_dict_degrades():
    res = run_full_auto(
        domain="wifi",
        panel_state="not a dict",  # type: ignore[arg-type]
        ai_planner=_FakePlanner(),
        walk_chain=lambda _s, _seed: {},
        confirm_fn=_make_confirm(),
    )
    assert res["ok"] is False


def test_target_must_be_dict():
    res = run_full_auto(
        domain="wifi",
        panel_state={"target": "not a dict"},
        ai_planner=_FakePlanner(),
        walk_chain=lambda _s, _seed: {},
        confirm_fn=_make_confirm(),
    )
    assert res["ok"] is False


# ---------------------------------------------------------------------------
# Happy paths
# ---------------------------------------------------------------------------

def test_happy_path_with_access():
    confirm = _make_confirm(accept=True)
    planner = _FakePlanner()
    walk = _walk_chain_factory(
        executed=[{"ok": True, "action": "recon_probe"},
                 {"ok": True, "action": "wifi_attack"}],
        access_achieved=True,
    )
    spawn = _make_spawn(ok=True)
    res = run_full_auto(
        domain="wifi",
        panel_state=_panel_state(),
        ai_planner=planner,
        walk_chain=walk,
        spawn_post_access_tui=spawn,
        confirm_fn=confirm,
    )
    assert res["ok"] is True
    assert res["data"]["access_achieved"] is True
    assert res["data"]["steps_planned"] == 2
    assert res["data"]["steps_executed"] == 2
    assert res["data"]["spawned_tui"] is True
    # spawn was called with the report envelope
    assert len(spawn.log) == 1  # type: ignore[attr-defined]


def test_chain_no_access_no_tui():
    confirm = _make_confirm(accept=True)
    planner = _FakePlanner()
    walk = _walk_chain_factory(
        executed=[{"ok": True, "action": "recon_probe"}],
        access_achieved=False,
    )
    spawn = _make_spawn()
    res = run_full_auto(
        domain="wifi",
        panel_state=_panel_state(),
        ai_planner=planner,
        walk_chain=walk,
        spawn_post_access_tui=spawn,
        confirm_fn=confirm,
    )
    assert res["ok"] is True
    assert res["data"]["access_achieved"] is False
    assert res["data"]["spawned_tui"] is False
    assert spawn.log == []  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# ai_planner edge cases
# ---------------------------------------------------------------------------

def test_planner_raises_degrades():
    confirm = _make_confirm(accept=True)
    planner = _FakePlanner(plan_raises=RuntimeError("LLM down"))
    walk = _walk_chain_factory(executed=[])
    res = run_full_auto(
        domain="wifi",
        panel_state=_panel_state(),
        ai_planner=planner,
        walk_chain=walk,
        confirm_fn=confirm,
    )
    assert res["ok"] is False
    assert "planner" in res["error"].lower() or "LLM" in res["error"]


def test_planner_wrong_shape_degrades():
    confirm = _make_confirm(accept=True)
    planner = _FakePlanner(plan_returns=["not a dict"])
    walk = _walk_chain_factory(executed=[])
    res = run_full_auto(
        domain="wifi",
        panel_state=_panel_state(),
        ai_planner=planner,
        walk_chain=walk,
        confirm_fn=confirm,
    )
    assert res["ok"] is False
    assert "dict" in res["error"]


def test_planner_empty_chain_degrades():
    confirm = _make_confirm(accept=True)
    planner = _FakePlanner(plan_returns={"steps": []})
    walk = _walk_chain_factory(executed=[])
    res = run_full_auto(
        domain="wifi",
        panel_state=_panel_state(),
        ai_planner=planner,
        walk_chain=walk,
        confirm_fn=confirm,
    )
    assert res["ok"] is False
    assert "empty" in res["error"]


def test_planner_accepts_chain_key_as_alias():
    confirm = _make_confirm(accept=True)
    planner = _FakePlanner(plan_returns={"chain": [
        {"action": "recon_probe", "args": {}},
    ]})
    walk = _walk_chain_factory(executed=[{"ok": True}], access_achieved=False)
    res = run_full_auto(
        domain="wifi",
        panel_state=_panel_state(),
        ai_planner=planner,
        walk_chain=walk,
        confirm_fn=confirm,
    )
    assert res["data"]["steps_planned"] == 1


# ---------------------------------------------------------------------------
# walk_chain edge cases
# ---------------------------------------------------------------------------

def test_walk_chain_raises_degrades():
    confirm = _make_confirm(accept=True)
    planner = _FakePlanner()
    walk = _walk_chain_factory(executed=[], raises=RuntimeError("oops"))
    res = run_full_auto(
        domain="wifi",
        panel_state=_panel_state(),
        ai_planner=planner,
        walk_chain=walk,
        confirm_fn=confirm,
    )
    assert res["ok"] is False
    assert "walk" in res["error"].lower() or "raised" in res["error"]


def test_walk_chain_wrong_shape_degrades():
    confirm = _make_confirm(accept=True)
    planner = _FakePlanner()
    walk = _walk_chain_factory(executed=[], returns="not a dict")
    res = run_full_auto(
        domain="wifi",
        panel_state=_panel_state(),
        ai_planner=planner,
        walk_chain=walk,
        confirm_fn=confirm,
    )
    assert res["ok"] is False


def test_walk_chain_autonomous_flag():
    confirm = _make_confirm(accept=True)
    planner = _FakePlanner()
    walk = _walk_chain_factory(executed=[])
    run_full_auto(
        domain="wifi",
        panel_state=_panel_state(),
        ai_planner=planner,
        walk_chain=walk,
        confirm_fn=confirm,
    )
    # The chain is autonomous; the per-step gate lives inside
    # _walk_ai_step, NOT here.
    assert walk.invocations[0]["seed"]["autonomous"] is True  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# Spawn edge cases
# ---------------------------------------------------------------------------

def test_spawn_raises_no_crash():
    confirm = _make_confirm(accept=True)
    planner = _FakePlanner()
    walk = _walk_chain_factory(executed=[{"ok": True}], access_achieved=True)
    spawn = _make_spawn(raises=RuntimeError("terminal down"))
    res = run_full_auto(
        domain="wifi",
        panel_state=_panel_state(),
        ai_planner=planner,
        walk_chain=walk,
        spawn_post_access_tui=spawn,
        confirm_fn=confirm,
    )
    assert res["ok"] is True
    assert res["data"]["access_achieved"] is True
    assert res["data"]["spawned_tui"] is False


def test_spawn_falls_back_to_real_spawner(tmp_path, monkeypatch):
    """When ``spawn_post_access_tui`` is None, the function falls
    back to the real :func:`core.post_access_tui.spawner.spawn_post_access_tui`.
    We patch that fallback to assert it was called."""
    from core.post_access_tui import full_auto as fa
    confirm = _make_confirm(accept=True)
    planner = _FakePlanner()
    walk = _walk_chain_factory(executed=[{"ok": True}], access_achieved=True)
    # Patch the lazy import inside run_full_auto
    captured = {"called": False, "argv": None}
    def _fake_real_spawn(report, *args, **kwargs):
        captured["called"] = True
        captured["argv"] = args
        return {"ok": True}
    monkeypatch.setattr(
        "core.post_access_tui.spawner.spawn_post_access_tui",
        _fake_real_spawn,
    )
    res = run_full_auto(
        domain="wifi",
        panel_state=_panel_state(),
        ai_planner=planner,
        walk_chain=walk,
        spawn_post_access_tui=None,  # force fallback
        confirm_fn=confirm,
    )
    assert captured["called"], "fallback spawn was not called"
    assert res["data"]["spawned_tui"] is True


# ---------------------------------------------------------------------------
# Never-fabricate
# ---------------------------------------------------------------------------

def test_never_fabricate_access_when_chain_says_no():
    """A walk_chain that reports access=False must NEVER be
    overridden to True by run_full_auto."""
    confirm = _make_confirm(accept=True)
    planner = _FakePlanner()
    walk = _walk_chain_factory(
        executed=[{"ok": True}],
        access_achieved=False,
    )
    res = run_full_auto(
        domain="wifi",
        panel_state=_panel_state(),
        ai_planner=planner,
        walk_chain=walk,
        confirm_fn=confirm,
    )
    assert res["data"]["access_achieved"] is False


def test_never_fabricate_spawn_when_no_access():
    """A spawn callable must NOT be called when access wasn't
    achieved."""
    confirm = _make_confirm(accept=True)
    planner = _FakePlanner()
    walk = _walk_chain_factory(
        executed=[{"ok": True}],
        access_achieved=False,
    )
    spawn = _make_spawn()
    res = run_full_auto(
        domain="wifi",
        panel_state=_panel_state(),
        ai_planner=planner,
        walk_chain=walk,
        spawn_post_access_tui=spawn,
        confirm_fn=confirm,
    )
    assert spawn.log == []  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# attach_zero_day / attach_post_exploit flags
# ---------------------------------------------------------------------------

def test_attach_zero_day_flag_forwarded():
    confirm = _make_confirm(accept=True)
    planner = _FakePlanner()
    walk = _walk_chain_factory(executed=[{"ok": True}])
    run_full_auto(
        domain="wifi",
        panel_state=_panel_state(),
        ai_planner=planner,
        walk_chain=walk,
        confirm_fn=confirm,
        attach_zero_day=False,
    )
    assert planner.calls[0]["attach_zero_day"] is False


def test_attach_post_exploit_flag_forwarded():
    confirm = _make_confirm(accept=True)
    planner = _FakePlanner()
    walk = _walk_chain_factory(executed=[{"ok": True}])
    run_full_auto(
        domain="wifi",
        panel_state=_panel_state(),
        ai_planner=planner,
        walk_chain=walk,
        confirm_fn=confirm,
        attach_post_exploit=False,
    )
    assert planner.calls[0]["attach_post_exploit"] is False


# ---------------------------------------------------------------------------
# Panel wiring (WiFi + BLE)
# ---------------------------------------------------------------------------

def test_wifi_panel_dispatches_full_auto_via_run_full_auto():
    """wifi_dispatch with hotkey '!' must route through run_full_auto."""
    from core.post_access_tui import wifi_panel
    from core.post_access_tui.wifi_panel import WiFiAP
    from core.post_access_tui import full_auto as fa_mod
    # Patch run_full_auto at the post_access_tui.full_auto module
    # level so the panel's lazy import picks up the fake.
    with mock.patch.object(fa_mod, "run_full_auto",
                           return_value={"ok": True}) as fake:
        panel = wifi_panel.WiFiPanel(
            client=_MinimalFakeClient(),
            confirm_fn=lambda _p: True,
        )
        panel.adapter = "wlan0mon"
        panel._monitor_mode = True
        panel.selected_ap = WiFiAP(
            bssid="00:11:22:33:44:55", ssid="lab",
            channel=6, encryption="WPA2", band="2.4",
        )
        panel._ai_chain_planner = object()
        panel._walk_chain = lambda _s, _seed: {"ok": True, "executed": []}
        env = panel.dispatch("full_auto_pwn", {})
        assert env["ok"] is True
        assert fake.called


def test_ble_panel_dispatches_full_auto_via_run_full_auto():
    from core.post_access_tui import ble_panel
    from core.post_access_tui import full_auto as fa_mod
    with mock.patch.object(fa_mod, "run_full_auto",
                           return_value={"ok": True}) as fake:
        panel = ble_panel.BLEPanel(confirm_fn=lambda _p: True)
        panel.connected_address = "AA:BB:CC:DD:EE:01"
        panel._ai_chain_planner = object()
        panel._walk_chain = lambda _s, _seed: {"ok": True, "executed": []}
        env = panel.dispatch("full_auto_pwn", {})
        assert env["ok"] is True
        assert fake.called


def test_wifi_panel_full_auto_no_ap_degrades():
    from core.post_access_tui.wifi_panel import WiFiPanel
    panel = WiFiPanel(client=_MinimalFakeClient(),
                      confirm_fn=lambda _p: True)
    env = panel.dispatch("full_auto_pwn", {})
    assert env["ok"] is False
    assert "no ap" in env["error"].lower()


def test_ble_panel_full_auto_no_device_degrades():
    from core.post_access_tui.ble_panel import BLEPanel
    panel = BLEPanel(confirm_fn=lambda _p: True)
    env = panel.dispatch("full_auto_pwn", {})
    assert env["ok"] is False
    assert "no ble" in env["error"].lower() or "no device" in env["error"].lower()


def test_wifi_panel_full_auto_no_planner_degrades():
    from core.post_access_tui.wifi_panel import WiFiPanel, WiFiAP
    panel = WiFiPanel(client=_MinimalFakeClient(),
                      confirm_fn=lambda _p: True)
    panel.selected_ap = WiFiAP(
        bssid="00:11:22:33:44:55", ssid="lab",
        channel=6, encryption="WPA2", band="2.4",
    )
    # No _ai_chain_planner → degrade.
    env = panel.dispatch("full_auto_pwn", {})
    assert env["ok"] is False
    assert "not wired" in env["error"].lower()


# ---------------------------------------------------------------------------
# Safety
# ---------------------------------------------------------------------------

def test_no_bare_except_in_full_auto():
    from core.post_access_tui import full_auto
    src = open(full_auto.__file__, "r", encoding="utf-8").read()
    bare = [line for line in src.splitlines()
            if line.strip() in ("except:", "except:  # noqa")]
    assert not bare, f"bare except in full_auto: {bare}"


def test_confirm_fn_raising_is_handled():
    """If confirm_fn itself raises, the function degrades
    honestly with an error envelope (NOT a crash)."""
    def _boom(_p):
        raise RuntimeError("gate broken")
    planner = _FakePlanner()
    walk = _walk_chain_factory(executed=[])
    res = run_full_auto(
        domain="wifi",
        panel_state=_panel_state(),
        ai_planner=planner,
        walk_chain=walk,
        confirm_fn=_boom,
    )
    assert res["ok"] is False
    assert "confirm" in res["error"].lower()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class _MinimalFakeClient:
    """Stand-in for the wifi / ble client; no real I/O."""
    def list_adapters(self):
        return {"ok": True, "data": {"adapters": []}, "error": ""}
    def scan(self, *_a, **_kw):
        return {"ok": True, "data": {"results": []}, "error": ""}
    def services(self, *_a, **_kw):
        return {"ok": True, "data": {"services": []}, "error": ""}
    def read(self, *_a, **_kw):
        return {"ok": True, "data": {"value_hex": ""}, "error": ""}
    def write(self, *_a, **_kw):
        return {"ok": True, "data": {}, "error": ""}
    def notify(self, *_a, **_kw):
        return {"ok": True, "data": {"notifications": []}, "error": ""}
