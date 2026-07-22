"""core.post_access_tui.full_auto — single-gated AI full-auto pwn.

The operator's UX request: pick a target, press one key, and the
chain runs end-to-end. The single-gate invariant is preserved:
ONE confirm_fn prompt fires BEFORE the chain is planned, with
the wording ``ACCEPT INTRUSIVE? Full auto: run AI plan to access
on <target> and open RAT-like TUI on success.`` The chain steps
themselves are per-step ACCEPT-gated as today (see
``orchestrator._walk_ai_step``).

The executor lives here (not in the panel) so the same flow
serves the WiFi panel, the BLE panel, and the network panel.
The panels' ``_action_full_auto_pwn`` methods are thin
wrappers that call :func:`run_full_auto`.

The function returns a standard envelope:

    {
      "ok": True | False,
      "exit": "back" | True | False,  # never 'no_input' (this
                                       #  is not a loop)
      "data": {
        "steps_planned": <int>,
        "steps_executed": <int>,
        "access_achieved": <bool>,
        "spawned_tui": <bool>,
        "executed": [<envelope>, ...],
      },
      "error": "...",
    }

The single-gate invariant: ``confirm_fn`` is called EXACTLY ONCE
for the full-auto action itself, BEFORE the chain is planned.
The per-step ACCEPT prompts (inside ``_walk_ai_step``) are NOT
replaced; the operator still sees the per-step gate for each
chain step.
"""
from __future__ import annotations

import logging
import os
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class FullAutoError(Exception):
    """Raised when the full-auto flow cannot run."""


# ---------------------------------------------------------------------------
# Public surface
# ---------------------------------------------------------------------------

def run_full_auto(
    *,
    domain: str,
    panel_state: Dict[str, Any],
    ai_planner: Any,
    walk_chain: Callable[[List[Dict[str, Any]], Dict[str, Any]], Dict[str, Any]],
    spawn_post_access_tui: Optional[Callable[..., Any]] = None,
    confirm_fn: Optional[Callable[[str], bool]] = None,
    on_event: Optional[Callable[[str], None]] = None,
    report: Optional[Dict[str, Any]] = None,
    attach_zero_day: bool = True,
    attach_post_exploit: bool = True,
) -> Dict[str, Any]:
    """Plan and walk a full-AI chain, then spawn the post-access
    TUI on success.

    Args:
        domain: ``"wifi"`` / ``"ble"`` / ``"network"`` — the
            context for the LLM prompt and the chain schema.
        panel_state: dict-like snapshot of the panel (target,
            adapter, services, etc.). The planner pulls
            ``target`` from this.
        ai_planner: an ``AIChainPlanner`` (or any object with a
            ``.plan(domain, target, ...)`` method that returns
            a list of step dicts).
        walk_chain: callable that takes ``(steps, seed)`` and
            returns the executed report envelope. The caller
            wires this to the orchestrator's
            ``_walk_chain_with_replan`` (or a hermetic fake in
            tests).
        spawn_post_access_tui: optional callable invoked when
            ``access_achieved`` is True. Defaults to the real
            :func:`core.post_access_tui.spawner.spawn_post_access_tui`.
        confirm_fn: optional callable for the single gate. If
            falsy, the function is a no-op (returns
            ``{"ok": False, "error": "no confirm_fn"}``).
        on_event: optional callable for log lines.
        report: optional pre-existing report envelope to merge
            into (used by orchestrator callers); the executor
            builds a fresh envelope if not provided.
        attach_zero_day: forwarded to ``ai_planner.plan``.
        attach_post_exploit: forwarded to ``ai_planner.plan``.

    Returns:
        Standard envelope (see module docstring).
    """
    started_at: float = 0.0
    try:
        import time
        started_at = time.time()
    except Exception:  # noqa: BLE001
        pass

    out: Dict[str, Any] = {
        "ok": True,
        "detached": False,
        "exit": "back",
        "data": {
            "steps_planned": 0,
            "steps_executed": 0,
            "access_achieved": False,
            "spawned_tui": False,
            "executed": [],
        },
        "error": "",
    }

    def _emit(msg: str) -> None:
        if on_event is not None:
            try:
                on_event(msg)
            except Exception:  # noqa: BLE001
                pass
        logger.info(msg)

    # Pre-condition checks.
    if confirm_fn is None:
        out["ok"] = False
        out["error"] = "no confirm_fn available — gate invariant requires one"
        _emit(f"[!] {out['error']}")
        return out
    if ai_planner is None:
        out["ok"] = False
        out["error"] = "no ai_planner provided"
        _emit(f"[!] {out['error']}")
        return out
    if not isinstance(panel_state, dict):
        out["ok"] = False
        out["error"] = "panel_state must be a dict"
        return out
    target = panel_state.get("target") or panel_state
    if not isinstance(target, dict):
        out["ok"] = False
        out["error"] = "panel_state.target must be a dict"
        return out

    # ---------------------------------------------------------------------------
    # The single gate. The wording is fixed; the operator ACKNOWLEDGES
    # the FULL-AUTO sequence in one prompt. Per-step ACCEPT still fires
    # inside ``walk_chain`` (orchestrator._walk_ai_step).
    # ---------------------------------------------------------------------------
    target_label = (
        target.get("ssid")
        or target.get("bssid")
        or target.get("address")
        or target.get("id")
        or "<target>"
    )
    gate_prompt = (
        f"ACCEPT INTRUSIVE? Full auto: run AI plan to access on "
        f"{domain.upper()} target {target_label!r} and open "
        f"RAT-like TUI on success."
    )
    try:
        accepted = bool(confirm_fn(gate_prompt))
    except Exception as e:  # noqa: BLE001
        out["ok"] = False
        out["error"] = f"confirm_fn raised: {e}"
        _emit(f"[!] {out['error']}")
        return out
    if not accepted:
        out["ok"] = False
        out["error"] = "CANCELLED by operator at the full-auto gate"
        out["exit"] = "back"
        out["data"]["access_achieved"] = False
        _emit(f"[-] {out['error']}")
        return out
    _emit("[*] full-auto: gate ACCEPTED — planning chain")

    # ---------------------------------------------------------------------------
    # Plan. The planner returns a list of step dicts matching the
    # orchestrator's _walk_ai_step schema.
    # ---------------------------------------------------------------------------
    try:
        plan_result = ai_planner.plan(
            domain=domain,
            target=target,
            panel_state=panel_state,
            attach_zero_day=attach_zero_day,
            attach_post_exploit=attach_post_exploit,
        )
    except Exception as e:  # noqa: BLE001
        out["ok"] = False
        out["error"] = f"ai_planner.plan raised: {e}"
        _emit(f"[!] {out['error']}")
        return out
    if not isinstance(plan_result, dict):
        out["ok"] = False
        out["error"] = (
            f"ai_planner.plan must return a dict (got {type(plan_result).__name__})"
        )
        return out
    steps = plan_result.get("steps") or plan_result.get("chain") or []
    if not isinstance(steps, list):
        out["ok"] = False
        out["error"] = (
            f"ai_planner.plan['steps'] must be a list (got {type(steps).__name__})"
        )
        return out
    out["data"]["steps_planned"] = len(steps)
    if not steps:
        out["error"] = "ai_planner.plan returned an empty chain"
        out["ok"] = False
        _emit(f"[!] {out['error']}")
        return out
    _emit(f"[*] full-auto: planned {len(steps)} chain step(s)")

    # ---------------------------------------------------------------------------
    # Walk. The walk_chain callable is the orchestrator's
    # _walk_chain_with_replan; tests inject a hermetic fake.
    # ---------------------------------------------------------------------------
    seed: Dict[str, Any] = {
        "domain": domain,
        "target": target,
        "panel_state": panel_state,
        "autonomous": True,  # the chain is autonomous; the
                              # per-step gate lives inside _walk_ai_step
    }
    try:
        report_envelope = walk_chain(steps, seed)
    except Exception as e:  # noqa: BLE001
        out["ok"] = False
        out["error"] = f"walk_chain raised: {e}"
        _emit(f"[!] {out['error']}")
        return out
    if not isinstance(report_envelope, dict):
        out["ok"] = False
        out["error"] = (
            f"walk_chain must return a dict (got {type(report_envelope).__name__})"
        )
        return out

    # Merge results.
    executed = report_envelope.get("executed", [])
    out["data"]["executed"] = list(executed) if executed else []
    out["data"]["steps_executed"] = (
        len(executed) if executed else report_envelope.get("n_executed", 0)
    )
    access = (
        report_envelope.get("access", {}).get("achieved", False)
        if isinstance(report_envelope.get("access"), dict)
        else bool(report_envelope.get("access_achieved"))
    )
    out["data"]["access_achieved"] = bool(access)
    # If the caller provided a report, merge keys we don't override.
    if isinstance(report, dict):
        for k, v in report.items():
            if k not in out or not out.get(k):
                out[k] = v

    if not out["data"]["access_achieved"]:
        _emit("[*] full-auto: chain completed WITHOUT access — no TUI to spawn")
        out["ok"] = True
        out["exit"] = "back"
        return out

    # ---------------------------------------------------------------------------
    # Spawn the post-access TUI. This is operator-gated inside
    # ``spawn_post_access_tui`` (the operator gets a second prompt
    # to confirm the external window). We do NOT bypass that gate.
    # ---------------------------------------------------------------------------
    if spawn_post_access_tui is None:
        try:
            from core.post_access_tui.spawner import (
                spawn_post_access_tui as _real_spawn,
            )
            spawn_post_access_tui = _real_spawn
        except Exception as e:  # noqa: BLE001
            _emit(f"[!] full-auto: cannot import spawn_post_access_tui: {e}")
            out["data"]["spawned_tui"] = False
            out["exit"] = "back"
            return out
    try:
        spawn_argv = None
        if isinstance(report, dict) and "argv" in report:
            spawn_argv = report["argv"]
        if spawn_argv is not None:
            res = spawn_post_access_tui(report_envelope,
                                        argv=spawn_argv)
        else:
            res = spawn_post_access_tui(report_envelope)
    except Exception as e:  # noqa: BLE001
        _emit(f"[!] full-auto: spawn raised: {e}")
        out["data"]["spawned_tui"] = False
        out["exit"] = "back"
        return out
    if isinstance(res, dict):
        out["data"]["spawned_tui"] = bool(res.get("ok"))
    else:
        out["data"]["spawned_tui"] = bool(res)
    _emit(
        f"[*] full-auto: chain succeeded, "
        f"spawned_tui={out['data']['spawned_tui']}"
    )

    # ---------------------------------------------------------------------------
    # Phase 2.4 §B.11 — auto-PDF export after every finished attack
    # (operator's hard rule: ALWAYS export, even on success or
    # partial access). The PDF goes to ~/.kfiosa/reports/<ts>_<chain>.pdf.
    # ---------------------------------------------------------------------------
    try:
        from .rat_ext import auto_pdf as _auto_pdf
        sessions_for_pdf = (
            (report or {}).get("sessions")
            if isinstance(report, dict)
            else None
        ) or []
        if not sessions_for_pdf:
            # synthesize a single-session envelope from the report
            sessions_for_pdf = [{
                "session_id": (report or {}).get("session_id") or "chain",
                "transport": domain,
                "target": target_label,
                "achieved": [s.get("name", "?")
                             for s in (out["data"].get("executed") or [])
                             if isinstance(s, dict)],
                "capabilities": [],
                "exfil_jobs": [],
                "persistence_mechanisms": [],
                "screens": [],
                "step_envelope_history":
                    (report or {}).get("step_envelope_history", []),
            }]
        pdf_env = _auto_pdf.export_full_report(
            sessions_for_pdf, chain=domain,
        )
        out["data"]["pdf_report"] = pdf_env
        if pdf_env.get("ok"):
            _emit(f"[*] full-auto: PDF report → {pdf_env.get('path')}")
        else:
            _emit(f"[!] full-auto: PDF export failed: "
                  f"{pdf_env.get('error', '?')}")
    except Exception as e:  # noqa: BLE001
        _emit(f"[!] full-auto: auto_pdf raised: {e}")
        out["data"]["pdf_report"] = {"ok": False, "error": str(e)}

    # ---------------------------------------------------------------------------
    # Phase 2.4 §B.11 — auto-spawn the Flask dashboard (one-shot;
    # the per-spawn sentinel ``report["access"]["rat_dashboard_opened"]``
    # prevents re-plan loops from re-spawning).
    # ---------------------------------------------------------------------------
    if isinstance(report, dict):
        access = report.get("access") or {}
        if not isinstance(access, dict):
            access = {}
        if not access.get("rat_dashboard_opened"):
            try:
                from .rat_ext import spawn_rat_dashboard as _spawn
                dash_env = _spawn(
                    sessions_for_pdf,
                    host=os.environ.get("RAT_DASHBOARD_HOST", "127.0.0.1"),
                )
                access["rat_dashboard_opened"] = bool(dash_env.get("ok"))
                access["rat_dashboard_port"] = dash_env.get("port")
                report["access"] = access
                out["data"]["rat_dashboard"] = dash_env
                if dash_env.get("ok"):
                    _emit(
                        f"[*] full-auto: dashboard → "
                        f"{dash_env.get('url', '?')}"
                    )
            except Exception as e:  # noqa: BLE001
                _emit(f"[!] full-auto: dashboard spawn raised: {e}")
                out["data"]["rat_dashboard"] = {"ok": False, "error": str(e)}

    out["ok"] = True
    out["exit"] = "back"
    return out


# ---------------------------------------------------------------------------
# Convenience accessors used by the panel hotkeys
# ---------------------------------------------------------------------------

def default_gate_prompt(domain: str, target: Dict[str, Any]) -> str:
    """The exact gate wording the operator sees for full-auto on
    a given domain + target. The wording is the contract."""
    label = (
        target.get("ssid")
        or target.get("bssid")
        or target.get("address")
        or target.get("id")
        or "<target>"
    )
    return (
        f"ACCEPT INTRUSIVE? Full auto: run AI plan to access on "
        f"{domain.upper()} target {label!r} and open "
        f"RAT-like TUI on success."
    )


__all__ = [
    "run_full_auto",
    "default_gate_prompt",
    "FullAutoError",
]
