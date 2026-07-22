"""core.post_access_tui.spawner — orchestrator hook for the post-access TUI.

The orchestrator calls :func:`spawn_post_access_tui` when access is
achieved. The function:
  1. Builds a :class:`SessionState` from ``report["access"]``.
  2. Verifies there's something to talk to (a session_id OR creds).
  3. Builds the argv ``python -m core.post_access_tui --state-b64 <b64>``
     (the screen reads its SessionState from base64-encoded JSON on argv).
  4. Routes through :func:`core.utils.external_terminal.launch_real_step`
     so the new TUI opens in a separate terminal window.

When no real terminal backend is wired, returns the manual command
instead of silently no-op'ing (consistent with
``AutonomousOrchestrator.open_interactive_session``).

The spawn is ONE-SHOT per chain: the orchestrator tracks
``report["access"]["tui_opened"]`` so re-plan loops don't re-fire it.
"""
from __future__ import annotations

import base64
import json
import shutil
from pathlib import Path
from typing import Any, Dict, Optional

from .session_state import (
    SessionState,
    TRANSPORT_MSF,
    TRANSPORT_SSH,
    TRANSPORT_UNKNOWN,
    _append_log,
)


def is_post_access_spawnable(report: Dict[str, Any]) -> bool:
    """Return True if the report has the access signal needed to spawn
    the post-access TUI. The orchestrator uses this as the precondition
    for the auto-open ACCEPT prompt.

    Returns True iff:
      - ``report["access"]["achieved"]`` is True, AND
      - either a session_id OR creds are present
    """
    if not isinstance(report, dict):
        return False
    access = report.get("access")
    if not isinstance(access, dict):
        return False
    if not access.get("achieved"):
        return False
    return bool(access.get("session_id")) or bool(access.get("creds"))


def _state_to_argv_b64(state: SessionState) -> str:
    """Encode a SessionState as a base64 JSON blob for argv.

    The screen (``core.post_access_tui.cli``) decodes this back.
    base64 keeps the data opaque to the terminal wrapper.
    """
    payload = json.dumps(state.to_dict(), default=str)
    return base64.b64encode(payload.encode("utf-8")).decode("ascii")


def _python_module_argv() -> list:
    """Return ``[sys.executable, "-m", "core.post_access_tui"]`` for
    spawning the new TUI in an external window. We invoke as a module
    so the package's __main__ is used."""
    import sys as _sys
    return [_sys.executable, "-m", "core.post_access_tui"]


def build_argv(state: SessionState, *,
               tui_mode: Optional[str] = None,
               ble_device_path: Optional[str] = None,
               net_session_filter: Optional[str] = None) -> list:
    """Build the argv that runs the post-access TUI as a child process.

    Always returns a list; never raises. When the runner has no real
    transport to talk to, returns an empty list (caller can fall
    back to a clear error).

    Args:
        state: the SessionState to send to the screen.
        tui_mode: optional initial panel — one of ``"shell"``,
                ``"ble"``, ``"network"``, ``"full"``. The screen
                uses it to highlight the first menu item. When
                ``None``, the screen defaults to the standard
                shell-first menu.
        ble_device_path: optional path to a ``btmgmt`` device
                (``/dev/bluetooth/...``). When set, the BLE
                panel pre-fills the address in its [C]onnect
                prompt.
        net_session_filter: optional substring filter for the
                network multiplexer (e.g. ``"ssh"``, ``"msf"``).
    """
    if not isinstance(state, SessionState):
        return []
    if not state.has_session():
        return []
    argv = _python_module_argv()
    argv.extend([
        "--state-b64", _state_to_argv_b64(state),
        "--log-path", str(_default_log_path()),
    ])
    if tui_mode:
        argv.extend(["--tui-mode", str(tui_mode)])
    if ble_device_path:
        argv.extend(["--ble-device", str(ble_device_path)])
    if net_session_filter:
        argv.extend(["--net-filter", str(net_session_filter)])
    return argv


def _default_log_path() -> Path:
    return Path(__file__).parent / "_tui_spawn.log"


def spawn_post_access_tui(report: Dict[str, Any],
                          external_terminal: Any = None,
                          log_path: Optional[str] = None,
                          *,
                          tui_mode: Optional[str] = None,
                          ble_device_path: Optional[str] = None,
                          net_session_filter: Optional[str] = None
                          ) -> Dict[str, Any]:
    """Spawn the post-access TUI in a separate terminal window.

    Args:
        report: the orchestrator's report dict (must have
                ``report["access"]["achieved"]`` True + either
                session_id or creds).
        external_terminal: optional backend handle; the orchestrator
                passes its own. When None, falls back to a "no
                backend" honest result.
        log_path: optional override for the spawn's log path.
        tui_mode: optional initial panel — one of ``"shell"``,
                ``"ble"``, ``"network"``, ``"full"``. Forwarded
                to ``build_argv``.
        ble_device_path: optional path to a ``btmgmt`` device
                (``/dev/bluetooth/...``). Forwarded to
                ``build_argv``.
        net_session_filter: optional substring filter for the
                network multiplexer. Forwarded to ``build_argv``.

    Returns:
        ``{"ok": True, "pid": <popen pid>, "argv": [...]}`` on success,
        or ``{"ok": False, "error": "..."}`` on refusal (no signal,
        no terminal backend, etc.). NEVER raises.
    """
    try:
        if not is_post_access_spawnable(report):
            return {
                "ok": False,
                "error": "access not achieved (no session_id or creds)",
                "spawned": False,
            }
        access = report.get("access") or {}
        state = SessionState.from_access_report(access)
        # Optional: pull the target from report["target"] or seed
        target = (
            report.get("target")
            or (report.get("seed") or {}).get("target")
            or (report.get("seed") or {}).get("bssid")
            or ""
        )
        state.target = str(target or "")
        # Mark one-shot (idempotent if called twice).
        report.setdefault("access", {})
        report["access"]["tui_opened"] = True
        argv = build_argv(
            state,
            tui_mode=tui_mode,
            ble_device_path=ble_device_path,
            net_session_filter=net_session_filter,
        )
        if not argv:
            return {
                "ok": False,
                "error": "no active session (state.has_session() == False)",
                "spawned": False,
            }
        # Build the step dict for the external_terminal helper.
        step = {
            "action": "open_post_access_tui",
            "tool": "core.post_access_tui",
            "session_id": state.session_id,
        }
        lp = log_path or str(_default_log_path())
        try:
            from core.utils.external_terminal import (
                is_real_backend, launch_real_step,
            )
        except Exception as e:  # noqa: BLE001
            _append_log({
                "event": "spawn_fail",
                "reason": f"import external_terminal: {e}",
            })
            return {"ok": False, "error": f"external_terminal import: {e}",
                    "spawned": False, "manual": " ".join(argv)}
        if not is_real_backend(external_terminal):
            manual = " ".join(argv)
            _append_log({
                "event": "spawn_deferred",
                "reason": "no terminal backend",
                "manual": manual,
            })
            return {
                "ok": False,
                "error": "no real terminal backend wired",
                "spawned": False,
                "manual": manual,
            }
        res = launch_real_step(step, argv, log_path=lp,
                               title="KFIOSA Post-Access TUI")
        _append_log({
            "event": "spawn",
            "ok": bool(res.get("ok")),
            "pid": res.get("pid"),
        })
        if not res.get("ok"):
            return {"ok": False, "error": res.get("error", "spawn failed"),
                    "spawned": False, "manual": " ".join(argv)}
        return {"ok": True, "pid": res.get("pid"),
                "argv": argv, "spawned": True}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": f"spawner raised: {e}",
                "spawned": False}
