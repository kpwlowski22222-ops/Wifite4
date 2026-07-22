"""core.post_access_tui.menu_loop — shared curses-free input loop
for the post-access BLE / WiFi / Network panels.

The previous :func:`wifi_dispatch` / :func:`ble_dispatch` /
:func:`network_dispatch` loops were single-key (``e`` exits, a
single letter matches a hotkey). The operator wants real arrow /
ENTER / BACKSPACE ergonomics — behave like a curses TUI, but stay
synchronous so hermetic tests can drive ``input_fn``.

This module provides :func:`curses_free_loop` which:

  - Reads a single keystroke from ``screen.input_fn``.
  - Recognizes ANSI arrow tokens (``\\x1b[A`` / ``\\x1b[B``) and
    the literal text tokens ``up`` / ``down`` / ``enter`` /
    ``backspace`` that hermetic tests / piped stdin produce.
  - Tracks a ``menu_index`` cursor. ``\\r`` / ``\\n`` / `` ``
    accept the current item. ``\\x1b`` / ``127`` / ``8`` / ``q``
    return with ``exit='back'``. ``e`` exits the panel outright.
  - Single-key hotkeys (the panel's existing UX) keep working:
    pressing ``s`` jumps directly to the ``s`` capability, not
    the cursor position.
  - The single-gate invariant is preserved: the screen's
    ``confirm_fn`` is called for ``requires_gate=True`` caps; the
    loop does NOT re-confirm.
"""
from __future__ import annotations

import logging
import re
from typing import Any, Callable, Dict, List, Optional, Set

logger = logging.getLogger(__name__)


# Token normalization. Tests / piped stdin send plain text;
# real terminals send ANSI escape sequences. We map both.
_UP_TOKENS = ("\x1b[A", "key_up", "up", "UP", "k")
_DOWN_TOKENS = ("\x1b[B", "key_down", "down", "DOWN", "j")
_ENTER_TOKENS = ("\r", "\n", " ", "key_enter", "enter", "ENTER")
_BACK_TOKENS = ("\x1b", "\x1b\x1b", "key_backspace", "backspace",
                 "BACKSPACE", "127", "8", "q", "Q")


def _is_up(k: str) -> bool:
    return k in _UP_TOKENS


def _is_down(k: str) -> bool:
    return k in _DOWN_TOKENS


def _is_enter(k: str) -> bool:
    return k in _ENTER_TOKENS


def _is_back(k: str) -> bool:
    return k in _BACK_TOKENS


def _normalize(raw: str) -> str:
    """Strip leading/trailing ASCII whitespace BUT preserve the
    carriage return / newline tokens (``\\r`` / ``\\n``) which
    the loop treats as ENTER. Without this, ``_normalize('\\r')``
    would return the empty string and the loop would exit as
    ``'no_input'`` before the ENTER check could fire.

    ANSI escape sequences like ``\\x1b[A`` are preserved because
    ``str.strip()`` doesn't touch ``\\x1b``.
    """
    if not isinstance(raw, str):
        return ""
    # Strip space and tab, but NOT \r or \n — those are ENTER.
    return raw.strip(" \t")


def curses_free_loop(
    *,
    prompt: str,
    screen: Any,
    render_menu: Callable[[], None],
    visible_hotkeys: Callable[[], Set[str]],
    handle: Callable[[str], Optional[Dict[str, Any]]],
    input_fn: Optional[Callable[[str], str]] = None,
    confirm_fn: Optional[Callable[[str], bool]] = None,
    requires_gate_lookup: Optional[Callable[[str], bool]] = None,
    gate_prompt: Optional[Callable[[str], str]] = None,
    pdf_on_exit: Optional[Callable[[Dict[str, Any]],
                                   Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Single-key + arrow / enter / back loop.

    Args:
        prompt: text shown to the user (e.g. ``"wifi> "``).
        screen: the post-access screen (used for ``_emit``).
        render_menu: callable that re-prints the current menu.
        visible_hotkeys: callable that returns the set of hotkeys
            currently available.
        handle: callable that takes a hotkey and returns either
            an exit envelope (``{"exit": True}`` or
            ``{"exit": "back"}``) or ``None`` to continue.
        input_fn: optional override for ``screen.input_fn``.
        confirm_fn: optional override for ``screen.confirm_fn``.
        requires_gate_lookup: optional callable returning
            ``True`` if the action needs the per-step ACCEPT gate.
        gate_prompt: optional callable that returns the gate
            prompt string for an action.
        pdf_on_exit: optional Phase 2.4 §B.11 hook. When
            provided, the function is invoked with the final
            loop envelope and is expected to return a dict
            like ``{"ok": True, "path": "..."}``. The PDF
            export is best-effort — failure does NOT block
            the loop return.

    Returns:
        Standard envelope ``{"ok": True, "detached": False,
        "exit": True | False | "back" | "no_input"}``.
    """
    inp = input_fn or getattr(screen, "input_fn", None)
    cf = confirm_fn or getattr(screen, "confirm_fn", None)
    requires_gate = requires_gate_lookup or (lambda _a: False)
    render_prompt = gate_prompt or (
        lambda action: f"ACCEPT INTRUSIVE? {action}"
    )
    emit = getattr(screen, "_emit", lambda m: None)

    def _menu_index_bounds() -> tuple:
        v = sorted(visible_hotkeys() or [])
        return (0, max(0, len(v) - 1), v)

    try:
        render_menu()
    except Exception:  # noqa: BLE001
        # render_menu failure must not crash the loop; the operator
        # still gets a chance to interact.
        pass
    menu_index = 0
    while True:
        try:
            raw = (inp(prompt) if inp is not None else "")
        except Exception:  # noqa: BLE001
            final = {"ok": True, "detached": False, "exit": "no_input"}
            break
        k = _normalize(raw)
        if not k:
            # Empty input (operator pressed bare Enter, or input_fn
            # returned ""). CR/LF survive _normalize and are handled
            # by the ENTER branch below.
            final = {"ok": True, "detached": False, "exit": "no_input"}
            break
        # UP — move cursor up.
        if _is_up(k):
            lo, hi, _ = _menu_index_bounds()
            menu_index = max(lo, menu_index - 1)
            continue
        # DOWN — move cursor down.
        if _is_down(k):
            lo, hi, _ = _menu_index_bounds()
            menu_index = min(hi, menu_index + 1)
            continue
        # ENTER / SPACE — accept the currently-highlighted item.
        if _is_enter(k):
            lo, hi, v = _menu_index_bounds()
            if not v:
                continue
            if not (lo <= menu_index <= hi):
                menu_index = lo
            k = v[menu_index]
            # fall through to the regular single-key path
        # BACK / ESC / q — return to the parent screen.
        if _is_back(k):
            final = {"ok": True, "detached": False, "exit": "back"}
            break
        # 'e' exits the panel outright.
        if k == "e":
            final = {"ok": True, "detached": False, "exit": True}
            break
        # If the key is not a visible hotkey, log + continue.
        visible = visible_hotkeys() or set()
        if k not in visible:
            try:
                emit(
                    f"key {k!r} not in current menu — "
                    f"press [?] to see what's available"
                )
            except Exception:  # noqa: BLE001
                pass
            continue
        # Gate check (the per-step ACCEPT for requires_gate=True caps).
        if cf is not None and requires_gate(k):
            try:
                if not cf(render_prompt(k)):
                    try:
                        emit(f"CANCELLED: {k}")
                    except Exception:  # noqa: BLE001
                        pass
                    continue
            except Exception:  # noqa: BLE001
                continue
        # Dispatch.
        try:
            env = handle(k)
        except Exception as e:  # noqa: BLE001
            try:
                emit(f"[!] handler raised: {e}")
            except Exception:  # noqa: BLE001
                pass
            continue
        if isinstance(env, dict) and env.get("exit"):
            final = env
            break
        # Re-render the menu so the operator sees the result.
        try:
            render_menu()
        except Exception:  # noqa: BLE001
            pass
    # Phase 2.4 §B.11 — best-effort PDF export on every loop exit.
    if pdf_on_exit is not None:
        try:
            pdf_env = pdf_on_exit(final)
            if isinstance(pdf_env, dict):
                # attach to the returned envelope without overwriting keys
                final.setdefault("pdf_report", pdf_env)
        except Exception as e:  # noqa: BLE001
            final["pdf_report"] = {"ok": False, "error": str(e)}
    return final


__all__ = [
    "curses_free_loop",
]
