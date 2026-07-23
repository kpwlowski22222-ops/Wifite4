"""core.post_access_tui.cli — ``python -m core.post_access_tui`` entry point.

Usage (the spawner builds this for you):
  python -m core.post_access_tui --state-b64 <base64> [--log-path <path>]

The CLI:
  1. Parses argv.
  2. Decodes the SessionState from the base64 blob.
  3. Constructs a PostAccessRunner.
  4. Constructs a PostAccessScreen with a default ACCEPT-yes confirm_fn
     (the orchestrator already gated the auto-open prompt; the menu
     actions themselves re-gate per action).
  5. Enters the curses loop.
  6. On F12 / Esc, returns 0 (the spawner process exits; the main
     chain keeps running in its own process).

If ``--state-b64`` is missing or invalid, prints a usage line and
returns 2 (not 1 — we don't want a crash on a transient spawn bug;
the operator will see the error in the spawner's log).

``curses-free`` mode (--no-curses): for hermetic tests, the CLI can be
driven without curses. The screen runs in curses-free mode and reads
keys from stdin. In production, --no-curses is not used; curses is
the default.
"""
from __future__ import annotations

import argparse
import base64
import json
import logging
import sys
from typing import Any, Dict, List, Optional

from .session_state import SessionState, get_log_path
from .runner import PostAccessRunner
from .screen import PostAccessScreen

logger = logging.getLogger(__name__)


#: Default ACCEPT-yes confirm_fn (the menu actions re-gate).
def _default_confirm_fn(prompt: str) -> bool:
    return True


def _parse_state_b64(s: str) -> Optional[SessionState]:
    """Decode the base64 blob and return a SessionState. None on error."""
    if not isinstance(s, str) or not s:
        return None
    try:
        raw = base64.b64decode(s.encode("ascii"), validate=False)
        d = json.loads(raw.decode("utf-8"))
        return SessionState.from_dict(d)
    except Exception:  # noqa: BLE001
        return None


def _build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="core.post_access_tui",
        description=(
            "KFIOSA post-access external TUI. Spawned by the orchestrator "
            "after a chain step achieves access. Use --state-b64 with the "
            "blob from spawner.build_argv."
        ),
    )
    p.add_argument("--state-b64", default="",
                   help="base64-encoded SessionState JSON")
    p.add_argument("--log-path", default="",
                   help="optional path for the in-TUI log file")
    p.add_argument("--no-curses", action="store_true",
                   help="curses-free loop (for tests; reads keys from stdin)")
    p.add_argument("--tui-mode", default="",
                   help="initial panel: shell|ble|network|full")
    p.add_argument("--ble-device", default="",
                   help="default BLE address to prefill on [C]onnect")
    p.add_argument("--net-filter", default="",
                   help="default session-name filter for [S]essions")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    """Entry point. Returns 0 on clean detach, 2 on usage error.

    Never raises — exceptions are logged to stderr and converted to
    a non-zero return code.
    """
    try:
        args = _build_argparser().parse_args(argv)
        state = _parse_state_b64(args.state_b64)
        if state is None:
            print("post_access_tui: invalid --state-b64", file=sys.stderr)
            return 2
        if not state.has_session():
            print("post_access_tui: state has no session", file=sys.stderr)
            return 2
        runner = PostAccessRunner(state=state)
        if args.no_curses:
            return _run_curses_free(runner, state, args)
        return _run_curses(runner, state, args)
    except Exception as e:  # noqa: BLE001
        print(f"post_access_tui: fatal: {e}", file=sys.stderr)
        logger.exception("post_access_tui fatal")
        return 1


def _run_curses(runner: PostAccessRunner, state: SessionState,
                args: argparse.Namespace) -> int:
    """Real curses loop. Imported lazily so --no-curses works in tests."""
    try:
        import curses  # noqa: F401  — used inside _curses_main
    except Exception as e:  # noqa: BLE001
        print(f"post_access_tui: curses not available: {e}", file=sys.stderr)
        return 1
    return _curses_main(runner, state, args)


def _curses_main(runner: PostAccessRunner, state: SessionState,
                 args: argparse.Namespace) -> int:
    """Run the curses loop. The full curses screen is a 600-LOC
    implementation; here we wire the screen to a curses wrapper that
    routes keys to ``input_fn`` and reads input via ``getch``."""
    import curses

    def _loop(stdscr) -> int:
        # We pass input_fn=None; the screen will use real curses getch
        # via the override below.
        activity_log: List[str] = []
        screen = PostAccessScreen(
            stdscr, state=state, runner=runner,
            confirm_fn=_default_confirm_fn,
            on_event=lambda m: activity_log.append(m),
            activity_log=activity_log,
        )
        # Override input_fn to read from curses getch in non-blocking
        # polling mode.
        def _curses_input(prompt: str) -> str:
            try:
                # Print the prompt on the status line.
                h, w = stdscr.getmaxyx()
                stdscr.move(h - 1, 0)
                stdscr.clrtoeol()
                if prompt:
                    stdscr.addstr(h - 1, 0, prompt[: max(0, w - 1)])
                stdscr.nodelay(False)
                ch = stdscr.getch()
                if ch == -1:
                    return ""
                if ch == curses.KEY_UP:
                    return "\x1b[A"
                if ch == curses.KEY_DOWN:
                    return "\x1b[B"
                if ch == curses.KEY_RIGHT:
                    return "\x1b[C"
                if ch == curses.KEY_LEFT:
                    return "\x1b[D"
                # Map special keys & escape sequences
                if ch == 27:  # ESC
                    try:
                        stdscr.timeout(0)
                        ch1 = stdscr.getch()
                        if ch1 in (ord("["), ord("O")):
                            ch2 = stdscr.getch()
                            if ch2 in (ord("A"), ord("a")):
                                return "\x1b[A"
                            elif ch2 in (ord("B"), ord("b")):
                                return "\x1b[B"
                            elif ch2 in (ord("C"), ord("c")):
                                return "\x1b[C"
                            elif ch2 in (ord("D"), ord("d")):
                                return "\x1b[D"
                    except Exception:
                        pass
                    return "\x1b"
                if ch == curses.KEY_F12:
                    return "KEY_F12"
                try:
                    return chr(ch)
                except Exception:  # noqa: BLE001
                    return ""
            except Exception:  # noqa: BLE001
                return ""
        screen.input_fn = _curses_input
        # Render the title + first help line.
        try:
            stdscr.clear()
            h, w = stdscr.getmaxyx()
            stdscr.addstr(0, 0, screen.title[: max(0, w - 1)])
            stdscr.addstr(1, 0, "Detach: F12 / Esc / X.  Per-step gate: every action ACCEPT/CANCEL'd."[: max(0, w - 1)])
            for i, (label, key, _) in enumerate(screen.__class__.__mro__[0].__dict__.get("MENU", [])):
                if i + 2 >= h - 1:
                    break
                stdscr.addstr(i + 2, 0, label[: max(0, w - 1)])
            stdscr.refresh()
        except Exception:  # noqa: BLE001
            pass
        # Drive the loop via run_curses_free (we've overridden input_fn).
        result = screen.run_curses_free()
        try:
            stdscr.refresh()
        except Exception:  # noqa: BLE001
            pass
        return 0 if result.get("ok") else 1

    try:
        import curses as _curses
        return _curses.wrapper(_loop)
    except Exception as e:  # noqa: BLE001
        print(f"post_access_tui: curses wrapper failed: {e}", file=sys.stderr)
        return 1


def _run_curses_free(runner: PostAccessRunner, state: SessionState,
                     args: argparse.Namespace) -> int:
    """No-curses loop — used by the test harness.

    Reads keys from stdin one per line (or, when a string is piped in,
    one char per iteration). This is the hermetic path.
    """
    activity_log: List[str] = []
    # Build a tiny input_fn that returns "" (test calls run_curses_free
    # directly with a custom input_fn).
    screen = PostAccessScreen(
        None, state=state, runner=runner,
        confirm_fn=_default_confirm_fn,
        on_event=lambda m: activity_log.append(m),
        activity_log=activity_log,
        input_fn=lambda _p: "",
    )
    res = screen.run_curses_free()
    return 0 if res.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())
