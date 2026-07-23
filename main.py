#!/usr/bin/env python3
"""
KFIOSA — Main Entry Point
=========================
Thin launcher: runs a preflight check (and starts ``ollama serve`` when
needed), then starts the wifite-style curses dashboard
(`core.tui.dashboard.KfiosaDashboard`).

Also exposes a non-curses **agentic CLI** for headless / scripted use:

  python main.py --cli holo status
  python main.py --cli holo run --goal ble_long_range_prep
  python main.py --cli ble-scan --text --seconds 20
  python main.py --cli wifi-scan --iface wlan0mon --text
  python main.py --help

Works under ``sudo python main.py``: expands PATH for ollama + holo
install locations and boots the daemon before curses takes the TTY.
"""

from __future__ import annotations

import argparse
import os
import sys
from typing import List, Optional

# Add project root to path for `core.*` / `dashboard.*` imports.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Load `.env` credentials early so all tools (AI, OSINT, Kismet, Flask, …)
# see keys via os.environ / core.env_loader before any backend imports.
try:
    from core.env_loader import load_project_env
    load_project_env()
except Exception:
    pass


def _ensure_path_for_tools() -> None:
    """Make sure ollama / holo / aircrack tools are findable under sudo.

    ``sudo`` often strips user PATH; ollama and holo-desktop-cli commonly
    live under ``~/.local/bin`` or ``~/.holo/bin``.
    """
    extras = [
        "/usr/local/bin",
        "/usr/bin",
        "/opt/ollama/bin",
        "/snap/bin",
    ]
    sudo_user = os.environ.get("SUDO_USER") or ""
    if sudo_user:
        extras.append(f"/home/{sudo_user}/.local/bin")
        extras.append(f"/home/{sudo_user}/bin")
        extras.append(f"/home/{sudo_user}/.holo/bin")
    home = os.path.expanduser("~")
    if home and home != "/root":
        extras.append(os.path.join(home, ".local", "bin"))
        extras.append(os.path.join(home, ".holo", "bin"))
    # root home when sudo without preserve
    extras.append("/root/.local/bin")
    extras.append("/root/.holo/bin")
    path = os.environ.get("PATH", "")
    parts = path.split(os.pathsep) if path else []
    for p in extras:
        if p and p not in parts and os.path.isdir(p):
            parts.insert(0, p)
    os.environ["PATH"] = os.pathsep.join(parts)


def _bootstrap_before_curses() -> None:
    """Load settings, start ollama if needed, print preflight.

    Runs **before** curses.wrapper so stdout is still a normal TTY and
    ``ollama serve`` can be spawned cleanly (including under sudo).
    """
    _ensure_path_for_tools()
    from core.settings import settings_manager
    try:
        settings_manager.load_settings()
    except Exception as e:
        print(f"[!] Settings load warning: {e}")

    try:
        from core.bootstrap import ensure_ollama_ready, preflight

        def _log(msg: str) -> None:
            print(msg)

        orep = ensure_ollama_ready(
            settings=settings_manager,
            on_event=_log,
            pull_missing=False,
            start_serve=True,
        )
        if orep.get("started_serve"):
            print("[+] Started `ollama serve` in background")
        if orep.get("reachable"):
            n = len(orep.get("models") or [])
            print(f"[+] Ollama API ready ({n} models at {orep.get('endpoint')})")
        else:
            print(
                f"[!] Ollama not ready: {orep.get('error') or 'unreachable'} "
                f"— AI chains fall back to heuristic"
            )
        preflight(settings=settings_manager, ensure_ollama=False)
    except Exception as e:
        print(f"[!] Preflight / Ollama bootstrap warning: {e}")
        try:
            from core.bootstrap import preflight
            preflight(settings=settings_manager, ensure_ollama=False)
        except Exception as e2:
            print(f"[!] Preflight warning: {e2}")


def _launch(stdscr):
    from core.tui.dashboard import KfiosaDashboard
    dashboard = KfiosaDashboard(stdscr)
    dashboard.run()


# ---------------------------------------------------------------------------
# Agentic / OS-tool CLI (no curses)
# ---------------------------------------------------------------------------

def _cli_holo(argv: List[str]) -> int:
    """``main.py --cli holo …`` — OS agentic desktop CLI (holo-desktop-cli)."""
    from core.desktop.holo_agent import (
        TASK_PRESETS,
        HoloDesktopBridge,
        holo_status,
        stop_holo,
    )

    ap = argparse.ArgumentParser(
        prog="main.py --cli holo",
        description=(
            "OS agentic tool CLI via holo-desktop-cli "
            "(https://github.com/hcompai/holo-desktop-cli). "
            "Desktop control is ACCEPT-gated unless --fake/--dry-run."
        ),
    )
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("status", help="Probe holo binary / login / version")
    sub.add_parser("presets", help="List built-in desktop task presets")
    p_stop = sub.add_parser("stop", help="Stop current holo turn")
    p_stop.add_argument("--force", action="store_true")

    p_run = sub.add_parser(
        "run",
        help="Run a desktop task (preset goal or free-text --task)",
    )
    p_run.add_argument(
        "--goal",
        default="",
        help=f"Preset key ({', '.join(sorted(TASK_PRESETS)[:6])}…)",
    )
    p_run.add_argument("--task", default="", help="Free-text desktop instruction")
    p_run.add_argument("--tool", default="", help="Focus application/tool name")
    p_run.add_argument("--model", default="", help="Ollama model name for ensure/pull")
    p_run.add_argument("--extra", default="", help="Extra instruction text")
    p_run.add_argument("--fake", action="store_true", help="holo run --fake (no desktop)")
    p_run.add_argument("--dry-run", action="store_true", help="Print argv only")
    p_run.add_argument(
        "--yes",
        action="store_true",
        help="Auto-ACCEPT the desktop gate (operator opts in on this CLI call)",
    )
    p_run.add_argument("--max-steps", type=int, default=None)
    p_run.add_argument("--max-time-s", type=float, default=None)

    p_plan = sub.add_parser(
        "plan",
        help="Run a structured predict→act→read→label desktop plan",
    )
    p_plan.add_argument(
        "--what", required=True,
        help="UI element to click (what_to_click)",
    )
    p_plan.add_argument(
        "--where", required=True,
        help="Where on screen / in which application",
    )
    p_plan.add_argument(
        "--for", dest="what_for", required=True,
        help="Purpose of the click/action",
    )
    p_plan.add_argument(
        "--predict", required=True,
        help="Predicted outcome after the action",
    )
    p_plan.add_argument("--goal", default="execute_plan", help="Plan preset/goal")
    p_plan.add_argument("--tool", default="", help="Focus application/tool name")
    p_plan.add_argument("--model", default="", help="Ollama model for ensure/pull")
    p_plan.add_argument(
        "--read-labels", action="store_true", default=None,
        help="Run live screen OCR labeling after the action (default: on for real runs)",
    )
    p_plan.add_argument(
        "--no-read-labels", action="store_true",
        help="Disable live screen OCR labeling after the action",
    )
    p_plan.add_argument(
        "--label-duration-s", type=float, default=6.0,
        help="Seconds to run live labeling",
    )
    p_plan.add_argument("--fake", action="store_true", help="holo run --fake (no desktop)")
    p_plan.add_argument("--dry-run", action="store_true", help="Print argv only")
    p_plan.add_argument(
        "--yes", action="store_true",
        help="Auto-ACCEPT the desktop gate (operator opts in on this CLI call)",
    )
    p_plan.add_argument("--max-steps", type=int, default=None)
    p_plan.add_argument("--max-time-s", type=float, default=None)

    args = ap.parse_args(argv)

    if args.cmd == "status":
        st = holo_status()
        print("=== Holo OS agent (holo-desktop-cli) ===")
        print(f"  ok:          {st.get('ok')}")
        print(f"  binary:      {st.get('holo_bin') or '(not found)'}")
        print(f"  version:     {st.get('version') or '-'}")
        print(f"  logged_in:   {st.get('logged_in_hint')}")
        print(f"  python_api:  {st.get('python_api')}")
        if st.get("error"):
            print(f"  error:       {st.get('error')}")
            print(f"  install:     {st.get('install_hint')}")
        return 0 if st.get("ok") else 1

    if args.cmd == "presets":
        print("=== Holo task presets ===")
        for k in sorted(TASK_PRESETS):
            text = TASK_PRESETS[k].replace("\n", " ")
            print(f"  {k:22}  {text[:90]}…")
        return 0

    if args.cmd == "stop":
        r = stop_holo(force=bool(args.force))
        print(r)
        return 0 if r.get("ok") else 1

    if args.cmd == "run":
        confirm = (lambda _p: True) if args.yes or args.fake or args.dry_run else None
        if confirm is None:
            print(
                "[!] Desktop control requires --yes (explicit ACCEPT on CLI) "
                "or use --fake / --dry-run."
            )
            return 2
        if args.yes:
            print(
                "[!] SECURITY: --yes bypasses the per-step ACCEPT/CANCEL gate. "
                "Use only in scripted, pre-approved workflows."
            )
        try:
            from core.settings import settings_manager
            sm = settings_manager
            sm.load_settings()
        except Exception:
            sm = None
        bridge = HoloDesktopBridge(confirm_fn=confirm, settings=sm)
        result = bridge.run(
            task=args.task,
            goal=args.goal or ("open_terminal" if not args.task else ""),
            tool=args.tool,
            model_name=args.model,
            extra=args.extra,
            max_steps=args.max_steps,
            max_time_s=args.max_time_s,
            fake=bool(args.fake),
            dry_run=bool(args.dry_run),
        )
        ok = bool(result.get("ok"))
        print(f"[{'+' if ok else '!'}] holo run ok={ok}")
        if result.get("error"):
            print(f"  error: {result['error']}")
        if result.get("cmd"):
            print(f"  cmd:   {result['cmd']}")
        if result.get("stdout"):
            print("--- stdout ---")
            print(result["stdout"][:4000])
        if result.get("stderr"):
            print("--- stderr ---")
            print(result["stderr"][:2000])
        return 0 if ok else 1

    if args.cmd == "plan":
        confirm = (lambda _p: True) if args.yes or args.fake or args.dry_run else None
        if confirm is None:
            print(
                "[!] Desktop control requires --yes (explicit ACCEPT on CLI) "
                "or use --fake / --dry-run."
            )
            return 2
        if args.yes:
            print(
                "[!] SECURITY: --yes bypasses the per-step ACCEPT/CANCEL gate. "
                "Use only in scripted, pre-approved workflows."
            )
        try:
            from core.settings import settings_manager
            sm = settings_manager
            sm.load_settings()
        except Exception:
            sm = None
        bridge = HoloDesktopBridge(confirm_fn=confirm, settings=sm)
        plan = {
            "what_to_click": args.what,
            "where": args.where,
            "what_for": args.what_for,
            "predicted_outcome": args.predict,
            "goal": args.goal,
            "tool": args.tool,
            "model": args.model,
        }
        # Default read_labels to True for real runs; --no-read-labels opts out.
        # Fake/dry-run are already screen-safe inside run_holo_plan.
        read_labels = not args.no_read_labels
        result = bridge.run_plan(
            plan,
            max_steps=args.max_steps,
            max_time_s=args.max_time_s,
            fake=bool(args.fake),
            dry_run=bool(args.dry_run),
            read_labels=read_labels,
            label_duration_s=args.label_duration_s,
        )
        ok = bool(result.get("ok"))
        print(f"[{'+' if ok else '!'}] holo plan ok={ok}")
        if result.get("error"):
            print(f"  error: {result['error']}")
        if result.get("cmd"):
            print(f"  cmd:   {result['cmd']}")
        if result.get("prediction_match") is not None:
            print(f"  prediction_match: {result['prediction_match']}")
        if result.get("labels"):
            print(f"  labels: {len(result['labels'])} extracted")
        if result.get("stdout"):
            print("--- stdout ---")
            print(result["stdout"][:4000])
        if result.get("stderr"):
            print("--- stderr ---")
            print(result["stderr"][:2000])
        return 0 if ok else 1

    return 2


def _cli_ble_scan(argv: List[str]) -> int:
    """``main.py --cli ble-scan`` — long-range external BLE scanner."""
    from core.tui.ble_scan_external import main as ble_main
    return int(ble_main(argv) or 0)


def _cli_wifi_scan(argv: List[str]) -> int:
    """``main.py --cli wifi-scan`` — external WiFi scanner."""
    from core.tui.wifi_scan_external import main as wifi_main
    return int(wifi_main(argv) or 0)


def _cli_agentic_debug(argv: List[str]) -> int:
    """Delegate to scripts/agentic_tui_debug.py."""
    script = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "scripts",
        "agentic_tui_debug.py",
    )
    if not os.path.isfile(script):
        print(f"[!] missing {script}")
        return 1
    os.execv(sys.executable, [sys.executable, script] + list(argv))
    return 1  # unreachable


def _run_cli(argv: List[str]) -> int:
    """Top-level non-curses CLI router."""
    _ensure_path_for_tools()
    if not argv or argv[0] in ("-h", "--help", "help"):
        print(
            "KFIOSA agentic CLI\n\n"
            "Usage:\n"
            "  python main.py --cli holo status\n"
            "  python main.py --cli holo presets\n"
            "  python main.py --cli holo run --goal ble_long_range_prep --yes\n"
            "  python main.py --cli holo run --goal ble_scan_cli --yes\n"
            "  python main.py --cli holo stop\n"
            "  python main.py --cli ble-scan --text --seconds 20\n"
            "  python main.py --cli wifi-scan --iface wlan0mon --text\n"
            "  python main.py --cli agentic-debug --preflight-only\n"
            "  python main.py                 # launch curses dashboard\n"
        )
        return 0

    head, rest = argv[0], argv[1:]
    if head == "holo":
        return _cli_holo(rest)
    if head in ("ble-scan", "ble_scan", "blescan"):
        return _cli_ble_scan(rest)
    if head in ("wifi-scan", "wifi_scan", "wifiscan"):
        return _cli_wifi_scan(rest)
    if head in ("agentic-debug", "agentic_debug", "tui-debug"):
        return _cli_agentic_debug(rest)
    print(f"[!] unknown CLI command: {head!r} (try --cli help)")
    return 2


def _main(argv: Optional[List[str]] = None):
    argv = list(sys.argv[1:] if argv is None else argv)

    # Non-TTY / --help without curses: avoid cbreak ERR in CI.
    if argv and argv[0] in ("-h", "--help"):
        print(
            "KFIOSA / Wifite4 — AI-driven offensive security TUI\n\n"
            "  sudo python main.py              Launch dashboard\n"
            "  python main.py --cli help        Agentic / OS-tool CLI\n"
            "  ./run_tui.sh                     Alt launcher\n"
        )
        return 0

    if argv and argv[0] == "--cli":
        return _run_cli(argv[1:])

    # Also accept bare `holo` as first arg for convenience
    if argv and argv[0] in ("holo", "ble-scan", "wifi-scan", "agentic-debug"):
        return _run_cli(argv)

    _bootstrap_before_curses()
    try:
        import curses
        curses.wrapper(_launch)
        print("\n[+] KFIOSA closed cleanly.")
        return 0
    except KeyboardInterrupt:
        print("\n[-] KFIOSA terminated by user.")
        return 130
    except Exception as e:
        print(f"\n[!] Error launching KFIOSA TUI: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(_main() or 0)
