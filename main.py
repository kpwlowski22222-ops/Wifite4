#!/usr/bin/env python3
"""
KFIOSA — Main Entry Point
=========================
Thin launcher: runs a preflight check (and starts ``ollama serve`` when
needed), then starts the wifite-style curses dashboard
(`core.tui.dashboard.KfiosaDashboard`).

The legacy 8-item `WiFiOffensiveTUI` is preserved in `main.py.backup`; this
file now only delegates. The dashboard exposes the exact 5-item menu
required by the operator: wifi scan / ble scan / osint / settings / quit.

Works under ``sudo python main.py``: expands PATH for common ollama
install locations and boots the daemon before curses takes the TTY.
"""

import sys
import os
import curses

# Add project root to path for `core.*` / `dashboard.*` imports.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def _ensure_path_for_tools() -> None:
    """Make sure ollama / aircrack-style tools are findable under sudo.

    ``sudo`` often strips user PATH; ollama is commonly in /usr/local/bin
    or the invoking user's home.
    """
    extras = [
        "/usr/local/bin",
        "/usr/bin",
        "/opt/ollama/bin",
        "/snap/bin",
    ]
    # Invoking user home when run via sudo
    sudo_user = os.environ.get("SUDO_USER") or ""
    if sudo_user:
        extras.append(f"/home/{sudo_user}/.local/bin")
        extras.append(f"/home/{sudo_user}/bin")
    home = os.path.expanduser("~")
    if home and home != "/root":
        extras.append(os.path.join(home, ".local", "bin"))
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

    # Start ollama serve early (fast probe). Do not auto-pull models
    # here — that would freeze startup for minutes.
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
        # ensure_ollama=False: already started above; avoid double wait
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


def _main():
    _bootstrap_before_curses()
    try:
        curses.wrapper(_launch)
        print("\n[+] KFIOSA closed cleanly.")
    except KeyboardInterrupt:
        print("\n[-] KFIOSA terminated by user.")
    except Exception as e:
        print(f"\n[!] Error launching KFIOSA TUI: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    _main()
