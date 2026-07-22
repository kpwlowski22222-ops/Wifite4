#!/usr/bin/env python3
"""
KFIOSA — Main Entry Point
=========================
Thin launcher: runs a preflight check, then starts the wifite-style curses
dashboard (`core.tui.dashboard.KfiosaDashboard`).

The legacy 8-item `WiFiOffensiveTUI` is preserved in `main.py.backup`; this
file now only delegates. The dashboard exposes the exact 5-item menu
required by the operator: wifi scan / ble scan / osint / settings / quit.
"""

import sys
import os
import curses

# Add project root to path for `core.*` / `dashboard.*` imports.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def _launch(stdscr):
    from core.bootstrap import preflight
    from core.settings import settings_manager
    settings_manager.load_settings()
    # Preflight prints a present/missing table to stdout before curses
    # owns the screen.
    try:
        preflight(settings=settings_manager)
    except Exception as e:
        print(f"[!] Preflight warning: {e}")

    from core.tui.dashboard import KfiosaDashboard
    dashboard = KfiosaDashboard(stdscr)
    dashboard.run()


def _main():
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