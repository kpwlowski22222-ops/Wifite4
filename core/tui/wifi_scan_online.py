#!/usr/bin/env python3
"""Top-left window: live online APs — unified TUI keys (↑↓ Enter/Space Backspace q)."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from core.tui import wifi_scan_bus as bus
from core.tui.scan_window_shell import (
    format_wifi_online,
    run_list_loop,
)
from core.tui.wifi_scan_external import LiveScanner


def run_curses(bus_dir: Path, iface: str) -> int:
    scanner = LiveScanner(iface, disappeared_timeout=10.0)
    scanner.start()
    latest_online: List[Dict[str, Any]] = []

    def get_items() -> List[Dict[str, Any]]:
        nonlocal latest_online
        online, offline = scanner.poll()
        latest_online = list(online or [])
        clients: Dict[str, Any] = {}
        for ap in list(online or []) + list(offline or []):
            b = str(ap.get("bssid") or "").upper()
            if b:
                clients[b] = list(ap.get("clients") or [])
        focus = None
        if latest_online:
            # focus updated in on_tick via state.idx — approximate first
            focus = latest_online[0].get("bssid")
        bus.update_state(
            bus_dir,
            online=online,
            offline=offline,
            clients=clients,
            focus_bssid=focus,
            iface=iface,
            error=scanner.last_error,
        )
        return latest_online

    def on_tick(state) -> None:
        if state.items:
            i = max(0, min(state.idx, len(state.items) - 1))
            focus = state.items[i].get("bssid")
            bus.update_state(bus_dir, focus_bssid=focus)

    def on_select(ap: Dict[str, Any]) -> None:
        bus.set_selection(bus_dir, ap)
        bus.request_quit(bus_dir)

    try:
        return run_list_loop(
            title=f"APs ONLINE  iface={iface}",
            get_items=get_items,
            row_fmt=format_wifi_online,
            on_select=on_select,
            on_tick=on_tick,
            should_stop=lambda: bus.should_quit(bus_dir),
            detail_kind="wifi",
            timeout_ms=200,
        )
    finally:
        scanner.stop()
        bus.request_quit(bus_dir)


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="KFIOSA WiFi online AP window")
    ap.add_argument("--bus", required=True, help="scan bus directory")
    ap.add_argument("--iface", required=True, help="monitor interface")
    args = ap.parse_args(argv)
    bus_dir = Path(args.bus)
    try:
        return run_curses(bus_dir, args.iface)
    except KeyboardInterrupt:
        bus.request_quit(bus_dir)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
