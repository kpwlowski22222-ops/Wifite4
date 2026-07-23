#!/usr/bin/env python3
"""Top-left: live online BLE — unified TUI keys (↑↓ Enter/Space Backspace q)."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from core.tui import ble_scan_bus as bus
from core.tui.ble_scan_external import LiveBLEScanner
from core.tui.scan_window_shell import format_ble_online, run_list_loop


def run_curses(bus_dir: Path, adapter: Optional[str]) -> int:
    scanner = LiveBLEScanner(adapter=adapter, disappeared_timeout=30.0)
    scanner.start()
    latest: List[Dict[str, Any]] = []

    def get_items() -> List[Dict[str, Any]]:
        nonlocal latest
        online, offline = scanner.poll()
        latest = list(online or [])
        focus = None
        if latest:
            focus = latest[0].get("address") or latest[0].get("addr")
        bus.update_state(
            bus_dir,
            online=online,
            offline=offline,
            focus_addr=focus,
            adapter=adapter,
            error=getattr(scanner, "last_error", None),
        )
        return latest

    def on_tick(state) -> None:
        if state.items:
            i = max(0, min(state.idx, len(state.items) - 1))
            focus = state.items[i].get("address") or state.items[i].get("addr")
            bus.update_state(bus_dir, focus_addr=focus)

    def on_select(dev: Dict[str, Any]) -> None:
        bus.set_selection(bus_dir, dev)
        bus.request_quit(bus_dir)

    try:
        return run_list_loop(
            title=f"BLE ONLINE  adapter={adapter or 'auto'}",
            get_items=get_items,
            row_fmt=format_ble_online,
            on_select=on_select,
            on_tick=on_tick,
            should_stop=lambda: bus.should_quit(bus_dir),
            detail_kind="ble",
            timeout_ms=250,
        )
    finally:
        try:
            scanner.stop()
        except Exception:
            pass
        bus.request_quit(bus_dir)


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="KFIOSA BLE online window")
    ap.add_argument("--bus", required=True)
    ap.add_argument("--adapter", default="")
    args = ap.parse_args(argv)
    bus_dir = Path(args.bus)
    try:
        return run_curses(bus_dir, args.adapter or None)
    except KeyboardInterrupt:
        bus.request_quit(bus_dir)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
