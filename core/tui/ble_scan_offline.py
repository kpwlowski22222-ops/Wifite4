#!/usr/bin/env python3
"""Bottom-right: offline BLE devices with history — unified TUI keys."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from core.tui import ble_scan_bus as bus
from core.tui.scan_window_shell import format_ble_offline, run_list_loop


def run_curses(bus_dir: Path) -> int:
    def get_items() -> List[Dict[str, Any]]:
        st = bus.read_json(bus_dir / "state.json")
        return list(st.get("offline") or [])

    def on_select(dev: Dict[str, Any]) -> None:
        bus.set_selection(bus_dir, {**dev, "from_offline": True})

    return run_list_loop(
        title="BLE OFFLINE  (history + timestamps)",
        get_items=get_items,
        row_fmt=format_ble_offline,
        on_select=on_select,
        should_stop=lambda: bus.should_quit(bus_dir),
        detail_kind="ble",
        timeout_ms=400,
    )


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--bus", required=True)
    ap.add_argument("--adapter", default="")
    args = ap.parse_args(argv)
    return run_curses(Path(args.bus))


if __name__ == "__main__":
    raise SystemExit(main())
