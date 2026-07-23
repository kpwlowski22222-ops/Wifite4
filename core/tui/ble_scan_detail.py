#!/usr/bin/env python3
"""Top-right window: focused BLE device detail — unified TUI keys."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from core.tui import ble_scan_bus as bus
from core.tui.scan_window_shell import format_kv_row, run_list_loop

_PRIORITY_KEYS = (
    "address", "addr", "name", "local_name", "rssi", "vendor",
    "uuids", "services", "manufacturer", "tx_power", "connectable",
    "first_seen_ts", "last_seen_ts",
)


def _find_dev(st: Dict[str, Any], addr: str) -> Optional[Dict[str, Any]]:
    if not addr:
        return None
    a = str(addr).upper()
    for d in list(st.get("online") or []) + list(st.get("offline") or []):
        da = str(d.get("address") or d.get("addr") or "").upper()
        if da == a:
            return d
    return None


def _kv_items(dev: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
    if not dev:
        return [{"key": "(empty)", "value": "no device focused yet", "id": "empty"}]
    rows: List[Dict[str, Any]] = []
    seen = set()
    for k in _PRIORITY_KEYS:
        if k in dev and dev[k] not in (None, "", [], {}):
            rows.append({"key": k, "value": str(dev[k])[:80], "id": k})
            seen.add(k)
    for k, v in list(dev.items())[:24]:
        if k in seen or v in (None, "", [], {}):
            continue
        rows.append({"key": str(k), "value": str(v)[:80], "id": str(k)})
        seen.add(k)
    return rows or [{"key": "(empty)", "value": "device has no fields", "id": "empty"}]


def run_curses(bus_dir: Path) -> int:
    focus_holder: Dict[str, Any] = {"focus": None, "dev": None}

    def get_items() -> List[Dict[str, Any]]:
        st = bus.read_json(bus_dir / "state.json")
        focus = st.get("focus_addr") or st.get("selected")
        focus_holder["focus"] = focus
        dev = _find_dev(st, str(focus or ""))
        focus_holder["dev"] = dev
        return _kv_items(dev)

    def on_tick(state) -> None:
        focus = focus_holder.get("focus") or "-"
        state.title = f"BLE DETAIL  focus={focus}"
        state.msg = "follows ONLINE focus · ↑↓ · ENTER mark field · BACKSPACE · q"
        dev = focus_holder.get("dev") or {}
        if dev:
            state.detail = (
                f"addr={dev.get('address') or dev.get('addr')}  "
                f"name={dev.get('name') or dev.get('local_name')}  "
                f"rssi={dev.get('rssi')}  vendor={dev.get('vendor')}"
            )
        else:
            state.detail = "Move focus on ONLINE window to populate fields"

    def on_select(row: Dict[str, Any]) -> None:
        try:
            bus.update_state(bus_dir, detail_field=row.get("key"))
        except Exception:
            pass

    return run_list_loop(
        title="BLE DETAIL",
        get_items=get_items,
        row_fmt=format_kv_row,
        on_select=on_select,
        on_tick=on_tick,
        should_stop=lambda: bus.should_quit(bus_dir),
        detail_kind="ble_kv",
        timeout_ms=300,
        exit_on_select=False,
    )


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="KFIOSA BLE detail window")
    ap.add_argument("--bus", required=True)
    ap.add_argument("--adapter", default="")
    args = ap.parse_args(argv)
    return run_curses(Path(args.bus))


if __name__ == "__main__":
    raise SystemExit(main())
