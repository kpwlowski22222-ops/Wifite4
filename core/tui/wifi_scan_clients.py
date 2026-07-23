#!/usr/bin/env python3
"""Top-right window: clients for focused AP — unified TUI keys."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from core.tui import wifi_scan_bus as bus
from core.tui.scan_window_shell import format_client_row, run_list_loop


def _as_client_items(raw: List[Any]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for c in raw or []:
        if isinstance(c, dict):
            mac = str(
                c.get("mac") or c.get("bssid") or c.get("addr")
                or c.get("station") or ""
            )
            if mac:
                out.append(dict(c, mac=mac, id=mac))
        else:
            mac = str(c).strip()
            if mac:
                out.append({"mac": mac, "id": mac})
    return out


def run_curses(bus_dir: Path) -> int:
    focus_holder: Dict[str, Any] = {"focus": None}

    def get_items() -> List[Dict[str, Any]]:
        st = bus.read_json(bus_dir / "state.json")
        focus = st.get("focus_bssid") or st.get("selected")
        focus_holder["focus"] = focus
        clients_map = st.get("clients") or {}
        raw: List[Any] = []
        if focus:
            raw = list(clients_map.get(str(focus).upper()) or [])
            if not raw:
                raw = list(clients_map.get(str(focus)) or [])
        return _as_client_items(raw)

    def on_tick(state) -> None:
        focus = focus_holder.get("focus") or "-"
        state.title = f"CLIENTS  focus={focus}  n={len(state.items)}"
        if not state.items:
            state.msg = (
                "no associated clients yet — hop channels / wait · "
                "↑↓ · BACKSPACE · q quit"
            )
            state.detail = f"Waiting for STAs on AP {focus}"
        else:
            state.msg = (
                f"focus={focus} · ↑↓ move · ENTER mark · "
                "BACKSPACE clear · q quit"
            )
            cur = state.items[state.idx] if state.items else {}
            state.detail = (
                f"mac={cur.get('mac')}  power={cur.get('power')}  "
                f"vendor={cur.get('vendor') or '-'}"
            )

    def on_select(cli: Dict[str, Any]) -> None:
        try:
            bus.update_state(
                bus_dir,
                selected_client=cli.get("mac") or cli.get("id"),
            )
        except Exception:
            pass

    return run_list_loop(
        title="CLIENTS",
        get_items=get_items,
        row_fmt=format_client_row,
        on_select=on_select,
        on_tick=on_tick,
        should_stop=lambda: bus.should_quit(bus_dir),
        detail_kind="wifi_client",
        timeout_ms=300,
        exit_on_select=False,
    )


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="KFIOSA WiFi clients window")
    ap.add_argument("--bus", required=True)
    ap.add_argument("--iface", default="")
    args = ap.parse_args(argv)
    bus_dir = Path(args.bus)
    try:
        return run_curses(bus_dir)
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
