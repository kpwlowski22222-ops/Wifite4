"""Unified external scan window shell — same movement model as main TUI.

Keys (all external scan windows)::

  ↑ / k       move selection up
  ↓ / j       move selection down
  ENTER/SPACE select (caller callback)
  BACKSPACE   clear selection / back (caller callback)
  q / Esc     quit
  PgUp/PgDn   page scroll (large lists)

Draws a consistent header, help bar, list, optional detail strip, status.
"""
from __future__ import annotations

import curses
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence


HELP_LINE = "↑↓ move · ENTER/SPACE select · BACKSPACE clear · q quit · PgUp/PgDn page"


@dataclass
class ScanWindowState:
    title: str = "SCAN"
    items: List[Dict[str, Any]] = field(default_factory=list)
    idx: int = 0
    msg: str = ""
    detail: str = ""
    selected_id: Optional[str] = None


def clamp_idx(idx: int, n: int) -> int:
    if n <= 0:
        return 0
    return max(0, min(int(idx), n - 1))


def format_wifi_online(ap: Dict[str, Any]) -> str:
    bssid = str(ap.get("bssid") or "")[:17]
    ssid = str(ap.get("ssid") or "?")[:16]
    ch = str(ap.get("channel") or "?")
    enc = str(ap.get("encryption") or ap.get("enc") or "?")[:8]
    pwr = str(ap.get("power") if ap.get("power") is not None else "")
    cli = str(ap.get("clients_count") or len(ap.get("clients") or []))
    pmf = "PMF" if ap.get("pmf") or ap.get("pmf_supported") else ""
    return f"{bssid}  {ssid:<16} ch={ch:<3} {enc:<8} pwr={pwr:<4} cli={cli} {pmf}"


def format_wifi_offline(ap: Dict[str, Any]) -> str:
    bssid = str(ap.get("bssid") or "")[:17]
    ssid = str(ap.get("ssid") or "?")[:14]
    last = _fmt_ts(ap.get("last_seen_ts") or ap.get("disappeared_at"))
    first = _fmt_ts(ap.get("first_seen_ts"))
    enc = str(ap.get("encryption") or ap.get("enc") or "")[:8]
    ch = ap.get("channel")
    dur = ap.get("seen_duration_s")
    if dur is None and ap.get("first_seen_ts") and ap.get("last_seen_ts"):
        try:
            dur = int(float(ap["last_seen_ts"]) - float(ap["first_seen_ts"]))
        except Exception:
            dur = None
    dur_s = f"{dur}s" if dur is not None else "-"
    return (
        f"{bssid}  {ssid:<14} last={last} first={first} "
        f"{enc} ch={ch} seen={dur_s}"
    )


def format_ble_online(dev: Dict[str, Any]) -> str:
    addr = str(dev.get("address") or dev.get("addr") or "")[:17]
    name = str(dev.get("name") or dev.get("local_name") or "?")[:16]
    rssi = str(dev.get("rssi") if dev.get("rssi") is not None else "?")
    vendor = str(dev.get("vendor") or "")[:12]
    conn = "conn" if dev.get("connectable") else ""
    return f"{addr}  {name:<16} rssi={rssi:<5} {vendor} {conn}"


def format_ble_offline(dev: Dict[str, Any]) -> str:
    addr = str(dev.get("address") or dev.get("addr") or "")[:17]
    name = str(dev.get("name") or "?")[:14]
    last = _fmt_ts(dev.get("last_seen_ts") or dev.get("disappeared_at"))
    first = _fmt_ts(dev.get("first_seen_ts"))
    rssi = dev.get("rssi")
    vendor = str(dev.get("vendor") or "")[:10]
    return f"{addr}  {name:<14} last={last} first={first} rssi={rssi} {vendor}"


def format_client_row(cli: Dict[str, Any]) -> str:
    """Associated WiFi client (or MAC-only bus entry)."""
    mac = str(cli.get("mac") or cli.get("bssid") or cli.get("addr") or cli.get("id") or "?")
    if len(mac) > 17:
        mac = mac[:17]
    pwr = cli.get("power")
    pwr_s = f" pwr={pwr}" if pwr is not None else ""
    vendor = str(cli.get("vendor") or "")[:14]
    note = str(cli.get("note") or cli.get("label") or "")[:20]
    return f"{mac}{pwr_s}  {vendor}  {note}".rstrip()


def format_kv_row(row: Dict[str, Any]) -> str:
    """Key/value detail line for BLE detail / generic inspectors."""
    k = str(row.get("key") or row.get("k") or "")
    v = str(row.get("value") or row.get("v") or row.get("val") or "")
    if not k and row.get("line"):
        return str(row["line"])[:120]
    return f"{k}: {v}"[:120]


def _fmt_ts(ts: Any) -> str:
    try:
        return time.strftime("%H:%M:%S", time.localtime(float(ts)))
    except Exception:
        return "-"


def detail_for_item(item: Dict[str, Any], kind: str = "wifi") -> str:
    """Multi-field detail strip for selected/highlighted target."""
    if not item:
        return ""
    if kind.startswith("ble"):
        return (
            f"addr={item.get('address') or item.get('addr')}  "
            f"name={item.get('name') or item.get('local_name')}  "
            f"rssi={item.get('rssi')}  vendor={item.get('vendor')}  "
            f"connectable={item.get('connectable')}  "
            f"first={_fmt_ts(item.get('first_seen_ts'))}  "
            f"last={_fmt_ts(item.get('last_seen_ts'))}"
        )
    return (
        f"bssid={item.get('bssid')}  ssid={item.get('ssid')}  "
        f"ch={item.get('channel')}  enc={item.get('encryption') or item.get('enc')}  "
        f"pwr={item.get('power')}  pmf={item.get('pmf') or item.get('pmf_supported')}  "
        f"vendor={item.get('vendor')}  "
        f"first={_fmt_ts(item.get('first_seen_ts'))}  "
        f"last={_fmt_ts(item.get('last_seen_ts'))}  "
        f"clients={item.get('clients_count') or len(item.get('clients') or [])}"
    )


def _theme_pair(n: int) -> int:
    try:
        return curses.color_pair(n)
    except Exception:
        return 0


def draw_scan_window(
    stdscr,
    state: ScanWindowState,
    *,
    row_fmt: Callable[[Dict[str, Any]], str],
    help_line: str = HELP_LINE,
) -> None:
    """Paint a full scan window frame (main-TUI palette when colours exist)."""
    stdscr.erase()
    try:
        h, w = stdscr.getmaxyx()
    except Exception:
        return
    # Apply shared theme once (no-op if already applied)
    try:
        from core.tui.ui_theme import apply_theme, get_current_theme
        apply_theme(stdscr, theme=get_current_theme())
    except Exception:
        pass

    # KFIOSA-style mini banner (matches BaseScreen.draw_header accent)
    title = f" {state.title}  n={len(state.items)} "
    if state.selected_id:
        title += f"  SEL={state.selected_id[:17]} "
    banner = " ╔" + "═" * min(56, max(20, w - 6)) + "╗"
    try:
        stdscr.addnstr(
            0, max(0, (w - len(banner)) // 2), banner[: w - 1], w - 1,
            _theme_pair(5) | curses.A_BOLD,
        )
        mid = f" ║  KFIOSA — {title.strip()[:40].center(40)}  ║"
        stdscr.addnstr(
            1, max(0, (w - len(mid)) // 2), mid[: w - 1], w - 1,
            _theme_pair(5) | curses.A_BOLD,
        )
        bot = " ╚" + "═" * min(56, max(20, w - 6)) + "╝"
        stdscr.addnstr(
            2, max(0, (w - len(bot)) // 2), bot[: w - 1], w - 1,
            _theme_pair(5) | curses.A_BOLD,
        )
        stdscr.addnstr(
            3, 0, help_line[: w - 1], w - 1, _theme_pair(4),
        )
        stdscr.addnstr(4, 0, ("─" * (w - 1))[: w - 1], w - 1, _theme_pair(6))
    except curses.error:
        pass

    detail_rows = 2 if state.detail else 0
    max_rows = max(1, h - 7 - detail_rows)
    n = len(state.items)
    idx = clamp_idx(state.idx, n)
    start = max(0, idx - max_rows + 1) if idx >= max_rows else 0

    for row, item in enumerate(state.items[start: start + max_rows]):
        y = row + 5
        i = start + row
        line = row_fmt(item)
        if i == idx:
            attr = curses.A_REVERSE | _theme_pair(1)
        else:
            attr = _theme_pair(6)
        try:
            stdscr.addnstr(y, 0, line[: w - 1], w - 1, attr)
        except curses.error:
            pass

    if state.detail:
        dy = h - 2 - 1
        try:
            stdscr.addnstr(dy, 0, ("─" * (w - 1))[: w - 1], w - 1, _theme_pair(6))
            stdscr.addnstr(
                dy + 1, 0, state.detail[: w - 1], w - 1, _theme_pair(4),
            )
        except curses.error:
            pass

    try:
        stdscr.addnstr(
            h - 1, 0, (state.msg or "")[: w - 1], w - 1,
            _theme_pair(3) | curses.A_BOLD,
        )
    except curses.error:
        pass
    try:
        stdscr.refresh()
    except curses.error:
        pass


def handle_nav_key(
    ch: int,
    idx: int,
    n: int,
    *,
    page: int = 5,
) -> tuple:
    """Return (new_idx, action) where action is None|'select'|'back'|'quit'|'none'."""
    if ch in (curses.KEY_UP, ord("k"), ord("K")):
        return clamp_idx(idx - 1, n), None
    if ch in (curses.KEY_DOWN, ord("j"), ord("J")):
        return clamp_idx(idx + 1, n), None
    if ch in (curses.KEY_PPAGE,):
        return clamp_idx(idx - page, n), None
    if ch in (curses.KEY_NPAGE,):
        return clamp_idx(idx + page, n), None
    if ch in (curses.KEY_ENTER, 10, 13, ord(" ")):
        return idx, "select"
    if ch in (curses.KEY_BACKSPACE, 127, 8):
        return idx, "back"
    if ch in (ord("q"), ord("Q"), 27, 3):  # q, ESC, Ctrl+C
        return idx, "quit"
    return idx, "none"


def run_list_loop(
    *,
    title: str,
    get_items: Callable[[], List[Dict[str, Any]]],
    row_fmt: Callable[[Dict[str, Any]], str],
    on_select: Optional[Callable[[Dict[str, Any]], None]] = None,
    on_tick: Optional[Callable[[ScanWindowState], None]] = None,
    should_stop: Optional[Callable[[], bool]] = None,
    detail_kind: str = "wifi",
    timeout_ms: int = 200,
    allow_empty_select: bool = False,
    exit_on_select: bool = True,
) -> int:
    """Generic interactive list loop using unified keys.

    ``exit_on_select`` True (default) closes after ENTER/SPACE — online target
    pick. False keeps the window open (clients / detail inspectors).

    Returns 0 on normal quit, 130 on interrupt.
    """
    state = ScanWindowState(title=title, msg="scanning…")

    def _main(stdscr) -> None:
        curses.curs_set(0)
        stdscr.nodelay(True)
        stdscr.timeout(timeout_ms)
        while True:
            if should_stop and should_stop():
                return
            items = get_items() or []
            state.items = items
            state.idx = clamp_idx(state.idx, len(items))
            cur = items[state.idx] if items else {}
            # Default detail strip for target lists; on_tick may override.
            if cur and detail_kind not in ("wifi_client", "ble_kv", "raw"):
                state.detail = detail_for_item(cur, detail_kind)
            elif not cur and detail_kind not in ("wifi_client", "ble_kv", "raw"):
                state.detail = ""
            if on_tick:
                try:
                    on_tick(state)
                except Exception:
                    pass
            draw_scan_window(stdscr, state, row_fmt=row_fmt)
            try:
                ch = stdscr.getch()
            except KeyboardInterrupt:
                return
            if ch == -1:
                continue
            state.idx, action = handle_nav_key(ch, state.idx, len(items))
            if action == "select":
                if items or allow_empty_select:
                    item = items[state.idx] if items else {}
                    if item and on_select:
                        on_select(item)
                        state.selected_id = str(
                            item.get("bssid")
                            or item.get("address")
                            or item.get("addr")
                            or item.get("mac")
                            or item.get("id")
                            or item.get("key")
                            or ""
                        )
                        if exit_on_select:
                            state.msg = f"SELECTED {state.selected_id} — engagement…"
                            draw_scan_window(stdscr, state, row_fmt=row_fmt)
                            time.sleep(0.45)
                            return
                        state.msg = f"marked {state.selected_id}"
            elif action == "back":
                state.selected_id = None
                state.msg = "selection cleared"
            elif action == "quit":
                return

    try:
        curses.wrapper(_main)
    except KeyboardInterrupt:
        return 130
    return 0
