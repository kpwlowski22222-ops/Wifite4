"""In-TUI live scan panels — same aesthetics as the main KFIOSA dashboard.

Replaces external xterm/gnome-terminal scan windows with a full-screen
overlay on the shared ``stdscr``:

  * KFIOSA box banner (color_pair 5) + status strip (pair 4)
  * ONLINE / OFFLINE tables with SELECTED reverse highlight (pair 1)
  * Detail strip + help footer matching BaseScreen / ui_theme
  * Keys: ↑↓ j/k · ENTER/SPACE select · TAB switch table · A AIO · r rescan · q back

Default path for WiFi/BLE Scan; set ``KFIOSA_EXTERNAL_SCAN=1`` to restore
external windows.
"""
from __future__ import annotations

import curses
import json
import logging
import os
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from core.tui.scan_window_shell import (
    clamp_idx,
    detail_for_item,
    format_ble_offline,
    format_ble_online,
    format_client_row,
    format_wifi_offline,
    format_wifi_online,
    handle_nav_key,
)

logger = logging.getLogger(__name__)

HELP_WIFI = (
    "↑↓/jk move · TAB tables · ENTER/SPACE select · A AIO eng · r rescan · q back"
)
HELP_BLE = (
    "↑↓/jk move · TAB online/offline · ENTER/SPACE select · A AIO · r rescan · q back"
)


def prefer_embedded_scan() -> bool:
    """True unless operator forces external windows."""
    raw = (os.environ.get("KFIOSA_EXTERNAL_SCAN") or "").strip().lower()
    if raw in ("1", "true", "yes", "on", "external"):
        return False
    # settings optional: scan.embed_in_tui
    return True


def _pair(n: int) -> int:
    try:
        return curses.color_pair(n)
    except Exception:
        return 0


def _safe_add(stdscr, y: int, x: int, text: str, attr: int = 0, width: int = 0) -> None:
    try:
        h, w = stdscr.getmaxyx()
        if y < 0 or y >= h or x >= w:
            return
        lim = (width or (w - x)) - 1
        if lim <= 0:
            return
        stdscr.addnstr(y, x, (text or "")[:lim], lim, attr)
    except curses.error:
        pass


def _draw_kfiosa_header(
    stdscr,
    *,
    title: str,
    iface: str,
    online_n: int,
    offline_n: int,
    err: str = "",
) -> int:
    """Return first body row y (below header)."""
    try:
        h, w = stdscr.getmaxyx()
    except Exception:
        return 5
    banner = " ╔══════════════════════════════════════════════════════════╗"
    mid = f" ║          KFIOSA — {title.upper()[:30].center(30)}          ║"
    bot = " ╚══════════════════════════════════════════════════════════╝"
    attr = _pair(5) | curses.A_BOLD
    _safe_add(stdscr, 0, max(0, (w - len(banner)) // 2), banner, attr, w)
    _safe_add(stdscr, 1, max(0, (w - len(mid)) // 2), mid, attr, w)
    _safe_add(stdscr, 2, max(0, (w - len(bot)) // 2), bot, attr, w)

    status = (
        f" [ iface: {iface or 'auto'} ] "
        f"[ online: {online_n} ] [ offline: {offline_n} ] "
        f"[ LIVE SCAN ] "
    )
    if err:
        status += f"[ ! {err[:28]} ]"
    _safe_add(
        stdscr, 3, max(0, (w - len(status)) // 2),
        status, _pair(4) | curses.A_BOLD, w,
    )
    _safe_add(stdscr, 4, 0, "─" * max(1, w - 1), _pair(6), w)
    return 5


def _draw_table_block(
    stdscr,
    *,
    top: int,
    height: int,
    width: int,
    x: int,
    title: str,
    items: List[Dict[str, Any]],
    idx: int,
    row_fmt: Callable[[Dict[str, Any]], str],
    focused: bool,
) -> None:
    head_attr = (
        (_pair(4) | curses.A_BOLD | curses.A_REVERSE)
        if focused
        else (_pair(4) | curses.A_BOLD)
    )
    label = f" {title} ({len(items)}) "
    if focused:
        label = f"▶{label}"
    _safe_add(stdscr, top, x, label.ljust(max(8, width - 1)), head_attr, width)

    body_h = max(1, height - 1)
    n = len(items)
    idx = clamp_idx(idx, n)
    start = max(0, idx - body_h + 1) if idx >= body_h else 0
    for row, item in enumerate(items[start: start + body_h]):
        y = top + 1 + row
        i = start + row
        line = row_fmt(item)
        selected = focused and i == idx
        if selected:
            attr = curses.A_REVERSE | _pair(1)
        else:
            attr = _pair(6)
        _safe_add(stdscr, y, x + 1, line, attr, width - 1)


def run_embedded_wifi_scan(
    stdscr,
    *,
    iface: str,
    out_path: str = "logs/wifi_scan_selection.json",
    activity_log: Optional[List[str]] = None,
) -> Optional[Dict[str, Any]]:
    """Full-screen embedded WiFi live scan. Returns selected AP or None."""
    from core.tui.wifi_scan_external import LiveScanner

    log = activity_log if activity_log is not None else []
    try:
        from core.tui.ui_theme import apply_theme, get_current_theme
        apply_theme(stdscr, theme=get_current_theme())
    except Exception:
        pass

    scanner = LiveScanner(iface, disappeared_timeout=8.0)
    scanner.start()
    log.append(f"[*] Embedded WiFi scan on {iface} (in-TUI)…")

    focus = "online"  # online | offline | clients
    online_idx = 0
    offline_idx = 0
    clients_idx = 0
    selected: Optional[Dict[str, Any]] = None
    aio = False
    msg = "scanning…"
    prev_nodelay = True
    try:
        try:
            stdscr.nodelay(True)
            stdscr.timeout(200)
            curses.curs_set(0)
        except Exception:
            pass

        while True:
            online, offline = scanner.poll()
            online = list(online or [])
            offline = list(offline or [])
            focus_ap = None
            if focus == "online" and online:
                online_idx = clamp_idx(online_idx, len(online))
                focus_ap = online[online_idx]
            elif focus == "offline" and offline:
                offline_idx = clamp_idx(offline_idx, len(offline))
                focus_ap = offline[offline_idx]
            elif online:
                focus_ap = online[clamp_idx(online_idx, len(online))]
            clients: List[Dict[str, Any]] = []
            if focus_ap:
                raw_cli = focus_ap.get("clients") or []
                for c in raw_cli:
                    if isinstance(c, dict):
                        clients.append(c)
                    else:
                        clients.append({"mac": str(c)})
            if focus == "clients":
                clients_idx = clamp_idx(clients_idx, len(clients))

            try:
                h, w = stdscr.getmaxyx()
            except Exception:
                h, w = 24, 80
            stdscr.erase()
            body_y = _draw_kfiosa_header(
                stdscr,
                title="WiFi SCAN",
                iface=scanner.iface or iface,
                online_n=len(online),
                offline_n=len(offline),
                err=scanner.last_error or "",
            )
            # Layout: left 60% online+offline stacked, right 40% clients
            avail = max(6, h - body_y - 3)
            if w >= 90:
                left_w = max(40, int(w * 0.62))
                right_w = w - left_w
                h_on = max(4, (avail * 6) // 10)
                h_off = max(3, avail - h_on)
                _draw_table_block(
                    stdscr, top=body_y, height=h_on, width=left_w, x=0,
                    title="ONLINE APs", items=online, idx=online_idx,
                    row_fmt=format_wifi_online, focused=(focus == "online"),
                )
                _draw_table_block(
                    stdscr, top=body_y + h_on, height=h_off, width=left_w, x=0,
                    title="OFFLINE / SEEN", items=offline, idx=offline_idx,
                    row_fmt=format_wifi_offline, focused=(focus == "offline"),
                )
                _draw_table_block(
                    stdscr, top=body_y, height=avail, width=right_w, x=left_w,
                    title="CLIENTS (focus AP)", items=clients, idx=clients_idx,
                    row_fmt=format_client_row, focused=(focus == "clients"),
                )
            else:
                h_on = max(4, (avail * 6) // 10)
                h_off = max(3, avail - h_on)
                _draw_table_block(
                    stdscr, top=body_y, height=h_on, width=w, x=0,
                    title="ONLINE APs", items=online, idx=online_idx,
                    row_fmt=format_wifi_online, focused=(focus == "online"),
                )
                _draw_table_block(
                    stdscr, top=body_y + h_on, height=h_off, width=w, x=0,
                    title="OFFLINE / SEEN", items=offline, idx=offline_idx,
                    row_fmt=format_wifi_offline, focused=(focus == "offline"),
                )

            detail = detail_for_item(focus_ap or {}, "wifi") if focus_ap else ""
            _safe_add(stdscr, h - 3, 0, "─" * max(1, w - 1), _pair(6), w)
            _safe_add(stdscr, h - 2, 0, detail, _pair(4), w)
            foot = f" {HELP_WIFI}  ·  {msg}"
            _safe_add(stdscr, h - 1, 0, foot, _pair(3) | curses.A_BOLD, w)
            try:
                stdscr.refresh()
            except curses.error:
                pass

            try:
                ch = stdscr.getch()
            except Exception:
                ch = -1
            if ch == -1:
                continue

            # TAB cycles tables
            if ch in (9, ord("\t")):
                order = ["online", "offline", "clients"]
                focus = order[(order.index(focus) + 1) % len(order)]
                msg = f"focus={focus}"
                continue
            if ch in (ord("r"), ord("R")):
                scanner.stop()
                scanner = LiveScanner(iface, disappeared_timeout=8.0)
                scanner.start()
                msg = "rescanning…"
                continue
            if ch in (ord("a"), ord("A")):
                items = online if focus == "online" else offline
                idx = online_idx if focus == "online" else offline_idx
                if items:
                    selected = dict(items[clamp_idx(idx, len(items))])
                    aio = True
                    msg = "AIO select"
                    break
                msg = "nothing to AIO-select"
                continue

            n = (
                len(online) if focus == "online"
                else len(offline) if focus == "offline"
                else len(clients)
            )
            idx = (
                online_idx if focus == "online"
                else offline_idx if focus == "offline"
                else clients_idx
            )
            new_idx, act = handle_nav_key(ch, idx, n)
            if focus == "online":
                online_idx = new_idx
            elif focus == "offline":
                offline_idx = new_idx
            else:
                clients_idx = new_idx

            if act == "quit":
                selected = None
                break
            if act == "back":
                selected = None
                msg = "selection cleared"
                continue
            if act == "select":
                if focus == "clients":
                    msg = "select an AP (TAB to ONLINE)"
                    continue
                items = online if focus == "online" else offline
                if not items:
                    msg = "no targets"
                    continue
                selected = dict(items[clamp_idx(new_idx, len(items))])
                break
    finally:
        try:
            scanner.stop()
        except Exception:
            pass
        try:
            stdscr.nodelay(True)
            stdscr.timeout(100)
            stdscr.erase()
            stdscr.refresh()
        except Exception:
            pass

    if selected:
        selected["interface"] = scanner.iface or iface
        selected["from_external_scan"] = False
        selected["from_embedded_scan"] = True
        try:
            Path("logs").mkdir(parents=True, exist_ok=True)
            Path(out_path).write_text(
                json.dumps({
                    "selected": selected,
                    "aio_attack": bool(aio),
                    "networks": [selected],
                    "ts": time.time(),
                    "embedded": True,
                }, ensure_ascii=False, default=str),
                encoding="utf-8",
            )
        except Exception as e:
            logger.debug("write selection: %s", e)
        log.append(
            f"[+] Selected AP: {selected.get('ssid') or '<hidden>'} "
            f"[{selected.get('bssid')}]"
            + (" — AIO" if aio else "")
        )
    else:
        log.append("[i] Embedded WiFi scan closed (no selection).")
    return selected


def run_embedded_ble_scan(
    stdscr,
    *,
    adapter: Optional[str] = None,
    out_path: str = "logs/ble_scan_selection.json",
    activity_log: Optional[List[str]] = None,
) -> Optional[Dict[str, Any]]:
    """Full-screen embedded BLE live scan. Returns selected device or None."""
    from core.tui.ble_scan_external import LiveBLEScanner

    log = activity_log if activity_log is not None else []
    try:
        from core.tui.ui_theme import apply_theme, get_current_theme
        apply_theme(stdscr, theme=get_current_theme())
    except Exception:
        pass

    scanner = LiveBLEScanner(adapter=adapter, disappeared_timeout=20.0, pulse_s=8)
    scanner.start()
    log.append(f"[*] Embedded BLE scan (adapter={adapter or 'auto'})…")

    focus = "online"
    online_idx = 0
    offline_idx = 0
    selected: Optional[Dict[str, Any]] = None
    aio = False
    msg = "scanning…"
    try:
        try:
            stdscr.nodelay(True)
            stdscr.timeout(250)
            curses.curs_set(0)
        except Exception:
            pass

        while True:
            online, offline = scanner.poll()
            online = list(online or [])
            offline = list(offline or [])
            online_idx = clamp_idx(online_idx, len(online))
            offline_idx = clamp_idx(offline_idx, len(offline))
            cur = None
            if focus == "online" and online:
                cur = online[online_idx]
            elif focus == "offline" and offline:
                cur = offline[offline_idx]

            try:
                h, w = stdscr.getmaxyx()
            except Exception:
                h, w = 24, 80
            stdscr.erase()
            body_y = _draw_kfiosa_header(
                stdscr,
                title="BLE SCAN",
                iface=adapter or "auto",
                online_n=len(online),
                offline_n=len(offline),
                err=scanner.last_error or "",
            )
            avail = max(6, h - body_y - 3)
            h_on = max(4, (avail * 6) // 10)
            h_off = max(3, avail - h_on)
            _draw_table_block(
                stdscr, top=body_y, height=h_on, width=w, x=0,
                title="ONLINE DEVICES", items=online, idx=online_idx,
                row_fmt=format_ble_online, focused=(focus == "online"),
            )
            _draw_table_block(
                stdscr, top=body_y + h_on, height=h_off, width=w, x=0,
                title="OFFLINE / SEEN", items=offline, idx=offline_idx,
                row_fmt=format_ble_offline, focused=(focus == "offline"),
            )
            detail = detail_for_item(cur or {}, "ble") if cur else ""
            _safe_add(stdscr, h - 3, 0, "─" * max(1, w - 1), _pair(6), w)
            _safe_add(stdscr, h - 2, 0, detail, _pair(4), w)
            _safe_add(
                stdscr, h - 1, 0, f" {HELP_BLE}  ·  {msg}",
                _pair(3) | curses.A_BOLD, w,
            )
            try:
                stdscr.refresh()
            except curses.error:
                pass

            try:
                ch = stdscr.getch()
            except Exception:
                ch = -1
            if ch == -1:
                continue
            if ch in (9, ord("\t")):
                focus = "offline" if focus == "online" else "online"
                msg = f"focus={focus}"
                continue
            if ch in (ord("r"), ord("R")):
                scanner.stop()
                scanner = LiveBLEScanner(
                    adapter=adapter, disappeared_timeout=20.0, pulse_s=8,
                )
                scanner.start()
                msg = "rescanning…"
                continue
            if ch in (ord("a"), ord("A")):
                items = online if focus == "online" else offline
                idx = online_idx if focus == "online" else offline_idx
                if items:
                    selected = dict(items[clamp_idx(idx, len(items))])
                    aio = True
                    break
                msg = "nothing to select"
                continue

            items = online if focus == "online" else offline
            idx = online_idx if focus == "online" else offline_idx
            new_idx, act = handle_nav_key(ch, idx, len(items))
            if focus == "online":
                online_idx = new_idx
            else:
                offline_idx = new_idx
            if act == "quit":
                selected = None
                break
            if act == "back":
                selected = None
                msg = "cleared"
                continue
            if act == "select":
                if not items:
                    msg = "no devices"
                    continue
                selected = dict(items[clamp_idx(new_idx, len(items))])
                break
    finally:
        try:
            scanner.stop()
        except Exception:
            pass
        try:
            stdscr.nodelay(True)
            stdscr.timeout(100)
            stdscr.erase()
            stdscr.refresh()
        except Exception:
            pass

    if selected:
        if adapter:
            selected.setdefault("adapter", adapter)
        selected["from_external_scan"] = False
        selected["from_embedded_scan"] = True
        try:
            Path("logs").mkdir(parents=True, exist_ok=True)
            Path(out_path).write_text(
                json.dumps({
                    "selected": selected,
                    "aio_attack": bool(aio),
                    "devices": [selected],
                    "ts": time.time(),
                    "embedded": True,
                }, ensure_ascii=False, default=str),
                encoding="utf-8",
            )
        except Exception as e:
            logger.debug("write ble selection: %s", e)
        log.append(
            f"[+] Selected BLE: {selected.get('name')} "
            f"[{selected.get('address')}]"
            + (" — AIO" if aio else "")
        )
    else:
        log.append("[i] Embedded BLE scan closed (no selection).")
    return selected


__all__ = [
    "prefer_embedded_scan",
    "run_embedded_wifi_scan",
    "run_embedded_ble_scan",
]
