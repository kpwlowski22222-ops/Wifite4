"""In-TUI live scan panels — smooth input-first WiFi / BLE scanners.

Layout (wide terminal):
  Left top    ONLINE APs / devices
  Left bottom OFFLINE / SEEN
  Right       Clients (WiFi) or Services/detail (BLE) for the *focused* row

Focus (cursor) drives the right panel — ENTER only *marks* a target for AIO;
it is not an engagement accept. Scan runs infinitely until q / Ctrl+C (or A).

Design: keys are always handled before catalog I/O. Background scan is slow
on purpose so arrow movement stays smooth.
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
    format_kv_row,
    format_wifi_offline,
    format_wifi_online,
    handle_nav_key,
)

logger = logging.getLogger(__name__)

HELP_WIFI = (
    "↑↓/jk move · TAB panels · ENTER mark · A AIO · r rescan · q/Ctrl+C exit · LIVE slow"
)
HELP_BLE = (
    "↑↓/jk move · TAB panels · ENTER mark · A AIO · r rescan · q/Ctrl+C exit · LIVE slow"
)

# Catalog refresh deliberately slow — UI smoothness > scan refresh rate
WIFI_POLL_S = 1.25
BLE_POLL_S = 1.20
KEY_TIMEOUT_MS = 20
IDLE_PAINT_S = 0.45


def _item_id(item: Optional[Dict[str, Any]]) -> str:
    """Stable identity for cursor tracking across catalog updates."""
    if not isinstance(item, dict):
        return ""
    for k in ("bssid", "address", "addr", "mac", "id"):
        v = item.get(k)
        if v:
            return str(v).upper()
    return ""


def _idx_for_id(
    items: List[Dict[str, Any]], item_id: str, fallback: int = 0
) -> int:
    n = len(items)
    if n <= 0:
        return 0
    if item_id:
        for i, it in enumerate(items):
            if _item_id(it) == item_id:
                return i
    return clamp_idx(fallback, n)


def _prepare_stdscr(stdscr, timeout_ms: int = KEY_TIMEOUT_MS) -> None:
    try:
        curses.curs_set(0)
    except Exception:
        pass
    try:
        stdscr.keypad(True)
    except Exception:
        pass
    try:
        stdscr.nodelay(True)
        stdscr.timeout(int(timeout_ms))
    except Exception:
        pass


def _read_key(stdscr, timeout_ms: int = KEY_TIMEOUT_MS) -> int:
    """Read one key; set timeout for this read then restore."""
    try:
        stdscr.timeout(int(timeout_ms))
    except Exception:
        pass
    try:
        from core.tui.base_screen import read_curses_key
        return int(read_curses_key(stdscr, timeout_ms=timeout_ms))
    except Exception:
        try:
            return int(stdscr.getch())
        except Exception:
            return -1


def _move_idx(idx: int, n: int, delta: int) -> int:
    if n <= 0:
        return 0
    return (int(idx) + int(delta)) % n


def _drain_nav_burst(stdscr, first_key: int) -> int:
    """Coalesce held/mashed ↑↓/jk into one net step (smooth high-rate move)."""

    def step_for(k: int) -> int:
        if k in (curses.KEY_UP, ord("k"), ord("K")):
            return -1
        if k in (curses.KEY_DOWN, ord("j"), ord("J")):
            return 1
        if k in (curses.KEY_PPAGE,):
            return -5
        if k in (curses.KEY_NPAGE,):
            return 5
        return 0

    steps = step_for(first_key)
    if steps == 0 or stdscr is None:
        return steps
    try:
        stdscr.timeout(0)
        for _ in range(64):
            k = stdscr.getch()
            if k == -1:
                break
            d = step_for(k)
            if d == 0:
                try:
                    curses.ungetch(k)
                except Exception:
                    pass
                break
            steps += d
    except Exception:
        pass
    finally:
        try:
            stdscr.timeout(KEY_TIMEOUT_MS)
        except Exception:
            pass
    return steps


def prefer_embedded_scan() -> bool:
    raw = (os.environ.get("KFIOSA_EXTERNAL_SCAN") or "").strip().lower()
    if raw in ("1", "true", "yes", "on", "external"):
        return False
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
        f"[ LIVE · slow catalog ] "
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
    marked_id: str = "",
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
        is_focus = focused and i == idx
        is_mark = bool(marked_id) and _item_id(item) == marked_id
        if is_focus:
            attr = curses.A_REVERSE | _pair(1)
            prefix = "▶ "
        elif is_mark:
            attr = _pair(1) | curses.A_BOLD
            prefix = "* "
        else:
            attr = _pair(6)
            prefix = f"{i + 1} " if i < 9 else "  "
        _safe_add(stdscr, y, x + 1, (prefix + line), attr, width - 1)


def _clients_from_ap(ap: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
    if not ap:
        return []
    out: List[Dict[str, Any]] = []
    for c in ap.get("clients") or []:
        if isinstance(c, dict):
            out.append(c)
        else:
            out.append({"mac": str(c)})
    return out


def _ble_detail_rows(dev: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Right-panel rows for focused BLE device (not ENTER-accept)."""
    if not dev:
        return []
    rows: List[Dict[str, Any]] = []
    rows.append({"key": "name", "value": str(dev.get("name") or "?")})
    rows.append({"key": "addr", "value": str(dev.get("address") or "")})
    if dev.get("rssi") is not None:
        rows.append({"key": "rssi", "value": str(dev.get("rssi"))})
    if dev.get("vendor"):
        rows.append({"key": "vendor", "value": str(dev["vendor"])[:40]})
    if dev.get("connectable") is not None:
        rows.append({"key": "connectable", "value": str(bool(dev.get("connectable")))})
    for s in (dev.get("services") or [])[:12]:
        rows.append({"key": "svc", "value": str(s)[:48]})
    for u in (dev.get("service_uuids") or dev.get("uuids") or [])[:8]:
        rows.append({"key": "uuid", "value": str(u)[:48]})
    if dev.get("manufacturer_data") or dev.get("mfg_note"):
        rows.append({
            "key": "mfg",
            "value": str(dev.get("mfg_note") or dev.get("manufacturer_data"))[:48],
        })
    badges = dev.get("recon_badges") or []
    if badges:
        rows.append({"key": "badges", "value": " ".join(str(b) for b in badges[:8])})
    return rows


def _focus_item(
    focus: str,
    online: List[Dict[str, Any]],
    offline: List[Dict[str, Any]],
    online_idx: int,
    offline_idx: int,
) -> Optional[Dict[str, Any]]:
    if focus == "online" and online:
        return online[clamp_idx(online_idx, len(online))]
    if focus == "offline" and offline:
        return offline[clamp_idx(offline_idx, len(offline))]
    if online:
        return online[clamp_idx(online_idx, len(online))]
    if offline:
        return offline[clamp_idx(offline_idx, len(offline))]
    return None


# ---------------------------------------------------------------------------
# WiFi
# ---------------------------------------------------------------------------

def run_embedded_wifi_scan(
    stdscr,
    *,
    iface: str,
    out_path: str = "logs/wifi_scan_selection.json",
    activity_log: Optional[List[str]] = None,
) -> Optional[Dict[str, Any]]:
    """Full-screen embedded WiFi live scan — input-first, infinite until q/A."""
    from core.tui.wifi_scan_external import LiveScanner

    log = activity_log if activity_log is not None else []
    try:
        from core.tui.ui_theme import apply_theme, get_current_theme
        apply_theme(stdscr, theme=get_current_theme())
    except Exception:
        pass

    scanner = LiveScanner(iface, disappeared_timeout=120.0)
    scanner.sort_mode = "stable"
    scanner.start()
    log.append(
        f"[*] Embedded WiFi scan on {iface} — LIVE until q/Ctrl+C "
        f"(↑↓ move · focus shows clients · ENTER mark · A AIO)"
    )

    focus = "online"  # online | offline | clients
    online_idx = offline_idx = clients_idx = 0
    online_id = offline_id = clients_id = ""
    selected: Optional[Dict[str, Any]] = None
    aio = False
    online: List[Dict[str, Any]] = []
    offline: List[Dict[str, Any]] = []
    clients: List[Dict[str, Any]] = []
    msg = "LIVE · catalog ~1 Hz · keys never wait on scan"
    last_poll_t = 0.0
    last_draw_t = 0.0
    exit_loop = False

    def refresh_catalog() -> None:
        nonlocal online, offline, online_idx, offline_idx, online_id, offline_id
        nonlocal clients, clients_idx, clients_id, focus
        on, off = scanner.poll()
        online = list(on or [])
        offline = list(off or [])
        if focus == "online" and not online and offline:
            focus = "offline"
        elif focus == "offline" and not offline and online:
            focus = "online"
        online_idx = _idx_for_id(online, online_id, online_idx)
        offline_idx = _idx_for_id(offline, offline_id, offline_idx)
        if online:
            online_id = _item_id(online[online_idx]) or online_id
        if offline:
            offline_id = _item_id(offline[offline_idx]) or offline_id
        ap = _focus_item(focus, online, offline, online_idx, offline_idx)
        # Clients always follow *focus* AP (not ENTER mark)
        if focus in ("online", "offline"):
            clients = _clients_from_ap(ap)
        clients_idx = _idx_for_id(clients, clients_id, clients_idx)
        if clients:
            clients_id = _item_id(clients[clients_idx]) or clients_id
        if focus == "clients" and not clients:
            focus = "online" if online else "offline"

    def paint() -> None:
        nonlocal last_draw_t
        try:
            h, w = stdscr.getmaxyx()
        except Exception:
            h, w = 24, 80
        # Keep clients panel in sync with focus without full re-poll
        ap = _focus_item(focus, online, offline, online_idx, offline_idx)
        cli = clients
        if focus in ("online", "offline"):
            cli = _clients_from_ap(ap)
        marked = _item_id(selected)
        stdscr.erase()
        body_y = _draw_kfiosa_header(
            stdscr,
            title="WiFi SCAN",
            iface=scanner.iface or iface,
            online_n=len(online),
            offline_n=len(offline),
            err=scanner.last_error or "",
        )
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
                marked_id=marked,
            )
            _draw_table_block(
                stdscr, top=body_y + h_on, height=h_off, width=left_w, x=0,
                title="OFFLINE / SEEN", items=offline, idx=offline_idx,
                row_fmt=format_wifi_offline, focused=(focus == "offline"),
                marked_id=marked,
            )
            _draw_table_block(
                stdscr, top=body_y, height=avail, width=right_w, x=left_w,
                title="CLIENTS (focused AP)", items=cli, idx=clients_idx,
                row_fmt=format_client_row, focused=(focus == "clients"),
            )
        else:
            h_on = max(4, (avail * 6) // 10)
            h_off = max(3, avail - h_on)
            _draw_table_block(
                stdscr, top=body_y, height=h_on, width=w, x=0,
                title="ONLINE APs", items=online, idx=online_idx,
                row_fmt=format_wifi_online, focused=(focus == "online"),
                marked_id=marked,
            )
            _draw_table_block(
                stdscr, top=body_y + h_on, height=h_off, width=w, x=0,
                title="OFFLINE / SEEN", items=offline, idx=offline_idx,
                row_fmt=format_wifi_offline, focused=(focus == "offline"),
                marked_id=marked,
            )
        detail = detail_for_item(ap or {}, "wifi") if ap else ""
        _safe_add(stdscr, h - 3, 0, "─" * max(1, w - 1), _pair(6), w)
        _safe_add(stdscr, h - 2, 0, detail, _pair(4), w)
        n_cur = (
            len(online) if focus == "online"
            else len(offline) if focus == "offline"
            else len(cli)
        )
        i_cur = (
            online_idx if focus == "online"
            else offline_idx if focus == "offline"
            else clients_idx
        )
        foot = (
            f" {HELP_WIFI}  ·  focus={focus} "
            f"#{i_cur + 1}/{n_cur or 0}  ·  {msg}"
        )
        _safe_add(stdscr, h - 1, 0, foot, _pair(3) | curses.A_BOLD, w)
        try:
            stdscr.refresh()
        except curses.error:
            pass
        last_draw_t = time.monotonic()

    def handle_key(ch: int) -> bool:
        """Return True to exit loop."""
        nonlocal focus, online_idx, offline_idx, clients_idx
        nonlocal online_id, offline_id, clients_id, selected, aio, msg, scanner
        nonlocal clients

        if ch in (3,):  # Ctrl+C
            msg = "Ctrl+C — leaving live scan"
            return True
        order = ["online", "offline", "clients"]
        if ch in (9, ord("\t"), curses.KEY_RIGHT):
            focus = order[(order.index(focus) + 1) % len(order)]
            msg = f"table={focus}"
            return False
        if ch in (curses.KEY_LEFT,):
            focus = order[(order.index(focus) - 1) % len(order)]
            msg = f"table={focus}"
            return False
        if ch in (ord("r"), ord("R")):
            scanner.stop()
            scanner = LiveScanner(iface, disappeared_timeout=120.0)
            scanner.sort_mode = "stable"
            scanner.start()
            msg = "rescanning… still LIVE"
            return False
        if ch in (ord("a"), ord("A")):
            items = online if focus == "online" else offline
            idx = online_idx if focus == "online" else offline_idx
            if items:
                selected = dict(items[clamp_idx(idx, len(items))])
                aio = True
                return True
            if selected:
                aio = True
                return True
            msg = "nothing to AIO-select"
            return False

        items = (
            online if focus == "online"
            else offline if focus == "offline"
            else clients
        )
        n = len(items)
        idx = (
            online_idx if focus == "online"
            else offline_idx if focus == "offline"
            else clients_idx
        )

        if 0 <= ch < 256 and chr(ch).isdigit() and chr(ch) != "0":
            jump = int(chr(ch)) - 1
            if items and 0 <= jump < len(items):
                if focus == "online":
                    online_idx, online_id = jump, _item_id(items[jump])
                    clients = _clients_from_ap(items[jump])
                    clients_idx, clients_id = 0, ""
                elif focus == "offline":
                    offline_idx, offline_id = jump, _item_id(items[jump])
                    clients = _clients_from_ap(items[jump])
                    clients_idx, clients_id = 0, ""
                else:
                    clients_idx, clients_id = jump, _item_id(items[jump])
                msg = f"jump #{jump + 1}"
            return False
        if ch in (curses.KEY_HOME, ord("g")):
            if focus == "online":
                online_idx = 0
                online_id = _item_id(online[0]) if online else ""
                clients = _clients_from_ap(online[0] if online else None)
                clients_idx, clients_id = 0, ""
            elif focus == "offline":
                offline_idx = 0
                offline_id = _item_id(offline[0]) if offline else ""
                clients = _clients_from_ap(offline[0] if offline else None)
                clients_idx, clients_id = 0, ""
            else:
                clients_idx = 0
                clients_id = _item_id(clients[0]) if clients else ""
            msg = "first"
            return False
        if ch in (curses.KEY_END, ord("G")):
            if focus == "online" and online:
                online_idx = len(online) - 1
                online_id = _item_id(online[online_idx])
                clients = _clients_from_ap(online[online_idx])
                clients_idx, clients_id = 0, ""
            elif focus == "offline" and offline:
                offline_idx = len(offline) - 1
                offline_id = _item_id(offline[offline_idx])
                clients = _clients_from_ap(offline[offline_idx])
                clients_idx, clients_id = 0, ""
            elif clients:
                clients_idx = len(clients) - 1
                clients_id = _item_id(clients[clients_idx])
            msg = "last"
            return False

        if ch in (
            curses.KEY_UP, ord("k"), ord("K"),
            curses.KEY_DOWN, ord("j"), ord("J"),
            curses.KEY_PPAGE, curses.KEY_NPAGE,
        ):
            steps = _drain_nav_burst(stdscr, ch)
            if n > 0:
                new_idx = _move_idx(idx, n, steps)
                if focus == "online":
                    online_idx = new_idx
                    online_id = _item_id(online[online_idx])
                    clients = _clients_from_ap(online[online_idx])
                    clients_idx = 0
                    clients_id = ""
                elif focus == "offline":
                    offline_idx = new_idx
                    offline_id = _item_id(offline[offline_idx])
                    clients = _clients_from_ap(offline[offline_idx])
                    clients_idx = 0
                    clients_id = ""
                else:
                    clients_idx = new_idx
                    clients_id = (
                        _item_id(clients[clients_idx]) if clients else ""
                    )
                msg = f"#{new_idx + 1}/{n}"
            return False

        new_idx, act = handle_nav_key(ch, idx, n)
        if focus == "online":
            online_idx = new_idx
            if online:
                online_id = _item_id(online[online_idx])
        elif focus == "offline":
            offline_idx = new_idx
            if offline:
                offline_id = _item_id(offline[offline_idx])
        else:
            clients_idx = new_idx
            if clients:
                clients_id = _item_id(clients[clients_idx])
        if act == "quit":
            return True
        if act == "back":
            selected = None
            msg = "selection cleared"
            return False
        if act == "select":
            if focus == "clients":
                msg = "select an AP (TAB → ONLINE) — clients follow focus"
                return False
            items2 = online if focus == "online" else offline
            if not items2:
                msg = "no targets"
                return False
            selected = dict(items2[clamp_idx(new_idx, len(items2))])
            msg = (
                f"MARKED {selected.get('ssid') or '<hidden>'} "
                f"[{selected.get('bssid')}] — A=AIO · q=done · still LIVE"
            )
            return False
        return False

    try:
        _prepare_stdscr(stdscr, timeout_ms=KEY_TIMEOUT_MS)
        refresh_catalog()
        paint()
        while not exit_loop:
            # 1) KEYS FIRST — never blocked by scan I/O
            ch = _read_key(stdscr, timeout_ms=KEY_TIMEOUT_MS)
            if ch != -1:
                if handle_key(ch):
                    break
                paint()  # immediate visual feedback
                continue

            # 2) Slow catalog refresh only when idle (no key)
            now = time.monotonic()
            if (now - last_poll_t) >= WIFI_POLL_S:
                refresh_catalog()
                last_poll_t = now
                paint()
            elif (now - last_draw_t) >= IDLE_PAINT_S:
                paint()
    finally:
        try:
            scanner.stop()
        except Exception:
            pass
        try:
            stdscr.keypad(True)
            stdscr.nodelay(True)
            stdscr.timeout(100)
            stdscr.erase()
            stdscr.refresh()
        except Exception:
            pass

    networks_snapshot = list(online) + [
        a for a in offline
        if _item_id(a) not in {_item_id(x) for x in online}
    ]
    if selected:
        selected["interface"] = scanner.iface or iface
        selected["from_external_scan"] = False
        selected["from_embedded_scan"] = True
        selected["aio_attack"] = bool(aio)
        try:
            Path("logs").mkdir(parents=True, exist_ok=True)
            Path(out_path).write_text(
                json.dumps({
                    "selected": selected,
                    "aio_attack": bool(aio),
                    "networks": networks_snapshot or [selected],
                    "disappeared_networks": list(offline),
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
            + (" — AIO" if aio else f" · {len(networks_snapshot)} in catalog")
        )
    else:
        try:
            if networks_snapshot:
                Path("logs").mkdir(parents=True, exist_ok=True)
                Path(out_path).write_text(
                    json.dumps({
                        "selected": None,
                        "aio_attack": False,
                        "networks": networks_snapshot,
                        "disappeared_networks": list(offline),
                        "ts": time.time(),
                        "embedded": True,
                    }, ensure_ascii=False, default=str),
                    encoding="utf-8",
                )
        except Exception:
            pass
        log.append(
            f"[i] Embedded WiFi scan closed"
            f" ({len(networks_snapshot)} AP(s) in catalog, no selection)."
        )
    return selected


# ---------------------------------------------------------------------------
# BLE
# ---------------------------------------------------------------------------

def run_embedded_ble_scan(
    stdscr,
    *,
    adapter: Optional[str] = None,
    out_path: str = "logs/ble_scan_selection.json",
    activity_log: Optional[List[str]] = None,
) -> Optional[Dict[str, Any]]:
    """Full-screen embedded BLE live scan — same layout/feel as WiFi."""
    from core.tui.ble_scan_external import LiveBLEScanner

    log = activity_log if activity_log is not None else []
    try:
        from core.tui.ui_theme import apply_theme, get_current_theme
        apply_theme(stdscr, theme=get_current_theme())
    except Exception:
        pass

    scanner = LiveBLEScanner(
        adapter=adapter, disappeared_timeout=120.0, pulse_s=4,
    )
    scanner.sort_mode = "stable"
    scanner.start()
    log.append(
        f"[*] Embedded BLE scan (adapter={adapter or 'auto'}) — "
        f"LIVE until q/Ctrl+C; focus shows services · ENTER mark · A AIO"
    )

    focus = "online"  # online | offline | detail
    online_idx = offline_idx = detail_idx = 0
    online_id = offline_id = ""
    selected: Optional[Dict[str, Any]] = None
    aio = False
    online: List[Dict[str, Any]] = []
    offline: List[Dict[str, Any]] = []
    detail_rows: List[Dict[str, Any]] = []
    msg = "LIVE · catalog ~1 Hz · keys never wait on scan"
    last_poll_t = 0.0
    last_draw_t = 0.0

    def refresh_catalog() -> None:
        nonlocal online, offline, online_idx, offline_idx, online_id, offline_id
        nonlocal detail_rows, detail_idx, focus
        on, off = scanner.poll()
        online = list(on or [])
        offline = list(off or [])
        if focus == "online" and not online and offline:
            focus = "offline"
        elif focus == "offline" and not offline and online:
            focus = "online"
        online_idx = _idx_for_id(online, online_id, online_idx)
        offline_idx = _idx_for_id(offline, offline_id, offline_idx)
        if online:
            online_id = _item_id(online[online_idx]) or online_id
        if offline:
            offline_id = _item_id(offline[offline_idx]) or offline_id
        dev = _focus_item(focus, online, offline, online_idx, offline_idx)
        if focus in ("online", "offline"):
            detail_rows = _ble_detail_rows(dev)
            detail_idx = clamp_idx(detail_idx, len(detail_rows))
        if focus == "detail" and not detail_rows:
            focus = "online" if online else "offline"

    def paint() -> None:
        nonlocal last_draw_t
        try:
            h, w = stdscr.getmaxyx()
        except Exception:
            h, w = 24, 80
        dev = _focus_item(focus, online, offline, online_idx, offline_idx)
        rows = detail_rows
        if focus in ("online", "offline"):
            rows = _ble_detail_rows(dev)
        marked = _item_id(selected)
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
        if w >= 90:
            left_w = max(40, int(w * 0.58))
            right_w = w - left_w
            h_on = max(4, (avail * 6) // 10)
            h_off = max(3, avail - h_on)
            _draw_table_block(
                stdscr, top=body_y, height=h_on, width=left_w, x=0,
                title="ONLINE DEVICES", items=online, idx=online_idx,
                row_fmt=format_ble_online, focused=(focus == "online"),
                marked_id=marked,
            )
            _draw_table_block(
                stdscr, top=body_y + h_on, height=h_off, width=left_w, x=0,
                title="OFFLINE / SEEN", items=offline, idx=offline_idx,
                row_fmt=format_ble_offline, focused=(focus == "offline"),
                marked_id=marked,
            )
            _draw_table_block(
                stdscr, top=body_y, height=avail, width=right_w, x=left_w,
                title="DETAIL (focused device)", items=rows, idx=detail_idx,
                row_fmt=format_kv_row, focused=(focus == "detail"),
            )
        else:
            h_on = max(4, (avail * 6) // 10)
            h_off = max(3, avail - h_on)
            _draw_table_block(
                stdscr, top=body_y, height=h_on, width=w, x=0,
                title="ONLINE DEVICES", items=online, idx=online_idx,
                row_fmt=format_ble_online, focused=(focus == "online"),
                marked_id=marked,
            )
            _draw_table_block(
                stdscr, top=body_y + h_on, height=h_off, width=w, x=0,
                title="OFFLINE / SEEN", items=offline, idx=offline_idx,
                row_fmt=format_ble_offline, focused=(focus == "offline"),
                marked_id=marked,
            )
        detail = detail_for_item(dev or {}, "ble") if dev else ""
        _safe_add(stdscr, h - 3, 0, "─" * max(1, w - 1), _pair(6), w)
        _safe_add(stdscr, h - 2, 0, detail, _pair(4), w)
        n_cur = (
            len(online) if focus == "online"
            else len(offline) if focus == "offline"
            else len(rows)
        )
        i_cur = (
            online_idx if focus == "online"
            else offline_idx if focus == "offline"
            else detail_idx
        )
        foot = (
            f" {HELP_BLE}  ·  focus={focus} "
            f"#{i_cur + 1}/{n_cur or 0}  ·  {msg}"
        )
        _safe_add(stdscr, h - 1, 0, foot, _pair(3) | curses.A_BOLD, w)
        try:
            stdscr.refresh()
        except curses.error:
            pass
        last_draw_t = time.monotonic()

    def handle_key(ch: int) -> bool:
        nonlocal focus, online_idx, offline_idx, detail_idx
        nonlocal online_id, offline_id, selected, aio, msg, scanner
        nonlocal detail_rows

        if ch in (3,):
            msg = "Ctrl+C — leaving live scan"
            return True
        order = ["online", "offline", "detail"]
        if ch in (9, ord("\t"), curses.KEY_RIGHT):
            focus = order[(order.index(focus) + 1) % len(order)]
            msg = f"table={focus}"
            return False
        if ch in (curses.KEY_LEFT,):
            focus = order[(order.index(focus) - 1) % len(order)]
            msg = f"table={focus}"
            return False
        if ch in (ord("r"), ord("R")):
            scanner.stop()
            scanner = LiveBLEScanner(
                adapter=adapter, disappeared_timeout=120.0, pulse_s=4,
            )
            scanner.sort_mode = "stable"
            scanner.start()
            msg = "rescanning… still LIVE"
            return False
        if ch in (ord("a"), ord("A")):
            items = online if focus == "online" else offline
            idx = online_idx if focus == "online" else offline_idx
            if focus == "detail":
                items = online if online else offline
                idx = online_idx if online else offline_idx
            if items:
                selected = dict(items[clamp_idx(idx, len(items))])
                aio = True
                return True
            if selected:
                aio = True
                return True
            msg = "nothing to select"
            return False

        items = (
            online if focus == "online"
            else offline if focus == "offline"
            else detail_rows
        )
        n = len(items)
        idx = (
            online_idx if focus == "online"
            else offline_idx if focus == "offline"
            else detail_idx
        )

        if 0 <= ch < 256 and chr(ch).isdigit() and chr(ch) != "0":
            jump = int(chr(ch)) - 1
            if items and 0 <= jump < len(items) and focus != "detail":
                if focus == "online":
                    online_idx, online_id = jump, _item_id(items[jump])
                    detail_rows = _ble_detail_rows(items[jump])
                    detail_idx = 0
                else:
                    offline_idx, offline_id = jump, _item_id(items[jump])
                    detail_rows = _ble_detail_rows(items[jump])
                    detail_idx = 0
                msg = f"jump #{jump + 1}"
            return False
        if ch in (curses.KEY_HOME, ord("g")):
            if focus == "online":
                online_idx = 0
                online_id = _item_id(online[0]) if online else ""
            elif focus == "offline":
                offline_idx = 0
                offline_id = _item_id(offline[0]) if offline else ""
            else:
                detail_idx = 0
            msg = "first"
            return False
        if ch in (curses.KEY_END, ord("G")):
            if focus == "online" and online:
                online_idx = len(online) - 1
                online_id = _item_id(online[online_idx])
            elif focus == "offline" and offline:
                offline_idx = len(offline) - 1
                offline_id = _item_id(offline[offline_idx])
            elif detail_rows:
                detail_idx = len(detail_rows) - 1
            msg = "last"
            return False

        if ch in (
            curses.KEY_UP, ord("k"), ord("K"),
            curses.KEY_DOWN, ord("j"), ord("J"),
            curses.KEY_PPAGE, curses.KEY_NPAGE,
        ):
            steps = _drain_nav_burst(stdscr, ch)
            if n > 0:
                new_idx = _move_idx(idx, n, steps)
                if focus == "online":
                    online_idx = new_idx
                    online_id = _item_id(online[online_idx])
                    detail_rows = _ble_detail_rows(online[online_idx])
                    detail_idx = 0
                elif focus == "offline":
                    offline_idx = new_idx
                    offline_id = _item_id(offline[offline_idx])
                    detail_rows = _ble_detail_rows(offline[offline_idx])
                    detail_idx = 0
                else:
                    detail_idx = new_idx
                msg = f"#{new_idx + 1}/{n}"
            return False

        new_idx, act = handle_nav_key(ch, idx, n)
        if focus == "online":
            online_idx = new_idx
            if online:
                online_id = _item_id(online[online_idx])
        elif focus == "offline":
            offline_idx = new_idx
            if offline:
                offline_id = _item_id(offline[offline_idx])
        else:
            detail_idx = new_idx
        if act == "quit":
            return True
        if act == "back":
            selected = None
            msg = "cleared"
            return False
        if act == "select":
            if focus == "detail":
                msg = "select a device (TAB → ONLINE)"
                return False
            items2 = online if focus == "online" else offline
            if not items2:
                msg = "no devices"
                return False
            selected = dict(items2[clamp_idx(new_idx, len(items2))])
            msg = (
                f"MARKED {selected.get('name') or '?'} "
                f"[{selected.get('address')}] — A=AIO · q=done · still LIVE"
            )
            return False
        return False

    try:
        _prepare_stdscr(stdscr, timeout_ms=KEY_TIMEOUT_MS)
        refresh_catalog()
        paint()
        while True:
            ch = _read_key(stdscr, timeout_ms=KEY_TIMEOUT_MS)
            if ch != -1:
                if handle_key(ch):
                    break
                paint()
                continue
            now = time.monotonic()
            if (now - last_poll_t) >= BLE_POLL_S:
                refresh_catalog()
                last_poll_t = now
                paint()
            elif (now - last_draw_t) >= IDLE_PAINT_S:
                paint()
    finally:
        try:
            scanner.stop()
        except Exception:
            pass
        try:
            stdscr.keypad(True)
            stdscr.nodelay(True)
            stdscr.timeout(100)
            stdscr.erase()
            stdscr.refresh()
        except Exception:
            pass

    devices_snapshot = list(online) + [
        d for d in offline
        if _item_id(d) not in {_item_id(x) for x in online}
    ]
    if selected:
        if adapter:
            selected.setdefault("adapter", adapter)
        selected["from_external_scan"] = False
        selected["from_embedded_scan"] = True
        selected["aio_attack"] = bool(aio)
        try:
            Path("logs").mkdir(parents=True, exist_ok=True)
            Path(out_path).write_text(
                json.dumps({
                    "selected": selected,
                    "aio_attack": bool(aio),
                    "devices": devices_snapshot or [selected],
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
            + (" — AIO" if aio else f" · {len(devices_snapshot)} in catalog")
        )
    else:
        try:
            if devices_snapshot:
                Path("logs").mkdir(parents=True, exist_ok=True)
                Path(out_path).write_text(
                    json.dumps({
                        "selected": None,
                        "aio_attack": False,
                        "devices": devices_snapshot,
                        "ts": time.time(),
                        "embedded": True,
                    }, ensure_ascii=False, default=str),
                    encoding="utf-8",
                )
        except Exception:
            pass
        log.append(
            f"[i] Embedded BLE scan closed"
            f" ({len(devices_snapshot)} device(s) in catalog, no selection)."
        )
    return selected


__all__ = [
    "prefer_embedded_scan",
    "_item_id",
    "_idx_for_id",
    "_move_idx",
    "_drain_nav_burst",
    "_clients_from_ap",
    "_ble_detail_rows",
    "run_embedded_wifi_scan",
    "run_embedded_ble_scan",
    "WIFI_POLL_S",
    "BLE_POLL_S",
]
