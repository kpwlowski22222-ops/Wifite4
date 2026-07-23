"""In-TUI live scan panels — same aesthetics as the main KFIOSA dashboard.

Replaces external xterm/gnome-terminal scan windows with a full-screen
overlay on the shared ``stdscr``:

  * KFIOSA box banner (color_pair 5) + status strip (pair 4)
  * ONLINE / OFFLINE tables with SELECTED reverse highlight (pair 1)
  * Detail strip + help footer matching BaseScreen / ui_theme
  * Live scan runs **infinitely** until q / Ctrl+C (never auto-stops)
  * Keys: ↑↓ j/k · ←→/TAB · 1-9 · ENTER mark · A AIO+exit · r rescan · q/Ctrl+C exit

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
    "↑↓/jk move · ←→/TAB · 1-9 · ENTER mark · A AIO · r rescan · q/Ctrl+C exit · LIVE"
)
HELP_BLE = (
    "↑↓/jk move · ←→/TAB · 1-9 · ENTER mark · A AIO · r rescan · q/Ctrl+C exit · LIVE"
)


def _item_id(item: Optional[Dict[str, Any]]) -> str:
    """Stable identity for cursor tracking across catalog re-sorts."""
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
    """Locate item by stable id; fall back to clamped index."""
    n = len(items)
    if n <= 0:
        return 0
    if item_id:
        for i, it in enumerate(items):
            if _item_id(it) == item_id:
                return i
    return clamp_idx(fallback, n)


def _prepare_stdscr(stdscr, timeout_ms: int = 200) -> None:
    """Enable keypad + non-blocking so arrows/j/k navigate targets."""
    try:
        curses.curs_set(0)
    except Exception:
        pass
    try:
        stdscr.keypad(True)  # map arrow keys → KEY_UP/DOWN (required)
    except Exception:
        pass
    try:
        stdscr.nodelay(True)
        stdscr.timeout(int(timeout_ms))
    except Exception:
        pass


def _read_key(stdscr, timeout_ms: int = 200) -> int:
    """Read one key with ANSI arrow fallback (same as main TUI)."""
    try:
        from core.tui.base_screen import read_curses_key
        return int(read_curses_key(stdscr, timeout_ms=timeout_ms))
    except Exception:
        try:
            return int(stdscr.getch())
        except Exception:
            return -1


def _move_idx(idx: int, n: int, delta: int) -> int:
    """Move selection; wrap at ends so movement always feels responsive."""
    if n <= 0:
        return 0
    return (int(idx) + int(delta)) % n


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
            prefix = "▶ "
        else:
            attr = _pair(6)
            # Number prefix for first 9 rows so 1-9 jump is discoverable
            prefix = f"{i + 1} " if i < 9 else "  "
        _safe_add(stdscr, y, x + 1, (prefix + line), attr, width - 1)


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

    # Keep disappeared APs visible long enough to browse; scan itself never
    # auto-stops — only q / Ctrl+C / AIO exit the overlay.
    scanner = LiveScanner(iface, disappeared_timeout=120.0)
    scanner.start()
    log.append(
        f"[*] Embedded WiFi scan on {iface} (LIVE until q/Ctrl+C; "
        f"↑↓ move · ENTER mark · A AIO)"
    )

    focus = "online"  # online | offline | clients
    online_idx = 0
    offline_idx = 0
    clients_idx = 0
    # Stable ids so re-sort by power/RSSI does not jump the cursor / "stick"
    online_id = ""
    offline_id = ""
    clients_id = ""
    selected: Optional[Dict[str, Any]] = None
    aio = False
    last_online: List[Dict[str, Any]] = []
    last_offline: List[Dict[str, Any]] = []
    online: List[Dict[str, Any]] = []
    offline: List[Dict[str, Any]] = []
    clients: List[Dict[str, Any]] = []
    focus_ap: Optional[Dict[str, Any]] = None
    msg = "LIVE scanning… (never auto-stops)"
    last_poll_t = 0.0
    last_draw_t = 0.0
    last_draw_sig: Optional[Tuple[Any, ...]] = None
    poll_every = 0.35  # CSV/catalog work is expensive — don't thrash
    draw_every = 0.12  # ~8 fps idle paint
    try:
        _prepare_stdscr(stdscr, timeout_ms=80)

        while True:
            now = time.monotonic()
            # Throttle heavy poll(); still service keys every loop
            if (now - last_poll_t) >= poll_every or not last_online and not last_offline:
                online, offline = scanner.poll()
                online = list(online or [])
                offline = list(offline or [])
                last_online, last_offline = online, offline
                last_poll_t = now
            else:
                online, offline = last_online, last_offline

            # Auto-land on a non-empty table so arrows always do something
            if focus == "online" and not online and offline:
                focus = "offline"
            elif focus == "offline" and not offline and online:
                focus = "online"
            # Re-anchor index by BSSID so catalog re-sorts don't freeze movement
            online_idx = _idx_for_id(online, online_id, online_idx)
            offline_idx = _idx_for_id(offline, offline_id, offline_idx)
            if online:
                online_id = _item_id(online[online_idx]) or online_id
            if offline:
                offline_id = _item_id(offline[offline_idx]) or offline_id
            focus_ap = None
            if focus == "online" and online:
                focus_ap = online[online_idx]
            elif focus == "offline" and offline:
                focus_ap = offline[offline_idx]
            elif online:
                focus_ap = online[clamp_idx(online_idx, len(online))]
            clients = []
            if focus_ap:
                raw_cli = focus_ap.get("clients") or []
                for c in raw_cli:
                    if isinstance(c, dict):
                        clients.append(c)
                    else:
                        clients.append({"mac": str(c)})
            clients_idx = _idx_for_id(clients, clients_id, clients_idx)
            if clients:
                clients_id = _item_id(clients[clients_idx]) or clients_id
            if focus == "clients" and not clients:
                focus = "online" if online else "offline"

            draw_sig = (
                focus, online_idx, offline_idx, clients_idx,
                len(online), len(offline), len(clients),
                online_id, offline_id, msg,
                selected.get("bssid") if selected else None,
            )
            need_draw = (
                draw_sig != last_draw_sig
                or (now - last_draw_t) >= draw_every
            )
            if need_draw:
                try:
                    h, w = stdscr.getmaxyx()
                except Exception:
                    h, w = 24, 80
                stdscr.erase()
                enrich_note = ""
                try:
                    enr = getattr(scanner, "_enricher", None)
                    if enr is not None:
                        st = enr.snapshot_stats()
                        enrich_note = (
                            f"recon deep={st.get('deep_ok', 0)}/"
                            f"{st.get('deep_count', 0)} "
                            f"pass={st.get('passive_ticks', 0)}"
                        )
                except Exception:
                    pass
                body_y = _draw_kfiosa_header(
                    stdscr,
                    title="WiFi SCAN",
                    iface=scanner.iface or iface,
                    online_n=len(online),
                    offline_n=len(offline),
                    err=scanner.last_error or enrich_note,
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
                        stdscr, top=body_y + h_on, height=h_off, width=left_w,
                        x=0,
                        title="OFFLINE / SEEN", items=offline, idx=offline_idx,
                        row_fmt=format_wifi_offline,
                        focused=(focus == "offline"),
                    )
                    _draw_table_block(
                        stdscr, top=body_y, height=avail, width=right_w,
                        x=left_w,
                        title="CLIENTS (focus AP)", items=clients,
                        idx=clients_idx,
                        row_fmt=format_client_row,
                        focused=(focus == "clients"),
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
                        row_fmt=format_wifi_offline,
                        focused=(focus == "offline"),
                    )

                detail = (
                    detail_for_item(focus_ap or {}, "wifi") if focus_ap else ""
                )
                _safe_add(stdscr, h - 3, 0, "─" * max(1, w - 1), _pair(6), w)
                _safe_add(stdscr, h - 2, 0, detail, _pair(4), w)
                n_cur = (
                    len(online) if focus == "online"
                    else len(offline) if focus == "offline"
                    else len(clients)
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
                last_draw_t = now
                last_draw_sig = draw_sig

            # Short key poll — never block long enough to feel stuck
            ch = _read_key(stdscr, timeout_ms=50)
            if ch in (-1,):
                continue
            # Force repaint after any key so movement is instant
            last_draw_sig = None

            # Ctrl+C → clean exit (keep marked selection if any)
            if ch in (3,):  # ^C
                msg = "Ctrl+C — leaving live scan"
                break

            order = ["online", "offline", "clients"]
            # TAB / LEFT / RIGHT cycle tables
            if ch in (9, ord("\t"), curses.KEY_RIGHT):
                focus = order[(order.index(focus) + 1) % len(order)]
                msg = f"table={focus}"
                continue
            if ch in (curses.KEY_LEFT,):
                focus = order[(order.index(focus) - 1) % len(order)]
                msg = f"table={focus}"
                continue
            if ch in (ord("r"), ord("R")):
                scanner.stop()
                scanner = LiveScanner(iface, disappeared_timeout=120.0)
                scanner.start()
                msg = "rescanning… (still LIVE until q/Ctrl+C)"
                continue
            if ch in (ord("a"), ord("A")):
                items = online if focus == "online" else offline
                idx = online_idx if focus == "online" else offline_idx
                if items:
                    selected = dict(items[clamp_idx(idx, len(items))])
                    aio = True
                    msg = "AIO — leaving scan"
                    break
                if selected:
                    aio = True
                    msg = "AIO with marked target"
                    break
                msg = "nothing to AIO-select"
                continue

            # 1-9 jump to target in focused list
            if 0 <= ch < 256 and chr(ch).isdigit() and chr(ch) != "0":
                jump = int(chr(ch)) - 1
                items = (
                    online if focus == "online"
                    else offline if focus == "offline"
                    else clients
                )
                if items and 0 <= jump < len(items):
                    if focus == "online":
                        online_idx = jump
                        online_id = _item_id(items[jump])
                    elif focus == "offline":
                        offline_idx = jump
                        offline_id = _item_id(items[jump])
                    else:
                        clients_idx = jump
                        clients_id = _item_id(items[jump])
                    msg = f"jump #{jump + 1}"
                continue

            # Home / End
            if ch in (curses.KEY_HOME, ord("g")):
                if focus == "online":
                    online_idx = 0
                    online_id = _item_id(online[0]) if online else ""
                elif focus == "offline":
                    offline_idx = 0
                    offline_id = _item_id(offline[0]) if offline else ""
                else:
                    clients_idx = 0
                    clients_id = _item_id(clients[0]) if clients else ""
                msg = "first"
                continue
            if ch in (curses.KEY_END, ord("G")):
                if focus == "online" and online:
                    online_idx = len(online) - 1
                    online_id = _item_id(online[online_idx])
                elif focus == "offline" and offline:
                    offline_idx = len(offline) - 1
                    offline_id = _item_id(offline[offline_idx])
                elif clients:
                    clients_idx = len(clients) - 1
                    clients_id = _item_id(clients[clients_idx])
                msg = "last"
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
            # Explicit arrow / vim move (wrap) — never a no-op when n>0
            if ch in (curses.KEY_UP, ord("k"), ord("K")):
                new_idx = _move_idx(idx, n, -1)
                act = None
            elif ch in (curses.KEY_DOWN, ord("j"), ord("J")):
                new_idx = _move_idx(idx, n, +1)
                act = None
            else:
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
                # q / ESC — leave live scan; keep marked selection if any
                break
            if act == "back":
                selected = None
                msg = "selection cleared"
                continue
            if act == "select":
                # ENTER/SPACE: mark target but KEEP scanning (infinite until q/A)
                if focus == "clients":
                    msg = "select an AP (←/→ or TAB to ONLINE)"
                    continue
                items = online if focus == "online" else offline
                if not items:
                    msg = "no targets"
                    continue
                selected = dict(items[clamp_idx(new_idx, len(items))])
                msg = (
                    f"MARKED {selected.get('ssid') or '<hidden>'} "
                    f"[{selected.get('bssid')}] — A=AIO · q=done · still LIVE"
                )
                continue
            if n > 0 and act is None and ch in (
                curses.KEY_UP, curses.KEY_DOWN, ord("j"), ord("k"),
                ord("J"), ord("K"), curses.KEY_PPAGE, curses.KEY_NPAGE,
            ):
                msg = f"#{new_idx + 1}/{n}"
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

    networks_snapshot = list(last_online) + [
        a for a in last_offline
        if _item_id(a) not in {_item_id(x) for x in last_online}
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
                    "disappeared_networks": list(last_offline),
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
        # Still persist catalog so operator can re-open targets later
        try:
            if networks_snapshot:
                Path("logs").mkdir(parents=True, exist_ok=True)
                Path(out_path).write_text(
                    json.dumps({
                        "selected": None,
                        "aio_attack": False,
                        "networks": networks_snapshot,
                        "disappeared_networks": list(last_offline),
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

    scanner = LiveBLEScanner(
        adapter=adapter, disappeared_timeout=120.0, pulse_s=8,
    )
    scanner.start()
    log.append(
        f"[*] Embedded BLE scan (adapter={adapter or 'auto'}) — "
        f"LIVE until q/Ctrl+C; ↑↓ move · ENTER mark · A AIO"
    )

    focus = "online"
    online_idx = 0
    offline_idx = 0
    online_id = ""
    offline_id = ""
    selected: Optional[Dict[str, Any]] = None
    aio = False
    last_online: List[Dict[str, Any]] = []
    last_offline: List[Dict[str, Any]] = []
    online: List[Dict[str, Any]] = []
    offline: List[Dict[str, Any]] = []
    msg = "LIVE scanning… (never auto-stops)"
    last_poll_t = 0.0
    last_draw_t = 0.0
    last_draw_sig: Optional[Tuple[Any, ...]] = None
    poll_every = 0.40
    draw_every = 0.12
    try:
        _prepare_stdscr(stdscr, timeout_ms=80)

        while True:
            now = time.monotonic()
            if (now - last_poll_t) >= poll_every or not last_online and not last_offline:
                online, offline = scanner.poll()
                online = list(online or [])
                offline = list(offline or [])
                last_online, last_offline = online, offline
                last_poll_t = now
            else:
                online, offline = last_online, last_offline
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
            cur = None
            if focus == "online" and online:
                cur = online[online_idx]
            elif focus == "offline" and offline:
                cur = offline[offline_idx]

            draw_sig = (
                focus, online_idx, offline_idx, len(online), len(offline),
                online_id, offline_id, msg,
            )
            need_draw = (
                draw_sig != last_draw_sig or (now - last_draw_t) >= draw_every
            )
            if need_draw:
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
                n_cur = len(online) if focus == "online" else len(offline)
                i_cur = online_idx if focus == "online" else offline_idx
                _safe_add(stdscr, h - 3, 0, "─" * max(1, w - 1), _pair(6), w)
                _safe_add(stdscr, h - 2, 0, detail, _pair(4), w)
                _safe_add(
                    stdscr, h - 1, 0,
                    f" {HELP_BLE}  ·  focus={focus} "
                    f"#{i_cur + 1}/{n_cur or 0}  ·  {msg}",
                    _pair(3) | curses.A_BOLD, w,
                )
                try:
                    stdscr.refresh()
                except curses.error:
                    pass
                last_draw_t = now
                last_draw_sig = draw_sig

            ch = _read_key(stdscr, timeout_ms=50)
            if ch in (-1,):
                continue
            last_draw_sig = None
            if ch in (3,):  # Ctrl+C
                msg = "Ctrl+C — leaving live scan"
                break
            if ch in (9, ord("\t"), curses.KEY_RIGHT, curses.KEY_LEFT):
                focus = "offline" if focus == "online" else "online"
                msg = f"table={focus}"
                continue
            if ch in (ord("r"), ord("R")):
                scanner.stop()
                scanner = LiveBLEScanner(
                    adapter=adapter, disappeared_timeout=120.0, pulse_s=8,
                )
                scanner.start()
                msg = "rescanning… (still LIVE until q/Ctrl+C)"
                continue
            if ch in (ord("a"), ord("A")):
                items = online if focus == "online" else offline
                idx = online_idx if focus == "online" else offline_idx
                if items:
                    selected = dict(items[clamp_idx(idx, len(items))])
                    aio = True
                    break
                if selected:
                    aio = True
                    break
                msg = "nothing to select"
                continue

            items = online if focus == "online" else offline
            idx = online_idx if focus == "online" else offline_idx
            n = len(items)

            if 0 <= ch < 256 and chr(ch).isdigit() and chr(ch) != "0":
                jump = int(chr(ch)) - 1
                if items and 0 <= jump < len(items):
                    if focus == "online":
                        online_idx = jump
                        online_id = _item_id(items[jump])
                    else:
                        offline_idx = jump
                        offline_id = _item_id(items[jump])
                    msg = f"jump #{jump + 1}"
                continue
            if ch in (curses.KEY_HOME, ord("g")):
                if focus == "online":
                    online_idx = 0
                    online_id = _item_id(online[0]) if online else ""
                else:
                    offline_idx = 0
                    offline_id = _item_id(offline[0]) if offline else ""
                msg = "first"
                continue
            if ch in (curses.KEY_END, ord("G")):
                if focus == "online" and online:
                    online_idx = len(online) - 1
                    online_id = _item_id(online[online_idx])
                elif offline:
                    offline_idx = len(offline) - 1
                    offline_id = _item_id(offline[offline_idx])
                msg = "last"
                continue

            if ch in (curses.KEY_UP, ord("k"), ord("K")):
                new_idx = _move_idx(idx, n, -1)
                act = None
            elif ch in (curses.KEY_DOWN, ord("j"), ord("J")):
                new_idx = _move_idx(idx, n, +1)
                act = None
            else:
                new_idx, act = handle_nav_key(ch, idx, n)

            if focus == "online":
                online_idx = new_idx
                if online:
                    online_id = _item_id(online[online_idx])
            else:
                offline_idx = new_idx
                if offline:
                    offline_id = _item_id(offline[offline_idx])
            if act == "quit":
                # leave live scan; keep marked selection if any
                break
            if act == "back":
                selected = None
                msg = "cleared"
                continue
            if act == "select":
                # Mark but keep LIVE scanning
                if not items:
                    msg = "no devices"
                    continue
                selected = dict(items[clamp_idx(new_idx, len(items))])
                msg = (
                    f"MARKED {selected.get('name') or '?'} "
                    f"[{selected.get('address')}] — A=AIO · q=done · still LIVE"
                )
                continue
            if n > 0 and act is None and ch in (
                curses.KEY_UP, curses.KEY_DOWN, ord("j"), ord("k"),
                ord("J"), ord("K"),
            ):
                msg = f"#{new_idx + 1}/{n}"
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

    devices_snapshot = list(last_online) + [
        d for d in last_offline
        if _item_id(d) not in {_item_id(x) for x in last_online}
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
    "run_embedded_wifi_scan",
    "run_embedded_ble_scan",
]
