#!/usr/bin/env python3
"""Shared activity-log rendering for dashboard + sub-screens.

Improvements over the old single-tag path:
  * more tag colours ([AIO], [recon], [holo], [plan], [0day], …)
  * optional HH:MM:SS timestamps
  * soft word-wrap so long engagement lines stay readable
  * scroll offset (0 = follow newest / tail)
  * ring-buffer cap so the TUI never grows without bound
  * safe curses writes (no crash on tiny terminals)
"""
from __future__ import annotations

import curses
import re
import time
from typing import Any, List, Optional, Sequence, Tuple

# Max lines kept in the shared activity_log list
MAX_ACTIVITY_LINES = 2000

# (regex or exact prefix matcher, color_pair_id, bold)
# Pair IDs match ui_theme ThemePair (1=ok, 2=err, 3=warn, 4=info, 5=accent, 6=muted)
_TAG_RULES: Tuple[Tuple[str, int, bool], ...] = (
    (r"^\[\+\]", 1, True),          # success
    (r"^\[!\]", 2, True),          # error
    (r"^\[\*\]", 3, True),         # progress / warn
    (r"^\[i\]", 4, True),          # info
    (r"^\[AIO\]", 5, True),        # AIO attack
    (r"^\[plan\]", 4, False),
    (r"^\[recon\]", 3, False),
    (r"^\[holo\]", 5, False),
    (r"^\[0day", 5, True),
    (r"^\[people\]", 4, False),
    (r"^\[web\]", 4, False),
    (r"^\[post\]", 3, False),
    (r"^\[poly\]", 5, False),
    (r"^\[CVE", 3, True),
    (r"^\[EXPLOIT", 2, True),
    (r"^===", 5, True),            # section banners
    (r"^  ·", 6, False),           # indented bullets
    (r"^  ", 6, False),
)

_COMPILED = [(re.compile(pat, re.I), pair, bold) for pat, pair, bold in _TAG_RULES]

# Leading timestamp we may inject: "12:34:56 "
_TS_RE = re.compile(r"^(\d{2}:\d{2}:\d{2})\s+(.*)$")


def now_ts() -> str:
    return time.strftime("%H:%M:%S")


def append_log(
    activity_log: List[str],
    msg: str,
    *,
    timestamp: bool = True,
    cap: int = MAX_ACTIVITY_LINES,
) -> None:
    """Append one (or multi-line) message, optionally with HH:MM:SS prefix."""
    if msg is None:
        return
    text = str(msg).rstrip("\n")
    if not text:
        return
    prefix = f"{now_ts()} " if timestamp else ""
    for raw in text.splitlines() or [text]:
        line = raw.replace("\t", "    ").rstrip()
        if not line:
            continue
        # Avoid double-stamping if caller already put a clock on the line
        if timestamp and _TS_RE.match(line):
            activity_log.append(line)
        else:
            activity_log.append(prefix + line if timestamp else line)
    # Ring-buffer trim from the front
    if cap > 0 and len(activity_log) > cap:
        del activity_log[: len(activity_log) - cap]


def classify_line(line: str) -> Tuple[int, bool, str, str]:
    """Return ``(pair_id, bold, tag_or_empty, body)``.

    Strips an optional leading timestamp for classification only.
    """
    raw = (line or "").replace("\n", " ").replace("\t", " ")
    ts = ""
    body = raw
    m = _TS_RE.match(raw)
    if m:
        ts, body = m.group(1), m.group(2)

    pair, bold = 6, False
    tag = ""
    for cre, p, b in _COMPILED:
        if cre.search(body):
            pair, bold = p, b
            # Extract a short leading tag token like [+] or [AIO]
            tm = re.match(r"^(\[[^\]]+\])\s*(.*)$", body)
            if tm:
                tag, rest = tm.group(1), tm.group(2)
                body_out = rest
            else:
                body_out = body
            display_prefix = (f"{ts} " if ts else "") + (tag + " " if tag else "")
            return pair, bold, display_prefix.rstrip() + (" " if display_prefix else ""), body_out

    # No tag match
    if ts:
        return pair, bold, f"{ts} ", body
    return pair, bold, "", body


def wrap_text(text: str, width: int) -> List[str]:
    """Soft-wrap *text* to *width* (greedy word wrap; hard-split long tokens)."""
    if width <= 8:
        return [text[: max(1, width)]] if text else [""]
    text = text.replace("\n", " ")
    if len(text) <= width:
        return [text]
    out: List[str] = []
    rest = text
    while rest:
        if len(rest) <= width:
            out.append(rest)
            break
        chunk = rest[:width]
        # Prefer breaking on space
        sp = chunk.rfind(" ")
        if sp >= max(8, width // 3):
            out.append(rest[:sp])
            rest = rest[sp + 1 :].lstrip()
        else:
            out.append(chunk)
            rest = rest[width:]
    return out or [""]


def visible_rows(
    lines: Sequence[str],
    *,
    width: int,
    max_rows: int,
    scroll_from_end: int = 0,
    wrap: bool = True,
) -> Tuple[List[Tuple[int, bool, str, str]], int, int]:
    """Build display rows for the log panel.

    Returns ``(rows, total_wrapped, scroll_from_end_clamped)`` where each
    row is ``(pair, bold, prefix, body)`` ready for drawing.
    """
    if max_rows <= 0 or width <= 4:
        return [], 0, 0

    # Expand to wrapped display lines (newest at end)
    expanded: List[Tuple[int, bool, str, str]] = []
    body_width = max(12, width - 2)
    for line in lines:
        pair, bold, prefix, body = classify_line(str(line))
        pref_w = min(len(prefix), body_width // 2)
        content_w = max(8, body_width - pref_w)
        if wrap:
            chunks = wrap_text(body if body else " ", content_w)
        else:
            chunks = [(body if body else " ")[:content_w]]
        for i, ch in enumerate(chunks):
            if i == 0:
                expanded.append((pair, bold, prefix, ch))
            else:
                # Continuation: indent under body, muted style
                pad = " " * min(len(prefix), 12) if prefix else "  "
                expanded.append((6, False, pad, ch))

    total = len(expanded)
    if total == 0:
        return [], 0, 0

    max_scroll = max(0, total - max_rows)
    scroll = max(0, min(int(scroll_from_end), max_scroll))
    # scroll_from_end=0 → show the last max_rows lines
    end = total - scroll
    start = max(0, end - max_rows)
    return expanded[start:end], total, scroll


def _safe_add(stdscr, y: int, x: int, text: str, attr: int = 0) -> None:
    try:
        h, w = stdscr.getmaxyx()
        if y < 0 or y >= h or x >= w:
            return
        room = w - x - 1
        if room <= 0:
            return
        stdscr.addnstr(y, x, text[:room], room, attr)
    except curses.error:
        pass
    except Exception:
        pass


def draw_activity_log(
    stdscr,
    activity_log: Sequence[str],
    start_y: int,
    max_height: int,
    *,
    scroll_from_end: int = 0,
    wrap: bool = True,
    title: str = "Live story",
    start_x: int = 0,
    panel_width: Optional[int] = None,
) -> int:
    """Draw the activity log panel. Returns the clamped scroll offset used.

    Optional *start_x* / *panel_width* pin the panel to a right-hand column
    (split layout). When omitted, uses the full terminal width.
    """
    try:
        height, term_w = stdscr.getmaxyx()
    except Exception:
        return 0

    sx = max(0, int(start_x or 0))
    width = int(panel_width) if panel_width else max(20, term_w - sx)
    width = max(16, min(width, term_w - sx))

    log_height = min(max_height, height - start_y - 1)
    if log_height <= 1:
        return 0

    # Vertical border for split panel
    if sx > 0:
        try:
            for yy in range(start_y, min(height - 1, start_y + log_height)):
                _safe_add(stdscr, yy, sx, "│", curses.color_pair(6))
        except Exception:
            pass
        content_x = sx + 1
        content_w = max(12, width - 1)
    else:
        content_x = 0
        content_w = width

    # Title row + body rows
    body_rows = max(1, log_height - 1)
    rows, total, scroll = visible_rows(
        list(activity_log),
        width=max(16, content_w - 3),
        max_rows=body_rows,
        scroll_from_end=scroll_from_end,
        wrap=wrap,
    )

    following = scroll == 0
    if total <= body_rows:
        pos_hint = "all"
    elif following:
        pos_hint = "live↓"
    else:
        pos_hint = f"↑{scroll}"
    n_src = len(activity_log)
    header = f" {title} · {n_src} · {pos_hint} · PgUp/PgDn "
    try:
        _safe_add(
            stdscr, start_y, content_x,
            "─" * max(1, content_w - 1),
            curses.color_pair(6),
        )
        _safe_add(
            stdscr, start_y, content_x + 1,
            header[: max(0, content_w - 3)],
            curses.color_pair(4) | curses.A_BOLD,
        )
    except Exception:
        pass

    for i, (pair, bold, prefix, body) in enumerate(rows):
        y = start_y + 1 + i
        if y >= height - 1:
            break
        attr = curses.color_pair(pair)
        if bold:
            attr |= curses.A_BOLD
        x = content_x + 1
        if prefix:
            _safe_add(stdscr, y, x, prefix, attr)
            x += len(prefix)
        body_attr = attr if pair != 6 else curses.color_pair(6)
        _safe_add(stdscr, y, x, body, body_attr)

    if not rows:
        _safe_add(
            stdscr, start_y + 1, content_x + 2,
            "(waiting for the next step…)",
            curses.color_pair(6),
        )

    return scroll


def handle_log_scroll_key(
    key: int,
    scroll_from_end: int,
    *,
    page: int = 5,
) -> Optional[int]:
    """Map keys to a new scroll_from_end, or None if not a log-scroll key.

    * PgUp / Ctrl+B / '['  → older (increase offset from end)
    * PgDn / Ctrl+F / ']'  → newer
    * End / 'G'            → live tail (0)
    * Home / 'g'           → oldest (large offset; clamp later)
    """
    if key in (curses.KEY_PPAGE, 2, ord("[")):  # PgUp, Ctrl+B
        return scroll_from_end + max(1, page)
    if key in (curses.KEY_NPAGE, 6, ord("]")):  # PgDn, Ctrl+F
        return max(0, scroll_from_end - max(1, page))
    if key in (curses.KEY_END, ord("G")):
        return 0
    if key in (curses.KEY_HOME,):
        return 10**9  # clamped by draw/visible_rows
    return None
