#!/usr/bin/env python3
"""
KFIOSA TUI Theme Engine
========================
Centralised palette, spacing, and layout constants for all TUI screens.

Two built-in palettes:
  - ``STANDARD``   : Full-colour scheme with role-semantic colours.
  - ``FOCUS_MODE`` : Minimal 2-accent ADHD-friendly palette. Only cyan
                     (action/primary) and amber/white (status) survive;
                     everything else renders in muted grey tones.

Usage
-----
    from core.tui.ui_theme import UITheme, apply_theme, FOCUS_MODE

    # In dashboard setup:
    apply_theme(stdscr, theme=UITheme.FOCUS_MODE)

    # In any screen draw loop:
    from core.tui.ui_theme import PAIR, LABEL_SUCCESS, LABEL_ERROR
    stdscr.attron(curses.color_pair(PAIR[LABEL_SUCCESS]))

Pair ID layout (1-16, stable across both palettes)
---------------------------------------------------
  1  SUCCESS   — green (standard) / cyan  (focus)
  2  DANGER    — red   (standard) / white (focus)
  3  WARN      — amber (standard) / amber (focus)
  4  INFO      — cyan  (standard) / cyan  (focus)
  5  ACCENT    — magenta (standard) / muted-white (focus)
  6  MUTED     — white (standard) / dark-grey (focus)
  7  HEADER    — bright-white + black bg (standard) / white + black bg (focus)
  8  SELECTED  — cyan fg + black bg (standard) / white fg + black bg (focus)
  9  CRITICAL  — red fg + black bg (both)

These symbolic names are exposed as module-level constants so callers
do **not** hardcode magic integers.
"""

from __future__ import annotations

import curses
import logging
import os
from enum import IntEnum
from typing import Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Symbolic pair identifiers  (stable integers usable as curses pair IDs)
# ---------------------------------------------------------------------------
class ThemePair(IntEnum):
    SUCCESS = 1   # [+] OK, test pass, connection success
    DANGER = 2    # [!] Error, alarm, crack found
    WARN = 3      # [*] Warning, in-progress, caution
    INFO = 4      # [i] Informational, secondary detail
    ACCENT = 5    # banner, logo, decorative highlight
    MUTED = 6     # low-priority text, secondary labels
    HEADER = 7    # top-bar / section header foreground
    SELECTED = 8  # currently highlighted menu item
    CRITICAL = 9  # critical alert — used sparingly


# Convenience aliases so callers can write PAIR[LABEL_SUCCESS]
LABEL_SUCCESS = ThemePair.SUCCESS
LABEL_DANGER = ThemePair.DANGER
LABEL_WARN = ThemePair.WARN
LABEL_INFO = ThemePair.INFO
LABEL_ACCENT = ThemePair.ACCENT
LABEL_MUTED = ThemePair.MUTED
LABEL_HEADER = ThemePair.HEADER
LABEL_SELECTED = ThemePair.SELECTED
LABEL_CRITICAL = ThemePair.CRITICAL

PAIR = {p: int(p) for p in ThemePair}


class UITheme:
    """Available palettes. Pass one to ``apply_theme()``."""
    STANDARD = "standard"
    FOCUS_MODE = "focus"


# ---------------------------------------------------------------------------
# Internal palette definitions
# ---------------------------------------------------------------------------
#  Each entry: (fg_color_constant, bg_color_constant)
#  Use -1 for default terminal fg/bg.
_STANDARD_PAIRS = {
    ThemePair.SUCCESS: (curses.COLOR_GREEN, -1),
    ThemePair.DANGER: (curses.COLOR_RED, -1),
    ThemePair.WARN: (curses.COLOR_YELLOW, -1),
    ThemePair.INFO: (curses.COLOR_CYAN, -1),
    ThemePair.ACCENT: (curses.COLOR_MAGENTA, -1),
    ThemePair.MUTED: (curses.COLOR_WHITE, -1),
    ThemePair.HEADER: (curses.COLOR_WHITE, curses.COLOR_BLACK),
    ThemePair.SELECTED: (curses.COLOR_CYAN, curses.COLOR_BLACK),
    ThemePair.CRITICAL: (curses.COLOR_RED, curses.COLOR_BLACK),
}

# Focus Mode: strip non-essential colours.
#  - PRIMARY action cue  → cyan (ThemePair.INFO / ThemePair.SUCCESS)
#  - CRITICAL status cue → bright-white (treated as bold-white via A_BOLD)
#  - Everything else     → default terminal colours (no colour distraction)
_FOCUS_PAIRS = {
    ThemePair.SUCCESS: (curses.COLOR_CYAN, -1),       # cyan = "good" signal
    ThemePair.DANGER: (curses.COLOR_WHITE, -1),        # white bold = alert
    ThemePair.WARN: (curses.COLOR_YELLOW, -1),         # amber kept (critical)
    ThemePair.INFO: (curses.COLOR_CYAN, -1),           # same cyan
    ThemePair.ACCENT: (-1, -1),                        # plain — no decoration
    ThemePair.MUTED: (-1, -1),                         # plain
    ThemePair.HEADER: (curses.COLOR_WHITE, curses.COLOR_BLACK),
    ThemePair.SELECTED: (curses.COLOR_WHITE, curses.COLOR_BLACK),
    ThemePair.CRITICAL: (curses.COLOR_WHITE, curses.COLOR_BLACK),
}


# ---------------------------------------------------------------------------
# Runtime state
# ---------------------------------------------------------------------------
_current_theme: str = UITheme.STANDARD
_theme_applied: bool = False


def get_current_theme() -> str:
    """Return the name of the currently active theme."""
    return _current_theme


def is_focus_mode() -> bool:
    """Return True when Focus Mode (ADHD palette) is active."""
    return _current_theme == UITheme.FOCUS_MODE


def apply_theme(stdscr, theme: str = UITheme.STANDARD) -> bool:
    """Initialise curses colour pairs from the chosen palette.

    Call once after ``curses.wrapper`` / ``curses.start_color()`` is set up.
    Returns True on success, False when the terminal has no colour support.
    """
    global _current_theme, _theme_applied
    _current_theme = theme

    try:
        if not curses.has_colors():
            logger.warning("Terminal has no colour support — theme skipped.")
            return False

        curses.start_color()
        curses.use_default_colors()  # allow -1 = terminal default

        palette = _FOCUS_PAIRS if theme == UITheme.FOCUS_MODE else _STANDARD_PAIRS
        for pair_id, (fg, bg) in palette.items():
            try:
                curses.init_pair(int(pair_id), fg, bg)
            except Exception as e:
                logger.debug("init_pair(%d) failed: %s", int(pair_id), e)

        _theme_applied = True
        return True
    except Exception as e:
        logger.warning("apply_theme failed: %s", e)
        return False


def toggle_focus_mode(stdscr) -> str:
    """Toggle between STANDARD and FOCUS_MODE. Returns the new theme name."""
    new_theme = (
        UITheme.STANDARD if _current_theme == UITheme.FOCUS_MODE
        else UITheme.FOCUS_MODE
    )
    apply_theme(stdscr, theme=new_theme)
    return new_theme


# ---------------------------------------------------------------------------
# Layout / Spacing constants
# ---------------------------------------------------------------------------

# Padding from left edge for main content
CONTENT_X = 2
# Padding from right edge before wrapping
CONTENT_RIGHT_PAD = 2

# Row reserved at the very top for the header bar
HEADER_ROW = 0
# First row available for content below header
CONTENT_START_ROW = 2

# Bottom rows reserved for the status bar + input line
STATUS_BAR_ROW_OFFSET = 2   # n rows from bottom
INPUT_ROW_OFFSET = 1         # 1 row from bottom

# Menu column allocation (in percentage of width)
MENU_WIDTH_FRAC = 0.25       # 25 % of width for nav sidebar
LOG_MAX_LINES = 200          # activity log ring-buffer length

# Focus Mode: minimum header/footer size when sidebar is hidden
FOCUS_HEADER_HEIGHT = 1


# ---------------------------------------------------------------------------
# Drawing helpers
# ---------------------------------------------------------------------------

def attr_for(pair: ThemePair, bold: bool = False) -> int:
    """Return a curses attribute integer for the given semantic pair."""
    attr = curses.color_pair(int(pair))
    if bold:
        attr |= curses.A_BOLD
    return attr


def safe_addstr(
    win,
    y: int,
    x: int,
    text: str,
    attr: int = 0,
    max_width: Optional[int] = None,
) -> None:
    """Write ``text`` at (y, x) without raising on boundary errors.

    Truncates text to fit within ``max_width`` (or window width) with a '…'
    ellipsis suffix so the caller never has to worry about clipping.
    """
    try:
        height, width = win.getmaxyx()
        if y < 0 or y >= height or x < 0 or x >= width:
            return
        available = (max_width or (width - x)) - 1
        if available <= 0:
            return
        if len(text) > available:
            text = text[: available - 1] + "…"
        if attr:
            win.attron(attr)
        win.addstr(y, x, text)
        if attr:
            win.attroff(attr)
    except curses.error:
        pass


def draw_header(win, title: str, right_label: str = "") -> None:
    """Draw a full-width header bar on row 0."""
    try:
        height, width = win.getmaxyx()
        attr = attr_for(ThemePair.HEADER, bold=True)
        win.attron(attr)
        win.addstr(0, 0, " " * (width - 1))
        win.attroff(attr)
        safe_addstr(win, 0, CONTENT_X, f"  {title}", attr,
                    max_width=width // 2)
        if right_label:
            rx = width - len(right_label) - CONTENT_RIGHT_PAD - 1
            if rx > 0:
                safe_addstr(win, 0, rx, right_label, attr)
    except curses.error:
        pass


def draw_status_bar(win, message: str, pair: ThemePair = ThemePair.MUTED) -> None:
    """Draw a status bar on the second-to-last row."""
    try:
        height, width = win.getmaxyx()
        y = height - STATUS_BAR_ROW_OFFSET
        if y < 1:
            return
        attr = attr_for(pair)
        win.attron(attr)
        win.addstr(y, 0, " " * (width - 1))
        win.attroff(attr)
        safe_addstr(win, y, CONTENT_X, message, attr, max_width=width - 4)
    except curses.error:
        pass


def draw_focus_badge(win) -> None:
    """Draw a subtle [FOCUS] badge in the header when Focus Mode is active."""
    if not is_focus_mode():
        return
    try:
        _, width = win.getmaxyx()
        badge = " [FOCUS] "
        x = width - len(badge) - 1
        if x > 0:
            attr = attr_for(ThemePair.WARN, bold=True)
            safe_addstr(win, 0, x, badge, attr)
    except curses.error:
        pass


# ---------------------------------------------------------------------------
# Env / persistence helpers
# ---------------------------------------------------------------------------

_THEME_ENV_VAR = "KFIOSA_FOCUS_MODE"


def load_theme_from_env() -> str:
    """Read the KFIOSA_FOCUS_MODE environment variable.

    Set KFIOSA_FOCUS_MODE=1 to start in Focus Mode.
    """
    if os.getenv(_THEME_ENV_VAR, "0").strip() in ("1", "true", "yes"):
        return UITheme.FOCUS_MODE
    return UITheme.STANDARD


def save_theme_to_env(theme: str) -> None:
    """Persist the current theme choice in the process environment."""
    os.environ[_THEME_ENV_VAR] = "1" if theme == UITheme.FOCUS_MODE else "0"
