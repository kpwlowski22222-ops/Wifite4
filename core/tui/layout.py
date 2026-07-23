"""Split-panel geometry for the KFIOSA TUI.

Wide terminals (≥90 cols): menu/controls on the left, activity narrative
on the right. Narrow terminals keep a stacked (top/bottom) layout.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Tuple


MIN_SPLIT_WIDTH = 90
MIN_LEFT = 32
MIN_RIGHT = 36


@dataclass(frozen=True)
class Rect:
    y: int
    x: int
    h: int
    w: int


@dataclass(frozen=True)
class Layout:
    mode: str  # "split" | "stack"
    header: Rect
    left: Rect
    right: Rect  # activity panel (or full-width log in stack mode)
    status: Rect


def layout_panels(
    height: int,
    width: int,
    *,
    header_h: int = 5,
    status_h: int = 1,
    right_ratio: float = 0.48,
) -> Layout:
    """Compute panel rectangles for the current terminal size."""
    height = max(8, int(height))
    width = max(40, int(width))
    header_h = max(2, min(header_h, height // 4))
    status_h = 1 if height > 6 else 0
    body_y = header_h
    body_h = max(1, height - header_h - status_h)
    status_y = height - status_h if status_h else height - 1

    header = Rect(0, 0, header_h, width)
    status = Rect(status_y, 0, status_h or 1, width)

    if width >= MIN_SPLIT_WIDTH and body_h >= 6:
        right_w = max(MIN_RIGHT, int(width * right_ratio))
        left_w = width - right_w
        if left_w < MIN_LEFT:
            # Steal from right until left is usable
            left_w = MIN_LEFT
            right_w = width - left_w
        if right_w < MIN_RIGHT:
            # Fall back to stack if both can't fit
            return Layout(
                mode="stack",
                header=header,
                left=Rect(body_y, 0, body_h, width),
                right=Rect(body_y, 0, body_h, width),
                status=status,
            )
        return Layout(
            mode="split",
            header=header,
            left=Rect(body_y, 0, body_h, left_w),
            right=Rect(body_y, left_w, body_h, right_w),
            status=status,
        )

    # Stacked: left = menu area concept (full width upper is managed by caller)
    return Layout(
        mode="stack",
        header=header,
        left=Rect(body_y, 0, body_h, width),
        right=Rect(body_y, 0, body_h, width),
        status=status,
    )


def stack_log_band(
    height: int,
    width: int,
    menu_lines: int,
    *,
    header_h: int = 6,
    status_h: int = 1,
) -> Tuple[int, int]:
    """Legacy-compatible log band under the menu (y, h)."""
    log_y = header_h + max(0, menu_lines) + 1
    log_h = max(3, height - log_y - status_h - 1)
    return log_y, log_h
