"""Desktop automation surface for KFIOSA.

Integrates `holo-desktop-cli` (H Company Holo3) so the chain / AI can
drive real desktop apps for tool setup and model management — always
behind the operator ACCEPT gate.
"""
from __future__ import annotations

from .holo_agent import (
    HoloDesktopBridge,
    build_desktop_task,
    holo_status,
    run_holo_task,
    stop_holo,
)

__all__ = [
    "HoloDesktopBridge",
    "build_desktop_task",
    "holo_status",
    "run_holo_task",
    "stop_holo",
]
