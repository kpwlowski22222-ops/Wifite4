"""core.c2 — authorized-lab C2 beacon (HTTP/HTTPS/DNS/TCP) + TUI/PTY
executor for cloned C2 frameworks (Sliver, Empire, Havoc, Merlin,
Covenant, Mythic, Adaptix, Villain).

AUTHORIZED LAB USE ONLY. No steganography, no domain fronting against
real CDNs, no anti-forensics — those are informational plan text only,
never implemented here.
"""

from .lab_beacon import LabBeacon, LabBeaconServer  # noqa: F401
from . import lab_beacon  # noqa: F401
from .executor import (  # noqa: F401
    C2Executor,
    C2FrameworkSpec,
    C2_FRAMEWORKS,
    list_frameworks,
    run_c2_framework,
)
from . import executor as _executor_mod  # noqa: F401

__all__ = [
    "LabBeacon",
    "LabBeaconServer",
    "lab_beacon",
    "C2Executor",
    "C2FrameworkSpec",
    "C2_FRAMEWORKS",
    "list_frameworks",
    "run_c2_framework",
    "executor",
]
