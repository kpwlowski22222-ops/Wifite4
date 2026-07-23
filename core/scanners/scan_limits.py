"""Shared scan duration / range limits for WiFi and BLE scanners.

``MAX_*`` is the hard ceiling (1 hour continuous capture).
``DEFAULT_*`` is the long-range default used when callers pass no
duration — long enough to hop the full channel map and hear weak /
intermittent beacons and advertisements.

Override via env (seconds):
  * ``KFIOSA_WIFI_SCAN_S``
  * ``KFIOSA_BLE_SCAN_S``
  * ``KFIOSA_MAX_SCAN_S``  (ceiling for both)
"""
from __future__ import annotations

import os
from typing import Optional


# Hard ceiling: continuous airodump / lescan for up to 1 hour.
# Beyond this, operators should run a dedicated long capture (kismet).
MAX_SCAN_S = 3600

# Long-range defaults: full 2.4/5 GHz hop cycles + weak-AP retention.
DEFAULT_WIFI_SCAN_S = 300   # 5 minutes
DEFAULT_BLE_SCAN_S = 300    # 5 minutes
# Floor so a typo of 0 still does something useful.
MIN_SCAN_S = 2


def _env_int(name: str) -> Optional[int]:
    raw = (os.environ.get(name) or "").strip()
    if not raw:
        return None
    try:
        return int(raw)
    except ValueError:
        return None


def max_scan_s() -> int:
    v = _env_int("KFIOSA_MAX_SCAN_S")
    if v is not None and v >= MIN_SCAN_S:
        return min(v, 24 * 3600)  # absolute safety: 24h
    return MAX_SCAN_S


def clamp_scan_s(seconds: Optional[int], *, default: int) -> int:
    """Clamp a requested scan duration into [MIN, max_scan_s()]."""
    try:
        s = int(seconds) if seconds is not None else int(default)
    except (TypeError, ValueError):
        s = int(default)
    ceiling = max_scan_s()
    if s < MIN_SCAN_S:
        s = MIN_SCAN_S
    if s > ceiling:
        s = ceiling
    return s


def wifi_scan_s(requested: Optional[int] = None) -> int:
    env = _env_int("KFIOSA_WIFI_SCAN_S")
    default = env if env is not None else DEFAULT_WIFI_SCAN_S
    return clamp_scan_s(requested if requested is not None else default,
                        default=default)


def ble_scan_s(requested: Optional[int] = None) -> int:
    env = _env_int("KFIOSA_BLE_SCAN_S")
    default = env if env is not None else DEFAULT_BLE_SCAN_S
    return clamp_scan_s(requested if requested is not None else default,
                        default=default)
