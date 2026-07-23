"""core.scanners — WiFi / BLE / Kismet scanner surface.

4-touchpoint pattern (the convention established in
``core.post_access_tui`` / ``core.toolbox``):

  1. A registry / module-level constants dict (the single source
     of truth) — currently empty; per-scanner constants live on
     the scanner class itself.
  2. Module-level entrypoint functions:
     - :func:`is_kismet_installed` (Kismet capability probe).
     - :func:`scan_wifi` / :func:`scan_ble` (top-level scan
       helpers — thin wrappers around the scanner classes).
  3. The scanner classes themselves:
     - :class:`WiFiScanner` (legacy airodump/iw-based scanner).
     - :class:`EnhancedWiFiScanner` (ext-wifi v2 wrapper).
     - :class:`EnhancedBLEScanner` (BLE v2 wrapper).
     - :class:`KismetRunner` (Kismet server / client / cap-to-pcap).
     - :class:`KismetRunResult` (the envelope every Kismet call
       returns — never fabricated; real subprocess output only).
  4. Hermetic tests:
     - :mod:`tests.test_wifi_iface_toggle` / :mod:`tests.test_kismet_runner`
     - :mod:`tests.test_extended_wifi_runner` / :mod:`tests.test_extended_ble_runner`.

The ``__all__`` below is the explicit public surface. Adding a
new scanner or capability requires updating this list.
"""
from __future__ import annotations

from .kismet_runner import (
    DEFAULT_CONVERT_TIMEOUT_S,
    DEFAULT_PASSWORD,
    DEFAULT_STARTUP_WAIT_S,
    DEFAULT_USERNAME,
    DEFAULT_WS_URL,
    KISMET_CLIENT_PASSWORD_ENV,
    KISMET_CLIENT_USERNAME_ENV,
    KismetRunResult,
    KismetRunner,
    is_kismet_installed,
)
from .wifi_scanner import (
    WiFiScanner,
)
from .enhanced_wifi_scanner import (
    EnhancedWiFiScanner,
)
from .enhanced_ble_scanner import (
    EnhancedBLEScanner,
)
from .scan_limits import (
    DEFAULT_BLE_SCAN_S,
    DEFAULT_WIFI_SCAN_S,
    MAX_SCAN_S,
    ble_scan_s,
    wifi_scan_s,
)
from .wifi_radio import (
    prep_for_wifi_scan,
    pick_best_scan_iface,
)

# --- Top-level entrypoint helpers (4-touchpoint layer 2) ----
def scan_wifi(*args, **kwargs):
    """Thin wrapper around :class:`WiFiScanner` for symmetry
    with :func:`scan_ble`."""
    return WiFiScanner(*args, **kwargs).scan(**kwargs)


def scan_ble(*args, **kwargs):
    """Thin wrapper around :class:`EnhancedBLEScanner`."""
    return EnhancedBLEScanner(*args, **kwargs).scan(**kwargs)


__all__ = [
    # Kismet
    "DEFAULT_CONVERT_TIMEOUT_S",
    "DEFAULT_PASSWORD",
    "DEFAULT_STARTUP_WAIT_S",
    "DEFAULT_USERNAME",
    "DEFAULT_WS_URL",
    "KISMET_CLIENT_PASSWORD_ENV",
    "KISMET_CLIENT_USERNAME_ENV",
    "KismetRunResult",
    "KismetRunner",
    "is_kismet_installed",
    # Long-range scan limits
    "DEFAULT_BLE_SCAN_S",
    "DEFAULT_WIFI_SCAN_S",
    "MAX_SCAN_S",
    "ble_scan_s",
    "wifi_scan_s",
    # Radio pre-flight
    "prep_for_wifi_scan",
    "pick_best_scan_iface",
    # Scanners
    "WiFiScanner",
    "EnhancedWiFiScanner",
    "EnhancedBLEScanner",
    # Top-level helpers
    "scan_wifi",
    "scan_ble",
]
