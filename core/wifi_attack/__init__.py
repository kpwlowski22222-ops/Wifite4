"""WiFi attack algorithms + 802.11 frame-crafting helpers.

This package hosts the per-domain WiFi attack runner (``runner.py``) and
the frame-crafting helpers (``frames.py``) that complement
:mod:`core.modules.mt7921e_tools` (the canonical MediaTek MT7922 /
``mt7921e`` injection toolbox).

The ``craft_*`` helpers here build the frame types the historical
``wifi_offensive_ai/wifite4/packet_injection.py`` facade referenced but
never had a real implementation for (``craft_arp_frame``,
``craft_probe_response``, ``craft_auth_frame``, ``craft_assoc_req_frame``).
They follow the exact contract of ``mt7921e_tools.craft_deauth_frame`` /
``craft_fakeauth_frame`` / ``craft_beacon_frame`` / ``craft_cts_frame``:
``{"ok": True, "frame": bytes}`` on success, ``{"ok": False, "error": ...}``
when scapy (or a layer) is unavailable, never raises.
"""
from . import frames, runner  # noqa: F401
from .frames import (  # noqa: F401
    craft_arp_frame,
    craft_assoc_req_frame,
    craft_auth_frame,
    craft_disassoc_frame,
    craft_null_data_frame,
    craft_probe_response,
)
from .runner import (  # noqa: F401
    WIFI_ATTACKS,
    WiFiAttackRunner,
)

__all__ = [
    # Submodules
    "frames",
    "runner",
    # Frame-crafting helpers (4-touchpoint layer 2)
    "craft_arp_frame",
    "craft_assoc_req_frame",
    "craft_auth_frame",
    "craft_disassoc_frame",
    "craft_null_data_frame",
    "craft_probe_response",
    # Runner surface
    "WIFI_ATTACKS",
    "WiFiAttackRunner",
]
