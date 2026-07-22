"""core.post_access_tui — auto-spawned external TUI for post-access control.

When a chain step's result flips ``report["access"]["achieved"]`` to
True (captured creds OR a meterpreter ``session_id``), the orchestrator
auto-prompts the operator to open this TUI in a separate window. The
TUI is purpose-built for post-access operations: shell on the target,
file transfer, pivoting, persistence, post-exploit module re-run, and
session switching.

Public surface:
  - ``SessionState`` — active-session descriptor (dataclass + JSON)
  - ``PostAccessRunner`` — action layer (shell, file, network, modules)
  - ``PostAccessScreen`` — curses menu UI (extends core.tui.BaseScreen)
  - ``spawn_post_access_tui`` — orchestrator hook (routes through
    core.utils.external_terminal.launch_real_step)

Safety stance (per project rules, still in effect):
  - The post-access TUI is OPERATOR-GATED at the auto-open point.
  - Every menu action is also ACCEPT-gated before the subprocess runs.
  - Every subprocess is REAL (msfconsole / ssh / scp / ncat). When
    none of the tools are present, the runner degrades honestly.
  - No fabricated session ids, no fabricated cracked PSKs, no fake
    Meterpreter verdicts.
  - Detach (F12/Esc) NEVER kills the main chain; the parent loop is
    independent.
"""
from __future__ import annotations

from .session_state import (
    SessionState,
    TRANSPORT_LOCAL,
    TRANSPORT_MSF,
    TRANSPORT_SSH,
    TRANSPORT_UNKNOWN,
)
from .runner import PostAccessRunner, PostAccessRunnerError
from .screen import PostAccessScreen, MENU, KEY_MAP
from .spawner import (
    spawn_post_access_tui,
    is_post_access_spawnable,
    build_argv,
)
from .ble_panel import (
    BLEDevice,
    BLEService,
    BLECharacteristic,
    BLEPanel,
    BLEPanelClient,
    ble_menu_entry,
    ble_dispatch,
)
from .wifi_panel import (
    WiFiAP,
    WiFiPanel,
    WiFiPanelClient,
    wifi_menu_entry,
    wifi_dispatch,
)
from .network_panel import (
    NetSession,
    NetworkPanel,
    NetworkPanelClient,
    network_menu_entry,
    network_dispatch,
)
from .menu_loop import curses_free_loop
from .full_auto import run_full_auto, default_gate_prompt, FullAutoError
from .rat_ext import (
    SessionCapability as RatSessionCapability,
    RatDashboardServer,
    spawn_rat_dashboard,
    is_rat_dashboard_available,
    BLUETOOTH_CAPABILITIES as RAT_BLE_CAPS,
    NETWORK_CAPABILITIES as RAT_NET_CAPS,
    build_session_roster as build_rat_roster,
)

__all__ = [
    "SessionState",
    "PostAccessRunner",
    "PostAccessRunnerError",
    "PostAccessScreen",
    "MENU",
    "KEY_MAP",
    "spawn_post_access_tui",
    "is_post_access_spawnable",
    "build_argv",
    "BLEDevice",
    "BLEService",
    "BLECharacteristic",
    "BLEPanel",
    "BLEPanelClient",
    "ble_menu_entry",
    "ble_dispatch",
    "WiFiAP",
    "WiFiPanel",
    "WiFiPanelClient",
    "wifi_menu_entry",
    "wifi_dispatch",
    "NetSession",
    "NetworkPanel",
    "NetworkPanelClient",
    "network_menu_entry",
    "network_dispatch",
    "curses_free_loop",
    "run_full_auto",
    "default_gate_prompt",
    "FullAutoError",
    "TRANSPORT_LOCAL",
    "TRANSPORT_MSF",
    "TRANSPORT_SSH",
    "TRANSPORT_UNKNOWN",
    "RatSessionCapability",
    "RatDashboardServer",
    "spawn_rat_dashboard",
    "is_rat_dashboard_available",
    "RAT_BLE_CAPS",
    "RAT_NET_CAPS",
    "build_rat_roster",
]
