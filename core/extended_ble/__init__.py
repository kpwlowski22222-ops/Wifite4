"""Extended BLE 5.x attack runner.

This is touchpoint (4) of the BLE 5.x surface area (modules 80-99 + 101-110
from ``implementacja.txt``). The orchestrator dispatch
(``_dispatch_extended_ble`` in
``core/orchestrator/autonomous_orchestrator.py``) and the MCP factory
wrapper (``_make_extended_ble_wrappers`` in ``core/mcp/tools.py``) wire
it in main — both route through this module's
``EXTENDED_BLE_ATTACKS`` registry and ``run_attack`` entrypoint.

Re-exports the public surface (the runner class, the registry, the
module-level entrypoint) so callers can ``from core.extended_ble import
ExtendedBLERunner, EXTENDED_BLE_ATTACKS, run_attack``.
"""
from __future__ import annotations

from core.extended_ble.runner import (EXTENDED_BLE_ATTACKS,
                                       EXTENDED_BLE_METHODS,
                                       ExtendedBLERunner, run_attack)

__all__ = [
    "EXTENDED_BLE_ATTACKS",
    "EXTENDED_BLE_METHODS",
    "ExtendedBLERunner",
    "run_attack",
]
