"""
Offensive Automations Module — re-export shim.

The real implementations of ``KaliToolsIntegration`` (28+ Kali tools,
:mod:`core.modules.kali_tools_integration`) and ``PolymorphicEvasion``
(:mod:`core.modules.polymorphic_evasion`) live in :mod:`core.modules`. This
file re-exports them under the historical
``wifi_offensive_ai.modules.offensive_automations`` import path so legacy
callers keep working without parallel re-implementations.

New code should import the canonical classes directly from
``core.modules`` — this shim is for backwards compatibility only.
"""

from core.modules.kali_tools_integration import KaliToolsIntegration
from core.modules.polymorphic_evasion import PolymorphicEvasion

__all__ = [
    "KaliToolsIntegration",
    "PolymorphicEvasion",
    "OffensiveAutomationsFacade",
]


class OffensiveAutomationsFacade:
    """Back-compat surface for callers that used the historical
    ``OffensiveAutomations(config)`` constructor. Composes the canonical
    Kali + Polymorphic modules so old code keeps running unchanged.

    New code should instantiate ``KaliToolsIntegration`` and
    ``PolymorphicEvasion`` directly.
    """

    def __init__(self, config):
        self.kali = KaliToolsIntegration(config)
        self.polymorphic = PolymorphicEvasion(config)
