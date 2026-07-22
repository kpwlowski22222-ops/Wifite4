"""Revival tests for ``wifi_offensive_ai/``.

The revived tree is a thin re-export shim around ``core.modules``. These
tests assert the import paths work, ``AIEngine`` instantiates, and the
``OffensiveAutomationsFacade`` composes the canonical classes.

No network, no subprocess, no real model loading.
"""

import pytest


def test_engine_imports():
    from wifi_offensive_ai.core.engine import AIEngine
    assert AIEngine is not None
    assert AIEngine.__module__ == "wifi_offensive_ai.core.engine"


def test_engine_instantiates_with_minimal_config():
    from wifi_offensive_ai.core.engine import AIEngine
    ai = AIEngine({})
    status = ai.get_model_status()
    assert status["loaded_models"] == []
    assert status["training_examples"] == 0
    assert status["decision_history"] == 0
    # ``model_path`` should be the default (./models) — Path-typed.
    assert "models" in str(status["model_path"])


def test_offensive_automations_re_exports_canonical_classes():
    from wifi_offensive_ai.modules.offensive_automations import (
        KaliToolsIntegration, OffensiveAutomationsFacade, PolymorphicEvasion,
    )
    # The classes are the *same objects* as the canonical ones in
    # ``core.modules`` — no parallel re-implementation.
    from core.modules.kali_tools_integration import KaliToolsIntegration as K
    from core.modules.polymorphic_evasion import PolymorphicEvasion as P
    assert KaliToolsIntegration is K
    assert PolymorphicEvasion is P


def test_offensive_automations_facade_composes_canonical_classes():
    from wifi_offensive_ai.modules.offensive_automations import (
        OffensiveAutomationsFacade,
    )
    facade = OffensiveAutomationsFacade({})
    # ``kali`` and ``polymorphic`` are the canonical instances.
    assert facade.kali.__class__.__module__ == "core.modules.kali_tools_integration"
    assert facade.polymorphic.__class__.__module__ == "core.modules.polymorphic_evasion"


def test_offensive_automations_all_exports():
    from wifi_offensive_ai.modules import offensive_automations
    expected = {"KaliToolsIntegration", "PolymorphicEvasion",
                "OffensiveAutomationsFacade"}
    assert expected.issubset(set(offensive_automations.__all__))


def test_engine_decision_rule_based_handles_missing_features():
    import asyncio
    from wifi_offensive_ai.core.engine import AIEngine
    ai = AIEngine({})
    # Minimal context: no target, no network. Should fall through
    # gracefully to the rule-based branch.
    decision = asyncio.run(ai.make_decision({}))
    assert decision["method"] == "rule_based"
    assert "action" in decision
    assert "confidence" in decision
    assert 0.0 <= decision["confidence"] <= 1.0


def test_engine_plan_attack_sequence_for_wpa2():
    import asyncio
    from wifi_offensive_ai.core.engine import AIEngine
    ai = AIEngine({})
    target = {
        "ssid": "TestNet", "bssid": "AA:BB:CC:DD:EE:FF",
        "encryption": "wpa2", "channel": 6,
        "signal_strength": "-45dBm",
    }
    plan = asyncio.run(ai.plan_attack_sequence(target, []))
    assert plan["target"] == "TestNet"
    assert any(p["phase"] == "reconnaissance" for p in plan["phases"])
    # wpa2 should include a handshake phase + crack phase
    phases = {p["phase"] for p in plan["phases"]}
    assert "handshake" in phases
    assert "crack" in phases
    assert 0.0 < plan["success_probability"] <= 1.0
