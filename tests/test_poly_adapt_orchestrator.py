"""Tests for poly_adapt orchestrator dispatch (Phase 2.4 §H)."""
from __future__ import annotations

import pytest


class TestPolyAdaptOrchestratorDispatch:
    def _seed(self):
        return {"executed": [], "access": {}}

    def test_dispatch_poly_adapt_deauth(self):
        from core.orchestrator.autonomous_orchestrator import (
            AutonomousOrchestrator,
        )
        orch = AutonomousOrchestrator()
        report = self._seed()
        step = {
            "action": "poly_adapt",
            "args": {
                "method": "poly_deauth_burst_pattern_grammar",
                "bssid": "aa:bb:cc:dd:ee:ff",
            },
        }
        orch._dispatch_poly_adapt(step, {"access": {}}, report)
        assert len(report["executed"]) == 1
        entry = report["executed"][0]
        assert entry["action"] == "poly_adapt"
        assert entry["result"]["ok"] is True
        assert entry["result"]["data"]["model"] == "polymorphic (heuristic)"

    def test_dispatch_poly_adapt_adaptive_picker(self):
        from core.orchestrator.autonomous_orchestrator import (
            AutonomousOrchestrator,
        )
        orch = AutonomousOrchestrator()
        report = self._seed()
        step = {
            "action": "poly_adapt",
            "args": {
                "method": "adapt_attack_wps_strategy_picker",
                "wps_locked": True,
            },
        }
        orch._dispatch_poly_adapt(step, {"access": {}}, report)
        entry = report["executed"][0]
        assert entry["result"]["ok"] is True
        assert entry["result"]["data"]["pick"] == "reaver_aggressive"

    def test_dispatch_unknown_method(self):
        from core.orchestrator.autonomous_orchestrator import (
            AutonomousOrchestrator,
        )
        orch = AutonomousOrchestrator()
        report = self._seed()
        step = {
            "action": "poly_adapt",
            "args": {"method": "totally_made_up"},
        }
        orch._dispatch_poly_adapt(step, {"access": {}}, report)
        entry = report["executed"][0]
        assert entry["result"]["ok"] is False
        assert "unknown" in entry["result"]["error"]

    def test_dispatch_missing_method(self):
        from core.orchestrator.autonomous_orchestrator import (
            AutonomousOrchestrator,
        )
        orch = AutonomousOrchestrator()
        report = self._seed()
        step = {"action": "poly_adapt", "args": {}}
        orch._dispatch_poly_adapt(step, {"access": {}}, report)
        entry = report["executed"][0]
        assert entry["result"]["ok"] is False
        assert "missing" in entry["result"]["error"]

    def test_dispatch_uses_step_name_fallback(self):
        # When args.method is missing, fall back to step["name"]
        from core.orchestrator.autonomous_orchestrator import (
            AutonomousOrchestrator,
        )
        orch = AutonomousOrchestrator()
        report = self._seed()
        step = {
            "action": "poly_adapt",
            "name": "poly_gatt_value_template",
            "args": {},
        }
        orch._dispatch_poly_adapt(step, {"access": {}}, report)
        entry = report["executed"][0]
        assert entry["result"]["ok"] is True
        assert entry["method"] == "poly_gatt_value_template"

    def test_dispatch_top_level_method(self):
        from core.orchestrator.autonomous_orchestrator import (
            AutonomousOrchestrator,
        )
        orch = AutonomousOrchestrator()
        report = self._seed()
        step = {
            "action": "poly_adapt",
            "method": "poly_hid_report_template",
            "args": {},
        }
        orch._dispatch_poly_adapt(step, {"access": {}}, report)
        entry = report["executed"][0]
        assert entry["result"]["ok"] is True
        assert entry["method"] == "poly_hid_report_template"
