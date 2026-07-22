"""Tests for the dashboard's CVE-lookup + exploit-generation status pills.

The pills are read-only views on attributes populated by the
orchestrator. The pill strings must:
  - return "" when no data has been pushed yet
  - show hits / empty / failed for the CVE pill
  - show model + cve for the exploit-gen pill
  - never break the status line layout (truncate when long)
"""
from __future__ import annotations

import time

import pytest


def _dash():
    """Build a bare KfiosaDashboard with no curses init."""
    from core.tui.dashboard import KfiosaDashboard
    d = KfiosaDashboard.__new__(KfiosaDashboard)
    d.cve_lookup_status = {}
    d.exploit_gen_status = {}
    return d


class TestCVEPill:
    def test_no_cve_status(self):
        d = _dash()
        assert d._status_cve_lookup() == ""

    def test_cve_hits(self):
        d = _dash()
        d.cve_lookup_status = {
            "last_query": "CVE-2024-1234",
            "last_count": 5,
            "ok": True,
            "last_ts": time.time(),
        }
        out = d._status_cve_lookup()
        assert "CVE" in out
        assert "5 hits" in out
        assert "CVE-2024-1234" in out

    def test_cve_hits_singular(self):
        d = _dash()
        d.cve_lookup_status = {"last_query": "CVE-1", "last_count": 1, "ok": True}
        out = d._status_cve_lookup()
        assert "1 hit " in out
        assert "1 hits" not in out

    def test_cve_empty(self):
        d = _dash()
        d.cve_lookup_status = {"last_query": "CVE-2024-X", "last_count": 0, "ok": True}
        out = d._status_cve_lookup()
        assert "empty" in out
        assert "CVE-2024-X" in out

    def test_cve_failed(self):
        d = _dash()
        d.cve_lookup_status = {"last_query": "CVE-Z", "ok": False}
        out = d._status_cve_lookup()
        assert "failed" in out
        assert "CVE-Z" in out

    def test_cve_truncation(self):
        """A very long query is truncated to keep the pill compact."""
        d = _dash()
        long_q = "CVE-2024-" + "9" * 60
        d.cve_lookup_status = {"last_query": long_q, "last_count": 1, "ok": True}
        out = d._status_cve_lookup()
        # 24-char cap → at most 24 chars before "..." marker.
        assert "..." in out
        # Pill is not the full long string.
        assert long_q not in out


class TestExploitGenPill:
    def test_no_exploit_status(self):
        d = _dash()
        assert d._status_exploit_gen() == ""

    def test_exploit_ok(self):
        d = _dash()
        d.exploit_gen_status = {
            "last_cve_id": "CVE-2024-9999",
            "last_model": "hf.co/DavidAU/Qwen2.5-Coder-22B",
            "ok": True,
        }
        out = d._status_exploit_gen()
        assert "EXPLOIT" in out
        assert "CVE-2024-9999" in out
        assert "hf.co/DavidAU" in out

    def test_exploit_failed(self):
        d = _dash()
        d.exploit_gen_status = {"last_cve_id": "CVE-X", "ok": False}
        out = d._status_exploit_gen()
        assert "failed" in out
        assert "CVE-X" in out

    def test_exploit_model_truncation(self):
        d = _dash()
        d.exploit_gen_status = {
            "last_cve_id": "CVE-1",
            "last_model": "hf.co/" + "verylongmodelname" * 5,
            "ok": True,
        }
        out = d._status_exploit_gen()
        assert "..." in out

    def test_exploit_cve_truncation(self):
        d = _dash()
        d.exploit_gen_status = {
            "last_cve_id": "CVE-" + "9" * 30,
            "last_model": "m",
            "ok": True,
        }
        out = d._status_exploit_gen()
        assert "..." in out


class TestOrchestratorPush:
    def test_orchestrator_push_cve_status(self):
        from core.orchestrator.autonomous_orchestrator import AutonomousOrchestrator
        from tests.fakes import FakeAIBackend

        class FakeDashboard:
            def __init__(self):
                self.cve_lookup_status = {}
                self.exploit_gen_status = {}

        d = FakeDashboard()
        o = AutonomousOrchestrator(
            ai_backend=FakeAIBackend(),
            confirm_fn=lambda p: True,
            on_event=lambda m: None,
            dashboard=d,
        )
        o._push_dashboard_cve_status({
            "last_query": "CVE-2024-X", "last_count": 3, "ok": True,
        })
        assert d.cve_lookup_status.get("last_count") == 3
        assert d.cve_lookup_status.get("last_query") == "CVE-2024-X"

    def test_orchestrator_push_exploit_status(self):
        from core.orchestrator.autonomous_orchestrator import AutonomousOrchestrator
        from tests.fakes import FakeAIBackend

        class FakeDashboard:
            def __init__(self):
                self.cve_lookup_status = {}
                self.exploit_gen_status = {}

        d = FakeDashboard()
        o = AutonomousOrchestrator(
            ai_backend=FakeAIBackend(),
            confirm_fn=lambda p: True,
            on_event=lambda m: None,
            dashboard=d,
        )
        o._push_dashboard_exploit_status({
            "last_cve_id": "CVE-2024-5555",
            "last_model": "hf.co/DavidAU/Qwen2.5-Coder-22B",
            "ok": True,
        })
        assert d.exploit_gen_status.get("last_cve_id") == "CVE-2024-5555"
        assert d.exploit_gen_status.get("ok") is True

    def test_orchestrator_no_dashboard_no_crash(self):
        from core.orchestrator.autonomous_orchestrator import AutonomousOrchestrator
        from tests.fakes import FakeAIBackend

        o = AutonomousOrchestrator(
            ai_backend=FakeAIBackend(),
            confirm_fn=lambda p: True,
            on_event=lambda m: None,
            # no dashboard=
        )
        # Should not raise even though no dashboard is wired.
        o._push_dashboard_cve_status({"ok": True, "last_count": 1})
        o._push_dashboard_exploit_status({"ok": True, "last_cve_id": "CVE-1"})

    def test_dashboard_missing_attributes_no_crash(self):
        """Dashboard without cve_lookup_status / exploit_gen_status
        attributes doesn't crash the orchestrator (best-effort)."""
        from core.orchestrator.autonomous_orchestrator import AutonomousOrchestrator
        from tests.fakes import FakeAIBackend

        class BareDashboard:
            pass  # no cve_lookup_status or exploit_gen_status

        d = BareDashboard()
        o = AutonomousOrchestrator(
            ai_backend=FakeAIBackend(),
            confirm_fn=lambda p: True,
            on_event=lambda m: None,
            dashboard=d,
        )
        # Should not raise.
        o._push_dashboard_cve_status({"ok": True})
        o._push_dashboard_exploit_status({"ok": True})
