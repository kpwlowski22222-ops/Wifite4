"""Tests for v3 method dispatch in core.wifi_attack.runner (Phase 2.4)."""
from __future__ import annotations

import pytest

from core.wifi_attack.runner import WiFiAttackRunner


class TestWifiAttackV3Fallback:
    """The wifi_attack runner must dispatch v3 method names via the
    v3 fallback in addition to the v2 fallback."""

    def test_v3_method_returns_honest_degrade(self):
        runner = WiFiAttackRunner()
        r = runner.run_attack("wifi_ap_blacklist_bypass")
        # v3 fallback → ok=False, with the v3 envelope fields.
        assert r["ok"] is False
        assert r["name"] == "wifi_ap_blacklist_bypass"
        assert r["risk"] == "intrusive"
        assert "Scan associated MACs" in r["description"]
        assert r["data"]["v3"] is True
        assert r["data"]["category"] == "wifi_attack"
        assert "registered in v3_methods" in r["error"]

    def test_v3_destructive_keeps_risk(self):
        runner = WiFiAttackRunner()
        r = runner.run_attack("wifi_cve_exploit_runner")
        assert r["ok"] is False
        assert r["risk"] == "destructive"

    def test_unknown_method_returns_error(self):
        runner = WiFiAttackRunner()
        r = runner.run_attack("totally_made_up_method_zzz")
        assert r["ok"] is False
        assert "unknown attack method" in r["error"]

    def test_v2_ghost_still_returns_honest_degrade(self):
        """The v2 fallback path (without v3) must still work."""
        # The v2 fallback is already covered by
        # tests/test_v2_ghost_catalog_honest_degrade.py. This test
        # only checks that the v2 registry is non-empty.
        from core.ai_backend.expanded_modules import list_v2_methods
        v2_names = list_v2_methods("wifi")
        assert isinstance(v2_names, list)
        assert len(v2_names) > 0

    def test_known_primary_method_still_works(self):
        # Pick a primary method to confirm we don't break the happy path.
        runner = WiFiAttackRunner()
        # packet_injection_test is a primary method, not v2/v3.
        r = runner.run_attack("packet_injection_test")
        # The result shape is "step" — we just assert we got past
        # the v2/v3 fallback (no v3 envelope fields).
        if r.get("data") and r["data"].get("v3"):
            pytest.fail("primary method routed through v3 fallback")
        if r.get("data") and r["data"].get("category") == "wifi_attack":
            pytest.fail("primary method routed through v2 fallback")
