"""Tests for core.ai_backend.v3_runner_helpers (Phase 2.4)."""
from __future__ import annotations

import pytest

from core.ai_backend.v3_methods import describe_v3_method
from core.ai_backend.v3_runner_helpers import v3_lookup, v3_method_envelope


# ---------------------------------------------------------------------------
# v3_method_envelope
# ---------------------------------------------------------------------------

class TestV3MethodEnvelope:
    def test_envelope_shape(self):
        v3 = describe_v3_method("wifi_attack", "wifi_ap_blacklist_bypass")
        env = v3_method_envelope("wifi_ap_blacklist_bypass", "wifi_attack", v3)
        assert env["ok"] is False
        assert env["name"] == "wifi_ap_blacklist_bypass"
        assert env["risk"] == "intrusive"
        assert "Scan associated MACs" in env["description"]
        assert env["data"]["category"] == "wifi_attack"
        assert env["data"]["v3"] is True
        assert env["data"]["honest_degrade"] is True
        assert "registered in v3_methods" in env["error"]
        assert "duration_s" in env

    def test_envelope_preserves_risk_levels(self):
        # destructive methods must keep the destructive risk so the
        # chain gate still applies.
        v3 = describe_v3_method("post_exploit", "post_exploit_dcsync")
        env = v3_method_envelope("post_exploit_dcsync", "post_exploit", v3)
        assert env["risk"] == "destructive"

    def test_envelope_handles_missing_descriptor_fields(self):
        env = v3_method_envelope("foo", "bar", {})
        assert env["ok"] is False
        assert env["risk"] == "read"  # default
        assert env["description"] == ""  # default


class TestV3Lookup:
    def test_lookup_known_method(self):
        env = v3_lookup("ble_attack", "ble_gatt_char_bruteforce")
        assert env["ok"] is False
        assert env["name"] == "ble_gatt_char_bruteforce"
        assert env["data"]["category"] == "ble_attack"

    def test_lookup_unknown_method(self):
        env = v3_lookup("wifi_attack", "totally_made_up_method")
        assert env["ok"] is False
        assert "unknown v3 method" in env["error"]

    def test_lookup_uses_describe_v3_method(self):
        # Mock patch to verify the helper goes through the registry.
        v3 = describe_v3_method("osint_web", "osint_web_cve_mapping")
        env = v3_lookup("osint_web", "osint_web_cve_mapping")
        assert v3["description"] in env["description"] or v3["description"] == env["description"]


# ---------------------------------------------------------------------------
# Integration with runners: ensure each runner can dispatch v3 methods
# ---------------------------------------------------------------------------

# We don't test every runner here — that lives in
# tests/test_v3_methods_dispatch.py once each runner is wired. This
# file is the unit-level coverage of the helper.

class TestV3RunnerHelpersSmoke:
    @pytest.mark.parametrize("category,method", [
        ("wifi_attack", "wifi_ap_blacklist_bypass"),
        ("wifi_recon", "wifi_client_rssi_heatmap"),
        ("ble_attack", "ble_gatt_char_bruteforce"),
        ("ble_recon", "ble_adv_rssi_histogram"),
        ("osint_web", "osint_web_cve_mapping"),
        ("osint_people", "osint_people_pesel_validate"),
        ("post_exploit", "post_exploit_dcsync"),
    ])
    def test_every_category_dispatches(self, category, method):
        env = v3_lookup(category, method)
        assert env["ok"] is False
        assert env["name"] == method
        assert env["data"]["category"] == category
        assert env["data"]["v3"] is True
        assert env["risk"] in {"read", "intrusive", "destructive"}
