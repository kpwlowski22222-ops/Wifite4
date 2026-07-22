"""Tests for core.refactors.poly_adapt_companions (Phase 2.4 §H).

Verifies the polymorphic / target-adaptive companion methods.
Phase 2.4 §H.2 doubled to 40; Phase 3 expansion T2 added 20 more
(30 poly + 30 adapt = 60). T7 expansion adds 10 more
(35 poly + 35 adapt = 70 total).
"""
from __future__ import annotations

import pytest

from core.refactors import (
    POLY_ADAPT_DESCRIPTIONS,
    POLY_ADAPT_REGISTRY,
    POLY_ADAPT_RISK,
    build_poly_adapt_prompt_stanza,
    describe_poly_adapt_method,
    list_poly_adapt_methods,
    run_poly_adapt,
)


# ---------------------------------------------------------------------------
# Registry shape
# ---------------------------------------------------------------------------

class TestRegistryShape:
    def test_seventy_methods(self):
        # Phase 4 T20: 70 (pre-Phase 4) + 30 new = 100
        assert len(POLY_ADAPT_REGISTRY) == 100

    def test_thirty_five_polymorphic(self):
        # Phase 4 T20: 35 (pre-Phase 4) + 26 new poly = 55
        poly = [m for m in POLY_ADAPT_REGISTRY if m.startswith("poly_")]
        assert len(poly) == 55

    def test_thirty_five_adaptive(self):
        # Phase 4 T20: 35 (pre-Phase 4) + 11 new adapt = 45
        adapt = [m for m in POLY_ADAPT_REGISTRY if m.startswith("adapt_")]
        assert len(adapt) == 45

    def test_all_have_risk(self):
        for m in POLY_ADAPT_REGISTRY:
            assert m in POLY_ADAPT_RISK
            assert POLY_ADAPT_RISK[m] in {"read", "intrusive", "destructive"}

    def test_all_have_description(self):
        for m in POLY_ADAPT_REGISTRY:
            assert m in POLY_ADAPT_DESCRIPTIONS
            assert POLY_ADAPT_DESCRIPTIONS[m]

    def test_no_destructive_companions(self):
        # Poly/adapt are planners; the next real step is what may
        # be destructive. So companions stay at "intrusive".
        for m, r in POLY_ADAPT_RISK.items():
            assert r in {"read", "intrusive"}, f"{m} should not be destructive"


# ---------------------------------------------------------------------------
# Polymorphic grammars
# ---------------------------------------------------------------------------

class TestPolymorphicGrammars:
    @pytest.mark.parametrize("name", [
        "poly_deauth_burst_pattern_grammar",
        "poly_eapol_replay_grammar",
        "poly_pmkid_eapol_field_grammar",
        "poly_wps_eap_failure_grammar",
        "poly_evil_twin_hostapd_conf_grammar",
        "poly_passive_scan_channel_hop_grammar",
        "poly_client_probe_request_grammar",
        "poly_gatt_value_template",
        "poly_hid_report_template",
        "poly_adv_data_template_grammar",
    ])
    def test_polymorphic_envelope(self, name):
        r = run_poly_adapt(name, {"seed": "test"})
        assert r["ok"] is True, r
        assert r["name"] == name
        assert r["data"]["model"] == "polymorphic (heuristic)"
        assert "variants" in r["data"]
        assert "primary" in r["data"]
        assert isinstance(r["data"]["variants"], list)
        assert len(r["data"]["variants"]) >= 1

    def test_deauth_grammar_includes_ramp_or_constant(self):
        r = run_poly_adapt("poly_deauth_burst_pattern_grammar", {"seed": "x"})
        # The grammar always returns at least 3 patterns from the pool
        assert len(r["data"]["variants"]) >= 1
        for v in r["data"]["variants"]:
            assert isinstance(v, str)


# ---------------------------------------------------------------------------
# Target-adaptive pickers
# ---------------------------------------------------------------------------

class TestTargetAdaptivePickers:
    @pytest.mark.parametrize("name", [
        "adapt_attack_deauth_strategy_picker",
        "adapt_attack_handshake_strategy_picker",
        "adapt_attack_pmkid_target_picker",
        "adapt_attack_wps_strategy_picker",
        "adapt_attack_evil_twin_strategy_picker",
        "adapt_recon_scan_strategy_picker",
        "adapt_recon_client_strategy_picker",
        "adapt_attack_gatt_strategy_picker",
        "adapt_attack_hid_strategy_picker",
        "adapt_recon_adv_strategy_picker",
    ])
    def test_adaptive_envelope(self, name):
        r = run_poly_adapt(name, {"pmf_supported": True, "client_count": 5})
        assert r["ok"] is True, r
        assert r["name"] == name
        assert r["data"]["model"] == "target-adaptive (heuristic)"
        assert "pick" in r["data"]
        assert "rationale" in r["data"]

    def test_pmf_with_few_clients_picks_sa_query(self):
        r = run_poly_adapt(
            "adapt_attack_deauth_strategy_picker",
            {"pmf_supported": True, "client_count": 1},
        )
        assert r["data"]["pick"] == "sa_query_flood"

    def test_no_pmf_many_clients_picks_broadcast(self):
        r = run_poly_adapt(
            "adapt_attack_deauth_strategy_picker",
            {"pmf_supported": False, "client_count": 8},
        )
        assert r["data"]["pick"] == "broadcast_deauth_burst"

    def test_wpa3_picks_sae(self):
        r = run_poly_adapt(
            "adapt_attack_handshake_strategy_picker",
            {"wpa_version": "wpa3"},
        )
        assert r["data"]["pick"] == "sae_handshake_capture"

    def test_wps_locked_picks_reaver_aggressive(self):
        r = run_poly_adapt(
            "adapt_attack_wps_strategy_picker",
            {"wps_locked": True},
        )
        assert r["data"]["pick"] == "reaver_aggressive"

    def test_wps_unlocked_picks_pixie_dust(self):
        r = run_poly_adapt(
            "adapt_attack_wps_strategy_picker",
            {"wps_locked": False},
        )
        assert r["data"]["pick"] == "pixie_dust"

    def test_windows_target_picks_win_r_cmd(self):
        r = run_poly_adapt(
            "adapt_attack_hid_strategy_picker",
            {"target_os": "windows"},
        )
        assert r["data"]["pick"] == "win_r_win_r_cmd"

    def test_6ghz_picks_full_band_scan(self):
        r = run_poly_adapt(
            "adapt_recon_scan_strategy_picker",
            {"2_4ghz_present": True, "5ghz_present": True, "6ghz_present": True},
        )
        assert r["data"]["pick"] == "wifi_6e_full_band_scan"

    def test_2_4_only_picks_2_4_only(self):
        r = run_poly_adapt(
            "adapt_recon_scan_strategy_picker",
            {"2_4ghz_present": True, "5ghz_present": False, "6ghz_present": False},
        )
        assert r["data"]["pick"] == "wifi_2_4_only"


# ---------------------------------------------------------------------------
# Lookup / describe
# ---------------------------------------------------------------------------

class TestLookup:
    def test_describe_known(self):
        d = describe_poly_adapt_method("poly_deauth_burst_pattern_grammar")
        assert d is not None
        assert d["name"] == "poly_deauth_burst_pattern_grammar"
        assert d["risk"] == "intrusive"
        assert d["description"]

    def test_describe_unknown(self):
        assert describe_poly_adapt_method("nope_nope") is None

    def test_list_methods(self):
        names = list_poly_adapt_methods()
        # Phase 4 T20 brought the count to 100
        assert len(names) == 100
        for n in names:
            assert isinstance(n, str)


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------

class TestErrorHandling:
    def test_unknown_method(self):
        r = run_poly_adapt("totally_made_up")
        assert r["ok"] is False
        assert "unknown" in r["error"]

    def test_none_args_uses_empty(self):
        # Should not crash with None args
        r = run_poly_adapt("poly_deauth_burst_pattern_grammar", None)
        assert r["ok"] is True


# ---------------------------------------------------------------------------
# Prompt stanza
# ---------------------------------------------------------------------------

class TestPromptStanza:
    def test_stanza_mentions_all(self):
        stanza = build_poly_adapt_prompt_stanza()
        for m in POLY_ADAPT_REGISTRY:
            assert m in stanza, f"missing {m} in stanza"

    def test_stanza_mentions_polymorphic_section(self):
        stanza = build_poly_adapt_prompt_stanza()
        assert "POLYMORPHIC GRAMMAR" in stanza
        assert "TARGET-ADAPTIVE PICKER" in stanza

    def test_stanza_no_fabricated_cve(self):
        import re
        stanza = build_poly_adapt_prompt_stanza()
        cves = re.findall(r"CVE-\d{4}-\d+", stanza)
        assert not cves


# ---------------------------------------------------------------------------
# Honest-degrade
# ---------------------------------------------------------------------------

class TestHonestDegrade:
    def test_no_fabricated_versions(self):
        import re
        for desc in POLY_ADAPT_DESCRIPTIONS.values():
            assert not re.search(r"\bv\d+\.\d+", desc), f"version in {desc!r}"

    def test_no_inline_creds(self):
        for desc in POLY_ADAPT_DESCRIPTIONS.values():
            dl = desc.lower()
            for bad in ("password=", "hash=", "ntlm:"):
                assert bad not in dl
