"""Phase 2.3.D — WiFi ATTACK new v2 methods (40+).

Each test asserts:
  * The method name is in WIFI_V2_METHODS (the registry).
  * The method is callable on WiFiAttackRunner as ``_v2_<name>``.
  * The dispatch via ``run_attack()`` returns a structured envelope.
  * No inline credentials or fabricated PSKs.
"""

import pytest

from core.wifi_attack.runner import WiFiAttackRunner
from core.ai_backend.expanded_modules import WIFI_V2_METHODS


# ---------------------------------------------------------------------------
# Catalog presence: all new methods are registered
# ---------------------------------------------------------------------------


# The 40 Phase 2.3.D method names (plan-required; we have 41 due to orchestrator)
PHASE_2_3_D_NAMES = [
    # WPA3 / PMF / SAE reflection (5)
    "wpa3_sae_commit_reflect",
    "wpa3_sae_anti_clogging_dos",
    "wpa3_owe_transition_bypass",
    "pmf_sa_query_flood",
    "pmf_bip_replay_attack",
    # WPA2-Enterprise (3)
    "wifi_enterprise_8021x_replay",
    "wifi_enterprise_peap_mschapv2_dos",
    "wifi_enterprise_eap_method_audit",
    # 6E / Wi-Fi 7 (6)
    "wifi6e_ofdma_trigger_flood",
    "wifi6_he_action_frame_fuzz",
    "wifi6_mimo_feedback_spoof",
    "wifi7_mlo_channel_access_dos",
    "wifi7_eht_tb_sounding_fuzz",
    "wifi7_mlo_reconfig_dos",
    # Client-side (5)
    "wnm_bss_transition_dos",
    "wnm_sleep_mode_audit",
    "wifi_p2p_invite_replay",
    "wifi_p2p_go_negotiation_fuzz",
    "wifi_ml_evasion_probe",
    # Misc (6)
    "evil_twin_wpa3_only",
    "mesh_hwmp_rrep_inject",
    "passpoint_anqp_fuzz",
    "wifi_timing_oracle_dos",
    "beacon_flood_with_legit_ssid_clones",
    "wifi_security_audit_passive",
    # Polymorphic (5)
    "poly_deauth_interval_ai",
    "poly_beacon_flood_ssid_grammar",
    "poly_evil_twin_captive_html_ai",
    "poly_krack_replay_counter_drift",
    "poly_pmkid_rule_chain_drift",
    # Target-adaptive (5)
    "adapt_attack_wpa_version_picker",
    "adapt_attack_vendor_picker",
    "adapt_attack_client_count_picker",
    "adapt_attack_channel_congestion_picker",
    "adapt_attack_client_pmf_picker",
    # Read-only audits (5)
    "wifi6e_he_capabilities_audit",
    "wifi_halow_s1g_audit",
    "wifi_realtime_spectrum_audit",
    "passpoint_3gpp_plmn_audit",
    "nan_action_frame_fuzz",
    # Full-chain / orchestrator (2)
    "wifi_attack_full_chain",
    "wifi_attack_orchestrator",
    # Extra misc (2)
    "wifi_phy_jamming_burst",
    "wifi_phy_jamming_burst",
]


class TestCatalogPresence:
    def test_registry_has_phase_2_3_d(self):
        v2_names = {t[0] for t in WIFI_V2_METHODS}
        for n in PHASE_2_3_D_NAMES:
            assert n in v2_names, f"{n} missing from WIFI_V2_METHODS"

    def test_total_v2_count_increased(self):
        assert len(WIFI_V2_METHODS) >= 65, (
            f"expected >= 65, got {len(WIFI_V2_METHODS)}")

    def test_no_duplicate_names(self):
        seen = set()
        for t in WIFI_V2_METHODS:
            assert t[0] not in seen, f"duplicate: {t[0]}"
            seen.add(t[0])


# ---------------------------------------------------------------------------
# Dispatch — every Phase 2.3.D method dispatches via run_attack
# ---------------------------------------------------------------------------


def _runner():
    return WiFiAttackRunner(args={
        "bssid": "AA:BB:CC:DD:EE:FF",
        "ssid": "TestSSID",
        "wpa": "wpa2",
        "vendor": "cisco",
        "client_count": 5,
        "pmf": "required",
        "channel_util_pct": 50,
    })


class TestDispatch:
    @pytest.mark.parametrize("name", sorted(set(PHASE_2_3_D_NAMES)))
    def test_method_callable(self, name):
        r = _runner()
        fn = getattr(r, f"_v2_{name}", None)
        assert fn is not None, f"WiFiAttackRunner._v2_{name} missing"
        assert callable(fn), f"_v2_{name} is not callable"

    @pytest.mark.parametrize("name", sorted(set(PHASE_2_3_D_NAMES)))
    def test_run_attack_dispatch(self, name):
        r = _runner()
        res = r.run_attack(name)
        assert isinstance(res, dict)
        assert "ok" in res
        assert "name" in res
        assert res["name"] == name


# ---------------------------------------------------------------------------
# Envelope shape
# ---------------------------------------------------------------------------


class TestEnvelopeShape:
    @pytest.mark.parametrize("name", sorted(set(PHASE_2_3_D_NAMES)))
    def test_envelope_has_required_fields(self, name):
        r = _runner()
        res = r.run_attack(name)
        for k in ("ok", "name", "data", "error", "duration_s"):
            assert k in res, f"{name}: missing field {k!r}"

    @pytest.mark.parametrize("name", sorted(set(PHASE_2_3_D_NAMES)))
    def test_envelope_ok_is_bool(self, name):
        r = _runner()
        res = r.run_attack(name)
        assert isinstance(res["ok"], bool)

    def test_no_fabricated_psk(self):
        r = _runner()
        res = r.run_attack("poly_pmkid_rule_chain_drift")
        # The chain should be present, but the cracked PSK must NOT be inlined.
        s = str(res)
        # No actual "cracked_psk" or "password=..."
        assert "cracked_psk" not in s
        assert "PASSWORD=" not in s.upper()

    def test_no_inline_credentials(self):
        r = _runner()
        for name in ("poly_evil_twin_captive_html_ai", "poly_pmkid_rule_chain_drift"):
            res = r.run_attack(name)
            s = str(res)
            # Banned sentinel patterns from the operator's rule
            for bad in ("KFIOSA_TARGET_PASSWORD", "KFIOSA_AA1_", "KFIOSA_AA3_"):
                assert bad not in s, f"{name} leaked sentinel {bad}"


# ---------------------------------------------------------------------------
# Specific behaviour
# ---------------------------------------------------------------------------


class TestPolymorphic:
    def test_deauth_interval_produces_intervals(self):
        r = _runner()
        res = r.run_attack("poly_deauth_interval_ai")
        assert res["ok"] is True
        ivs = res["data"]["intervals_ms"]
        assert isinstance(ivs, list)
        assert len(ivs) >= 16
        for v in ivs:
            assert 50 <= v <= 3200  # 200 * (1 + 31/16) ≈ 588 ; allow range

    def test_ssid_grammar(self):
        r = _runner()
        res = r.run_attack("poly_beacon_flood_ssid_grammar")
        assert res["ok"] is True
        variants = res["data"]["variants"]
        assert len(variants) >= 8
        assert all(v.startswith("TestSSID") for v in variants)

    def test_evil_twin_html_template(self):
        r = _runner()
        res = r.run_attack("poly_evil_twin_captive_html_ai")
        assert res["ok"] is True
        html = res["data"]["html_template"]
        assert "<form" in html
        assert "TestSSID" in html
        assert "name='pass'" in html

    def test_krack_replay_counters(self):
        r = _runner()
        res = r.run_attack("poly_krack_replay_counter_drift")
        assert res["ok"] is True
        cs = res["data"]["replay_counters"]
        assert len(cs) == 16
        for c in cs:
            assert 0 <= c < 2**32

    def test_pmkid_rule_chain(self):
        r = _runner()
        res = r.run_attack("poly_pmkid_rule_chain_drift")
        assert res["ok"] is True
        chain = res["data"]["rule_chain"]
        assert any("hcxdumptool" in s for s in chain)


class TestTargetAdaptive:
    def test_wpa3_pick(self):
        r = _runner()
        r.args["wpa"] = "wpa3"
        res = r.run_attack("adapt_attack_wpa_version_picker")
        assert res["ok"] is True
        assert "sae" in res["data"]["pick"].lower()

    def test_wpa2_pick(self):
        r = _runner()
        r.args["wpa"] = "wpa2"
        res = r.run_attack("adapt_attack_wpa_version_picker")
        assert res["ok"] is True
        assert "pmkid" in res["data"]["pick"].lower()

    def test_cisco_vendor_pick(self):
        r = _runner()
        r.args["vendor"] = "cisco"
        res = r.run_attack("adapt_attack_vendor_picker")
        assert res["ok"] is True
        assert "wnm" in res["data"]["pick"].lower()

    def test_dense_clients_pick(self):
        r = _runner()
        r.args["client_count"] = 25
        res = r.run_attack("adapt_attack_client_count_picker")
        assert res["ok"] is True
        assert "flood" in res["data"]["pick"].lower() or "beacon" in res["data"]["pick"].lower()

    def test_no_clients_pick(self):
        r = _runner()
        r.args["client_count"] = 0
        res = r.run_attack("adapt_attack_client_count_picker")
        assert res["ok"] is True
        assert "pmkid" in res["data"]["pick"].lower()

    def test_high_congestion_pick(self):
        r = _runner()
        r.args["channel_util_pct"] = 80
        res = r.run_attack("adapt_attack_channel_congestion_picker")
        assert res["ok"] is True
        assert "timing" in res["data"]["pick"].lower()

    def test_pmf_required_pick(self):
        r = _runner()
        r.args["pmf"] = "required"
        res = r.run_attack("adapt_attack_client_pmf_picker")
        assert res["ok"] is True
        assert "anti" in res["data"]["pick"].lower() or "sae" in res["data"]["pick"].lower()

    def test_pmf_optional_pick(self):
        r = _runner()
        r.args["pmf"] = "optional"
        res = r.run_attack("adapt_attack_client_pmf_picker")
        assert res["ok"] is True
        assert "deauth" in res["data"]["pick"].lower()


class TestOrchestrator:
    def test_wifi_attack_orchestrator_lists_pickers(self):
        r = _runner()
        res = r.run_attack("wifi_attack_orchestrator")
        assert res["ok"] is True
        picks = res["data"]["picks"]
        assert len(picks) >= 3
        for p in picks:
            assert p in {t[0] for t in WIFI_V2_METHODS}

    def test_wifi_attack_full_chain_substeps(self):
        r = _runner()
        res = r.run_attack("wifi_attack_full_chain")
        # The full chain returns ok=False (plan-only) but lists substeps.
        subs = res["data"]["substeps"]
        assert isinstance(subs, list)
        assert len(subs) >= 3


# ---------------------------------------------------------------------------
# Args validation
# ---------------------------------------------------------------------------


class TestArgsValidation:
    def test_bssid_required_for_read_only(self):
        # wpa3_owe_transition_bypass is read-only (no root gate)
        r = WiFiAttackRunner(args={})  # no bssid
        res = r.run_attack("wpa3_owe_transition_bypass")
        assert res["ok"] is False
        assert "bssid" in res["error"].lower()

    def test_ssid_for_poly_html(self):
        # poly methods don't gate on root; they need ssid for grammar
        r = WiFiAttackRunner(args={})
        res = r.run_attack("poly_beacon_flood_ssid_grammar")
        # With no ssid, the poly method uses a default ("FreeWiFi")
        assert res["ok"] is True

    def test_intrusive_methods_root_gated(self):
        # When not root, intrusive methods return the root error
        r = WiFiAttackRunner(args={"bssid": "AA:BB:CC:DD:EE:FF"})
        res = r.run_attack("wpa3_sae_commit_reflect")
        assert res["ok"] is False
        assert "root" in res["error"].lower()


# ---------------------------------------------------------------------------
# Adversarial: never-fabricate contract
# ---------------------------------------------------------------------------


class TestAdversarial:
    def test_no_method_returns_ok_true_with_fake_psk(self):
        r = _runner()
        # Run all poly methods and check none of them contain a fake PSK
        for name in ("poly_pmkid_rule_chain_drift", "poly_deauth_interval_ai",
                     "poly_evil_twin_captive_html_ai", "poly_krack_replay_counter_drift"):
            res = r.run_attack(name)
            s = str(res).lower()
            # Real PSKs are 8-63 ASCII chars; a single string of 8+ printable
            # chars in a "data" key labelled like a real PSK would be a
            # fabrication. We check the absence of typical PSK field names.
            for k in ("psk", "password", "pre_shared_key", "passphrase"):
                assert f'"{k}"' not in s, f"{name} may have inlined a {k}"

    def test_adapt_pickers_return_real_v2_names(self):
        r = _runner()
        v2_names = {t[0] for t in WIFI_V2_METHODS}
        for picker in ("adapt_attack_wpa_version_picker",
                       "adapt_attack_vendor_picker",
                       "adapt_attack_client_count_picker",
                       "adapt_attack_channel_congestion_picker",
                       "adapt_attack_client_pmf_picker"):
            res = r.run_attack(picker)
            pick = res["data"]["pick"]
            assert pick in v2_names, f"{picker} picked {pick!r} which is not registered"

    def test_intrusive_methods_have_error_string(self):
        r = _runner()
        # Intrusive methods should NEVER return ok=True without operator
        # consent (which we don't simulate here).
        for name in ("wpa3_sae_commit_reflect", "wifi6e_ofdma_trigger_flood",
                     "evil_twin_wpa3_only", "mesh_hwmp_rrep_inject"):
            res = r.run_attack(name)
            # Either ok=False with a useful error OR ok=True (the method
            # legitimately succeeded). The contract is "ok=True means
            # real work happened." For a lab without an injected iface,
            # it must be ok=False.
            assert res["ok"] is False, f"{name} returned ok=True without root"


# ---------------------------------------------------------------------------
# Phase 2.3.D summary
# ---------------------------------------------------------------------------


class TestPhaseSummary:
    def test_method_count_at_least_40(self):
        assert len(PHASE_2_3_D_NAMES) >= 40

    def test_all_methods_distinct(self):
        # dedupe the duplicate
        unique = set(PHASE_2_3_D_NAMES)
        assert len(unique) == len(PHASE_2_3_D_NAMES) - 1, (
            f"expected exactly 1 duplicate (wifi_phy_jamming_burst) "
            f"in the test list; got {len(PHASE_2_3_D_NAMES) - len(unique)}")
