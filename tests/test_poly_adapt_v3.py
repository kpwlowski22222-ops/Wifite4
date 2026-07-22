"""tests.test_poly_adapt_v3 — Phase 3 expansion: 20 new poly/adapt methods.

Adds smoke + adversarial tests for the 10 v3 polymorphic grammars
and 10 v3 target-adaptive pickers. All companions must:

* Return a real envelope {ok, data} — never fakes.
* Mark model as ``heuristic`` — never trained-ML.
* Stay at risk="intrusive" (never destructive).

Each method also gets at least one happy-path test that exercises
its primary pick/branch.
"""

from core.refactors.poly_adapt_companions import (
    POLY_ADAPT_REGISTRY,
    POLY_ADAPT_RISK,
    POLY_ADAPT_DESCRIPTIONS,
    list_poly_adapt_methods,
    describe_poly_adapt_method,
    run_poly_adapt,
    build_poly_adapt_prompt_stanza,
)


# ---------------------------------------------------------------------------
# Registry counts
# ---------------------------------------------------------------------------


class TestRegistryCounts:
    def test_total_at_least_60(self):
        # Phase 3 expansion: 20 → 60 methods
        assert len(POLY_ADAPT_REGISTRY) >= 60

    def test_v3_polymorphic_count(self):
        v3_poly = [
            n for n in POLY_ADAPT_REGISTRY
            if n in {
                "poly_wpa3_sae_grammar",
                "poly_eapol_key_replay_grammar",
                "poly_ble_ll_fragment_grammar",
                "poly_gatt_write_payload_grammar",
                "poly_email_pattern_grammar",
                "poly_dorking_query_grammar",
                "poly_disk_carve_signature_grammar",
                "poly_memory_yara_pattern_grammar",
                "poly_lateral_movement_grammar",
                "poly_persistence_registry_grammar",
            }
        ]
        assert len(v3_poly) == 10

    def test_v3_adaptive_count(self):
        v3_adapt = [
            n for n in POLY_ADAPT_REGISTRY
            if n in {
                "adapt_wifi_chipset_picker",
                "adapt_wifi_channel_width_picker",
                "adapt_ble_chipset_picker",
                "adapt_ble_pairing_method_picker",
                "adapt_osint_jurisdiction_picker",
                "adapt_osint_query_language_picker",
                "adapt_forensics_image_format_picker",
                "adapt_forensics_timeline_format_picker",
                "adapt_persistence_mechanism_picker",
                "adapt_exfil_channel_picker",
            }
        ]
        assert len(v3_adapt) == 10

    def test_all_v3_have_risk(self):
        v3 = [
            "poly_wpa3_sae_grammar", "poly_eapol_key_replay_grammar",
            "poly_ble_ll_fragment_grammar", "poly_gatt_write_payload_grammar",
            "poly_email_pattern_grammar", "poly_dorking_query_grammar",
            "poly_disk_carve_signature_grammar", "poly_memory_yara_pattern_grammar",
            "poly_lateral_movement_grammar", "poly_persistence_registry_grammar",
            "adapt_wifi_chipset_picker", "adapt_wifi_channel_width_picker",
            "adapt_ble_chipset_picker", "adapt_ble_pairing_method_picker",
            "adapt_osint_jurisdiction_picker", "adapt_osint_query_language_picker",
            "adapt_forensics_image_format_picker", "adapt_forensics_timeline_format_picker",
            "adapt_persistence_mechanism_picker", "adapt_exfil_channel_picker",
        ]
        for n in v3:
            assert n in POLY_ADAPT_RISK
            assert POLY_ADAPT_RISK[n] in {"read", "intrusive", "destructive"}

    def test_all_v3_have_description(self):
        v3 = [
            "poly_wpa3_sae_grammar", "poly_eapol_key_replay_grammar",
            "poly_ble_ll_fragment_grammar", "poly_gatt_write_payload_grammar",
            "poly_email_pattern_grammar", "poly_dorking_query_grammar",
            "poly_disk_carve_signature_grammar", "poly_memory_yara_pattern_grammar",
            "poly_lateral_movement_grammar", "poly_persistence_registry_grammar",
            "adapt_wifi_chipset_picker", "adapt_wifi_channel_width_picker",
            "adapt_ble_chipset_picker", "adapt_ble_pairing_method_picker",
            "adapt_osint_jurisdiction_picker", "adapt_osint_query_language_picker",
            "adapt_forensics_image_format_picker", "adapt_forensics_timeline_format_picker",
            "adapt_persistence_mechanism_picker", "adapt_exfil_channel_picker",
        ]
        for n in v3:
            assert n in POLY_ADAPT_DESCRIPTIONS
            assert len(POLY_ADAPT_DESCRIPTIONS[n]) > 0

    def test_no_v3_method_marks_destructive(self):
        v3 = [
            "poly_wpa3_sae_grammar", "poly_eapol_key_replay_grammar",
            "poly_ble_ll_fragment_grammar", "poly_gatt_write_payload_grammar",
            "poly_email_pattern_grammar", "poly_dorking_query_grammar",
            "poly_disk_carve_signature_grammar", "poly_memory_yara_pattern_grammar",
            "poly_lateral_movement_grammar", "poly_persistence_registry_grammar",
            "adapt_wifi_chipset_picker", "adapt_wifi_channel_width_picker",
            "adapt_ble_chipset_picker", "adapt_ble_pairing_method_picker",
            "adapt_osint_jurisdiction_picker", "adapt_osint_query_language_picker",
            "adapt_forensics_image_format_picker", "adapt_forensics_timeline_format_picker",
            "adapt_persistence_mechanism_picker", "adapt_exfil_channel_picker",
        ]
        for n in v3:
            assert POLY_ADAPT_RISK[n] != "destructive", (
                f"{n} is destructive — pickers must be intrusive only"
            )


# ---------------------------------------------------------------------------
# Polymorphic v3 smoke tests
# ---------------------------------------------------------------------------


class TestPolymorphicV3:
    def test_wpa3_sae_returns_grammar_envelope(self):
        r = run_poly_adapt("poly_wpa3_sae_grammar", {"seed": "test"})
        assert r["ok"] is True, r
        assert r["data"]["grammar"] == "wpa3_sae"
        assert "variants" in r["data"]
        assert "primary" in r["data"]
        assert r["data"]["model"] == "polymorphic (heuristic)"

    def test_eapol_key_replay_returns_grammar_envelope(self):
        r = run_poly_adapt("poly_eapol_key_replay_grammar", {"seed": "krack"})
        assert r["ok"] is True
        assert r["data"]["grammar"] == "eapol_key_replay"
        assert isinstance(r["data"]["variants"], list)
        assert len(r["data"]["variants"]) >= 1

    def test_ble_ll_fragment_returns_grammar_envelope(self):
        r = run_poly_adapt("poly_ble_ll_fragment_grammar", {})
        assert r["ok"] is True
        assert r["data"]["grammar"] == "ble_ll_fragment"

    def test_gatt_write_payload_returns_grammar_envelope(self):
        r = run_poly_adapt("poly_gatt_write_payload_grammar", {"seed": "gatt"})
        assert r["ok"] is True
        assert r["data"]["grammar"] == "gatt_write_payload"

    def test_email_pattern_returns_grammar_envelope(self):
        r = run_poly_adapt("poly_email_pattern_grammar", {"seed": "email"})
        assert r["ok"] is True
        assert r["data"]["grammar"] == "email_pattern"
        # Variants are templates like "firstname_lastname_at_domain" (heuristic
        # placeholders — no real emails produced). Each must contain the
        # "at_domain" marker that gets substituted at chain-step time.
        for v in r["data"]["variants"]:
            assert "at_domain" in v, (
                f"email pattern variant {v!r} should contain 'at_domain' marker"
            )

    def test_dorking_query_has_placeholder(self):
        r = run_poly_adapt("poly_dorking_query_grammar", {"seed": "dork"})
        assert r["ok"] is True
        # Variants are templates with {target}, {keyword}, etc.
        primary = r["data"]["primary"]
        assert "{" in primary and "}" in primary, (
            f"dorking primary should be a template, got: {primary!r}"
        )

    def test_disk_carve_signature_envelope(self):
        r = run_poly_adapt("poly_disk_carve_signature_grammar", {})
        assert r["ok"] is True
        assert r["data"]["grammar"] == "disk_carve_signature"

    def test_memory_yara_pattern_envelope(self):
        r = run_poly_adapt("poly_memory_yara_pattern_grammar", {})
        assert r["ok"] is True
        assert r["data"]["grammar"] == "memory_yara"

    def test_lateral_movement_envelope(self):
        r = run_poly_adapt("poly_lateral_movement_grammar", {})
        assert r["ok"] is True
        assert r["data"]["grammar"] == "lateral_movement"

    def test_persistence_registry_envelope(self):
        r = run_poly_adapt("poly_persistence_registry_grammar", {})
        assert r["ok"] is True
        assert r["data"]["grammar"] == "persistence_registry"
        # Variants must look like registry keys
        for v in r["data"]["variants"]:
            assert "HK" in v.upper() or "currentversion" in v.lower() or "services" in v.lower()


# ---------------------------------------------------------------------------
# Target-adaptive v3 smoke tests
# ---------------------------------------------------------------------------


class TestAdaptiveV3:
    def test_wifi_chipset_mt7922(self):
        r = run_poly_adapt("adapt_wifi_chipset_picker", {"chipset": "mt7922"})
        assert r["ok"] is True
        assert r["data"]["pick"] == "mt7921e_nexmon_monitor"
        assert "mt7922" in r["data"]["rationale"].lower() or "mt7921" in r["data"]["rationale"].lower()

    def test_wifi_chipset_intel(self):
        r = run_poly_adapt("adapt_wifi_chipset_picker", {"chipset": "iwlwifi"})
        assert r["ok"] is True
        assert "iwlwifi" in r["data"]["pick"]

    def test_wifi_chipset_unknown_falls_back(self):
        r = run_poly_adapt("adapt_wifi_chipset_picker", {"chipset": "made_up_chip"})
        assert r["ok"] is True
        assert r["data"]["pick"] == "generic_nl80211_monitor"

    def test_wifi_channel_width_6ghz(self):
        r = run_poly_adapt("adapt_wifi_channel_width_picker", {"band": "6ghz"})
        assert r["ok"] is True
        assert r["data"]["pick"] == "160mhz"

    def test_wifi_channel_width_2_4(self):
        r = run_poly_adapt("adapt_wifi_channel_width_picker", {"band": "2.4ghz"})
        assert r["ok"] is True
        assert r["data"]["pick"] == "20mhz"

    def test_wifi_channel_width_5ghz(self):
        r = run_poly_adapt("adapt_wifi_channel_width_picker", {"band": "5ghz"})
        assert r["ok"] is True
        assert r["data"]["pick"] == "80mhz"

    def test_ble_chipset_u4000(self):
        r = run_poly_adapt("adapt_ble_chipset_picker", {"chipset": "u4000"})
        assert r["ok"] is True
        assert "realtek" in r["data"]["pick"]
        # The picker is intentionally tolerant of older "ub500" labels
        # (operators may have older notes / configs from when the
        # hardware was reported as TP-LINK UB500 Plus).
        r2 = run_poly_adapt("adapt_ble_chipset_picker", {"chipset": "ub500"})
        assert r2["ok"] is True
        assert "realtek" in r2["data"]["pick"]

    def test_ble_pairing_just_works(self):
        r = run_poly_adapt("adapt_ble_pairing_method_picker", {"io_cap": "NoInputNoOutput"})
        assert r["ok"] is True
        assert r["data"]["pick"] == "just_works"

    def test_ble_pairing_passkey(self):
        r = run_poly_adapt("adapt_ble_pairing_method_picker", {"io_cap": "KeyboardOnly"})
        assert r["ok"] is True
        assert r["data"]["pick"] == "passkey_entry"

    def test_osint_jurisdiction_pl(self):
        r = run_poly_adapt("adapt_osint_jurisdiction_picker", {"jurisdiction": "PL"})
        assert r["ok"] is True
        assert "ceidg" in r["data"]["pick"] or "knf" in r["data"]["pick"]

    def test_osint_jurisdiction_unknown_falls_back(self):
        r = run_poly_adapt("adapt_osint_jurisdiction_picker", {"jurisdiction": "XX"})
        assert r["ok"] is True
        # Falls back to no-key sources
        pick = r["data"]["pick"]
        assert "github" in pick or "nameday" in pick or "hibp" in pick

    def test_osint_query_language_github(self):
        r = run_poly_adapt("adapt_osint_query_language_picker", {"target": "github"})
        assert r["ok"] is True
        assert r["data"]["pick"] == "github_search_qualifiers"

    def test_osint_query_language_graph(self):
        r = run_poly_adapt("adapt_osint_query_language_picker", {"target": "graph"})
        assert r["ok"] is True
        assert r["data"]["pick"] == "cypher"

    def test_forensics_image_court(self):
        r = run_poly_adapt("adapt_forensics_image_format_picker", {"audience": "court"})
        assert r["ok"] is True
        assert "e01" in r["data"]["pick"] or "ewf" in r["data"]["pick"]

    def test_forensics_image_airgap(self):
        # airgap maps to raw dd (audience=='raw' or default)
        r = run_poly_adapt("adapt_forensics_image_format_picker", {"audience": "raw"})
        assert r["ok"] is True
        assert r["data"]["pick"] == "raw_dd"

    def test_forensics_timeline_ir(self):
        r = run_poly_adapt("adapt_forensics_timeline_format_picker", {"audience": "ir_team"})
        assert r["ok"] is True
        assert r["data"]["pick"] == "plaso_csv"

    def test_forensics_timeline_audit(self):
        r = run_poly_adapt("adapt_forensics_timeline_format_picker", {"audience": "auditor"})
        assert r["ok"] is True
        assert r["data"]["pick"] == "jsonl_audit"

    def test_persistence_windows_persistent(self):
        r = run_poly_adapt("adapt_persistence_mechanism_picker",
                           {"target_os": "windows", "survive_reboot": True})
        assert r["ok"] is True
        assert "registry" in r["data"]["pick"] or "hklm" in r["data"]["pick"]

    def test_persistence_linux_persistent(self):
        r = run_poly_adapt("adapt_persistence_mechanism_picker",
                           {"target_os": "linux", "survive_reboot": True})
        assert r["ok"] is True
        assert "systemd" in r["data"]["pick"]

    def test_persistence_android(self):
        r = run_poly_adapt("adapt_persistence_mechanism_picker",
                           {"target_os": "android"})
        assert r["ok"] is True
        assert "boot" in r["data"]["pick"]

    def test_exfil_blocked_https(self):
        r = run_poly_adapt("adapt_exfil_channel_picker", {"egress": "https_blocked"})
        assert r["ok"] is True
        assert r["data"]["pick"] == "dns_tunnel"

    def test_exfil_airgap(self):
        r = run_poly_adapt("adapt_exfil_channel_picker", {"egress": "airgap"})
        assert r["ok"] is True
        assert "sneakernet" in r["data"]["pick"] or "usb" in r["data"]["pick"]

    def test_exfil_default_https(self):
        r = run_poly_adapt("adapt_exfil_channel_picker", {"egress": "default", "size_kb": 500})
        assert r["ok"] is True
        assert "https" in r["data"]["pick"]


# ---------------------------------------------------------------------------
# Adversarial — never fabricate / never claim trained ML
# ---------------------------------------------------------------------------


class TestAdversarial:
    def test_no_v3_method_claims_trained_ml(self):
        v3 = [
            "poly_wpa3_sae_grammar", "poly_eapol_key_replay_grammar",
            "poly_ble_ll_fragment_grammar", "poly_gatt_write_payload_grammar",
            "poly_email_pattern_grammar", "poly_dorking_query_grammar",
            "poly_disk_carve_signature_grammar", "poly_memory_yara_pattern_grammar",
            "poly_lateral_movement_grammar", "poly_persistence_registry_grammar",
            "adapt_wifi_chipset_picker", "adapt_wifi_channel_width_picker",
            "adapt_ble_chipset_picker", "adapt_ble_pairing_method_picker",
            "adapt_osint_jurisdiction_picker", "adapt_osint_query_language_picker",
            "adapt_forensics_image_format_picker", "adapt_forensics_timeline_format_picker",
            "adapt_persistence_mechanism_picker", "adapt_exfil_channel_picker",
        ]
        for n in v3:
            r = run_poly_adapt(n, {})
            if r["ok"]:
                m = r["data"].get("model", "")
                assert "heuristic" in m, (
                    f"{n} claims model={m!r} (must be heuristic)"
                )

    def test_no_v3_method_fabricates_creds(self):
        v3 = [
            "poly_email_pattern_grammar",
            "poly_dorking_query_grammar",
            "poly_lateral_movement_grammar",
            "poly_persistence_registry_grammar",
            "adapt_osint_jurisdiction_picker",
            "adapt_persistence_mechanism_picker",
        ]
        for n in v3:
            r = run_poly_adapt(n, {})
            if r["ok"]:
                # Scan the envelope for any inline password/hash/ntlm
                import json
                blob = json.dumps(r["data"]).lower()
                for bad in ("password=", "ntlm:", "hash="):
                    assert bad not in blob, (
                        f"{n} envelope contains {bad!r} — fabricated cred"
                    )

    def test_describe_known(self):
        d = describe_poly_adapt_method("poly_wpa3_sae_grammar")
        assert d is not None
        assert d["name"] == "poly_wpa3_sae_grammar"
        assert d["risk"] in ("intrusive", "destructive")
        assert d["description"]

    def test_prompt_stanza_lists_all_v3(self):
        stanza = build_poly_adapt_prompt_stanza()
        v3 = [
            "poly_wpa3_sae_grammar", "poly_eapol_key_replay_grammar",
            "poly_ble_ll_fragment_grammar", "poly_gatt_write_payload_grammar",
            "poly_email_pattern_grammar", "poly_dorking_query_grammar",
            "poly_disk_carve_signature_grammar", "poly_memory_yara_pattern_grammar",
            "poly_lateral_movement_grammar", "poly_persistence_registry_grammar",
            "adapt_wifi_chipset_picker", "adapt_wifi_channel_width_picker",
            "adapt_ble_chipset_picker", "adapt_ble_pairing_method_picker",
            "adapt_osint_jurisdiction_picker", "adapt_osint_query_language_picker",
            "adapt_forensics_image_format_picker", "adapt_forensics_timeline_format_picker",
            "adapt_persistence_mechanism_picker", "adapt_exfil_channel_picker",
        ]
        for n in v3:
            assert n in stanza, f"{n} missing from prompt stanza"
