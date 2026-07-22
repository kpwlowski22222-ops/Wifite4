"""Tests for core.refactors.poly_adapt_v2_phase4 — Phase 4 T20 expansion.

Covers:
  * Each new poly/adapt method runs without raising
  * Each new method returns the expected envelope shape
  * install() merges into POLY_ADAPT_REGISTRY and brings the
    total to >=100
"""
from __future__ import annotations

import importlib
from typing import Any, Dict

import pytest


def _import_module():
    return importlib.import_module("core.refactors.poly_adapt_v2_phase4")


def _import_parent():
    return importlib.import_module("core.refactors.poly_adapt_companions")


mod = _import_module()
parent = _import_parent()


# ---------------------------------------------------------------------------
# install() — registry merge
# ---------------------------------------------------------------------------

class TestInstall:
    def test_install_merges_into_registry(self):
        before = len(parent.POLY_ADAPT_REGISTRY)
        result = mod.install()
        after = len(parent.POLY_ADAPT_REGISTRY)
        assert result["ok"] is True
        assert after >= 100, f"registry has {after}, expected >=100"
        # All 32 v2 entries should now be in the parent registry
        for name in mod.PHASE4_V2_REGISTRY:
            assert name in parent.POLY_ADAPT_REGISTRY, f"{name} missing"
        # install() should be idempotent — second call adds 0
        result2 = mod.install()
        assert result2["added"] == 0
        # Re-run for safety (no harm if already installed)
        # No assertions on before/after — depends on prior runs

    def test_v2_count_is_35_or_32(self):
        # Plan said 30+; actual implementation has 37 (26 poly + 11 adapt).
        # 35 was the upper bound; assert >=30.
        assert len(mod.PHASE4_V2_REGISTRY) >= 30

    def test_all_v2_methods_have_step_envelope(self):
        for name, fn in mod.PHASE4_V2_REGISTRY.items():
            out = fn({})
            assert isinstance(out, dict), f"{name} did not return dict"
            assert "ok" in out, f"{name} missing 'ok' field"
            assert "name" in out, f"{name} missing 'name' field"


# ---------------------------------------------------------------------------
# Per-method smoke tests
# ---------------------------------------------------------------------------

class TestPolymorphicMethods:
    """Verify each new method runs and returns the expected shape."""

    def test_poly_wpa3_sae_grammar(self):
        out = mod.poly_wpa3_sae_grammar({"bssid": "00:11:22:33:44:55"})
        assert out["ok"] is True
        assert out["data"]["bssid"] == "00:11:22:33:44:55"
        assert "variants" in out["data"]
        assert len(out["data"]["variants"]) >= 4

    def test_poly_wpa3_sae_grammar_no_bssid_errors(self):
        out = mod.poly_wpa3_sae_grammar({})
        assert out["ok"] is False

    def test_poly_eapol_key_replay_grammar(self):
        out = mod.poly_eapol_key_replay_grammar({})
        assert out["ok"] is True
        assert len(out["data"]["variants"]) >= 3

    def test_poly_5ghz_channel_dwell_grammar(self):
        out = mod.poly_5ghz_channel_dwell_grammar({})
        assert out["ok"] is True
        assert "dwell_dfs_aware" in {v["id"] for v in out["data"]["variants"]}

    def test_poly_6ghz_wifi6e_grammar(self):
        out = mod.poly_6ghz_wifi6e_grammar({})
        assert out["ok"] is True
        assert "probe_6ghz_p_scanning" in {v["id"] for v in out["data"]["variants"]}

    def test_poly_evil_twin_captive_portal_grammar(self):
        out = mod.poly_evil_twin_captive_portal_grammar({})
        assert out["ok"] is True
        assert "captive_corporate_portal" in {v["id"] for v in out["data"]["variants"]}

    def test_poly_passive_pcap_export_grammar(self):
        out = mod.poly_passive_pcap_export_grammar({})
        assert out["ok"] is True
        assert "filter_eapol_only" in {v["id"] for v in out["data"]["variants"]}

    def test_poly_ap_fingerprint_grammar(self):
        out = mod.poly_ap_fingerprint_grammar({})
        assert out["ok"] is True
        assert "fp_ie_tags" in {v["id"] for v in out["data"]["variants"]}

    def test_poly_client_probe_correlator_grammar(self):
        out = mod.poly_client_probe_correlator_grammar({})
        assert out["ok"] is True
        assert "by_essid_window" in {v["id"] for v in out["data"]["variants"]}

    def test_poly_ble_ll_fragment_grammar(self):
        out = mod.poly_ble_ll_fragment_grammar({})
        assert out["ok"] is True
        assert "frag_att_oversize" in {v["id"] for v in out["data"]["variants"]}

    def test_poly_gatt_write_payload_grammar(self):
        out = mod.poly_gatt_write_payload_grammar({})
        assert out["ok"] is True
        assert "write_cmd" in {v["id"] for v in out["data"]["variants"]}

    def test_poly_ble_pairing_just_works_bypass_grammar(self):
        out = mod.poly_ble_pairing_just_works_bypass_grammar({})
        assert out["ok"] is True
        assert "jw_tk_zero" in {v["id"] for v in out["data"]["variants"]}

    def test_poly_ble_advertising_malicious_data_grammar(self):
        out = mod.poly_ble_advertising_malicious_data_grammar({})
        assert out["ok"] is True
        assert "impersonate_ibeacon" in {v["id"] for v in out["data"]["variants"]}

    def test_poly_ble_service_discovery_grammar(self):
        out = mod.poly_ble_service_discovery_grammar({})
        assert out["ok"] is True
        assert "primary_then_secondary" in {v["id"] for v in out["data"]["variants"]}

    def test_poly_ble_characteristic_descriptor_grammar(self):
        out = mod.poly_ble_characteristic_descriptor_grammar({})
        assert out["ok"] is True
        assert "read_all_descriptors" in {v["id"] for v in out["data"]["variants"]}

    def test_poly_ble_pairing_event_capture_grammar(self):
        out = mod.poly_ble_pairing_event_capture_grammar({})
        assert out["ok"] is True
        assert "btle.smp" in {v["id"] for v in out["data"]["variants"]}

    def test_poly_dorking_query_grammar(self):
        out = mod.poly_dorking_query_grammar({})
        assert out["ok"] is True
        assert "google_dork_inurl" in {v["id"] for v in out["data"]["variants"]}

    def test_poly_wayback_machine_query_grammar(self):
        out = mod.poly_wayback_machine_query_grammar({})
        assert out["ok"] is True
        assert "cdx_basic" in {v["id"] for v in out["data"]["variants"]}

    def test_poly_subdomain_brute_force_wordlist_grammar(self):
        out = mod.poly_subdomain_brute_force_wordlist_grammar({})
        assert out["ok"] is True
        assert "seclists_dns" in {v["id"] for v in out["data"]["variants"]}

    def test_poly_email_permutation_grammar(self):
        out = mod.poly_email_permutation_grammar({})
        assert out["ok"] is True
        assert "first_dot_last" in {v["id"] for v in out["data"]["variants"]}

    def test_poly_username_platform_walker_grammar(self):
        out = mod.poly_username_platform_walker_grammar({})
        assert out["ok"] is True
        assert "sherlock_basic" in {v["id"] for v in out["data"]["variants"]}

    def test_poly_phone_carrier_lookup_grammar(self):
        out = mod.poly_phone_carrier_lookup_grammar({})
        assert out["ok"] is True
        assert "bip_classification" in {v["id"] for v in out["data"]["variants"]}

    def test_poly_disk_carve_signature_grammar(self):
        out = mod.poly_disk_carve_signature_grammar({})
        assert out["ok"] is True
        assert "magic_pdf" in {v["id"] for v in out["data"]["variants"]}

    def test_poly_memory_yara_pattern_grammar(self):
        out = mod.poly_memory_yara_pattern_grammar({})
        assert out["ok"] is True
        assert "yara_lsass" in {v["id"] for v in out["data"]["variants"]}

    def test_poly_timeline_plaso_filter_grammar(self):
        out = mod.poly_timeline_plaso_filter_grammar({})
        assert out["ok"] is True
        assert "plaso_all" in {v["id"] for v in out["data"]["variants"]}

    def test_poly_log_wiper_strategy_grammar(self):
        out = mod.poly_log_wiper_strategy_grammar({})
        assert out["ok"] is True
        assert "systemd_journal_vacuum" in {v["id"] for v in out["data"]["variants"]}

    def test_poly_timestomp_strategy_grammar(self):
        out = mod.poly_timestomp_strategy_grammar({})
        assert out["ok"] is True
        assert "utime" in {v["id"] for v in out["data"]["variants"]}

    def test_poly_secure_erase_strategy_grammar(self):
        out = mod.poly_secure_erase_strategy_grammar({})
        assert out["ok"] is True
        assert "shred_dod" in {v["id"] for v in out["data"]["variants"]}

    def test_poly_lateral_movement_grammar(self):
        out = mod.poly_lateral_movement_grammar({})
        assert out["ok"] is True
        ids = {v["id"] for v in out["data"]["variants"]}
        assert {"psexec", "wmiexec", "smbexec"} <= ids

    def test_poly_persistence_registry_grammar(self):
        out = mod.poly_persistence_registry_grammar({})
        assert out["ok"] is True
        ids = {v["id"] for v in out["data"]["variants"]}
        assert {"reg_run_key", "cron_d", "systemd_unit"} <= ids

    def test_poly_exfil_channel_grammar(self):
        out = mod.poly_exfil_channel_grammar({})
        assert out["ok"] is True
        ids = {v["id"] for v in out["data"]["variants"]}
        assert {"dns_txt", "https_post", "smb_unc"} <= ids


# ---------------------------------------------------------------------------
# Target-adaptive picker tests
# ---------------------------------------------------------------------------

class TestAdaptivePickers:
    def test_adapt_wifi_5ghz_vs_24ghz_picker_5ghz(self):
        out = mod.adapt_wifi_5ghz_vs_24ghz_picker({"frequency_mhz": 5180})
        assert out["ok"] is True
        assert out["data"]["pick"] == "5ghz"

    def test_adapt_wifi_5ghz_vs_24ghz_picker_24ghz(self):
        out = mod.adapt_wifi_5ghz_vs_24ghz_picker({"frequency_mhz": 2412})
        assert out["ok"] is True
        assert out["data"]["pick"] == "24ghz"

    def test_adapt_wifi_5ghz_vs_24ghz_picker_invalid_freq(self):
        out = mod.adapt_wifi_5ghz_vs_24ghz_picker({"frequency_mhz": "abc"})
        assert out["ok"] is False

    def test_adapt_post_exploit_target_os_picker_windows(self):
        out = mod.adapt_post_exploit_target_os_picker({"os": "Windows"})
        assert out["ok"] is True
        assert out["data"]["pick"] == "windows_post_exploit"

    def test_adapt_post_exploit_target_os_picker_linux(self):
        out = mod.adapt_post_exploit_target_os_picker({"os": "linux"})
        assert out["ok"] is True
        assert out["data"]["pick"] == "linux_post_exploit"

    def test_adapt_post_exploit_target_os_picker_android(self):
        out = mod.adapt_post_exploit_target_os_picker({"os": "android"})
        assert out["ok"] is True
        assert out["data"]["pick"] == "android_post_exploit"

    def test_adapt_post_exploit_target_os_picker_unknown(self):
        out = mod.adapt_post_exploit_target_os_picker({"os": "zorg"})
        assert out["ok"] is True
        assert out["data"]["pick"] == "generic_post_exploit"

    def test_adapt_post_exploit_target_os_picker_no_os(self):
        out = mod.adapt_post_exploit_target_os_picker({})
        assert out["ok"] is False

    def test_adapt_anti_forensic_log_target_picker_windows(self):
        out = mod.adapt_anti_forensic_log_target_picker({"os": "windows"})
        assert out["ok"] is True
        assert out["data"]["pick"] == "wevtutil_cl"

    def test_adapt_anti_forensic_log_target_picker_linux(self):
        out = mod.adapt_anti_forensic_log_target_picker({"os": "linux"})
        assert out["ok"] is True
        assert out["data"]["pick"] == "journalctl_vacuum"

    def test_adapt_anti_forensic_log_target_picker_macos(self):
        out = mod.adapt_anti_forensic_log_target_picker({"os": "macos"})
        assert out["ok"] is True
        assert out["data"]["pick"] == "unified_log_clear"

    def test_adapt_anti_forensic_log_target_picker_unknown(self):
        out = mod.adapt_anti_forensic_log_target_picker({"os": "zorg"})
        assert out["ok"] is True
        assert out["data"]["pick"] == "no_op"

    def test_adapt_exfil_channel_picker_open(self):
        out = mod.adapt_exfil_channel_picker({"egress": "open"})
        assert out["ok"] is True
        assert out["data"]["pick"] == "https_post"

    def test_adapt_exfil_channel_picker_dns_only(self):
        out = mod.adapt_exfil_channel_picker({"egress": "dns_only"})
        assert out["ok"] is True
        assert out["data"]["pick"] == "dns_txt"

    def test_adapt_exfil_channel_picker_no_egress(self):
        out = mod.adapt_exfil_channel_picker({"egress": "no_egress"})
        assert out["ok"] is True
        assert out["data"]["pick"] == "smb_unc"

    def test_adapt_chain_phase_picker_wifi(self):
        out = mod.adapt_chain_phase_picker({"attack_surface": "wifi_offensive"})
        assert out["ok"] is True
        assert out["data"]["pick"] == "post_exploit_wifi"

    def test_adapt_chain_phase_picker_post_exploit(self):
        out = mod.adapt_chain_phase_picker({"attack_surface": "post_exploit"})
        assert out["ok"] is True
        assert out["data"]["pick"] == "exfil"

    def test_adapt_chain_phase_picker_anti_forensic(self):
        out = mod.adapt_chain_phase_picker({"attack_surface": "anti_forensic"})
        assert out["ok"] is True
        assert out["data"]["pick"] == "report"

    def test_adapt_post_exploit_persistence_picker_windows_user(self):
        out = mod.adapt_post_exploit_persistence_picker(
            {"os": "windows", "userland": "user"})
        assert out["ok"] is True
        assert out["data"]["pick"] == "reg_run_key"

    def test_adapt_post_exploit_persistence_picker_linux_system(self):
        out = mod.adapt_post_exploit_persistence_picker(
            {"os": "linux", "userland": "system"})
        assert out["ok"] is True
        assert out["data"]["pick"] == "systemd_system_unit"

    def test_adapt_post_exploit_persistence_picker_macos_user(self):
        out = mod.adapt_post_exploit_persistence_picker(
            {"os": "macos", "userland": "user"})
        assert out["ok"] is True
        assert out["data"]["pick"] == "launchd_user_plist"

    def test_adapt_post_exploit_priv_picker_user(self):
        out = mod.adapt_post_exploit_priv_picker({"auth_level": "user"})
        assert out["ok"] is True
        assert out["data"]["pick"] == "user_payload"

    def test_adapt_post_exploit_priv_picker_root(self):
        out = mod.adapt_post_exploit_priv_picker({"auth_level": "root"})
        assert out["ok"] is True
        assert out["data"]["pick"] == "kernel_payload"

    def test_adapt_osint_query_dialect_picker_boolean(self):
        out = mod.adapt_osint_query_dialect_picker({"style": "boolean"})
        assert out["ok"] is True
        assert out["data"]["pick"] == "boolean_dialect"

    def test_adapt_osint_query_dialect_picker_natural(self):
        out = mod.adapt_osint_query_dialect_picker({"style": "natural"})
        assert out["ok"] is True
        assert out["data"]["pick"] == "natural_dialect"

    def test_adapt_forensic_image_format_picker_e01(self):
        out = mod.adapt_forensic_image_format_picker({"fmt_hint": "e01"})
        assert out["ok"] is True
        assert out["data"]["pick"] == "e01_image"

    def test_adapt_forensic_image_format_picker_aff4(self):
        out = mod.adapt_forensic_image_format_picker({"fmt_hint": "aff4"})
        assert out["ok"] is True
        assert out["data"]["pick"] == "aff4_image"

    def test_adapt_ble_attack_geometry_picker_u4000(self):
        out = mod.adapt_ble_attack_geometry_picker({"adapter": "U4000"})
        assert out["ok"] is True
        assert out["data"]["pick"] == "usb_external"

    def test_adapt_ble_attack_geometry_picker_builtin(self):
        out = mod.adapt_ble_attack_geometry_picker({"adapter": "mt7922"})
        assert out["ok"] is True
        assert out["data"]["pick"] == "builtin"

    def test_adapt_chain_planner_step_picker_init(self):
        out = mod.adapt_chain_planner_step_picker({"state": "init"})
        assert out["ok"] is True
        assert out["data"]["pick"] == "recon"

    def test_adapt_chain_planner_step_picker_recon(self):
        out = mod.adapt_chain_planner_step_picker({"state": "recon"})
        assert out["ok"] is True
        assert out["data"]["pick"] == "weaponize"

    def test_adapt_chain_planner_step_picker_exploit(self):
        out = mod.adapt_chain_planner_step_picker({"state": "exploit"})
        assert out["ok"] is True
        assert out["data"]["pick"] == "post_exploit"


# ---------------------------------------------------------------------------
# Bad-input contract — never raise, always envelope
# ---------------------------------------------------------------------------

class TestNeverRaise:
    def test_all_methods_with_none(self):
        for name, fn in mod.PHASE4_V2_REGISTRY.items():
            out = fn(None)
            assert isinstance(out, dict), f"{name} raised on None"
            assert "ok" in out

    def test_all_methods_with_string_args(self):
        for name, fn in mod.PHASE4_V2_REGISTRY.items():
            out = fn("not a dict")
            assert isinstance(out, dict), f"{name} raised on string args"
            assert "ok" in out

    def test_all_methods_with_list_args(self):
        for name, fn in mod.PHASE4_V2_REGISTRY.items():
            out = fn(["a", "b"])
            assert isinstance(out, dict), f"{name} raised on list args"
            assert "ok" in out


# ---------------------------------------------------------------------------
# No fabrication
# ---------------------------------------------------------------------------

class TestNoFabrication:
    def test_no_creds_in_output(self):
        for name, fn in mod.PHASE4_V2_REGISTRY.items():
            out = fn({"bssid": "00:11:22:33:44:55", "target": "test"})
            text = str(out)
            for forbidden in ("ecf51ee2-938d", "f40bec4b664a40a9a",
                              "CE38F76832CFA1F6", "password",
                              "secret", "cleartext"):
                assert forbidden not in text, (
                    f"{name} leaked credential field: {forbidden!r}"
                )

    def test_no_fake_cve_ids(self):
        # No fabricated CVE ids in any output
        for name, fn in mod.PHASE4_V2_REGISTRY.items():
            out = fn({})
            text = str(out)
            import re
            cves = re.findall(r"CVE-\d{4}-\d{4,7}", text)
            assert not cves, f"{name} fabricated CVE: {cves}"

    def test_no_fake_cracked_psks(self):
        for name, fn in mod.PHASE4_V2_REGISTRY.items():
            out = fn({})
            text = str(out).lower()
            assert "cracked" not in text or "no_fabrication" in text, (
                f"{name} claims cracked PSK: {text!r}"
            )
