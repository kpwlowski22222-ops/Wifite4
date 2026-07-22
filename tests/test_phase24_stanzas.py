"""Tests for core.ai_backend.phase24_stanzas (Phase 2.4 §G)."""
from __future__ import annotations

import pytest

from core.ai_backend.phase24_stanzas import (
    CATALOG_ENRICHMENT_V2_STANZA,
    DASHBOARD_PROMPT_STANZA,
    EXPLOIT_CHAIN_PROMPT_STANZA,
    POLY_ADAPT_PROMPT_STANZA,
    V3_METHODS_PROMPT_STANZA,
    all_phase24_stanzas,
)


# ---------------------------------------------------------------------------
# Shape checks
# ---------------------------------------------------------------------------

class TestStanzasShape:
    def test_v3_stanza_lists_every_category(self):
        for cat in ("wifi_attack", "wifi_recon", "ble_attack", "ble_recon",
                    "osint_web", "osint_people", "post_exploit"):
            assert cat in V3_METHODS_PROMPT_STANZA, f"missing {cat}"

    def test_poly_adapt_stanza_has_polymorphic(self):
        assert "POLYMORPHIC" in POLY_ADAPT_PROMPT_STANZA
        # 10 polymorphic names are present
        for n in ("poly_deauth_burst_pattern_grammar",
                  "poly_eapol_replay_grammar",
                  "poly_pmkid_eapol_field_grammar",
                  "poly_wps_eap_failure_grammar",
                  "poly_evil_twin_hostapd_conf_grammar",
                  "poly_passive_scan_channel_hop_grammar",
                  "poly_client_probe_request_grammar",
                  "poly_gatt_value_template",
                  "poly_hid_report_template",
                  "poly_adv_data_template_grammar"):
            assert n in POLY_ADAPT_PROMPT_STANZA, f"missing {n}"

    def test_poly_adapt_stanza_has_adaptive(self):
        assert "TARGET-ADAPTIVE" in POLY_ADAPT_PROMPT_STANZA
        for n in ("adapt_attack_deauth_strategy_picker",
                  "adapt_attack_wps_strategy_picker",
                  "adapt_attack_hid_strategy_picker",
                  "adapt_recon_adv_strategy_picker"):
            assert n in POLY_ADAPT_PROMPT_STANZA, f"missing {n}"

    def test_catalog_v2_stanza_mentions_minimums(self):
        assert "8-15" in CATALOG_ENRICHMENT_V2_STANZA
        assert "5-10" in CATALOG_ENRICHMENT_V2_STANZA
        assert "4-8" in CATALOG_ENRICHMENT_V2_STANZA
        assert "attack_surface" in CATALOG_ENRICHMENT_V2_STANZA
        assert "phase_hint" in CATALOG_ENRICHMENT_V2_STANZA
        assert "requires_hardware" in CATALOG_ENRICHMENT_V2_STANZA

    def test_dashboard_stanza_lists_endpoints(self):
        for ep in ("/api/session/<sid>/recommend",
                   "/api/session/<sid>/exfil",
                   "/api/session/<sid>/persistence",
                   "/upload/<sid>",
                   "/api/session/<sid>/report.pdf"):
            assert ep in DASHBOARD_PROMPT_STANZA, f"missing {ep}"

    def test_exploit_chain_stanza_mentions_nvd_key(self):
        assert "NVD" in EXPLOIT_CHAIN_PROMPT_STANZA
        assert "uncensored" in EXPLOIT_CHAIN_PROMPT_STANZA
        assert "offline" in EXPLOIT_CHAIN_PROMPT_STANZA.lower()
        # CVE ids that we own (honest references)
        assert "CVE-2021-34981" in EXPLOIT_CHAIN_PROMPT_STANZA
        assert "CVE-2020-26880" in EXPLOIT_CHAIN_PROMPT_STANZA

    def test_exploit_chain_stanza_mentions_pseudocode_only(self):
        # The LLM must understand the operator's "pseudocode only" rule
        assert "pseudocode" in EXPLOIT_CHAIN_PROMPT_STANZA.lower()


# ---------------------------------------------------------------------------
# Honest-degrade
# ---------------------------------------------------------------------------

class TestStanzasHonestDegrade:
    def test_v3_stanza_no_fabricated_cve(self):
        import re
        cves = re.findall(r"CVE-\d{4}-\d+", V3_METHODS_PROMPT_STANZA)
        allowed = {"CVE-2021-34981", "CVE-2020-26880"}
        unexpected = [c for c in cves if c not in allowed]
        assert not unexpected, f"unexpected CVE ids: {unexpected}"

    def test_poly_adapt_stanza_no_fabricated_cve(self):
        import re
        cves = re.findall(r"CVE-\d{4}-\d+", POLY_ADAPT_PROMPT_STANZA)
        assert not cves

    def test_dashboard_stanza_no_inline_creds(self):
        dl = DASHBOARD_PROMPT_STANZA.lower()
        for bad in ("password=", "hash=", "ntlm:"):
            assert bad not in dl

    def test_exploit_chain_stanza_no_inline_nvd_key(self):
        # The operator's NVD key must never appear inline
        assert "ecf51ee2-938d-44de-b015-896a3f6c758c" not in EXPLOIT_CHAIN_PROMPT_STANZA

    def test_exploit_chain_stanza_no_inline_ollama_key(self):
        # The operator's Ollama token must never appear inline
        assert "3d94e52cff9f4df5a01973f24d5bc8db" not in EXPLOIT_CHAIN_PROMPT_STANZA

    def test_no_version_shape_in_descriptions(self):
        import re
        for stanza in (V3_METHODS_PROMPT_STANZA, POLY_ADAPT_PROMPT_STANZA,
                       CATALOG_ENRICHMENT_V2_STANZA, DASHBOARD_PROMPT_STANZA,
                       EXPLOIT_CHAIN_PROMPT_STANZA):
            # The allowed v-shaped token is the model's own tag, not a
            # fake version of a tool.
            versions = re.findall(r"\bv\d+\.\d+\.\d+", stanza)
            assert not versions, f"version token in stanza: {versions[:3]}"


# ---------------------------------------------------------------------------
# Combined accessor
# ---------------------------------------------------------------------------

class TestAllStanzas:
    def test_all_combined_is_concatenation(self):
        combined = all_phase24_stanzas()
        for stanza in (V3_METHODS_PROMPT_STANZA, POLY_ADAPT_PROMPT_STANZA,
                       CATALOG_ENRICHMENT_V2_STANZA, DASHBOARD_PROMPT_STANZA,
                       EXPLOIT_CHAIN_PROMPT_STANZA):
            assert stanza in combined

    def test_combined_under_8k_tokens(self):
        # Rough heuristic: 1 token ~= 4 chars
        combined = all_phase24_stanzas()
        tokens = len(combined) // 4
        assert tokens < 8192, f"combined stanzas ~{tokens} tokens (cap 8192)"


# ---------------------------------------------------------------------------
# Integration with chain.py
# ---------------------------------------------------------------------------

class TestChainIntegration:
    def test_chain_imports_all_stanzas(self):
        # Force chain.py to import
        from core.ai_backend import chain
        # Each stanza should be a string attribute
        for attr in ("V3_METHODS_PROMPT_STANZA",
                     "POLY_ADAPT_PROMPT_STANZA",
                     "CATALOG_ENRICHMENT_V2_STANZA",
                     "DASHBOARD_PROMPT_STANZA",
                     "EXPLOIT_CHAIN_PROMPT_STANZA"):
            assert hasattr(chain, attr), f"chain.{attr} missing"
            val = getattr(chain, attr)
            assert isinstance(val, str) and val

    def test_chain_includes_stanzas_in_system_prompt(self):
        from core.ai_backend import chain
        # Build a minimal system prompt by reading the template
        # The _build_system_prompt function is referenced from the
        # chain. We just verify that the 5 stanzas are referenced
        # in the source.
        import inspect
        src = inspect.getsource(chain)
        for var in ("V3_METHODS_PROMPT_STANZA",
                    "POLY_ADAPT_PROMPT_STANZA",
                    "CATALOG_ENRICHMENT_V2_STANZA",
                    "DASHBOARD_PROMPT_STANZA",
                    "EXPLOIT_CHAIN_PROMPT_STANZA"):
            assert var in src, f"chain.py does not reference {var}"
