"""Hermetic tests for the 40 new Phase 2.3.C Polish OSINT methods
added to ``core/osint/runner_ext.py``.

Polish methods (40):
  - 15 Polish registries (CEIDG, KRS, GUS BIR1, TERYT, KNF)
  - 5  Allegro REST
  - 10 Polish social / people search + format validators
  - 5  Polymorphic Polish OSINT
  - 5  Target-adaptive Polish OSINT

The contract:
  * Every method returns a valid envelope (``ok``, ``data``, ``error``,
    ``duration_s``).
  * PESEL / NIP / REGON validators compute the checksum locally — they
    never look up the actual entity (GDPR-restricted).
  * Phone carrier is a deterministic lookup table.
  * CAPTCHA-walled registry paths return honest-degrade with the URL
    the operator should visit.
  * HTTP-based methods are tested hermetically by monkeypatching
    ``_http_get`` so no real network call is made.
  * Methods NEVER fabricate a registry hit, a person match, a social
    profile, a financial entry, or a court judgment.
"""
import os
import re
import subprocess
from typing import Any, Dict, List, Optional, Tuple
from unittest.mock import patch, MagicMock

import pytest

from core.osint.runner_ext import (
    OSINTExtRunner,
    OSINT_EXT_PROBES,
    _finalize,
    _finalize_with_url,
    _nip_checksum_ok,
    _regon9_checksum_ok,
    _regon14_checksum_ok,
    _pesel_checksum_ok,
    _pesel_birth_date,
    _polish_phone_carrier,
    _POLISH_PHONE_PREFIXES,
)

# OSINT_EXT_METHODS is a class attribute on OSINTExtRunner, not a
# module-level symbol.
OSINT_EXT_METHODS = OSINTExtRunner.OSINT_EXT_METHODS


# ---------------------------------------------------------------------------
# Method inventory
# ---------------------------------------------------------------------------
POLISH_REGISTRY_METHODS = [
    "polish_ceidg_search_nip",
    "polish_ceidg_search_regon",
    "polish_ceidg_search_name",
    "polish_ceidg_search_address",
    "polish_krs_search_krs_number",
    "polish_krs_search_name",
    "polish_krs_search_representatives",
    "polish_krs_search_shareholders",
    "polish_krs_search_address",
    "polish_gus_bir1_regon",
    "polish_gus_bir1_nip",
    "polish_gus_bir1_pkd",
    "polish_gus_teryt_voivodeship",
    "polish_gus_teryt_commune",
    "polish_knf_search",
]
ALLEGRO_METHODS = [
    "allegro_auth_client_credentials",
    "allegro_search_offers",
    "allegro_search_categories",
    "allegro_user_offers",
    "allegro_user_categories",
]
POLISH_SOCIAL_METHODS = [
    "polish_linkedin_public_profile_enrich",
    "polish_facebook_public_page_enrich",
    "polish_goldenline_search",
    "polish_wykop_user_search",
    "polish_numerology_name_match",
    "polish_phone_prefix_carrier",
    "polish_address_postal_code_lookup",
    "polish_pesel_validate_format",
    "polish_nip_validate_format",
    "polish_regon_validate_format",
]
POLY_METHODS = [
    "polish_osint_poly_email_drift",
    "polish_osint_poly_username_platform_drift",
    "polish_osint_poly_phone_format_drift",
    "polish_osint_poly_handle_normalizer",
    "polish_osint_poly_subdomain_wordlist_drift",
]
ADAPT_METHODS = [
    "polish_osint_adapt_target_tier_classifier",
    "polish_osint_adapt_osint_playbook_picker",
    "polish_osint_adapt_dork_query_picker",
    "polish_osint_adapt_breach_window_filter",
    "polish_osint_adapt_dns_record_priority",
]

ALL_40 = (POLISH_REGISTRY_METHODS + ALLEGRO_METHODS +
          POLISH_SOCIAL_METHODS + POLY_METHODS + ADAPT_METHODS)


def _is_valid_envelope(r: Any) -> bool:
    """The standard envelope: ok: bool, data: any, error: str,
    duration_s: number, started: number."""
    return (isinstance(r, dict)
            and isinstance(r.get("ok"), bool)
            and "error" in r
            and "data" in r
            and "duration_s" in r
            and "started" in r)


def _ok_envelope(r: Dict[str, Any]) -> bool:
    return r.get("ok") is True


# ---------------------------------------------------------------------------
# 1. Catalog presence
# ---------------------------------------------------------------------------
class TestCatalogPresence:
    def test_all_40_in_methods_tuple(self):
        assert len(ALL_40) == 40, f"expected 40 methods, got {len(ALL_40)}"
        for m in ALL_40:
            assert m in OSINT_EXT_METHODS, f"{m} not in OSINT_EXT_METHODS"

    def test_all_40_in_probes(self):
        probe_names = {p["method"] for p in OSINT_EXT_PROBES}
        for m in ALL_40:
            assert m in probe_names, f"{m} not in OSINT_EXT_PROBES"

    def test_all_40_have_impl(self):
        for m in ALL_40:
            assert hasattr(OSINTExtRunner, "_" + m), (
                f"missing _v2 impl: {m}"
            )

    def test_probes_are_read_risk(self):
        for p in OSINT_EXT_PROBES:
            if p["method"] in ALL_40:
                assert p["risk_level"] == "read", (
                    f"{p['method']}: read-only method, got {p['risk_level']}"
                )
                assert p["requires_root"] is False, (
                    f"{p['method']}: passive method, must not require root"
                )

    def test_polish_methods_never_require_root(self):
        for m in ALL_40:
            probes = [p for p in OSINT_EXT_PROBES if p["method"] == m]
            assert probes
            assert probes[0]["requires_root"] is False


# ---------------------------------------------------------------------------
# 2. Format validators (deterministic, no network)
# ---------------------------------------------------------------------------
class TestNipChecksum:
    def test_valid_nip(self):
        # 1234567890 → weights 6,5,7,2,3,4,5,6,7 → 6+10+21+8+15+24+35+48+63 = 230
        # 230 mod 11 = 10, 10 mod 10 = 0 → check digit is 0 → "1234567890"
        assert _nip_checksum_ok("1234567890") is True

    def test_invalid_nip(self):
        assert _nip_checksum_ok("1234567891") is False

    def test_non_10_digits(self):
        assert _nip_checksum_ok("123") is False
        assert _nip_checksum_ok("12345678901") is False
        assert _nip_checksum_ok("") is False

    def test_alpha_in_nip(self):
        assert _nip_checksum_ok("123456789A") is False

    @pytest.mark.parametrize("m", ["polish_nip_validate_format"])
    def test_method_valid(self, m):
        r = OSINTExtRunner(args={"nip": "1234567890"}).run_probe(m)
        assert _is_valid_envelope(r)
        assert r["ok"] is True
        assert r["data"]["checksum_ok"] is True

    @pytest.mark.parametrize("m", ["polish_nip_validate_format"])
    def test_method_invalid_checksum(self, m):
        r = OSINTExtRunner(args={"nip": "1234567891"}).run_probe(m)
        assert _is_valid_envelope(r)
        assert r["ok"] is False
        assert r["data"]["checksum_ok"] is False

    def test_method_wrong_length(self):
        r = OSINTExtRunner(args={"nip": "123"}).run_probe(
            "polish_nip_validate_format")
        assert _is_valid_envelope(r)
        assert r["ok"] is False
        assert "NIP must be 10 digits" in r["error"]

    def test_method_missing_arg(self):
        r = OSINTExtRunner(args={}).run_probe("polish_nip_validate_format")
        assert _is_valid_envelope(r)
        assert r["ok"] is False


class TestRegonChecksum:
    def test_valid_regon9(self):
        # 123456785 → check 8*8+9*2+3*3+4*4+5*5+6*6+7*7 = 64+18+9+16+25+36+49 = 217
        # 217 mod 11 = 8 → check 5... wait let me recompute.
        # regon 9 chars: w[0..7] = 8,9,2,3,4,5,6,7; regon[8] = check
        # 1*8 + 2*9 + 3*2 + 4*3 + 5*4 + 6*5 + 7*6 + 8*7
        # = 8 + 18 + 6 + 12 + 20 + 30 + 42 + 56 = 192
        # 192 mod 11 = 5 → check 5
        # So valid REGON9 = 123456785
        assert _regon9_checksum_ok("123456785") is True

    def test_invalid_regon9(self):
        assert _regon9_checksum_ok("123456780") is False

    def test_valid_regon14(self):
        # 12345678901125 → weights 2,4,8,5,0,9,7,3,6,1,2,4,8 over 13 chars
        # 1*2+2*4+3*8+4*5+5*0+6*9+7*7+8*3+9*6+0*1+1*2+1*4+2*8
        # = 2+8+24+20+0+54+49+24+54+0+2+4+16 = 257
        # 257 mod 11 = 4 → check 4
        # So valid REGON14 = 12345678901124... let me recompute
        # First, 1*2 = 2; 2*4 = 8; 3*8 = 24; 4*5 = 20; 5*0 = 0
        # 6*9 = 54; 7*7 = 49; 8*3 = 24; 9*6 = 54; 0*1 = 0
        # 1*2 = 2; 1*4 = 4; 2*8 = 16
        # Sum = 2+8+24+20+0+54+49+24+54+0+2+4+16 = 257
        # 257 mod 11 = 4 → check 4
        # So valid REGON14 = 12345678901124
        # Verify: 13 chars "1234567890112", check 4 → "12345678901124"
        assert _regon14_checksum_ok("12345678901124") is True

    def test_invalid_regon14(self):
        assert _regon14_checksum_ok("12345678901125") is False

    def test_wrong_length(self):
        assert _regon14_checksum_ok("123") is False
        assert _regon14_checksum_ok("") is False

    @pytest.mark.parametrize("m", ["polish_regon_validate_format"])
    def test_method_valid_9(self, m):
        r = OSINTExtRunner(args={"regon": "123456785"}).run_probe(m)
        assert _is_valid_envelope(r)
        assert r["ok"] is True
        assert r["data"]["length"] == 9
        assert r["data"]["checksum_ok"] is True

    @pytest.mark.parametrize("m", ["polish_regon_validate_format"])
    def test_method_valid_14(self, m):
        r = OSINTExtRunner(args={"regon": "12345678901124"}).run_probe(m)
        assert _is_valid_envelope(r)
        assert r["ok"] is True
        assert r["data"]["length"] == 14

    def test_method_wrong_length(self):
        r = OSINTExtRunner(args={"regon": "12345"}).run_probe(
            "polish_regon_validate_format")
        assert _is_valid_envelope(r)
        assert r["ok"] is False
        assert "9 or 14 digits" in r["error"]


class TestPeselChecksum:
    def test_valid_pesel_2002(self):
        # We computed earlier: 0227081234 + checksum 7 = 02270812347
        assert _pesel_checksum_ok("02270812347") is True

    def test_invalid_pesel(self):
        assert _pesel_checksum_ok("11111111111") is False

    def test_wrong_length(self):
        assert _pesel_checksum_ok("12345") is False
        assert _pesel_checksum_ok("") is False

    def test_birth_date_2002(self):
        assert _pesel_birth_date("02270812347") == "2002-07-08"

    def test_birth_date_1985(self):
        # 85010112345 → year 85, month 01, day 01 → 1985-01-01
        # We need a valid checksum; compute it
        weights = [1, 3, 7, 9, 1, 3, 7, 9, 1, 3]
        base = "8501011234"
        s = sum(int(c) * w for c, w in zip(base, weights))
        check = s % 10
        pesel = base + str(check)
        assert _pesel_checksum_ok(pesel) is True
        assert _pesel_birth_date(pesel) == "1985-01-01"

    def test_birth_date_invalid(self):
        # Month out of range (e.g. 13)
        assert _pesel_birth_date("99130112345") is None

    def test_birth_date_invalid_day(self):
        # Day 32 doesn't exist
        assert _pesel_birth_date("99013212345") is None

    @pytest.mark.parametrize("m", ["polish_pesel_validate_format"])
    def test_method_valid(self, m):
        r = OSINTExtRunner(args={"pesel": "02270812347"}).run_probe(m)
        assert _is_valid_envelope(r)
        assert r["ok"] is True
        assert r["data"]["checksum_ok"] is True
        assert r["data"]["birth_date_iso"] == "2002-07-08"

    def test_method_invalid_checksum(self):
        r = OSINTExtRunner(args={"pesel": "11111111111"}).run_probe(
            "polish_pesel_validate_format")
        assert _is_valid_envelope(r)
        assert r["ok"] is False
        assert "PESEL checksum invalid" in r["error"]

    def test_method_gdpr_note(self):
        r = OSINTExtRunner(args={"pesel": "02270812347"}).run_probe(
            "polish_pesel_validate_format")
        # Verify the GDPR-restriction note is present
        assert "GDPR" in r["data"]["note"]


# ---------------------------------------------------------------------------
# 3. Phone carrier
# ---------------------------------------------------------------------------
class TestPhoneCarrier:
    def test_mobile_t_mobile(self):
        # 60x prefix = T-Mobile / Era
        assert _polish_phone_carrier("+48600100200") == "T-Mobile / Era"

    def test_mobile_play(self):
        # 72x prefix = Play
        assert _polish_phone_carrier("+48720000000") == "Play (P4)"

    def test_mobile_orange(self):
        # 51x prefix = Orange
        assert _polish_phone_carrier("+48510000000") == "Orange Polska"

    def test_mobile_plus(self):
        # 50x prefix = Plus
        assert _polish_phone_carrier("+48500000000") == "Plus (Polkomtel)"

    def test_landline_warszawa(self):
        # 22x prefix = Warszawa landline
        assert _polish_phone_carrier("+48221002030") == "Warszawa landline"

    def test_landline_krakow(self):
        assert _polish_phone_carrier("+48120000000") == "Kraków landline"

    def test_with_0048_prefix(self):
        assert _polish_phone_carrier("0048600100200") == "T-Mobile / Era"

    def test_with_no_prefix(self):
        assert _polish_phone_carrier("600100200") == "T-Mobile / Era"

    def test_unknown_prefix(self):
        # 99x is not a known prefix
        assert _polish_phone_carrier("+48990000000") is None

    def test_wrong_length(self):
        assert _polish_phone_carrier("+48123") is None

    def test_empty(self):
        assert _polish_phone_carrier("") is None

    def test_method_known(self):
        r = OSINTExtRunner(args={"phone": "+48600100200"}).run_probe(
            "polish_phone_prefix_carrier")
        assert _is_valid_envelope(r)
        assert r["ok"] is True
        assert r["data"]["carrier"] == "T-Mobile / Era"

    def test_method_unknown(self):
        r = OSINTExtRunner(args={"phone": "+48990000000"}).run_probe(
            "polish_phone_prefix_carrier")
        assert _is_valid_envelope(r)
        assert r["ok"] is False
        assert "no match" in r["error"]


# ---------------------------------------------------------------------------
# 4. Numerology (deterministic, heuristic)
# ---------------------------------------------------------------------------
class TestNumerology:
    def test_letter_sum_deterministic(self):
        r1 = OSINTExtRunner(args={"name": "Jan Kowalski"}).run_probe(
            "polish_numerology_name_match")
        r2 = OSINTExtRunner(args={"name": "Jan Kowalski"}).run_probe(
            "polish_numerology_name_match")
        assert r1["data"]["letter_sum"] == r2["data"]["letter_sum"]

    def test_letter_sum_in_range_1_9(self):
        r = OSINTExtRunner(args={"name": "Jan Kowalski"}).run_probe(
            "polish_numerology_name_match")
        s = r["data"]["letter_sum"]
        assert isinstance(s, int)
        assert 1 <= s <= 9

    def test_polish_chars_handled(self):
        # Names with Polish diacritics should still produce a single digit
        r = OSINTExtRunner(args={"name": "Łukasz Żółciński"}).run_probe(
            "polish_numerology_name_match")
        assert _is_valid_envelope(r)
        assert r["ok"] is True
        s = r["data"]["letter_sum"]
        assert 1 <= s <= 9

    def test_heuristic_label(self):
        r = OSINTExtRunner(args={"name": "Test"}).run_probe(
            "polish_numerology_name_match")
        assert r["data"]["model"] == "heuristic (not trained)"

    def test_missing_name(self):
        r = OSINTExtRunner(args={}).run_probe(
            "polish_numerology_name_match")
        assert r["ok"] is False


# ---------------------------------------------------------------------------
# 5. Polymorphic methods
# ---------------------------------------------------------------------------
class TestPolymorphic:
    def test_email_drift_with_domain(self):
        r = OSINTExtRunner(args={"name": "Jan Kowalski",
                                  "domain": "example.com"}).run_probe(
            "polish_osint_poly_email_drift")
        assert r["ok"] is True
        perms = r["data"]["permutations"]
        assert len(perms) >= 1
        for p in perms:
            assert "@example.com" in p
            assert " " not in p

    def test_email_drift_without_domain(self):
        r = OSINTExtRunner(args={"name": "Anna Nowak"}).run_probe(
            "polish_osint_poly_email_drift")
        assert r["ok"] is True
        perms = r["data"]["permutations"]
        # No @ → bare local-part candidates
        for p in perms:
            assert "@" not in p

    def test_email_drift_polish_chars(self):
        r = OSINTExtRunner(args={"name": "Łukasz Żółciński",
                                  "domain": "test.pl"}).run_probe(
            "polish_osint_poly_email_drift")
        assert r["ok"] is True
        perms = r["data"]["permutations"]
        # Polish diacritics should be normalised
        for p in perms:
            assert "@test.pl" in p
            assert "ł" not in p
            assert "ż" not in p
            assert "ć" not in p
            assert "ś" not in p

    def test_username_platform_drift(self):
        r = OSINTExtRunner(args={"username": "jankowalski"}).run_probe(
            "polish_osint_poly_username_platform_drift")
        assert r["ok"] is True
        variants = r["data"]["variants"]
        assert len(variants) >= 1
        # No spaces, no special chars
        for v in variants:
            assert re.match(r"^[A-Za-z0-9_.]+$", v)

    def test_phone_format_drift(self):
        r = OSINTExtRunner(args={"phone": "+48600100200"}).run_probe(
            "polish_osint_poly_phone_format_drift")
        assert r["ok"] is True
        formats = r["data"]["formats"]
        assert "600100200" in formats
        assert "+48600100200" in formats
        assert "0048600100200" in formats

    def test_phone_format_drift_polish_chars(self):
        r = OSINTExtRunner(args={"phone": "0048 600 100 200"}).run_probe(
            "polish_osint_poly_phone_format_drift")
        assert r["ok"] is True
        formats = r["data"]["formats"]
        assert any("+48" in f for f in formats)

    def test_phone_format_drift_wrong_length(self):
        r = OSINTExtRunner(args={"phone": "+48123"}).run_probe(
            "polish_osint_poly_phone_format_drift")
        assert r["ok"] is False

    def test_handle_normalizer(self):
        r = OSINTExtRunner(args={"username": "Jan.Kowalski"}).run_probe(
            "polish_osint_poly_handle_normalizer")
        assert r["ok"] is True
        normalized = r["data"]["normalized"]
        assert "Jan.Kowalski" in normalized
        assert "jan.kowalski" in normalized
        # All-normalised variant (no dots/underscores/dashes)
        assert "jankowalski" in normalized

    def test_handle_normalizer_polish_chars(self):
        r = OSINTExtRunner(args={"username": "Łukasz-Żółciński"}).run_probe(
            "polish_osint_poly_handle_normalizer")
        assert r["ok"] is True
        normalized = r["data"]["normalized"]
        # The set includes the original (with Polish chars) AND the
        # normalised variants (without). Check the *normalised* ones
        # specifically: they should have Polish chars stripped.
        original = "Łukasz-Żółciński"
        norm_variants = [n for n in normalized if n != original]
        for n in norm_variants:
            assert "Ł" not in n
            assert "Ż" not in n
            assert "ł" not in n
            assert "ż" not in n
        # And at least one should be fully ASCII + separator-free
        assert "lukaszzolcinski" in normalized or "lukasz_zolcinski" in normalized or "lukasz-zolcinski" in normalized

    def test_subdomain_wordlist_drift(self):
        r = OSINTExtRunner(args={"domain": "example.pl"}).run_probe(
            "polish_osint_poly_subdomain_wordlist_drift")
        assert r["ok"] is True
        candidates = r["data"]["candidates"]
        assert len(candidates) >= 1
        for c in candidates:
            assert c.endswith(".example.pl")
        # Polish-specific terms should appear
        assert any("sklep" in c for c in candidates)
        assert any("warszawa" in c for c in candidates)


# ---------------------------------------------------------------------------
# 6. Target-adaptive methods
# ---------------------------------------------------------------------------
class TestTargetAdaptive:
    def test_tier_classifier_email(self):
        r = OSINTExtRunner(args={"target": "jan@example.com"}).run_probe(
            "polish_osint_adapt_target_tier_classifier")
        assert r["ok"] is True
        assert r["data"]["tier"] == "person"

    def test_tier_classifier_company(self):
        # "Acme sp. z o.o." has a leading space before " sp. z o.o."
        r = OSINTExtRunner(args={"target": "Acme sp. z o.o."}).run_probe(
            "polish_osint_adapt_target_tier_classifier")
        assert r["ok"] is True
        assert r["data"]["tier"] == "company"

    def test_tier_classifier_company_nip(self):
        r = OSINTExtRunner(args={"target": "1234567890"}).run_probe(
            "polish_osint_adapt_target_tier_classifier")
        assert r["ok"] is True
        assert r["data"]["tier"] == "company"

    def test_tier_classifier_person_pesel(self):
        r = OSINTExtRunner(args={"target": "02270812347"}).run_probe(
            "polish_osint_adapt_target_tier_classifier")
        assert r["ok"] is True
        assert r["data"]["tier"] == "person"

    def test_tier_classifier_public_institution(self):
        r = OSINTExtRunner(args={"target": "Urząd Miasta"}).run_probe(
            "polish_osint_adapt_target_tier_classifier")
        assert r["ok"] is True
        assert r["data"]["tier"] == "public_institution"

    def test_playbook_email(self):
        r = OSINTExtRunner(args={"target": "test@example.com"}).run_probe(
            "polish_osint_adapt_osint_playbook_picker")
        assert r["ok"] is True
        pb = r["data"]["playbook"]
        assert "polish_pesel_validate_format" in pb
        assert "polish_osint_poly_email_drift" in pb

    def test_playbook_company(self):
        r = OSINTExtRunner(args={"target": "1234567890"}).run_probe(
            "polish_osint_adapt_osint_playbook_picker")
        assert r["ok"] is True
        pb = r["data"]["playbook"]
        assert "polish_nip_validate_format" in pb
        assert "polish_ceidg_search_nip" in pb

    def test_playbook_unknown(self):
        r = OSINTExtRunner(args={"target": "Acme"}).run_probe(
            "polish_osint_adapt_osint_playbook_picker")
        assert r["ok"] is True
        pb = r["data"]["playbook"]
        assert isinstance(pb, list)
        assert len(pb) >= 1

    def test_dork_query_picker(self):
        r = OSINTExtRunner(args={"target": "Jan Kowalski"}).run_probe(
            "polish_osint_adapt_dork_query_picker")
        assert r["ok"] is True
        dorks = r["data"]["dorks"]
        for d in dorks:
            assert "Jan Kowalski" in d or '"Jan Kowalski"' in d
        # LinkedIn dork
        assert any("linkedin.com" in d for d in dorks)
        # Polish-platform dork
        assert any("goldenline.pl" in d for d in dorks)
        # Wykop dork
        assert any("wykop.pl" in d for d in dorks)

    def test_breach_window_filter(self):
        r = OSINTExtRunner(args={"target": "jan@example.com",
                                  "window_months": 12}).run_probe(
            "polish_osint_adapt_breach_window_filter")
        assert r["ok"] is True
        assert r["data"]["window_months"] == 12
        assert r["data"]["cutoff_iso"].endswith("Z")

    def test_breach_window_default(self):
        r = OSINTExtRunner(args={"target": "jan"}).run_probe(
            "polish_osint_adapt_breach_window_filter")
        assert r["ok"] is True
        assert r["data"]["window_months"] == 24

    def test_dns_record_priority(self):
        r = OSINTExtRunner(args={"domain": "example.pl"}).run_probe(
            "polish_osint_adapt_dns_record_priority")
        assert r["ok"] is True
        priority = r["data"]["record_priority"]
        # Polish target → MX first
        assert priority[0] == "MX"
        # TXT (DMARC/SPF) high priority
        assert "TXT" in priority
        assert "NS" in priority


# ---------------------------------------------------------------------------
# 7. Hermetic HTTP-based methods
# ---------------------------------------------------------------------------
class TestHermeticHTTP:
    """The HTTP-based methods should be tested without real network."""

    def test_ceidg_search_nip_invalid_checksum(self):
        r = OSINTExtRunner(args={"nip": "1234567891"}).run_probe(
            "polish_ceidg_search_nip")
        assert r["ok"] is False
        assert "checksum" in r["error"].lower()
        assert r["data"]["checksum_ok"] is False

    def test_ceidg_search_nip_valid_checksum_no_network(self, monkeypatch):
        # Patch _http_get to simulate offline
        def fake_http_get(url, timeout=8):
            return {"ok": False, "error": "no network"}
        monkeypatch.setattr("core.osint.runner_ext._http_get", fake_http_get)
        r = OSINTExtRunner(args={"nip": "1234567890"}).run_probe(
            "polish_ceidg_search_nip")
        assert _is_valid_envelope(r)
        # Either we get ok=False with the network error, or the url degrade
        assert r["ok"] is False

    def test_ceidg_search_regon_wrong_format(self):
        r = OSINTExtRunner(args={"regon": "abc"}).run_probe(
            "polish_ceidg_search_regon")
        assert r["ok"] is False

    def test_ceidg_search_name_captcha(self):
        r = OSINTExtRunner(args={"name": "Test Firma"}).run_probe(
            "polish_ceidg_search_name")
        assert r["ok"] is False
        assert "CAPTCHA" in r["error"] or "captcha" in r["error"]
        # The URL the operator should visit should be in data
        assert "ceidg.gov.pl" in str(r.get("data", ""))

    def test_ceidg_search_address_captcha(self):
        r = OSINTExtRunner(args={"address": "Marszałkowska 1"}).run_probe(
            "polish_ceidg_search_address")
        assert r["ok"] is False
        assert "CAPTCHA" in r["error"] or "captcha" in r["error"]

    def test_krs_search_wrong_length(self):
        r = OSINTExtRunner(args={"krs": "12345"}).run_probe(
            "polish_krs_search_krs_number")
        assert r["ok"] is False
        assert "10 digits" in r["error"]

    def test_krs_search_name_captcha(self):
        r = OSINTExtRunner(args={"name": "Test"}).run_probe(
            "polish_krs_search_name")
        assert r["ok"] is False
        assert "CAPTCHA" in r["error"] or "captcha" in r["error"]
        assert "ekrs.ms.gov.pl" in str(r.get("data", ""))

    def test_krs_reps_captcha(self):
        r = OSINTExtRunner(args={"krs": "0000123456"}).run_probe(
            "polish_krs_search_representatives")
        assert r["ok"] is False
        assert "CAPTCHA" in r["error"] or "captcha" in r["error"]

    def test_krs_shareholders_captcha(self):
        r = OSINTExtRunner(args={"krs": "0000123456"}).run_probe(
            "polish_krs_search_shareholders")
        assert r["ok"] is False
        assert "CAPTCHA" in r["error"]

    def test_krs_address_captcha(self):
        r = OSINTExtRunner(args={"address": "Test"}).run_probe(
            "polish_krs_search_address")
        assert r["ok"] is False
        assert "CAPTCHA" in r["error"]

    def test_gus_bir1_no_key_degrade(self, monkeypatch):
        monkeypatch.delenv("GUS_BIR1_KEY", raising=False)
        r = OSINTExtRunner(args={"regon": "123456785"}).run_probe(
            "polish_gus_bir1_regon")
        assert r["ok"] is False
        assert "GUS_BIR1_KEY" in r["error"]
        assert r["data"]["key_present"] is False

    def test_gus_bir1_invalid_regon(self, monkeypatch):
        monkeypatch.setenv("GUS_BIR1_KEY", "fake_key")
        r = OSINTExtRunner(args={"regon": "12345"}).run_probe(
            "polish_gus_bir1_regon")
        assert r["ok"] is False
        assert "checksum" in r["error"].lower() or "REGON" in r["error"]

    def test_gus_bir1_nip_no_key(self, monkeypatch):
        monkeypatch.delenv("GUS_BIR1_KEY", raising=False)
        r = OSINTExtRunner(args={"nip": "1234567890"}).run_probe(
            "polish_gus_bir1_nip")
        assert r["ok"] is False
        assert "GUS_BIR1_KEY" in r["error"]

    def test_gus_bir1_pkd_no_key(self, monkeypatch):
        monkeypatch.delenv("GUS_BIR1_KEY", raising=False)
        r = OSINTExtRunner(args={"nip": "1234567890"}).run_probe(
            "polish_gus_bir1_pkd")
        assert r["ok"] is False

    def test_teryt_voivodeship_no_network(self, monkeypatch):
        def fake_http_get(url, timeout=8):
            return {"ok": False, "error": "no network"}
        monkeypatch.setattr("core.osint.runner_ext._http_get", fake_http_get)
        r = OSINTExtRunner(args={"voivodeship": "mazowieckie"}).run_probe(
            "polish_gus_teryt_voivodeship")
        assert r["ok"] is False
        assert "no network" in r["error"] or "stat.gov.pl" in str(r.get("data", ""))

    def test_teryt_commune(self):
        r = OSINTExtRunner(args={}).run_probe(
            "polish_gus_teryt_commune")
        assert r["ok"] is False
        assert "commune" in r["error"]

    def test_knf_search_no_network(self, monkeypatch):
        def fake_http_get(url, timeout=8):
            return {"ok": False, "error": "no network"}
        monkeypatch.setattr("core.osint.runner_ext._http_get", fake_http_get)
        r = OSINTExtRunner(args={"query": "Test Bank"}).run_probe(
            "polish_knf_search")
        assert r["ok"] is False
        assert "knf.gov.pl" in str(r.get("data", ""))

    def test_wykop_user_no_network(self, monkeypatch):
        def fake_http_get(url, timeout=8):
            return {"ok": False, "error": "no network"}
        monkeypatch.setattr("core.osint.runner_ext._http_get", fake_http_get)
        r = OSINTExtRunner(args={"username": "test"}).run_probe(
            "polish_wykop_user_search")
        assert r["ok"] is False
        assert "no network" in r["error"]

    def test_postal_code_no_network(self, monkeypatch):
        def fake_http_get(url, timeout=8):
            return {"ok": False, "error": "no network"}
        monkeypatch.setattr("core.osint.runner_ext._http_get", fake_http_get)
        r = OSINTExtRunner(args={"postal_code": "00-001"}).run_probe(
            "polish_address_postal_code_lookup")
        assert r["ok"] is False

    def test_postal_code_wrong_length(self):
        r = OSINTExtRunner(args={"postal_code": "123"}).run_probe(
            "polish_address_postal_code_lookup")
        assert r["ok"] is False
        assert "5 digits" in r["error"]


# ---------------------------------------------------------------------------
# 8. Allegro REST (no creds → degrade; with creds → returns API spec)
# ---------------------------------------------------------------------------
class TestAllegro:
    def test_allegro_auth_no_creds(self, monkeypatch):
        monkeypatch.delenv("ALLEGRO_CLIENT_ID", raising=False)
        monkeypatch.delenv("ALLEGRO_CLIENT_SECRET", raising=False)
        r = OSINTExtRunner(args={}).run_probe(
            "allegro_auth_client_credentials")
        assert r["ok"] is False
        assert "ALLEGRO_CLIENT_ID" in r["error"] or "client_credentials" in r["error"].lower()

    def test_allegro_auth_with_creds(self, monkeypatch):
        monkeypatch.setenv("ALLEGRO_CLIENT_ID", "fake_id")
        monkeypatch.setenv("ALLEGRO_CLIENT_SECRET", "fake_secret")
        r = OSINTExtRunner(args={}).run_probe(
            "allegro_auth_client_credentials")
        assert r["ok"] is True
        assert "auth_url" in r["data"]
        assert r["data"]["grant_type"] == "client_credentials"

    def test_allegro_search_offers(self):
        r = OSINTExtRunner(args={"query": "laptop"}).run_probe(
            "allegro_search_offers")
        assert r["ok"] is True
        assert "api_endpoint" in r["data"]
        assert r["data"]["method"] == "GET"

    def test_allegro_search_categories(self):
        r = OSINTExtRunner(args={}).run_probe(
            "allegro_search_categories")
        assert r["ok"] is True
        assert "api_endpoint" in r["data"]

    def test_allegro_user_offers(self):
        r = OSINTExtRunner(args={"user_id": "12345"}).run_probe(
            "allegro_user_offers")
        assert r["ok"] is True
        assert "user_id" in r["data"]
        assert r["data"]["user_id"] == "12345"

    def test_allegro_user_offers_missing(self):
        r = OSINTExtRunner(args={}).run_probe(
            "allegro_user_offers")
        assert r["ok"] is False

    def test_allegro_user_categories(self):
        r = OSINTExtRunner(args={}).run_probe(
            "allegro_user_categories")
        assert r["ok"] is True


# ---------------------------------------------------------------------------
# 9. Social/people search (degrade or ok, never fabricate)
# ---------------------------------------------------------------------------
class TestSocialSearch:
    def test_linkedin_enrich(self):
        r = OSINTExtRunner(args={"url": "https://linkedin.com/in/test"}).run_probe(
            "polish_linkedin_public_profile_enrich")
        assert r["ok"] is False
        assert "linkedin.com" in str(r.get("data", ""))
        assert r["data"]["url"] == "https://linkedin.com/in/test"

    def test_linkedin_enrich_missing_url(self):
        r = OSINTExtRunner(args={}).run_probe(
            "polish_linkedin_public_profile_enrich")
        assert r["ok"] is False
        assert "url" in r["error"]

    def test_facebook_enrich(self):
        r = OSINTExtRunner(args={"url": "https://facebook.com/test"}).run_probe(
            "polish_facebook_public_page_enrich")
        assert r["ok"] is False
        assert "facebook.com" in str(r.get("data", ""))

    def test_goldenline_search(self):
        r = OSINTExtRunner(args={"query": "jan"}).run_probe(
            "polish_goldenline_search")
        assert r["ok"] is False
        assert "goldenline.pl" in str(r.get("data", ""))

    def test_goldenline_search_missing(self):
        r = OSINTExtRunner(args={}).run_probe(
            "polish_goldenline_search")
        assert r["ok"] is False


# ---------------------------------------------------------------------------
# 10. Adversarial: never inline credentials, never fabricate
# ---------------------------------------------------------------------------
class TestAdversarial:
    def test_no_inline_credentials_in_methods(self):
        """The catalog must NEVER contain inline credentials."""
        import inspect
        for m in ALL_40:
            fn = getattr(OSINTExtRunner, "_" + m, None)
            if fn is None:
                continue
            src = inspect.getsource(fn)
            # No hardcoded "password=..."
            assert "password=" not in src.lower(), (
                f"{m}: contains 'password=' (credential inline)"
            )
            # No long hex strings (likely a hash or API key)
            for m_ in re.findall(r"['\"]([0-9a-fA-F]{32,})['\"]", src):
                pytest.fail(
                    f"{m}: contains inline 32+ char hex token {m_[:8]}..."
                )

    def test_no_cve_id_fabrication_in_tags(self):
        """Phase 1.x rule: methods should NOT fabricate CVE ids."""
        for m in ALL_40:
            fn = getattr(OSINTExtRunner, "_" + m, None)
            if fn is None:
                continue
            import inspect
            src = inspect.getsource(fn)
            # We allow method-args to flow through, but the method body
            # should not invent CVE ids.
            for m_ in re.findall(r"['\"]CVE-\d{4}-\d{4,7}['\"]", src):
                pytest.fail(
                    f"{m}: contains hardcoded CVE id {m_}"
                )

    def test_envelope_shape_uniform(self):
        """Every method returns the same envelope shape."""
        for m in ALL_40:
            r = OSINTExtRunner(args={}).run_probe(m)
            assert _is_valid_envelope(r), (
                f"{m}: invalid envelope shape, got {r}"
            )

    def test_methods_never_return_fabricated_data(self):
        """A bare call (no args) should NEVER return ok=True with a
        fabricated data dict."""
        for m in ALL_40:
            r = OSINTExtRunner(args={}).run_probe(m)
            if r.get("ok") is True:
                # If ok=True, the data must come from a real source
                # OR be a deterministic grammar result. For methods
                # requiring an arg, ok=True without args is suspicious.
                # Exception: methods that don't require args (e.g.
                # allegro_search_categories).
                no_arg_methods = {
                    "allegro_search_categories",
                    "allegro_user_categories",
                    "polish_osint_adapt_dns_record_priority",
                }
                if m not in no_arg_methods:
                    # Either the data is empty, or the method
                    # genuinely doesn't need an arg
                    pytest.fail(
                        f"{m}: returned ok=True with no args; "
                        f"data={r.get('data')}"
                    )

    def test_never_raises(self):
        """No method should raise, even with hostile input."""
        for m in ALL_40:
            runner = OSINTExtRunner(args={"nip": "\x00\x01",
                                          "pesel": None,
                                          "krs": [],
                                          "name": 12345,
                                          "domain": {"x": 1}})
            try:
                r = runner.run_probe(m)
            except Exception as e:
                pytest.fail(f"{m}: raised {e!r}")


# ---------------------------------------------------------------------------
# 11. Spot-check: each method returns within 100ms locally
# ---------------------------------------------------------------------------
class TestPerformance:
    @pytest.mark.parametrize("m", ALL_40)
    def test_each_method_under_2s(self, m):
        """No method should hang. Most are <100ms."""
        import time
        runner = OSINTExtRunner(args={})
        t0 = time.time()
        r = runner.run_probe(m)
        elapsed = time.time() - t0
        assert elapsed < 2.0, (
            f"{m}: took {elapsed:.2f}s (> 2s threshold)"
        )
        assert _is_valid_envelope(r)


# ---------------------------------------------------------------------------
# 12. Phase 2.3.C summary
# ---------------------------------------------------------------------------
class TestPhaseSummary:
    def test_40_methods_total(self):
        assert len(ALL_40) == 40, (
            f"Phase 2.3.C: 40 methods expected, got {len(ALL_40)}"
        )

    def test_15_polish_registries(self):
        assert len(POLISH_REGISTRY_METHODS) == 15

    def test_5_allegro(self):
        assert len(ALLEGRO_METHODS) == 5

    def test_10_polish_social(self):
        assert len(POLISH_SOCIAL_METHODS) == 10

    def test_5_polymorphic(self):
        assert len(POLY_METHODS) == 5

    def test_5_target_adaptive(self):
        assert len(ADAPT_METHODS) == 5

    def test_polish_phone_prefixes_table_completeness(self):
        # 50-79 mobile, 12-95 landline
        prefixes = set(_POLISH_PHONE_PREFIXES.keys())
        # All 2-digit
        for p in prefixes:
            assert len(p) == 2
            assert p.isdigit()
        # Spot-check a few key prefixes
        assert "50" in prefixes  # Plus
        assert "60" in prefixes  # T-Mobile
        assert "72" in prefixes  # Play
        assert "22" in prefixes  # Warszawa
        assert "12" in prefixes  # Kraków
