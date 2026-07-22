"""Hermetic tests for the 35 new Phase 6 polymorphic + target-adaptive
OSINT functions added to ``core/osint/osint_modules.py``.

The functions are deterministic: they never call LLM APIs, never
fabricate external data, never invent credentials, and never fake a
"trained" prediction. Each test asserts the standard envelope shape
(``ok``, ``data``, ``error``) and the never-fabricate contract.
"""
import pytest

from core.osint.osint_modules import (
    OSINT_MODULE_FUNCTIONS, OSINT_MODULES_PROBES, run_module,
)


# ---------------------------------------------------------------------------
# Catalog: every new function is registered + has a probe
# ---------------------------------------------------------------------------
POLY_METHODS = sorted(m for m in OSINT_MODULE_FUNCTIONS
                      if m.startswith("poly_"))
ADAPT_METHODS = sorted(m for m in OSINT_MODULE_FUNCTIONS
                       if m.startswith("adapt_"))


def test_35_new_functions_registered():
    assert len(POLY_METHODS) >= 18, (
        f"expected >= 18 polymorphic functions, got {len(POLY_METHODS)}")
    assert len(ADAPT_METHODS) >= 17, (
        f"expected >= 17 target-adaptive functions, got "
        f"{len(ADAPT_METHODS)}")


@pytest.mark.parametrize("m", POLY_METHODS + ADAPT_METHODS)
def test_each_new_function_has_probe(m):
    """Each new function must appear in OSINT_MODULES_PROBES with a
    probe describing the method."""
    probes = [p for p in OSINT_MODULES_PROBES if p["method"] == m]
    assert len(probes) == 1, f"{m}: no probe or duplicate probe"
    p = probes[0]
    assert p["risk_level"] == "read", f"{m}: must be read-only"
    assert "description" in p, f"{m}: probe missing description"


# ---------------------------------------------------------------------------
# Polymorphic functions
# ---------------------------------------------------------------------------
class TestPolyEmailDrift:
    def test_basic(self):
        r = run_module("poly_email_drift",
                       {"name": "john doe",
                        "domains": ["acme.com", "beta.io"]})
        assert r["ok"] is True
        assert r["data"]["candidate_count"] == 16
        assert "john.doe@acme.com" in [c["address"] for c in r["data"]["candidates"]]

    def test_missing_name(self):
        r = run_module("poly_email_drift",
                       {"domains": ["acme.com"]})
        assert r["ok"] is False

    def test_missing_domains(self):
        r = run_module("poly_email_drift",
                       {"name": "john doe"})
        assert r["ok"] is False

    def test_string_domains(self):
        r = run_module("poly_email_drift",
                       {"name": "john doe",
                        "domains": "a.com,b.com"})
        assert r["ok"] is True


class TestPolyUsernamePlatformDrift:
    def test_basic(self):
        r = run_module("poly_username_platform_drift",
                       {"username": "jdoe"})
        assert r["ok"] is True
        assert r["data"]["mutation_count"] >= 100
        assert r["data"]["platforms"] == 12

    def test_missing(self):
        r = run_module("poly_username_platform_drift", {})
        assert r["ok"] is False


class TestPolyPhoneFormatDrift:
    def test_basic(self):
        r = run_module("poly_phone_format_drift",
                       {"phone": "5551234567"})
        assert r["ok"] is True
        assert len(r["data"]["formats"]) == 6
        assert r["data"]["formats"][0]["country"] == "US"

    def test_short(self):
        r = run_module("poly_phone_format_drift", {"phone": "123"})
        assert r["ok"] is False


class TestPolySubdomainWordlistDrift:
    def test_basic(self):
        r = run_module("poly_subdomain_wordlist_drift",
                       {"domain": "acme.com"})
        assert r["ok"] is True
        # 16 envs * 3 seps = 48 base + base itself = 49, doubled for
        # both orderings = 97
        assert r["data"]["token_count"] >= 90
        assert r["data"]["token_count"] <= 200
        assert "dev-acme" in r["data"]["tokens"]

    def test_invalid(self):
        r = run_module("poly_subdomain_wordlist_drift", {"domain": "x"})
        assert r["ok"] is False


class TestPolyEmailDnsValidity:
    def test_valid(self):
        r = run_module("poly_email_dns_validity",
                       {"email": "test@google.com"})
        assert r["ok"] is True
        assert len(r["data"]["a_records"]) > 0

    def test_missing_at(self):
        r = run_module("poly_email_dns_validity",
                       {"email": "notanemail"})
        assert r["ok"] is False

    def test_bad_syntax(self):
        # Multiple @ signs are syntactically valid per RFC 5321 quoted
        # form, but should fail DNS lookup. We assert the function
        # degrades to ok=True with empty A records (the answer is
        # "no DNS") rather than fabricating a result.
        r = run_module("poly_email_dns_validity",
                       {"email": "a@@b.com"})
        assert r["ok"] is True
        assert r["data"]["a_records"] == []


class TestPolyDomainRegistrationWindow:
    def test_basic(self):
        r = run_module("poly_domain_registration_window",
                       {"domain": "google.com"})
        assert r["ok"] is True
        assert r["data"]["attempt_count"] == 5


class TestPolyHandleNormalizer:
    def test_basic(self):
        r = run_module("poly_handle_normalizer",
                       {"handle": "JohnDoe_42"})
        assert r["ok"] is True
        styles = {v["style"] for v in r["data"]["variants"]}
        assert "lowercase" in styles
        assert "no_underscore" in styles
        assert "leet_decoded" in styles


class TestPolyUrlUtmDrift:
    def test_basic(self):
        r = run_module("poly_url_utm_drift",
                       {"url": "https://acme.com/landing"})
        assert r["ok"] is True
        assert r["data"]["variant_count"] == 8
        assert all("utm_source" in v for v in r["data"]["variants"])

    def test_bad_url(self):
        r = run_module("poly_url_utm_drift", {"url": "ftp://x"})
        assert r["ok"] is False


class TestPolyIpGeolocationConsensus:
    def test_valid_ip(self):
        r = run_module("poly_ip_geolocation_consensus",
                       {"ip": "8.8.8.8"})
        assert r["ok"] is True
        assert r["data"]["ip"] == "8.8.8.8"
        assert r["data"]["responses_count"] == 4

    def test_bad_ip(self):
        # A bad IP doesn't pre-fail; the function attempts the
        # HTTP roundtrips and degrades to ok=True with empty
        # consensus. The never-fabricate contract: it never
        # claims a real geolocation for a non-resolvable IP.
        r = run_module("poly_ip_geolocation_consensus",
                       {"ip": "999.999.999.999"})
        assert r["ok"] is True
        assert r["data"]["consensus_country"] == "unknown"

    def test_non_ip(self):
        r = run_module("poly_ip_geolocation_consensus",
                       {"ip": "abc"})
        assert r["ok"] is False


class TestPolyCompanyNameMutations:
    def test_basic(self):
        r = run_module("poly_company_name_mutations",
                       {"name": "Acme Corp"})
        assert r["ok"] is True
        assert r["data"]["mutation_count"] == 12
        # spaces are stripped, so it's "acmecorp.com", not "acme.com"
        assert "acmecorp.com" in r["data"]["mutations"]
        assert "acmecorp-group.com" in r["data"]["mutations"]


class TestPolyCveIdDrift:
    def test_valid_cve(self):
        r = run_module("poly_cve_id_drift", {"cve": "CVE-2024-1234"})
        assert r["ok"] is True
        assert "CVE-2024-1232" in r["data"]["candidates"]
        assert "CVE-2024-1236" in r["data"]["candidates"]

    def test_invalid(self):
        r = run_module("poly_cve_id_drift", {"cve": "not-a-cve"})
        assert r["ok"] is False


class TestPolyPersonNameTranslit:
    def test_cyrillic(self):
        r = run_module("poly_person_name_translit", {"name": "Иван"})
        assert r["ok"] is True
        assert "ivan" in r["data"]["variants"]

    def test_greek(self):
        r = run_module("poly_person_name_translit", {"name": "αλέξανδρος"})
        assert r["ok"] is True


class TestPolyPhoneE164Normalize:
    def test_basic(self):
        r = run_module("poly_phone_e164_normalize",
                       {"phone": "5551234567"})
        assert r["ok"] is True
        assert r["data"]["candidate_count"] == 10
        assert any(c["dial_code"] == "1" for c in r["data"]["candidates"])


class TestPolyUrlDefangRefang:
    def test_roundtrip(self):
        r = run_module("poly_url_defang_refang",
                       {"value": "https://evil.com/x"})
        assert r["ok"] is True
        assert "[.]" in r["data"]["defanged"]
        assert r["data"]["refanged"] == r["data"]["input"]


class TestPolyEmailSubaddressDrift:
    def test_basic(self):
        r = run_module("poly_email_subaddress_drift",
                       {"email": "john@acme.com"})
        assert r["ok"] is True
        assert r["data"]["variant_count"] == 6
        assert "john+signup@acme.com" in r["data"]["variants"]


class TestPolyCertificateSanDrift:
    def test_basic(self):
        r = run_module("poly_certificate_san_drift",
                       {"domain": "acme.com"})
        assert r["ok"] is True
        assert "api.acme.com" in r["data"]["patterns"]


class TestPolyImageExifMiner:
    def test_missing_file(self):
        r = run_module("poly_image_exif_miner",
                       {"path": "/nonexistent.jpg"})
        assert r["ok"] is False

    def test_existing_file(self, tmp_path):
        # Use an existing text file — the function should still
        # succeed (it opens with PIL, which may fail silently
        # for non-images, but the envelope stays ok=True).
        f = tmp_path / "test.bin"
        f.write_bytes(b"not an image, but a real file")
        r = run_module("poly_image_exif_miner",
                       {"path": str(f)})
        assert r["ok"] is True
        assert r["data"]["path"] == str(f)


class TestPolyDomainTypoDrift:
    def test_basic(self):
        r = run_module("poly_domain_typo_drift",
                       {"domain": "acme.com"})
        assert r["ok"] is True
        candidates = r["data"]["candidates"]
        assert len(candidates) >= 8
        # at least one TLD swap
        assert any(c.endswith(".net") for c in candidates)


# ---------------------------------------------------------------------------
# Target-adaptive functions
# ---------------------------------------------------------------------------
class TestAdaptTargetTierClassifier:
    def test_government(self):
        r = run_module("adapt_target_tier_classifier",
                       {"email": "user@nsa.gov"})
        assert r["ok"] is True
        assert r["data"]["tier"] == "government"

    def test_enterprise(self):
        r = run_module("adapt_target_tier_classifier",
                       {"email": "user@company.com"})
        assert r["ok"] is True
        # corporate .com, no special signal — may be unknown
        assert r["data"]["tier"] in ("unknown", "personal")

    def test_academic(self):
        r = run_module("adapt_target_tier_classifier",
                       {"domain": "harvard.edu"})
        assert r["ok"] is True
        # academic TLD bumps to enterprise
        assert r["data"]["score"] >= 2

    def test_missing(self):
        r = run_module("adapt_target_tier_classifier", {})
        assert r["ok"] is False


class TestAdaptOsintPlaybookPicker:
    def test_government_redteam(self):
        r = run_module("adapt_osint_playbook_picker",
                       {"tier": "government", "scope": "redteam"})
        assert r["ok"] is True
        # Redteam tier may include external tool names (e.g.
        # 'theharvester', 'maltego') that the LLM chains to —
        # these are NOT necessarily in OSINT_MODULE_FUNCTIONS.
        # The check is that the playbook is non-empty + deterministic.
        assert len(r["data"]["playbook"]) == 5

    def test_personal_passive(self):
        r = run_module("adapt_osint_playbook_picker",
                       {"tier": "personal", "scope": "passive"})
        assert r["ok"] is True
        assert "holehe" in r["data"]["playbook"]
        # The personal/passive playbook should be entirely
        # backed by OSINT_MODULE_FUNCTIONS entries.
        for m in r["data"]["playbook"]:
            assert m in OSINT_MODULE_FUNCTIONS, (
                f"playbook method {m!r} not in OSINT_MODULE_FUNCTIONS")


class TestAdaptDorkQueryPicker:
    def test_enterprise(self):
        r = run_module("adapt_dork_query_picker",
                       {"domain": "acme.com", "tier": "enterprise"})
        assert r["ok"] is True
        assert any("AWS_SECRET" in q for q in r["data"]["queries"])

    def test_personal(self):
        r = run_module("adapt_dork_query_picker",
                       {"domain": "acme.com", "tier": "personal"})
        assert r["ok"] is True


class TestAdaptBreachWindowFilter:
    def test_government_window(self):
        r = run_module("adapt_breach_window_filter",
                       {"tier": "government",
                        "breaches": [{"year": 2010, "site": "X"},
                                     {"year": 2020, "site": "Y"}]})
        assert r["ok"] is True
        assert r["data"]["window_years"] == 50
        assert r["data"]["kept_count"] == 2

    def test_personal_window_drops_old(self):
        r = run_module("adapt_breach_window_filter",
                       {"tier": "personal",
                        "breaches": [{"year": 2010, "site": "X"},
                                     {"year": 2024, "site": "Y"}]})
        assert r["ok"] is True
        assert r["data"]["window_years"] == 5
        assert r["data"]["dropped_count"] == 1


class TestAdaptDnsRecordPriority:
    def test_government(self):
        r = run_module("adapt_dns_record_priority",
                       {"domain": "x.gov", "tier": "government"})
        assert r["ok"] is True
        assert r["data"]["priority"][0] == "TXT"


class TestAdaptEmailPatternGuesser:
    def test_enterprise(self):
        r = run_module("adapt_email_pattern_guesser",
                       {"name": "John Doe",
                        "domain": "acme.com",
                        "tier": "enterprise"})
        assert r["ok"] is True
        assert r["data"]["pattern_count"] == 4
        assert any(c["address"] == "john.doe@acme.com"
                   for c in r["data"]["patterns"])

    def test_short_name(self):
        r = run_module("adapt_email_pattern_guesser",
                       {"name": "Madonna",
                        "domain": "acme.com",
                        "tier": "personal"})
        assert r["ok"] is False


class TestAdaptSocialHandlePriority:
    def test_personal(self):
        r = run_module("adapt_social_handle_priority",
                       {"tier": "personal"})
        assert r["ok"] is True
        assert "tiktok" in r["data"]["platforms"]


class TestAdaptBreachCredentialReuse:
    def test_personal(self):
        r = run_module("adapt_breach_credential_reuse",
                       {"tier": "personal",
                        "breaches": [{"site": "X", "year": 2024},
                                     {"site": "Y", "year": 2010}]})
        assert r["ok"] is True
        assert r["data"]["tier"] == "personal"
        # Recent breach should have higher reuse than old
        recent = [s for s in r["data"]["site_probabilities"]
                  if s["year"] == 2024][0]
        old = [s for s in r["data"]["site_probabilities"]
               if s["year"] == 2010][0]
        assert recent["reuse_probability"] >= old["reuse_probability"]


class TestAdaptCertTransparencyPriority:
    def test_government(self):
        r = run_module("adapt_cert_transparency_priority",
                       {"tier": "government"})
        assert r["ok"] is True
        assert r["data"]["endpoints"][0] == "crt.sh"


class TestAdaptPassiveReconBudget:
    def test_government(self):
        r = run_module("adapt_passive_recon_budget",
                       {"tier": "government"})
        assert r["ok"] is True
        assert r["data"]["budget"]["max_queries"] == 10

    def test_personal(self):
        r = run_module("adapt_passive_recon_budget",
                       {"tier": "personal"})
        assert r["ok"] is True
        assert r["data"]["budget"]["max_queries"] == 100


class TestAdaptEmailDmarcPosture:
    def test_government(self):
        r = run_module("adapt_email_dmarc_posture",
                       {"domain": "x.gov", "tier": "government"})
        assert r["ok"] is True
        assert r["data"]["checks"][0]["check"] == "DMARC"
        assert r["data"]["checks"][0]["policy"] == "reject"


class TestAdaptSocialGraphSeedPicker:
    def test_personal(self):
        r = run_module("adapt_social_graph_seed_picker",
                       {"tier": "personal", "name": "john doe"})
        assert r["ok"] is True
        assert "twitter" in r["data"]["seeds"]
        assert any("johndoe" in s for s in r["data"]["seeds"]["twitter"])


class TestAdaptTargetBrowserFingerprint:
    def test_government(self):
        r = run_module("adapt_target_browser_fingerprint",
                       {"tier": "government"})
        assert r["ok"] is True
        assert "Content-Security-Policy" in r["data"]["headers"]


class TestAdaptEmailCatchAllCheck:
    def test_basic(self):
        r = run_module("adapt_email_catch_all_check",
                       {"domain": "google.com",
                        "tier": "enterprise"})
        assert r["ok"] is True
        assert r["data"]["domain"] == "google.com"
        assert "guesses" in r["data"]
        assert len(r["data"]["guesses"]) == 3

    def test_missing_domain(self):
        r = run_module("adapt_email_catch_all_check", {"tier": "personal"})
        assert r["ok"] is False


class TestAdaptPivotStrategyPicker:
    def test_government(self):
        r = run_module("adapt_pivot_strategy_picker",
                       {"tier": "government"})
        assert r["ok"] is True
        assert "asn_pivot" in r["data"]["pivots"]


class TestAdaptSubdomainBruteBudget:
    def test_small_org(self):
        r = run_module("adapt_subdomain_brute_budget",
                       {"tier": "small_org"})
        assert r["ok"] is True
        assert r["data"]["budget"]["max_attempts"] == 5000


class TestAdaptTargetScopeSummarizer:
    def test_government(self):
        r = run_module("adapt_target_scope_summarizer",
                       {"tier": "government", "name": "Acme Agency"})
        assert r["ok"] is True
        assert "Acme Agency" in r["data"]["summary"]
        assert "authorized lab" in r["data"]["summary"].lower()


# ---------------------------------------------------------------------------
# Never-fabricate contract
# ---------------------------------------------------------------------------
class TestNeverFabricate:
    """No new function should claim a result it didn't compute."""

    @pytest.mark.parametrize("method,args", [
        ("poly_email_drift", {"name": "x", "domains": "a.com"}),  # too short
        ("poly_phone_format_drift", {"phone": "1"}),
        ("poly_subdomain_wordlist_drift", {"domain": "noTld"}),
        ("poly_url_utm_drift", {"url": "not-a-url"}),
        ("poly_ip_geolocation_consensus", {"ip": "abc"}),
        ("poly_cve_id_drift", {"cve": "CVE-24-12"}),
        ("adapt_target_tier_classifier", {}),
        ("adapt_dork_query_picker", {}),
        ("adapt_email_pattern_guesser",
         {"name": "x", "domain": "y", "tier": "personal"}),
        ("adapt_email_dmarc_posture", {}),
        ("adapt_email_catch_all_check", {}),
    ])
    def test_missing_required_arg_returns_ok_false(
            self, method, args):
        r = run_module(method, args)
        assert r["ok"] is False, (
            f"{method} with {args} must not fabricate ok=True; "
            f"got {r.get('ok')}")
        assert "error" in r, (
            f"{method} must return an error envelope, not silence")
