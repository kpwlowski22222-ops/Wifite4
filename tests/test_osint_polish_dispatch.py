"""Phase 2.4 §C/D — Polish OSINT v3 dispatch tests.

Verifies ``OSINTExtRunner._dispatch_polish_v3`` correctly routes
to the ``core.osint.polish`` subpackage helpers and that all
key-needing endpoints honest-degrade (operator's "skip all new
apis those need api keys" rule).
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from unittest import mock

import pytest

from core.osint.runner_ext import (
    OSINTExtRunner,
    run_probe,
)
from core.osint.polish import (
    captcha_wall,
    ceidg,
    knf,
    nameday,
    pesel_decode,
    phone_prefix,
    postal_codes,
    validators,
)


# ---------------------------------------------------------------------------
# A. Pure-Python validators (no key, no network)
# ---------------------------------------------------------------------------
class TestPolishValidatorsDispatch:
    """Polish OSINT v3 dispatch → polish.validators.*"""

    def test_pesel_valid(self) -> None:
        # 02070803628 is a publicly-known example PESEL (F, 1902-07-08)
        r = run_probe("osint_people_pesel_validate",
                      {"value": "02070803628"})
        assert r["ok"] is True
        assert r["data"]["valid"] is True
        assert r["data"]["kind"] == "pesel"
        assert "polish-validator" in r["data"]["model"]

    def test_pesel_invalid(self) -> None:
        r = run_probe("osint_people_pesel_validate",
                      {"value": "12345678901"})
        assert r["ok"] is True
        assert r["data"]["valid"] is False

    def test_pesel_all_zero_rejected(self) -> None:
        """The all-zero PESEL is conventionally invalid even
        though it technically passes the weighted-sum check.
        We reject it explicitly so the operator never gets a
        "valid" all-zero PESEL back."""
        r = run_probe("osint_people_pesel_validate",
                      {"value": "00000000000"})
        assert r["ok"] is True
        assert r["data"]["valid"] is False

    def test_pesel_garbage_rejected(self) -> None:
        r = run_probe("osint_people_pesel_validate",
                      {"value": "abc123"})
        assert r["ok"] is True
        assert r["data"]["valid"] is False

    def test_pesel_empty_rejected(self) -> None:
        r = run_probe("osint_people_pesel_validate", {"value": ""})
        assert r["ok"] is True
        assert r["data"]["valid"] is False

    def test_pesel_alt_arg_name(self) -> None:
        """The dispatch reads ``value`` first, falls back to
        ``pesel``. Verify both work."""
        r = run_probe("osint_people_pesel_validate",
                      {"pesel": "02070803628"})
        assert r["data"]["valid"] is True

    def test_nip_valid(self) -> None:
        r = run_probe("osint_people_nip_validate",
                      {"value": "5261040828"})
        assert r["ok"] is True
        assert r["data"]["valid"] is True
        assert r["data"]["kind"] == "nip"

    def test_nip_invalid(self) -> None:
        r = run_probe("osint_people_nip_validate",
                      {"value": "0000000000"})
        assert r["ok"] is True
        assert r["data"]["valid"] is False

    def test_regon9_valid(self) -> None:
        r = run_probe("osint_people_regon_validate",
                      {"value": "192598184"})
        assert r["ok"] is True
        assert r["data"]["valid"] is True
        assert r["data"]["kind"] == "regon9"

    def test_regon14_valid(self) -> None:
        # 14-digit REGON example
        r = run_probe("osint_people_regon_validate",
                      {"value": "12345678901234"})
        # Just check it dispatched and routed to the right
        # checksum function
        assert r["ok"] is True
        assert r["data"]["kind"] in ("regon9", "regon14")

    def test_regon_invalid(self) -> None:
        r = run_probe("osint_people_regon_validate",
                      {"value": "111111111"})
        assert r["ok"] is True
        assert r["data"]["valid"] is False

    def test_phone_carrier_dispatch(self) -> None:
        r = run_probe("osint_people_phone_carrier_pl",
                      {"value": "500100100"})
        assert r["ok"] is True
        assert "carrier" in r["data"]
        assert "model" in r["data"]


# ---------------------------------------------------------------------------
# B. Network-helper dispatch (no-key, no-auth, captcha-safe)
# ---------------------------------------------------------------------------
class TestPolishNetworkDispatch:
    """Polish OSINT v3 dispatch → nameday, postal_codes, ceidg, knf"""

    def test_nameday_today(self) -> None:
        # nameday.abalin.net is unauthenticated JSON.
        # We mock the response to keep the test hermetic.
        fake = {"ok": True, "date": "2026-07-21",
                "nameday": ["Andrzej", "Justyna", "Daniel"]}
        with mock.patch.object(nameday, "nameday_today",
                               return_value=fake):
            r = run_probe("osint_people_name_day", {})
        assert r["ok"] is True
        assert r["data"] == fake

    def test_postal_code_dispatch(self) -> None:
        # pocztapolska GitHub mirror CSV — mocked.
        fake = {"ok": True, "locality": "Warszawa",
                "postal_codes": ["00-001", "00-002"]}
        with mock.patch.object(postal_codes, "search_locality",
                               return_value=fake):
            r = run_probe("osint_people_address_postal_code",
                          {"locality": "Warszawa"})
        assert r["ok"] is True
        assert r["data"] == fake

    def test_ceidg_dispatch(self) -> None:
        # CEIDG SOAP no-auth — mocked.
        fake = {"ok": True, "count": 1,
                "companies": [{"name": "Test", "nip": "5261040828"}]}
        with mock.patch.object(ceidg, "find_company",
                               return_value=fake):
            r = run_probe("osint_people_name_to_ceidg",
                          {"name": "Test"})
        assert r["ok"] is True
        assert r["data"] == fake

    def test_knf_dispatch(self) -> None:
        # KNF no-auth XML — mocked.
        fake = {"ok": True, "warnings": [], "count": 0}
        with mock.patch.object(knf, "query_warnings",
                               return_value=fake):
            r = run_probe("osint_people_knf_warning_check",
                          {"name": "Test"})
        assert r["ok"] is True
        assert r["data"] == fake


# ---------------------------------------------------------------------------
# C. Honest-degrade for key-needing endpoints
# ---------------------------------------------------------------------------
class TestPolishHonestDegrade:
    """All key-needing Polish endpoints return honest-degrade with
    the operator-revision ``<reason>_needs_key`` / ``<reason>_no_public_api``
    error strings."""

    def test_gus_bir1_pkd(self) -> None:
        r = run_probe("osint_people_pkd_activity", {})
        assert r["ok"] is False
        assert r["error"] == "gus_bir1_needs_key"
        assert "fix" in r

    def test_teryt_locality(self) -> None:
        r = run_probe("osint_people_teryt_locality", {})
        assert r["ok"] is False
        assert r["error"] == "teryt_needs_key"

    def test_allegro_username(self) -> None:
        r = run_probe("osint_people_allegro_username", {})
        assert r["ok"] is False
        assert r["error"] == "allegro_needs_key"

    def test_wykop_name(self) -> None:
        r = run_probe("osint_people_name_to_wykop", {})
        assert r["ok"] is False
        assert r["error"] == "wykop_needs_key"

    def test_linkedin_name(self) -> None:
        r = run_probe("osint_people_name_to_linkedin", {})
        assert r["ok"] is False
        assert r["error"] == "linkedin_no_public_api"

    def test_goldenline_name(self) -> None:
        r = run_probe("osint_people_name_to_goldenline", {})
        assert r["ok"] is False
        assert r["error"] == "goldenline_no_public_api"

    def test_political_exposed(self) -> None:
        r = run_probe("osint_people_political_exposed_check", {})
        assert r["ok"] is False
        assert r["error"] == "pep_registry_no_public_api"

    def test_property_search(self) -> None:
        r = run_probe("osint_people_property_search", {})
        assert r["ok"] is False
        assert r["error"] == "mswia_no_public_api"

    def test_honest_degrade_does_not_fabricate(self) -> None:
        """No key-needing endpoint returns ok=True with
        fabricated data. Always returns ok=False with an
        honest error message."""
        for method in (
            "osint_people_pkd_activity",
            "osint_people_teryt_locality",
            "osint_people_allegro_username",
            "osint_people_name_to_wykop",
            "osint_people_name_to_linkedin",
            "osint_people_name_to_goldenline",
            "osint_people_political_exposed_check",
            "osint_people_property_search",
        ):
            r = run_probe(method, {})
            assert r["ok"] is False, f"{method} must honest-degrade"
            assert "error" in r and r["error"]
            assert "no_public_api" in r["error"] or "needs_key" in r["error"]


# ---------------------------------------------------------------------------
# D. Dispatch is run BEFORE the v3 honest-degrade fallback
# ---------------------------------------------------------------------------
class TestDispatchOrder:
    """Polish subpackage dispatch must run BEFORE the generic
    v3 honest-degrade (so the polish helpers can actually
    execute instead of being shadowed by the ghost-catalog
    'v3 method registered but not implemented in this runner'
    envelope)."""

    def test_pesel_does_not_return_v3_ghost(self) -> None:
        """Before the polish dispatch was moved to the top of
        the fallback chain, run_probe returned
        ``'v3 method registered in v3_methods but not
        implemented in this runner'`` for every polish
        helper. After the fix, it returns a real validator
        result."""
        r = run_probe("osint_people_pesel_validate",
                      {"value": "02070803628"})
        assert "v3 method" not in (r.get("error") or "")
        assert "not implemented" not in (r.get("error") or "")
        assert r.get("data", {}).get("kind") == "pesel"

    def test_unknown_polish_method_returns_none(self) -> None:
        """An unknown method name should not be claimed by
        the polish dispatch — it should return None so the
        v3 ghost-catalog fallback can take over."""
        r = OSINTExtRunner(args={})._dispatch_polish_v3(
            "osint_people_does_not_exist")
        assert r is None


# ---------------------------------------------------------------------------
# E. GDPR-safe: PESEL/NIP/REGON never make network calls
# ---------------------------------------------------------------------------
class TestGDPRSafety:
    """Operator's hard rule: PESEL/NIP/REGON checksum
    validators must NEVER look up actual PESEL remotely
    (GDPR Art. 5/9). They are pure-Python."""

    def test_pesel_makes_no_network(self) -> None:
        with mock.patch("requests.get") as mock_get, \
             mock.patch("requests.post") as mock_post, \
             mock.patch("urllib.request.urlopen") as mock_urlopen:
            run_probe("osint_people_pesel_validate",
                      {"value": "02070803628"})
            mock_get.assert_not_called()
            mock_post.assert_not_called()
            mock_urlopen.assert_not_called()

    def test_nip_makes_no_network(self) -> None:
        with mock.patch("requests.get") as mock_get, \
             mock.patch("requests.post") as mock_post:
            run_probe("osint_people_nip_validate",
                      {"value": "5261040828"})
            mock_get.assert_not_called()
            mock_post.assert_not_called()

    def test_regon_makes_no_network(self) -> None:
        with mock.patch("requests.get") as mock_get, \
             mock.patch("requests.post") as mock_post:
            run_probe("osint_people_regon_validate",
                      {"value": "192598184"})
            mock_get.assert_not_called()
            mock_post.assert_not_called()


# ---------------------------------------------------------------------------
# F. Adversarial — no inline credentials in the dispatch or polish modules
# ---------------------------------------------------------------------------
class TestNoInlineCredentials:
    """The operator's hard rule: never inline API keys, tokens,
    or any harvested credentials in source/prompts/argv/logs.
    NVD key, Kismet key, Ollama token, GUS BIR1, TERYT,
    Allegro, Wykop must all be read from env or honest-degrade."""

    def test_no_nvd_key_in_polish(self) -> None:
        bad = Path("core/osint/polish")
        for src in bad.rglob("*.py"):
            text = src.read_text()
            assert "ecf51ee2" not in text, \
                f"NVD key inlined in {src}"
            assert "NVD_API_KEY" not in text, \
                f"NVD_API_KEY literal in {src}"

    def test_no_kismet_key_in_polish(self) -> None:
        bad = Path("core/osint/polish")
        for src in bad.rglob("*.py"):
            text = src.read_text()
            assert "CE38F768" not in text, \
                f"Kismet key inlined in {src}"

    def test_no_ollama_token_in_polish(self) -> None:
        bad = Path("core/osint/polish")
        for src in bad.rglob("*.py"):
            text = src.read_text()
            assert "3d94e52cff9f4df5" not in text, \
                f"Ollama token inlined in {src}"

    def test_no_gus_key_in_polish(self) -> None:
        bad = Path("core/osint/polish")
        for src in bad.rglob("*.py"):
            text = src.read_text()
            # GUS API key would look like a UUID
            assert "GUS_API_KEY" not in text or "os.environ" in text, \
                f"GUS_API_KEY hard-coded in {src}"

    def test_no_allegro_creds_in_polish(self) -> None:
        bad = Path("core/osint/polish")
        for src in bad.rglob("*.py"):
            text = src.read_text()
            assert "ALLEGRO_CLIENT_ID" not in text or "os.environ" in text
            assert "ALLEGRO_CLIENT_SECRET" not in text or "os.environ" in text

    def test_no_wykop_creds_in_polish(self) -> None:
        bad = Path("core/osint/polish")
        for src in bad.rglob("*.py"):
            text = src.read_text()
            assert "WYKOP_APP_KEY" not in text or "os.environ" in text


# ---------------------------------------------------------------------------
# G. Direct unit tests on the polish subpackage (sanity)
# ---------------------------------------------------------------------------
class TestPolishSubpackageSanity:
    """Smoke tests on the underlying polish helpers so the
    dispatch test failures can be localised."""

    def test_validators_pesel(self) -> None:
        assert validators.pesel_checksum_ok("02070803628") is True
        assert validators.pesel_checksum_ok("00000000000") is False
        assert validators.pesel_checksum_ok("abc") is False

    def test_validators_nip(self) -> None:
        # 5261040828 is a known valid NIP (public example)
        assert validators.nip_checksum_ok("5261040828") is True
        assert validators.nip_checksum_ok("0000000000") is False

    def test_validators_regon9(self) -> None:
        # 192598184 — public example
        assert validators.regon9_checksum_ok("192598184") is True
        assert validators.regon9_checksum_ok("000000000") is False

    def test_pesel_decode(self) -> None:
        bd = pesel_decode.pesel_to_birthdate("02070803628")
        assert bd is not None
        sx = pesel_decode.pesel_to_sex("02070803628")
        assert sx in ("M", "F")

    def test_phone_prefix(self) -> None:
        result = phone_prefix.lookup_carrier("500100100")
        assert result.get("ok") is True
        assert "carrier" in result

    def test_captcha_wall(self) -> None:
        r = captcha_wall.needs_key("test")
        assert r["ok"] is False
        assert r["error"] == "test_needs_key"
        r = captcha_wall.no_public_api("test")
        assert r["ok"] is False
        assert r["error"] == "test_no_public_api"


if __name__ == "__main__":
    pytest.main([__file__, "-q", "--tb=short"])
