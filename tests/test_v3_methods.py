"""Tests for core.ai_backend.v3_methods (Phase 2.4).

Validates the 280 new v3 method tuples (40 × 7 categories) and
ensures the registry matches the Phase 2.4 plan.
"""
from __future__ import annotations

import pytest

from core.ai_backend import (
    BLE_ATTACK_V3_METHODS,
    BLE_RECON_V3_METHODS,
    OSINT_PEOPLE_V3_METHODS,
    OSINT_WEB_V3_METHODS,
    POST_EXPLOIT_V3_METHODS,
    V3_PROMPT_STANZA,
    V3_REGISTRY,
    WIFI_ATTACK_V3_METHODS,
    WIFI_RECON_V3_METHODS,
    all_v3_method_names,
    build_v3_prompt_stanza,
    describe_v3_category,
    describe_v3_method,
    list_v3_methods,
    total_v3_count,
)


# ---------------------------------------------------------------------------
# Registry shape
# ---------------------------------------------------------------------------

class TestRegistryShape:
    def test_seven_categories(self):
        expected = {
            "wifi_attack", "wifi_recon", "ble_attack", "ble_recon",
            "osint_web", "osint_people", "post_exploit",
        }
        assert set(V3_REGISTRY.keys()) == expected

    def test_each_category_has_40(self):
        for cat, methods in V3_REGISTRY.items():
            assert len(methods) == 40, f"{cat} has {len(methods)} methods"

    def test_total_is_280(self):
        assert sum(total_v3_count().values()) == 280

    def test_total_v3_count_per_category(self):
        c = total_v3_count()
        for k in V3_REGISTRY:
            assert c[k] == 40

    def test_every_method_is_triple(self):
        for cat, methods in V3_REGISTRY.items():
            for m in methods:
                assert isinstance(m, tuple), f"{cat}: {m!r}"
                assert len(m) == 3, f"{cat}: {m!r}"
                name, risk, desc = m
                assert isinstance(name, str) and name
                assert isinstance(risk, str) and risk in {
                    "read", "intrusive", "destructive",
                }, f"{cat}: bad risk {risk!r}"
                assert isinstance(desc, str) and desc


# ---------------------------------------------------------------------------
# Naming uniqueness across categories
# ---------------------------------------------------------------------------

class TestNaming:
    def test_no_duplicate_names(self):
        seen = {}
        for cat, methods in V3_REGISTRY.items():
            for name, risk, desc in methods:
                if name in seen:
                    pytest.fail(
                        f"duplicate name {name!r} in {cat} and {seen[name]}"
                    )
                seen[name] = cat

    def test_v3_names_dont_clash_with_v2(self):
        # Import v2 registry lazily; just sanity-check a few
        # common names.
        from core.ai_backend.expanded_modules import (
            WIFI_V2_METHODS, BLE_V2_METHODS, OSINT_V2_METHODS,
            POST_EXPLOIT_V2_METHODS,
        )
        v2_names = set()
        for t in (WIFI_V2_METHODS, BLE_V2_METHODS, OSINT_V2_METHODS,
                  POST_EXPLOIT_V2_METHODS):
            for n, _r, _d in t:
                v2_names.add(n)
        v3_names = set(all_v3_method_names())
        overlap = v2_names & v3_names
        assert not overlap, f"v2/v3 name overlap: {sorted(overlap)[:5]}"

    def test_names_use_snake_case(self):
        import re
        for cat, methods in V3_REGISTRY.items():
            for name, _r, _d in methods:
                assert re.match(r"^[a-z0-9_]+$", name), (
                    f"{cat}: {name!r} is not snake_case"
                )

    def test_names_are_unique_within_category(self):
        for cat, methods in V3_REGISTRY.items():
            names = [m[0] for m in methods]
            assert len(set(names)) == len(names), f"dup in {cat}"


# ---------------------------------------------------------------------------
# Lookup helpers
# ---------------------------------------------------------------------------

class TestLookup:
    def test_describe_v3_method_known(self):
        d = describe_v3_method("wifi_attack", "wifi_ap_blacklist_bypass")
        assert d is not None
        assert d["name"] == "wifi_ap_blacklist_bypass"
        assert d["risk"] == "intrusive"
        assert isinstance(d["description"], str) and d["description"]

    def test_describe_v3_method_unknown(self):
        assert describe_v3_method("wifi_attack", "nonexistent") is None
        assert describe_v3_method("ble_attack", "foo") is None

    def test_list_v3_methods_returns_strings(self):
        names = list_v3_methods("wifi_attack")
        assert len(names) == 40
        for n in names:
            assert isinstance(n, str)

    def test_describe_v3_category_returns_all(self):
        d = describe_v3_category("ble_recon")
        assert len(d) == 40
        assert all("name" in e and "risk" in e and "description" in e
                   for e in d)

    def test_all_v3_method_names(self):
        all_names = all_v3_method_names()
        assert len(all_names) == 280
        assert len(set(all_names)) == 280


# ---------------------------------------------------------------------------
# Prompt stanza
# ---------------------------------------------------------------------------

class TestPromptStanza:
    def test_stanza_lists_every_category(self):
        for cat in V3_REGISTRY:
            assert cat in V3_PROMPT_STANZA, f"missing {cat} in stanza"

    def test_stanza_mentions_280(self):
        assert "280" in V3_PROMPT_STANZA

    def test_stanza_no_fabricated_cve_ids(self):
        import re
        # No 'CVE-YYYY-N+' style ids in the stanza (we never fabricate).
        # The only acceptable CVE id would be the operator's known
        # 2021-34981 / 2020-26880 — those are honest references.
        cves = re.findall(r"CVE-\d{4}-\d+", V3_PROMPT_STANZA)
        # We may legitimately mention CVE-2021-34981 and CVE-2020-26880.
        allowed = {"CVE-2021-34981", "CVE-2020-26880"}
        unexpected = [c for c in cves if c not in allowed]
        assert not unexpected, f"unexpected CVE ids: {unexpected}"

    def test_build_v3_prompt_stanza_matches_cached(self):
        # The cached V3_PROMPT_STANZA is built at import time. Re-running
        # the builder must produce the same string.
        assert build_v3_prompt_stanza() == V3_PROMPT_STANZA


# ---------------------------------------------------------------------------
# Honest-degrade: descriptions are factual, no fabricated stats
# ---------------------------------------------------------------------------

class TestHonestDegrade:
    @pytest.mark.parametrize("cat,methods", list(V3_REGISTRY.items()))
    def test_no_fabricated_versions_in_descriptions(self, cat, methods):
        import re
        for name, risk, desc in methods:
            # No 'v1.2.3' style version tokens in descriptions.
            assert not re.search(r"\bv\d+\.\d+", desc), (
                f"{cat}.{name}: version-shaped token in {desc!r}"
            )

    @pytest.mark.parametrize("cat,methods", list(V3_REGISTRY.items()))
    def test_no_fabricated_cve_ids_in_descriptions(self, cat, methods):
        import re
        for name, risk, desc in methods:
            cves = re.findall(r"CVE-\d{4}-\d+", desc)
            allowed = {"CVE-2021-34981", "CVE-2020-26880"}
            unexpected = [c for c in cves if c not in allowed]
            assert not unexpected, (
                f"{cat}.{name}: unexpected CVE ids {unexpected} in {desc!r}"
            )

    @pytest.mark.parametrize("cat,methods", list(V3_REGISTRY.items()))
    def test_no_inline_credentials(self, cat, methods):
        for name, risk, desc in methods:
            dl = desc.lower()
            for bad in ("password=", "hash=", "ntlm:",
                        "$kfiosa_target_password"):
                assert bad not in dl, (
                    f"{cat}.{name}: bad token {bad!r} in {desc!r}"
                )


# ---------------------------------------------------------------------------
# Specific category checks
# ---------------------------------------------------------------------------

class TestOSINTTopics:
    def test_osint_web_has_no_key_apis_only(self):
        """Per operator's revision, OSINT web methods must use
        only truly no-key APIs. We verify by name."""
        names = [m[0] for m in OSINT_WEB_V3_METHODS]
        # The dropped ones (Allegro, GUS BIR1, Wykop Daisy) must
        # NOT appear as v3 method names.
        for forbidden in ("osint_web_allegro_search",
                          "osint_web_gus_bir1",
                          "osint_web_wykop_oauth"):
            assert forbidden not in names

    def test_osint_people_has_gdgr_safe_validators(self):
        names = [m[0] for m in OSINT_PEOPLE_V3_METHODS]
        # Pure-Python validators (no key, no network) are present.
        assert "osint_people_pesel_validate" in names
        assert "osint_people_nip_validate" in names
        assert "osint_people_regon_validate" in names
        assert "osint_people_regon14_validate" in names
        assert "osint_people_phone_carrier_pl" in names

    def test_osint_people_honest_degrade_present(self):
        names = [m[0] for m in OSINT_PEOPLE_V3_METHODS]
        # These need keys and must honest-degrade.
        for hd in ("osint_people_teryt_locality",
                   "osint_people_allegro_username",
                   "osint_people_pkd_activity"):
            assert hd in names, f"missing {hd} in OSINT people v3"


class TestDestructiveMethods:
    def test_destructive_methods_marked_destructive(self):
        # All 280 entries should have a risk level; destructive ones
        # must be marked as such (so the chain gate applies).
        destructive = []
        for cat, methods in V3_REGISTRY.items():
            for name, risk, desc in methods:
                if risk == "destructive":
                    destructive.append((cat, name))
        # We expect a healthy count of destructive (RCE, brick-AP, etc).
        assert len(destructive) >= 30, (
            f"only {len(destructive)} destructive v3 methods — "
            "expected ≥30 (post-exploit + RCE + brick-AP)"
        )

    def test_post_exploit_has_persistence_methods(self):
        names = [m[0] for m in POST_EXPLOIT_V3_METHODS]
        for p in ("post_exploit_persistence_wmi",
                  "post_exploit_persistence_mbr",
                  "post_exploit_persistence_uefi",
                  "post_exploit_dcsync",
                  "post_exploit_golden_ticket",
                  "post_exploit_skeleton_key"):
            assert p in names, f"missing {p} in post-exploit v3"

    def test_wifi_attack_has_rce_methods(self):
        names = [m[0] for m in WIFI_ATTACK_V3_METHODS]
        for r in ("wifi_cve_exploit_runner",
                  "wifi_netgear_rce",
                  "wifi_tplink_rce"):
            assert r in names, f"missing {r} in wifi_attack v3"
