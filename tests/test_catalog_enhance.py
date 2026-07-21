"""Tests for the catalog enhancement module.

These tests use ``tmp_path`` and copies of the real catalog files
to keep the operator's actual ``catalog/`` directory read-only.
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any, Dict, List

import pytest

from core.catalog.enhance import (
    SCHEMA_VERSION,
    ENHANCED_TAG,
    enhance_file,
    enhance_all,
    is_enhanced,
    build_enrichment_prompt_stanza,
    _enrich_summary,
    _enrich_tags,
    _enrich_use_cases,
    _enrich_command_examples,
    _enrich_risk_signals,
    _enrich_trust,
    CATEGORY_DESCRIPTORS,
    DEFAULT_RISK_SIGNALS_BY_CATEGORY,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def sample_entry() -> Dict[str, Any]:
    """A canonical, minimal github_* entry as the indexer would write it."""
    return {
        "id": "github:00xCanelo/CVE-2025-27591",
        "kind": "external_repository",
        "name": "CVE-2025-27591",
        "full_name": "00xCanelo/CVE-2025-27591",
        "owner": "00xCanelo",
        "category": "Exploits and CVE Research",
        "url": "https://github.com/00xCanelo/CVE-2025-27591",
        "summary": None,
        "documentation": {
            "readme": None,
            "usage_sections": [],
            "arguments": [],
            "examples": [],
        },
        "metadata_status": "index_only",
        "trust": {
            "official_kali": False,
            "reviewed": False,
            "warning": "Attribution/index entry only.",
        },
        "risk": {
            "level": "high",
            "signals": ["exploit"],
            "requires_explicit_authorization": False,
            "allow_autonomous_execution": True,
            "examples_policy": "operational",
        },
    }


@pytest.fixture
def tmp_catalog(tmp_path: Path, sample_entry: Dict[str, Any]) -> Path:
    """A tiny catalog directory with 3 entries of varying categories."""
    cat = tmp_path / "catalog"
    cat.mkdir()
    # Three entries, different categories
    entries = [
        dict(sample_entry, name="CVE-2025-27591", full_name="owner1/CVE-2025-27591",
             id="github:owner1/CVE-2025-27591",
             url="https://github.com/owner1/CVE-2025-27591"),
        dict(sample_entry, name="webapp-scanner", full_name="owner2/webapp-scanner",
             id="github:owner2/webapp-scanner", category="Web Application Security",
             url="https://github.com/owner2/webapp-scanner"),
        dict(sample_entry, name="evil-twin-ai", full_name="owner3/evil-twin-ai",
             id="github:owner3/evil-twin-ai", category="Wireless Security",
             url="https://github.com/owner3/evil-twin-ai"),
    ]
    for i, e in enumerate(entries):
        p = cat / f"github_test_{i}_{e['name']}.json"
        p.write_text(json.dumps(e, indent=2), encoding="utf-8")
    return cat


# ---------------------------------------------------------------------------
# is_enhanced
# ---------------------------------------------------------------------------

class TestIsEnhanced:
    def test_enhanced_predicate_true(self, sample_entry):
        sample_entry["_kfiosa_enriched_schema"] = SCHEMA_VERSION
        sample_entry["_kfiosa_enriched_at"] = "phase_2_3"
        assert is_enhanced(sample_entry) is True

    def test_enhanced_predicate_false(self, sample_entry):
        assert is_enhanced(sample_entry) is False

    def test_enhanced_predicate_wrong_schema(self, sample_entry):
        sample_entry["_kfiosa_enriched_schema"] = "0.0.1"
        assert is_enhanced(sample_entry) is False

    def test_enhanced_predicate_non_dict(self):
        assert is_enhanced(None) is False
        assert is_enhanced([]) is False
        assert is_enhanced("string") is False


# ---------------------------------------------------------------------------
# _enrich_summary
# ---------------------------------------------------------------------------

class TestEnrichSummary:
    def test_summary_includes_descriptor(self, sample_entry):
        s = _enrich_summary(
            sample_entry, CATEGORY_DESCRIPTORS["Exploits and CVE Research"],
            sample_entry["name"],
        )
        assert "CVE-2025-27591" in s
        assert "Audit" in s or "provenance" in s.lower()

    def test_summary_is_2_to_3_sentences(self, sample_entry):
        s = _enrich_summary(
            sample_entry, CATEGORY_DESCRIPTORS["Exploits and CVE Research"],
            sample_entry["name"],
        )
        # Should end with a period; not a single sentence
        assert s.endswith(".")
        # Multiple sentences (period followed by space)
        assert s.count(". ") >= 1

    def test_summary_never_includes_harvested_creds(self, sample_entry):
        s = _enrich_summary(
            sample_entry, CATEGORY_DESCRIPTORS["Exploits and CVE Research"],
            sample_entry["name"],
        )
        # No password/cred token leakage
        for bad in ("password=", "hash=", "ntlm=", "0x"):
            assert bad not in s.lower()


# ---------------------------------------------------------------------------
# _enrich_tags
# ---------------------------------------------------------------------------

class TestEnrichTags:
    def test_tags_at_least_5(self, sample_entry):
        tags = _enrich_tags(sample_entry, "Exploits and CVE Research",
                            sample_entry["name"], sample_entry["full_name"])
        assert len(tags) >= 5

    def test_tags_at_most_15(self, sample_entry):
        # Phase 2.4: bumped to 8-15 (was 5-8)
        tags = _enrich_tags(sample_entry, "Exploits and CVE Research",
                            sample_entry["name"], sample_entry["full_name"])
        assert len(tags) <= 15

    def test_tags_at_least_8(self, sample_entry):
        # Phase 2.4: minimum is now 8
        tags = _enrich_tags(sample_entry, "Exploits and CVE Research",
                            sample_entry["name"], sample_entry["full_name"])
        assert len(tags) >= 8

    def test_tags_are_lowercase_strings(self, sample_entry):
        tags = _enrich_tags(sample_entry, "Exploits and CVE Research",
                            sample_entry["name"], sample_entry["full_name"])
        for t in tags:
            assert isinstance(t, str)
            assert t == t.lower()

    def test_tags_no_fabricated_versions(self, sample_entry):
        tags = _enrich_tags(sample_entry, "Exploits and CVE Research",
                            "CVE-2025-27591", "00xCanelo/CVE-2025-27591")
        # No version-shaped tokens like "v1.2.3" or "2.0.0"
        import re
        for t in tags:
            assert not re.match(r"^v?\d+\.\d+", t), (
                f"version-shaped tag: {t!r}"
            )

    def test_tags_unknown_category_pads(self, sample_entry):
        tags = _enrich_tags(sample_entry, "Made-Up Category",
                            sample_entry["name"], sample_entry["full_name"])
        assert len(tags) >= 5


# ---------------------------------------------------------------------------
# _enrich_use_cases
# ---------------------------------------------------------------------------

class TestEnrichUseCases:
    def test_use_cases_count(self, sample_entry):
        # Phase 2.4: bumped to 5-10 (was 3-5)
        uc = _enrich_use_cases(sample_entry, "Exploits and CVE Research")
        assert 5 <= len(uc) <= 10

    def test_use_cases_strings(self, sample_entry):
        uc = _enrich_use_cases(sample_entry, "OSINT and Recon")
        for u in uc:
            assert isinstance(u, str)
            assert len(u) > 10

    def test_use_cases_unknown_category(self, sample_entry):
        uc = _enrich_use_cases(sample_entry, "Nonexistent Category")
        # Falls back to generic; should still be 3+ items
        assert len(uc) >= 3


# ---------------------------------------------------------------------------
# _enrich_command_examples
# ---------------------------------------------------------------------------

class TestEnrichCommandExamples:
    def test_count(self, sample_entry):
        # Phase 2.4: bumped to 5-10 (was 3-5)
        ce = _enrich_command_examples(
            sample_entry, "Exploits and CVE Research", sample_entry["name"]
        )
        assert 5 <= len(ce) <= 10

    def test_uses_kfiosa_env_sentinels(self, sample_entry):
        ce = _enrich_command_examples(
            sample_entry, "Penetration Testing", "my-tool"
        )
        joined = " ".join(ce)
        assert "$KFIOSA_TARGET_HOST" in joined

    def test_never_inline_credentials(self, sample_entry):
        """The never-inline ground rule: command_examples must never
        contain an actual password= or hash= with a long hex value."""
        for cat in DEFAULT_RISK_SIGNALS_BY_CATEGORY:
            ce = _enrich_command_examples(sample_entry, cat, "demo-tool")
            for line in ce:
                ll = line.lower()
                # No literal password= with a value
                assert "password=\"secret" not in ll
                assert "password='secret" not in ll
                # No long hex hashes
                import re
                assert not re.search(r"[a-f0-9]{32,}", line.lower()), (
                    f"long hex found in: {line}"
                )

    def test_name_safe(self, sample_entry):
        # Name with weird chars should not break the format
        ce = _enrich_command_examples(
            sample_entry, "Web Application Security", "weird/tool name!"
        )
        joined = " ".join(ce)
        # The format must complete without KeyError (we sanitise the name)
        assert "weird_tool_name_" in joined or "weird_tool_name" in joined


# ---------------------------------------------------------------------------
# _enrich_risk_signals
# ---------------------------------------------------------------------------

class TestEnrichRiskSignals:
    def test_signals_count(self, sample_entry):
        # Phase 2.4: bumped to 4-8 (was 2-5)
        s = _enrich_risk_signals(sample_entry, "Exploits and CVE Research")
        assert 4 <= len(s) <= 8

    def test_signals_known_category(self, sample_entry):
        s = _enrich_risk_signals(sample_entry, "Exploits and CVE Research")
        assert "exploit" in s

    def test_signals_unknown_category_falls_back(self, sample_entry):
        s = _enrich_risk_signals(sample_entry, "Imaginary Category")
        assert len(s) >= 1


# ---------------------------------------------------------------------------
# _enrich_trust
# ---------------------------------------------------------------------------

class TestEnrichTrust:
    def test_trust_reviewed_always_false(self, sample_entry):
        # Even if the input is True, we downgrade to False (we never claim review)
        sample_entry["trust"]["reviewed"] = True
        out = _enrich_trust(sample_entry)
        assert out["reviewed"] is False

    def test_trust_preserves_warning(self, sample_entry):
        out = _enrich_trust(sample_entry)
        assert "Attribution/index entry only" in out["warning"]


# ---------------------------------------------------------------------------
# enhance_file
# ---------------------------------------------------------------------------

class TestEnhanceFile:
    def test_enhance_writes_fields(self, tmp_path, sample_entry):
        p = tmp_path / "x.json"
        p.write_text(json.dumps(sample_entry), encoding="utf-8")
        r = enhance_file(p)
        assert r["ok"] is True
        assert r["changed"] is True
        # Read back
        data = json.loads(p.read_text())
        assert is_enhanced(data) is True
        assert data["summary"] is not None
        assert len(data["tags"]) >= 5
        assert len(data["use_cases"]) >= 3
        assert len(data["command_examples"]) >= 3
        # Protected fields preserved
        assert data["id"] == sample_entry["id"]
        assert data["kind"] == sample_entry["kind"]
        assert data["url"] == sample_entry["url"]
        assert data["category"] == sample_entry["category"]

    def test_enhance_idempotent(self, tmp_path, sample_entry):
        p = tmp_path / "x.json"
        p.write_text(json.dumps(sample_entry), encoding="utf-8")
        r1 = enhance_file(p)
        assert r1["changed"] is True
        r2 = enhance_file(p)
        assert r2["changed"] is False
        assert r2["skipped_reason"] == "already enhanced"

    def test_enhance_missing_file(self, tmp_path):
        r = enhance_file(tmp_path / "does_not_exist.json")
        assert r["ok"] is False
        assert "does not exist" in r["error"]

    def test_enhance_unparseable_json(self, tmp_path):
        p = tmp_path / "bad.json"
        p.write_text("{not valid", encoding="utf-8")
        r = enhance_file(p)
        assert r["ok"] is False
        assert "parse" in r["error"].lower()

    def test_enhance_non_object_top_level(self, tmp_path):
        p = tmp_path / "list.json"
        p.write_text("[1, 2, 3]", encoding="utf-8")
        r = enhance_file(p)
        assert r["ok"] is False
        assert "not an object" in r["error"]

    def test_enhance_skips_non_github(self, tmp_path):
        """kali:* entries are not github external_repository; should be skipped."""
        p = tmp_path / "kali_aircrack-ng.json"
        p.write_text(json.dumps({
            "id": "kali:aircrack-ng",
            "kind": "kali_source_package",
            "name": "aircrack-ng",
        }), encoding="utf-8")
        r = enhance_file(p)
        assert r["ok"] is True
        assert r["changed"] is False
        assert "not a github" in r["skipped_reason"]

    def test_enhance_writes_sorted_documentation(self, tmp_path, sample_entry):
        # Add a partial documentation block; should be normalized
        sample_entry["documentation"] = {"readme": "Hello"}
        p = tmp_path / "x.json"
        p.write_text(json.dumps(sample_entry), encoding="utf-8")
        r = enhance_file(p)
        assert r["ok"] is True
        data = json.loads(p.read_text())
        doc = data["documentation"]
        # All four sub-keys should exist
        for k in ("readme", "usage_sections", "arguments", "examples"):
            assert k in doc

    def test_enhance_pads_short_tags(self, tmp_path, sample_entry):
        # Start with only 2 tags; should be expanded
        sample_entry["tags"] = ["foo", "bar"]
        p = tmp_path / "x.json"
        p.write_text(json.dumps(sample_entry), encoding="utf-8")
        r = enhance_file(p)
        assert r["ok"] is True
        data = json.loads(p.read_text())
        assert len(data["tags"]) >= 5


# ---------------------------------------------------------------------------
# enhance_all
# ---------------------------------------------------------------------------

class TestEnhanceAll:
    def test_enhance_all_directory(self, tmp_catalog):
        r = enhance_all(tmp_catalog)
        assert r["ok"] is True
        assert r["total_seen"] == 3
        assert r["total_changed"] == 3
        assert r["total_failed"] == 0
        # All 3 files now report enhanced
        for p in tmp_catalog.glob("github_test_*.json"):
            data = json.loads(p.read_text())
            assert is_enhanced(data) is True

    def test_enhance_all_idempotent(self, tmp_catalog):
        r1 = enhance_all(tmp_catalog)
        assert r1["total_changed"] == 3
        r2 = enhance_all(tmp_catalog)
        assert r2["total_changed"] == 0
        assert r2["total_skipped"] == 3

    def test_enhance_all_nonexistent_dir(self, tmp_path):
        r = enhance_all(tmp_path / "nope")
        assert r["ok"] is False
        assert "not a directory" in r["error"]

    def test_enhance_all_with_limit(self, tmp_catalog):
        r = enhance_all(tmp_catalog, limit=2)
        assert r["total_seen"] == 2
        assert r["total_changed"] == 2
        # At least one file should be untouched (the one not in the
        # sorted prefix of size 2). Walk all files.
        enhanced_count = 0
        untouched_count = 0
        for p in tmp_catalog.glob("github_test_*.json"):
            data = json.loads(p.read_text())
            if is_enhanced(data):
                enhanced_count += 1
            else:
                untouched_count += 1
        assert enhanced_count == 2
        assert untouched_count == 1

    def test_enhance_all_empty_directory(self, tmp_path):
        d = tmp_path / "empty"
        d.mkdir()
        r = enhance_all(d)
        assert r["ok"] is True
        assert r["total_seen"] == 0


# ---------------------------------------------------------------------------
# build_enrichment_prompt_stanza
# ---------------------------------------------------------------------------

class TestPromptStanza:
    def test_stanza_no_sample(self):
        s = build_enrichment_prompt_stanza()
        assert "summary" in s
        assert "tags" in s
        assert "use_cases" in s
        assert "command_examples" in s
        assert "metadata_status" in s
        assert "trust.reviewed" in s

    def test_stanza_with_sample(self, sample_entry):
        s = build_enrichment_prompt_stanza([sample_entry])
        assert sample_entry["name"] in s or "CVE-2025" in s

    def test_stanza_emphasises_never_inline(self):
        s = build_enrichment_prompt_stanza()
        # The LLM should be told about the never-inline ground rule
        assert "inline" in s.lower() or "env-var" in s.lower()

    def test_stanza_no_fabricated_cve(self):
        s = build_enrichment_prompt_stanza()
        # Should NOT contain a literal CVE id from the sample set
        # (we never tell the LLM to invent one)
        assert "CVE-2025-12345" not in s


# ---------------------------------------------------------------------------
# Adversarial: never-invoke forbidden
# ---------------------------------------------------------------------------

class TestAdversarial:
    def test_enhance_never_inlines_password_in_real_file(self, tmp_path):
        """Run the enhancer on a copy of a real catalog file and
        confirm the command_examples / use_cases never contain a
        password=literal or long hex string."""
        # Copy a real file to tmp
        real = Path("catalog/github_00xCanelo_CVE-2025-27591.json")
        if not real.exists():
            pytest.skip("real catalog file not present")
        copy = tmp_path / "x.json"
        copy.write_text(real.read_text(encoding="utf-8"), encoding="utf-8")
        r = enhance_file(copy)
        assert r["ok"] is True
        text = copy.read_text(encoding="utf-8")
        # No password=literal (with value, not sentinel)
        import re
        # We allow the literal "$KFIOSA_TARGET_PASSWORD" sentinel
        # We forbid "password=\"secret_xxx\"" etc.
        forbidden = re.findall(r"password\s*=\s*\"[^\"$]", text)
        assert not forbidden, f"found forbidden password= in: {forbidden}"
        # No long hex strings
        longhex = re.findall(r"[a-f0-9]{32,}", text)
        # None of the existing fields should have a 32+ char hex blob
        # that isn't the NVD key (we never inline that here).
        assert not longhex, f"found long hex in: {longhex}"

    def test_enhance_protected_fields_immutable(self, tmp_path, sample_entry):
        p = tmp_path / "x.json"
        p.write_text(json.dumps(sample_entry), encoding="utf-8")
        # If somehow enhance_file tried to mutate id, it would error
        r = enhance_file(p)
        assert r["ok"] is True
        data = json.loads(p.read_text())
        # All protected fields identical to input
        for k in ("id", "kind", "full_name", "url", "category", "owner", "name"):
            assert data[k] == sample_entry[k]
