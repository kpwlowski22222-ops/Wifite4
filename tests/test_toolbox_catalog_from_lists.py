"""tests.test_toolbox_catalog_from_lists — hermetic tests for the
``core.toolbox.catalog_from_lists`` module.

Coverage:
  - build_github_entry: shape, risk policy per category, idempotency
  - emit_from_list: dry-run vs write, skip-existing behavior,
    inline ``# cat: <cat>`` overrides the per-file default
  - main() CLI: --write flag, --lists-dir, --catalog-dir
  - All 6 fetch_lists/*.txt files parse cleanly (Phase 5 contract)

Why this file exists: Phase 5 added ``phase5_more.txt`` (130+
URLs) and updated the risk policy so non-exploit categories are
autonomously runnable. We want a hermetic test that catches:
  - regressions in the risk policy
  - regressions in inline-category parsing
  - regressions in the idempotency contract (re-runs skip existing
    files so operator-enriched entries survive)
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List

import pytest


# ---------------------------------------------------------------------------
# build_github_entry shape + risk policy
# ---------------------------------------------------------------------------

def test_build_github_entry_minimal_shape():
    from core.toolbox.catalog_from_lists import build_github_entry
    e = build_github_entry(
        "octocat", "hello-world",
        category="recon",
        description="test entry",
        list_file="phase5_more.txt",
    )
    assert e["id"] == "github:octocat/hello-world"
    assert e["kind"] == "external_repository"
    assert e["name"] == "hello-world"
    assert e["full_name"] == "octocat/hello-world"
    assert e["owner"] == "octocat"
    assert e["category"] == "recon"
    assert e["url"] == "https://github.com/octocat/hello-world"
    assert e["metadata_status"] == "index_only"
    assert "trust" in e
    assert "risk" in e


def test_risk_policy_exploit_category_is_gated():
    """Exploit category requires explicit authorization and is NOT
    autonomously runnable. This is the highest-risk surface — CVE
    PoCs, kernel exploits, RCE chains."""
    from core.toolbox.catalog_from_lists import build_github_entry
    e = build_github_entry("a", "b", category="exploit",
                            description="x", list_file="x.txt")
    assert e["risk"]["requires_explicit_authorization"] is True
    assert e["risk"]["allow_autonomous_execution"] is False
    assert e["risk"]["level"] == "high"
    assert "exploit" in e["risk"]["signals"]


@pytest.mark.parametrize("category", [
    "post_exploitation", "osint", "recon", "web", "c2",
    "wifi", "ble", "android", "ios", "microsoft",
])
def test_risk_policy_non_exploit_categories_are_autonomous(category):
    """Non-exploit categories are autonomously runnable so the
    chain planner can chain them behind the per-step ACCEPT/CANCEL
    gate. The chain step itself is gated; the entry signals the
    runner can invoke without additional operator action."""
    from core.toolbox.catalog_from_lists import build_github_entry
    e = build_github_entry("a", "b", category=category,
                            description="x", list_file="x.txt")
    assert e["risk"]["requires_explicit_authorization"] is False
    assert e["risk"]["allow_autonomous_execution"] is True
    assert e["risk"]["level"] == "medium"


# ---------------------------------------------------------------------------
# Phase 5 enrichment: curated description maps
# ---------------------------------------------------------------------------

def test_repo_summaries_map_is_populated():
    """Phase 5 contract: every major tool from the operator's
    fetch lists has a curated entry in ``_REPO_SUMMARIES``. This
    is what the operator asked for: 'catalog/ contents must be
    described as much as possible'."""
    from core.toolbox.catalog_from_lists import _REPO_SUMMARIES
    # We expect at least 80 curated entries covering the major
    # tools from phase3/4/5. (Was 50 before Phase 5 enrichment.)
    assert len(_REPO_SUMMARIES) >= 80, (
        f"only {len(_REPO_SUMMARIES)} curated descriptions; "
        f"expected >= 80"
    )
    # Spot-check 6 well-known tools are present with non-trivial
    # descriptions.
    for full_name, expected_keyword in [
        ("threat9/routersploit", "RouterSploit"),
        ("BishopFox/sliver", "Sliver"),
        ("fortra/impacket", "Impacket"),
        ("PowerShellMafia/PowerSploit", "PowerSploit"),
        ("sqlmapproject/sqlmap", "sqlmap"),
        ("smicallef/spiderfoot", "SpiderFoot"),
    ]:
        assert full_name in _REPO_SUMMARIES, (
            f"{full_name} missing from _REPO_SUMMARIES"
        )
        assert expected_keyword in _REPO_SUMMARIES[full_name]
        # Real descriptions are > 80 chars; the empty / one-line
        # placeholder is the bug the test is preventing.
        assert len(_REPO_SUMMARIES[full_name]) > 80


def test_category_defaults_map_is_populated():
    """Every category used in the fetch lists has a default
    description in ``_CATEGORY_DEFAULTS`` so even uncurated
    entries get a useful summary."""
    from core.toolbox.catalog_from_lists import _CATEGORY_DEFAULTS
    for category in [
        "exploit", "post_exploitation", "osint", "recon", "web",
        "c2", "wifi", "ble", "android", "ios", "microsoft",
        "frameworks", "offensive", "wireless_ble_ext",
    ]:
        assert category in _CATEGORY_DEFAULTS, (
            f"category {category!r} missing from _CATEGORY_DEFAULTS"
        )
        assert len(_CATEGORY_DEFAULTS[category]) > 40


def test_summary_for_uses_curated_map_first():
    """When a repo is in ``_REPO_SUMMARIES``, the curated entry
    wins. This is the operator's 'describe as much as possible'
    contract: the LLM gets the curated, multi-sentence
    description, not the generic category default."""
    from core.toolbox.catalog_from_lists import _summary_for
    s = _summary_for("threat9", "routersploit", "frameworks")
    # Curated description includes 'RouterSploit' and
    # 'Metasploit'; the generic default does not.
    assert "RouterSploit" in s
    assert "Metasploit" in s


def test_summary_for_falls_back_to_category_default():
    """Repos not in the curated map get a category-derived
    default that still tells the LLM what category the tool
    fits and the gating policy."""
    from core.toolbox.catalog_from_lists import _summary_for
    s = _summary_for("nobody", "some-tool", "osint")
    assert "**nobody/some-tool**" in s
    assert "OSINT" in s.upper() or "osint" in s.lower()
    assert "scope" in s.lower() or "operator" in s.lower() or "contact" in s.lower()


def test_derive_tag_strips_separators():
    """The ``tags`` field should be searchable by the LLM with
    common variants: 'pupy', 'pupy-rat', 'Pupy_Rat' all map to
    the same tag."""
    from core.toolbox.catalog_from_lists import _derive_tag
    assert _derive_tag("a", "Pupy") == "pupy"
    assert _derive_tag("a", "pupy-rat") == "pupyrat"
    assert _derive_tag("a", "pupy_rat") == "pupyrat"
    assert _derive_tag("a", "n1nj4.pupy") == "n1nj4pupy"


def test_entry_includes_tags_and_curated_summary(tmp_path):
    """End-to-end: emit a phase5 entry and assert the resulting
    JSON has the new ``tags`` field and the curated summary."""
    from core.toolbox.catalog_from_lists import emit_from_list
    list_path = tmp_path / "phase5_more.txt"
    list_path.write_text(
        "https://github.com/threat9/routersploit  # cat: frameworks\n"
    )
    catalog = tmp_path / "c"
    out = emit_from_list(list_path, catalog_dir=catalog, dry_run=False)
    assert len(out) == 1
    import json
    d = json.loads((catalog / out[0]).read_text())
    assert d["category"] == "frameworks"
    assert "tags" in d
    assert "frameworks" in d["tags"]
    assert "routersploit" in d["tags"]
    # Curated summary is the routersploit one, not the generic default
    assert "RouterSploit" in d["summary"]
    assert "Metasploit" in d["summary"]


# ---------------------------------------------------------------------------
# Phase 5+ enrichment: use_cases + command_examples
# ---------------------------------------------------------------------------

def test_repo_details_map_is_populated():
    """Phase 5+ contract: every major tool from the operator's
    fetch lists has curated ``use_cases`` and
    ``command_examples`` so the LLM can decide WHEN and HOW to
    invoke the tool."""
    from core.toolbox.catalog_from_lists import _REPO_DETAILS
    assert len(_REPO_DETAILS) >= 30, (
        f"only {len(_REPO_DETAILS)} curated details; "
        f"expected >= 30"
    )
    for full_name, details in _REPO_DETAILS.items():
        assert "use_cases" in details
        assert "command_examples" in details
        assert len(details["use_cases"]) >= 1
        assert len(details["command_examples"]) >= 1


def test_category_use_cases_map_is_populated():
    """Every category used in the fetch lists has default
    use_cases so even un-curated entries get actionable hints."""
    from core.toolbox.catalog_from_lists import _CATEGORY_USE_CASES
    for category in [
        "exploit", "post_exploitation", "osint", "recon", "web",
        "c2", "wifi", "ble", "android", "ios", "microsoft",
        "frameworks", "offensive", "wireless_ble_ext",
    ]:
        assert category in _CATEGORY_USE_CASES, (
            f"category {category!r} missing from _CATEGORY_USE_CASES"
        )
        assert len(_CATEGORY_USE_CASES[category]) >= 2


def test_details_for_uses_curated_map_first():
    """When a repo is in ``_REPO_DETAILS``, the curated entry
    wins. Spot-check a major tool."""
    from core.toolbox.catalog_from_lists import _details_for
    d = _details_for("threat9", "routersploit", "frameworks")
    # Curated: 'default-credential scan of an exposed router'
    assert any("router" in u.lower() for u in d["use_cases"])
    # Curated: 'python rsf.py --target <ip>'
    assert any("rsf" in c for c in d["command_examples"])


def test_details_for_falls_back_to_category_default():
    """Repos not in the curated map get a category-derived
    default that still tells the LLM when to use the tool."""
    from core.toolbox.catalog_from_lists import _details_for
    d = _details_for("nobody", "some-tool", "osint")
    assert len(d["use_cases"]) >= 2
    assert len(d["command_examples"]) >= 1
    # OSINT defaults mention "passive" or "OSINT"
    joined = " ".join(d["use_cases"]).lower()
    assert "osint" in joined or "passive" in joined or "recon" in joined


def test_entry_includes_use_cases_and_command_examples(tmp_path):
    """End-to-end: emit a curated entry and assert the new
    ``use_cases`` + ``command_examples`` fields are present and
    non-empty."""
    from core.toolbox.catalog_from_lists import emit_from_list
    list_path = tmp_path / "phase5_more.txt"
    list_path.write_text(
        "https://github.com/threat9/routersploit  # cat: frameworks\n"
    )
    catalog = tmp_path / "c"
    out = emit_from_list(list_path, catalog_dir=catalog, dry_run=False)
    import json
    d = json.loads((catalog / out[0]).read_text())
    assert "use_cases" in d
    assert "command_examples" in d
    assert len(d["use_cases"]) >= 2
    assert len(d["command_examples"]) >= 1
    # Curated: routersploit has 'rsf.py' in the examples
    assert any("rsf" in c for c in d["command_examples"])


# ---------------------------------------------------------------------------
# emit_from_list: dry-run, write, skip-existing
# ---------------------------------------------------------------------------

def test_emit_from_list_dry_run_returns_filenames(tmp_path):
    from core.toolbox.catalog_from_lists import emit_from_list
    list_path = tmp_path / "phase5_more.txt"
    list_path.write_text(
        "https://github.com/octocat/Hello-World  # cat: osint\n"
        "https://github.com/octocat/Spoon-Knife  # cat: recon\n"
    )
    out = emit_from_list(list_path, catalog_dir=tmp_path / "c", dry_run=True)
    assert len(out) == 2
    # dry-run: no files were actually written
    assert not (tmp_path / "c").exists() or not list((tmp_path / "c").iterdir())


def test_emit_from_list_write_creates_files(tmp_path):
    from core.toolbox.catalog_from_lists import emit_from_list
    list_path = tmp_path / "phase5_more.txt"
    list_path.write_text(
        "https://github.com/octocat/Hello-World  # cat: osint\n"
    )
    catalog = tmp_path / "c"
    out = emit_from_list(list_path, catalog_dir=catalog, dry_run=False)
    assert len(out) == 1
    f = catalog / out[0]
    assert f.is_file()
    d = json.loads(f.read_text())
    assert d["category"] == "osint"
    assert d["owner"] == "octocat"


def test_emit_from_list_idempotent_skips_existing(tmp_path):
    """Re-running the emit on a populated catalog must NOT overwrite
    operator-enriched entries. The contract: skip-existing is
    signaled in the returned filename list."""
    from core.toolbox.catalog_from_lists import emit_from_list
    list_path = tmp_path / "phase5_more.txt"
    list_path.write_text(
        "https://github.com/octocat/Hello-World  # cat: osint\n"
    )
    catalog = tmp_path / "c"
    # First write
    out1 = emit_from_list(list_path, catalog_dir=catalog, dry_run=False)
    assert len(out1) == 1
    assert "(skipped" not in out1[0]
    # Mutate the existing entry to detect overwrites
    f = catalog / out1[0]
    original = json.loads(f.read_text())
    original["category"] = "OPERATOR_OVERRIDE"
    f.write_text(json.dumps(original, indent=2) + "\n")
    # Second emit: must skip, must not overwrite
    out2 = emit_from_list(list_path, catalog_dir=catalog, dry_run=False)
    assert len(out2) == 1
    assert "(skipped" in out2[0]
    after = json.loads(f.read_text())
    assert after["category"] == "OPERATOR_OVERRIDE"


def test_emit_from_list_inline_category_overrides_default(tmp_path):
    """Phase 4/5: ``# cat: <category>`` inline hint overrides the
    per-file default category. Without the hint, falls back to the
    per-file default."""
    from core.toolbox.catalog_from_lists import emit_from_list
    list_path = tmp_path / "phase5_more.txt"
    list_path.write_text(
        "https://github.com/octocat/A  # cat: osint\n"
        "https://github.com/octocat/B  # cat: web\n"
        "https://github.com/octocat/C  # cat: c2\n"
    )
    catalog = tmp_path / "c"
    out = emit_from_list(list_path, catalog_dir=catalog, dry_run=False)
    assert len(out) == 3
    cats = []
    for fname in out:
        d = json.loads((catalog / fname).read_text())
        cats.append((d["full_name"], d["category"]))
    assert ("octocat/A", "osint") in cats
    assert ("octocat/B", "web") in cats
    assert ("octocat/C", "c2") in cats


def test_emit_from_list_no_inline_category_uses_default(tmp_path):
    from core.toolbox.catalog_from_lists import emit_from_list
    list_path = tmp_path / "phase5_more.txt"
    list_path.write_text(
        "https://github.com/octocat/A  # plain comment, no cat hint\n"
    )
    catalog = tmp_path / "c"
    out = emit_from_list(list_path, catalog_dir=catalog, dry_run=False)
    assert len(out) == 1
    d = json.loads((catalog / out[0]).read_text())
    # phase5_more.txt's default is "offensive" (see _LIST_CATEGORY)
    assert d["category"] == "offensive"


def test_emit_from_list_skips_unparseable_urls(tmp_path):
    from core.toolbox.catalog_from_lists import emit_from_list
    list_path = tmp_path / "phase5_more.txt"
    list_path.write_text(
        "https://example.com/notgithub/foo\n"  # not github
        "garbage line\n"  # not a URL
        "https://github.com/octocat/Hello-World  # cat: osint\n"
    )
    catalog = tmp_path / "c"
    out = emit_from_list(list_path, catalog_dir=catalog, dry_run=False)
    assert len(out) == 1
    assert "Hello-World" in out[0]


# ---------------------------------------------------------------------------
# All 6 fetch_lists/*.txt parse cleanly (Phase 5 contract)
# ---------------------------------------------------------------------------

def _project_root() -> Path:
    # tests/ is one level deep
    return Path(__file__).resolve().parent.parent


@pytest.mark.parametrize("list_name", [
    "fresh_cves.txt",
    "kali_frameworks.txt",
    "phase3_more.txt",
    "phase4_offensive.txt",
    "phase5_more.txt",
    "phase6_more.txt",
    "wireless_ble_ext.txt",
])
def test_fetch_list_parses_at_least_one_entry(list_name):
    """Every fetch list must parse to >= 1 valid (url, category)
    pair. Phase 5 contract: phase5_more.txt adds 130+ on top of
    the 4 prior lists. Phase 6 contract: phase6_more.txt adds
    140+ more from 4 parallel web-research subagents."""
    from core.toolbox.fetch import parse_list_with_categories
    p = _project_root() / "core" / "toolbox" / "fetch_lists" / list_name
    if not p.is_file():
        pytest.skip(f"{list_name} not present in this checkout")
    entries = parse_list_with_categories(p.read_text())
    assert len(entries) >= 1, f"{list_name} parsed to 0 entries"
    for url, cat in entries:
        assert url.startswith("https://github.com/"), url
        # cat is either None (uses default) or a non-empty string
        if cat is not None:
            assert cat, f"{list_name} has empty cat hint for {url}"


def test_phase5_more_has_at_least_120_entries():
    """Phase 5 contract: phase5_more.txt brings the curated fetch
    list total to 466+ across 6 lists, with phase5 itself adding
    120+ on top of the prior 336."""
    from core.toolbox.fetch import parse_list_with_categories
    p = _project_root() / "core" / "toolbox" / "fetch_lists" / "phase5_more.txt"
    entries = parse_list_with_categories(p.read_text())
    assert len(entries) >= 120, (
        f"phase5_more.txt has {len(entries)} entries, expected >= 120"
    )


def test_phase6_more_has_at_least_120_entries():
    """Phase 6 contract: phase6_more.txt adds 140+ on top of the
    466 from phase 5, sourced from 4 parallel web-research
    subagents. Brings the curated total to 600+."""
    from core.toolbox.fetch import parse_list_with_categories
    p = _project_root() / "core" / "toolbox" / "fetch_lists" / "phase6_more.txt"
    if not p.is_file():
        pytest.skip("phase6_more.txt not present")
    entries = parse_list_with_categories(p.read_text())
    assert len(entries) >= 120, (
        f"phase6_more.txt has {len(entries)} entries, expected >= 120"
    )


def test_phase6_more_covers_all_categories():
    """Phase 6 contract: phase6_more.txt explicitly covers the
    categories the 4 subagents researched: c2, post_exploitation,
    osint, recon, exploit, microsoft, wifi, ble, web, android, ios.
    """
    from core.toolbox.fetch import parse_list_with_categories
    p = _project_root() / "core" / "toolbox" / "fetch_lists" / "phase6_more.txt"
    if not p.is_file():
        pytest.skip("phase6_more.txt not present")
    entries = parse_list_with_categories(p.read_text())
    cats = {c for _, c in entries if c is not None}
    for required in [
        "c2", "post_exploitation", "osint", "recon", "exploit",
        "microsoft", "wifi", "ble", "web", "android", "ios",
    ]:
        assert required in cats, (
            f"phase6_more.txt missing category {required!r}; "
            f"have {sorted(cats)}"
        )


def test_phase5_more_covers_underrepresented_categories():
    """Phase 5 contract: phase5_more.txt explicitly covers
    post_exploitation, osint, recon, web, c2, android, ios — the
    under-represented categories from the pre-Phase-5 audit."""
    from core.toolbox.fetch import parse_list_with_categories
    p = _project_root() / "core" / "toolbox" / "fetch_lists" / "phase5_more.txt"
    entries = parse_list_with_categories(p.read_text())
    cats = {c for _, c in entries if c is not None}
    # All 9 underrepresented categories present
    for required in [
        "post_exploitation", "osint", "recon", "web", "c2",
        "android", "ios", "wifi", "ble", "exploit",
    ]:
        assert required in cats, (
            f"phase5_more.txt missing category {required!r}; "
            f"have {sorted(cats)}"
        )


# ---------------------------------------------------------------------------
# main() CLI smoke
# ---------------------------------------------------------------------------

def test_main_dry_run_no_files_written(tmp_path, capsys):
    """``python -m core.toolbox.catalog_from_lists`` without --write
    is a dry-run — no catalog files are touched."""
    from core.toolbox.catalog_from_lists import main
    # Use a tmp_lists_dir so we don't pollute the real fetch_lists
    list_dir = tmp_path / "lists"
    list_dir.mkdir()
    (list_dir / "phase5_more.txt").write_text(
        "https://github.com/octocat/Hello-World  # cat: osint\n"
    )
    rc = main(["--lists-dir", str(list_dir), "--catalog-dir", str(tmp_path / "c")])
    assert rc == 0
    out = capsys.readouterr().out
    assert "DRY-RUN" in out
    assert not (tmp_path / "c").exists() or not list((tmp_path / "c").iterdir())


def test_main_write_creates_files(tmp_path, capsys):
    from core.toolbox.catalog_from_lists import main
    list_dir = tmp_path / "lists"
    list_dir.mkdir()
    (list_dir / "phase5_more.txt").write_text(
        "https://github.com/octocat/Hello-World  # cat: osint\n"
    )
    rc = main(["--lists-dir", str(list_dir), "--catalog-dir",
               str(tmp_path / "c"), "--write"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "WROTE" in out
    files = list((tmp_path / "c").iterdir())
    assert len(files) == 1


def test_main_missing_lists_dir_returns_2(tmp_path, capsys):
    from core.toolbox.catalog_from_lists import main
    rc = main(["--lists-dir", str(tmp_path / "nonexistent"),
               "--catalog-dir", str(tmp_path / "c")])
    assert rc == 2
    err = capsys.readouterr().err
    assert "lists dir not found" in err


# ---------------------------------------------------------------------------
# Phase 5: list registration (catalog_from_lists maps for new files)
# ---------------------------------------------------------------------------

def test_phase5_more_list_is_registered():
    """Phase 5 contract: phase5_more.txt is in the
    ``_LIST_CATEGORY`` map so the catalog emit picks it up."""
    from core.toolbox.catalog_from_lists import _LIST_CATEGORY
    assert "phase5_more.txt" in _LIST_CATEGORY


def test_phase5_more_list_has_description():
    """The list description is what the operator sees in the
    dry-run output and what flows into the summary for entries
    on the new list."""
    from core.toolbox.catalog_from_lists import _LIST_DESCRIPTION
    assert "phase5_more.txt" in _LIST_DESCRIPTION
    desc = _LIST_DESCRIPTION["phase5_more.txt"]
    # Must mention the operator's Phase 5 intent
    assert "post_exploitation" in desc
    assert "osint" in desc
    assert "recon" in desc
    assert "web" in desc
    assert "c2" in desc
    assert "android" in desc
    assert "ios" in desc


def test_phase6_more_list_is_registered():
    """Phase 6 contract: phase6_more.txt is in the
    ``_LIST_CATEGORY`` map so the catalog emit picks it up."""
    from core.toolbox.catalog_from_lists import _LIST_CATEGORY
    assert "phase6_more.txt" in _LIST_CATEGORY


def test_phase6_more_list_has_description():
    """Phase 6 contract: phase6_more.txt has a description
    mentioning the 4-subagent fan-out sourcing."""
    from core.toolbox.catalog_from_lists import _LIST_DESCRIPTION
    assert "phase6_more.txt" in _LIST_DESCRIPTION
    desc = _LIST_DESCRIPTION["phase6_more.txt"]
    assert "subagent" in desc.lower() or "agent" in desc.lower()
    # The new categories from the 4 subagents
    for cat in ("c2", "post_exploitation", "osint", "wifi", "ble", "web"):
        assert cat in desc, f"phase6 desc missing category {cat!r}"


def test_all_fetch_lists_have_category_and_description():
    """Every fetch list registered in ``_LIST_CATEGORY`` must
    also have a description. This catches the case where a new
    list is added but the description map isn't updated."""
    from core.toolbox.catalog_from_lists import (
        _LIST_CATEGORY, _LIST_DESCRIPTION,
    )
    for list_file in _LIST_CATEGORY:
        assert list_file in _LIST_DESCRIPTION, (
            f"{list_file} in _LIST_CATEGORY but missing from "
            f"_LIST_DESCRIPTION"
        )


# ---------------------------------------------------------------------------
# Phase 5+ schema: official schema documents the new fields
# ---------------------------------------------------------------------------

def test_catalog_schema_documents_new_fields():
    """The official ``catalog/catalog.schema.json`` must document
    the Phase 5+ fields so downstream consumers can rely on
    them. We check for the property names — types are
    additionalProperties: true so this is a soft check."""
    import json
    schema_path = _project_root() / "catalog" / "catalog.schema.json"
    schema = json.loads(schema_path.read_text())
    repo_props = (
        schema["$defs"]["repository"]["properties"]
    )
    # Soft check: the new fields appear in the schema
    for field in (
        "summary", "tags", "use_cases", "command_examples",
        "toolbox_path", "trust",
    ):
        assert field in repo_props, (
            f"catalog.schema.json repository.$defs is missing "
            f"the {field!r} field"
        )
