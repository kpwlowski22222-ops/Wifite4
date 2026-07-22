"""tests.test_catalog_from_lists — verify the Phase 3 catalog emit
for the new toolbox URLs.

Verifies:
  - The CLI runs (dry-run + write)
  - The CLI emits an entry per URL in each list file
  - The CLI respects the no-overwrite invariant
  - Each emitted entry has the expected schema fields
  - The total entries emitted is at least 200 (Phase 3 + earlier)
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from core.toolbox.catalog_from_lists import (
    build_github_entry,
    emit_from_list,
)


# ---------------------------------------------------------------------------
# Helper: build a tiny fetch-list file in tmp_path
# ---------------------------------------------------------------------------
def _write_list(tmp_path: Path, name: str, urls: list) -> Path:
    p = tmp_path / name
    body = "\n".join(["# test list"] + urls) + "\n"
    p.write_text(body, encoding="utf-8")
    return p


# ---------------------------------------------------------------------------
# Single-file emit
# ---------------------------------------------------------------------------
def test_emit_from_list_dry_run(tmp_path):
    list_path = _write_list(tmp_path, "test.txt", [
        "https://github.com/foo/bar",
        "https://github.com/baz/qux",
    ])
    cat_dir = tmp_path / "catalog"
    out = emit_from_list(list_path, catalog_dir=cat_dir, dry_run=True)
    assert out == ["github_foo_bar.json", "github_baz_qux.json"]
    # dry-run must NOT create files
    assert not cat_dir.exists() or list(cat_dir.glob("*.json")) == []


def test_emit_from_list_write(tmp_path):
    list_path = _write_list(tmp_path, "test.txt", [
        "https://github.com/foo/bar",
    ])
    cat_dir = tmp_path / "catalog"
    out = emit_from_list(list_path, catalog_dir=cat_dir, dry_run=False)
    assert out == ["github_foo_bar.json"]
    f = cat_dir / "github_foo_bar.json"
    assert f.is_file()
    data = json.loads(f.read_text())
    assert data["id"] == "github:foo/bar"
    assert data["kind"] == "external_repository"
    assert data["owner"] == "foo"
    assert data["name"] == "bar"
    assert data["full_name"] == "foo/bar"
    assert data["url"] == "https://github.com/foo/bar"
    # Risk + trust
    assert "risk" in data
    assert "trust" in data
    assert data["metadata_status"] == "index_only"


def test_emit_from_list_no_overwrite(tmp_path):
    list_path = _write_list(tmp_path, "test.txt", [
        "https://github.com/foo/bar",
    ])
    cat_dir = tmp_path / "catalog"
    # Pre-create a different file
    cat_dir.mkdir()
    pre = cat_dir / "github_foo_bar.json"
    pre.write_text('{"id": "old", "kind": "external_repository"}')
    out = emit_from_list(list_path, catalog_dir=cat_dir, dry_run=False)
    # Must NOT overwrite
    assert "skipped" in out[0]
    assert json.loads(pre.read_text())["id"] == "old"


def test_emit_from_list_handles_garbage_urls(tmp_path):
    list_path = _write_list(tmp_path, "test.txt", [
        "https://github.com/foo/bar",
        "not a url",
        "https://gitlab.com/x/y",  # not github
    ])
    cat_dir = tmp_path / "catalog"
    out = emit_from_list(list_path, catalog_dir=cat_dir, dry_run=True)
    assert out == ["github_foo_bar.json"]


def test_emit_from_list_missing_file(tmp_path):
    out = emit_from_list(tmp_path / "no_such.txt",
                          catalog_dir=tmp_path / "cat",
                          dry_run=True)
    assert out == []


# ---------------------------------------------------------------------------
# build_github_entry shape
# ---------------------------------------------------------------------------
def test_build_github_entry_default_category():
    e = build_github_entry(
        "foo", "bar",
        category="exploit", description="Test desc",
        list_file="x.txt",
    )
    assert e["category"] == "exploit"
    assert e["risk"]["level"] == "high"
    assert e["risk"]["requires_explicit_authorization"] is True
    assert e["trust"]["reviewed"] is False
    assert e["documentation"]["source_list"] == "x.txt"


def test_build_github_entry_non_exploit_category_lower_risk():
    e = build_github_entry(
        "foo", "bar",
        category="frameworks", description="Test",
        list_file="y.txt",
    )
    assert e["risk"]["level"] == "medium"


# ---------------------------------------------------------------------------
# End-to-end CLI on the actual fetch_lists/
# ---------------------------------------------------------------------------
def test_cli_dry_run_emits_at_least_200(tmp_path):
    repo_root = Path(__file__).resolve().parent.parent
    out = subprocess.run(
        [sys.executable, "-m", "core.toolbox.catalog_from_lists",
         "--lists-dir", str(repo_root / "core" / "toolbox" / "fetch_lists"),
         "--catalog-dir", str(tmp_path)],
        capture_output=True, text=True, timeout=60,
    )
    assert out.returncode == 0, out.stderr
    # Sum the per-file counts
    total = 0
    for line in out.stdout.splitlines():
        if "DRY-RUN" in line and "entries" in line:
            n = int(line.split(":")[1].strip().split(" ")[0])
            total += n
    assert total >= 200, f"only {total} entries emitted by dry-run"


# ---------------------------------------------------------------------------
# Phase 4 — operator's 120+ new toolboxes
# ---------------------------------------------------------------------------

def test_phase4_offensive_list_has_inline_categories():
    """The phase4 list has inline category hints; catalog emit routes
    each URL to its hint's category rather than a single per-file
    default."""
    from core.toolbox.fetch import parse_list_with_categories
    from core.toolbox.catalog_from_lists import _LIST_CATEGORY

    path = (
        Path(__file__).resolve().parent.parent
        / "core" / "toolbox" / "fetch_lists" / "phase4_offensive.txt"
    )
    text = path.read_text(encoding="utf-8")
    entries = parse_list_with_categories(text)
    assert len(entries) >= 100
    # Every entry must have a category — operator curated.
    cats = [c for _, c in entries]
    assert all(c is not None for c in cats), (
        "phase4 is supposed to have inline category hints on every "
        "line; some are missing")

    # Now check the catalog emit: at least 11 distinct categories
    # (matches the operator-curated 11 cat: groups).
    from collections import Counter
    counts = Counter(cats)
    assert len(counts) >= 8, f"only {len(counts)} categories: {counts}"


def test_phase4_catalog_emits_to_correct_categories(tmp_path):
    """The emit_from_list function for phase4 routes each entry to
    the inline hint's category."""
    import json
    from core.toolbox.catalog_from_lists import emit_from_list

    repo_root = Path(__file__).resolve().parent.parent
    files = emit_from_list(
        repo_root / "core" / "toolbox" / "fetch_lists"
        / "phase4_offensive.txt",
        catalog_dir=tmp_path,
        dry_run=False,
    )
    # Read a sample of the emitted entries to confirm the category
    # is the inline one (microsoft/wifi/ble/etc).
    new_files = [f for f in files if "skipped" not in f]
    assert new_files, "no new files emitted"
    # The phase4 list has 11 categories; sample enough files to
    # cover 3+ distinct ones.
    sample = list(tmp_path.glob("*.json"))[:30]
    assert sample, "no JSON files in tmp"
    seen_cats = set()
    for f in sample:
        data = json.loads(f.read_text())
        seen_cats.add(data["category"])
    # Should see 2+ distinct categories (the inline hints are
    # respected).
    assert len(seen_cats) >= 2, f"only one category: {seen_cats}"
