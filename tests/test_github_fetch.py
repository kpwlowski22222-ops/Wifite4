"""Tests for core.tool_installer.github_fetch (Phase 2.4)."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.tool_installer.github_fetch import (
    build_entry,
    fetch_all_to_catalog,
    fetch_list,
)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestFetchList:
    def test_returns_30(self):
        tools = fetch_list()
        assert len(tools) == 30

    def test_no_duplicate_slugs(self):
        tools = fetch_list()
        assert len(set(tools)) == 30

    def test_all_slugs_have_owner_and_repo(self):
        for slug in fetch_list():
            assert "/" in slug, slug
            owner, repo = slug.split("/", 1)
            assert owner and repo
            assert " " not in slug


class TestBuildEntry:
    def test_returns_none_for_unknown(self):
        assert build_entry("not/curated") is None

    def test_builds_valid_entry(self):
        e = build_entry("v1s1t0r1sh3r3/airgeddon")
        assert e is not None
        assert e["id"] == "github:v1s1t0r1sh3r3/airgeddon"
        assert e["full_name"] == "v1s1t0r1sh3r3/airgeddon"
        assert e["owner"] == "v1s1t0r1sh3r3"
        assert e["name"] == "airgeddon"
        assert e["url"] == "https://github.com/v1s1t0r1sh3r3/airgeddon"
        assert e["kind"] == "external_repository"
        assert e["category"] == "Wireless Security"
        assert e["metadata_status"] == "index_only"
        # Never fabricate stats
        assert "stargazers_count" not in e
        assert "version" not in e
        assert "commit_sha" not in e

    def test_includes_trust_warning(self):
        e = build_entry("smicallef/spiderfoot")
        assert e is not None
        assert "trust" in e
        assert e["trust"]["reviewed"] is False
        assert "warning" in e["trust"]

    @pytest.mark.parametrize("slug", fetch_list())
    def test_every_slug_creates_valid_entry(self, slug: str):
        e = build_entry(slug)
        assert e is not None
        # The entry has the minimum required github_* fields.
        for key in ("id", "name", "full_name", "owner", "url",
                    "category", "kind", "metadata_status"):
            assert key in e, f"{slug}: missing {key}"


class TestFetchAllToCatalog:
    def test_writes_to_empty_dir(self, tmp_path: Path):
        cat = tmp_path / "catalog"
        result = fetch_all_to_catalog(cat)
        assert result["ok"]
        # 30 - already_existing (10 from prior run) = written
        # But the tmp_path is empty, so all 30 should be written.
        assert result["written"] + result["skipped"] == 30
        # All written files must be valid JSON.
        for p in cat.glob("github_*.json"):
            data = json.loads(p.read_text())
            assert "id" in data
            assert "category" in data

    def test_idempotent(self, tmp_path: Path):
        cat = tmp_path / "catalog"
        r1 = fetch_all_to_catalog(cat)
        r2 = fetch_all_to_catalog(cat)
        # On the second pass all 30 should be skipped.
        assert r2["written"] == 0
        assert r2["skipped"] == 30
        assert r2["ok"]

    def test_returns_count_envelope(self, tmp_path: Path):
        cat = tmp_path / "catalog"
        r = fetch_all_to_catalog(cat)
        for k in ("ok", "written", "skipped", "failed", "total"):
            assert k in r
        assert r["total"] == 30
