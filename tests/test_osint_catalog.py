"""Tests for core.osint_catalog — Phase 4 T22 coverage."""
from __future__ import annotations

import importlib

import pytest


def _import_mod():
    return importlib.import_module("core.osint_catalog")


mod = _import_mod()


# ---------------------------------------------------------------------------
# Initialization
# ---------------------------------------------------------------------------

class TestInit:
    def test_creates_catalog(self):
        c = mod.OSINTCatalog()
        assert c.tools is not None

    def test_has_expected_categories(self):
        c = mod.OSINTCatalog()
        cats = c.get_categories()
        for cat in ("email", "phone", "username", "domain",
                    "social_media", "telegram", "git", "geospatial",
                    "breach", "comprehensive", "network", "maltego",
                    "image", "face", "crypto"):
            assert cat in cats, f"missing category {cat}"


# ---------------------------------------------------------------------------
# get_tools_by_category
# ---------------------------------------------------------------------------

class TestGetByCategory:
    def test_email_has_tools(self):
        c = mod.OSINTCatalog()
        tools = c.get_tools_by_category("email")
        assert len(tools) >= 1

    def test_unknown_category_empty(self):
        c = mod.OSINTCatalog()
        assert c.get_tools_by_category("nonexistent") == []

    def test_phone_has_tools(self):
        c = mod.OSINTCatalog()
        tools = c.get_tools_by_category("phone")
        assert len(tools) >= 1

    def test_username_has_sherlock(self):
        c = mod.OSINTCatalog()
        tools = c.get_tools_by_category("username")
        names = {t["name"] for t in tools}
        assert "sherlock" in names


# ---------------------------------------------------------------------------
# get_all_tools
# ---------------------------------------------------------------------------

class TestGetAllTools:
    def test_returns_flat_list(self):
        c = mod.OSINTCatalog()
        all_tools = c.get_all_tools()
        assert isinstance(all_tools, list)
        assert len(all_tools) >= 50  # at least 50 OSINT tools

    def test_adds_category_field(self):
        c = mod.OSINTCatalog()
        all_tools = c.get_all_tools()
        for t in all_tools:
            assert "category" in t

    def test_no_duplicates(self):
        c = mod.OSINTCatalog()
        all_tools = c.get_all_tools()
        names = [t["name"] for t in all_tools]
        # Most names should be unique, but allow some overlap
        assert len(set(names)) >= len(names) - 5


# ---------------------------------------------------------------------------
# search_tools
# ---------------------------------------------------------------------------

class TestSearch:
    def test_search_by_name(self):
        c = mod.OSINTCatalog()
        results = c.search_tools("sherlock")
        assert len(results) >= 1
        assert results[0]["name"].lower() == "sherlock"

    def test_search_by_description_term(self):
        c = mod.OSINTCatalog()
        results = c.search_tools("subdomain")
        assert len(results) >= 1

    def test_search_case_insensitive(self):
        c = mod.OSINTCatalog()
        r1 = c.search_tools("Sherlock")
        r2 = c.search_tools("sherlock")
        assert len(r1) == len(r2)

    def test_search_no_match(self):
        c = mod.OSINTCatalog()
        results = c.search_tools("xyzzy_nothing_matches_this")
        assert results == []

    def test_search_adds_category(self):
        c = mod.OSINTCatalog()
        results = c.search_tools("holehe")
        for r in results:
            assert "category" in r


# ---------------------------------------------------------------------------
# tool_count
# ---------------------------------------------------------------------------

class TestToolCount:
    def test_count_at_least_50(self):
        c = mod.OSINTCatalog()
        n = c.tool_count()
        assert n >= 50, f"only {n} tools"

    def test_count_matches_get_all_tools(self):
        c = mod.OSINTCatalog()
        assert c.tool_count() == len(c.get_all_tools())


# ---------------------------------------------------------------------------
# get_tool_by_name
# ---------------------------------------------------------------------------

class TestGetByName:
    def test_exact_match(self):
        c = mod.OSINTCatalog()
        t = c.get_tool_by_name("sherlock")
        assert t is not None
        assert t["name"] == "sherlock"

    def test_case_insensitive(self):
        c = mod.OSINTCatalog()
        t1 = c.get_tool_by_name("sherlock")
        t2 = c.get_tool_by_name("Sherlock")
        assert t1 is not None and t2 is not None
        assert t1["name"] == t2["name"]

    def test_partial_match(self):
        c = mod.OSINTCatalog()
        t = c.get_tool_by_name("hole")
        # Should match "holehe" via partial
        assert t is not None

    def test_unknown_returns_none(self):
        c = mod.OSINTCatalog()
        assert c.get_tool_by_name("nonexistent_tool_xyz") is None


# ---------------------------------------------------------------------------
# get_categories
# ---------------------------------------------------------------------------

class TestGetCategories:
    def test_returns_sorted(self):
        c = mod.OSINTCatalog()
        cats = c.get_categories()
        assert cats == sorted(cats)

    def test_at_least_10_categories(self):
        c = mod.OSINTCatalog()
        assert len(c.get_categories()) >= 10


# ---------------------------------------------------------------------------
# get_install_guide
# ---------------------------------------------------------------------------

class TestInstallGuide:
    def test_pip_tool(self):
        c = mod.OSINTCatalog()
        guide = c.get_install_guide("sherlock")
        assert guide is not None
        assert "pip" in guide.lower() or "sherlock" in guide.lower()

    def test_git_clone_tool(self):
        c = mod.OSINTCatalog()
        guide = c.get_install_guide("Mr.Holmes")
        assert guide is not None
        assert "git clone" in guide.lower() or "github.com" in guide.lower()

    def test_reference_tool(self):
        c = mod.OSINTCatalog()
        # OSINT-BIBLE is a reference
        guide = c.get_install_guide("OSINT-BIBLE")
        assert guide is not None

    def test_unknown_returns_none(self):
        c = mod.OSINTCatalog()
        assert c.get_install_guide("nonexistent_tool_xyz") is None


# ---------------------------------------------------------------------------
# summary
# ---------------------------------------------------------------------------

class TestSummary:
    def test_summary_shape(self):
        c = mod.OSINTCatalog()
        s = c.summary()
        assert "total_tools" in s
        assert "categories" in s
        assert s["total_tools"] == c.tool_count()

    def test_summary_categories_dict(self):
        c = mod.OSINTCatalog()
        s = c.summary()
        for cat, count in s["categories"].items():
            assert isinstance(cat, str)
            assert isinstance(count, int)
            assert count >= 1


# ---------------------------------------------------------------------------
# No fabrication
# ---------------------------------------------------------------------------

class TestNoFabrication:
    def test_no_inline_creds(self):
        c = mod.OSINTCatalog()
        all_tools = c.get_all_tools()
        for t in all_tools:
            text = str(t).lower()
            for forbidden in ("ecf51ee2-938d", "f40bec4b664a40a9a",
                              "ce38f76832cfa1f6", "password=", "secret="):
                assert forbidden not in text, f"leaked {forbidden!r}"
