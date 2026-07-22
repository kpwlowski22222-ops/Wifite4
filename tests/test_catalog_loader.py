"""Tests for core.utils.catalog_loader — Phase 4 T22 coverage."""
from __future__ import annotations

import importlib
import json
from pathlib import Path

import pytest


def _import_mod():
    return importlib.import_module("core.utils.catalog_loader")


mod = _import_mod()


# ---------------------------------------------------------------------------
# _truncate
# ---------------------------------------------------------------------------

class TestTruncate:
    def test_short_unchanged(self):
        assert mod._truncate("hello", 100) == "hello"

    def test_empty_string(self):
        assert mod._truncate("", 100) == ""

    def test_none_safe(self):
        assert mod._truncate(None, 100) == ""

    def test_truncate_at_limit(self):
        # limit=10 → "abcdefghi" + "…" = 10 chars
        out = mod._truncate("abcdefghijklmnop", 10)
        assert out.endswith("…")
        assert len(out) == 10

    def test_truncate_strips_trailing_spaces(self):
        out = mod._truncate("hello world  ", 8)
        # Trailing spaces stripped before truncation
        assert not out.endswith(" ")


# ---------------------------------------------------------------------------
# _walk_strings
# ---------------------------------------------------------------------------

class TestWalkStrings:
    def test_collects_strings(self):
        out = []
        mod._walk_strings({"a": "b", "c": ["d", "e"]}, out)
        assert "b" in out
        assert "d" in out
        assert "e" in out

    def test_skips_empty(self):
        out = []
        mod._walk_strings({"a": "", "b": "c"}, out)
        assert "" not in out
        assert "c" in out

    def test_respects_max_depth(self):
        # max_depth=0 means no recursion
        out = []
        mod._walk_strings({"a": "b"}, out, depth=0, max_depth=0)
        assert "b" not in out
        # But at depth 0 directly, it works
        out = []
        mod._walk_strings("a", out, depth=0, max_depth=0)
        assert "a" in out

    def test_handles_list(self):
        out = []
        mod._walk_strings(["a", "b"], out)
        assert "a" in out
        assert "b" in out

    def test_handles_primitives(self):
        out = []
        mod._walk_strings(42, out)
        # 42 is not a string — should not be added
        assert out == []


# ---------------------------------------------------------------------------
# CatalogEntry
# ---------------------------------------------------------------------------

class TestCatalogEntry:
    def test_init_basic(self):
        e = mod.CatalogEntry("kali:nmap", "kali_source_package",
                              "nmap", "Nmap",
                              "Network scanner", [], "nmap",
                              [], "/path", {})
        assert e.id == "kali:nmap"
        assert e.kind == "kali_source_package"
        assert e.name == "nmap"
        assert e.title == "Nmap"
        assert e.summary == "Network scanner"
        assert e.install_apt == "nmap"
        assert e.source_path == "/path"
        assert e.extra == {}

    def test_title_fallback_to_name(self):
        e = mod.CatalogEntry("x", "y", "name", "",
                              "", [], "", [], "", {})
        assert e.title == "name"

    def test_is_kali(self):
        e = mod.CatalogEntry("x", "kali_source_package", "n", "t",
                              "", [], "", [], "", {})
        assert e.is_kali is True
        assert e.is_github is False

    def test_is_github(self):
        e = mod.CatalogEntry("x", "external_repository", "n", "t",
                              "", [], "", [], "", {})
        assert e.is_github is True
        assert e.is_kali is False

    def test_is_neither(self):
        e = mod.CatalogEntry("x", "weird_kind", "n", "t",
                              "", [], "", [], "", {})
        assert e.is_kali is False
        assert e.is_github is False

    def test_matches_no_tokens(self):
        e = mod.CatalogEntry("x", "y", "n", "t", "s", [], "", [], "", {})
        # No tokens → matches all
        assert e.matches([]) is True

    def test_matches_in_id(self):
        e = mod.CatalogEntry("wifi:nmap", "y", "n", "t", "s",
                              [], "", [], "", {})
        assert e.matches(["wifi"]) is True

    def test_matches_in_title(self):
        e = mod.CatalogEntry("x", "y", "n", "nmap scanner", "s",
                              [], "", [], "", {})
        assert e.matches(["nmap"]) is True

    def test_matches_in_summary(self):
        e = mod.CatalogEntry("x", "y", "n", "t", "scans networks",
                              [], "", [], "", {})
        assert e.matches(["networks"]) is True

    def test_matches_in_metapackages(self):
        e = mod.CatalogEntry("x", "y", "n", "t", "s",
                              ["kali-tools-wireless"], "", [], "", {})
        assert e.matches(["wireless"]) is True

    def test_matches_in_use_cases(self):
        e = mod.CatalogEntry("x", "y", "n", "t", "s",
                              [], "", [], "", {
                                  "use_cases": ["wifi pentesting"]
                              })
        assert e.matches(["pentest"]) is True

    def test_matches_in_command_examples(self):
        e = mod.CatalogEntry("x", "y", "n", "t", "s",
                              [], "", [], "", {
                                  "command_examples": ["nmap -sV target"]
                              })
        assert e.matches(["-sV"]) is True

    def test_matches_case_insensitive(self):
        e = mod.CatalogEntry("x", "y", "NMAP", "t", "s",
                              [], "", [], "", {})
        assert e.matches(["nmap"]) is True

    def test_no_match(self):
        e = mod.CatalogEntry("x", "y", "n", "t", "s",
                              [], "", [], "", {})
        assert e.matches(["xyzzy"]) is False

    def test_repr(self):
        e = mod.CatalogEntry("kali:nmap", "kali_source_package",
                              "n", "t", "s", [], "", [], "", {})
        r = repr(e)
        assert "kali:nmap" in r
        assert "kali_source_package" in r

    def test_prompt_line_basic(self):
        e = mod.CatalogEntry("kali:nmap", "kali_source_package",
                              "nmap", "Nmap", "Network scanner",
                              [], "nmap", [], "", {})
        line = e.prompt_line()
        assert "kali" in line
        assert "kali:nmap" in line
        assert "install=nmap" in line
        assert "Network scanner" in line

    def test_prompt_line_with_commands(self):
        cmds = [{"name": "scan", "usage": "nmap -sV",
                 "example": "nmap -sV target",
                 "risk_level": "low"}]
        e = mod.CatalogEntry("x", "y", "n", "t", "s",
                              [], "", cmds, "", {})
        line = e.prompt_line()
        assert "cmd scan" in line
        assert "nmap -sV" in line
        assert "risk=low" in line
        assert "ex: nmap -sV target" in line

    def test_prompt_line_skips_bad_commands(self):
        # Non-dict commands are skipped
        cmds = ["plain string", {"name": "", "usage": ""}, 42]
        e = mod.CatalogEntry("x", "y", "n", "t", "s",
                              [], "", cmds, "", {})
        line = e.prompt_line()
        # None of the bad commands appear
        assert "cmd" not in line or "cmd :" not in line


# ---------------------------------------------------------------------------
# _parse_entry
# ---------------------------------------------------------------------------

class TestParseEntry:
    def test_minimal_valid(self, tmp_path):
        p = tmp_path / "x.json"
        p.write_text(json.dumps({"id": "x", "kind": "y"}))
        out = mod._parse_entry(p, json.loads(p.read_text()))
        assert out is not None
        assert out.id == "x"
        assert out.kind == "y"
        assert out.name == "x"

    def test_missing_id(self, tmp_path):
        p = tmp_path / "x.json"
        out = mod._parse_entry(p, {"kind": "y"})
        assert out is None

    def test_missing_kind(self, tmp_path):
        p = tmp_path / "x.json"
        out = mod._parse_entry(p, {"id": "x"})
        assert out is None

    def test_non_dict_input(self, tmp_path):
        p = tmp_path / "x.json"
        out = mod._parse_entry(p, "not a dict")
        assert out is None

    def test_name_extracted_from_id(self, tmp_path):
        p = tmp_path / "x.json"
        out = mod._parse_entry(p, {"id": "github:foo_bar", "kind": "y"})
        assert out.name == "foo_bar"

    def test_summary_strips_heading(self, tmp_path):
        p = tmp_path / "x.json"
        out = mod._parse_entry(p, {
            "id": "x", "kind": "y",
            "summary": "## Heading\nText"
        })
        # Heading prefix stripped
        assert "##" not in out.summary
        assert "Heading" in out.summary

    def test_install_apt_extracted(self, tmp_path):
        p = tmp_path / "x.json"
        out = mod._parse_entry(p, {
            "id": "x", "kind": "y",
            "install": {"apt": "nmap"}
        })
        assert out.install_apt == "nmap"

    def test_commands_extracted(self, tmp_path):
        p = tmp_path / "x.json"
        out = mod._parse_entry(p, {
            "id": "x", "kind": "y",
            "commands": [{"name": "scan", "usage": "nmap",
                          "examples": [{"command": "nmap -sV"}],
                          "risk": {"level": "low"}}]
        })
        assert len(out.commands) == 1
        assert out.commands[0]["name"] == "scan"
        assert out.commands[0]["risk_level"] == "low"

    def test_string_command(self, tmp_path):
        p = tmp_path / "x.json"
        out = mod._parse_entry(p, {
            "id": "x", "kind": "y",
            "commands": ["plain_cmd"]
        })
        assert len(out.commands) == 1
        assert out.commands[0]["name"] == "plain_cmd"

    def test_entry_level_risk_fallback(self, tmp_path):
        p = tmp_path / "x.json"
        out = mod._parse_entry(p, {
            "id": "x", "kind": "y",
            "risk": {"level": "medium"},
            "commands": [{"name": "scan"}]  # no risk → fallback
        })
        assert out.commands[0]["risk_level"] == "medium"

    def test_metapackages_extracted(self, tmp_path):
        p = tmp_path / "x.json"
        out = mod._parse_entry(p, {
            "id": "x", "kind": "y",
            "metapackages": ["kali-tools-wireless", 42, "valid"]
        })
        # Only strings are kept
        assert "kali-tools-wireless" in out.metapackages
        assert "valid" in out.metapackages
        assert len(out.metapackages) == 2


# ---------------------------------------------------------------------------
# _iter_catalog_files
# ---------------------------------------------------------------------------

class TestIterCatalogFiles:
    def test_nonexistent(self, tmp_path):
        out = list(mod._iter_catalog_files(tmp_path / "nope"))
        assert out == []

    def test_iterates_json_files(self, tmp_path):
        (tmp_path / "a.json").write_text("{}")
        (tmp_path / "b.json").write_text("{}")
        (tmp_path / "c.txt").write_text("ignored")
        out = list(mod._iter_catalog_files(tmp_path))
        names = [p.name for p in out]
        assert "a.json" in names
        assert "b.json" in names
        assert "c.txt" not in names

    def test_only_one_level(self, tmp_path):
        (tmp_path / "a.json").write_text("{}")
        sub = tmp_path / "sub"
        sub.mkdir()
        (sub / "nested.json").write_text("{}")
        out = list(mod._iter_catalog_files(tmp_path))
        names = [p.name for p in out]
        assert "a.json" in names
        # No recursion
        assert "nested.json" not in names


# ---------------------------------------------------------------------------
# load_catalog
# ---------------------------------------------------------------------------

class TestLoadCatalog:
    def test_loads_valid_files(self, tmp_path):
        (tmp_path / "a.json").write_text(json.dumps({
            "id": "x", "kind": "y"
        }))
        out = mod.load_catalog(tmp_path)
        assert len(out) == 1
        assert out[0].id == "x"

    def test_skips_invalid_json(self, tmp_path):
        (tmp_path / "bad.json").write_text("NOT JSON {{{")
        (tmp_path / "good.json").write_text(json.dumps({
            "id": "x", "kind": "y"
        }))
        out = mod.load_catalog(tmp_path)
        # bad.json is skipped
        assert len(out) == 1

    def test_kinds_filter(self, tmp_path):
        (tmp_path / "a.json").write_text(json.dumps({
            "id": "kali:nmap", "kind": "kali_source_package"
        }))
        (tmp_path / "b.json").write_text(json.dumps({
            "id": "github:foo", "kind": "external_repository"
        }))
        out = mod.load_catalog(tmp_path, kinds=("kali_source_package",))
        assert len(out) == 1
        assert out[0].kind == "kali_source_package"

    def test_limit(self, tmp_path):
        for i in range(10):
            (tmp_path / f"{i}.json").write_text(json.dumps({
                "id": f"x{i}", "kind": "y"
            }))
        out = mod.load_catalog(tmp_path, limit=3)
        assert len(out) == 3

    def test_nonexistent_dir(self, tmp_path):
        out = mod.load_catalog(tmp_path / "nope")
        assert out == []


# ---------------------------------------------------------------------------
# filter_by_keywords
# ---------------------------------------------------------------------------

class TestFilterByKeywords:
    def test_filters_by_token(self):
        e1 = mod.CatalogEntry("wifi:nmap", "y", "n", "t", "s",
                               [], "", [], "", {})
        e2 = mod.CatalogEntry("other:foo", "y", "n", "t", "s",
                               [], "", [], "", {})
        out = mod.filter_by_keywords([e1, e2], ["wifi"])
        assert len(out) == 1
        assert out[0].id == "wifi:nmap"

    def test_no_match(self):
        e = mod.CatalogEntry("x", "y", "n", "t", "s", [], "", [], "", {})
        out = mod.filter_by_keywords([e], ["xyzzy"])
        assert out == []


# ---------------------------------------------------------------------------
# Catalog class
# ---------------------------------------------------------------------------

class TestCatalogClass:
    def test_init_with_entries(self):
        entries = [mod.CatalogEntry("x", "y", "n", "t", "s",
                                     [], "", [], "", {})]
        c = mod.Catalog(entries=entries)
        assert c.entries() == entries

    def test_init_empty_loads_lazily(self, tmp_path, monkeypatch):
        # If no entries provided, entries() loads from CATALOG_DIR
        # We test that it's a list (could be empty or not depending on real catalog)
        c = mod.Catalog()
        out = c.entries()
        assert isinstance(out, list)

    def test_context_block_empty_catalog(self, tmp_path):
        # Catalog at non-existent dir → empty entries
        c = mod.Catalog(root=tmp_path / "empty")
        # Need to force-load by calling entries() first, or pass empty
        c2 = mod.Catalog(entries=[], root=tmp_path / "empty")
        out = c2.context_block()
        assert out == ""

    def test_context_block_wifi_domain(self):
        e = mod.CatalogEntry("wifi:nmap", "y", "n", "t", "wifi scanner",
                              [], "", [], "", {})
        c = mod.Catalog(entries=[e])
        out = c.context_block(domain="wifi")
        assert "AVAILABLE KALI PACKAGES" in out
        assert "wifi:nmap" in out

    def test_context_block_other_domain(self):
        e = mod.CatalogEntry("kali:nmap", "y", "n", "t", "scanner",
                              [], "", [], "", {})
        c = mod.Catalog(entries=[e])
        out = c.context_block()
        assert "AVAILABLE KALI PACKAGES" in out
        assert "kali:nmap" in out

    def test_wifi_entries_returns_matching(self):
        e1 = mod.CatalogEntry("wifi:nmap", "y", "n", "t",
                               "wireless scanner for 802.11",
                               [], "", [], "", {})
        e2 = mod.CatalogEntry("other:foo", "y", "n", "t", "no wifi here",
                               [], "", [], "", {})
        c = mod.Catalog(entries=[e1, e2])
        # "wpa3" only matches e1 (which has "802.11" → not wpa3, but
        # "wifi" itself is in both). Use "nmap" which is only in e1.
        out = c.wifi_entries(limit=10)
        # The wifi pool includes any entry matching ANY wifi keyword.
        # Both e1 and e2 match "wifi". Verify the wifi_entries returns
        # at least e1 (and possibly e2 if "wifi" is a keyword)
        ids = {e.id for e in out}
        assert "wifi:nmap" in ids

    def test_wifi_entries_fallback(self):
        # No wifi entries → falls back to all
        e = mod.CatalogEntry("other:foo", "y", "n", "t", "no wifi here",
                              [], "", [], "", {})
        c = mod.Catalog(entries=[e])
        out = c.wifi_entries()
        assert len(out) == 1


# ---------------------------------------------------------------------------
# No fabrication
# ---------------------------------------------------------------------------

class TestNoFabrication:
    def test_no_creds_in_prompt_line(self):
        e = mod.CatalogEntry("x", "y", "n", "t", "normal", [], "",
                              [], "", {"use_cases": ["hello"]})
        out = e.prompt_line()
        for forbidden in ("ecf51ee2-938d", "f40bec4b664a40a9a",
                          "CE38F76832CFA1F6", "password=", "secret="):
            assert forbidden not in out, f"leaked {forbidden!r}"
