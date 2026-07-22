"""Tests for core.tool_registry — Phase 4 T22 coverage."""
from __future__ import annotations

import importlib
import json
import os
import tempfile
from pathlib import Path

import pytest


def _import_mod():
    return importlib.import_module("core.tool_registry")


mod = _import_mod()


# ---------------------------------------------------------------------------
# Static helper functions
# ---------------------------------------------------------------------------

class TestReadText:
    def test_reads_existing_file(self, tmp_path):
        f = tmp_path / "x.txt"
        f.write_text("hello world")
        out = mod._read_text(f)
        assert out == "hello world"

    def test_missing_file_returns_empty(self, tmp_path):
        out = mod._read_text(tmp_path / "missing.txt")
        assert out == ""

    def test_limit_truncates(self, tmp_path):
        f = tmp_path / "x.txt"
        f.write_text("A" * 1000)
        out = mod._read_text(f, limit=100)
        assert len(out) == 100


class TestExtractDescription:
    def test_extracts_first_prose(self):
        # The function skips headings and takes the first prose line
        readme = (
            "# Title\n"
            "Some intro text.\n"
            "\n"
            "## Description\n"
            "This is the actual description.\n"
        )
        out = mod._extract_description(readme)
        # First non-heading line is "Some intro text."
        assert "intro" in out.lower()

    def test_no_description_section(self):
        readme = "# Title\nNo description here.\n"
        out = mod._extract_description(readme)
        # Should still return some text
        assert isinstance(out, str)
        assert "description" in out.lower() or "title" in out.lower() or len(out) > 0


class TestExtractUsage:
    def test_extracts_dollar_command(self):
        # The function matches `$ cmd` or `> cmd` patterns
        readme = (
            "## Usage\n"
            "```bash\n"
            "$ nmap -sV target\n"
            "```\n"
            "## End\n"
        )
        out = mod._extract_usage(readme, limit=5)
        assert isinstance(out, list)
        assert any("nmap" in u for u in out)

    def test_extracts_python_invocation(self):
        # _BARE_CMD matches "python X" or "pip X" etc.
        readme = (
            "## Usage\n"
            "```bash\n"
            "python exploit.py\n"
            "```\n"
            "## End\n"
        )
        out = mod._extract_usage(readme, limit=5)
        assert isinstance(out, list)
        assert any("python" in u.lower() for u in out)

    def test_no_code_blocks(self):
        out = mod._extract_usage("just plain text", limit=3)
        assert isinstance(out, list)
        assert out == []


class TestScore:
    def test_name_match_high_score(self):
        tool = {"name": "nmap", "description": "scanner",
                "domain": "wifi", "usage": []}
        s = mod._score(tool, "nmap")
        assert s >= 30  # name match

    def test_name_prefix_extra(self):
        tool = {"name": "nmap-scanner", "description": "",
                "domain": "", "usage": []}
        s = mod._score(tool, "nmap")
        # name match (30) + name starts_with (15) = 45
        assert s >= 45

    def test_description_match(self):
        tool = {"name": "x", "description": "nmap-like scanner",
                "domain": "", "usage": []}
        s = mod._score(tool, "nmap")
        assert s >= 12  # description match

    def test_no_match(self):
        tool = {"name": "x", "description": "y", "domain": "z", "usage": []}
        s = mod._score(tool, "nmap")
        assert s == 0

    def test_domain_match(self):
        tool = {"name": "x", "description": "y",
                "domain": "nmap-tools", "usage": []}
        s = mod._score(tool, "nmap")
        assert s >= 8  # domain match

    def test_case_insensitive(self):
        tool = {"name": "NMAP", "description": "",
                "domain": "", "usage": []}
        s = mod._score(tool, "nmap")
        assert s >= 30


# ---------------------------------------------------------------------------
# ToolRegistry class
# ---------------------------------------------------------------------------

class TestToolRegistry:
    def test_init_empty(self, tmp_path):
        reg = mod.ToolRegistry(path=tmp_path / "reg.json")
        assert reg.tools == []
        assert reg._by_name == {}

    def test_get_unknown_returns_none(self, tmp_path):
        reg = mod.ToolRegistry(path=tmp_path / "reg.json")
        assert reg.get("nonexistent") is None

    def test_search_empty_query(self, tmp_path):
        reg = mod.ToolRegistry(path=tmp_path / "reg.json")
        reg.tools = [
            {"name": "nmap", "source": "kali", "domain": "wifi",
             "description": "scanner", "usage": []},
            {"name": "airodump-ng", "source": "kali", "domain": "wifi",
             "description": "wifi scanner", "usage": []},
        ]
        out = reg.search("", limit=10)
        assert len(out) == 2

    def test_search_with_query(self, tmp_path):
        reg = mod.ToolRegistry(path=tmp_path / "reg.json")
        reg.tools = [
            {"name": "nmap", "source": "kali", "domain": "wifi",
             "description": "scanner", "usage": []},
            {"name": "airodump-ng", "source": "kali", "domain": "wifi",
             "description": "wifi scanner", "usage": []},
        ]
        out = reg.search("nmap")
        assert len(out) >= 1
        assert out[0]["name"] == "nmap"

    def test_search_limit(self, tmp_path):
        reg = mod.ToolRegistry(path=tmp_path / "reg.json")
        reg.tools = [{"name": f"tool{i}", "source": "kali",
                      "domain": "wifi", "description": "",
                      "usage": []} for i in range(100)]
        out = reg.search("tool", limit=5)
        assert len(out) == 5

    def test_tools_for_domain(self, tmp_path):
        reg = mod.ToolRegistry(path=tmp_path / "reg.json")
        reg.tools = [
            {"name": "nmap", "source": "kali", "domain": "wifi",
             "description": "", "usage": []},
            {"name": "msfconsole", "source": "kali", "domain": "exploit",
             "description": "", "usage": []},
        ]
        out = reg.tools_for_domain("wifi")
        assert len(out) == 1
        assert out[0]["name"] == "nmap"

    def test_tools_for_domain_orders_by_source(self, tmp_path):
        reg = mod.ToolRegistry(path=tmp_path / "reg.json")
        reg.tools = [
            {"name": "v_tool", "source": "venv", "domain": "wifi",
             "description": "", "usage": []},
            {"name": "k_tool", "source": "kali", "domain": "wifi",
             "description": "", "usage": []},
        ]
        out = reg.tools_for_domain("wifi")
        # kali should come before venv
        assert out[0]["name"] == "k_tool"
        assert out[1]["name"] == "v_tool"

    def test_reindex(self, tmp_path):
        reg = mod.ToolRegistry(path=tmp_path / "reg.json")
        reg.tools = [
            {"name": "nmap", "source": "kali"},
            {"name": "nmap", "source": "venv"},  # same name, different source
        ]
        reg._reindex()
        assert "kali:nmap" in reg._by_name
        assert "venv:nmap" in reg._by_name

    def test_by_domain_counts(self, tmp_path):
        reg = mod.ToolRegistry(path=tmp_path / "reg.json")
        reg.tools = [
            {"name": "a", "source": "kali", "domain": "wifi"},
            {"name": "b", "source": "kali", "domain": "wifi"},
            {"name": "c", "source": "kali", "domain": "exploit"},
        ]
        counts = reg._by_domain_counts()
        assert counts["wifi"] == 2
        assert counts["exploit"] == 1


# ---------------------------------------------------------------------------
# context_block
# ---------------------------------------------------------------------------

class TestContextBlock:
    def test_empty_returns_empty_string(self, tmp_path):
        # Build a fresh registry that has no file, then set tools=[] and
        # a non-existent path BEFORE calling context_block, and patch
        # build() to be a no-op so it doesn't try to scan the filesystem.
        reg = mod.ToolRegistry(path=tmp_path / "reg.json")
        reg.build = lambda: {"total": 0, "toolbox": 0, "kali": 0,
                              "venv": 0, "by_domain": {}}  # no-op
        reg.tools = []
        out = reg.context_block()
        assert out == ""

    def test_with_tools(self, tmp_path):
        reg = mod.ToolRegistry(path=tmp_path / "reg.json")
        reg.tools = [
            {"name": "nmap", "source": "kali", "domain": "wifi",
             "description": "Network scanner", "usage": ["nmap -sV target"]},
        ]
        # Skip the auto-load → build path so tools stays as we set it
        reg.build = lambda: {"total": 0, "toolbox": 0, "kali": 0,
                              "venv": 0, "by_domain": {}}
        out = reg.context_block()
        assert "AVAILABLE TOOLS" in out
        assert "nmap" in out

    def test_with_domain_filter(self, tmp_path):
        reg = mod.ToolRegistry(path=tmp_path / "reg.json")
        reg.tools = [
            {"name": "nmap", "source": "kali", "domain": "wifi",
             "description": "Network scanner", "usage": []},
            {"name": "msfconsole", "source": "kali", "domain": "exploit",
             "description": "Metasploit", "usage": []},
        ]
        reg.build = lambda: {"total": 0, "toolbox": 0, "kali": 0,
                              "venv": 0, "by_domain": {}}
        out = reg.context_block(domain="wifi")
        assert "nmap" in out
        # Domain filter should exclude msfconsole
        assert "msfconsole" not in out

    def test_truncates_long_descriptions(self, tmp_path):
        reg = mod.ToolRegistry(path=tmp_path / "reg.json")
        long_desc = "A" * 500
        reg.tools = [
            {"name": "x", "source": "kali", "domain": "wifi",
             "description": long_desc, "usage": []},
        ]
        reg.build = lambda: {"total": 0, "toolbox": 0, "kali": 0,
                              "venv": 0, "by_domain": {}}
        out = reg.context_block()
        # Should have truncation indicator
        assert "…" in out or len(out) < len(long_desc) + 200


# ---------------------------------------------------------------------------
# _save
# ---------------------------------------------------------------------------

class TestSave:
    def test_save_writes_file(self, tmp_path):
        reg = mod.ToolRegistry(path=tmp_path / "reg.json")
        reg.tools = [{"name": "x", "source": "kali"}]
        reg._save()
        assert (tmp_path / "reg.json").exists()

    def test_save_load_roundtrip(self, tmp_path):
        reg1 = mod.ToolRegistry(path=tmp_path / "reg.json")
        reg1.tools = [{"name": "x", "source": "kali", "domain": "wifi"}]
        reg1._save()
        reg2 = mod.ToolRegistry(path=tmp_path / "reg.json")
        out = reg2.load()
        assert len(out) == 1
        assert out[0]["name"] == "x"


# ---------------------------------------------------------------------------
# No fabrication
# ---------------------------------------------------------------------------

class TestNoFabrication:
    def test_no_creds_in_search(self, tmp_path):
        reg = mod.ToolRegistry(path=tmp_path / "reg.json")
        reg.tools = [
            {"name": "tool1", "source": "kali", "domain": "wifi",
             "description": "normal", "usage": []},
        ]
        out = reg.search("tool1")
        text = str(out)
        for forbidden in ("ecf51ee2-938d", "f40bec4b664a40a9a",
                          "CE38F76832CFA1F6"):
            assert forbidden not in text
