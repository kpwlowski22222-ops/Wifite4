"""Tests for core.catalog.github_generate — Phase 2.4+ catalog generator."""
from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path
from typing import Any, Dict, List

import pytest

from core.catalog import github_generate as gen


@pytest.fixture
def fake_toolbox(tmp_path: Path) -> Path:
    """Build a tiny fake toolbox with a README and one Python file."""
    tb = tmp_path / "TestOwner__FakeTool"
    tb.mkdir()
    (tb / "README.md").write_text(
        "# FakeTool\n\n"
        "This is a fake test tool that does fake things. "
        "Use it for testing the catalog generator.\n\n"
        "## Usage\n\n"
        "Run with `--target <host>` and `--port 8080`.\n",
        encoding="utf-8")
    (tb / "fake_tool.py").write_text(
        '"""fake tool."""\n'
        'import argparse\n\n'
        'def run(target, port=8080):\n'
        '    """Run the tool."""\n'
        '    return f"running on {target}:{port}"\n\n'
        'def main():\n'
        '    parser = argparse.ArgumentParser()\n'
        '    parser.add_argument("--target", required=True)\n'
        '    parser.add_argument("--port", type=int, default=8080)\n'
        '    args = parser.parse_args()\n'
        '    return run(args.target, args.port)\n',
        encoding="utf-8")
    return tb


@pytest.fixture
def empty_catalog(tmp_path: Path) -> Path:
    p = tmp_path / "catalog"
    p.mkdir()
    return p


# ---------------------------------------------------------------------------
# A. parse_toolbox_dir
# ---------------------------------------------------------------------------

class TestParseToolboxDir:
    def test_double_underscore(self) -> None:
        o, r = gen.parse_toolbox_dir("Owner__Repo")
        assert o == "Owner"
        assert r == "Repo"

    def test_no_double_underscore(self) -> None:
        o, r = gen.parse_toolbox_dir("JustAName")
        assert o == "unknown"
        assert r == "JustAName"

    def test_three_underscores(self) -> None:
        o, r = gen.parse_toolbox_dir("Owner__Repo__With__More")
        assert o == "Owner"
        assert r == "Repo__With__More"


# ---------------------------------------------------------------------------
# B. read_readme_first_para
# ---------------------------------------------------------------------------

class TestReadmeFirstPara:
    def test_reads_first_paragraph(self, fake_toolbox: Path) -> None:
        para = gen.read_readme_first_para(fake_toolbox)
        assert para is not None
        assert "fake test tool" in para
        assert "Use it for testing" in para

    def test_no_readme_returns_none(self, tmp_path: Path) -> None:
        tb = tmp_path / "NoReadmeTool"
        tb.mkdir()
        assert gen.read_readme_first_para(tb) is None

    def test_skips_code_fences(self, tmp_path: Path) -> None:
        tb = tmp_path / "CodeFenceTool"
        tb.mkdir()
        (tb / "README.md").write_text(
            "# Title\n\n```\ncode block\n```\n\n"
            "This is the actual first paragraph.\n",
            encoding="utf-8")
        para = gen.read_readme_first_para(tb)
        assert "actual first paragraph" in para
        assert "code block" not in para


# ---------------------------------------------------------------------------
# C. detect_languages
# ---------------------------------------------------------------------------

class TestDetectLanguages:
    def test_python_detected(self, fake_toolbox: Path) -> None:
        langs = gen.detect_languages(fake_toolbox)
        assert "python" in langs

    def test_no_languages(self, tmp_path: Path) -> None:
        tb = tmp_path / "EmptyTool"
        tb.mkdir()
        assert gen.detect_languages(tb) == []

    def test_multiple_languages(self, tmp_path: Path) -> None:
        tb = tmp_path / "MultiLangTool"
        tb.mkdir()
        (tb / "a.py").write_text("x = 1")
        (tb / "b.sh").write_text("echo hi")
        (tb / "c.go").write_text("package main")
        langs = gen.detect_languages(tb)
        assert set(langs) >= {"python", "shell", "go"}


# ---------------------------------------------------------------------------
# D. build_entry
# ---------------------------------------------------------------------------

class TestBuildEntry:
    def test_builds_complete_entry(self, fake_toolbox: Path) -> None:
        entry = gen.build_entry(fake_toolbox, "OSINT", "TestOwner",
                                "FakeTool")
        # Required fields
        assert entry["id"] == "github:TestOwner/FakeTool"
        assert entry["kind"] == "external_repository"
        assert entry["name"] == "FakeTool"
        assert entry["full_name"] == "TestOwner/FakeTool"
        assert entry["owner"] == "TestOwner"
        assert entry["category"] == "OSINT"
        assert entry["url"] == "https://github.com/TestOwner/FakeTool"
        # Enhanced fields
        assert entry["summary"]
        assert 8 <= len(entry["tags"]) <= 15
        assert 5 <= len(entry["use_cases"]) <= 10
        assert 5 <= len(entry["command_examples"]) <= 10
        assert 4 <= len(entry["risk"]["signals"]) <= 8
        assert entry["attack_surface"]
        assert entry["phase_hint"]
        assert entry["requires_hardware"]
        assert entry["polymorphic_strategies"]
        assert entry["target_adaptive_targets"]
        # Documentation
        doc = entry["documentation"]
        assert doc["readme"] is not None
        assert doc["languages"]
        # Function signatures
        funcs = doc.get("function_signatures", [])
        names = [f["name"] for f in funcs]
        assert "run" in names
        assert "main" in names

    def test_detects_args(self, fake_toolbox: Path) -> None:
        entry = gen.build_entry(fake_toolbox, "OSINT", "TestOwner",
                                "FakeTool")
        args = entry["documentation"]["arguments"]
        names = {a["name"] for a in args}
        assert "--target" in names
        assert "--port" in names

    def test_no_fabricated_versions(self, fake_toolbox: Path) -> None:
        entry = gen.build_entry(fake_toolbox, "OSINT", "TestOwner",
                                "FakeTool")
        text = json.dumps(entry)
        # Must not contain fake version patterns
        for bad in ("v1.0.0", "version 1.0", "release 2024"):
            assert bad not in text.lower()

    def test_no_fabricated_cve(self, fake_toolbox: Path) -> None:
        entry = gen.build_entry(fake_toolbox, "OSINT", "TestOwner",
                                "FakeTool")
        text = json.dumps(entry)
        assert "CVE-2024-9999" not in text
        assert "CVE-2025-9999" not in text


# ---------------------------------------------------------------------------
# E. find_unlisted
# ---------------------------------------------------------------------------

class TestFindUnlisted:
    def test_finds_unlisted(self, tmp_path: Path,
                              empty_catalog: Path) -> None:
        # Create a fake toolboxes/ + catalog/
        tb = tmp_path / "toolboxes" / "wifi"
        tb.mkdir(parents=True)
        tool = tb / "0xABC__WifiTool"
        tool.mkdir()
        (tool / "README.md").write_text("# WifiTool\n", encoding="utf-8")

        unlisted = gen.find_unlisted(tmp_path / "toolboxes",
                                       empty_catalog)
        assert len(unlisted) == 1
        path, cat, owner, repo = unlisted[0]
        assert cat == "Wireless"
        assert owner == "0xABC"
        assert repo == "WifiTool"

    def test_skips_already_listed(self, tmp_path: Path,
                                   empty_catalog: Path) -> None:
        tb = tmp_path / "toolboxes" / "wifi"
        tb.mkdir(parents=True)
        tool = tb / "Owner__ListedTool"
        tool.mkdir()
        # Already in catalog
        (empty_catalog / "github_Owner_ListedTool.json").write_text("{}",
            encoding="utf-8")

        unlisted = gen.find_unlisted(tmp_path / "toolboxes",
                                       empty_catalog)
        assert unlisted == []

    def test_skips_manifest(self, tmp_path: Path,
                              empty_catalog: Path) -> None:
        tb = tmp_path / "toolboxes" / "wifi"
        tb.mkdir(parents=True)
        (tb / "MANIFEST.txt").write_text("not a real toolbox",
                                           encoding="utf-8")
        (tb / "tree.txt").write_text("not a real toolbox",
                                       encoding="utf-8")
        unlisted = gen.find_unlisted(tmp_path / "toolboxes",
                                       empty_catalog)
        assert unlisted == []


# ---------------------------------------------------------------------------
# F. generate_unlisted
# ---------------------------------------------------------------------------

class TestGenerateUnlisted:
    def test_writes_files(self, tmp_path: Path,
                            empty_catalog: Path) -> None:
        tb = tmp_path / "toolboxes" / "wifi"
        tb.mkdir(parents=True)
        for i in range(3):
            tool = tb / f"Owner__Tool{i}"
            tool.mkdir()
            (tool / "README.md").write_text(
                f"# Tool{i}\n\nA test tool number {i}.\n",
                encoding="utf-8")
        r = gen.generate_unlisted(tmp_path / "toolboxes",
                                    empty_catalog)
        assert r["ok"] is True
        assert r["total"] == 3
        assert r["written"] == 3
        # Files exist
        for i in range(3):
            assert (empty_catalog /
                    f"github_Owner_Tool{i}.json").exists()

    def test_idempotent_on_second_run(self, tmp_path: Path,
                                        empty_catalog: Path) -> None:
        tb = tmp_path / "toolboxes" / "wifi"
        tb.mkdir(parents=True)
        tool = tb / "Owner__Tool1"
        tool.mkdir()
        (tool / "README.md").write_text("# Tool1\n", encoding="utf-8")
        gen.generate_unlisted(tmp_path / "toolboxes", empty_catalog)
        r2 = gen.generate_unlisted(tmp_path / "toolboxes", empty_catalog)
        assert r2["total"] == 0
        assert r2["written"] == 0

    def test_writes_valid_json(self, tmp_path: Path,
                                 empty_catalog: Path) -> None:
        tb = tmp_path / "toolboxes" / "wifi"
        tb.mkdir(parents=True)
        tool = tb / "Owner__Tool1"
        tool.mkdir()
        (tool / "README.md").write_text("# Tool1\n", encoding="utf-8")
        gen.generate_unlisted(tmp_path / "toolboxes", empty_catalog)
        path = empty_catalog / "github_Owner_Tool1.json"
        data = json.loads(path.read_text())
        # Verify it satisfies schema
        assert data["_kfiosa_enriched_schema"] == "1.1.0"
        assert data["id"] == "github:Owner/Tool1"
        assert data["kind"] == "external_repository"


# ---------------------------------------------------------------------------
# G. catalog_filename
# ---------------------------------------------------------------------------

class TestCatalogFilename:
    def test_simple(self) -> None:
        assert (gen.catalog_filename("Owner", "Repo")
                == "github_Owner_Repo.json")

    def test_underscore_in_name(self) -> None:
        assert (gen.catalog_filename("Owner", "Repo_With_Underscores")
                == "github_Owner_Repo_With_Underscores.json")


if __name__ == "__main__":
    pytest.main([__file__, "-q", "--tb=short"])
