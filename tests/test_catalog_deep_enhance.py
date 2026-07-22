"""tests.test_catalog_deep_enhance — Phase 2.4 deep_enhance() smoke tests.

deep_enhance() backfills documentation.arguments, function_signatures,
file_listing, and languages for catalog/github_*.json entries that
were created by the older v1 enhance pass.
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any, Dict, List

import pytest

from core.catalog.deep_enhance import deep_enhance_one, deep_enhance_all


def _write_minimal_catalog(path: Path, *,
                            full_name: str = "octocat/hello",
                            owner: str = "octocat",
                            name: str = "hello",
                            category: str = "Penetration Testing"
                            ) -> Dict[str, Any]:
    """Write a minimal catalog file with shallow documentation."""
    data = {
        "id": f"github:{full_name}",
        "kind": "external_repository",
        "name": name,
        "full_name": full_name,
        "owner": owner,
        "category": category,
        "url": f"https://github.com/{full_name}",
        "summary": f"Index entry for {full_name}.",
        "documentation": {
            "readme": "Some short readme.",
            "arguments": [],
            "function_signatures": [],
            "file_listing": [],
            "languages": [],
        },
        "metadata_status": "shallow",
        "tags": ["penetration_testing"],
        "use_cases": ["index entry"],
    }
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False),
                    encoding="utf-8")
    return data


def test_deep_enhance_one_with_no_toolbox_derives_from_metadata():
    """If no matching toolbox dir exists, the entry is still
    back-filled from command_examples + use_cases + tags (4x detail)."""
    with tempfile.TemporaryDirectory() as tmp:
        catalog = Path(tmp) / "catalog"
        catalog.mkdir()
        cpath = catalog / "github_octocat_hello.json"
        _write_minimal_catalog(cpath)
        out = deep_enhance_one(cpath, toolboxes_dir=None)
        assert out["ok"] is True
        assert out["changed"] is True
        # The metadata-derived path populates all 4 fields
        data = json.loads(cpath.read_text(encoding="utf-8"))
        doc = data["documentation"]
        assert doc.get("arguments")
        assert doc.get("function_signatures")
        assert doc.get("file_listing")
        assert doc.get("languages")


def test_deep_enhance_one_already_deep_skips():
    """If all 4 fields (arguments + function_signatures + file_listing
    + languages) are populated, the entry is left untouched (idempotent)."""
    with tempfile.TemporaryDirectory() as tmp:
        catalog = Path(tmp) / "catalog"
        catalog.mkdir()
        cpath = catalog / "github_octocat_hello.json"
        data = _write_minimal_catalog(cpath)
        # Pre-fill with a 'deep' state — all 5 required fields
        # (Phase 2.4 added chain_examples as a required field)
        data["documentation"]["arguments"] = [
            {"name": "--target", "description": "target host"}]
        data["documentation"]["function_signatures"] = [
            {"name": "scan", "signature": "scan()", "file": "main.py",
             "language": "python"}]
        data["documentation"]["file_listing"] = ["main.py", "README.md"]
        data["documentation"]["languages"] = ["python"]
        data["documentation"]["chain_examples"] = [
            {"chain": "recon→attack", "predecessor": "nmap",
             "successor": "exploit", "note": "derived"}]
        cpath.write_text(json.dumps(data, indent=2, ensure_ascii=False),
                         encoding="utf-8")
        out = deep_enhance_one(cpath, toolboxes_dir=None)
        assert out["ok"] is True
        assert out["changed"] is False
        assert "already deep" in out.get("skipped_reason", "")


def test_deep_enhance_one_with_toolbox_populates():
    """A toolbox dir with a Python entry-point + README must populate
    the documentation block."""
    with tempfile.TemporaryDirectory() as tmp:
        # Build a fake toolbox: toolboxes/wifi/octocat__hello/
        tb = Path(tmp) / "toolboxes" / "wifi" / "octocat__hello"
        tb.mkdir(parents=True)
        (tb / "README.md").write_text(
            "# hello\n\nThis is the hello world pen-test tool. "
            "It scans and deauths.\n\n"
            "## Usage\n\n"
            "Run `scan()` to enumerate targets.\n"
            "Run `deauth(target, count=10)` to deauth clients.\n",
            encoding="utf-8",
        )
        (tb / "main.py").write_text(
            "def scan(bssid):\n    pass\n\n"
            "def deauth(target, count=10):\n    pass\n\n"
            "def _helper():\n    pass\n",
            encoding="utf-8",
        )
        # Catalog entry
        catalog = Path(tmp) / "catalog"
        catalog.mkdir()
        cpath = catalog / "github_octocat_hello.json"
        _write_minimal_catalog(cpath)
        out = deep_enhance_one(cpath, toolboxes_dir=Path(tmp) / "toolboxes")
        assert out["ok"] is True
        assert out["changed"] is True
        # Verify the file now has populated docs
        data = json.loads(cpath.read_text(encoding="utf-8"))
        doc = data["documentation"]
        assert isinstance(doc.get("arguments"), list)
        assert isinstance(doc.get("function_signatures"), list)
        # At least one of the public functions was detected
        names = {f["name"] for f in doc["function_signatures"]}
        assert "scan" in names or "deauth" in names


def test_deep_enhance_all_bulk():
    """deep_enhance_all() should process all github_*.json in the dir."""
    with tempfile.TemporaryDirectory() as tmp:
        catalog = Path(tmp) / "catalog"
        catalog.mkdir()
        # Create 3 catalog files: 2 with toolbox dirs, 1 without
        for i, has_tb in enumerate([True, True, False]):
            full_name = f"user{i}/tool{i}"
            owner, name = full_name.split("/")
            cpath = catalog / f"github_user{i}_tool{i}.json"
            _write_minimal_catalog(
                cpath, full_name=full_name, owner=owner, name=name)
            if has_tb:
                tb = Path(tmp) / "toolboxes" / "wifi" / f"{owner}__{name}"
                tb.mkdir(parents=True)
                (tb / "README.md").write_text(
                    f"# {name}\n\nThis is a pen-test tool "
                    f"with a CLI flag `--target` for the host.\n",
                    encoding="utf-8",
                )
                (tb / "main.py").write_text(
                    "def go(target):\n    pass\n",
                    encoding="utf-8",
                )
        out = deep_enhance_all(catalog, toolboxes_dir=Path(tmp) / "toolboxes")
        assert out["ok"] is True
        assert out["total"] == 3
        # All 3 are now changed: 2 with toolboxes + 1 metadata-derived
        assert out["changed"] == 3
        assert out["skipped"] == 0


def test_deep_enhance_all_handles_missing_dir():
    """If catalog_dir doesn't exist, deep_enhance_all returns an error."""
    out = deep_enhance_all(Path("/tmp/this-does-not-exist-12345"))
    assert out["ok"] is False
    assert "not found" in out["error"]


def test_deep_enhance_one_handles_bad_json():
    """A non-JSON file must produce a graceful error, not crash."""
    with tempfile.TemporaryDirectory() as tmp:
        catalog = Path(tmp) / "catalog"
        catalog.mkdir()
        cpath = catalog / "github_broken.json"
        cpath.write_text("this is not valid json {{{",
                         encoding="utf-8")
        out = deep_enhance_one(cpath, toolboxes_dir=None)
        assert out["ok"] is False
        assert "read/parse" in out["error"]


def test_deep_enhance_one_handles_non_object_json():
    """A JSON list (not object) must produce a graceful error."""
    with tempfile.TemporaryDirectory() as tmp:
        catalog = Path(tmp) / "catalog"
        catalog.mkdir()
        cpath = catalog / "github_array.json"
        cpath.write_text("[1, 2, 3]", encoding="utf-8")
        out = deep_enhance_one(cpath, toolboxes_dir=None)
        assert out["ok"] is False
        assert "not an object" in out["error"]


def test_deep_enhance_one_derives_args_from_command_examples():
    """The metadata-derived path must extract --flags from
    command_examples and put them into documentation.arguments."""
    with tempfile.TemporaryDirectory() as tmp:
        catalog = Path(tmp) / "catalog"
        catalog.mkdir()
        cpath = catalog / "github_x_y.json"
        data = _write_minimal_catalog(cpath)
        data["command_examples"] = [
            "tool --target 10.0.0.1 --port 8080 --wordlist users.txt",
            "tool --insecure --json",
        ]
        cpath.write_text(json.dumps(data, indent=2, ensure_ascii=False),
                         encoding="utf-8")
        out = deep_enhance_one(cpath, toolboxes_dir=None)
        assert out["ok"] is True
        assert out["changed"] is True
        doc = json.loads(cpath.read_text(encoding="utf-8"))["documentation"]
        names = {a["name"] for a in doc["arguments"]}
        # The flags from command_examples should be in the output
        for flag in ("--target", "--port", "--wordlist", "--insecure", "--json"):
            assert flag in names, f"missing {flag} in {names}"


def test_deep_enhance_one_adds_attack_surface_specific_args():
    """The metadata-derived path adds attack-surface-specific flags."""
    with tempfile.TemporaryDirectory() as tmp:
        catalog = Path(tmp) / "catalog"
        catalog.mkdir()
        cpath = catalog / "github_x_y.json"
        data = _write_minimal_catalog(cpath)
        data["attack_surface"] = ["wireless"]
        cpath.write_text(json.dumps(data, indent=2, ensure_ascii=False),
                         encoding="utf-8")
        out = deep_enhance_one(cpath, toolboxes_dir=None)
        assert out["ok"] is True
        names = {a["name"] for a in json.loads(
            cpath.read_text(encoding="utf-8"))["documentation"]["arguments"]}
        for flag in ("--bssid", "--channel", "--essid", "--client"):
            assert flag in names, f"missing {flag} in {names}"


def test_deep_enhance_one_derives_funcs_from_use_cases():
    """Functions are derived from use_cases + an inferred main + run."""
    with tempfile.TemporaryDirectory() as tmp:
        catalog = Path(tmp) / "catalog"
        catalog.mkdir()
        cpath = catalog / "github_x_y.json"
        data = _write_minimal_catalog(cpath)
        data["use_cases"] = [
            "scan targets for open ports",
            "exploit the vulnerable service",
        ]
        cpath.write_text(json.dumps(data, indent=2, ensure_ascii=False),
                         encoding="utf-8")
        out = deep_enhance_one(cpath, toolboxes_dir=None)
        assert out["ok"] is True
        funcs = json.loads(cpath.read_text(encoding="utf-8"))[
            "documentation"]["function_signatures"]
        names = {f["name"] for f in funcs}
        assert "main" in names
        assert "run" in names
        # use_cases were used
        assert "scan_targets_for_open_ports" in names


def test_deep_enhance_one_handles_list_attack_surface():
    """attack_surface can be a list (e.g. ['web']) — must not crash."""
    with tempfile.TemporaryDirectory() as tmp:
        catalog = Path(tmp) / "catalog"
        catalog.mkdir()
        cpath = catalog / "github_x_y.json"
        data = _write_minimal_catalog(cpath)
        data["attack_surface"] = ["web", "remote"]
        cpath.write_text(json.dumps(data, indent=2, ensure_ascii=False),
                         encoding="utf-8")
        out = deep_enhance_one(cpath, toolboxes_dir=None)
        assert out["ok"] is True
        assert out["changed"] is True
