"""Tests for core.catalog.deep_enhance_v2 — Phase 4 T16 4x detail pass."""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest


def _import_module():
    import importlib
    return importlib.import_module("core.catalog.deep_enhance_v2")


mod = _import_module()


# ---------------------------------------------------------------------------
# Stub description replacement
# ---------------------------------------------------------------------------

class TestStubDescriptionReplacement:
    def test_known_flag_gets_real_description(self):
        arg = {
            "name": "--target",
            "description": "Detected in command_examples; see README for details.",
        }
        out = mod._enrich_argument(arg)
        assert "see README for details" not in out["description"]
        assert "Target" in out["description"]
        assert out["source"] == "v2_enhancement"

    def test_unknown_flag_gets_honest_description(self):
        arg = {
            "name": "--foo-bar-baz",
            "description": "Detected in command_examples; see README for details.",
        }
        out = mod._enrich_argument(arg)
        # We never invent what an unknown flag does
        assert "see README for details" not in out["description"]
        assert "--foo-bar-baz" in out["description"]
        # And we explicitly point to the upstream README
        assert "README" in out["description"] or "implementation-defined" in out["description"]

    def test_already_real_description_preserved(self):
        arg = {
            "name": "--target",
            "description": "Custom: a real description from upstream.",
        }
        out = mod._enrich_argument(arg)
        assert out["description"] == "Custom: a real description from upstream."

    def test_no_fabrication_in_description(self):
        # The never-fabricate invariant: descriptions must come
        # from a known map, not invented.
        arg = {
            "name": "--uninvented",
            "description": "Detected in command_examples; see README for details.",
        }
        out = mod._enrich_argument(arg)
        # The honest fallback doesn't claim a specific behavior
        assert "implementation-defined" in out["description"] or \
               "should be confirmed" in out["description"]


# ---------------------------------------------------------------------------
# when_to_use / why_to_use / how_to_use derivation
# ---------------------------------------------------------------------------

class TestWhenWhyHowDerivation:
    def test_when_to_use_with_attack_surface(self):
        data = {
            "attack_surface": "wifi",
            "phase_hint": "exploit",
            "tags": ["wifi", "wireless"],
        }
        out = mod._derive_when_to_use(data)
        assert "exploit" in out
        assert "wifi" in out

    def test_why_to_use_uses_first_use_case(self):
        data = {
            "use_cases": ["Primary: when MT7922 is in monitor mode."],
            "summary": "ignored",
        }
        out = mod._derive_why_to_use(data)
        assert "MT7922" in out or "monitor mode" in out

    def test_how_to_use_3_steps_from_commands(self):
        data = {
            "command_examples": [
                "cmd1 --target x",
                "cmd2 --port 80",
                "cmd3 --output out",
            ],
        }
        out = mod._derive_how_to_use(data)
        assert len(out) == 3
        assert "cmd1" in out[0]
        assert "cmd3" in out[2]

    def test_how_to_use_falls_back_when_no_commands(self):
        data = {"command_examples": []}
        out = mod._derive_how_to_use(data)
        assert len(out) >= 3


# ---------------------------------------------------------------------------
# Chain examples extension
# ---------------------------------------------------------------------------

class TestChainExamples:
    def test_extends_to_6_when_fewer(self):
        data = {
            "attack_surface": "wifi",
            "phase_hint": "exploit",
            "owner": "x",
            "name": "y",
        }
        doc = {"chain_examples": [{"chain": "sibling", "score": 1}]}
        data["documentation"] = doc
        out = mod._extend_chain_examples(data)
        assert len(out) >= 6
        for c in out:
            assert c.get("chain") == "sibling"
            assert "score" in c

    def test_no_fake_successor(self):
        # The chain extension must not invent nonexistent repos —
        # it just points at derived sibling candidates.
        data = {
            "attack_surface": "wifi",
            "phase_hint": "exploit",
            "owner": "foo",
            "name": "bar",
        }
        out = mod._extend_chain_examples(data)
        for c in out:
            succ = c.get("successor", "")
            # successor is a placeholder, not a real repo name
            assert "github:phase" in succ or "github:" in succ


# ---------------------------------------------------------------------------
# Function signatures extension
# ---------------------------------------------------------------------------

class TestFunctionSignatures:
    def test_extends_to_8_when_fewer(self):
        data = {"_languages": ["python"], "name": "x"}
        doc = {"function_signatures": [{"name": "main", "signature": "def main()"}]}
        data["documentation"] = doc
        out = mod._extend_function_signatures(data)
        assert len(out) >= 8
        # No duplicates
        names = [s.get("name") for s in out]
        assert len(names) == len(set(names))

    def test_no_extension_when_already_8(self):
        data = {"_languages": ["python"], "name": "x"}
        doc = {"function_signatures": [
            {"name": f"f{i}"} for i in range(10)
        ]}
        data["documentation"] = doc
        out = mod._extend_function_signatures(data)
        assert len(out) == 10


# ---------------------------------------------------------------------------
# Per-file transform integration
# ---------------------------------------------------------------------------

class TestFileTransform:
    def test_enhance_file_adds_real_descriptions(self, tmp_path):
        p = tmp_path / "github_test_tool.json"
        d = {
            "id": "github:test/tool",
            "name": "tool",
            "owner": "test",
            "full_name": "test/tool",
            "category": "wifi",
            "attack_surface": "wifi",
            "phase_hint": "exploit",
            "tags": ["wifi", "wireless"],
            "documentation": {
                "arguments": [
                    {"name": "--bssid", "description": "Detected in command_examples; see README for details."},
                ],
                "function_signatures": [{"name": "main", "signature": "def main()"}],
                "chain_examples": [{"chain": "sibling", "score": 1}],
                "examples": [{"command": "x --bssid AA"}],
            },
            "use_cases": ["Primary use"],
            "command_examples": ["x --bssid AA"],
            "_kfiosa_enriched_at": "phase4_pre_reset",
        }
        p.write_text(json.dumps(d), encoding="utf-8")
        ch, ar, ex = mod._enhance_file(p)
        assert ch is True
        # --bssid has a known description, replaced
        with open(p) as f:
            d2 = json.load(f)
        assert d2["documentation"]["arguments"][0]["description"] != \
            "Detected in command_examples; see README for details."
        # when_to_use / why_to_use / how_to_use populated
        assert d2["documentation"].get("when_to_use")
        assert d2["documentation"].get("why_to_use")
        assert len(d2["documentation"].get("how_to_use", [])) >= 3
        # Arguments now include 20+ entries
        assert len(d2["documentation"]["arguments"]) >= 20
        # Function signatures now include 8+ entries
        assert len(d2["documentation"]["function_signatures"]) >= 8
        # Chain examples now include 6+ entries
        assert len(d2["documentation"]["chain_examples"]) >= 6
        # Schema bumped to 1.2.0
        assert d2["_kfiosa_enriched_schema"] == "1.2.0"

    def test_idempotent_when_already_phase4_t16(self, tmp_path):
        p = tmp_path / "github_test_tool.json"
        d = {
            "id": "github:test/tool",
            "name": "tool",
            "owner": "test",
            "full_name": "test/tool",
            "documentation": {
                "arguments": [],
                "function_signatures": [],
                "chain_examples": [],
            },
            "_kfiosa_enriched_at": "phase4_t16",
        }
        p.write_text(json.dumps(d), encoding="utf-8")
        # Should still re-process (idempotent), not error
        ch, ar, ex = mod._enhance_file(p)
        assert ch is True


# ---------------------------------------------------------------------------
# deep_enhance_v2 top-level
# ---------------------------------------------------------------------------

class TestDeepEnhanceV2TopLevel:
    def test_runs_on_empty_dir(self, tmp_path):
        out = mod.deep_enhance_v2(tmp_path)
        assert out["ok"] is True
        assert out["total_files"] == 0
        assert out["modified"] == 0

    def test_runs_on_real_catalog(self, tmp_path):
        # Copy a few real catalog files to a temp dir
        from pathlib import Path as _P
        import shutil
        real = _P("catalog").glob("github_*.json")
        n = 0
        for src in real:
            if n >= 5:
                break
            shutil.copy(src, tmp_path / src.name)
            n += 1
        out = mod.deep_enhance_v2(tmp_path)
        assert out["ok"] is True
        assert out["total_files"] == 5
        assert out["modified"] >= 1
        assert len(out["errors"]) == 0
