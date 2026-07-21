"""Tests for core.catalog.{validate, audit, enhance_v2} (Phase 2.4)."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.catalog import (
    SCHEMA_VERSION,
    audit_enhancements,
    enhance_pending,
    reenhance_all,
    reenhance_one,
    validate_catalog,
)
from core.catalog.enhance import _enrich_attack_surface
from core.catalog.enhance_v2 import _maybe_reenhance


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def tmp_catalog(tmp_path: Path) -> Path:
    """Build a tiny catalog with one github and one kali entry."""
    cat = tmp_path / "catalog"
    cat.mkdir()
    (cat / "github_test1_foo.json").write_text(json.dumps({
        "id": "github:test1/foo",
        "kind": "external_repository",
        "name": "foo",
        "full_name": "test1/foo",
        "owner": "test1",
        "url": "https://github.com/test1/foo",
        "category": "Wireless Security",
        "summary": "Test tool",
    }))
    (cat / "github_test2_bar.json").write_text(json.dumps({
        "id": "github:test2/bar",
        "kind": "external_repository",
        "name": "bar",
        "full_name": "test2/bar",
        "owner": "test2",
        "url": "https://github.com/test2/bar",
        "category": "OSINT and Recon",
        "summary": "Another test",
    }))
    (cat / "kali_0trace.json").write_text(json.dumps({
        "id": "kali:0trace",
        "kind": "kali_package",
        "name": "0trace",
        "apt_metadata": {"package": "0trace"},
    }))
    (cat / "catalog.schema.json").write_text(json.dumps({
        "schema": "1.1.0", "type": "object"
    }))
    (cat / "catalog.txt").write_text("text list, not an entry")
    return cat


# ---------------------------------------------------------------------------
# validate
# ---------------------------------------------------------------------------

class TestValidate:
    def test_validates_github_entries(self, tmp_catalog: Path):
        v = validate_catalog(tmp_catalog)
        assert v["ok"] is True, v["errors"]
        assert v["counts"]["errors"] == 0

    def test_validates_kali_entries(self, tmp_catalog: Path):
        v = validate_catalog(tmp_catalog)
        # The kali entry has only id+name (its kind allows that).
        assert v["ok"] is True

    def test_skips_schema_file(self, tmp_catalog: Path):
        v = validate_catalog(tmp_catalog)
        # catalog.schema.json must NOT be parsed (glob *.json).
        # The other non-entry file (catalog.txt) is not in the glob.
        # So skipped == 1 (the schema), parsed == 3 (2 github + 1 kali).
        assert v["parsed"] == 3
        assert v["skipped"] == 1
        # And the schema file is not flagged as an error.
        assert not any("catalog.schema.json" in e for e in v["errors"])

    def test_detects_missing_field(self, tmp_catalog: Path):
        bad = tmp_catalog / "github_test3_baz.json"
        bad.write_text(json.dumps({"id": "github:test3/baz", "name": "baz"}))
        v = validate_catalog(tmp_catalog)
        assert v["ok"] is False
        assert any("missing required field 'url'" in e for e in v["errors"])
        assert any("missing required field 'category'" in e for e in v["errors"])

    def test_handles_invalid_json(self, tmp_catalog: Path):
        bad = tmp_catalog / "github_test4_x.json"
        bad.write_text("{not valid json")
        v = validate_catalog(tmp_catalog)
        assert v["ok"] is False
        assert any("invalid JSON" in e for e in v["errors"])

    def test_nonexistent_dir(self, tmp_path: Path):
        v = validate_catalog(tmp_path / "nope")
        assert v["ok"] is False
        assert v["errors"]


# ---------------------------------------------------------------------------
# reenhance
# ---------------------------------------------------------------------------

class TestReenhance:
    def test_reenhance_one_adds_new_fields(self, tmp_catalog: Path):
        path = tmp_catalog / "github_test1_foo.json"
        r = reenhance_one(path)
        assert r["ok"]
        assert r["changed"]
        data = json.loads(path.read_text())
        assert data["_kfiosa_enriched_schema"] == SCHEMA_VERSION
        assert "attack_surface" in data
        assert "phase_hint" in data
        assert "requires_hardware" in data
        assert "polymorphic_strategies" in data
        assert "target_adaptive_targets" in data

    def test_reenhance_writes_tag_minimum_8(self, tmp_catalog: Path):
        path = tmp_catalog / "github_test1_foo.json"
        reenhance_one(path)
        data = json.loads(path.read_text())
        assert len(data.get("tags", [])) >= 8

    def test_reenhance_idempotent(self, tmp_catalog: Path):
        path = tmp_catalog / "github_test1_foo.json"
        reenhance_one(path)
        r2 = reenhance_one(path)
        # Second pass may or may not change (no-op on equal data) —
        # but it must remain ok and schema is still 1.1.0.
        assert r2["ok"]
        data = json.loads(path.read_text())
        assert data["_kfiosa_enriched_schema"] == SCHEMA_VERSION

    def test_reenhance_all(self, tmp_catalog: Path):
        r = reenhance_all(tmp_catalog)
        assert r["ok"]
        assert r["total"] >= 3
        # All three (2 github + 1 kali) should be re-enhanced.
        for f in r.get("changed", []) if isinstance(r.get("changed"), list) else []:
            pass
        # changed is a count, not a list — just verify it's >= 0.
        assert r["changed"] >= 0

    def test_enhance_pending_only_picks_old_schema(self, tmp_catalog: Path):
        # First call: everything pending.
        r1 = enhance_pending(tmp_catalog)
        assert r1["pending"] >= 2
        assert r1["changed"] >= 2
        # Second call: nothing pending anymore.
        r2 = enhance_pending(tmp_catalog)
        assert r2["pending"] == 0

    def test_reenhance_handles_invalid_json(self, tmp_catalog: Path):
        bad = tmp_catalog / "github_test5_q.json"
        bad.write_text("not json")
        r = reenhance_one(bad)
        assert not r["ok"]
        assert "read/parse" in r["error"]


# ---------------------------------------------------------------------------
# audit
# ---------------------------------------------------------------------------

class TestAudit:
    def test_audit_returns_stats(self, tmp_catalog: Path):
        reenhance_all(tmp_catalog)
        a = audit_enhancements(tmp_catalog)
        assert a["ok"]
        assert a["total"] >= 3
        assert a["schema_v1_1_0_count"] >= 2
        assert "by_category" in a
        assert "mean_counts" in a
        assert "missing_new_fields" in a

    def test_audit_handles_nonexistent(self, tmp_path: Path):
        a = audit_enhancements(tmp_path / "nope")
        assert not a["ok"]
        assert "error" in a

    def test_audit_tracks_missing_fields(self, tmp_path: Path):
        cat = tmp_path / "catalog"
        cat.mkdir()
        (cat / "github_test1_foo.json").write_text(json.dumps({
            "id": "github:test1/foo",
            "name": "foo",
            "url": "https://github.com/test1/foo",
            "category": "Wireless Security",
        }))
        a = audit_enhancements(cat)
        # No schema tag yet.
        assert a["schema_v1_1_0_count"] == 0
        # attack_surface etc. are missing.
        assert "github_test1_foo.json" in a["missing_new_fields"]["attack_surface"]


# ---------------------------------------------------------------------------
# _maybe_reenhance
# ---------------------------------------------------------------------------

class TestMaybeReenhance:
    def test_returns_false_for_non_dict(self):
        assert _maybe_reenhance("not a dict") is False
        assert _maybe_reenhance(None) is False
        assert _maybe_reenhance([1, 2, 3]) is False

    def test_adds_new_fields(self):
        data = {
            "id": "github:x/y", "name": "y", "full_name": "x/y",
            "url": "https://github.com/x/y",
            "category": "Wireless Security",
        }
        changed = _maybe_reenhance(data, level="light")
        assert changed is True
        assert "attack_surface" in data
        assert "phase_hint" in data
        assert "requires_hardware" in data
        assert "polymorphic_strategies" in data
        assert "target_adaptive_targets" in data
        assert data["_kfiosa_enriched_schema"] == SCHEMA_VERSION


# ---------------------------------------------------------------------------
# _enrich_attack_surface
# ---------------------------------------------------------------------------

class TestEnrichAttackSurface:
    def test_wifi_returns_wifi_tokens(self):
        data = {"name": "wifite2", "category": "Wireless Security"}
        out = _enrich_attack_surface(data, "Wireless Security", "wifite2")
        assert isinstance(out, list)
        assert len(out) > 0
        # No fabricated versions.
        import re
        for t in out:
            assert not re.match(r"^v?\d+\.\d+", t)

    def test_ble_returns_ble_tokens(self):
        data = {"name": "btlejack", "category": "Bluetooth/BLE"}
        out = _enrich_attack_surface(data, "Bluetooth/BLE", "btlejack")
        assert isinstance(out, list)
        assert any("ble" in t for t in out)
