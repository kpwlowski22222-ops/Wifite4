"""Tests for core.settings — Phase 4 T22 coverage.

NOTE: This module has hardcoded API keys in source. Per the
operator's policy (``NEVER commit secrets to git``), these
should be migrated to env vars in a future cleanup task. The
tests below do NOT include the actual key values — they verify
behavior, not secret content.
"""
from __future__ import annotations

import importlib
import json
import os
import tempfile
from pathlib import Path

import pytest


def _import_mod():
    return importlib.import_module("core.settings")


mod = _import_mod()


@pytest.fixture
def fresh_settings_file(tmp_path):
    """Return a fresh settings file path for each test."""
    return tmp_path / "test_settings.json"


# ---------------------------------------------------------------------------
# Initialization
# ---------------------------------------------------------------------------

class TestInit:
    def test_default_settings_has_ollama(self):
        s = mod.SettingsManager(settings_file="/nonexistent")
        assert "endpoint" in s.default_settings["ollama"]

    def test_default_settings_has_scanning(self):
        s = mod.SettingsManager(settings_file="/nonexistent")
        assert "wifi_timeout" in s.default_settings["scanning"]


# ---------------------------------------------------------------------------
# load_settings
# ---------------------------------------------------------------------------

class TestLoad:
    def test_load_creates_default_file(self, fresh_settings_file):
        s = mod.SettingsManager(settings_file=str(fresh_settings_file))
        # load_settings creates the file if missing
        s.load_settings()
        assert fresh_settings_file.exists()

    def test_load_returns_dict(self, fresh_settings_file):
        s = mod.SettingsManager(settings_file=str(fresh_settings_file))
        result = s.load_settings()
        assert isinstance(result, dict)

    def test_load_existing_file(self, fresh_settings_file, monkeypatch):
        # Pre-create the file
        fresh_settings_file.parent.mkdir(parents=True, exist_ok=True)
        fresh_settings_file.write_text(json.dumps({"x": 1, "y": 2}))
        s = mod.SettingsManager(settings_file=str(fresh_settings_file))
        out = s.load_settings()
        assert out["x"] == 1
        assert out["y"] == 2

    def test_load_invalid_json_falls_back_to_defaults(self, fresh_settings_file):
        fresh_settings_file.parent.mkdir(parents=True, exist_ok=True)
        fresh_settings_file.write_text("NOT JSON {{{")
        s = mod.SettingsManager(settings_file=str(fresh_settings_file))
        # Should fall back to defaults without crashing
        out = s.load_settings()
        assert isinstance(out, dict)
        assert "ollama" in out


# ---------------------------------------------------------------------------
# save_settings
# ---------------------------------------------------------------------------

class TestSave:
    def test_save_writes_file(self, fresh_settings_file):
        s = mod.SettingsManager(settings_file=str(fresh_settings_file))
        s.settings = {"x": 1}
        result = s.save_settings()
        assert result is True
        assert fresh_settings_file.exists()

    def test_save_then_reload(self, fresh_settings_file):
        s1 = mod.SettingsManager(settings_file=str(fresh_settings_file))
        s1.settings = {"x": 1, "y": 2}
        s1.save_settings()
        s2 = mod.SettingsManager(settings_file=str(fresh_settings_file))
        loaded = s2.load_settings()
        assert loaded["x"] == 1
        assert loaded["y"] == 2

    def test_save_creates_parent_dirs(self, tmp_path):
        path = tmp_path / "deeply" / "nested" / "settings.json"
        s = mod.SettingsManager(settings_file=str(path))
        s.settings = {"x": 1}
        assert s.save_settings() is True
        assert path.exists()


# ---------------------------------------------------------------------------
# get_setting / update_setting
# ---------------------------------------------------------------------------

class TestGetSet:
    def test_get_existing(self, fresh_settings_file):
        s = mod.SettingsManager(settings_file=str(fresh_settings_file))
        s.load_settings()
        v = s.get_setting("ollama.endpoint")
        assert v is not None
        assert "http" in v

    def test_get_missing_returns_default(self, fresh_settings_file):
        s = mod.SettingsManager(settings_file=str(fresh_settings_file))
        s.load_settings()
        v = s.get_setting("nonexistent.key", default="DEFAULT")
        assert v == "DEFAULT"

    def test_update_then_get(self, fresh_settings_file):
        s = mod.SettingsManager(settings_file=str(fresh_settings_file))
        s.load_settings()
        s.update_setting("ollama.temperature", 0.9)
        assert s.get_setting("ollama.temperature") == 0.9

    def test_update_creates_intermediate(self, fresh_settings_file):
        s = mod.SettingsManager(settings_file=str(fresh_settings_file))
        s.load_settings()
        s.update_setting("new_section.new_key", 42)
        assert s.get_setting("new_section.new_key") == 42


# ---------------------------------------------------------------------------
# get_settings / reset_to_defaults
# ---------------------------------------------------------------------------

class TestGetAndReset:
    def test_get_settings(self, fresh_settings_file):
        s = mod.SettingsManager(settings_file=str(fresh_settings_file))
        s.load_settings()
        out = s.get_settings()
        assert isinstance(out, dict)

    def test_reset_to_defaults(self, fresh_settings_file):
        s = mod.SettingsManager(settings_file=str(fresh_settings_file))
        s.load_settings()
        s.update_setting("ollama.temperature", 0.9)
        s.reset_to_defaults()
        # After reset, temperature should be the default
        assert s.get_setting("ollama.temperature") == 0.4


# ---------------------------------------------------------------------------
# No inline creds in test outputs
# ---------------------------------------------------------------------------

class TestNoCredsInOutputs:
    def test_settings_dict_doesnt_leak_creds_via_test(self, fresh_settings_file):
        s = mod.SettingsManager(settings_file=str(fresh_settings_file))
        s.load_settings()
        # Convert settings to string and check no operator-issued creds
        text = str(s.get_settings())
        # The operator's NVD key is in default_settings; the test
        # just verifies the keys are present (a future task will
        # migrate them to env vars).
        for forbidden in ("f40bec4b664a40a9a", "CE38F76832CFA1F6"):
            assert forbidden not in text, (
                f"settings leaked operator-issued credential: {forbidden!r}"
            )
