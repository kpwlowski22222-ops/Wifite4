"""Tests for core.bootstrap — Phase 4 T22 coverage."""
from __future__ import annotations

import importlib
import os

import pytest


def _import_mod():
    return importlib.import_module("core.bootstrap")


mod = _import_mod()


# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------

class TestConstants:
    def test_hard_deps_contains_curses(self):
        assert "curses" in mod._HARD_DEPS

    def test_hard_deps_contains_requests(self):
        assert "requests" in mod._HARD_DEPS

    def test_soft_deps_optional(self):
        # Soft deps include bleak, shodan, etc.
        assert "bleak" in mod._SOFT_DEPS
        assert "shodan" in mod._SOFT_DEPS

    def test_toolchain_has_wifi_tools(self):
        for tool in ("airodump-ng", "aireplay-ng", "aircrack-ng",
                     "hashcat", "hostapd", "dnsmasq"):
            assert tool in mod._TOOLCHAIN, f"missing {tool}"

    def test_toolchain_has_ble_tools(self):
        for tool in ("bluetoothctl", "hcitool", "gatttool", "bettercap"):
            assert tool in mod._TOOLCHAIN, f"missing {tool}"

    def test_toolchain_has_metasploit(self):
        assert "msfconsole" in mod._TOOLCHAIN
        assert "msfvenom" in mod._TOOLCHAIN

    def test_toolchain_has_osint(self):
        for tool in ("sherlock", "theHarvester", "subfinder", "amass"):
            assert tool in mod._TOOLCHAIN, f"missing {tool}"


# ---------------------------------------------------------------------------
# check_requirements
# ---------------------------------------------------------------------------

class TestCheckRequirements:
    def test_returns_dict(self):
        out = mod.check_requirements()
        assert isinstance(out, dict)

    def test_keys_match_deps(self):
        out = mod.check_requirements()
        for dep in mod._HARD_DEPS + mod._SOFT_DEPS:
            assert dep in out, f"missing {dep}"

    def test_values_are_bool(self):
        out = mod.check_requirements()
        for v in out.values():
            assert isinstance(v, bool)

    def test_curses_present(self):
        # curses is a hard dep and is in the test env
        out = mod.check_requirements()
        assert out.get("curses") is True

    def test_requests_present(self):
        out = mod.check_requirements()
        assert out.get("requests") is True


# ---------------------------------------------------------------------------
# check_tools
# ---------------------------------------------------------------------------

class TestCheckTools:
    def test_returns_dict(self):
        out = mod.check_tools()
        assert isinstance(out, dict)

    def test_keys_match_toolchain(self):
        out = mod.check_tools()
        for tool in mod._TOOLCHAIN:
            assert tool in out, f"missing {tool}"

    def test_values_are_bool(self):
        out = mod.check_tools()
        for v in out.values():
            assert isinstance(v, bool)


# ---------------------------------------------------------------------------
# check_ollama
# ---------------------------------------------------------------------------

class TestCheckOllama:
    def test_default_endpoint(self):
        out = mod.check_ollama()
        assert "reachable" in out
        assert "models" in out
        assert "endpoint" in out
        assert out["endpoint"] == "http://127.0.0.1:11434"

    def test_unreachable_endpoint(self):
        # Use a high unused port (port 1 can be claimed on some hosts)
        out = mod.check_ollama("http://127.0.0.1:59999", timeout=0.8)
        assert out["reachable"] is False
        assert out["models"] == []

    def test_missing_scheme_added(self):
        # If user gives "127.0.0.1:11434" without scheme, the function
        # adds the scheme internally for the request.  The returned
        # endpoint field is the *input* the caller gave.
        out = mod.check_ollama("127.0.0.1:1")
        # endpoint field preserves the input
        assert out["endpoint"] == "127.0.0.1:1"
        # but the request would have been made to http://127.0.0.1:1
        # (we can't observe this directly; the test just verifies
        # the function doesn't crash on scheme-less input)
        assert "reachable" in out

    def test_endpoint_preserved(self):
        out = mod.check_ollama("http://example.com:9999")
        assert out["endpoint"] == "http://example.com:9999"


# ---------------------------------------------------------------------------
# preflight
# ---------------------------------------------------------------------------

class TestPreflight:
    def test_runs_without_settings(self, capsys):
        out = mod.preflight()
        captured = capsys.readouterr()
        assert "KFIOSA PREFLIGHT" in captured.out
        assert "[Python deps]" in captured.out
        assert "[Ollama]" in captured.out
        assert "[Offensive toolchain]" in captured.out
        assert "deps" in out
        assert "tools" in out
        assert "ollama" in out
        assert "hard_missing" in out

    def test_runs_with_none_settings(self, capsys):
        # explicit None
        out = mod.preflight(settings=None)
        assert "deps" in out

    def test_uses_settings_ollama_endpoint(self, capsys):
        class FakeSettings:
            def get_setting(self, key, default=None):
                return "http://192.0.2.1:1234"  # TEST-NET-1, unreachable
        out = mod.preflight(settings=FakeSettings())
        # Even if endpoint was overridden, preflight doesn't crash
        assert "deps" in out

    def test_ollama_host_env_var(self, capsys, monkeypatch):
        monkeypatch.setenv("OLLAMA_HOST", "http://127.0.0.1:1")
        out = mod.preflight()
        assert out["ollama"]["endpoint"] == "http://127.0.0.1:1"

    def test_hard_missing_reported(self, capsys):
        out = mod.preflight()
        # In test env, hard deps are present, so hard_missing is empty
        # (or contains only the truly missing ones)
        if "curses" in mod._HARD_DEPS and "requests" in mod._HARD_DEPS:
            # Both should be present
            for d in ("curses", "requests"):
                if not out["deps"].get(d):
                    assert d in out["hard_missing"]

    def test_no_inline_creds(self, capsys):
        out = mod.preflight()
        text = str(out)
        for forbidden in ("ecf51ee2-938d", "f40bec4b664a40a9a",
                          "CE38F76832CFA1F6", "password", "secret",
                          "OLLAMA_CLOUD_TOKEN"):
            assert forbidden not in text, f"leaked {forbidden!r}"


# ---------------------------------------------------------------------------
# Main entrypoint (smoke)
# ---------------------------------------------------------------------------

class TestMain:
    def test_module_runs_as_main(self, capsys, monkeypatch):
        # Don't actually run preflight from __main__ since it prints
        # to stdout; just verify the block exists
        import inspect
        src = inspect.getsource(mod)
        assert 'if __name__ == "__main__"' in src
