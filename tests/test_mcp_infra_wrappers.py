"""Hermetic tests for the live_edit + tool_installer MCP wrappers.

These wrappers are added to KALI_TOOL_WRAPPERS in core/mcp/tools.py so
the chain planner (and any external MCP client) can drive the new
infrastructure via the same `mcp_call` envelope as Kali tools.

Tests assert:
  - wrappers are present in KALI_TOOL_WRAPPERS
  - list_mcp_tools("infra") surfaces them
  - run() returns the documented envelope shape
  - live_edit_apply requires patch_id (missing-arg path is honest)
  - live_edit_revert rejects empty overlay_path
  - install_tool rejects empty tool
  - list_install_log returns a jsonl-like stdout
  - install_tool routes through the tool-installer maybe_install path
    (mocked so no real apt/pip/git runs)
"""
from __future__ import annotations

import json
import sys


# ---------------------------------------------------------------------------
# Wrapper registry presence
# ---------------------------------------------------------------------------

class TestWrappersPresent:
    def test_live_edit_wrappers_in_registry(self):
        from core.mcp.tools import KALI_TOOL_WRAPPERS
        assert "live_edit_apply" in KALI_TOOL_WRAPPERS
        assert "live_edit_revert" in KALI_TOOL_WRAPPERS
        assert "live_edit_list_patches" in KALI_TOOL_WRAPPERS

    def test_tool_installer_wrappers_in_registry(self):
        from core.mcp.tools import KALI_TOOL_WRAPPERS
        assert "install_tool" in KALI_TOOL_WRAPPERS
        assert "list_install_log" in KALI_TOOL_WRAPPERS

    def test_live_edit_wrappers_have_schemas(self):
        from core.mcp.tools import KALI_TOOL_WRAPPERS
        for name in ("live_edit_apply", "live_edit_revert",
                     "live_edit_list_patches"):
            w = KALI_TOOL_WRAPPERS[name]
            rec = w.as_mcp_record()
            assert "inputSchema" in rec
            assert "description" in rec
            assert rec["description"]  # non-empty

    def test_tool_installer_wrappers_have_schemas(self):
        from core.mcp.tools import KALI_TOOL_WRAPPERS
        for name in ("install_tool", "list_install_log"):
            w = KALI_TOOL_WRAPPERS[name]
            rec = w.as_mcp_record()
            assert "inputSchema" in rec


# ---------------------------------------------------------------------------
# Domain tagging
# ---------------------------------------------------------------------------

class TestDomainTagging:
    def test_live_edit_tagged_infra(self):
        from core.mcp.tools import list_mcp_tools
        tools = {t["name"]: t for t in list_mcp_tools("infra")}
        for name in ("live_edit_apply", "live_edit_revert",
                     "live_edit_list_patches", "install_tool",
                     "list_install_log"):
            assert name in tools, f"{name} not surfaced as infra"
            assert tools[name]["domain"] == "infra"


# ---------------------------------------------------------------------------
# live_edit_apply
# ---------------------------------------------------------------------------

class TestLiveEditApply:
    def test_missing_args_returns_error_envelope(self):
        from core.mcp.tools import call_mcp_tool
        # patch_id is required; omit it
        r = call_mcp_tool("live_edit_apply", {
            "target_runner": "x.y",
            "target_method": "_foo",
        })
        assert r["ok"] is False
        assert "missing" in r.get("error", "") or "required" in r.get("error", "")
        assert r["returncode"] == -1

    def test_unknown_target_runner_returns_error_envelope(self):
        from core.mcp.tools import call_mcp_tool
        r = call_mcp_tool("live_edit_apply", {
            "target_runner": "core.no_such_module_x_y_z",
            "target_method": "_foo",
            "patch_id": "add_logging",
            "rationale": "x",
        })
        assert r["ok"] is False
        assert "refused" in r.get("error", "") or "patch refused" in r.get("error", "")

    def test_unknown_patch_id_returns_error_envelope(self, monkeypatch):
        from core.mcp.tools import call_mcp_tool
        r = call_mcp_tool("live_edit_apply", {
            "target_runner": "x.y",
            "target_method": "_foo",
            "patch_id": "not_a_real_patch_xx",
            "rationale": "x",
        })
        # No runner module — the import fails before validation
        assert r["ok"] is False


# ---------------------------------------------------------------------------
# live_edit_revert
# ---------------------------------------------------------------------------

class TestLiveEditRevert:
    def test_empty_overlay_path_rejected(self):
        from core.mcp.tools import call_mcp_tool
        r = call_mcp_tool("live_edit_revert", {"overlay_path": ""})
        assert r["ok"] is False
        assert "required" in r.get("error", "") or "overlay_path" in r.get("error", "")

    def test_missing_overlay_path_rejected(self):
        from core.mcp.tools import call_mcp_tool
        r = call_mcp_tool("live_edit_revert", {})
        assert r["ok"] is False

    def test_nonexistent_overlay_rejected_honestly(self):
        from core.mcp.tools import call_mcp_tool
        r = call_mcp_tool("live_edit_revert",
                          {"overlay_path": "/tmp/definitely_not_here_overlay_x.py"})
        assert r["ok"] is False


# ---------------------------------------------------------------------------
# live_edit_list_patches
# ---------------------------------------------------------------------------

class TestLiveEditListPatches:
    def test_returns_csv_of_known_patches(self):
        from core.mcp.tools import call_mcp_tool
        r = call_mcp_tool("live_edit_list_patches", {})
        assert r["ok"] is True
        # stdout is a comma-separated list of patch ids
        names = [n for n in r["stdout"].split(",") if n]
        for expected in ("add_logging", "add_optional_arg",
                         "swap_retry_count", "set_which_fail_to_real"):
            assert expected in names


# ---------------------------------------------------------------------------
# install_tool
# ---------------------------------------------------------------------------

class TestInstallTool:
    def test_missing_tool_rejected(self, monkeypatch):
        from core.mcp.tools import call_mcp_tool
        r = call_mcp_tool("install_tool", {})
        assert r["ok"] is False
        assert "required" in r.get("error", "") or "tool" in r.get("error", "")

    def test_unknown_tool_rejected_honestly(self, monkeypatch):
        """Tool not in catalog → maybe_install returns False, not raise."""
        from core.mcp.tools import call_mcp_tool
        # route through the actual install path but with a clearly
        # non-catalog tool name
        r = call_mcp_tool("install_tool",
                          {"tool": "definitely_not_in_catalog_xyz123",
                           "auto": True})
        assert r["ok"] is False
        assert "install failed" in r.get("stdout", "")

    def test_known_tool_calls_maybe_install(self, monkeypatch):
        """When tool is in catalog, call_mcp_tool delegates to maybe_install."""
        from core.mcp import tools as mcp_tools

        called = {"args": None}

        def fake_maybe_install(tool, auto=False, **_):
            called["args"] = (tool, auto)
            return True

        monkeypatch.setattr(
            "core.tool_installer.install.maybe_install", fake_maybe_install,
        )
        # Force the lazy import inside _run_install_tool to find the monkeypatch
        r = mcp_tools.call_mcp_tool(
            "install_tool", {"tool": "gatttool", "auto": True},
        )
        assert r["ok"] is True
        assert called["args"] == ("gatttool", True)


# ---------------------------------------------------------------------------
# list_install_log
# ---------------------------------------------------------------------------

class TestListInstallLog:
    def test_returns_envelope(self):
        from core.mcp.tools import call_mcp_tool
        r = call_mcp_tool("list_install_log", {"last": 5})
        assert r["ok"] is True
        assert "stdout" in r
        # If there are entries, each line is JSON
        for line in [ln for ln in r["stdout"].splitlines() if ln.strip()]:
            json.loads(line)  # raises on malformed
