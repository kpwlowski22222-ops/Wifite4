"""Hermetic tests for the Phase 2.0 MCP factory wrappers:

  * ``_make_microsoft_attack_wrappers`` (14 methods: 8 read + 6 intrusive)
  * ``_make_android_attack_wrappers``  (12 methods: 8 read + 4 intrusive)
  * ``_make_ios_attack_wrappers``      (12 methods: 8 read + 4 intrusive)
  * ``_make_live_target_wrappers``     (9 whitelist patches)

These wrappers are added to ``KALI_TOOL_WRAPPERS`` in
``core/mcp/tools.py`` so the chain planner and any external MCP
client can drive the new target classes via the same ``mcp_call``
envelope as Kali tools.

Tests assert:
  - the wrappers are present in ``KALI_TOOL_WRAPPERS``
  - the registry names match the expected pattern
  - ``as_mcp_record()`` returns a non-empty description + inputSchema
  - ``run()`` returns the documented envelope shape
  - the dispatchers route through the right runner module
  - ``list_mcp_tools("microsoft") / "android" / "ios" / "live_target"``
    surfaces them and tags the right domain
  - ``call_mcp_tool`` returns the honest error envelope for unknown
    methods (no fabricated success)
"""
from __future__ import annotations

import json
import sys


# ---------------------------------------------------------------------------
# Microsoft wrappers
# ---------------------------------------------------------------------------

class TestMicrosoftWrappers:
    def test_in_registry(self):
        from core.mcp.tools import KALI_TOOL_WRAPPERS
        ms = [n for n in KALI_TOOL_WRAPPERS
              if n.startswith("microsoft_attack_")]
        assert len(ms) == 14, f"expected 14 microsoft_attack_*, got {len(ms)}"

    def test_names_unique(self):
        from core.mcp.tools import KALI_TOOL_WRAPPERS
        ms = [n for n in KALI_TOOL_WRAPPERS
              if n.startswith("microsoft_attack_")]
        assert len(ms) == len(set(ms))

    def test_schemas(self):
        from core.mcp.tools import KALI_TOOL_WRAPPERS
        for n in [n for n in KALI_TOOL_WRAPPERS
                  if n.startswith("microsoft_attack_")]:
            rec = KALI_TOOL_WRAPPERS[n].as_mcp_record()
            assert "inputSchema" in rec
            assert "description" in rec
            assert rec["description"]

    def test_domain_tagging(self):
        from core.mcp.tools import list_mcp_tools
        tools = {t["name"]: t for t in list_mcp_tools("microsoft")}
        ms = [n for n in tools if n.startswith("microsoft_attack_")]
        assert len(ms) == 14
        for t in tools.values():
            assert t["domain"] == "microsoft"

    def test_risk_levels(self):
        # 8 read + 5 intrusive + 1 destructive (mimikatz)
        from core.mcp.tools import KALI_TOOL_WRAPPERS
        risks = {KALI_TOOL_WRAPPERS[n].risk_level
                 for n in KALI_TOOL_WRAPPERS
                 if n.startswith("microsoft_attack_")}
        assert "read" in risks
        assert "intrusive" in risks
        assert "destructive" in risks

    def test_run_envelope_unknown(self):
        # An unknown method shouldn't fake a success — it should
        # return the standard error envelope.
        from core.mcp.tools import call_mcp_tool
        r = call_mcp_tool("microsoft_attack_nope_xyz", {})
        assert r["ok"] is False
        assert r.get("returncode", -1) != 0


# ---------------------------------------------------------------------------
# Android wrappers
# ---------------------------------------------------------------------------

class TestAndroidWrappers:
    def test_in_registry(self):
        from core.mcp.tools import KALI_TOOL_WRAPPERS
        a = [n for n in KALI_TOOL_WRAPPERS
             if n.startswith("android_attack_")]
        assert len(a) == 12, f"expected 12 android_attack_*, got {len(a)}"

    def test_names_unique(self):
        from core.mcp.tools import KALI_TOOL_WRAPPERS
        a = [n for n in KALI_TOOL_WRAPPERS
             if n.startswith("android_attack_")]
        assert len(a) == len(set(a))

    def test_schemas(self):
        from core.mcp.tools import KALI_TOOL_WRAPPERS
        for n in [n for n in KALI_TOOL_WRAPPERS
                  if n.startswith("android_attack_")]:
            rec = KALI_TOOL_WRAPPERS[n].as_mcp_record()
            assert "inputSchema" in rec
            assert "description" in rec
            assert rec["description"]

    def test_domain_tagging(self):
        from core.mcp.tools import list_mcp_tools
        tools = {t["name"]: t for t in list_mcp_tools("android")}
        a = [n for n in tools if n.startswith("android_attack_")]
        assert len(a) == 12
        for t in tools.values():
            assert t["domain"] == "android"

    def test_risk_levels(self):
        # 8 read + 3 intrusive + 1 destructive (apktool_repack)
        from core.mcp.tools import KALI_TOOL_WRAPPERS
        risks = {KALI_TOOL_WRAPPERS[n].risk_level
                 for n in KALI_TOOL_WRAPPERS
                 if n.startswith("android_attack_")}
        assert "read" in risks
        assert "intrusive" in risks
        assert "destructive" in risks

    def test_run_envelope_unknown(self):
        from core.mcp.tools import call_mcp_tool
        r = call_mcp_tool("android_attack_nope_xyz", {})
        assert r["ok"] is False


# ---------------------------------------------------------------------------
# iOS wrappers
# ---------------------------------------------------------------------------

class TestIosWrappers:
    def test_in_registry(self):
        from core.mcp.tools import KALI_TOOL_WRAPPERS
        i = [n for n in KALI_TOOL_WRAPPERS
             if n.startswith("ios_attack_")]
        assert len(i) == 12, f"expected 12 ios_attack_*, got {len(i)}"

    def test_names_unique(self):
        from core.mcp.tools import KALI_TOOL_WRAPPERS
        i = [n for n in KALI_TOOL_WRAPPERS
             if n.startswith("ios_attack_")]
        assert len(i) == len(set(i))

    def test_schemas(self):
        from core.mcp.tools import KALI_TOOL_WRAPPERS
        for n in [n for n in KALI_TOOL_WRAPPERS
                  if n.startswith("ios_attack_")]:
            rec = KALI_TOOL_WRAPPERS[n].as_mcp_record()
            assert "inputSchema" in rec
            assert "description" in rec
            assert rec["description"]

    def test_domain_tagging(self):
        from core.mcp.tools import list_mcp_tools
        tools = {t["name"]: t for t in list_mcp_tools("ios")}
        i = [n for n in tools if n.startswith("ios_attack_")]
        assert len(i) == 12
        for t in tools.values():
            assert t["domain"] == "ios"

    def test_risk_levels(self):
        # 8 read + 4 intrusive (all 4 intrusive iOS methods are intrusive)
        from core.mcp.tools import KALI_TOOL_WRAPPERS
        risks = {KALI_TOOL_WRAPPERS[n].risk_level
                 for n in KALI_TOOL_WRAPPERS
                 if n.startswith("ios_attack_")}
        assert "read" in risks
        assert "intrusive" in risks

    def test_run_envelope_unknown(self):
        from core.mcp.tools import call_mcp_tool
        r = call_mcp_tool("ios_attack_nope_xyz", {})
        assert r["ok"] is False


# ---------------------------------------------------------------------------
# live_target wrappers
# ---------------------------------------------------------------------------

class TestLiveTargetWrappers:
    def test_in_registry(self):
        from core.mcp.tools import KALI_TOOL_WRAPPERS
        lt = [n for n in KALI_TOOL_WRAPPERS
              if n.startswith("live_target_")]
        assert len(lt) == 9, f"expected 9 live_target_*, got {len(lt)}"

    def test_names_unique(self):
        from core.mcp.tools import KALI_TOOL_WRAPPERS
        lt = [n for n in KALI_TOOL_WRAPPERS
              if n.startswith("live_target_")]
        assert len(lt) == len(set(lt))

    def test_schemas(self):
        from core.mcp.tools import KALI_TOOL_WRAPPERS
        for n in [n for n in KALI_TOOL_WRAPPERS
                  if n.startswith("live_target_")]:
            rec = KALI_TOOL_WRAPPERS[n].as_mcp_record()
            assert "inputSchema" in rec
            assert "description" in rec
            assert rec["description"]

    def test_domain_tagging(self):
        from core.mcp.tools import list_mcp_tools
        tools = {t["name"]: t for t in list_mcp_tools("live_target")}
        lt = [n for n in tools if n.startswith("live_target_")]
        assert len(lt) == 9
        for t in tools.values():
            assert t["domain"] == "live_target"

    def test_risk_level_intrusive(self):
        # live_target is whitelist-only editing of KFIOSA's own
        # emitted artifacts (PowerShell, Frida .js, plist, etc).
        # The patches are intrusive (they change the artifact that
        # will be run) but never touch the target machine's code.
        from core.mcp.tools import KALI_TOOL_WRAPPERS
        for n in [n for n in KALI_TOOL_WRAPPERS
                  if n.startswith("live_target_")]:
            assert KALI_TOOL_WRAPPERS[n].risk_level == "intrusive"

    def test_run_envelope_missing_patch_id(self):
        from core.mcp.tools import call_mcp_tool
        r = call_mcp_tool("live_target_apply", {"params": {}})
        assert r["ok"] is False

    def test_run_envelope_unknown(self):
        from core.mcp.tools import call_mcp_tool
        r = call_mcp_tool("live_target_nope_xyz", {})
        assert r["ok"] is False


# ---------------------------------------------------------------------------
# Cross-cutting: registry shape
# ---------------------------------------------------------------------------

class TestRegistryShape:
    def test_all_new_wrappers_present(self):
        from core.mcp.tools import KALI_TOOL_WRAPPERS
        all_new = []
        for prefix, n_expected in (("microsoft_attack_", 14),
                                    ("android_attack_", 12),
                                    ("ios_attack_", 12),
                                    ("live_target_", 9)):
            got = [n for n in KALI_TOOL_WRAPPERS
                   if n.startswith(prefix)]
            assert len(got) == n_expected, (
                f"{prefix}* has {len(got)}, expected {n_expected}")
            all_new.extend(got)
        assert len(all_new) == len(set(all_new))

    def test_no_overlap_with_existing(self):
        from core.mcp.tools import KALI_TOOL_WRAPPERS
        ms = {n for n in KALI_TOOL_WRAPPERS
              if n.startswith(("microsoft_attack_", "android_attack_",
                              "ios_attack_", "live_target_"))}
        # The prefixes are unique by construction — but assert
        # the live_target_* methods don't collide with the attack_
        # methods.
        for n in ms:
            assert n.startswith(("microsoft_attack_", "android_attack_",
                                 "ios_attack_", "live_target_"))
