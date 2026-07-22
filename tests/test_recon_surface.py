"""Surface tests for the recon-probe batch — verifies the 9 novel passive
recon algorithms (implemented IN ``core/modules/catalog_recon.py``) are
correctly surfaced to the AI through all three channels:

  1. Orchestrator ``_dispatch_recon_probe`` (the native ``recon_probe``
     chain action — routes the AI step to ``catalog_recon.run_probe``,
     records the result, and merges probe data into ``seed["recon"]`` so
     the re-planner sees the new signal).
  2. MCP wrappers ``recon_probe_<method>`` in ``KALI_TOOL_WRAPPERS`` —
     the ``mcp_call`` path; ``list_mcp_tools("wifi")`` tags them wifi and
     ``mcp_tools_context_block`` renders their schema/examples/risk.
  3. The chain planner ``_SYSTEM_PROMPT`` + ``_CHAIN_STEP_SCHEMA_HINT``
     teach the LLM the ``recon_probe`` action and all 15 methods
     (6 core steps + 9 novel passive probes).

Hermetic: ``shutil.which`` is mocked empty so no real Kali binary runs;
``catalog_recon.run_probe`` is patched where we only assert routing (not
algorithm output — that is covered by ``test_catalog_recon_probes.py``).
"""

import unittest.mock as mock

import pytest

from core.orchestrator.autonomous_orchestrator import AutonomousOrchestrator
from core.modules.catalog_recon import RECON_PROBES, CatalogRecon
from core.mcp import tools as mcp_tools
from core.ai_backend.chain import AIChainPlanner, _SYSTEM_PROMPT, _CHAIN_STEP_SCHEMA_HINT
from tests.fakes import FakeAIBackend, FakeKB


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_orch(confirm_fn=None, log=None):
    return AutonomousOrchestrator(
        ai_backend=FakeAIBackend(),
        kb=FakeKB(),
        confirm_fn=confirm_fn or (lambda p: True),
        on_event=(log or []).append,
    )


def _seed():
    return {"bssid": "EC:08:6B:11:22:33", "ssid": "TestNet",
            "channel": "6", "interface": "wlan0mon",
            "encryption": "WPA2"}


# ---------------------------------------------------------------------------
# 1. Orchestrator _dispatch_recon_probe
# ---------------------------------------------------------------------------

def test_dispatch_recon_probe_routes_and_records():
    """A valid method calls run_probe, records an executed entry, and
    merges the probe data into seed["recon"][method]."""
    o = _make_orch()
    report = {"executed": [], "skipped": [], "access": {}}
    seed = _seed()
    captured = {}

    def fake_run_probe(method, target=None, settings=None, **_):
        captured["method"] = method
        captured["target"] = target
        captured["settings"] = settings
        return {"ok": True, "data": {"pmkid_feasible": True, "foo": 1},
                "error": None}

    with mock.patch(
            "core.modules.catalog_recon.run_probe", side_effect=fake_run_probe):
        o._dispatch_recon_probe(
            {"action": "recon_probe",
             "args": {"method": "handshake_harvest"}},
            seed, report)

    assert captured["method"] == "handshake_harvest"
    # target dict built from seed + args
    assert captured["target"]["bssid"] == "EC:08:6B:11:22:33"
    assert captured["target"]["interface"] == "wlan0mon"
    assert captured["settings"] is o.settings
    assert len(report["executed"]) == 1
    entry = report["executed"][0]
    assert entry["action"] == "recon_probe"
    assert entry["method"] == "handshake_harvest"
    assert entry["ok"] is True
    assert entry["tool"] == "catalog_recon.handshake_harvest"
    # merged into seed["recon"] for the re-planner
    assert seed["recon"]["handshake_harvest"] == {"pmkid_feasible": True, "foo": 1}
    assert report["skipped"] == []


def test_dispatch_recon_probe_unknown_method_skipped():
    """An unknown method is skipped (not executed) and never raises."""
    o = _make_orch()
    report = {"executed": [], "skipped": [], "access": {}}
    seed = _seed()
    called = {"n": 0}

    def fake_run_probe(*a, **k):
        called["n"] += 1
        return {"ok": True, "data": {}}

    with mock.patch(
            "core.modules.catalog_recon.run_probe", side_effect=fake_run_probe):
        o._dispatch_recon_probe(
            {"action": "recon_probe", "args": {"method": "bogus"}},
            seed, report)

    assert called["n"] == 0                      # never ran
    assert report["executed"] == []
    assert any("unknown method" in s for s in report["skipped"])
    assert "recon" not in seed                   # nothing merged


def test_dispatch_recon_probe_strips_recon_probe_prefix_from_tool():
    """The AI may set tool='recon_probe_beacon_parse' (the MCP name) —
    dispatch strips the prefix and runs beacon_parse."""
    o = _make_orch()
    report = {"executed": [], "skipped": [], "access": {}}
    seed = _seed()
    captured = {}

    def fake_run_probe(method, target=None, settings=None, **_):
        captured["method"] = method
        return {"ok": True, "data": {"is_wpa3": False}}

    with mock.patch(
            "core.modules.catalog_recon.run_probe", side_effect=fake_run_probe):
        # No args.method — method falls back to step["tool"].
        o._dispatch_recon_probe(
            {"action": "recon_probe", "tool": "recon_probe_beacon_parse",
             "args": {}},
            seed, report)

    assert captured["method"] == "beacon_parse"
    assert report["executed"][0]["method"] == "beacon_parse"


def test_dispatch_recon_probe_run_probe_exception_never_raises():
    """If run_probe raises, dispatch catches it and records a skip."""
    o = _make_orch()
    report = {"executed": [], "skipped": [], "access": {}}
    seed = _seed()

    def boom(*a, **k):
        raise RuntimeError("explode")

    with mock.patch(
            "core.modules.catalog_recon.run_probe", side_effect=boom):
        # Must not raise.
        o._dispatch_recon_probe(
            {"action": "recon_probe", "args": {"method": "signal_map"}},
            seed, report)

    assert report["executed"] == []
    assert any("signal_map" in s for s in report["skipped"])


def test_dispatch_recon_probe_failed_probe_not_merged():
    """ok=False probe data is NOT merged into seed (re-planner only
    trusts successful signal)."""
    o = _make_orch()
    report = {"executed": [], "skipped": [], "access": {}}
    seed = _seed()

    with mock.patch(
            "core.modules.catalog_recon.run_probe",
            return_value={"ok": False, "error": "tshark not installed",
                          "data": None}):
        o._dispatch_recon_probe(
            {"action": "recon_probe", "args": {"method": "eapol_monitor"}},
            seed, report)

    assert report["executed"][0]["ok"] is False
    assert "recon" not in seed


# ---------------------------------------------------------------------------
# 2. MCP wrappers
# ---------------------------------------------------------------------------

def test_recon_probe_wrappers_registered():
    """All 9 recon_probe_<method> wrappers are in KALI_TOOL_WRAPPERS,
    passive (risk=read), and do not require root."""
    for spec in RECON_PROBES:
        name = spec["name"]
        assert name in mcp_tools.KALI_TOOL_WRAPPERS, name
        w = mcp_tools.KALI_TOOL_WRAPPERS[name]
        rec = w.as_mcp_record()
        assert rec["risk_level"] == "read"
        assert rec["requires_root"] is False
        assert rec["inputSchema"]                   # schema present
        assert rec["examples"]                      # examples present


def test_call_mcp_tool_recon_probe_runs_algorithm():
    """call_mcp_tool('recon_probe_<method>', target) dispatches into
    catalog_recon.run_probe with the method bound to the wrapper. The
    wrapper captured the module-level ``run_probe`` at import time, so we
    patch the instance method it ultimately calls
    (``CatalogRecon.run_probe``) — this exercises the real module-level
    wrapper too."""
    captured = {}

    def fake_inst_run_probe(self, method):
        captured["method"] = method
        captured["target"] = self.target
        return {"ok": True, "data": {"x": 1}, "error": None}

    with mock.patch.object(CatalogRecon, "run_probe", fake_inst_run_probe):
        res = mcp_tools.call_mcp_tool(
            "recon_probe_channel_plan",
            {"bssid": "AA:BB:CC:DD:EE:FF", "channel": "6"})

    assert res["ok"] is True
    assert captured["method"] == "channel_plan"
    assert captured["target"]["bssid"] == "AA:BB:CC:DD:EE:FF"


def test_call_mcp_tool_recon_probe_unknown_method():
    """An unknown recon_probe name is surfaced as ok=False (never raises)."""
    res = mcp_tools.call_mcp_tool("recon_probe_nope", {})
    assert res["ok"] is False


def test_call_mcp_tool_recon_probe_runner_swallows_exception():
    """The wrapper runner never lets an exception escape MCP. The
    module-level run_probe catches it and returns ok=False."""
    def boom(self, method):
        raise RuntimeError("boom")

    with mock.patch.object(CatalogRecon, "run_probe", boom):
        res = mcp_tools.call_mcp_tool("recon_probe_gps_wardrive", {})
    assert res["ok"] is False
    assert "boom" in (res.get("error") or "")


def test_list_mcp_tools_wifi_includes_recon_probes():
    """list_mcp_tools('wifi') surfaces the 9 recon probes (wifi-tagged)."""
    tools = mcp_tools.list_mcp_tools("wifi")
    names = {t["name"] for t in tools}
    recon_names = {s["name"] for s in RECON_PROBES}
    assert recon_names <= names
    for t in tools:
        if t["name"] in recon_names:
            assert t["domain"] == "wifi"


def test_mcp_tools_context_block_surfaces_recon_probes():
    """mcp_tools_context_block('wifi') renders the recon probes with
    schema + risk so the chain planner prompt can offer them."""
    block = mcp_tools.mcp_tools_context_block("wifi", limit=200)
    assert block  # non-empty
    for spec in RECON_PROBES:
        assert spec["name"] in block
    # at least one recon probe line carries risk=read
    assert "risk=read" in block


# ---------------------------------------------------------------------------
# 3. Chain planner prompt + schema
# ---------------------------------------------------------------------------

def test_chain_schema_hint_includes_recon_probe_action():
    assert "recon_probe" in _CHAIN_STEP_SCHEMA_HINT


def test_chain_system_prompt_teaches_all_recon_methods():
    """The planner system prompt names the recon_probe action and all
    15 method names (6 core steps + 9 novel passive probes) so the LLM
    can emit them pre-attack."""
    assert "recon_probe" in _SYSTEM_PROMPT
    methods = CatalogRecon.RECON_PROBE_METHODS
    assert set(methods) == {
        # 6 core steps (also run bundled by CatalogRecon.run()).
        "wps", "clients", "cves", "weakpass", "kb_hits", "catalog_runs",
        # 9 novel passive probes.
        "probe_profile", "hidden_ssid", "signal_map", "handshake_harvest",
        "eapol_monitor", "channel_plan", "deauth_detect", "gps_wardrive",
        "beacon_parse",
    }
    for m in methods:
        assert m in _SYSTEM_PROMPT, m
    # Emphasis: PASSIVE (no deauth/injection) + emit early.
    assert "PASSIVE" in _SYSTEM_PROMPT
    assert "EARLY" in _SYSTEM_PROMPT


def test_chain_plan_prompt_contains_mcp_probe_names():
    """The planner system prompt mentions the recon_probe_<method> MCP
    names (the mcp_call path) too, so the LLM knows it can drive the same
    probes via mcp_call. The prompt lists a couple of example names plus
    an ellipsis rather than all 15 verbatim."""
    assert "mcp_call" in _SYSTEM_PROMPT
    assert "recon_probe_profile" in _SYSTEM_PROMPT
    assert "recon_probe_hidden_ssid" in _SYSTEM_PROMPT
    assert "..." in _SYSTEM_PROMPT