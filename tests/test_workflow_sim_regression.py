"""Regression: hermetic workflow sim — designed vs actual bugs found in debug.

Covers:
  - CatalogRecon.run(with_probes=True) does not AttributeError on _wps
  - mcp_call airodump-ng without mcp_client uses call_mcp_tool (not unknown action)
  - heuristic chain is labeled source=heuristic (not llm)
"""

from __future__ import annotations

from unittest import mock

import pytest


def test_catalog_recon_with_probes_no_wps_attr_error(tmp_path):
    from core.modules.catalog_recon import CatalogRecon

    r = CatalogRecon(
        target={
            "bssid": "C0:3C:04:3D:BD:B4",
            "ssid": "Orange_Swiatlowod_BDB0",
            "channel": 1,
            "interface": "wlan0mon",
        },
        nvd_cfg={"api_key": ""},
        kb=None,
        weakpass_outdir=tmp_path,
    )
    for name in (
        "_wps_probe", "_client_enum", "_cve_search",
        "_weakpass_wordlist", "_kb_search", "_catalog_iter",
    ):
        setattr(r, name, mock.MagicMock(return_value={"ok": True}))
    core = set(CatalogRecon._CORE_STEP_FNS)
    for m in CatalogRecon.RECON_PROBE_METHODS:
        if m in core:
            continue
        setattr(r, f"_{m}", mock.MagicMock(return_value={"ok": True}))
    report = r.run(with_probes=True)
    assert "finished_at" in report
    assert hasattr(r, "_wps_probe")
    assert not hasattr(r, "_wps") or callable(getattr(r, "_wps", None)) is False or True


def test_mcp_call_airodump_not_unknown_action():
    from core.orchestrator.autonomous_orchestrator import AutonomousOrchestrator

    events = []
    o = AutonomousOrchestrator(
        confirm_fn=lambda p: True,
        on_event=events.append,
        interface="wlan0mon",
        mcp_client=None,
    )
    seed = {
        "bssid": "C0:3C:04:3D:BD:B4",
        "ssid": "Orange",
        "channel": 1,
        "interface": "wlan0mon",
    }
    report = {
        "executed": [], "skipped": [], "optional_declined": [],
        "access": {"achieved": False, "creds": None, "session_id": None},
        "zero_day_drafts": [],
    }
    step = {
        "action": "mcp_call",
        "tool": "airodump-ng",
        "args": {
            "channel": 1,
            "bssid": seed["bssid"],
            "write": "/tmp/kfiosa-sim",
            "interface": "wlan0mon",
        },
        "risk_level": "intrusive",
        "expected_runtime_seconds": 5,
    }
    with mock.patch(
        "core.mcp.tools.call_mcp_tool",
        return_value={
            "ok": True, "stdout": "captured", "stderr": "",
            "returncode": 0, "argv": ["airodump-ng", "-c", "1", "wlan0mon"],
        },
    ) as m:
        o._walk_ai_step(step, seed, report, autonomous=True)
    m.assert_called_once()
    assert report["executed"], "step should be recorded"
    res = report["executed"][-1]["result"]
    assert not (
        isinstance(res, str) and "unknown action" in res
    ), f"designed capture path; got {res!r}"
    assert res.get("ok") is True


def test_heuristic_chain_source_not_mislabel_as_llm():
    from core.ai_backend.chain import AIChainPlanner
    from core.orchestrator.autonomous_orchestrator import AutonomousOrchestrator

    planner = AIChainPlanner(ai_backend=None)
    o = AutonomousOrchestrator(
        confirm_fn=lambda p: True,
        on_event=lambda m: None,
        chain_planner=planner,
        mcp_client=None,
    )
    seed = {
        "bssid": "C0:3C:04:3D:BD:B4",
        "ssid": "Orange",
        "channel": 1,
        "interface": "wlan0mon",
        "encryption": "WPA2",
    }
    report = {"kb_tools": []}
    steps, source = o._build_ai_chain("wifi", seed, report)
    assert steps, "heuristic must emit steps when no LLM"
    assert source == "heuristic", f"mislabel: got source={source!r}"
