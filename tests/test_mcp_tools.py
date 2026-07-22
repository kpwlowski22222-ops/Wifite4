"""core.mcp.tools — Kali / mt7921e / cve_lookup MCP wrappers.

These tests exercise:
  - the registry of public tool records (list_mcp_tools, get_mcp_tool),
  - the schema shape (JSON Schema + risk_level + requires_root),
  - the call_mcp_tool dispatch + a fake-subprocess happy path,
  - CVE lookup when no NVD key is configured (graceful no-op).
"""

import json
import sys
import types
from typing import Any, Dict, List
from unittest import mock

import pytest

from core.mcp import tools as mcp_tools


# ----------------------------------------------------------------------
# list_mcp_tools / get_mcp_tool
# ----------------------------------------------------------------------

EXPECTED_KALI_NAMES = {
    "airodump-ng", "aireplay-ng", "aircrack-ng",
    "wash", "reaver", "nmap", "hashcat", "msfconsole",
}
EXPECTED_MT7921E_NAMES = {
    "mt7921e.detect", "mt7921e.test_injection",
    "mt7921e.set_channel", "mt7921e.set_txpower", "mt7921e.inject_frame",
}


def test_list_mcp_tools_returns_full_registry():
    records = mcp_tools.list_mcp_tools()
    names = {r["name"] for r in records}
    assert EXPECTED_KALI_NAMES.issubset(names), (
        f"missing Kali tools: {EXPECTED_KALI_NAMES - names}"
    )
    assert EXPECTED_MT7921E_NAMES.issubset(names), (
        f"missing mt7921e tools: {EXPECTED_MT7921E_NAMES - names}"
    )
    assert "cve_lookup" in names


def test_list_mcp_tools_filter_by_domain_wifi():
    records = mcp_tools.list_mcp_tools(domain="wifi")
    names = {r["name"] for r in records}
    # airodump-ng is wifi
    assert "airodump-ng" in names
    # hashcat is under password (not wifi)
    assert "hashcat" not in names


def test_get_mcp_tool_returns_schema_for_airodump():
    rec = mcp_tools.get_mcp_tool("airodump-ng")
    assert rec is not None
    assert rec["name"] == "airodump-ng"
    assert "description" in rec
    assert "inputSchema" in rec
    assert rec["inputSchema"]["type"] == "object"
    assert "interface" in rec["inputSchema"]["properties"]
    assert "interface" in rec["inputSchema"]["required"]
    assert rec["requires_root"] is True
    assert rec["risk_level"] in ("read", "intrusive", "destructive")


def test_get_mcp_tool_returns_schema_for_mt7921e_test_injection():
    rec = mcp_tools.get_mcp_tool("mt7921e.test_injection")
    assert rec is not None
    assert "iface" in rec["inputSchema"]["properties"]
    assert "iface" in rec["inputSchema"]["required"]
    assert rec["requires_root"] is True
    # Examples are surfaced for the AI to learn from.
    assert isinstance(rec.get("examples"), list) and rec["examples"]


def test_get_mcp_tool_returns_schema_for_cve_lookup():
    rec = mcp_tools.get_mcp_tool("cve_lookup")
    assert rec is not None
    # The cve_lookup wrapper takes a keyword (and optional limit) —
    # NVD CPE search params are not all surfaced at this layer.
    assert "keyword" in rec["inputSchema"]["properties"]
    assert "keyword" in rec["inputSchema"]["required"]
    # CVE lookup is read-only.
    assert rec["risk_level"] == "read"


def test_get_mcp_tool_returns_none_for_unknown():
    assert mcp_tools.get_mcp_tool("definitely-not-a-real-tool") is None


# ----------------------------------------------------------------------
# call_mcp_tool dispatch
# ----------------------------------------------------------------------

def test_call_mcp_tool_unknown_returns_error():
    res = mcp_tools.call_mcp_tool("nope", {})
    assert res.get("ok") is False
    assert "unknown" in res.get("error", "").lower() or \
           "not found" in res.get("error", "").lower()


def test_call_mcp_tool_dispatches_to_runner():
    """The airodump wrapper's runner is what actually invokes
    airodump-ng. We mock the wrapper to confirm dispatch."""
    fake = mcp_tools.KALI_TOOL_WRAPPERS["airodump-ng"]
    with mock.patch.object(fake, "run", return_value={
        "ok": True, "stdout": "fake capture", "stderr": "", "returncode": 0,
    }) as fake_run:
        res = mcp_tools.call_mcp_tool("airodump-ng", {
            "channel": 6, "bssid": "AA:BB:CC:DD:EE:01",
            "interface": "wlan0mon",
        })
    assert res["ok"] is True
    assert res["stdout"] == "fake capture"
    # The wrapper received the args verbatim.
    fake_run.assert_called_once()
    call_args = fake_run.call_args
    # call_args.args == (args_dict, timeout) per call_mcp_tool's signature
    assert call_args.args[0]["channel"] == 6
    assert call_args.args[0]["bssid"] == "AA:BB:CC:DD:EE:01"


def test_call_mcp_tool_mt7921e_detect_dispatches():
    """mt7921e.detect goes through its own wrapper. Mock the runner."""
    fake = mcp_tools.KALI_TOOL_WRAPPERS["mt7921e.detect"]
    with mock.patch.object(fake, "run", return_value={
        "ok": True, "stdout": "[]", "stderr": "", "returncode": 0,
    }) as fake_run:
        res = mcp_tools.call_mcp_tool("mt7921e.detect", {})
    assert res["ok"] is True
    fake_run.assert_called_once()


def test_call_mcp_tool_propagates_runner_exception():
    """If the wrapper's run() raises, call_mcp_tool surfaces the
    exception (so the caller can fall back). The wrapper's run
    catches subprocess errors but lets RuntimeError through."""
    fake = mcp_tools.KALI_TOOL_WRAPPERS["nmap"]
    with mock.patch.object(fake, "run", side_effect=RuntimeError("boom")):
        with pytest.raises(RuntimeError) as e:
            mcp_tools.call_mcp_tool("nmap", {})
    assert "boom" in str(e.value)


# ----------------------------------------------------------------------
# KaliToolWrapper.as_mcp_record
# ----------------------------------------------------------------------

def test_kali_tool_wrapper_as_mcp_record_shape():
    w = mcp_tools.KALI_TOOL_WRAPPERS["airodump-ng"]
    rec = w.as_mcp_record()
    # Must be a JSON-serializable dict with the canonical MCP fields.
    json.dumps(rec)
    for key in ("name", "description", "inputSchema"):
        assert key in rec, f"missing {key}"
    # Required + properties must be present.
    assert rec["inputSchema"]["type"] == "object"
    assert "properties" in rec["inputSchema"]


def test_kali_tool_wrapper_examples_contain_actual_command():
    """The AI learns from `examples`; they should look like real
    invocations (binary name first)."""
    w = mcp_tools.KALI_TOOL_WRAPPERS["airodump-ng"]
    rec = w.as_mcp_record()
    assert any("airodump-ng" in ex for ex in rec["examples"])


def test_kali_tool_wrapper_risk_levels_valid():
    valid = {"read", "intrusive", "destructive"}
    for name, w in mcp_tools.KALI_TOOL_WRAPPERS.items():
        rec = w.as_mcp_record()
        assert rec["risk_level"] in valid, (
            f"{name} has invalid risk_level={rec['risk_level']}"
        )


# ----------------------------------------------------------------------
# CVE lookup: graceful when no NVD key
# ----------------------------------------------------------------------

def test_cve_lookup_no_nvd_key_returns_graceful_error():
    """When the operator has no NVD key configured, cve_lookup
    returns ok=False with a hint (not a traceback). The chain
    planner treats this as 'no CVE data' and continues."""
    import os
    saved = os.environ.pop("NVD_API_KEY", None)
    try:
        with mock.patch("core.ai_backend.get_nvd_key", return_value=""):
            res = mcp_tools.call_mcp_tool("cve_lookup", {"keyword": "TP-Link"})
        assert res.get("ok") is False
        assert "NVD" in res.get("error", "")
        assert "hint" in res
    finally:
        if saved is not None:
            os.environ["NVD_API_KEY"] = saved
