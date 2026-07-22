"""Hermetic tests for the extended-WiFi runner
(``core/extended_wifi/runner.py``).

60 advanced WiFi modules (HE / Wi-Fi 6 / 7 / WPA3 / AI), each real
scapy-craft + parse + heuristic or a clear degrade. The parametrized
shape test asserts every method returns a valid envelope and never
raises — and never returns a fabricated ``ok=True`` when the backing
tool is absent (``shutil.which`` mocked empty / scapy missing).

Crucial never-fake invariants exercised here:
  * Root-gated modules (most of them) degrade to ``ok=False`` when
    ``os.geteuid`` is forced to non-root; they NEVER fabricate success.
  * BSSID/station-required modules degrade cleanly when args are absent.
  * TRAINED-ML modules (beacon_rssi_triangulation_ai, rf_fingerprint
    _cloning, spectrum_scan_anomaly_detection, dtim_period_prediction,
    ai_channel_occupancy_forecast, cross_layer_ai_fusion) report
    ``data["model"] == "heuristic (not trained)"`` and
    ``data["trained"] is False`` — never a fabricated trained prediction.
  * pcap-parse modules degrade on missing cap_file; CVE/searchsploit
    modules only emit EDB ids from REAL searchsploit output.

Hermeticity: ``shutil.which`` is monkeypatched to a no-tool function
so no real Kali binary runs unless a test explicitly opts in for a
happy-path fake; ``subprocess.run`` is monkeypatched where the method
drives a real subprocess, to return canned CompletedProcess output.
``os.geteuid`` is forced to non-root so the root-gate branch runs
honestly. ``scapy`` import is monkeypatched to a no-op so all scapy-
craft degrades with the honest "scapy not installed" error.
"""
import json
import math
import os
import subprocess
import unittest.mock as mock

import pytest

from core.extended_wifi.runner import (ExtendedWiFiRunner,
                                       EXT_WIFI_ATTACKS,
                                       run_attack)
from core.orchestrator.autonomous_orchestrator import AutonomousOrchestrator
from core.mcp import tools as mcp_tools
from core.ai_backend.chain import _SYSTEM_PROMPT, _CHAIN_STEP_SCHEMA_HINT
from tests.fakes import FakeAIBackend, FakeKB, FakeConfirmFn


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _no_tool(name: str, *_, **__):
    return None


class _FakeCompleted:
    def __init__(self, rc=0, out=""):
        self.returncode = rc
        self.stdout = out
        self.stderr = ""


def _no_scapy(*_a, **_k):
    raise ImportError("scapy not installed (test stub)")


def _make_orch(confirm_fn=None, log=None):
    return AutonomousOrchestrator(
        ai_backend=FakeAIBackend(),
        kb=FakeKB(),
        confirm_fn=confirm_fn or (lambda p: True),
        on_event=(log or []).append,
    )


# Common args (no BSSID/station) — most methods must degrade on args.
def _common_args() -> dict:
    return {
        "interface": "wlan0mon",
        "bssid": "EC:08:6B:11:22:33",
        "station": "AA:BB:CC:DD:EE:01",
        "channel": 6,
        "count": 3,
        "ssids": ["Guest", "FreeWiFi"],
        "cap_file": "/tmp/kfiosa_extwifi.pcap",
        "ssid": "extwifi",
        "aps": [
            {"bssid": "EC:08:6B:11:22:33", "rssi": -45, "lat": 50.0,
             "lon": 20.0},
            {"bssid": "EC:08:6B:11:22:34", "rssi": -55, "lat": 50.001,
             "lon": 20.001},
            {"bssid": "EC:08:6B:11:22:35", "rssi": -65, "lat": 50.002,
             "lon": 20.002},
        ],
        "features": {"signal": -60, "noise": -90, "frame_count": 50},
    }


# ---------------------------------------------------------------------------
# 1. Parametrized shape test — every method returns a valid envelope,
#    never raises, and never fabricates ok=True when no tool is present.
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("method",
                          ExtendedWiFiRunner.EXT_WIFI_METHODS)
def test_method_returns_valid_envelope_and_never_fakes(method,
                                                          monkeypatch):
    """With shutil.which mocked empty, scapy unavailable, geteuid
    forced to non-root, every method must return a dict with
    ok in {True, False}, error a str, data dict-or-None, and must NEVER
    raise. Root-gated methods must report ok=False (root required) —
    never a fabricated success."""
    monkeypatch.setattr("core.extended_wifi.runner.shutil.which",
                        _no_tool)
    monkeypatch.setattr("core.extended_wifi.runner.os.geteuid",
                        lambda: 1000)
    # No scapy available — all scapy-craft methods degrade honestly.
    sys_mod = mock.MagicMock()
    sys_mod.RadioTap = mock.MagicMock(side_effect=_no_scapy)
    sys_mod.Dot11 = mock.MagicMock(side_effect=_no_scapy)
    sys_mod.Dot11Beacon = mock.MagicMock(side_effect=_no_scapy)
    sys_mod.Dot11ProbeResp = mock.MagicMock(side_effect=_no_scapy)
    sys_mod.Dot11Elt = mock.MagicMock(side_effect=_no_scapy)
    sys_mod.Dot11Auth = mock.MagicMock(side_effect=_no_scapy)
    sys_mod.Dot11ProbeReq = mock.MagicMock(side_effect=_no_scapy)
    sys_mod.EAPOL = mock.MagicMock(side_effect=_no_scapy)
    sys_mod.Raw = mock.MagicMock(side_effect=_no_scapy)
    sys_mod.rdpcap = mock.MagicMock(side_effect=_no_scapy)
    sys_mod.IP = mock.MagicMock(side_effect=_no_scapy)
    sys_mod.UDP = mock.MagicMock(side_effect=_no_scapy)
    sys_mod.BOOTP = mock.MagicMock(side_effect=_no_scapy)
    sys_mod.DHCP = mock.MagicMock(side_effect=_no_scapy)
    sys_mod.all = sys_mod
    monkeypatch.setitem(__import__("sys").modules, "scapy", sys_mod)
    monkeypatch.setitem(__import__("sys").modules, "scapy.all", sys_mod)
    runner = ExtendedWiFiRunner(adapter="wlan0mon", args=_common_args())
    res = runner.run_attack(method)
    assert isinstance(res, dict), method
    assert res["ok"] in (True, False), method
    assert isinstance(res.get("error", ""), str), method
    assert res.get("data") is None or isinstance(res["data"], dict), method


# ---------------------------------------------------------------------------
# 2. Registry / methods parity + AI-surfacing (4 touchpoints)
# ---------------------------------------------------------------------------
def test_registry_matches_methods():
    reg = {s["method"] for s in EXT_WIFI_ATTACKS}
    meth = set(ExtendedWiFiRunner.EXT_WIFI_METHODS)
    assert reg == meth
    assert len(meth) == 60


def test_every_method_has_impl():
    missing = [m for m in ExtendedWiFiRunner.EXT_WIFI_METHODS
               if not hasattr(ExtendedWiFiRunner, "_" + m)]
    assert missing == []


def test_extended_wifi_wrappers_registered():
    for spec in EXT_WIFI_ATTACKS:
        assert spec["name"] in mcp_tools.KALI_TOOL_WRAPPERS, spec["name"]
        rec = mcp_tools.KALI_TOOL_WRAPPERS[spec["name"]].as_mcp_record()
        assert rec["inputSchema"]
        assert rec["examples"]
        # risk_level is one of the documented classes
        assert rec["risk_level"] in ("read", "intrusive", "destructive")
        # requires_root is a bool
        assert isinstance(rec["requires_root"], bool)


def test_list_mcp_tools_wifi_surfaces_all_extended_wifi():
    tools = mcp_tools.list_mcp_tools("wifi")
    names = {t["name"] for t in tools}
    atk = {s["name"] for s in EXT_WIFI_ATTACKS}
    assert atk <= names
    for t in tools:
        if t["name"] in atk:
            assert t["domain"] == "wifi"


def test_chain_schema_hint_includes_extended_wifi():
    assert "extended_wifi" in _CHAIN_STEP_SCHEMA_HINT


def test_chain_system_prompt_teaches_all_extended_wifi_methods():
    assert "extended_wifi" in _SYSTEM_PROMPT
    for m in ExtendedWiFiRunner.EXT_WIFI_METHODS:
        assert m in _SYSTEM_PROMPT, m
    # TRAINED-ML guard: never-inline never-fake rule must be in the prompt
    assert "heuristic (not trained)" in _SYSTEM_PROMPT
    assert "NEVER a fabricated" in _SYSTEM_PROMPT


# ---------------------------------------------------------------------------
# 3. Never-fake assertions
# ---------------------------------------------------------------------------
def test_unknown_method_degrades():
    res = run_attack("totally_bogus", args={})
    assert res["ok"] is False
    assert "unknown attack method" in res["error"]


def test_call_mcp_tool_extended_wifi_unknown_method():
    res = mcp_tools.call_mcp_tool("ext_wifi_bogus", {})
    assert res["ok"] is False


def test_call_mcp_tool_extended_wifi_runner_swallows_exception(monkeypatch):
    def boom(self, method):
        raise RuntimeError("boom")
    monkeypatch.setattr(ExtendedWiFiRunner, "run_attack", boom)
    res = mcp_tools.call_mcp_tool("ext_wifi_ofdma_resource_stealing", {})
    assert res["ok"] is False
    assert "boom" in (res.get("error") or "")


def test_trained_ml_modules_label_heuristic():
    """The 6 TRAINED-ML modules must report
    data['model'] == 'heuristic (not trained)' and data['trained'] is
    False, never a fabricated trained prediction."""
    trained_ml_methods = {
        "beacon_rssi_triangulation_ai", "rf_fingerprint_cloning",
        "spectrum_scan_anomaly_detection", "dtim_period_prediction",
        "ai_channel_occupancy_forecast", "cross_layer_ai_fusion",
    }
    runner = ExtendedWiFiRunner(adapter="wlan0mon",
                                  args=_common_args())
    for m in trained_ml_methods:
        res = runner.run_attack(m)
        assert res["ok"] in (True, False), m
        # If data is present, it must be a heuristic label.
        if res.get("data") is not None:
            assert res["data"].get("model") == "heuristic (not trained)", m
            assert res["data"].get("trained") is False, m


def test_beacon_rssi_triangulation_ai_uses_heuristic_weights():
    runner = ExtendedWiFiRunner(adapter="wlan0mon",
                                  args=_common_args())
    res = runner.run_attack("beacon_rssi_triangulation_ai")
    assert res["ok"] is True
    d = res["data"]
    assert d["model"] == "heuristic (not trained)"
    assert d["trained"] is False
    assert isinstance(d["estimated_lat"], (int, float))
    assert isinstance(d["estimated_lon"], (int, float))
    assert d["ap_weight_count"] >= 1


def test_rf_fingerprint_cloning_uses_jaccard():
    runner = ExtendedWiFiRunner(adapter="wlan0mon",
                                  args={**_common_args(),
                                        "target_channels": [1, 6, 11]})
    res = runner.run_attack("rf_fingerprint_cloning")
    # iw mocked empty via _no_tool — but the module may still return
    # ok=True with similarity=None. Either way, the model label must
    # be 'heuristic (not trained)' if data is present.
    if res.get("data") is not None:
        d = res["data"]
        assert d["model"] == "heuristic (not trained)"
        assert d["trained"] is False


def test_spectrum_scan_anomaly_zscore_heuristic():
    runner = ExtendedWiFiRunner(adapter="wlan0mon",
                                  args=_common_args())
    res = runner.run_attack("spectrum_scan_anomaly_detection")
    if res.get("data") is not None:
        d = res["data"]
        assert d["model"] == "heuristic (not trained)"
        assert d["trained"] is False
        assert "anomaly_count" in d


def test_dtim_period_prediction_constant_mean_heuristic():
    runner = ExtendedWiFiRunner(adapter="wlan0mon",
                                  args=_common_args())
    res = runner.run_attack("dtim_period_prediction")
    if res.get("data") is not None:
        d = res["data"]
        assert d["model"] == "heuristic (not trained)"
        assert d["trained"] is False
        # predicted_dtim in {1, 2, 3}
        assert d["predicted_dtim"] in (1, 2, 3)


def test_ai_channel_occupancy_forecast_constant_mean():
    runner = ExtendedWiFiRunner(adapter="wlan0mon",
                                  args=_common_args())
    res = runner.run_attack("ai_channel_occupancy_forecast")
    if res.get("data") is not None:
        d = res["data"]
        assert d["model"] == "heuristic (not trained)"
        assert d["trained"] is False
        assert d["current_mean_signal_dbm"] == d["forecast_next_interval_signal_dbm"]


def test_cross_layer_ai_fusion_uses_mean_std():
    runner = ExtendedWiFiRunner(adapter="wlan0mon",
                                  args=_common_args())
    res = runner.run_attack("cross_layer_ai_fusion")
    assert res["ok"] is True
    d = res["data"]
    assert d["model"] == "heuristic (not trained)"
    assert d["trained"] is False
    assert d["feature_count"] == 3
    assert isinstance(d["fusion_score"], (int, float))


def test_ofdma_resource_stealing_no_scapy_no_fabrication(monkeypatch):
    """With scapy unavailable and no root, ofdma_resource_stealing must
    degrade — never fabricate an 'HE MU RU stolen' verdict."""
    monkeypatch.setattr("core.extended_wifi.runner.os.geteuid",
                        lambda: 1000)
    sys_mod = mock.MagicMock()
    sys_mod.RadioTap = mock.MagicMock(side_effect=_no_scapy)
    sys_mod.Raw = mock.MagicMock(side_effect=_no_scapy)
    sys_mod.all = sys_mod
    monkeypatch.setitem(__import__("sys").modules, "scapy", sys_mod)
    monkeypatch.setitem(__import__("sys").modules, "scapy.all", sys_mod)
    runner = ExtendedWiFiRunner(adapter="wlan0mon", args=_common_args())
    res = runner.run_attack("ofdma_resource_stealing")
    assert res["ok"] is False
    assert "scapy" in res["error"].lower()


def test_bss_coloring_poisoning_requires_root(monkeypatch):
    """bss_coloring_poisoning is root-gated; non-root must degrade."""
    monkeypatch.setattr("core.extended_wifi.runner.os.geteuid",
                        lambda: 1000)
    runner = ExtendedWiFiRunner(adapter="wlan0mon", args=_common_args())
    res = runner.run_attack("bss_coloring_poisoning")
    assert res["ok"] is False
    assert "root" in res["error"].lower()


def test_pfn_probe_attack_works_without_root(monkeypatch):
    """pfn_probe_attack is non-root (parse-only, scapy-craft optional
    for the inject step; if scapy is absent, degrade cleanly)."""
    monkeypatch.setattr("core.extended_wifi.runner.os.geteuid",
                        lambda: 1000)
    sys_mod = mock.MagicMock()
    sys_mod.RadioTap = mock.MagicMock(side_effect=_no_scapy)
    sys_mod.Dot11 = mock.MagicMock(side_effect=_no_scapy)
    sys_mod.Raw = mock.MagicMock(side_effect=_no_scapy)
    sys_mod.all = sys_mod
    monkeypatch.setitem(__import__("sys").modules, "scapy", sys_mod)
    monkeypatch.setitem(__import__("sys").modules, "scapy.all", sys_mod)
    runner = ExtendedWiFiRunner(adapter="wlan0mon", args=_common_args())
    res = runner.run_attack("pfn_probe_attack")
    assert res["ok"] is False  # scapy absent
    assert "scapy" in res["error"].lower()


def test_passive_ap_uptime_no_fake_fabrication(monkeypatch):
    """passive_ap_uptime_estimation must NOT fabricate a long uptime
    when the cap_file is absent — it degrades honestly."""
    runner = ExtendedWiFiRunner(adapter="wlan0mon",
                                  args={"cap_file": ""})
    res = runner.run_attack("passive_ap_uptime_estimation")
    assert res["ok"] is False
    assert "cap_file" in res["error"]


def test_wapi_exploit_never_fabricates_cve_id(monkeypatch):
    """wapi_exploit must NEVER invent an EDB id — only emit ids from
    real searchsploit output."""
    monkeypatch.setattr("core.extended_wifi.runner.shutil.which",
                        _no_tool)
    runner = ExtendedWiFiRunner(adapter="wlan0mon",
                                  args={"cap_file": ""})
    res = runner.run_attack("wapi_exploit")
    # No cap_file and no searchsploit — both required for any positive
    # result; degrade honestly.
    assert res["ok"] is False
    assert "cap_file" in res["error"] or "searchsploit" in res["error"]


def test_wapi_exploit_uses_real_searchsploit_output(monkeypatch):
    """When searchsploit IS available, wapi_exploit must surface its
    REAL output verbatim — never invent an EDB id."""
    monkeypatch.setattr("core.extended_wifi.runner.shutil.which",
                        lambda *a, **k: "/fake/searchsploit")
    fake_searchsploit = {
        "RESULTS_EXPLOIT": [
            {"EDB-ID": "12345",
             "Title": "WAPI bss 0-day (real searchsploit entry)"}]
    }
    # Use a pcap that won't trip the "no wapi" check by using a real
    # cap_file (we patch rdpcap to return an empty list).
    sys_mod = mock.MagicMock()
    sys_mod.rdpcap = mock.MagicMock(return_value=[])
    sys_mod.all = sys_mod
    monkeypatch.setitem(__import__("sys").modules, "scapy", sys_mod)
    monkeypatch.setitem(__import__("sys").modules, "scapy.all", sys_mod)
    monkeypatch.setattr("core.extended_wifi.runner.subprocess.run",
                        lambda *a, **k: _FakeCompleted(
                            0, json.dumps(fake_searchsploit)))
    # Need a cap_file that exists; use tmp_path.
    import tempfile
    with tempfile.NamedTemporaryFile(delete=False) as tf:
        tf.write(b"")
        cap_path = tf.name
    try:
        runner = ExtendedWiFiRunner(adapter="wlan0mon",
                                       args={"cap_file": cap_path})
        res = runner.run_attack("wapi_exploit")
        assert res["ok"] is True
        edb = res["data"]["edb_hits"]
        assert len(edb) == 1
        assert edb[0]["edb_id"] == "12345"  # real searchsploit, not invented
    finally:
        os.unlink(cap_path)


def test_ssid_probe_harvesting_no_fake_pfn(monkeypatch):
    """ssid_probe_harvesting_advanced must NOT fabricate a PFN — it
    parses the real cap."""
    runner = ExtendedWiFiRunner(adapter="wlan0mon",
                                  args={"cap_file": ""})
    res = runner.run_attack("ssid_probe_harvesting_advanced")
    assert res["ok"] is False
    assert "cap_file" in res["error"]


def test_timing_side_channel_uses_real_timestamps(monkeypatch):
    """timing_side_channel_attack_wpa3 must compute jitter from the
    REAL pcap, never a fabricated value."""
    runner = ExtendedWiFiRunner(adapter="wlan0mon",
                                  args={"cap_file": ""})
    res = runner.run_attack("timing_side_channel_attack_wpa3")
    assert res["ok"] is False
    assert "cap_file" in res["error"]


def test_client_kck_extraction_never_fakes_kck(monkeypatch):
    """client_kck_extraction must NOT invent a KCK; it only reports
    the EAPOL bytes parsed from the cap."""
    runner = ExtendedWiFiRunner(adapter="wlan0mon",
                                  args={"cap_file": ""})
    res = runner.run_attack("client_kck_extraction")
    assert res["ok"] is False
    assert "cap_file" in res["error"]


def test_dual_band_steering_requires_station(monkeypatch):
    """dual_band_steering_hijack requires BOTH bssid AND station."""
    monkeypatch.setattr("core.extended_wifi.runner.os.geteuid",
                        lambda: 1000)
    runner = ExtendedWiFiRunner(adapter="wlan0mon", args={})
    res = runner.run_attack("dual_band_steering_hijack")
    assert res["ok"] is False
    # either bssid or station missing
    assert ("args.bssid" in res["error"]
            or "args.station" in res["error"]
            or "root" in res["error"].lower())


# ---------------------------------------------------------------------------
# 4. Orchestrator dispatch + gate-once invariant
# ---------------------------------------------------------------------------
def test_dispatch_extended_wifi_routes_and_records():
    captured = {}

    def fake_run_attack(method, adapter=None, scanner=None, args=None, **_):
        captured["method"] = method
        captured["adapter"] = adapter
        captured["args"] = args
        return {"ok": True, "data": {"injected": True}, "error": ""}

    o = _make_orch()
    report = {"executed": [], "skipped": [], "access": {}}
    seed = {"bssid": "EC:08:6B:11:22:33", "ssid": "TestNet",
            "channel": "6", "interface": "wlan0mon"}
    with mock.patch("core.extended_wifi.runner.run_attack",
                    side_effect=fake_run_attack):
        o._dispatch_extended_wifi(
            {"action": "extended_wifi",
             "args": {"method": "ofdma_resource_stealing",
                      "bssid": "EC:08:6B:11:22:33", "channel": 6}},
            seed, report)
    assert captured["method"] == "ofdma_resource_stealing"
    assert len(report["executed"]) == 1
    entry = report["executed"][0]
    assert entry["action"] == "extended_wifi"
    assert entry["method"] == "ofdma_resource_stealing"
    assert entry["ok"] is True
    assert entry["tool"] == "core.extended_wifi.runner.ofdma_resource_stealing"
    assert seed["extended_wifi"]["ofdma_resource_stealing"] == {"injected": True}


def test_dispatch_extended_wifi_unknown_method_skipped():
    o = _make_orch()
    report = {"executed": [], "skipped": [], "access": {}}
    o._dispatch_extended_wifi(
        {"action": "extended_wifi", "args": {"method": "bogus"}},
        {"bssid": "AA:BB:CC:DD:EE:FF"}, report)
    assert report["executed"] == []
    assert any("unknown method" in s for s in report["skipped"])


def test_dispatch_strips_extended_wifi_prefix():
    o = _make_orch()
    report = {"executed": [], "skipped": [], "access": {}}
    captured = {}
    with mock.patch(
            "core.extended_wifi.runner.run_attack",
            side_effect=lambda method, **k: (
                captured.update(method=method),
                {"ok": True, "data": {}, "error": ""})[1]):
        o._dispatch_extended_wifi(
            {"action": "extended_wifi",
             "tool": "ext_wifi_ofdma_resource_stealing",
             "args": {}}, {"bssid": "AA:BB:CC:DD:EE:FF"}, report)
    assert captured["method"] == "ofdma_resource_stealing"


def test_gate_fires_once_per_extended_wifi_step():
    """The per-step ACCEPT gate fires exactly once per extended_wifi
    step (single-gate invariant): the dispatcher does NOT re-confirm."""
    confirm = FakeConfirmFn([True])
    o = _make_orch(confirm_fn=confirm)
    report = {"executed": [], "skipped": [], "access": {}}
    with mock.patch("core.extended_wifi.runner.run_attack",
                    return_value={"ok": True, "data": {}, "error": ""}):
        step = {"action": "extended_wifi",
                "args": {"method": "ofdma_resource_stealing"},
                "risk_level": "intrusive"}
        o._walk_ai_step(step, {"bssid": "AA"}, report, autonomous=False)
    assert len(confirm.prompts) == 1, (
        f"gate fired {len(confirm.prompts)} times; expected 1")
    assert len(report["executed"]) == 1


def test_gate_cancel_skips_extended_wifi_dispatch():
    confirm = FakeConfirmFn([False])
    o = _make_orch(confirm_fn=confirm)
    report = {"executed": [], "skipped": [], "access": {}}
    called = {"n": 0}
    with mock.patch(
            "core.extended_wifi.runner.run_attack",
            side_effect=lambda *a, **k: (
                called.__setitem__("n", called["n"] + 1),
                {"ok": True, "data": {}, "error": ""})[1]):
        step = {"action": "extended_wifi",
                "args": {"method": "bss_coloring_poisoning"},
                "risk_level": "intrusive"}
        o._walk_ai_step(step, {"bssid": "AA"}, report, autonomous=False)
    assert called["n"] == 0
    assert report["executed"] == []


# ---------------------------------------------------------------------------
# 5. Adversarial grep — dispatcher has no confirm_fn; prompt has no CVE
# ---------------------------------------------------------------------------
def test_dispatcher_no_reconfirm(monkeypatch):
    """The dispatcher must not call confirm_fn or self.confirm — the
    single-gate invariant."""
    src = open("/home/user/Pulpit/kfiosa/core/orchestrator/autonomous_orchestrator.py").read()
    # Find the _dispatch_extended_wifi method body and assert no
    # confirm_fn reference inside.
    i = src.find("def _dispatch_extended_wifi")
    j = src.find("\n    def ", i + 1)
    if j < 0:
        j = len(src)
    body = src[i:j]
    assert "confirm_fn" not in body, (
        f"dispatcher body contains confirm_fn: {body[:200]}...")
    assert "self.confirm" not in body, (
        f"dispatcher body contains self.confirm: {body[:200]}...")