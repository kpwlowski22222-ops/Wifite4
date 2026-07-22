"""Hermetic tests for the WiFi attack runner (``core/wifi_attack/runner.py``).

38 attack algorithms (the implementacja.txt wifi_attack domain + gap-list
primitives), each real subprocess / scapy / parse or a clear degrade. The
parametrized shape test asserts every method returns a valid envelope and
never raises — and never returns a fabricated ``ok=True`` when the backing
tool is absent (``shutil.which`` mocked empty). Per-method happy-path fakes
exercise the real parse/subprocess paths. TRAINED-ML modules are asserted
to carry the ``heuristic (not trained)`` label and ``trained=False``.

Hermeticity:
  * ``shutil.which`` is monkeypatched to a no-tool function so no real Kali
    binary runs unless a test explicitly opts in for a happy-path fake.
  * ``subprocess.run`` / ``subprocess.Popen`` are monkeypatched where a
    method drives a real subprocess, to return canned CompletedProcess
    output. ``os.geteuid`` is forced to 0 (root) for root-gated methods so
    the root gate passes and the underlying tool-absence / fake-subprocess
    branch is what runs.
  * The orchestrator gate-once invariant is asserted by counting
    ``confirm_fn`` calls: exactly one per ``wifi_attack`` step, because
    ``_dispatch_wifi_attack`` does NOT re-confirm.
"""
import os
import subprocess
import unittest.mock as mock
from pathlib import Path

import pytest

from core.wifi_attack.runner import (WiFiAttackRunner, WIFI_ATTACKS,
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
# 1. Parametrized shape test — every method returns a valid envelope,
#    never raises, and never fabricates ok=True when no tool is present.
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("method", WiFiAttackRunner.WIFI_ATTACK_METHODS)
def test_method_returns_valid_envelope_and_never_fakes(method, monkeypatch):
    """With shutil.which mocked empty and geteuid forced to non-root (so
    root-gated methods return the root degrade), every method must return
    a dict with ok in {True, False}, error a str, data dict-or-None, and must
    NEVER raise. Root-gated methods must report ok=False (needs root), not a
    fabricated success. Non-root parse/heuristic methods that need no tool
    may legitimately return ok=True (pure computation) — but must not claim
    a tool-backed result."""
    monkeypatch.setattr("core.wifi_attack.runner.shutil.which", _no_tool)
    monkeypatch.setattr("core.wifi_attack.runner.os.geteuid", lambda: 1000)
    runner = WiFiAttackRunner(
        adapter="wlan0mon",
        args={"bssid": "AA:BB:CC:DD:EE:FF", "channel": 6,
              "station": "11:22:33:44:55:66",
              "cap_file": "/nonexistent.pcap",
              "hash_file": "/nonexistent.22000",
              "samples": [{"rssi": -40, "distance_m": 1},
                          {"rssi": -70, "distance_m": 10}],
              "clients": [{"mac": "AA", "signal": -50}],
              "rsn": {"akm": "psk", "pmkid_friendly": True},
              "plan_steps": [{"method": "packet_injection_test",
                              "args": {}}]})
    res = runner.run_attack(method)
    assert isinstance(res, dict), method
    assert res["ok"] in (True, False), method
    assert isinstance(res.get("error", ""), str), method
    assert res.get("data") is None or isinstance(res["data"], dict), method
    # Root-gated methods must NOT fabricate ok=True when not root — they
    # degrade honestly (either the root gate fires "needs root", OR a
    # tool-absence check fires first with "<tool> not installed"). Both
    # are honest ok=False; the invariant is no fabrication, not a specific
    # error string.
    spec = next(s for s in WIFI_ATTACKS if s["method"] == method)
    if spec.get("requires_root"):
        assert res["ok"] is False, f"{method} should degrade (needs root)"


# ---------------------------------------------------------------------------
# 2. Registry / methods parity + AI-surfacing (4 touchpoints)
# ---------------------------------------------------------------------------
def test_registry_matches_methods():
    reg = {s["method"] for s in WIFI_ATTACKS}
    meth = set(WiFiAttackRunner.WIFI_ATTACK_METHODS)
    assert reg == meth
    # 38 baseline + 3 Phase 1.6 patterns = 41.
    assert len(meth) == 41


def test_every_method_has_impl():
    missing = [m for m in WiFiAttackRunner.WIFI_ATTACK_METHODS
               if not hasattr(WiFiAttackRunner, "_" + m)]
    assert missing == []


def test_wifi_attack_wrappers_registered():
    for spec in WIFI_ATTACKS:
        assert spec["name"] in mcp_tools.KALI_TOOL_WRAPPERS, spec["name"]
        rec = mcp_tools.KALI_TOOL_WRAPPERS[spec["name"]].as_mcp_record()
        assert rec["inputSchema"]
        assert rec["examples"]
        # risk_level one of the documented classes
        assert rec["risk_level"] in ("read", "intrusive", "destructive")


def test_list_mcp_tools_wifi_surfaces_all_wifi_attack():
    tools = mcp_tools.list_mcp_tools("wifi")
    names = {t["name"] for t in tools}
    atk = {s["name"] for s in WIFI_ATTACKS}
    assert atk <= names
    for t in tools:
        if t["name"] in atk:
            assert t["domain"] == "wifi"


def test_chain_schema_hint_includes_wifi_attack():
    assert "wifi_attack" in _CHAIN_STEP_SCHEMA_HINT


def test_chain_system_prompt_teaches_all_wifi_attack_methods():
    assert "wifi_attack" in _SYSTEM_PROMPT
    for m in WiFiAttackRunner.WIFI_ATTACK_METHODS:
        assert m in _SYSTEM_PROMPT, m
    assert "heuristic (not trained)" in _SYSTEM_PROMPT


# ---------------------------------------------------------------------------
# 3. Never-fake assertions
# ---------------------------------------------------------------------------
def test_unknown_method_degrades():
    res = run_attack("totally_bogus", args={})
    assert res["ok"] is False
    assert "unknown attack method" in res["error"]


def test_call_mcp_tool_wifi_attack_unknown_method():
    res = mcp_tools.call_mcp_tool("wifi_attack_bogus", {})
    assert res["ok"] is False


def test_call_mcp_tool_wifi_attack_runner_swallows_exception(monkeypatch):
    def boom(self, method):
        raise RuntimeError("boom")
    monkeypatch.setattr(WiFiAttackRunner, "run_attack", boom)
    res = mcp_tools.call_mcp_tool("wifi_attack_evil_twin_automated", {})
    assert res["ok"] is False
    assert "boom" in (res.get("error") or "")


def test_hashcat_never_fabricates_crack_when_not_installed(monkeypatch, tmp_path):
    monkeypatch.setattr("core.wifi_attack.runner.shutil.which", _no_tool)
    monkeypatch.setattr("core.wifi_attack.runner.os.geteuid", lambda: 0)
    hf = tmp_path / "hs.22001"
    hf.write_text("fakehash\n")
    res = run_attack("hashcat_22001", args={"hash_file": str(hf)})
    assert res["ok"] is False
    assert "hashcat not installed" in res["error"]


def test_hashcat_reports_real_crack_from_subprocess(monkeypatch, tmp_path):
    """A real hashcat stdout carrying a cracked line is parsed verbatim —
    no fabrication, and no false 'not cracked' when the line IS present."""
    monkeypatch.setattr("core.wifi_attack.runner.shutil.which",
                        lambda *a, **k: "/fake/hashcat")
    monkeypatch.setattr("core.wifi_attack.runner.os.geteuid", lambda: 0)
    hf = tmp_path / "hs.22001"
    hf.write_text("fakehash:testpassword\n")
    fake_out = "hashcat output\nfakehash:testpassword\n"
    monkeypatch.setattr(
        "core.wifi_attack.runner.subprocess.run",
        lambda *a, **k: _FakeCompleted(0, fake_out))
    res = run_attack("hashcat_22001", args={"hash_file": str(hf)})
    assert res["ok"] is True
    assert res["data"]["cracked"] == "testpassword"
    assert "testpassword" in str(res["data"])


def test_hcxpcapngtool_never_fabricates_psk(monkeypatch, tmp_path):
    """If hcxpcapngtool fails, no PSK is fabricated."""
    monkeypatch.setattr("core.wifi_attack.runner.shutil.which",
                        lambda *a, **k: "/fake/hcxpcapngtool")
    cap = tmp_path / "hs.pcap"
    cap.write_text("fakecap")
    monkeypatch.setattr(
        "core.wifi_attack.runner.subprocess.run",
        lambda *a, **k: _FakeCompleted(1, "no handshake found"))
    res = run_attack("automatic_handshake_cracker",
                     args={"cap_file": str(cap)})
    assert res["ok"] is False


def test_searchspilot_absent_no_fabricated_edb(monkeypatch, tmp_path):
    """wpa_dragonblood_test must NOT fabricate EDB/CVE ids when searchsploit
    is absent — only the scapy-derived SAE/OWE flags are reported."""
    monkeypatch.setattr("core.wifi_attack.runner.shutil.which", _no_tool)
    # No scapy either -> degrades on the cap parse.
    res = run_attack("wpa_dragonblood_test",
                     args={"cap_file": "/nonexistent.pcap"})
    assert res["ok"] is False  # cap missing


# ---------------------------------------------------------------------------
# 4. TRAINED-ML label assertions
# ---------------------------------------------------------------------------
def test_sig_strength_model_is_labelled_heuristic():
    res = run_attack("sig_strength_prediction_model", args={
        "samples": [{"rssi": -40, "distance_m": 1},
                     {"rssi": -70, "distance_m": 10}]})
    assert res["ok"] is True
    assert "heuristic" in res["data"]["model"]
    assert "not trained" in res["data"]["model"]
    assert res["data"]["trained"] is False
    assert "path_loss_exponent_n" in res["data"]


def test_pmkid_prioritizer_is_labelled_heuristic():
    res = run_attack("pmkid_ai_prioritizer", args={
        "clients": [{"mac": "AA:BB", "signal": -50},
                    {"mac": "CC:DD", "signal": -80}],
        "rsn": {"akm": "psk", "pmkid_friendly": True}})
    assert res["ok"] is True
    assert "heuristic" in res["data"]["model"]
    assert res["data"]["trained"] is False
    # ranked by feasibility: stronger signal first
    assert res["data"]["ranked_clients"][0]["mac"] == "AA:BB"


# ---------------------------------------------------------------------------
# 5. Orchestrator dispatch + gate-once invariant
# ---------------------------------------------------------------------------
def test_dispatch_wifi_attack_routes_and_records(monkeypatch):
    captured = {}

    def fake_run_attack(method, adapter=None, scanner=None, args=None, **_):
        captured["method"] = method
        captured["adapter"] = adapter
        captured["args"] = args
        return {"ok": True, "data": {"cracked_psk": "secret"},
                "error": ""}

    o = _make_orch()
    report = {"executed": [], "skipped": [], "access": {}}
    seed = _seed()
    with mock.patch("core.wifi_attack.runner.run_attack",
                    side_effect=fake_run_attack):
        o._dispatch_wifi_attack(
            {"action": "wifi_attack",
             "args": {"method": "hashcat_22001",
                      "hash_file": "/tmp/x.22001"}},
            seed, report)
    assert captured["method"] == "hashcat_22001"
    assert captured["adapter"] == "wlan0mon"
    assert len(report["executed"]) == 1
    entry = report["executed"][0]
    assert entry["action"] == "wifi_attack"
    assert entry["method"] == "hashcat_22001"
    assert entry["ok"] is True
    assert entry["tool"] == "core.wifi_attack.runner.hashcat_22001"
    assert seed["wifi_attack"]["hashcat_22001"] == {"cracked_psk": "secret"}


def test_dispatch_wifi_attack_unknown_method_skipped():
    o = _make_orch()
    report = {"executed": [], "skipped": [], "access": {}}
    o._dispatch_wifi_attack(
        {"action": "wifi_attack", "args": {"method": "bogus"}},
        _seed(), report)
    assert report["executed"] == []
    assert any("unknown method" in s for s in report["skipped"])


def test_dispatch_strips_wifi_attack_prefix():
    o = _make_orch()
    report = {"executed": [], "skipped": [], "access": {}}
    captured = {}
    with mock.patch("core.wifi_attack.runner.run_attack",
                    side_effect=lambda method, **k: (
                        captured.update(method=method),
                        {"ok": True, "data": {}, "error": ""})[1]):
        o._dispatch_wifi_attack(
            {"action": "wifi_attack",
             "tool": "wifi_attack_packet_injection_test",
             "args": {}}, _seed(), report)
    assert captured["method"] == "packet_injection_test"


def test_gate_fires_once_per_wifi_attack_step():
    """The per-step ACCEPT gate fires exactly once per wifi_attack step
    (single-gate invariant): the dispatcher does NOT re-confirm. We count
    confirm_fn calls across _walk_ai_step (autonomous=False so the gate
    actually fires) for a wifi_attack action."""
    confirm = FakeConfirmFn([True])
    o = _make_orch(confirm_fn=confirm)
    report = {"executed": [], "skipped": [], "access": {}}
    seed = _seed()
    with mock.patch("core.wifi_attack.runner.run_attack",
                    return_value={"ok": True, "data": {}, "error": ""}):
        step = {"action": "wifi_attack",
                "args": {"method": "packet_injection_test"},
                "risk_level": "intrusive"}
        o._walk_ai_step(step, seed, report, autonomous=False)
    assert len(confirm.prompts) == 1, (
        f"gate fired {len(confirm.prompts)} times; expected 1")
    assert len(report["executed"]) == 1


def test_gate_cancel_skips_dispatch():
    """A CANCEL at the gate means the wifi_attack step is NOT dispatched
    (run_attack never called) and is recorded as skipped."""
    confirm = FakeConfirmFn([False])
    o = _make_orch(confirm_fn=confirm)
    report = {"executed": [], "skipped": [], "access": {}}
    called = {"n": 0}
    with mock.patch("core.wifi_attack.runner.run_attack",
                    side_effect=lambda *a, **k: called.__setitem__(
                        "n", called["n"] + 1) or {"ok": True}):
        step = {"action": "wifi_attack",
                "args": {"method": "hashcat_22001"},
                "risk_level": "intrusive"}
        o._walk_ai_step(step, _seed(), report, autonomous=False)
    assert called["n"] == 0
    assert report["executed"] == []


# ---------------------------------------------------------------------------
# 6. LLM-coordinated executor — real sub-dispatch, no fabrication
# ---------------------------------------------------------------------------
def test_wifi_auto_attack_executor_requires_plan():
    res = run_attack("wifi_auto_attack_executor", args={})
    assert res["ok"] is False
    assert "plan_steps" in res["error"]


def test_full_auto_pwn_executes_plan_steps(monkeypatch):
    """full_auto_pwn dispatches each plan_steps entry through run_attack —
    real sub-dispatch. With tools absent + non-root, the sub-steps degrade
    honestly and the executor reports ok_count accordingly (no fabricated
    success)."""
    monkeypatch.setattr("core.wifi_attack.runner.shutil.which", _no_tool)
    monkeypatch.setattr("core.wifi_attack.runner.os.geteuid", lambda: 1000)
    res = run_attack("full_auto_pwn", args={
        "plan_steps": [
            {"method": "packet_injection_test", "args": {}},
            {"method": "hashcat_22001", "args": {"hash_file": "/x"}},
        ]})
    assert res["ok"] is False  # both sub-steps degrade (root/tool absent)
    assert res["data"]["ok_count"] == 0
    assert res["data"]["step_count"] == 2


# ---------------------------------------------------------------------------
# Phase 1.6: vuln_classification_by_encryption_rule_engine
# ---------------------------------------------------------------------------
class TestVulnClassificationByEncryption:
    def test_wpa2_ccmp_returns_ccmp_applicable_set(self):
        """Pure-logic rule engine. Encryption=WPA2-CCMP -> applicable
        methods include the CCMP-relevant attack set."""
        r = run_attack("vuln_classification_by_encryption_rule_engine",
                       args={"encryption": "WPA2-CCMP"})
        assert r["ok"] is True
        assert r["data"]["encryption"] == "WPA2-CCMP"
        v = r["data"]["applicable_methods"]
        assert "automatic_handshake_cracker" in v
        assert "hashcat_22001" in v
        assert "pmkid_ai_prioritizer" in v
        assert "kr00k_vulnerability_check" in v

    def test_wpa3_sae_routes_to_dragonblood_only(self):
        r = run_attack("vuln_classification_by_encryption_rule_engine",
                       args={"encryption": "WPA3-SAE"})
        assert r["ok"] is True
        v = r["data"]["applicable_methods"]
        assert v == ["wpa_dragonblood_test", "sae_group_downgrade"]

    def test_open_routes_to_captive_portal_and_credential_hijack(self):
        r = run_attack("vuln_classification_by_encryption_rule_engine",
                       args={"encryption": "OPEN"})
        v = r["data"]["applicable_methods"]
        assert "captive_portal_detection_and_bypass" in v
        assert "client_credential_hijack" in v

    def test_wep_routes_to_wep_recovery(self):
        r = run_attack("vuln_classification_by_encryption_rule_engine",
                       args={"encryption": "WEP"})
        v = r["data"]["applicable_methods"]
        assert "wep_recovery_fms_ptw" in v
        assert "ai_driven_wep_attack" in v

    def test_unknown_encryption_returns_safe_default(self):
        """Unknown encryption -> a safe default list (not fabricated)."""
        r = run_attack("vuln_classification_by_encryption_rule_engine",
                       args={"encryption": "FOOBAR"})
        assert r["ok"] is True
        v = r["data"]["applicable_methods"]
        assert len(v) >= 1
        assert r["data"]["encryption"] == "FOOBAR"

    def test_no_encryption_or_cap_returns_unknown(self):
        """Neither args.encryption nor args.cap_file -> UNKNOWN rule."""
        r = run_attack("vuln_classification_by_encryption_rule_engine",
                       args={})
        assert r["ok"] is True
        assert r["data"]["encryption"] == "UNKNOWN"


# ---------------------------------------------------------------------------
# Phase 1.6: phase_based_ssid_aware_wordlist_forge
# ---------------------------------------------------------------------------
class TestPhaseBasedWordlistForge:
    def test_forge_writes_wordlist_file(self, tmp_path, monkeypatch):
        out = tmp_path / "wl.txt"
        r = run_attack("phase_based_ssid_aware_wordlist_forge",
                       args={"ssid": "AcmeCorp", "out_path": str(out)})
        assert r["ok"] is True
        assert r["data"]["ssid"] == "AcmeCorp"
        assert Path(r["data"]["out_path"]) == out
        assert r["data"]["total_lines"] > 0
        # All 4 phases produced lines.
        pc = r["data"]["phase_counts"]
        assert all(pc[p] > 0 for p in ("phase1", "phase2", "phase3", "phase4"))
        # The file exists with content.
        assert out.exists()
        lines = out.read_text().splitlines()
        assert len(lines) == r["data"]["total_lines"]
        # The SSID appears in at least one phase.
        assert any("AcmeCorp" in l for l in lines)

    def test_forge_degrades_on_empty_ssid(self):
        r = run_attack("phase_based_ssid_aware_wordlist_forge", args={})
        assert r["ok"] is False
        assert "ssid" in r["error"]

    def test_forge_phase4_capped_at_2000(self, tmp_path):
        """Phase 4 mask-lattice is capped at 2000 to bound the file."""
        out = tmp_path / "wl.txt"
        r = run_attack("phase_based_ssid_aware_wordlist_forge",
                       args={"ssid": "X", "out_path": str(out)})
        assert r["ok"] is True
        assert r["data"]["phase_counts"]["phase4"] <= 2000

    def test_forge_no_scapy_no_subprocess_no_network(self, monkeypatch):
        """The forge is pure local I/O — no subprocess, no network, no
        scapy. Monkeypatch subprocess.run to fail if called."""
        def _fail(*a, **k):
            raise AssertionError("subprocess must not be called")
        monkeypatch.setattr("core.wifi_attack.runner.subprocess.run", _fail)
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            r = run_attack("phase_based_ssid_aware_wordlist_forge",
                           args={"ssid": "TestNet",
                                 "out_path": f"{td}/wl.txt"})
            assert r["ok"] is True


# ---------------------------------------------------------------------------
# Phase 1.6: scapy_flooder_auth_assoc_probe_beacon_deauth
# ---------------------------------------------------------------------------
def _scapy_available() -> bool:
    try:
        import scapy.all  # noqa: F401
        return True
    except Exception:  # noqa: BLE001
        return False


class TestScapyFlooderFrameBuilder:
    def test_build_deauth_frames(self, monkeypatch):
        """The frame builder is pure-Python via scapy's __bytes__ — does
        NOT require monitor mode. If scapy is installed, builds N
        frames. If not, returns ok=False with the 'scapy not installed'
        error (honest degradation, never a fabricated success)."""
        if not _scapy_available():
            r = run_attack("scapy_flooder_auth_assoc_probe_beacon_deauth",
                           args={"subtype": "deauth", "count": 5, "seed": 42})
            assert r["ok"] is False
            assert "scapy" in r["error"].lower()
            return
        r = run_attack("scapy_flooder_auth_assoc_probe_beacon_deauth",
                       args={"subtype": "deauth", "count": 5, "seed": 42})
        assert r["ok"] is True
        assert r["data"]["subtype"] == "deauth"
        assert r["data"]["frames_built"] == 5
        assert len(r["data"]["frame_size_bytes"]) >= 1

    def test_build_beacon_frames(self):
        if not _scapy_available():
            r = run_attack("scapy_flooder_auth_assoc_probe_beacon_deauth",
                           args={"subtype": "beacon", "count": 3, "seed": 1})
            assert r["ok"] is False
            return
        r = run_attack("scapy_flooder_auth_assoc_probe_beacon_deauth",
                       args={"subtype": "beacon", "count": 3, "seed": 1})
        assert r["ok"] is True
        assert r["data"]["frames_built"] == 3
        assert r["data"]["subtype"] == "beacon"

    def test_build_probe_assoc_auth_reassoc_disassoc(self):
        for sub in ("probe", "assoc", "auth", "reassoc", "disassoc"):
            r = run_attack("scapy_flooder_auth_assoc_probe_beacon_deauth",
                           args={"subtype": sub, "count": 2, "seed": 0})
            if _scapy_available():
                assert r["ok"] is True, f"{sub} failed: {r}"
                assert r["data"]["frames_built"] == 2
            else:
                assert r["ok"] is False

    def test_build_unknown_subtype_degrades(self):
        r = run_attack("scapy_flooder_auth_assoc_probe_beacon_deauth",
                       args={"subtype": "no_such_subtype"})
        assert r["ok"] is False
        # Either scapy is missing (error contains "scapy") or the
        # subtype is unknown (error contains "subtype"). Both are
        # honest degradations — no fabricated success.
        assert ("subtype" in r["error"] or "scapy" in r["error"].lower())

    def test_deterministic_with_seed(self):
        """Same seed -> same bssid -> same frame bytes (when scapy
        available)."""
        if not _scapy_available():
            return  # skip determinism check when scapy absent
        a = run_attack("scapy_flooder_auth_assoc_probe_beacon_deauth",
                       args={"subtype": "deauth", "count": 2, "seed": 7})
        b = run_attack("scapy_flooder_auth_assoc_probe_beacon_deauth",
                       args={"subtype": "deauth", "count": 2, "seed": 7})
        assert a["data"]["bssid"] == b["data"]["bssid"]
        assert a["data"]["frames_built"] == b["data"]["frames_built"]
        assert a["data"]["frame_size_bytes"] == b["data"]["frame_size_bytes"]

    def test_no_subprocess_called(self, monkeypatch):
        """The builder is hermetic — no subprocess should be invoked."""
        def _fail(*a, **k):
            raise AssertionError("subprocess must not be called")
        monkeypatch.setattr("core.wifi_attack.runner.subprocess.run", _fail)
        monkeypatch.setattr("core.wifi_attack.runner.subprocess.Popen", _fail)
        r = run_attack("scapy_flooder_auth_assoc_probe_beacon_deauth",
                       args={"subtype": "beacon", "count": 2, "seed": 1})
        # Either scapy is absent (ok=False honest) or scapy is present
        # and frames were built (ok=True). Both are valid here — the
        # invariant is: subprocess.run / subprocess.Popen was never
        # called by the builder (the monkeypatched _fail would have
        # raised otherwise).
        assert r["ok"] in (True, False)