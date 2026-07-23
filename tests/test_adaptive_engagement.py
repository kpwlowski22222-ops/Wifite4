"""Tests for target-adaptive engagement controller."""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from core.orchestrator.adaptive_engagement import (
    AdaptiveEngagement,
    generate_reverse_stubs,
    score_recon,
    _poly_mutate_steps,
)


def test_score_recon_wifi_empty():
    s = score_recon("wifi", {})
    assert s["score"] == 0
    assert s["enough"] is False


def test_score_recon_wifi_rich():
    seed = {
        "bssid": "AA:BB:CC:DD:EE:FF",
        "ssid": "Test",
        "channel": 6,
        "encryption": "WPA2",
        "cves": [{"id": "CVE-2017-13077"}, {"id": "CVE-2020-24588"}],
        "kb_hits": [{"name": "x"}] * 3,
        "cap_file": "/tmp/x.cap",
        "recon": {
            "wps": {"ok": True, "data": {"enabled": False}},
            "clients": {"ok": True, "data": {"count": 2}},
            "cves": {"ok": True, "data": {"count": 2}},
            "handshake_harvest": {"ok": True, "data": {"pcap": "/tmp/x.cap"}},
        },
    }
    s = score_recon("wifi", seed)
    assert s["score"] >= 35
    assert s["enough"] is True
    assert "bssid" in s["reasons"]


def test_score_recon_ble_address():
    s = score_recon("ble", {"address": "AA:BB:CC:DD:EE:01", "rssi": -50})
    assert s["score"] >= 15
    assert "address" in s["reasons"]


def test_poly_mutate_injects_wifi_args():
    steps = [{"action": "wifi_attack", "method": "deauth", "args": {}}]
    seed = {
        "bssid": "AA:BB:CC:DD:EE:FF",
        "channel": 11,
        "interface": "wlan0mon",
        "encryption": "wpa2",
    }
    out = _poly_mutate_steps(steps, seed, "wifi", cycle=1)
    assert len(out) == 1
    assert out[0]["args"]["bssid"] == "AA:BB:CC:DD:EE:FF"
    assert out[0]["args"]["channel"] == 11
    assert out[0]["poly"]["target_adaptive"] is True
    assert out[0]["args"].get("poly_variant")


def test_generate_reverse_stubs(tmp_path):
    r = generate_reverse_stubs("10.0.0.5", 5555, out_dir=tmp_path)
    assert r["ok"] is True
    files = r["files"]
    assert "linux" in files
    assert "windows" in files
    assert "android" in files
    assert "ios" in files
    assert "macos" in files
    assert Path(files["linux"]).is_file()
    body = Path(files["linux"]).read_text(encoding="utf-8")
    assert "10.0.0.5" in body
    assert "5555" in body


def test_generate_reverse_stubs_requires_host():
    r = generate_reverse_stubs("")
    assert r["ok"] is False


class _FakeOrch:
    def __init__(self):
        self.kb = None
        self.chain_planner = None
        self.emitted = []

    def _emit(self, m):
        self.emitted.append(m)

    def _build_steps(self, domain, seed, report):
        return [
            {"action": "decide", "desc": "noop-decide", "kind": "info"},
        ]

    def _walk_static_step(self, step, seed, report, autonomous=False):
        report["executed"].append({
            "desc": step.get("desc") or step.get("action"),
            "kind": "real",
            "result": {"ok": True, "data": {}},
        })

    def _walk_chain_with_replan(self, *a, **k):
        # Should not be called without chain_planner
        raise AssertionError("replan path unexpected without planner")

    def _maybe_run_gain_access_hooks(self, *a, **k):
        return None

    def _build_ai_chain(self, *a, **k):
        return [], "empty"

    def _dispatch_cve_to_exploit(self, step, seed, report):
        report["skipped"].append("cve_to_exploit: fake-skip")


def test_adaptive_engagement_one_cycle_no_access():
    orch = _FakeOrch()
    eng = AdaptiveEngagement(
        orch,
        catalog_recon_factory=None,
        on_event=lambda m: None,
        max_cycles=1,
        until_access=False,
        enable_cve_code=False,
        enable_reverse_stubs=False,
    )
    # BLE path without factory uses ble runner — mock by using wifi with no factory
    report = eng.run("wifi", {"bssid": "AA:BB:CC:DD:EE:FF", "ssid": "t"})
    assert report["ok"] is True
    assert len(report["cycles"]) == 1
    assert report["access"]["achieved"] is False


def test_adaptive_engagement_rejects_bad_domain():
    eng = AdaptiveEngagement(_FakeOrch())
    r = eng.run("osint", {})
    assert r["ok"] is False


def test_adaptive_run_clears_leftover_auto_until_access():
    """TUI uses AdaptiveEngagement.run, not orch.run — must clear AUTO latch.

    A prior engagement's ``TuiConfirmFn.auto_until_access`` must not
    silently auto-ACCEPT every step of the next adaptive chain.
    """
    from core.orchestrator.autonomous_orchestrator import TuiConfirmFn

    tui = TuiConfirmFn()
    tui.auto_until_access = True  # leftover latch from a previous session

    orch = _FakeOrch()
    orch.confirm_fn = tui.confirm  # bound method → _confirm_owner finds tui

    logs: list = []
    eng = AdaptiveEngagement(
        orch,
        catalog_recon_factory=None,
        on_event=logs.append,
        max_cycles=1,
        until_access=False,
        enable_cve_code=False,
        enable_reverse_stubs=False,
    )
    report = eng.run("wifi", {"bssid": "AA:BB:CC:DD:EE:FF", "ssid": "t"})
    assert report["ok"] is True
    assert tui.auto_until_access is False, (
        "leftover AUTO→access latch must be cleared at AdaptiveEngagement.run start"
    )
    assert any("cleared leftover AUTO→access" in m for m in logs)


def test_adaptive_clear_auto_helper_idempotent_when_unset():
    """clear when latch already False is a no-op (no log spam required)."""
    from core.orchestrator.autonomous_orchestrator import TuiConfirmFn

    tui = TuiConfirmFn()
    assert tui.auto_until_access is False
    orch = _FakeOrch()
    orch.confirm_fn = tui.confirm
    eng = AdaptiveEngagement(orch, on_event=lambda m: None, max_cycles=1,
                             until_access=False, enable_cve_code=False,
                             enable_reverse_stubs=False)
    assert eng._clear_leftover_auto_access() is False
    assert tui.auto_until_access is False
