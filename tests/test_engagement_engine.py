"""Unit tests for EngagementEngine (fakes only — no real attacks)."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

from core.orchestrator.engagement_engine import (
    ENGAGEMENT_TOOL_CONTEXT,
    EngagementEngine,
    run_engagement,
)


def test_engagement_tool_context_mentions_catalog_and_holo():
    blob = ENGAGEMENT_TOOL_CONTEXT.lower()
    assert "catalog" in blob or "toolboxes" in blob
    assert "holo" in blob
    assert "cve" in blob


def test_run_unsupported_domain():
    eng = EngagementEngine(orchestrator=None, enable_bg_zero_day=False)
    rep = eng.run("space_laser", {"x": 1}, skip_holo_prep=True)
    assert rep["ok"] is False
    assert "unsupported" in (rep.get("error") or "")


def test_run_wifi_delegates_to_adaptive():
    fake_orch = MagicMock()
    eng = EngagementEngine(
        fake_orch,
        enable_bg_zero_day=False,
        enable_holo_prep=False,
    )
    fake_report = {
        "ok": True,
        "cycles": [{"cycle": 1}],
        "access": {"achieved": False},
    }
    with patch.object(eng, "_run_adaptive", return_value=fake_report) as m:
        with patch.object(eng, "_phase_holo", return_value={"ok": False}):
            rep = eng.run("wifi", {"bssid": "AA:BB:CC:DD:EE:FF", "ssid": "lab"})
    m.assert_called_once()
    assert rep["ok"] is True
    assert rep["adaptive"]["ok"] is True
    assert rep["access"]["achieved"] is False


def test_module_run_engagement_wrapper():
    with patch(
        "core.orchestrator.engagement_engine.EngagementEngine.run",
        return_value={"ok": True, "domain": "ble"},
    ):
        r = run_engagement("ble", {"address": "00:11:22:33:44:55"})
    assert r["ok"] is True


def test_holo_phase_honest_when_missing():
    eng = EngagementEngine(None, enable_holo_prep=True, enable_bg_zero_day=False)
    with patch(
        "core.desktop.holo_agent.holo_status",
        return_value={"ok": False, "error": "not found", "holo_bin": ""},
    ):
        out = eng._phase_holo("wifi", {}, skip=False)
    assert out["status"]["ok"] is False


def test_detect_adapter_blocked_no_iface():
    eng = EngagementEngine(None, enable_bg_zero_day=False, enable_holo_prep=False)
    assert eng._detect_adapter_blocked("wifi", {}) is True
    assert eng._detect_adapter_blocked("wifi", {"adapter_blocked": True}) is True
    # Explicit clear path: not blocked when flag unset and iface present with
    # require_monitor=False (skip monitor check).
    assert eng._detect_adapter_blocked(
        "wifi",
        {"interface": "wlan0mon", "require_monitor": False},
    ) is False


def test_seed_flags_on_wifi_run():
    orch = MagicMock()
    eng = EngagementEngine(
        orch, enable_bg_zero_day=False, enable_holo_prep=False,
    )
    with patch.object(eng, "_phase_holo", return_value={"ok": False}):
        with patch.object(
            eng, "_run_adaptive",
            return_value={"ok": True, "access": {"achieved": False}, "cycles": []},
        ) as m:
            eng.run("wifi", {"bssid": "AA:BB:CC:DD:EE:FF", "ssid": "lab", "interface": "wlan0mon"})
    seed = m.call_args[0][1]
    assert seed.get("use_ai_chain") is True
    assert seed.get("attach_zero_day") is True
    assert seed.get("prefer_holo_when_blocked") is True
    assert "holo" in (seed.get("engagement_context") or "").lower()
    assert "toolboxes" in (seed.get("engagement_context") or "").lower()
