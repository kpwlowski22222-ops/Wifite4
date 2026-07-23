"""Tests for RAT dashboard v6 anti-lag + polymorphic filters."""
from __future__ import annotations

from core.post_access_tui.rat_ext import v6_enhancements as v6


class TestPoll:
    def test_idle_slower(self):
        busy = v6.adaptive_poll_config(sessions=[{}] * 3, idle=False)
        idle = v6.adaptive_poll_config(sessions=[], idle=True)
        assert idle["attack_state_ms"] >= busy["attack_state_ms"]
        assert idle["hidden_ms"] >= 10000


class TestPolyFilter:
    def test_filters_by_achievements(self):
        caps = [
            {"name": "dump", "required_achievements": {"shell"}},
            {"name": "scan", "required_achievements": set()},
        ]
        out = v6.polymorphic_capability_filter(
            caps, session={"achieved": set(), "kind": "wifi"},
        )
        names = [c["name"] for c in out["capabilities"]]
        assert "scan" in names
        assert "dump" not in names
        assert out["ok"] is True


class TestRecommend:
    def test_situational_recommend(self):
        out = v6.situational_recommend(
            {"kind": "wifi", "wpa_version": "wpa2", "bssid": "aa:bb"},
        )
        assert out["ok"] is True
        assert out.get("pick")


class TestShell:
    def test_inject_shell(self):
        html = "<!doctype html><html><head></head><body>hi</body></html>"
        out = v6.inject_shell(html, sessions=[])
        assert "kf-v6-css" in out
        assert "__KFIOSA_POLL__" in out
        assert "kfiosaDash" in out

    def test_health_v6(self):
        h = v6.health_v6([])
        assert h.get("model") == "rat-dashboard-v6"
        assert "poll" in h
