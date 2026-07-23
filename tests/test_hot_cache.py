"""Tests for core.utils.hot_cache + creative optimisations."""
from __future__ import annotations

import time

from core.utils.hot_cache import GLOBAL_CACHE, HotCache, fingerprint
from core.utils.poly_adapt import extract_target_features, pick_wifi_strategy


class TestHotCache:
    def test_get_or_set_hits(self):
        c = HotCache(default_ttl_s=5.0, max_entries=16)
        n = {"i": 0}

        def factory():
            n["i"] += 1
            return n["i"]

        a = c.get_or_set("t", "k", factory)
        b = c.get_or_set("t", "k", factory)
        assert a == 1 and b == 1
        assert c.hits >= 1
        assert c.misses >= 1

    def test_ttl_expiry(self):
        c = HotCache(default_ttl_s=0.05, max_entries=8)
        c.put("ns", "x", 42, ttl_s=0.05)
        assert c.get("ns", "x") == 42
        time.sleep(0.08)
        from core.utils import hot_cache as hc
        assert c.get("ns", "x") is hc._MISS

    def test_fingerprint_stable(self):
        a = fingerprint({"wpa_version": "wpa2", "client_count": 2})
        b = fingerprint({"client_count": 2, "wpa_version": "wpa2"})
        assert a == b

    def test_global_cache_stats(self):
        GLOBAL_CACHE.clear("test_ns")
        GLOBAL_CACHE.put("test_ns", "a", "b", ttl_s=10)
        s = GLOBAL_CACHE.stats()
        assert "hits" in s and "namespaces" in s
        GLOBAL_CACHE.clear("test_ns")


class TestFeatureFlyweight:
    def test_second_extract_reuses_bag(self):
        seed = {"encryption": "WPA2", "clients": ["a", "b"], "channel": 6}
        f1 = extract_target_features(seed)
        assert f1["wpa_version"] == "wpa2"
        assert f1["client_count"] == 2
        # Must not mutate the caller's seed
        assert "_kfiosa_features" not in seed
        f2 = extract_target_features(seed)
        assert f2["client_count"] == 2
        assert pick_wifi_strategy(f2) == "wpa2"


class TestDispatchTable:
    def test_orchestrator_builds_table(self):
        from core.orchestrator.autonomous_orchestrator import (
            AutonomousOrchestrator,
        )
        orch = AutonomousOrchestrator()
        table = orch._action_dispatch_table()
        assert "wifi_attack" in table
        assert "holo_desktop" in table
        assert "poly_adapt" in table
        # Same bound target method (may be distinct bound-method objects)
        assert table["holo_run"].__func__ is table["holo_desktop"].__func__
        # second call is cached instance
        assert orch._action_dispatch_table() is table
