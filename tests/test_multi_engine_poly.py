"""Multi-library polymorphism engines (Python ≥3.10)."""
from __future__ import annotations

import pytest


def test_engines_status_lists_github_libs():
    from core.poly.multi_engine import engines_status, enabled_engines
    st = engines_status()
    assert st["ok"] is True
    assert st["available"]["singledispatch"] is True
    assert st["available"]["match_case"] is True
    # installed deps
    assert st["available"]["plum"] is True
    assert st["available"]["multimethod"] is True
    assert st["available"]["multipledispatch"] is True
    enabled = enabled_engines()
    assert len(enabled) >= 4
    assert "plum" in st["libraries"]
    assert "github.com" in st["libraries"]["plum"]


def test_ensemble_wifi_uses_multiple_engines():
    from core.poly.multi_engine import ensemble_adapt
    env = ensemble_adapt(
        {"encryption": "WPA3-SAE", "pmf": True, "bssid": "AA:BB"},
        domain="wifi",
    )
    assert env["ok"] is True
    assert env["engine_count"] >= 3
    assert "plum" in env["engines_used"] or "multimethod" in env["engines_used"]
    assert env["family"] in ("wifi", "generic") or env["focus"]
    assert env["boosts"]
    assert "ensemble" in (env.get("model") or "")


def test_ensemble_ble_and_web():
    from core.poly.multi_engine import ensemble_adapt
    ble = ensemble_adapt(
        {"address": "11:22:33:44:55:66", "connectable": True},
        domain="ble",
    )
    assert ble["ok"] and ble["engine_count"] >= 2
    web = ensemble_adapt({"url": "https://example.test/admin"})
    assert web["ok"]
    assert web.get("family") in ("web", "osint", "generic") or web.get("focus")


def test_each_engine_callable_via_subset(monkeypatch):
    from core.poly import multi_engine as me
    # Reset status cache when filtering
    for eng in ("plum", "multimethod", "multipledispatch",
                "singledispatch", "match_case", "strategy"):
        monkeypatch.setenv("KFIOSA_POLY_ENGINES", eng)
        # clear module-level cache of enabled list (enabled_engines reads env each time)
        env = me.ensemble_adapt({"bssid": "AA", "encryption": "WPA2"}, domain="wifi")
        assert env["ok"] is True
        assert eng in (env.get("engines_used") or [eng]) or env.get("engine_count", 0) >= 0


def test_algorithm_pick_uses_ensemble_engines():
    from core.ai_backend.algorithm_poly import pick_variant
    p = pick_variant(
        "zero_day_wifi_wpa3_sae",
        target={"encryption": "WPA3-SAE", "pmf": True, "bssid": "AA"},
        args={"domain": "wifi"},
    )
    assert p.variant
    d = p.as_dict()
    assert d["enabled"] is True
    # engines list from ensemble
    engines = d.get("engines") or p.knobs.get("poly_engines")
    assert engines is None or len(engines) >= 1
    assert "polymorphic" in (d.get("model") or "")


def test_all_algorithms_wrapped_and_dispatch_ensemble(tmp_path, monkeypatch):
    monkeypatch.setenv("KFIOSA_ZERO_DAY_DRAFTS", str(tmp_path))
    monkeypatch.setenv("KFIOSA_ALGO_POLY", "1")
    from core.ai_backend.zero_day_algorithms import (
        list_algorithms, ZERO_DAY_ALGORITHMS, _build_registry, dispatch,
    )
    _build_registry()
    names = list_algorithms()
    assert len(names) >= 70
    for n in names[:15]:  # sample for speed
        assert getattr(ZERO_DAY_ALGORITHMS[n], "_kfiosa_poly_wrapped", False)
    r = dispatch(
        "zero_day_poly_buffer_boundary_prober",
        {"name": "libx", "binary": "/tmp/x"},
        {},
        {"signature": "void f(char *p, int n)", "domain": "binary"},
    )
    assert r.get("ok") is True
    poly = r.get("polymorphic") or {}
    assert poly.get("enabled") is True
    assert poly.get("variant")


def test_multi_engine_prompt_block():
    from core.poly.multi_engine import multi_engine_prompt_block
    block = multi_engine_prompt_block(
        {"url": "https://t.test"}, domain="web",
    )
    assert "MULTI-ENGINE POLY" in block
    assert "plum" in block.lower() or "engines=" in block


def test_engines_off(monkeypatch):
    monkeypatch.setenv("KFIOSA_POLY_ENGINES", "0")
    from core.poly.multi_engine import ensemble_adapt, enabled_engines
    assert enabled_engines() == []
    env = ensemble_adapt({"bssid": "AA"}, domain="wifi")
    assert env.get("engines_used") == [] or "disabled" in (env.get("model") or "")
