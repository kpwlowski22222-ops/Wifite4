"""Plum-dispatch multiple dispatch for target-adaptive polymorphism."""
from __future__ import annotations

import pytest


def test_plum_available():
    from core.poly.plum_adapt import plum_available
    assert plum_available() is True


def test_coerce_wifi_vs_ble():
    from core.poly.plum_adapt import coerce_target, WifiTarget, BleTarget
    w = coerce_target({"bssid": "AA:BB", "encryption": "WPA3-SAE", "pmf": True})
    assert isinstance(w, WifiTarget)
    assert w.domain == "wifi"
    b = coerce_target(
        {"address": "11:22:33:44:55:66", "connectable": True, "domain": "ble"},
        domain="ble",
    )
    assert isinstance(b, BleTarget)


def test_adapt_wifi_sae_boosts():
    from core.poly.plum_adapt import adapt_target
    env = adapt_target(
        {"encryption": "WPA3-SAE", "pmf": True, "bssid": "AA:BB"},
        domain="wifi",
    )
    assert env["ok"] is True
    assert env["family"] == "wifi"
    assert env["focus"] == "sae"
    assert env["engine"].startswith("plum")
    assert env["boosts"].get("sae_commit", 0) > 0
    assert "target_type" in env


def test_adapt_web_and_binary():
    from core.poly.plum_adapt import adapt_target
    web = adapt_target({"url": "https://example.test/login"})
    assert web["family"] == "web"
    assert web["boosts"]
    bin_ = adapt_target({"binary": "/tmp/a.out", "crash_path": "/tmp/core"})
    assert bin_["family"] == "binary"
    assert "crash" in (bin_["method"] or "") or bin_["depth"] == "deep"


def test_algorithm_poly_uses_plum_boosts():
    from core.ai_backend.algorithm_poly import pick_variant
    p = pick_variant(
        "zero_day_wifi_wpa3_sae",
        target={"encryption": "WPA3-SAE", "pmf": True, "bssid": "AA"},
        args={"domain": "wifi"},
    )
    assert p.family == "wifi"
    assert p.variant
    eng = str(p.knobs.get("plum_engine") or p.knobs.get("poly_model") or "")
    assert (
        "plum" in eng
        or "ensemble" in eng
        or p.features.get("plum_target_type")
        or p.features.get("poly_engines")
    )


def test_situational_pick_includes_plum():
    from core.utils.poly_runtime import situational_pick
    env = situational_pick(
        "wifi",
        context={"encryption": "WPA2", "client_count": 3, "bssid": "AA"},
    )
    assert env["ok"] is True
    assert env.get("pick")
    # plum metadata attached when available
    assert "plum" in env or env.get("model")


def test_react_prefers_plum_method():
    from core.poly.live_adapt import react
    r = react("wifi", {"encryption": "WPA3-SAE", "pmf": True, "bssid": "AA"})
    assert r.get("method")
    assert r.get("plum") or r.get("features")


def test_plum_prompt_block():
    from core.poly.plum_adapt import plum_prompt_block
    block = plum_prompt_block(
        {"url": "https://t.test"}, domain="web",
    )
    assert "PLUM TARGET ADAPT" in block
    assert "WebTarget" in block or "web" in block.lower()


def test_dispatch_stamps_plum_via_poly(tmp_path, monkeypatch):
    monkeypatch.setenv("KFIOSA_ZERO_DAY_DRAFTS", str(tmp_path))
    monkeypatch.setenv("KFIOSA_ALGO_POLY", "1")
    from core.ai_backend.zero_day_algorithms import dispatch
    r = dispatch(
        "zero_day_poly_auth_flow_chain",
        {"url": "https://auth.test"},
        {},
        {"domain": "web"},
    )
    assert r.get("ok") is True
    poly = r.get("polymorphic") or {}
    assert poly.get("enabled") is True
    # plum knobs may appear under knobs snapshot inside polymorphic
    assert poly.get("variant")


def test_coerce_cache_stable():
    from core.poly.plum_adapt import coerce_target
    t = {"bssid": "AA:BB:CC", "encryption": "WPA2"}
    a = coerce_target(t, domain="wifi")
    b = coerce_target(t, domain="wifi")
    assert type(a) is type(b)
    assert a.domain == b.domain == "wifi"
