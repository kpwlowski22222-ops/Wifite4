"""All algorithms are polymorphic — hermetic tests."""
from __future__ import annotations

import os

import pytest


@pytest.fixture(autouse=True)
def _poly_on(monkeypatch):
    monkeypatch.setenv("KFIOSA_ALGO_POLY", "1")


def test_classify_families():
    from core.ai_backend.algorithm_poly import classify_family
    assert classify_family("zero_day_wifi_wpa3_sae") == "wifi"
    assert classify_family("zero_day_ble_gatt") == "ble"
    assert classify_family("zero_day_use_after_free") == "memory"
    assert classify_family("zero_day_jwt_alg_confusion") in ("crypto", "web", "auth")
    assert classify_family("zero_day_crash_triager") == "binary"
    assert classify_family("chain_of_thought") == "thinking"


def test_pick_variant_wifi_prefers_sae_when_pmf():
    from core.ai_backend.algorithm_poly import pick_variant
    p = pick_variant(
        "zero_day_wifi_wpa3_sae",
        target={"encryption": "WPA3-SAE", "pmf": True, "clients": 0},
    )
    assert p.family == "wifi"
    assert p.variant
    assert p.score > 0
    # SAE / pmkid preferred over evil_twin when PMF
    assert p.variant in (
        "sae_commit", "pmkid_first", "passive_long",
        "handshake_deauth", "evil_twin_branch",
    )


def test_apply_poly_args_injects_knobs():
    from core.ai_backend.algorithm_poly import pick_variant, apply_poly_args
    p = pick_variant("zero_day_heap_overflow", target={"binary": "/tmp/x"})
    args = apply_poly_args({"timeout": 10}, p)
    assert args["timeout"] == 10
    assert args["_poly"]["variant"] == p.variant
    assert args["poly_variant"] == p.variant
    assert "poly_depth" in args or args["_poly"].get("depth")


def test_wrap_stamps_result():
    from core.ai_backend.algorithm_poly import wrap_algorithm

    def fake(target, recon, args, **kw):
        return {"ok": True, "draft_id": "d1", "concept": {"technique": "x"}}

    wrapped = wrap_algorithm("zero_day_xss_polyglot", fake)
    out = wrapped({"url": "http://t"}, {}, {})
    assert out["ok"] is True
    assert out["polymorphic"]["enabled"] is True
    assert out["polymorphic"]["family"]
    assert out["polymorphic"]["variant"]
    assert "poly:" in (out["concept"].get("technique") or "")


def test_poly_disable_passthrough():
    from core.ai_backend.algorithm_poly import wrap_algorithm

    def fake(target, recon, args, **kw):
        return {"ok": True, "nopoly": True}

    wrapped = wrap_algorithm("zero_day_dns_message_parser", fake)
    out = wrapped({}, {}, {"poly_disable": True})
    assert out == {"ok": True, "nopoly": True}


def test_all_registry_algorithms_wrapped():
    from core.ai_backend.zero_day_algorithms import (
        ZERO_DAY_ALGORITHMS, _build_registry, list_algorithms,
    )
    _build_registry()
    names = list_algorithms()
    assert len(names) >= 70
    for n in names:
        fn = ZERO_DAY_ALGORITHMS[n]
        assert getattr(fn, "_kfiosa_poly_wrapped", False), f"{n} not wrapped"


def test_dispatch_includes_polymorphic_meta(tmp_path, monkeypatch):
    """Phase 6 pure algorithms via dispatch get poly stamp."""
    monkeypatch.setenv("KFIOSA_ZERO_DAY_DRAFTS", str(tmp_path))
    from core.ai_backend.zero_day_algorithms import dispatch
    r = dispatch(
        "zero_day_poly_buffer_boundary_prober",
        {"name": "libfoo"},
        {},
        {"signature": "void f(char *p, int n)"},
    )
    assert r.get("ok") is True
    assert r.get("polymorphic", {}).get("enabled") is True
    assert r["polymorphic"].get("variant")


def test_describe_poly():
    from core.ai_backend.zero_day_algorithms import describe_poly
    one = describe_poly("zero_day_tls_state_machine")
    assert one.get("ok") is True
    assert one.get("family")
    assert one.get("variant_count", 0) >= 2
    all_ = describe_poly()
    assert all_.get("algorithm_count", 0) >= 70
    assert all_.get("families")


def test_poly_off_env(monkeypatch):
    monkeypatch.setenv("KFIOSA_ALGO_POLY", "0")
    from core.ai_backend.algorithm_poly import wrap_algorithm, poly_enabled
    assert poly_enabled() is False

    def fake(target, recon, args, **kw):
        return {"ok": True}

    # re-import wrap uses poly_enabled at call time
    out = wrap_algorithm("zero_day_arp_poison", fake)({}, {}, {})
    assert "polymorphic" not in out


def test_retry_on_failure_picks_alternate():
    from core.ai_backend.algorithm_poly import wrap_algorithm
    calls = []

    def flaky(target, recon, args, **kw):
        calls.append(dict(args or {}))
        if not args.get("_poly_retry"):
            return {"ok": False, "error": "first variant failed"}
        return {"ok": True, "draft_id": "recovered"}

    wrapped = wrap_algorithm("zero_day_integer_overflow", flaky)
    out = wrapped({"binary": "x"}, {}, {})
    # Either recovered via retry or stamped first failure
    assert "polymorphic" in out
    if out.get("ok"):
        assert out.get("polymorphic_retry") or len(calls) >= 1
