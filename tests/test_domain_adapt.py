"""Domain polymorphic / target-adaptive / AI-ready facade."""
from __future__ import annotations


def test_list_domains_and_methods():
    from core.poly.domain_adapt import list_domains, list_domain_methods, describe_domains
    doms = list_domains()
    assert "wifi" in doms and "ble" in doms and "post_exploit" in doms
    wifi_m = list_domain_methods("wifi")
    assert len(wifi_m) >= 10
    d = describe_domains()
    assert d["ok"] and d["domains"]["wifi"]["method_count"] >= 10


def test_prepare_wifi_ensemble():
    from core.poly.domain_adapt import prepare
    p = prepare(
        "wifi",
        {"bssid": "AA:BB:CC:DD:EE:FF", "encryption": "WPA3-SAE", "pmf": True},
    )
    assert p["ok"]
    assert p["domain"] == "wifi"
    assert p.get("ensemble") or p.get("engines") is not None


def test_pick_wifi_sae_prefers_sae_method():
    from core.poly.domain_adapt import pick
    r = pick(
        "wifi",
        {"encryption": "WPA3 SAE", "pmf": True, "bssid": "AA:BB:CC:DD:EE:FF"},
        phase="exploit",
    )
    assert r["ok"]
    assert r["method"]
    # should lean toward SAE / non-classic deauth
    m = r["method"].lower()
    assert any(x in m for x in ("sae", "pmkid", "pmf", "wpa3", "dragon", "full_auto", "signal"))


def test_prepare_run_auto_pick():
    from core.poly.domain_adapt import prepare_run
    m, args, meta = prepare_run(
        "wifi",
        "auto",
        {"bssid": "AA:BB", "encryption": "WPA2", "client_count": 0, "session": {}},
    )
    assert m
    assert args.get("_poly") or args.get("poly_depth")
    assert meta.get("enabled") is True


def test_prepare_run_keeps_explicit_method():
    from core.poly.domain_adapt import prepare_run
    m, args, meta = prepare_run(
        "wifi",
        "targeted_deauth_timing",
        {"bssid": "AA:BB", "encryption": "WPA2"},
        auto_pick=True,
    )
    assert m == "targeted_deauth_timing"
    assert args.get("method") == "targeted_deauth_timing"


def test_plan_poly_first():
    from core.poly.domain_adapt import plan
    p = plan("wifi", {"encryption": "WPA2", "bssid": "AA"}, n_steps=3)
    assert p["ok"]
    assert p["steps"]
    assert p["steps"][0]["action"] == "poly_adapt"


def test_osint_people_vs_web():
    from core.poly.domain_adapt import prepare, normalize_domain
    assert normalize_domain("people") == "osint_people"
    p = prepare("osint_web", {"url": "https://example.test"})
    assert p["domain"] == "osint_web"


def test_domain_poly_module_facade():
    from core.modules.domain_poly import describe_domains, pick
    d = describe_domains()
    assert "ble" in d["domains"]
    r = pick("post_exploit", {"has_creds": True, "os": "linux"})
    assert r.get("ok") is True
    assert r.get("method")


def test_stamp_result():
    from core.poly.domain_adapt import stamp_result
    out = stamp_result(
        {"ok": True, "name": "x"},
        {"enabled": True, "domain": "wifi", "pick": {"method": "x", "source": "heuristic"},
         "prepare": {"engines": ["plum"], "ensemble": {"focus": "sae", "depth": "deep"}},
         "model": "test"},
    )
    assert out["domain_poly"]["domain"] == "wifi"
    assert out["domain_poly"]["engines"] == ["plum"]


def test_forensics_and_anti_forensics_domains():
    from core.poly.domain_adapt import (
        list_domains, list_domain_methods, pick, plan, normalize_domain,
    )
    assert "forensics" in list_domains()
    assert "anti_forensics" in list_domains()
    assert normalize_domain("dfir") == "forensics"
    assert normalize_domain("opsec") == "anti_forensics"
    f_methods = list_domain_methods("forensics")
    assert "file_hash" in f_methods
    assert not any(m.startswith("anti_") for m in f_methods)
    af_methods = list_domain_methods("anti_forensics")
    assert any(m.startswith("post_") for m in af_methods) or any(
        m.startswith("anti_") for m in af_methods
    )
    # pcap path → pcap method
    r = pick("forensics", {"path": "/tmp/capture.pcap"})
    assert r["ok"] and "pcap" in r["method"]
    # image → exif
    r2 = pick("forensics", {"path": "/tmp/photo.jpg"})
    assert r2["ok"] and "exif" in r2["method"]
    # anti-forensics plan
    p = plan("anti_forensics", {"os": "Linux", "opsec": True}, n_steps=2)
    assert p["ok"] and p["steps"][0]["action"] == "poly_adapt"
    assert any(
        s.get("action") == "post_exploit_anti_forensic" for s in p["steps"][1:]
    ) or len(p["steps"]) >= 1
