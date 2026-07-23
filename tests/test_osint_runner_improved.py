"""Tests for improved OSINTRunner (classify, parse, breach, auto)."""
from __future__ import annotations

from core.osint.runner import (
    OSINTRunner,
    aggregate_findings,
    classify_osint_target,
)


def test_classify_email():
    c = classify_osint_target("Alice@Example.COM")
    assert c["kind"] == "email"
    assert c["normalized"] == "alice@example.com"
    assert c["meta"]["domain"] == "example.com"


def test_classify_domain():
    c = classify_osint_target("sub.example.org")
    assert c["kind"] == "domain"


def test_classify_phone():
    c = classify_osint_target("+48 501 234 567")
    assert c["kind"] == "phone"
    assert "501" in c["normalized"] or "48501" in c["normalized"].replace("+", "")


def test_classify_username():
    c = classify_osint_target("@alice_bob")
    assert c["kind"] == "username"
    assert c["normalized"] == "alice_bob"


def test_classify_url():
    c = classify_osint_target("https://github.com/alice")
    assert c["kind"] == "url"
    assert c["meta"].get("host") == "github.com"


def test_parse_sherlock_output():
    r = OSINTRunner()
    sample = """
[*] Checking username alice on:
[+] Twitter: https://twitter.com/alice
[+] GitHub: https://github.com/alice
[-] Facebook: Not Found
"""
    findings = r._parse("sherlock", sample)
    types = {f["type"] for f in findings}
    assert "profile" in types or "url" in types
    values = " ".join(f["value"] for f in findings)
    assert "twitter" in values.lower() or "github" in values.lower()
    assert len(findings) >= 2


def test_parse_holehe():
    r = OSINTRunner()
    findings = r._parse("holehe", "[+] twitter.com\n[-] facebook.com\n")
    assert any(f["type"] == "email_registered" for f in findings)
    assert any("twitter" in f["value"] for f in findings)


def test_parse_subfinder():
    r = OSINTRunner()
    findings = r._parse("subfinder", "a.example.com\nb.example.com\n")
    assert len(findings) == 2
    assert all(f["type"] == "subdomain" for f in findings)


def test_aggregate_dedupes():
    findings = [
        {"type": "url", "value": "https://x", "source": "a"},
        {"type": "url", "value": "https://x", "source": "a"},
        {"type": "email", "value": "a@b.c", "source": "b"},
    ]
    agg = aggregate_findings(findings)
    assert agg["count"] == 2


def test_breach_no_fabricated_names():
    r = OSINTRunner()
    res = r._correlate_breach_data("test1234")
    assert res["type"] == "breach_correlation"
    assert "contains_numbers" in res["value"]["risk_indicators"]
    # Without API key, identified_breaches must not be random fake names
    assert res["value"]["identified_breaches"] == []
    assert "hibp" in (res["value"].get("source_note") or "").lower() or "non_email" in (
        res["value"].get("source_note") or ""
    ).lower() or "no_hibp" in (res["value"].get("source_note") or "").lower()


def test_breach_email_without_key_honest():
    r = OSINTRunner()
    res = r._correlate_breach_data("user@example.com")
    assert res["value"]["identified_breaches"] == []
    assert "email_format" in res["value"]["risk_indicators"]


def test_phone_pl_carrier():
    r = OSINTRunner()
    res = r._infer_phone_carrier("+48501234567")
    assert res["type"] == "phone_carrier_inference"
    # Orange prefix 501
    assert res["value"]["carrier"] == "Orange"
    assert res["value"]["country_code"] == "48"


def test_run_auto_classifies_username(monkeypatch):
    r = OSINTRunner(confirm_fn=lambda *_a, **_k: False)

    # Avoid catalog tool runs — confirm denies; still get local probes
    class FakeCat:
        def get_tools_by_category(self, cat):
            return []
        def get_tool_by_name(self, n):
            return None

    r.catalog = FakeCat()
    out = r.run_auto("alice_dev")
    assert out["classification"]["kind"] == "username"
    assert "username" in out["plan"]
    assert "username_patterns" in out["local_probes"]


def test_username_patterns_still_works():
    r = OSINTRunner()
    res = r._analyze_username_patterns("AdminUser")
    assert res["value"]["original"] == "AdminUser"
    assert "adminuser" in res["value"]["patterns"]
