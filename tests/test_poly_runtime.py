"""Tests for core.utils.poly_runtime — detailed Python 3.10 polymorphism."""
from __future__ import annotations

from core.utils.poly_runtime import (
    Domain,
    Phase,
    SituationalMixin,
    describe_polymorphism,
    dispatch_by_domain,
    situational_pick,
)


class TestSituationalPick:
    def test_wifi_wpa3(self):
        env = situational_pick(
            "wifi",
            {"wpa_version": "wpa3", "pmf_supported": True, "bssid": "aa"},
        )
        assert env["ok"] is True
        assert env["pick"] == "wpa3_sae"
        assert "heuristic" in env["model"]

    def test_wifi_open(self):
        env = situational_pick("wifi", {"wpa_version": "open", "bssid": "bb"})
        assert env["pick"] == "open"

    def test_ble_hid(self):
        env = situational_pick(
            "ble", {"address": "aa:bb", "has_hid": True}, phase="exploit",
        )
        assert env["pick"] == "hid_inject"

    def test_osint_email_ai_hint(self):
        env = situational_pick(
            "osint",
            context={"query": "a@b.com"},
            ai_hint="email",
        )
        assert env["pick"] == "email"
        assert env["poly_kind"] == "ai-driven"

    def test_ai_hint_rejected_when_incompatible(self):
        env = situational_pick(
            "wifi",
            {"wpa_version": "wpa2", "bssid": "aa"},
            ai_hint="hid_inject",  # BLE-only
        )
        assert env["pick"] != "hid_inject"
        assert "rejected" in (env.get("rationale") or "").lower() or env["pick"] == "wpa2"

    def test_post_lateral(self):
        env = situational_pick(
            "post_exploitation",
            {
                "os": "windows",
                "has_creds": True,
                "network_access": True,
            },
        )
        assert env["pick"] == "lateral"

    def test_domain_coerce(self):
        assert Domain.coerce("post_exploit") is Domain.POST_EXPLOIT
        assert Domain.coerce("nope") is Domain.UNKNOWN


class TestDispatchAndDescribe:
    def test_singledispatch_str(self):
        name = dispatch_by_domain("wifi", {"wpa_version": "wep"})
        assert name == "wep"

    def test_singledispatch_enum(self):
        name = dispatch_by_domain(Domain.BLE, {"address": ""})
        assert name == "recon"

    def test_describe(self):
        text = describe_polymorphism()
        assert "match/case" in text
        assert "singledispatch" in text


class TestMixin:
    def test_mixin_pick(self):
        class R(SituationalMixin):
            pass

        r = R()
        env = r.situational_pick(
            "osint", query="example.com", query_type="domain",
        )
        assert env["ok"] is True
        assert env["pick"] == "domain"
