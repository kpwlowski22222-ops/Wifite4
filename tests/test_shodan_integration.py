"""Tests for core.integrations.shodan_integration — Phase 4 T22 coverage."""
from __future__ import annotations

import importlib
import os
from unittest import mock

import pytest


def _import_mod():
    return importlib.import_module("core.integrations.shodan_integration")


mod = _import_mod()


# ---------------------------------------------------------------------------
# Init
# ---------------------------------------------------------------------------

class TestInit:
    def test_init_with_explicit_key(self):
        s = mod.ShodanIntegration(api_key="test_key")
        assert s.api_key == "test_key"

    def test_init_from_env(self, monkeypatch):
        monkeypatch.setenv("SHODAN_API_KEY", "env_key")
        s = mod.ShodanIntegration()
        assert s.api_key == "env_key"

    def test_init_no_key(self, monkeypatch):
        monkeypatch.delenv("SHODAN_API_KEY", raising=False)
        s = mod.ShodanIntegration()
        assert s.api_key == ""

    def test_explicit_key_wins_over_env(self, monkeypatch):
        monkeypatch.setenv("SHODAN_API_KEY", "env_key")
        s = mod.ShodanIntegration(api_key="explicit_key")
        assert s.api_key == "explicit_key"

    def test_init_with_settings(self, monkeypatch):
        monkeypatch.delenv("SHODAN_API_KEY", raising=False)
        fake_settings = mock.MagicMock()
        fake_settings.get_setting.side_effect = lambda k, d=None: {
            "shodan.api_key": "settings_key",
            "shodan.base_url": "https://custom.shodan.io",
        }.get(k, d)
        s = mod.ShodanIntegration(settings=fake_settings)
        assert s.api_key == "settings_key"
        assert s.base_url == "https://custom.shodan.io"

    def test_init_with_settings_loading(self, monkeypatch):
        monkeypatch.delenv("SHODAN_API_KEY", raising=False)
        # Settings that has load_settings but settings attr empty
        fake_settings = mock.MagicMock()
        fake_settings.settings = {}  # falsy → triggers load_settings
        fake_settings.get_setting.return_value = "from_load"
        s = mod.ShodanIntegration(settings=fake_settings)
        assert s.api_key == "from_load"
        fake_settings.load_settings.assert_called_once()

    def test_init_settings_exception_safe(self, monkeypatch):
        monkeypatch.delenv("SHODAN_API_KEY", raising=False)
        # Settings that raises on get_setting
        fake_settings = mock.MagicMock()
        fake_settings.get_setting.side_effect = RuntimeError("nope")
        s = mod.ShodanIntegration(settings=fake_settings)
        # Falls back to empty key
        assert s.api_key == ""

    def test_default_base_url(self, monkeypatch):
        monkeypatch.delenv("SHODAN_API_KEY", raising=False)
        s = mod.ShodanIntegration()
        assert s.base_url == "https://api.shodan.io"

    def test_initialize_noop(self):
        s = mod.ShodanIntegration(api_key="k")
        # Just shouldn't crash
        assert s.initialize() is None


# ---------------------------------------------------------------------------
# _make_request
# ---------------------------------------------------------------------------

class TestMakeRequest:
    def test_success(self):
        s = mod.ShodanIntegration(api_key="k")
        fake = mock.MagicMock()
        fake.json.return_value = {"data": "ok"}
        fake.raise_for_status = mock.MagicMock()
        with mock.patch.object(s.session, "get", return_value=fake) as m:
            out = s._make_request("/test")
        assert out == {"data": "ok"}
        # Key is in params
        assert m.call_args[1]["params"]["key"] == "k"

    def test_default_params(self):
        s = mod.ShodanIntegration(api_key="k")
        fake = mock.MagicMock()
        fake.json.return_value = {}
        fake.raise_for_status = mock.MagicMock()
        with mock.patch.object(s.session, "get", return_value=fake) as m:
            s._make_request("/x")
        params = m.call_args[1]["params"]
        # Default empty dict but key added
        assert params["key"] == "k"

    def test_custom_params(self):
        s = mod.ShodanIntegration(api_key="k")
        fake = mock.MagicMock()
        fake.json.return_value = {}
        fake.raise_for_status = mock.MagicMock()
        with mock.patch.object(s.session, "get", return_value=fake) as m:
            s._make_request("/x", params={"q": "apache"})
        params = m.call_args[1]["params"]
        assert params["q"] == "apache"
        assert params["key"] == "k"

    def test_request_error_raises(self):
        import requests
        s = mod.ShodanIntegration(api_key="k")
        fake = mock.MagicMock()
        fake.raise_for_status.side_effect = requests.HTTPError("404")
        with mock.patch.object(s.session, "get", return_value=fake):
            with pytest.raises(Exception) as exc:
                s._make_request("/x")
        assert "Shodan API request failed" in str(exc.value)

    def test_url_construction(self):
        s = mod.ShodanIntegration(api_key="k")
        s.base_url = "https://test.shodan.io"
        fake = mock.MagicMock()
        fake.json.return_value = {}
        fake.raise_for_status = mock.MagicMock()
        with mock.patch.object(s.session, "get", return_value=fake) as m:
            s._make_request("/test")
        assert m.call_args[0][0] == "https://test.shodan.io/test"


# ---------------------------------------------------------------------------
# search_host dispatcher
# ---------------------------------------------------------------------------

class TestSearchHost:
    def test_ip_dispatches_to_host_lookup(self):
        s = mod.ShodanIntegration(api_key="k")
        with mock.patch.object(s, "host_lookup", return_value={"ip": "1.2.3.4"}) as m:
            out = s.search_host("1.2.3.4")
        m.assert_called_once_with("1.2.3.4")
        assert out == {"ip": "1.2.3.4"}

    def test_domain_dispatches_to_domain_lookup(self):
        s = mod.ShodanIntegration(api_key="k")
        with mock.patch.object(s, "domain_lookup", return_value={"domain": "example.com"}) as m:
            out = s.search_host("example.com")
        m.assert_called_once_with("example.com")
        assert out == {"domain": "example.com"}

    def test_subdomain_dispatches_to_domain(self):
        # Subdomain has letters before TLD → not IP
        s = mod.ShodanIntegration(api_key="k")
        with mock.patch.object(s, "domain_lookup", return_value={}):
            out = s.search_host("www.example.com")
        # Routed to domain_lookup
        assert out == {}

    def test_exception_returns_error(self):
        s = mod.ShodanIntegration(api_key="k")
        with mock.patch.object(s, "host_lookup", side_effect=RuntimeError("boom")):
            out = s.search_host("1.2.3.4")
        assert "error" in out
        assert "boom" in out["error"]


# ---------------------------------------------------------------------------
# host_lookup, domain_lookup, search, get_api_info, get_my_ip
# ---------------------------------------------------------------------------

class TestEndpoints:
    def test_host_lookup(self):
        s = mod.ShodanIntegration(api_key="k")
        with mock.patch.object(s, "_make_request", return_value={"ip": "x"}) as m:
            out = s.host_lookup("1.2.3.4")
        m.assert_called_once_with("/shodan/host/1.2.3.4")
        assert out == {"ip": "x"}

    def test_domain_lookup(self):
        s = mod.ShodanIntegration(api_key="k")
        with mock.patch.object(s, "_make_request", return_value={"d": "x"}) as m:
            out = s.domain_lookup("example.com")
        m.assert_called_once_with("/dns/domain/example.com")
        assert out == {"d": "x"}

    def test_search(self):
        s = mod.ShodanIntegration(api_key="k")
        with mock.patch.object(s, "_make_request", return_value={"matches": []}) as m:
            out = s.search("apache", limit=10)
        m.assert_called_once()
        args, kwargs = m.call_args
        # Called as (endpoint, params) — positional
        assert args[0] == "/shodan/host/search"
        assert args[1]["query"] == "apache"
        assert args[1]["limit"] == 10

    def test_search_default_limit(self):
        s = mod.ShodanIntegration(api_key="k")
        with mock.patch.object(s, "_make_request", return_value={}) as m:
            s.search("apache")
        args, kwargs = m.call_args
        assert args[1]["limit"] == 100

    def test_get_api_info(self):
        s = mod.ShodanIntegration(api_key="k")
        with mock.patch.object(s, "_make_request", return_value={"plan": "free"}) as m:
            out = s.get_api_info()
        m.assert_called_once_with("/api-info")
        assert out == {"plan": "free"}

    def test_get_my_ip(self):
        s = mod.ShodanIntegration(api_key="k")
        with mock.patch.object(s, "_make_request", return_value={"ip": "1.2.3.4"}) as m:
            out = s.get_my_ip()
        m.assert_called_once_with("/tools/myip")
        assert out == {"ip": "1.2.3.4"}

    def test_scan_ip(self):
        s = mod.ShodanIntegration(api_key="k")
        with mock.patch.object(s, "_make_request", return_value={"id": "abc"}) as m:
            out = s.scan_ip(["1.2.3.4", "5.6.7.8"])
        m.assert_called_once()
        args, kwargs = m.call_args
        assert args[0] == "/shodan/scan"
        # IPs joined with comma
        assert args[1]["ips"] == "1.2.3.4,5.6.7.8"
        assert out == {"id": "abc"}

    def test_get_scan_status(self):
        s = mod.ShodanIntegration(api_key="k")
        with mock.patch.object(s, "_make_request", return_value={"status": "PROCESSING"}) as m:
            out = s.get_scan_status("scan_abc")
        m.assert_called_once_with("/shodan/scan/scan_abc")
        assert out == {"status": "PROCESSING"}


# ---------------------------------------------------------------------------
# format_host_info
# ---------------------------------------------------------------------------

class TestFormatHostInfo:
    def test_basic_format(self):
        data = {
            "ip_str": "1.2.3.4",
            "org": "Test Org",
            "os": "Linux 5.x",
            "location": {"country_name": "US", "city": "NYC",
                         "latitude": 40.7, "longitude": -74.0},
            "hostnames": ["host.example.com"],
            "domains": ["example.com"],
            "ports": [80, 443],
            "vulns": {"CVE-2021-1234": {}, "CVE-2021-5678": {}},
            "last_update": "2024-01-15",
            "tags": ["iot"],
            "asn": "AS12345",
            "isp": "Test ISP",
            "data": [],
        }
        s = mod.ShodanIntegration(api_key="k")
        out = s.format_host_info(data)
        assert out["ip"] == "1.2.3.4"
        assert out["organization"] == "Test Org"
        assert out["operating_system"] == "Linux 5.x"
        assert out["country"] == "US"
        assert out["city"] == "NYC"
        assert out["latitude"] == 40.7
        assert out["longitude"] == -74.0
        assert out["hostnames"] == ["host.example.com"]
        assert out["domains"] == ["example.com"]
        assert out["open_ports"] == [80, 443]
        assert "CVE-2021-1234" in out["vulnerabilities"]
        assert out["last_update"] == "2024-01-15"
        assert out["tags"] == ["iot"]
        assert out["asn"] == "AS12345"
        assert out["isp"] == "Test ISP"
        assert out["services"] == []

    def test_empty_data(self):
        s = mod.ShodanIntegration(api_key="k")
        out = s.format_host_info({})
        # Defaults
        assert out["ip"] == "N/A"
        assert out["organization"] == "N/A"
        assert out["operating_system"] == "N/A"
        assert out["country"] == "N/A"
        assert out["city"] == "N/A"
        assert out["latitude"] == 0
        assert out["longitude"] == 0
        assert out["hostnames"] == []
        assert out["domains"] == []
        assert out["open_ports"] == []
        assert out["vulnerabilities"] == []
        assert out["tags"] == []
        assert out["services"] == []

    def test_services_extracted(self):
        data = {
            "data": [
                {"port": 80, "transport": "tcp", "product": "nginx",
                 "version": "1.21", "data": "HTTP/1.1 200 OK\nServer: nginx",
                 "timestamp": "2024-01-01"},
                {"port": 22, "transport": "tcp", "product": "openssh",
                 "version": "8.4", "data": "SSH-2.0-OpenSSH_8.4",
                 "timestamp": "2024-01-01"},
            ]
        }
        s = mod.ShodanIntegration(api_key="k")
        out = s.format_host_info(data)
        assert len(out["services"]) == 2
        assert out["services"][0]["port"] == 80
        assert out["services"][0]["service"] == "nginx"
        assert out["services"][0]["protocol"] == "tcp"

    def test_banner_truncated(self):
        long_banner = "X" * 500
        data = {
            "data": [
                {"port": 80, "product": "p", "version": "v",
                 "data": long_banner, "timestamp": "t"}
            ]
        }
        s = mod.ShodanIntegration(api_key="k")
        out = s.format_host_info(data)
        # Banner truncated with "..." suffix
        banner = out["services"][0]["banner"]
        assert banner.endswith("...")
        assert len(banner) <= 203  # 200 + "..."

    def test_banner_short(self):
        short_banner = "OK"
        data = {
            "data": [
                {"port": 80, "product": "p", "version": "v",
                 "data": short_banner, "timestamp": "t"}
            ]
        }
        s = mod.ShodanIntegration(api_key="k")
        out = s.format_host_info(data)
        # Short banner: no "..." appended
        assert out["services"][0]["banner"] == "OK"

    def test_default_transport(self):
        data = {
            "data": [
                {"port": 80, "product": "p", "version": "v",
                 "data": "x", "timestamp": "t"}
            ]
        }
        s = mod.ShodanIntegration(api_key="k")
        out = s.format_host_info(data)
        # transport missing → defaults to "tcp"
        assert out["services"][0]["protocol"] == "tcp"


# ---------------------------------------------------------------------------
# Convenience functions
# ---------------------------------------------------------------------------

class TestConvenienceFunctions:
    def test_lookup_ip(self):
        s = mod.ShodanIntegration(api_key="k")
        with mock.patch.object(s, "host_lookup", return_value={"ip": "x"}), \
             mock.patch.object(s, "format_host_info", return_value={"formatted": True}):
            # Re-patch the constructor used inside lookup_ip
            with mock.patch.object(mod, "ShodanIntegration", return_value=s):
                out = mod.lookup_ip("1.2.3.4", api_key="k")
        assert out == {"formatted": True}

    def test_lookup_ip_propagates_api_key(self):
        with mock.patch.object(mod, "ShodanIntegration") as M:
            s = M.return_value
            s.host_lookup.return_value = {}
            s.format_host_info.return_value = {}
            mod.lookup_ip("1.2.3.4", api_key="mykey")
        M.assert_called_once_with("mykey")

    def test_search_shodan(self):
        s = mod.ShodanIntegration(api_key="k")
        with mock.patch.object(s, "search", return_value={
                "matches": [{"ip": "1.2.3.4"}]}), \
             mock.patch.object(s, "format_host_info", return_value={"f": 1}):
            with mock.patch.object(mod, "ShodanIntegration", return_value=s):
                out = mod.search_shodan("apache", limit=5, api_key="k")
        assert out == [{"f": 1}]

    def test_search_shodan_no_matches(self):
        s = mod.ShodanIntegration(api_key="k")
        with mock.patch.object(s, "search", return_value={}), \
             mock.patch.object(s, "format_host_info", return_value={}):
            with mock.patch.object(mod, "ShodanIntegration", return_value=s):
                out = mod.search_shodan("nothing")
        assert out == []

    def test_get_shodan_api_info(self):
        s = mod.ShodanIntegration(api_key="k")
        with mock.patch.object(s, "get_api_info", return_value={"plan": "free"}):
            with mock.patch.object(mod, "ShodanIntegration", return_value=s):
                out = mod.get_shodan_api_info(api_key="k")
        assert out == {"plan": "free"}


# ---------------------------------------------------------------------------
# No fabrication
# ---------------------------------------------------------------------------

class TestNoFabrication:
    def test_no_creds_in_format(self):
        s = mod.ShodanIntegration(api_key="real_api_key_12345")
        out = s.format_host_info({"ip_str": "1.2.3.4", "org": "X"})
        text = str(out)
        for forbidden in ("ecf51ee2-938d", "f40bec4b664a40a9a",
                          "CE38F76832CFA1F6", "password=", "secret="):
            assert forbidden not in text, f"leaked {forbidden!r}"
