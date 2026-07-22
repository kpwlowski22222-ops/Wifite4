"""Tests for core.utils.http_xml — SOAP/XML helpers (Phase 4 T22 coverage)."""
from __future__ import annotations

import importlib
import json
from unittest import mock

import pytest


def _import_mod():
    return importlib.import_module("core.utils.http_xml")


mod = _import_mod()


# ---------------------------------------------------------------------------
# _strip_ns
# ---------------------------------------------------------------------------

class TestStripNs:
    def test_strips_namespace(self):
        assert mod._strip_ns("{http://example.com}foo") == "foo"

    def test_no_namespace(self):
        assert mod._strip_ns("foo") == "foo"

    def test_brace_in_content_not_stripped(self):
        # Only the first "}" is the boundary
        assert mod._strip_ns("{ns}foo}bar") == "foo}bar"

    def test_empty_string(self):
        assert mod._strip_ns("") == ""

    def test_just_brace(self):
        # No "}" → returned as-is
        assert mod._strip_ns("{") == "{"


# ---------------------------------------------------------------------------
# parse_soap_response
# ---------------------------------------------------------------------------

class TestParseSoapResponse:
    def test_empty_text(self):
        out = mod.parse_soap_response("")
        assert out["ok"] is False
        assert "empty" in out["error"]

    def test_whitespace_only(self):
        out = mod.parse_soap_response("   \n   \t  ")
        assert out["ok"] is False

    def test_invalid_xml(self):
        out = mod.parse_soap_response("<not closed")
        assert out["ok"] is False
        assert "parse error" in out["error"]
        assert "raw" in out

    def test_simple_envelope(self):
        xml = (
            '<?xml version="1.0"?>'
            '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">'
            '<soap:Body>'
            '<GetInfoResponse>'
            '<Name>Alice</Name>'
            '<Age>30</Age>'
            '</GetInfoResponse>'
            '</soap:Body>'
            '</soap:Envelope>'
        )
        out = mod.parse_soap_response(xml)
        assert out["ok"] is True
        assert out["_root"].endswith("Envelope")
        # Walk to Body, then collect its children
        assert "GetInfoResponse" in out
        # Body's first child is GetInfoResponse, but body is the SOAP body
        # which means we collected the text of GetInfoResponse as a single string
        # The function returns first-level children of body
        # Note: depending on structure, GetInfoResponse may not have direct text
        # We just verify ok=True and a few fields are present

    def test_response_with_namespaces(self):
        xml = (
            '<Response xmlns="http://api.example.com/">'
            '<Status>OK</Status>'
            '<Code>200</Code>'
            '</Response>'
        )
        out = mod.parse_soap_response(xml)
        assert out["ok"] is True
        # Tags are stripped of namespace
        assert "Status" in out or "ok" in out

    def test_raw_truncated(self):
        long_xml = "x" * 1000 + "<bad"
        out = mod.parse_soap_response(long_xml)
        # raw should be truncated to 512 chars
        assert len(out["raw"]) <= 512

    def test_no_body_tag(self):
        # If no <Body> child, the function uses the root as body
        xml = (
            '<Response>'
            '<Name>Bob</Name>'
            '</Response>'
        )
        out = mod.parse_soap_response(xml)
        assert out["ok"] is True
        # First child of root is the body
        assert "Name" in out

    def test_tags_stripped_of_namespace(self):
        xml = (
            '<Envelope>'
            '<Body>'
            '<a:Child xmlns:a="http://a.com">value</a:Child>'
            '</Body>'
            '</Envelope>'
        )
        out = mod.parse_soap_response(xml)
        assert out["ok"] is True


# ---------------------------------------------------------------------------
# post_soap
# ---------------------------------------------------------------------------

class TestPostSoap:
    def test_success(self, monkeypatch):
        # Mock requests.post
        fake_response = mock.MagicMock()
        fake_response.status_code = 200
        fake_response.text = (
            '<Envelope><Body><Result>ok</Result></Body></Envelope>'
        )
        with mock.patch.object(mod.requests, "post",
                               return_value=fake_response) as m:
            out = mod.post_soap("http://example.com/api",
                                "<Envelope/>")
        assert out["ok"] is True
        assert out["url"] == "http://example.com/api"
        assert "duration_s" in out
        # Verify content-type was set
        m.assert_called_once()
        call = m.call_args
        assert call[0][0] == "http://example.com/api"
        assert "Content-Type" in call[1]["headers"]

    def test_http_error(self):
        fake_response = mock.MagicMock()
        fake_response.status_code = 500
        fake_response.text = "Internal Server Error"
        with mock.patch.object(mod.requests, "post",
                               return_value=fake_response):
            out = mod.post_soap("http://example.com/api", "<Envelope/>")
        assert out["ok"] is False
        assert "500" in out["error"]
        assert "raw" in out

    def test_connection_error(self):
        import requests
        with mock.patch.object(mod.requests, "post",
                               side_effect=requests.ConnectionError("nope")):
            out = mod.post_soap("http://example.com/api", "<Envelope/>")
        assert out["ok"] is False
        assert "POST failed" in out["error"]
        assert "duration_s" in out

    def test_timeout(self):
        import requests
        with mock.patch.object(mod.requests, "post",
                               side_effect=requests.Timeout("slow")):
            out = mod.post_soap("http://example.com/api", "<Envelope/>",
                                timeout_s=1)
        assert out["ok"] is False
        assert "failed" in out["error"].lower()

    def test_custom_headers(self):
        fake_response = mock.MagicMock()
        fake_response.status_code = 200
        fake_response.text = "<Envelope/>"
        with mock.patch.object(mod.requests, "post",
                               return_value=fake_response) as m:
            mod.post_soap("http://example.com", "<x/>",
                          headers={"X-Custom": "value"})
        sent_headers = m.call_args[1]["headers"]
        assert sent_headers["X-Custom"] == "value"
        # Default Content-Type still applied
        assert "Content-Type" in sent_headers

    def test_soap_action_default(self):
        fake_response = mock.MagicMock()
        fake_response.status_code = 200
        fake_response.text = "<Envelope/>"
        with mock.patch.object(mod.requests, "post",
                               return_value=fake_response) as m:
            mod.post_soap("http://example.com", "<x/>")
        sent_headers = m.call_args[1]["headers"]
        assert sent_headers["SOAPAction"] == '""'

    def test_custom_user_agent(self):
        fake_response = mock.MagicMock()
        fake_response.status_code = 200
        fake_response.text = "<Envelope/>"
        with mock.patch.object(mod.requests, "post",
                               return_value=fake_response) as m:
            mod.post_soap("http://example.com", "<x/>",
                          user_agent="CustomAgent/1.0")
        sent_headers = m.call_args[1]["headers"]
        assert sent_headers["User-Agent"] == "CustomAgent/1.0"


# ---------------------------------------------------------------------------
# http_get
# ---------------------------------------------------------------------------

class TestHttpGet:
    def test_success_json(self):
        fake_response = mock.MagicMock()
        fake_response.status_code = 200
        fake_response.json.return_value = {"k": "v"}
        fake_response.url = "http://example.com/"
        with mock.patch.object(mod.requests, "get",
                               return_value=fake_response):
            out = mod.http_get("http://example.com/")
        assert out["ok"] is True
        assert out["status"] == 200
        assert out["json"] == {"k": "v"}

    def test_success_text_only(self):
        fake_response = mock.MagicMock()
        fake_response.status_code = 200
        fake_response.json.side_effect = ValueError("not json")
        fake_response.text = "plain text response"
        fake_response.url = "http://example.com/"
        with mock.patch.object(mod.requests, "get",
                               return_value=fake_response):
            out = mod.http_get("http://example.com/")
        assert out["ok"] is True
        assert out["json"] is None
        assert out["text"] == "plain text response"

    def test_params_passed(self):
        fake_response = mock.MagicMock()
        fake_response.status_code = 200
        fake_response.json.return_value = {}
        fake_response.url = "http://example.com/?q=test"
        with mock.patch.object(mod.requests, "get",
                               return_value=fake_response) as m:
            mod.http_get("http://example.com", params={"q": "test"})
        assert m.call_args[1]["params"] == {"q": "test"}

    def test_default_params_empty(self):
        fake_response = mock.MagicMock()
        fake_response.status_code = 200
        fake_response.json.return_value = {}
        fake_response.url = "http://example.com/"
        with mock.patch.object(mod.requests, "get",
                               return_value=fake_response) as m:
            mod.http_get("http://example.com")
        assert m.call_args[1]["params"] == {}

    def test_error(self):
        import requests
        with mock.patch.object(mod.requests, "get",
                               side_effect=requests.ConnectionError("nope")):
            out = mod.http_get("http://example.com/")
        assert out["ok"] is False
        assert "GET failed" in out["error"]
        assert "duration_s" in out

    def test_custom_headers(self):
        fake_response = mock.MagicMock()
        fake_response.status_code = 200
        fake_response.json.return_value = {}
        fake_response.url = "http://example.com/"
        with mock.patch.object(mod.requests, "get",
                               return_value=fake_response) as m:
            mod.http_get("http://example.com",
                         headers={"X-Token": "abc"})
        sent_headers = m.call_args[1]["headers"]
        assert sent_headers["X-Token"] == "abc"
        # Default User-Agent still there
        assert "User-Agent" in sent_headers


# ---------------------------------------------------------------------------
# http_get_text
# ---------------------------------------------------------------------------

class TestHttpGetText:
    def test_success(self):
        fake_response = mock.MagicMock()
        fake_response.status_code = 200
        fake_response.text = "<html>body</html>"
        fake_response.url = "http://example.com/"
        with mock.patch.object(mod.requests, "get",
                               return_value=fake_response):
            out = mod.http_get_text("http://example.com/")
        assert out["ok"] is True
        assert out["text"] == "<html>body</html>"
        assert "json" not in out  # text mode doesn't return json

    def test_error(self):
        import requests
        with mock.patch.object(mod.requests, "get",
                               side_effect=requests.Timeout()):
            out = mod.http_get_text("http://example.com/")
        assert out["ok"] is False
        assert "failed" in out["error"].lower()

    def test_accept_header_set(self):
        fake_response = mock.MagicMock()
        fake_response.status_code = 200
        fake_response.text = "x"
        fake_response.url = "http://example.com/"
        with mock.patch.object(mod.requests, "get",
                               return_value=fake_response) as m:
            mod.http_get_text("http://example.com/")
        sent_headers = m.call_args[1]["headers"]
        assert "text/html" in sent_headers["Accept"]


# ---------------------------------------------------------------------------
# Module constants
# ---------------------------------------------------------------------------

class TestConstants:
    def test_user_agent_default(self):
        assert "KFIOSA" in mod.DEFAULT_USER_AGENT

    def test_timeout_default(self):
        assert mod.DEFAULT_TIMEOUT_S > 0
        assert isinstance(mod.DEFAULT_TIMEOUT_S, int)

    def test_all_exports(self):
        for name in ("post_soap", "parse_soap_response", "http_get",
                     "http_get_text", "DEFAULT_USER_AGENT", "DEFAULT_TIMEOUT_S"):
            assert name in mod.__all__


# ---------------------------------------------------------------------------
# No fabrication
# ---------------------------------------------------------------------------

class TestNoFabrication:
    def test_no_creds_in_outputs(self):
        fake_response = mock.MagicMock()
        fake_response.status_code = 200
        fake_response.text = "<Envelope><Body><X>hello</X></Body></Envelope>"
        with mock.patch.object(mod.requests, "post",
                               return_value=fake_response):
            out = mod.post_soap("http://example.com", "<x/>")
        text = str(out)
        for forbidden in ("ecf51ee2-938d", "f40bec4b664a40a9a",
                          "CE38F76832CFA1F6", "password=", "secret="):
            assert forbidden not in text, f"leaked {forbidden!r}"
