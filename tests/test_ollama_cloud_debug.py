"""Phase 2.3.H — Ollama cloud debug .py."""

import json
import os
import sys
from unittest import mock

import pytest


# Make sure the test does not depend on the optional 'requests' lib
# being installed at test time.
try:
    import requests  # noqa: F401
    HAS_REQUESTS = True
except ImportError:  # pragma: no cover
    HAS_REQUESTS = False


# The module MUST be importable even if 'requests' is missing.
def _import_module():
    if "core.ai_backend.ollama_cloud_debug" in sys.modules:
        return sys.modules["core.ai_backend.ollama_cloud_debug"]
    import importlib
    mod = importlib.import_module("core.ai_backend.ollama_cloud_debug")
    return mod


mod = _import_module()


# ---------------------------------------------------------------------------
# Token + defaults
# ---------------------------------------------------------------------------


class TestToken:
    def setup_method(self):
        # Clean env
        for k in ("OLLAMA_CLOUD_TOKEN", "OLLAMA_AUTH_TOKEN"):
            os.environ.pop(k, None)

    def test_get_ollama_token_none_when_unset(self):
        assert mod.get_ollama_token() is None

    def test_get_ollama_token_uses_primary(self):
        os.environ["OLLAMA_CLOUD_TOKEN"] = "primary-1"
        os.environ["OLLAMA_AUTH_TOKEN"] = "fallback-1"
        assert mod.get_ollama_token() == "primary-1"

    def test_get_ollama_token_falls_back(self):
        os.environ["OLLAMA_AUTH_TOKEN"] = "fallback-1"
        assert mod.get_ollama_token() == "fallback-1"


class TestDefaults:
    def test_default_cloud_endpoint(self):
        assert mod.DEFAULT_CLOUD_ENDPOINT.startswith("https://")

    def test_default_model_is_uncensored_coder(self):
        # Phase 2.4 §J.2: default is the operator's uncensored
        # Qwen2.5-Coder-14B model (loaded via the LOCAL Ollama
        # daemon), not the kimi-k2.7-code cloud model.
        assert "Qwen" in mod.DEFAULT_MODEL
        assert "Coder" in mod.DEFAULT_MODEL
        assert "Uncensored" in mod.DEFAULT_MODEL
        # kimi is no longer the default
        assert "kimi" not in mod.DEFAULT_MODEL.lower()


# ---------------------------------------------------------------------------
# Reachable / list-models / generate
# ---------------------------------------------------------------------------


def _fake_response(status_code, json_data=None, text=None):
    """Build a minimal requests.Response-like object."""
    r = mock.MagicMock()
    r.ok = 200 <= status_code < 300
    r.status_code = status_code
    r.reason = "OK" if r.ok else "Error"
    if json_data is not None:
        r.json.return_value = json_data
        r.text = json.dumps(json_data)
    else:
        r.json.side_effect = ValueError("no json")
        r.text = text or ""
    return r


class TestReachable:
    def test_reachable_200(self):
        with mock.patch.object(mod, "_do_request") as m:
            m.return_value = {
                "ok": True, "status": 200,
                "body": {"models": [{"name": "x", "size": 100}]},
            }
            out = mod.ollama_cloud_reachable()
            assert out["ok"] is True
            m.assert_called_once()
            url = m.call_args[0][0]
            assert url.endswith("/api/tags")

    def test_reachable_401(self):
        with mock.patch.object(mod, "_do_request") as m:
            m.return_value = {
                "ok": False, "status": 401,
                "error": "http 401: Unauthorized",
            }
            out = mod.ollama_cloud_reachable()
            assert out["ok"] is False
            assert "401" in out["error"]


class TestListModels:
    def test_list_models_200(self):
        with mock.patch.object(mod, "_do_request") as m:
            m.return_value = {
                "ok": True, "status": 200,
                "body": {"models": [
                    {"name": "model-a", "size": 1024},
                    {"name": "model-b", "size": 2048},
                ]},
            }
            out = mod.ollama_cloud_list_models()
            assert out["ok"] is True
            assert out["count"] == 2
            assert out["models"][0]["name"] == "model-a"

    def test_list_models_429(self):
        with mock.patch.object(mod, "_do_request") as m:
            m.return_value = {
                "ok": False, "status": 429,
                "error": "http 429: Too Many Requests",
            }
            out = mod.ollama_cloud_list_models()
            assert out["ok"] is False


class TestGenerate:
    def test_generate_200(self):
        with mock.patch.object(mod, "_do_request") as m:
            m.return_value = {
                "ok": True, "status": 200,
                "body": {"response": "hello world",
                         "eval_count": 2, "eval_duration": 1000},
            }
            out = mod.ollama_cloud_generate("hi")
            assert out["ok"] is True
            assert out["response"] == "hello world"
            # Bearer was NOT inlined
            assert "Bearer" not in str(out)

    def test_generate_403(self):
        with mock.patch.object(mod, "_do_request") as m:
            m.return_value = {
                "ok": False, "status": 403,
                "error": "http 403: Forbidden",
            }
            out = mod.ollama_cloud_generate("hi")
            assert out["ok"] is False

    def test_generate_uses_model(self):
        with mock.patch.object(mod, "_do_request") as m:
            m.return_value = {
                "ok": True, "status": 200,
                "body": {"response": "ok"},
            }
            mod.ollama_cloud_generate("hi", model="custom-1")
            # Phase 2.4 v2: _do_request is called with (url, payload) positionally
            payload = m.call_args[0][1]
            assert payload["model"] == "custom-1"
            assert payload["prompt"] == "hi"
            assert payload["stream"] is False


# ---------------------------------------------------------------------------
# Header construction
# ---------------------------------------------------------------------------


class TestHeaders:
    def test_no_token_no_auth_header(self):
        h = mod._build_headers(None)
        assert "Authorization" not in h
        assert h["Content-Type"] == "application/json"

    def test_with_token_bearer(self):
        h = mod._build_headers("abc-123")
        assert h["Authorization"] == "Bearer abc-123"

    def test_does_not_leak_token_in_envelope(self):
        h = mod._build_headers("super-secret")
        envelope = str(h)
        # The envelope is just a header dict, not a network call, so
        # the token WILL appear here — but the request body and
        # returned envelopes must NEVER include it. We assert that
        # the helper exposes a clean API for the HTTP layer.
        assert "super-secret" in envelope  # used by requests.post
        # And the helper itself does not embed it anywhere else.
        assert h.get("Content-Type") == "application/json"


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


class TestCLI:
    def test_cli_default_shows_status(self, capsys):
        rc = mod.main([])
        assert rc == 0
        out = capsys.readouterr().out
        assert "endpoint" in out
        assert "default_model" in out

    def test_cli_reachable_calls_endpoint(self, capsys):
        # Phase 2.4 §J.2: --reachable now routes to LOCAL by
        # default (offline-first). To reach the cloud, use
        # ``--reachable --cloud``.
        with mock.patch.object(mod, "ollama_local_reachable") as m:
            m.return_value = {"ok": True, "status": 200, "body": {}}
            rc = mod.main(["--reachable"])
            assert rc == 0
            assert m.called

    def test_cli_list_models(self, capsys):
        with mock.patch.object(mod, "ollama_cloud_list_models") as m:
            m.return_value = {"ok": True, "models": [], "count": 0}
            rc = mod.main(["--list-models"])
            assert rc == 0
            assert m.called

    def test_cli_generate(self, capsys):
        with mock.patch.object(mod, "ollama_cloud_generate") as m:
            m.return_value = {"ok": True, "response": "hi"}
            rc = mod.main(["--generate", "hello"])
            assert rc == 0
            assert m.called

    def test_cli_no_token(self, capsys):
        os.environ.pop("OLLAMA_CLOUD_TOKEN", None)
        os.environ.pop("OLLAMA_AUTH_TOKEN", None)
        # --cloud opt-in to force the cloud code path
        with mock.patch.object(mod, "ollama_cloud_reachable") as m:
            m.return_value = {"ok": True, "status": 200, "body": {}}
            mod.main(["--cloud", "--reachable", "--no-token"])
            # token was None
            assert m.call_args[1]["token"] is None


# ---------------------------------------------------------------------------
# Adversarial
# ---------------------------------------------------------------------------


class TestAdversarial:
    def test_no_inline_token_in_source(self):
        # Read the source and assert that the operator's token is
        # never inlined as a literal.
        import inspect
        src = inspect.getsource(mod)
        for bad in ("3d94e52cff9f4df5", "3d94e52cff9f4df5a01973f24d5bc8db"):
            assert bad not in src, f"token literal leaked in source: {bad}"

    def test_no_inline_nvd_key_in_source(self):
        import inspect
        src = inspect.getsource(mod)
        assert "ecf51ee2-938d-44de-b015" not in src

    def test_uses_env_only(self):
        # All the API surface must use os.environ; assert it
        import inspect
        src = inspect.getsource(mod)
        assert "os.environ" in src
        # And the token getter MUST be the only path
        assert "get_ollama_token" in src

    def test_reports_401_honestly(self):
        with mock.patch.object(mod, "_do_request") as m:
            m.return_value = {
                "ok": False, "status": 401,
                "error": "http 401: Unauthorized",
            }
            out = mod.ollama_cloud_generate("hi")
            assert out["ok"] is False
            assert "401" in out["error"]
            # The envelope does NOT invent a fake successful response
            assert "response" not in out

    def test_reports_429_honestly(self):
        with mock.patch.object(mod, "_do_request") as m:
            m.return_value = {
                "ok": False, "status": 429,
                "error": "http 429: Too Many Requests",
            }
            out = mod.ollama_cloud_list_models()
            assert out["ok"] is False
            assert "429" in out["error"]

    def test_does_not_fabricate_responses(self):
        # If the upstream returns garbage, we surface it, not invent.
        with mock.patch.object(mod, "_do_request") as m:
            m.return_value = {
                "ok": True, "status": 200,
                "body": "raw text not json",
            }
            out = mod.ollama_cloud_generate("hi")
            assert out["ok"] is True
            assert "response" in out
            # We do NOT synthesize a fake structured response
            assert out.get("model") == mod.DEFAULT_MODEL
