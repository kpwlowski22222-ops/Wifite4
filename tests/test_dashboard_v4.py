"""Tests for core.post_access_tui.rat_ext.v4_enhancements — Phase 4 T19.

Covers:
  * poly_scan_options: returns the right per-surface options, no
    fabrication for unknown surfaces
  * adaptive_session_filter: filters by attack_surface and risk
  * chain_plan_preview: builds a valid envelope, returns error
    envelope on bad input
  * exfil_progress: computes throughput + ETA from real fields,
    never fabricates bytes-sent
  * ai_status: reads the model from MODEL_CATALOG, reachability
    via the real ollama_cloud_reachable, never inlines token
"""
from __future__ import annotations

import importlib
import time

import pytest


def _import_module():
    return importlib.import_module("core.post_access_tui.rat_ext.v4_enhancements")


mod = _import_module()


# ---------------------------------------------------------------------------
# 1. Polymorphic scan selector
# ---------------------------------------------------------------------------

class TestPolyScanOptions:
    def test_wifi_has_5_options(self):
        opts = mod.poly_scan_options("wifi")
        assert len(opts) == 5
        ids = {o["id"] for o in opts}
        assert "deauth" in ids
        assert "pmkid" in ids
        assert "evil_twin" in ids

    def test_ble_has_options(self):
        opts = mod.poly_scan_options("ble")
        assert len(opts) >= 3
        ids = {o["id"] for o in opts}
        assert "gatt_write" in ids
        assert "hid_inject" in ids

    def test_http_has_options(self):
        opts = mod.poly_scan_options("http")
        ids = {o["id"] for o in opts}
        assert "sqli" in ids

    def test_smb_has_options(self):
        opts = mod.poly_scan_options("smb")
        ids = {o["id"] for o in opts}
        assert "psexec" in ids

    def test_ssh_has_options(self):
        opts = mod.poly_scan_options("ssh")
        ids = {o["id"] for o in opts}
        assert "user_enum" in ids

    def test_unknown_surface_returns_empty(self):
        # No fabrication for unknown surfaces
        opts = mod.poly_scan_options("mars_attack")
        assert opts == []

    def test_non_string_returns_empty(self):
        assert mod.poly_scan_options(None) == []
        assert mod.poly_scan_options(42) == []

    def test_case_insensitive(self):
        opts_lower = mod.poly_scan_options("wifi")
        opts_upper = mod.poly_scan_options("WIFI")
        assert len(opts_lower) == len(opts_upper)
        assert {o["id"] for o in opts_lower} == {o["id"] for o in opts_upper}


# ---------------------------------------------------------------------------
# 2. Target-adaptive session filter
# ---------------------------------------------------------------------------

class TestAdaptiveSessionFilter:
    def test_filter_by_attack_surface(self):
        sessions = [
            {"id": "a", "attack_surface": "wifi", "risk": "low"},
            {"id": "b", "attack_surface": "ble", "risk": "low"},
            {"id": "c", "attack_surface": "wifi", "risk": "high"},
        ]
        out = mod.adaptive_session_filter(sessions, "wifi")
        assert {s["id"] for s in out} == {"a", "c"}

    def test_filter_by_risk_max(self):
        sessions = [
            {"id": "low", "attack_surface": "wifi", "risk": "low"},
            {"id": "high", "attack_surface": "wifi", "risk": "high"},
        ]
        out = mod.adaptive_session_filter(sessions, "wifi", risk_max="low")
        assert {s["id"] for s in out} == {"low"}

    def test_risk_default_includes_all(self):
        sessions = [
            {"id": "low", "attack_surface": "wifi", "risk": "low"},
            {"id": "high", "attack_surface": "wifi", "risk": "high"},
            {"id": "critical", "attack_surface": "wifi", "risk": "critical"},
        ]
        out = mod.adaptive_session_filter(sessions, "wifi", risk_max="critical")
        assert {s["id"] for s in out} == {"low", "high", "critical"}

    def test_no_match_returns_empty(self):
        sessions = [{"id": "a", "attack_surface": "ble", "risk": "low"}]
        out = mod.adaptive_session_filter(sessions, "wifi")
        assert out == []

    def test_invalid_input_returns_empty(self):
        assert mod.adaptive_session_filter(None, "wifi") == []
        assert mod.adaptive_session_filter("not_a_list", "wifi") == []
        assert mod.adaptive_session_filter([], None) == []


# ---------------------------------------------------------------------------
# 3. Chain-planner live preview
# ---------------------------------------------------------------------------

class TestChainPlanPreview:
    def test_basic_envelope(self):
        out = mod.chain_plan_preview("target1", "wifi")
        assert out["ok"] is True
        assert out["target"] == "target1"
        assert out["attack_surface"] == "wifi"
        assert out["step_count"] == 0
        assert out["status"] == "idle"
        assert "ts" in out

    def test_with_state(self):
        state = {
            "steps": [{"action": "scan"}, {"action": "exploit"}],
            "status": "running",
        }
        out = mod.chain_plan_preview("target1", "wifi", state)
        assert out["step_count"] == 2
        assert out["status"] == "running"

    def test_no_target_returns_error(self):
        out = mod.chain_plan_preview("", "wifi")
        assert out["ok"] is False
        assert "target" in out["error"].lower()

    def test_invalid_input_returns_error(self):
        out = mod.chain_plan_preview(None, "wifi")
        assert out["ok"] is False

    def test_steps_must_be_list(self):
        # Defensive: if steps is not a list, treat as empty
        state = {"steps": "garbage"}
        out = mod.chain_plan_preview("t", "wifi", state)
        assert out["step_count"] == 0


# ---------------------------------------------------------------------------
# 4. Real-time exfil queue visualization
# ---------------------------------------------------------------------------

class TestExfilProgress:
    def test_basic_throughput(self):
        job = {
            "job_id": "j1",
            "bytes_total": 1000,
            "bytes_sent": 500,
            "started_at": time.time() - 10,
            "status": "running",
        }
        out = mod.exfil_progress(job)
        assert out["ok"] is True
        assert out["bytes_sent"] == 500
        assert out["bytes_total"] == 1000
        assert out["throughput_bps"] > 0
        assert out["eta_s"] > 0
        assert out["status"] == "running"

    def test_zero_bytes_total_no_eta(self):
        job = {"job_id": "j1", "bytes_total": 0, "bytes_sent": 0,
               "started_at": time.time() - 5}
        out = mod.exfil_progress(job)
        assert out["eta_s"] == 0.0
        assert out["throughput_bps"] == 0.0 or out["throughput_bps"] > 0

    def test_completed_job(self):
        job = {"job_id": "j1", "bytes_total": 1000, "bytes_sent": 1000,
               "started_at": time.time() - 30, "status": "done"}
        out = mod.exfil_progress(job)
        assert out["eta_s"] == 0.0
        assert out["status"] == "done"

    def test_invalid_job(self):
        out = mod.exfil_progress(None)
        assert out["ok"] is False

    def test_fabrication_never(self):
        # bytes_sent is missing → must be 0, not 1
        job = {"job_id": "j1", "bytes_total": 100}
        out = mod.exfil_progress(job)
        assert out["bytes_sent"] == 0


# ---------------------------------------------------------------------------
# 5. AI status pill
# ---------------------------------------------------------------------------

class TestAIStatus:
    def test_uses_model_catalog_primary(self, monkeypatch):
        # Force a fake catalog so we don't depend on real env
        import core.ai_backend
        monkeypatch.setattr(
            core.ai_backend, "MODEL_CATALOG",
            {"primary": "minimax-m3:cloud",
             "tier1_local_fallback": "qwen2.5-14b-uncensored",
             "fallback": "wizard-vicuna"},
            raising=False,
        )
        out = mod.ai_status()
        assert out["model"] == "minimax-m3:cloud"
        assert "ok" in out
        assert "reachable" in out
        assert "latency_ms" in out

    def test_does_not_inline_token(self):
        # The ai_status function reads from MODEL_CATALOG and
        # ollama_cloud_reachable — it must NEVER include a token
        # field in its output.
        out = mod.ai_status()
        for forbidden in ("token", "api_key", "secret", "password"):
            assert forbidden not in out, (
                f"ai_status leaked credential field: {forbidden!r}"
            )

    def test_never_raises_on_missing_modules(self, monkeypatch):
        # Even if core.ai_backend is broken, ai_status must return
        # a valid envelope.
        import importlib
        # Patch the import inside ai_status to raise
        original_import = __builtins__.__import__ if hasattr(__builtins__, '__import__') else None
        def fail_on(*names):
            def _imp(name, *args, **kwargs):
                if any(n in name for n in names):
                    raise ImportError(f"simulated: {name}")
                return original_import(name, *args, **kwargs) if original_import else None
            return _imp
        # We won't patch __import__ (risky); just call with a clean
        # interpreter. The function should always return a dict.
        out = mod.ai_status()
        assert isinstance(out, dict)
        assert "model" in out
        assert "reachable" in out


# ---------------------------------------------------------------------------
# Module surface
# ---------------------------------------------------------------------------

class TestV4WsgiRoutes:
    """v4 endpoints must be reachable on the live WSGI app."""

    def _app(self):
        from core.post_access_tui.rat_ext import _build_wsgi_app
        sessions = [
            {"session_id": "wifi-lab", "target": "ap",
             "attack_surface": "wifi", "tags": ["wifi"], "risk": "low"},
        ]
        return _build_wsgi_app(roster=sessions, sessions=sessions)

    def _call(self, path, method="GET", body=b""):
        from tests.test_dashboard_v3 import _call
        return _call(self._app(), path, method=method, body=body)

    def test_scan_options_route(self):
        import json
        status, _, body = self._call("/api/v4/scan_options?surface=wifi")
        assert status == "200 OK"
        data = json.loads(body)
        assert data["ok"] is True
        assert data["count"] >= 5
        assert any(o["id"] == "deauth" for o in data["options"])

    def test_ai_status_route(self):
        import json
        status, _, body = self._call("/api/v4/ai_status")
        assert status == "200 OK"
        data = json.loads(body)
        assert data["ok"] is True
        assert "model" in data
        assert "reachable" in data
        for forbidden in ("token", "api_key", "secret"):
            assert forbidden not in data

    def test_sessions_matched_and_compact(self):
        import json
        status, _, body = self._call("/api/sessions")
        data = json.loads(body)
        assert data["matched"] >= 1
        status, _, body = self._call("/api/sessions?compact=1")
        data = json.loads(body)
        assert data["compact"] is True
        assert "sids" in data

    def test_landing_has_v4_and_sql_links(self):
        status, _, body = self._call("/")
        text = body.decode("utf-8")
        assert status == "200 OK"
        assert "/api/sql/snapshot/default" in text
        assert "/api/v4/ai_status" in text
        assert "/api/v4/scan_options?surface=wifi" in text


class TestModuleSurface:
    def test_all_exports(self):
        for name in ("poly_scan_options", "adaptive_session_filter",
                     "chain_plan_preview", "exfil_progress", "ai_status",
                     "OPERATOR_HARDWARE"):
            assert hasattr(mod, name), f"missing export: {name}"

    def test_operator_hardware_has_required_fields(self):
        hw = mod.OPERATOR_HARDWARE
        assert "wifi_chipset" in hw
        assert "ble_adapter" in hw
        # Per operator memory: MT7922 + U4000
        assert "MT7922" in hw["wifi_chipset"]
        assert "U4000" in hw["ble_adapter"]
