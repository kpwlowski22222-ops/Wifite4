"""Tests for Flask/WSGI dashboard v5 UX enhancements."""
from __future__ import annotations

import json
from typing import Any, Dict

import pytest

from core.post_access_tui.rat_ext import _build_wsgi_app
from core.post_access_tui.rat_ext import v5_enhancements as v5
from core.post_access_tui.rat_ext.rat_dynamic import build_rat_dashboard_html


def _call(app, path: str, method: str = "GET", body: bytes = b"",
          headers: Dict[str, str] = None):
    headers = headers or {}
    if "?" in path:
        path_only, qs = path.split("?", 1)
    else:
        path_only, qs = path, ""
    environ = {
        "REQUEST_METHOD": method,
        "PATH_INFO": path_only,
        "QUERY_STRING": qs,
        "SERVER_NAME": "127.0.0.1",
        "SERVER_PORT": "9999",
        "wsgi.input": __import__("io").BytesIO(body),
        "CONTENT_LENGTH": str(len(body)),
        "HTTP_HOST": "127.0.0.1:9999",
    }
    for k, v in headers.items():
        environ[k] = v
    status_headers = {}
    body_parts = []

    def start_response(status, hdrs):
        status_headers["status"] = status
        status_headers["headers"] = dict(hdrs)

    out = app(environ, start_response)
    for chunk in out:
        body_parts.append(chunk)
    return status_headers["status"], status_headers["headers"], b"".join(body_parts)


@pytest.fixture
def app():
    roster = [
        {
            "id": "sess-wifi-1",
            "session_id": "sess-wifi-1",
            "transport": "wifi",
            "kind": "wifi",
            "target": "AA:BB:CC:DD:EE:FF",
            "achieved": ["handshake"],
            "capabilities": [
                {"name": "recon", "label": "Recon", "risk": "read",
                 "description": "read-only"},
            ],
        },
        {
            "id": "sess-ble-1",
            "session_id": "sess-ble-1",
            "transport": "ble",
            "kind": "ble",
            "target": "11:22:33:44:55:66",
            "achieved": ["gatt_connect"],
        },
    ]
    return _build_wsgi_app(roster, sessions=roster)


def test_v5_health(app):
    status, hdrs, body = _call(app, "/api/v5/health")
    assert status.startswith("200")
    data = json.loads(body)
    assert data["ok"] is True
    assert "uptime_s" in data
    assert "ai" in data
    assert "sql" in data
    assert "scan" in data
    assert data["sessions"] == 2


def test_v5_summary(app):
    status, _, body = _call(app, "/api/v5/summary")
    assert status.startswith("200")
    data = json.loads(body)
    assert data["total"] == 2
    assert data["by_kind"].get("wifi") == 1
    assert data["by_kind"].get("ble") == 1
    assert data["with_access"] >= 1


def test_v5_shortcuts(app):
    status, _, body = _call(app, "/api/v5/shortcuts")
    data = json.loads(body)
    assert data["ok"] is True
    assert "/" in data["shortcuts"]


def test_v5_refresh(app):
    status, _, body = _call(app, "/api/v5/refresh")
    data = json.loads(body)
    assert data["ok"] is True
    assert data["ai_status_ms"] >= 1000


def test_cap_includes_pretty(app):
    def runner(sid, cap):
        return {"ok": True, "session_id": sid, "capability": cap, "data": {"x": 1}}

    app2 = _build_wsgi_app(
        [{"id": "s1", "session_id": "s1", "kind": "wifi"}],
        capability_runner=runner,
        sessions=[{"id": "s1", "session_id": "s1", "kind": "wifi"}],
    )
    status, _, body = _call(app2, "/cap/s1/recon")
    data = json.loads(body)
    assert "pretty" in data
    assert "x" in data["pretty"]


def test_format_capability_redacts_secrets():
    out = v5.format_capability_result({
        "ok": True,
        "password": "hunter2",
        "data": {"n": 1},
    })
    assert out["ok"] is True
    assert "hunter2" not in out["pretty"]
    assert "[redacted]" in out["pretty"]


def test_html_includes_v5_shell():
    html = build_rat_dashboard_html([])
    assert "health-pill" in html
    assert "/api/v5/health" in html
    assert "drawer" in html
    assert "keyboard" in html.lower() or "help-dl" in html
    # no double dead return issues — single closing body
    assert html.count("</body>") == 1


def test_session_summary_unit():
    s = v5.session_summary([
        {"kind": "wifi", "achieved": ["x"], "risk": "read"},
        {"kind": "wifi", "risk": "destructive"},
    ])
    assert s["total"] == 2
    assert s["by_kind"]["wifi"] == 2
    assert s["with_access"] == 1
