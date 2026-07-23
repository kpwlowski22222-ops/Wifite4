"""HTTP smoke tests for the Flask/WSGI RAT dashboard.

Spawns an in-process server, hits index + health APIs, tears down.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request

from core.post_access_tui.rat_ext import spawn_rat_dashboard, RatDashboardServer


def _get(url: str, timeout: float = 3.0):
    req = urllib.request.Request(url, method="GET")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = resp.read()
        return resp.status, body, dict(resp.headers)


def test_spawn_serves_index_and_health_apis():
    res = spawn_rat_dashboard(sessions=[
        {
            "id": "s1",
            "kind": "wifi",
            "transport": "wifi",
            "achieved": {"access", "shell"},
            "label": "lab-ap",
        }
    ])
    assert res.get("ok") is True, res
    base = res["url"].rstrip("/")

    st, body, _ = _get(base + "/")
    assert st == 200
    assert b"html" in body.lower() or b"KFIOSA" in body or b"session" in body.lower()

    for path in (
        "/api/attack_state",
        "/api/v5/health",
        "/api/v6/poll",
        "/api/v4/ai_status",
        "/api/sessions",
    ):
        st, body, _ = _get(base + path)
        assert st == 200, (path, st, body[:200])
        data = json.loads(body.decode("utf-8"))
        assert isinstance(data, dict)


def test_spawn_with_report_derives_session():
    res = spawn_rat_dashboard(
        sessions=[],
        report={
            "access": {
                "achieved": True,
                "session_id": 42,
                "transport": "meterpreter",
                "label": "msf",
            }
        },
    )
    assert res.get("ok") is True
    assert res.get("sessions", 0) >= 1
    st, body, _ = _get(res["url"].rstrip("/") + "/api/sessions")
    assert st == 200
    data = json.loads(body.decode("utf-8"))
    assert data.get("ok") is True
    assert data.get("total", data.get("count", 0)) >= 1


def test_server_shutdown_stops_listen():
    srv = RatDashboardServer(
        roster=[{"id": "x", "transport": "wifi", "achieved": set()}],
        host="127.0.0.1",
        port=0,
    )
    started = srv.try_serve()
    assert started is not None
    port, _t = started
    st, _, _ = _get(f"http://127.0.0.1:{port}/")
    assert st == 200
    srv.shutdown()
