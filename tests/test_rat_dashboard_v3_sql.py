"""tests.test_rat_dashboard_v3_sql — Phase 2.4 v3 dashboard SQL endpoints.

The dashboard exposes a set of SQL read-only endpoints that mirror
the in-memory session state to a persistent store. This test file
exercises every new endpoint:

  * /api/sql_health        — backend health + table counts
  * /api/sql/sessions      — list all sessions
  * /api/sql/log/<sid>     — last N log rows for a session
  * /api/sql/history/<sid> — last N history rows for a session
  * /api/sql/exfil/<sid>   — exfil queue
  * /api/sql/persistence/<sid> — persistence mechanisms
  * /api/sql/snapshot/<sid> — combined one-shot view
"""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Tuple

import pytest


@pytest.fixture
def wsgi_env():
    """Build a minimal WSGI env caller for the dashboard app."""
    from core.post_access_tui.rat_ext import _build_wsgi_app

    roster: List[Dict[str, Any]] = [
        {
            "id": "sess-A",
            "session_id": "sess-A",
            "transport": "ble",
            "target": "AA:BB:CC:DD:EE:FF",
            "achieved": ["connect"],
            "capabilities": [
                {"name": "gatt_read", "label": "GATT read",
                 "risk": "read", "description": "Read GATT char"},
            ],
        },
    ]
    app = _build_wsgi_app(roster)

    # Use a temp DB path for the SQL store
    tmp = tempfile.mkdtemp(prefix="kfiosa-dash-")
    db_path = Path(tmp) / "test.db"
    os.environ["KFIOSA_SQLITE_PATH"] = str(db_path)
    # Reset thread-local connection so the new path is picked up
    try:
        from core.db import sqlstore
        sqlstore.close()
    except Exception:  # noqa: BLE001
        pass

    def call(path: str, method: str = "GET",
             query: str = "") -> Tuple[int, Dict[str, str], bytes]:
        # Strip query from path so the env var matches the route
        if "?" in path:
            path, query = path.split("?", 1)
        env = {
            "PATH_INFO": path,
            "REQUEST_METHOD": method,
            "QUERY_STRING": query,
            "HTTP_HOST": "localhost:1",
            "SERVER_NAME": "localhost",
            "CONTENT_TYPE": "application/json",
        }
        captured: List[Tuple[str, List[Tuple[str, str]]]] = []

        def start(status, headers):
            captured.append((status, headers))

        body = app(env, start)
        status = captured[0][0] if captured else "000"
        headers_list = captured[0][1] if captured else []
        headers = {k: v for k, v in headers_list}
        return status, headers, b"".join(body) if body else b""

    return call


def _init_sql_with_data(sid: str = "sess-A") -> None:
    """Populate the SQL store with one session, one log, one history."""
    from core.db import sqlstore
    sqlstore.init()
    sqlstore.record_session(
        sid, kind="ble", target="AA:BB:CC:DD:EE:FF",
        meta={"transport": "ble", "achieved": ["connect"]},
    )
    sqlstore.append_log(sid, "step_started", {"msg": "starting chain step"})
    sqlstore.append_history(sid, "cmd", {"cmd": "whoami", "ts": 1.0})
    sqlstore.add_exfil(sid, channel="http", bytes_pending=1024, status="pending")
    sqlstore.add_persistence(
        sid, mech_id="schtasks-A", kind="scheduled_task", state="installed",
    )


def test_sql_health(wsgi_env):
    status, _, body = wsgi_env("/api/sql_health")
    assert status == "200 OK"
    payload = json.loads(body)
    assert payload["ok"] is True
    assert "store" in payload
    assert "backend" in payload
    assert payload["model"] == "rat-dashboard-v3"


def test_sql_sessions(wsgi_env):
    _init_sql_with_data()
    status, _, body = wsgi_env("/api/sql/sessions")
    assert status == "200 OK"
    payload = json.loads(body)
    assert payload["ok"] is True
    assert isinstance(payload["sessions"], list)
    assert any(s.get("sid") == "sess-A" for s in payload["sessions"])


def test_sql_log_endpoint(wsgi_env):
    _init_sql_with_data()
    status, _, body = wsgi_env("/api/sql/log/sess-A?limit=5")
    assert status == "200 OK"
    payload = json.loads(body)
    assert payload["ok"] is True
    assert payload["sid"] == "sess-A"
    assert payload["limit"] == 5
    assert isinstance(payload["log"], list)


def test_sql_log_default_sid(wsgi_env):
    _init_sql_with_data()
    status, _, body = wsgi_env("/api/sql/log/default?limit=10")
    assert status == "200 OK"
    payload = json.loads(body)
    assert payload["ok"] is True
    assert payload["sid"] == "default"
    assert payload["limit"] == 10


def test_sql_history_endpoint(wsgi_env):
    _init_sql_with_data()
    status, _, body = wsgi_env("/api/sql/history/sess-A?limit=5")
    assert status == "200 OK"
    payload = json.loads(body)
    assert payload["ok"] is True
    assert payload["sid"] == "sess-A"
    assert isinstance(payload["history"], list)


def test_sql_exfil_endpoint(wsgi_env):
    _init_sql_with_data()
    status, _, body = wsgi_env("/api/sql/exfil/sess-A")
    assert status == "200 OK"
    payload = json.loads(body)
    assert payload["ok"] is True
    assert isinstance(payload["exfil"], list)


def test_sql_persistence_endpoint(wsgi_env):
    _init_sql_with_data()
    status, _, body = wsgi_env("/api/sql/persistence/sess-A")
    assert status == "200 OK"
    payload = json.loads(body)
    assert payload["ok"] is True
    assert isinstance(payload["persistence"], list)


def test_sql_snapshot_endpoint(wsgi_env):
    _init_sql_with_data()
    status, _, body = wsgi_env("/api/sql/snapshot/sess-A")
    assert status == "200 OK"
    payload = json.loads(body)
    assert payload["ok"] is True
    assert "log" in payload
    assert "history" in payload
    assert "exfil" in payload
    assert "persistence" in payload
    assert payload["model"] == "rat-dashboard-v3"


def test_sql_log_limit_clamped(wsgi_env):
    """Limit > 500 must be clamped to 500."""
    _init_sql_with_data()
    status, _, body = wsgi_env("/api/sql/log/sess-A?limit=99999")
    assert status == "200 OK"
    payload = json.loads(body)
    assert payload["limit"] == 500


def test_sql_log_limit_min(wsgi_env):
    """Limit < 1 must be clamped to 1."""
    _init_sql_with_data()
    status, _, body = wsgi_env("/api/sql/log/sess-A?limit=0")
    assert status == "200 OK"
    payload = json.loads(body)
    assert payload["limit"] == 1


def test_sql_log_invalid_limit_falls_back(wsgi_env):
    """Invalid (non-numeric) limit falls back to 50."""
    _init_sql_with_data()
    status, _, body = wsgi_env("/api/sql/log/sess-A?limit=notanumber")
    assert status == "200 OK"
    payload = json.loads(body)
    assert payload["limit"] == 50


def test_sql_log_unknown_sid_returns_empty(wsgi_env):
    _init_sql_with_data()
    status, _, body = wsgi_env("/api/sql/log/never-existed")
    assert status == "200 OK"
    payload = json.loads(body)
    assert payload["ok"] is True
    # list_log returns [] for an unknown sid
    assert payload["log"] == []


def test_sql_redaction_in_history(wsgi_env):
    """Keys/credentials in payload must be redacted before storage."""
    from core.db import sqlstore
    sqlstore.init()
    # Simulate a row that contains a known-bad token
    sqlstore.append_history(
        "sess-redact", "test",
        {"msg": "Authorization: Bearer 3d94e52cff9f4df5a01973f24d5bc8db"},
    )
    status, _, body = wsgi_env("/api/sql/history/sess-redact?limit=5")
    assert status == "200 OK"
    payload = json.loads(body)
    # The token must not be in the response body
    text = body.decode("utf-8")
    assert "3d94e52cff9f4df5a01973f24d5bc8db" not in text


def test_dashboard_landing_has_sql_links(wsgi_env):
    """The HTML landing page must include the new SQL link."""
    status, headers, body = wsgi_env("/")
    assert status == "200 OK"
    text = body.decode("utf-8")
    assert "/api/sql/snapshot/default" in text
    assert "/api/sql/log/default" in text
    assert "/api/sql/history/default" in text
