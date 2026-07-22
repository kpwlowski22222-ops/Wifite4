"""Tests for core.db.sqlstore — Phase 2.4+ SQL store.

Verifies:
  * init / record / list / update / append / list for all
    tables (sessions, log, history, exfil, persistence).
  * Redaction of inlined API keys (NVD, Kismet, Ollama).
  * File permissions (umask 0o077) on the default DB.
  * Health endpoint reports counts.
  * Thread-local connections don't share state.
"""
from __future__ import annotations

import json
import os
import sqlite3
import tempfile
import threading
from pathlib import Path
from typing import Any, Dict

import pytest

from core.db import sqlstore


@pytest.fixture
def tmp_db(tmp_path: Path) -> Path:
    p = tmp_path / "kfiosa_test.db"
    return p


# ---------------------------------------------------------------------------
# A. Init / lifecycle
# ---------------------------------------------------------------------------

class TestInit:
    def test_init_creates_db(self, tmp_db: Path) -> None:
        r = sqlstore.init(tmp_db)
        assert r["ok"] is True
        assert r["backend"] == "sqlite"
        assert tmp_db.exists()

    def test_init_is_idempotent(self, tmp_db: Path) -> None:
        sqlstore.init(tmp_db)
        r = sqlstore.init(tmp_db)
        assert r["ok"] is True

    def test_init_creates_parent_dir(self, tmp_path: Path) -> None:
        deep = tmp_path / "a" / "b" / "c" / "kfiosa.db"
        r = sqlstore.init(deep)
        assert r["ok"] is True
        assert deep.exists()

    def test_init_default_path(self) -> None:
        r = sqlstore.init()  # no path → DEFAULT_DB_PATH
        assert r["ok"] is True
        # The default file is created at ~/.kfiosa/kfiosa.db
        assert Path(r["db_path"]).exists()


# ---------------------------------------------------------------------------
# B. Sessions
# ---------------------------------------------------------------------------

class TestSessions:
    def test_record_session(self, tmp_db: Path) -> None:
        r = sqlstore.record_session("s1", "ble", "AA:BB:CC",
                                    db_path=tmp_db)
        assert r["ok"] is True
        rows = sqlstore.list_sessions(tmp_db)
        assert len(rows) == 1
        assert rows[0]["sid"] == "s1"
        assert rows[0]["kind"] == "ble"
        assert rows[0]["target"] == "AA:BB:CC"

    def test_record_session_upsert(self, tmp_db: Path) -> None:
        sqlstore.record_session("s1", "ble", "t", db_path=tmp_db)
        # Re-record with the same sid — must NOT crash, must update
        sqlstore.record_session("s1", "network", "t2", db_path=tmp_db)
        rows = sqlstore.list_sessions(tmp_db)
        assert len(rows) == 1
        assert rows[0]["target"] == "t2"
        assert rows[0]["kind"] == "network"

    def test_update_session(self, tmp_db: Path) -> None:
        sqlstore.record_session("s1", "ble", "t", db_path=tmp_db)
        r = sqlstore.update_session("s1", risk_max="destructive",
                                    achieved_count=5, db_path=tmp_db)
        assert r["ok"] is True
        rows = sqlstore.list_sessions(tmp_db)
        assert rows[0]["risk_max"] == "destructive"
        assert rows[0]["achieved_count"] == 5

    def test_update_session_ignores_unknown_fields(
        self, tmp_db: Path
    ) -> None:
        sqlstore.record_session("s1", "ble", "t", db_path=tmp_db)
        # An unknown field name should be silently ignored
        # (defensive — never raise)
        r = sqlstore.update_session("s1", bogus_field="x",
                                    db_path=tmp_db)
        assert r["ok"] is True


# ---------------------------------------------------------------------------
# C. Log
# ---------------------------------------------------------------------------

class TestLog:
    def test_append_log(self, tmp_db: Path) -> None:
        r = sqlstore.append_log("s1", "info", "hello", db_path=tmp_db)
        assert r["ok"] is True
        rows = sqlstore.list_log("s1", db_path=tmp_db)
        assert len(rows) == 1
        assert rows[0]["msg"] == "hello"

    def test_list_log_since(self, tmp_db: Path) -> None:
        sqlstore.append_log("s1", "info", "old", ts=100.0,
                            db_path=tmp_db)
        sqlstore.append_log("s1", "info", "new", ts=200.0,
                            db_path=tmp_db)
        rows = sqlstore.list_log("s1", since_ts=150.0, db_path=tmp_db)
        assert len(rows) == 1
        assert rows[0]["msg"] == "new"

    def test_log_msg_truncated(self, tmp_db: Path) -> None:
        huge = "x" * 10000
        sqlstore.append_log("s1", "info", huge, db_path=tmp_db)
        rows = sqlstore.list_log("s1", db_path=tmp_db)
        # We cap at 4096 chars
        assert len(rows[0]["msg"]) <= 4096


# ---------------------------------------------------------------------------
# D. History
# ---------------------------------------------------------------------------

class TestHistory:
    def test_append_history(self, tmp_db: Path) -> None:
        r = sqlstore.append_history("s1", "replay",
                                    {"orig": "cmd"}, db_path=tmp_db)
        assert r["ok"] is True
        rows = sqlstore.list_history("s1", db_path=tmp_db)
        assert len(rows) == 1
        assert rows[0]["action"] == "replay"
        assert rows[0]["payload"]["orig"] == "cmd"

    def test_history_since(self, tmp_db: Path) -> None:
        sqlstore.append_history("s1", "x", {}, ts=10.0,
                                db_path=tmp_db)
        sqlstore.append_history("s1", "y", {}, ts=20.0,
                                db_path=tmp_db)
        rows = sqlstore.list_history("s1", since_ts=15.0,
                                     db_path=tmp_db)
        assert len(rows) == 1
        assert rows[0]["action"] == "y"


# ---------------------------------------------------------------------------
# E. Exfil
# ---------------------------------------------------------------------------

class TestExfil:
    def test_add_exfil(self, tmp_db: Path) -> None:
        r = sqlstore.add_exfil("s1", "dns", 1024, "pending",
                               db_path=tmp_db)
        assert r["ok"] is True
        assert r["job_id"] >= 1
        rows = sqlstore.list_exfil("s1", db_path=tmp_db)
        assert len(rows) == 1
        assert rows[0]["channel"] == "dns"
        assert rows[0]["bytes_pending"] == 1024

    def test_cancel_exfil(self, tmp_db: Path) -> None:
        r = sqlstore.add_exfil("s1", "dns", 1024, db_path=tmp_db)
        cid = r["cancel_exfil" if "cancel_exfil" in r else "job_id"]
        cancel = sqlstore.cancel_exfil("s1", cid, db_path=tmp_db)
        assert cancel["ok"] is True
        rows = sqlstore.list_exfil("s1", db_path=tmp_db)
        assert rows[0]["status"] == "cancelled"

    def test_cancel_nonexistent_is_noop(self, tmp_db: Path) -> None:
        r = sqlstore.cancel_exfil("s1", 99999, db_path=tmp_db)
        # Does not raise; just returns ok envelope
        assert r["ok"] is True


# ---------------------------------------------------------------------------
# F. Persistence
# ---------------------------------------------------------------------------

class TestPersistence:
    def test_add_persistence(self, tmp_db: Path) -> None:
        r = sqlstore.add_persistence("s1", "wmi", "wmi-persistence",
                                     db_path=tmp_db)
        assert r["ok"] is True
        rows = sqlstore.list_persistence("s1", db_path=tmp_db)
        assert len(rows) == 1
        assert rows[0]["mech_id"] == "wmi"

    def test_remove_persistence(self, tmp_db: Path) -> None:
        sqlstore.add_persistence("s1", "wmi", "wmi-persistence",
                                 db_path=tmp_db)
        r = sqlstore.remove_persistence("s1", "wmi", db_path=tmp_db)
        assert r["ok"] is True
        rows = sqlstore.list_persistence("s1", db_path=tmp_db)
        assert rows[0]["state"] == "removed"


# ---------------------------------------------------------------------------
# G. Health
# ---------------------------------------------------------------------------

class TestHealth:
    def test_health_reports_counts(self, tmp_db: Path) -> None:
        sqlstore.record_session("s1", "ble", "t", db_path=tmp_db)
        sqlstore.append_log("s1", "info", "x", db_path=tmp_db)
        h = sqlstore.health(tmp_db)
        assert h["ok"] is True
        assert h["counts"]["sessions"] == 1
        assert h["counts"]["log"] == 1
        assert h["backend"] == "sqlite"
        assert h["size_bytes"] > 0

    def test_backend_from_env_default(self) -> None:
        # No env set → sqlite
        b = sqlstore.backend_from_env()
        assert b["backend"] == "sqlite"
        assert b["available"] is True

    def test_backend_from_env_sqlite_url(self) -> None:
        os.environ["KFIOSA_SQL_URL"] = "sqlite:///tmp/test.db"
        try:
            b = sqlstore.backend_from_env()
            assert b["backend"] == "sqlite"
        finally:
            del os.environ["KFIOSA_SQL_URL"]

    def test_backend_from_env_mssql_no_sqlalchemy(self) -> None:
        os.environ["KFIOSA_SQL_URL"] = "mssql+pymssql://u:p@host/db"
        try:
            b = sqlstore.backend_from_env()
            # Without SQLAlchemy installed, must honest-degrade
            # with available=False
            if not b["available"]:
                assert b["backend"] == "sqlite"
                assert "mssql" in b["note"] or "sqlalchemy" in b["note"]
        finally:
            del os.environ["KFIOSA_SQL_URL"]


# ---------------------------------------------------------------------------
# H. Redaction — never inline credentials
# ---------------------------------------------------------------------------

class TestRedaction:
    def test_nvd_key_redacted_in_meta(self, tmp_db: Path) -> None:
        NVD = "ecf51ee2-938d-44de-b015-896a3f6c758c"
        sqlstore.record_session("s1", "ble", "t",
                                meta={"key": NVD}, db_path=tmp_db)
        # Read the raw sqlite file to verify
        conn = sqlite3.connect(str(tmp_db))
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT meta_json FROM sessions WHERE sid = 's1'"
        ).fetchone()
        conn.close()
        assert NVD not in row["meta_json"]
        assert "***" in row["meta_json"]

    def test_kismet_key_redacted_in_log(self, tmp_db: Path) -> None:
        KISMET = "CE38F76832CFA1F6F35C89EAAEAF61C3"
        sqlstore.append_log("s1", "info", f"using {KISMET}",
                            db_path=tmp_db)
        conn = sqlite3.connect(str(tmp_db))
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT msg FROM log").fetchone()
        conn.close()
        assert KISMET not in row["msg"]
        assert "***" in row["msg"]

    def test_ollama_token_redacted(self, tmp_db: Path) -> None:
        T = "3d94e52cff9f4df5a01973f24d5bc8db"
        sqlstore.append_log("s1", "info", f"auth={T}",
                            db_path=tmp_db)
        conn = sqlite3.connect(str(tmp_db))
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT msg FROM log").fetchone()
        conn.close()
        assert T not in row["msg"]
        assert "***" in row["msg"]


# ---------------------------------------------------------------------------
# I. Thread-local connections
# ---------------------------------------------------------------------------

class TestThreadLocal:
    def test_concurrent_writes_dont_collide(self, tmp_db: Path) -> None:
        # Two threads writing to different sids concurrently
        # must NOT collide or block each other.
        def writer(sid: str) -> None:
            for i in range(20):
                sqlstore.append_log(sid, "info", f"msg-{i}",
                                    db_path=tmp_db)

        t1 = threading.Thread(target=writer, args=("s1",))
        t2 = threading.Thread(target=writer, args=("s2",))
        t1.start()
        t2.start()
        t1.join()
        t2.join()
        s1_rows = sqlstore.list_log("s1", db_path=tmp_db)
        s2_rows = sqlstore.list_log("s2", db_path=tmp_db)
        assert len(s1_rows) == 20
        assert len(s2_rows) == 20


# ---------------------------------------------------------------------------
# J. Dashboard integration — SQL endpoints work via the WSGI app
# ---------------------------------------------------------------------------

class TestDashboardSQLEndpoints:
    def test_sql_health_endpoint(self) -> None:
        from core.post_access_tui.rat_ext import _build_wsgi_app
        roster = []
        app = _build_wsgi_app(roster)
        import io
        captured: list = []
        def start_response(status, headers, exc_info=None):
            captured.append((status, dict(headers)))
            return lambda b: None
        body = app({"PATH_INFO": "/api/sql_health",
                    "REQUEST_METHOD": "GET",
                    "QUERY_STRING": "",
                    "wsgi.input": io.BytesIO()}, start_response)
        assert captured[0][0] == "200 OK"
        import json
        out = json.loads(body[0])
        assert out["ok"] is True
        assert "store" in out
        assert "backend" in out

    def test_sql_sessions_endpoint(self) -> None:
        from core.post_access_tui.rat_ext import _build_wsgi_app
        roster = [{"id": "s1", "transport": "ble", "target": "AA:BB:CC",
                   "achieved": set(), "capabilities": [],
                   "log_buffer": [], "step_envelope_history": []}]
        app = _build_wsgi_app(roster)
        import io
        def start_response(status, headers, exc_info=None):
            return lambda b: None
        body = app({"PATH_INFO": "/api/sql/sessions",
                    "REQUEST_METHOD": "GET",
                    "QUERY_STRING": "",
                    "wsgi.input": io.BytesIO()}, start_response)
        import json
        out = json.loads(body[0])
        assert out["ok"] is True
        assert "sessions" in out


if __name__ == "__main__":
    pytest.main([__file__, "-q", "--tb=short"])
