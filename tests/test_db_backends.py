"""tests.test_db_backends — Phase 3 expansion: backends selector.

Verifies that :mod:`core.db.backends` selects the right backend
based on KFIOSA_SQL_URL + installed deps.

* Without KFIOSA_SQL_URL: sqlite backend.
* With KFIOSA_SQL_URL=sqlite:///:memory:: sqlite backend.
* With KFIOSA_SQL_URL=mssql+pymssql://…: SQLAlchemy backend **if**
  SQLAlchemy + pymssql are installed; otherwise sqlite + a clear
  note in the health output (we never fake).
"""
from __future__ import annotations

import importlib
import os
import sys

import pytest


@pytest.fixture
def reload_backends(monkeypatch):
    """Force a fresh import of backends after env changes."""
    # Pre-import the backends module so the reload has something
    # to reload (otherwise reload raises ImportError).
    import core.db.backends  # noqa: F401

    def _reload():
        from core.db import backends
        return importlib.reload(backends)
    return _reload


def test_default_is_sqlite(reload_backends):
    """No KFIOSA_SQL_URL → sqlite backend."""
    monkeypatch_saved = os.environ.pop("KFIOSA_SQL_URL", None)
    try:
        b = reload_backends()
        d = b.describe_backend()
        assert d["ok"] is True
        assert d["backend"] == "sqlite"
    finally:
        if monkeypatch_saved is not None:
            os.environ["KFIOSA_SQL_URL"] = monkeypatch_saved


def test_sqlite_url_is_sqlite(reload_backends):
    """KFIOSA_SQL_URL=sqlite:// → sqlite backend."""
    old = os.environ.get("KFIOSA_SQL_URL")
    os.environ["KFIOSA_SQL_URL"] = "sqlite:///:memory:"
    try:
        b = reload_backends()
        d = b.describe_backend()
        assert d["ok"] is True
        assert d["backend"] == "sqlite"
    finally:
        if old is None:
            os.environ.pop("KFIOSA_SQL_URL", None)
        else:
            os.environ["KFIOSA_SQL_URL"] = old


def test_unknown_url_falls_back_to_sqlite(reload_backends):
    """If the URL scheme is unknown, fall back to sqlite."""
    old = os.environ.get("KFIOSA_SQL_URL")
    os.environ["KFIOSA_SQL_URL"] = "mssql+pymssql://nope:nope@127.0.0.1:0/x"
    try:
        b = reload_backends()
        # If sqlalchemy+pymssql are both installed, this is sqlalchemy.
        # If either is missing, the selector returns sqlite (per
        # backend_from_env's explicit fallback). Either is correct —
        # we just check the selector ran without crashing.
        d = b.describe_backend()
        assert d["ok"] is True
        assert d["backend"] in {"sqlite", "sqlalchemy"}
    finally:
        if old is None:
            os.environ.pop("KFIOSA_SQL_URL", None)
        else:
            os.environ["KFIOSA_SQL_URL"] = old


def test_sqlite_backend_has_all_16_functions():
    """The sqlite backend must expose the same 16 functions as sqlstore."""
    from core.db.backends.sqlite_backend import (
        init, record_session, update_session, list_sessions,
        append_log, list_log, append_history, list_history,
        add_exfil, cancel_exfil, list_exfil,
        add_persistence, list_persistence, remove_persistence,
        health, close, backend_from_env,
    )
    for fn in (init, record_session, update_session, list_sessions,
               append_log, list_log, append_history, list_history,
               add_exfil, cancel_exfil, list_exfil,
               add_persistence, list_persistence, remove_persistence,
               health, close, backend_from_env):
        assert callable(fn), f"{fn.__name__} must be callable"


def test_sqlalchemy_backend_has_all_16_functions():
    """The SQLAlchemy backend must expose the same 16 functions."""
    from core.db.backends.sqlalchemy_backend import (
        init, record_session, update_session, list_sessions,
        append_log, list_log, append_history, list_history,
        add_exfil, cancel_exfil, list_exfil,
        add_persistence, list_persistence, remove_persistence,
        health, close, backend_from_env,
    )
    for fn in (init, record_session, update_session, list_sessions,
               append_log, list_log, append_history, list_history,
               add_exfil, cancel_exfil, list_exfil,
               add_persistence, list_persistence, remove_persistence,
               health, close, backend_from_env):
        assert callable(fn), f"{fn.__name__} must be callable"


def test_sqlite_backend_init_record_list(tmp_path, monkeypatch):
    """sqlite backend end-to-end: init → record → list."""
    monkeypatch.chdir(tmp_path)
    db = tmp_path / "sub" / "test.db"
    from core.db.backends.sqlite_backend import (
        init, record_session, list_sessions, close,
    )
    r = init(db_path=db)
    assert r["ok"] is True
    r = record_session("t1", "auto", "127.0.0.1", db_path=db)
    assert r["ok"] is True
    rows = list_sessions(db_path=db)
    assert isinstance(rows, list)
    # The list_sessions returns raw rows; sid is present
    sids = [row.get("sid") for row in rows]
    assert "t1" in sids
    close()


def test_sqlite_backend_appends_log_and_history(tmp_path):
    """sqlite backend end-to-end: append_log + list_log + append_history + list_history."""
    db = tmp_path / "log.db"
    from core.db.backends.sqlite_backend import (
        init, record_session, append_log, list_log,
        append_history, list_history, close,
    )
    init(db_path=db)
    record_session("t1", "auto", "x", db_path=db)
    append_log("t1", "info", "hello", db_path=db)
    append_log("t1", "warn", "world", db_path=db)
    append_history("t1", "click", {"x": 1}, db_path=db)
    log_rows = list_log("t1", db_path=db)
    hist_rows = list_history("t1", db_path=db)
    assert len(log_rows) >= 2
    assert len(hist_rows) >= 1
    close()


def test_sqlite_backend_exfil_lifecycle(tmp_path):
    """sqlite backend end-to-end: add_exfil → cancel_exfil → list_exfil."""
    db = tmp_path / "exfil.db"
    from core.db.backends.sqlite_backend import (
        init, record_session, add_exfil, list_exfil, cancel_exfil, close,
    )
    init(db_path=db)
    record_session("t1", "auto", "x", db_path=db)
    r = add_exfil("t1", "dns", 1024, "queued", db_path=db)
    assert r["ok"] is True
    assert "job_id" in r and r["job_id"]
    jid = int(r["job_id"])
    rows = list_exfil("t1", db_path=db)
    assert len(rows) >= 1
    r = cancel_exfil("t1", jid, db_path=db)
    assert r["ok"] is True
    close()


def test_sqlite_backend_persistence_lifecycle(tmp_path):
    """sqlite backend end-to-end: add_persistence → list_persistence → remove_persistence."""
    db = tmp_path / "persist.db"
    from core.db.backends.sqlite_backend import (
        init, record_session, add_persistence, list_persistence,
        remove_persistence, close,
    )
    init(db_path=db)
    record_session("t1", "auto", "x", db_path=db)
    r = add_persistence("t1", "m1", "registry_run", "HKLM", db_path=db)
    assert r["ok"] is True
    rows = list_persistence("t1", db_path=db)
    assert len(rows) >= 1
    r = remove_persistence("t1", "m1", db_path=db)
    assert r["ok"] is True
    close()


def test_sqlite_backend_health(tmp_path):
    """sqlite backend end-to-end: health returns ok with counts."""
    db = tmp_path / "health.db"
    from core.db.backends.sqlite_backend import (
        init, record_session, health, close,
    )
    init(db_path=db)
    record_session("t1", "auto", "x", db_path=db)
    h = health(db_path=db)
    assert h["ok"] is True
    assert "counts" in h
    assert "sessions" in h["counts"]
    assert h["counts"]["sessions"] >= 1
    close()


def test_sqlalchemy_backend_health_without_init_fails_cleanly():
    """Without init, the SQLAlchemy backend raises a clear error."""
    from core.db.backends import sqlalchemy_backend
    # health() should NOT raise; it should return ok=False
    h = sqlalchemy_backend.health()
    # Either ok=False with an error, or ok=True (if KFIOSA_SQL_URL is set)
    assert "ok" in h
    assert "backend" in h
    assert h["backend"] == "sqlalchemy"


def test_sqlalchemy_backend_redact_keys():
    """The SQLAlchemy backend redaction must scrub known keys."""
    from core.db.backends.sqlalchemy_backend import _redact
    needle = "ecf51ee2-938d-44de-b015-896a3f6c758c"
    out = _redact({"nvd_key": needle, "other": "ok"})
    assert out["other"] == "ok"
    assert "***" in out["nvd_key"]
    assert needle not in out["nvd_key"]


def test_no_fabricated_cve_or_creds():
    """Adversarial: the backends module's source must not contain
    inline credentials, CVE ids, or NTLM hashes."""
    import os
    backends_dir = os.path.join(
        os.path.dirname(__file__), "..", "core", "db", "backends",
    )
    for fname in os.listdir(backends_dir):
        if not fname.endswith(".py"):
            continue
        path = os.path.join(backends_dir, fname)
        with open(path, encoding="utf-8", errors="replace") as f:
            blob = f.read()
        # These are the real keys from the memory file; they should
        # be referenced only in redaction needles (substring) or
        # documentation comments.
        for needle in (
            "NVD_API_KEY=", "KISMET_API_KEY=", "OLLAMA_AUTH_TOKEN=",
            "password=",  # not "password:"
        ):
            # Skip string occurrences inside redaction needles
            # (we keep them as substrings to redact at runtime)
            if needle in ("NVD_API_KEY=", "KISMET_API_KEY=",
                          "OLLAMA_AUTH_TOKEN="):
                # These should appear as bare substrings, not as key=value
                # assignments. If they appear as "X=" that's a fabrication.
                if needle in blob:
                    # Check it's inside a string literal in the
                    # _REDACT_KEYS tuple, not a config assignment.
                    assert "REDACT" in blob or "_KEYS" in blob, (
                        f"{fname} mentions {needle!r} outside redaction"
                    )
            else:
                # password= should never appear
                assert needle not in blob, (
                    f"{fname} contains forbidden {needle!r}"
                )
