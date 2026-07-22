"""core.db.backends.sqlalchemy_backend — SQLAlchemy / SQL Server backend.

Phase 3 expansion: when ``KFIOSA_SQL_URL`` is set to a non-sqlite
URL and ``sqlalchemy`` is importable, the store routes through this
module. For SQL Server, ``pymssql`` is loaded lazily when the URL
scheme is ``mssql+pymssql://...``.

This module exposes the same 16-function public surface as
:mod:`core.db.sqlstore`. Schema (5 tables) is identical so the
dashboard consumes envelopes unchanged.

The backend is loaded **only** when SQLAlchemy is importable. If
SQLAlchemy is not installed, the selector in
:mod:`core.db.backends.__init__` falls back to sqlite + a warning.

The 5 tables:

* ``sessions(sid PK, kind, target, created_at, last_activity,
  achieved_count, capability_count, risk_max, state, meta_json)``
* ``log(sid, ts, kind, msg)``
* ``history(sid, ts, action, payload_json)``
* ``exfil(job_id PK, sid, channel, bytes_pending, status, created_at)``
* ``persistence(mech_id PK, sid, kind, label, installed_at, state,
  meta_json)``
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

# Same redaction rules as core.db.sqlstore
_REDACT_KEYS: tuple = (
    "ecf51ee2-938d-44de-b015-896a3f6c758c",
    "CE38F76832CFA1F6F35C89EAAEAF61C3",
    "3d94e52cff9f4df5a01973f24d5bc8db",
    "OLLAMA_CLOUD_TOKEN", "NVD_API_KEY",
    "KISMET_API_KEY", "OLLAMA_AUTH_TOKEN",
)


def _redact(value: Any) -> Any:
    if isinstance(value, str):
        for needle in _REDACT_KEYS:
            if needle and needle in value:
                value = value.replace(needle, "***")
        return value
    if isinstance(value, dict):
        return {k: _redact(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact(v) for v in value]
    return value


# Engine is created lazily; the env var is read at first call.
_engine = None
_url: str = ""


def _get_engine() -> Any:
    """Lazily create the SQLAlchemy engine from KFIOSA_SQL_URL."""
    global _engine, _url
    if _engine is not None:
        return _engine
    import sqlalchemy
    from sqlalchemy import create_engine  # type: ignore
    url = os.environ.get("KFIOSA_SQL_URL", "").strip()
    if not url:
        raise RuntimeError("KFIOSA_SQL_URL is empty; SQLAlchemy backend requires it")
    if "mssql" in url:
        # Make sure pymssql is importable; if not, fail with a clear message.
        try:
            import pymssql  # noqa: F401
        except ImportError as e:
            raise RuntimeError(
                f"mssql URL requested but pymssql is not installed: {e}. "
                "Install with: pip install pymssql"
            ) from e
    _url = url
    _engine = create_engine(url, future=True, pool_pre_ping=True)
    _create_schema(_engine)
    return _engine


def _create_schema(engine: Any) -> None:
    """Create the 5 tables if they don't exist. Idempotent.

    The table names match the sqlite backend (sessions, log, history,
    exfil, persistence) so a session written via sqlite can be read
    via SQLAlchemy, and vice versa. The previous version prefixed
    every table with ``kf_`` which made the two backends
    incompatible at the data layer.
    """
    from sqlalchemy import text  # type: ignore
    ddl = [
        """IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='sessions' AND xtype='U')
           CREATE TABLE sessions (
             sid NVARCHAR(64) NOT NULL PRIMARY KEY,
             kind NVARCHAR(16) NULL,
             target NVARCHAR(255) NULL,
             created_at FLOAT NULL,
             last_activity FLOAT NULL,
             achieved_count INT NULL DEFAULT 0,
             capability_count INT NULL DEFAULT 0,
             risk_max NVARCHAR(16) NULL,
             state NVARCHAR(16) NULL,
             meta_json NVARCHAR(MAX) NULL
           )""",
        """IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='log' AND xtype='U')
           CREATE TABLE log (
             id INT IDENTITY(1,1) PRIMARY KEY,
             sid NVARCHAR(64) NOT NULL,
             ts FLOAT NOT NULL,
             kind NVARCHAR(32) NULL,
             msg NVARCHAR(MAX) NULL
           )""",
        """IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='history' AND xtype='U')
           CREATE TABLE history (
             id INT IDENTITY(1,1) PRIMARY KEY,
             sid NVARCHAR(64) NOT NULL,
             ts FLOAT NOT NULL,
             action NVARCHAR(64) NULL,
             payload_json NVARCHAR(MAX) NULL
           )""",
        """IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='exfil' AND xtype='U')
           CREATE TABLE exfil (
             id INT IDENTITY(1,1) PRIMARY KEY,
             sid NVARCHAR(64) NOT NULL,
             ts FLOAT NOT NULL,
             channel NVARCHAR(32) NULL,
             bytes_pending BIGINT NULL DEFAULT 0,
             status NVARCHAR(16) NULL DEFAULT 'pending'
           )""",
        """IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='persistence' AND xtype='U')
           CREATE TABLE persistence (
             id INT IDENTITY(1,1) PRIMARY KEY,
             sid NVARCHAR(64) NOT NULL,
             ts FLOAT NOT NULL,
             mech_id NVARCHAR(64) NULL,
             kind NVARCHAR(32) NULL,
             state NVARCHAR(16) NULL DEFAULT 'installed',
             meta_json NVARCHAR(MAX) NULL
           )""",
    ]
    indexes = [
        "CREATE INDEX ix_log_sid ON log(sid, ts)",
        "CREATE INDEX ix_history_sid ON history(sid, ts)",
        "CREATE INDEX ix_exfil_sid ON exfil(sid, ts)",
        "CREATE INDEX ix_persistence_sid ON persistence(sid, ts)",
    ]
    with engine.begin() as cx:
        for stmt in ddl:
            cx.execute(text(stmt))
        # SQL Server: index creation must come AFTER the table.
        for stmt in indexes:
            try:
                cx.execute(text(stmt))
            except Exception:  # noqa: BLE001
                # Already exists — SQL Server has no IF NOT EXISTS for
                # indexes, so swallow the duplicate-index error.
                pass


def _row_to_dict(row: Any) -> Dict[str, Any]:
    """Convert a SQLAlchemy Row to a plain dict."""
    if row is None:
        return {}
    try:
        return dict(row._mapping)
    except Exception:
        try:
            return dict(row)
        except Exception:
            return {}


# ---------------------------------------------------------------------------
# Public surface
# ---------------------------------------------------------------------------

BACKEND_NAME = "sqlalchemy"


def init(db_path: Optional[Path] = None) -> Dict[str, Any]:
    """Open / create the schema. Idempotent. db_path is ignored
    (the URL is taken from KFIOSA_SQL_URL)."""
    try:
        _get_engine()
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "backend": "sqlalchemy",
                "url": os.environ.get("KFIOSA_SQL_URL", ""),
                "error": f"open: {e}"}
    return {"ok": True, "backend": "sqlalchemy",
            "url": _url, "error": None}


def record_session(sid: str, kind: str = "auto", target: str = "",
                   created_at: Optional[float] = None,
                   db_path: Optional[Path] = None,
                   meta: Optional[Dict[str, Any]] = None,
                   ) -> Dict[str, Any]:
    """Open (or upsert) a session row."""
    from sqlalchemy import text  # type: ignore
    try:
        engine = _get_engine()
        ts = float(created_at or time.time())
        meta_json = json.dumps(_redact(meta or {}), default=str)
        with engine.begin() as cx:
            # SQL Server uses MERGE for upsert
            cx.execute(text("""
                IF EXISTS (SELECT 1 FROM sessions WHERE sid = :sid)
                    UPDATE sessions
                       SET kind = :kind, target = :target,
                           last_activity = :ts, state = N'open',
                           meta_json = :meta
                     WHERE sid = :sid
                ELSE
                    INSERT INTO sessions
                        (sid, kind, target, created_at, last_activity,
                         state, meta_json)
                    VALUES
                        (:sid, :kind, :target, :ts, :ts, N'open', :meta)
            """), {"sid": sid, "kind": kind, "target": target,
                   "ts": ts, "meta": meta_json})
        return {"ok": True, "sid": sid, "ts": ts}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": f"insert: {e}"}


def update_session(sid: str, db_path: Optional[Path] = None,
                   **fields: Any) -> Dict[str, Any]:
    """Patch one or more columns on a session row."""
    from sqlalchemy import text  # type: ignore
    allowed = {"kind", "target", "achieved_count", "capability_count",
               "risk_max", "state", "meta_json"}
    sets: List[str] = []
    vals: Dict[str, Any] = {"sid": sid}
    for k, v in fields.items():
        if k not in allowed:
            continue
        if k == "meta_json" and not isinstance(v, str):
            v = json.dumps(_redact(v), default=str)
        sets.append(f"{k} = :{k}")
        vals[k] = v
    if not sets:
        return {"ok": True, "sid": sid, "patched": 0}
    try:
        engine = _get_engine()
        with engine.begin() as cx:
            cx.execute(text(
                f"UPDATE sessions SET {', '.join(sets)} WHERE sid = :sid"
            ), vals)
        return {"ok": True, "sid": sid, "patched": len(sets)}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": f"update: {e}"}


def list_sessions(db_path: Optional[Path] = None) -> List[Dict[str, Any]]:
    """Return all session rows (most recent first)."""
    from sqlalchemy import text  # type: ignore
    try:
        engine = _get_engine()
        with engine.connect() as cx:
            rows = cx.execute(text(
                "SELECT TOP 200 * FROM sessions "
                "ORDER BY last_activity DESC"
            )).fetchall()
        return [_row_to_dict(r) for r in rows]
    except Exception:
        return []


def append_log(sid: str, kind: str, msg: str,
               db_path: Optional[Path] = None,
               ts: Optional[float] = None) -> Dict[str, Any]:
    """Append a log line."""
    from sqlalchemy import text  # type: ignore
    try:
        engine = _get_engine()
        with engine.begin() as cx:
            cx.execute(text(
                "INSERT INTO log(sid, ts, kind, msg) "
                "VALUES (:sid, :ts, :kind, :msg)"
            ), {"sid": sid, "ts": float(ts or time.time()),
                "kind": kind, "msg": _redact(msg)})
        return {"ok": True, "sid": sid, "ts": float(ts or time.time())}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": f"insert: {e}"}


def list_log(sid: str, since_ts: Optional[float] = None,
             limit: int = 200,
             db_path: Optional[Path] = None) -> List[Dict[str, Any]]:
    """Return log rows for a session (ascending)."""
    from sqlalchemy import text  # type: ignore
    try:
        engine = _get_engine()
        with engine.connect() as cx:
            if since_ts is not None:
                rows = cx.execute(text(
                    "SELECT TOP :lim * FROM log WHERE sid = :sid "
                    "AND ts >= :ts ORDER BY ts ASC"
                ), {"sid": sid, "ts": since_ts, "lim": int(limit)}).fetchall()
            else:
                rows = cx.execute(text(
                    "SELECT TOP :lim * FROM log WHERE sid = :sid "
                    "ORDER BY ts ASC"
                ), {"sid": sid, "lim": int(limit)}).fetchall()
        return [_row_to_dict(r) for r in rows]
    except Exception:
        return []


def append_history(sid: str, action: str, payload: Dict[str, Any],
                   db_path: Optional[Path] = None,
                   ts: Optional[float] = None) -> Dict[str, Any]:
    """Append a history row."""
    from sqlalchemy import text  # type: ignore
    try:
        engine = _get_engine()
        payload_json = json.dumps(_redact(payload or {}), default=str)
        with engine.begin() as cx:
            cx.execute(text(
                "INSERT INTO history(sid, ts, action, payload_json) "
                "VALUES (:sid, :ts, :action, :payload)"
            ), {"sid": sid, "ts": float(ts or time.time()),
                "action": action, "payload": payload_json})
        return {"ok": True, "sid": sid, "ts": float(ts or time.time())}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": f"insert: {e}"}


def list_history(sid: str, since_ts: Optional[float] = None,
                 limit: int = 200,
                 db_path: Optional[Path] = None) -> List[Dict[str, Any]]:
    """Return history rows for a session (ascending)."""
    from sqlalchemy import text  # type: ignore
    try:
        engine = _get_engine()
        with engine.connect() as cx:
            if since_ts is not None:
                rows = cx.execute(text(
                    "SELECT TOP :lim * FROM history WHERE sid = :sid "
                    "AND ts >= :ts ORDER BY ts ASC"
                ), {"sid": sid, "ts": since_ts, "lim": int(limit)}).fetchall()
            else:
                rows = cx.execute(text(
                    "SELECT TOP :lim * FROM history WHERE sid = :sid "
                    "ORDER BY ts ASC"
                ), {"sid": sid, "lim": int(limit)}).fetchall()
        return [_row_to_dict(r) for r in rows]
    except Exception:
        return []


def add_exfil(sid: str, channel: str, bytes_pending: int = 0,
              status: str = "queued",
              db_path: Optional[Path] = None) -> Dict[str, Any]:
    """Register an exfiltration job."""
    from sqlalchemy import text  # type: ignore
    try:
        engine = _get_engine()
        ts = time.time()
        with engine.begin() as cx:
            cx.execute(text(
                "INSERT INTO exfil(sid, ts, channel, bytes_pending, status) "
                "VALUES (:sid, :ts, :channel, :bytes, :status)"
            ), {"sid": sid, "channel": channel, "bytes": int(bytes_pending),
                "status": status, "ts": ts})
            # SQL Server SCOPE_IDENTITY() gives the just-inserted
            # identity value without OUTPUT INSERTED (which is also
            # valid but requires explicit column naming).
            row = cx.execute(text("SELECT SCOPE_IDENTITY()")).fetchone()
            job_id = int(row[0]) if row else None
        return {"ok": True, "job_id": job_id, "sid": sid, "ts": ts}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": f"insert: {e}"}


def cancel_exfil(sid: str, job_id: int,
                 db_path: Optional[Path] = None) -> Dict[str, Any]:
    """Mark a job as cancelled."""
    from sqlalchemy import text  # type: ignore
    try:
        engine = _get_engine()
        with engine.begin() as cx:
            cx.execute(text(
                "UPDATE exfil SET status = N'cancelled' "
                "WHERE id = :jid AND sid = :sid"
            ), {"sid": sid, "jid": int(job_id)})
        return {"ok": True, "job_id": int(job_id)}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": f"update: {e}"}


def list_exfil(sid: str, db_path: Optional[Path] = None,
               ) -> List[Dict[str, Any]]:
    """Return exfil jobs for a session."""
    from sqlalchemy import text  # type: ignore
    try:
        engine = _get_engine()
        with engine.connect() as cx:
            rows = cx.execute(text(
                "SELECT * FROM exfil WHERE sid = :sid "
                "ORDER BY created_at ASC"
            ), {"sid": sid}).fetchall()
        return [_row_to_dict(r) for r in rows]
    except Exception:
        return []


def add_persistence(sid: str, mech_id: str, kind: str,
                    state: str = "installed",
                    meta: Optional[Dict[str, Any]] = None,
                    db_path: Optional[Path] = None,
                    ) -> Dict[str, Any]:
    """Register a persistence mechanism. The schema matches the
    sqlite backend: (id PK, sid, ts, mech_id, kind, state, meta_json).
    No `label` column (sqlite doesn't have one) — the kind+state pair
    is the canonical identifier."""
    from sqlalchemy import text  # type: ignore
    try:
        engine = _get_engine()
        ts = time.time()
        meta_json = json.dumps(_redact(meta or {}), default=str)
        with engine.begin() as cx:
            # mech_id is unique but not a PK in the new schema; we
            # use IF EXISTS to make this an upsert keyed on mech_id.
            existing = cx.execute(text(
                "SELECT id FROM persistence WHERE mech_id = :mid"
            ), {"mid": mech_id}).fetchone()
            if existing:
                cx.execute(text(
                    "UPDATE persistence SET sid = :sid, kind = :kind, "
                    "ts = :ts, state = :state, meta_json = :meta "
                    "WHERE mech_id = :mid"
                ), {"mid": mech_id, "sid": sid, "kind": kind,
                     "ts": ts, "state": state, "meta": meta_json})
            else:
                cx.execute(text(
                    "INSERT INTO persistence(sid, ts, mech_id, kind, "
                    "state, meta_json) VALUES "
                    "(:sid, :ts, :mid, :kind, :state, :meta)"
                ), {"mid": mech_id, "sid": sid, "kind": kind,
                     "ts": ts, "state": state, "meta": meta_json})
        return {"ok": True, "mech_id": mech_id, "ts": ts}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": f"insert: {e}"}


def list_persistence(sid: str, db_path: Optional[Path] = None,
                     ) -> List[Dict[str, Any]]:
    """Return persistence mechanisms for a session."""
    from sqlalchemy import text  # type: ignore
    try:
        engine = _get_engine()
        with engine.connect() as cx:
            rows = cx.execute(text(
                "SELECT * FROM persistence WHERE sid = :sid "
                "ORDER BY installed_at ASC"
            ), {"sid": sid}).fetchall()
        return [_row_to_dict(r) for r in rows]
    except Exception:
        return []


def remove_persistence(sid: str, mech_id: str,
                       db_path: Optional[Path] = None) -> Dict[str, Any]:
    """Mark a persistence mechanism as removed."""
    from sqlalchemy import text  # type: ignore
    try:
        engine = _get_engine()
        with engine.begin() as cx:
            cx.execute(text(
                "UPDATE persistence SET state = N'removed' "
                "WHERE mech_id = :mid AND sid = :sid"
            ), {"sid": sid, "mid": mech_id})
        return {"ok": True, "mech_id": mech_id}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": f"update: {e}"}


def health(db_path: Optional[Path] = None) -> Dict[str, Any]:
    """Return a health summary. Mirrors the sqlite backend's shape
    so callers can swap backends transparently."""
    try:
        from sqlalchemy import text  # type: ignore
        engine = _get_engine()
        with engine.connect() as cx:
            sessions = cx.execute(text(
                "SELECT COUNT(*) FROM sessions"
            )).scalar() or 0
            log_count = cx.execute(text(
                "SELECT COUNT(*) FROM log"
            )).scalar() or 0
            history = cx.execute(text(
                "SELECT COUNT(*) FROM history"
            )).scalar() or 0
            exfil = cx.execute(text(
                "SELECT COUNT(*) FROM exfil"
            )).scalar() or 0
            persistence = cx.execute(text(
                "SELECT COUNT(*) FROM persistence"
            )).scalar() or 0
        return {
            "ok": True,
            "backend": "sqlalchemy",
            "url": os.environ.get("KFIOSA_SQL_URL", ""),
            "counts": {
                "sessions": int(sessions), "log": int(log_count),
                "history": int(history), "exfil": int(exfil),
                "persistence": int(persistence),
            },
            "error": None,
        }
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "backend": "sqlalchemy",
                "url": os.environ.get("KFIOSA_SQL_URL", ""),
                "error": f"health: {e}"}


def close() -> Dict[str, Any]:
    """Dispose the engine."""
    global _engine
    try:
        if _engine is not None:
            _engine.dispose()
    except Exception:
        pass
    finally:
        _engine = None
    return {"ok": True, "backend": "sqlalchemy"}


def backend_from_env() -> Dict[str, Any]:
    """Inspect KFIOSA_SQL_URL; return what *would* be used."""
    url = os.environ.get("KFIOSA_SQL_URL", "").strip()
    if not url:
        return {"ok": True, "backend": "sqlite",
                "url": "", "available": True,
                "note": "KFIOSA_SQL_URL not set; using sqlite default"}
    if url.startswith("sqlite"):
        return {"ok": True, "backend": "sqlite",
                "url": url, "available": True, "note": "sqlite URL"}
    try:
        import sqlalchemy  # noqa: F401
    except ImportError:
        return {"ok": False, "backend": "sqlite",
                "url": url, "available": False,
                "note": ("non-sqlite URL but SQLAlchemy not installed; "
                         "falling back to sqlite. Install with: "
                         "pip install sqlalchemy")}
    if "mssql" in url:
        try:
            import pymssql  # noqa: F401
        except ImportError:
            return {"ok": False, "backend": "sqlite",
                    "url": url, "available": False,
                    "note": ("mssql URL but pymssql not installed; "
                             "falling back to sqlite. Install with: "
                             "pip install pymssql")}
    return {"ok": True, "backend": "sqlalchemy",
            "url": url, "available": True,
            "note": "sqlalchemy backend ready"}
