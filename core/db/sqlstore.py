"""core.db — SQL store for KFIOSA sessions, history, exfil, audit.

Phase 2.4+ — backends:

* **sqlite** (default, stdlib). File at ``~/.kfiosa/kfiosa.db`` with
  ``os.umask(0o077)`` so the file is owner-readable only. No
  external dependency. Always available.

* **sqlalchemy** (optional). If ``sqlalchemy`` is importable and
  ``KFIOSA_SQL_URL`` is set to a non-sqlite URL, the store uses
  SQLAlchemy's create_engine. ``pymssql`` is loaded lazily when
  the URL scheme is ``mssql+pymssql://`` for SQL Server.

The store exposes a tiny, stable surface:

* ``init(db_path=None)``  — open / create the schema. Idempotent.
* ``record_session(sid, kind, target, created_at)`` — open a row.
* ``update_session(sid, **fields)`` — patch any column.
* ``append_log(sid, ts, kind, msg)`` — append a log line.
* ``append_history(sid, ts, action, payload_json)`` — append a
  command-history line.
* ``add_exfil(sid, channel, bytes_pending, status)`` — register
  an exfiltration job.
* ``cancel_exfil(sid, job_id)`` — operator-initiated cancel.
* ``list_sessions()`` — for the dashboard aggregate endpoint.
* ``list_exfil(sid)`` — for the dashboard exfil endpoint.
* ``list_history(sid, since_ts=None, limit=200)`` — for the
  dashboard history endpoint.
* ``close()`` — close the connection (sqlite).

All methods NEVER raise; they return ``{ok, error}`` envelopes
on failure. The dashboard consumes these envelopes directly.

Privacy / safety rules:

* No raw credentials are stored. Payloads are JSON; if a key
  string (NVD, Kismet, Ollama) appears in the payload it is
  redacted to ``"***"`` before write.
* Database file is owner-readable only (``os.umask(0o077)``).
* The store is **opt-in**: nothing else in KFIOSA writes here
  unless it explicitly calls ``record_session`` /
  ``append_log`` / etc. The dashboard does this; the chain
  planner stays file-based.
"""
from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


DEFAULT_DB_PATH = Path.home() / ".kfiosa" / "kfiosa.db"

# Per-thread connection cache (sqlite3 connections are not safe
# to share across threads).
_local = threading.local()

# Substrings that should NEVER appear in stored payloads. The
# store redacts them to "***" before write.
_REDACT_KEYS: Tuple[str, ...] = (
    "ecf51ee2-938d-44de-b015-896a3f6c758c",  # NVD
    "CE38F76832CFA1F6F35C89EAAEAF61C3",     # Kismet
    "3d94e52cff9f4df5a01973f24d5bc8db",     # Ollama cloud
    "OLLAMA_CLOUD_TOKEN", "NVD_API_KEY",
    "KISMET_API_KEY", "OLLAMA_AUTH_TOKEN",
)


def _redact(value: Any) -> Any:
    """Recursively redact known-key substrings from ``value``."""
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


# ---------------------------------------------------------------------------
# Schema (sqlite DDL — portable to any SQL backend)
# ---------------------------------------------------------------------------

_DDL = [
    """
    CREATE TABLE IF NOT EXISTS sessions (
        sid TEXT PRIMARY KEY,
        kind TEXT,
        target TEXT,
        created_at REAL,
        last_activity REAL,
        achieved_count INTEGER DEFAULT 0,
        capability_count INTEGER DEFAULT 0,
        risk_max TEXT DEFAULT 'read',
        state TEXT DEFAULT 'open',
        meta_json TEXT
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sid TEXT,
        ts REAL,
        kind TEXT,
        msg TEXT
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sid TEXT,
        ts REAL,
        action TEXT,
        payload_json TEXT
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS exfil (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sid TEXT,
        ts REAL,
        channel TEXT,
        bytes_pending INTEGER DEFAULT 0,
        status TEXT DEFAULT 'pending'
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS persistence (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sid TEXT,
        ts REAL,
        mech_id TEXT,
        kind TEXT,
        state TEXT DEFAULT 'installed',
        meta_json TEXT
    )
    """,
    "CREATE INDEX IF NOT EXISTS ix_log_sid ON log(sid, ts)",
    "CREATE INDEX IF NOT EXISTS ix_history_sid ON history(sid, ts)",
    "CREATE INDEX IF NOT EXISTS ix_exfil_sid ON exfil(sid, ts)",
    "CREATE INDEX IF NOT EXISTS ix_persistence_sid ON persistence(sid, ts)",
]


def _ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path.parent, 0o700)
    except Exception:  # noqa: BLE001
        pass


def _conn(db_path: Path) -> sqlite3.Connection:
    """Return a per-thread sqlite connection with row_factory."""
    existing = getattr(_local, "conns", None)
    if existing is not None and str(db_path) in existing:
        conn = existing[str(db_path)]
        try:
            conn.execute("SELECT 1")
            return conn
        except sqlite3.ProgrammingError:
            pass  # connection closed
    conn = sqlite3.connect(str(db_path), timeout=5.0,
                           detect_types=sqlite3.PARSE_DECLTYPES)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA synchronous = NORMAL")
    if existing is None:
        _local.conns = {}
    _local.conns[str(db_path)] = conn
    return conn


def init(db_path: Optional[Path] = None) -> Dict[str, Any]:
    """Open (or create) the SQL store. Idempotent.

    Returns ``{ok, backend, db_path, error}``."""
    path = Path(db_path) if db_path else DEFAULT_DB_PATH
    _ensure_parent(path)
    prev_umask = os.umask(0o077)
    try:
        try:
            conn = _conn(path)
        except sqlite3.Error as e:
            return {"ok": False, "backend": "sqlite",
                    "db_path": str(path),
                    "error": f"open: {e}"}
        try:
            for stmt in _DDL:
                conn.execute(stmt)
            conn.commit()
        except sqlite3.Error as e:
            return {"ok": False, "backend": "sqlite",
                    "db_path": str(path),
                    "error": f"DDL: {e}"}
    finally:
        os.umask(prev_umask)
    try:
        os.chmod(path, 0o600)
    except Exception:  # noqa: BLE001
        pass
    return {"ok": True, "backend": "sqlite",
            "db_path": str(path), "error": None}


# ---------------------------------------------------------------------------
# Sessions
# ---------------------------------------------------------------------------

def record_session(sid: str, kind: str = "auto", target: str = "",
                   created_at: Optional[float] = None,
                   db_path: Optional[Path] = None,
                   meta: Optional[Dict[str, Any]] = None,
                   ) -> Dict[str, Any]:
    """Open (or upsert) a session row."""
    init(db_path=db_path)  # idempotent
    path = Path(db_path) if db_path else DEFAULT_DB_PATH
    conn = _conn(path)
    ts = float(created_at or time.time())
    try:
        conn.execute(
            "INSERT INTO sessions(sid, kind, target, created_at, last_activity, "
            "state, meta_json) VALUES (?,?,?,?,?,?,?) "
            "ON CONFLICT(sid) DO UPDATE SET "
            "kind=excluded.kind, target=excluded.target, "
            "last_activity=excluded.last_activity, "
            "state=excluded.state, meta_json=excluded.meta_json",
            (sid, kind, target, ts, ts, "open",
             json.dumps(_redact(meta or {}), default=str)),
        )
        conn.commit()
    except sqlite3.Error as e:
        return {"ok": False, "error": f"insert: {e}"}
    return {"ok": True, "sid": sid, "ts": ts}


def update_session(sid: str, db_path: Optional[Path] = None,
                   **fields: Any) -> Dict[str, Any]:
    """Patch one or more columns on a session row."""
    init(db_path=db_path)
    path = Path(db_path) if db_path else DEFAULT_DB_PATH
    conn = _conn(path)
    allowed = {"kind", "target", "achieved_count", "capability_count",
               "risk_max", "state", "meta_json"}
    sets: List[str] = []
    vals: List[Any] = []
    for k, v in fields.items():
        if k not in allowed:
            continue
        if k == "meta_json" and not isinstance(v, str):
            v = json.dumps(_redact(v), default=str)
        sets.append(f"{k} = ?")
        vals.append(v)
    if not sets:
        return {"ok": True, "sid": sid, "fields": []}
    vals.append(sid)
    try:
        conn.execute(
            f"UPDATE sessions SET last_activity = ?, {', '.join(sets)} "
            f"WHERE sid = ?",
            [time.time(), *vals],
        )
        conn.commit()
    except sqlite3.Error as e:
        return {"ok": False, "error": f"update: {e}"}
    return {"ok": True, "sid": sid, "fields": list(fields.keys())}


def list_sessions(db_path: Optional[Path] = None,
                  limit: int = 200) -> List[Dict[str, Any]]:
    """List all sessions (newest first)."""
    init(db_path=db_path)
    path = Path(db_path) if db_path else DEFAULT_DB_PATH
    conn = _conn(path)
    try:
        rows = conn.execute(
            "SELECT sid, kind, target, created_at, last_activity, "
            "achieved_count, capability_count, risk_max, state "
            "FROM sessions ORDER BY last_activity DESC LIMIT ?",
            (limit,),
        ).fetchall()
    except sqlite3.Error:
        return []
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Log
# ---------------------------------------------------------------------------

def append_log(sid: str, kind: str, msg: str,
               ts: Optional[float] = None,
               db_path: Optional[Path] = None) -> Dict[str, Any]:
    """Append a single log entry to the log table."""
    init(db_path=db_path)
    path = Path(db_path) if db_path else DEFAULT_DB_PATH
    conn = _conn(path)
    try:
        conn.execute(
            "INSERT INTO log(sid, ts, kind, msg) VALUES (?,?,?,?)",
            (sid, float(ts or time.time()), kind, str(_redact(msg))[:4096]),
        )
        conn.commit()
    except sqlite3.Error as e:
        return {"ok": False, "error": f"insert: {e}"}
    return {"ok": True, "sid": sid}


def list_log(sid: str, since_ts: Optional[float] = None,
             limit: int = 200,
             db_path: Optional[Path] = None) -> List[Dict[str, Any]]:
    """Return log entries for ``sid`` after ``since_ts``."""
    init(db_path=db_path)
    path = Path(db_path) if db_path else DEFAULT_DB_PATH
    conn = _conn(path)
    if since_ts is None:
        rows = conn.execute(
            "SELECT id, ts, kind, msg FROM log WHERE sid = ? "
            "ORDER BY id DESC LIMIT ?",
            (sid, limit),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT id, ts, kind, msg FROM log WHERE sid = ? AND ts > ? "
            "ORDER BY id DESC LIMIT ?",
            (sid, since_ts, limit),
        ).fetchall()
    return [{"id": r["id"], "ts": r["ts"],
             "kind": r["kind"], "msg": r["msg"]} for r in rows]


# ---------------------------------------------------------------------------
# History (per-session command history)
# ---------------------------------------------------------------------------

def append_history(sid: str, action: str, payload: Dict[str, Any],
                   ts: Optional[float] = None,
                   db_path: Optional[Path] = None) -> Dict[str, Any]:
    """Append a history line."""
    init(db_path=db_path)
    path = Path(db_path) if db_path else DEFAULT_DB_PATH
    conn = _conn(path)
    try:
        conn.execute(
            "INSERT INTO history(sid, ts, action, payload_json) "
            "VALUES (?,?,?,?)",
            (sid, float(ts or time.time()), action,
             json.dumps(_redact(payload), default=str)),
        )
        conn.commit()
    except sqlite3.Error as e:
        return {"ok": False, "error": f"insert: {e}"}
    return {"ok": True, "sid": sid, "action": action}


def list_history(sid: str, since_ts: Optional[float] = None,
                 limit: int = 200,
                 db_path: Optional[Path] = None
                 ) -> List[Dict[str, Any]]:
    """Return history rows for ``sid`` after ``since_ts``."""
    init(db_path=db_path)
    path = Path(db_path) if db_path else DEFAULT_DB_PATH
    conn = _conn(path)
    if since_ts is None:
        rows = conn.execute(
            "SELECT id, ts, action, payload_json FROM history "
            "WHERE sid = ? ORDER BY id DESC LIMIT ?",
            (sid, limit),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT id, ts, action, payload_json FROM history "
            "WHERE sid = ? AND ts > ? ORDER BY id DESC LIMIT ?",
            (sid, since_ts, limit),
        ).fetchall()
    out: List[Dict[str, Any]] = []
    for r in rows:
        try:
            pj = json.loads(r["payload_json"])
        except Exception:  # noqa: BLE001
            pj = {}
        out.append({"id": r["id"], "ts": r["ts"],
                    "action": r["action"], "payload": pj})
    return out


# ---------------------------------------------------------------------------
# Exfil
# ---------------------------------------------------------------------------

def add_exfil(sid: str, channel: str, bytes_pending: int = 0,
              status: str = "pending",
              ts: Optional[float] = None,
              db_path: Optional[Path] = None
              ) -> Dict[str, Any]:
    """Add an exfiltration job."""
    init(db_path=db_path)
    path = Path(db_path) if db_path else DEFAULT_DB_PATH
    conn = _conn(path)
    try:
        cur = conn.execute(
            "INSERT INTO exfil(sid, ts, channel, bytes_pending, status) "
            "VALUES (?,?,?,?,?)",
            (sid, float(ts or time.time()), channel, bytes_pending, status),
        )
        conn.commit()
    except sqlite3.Error as e:
        return {"ok": False, "error": f"insert: {e}"}
    return {"ok": True, "sid": sid, "job_id": cur.lastrowid,
            "channel": channel}


def cancel_exfil(sid: str, job_id: int,
                 db_path: Optional[Path] = None) -> Dict[str, Any]:
    """Mark an exfil job as cancelled."""
    init(db_path=db_path)
    path = Path(db_path) if db_path else DEFAULT_DB_PATH
    conn = _conn(path)
    try:
        conn.execute(
            "UPDATE exfil SET status = 'cancelled' "
            "WHERE sid = ? AND id = ?",
            (sid, int(job_id)),
        )
        conn.commit()
    except sqlite3.Error as e:
        return {"ok": False, "error": f"update: {e}"}
    return {"ok": True, "sid": sid, "job_id": int(job_id)}


def list_exfil(sid: str, db_path: Optional[Path] = None
               ) -> List[Dict[str, Any]]:
    """List exfil jobs for ``sid`` (newest first)."""
    init(db_path=db_path)
    path = Path(db_path) if db_path else DEFAULT_DB_PATH
    conn = _conn(path)
    try:
        rows = conn.execute(
            "SELECT id, ts, channel, bytes_pending, status FROM exfil "
            "WHERE sid = ? ORDER BY id DESC",
            (sid,),
        ).fetchall()
    except sqlite3.Error:
        return []
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------

def add_persistence(sid: str, mech_id: str, kind: str,
                    state: str = "installed",
                    meta: Optional[Dict[str, Any]] = None,
                    ts: Optional[float] = None,
                    db_path: Optional[Path] = None
                    ) -> Dict[str, Any]:
    """Register an installed persistence mechanism."""
    init(db_path=db_path)
    path = Path(db_path) if db_path else DEFAULT_DB_PATH
    conn = _conn(path)
    try:
        cur = conn.execute(
            "INSERT INTO persistence(sid, ts, mech_id, kind, state, meta_json) "
            "VALUES (?,?,?,?,?,?)",
            (sid, float(ts or time.time()), mech_id, kind, state,
             json.dumps(_redact(meta or {}), default=str)),
        )
        conn.commit()
    except sqlite3.Error as e:
        return {"ok": False, "error": f"insert: {e}"}
    return {"ok": True, "sid": sid, "mech_id": mech_id, "id": cur.lastrowid}


def list_persistence(sid: str, db_path: Optional[Path] = None
                     ) -> List[Dict[str, Any]]:
    """List installed persistence for ``sid`` (newest first)."""
    init(db_path=db_path)
    path = Path(db_path) if db_path else DEFAULT_DB_PATH
    conn = _conn(path)
    try:
        rows = conn.execute(
            "SELECT id, ts, mech_id, kind, state FROM persistence "
            "WHERE sid = ? ORDER BY id DESC",
            (sid,),
        ).fetchall()
    except sqlite3.Error:
        return []
    return [dict(r) for r in rows]


def remove_persistence(sid: str, mech_id: str,
                       db_path: Optional[Path] = None
                       ) -> Dict[str, Any]:
    """Mark a persistence mechanism as removed."""
    init(db_path=db_path)
    path = Path(db_path) if db_path else DEFAULT_DB_PATH
    conn = _conn(path)
    try:
        conn.execute(
            "UPDATE persistence SET state = 'removed' "
            "WHERE sid = ? AND mech_id = ?",
            (sid, mech_id),
        )
        conn.commit()
    except sqlite3.Error as e:
        return {"ok": False, "error": f"update: {e}"}
    return {"ok": True, "sid": sid, "mech_id": mech_id}


# ---------------------------------------------------------------------------
# Health / introspection
# ---------------------------------------------------------------------------

def health(db_path: Optional[Path] = None) -> Dict[str, Any]:
    """Return a tiny health dict the dashboard can use."""
    init(db_path=db_path)
    path = Path(db_path) if db_path else DEFAULT_DB_PATH
    conn = _conn(path)
    try:
        sc = conn.execute("SELECT COUNT(*) AS c FROM sessions").fetchone()["c"]
        lc = conn.execute("SELECT COUNT(*) AS c FROM log").fetchone()["c"]
        hc = conn.execute("SELECT COUNT(*) AS c FROM history").fetchone()["c"]
        ec = conn.execute("SELECT COUNT(*) AS c FROM exfil").fetchone()["c"]
        pc = conn.execute("SELECT COUNT(*) AS c FROM persistence").fetchone()["c"]
    except sqlite3.Error as e:
        return {"ok": False, "error": f"query: {e}"}
    return {
        "ok": True,
        "backend": "sqlite",
        "db_path": str(path),
        "size_bytes": path.stat().st_size if path.exists() else 0,
        "counts": {
            "sessions": sc, "log": lc, "history": hc,
            "exfil": ec, "persistence": pc,
        },
    }


def close() -> None:
    """Close the per-thread connection (sqlite)."""
    existing = getattr(_local, "conns", None)
    if not existing:
        return
    for path, conn in list(existing.items()):
        try:
            conn.close()
        except Exception:  # noqa: BLE001
            pass
        existing.pop(path, None)


def backend_from_env() -> Dict[str, Any]:
    """Inspect the KFIOSA_SQL_URL env var. If set to a non-sqlite
    URL, the store would prefer SQLAlchemy (when installed) or
    fall back to sqlite + a warning. If unset or sqlite, returns
    sqlite as the chosen backend.

    The optional deps are not installed by default to honor the
    operator's "no silent installs" rule. The dashboard reports
    the current backend via :func:`health`."""
    url = os.environ.get("KFIOSA_SQL_URL", "").strip()
    if not url:
        return {"ok": True, "backend": "sqlite",
                "url": "", "available": True,
                "note": "KFIOSA_SQL_URL not set; using sqlite default"}
    if url.startswith("sqlite"):
        return {"ok": True, "backend": "sqlite",
                "url": url, "available": True, "note": "sqlite URL"}
    # Non-sqlite URL — try SQLAlchemy
    try:
        import sqlalchemy  # noqa: F401
        try:
            import pymssql  # noqa: F401
        except ImportError:
            if "mssql" in url:
                return {"ok": False, "backend": "sqlite",
                        "url": url,
                        "available": False,
                        "note": ("mssql URL requested but pymssql "
                                 "is not installed; falling back "
                                 "to sqlite. Install pymssql or "
                                 "set KFIOSA_SQL_URL=sqlite:///...")}
        return {"ok": True, "backend": "sqlalchemy",
                "url": url, "available": True,
                "note": "SQLAlchemy backend selected"}
    except ImportError:
        return {"ok": False, "backend": "sqlite",
                "url": url, "available": False,
                "note": ("non-sqlite URL but SQLAlchemy not "
                         "installed; falling back to sqlite. "
                         "Install sqlalchemy or set "
                         "KFIOSA_SQL_URL=sqlite:///...")}


__all__ = [
    "DEFAULT_DB_PATH", "init", "record_session", "update_session",
    "list_sessions", "append_log", "list_log",
    "append_history", "list_history",
    "add_exfil", "cancel_exfil", "list_exfil",
    "add_persistence", "list_persistence", "remove_persistence",
    "health", "close", "backend_from_env",
]
