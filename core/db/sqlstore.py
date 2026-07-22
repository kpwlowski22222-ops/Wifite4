"""core.db — SQL store for KFIOSA sessions, history, exfil, audit.

Phase 3 — backends:

* **sqlite** (default, stdlib). File at ``~/.kfiosa/kfiosa.db`` with
  ``os.umask(0o077)`` so the file is owner-readable only. No
  external dependency. Always available.

* **sqlalchemy** (optional). If ``sqlalchemy`` is importable and
  ``KFIOSA_SQL_URL`` is set to a non-sqlite URL, the store uses
  SQLAlchemy's create_engine. ``pymssql`` is loaded lazily when
  the URL scheme is ``mssql+pymssql://`` for SQL Server.

The store exposes a tiny, stable surface (16 functions):

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
* ``backend_from_env()`` — what *would* be selected given the env.

All methods NEVER raise; they return ``{ok, error}`` envelopes
on failure. The dashboard consumes these envelopes directly.

This module is now a **thin router** over the backend selected
by :func:`core.db.backends.get_backend`. The actual implementations
live in:

* :mod:`core.db.backends.sqlite_backend` — the canonical sqlite
  implementation (also reachable directly when SQLAlchemy is
  unavailable).
* :mod:`core.db.backends.sqlalchemy_backend` — used when
  ``KFIOSA_SQL_URL`` is set to a non-sqlite URL and SQLAlchemy +
  pymssql are installed.

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

import os
from pathlib import Path
from typing import Any, Dict, List, Optional


DEFAULT_DB_PATH = Path.home() / ".kfiosa" / "kfiosa.db"


# ---------------------------------------------------------------------------
# Backend selection (cached; only the env var matters for the choice)
# ---------------------------------------------------------------------------


def _backend():
    """Return the active backend module. Delegates to
    :func:`core.db.backends.get_backend` so the choice is consistent
    across both entry points."""
    from core.db.backends import get_backend
    return get_backend()


# ---------------------------------------------------------------------------
# Public surface — every function is a thin pass-through to the backend
# ---------------------------------------------------------------------------


def init(db_path: Optional[Path] = None) -> Dict[str, Any]:
    """Open (or create) the SQL store. Idempotent."""
    return _backend().init(db_path)


def record_session(sid: str, kind: str = "auto", target: str = "",
                   created_at: Optional[float] = None,
                   db_path: Optional[Path] = None,
                   meta: Optional[Dict[str, Any]] = None,
                   ) -> Dict[str, Any]:
    """Open (or upsert) a session row."""
    return _backend().record_session(
        sid, kind=kind, target=target, created_at=created_at,
        db_path=db_path, meta=meta,
    )


def update_session(sid: str, db_path: Optional[Path] = None,
                   **fields: Any) -> Dict[str, Any]:
    """Patch one or more columns on a session row."""
    return _backend().update_session(sid, db_path=db_path, **fields)


def list_sessions(db_path: Optional[Path] = None,
                  limit: int = 200) -> List[Dict[str, Any]]:
    """List all sessions (newest first)."""
    return _backend().list_sessions(db_path=db_path, limit=limit)


def append_log(sid: str, kind: str, msg: str,
               ts: Optional[float] = None,
               db_path: Optional[Path] = None) -> Dict[str, Any]:
    """Append a single log entry to the log table."""
    return _backend().append_log(sid, kind, msg, ts=ts, db_path=db_path)


def list_log(sid: str, since_ts: Optional[float] = None,
             limit: int = 200,
             db_path: Optional[Path] = None) -> List[Dict[str, Any]]:
    """Return log entries for ``sid`` after ``since_ts``."""
    return _backend().list_log(sid, since_ts=since_ts, limit=limit,
                               db_path=db_path)


def append_history(sid: str, action: str, payload: Dict[str, Any],
                   ts: Optional[float] = None,
                   db_path: Optional[Path] = None) -> Dict[str, Any]:
    """Append a history line."""
    return _backend().append_history(sid, action, payload, ts=ts,
                                    db_path=db_path)


def list_history(sid: str, since_ts: Optional[float] = None,
                 limit: int = 200,
                 db_path: Optional[Path] = None
                 ) -> List[Dict[str, Any]]:
    """Return history rows for ``sid`` after ``since_ts``."""
    return _backend().list_history(sid, since_ts=since_ts, limit=limit,
                                   db_path=db_path)


def add_exfil(sid: str, channel: str, bytes_pending: int = 0,
              status: str = "pending",
              ts: Optional[float] = None,
              db_path: Optional[Path] = None,
              ) -> Dict[str, Any]:
    """Add an exfiltration job."""
    return _backend().add_exfil(sid, channel, bytes_pending=bytes_pending,
                                status=status, ts=ts, db_path=db_path)


def cancel_exfil(sid: str, job_id: int,
                 db_path: Optional[Path] = None) -> Dict[str, Any]:
    """Mark an exfil job as cancelled."""
    return _backend().cancel_exfil(sid, job_id, db_path=db_path)


def list_exfil(sid: str, db_path: Optional[Path] = None
               ) -> List[Dict[str, Any]]:
    """List exfil jobs for ``sid`` (newest first)."""
    return _backend().list_exfil(sid, db_path=db_path)


def add_persistence(sid: str, mech_id: str, kind: str,
                    state: str = "installed",
                    meta: Optional[Dict[str, Any]] = None,
                    ts: Optional[float] = None,
                    db_path: Optional[Path] = None,
                    ) -> Dict[str, Any]:
    """Register an installed persistence mechanism."""
    return _backend().add_persistence(sid, mech_id, kind, state=state,
                                      meta=meta, ts=ts, db_path=db_path)


def list_persistence(sid: str, db_path: Optional[Path] = None
                     ) -> List[Dict[str, Any]]:
    """List installed persistence for ``sid`` (newest first)."""
    return _backend().list_persistence(sid, db_path=db_path)


def remove_persistence(sid: str, mech_id: str,
                       db_path: Optional[Path] = None
                       ) -> Dict[str, Any]:
    """Mark a persistence mechanism as removed."""
    return _backend().remove_persistence(sid, mech_id, db_path=db_path)


def health(db_path: Optional[Path] = None) -> Dict[str, Any]:
    """Return a tiny health dict the dashboard can use."""
    return _backend().health(db_path=db_path)


def close() -> None:
    """Close the per-thread connection (sqlite only)."""
    return _backend().close()


def backend_from_env() -> Dict[str, Any]:
    """Inspect the KFIOSA_SQL_URL env var. If set to a non-sqlite
    URL, the store would prefer SQLAlchemy (when installed) or
    fall back to sqlite + a warning. If unset or sqlite, returns
    sqlite as the chosen backend.

    The optional deps are not installed by default to honor the
    operator's "no silent installs" rule. The dashboard reports
    the current backend via :func:`health`.
    """
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
