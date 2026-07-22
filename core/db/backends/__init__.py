"""core.db.backends — pluggable SQL backend for KFIOSA.

Phase 3 expansion: extract the public SQL surface from
``core.db.sqlstore`` into a backend-protocol so that
SQLAlchemy/pymssql can be plugged in via the
``KFIOSA_SQL_URL`` environment variable.

The public surface is intentionally small — it is what the
existing ``core.db.sqlstore`` already exposes:

* ``init(db_path=None)``
* ``record_session(sid, kind, target, ...)``
* ``update_session(sid, **fields)``
* ``list_sessions()``
* ``append_log(sid, kind, msg)``
* ``list_log(sid, since_ts=None, limit=200)``
* ``append_history(sid, action, payload)``
* ``list_history(sid, since_ts=None, limit=200)``
* ``add_exfil(sid, channel, bytes_pending, status)``
* ``cancel_exfil(sid, job_id)``
* ``list_exfil(sid)``
* ``add_persistence(sid, mech_id, kind, ...)``
* ``list_persistence(sid)``
* ``remove_persistence(sid, mech_id)``
* ``health()``
* ``close()``
* ``backend_from_env()``

Two backends are wired in:

* **sqlite** (default, stdlib). File at
  ``~/.kfiosa/kfiosa.db`` with ``os.umask(0o077)`` so the file is
  owner-readable only. No external dependency. Always available.

* **sqlalchemy** (optional). Used when ``KFIOSA_SQL_URL`` is set
  to a non-sqlite URL **and** ``sqlalchemy`` is importable. For
  SQL Server, ``pymssql`` is loaded lazily.

Selection logic lives in :func:`get_backend` — it calls
:func:`core.db.sqlstore.backend_from_env` first; if the answer is
"sqlite" (because the URL is unset, is sqlite, or because the
optional deps are missing) it returns the sqlite backend; otherwise
it returns the SQLAlchemy backend.

Backends MUST implement the 16 functions above. They MUST return
the same ``{ok, error}`` envelope on failure. They MUST never
raise. They MUST redact known-key substrings before write.
"""
from __future__ import annotations

from typing import Any, Dict


def get_backend() -> Any:
    """Return the active backend module.

    Returns either :mod:`core.db.backends.sqlite_backend` or
    :mod:`core.db.backends.sqlalchemy_backend`. The returned object
    exposes the 16-function public surface (the same as
    :mod:`core.db.sqlstore`).
    """
    # Defer import to keep the cold-start path cheap and to avoid
    # any SQLAlchemy import on systems that only have sqlite.
    from core.db.sqlstore import backend_from_env
    info = backend_from_env()
    if not info.get("ok"):
        # SQLAlchemy import failed or mssql missing — fall back to sqlite
        from core.db.backends import sqlite_backend
        return sqlite_backend
    if info.get("backend") == "sqlalchemy":
        from core.db.backends import sqlalchemy_backend
        return sqlalchemy_backend
    from core.db.backends import sqlite_backend
    return sqlite_backend


def describe_backend() -> Dict[str, Any]:
    """Return a one-line description of the active backend."""
    b = get_backend()
    return {
        "ok": True,
        "backend": getattr(b, "BACKEND_NAME", "unknown"),
        "module": getattr(b, "__name__", "?"),
    }
