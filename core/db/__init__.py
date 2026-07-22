"""core.db — SQL store for KFIOSA.

Phase 2.4+ — see :mod:`core.db.sqlstore` for the implementation.

This package re-exports the stable surface from :mod:`.sqlstore`.
"""
from __future__ import annotations

from .sqlstore import (
    DEFAULT_DB_PATH,
    init,
    record_session,
    update_session,
    list_sessions,
    append_log,
    list_log,
    append_history,
    list_history,
    add_exfil,
    cancel_exfil,
    list_exfil,
    add_persistence,
    list_persistence,
    remove_persistence,
    health,
    close,
)

__all__ = [
    "DEFAULT_DB_PATH",
    "init",
    "record_session",
    "update_session",
    "list_sessions",
    "append_log",
    "list_log",
    "append_history",
    "list_history",
    "add_exfil",
    "cancel_exfil",
    "list_exfil",
    "add_persistence",
    "list_persistence",
    "remove_persistence",
    "health",
    "close",
]
