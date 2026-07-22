"""tests.test_db_schema_compat — Phase 3: cross-backend schema compatibility.

Verifies the two backends use the SAME table names so a session
written via sqlite can be read via SQLAlchemy (and vice versa).
This is the T5 schema-normalisation guarantee.

Before the fix:
* sqlite:    tables named `sessions`, `log`, `history`, `exfil`, `persistence`
* SQLAlchemy: tables named `kf_sessions`, `kf_log`, `kf_history`,
              `kf_exfil`, `kf_persistence` (the kf_ prefix was a
              vestige of an earlier schema-design attempt)

That mismatch made it impossible to migrate a session from one
backend to the other without an ETL step.
"""
from __future__ import annotations

import re
from pathlib import Path


def _read_module(path: str) -> str:
    return Path(path).read_text(encoding="utf-8")


def test_sqlite_backend_uses_unprefixed_table_names():
    """sqlite_backend.py must reference the unprefixed table names."""
    src = _read_module("/home/user/Pulpit/kfiosa/core/db/backends/sqlite_backend.py")
    for table in ("sessions", "log", "history", "exfil", "persistence"):
        # The string `CREATE TABLE IF NOT EXISTS <table>` must appear
        # (case-insensitive).
        assert re.search(rf"CREATE\s+TABLE\s+IF\s+NOT\s+EXISTS\s+{table}\b",
                         src, re.IGNORECASE), (
            f"sqlite_backend.py missing CREATE TABLE for {table!r}"
        )
    # And must NOT use the kf_ prefix anywhere in the DDL.
    for tbl in ("kf_sessions", "kf_log", "kf_history", "kf_exfil",
                "kf_persistence"):
        assert tbl not in src, (
            f"sqlite_backend.py still references {tbl!r} (vestigial kf_ prefix)"
        )


def test_sqlalchemy_backend_uses_unprefixed_table_names():
    """sqlalchemy_backend.py must use the same unprefixed table names
    so the two backends share a schema."""
    src = _read_module("/home/user/Pulpit/kfiosa/core/db/backends/sqlalchemy_backend.py")
    for table in ("sessions", "log", "history", "exfil", "persistence"):
        # The DDL strings include CREATE TABLE <table>.
        assert f"CREATE TABLE {table}" in src, (
            f"sqlalchemy_backend.py missing CREATE TABLE for {table!r}"
        )
    # And must NOT use the kf_ prefix.
    for tbl in ("kf_sessions", "kf_log", "kf_history", "kf_exfil",
                "kf_persistence"):
        # Allow the word "kf_" in docstrings (e.g. ``kf_`` is mentioned
        # in the description of the previous bug), but not in SQL.
        for line in src.splitlines():
            if line.strip().startswith("#") or line.strip().startswith('"""'):
                continue
            if "'''" in line:
                continue
            assert tbl not in line, (
                f"sqlalchemy_backend.py still uses {tbl!r} in non-doc line: {line!r}"
            )


def test_both_backends_define_same_16_function_surface():
    """Each backend must expose the same 16 public functions so
    callers (and the dashboard) can swap them transparently."""
    expected = {
        "init", "record_session", "update_session", "list_sessions",
        "append_log", "list_log", "append_history", "list_history",
        "add_exfil", "cancel_exfil", "list_exfil",
        "add_persistence", "list_persistence", "remove_persistence",
        "health", "close", "backend_from_env",
    }
    for modpath in (
        "/home/user/Pulpit/kfiosa/core/db/backends/sqlite_backend.py",
        "/home/user/Pulpit/kfiosa/core/db/backends/sqlalchemy_backend.py",
    ):
        src = _read_module(modpath)
        defined = set(re.findall(r"^def\s+(\w+)\s*\(", src, re.MULTILINE))
        missing = expected - defined
        assert not missing, (
            f"{modpath} missing public functions: {missing}"
        )


def test_both_backends_use_same_redact_keys():
    """Redaction must be byte-identical across backends so a payload
    redacted in sqlite is the same string after redaction in
    SQLAlchemy (and vice versa)."""
    sqlite_src = _read_module("/home/user/Pulpit/kfiosa/core/db/backends/sqlite_backend.py")
    sa_src = _read_module("/home/user/Pulpit/kfiosa/core/db/backends/sqlalchemy_backend.py")

    # Extract the _REDACT_KEYS tuple contents. Strip comments and
    # string-quote-wrapped keys to get the canonical set.
    def _extract(src):
        m = re.search(r"_REDACT_KEYS[^=]*=\s*\((.*?)\)", src, re.DOTALL)
        assert m, "no _REDACT_KEYS tuple"
        body = m.group(1)
        # Strip comments: anything from `#` to end-of-line.
        body = re.sub(r"#[^\n]*", "", body)
        # Find every quoted string.
        keys = set(re.findall(r"""['"]([^'"]+)['"]""", body))
        return keys

    sqlite_keys = _extract(sqlite_src)
    sa_keys = _extract(sa_src)
    assert sqlite_keys == sa_keys, (
        f"redaction keys diverge: only-in-sqlite={sqlite_keys - sa_keys}, "
        f"only-in-sqlalchemy={sa_keys - sqlite_keys}"
    )


def test_sqlstore_routes_through_backends():
    """core.db.sqlstore must route every public call through the
    selected backend — it must not embed sqlite-specific code in the
    module body."""
    src = _read_module("/home/user/Pulpit/kfiosa/core/db/sqlstore.py")
    # sqlite3 must NOT be imported in the router.
    assert "import sqlite3" not in src, (
        "sqlstore.py imports sqlite3 — it should route through backends"
    )
    # The `_backend()` helper must be called for the public functions.
    assert "def _backend" in src, "sqlstore.py missing _backend() helper"
    for fn in ("def init(", "def record_session(", "def list_sessions(",
               "def append_log(", "def add_exfil("):
        assert fn in src, f"sqlstore.py missing {fn}"
