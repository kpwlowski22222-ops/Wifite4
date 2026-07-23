"""Catalog JSON → SQLite store for fast filtered queries.

Ingests every ``catalog/*.json`` (except schema/meta files) into a
dedicated DB (default ``~/.kfiosa/catalog.db``). The AI / tool router
(:mod:`core.catalog.source_router`) picks SQL vs on-disk JSON vs
in-memory index based on readiness and estimated cost.

Never fabricates catalog entries; ingest is a pure projection of files.
"""
from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

__all__ = [
    "catalog_db_path",
    "init_catalog_db",
    "ingest_catalog",
    "ingest_file",
    "search_sql",
    "get_by_id",
    "get_by_path",
    "count_stats",
    "sql_ready",
    "list_surfaces",
]

_SKIP_NAMES = frozenset({
    "catalog.schema.json",
    "catalog.txt",
    "catalog.min.json",
})

_DEFAULT_CATALOG = Path(__file__).resolve().parents[2] / "catalog"
_lock = threading.RLock()
_conn_local = threading.local()


def catalog_db_path(db_path: Optional[Path] = None) -> Path:
    if db_path is not None:
        return Path(db_path)
    raw = (os.environ.get("KFIOSA_CATALOG_DB") or "").strip()
    if raw:
        return Path(raw).expanduser()
    return Path.home() / ".kfiosa" / "catalog.db"


def _connect(db_path: Optional[Path] = None) -> sqlite3.Connection:
    path = catalog_db_path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    key = str(path)
    cache = getattr(_conn_local, "conns", None)
    if cache is None:
        _conn_local.conns = {}
        cache = _conn_local.conns
    conn = cache.get(key)
    if conn is None:
        conn = sqlite3.connect(str(path), check_same_thread=False, timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA temp_store=MEMORY")
        cache[key] = conn
    return conn


def init_catalog_db(db_path: Optional[Path] = None) -> Dict[str, Any]:
    """Create schema if missing. Idempotent."""
    try:
        conn = _connect(db_path)
        with _lock:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS catalog_meta (
                    key TEXT PRIMARY KEY,
                    value TEXT
                );
                CREATE TABLE IF NOT EXISTS catalog_entries (
                    entry_id TEXT PRIMARY KEY,
                    path TEXT UNIQUE NOT NULL,
                    filename TEXT,
                    kind TEXT,
                    name TEXT,
                    full_name TEXT,
                    category TEXT,
                    attack_surface TEXT,
                    phase_hint TEXT,
                    tags TEXT,
                    summary TEXT,
                    url TEXT,
                    toolbox_path TEXT,
                    payload_json TEXT NOT NULL,
                    mtime REAL,
                    size_bytes INTEGER,
                    ingested_at REAL
                );
                CREATE INDEX IF NOT EXISTS ix_cat_kind ON catalog_entries(kind);
                CREATE INDEX IF NOT EXISTS ix_cat_surface ON catalog_entries(attack_surface);
                CREATE INDEX IF NOT EXISTS ix_cat_phase ON catalog_entries(phase_hint);
                CREATE INDEX IF NOT EXISTS ix_cat_category ON catalog_entries(category);
                CREATE INDEX IF NOT EXISTS ix_cat_name ON catalog_entries(name);
                CREATE INDEX IF NOT EXISTS ix_cat_mtime ON catalog_entries(mtime);

                CREATE TABLE IF NOT EXISTS catalog_stats (
                    key TEXT PRIMARY KEY,
                    value_json TEXT,
                    updated_at REAL
                );

                CREATE VIRTUAL TABLE IF NOT EXISTS catalog_fts USING fts5(
                    entry_id UNINDEXED,
                    name,
                    full_name,
                    category,
                    tags,
                    summary,
                    body,
                    tokenize = 'porter'
                );
                """
            )
            conn.commit()
        return {"ok": True, "path": str(catalog_db_path(db_path))}
    except Exception as e:
        return {"ok": False, "error": str(e)[:200]}


def _first_str(val: Any) -> str:
    if isinstance(val, list) and val:
        return str(val[0])
    if isinstance(val, str):
        return val
    return ""


def _tags_str(entry: Dict[str, Any]) -> str:
    tags = entry.get("tags")
    if isinstance(tags, list):
        return " ".join(str(t) for t in tags if t)
    if isinstance(tags, str):
        return tags
    return ""


def _body_text(entry: Dict[str, Any]) -> str:
    parts: List[str] = []
    for k in (
        "name", "full_name", "summary", "description", "title",
        "category", "kind",
    ):
        v = entry.get(k)
        if isinstance(v, str) and v:
            parts.append(v)
    docs = entry.get("documentation")
    if isinstance(docs, dict):
        for k in ("readme",):
            v = docs.get(k)
            if isinstance(v, str) and v:
                parts.append(v[:2000])
    return " ".join(parts)


def ingest_file(
    path: Path,
    *,
    db_path: Optional[Path] = None,
    conn: Optional[sqlite3.Connection] = None,
) -> Dict[str, Any]:
    """Upsert one catalog JSON file into SQL."""
    path = Path(path)
    if path.name in _SKIP_NAMES or not path.suffix == ".json":
        return {"ok": False, "skipped": True, "path": str(path)}
    try:
        st = path.stat()
        raw = path.read_text(encoding="utf-8", errors="replace")
        data = json.loads(raw)
        if not isinstance(data, dict):
            return {"ok": False, "error": "not an object", "path": str(path)}
    except Exception as e:
        return {"ok": False, "error": str(e)[:160], "path": str(path)}

    entry_id = str(data.get("id") or path.stem)
    surface = _first_str(data.get("attack_surface")).lower()
    phase = _first_str(data.get("phase_hint")).lower()
    tags = _tags_str(data)
    name = str(data.get("name") or "")
    full_name = str(data.get("full_name") or "")
    category = str(data.get("category") or "")
    summary = str(data.get("summary") or data.get("title") or "")[:2000]
    kind = str(data.get("kind") or "")
    url = str(data.get("url") or "")
    toolbox = str(data.get("toolbox_path") or "")
    body = _body_text(data)
    now = time.time()
    payload = json.dumps(data, ensure_ascii=False, default=str)

    own = conn is None
    try:
        c = conn or _connect(db_path)
        init_catalog_db(db_path)
        with _lock:
            c.execute(
                """
                INSERT INTO catalog_entries(
                    entry_id, path, filename, kind, name, full_name, category,
                    attack_surface, phase_hint, tags, summary, url, toolbox_path,
                    payload_json, mtime, size_bytes, ingested_at
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(entry_id) DO UPDATE SET
                    path=excluded.path,
                    filename=excluded.filename,
                    kind=excluded.kind,
                    name=excluded.name,
                    full_name=excluded.full_name,
                    category=excluded.category,
                    attack_surface=excluded.attack_surface,
                    phase_hint=excluded.phase_hint,
                    tags=excluded.tags,
                    summary=excluded.summary,
                    url=excluded.url,
                    toolbox_path=excluded.toolbox_path,
                    payload_json=excluded.payload_json,
                    mtime=excluded.mtime,
                    size_bytes=excluded.size_bytes,
                    ingested_at=excluded.ingested_at
                """,
                (
                    entry_id, str(path.resolve()), path.name, kind, name,
                    full_name, category, surface, phase, tags, summary,
                    url, toolbox, payload, float(st.st_mtime), int(st.st_size),
                    now,
                ),
            )
            # FTS rebuild row
            c.execute("DELETE FROM catalog_fts WHERE entry_id = ?", (entry_id,))
            c.execute(
                """
                INSERT INTO catalog_fts(entry_id, name, full_name, category, tags, summary, body)
                VALUES (?,?,?,?,?,?,?)
                """,
                (entry_id, name, full_name, category, tags, summary, body[:8000]),
            )
            if own:
                c.commit()
        return {"ok": True, "entry_id": entry_id, "path": str(path)}
    except Exception as e:
        return {"ok": False, "error": str(e)[:200], "path": str(path)}


def ingest_catalog(
    catalog_dir: Optional[Path] = None,
    *,
    db_path: Optional[Path] = None,
    force: bool = False,
    progress_cb=None,
    max_files: int = 0,
) -> Dict[str, Any]:
    """Ingest all catalog JSON files (incremental by mtime unless force)."""
    catalog_dir = Path(catalog_dir or _DEFAULT_CATALOG)
    t0 = time.time()
    init = init_catalog_db(db_path)
    if not init.get("ok"):
        return init
    if not catalog_dir.is_dir():
        return {"ok": False, "error": f"catalog dir missing: {catalog_dir}"}

    conn = _connect(db_path)
    # existing mtimes for incremental
    existing: Dict[str, float] = {}
    if not force:
        try:
            for row in conn.execute("SELECT path, mtime FROM catalog_entries"):
                existing[str(row["path"])] = float(row["mtime"] or 0)
        except Exception:
            existing = {}

    files = sorted(
        p for p in catalog_dir.glob("*.json") if p.name not in _SKIP_NAMES
    )
    if max_files and max_files > 0:
        files = files[:max_files]

    inserted = updated = skipped = errors = 0
    for i, path in enumerate(files):
        try:
            mtime = path.stat().st_mtime
        except OSError:
            errors += 1
            continue
        key = str(path.resolve())
        if not force and existing.get(key) and abs(existing[key] - mtime) < 0.001:
            skipped += 1
            continue
        r = ingest_file(path, db_path=db_path, conn=conn)
        if r.get("ok"):
            if key in existing:
                updated += 1
            else:
                inserted += 1
        elif r.get("skipped"):
            skipped += 1
        else:
            errors += 1
        if progress_cb and i % 200 == 0:
            try:
                progress_cb(i, len(files))
            except Exception:
                pass
    with _lock:
        conn.commit()

    # refresh aggregate stats snapshot
    stats = count_stats(db_path=db_path, refresh=True)
    meta = {
        "ok": True,
        "catalog_dir": str(catalog_dir),
        "db": str(catalog_db_path(db_path)),
        "files_seen": len(files),
        "inserted": inserted,
        "updated": updated,
        "skipped": skipped,
        "errors": errors,
        "took_s": round(time.time() - t0, 3),
        "stats": stats,
    }
    try:
        with _lock:
            conn.execute(
                """
                INSERT INTO catalog_meta(key, value) VALUES('last_ingest', ?)
                ON CONFLICT(key) DO UPDATE SET value=excluded.value
                """,
                (json.dumps({
                    "at": time.time(),
                    "inserted": inserted,
                    "updated": updated,
                    "skipped": skipped,
                    "files_seen": len(files),
                }),),
            )
            conn.commit()
    except Exception:
        pass
    return meta


def sql_ready(db_path: Optional[Path] = None) -> bool:
    try:
        p = catalog_db_path(db_path)
        if not p.is_file() or p.stat().st_size < 1024:
            return False
        conn = _connect(db_path)
        n = conn.execute("SELECT COUNT(*) AS c FROM catalog_entries").fetchone()["c"]
        return int(n) > 0
    except Exception:
        return False


def count_stats(
    db_path: Optional[Path] = None,
    *,
    refresh: bool = False,
) -> Dict[str, Any]:
    """Fast aggregate counts (cached in catalog_stats unless refresh)."""
    try:
        init_catalog_db(db_path)
        conn = _connect(db_path)
        if not refresh:
            row = conn.execute(
                "SELECT value_json, updated_at FROM catalog_stats WHERE key='summary'"
            ).fetchone()
            if row and row["value_json"]:
                try:
                    data = json.loads(row["value_json"])
                    data["cached"] = True
                    data["updated_at"] = row["updated_at"]
                    return data
                except Exception:
                    pass
        total = conn.execute("SELECT COUNT(*) AS c FROM catalog_entries").fetchone()["c"]
        by_kind = {
            r["kind"] or "": r["c"]
            for r in conn.execute(
                "SELECT kind, COUNT(*) AS c FROM catalog_entries GROUP BY kind"
            )
        }
        by_surface = {
            r["attack_surface"] or "": r["c"]
            for r in conn.execute(
                "SELECT attack_surface, COUNT(*) AS c FROM catalog_entries "
                "GROUP BY attack_surface"
            )
        }
        by_phase = {
            r["phase_hint"] or "": r["c"]
            for r in conn.execute(
                "SELECT phase_hint, COUNT(*) AS c FROM catalog_entries "
                "GROUP BY phase_hint"
            )
        }
        summary = {
            "ok": True,
            "total": int(total),
            "by_kind": by_kind,
            "by_surface": by_surface,
            "by_phase": by_phase,
            "cached": False,
            "updated_at": time.time(),
            "source": "sql",
        }
        with _lock:
            conn.execute(
                """
                INSERT INTO catalog_stats(key, value_json, updated_at)
                VALUES('summary', ?, ?)
                ON CONFLICT(key) DO UPDATE SET
                    value_json=excluded.value_json,
                    updated_at=excluded.updated_at
                """,
                (json.dumps(summary, default=str), time.time()),
            )
            conn.commit()
        return summary
    except Exception as e:
        return {"ok": False, "error": str(e)[:160], "total": 0}


def search_sql(
    *,
    attack_surface: str = "",
    phase_hint: str = "",
    tag: str = "",
    text: str = "",
    kind: str = "",
    limit: int = 50,
    db_path: Optional[Path] = None,
    include_payload: bool = True,
) -> Dict[str, Any]:
    """SQL search with optional FTS. Returns {ok, source, took_s, results}."""
    t0 = time.time()
    if not sql_ready(db_path):
        return {
            "ok": False,
            "source": "sql",
            "error": "catalog SQL empty — run ingest_catalog",
            "results": [],
            "took_s": 0.0,
        }
    try:
        conn = _connect(db_path)
        limit = max(1, min(int(limit or 50), 500))
        params: List[Any] = []
        where: List[str] = []
        if attack_surface:
            where.append("e.attack_surface = ?")
            params.append(attack_surface.lower())
        if phase_hint:
            where.append("e.phase_hint = ?")
            params.append(phase_hint.lower())
        if kind:
            where.append("e.kind = ?")
            params.append(kind)
        if tag:
            where.append("e.tags LIKE ?")
            params.append(f"%{tag}%")

        cols = (
            "e.entry_id, e.path, e.filename, e.kind, e.name, e.full_name, "
            "e.category, e.attack_surface, e.phase_hint, e.tags, e.summary, "
            "e.url, e.toolbox_path"
        )
        if include_payload:
            cols += ", e.payload_json"

        if text and text.strip():
            # FTS5 MATCH
            q = " ".join(
                w for w in text.lower().split() if len(w.strip(".,:;")) >= 2
            )
            if not q:
                q = text.strip()
            sql = (
                f"SELECT {cols} FROM catalog_fts f "
                f"JOIN catalog_entries e ON e.entry_id = f.entry_id "
                f"WHERE catalog_fts MATCH ?"
            )
            params_fts: List[Any] = [q]
            if where:
                sql += " AND " + " AND ".join(where)
                params_fts.extend(params)
            sql += f" LIMIT {limit}"
            rows = conn.execute(sql, params_fts).fetchall()
        else:
            sql = f"SELECT {cols} FROM catalog_entries e"
            if where:
                sql += " WHERE " + " AND ".join(where)
            sql += f" LIMIT {limit}"
            rows = conn.execute(sql, params).fetchall()

        results: List[Dict[str, Any]] = []
        for r in rows:
            if include_payload and r["payload_json"]:
                try:
                    entry = json.loads(r["payload_json"])
                except Exception:
                    entry = {k: r[k] for k in r.keys() if k != "payload_json"}
            else:
                entry = {k: r[k] for k in r.keys() if k != "payload_json"}
            results.append(entry)
        return {
            "ok": True,
            "source": "sql",
            "count": len(results),
            "results": results,
            "took_s": round(time.time() - t0, 4),
        }
    except Exception as e:
        return {
            "ok": False,
            "source": "sql",
            "error": str(e)[:200],
            "results": [],
            "took_s": round(time.time() - t0, 4),
        }


def get_by_id(entry_id: str, *, db_path: Optional[Path] = None) -> Optional[Dict[str, Any]]:
    try:
        conn = _connect(db_path)
        row = conn.execute(
            "SELECT payload_json FROM catalog_entries WHERE entry_id = ?",
            (entry_id,),
        ).fetchone()
        if not row:
            return None
        return json.loads(row["payload_json"])
    except Exception:
        return None


def get_by_path(path: str, *, db_path: Optional[Path] = None) -> Optional[Dict[str, Any]]:
    try:
        conn = _connect(db_path)
        row = conn.execute(
            "SELECT payload_json FROM catalog_entries WHERE path = ? OR filename = ?",
            (str(path), Path(path).name),
        ).fetchone()
        if not row:
            return None
        return json.loads(row["payload_json"])
    except Exception:
        return None


def list_surfaces(db_path: Optional[Path] = None) -> List[Tuple[str, int]]:
    st = count_stats(db_path=db_path)
    by = st.get("by_surface") or {}
    return sorted(((k, int(v)) for k, v in by.items()), key=lambda x: -x[1])
