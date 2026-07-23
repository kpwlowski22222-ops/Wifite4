"""Long-term memory OS for KFIOSA (MemOS-inspired, local-first).

Concepts from https://github.com/MemTensor/MemOS — unified store/retrieve,
multi-cube isolation, L1 traces / L2 skills / L3 policies — reimplemented
for KFIOSA without requiring Neo4j/Qdrant/Electron.

Storage:
  * SQLite cubes + FTS5 hybrid search under ``data/memos/``
  * Optional remote MemOS HTTP if ``MEMOS_URL`` + ``MEMOS_API_KEY`` set

Never fabricates memories; never stores raw API keys.
"""
from __future__ import annotations

import json
import os
import re
import sqlite3
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

_REDACT = re.compile(
    r"(?i)(api[_-]?key|token|password|secret|bearer)\s*[:=]\s*\S+"
)

_lock = threading.RLock()
_local = threading.local()


def memos_root() -> Path:
    raw = (os.environ.get("KFIOSA_MEMOS_ROOT") or "").strip()
    if raw:
        return Path(raw).expanduser()
    return Path(__file__).resolve().parents[2] / "data" / "memos"


def memos_db_path() -> Path:
    raw = (os.environ.get("KFIOSA_MEMOS_DB") or "").strip()
    if raw:
        return Path(raw).expanduser()
    return memos_root() / "memos_ltm.db"


def _redact(text: str) -> str:
    out = str(text or "")
    for key in (
        "OLLAMA_CLOUD_TOKEN", "NVD_API_KEY", "HF_TOKEN", "GROQ_API_KEY",
        "MEMOS_API_KEY",
    ):
        val = os.environ.get(key) or ""
        if len(val) >= 8 and val in out:
            out = out.replace(val, "***")
    return _REDACT.sub(r"\1=***", out)


def _conn() -> sqlite3.Connection:
    path = memos_db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    key = str(path)
    cache = getattr(_local, "c", None)
    if cache is None or cache.get("path") != key:
        c = sqlite3.connect(str(path), check_same_thread=False, timeout=30)
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA journal_mode=WAL")
        _local.c = {"path": key, "conn": c}
        cache = _local.c
    return cache["conn"]


def init() -> Dict[str, Any]:
    try:
        c = _conn()
        with _lock:
            c.executescript(
                """
                CREATE TABLE IF NOT EXISTS cubes (
                    cube_id TEXT PRIMARY KEY,
                    name TEXT,
                    domain TEXT,
                    owner TEXT DEFAULT 'kfiosa',
                    created_at REAL,
                    meta_json TEXT
                );
                CREATE TABLE IF NOT EXISTS memories (
                    mem_id TEXT PRIMARY KEY,
                    cube_id TEXT,
                    layer TEXT,          -- L1_trace | L2_skill | L3_policy
                    kind TEXT,
                    content TEXT,
                    tags TEXT,
                    score REAL DEFAULT 0,
                    domain TEXT,
                    target_key TEXT,
                    created_at REAL,
                    updated_at REAL,
                    meta_json TEXT
                );
                CREATE INDEX IF NOT EXISTS ix_mem_cube ON memories(cube_id);
                CREATE INDEX IF NOT EXISTS ix_mem_layer ON memories(layer);
                CREATE INDEX IF NOT EXISTS ix_mem_domain ON memories(domain);
                CREATE VIRTUAL TABLE IF NOT EXISTS mem_fts USING fts5(
                    mem_id UNINDEXED,
                    content,
                    tags,
                    kind,
                    tokenize='porter'
                );
                """
            )
            c.commit()
        return {"ok": True, "path": str(memos_db_path())}
    except Exception as e:
        return {"ok": False, "error": str(e)[:160]}


def ensure_cube(
    cube_id: str,
    *,
    name: str = "",
    domain: str = "",
    meta: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    init()
    c = _conn()
    now = time.time()
    with _lock:
        c.execute(
            """
            INSERT INTO cubes(cube_id, name, domain, created_at, meta_json)
            VALUES(?,?,?,?,?)
            ON CONFLICT(cube_id) DO UPDATE SET
                name=COALESCE(excluded.name, cubes.name),
                domain=COALESCE(excluded.domain, cubes.domain)
            """,
            (
                cube_id,
                name or cube_id,
                domain,
                now,
                json.dumps(meta or {}, default=str),
            ),
        )
        c.commit()
    return {"ok": True, "cube_id": cube_id}


def add_memory(
    content: str,
    *,
    cube_id: str = "default",
    layer: str = "L1_trace",
    kind: str = "note",
    domain: str = "",
    target_key: str = "",
    tags: Optional[List[str]] = None,
    meta: Optional[Dict[str, Any]] = None,
    score: float = 0.0,
) -> Dict[str, Any]:
    """Add a durable memory (L1 trace / L2 skill / L3 policy)."""
    init()
    body = _redact((content or "").strip())
    if not body:
        return {"ok": False, "error": "empty content"}
    ensure_cube(cube_id, domain=domain)
    mid = "m-" + uuid.uuid4().hex[:12]
    now = time.time()
    tags_s = " ".join(tags or [])
    layer = layer if layer in ("L1_trace", "L2_skill", "L3_policy") else "L1_trace"
    c = _conn()
    with _lock:
        c.execute(
            """
            INSERT INTO memories(
                mem_id, cube_id, layer, kind, content, tags, score,
                domain, target_key, created_at, updated_at, meta_json
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                mid, cube_id, layer, kind, body, tags_s, float(score),
                domain, target_key, now, now,
                json.dumps(meta or {}, default=str),
            ),
        )
        c.execute(
            "INSERT INTO mem_fts(mem_id, content, tags, kind) VALUES (?,?,?,?)",
            (mid, body[:8000], tags_s, kind),
        )
        c.commit()
    # Mirror into short-term engagement memory
    try:
        from core.memory.store import ingest
        ingest(
            f"memos_{layer.lower()}",
            body[:1500],
            domain=domain,
            target_key=target_key,
            tags=(tags or []) + [cube_id, layer],
        )
    except Exception:
        pass
    # Optional remote MemOS
    _maybe_push_remote(cube_id, body, domain=domain)
    return {"ok": True, "mem_id": mid, "cube_id": cube_id, "layer": layer}


def search_memory(
    query: str,
    *,
    cube_id: str = "",
    domain: str = "",
    layer: str = "",
    limit: int = 12,
) -> Dict[str, Any]:
    """Hybrid FTS search across long-term memories."""
    init()
    q = (query or "").strip()
    limit = max(1, min(int(limit or 12), 50))
    c = _conn()
    rows: List[Dict[str, Any]] = []
    try:
        if q:
            sql = (
                "SELECT m.* FROM mem_fts f "
                "JOIN memories m ON m.mem_id = f.mem_id "
                "WHERE mem_fts MATCH ?"
            )
            params: List[Any] = [q]
            if cube_id:
                sql += " AND m.cube_id = ?"
                params.append(cube_id)
            if domain:
                sql += " AND m.domain = ?"
                params.append(domain)
            if layer:
                sql += " AND m.layer = ?"
                params.append(layer)
            sql += f" ORDER BY m.score DESC, m.updated_at DESC LIMIT {limit}"
            cur = c.execute(sql, params)
        else:
            sql = "SELECT * FROM memories WHERE 1=1"
            params = []
            if cube_id:
                sql += " AND cube_id = ?"
                params.append(cube_id)
            if domain:
                sql += " AND domain = ?"
                params.append(domain)
            if layer:
                sql += " AND layer = ?"
                params.append(layer)
            sql += f" ORDER BY updated_at DESC LIMIT {limit}"
            cur = c.execute(sql, params)
        for r in cur.fetchall():
            rows.append({k: r[k] for k in r.keys()})
    except Exception as e:
        return {"ok": False, "error": str(e)[:160], "results": []}
    return {"ok": True, "count": len(rows), "results": rows}


def crystallize_skill(
    content: str,
    *,
    cube_id: str,
    domain: str = "",
    tags: Optional[List[str]] = None,
    meta: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Promote a successful plan pattern to L2 skill memory."""
    return add_memory(
        content,
        cube_id=cube_id,
        layer="L2_skill",
        kind="skill",
        domain=domain,
        tags=(tags or []) + ["skill", "learn"],
        meta=meta,
        score=10.0,
    )


def list_cubes() -> List[Dict[str, Any]]:
    init()
    c = _conn()
    return [
        {k: r[k] for k in r.keys()}
        for r in c.execute("SELECT * FROM cubes ORDER BY created_at DESC")
    ]


def stats() -> Dict[str, Any]:
    init()
    c = _conn()
    total = c.execute("SELECT COUNT(*) AS n FROM memories").fetchone()["n"]
    by_layer = {
        r["layer"]: r["n"]
        for r in c.execute(
            "SELECT layer, COUNT(*) AS n FROM memories GROUP BY layer"
        )
    }
    return {
        "ok": True,
        "total": int(total),
        "by_layer": by_layer,
        "cubes": len(list_cubes()),
        "db": str(memos_db_path()),
        "memos_project": "https://github.com/MemTensor/MemOS",
        "mode": "local_kfiosa",
    }


def _maybe_push_remote(cube_id: str, content: str, *, domain: str = "") -> None:
    base = (os.environ.get("MEMOS_URL") or "").strip().rstrip("/")
    key = (os.environ.get("MEMOS_API_KEY") or "").strip()
    if not base or not key:
        return
    try:
        import urllib.request
        payload = json.dumps({
            "user_id": "kfiosa",
            "conversation_id": cube_id,
            "messages": [{"role": "user", "content": content[:2000]}],
            "async_mode": "sync",
        }).encode("utf-8")
        req = urllib.request.Request(
            f"{base}/add/message" if "/api/" not in base else f"{base}/add/message",
            data=payload,
            headers={
                "Authorization": f"Token {key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        urllib.request.urlopen(req, timeout=8)
    except Exception:
        pass
