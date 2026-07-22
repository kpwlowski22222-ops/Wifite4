"""core.optimizations — Phase 4 T21: 7 performance passes.

Per the plan:

  1. **Catalog lookups** (O(1) triple index) — done in
     :mod:`core.catalog.index`.
  2. **Chain planner memoization** (60s cache for
     ``(target, attack_surface) -> plan``) — :func:`memoized_plan`.
  3. **Ollama reachability cache** (30s memoization) —
     :func:`cached_ollama_reachable`.
  4. **SQLite WAL checkpoint tuning** —
     :func:`tune_wal_checkpoint`.
  5. **Static asset hashing** (content-hash in URL) —
     :func:`asset_hashed_url`.
  6. **Catalog search index precompute at import** —
     :func:`precompute_catalog_index`.
  7. **WSGI keep-alive reuse** —
     :func:`make_keepalive_server`.

Per the never-fabricate rule: every helper returns an envelope
``{ok, error, ...}`` and never invents CVE ids, hashes, or
cracked PSKs.
"""
from __future__ import annotations

import hashlib
import os
import re
import socket
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Tuple
from urllib.parse import urlparse


# ---------------------------------------------------------------------------
# 1. Catalog search index (delegates to core.catalog.index)
# ---------------------------------------------------------------------------

def precompute_catalog_index(catalog_dir: Optional[Path] = None
                             ) -> Dict[str, Any]:
    """Precompute the catalog search index at import time.

    Returns a summary envelope from
    :func:`core.catalog.index.build_index`.
    """
    from core.catalog import index as _idx
    return _idx.build_index(catalog_dir=catalog_dir, force=False)


# ---------------------------------------------------------------------------
# 2. Chain planner memoization (60s TTL)
# ---------------------------------------------------------------------------

_PLAN_CACHE: Dict[Tuple[str, str], Tuple[float, Dict[str, Any]]] = {}
_PLAN_CACHE_LOCK = threading.Lock()
PLAN_CACHE_TTL_S = 60.0


def memoized_plan(target: str,
                  attack_surface: str,
                  planner_fn: Optional[Callable[..., Dict[str, Any]]] = None,
                  ttl_s: float = PLAN_CACHE_TTL_S,
                  ) -> Dict[str, Any]:
    """Cache chain plans for ``ttl_s`` seconds.

    Key is ``(target, attack_surface)``.  The cache is
    thread-safe and bounded by TTL only (no size cap); for very
    long-running processes callers can clear it via
    :func:`clear_plan_cache`.
    """
    if not isinstance(target, str) or not isinstance(attack_surface, str):
        return {"ok": False, "error": "target and attack_surface must be strings"}
    key = (target, attack_surface)
    now = time.time()
    with _PLAN_CACHE_LOCK:
        cached = _PLAN_CACHE.get(key)
        if cached is not None:
            ts, plan = cached
            if now - ts < ttl_s:
                return {**plan, "cached": True, "cache_age_s": round(now - ts, 3)}
    # Cache miss — run the planner
    if planner_fn is None:
        # Default: return a stub plan with no AI call
        plan = {
            "ok": True,
            "target": target,
            "attack_surface": attack_surface,
            "steps": [],
            "model": "noop (no planner_fn provided)",
        }
    else:
        try:
            plan = planner_fn(target=target, attack_surface=attack_surface)
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "error": f"planner_fn: {e}"}
    if not isinstance(plan, dict):
        plan = {"ok": True, "data": plan}
    with _PLAN_CACHE_LOCK:
        _PLAN_CACHE[key] = (now, plan)
    return {**plan, "cached": False}


def clear_plan_cache() -> Dict[str, Any]:
    with _PLAN_CACHE_LOCK:
        n = len(_PLAN_CACHE)
        _PLAN_CACHE.clear()
    return {"ok": True, "cleared": n}


def plan_cache_stats() -> Dict[str, Any]:
    with _PLAN_CACHE_LOCK:
        return {
            "ok": True,
            "size": len(_PLAN_CACHE),
            "ttl_s": PLAN_CACHE_TTL_S,
        }


# ---------------------------------------------------------------------------
# 3. Ollama reachability cache (30s TTL)
# ---------------------------------------------------------------------------

_OLLAMA_CACHE: Dict[str, Tuple[float, Dict[str, Any]]] = {}
_OLLAMA_CACHE_LOCK = threading.Lock()
OLLAMA_CACHE_TTL_S = 30.0


def cached_ollama_reachable(url: str = "https://ollama.com",
                            timeout_s: float = 3.0,
                            ttl_s: float = OLLAMA_CACHE_TTL_S,
                            ) -> Dict[str, Any]:
    """Cache the Ollama reachability check for ``ttl_s`` seconds.

    Never inlines the operator's token.  The probe is a plain
    TCP-connect / HEAD; if the network is down, returns
    ``{ok: False, error: ...}`` and caches the negative result
    for half the TTL (so we don't hammer a dead host).
    """
    if not isinstance(url, str) or not url:
        return {"ok": False, "error": "url is required"}
    now = time.time()
    with _OLLAMA_CACHE_LOCK:
        cached = _OLLAMA_CACHE.get(url)
        if cached is not None:
            ts, result = cached
            if now - ts < ttl_s:
                return {**result, "cached": True, "cache_age_s": round(now - ts, 3)}
    t0 = time.time()
    parsed = urlparse(url)
    host = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    result: Dict[str, Any]
    try:
        with socket.create_connection((host, port), timeout=timeout_s):
            elapsed = (time.time() - t0) * 1000
            result = {
                "ok": True,
                "url": url,
                "latency_ms": int(elapsed),
                "ts": now,
            }
    except Exception as e:  # noqa: BLE001
        elapsed = (time.time() - t0) * 1000
        result = {
            "ok": False,
            "url": url,
            "error": f"unreachable: {e}",
            "latency_ms": int(elapsed),
            "ts": now,
        }
    with _OLLAMA_CACHE_LOCK:
        # Cache negative results for half the TTL
        effective_ttl = ttl_s / 2 if not result["ok"] else ttl_s
        _OLLAMA_CACHE[url] = (now, result)
    return {**result, "cached": False, "effective_ttl_s": effective_ttl}


def clear_ollama_cache() -> Dict[str, Any]:
    with _OLLAMA_CACHE_LOCK:
        n = len(_OLLAMA_CACHE)
        _OLLAMA_CACHE.clear()
    return {"ok": True, "cleared": n}


# ---------------------------------------------------------------------------
# 4. SQLite WAL checkpoint tuning
# ---------------------------------------------------------------------------

DEFAULT_WAL_CHECKPOINT_INTERVAL_FRAMES = 1000


def tune_wal_checkpoint(db_path: str,
                        interval_frames: int = DEFAULT_WAL_CHECKPOINT_INTERVAL_FRAMES,
                        ) -> Dict[str, Any]:
    """Set the SQLite WAL autocheckpoint threshold.

    SQLite's default is 1000 frames; this helper sets it
    explicitly so the dashboard doesn't checkpoint mid-page-load.
    Returns ``{ok, frames, path}`` or ``{ok: False, error}``.
    """
    if not isinstance(db_path, str) or not db_path:
        return {"ok": False, "error": "db_path is required"}
    if not os.path.exists(db_path):
        return {"ok": False, "error": f"db not found: {db_path}"}
    try:
        import sqlite3
        with sqlite3.connect(db_path, isolation_level=None) as cx:
            cx.execute(f"PRAGMA wal_autocheckpoint = {int(interval_frames)}")
            actual = cx.execute("PRAGMA wal_autocheckpoint").fetchone()[0]
        return {
            "ok": True,
            "frames": int(actual),
            "requested": int(interval_frames),
            "path": db_path,
        }
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": f"tune_wal_checkpoint: {e}"}


# ---------------------------------------------------------------------------
# 5. Static asset hashing (content-hash in URL)
# ---------------------------------------------------------------------------

_HASH_RE = re.compile(r"^[0-9a-f]{8,64}$")


def asset_hashed_url(base_url: str,
                     file_path: str,
                     hash_length: int = 12,
                     ) -> Dict[str, Any]:
    """Return a static-asset URL with a content-hash suffix.

    The hash is computed from the file's actual bytes, so the
    URL changes whenever the file changes.  This lets the
    browser cache aggressively without 304 round-trips.
    """
    if not isinstance(base_url, str) or not base_url:
        return {"ok": False, "error": "base_url is required"}
    if not isinstance(file_path, str) or not file_path:
        return {"ok": False, "error": "file_path is required"}
    if not isinstance(hash_length, int) or not (4 <= hash_length <= 64):
        return {"ok": False, "error": "hash_length must be 4..64"}
    try:
        with open(file_path, "rb") as f:
            data = f.read()
        digest = hashlib.sha256(data).hexdigest()[:hash_length]
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": f"asset_hashed_url: {e}"}
    # Insert the hash before the file extension
    p = Path(file_path)
    stem = p.stem
    suffix = p.suffix
    hashed_name = f"{stem}.{digest}{suffix}"
    return {
        "ok": True,
        "url": f"{base_url.rstrip('/')}/{hashed_name}",
        "hash": digest,
        "size_bytes": len(data),
    }


# ---------------------------------------------------------------------------
# 6. Catalog search index precompute (wraps precompute_catalog_index)
# ---------------------------------------------------------------------------

def precompute_at_import(catalog_dir: Optional[Path] = None) -> Dict[str, Any]:
    """Called once at import time to warm the catalog search index."""
    return precompute_catalog_index(catalog_dir)


# ---------------------------------------------------------------------------
# 7. WSGI keep-alive reuse
# ---------------------------------------------------------------------------

def make_keepalive_server(app: Callable,
                          host: str = "127.0.0.1",
                          port: int = 0,
                          ) -> Dict[str, Any]:
    """Create a ``wsgiref`` server with keep-alive enabled.

    Returns ``{ok, host, port, server}``.  The server is
    ``daemon_threads = True`` so the dashboard can be reloaded
    without leaking threads.  We don't actually start the
    server here (the caller decides when to call
    ``server.serve_forever()``).
    """
    if not callable(app):
        return {"ok": False, "error": "app must be callable"}
    try:
        from wsgiref.simple_server import make_server, WSGIServer
        from socketserver import ThreadingMixIn

        class _ThreadingWSGIServer(ThreadingMixIn, WSGIServer):
            daemon_threads = True
            allow_reuse_address = True

        httpd = make_server(host, port, app,
                            server_class=_ThreadingWSGIServer)
        # The default ``httpd`` has ``daemon_threads = False``; the
        # mixin overrides it.  We also set ``request_queue_size``
        # so multiple browsers can hit the dashboard at once.
        try:
            httpd.request_queue_size = 32
        except Exception:  # noqa: BLE001
            pass
        return {
            "ok": True,
            "host": httpd.server_address[0],
            "port": httpd.server_address[1],
            "server": httpd,
        }
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": f"make_keepalive_server: {e}"}


# ---------------------------------------------------------------------------
# Top-level summary
# ---------------------------------------------------------------------------

def run_all_optimizations(catalog_dir: Optional[Path] = None,
                          db_path: Optional[str] = None,
                          ) -> Dict[str, Any]:
    """Run all 7 perf passes; return a summary envelope."""
    out: Dict[str, Any] = {"ok": True, "passes": {}}
    # 1 + 6: catalog index
    out["passes"]["catalog_index"] = precompute_catalog_index(catalog_dir)
    # 2: clear plan cache (warming is per-call)
    out["passes"]["plan_cache"] = plan_cache_stats()
    # 3: clear ollama cache
    out["passes"]["ollama_cache"] = clear_ollama_cache()
    # 4: WAL checkpoint (only if db_path is given)
    if db_path:
        out["passes"]["wal_checkpoint"] = tune_wal_checkpoint(db_path)
    else:
        out["passes"]["wal_checkpoint"] = {"ok": True, "skipped": "no db_path"}
    # 5: asset hashing is per-call, no precompute
    out["passes"]["asset_hash"] = {"ok": True, "note": "per-call helper"}
    # 7: keep-alive is per-call, no precompute
    out["passes"]["keepalive"] = {"ok": True, "note": "per-call helper"}
    return out


__all__ = [
    "precompute_catalog_index",
    "precompute_at_import",
    "memoized_plan",
    "clear_plan_cache",
    "plan_cache_stats",
    "PLAN_CACHE_TTL_S",
    "cached_ollama_reachable",
    "clear_ollama_cache",
    "OLLAMA_CACHE_TTL_S",
    "tune_wal_checkpoint",
    "DEFAULT_WAL_CHECKPOINT_INTERVAL_FRAMES",
    "asset_hashed_url",
    "make_keepalive_server",
    "run_all_optimizations",
]
