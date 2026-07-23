"""Tests for core.optimizations — Phase 4 T21 (7 perf passes).

Covers:
  1. Catalog search index: build + search by attack_surface / phase /
     tag / text; stats; reset
  2. Chain planner memoization: cache hit/miss; TTL expiry; clear
  3. Ollama reachability cache: positive + negative; clear
  4. SQLite WAL checkpoint tuning: sets PRAGMA
  5. Static asset hashing: content-hash in URL
  6. Catalog index precompute: idempotent
  7. WSGI keep-alive server: builds and serves
"""
from __future__ import annotations

import importlib
import os
import socket
import tempfile
import time
from pathlib import Path

import pytest


def _import_mod():
    return importlib.import_module("core.optimizations")


def _import_index():
    return importlib.import_module("core.catalog.index")


opt = _import_mod()
idx = _import_index()


# ---------------------------------------------------------------------------
# 1. Catalog search index
# ---------------------------------------------------------------------------

class TestCatalogIndex:
    def test_build_index_returns_envelope(self):
        out = idx.build_index()
        assert "ok" in out
        assert "count" in out

    def test_search_by_attack_surface(self):
        idx.build_index()
        # Most catalog entries have wifi or http attack surface
        results = idx.search(attack_surface="wifi", limit=5)
        assert isinstance(results, list)

    def test_search_by_tag(self):
        idx.build_index()
        # `kali` is a common tag in the catalog
        results = idx.search(tag="kali", limit=5)
        assert isinstance(results, list)

    def test_search_by_text(self):
        idx.build_index()
        results = idx.search(text="scanner", limit=5)
        assert isinstance(results, list)

    def test_search_combined(self):
        idx.build_index()
        results = idx.search(
            attack_surface="wifi", phase_hint="attack", limit=5)
        assert isinstance(results, list)

    def test_index_stats(self):
        idx.build_index()
        s = idx.index_stats()
        assert s["ok"] is True
        assert s["count"] > 0

    def test_reset_clears_index(self):
        idx.build_index()
        before = idx.index_stats()["count"]
        idx.reset()
        after_empty = idx.index_stats()["count"]
        assert after_empty == 0
        # Re-build
        idx.build_index()
        assert idx.index_stats()["count"] == before

    def test_no_fabrication_in_search(self):
        idx.build_index()
        results = idx.search(limit=10)
        # Search results must come from the actual catalog — never fabricate
        for entry in results:
            assert "id" in entry or "name" in entry


# ---------------------------------------------------------------------------
# 2. Chain planner memoization
# ---------------------------------------------------------------------------

class TestPlanMemoization:
    def test_cache_miss_then_hit(self):
        opt.clear_plan_cache()
        calls = []
        def planner(target, attack_surface):
            calls.append((target, attack_surface))
            return {"ok": True, "steps": ["s1"], "target": target}
        r1 = opt.memoized_plan("t1", "wifi", planner_fn=planner)
        r2 = opt.memoized_plan("t1", "wifi", planner_fn=planner)
        assert r1["cached"] is False
        assert r2["cached"] is True
        assert len(calls) == 1, f"planner called {len(calls)} times"

    def test_different_keys_different_cache(self):
        opt.clear_plan_cache()
        calls = []
        def planner(target, attack_surface):
            calls.append((target, attack_surface))
            return {"ok": True}
        opt.memoized_plan("t1", "wifi", planner_fn=planner)
        opt.memoized_plan("t2", "wifi", planner_fn=planner)
        opt.memoized_plan("t1", "ble", planner_fn=planner)
        assert len(calls) == 3

    def test_ttl_expiry(self):
        opt.clear_plan_cache()
        calls = []
        def planner(target, attack_surface):
            calls.append(1)
            return {"ok": True}
        r1 = opt.memoized_plan("ttl_test", "wifi", planner_fn=planner,
                               ttl_s=0.1)
        r2 = opt.memoized_plan("ttl_test", "wifi", planner_fn=planner,
                               ttl_s=0.1)
        assert r1["cached"] is False
        assert r2["cached"] is True
        time.sleep(0.15)
        r3 = opt.memoized_plan("ttl_test", "wifi", planner_fn=planner,
                               ttl_s=0.1)
        assert r3["cached"] is False

    def test_clear_cache(self):
        opt.memoized_plan("t1", "wifi", planner_fn=lambda **k: {"ok": True})
        out = opt.clear_plan_cache()
        assert out["ok"] is True
        assert out["cleared"] >= 1

    def test_plan_cache_stats(self):
        opt.clear_plan_cache()
        s = opt.plan_cache_stats()
        assert s["size"] == 0
        opt.memoized_plan("t1", "wifi", planner_fn=lambda **k: {"ok": True})
        s = opt.plan_cache_stats()
        assert s["size"] >= 1

    def test_invalid_input_returns_error(self):
        out = opt.memoized_plan(None, "wifi")
        assert out["ok"] is False
        out = opt.memoized_plan("t1", None)
        assert out["ok"] is False

    def test_no_planner_fn_returns_stub(self):
        opt.clear_plan_cache()
        r = opt.memoized_plan("t1", "wifi")
        assert r["ok"] is True
        assert "model" in r

    def test_planner_exception_returns_error(self):
        opt.clear_plan_cache()
        def bad_planner(**k):
            raise ValueError("boom")
        r = opt.memoized_plan("t1", "wifi", planner_fn=bad_planner)
        assert r["ok"] is False
        assert "boom" in r["error"]


# ---------------------------------------------------------------------------
# 3. Ollama reachability cache
# ---------------------------------------------------------------------------

class TestOllamaCache:
    def test_cache_miss_then_hit(self):
        opt.clear_ollama_cache()
        # Deterministic unreachable probe: mock socket to refuse.
        real_create = __import__("socket").create_connection
        def fake_create(addr, timeout=None):
            raise ConnectionRefusedError("mock unreachable")
        __import__("socket").create_connection = fake_create
        try:
            r1 = opt.cached_ollama_reachable("http://127.0.0.1:1", timeout_s=0.1)
            r2 = opt.cached_ollama_reachable("http://127.0.0.1:1", timeout_s=0.1)
        finally:
            __import__("socket").create_connection = real_create
        # Negative result is cached for half the TTL
        assert r1["ok"] is False
        assert r2["cached"] is True

    def test_clear_ollama_cache(self):
        opt.cached_ollama_reachable("http://127.0.0.1:1", timeout_s=0.1)
        out = opt.clear_ollama_cache()
        assert out["ok"] is True
        assert out["cleared"] >= 1

    def test_invalid_url_returns_error(self):
        r = opt.cached_ollama_reachable("")
        assert r["ok"] is False

    def test_no_token_leaked(self):
        out = opt.cached_ollama_reachable("http://127.0.0.1:1",
                                          timeout_s=0.1)
        for forbidden in ("f40bec4b664a40a9a", "ecf51ee2-938d",
                          "CE38F76832CFA1F6", "token", "api_key"):
            assert forbidden not in str(out), (
                f"Ollama cache leaked credential field: {forbidden!r}"
            )


# ---------------------------------------------------------------------------
# 4. SQLite WAL checkpoint tuning
# ---------------------------------------------------------------------------

class TestWALCheckpoint:
    def test_tune_wal_checkpoint(self, tmp_path):
        import sqlite3
        db = tmp_path / "test.db"
        with sqlite3.connect(str(db)) as cx:
            cx.execute("PRAGMA journal_mode = WAL")
        out = opt.tune_wal_checkpoint(str(db), interval_frames=2000)
        assert out["ok"] is True
        assert out["frames"] == 2000

    def test_missing_db_returns_error(self):
        out = opt.tune_wal_checkpoint("/nonexistent/path.db")
        assert out["ok"] is False

    def test_empty_path_returns_error(self):
        out = opt.tune_wal_checkpoint("")
        assert out["ok"] is False

    def test_default_frames_is_1000(self):
        assert opt.DEFAULT_WAL_CHECKPOINT_INTERVAL_FRAMES == 1000


# ---------------------------------------------------------------------------
# 5. Static asset hashing
# ---------------------------------------------------------------------------

class TestAssetHashing:
    def test_basic_hashing(self, tmp_path):
        f = tmp_path / "style.css"
        f.write_text("body { color: red; }")
        out = opt.asset_hashed_url("/static", str(f))
        assert out["ok"] is True
        assert "/static/style." in out["url"]
        assert out["url"].endswith(".css")
        assert len(out["hash"]) == 12

    def test_different_content_different_hash(self, tmp_path):
        f1 = tmp_path / "a.js"
        f1.write_text("var a = 1;")
        f2 = tmp_path / "b.js"
        f2.write_text("var b = 2;")
        out1 = opt.asset_hashed_url("/x", str(f1))
        out2 = opt.asset_hashed_url("/x", str(f2))
        assert out1["hash"] != out2["hash"]

    def test_same_content_same_hash(self, tmp_path):
        f1 = tmp_path / "a.js"
        f1.write_text("var a = 1;")
        f2 = tmp_path / "b.js"
        f2.write_text("var a = 1;")
        out1 = opt.asset_hashed_url("/x", str(f1))
        out2 = opt.asset_hashed_url("/x", str(f2))
        assert out1["hash"] == out2["hash"]

    def test_missing_file_returns_error(self):
        out = opt.asset_hashed_url("/x", "/nonexistent.css")
        assert out["ok"] is False

    def test_invalid_hash_length(self, tmp_path):
        f = tmp_path / "a.css"
        f.write_text("x")
        out = opt.asset_hashed_url("/x", str(f), hash_length=2)
        assert out["ok"] is False


# ---------------------------------------------------------------------------
# 6. Catalog index precompute (idempotent)
# ---------------------------------------------------------------------------

class TestCatalogPrecompute:
    def test_idempotent(self):
        r1 = opt.precompute_catalog_index()
        r2 = opt.precompute_catalog_index()
        assert r1["ok"] is True
        assert r2["ok"] is True
        # Second call should be cached
        assert r2.get("cached") is True

    def test_force_rebuild(self):
        r1 = opt.precompute_catalog_index()
        # Force a rebuild
        from core.catalog import index as _idx
        r2 = _idx.build_index(force=True)
        assert r1["ok"] is True
        assert r2["ok"] is True
        assert r2.get("cached") is False


# ---------------------------------------------------------------------------
# 7. WSGI keep-alive server
# ---------------------------------------------------------------------------

class TestWSGIServer:
    def test_builds_server(self):
        def app(environ, start_response):
            start_response("200 OK", [("Content-Type", "text/plain")])
            return [b"hello"]
        out = opt.make_keepalive_server(app, host="127.0.0.1", port=0)
        assert out["ok"] is True
        assert "server" in out
        # Daemon threads
        assert out["server"].daemon_threads is True

    def test_non_callable_app_returns_error(self):
        out = opt.make_keepalive_server("not callable")
        assert out["ok"] is False

    def test_serves_request(self):
        """Smoke-test: start the server, hit it, verify response."""
        from io import BytesIO
        def app(environ, start_response):
            start_response("200 OK", [("Content-Type", "text/plain")])
            return [b"hi from kfiosa"]
        out = opt.make_keepalive_server(app, host="127.0.0.1", port=0)
        assert out["ok"] is True
        srv = out["server"]
        port = out["port"]
        # Start the server in a thread
        import threading
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=2) as s:
                s.sendall(b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
                # Read all available bytes
                data = b""
                while True:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    data += chunk
            assert b"hi from kfiosa" in data, f"missing body in: {data!r}"
        finally:
            srv.shutdown()
            srv.server_close()


# ---------------------------------------------------------------------------
# Top-level orchestrator
# ---------------------------------------------------------------------------

class TestRunAll:
    def test_run_all_optimizations(self, tmp_path):
        # Create a dummy DB
        import sqlite3
        db = tmp_path / "test.db"
        with sqlite3.connect(str(db)) as cx:
            cx.execute("PRAGMA journal_mode = WAL")
        out = opt.run_all_optimizations(db_path=str(db))
        assert out["ok"] is True
        assert "catalog_index" in out["passes"]
        assert "plan_cache" in out["passes"]
        assert "ollama_cache" in out["passes"]
        assert "wal_checkpoint" in out["passes"]
        assert "asset_hash" in out["passes"]
        assert "keepalive" in out["passes"]


# ---------------------------------------------------------------------------
# Module surface
# ---------------------------------------------------------------------------

class TestModuleSurface:
    def test_all_exports(self):
        for name in ("precompute_catalog_index", "precompute_at_import",
                     "memoized_plan", "clear_plan_cache",
                     "plan_cache_stats", "cached_ollama_reachable",
                     "clear_ollama_cache", "tune_wal_checkpoint",
                     "asset_hashed_url", "make_keepalive_server",
                     "run_all_optimizations"):
            assert hasattr(opt, name), f"missing export: {name}"
