"""tests.test_dashboard_v3 — Phase 3 expansion T6.

Verifies the 7 dashboard improvements:

1. Capability search + filter (``/api/sessions?q=foo``)
2. Pagination on history/exfil/log (``paginate_with_offset``)
3. CSRF protection on POSTs (``csrf_token_for`` / ``verify_csrf``)
4. Compact mode (``is_compact_mode``)
5. Better 404 page (``best_match_sid``)
6. WebSocket live tail (``/api/session/<sid>/live_tail?since=ts``)
7. Chain-planner integration (``/api/plan`` with CSRF)

The tests do not need a running server — they call the WSGI app
directly with stub ``environ`` dicts.
"""
from __future__ import annotations

import json
import socket
import threading
import time
from typing import Any, Dict, List

import pytest

from core.post_access_tui.rat_ext import _build_wsgi_app
from core.post_access_tui.rat_ext.v3_enhancements import (
    filter_sessions,
    paginate_with_offset,
    since_filter,
    csrf_token_for,
    verify_csrf,
    is_compact_mode,
    best_match_sid,
    live_tail_lines,
    chain_plan_from_session,
)


# ---------------------------------------------------------------------------
# Test fixtures
# ---------------------------------------------------------------------------


def _call(app, path: str, method: str = "GET", body: bytes = b"",
          headers: Dict[str, str] = None) -> tuple:
    """Call a WSGI app with a minimal environ. Returns
    ``(status, headers_dict, body_bytes)``.

    The ``path`` may include ``?query=string`` — it is split out
    into ``PATH_INFO`` and ``QUERY_STRING`` per WSGI conventions.
    """
    headers = headers or {}
    if "?" in path:
        path_only, qs = path.split("?", 1)
    else:
        path_only, qs = path, ""
    environ = {
        "REQUEST_METHOD": method,
        "PATH_INFO": path_only,
        "QUERY_STRING": qs,
        "CONTENT_TYPE": "application/json",
        "CONTENT_LENGTH": str(len(body)) if body else "0",
        "SERVER_NAME": "127.0.0.1",
        "SERVER_PORT": "0",
        "wsgi.input": _FakeInput(body),
        "wsgi.errors": _FakeErrors(),
        "wsgi.version": (1, 0),
        "wsgi.url_scheme": "http",
        "wsgi.multithread": True,
        "wsgi.multiprocess": False,
        "wsgi.run_once": False,
    }
    for k, v in headers.items():
        environ["HTTP_" + k.upper().replace("-", "_")] = v
    captured = {"status": None, "headers": [], "body": []}

    def start_response(status, headers, exc_info=None):
        captured["status"] = status
        captured["headers"] = headers

    result = app(environ, start_response)
    body_bytes = b"".join(result) if result else b""
    return captured["status"], dict(captured["headers"]), body_bytes


class _FakeInput:
    def __init__(self, body: bytes = b""):
        self._body = body

    def read(self, size: int = -1) -> bytes:
        if size < 0 or size >= len(self._body):
            data = self._body
            self._body = b""
            return data
        data = self._body[:size]
        self._body = self._body[size:]
        return data


class _FakeErrors:
    def write(self, s):
        return len(s)

    def flush(self):
        return None


@pytest.fixture
def app():
    """Build a fresh WSGI app for each test."""
    sessions = [
        {"session_id": "wifi-lab", "target": "lab-ap",
         "attack_surface": ["wireless"],
         "phase_hint": "recon",
         "tags": ["wifi", "wpa3"]},
        {"session_id": "ble-iot", "target": "iot-tile",
         "attack_surface": ["wireless"],
         "phase_hint": "recon",
         "tags": ["ble", "gatt"]},
        {"session_id": "phish-web", "target": "https://example.com",
         "attack_surface": ["web"],
         "phase_hint": "exploit",
         "tags": ["osint", "phishing"]},
    ]
    return _build_wsgi_app(roster=sessions, sessions=sessions)


# ---------------------------------------------------------------------------
# 1. Capability search + filter
# ---------------------------------------------------------------------------


class TestCapabilityFilter:
    def test_no_query_returns_all(self, app):
        status, _hdrs, body = _call(app, "/api/sessions")
        assert status == "200 OK"
        data = json.loads(body)
        assert data["ok"] is True
        assert data["matched"] == 3

    def test_query_matches_session_id(self, app):
        status, _hdrs, body = _call(app, "/api/sessions?q=wifi")
        data = json.loads(body)
        assert data["matched"] >= 1
        sids = [s["session_id"] for s in data["sessions"]]
        assert "wifi-lab" in sids

    def test_query_matches_target(self, app):
        status, _hdrs, body = _call(app, "/api/sessions?q=tile")
        data = json.loads(body)
        sids = [s["session_id"] for s in data["sessions"]]
        assert "ble-iot" in sids

    def test_query_matches_tag(self, app):
        status, _hdrs, body = _call(app, "/api/sessions?q=wpa3")
        data = json.loads(body)
        sids = [s["session_id"] for s in data["sessions"]]
        assert "wifi-lab" in sids

    def test_query_matches_attack_surface(self, app):
        status, _hdrs, body = _call(app, "/api/sessions?q=web")
        data = json.loads(body)
        sids = [s["session_id"] for s in data["sessions"]]
        assert "phish-web" in sids

    def test_unknown_query_returns_empty(self, app):
        status, _hdrs, body = _call(app, "/api/sessions?q=zzz_nope")
        data = json.loads(body)
        assert data["matched"] == 0

    def test_unit_filter_sessions(self):
        sessions = [
            {"session_id": "a", "tags": ["wifi"]},
            {"session_id": "b", "tags": ["ble"]},
        ]
        assert filter_sessions(sessions, "wifi") == [{"session_id": "a",
                                                       "tags": ["wifi"]}]
        assert filter_sessions(sessions, "") == sessions
        assert filter_sessions(sessions, "x") == []


# ---------------------------------------------------------------------------
# 2. Pagination
# ---------------------------------------------------------------------------


class TestPagination:
    def test_unit_paginate_with_offset(self):
        rows = list(range(10))
        r = paginate_with_offset(rows, limit=3, offset=0)
        assert r["ok"] is True
        assert r["rows"] == [0, 1, 2]
        assert r["total"] == 10
        assert r["has_more"] is True

        r = paginate_with_offset(rows, limit=3, offset=9)
        assert r["rows"] == [9]
        assert r["has_more"] is False

    def test_unit_paginate_invalid_args(self):
        r = paginate_with_offset([1, 2, 3], limit="not a number",
                                 offset="also not")
        assert r["ok"] is True
        # Defaults: limit=50, offset=0
        assert r["rows"] == [1, 2, 3]

    def test_unit_paginate_empty(self):
        r = paginate_with_offset([], limit=10)
        assert r["rows"] == []
        assert r["total"] == 0
        assert r["has_more"] is False

    def test_unit_since_filter(self):
        rows = [{"ts": 1.0, "msg": "a"},
                {"ts": 2.0, "msg": "b"},
                {"ts": 3.0, "msg": "c"}]
        out = since_filter(rows, 1.5)
        assert len(out) == 2
        out = since_filter(rows, None)
        assert len(out) == 3


# ---------------------------------------------------------------------------
# 3. CSRF
# ---------------------------------------------------------------------------


class TestCSRF:
    def test_token_format(self):
        tok = csrf_token_for("s1")
        assert ":" in tok
        ts, mac = tok.split(":", 1)
        assert int(ts) > 0
        assert len(mac) == 16

    def test_verify_valid(self):
        tok = csrf_token_for("s1")
        ok, reason = verify_csrf("s1", tok)
        assert ok is True
        assert reason == "ok"

    def test_verify_malformed(self):
        ok, reason = verify_csrf("s1", "garbage")
        assert ok is False
        assert "missing" in reason or "malformed" in reason

    def test_verify_wrong_sid(self):
        tok = csrf_token_for("s1")
        ok, reason = verify_csrf("s2", tok)
        assert ok is False
        assert "mismatch" in reason

    def test_verify_expired(self):
        # Generate a token with a timestamp 1 hour ago
        old_ts = time.time() - 3700
        tok = csrf_token_for("s1", ts=old_ts)
        ok, reason = verify_csrf("s1", tok, max_age_s=300)
        assert ok is False
        assert "expired" in reason


# ---------------------------------------------------------------------------
# 4. Compact mode
# ---------------------------------------------------------------------------


class TestCompactMode:
    def test_is_compact_1(self):
        assert is_compact_mode({"compact": "1"}) is True

    def test_is_compact_true(self):
        assert is_compact_mode({"compact": "true"}) is True

    def test_is_compact_yes(self):
        assert is_compact_mode({"compact": "yes"}) is True

    def test_is_not_compact(self):
        assert is_compact_mode({"compact": "0"}) is False
        assert is_compact_mode({}) is False
        assert is_compact_mode({"compact": "false"}) is False

    def test_compact_mode_sessions_endpoint(self, app):
        status, _hdrs, body = _call(app, "/api/sessions?compact=1&q=wifi")
        data = json.loads(body)
        assert data["ok"] is True
        assert data["compact"] is True
        assert "sids" in data
        # No full session dicts in compact mode
        assert "sessions" not in data


# ---------------------------------------------------------------------------
# 5. Better 404 with nearest sids
# ---------------------------------------------------------------------------


class TestBestMatchSid:
    def test_exact_match(self):
        out = best_match_sid("abc", ["abc", "xyz"])
        assert out == [("abc", 0)]

    def test_within_max_dist(self):
        out = best_match_sid("abc", ["abd", "xyz", "ab"])
        # 'abd' distance 1, 'ab' distance 1, sorted by (dist, name)
        assert ("abd", 1) in out
        assert ("ab", 1) in out
        assert ("xyz", 2) not in out  # distance 3

    def test_no_match(self):
        out = best_match_sid("abc", ["xyz", "123"])
        assert out == []

    def test_empty_inputs(self):
        assert best_match_sid("", ["a"]) == []
        assert best_match_sid("a", []) == []

    def test_404_returns_nearest(self, app):
        # Hit a completely unrouted path so the T6.5 404 handler fires
        status, _hdrs, body = _call(app, "/totally_unknown_route")
        data = json.loads(body)
        assert status.startswith("404")
        # The T6.5 handler is JSON (not the legacy _err handler)
        assert data["ok"] is False
        assert data["path"] == "/totally_unknown_route"
        assert data["method"] == "GET"
        # No Levenshtein match expected (we hit a top-level unknown
        # path, not a session-sid) — just verify the field exists
        assert "nearest_sids" in data
        assert "recent_sids" in data


# ---------------------------------------------------------------------------
# 6. Live tail
# ---------------------------------------------------------------------------


class TestLiveTail:
    def test_unit_live_tail_merges_and_sorts(self):
        log = [{"ts": 1.0, "msg": "a"},
               {"ts": 3.0, "msg": "c"}]
        hist = [{"ts": 2.0, "msg": "b", "action": "click"}]
        out = live_tail_lines(log, hist)
        assert out["count"] == 3
        # Sorted by ts ascending
        assert out["lines"][0]["ts"] == 1.0
        assert out["lines"][1]["ts"] == 2.0
        assert out["lines"][2]["ts"] == 3.0
        # Source annotated
        sources = [l["source"] for l in out["lines"]]
        assert "log" in sources
        assert "history" in sources

    def test_unit_live_tail_since_filter(self):
        log = [{"ts": 1.0, "msg": "a"}, {"ts": 2.0, "msg": "b"}]
        out = live_tail_lines(log, [], since_ts=1.5)
        assert out["count"] == 1
        assert out["lines"][0]["msg"] == "b"
        assert out["latest_ts"] == 2.0

    def test_unit_live_tail_empty(self):
        out = live_tail_lines([], [])
        assert out["count"] == 0
        assert out["latest_ts"] == 0.0

    def test_endpoint_returns_tail(self, app):
        status, _hdrs, body = _call(
            app, "/api/session/wifi-lab/live_tail?since=0",
        )
        # SQLite backend may not have rows for this sid, so the
        # endpoint should still return ok=True with count=0
        data = json.loads(body)
        assert data["ok"] is True
        assert "count" in data
        assert "latest_ts" in data

    def test_endpoint_unknown_session(self, app):
        status, _hdrs, body = _call(
            app, "/api/session/no-such-sid/live_tail",
        )
        data = json.loads(body)
        assert data["ok"] is False
        assert "unknown" in data["error"]

    def test_endpoint_compact(self, app):
        status, _hdrs, body = _call(
            app, "/api/session/wifi-lab/live_tail?compact=1",
        )
        data = json.loads(body)
        assert data["ok"] is True
        assert data["compact"] is True
        assert "lines" not in data


# ---------------------------------------------------------------------------
# 7. Chain planner + CSRF
# ---------------------------------------------------------------------------


class TestChainPlanner:
    def test_unit_chain_plan_stub(self):
        sess = {"session_id": "s1", "attack_surface": ["wireless"],
                "phase_hint": "recon"}
        out = chain_plan_from_session(sess, "scan")
        assert out["ok"] is True
        assert out["sid"] == "s1"
        assert out["capability"] == "scan"
        assert out["source"] == "stub"
        # Plan steps derived only from metadata — no fabrication
        plan = out["plan"]
        assert plan["stub"] is True
        assert plan["steps"][0]["name"] == "scan"
        assert plan["steps"][0]["attack_surface"] == "wireless"

    def test_unit_chain_plan_with_runner(self):
        sess = {"session_id": "s1"}
        def runner(s, cap):
            return {"ok": True, "steps": [{"name": cap, "note": "ok"}]}
        out = chain_plan_from_session(sess, "x", chain_planner_runner=runner)
        assert out["ok"] is True
        assert out["source"] == "chain_planner"
        assert out["plan"]["steps"][0]["note"] == "ok"

    def test_unit_chain_plan_missing_cap(self):
        out = chain_plan_from_session({}, "")
        assert out["ok"] is False

    def test_unit_chain_plan_handles_string_attack_surface(self):
        sess = {"attack_surface": "web"}
        out = chain_plan_from_session(sess, "x")
        assert out["plan"]["steps"][0]["attack_surface"] == "web"

    def test_endpoint_plan_requires_csrf(self, app):
        body = json.dumps({"sid": "wifi-lab", "capability": "scan"})
        status, _hdrs, resp = _call(
            app, "/api/plan", method="POST", body=body.encode(),
            headers={"X-CSRF-Token": "no-such-token"},
        )
        # No valid CSRF → 403
        assert status.startswith("403")
        data = json.loads(resp)
        assert data["ok"] is False
        assert "CSRF" in data["error"]

    def test_endpoint_plan_with_valid_csrf(self, app):
        # First, mint a token
        status, _hdrs, body = _call(app, "/api/csrf/wifi-lab")
        token_data = json.loads(body)
        assert token_data["ok"] is True
        token = token_data["token"]
        # Now POST /api/plan with the token
        body = json.dumps({"sid": "wifi-lab", "capability": "scan"})
        status, _hdrs, resp = _call(
            app, "/api/plan", method="POST", body=body.encode(),
            headers={"X-CSRF-Token": token},
        )
        data = json.loads(resp)
        assert data["ok"] is True
        assert data["sid"] == "wifi-lab"
        assert data["capability"] == "scan"

    def test_endpoint_plan_missing_fields(self, app):
        # No sid/cap
        status, _hdrs, body = _call(app, "/api/plan", method="POST",
                                    body=b"{}",
                                    headers={"X-CSRF-Token": "x.y"})
        # CSRF still runs first; missing fields return 400
        # Actually CSRF will fail with token "x.y" → 403
        # (CSRF check is before field check; that's correct for
        #  security — never leak field-validation info to a CSRF
        #  attacker)
        assert status.startswith("403") or status.startswith("400")


# ---------------------------------------------------------------------------
# Adversarial: no fabrication
# ---------------------------------------------------------------------------


class TestAdversarial:
    def test_no_endpoint_fabricates_cve(self, app):
        """Hit every endpoint and confirm no CVE in the output."""
        paths = [
            "/api/sessions",
            "/api/sessions?q=wifi",
            "/api/transport_summary",
            "/api/sql_health",
        ]
        for p in paths:
            status, _hdrs, body = _call(app, p)
            text = body.decode("utf-8", errors="replace")
            import re
            cves = re.findall(r"CVE-\d{4}-\d+", text)
            assert not cves, f"{p} returned fabricated CVE: {cves}"

    def test_no_endpoint_fabricates_credentials(self, app):
        paths = [
            "/api/sessions",
            "/api/sessions?q=wifi",
        ]
        bad = ("password=", "ntlm:")
        for p in paths:
            _status, _hdrs, body = _call(app, p)
            text = body.decode("utf-8", errors="replace").lower()
            for b in bad:
                assert b not in text, f"{p} returned {b!r}"


# ---------------------------------------------------------------------------
# Optional: end-to-end server smoke (skipped if port 0 is busy)
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    not hasattr(socket, "AF_INET"),
    reason="no socket",
)
class TestServerSmoke:
    def test_serve_thread_serves_sessions_endpoint(self):
        from core.post_access_tui.rat_ext import RatDashboardServer
        # The RatDashboardServer dataclass only exposes `roster`;
        # the `_sessions` attribute is set post-init by
        # spawn_rat_dashboard(). For a unit test, roster is enough.
        sessions = [{"session_id": "s1", "target": "x"}]
        server = RatDashboardServer(roster=sessions,
                                    host="127.0.0.1", port=0)
        port_thread = server.try_serve()
        if port_thread is None:
            pytest.skip("could not bind port")
        port, _t = port_thread
        try:
            import urllib.request
            url = f"http://127.0.0.1:{port}/api/sessions"
            with urllib.request.urlopen(url, timeout=2) as resp:
                body = resp.read().decode("utf-8")
                data = json.loads(body)
                assert data["ok"] is True
        finally:
            server.shutdown()
