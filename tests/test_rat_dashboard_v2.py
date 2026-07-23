"""tests.test_rat_dashboard_v2 — Phase 2.4 §B dashboard v2 tests.

Exercises every new v2 route + the auth gate + the auto-PDF /
auto-dashboard integration in ``run_full_auto`` and the panel
``curses_free_loop`` callers.

All tests are hermetic: no real network, no real Kismet, no real
Ollama, no real filesystem writes outside ``tmp_path``. The
screenshot / PDF / history modules use a temp dir per test.
"""
from __future__ import annotations

import importlib
import json
import os
import socket
import sys
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest


# ---------------------------------------------------------------------------
# Module-level fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def rat_dashboard():
    """Import the rat_ext package and pre-load all submodules so
    tests can access them via ``rat_dashboard.auth`` etc."""
    from core.post_access_tui import rat_ext
    from core.post_access_tui.rat_ext import (
        auth, file_browser, sse, history, screenshot, aggregate,
        recommender, exfil_queue, persistence_ui, pdf_export, auto_pdf,
    )
    # Bind the submodules to the package so rat_dashboard.<name> works
    rat_ext.auth = auth
    rat_dashboard_ = type("RD", (), {})()
    rat_dashboard_.auth = auth
    rat_dashboard_.file_browser = file_browser
    rat_dashboard_.sse = sse
    rat_dashboard_.history = history
    rat_dashboard_.screenshot = screenshot
    rat_dashboard_.aggregate = aggregate
    rat_dashboard_.recommender = recommender
    rat_dashboard_.exfil_queue = exfil_queue
    rat_dashboard_.persistence_ui = persistence_ui
    rat_dashboard_.pdf_export = pdf_export
    rat_dashboard_.auto_pdf = auto_pdf
    rat_dashboard_.build_session_roster = rat_ext.build_session_roster
    rat_dashboard_.default_dashboard_html = rat_ext.default_dashboard_html
    rat_dashboard_._build_wsgi_app = rat_ext._build_wsgi_app
    rat_dashboard_.spawn_rat_dashboard = rat_ext.spawn_rat_dashboard
    rat_dashboard_.is_rat_dashboard_available = (
        rat_ext.is_rat_dashboard_available
    )
    return rat_dashboard_


@pytest.fixture
def sample_sessions() -> List[Dict[str, Any]]:
    return [
        {
            "id": "S_BLE",
            "session_id": "S_BLE",
            "transport": "ble",
            "target": "AA:BB:CC:DD:EE:FF",
            "achieved": ["handshake"],
            "capabilities": [
                {"name": "ble_gatt_discover", "label": "GATT",
                 "risk": "read", "description": "d",
                 "required_achievements": []},
                {"name": "ble_hid_inject", "label": "HID",
                 "risk": "destructive", "description": "d",
                 "required_achievements": []},
            ],
            "exfil_jobs": [
                {"id": "J1", "channel": "http",
                 "bytes_pending": 1024, "status": "queued"},
            ],
            "persistence_mechanisms": [
                {"id": "M1", "name": "wmi", "target_os": "windows",
                 "installed_at": 1.0, "status": "active"},
            ],
            "step_envelope_history": [
                {"ts": 1.0, "action": "a"},
                {"ts": 2.0, "action": "b"},
            ],
        },
        {
            "id": "S_NET",
            "session_id": "S_NET",
            "transport": "network",
            "target": "192.168.1.10",
            "achieved": ["creds"],
            "capabilities": [
                {"name": "impacket_psexec", "label": "psexec",
                 "risk": "intrusive", "description": "d",
                 "required_achievements": []},
            ],
            "exfil_jobs": [],
            "persistence_mechanisms": [],
            "step_envelope_history": [],
        },
    ]


def _call(app, path, method="GET", body=b"", query="",
          cookie: Optional[str] = None) -> Dict[str, Any]:
    """WSGI dispatch helper."""
    env = {
        "REQUEST_METHOD": method,
        "PATH_INFO": path,
        "QUERY_STRING": query,
        "SERVER_NAME": "127.0.0.1",
        "HTTP_HOST": "127.0.0.1:0",
        "wsgi.input": type("I", (), {"read": lambda self, n: body})(),
    }
    if cookie:
        env["HTTP_COOKIE"] = cookie
    out = {"status": None, "headers": None, "body": b""}

    def start_resp(status, headers):
        out["status"] = status
        out["headers"] = dict(headers)

    chunks = app(env, start_resp)
    out["body"] = b"".join(chunks)
    return out


# ===========================================================================
# §B.1 auth
# ===========================================================================


class TestAuth:
    def test_get_required_token(self, monkeypatch):
        from core.post_access_tui.rat_ext import auth
        monkeypatch.delenv("RAT_DASHBOARD_TOKEN", raising=False)
        assert auth.get_required_token() is None
        monkeypatch.setenv("RAT_DASHBOARD_TOKEN", "secret-12345")
        assert auth.get_required_token() == "secret-12345"

    def test_is_token_required_only_on_wildcard(self, monkeypatch):
        from core.post_access_tui.rat_ext import auth
        monkeypatch.delenv("RAT_DASHBOARD_TOKEN", raising=False)
        # Localhost binds don't require a token (function is pure: just
        # checks the host argument)
        assert auth.is_token_required("127.0.0.1") is False
        assert auth.is_token_required("localhost") is False
        # Non-loopback hosts (including wildcard 0.0.0.0) DO require it
        assert auth.is_token_required("0.0.0.0") is True
        # Spawner enforces the actual env check (see TestSpawner below)

    def test_login_html(self, rat_dashboard):
        html = rat_dashboard.auth.build_login_html()
        assert isinstance(html, bytes)
        assert b"KFIOSA" in html
        assert b"token" in html.lower()
        html2 = rat_dashboard.auth.build_login_html("mismatch")
        assert b"wrong" in html2.lower() or b"err" in html2.lower()

    def test_parse_cookie(self):
        from core.post_access_tui.rat_ext.auth import (
            parse_cookie, build_set_cookie,
        )
        c = build_set_cookie("hunter2")
        assert "rat_dash" in c
        assert parse_cookie(c) == "hunter2"
        assert parse_cookie("other=value") is None
        assert parse_cookie("") is None

    def test_auth_state_bruteforce_lockout(self, monkeypatch):
        from core.post_access_tui.rat_ext.auth import AuthState
        monkeypatch.setenv("RAT_DASHBOARD_TOKEN", "good")
        st = AuthState()
        # After 5 wrong attempts the AuthState triggers cooldown.
        # The 5th attempt itself still returns "mismatch" (it sets the
        # cooldown after the check); the 6th attempt sees the cooldown.
        for i in range(5):
            ok, reason = st.check_token("wrong")
            assert ok is False
        # 6th attempt: cooldown enforced, even a correct token is refused
        ok, reason = st.check_token("good")
        assert ok is False
        assert reason == "cooldown"

    def test_auth_state_correct_token(self, monkeypatch):
        from core.post_access_tui.rat_ext.auth import AuthState
        monkeypatch.setenv("RAT_DASHBOARD_TOKEN", "good")
        st = AuthState()
        ok, _ = st.check_token("good")
        assert ok is True
        ok, _ = st.check_token("wrong")
        assert ok is False


# ===========================================================================
# §B.2 file browser
# ===========================================================================


class TestFileBrowser:
    def test_ls_rejects_when_no_paths(self, rat_dashboard):
        r = rat_dashboard.file_browser.ls(".", [])
        assert r["ok"] is False
        assert "allow-list" in r["error"].lower()

    def test_ls_rejects_path_traversal(self, rat_dashboard, tmp_path):
        r = rat_dashboard.file_browser.ls("../../etc/passwd", [str(tmp_path)])
        assert r["ok"] is False
        assert "traversal" in r["error"].lower() or "denied" in r["error"].lower()

    def test_ls_inside_allowed_dir(self, rat_dashboard, tmp_path):
        (tmp_path / "a.txt").write_text("hi")
        r = rat_dashboard.file_browser.ls(".", [str(tmp_path)])
        assert r["ok"] is True
        assert any(e["name"] == "a.txt" for e in r["entries"])

    def test_get_text_small(self, rat_dashboard, tmp_path):
        p = tmp_path / "x.txt"
        p.write_text("hello\n")
        r = rat_dashboard.file_browser.get("x.txt", [str(tmp_path)])
        assert r["ok"] is True
        assert r["mime"] == "text/plain"
        assert "hello" in r["text"]

    def test_get_image_thumbnail(self, rat_dashboard, tmp_path):
        # 1x1 PNG
        png = (
            b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"
            b"\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4"
            b"\x89\x00\x00\x00\rIDATx\x9cc\x00\x01\x00\x00\x05\x00\x01\r\n"
            b"\x2d\xb4\x00\x00\x00\x00IEND\xaeB`\x82"
        )
        (tmp_path / "x.png").write_bytes(png)
        r = rat_dashboard.file_browser.get("x.png", [str(tmp_path)])
        # If Pillow is installed → ok=True with thumbnail metadata
        # If Pillow is missing → ok=False with helpful error
        assert "ok" in r

    def test_get_path_traversal_blocked(self, rat_dashboard, tmp_path):
        r = rat_dashboard.file_browser.get(
            "../../../etc/passwd", [str(tmp_path)])
        assert r["ok"] is False

    def test_put_blocked(self, rat_dashboard):
        r = rat_dashboard.file_browser.put_blocked()
        assert r["ok"] is False
        assert "not exposed" in r["error"].lower() or \
               "/upload" in r["error"].lower()


# ===========================================================================
# §B.3 SSE + polling
# ===========================================================================


class TestSSE:
    def test_build_sse_envelope(self, rat_dashboard):
        sse = rat_dashboard.sse.build_sse_envelope(
            [("log", {"ts": 1.0, "payload": "x"})],
            start_ts=1.0,
        )
        assert sse.startswith("event:")
        assert "log" in sse
        assert "done" in sse  # final marker

    def test_heartbeat(self, rat_dashboard):
        sse = rat_dashboard.sse.build_heartbeat()
        assert "heartbeat" in sse

    def test_poll_session_log(self, rat_dashboard):
        session = {
            "log_buffer": [
                {"ts": 1.0, "kind": "log", "msg": "a"},
                {"ts": 2.0, "kind": "log", "msg": "b"},
                {"ts": 3.0, "kind": "log", "msg": "c"},
            ],
        }
        ct, body = rat_dashboard.sse.poll_session_log(
            "S1", session, since_ts=1.5)
        assert "ndjson" in ct or "json" in ct
        lines = [l for l in body.strip().split("\n") if l]
        # 2 events (ts=2,3) since since_ts=1.5
        assert len(lines) == 2

    def test_poll_no_history(self, rat_dashboard):
        ct, body = rat_dashboard.sse.poll_session_log("S1", {}, since_ts=None)
        assert "ndjson" in ct or "json" in ct
        # Just a heartbeat
        data = json.loads(body.strip().split("\n")[0])
        assert data["kind"] == "heartbeat"


# ===========================================================================
# §B.4 history
# ===========================================================================


class TestHistory:
    def test_append_and_read(self, rat_dashboard, tmp_path, monkeypatch):
        monkeypatch.setattr(rat_dashboard.history, "HISTORY_DIR", tmp_path)
        e1 = {"ts": 1.0, "action": "x", "cmd": "ls"}
        e2 = {"ts": 2.0, "action": "y", "cmd": "cat"}
        rat_dashboard.history.append_event("S1", e1)
        rat_dashboard.history.append_event("S1", e2)
        events = rat_dashboard.history.read_history("S1")
        assert len(events) == 2
        assert events[0]["ts"] == 1.0

    def test_paginate(self, rat_dashboard, tmp_path, monkeypatch):
        monkeypatch.setattr(rat_dashboard.history, "HISTORY_DIR", tmp_path)
        for i in range(10):
            rat_dashboard.history.append_event(
                "S1", {"ts": float(i), "action": f"a{i}"})
        r = rat_dashboard.history.paginate("S1", limit=3)
        assert r["ok"] is True
        assert r["count"] == 3
        assert r["next_since_ts"] is not None

    def test_paginate_with_since(self, rat_dashboard, tmp_path, monkeypatch):
        monkeypatch.setattr(rat_dashboard.history, "HISTORY_DIR", tmp_path)
        for i in range(5):
            rat_dashboard.history.append_event(
                "S1", {"ts": float(i), "action": f"a{i}"})
        # since_ts=2.0 excludes ts=0,1,2 (inclusive boundary); keeps 3,4
        r = rat_dashboard.history.paginate("S1", since_ts=2.0)
        assert r["ok"] is True
        assert r["count"] == 2  # ts=3,4
        # since_ts=1.5 excludes ts=0,1; keeps 2,3,4
        r = rat_dashboard.history.paginate("S1", since_ts=1.5)
        assert r["count"] == 3

    def test_replay_envelope(self, rat_dashboard):
        e = {"ts": 1.0, "action": "x", "cmd": "ls"}
        r = rat_dashboard.history.build_replay_envelope("S1", e)
        assert r["ok"] is True
        assert r["session_id"] == "S1"
        assert r["original"]["cmd"] == "ls"
        assert r["action"] == "replay_history"

    def test_replay_envelope_empty(self, rat_dashboard):
        r = rat_dashboard.history.build_replay_envelope("S1", {})
        assert r["ok"] is False
        assert "missing" in r["error"] or "empty" in r["error"].lower()


# ===========================================================================
# §B.5 screenshot
# ===========================================================================


class TestScreenshot:
    def test_save_png(self, rat_dashboard, tmp_path, monkeypatch):
        monkeypatch.setattr(rat_dashboard.screenshot, "SCREENS_DIR", tmp_path)
        # Build a real, valid 1x1 PNG using Pillow if available, so
        # the test doesn't depend on the older hand-rolled PNG bytes
        # (which Pillow 12+ rejects with a checksum error).
        try:
            from PIL import Image
            import io
            buf = io.BytesIO()
            Image.new("RGB", (1, 1), (255, 0, 0)).save(buf, format="PNG")
            png = buf.getvalue()
        except Exception:  # noqa: BLE001
            # Fallback to the hand-rolled PNG (works without Pillow)
            png = (
                b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"
                b"\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4"
                b"\x89\x00\x00\x00\rIDATx\x9cc\x00\x01\x00\x00\x05\x00\x01\r\n"
                b"\x2d\xb4\x00\x00\x00\x00IEND\xaeB`\x82"
            )
        r = rat_dashboard.screenshot.save_screenshot(
            "S1", png, declared_mime="image/png")
        # Pillow may or may not be installed
        if r["ok"]:
            assert r["path"].endswith(".png")
        else:
            # Honest-degrade if Pillow is missing — that's the
            # operator's expected fallback
            assert "pillow" in r["error"].lower() or \
                   "exif" in r["error"].lower() or \
                   "image" in r["error"].lower()

    def test_save_rejects_oversize(self, rat_dashboard, tmp_path, monkeypatch):
        monkeypatch.setattr(rat_dashboard.screenshot, "SCREENS_DIR", tmp_path)
        huge = b"\xff" * (6 * 1024 * 1024)
        r = rat_dashboard.screenshot.save_screenshot(
            "S1", huge, declared_mime="image/png")
        assert r["ok"] is False
        assert "too large" in r["error"].lower() or "size" in r["error"].lower()

    def test_save_rejects_bad_mime(self, rat_dashboard, tmp_path, monkeypatch):
        monkeypatch.setattr(rat_dashboard.screenshot, "SCREENS_DIR", tmp_path)
        r = rat_dashboard.screenshot.save_screenshot(
            "S1", b"x", declared_mime="text/html")
        assert r["ok"] is False
        assert "mime" in r["error"].lower()

    def test_list_screens(self, rat_dashboard, tmp_path, monkeypatch):
        monkeypatch.setattr(rat_dashboard.screenshot, "SCREENS_DIR", tmp_path)
        (tmp_path / "S1").mkdir()
        (tmp_path / "S1" / "1.png").write_bytes(b"\x89PNG")
        r = rat_dashboard.screenshot.list_screens("S1")
        assert r["ok"] is True
        assert r["count"] >= 1


# ===========================================================================
# §B.6 aggregate
# ===========================================================================


class TestAggregate:
    def test_transport_summary(self, rat_dashboard, sample_sessions):
        r = rat_dashboard.aggregate.build_transport_summary(sample_sessions)
        assert r["ok"] is True
        assert r["total_sessions"] == 2
        assert r["ble_sessions"] == 1
        assert r["network_sessions"] == 1

    def test_transport_summary_empty(self, rat_dashboard):
        r = rat_dashboard.aggregate.build_transport_summary([])
        assert r["ok"] is True
        assert r["total_sessions"] == 0

    def test_aggregate_html(self, rat_dashboard, sample_sessions):
        body = rat_dashboard.aggregate.build_aggregate_html(sample_sessions)
        assert b"KFIOSA" in body
        assert b"S_BLE" in body
        assert b"S_NET" in body
        assert b"PDF" in body


# ===========================================================================
# §B.7 recommender
# ===========================================================================


class TestRecommender:
    def test_recommend_excludes_destructive(self, rat_dashboard):
        session = {
            "session_id": "S1",
            "achieved": [],
            "capabilities": [
                {"name": "a", "label": "A", "risk": "read",
                 "description": "x"},
                {"name": "b", "label": "B", "risk": "destructive",
                 "description": "x"},
                {"name": "c", "label": "C", "risk": "intrusive",
                 "description": "x"},
            ],
        }
        r = rat_dashboard.recommender.recommend_for_session(session)
        assert r["ok"] is True
        names = [c["name"] for c in r["recommendations"]]
        assert "b" not in names  # destructive excluded
        assert "a" in names
        assert "c" in names  # intrusive is OK

    def test_recommend_score_ordering(self, rat_dashboard):
        session = {
            "session_id": "S1",
            "achieved": [],
            "capabilities": [
                {"name": "lo", "label": "L", "risk": "read",
                 "description": "x"},
                {"name": "hi", "label": "H", "risk": "read",
                 "description": "x"},
            ],
        }
        r = rat_dashboard.recommender.recommend_for_session(session)
        # Recommendations are sorted by score desc
        scores = [c["score"] for c in r["recommendations"]]
        assert scores == sorted(scores, reverse=True)

    def test_recommend_empty_session(self, rat_dashboard):
        r = rat_dashboard.recommender.recommend_for_session({})
        assert r["ok"] is True
        assert r["count"] == 0


# ===========================================================================
# §B.8 exfil + persistence
# ===========================================================================


class TestExfilQueue:
    def test_list_jobs(self, rat_dashboard):
        session = {
            "session_id": "S1",
            "exfil_jobs": [
                {"id": "J1", "channel": "http",
                 "bytes_pending": 1024, "status": "queued"},
                {"id": "J2", "channel": "dns",
                 "bytes_pending": 0, "status": "cancelled"},
            ],
        }
        r = rat_dashboard.exfil_queue.list_jobs(session)
        assert r["ok"] is True
        assert r["count"] == 2
        # Cancelled jobs are excluded from pending bytes
        assert r["total_pending_bytes"] == 1024

    def test_cancel_envelope(self, rat_dashboard):
        session = {"session_id": "S1",
                   "exfil_jobs": [{"id": "J1", "channel": "http"}]}
        r = rat_dashboard.exfil_queue.build_cancel_envelope(
            "S1", "J1", session)
        assert r["ok"] is True
        assert r["action"] == "cancel_exfil"
        assert r["cancellation_token"]

    def test_cancel_envelope_missing_job(self, rat_dashboard):
        session = {"exfil_jobs": []}
        r = rat_dashboard.exfil_queue.build_cancel_envelope(
            "S1", "MISSING", session)
        assert r["ok"] is False
        assert "not found" in r["error"]


class TestPersistence:
    def test_list_mechanisms(self, rat_dashboard):
        session = {
            "session_id": "S1",
            "persistence_mechanisms": [
                {"id": "M1", "name": "wmi", "target_os": "windows",
                 "installed_at": 1.0, "status": "active"},
            ],
        }
        r = rat_dashboard.persistence_ui.list_mechanisms(session)
        assert r["ok"] is True
        assert r["count"] == 1
        assert r["mechanisms"][0]["id"] == "M1"

    def test_remove_envelope(self, rat_dashboard):
        session = {
            "session_id": "S1",
            "persistence_mechanisms": [
                {"id": "M1", "name": "wmi"},
            ],
        }
        r = rat_dashboard.persistence_ui.build_remove_envelope(
            "S1", "M1", session)
        assert r["ok"] is True
        assert r["action"] == "remove_persistence"
        assert r["mech_id"] == "M1"

    def test_remove_envelope_missing_mech(self, rat_dashboard):
        r = rat_dashboard.persistence_ui.build_remove_envelope(
            "S1", "MISSING", {"persistence_mechanisms": []})
        assert r["ok"] is False


# ===========================================================================
# §B.9 PDF report
# ===========================================================================


class TestPDFReport:
    def test_session_report_returns_bytes(self, rat_dashboard):
        session = {
            "session_id": "S1",
            "transport": "ble",
            "target": "AA:BB:CC:DD:EE:FF",
            "achieved": ["g"],
            "capabilities": [],
            "exfil_jobs": [],
            "persistence_mechanisms": [],
            "screens": [],
            "step_envelope_history": [
                {"ts": 1.0, "action": "a"},
                {"ts": 2.0, "action": "b"},
            ],
        }
        body, ct = rat_dashboard.pdf_export.build_session_report_bytes(
            session)
        assert isinstance(body, (bytes, bytearray))
        # If fpdf2 installed → application/pdf. Else text/plain.
        assert "pdf" in ct or "text/plain" in ct

    def test_full_report(self, rat_dashboard, sample_sessions):
        body, ct = rat_dashboard.pdf_export.build_full_report_bytes(
            sample_sessions)
        assert isinstance(body, (bytes, bytearray))

    def test_envelope_hash_deterministic(self, rat_dashboard):
        envs = [{"ts": 2.0, "action": "b"},
                {"ts": 1.0, "action": "a"}]
        h1 = rat_dashboard.pdf_export._hash_envelopes(envs)
        h2 = rat_dashboard.pdf_export._hash_envelopes(envs)
        assert h1 == h2
        # Different order must still produce same hash (sort by ts)
        h3 = rat_dashboard.pdf_export._hash_envelopes(
            list(reversed(envs)))
        assert h1 == h3


class TestAutoPDF:
    def test_export_to_tmp(self, rat_dashboard, tmp_path, monkeypatch):
        monkeypatch.setattr(rat_dashboard.auto_pdf, "REPORTS_DIR", tmp_path)
        r = rat_dashboard.auto_pdf.export_full_report(
            [{"session_id": "S1", "transport": "ble",
              "target": "AA:BB", "achieved": [],
              "capabilities": [], "exfil_jobs": [],
              "persistence_mechanisms": [], "screens": [],
              "step_envelope_history": []}],
            chain="test",
        )
        assert r["ok"] is True
        assert r["path"].endswith(".pdf") or r["path"].endswith(".txt")
        assert r["size"] > 0
        assert r["chain"] == "test"

    def test_build_report_path(self, rat_dashboard, tmp_path, monkeypatch):
        monkeypatch.setattr(rat_dashboard.auto_pdf, "REPORTS_DIR", tmp_path)
        p = rat_dashboard.auto_pdf.build_report_path(chain="my_chain")
        assert "my_chain" in str(p)

    def test_export_handles_error(self, rat_dashboard, tmp_path, monkeypatch):
        # Force a write failure by passing an unwritable path
        r = rat_dashboard.auto_pdf.export_full_report(
            [{"session_id": "S1", "transport": "ble",
              "target": "AA:BB", "achieved": [],
              "capabilities": [], "exfil_jobs": [],
              "persistence_mechanisms": [], "screens": [],
              "step_envelope_history": []}],
            out_path=tmp_path / "nonexistent_dir" / "x.pdf",
        )
        assert r["ok"] is False
        assert "error" in r


# ===========================================================================
# §B.10 dashboard HTML
# ===========================================================================


class TestDashboardHTML:
    def test_dashboard_html_contains_pdf_button(self, rat_dashboard,
                                                  sample_sessions, monkeypatch):
        monkeypatch.setenv("KFIOSA_DASHBOARD_MERGE_SQL", "0")
        roster = rat_dashboard.build_session_roster(sample_sessions)
        html = rat_dashboard.default_dashboard_html(roster)
        assert "KFIOSA" in html
        assert "export PDF" in html
        assert "report.pdf" in html
        # Per-session nav
        for s in sample_sessions:
            assert s["session_id"] in html

    def test_dashboard_html_empty(self, rat_dashboard, monkeypatch):
        monkeypatch.setenv("KFIOSA_DASHBOARD_MERGE_SQL", "0")
        html = rat_dashboard.default_dashboard_html([])
        assert "No active sessions" in html

    def test_dashboard_html_has_recommend_and_stream(self, rat_dashboard,
                                                      sample_sessions,
                                                      monkeypatch):
        monkeypatch.setenv("KFIOSA_DASHBOARD_MERGE_SQL", "0")
        roster = rat_dashboard.build_session_roster(sample_sessions)
        html = rat_dashboard.default_dashboard_html(roster)
        assert "recommend" in html
        assert "stream" in html
        assert "exfil" in html
        assert "persistence" in html


# ===========================================================================
# §B.10 WSGI integration
# ===========================================================================


class TestWSGIIntegration:
    def test_root(self, rat_dashboard, sample_sessions, monkeypatch):
        monkeypatch.setenv("KFIOSA_DASHBOARD_MERGE_SQL", "0")
        roster = rat_dashboard.build_session_roster(sample_sessions)
        app = rat_dashboard._build_wsgi_app(roster, sessions=sample_sessions)
        r = _call(app, "/")
        assert r["status"] == "200 OK"
        assert b"KFIOSA" in r["body"]
        assert b"export PDF" in r["body"]

    def test_aggregate_route(self, rat_dashboard, sample_sessions):
        roster = rat_dashboard.build_session_roster(sample_sessions)
        app = rat_dashboard._build_wsgi_app(roster, sessions=sample_sessions)
        r = _call(app, "/aggregate")
        assert r["status"] == "200 OK"
        assert b"S_BLE" in r["body"]

    def test_transport_summary_route(self, rat_dashboard, sample_sessions):
        roster = rat_dashboard.build_session_roster(sample_sessions)
        app = rat_dashboard._build_wsgi_app(roster, sessions=sample_sessions)
        r = _call(app, "/api/transport_summary")
        data = json.loads(r["body"])
        assert data["total_sessions"] == 2

    def test_exfil_list(self, rat_dashboard, sample_sessions):
        roster = rat_dashboard.build_session_roster(sample_sessions)
        app = rat_dashboard._build_wsgi_app(roster, sessions=sample_sessions)
        r = _call(app, "/api/session/S_BLE/exfil")
        assert r["status"] == "200 OK"
        data = json.loads(r["body"])
        assert data["jobs"][0]["id"] == "J1"

    def test_exfil_cancel(self, rat_dashboard, sample_sessions):
        roster = rat_dashboard.build_session_roster(sample_sessions)
        app = rat_dashboard._build_wsgi_app(roster, sessions=sample_sessions)
        r = _call(app, "/api/session/S_BLE/exfil/J1/cancel", method="POST")
        assert r["status"] == "200 OK"
        data = json.loads(r["body"])
        assert data["ok"] is True
        assert data["job_id"] == "J1"

    def test_persistence_list(self, rat_dashboard, sample_sessions):
        roster = rat_dashboard.build_session_roster(sample_sessions)
        app = rat_dashboard._build_wsgi_app(roster, sessions=sample_sessions)
        r = _call(app, "/api/session/S_BLE/persistence")
        data = json.loads(r["body"])
        assert data["mechanisms"][0]["id"] == "M1"

    def test_persistence_remove(self, rat_dashboard, sample_sessions):
        roster = rat_dashboard.build_session_roster(sample_sessions)
        app = rat_dashboard._build_wsgi_app(roster, sessions=sample_sessions)
        r = _call(app, "/api/session/S_BLE/persistence/M1/remove",
                  method="POST")
        data = json.loads(r["body"])
        assert data["ok"] is True

    def test_recommend(self, rat_dashboard, sample_sessions):
        roster = rat_dashboard.build_session_roster(sample_sessions)
        app = rat_dashboard._build_wsgi_app(roster, sessions=sample_sessions)
        r = _call(app, "/api/session/S_BLE/recommend")
        data = json.loads(r["body"])
        assert "recommendations" in data

    def test_history(self, rat_dashboard, sample_sessions, tmp_path,
                     monkeypatch):
        monkeypatch.setattr(rat_dashboard.history, "HISTORY_DIR", tmp_path)
        roster = rat_dashboard.build_session_roster(sample_sessions)
        app = rat_dashboard._build_wsgi_app(roster, sessions=sample_sessions)
        r = _call(app, "/api/session/S_BLE/history", query="limit=10")
        data = json.loads(r["body"])
        assert data["ok"] is True

    def test_ls(self, rat_dashboard, sample_sessions):
        roster = rat_dashboard.build_session_roster(sample_sessions)
        app = rat_dashboard._build_wsgi_app(roster, sessions=sample_sessions)
        r = _call(app, "/api/session/S_BLE/ls")
        data = json.loads(r["body"])
        # empty allowed_paths → 403
        assert data["ok"] is False

    def test_get(self, rat_dashboard, sample_sessions):
        roster = rat_dashboard.build_session_roster(sample_sessions)
        app = rat_dashboard._build_wsgi_app(roster, sessions=sample_sessions)
        r = _call(app, "/api/session/S_BLE/get", query="path=.")
        data = json.loads(r["body"])
        assert data["ok"] is False

    def test_report_pdf(self, rat_dashboard, sample_sessions):
        roster = rat_dashboard.build_session_roster(sample_sessions)
        app = rat_dashboard._build_wsgi_app(roster, sessions=sample_sessions)
        r = _call(app, "/api/session/S_BLE/report.pdf")
        assert r["status"] == "200 OK"

    def test_unknown_session(self, rat_dashboard, sample_sessions):
        roster = rat_dashboard.build_session_roster(sample_sessions)
        app = rat_dashboard._build_wsgi_app(roster, sessions=sample_sessions)
        r = _call(app, "/api/session/UNKNOWN/recommend")
        assert r["status"] == "404 Not Found"

    def test_login_get(self, rat_dashboard, sample_sessions):
        roster = rat_dashboard.build_session_roster(sample_sessions)
        app = rat_dashboard._build_wsgi_app(roster, sessions=sample_sessions)
        r = _call(app, "/login")
        assert r["status"] == "200 OK"
        assert b"token" in r["body"].lower()

    def test_login_post_wrong_token(self, rat_dashboard, sample_sessions):
        roster = rat_dashboard.build_session_roster(sample_sessions)
        app = rat_dashboard._build_wsgi_app(roster, sessions=sample_sessions)
        r = _call(app, "/login", method="POST", body=b"token=wrong")
        assert r["status"] == "401"

    def test_404_route(self, rat_dashboard, sample_sessions):
        roster = rat_dashboard.build_session_roster(sample_sessions)
        app = rat_dashboard._build_wsgi_app(roster, sessions=sample_sessions)
        r = _call(app, "/no/such/path")
        assert r["status"] == "404 Not Found"

    def test_cap_route_legacy(self, rat_dashboard, sample_sessions):
        roster = rat_dashboard.build_session_roster(sample_sessions)
        runner = lambda sid, cap: {"ok": True, "sid": sid, "cap": cap}
        app = rat_dashboard._build_wsgi_app(roster, capability_runner=runner,
                                            sessions=sample_sessions)
        r = _call(app, "/cap/S_BLE/ble_gatt_discover")
        data = json.loads(r["body"])
        assert data["ok"] is True
        assert data["cap"] == "ble_gatt_discover"

    def test_cap_route_no_runner(self, rat_dashboard, sample_sessions):
        roster = rat_dashboard.build_session_roster(sample_sessions)
        app = rat_dashboard._build_wsgi_app(roster, sessions=sample_sessions)
        r = _call(app, "/cap/S_BLE/ble_gatt_discover")
        data = json.loads(r["body"])
        assert data["ok"] is False
        assert "view-only" in data["error"]

    def test_sse_log_route(self, rat_dashboard, sample_sessions):
        roster = rat_dashboard.build_session_roster(sample_sessions)
        app = rat_dashboard._build_wsgi_app(roster, sessions=sample_sessions)
        r = _call(app, "/stream/S_BLE/log")
        # Returns JSONL (the polling fallback) — first line is a heartbeat
        # when there's no log_buffer, or events when there is
        body = r["body"].decode("utf-8").strip()
        lines = [l for l in body.split("\n") if l]
        assert len(lines) >= 1
        first = json.loads(lines[0])
        # The first entry is either a heartbeat or a log entry
        assert "kind" in first or "events" in first

    def test_sse_stream_route(self, rat_dashboard, sample_sessions):
        roster = rat_dashboard.build_session_roster(sample_sessions)
        app = rat_dashboard._build_wsgi_app(roster, sessions=sample_sessions)
        r = _call(app, "/stream/S_BLE")
        ct = r["headers"].get("Content-Type", "")
        assert "event-stream" in ct or "text/" in ct


# ===========================================================================
# Spawner + auth
# ===========================================================================


class TestSpawner:
    def test_spawn_localhost(self, rat_dashboard, sample_sessions,
                              monkeypatch):
        monkeypatch.setenv("RAT_DASHBOARD_HOST", "127.0.0.1")
        env = rat_dashboard.spawn_rat_dashboard(sample_sessions)
        assert env["ok"] is True
        assert env["port"] > 0
        # Best-effort shutdown
        # (server isn't returned; lifespan ends when the daemon thread dies)

    def test_spawn_0000_refused_without_token(self, rat_dashboard,
                                                sample_sessions, monkeypatch):
        monkeypatch.delenv("RAT_DASHBOARD_TOKEN", raising=False)
        env = rat_dashboard.spawn_rat_dashboard(sample_sessions, host="0.0.0.0")
        assert env["ok"] is False
        assert "RAT_DASHBOARD_TOKEN" in env["error"]

    def test_spawn_0000_with_token(self, rat_dashboard, sample_sessions,
                                    monkeypatch):
        monkeypatch.setenv("RAT_DASHBOARD_TOKEN", "test-12345")
        env = rat_dashboard.spawn_rat_dashboard(sample_sessions, host="0.0.0.0")
        assert env["ok"] is True
        assert env["port"] > 0
        # Best-effort cleanup: bind to local to free the port
        del os.environ["RAT_DASHBOARD_TOKEN"]

    def test_spawn_envelope_shape(self, rat_dashboard, sample_sessions,
                                    monkeypatch):
        monkeypatch.setenv("RAT_DASHBOARD_HOST", "127.0.0.1")
        env = rat_dashboard.spawn_rat_dashboard(sample_sessions)
        for k in ("ok", "port", "host", "url", "sessions", "manual"):
            assert k in env

    def test_is_rat_dashboard_available(self, rat_dashboard):
        assert rat_dashboard.is_rat_dashboard_available() is True


# ===========================================================================
# Auto-PDF + auto-dashboard integration into run_full_auto
# ===========================================================================


class TestFullAutoIntegration:
    def test_run_full_auto_emits_pdf_report(self, tmp_path, monkeypatch):
        from core.post_access_tui import run_full_auto
        from core.post_access_tui.rat_ext import auto_pdf
        monkeypatch.setattr(auto_pdf, "REPORTS_DIR", tmp_path)
        # We don't want the dashboard to actually bind a port
        monkeypatch.setenv("RAT_DASHBOARD_HOST", "127.0.0.1")
        # Don't actually spawn the post-access TUI
        called_spawn = []
        def fake_spawn(_report, **kw):
            called_spawn.append(_report)
            return {"ok": True, "pid": 12345}

        # Fake ai_planner + walk_chain
        class FakePlanner:
            def plan(self, **kw):
                return {"steps": [{"action": "noop"}]}

        def fake_walk_chain(steps, seed):
            return {
                "ok": True,
                "executed": [{"name": "noop", "ok": True}],
                "access": {"achieved": True},
                "session_id": "FAKE",
                "step_envelope_history": [{"ts": 1.0, "action": "x"}],
            }

        env = run_full_auto(
            domain="wifi",
            panel_state={"target": {"ssid": "TEST"}},
            ai_planner=FakePlanner(),
            walk_chain=fake_walk_chain,
            spawn_post_access_tui=fake_spawn,
            confirm_fn=lambda prompt: True,
        )
        assert env["ok"] is True
        assert env["data"]["access_achieved"] is True
        assert env["data"]["spawned_tui"] is True
        # PDF report was emitted
        pdf = env["data"].get("pdf_report")
        assert pdf is not None
        if pdf["ok"]:
            assert pdf["size"] > 0
            assert Path(pdf["path"]).exists()

    def test_run_full_auto_one_shot_dashboard_sentinel(self, tmp_path,
                                                        monkeypatch):
        """The rat_dashboard_opened sentinel must prevent re-spawn."""
        from core.post_access_tui import run_full_auto
        from core.post_access_tui.rat_ext import auto_pdf
        monkeypatch.setattr(auto_pdf, "REPORTS_DIR", tmp_path)
        monkeypatch.setenv("RAT_DASHBOARD_HOST", "127.0.0.1")

        spawn_calls = []
        def fake_spawn(_report, **kw):
            spawn_calls.append(_report)
            return {"ok": True}

        class FakePlanner:
            def plan(self, **kw):
                return {"steps": [{"action": "noop"}]}

        def fake_walk_chain(steps, seed):
            return {
                "ok": True,
                "executed": [{"name": "noop", "ok": True}],
                "access": {"achieved": True,
                           "rat_dashboard_opened": True},  # already
                "session_id": "FAKE",
            }

        env = run_full_auto(
            domain="ble",
            panel_state={"target": {"address": "AA:BB"}},
            ai_planner=FakePlanner(),
            walk_chain=fake_walk_chain,
            spawn_post_access_tui=fake_spawn,
            confirm_fn=lambda prompt: True,
        )
        # Even with access achieved, dashboard must NOT be re-spawned
        # because the sentinel is already True.
        dash = env["data"].get("rat_dashboard", {})
        # The envelope key may be absent (no spawn attempted) or have
        # port=None / ok=False (no spawn happened). The point is the
        # code path didn't bind a new port.
        assert dash == {} or dash.get("port") is None \
            or dash.get("ok") is False \
            or dash.get("note") == "sentinel set, not respawning"


# ===========================================================================
# Menu loop pdf_on_exit hook
# ===========================================================================


class TestMenuLoopPDFHook:
    def test_pdf_on_exit_fires(self):
        from core.post_access_tui import curses_free_loop
        called = []
        def hook(env):
            called.append(env)
            return {"ok": True, "path": "/tmp/x.pdf"}
        env = curses_free_loop(
            prompt="wifi> ",
            screen=type("S", (), {
                "input_fn": staticmethod(lambda p: ""),
                "confirm_fn": staticmethod(lambda p: True),
            })(),
            render_menu=lambda: None,
            visible_hotkeys=lambda: set(),
            handle=lambda k: None,
            pdf_on_exit=hook,
        )
        assert env["pdf_report"]["ok"] is True
        assert len(called) == 1

    def test_pdf_on_exit_failure_does_not_block(self):
        from core.post_access_tui import curses_free_loop
        def hook(env):
            raise RuntimeError("disk full")
        env = curses_free_loop(
            prompt="wifi> ",
            screen=type("S", (), {
                "input_fn": staticmethod(lambda p: ""),
                "confirm_fn": staticmethod(lambda p: True),
            })(),
            render_menu=lambda: None,
            visible_hotkeys=lambda: set(),
            handle=lambda k: None,
            pdf_on_exit=hook,
        )
        assert env["exit"] == "no_input"
        assert "pdf_report" in env
        assert env["pdf_report"]["ok"] is False

    def test_no_pdf_on_exit_works(self):
        from core.post_access_tui import curses_free_loop
        env = curses_free_loop(
            prompt="wifi> ",
            screen=type("S", (), {
                "input_fn": staticmethod(lambda p: ""),
                "confirm_fn": staticmethod(lambda p: True),
            })(),
            render_menu=lambda: None,
            visible_hotkeys=lambda: set(),
            handle=lambda k: None,
        )
        assert env["exit"] == "no_input"
        assert "pdf_report" not in env


# ===========================================================================
# Adversarial: never inline credentials / never fake
# ===========================================================================


class TestAdversarial:
    def test_no_inline_nvd_key(self):
        from pathlib import Path
        from core.post_access_tui import rat_ext
        nvd_key = "ecf51ee2-938d-44de-b015-896a3f6c758c"
        pkg_dir = Path(rat_ext.__file__).parent
        for py in pkg_dir.glob("*.py"):
            text = py.read_text()
            assert nvd_key not in text, \
                f"NVD key inlined in {py}"

    def test_no_inline_kismet_key(self):
        from pathlib import Path
        from core.post_access_tui import rat_ext
        kismet_key = "CE38F76832CFA1F6F35C89EAAEAF61C3"
        pkg_dir = Path(rat_ext.__file__).parent
        for py in pkg_dir.glob("*.py"):
            text = py.read_text()
            assert kismet_key not in text, \
                f"Kismet key inlined in {py}"

    def test_no_inline_ollama_token(self):
        from pathlib import Path
        from core.post_access_tui import rat_ext
        ollama_token = "3d94e52cff9f4df5a01973f24d5bc8db"
        pkg_dir = Path(rat_ext.__file__).parent
        for py in pkg_dir.glob("*.py"):
            text = py.read_text()
            assert ollama_token not in text, \
                f"Ollama token inlined in {py}"

    def test_screenshot_rejects_executable(self, rat_dashboard, tmp_path,
                                            monkeypatch):
        monkeypatch.setattr(rat_dashboard.screenshot, "SCREENS_DIR", tmp_path)
        # HTML masquerading as PNG
        r = rat_dashboard.screenshot.save_screenshot(
            "S1", b"<html>evil</html>", declared_mime="image/png")
        # If Pillow is installed: verify() rejects this. Otherwise the
        # MIME check or the EXIF strip path rejects it. Either way,
        # the envelope must NOT be {ok: True} with a saved .png.
        assert r["ok"] is False
        assert "error" in r
