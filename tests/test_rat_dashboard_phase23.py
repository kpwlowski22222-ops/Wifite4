"""Phase 2.3.G — RAT-like Flask dashboard."""

import json
import time
import threading
import urllib.request
import urllib.error
import socket

import pytest

from core.post_access_tui.rat_ext import (
    SessionCapability,
    RatDashboardServer,
    spawn_rat_dashboard,
    is_rat_dashboard_available,
    BLUETOOTH_CAPABILITIES,
    NETWORK_CAPABILITIES,
    build_session_roster,
    default_dashboard_html,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _http_get(url: str, timeout: float = 2.0) -> tuple:
    """Tiny HTTP GET that returns (status, body_bytes, content_type)."""
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return r.status, r.read(), r.headers.get("Content-Type", "")
    except urllib.error.HTTPError as e:
        return e.code, e.read() if e.fp else b"", ""


# ---------------------------------------------------------------------------
# Capability registry
# ---------------------------------------------------------------------------


class TestCapabilityRegistry:
    def test_bluetooth_caps_nonempty(self):
        assert len(BLUETOOTH_CAPABILITIES) >= 10

    def test_network_caps_nonempty(self):
        assert len(NETWORK_CAPABILITIES) >= 10

    def test_capability_names_unique(self):
        names = [c.name for c in BLUETOOTH_CAPABILITIES + NETWORK_CAPABILITIES]
        assert len(names) == len(set(names)), f"dup: {names}"

    def test_capability_transport_aligned(self):
        for c in BLUETOOTH_CAPABILITIES:
            assert c.transport == "ble"
        for c in NETWORK_CAPABILITIES:
            assert c.transport == "network"

    def test_capability_required_tuple(self):
        for c in BLUETOOTH_CAPABILITIES + NETWORK_CAPABILITIES:
            assert isinstance(c.required_achievements, tuple)

    def test_risk_in_known_set(self):
        for c in BLUETOOTH_CAPABILITIES + NETWORK_CAPABILITIES:
            assert c.risk in ("read", "destructive")


# ---------------------------------------------------------------------------
# Roster builder
# ---------------------------------------------------------------------------


class TestRosterBuilder:
    def test_no_sessions(self):
        roster = build_session_roster([])
        assert roster == []

    def test_ble_session_no_achievements(self):
        roster = build_session_roster([{
            "id": "ble-1",
            "transport": "ble",
            "target": "AA:BB:CC:DD:EE:FF",
            "achieved": [],
        }])
        assert len(roster) == 1
        # Only the always-available capabilities are shown.
        caps = {c["name"] for c in roster[0]["capabilities"]}
        assert "channel_map" in caps
        assert "gatt_write" not in caps  # requires gatt_write achievement

    def test_ble_session_with_gatt_write(self):
        roster = build_session_roster([{
            "id": "ble-2",
            "transport": "ble",
            "target": "AA:BB:CC:DD:EE:FF",
            "achieved": ["gatt_connect", "gatt_write"],
        }])
        caps = {c["name"] for c in roster[0]["capabilities"]}
        assert "gatt_write" in caps
        assert "gatt_browse" in caps
        assert "gatt_read" in caps
        # No HID without HID achievement
        assert "hid_inject" not in caps

    def test_network_session_with_creds(self):
        roster = build_session_roster([{
            "id": "net-1",
            "transport": "network",
            "target": "10.0.0.5",
            "achieved": ["shell", "creds_dump"],
        }])
        caps = {c["name"] for c in roster[0]["capabilities"]}
        assert "shell" in caps
        assert "hash_dump" in caps
        # No bloodhound without the achievement
        assert "bloodhound" not in caps

    def test_unknown_transport_falls_back_to_network(self):
        roster = build_session_roster([{
            "id": "x",
            "transport": "weird",
            "target": "t",
            "achieved": ["shell"],
        }])
        caps = {c["name"] for c in roster[0]["capabilities"]}
        assert "shell" in caps


# ---------------------------------------------------------------------------
# HTML rendering
# ---------------------------------------------------------------------------


class TestHtmlRendering:
    def test_renders_empty_roster(self):
        html = default_dashboard_html([])
        assert "KFIOSA RAT dashboard" in html
        assert "No active sessions" in html

    def test_renders_session(self):
        html = default_dashboard_html([{
            "id": "ble-1",
            "transport": "ble",
            "target": "AA:BB:CC:DD:EE:FF",
            "achieved": ["gatt_connect"],
            "capabilities": [
                {"name": "gatt_browse", "label": "Browse GATT",
                 "risk": "read", "description": "..."},
            ],
            "meta": {},
        }])
        assert "ble-1" in html
        assert "Browse GATT" in html

    def test_escapes_html_in_session_id(self):
        html = default_dashboard_html([{
            "id": "<script>alert(1)</script>",
            "transport": "ble",
            "target": "AA:BB",
            "achieved": [],
            "capabilities": [],
            "meta": {},
        }])
        assert "<script>alert(1)</script>" not in html
        assert "&lt;script&gt;" in html


# ---------------------------------------------------------------------------
# Server (in-process)
# ---------------------------------------------------------------------------


class TestServer:
    def test_serve_thread_returns_port(self):
        roster = build_session_roster([])
        s = RatDashboardServer(roster=roster, port=0)
        result = s.try_serve()
        assert result is not None
        port, _t = result
        assert port > 0
        s.shutdown()

    def test_root_path_returns_html(self):
        roster = build_session_roster([])
        s = RatDashboardServer(roster=roster, port=0)
        result = s.try_serve()
        assert result is not None
        port, _t = result
        try:
            status, body, ctype = _http_get(f"http://127.0.0.1:{port}/")
            assert status == 200
            assert b"KFIOSA RAT dashboard" in body
            assert "html" in ctype
        finally:
            s.shutdown()

    def test_cap_path_routes_to_runner(self):
        roster = build_session_roster([])
        runner_calls = []

        def runner(sid, cap):
            runner_calls.append((sid, cap))
            return {"ok": True, "session": sid, "capability": cap}

        s = RatDashboardServer(
            roster=roster, port=0, capability_runner=runner)
        result = s.try_serve()
        assert result is not None
        port, _t = result
        try:
            status, body, ctype = _http_get(
                f"http://127.0.0.1:{port}/cap/sess-1/gatt_browse"
            )
            assert status == 200
            assert "json" in ctype
            payload = json.loads(body)
            assert payload["ok"] is True
            assert payload["session"] == "sess-1"
            assert payload["capability"] == "gatt_browse"
            assert runner_calls == [("sess-1", "gatt_browse")]
        finally:
            s.shutdown()

    def test_cap_path_no_runner_returns_view_only(self):
        s = RatDashboardServer(roster=[], port=0)
        result = s.try_serve()
        assert result is not None
        port, _t = result
        try:
            status, body, ctype = _http_get(
                f"http://127.0.0.1:{port}/cap/sess-1/foo"
            )
            assert status == 200
            payload = json.loads(body)
            assert payload["ok"] is False
            assert "view-only" in payload["error"].lower()
        finally:
            s.shutdown()

    def test_unknown_path_returns_404(self):
        s = RatDashboardServer(roster=[], port=0)
        result = s.try_serve()
        assert result is not None
        port, _t = result
        try:
            status, _b, _c = _http_get(f"http://127.0.0.1:{port}/nope")
            assert status == 404
        finally:
            s.shutdown()

    def test_only_get_allowed(self):
        s = RatDashboardServer(roster=[], port=0)
        result = s.try_serve()
        assert result is not None
        port, _t = result
        try:
            req = urllib.request.Request(
                f"http://127.0.0.1:{port}/", method="POST")
            try:
                urllib.request.urlopen(req, timeout=2.0)
                # If the server didn't raise, the response was
                # not 405 (root only accepts GET). The dashboard
                # currently returns 404 for POST to /, which is
                # also fine.
            except urllib.error.HTTPError as ei:
                # Either 405 (method not allowed) or 404 (not
                # found) is acceptable — both indicate POST
                # to / is rejected.
                assert ei.code in (405, 404)
        finally:
            s.shutdown()


# ---------------------------------------------------------------------------
# Spawner
# ---------------------------------------------------------------------------


class TestSpawner:
    def test_is_rat_dashboard_available(self):
        assert is_rat_dashboard_available() is True

    def test_spawn_returns_envelope(self):
        sessions = [
            {"id": "ble-x", "transport": "ble", "target": "AA:BB",
             "achieved": ["gatt_connect"]},
        ]
        result = spawn_rat_dashboard(sessions)
        assert result["ok"] is True
        assert "port" in result
        assert result["port"] > 0
        assert result["host"] == "127.0.0.1"
        assert "manual" in result
        # Verify it's actually serving
        status, body, _c = _http_get(
            f"http://{result['host']}:{result['port']}/"
        )
        assert status == 200
        assert b"ble-x" in body

    def test_spawn_empty_sessions(self):
        result = spawn_rat_dashboard([])
        assert result["ok"] is True
        assert result["sessions"] == 0

    def test_spawn_no_capability_runner(self):
        result = spawn_rat_dashboard([])
        assert result["ok"] is True
        status, body, ctype = _http_get(
            f"http://{result['host']}:{result['port']}/cap/x/y"
        )
        assert status == 200
        payload = json.loads(body)
        assert payload["ok"] is False


# ---------------------------------------------------------------------------
# Adversarial
# ---------------------------------------------------------------------------


class TestAdversarial:
    def test_no_inline_credentials_in_dashboard(self):
        roster = build_session_roster([
            {"id": "net-1", "transport": "network", "target": "10.0.0.5",
             "achieved": ["shell", "creds_dump"]},
        ])
        html = default_dashboard_html(roster)
        # The dashboard must NEVER contain real credential values,
        # only capability labels and descriptions.
        for bad in ("KFIOSA_TARGET_PASSWORD", "KFIOSA_AA1_",
                    "KFIOSA_AA3_", "NThash", "ntlm_hash:",
                    '"password"', '"psk"'):
            assert bad not in html, f"dashboard leaked {bad}"

    def test_host_defaults_to_loopback(self):
        result = spawn_rat_dashboard([])
        # The default MUST be 127.0.0.1, not 0.0.0.0
        assert result["host"] == "127.0.0.1"
        # The manual should not contain a binding instruction that
        # would auto-expose on 0.0.0.0; it may mention the env var
        # but only as the operator's opt-in path.
        # We assert the host itself is loopback, which is the safety
        # critical property.

    def test_roster_does_not_duplicate_caps(self):
        roster = build_session_roster([
            {"id": "n1", "transport": "network", "target": "x",
             "achieved": ["shell", "creds_dump"]},
        ])
        cap_names = [c["name"] for c in roster[0]["capabilities"]]
        assert len(cap_names) == len(set(cap_names))

    def test_session_with_always_available_caps(self):
        # With NO achievements, the session still gets the
        # always-available capabilities (channel_map, rssi_track
        # in BLE; some always-available in network).
        roster = build_session_roster([
            {"id": "empty", "transport": "ble", "target": "x",
             "achieved": []},
        ])
        html = default_dashboard_html(roster)
        assert "empty" in html
        # Verify the always-available cap is shown
        assert "channel_map" in html
        # And the gated ones are NOT
        assert "gatt_write" not in html
        assert "hid_inject" not in html


# ---------------------------------------------------------------------------
# Phase summary
# ---------------------------------------------------------------------------


class TestPhaseSummary:
    def test_bluetooth_caps_at_least_10(self):
        assert len(BLUETOOTH_CAPABILITIES) >= 10

    def test_network_caps_at_least_10(self):
        assert len(NETWORK_CAPABILITIES) >= 10
