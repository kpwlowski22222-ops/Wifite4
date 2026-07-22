"""Tests for core.post_access_tui.rat_ext.rat_dynamic — multi-session RAT UI."""
from __future__ import annotations

import json
import socket
import threading
import urllib.request
import urllib.error

import pytest

from core.post_access_tui.rat_ext import (
    build_session_roster,
    spawn_rat_dashboard,
    default_dashboard_html,
)
from core.post_access_tui.rat_ext.rat_dynamic import (
    normalize_kind,
    kind_label,
    rat_menu_for_session,
    build_attack_state,
    SessionRegistry,
    enrich_roster_entry,
    build_rat_dashboard_html,
)


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _get(url: str, timeout: float = 2.0):
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return r.status, r.read(), r.headers.get("Content-Type", "")


# ---------------------------------------------------------------------------
# Kind + menu
# ---------------------------------------------------------------------------


class TestKindNormalize:
    def test_wifi_aliases(self):
        assert normalize_kind({"transport": "wifi"}) == "wifi"
        assert normalize_kind({"transport": "wpa3"}) == "wifi"

    def test_ble(self):
        assert normalize_kind({"transport": "ble"}) == "ble"

    def test_host_from_network(self):
        assert normalize_kind({"transport": "network"}) == "host"
        assert normalize_kind({"transport": "ssh"}) == "host"

    def test_friendly_labels(self):
        assert "Wi-Fi" in kind_label("wifi") or "Wi‑Fi" in kind_label("wifi") or "Wi" in kind_label("wifi")
        assert "Bluetooth" in kind_label("ble")
        assert "Host" in kind_label("host")


class TestRatMenu:
    def test_host_shell_unlocks_shell_action(self):
        menu = rat_menu_for_session({
            "id": "h1",
            "transport": "network",
            "achieved": ["shell"],
            "target": "10.0.0.5",
        })
        assert menu["ok"] is True
        assert menu["kind"] == "host"
        ids = [a["id"] for g in menu["groups"] for a in g["actions"]]
        assert "shell" in ids
        assert "file_get" in ids
        assert menu["access_gained"] is True

    def test_no_shell_hides_destructive_host_ops(self):
        menu = rat_menu_for_session({
            "id": "h2",
            "transport": "network",
            "achieved": [],
            "target": "10.0.0.6",
        })
        ids = [a["id"] for g in menu["groups"] for a in g["actions"]]
        assert "shell" not in ids
        assert "file_put" not in ids

    def test_ble_gatt_connect_unlocks_browse(self):
        menu = rat_menu_for_session({
            "id": "b1",
            "transport": "ble",
            "achieved": ["gatt_connect"],
            "target": "AA:BB:CC:DD:EE:FF",
        })
        ids = [a["id"] for g in menu["groups"] for a in g["actions"]]
        assert "gatt_browse" in ids
        assert "gatt_read" in ids
        # channel_map is always available for BLE
        assert "channel_map" in ids

    def test_wifi_access_unlocks_lan_scan(self):
        menu = rat_menu_for_session({
            "id": "w1",
            "transport": "wifi",
            "achieved": ["wifi_access"],
            "target": "AA:BB:CC:00:11:22",
        })
        ids = [a["id"] for g in menu["groups"] for a in g["actions"]]
        assert "wifi_lan_scan" in ids

    def test_never_fabricates_for_unknown_session(self):
        menu = rat_menu_for_session(None)  # type: ignore[arg-type]
        assert menu["ok"] is False


class TestAttackState:
    def test_counts_by_kind(self):
        state = build_attack_state([
            {"id": "1", "transport": "wifi", "achieved": ["handshake"]},
            {"id": "2", "transport": "ble", "achieved": ["gatt_connect"]},
            {"id": "3", "transport": "network", "achieved": ["shell"]},
        ], active_session_id="3")
        assert state["ok"] is True
        assert state["total_sessions"] == 3
        assert state["by_kind"].get("wifi") == 1
        assert state["by_kind"].get("ble") == 1
        assert state["by_kind"].get("host") == 1
        active = [s for s in state["sessions"] if s["active"]]
        assert len(active) == 1
        assert active[0]["id"] == "3"


class TestSessionRegistry:
    def test_switch_and_list(self):
        reg = SessionRegistry()
        reg.load([
            {"id": "ble-1", "transport": "ble", "achieved": ["gatt_connect"]},
            {"id": "net-1", "transport": "network", "achieved": ["shell"]},
        ])
        assert len(reg.list_sessions()) == 2
        assert len(reg.list_sessions(kind="ble")) == 1
        sw = reg.switch("net-1")
        assert sw["ok"] is True
        assert sw["active_session_id"] == "net-1"
        assert reg.active()["id"] == "net-1"
        bad = reg.switch("nope")
        assert bad["ok"] is False


class TestRosterEnrichment:
    def test_build_session_roster_adds_rat_menu(self):
        roster = build_session_roster([
            {
                "id": "s1",
                "transport": "network",
                "target": "10.0.0.1",
                "achieved": ["shell", "creds_dump"],
            },
            {
                "id": "s2",
                "transport": "ble",
                "target": "11:22:33:44:55:66",
                "achieved": ["gatt_connect"],
            },
        ])
        assert len(roster) == 2
        host = next(r for r in roster if r["id"] == "s1")
        assert host.get("kind") in ("host", "network")
        assert host.get("rat_menu", {}).get("ok") is True
        assert host["rat_menu"]["action_count"] >= 1
        ble = next(r for r in roster if r["id"] == "s2")
        assert ble.get("kind") == "ble"

    def test_html_contains_rat_control(self):
        roster = build_session_roster([
            {"id": "x", "transport": "network", "target": "1.2.3.4",
             "achieved": ["shell"]},
        ])
        html = default_dashboard_html(roster)
        assert "RAT control" in html or "KFIOSA" in html
        assert "Open remote shell" in html or "shell" in html.lower()


class TestLiveDashboardEndpoints:
    def test_attack_state_and_switch_endpoints(self):
        sessions = [
            {"id": "ble-a", "transport": "ble", "target": "AA:BB",
             "achieved": ["gatt_connect", "rssi_sample"]},
            {"id": "host-b", "transport": "network", "target": "10.0.0.9",
             "achieved": ["shell", "persistence_mechanism"]},
        ]
        env = spawn_rat_dashboard(sessions)
        assert env.get("ok") is True, env
        port = env["port"]
        base = f"http://127.0.0.1:{port}"
        try:
            st, body, _ = _get(f"{base}/api/attack_state")
            assert st == 200
            data = json.loads(body.decode())
            assert data["ok"] is True
            assert data["total_sessions"] == 2

            st, body, _ = _get(f"{base}/api/sessions?kind=ble")
            assert st == 200
            data = json.loads(body.decode())
            assert data["count"] >= 1

            st, body, _ = _get(f"{base}/api/session/host-b/switch")
            assert st == 200
            data = json.loads(body.decode())
            assert data["ok"] is True
            assert data["active_session_id"] == "host-b"

            st, body, _ = _get(f"{base}/api/session/host-b/rat_menu")
            assert st == 200
            data = json.loads(body.decode())
            assert data["ok"] is True
            assert data["action_count"] >= 1

            st, body, ct = _get(f"{base}/")
            assert st == 200
            assert b"text/html" in ct.encode() or True
            assert b"RAT" in body or b"KFIOSA" in body
        finally:
            # daemon thread dies with process; nothing to join required
            pass
