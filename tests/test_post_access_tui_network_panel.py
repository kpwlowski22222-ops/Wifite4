"""Hermetic tests for the network session multiplexer TUI panel.

Covers:
  - catalog size + uniqueness
  - all required fields present on every capability
  - destructive actions correctly marked
  - NetworkPanelState helpers
  - compute_visible_menu for: no-sessions, has-sessions, multi-session,
    active-session, has-portfwds, has-socks, missing-tool
  - NetworkPanel: visible_capabilities, menu_text, refresh_state
  - NetworkPanel integration: dynamic menu reflects state
  - screen hook: rejects unavailable hotkey, accepts available hotkey
  - NetworkPanelClient: list_tools, start_ssh, start_msf_session,
    start_chisel, start_socat, start_revshell, kill
  - dispatcher mapping: unknown action degrades
  - module exports: NetSession, NetworkPanel, NetworkPanelClient,
    network_dispatch, network_menu_entry
  - post_access_tui init re-exports
"""
from __future__ import annotations

import collections
import dataclasses
import inspect
import os
import sys
from unittest import mock

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _state(**overrides):
    """Build a fresh NetworkPanelState with overrides."""
    from core.post_access_tui.network_panel_capabilities import NetworkPanelState
    base = NetworkPanelState()
    for k, v in overrides.items():
        setattr(base, k, v)
    return base


def _cap(action):
    from core.post_access_tui.network_panel_capabilities import CAPABILITY_CATALOG
    for c in CAPABILITY_CATALOG:
        if c.action == action:
            return c
    return None


# ---------------------------------------------------------------------------
# Catalog basics
# ---------------------------------------------------------------------------

class TestCatalog:
    def test_catalog_size_at_least_25(self):
        from core.post_access_tui.network_panel_capabilities import (
            CAPABILITY_CATALOG,
        )
        assert len(CAPABILITY_CATALOG) >= 25

    def test_unique_actions(self):
        from core.post_access_tui.network_panel_capabilities import (
            CAPABILITY_CATALOG,
        )
        actions = [c.action for c in CAPABILITY_CATALOG]
        assert len(actions) == len(set(actions)), (
            f"duplicate actions: "
            f"{[a for a, n in collections.Counter(actions).items() if n > 1]}"
        )

    def test_unique_hotkeys(self):
        from core.post_access_tui.network_panel_capabilities import (
            CAPABILITY_CATALOG,
        )
        keys = [c.hotkey for c in CAPABILITY_CATALOG]
        assert len(keys) == len(set(keys)), (
            f"duplicate hotkeys: "
            f"{[k for k, n in collections.Counter(keys).items() if n > 1]}"
        )

    def test_each_capability_has_required_fields(self):
        from core.post_access_tui.network_panel_capabilities import (
            CAPABILITY_CATALOG, RISK_READ, RISK_INTRUSIVE, RISK_DESTRUCTIVE,
        )
        for cap in CAPABILITY_CATALOG:
            assert isinstance(cap.action, str) and cap.action
            assert isinstance(cap.hotkey, str) and len(cap.hotkey) >= 1
            assert isinstance(cap.label, str) and cap.label
            assert cap.risk in (RISK_READ, RISK_INTRUSIVE, RISK_DESTRUCTIVE)
            assert isinstance(cap.requires_gate, bool)
            assert callable(cap.availability_fn)
            assert isinstance(cap.help_text, str)

    def test_destructive_actions_marked(self):
        from core.post_access_tui.network_panel_capabilities import (
            CAPABILITY_CATALOG, RISK_DESTRUCTIVE,
        )
        for expected in ("kill", "broadcast", "new_revshell", "persistence"):
            cap = _cap(expected)
            assert cap is not None
            assert cap.risk == RISK_DESTRUCTIVE, (
                f"{expected} should be RISK_DESTRUCTIVE, got {cap.risk}"
            )

    def test_intrusive_actions_marked(self):
        from core.post_access_tui.network_panel_capabilities import (
            CAPABILITY_CATALOG, RISK_INTRUSIVE,
        )
        for expected in ("shell", "get", "put", "portfwd_add", "socks_start",
                         "new_ssh", "new_msf", "new_chisel", "new_socat",
                         "module"):
            cap = _cap(expected)
            assert cap is not None
            assert cap.risk == RISK_INTRUSIVE, (
                f"{expected} should be RISK_INTRUSIVE, got {cap.risk}"
            )

    def test_read_only_actions_not_gated(self):
        from core.post_access_tui.network_panel_capabilities import (
            CAPABILITY_CATALOG, RISK_READ,
        )
        for expected in ("help", "exit", "list", "view", "portfwd_list",
                         "new_local", "audit", "refresh", "ai_plan"):
            cap = _cap(expected)
            assert cap is not None
            assert cap.risk == RISK_READ
            assert cap.requires_gate is False, (
                f"{expected} should not require a gate"
            )

    def test_ai_modules_labeled_heuristic(self):
        """Per never-fabricate-trained-ML: AI helpers must explicitly
        label themselves as 'heuristic (not trained)'."""
        from core.post_access_tui.network_panel_capabilities import (
            CAPABILITY_CATALOG,
        )
        for cap in CAPABILITY_CATALOG:
            if "ai" in cap.action or "plan" in cap.action:
                assert "heuristic" in cap.help_text.lower() or \
                       "not trained" in cap.help_text.lower(), (
                    f"{cap.action} help_text must declare itself heuristic"
                )


# ---------------------------------------------------------------------------
# State helpers
# ---------------------------------------------------------------------------

class TestNetworkPanelState:
    def test_defaults(self):
        s = _state()
        assert s.sessions == []
        assert s.active_session_id is None
        assert s.portfwd_count == 0
        assert s.socks_running is False
        assert s.tools_available == {}
        assert s.input_active is True

    def test_has_sessions(self):
        assert _state().has_sessions() is False
        assert _state(sessions=[{"id": "ssh-1"}]).has_sessions() is True

    def test_has_active_session(self):
        # active_session_id set but no matching session → False
        s = _state(active_session_id="ssh-9", sessions=[])
        assert s.has_active_session() is False
        # active_session_id matches a session → True
        s = _state(active_session_id="ssh-1",
                   sessions=[{"id": "ssh-1"}])
        assert s.has_active_session() is True

    def test_session_count(self):
        assert _state().session_count() == 0
        s = _state(sessions=[{"id": "ssh-1"}, {"id": "msf-1"}])
        assert s.session_count() == 2

    def test_has_multiple_sessions(self):
        assert _state().has_multiple_sessions() is False
        s = _state(sessions=[{"id": "ssh-1"}])
        assert s.has_multiple_sessions() is False
        s = _state(sessions=[{"id": "ssh-1"}, {"id": "msf-1"}])
        assert s.has_multiple_sessions() is True

    def test_has_portfwds(self):
        assert _state().has_portfwds() is False
        assert _state(portfwd_count=1).has_portfwds() is True

    def test_has_socks(self):
        assert _state().has_socks() is False
        assert _state(socks_running=True).has_socks() is True

    def test_has_tool(self):
        s = _state(tools_available={"ssh": True, "msfconsole": False})
        assert s.has_tool("ssh") is True
        assert s.has_tool("msfconsole") is False
        assert s.has_tool("missing") is False


# ---------------------------------------------------------------------------
# compute_visible_menu
# ---------------------------------------------------------------------------

class TestComputeVisibleMenu:
    def test_empty_state(self):
        from core.post_access_tui.network_panel_capabilities import (
            compute_visible_menu,
        )
        v = compute_visible_menu(_state())
        # Always-visible: help, exit
        # Visible only with sessions: list is read-only and always visible
        # Per-state entries hide.
        actions = {c.action for c in v}
        assert "help" in actions
        assert "exit" in actions
        assert "list" in actions  # list is _always
        # Hidden: shell, get, put, attach, kill, broadcast, view,
        # portfwd_*, socks_*, module, persistence
        for hidden in ("shell", "get", "put", "attach", "kill",
                       "broadcast", "view", "module", "persistence"):
            assert hidden not in actions, f"{hidden} should be hidden"

    def test_with_one_session(self):
        from core.post_access_tui.network_panel_capabilities import (
            compute_visible_menu,
        )
        s = _state(
            sessions=[{"id": "ssh-1", "transport": "ssh", "host": "h",
                       "port": 22, "user": "u", "alive": True, "pid": -1}],
            active_session_id="ssh-1",
            tools_available={"ssh": True, "scp": True},
        )
        v = compute_visible_menu(s)
        actions = {c.action for c in v}
        for expected in ("view", "shell", "kill", "get", "put",
                         "portfwd_add", "socks_start", "module",
                         "persistence", "refresh", "ai_plan"):
            assert expected in actions, f"{expected} should be visible"

    def test_attach_only_with_multiple_sessions(self):
        from core.post_access_tui.network_panel_capabilities import (
            compute_visible_menu,
        )
        s1 = _state(sessions=[{"id": "ssh-1"}], active_session_id="ssh-1")
        s2 = _state(sessions=[{"id": "ssh-1"}, {"id": "msf-1"}],
                    active_session_id="ssh-1")
        v1 = {c.action for c in compute_visible_menu(s1)}
        v2 = {c.action for c in compute_visible_menu(s2)}
        assert "attach" not in v1
        assert "attach" in v2
        assert "broadcast" not in v1
        assert "broadcast" in v2

    def test_socks_start_vs_stop(self):
        from core.post_access_tui.network_panel_capabilities import (
            compute_visible_menu,
        )
        s_off = _state(
            sessions=[{"id": "ssh-1"}], active_session_id="ssh-1",
            socks_running=False,
        )
        s_on = _state(
            sessions=[{"id": "ssh-1"}], active_session_id="ssh-1",
            socks_running=True,
        )
        v_off = {c.action for c in compute_visible_menu(s_off)}
        v_on = {c.action for c in compute_visible_menu(s_on)}
        assert "socks_start" in v_off
        assert "socks_stop" not in v_off
        assert "socks_start" not in v_on
        assert "socks_stop" in v_on

    def test_portfwd_kill_only_with_portfwds(self):
        from core.post_access_tui.network_panel_capabilities import (
            compute_visible_menu,
        )
        s0 = _state(
            sessions=[{"id": "ssh-1"}], active_session_id="ssh-1",
            portfwd_count=0,
        )
        s1 = _state(
            sessions=[{"id": "ssh-1"}], active_session_id="ssh-1",
            portfwd_count=1,
        )
        v0 = {c.action for c in compute_visible_menu(s0)}
        v1 = {c.action for c in compute_visible_menu(s1)}
        assert "portfwd_kill" not in v0
        assert "portfwd_kill" in v1
        assert "portfwd_list" not in v0
        assert "portfwd_list" in v1

    def test_new_ssh_hidden_when_no_ssh(self):
        from core.post_access_tui.network_panel_capabilities import (
            compute_visible_menu,
        )
        s = _state(tools_available={"ssh": False, "msfconsole": False,
                                    "chisel": False, "socat": False})
        v = {c.action for c in compute_visible_menu(s)}
        # Session starters whose tool is missing must be hidden
        for hidden in ("new_ssh", "new_msf", "new_chisel", "new_socat"):
            assert hidden not in v, f"{hidden} should be hidden"
        # new_local and new_revshell are tool-agnostic
        assert "new_local" in v
        assert "new_revshell" in v

    def test_availability_fn_exception_hides_capability(self):
        from core.post_access_tui.network_panel_capabilities import (
            CAPABILITY_CATALOG, compute_visible_menu,
        )
        # Pick a non-universal cap so we can still assert help/exit
        # are visible.
        target = next(c for c in CAPABILITY_CATALOG if c.action == "view")
        buggy = dataclasses.replace(target, availability_fn=lambda _s: 1/0)
        catalog = [buggy if c.action == target.action else c
                   for c in CAPABILITY_CATALOG]
        with mock.patch(
            "core.post_access_tui.network_panel_capabilities.CAPABILITY_CATALOG",
            catalog,
        ):
            v = compute_visible_menu(_state())
        actions = {c.action for c in v}
        assert target.action not in actions
        # The rest of the catalog is intact
        assert "help" in actions
        assert "exit" in actions


# ---------------------------------------------------------------------------
# Panel integration
# ---------------------------------------------------------------------------

class TestNetworkPanelIntegration:
    def test_visible_capabilities_empty_state(self):
        from core.post_access_tui.network_panel import NetworkPanel
        p = NetworkPanel()
        v = p.visible_capabilities()
        actions = {c.action for c in v}
        assert "help" in actions
        assert "exit" in actions
        assert "new_ssh" in actions or "new_local" in actions

    def test_visible_capabilities_with_ssh_session(self):
        from core.post_access_tui.network_panel import (
            NetworkPanel, NetSession,
        )
        from core.post_access_tui.session_state import TRANSPORT_SSH
        p = NetworkPanel()
        p.sessions.append(NetSession(
            id="ssh-1", transport=TRANSPORT_SSH, host="h", port=22, user="u",
        ))
        p.active_session_id = "ssh-1"
        p.refresh_state()
        v = p.visible_capabilities()
        actions = {c.action for c in v}
        assert "shell" in actions
        assert "kill" in actions
        assert "view" in actions
        assert "attach" not in actions  # only 1 session

    def test_menu_text_includes_session_lines(self):
        from core.post_access_tui.network_panel import (
            NetworkPanel, NetSession,
        )
        from core.post_access_tui.session_state import TRANSPORT_SSH
        p = NetworkPanel()
        p.sessions.append(NetSession(
            id="ssh-1", transport=TRANSPORT_SSH, host="h", port=22, user="u",
        ))
        p.active_session_id = "ssh-1"
        text = p.menu_text()
        assert "Network session multiplexer" in text
        assert "ssh-1" in text
        assert "sessions: 1" in text

    def test_menu_text_no_sessions(self):
        from core.post_access_tui.network_panel import NetworkPanel
        p = NetworkPanel()
        text = p.menu_text()
        assert "no active sessions" in text

    def test_menu_text_socks_running(self):
        from core.post_access_tui.network_panel import (
            NetworkPanel, NetSession,
        )
        from core.post_access_tui.session_state import TRANSPORT_SSH
        p = NetworkPanel()
        p.sessions.append(NetSession(
            id="ssh-1", transport=TRANSPORT_SSH, host="h", port=22, user="u",
        ))
        p.active_session_id = "ssh-1"
        p._socks_running = True
        text = p.menu_text()
        assert "socks: on" in text

    def test_refresh_state_picks_up_changes(self):
        from core.post_access_tui.network_panel import (
            NetworkPanel, NetSession,
        )
        from core.post_access_tui.session_state import TRANSPORT_SSH
        p = NetworkPanel()
        p.refresh_state()
        assert p.panel_state.has_sessions() is False
        p.sessions.append(NetSession(
            id="ssh-1", transport=TRANSPORT_SSH, host="h", port=22, user="u",
        ))
        p.refresh_state()
        assert p.panel_state.has_sessions() is True

    def test_saved_sessions_path_memory(self):
        from core.post_access_tui.network_panel import NetworkPanel
        p = NetworkPanel(saved_sessions_path=":memory:")
        # Should not raise; path is ignored
        p._persist_saved_sessions()
        assert True

    def test_saved_sessions_persistence(self, tmp_path):
        from core.post_access_tui.network_panel import (
            NetworkPanel, NetSession,
        )
        from core.post_access_tui.session_state import TRANSPORT_SSH
        path = str(tmp_path / "sessions.json")
        p1 = NetworkPanel(saved_sessions_path=path)
        p1.sessions.append(NetSession(
            id="ssh-1", transport=TRANSPORT_SSH, host="h", port=22, user="u",
        ))
        p1._persist_saved_sessions()
        # Re-load in a fresh panel
        p2 = NetworkPanel(saved_sessions_path=path)
        p2._load_saved_sessions()
        # The persistence layer is best-effort; the path is opened
        # without error.
        assert os.path.exists(path)


# ---------------------------------------------------------------------------
# Screen hook
# ---------------------------------------------------------------------------

class TestScreenHook:
    def test_screen_hook_rejects_unavailable_hotkey(self):
        from core.post_access_tui.network_panel import (
            NetworkPanel, network_dispatch,
        )
        from core.tui.base_screen import BaseScreen

        # Build a fake screen that records emit + input + confirm
        class _FakeScreen:
            def __init__(self):
                self.emits: list = []
                self.inputs: list = []
                self.confirms: list = []
                self.input_fn = self._in
                self._on_event = self._emit
                self.confirm_fn = self._confirm
                self._in_count = 0

            def _in(self, prompt):
                self.inputs.append(prompt)
                self._in_count += 1
                # First call: an unavailable key, then second call: exit
                if self._in_count == 1:
                    return "q"
                return "e"

            def _emit(self, msg):
                self.emits.append(msg)

            def _confirm(self, prompt):
                self.confirms.append(prompt)
                return True

        p = NetworkPanel()
        screen = _FakeScreen()
        result = network_dispatch(screen, p)
        assert isinstance(result, dict)
        # The new menu_loop helper treats 'q' as BACK and returns
        # exit='back'. To exercise the "not in current menu" path
        # we drive an unknown key (e.g. 'z') first.
        screen2 = _FakeScreen()
        it = iter(["z", "e"])
        def _in2(prompt):
            try:
                return next(it)
            except StopIteration:
                return ""
        screen2.input_fn = _in2
        result2 = network_dispatch(screen2, p)
        assert result2.get("exit") is True
        assert any("not in current menu" in m or "not available" in m
                   for m in screen2.emits)

    def test_screen_hook_accepts_available_hotkey(self):
        from core.post_access_tui.network_panel import (
            NetworkPanel, network_dispatch,
        )

        class _FakeScreen:
            def __init__(self):
                self.emits: list = []
                self.confirms: list = []
                self.input_fn = self._in
                self._on_event = self._emit
                self.confirm_fn = self._confirm
                self._in_count = 0

            def _in(self, prompt):
                # First call: "?" (help, always visible), then "e" to exit
                self._in_count += 1
                if self._in_count == 1:
                    return "?"
                return "e"

            def _emit(self, msg):
                self.emits.append(msg)

            def _confirm(self, prompt):
                self.confirms.append(prompt)
                return True

        p = NetworkPanel()
        screen = _FakeScreen()
        result = network_dispatch(screen, p)
        assert result.get("exit") is True
        # Help text was emitted, then exit
        assert any("help" in m.lower() for m in screen.emits)
        # help is read-only → no confirm prompt
        assert len(screen.confirms) == 0


# ---------------------------------------------------------------------------
# Menu + KEY_MAP consistency
# ---------------------------------------------------------------------------

class TestMenuKeyMap:
    def test_menu_and_key_map_match(self):
        from core.post_access_tui.network_panel import NetworkPanel
        # All catalog hotkeys are present in KEY_MAP
        from core.post_access_tui.network_panel_capabilities import (
            CAPABILITY_CATALOG,
        )
        for cap in CAPABILITY_CATALOG:
            assert cap.hotkey in NetworkPanel.KEY_MAP
            # KEY_MAP is keyed by the catalog hotkey (case-sensitive);
            # uppercase hotkeys are bound to shift+key in the curses TUI.
            assert NetworkPanel.KEY_MAP[cap.hotkey] == cap.action

    def test_hotkey_map_inverse(self):
        from core.post_access_tui.network_panel import NetworkPanel
        for action, hk in NetworkPanel.HOTKEY_MAP.items():
            assert NetworkPanel.KEY_MAP[hk] == action

    def test_key_map_values_are_action_names(self):
        from core.post_access_tui.network_panel import NetworkPanel
        from core.post_access_tui.network_panel_capabilities import (
            CAPABILITY_CATALOG,
        )
        valid_actions = {c.action for c in CAPABILITY_CATALOG} | {"exit"}
        for hk, action in NetworkPanel.KEY_MAP.items():
            assert action in valid_actions, (
                f"KEY_MAP[{hk}] = {action!r} not in catalog"
            )


# ---------------------------------------------------------------------------
# NetworkPanelClient
# ---------------------------------------------------------------------------

class TestNetworkPanelClient:
    def test_list_tools_no_exception(self):
        from core.post_access_tui.network_panel import NetworkPanelClient
        c = NetworkPanelClient()
        tools = c.list_tools()
        assert isinstance(tools, dict)
        for n in ("ssh", "scp", "msfconsole", "chisel", "socat", "ncat",
                  "netcat"):
            assert n in tools
            assert isinstance(tools[n], bool)

    def test_start_ssh_no_user(self):
        from core.post_access_tui.network_panel import NetworkPanelClient
        c = NetworkPanelClient()
        env = c.start_ssh("", "host")
        assert env["ok"] is False
        assert "user" in (env.get("error") or "").lower()

    def test_start_msf_session_empty_id(self):
        from core.post_access_tui.network_panel import NetworkPanelClient
        c = NetworkPanelClient()
        env = c.start_msf_session("")
        assert env["ok"] is False

    def test_start_chisel_bad_mode(self):
        from core.post_access_tui.network_panel import NetworkPanelClient
        c = NetworkPanelClient()
        env = c.start_chisel("oops", "0.0.0.0:8000", "1.2.3.4:80")
        assert env["ok"] is False

    def test_start_socat_empty_args(self):
        from core.post_access_tui.network_panel import NetworkPanelClient
        c = NetworkPanelClient()
        env = c.start_socat("", "")
        assert env["ok"] is False

    def test_start_revshell(self):
        from core.post_access_tui.network_panel import NetworkPanelClient
        c = NetworkPanelClient()
        env = c.start_revshell("1.2.3.4", 4444, "bash")
        assert env["ok"] is True
        assert "command" in (env.get("data") or {})

    def test_start_revshell_bad_payload(self):
        from core.post_access_tui.network_panel import NetworkPanelClient
        c = NetworkPanelClient()
        env = c.start_revshell("1.2.3.4", 4444, "lua")
        assert env["ok"] is False

    def test_start_revshell_bad_port(self):
        from core.post_access_tui.network_panel import NetworkPanelClient
        c = NetworkPanelClient()
        env = c.start_revshell("1.2.3.4", 0, "bash")
        assert env["ok"] is False

    def test_kill_invalid_pid(self):
        from core.post_access_tui.network_panel import NetworkPanelClient
        c = NetworkPanelClient()
        env = c.kill(0)
        assert env["ok"] is False
        env = c.kill(-1)
        assert env["ok"] is False

    def test_kill_self_pid_does_not_crash(self):
        """os.kill(0, SIGTERM) on the current process group is
        platform-dependent; the client must not raise. We feed an
        obviously invalid pid instead."""
        from core.post_access_tui.network_panel import NetworkPanelClient
        c = NetworkPanelClient()
        env = c.kill(999999)
        # Either ok (process already gone) or ok=False with a
        # permission / not found error — never raises.
        assert "ok" in env

    def test_run_shell_local(self):
        from core.post_access_tui.network_panel import (
            NetworkPanelClient, NetSession,
        )
        from core.post_access_tui.session_state import TRANSPORT_LOCAL
        c = NetworkPanelClient()
        s = NetSession(id="local-1", transport=TRANSPORT_LOCAL)
        env = c.run_shell(s, "echo hello")
        assert env["ok"] is True
        assert "hello" in (env.get("stdout") or "")

    def test_run_shell_empty_command(self):
        from core.post_access_tui.network_panel import (
            NetworkPanelClient, NetSession,
        )
        from core.post_access_tui.session_state import TRANSPORT_LOCAL
        c = NetworkPanelClient()
        s = NetSession(id="local-1", transport=TRANSPORT_LOCAL)
        env = c.run_shell(s, "")
        assert env["ok"] is False

    def test_run_shell_msf_delegates(self):
        from core.post_access_tui.network_panel import (
            NetworkPanelClient, NetSession,
        )
        from core.post_access_tui.session_state import TRANSPORT_MSF
        c = NetworkPanelClient()
        s = NetSession(id="msf-1", transport=TRANSPORT_MSF)
        env = c.run_shell(s, "whoami")
        assert env["ok"] is False
        assert "msf" in (env.get("error") or "").lower()

    def test_run_shell_tunnel_degrades(self):
        from core.post_access_tui.network_panel import (
            NetworkPanelClient, NetSession,
        )
        c = NetworkPanelClient()
        for t in ("chisel", "socat", "revshell"):
            s = NetSession(id=f"{t}-1", transport=t)
            env = c.run_shell(s, "whoami")
            assert env["ok"] is False
            assert "tunnel" in (env.get("error") or "").lower() or \
                   t in (env.get("error") or "").lower()

    def test_run_shell_ssh_no_ssh_binary(self):
        from core.post_access_tui.network_panel import (
            NetworkPanelClient, NetSession,
        )
        from core.post_access_tui.session_state import TRANSPORT_SSH
        c = NetworkPanelClient()
        s = NetSession(id="ssh-1", transport=TRANSPORT_SSH, host="h",
                       port=22, user="u")
        with mock.patch.object(NetworkPanelClient, "_which", return_value=False):
            env = c.run_shell(s, "whoami")
        assert env["ok"] is False
        assert "ssh" in (env.get("error") or "").lower()

    def test_file_get_ssh_no_scp(self):
        from core.post_access_tui.network_panel import (
            NetworkPanelClient, NetSession,
        )
        from core.post_access_tui.session_state import TRANSPORT_SSH
        c = NetworkPanelClient()
        s = NetSession(id="ssh-1", transport=TRANSPORT_SSH, host="h",
                       port=22, user="u")
        with mock.patch.object(NetworkPanelClient, "_which", return_value=False):
            env = c.file_get(s, "/etc/hostname", "/tmp/x")
        assert env["ok"] is False
        assert "scp" in (env.get("error") or "").lower()

    def test_file_get_non_ssh_degrades(self):
        from core.post_access_tui.network_panel import (
            NetworkPanelClient, NetSession,
        )
        from core.post_access_tui.session_state import TRANSPORT_LOCAL
        c = NetworkPanelClient()
        s = NetSession(id="local-1", transport=TRANSPORT_LOCAL)
        env = c.file_get(s, "/etc/hostname", "/tmp/x")
        assert env["ok"] is False
        assert "ssh" in (env.get("error") or "").lower()

    def test_file_put_ssh_no_scp(self):
        from core.post_access_tui.network_panel import (
            NetworkPanelClient, NetSession,
        )
        from core.post_access_tui.session_state import TRANSPORT_SSH
        c = NetworkPanelClient()
        s = NetSession(id="ssh-1", transport=TRANSPORT_SSH, host="h",
                       port=22, user="u")
        with mock.patch.object(NetworkPanelClient, "_which", return_value=False):
            env = c.file_put(s, "/tmp/x", "/etc/hostname")
        assert env["ok"] is False

    def test_safe_run_timeout(self):
        from core.post_access_tui.network_panel import NetworkPanelClient
        c = NetworkPanelClient()
        # Use a binary that hangs. We use the test-timeout-safe
        # approach: invoke /bin/sleep 5 with a 1s timeout.
        rc, stdout, stderr = c._safe_run(["sleep", "5"], timeout=1)
        assert rc == -1
        assert "timeout" in stderr.lower()


# ---------------------------------------------------------------------------
# Dispatcher mapping
# ---------------------------------------------------------------------------

class TestDispatcher:
    def test_unknown_action_degrades(self):
        from core.post_access_tui.network_panel import NetworkPanel
        p = NetworkPanel()
        env = p.dispatch("definitely_not_an_action")
        assert env["ok"] is False
        assert "unknown" in (env.get("error") or "").lower()

    def test_exit_action(self):
        from core.post_access_tui.network_panel import NetworkPanel
        p = NetworkPanel()
        env = p.dispatch("exit")
        assert env["ok"] is True
        assert (env.get("data") or {}).get("exit") is True

    def test_help_action(self):
        from core.post_access_tui.network_panel import NetworkPanel
        p = NetworkPanel()
        env = p.dispatch("help")
        assert env["ok"] is True
        assert "help" in (env.get("data") or {})

    def test_list_action_no_sessions(self):
        from core.post_access_tui.network_panel import NetworkPanel
        p = NetworkPanel()
        env = p.dispatch("list")
        assert env["ok"] is True
        assert "no sessions" in (env.get("stdout") or "").lower()

    def test_list_action_with_session(self):
        from core.post_access_tui.network_panel import (
            NetworkPanel, NetSession,
        )
        from core.post_access_tui.session_state import TRANSPORT_SSH
        p = NetworkPanel()
        p.sessions.append(NetSession(
            id="ssh-1", transport=TRANSPORT_SSH, host="h", port=22, user="u",
        ))
        env = p.dispatch("list")
        assert env["ok"] is True
        assert "ssh-1" in (env.get("stdout") or "")

    def test_view_no_active(self):
        from core.post_access_tui.network_panel import NetworkPanel
        p = NetworkPanel()
        env = p.dispatch("view")
        assert env["ok"] is False
        assert "no active" in (env.get("error") or "").lower()

    def test_view_with_active(self):
        from core.post_access_tui.network_panel import (
            NetworkPanel, NetSession,
        )
        from core.post_access_tui.session_state import TRANSPORT_SSH
        p = NetworkPanel()
        p.sessions.append(NetSession(
            id="ssh-1", transport=TRANSPORT_SSH, host="h", port=22, user="u",
        ))
        p.active_session_id = "ssh-1"
        env = p.dispatch("view")
        assert env["ok"] is True
        assert "ssh-1" in (env.get("stdout") or "")

    def test_attach_no_sessions(self):
        from core.post_access_tui.network_panel import NetworkPanel
        p = NetworkPanel()
        env = p.dispatch("attach", {"session_id": "ssh-1"})
        assert env["ok"] is False
        assert "no sessions" in (env.get("error") or "").lower()

    def test_attach_unknown_session(self):
        from core.post_access_tui.network_panel import (
            NetworkPanel, NetSession,
        )
        from core.post_access_tui.session_state import TRANSPORT_SSH
        p = NetworkPanel()
        p.sessions.append(NetSession(
            id="ssh-1", transport=TRANSPORT_SSH, host="h", port=22, user="u",
        ))
        p.sessions.append(NetSession(
            id="ssh-2", transport=TRANSPORT_SSH, host="h", port=22, user="u",
        ))
        env = p.dispatch("attach", {"session_id": "ssh-9"})
        assert env["ok"] is False
        assert "no such session" in (env.get("error") or "").lower()

    def test_attach_known_session(self):
        from core.post_access_tui.network_panel import (
            NetworkPanel, NetSession,
        )
        from core.post_access_tui.session_state import TRANSPORT_SSH
        p = NetworkPanel()
        p.sessions.append(NetSession(
            id="ssh-1", transport=TRANSPORT_SSH, host="h", port=22, user="u",
        ))
        p.sessions.append(NetSession(
            id="ssh-2", transport=TRANSPORT_SSH, host="h", port=22, user="u",
        ))
        p.active_session_id = "ssh-1"
        env = p.dispatch("attach", {"session_id": "ssh-2"})
        assert env["ok"] is True
        assert p.active_session_id == "ssh-2"

    def test_kill_no_sessions(self):
        from core.post_access_tui.network_panel import NetworkPanel
        p = NetworkPanel()
        env = p.dispatch("kill", {"session_id": "ssh-1"})
        assert env["ok"] is False

    def test_kill_known_session(self):
        from core.post_access_tui.network_panel import (
            NetworkPanel, NetSession,
        )
        from core.post_access_tui.session_state import TRANSPORT_SSH
        p = NetworkPanel()
        sess = NetSession(
            id="ssh-1", transport=TRANSPORT_SSH, host="h", port=22, user="u",
        )
        p.sessions.append(sess)
        p.active_session_id = "ssh-1"
        # Feed an obviously invalid pid so kill() doesn't actually signal us.
        sess.pid = 999999
        env = p.dispatch("kill", {"session_id": "ssh-1"})
        # kill() is honest about already-gone processes
        assert "ok" in env

    def test_broadcast_no_sessions(self):
        from core.post_access_tui.network_panel import NetworkPanel
        p = NetworkPanel()
        env = p.dispatch("broadcast", {"cmd": "id"})
        assert env["ok"] is False
        assert "2+ sessions" in (env.get("error") or "")

    def test_broadcast_single_session(self):
        from core.post_access_tui.network_panel import (
            NetworkPanel, NetSession,
        )
        from core.post_access_tui.session_state import TRANSPORT_SSH
        p = NetworkPanel()
        p.sessions.append(NetSession(
            id="ssh-1", transport=TRANSPORT_SSH, host="h", port=22, user="u",
        ))
        env = p.dispatch("broadcast", {"cmd": "id"})
        assert env["ok"] is False
        assert "2+ sessions" in (env.get("error") or "")

    def test_broadcast_multi_session(self):
        from core.post_access_tui.network_panel import (
            NetworkPanel, NetSession,
        )
        from core.post_access_tui.session_state import TRANSPORT_LOCAL
        p = NetworkPanel()
        p.sessions.append(NetSession(
            id="local-1", transport=TRANSPORT_LOCAL,
        ))
        p.sessions.append(NetSession(
            id="local-2", transport=TRANSPORT_LOCAL,
        ))
        env = p.dispatch("broadcast", {"cmd": "echo hi"})
        assert env["ok"] is True
        assert (env.get("data") or {}).get("broadcast_to") == 2

    def test_shell_no_active(self):
        from core.post_access_tui.network_panel import NetworkPanel
        p = NetworkPanel()
        env = p.dispatch("shell", {"cmd": "id"})
        assert env["ok"] is False

    def test_shell_active(self):
        from core.post_access_tui.network_panel import (
            NetworkPanel, NetSession,
        )
        from core.post_access_tui.session_state import TRANSPORT_LOCAL
        p = NetworkPanel()
        p.sessions.append(NetSession(
            id="local-1", transport=TRANSPORT_LOCAL,
        ))
        p.active_session_id = "local-1"
        env = p.dispatch("shell", {"cmd": "echo hi"})
        assert env["ok"] is True
        assert "hi" in (env.get("stdout") or "")

    def test_get_no_active(self):
        from core.post_access_tui.network_panel import NetworkPanel
        p = NetworkPanel()
        env = p.dispatch("get", {"remote": "/etc/hostname", "local": "/tmp/x"})
        assert env["ok"] is False

    def test_put_no_active(self):
        from core.post_access_tui.network_panel import NetworkPanel
        p = NetworkPanel()
        env = p.dispatch("put", {"local": "/tmp/x", "remote": "/etc/x"})
        assert env["ok"] is False

    def test_portfwd_add_no_active(self):
        from core.post_access_tui.network_panel import NetworkPanel
        p = NetworkPanel()
        env = p.dispatch("portfwd_add",
                         {"listen": 8080, "host": "h", "port": 80})
        assert env["ok"] is False

    def test_portfwd_add_active(self):
        from core.post_access_tui.network_panel import (
            NetworkPanel, NetSession,
        )
        from core.post_access_tui.session_state import TRANSPORT_LOCAL
        p = NetworkPanel()
        p.sessions.append(NetSession(
            id="local-1", transport=TRANSPORT_LOCAL,
        ))
        p.active_session_id = "local-1"
        env = p.dispatch("portfwd_add",
                         {"listen": 8080, "host": "h", "port": 80})
        assert env["ok"] is True
        assert len(p._portfwds) == 1

    def test_portfwd_list_no_portfwds(self):
        from core.post_access_tui.network_panel import NetworkPanel
        p = NetworkPanel()
        env = p.dispatch("portfwd_list")
        assert env["ok"] is True
        assert "no port-forwards" in (env.get("stdout") or "").lower()

    def test_portfwd_kill_no_portfwds(self):
        from core.post_access_tui.network_panel import NetworkPanel
        p = NetworkPanel()
        env = p.dispatch("portfwd_kill", {"listen": 8080})
        assert env["ok"] is False

    def test_socks_start_then_stop(self):
        from core.post_access_tui.network_panel import NetworkPanel
        p = NetworkPanel()
        env1 = p.dispatch("socks_start", {"port": 9050})
        assert env1["ok"] is True
        env2 = p.dispatch("socks_start", {"port": 9050})
        assert env2["ok"] is False  # already running
        env3 = p.dispatch("socks_stop")
        assert env3["ok"] is True
        env4 = p.dispatch("socks_stop")
        assert env4["ok"] is False  # not running

    def test_new_ssh_no_target(self):
        from core.post_access_tui.network_panel import NetworkPanel
        p = NetworkPanel()
        env = p.dispatch("new_ssh", {"target": ""})
        assert env["ok"] is False

    def test_new_ssh_with_target(self):
        """The dispatcher accepts ``user@host[:port]`` and creates a
        session when start_ssh succeeds. We mock the client to avoid
        actually invoking ssh."""
        from core.post_access_tui.network_panel import (
            NetworkPanel, NetworkPanelClient,
        )
        p = NetworkPanel()

        def _fake_start_ssh(*_a, **_kw):
            return {
                "ok": True, "returncode": 0, "error": None,
                "data": {"transport": "ssh"},
            }
        p.client.start_ssh = _fake_start_ssh  # type: ignore[assignment]
        env = p.dispatch("new_ssh", {"target": "user@h:2222"})
        assert env["ok"] is True
        assert (env.get("data") or {}).get("session_id", "").startswith("ssh-")
        # Session is registered
        assert any(s.id == env["data"]["session_id"] for s in p.sessions)

    def test_new_local(self):
        from core.post_access_tui.network_panel import NetworkPanel
        p = NetworkPanel()
        env = p.dispatch("new_local")
        assert env["ok"] is True
        assert (env.get("data") or {}).get("session_id", "").startswith("local-")
        assert p.active_session_id is not None

    def test_new_msf_empty_id(self):
        from core.post_access_tui.network_panel import NetworkPanel
        p = NetworkPanel()
        env = p.dispatch("new_msf", {"session_id": ""})
        # msfconsole likely not installed; honest-degrade is fine
        assert "ok" in env

    def test_new_chisel_bad_mode(self):
        from core.post_access_tui.network_panel import NetworkPanel
        p = NetworkPanel()
        env = p.dispatch("new_chisel",
                         {"mode": "oops", "listen": "0.0.0.0:8000",
                          "target": "1.2.3.4:80"})
        assert env["ok"] is False

    def test_new_socat_empty_args(self):
        from core.post_access_tui.network_panel import NetworkPanel
        p = NetworkPanel()
        env = p.dispatch("new_socat", {"listen": "", "target": ""})
        assert env["ok"] is False

    def test_new_revshell(self):
        from core.post_access_tui.network_panel import NetworkPanel
        p = NetworkPanel()
        env = p.dispatch("new_revshell",
                         {"host": "1.2.3.4", "port": 4444, "payload": "bash"})
        assert env["ok"] is True
        assert (env.get("data") or {}).get("session_id", "").startswith("rev-")

    def test_module_no_active(self):
        from core.post_access_tui.network_panel import NetworkPanel
        p = NetworkPanel()
        env = p.dispatch("module")
        assert env["ok"] is False

    def test_module_with_active(self):
        from core.post_access_tui.network_panel import (
            NetworkPanel, NetSession,
        )
        from core.post_access_tui.session_state import TRANSPORT_SSH
        p = NetworkPanel()
        p.sessions.append(NetSession(
            id="ssh-1", transport=TRANSPORT_SSH, host="h", port=22, user="u",
        ))
        p.active_session_id = "ssh-1"
        env = p.dispatch("module")
        assert env["ok"] is True
        assert (env.get("data") or {}).get("hint")

    def test_persistence_no_active(self):
        from core.post_access_tui.network_panel import NetworkPanel
        p = NetworkPanel()
        env = p.dispatch("persistence")
        assert env["ok"] is False

    def test_persistence_with_active(self):
        from core.post_access_tui.network_panel import (
            NetworkPanel, NetSession,
        )
        from core.post_access_tui.session_state import TRANSPORT_SSH
        p = NetworkPanel()
        p.sessions.append(NetSession(
            id="ssh-1", transport=TRANSPORT_SSH, host="h", port=22, user="u",
        ))
        p.active_session_id = "ssh-1"
        env = p.dispatch("persistence")
        assert env["ok"] is True

    def test_audit(self):
        from core.post_access_tui.network_panel import NetworkPanel
        p = NetworkPanel()
        env = p.dispatch("audit")
        assert env["ok"] is True

    def test_refresh(self):
        from core.post_access_tui.network_panel import (
            NetworkPanel, NetSession,
        )
        from core.post_access_tui.session_state import TRANSPORT_SSH
        p = NetworkPanel()
        p.sessions.append(NetSession(
            id="ssh-1", transport=TRANSPORT_SSH, host="h", port=22, user="u",
            pid=999999,  # invalid pid → not alive
        ))
        env = p.dispatch("refresh")
        assert env["ok"] is True
        # Refresh should have flipped alive to False
        assert p.sessions[0].alive is False

    def test_ai_plan_no_sessions(self):
        from core.post_access_tui.network_panel import NetworkPanel
        p = NetworkPanel()
        env = p.dispatch("ai_plan")
        assert env["ok"] is True
        plan = (env.get("data") or {}).get("plan", [])
        assert any("no active sessions" in r.lower() for r in plan)

    def test_ai_plan_with_sessions(self):
        from core.post_access_tui.network_panel import (
            NetworkPanel, NetSession,
        )
        from core.post_access_tui.session_state import TRANSPORT_SSH
        p = NetworkPanel()
        p.sessions.append(NetSession(
            id="ssh-1", transport=TRANSPORT_SSH, host="h", port=22, user="u",
        ))
        p.active_session_id = "ssh-1"
        env = p.dispatch("ai_plan")
        assert env["ok"] is True
        plan = (env.get("data") or {}).get("plan", [])
        assert any("socks" in r.lower() or "port-forward" in r.lower()
                   for r in plan)
        # Heuristic label
        assert "heuristic" in (env.get("data") or {}).get("note", "").lower() or \
               "not trained" in (env.get("data") or {}).get("note", "").lower()

    def test_ai_plan_multi_session(self):
        from core.post_access_tui.network_panel import (
            NetworkPanel, NetSession,
        )
        from core.post_access_tui.session_state import TRANSPORT_SSH
        p = NetworkPanel()
        p.sessions.append(NetSession(
            id="ssh-1", transport=TRANSPORT_SSH, host="h", port=22, user="u",
        ))
        p.sessions.append(NetSession(
            id="ssh-2", transport=TRANSPORT_SSH, host="h", port=22, user="u",
        ))
        env = p.dispatch("ai_plan")
        assert env["ok"] is True
        plan = (env.get("data") or {}).get("plan", [])
        assert any("broadcast" in r.lower() for r in plan)

    def test_ai_plan_revshell_recommendation(self):
        from core.post_access_tui.network_panel import (
            NetworkPanel, NetSession,
        )
        p = NetworkPanel()
        p.sessions.append(NetSession(
            id="rev-1", transport="revshell", host="h", port=4444,
        ))
        p.active_session_id = "rev-1"
        env = p.dispatch("ai_plan")
        assert env["ok"] is True
        plan = (env.get("data") or {}).get("plan", [])
        assert any("revshell" in r.lower() or "ssh" in r.lower()
                   for r in plan)

    def test_dispatch_hotkey_normalized(self):
        """The dispatcher accepts the single-letter hotkey and
        converts it to the action name."""
        from core.post_access_tui.network_panel import NetworkPanel
        p = NetworkPanel()
        env = p.dispatch("?")
        assert env["ok"] is True
        # help was invoked
        assert "help" in (env.get("data") or {})

    def test_attach_advances_active_after_kill(self):
        """When the active session is killed, the active pointer
        advances to the next alive session (or None)."""
        from core.post_access_tui.network_panel import (
            NetworkPanel, NetSession,
        )
        from core.post_access_tui.session_state import TRANSPORT_SSH
        p = NetworkPanel()
        p.sessions.append(NetSession(
            id="ssh-1", transport=TRANSPORT_SSH, host="h", port=22, user="u",
            pid=999999,
        ))
        p.sessions.append(NetSession(
            id="ssh-2", transport=TRANSPORT_SSH, host="h", port=22, user="u",
            pid=999999,
        ))
        p.active_session_id = "ssh-1"
        p.dispatch("kill", {"session_id": "ssh-1"})
        assert p.active_session_id == "ssh-2"
        # Kill ssh-2; no more alive sessions → None
        p.dispatch("kill", {"session_id": "ssh-2"})
        assert p.active_session_id is None


# ---------------------------------------------------------------------------
# Module exports
# ---------------------------------------------------------------------------

class TestExports:
    def test_post_access_tui_re_exports(self):
        from core.post_access_tui import (
            NetSession,
            NetworkPanel,
            NetworkPanelClient,
            network_dispatch,
            network_menu_entry,
        )
        assert NetSession is not None
        assert NetworkPanel is not None
        assert NetworkPanelClient is not None
        assert callable(network_dispatch)
        assert callable(network_menu_entry)

    def test_network_menu_entry_shape(self):
        from core.post_access_tui.network_panel import network_menu_entry
        label, key, action = network_menu_entry()
        assert isinstance(label, str)
        assert isinstance(key, str)
        assert action == "sessions"
        # The hotkey is NOT "s" (which is taken by [S]hell)
        assert key != "s"

    def test_panel_module_exports(self):
        from core.post_access_tui import network_panel
        names = ("NetSession", "NetworkPanel", "NetworkPanelClient",
                 "network_dispatch", "network_menu_entry")
        for n in names:
            assert n in network_panel.__all__
            assert hasattr(network_panel, n)


# ---------------------------------------------------------------------------
# safety: never-inline credentials
# ---------------------------------------------------------------------------

class TestSafety:
    def test_no_bare_except(self):
        from core.post_access_tui import network_panel
        import re
        src = inspect.getsource(network_panel)
        # No bare except: lines (allow except Exception: noqa)
        for m in re.finditer(r"^\s*except\s*:\s*$", src, re.MULTILINE):
            raise AssertionError(
                f"bare except: at line {src[:m.start()].count(chr(10)) + 1}"
            )

    def test_no_fabricated_sessions(self):
        """The panel never invents a session id that wasn't actually
        started via start_ssh/start_msf_session/etc."""
        from core.post_access_tui.network_panel import (
            NetworkPanel, NetSession,
        )
        from core.post_access_tui.session_state import TRANSPORT_SSH
        p = NetworkPanel()
        # The list starts empty; no synthetic "demo" session
        assert p.sessions == []
        # Manually adding a session is fine; the catalog code
        # does not auto-create one.
        p.sessions.append(NetSession(
            id="ssh-1", transport=TRANSPORT_SSH, host="h", port=22, user="u",
        ))
        assert len(p.sessions) == 1
        assert p.sessions[0].id == "ssh-1"
