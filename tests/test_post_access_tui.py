"""Hermetic tests for core.post_access_tui — Phase 6 (post-access external TUI).

Covers:
  - SessionState serialization + helpers
  - PostAccessRunner methods (envelope shape, never raises, honest
    degradation when tools are missing)
  - PostAccessScreen single-gate (every menu action wraps in confirm_fn)
  - Detach is clean (F12 / Esc / x all return; runner is detached)
  - Spawner routes through external_terminal + handles no-real-backend
  - build_argv shape
  - No bare `except:` in any source file

Every test is hermetic: fakes / monkeypatch / input_fn injection.
No real curses, no real ssh, no real msfconsole.
"""
from __future__ import annotations

import base64
import inspect
import json
import re
from pathlib import Path

import pytest


# ---------------------------------------------------------------------------
# SessionState
# ---------------------------------------------------------------------------

class TestSessionState:
    def test_default_construction(self):
        from core.post_access_tui import SessionState
        s = SessionState()
        assert s.session_id is None
        assert s.target == ""
        assert s.creds_b64 == ""
        assert s.transport == "unknown"
        assert s.has_session() is False

    def test_round_trip(self):
        from core.post_access_tui import SessionState
        s = SessionState(
            session_id=7, target="10.0.0.5",
            creds_b64=base64.b64encode(b"p@ss w0rd").decode("ascii"),
            transport="ssh", started_at=1234567890.0,
            note="captured via PMKID on BSSID AA:BB:CC:DD:EE:01",
        )
        d = s.to_dict()
        s2 = SessionState.from_dict(d)
        assert s2.session_id == 7
        assert s2.target == "10.0.0.5"
        assert s2.creds_plain() == "p@ss w0rd"
        assert s2.transport == "ssh"
        assert s2.started_at == 1234567890.0
        assert "PMKID" in s2.note

    def test_has_session_with_sid(self):
        from core.post_access_tui import SessionState
        s = SessionState(session_id=3, transport="msfconsole")
        assert s.has_session() is True

    def test_has_session_with_creds(self):
        from core.post_access_tui import SessionState
        s = SessionState(
            creds_b64=base64.b64encode(b"hunter2").decode("ascii"),
            transport="ssh",
        )
        assert s.has_session() is True
        assert s.creds_plain() == "hunter2"

    def test_from_access_report_with_session_id(self):
        from core.post_access_tui import SessionState
        s = SessionState.from_access_report(
            {"achieved": True, "session_id": 12, "creds": None}
        )
        assert s.session_id == 12
        assert s.transport == "msfconsole"
        assert s.creds_b64 == ""

    def test_from_access_report_with_creds(self):
        from core.post_access_tui import SessionState
        s = SessionState.from_access_report(
            {"achieved": True, "session_id": None, "creds": "letmein"}
        )
        assert s.session_id is None
        assert s.transport == "ssh"
        assert s.creds_plain() == "letmein"

    def test_from_access_report_none(self):
        from core.post_access_tui import SessionState
        assert SessionState.from_access_report(None).has_session() is False
        assert SessionState.from_access_report({}).has_session() is False

    def test_creds_b64_decode_handles_malformed(self):
        from core.post_access_tui import SessionState
        s = SessionState(creds_b64="not-valid-base64-!!!")
        # Should not raise; should return ""
        assert s.creds_plain() == ""

    def test_transport_label(self):
        from core.post_access_tui import SessionState, TRANSPORT_MSF, TRANSPORT_SSH
        assert SessionState(transport=TRANSPORT_MSF).transport_label() == "msfconsole"
        assert SessionState(transport=TRANSPORT_SSH).transport_label() == "ssh"


# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------

class TestAuditLog:
    def test_append_log_does_not_raise(self):
        from core.post_access_tui.session_state import _append_log, get_log
        before = len(get_log())
        _append_log({"event": "test_marker", "x": 1})
        assert len(get_log()) == before + 1

    def test_log_file_is_jsonl(self):
        from core.post_access_tui.session_state import (
            _append_log, get_log_path,
        )
        _append_log({"event": "jsonl_test_post_access", "n": 7})
        text = get_log_path().read_text()
        # The last line with our marker
        last = [ln for ln in text.strip().splitlines()
                if "jsonl_test_post_access" in ln]
        assert last
        parsed = json.loads(last[-1])
        assert parsed["event"] == "jsonl_test_post_access"
        assert parsed["n"] == 7


# ---------------------------------------------------------------------------
# PostAccessRunner
# ---------------------------------------------------------------------------

class TestPostAccessRunner:
    def test_construction_does_not_raise(self):
        from core.post_access_tui import PostAccessRunner, SessionState
        r = PostAccessRunner(state=SessionState(session_id=1, transport="msfconsole"))
        assert r.detached is False
        assert r.list_portfwds() == []

    def test_run_shell_no_session_returns_error(self):
        from core.post_access_tui import PostAccessRunner, SessionState
        r = PostAccessRunner(state=SessionState())
        env = r.run_shell("id")
        assert env["ok"] is False
        assert env["returncode"] == 0  # honest no-op
        assert "no active session" in env["error"] or "no transport" in env["error"]

    def test_run_shell_empty_command(self):
        from core.post_access_tui import PostAccessRunner, SessionState
        r = PostAccessRunner(state=SessionState(session_id=1, transport="msfconsole"))
        env = r.run_shell("   ")
        assert env["ok"] is False
        assert "empty" in env["error"]

    def test_run_shell_local_transport_real_subprocess(self, monkeypatch):
        """With transport=local, we run the command in /bin/sh locally.
        That's intentional (lab testing)."""
        from core.post_access_tui import PostAccessRunner, SessionState
        r = PostAccessRunner(state=SessionState(transport="local"))
        env = r.run_shell("echo hello-from-post-access")
        assert env["ok"] is True
        assert "hello-from-post-access" in env["stdout"]

    def test_run_shell_msf_no_msfconsole(self, monkeypatch):
        """With transport=msf but msfconsole absent, returns ok=False."""
        from core.post_access_tui import PostAccessRunner, SessionState
        import shutil
        monkeypatch.setattr(shutil, "which", lambda t: None)
        r = PostAccessRunner(state=SessionState(session_id=1, transport="msfconsole"))
        env = r.run_shell("id")
        assert env["ok"] is False
        assert "msfconsole" in env["error"] or "no transport" in env["error"]

    def test_run_shell_ssh_no_target(self, monkeypatch):
        from core.post_access_tui import PostAccessRunner, SessionState
        import shutil
        monkeypatch.setattr(shutil, "which",
                            lambda t: "/usr/bin/ssh" if t == "ssh" else None)
        r = PostAccessRunner(state=SessionState(transport="ssh"))
        env = r.run_shell("id")
        assert env["ok"] is False
        assert "target" in env["error"].lower() or "ssh" in env["error"].lower()

    def test_run_shell_ssh_calls_ssh(self, monkeypatch):
        """When ssh is present + target set, build the ssh argv correctly
        (we mock _safe_subprocess to capture the argv)."""
        from core.post_access_tui import PostAccessRunner, SessionState
        import shutil
        monkeypatch.setattr(shutil, "which",
                            lambda t: "/usr/bin/ssh" if t == "ssh" else None)
        r = PostAccessRunner(state=SessionState(
            target="10.0.0.5", transport="ssh",
        ))
        captured = {}
        def fake_safe_subprocess(argv, *, timeout=30, cwd=None):
            captured["argv"] = argv
            return (0, "uid=0(root)\n", "")
        monkeypatch.setattr(
            "core.post_access_tui.runner._safe_subprocess",
            fake_safe_subprocess,
        )
        env = r.run_shell("id")
        assert env["ok"] is True
        assert captured["argv"][0].endswith("ssh")
        # No creds in argv (BatchMode=yes)
        joined = " ".join(captured["argv"])
        assert "BatchMode=yes" in joined
        assert "PasswordAuthentication=no" in joined
        assert "operator@10.0.0.5" in joined
        # No creds leaked
        assert "letmein" not in joined  # the canonical bad cred

    def test_file_get_requires_session(self):
        from core.post_access_tui import PostAccessRunner, SessionState
        r = PostAccessRunner(state=SessionState())
        env = r.file_get("/etc/passwd", "/tmp/out")
        assert env["ok"] is False
        assert "no active session" in env["error"]

    def test_file_get_msf_transport_rejected_honestly(self):
        from core.post_access_tui import PostAccessRunner, SessionState
        r = PostAccessRunner(state=SessionState(
            session_id=1, transport="msfconsole",
        ))
        env = r.file_get("/etc/passwd", "/tmp/out")
        assert env["ok"] is False
        assert "ssh" in env["error"].lower() or "transport" in env["error"].lower()

    def test_file_put_requires_session(self):
        from core.post_access_tui import PostAccessRunner, SessionState
        r = PostAccessRunner(state=SessionState())
        env = r.file_put("/tmp/x", "/tmp/y")
        assert env["ok"] is False

    def test_portfwd_add_invalid_ports(self):
        from core.post_access_tui import PostAccessRunner, SessionState
        import base64
        r = PostAccessRunner(state=SessionState(
            target="10.0.0.5", transport="ssh",
            creds_b64=base64.b64encode(b"hunter2").decode("ascii"),
        ))
        env = r.portfwd_add("not-an-int", "127.0.0.1", 80)
        assert env["ok"] is False
        assert "integer" in env["error"]

    def test_portfwd_add_requires_target_host(self):
        from core.post_access_tui import PostAccessRunner, SessionState
        import base64
        r = PostAccessRunner(state=SessionState(
            target="10.0.0.5", transport="ssh",
            creds_b64=base64.b64encode(b"hunter2").decode("ascii"),
        ))
        env = r.portfwd_add(8080, "", 80)
        assert env["ok"] is False
        assert "target_host" in env["error"]

    def test_portfwd_add_ssh_records_suggestion(self):
        from core.post_access_tui import PostAccessRunner, SessionState
        import base64
        r = PostAccessRunner(state=SessionState(
            target="10.0.0.5", transport="ssh",
            creds_b64=base64.b64encode(b"hunter2").decode("ascii"),
        ))
        env = r.portfwd_add(8080, "127.0.0.1", 80)
        assert env["ok"] is True  # suggested, not run
        assert "ssh -L" in env["stdout"]
        assert len(r.list_portfwds()) == 1

    def test_socks_start_invalid_port(self):
        from core.post_access_tui import PostAccessRunner, SessionState
        import base64
        r = PostAccessRunner(state=SessionState(
            target="10.0.0.5", transport="ssh",
            creds_b64=base64.b64encode(b"hunter2").decode("ascii"),
        ))
        env = r.socks_start("not-a-port")
        assert env["ok"] is False
        assert "integer" in env["error"]

    def test_socks_stop_no_proxy(self):
        from core.post_access_tui import PostAccessRunner, SessionState
        r = PostAccessRunner(state=SessionState(
            target="10.0.0.5", transport="ssh",
        ))
        env = r.socks_stop()
        assert env["ok"] is False
        assert "no SOCKS" in env["error"]

    def test_socks_start_ssh_suggests_command(self):
        from core.post_access_tui import PostAccessRunner, SessionState
        import base64
        r = PostAccessRunner(state=SessionState(
            target="10.0.0.5", transport="ssh",
            creds_b64=base64.b64encode(b"hunter2").decode("ascii"),
        ))
        env = r.socks_start(9050)
        assert env["ok"] is True
        assert "ssh -D 9050" in env["stdout"]

    def test_run_module_empty_name(self):
        from core.post_access_tui import PostAccessRunner, SessionState
        r = PostAccessRunner(state=SessionState())
        env = r.run_module("")
        assert env["ok"] is False
        assert "name required" in env["error"]

    def test_run_module_unknown_name(self):
        from core.post_access_tui import PostAccessRunner, SessionState
        r = PostAccessRunner(state=SessionState())
        env = r.run_module("definitely_not_a_real_method_xyz")
        assert env["ok"] is False
        assert "unknown module" in env["error"]

    def test_apply_persistence_unknown_alias(self):
        from core.post_access_tui import PostAccessRunner, SessionState
        r = PostAccessRunner(state=SessionState())
        env = r.apply_persistence("not_an_alias_xx")
        assert env["ok"] is False
        assert "unknown persistence" in env["error"]

    def test_detach_cleans_records(self):
        from core.post_access_tui import PostAccessRunner, SessionState
        r = PostAccessRunner(state=SessionState(
            target="10.0.0.5", transport="ssh",
        ))
        r.portfwd_add(8080, "127.0.0.1", 80)
        r.socks_start(9050)
        env = r.detach()
        assert env["ok"] is True
        assert r.detached is True
        # Idempotent
        env2 = r.detach()
        assert env2["ok"] is True
        assert "already detached" in env2["stdout"]

    def test_run_shell_after_detach_rejected(self):
        from core.post_access_tui import PostAccessRunner, SessionState
        r = PostAccessRunner(state=SessionState(transport="local"))
        r.detach()
        env = r.run_shell("id")
        assert env["ok"] is False
        assert "detached" in env["error"]

    def test_envelope_shape(self):
        """All envelope fields are present and have the right types."""
        from core.post_access_tui import PostAccessRunner, SessionState
        r = PostAccessRunner(state=SessionState(transport="local"))
        env = r.run_shell("true")
        for key in ("action", "ok", "stdout", "stderr", "returncode",
                    "error", "ts", "duration_s"):
            assert key in env
        assert isinstance(env["ok"], bool)
        assert isinstance(env["returncode"], int)
        assert isinstance(env["duration_s"], (int, float))
        assert env["duration_s"] >= 0.0

    def test_on_action_callback_invoked(self):
        from core.post_access_tui import PostAccessRunner, SessionState
        envelopes = []
        r = PostAccessRunner(
            state=SessionState(transport="local"),
            on_action=lambda e: envelopes.append(e),
        )
        r.run_shell("echo hi")
        assert len(envelopes) == 1
        assert envelopes[0]["ok"] is True


# ---------------------------------------------------------------------------
# No bare except
# ---------------------------------------------------------------------------

class TestNoBareExcept:
    @pytest.mark.parametrize("module", [
        "core.post_access_tui.session_state",
        "core.post_access_tui.runner",
        "core.post_access_tui.screen",
        "core.post_access_tui.spawner",
        "core.post_access_tui.cli",
    ])
    def test_no_bare_except(self, module):
        """No bare ``except:`` (no exception class) in any module.
        Strips comment lines first so docstring examples don't false-positive."""
        import importlib
        m = importlib.import_module(module)
        src = inspect.getsource(m)
        # Strip lines whose first non-whitespace is '#'
        lines = [ln for ln in src.splitlines()
                 if ln.strip() and not ln.lstrip().startswith("#")]
        bare = []
        for ln in lines:
            stripped = ln.lstrip()
            # We accept: `except Exception:`, `except (X, Y):`, `except X as e:`
            # We reject: `except:` (no class), and `except , Y:` (no class before comma)
            if stripped.startswith("except"):
                after = stripped[len("except"):].lstrip()
                # `except:` (immediately colon)
                if after.startswith(":"):
                    bare.append(ln)
                    continue
                # `except , Y:` (comma before any class)
                if after.startswith(","):
                    bare.append(ln)
                    continue
        assert not bare, f"{module} has bare except: {bare}"


# ---------------------------------------------------------------------------
# Single-gate invariant for the screen
# ---------------------------------------------------------------------------

class TestSingleGateScreen:
    def test_screen_actions_call_confirm_fn(self):
        """Every action method in PostAccessScreen routes through
        self._gate(...) BEFORE calling into the runner."""
        from core.post_access_tui import screen as screen_mod
        for name, fn in inspect.getmembers(screen_mod.PostAccessScreen,
                                            inspect.isfunction):
            if not name.startswith("_action_"):
                continue
            if name == "_action_detach":
                # detach is intentionally ungated (F12 = operator's exit)
                continue
            if name == "_action_help":
                # help is a read action; not gated
                continue
            if name == "_action_reports":
                # reports is a read action; not gated
                continue
            if name == "_action_ble":
                # _action_ble opens the BLE sub-panel which has its
                # OWN per-action gate (write/notify/bleshell fire
                # confirm_fn). The screen itself does not re-gate.
                # The single-gate invariant still holds: the BLE
                # panel fires confirm_fn BEFORE dispatching high-
                # risk actions.
                continue
            if name == "_action_wifi":
                # _action_wifi opens the WiFi sub-panel which has its
                # OWN per-action gate (deauth/evil-twin/karma fire
                # confirm_fn). Same single-gate invariant as BLE.
                continue
            if name == "_action_sessions":
                # _action_sessions opens the network session multiplexer
                # sub-panel which has its OWN per-action gate (shell,
                # file transfer, broadcast, kill, socks start/stop
                # fire confirm_fn). Same single-gate invariant.
                continue
            try:
                src = inspect.getsource(fn)
            except (OSError, TypeError):
                continue
            # Strip the `confirm_fn=None` keyword form (NOT a re-confirm)
            cleaned = re.sub(r"confirm_fn\s*=\s*[^,)\s]+", "", src)
            assert "self._gate" in cleaned, (
                f"{name} does not call self._gate()"
            )

    def test_runner_does_not_re_confirm(self):
        """PostAccessRunner methods do NOT call confirm_fn / self.confirm /
        self._gate — the single-gate invariant means the SCREEN is the
        only place that gates, the runner is the action layer."""
        from core.post_access_tui import runner as runner_mod
        src = inspect.getsource(runner_mod)
        # Strip docstrings + comments + argument references
        # (docstrings may legitimately mention confirm_fn).
        no_doc = re.sub(r'"""[\s\S]*?"""', "", src)
        no_doc = re.sub(r"'''[\s\S]*?'''", "", no_doc)
        no_comments = "\n".join(
            ln for ln in no_doc.splitlines()
            if not ln.lstrip().startswith("#")
        )
        # Strip `confirm_fn=None` keyword argument references
        cleaned = re.sub(r"confirm_fn\s*=\s*[^,)\s]+", "", no_comments)
        assert "confirm_fn" not in cleaned
        assert "self._gate" not in cleaned


# ---------------------------------------------------------------------------
# Detach: F12 / Esc / x all return; runner is detached
# ---------------------------------------------------------------------------

class TestDetach:
    def _screen(self, keys):
        from core.post_access_tui import (
            PostAccessRunner, SessionState, PostAccessScreen,
        )
        state = SessionState(transport="local")
        runner = PostAccessRunner(state=state)
        keys_q = list(keys)
        def input_fn(prompt):
            return keys_q.pop(0) if keys_q else ""
        # confirm_fn accepts everything (gate is the SCREEN, not the runner)
        s = PostAccessScreen(
            stdscr=None, state=state, runner=runner,
            confirm_fn=lambda p: True,
            input_fn=input_fn,
        )
        return s, s.run_curses_free()

    def test_x_detaches(self):
        _, res = self._screen(["x"])
        assert res.get("detached") is True
        assert res.get("ok") is True

    def test_esc_detaches(self):
        _, res = self._screen(["\x1b"])
        assert res.get("detached") is True

    def test_q_detaches(self):
        _, res = self._screen(["q"])
        assert res.get("detached") is True

    def test_unknown_key_does_not_crash(self):
        from core.post_access_tui import (
            PostAccessRunner, SessionState, PostAccessScreen,
        )
        state = SessionState(transport="local")
        runner = PostAccessRunner(state=state)
        keys = ["z", "?", " ", "x"]
        s = PostAccessScreen(
            stdscr=None, state=state, runner=runner,
            confirm_fn=lambda p: True,
            input_fn=lambda _p: keys.pop(0) if keys else "",
        )
        res = s.run_curses_free()
        assert res.get("detached") is True


# ---------------------------------------------------------------------------
# Menu key mapping
# ---------------------------------------------------------------------------

class TestMenuKeys:
    @pytest.mark.parametrize("key,expected_action", [
        ("s", "shell"),
        ("f", "file"),
        ("n", "network"),
        ("p", "persistence"),
        ("m", "modules"),
        ("r", "reports"),
        ("h", "help"),
        ("x", "detach"),
    ])
    def test_key_routes(self, key, expected_action):
        from core.post_access_tui.screen import KEY_MAP
        assert KEY_MAP[key] == expected_action

    def test_menu_has_all_keys(self):
        from core.post_access_tui.screen import MENU, KEY_MAP
        for label, k, action in MENU:
            assert KEY_MAP[k] == action
            assert label  # non-empty


# ---------------------------------------------------------------------------
# Shell action routes through gate then runner
# ---------------------------------------------------------------------------

class TestShellActionGate:
    def test_shell_runs_when_gate_accepted(self):
        from core.post_access_tui import (
            PostAccessRunner, SessionState, PostAccessScreen,
        )
        state = SessionState(transport="local")
        runner = PostAccessRunner(state=state)
        keys = ["s", "echo yes-accepted"]
        gate_prompts = []
        def gate(p):
            gate_prompts.append(p)
            return True
        s = PostAccessScreen(
            stdscr=None, state=state, runner=runner,
            confirm_fn=gate,
            input_fn=lambda _p: keys.pop(0) if keys else "",
        )
        s.run_curses_free()
        assert any("run_shell" in p for p in gate_prompts)

    def test_shell_skipped_when_gate_rejected(self):
        from core.post_access_tui import (
            PostAccessRunner, SessionState, PostAccessScreen,
        )
        state = SessionState(transport="local")
        runner = PostAccessRunner(state=state)
        envelopes = []
        runner._on_action = lambda e: envelopes.append(e)  # type: ignore[attr-defined]
        keys = ["s", "echo should-not-run"]
        gate_prompts = []
        def gate(p):
            gate_prompts.append(p)
            return False  # CANCEL
        s = PostAccessScreen(
            stdscr=None, state=state, runner=runner,
            confirm_fn=gate,
            input_fn=lambda _p: keys.pop(0) if keys else "",
        )
        s.run_curses_free()
        # No envelope from run_shell (gate cancelled)
        assert not any(e.get("action") == "run_shell" for e in envelopes)


# ---------------------------------------------------------------------------
# Spawner
# ---------------------------------------------------------------------------

class TestSpawner:
    def test_is_post_access_spawnable_yes(self):
        from core.post_access_tui.spawner import is_post_access_spawnable
        assert is_post_access_spawnable({
            "access": {"achieved": True, "session_id": 3, "creds": None}
        }) is True
        assert is_post_access_spawnable({
            "access": {"achieved": True, "session_id": None, "creds": "x"}
        }) is True

    def test_is_post_access_spawnable_no(self):
        from core.post_access_tui.spawner import is_post_access_spawnable
        assert is_post_access_spawnable({}) is False
        assert is_post_access_spawnable(
            {"access": {"achieved": False, "session_id": 3}}
        ) is False
        assert is_post_access_spawnable(
            {"access": {"achieved": True, "session_id": None, "creds": None}}
        ) is False
        assert is_post_access_spawnable(None) is False  # type: ignore[arg-type]

    def test_build_argv_includes_state_b64(self):
        from core.post_access_tui.spawner import build_argv
        from core.post_access_tui import SessionState
        s = SessionState(session_id=2, transport="msfconsole", target="10.0.0.5")
        argv = build_argv(s)
        assert "--state-b64" in argv
        assert "--log-path" in argv
        # The b64 blob is the next arg
        idx = argv.index("--state-b64")
        b64 = argv[idx + 1]
        # Decodes to JSON with session_id=2
        import base64 as _b64, json as _json
        decoded = _json.loads(_b64.b64decode(b64).decode("utf-8"))
        assert decoded["session_id"] == 2
        assert decoded["transport"] == "msfconsole"

    def test_build_argv_no_session_returns_empty(self):
        from core.post_access_tui.spawner import build_argv
        from core.post_access_tui import SessionState
        assert build_argv(SessionState()) == []

    def test_spawn_no_signal_returns_error(self):
        from core.post_access_tui.spawner import spawn_post_access_tui
        r = spawn_post_access_tui({}, external_terminal=None)
        assert r["ok"] is False
        assert "access not achieved" in r["error"]

    def test_spawn_no_real_backend_returns_manual(self, monkeypatch):
        from core.post_access_tui.spawner import spawn_post_access_tui
        report = {"access": {"achieved": True, "session_id": 4}}
        # No external_terminal → is_real_backend(None) is False
        r = spawn_post_access_tui(report, external_terminal=None)
        assert r["ok"] is False
        assert "no real terminal backend" in r["error"] or "no terminal" in r["error"]
        assert "manual" in r

    def test_spawn_marks_one_shot(self, monkeypatch):
        from core.post_access_tui.spawner import spawn_post_access_tui

        # Patch is_real_backend to True; patch launch_real_step to fake-success.
        monkeypatch.setattr(
            "core.utils.external_terminal.is_real_backend",
            lambda _x: True,
        )
        monkeypatch.setattr(
            "core.utils.external_terminal.launch_real_step",
            lambda step, cmd, log_path=None, title=None: {"ok": True, "pid": 9999},
        )
        report = {
            "access": {"achieved": True, "session_id": 4},
            "target": "10.0.0.5",
        }
        r = spawn_post_access_tui(report, external_terminal="fake")
        assert r["ok"] is True
        assert r.get("pid") == 9999
        # one-shot sentinel set
        assert report["access"].get("tui_opened") is True


# ---------------------------------------------------------------------------
# CLI argparse
# ---------------------------------------------------------------------------

class TestCLI:
    def test_main_invalid_state_b64_returns_2(self, capsys):
        from core.post_access_tui.cli import main
        rc = main(["--state-b64", "this-is-not-valid", "--no-curses"])
        assert rc == 2

    def test_main_no_curses_loop_runs(self, monkeypatch):
        from core.post_access_tui import SessionState
        from core.post_access_tui.cli import main, _parse_state_b64
        s = SessionState(session_id=5, transport="msfconsole")
        import base64 as _b64, json as _json
        b64 = _b64.b64encode(
            _json.dumps(s.to_dict()).encode("utf-8")
        ).decode("ascii")
        # The screen reads from input_fn; we pass --no-curses so the
        # cli runs the no-curses loop with an empty input_fn that
        # returns "". The loop should exit immediately (return 0).
        rc = main(["--state-b64", b64, "--no-curses"])
        assert rc == 0
