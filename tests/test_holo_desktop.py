"""Tests for Holo desktop-cli integration (OS navigation for tools/models)."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from core.desktop.holo_agent import (
    TASK_PRESETS,
    HoloDesktopBridge,
    build_desktop_task,
    holo_status,
    run_holo_task,
    stop_holo,
)


def test_presets_cover_models_and_tools():
    assert "ollama_list" in TASK_PRESETS
    assert "ollama_pull_primary" in TASK_PRESETS
    assert "open_terminal" in TASK_PRESETS
    assert "wifi_monitor_help" in TASK_PRESETS


def test_build_desktop_task_preset():
    t = build_desktop_task("ollama_list")
    assert "ollama list" in t.lower()
    assert "secrets" in t.lower() or "password" in t.lower()


def test_build_desktop_task_with_tool_and_model():
    t = build_desktop_task(
        "custom goal open something",
        tool="wireshark",
        model="xploiter/pentester:latest",
    )
    assert "wireshark" in t
    assert "xploiter/pentester" in t


def test_holo_status_no_binary(monkeypatch):
    monkeypatch.setattr(
        "core.desktop.holo_agent._find_holo_bin", lambda: ""
    )
    st = holo_status()
    assert st["ok"] is False
    assert "install" in st["install_hint"].lower()


def test_run_default_deny_without_confirm(monkeypatch):
    monkeypatch.setattr(
        "core.desktop.holo_agent._find_holo_bin", lambda: "/usr/bin/holo"
    )
    r = run_holo_task("Open Calculator", confirm_fn=None)
    assert r["ok"] is False
    assert "confirm" in r["error"].lower() or "deny" in r["error"].lower()


def test_run_cancelled(monkeypatch):
    monkeypatch.setattr(
        "core.desktop.holo_agent._find_holo_bin", lambda: "/usr/bin/holo"
    )
    r = run_holo_task("Open Calculator", confirm_fn=lambda _p: False)
    assert r["ok"] is False
    assert "cancel" in r["error"].lower()


def test_dry_run_builds_argv(monkeypatch):
    monkeypatch.setattr(
        "core.desktop.holo_agent._find_holo_bin", lambda: "/usr/bin/holo"
    )
    r = run_holo_task(
        "Open Calculator",
        confirm_fn=lambda _p: True,
        dry_run=True,
        max_steps=5,
        base_url="http://127.0.0.1:8000/v1",
    )
    assert r["ok"] is True
    assert r["dry_run"] is True
    assert r["cmd"][0].endswith("holo") or r["cmd"][0] == "/usr/bin/holo"
    assert "run" in r["cmd"]
    assert "--base-url" in r["cmd"]
    assert "--max-steps" in r["cmd"]


def test_run_executes_subprocess(monkeypatch):
    monkeypatch.setattr(
        "core.desktop.holo_agent._find_holo_bin", lambda: "/usr/bin/holo"
    )
    fake = MagicMock()
    fake.returncode = 0
    fake.stdout = "done"
    fake.stderr = ""
    with patch("core.desktop.holo_agent.subprocess.run", return_value=fake) as m:
        r = run_holo_task(
            "Open Calculator",
            confirm_fn=lambda _p: True,
            quiet=True,
            max_time_s=30,
        )
    assert r["ok"] is True
    assert r["rc"] == 0
    assert m.called
    argv = m.call_args[0][0]
    assert argv[0] == "/usr/bin/holo"
    assert argv[1] == "run"


def test_stop_holo(monkeypatch):
    monkeypatch.setattr(
        "core.desktop.holo_agent._find_holo_bin", lambda: "/usr/bin/holo"
    )
    fake = MagicMock()
    fake.returncode = 0
    fake.stdout = "stopped"
    fake.stderr = ""
    with patch("core.desktop.holo_agent.subprocess.run", return_value=fake) as m:
        r = stop_holo(force=True)
    assert r["ok"] is True
    assert "--force" in m.call_args[0][0]


def test_bridge_navigate_model(monkeypatch):
    monkeypatch.setattr(
        "core.desktop.holo_agent._find_holo_bin", lambda: "/usr/bin/holo"
    )
    b = HoloDesktopBridge(confirm_fn=lambda _p: True)
    with patch(
        "core.desktop.holo_agent.run_holo_task",
        return_value={"ok": True, "dry_run": True},
    ) as m:
        b.navigate_model("llama3.1:8b", action="list")
    assert m.called


def test_orchestrator_dispatch_holo():
    from core.orchestrator.autonomous_orchestrator import AutonomousOrchestrator

    events = []
    orch = AutonomousOrchestrator(
        confirm_fn=lambda _p: True,
        on_event=events.append,
    )
    report = {"executed": [], "skipped": [], "optional_declined": []}
    with patch(
        "core.desktop.holo_agent.run_holo_task",
        return_value={"ok": True, "task": "t", "duration_s": 0.1},
    ):
        # Patch at bridge level
        with patch.object(
            __import__("core.desktop.holo_agent", fromlist=["HoloDesktopBridge"]).HoloDesktopBridge,
            "run",
            return_value={"ok": True, "task": "t", "duration_s": 0.1},
        ):
            orch._dispatch_holo_desktop(
                {
                    "action": "holo_desktop",
                    "args": {"goal": "ollama_list"},
                    "desc": "list models via holo",
                },
                {},
                report,
            )
    assert len(report["executed"]) == 1
    assert report["executed"][0]["action"] == "holo_desktop"
    assert report["executed"][0]["result"]["ok"] is True


def test_chain_schema_mentions_holo():
    from core.ai_backend import chain as ch
    assert "holo_desktop" in ch._CHAIN_STEP_SCHEMA_HINT
    assert "HOLO_DESKTOP" in dir(ch) or hasattr(ch, "HOLO_DESKTOP_PROMPT_STANZA")
    assert "holo-desktop" in ch.HOLO_DESKTOP_PROMPT_STANZA.lower()
