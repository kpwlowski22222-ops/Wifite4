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
    assert "wifi_scan_windows_layout" in TASK_PRESETS
    assert "post_access_browser_dashboard" in TASK_PRESETS
    assert "engagement_tool_prep" in TASK_PRESETS
    assert "ble_long_range_prep" in TASK_PRESETS


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


# --- Phase 2.4 §151: deep holo OS-agent AI integration (predict/read/label) ---

from core.desktop.holo_agent import (  # noqa: E402
    _holo_plan_to_task,
    run_holo_plan,
)


def test_holo_plan_to_task_includes_predict_and_click():
    t = _holo_plan_to_task({
        "what_to_click": "WiFi icon",
        "what_for": "open the networks panel",
        "predicted_outcome": "network list appears",
    })
    low = t.lower()
    assert "open the networks panel" in low
    assert "wifi icon" in low
    assert "network list appears" in low
    assert "stop" in low  # must tell holo when to stop


def test_holo_plan_to_task_empty_plan_is_describe_only():
    t = _holo_plan_to_task({})
    assert "describe" in t.lower()


def test_holo_plan_to_task_goal_preset_expanded():
    t = _holo_plan_to_task({"goal": "ollama_list"})
    assert "ollama list" in t.lower()


def test_holo_plan_dry_run_never_reads_screen(monkeypatch):
    # dry_run must not touch the real screen / navigator.
    called = {"read": False}
    import core.utils.ui_navigator as un
    monkeypatch.setattr(
        un.navigator, "read_screen_content",
        lambda: called.__setitem__("read", True) or {"ok": True, "labels": [], "text": ""},
    )
    monkeypatch.setattr(
        "core.desktop.holo_agent._find_holo_bin", lambda: "/usr/bin/holo"
    )
    r = run_holo_plan(
        {"what_to_click": "x", "predicted_outcome": "y"},
        confirm_fn=lambda _p: True,
        dry_run=True,
    )
    assert r["ok"] is True
    assert r["model"] == "holo-ai-decide (heuristic)"
    assert r["prediction_match"] is None  # dry_run skips verification
    assert called["read"] is False  # screen never read in dry-run


def test_holo_plan_fake_never_reads_screen(monkeypatch):
    # fake mode is screen-safe: it runs holo with --fake and skips reads.
    called = {"read": False, "run": []}
    import core.utils.ui_navigator as un
    monkeypatch.setattr(
        un.navigator, "read_screen_content",
        lambda: called.__setitem__("read", True) or {"ok": True, "labels": [], "text": ""},
    )
    monkeypatch.setattr(
        "core.desktop.holo_agent._find_holo_bin", lambda: "/usr/bin/holo"
    )
    from unittest.mock import MagicMock
    fake = MagicMock(returncode=0, stdout="fake-run", stderr="")
    with patch("core.desktop.holo_agent.subprocess.run", return_value=fake) as m:
        r = run_holo_plan(
            {"what_to_click": "x", "predicted_outcome": "y"},
            confirm_fn=lambda _p: True,
            fake=True,
            max_time_s=30,
        )
    assert r["ok"] is True
    assert called["read"] is False
    assert r["prediction_match"] is None
    assert m.called
    argv = m.call_args[0][0]
    assert "--fake" in argv


def test_holo_plan_prediction_match_heuristic(monkeypatch):
    monkeypatch.setattr(
        "core.desktop.holo_agent._find_holo_bin", lambda: "/usr/bin/holo"
    )
    fake = MagicMock(returncode=0, stdout="clicked", stderr="")
    with patch("core.desktop.holo_agent.subprocess.run", return_value=fake):
        import core.utils.ui_navigator as un
        monkeypatch.setattr(
            un.navigator, "read_screen_content",
            lambda: {"ok": True, "text": "network list appears now",
                     "labels": ["Network List"], "count": 1},
        )
        # Skip live-label sweep so the test is fast.
        monkeypatch.setattr(
            un.navigator, "label_screen_live",
            lambda duration_s=6.0, on_label=None: {"ok": True, "labels": [], "labels_count": 0},
        )
        r = run_holo_plan(
            {"what_to_click": "WiFi icon", "predicted_outcome": "network list appears"},
            confirm_fn=lambda _p: True,
            max_time_s=30,
            label_duration_s=0,  # disable live sweep
        )
    assert r["ok"] is True
    assert r["prediction_match"] is True
    assert "network" in r["prediction_matched_tokens"]
    assert r["observed"]["ok"] is True


def test_holo_plan_prediction_mismatch_is_false(monkeypatch):
    monkeypatch.setattr(
        "core.desktop.holo_agent._find_holo_bin", lambda: "/usr/bin/holo"
    )
    fake = MagicMock(returncode=0, stdout="clicked", stderr="")
    with patch("core.desktop.holo_agent.subprocess.run", return_value=fake):
        import core.utils.ui_navigator as un
        monkeypatch.setattr(
            un.navigator, "read_screen_content",
            lambda: {"ok": True, "text": "totally different thing",
                     "labels": ["Other"], "count": 1},
        )
        r = run_holo_plan(
            {"predicted_outcome": "network list appears"},
            confirm_fn=lambda _p: True,
            max_time_s=30,
            label_duration_s=0,
        )
    assert r["ok"] is True
    assert r["prediction_match"] is False
    assert r["prediction_matched_tokens"] == []


def test_holo_plan_no_prediction_yields_none_match(monkeypatch):
    # No predicted_outcome → prediction_match is None (not a false claim).
    monkeypatch.setattr(
        "core.desktop.holo_agent._find_holo_bin", lambda: "/usr/bin/holo"
    )
    fake = MagicMock(returncode=0, stdout="clicked", stderr="")
    with patch("core.desktop.holo_agent.subprocess.run", return_value=fake):
        import core.utils.ui_navigator as un
        monkeypatch.setattr(
            un.navigator, "read_screen_content",
            lambda: {"ok": True, "text": "something", "labels": [], "count": 0},
        )
        r = run_holo_plan(
            {"what_to_click": "WiFi icon"},
            confirm_fn=lambda _p: True,
            max_time_s=30,
            label_duration_s=0,
        )
    assert r["ok"] is True
    assert r["prediction_match"] is None


def test_holo_plan_default_deny_without_confirm(monkeypatch):
    monkeypatch.setattr(
        "core.desktop.holo_agent._find_holo_bin", lambda: "/usr/bin/holo"
    )
    r = run_holo_plan({"what_to_click": "x"}, confirm_fn=None)
    assert r["ok"] is False
    assert "confirm" in r["error"].lower() or "deny" in r["error"].lower()


def test_bridge_run_plan_delegates(monkeypatch):
    monkeypatch.setattr(
        "core.desktop.holo_agent._find_holo_bin", lambda: "/usr/bin/holo"
    )
    b = HoloDesktopBridge(confirm_fn=lambda _p: True)
    captured = {}
    with patch("core.desktop.holo_agent.run_holo_plan",
               side_effect=lambda plan, **kw: captured.update({"plan": plan, "kw": kw}) or {"ok": True, "model": "holo-ai-decide (heuristic)"}):
        r = b.run_plan({"what_to_click": "WiFi icon", "predicted_outcome": "x"})
    assert r["ok"] is True
    assert captured["plan"]["what_to_click"] == "WiFi icon"
    # confirm_fn threaded through
    assert captured["kw"]["confirm_fn"] is b.confirm_fn


def test_bridge_click_uses_navigator_label(monkeypatch):
    """Bridge.click delegates to HostVisionNavigator.click_label so the
    OS-agent loop can act on a discovered control without invoking Holo."""
    b = HoloDesktopBridge(confirm_fn=lambda _p: True)
    calls = []

    def _fake_click(label):
        calls.append(label)
        return {"ok": True, "label": label, "box": [0, 0, 10, 10], "click": [5, 5]}

    import core.utils.ui_navigator as un
    monkeypatch.setattr(un.navigator, "click_label", _fake_click)
    res = b.click("WiFi icon")
    assert res["ok"] is True
    assert calls == ["WiFi icon"]
    assert res["click"] == [5, 5]


def test_orchestrator_dispatch_holo_plan_mode():
    from core.orchestrator.autonomous_orchestrator import AutonomousOrchestrator

    events = []
    orch = AutonomousOrchestrator(
        confirm_fn=lambda _p: True,
        on_event=events.append,
    )
    report = {"executed": [], "skipped": [], "optional_declined": []}
    plan = {
        "what_to_click": "WiFi icon",
        "what_for": "open networks",
        "predicted_outcome": "network list",
    }
    with patch(
        "core.desktop.holo_agent.run_holo_plan",
        return_value={"ok": True, "task": "t", "duration_s": 0.1,
                       "prediction_match": True, "model": "holo-ai-decide (heuristic)"},
    ) as m:
        orch._dispatch_holo_desktop(
            {"action": "holo_desktop",
             "args": {"plan": plan, "read_labels": True},
             "desc": "ai-decided desktop click"},
            {},
            report,
        )
    assert m.called
    sent_plan = m.call_args[0][0]
    assert sent_plan["what_to_click"] == "WiFi icon"
    assert len(report["executed"]) == 1
    assert report["executed"][0]["action"] == "holo_desktop"
    assert report["executed"][0]["result"]["ok"] is True


def test_orchestrator_dispatch_holo_flat_plan_fields():
    # AI may emit what_to_click / predicted_outcome at the top level.
    from core.orchestrator.autonomous_orchestrator import AutonomousOrchestrator

    events = []
    orch = AutonomousOrchestrator(
        confirm_fn=lambda _p: True,
        on_event=events.append,
    )
    report = {"executed": [], "skipped": [], "optional_declined": []}
    with patch(
        "core.desktop.holo_agent.run_holo_plan",
        return_value={"ok": True, "task": "t", "duration_s": 0.1,
                       "model": "holo-ai-decide (heuristic)"},
    ) as m:
        orch._dispatch_holo_desktop(
            {"action": "holo_desktop",
             "args": {"what_to_click": "Settings", "predicted_outcome": "opens"},
             "desc": "flat plan fields"},
            {},
            report,
        )
    assert m.called
    plan = m.call_args[0][0]
    assert plan["what_to_click"] == "Settings"
    assert plan["predicted_outcome"] == "opens"


def test_chain_stanza_teaches_plan_mode():
    from core.ai_backend import chain as ch
    low = ch.HOLO_DESKTOP_PROMPT_STANZA.lower()
    assert "what_to_click" in low
    assert "predicted_outcome" in low
    assert "plan" in low
    assert "holo-ai-decide" in low
