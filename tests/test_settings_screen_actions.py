"""SettingsScreen actions — curses-free, one test per action."""

import subprocess
import sys
import types

from core.tui.settings_screen import SettingsScreen
from tests.conftest import _make_screen
from tests.fakes import FakeAIBackend, FakeInput, FakeSettingsManager, sync_thread_runner


def _settings(log, **over):
    return _make_screen(SettingsScreen, log, **over)


def test_view_ollama_status(log):
    sc = _settings(log, ai_backend=FakeAIBackend(models=["xploiter/pentester:latest"]))
    sc.view_ollama_status()
    assert any("Ollama Backend Status" in l for l in log)
    assert any("Per-domain model mapping" in l for l in log)


def test_view_ollama_status_no_backend(log):
    sc = _settings(log, ai_backend=None)
    sc.view_ollama_status()
    assert any("AI backend not initialized" in l for l in log)


def test_set_ollama_endpoint(log):
    sm = FakeSettingsManager()
    ai = FakeAIBackend()
    sc = _settings(log, ai_backend=ai, settings_manager=sm, input_fn=FakeInput(["127.0.0.1:11434"]))
    sc.set_ollama_endpoint()
    assert any("Ollama endpoint set" in l for l in log)
    assert any(u["key"] == "ollama.endpoint" for u in sm.updates)
    # the screen prepends http:// if no scheme was given
    assert ai.ollama.endpoint == "http://127.0.0.1:11434"


def test_select_domain_model(log):
    sm = FakeSettingsManager()
    sc = _settings(log, settings_manager=sm, input_fn=FakeInput(["wifi", "xploiter/pentester:latest"]))
    sc.select_domain_model()
    assert any(u["key"] == "ollama.domain_models.wifi" for u in sm.updates)


def test_select_domain_model_unknown(log):
    sc = _settings(log, input_fn=FakeInput(["bogus", "x"]))
    sc.select_domain_model()
    assert any("Unknown domain" in l for l in log)


def test_pull_models_info(log):
    sc = _settings(log)
    sc.pull_models_info()
    assert any("Pull models via CLI" in l for l in log)


def test_holo_os_agent_status(log, monkeypatch):
    monkeypatch.setattr(
        "core.desktop.holo_agent._find_holo_bin", lambda: ""
    )
    sc = _settings(log, settings_manager=FakeSettingsManager())
    sc.holo_os_agent_status()
    assert any("OS Agentic CLI" in l for l in log)
    assert any("main.py --cli holo" in l for l in log)


def test_holo_os_agent_dry_run(log, monkeypatch):
    monkeypatch.setattr(
        "core.desktop.holo_agent._find_holo_bin", lambda: "/usr/bin/holo"
    )
    sc = _settings(
        log,
        settings_manager=FakeSettingsManager(),
        input_fn=FakeInput(["ble_long_range_prep"]),
    )
    sc.holo_os_agent_dry_run()
    assert any("dry_run" in l for l in log)


def test_holo_os_agent_plan(log, monkeypatch):
    """Holo AI-decided plan path: collect plan params and run predict→act→read→label."""
    captured = {}

    class FakeBridge:
        def __init__(self, confirm_fn=None, settings=None):
            self.confirm_fn = confirm_fn
            self.settings = settings

        def run_plan(self, plan, **kwargs):
            captured["plan"] = plan
            captured["kwargs"] = kwargs
            return {
                "ok": True,
                "predicted_outcome": "terminal window appears",
                "observed": {"ok": True, "count": 3, "labels": ["terminal"]},
                "prediction_match": True,
                "live_labels_count": 2,
                "error": "",
            }

    monkeypatch.setattr(
        "core.desktop.holo_agent.HoloDesktopBridge", FakeBridge
    )
    # Inputs: what, where, what_for, predicted, goal, tool, model,
    # max_steps, read_labels, label_duration_s, dry_run.
    inputs = [
        "terminal icon", "top-left dock", "open a shell",
        "terminal window appears", "open_terminal", "", "",
        "", "n", "", "",
    ]
    sc = _settings(
        log,
        input_fn=FakeInput(inputs),
        thread_runner=sync_thread_runner,
    )
    sc.holo_os_agent_plan()
    assert any("Holo plan" in l for l in log)
    assert any("predicted: terminal window appears" in l for l in log)
    assert any("observed 3 labels" in l for l in log)
    assert any("prediction verified" in l for l in log)
    assert any("live labels: 2" in l for l in log)
    assert captured["plan"]["what_to_click"] == "terminal icon"
    assert captured["kwargs"]["dry_run"] is False
    assert captured["kwargs"]["read_labels"] is False


def test_toggle_holo_enabled(log):
    sm = FakeSettingsManager()
    sc = _settings(log, settings_manager=sm)
    sc.toggle_holo_enabled()
    assert any(u["key"] == "holo.enabled" for u in sm.updates)


def test_fetch_toolboxes(log, monkeypatch):
    class FakeCP:
        stdout = "cloning a\ncloning b"
        stderr = ""
        returncode = 0
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: FakeCP())
    sc = _settings(log, input_fn=FakeInput(["wifi", "5"]))
    sc.fetch_toolboxes()
    assert any("Fetch complete" in l for l in log)


def test_prepare_toolboxes(log, monkeypatch):
    class FakeCP:
        stdout = "pip ok"
        stderr = ""
        returncode = 0
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: FakeCP())
    # fake ToolRegistry so the rebuild branch inside prepare succeeds
    fake_mod = types.ModuleType("core.tool_registry")

    class FakeReg:
        def build(self):
            return {"total": 3, "toolbox": 1, "kali": 1, "venv": 1,
                    "by_domain": {"wifi": 1}}
    fake_mod.ToolRegistry = FakeReg
    monkeypatch.setitem(sys.modules, "core.tool_registry", fake_mod)
    sc = _settings(log, input_fn=FakeInput(["wifi"]))
    sc.prepare_toolboxes()
    # settings prepare_toolboxes finishes by rebuilding the registry on success
    assert any("Registry rebuilt" in l for l in log)


def test_rebuild_registry(log, monkeypatch):
    fake_mod = types.ModuleType("core.tool_registry")

    class FakeReg:
        def build(self):
            return {"total": 7, "toolbox": 2, "kali": 3, "venv": 2,
                    "by_domain": {"wifi": 2, "ble": 2, "osint": 3}}
    fake_mod.ToolRegistry = FakeReg
    monkeypatch.setitem(sys.modules, "core.tool_registry", fake_mod)
    sc = _settings(log)
    sc.rebuild_registry()
    assert any("Registry: 7 tools" in l for l in log)


def test_mcp_info(log):
    sc = _settings(log)
    sc.mcp_info()
    assert any("MCP Server" in l for l in log)
    assert any("KFIOSA_MCP_ALLOW_EXEC" in l for l in log)


def test_view_api_keys_status(log):
    sc = _settings(log)
    sc.view_api_keys_status()
    assert any("API Keys Presence" in l for l in log)


def test_adjust_timeouts(log):
    sm = FakeSettingsManager()
    sc = _settings(log, settings_manager=sm, input_fn=FakeInput(["15", "8"]))
    sc.adjust_timeouts()
    assert any(u["key"] == "scanning.wifi_timeout" for u in sm.updates)
    assert any("WiFi timeout set to 15s" in l for l in log)


def test_adjust_timeouts_invalid(log):
    sc = _settings(log, input_fn=FakeInput(["abc", "xyz"]))
    sc.adjust_timeouts()
    assert any("Invalid timeout" in l for l in log)


def test_configure_external_terminal_pick(log, monkeypatch):
    monkeypatch.setattr(
        "core.utils.external_terminal.list_available",
        lambda: ["xterm", "kitty", "tail"],
    )
    monkeypatch.setattr(
        "core.utils.external_terminal.detect",
        lambda settings=None: "xterm",
    )
    sm = FakeSettingsManager()
    sc = _settings(log, settings_manager=sm, input_fn=FakeInput(["kitty"]))
    # detect after update still returns xterm from monkeypatch — that's fine;
    # we only assert the setting was written and log shows confirmation.
    sc.configure_external_terminal()
    assert any(u["key"] == "terminal" and u["value"] == "kitty" for u in sm.updates)
    assert any("External Terminal" in l for l in log)


def test_configure_external_terminal_keep(log, monkeypatch):
    monkeypatch.setattr(
        "core.utils.external_terminal.list_available",
        lambda: ["xterm", "tail"],
    )
    monkeypatch.setattr(
        "core.utils.external_terminal.detect",
        lambda settings=None: "xterm",
    )
    sm = FakeSettingsManager()
    sc = _settings(log, settings_manager=sm, input_fn=FakeInput([""]))
    sc.configure_external_terminal()
    assert not any(u["key"] == "terminal" for u in sm.updates)
    assert any("unchanged" in l for l in log)


def test_configure_scan_font_scale(log, monkeypatch):
    monkeypatch.delenv("KFIOSA_SCAN_FONT_SCALE", raising=False)
    sm = FakeSettingsManager()
    sc = _settings(log, settings_manager=sm, input_fn=FakeInput(["2.0"]))
    sc.configure_scan_font_scale()
    assert any(
        u["key"] == "scanning.font_scale" and u["value"] == 2.0
        for u in sm.updates
    )
    assert any("font scale set to 2.0" in l for l in log)
    # restore default for other tests
    from core.utils.external_terminal import set_scan_font_scale
    set_scan_font_scale(1.0)


def test_configure_scan_font_scale_invalid(log):
    sm = FakeSettingsManager()
    sc = _settings(log, settings_manager=sm, input_fn=FakeInput(["nope"]))
    sc.configure_scan_font_scale()
    assert any("Enter a number" in l for l in log)


def test_print_settings(log):
    sc = _settings(log)
    sc.print_settings()
    assert any("Current Configuration Profile" in l for l in log)


def test_reset_settings_confirmed(log):
    sm = FakeSettingsManager()
    sc = _settings(log, settings_manager=sm, input_fn=FakeInput(["RESET"]))
    sc.reset_settings()
    assert sm.resets == 1
    assert any("reset to default" in l for l in log)


def test_reset_settings_canceled(log):
    sm = FakeSettingsManager()
    sc = _settings(log, settings_manager=sm, input_fn=FakeInput(["no"]))
    sc.reset_settings()
    assert sm.resets == 0
    assert any("Reset canceled" in l for l in log)


def test_toggle_vision_os_learning(log):
    sm = FakeSettingsManager()
    sc = _settings(log, settings_manager=sm, thread_runner=sync_thread_runner)
    sc.toggle_vision_os_learning()
    assert any(u["key"] == "vision_os_learning.enabled" for u in sm.updates)
    assert any("AI Vision OS Navigation & UI Auto-Labeling" in l for l in log)
    assert any("Active learning started" in l for l in log)