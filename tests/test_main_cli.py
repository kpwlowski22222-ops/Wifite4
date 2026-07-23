#!/usr/bin/env python3
"""Tests for main.py agentic / OS-tool CLI surface (no curses)."""
from __future__ import annotations

import main as kfiosa_main


def test_cli_help_exits_zero():
    assert kfiosa_main._run_cli(["help"]) == 0
    assert kfiosa_main._run_cli([]) == 0


def test_cli_unknown_command():
    assert kfiosa_main._run_cli(["nope"]) == 2


def test_cli_holo_status_without_binary(monkeypatch):
    monkeypatch.setattr(
        "core.desktop.holo_agent._find_holo_bin", lambda: ""
    )
    # Also patch via the import path used inside _cli_holo
    import core.desktop.holo_agent as ha
    monkeypatch.setattr(ha, "_find_holo_bin", lambda: "")
    rc = kfiosa_main._cli_holo(["status"])
    assert rc == 1


def test_cli_holo_presets_lists_ble_goals():
    rc = kfiosa_main._cli_holo(["presets"])
    assert rc == 0


def test_cli_holo_run_requires_yes():
    rc = kfiosa_main._cli_holo(["run", "--goal", "open_terminal"])
    assert rc == 2


def test_cli_holo_run_dry_run(monkeypatch):
    import core.desktop.holo_agent as ha
    monkeypatch.setattr(ha, "_find_holo_bin", lambda: "/usr/bin/holo")
    rc = kfiosa_main._cli_holo(
        ["run", "--goal", "ble_long_range_prep", "--dry-run"]
    )
    assert rc == 0


def test_main_help_no_curses():
    assert kfiosa_main._main(["--help"]) == 0


def test_task_presets_cover_ble_and_wifi():
    from core.desktop.holo_agent import TASK_PRESETS
    for key in (
        "ble_long_range_prep",
        "ble_scan_cli",
        "ble_adapter_help",
        "ble_system_settings",
        "wifi_monitor_prep",
        "wifi_scan_cli",
        "install_ble_stack",
    ):
        assert key in TASK_PRESETS


def test_cli_holo_plan_requires_yes():
    rc = kfiosa_main._cli_holo(
        [
            "plan",
            "--what", "WiFi icon",
            "--where", "top panel",
            "--for", "open networks",
            "--predict", "list appears",
        ]
    )
    assert rc == 2


def test_cli_holo_plan_dry_run(monkeypatch):
    import core.desktop.holo_agent as ha
    monkeypatch.setattr(ha, "_find_holo_bin", lambda: "/usr/bin/holo")
    rc = kfiosa_main._cli_holo(
        [
            "plan",
            "--what", "WiFi icon",
            "--where", "top panel",
            "--for", "open networks",
            "--predict", "list appears",
            "--dry-run",
        ]
    )
    assert rc == 0


def test_cli_holo_plan_no_read_labels(monkeypatch):
    import core.desktop.holo_agent as ha
    monkeypatch.setattr(ha, "_find_holo_bin", lambda: "/usr/bin/holo")
    rc = kfiosa_main._cli_holo(
        [
            "plan",
            "--what", "WiFi icon",
            "--where", "top panel",
            "--for", "open networks",
            "--predict", "list appears",
            "--dry-run",
            "--no-read-labels",
        ]
    )
    assert rc == 0
