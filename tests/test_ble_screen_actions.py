"""BLEScreen actions — curses-free, one test per action."""

import shutil
import subprocess
import sys
import types

import pytest

from core.tui.ble_screen import BLEScreen
from tests.conftest import _make_screen
from tests.fakes import (
    FakeBLEScanner, FakeConfirmFn, FakeInput, FakeKB, FakeOrchestrator,
    FakePostRunner, sync_thread_runner,
)


def _ble(log, **over):
    over.setdefault("scanner_cls", FakeBLEScanner)
    return _make_screen(BLEScreen, log, **over)


def test_scan_finds_devices_and_enters_targets(log):
    sc = _ble(log)
    sc.scan_ble_devices()
    assert len(sc.ble_devices) == 2
    assert sc.flow_state == "targets"
    assert sc.menu_items[0][0].startswith("1. Bandage-1")
    assert any("Found 2 BLE devices" in l for l in log)


def test_scan_no_devices(log):
    sc = _ble(log, scanner_cls=lambda: FakeBLEScanner(devices=[], error=None))
    sc.scan_ble_devices()
    assert sc.ble_devices == []
    assert any("No BLE devices discovered" in l for l in log)


def test_scan_error(log):
    sc = _ble(log, scanner_cls=lambda: FakeBLEScanner(error="adapter down"))
    sc.scan_ble_devices()
    assert any("Scan error: adapter down" in l for l in log)


def test_select_target_sets_device_and_target(log):
    sc = _ble(log)
    sc.scan_ble_devices()
    sc.select_target_by_index(0)
    assert sc.selected_device and sc.selected_device["address"].endswith("EE:F1")
    assert sc.selected_target == sc.selected_device
    assert sc.flow_state == "menu"


def test_run_attack_chain_calls_orchestrator(log):
    orch = FakeOrchestrator()
    sc = _ble(log, orchestrator=orch)
    sc.scan_ble_devices()
    sc.select_target_by_index(0)
    sc.run_attack_chain()
    assert orch.runs[0]["domain"] == "ble"


def test_run_attack_chain_no_device(log):
    sc = _ble(log)
    sc.run_attack_chain()
    assert any("Select a BLE device first" in l for l in log)


def test_connect_and_enumerate(monkeypatch, log):
    sc = _ble(log)
    sc.scan_ble_devices()
    monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/gatttool" if name == "gatttool" else None)

    class FakeCP:
        returncode = 0
        stdout = "handle: 0x0002 char: uuid\nhandle: 0x0005 char: uuid2"
        stderr = ""

    monkeypatch.setattr(subprocess, "run", lambda *a, **k: FakeCP())
    sc.input_fn = FakeInput(["AA:BB:CC:DD:EE:F1"])
    sc.connect_and_enumerate()
    assert sc.selected_device["address"].endswith("EE:F1")
    assert any("gatttool rc=0" in l for l in log)


def test_connect_unknown_device(log):
    sc = _ble(log)
    sc.scan_ble_devices()
    sc.input_fn = FakeInput(["00:11:22:33:44:55"])
    sc.connect_and_enumerate()
    assert any("not found in scan results" in l for l in log)


def test_connect_without_scan(log):
    sc = _ble(log)
    sc.input_fn = FakeInput(["AA:BB:CC:DD:EE:F1"])
    sc.connect_and_enumerate()
    assert any("perform BLE scan first" in l for l in log)


def test_ai_risk_assessment(log):
    sc = _ble(log)
    sc.scan_ble_devices()
    sc.run_ai_risk_assessment()
    assert any("AI BLE Risk Profile" in l for l in log)


def test_ai_risk_assessment_no_device(log):
    sc = _ble(log, scanner_cls=lambda: FakeBLEScanner(devices=[]))
    sc.run_ai_risk_assessment()
    assert any("Run scan first" in l for l in log)


def test_plan_post_exploit_with_session(log):
    sc = _ble(log, post_runner=FakePostRunner(msf_steps=[{"desc": "s1"}]),
              input_fn=FakeInput(["sess-1"]))
    sc.scan_ble_devices()
    sc.select_target_by_index(0)
    sc.plan_post_exploit()
    assert sc._post_plan["msf_plan"] is not None
    assert any("MSF plan: 1 steps" in l for l in log)


def test_execute_post_exploit_no_plan(log):
    sc = _ble(log)
    sc.execute_post_exploit()
    assert any("No MSF plan to execute" in l for l in log)


def test_show_kb_tools(log):
    sc = _ble(log, kb=FakeKB())
    sc.show_kb_tools()
    assert any("KB BLE tools" in l for l in log)


def test_pick_adapter(monkeypatch, log):
    fake_mod = types.ModuleType("core.tui.interface_picker")
    fake_mod.pick_ble_interface = lambda stdscr, alog: "hci0"
    monkeypatch.setitem(sys.modules, "core.tui.interface_picker", fake_mod)
    sc = _ble(log)
    sc.pick_adapter()
    assert sc.interface == "hci0"
    assert any("Selected BLE adapter: hci0" in l for l in log)