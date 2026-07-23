"""WiFiScreen actions — curses-free, one test per primary/advanced action."""

import sys
import types

import pytest

from core.tui.wifi_screen import WiFiScreen
from tests.conftest import _make_screen
from tests.fakes import (
    FakeConfirmFn, FakeInput, FakeKB, FakeOrchestrator, FakePostRunner,
    FakeWiFiScanner, sync_thread_runner,
)


def _wifi(log, **over):
    over.setdefault("scanner_cls", FakeWiFiScanner)
    return _make_screen(WiFiScreen, log, **over)


# ---- primary flow ----

def test_scan_finds_aps_and_enters_targets_view(log):
    sc = _wifi(log)
    sc.interface = "wlan0"
    sc.scan_networks()
    assert sc.scan_results and len(sc.scan_results) == 2
    assert sc.flow_state == "targets"
    assert sc.menu_items[0][0].startswith("1. AP1")
    assert any("WiFi scan completed" in l for l in log)


def test_scan_without_interface_errors(log):
    sc = _wifi(log)
    sc.scan_networks()
    assert sc.scan_results == []
    assert any("No interface selected" in l for l in log)


def test_scan_error_reported_honestly(log):
    sc = _wifi(log, scanner_cls=lambda: FakeWiFiScanner(networks=[], error="no monitor mode"))
    sc.interface = "wlan0"
    sc.scan_networks()
    assert any("Scan error: no monitor mode" in l for l in log)


def test_select_target_by_index(log):
    sc = _wifi(log)
    sc.interface = "wlan0"
    sc.scan_networks()
    sc.select_target_by_index(1)
    assert sc.selected_target["ssid"] == "AP2"
    assert sc.flow_state == "menu"
    assert any("Target #2 selected" in l for l in log)


def test_select_target_out_of_range(log):
    sc = _wifi(log)
    sc.interface = "wlan0"
    sc.scan_networks()
    sc.select_target_by_index(99)
    assert sc.selected_target is None
    assert any("No target #100" in l for l in log)


def test_show_report_after_engagement(log):
    sc = _wifi(log)
    sc.interface = "wlan0"
    sc.scan_networks()
    sc.select_target_by_index(0)
    sc.show_report()
    assert any("Last WiFi Engagement Report" in l for l in log)
    assert any("AP1" in l for l in log)


def test_list_devices_no_recon_prompts_to_run(log):
    sc = _wifi(log)
    sc.list_devices()
    assert any("No devices yet" in l for l in log)


def test_list_devices_picks_and_stashes_mac(monkeypatch, log):
    from core.tui import device_screen
    devices = [{"mac": "AA:BB:CC:00:00:07", "power": "-50",
                 "probes": "X", "packets": "5", "bssid": "AA:BB:CC:DD:EE:01"}]
    monkeypatch.setattr(device_screen, "pick_device",
                        lambda stdscr, alog, dev: dev[0]["mac"])
    sc = _wifi(log)
    sc._last_recon = {"clients": {"data": {"count": 1, "clients": devices}}}
    sc.list_devices()
    assert getattr(sc, "selected_device_mac", None) == "AA:BB:CC:00:00:07"
    assert any("staged for targeted" in l for l in log)


# ---- one-click attack ----

def test_one_click_requires_target(log):
    sc = _wifi(log)
    sc.interface = "wlan0"
    sc.one_click_attack()
    assert any("Select a target first" in l for l in log)


def test_one_click_builds_wpa3_plan_and_runs_chain(log):
    orch = FakeOrchestrator()
    sc = _wifi(log, orchestrator=orch)
    sc.interface = "wlan0"
    sc.adapter_caps = {"mt7921e": True, "injection_capable": True}
    sc.scan_networks()
    sc.select_target_by_index(0)
    # Force WPA3-SAE on the selected AP for the planner branch.
    sc.selected_target["encryption"] = "WPA3-SAE"
    sc.selected_target["pmf"] = True
    sc.one_click_attack()
    assert sc._last_one_click_plan is not None
    assert sc._last_one_click_plan.get("is_sae") is True
    assert "sae_frame_capture" in [
        s["id"] for s in sc._last_one_click_plan.get("steps") or []
    ]
    assert any("One-click plan" in l for l in log)
    assert orch.runs and orch.runs[0]["domain"] == "wifi"


def test_primary_menu_has_one_click_first(log):
    sc = _wifi(log)
    labels = [item[0] for item in sc.primary_items]
    assert any("ATTACK" in lab for lab in labels)
    assert any(lab.startswith("▶") for lab in labels)


def test_aio_attack_requires_target(log):
    sc = _wifi(log, orchestrator=FakeOrchestrator())
    sc._no_external_load = True
    sc.interface = "wlan0"
    sc.aio_attack()
    assert any("Select a target first" in l for l in log)


def test_aio_attack_runs_orchestrator_with_zero_day(log):
    orch = FakeOrchestrator()
    sc = _wifi(log, orchestrator=orch)
    sc.interface = "wlan0"
    sc.scan_networks()
    sc.select_target_by_index(0)
    sc.selected_target["encryption"] = "WPA3-SAE"
    sc.aio_attack()
    assert sc.attach_zero_day is True
    assert orch.runs and orch.runs[0]["domain"] == "wifi"
    assert orch.runs[0]["target"].get("aio") is True
    assert any("AIO" in l for l in log)


# ---- attack chain ----

def test_run_attack_chain_calls_orchestrator(log):
    orch = FakeOrchestrator()
    sc = _wifi(log, orchestrator=orch)
    sc.interface = "wlan0"
    sc.scan_networks()
    sc.select_target_by_index(0)
    sc.run_attack_chain()
    assert orch.runs and orch.runs[0]["domain"] == "wifi"
    assert orch.runs[0]["target"].get("interface") == "wlan0"


def test_run_attack_chain_no_target(log):
    sc = _wifi(log)
    sc.run_attack_chain()
    assert any("Select a target first" in l for l in log)


def test_run_attack_chain_no_orchestrator(log):
    sc = _wifi(log, orchestrator=None)
    sc.selected_target = {"ssid": "x", "bssid": "aa"}
    sc.run_attack_chain()
    assert any("Orchestrator unavailable" in l for l in log)


# ---- advanced: AI plan + post-exploit ----

def test_generate_attack_plan(log):
    sc = _wifi(log)
    sc.selected_target = {"ssid": "AP1", "encryption": "WPA2", "channel": 6, "vendor": "V"}
    sc.generate_attack_plan()
    assert any("AI Wireless Attack Plan" in l for l in log)


def test_generate_attack_plan_no_target(log):
    sc = _wifi(log)
    sc.generate_attack_plan()
    assert any("select a target first" in l for l in log)


def test_plan_post_exploit_no_session(log):
    sc = _wifi(log)
    sc.selected_target = {"ssid": "AP1", "bssid": "aa", "channel": 6}
    sc.plan_post_exploit()
    assert sc._post_plan is not None
    assert sc._post_plan["msf_plan"] is None
    assert any("AI Post-Exploit Plan" in l for l in log)


def test_plan_post_exploit_with_session(log):
    sc = _wifi(log, post_runner=FakePostRunner(msf_steps=[{"desc": "s1"}]),
               input_fn=FakeInput(["session-7"]))
    sc.selected_target = {"ssid": "AP1", "bssid": "aa", "channel": 6}
    sc.plan_post_exploit()
    assert sc._post_plan["msf_plan"] is not None
    assert sc._post_plan["msf_plan"]["steps"]
    assert any("MSF plan: 1 steps" in l for l in log)


def test_execute_post_exploit_no_plan(log):
    sc = _wifi(log)
    sc.execute_post_exploit()
    assert any("No MSF plan to execute" in l for l in log)


def test_execute_post_exploit_with_plan(log):
    pr = FakePostRunner(msf_steps=[{"desc": "s1"}])
    sc = _wifi(log, post_runner=pr, input_fn=FakeInput(["session-1"]))
    sc.selected_target = {"ssid": "AP1", "bssid": "aa", "channel": 6}
    sc.plan_post_exploit()
    sc.execute_post_exploit()
    assert any("step:" in l for l in log)


# ---- advanced: MSF payload ----

def test_launch_metasploit_exploit_generates_payload(log):
    pr = FakePostRunner(payload=b"\x90" * 300, mutated=b"\xcc" * 320)
    sc = _wifi(log, post_runner=pr, input_fn=FakeInput(["10.0.0.5", "4444"]))
    sc.selected_target = {"ssid": "AP1", "bssid": "aa"}
    sc.launch_metasploit_exploit()
    assert any("Base payload: 300" in l for l in log)
    assert any("Polymorphic mutation" in l for l in log)


def test_launch_metasploit_exploit_no_target(log):
    sc = _wifi(log)
    sc.launch_metasploit_exploit()
    assert any("select a target first" in l for l in log)


# ---- advanced: C2 beacon ----

def test_establish_c2_beacon(monkeypatch, log):
    fake_mod = types.ModuleType("core.c2.lab_beacon")

    class FakeBeacon:
        def __init__(self, **kw):
            self.beacon_id = "b-1"
            self.kw = kw

        def register(self):
            return {}  # no error/status → success path

        def run(self, on_task=None):
            if on_task:
                on_task("test-task")

    fake_mod.LabBeacon = FakeBeacon
    monkeypatch.setitem(sys.modules, "core.c2.lab_beacon", fake_mod)
    sc = _wifi(log, tui_confirm=FakeConfirmFn(), input_fn=FakeInput(["127.0.0.1", "8443"]))
    sc.establish_c2_beacon()
    assert any("Beacon registered" in l for l in log)
    assert any("Beacon task received: test-task" in l for l in log)


def test_establish_c2_beacon_no_gate(log):
    sc = _wifi(log, tui_confirm=None)
    sc.establish_c2_beacon()
    assert any("ACCEPT/CANCEL gate unavailable" in l for l in log)


# ---- advanced: KB tools + toolbox fetch/prepare ----

def test_show_kb_tools(log):
    sc = _wifi(log, kb=FakeKB())
    sc.show_kb_tools()
    assert any("KB WiFi tools" in l for l in log)


def test_fetch_domain_repos(monkeypatch, log):
    import subprocess

    class FakeCP:
        stdout = "cloning repo-a\ncloning repo-b"
        stderr = ""
        returncode = 0

    monkeypatch.setattr(subprocess, "run", lambda *a, **k: FakeCP())
    sc = _wifi(log)
    sc.fetch_domain_repos("wifi")
    assert any("toolboxes/wifi/ ready" in l for l in log)


def test_prepare_domain_tools(monkeypatch, log):
    import subprocess

    class FakeCP:
        stdout = "pip install ok"
        stderr = ""
        returncode = 0

    monkeypatch.setattr(subprocess, "run", lambda *a, **k: FakeCP())
    sc = _wifi(log)
    sc.prepare_domain_tools("wifi")
    assert any("wifi toolboxes prepared" in l for l in log)


# ---- pick_interface (monitor-mode name handling) ----
#
# pick_interface instantiates WiFiScanner directly via import, so we
# monkey-patch the symbol in the wifi_screen module. scan_networks uses
# the injected ``scanner_cls``, which we also wire up to a
# FakeWiFiScanner for the combined pick-then-scan test.

def _patch_pick_and_scanner(monkeypatch, ensure_monitor_result=None,
                            airmon_result=None):
    """Wire pick_wireless_interface + airmon_start + WiFiScanner + the
    mt7921e probe to fakes.

    Returns the shared FakeWiFiScanner that pick_interface will use for
    the iw+ip fallback (and that scan_networks will also call .scan on,
    if the caller injects it via ``scanner_cls``).

    ``pick_interface`` imports these symbols inside the function, so we
    patch them on their source modules — the local names in
    ``core.tui.wifi_screen`` are only ever rebound by the import.
    ``airmon_result`` defaults to a successful airmon-ng start producing
    ``wlan0mon``; the mt7921e probe is stubbed to return no adapters so no
    real ``aireplay-ng --test`` subprocess runs.
    """
    from core.tui import interface_picker
    from core.scanners import wifi_scanner
    from core.utils import airmon
    from core.modules import mt7921e_tools
    from tests.fakes import FakeWiFiScanner

    fake = FakeWiFiScanner(ensure_monitor_result=ensure_monitor_result)
    monkeypatch.setattr(interface_picker, "pick_wireless_interface",
                        lambda stdscr, log: "wlan0")
    monkeypatch.setattr(wifi_scanner, "WiFiScanner",
                        lambda interface=None: fake)
    if airmon_result is None:
        airmon_result = {"ok": True, "monitor_iface": "wlan0mon",
                         "original_iface": "wlan0", "method": "airmon",
                         "error": ""}
    monkeypatch.setattr(airmon, "airmon_start", lambda iface: airmon_result)
    # Stub the mt7921e capability probe so pick_interface never shells out
    # to aireplay-ng --test in unit tests.
    monkeypatch.setattr(mt7921e_tools, "probe_mt7921e_capabilities",
                        lambda *a, **k: [])
    return fake


def test_pick_interface_uses_airmon_name(monkeypatch, log):
    # Default airmon_start result creates wlan0mon via sudo airmon-ng start.
    sc = _wifi(log)
    _patch_pick_and_scanner(monkeypatch)
    sc.pick_interface()
    assert sc.interface == "wlan0mon"
    assert any("Monitor mode ACTIVE on wlan0mon" in l for l in log)
    assert any("Original interface wlan0 left in managed mode" in l for l in log)


def test_pick_interface_airmon_failure_keeps_original_and_remediation(monkeypatch, log):
    # airmon-ng ran but failed ("needs root" — not "not installed"), so the
    # TUI does NOT fall back to iw: it keeps self.interface as the original
    # name and appends the remediation text the operator can run by hand.
    sc = _wifi(log)
    _patch_pick_and_scanner(
        monkeypatch,
        airmon_result={"ok": False, "error": "airmon-ng needs root"},
    )
    sc.pick_interface()
    assert sc.interface == "wlan0"
    assert any("Monitor mode failed on wlan0: airmon-ng needs root" in l for l in log)
    assert any("Run one of these in a root terminal" in l for l in log)
    assert any("sudo airmon-ng start wlan0" in l for l in log)


def test_pick_interface_airmon_missing_falls_back_to_iw(monkeypatch, log):
    # airmon-ng is not installed → pick_interface falls back to the in-place
    # iw+ip monitor flip via WiFiScanner.ensure_monitor, which keeps the
    # original iface name (no wlan0mon vif is created).
    sc = _wifi(log)
    _patch_pick_and_scanner(
        monkeypatch,
        ensure_monitor_result={"ok": True, "interface": "wlan0",
                               "method": "iw"},
        airmon_result={"ok": False, "error": "airmon-ng not installed"},
    )
    sc.pick_interface()
    assert sc.interface == "wlan0"
    assert any("airmon-ng not installed" in l for l in log)
    assert any("Monitor mode ACTIVE on wlan0 (iw fallback)" in l for l in log)


def test_scan_after_pick_uses_monitor_iface(monkeypatch, log):
    # End-to-end: pick_interface finds wlan0, airmon-ng creates wlan0mon,
    # and the follow-up scan_networks call must target wlan0mon — not
    # the original wlan0. This is the regression test for the original
    # bug ("still wlan0 not wlan0mon").
    sc = _wifi(log)
    fake = _patch_pick_and_scanner(monkeypatch)
    # scan_networks uses the injected scanner_cls, not the one we patched
    # for pick_interface. Route it through the same fake so we can read
    # what iface was passed to .scan().
    sc.scanner_cls = lambda: fake

    sc.pick_interface()
    assert sc.interface == "wlan0mon"
    sc.scan_networks()
    assert fake.scan_calls, "scan() was never called"
    assert "wlan0" not in fake.scan_calls, (
        f"scan() was called on the original iface (calls={fake.scan_calls})"
    )
    assert "wlan0mon" in fake.scan_calls