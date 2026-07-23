"""Post-exploit is auto-attached to engagement chains — not a main TUI mode."""
from __future__ import annotations

from core.tui.dashboard import KfiosaDashboard
from core.tui.wifi_screen import WiFiScreen
from core.tui.ble_screen import BLEScreen
from tests.conftest import _make_screen
from tests.fakes import FakeOrchestrator


def test_main_menu_has_no_post_exploit_entry():
    import inspect
    src = inspect.getsource(KfiosaDashboard.__init__)
    assert '"Post-exploit"' not in src and "'Post-exploit'" not in src
    assert "wifi" in src and "ble" in src


def test_wifi_advanced_has_no_standalone_pe_menu(log):
    sc = _make_screen(WiFiScreen, log, orchestrator=FakeOrchestrator())
    labels = [x[0] for x in sc.advanced_items]
    assert not any("Post-Exploit" in lab for lab in labels)
    assert not any("Post-exploit" in lab for lab in labels)


def test_ble_advanced_has_no_standalone_pe_menu(log):
    sc = _make_screen(BLEScreen, log, orchestrator=FakeOrchestrator())
    labels = [x[0] for x in sc.advanced_items]
    assert not any("Post-Exploit" in lab for lab in labels)


def test_wifi_run_adaptive_seed_has_attach_post_exploit(log, monkeypatch):
    sc = _make_screen(WiFiScreen, log, orchestrator=FakeOrchestrator())
    sc.interface = "wlan0mon"
    sc.selected_target = {"bssid": "AA:BB:CC:DD:EE:FF", "ssid": "lab"}
    captured = {}

    class FakeEng:
        def __init__(self, *a, **k):
            pass

        def run(self, domain, target, **kw):
            captured["target"] = dict(target)
            return {"access": {"achieved": False}, "adaptive": {"cycles": []}}

    monkeypatch.setattr(
        "core.orchestrator.engagement_engine.EngagementEngine", FakeEng,
    )
    # run sync
    sc._spawn = lambda fn: fn()
    sc._run_adaptive(until_access=True)
    assert captured["target"].get("attach_post_exploit") is True
    assert captured["target"].get("post_exploit") is True


def test_ble_run_adaptive_seed_has_attach_post_exploit(log, monkeypatch):
    sc = _make_screen(BLEScreen, log, orchestrator=FakeOrchestrator())
    sc.selected_device = {"address": "11:22:33:44:55:66", "name": "sensor"}
    sc.selected_target = sc.selected_device
    captured = {}

    class FakeEng:
        def __init__(self, *a, **k):
            pass

        def run(self, domain, target, **kw):
            captured["target"] = dict(target)
            return {"access": {"achieved": False}, "adaptive": {"cycles": []}}

    monkeypatch.setattr(
        "core.orchestrator.engagement_engine.EngagementEngine", FakeEng,
    )
    sc._spawn = lambda fn: fn()
    sc._run_adaptive(until_access=True)
    assert captured["target"].get("attach_post_exploit") is True
    assert captured["target"].get("post_exploit") is True
