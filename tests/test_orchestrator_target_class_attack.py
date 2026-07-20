"""Tests for the orchestrator's microsoft_attack / android_attack /
ios_attack dispatchers.

Covers:
  * the AI-driven ``microsoft_attack`` / ``android_attack`` /
    ``ios_attack`` actions in ``_walk_ai_step``
  * the dispatcher honors unknown methods and exceptions
  * seed merge behavior (``seed["<target_class>"][<method>]``)
  * the dispatcher strips ``microsoft_attack_<method>`` / etc. prefix
    from the AI's tool-name-style method argument

The Phase 2.0.M0+A0+I0 dispatcher tests.
"""
from __future__ import annotations

import inspect
import re

import pytest


# ---------------------------------------------------------------------------
# Single-gate invariant for the 3 new dispatchers
# ---------------------------------------------------------------------------

class TestSingleGate:

    def _body(self, name):
        from core.orchestrator import autonomous_orchestrator as mod
        src = inspect.getsource(mod)
        i = src.find(f"def {name}")
        j = src.find("\n    def ", i + 1)
        if j < 0:
            j = len(src)
        return src[i:j]

    def _has_reconfirm(self, body):
        cleaned = re.sub(r"confirm_fn\s*=\s*[^,)\s]+", "", body)
        return "confirm_fn" in cleaned or "self.confirm" in cleaned

    def test_microsoft_no_reconfirm(self):
        body = self._body("_dispatch_microsoft_attack")
        assert not self._has_reconfirm(body), (
            f"microsoft_attack dispatcher re-confirms: {body[:200]}...")

    def test_android_no_reconfirm(self):
        body = self._body("_dispatch_android_attack")
        assert not self._has_reconfirm(body), (
            f"android_attack dispatcher re-confirms: {body[:200]}...")

    def test_ios_no_reconfirm(self):
        body = self._body("_dispatch_ios_attack")
        assert not self._has_reconfirm(body), (
            f"ios_attack dispatcher re-confirms: {body[:200]}...")


# ---------------------------------------------------------------------------
# Fake results + dispatcher behavior
# ---------------------------------------------------------------------------

def _ok_microsoft_result(method="nmap_smb_rpc_winrm_discovery"):
    return {
        "name": method, "ok": True,
        "data": {"target": "10.10.10.1", "open_count": 3,
                 "summary": {"smb_open": True}},
        "error": "", "duration_s": 0.1,
    }


def _ok_android_result(method="adb_devices_list"):
    return {
        "name": method, "ok": True,
        "data": {"device_count": 1, "ready": [{"serial": "emulator-5554",
                                                "state": "device"}]},
        "error": "", "duration_s": 0.1,
    }


def _ok_ios_result(method="libimobiledevice_list_devices"):
    return {
        "name": method, "ok": True,
        "data": {"device_count": 1,
                 "devices": [{"udid": "00008101001234567890abcdef0102030a0b0c0d"}]},
        "error": "", "duration_s": 0.1,
    }


class _FakeResult:
    def __init__(self, d):
        self._d = d

    def __getitem__(self, k):
        return self._d[k]

    def get(self, k, default=None):
        return self._d.get(k, default)


def _make_orchestrator(monkeypatch, target_class: str,
                        fake_run_attack):
    """Build an AutonomousOrchestrator with a faked runner."""
    from core.orchestrator.autonomous_orchestrator import AutonomousOrchestrator
    from tests.fakes import FakeAIBackend

    if target_class == "microsoft":
        import core.microsoft.runner as m
        monkeypatch.setattr(m, "run_attack", fake_run_attack)
    elif target_class == "android":
        import core.android.runner as m
        monkeypatch.setattr(m, "run_attack", fake_run_attack)
    elif target_class == "ios":
        import core.ios.runner as m
        monkeypatch.setattr(m, "run_attack", fake_run_attack)
    return AutonomousOrchestrator(
        ai_backend=FakeAIBackend(),
        confirm_fn=lambda p: True,
        on_event=lambda m: None,
    )


class TestMicrosoftDispatcher:
    def test_records_step_and_merges_seed(self, monkeypatch):
        def fake_run_attack(method, *a, **kw):
            return _FakeResult(_ok_microsoft_result(method))
        o = _make_orchestrator(monkeypatch, "microsoft", fake_run_attack)
        seed = {}
        report = {"executed": [], "skipped": [], "access": {}}
        step = {"action": "microsoft_attack",
                "args": {"method": "nmap_smb_rpc_winrm_discovery",
                         "target": "10.10.10.1"}}
        o._dispatch_microsoft_attack(step, seed, report)
        assert len(report["executed"]) == 1
        e = report["executed"][0]
        assert e["action"] == "microsoft_attack"
        assert e["method"] == "nmap_smb_rpc_winrm_discovery"
        assert e["ok"] is True
        assert "microsoft" in seed
        assert "nmap_smb_rpc_winrm_discovery" in seed["microsoft"]

    def test_unknown_method(self, monkeypatch):
        called = {"n": 0}

        def fake_run_attack(method, *a, **kw):
            called["n"] += 1
            return _FakeResult({"name": method, "ok": False,
                                "error": "x", "data": None,
                                "duration_s": 0.0})
        o = _make_orchestrator(monkeypatch, "microsoft", fake_run_attack)
        report = {"executed": [], "skipped": [], "access": {}}
        o._dispatch_microsoft_attack(
            {"action": "microsoft_attack",
             "args": {"method": "nope"}}, {}, report)
        assert report["executed"] == []
        assert "microsoft" not in report
        assert called["n"] == 0
        assert any("microsoft_attack" in s for s in report["skipped"])

    def test_runner_exception(self, monkeypatch):
        def fake_run_attack(method, *a, **kw):
            raise RuntimeError("kaboom")
        o = _make_orchestrator(monkeypatch, "microsoft", fake_run_attack)
        report = {"executed": [], "skipped": [], "access": {}}
        o._dispatch_microsoft_attack(
            {"action": "microsoft_attack",
             "args": {"method": "nmap_smb_rpc_winrm_discovery",
                      "target": "10.10.10.1"}}, {}, report)
        assert report["executed"] == []
        assert any("kaboom" in s for s in report["skipped"])

    def test_stripped_prefix(self, monkeypatch):
        seen = {"method": None}

        def fake_run_attack(method, *a, **kw):
            seen["method"] = method
            return _FakeResult(_ok_microsoft_result(method))
        o = _make_orchestrator(monkeypatch, "microsoft", fake_run_attack)
        report = {"executed": [], "skipped": [], "access": {}}
        o._dispatch_microsoft_attack(
            {"action": "microsoft_attack",
             "args": {"method": "microsoft_attack_nmap_smb_rpc_winrm_discovery",
                      "target": "10.10.10.1"}}, {}, report)
        assert seen["method"] == "nmap_smb_rpc_winrm_discovery"


class TestAndroidDispatcher:
    def test_records_step_and_merges_seed(self, monkeypatch):
        def fake_run_attack(method, *a, **kw):
            return _FakeResult(_ok_android_result(method))
        o = _make_orchestrator(monkeypatch, "android", fake_run_attack)
        seed = {}
        report = {"executed": [], "skipped": [], "access": {}}
        step = {"action": "android_attack",
                "args": {"method": "adb_devices_list"}}
        o._dispatch_android_attack(step, seed, report)
        assert len(report["executed"]) == 1
        e = report["executed"][0]
        assert e["action"] == "android_attack"
        assert "android" in seed
        assert "adb_devices_list" in seed["android"]

    def test_unknown_method(self, monkeypatch):
        def fake_run_attack(method, *a, **kw):
            raise AssertionError("should not be called")
        o = _make_orchestrator(monkeypatch, "android", fake_run_attack)
        report = {"executed": [], "skipped": [], "access": {}}
        o._dispatch_android_attack(
            {"action": "android_attack", "args": {"method": "nope"}},
            {}, report)
        assert report["executed"] == []
        assert any("android_attack" in s for s in report["skipped"])

    def test_runner_exception(self, monkeypatch):
        def fake_run_attack(method, *a, **kw):
            raise RuntimeError("kaboom")
        o = _make_orchestrator(monkeypatch, "android", fake_run_attack)
        report = {"executed": [], "skipped": [], "access": {}}
        o._dispatch_android_attack(
            {"action": "android_attack",
             "args": {"method": "adb_devices_list"}}, {}, report)
        assert report["executed"] == []
        assert any("kaboom" in s for s in report["skipped"])

    def test_stripped_prefix(self, monkeypatch):
        seen = {"method": None}

        def fake_run_attack(method, *a, **kw):
            seen["method"] = method
            return _FakeResult(_ok_android_result(method))
        o = _make_orchestrator(monkeypatch, "android", fake_run_attack)
        report = {"executed": [], "skipped": [], "access": {}}
        o._dispatch_android_attack(
            {"action": "android_attack",
             "args": {"method": "android_attack_adb_devices_list"}},
            {}, report)
        assert seen["method"] == "adb_devices_list"


class TestIosDispatcher:
    def test_records_step_and_merges_seed(self, monkeypatch):
        def fake_run_attack(method, *a, **kw):
            return _FakeResult(_ok_ios_result(method))
        o = _make_orchestrator(monkeypatch, "ios", fake_run_attack)
        seed = {}
        report = {"executed": [], "skipped": [], "access": {}}
        step = {"action": "ios_attack",
                "args": {"method": "libimobiledevice_list_devices"}}
        o._dispatch_ios_attack(step, seed, report)
        assert len(report["executed"]) == 1
        e = report["executed"][0]
        assert e["action"] == "ios_attack"
        assert "ios" in seed
        assert "libimobiledevice_list_devices" in seed["ios"]

    def test_unknown_method(self, monkeypatch):
        def fake_run_attack(method, *a, **kw):
            raise AssertionError("should not be called")
        o = _make_orchestrator(monkeypatch, "ios", fake_run_attack)
        report = {"executed": [], "skipped": [], "access": {}}
        o._dispatch_ios_attack(
            {"action": "ios_attack", "args": {"method": "nope"}},
            {}, report)
        assert report["executed"] == []
        assert any("ios_attack" in s for s in report["skipped"])

    def test_runner_exception(self, monkeypatch):
        def fake_run_attack(method, *a, **kw):
            raise RuntimeError("kaboom")
        o = _make_orchestrator(monkeypatch, "ios", fake_run_attack)
        report = {"executed": [], "skipped": [], "access": {}}
        o._dispatch_ios_attack(
            {"action": "ios_attack",
             "args": {"method": "libimobiledevice_list_devices"}},
            {}, report)
        assert report["executed"] == []
        assert any("kaboom" in s for s in report["skipped"])

    def test_stripped_prefix(self, monkeypatch):
        seen = {"method": None}

        def fake_run_attack(method, *a, **kw):
            seen["method"] = method
            return _FakeResult(_ok_ios_result(method))
        o = _make_orchestrator(monkeypatch, "ios", fake_run_attack)
        report = {"executed": [], "skipped": [], "access": {}}
        o._dispatch_ios_attack(
            {"action": "ios_attack",
             "args": {"method": "ios_attack_libimobiledevice_list_devices"}},
            {}, report)
        assert seen["method"] == "libimobiledevice_list_devices"


# ---------------------------------------------------------------------------
# _walk_ai_step routing
# ---------------------------------------------------------------------------

class TestWalkAIStep:
    def test_walk_routes_microsoft(self, monkeypatch):
        from core.orchestrator.autonomous_orchestrator import AutonomousOrchestrator
        from tests.fakes import FakeAIBackend
        import core.microsoft.runner as m

        def fake_run_attack(method, *a, **kw):
            return _FakeResult(_ok_microsoft_result(method))
        monkeypatch.setattr(m, "run_attack", fake_run_attack)
        o = AutonomousOrchestrator(
            ai_backend=FakeAIBackend(),
            confirm_fn=lambda p: True,
            on_event=lambda m: None,
        )
        seed = {}
        report = {"executed": [], "skipped": [], "access": {}}
        o._walk_ai_step(
            {"action": "microsoft_attack",
             "args": {"method": "nmap_smb_rpc_winrm_discovery",
                      "target": "10.10.10.1"}},
            seed, report, autonomous=True)
        assert any(e.get("action") == "microsoft_attack"
                   for e in report["executed"])
        assert "microsoft" in seed

    def test_walk_routes_android(self, monkeypatch):
        from core.orchestrator.autonomous_orchestrator import AutonomousOrchestrator
        from tests.fakes import FakeAIBackend
        import core.android.runner as m

        def fake_run_attack(method, *a, **kw):
            return _FakeResult(_ok_android_result(method))
        monkeypatch.setattr(m, "run_attack", fake_run_attack)
        o = AutonomousOrchestrator(
            ai_backend=FakeAIBackend(),
            confirm_fn=lambda p: True,
            on_event=lambda m: None,
        )
        seed = {}
        report = {"executed": [], "skipped": [], "access": {}}
        o._walk_ai_step(
            {"action": "android_attack",
             "args": {"method": "adb_devices_list"}},
            seed, report, autonomous=True)
        assert any(e.get("action") == "android_attack"
                   for e in report["executed"])
        assert "android" in seed

    def test_walk_routes_ios(self, monkeypatch):
        from core.orchestrator.autonomous_orchestrator import AutonomousOrchestrator
        from tests.fakes import FakeAIBackend
        import core.ios.runner as m

        def fake_run_attack(method, *a, **kw):
            return _FakeResult(_ok_ios_result(method))
        monkeypatch.setattr(m, "run_attack", fake_run_attack)
        o = AutonomousOrchestrator(
            ai_backend=FakeAIBackend(),
            confirm_fn=lambda p: True,
            on_event=lambda m: None,
        )
        seed = {}
        report = {"executed": [], "skipped": [], "access": {}}
        o._walk_ai_step(
            {"action": "ios_attack",
             "args": {"method": "libimobiledevice_list_devices"}},
            seed, report, autonomous=True)
        assert any(e.get("action") == "ios_attack"
                   for e in report["executed"])
        assert "ios" in seed
