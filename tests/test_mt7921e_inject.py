"""core.modules.mt7921e_tools — craft_deauth_frame / inject_deauth hermetic tests.

Exercises the scapy-import gate, the aireplay-ng --deauth fallback command
shape, the euid gate, and the all-ok scapy path — all without spawning a
real subprocess or touching a wireless adapter. Subprocess + scapy import
are monkeypatched.

Per the [[kfiosa-test-sudo]] convention, the euid-gated assertion is
marked ``root`` and run via ``sudo -u user pytest -m root``.
"""

import builtins
import os
import subprocess
from unittest import mock

import pytest

from core.modules import mt7921e_tools
from core.modules.mt7921e_tools import craft_deauth_frame, inject_deauth


# ----------------------------------------------------------------------
# craft_deauth_frame
# ----------------------------------------------------------------------
def test_craft_deauth_frame_scapy_absent(monkeypatch):
    """When scapy import fails, returns the documented fall-back error."""
    real_import = builtins.__import__

    def fake_import(name, *args, **kw):
        if name == "scapy.all" or name.startswith("scapy"):
            raise ImportError("no scapy")
        return real_import(name, *args, **kw)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    res = craft_deauth_frame("AA:BB:CC:DD:EE:01")
    assert res["ok"] is False
    assert res["error"] == "scapy not installed"


def test_craft_deauth_frame_scapy_present(monkeypatch):
    """When scapy is available, returns a non-empty bytes frame."""
    class _FakeLayer:
        def __init__(self, **kw):
            self.kw = kw
        def __truediv__(self, other):
            self.child = other
            return self
        def __bytes__(self):
            return b"\x00\x01\x02\x03deauth"

    class _FakeScapy:
        RadioTap = _FakeLayer
        Dot11 = _FakeLayer
        Dot11Deauth = _FakeLayer

    real_import = builtins.__import__

    def fake_import(name, *args, **kw):
        if name == "scapy.all":
            return _FakeScapy
        return real_import(name, *args, **kw)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    res = craft_deauth_frame("AA:BB:CC:DD:EE:01")
    assert res["ok"] is True
    assert isinstance(res["frame"], (bytes, bytearray))
    assert len(res["frame"]) > 0


# ----------------------------------------------------------------------
# inject_deauth — aireplay fallback command shape
# ----------------------------------------------------------------------
def _disable_scapy(monkeypatch):
    real_import = builtins.__import__

    def fake_import(name, *args, **kw):
        if name == "scapy.all" or name.startswith("scapy"):
            raise ImportError("no scapy")
        return real_import(name, *args, **kw)

    monkeypatch.setattr(builtins, "__import__", fake_import)


def test_inject_deauth_aireplay_fallback_command_shape(monkeypatch):
    """Scapy absent + root → aireplay-ng --deauth <count> -a <bssid> <iface>."""
    _disable_scapy(monkeypatch)
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        mt7921e_tools.shutil, "which",
        lambda name: "/usr/sbin/aireplay-ng" if name == "aireplay-ng" else None,
    )
    captured = {}

    def fake_run(cmd, **kw):
        captured["cmd"] = list(cmd)
        return {"ok": True, "stdout": "ok", "stderr": "", "returncode": 0}

    monkeypatch.setattr(mt7921e_tools, "_run", fake_run)
    res = inject_deauth("wlan0mon", "AA:BB:CC:DD:EE:01", count=5)
    assert res["ok"] is True
    assert res["method"] == "aireplay"
    assert res["count"] == 5
    assert captured["cmd"] == [
        "aireplay-ng", "--deauth", "5", "-a", "AA:BB:CC:DD:EE:01", "wlan0mon",
    ]


def test_inject_deauth_aireplay_not_installed(monkeypatch):
    _disable_scapy(monkeypatch)
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(mt7921e_tools.shutil, "which", lambda name: None)
    res = inject_deauth("wlan0mon", "AA:BB:CC:DD:EE:01")
    assert res["ok"] is False
    assert res["method"] == "aireplay"
    assert res["error"] == "aireplay-ng not installed"


def test_inject_deauth_aireplay_failure_carries_stderr(monkeypatch):
    _disable_scapy(monkeypatch)
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        mt7921e_tools.shutil, "which",
        lambda name: "/usr/sbin/aireplay-ng" if name == "aireplay-ng" else None,
    )

    def fake_run(cmd, **kw):
        return {"ok": False, "stdout": "", "stderr": "device busy",
                "returncode": 1, "error": "boom"}

    monkeypatch.setattr(mt7921e_tools, "_run", fake_run)
    res = inject_deauth("wlan0mon", "AA:BB:CC:DD:EE:01", count=3)
    assert res["ok"] is False
    assert res["method"] == "aireplay"
    assert "device busy" in res["error"]


# ----------------------------------------------------------------------
# inject_deauth — euid gate (hermetic + root-marked real-euid)
# ----------------------------------------------------------------------
def test_inject_deauth_needs_root_when_unprivileged(monkeypatch):
    """Scapy absent + euid!=0 → aireplay fallback refuses with 'needs root'."""
    _disable_scapy(monkeypatch)
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    monkeypatch.setattr(
        mt7921e_tools.shutil, "which",
        lambda name: "/usr/sbin/aireplay-ng" if name == "aireplay-ng" else None,
    )
    res = inject_deauth("wlan0mon", "AA:BB:CC:DD:EE:01")
    assert res["ok"] is False
    assert res["method"] == "aireplay"
    assert res["error"] == "needs root"


# ----------------------------------------------------------------------
# inject_deauth — scapy path success
# ----------------------------------------------------------------------
def test_inject_deauth_scapy_path_success(monkeypatch):
    """craft ok + inject_raw_frame ok for all count → method scapy."""
    monkeypatch.setattr(os, "geteuid", lambda: 0)

    # Make craft_deauth_frame succeed by faking the scapy import.
    class _FakeLayer:
        def __init__(self, **kw):
            pass
        def __truediv__(self, other):
            return self
        def __bytes__(self):
            return b"\xde\xad"

    class _FakeScapy:
        RadioTap = _FakeLayer
        Dot11 = _FakeLayer
        Dot11Deauth = _FakeLayer

    real_import = builtins.__import__

    def fake_import(name, *args, **kw):
        if name == "scapy.all":
            return _FakeScapy
        return real_import(name, *args, **kw)

    monkeypatch.setattr(builtins, "__import__", fake_import)

    calls = []

    def fake_inject_raw_frame(iface, frame, channel=None):
        calls.append({"iface": iface, "frame": frame, "channel": channel})
        return {"ok": True, "error": ""}

    monkeypatch.setattr(mt7921e_tools, "inject_raw_frame", fake_inject_raw_frame)
    res = inject_deauth("wlan0mon", "AA:BB:CC:DD:EE:01",
                        channel=6, count=4)
    assert res["ok"] is True
    assert res["method"] == "scapy"
    assert res["count"] == 4
    assert res["error"] == ""
    assert len(calls) == 4
    assert calls[0]["channel"] == 6


def test_inject_deauth_scapy_failure_falls_back_to_aireplay(monkeypatch):
    """craft ok but inject_raw_frame fails → fall back to aireplay-ng."""
    monkeypatch.setattr(os, "geteuid", lambda: 0)

    class _FakeLayer:
        def __init__(self, **kw):
            pass
        def __truediv__(self, other):
            return self
        def __bytes__(self):
            return b"\xde\xad"

    class _FakeScapy:
        RadioTap = _FakeLayer
        Dot11 = _FakeLayer
        Dot11Deauth = _FakeLayer

    real_import = builtins.__import__

    def fake_import(name, *args, **kw):
        if name == "scapy.all":
            return _FakeScapy
        return real_import(name, *args, **kw)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    monkeypatch.setattr(
        mt7921e_tools, "inject_raw_frame",
        lambda iface, frame, channel=None: {"ok": False, "error": "sendp boom"},
    )
    monkeypatch.setattr(
        mt7921e_tools.shutil, "which",
        lambda name: "/usr/sbin/aireplay-ng" if name == "aireplay-ng" else None,
    )
    monkeypatch.setattr(
        mt7921e_tools, "_run",
        lambda cmd, **kw: {"ok": True, "stdout": "ok", "stderr": "",
                           "returncode": 0},
    )
    res = inject_deauth("wlan0mon", "AA:BB:CC:DD:EE:01", count=2)
    assert res["ok"] is True
    assert res["method"] == "aireplay"


# ----------------------------------------------------------------------
# Root-marked: real euid gate
# ----------------------------------------------------------------------
@pytest.mark.root
class TestInjectDeauthRealEuid:
    """Asserts the euid gate against the real process euid. Skipped
    under the hermetic unprivileged run; exercised when the operator
    runs the root-marked subset."""

    def test_needs_root_reflects_real_euid(self, monkeypatch):
        _disable_scapy(monkeypatch)
        monkeypatch.setattr(
            mt7921e_tools.shutil, "which",
            lambda name: "/usr/sbin/aireplay-ng" if name == "aireplay-ng" else None,
        )
        res = inject_deauth("wlan0mon", "AA:BB:CC:DD:EE:01")
        if os.geteuid() == 0:
            # Root — should proceed to the _run call (stub it to succeed).
            monkeypatch.setattr(
                mt7921e_tools, "_run",
                lambda cmd, **kw: {"ok": True, "stdout": "", "stderr": "",
                                   "returncode": 0},
            )
            res = inject_deauth("wlan0mon", "AA:BB:CC:DD:EE:01")
            assert res["method"] == "aireplay"
            assert res["ok"] is True
        else:
            assert res["ok"] is False
            assert res["error"] == "needs root"


# ----------------------------------------------------------------------
# Part D: Strategy family and choose_injection_strategy
# ----------------------------------------------------------------------

def test_choose_injection_strategy():
    from core.modules.mt7921e_tools import choose_injection_strategy
    
    # WEP encryption -> arp_replay
    assert choose_injection_strategy({}, {"ssid": "VisibleSSID", "encryption": "WEP"}) == "arp_replay"
    assert choose_injection_strategy({}, {"ssid": "VisibleSSID", "encryption": "wep"}) == "arp_replay"
    
    # hidden/empty SSID -> beacon_flood
    assert choose_injection_strategy({}, {"ssid": ""}) == "beacon_flood"
    assert choose_injection_strategy({}, {"ssid": "hidden"}) == "beacon_flood"
    assert choose_injection_strategy({}, {"ssid": "<hidden>"}) == "beacon_flood"
    
    # clients present -> deauth
    assert choose_injection_strategy({}, {"ssid": "VisibleSSID", "clients": {"data": {"count": 3}}}) == "deauth"
    assert choose_injection_strategy({}, {"ssid": "VisibleSSID", "station": "00:11:22:33:44:55"}) == "deauth"
    
    # quality < 30 -> deauth
    assert choose_injection_strategy({"quality": 25}, {"ssid": "VisibleSSID"}) == "deauth"
    
    # no clients -> fakeauth
    assert choose_injection_strategy({"quality": 80}, {"ssid": "VisibleSSID", "clients": {"data": {"count": 0}}}) == "fakeauth"



def test_craft_frames_scapy_absent(monkeypatch):
    from core.modules.mt7921e_tools import craft_beacon_frame, craft_cts_frame, craft_fakeauth_frame
    _disable_scapy(monkeypatch)
    
    assert craft_beacon_frame("AA:BB:CC:DD:EE:01")["error"] == "scapy not installed"
    assert craft_cts_frame("AA:BB:CC:DD:EE:01")["error"] == "scapy not installed"
    assert craft_fakeauth_frame("AA:BB:CC:DD:EE:01", "00:11:22:33:44:55")["error"] == "scapy not installed"


def test_inject_dispatcher_routes_correctly(monkeypatch):
    from core.modules.mt7921e_tools import inject
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    
    # Mock _run for fallback / aireplay modes
    calls = []
    monkeypatch.setattr(mt7921e_tools, "_run", lambda cmd, **kw: (calls.append(cmd) or {"ok": True, "stdout": "", "stderr": "", "returncode": 0}))
    monkeypatch.setattr(mt7921e_tools.shutil, "which", lambda name: "/usr/sbin/aireplay-ng")
    _disable_scapy(monkeypatch)
    
    # arp_replay
    res = inject("wlan0mon", mode="arp_replay", bssid="AA:BB:CC:DD:EE:01", station="00:11:22:33:44:55")
    assert res["ok"] is True
    assert res["method"] == "aireplay"
    assert "arp_replay" in res["mode"]
    assert any("--arpreplay" in c for c in calls)
    
    # chopchop
    calls.clear()
    res = inject("wlan0mon", mode="chopchop", bssid="AA:BB:CC:DD:EE:01")
    assert res["ok"] is True
    assert any("--chopchop" in c for c in calls)
    
    # fragmentation
    calls.clear()
    res = inject("wlan0mon", mode="fragmentation", bssid="AA:BB:CC:DD:EE:01")
    assert res["ok"] is True
    assert any("--fragment" in c for c in calls)