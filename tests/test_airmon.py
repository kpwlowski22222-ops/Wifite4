"""core.utils.airmon — airmon_start / airmon_stop hermetic unit tests.

Exercises the subprocess+timeout wrapper, the sudo-vs-root command
selection, the monitor-iface name parse, and the failure-safe never-raise
contract without spawning a real airmon-ng or touching a wireless adapter.

Per the [[kfiosa-test-sudo]] convention, the command-shape and parse
assertions are hermetic (monkeypatch ``os.geteuid`` + ``subprocess.run``),
while the real-euid path is marked ``root`` and run via
``sudo -u user pytest -m root``.
"""

import os
import re
import subprocess
from unittest import mock

import pytest

from core.utils import airmon
from core.utils.airmon import airmon_start, airmon_stop


# ----------------------------------------------------------------------
# Hermetic helpers
# ----------------------------------------------------------------------
class _FakeProc:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


_AIRMON_STDOUT = (
    "Found 2 processes that could cause trouble.\n"
    "Kill them before proceeding; this can be skipped with --ignore\n"
    "(mac80211 monitor mode vif enabled for [phy0]wlan0mon on phy0)\n"
    "      (mac80211 station mode vif disabled for [phy0]wlan0 on phy0)\n"
)


# ----------------------------------------------------------------------
# airmon_start — command shape (root vs sudo)
# ----------------------------------------------------------------------
def _mon_after_airmon(iface: str) -> bool:
    """Verify stub: only *mon names are monitor (pre-start managed ifaces
    return False so the idempotent already_monitor short-circuit does
    not fire before airmon-ng runs)."""
    n = (iface or "").lower()
    return n.endswith("mon") or bool(re.search(r"mon\d*$", n))


def test_airmon_start_root_no_sudo_prefix(monkeypatch):
    """When euid==0 the command is bare ``airmon-ng start <iface>``.

    ``_iw_is_monitor`` is true only for mon-named ifaces so the early
    already_monitor guard does not skip airmon-ng on ``wlan0``.
    """
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(airmon.shutil, "which", lambda name: "/usr/sbin/airmon-ng")
    monkeypatch.setattr(airmon, "_iw_is_monitor", _mon_after_airmon)
    captured = {}

    def fake_run(cmd, **kw):
        captured["cmd"] = list(cmd)
        return _FakeProc(0, _AIRMON_STDOUT, "")

    monkeypatch.setattr(subprocess, "run", fake_run)
    res = airmon_start("wlan0")
    assert res["ok"] is True
    assert res["monitor_iface"] == "wlan0mon"
    assert res["original_iface"] == "wlan0"
    assert res["method"] == "airmon"
    assert res["returncode"] == 0
    assert captured["cmd"] == ["airmon-ng", "start", "wlan0"]


def test_airmon_start_unprivileged_uses_sudo_prefix(monkeypatch):
    """When euid!=0 the command gets a ``sudo`` prefix."""
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    monkeypatch.setattr(airmon.shutil, "which", lambda name: "/usr/sbin/airmon-ng")
    monkeypatch.setattr(airmon, "_iw_is_monitor", _mon_after_airmon)
    captured = {}

    def fake_run(cmd, **kw):
        captured["cmd"] = list(cmd)
        return _FakeProc(0, _AIRMON_STDOUT.replace("wlan0mon", "wlan1mon"), "")

    monkeypatch.setattr(subprocess, "run", fake_run)
    res = airmon_start("wlan1")
    assert res["ok"] is True
    assert res["monitor_iface"] == "wlan1mon"
    assert captured["cmd"] == ["sudo", "airmon-ng", "start", "wlan1"]


# ----------------------------------------------------------------------
# airmon_start — monitor-iface parse
# ----------------------------------------------------------------------
def test_airmon_start_parses_wlan0mon_from_stdout(monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(airmon.shutil, "which", lambda name: "/usr/sbin/airmon-ng")
    monkeypatch.setattr(airmon, "_iw_is_monitor", _mon_after_airmon)
    monkeypatch.setattr(
        subprocess, "run",
        lambda cmd, **kw: _FakeProc(0, _AIRMON_STDOUT, ""),
    )
    res = airmon_start("wlan0")
    assert res["monitor_iface"] == "wlan0mon"


def test_airmon_start_parse_fallback_to_iface_mon(monkeypatch):
    """rc==0 but no parseable monitor name → fall back to <iface>mon,
    then the verify step confirms monitor mode."""
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(airmon.shutil, "which", lambda name: "/usr/sbin/airmon-ng")
    monkeypatch.setattr(airmon, "_iw_is_monitor", _mon_after_airmon)
    monkeypatch.setattr(
        subprocess, "run",
        lambda cmd, **kw: _FakeProc(0, "nothing useful here\n", ""),
    )
    res = airmon_start("wlan0")
    assert res["ok"] is True
    assert res["monitor_iface"] == "wlan0mon"


# ----------------------------------------------------------------------
# airmon_start — mt7921e verify + iw_flip fallback (monitor-mode fix)
# ----------------------------------------------------------------------
def test_airmon_start_falls_back_to_iw_flip_when_airmon_vif_not_monitor(monkeypatch):
    """mt7921e case: airmon-ng rc==0 and parses a monitor vif name, but the
    vif is NOT actually in monitor mode (``_iw_is_monitor`` False for the
    vif, True after the in-place iw flip on the original iface). The
    fallback must engage and report method='iw_flip' on the original iface."""
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(airmon.shutil, "which", lambda name: f"/usr/sbin/{name}")
    # Stateful: before flip nothing is monitor; after ``iw set type monitor``
    # on wlan0, wlan0 becomes monitor. wlan0mon never is.
    flipped = {"wlan0": False}

    def is_mon(iface):
        return bool(flipped.get(iface))

    def fake_run(cmd, **kw):
        # Detect the iw flip to monitor.
        if list(cmd)[-3:] == ["set", "type", "monitor"] or (
            len(cmd) >= 4 and cmd[-2:] == ["type", "monitor"]
        ):
            # cmd like [iw, dev, wlan0, set, type, monitor]
            if "wlan0" in cmd:
                flipped["wlan0"] = True
        if "airmon-ng" in cmd:
            return _FakeProc(0, _AIRMON_STDOUT, "")
        return _FakeProc(0, "", "")

    monkeypatch.setattr(airmon, "_iw_is_monitor", is_mon)
    monkeypatch.setattr(subprocess, "run", fake_run)
    res = airmon_start("wlan0")
    assert res["ok"] is True
    assert res["method"] == "iw_flip"
    assert res["monitor_iface"] == "wlan0"  # flip uses the original iface


def test_airmon_start_iw_flip_succeeds_when_airmon_ng_absent(monkeypatch):
    """No airmon-ng installed → try the iw flip directly on the MT7922."""
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(airmon.shutil, "which",
                        lambda name: None if name == "airmon-ng"
                        else f"/usr/sbin/{name}")
    flipped = {"done": False}

    def is_mon(iface):
        return flipped["done"] and iface == "wlan0"

    def fake_run(cmd, **kw):
        if "type" in cmd and "monitor" in cmd:
            flipped["done"] = True
        return _FakeProc(0, "", "")

    monkeypatch.setattr(airmon, "_iw_is_monitor", is_mon)
    monkeypatch.setattr(subprocess, "run", fake_run)
    res = airmon_start("wlan0")
    assert res["ok"] is True
    assert res["method"] == "iw_flip"
    assert res["monitor_iface"] == "wlan0"


def test_airmon_start_both_paths_fail_surfaces_error(monkeypatch):
    """airmon-ng rc==0 but verify fails AND the iw flip fails → ok=False
    with a concrete error mentioning both, never raises."""
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(airmon.shutil, "which", lambda name: f"/usr/sbin/{name}")
    monkeypatch.setattr(airmon, "_iw_is_monitor", lambda iface: False)
    monkeypatch.setattr(
        subprocess, "run",
        lambda cmd, **kw: _FakeProc(0, _AIRMON_STDOUT, ""),
    )
    res = airmon_start("wlan0")
    assert res["ok"] is False
    assert "monitor" in res["error"].lower()


def test_airmon_start_nonzero_returncode_is_failure(monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(airmon.shutil, "which", lambda name: "/usr/sbin/airmon-ng")
    monkeypatch.setattr(
        subprocess, "run",
        lambda cmd, **kw: _FakeProc(3, "", "airmon-ng: device busy"),
    )
    res = airmon_start("wlan0")
    assert res["ok"] is False
    assert res["monitor_iface"] is None
    assert "device busy" in res["error"]


def test_airmon_start_missing_binary(monkeypatch):
    monkeypatch.setattr(airmon.shutil, "which", lambda name: None)
    res = airmon_start("wlan0")
    assert res["ok"] is False
    assert res["error"] == "airmon-ng not installed"
    assert res["monitor_iface"] is None


def test_airmon_start_timeout_never_raises(monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(airmon.shutil, "which", lambda name: "/usr/sbin/airmon-ng")

    def boom(cmd, **kw):
        raise subprocess.TimeoutExpired(cmd, kw.get("timeout", 20))

    monkeypatch.setattr(subprocess, "run", boom)
    res = airmon_start("wlan0")
    assert res["ok"] is False
    assert "timed out" in res["error"]


def test_airmon_start_generic_exception_never_raises(monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(airmon.shutil, "which", lambda name: "/usr/sbin/airmon-ng")
    monkeypatch.setattr(
        subprocess, "run",
        lambda cmd, **kw: (_ for _ in ()).throw(RuntimeError("boom")),
    )
    res = airmon_start("wlan0")
    assert res["ok"] is False
    assert "boom" in res["error"]


# ----------------------------------------------------------------------
# airmon_stop
# ----------------------------------------------------------------------
def test_airmon_stop_root_command_shape(monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(airmon.shutil, "which", lambda name: "/usr/sbin/airmon-ng")
    captured = {}

    def fake_run(cmd, **kw):
        captured["cmd"] = list(cmd)
        return _FakeProc(0, "monitor mode vif disabled", "")

    monkeypatch.setattr(subprocess, "run", fake_run)
    res = airmon_stop("wlan0mon")
    assert res["ok"] is True
    assert captured["cmd"] == ["airmon-ng", "stop", "wlan0mon"]


def test_airmon_stop_unprivileged_uses_sudo_prefix(monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    monkeypatch.setattr(airmon.shutil, "which", lambda name: "/usr/sbin/airmon-ng")
    captured = {}

    def fake_run(cmd, **kw):
        captured["cmd"] = list(cmd)
        return _FakeProc(0, "", "")

    monkeypatch.setattr(subprocess, "run", fake_run)
    res = airmon_stop("wlan0mon")
    assert res["ok"] is True
    assert captured["cmd"] == ["sudo", "airmon-ng", "stop", "wlan0mon"]


def test_airmon_stop_failure_includes_remediation(monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(airmon.shutil, "which", lambda name: "/usr/sbin/airmon-ng")
    monkeypatch.setattr(
        subprocess, "run",
        lambda cmd, **kw: _FakeProc(1, "", "nope"),
    )
    res = airmon_stop("wlan0mon")
    assert res["ok"] is False
    assert "sudo airmon-ng stop wlan0mon" in res["error"]


def test_airmon_stop_timeout_never_raises(monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(airmon.shutil, "which", lambda name: "/usr/sbin/airmon-ng")

    def boom(cmd, **kw):
        raise subprocess.TimeoutExpired(cmd, kw.get("timeout", 15))

    monkeypatch.setattr(subprocess, "run", boom)
    res = airmon_stop("wlan0mon")
    assert res["ok"] is False
    assert "sudo airmon-ng stop wlan0mon" in res["error"]


def test_airmon_stop_missing_binary(monkeypatch):
    """No airmon-ng and no iw/ip → honest failure with remediation hint."""
    monkeypatch.setattr(airmon.shutil, "which", lambda name: None)
    res = airmon_stop("wlan0mon")
    assert res["ok"] is False
    # Implementation falls back to iw managed flip; when iw/ip are also
    # missing the error names that path and still includes the manual
    # airmon-ng stop remediation.
    err = res["error"] or ""
    assert "iw or ip not installed" in err or "airmon-ng" in err
    assert "sudo airmon-ng stop wlan0mon" in err or "set type managed" in err


# ----------------------------------------------------------------------
# Root-marked: real euid path (run via `sudo -u user pytest -m root`)
# ----------------------------------------------------------------------
@pytest.mark.root
class TestAirmonRealEuid:
    """Asserts the command selection against the *real* process euid,
    not a monkeypatched one. Skipped under the hermetic unprivileged
    run; exercised when the operator runs the root-marked subset."""

    def test_start_command_matches_real_euid(self, monkeypatch):
        monkeypatch.setattr(airmon.shutil, "which", lambda name: "/usr/sbin/airmon-ng")
        # Only mon ifaces report monitor so airmon-ng actually runs.
        monkeypatch.setattr(airmon, "_iw_is_monitor", _mon_after_airmon)
        captured = {}
        monkeypatch.setattr(
            subprocess, "run",
            lambda cmd, **kw: (captured.__setitem__("cmd", list(cmd)),
                               _FakeProc(0, _AIRMON_STDOUT, ""))[1],
        )
        res = airmon_start("wlan0")
        assert res["ok"] is True
        assert "cmd" in captured
        if os.geteuid() == 0:
            assert captured["cmd"] == ["airmon-ng", "start", "wlan0"]
        else:
            assert captured["cmd"] == ["sudo", "airmon-ng", "start", "wlan0"]

    def test_stop_command_matches_real_euid(self, monkeypatch):
        monkeypatch.setattr(airmon.shutil, "which", lambda name: "/usr/sbin/airmon-ng")
        captured = {}
        monkeypatch.setattr(
            subprocess, "run",
            lambda cmd, **kw: (captured.__setitem__("cmd", list(cmd)),
                               _FakeProc(0, "", ""))[1],
        )
        res = airmon_stop("wlan0mon")
        assert res["ok"] is True
        if os.geteuid() == 0:
            assert captured["cmd"] == ["airmon-ng", "stop", "wlan0mon"]
        else:
            assert captured["cmd"] == ["sudo", "airmon-ng", "stop", "wlan0mon"]