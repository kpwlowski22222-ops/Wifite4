"""Tests for ``core.utils.wifi_iface`` — monitor-mode detection +
``MonitorModeRequired`` remediation.

Most of these tests run unprivileged (mocking ``shutil.which`` /
``subprocess.run``). The actual ``iw dev <iface> info`` call is
exercised by ``test_wifi_iface_root.py`` under the ``root`` marker
(``sudo -u user pytest -m root ...``).
"""

import subprocess
from unittest import mock

import pytest

from core.utils.wifi_iface import (
    MonitorModeRequired, iface_current_mode, is_monitor_capable,
    assert_monitor_mode,
)


def test_iface_current_mode_parses_monitor():
    fake_output = """Interface wlan0
	ifindex 3
	type monitor
	wiphy 0
	addr aa:bb:cc:dd:ee:ff
"""
    fake = mock.MagicMock()
    fake.returncode = 0
    fake.stdout = fake_output
    with mock.patch("core.utils.wifi_iface.shutil.which", return_value="/usr/sbin/iw"), \
         mock.patch("core.utils.wifi_iface.subprocess.run", return_value=fake):
        assert iface_current_mode("wlan0") == "monitor"


def test_iface_current_mode_parses_managed():
    fake_output = """Interface wlan0
	ifindex 3
	type managed
"""
    fake = mock.MagicMock()
    fake.returncode = 0
    fake.stdout = fake_output
    with mock.patch("core.utils.wifi_iface.shutil.which", return_value="/usr/sbin/iw"), \
         mock.patch("core.utils.wifi_iface.subprocess.run", return_value=fake):
        assert iface_current_mode("wlan0") == "managed"


def test_iface_current_mode_returns_error_when_iw_missing():
    with mock.patch("core.utils.wifi_iface.shutil.which", return_value=None):
        assert iface_current_mode("wlan0") == "error"


def test_iface_current_mode_returns_error_when_iw_nonzero_rc():
    fake = mock.MagicMock()
    fake.returncode = 234
    fake.stdout = ""
    with mock.patch("core.utils.wifi_iface.shutil.which", return_value="/usr/sbin/iw"), \
         mock.patch("core.utils.wifi_iface.subprocess.run", return_value=fake):
        assert iface_current_mode("wlan0") == "error"


def test_iface_current_mode_returns_unknown_when_type_field_missing():
    fake = mock.MagicMock()
    fake.returncode = 0
    fake.stdout = "Interface wlan0\n\tifindex 3\n"
    with mock.patch("core.utils.wifi_iface.shutil.which", return_value="/usr/sbin/iw"), \
         mock.patch("core.utils.wifi_iface.subprocess.run", return_value=fake):
        assert iface_current_mode("wlan0") == "unknown"


def test_iface_current_mode_handles_empty_iface():
    assert iface_current_mode("") == "error"


def test_assert_monitor_mode_passes_when_already_monitor():
    fake = mock.MagicMock()
    fake.returncode = 0
    fake.stdout = "Interface wlan0\n\ttype monitor\n"
    with mock.patch("core.utils.wifi_iface.shutil.which", return_value="/usr/sbin/iw"), \
         mock.patch("core.utils.wifi_iface.subprocess.run", return_value=fake):
        assert assert_monitor_mode("wlan0") == "monitor"


def test_assert_monitor_mode_raises_with_airmon_command():
    fake = mock.MagicMock()
    fake.returncode = 0
    fake.stdout = "Interface wlan0\n\ttype managed\n"
    with mock.patch("core.utils.wifi_iface.shutil.which", return_value="/usr/sbin/iw"), \
         mock.patch("core.utils.wifi_iface.subprocess.run", return_value=fake):
        with pytest.raises(MonitorModeRequired) as excinfo:
            assert_monitor_mode("wlan0")
    err = excinfo.value
    assert err.iface == "wlan0"
    assert err.current_mode == "managed"
    # The airmon-ng command is the first remediation; the iw sequence
    # is the second. Both must be present.
    assert any("airmon-ng start wlan0" in c for c in err.commands)
    assert any("iw dev wlan0 set type monitor" in c for c in err.commands)
    # The error message itself includes the iface name + mode name.
    assert "wlan0" in str(err)
    assert "managed" in str(err)


def test_assert_monitor_mode_raises_on_missing_iw():
    with mock.patch("core.utils.wifi_iface.shutil.which", return_value=None):
        with pytest.raises(MonitorModeRequired) as excinfo:
            assert_monitor_mode("wlan0")
    assert "error" in excinfo.value.current_mode


def test_is_monitor_capable_returns_false_when_picker_missing():
    with mock.patch.dict("sys.modules", {"core.tui.interface_picker": None}):
        assert is_monitor_capable("wlan0") is False


def test_is_monitor_capable_returns_true_when_picker_says_yes():
    fake_ifaces = [{"name": "wlan0", "monitor": True}]
    fake_module = mock.MagicMock()
    fake_module.detect_wireless_interfaces = mock.MagicMock(return_value=fake_ifaces)
    with mock.patch.dict("sys.modules", {"core.tui.interface_picker": fake_module}):
        assert is_monitor_capable("wlan0") is True
        assert is_monitor_capable("wlan99") is False
