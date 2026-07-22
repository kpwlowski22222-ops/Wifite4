"""Sudo-requiring root test: verify the monitor-mode detector works
against a *real* wireless interface on the host.

Run with::

    sudo -u user pytest -m root tests/test_wifi_iface_root.py -v

This test only runs when explicitly marked ``root`` (per ``pytest.ini``)
so unprivileged unit-test runs (``pytest``) skip it.
"""

import shutil

import pytest


pytestmark = pytest.mark.root


def _first_wireless_iface() -> str:
    """Return the first wireless interface name on the host, or skip."""
    if not shutil.which("iw"):
        pytest.skip("iw not installed")
    import subprocess
    r = subprocess.run(
        ["iw", "dev"], capture_output=True, text=True, timeout=5,
    )
    for line in (r.stdout or "").splitlines():
        line = line.strip()
        # ``iw dev`` prints ``Interface wlan0`` for each iface.
        if line.startswith("Interface "):
            return line.split(None, 1)[1].strip()
    pytest.skip("no wireless interface on this host")


def test_real_iface_current_mode_returns_known_value():
    from core.utils.wifi_iface import iface_current_mode
    iface = _first_wireless_iface()
    mode = iface_current_mode(iface)
    assert mode in ("monitor", "managed", "mesh", "ad-hoc", "ibss", "ap",
                    "unknown", "error"), f"unexpected mode {mode!r}"


def test_real_assert_monitor_mode_raises_or_returns():
    from core.utils.wifi_iface import (
        MonitorModeRequired, assert_monitor_mode, iface_current_mode,
    )
    iface = _first_wireless_iface()
    current = iface_current_mode(iface)
    if current == "monitor":
        # Already in monitor mode — assertion should pass.
        assert assert_monitor_mode(iface) == "monitor"
    else:
        # Anything else: the assertion should raise with the remediation
        # commands in the error.
        with pytest.raises(MonitorModeRequired) as excinfo:
            assert_monitor_mode(iface)
        assert any("airmon-ng" in c for c in excinfo.value.commands)
        assert any("iw dev" in c for c in excinfo.value.commands)
