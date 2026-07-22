"""tests.test_ble_adapter_select — Phase 3 expansion addendum.

Verifies the new :mod:`core.ble.adapter_select` module:

* :func:`list_adapters` parses a stub ``hciconfig -a`` output.
* :func:`select_external_adapter` filters to ``Bus: USB`` and
  picks the lowest-indexed controller.
* :func:`resolve_default_adapter` honours the operator's
  ``KFIOSA_BLE_ADAPTER`` env var as the override.
* The module never fabricates a controller that isn't in the
  real ``hciconfig`` output.

The runner integration tests cover the BLEProbeRunner /
BLEAttackRunner / BLEPanelClient constructor change (default
adapter is no longer ``None``).
"""
from __future__ import annotations

import os
import subprocess
from typing import Any, Dict, List
from unittest import mock

import pytest

from core.ble.adapter_select import (
    BLE_ADAPTER_ENV,
    _parse_hciconfig,
    list_adapters,
    resolve_default_adapter,
    select_external_adapter,
)


# ---------------------------------------------------------------------------
# Sample hciconfig -a output
# ---------------------------------------------------------------------------


SAMPLE_HCICONFIG = """\
hci1:\tType: Primary  Bus: USB
\tBD Address: E0:D3:62:27:15:DE  ACL MTU: 1021:6  SCO MTU: 255:12
\tDOWN
\tRX bytes:1677 acl:0 sco:0 events:185 errors:0
\tTX bytes:34347 acl:0 sco:0 commands:185 errors:0

hci0:\tType: Primary  Bus: USB
\tBD Address: 50:BB:B5:0A:D6:35  ACL MTU: 1021:6  SCO MTU: 240:8
\tDOWN
\tRX bytes:16006 acl:0 sco:0 events:2175 errors:0
\tTX bytes:533254 acl:0 sco:0 commands:2175 errors:0
"""


SAMPLE_BUILTIN_UART = """\
hci0:\tType: Primary  Bus: UART
\tBD Address: 00:11:22:33:44:55  ACL MTU: 1021:6  SCO MTU: 255:12
\tUP RUNNING
\tRX bytes:100 acl:0 sco:0 events:1 errors:0
"""


# ---------------------------------------------------------------------------
# _parse_hciconfig
# ---------------------------------------------------------------------------


class TestParseHciconfig:
    def test_parses_two_usb_adapters(self):
        out = _parse_hciconfig(SAMPLE_HCICONFIG)
        assert len(out) == 2
        # Sorted by hci-name numerically
        assert out[0]["name"] == "hci0"
        assert out[1]["name"] == "hci1"

    def test_extracts_bus_and_address(self):
        out = _parse_hciconfig(SAMPLE_HCICONFIG)
        for a in out:
            assert a["bus"] == "USB"
            assert a["address"]
            assert a["type"] == "Primary"

    def test_extracts_acl_mtu(self):
        out = _parse_hciconfig(SAMPLE_HCICONFIG)
        assert all(a["acl_mtu"] == 1021 for a in out)

    def test_handles_empty(self):
        assert _parse_hciconfig("") == []
        assert _parse_hciconfig("garbage\nno headers here\n") == []

    def test_handles_builtin_uart(self):
        out = _parse_hciconfig(SAMPLE_BUILTIN_UART)
        assert len(out) == 1
        assert out[0]["name"] == "hci0"
        assert out[0]["bus"] == "UART"
        assert out[0]["up"] is True

    def test_up_flag_set_when_running(self):
        out = _parse_hciconfig(SAMPLE_BUILTIN_UART)
        # The `UP RUNNING` line is parsed as 'up' True
        assert out[0]["up"] is True

    def test_down_flag_when_not_running(self):
        out = _parse_hciconfig(SAMPLE_HCICONFIG)
        # The DOWN line — hci0/hci1 are DOWN in this sample
        for a in out:
            assert a["up"] is False


# ---------------------------------------------------------------------------
# list_adapters (subprocess integration)
# ---------------------------------------------------------------------------


class TestListAdapters:
    def test_returns_parsed_list_when_hciconfig_present(self):
        fake = subprocess.CompletedProcess(
            args=["hciconfig", "-a"], returncode=0,
            stdout=SAMPLE_HCICONFIG, stderr="",
        )
        with mock.patch("shutil.which", return_value="/usr/sbin/hciconfig"), \
             mock.patch("subprocess.run", return_value=fake):
            r = list_adapters()
        assert r["ok"] is True
        assert r["data"]["count"] == 2
        assert r["source"] == "hciconfig"
        names = [a["name"] for a in r["data"]["adapters"]]
        assert names == ["hci0", "hci1"]

    def test_returns_empty_when_hciconfig_missing(self):
        with mock.patch("shutil.which", return_value=None):
            r = list_adapters()
        assert r["ok"] is False
        assert r["data"]["adapters"] == []
        assert "hciconfig" in r["error"].lower()

    def test_returns_empty_when_no_controllers(self):
        fake = subprocess.CompletedProcess(
            args=["hciconfig", "-a"], returncode=0,
            stdout="", stderr="",
        )
        with mock.patch("shutil.which", return_value="/usr/sbin/hciconfig"), \
             mock.patch("subprocess.run", return_value=fake):
            r = list_adapters()
        assert r["ok"] is False
        assert r["data"]["adapters"] == []
        assert "no hci" in r["error"].lower()

    def test_handles_timeout(self):
        with mock.patch("shutil.which", return_value="/usr/sbin/hciconfig"), \
             mock.patch("subprocess.run",
                        side_effect=subprocess.TimeoutExpired(cmd="hciconfig",
                                                               timeout=5)):
            r = list_adapters(timeout_s=2)
        assert r["ok"] is False
        assert "timed out" in r["error"].lower()


# ---------------------------------------------------------------------------
# select_external_adapter
# ---------------------------------------------------------------------------


class TestSelectExternalAdapter:
    def test_picks_lowest_indexed_usb(self):
        fake = subprocess.CompletedProcess(
            args=["hciconfig", "-a"], returncode=0,
            stdout=SAMPLE_HCICONFIG, stderr="",
        )
        with mock.patch("shutil.which", return_value="/usr/sbin/hciconfig"), \
             mock.patch("subprocess.run", return_value=fake):
            r = select_external_adapter()
        assert r["ok"] is True
        assert r["data"]["pick"] == "hci0"
        assert r["data"]["prefer"] == "external"
        assert r["source"] == "filter"

    def test_excludes_uart_built_in(self):
        fake = subprocess.CompletedProcess(
            args=["hciconfig", "-a"], returncode=0,
            stdout=SAMPLE_BUILTIN_UART, stderr="",
        )
        with mock.patch("shutil.which", return_value="/usr/sbin/hciconfig"), \
             mock.patch("subprocess.run", return_value=fake):
            r = select_external_adapter()
        assert r["ok"] is False
        assert r["data"]["pick"] is None
        # The built-in UART adapter is NOT in the external candidates
        assert "USB" in r["error"]

    def test_override_wins(self):
        fake = subprocess.CompletedProcess(
            args=["hciconfig", "-a"], returncode=0,
            stdout=SAMPLE_HCICONFIG, stderr="",
        )
        with mock.patch("shutil.which", return_value="/usr/sbin/hciconfig"), \
             mock.patch("subprocess.run", return_value=fake):
            r = select_external_adapter(override="hci1")
        assert r["ok"] is True
        assert r["data"]["pick"] == "hci1"
        assert r["source"] == "override"

    def test_override_unknown_returns_error(self):
        fake = subprocess.CompletedProcess(
            args=["hciconfig", "-a"], returncode=0,
            stdout=SAMPLE_HCICONFIG, stderr="",
        )
        with mock.patch("shutil.which", return_value="/usr/sbin/hciconfig"), \
             mock.patch("subprocess.run", return_value=fake):
            r = select_external_adapter(override="hci99")
        # We never invent a controller that isn't in the real output
        assert r["ok"] is False
        assert r["data"]["pick"] is None
        assert "not in parsed" in r["error"]

    def test_prefer_any_no_filter(self):
        fake = subprocess.CompletedProcess(
            args=["hciconfig", "-a"], returncode=0,
            stdout=SAMPLE_BUILTIN_UART, stderr="",
        )
        with mock.patch("shutil.which", return_value="/usr/sbin/hciconfig"), \
             mock.patch("subprocess.run", return_value=fake):
            r = select_external_adapter(prefer="any")
        assert r["ok"] is True
        assert r["data"]["pick"] == "hci0"

    def test_prefer_unknown_returns_error(self):
        fake = subprocess.CompletedProcess(
            args=["hciconfig", "-a"], returncode=0,
            stdout=SAMPLE_HCICONFIG, stderr="",
        )
        with mock.patch("shutil.which", return_value="/usr/sbin/hciconfig"), \
             mock.patch("subprocess.run", return_value=fake):
            r = select_external_adapter(prefer="frobnicate")
        assert r["ok"] is False
        assert "unknown prefer" in r["error"]


# ---------------------------------------------------------------------------
# resolve_default_adapter
# ---------------------------------------------------------------------------


class TestResolveDefaultAdapter:
    def test_kwarg_override_wins(self):
        with mock.patch.dict(os.environ, {BLE_ADAPTER_ENV: "hci1"}):
            assert resolve_default_adapter(override="hci99") == "hci99"

    def test_env_var_overrides_heuristic(self):
        with mock.patch.dict(os.environ, {BLE_ADAPTER_ENV: "hci1"}):
            # Heuristic would pick hci0; env says hci1; env wins
            fake = subprocess.CompletedProcess(
                args=["hciconfig", "-a"], returncode=0,
                stdout=SAMPLE_HCICONFIG, stderr="",
            )
            with mock.patch("shutil.which", return_value="/usr/sbin/hciconfig"), \
                 mock.patch("subprocess.run", return_value=fake):
                assert resolve_default_adapter() == "hci1"

    def test_heuristic_picks_usb(self):
        # Make sure the env var is empty so heuristic runs
        env = os.environ.copy()
        env.pop(BLE_ADAPTER_ENV, None)
        with mock.patch.dict(os.environ, env, clear=True):
            fake = subprocess.CompletedProcess(
                args=["hciconfig", "-a"], returncode=0,
                stdout=SAMPLE_HCICONFIG, stderr="",
            )
            with mock.patch("shutil.which", return_value="/usr/sbin/hciconfig"), \
                 mock.patch("subprocess.run", return_value=fake):
                assert resolve_default_adapter() == "hci0"

    def test_fallback_when_nothing_works(self):
        # No hciconfig, no env var — must return the fallback (hci0)
        env = os.environ.copy()
        env.pop(BLE_ADAPTER_ENV, None)
        with mock.patch.dict(os.environ, env, clear=True), \
             mock.patch("shutil.which", return_value=None):
            assert resolve_default_adapter(fallback="hci0") == "hci0"

    def test_fallback_custom(self):
        env = os.environ.copy()
        env.pop(BLE_ADAPTER_ENV, None)
        with mock.patch.dict(os.environ, env, clear=True), \
             mock.patch("shutil.which", return_value=None):
            assert resolve_default_adapter(fallback="hci3") == "hci3"


# ---------------------------------------------------------------------------
# Runner integration — the default-adapter change must be opt-in
# ---------------------------------------------------------------------------


class TestRunnerIntegration:
    def test_ble_probe_runner_uses_default_adapter(self):
        """When the runner is constructed with no ``adapter=`` kwarg,
        it now calls ``resolve_default_adapter`` and stores a real
        controller name (not ``None``)."""
        from core.ble.runner import BLEProbeRunner
        env = os.environ.copy()
        env.pop(BLE_ADAPTER_ENV, None)
        with mock.patch.dict(os.environ, env, clear=True), \
             mock.patch("shutil.which", return_value=None):
            r = BLEProbeRunner(adapter=None)
        # With no hciconfig + no env, resolve_default_adapter returns
        # the fallback 'hci0' — the runner's historic default.
        assert r.adapter == "hci0"

    def test_ble_probe_runner_honours_explicit_adapter(self):
        from core.ble.runner import BLEProbeRunner
        r = BLEProbeRunner(adapter="hci1")
        assert r.adapter == "hci1"

    def test_ble_probe_runner_honours_env(self):
        from core.ble.runner import BLEProbeRunner
        with mock.patch.dict(os.environ, {BLE_ADAPTER_ENV: "hci2"}):
            r = BLEProbeRunner(adapter=None)
        assert r.adapter == "hci2"

    def test_ble_attack_runner_uses_default_adapter(self):
        from core.ble.attack_runner import BLEAttackRunner
        env = os.environ.copy()
        env.pop(BLE_ADAPTER_ENV, None)
        with mock.patch.dict(os.environ, env, clear=True), \
             mock.patch("shutil.which", return_value=None):
            r = BLEAttackRunner(adapter=None)
        assert r.adapter == "hci0"

    def test_ble_attack_runner_honours_explicit_adapter(self):
        from core.ble.attack_runner import BLEAttackRunner
        r = BLEAttackRunner(adapter="hci1")
        assert r.adapter == "hci1"

    def test_ble_panel_client_uses_default_adapter(self):
        from core.post_access_tui.ble_panel import BLEPanelClient
        env = os.environ.copy()
        env.pop(BLE_ADAPTER_ENV, None)
        with mock.patch.dict(os.environ, env, clear=True), \
             mock.patch("shutil.which", return_value=None):
            c = BLEPanelClient(adapter=None)
        assert c.adapter == "hci0"

    def test_ble_panel_client_honours_explicit_adapter(self):
        from core.post_access_tui.ble_panel import BLEPanelClient
        c = BLEPanelClient(adapter="hci1")
        assert c.adapter == "hci1"


# ---------------------------------------------------------------------------
# Adversarial — never fabricate
# ---------------------------------------------------------------------------


class TestAdversarial:
    def test_no_fabricated_controllers(self):
        """The parser must NOT invent a controller that isn't in the
        real ``hciconfig -a`` output. The override path also rejects
        unknown names instead of silently using them."""
        fake = subprocess.CompletedProcess(
            args=["hciconfig", "-a"], returncode=0,
            stdout=SAMPLE_HCICONFIG, stderr="",
        )
        with mock.patch("shutil.which", return_value="/usr/sbin/hciconfig"), \
             mock.patch("subprocess.run", return_value=fake):
            r = select_external_adapter(override="hci42")
            assert r["ok"] is False
            assert r["data"]["pick"] is None
            # The candidates list is the real parsed set, never
            # augmented with the unknown override.
            assert r["data"]["candidates"] == ["hci0", "hci1"]

    def test_no_fabrication_with_completely_empty_output(self):
        fake = subprocess.CompletedProcess(
            args=["hciconfig", "-a"], returncode=1,
            stdout="", stderr="hci0: error",
        )
        with mock.patch("shutil.which", return_value="/usr/sbin/hciconfig"), \
             mock.patch("subprocess.run", return_value=fake):
            r = select_external_adapter()
        assert r["ok"] is False
        assert r["data"]["pick"] is None
        assert r["data"]["candidates"] == []
