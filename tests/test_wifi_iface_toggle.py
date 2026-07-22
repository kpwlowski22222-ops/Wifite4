"""Tests for the WiFi monitor <-> managed toggle + dynamic label.

Operator-reported bug (2026-07-20):

  "fix changing managed <-> monitor mode in textual state, it changes
   into monitor mode (and into managed) but no changes in TUI's text,
   it should change into managed when selected and clicked by
   enter/spacebar again on the iface in monitor mode, not only on exit
   of the app/tool"

The fix:
  - ``WiFiScreen.interface_mode`` tracks the current state
    (None | "managed" | "monitor").
  - ``WiFiScreen.original_iface`` records the pre-airmon managed
    name when airmon produced a separate ``wlan[id]mon`` vif.
  - After ``pick_interface`` succeeds, the Advanced menu item text
    is rebuilt via ``_rebuild_advanced_items`` so the operator can
    see the new state from the TUI.
  - The new ``WiFiScreen.toggle_interface_mode`` is what the menu
    item now routes to. It dispatches on ``interface_mode``:
    ``None`` → first-time pick, ``"monitor"`` → airmon_stop /
    iw-flip back to managed, ``"managed"`` → re-engage monitor.
  - On managed flip, ``interface_mode`` flips to ``"managed"`` and
    the label is rebuilt again.

All tests are hermetic: ``airmon_start`` / ``airmon_stop`` /
``WiFiScanner.ensure_monitor`` / ``WiFiScanner.ensure_managed``
are monkeypatched, no real subprocess runs, no curses required.
"""
from __future__ import annotations

import pytest

from core.tui.wifi_screen import WiFiScreen
from tests.conftest import _make_screen
from tests.fakes import FakeWiFiScanner


def _wifi(log, **over):
    over.setdefault("scanner_cls", FakeWiFiScanner)
    return _make_screen(WiFiScreen, log, **over)


def _patch_pick(monkeypatch, *, airmon_result=None,
                ensure_monitor_result=None,
                restore_managed_result=None):
    """Wire pick_wireless_interface + airmon_start + airmon_stop +
    WiFiScanner + the mt7921e probe to fakes. Returns the shared
    ``FakeWiFiScanner`` so tests can assert on the calls."""
    from core.tui import interface_picker
    from core.scanners import wifi_scanner
    from core.utils import airmon
    from core.modules import mt7921e_tools
    from tests.fakes import FakeWiFiScanner

    fake = FakeWiFiScanner(
        ensure_monitor_result=ensure_monitor_result,
    )
    # If the test wants restore_managed to record something other
    # than "no exception", patch the call signature.
    if restore_managed_result is not None:
        orig_restore = fake.restore_managed
        def _restore(iface):
            fake.calls.append(("restore_managed", iface))
            if restore_managed_result.get("raise"):
                raise Exception("simulated restore failure")
        fake.restore_managed = _restore  # type: ignore[method-assign]
    else:
        # Default: record the call; do not raise.
        orig = fake.restore_managed
        def _record_restore(iface):
            fake.calls.append(("restore_managed", iface))
        fake.restore_managed = _record_restore  # type: ignore[method-assign]

    monkeypatch.setattr(interface_picker, "pick_wireless_interface",
                        lambda stdscr, log: "wlan0")
    monkeypatch.setattr(wifi_scanner, "WiFiScanner",
                        lambda interface=None: fake)
    if airmon_result is None:
        airmon_result = {"ok": True, "monitor_iface": "wlan0mon",
                         "original_iface": "wlan0", "method": "airmon",
                         "error": ""}
    monkeypatch.setattr(airmon, "airmon_start", lambda iface: airmon_result)
    monkeypatch.setattr(mt7921e_tools, "probe_mt7921e_capabilities",
                        lambda *a, **k: [])
    return fake


# ---------------------------------------------------------------------------
# Initial state: no iface, no mode
# ---------------------------------------------------------------------------

class TestInitialState:
    def test_init_interface_mode_is_none(self, log):
        sc = _wifi(log)
        assert sc.interface is None
        assert sc.interface_mode is None
        assert sc.original_iface is None

    def test_init_advanced_label_is_static_pick(self, log):
        """No iface → label is the static 'Pick...' text (matches
        pre-fix behaviour for a fresh screen)."""
        sc = _wifi(log)
        label = sc.advanced_items[0][0]
        assert label == "Pick Wireless Interface (auto-detect + monitor)"

    def test_toggle_with_no_iface_falls_through_to_pick(self, monkeypatch, log):
        """Pressing the menu item on a fresh screen runs ``pick_interface``
        (the existing first-pick path) — backward compatible."""
        sc = _wifi(log)
        _patch_pick(monkeypatch)
        sc.toggle_interface_mode()
        assert sc.interface == "wlan0mon"
        assert sc.interface_mode == "monitor"


# ---------------------------------------------------------------------------
# After pick_interface: state is recorded, label is dynamic
# ---------------------------------------------------------------------------

class TestPickInterfaceSetsState:
    def test_airmon_success_records_mode_monitor_and_original(self, monkeypatch, log):
        sc = _wifi(log)
        _patch_pick(monkeypatch)
        sc.pick_interface()
        assert sc.interface == "wlan0mon"
        assert sc.interface_mode == "monitor"
        assert sc.original_iface == "wlan0"

    def test_airmon_success_rebuilds_label_to_dynamic(self, monkeypatch, log):
        """After a successful pick, the Advanced menu item text changes
        from the static 'Pick...' to a dynamic 'Toggle ... currently
        monitor on wlan0mon'. This is the textual-state-bug fix."""
        sc = _wifi(log)
        _patch_pick(monkeypatch)
        sc.pick_interface()
        label = sc.advanced_items[0][0]
        assert "currently monitor" in label
        assert "wlan0mon" in label
        assert "MANAGED" in label  # the action it WILL do (flip back)

    def test_iw_fallback_records_mode_monitor_no_original(self, monkeypatch, log):
        """In-place iw+ip flip (no separate vif) — interface_mode is
        "monitor" but original_iface is None (no separate name to
        flip back to)."""
        sc = _wifi(log)
        _patch_pick(
            monkeypatch,
            airmon_result={"ok": False, "error": "airmon-ng not installed"},
            ensure_monitor_result={"ok": True, "interface": "wlan0"},
        )
        sc.pick_interface()
        assert sc.interface == "wlan0"
        assert sc.interface_mode == "monitor"
        assert sc.original_iface is None

    def test_airmon_failure_does_not_set_mode(self, monkeypatch, log):
        """A hard airmon failure (e.g. needs root) does NOT record
        monitor mode — the operator can re-pick."""
        sc = _wifi(log)
        _patch_pick(
            monkeypatch,
            airmon_result={"ok": False, "error": "airmon-ng needs root"},
        )
        sc.pick_interface()
        assert sc.interface == "wlan0"
        # Mode stays None — the operator can re-pick without surprises.
        assert sc.interface_mode is None


# ---------------------------------------------------------------------------
# Toggle: monitor → managed
# ---------------------------------------------------------------------------

class TestToggleMonitorToManaged:
    def test_toggle_monitor_calls_airmon_stop(self, monkeypatch, log):
        from core.utils import airmon

        sc = _wifi(log)
        _patch_pick(monkeypatch)
        sc.pick_interface()
        # Pre-condition.
        assert sc.interface == "wlan0mon"
        assert sc.interface_mode == "monitor"

        stop_calls = {"n": 0, "args": []}
        def fake_stop(monitor_iface, timeout=15):
            stop_calls["n"] += 1
            stop_calls["args"].append(monitor_iface)
            return {"ok": True, "returncode": 0, "stdout": "",
                    "stderr": "", "error": ""}
        monkeypatch.setattr(airmon, "airmon_stop", fake_stop)

        sc.toggle_interface_mode()
        assert stop_calls["n"] == 1
        assert stop_calls["args"][0] == "wlan0mon"

    def test_toggle_monitor_flips_state_to_managed(self, monkeypatch, log):
        sc = _wifi(log)
        _patch_pick(monkeypatch)
        sc.pick_interface()
        # Pre-condition
        assert sc.interface_mode == "monitor"

        sc.toggle_interface_mode()
        # Post-condition: mode flipped, iface is the original managed name
        assert sc.interface_mode == "managed"
        assert sc.interface == "wlan0"
        # And the label is rebuilt to show the new state.
        label = sc.advanced_items[0][0]
        assert "currently managed" in label
        assert "wlan0" in label
        assert "MONITOR" in label  # the action it WILL do (re-engage)

    def test_toggle_monitor_emits_log(self, monkeypatch, log):
        sc = _wifi(log)
        _patch_pick(monkeypatch)
        sc.pick_interface()
        log.clear()
        sc.toggle_interface_mode()
        assert any("Tearing down monitor mode" in l for l in log)
        assert any("Managed mode ACTIVE on wlan0" in l for l in log)

    def test_toggle_monitor_airmon_stop_failure_falls_back_to_iw(self, monkeypatch, log):
        """airmon_stop fails → falls back to WiFiScanner.restore_managed
        on the original_iface. The toggle still succeeds honestly."""
        from core.utils import airmon

        sc = _wifi(log)
        fake = _patch_pick(
            monkeypatch,
        )
        sc.pick_interface()
        # airmon_stop fails
        monkeypatch.setattr(
            airmon, "airmon_stop",
            lambda iface, timeout=15: {"ok": False, "error": "airmon-ng broken"},
        )
        sc.toggle_interface_mode()
        # The scanner fallback ran.
        assert any(
            call[0] == "restore_managed" for call in fake.calls
        ), f"restore_managed was not called: {fake.calls}"
        # And the state flipped.
        assert sc.interface_mode == "managed"
        assert sc.interface == "wlan0"

    def test_toggle_monitor_iw_fallback_too(self, monkeypatch, log):
        """In-place iw flip (no separate vif) → toggle uses the
        scanner's restore_managed with the same iface name."""
        from core.utils import airmon

        sc = _wifi(log)
        fake = _patch_pick(
            monkeypatch,
            airmon_result={"ok": False, "error": "airmon-ng not installed"},
            ensure_monitor_result={"ok": True, "interface": "wlan0"},
        )
        sc.pick_interface()
        assert sc.interface == "wlan0"
        assert sc.interface_mode == "monitor"
        assert sc.original_iface is None

        sc.toggle_interface_mode()
        # airmon_stop is NOT called (in-place flip, no separate vif).
        # The scanner fallback ran.
        assert any(
            call[0] == "restore_managed" for call in fake.calls
        )
        # State still flipped honestly.
        assert sc.interface_mode == "managed"
        assert sc.interface == "wlan0"


# ---------------------------------------------------------------------------
# Toggle: managed → monitor (re-engage)
# ---------------------------------------------------------------------------

class TestToggleManagedToMonitor:
    def test_toggle_managed_runs_pick_interface(self, monkeypatch, log):
        sc = _wifi(log)
        _patch_pick(monkeypatch)
        # First pick → monitor.
        sc.pick_interface()
        sc.toggle_interface_mode()  # → managed
        assert sc.interface_mode == "managed"
        # Now re-toggle → re-engages monitor.
        sc.toggle_interface_mode()
        assert sc.interface_mode == "monitor"
        assert sc.interface == "wlan0mon"

    def test_toggle_managed_emits_log(self, monkeypatch, log):
        sc = _wifi(log)
        _patch_pick(monkeypatch)
        sc.pick_interface()
        sc.toggle_interface_mode()  # → managed
        log.clear()
        sc.toggle_interface_mode()  # → monitor
        assert any("Re-engaging monitor mode" in l for l in log)


# ---------------------------------------------------------------------------
# Dashboard tracker integration
# ---------------------------------------------------------------------------

class TestDashboardTracker:
    def test_toggle_monitor_to_managed_clears_dashboard_monitor_iface(self, monkeypatch, log):
        sc = _wifi(log)

        # Wire a fake dashboard.
        class _Dash:
            def __init__(self):
                self.monitor_iface = None
                self.original_iface = None
        dash = _Dash()
        sc.dashboard = dash

        _patch_pick(monkeypatch)
        sc.pick_interface()
        # airmon path → dashboard tracker is populated.
        assert dash.monitor_iface == "wlan0mon"
        assert dash.original_iface == "wlan0"

        sc.toggle_interface_mode()
        # After toggle → monitor_iface is cleared, original_iface is
        # the post-stop managed name.
        assert dash.monitor_iface is None
        assert dash.original_iface == "wlan0"


# ---------------------------------------------------------------------------
# Hermetic: never raises
# ---------------------------------------------------------------------------

class TestNoCrash:
    def test_toggle_with_broken_airmon_stop_import(self, monkeypatch, log):
        """If airmon_stop itself raises during import, the toggle
        degrades to the iw-fallback path (no crash)."""
        sc = _wifi(log)
        _patch_pick(monkeypatch)
        sc.pick_interface()

        # Force airmon_stop import to fail.
        import core.utils.airmon as airmon_mod
        monkeypatch.setattr(
            airmon_mod, "airmon_stop", None, raising=False,
        )
        # We also need the import to fail inside the function —
        # easiest is to make the symbol's container raise on attr
        # access. We do that with a sentinel object.
        class _Boom:
            def __getattr__(self, name):
                raise ImportError("simulated import failure")
        # Monkeypatch the from-import source: the toggle does
        # ``from core.utils.airmon import airmon_stop`` inside a
        # try/except. Make the module itself raise on attr access.
        import core.utils.airmon as airmon_pkg
        monkeypatch.setattr(airmon_pkg, "airmon_stop",
                            _Boom(), raising=False)
        # Should not raise.
        sc.toggle_interface_mode()
        # Mode flips via the iw-fallback path.
        assert sc.interface_mode == "managed"
