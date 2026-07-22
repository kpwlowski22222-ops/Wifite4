"""Hermetic tests for the BLE dynamic-menu pattern.

Covers:
  - The capability catalog is non-empty
  - Every capability has a unique hotkey
  - PanelState helpers (has_service, has_writable_char, etc.)
  - The SIG UUID table resolves common 16-bit UUIDs to friendly names
  - compute_visible_menu returns the right actions for each state
  - BLEPanel.visible_capabilities() recomputes correctly
  - BLEPanel.menu_text() renders only visible actions
  - The dynamic menu hides unavailable hotkeys (e.g. [H]eart rate
    only when 0x180D service is present)
  - The dynamic menu ADDS actions when state changes (e.g. after a
    gatt enumeration, [1]Read/[2]Write/[3]Notify appear)
  - The saved-devices JSON file is loaded and persisted
  - The capability catalog can be extended without breaking the
    dispatcher
  - The screen hook (ble_dispatch) only accepts currently-visible
    hotkeys
"""
from __future__ import annotations

import json
import re

import pytest


# ---------------------------------------------------------------------------
# Capability catalog
# ---------------------------------------------------------------------------
def test_catalog_non_empty():
    from core.post_access_tui.ble_panel_capabilities import CAPABILITY_CATALOG
    assert len(CAPABILITY_CATALOG) >= 20


def test_catalog_unique_hotkeys():
    from core.post_access_tui.ble_panel_capabilities import CAPABILITY_CATALOG
    seen = set()
    for cap in CAPABILITY_CATALOG:
        assert cap.hotkey not in seen, (
            f"duplicate hotkey {cap.hotkey!r} on action {cap.action!r}"
        )
        seen.add(cap.hotkey)


def test_catalog_unique_actions():
    from core.post_access_tui.ble_panel_capabilities import CAPABILITY_CATALOG
    seen = set()
    for cap in CAPABILITY_CATALOG:
        assert cap.action not in seen, f"duplicate action {cap.action!r}"
        seen.add(cap.action)


def test_catalog_capabilities_have_required_fields():
    from core.post_access_tui.ble_panel_capabilities import CAPABILITY_CATALOG
    for cap in CAPABILITY_CATALOG:
        assert isinstance(cap.action, str) and cap.action
        assert isinstance(cap.hotkey, str) and len(cap.hotkey) == 1
        assert isinstance(cap.label, str) and cap.label
        assert cap.risk in ("read", "intrusive", "destructive")
        assert isinstance(cap.requires_gate, bool)
        assert callable(cap.availability_fn)


# ---------------------------------------------------------------------------
# SIG UUID table
# ---------------------------------------------------------------------------
def test_sig_uuid_table_resolves_common_services():
    from core.post_access_tui.ble_panel_capabilities import friendly_uuid_name
    # Heart Rate Measurement
    assert "Heart Rate" in friendly_uuid_name(
        "00002a37-0000-1000-8000-00805f9b34fb"
    )
    # Battery Service
    assert "Battery" in friendly_uuid_name(
        "0000180f-0000-1000-8000-00805f9b34fb"
    )
    # Device Information Service
    assert "Device Information" in friendly_uuid_name(
        "0000180a-0000-1000-8000-00805f9b34fb"
    )


def test_sig_uuid_table_returns_bare_uuid_for_unknown():
    from core.post_access_tui.ble_panel_capabilities import friendly_uuid_name
    custom = "abcdef00-1234-1234-1234-123456789012"
    assert friendly_uuid_name(custom) == custom


def test_sig_uuid_table_full_form_generation():
    from core.post_access_tui.ble_panel_capabilities import (
        _uuid16_to_full, _full_to_uuid16,
    )
    assert _uuid16_to_full(0x2A37) == "00002a37-0000-1000-8000-00805f9b34fb"
    assert _full_to_uuid16(_uuid16_to_full(0x2A37)) == 0x2A37
    # Custom UUID returns None
    assert _full_to_uuid16("abcdef00-1234-1234-1234-123456789012") is None


# ---------------------------------------------------------------------------
# PanelState
# ---------------------------------------------------------------------------
def test_panel_state_defaults_disconnected():
    from core.post_access_tui.ble_panel_capabilities import PanelState
    ps = PanelState()
    assert ps.connected is False
    assert ps.has_writable_char() is False
    assert ps.has_notifiable_char() is False
    assert ps.has_readable_char() is False
    assert ps.has_service(0x180D) is False
    assert ps.has_char(0x2A37) is False


def test_panel_state_has_service():
    from core.post_access_tui.ble_panel_capabilities import PanelState
    ps = PanelState()
    ps.service_uuids.add("0000180d-0000-1000-8000-00805f9b34fb")
    assert ps.has_service(0x180D) is True
    assert ps.has_service(0x180F) is False


def test_panel_state_has_writable_char():
    from core.post_access_tui.ble_panel_capabilities import PanelState
    ps = PanelState()
    ps.chars["00002a37-0000-1000-8000-00805f9b34fb"] = {
        "properties": ["read", "write"],
    }
    assert ps.has_writable_char() is True
    assert ps.has_readable_char() is True
    assert ps.has_notifiable_char() is False


def test_panel_state_has_notifiable_char():
    from core.post_access_tui.ble_panel_capabilities import PanelState
    ps = PanelState()
    ps.chars["00002a37-0000-1000-8000-00805f9b34fb"] = {
        "properties": ["notify"],
    }
    assert ps.has_writable_char() is False
    assert ps.has_notifiable_char() is True


def test_panel_state_write_without_response_qualifies_as_writable():
    """A char with 'write-without-response' counts as writable."""
    from core.post_access_tui.ble_panel_capabilities import PanelState
    ps = PanelState()
    ps.chars["00002a37-0000-1000-8000-00805f9b34fb"] = {
        "properties": ["write-without-response"],
    }
    assert ps.has_writable_char() is True


# ---------------------------------------------------------------------------
# compute_visible_menu
# ---------------------------------------------------------------------------
def test_compute_visible_disconnected_state():
    """When disconnected, the menu shows scan/list/connect/saved/help/exit."""
    from core.post_access_tui.ble_panel_capabilities import (
        CAPABILITY_CATALOG, PanelState, compute_visible_menu,
    )
    visible = compute_visible_menu(PanelState())
    actions = {c.action for c in visible}
    # Universal actions always present
    assert "scan" in actions
    assert "help" in actions
    assert "exit" in actions
    # No high-risk actions when disconnected
    assert "write" not in actions
    assert "read" not in actions
    assert "heart_rate" not in actions
    assert "battery" not in actions


def test_compute_visible_connected_no_services():
    """When connected but no services, [1]Read and [D]isconnect
    appear (because they're gated only on 'connected'), but
    [H]eart rate and [Y] Battery do NOT."""
    from core.post_access_tui.ble_panel_capabilities import (
        PanelState, compute_visible_menu,
    )
    ps = PanelState(connected=True, address="AA:BB:CC:DD:EE:01")
    visible = compute_visible_menu(ps)
    actions = {c.action for c in visible}
    assert "disconnect" in actions
    assert "gatt" in actions
    assert "help" in actions
    # No service-specific actions
    assert "heart_rate" not in actions
    assert "battery" not in actions
    assert "device_info" not in actions
    # No writable char (no gatt done yet)
    assert "write" not in actions


def test_compute_visible_heart_rate_service_present():
    """When the Heart Rate service is present, [H]eart rate
    appears in the menu."""
    from core.post_access_tui.ble_panel_capabilities import (
        PanelState, compute_visible_menu,
    )
    ps = PanelState(connected=True, address="AA:BB:CC:DD:EE:01")
    ps.service_uuids.add("0000180d-0000-1000-8000-00805f9b34fb")
    visible = compute_visible_menu(ps)
    actions = {c.action for c in visible}
    assert "heart_rate" in actions
    # But not battery (no battery service)
    assert "battery" not in actions


def test_compute_visible_battery_service_present():
    """When the Battery service is present, [Y] Battery appears."""
    from core.post_access_tui.ble_panel_capabilities import (
        PanelState, compute_visible_menu,
    )
    ps = PanelState(connected=True, address="AA:BB:CC:DD:EE:01")
    ps.service_uuids.add("0000180f-0000-1000-8000-00805f9b34fb")
    visible = compute_visible_menu(ps)
    actions = {c.action for c in visible}
    assert "battery" in actions
    assert "heart_rate" not in actions


def test_compute_visible_device_info_service_present():
    from core.post_access_tui.ble_panel_capabilities import (
        PanelState, compute_visible_menu,
    )
    ps = PanelState(connected=True, address="AA:BB:CC:DD:EE:01")
    ps.service_uuids.add("0000180a-0000-1000-8000-00805f9b34fb")
    visible = compute_visible_menu(ps)
    actions = {c.action for c in visible}
    assert "device_info" in actions


def test_compute_visible_writable_char_present():
    """When a writable char is present, [2]Write and [B]le-shell
    appear."""
    from core.post_access_tui.ble_panel_capabilities import (
        PanelState, compute_visible_menu,
    )
    ps = PanelState(connected=True, address="AA:BB:CC:DD:EE:01")
    ps.chars["00002a37-0000-1000-8000-00805f9b34fb"] = {
        "properties": ["read", "write"],
    }
    visible = compute_visible_menu(ps)
    actions = {c.action for c in visible}
    assert "write" in actions
    assert "bleshell" in actions
    assert "read" in actions
    # But not notify
    assert "notify" not in actions


def test_compute_visible_notifiable_char_present():
    from core.post_access_tui.ble_panel_capabilities import (
        PanelState, compute_visible_menu,
    )
    ps = PanelState(connected=True, address="AA:BB:CC:DD:EE:01")
    ps.chars["00002a37-0000-1000-8000-00805f9b34fb"] = {
        "properties": ["notify"],
    }
    visible = compute_visible_menu(ps)
    actions = {c.action for c in visible}
    assert "notify" in actions
    assert "stream" in actions
    # No write
    assert "write" not in actions


def test_compute_visible_repeat_requires_last_write():
    """[5] Repeat only appears after a write has been performed."""
    from core.post_access_tui.ble_panel_capabilities import (
        PanelState, compute_visible_menu,
    )
    ps = PanelState(connected=True, address="AA:BB:CC:DD:EE:01")
    visible_before = compute_visible_menu(ps)
    assert "repeat" not in {c.action for c in visible_before}
    # Simulate a write
    ps.last_write_uuid = "00002a37-0000-1000-8000-00805f9b34fb"
    ps.last_write_hex = "deadbeef"
    visible_after = compute_visible_menu(ps)
    assert "repeat" in {c.action for c in visible_after}


# ---------------------------------------------------------------------------
# BLEPanel.dynamic menu integration
# ---------------------------------------------------------------------------
def _build_panel(state=None, fake_client=None):
    from core.post_access_tui.ble_panel import BLEPanel
    if state is None:
        state = {}
    if fake_client is None:
        fake_client = _MinimalFakeClient()
    panel = BLEPanel(client=fake_client, confirm_fn=lambda _p: True)
    for k, v in state.items():
        setattr(panel, k, v)
    return panel


class _MinimalFakeClient:
    """A bare-bones client for tests that don't call methods."""

    def _valid_mac(self, s):
        return bool(re.match(r"^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$", s))

    def _valid_uuid(self, s):
        return bool(re.match(
            r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
            r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", s))

    def _valid_hex(self, s):
        return bool(re.match(r"^[0-9a-fA-F]+$", s)) and len(s) % 2 == 0


def test_panel_visible_capabilities_disconnected():
    panel = _build_panel()
    caps = panel.visible_capabilities()
    actions = {c.action for c in caps}
    assert "scan" in actions
    assert "exit" in actions
    # No write without a writable char
    assert "write" not in actions


def test_panel_menu_text_renders_only_visible_actions():
    """menu_text() must NOT include actions that are not in
    visible_capabilities()."""
    panel = _build_panel()
    text = panel.menu_text()
    # In disconnected state, "Heart Rate" should NOT appear
    assert "[H]eart rate" not in text
    # But "[S]can" and "[E]xit" should
    assert "[S]can" in text
    assert "[E]xit" in text


def test_panel_menu_text_includes_heart_rate_after_gatt():
    """After a gatt discovers the Heart Rate service, [H]eart
    rate must appear in the menu text."""
    from core.post_access_tui.ble_panel import BLEService, BLECharacteristic
    panel = _build_panel({
        "connected_address": "AA:BB:CC:DD:EE:01",
        "services_cache": [BLEService(
            uuid="0000180d-0000-1000-8000-00805f9b34fb",
            start_handle="0x0001", end_handle="0x0010",
            characteristics=[BLECharacteristic(
                uuid="00002a37-0000-1000-8000-00805f9b34fb",
                handle="0x0002",
                properties=["notify"],
            )],
        )],
    })
    text = panel.menu_text()
    assert "[H]eart rate" in text


def test_panel_menu_text_includes_writable_action_after_gatt():
    """After a gatt discovers a writable char, [2] Write appears."""
    from core.post_access_tui.ble_panel import BLEService, BLECharacteristic
    panel = _build_panel({
        "connected_address": "AA:BB:CC:DD:EE:01",
        "services_cache": [BLEService(
            uuid="0000180d-0000-1000-8000-00805f9b34fb",
            start_handle="0x0001", end_handle="0x0010",
            characteristics=[BLECharacteristic(
                uuid="00002a37-0000-1000-8000-00805f9b34fb",
                handle="0x0002",
                properties=["read", "write"],
            )],
        )],
    })
    text = panel.menu_text()
    assert "[2] Write" in text


def test_panel_menu_text_includes_battery_after_gatt():
    from core.post_access_tui.ble_panel import BLEService, BLECharacteristic
    panel = _build_panel({
        "connected_address": "AA:BB:CC:DD:EE:01",
        "services_cache": [BLEService(
            uuid="0000180f-0000-1000-8000-00805f9b34fb",
            start_handle="0x0001", end_handle="0x0010",
            characteristics=[BLECharacteristic(
                uuid="00002a19-0000-1000-8000-00805f9b34fb",
                handle="0x0002",
                properties=["read"],
            )],
        )],
    })
    text = panel.menu_text()
    assert "[Y] Battery" in text


def test_panel_menu_text_shows_connected_footer():
    panel = _build_panel({"connected_address": "AA:BB:CC:DD:EE:01"})
    text = panel.menu_text()
    assert "connected to" in text
    assert "AA:BB:CC:DD:EE:01" in text
    assert "disconnected" not in text


def test_panel_menu_text_shows_disconnected_footer():
    panel = _build_panel()
    text = panel.menu_text()
    assert "disconnected" in text


def test_panel_visible_hotkey_set_changes_with_state():
    """The set of available hotkeys MUST change when state changes."""
    panel = _build_panel()
    initial = {c.hotkey for c in panel.visible_capabilities()}
    # Connect + add a writable char
    from core.post_access_tui.ble_panel import BLEService, BLECharacteristic
    panel.connected_address = "AA:BB:CC:DD:EE:01"
    panel.services_cache = [BLEService(
        uuid="0000180d-0000-1000-8000-00805f9b34fb",
        start_handle="0x0001", end_handle="0x0010",
        characteristics=[BLECharacteristic(
            uuid="00002a37-0000-1000-8000-00805f9b34fb",
            handle="0x0002",
            properties=["write"],
        )],
    )]
    after_connect = {c.hotkey for c in panel.visible_capabilities()}
    # New hotkeys should appear (write, disconnect, heart_rate)
    assert "2" in after_connect
    assert "d" in after_connect
    assert "h" in after_connect
    # And not in the initial
    assert "2" not in initial or "h" not in initial


# ---------------------------------------------------------------------------
# Saved devices persistence
# ---------------------------------------------------------------------------
def test_saved_devices_load_persistence(tmp_path):
    """Saved devices are loaded from disk at panel construction."""
    from core.post_access_tui.ble_panel import BLEPanel
    path = tmp_path / "saved.json"
    path.write_text(json.dumps([
        {"address": "AA:BB:CC:DD:EE:01", "name": "Foo", "rssi": -50,
         "services": [], "last_seen": 1000.0},
    ]))
    panel = BLEPanel(
        client=_MinimalFakeClient(),
        confirm_fn=lambda _p: True,
        saved_devices_path=str(path),
    )
    panel.refresh_state()
    assert len(panel.panel_state.saved_devices) == 1
    assert panel.panel_state.saved_devices[0]["address"] == "AA:BB:CC:DD:EE:01"


def test_saved_devices_persist_on_add(tmp_path):
    """Adding a device via _add_saved_device persists to disk."""
    from core.post_access_tui.ble_panel import BLEPanel
    path = tmp_path / "saved.json"
    panel = BLEPanel(
        client=_MinimalFakeClient(),
        confirm_fn=lambda _p: True,
        saved_devices_path=str(path),
    )
    panel._add_saved_device("AA:BB:CC:DD:EE:02", name="Bar", rssi=-40)
    # Read the file back
    data = json.loads(path.read_text())
    assert any(d["address"] == "AA:BB:CC:DD:EE:02" for d in data)


def test_saved_devices_memory_only_when_path_is_memory():
    """Passing saved_devices_path=':memory:' disables persistence."""
    from core.post_access_tui.ble_panel import BLEPanel
    panel = BLEPanel(
        client=_MinimalFakeClient(),
        confirm_fn=lambda _p: True,
        saved_devices_path=":memory:",
    )
    # Adding a device must NOT raise even with no path
    panel._add_saved_device("AA:BB:CC:DD:EE:03", name="Baz")
    assert len(panel.panel_state.saved_devices) == 1


# ---------------------------------------------------------------------------
# Screen hook: hotkey availability check
# ---------------------------------------------------------------------------
def test_screen_hook_rejects_unavailable_hotkey():
    """ble_dispatch with an unavailable hotkey must say so and
    NOT dispatch."""
    from core.post_access_tui.ble_panel import BLEPanel, ble_dispatch
    panel = BLEPanel(
        client=_MinimalFakeClient(),
        confirm_fn=lambda _p: True,
    )

    class _Screen:
        def __init__(self):
            self.log = []
            self.confirm_fn = lambda _p: True
            self._on_event = self._emit
            it = iter(["h", "e"])
            def _f(_p):
                try:
                    return next(it)
                except StopIteration:
                    return ""
            self.input_fn = _f

        def _emit(self, m):
            self.log.append(m)

    screen = _Screen()
    ble_dispatch(screen, panel)
    # 'h' is Heart Rate which is unavailable when disconnected
    # We expect the screen log to include "not in current menu"
    assert any("not in current menu" in line or "not available" in line
               for line in screen.log), screen.log


def test_screen_hook_accepts_available_hotkey():
    """ble_dispatch with a currently-available hotkey (after
    connecting + adding writable char) must dispatch it."""
    from core.post_access_tui.ble_panel import BLEPanel, ble_dispatch
    from core.post_access_tui.ble_panel import BLEService, BLECharacteristic

    class _WriteClient(_MinimalFakeClient):
        def write(self, address, char_uuid, value_hex):
            return {"ok": True, "data": {"wrote": value_hex},
                    "error": "", "duration_s": 0.1,
                    "host_os": "Linux", "risk": "intrusive"}

    panel = BLEPanel(client=_WriteClient(), confirm_fn=lambda _p: True)
    panel.connected_address = "AA:BB:CC:DD:EE:01"
    panel.services_cache = [BLEService(
        uuid="0000180d-0000-1000-8000-00805f9b34fb",
        start_handle="0x0001", end_handle="0x0010",
        characteristics=[BLECharacteristic(
            uuid="00002a37-0000-1000-8000-00805f9b34fb",
            handle="0x0002",
            properties=["read", "write"],
        )],
    )]

    # Capture dispatched actions by patching panel.dispatch
    dispatched = []

    class _Screen:
        def __init__(self):
            self.log = []
            self.confirm_fn = lambda _p: True  # accept all
            self._on_event = self._emit
            it = iter(["2", "e"])
            def _f(_p):
                try:
                    return next(it)
                except StopIteration:
                    return ""
            self.input_fn = _f

        def _emit(self, m):
            self.log.append(m)

    screen = _Screen()
    real_dispatch = panel.dispatch

    def _spy_dispatch(action, args=None):
        dispatched.append(action)
        # Simulate a successful write to keep the loop happy
        return {"ok": True, "data": {"written": True},
                "error": "", "duration_s": 0.0, "host_os": "Linux",
                "risk": "intrusive", "action": "write"}

    panel.dispatch = _spy_dispatch
    try:
        ble_dispatch(screen, panel)
    finally:
        panel.dispatch = real_dispatch
    # The action "write" should have been dispatched
    assert "write" in dispatched, dispatched


# ---------------------------------------------------------------------------
# Catalog extensibility
# ---------------------------------------------------------------------------
def test_catalog_action_appears_after_state_change():
    """A capability that requires a service is not visible before
    the service is present, and is visible after."""
    from core.post_access_tui.ble_panel_capabilities import (
        PanelState, compute_visible_menu,
    )
    ps_before = PanelState(connected=True, address="AA:BB:CC:DD:EE:01")
    actions_before = {c.action for c in compute_visible_menu(ps_before)}
    assert "link_loss" not in actions_before
    # Add the Link Loss service
    ps_after = PanelState(connected=True, address="AA:BB:CC:DD:EE:01")
    ps_after.service_uuids.add("00001803-0000-1000-8000-00805f9b34fb")
    actions_after = {c.action for c in compute_visible_menu(ps_after)}
    assert "link_loss" in actions_after


def test_availability_fn_exception_does_not_crash_menu():
    """A buggy availability_fn must NOT crash compute_visible_menu."""
    from core.post_access_tui.ble_panel_capabilities import (
        CAPABILITY_CATALOG, PanelState, compute_visible_menu,
    )
    # Monkeypatch one capability's availability_fn to raise
    original = CAPABILITY_CATALOG[0].availability_fn
    CAPABILITY_CATALOG[0].availability_fn = lambda _s: (
        1 / 0  # ZeroDivisionError
    )
    try:
        ps = PanelState(connected=True, address="AA:BB:CC:DD:EE:01")
        # Should NOT raise
        visible = compute_visible_menu(ps)
        # The buggy capability should be filtered out
        assert all(
            c is not CAPABILITY_CATALOG[0] for c in visible
        )
    finally:
        CAPABILITY_CATALOG[0].availability_fn = original
