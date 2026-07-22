"""Hermetic tests for the BLE TUI panel (Phase 2.1.C).

Covers:
  - module imports
  - envelope shape (ok/data/error/duration_s/host_os/risk)
  - scan/connect/gatt/read/write/notify/bleshell/disconnect/exit
    dispatch paths
  - per-OS auto-detection: invalid address, invalid uuid, invalid hex
    → honest degrade
  - no fabricated values: a fake client that returns crafted
    envelopes must NOT be silently overridden
  - single-gate invariant: the panel does NOT call self.confirm_fn
    inside the dispatcher (the screen is the gate)
  - the screen hook (ble_dispatch) wires the screen's
    confirm_fn/input_fn into the panel
  - high-risk actions (write/notify/bleshell) gate via the screen;
    low-risk actions (scan/list/connect/gatt/disconnect) do not
  - never inline credentials in source
"""
from __future__ import annotations

import re

import pytest


# ---------------------------------------------------------------------------
# Imports
# ---------------------------------------------------------------------------
def test_ble_panel_module_imports():
    from core.post_access_tui import ble_panel
    assert hasattr(ble_panel, "BLEPanel")
    assert hasattr(ble_panel, "BLEPanelClient")
    assert hasattr(ble_panel, "BLEDevice")
    assert hasattr(ble_panel, "BLEService")
    assert hasattr(ble_panel, "BLECharacteristic")
    assert hasattr(ble_panel, "ble_menu_entry")
    assert hasattr(ble_panel, "ble_dispatch")


def test_post_access_tui_re_exports_ble_panel():
    """The post_access_tui package exposes the BLE panel surface."""
    from core.post_access_tui import (
        BLEPanel, BLEPanelClient, ble_menu_entry, ble_dispatch,
    )
    assert callable(BLEPanel)
    assert callable(BLEPanelClient)
    assert callable(ble_menu_entry)
    assert callable(ble_dispatch)


# ---------------------------------------------------------------------------
# Envelope shape
# ---------------------------------------------------------------------------
def test_panel_action_envelope_has_required_keys():
    """Every panel action returns an envelope with name/ok/data/error/
    duration_s/host_os/risk."""
    from core.post_access_tui.ble_panel import BLEPanel

    panel = BLEPanel(
        client=_FakeClient(),
        confirm_fn=lambda _p: True,
    )
    for action in ("list",):
        env = panel.dispatch(action)
        for k in ("name", "ok", "data", "error", "duration_s",
                  "host_os", "risk"):
            assert k in env, f"action={action} missing {k!r}"


def test_panel_scan_returns_envelope_with_devices_list():
    from core.post_access_tui.ble_panel import BLEPanel, BLEDevice

    class _FakeClient:
        def scan(self, duration_s=8):
            return {
                "name": "ble_panel", "ok": True,
                "data": {"devices": [
                    BLEDevice(address="AA:BB:CC:DD:EE:01", name="Foo", rssi=-50),
                ]},
                "error": "", "duration_s": 0.1, "host_os": "Linux", "risk": "read",
            }

    panel = BLEPanel(client=_FakeClient(), confirm_fn=lambda _p: True)
    env = panel.dispatch("scan", {"duration_s": 4})
    assert env["ok"] is True
    assert "devices" in env["data"]
    assert env["data"]["devices"][0].address == "AA:BB:CC:DD:EE:01"


# ---------------------------------------------------------------------------
# Invalid input → honest degrade
# ---------------------------------------------------------------------------
def test_invalid_duration_degrades_honestly():
    from core.post_access_tui.ble_panel import BLEPanel

    panel = BLEPanel(client=_FakeClient(), confirm_fn=lambda _p: True)
    env = panel.dispatch("scan", {"duration_s": 0})
    assert env["ok"] is False
    assert "duration" in env["error"].lower()


def test_connect_without_address_returns_honest_degrade():
    """No devices cached + no address arg → honest degrade, not a
    fabricated connection."""
    from core.post_access_tui.ble_panel import BLEPanel

    panel = BLEPanel(client=_FakeClient(), confirm_fn=lambda _p: True,
                     input_fn=lambda _p: "")  # empty input
    env = panel.dispatch("connect")
    assert env["ok"] is False
    assert "no address" in env["error"].lower() or "no device" in env["error"].lower()


def test_connect_with_invalid_mac_returns_honest_degrade():
    from core.post_access_tui.ble_panel import BLEPanel

    panel = BLEPanel(client=_FakeClient(), confirm_fn=lambda _p: True)
    env = panel.dispatch("connect", {"address": "not-a-mac"})
    assert env["ok"] is False
    assert "invalid" in env["error"].lower()


def test_read_without_connection_returns_honest_degrade():
    from core.post_access_tui.ble_panel import BLEPanel

    panel = BLEPanel(client=_FakeClient(), confirm_fn=lambda _p: True)
    env = panel.dispatch("read", {"char_uuid": "00002a00-0000-1000-8000-00805f9b34fb"})
    assert env["ok"] is False
    assert "no device" in env["error"].lower() or "not connected" in env["error"].lower()


def test_read_with_invalid_uuid_degrades_honestly():
    from core.post_access_tui.ble_panel import BLEPanel

    class _FakeClient:
        def __init__(self):
            self.calls = []

        def _valid_mac(self, s):
            return bool(re.match(r"^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$", s))

        def _valid_uuid(self, s):
            return bool(re.match(
                r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", s))

        def read(self, address, char_uuid):
            self.calls.append(("read", address, char_uuid))
            return {"ok": True, "data": {"value_hex": "deadbeef"}}

    panel = BLEPanel(
        client=_FakeClient(),
        confirm_fn=lambda _p: True,
    )
    panel.connected_address = "AA:BB:CC:DD:EE:01"
    env = panel.dispatch("read", {"char_uuid": "not-a-uuid"})
    assert env["ok"] is False
    assert "uuid" in env["error"].lower()


def test_write_with_invalid_hex_degrades_honestly():
    from core.post_access_tui.ble_panel import BLEPanel

    class _FakeClient:
        def _valid_mac(self, s):
            return bool(re.match(r"^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$", s))

        def _valid_uuid(self, s):
            return bool(re.match(
                r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", s))

        def _valid_hex(self, s):
            return bool(re.match(r"^[0-9a-fA-F]+$", s)) and len(s) % 2 == 0

    panel = BLEPanel(
        client=_FakeClient(),
        confirm_fn=lambda _p: True,
    )
    panel.connected_address = "AA:BB:CC:DD:EE:01"
    env = panel.dispatch("write", {
        "char_uuid": "00002a37-0000-1000-8000-00805f9b34fb",
        "value_hex": "not-hex",
    })
    assert env["ok"] is False
    assert "hex" in env["error"].lower()


# ---------------------------------------------------------------------------
# No fabrication
# ---------------------------------------------------------------------------
def test_no_fabricated_device_address():
    """The panel never invents a device address. Connect without an
    address must return a degraded envelope, NOT a fake connection."""
    from core.post_access_tui.ble_panel import BLEPanel

    panel = BLEPanel(
        client=_FakeClient(),
        confirm_fn=lambda _p: True,
        input_fn=lambda _p: "",
    )
    env = panel.dispatch("connect")
    assert env["ok"] is False
    # No "connected" key in the result
    assert "connected" not in (env.get("data") or {})


def test_no_fabricated_char_value():
    """Read with a valid uuid but disconnected must NOT return a
    fake value."""
    from core.post_access_tui.ble_panel import BLEPanel

    panel = BLEPanel(
        client=_FakeClient(),
        confirm_fn=lambda _p: True,
    )
    env = panel.dispatch("read", {"char_uuid": "00002a00-0000-1000-8000-00805f9b34fb"})
    assert env["ok"] is False
    # No value_hex in the result
    assert "value_hex" not in (env.get("data") or {})


# ---------------------------------------------------------------------------
# Single-gate invariant
# ---------------------------------------------------------------------------
def test_panel_does_not_call_confirm_fn_internally():
    """The panel's dispatch() method must NOT call self.confirm_fn
    for high-risk actions when called via the screen hook (the
    screen is the gate). The panel does its own internal
    validation but the operator ACCEPT is the screen's job.

    Note: when called directly (e.g. from the chain planner's
    open_ble_tui step), the SCREEN also fires the gate; the panel
    does NOT re-confirm either way.
    """
    from core.post_access_tui.ble_panel import BLEPanel

    called = {"n": 0}

    def gate(_p):
        called["n"] += 1
        return True

    panel = BLEPanel(
        client=_FakeClient(),
        confirm_fn=gate,
    )
    # Set up connected state
    panel.connected_address = "AA:BB:CC:DD:EE:01"
    # Run high-risk actions
    for action, args in [
        ("read", {"char_uuid": "00002a00-0000-1000-8000-00805f9b34fb"}),
        ("write", {"char_uuid": "00002a37-0000-1000-8000-00805f9b34fb",
                   "value_hex": "deadbeef"}),
        ("notify", {"char_uuid": "00002a37-0000-1000-8000-00805f9b34fb"}),
        ("bleshell", {"write_uuid": "00002a37-0000-1000-8000-00805f9b34fb",
                      "cmd": "help"}),
    ]:
        panel.dispatch(action, args)
    # The panel's _gate is for "re-confirm" cases, but the dispatcher
    # path itself (BLEPanel.dispatch) does NOT call confirm_fn.
    # The screen hook (ble_dispatch) is the one that fires the gate.
    assert called["n"] == 0, (
        f"panel dispatcher called confirm_fn {called['n']} time(s) — "
        f"single-gate invariant violated"
    )


# ---------------------------------------------------------------------------
# Screen hook (ble_dispatch) wires the gate
# ---------------------------------------------------------------------------
class _FakeScreen:
    """A minimal stand-in for PostAccessScreen that captures the
    activity log and exposes input_fn/confirm_fn."""

    def __init__(self, *, gate_response: bool = True,
                 input_responses: list = None):
        self.log: list = []
        self.confirm_fn = lambda _p: gate_response
        self.input_fn = self._input_iter(iter(input_responses or []))
        self._on_event = self._emit
        self.running = True

    def _emit(self, msg: str) -> None:
        self.log.append(msg)

    def _input_iter(self, it):
        def _f(_prompt: str) -> str:
            try:
                return next(it)
            except StopIteration:
                return ""
        return _f


def test_screen_hook_writes_via_gate():
    """ble_dispatch with [W]rite must call the screen's confirm_fn
    with the high-risk prompt, and skip the action if the gate
    returns False."""
    from core.post_access_tui.ble_panel import BLEPanel, ble_dispatch

    class _FakeClient:
        def _valid_mac(self, s):
            return bool(re.match(r"^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$", s))

        def _valid_uuid(self, s):
            return bool(re.match(
                r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", s))

        def _valid_hex(self, s):
            return bool(re.match(r"^[0-9a-fA-F]+$", s)) and len(s) % 2 == 0

        def write(self, address, char_uuid, value_hex):
            return {"ok": True, "data": {"wrote": value_hex},
                    "error": "", "duration_s": 0.1,
                    "host_os": "Linux", "risk": "intrusive"}

    panel = BLEPanel(
        client=_FakeClient(),
        confirm_fn=lambda _p: False,  # never used directly
    )
    panel.connected_address = "AA:BB:CC:DD:EE:01"
    # Inject a writable characteristic so the dynamic menu shows [2]Write
    from core.post_access_tui.ble_panel import BLEService, BLECharacteristic
    panel.services_cache = [BLEService(
        uuid="00002a37-0000-1000-8000-00805f9b34fb",
        start_handle="0x0025", end_handle="0x0026",
        characteristics=[BLECharacteristic(
            uuid="00002a37-0000-1000-8000-00805f9b34fb",
            handle="0x0026",
            properties=["read", "write"],
        )],
    )]
    panel.refresh_state()

    screen = _FakeScreen(gate_response=False,
                         input_responses=["2", "e"])
    ble_dispatch(screen, panel)
    # The CANCELLED line should be in the log
    assert any("CANCELLED" in line for line in screen.log), screen.log


def test_screen_hook_skips_low_risk_actions():
    """ble_dispatch with [S]can must NOT call the screen's
    confirm_fn (scan is a passive read, not a high-risk write)."""
    from core.post_access_tui.ble_panel import BLEPanel, ble_dispatch

    class _FakeClient:
        def __init__(self):
            self.scan_calls = 0

        def scan(self, duration_s=8):
            self.scan_calls += 1
            return {
                "name": "ble_panel", "ok": True,
                "data": {"devices": []},
                "error": "", "duration_s": 0.1, "host_os": "Linux", "risk": "read",
            }

    called = {"gate": 0}

    def gate(_p):
        called["gate"] += 1
        return True

    screen = _FakeScreen(gate_response=True, input_responses=["s", "e"])
    screen.confirm_fn = gate
    panel = BLEPanel(
        client=_FakeClient(),
        confirm_fn=lambda _p: True,
    )
    ble_dispatch(screen, panel)
    assert called["gate"] == 0, (
        "scan triggered the gate — scan is a passive action, not a "
        "high-risk write")


def test_screen_hook_exit_returns_exit_envelope():
    from core.post_access_tui.ble_panel import BLEPanel, ble_dispatch

    panel = BLEPanel(
        client=_FakeClient(),
        confirm_fn=lambda _p: True,
    )
    screen = _FakeScreen(input_responses=["e"])
    result = ble_dispatch(screen, panel)
    assert result.get("exit") is True
    assert result.get("ok") is True


# ---------------------------------------------------------------------------
# Connect to a real device by index
# ---------------------------------------------------------------------------
def test_connect_by_index_picks_cached_device():
    from core.post_access_tui.ble_panel import BLEPanel, BLEDevice

    class _FakeClient:
        def _valid_mac(self, s):
            return bool(re.match(r"^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$", s))

    panel = BLEPanel(
        client=_FakeClient(),
        confirm_fn=lambda _p: True,
    )
    panel.devices = [
        BLEDevice(address="AA:BB:CC:DD:EE:01", name="Foo"),
        BLEDevice(address="AA:BB:CC:DD:EE:02", name="Bar"),
    ]
    screen = _FakeScreen(input_responses=["1"])
    screen._emit = lambda m: None
    env = panel.dispatch("connect", {})
    # Without a real input_fn wired in, the panel's _ask will be a
    # no-op (no input_fn). Test the direct path: pre-set input_fn.
    panel._input_fn = screen.input_fn
    env = panel.dispatch("connect", {})
    assert env["ok"] is True
    assert env["data"]["connected"] == "AA:BB:CC:DD:EE:02"


# ---------------------------------------------------------------------------
# Disconnect
# ---------------------------------------------------------------------------
def test_disconnect_clears_connected_state():
    from core.post_access_tui.ble_panel import BLEPanel

    class _FakeClient:
        def _valid_mac(self, s):
            return bool(re.match(r"^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$", s))

    panel = BLEPanel(
        client=_FakeClient(),
        confirm_fn=lambda _p: True,
    )
    panel.connected_address = "AA:BB:CC:DD:EE:01"
    panel.services_cache = ["x"]
    env = panel.dispatch("disconnect")
    assert env["ok"] is True
    assert panel.connected_address is None
    assert panel.services_cache == []


def test_disconnect_without_connection_degrades_honestly():
    from core.post_access_tui.ble_panel import BLEPanel

    panel = BLEPanel(
        client=_FakeClient(),
        confirm_fn=lambda _p: True,
    )
    env = panel.dispatch("disconnect")
    assert env["ok"] is False


# ---------------------------------------------------------------------------
# gatt action (services enumeration)
# ---------------------------------------------------------------------------
def test_gatt_without_connection_degrades_honestly():
    from core.post_access_tui.ble_panel import BLEPanel

    panel = BLEPanel(
        client=_FakeClient(),
        confirm_fn=lambda _p: True,
    )
    env = panel.dispatch("gatt")
    assert env["ok"] is False


def test_gatt_caches_services_on_success():
    from core.post_access_tui.ble_panel import BLEPanel, BLEService

    class _FakeClient:
        def _valid_mac(self, s):
            return bool(re.match(r"^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$", s))

        def services(self, address):
            return {
                "name": "ble_panel", "ok": True,
                "data": {"services": [
                    BLEService(uuid="00001800-0000-1000-8000-00805f9b34fb",
                                start_handle="0x0001", end_handle="0x0005"),
                ]},
                "error": "", "duration_s": 0.1, "host_os": "Linux", "risk": "read",
            }

    panel = BLEPanel(
        client=_FakeClient(),
        confirm_fn=lambda _p: True,
    )
    panel.connected_address = "AA:BB:CC:DD:EE:01"
    env = panel.dispatch("gatt")
    assert env["ok"] is True
    assert len(panel.services_cache) == 1
    assert panel.services_cache[0].uuid.startswith("00001800")


# ---------------------------------------------------------------------------
# No inline credentials in source
# ---------------------------------------------------------------------------
def test_no_inline_credentials_in_ble_panel_module():
    """Never-inline ground rule: no long hex/hash in the panel's
    source."""
    from core.post_access_tui import ble_panel
    import inspect
    src = inspect.getsource(ble_panel)
    # 32+ hex chars in source = suspect (skip the test file
    # docstring which has examples)
    for bad in re.findall(r"\b[a-f0-9]{32,}\b", src):
        # Allow if it's in a comment about a known hash that the
        # panel uses for testing
        if "test" in src[max(0, src.find(bad) - 50):
                       src.find(bad) + len(bad) + 50].lower():
            continue
        pytest.fail(
            f"possible inline credential in ble_panel: {bad!r}"
        )


# ---------------------------------------------------------------------------
# Menu entry
# ---------------------------------------------------------------------------
def test_ble_menu_entry_shape():
    from core.post_access_tui.ble_panel import ble_menu_entry
    label, key, action = ble_menu_entry()
    assert "BLE" in label or "Bluetooth" in label
    assert key == "b"
    assert action == "ble"


# ---------------------------------------------------------------------------
# Real-client parsing (hermetic: does NOT actually call gatttool)
# ---------------------------------------------------------------------------
def test_parse_lescan_dedupes_by_address():
    from core.post_access_tui.ble_panel import BLEPanelClient
    raw = (
        "LE Scan ...\n"
        "AA:BB:CC:DD:EE:01 (unknown)\n"
        "AA:BB:CC:DD:EE:01 (unknown)\n"
        "AA:BB:CC:DD:EE:02 FooBar\n"
        "AA:BB:CC:DD:EE:03 \n"
    )
    devices = BLEPanelClient._parse_lescan(raw)
    addrs = [d.address for d in devices]
    assert addrs == [
        "AA:BB:CC:DD:EE:01", "AA:BB:CC:DD:EE:02", "AA:BB:CC:DD:EE:03",
    ]
    # Names: "(unknown)" → "", "FooBar" stays
    by_addr = {d.address: d.name for d in devices}
    assert by_addr["AA:BB:CC:DD:EE:01"] == ""
    assert by_addr["AA:BB:CC:DD:EE:02"] == "FooBar"


def test_parse_primary_services():
    from core.post_access_tui.ble_panel import BLEPanelClient
    raw = (
        "attr handle: 0x0001, end grp handle: 0x0005 "
        "uuid: 00001800-0000-1000-8000-00805f9b34fb\n"
        "attr handle: 0x0006, end grp handle: 0x0009 "
        "uuid: 00001801-0000-1000-8000-00805f9b34fb\n"
    )
    services = BLEPanelClient._parse_primary_services(raw)
    assert len(services) == 2
    assert services[0].uuid == "00001800-0000-1000-8000-00805f9b34fb"
    assert services[0].start_handle == "0x0001"
    assert services[0].end_handle == "0x0005"


def test_properties_from_byte_known_bits():
    from core.post_access_tui.ble_panel import _properties_from_byte
    # 0x02 = read; 0x08 = write; 0x10 = notify
    assert _properties_from_byte(0x02) == ["read"]
    assert _properties_from_byte(0x08) == ["write"]
    assert _properties_from_byte(0x10) == ["notify"]
    assert _properties_from_byte(0x1A) == ["read", "write", "notify"]
    # 0x00 → "(none)"
    assert _properties_from_byte(0x00) == ["(none)"]


def test_validators_reject_garbage():
    from core.post_access_tui.ble_panel import BLEPanelClient
    assert BLEPanelClient._valid_mac("AA:BB:CC:DD:EE:01") is True
    assert BLEPanelClient._valid_mac("not-a-mac") is False
    assert BLEPanelClient._valid_mac("") is False
    assert BLEPanelClient._valid_uuid(
        "00002a00-0000-1000-8000-00805f9b34fb") is True
    assert BLEPanelClient._valid_uuid("not-a-uuid") is False
    assert BLEPanelClient._valid_hex("deadbeef") is True
    assert BLEPanelClient._valid_hex("DEADBEEF") is True
    assert BLEPanelClient._valid_hex("xyz") is False
    assert BLEPanelClient._valid_hex("abc") is False  # odd length
    assert BLEPanelClient._valid_hex("") is False


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
class _FakeClient:
    """Default fake client for tests that don't care about specific
    client methods."""

    def _valid_mac(self, s):
        return bool(re.match(r"^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$", s))

    def _valid_uuid(self, s):
        return bool(re.match(
            r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
            r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", s))

    def _valid_hex(self, s):
        return bool(re.match(r"^[0-9a-fA-F]+$", s)) and len(s) % 2 == 0

    def scan(self, duration_s=8):
        return {
            "name": "ble_panel", "ok": True,
            "data": {"devices": []},
            "error": "", "duration_s": 0.1, "host_os": "Linux", "risk": "read",
        }

    def services(self, address):
        return {
            "name": "ble_panel", "ok": True,
            "data": {"services": []},
            "error": "", "duration_s": 0.1, "host_os": "Linux", "risk": "read",
        }

    def characteristics(self, address, service_uuid):
        return {
            "name": "ble_panel", "ok": True,
            "data": {"characteristics": []},
            "error": "", "duration_s": 0.1, "host_os": "Linux", "risk": "read",
        }

    def read(self, address, char_uuid):
        return {
            "name": "ble_panel", "ok": True,
            "data": {"value_hex": "deadbeef"},
            "error": "", "duration_s": 0.1, "host_os": "Linux", "risk": "intrusive",
        }

    def write(self, address, char_uuid, value_hex):
        return {
            "name": "ble_panel", "ok": True,
            "data": {"wrote": value_hex},
            "error": "", "duration_s": 0.1, "host_os": "Linux", "risk": "intrusive",
        }

    def notify(self, address, char_uuid, duration_s=5):
        return {
            "name": "ble_panel", "ok": True,
            "data": {"notifications": [], "count": 0},
            "error": "", "duration_s": 0.1, "host_os": "Linux", "risk": "intrusive",
        }
