"""core.post_access_tui.ble_panel_capabilities — capability catalog
for the dynamic BLE TUI menu.

The dynamic-menu pattern:
  - Every action the panel can ever do is registered as a
    ``Capability`` here. Each capability declares:
      * a single-letter hotkey
      * a label
      * a risk level (read / intrusive / destructive)
      * a list of state conditions it requires
        (``"connected"``, ``"writable_char"``, ``"heart_rate_service"``,
        ``"monitor_mode"``, etc.)
      * a function that tests whether the capability is currently
        available, given the panel's state snapshot.
  - The panel computes the visible menu by filtering the catalog with
    the current state. The rendered menu shows ONLY the actions that
    pass the availability check. The full catalog is always registered;
    the panel just doesn't show unavailable entries.

This decouples the action set (60+ entries) from the menu rendering
(whatever subset is relevant to the connected target).

The SIG UUID table (16-bit) maps standard UUIDs to friendly names so
the GATT browser shows ``Heart Rate Measurement (0x2A37)`` instead of
the bare UUID.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set


# ---------------------------------------------------------------------------
# SIG-assigned 16-bit BLE UUIDs (Bluetooth SIG GATT specifications)
# ---------------------------------------------------------------------------
#: Maps the 16-bit SIG-assigned UUID (e.g. ``0x180D``) to its full
#: 128-bit form and a friendly name. Used by the GATT browser to render
#: readable labels. The set covers the most common services +
#: characteristics seen in field work.

_SIG_UUID_16BIT: Dict[int, str] = {
    # --- Services ---
    0x1800: "Generic Access",
    0x1801: "Generic Attribute",
    0x1802: "Immediate Alert",
    0x1803: "Link Loss",
    0x1804: "Tx Power",
    0x1805: "Current Time",
    0x1806: "Reference Time Update",
    0x1807: "Next DST Change",
    0x1808: "Glucose",
    0x1809: "Health Thermometer",
    0x180A: "Device Information",
    0x180D: "Heart Rate",
    0x180E: "Phone Alert Status",
    0x180F: "Battery",
    0x1810: "Blood Pressure",
    0x1811: "Alert Notification",
    0x1812: "Human Interface Device",
    0x1813: "Scan Parameters",
    0x1814: "Running Speed and Cadence",
    0x1815: "Automation IO",
    0x1816: "Cycling Power",
    0x1817: "Cycling Speed and Cadence",
    0x1818: "Location and Navigation",
    0x1819: "Environmental Sensing",
    0x181A: "Body Composition",
    0x181B: "User Data",
    0x181C: "Weight Scale",
    0x181D: "Bond Management",
    0x181E: "Continuous Glucose Monitoring",
    0x181F: "Pulse Oximeter",
    0x1820: "Internet Protocol Support",
    0x1821: "Indoor Positioning",
    0x1822: "Cycling Power (Vector)",
    0x1823: "Date Time",
    0x1824: "Weight (kg, lbs)",
    0x1825: "Weight (resolution 0.01)",
    0x1826: "Fitness Machine",
    0x1827: "Mesh Provisioning",
    0x1828: "Mesh Proxy",
    0x1829: "Reconnection Configuration",
    # --- Characteristics ---
    0x2A00: "Device Name",
    0x2A01: "Appearance",
    0x2A02: "Peripheral Privacy Flag",
    0x2A03: "Reconnection Address",
    0x2A04: "Peripheral Preferred Connection Parameters",
    0x2A05: "Service Changed",
    0x2A06: "Alert Level",
    0x2A07: "Tx Power Level",
    0x2A08: "Date Time",
    0x2A09: "Day of Week",
    0x2A0A: "Day Date Time",
    0x2A0C: "Exact Time 256",
    0x2A0D: "DST Offset",
    0x2A0E: "Time Zone",
    0x2A0F: "Local Time Information",
    0x2A11: "Time with DST",
    0x2A12: "Time Accuracy",
    0x2A13: "Time Source",
    0x2A14: "Reference Time Information",
    0x2A16: "Time Update Control Point",
    0x2A17: "Time Update State",
    0x2A18: "Glucose Measurement",
    0x2A19: "Battery Level",
    0x2A1C: "Temperature Measurement",
    0x2A1D: "Temperature Type",
    0x2A1E: "Intermediate Temperature",
    0x2A21: "Measurement Interval",
    0x2A22: "Boot Keyboard Input Report",
    0x2A23: "System ID",
    0x2A24: "Model Number String",
    0x2A25: "Serial Number String",
    0x2A26: "Firmware Revision String",
    0x2A27: "Hardware Revision String",
    0x2A28: "Software Revision String",
    0x2A29: "Manufacturer Name String",
    0x2A2A: "IEEE 11073-20601 Regulatory Certification Data List",
    0x2A2B: "Current Time",
    0x2A2C: "Magnetic Declination",
    0x2A31: "Scan Refresh",
    0x2A32: "Boot Keyboard Output Report",
    0x2A33: "Boot Mouse Input Report",
    0x2A34: "Glucose Measurement Context",
    0x2A35: "Blood Pressure Measurement",
    0x2A36: "Intermediate Cuff Pressure",
    0x2A37: "Heart Rate Measurement",
    0x2A38: "Body Sensor Location",
    0x2A39: "Heart Rate Control Point",
    0x2A3F: "Alert Status",
    0x2A40: "Ringer Control Point",
    0x2A41: "Ringer Setting",
    0x2A42: "Alert Category ID Bit Mask",
    0x2A43: "Alert Category ID",
    0x2A44: "Alert Notification Control Point",
    0x2A45: "Unread Alert Status",
    0x2A46: "New Alert",
    0x2A47: "Supported New Alert Category",
    0x2A48: "Supported Unread Alert Category",
    0x2A49: "Blood Pressure Feature",
    0x2A4A: "HID Information",
    0x2A4B: "Report Map",
    0x2A4C: "HID Control Point",
    0x2A4D: "Report",
    0x2A4E: "Protocol Mode",
    0x2A50: "PnP ID",
    0x2A51: "Glucose Feature",
    0x2A52: "Record Access Control Point",
    0x2A53: "RSC Measurement",
    0x2A54: "RSC Feature",
    0x2A55: "SC Control Point",
    0x2A5B: "CSC Measurement",
    0x2A5C: "CSC Feature",
    0x2A5D: "Sensor Location",
    0x2A5E: "PLX Spot-Check Measurement",
    0x2A5F: "PLX Continuous Measurement",
    0x2A60: "PLX Features",
    0x2A63: "Cycling Power Measurement",
    0x2A64: "Cycling Power Vector",
    0x2A65: "Cycling Power Feature",
    0x2A66: "Cycling Power Control Point",
    0x2A67: "Location and Speed",
    0x2A68: "Navigation",
    0x2A69: "Position Quality",
    0x2A6A: "LN Feature",
    0x2A6B: "Position 2D",
    0x2A6C: "Position 3D",
    0x2A6D: "Local Position",
    0x2A6E: "Network Availability",
    0x2A6F: "AP Sync Key",
    0x2A70: "LN Control Point",
    0x2A71: "LN Feature (Vector)",
    0x2A72: "Indoor Positioning Configuration",
    0x2A73: "Latitude",
    0x2A74: "Longitude",
    0x2A75: "Local North",
    0x2A76: "Floor Number",
    0x2A77: "Altitude",
    0x2A78: "Uncertainty",
    0x2A79: "Location Name",
    0x2A7A: "URI",
    0x2A7B: "HTTP Headers",
    0x2A7C: "HTTP Status Code",
    0x2A7D: "HTTP Entity Body",
    0x2A7E: "HTTP Control Point",
    0x2A7F: "HTTPS Security",
    0x2A80: "Network Address",
    0x2A81: "Manufacturer Name",
    0x2A82: "Model Number",
    0x2A83: "Serial Number",
    0x2A84: "Firmware Revision",
    0x2A85: "Hardware Revision",
    0x2A86: "Software Revision",
    0x2A87: "System ID",
    0x2A88: "Battery Level State",
    0x2A89: "Battery Level (Full)",
    0x2A8A: "Battery Time (days)",
    0x2A8B: "Battery Time (hours)",
    0x2A8C: "Battery Time (minutes)",
    0x2A8D: "Battery Time (seconds)",
    0x2A8E: "Battery Energy",
    0x2A8F: "Battery Energy (Full)",
    0x2A90: "Battery Temperature",
    0x2A91: "Battery Voltage",
    0x2A92: "Battery Current",
    0x2A93: "Battery Health",
    0x2A94: "Battery Health Summary",
    0x2A95: "Battery Information",
    0x2A96: "Battery Service Specification",
    0x2A97: "Battery Service Date",
    0x2A98: "Battery Service Serial",
    0x2A99: "Battery Service Type",
    0x2A9A: "Battery Service Status",
    0x2A9B: "Battery Service Fault",
    0x2A9C: "Battery Service Event",
    0x2A9D: "Battery Service Test",
    0x2A9E: "Battery Service Reset",
}


def _uuid16_to_full(uuid16: int) -> str:
    """Convert a 16-bit SIG UUID to the canonical 128-bit form
    ``0000XXXX-0000-1000-8000-00805f9b34fb``."""
    return f"0000{uuid16:04x}-0000-1000-8000-00805f9b34fb"


def _full_to_uuid16(uuid_full: str) -> Optional[int]:
    """Inverse of ``_uuid16_to_full``. Returns ``None`` for custom
    (non-SIG) UUIDs."""
    m = re.match(
        r"^0000([0-9a-fA-F]{4})-0000-1000-8000-00805f9b34fb$",
        uuid_full,
    )
    if not m:
        return None
    try:
        return int(m.group(1), 16)
    except (TypeError, ValueError):
        return None


def friendly_uuid_name(uuid: str) -> str:
    """Return the SIG-friendly name for a UUID, or the bare UUID if
    not in the SIG table.

    Examples:
        >>> friendly_uuid_name("00002a37-0000-1000-8000-00805f9b34fb")
        'Heart Rate Measurement (0x2A37)'
        >>> friendly_uuid_name("00001800-0000-1000-8000-00805f9b34fb")
        'Generic Access (0x1800)'
        >>> friendly_uuid_name("abcdef00-1234-1234-1234-123456789012")
        'abcdef00-1234-1234-1234-123456789012'
    """
    u16 = _full_to_uuid16(uuid)
    if u16 is not None and u16 in _SIG_UUID_16BIT:
        return f"{_SIG_UUID_16BIT[u16]} (0x{u16:04x})"
    return uuid


# ---------------------------------------------------------------------------
# Capability model
# ---------------------------------------------------------------------------

#: Risk levels — used by the gate prompt wording.
RISK_READ = "read"
RISK_INTRUSIVE = "intrusive"
RISK_DESTRUCTIVE = "destructive"


@dataclass
class Capability:
    """A single action the panel can perform, with a description of
    when it is available.

    The availability_fn receives a :class:`PanelState` snapshot and
    returns True iff the action is currently usable.
    """
    action: str                              # "write", "heart_rate", ...
    hotkey: str                              # "w", "h", ...
    label: str                               # "[W]rite — ..."
    risk: str = RISK_READ
    requires_gate: bool = False
    availability_fn: Callable[["PanelState"], bool] = (
        lambda _s: True
    )
    needs: List[str] = field(default_factory=list)
    help_text: str = ""


@dataclass
class PanelState:
    """A snapshot of the panel's current state.

    Used to compute the visible menu. The panel mutates this on
    every state change (after scan, connect, gatt, etc.) and the
    menu is recomputed.
    """
    # Connection state
    connected: bool = False
    address: Optional[str] = None
    # Discovered service UUIDs (lowercase 128-bit)
    service_uuids: Set[str] = field(default_factory=set)
    # Discovered characteristic UUIDs indexed by uuid
    chars: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    # Bond state
    bonded: bool = False
    # MTU (0 = default 23)
    mtu: int = 0
    # RSSI history
    rssi_history: List[int] = field(default_factory=list)
    # Last notification timestamp (epoch seconds; 0 = none)
    last_notify_at: float = 0.0
    # Last write value (for [R]epeat)
    last_write_uuid: Optional[str] = None
    last_write_hex: Optional[str] = None
    # Last read value (for [P]rint)
    last_read_uuid: Optional[str] = None
    last_read_hex: Optional[str] = None
    # Saved devices (loaded from disk)
    saved_devices: List[Dict[str, Any]] = field(default_factory=list)
    # Cached scan results
    devices: List[Any] = field(default_factory=list)

    def has_service(self, uuid16: int) -> bool:
        """True iff a SIG service UUID ``uuid16`` is in service_uuids."""
        return _uuid16_to_full(uuid16) in self.service_uuids

    def has_char(self, uuid16: int) -> bool:
        """True iff a SIG char UUID ``uuid16`` is in chars."""
        return _uuid16_to_full(uuid16) in self.chars

    def has_writable_char(self) -> bool:
        """True iff any characteristic in chars has the 'write' or
        'write-without-response' property."""
        for c in self.chars.values():
            props = c.get("properties") or []
            if "write" in props or "write-without-response" in props:
                return True
        return False

    def has_notifiable_char(self) -> bool:
        for c in self.chars.values():
            props = c.get("properties") or []
            if "notify" in props or "indicate" in props:
                return True
        return False

    def has_readable_char(self) -> bool:
        for c in self.chars.values():
            props = c.get("properties") or []
            if "read" in props:
                return True
        return False


# ---------------------------------------------------------------------------
# Capability builders (small helpers for the common shape)
# ---------------------------------------------------------------------------

def _always(_s: PanelState) -> bool:
    return True


def _connected(s: PanelState) -> bool:
    return s.connected


def _writable(s: PanelState) -> bool:
    return s.connected and s.has_writable_char()


def _notifiable(s: PanelState) -> bool:
    return s.connected and s.has_notifiable_char()


def _readable(s: PanelState) -> bool:
    return s.connected and s.has_readable_char()


def _has_hr(s: PanelState) -> bool:
    return s.connected and s.has_service(0x180D)


def _has_battery(s: PanelState) -> bool:
    return s.connected and s.has_service(0x180F)


def _has_device_info(s: PanelState) -> bool:
    return s.connected and s.has_service(0x180A)


def _has_tx_power(s: PanelState) -> bool:
    return s.connected and (s.has_service(0x1804) or s.has_char(0x2A07))


def _has_link_loss(s: PanelState) -> bool:
    return s.connected and s.has_service(0x1803)


def _has_automation_io(s: PanelState) -> bool:
    return s.connected and s.has_service(0x1815)


def _has_descriptor(s: PanelState) -> bool:
    return s.connected and bool(s.chars)


def _has_rssi(s: PanelState) -> bool:
    return s.connected and bool(s.rssi_history)


def _has_mtu(s: PanelState) -> bool:
    return s.connected


def _has_pair(s: PanelState) -> bool:
    return s.connected and not s.bonded


def _has_unpair(s: PanelState) -> bool:
    return s.connected and s.bonded


def _has_saved_devices(s: PanelState) -> bool:
    return bool(s.saved_devices)


def _has_scan_results(s: PanelState) -> bool:
    """True iff the panel has any scan results to work with."""
    return bool(s.devices)


def _has_adapter(s: PanelState) -> bool:
    """True iff the panel has a HCI adapter detected (hci0 visible)."""
    # The adapter presence is tracked via devices/devices-last-seen;
    # if either is non-empty, the adapter is alive.
    return bool(getattr(s, "devices", None)) or bool(
        getattr(s, "saved_devices", None)
    )


def _has_repeat_write(s: PanelState) -> bool:
    return s.connected and s.last_write_hex is not None


def _always_available(s: PanelState) -> bool:
    """Always available (the panel-side gate is the only gate)."""
    return True


# ---------------------------------------------------------------------------
# The capability catalog
# ---------------------------------------------------------------------------

CAPABILITY_CATALOG: List[Capability] = [
    # ----- Universal (always available) -----
    Capability(
        action="scan", hotkey="s",
        label="[S]can — discover nearby BLE devices",
        risk=RISK_READ, requires_gate=False,
        availability_fn=_always, needs=[],
        help_text="Run hcitool lescan for a few seconds. Discovers all BLE peripherals in range.",
    ),
    Capability(
        action="list", hotkey="l",
        label="[L]ist — show devices from last scan",
        risk=RISK_READ, requires_gate=False,
        availability_fn=lambda s: bool(s.devices),
        needs=["scan_results"],
        help_text="Show the device list from the last scan.",
    ),
    Capability(
        action="connect", hotkey="c",
        label="[C]onnect — pick a device from the list",
        risk=RISK_READ, requires_gate=False,
        availability_fn=lambda s: bool(s.devices) or bool(s.saved_devices),
        needs=["scan_results"],
        help_text="Connect to a device. Pick by index from the list, or type an address.",
    ),
    Capability(
        action="saved", hotkey="v",
        label="[V]iew saved — show persisted device profiles",
        risk=RISK_READ, requires_gate=False,
        availability_fn=_has_saved_devices,
        needs=["saved_devices"],
        help_text="Show the device profiles persisted on disk (address, last seen, services).",
    ),
    Capability(
        action="help", hotkey="?",
        label="[?] Help — list all currently-available actions",
        risk=RISK_READ, requires_gate=False,
        availability_fn=_always, needs=[],
        help_text="Show only the actions you can take right now.",
    ),
    Capability(
        action="exit", hotkey="e",
        label="[E]xit — return to the post-access TUI menu",
        risk=RISK_READ, requires_gate=False,
        availability_fn=_always, needs=[],
        help_text="Close the BLE panel and return to the post-access TUI.",
    ),

    # ----- Connection management -----
    Capability(
        action="gatt", hotkey="g",
        label="[G]att — walk services on the connected device",
        risk=RISK_READ, requires_gate=False,
        availability_fn=_connected, needs=["connected"],
        help_text="Enumerate all primary services + characteristics on the connected device.",
    ),
    Capability(
        action="rssi", hotkey="r",
        label="[R]ssi — show recent signal strength readings",
        risk=RISK_READ, requires_gate=False,
        availability_fn=_has_rssi, needs=["connected", "rssi_history"],
        help_text="Show the RSSI history (dBm) — used to estimate distance.",
    ),
    Capability(
        action="mtu", hotkey="m",
        label="[M]tu — request larger MTU on the connection",
        risk=RISK_INTRUSIVE, requires_gate=True,
        availability_fn=_has_mtu, needs=["connected"],
        help_text="Negotiate a larger MTU (e.g. 185, 247) for faster transfers.",
    ),
    Capability(
        action="pair", hotkey="p",
        label="[P]air — initiate pairing/bonding (no auto-bond)",
        risk=RISK_INTRUSIVE, requires_gate=True,
        availability_fn=_has_pair, needs=["connected", "not_bonded"],
        help_text="Start the pairing/bonding flow. Surfaces the btmgmt pair command for the operator.",
    ),
    Capability(
        action="unpair", hotkey="u",
        label="[U]npair — drop the bond",
        risk=RISK_INTRUSIVE, requires_gate=True,
        availability_fn=_has_unpair, needs=["connected", "bonded"],
        help_text="Remove the bond. Surfaces the btmgmt unpair command for the operator.",
    ),
    Capability(
        action="disconnect", hotkey="d",
        label="[D]isconnect — drop the current device",
        risk=RISK_READ, requires_gate=False,
        availability_fn=_connected, needs=["connected"],
        help_text="Disconnect from the current device.",
    ),

    # ----- Generic GATT operations -----
    Capability(
        action="read", hotkey="1",
        label="[1] Read — pick a characteristic to read",
        risk=RISK_INTRUSIVE, requires_gate=True,
        availability_fn=_readable, needs=["connected", "readable_char"],
        help_text="Pick a characteristic by index from the GATT table, or type a UUID.",
    ),
    Capability(
        action="write", hotkey="2",
        label="[2] Write — pick a characteristic to write",
        risk=RISK_INTRUSIVE, requires_gate=True,
        availability_fn=_writable, needs=["connected", "writable_char"],
        help_text="Pick a writable characteristic, then enter hex bytes (with ASCII preview).",
    ),
    Capability(
        action="notify", hotkey="3",
        label="[3] Notify — subscribe to a notifiable characteristic",
        risk=RISK_INTRUSIVE, requires_gate=True,
        availability_fn=_notifiable, needs=["connected", "notifiable_char"],
        help_text="Subscribe to notifications from a notifiable char. Captures values for the duration.",
    ),
    Capability(
        action="desc", hotkey="4",
        label="[4] Descriptors — read/write CCCD and others",
        risk=RISK_INTRUSIVE, requires_gate=True,
        availability_fn=_has_descriptor, needs=["connected"],
        help_text="Read or write characteristic descriptors (e.g. CCCD to enable notify).",
    ),
    Capability(
        action="repeat", hotkey="5",
        label="[5] Repeat — re-send the last write",
        risk=RISK_INTRUSIVE, requires_gate=True,
        availability_fn=_has_repeat_write, needs=["connected", "last_write"],
        help_text="Re-send the last hex value to the same char (convenience for testing).",
    ),
    Capability(
        action="bleshell", hotkey="b",
        label="[B]le-shell — cmd over a writable char (hex)",
        risk=RISK_INTRUSIVE, requires_gate=True,
        availability_fn=_writable, needs=["connected", "writable_char"],
        help_text="Type a command, panel hex-encodes + writes to write_uuid, then reads back from read_uuid.",
    ),

    # ----- SIG profile shortcuts (only available if the service is present) -----
    Capability(
        action="heart_rate", hotkey="h",
        label="[H]eart rate — auto-read 0x2A37 (live)",
        risk=RISK_INTRUSIVE, requires_gate=True,
        availability_fn=_has_hr, needs=["connected", "service:0x180D"],
        help_text="Subscribe to Heart Rate Measurement (0x2A37). Decodes bpm + sensor contact.",
    ),
    Capability(
        action="battery", hotkey="y",
        label="[Y] Battery — read 0x2A19 once",
        risk=RISK_INTRUSIVE, requires_gate=True,
        availability_fn=_has_battery, needs=["connected", "service:0x180F"],
        help_text="Read Battery Level (0x2A19) once. Returns 0..100 percent.",
    ),
    Capability(
        action="device_info", hotkey="i",
        label="[I] Device info — read 0x180A strings",
        risk=RISK_INTRUSIVE, requires_gate=True,
        availability_fn=_has_device_info, needs=["connected", "service:0x180A"],
        help_text="Read all Device Information strings: manufacturer, model, serial, firmware, hardware, software.",
    ),
    Capability(
        action="tx_power", hotkey="t",
        label="[T]x power — read 0x2A07 (dBm)",
        risk=RISK_READ, requires_gate=False,
        availability_fn=_has_tx_power, needs=["connected", "service:0x1804"],
        help_text="Read the Tx Power Level characteristic (0x2A07).",
    ),
    Capability(
        action="link_loss", hotkey="k",
        label="[K] Link loss — set alert level (0x2A06)",
        risk=RISK_INTRUSIVE, requires_gate=True,
        availability_fn=_has_link_loss, needs=["connected", "service:0x1803"],
        help_text="Set the Link Loss Alert Level (0=no, 1=mild, 2=high). Affects peripheral's reaction.",
    ),
    Capability(
        action="automation_io", hotkey="o",
        label="[O] Automation IO — digital/analog I/O over 0x1815",
        risk=RISK_INTRUSIVE, requires_gate=True,
        availability_fn=_has_automation_io, needs=["connected", "service:0x1815"],
        help_text="Read/write digital + analog I/O values via the Automation IO service.",
    ),

    # ----- Live-stream shortcuts -----
    Capability(
        action="stream", hotkey="6",
        label="[6] Stream — continuous notify + live tail",
        risk=RISK_INTRUSIVE, requires_gate=True,
        availability_fn=_notifiable, needs=["connected", "notifiable_char"],
        help_text="Run notify continuously, with a live tail and optional hex filter.",
    ),

    # ----- Advanced recon / attack modules (creative + useful) -----
    Capability(
        action="ble_adv_scan", hotkey="A",
        label="[A]dv-scan — extended advertisement parsing",
        risk=RISK_READ, requires_gate=False,
        availability_fn=_always, needs=[],
        help_text="Capture extended advertising PDUs, decode manufacturer data, "
                  "parse service data, identify beacon types (iBeacon, Eddystone, "
                  "AltBeacon, custom).",
    ),
    Capability(
        action="ble_eddystone", hotkey="E",
        label="[E]ddystone — URL/UID/TLM frame parser",
        risk=RISK_READ, requires_gate=False,
        availability_fn=_has_scan_results, needs=["scan_results"],
        help_text="Decode Eddystone frames: URL, UID, TLM (telemetry), EID "
                  "(ephemeral identifier). Surfaces physical-web URLs.",
    ),
    Capability(
        action="ble_ibeacon", hotkey="J",
        label="[J]iBeacon — major/minor/UUID extractor",
        risk=RISK_READ, requires_gate=False,
        availability_fn=_has_scan_results, needs=["scan_results"],
        help_text="Detect iBeacon frames; extract proximity UUID, major, minor, "
                  "tx power. Useful for indoor positioning recon.",
    ),
    Capability(
        action="ble_servicedata", hotkey="W",
        label="[W] Service-data — decode manufacturer/service-data blobs",
        risk=RISK_READ, requires_gate=False,
        availability_fn=_has_scan_results, needs=["scan_results"],
        help_text="Parse Service Data (0x16) and Manufacturer Specific Data "
                  "(0xFF) into known formats (Tile, AirTag, Samsung, Nordic).",
    ),
    Capability(
        action="ble_pair_passkey", hotkey="9",
        label="[9] Passkey — supply 6-digit passkey (LE legacy pairing)",
        risk=RISK_INTRUSIVE, requires_gate=True,
        availability_fn=_has_pair, needs=["connected", "not_bonded"],
        help_text="Inject the operator's 6-digit passkey for LE legacy pairing. "
                  "Used when the peripheral displays a passkey.",
    ),
    Capability(
        action="ble_pair_noresp", hotkey="0",
        label="[0] NoRespPair — pair without IO capability",
        risk=RISK_INTRUSIVE, requires_gate=True,
        availability_fn=_has_pair, needs=["connected", "not_bonded"],
        help_text="Use NoInputNoOutput IO capability to pair against peripherals "
                  "without a display/keyboard (e.g. heart-rate straps).",
    ),
    Capability(
        action="ble_justworks", hotkey="=",
        label="[=] JustWorks — accept default Just-Works pairing",
        risk=RISK_INTRUSIVE, requires_gate=True,
        availability_fn=_has_pair, needs=["connected", "not_bonded"],
        help_text="Accept Just-Works pairing (no auth). Vulnerable to MITM unless "
                  "Out-of-Band data is verified out-of-band.",
    ),
    Capability(
        action="ble_oob_pair", hotkey="+",
        label="[+] OOB — supply Out-of-Band TK (NFC / QR)",
        risk=RISK_INTRUSIVE, requires_gate=True,
        availability_fn=_has_pair, needs=["connected", "not_bonded"],
        help_text="Inject the Out-of-Band TK (e.g. from an NFC tag, QR code, or "
                  "operator's other channel). Defeats MITM even on Just-Works.",
    ),
    Capability(
        action="ble_crackltk", hotkey="K",
        label="[K] Crack-LTK — brute-force legacy long-term key",
        risk=RISK_DESTRUCTIVE, requires_gate=True,
        availability_fn=_has_repeat_write, needs=["connected", "last_write"],
        help_text="Brute-force a captured LTK against a known IRK. Used after "
                  "LE legacy pairing capture. Lab-only; never on prod devices.",
    ),
    Capability(
        action="ble_irk_recover", hotkey="Q",
        label="[Q] Recover IRK — derive IRK from Identity Address",
        risk=RISK_DESTRUCTIVE, requires_gate=True,
        availability_fn=_connected, needs=["connected"],
        help_text="Use random address resolution to recover the device's IRK "
                  "(privacy-defeating). Lab-only.",
    ),
    Capability(
        action="ble_keyfuzz", hotkey="F",
        label="[F] Fuzz — af-fuzz-style input fuzzer over a writable char",
        risk=RISK_DESTRUCTIVE, requires_gate=True,
        availability_fn=_writable, needs=["connected", "writable_char"],
        help_text="Fuzz a writable char with structured random inputs (length "
                  "classes, ASCII, binary, json). Logs all responses. Lab only.",
    ),
    Capability(
        action="ble_protocol", hotkey="Z",
        label="[Z] Protocol-decoder — pick a known BLE-over-GATT protocol",
        risk=RISK_INTRUSIVE, requires_gate=True,
        availability_fn=_connected, needs=["connected"],
        help_text="Pick a known protocol (Nordic UART, DFU, ANCS, AMS) and "
                  "auto-decode notify traffic into structured records.",
    ),
    Capability(
        action="ble_nus_bridge", hotkey="N",
        label="[N] NUS — Nordic UART Service shell bridge",
        risk=RISK_INTRUSIVE, requires_gate=True,
        availability_fn=_connected, needs=["connected"],
        help_text="Open a shell over Nordic UART Service (6E400001-B5A3-F393-E0A9-E50E24DCCA9E). "
                  "Useful for ESP32 / nRF52 / Arduino boards exposed as NUS.",
    ),
    Capability(
        action="ble_dfu", hotkey="D",
        label="[D] DFU — push firmware update (nRF DFU / OTA)",
        risk=RISK_DESTRUCTIVE, requires_gate=True,
        availability_fn=_connected, needs=["connected"],
        help_text="Push a .zip firmware update over the nRF52 Device Firmware "
                  "Update (DFU) service. Brick risk: HIGH. Lab only.",
    ),
    Capability(
        action="ble_logbook", hotkey="L",
        label="[L]ogbook — write a session entry (markdown + JSON)",
        risk=RISK_READ, requires_gate=False,
        availability_fn=_connected, needs=["connected"],
        help_text="Write a session entry to data/ble_sessions/. Captures "
                  "device profile, services, last 50 char reads, timeline.",
    ),
    Capability(
        action="ble_replay", hotkey="R",
        label="[R]eplay — replay captured write sequence",
        risk=RISK_DESTRUCTIVE, requires_gate=True,
        availability_fn=_has_repeat_write, needs=["connected", "last_write"],
        help_text="Replay a previously captured notify+write sequence against "
                  "the same or a different device.",
    ),
    Capability(
        action="ble_channel_map", hotkey="M",
        label="[M] Channel-map — show all 40 BLE data channels seen",
        risk=RISK_READ, requires_gate=False,
        availability_fn=_has_scan_results, needs=["scan_results"],
        help_text="Histogram of which of the 40 BLE data channels each device "
                  "is using. Surfaces channel-hopping patterns.",
    ),
    Capability(
        action="ble_rssi_track", hotkey="T",
        label="[T]rack — log RSSI over time to estimate proximity",
        risk=RISK_READ, requires_gate=False,
        availability_fn=_connected, needs=["connected"],
        help_text="Sample RSSI for 30s and apply a path-loss model to estimate "
                  "distance. Useful for indoor recon of moving devices.",
    ),
    Capability(
        action="ble_addr_resolve", hotkey="X",
        label="[X] Addr-resolve — random address → identity (IRK)",
        risk=RISK_DESTRUCTIVE, requires_gate=True,
        availability_fn=_has_scan_results, needs=["scan_results"],
        help_text="Try to resolve a random address using all known IRKs. "
                  "Defeats BLE privacy. Lab only.",
    ),
    Capability(
        action="ble_clone", hotkey="n",
        label="Clo[n]e — clone a discovered device profile",
        risk=RISK_INTRUSIVE, requires_gate=True,
        availability_fn=_has_scan_results, needs=["scan_results"],
        help_text="Clone the discovered device's service/char UUIDs + name "
                  "into a local profile (data/ble_profiles/).",
    ),
    Capability(
        action="ble_central_role", hotkey="B",
        label="[B]roadcaster — switch adapter to broadcaster role",
        risk=RISK_INTRUSIVE, requires_gate=True,
        availability_fn=_has_adapter, needs=["adapter"],
        help_text="Switch the HCI adapter to broadcaster role and emit a "
                  "configurable advertisement (used for cloning tests).",
    ),
    Capability(
        action="ble_observer_role", hotkey="q",
        label="Ob[q]erver — switch adapter to observer role",
        risk=RISK_READ, requires_gate=False,
        availability_fn=_has_adapter, needs=["adapter"],
        help_text="Switch the HCI adapter to observer role (passive scan, "
                  "no scan-response requests). Less disruptive than active scan.",
    ),
    Capability(
        action="ble_export_pcap", hotkey="P",
        label="[P]cap-export — write a pcapng of the BLE traffic",
        risk=RISK_READ, requires_gate=False,
        availability_fn=_has_scan_results, needs=["scan_results"],
        help_text="Export the captured BLE traffic as a .pcapng (decoded as "
                  "LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR for Wireshark).",
    ),
    Capability(
        action="ble_passive_capture", hotkey="x",
        label="Passi[v]e-capture — long passive scan (60s, no connect)",
        risk=RISK_READ, requires_gate=False,
        availability_fn=_has_adapter, needs=["adapter"],
        help_text="Run a 60-second passive scan, log every advertisement. "
                  "Useful for low-noise recon.",
    ),
    Capability(
        action="ble_hid_inject", hotkey="f",
        label="HID-in[j]ect — push keystrokes to a HID-over-GATT device",
        risk=RISK_DESTRUCTIVE, requires_gate=True,
        availability_fn=_writable, needs=["connected", "writable_char"],
        help_text="Push keystrokes to a HID-over-GATT peripheral (e.g. BLE "
                  "keyboards). Lab only — keystroke injection is a hostile "
                  "action against a target's input device.",
    ),

    # ----- Full auto (single-gated AI pwn) -----
    Capability(
        action="full_auto_pwn", hotkey="!",
        label="[!] Full auto — AI-driven end-to-end pwn",
        risk=RISK_DESTRUCTIVE, requires_gate=True,
        availability_fn=_always_available, needs=["connected"],
        help_text="One gate prompt, then AI plans + walks the full chain "
                  "and opens the post-access TUI on access. Operator-owned "
                  "device only.",
    ),
]


def compute_visible_menu(state: PanelState) -> List[Capability]:
    """Return the list of capabilities that are currently available
    given the panel state. The menu shows ONLY these.

    Order: catalog order is preserved (so the menu is stable). The
    panel can re-order if it wants; for now we keep catalog order.
    """
    out: List[Capability] = []
    for cap in CAPABILITY_CATALOG:
        try:
            if bool(cap.availability_fn(state)):
                out.append(cap)
        except Exception:  # noqa: BLE001
            # A bug in one capability's availability_fn must NOT
            # crash the menu. Skip silently.
            continue
    return out


# ---------------------------------------------------------------------------
# Exports
# ---------------------------------------------------------------------------
__all__ = [
    "RISK_READ",
    "RISK_INTRUSIVE",
    "RISK_DESTRUCTIVE",
    "Capability",
    "PanelState",
    "CAPABILITY_CATALOG",
    "compute_visible_menu",
    "friendly_uuid_name",
    "_SIG_UUID_16BIT",
    "_uuid16_to_full",
    "_full_to_uuid16",
]
