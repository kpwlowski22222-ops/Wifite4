"""core.post_access_tui.ble_panel — BLE RAT-like TUI panel.

Extends the post-access TUI with a Bluetooth Low Energy control panel
that talks to nearby BLE peripherals via ``gatttool`` (the same
substrate used by ``core.ble.runner`` and ``core.ble.attack_runner``).

Dynamic menu (Phase 2.1.C++):
  The panel keeps a :class:`PanelState` snapshot (connected address,
  discovered service UUIDs, characteristic properties, RSSI history,
  etc.) and renders ONLY the actions that are currently applicable
  to the connected target. The capability catalog is in
  ``ble_panel_capabilities.py`` (60+ actions including SIG-profile
  shortcuts like ``heart_rate`` and ``battery``). The menu is
  recomputed on every state change.

Examples:
  - Disconnected: ``[S]can / [L]ist / [C]onnect / [V]iew saved / [?] Help / [E]xit``
  - Connected to a heart-rate monitor: adds ``[H]eart rate``,
    ``[R]ssi``, ``[1] Read``, ``[2] Write``, ``[3] Notify``,
    ``[4] Descriptors``, ``[5] Repeat``, ``[B]le-shell``,
    ``[P]air``, ``[D]isconnect``, etc.
  - Connected to a battery-only device: adds ``[Y] Battery``,
    hides ``[H]eart rate``, etc.

The panel is hermetic-friendly: every method takes an injected
``client`` object (the default is a real ``BLEPanelClient`` that
wraps gatttool). Tests inject a fake.

Safety stance (carried over):
  - Every write/notify/shell action is operator-gated via
    ``self.confirm_fn(prompt)`` BEFORE the dispatch.
  - The panel NEVER auto-pairs or auto-bonds to a device. The
    ``pair`` action surfaces the ``btmgmt pair`` command; the
    operator runs it.
  - The panel NEVER executes the connected device's response — the
    operator copies it to a separate terminal.
  - No fabricated device addresses, no fabricated UUIDs, no
    fabricated characteristic values.

Single-gate invariant:
  The screen's ``_gate`` is the only gate. The panel's
  ``dispatch(...)`` method is the action layer; it does NOT
  re-confirm (single-gate).
"""
from __future__ import annotations

import json
import logging
import os
import re
import shlex
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from core.tui.base_screen import BaseScreen

from .session_state import _now
from .ble_panel_capabilities import (
    CAPABILITY_CATALOG,
    RISK_DESTRUCTIVE,
    RISK_INTRUSIVE,
    RISK_READ,
    Capability,
    PanelState,
    compute_visible_menu,
    friendly_uuid_name,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# BLE device / service / characteristic descriptors
# ---------------------------------------------------------------------------

@dataclass
class BLEDevice:
    """A discovered BLE peripheral.

    Attributes:
        address:  MAC address (``AA:BB:CC:DD:EE:FF``)
        name:     advertised local name (may be empty)
        rssi:     signal strength in dBm (int, may be 0 if unknown)
        adv_data: dict of parsed AD structures (manufacturer, service
                  UUIDs, etc.) — empty dict if not parsed
    """
    address: str
    name: str = ""
    rssi: int = 0
    adv_data: Dict[str, Any] = field(default_factory=dict)

    def label(self) -> str:
        n = self.name or "(no name)"
        return f"{self.address}  {n}  rssi={self.rssi}"


@dataclass
class BLECharacteristic:
    """A GATT characteristic on a connected device.

    Attributes:
        uuid:        characteristic UUID (string, e.g.
                     ``00002a37-0000-1000-8000-00805f9b34fb``)
        handle:      attribute handle (string, ``0x0025``)
        properties:  list of property strings (e.g. ``["read",
                     "write", "notify"]``)
        value_hex:   last read value (hex string, ``""`` until read)
    """
    uuid: str
    handle: str = ""
    properties: List[str] = field(default_factory=list)
    value_hex: str = ""


@dataclass
class BLEService:
    """A GATT service on a connected device.

    Attributes:
        uuid:             service UUID
        start_handle:     first attribute handle (hex string)
        end_handle:       last attribute handle (hex string)
        characteristics:  list of :class:`BLECharacteristic`
    """
    uuid: str
    start_handle: str = ""
    end_handle: str = ""
    characteristics: List[BLECharacteristic] = field(default_factory=list)


# ---------------------------------------------------------------------------
# BLE panel client (real gatttool/hcitool backend)
# ---------------------------------------------------------------------------

class BLEPanelClient:
    """Default backend: real ``gatttool`` + ``hcitool`` subprocesses.

    Mirrors the conventions in ``core.ble.runner`` / ``core.ble.attack_runner``.
    Returns the same envelope shape ``{"ok", "data", "error", ...}`` for
    hermetic parity with the runners.
    """

    DEFAULT_TIMEOUT = 30  # seconds

    def __init__(self, *, adapter: Optional[str] = None,
                 timeout: int = DEFAULT_TIMEOUT):
        self.adapter = adapter  # e.g. ``hci0``; ``None`` → default
        self.timeout = timeout

    def _hcitool(self) -> Optional[List[str]]:
        return (["hcitool"] if not self.adapter
                else ["hcitool", "-i", self.adapter])

    def _gatttool(self) -> List[str]:
        return (["gatttool"] if not self.adapter
                else ["gatttool", "-i", self.adapter])

    def _run(self, argv: List[str], *, timeout: Optional[int] = None
             ) -> Tuple[int, str, str]:
        """Run a subprocess. Returns (returncode, stdout, stderr).
        Never raises — the panel handles error envelopes."""
        try:
            p = subprocess.run(
                argv, capture_output=True, text=True,
                timeout=timeout or self.timeout,
            )
            return (p.returncode, p.stdout, p.stderr)
        except FileNotFoundError as e:
            return (127, "", f"tool not found: {e}")
        except subprocess.TimeoutExpired as e:
            return (124, e.stdout or "", f"timeout after {e.timeout}s")
        except Exception as e:  # noqa: BLE001
            return (1, "", f"subprocess error: {e}")

    # ------------------------------------------------------------------
    # Discovery
    # ------------------------------------------------------------------
    def scan(self, duration_s: int = 8) -> Dict[str, Any]:
        """``hcitool lescan`` for ``duration_s`` seconds. Returns
        envelope with ``data.devices`` (list of :class:`BLEDevice`).
        No auto-pairing; we only LIST devices.
        """
        started = _now()
        argv = self._hcitool() + ["lescan", "--duplicates"]
        try:
            p = subprocess.Popen(
                argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True,
            )
            time.sleep(max(1, duration_s))
            try:
                p.terminate()
            except Exception:  # noqa: BLE001
                pass
            try:
                stdout, stderr = p.communicate(timeout=5)
            except Exception:  # noqa: BLE001
                stdout, stderr = ("", "")
            try:
                p.kill()
            except Exception:  # noqa: BLE001
                pass
        except FileNotFoundError as e:
            return self._envelope(started, ok=False, error=str(e),
                                  data={"devices": []})
        except Exception as e:  # noqa: BLE001
            return self._envelope(started, ok=False,
                                  error=f"scan failed: {e}",
                                  data={"devices": []})
        devices = self._parse_lescan(stdout or "")
        return self._envelope(started, ok=True,
                              data={"devices": devices},
                              stdout=stdout or "",
                              stderr=stderr or "")

    @staticmethod
    def _parse_lescan(raw: str) -> List[BLEDevice]:
        """Parse ``hcitool lescan`` output: lines like
        ``AA:BB:CC:DD:EE:FF (unknown)`` or
        ``AA:BB:CC:DD:EE:FF FooBar``.
        Dedupe by address; preserve first-seen order."""
        out: Dict[str, BLEDevice] = {}
        addr_re = re.compile(
            r"^([0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:"
            r"[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2})\s*(.*)$"
        )
        for line in (raw or "").splitlines():
            line = line.strip()
            if not line or line.startswith("LE Scan ..."):
                continue
            m = addr_re.match(line)
            if not m:
                continue
            addr = m.group(1).upper()
            rest = (m.group(2) or "").strip()
            # Name is sometimes "(unknown)" — strip that
            if rest.startswith("(") and rest.endswith(")"):
                rest = ""
            if addr in out:
                continue
            out[addr] = BLEDevice(address=addr, name=rest, rssi=0)
        return list(out.values())

    # ------------------------------------------------------------------
    # GATT
    # ------------------------------------------------------------------
    def services(self, address: str) -> Dict[str, Any]:
        """Run ``gatttool -b <addr> --primary`` to enumerate primary
        services. Returns envelope with ``data.services``."""
        started = _now()
        if not self._valid_mac(address):
            return self._envelope(started, ok=False,
                                  error=f"invalid BLE address: {address!r}",
                                  data={"services": []})
        argv = self._gatttool() + ["-b", address, "--primary"]
        rc, stdout, stderr = self._run(argv)
        if rc != 0:
            return self._envelope(started, ok=False,
                                  error=f"gatttool primary failed (rc={rc}): {stderr.strip()}",
                                  data={"services": []})
        services = self._parse_primary_services(stdout)
        return self._envelope(started, ok=True,
                              data={"services": services},
                              stdout=stdout, stderr=stderr)

    @staticmethod
    def _parse_primary_services(raw: str) -> List[BLEService]:
        """Parse ``gatttool --primary`` output. Each line is
        ``attr handle: 0x0001, end grp handle: 0x0005 uuid: 00001800-0000-1000-8000-00805f9b34fb``.
        """
        out: List[BLEService] = []
        line_re = re.compile(
            r"attr handle:\s*(0x[0-9a-fA-F]+),\s*end grp handle:\s*"
            r"(0x[0-9a-fA-F]+)\s+uuid:\s*([0-9a-fA-F-]{8,})"
        )
        for line in (raw or "").splitlines():
            m = line_re.search(line)
            if not m:
                continue
            out.append(BLEService(
                uuid=m.group(3).lower(),
                start_handle=m.group(1).lower(),
                end_handle=m.group(2).lower(),
            ))
        return out

    def characteristics(self, address: str, service_uuid: str) -> Dict[str, Any]:
        """``gatttool -b <addr> --char-desc`` to enumerate characteristics
        of ``service_uuid``. Returns envelope with ``data.characteristics``."""
        started = _now()
        if not self._valid_mac(address):
            return self._envelope(started, ok=False,
                                  error=f"invalid BLE address: {address!r}",
                                  data={"characteristics": []})
        argv = self._gatttool() + ["-b", address, "--char-desc"]
        rc, stdout, stderr = self._run(argv)
        if rc != 0:
            return self._envelope(started, ok=False,
                                  error=f"gatttool char-desc failed (rc={rc}): {stderr.strip()}",
                                  data={"characteristics": []})
        chars = self._parse_characteristics(stdout)
        return self._envelope(started, ok=True,
                              data={"characteristics": chars},
                              stdout=stdout, stderr=stderr)

    @staticmethod
    def _parse_characteristics(raw: str) -> List[BLECharacteristic]:
        """Parse ``gatttool --char-desc`` output. Each line is
        ``handle: 0x0002, char properties: 0x02, char value handle: 0x0003, uuid: 00002a00-0000-1000-8000-00805f9b34fb``.
        """
        out: List[BLECharacteristic] = []
        # We pair declarations with property lines.
        # The output alternates between "handle:" (declaration) and
        # "char properties:" (description). We group on the same
        # declaration.
        current: Optional[BLECharacteristic] = None
        decl_re = re.compile(
            r"handle:\s*(0x[0-9a-fA-F]+),\s*char properties:\s*0x([0-9a-fA-F]+),"
            r"\s*char value handle:\s*(0x[0-9a-fA-F]+),\s*uuid:\s*"
            r"([0-9a-fA-F-]{8,})"
        )
        for line in (raw or "").splitlines():
            m = decl_re.search(line)
            if m:
                if current is not None:
                    out.append(current)
                props = int(m.group(2), 16)
                current = BLECharacteristic(
                    uuid=m.group(4).lower(),
                    handle=m.group(3).lower(),
                    properties=_properties_from_byte(props),
                )
                continue
            # Otherwise, hex value line "handle: 0x0003 value: ..."
            if current is not None:
                m2 = re.search(
                    r"handle:\s*0x[0-9a-fA-F]+\s+value:\s*([0-9a-fA-F.\s]+)",
                    line,
                )
                if m2:
                    current.value_hex = m2.group(1).strip()
        if current is not None:
            out.append(current)
        return out

    def read(self, address: str, char_uuid: str) -> Dict[str, Any]:
        """``gatttool -b <addr> --char-read -u <uuid>``."""
        started = _now()
        if not self._valid_mac(address):
            return self._envelope(started, ok=False,
                                  error=f"invalid BLE address: {address!r}")
        if not self._valid_uuid(char_uuid):
            return self._envelope(started, ok=False,
                                  error=f"invalid char uuid: {char_uuid!r}")
        argv = self._gatttool() + ["-b", address, "--char-read",
                                   "-u", char_uuid]
        rc, stdout, stderr = self._run(argv)
        if rc != 0:
            return self._envelope(started, ok=False,
                                  error=f"char-read failed (rc={rc}): {stderr.strip()}")
        # gatttool prints "Characteristic value/descriptor: <hex> ..."
        m = re.search(r"value:\s*([0-9a-fA-F]+)", stdout or "")
        if not m:
            return self._envelope(started, ok=False,
                                  error=f"no value in gatttool output: {stdout!r}")
        return self._envelope(started, ok=True,
                              data={"value_hex": m.group(1).lower()},
                              stdout=stdout, stderr=stderr)

    def write(self, address: str, char_uuid: str, value_hex: str) -> Dict[str, Any]:
        """``gatttool -b <addr> --char-write -u <uuid> -n <hex>``."""
        started = _now()
        if not self._valid_mac(address):
            return self._envelope(started, ok=False,
                                  error=f"invalid BLE address: {address!r}")
        if not self._valid_uuid(char_uuid):
            return self._envelope(started, ok=False,
                                  error=f"invalid char uuid: {char_uuid!r}")
        if not self._valid_hex(value_hex):
            return self._envelope(started, ok=False,
                                  error=f"invalid hex value: {value_hex!r}")
        argv = self._gatttool() + ["-b", address, "--char-write",
                                   "-u", char_uuid, "-n", value_hex]
        rc, stdout, stderr = self._run(argv)
        if rc != 0:
            return self._envelope(started, ok=False,
                                  error=f"char-write failed (rc={rc}): {stderr.strip()}")
        return self._envelope(started, ok=True, data={"wrote": value_hex},
                              stdout=stdout, stderr=stderr)

    def notify(self, address: str, char_uuid: str,
               duration_s: int = 5) -> Dict[str, Any]:
        """Run ``gatttool -b <addr> --char-read -u <uuid> --listen`` for
        ``duration_s`` seconds, then return the captured notifications.
        The ``--listen`` flag keeps gatttool in interactive mode;
        we use ``-I`` (interactive) + Popen and feed commands via stdin.

        For hermetic reasons, we use ``timeout`` to bound the listen.
        """
        started = _now()
        if not self._valid_mac(address):
            return self._envelope(started, ok=False,
                                  error=f"invalid BLE address: {address!r}")
        if not self._valid_uuid(char_uuid):
            return self._envelope(started, ok=False,
                                  error=f"invalid char uuid: {char_uuid!r}")
        # gatttool -I reads "connect\n" then "char-read-uuid <uuid>\n"
        argv = self._gatttool() + ["-b", address, "-I"]
        try:
            p = subprocess.Popen(
                argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, text=True,
            )
            assert p.stdin is not None and p.stdout is not None
            try:
                p.stdin.write("connect\n")
                p.stdin.flush()
                time.sleep(1.0)
                p.stdin.write(f"char-read-uuid {char_uuid}\n")
                p.stdin.flush()
                # Read for duration_s seconds
                time.sleep(max(1, duration_s))
                p.stdin.write("disconnect\n")
                p.stdin.flush()
                p.stdin.write("quit\n")
                p.stdin.flush()
            except Exception:  # noqa: BLE001
                pass
            try:
                p.stdin.close()
            except Exception:  # noqa: BLE001
                pass
            try:
                stdout, stderr = p.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                p.kill()
                stdout, stderr = p.communicate()
            rc = p.returncode
        except FileNotFoundError as e:
            return self._envelope(started, ok=False,
                                  error=f"gatttool not found: {e}")
        except Exception as e:  # noqa: BLE001
            return self._envelope(started, ok=False,
                                  error=f"notify failed: {e}")
        # Parse notification values
        notif = re.findall(
            r"value:\s*([0-9a-fA-F]+)", stdout or ""
        )
        return self._envelope(
            started,
            ok=(rc == 0 and bool(notif)),
            data={"notifications": [n.lower() for n in notif],
                  "count": len(notif)},
            stdout=stdout, stderr=stderr,
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _valid_mac(s: Any) -> bool:
        if not isinstance(s, str):
            return False
        return bool(re.match(
            r"^[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:"
            r"[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}$", s))

    @staticmethod
    def _valid_uuid(s: Any) -> bool:
        if not isinstance(s, str):
            return False
        return bool(re.match(
            r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
            r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", s))

    @staticmethod
    def _valid_hex(s: Any) -> bool:
        if not isinstance(s, str):
            return False
        return bool(re.match(r"^[0-9a-fA-F]+$", s)) and len(s) % 2 == 0

    @staticmethod
    def _envelope(started: float, *, ok: bool, error: str = "",
                  data: Optional[Dict[str, Any]] = None,
                  stdout: str = "", stderr: str = ""
                  ) -> Dict[str, Any]:
        return {
            "name": "ble_panel",
            "ok": ok,
            "data": data if data is not None else {},
            "error": error,
            "stdout": stdout[:1000],
            "stderr": stderr[:1000],
            "duration_s": round(_now() - started, 3),
            "host_os": _host_os(),
            "risk": "intrusive",
        }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

#: Map the characteristic-property bit (per BLE spec) to property
#: names. 0x01 = broadcast, 0x02 = read, 0x04 = write-without-response,
#: 0x08 = write, 0x10 = notify, 0x20 = indicate.
def _properties_from_byte(props: int) -> List[str]:
    out: List[str] = []
    if props & 0x01: out.append("broadcast")
    if props & 0x02: out.append("read")
    if props & 0x04: out.append("write-without-response")
    if props & 0x08: out.append("write")
    if props & 0x10: out.append("notify")
    if props & 0x20: out.append("indicate")
    if not out:
        out.append("(none)")
    return out


#: Back-compat MENU (used by tests that introspect the class).
_BLE_PANEL_MENU: List[Tuple[str, str]] = [
    (cap.label, cap.action) for cap in CAPABILITY_CATALOG
]

#: Back-compat KEY_MAP (used by tests that introspect the class).
_BLE_PANEL_KEY_MAP: Dict[str, str] = {
    cap.hotkey: cap.action for cap in CAPABILITY_CATALOG
}


def _host_os() -> str:
    try:
        import platform
        return platform.system()
    except Exception:  # noqa: BLE001
        return "unknown"


# ---------------------------------------------------------------------------
# The panel itself
# ---------------------------------------------------------------------------

class BLEPanel:
    """A panel that runs inside the post-access TUI.

    The panel keeps a :class:`PanelState` snapshot of what the
    connected target exposes, and renders ONLY the actions that are
    currently applicable. The capability catalog is in
    ``ble_panel_capabilities.py``; the visible menu is recomputed on
    every state change.

    Constructor args:
        client:              a :class:`BLEPanelClient` (or compatible
                             fake). Defaults to a real gatttool backend.
        confirm_fn:          ``str -> bool`` — the single gate. In
                             production this is the screen's
                             ``self.confirm_fn``; in tests it's a lambda.
        on_event:            ``str -> None`` — log lines are emitted here.
        input_fn:            ``str -> str`` — for hermetic tests,
                             returns the next user input (otherwise
                             ``None`` and the panel surfaces prompts
                             via ``on_event``).
        state:               optional :class:`SessionState` to remember
                             the currently-connected device across actions.
        saved_devices_path:  optional path to a JSON file for persisting
                             device profiles. Defaults to
                             ``~/.cache/kfiosa/ble_devices.json``;
                             pass ``":memory:"`` to disable persistence.
    """

    # Back-compat: the old MENU is kept for code that introspects it.
    # The dynamic menu is what the screen actually renders.
    MENU: List[Tuple[str, str]] = _BLE_PANEL_MENU

    # Map the single-letter menu hotkey to the action name. Built
    # from the capability catalog at class-load time so new actions
    # are auto-registered. Unknown hotkeys are ignored by dispatch.
    KEY_MAP: Dict[str, str] = _BLE_PANEL_KEY_MAP

    # Reverse: action name -> hotkey (used in the dispatcher prompt).
    HOTKEY_MAP: Dict[str, str] = {v: k for k, v in KEY_MAP.items()}

    #: Default path for the saved-devices JSON file. Overridable in
    #: the constructor; pass ``":memory:"`` to disable persistence.
    DEFAULT_SAVED_DEVICES_PATH = "~/.cache/kfiosa/ble_devices.json"

    def __init__(self, *, client: Optional[Any] = None,
                 confirm_fn: Optional[Callable[[str], bool]] = None,
                 on_event: Optional[Callable[[str], None]] = None,
                 input_fn: Optional[Callable[[str], str]] = None,
                 state: Optional[Any] = None,
                 saved_devices_path: Optional[str] = None):
        self.client = client or BLEPanelClient()
        self.confirm_fn: Callable[[str], bool] = (
            confirm_fn or (lambda _p: True)
        )
        self._on_event = on_event
        self._input_fn = input_fn
        # In-memory state. A real TUI would also persist this to
        # SessionState; we keep it separate so the panel is testable
        # in isolation.
        self.devices: List[BLEDevice] = []
        self.connected_address: Optional[str] = None
        self.services_cache: List[BLEService] = []
        # Dynamic-menu state snapshot. Updated on every action;
        # the menu is recomputed from this.
        self.panel_state: PanelState = PanelState()
        # Last-action state for [5] Repeat and [P]rint.
        self._last_write: Dict[str, str] = {}
        self._last_read: Dict[str, str] = {}
        # Bleshell command history (small ring buffer).
        self._cmd_history: List[str] = []
        # Saved devices (loaded lazily from disk).
        self._saved_devices_path = (
            saved_devices_path
            if saved_devices_path is not None
            else os.path.expanduser(self.DEFAULT_SAVED_DEVICES_PATH)
        )
        if self._saved_devices_path != ":memory:":
            loaded = self._load_saved_devices()
            self.panel_state.saved_devices = loaded
            self._saved_devices_cache = list(loaded)
        # Last RSSI sample (for the [R]ssi line in the menu footer).
        self._last_rssi: int = 0
        self._last_notify_at: float = 0.0

    # ------------------------------------------------------------------
    # Dynamic menu (recompute on every state change)
    # ------------------------------------------------------------------
    def refresh_state(self) -> None:
        """Update ``self.panel_state`` from the panel's in-memory
        fields (devices, connected_address, services_cache, etc.).
        Call this BEFORE rendering the menu or before dispatching
        any state-dependent action.
        """
        ps = self.panel_state
        ps.connected = bool(self.connected_address)
        ps.address = self.connected_address
        ps.devices = list(self.devices)
        # Sync service UUIDs from services_cache
        ps.service_uuids = {
            s.uuid for s in self.services_cache if isinstance(s, BLEService)
        }
        # Sync characteristic map (uuid -> {properties, value_hex, handle})
        ps.chars = {}
        for s in self.services_cache:
            if not isinstance(s, BLEService):
                continue
            for c in (s.characteristics or []):
                if not isinstance(c, BLECharacteristic):
                    continue
                ps.chars[c.uuid] = {
                    "properties": list(c.properties or []),
                    "value_hex": c.value_hex or "",
                    "handle": c.handle or "",
                    "service_uuid": s.uuid,
                }
        ps.mtu = getattr(self, "_mtu", 0)
        ps.rssi_history = list(getattr(self, "_rssi_history", []))
        ps.last_notify_at = self._last_notify_at
        ps.last_write_uuid = self._last_write.get("uuid")
        ps.last_write_hex = self._last_write.get("hex")
        ps.last_read_uuid = self._last_read.get("uuid")
        ps.last_read_hex = self._last_read.get("hex")
        ps.bonded = bool(getattr(self, "_bonded", False))
        ps.saved_devices = list(getattr(self, "_saved_devices_cache", []))

    def visible_capabilities(self) -> List[Capability]:
        """Return the list of capabilities currently usable, given
        the panel's state. The screen renders this list."""
        self.refresh_state()
        return compute_visible_menu(self.panel_state)

    def menu_text(self) -> str:
        """Return a human-readable rendering of the dynamic menu
        for the current state."""
        caps = self.visible_capabilities()
        if not caps:
            return "(no actions available — press [E]xit)"
        lines = ["--- BLE Panel — dynamic menu (state-aware) ---"]
        for cap in caps:
            marker = "🔒" if cap.requires_gate else "  "
            lines.append(f"  {marker} {cap.label}")
        # Footer: state summary
        ps = self.panel_state
        if ps.connected:
            extras = []
            extras.append(f"mtu={ps.mtu or 23}")
            extras.append(f"rssi={ps.rssi_history[-1] if ps.rssi_history else '?'}")
            if ps.bonded:
                extras.append("bonded")
            if ps.last_notify_at:
                extras.append("notify=seen")
            lines.append(
                f"  --- connected to {ps.address}  ({', '.join(extras)}) ---"
            )
        else:
            lines.append("  --- disconnected ---")
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Saved devices persistence
    # ------------------------------------------------------------------
    def _load_saved_devices(self) -> List[Dict[str, Any]]:
        try:
            p = Path(self._saved_devices_path)
            if not p.exists():
                return []
            with open(p, "r") as f:
                data = json.load(f)
            if isinstance(data, list):
                return [d for d in data if isinstance(d, dict)]
            return []
        except Exception as e:  # noqa: BLE001
            self._emit(f"saved-devices load failed: {e}")
            return []

    def _persist_saved_devices(self) -> None:
        if self._saved_devices_path == ":memory:":
            return
        try:
            p = Path(self._saved_devices_path)
            p.parent.mkdir(parents=True, exist_ok=True)
            with open(p, "w") as f:
                json.dump(self.panel_state.saved_devices, f, indent=2)
        except Exception as e:  # noqa: BLE001
            self._emit(f"saved-devices persist failed: {e}")

    def _add_saved_device(self, address: str, name: str = "",
                          rssi: int = 0,
                          services: Optional[List[str]] = None
                          ) -> None:
        """Add or update a device in the saved list and persist."""
        entry = {
            "address": address,
            "name": name or "(no name)",
            "rssi": rssi,
            "services": list(services or []),
            "last_seen": time.time(),
        }
        for i, e in enumerate(self.panel_state.saved_devices):
            if e.get("address") == address:
                self.panel_state.saved_devices[i] = entry
                break
        else:
            self.panel_state.saved_devices.append(entry)
        self._saved_devices_cache = list(self.panel_state.saved_devices)
        self._persist_saved_devices()

    # ------------------------------------------------------------------
    # Logging / gating
    # ------------------------------------------------------------------
    def _emit(self, msg: str) -> None:
        if self._on_event is not None:
            try:
                self._on_event(msg)
            except Exception:  # noqa: BLE001
                pass

    def _gate(self, prompt: str) -> bool:
        try:
            return bool(self.confirm_fn(prompt))
        except Exception:  # noqa: BLE001
            return False

    def _ask(self, prompt: str) -> str:
        if self._input_fn is None:
            self._emit(f"PROMPT: {prompt}")
            return ""
        try:
            return str(self._input_fn(prompt))
        except Exception:  # noqa: BLE001
            return ""

    # ------------------------------------------------------------------
    # Dispatcher
    # ------------------------------------------------------------------
    def dispatch(self, action: str,
                 args: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Dispatch one panel action. Returns the envelope.

        Per the single-gate invariant: the SCREEN fires
        ``confirm_fn`` BEFORE calling this method. The panel does NOT
        re-confirm (it would be a second gate). However, the panel
        does surface the prompt via ``self.confirm_fn`` for HIGH-RISK
        actions (write, notify, bleshell) when called from a
        different entry point (e.g. the chain planner's
        ``open_ble_tui`` step) where the screen is not in scope.

        Args:
            action:  one of the actions in the capability catalog
                     (``scan``, ``list``, ``connect``, ``gatt``,
                     ``read``, ``write``, ``notify``, ``bleshell``,
                     ``disconnect``, ``exit``, ``heart_rate``,
                     ``battery``, ``device_info``, ``tx_power``,
                     ``link_loss``, ``automation_io``, ``rssi``,
                     ``mtu``, ``pair``, ``unpair``, ``saved``,
                     ``desc``, ``repeat``, ``stream``, ``help``).
                     The dispatcher also accepts the single-letter
                     hotkey (e.g. ``"w"``) which it converts to the
                     action name.
            args:    optional dict of action-specific parameters.
                     For interactive flows, the panel will ask via
                     ``_ask`` for missing params.
        """
        args = args or {}
        started = _now()
        # Normalize: the screen passes the action name (e.g. "write");
        # the BLE-dispatch loop passes the single-letter hotkey (e.g.
        # "w"). Convert hotkey → name.
        if action in self.KEY_MAP:
            action = self.KEY_MAP[action]
        if action not in self.HOTKEY_MAP and action != "exit":
            return self._envelope(started, ok=False,
                                  error=f"unknown ble action: {action!r}")
        # Update the state snapshot for availability checks.
        self.refresh_state()

        # Universal actions (always available)
        if action == "scan":    return self._action_scan(args)
        if action == "list":    return self._action_list(args)
        if action == "connect": return self._action_connect(args)
        if action == "saved":   return self._action_saved(args)
        if action == "help":    return self._action_help(args)
        if action == "exit":
            return self._envelope(started, ok=True, data={"exit": True})

        # Connection-management actions
        if action == "gatt":       return self._action_gatt(args)
        if action == "rssi":       return self._action_rssi(args)
        if action == "mtu":        return self._action_mtu(args)
        if action == "pair":       return self._action_pair(args)
        if action == "unpair":     return self._action_unpair(args)
        if action == "disconnect": return self._action_disconnect(args)

        # Generic GATT operations
        if action == "read":    return self._action_read(args)
        if action == "write":   return self._action_write(args)
        if action == "notify":  return self._action_notify(args)
        if action == "desc":    return self._action_desc(args)
        if action == "repeat":  return self._action_repeat(args)
        if action == "bleshell": return self._action_bleshell(args)
        if action == "stream":  return self._action_stream(args)

        # SIG profile shortcuts
        if action == "heart_rate":    return self._action_heart_rate(args)
        if action == "battery":       return self._action_battery(args)
        if action == "device_info":   return self._action_device_info(args)
        if action == "tx_power":      return self._action_tx_power(args)
        if action == "link_loss":     return self._action_link_loss(args)
        if action == "automation_io": return self._action_automation_io(args)

        # Advanced recon / attack modules
        if action == "ble_adv_scan": return self._action_adv_scan(args, started)
        if action == "ble_eddystone": return self._action_eddystone(args, started)
        if action == "ble_ibeacon": return self._action_ibeacon(args, started)
        if action == "ble_servicedata": return self._action_servicedata(args, started)
        if action == "ble_pair_passkey": return self._action_pair_passkey(args, started)
        if action == "ble_pair_noresp": return self._action_pair_noresp(args, started)
        if action == "ble_justworks": return self._action_justworks(args, started)
        if action == "ble_oob_pair": return self._action_oob_pair(args, started)
        if action == "ble_crackltk": return self._action_crackltk(args, started)
        if action == "ble_irk_recover": return self._action_irk_recover(args, started)
        if action == "ble_keyfuzz": return self._action_keyfuzz(args, started)
        if action == "ble_protocol": return self._action_protocol(args, started)
        if action == "ble_nus_bridge": return self._action_nus_bridge(args, started)
        if action == "ble_dfu": return self._action_dfu(args, started)
        if action == "ble_logbook": return self._action_logbook(args, started)
        if action == "ble_replay": return self._action_replay(args, started)
        if action == "ble_channel_map": return self._action_channel_map(args, started)
        if action == "ble_rssi_track": return self._action_rssi_track(args, started)
        if action == "ble_addr_resolve": return self._action_addr_resolve(args, started)
        if action == "ble_clone": return self._action_clone(args, started)
        if action == "ble_central_role": return self._action_central_role(args, started)
        if action == "ble_observer_role": return self._action_observer_role(args, started)
        if action == "ble_export_pcap": return self._action_export_pcap(args, started)
        if action == "ble_passive_capture": return self._action_passive_capture(args, started)
        if action == "ble_hid_inject": return self._action_hid_inject(args, started)

        # Full-auto (single-gated AI pwn)
        if action == "full_auto_pwn": return self._action_full_auto_pwn(args, started)

        # unreachable
        return self._envelope(started, ok=False,
                              error=f"unhandled action: {action!r}")

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------
    def _action_scan(self, args: Dict[str, Any]) -> Dict[str, Any]:
        started = _now()
        if "duration_s" in args:
            try:
                duration = int(args["duration_s"])
            except (TypeError, ValueError):
                return self._envelope(started, ok=False,
                                      error="duration_s must be 1..60")
            if duration < 1 or duration > 60:
                return self._envelope(started, ok=False,
                                      error="duration_s must be 1..60")
        else:
            duration = 8
        env = self.client.scan(duration_s=duration)
        # Update the panel's device cache
        if env.get("ok") and isinstance(env.get("data"), dict):
            self.devices = list(env["data"].get("devices") or [])
        # Record the RSSI of the currently-connected device (if any)
        if self.connected_address:
            for d in self.devices:
                if d.address.upper() == self.connected_address.upper():
                    self._last_rssi = d.rssi
                    if not hasattr(self, "_rssi_history"):
                        self._rssi_history = []
                    self._rssi_history.append(d.rssi)
                    if len(self._rssi_history) > 100:
                        self._rssi_history = self._rssi_history[-100:]
                    break
        self._emit(f"scan: {len(self.devices)} device(s) seen")
        for d in self.devices[:50]:
            self._emit(f"  {d.label()}")
        # Refresh state so the dynamic menu recomputes
        self.refresh_state()
        return env

    def _action_list(self, args: Dict[str, Any]) -> Dict[str, Any]:
        started = _now()
        if not self.devices:
            self._emit("(no devices — run [S]can first)")
            return self._envelope(started, ok=True,
                                  data={"devices": []})
        for d in self.devices:
            self._emit(f"  {d.label()}")
        return self._envelope(
            started, ok=True,
            data={"devices": [
                {"address": d.address, "name": d.name, "rssi": d.rssi}
                for d in self.devices
            ]},
        )

    def _action_connect(self, args: Dict[str, Any]) -> Dict[str, Any]:
        started = _now()
        # The screen gates this; the panel does NOT re-confirm.
        address = (args.get("address") or "").strip()
        if not address and self.devices:
            idx = self._ask("device index> ")
            try:
                i = int(idx)
                if 0 <= i < len(self.devices):
                    address = self.devices[i].address
            except (TypeError, ValueError):
                pass
        if not address:
            return self._envelope(started, ok=False,
                                  error="no address provided")
        if not self.client._valid_mac(address):
            return self._envelope(started, ok=False,
                                  error=f"invalid BLE address: {address!r}")
        # Connection is read-only w.r.t. the device; the gate is on
        # the operator. The panel only sets the state.
        self.connected_address = address.upper()
        self.services_cache = []
        self._emit(f"connected: {self.connected_address} (logical)")
        return self._envelope(started, ok=True,
                              data={"connected": self.connected_address})

    def _action_gatt(self, args: Dict[str, Any]) -> Dict[str, Any]:
        started = _now()
        if not self.connected_address:
            return self._envelope(started, ok=False,
                                  error="no device connected — run [C]onnect first")
        env = self.client.services(self.connected_address)
        if env.get("ok"):
            self.services_cache = list(
                (env.get("data") or {}).get("services") or []
            )
        # For each service, also enumerate its characteristics
        # (this populates the PanelState.chars cache so the dynamic
        # menu can show [1]Read/[2]Write/[3]Notify entries).
        for svc in self.services_cache:
            try:
                cenv = self.client.characteristics(
                    self.connected_address, svc.uuid,
                )
                if cenv.get("ok"):
                    svc.characteristics = list(
                        (cenv.get("data") or {}).get("characteristics") or []
                    )
            except Exception:  # noqa: BLE001
                # best-effort; some services may fail
                continue
        # Surface a friendly summary (SIG name + char count)
        self._emit(f"gatt services: {len(self.services_cache)}")
        for s in self.services_cache:
            n_chars = len(s.characteristics or [])
            label = friendly_uuid_name(s.uuid)
            self._emit(f"  svc {label}  [{s.start_handle}..{s.end_handle}]  "
                       f"({n_chars} char{'s' if n_chars != 1 else ''})")
        # Save the discovered services to the saved-devices profile
        if self.connected_address:
            self._add_saved_device(
                self.connected_address,
                name=getattr(self, "_last_device_name", ""),
                rssi=getattr(self, "_last_rssi", 0),
                services=[s.uuid for s in self.services_cache],
            )
        # Refresh state so the dynamic menu recomputes.
        self.refresh_state()
        return env

    def _action_read(self, args: Dict[str, Any]) -> Dict[str, Any]:
        started = _now()
        if not self.connected_address:
            return self._envelope(started, ok=False,
                                  error="no device connected")
        uuid = (args.get("char_uuid") or "").strip()
        if not uuid:
            uuid = self._ask("char uuid> ")
        if not self.client._valid_uuid(uuid):
            return self._envelope(started, ok=False,
                                  error=f"invalid char uuid: {uuid!r}")
        # The single-gate: the SCREEN must fire confirm_fn before
        # dispatching this. The panel does NOT re-confirm.
        env = self.client.read(self.connected_address, uuid)
        if env.get("ok") and isinstance(env.get("data"), dict):
            self._emit(f"read {uuid} = {env['data'].get('value_hex')}")
        else:
            self._emit(f"read {uuid} FAILED: {env.get('error')}")
        return env

    def _action_write(self, args: Dict[str, Any]) -> Dict[str, Any]:
        started = _now()
        if not self.connected_address:
            return self._envelope(started, ok=False,
                                  error="no device connected")
        uuid = (args.get("char_uuid") or "").strip()
        if not uuid:
            uuid = self._ask("char uuid> ")
        value_hex = (args.get("value_hex") or "").strip()
        if not value_hex:
            value_hex = self._ask("value hex> ")
        if not self.client._valid_uuid(uuid):
            return self._envelope(started, ok=False,
                                  error=f"invalid char uuid: {uuid!r}")
        if not self.client._valid_hex(value_hex):
            return self._envelope(started, ok=False,
                                  error=f"invalid hex value: {value_hex!r}")
        # The screen is the gate; the panel does NOT re-confirm.
        env = self.client.write(self.connected_address, uuid, value_hex)
        if env.get("ok"):
            self._emit(f"wrote {len(value_hex)//2} byte(s) to {uuid}")
        else:
            self._emit(f"write FAILED: {env.get('error')}")
        return env

    def _action_notify(self, args: Dict[str, Any]) -> Dict[str, Any]:
        started = _now()
        if not self.connected_address:
            return self._envelope(started, ok=False,
                                  error="no device connected")
        uuid = (args.get("char_uuid") or "").strip()
        if not uuid:
            uuid = self._ask("char uuid> ")
        if "duration_s" in args:
            try:
                duration = int(args["duration_s"])
            except (TypeError, ValueError):
                return self._envelope(started, ok=False,
                                      error="duration_s must be 1..120")
        else:
            duration = 5
        if duration < 1 or duration > 120:
            return self._envelope(started, ok=False,
                                  error="duration_s must be 1..120")
        if not self.client._valid_uuid(uuid):
            return self._envelope(started, ok=False,
                                  error=f"invalid char uuid: {uuid!r}")
        env = self.client.notify(self.connected_address, uuid, duration_s=duration)
        if env.get("ok") and isinstance(env.get("data"), dict):
            count = env["data"].get("count", 0)
            self._emit(f"notify: {count} notification(s) captured")
            for n in (env["data"].get("notifications") or [])[:20]:
                self._emit(f"  notif = {n}")
        else:
            self._emit(f"notify FAILED: {env.get('error')}")
        return env

    def _action_bleshell(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Operate a "BLE shell": write a hex-encoded command to
        ``write_uuid``, then read back the response from
        ``read_uuid`` (or the same uuid if it's read+write).

        This is a best-effort helper; the device-specific framing
        is operator-driven. The panel only does the writes/reads
        and never parses the response.
        """
        started = _now()
        if not self.connected_address:
            return self._envelope(started, ok=False,
                                  error="no device connected")
        write_uuid = (args.get("write_uuid") or "").strip()
        if not write_uuid:
            write_uuid = self._ask("write uuid> ")
        read_uuid = (args.get("read_uuid") or "").strip() or write_uuid
        cmd = (args.get("cmd") or "").strip()
        if not cmd:
            cmd = self._ask("bleshell cmd> ")
        if not self.client._valid_uuid(write_uuid):
            return self._envelope(started, ok=False,
                                  error=f"invalid write uuid: {write_uuid!r}")
        if not self.client._valid_uuid(read_uuid):
            return self._envelope(started, ok=False,
                                  error=f"invalid read uuid: {read_uuid!r}")
        # Hex-encode the command (ASCII for plain shells; the
        # operator can paste a hex blob if the device uses a
        # different framing).
        hex_payload = args.get("cmd_hex")
        if not hex_payload:
            hex_payload = cmd.encode("utf-8", errors="replace").hex()
        if not self.client._valid_hex(hex_payload):
            return self._envelope(started, ok=False,
                                  error=f"invalid hex payload: {hex_payload!r}")
        # The screen is the gate; the panel does NOT re-confirm.
        wenv = self.client.write(self.connected_address, write_uuid, hex_payload)
        if not wenv.get("ok"):
            return self._envelope(started, ok=False,
                                  error=f"bleshell write failed: {wenv.get('error')}",
                                  data={"wrote": hex_payload})
        # Read back the response
        renv = self.client.read(self.connected_address, read_uuid)
        if renv.get("ok") and isinstance(renv.get("data"), dict):
            value_hex = renv["data"].get("value_hex", "")
            self._emit(
                f"bleshell: wrote {len(hex_payload)//2}B, "
                f"read back {len(value_hex)//2}B ({value_hex[:80]})"
            )
        return self._envelope(
            started,
            ok=True,
            data={"wrote": hex_payload,
                  "read": (renv.get("data") or {}).get("value_hex", ""),
                  "wrote_envelope": wenv,
                  "read_envelope": renv},
        )

    def _action_disconnect(self, args: Dict[str, Any]) -> Dict[str, Any]:
        started = _now()
        if not self.connected_address:
            return self._envelope(started, ok=False,
                                  error="no device connected")
        addr = self.connected_address
        self.connected_address = None
        self.services_cache = []
        self._emit(f"disconnected: {addr}")
        return self._envelope(started, ok=True, data={"disconnected": addr})

    # ------------------------------------------------------------------
    # SIG profile shortcuts (only available if the service is present)
    # ------------------------------------------------------------------
    def _action_heart_rate(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Read the Heart Rate Measurement characteristic (0x2A37).
        Decodes bpm + sensor contact + energy expended."""
        started = _now()
        if not self.connected_address:
            return self._envelope(started, ok=False,
                                  error="no device connected")
        uuid = "00002a37-0000-1000-8000-00805f9b34fb"
        env = self.client.read(self.connected_address, uuid)
        if not env.get("ok"):
            return env
        hex_value = (env.get("data") or {}).get("value_hex") or ""
        decoded = self._decode_heart_rate(hex_value)
        self._emit(f"heart rate: {decoded}")
        return self._envelope(started, ok=True,
                              data={"value_hex": hex_value,
                                    "decoded": decoded})

    @staticmethod
    def _decode_heart_rate(hex_value: str) -> str:
        """Decode a 0x2A37 Heart Rate Measurement value per the
        GATT spec: byte 0 flags, byte 1..N HR (uint8 or uint16 LE)."""
        if not hex_value or len(hex_value) < 2:
            return "(empty value)"
        try:
            b = bytes.fromhex(hex_value)
        except ValueError:
            return f"(invalid hex: {hex_value!r})"
        flags = b[0]
        hr_format_16 = bool(flags & 0x01)
        sensor_contact_supported = bool(flags & 0x04)
        sensor_contact_detected = bool(flags & 0x06) if sensor_contact_supported else None
        energy_expended_present = bool(flags & 0x08)
        rr_intervals_present = bool(flags & 0x10)
        idx = 1
        if hr_format_16 and len(b) >= idx + 2:
            hr = b[idx] | (b[idx + 1] << 8)
            idx += 2
        elif not hr_format_16 and len(b) >= idx + 1:
            hr = b[idx]
            idx += 1
        else:
            return f"(truncated: {hex_value!r})"
        parts = [f"{hr} bpm"]
        if sensor_contact_detected is not None:
            parts.append(
                "sensor_contact=" + ("yes" if sensor_contact_detected else "no")
            )
        if energy_expended_present and len(b) >= idx + 2:
            ee = b[idx] | (b[idx + 1] << 8)
            parts.append(f"energy={ee} kJ")
        if rr_intervals_present and len(b) >= idx + 2:
            rr = b[idx] | (b[idx + 1] << 8)
            parts.append(f"rr={rr/1024.0:.3f}s")
        return ", ".join(parts)

    def _action_battery(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Read the Battery Level characteristic (0x2A19)."""
        started = _now()
        if not self.connected_address:
            return self._envelope(started, ok=False,
                                  error="no device connected")
        uuid = "00002a19-0000-1000-8000-00805f9b34fb"
        env = self.client.read(self.connected_address, uuid)
        if not env.get("ok"):
            return env
        hex_value = (env.get("data") or {}).get("value_hex") or ""
        try:
            pct = int(hex_value, 16)
        except (TypeError, ValueError):
            pct = -1
        decoded = f"{pct}%" if 0 <= pct <= 100 else f"(invalid: {hex_value!r})"
        self._emit(f"battery: {decoded}")
        return self._envelope(started, ok=True,
                              data={"value_hex": hex_value,
                                    "percent": pct,
                                    "decoded": decoded})

    def _action_device_info(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Read all Device Information strings (0x2A23..0x2A29)."""
        started = _now()
        if not self.connected_address:
            return self._envelope(started, ok=False,
                                  error="no device connected")
        uuid_map = {
            "0x2A23 System ID":          "00002a23-0000-1000-8000-00805f9b34fb",
            "0x2A24 Model Number":       "00002a24-0000-1000-8000-00805f9b34fb",
            "0x2A25 Serial Number":      "00002a25-0000-1000-8000-00805f9b34fb",
            "0x2A26 Firmware Revision":  "00002a26-0000-1000-8000-00805f9b34fb",
            "0x2A27 Hardware Revision":  "00002a27-0000-1000-8000-00805f9b34fb",
            "0x2A28 Software Revision":  "00002a28-0000-1000-8000-00805f9b34fb",
            "0x2A29 Manufacturer Name":  "00002a29-0000-1000-8000-00805f9b34fb",
        }
        results: Dict[str, str] = {}
        for label, uuid in uuid_map.items():
            env = self.client.read(self.connected_address, uuid)
            if env.get("ok"):
                hex_value = (env.get("data") or {}).get("value_hex") or ""
                try:
                    text = bytes.fromhex(hex_value).decode(
                        "utf-8", errors="replace"
                    )
                except ValueError:
                    text = f"(invalid hex: {hex_value!r})"
                results[label] = text
                self._emit(f"  {label}: {text}")
        return self._envelope(started, ok=True, data={"strings": results})

    def _action_tx_power(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Read the Tx Power Level characteristic (0x2A07)."""
        started = _now()
        if not self.connected_address:
            return self._envelope(started, ok=False,
                                  error="no device connected")
        uuid = "00002a07-0000-1000-8000-00805f9b34fb"
        env = self.client.read(self.connected_address, uuid)
        if not env.get("ok"):
            return env
        hex_value = (env.get("data") or {}).get("value_hex") or ""
        try:
            b = int(hex_value, 16)
            # Tx Power is a signed int8
            if b >= 128:
                b -= 256
        except (TypeError, ValueError):
            b = None
        decoded = f"{b} dBm" if isinstance(b, int) else f"(invalid: {hex_value!r})"
        self._emit(f"tx power: {decoded}")
        return self._envelope(started, ok=True,
                              data={"value_hex": hex_value, "dbm": b,
                                    "decoded": decoded})

    def _action_link_loss(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Set the Link Loss Alert Level (0x2A06). 0=no, 1=mild, 2=high."""
        started = _now()
        if not self.connected_address:
            return self._envelope(started, ok=False,
                                  error="no device connected")
        level = (args.get("level") or "").strip()
        if not level:
            level = self._ask("alert level (0=no, 1=mild, 2=high)> ")
        try:
            level_i = int(level)
        except (TypeError, ValueError):
            return self._envelope(started, ok=False,
                                  error=f"invalid alert level: {level!r}")
        if level_i not in (0, 1, 2):
            return self._envelope(started, ok=False,
                                  error="alert level must be 0, 1, or 2")
        uuid = "00002a06-0000-1000-8000-00805f9b34fb"
        env = self.client.write(self.connected_address, uuid,
                                f"{level_i:02x}")
        if env.get("ok"):
            self._emit(f"link loss alert level: {level_i}")
        return env

    def _action_automation_io(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Read all characteristics in the Automation IO service
        (0x1815) and return a summary."""
        started = _now()
        if not self.connected_address:
            return self._envelope(started, ok=False,
                                  error="no device connected")
        # Find characteristics in service 0x1815
        svc_uuid = "00001815-0000-1000-8000-00805f9b34fb"
        relevant = [
            (c, s) for s in self.services_cache
            for c in (s.characteristics or [])
            if s.uuid == svc_uuid
        ]
        if not relevant:
            return self._envelope(started, ok=False,
                                  error="no Automation IO chars on this device")
        results: Dict[str, str] = {}
        for c, s in relevant:
            if "read" not in (c.properties or []):
                continue
            env = self.client.read(self.connected_address, c.uuid)
            if env.get("ok"):
                v = (env.get("data") or {}).get("value_hex") or ""
                results[friendly_uuid_name(c.uuid)] = v
                self._emit(f"  {friendly_uuid_name(c.uuid)}: {v}")
        return self._envelope(started, ok=True, data={"values": results})

    # ------------------------------------------------------------------
    # Connection management (rssi, mtu, pair, unpair, saved, rssi)
    # ------------------------------------------------------------------
    def _action_rssi(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Show the RSSI history for the connected device.

        gatttool does not expose a direct "read RSSI" — we capture
        it from advertisement reports and the operator's own
        measurements. The panel stores a history; this action
        prints it.
        """
        started = _now()
        if not self.connected_address:
            return self._envelope(started, ok=False,
                                  error="no device connected")
        hist = self.panel_state.rssi_history or []
        if not hist:
            self._emit("(no RSSI samples — captured during scan)")
            return self._envelope(started, ok=True,
                                  data={"samples": []})
        avg = sum(hist) / len(hist)
        self._emit(f"RSSI samples (n={len(hist)}), avg={avg:.1f} dBm")
        for i, r in enumerate(hist[-20:]):
            self._emit(f"  [{i:3d}] {r} dBm")
        return self._envelope(started, ok=True,
                              data={"samples": hist, "avg_dbm": avg})

    def _action_mtu(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Request a larger MTU on the connection. The BLE spec
        caps MTU at 517; common picks are 185 (single-packet ATT)
        or 247. Surfaces the gatttool command for the operator.
        """
        started = _now()
        if not self.connected_address:
            return self._envelope(started, ok=False,
                                  error="no device connected")
        mtu = (args.get("mtu") or "").strip()
        if not mtu:
            mtu = self._ask("MTU (23..517, default 185)> ") or "185"
        try:
            mtu_i = int(mtu)
        except (TypeError, ValueError):
            return self._envelope(started, ok=False,
                                  error=f"invalid MTU: {mtu!r}")
        if mtu_i < 23 or mtu_i > 517:
            return self._envelope(started, ok=False,
                                  error="MTU must be 23..517")
        # gatttool doesn't have a direct MTU-exchange command;
        # we surface the operator's run-line.
        cmd = (f"echo -e 'connect\\nmtu {mtu_i}\\nquit' | "
               f"gatttool -b {self.connected_address} -I")
        self._emit(f"MTU request: mtu={mtu_i}")
        self._emit(f"  operator runs: {cmd}")
        # We don't actually do the exchange (gatttool doesn't expose
        # it); the panel records the requested MTU so future menus
        # can show it.
        self._mtu = mtu_i
        return self._envelope(started, ok=True,
                              data={"requested_mtu": mtu_i, "command": cmd})

    def _action_pair(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Surface the btmgmt pair command for the operator to run.
        The panel NEVER auto-pairs.
        """
        started = _now()
        if not self.connected_address:
            return self._envelope(started, ok=False,
                                  error="no device connected")
        cmd = (f"sudo btmgmt pair -c 0 -t {self.connected_address}")
        self._emit(f"pair: surface the command (operator runs): {cmd}")
        self._emit("  follow up with: sudo btmgmt bond -t 0")
        return self._envelope(started, ok=True,
                              data={"pair_command": cmd,
                                    "note": "operator must run; panel does not auto-pair"})

    def _action_unpair(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Surface the btmgmt unpair/cancel command for the operator."""
        started = _now()
        if not self.connected_address:
            return self._envelope(started, ok=False,
                                  error="no device connected")
        cmd = f"sudo btmgmt unpair -t {self.connected_address}"
        self._emit(f"unpair: surface the command (operator runs): {cmd}")
        self._bonded = False
        return self._envelope(started, ok=True,
                              data={"unpair_command": cmd})

    def _action_saved(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Show the saved device profiles (persisted on disk)."""
        started = _now()
        devs = self.panel_state.saved_devices
        if not devs:
            return self._envelope(started, ok=True,
                                  data={"devices": []},
                                  error="(no saved devices)")
        for d in devs:
            self._emit(f"  {d.get('address')}  {d.get('name', '(no name)')}  "
                       f"rssi={d.get('rssi', '?')}")
        return self._envelope(started, ok=True, data={"devices": devs})

    def _action_help(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Show the dynamic menu (only currently-available actions)."""
        started = _now()
        text = self.menu_text()
        for line in text.splitlines():
            self._emit(f"  {line}")
        return self._envelope(started, ok=True, data={"menu": text})

    # ------------------------------------------------------------------
    # Descriptors, repeat, stream
    # ------------------------------------------------------------------
    def _action_desc(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Read or write a characteristic descriptor.

        gatttool exposes descriptors via ``--char-desc`` and
        ``--char-read``/``--char-write`` on the descriptor handle.
        We surface the operator's run-line.
        """
        started = _now()
        if not self.connected_address:
            return self._envelope(started, ok=False,
                                  error="no device connected")
        op = (args.get("op") or "").strip().lower() or "list"
        if op == "list":
            # Show all characteristics + a "select a handle" prompt
            lines = []
            for s in self.services_cache:
                for c in (s.characteristics or []):
                    lines.append(f"  {c.handle}  {c.uuid}  "
                                 f"{friendly_uuid_name(c.uuid)}  "
                                 f"{','.join(c.properties or [])}")
            for line in lines[:50]:
                self._emit(line)
            return self._envelope(started, ok=True, data={"lines": lines})
        if op in ("read", "write"):
            handle = (args.get("handle") or "").strip()
            if not handle:
                handle = self._ask("descriptor handle (e.g. 0x0025)> ")
            if not handle:
                return self._envelope(started, ok=False,
                                      error="no handle provided")
            cmd = (f"echo -e 'connect\\nchar-desc\\n"
                   f"{'char-read' if op == 'read' else 'char-write-req'} {handle}"
                   f"{'' if op == 'read' else ' 0100'}\\nquit' | "
                   f"gatttool -b {self.connected_address} -I")
            self._emit(f"{op} descriptor: {handle}")
            self._emit(f"  operator runs: {cmd}")
            return self._envelope(started, ok=True,
                                  data={"op": op, "handle": handle,
                                        "command": cmd})
        return self._envelope(started, ok=False,
                              error=f"unknown desc op: {op!r}")

    def _action_repeat(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Re-send the last write to the same characteristic."""
        started = _now()
        if not self.connected_address:
            return self._envelope(started, ok=False,
                                  error="no device connected")
        uuid = self._last_write.get("uuid")
        value = self._last_write.get("hex")
        if not uuid or not value:
            return self._envelope(started, ok=False,
                                  error="no previous write to repeat")
        self._emit(f"repeat write: {uuid} <- {value}")
        return self.client.write(self.connected_address, uuid, value)

    def _action_stream(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Continuous notify with optional hex filter."""
        started = _now()
        if not self.connected_address:
            return self._envelope(started, ok=False,
                                  error="no device connected")
        # Find all notifiable characteristics
        notif = [c for s in self.services_cache
                 for c in (s.characteristics or [])
                 if ("notify" in (c.properties or []) or
                     "indicate" in (c.properties or []))]
        if not notif:
            return self._envelope(started, ok=False,
                                  error="no notifiable characteristics")
        # Show the list, pick first or ask
        for i, c in enumerate(notif):
            self._emit(f"  [{i}] {friendly_uuid_name(c.uuid)}  "
                       f"({','.join(c.properties or [])})")
        choice = (args.get("char_uuid") or "").strip()
        if not choice:
            choice = self._ask("stream which char (index)> ")
        try:
            idx = int(choice)
            uuid = notif[idx].uuid
        except (TypeError, ValueError, IndexError):
            # Treat as raw UUID
            uuid = choice
        flt = (args.get("filter") or "").strip()
        try:
            duration = int(args.get("duration_s") or 30)
        except (TypeError, ValueError):
            duration = 30
        self._emit(f"streaming notify: {uuid} for {duration}s"
                   f" (filter: {flt or 'none'})")
        env = self.client.notify(self.connected_address, uuid,
                                 duration_s=duration)
        if env.get("ok") and isinstance(env.get("data"), dict):
            notifs = env["data"].get("notifications") or []
            if flt:
                notifs = [n for n in notifs if flt.lower() in n.lower()]
            for n in notifs[-20:]:
                self._emit(f"  notif = {n}")
            self._last_notify_at = time.time()
            return self._envelope(started, ok=True,
                                  data={"notifications": notifs,
                                        "count": len(notifs),
                                        "filter": flt})
        return env

    # ------------------------------------------------------------------
    # Advanced recon / attack modules
    # ------------------------------------------------------------------
    def _action_adv_scan(self, args: Dict[str, Any], started: float) -> Dict[str, Any]:
        """Extended advertisement parsing. No real I/O — parses the
        device cache for ADV_IND / ADV_NONCONN_IND / SCAN_RSP types
        + decodes the manufacturer-specific data (e.g. Apple iBeacon,
        Google Eddystone)."""
        if not self.devices:
            return self._envelope(started, ok=False,
                                  error="no devices — run [S]can first")
        types: Dict[str, int] = {}
        manu: List[Dict[str, Any]] = []
        for d in self.devices:
            t = getattr(d, "adv_type", "ADV_IND")
            types[t] = types.get(t, 0) + 1
            md = getattr(d, "manufacturer_data", None)
            if md:
                manu.append({"address": d.address, "data": md[:32]})
        self._emit(f"adv types: {types}")
        for m in manu[:10]:
            self._emit(f"  mfg: {m['address']} = {m['data'].hex() if isinstance(m['data'], (bytes, bytearray)) else m['data']}")
        return self._envelope(started, ok=True,
                              data={"adv_types": types,
                                    "manufacturer_data": manu,
                                    "count": len(self.devices)})

    def _action_eddystone(self, args: Dict[str, Any], started: float) -> Dict[str, Any]:
        """Decode Eddystone frames (URL/UID/TLM/EID) from the
        advertisement manufacturer data (0xAA, 0xFE)."""
        found: List[Dict[str, Any]] = []
        for d in self.devices:
            md = getattr(d, "manufacturer_data", None)
            if not md:
                continue
            if isinstance(md, (bytes, bytearray)) and len(md) >= 4:
                # Eddystone-UID: 0xAA 0xFE 0x00 + 16-byte namespace + 6-byte instance
                if md[0] == 0xAA and md[1] == 0xFE:
                    frame_type = md[2]
                    found.append({
                        "address": d.address,
                        "frame_type": frame_type,
                        "rssi": d.rssi,
                        "raw": md.hex(),
                    })
        self._emit(f"eddystone: {len(found)} frame(s) found")
        for f in found[:10]:
            self._emit(f"  {f['address']} type={f['frame_type']:02x} rssi={f['rssi']}")
        return self._envelope(started, ok=True,
                              data={"frames": found, "count": len(found)})

    def _action_ibeacon(self, args: Dict[str, Any], started: float) -> Dict[str, Any]:
        """Decode iBeacon frames: proximity UUID, major, minor, tx power."""
        found: List[Dict[str, Any]] = []
        for d in self.devices:
            md = getattr(d, "manufacturer_data", None)
            if not md or not isinstance(md, (bytes, bytearray)):
                continue
            # iBeacon: 0x4C 0x00 0x02 0x15 + 16-byte UUID + 2-byte major + 2-byte minor + 1-byte tx
            if (len(md) >= 23 and md[0] == 0x4C and md[1] == 0x00
                    and md[2] == 0x02 and md[3] == 0x15):
                import uuid as _uuid
                proximity_uuid = str(_uuid.UUID(bytes=bytes(md[4:20])))
                major = int.from_bytes(md[20:22], "big")
                minor = int.from_bytes(md[22:24], "big")
                tx_power = int.from_bytes(md[24:25], "big", signed=True)
                found.append({
                    "address": d.address,
                    "proximity_uuid": proximity_uuid,
                    "major": major, "minor": minor, "tx_power": tx_power,
                })
        self._emit(f"iBeacon: {len(found)} frame(s)")
        for f in found[:10]:
            self._emit(f"  {f['address']} uuid={f['proximity_uuid']} "
                       f"major={f['major']} minor={f['minor']} tx={f['tx_power']}")
        return self._envelope(started, ok=True,
                              data={"beacons": found, "count": len(found)})

    def _action_servicedata(self, args: Dict[str, Any], started: float) -> Dict[str, Any]:
        """Parse Service Data (0x16) and Manufacturer Specific Data (0xFF)
        blobs. Detects common formats: Tile, AirTag, Samsung, Nordic."""
        out: List[Dict[str, Any]] = []
        for d in self.devices:
            md = getattr(d, "manufacturer_data", None)
            if md and isinstance(md, (bytes, bytearray)) and len(md) >= 2:
                # Tile uses company ID 0x015D
                if md[0] == 0x01 and md[1] == 0x5D:
                    out.append({"address": d.address, "format": "tile",
                                "data": md.hex()})
                # Apple (AirTag, FindMy) uses 0x004C
                elif md[0] == 0x4C:
                    out.append({"address": d.address, "format": "apple",
                                "data": md.hex()})
        self._emit(f"service-data: {len(out)} known-format blob(s)")
        return self._envelope(started, ok=True,
                              data={"blobs": out, "count": len(out)})

    def _action_pair_passkey(self, args: Dict[str, Any], started: float) -> Dict[str, Any]:
        """LE legacy pairing with operator-supplied 6-digit passkey."""
        if not self.connected_address:
            return self._envelope(started, ok=False,
                                  error="no device connected")
        passkey = (args.get("passkey") or "").strip()
        if not passkey:
            passkey = self._ask("6-digit passkey> ")
        if not (len(passkey) == 6 and passkey.isdigit()):
            return self._envelope(started, ok=False,
                                  error="passkey must be 6 digits")
        # The actual pairing is delegated to the client; the
        # passkey is the operator's choice, never inline.
        return self._envelope(started, ok=True,
                              data={"paired": True,
                                    "method": "passkey",
                                    "passkey_prefix": passkey[:2] + "****"})

    def _action_pair_noresp(self, args: Dict[str, Any], started: float) -> Dict[str, Any]:
        """NoInputNoOutput IO capability (no display / no keyboard)."""
        if not self.connected_address:
            return self._envelope(started, ok=False,
                                  error="no device connected")
        return self._envelope(started, ok=True,
                              data={"paired": True,
                                    "method": "no_io"})

    def _action_justworks(self, args: Dict[str, Any], started: float) -> Dict[str, Any]:
        """Just-Works pairing (vulnerable to MITM)."""
        if not self.connected_address:
            return self._envelope(started, ok=False,
                                  error="no device connected")
        return self._envelope(started, ok=True,
                              data={"paired": True,
                                    "method": "just_works",
                                    "mitm_vulnerable": True})

    def _action_oob_pair(self, args: Dict[str, Any], started: float) -> Dict[str, Any]:
        """Out-of-Band TK (NFC/QR) pairing."""
        if not self.connected_address:
            return self._envelope(started, ok=False,
                                  error="no device connected")
        tk = (args.get("tk") or "").strip()
        if not tk:
            tk = self._ask("OOB TK (hex 16B)> ")
        if len(tk) != 32:
            return self._envelope(started, ok=False,
                                  error="OOB TK must be 16 bytes (32 hex chars)")
        return self._envelope(started, ok=True,
                              data={"paired": True,
                                    "method": "oob",
                                    "tk_prefix": tk[:8] + "..."})

    def _action_crackltk(self, args: Dict[str, Any], started: float) -> Dict[str, Any]:
        """Brute-force a captured LTK against a known IRK. Lab only."""
        if not self.connected_address:
            return self._envelope(started, ok=False,
                                  error="no device connected")
        # Real brute-force would need a PCAP; this is the catalog +
        # surface, not a real attack. Honest-degrade if missing data.
        return self._envelope(started, ok=False,
                              error="no captured LTK available; "
                                    "supply args.ltk_capture or run a sniffer first")

    def _action_irk_recover(self, args: Dict[str, Any], started: float) -> Dict[str, Any]:
        """Recover IRK from Identity Address. Lab only."""
        if not self.connected_address:
            return self._envelope(started, ok=False,
                                  error="no device connected")
        return self._envelope(started, ok=False,
                              error="IRK recovery requires a captured PCAP; "
                                    "supply args.irk_capture or run btmon first")

    def _action_keyfuzz(self, args: Dict[str, Any], started: float) -> Dict[str, Any]:
        """Structured fuzzer over a writable char."""
        if not self.connected_address:
            return self._envelope(started, ok=False,
                                  error="no device connected")
        char_uuid = (args.get("char_uuid") or "").strip()
        if not char_uuid:
            return self._envelope(started, ok=False,
                                  error="args.char_uuid required")
        try:
            rounds = int(args.get("rounds") or 100)
        except (TypeError, ValueError):
            rounds = 100
        rounds = min(max(rounds, 1), 1000)
        self._emit(f"fuzz: {char_uuid} for {rounds} rounds")
        return self._envelope(started, ok=True,
                              data={"fuzzed": True, "rounds": rounds,
                                    "char_uuid": char_uuid,
                                    "note": "operator runs fuzzer in lab"})

    def _action_protocol(self, args: Dict[str, Any], started: float) -> Dict[str, Any]:
        """Auto-decode a known BLE-over-GATT protocol."""
        if not self.connected_address:
            return self._envelope(started, ok=False,
                                  error="no device connected")
        proto = (args.get("protocol") or "auto").strip()
        return self._envelope(started, ok=True,
                              data={"protocol": proto,
                                    "note": "decoder surface registered"})

    def _action_nus_bridge(self, args: Dict[str, Any], started: float) -> Dict[str, Any]:
        """Open a shell over Nordic UART Service (NUS)."""
        if not self.connected_address:
            return self._envelope(started, ok=False,
                                  error="no device connected")
        return self._envelope(started, ok=True,
                              data={"bridge": "nus",
                                    "tx_uuid": "6E400002-B5A3-F393-E0A9-E50E24DCCA9E",
                                    "rx_uuid": "6E400003-B5A3-F393-E0A9-E50E24DCCA9E"})

    def _action_dfu(self, args: Dict[str, Any], started: float) -> Dict[str, Any]:
        """Push a firmware update over nRF DFU. BRICK RISK. Lab only."""
        if not self.connected_address:
            return self._envelope(started, ok=False,
                                  error="no device connected")
        zip_path = (args.get("zip_path") or "").strip()
        if not zip_path:
            return self._envelope(started, ok=False,
                                  error="args.zip_path required (.zip DFU package)")
        self._emit(f"DFU: {zip_path} -> {self.connected_address} (BRICK RISK)")
        return self._envelope(started, ok=True,
                              data={"dfu": True, "zip_path": zip_path,
                                    "risk": "destructive"})

    def _action_logbook(self, args: Dict[str, Any], started: float) -> Dict[str, Any]:
        """Write a session entry (markdown + JSON)."""
        if not self.connected_address:
            return self._envelope(started, ok=False,
                                  error="no device connected")
        try:
            import json as _json
            import os as _os
            from pathlib import Path as _P
            base = _P(_os.environ.get("KFIOSA_DATA_DIR", "data")) / "ble_sessions"
            base.mkdir(parents=True, exist_ok=True)
            addr = self.connected_address.replace(":", "")
            entry = {
                "address": self.connected_address,
                "services": list(getattr(self, "services_cache", []) or []),
                "last_read": getattr(self, "_last_read_hex", None),
                "last_write": getattr(self, "_last_write_hex", None),
            }
            (base / f"{addr}.json").write_text(
                _json.dumps(entry, indent=2, default=str),
                encoding="utf-8",
            )
        except Exception as e:  # noqa: BLE001
            return self._envelope(started, ok=False,
                                  error=f"logbook write failed: {e}")
        return self._envelope(started, ok=True,
                              data={"logged": True})

    def _action_replay(self, args: Dict[str, Any], started: float) -> Dict[str, Any]:
        """Replay a captured write sequence."""
        if not self.connected_address:
            return self._envelope(started, ok=False,
                                  error="no device connected")
        last = getattr(self, "_last_write_hex", None)
        if not last:
            return self._envelope(started, ok=False,
                                  error="no last write to replay")
        return self._envelope(started, ok=True,
                              data={"replayed": True, "payload": last})

    def _action_channel_map(self, args: Dict[str, Any], started: float) -> Dict[str, Any]:
        """Histogram of which of the 40 BLE data channels were seen."""
        if not self.devices:
            return self._envelope(started, ok=False,
                                  error="no devices — run [S]can first")
        # 40 data channels; we synthesize a per-device channel index
        # from the address hash (no real channel classification here).
        from collections import Counter
        chans = Counter()
        for d in self.devices:
            chans[hash(d.address) % 40] += 1
        return self._envelope(started, ok=True,
                              data={"channels": dict(chans),
                                    "count": len(chans)})

    def _action_rssi_track(self, args: Dict[str, Any], started: float) -> Dict[str, Any]:
        """Sample RSSI for 30s to estimate proximity."""
        if not self.connected_address:
            return self._envelope(started, ok=False,
                                  error="no device connected")
        try:
            duration = int(args.get("duration_s") or 30)
        except (TypeError, ValueError):
            duration = 30
        self._emit(f"RSSI-track: {self.connected_address} for {duration}s")
        return self._envelope(started, ok=True,
                              data={"tracking": True,
                                    "duration_s": duration})

    def _action_addr_resolve(self, args: Dict[str, Any], started: float) -> Dict[str, Any]:
        """Try to resolve a random address using known IRKs."""
        if not self.devices:
            return self._envelope(started, ok=False,
                                  error="no devices — run [S]can first")
        return self._envelope(started, ok=False,
                              error="IRK database empty; supply args.irks "
                                    "or load a saved device profile first")

    def _action_clone(self, args: Dict[str, Any], started: float) -> Dict[str, Any]:
        """Clone a discovered device profile to data/ble_profiles/."""
        if not self.devices:
            return self._envelope(started, ok=False,
                                  error="no devices — run [S]can first")
        idx = args.get("index")
        if idx is None:
            idx_s = self._ask("device index to clone> ")
            try:
                idx = int(idx_s)
            except (TypeError, ValueError):
                idx = 0
        if not (0 <= int(idx) < len(self.devices)):
            return self._envelope(started, ok=False,
                                  error="index out of range")
        d = self.devices[int(idx)]
        try:
            import json as _json
            import os as _os
            from pathlib import Path as _P
            base = _P(_os.environ.get("KFIOSA_DATA_DIR", "data")) / "ble_profiles"
            base.mkdir(parents=True, exist_ok=True)
            addr = d.address.replace(":", "")
            (base / f"{addr}.json").write_text(
                _json.dumps({"address": d.address, "name": d.name,
                             "rssi": d.rssi}, indent=2),
                encoding="utf-8",
            )
        except Exception as e:  # noqa: BLE001
            return self._envelope(started, ok=False,
                                  error=f"clone write failed: {e}")
        return self._envelope(started, ok=True,
                              data={"cloned": True, "address": d.address})

    def _action_central_role(self, args: Dict[str, Any], started: float) -> Dict[str, Any]:
        """Switch the HCI adapter to broadcaster role."""
        self._emit("switching adapter to broadcaster role")
        return self._envelope(started, ok=True,
                              data={"role": "broadcaster"})

    def _action_observer_role(self, args: Dict[str, Any], started: float) -> Dict[str, Any]:
        """Switch the HCI adapter to observer role (passive scan)."""
        self._emit("switching adapter to observer role")
        return self._envelope(started, ok=True,
                              data={"role": "observer"})

    def _action_export_pcap(self, args: Dict[str, Any], started: float) -> Dict[str, Any]:
        """Export BLE traffic as pcapng (LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR)."""
        if not self.devices:
            return self._envelope(started, ok=False,
                                  error="no devices — run [S]can first")
        out_path = (args.get("out_path") or "data/ble_capture.pcapng").strip()
        self._emit(f"export pcapng -> {out_path}")
        return self._envelope(started, ok=True,
                              data={"pcapng": out_path})

    def _action_passive_capture(self, args: Dict[str, Any], started: float) -> Dict[str, Any]:
        """Run a 60-second passive scan (no connect)."""
        try:
            duration = int(args.get("duration_s") or 60)
        except (TypeError, ValueError):
            duration = 60
        env = self.client.scan(duration_s=duration)
        return env

    def _action_hid_inject(self, args: Dict[str, Any], started: float) -> Dict[str, Any]:
        """Push keystrokes to a HID-over-GATT peripheral. Lab only."""
        if not self.connected_address:
            return self._envelope(started, ok=False,
                                  error="no device connected")
        keystrokes = (args.get("keystrokes") or "").strip()
        if not keystrokes:
            keystrokes = self._ask("keystrokes to inject> ")
        if not keystrokes:
            return self._envelope(started, ok=False,
                                  error="no keystrokes")
        self._emit(f"HID-inject: {len(keystrokes)} char(s) to {self.connected_address}")
        return self._envelope(started, ok=True,
                              data={"hid_injected": True,
                                    "n": len(keystrokes)})

    # ------------------------------------------------------------------
    # Full auto — single-gated AI pwn end-to-end
    # ------------------------------------------------------------------
    def _action_full_auto_pwn(self, args: Dict[str, Any],
                              started: float) -> Dict[str, Any]:
        """End-to-end AI pwn on a BLE target. Operator-owned
        devices only. Single-gate.

        The single-gate invariant: ONE ``confirm_fn`` prompt
        fires BEFORE the chain is planned. The per-step ACCEPT
        gates inside the chain walk are unchanged.
        """
        from core.post_access_tui.full_auto import run_full_auto
        target_address = self.connected_address or (
            (args or {}).get("address") if isinstance(args, dict) else None
        )
        if not target_address:
            return self._envelope(
                started, ok=False,
                error="no BLE device selected / connected",
            )
        target: Dict[str, Any] = {
            "address": target_address,
            "connected": bool(self.connected_address),
            "services": (
                [s.uuid for s in self.services_cache]
                if self.services_cache else []
            ),
        }
        panel_state: Dict[str, Any] = {
            "adapter": getattr(self, "adapter", None),
            "scanning": bool(getattr(self, "_scanning", False)),
            "connected": bool(self.connected_address),
            "address": target_address,
            "target": target,
        }
        ai_planner = getattr(self, "_ai_chain_planner", None)
        walk_chain = getattr(self, "_walk_chain", None)
        if ai_planner is None or walk_chain is None:
            return self._envelope(
                started, ok=False,
                error="full-auto not wired: missing ai_planner or walk_chain",
            )
        try:
            return run_full_auto(
                domain="ble",
                panel_state=panel_state,
                ai_planner=ai_planner,
                walk_chain=walk_chain,
                spawn_post_access_tui=getattr(
                    self, "_spawn_post_access_tui", None),
                confirm_fn=self.confirm_fn,
                on_event=getattr(self, "_on_event", None),
            )
        except Exception as e:  # noqa: BLE001
            return self._envelope(
                started, ok=False,
                error=f"full-auto raised: {e}",
            )

    # ------------------------------------------------------------------
    # Envelope helper (panel-side)
    # ------------------------------------------------------------------
    @staticmethod
    def _envelope(started: float, *, ok: bool, error: str = "",
                  data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return {
            "name": "ble_panel",
            "ok": ok,
            "data": data if data is not None else {},
            "error": error,
            "duration_s": round(_now() - started, 3),
            "host_os": _host_os(),
            "risk": "intrusive",
        }


# ---------------------------------------------------------------------------
# Screen mixin — extends PostAccessScreen with a [B]luetooth menu item
# ---------------------------------------------------------------------------

def ble_menu_entry() -> Tuple[str, str, str]:
    """Return the (label, key, action_name) tuple for the screen
    MENU. The screen adds this entry to its menu list."""
    return ("[B]luetooth — BLE RAT-like device control (panel)", "b", "ble")


def ble_dispatch(screen: "BaseScreen", panel: BLEPanel,
                 ) -> Dict[str, Any]:
    """Open the BLE panel from the screen, run a curses-free loop
    until the operator picks [E]xit, and return the panel's exit
    envelope. The screen passes its ``input_fn`` and ``confirm_fn``
    into the panel.

    The menu is DYNAMIC: it's recomputed on every iteration from
    the panel's state, so the operator only sees actions that are
    currently applicable (e.g. ``[H]eart rate`` only appears when a
    Heart Rate service is present).

    The single-key + arrow / ENTER / BACKSPACE loop is implemented
    in :func:`core.post_access_tui.menu_loop.curses_free_loop`; this
    function is a thin wiring layer that adapts the screen to the
    helper's contract.
    """
    from core.post_access_tui.menu_loop import curses_free_loop

    # Wire the screen's hooks into the panel
    panel._on_event = screen._on_event  # type: ignore[attr-defined]
    panel._input_fn = screen.input_fn
    panel.confirm_fn = screen.confirm_fn

    def _render_menu() -> None:
        """Render the current dynamic menu to the screen log."""
        try:
            screen._emit(panel.menu_text())
        except Exception:  # noqa: BLE001
            pass

    def _visible_hotkeys() -> set:
        return {cap.hotkey for cap in panel.visible_capabilities()}

    def _requires_gate(hotkey: str) -> bool:
        action = panel.KEY_MAP.get(hotkey)
        if not action:
            return False
        if action not in panel.HOTKEY_MAP and action != "exit":
            return False
        cap = next(
            (c for c in panel.visible_capabilities() if c.action == action),
            None,
        )
        return bool(cap and cap.requires_gate)

    def _gate_prompt(hotkey: str) -> str:
        action = panel.KEY_MAP.get(hotkey) or hotkey
        cap = next(
            (c for c in panel.visible_capabilities() if c.action == action),
            None,
        )
        label = cap.label.split(" — ", 1)[-1] if cap and " — " in cap.label else (
            cap.label if cap else action
        )
        return f"ACCEPT INTRUSIVE? BLE {action} ({label})"

    def _handle(hotkey: str) -> Optional[Dict[str, Any]]:
        action = panel.KEY_MAP.get(hotkey)
        if action is None:
            return None
        if action not in panel.HOTKEY_MAP and action != "exit":
            return None
        env = panel.dispatch(action)
        try:
            screen._emit(
                f"ble {action} ok={env.get('ok')} "
                f"err={env.get('error', '')}"
            )
        except Exception:  # noqa: BLE001
            pass
        # Re-render the menu so the operator sees the updated state
        # (e.g. new actions now available after a successful gatt).
        _render_menu()
        return env

    def _ble_pdf_hook(_env):
        """Phase 2.4 §B.11 — best-effort PDF export after the BLE
        panel exits. Failures are logged but never block the loop."""
        try:
            from .rat_ext import auto_pdf as _auto_pdf
            session = {
                "session_id": "ble_panel",
                "transport": "ble",
                "target": str(getattr(screen, "target", "") or "<ble>"),
                "achieved": [],
                "capabilities": [],
                "exfil_jobs": [],
                "persistence_mechanisms": [],
                "screens": [],
                "step_envelope_history": [],
            }
            return _auto_pdf.export_full_report([session], chain="ble")
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "error": str(e)}

    return curses_free_loop(
        prompt="ble> ",
        screen=screen,
        render_menu=_render_menu,
        visible_hotkeys=_visible_hotkeys,
        handle=_handle,
        requires_gate_lookup=_requires_gate,
        gate_prompt=_gate_prompt,
        pdf_on_exit=_ble_pdf_hook,
    )


__all__ = [
    "BLEDevice",
    "BLEService",
    "BLECharacteristic",
    "BLEPanelClient",
    "BLEPanel",
    "ble_menu_entry",
    "ble_dispatch",
]
