#!/usr/bin/env python3
"""
Interface Picker
=================
Runtime detection of wireless (``iw dev`` / ``iw phy`` / ``ip link``) and
Bluetooth (``hcitool dev`` / ``bluetoothctl``) adapters, presented as a
curses list the operator picks from. No interface name is ever hardcoded —
every adapter is discovered at runtime.

Auto-selects the first monitor-capable wireless adapter if the operator
does not pick one.
"""

import logging
import shutil
import subprocess
from typing import List, Dict, Optional

logger = logging.getLogger(__name__)


def detect_wireless_interfaces() -> List[Dict[str, str]]:
    """Detect wireless adapters via `iw dev` + `iw phy` + `ip link`.

    Returns a list of dicts: {name, phy, monitor, injection, state}.
    ``injection`` reports whether the phy advertises packet-injection in
    its ``Supported interface modes`` block. It is a *static* check; the
    runtime check lives in ``core.modules.mt7921e_tools.test_injection``.
    """
    if not shutil.which("iw") or not shutil.which("ip"):
        return []
    ifaces: List[Dict[str, str]] = []
    try:
        devs = subprocess.run(
            ["iw", "dev"], capture_output=True, text=True, timeout=4
        ).stdout
    except Exception as e:
        logger.debug(f"iw dev failed: {e}")
        return []

    names = []
    for line in devs.splitlines():
        if "Interface" in line:
            parts = line.split("Interface", 1)
            if len(parts) == 2:
                names.append(parts[1].strip())

    # Per-phy monitor capability + link state.
    try:
        phys = subprocess.run(
            ["iw", "phy"], capture_output=True, text=True, timeout=4
        ).stdout
    except Exception:
        phys = ""
    try:
        links = subprocess.run(
            ["ip", "-o", "link"], capture_output=True, text=True, timeout=4
        ).stdout
    except Exception:
        links = ""

    for name in names:
        monitor = "monitor" in phys  # coarse; refined below
        # Refine monitor capability for this iface's phy.
        mon = _iface_monitor_capable(name, phys)
        injection = _iface_injection_capable(name, phys)
        state = "down"
        for ln in links.splitlines():
            if f" {name}:" in ln or ln.strip().startswith(f"{name}:"):
                if "UP" in ln:
                    state = "up"
                break
        ifaces.append(
            {"name": name, "phy": "", "monitor": mon,
             "injection": injection, "state": state}
        )
    return ifaces


def _iface_monitor_capable(name: str, phy_dump: str) -> bool:
    """Best-effort check that `name`'s phy supports monitor mode."""
    # Find the phy owning this interface, then look for "monitor" in its
    # supported interface modes block.
    try:
        out = subprocess.run(
            ["iw", "dev", name, "info"], capture_output=True, text=True, timeout=3
        ).stdout
        phy = ""
        for line in out.splitlines():
            if "wiphy" in line:
                phy = line.strip().split()[-1]
                break
        if phy:
            # Look for the phy's "supported interface modes" block.
            block = phy_dump.split(f"phy#{phy}")[-1] if f"phy#{phy}" in phy_dump else ""
            return "monitor" in block
    except Exception:
        pass
    return False


def _iface_injection_capable(name: str, phy_dump: str) -> bool:
    """Best-effort check that `name`'s phy reports packet-injection in
    its ``Supported interface modes`` block.

    Distinct from monitor capability: a phy can be monitor-capable but
    not injection-capable (some drivers report the former but silently
    drop injected frames at runtime — that's what
    ``core.modules.mt7921e_tools.test_injection`` catches).

    Parses the same `iw phy` block format as
    :func:`core.modules.mt7921e_tools._parse_iw_phy_block` but with the
    lighter substring match the rest of this module already uses.
    """
    try:
        out = subprocess.run(
            ["iw", "dev", name, "info"], capture_output=True, text=True, timeout=3
        ).stdout
        phy = ""
        for line in out.splitlines():
            if "wiphy" in line:
                phy = line.strip().split()[-1]
                break
        if not phy:
            return False
        # The `iw phy` block for this phy lists `* <mode>` under
        # `Supported interface modes`. We isolate the block by `phy#<id>`
        # (the same convention `_iface_monitor_capable` uses).
        if f"phy#{phy}" not in phy_dump:
            return False
        block = phy_dump.split(f"phy#{phy}", 1)[-1]
        # Look for `* injection` line.
        for line in block.splitlines():
            stripped = line.strip()
            if stripped == "* injection":
                return True
    except Exception:
        pass
    return False


def detect_ble_interfaces() -> List[Dict[str, str]]:
    """Detect Bluetooth adapters via `hcitool dev`.

    Returns a list of dicts: {name, address}.
    """
    if not shutil.which("hcitool"):
        return []
    try:
        out = subprocess.run(
            ["hcitool", "dev"], capture_output=True, text=True, timeout=4
        ).stdout
    except Exception:
        return []
    adapters: List[Dict[str, str]] = []
    lines = out.splitlines()
    for line in lines[1:]:  # skip "Devices:" header
        parts = line.split()
        if len(parts) >= 2:
            adapters.append({"name": parts[1], "address": parts[0]})
    return adapters


def _pick(stdscr, activity_log: List[str], title: str,
          items: List[Dict[str, str]], summary_fn) -> Optional[str]:
    """Render a small curses picker. Returns the chosen item's primary key
    (interface name), or None on cancel."""
    import curses
    if not items:
        activity_log.append(f"[!] No {title} detected (is the tool installed?)")
        return None
    idx = 0
    while True:
        stdscr.erase()
        h, w = stdscr.getmaxyx()
        stdscr.addstr(0, 2, f" {title} — UP/DOWN to move, ENTER to select, q to cancel ")
        for i, it in enumerate(items):
            y = 2 + i
            if y >= h - 1:
                break
            line = summary_fn(it)
            if i == idx:
                stdscr.attron(curses.A_REVERSE)
            try:
                stdscr.addstr(y, 2, line[: w - 4])
            except curses.error:
                pass
            if i == idx:
                stdscr.attroff(curses.A_REVERSE)
        stdscr.refresh()
        key = stdscr.getch()
        if key == -1:
            continue
        if key in (curses.KEY_UP,):
            idx = (idx - 1) % len(items)
        elif key in (curses.KEY_DOWN,):
            idx = (idx + 1) % len(items)
        elif key in (curses.KEY_ENTER, 10, 13):
            return items[idx].get("name")
        elif key in (ord("q"), ord("Q"), 27, curses.KEY_BACKSPACE, 127, 8):
            return None


def pick_wireless_interface(stdscr, activity_log: List[str]) -> Optional[str]:
    ifaces = detect_wireless_interfaces()
    # Auto-select first monitor-capable adapter if the operator cancels.
    chosen = _pick(
        stdscr, activity_log, "Wireless Adapters",
        ifaces,
        lambda it: f"{it['name']:12} state={it['state']:5} "
                   f"monitor={'yes' if it['monitor'] else 'no'}",
    )
    if chosen:
        return chosen
    mon = next((i["name"] for i in ifaces if i["monitor"]), None)
    if mon:
        activity_log.append(f"[i] Auto-selected monitor-capable adapter: {mon}")
        return mon
    if ifaces:
        activity_log.append(f"[i] Auto-selected adapter: {ifaces[0]['name']}")
        return ifaces[0]["name"]
    return None


def pick_ble_interface(stdscr, activity_log: List[str]) -> Optional[str]:
    adapters = detect_ble_interfaces()
    return _pick(
        stdscr, activity_log, "Bluetooth Adapters",
        adapters,
        lambda it: f"{it['name']:12} {it['address']}",
    )