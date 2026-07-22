#!/usr/bin/env python3
"""
Device Picker (airgeddon-style)
================================
Renders the Station MACs discovered during the WiFi recon pass as a
selectable curses list — ``MAC | Power | Probes | Packets | BSSID`` — so
the operator can target a single device for directed deauth, payload
staging, or an interactive shell. This is the "first step opens an
external window with fetched devices and their MACs" surface from the
operator's airgeddon-style engagement request.

The list is sourced from ``catalog_recon._client_enum``'s parsed
airodump-ng Station section (``recon["clients"].data.clients``); this
module only renders it and returns the chosen MAC. Selection itself is
gated upstream by the per-step ACCEPT/CANCEL gate before any action is
taken against the chosen device.
"""

import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


def collect_devices(recon_report: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Extract the client/device list from a catalog_recon report.

    Tolerates a missing or partial recon report (returns ``[]``). Each
    device dict carries at least ``mac``; ``power``/``probes``/``packets``
    /``bssid`` are passed through when present.
    """
    if not recon_report:
        return []
    clients_step = recon_report.get("clients") or {}
    data = clients_step.get("data") or {}
    if isinstance(data, list):  # tolerate the bare-list shape too
        return list(data)
    devices = data.get("clients") or []
    return list(devices) if isinstance(devices, list) else []


def _device_summary(it: Dict[str, Any], width: int) -> str:
    mac = it.get("mac", "?")
    power = it.get("power", "")
    probes = it.get("probes", "")
    packets = it.get("packets", "")
    bssid = it.get("bssid", "")
    line = (f"{mac:18} pwr={str(power):>4}  pkts={str(packets):>6}  "
            f"probes={probes}  ap={bssid}")
    return line[: max(0, width - 4)]


def pick_device(stdscr, activity_log: List[str],
                devices: List[Dict[str, Any]]) -> Optional[str]:
    """Render the device list and return the selected MAC, or None on
    cancel. Mirrors the :mod:`core.tui.interface_picker` list pattern."""
    import curses
    if not devices:
        activity_log.append("[!] No devices discovered (recon found no clients).")
        return None
    idx = 0
    result = None
    try:
        try:
            from core.tui.interface_picker import flush_curses_input
            flush_curses_input(stdscr)
        except Exception:
            pass
        try:
            stdscr.nodelay(False)
            stdscr.timeout(-1)
        except Exception:
            pass
        while True:
            stdscr.erase()
            h, w = stdscr.getmaxyx()
            stdscr.addstr(
                0, 2,
                " Discovered Devices — UP/DOWN to move, ENTER to select, q to cancel "
            )
            for i, it in enumerate(devices):
                y = 2 + i
                if y >= h - 1:
                    break
                line = _device_summary(it, w)
                if i == idx:
                    stdscr.attron(curses.A_REVERSE)
                try:
                    stdscr.addstr(y, 2, line)
                except curses.error:
                    pass
                if i == idx:
                    stdscr.attroff(curses.A_REVERSE)
            stdscr.refresh()
            key = stdscr.getch()
            if key == -1:
                continue
            if key in (curses.KEY_UP,):
                idx = (idx - 1) % len(devices)
            elif key in (curses.KEY_DOWN,):
                idx = (idx + 1) % len(devices)
            elif key in (curses.KEY_ENTER, 10, 13):
                mac = devices[idx].get("mac")
                activity_log.append(f"[+] Selected device: {mac}")
                result = mac
                break
            elif key in (ord("q"), ord("Q"), 27, curses.KEY_BACKSPACE, 127, 8):
                activity_log.append("[i] Device selection cancelled.")
                result = None
                break
    finally:
        try:
            stdscr.nodelay(True)
            stdscr.timeout(100)
        except Exception:
            pass
        try:
            from core.tui.interface_picker import flush_curses_input
            flush_curses_input(stdscr)
        except Exception:
            pass
    return result