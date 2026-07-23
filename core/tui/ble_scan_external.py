#!/usr/bin/env python3
"""Airgeddon / wifite2-style external BLE scan TUI.

Launched in a separate terminal from the main dashboard so the operator
gets a dedicated scan window:

  - Live-time updating BLE discovery (max-range multi-backend merge)
  - Table Above: devices currently advertising (online)
  - Table Under: devices previously seen that went silent (disappeared),
    preserving recon info (name, RSSI, services, last seen)
  - TAB switches focus between tables
  - ``A`` runs / confirms **AIO ATTACK** intent (written to out JSON)
  - ``r`` rescan/reset, ``q`` quit without forcing selection
"""
from __future__ import annotations

import argparse
import curses
import json
import os
import sys
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


def _get_oui_vendor(mac: str) -> str:
    if not mac or len(mac) < 8:
        return "Unknown"
    try:
        from core.ble.runner import _oui_vendor
        v = _oui_vendor(mac)
        if v and v != "Unknown":
            return v
    except Exception:
        pass
    # Small local fallback for common BLE chip vendors
    prefix = mac.upper()[:8]
    _LOCAL = {
        "00:1A:7D": "Cambridge Silicon",
        "00:1B:DC": "Apple",
        "00:25:00": "Apple",
        "AC:BC:32": "Apple",
        "A4:C1:38": "Xiaomi/Telink",
        "C4:7C:8D": "Xiaomi",
        "00:1E:C0": "Microchip",
        "00:07:80": "Bluegiga",
        "00:80:25": "Telit",
        "B8:27:EB": "Raspberry Pi",
        "DC:A6:32": "Raspberry Pi",
        "E4:5F:01": "Raspberry Pi",
        "00:1A:22": "Lexar/Unknown",
        "00:18:31": "Texas Instruments",
        "54:6C:0E": "Texas Instruments",
        "00:60:37": "Philips",
        "00:17:88": "Philips Hue",
    }
    return _LOCAL.get(prefix, "Unknown OUI")


def _norm_addr(addr: str) -> str:
    return (addr or "").strip().upper()


def _write_selection(
    out_path: Path,
    target: Optional[Dict[str, Any]],
    *,
    aio: bool = False,
    devices: Optional[List[Dict[str, Any]]] = None,
    disappeared_devices: Optional[List[Dict[str, Any]]] = None,
) -> None:
    payload = {
        "ts": time.time(),
        "selected": target,
        "aio_attack": bool(aio),
        "devices": devices or [],
        "disappeared_devices": disappeared_devices or [],
        # Alias keys so BLEScreen / WiFi-shaped loaders can both work
        "networks": devices or [],
        "disappeared_networks": disappeared_devices or [],
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


class LiveBLEScanner:
    """Background live BLE discovery with online / disappeared tables."""

    def __init__(
        self,
        adapter: Optional[str] = None,
        disappeared_timeout: float = 20.0,
        pulse_s: int = 8,
    ):
        self.adapter = adapter
        self.disappeared_timeout = float(disappeared_timeout)
        self.pulse_s = max(3, int(pulse_s))
        self.device_catalog: Dict[str, Dict[str, Any]] = {}
        self.last_seen_ts: Dict[str, float] = {}
        self._thread: Optional[threading.Thread] = None
        self._running = False
        self.last_error: str = ""
        self.prep_notes: List[str] = []
        self.backends_tried: List[str] = []
        self.total_pulses = 0
        self._lock = threading.Lock()
        self._did_prep = False
        self._scanner = None

    def start(self) -> None:
        self._running = True
        self.last_error = ""
        self._did_prep = False
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def _loop(self) -> None:
        while self._running:
            try:
                self._pulse()
            except Exception as e:
                self.last_error = str(e)[:200]
            # Brief yield so stop() is responsive between pulses
            for _ in range(4):
                if not self._running:
                    return
                time.sleep(0.25)

    def _pulse(self) -> None:
        try:
            root = Path(__file__).resolve().parents[2]
            if str(root) not in sys.path:
                sys.path.insert(0, str(root))
            from core.scanners.enhanced_ble_scanner import EnhancedBLEScanner
        except Exception as e:
            self.last_error = f"import EnhancedBLEScanner: {e}"
            time.sleep(2)
            return

        if self._scanner is None:
            self._scanner = EnhancedBLEScanner()
            self._scanner.initialize()
        sc = self._scanner
        # Prep only on first pulse / after rescan — max-range once,
        # then pure discovery pulses for a snappy live UI.
        do_prep = not self._did_prep
        data = sc.scan(
            duration=self.pulse_s, adapter=self.adapter, prep=do_prep,
        )
        self._did_prep = True
        self.total_pulses += 1
        if data.get("prep_notes"):
            self.prep_notes = list(data.get("prep_notes") or [])[:12]
        if data.get("backends_tried"):
            self.backends_tried = list(data.get("backends_tried") or [])
        if data.get("error") and not data.get("devices"):
            self.last_error = str(data["error"])[:200]
        elif data.get("devices"):
            self.last_error = ""
        now = time.time()
        with self._lock:
            for dev in data.get("devices") or []:
                addr = _norm_addr(dev.get("address") or "")
                if addr:
                    self._merge_device(addr, dev, now)

    def _merge_device(
        self, addr: str, dev: Dict[str, Any], now: float
    ) -> None:
        addr = _norm_addr(addr)
        if not addr:
            return
        if addr not in self.device_catalog:
            vendor = _get_oui_vendor(addr)
            entry = dict(dev)
            entry["address"] = addr
            entry["vendor"] = vendor
            entry["first_seen_ts"] = now
            self.device_catalog[addr] = entry
        else:
            cur = self.device_catalog[addr]
            name = dev.get("name") or ""
            if name and name != "Unknown":
                cur["name"] = name
            rssi = dev.get("rssi")
            if rssi is not None and (
                cur.get("rssi") is None or rssi > cur.get("rssi", -999)
            ):
                cur["rssi"] = rssi
            services = list(cur.get("services") or [])
            for s in dev.get("services") or []:
                if s not in services:
                    services.append(s)
            cur["services"] = services
            for k in ("manufacturer_data", "tx_power", "address_type",
                      "backend", "seen_by"):
                if dev.get(k) not in (None, "", [], {}):
                    if k == "seen_by":
                        merged = set(cur.get("seen_by") or [])
                        for b in dev.get("seen_by") or []:
                            merged.add(b)
                        cur["seen_by"] = sorted(merged)
                    else:
                        cur[k] = dev[k]
        self.last_seen_ts[addr] = now

    def poll(self) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        now = time.time()
        online: List[Dict[str, Any]] = []
        disappeared: List[Dict[str, Any]] = []
        with self._lock:
            items = list(self.device_catalog.items())
            last_map = dict(self.last_seen_ts)
        for addr, dev in items:
            last_ts = last_map.get(addr, 0.0)
            ago = max(0, int(now - last_ts))
            dev = dict(dev)
            dev["last_seen_ago"] = f"{ago}s ago"
            dev["last_seen_ts"] = last_ts
            vendor = dev.get("vendor") or _get_oui_vendor(addr)
            dev["vendor"] = vendor
            svc_n = len(dev.get("services") or [])
            dev["recon_info"] = {
                "vendor": vendor,
                "services_count": svc_n,
                "services": list(dev.get("services") or [])[:8],
                "rssi": dev.get("rssi"),
                "last_seen_ago": dev["last_seen_ago"],
                "seen_by": list(dev.get("seen_by") or []),
            }
            if (now - last_ts) <= self.disappeared_timeout:
                dev["status"] = "online"
                online.append(dev)
            else:
                dev["status"] = "disappeared"
                disappeared.append(dev)

        online.sort(
            key=lambda d: d.get("rssi") if d.get("rssi") is not None else -999,
            reverse=True,
        )
        disappeared.sort(
            key=lambda d: d.get("last_seen_ts") or 0.0, reverse=True
        )
        return online, disappeared

    def stop(self) -> None:
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)
        self._thread = None


def run_curses(
    stdscr,
    adapter: Optional[str],
    out_path: Path,
    pulse_s: int = 8,
    long_range: bool = False,
) -> int:
    curses.curs_set(0)
    stdscr.timeout(150)
    stdscr.keypad(True)
    if curses.has_colors():
        curses.start_color()
        curses.use_default_colors()
        curses.init_pair(1, curses.COLOR_GREEN, -1)
        curses.init_pair(2, curses.COLOR_YELLOW, -1)
        curses.init_pair(3, curses.COLOR_CYAN, -1)
        curses.init_pair(4, curses.COLOR_RED, -1)

    # Long-range: BLE devices advertise slowly, so keep disappeared
    # devices on screen much longer to catch intermittent/distant beacons.
    disappeared_timeout = 90.0 if long_range else 30.0
    scanner = LiveBLEScanner(
        adapter=adapter, disappeared_timeout=disappeared_timeout,
        pulse_s=pulse_s,
    )
    scanner.start()

    active_table = "online"
    online_idx = 0
    disappeared_idx = 0
    selected: Optional[Dict[str, Any]] = None
    iface_label = adapter or "auto"
    message = (
        "↑/↓ move · TAB switch table · ENTER/SPACE select · "
        "A AIO ATTACK · r rescan · q quit"
    )

    try:
        while True:
            online, disappeared = scanner.poll()

            if online:
                online_idx = max(0, min(online_idx, len(online) - 1))
            else:
                online_idx = 0
            if disappeared:
                disappeared_idx = max(
                    0, min(disappeared_idx, len(disappeared) - 1)
                )
            else:
                disappeared_idx = 0

            stdscr.erase()
            h, w = stdscr.getmaxyx()
            title = (
                f" KFIOSA · BLE Scan (Live Long-Range) · {iface_label} "
            )
            try:
                stdscr.addstr(
                    0, 2, title[: w - 3],
                    curses.color_pair(3) | curses.A_BOLD,
                )
                backends = (
                    "+".join(scanner.backends_tried)
                    if scanner.backends_tried else "…"
                )
                stat_str = (
                    f"Status: Live · Online: {len(online)} · "
                    f"Gone: {len(disappeared)} · "
                    f"pulses={scanner.total_pulses} · backends={backends}"
                )
                stdscr.addstr(1, 2, stat_str[: w - 4], curses.color_pair(2))
                if scanner.last_error and not online:
                    stdscr.addstr(
                        2, 2,
                        f"[!] {scanner.last_error}"[: w - 4],
                        curses.color_pair(4),
                    )
                else:
                    stdscr.addstr(2, 2, message[: w - 4])
            except curses.error:
                pass

            avail_h = max(4, h - 9)
            if disappeared:
                h_online = max(3, (avail_h * 6) // 10)
                h_disappeared = max(3, avail_h - h_online)
            else:
                h_online = avail_h
                h_disappeared = 0

            # --- TABLE ABOVE: ONLINE ---
            top1 = 3
            try:
                focus_hdr = (
                    curses.color_pair(1) | curses.A_BOLD
                    if active_table == "online"
                    else curses.A_DIM
                )
                hdr1 = (
                    f"── TABLE ABOVE: ONLINE DEVICES ({len(online)}) "
                    f"[arrows · ENTER/SPACE select] ──"
                )
                stdscr.addstr(top1, 2, hdr1[: w - 4], focus_hdr)
                col_hdr1 = (
                    "   NAME                 ADDRESS            RSSI   "
                    "TYPE     SVCS  VENDOR"
                )
                stdscr.addstr(
                    top1 + 1, 2, col_hdr1[: w - 4], curses.A_UNDERLINE
                )
            except curses.error:
                pass

            v_online = max(1, h_online - 2)
            start1 = max(
                0,
                min(online_idx - v_online // 2, max(0, len(online) - v_online)),
            )
            for row, i in enumerate(
                range(start1, min(start1 + v_online, len(online)))
            ):
                d = online[i]
                name = (d.get("name") or "Unknown")[:18]
                addr = (d.get("address") or "?")[:17]
                rssi = str(
                    d.get("rssi") if d.get("rssi") is not None else "?"
                )
                atype = (d.get("address_type") or "?")[:7]
                svcs = str(len(d.get("services") or []))
                vendor = (d.get("vendor") or "Unknown")[:12]
                is_focused = active_table == "online" and i == online_idx
                is_sel = (
                    selected is not None
                    and selected.get("address") == d.get("address")
                )
                mark = "▶" if is_focused else ("*" if is_sel else " ")
                line = (
                    f"{mark} {name:18} {addr:17} {rssi:>4}dBm  "
                    f"{atype:7} {svcs:>3}    {vendor}"
                )
                y = top1 + 2 + row
                if y >= top1 + h_online:
                    break
                attr = curses.A_REVERSE if is_focused else curses.A_NORMAL
                if is_sel:
                    attr |= curses.color_pair(1)
                try:
                    stdscr.addstr(y, 2, line[: w - 4], attr)
                except curses.error:
                    pass

            # --- TABLE UNDER: DISAPPEARED ---
            if h_disappeared > 0:
                top2 = top1 + h_online
                try:
                    focus_hdr2 = (
                        curses.color_pair(2) | curses.A_BOLD
                        if active_table == "disappeared"
                        else curses.A_DIM
                    )
                    hdr2 = (
                        f"── TABLE UNDER: DISAPPEARED ({len(disappeared)}) "
                        f"[with fetched recon] ──"
                    )
                    stdscr.addstr(top2, 2, hdr2[: w - 4], focus_hdr2)
                    col_hdr2 = (
                        "   NAME                 ADDRESS            RSSI  "
                        "RECON (Vendor, Services, Last Seen)"
                    )
                    stdscr.addstr(
                        top2 + 1, 2, col_hdr2[: w - 4], curses.A_UNDERLINE
                    )
                except curses.error:
                    pass

                v_dis = max(1, h_disappeared - 2)
                start2 = max(
                    0,
                    min(
                        disappeared_idx - v_dis // 2,
                        max(0, len(disappeared) - v_dis),
                    ),
                )
                for row, i in enumerate(
                    range(start2, min(start2 + v_dis, len(disappeared)))
                ):
                    d = disappeared[i]
                    name = (d.get("name") or "Unknown")[:18]
                    addr = (d.get("address") or "?")[:17]
                    rssi = str(
                        d.get("rssi") if d.get("rssi") is not None else "?"
                    )
                    ago = d.get("last_seen_ago", "?")
                    vendor = d.get("vendor", "Unknown")
                    svc_n = len(d.get("services") or [])
                    recon = (
                        f"Vendor: {vendor} | {svc_n} svc | last {ago}"
                    )
                    is_focused = (
                        active_table == "disappeared"
                        and i == disappeared_idx
                    )
                    is_sel = (
                        selected is not None
                        and selected.get("address") == d.get("address")
                    )
                    mark = "▶" if is_focused else ("*" if is_sel else " ")
                    line = (
                        f"{mark} {name:18} {addr:17} {rssi:>4}dBm  "
                        f"{recon}"
                    )
                    y = top2 + 2 + row
                    if y >= h - 5:
                        break
                    attr = (
                        curses.A_REVERSE
                        if is_focused
                        else curses.color_pair(2)
                    )
                    if is_sel:
                        attr |= curses.color_pair(1)
                    try:
                        stdscr.addstr(y, 2, line[: w - 4], attr)
                    except curses.error:
                        pass

            # Footer
            fy = h - 4
            try:
                hovered = None
                if active_table == "online" and online:
                    hovered = online[online_idx]
                elif active_table == "disappeared" and disappeared:
                    hovered = disappeared[disappeared_idx]

                if selected:
                    s = selected
                    stdscr.addstr(
                        fy, 2,
                        (
                            f"SELECTED: {s.get('name')} [{s.get('address')}] "
                            f"RSSI {s.get('rssi')}dBm "
                            f"({s.get('vendor', 'Unknown')})"
                        )[: w - 4],
                        curses.color_pair(1) | curses.A_BOLD,
                    )
                elif hovered:
                    hv = hovered
                    stdscr.addstr(
                        fy, 2,
                        (
                            f"Hovered: {hv.get('name')} [{hv.get('address')}] "
                            f"| Vendor: {hv.get('vendor')} | "
                            f"RSSI: {hv.get('rssi')} | "
                            f"Services: {len(hv.get('services') or [])}"
                        )[: w - 4],
                        curses.color_pair(3),
                    )
                else:
                    stdscr.addstr(
                        fy, 2, "No target selected yet."[: w - 4]
                    )

                stdscr.addstr(
                    fy + 1, 2,
                    (
                        "[A] AIO ATTACK = recon → CVE → plan → poly → "
                        "attack → post-exploit (ACCEPT/CANCEL gated)"
                    )[: w - 4],
                    curses.color_pair(2),
                )
                stdscr.addstr(
                    fy + 2, 2,
                    (
                        "↑/↓ move · TAB switch · ENTER/SPACE select · "
                        "A AIO · r rescan · q exit"
                    )[: w - 4],
                )
            except curses.error:
                pass

            stdscr.refresh()
            try:
                from core.tui.base_screen import read_curses_key
                key = read_curses_key(stdscr, timeout_ms=150)
            except Exception:
                key = stdscr.getch()
            if key == -1:
                continue

            if key in (curses.KEY_UP, ord("k"), ord("K")):
                if active_table == "online":
                    if online:
                        online_idx = max(0, online_idx - 1)
                else:
                    if disappeared_idx > 0:
                        disappeared_idx -= 1
                    else:
                        active_table = "online"
                        if online:
                            online_idx = len(online) - 1

            elif key in (curses.KEY_DOWN, ord("j"), ord("J")):
                if active_table == "online":
                    if online_idx < len(online) - 1:
                        online_idx += 1
                    elif disappeared:
                        active_table = "disappeared"
                        disappeared_idx = 0
                else:
                    if disappeared:
                        disappeared_idx = min(
                            len(disappeared) - 1, disappeared_idx + 1
                        )

            elif key in (
                ord("\t"), 9,
                getattr(curses, "KEY_LEFT", 260),
                getattr(curses, "KEY_RIGHT", 261),
                ord("h"), ord("H"), ord("l"), ord("L"),
            ):
                if active_table == "online" and disappeared:
                    active_table = "disappeared"
                else:
                    active_table = "online"

            elif key in (curses.KEY_ENTER, 10, 13, ord(" ")):
                if active_table == "online" and online:
                    selected = dict(online[online_idx])
                elif active_table == "disappeared" and disappeared:
                    selected = dict(disappeared[disappeared_idx])
                if selected:
                    _write_selection(
                        out_path,
                        selected,
                        aio=False,
                        devices=online,
                        disappeared_devices=disappeared,
                    )
                    message = (
                        f"Selected {selected.get('name')} "
                        f"[{selected.get('address')}] — "
                        f"press A for AIO ATTACK or q to return"
                    )

            elif key in (ord("a"), ord("A")):
                if not selected:
                    if active_table == "online" and online:
                        selected = dict(online[online_idx])
                    elif active_table == "disappeared" and disappeared:
                        selected = dict(disappeared[disappeared_idx])
                if not selected:
                    message = "Select a target first (ENTER/SPACE)"
                    continue
                _write_selection(
                    out_path,
                    selected,
                    aio=True,
                    devices=online,
                    disappeared_devices=disappeared,
                )
                message = "AIO ATTACK queued — closing scan window…"
                stdscr.refresh()
                time.sleep(0.4)
                return 0

            elif key in (ord("r"), ord("R")):
                scanner.stop()
                with scanner._lock:
                    scanner.device_catalog.clear()
                    scanner.last_seen_ts.clear()
                scanner._scanner = None
                scanner._did_prep = False
                scanner.start()
                online_idx = 0
                disappeared_idx = 0
                message = "Scanner reset — live long-range scan restarted."

            elif key in (ord("q"), ord("Q"), 27):
                _write_selection(
                    out_path,
                    selected,
                    aio=False,
                    devices=online,
                    disappeared_devices=disappeared,
                )
                return 0
    finally:
        scanner.stop()


def run_text_ui(
    adapter: Optional[str],
    out_path: Path,
    seconds: int = 20,
    pulse_s: int = 8,
    long_range: bool = False,
) -> int:
    """Non-curses fallback when stdin/stdout is not a real TTY."""
    print("=" * 65)
    print(" KFIOSA BLE Scan (text mode — live long-range)")
    print(f" Adapter: {adapter or 'auto'}  duration≈{seconds}s"
          f"{'  [LONG-RANGE]' if long_range else ''}")
    print("=" * 65)
    print("[*] Prepping adapter + starting live multi-backend scan…")
    disappeared_timeout = 90.0 if long_range else 30.0
    scanner = LiveBLEScanner(
        adapter=adapter, disappeared_timeout=disappeared_timeout,
        pulse_s=pulse_s,
    )
    scanner.start()
    try:
        time.sleep(max(4, int(seconds)))
        online, disappeared = scanner.poll()
        if scanner.prep_notes:
            for n in scanner.prep_notes[:6]:
                print(f"[i] {n}")
        if scanner.backends_tried:
            print(f"[i] backends: {', '.join(scanner.backends_tried)}")
        if scanner.last_error and not online:
            print(f"[!] {scanner.last_error}")

        print(f"\n[+] TABLE ABOVE: ONLINE DEVICES ({len(online)}):\n")
        if not online:
            print("  <no online BLE devices currently detected>")
        else:
            for i, d in enumerate(online):
                vendor = d.get("vendor", "Unknown")
                svcs = len(d.get("services") or [])
                print(
                    f"  {i + 1:3d}. {(d.get('name') or 'Unknown'):20s} "
                    f"{(d.get('address') or '?'):17s} "
                    f"{d.get('rssi') or '?':>4}dBm  "
                    f"[{vendor} | {svcs} svc]"
                )

        print(
            f"\n[+] TABLE UNDER: DISAPPEARED WITH RECON "
            f"({len(disappeared)}):\n"
        )
        if not disappeared:
            print("  <no disappeared devices>")
        else:
            for i, d in enumerate(disappeared):
                vendor = d.get("vendor", "Unknown")
                ago = d.get("last_seen_ago", "?")
                svcs = len(d.get("services") or [])
                print(
                    f"  D{i + 1:>2}. {(d.get('name') or 'Unknown'):20s} "
                    f"{(d.get('address') or '?'):17s} "
                    f"{d.get('rssi') or '?':>4}dBm  "
                    f"[Recon: Vendor={vendor}, Svcs={svcs}, Last={ago}]"
                )

        print(
            "\nCommands: number (e.g. 1 or D1) select | "
            "A <n> AIO ATTACK | i <n> device info | "
            "I <n> disappeared info | q quit"
        )
        selected = None
        aio = False

        def _print_info(dev: Optional[Dict[str, Any]], label: str) -> None:
            if dev is None:
                print("  invalid selection")
                return
            name = dev.get("name") or "Unknown"
            addr = dev.get("address") or "?"
            print(f"\n  Device info ({label}): {name} [{addr}]")
            print(f"    RSSI:     {dev.get('rssi') or '?'} dBm")
            print(f"    Vendor:   {dev.get('vendor') or 'Unknown'}")
            print(f"    Address type: {dev.get('address_type') or '?'}")
            print(f"    TX power: {dev.get('tx_power') or '?'}")
            svcs = dev.get("services") or []
            print(f"    Services ({len(svcs)}):")
            if svcs:
                for s in svcs[:12]:
                    print(f"      · {s}")
            else:
                print("      · none captured")
            mfg = dev.get("manufacturer_data") or {}
            if mfg:
                print(f"    Manufacturer data:")
                for k, v in list(mfg.items())[:8]:
                    print(f"      · {k}: {v}")
            seen = dev.get("seen_by") or []
            if seen:
                print(f"    Seen by: {', '.join(seen)}")

        while True:
            try:
                raw = input("> ").strip()
            except (EOFError, KeyboardInterrupt):
                print()
                break
            if not raw or raw.lower() in ("q", "quit", "exit"):
                break

            lower = raw.lower()
            if lower.startswith("i ") or lower == "i":
                parts = raw.split()
                target_str = parts[1] if len(parts) > 1 else (
                    "1" if online else ""
                )
                dev = _pick_text_dev(target_str, online, [])
                _print_info(dev, "online")
                continue
            if lower.startswith("I ") or lower == "I":
                parts = raw.split()
                target_str = parts[1] if len(parts) > 1 else (
                    "D1" if disappeared else ""
                )
                dev = _pick_text_dev(target_str, [], disappeared)
                _print_info(dev, "disappeared")
                continue

            if lower.startswith("a"):
                parts = raw.split()
                target_str = parts[1] if len(parts) > 1 else "1"
                selected = _pick_text_dev(target_str, online, disappeared)
                if selected:
                    aio = True
                    print(
                        f"[AIO] Selected {selected.get('name')} "
                        f"[{selected.get('address')}]"
                    )
                    break
                print("invalid selection")
                continue

            selected = _pick_text_dev(raw, online, disappeared)
            if selected:
                svcs = selected.get("services") or []
                print(
                    f"[+] Selected {selected.get('name')} "
                    f"[{selected.get('address')}] — "
                    f"{len(svcs)} service(s) — "
                    f"type A to launch AIO or q to save & quit"
                )
                continue
            print("enter a number (e.g. 1 or D1), A <n>, i <n>, I <n>, or q")

        _write_selection(
            out_path,
            selected,
            aio=aio,
            devices=online,
            disappeared_devices=disappeared,
        )
        if selected:
            print(f"[+] Wrote selection → {out_path}  aio={aio}")
        else:
            print(f"[i] No selection written (empty) → {out_path}")
        return 0
    finally:
        scanner.stop()


def _pick_text_dev(
    key: str,
    online: List[Dict[str, Any]],
    disappeared: List[Dict[str, Any]],
) -> Optional[Dict[str, Any]]:
    key = key.strip().upper()
    if key.startswith("D"):
        try:
            idx = int(key[1:]) - 1
            if 0 <= idx < len(disappeared):
                return dict(disappeared[idx])
        except ValueError:
            pass
    else:
        try:
            idx = int(key) - 1
            if 0 <= idx < len(online):
                return dict(online[idx])
        except ValueError:
            pass
    return None


def _curses_safe_wrapper(fn, *args) -> int:
    """Like curses.wrapper but never crashes on endwin/nocbreak ERR."""
    import curses as _curses

    stdscr = None
    try:
        stdscr = _curses.initscr()
        _curses.noecho()
        try:
            _curses.cbreak()
        except _curses.error:
            pass
        try:
            _curses.start_color()
        except _curses.error:
            pass
        try:
            stdscr.keypad(True)
        except _curses.error:
            pass
        return int(fn(stdscr, *args) or 0)
    except _curses.error as e:
        print(
            f"[!] curses UI unavailable ({e}); falling back to text mode.",
            file=sys.stderr,
        )
        if len(args) >= 2:
            return run_text_ui(
                args[0], args[1],
                seconds=20,
                pulse_s=args[2] if len(args) > 2 else 8,
                long_range=bool(args[3]) if len(args) > 3 else False,
            )
        return 1
    finally:
        if stdscr is not None:
            try:
                stdscr.keypad(False)
            except Exception:
                pass
            try:
                _curses.echo()
            except Exception:
                pass
            try:
                _curses.nocbreak()
            except Exception:
                pass
            try:
                _curses.endwin()
            except Exception:
                pass


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--adapter",
        default="",
        help="HCI adapter (e.g. hci0); empty = auto/default",
    )
    ap.add_argument(
        "--out",
        default=str(Path("logs") / "ble_scan_selection.json"),
        help="JSON path for selection + aio_attack flag",
    )
    ap.add_argument(
        "--seconds",
        type=int,
        default=20,
        help="Text-mode scan duration (curses is continuous)",
    )
    ap.add_argument(
        "--pulse",
        type=int,
        default=12,
        help="Live pulse duration per multi-backend scan cycle",
    )
    ap.add_argument(
        "--long-range",
        action="store_true",
        help="Long-range sweep: keep disappeared devices on screen far "
             "longer (90s) so intermittent/distant BLE beacons are caught.",
    )
    ap.add_argument(
        "--text",
        action="store_true",
        help="Force text UI (no curses); also auto if not a TTY",
    )
    args = ap.parse_args(argv)
    out_path = Path(args.out)
    adapter = (args.adapter or "").strip() or None

    use_text = bool(args.text)
    if not use_text:
        try:
            use_text = not (sys.stdin.isatty() and sys.stdout.isatty())
        except Exception:
            use_text = True
        term = (os.environ.get("TERM") or "").lower()
        if term in ("", "dumb", "unknown"):
            use_text = True

    if use_text:
        return run_text_ui(
            adapter, out_path, seconds=args.seconds, pulse_s=args.pulse,
            long_range=bool(args.long_range),
        )
    return _curses_safe_wrapper(
        run_curses, adapter, out_path, args.pulse, bool(args.long_range),
    )


if __name__ == "__main__":
    raise SystemExit(main())
