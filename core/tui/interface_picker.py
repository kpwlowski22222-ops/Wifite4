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

Display fields (wireless):
  name, state (ip link UP/DOWN), mode (current: managed|monitor|…),
  mon_cap (phy supports monitor), inject (static injection mode bit),
  note (e.g. stale airmon name still in managed mode).
"""

import logging
import os
import re
import shutil
import subprocess
from typing import List, Dict, Optional, Tuple

logger = logging.getLogger(__name__)


def _normalize_phy_id(raw: str) -> str:
    """Normalize ``0`` / ``phy0`` / ``phy#0`` → ``phy0``."""
    s = (raw or "").strip()
    if not s:
        return ""
    s = s.replace("phy#", "")
    if s.startswith("phy"):
        return s
    if s.isdigit():
        return f"phy{s}"
    return s


def _iw_dev_info(name: str) -> Dict[str, str]:
    """Parse ``iw dev <name> info`` → phy, mode (type)."""
    info = {"phy": "", "mode": "unknown"}
    try:
        out = subprocess.run(
            ["iw", "dev", name, "info"],
            capture_output=True, text=True, timeout=3,
        ).stdout
    except Exception:
        return info
    for line in out.splitlines():
        ls = line.strip()
        if ls.startswith("wiphy "):
            info["phy"] = _normalize_phy_id(ls.split()[-1])
        elif ls.startswith("type "):
            info["mode"] = ls.split(None, 1)[-1].strip() or "unknown"
    # Fallback phy from sysfs when wiphy line missing.
    if not info["phy"]:
        try:
            p = os.path.realpath(f"/sys/class/net/{name}/phy80211")
            info["phy"] = os.path.basename(p) or ""
        except OSError:
            pass
    return info


def _phy_modes_block(phy_id: str, phy_dump: str) -> str:
    """Return the Supported interface modes section for ``phy_id``.

    ``iw phy`` uses ``Wiphy phy0`` headers. Older code looked for
    ``phy#0`` which appears in ``iw dev`` only — that made every
    adapter report ``monitor=no`` on modern kernels (mt7921e).
    """
    if not phy_dump or not phy_id:
        return ""
    pid = _normalize_phy_id(phy_id)
    # Prefer "Wiphy phy0" (iw phy). Also accept "phy#0" if present.
    markers = [f"Wiphy {pid}", f"Wiphy {pid}\n", f"phy#{pid.replace('phy', '')}"]
    block = ""
    for m in (f"Wiphy {pid}", f"phy#{pid[3:]}" if pid.startswith("phy") else ""):
        if m and m in phy_dump:
            block = phy_dump.split(m, 1)[-1]
            break
    if not block and pid in phy_dump:
        block = phy_dump.split(pid, 1)[-1]
    # Cut at next Wiphy / phy#.
    block = re.split(r"\nWiphy\s+\S+|\nphy#\d+", block, maxsplit=1)[0]
    if "Supported interface modes" in block:
        modes = block.split("Supported interface modes", 1)[1]
        modes = re.split(r"\n\s*[A-Z][^\n]*:", modes, maxsplit=1)[0]
        return modes
    return block


def _mode_listed(modes_block: str, mode: str) -> bool:
    if not modes_block:
        return False
    return bool(re.search(rf"^\s*\*\s+{re.escape(mode)}\b", modes_block, re.M))


def detect_wireless_interfaces() -> List[Dict[str, object]]:
    """Detect wireless adapters via `iw dev` + `iw phy` + `ip link`.

    Returns dicts with:
      name, phy, mode, monitor (cap bool), injection (cap bool),
      state, note (str).
    ``injection`` is a *static* modes-list check; runtime proof is
    ``core.modules.mt7921e_tools.test_injection``.
    """
    if not shutil.which("iw") or not shutil.which("ip"):
        return []
    ifaces: List[Dict[str, object]] = []
    try:
        devs = subprocess.run(
            ["iw", "dev"], capture_output=True, text=True, timeout=4
        ).stdout
    except Exception as e:
        logger.debug(f"iw dev failed: {e}")
        return []

    names = []
    for line in devs.splitlines():
        m = re.match(r"\s*Interface\s+(\S+)\s*$", line)
        if m:
            names.append(m.group(1))

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
        info = _iw_dev_info(name)
        phy = info["phy"]
        mode = info["mode"]
        modes_block = _phy_modes_block(phy, phys)
        mon = _mode_listed(modes_block, "monitor")
        # mt76 / mt7921e always support monitor even when modes parse fails.
        if not mon:
            try:
                drv = os.path.basename(
                    os.path.realpath(f"/sys/class/net/{name}/device/driver")
                ).lower()
            except OSError:
                drv = ""
            if any(x in drv for x in ("mt7921", "mt76", "ath9k", "ath10k", "rtw")):
                mon = True
        # Static injection: few phys list "* injection"; treat mon-capable
        # mt76 as inject-capable for display (runtime test still required).
        injection = _mode_listed(modes_block, "injection")
        if not injection and mon:
            try:
                drv = os.path.basename(
                    os.path.realpath(f"/sys/class/net/{name}/device/driver")
                ).lower()
            except OSError:
                drv = ""
            if "mt7921" in drv or "mt76" in drv:
                injection = True

        state = "down"
        for ln in links.splitlines():
            if f": {name}:" in ln or ln.strip().startswith(f"{name}:"):
                # ip -o link: "N: name: <flags> ..."
                if ",UP" in ln or " state UP " in ln or "UP," in ln:
                    state = "up"
                # Some outputs put UP only in flags: <...,UP,...>
                if re.search(r"<[^>]*\bUP\b", ln):
                    state = "up"
                break

        note = ""
        if name.endswith("mon") and mode != "monitor":
            note = "stale-mon-name (not in monitor mode)"
        elif mode == "monitor":
            note = "already monitor"

        ifaces.append({
            "name": name,
            "phy": phy,
            "mode": mode,
            "monitor": mon,
            "injection": injection,
            "state": state,
            "note": note,
        })
    return ifaces


def _iface_monitor_capable(name: str, phy_dump: str) -> bool:
    """Best-effort check that `name`'s phy supports monitor mode."""
    info = _iw_dev_info(name)
    modes = _phy_modes_block(info.get("phy") or "", phy_dump)
    if _mode_listed(modes, "monitor"):
        return True
    # Fallback: whole dump contains monitor + this is an mt76 card.
    if "monitor" in (phy_dump or ""):
        try:
            drv = os.path.basename(
                os.path.realpath(f"/sys/class/net/{name}/device/driver")
            ).lower()
            if "mt7921" in drv or "mt76" in drv:
                return True
        except OSError:
            pass
    return False


def _iface_injection_capable(name: str, phy_dump: str) -> bool:
    """Best-effort static injection capability from phy modes / driver."""
    info = _iw_dev_info(name)
    modes = _phy_modes_block(info.get("phy") or "", phy_dump)
    if _mode_listed(modes, "injection"):
        return True
    # mt7921e does not list "* injection" but supports aireplay injection
    # when in monitor mode (confirmed at runtime by test_injection).
    if _mode_listed(modes, "monitor") or "monitor" in (phy_dump or ""):
        try:
            drv = os.path.basename(
                os.path.realpath(f"/sys/class/net/{name}/device/driver")
            ).lower()
            if "mt7921" in drv or "mt76" in drv:
                return True
        except OSError:
            pass
    return False


def detect_ble_interfaces() -> List[Dict[str, str]]:
    """Detect Bluetooth adapters via bluetoothctl / hcitool / sysfs.

    Returns dicts: ``{name, address, powered, note}``.
    Prefers ``bluetoothctl list`` (modern BlueZ); falls back to
    ``hcitool dev`` and ``/sys/class/bluetooth/hci*``.
    """
    adapters: List[Dict[str, str]] = []
    seen: set = set()

    # 1) bluetoothctl list — name is always hciN when sysfs maps the MAC
    if shutil.which("bluetoothctl"):
        try:
            out = subprocess.run(
                ["bluetoothctl", "list"],
                capture_output=True, text=True, timeout=4,
            ).stdout or ""
            for line in out.splitlines():
                # Controller AA:BB:.. Name [default]
                m = re.match(
                    r"Controller\s+([0-9A-Fa-f:]{11,17})\s+(.*)$", line.strip()
                )
                if not m:
                    continue
                addr = m.group(1).upper()
                rest = m.group(2).strip()
                alias = rest.replace("[default]", "").strip() or "bt"
                powered, power_note = _ble_power_state(addr)
                hci = _ble_hci_for_addr(addr)
                if not hci:
                    # Fallback: hci0, hci1 by list order if address file empty
                    hci = f"hci{len(adapters)}"
                key = addr
                if key in seen:
                    continue
                seen.add(key)
                adapters.append({
                    "name": hci,
                    "address": addr,
                    "powered": "yes" if powered else "no",
                    "note": power_note,
                    "alias": alias,
                })
        except Exception as e:
            logger.debug("bluetoothctl list failed: %s", e)

    # 2) hcitool dev — classic "hci0\\tMAC"
    if shutil.which("hcitool"):
        try:
            out = subprocess.run(
                ["hcitool", "dev"], capture_output=True, text=True, timeout=4,
            ).stdout or ""
            for line in out.splitlines():
                if line.strip().lower().startswith("devices"):
                    continue
                parts = line.split()
                if len(parts) >= 2 and parts[0].startswith("hci"):
                    hci, addr = parts[0], parts[1].upper()
                    if addr in seen:
                        continue
                    seen.add(addr)
                    powered, power_note = _ble_power_state(addr)
                    adapters.append({
                        "name": hci,
                        "address": addr,
                        "powered": "yes" if powered else "no",
                        "note": power_note,
                        "alias": hci,
                    })
        except Exception as e:
            logger.debug("hcitool dev failed: %s", e)

    # 3) sysfs hci* — only add hci nodes not already covered by MAC
    try:
        base = "/sys/class/bluetooth"
        if os.path.isdir(base):
            known_hci = {a.get("name") for a in adapters}
            for hci in sorted(os.listdir(base)):
                if not hci.startswith("hci"):
                    continue
                if hci in known_hci:
                    continue
                addr_path = os.path.join(base, hci, "address")
                addr = ""
                try:
                    addr = open(addr_path, encoding="utf-8").read().strip().upper()
                except OSError:
                    pass
                if addr and addr in seen:
                    # Same controller under another name — skip
                    continue
                if addr:
                    seen.add(addr)
                elif not addr:
                    # No MAC and no prior entry — still list the hci node
                    pass
                powered, power_note = _ble_power_state(addr or hci)
                adapters.append({
                    "name": hci,
                    "address": addr or "??:??:??:??:??:??",
                    "powered": "yes" if powered else "no",
                    "note": power_note,
                    "alias": hci,
                })
    except Exception as e:
        logger.debug("sysfs ble scan failed: %s", e)

    return adapters


def _ble_hci_for_addr(addr: str) -> str:
    try:
        base = "/sys/class/bluetooth"
        for hci in os.listdir(base):
            try:
                a = open(
                    os.path.join(base, hci, "address"), encoding="utf-8"
                ).read().strip().upper()
            except OSError:
                continue
            if a == (addr or "").upper():
                return hci
    except OSError:
        pass
    return ""


def _ble_power_state(addr_or_hci: str) -> Tuple[bool, str]:
    """Return (powered, note) for a controller."""
    if not shutil.which("bluetoothctl"):
        return False, "bluetoothctl missing"
    try:
        # Prefer show on MAC if it looks like one.
        target = addr_or_hci
        out = subprocess.run(
            ["bluetoothctl", "show", target] if ":" in target
            else ["bluetoothctl", "show"],
            capture_output=True, text=True, timeout=4,
        ).stdout or ""
        powered = False
        blocked = False
        for line in out.splitlines():
            ls = line.strip().lower()
            if ls.startswith("powered:"):
                powered = "yes" in ls
            if "powerstate:" in ls and "blocked" in ls:
                blocked = True
        if blocked and not powered:
            return False, "rfkill/blocked — unblock + power on"
        if not powered:
            return False, "powered off"
        return True, "powered"
    except Exception:
        return False, "unknown"


def ble_power_on(addr: str) -> Dict[str, object]:
    """Best-effort ``bluetoothctl power on`` for ``addr`` (needs root/policy)."""
    if not shutil.which("bluetoothctl"):
        return {"ok": False, "error": "bluetoothctl not installed"}
    try:
        # Select controller then power on.
        script = f"select {addr}\npower on\nshow {addr}\n"
        p = subprocess.run(
            ["bluetoothctl"],
            input=script,
            capture_output=True, text=True, timeout=8,
        )
        powered, note = _ble_power_state(addr)
        return {
            "ok": powered,
            "powered": powered,
            "note": note,
            "stdout": (p.stdout or "")[-500:],
            "error": "" if powered else (note or "power on failed"),
        }
    except Exception as e:
        return {"ok": False, "error": str(e)}


def _maybe_dump_picker_screen(stdscr, title: str = "", extra: str = "") -> None:
    """Write picker frame when ``$KFIOSA_TUI_SCREEN_DUMP`` is set."""
    path = os.environ.get("KFIOSA_TUI_SCREEN_DUMP", "").strip()
    if not path or stdscr is None:
        return
    try:
        h, w = stdscr.getmaxyx()
        lines = [f"## state=picker title={title}", extra] if extra else [
            f"## state=picker title={title}"
        ]
        for y in range(max(0, h)):
            try:
                raw = stdscr.instr(y, 0, max(0, w - 1))
                if isinstance(raw, bytes):
                    raw = raw.decode("utf-8", errors="replace")
                lines.append((raw or "").rstrip())
            except Exception:
                lines.append("")
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
        os.replace(tmp, path)
    except Exception:
        pass


def flush_curses_input(stdscr=None) -> None:
    """Drop any pending keypresses from the curses/terminal input queue.

    Critical after nested pickers and long blocking work (airmon, injection
    probe): the operator often mashes ENTER while waiting, and those keys
    would otherwise re-fire the parent menu handler (e.g. immediately flip
    monitor → managed after a successful iface pick).

    Uses ``curses.flushinp()`` only — do not drain via ``getch()`` here;
    nested pickers may have pre-seeded test doubles, and a getch drain
    would steal the operator's *next* intentional key if timing races.
    ``stdscr`` is accepted for API symmetry with callers; unused.
    """
    del stdscr  # API symmetry; flush is process-global for curses
    try:
        import curses
        curses.flushinp()
    except Exception:
        pass


def _pick(stdscr, activity_log: List[str], title: str,
          items: List[Dict], summary_fn,
          *, help_extra: str = "") -> Optional[str]:
    """Render a small curses picker. Returns the chosen item's ``name``.

    Keys: UP/DOWN move, ENTER select, q cancel.
    Optional ``help_extra`` is appended to the header line.

    Forces blocking input for the duration of the pick so a single ENTER
    selects reliably (the dashboard leaves ``nodelay(True)``). Flushes the
    input queue on entry and exit so leftover keys from the menu ENTER /
    keys mashed during slow ``detect_*`` do not auto-select or bounce
    back into the parent menu.
    """
    import curses
    if not items:
        activity_log.append(f"[!] No {title} detected (is the tool installed?)")
        return None
    idx = 0
    help_line = "UP/DOWN move, ENTER select, q cancel"
    if help_extra:
        help_line = f"{help_line} · {help_extra}"
    result: Optional[str] = None
    try:
        # Drop stale keys (menu ENTER, mashes during detect) before we wait.
        flush_curses_input(stdscr)
        try:
            stdscr.nodelay(False)
            stdscr.timeout(-1)
        except Exception:
            pass
        while True:
            stdscr.erase()
            h, w = stdscr.getmaxyx()
            try:
                stdscr.addstr(0, 2, f" {title} — {help_line} "[: w - 1])
            except curses.error:
                pass
            for i, it in enumerate(items):
                y = 2 + i
                if y >= h - 2:
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
            try:
                stdscr.addstr(
                    min(h - 1, 3 + len(items)), 2,
                    "SPACE=refresh list"[: w - 4],
                )
            except curses.error:
                pass
            stdscr.refresh()
            _maybe_dump_picker_screen(stdscr, title=title)
            try:
                from core.tui.base_screen import read_curses_key
                key = read_curses_key(stdscr)
            except Exception:
                key = stdscr.getch()
            if key == -1:
                continue
            if key in (curses.KEY_UP, ord("k"), ord("K")):
                idx = (idx - 1) % len(items)
            elif key in (curses.KEY_DOWN, ord("j"), ord("J")):
                idx = (idx + 1) % len(items)
            elif key in (curses.KEY_ENTER, 10, 13):
                result = items[idx].get("name")
                break
            elif key in (ord(" "),):
                # Caller may re-detect by returning special token.
                result = "__refresh__"
                break
            elif key in (ord("q"), ord("Q"), 27, curses.KEY_BACKSPACE, 127, 8):
                result = None
                break
    finally:
        # Restore dashboard input mode and drop any key doubles (some
        # terminals emit both CR and LF for one Enter).
        try:
            stdscr.nodelay(True)
            stdscr.timeout(100)
        except Exception:
            pass
        flush_curses_input(stdscr)
    return result


def _wireless_summary(it: Dict[str, object]) -> str:
    """One-line picker label: name, state, current mode, caps, note."""
    name = str(it.get("name") or "")
    state = str(it.get("state") or "?")
    mode = str(it.get("mode") or "?")
    mon = "yes" if it.get("monitor") else "no"
    inj = "yes" if it.get("injection") else "no"
    note = str(it.get("note") or "")
    base = (
        f"{name:12} state={state:4} mode={mode:8} "
        f"mon_cap={mon} inject={inj}"
    )
    if note:
        base = f"{base}  ({note})"
    return base


def _show_detecting(stdscr, label: str) -> None:
    """Brief status while ``detect_*`` runs (can take a second or two)."""
    if stdscr is None:
        return
    try:
        import curses
        stdscr.erase()
        h, w = stdscr.getmaxyx()
        msg = f" {label} — please wait… "
        stdscr.addstr(0, 2, msg[: max(0, w - 1)])
        stdscr.refresh()
    except Exception:
        pass


def pick_wireless_interface(stdscr, activity_log: List[str]) -> Optional[str]:
    """Interactive wireless picker with SPACE=refresh.

    On cancel, auto-selects live monitor → mon-capable → first iface.
    """
    while True:
        _show_detecting(stdscr, "Detecting wireless adapters")
        ifaces = detect_wireless_interfaces()
        # Annotate double-mon risk for display.
        for it in ifaces:
            name = str(it.get("name") or "")
            if re.search(r"monmon|mon{2,}", name, re.I):
                it["note"] = (str(it.get("note") or "") + " DOUBLE-MON name").strip()
        chosen = _pick(
            stdscr, activity_log, "Wireless Adapters",
            ifaces,
            _wireless_summary,
            help_extra="SPACE refresh",
        )
        if chosen == "__refresh__":
            activity_log.append("[i] Refreshing wireless adapter list…")
            continue
        if chosen:
            return str(chosen)
        # Cancel → smart auto-select
        mon_live = next(
            (i["name"] for i in ifaces if i.get("mode") == "monitor"), None
        )
        if mon_live:
            activity_log.append(f"[i] Auto-selected live monitor iface: {mon_live}")
            return str(mon_live)
        mon = next((i["name"] for i in ifaces if i.get("monitor")), None)
        if mon:
            activity_log.append(f"[i] Auto-selected monitor-capable adapter: {mon}")
            return str(mon)
        if ifaces:
            activity_log.append(f"[i] Auto-selected adapter: {ifaces[0]['name']}")
            return str(ifaces[0]["name"])
        return None


def _ble_summary(it: Dict) -> str:
    name = str(it.get("name") or "")
    addr = str(it.get("address") or "")
    powered = str(it.get("powered") or "?")
    note = str(it.get("note") or "")
    alias = str(it.get("alias") or "")
    base = f"{name:8} {addr:17} powered={powered:3}"
    if alias and alias != name:
        base += f"  ({alias})"
    if note and note not in ("powered",):
        base += f"  [{note}]"
    return base


def pick_ble_interface(stdscr, activity_log: List[str]) -> Optional[str]:
    """Interactive BLE picker. On select, attempts ``power on`` if off.

    Returns the hci name (e.g. ``hci0``), or None.
    """
    while True:
        _show_detecting(stdscr, "Detecting Bluetooth adapters")
        adapters = detect_ble_interfaces()
        chosen = _pick(
            stdscr, activity_log, "Bluetooth Adapters",
            adapters,
            _ble_summary,
            help_extra="SPACE refresh · ENTER selects + power on",
        )
        if chosen == "__refresh__":
            activity_log.append("[i] Refreshing BLE adapter list…")
            continue
        if not chosen:
            if adapters:
                # Prefer powered adapter
                for a in adapters:
                    if a.get("powered") == "yes":
                        activity_log.append(
                            f"[i] Auto-selected powered BLE: {a['name']}"
                        )
                        return str(a["name"])
                activity_log.append(
                    f"[i] Auto-selected BLE: {adapters[0]['name']}"
                )
                return str(adapters[0]["name"])
            return None
        # Power on if needed.
        match = next((a for a in adapters if a.get("name") == chosen), None)
        if match and match.get("powered") != "yes" and match.get("address"):
            activity_log.append(
                f"[*] Powering on BLE {match['name']} ({match['address']})…"
            )
            res = ble_power_on(str(match["address"]))
            if res.get("ok"):
                activity_log.append(f"[+] BLE {match['name']} powered on")
            else:
                activity_log.append(
                    f"[!] BLE power on: {res.get('error') or res.get('note')} "
                    f"(try: sudo rfkill unblock bluetooth && "
                    f"bluetoothctl power on)"
                )
        return str(chosen)