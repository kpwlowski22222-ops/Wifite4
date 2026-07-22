#!/usr/bin/env python3
"""Airgeddon / wifite2-style external WiFi scan TUI.

Launched in a separate terminal from the main dashboard so the operator
gets a dedicated scan window:

  - Live / batch scan of APs on the given interface
  - UP/DOWN (or j/k) moves the highlight
  - SPACE / ENTER selects a target
  - ``A`` runs / confirms **AIO ATTACK** intent (written to out JSON)
  - ``r`` rescan, ``q`` quit without selection

Selection is written to ``--out`` as JSON so the parent dashboard can
load the target and run the full AIO chain (recon → CVE/NVD → poly
exploits / 0-day → post-exploit → anti-forensics).
"""
from __future__ import annotations

import argparse
import curses
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional


def _scan_airodump(iface: str, seconds: int = 12) -> List[Dict[str, Any]]:
    """Best-effort airodump-ng CSV scan → list of AP dicts."""
    outdir = Path(os.environ.get("TMPDIR", "/tmp")) / "kfiosa_scan"
    outdir.mkdir(parents=True, exist_ok=True)
    prefix = outdir / f"scan_{int(time.time())}"
    # Clean previous csv for this prefix pattern
    for p in outdir.glob("scan_*.csv"):
        try:
            p.unlink()
        except OSError:
            pass
    cmd = [
        "airodump-ng", "--write-interval", "1",
        "-w", str(prefix), "--output-format", "csv",
        iface,
    ]
    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        time.sleep(max(5, int(seconds)))
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
    except FileNotFoundError:
        return []
    except Exception:
        return []

    csv_path = Path(str(prefix) + "-01.csv")
    if not csv_path.is_file():
        # airodump may use different suffix
        cands = sorted(outdir.glob("scan_*-01.csv"), key=lambda p: p.stat().st_mtime)
        csv_path = cands[-1] if cands else csv_path
    if not csv_path.is_file():
        return []
    return _parse_airodump_csv(csv_path.read_text(encoding="utf-8", errors="replace"))


def _parse_airodump_csv(text: str) -> List[Dict[str, Any]]:
    """Parse airodump-ng CSV (AP section only)."""
    aps: List[Dict[str, Any]] = []
    section = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("BSSID"):
            section = "ap"
            continue
        if line.startswith("Station MAC"):
            section = "sta"
            continue
        if section != "ap":
            continue
        parts = [p.strip() for p in line.split(",")]
        if len(parts) < 14:
            continue
        bssid = parts[0]
        if not bssid or bssid.lower() == "bssid":
            continue
        try:
            channel = int(parts[3]) if parts[3] else 0
        except ValueError:
            channel = 0
        try:
            pwr = int(parts[8]) if parts[8] else 0
        except ValueError:
            pwr = 0
        enc = parts[5] or ""
        cipher = parts[6] or ""
        auth = parts[7] or ""
        ssid = parts[13] if len(parts) > 13 else ""
        encryption = " ".join(x for x in (enc, cipher, auth) if x).strip() or enc
        aps.append({
            "bssid": bssid,
            "ssid": ssid or "<hidden>",
            "channel": channel,
            "power": pwr,
            "encryption": encryption,
            "enc": encryption,
            "cipher": cipher,
            "auth": auth,
        })
    # strongest first
    aps.sort(key=lambda a: a.get("power") or -999, reverse=True)
    return aps


def _scan_fallback(iface: str, seconds: int = 10) -> List[Dict[str, Any]]:
    """Use EnhancedWiFiScanner / iw when airodump unavailable."""
    try:
        # Ensure project root on path
        root = Path(__file__).resolve().parents[2]
        if str(root) not in sys.path:
            sys.path.insert(0, str(root))
        from core.scanners.enhanced_wifi_scanner import EnhancedWiFiScanner
        sc = EnhancedWiFiScanner()
        if hasattr(sc, "initialize"):
            sc.initialize()
        data = sc.scan(iface, timeout=seconds)
        return list(data.get("networks") or [])
    except Exception:
        pass
    # Last resort: iw dev scan (needs managed + root often)
    try:
        r = subprocess.run(
            ["iw", "dev", iface, "scan"],
            capture_output=True, text=True, timeout=seconds + 5,
        )
        aps: List[Dict[str, Any]] = []
        cur: Dict[str, Any] = {}
        for line in (r.stdout or "").splitlines():
            line = line.strip()
            if line.startswith("BSS "):
                if cur.get("bssid"):
                    aps.append(cur)
                bssid = line.split()[1].split("(")[0]
                cur = {"bssid": bssid, "ssid": "<hidden>", "channel": 0,
                       "encryption": "?", "power": 0}
            elif line.startswith("SSID:"):
                cur["ssid"] = line.split(":", 1)[-1].strip() or "<hidden>"
            elif "primary channel:" in line:
                try:
                    cur["channel"] = int(line.split(":")[-1].strip())
                except ValueError:
                    pass
            elif "signal:" in line:
                try:
                    # signal: -42.00 dBm
                    cur["power"] = int(float(line.split("signal:")[-1].split()[0]))
                except (ValueError, IndexError):
                    pass
            elif "WPA3" in line or "SAE" in line:
                cur["encryption"] = "WPA3-SAE"
            elif "WPA2" in line and "WPA3" not in (cur.get("encryption") or ""):
                cur["encryption"] = "WPA2"
        if cur.get("bssid"):
            aps.append(cur)
        return aps
    except Exception:
        return []


def scan_networks(iface: str, seconds: int = 12) -> List[Dict[str, Any]]:
    aps = _scan_airodump(iface, seconds=seconds)
    if not aps:
        aps = _scan_fallback(iface, seconds=min(seconds, 10))
    return aps


def _write_selection(
    out_path: Path,
    target: Optional[Dict[str, Any]],
    *,
    aio: bool = False,
    networks: Optional[List[Dict[str, Any]]] = None,
) -> None:
    payload = {
        "ts": time.time(),
        "selected": target,
        "aio_attack": bool(aio),
        "networks": networks or [],
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def run_curses(
    stdscr,
    iface: str,
    out_path: Path,
    seconds: int = 12,
) -> int:
    curses.curs_set(0)
    stdscr.nodelay(False)
    stdscr.keypad(True)
    if curses.has_colors():
        curses.start_color()
        curses.use_default_colors()
        curses.init_pair(1, curses.COLOR_GREEN, -1)
        curses.init_pair(2, curses.COLOR_YELLOW, -1)
        curses.init_pair(3, curses.COLOR_CYAN, -1)
        curses.init_pair(4, curses.COLOR_RED, -1)

    networks: List[Dict[str, Any]] = []
    idx = 0
    selected: Optional[Dict[str, Any]] = None
    status = f"Scanning {iface} ({seconds}s)…"
    message = ""

    def do_scan():
        nonlocal networks, idx, status, message
        status = f"Scanning {iface}…"
        stdscr.erase()
        h, w = stdscr.getmaxyx()
        stdscr.addstr(0, 2, " KFIOSA WiFi Scan (airgeddon/wifite style) "[: w - 1],
                      curses.color_pair(3) | curses.A_BOLD)
        stdscr.addstr(2, 2, status[: w - 4])
        stdscr.refresh()
        networks = scan_networks(iface, seconds=seconds)
        idx = 0
        status = f"{len(networks)} AP(s) on {iface}"
        message = "↑↓ move  SPACE/ENTER select  A = AIO ATTACK  r rescan  q quit"

    do_scan()

    while True:
        stdscr.erase()
        h, w = stdscr.getmaxyx()
        title = " KFIOSA · Wireless Scan · airgeddon/wifite-like "
        try:
            stdscr.addstr(0, 2, title[: w - 3],
                          curses.color_pair(3) | curses.A_BOLD)
            stdscr.addstr(1, 2, status[: w - 4], curses.color_pair(2))
            if message:
                stdscr.addstr(2, 2, message[: w - 4])
        except curses.error:
            pass

        # AP list
        top = 4
        view = max(1, h - top - 6)
        start = max(0, min(idx - view // 2, max(0, len(networks) - view)))
        for row, i in enumerate(range(start, min(start + view, len(networks)))):
            ap = networks[i]
            ssid = (ap.get("ssid") or "<hidden>")[:18]
            bssid = (ap.get("bssid") or "?")[:17]
            ch = str(ap.get("channel") or "?")
            enc = (ap.get("encryption") or ap.get("enc") or "?")[:16]
            pwr = str(ap.get("power") if ap.get("power") is not None else "?")
            mark = "▶" if i == idx else " "
            sel = "*" if selected and selected.get("bssid") == ap.get("bssid") else " "
            line = f"{mark}{sel} {ssid:18} {bssid:17} CH{ch:>3} {pwr:>4}dBm  {enc}"
            y = top + row
            if y >= h - 5:
                break
            attr = curses.A_REVERSE if i == idx else curses.A_NORMAL
            try:
                stdscr.addstr(y, 2, line[: w - 4], attr)
            except curses.error:
                pass

        # Footer / AIO panel
        fy = h - 4
        try:
            if selected:
                s = selected
                stdscr.addstr(
                    fy, 2,
                    (f"SELECTED: {s.get('ssid')} [{s.get('bssid')}] "
                     f"{s.get('encryption') or s.get('enc')}")[: w - 4],
                    curses.color_pair(1) | curses.A_BOLD,
                )
                stdscr.addstr(
                    fy + 1, 2,
                    ("[A] AIO ATTACK = recon + CVE/NVD + poly exploits + "
                     "0-day (if needed) + post-exploit + anti-forensics")[: w - 4],
                    curses.color_pair(2),
                )
            else:
                stdscr.addstr(fy, 2, "No target selected yet."[: w - 4])
            stdscr.addstr(
                fy + 2, 2,
                "ENTER/SPACE select · A AIO ATTACK · r rescan · q cancel"[: w - 4],
            )
        except curses.error:
            pass

        stdscr.refresh()
        key = stdscr.getch()
        if key in (curses.KEY_UP, ord("k")):
            if networks:
                idx = (idx - 1) % len(networks)
        elif key in (curses.KEY_DOWN, ord("j")):
            if networks:
                idx = (idx + 1) % len(networks)
        elif key in (curses.KEY_ENTER, 10, 13, ord(" ")):
            if networks:
                selected = dict(networks[idx])
                _write_selection(out_path, selected, aio=False, networks=networks)
                message = f"Selected {selected.get('ssid')} — press A for AIO ATTACK or q to return"
        elif key in (ord("a"), ord("A")):
            if not selected and networks:
                selected = dict(networks[idx])
            if not selected:
                message = "Select a target first (ENTER/SPACE)"
                continue
            _write_selection(out_path, selected, aio=True, networks=networks)
            message = "AIO ATTACK queued — closing window…"
            stdscr.refresh()
            time.sleep(0.4)
            return 0
        elif key in (ord("r"), ord("R")):
            do_scan()
        elif key in (ord("q"), ord("Q"), 27):
            if selected:
                _write_selection(out_path, selected, aio=False, networks=networks)
            else:
                _write_selection(out_path, None, aio=False, networks=networks)
            return 0
    return 0


def run_text_ui(
    iface: str,
    out_path: Path,
    seconds: int = 12,
) -> int:
    """Non-curses fallback when stdin/stdout is not a real TTY.

    Avoids ``curses.error: endwin()/nocbreak() returned ERR`` which is
    what the operator hit when the scan window was launched into a
    dumb/non-tty context (or nested under another curses app).
    """
    print("=" * 60)
    print(" KFIOSA WiFi Scan (text mode — no curses TTY)")
    print(f" Interface: {iface}  duration≈{seconds}s")
    print("=" * 60)
    print("[*] Scanning…")
    networks = scan_networks(iface, seconds=seconds)
    if not networks:
        print("[!] No APs found.")
        _write_selection(out_path, None, aio=False, networks=[])
        return 1
    print(f"[+] {len(networks)} AP(s):\n")
    for i, ap in enumerate(networks):
        print(
            f"  {i + 1:3d}. {(ap.get('ssid') or '<hidden>'):20s} "
            f"{(ap.get('bssid') or '?'):17s} "
            f"CH{ap.get('channel') or '?':>3}  "
            f"{ap.get('encryption') or ap.get('enc') or '?'}"
        )
    print()
    print("Enter number to select, 'A <n>' for AIO ATTACK, or q to quit.")
    selected = None
    aio = False
    while True:
        try:
            raw = input("> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not raw or raw.lower() in ("q", "quit", "exit"):
            break
        if raw.lower().startswith("a"):
            parts = raw.split()
            try:
                n = int(parts[1]) if len(parts) > 1 else 1
            except ValueError:
                print("usage: A <number>")
                continue
            if 1 <= n <= len(networks):
                selected = dict(networks[n - 1])
                aio = True
                print(f"[AIO] {selected.get('ssid')} [{selected.get('bssid')}]")
                break
            print("out of range")
            continue
        try:
            n = int(raw)
        except ValueError:
            print("enter a number, A <n>, or q")
            continue
        if 1 <= n <= len(networks):
            selected = dict(networks[n - 1])
            print(f"[+] Selected {selected.get('ssid')} — "
                  f"type A {n} for AIO or q to save & quit")
            # allow AIO on next line or just save
            continue
        print("out of range")
    _write_selection(out_path, selected, aio=aio, networks=networks)
    if selected:
        print(f"[+] Wrote selection → {out_path}  aio={aio}")
    else:
        print(f"[i] No selection written (empty) → {out_path}")
    return 0


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
        print(f"[!] curses UI unavailable ({e}); falling back to text mode.",
              file=sys.stderr)
        # args: iface, out_path, seconds
        if len(args) >= 2:
            return run_text_ui(args[0], args[1],
                               args[2] if len(args) > 2 else 12)
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
                # The operator's screenshot: endwin() returned ERR —
                # swallow so the process exits cleanly with selection written.
                pass


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--iface", required=True, help="Wireless interface (monitor preferred)")
    ap.add_argument(
        "--out",
        default=str(Path("logs") / "wifi_scan_selection.json"),
        help="JSON path for selection + aio_attack flag",
    )
    ap.add_argument("--seconds", type=int, default=12, help="Scan duration")
    ap.add_argument(
        "--text", action="store_true",
        help="Force text UI (no curses); also auto if not a TTY",
    )
    args = ap.parse_args(argv)
    out_path = Path(args.out)

    use_text = bool(args.text)
    if not use_text:
        # Auto text when not an interactive terminal (nested curses / dumb TERM).
        try:
            use_text = not (sys.stdin.isatty() and sys.stdout.isatty())
        except Exception:
            use_text = True
        term = (os.environ.get("TERM") or "").lower()
        if term in ("", "dumb", "unknown"):
            use_text = True

    if use_text:
        return run_text_ui(args.iface, out_path, args.seconds)
    return _curses_safe_wrapper(run_curses, args.iface, out_path, args.seconds)


if __name__ == "__main__":
    raise SystemExit(main())
