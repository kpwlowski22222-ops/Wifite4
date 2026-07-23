#!/usr/bin/env python3
"""Airgeddon / wifite2-style external WiFi scan TUI.

Launched in a separate terminal from the main dashboard so the operator
gets a dedicated scan window:

  - Live-time updating scanning of APs on the given interface
  - Table Above: APs online (active in live scan), navigable by arrows,
    ENTER / SPACEBAR selects target
  - Table Under: APs disappeared (previously seen during scanning), preserving
    all fetched recon info (OUI Vendor, client count, signal, last seen)
  - TAB switches focus between tables
  - ``A`` runs / confirms **AIO ATTACK** intent (written to out JSON)
  - ``r`` rescan/reset, ``q`` quit without selection
"""
from __future__ import annotations

import argparse
import curses
import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

_OUI_VENDORS: Dict[str, str] = {
    "00:1A:E9": "TP-Link", "50:C7:BF": "TP-Link", "74:DA:38": "TP-Link",
    "C0:25:E9": "TP-Link", "E8:48:B8": "TP-Link", "EC:08:6B": "TP-Link",
    "00:14:D1": "Netgear", "00:1F:A4": "Netgear", "10:0C:6B": "Netgear",
    "20:4E:71": "Netgear", "E0:46:9A": "Netgear", "A4:2B:8C": "Netgear",
    "00:1D:7E": "Cisco-Linksys", "00:25:9C": "Cisco-Linksys", "00:18:B9": "Cisco",
    "00:21:6A": "Cisco", "C4:72:95": "Cisco", "E0:D1:73": "Cisco",
    "00:1E:58": "D-Link", "00:26:5A": "D-Link", "1C:7E:E5": "D-Link",
    "C8:D3:FF": "D-Link", "28:10:7B": "D-Link",
    "00:0F:66": "ASUS", "00:1E:62": "ASUS", "00:24:8C": "ASUS",
    "04:D4:C4": "ASUS", "2C:4D:54": "ASUS", "38:D5:47": "ASUS", "10:7C:61": "ASUS",
    "00:01:E6": "Ubiquiti", "00:15:6D": "Ubiquiti", "00:27:22": "Ubiquiti",
    "04:18:D6": "Ubiquiti", "18:E8:29": "Ubiquiti", "24:A4:3C": "Ubiquiti",
    "68:72:51": "Ubiquiti", "78:8A:20": "Ubiquiti", "B4:FB:E4": "Ubiquiti",
    "DC:9F:DB": "Ubiquiti", "F4:92:BF": "Ubiquiti",
    "00:0C:42": "MikroTik", "4C:5E:0C": "MikroTik", "64:D1:54": "MikroTik",
    "B8:69:F4": "MikroTik", "CC:2D:E0": "MikroTik", "D4:CA:6D": "MikroTik",
    "E8:28:C1": "MikroTik",
    "00:CD:FE": "Apple", "00:17:F2": "Apple", "00:1C:B3": "Apple",
    "00:1D:4F": "Apple", "00:1E:C2": "Apple", "00:1F:5B": "Apple",
    "00:21:E9": "Apple", "00:22:41": "Apple", "00:23:12": "Apple",
    "00:24:36": "Apple", "00:25:00": "Apple", "00:26:08": "Apple",
    "00:26:4A": "Apple", "A4:83:E7": "Apple", "AC:BC:32": "Apple",
    "F0:18:98": "Apple",
    "00:21:70": "Intel", "00:24:D7": "Intel", "00:26:C7": "Intel",
    "00:1E:64": "Intel", "3C:A9:F4": "Intel", "48:51:B7": "Intel",
    "60:57:18": "Intel",
    "00:05:9E": "Cisco", "00:16:3E": "Xen", "00:E0:4C": "Realtek",
    "00:10:A4": "Xircom", "52:54:00": "QEMU/KVM", "08:00:27": "VirtualBox",
    "00:0C:29": "VMware", "00:50:56": "VMware",
    "00:0D:F0": "Huawei", "00:1B:11": "Huawei", "00:1E:10": "Huawei",
    "08:19:A6": "Huawei", "24:7F:20": "Huawei",
    "00:12:BF": "Technicolor", "00:1F:33": "Technicolor", "00:26:E8": "Technicolor",
    "28:6C:07": "Technicolor", "34:80:B4": "Technicolor",
    "00:1A:2B": "Arcadyan", "00:24:D4": "Arcadyan", "00:26:55": "Arcadyan",
    "34:6B:D3": "Arcadyan", "44:33:4C": "Arcadyan", "64:09:80": "Arcadyan",
}


def _get_oui_vendor(mac: str) -> str:
    if not mac or len(mac) < 8:
        return "Unknown"
    prefix = mac.upper()[:8]
    if prefix in _OUI_VENDORS:
        return _OUI_VENDORS[prefix]
    try:
        from core.ble.runner import _oui_vendor
        v = _oui_vendor(mac)
        if v and v != "Unknown":
            return v
    except Exception:
        pass
    return "Unknown OUI"


def _parse_airodump_csv_live(
    text: str,
) -> Tuple[Dict[str, Dict[str, Any]], Dict[str, List[str]]]:
    """Parse airodump-ng CSV into AP dict map and BSSID -> client MAC list map."""
    aps: Dict[str, Dict[str, Any]] = {}
    clients: Dict[str, List[str]] = {}
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
        parts = [p.strip() for p in line.split(",")]
        if section == "ap" and len(parts) >= 14:
            bssid = parts[0]
            if not bssid or bssid.lower() == "bssid":
                continue
            bssid = bssid.upper()
            try:
                channel = int(parts[3]) if parts[3] else 0
            except ValueError:
                channel = 0
            try:
                pwr = int(parts[8]) if parts[8] else 0
            except ValueError:
                pwr = 0
            try:
                beacons = int(parts[9]) if parts[9] else 0
            except ValueError:
                beacons = 0
            enc = parts[5] or ""
            cipher = parts[6] or ""
            auth = parts[7] or ""
            ssid = parts[13] if len(parts) > 13 else ""
            encryption = " ".join(x for x in (enc, cipher, auth) if x).strip() or enc
            aps[bssid] = {
                "bssid": bssid,
                "ssid": ssid or "<hidden>",
                "channel": channel,
                "power": pwr,
                "beacons": beacons,
                "encryption": encryption,
                "enc": encryption,
                "cipher": cipher,
                "auth": auth,
            }
        elif section == "sta" and len(parts) >= 6:
            sta_mac = parts[0]
            ap_bssid = parts[5]
            if (
                sta_mac
                and ap_bssid
                and ap_bssid.lower() not in ("bssid", "(not associated)")
            ):
                ap_bssid = ap_bssid.upper()
                if ap_bssid not in clients:
                    clients[ap_bssid] = []
                if sta_mac not in clients[ap_bssid]:
                    clients[ap_bssid].append(sta_mac)
    return aps, clients


def _parse_airodump_csv(text: str) -> List[Dict[str, Any]]:
    aps_map, _ = _parse_airodump_csv_live(text)
    aps = list(aps_map.values())
    aps.sort(key=lambda a: a.get("power") or -999, reverse=True)
    return aps


def _scan_airodump_oneshot(iface: str, seconds: int = 12) -> List[Dict[str, Any]]:
    """One-shot airodump-ng CSV scan with multi-band hop (no live UI)."""
    seconds = max(3, int(seconds))
    outdir = Path(os.environ.get("TMPDIR", "/tmp")) / "kfiosa_scan"
    outdir.mkdir(parents=True, exist_ok=True)
    prefix = str(outdir / f"oneshot_{int(time.time())}_{os.getpid()}")
    # Prefer multi-band; fall back if flag unsupported.
    variants = [
        [
            "airodump-ng", iface,
            "--write-interval", "1",
            "-w", prefix,
            "--output-format", "csv",
            "--berlin", str(max(seconds, 120)),
            "--band", "abg",
        ],
        [
            "airodump-ng", iface,
            "--write-interval", "1",
            "-w", prefix,
            "--output-format", "csv",
            "--berlin", str(max(seconds, 120)),
        ],
    ]
    last_err = ""
    for cmd in variants:
        try:
            subprocess.run(
                cmd, capture_output=True, text=True, timeout=seconds + 8,
            )
            last_err = ""
            break
        except subprocess.TimeoutExpired:
            last_err = ""
            break
        except FileNotFoundError:
            return []
        except Exception as e:
            last_err = str(e)
            continue
    if last_err:
        return []
    csv_path = Path(prefix + "-01.csv")
    if not csv_path.is_file():
        cands = sorted(outdir.glob("oneshot_*-01.csv"), key=lambda p: p.stat().st_mtime)
        if cands:
            csv_path = cands[-1]
    if not csv_path.is_file():
        return []
    try:
        return _parse_airodump_csv(
            csv_path.read_text(encoding="utf-8", errors="replace")
        )
    except Exception:
        return []


def _scan_airodump(iface: str, seconds: int = 12) -> List[Dict[str, Any]]:
    """Live-scanner wrapper for one-shot callers (with oneshot fallback)."""
    scanner = LiveScanner(iface, disappeared_timeout=8.0)
    scanner.start()
    try:
        # Wait for airodump CSV to populate; health-check falls back inside.
        time.sleep(max(3, int(seconds)))
        online, disappeared = scanner.poll()
        aps = online + disappeared
        if aps:
            return aps
    finally:
        scanner.stop()
    # Direct oneshot retry (covers airodump Popen that silently failed)
    return _scan_airodump_oneshot(iface, seconds=seconds)


def _scan_fallback(iface: str, seconds: int = 10) -> List[Dict[str, Any]]:
    """Use EnhancedWiFiScanner / iw when airodump unavailable or empty."""
    try:
        root = Path(__file__).resolve().parents[2]
        if str(root) not in sys.path:
            sys.path.insert(0, str(root))
        from core.scanners.enhanced_wifi_scanner import EnhancedWiFiScanner
        sc = EnhancedWiFiScanner()
        if hasattr(sc, "initialize"):
            sc.initialize()
        data = sc.scan(iface, timeout=min(int(seconds), 60))
        nets = list(data.get("networks") or [])
        if nets:
            return nets
    except Exception:
        pass
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
                bssid = line.split()[1].split("(")[0].upper()
                cur = {
                    "bssid": bssid, "ssid": "<hidden>", "channel": 0,
                    "encryption": "?", "power": 0,
                }
            elif line.startswith("SSID:"):
                cur["ssid"] = line.split(":", 1)[-1].strip() or "<hidden>"
            elif "primary channel:" in line:
                try:
                    cur["channel"] = int(line.split(":")[-1].strip())
                except ValueError:
                    pass
            elif "signal:" in line:
                try:
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
    """Scan with prep → airodump → fallback. Never fabricates APs."""
    scan_iface = iface
    try:
        from core.scanners.wifi_radio import prep_for_wifi_scan
        prep = prep_for_wifi_scan(iface, kill_interferers=True, collapse_dups=True)
        if prep.get("ok") and prep.get("interface"):
            scan_iface = prep["interface"]
        elif prep.get("notes"):
            pass  # non-fatal notes
    except Exception:
        pass
    aps = _scan_airodump(scan_iface, seconds=seconds)
    if not aps:
        aps = _scan_airodump_oneshot(scan_iface, seconds=seconds)
    if not aps:
        aps = _scan_fallback(scan_iface, seconds=min(seconds, 15))
    return aps


class LiveScanner:
    """Manages live background WiFi scanning via airodump-ng or fallback scanner.

    Also runs a polymorphic :class:`LiveTargetEnricher` so each AP accumulates
    vendor / PMF / hidden-SSID / WPS / client OUI data while the UI is open.
    """

    def __init__(self, iface: str, disappeared_timeout: float = 6.0):
        self.iface = iface
        self.disappeared_timeout = disappeared_timeout
        self.proc: Optional[subprocess.Popen] = None
        self.outdir = Path(os.environ.get("TMPDIR", "/tmp")) / "kfiosa_scan"
        self.prefix: Optional[Path] = None
        self.ap_catalog: Dict[str, Dict[str, Any]] = {}
        self.last_seen_ts: Dict[str, float] = {}
        self._thread: Optional[threading.Thread] = None
        self._health_thread: Optional[threading.Thread] = None
        self._running = False
        self._is_airodump = False
        self.last_error: str = ""
        self.prep_notes: List[str] = []
        self._stderr_path: Optional[Path] = None
        self._stderr_fh: Optional[Any] = None
        self._catalog_lock = threading.RLock()
        self._enricher: Optional[Any] = None

    def start(self) -> None:
        self._running = True
        self.last_error = ""
        self.outdir.mkdir(parents=True, exist_ok=True)
        for p in self.outdir.glob("live_scan_*.csv"):
            try:
                p.unlink()
            except OSError:
                pass

        # Radio pre-flight: kill NM, collapse dual mon, ensure monitor.
        try:
            from core.scanners.wifi_radio import prep_for_wifi_scan
            prep = prep_for_wifi_scan(
                self.iface, kill_interferers=True, collapse_dups=True,
            )
            self.prep_notes = list(prep.get("notes") or [])
            if prep.get("ok") and prep.get("interface"):
                self.iface = prep["interface"]
            elif prep.get("error"):
                self.last_error = str(prep["error"])
                self.prep_notes.append(self.last_error)
        except Exception as e:
            self.prep_notes.append(f"prep skipped: {e}")

        self.prefix = self.outdir / f"live_scan_{int(time.time())}_{os.getpid()}"
        self._stderr_path = self.outdir / f"{self.prefix.name}.err"
        # Polymorphic live recon (hidden SSID, WPS, OUI, flags) in background
        try:
            from core.scanners.live_enrich import LiveTargetEnricher

            def _targets() -> List[Dict[str, Any]]:
                with self._catalog_lock:
                    return list(self.ap_catalog.values())

            self._enricher = LiveTargetEnricher(
                domain="wifi",
                interface=str(self.iface or ""),
                get_targets=_targets,
                deep_interval_s=5.0,
                max_deep_per_tick=1,
            )
            self._enricher.start()
        except Exception as e:
            self.prep_notes.append(f"live enrich off: {e}")
            self._enricher = None
        berlin = 300
        cmd_variants = [
            [
                "airodump-ng", self.iface,
                "--write-interval", "1",
                "-w", str(self.prefix),
                "--output-format", "csv",
                "--berlin", str(berlin),
                "--band", "abg",
            ],
            [
                "airodump-ng", self.iface,
                "--write-interval", "1",
                "-w", str(self.prefix),
                "--output-format", "csv",
                "--berlin", str(berlin),
            ],
        ]

        started = False
        for cmd in cmd_variants:
            try:
                # Keep the stderr handle open until the process is stopped;
                # closing it immediately after Popen can lose diagnostics.
                self._stderr_fh = open(self._stderr_path, "w", encoding="utf-8")
                self.proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.DEVNULL,
                    stderr=self._stderr_fh,
                )
                # Brief health check: if airodump dies instantly, try next
                # variant / fallback (missing root, bad iface, bad flags).
                time.sleep(0.35)
                rc = self.proc.poll()
                if rc is not None:
                    err_txt = ""
                    try:
                        err_txt = (
                            self._stderr_path.read_text(encoding="utf-8",
                                                        errors="replace")[-400:]
                        )
                    except Exception:
                        pass
                    self.last_error = (
                        f"airodump exited rc={rc}"
                        + (f": {err_txt.strip()}" if err_txt.strip() else "")
                    )
                    self.proc = None
                    # Close the failed variant's stderr handle before trying
                    # the next command variant.
                    if self._stderr_fh:
                        try:
                            self._stderr_fh.close()
                        except Exception:
                            pass
                        self._stderr_fh = None
                    continue
                self._is_airodump = True
                started = True
                break
            except FileNotFoundError:
                self.last_error = "airodump-ng not found — install aircrack-ng"
                self.proc = None
                if self._stderr_fh:
                    try:
                        self._stderr_fh.close()
                    except Exception:
                        pass
                    self._stderr_fh = None
                break
            except (PermissionError, OSError) as e:
                self.last_error = f"airodump spawn: {e}"
                self.proc = None
                if self._stderr_fh:
                    try:
                        self._stderr_fh.close()
                    except Exception:
                        pass
                    self._stderr_fh = None
                continue

        if not started:
            self._is_airodump = False
            self._thread = threading.Thread(target=self._fallback_loop, daemon=True)
            self._thread.start()
        else:
            # Watchdog: if airodump dies mid-run or never writes APs, flip
            # to fallback so the operator still gets results.
            self._health_thread = threading.Thread(
                target=self._airodump_watchdog, daemon=True,
            )
            self._health_thread.start()

    def _airodump_watchdog(self) -> None:
        """After a grace period, if no APs and process dead → fallback."""
        grace = 4.0
        time.sleep(grace)
        if not self._running or not self._is_airodump:
            return
        dead = self.proc is None or self.proc.poll() is not None
        # Peek CSV for any BSSID rows
        has_aps = False
        if self.prefix:
            csv_path = Path(str(self.prefix) + "-01.csv")
            if csv_path.is_file():
                try:
                    text = csv_path.read_text(encoding="utf-8", errors="replace")
                    aps, _ = _parse_airodump_csv_live(text)
                    has_aps = bool(aps)
                except Exception:
                    pass
        if dead and not has_aps:
            self._is_airodump = False
            if not self.last_error:
                self.last_error = "airodump died without APs — using fallback"
            self._thread = threading.Thread(target=self._fallback_loop, daemon=True)
            self._thread.start()
        # If airodump is still alive but empty, leave it alone — multi-band
        # hop needs time. A second concurrent airodump would steal the radio.

    def _fallback_loop(self) -> None:
        while self._running:
            try:
                aps = _scan_airodump_oneshot(self.iface, seconds=5)
                if not aps:
                    aps = _scan_fallback(self.iface, seconds=4)
                now = time.time()
                for ap in aps:
                    bssid = ap.get("bssid")
                    if bssid:
                        self._merge_ap(str(bssid).upper(), ap, now)
            except Exception:
                pass
            time.sleep(3)

    def _merge_ap(self, bssid: str, ap: Dict[str, Any], now: float) -> None:
        bssid_upper = bssid.upper()
        with self._catalog_lock:
            if bssid_upper not in self.ap_catalog:
                vendor = _get_oui_vendor(bssid_upper)
                ap["vendor"] = vendor
                ap["first_seen_ts"] = now
                ap["bssid"] = bssid_upper
                try:
                    from core.scanners.live_enrich import passive_enrich_wifi
                    passive_enrich_wifi(ap)
                except Exception:
                    pass
                self.ap_catalog[bssid_upper] = ap
            else:
                cur = self.ap_catalog[bssid_upper]
                # Never overwrite a revealed SSID with <hidden>
                if ap.get("ssid") and ap.get("ssid") != "<hidden>":
                    cur["ssid"] = ap["ssid"]
                if ap.get("channel"):
                    cur["channel"] = ap["channel"]
                if ap.get("power"):
                    cur["power"] = ap["power"]
                if ap.get("encryption"):
                    cur["encryption"] = ap["encryption"]
                    cur["enc"] = ap["encryption"]
                if "clients" in ap:
                    cur["clients"] = ap["clients"]
                    cur["clients_count"] = ap["clients_count"]
                if ap.get("beacons"):
                    cur["beacons"] = ap["beacons"]
                try:
                    from core.scanners.live_enrich import passive_enrich_wifi
                    passive_enrich_wifi(cur)
                except Exception:
                    pass
            self.last_seen_ts[bssid_upper] = now

    def poll(self) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        now = time.time()
        if self._is_airodump and self.prefix:
            csv_path = Path(str(self.prefix) + "-01.csv")
            if not csv_path.is_file():
                cands = sorted(
                    self.outdir.glob("live_scan_*-01.csv"),
                    key=lambda p: p.stat().st_mtime,
                )
                if cands:
                    csv_path = cands[-1]
            if csv_path.is_file():
                try:
                    text = csv_path.read_text(encoding="utf-8", errors="replace")
                    parsed_aps, clients_map = _parse_airodump_csv_live(text)
                    for bssid, ap in parsed_aps.items():
                        ap["clients"] = clients_map.get(bssid, [])
                        ap["clients_count"] = len(ap["clients"])
                        self._merge_ap(bssid, ap, now)
                except Exception:
                    pass

        online_aps: List[Dict[str, Any]] = []
        disappeared_aps: List[Dict[str, Any]] = []

        with self._catalog_lock:
            items = list(self.ap_catalog.items())
        for bssid, ap in items:
            last_ts = self.last_seen_ts.get(bssid, 0.0)
            ago = max(0, int(now - last_ts))
            ap["last_seen_ago"] = f"{ago}s ago"
            ap["last_seen_ts"] = last_ts
            vendor = ap.get("vendor") or _get_oui_vendor(bssid)
            ap["vendor"] = vendor
            try:
                from core.scanners.live_enrich import passive_enrich_wifi
                passive_enrich_wifi(ap)
            except Exception:
                pass
            ap["recon_info"] = {
                "vendor": vendor,
                "clients_count": len(ap.get("clients") or []),
                "clients": ap.get("clients") or [],
                "beacons": ap.get("beacons") or 0,
                "last_seen_ago": ap["last_seen_ago"],
                "badges": list(ap.get("recon_badges") or []),
                "enrich_methods": list(ap.get("enrich_methods") or []),
                "revealed_ssid": ap.get("revealed_ssid"),
                "hidden": ap.get("hidden"),
                "pmf": ap.get("pmf") or ap.get("pmf_supported"),
                "band": ap.get("band"),
                "wps_enabled": ap.get("wps_enabled"),
            }
            if (now - last_ts) <= self.disappeared_timeout:
                ap["status"] = "online"
                online_aps.append(ap)
            else:
                ap["status"] = "disappeared"
                disappeared_aps.append(ap)

        online_aps.sort(key=lambda a: a.get("power") or -999, reverse=True)
        disappeared_aps.sort(
            key=lambda a: a.get("last_seen_ts") or 0.0, reverse=True
        )
        return online_aps, disappeared_aps

    def stop(self) -> None:
        self._running = False
        try:
            if self._enricher is not None:
                self._enricher.stop()
        except Exception:
            pass
        self._enricher = None
        if self.proc:
            try:
                self.proc.terminate()
                self.proc.wait(timeout=2)
            except Exception:
                try:
                    self.proc.kill()
                except Exception:
                    pass
            self.proc = None
        if self._stderr_fh:
            try:
                self._stderr_fh.close()
            except Exception:
                pass
            self._stderr_fh = None


def _write_selection(
    out_path: Path,
    target: Optional[Dict[str, Any]],
    *,
    aio: bool = False,
    networks: Optional[List[Dict[str, Any]]] = None,
    disappeared_networks: Optional[List[Dict[str, Any]]] = None,
) -> None:
    payload = {
        "ts": time.time(),
        "selected": target,
        "aio_attack": bool(aio),
        "networks": networks or [],
        "disappeared_networks": disappeared_networks or [],
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def run_curses(
    stdscr,
    iface: str,
    out_path: Path,
    seconds: int = 12,
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

    # Long-range: keep disappeared APs on screen far longer so the
    # operator sees everything that went offline during the sweep.
    disappeared_timeout = 60.0 if long_range else 20.0
    scanner = LiveScanner(iface, disappeared_timeout=disappeared_timeout)
    scanner.start()

    active_table = "online"  # "online" or "disappeared"
    online_idx = 0
    disappeared_idx = 0
    selected: Optional[Dict[str, Any]] = None
    # BSSID whose associated clients are shown in the expand panel (`c`).
    clients_view_ap: Optional[str] = None
    status = f"Live scanning {iface}…"
    message = "↑/↓ move · TAB switch table · ENTER/SPACE select · A AIO · c clients · r rescan · q quit"

    try:
        while True:
            online_aps, disappeared_aps = scanner.poll()

            # Bound cursor indices safely
            if online_aps:
                online_idx = max(0, min(online_idx, len(online_aps) - 1))
            else:
                online_idx = 0

            if disappeared_aps:
                disappeared_idx = max(
                    0, min(disappeared_idx, len(disappeared_aps) - 1)
                )
            else:
                disappeared_idx = 0

            stdscr.erase()
            h, w = stdscr.getmaxyx()
            title = f" KFIOSA · Wireless Scan (Live-Time Updating) · {iface} "
            try:
                stdscr.addstr(
                    0, 2, title[: w - 3], curses.color_pair(3) | curses.A_BOLD
                )
                stat_str = (
                    f"Status: Live-scanning | Online APs: {len(online_aps)} | "
                    f"Disappeared APs: {len(disappeared_aps)}"
                )
                stdscr.addstr(1, 2, stat_str[: w - 4], curses.color_pair(2))
                stdscr.addstr(2, 2, message[: w - 4])
            except curses.error:
                pass

            avail_h = max(4, h - 9)
            # Reserve a clients-expand panel at the bottom when active.
            panel_h = 10 if clients_view_ap else 0
            avail_h = max(4, h - 9 - panel_h)
            if disappeared_aps:
                h_online = max(3, (avail_h * 6) // 10)
                h_disappeared = max(3, avail_h - h_online)
            else:
                h_online = avail_h
                h_disappeared = 0

            # --- TABLE ABOVE: ONLINE APs ---
            top1 = 3
            try:
                focus_hdr = (
                    curses.color_pair(1) | curses.A_BOLD
                    if active_table == "online"
                    else curses.A_DIM
                )
                hdr1 = f"── TABLE ABOVE: ONLINE APs ({len(online_aps)}) [moving by arrows, enter/spacebar to select] ──"
                stdscr.addstr(top1, 2, hdr1[: w - 4], focus_hdr)
                col_hdr1 = "   SSID                 BSSID             CH   PWR    ENC             CLIENTS  VENDOR"
                stdscr.addstr(
                    top1 + 1, 2, col_hdr1[: w - 4], curses.A_UNDERLINE
                )
            except curses.error:
                pass

            v_online = max(1, h_online - 2)
            start1 = max(
                0, min(online_idx - v_online // 2, max(0, len(online_aps) - v_online))
            )
            for row, i in enumerate(
                range(start1, min(start1 + v_online, len(online_aps)))
            ):
                ap = online_aps[i]
                ssid = (ap.get("ssid") or "<hidden>")[:18]
                bssid = (ap.get("bssid") or "?")[:17]
                ch = str(ap.get("channel") or "?")
                enc = (ap.get("encryption") or ap.get("enc") or "?")[:14]
                pwr = str(ap.get("power") if ap.get("power") is not None else "?")
                cli_cnt = str(ap.get("clients_count") or 0)
                vendor = (ap.get("vendor") or "Unknown")[:12]

                is_focused = active_table == "online" and i == online_idx
                is_sel = (
                    selected is not None
                    and selected.get("bssid") == ap.get("bssid")
                )
                mark = "▶" if is_focused else ("*" if is_sel else " ")
                line = (
                    f"{mark} {ssid:18} {bssid:17} CH{ch:>3} {pwr:>4}dBm  "
                    f"{enc:14} {cli_cnt:>2} cli    {vendor}"
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

            # --- TABLE UNDER: DISAPPEARED APs WITH FETCHED RECON INFO ---
            if h_disappeared > 0:
                top2 = top1 + h_online
                try:
                    focus_hdr2 = (
                        curses.color_pair(2) | curses.A_BOLD
                        if active_table == "disappeared"
                        else curses.A_DIM
                    )
                    hdr2 = f"── TABLE UNDER: DISAPPEARED APs ({len(disappeared_aps)}) [with fetched recon info] ──"
                    stdscr.addstr(top2, 2, hdr2[: w - 4], focus_hdr2)
                    col_hdr2 = "   SSID                 BSSID             CH  LAST PWR ENC           FETCHED RECON INFO (Vendor, Clients, Last Seen)"
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
                        max(0, len(disappeared_aps) - v_dis),
                    ),
                )
                for row, i in enumerate(
                    range(start2, min(start2 + v_dis, len(disappeared_aps)))
                ):
                    ap = disappeared_aps[i]
                    ssid = (ap.get("ssid") or "<hidden>")[:18]
                    bssid = (ap.get("bssid") or "?")[:17]
                    ch = str(ap.get("channel") or "?")
                    enc = (ap.get("encryption") or ap.get("enc") or "?")[:13]
                    pwr = str(
                        ap.get("power") if ap.get("power") is not None else "?"
                    )
                    ago = ap.get("last_seen_ago", "?")
                    vendor = ap.get("vendor", "Unknown")
                    cli_cnt = ap.get("clients_count", 0)
                    recon_str = f"Vendor: {vendor} | {cli_cnt} cli | last seen {ago}"

                    is_focused = (
                        active_table == "disappeared" and i == disappeared_idx
                    )
                    is_sel = (
                        selected is not None
                        and selected.get("bssid") == ap.get("bssid")
                    )
                    mark = "▶" if is_focused else ("*" if is_sel else " ")
                    line = (
                        f"{mark} {ssid:18} {bssid:17} CH{ch:>3} {pwr:>4}dBm  "
                        f"{enc:13} {recon_str}"
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

            # --- CLIENTS EXPAND PANEL (per-network associated clients) ---
            if clients_view_ap:
                cap = None
                for a in online_aps + disappeared_aps:
                    if a.get("bssid") == clients_view_ap:
                        cap = a
                        break
                panel_top = 3 + avail_h
                try:
                    if cap:
                        cl = cap.get("clients") or []
                        hdr = (
                            f"── ASSOCIATED CLIENTS of "
                            f"{(cap.get('ssid') or '<hidden>')} "
                            f"[{cap.get('bssid')}] — {len(cl)} client(s) "
                            f"[c to close] ──"
                        )
                        stdscr.addstr(
                            panel_top, 2, hdr[: w - 4],
                            curses.color_pair(3) | curses.A_BOLD,
                        )
                        if not cl:
                            stdscr.addstr(
                                panel_top + 1, 2,
                                "  <no associated clients captured for this "
                                "network yet>"[: w - 4],
                                curses.color_pair(2),
                            )
                        else:
                            for ci, mac in enumerate(cl[: panel_h - 2]):
                                try:
                                    stdscr.addstr(
                                        panel_top + 1 + ci, 2,
                                        f"  {ci + 1:2d}. {mac}"[: w - 4],
                                        curses.color_pair(3),
                                    )
                                except curses.error:
                                    pass
                    else:
                        stdscr.addstr(
                            panel_top, 2,
                            "Focused AP no longer in catalog — press c to "
                            "close."[: w - 4],
                            curses.color_pair(2),
                        )
                except curses.error:
                    pass

            # Footer
            fy = h - 4
            try:
                hovered = None
                if active_table == "online" and online_aps:
                    hovered = online_aps[online_idx]
                elif active_table == "disappeared" and disappeared_aps:
                    hovered = disappeared_aps[disappeared_idx]

                if selected:
                    s = selected
                    stdscr.addstr(
                        fy, 2,
                        (
                            f"SELECTED TARGET: {s.get('ssid')} [{s.get('bssid')}] "
                            f"CH{s.get('channel')} {s.get('encryption')} "
                            f"({s.get('vendor', 'Unknown')})"
                        )[: w - 4],
                        curses.color_pair(1) | curses.A_BOLD,
                    )
                elif hovered:
                    hv = hovered
                    stdscr.addstr(
                        fy, 2,
                        (
                            f"Hovered: {hv.get('ssid')} [{hv.get('bssid')}] | "
                            f"Vendor: {hv.get('vendor')} | "
                            f"Clients: {hv.get('clients_count', 0)} | "
                            f"Status: {hv.get('status', 'online').upper()}"
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
                        "[A] AIO ATTACK = continuous recon → NVD/CVE → "
                        "exploit → post-exploit → anti-forensics"
                    )[: w - 4],
                    curses.color_pair(2),
                )
                stdscr.addstr(
                    fy + 2, 2,
                    "↑/↓ move · TAB switch table · ENTER/SPACE select · A AIO · c clients · r rescan · q exit"[: w - 4],
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
                    if online_aps:
                        online_idx = max(0, online_idx - 1)
                else:
                    if disappeared_idx > 0:
                        disappeared_idx -= 1
                    else:
                        active_table = "online"
                        if online_aps:
                            online_idx = len(online_aps) - 1

            elif key in (curses.KEY_DOWN, ord("j"), ord("J")):
                if active_table == "online":
                    if online_idx < len(online_aps) - 1:
                        online_idx += 1
                    elif disappeared_aps:
                        active_table = "disappeared"
                        disappeared_idx = 0
                else:
                    if disappeared_aps:
                        disappeared_idx = min(
                            len(disappeared_aps) - 1, disappeared_idx + 1
                        )

            elif key in (ord("\t"), 9, getattr(curses, "KEY_LEFT", 260), getattr(curses, "KEY_RIGHT", 261), ord("h"), ord("H"), ord("l"), ord("L")):
                if active_table == "online" and disappeared_aps:
                    active_table = "disappeared"
                else:
                    active_table = "online"

            elif key in (curses.KEY_ENTER, 10, 13, ord(" ")):
                if active_table == "online" and online_aps:
                    selected = dict(online_aps[online_idx])
                elif active_table == "disappeared" and disappeared_aps:
                    selected = dict(disappeared_aps[disappeared_idx])
                if selected:
                    _write_selection(
                        out_path,
                        selected,
                        aio=False,
                        networks=online_aps,
                        disappeared_networks=disappeared_aps,
                    )
                    message = (
                        f"Selected {selected.get('ssid')} [{selected.get('bssid')}] — "
                        f"press A for AIO ATTACK or q to return"
                    )

            elif key in (ord("a"), ord("A")):
                if not selected:
                    if active_table == "online" and online_aps:
                        selected = dict(online_aps[online_idx])
                    elif active_table == "disappeared" and disappeared_aps:
                        selected = dict(disappeared_aps[disappeared_idx])
                if not selected:
                    message = "Select a target first (ENTER/SPACE)"
                    continue
                _write_selection(
                    out_path,
                    selected,
                    aio=True,
                    networks=online_aps,
                    disappeared_networks=disappeared_aps,
                )
                message = "AIO ATTACK queued — closing scan window…"
                stdscr.refresh()
                time.sleep(0.4)
                return 0

            elif key in (ord("c"), ord("C")):
                # Toggle the per-network associated-clients expand panel.
                if active_table == "online" and online_aps:
                    ap = online_aps[online_idx]
                elif active_table == "disappeared" and disappeared_aps:
                    ap = disappeared_aps[disappeared_idx]
                else:
                    ap = None
                if ap:
                    bssid = ap.get("bssid")
                    ncli = len(ap.get("clients") or [])
                    if clients_view_ap == bssid:
                        clients_view_ap = None
                        message = "Clients panel closed."
                    else:
                        clients_view_ap = bssid
                        message = (
                            f"Showing {ncli} associated client(s) for "
                            f"{ap.get('ssid')} [{bssid}] — c to close."
                        )
                else:
                    message = "Focus an AP first (↑/↓) then press c."

            elif key in (ord("r"), ord("R")):
                scanner.stop()
                scanner.ap_catalog.clear()
                scanner.last_seen_ts.clear()
                scanner.start()
                online_idx = 0
                disappeared_idx = 0
                message = "Scanner reset — live scanning restarted."

            elif key in (ord("q"), ord("Q"), 27):
                _write_selection(
                    out_path,
                    selected,
                    aio=False,
                    networks=online_aps,
                    disappeared_networks=disappeared_aps,
                )
                return 0
    finally:
        scanner.stop()


def run_text_ui(
    iface: str,
    out_path: Path,
    seconds: int = 12,
    long_range: bool = False,
) -> int:
    """Non-curses fallback when stdin/stdout is not a real TTY."""
    print("=" * 65)
    print(" KFIOSA WiFi Scan (text mode — live scanning)")
    print(f" Interface: {iface}  duration≈{seconds}s"
          f"{'  [LONG-RANGE]' if long_range else ''}")
    print("=" * 65)
    print("[*] Prepping radio + starting live scan…")
    disappeared_timeout = 60.0 if long_range else 20.0
    scanner = LiveScanner(iface, disappeared_timeout=disappeared_timeout)
    scanner.start()
    if scanner.prep_notes:
        for n in scanner.prep_notes[:6]:
            print(f"[i] {n}")
    if scanner.iface != iface:
        print(f"[+] Using monitor interface: {scanner.iface}")
    try:
        time.sleep(max(3, int(seconds)))
        online_aps, disappeared_aps = scanner.poll()

        # If live path still empty, stop live airodump and oneshot-retry
        # (concurrent airodump on the same phy returns zero APs).
        if not online_aps and not disappeared_aps:
            print("[*] Live catalog empty — stopping live capture, oneshot retry…")
            if scanner.last_error:
                print(f"[i] live error: {scanner.last_error}")
            scanner.stop()
            seed = _scan_airodump_oneshot(
                scanner.iface, seconds=max(6, int(seconds))
            )
            if not seed:
                seed = _scan_fallback(scanner.iface, seconds=min(15, int(seconds)))
            now = time.time()
            for ap in seed:
                bssid = ap.get("bssid")
                if bssid:
                    scanner._merge_ap(str(bssid).upper(), ap, now)
            online_aps, disappeared_aps = scanner.poll()

        print(f"\n[+] TABLE ABOVE: ONLINE APs ({len(online_aps)}):\n")
        if not online_aps:
            print("  <no online APs currently detected>")
        else:
            for i, ap in enumerate(online_aps):
                vendor = ap.get("vendor", "Unknown")
                cli_cnt = ap.get("clients_count", 0)
                print(
                    f"  {i + 1:3d}. {(ap.get('ssid') or '<hidden>'):20s} "
                    f"{(ap.get('bssid') or '?'):17s} "
                    f"CH{ap.get('channel') or '?':>3}  "
                    f"{ap.get('power') or '?':>4}dBm  "
                    f"{(ap.get('encryption') or '?'):14s} "
                    f"[{vendor} | {cli_cnt} clients]"
                )

        print(
            f"\n[+] TABLE UNDER: DISAPPEARED APs WITH FETCHED RECON INFO ({len(disappeared_aps)}):\n"
        )
        if not disappeared_aps:
            print("  <no disappeared APs>")
        else:
            for i, ap in enumerate(disappeared_aps):
                vendor = ap.get("vendor", "Unknown")
                ago = ap.get("last_seen_ago", "?")
                cli_cnt = ap.get("clients_count", 0)
                idx_str = f"D{i + 1}"
                print(
                    f"  {idx_str:>4s}. {(ap.get('ssid') or '<hidden>'):20s} "
                    f"{(ap.get('bssid') or '?'):17s} "
                    f"CH{ap.get('channel') or '?':>3}  "
                    f"{ap.get('power') or '?':>4}dBm  "
                    f"{(ap.get('encryption') or '?'):14s} "
                    f"[Recon: Vendor={vendor}, Clients={cli_cnt}, LastSeen={ago}]"
                )

        print(
            "\nCommands: number (e.g. 1 or D1) select target | "
            "A <n> AIO ATTACK | c <n> view online clients | "
            "C <n> view disappeared clients | q quit"
        )
        selected = None
        aio = False
        all_listed = online_aps + disappeared_aps

        def _print_clients(ap: Optional[Dict[str, Any]], label: str) -> None:
            if ap is None:
                print("  invalid selection")
                return
            ssid = ap.get("ssid") or "<hidden>"
            bssid = ap.get("bssid") or "?"
            clients = ap.get("clients") or []
            print(f"\n  Clients for {ssid} [{bssid}] ({len(clients)} captured):")
            if not clients:
                print("    <no associated clients captured for this network yet>")
            else:
                for ci, mac in enumerate(clients, 1):
                    vendor = _get_oui_vendor(mac)
                    print(f"    {ci:2d}. {mac}  ({vendor})")

        while True:
            try:
                raw = input("> ").strip()
            except (EOFError, KeyboardInterrupt):
                print()
                break
            if not raw or raw.lower() in ("q", "quit", "exit"):
                break

            lower = raw.lower()
            if lower.startswith("c ") or lower == "c":
                parts = raw.split()
                target_str = parts[1] if len(parts) > 1 else (
                    "1" if online_aps else ""
                )
                ap = _pick_text_ap(target_str, online_aps, [])
                _print_clients(ap, "online")
                continue
            if lower.startswith("C ") or lower == "C":
                parts = raw.split()
                target_str = parts[1] if len(parts) > 1 else (
                    "D1" if disappeared_aps else ""
                )
                ap = _pick_text_ap(target_str, [], disappeared_aps)
                _print_clients(ap, "disappeared")
                continue

            if lower.startswith("a"):
                parts = raw.split()
                target_str = parts[1] if len(parts) > 1 else "1"
                selected = _pick_text_ap(target_str, online_aps, disappeared_aps)
                if selected:
                    aio = True
                    print(
                        f"[AIO] Selected {selected.get('ssid')} [{selected.get('bssid')}]"
                    )
                    break
                print("invalid selection")
                continue

            selected = _pick_text_ap(raw, online_aps, disappeared_aps)
            if selected:
                clients = selected.get("clients") or []
                print(
                    f"[+] Selected {selected.get('ssid')} [{selected.get('bssid')}] — "
                    f"{len(clients)} client(s) — "
                    f"type A to launch AIO or q to save & quit"
                )
                continue
            print("enter a number (e.g. 1 or D1), A <n>, c <n>, C <n>, or q")

        _write_selection(
            out_path,
            selected,
            aio=aio,
            networks=online_aps,
            disappeared_networks=disappeared_aps,
        )
        if selected:
            print(f"[+] Wrote selection → {out_path}  aio={aio}")
        else:
            print(f"[i] No selection written (empty) → {out_path}")
        return 0
    finally:
        scanner.stop()


def _pick_text_ap(
    key: str,
    online_aps: List[Dict[str, Any]],
    disappeared_aps: List[Dict[str, Any]],
) -> Optional[Dict[str, Any]]:
    key = key.strip().upper()
    if key.startswith("D"):
        try:
            idx = int(key[1:]) - 1
            if 0 <= idx < len(disappeared_aps):
                return dict(disappeared_aps[idx])
        except ValueError:
            pass
    else:
        try:
            idx = int(key) - 1
            if 0 <= idx < len(online_aps):
                return dict(online_aps[idx])
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
                args[0], args[1], args[2] if len(args) > 2 else 12,
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
        "--iface", required=True, help="Wireless interface (monitor preferred)"
    )
    ap.add_argument(
        "--out",
        default=str(Path("logs") / "wifi_scan_selection.json"),
        help="JSON path for selection + aio_attack flag",
    )
    ap.add_argument("--seconds", type=int, default=30, help="Scan duration")
    ap.add_argument(
        "--long-range",
        action="store_true",
        help="Long-range sweep: keep disappeared APs on screen far longer "
             "and dwell longer so distant networks are caught.",
    )
    ap.add_argument(
        "--text",
        action="store_true",
        help="Force text UI (no curses); also auto if not a TTY",
    )
    args = ap.parse_args(argv)
    out_path = Path(args.out)

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
            args.iface, out_path, args.seconds,
            long_range=bool(args.long_range),
        )
    return _curses_safe_wrapper(
        run_curses, args.iface, out_path, args.seconds, bool(args.long_range),
    )


if __name__ == "__main__":
    raise SystemExit(main())
