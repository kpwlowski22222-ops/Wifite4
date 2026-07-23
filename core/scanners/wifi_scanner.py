#!/usr/bin/env python3
"""
WiFi Scanner
=============
Real WiFi scanning via airodump-ng, with dynamic interface detection and
monitor-mode setup. No fake APs — when a tool is missing or permission is
denied, the scanner returns an empty result with an explicit error.

Offensive operations (deauth, handshake crack) call real aircrack-ng tools
and are gated by an injected ``confirm_fn`` (default-deny) so nothing
executes without explicit operator ACCEPT.
"""

import csv
import io
import logging
import os
import re
import shutil
import subprocess
import time
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)


def _default_deny(*_a, **_k) -> bool:
    """Safe default confirm handler — denies every offensive step."""
    return False


class WiFiScanner:
    def __init__(self, interface: Optional[str] = None, confirm_fn=None):
        self.logger = logging.getLogger(__name__)
        self.is_initialized = False
        self.scan_results = {}
        self.active_scans = {}
        # No hardcoded interface default — caller picks from detected list.
        self.interface = interface
        self.confirm_fn = confirm_fn or _default_deny
        self._restored_ifaces: List[str] = []

    def initialize(self):
        """Initialize WiFi scanner. Degrades gracefully if tools absent."""
        self.is_initialized = True
        if not shutil.which("airodump-ng"):
            self.logger.warning("airodump-ng not found — scan will report the error")
        return True

    # ------------------------------------------------------------------
    # Interface detection / monitor mode (no hardcoded ifaces)
    # ------------------------------------------------------------------
    def detect_interfaces(self) -> List[Dict[str, str]]:
        from core.tui.interface_picker import detect_wireless_interfaces
        return detect_wireless_interfaces()

    def ensure_monitor(self, iface: str) -> Dict[str, Any]:
        """Put ``iface`` into monitor mode (requires root). Returns status.

        Tries ``airmon-ng start`` first (creates the conventional
        ``<orig>mon`` interface, e.g. ``wlan0`` -> ``wlan0mon``), then
        falls back to an in-place ``iw``+``ip`` flip when airmon-ng is
        missing or not runnable as root.

        Returns a dict with at least one of:

        - ``{"ok": True, "interface": <name>, "mode": "monitor",
           "method": "airmon"|"iw"}`` on success. ``interface`` is the
           *post-monitor* name (e.g. ``wlan0mon`` for airmon-ng, the
           original ``wlan0`` for the iw fallback).
        - ``{"error": ...}`` on failure. Never fakes success.

        The post-monitor interface is recorded in
        ``self._restored_ifaces`` so :meth:`restore_managed` knows which
        adapter to flip back.
        """
        # First choice: airmon-ng (matches aircrack-ng convention).
        airmon = self._start_monitor_airmon(iface)
        if airmon.get("ok"):
            return airmon

        # Fallback: in-place iw+ip flip. Log the airmon reason at debug.
        self.logger.debug(
            "airmon-ng unavailable (%s); falling back to iw+ip", airmon.get("error")
        )
        iw = self._start_monitor_iw(iface)
        if iw.get("ok"):
            return iw

        # Both paths failed. Surface airmon's reason if iw's is empty.
        return {
            "error": iw.get("error") or airmon.get("error") or "unknown"
        }

    def _start_monitor_airmon(self, iface: str) -> Dict[str, Any]:
        """Try ``airmon-ng start <iface>`` to create ``<iface>mon``.

        Requires root. We never invoke sudo from the dashboard TUI — if
        the process is unprivileged, return an error so the caller can
        fall back or surface the remediation text.
        """
        if not shutil.which("airmon-ng"):
            return {"error": "airmon-ng not installed"}
        if os.geteuid() != 0:
            return {"error": "airmon-ng needs root"}
        try:
            p = subprocess.run(
                ["airmon-ng", "start", iface],
                capture_output=True, text=True, timeout=15,
            )
        except subprocess.TimeoutExpired:
            return {"error": "airmon-ng start timed out"}
        except Exception as e:
            return {"error": f"airmon-ng: {e}"}
        if p.returncode != 0:
            return {"error": f"airmon-ng: {p.stderr.strip() or 'rc='+str(p.returncode)}"}

        # airmon-ng prints a line like:
        #   (mac80211 monitor mode vif enabled on [phy0]wlan0mon)
        # or, on older versions:
        #   monitor mode enabled on wlan0mon
        out = p.stdout
        m = re.search(r"\]\s*(\S+mon)\b", out) or re.search(
            r"enabled on (\S+)", out
        )
        if not m:
            return {"error": "airmon-ng: could not parse new monitor interface name"}
        new_iface = m.group(1)
        self._restored_ifaces.append(new_iface)
        return {
            "ok": True,
            "interface": new_iface,
            "mode": "monitor",
            "method": "airmon",
        }

    def _start_monitor_iw(self, iface: str) -> Dict[str, Any]:
        """In-place monitor-mode flip using ``iw`` + ``ip``.

        The interface name is unchanged (e.g. ``wlan0`` stays ``wlan0``).
        Use this when airmon-ng is not available or did not produce a
        renamed monitor interface.
        """
        if not shutil.which("iw") or not shutil.which("ip"):
            return {"error": "iw/ip not installed"}
        try:
            for cmd in (["ip", "link", "set", iface, "down"],
                        ["iw", "dev", iface, "set", "type", "monitor"],
                        ["ip", "link", "set", iface, "up"]):
                p = subprocess.run(cmd, capture_output=True, text=True, timeout=8)
                if p.returncode != 0:
                    return {"error": f"{' '.join(cmd)}: {p.stderr.strip() or 'rc='+str(p.returncode)}"}
            self._restored_ifaces.append(iface)
            return {
                "ok": True,
                "interface": iface,
                "mode": "monitor",
                "method": "iw",
            }
        except Exception as e:
            return {"error": str(e)}

    def restore_managed(self, iface: str):
        """Return an interface to managed mode."""
        try:
            for cmd in (["ip", "link", "set", iface, "down"],
                        ["iw", "dev", iface, "set", "type", "managed"],
                        ["ip", "link", "set", iface, "up"]):
                subprocess.run(cmd, capture_output=True, text=True, timeout=8)
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Scan (real airodump-ng CSV parsing; no fake APs)
    # ------------------------------------------------------------------
    def scan(self, interface: str = None, timeout: int = None) -> Dict[str, Any]:
        """Scan for WiFi networks using airodump-ng (max RF / hop coverage).

        Args:
            interface: monitor-mode interface. If None, the scanner uses
                its constructor interface or auto-selects the first
                detected monitor-capable adapter.
            timeout: capture duration in seconds. Default long-range
                (``DEFAULT_WIFI_SCAN_S``, 300s); hard ceiling
                ``MAX_SCAN_S`` (3600s) via :mod:`core.scanners.scan_limits`.
                Multi-band hop (2.4 + 5 GHz) for maximum spatial coverage.

        Returns:
            {networks: [...], total_found, interface, duration, error?}
        """
        from core.scanners.scan_limits import wifi_scan_s

        if not self.is_initialized:
            return {"error": "WiFi scanner not initialized"}

        iface = interface or self.interface
        if not iface:
            ifaces = self.detect_interfaces()
            mon = next((i["name"] for i in ifaces if i["monitor"]), None) or (
                ifaces[0]["name"] if ifaces else None
            )
            if not mon:
                return {
                    "networks": [],
                    "error": "no wireless interface detected (run `iw dev`)",
                    "total_found": 0,
                }
            iface = mon

        if not shutil.which("airodump-ng"):
            return {
                "networks": [],
                "error": "airodump-ng not found — install aircrack-ng",
                "total_found": 0,
                "interface": iface,
            }

        # Pre-flight: stop NM/wpa, collapse dual-mon VIFs, ensure monitor.
        # Critical: use the *post*-prep interface name (airmon often
        # renames wlan0 → wlan0mon).
        try:
            from core.scanners.wifi_radio import prep_for_wifi_scan, airodump_cmd
            prep = prep_for_wifi_scan(iface, kill_interferers=True, collapse_dups=True)
        except Exception as e:
            prep = {"ok": False, "error": str(e), "interface": iface, "notes": []}

        if not prep.get("ok"):
            # Fall back to legacy ensure_monitor path
            mon = self.ensure_monitor(iface)
            if "error" in mon:
                return {
                    "networks": [],
                    "error": (
                        f"monitor prep on {iface}: "
                        f"{prep.get('error') or mon.get('error')} (needs root)"
                    ),
                    "total_found": 0,
                    "interface": iface,
                    "notes": prep.get("notes") or [],
                }
            scan_iface = mon.get("interface") or iface
            prep_notes = list(prep.get("notes") or [])
        else:
            scan_iface = prep.get("interface") or iface
            prep_notes = list(prep.get("notes") or [])
            for n in prep_notes:
                self.logger.info("wifi prep: %s", n)

        # Track post-monitor name for restore.
        if scan_iface and scan_iface not in self._restored_ifaces:
            self._restored_ifaces.append(scan_iface)
        self.interface = scan_iface

        scan_id = f"wifi_scan_{int(time.time())}"
        cap = wifi_scan_s(timeout)
        prefix = f"/tmp/kfiosa_{scan_id}"
        self.logger.info(
            f"airodump-ng on {scan_iface} for {cap}s "
            f"(long-range multi-band) -> {prefix}"
        )

        # Long-range airodump:
        #  * --band abg  → hop 2.4 GHz + 5 GHz (max spatial coverage)
        #  * no -c lock  → full channel hop (default)
        #  * --berlin    → keep weak/intermittent APs listed for the full
        #                  scan window (not the short default ~120s)
        #  * --write-interval 1 → stream CSV so mid-scan APs are kept
        berlin = max(cap, 120)
        try:
            attempts = airodump_cmd(
                scan_iface, prefix, berlin=berlin, multi_band=True,
            )
        except Exception:
            attempts = [[
                "airodump-ng", scan_iface,
                "-w", prefix,
                "--write-interval", "1",
                "--output-format", "csv",
                "--berlin", str(berlin),
                "--band", "abg",
            ], [
                "airodump-ng", scan_iface,
                "-w", prefix,
                "--write-interval", "1",
                "--output-format", "csv",
                "--berlin", str(berlin),
            ]]

        last_err = ""
        for cmd in attempts:
            try:
                subprocess.run(
                    cmd,
                    capture_output=True, text=True, timeout=cap + 15,
                )
                last_err = ""
                break
            except subprocess.TimeoutExpired:
                # Expected: airodump runs until our timeout kills it.
                last_err = ""
                break
            except FileNotFoundError:
                return {"networks": [], "error": "airodump-ng not found",
                        "total_found": 0, "interface": scan_iface}
            except Exception as e:
                last_err = str(e)
                continue
        if last_err and not os.path.exists(f"{prefix}-01.csv"):
            return {"networks": [], "error": f"airodump-ng: {last_err}",
                    "total_found": 0, "interface": scan_iface,
                    "notes": prep_notes}

        networks = self._parse_airodump_csv(f"{prefix}-01.csv")

        self.scan_results[scan_id] = {
            "timestamp": self._get_timestamp(),
            "interface": scan_iface,
            "duration": cap,
            "networks": networks,
            "total_found": len(networks),
            "notes": prep_notes,
        }
        if not networks:
            self.scan_results[scan_id]["error"] = (
                f"no APs heard on {scan_iface} after {cap}s — "
                "check antenna / rfkill / that NM is not re-grabbing the radio"
            )
        # Do NOT auto-restore managed after a successful pentest scan —
        # operator stays in monitor for follow-up attacks. Only restore
        # when we never saw a monitor-ready iface (prep failed mid-way).
        return self.scan_results[scan_id]

    def _parse_airodump_csv(self, path: str) -> List[Dict[str, Any]]:
        """Parse an airodump-ng CSV into the existing network dict shape.

        airodump-ng emits a two-section CSV; the first section is APs.
        Columns (standard airodump-ng layout):
          BSSID, First time seen, Last time seen, channel, Speed, Privacy,
          Cipher, Authentication, Power, # beacons, # IV, LAN IP, ID-length,
          ESSID, Key
        """
        if not os.path.exists(path):
            return []
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except Exception as e:
            self.logger.error(f"read csv {path}: {e}")
            return []

        # AP section is everything up to the blank line / "Station MAC".
        ap_section: List[str] = []
        for line in text.splitlines():
            if line.strip().startswith("Station MAC") or line.strip() == "":
                if ap_section:
                    break
                continue
            if line.strip():
                ap_section.append(line)
        if not ap_section:
            return []

        networks: List[Dict[str, Any]] = []
        try:
            reader = csv.reader(io.StringIO("\n".join(ap_section)))
            for row in reader:
                if len(row) < 14:
                    continue
                bssid = row[0].strip()
                if not bssid or bssid == "BSSID":
                    continue
                channel = row[3].strip()
                privacy = row[5].strip()
                power = row[8].strip()
                essid = row[13].strip()
                networks.append({
                    "ssid": essid or "<hidden>",
                    "bssid": bssid,
                    "channel": channel,
                    "encryption": privacy or "Open",
                    "signal_strength": f"{power} dBm" if power.lstrip("-").isdigit() else power,
                    "signal": int(power) if power.lstrip("-").isdigit() else -100,
                    "wps": False,  # requires a separate `wash` probe
                })
        except Exception as e:
            self.logger.error(f"parse airodump csv: {e}")
        return networks

    def wps_probe(self, interface: str, bssid: str) -> bool:
        """Probe WPS state with `wash` (real). Returns True if WPS present."""
        if not shutil.which("wash"):
            return False
        try:
            p = subprocess.run(
                ["wash", "-i", interface, "-b", bssid, "-t", "10"],
                capture_output=True, text=True, timeout=15,
            )
            return p.returncode == 0 and bssid.lower() in (p.stdout or "").lower()
        except Exception:
            return False

    # ------------------------------------------------------------------
    # Offensive ops — real, gated by confirm_fn (default-deny)
    # ------------------------------------------------------------------
    def deauth_attack(self, bssid: str, interface: str,
                     client: str = None, count: int = 10) -> Dict[str, Any]:
        """Real aireplay-ng deauth. Gated by confirm_fn."""
        if not shutil.which("aireplay-ng"):
            return {"error": "aireplay-ng not found"}
        if not self.confirm_fn(f"Send {count} deauth frames to {bssid} via {interface}?"):
            return {"status": "blocked by confirm_fn", "bssid": bssid}
        try:
            cmd = ["aireplay-ng", "--deauth", str(count), "-a", bssid]
            if client:
                cmd += ["-c", client]
            cmd += [interface]
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            return {
                "bssid": bssid, "target_client": client or "all",
                "rc": p.returncode,
                "stdout": p.stdout[-500:], "stderr": p.stderr[-500:],
                "status": "completed" if p.returncode == 0 else "failed",
                "timestamp": self._get_timestamp(),
            }
        except Exception as e:
            return {"error": str(e), "bssid": bssid}

    def crack_handshake(self, capture_file: str, wordlist: str = None,
                        bssid: str = None) -> Dict[str, Any]:
        """Real aircrack-ng / hashcat handshake crack. Gated by confirm_fn."""
        if not shutil.which("aircrack-ng") and not shutil.which("hashcat"):
            return {"error": "aircrack-ng/hashcat not found"}
        if not self.confirm_fn(f"Crack handshake {capture_file} with {wordlist}?"):
            return {"status": "blocked by confirm_fn"}
        if not wordlist:
            return {"error": "no wordlist supplied"}
        try:
            p = subprocess.run(
                ["aircrack-ng", "-w", wordlist, "-b", bssid or "", capture_file],
                capture_output=True, text=True, timeout=600,
            )
            password = None
            for line in (p.stdout or "").splitlines():
                if "KEY FOUND" in line:
                    pw = line.split("KEY FOUND!", 1)
                    if len(pw) == 2:
                        password = pw[1].strip().strip("[").rstrip("]")
            return {
                "bssid": bssid, "capture": capture_file,
                "password_found": password,
                "rc": p.returncode,
                "status": "completed" if password else "failed",
                "timestamp": self._get_timestamp(),
            }
        except Exception as e:
            return {"error": str(e)}

    # ------------------------------------------------------------------
    # Misc
    # ------------------------------------------------------------------
    def get_scan_history(self) -> Dict[str, Any]:
        return self.scan_results

    def _get_timestamp(self) -> str:
        from datetime import datetime
        return datetime.now().isoformat()

    def cleanup(self):
        self.scan_results.clear()
        self.active_scans.clear()
        for iface in list(self._restored_ifaces):
            self.restore_managed(iface)
        self._restored_ifaces.clear()
        self.is_initialized = False