"""
Catalog-driven Recon Pass
========================
Runs all six catalog-advertised recon steps against a chosen WiFi
target **without** an operator confirm gate. The recon pass is the
"what is the target telling us" pre-chain work — once recon is done
the existing :class:`AutonomousOrchestrator` runs the gated attack
chain (``airodump -> deauth -> hashcat -> evil_twin -> msf -> c2``).

The six steps (all best-effort, errors logged not raised):

1. ``wash``  -- WPS state probe (``wash -i <iface> -b <bssid> -C``)
2. ``airodump-ng`` -- client enumeration (association table) for the
   chosen BSSID + channel.
3. NVD CVE search per SSID + per BSSID OUI vendor (NVD_API_KEY honoured).
4. weakpass heuristic wordlist via ``hcxpsktool --weakpass`` (capped at
   100 MB by default).
5. KB / external repo search by SSID, OUI vendor, and any CVE IDs
   discovered in step 3.
6. Catalog iteration -- run anything else the catalog advertises for
   the target's toolset.

Output is a dict with all six step results + a JSON report persisted to
``logs/recon/<bssid>_<ts>.json`` (the ``logs/`` dir already exists from
``config/dashboard_settings.json:logging.file``).

The recon pass is **never** gated by ``confirm_fn``. The *attack* chain
is. The activity log emits ``[recon] <step>`` lines for each step.
"""

import json
import logging
import math
import os
import re
import shutil
import subprocess
import time
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Project root (parent of core/)
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent

# Hard cap on the weakpass output to avoid DoS'ing the disk.
WEAKPASS_MAX_BYTES = 100 * 1024 * 1024  # 100 MB

# NVD endpoint (NVD_API_KEY, if set, raises the per-30s rate limit).
NVD_ENDPOINT = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# OUI prefix -> vendor (very small offline set; load data/oui.txt if present)
_BUILTIN_OUI: Dict[str, str] = {
    "001A11": "Google", "F4F5D8": "Google", "001E52": "Apple",
    "3C0754": "Apple", "001124": "Apple", "002500": "Apple",
    "B827EB": "Raspberry Pi", "DCA632": "Raspberry Pi",
    "C0:25:06": "TP-Link", "EC086B": "TP-Link", "AC84C6": "TP-Link",
    "001CC0": "TP-Link", "B0487A": "TP-Link", "30B5C2": "TP-Link",
    "001D0F": "TP-Link", "F81D93": "ARRIS", "0023EB": "ARRIS",
    "0026F2": "Cisco", "0017DF": "Cisco", "002219": "Cisco",
    "0021D1": "Cisco", "001E7A": "Cisco", "0026B9": "Cisco",
    "ACF1DF": "Samsung", "001247": "Samsung", "08D40B": "Samsung",
    "B0C4E7": "Samsung", "5C0A5B": "Samsung", "34C3AC": "Samsung",
    "0013E8": "Intel", "001DE0": "Intel", "8086F2": "Intel",
    "AC7B61": "Intel", "C8F733": "Intel", "7CC537": "Intel",
}


# ---------------------------------------------------------------------------
# Recon-probe constants (used by the 9 novel CatalogRecon probe steps).
# These decode 802.11 RSN/EAP fields the way tshark emits them, so the
# probes can score WPA3/PMF/WPS/EAP-enterprise feasibility from a passive
# capture without any active injection. All maps are stdlib-only.
# ---------------------------------------------------------------------------

# Cipher suite OUI+type codes as tshark prints the numeric type.
_CIPHER_CODES: Dict[str, str] = {
    "4": "CCMP", "2": "TKIP", "5": "GCMP", "6": "GCMP-256",
    "3": "WEP-104", "1": "WEP-40", "0": "Use group",
}
# AKM codes -> name. 8/9/12 are SAE/FT-SAE/OWE (WPA3).
_AKM_CODES: Dict[str, str] = {
    "1": "PSK", "2": "FT-PSK", "8": "SAE", "9": "FT-SAE",
    "12": "OWE", "5": "802.1X", "6": "GTC", "16": "PSK-SHA256",
    "18": "SAE-EXT-KEY",
}
# EAP type -> method name (802.1X enterprise auth probing).
_EAP_TYPES: Dict[int, str] = {
    4: "MD5", 6: "GTC", 13: "PEAP", 17: "LEAP",
    21: "TTLS", 25: "FAST", 29: "MS-CHAP-v2",
}

# 2.4 GHz channel -> centre frequency (MHz); 5 GHz picks the common ones.
_CHAN_FREQ_24: Dict[int, int] = {c: 2412 + (c - 1) * 5 for c in range(1, 15)}
_CHAN_FREQ_5: Dict[int, int] = {
    36: 5180, 40: 5200, 44: 5220, 48: 5240, 52: 5260, 56: 5280,
    60: 5300, 64: 5320, 100: 5500, 104: 5520, 108: 5540, 112: 5560,
    116: 5580, 120: 5600, 124: 5620, 128: 5640, 132: 5660, 136: 5680,
    140: 5700, 144: 5720, 149: 5745, 153: 5765, 157: 5785, 161: 5805,
    165: 5825,
}


def _chan_freq(ch: Any) -> Optional[int]:
    """Centre frequency (MHz) for a channel number, or None."""
    try:
        c = int(ch)
    except (TypeError, ValueError):
        return None
    if c in _CHAN_FREQ_24:
        return _CHAN_FREQ_24[c]
    if c in _CHAN_FREQ_5:
        return _CHAN_FREQ_5[c]
    return None


def _is_band_5ghz(ch: Any) -> bool:
    try:
        return int(ch) >= 36
    except (TypeError, ValueError):
        return False


# Path-loss defaults for the signal_map distance estimate (log-distance).
# Overridable via settings keys wifi.pathloss.ref_rssi / wifi.pathloss.n.
_PATHLOSS_REF_RSSI = -40
_PATHLOSS_N = 2.7


def _vendor_for_bssid(bssid: str, oui_path: Optional[Path] = None) -> str:
    """Best-effort OUI vendor lookup. Returns vendor name or
    ``"unknown"`` if the prefix is not in the local table and the
    IEEE OUI file is missing."""
    if not bssid:
        return "unknown"
    norm = bssid.upper().replace(":", "").replace("-", "").replace(".", "")
    if len(norm) < 6:
        return "unknown"
    prefix = norm[:6]
    if prefix in _BUILTIN_OUI:
        return _BUILTIN_OUI[prefix]
    if oui_path and oui_path.exists():
        try:
            with open(oui_path, "r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    if prefix in line.upper():
                        # IEEE MA-L format: "AC-84-C6   (hex)		TP-LINK"
                        parts = re.split(r"\s+", line.strip())
                        if parts:
                            return parts[-1]
        except (OSError, UnicodeDecodeError) as e:
            logger.debug("read oui file %s: %s", oui_path, e)
    return "unknown"


def _target_identity_snapshot(target: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Shallow copy of identity fields from a live seed/target dict.

    Used for ``recon["target"]`` so the report never holds a live
    reference to the operator seed. Holding the live dict + later
    assigning ``seed["recon"] = recon`` creates a circular reference
    that breaks ``json.dumps`` in the AI chain planner / re-plan path.
    """
    if not isinstance(target, dict):
        return {}
    # Identity + engagement flags the planner actually reads from the
    # recon snapshot. Deliberately excludes nested recon/wifi_attack/
    # session blobs that can reintroduce cycles.
    keys = (
        "bssid", "BSSID", "ssid", "channel", "encryption", "enc",
        "cipher", "auth", "interface", "power", "vendor", "essid",
        "signal", "wps", "clients", "aio", "attach_zero_day",
        "post_exploit", "anti_forensics", "polymorphic", "target_class",
        "os", "address", "mac", "name",
    )
    out: Dict[str, Any] = {}
    for k in keys:
        if k in target:
            v = target[k]
            # Only copy JSON-safe scalars / short lists; skip nested
            # dicts that might already be cyclic from a prior run.
            if isinstance(v, (str, int, float, bool)) or v is None:
                out[k] = v
            elif isinstance(v, (list, tuple)) and len(v) <= 32:
                out[k] = list(v)
    return out


def _step(name: str) -> Dict[str, Any]:
    """Scaffold a per-step result dict with the standard fields."""
    return {"name": name, "ok": False, "started_at": time.time(),
            "duration_s": 0.0, "error": None, "data": None}


def _finalize(step: Dict[str, Any], started: float,
              *, ok: bool, data: Any = None, error: Optional[str] = None):
    step["duration_s"] = round(time.time() - started, 3)
    step["ok"] = ok
    step["data"] = data
    step["error"] = error
    return step


class CatalogRecon:
    """Run the 6 catalog-driven recon steps against a WiFi target.

    No ``confirm_fn`` -- this is a best-effort pre-chain that the
    operator has already accepted by selecting the target. All step
    failures are recorded, not raised.
    """

    def __init__(self, target: Dict[str, Any],
                 catalog_index: Optional[Dict[str, Any]] = None,
                 nvd_cfg: Optional[Dict[str, Any]] = None,
                 weakpass_outdir: Path = PROJECT_ROOT / "logs" / "recon",
                 kali: Optional[Any] = None,
                 kb: Optional[Any] = None,
                 oui_path: Optional[Path] = None,
                 settings: Optional[Any] = None):
        self.target = target or {}
        self.bssid = (self.target.get("bssid") or "").upper()
        self.ssid = self.target.get("ssid") or ""
        self.channel = self.target.get("channel") or ""
        self.interface = (
            self.target.get("interface")
            or (settings.get_setting("wifi.default_iface") if settings else None)
            or "<iface>"
        )
        self.catalog_index = catalog_index
        self.nvd_cfg = nvd_cfg or {}
        self.outdir = Path(weakpass_outdir)
        self.kali = kali  # may be None — we still call subprocess directly
        self.kb = kb      # may be None — we still operate without KB
        self.oui_path = oui_path or (PROJECT_ROOT / "data" / "oui.txt")
        self.settings = settings
        self.vendor = _vendor_for_bssid(self.bssid, self.oui_path)
        self._nvd_key_cache: Optional[str] = None
        # EMA of per-MAC RSSI across signal_map runs (persisted on the
        # instance so repeated probes smooth noisy single-sample reads).
        self._sig_cache: Dict[str, float] = {}
        # Snapshot identity fields only — NEVER hold a live reference to
        # ``self.target``. The TUI merges ``target["recon"] = recon_report``
        # after run(); if recon["target"] is the same dict, that creates
        # a cycle (target → recon → target) and every later
        # ``json.dumps(seed)`` in the chain planner fails with
        # "Circular reference detected", killing AI chains + re-plan.
        self.recon: Dict[str, Any] = {
            "target": _target_identity_snapshot(self.target),
            "vendor": self.vendor,
            "bssid": self.bssid,
            "ssid": self.ssid,
            "channel": self.channel,
            "started_at": time.time(),
            "wps": _step("wps_probe"),
            "clients": _step("client_enum"),
            "cves": _step("cve_search"),
            "weakpass": _step("weakpass_wordlist"),
            "kb_hits": _step("kb_search"),
            "catalog_runs": _step("catalog_iter"),
            # --- 9 novel passive recon probes (AI-driven via the
            # ``recon_probe`` chain action; not run by the default
            # 6-step ``run()`` unless with_probes=True). Each mirrors
            # an algorithm ported from a fetched toolboxes/recon repo,
            # implemented here in Python — never a wrapper. ---
            "probe_profile": _step("probe_profile"),
            "hidden_ssid": _step("hidden_ssid"),
            "signal_map": _step("signal_map"),
            "handshake_harvest": _step("handshake_harvest"),
            "eapol_monitor": _step("eapol_monitor"),
            "channel_plan": _step("channel_plan"),
            "deauth_detect": _step("deauth_detect"),
            "gps_wardrive": _step("gps_wardrive"),
            "beacon_parse": _step("beacon_parse"),
        }

    # ------------------------------------------------------------------
    # NVD key resolution
    # ------------------------------------------------------------------
    def _get_nvd_key(self) -> str:
        """Centralized NVD key resolution. Settings → env. Never raises."""
        if self._nvd_key_cache is not None:
            return self._nvd_key_cache
        from core.ai_backend import get_nvd_key
        self._nvd_key_cache = get_nvd_key(self.settings) or os.environ.get("NVD_API_KEY", "")
        return self._nvd_key_cache

    # ------------------------------------------------------------------
    # Step 1: WPS probe
    # ------------------------------------------------------------------
    def _wps_probe(self) -> Dict[str, Any]:
        started = time.time()
        if not shutil.which("wash"):
            return _finalize(self.recon["wps"], started, ok=False,
                             error="wash not installed")
        if not self.bssid:
            return _finalize(self.recon["wps"], started, ok=False,
                             error="no bssid in target")
        try:
            r = subprocess.run(
                ["wash", "-i", self.interface, "-b", self.bssid, "-C", "-t", "10"],
                capture_output=True, text=True, timeout=20,
            )
        except subprocess.TimeoutExpired:
            return _finalize(self.recon["wps"], started, ok=False,
                             error="wash timeout")
        except FileNotFoundError:
            return _finalize(self.recon["wps"], started, ok=False,
                             error="wash not found")
        except Exception as e:
            return _finalize(self.recon["wps"], started, ok=False,
                             error=str(e))
        # wash prints "BSSID Ch dBm WPS Lck Vendor ESSID" header + matching rows
        wps_locked = False
        wps_enabled = False
        for line in (r.stdout or "").splitlines():
            if self.bssid in line.upper():
                wps_enabled = True
                if "Yes" in line.split():
                    wps_locked = True
                break
        return _finalize(self.recon["wps"], started, ok=True,
                         data={"enabled": wps_enabled, "locked": wps_locked,
                               "wash_rc": r.returncode,
                               "wash_stdout_tail": r.stdout[-500:]})

    # ------------------------------------------------------------------
    # Step 2: Client enumeration
    # ------------------------------------------------------------------
    def _client_enum(self) -> Dict[str, Any]:
        started = time.time()
        if not shutil.which("airodump-ng"):
            return _finalize(self.recon["clients"], started, ok=False,
                             error="airodump-ng not installed")
        # 10-second capture; CSV format; we only parse CSV.
        prefix = f"/tmp/kfiosa_recon_{self.bssid.replace(':', '')}_{int(time.time())}"
        try:
            r = subprocess.run(
                ["airodump-ng", self.interface, "--bssid", self.bssid,
                 "-c", str(self.channel) if self.channel else "1",
                 "-w", prefix, "--output-format", "csv",
                 "--berlin", "10"],
                capture_output=True, text=True, timeout=25,
            )
        except subprocess.TimeoutExpired:
            pass
        except FileNotFoundError:
            return _finalize(self.recon["clients"], started, ok=False,
                             error="airodump-ng not found")
        except Exception as e:
            return _finalize(self.recon["clients"], started, ok=False,
                             error=str(e))
        csv_path = f"{prefix}-01.csv"
        clients = self._parse_clients_csv(csv_path)
        aps = self._parse_aps_csv(csv_path)
        return _finalize(self.recon["clients"], started, ok=True,
                         data={"count": len(clients), "clients": clients,
                               "aps": aps, "csv": csv_path})

    @staticmethod
    def _parse_clients_csv(path: str) -> List[Dict[str, Any]]:
        """Parse airodump-ng's CSV station section into client dicts."""
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except (OSError, UnicodeDecodeError):
            return []
        # Station section starts with "Station MAC, ..."
        if "Station MAC" not in text:
            return []
        try:
            tail = text.split("Station MAC", 1)[1]
        except IndexError:
            return []
        rows: List[Dict[str, Any]] = []
        for ln in tail.splitlines():
            ln = ln.strip()
            if not ln:
                continue
            cols = [c.strip() for c in ln.split(",")]
            if len(cols) < 6:
                continue
            mac, bssid, power, _, probes = cols[0], cols[1], cols[3], cols[4], cols[5]
            if not mac or mac == "Station MAC":
                continue
            rows.append({"mac": mac, "bssid": bssid, "power": power,
                         "probes": probes, "packets": cols[4] if len(cols) > 4 else ""})
        return rows

    @staticmethod
    def _parse_aps_csv(path: str) -> List[Dict[str, Any]]:
        """Parse airodump-ng's CSV AP section (the block *before* the
        ``Station MAC`` delimiter). Returns one dict per AP with the
        fields the novel probes need: bssid, ssid, channel, power, privacy,
        cipher, auth, beacons, lan_ip. Tolerates the leading
        ``BSSID, First time seen, ...`` header line."""
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except (OSError, UnicodeDecodeError):
            return []
        head = text.split("Station MAC", 1)[0] if "Station MAC" in text else text
        rows: List[Dict[str, Any]] = []
        for ln in head.splitlines():
            ln = ln.strip()
            if not ln or ln.startswith("BSSID,"):
                continue
            cols = [c.strip() for c in ln.split(",")]
            if len(cols) < 14:
                continue
            bssid = cols[0]
            if not bssid or bssid == "BSSID":
                continue
            rows.append({
                "bssid": bssid,
                "first_seen": cols[1] if len(cols) > 1 else "",
                "last_seen": cols[2] if len(cols) > 2 else "",
                "channel": cols[3] if len(cols) > 3 else "",
                "speed": cols[4] if len(cols) > 4 else "",
                "privacy": cols[5] if len(cols) > 5 else "",
                "cipher": cols[6] if len(cols) > 6 else "",
                "auth": cols[7] if len(cols) > 7 else "",
                "power": cols[8] if len(cols) > 8 else "",
                "beacons": cols[9] if len(cols) > 9 else "",
                "iv": cols[10] if len(cols) > 10 else "",
                "lan_ip": cols[11] if len(cols) > 11 else "",
                "id_length": cols[12] if len(cols) > 12 else "",
                "ssid": cols[13] if len(cols) > 13 else "",
                "key": cols[14] if len(cols) > 14 else "",
            })
        return rows

    def _airodump_csv_path(self) -> Optional[str]:
        """Return the airodump-ng CSV path produced by ``_client_enum`` if
        its data is populated, else ``None``. Lets the novel probes reuse
        the existing capture instead of re-running airodump-ng."""
        try:
            d = self.recon["clients"].get("data") or {}
            csv = d.get("csv")
            if csv and os.path.exists(csv):
                return csv
        except Exception:  # noqa: BLE001 — defensive, never raise
            return None
        return None

    def _fresh_airodump_csv(self, *, band: str = "",
                            duration_s: int = 15) -> Optional[str]:
        """Run a fresh airodump-ng CSV capture and return the CSV path.
        Used by probes that need a broader/longer sweep than the
        ``_client_enum`` BSSID-locked capture. Returns ``None`` on any
        failure (tool missing, timeout, no file). Never raises."""
        if not shutil.which("airodump-ng"):
            return None
        prefix = (f"/tmp/kfiosa_probe_{self.bssid.replace(':', '')}_"
                  f"{int(time.time())}")
        cmd = ["airodump-ng", self.interface, "-w", prefix,
               "--output-format", "csv", "--berlin", str(duration_s)]
        if band:
            cmd.extend(["--band", band])
        if self.bssid:
            cmd.extend(["--bssid", self.bssid])
        if self.channel:
            cmd.extend(["-c", str(self.channel)])
        try:
            subprocess.run(cmd, capture_output=True, text=True,
                           timeout=duration_s + 10)
        except Exception:  # noqa: BLE001 — timeout/FileNotFoundError/etc
            pass
        path = f"{prefix}-01.csv"
        return path if os.path.exists(path) else None

    def _fresh_airodump_pcap(self, *, duration_s: int = 15) -> Optional[str]:
        """Run a fresh airodump-ng pcap capture (BSSID+channel locked)
        and return the pcap path. Used by handshake/eapol/hidden-ssid
        probes that need frame-level data. Never raises."""
        if not shutil.which("airodump-ng"):
            return None
        prefix = (f"/tmp/kfiosa_pcap_{self.bssid.replace(':', '')}_"
                  f"{int(time.time())}")
        cmd = ["airodump-ng", self.interface, "-w", prefix,
               "--output-format", "pcap", "--berlin", str(duration_s)]
        if self.bssid:
            cmd.extend(["--bssid", self.bssid])
        if self.channel:
            cmd.extend(["-c", str(self.channel)])
        try:
            subprocess.run(cmd, capture_output=True, text=True,
                           timeout=duration_s + 10)
        except Exception:  # noqa: BLE001
            pass
        path = f"{prefix}-01.cap"
        return path if os.path.exists(path) else None

    def _tshark(self, args: List[str], timeout: int = 15) -> Optional[str]:
        """Run tshark with the given argv and return stdout, or ``None``
        if tshark is missing / the call failed. Never raises."""
        if not shutil.which("tshark"):
            return None
        try:
            r = subprocess.run(["tshark"] + args,
                               capture_output=True, text=True, timeout=timeout)
        except Exception:  # noqa: BLE001
            return None
        return r.stdout if r.returncode == 0 else None

    @staticmethod
    def _parse_tshark_table(stdout: str) -> List[List[str]]:
        """Split tshark ``-T fields`` stdout (tab-separated, one row per
        packet) into a list of column lists. Blank lines skipped."""
        out: List[List[str]] = []
        for ln in (stdout or "").splitlines():
            if not ln.strip():
                continue
            out.append(ln.split("\t"))
        return out

    # ------------------------------------------------------------------
    # Step 3: NVD CVE search
    # ------------------------------------------------------------------
    def _cve_search(self) -> Dict[str, Any]:
        started = time.time()
        if not shutil.which("curl") and not _have_requests():
            return _finalize(self.recon["cves"], started, ok=False,
                             error="neither curl nor requests available")
        key = (self.nvd_cfg.get("api_key")
               or self._get_nvd_key())
        base = (self.nvd_cfg.get("base_url") or NVD_ENDPOINT)
        queries = [q for q in (self.ssid, self.vendor) if q and q != "unknown"]
        if not queries:
            return _finalize(self.recon["cves"], started, ok=True,
                             data={"count": 0, "cves": [],
                                   "note": "no usable SSID/vendor query"})
        try:
            import requests
        except ImportError:
            return _finalize(self.recon["cves"], started, ok=False,
                             error="requests not installed")
        all_cves: List[Dict[str, Any]] = []
        last_err: Optional[str] = None
        for q in queries[:2]:  # cap at 2 queries to stay under rate limit
            try:
                r = requests.get(
                    base, headers={"apiKey": key} if key else {},
                    params={"keywordSearch": q, "resultsPerPage": 5},
                    timeout=20,
                )
                if r.status_code != 200:
                    last_err = f"http {r.status_code}"
                    continue
                blobs = r.json().get("vulnerabilities", [])
                for b in blobs:
                    cve = b.get("cve") or {}
                    all_cves.append({
                        "id": cve.get("id"),
                        "published": cve.get("published"),
                        "desc": (cve.get("descriptions", [{}])[0]
                                 .get("value", "")[:240]),
                    })
            except Exception as e:
                last_err = str(e)
        ok = bool(all_cves) or last_err is None
        return _finalize(self.recon["cves"], started, ok=ok,
                         data={"count": len(all_cves), "cves": all_cves,
                               "queries": queries, "last_err": last_err})

    # ------------------------------------------------------------------
    # Step 4: weakpass wordlist
    # ------------------------------------------------------------------
    def _weakpass_wordlist(self) -> Dict[str, Any]:
        started = time.time()
        if not shutil.which("hcxpsktool"):
            return _finalize(self.recon["weakpass"], started, ok=False,
                             error="hcxpsktool not installed")
        if "WPA" not in (self.target.get("encryption", "") or "").upper() \
                and "WPA" not in (self.target.get("privacy", "") or "").upper():
            return _finalize(self.recon["weakpass"], started, ok=True,
                             data={"count": 0, "path": None,
                                   "note": "not WPA/WPA2 — weakpass skipped"})
        self.outdir.mkdir(parents=True, exist_ok=True)
        out = self.outdir / f"weakpass_{self.bssid.replace(':', '')}_{int(time.time())}.txt"
        try:
            r = subprocess.run(
                ["hcxpsktool", "--weakpass", "-o", str(out)],
                capture_output=True, text=True, timeout=300,
            )
        except subprocess.TimeoutExpired:
            return _finalize(self.recon["weakpass"], started, ok=False,
                             error="hcxpsktool timeout")
        except FileNotFoundError:
            return _finalize(self.recon["weakpass"], started, ok=False,
                             error="hcxpsktool not found")
        except Exception as e:
            return _finalize(self.recon["weakpass"], started, ok=False,
                             error=str(e))
        # Cap the file at 100 MB to avoid disk DoS.
        truncated = False
        try:
            if out.exists() and out.stat().st_size > WEAKPASS_MAX_BYTES:
                with open(out, "rb") as fh:
                    data = fh.read(WEAKPASS_MAX_BYTES)
                with open(out, "wb") as fh:
                    fh.write(data)
                truncated = True
        except OSError as e:
            logger.debug("weakpass cap: %s", e)
        size = out.stat().st_size if out.exists() else 0
        return _finalize(self.recon["weakpass"], started,
                         ok=r.returncode == 0 or size > 0,
                         data={"path": str(out), "bytes": size,
                               "truncated": truncated,
                               "rc": r.returncode})

    # ------------------------------------------------------------------
    # Step 5: KB search
    # ------------------------------------------------------------------
    def _kb_search(self) -> Dict[str, Any]:
        started = time.time()
        if self.kb is None:
            return _finalize(self.recon["kb_hits"], started, ok=True,
                             data={"count": 0, "hits": [],
                                   "note": "no KB instance injected"})
        queries: List[str] = []
        if self.ssid:
            queries.append(self.ssid)
        if self.vendor and self.vendor != "unknown":
            queries.append(self.vendor)
        if not queries:
            return _finalize(self.recon["kb_hits"], started, ok=True,
                             data={"count": 0, "hits": [],
                                   "note": "no SSID/vendor for KB query"})
        hits: List[Dict[str, Any]] = []
        try:
            search = getattr(self.kb, "search", None) or getattr(self.kb, "get_tools_for_domain", None)
            if search is None:
                return _finalize(self.recon["kb_hits"], started, ok=False,
                                 error="KB has no search/get_tools_for_domain")
            for q in queries:
                try:
                    res = search(q) if callable(search) else []
                except TypeError:
                    res = self.kb.get_tools_for_domain(q) or []
                for r in (res or [])[:5]:
                    hits.append({
                        "name": r.get("name") or r.get("repo") or "",
                        "url": r.get("url") or "",
                        "description": (r.get("description") or "")[:160],
                    })
        except Exception as e:
            return _finalize(self.recon["kb_hits"], started, ok=False,
                             error=str(e))
        return _finalize(self.recon["kb_hits"], started, ok=True,
                         data={"count": len(hits), "hits": hits,
                               "queries": queries})

    # ------------------------------------------------------------------
    # Step 6: catalog iteration
    # ------------------------------------------------------------------
    def _catalog_iter(self) -> Dict[str, Any]:
        started = time.time()
        if self.catalog_index is None:
            return _finalize(self.recon["catalog_runs"], started, ok=True,
                             data={"count": 0, "runs": [],
                                   "note": "no catalog_index injected"})
        # catalog_index is a dict: name -> CatalogEntry
        # Run anything the catalog advertises that matches the target's
        # toolset, best-effort, dry-run style (we don't re-execute tools
        # here -- the operator already accepted the run; we just record
        # what the catalog would do).
        matches: List[Dict[str, str]] = []
        try:
            for name, entry in (self.catalog_index or {}).items():
                en = entry.matches(["wifi", "wpa", "wps", "aircrack", "hostapd"]) \
                    if hasattr(entry, "matches") else False
                if en:
                    matches.append({
                        "name": name,
                        "install": getattr(entry, "install_apt", "") or "",
                    })
                    if len(matches) >= 5:
                        break
        except Exception as e:
            return _finalize(self.recon["catalog_runs"], started, ok=False,
                             error=str(e))
        return _finalize(self.recon["catalog_runs"], started, ok=True,
                         data={"count": len(matches), "runs": matches})

    # ==================================================================
    # 9 novel passive recon probes
    # ------------------------------------------------------------------
    # Each is ported from a fetched toolboxes/recon repo's algorithm and
    # implemented HERE in Python (reusing airodump-ng / tshark / scapy /
    # gpspipe subprocess + custom parsing) — never a wrapper around the
    # fetched binary. All probes are PASSIVE (risk=low): no deauth, no
    # active PMKID capture, no injection. Active steps remain in the
    # gated attack chain (mt7921e_inject / pmkid / wps_pixie). Every probe
    # returns the standard {ok,error,data} envelope and never raises.
    # ==================================================================

    # ------------------------------------------------------------------
    # Probe 1: probe-request profiling (wifi-hawk / wifi-security-toolkit /
    # airprowl / whoishere.py)
    # ------------------------------------------------------------------
    def _probe_profile(self) -> Dict[str, Any]:
        """Profile client probe-request behaviour (Preferred Network List)
        from the airodump-ng station CSV, with optional scapy enrichment.
        Builds per-client PNL, detects randomized MACs (locally-admin
        bit), and clusters clients sharing >=60% Jaccard probe overlap
        (shared-ownership / same-device hint)."""
        started = time.time()
        try:
            csv = self._airodump_csv_path()
            if not csv:
                csv = self._fresh_airodump_csv(duration_s=12)
            if not csv or not os.path.exists(csv):
                return _finalize(self.recon["probe_profile"], started,
                                 ok=False, error="no airodump-ng CSV to parse")
            stations = self._parse_clients_csv(csv)
            pnl: Dict[str, Dict[str, Any]] = {}
            for st in stations:
                mac = (st.get("mac") or "").upper()
                if not mac:
                    continue
                probed = [s for s in re.split(r"\s*,\s*",
                            (st.get("probes") or "")) if s]
                norm = mac.replace(":", "").replace("-", "")
                second_nibble = norm[1] if len(norm) >= 2 else "0"
                is_rand = second_nibble.upper() in ("2", "6", "A", "E")
                try:
                    rssi = int(st.get("power") or 0)
                except ValueError:
                    rssi = None
                rec = pnl.setdefault(mac, {
                    "mac": mac, "vendor": _vendor_for_bssid(mac, self.oui_path),
                    "probed_ssids": set(), "first_seen": None,
                    "last_seen": None, "rssi_samples": [],
                    "is_randomized": is_rand,
                })
                rec["probed_ssids"].update(probed)
                if rssi is not None:
                    rec["rssi_samples"].append(rssi)
            # Union-find clusters by Jaccard >= 0.6 on probed SSID sets.
            macs = list(pnl.keys())
            parent = {m: m for m in macs}

            def find(x):
                while parent[x] != x:
                    parent[x] = parent[parent[x]]
                    x = parent[x]
                return x

            def union(a, b):
                ra, rb = find(a), find(b)
                if ra != rb:
                    parent[ra] = rb

            for i in range(len(macs)):
                si = pnl[macs[i]]["probed_ssids"]
                for j in range(i + 1, len(macs)):
                    sj = pnl[macs[j]]["probed_ssids"]
                    if not si or not sj:
                        continue
                    inter = len(si & sj)
                    union_sz = len(si | sj)
                    if union_sz and inter / union_sz >= 0.6:
                        union(macs[i], macs[j])
            clusters: Dict[str, List[str]] = {}
            for m in macs:
                clusters.setdefault(find(m), []).append(m)
            shared = [c for c in clusters.values() if len(c) > 1]
            # Optional scapy enrichment (live probe-request RSSI samples).
            scapy_note = None
            try:
                from scapy.all import sniff, Dot11ProbeReq  # type: ignore
                def _cb(p):
                    try:
                        dot = p.getlayer(Dot11ProbeReq)
                        if dot is None:
                            return
                        mac = (getattr(dot, "addr2", "") or "").upper()
                        if not mac:
                            return
                        rec = pnl.setdefault(mac, {
                            "mac": mac, "vendor": _vendor_for_bssid(mac, self.oui_path),
                            "probed_ssids": set(), "first_seen": None,
                            "last_seen": None, "rssi_samples": [],
                            "is_randomized": False,
                        })
                        rssi = int(getattr(p, "dBm_AntSignal", -100) or -100)
                        rec["rssi_samples"].append(rssi)
                    except Exception:  # noqa: BLE001
                        pass
                sniff(iface=self.interface, lfilter=lambda p: p.haslayer(Dot11ProbeReq),
                      timeout=12, store=0, prn=_cb)
                scapy_note = "scapy enrichment ok"
            except ImportError:
                scapy_note = "scapy not installed — CSV-only profile"
            except Exception as e:  # noqa: BLE001
                scapy_note = f"scapy enrichment skipped: {e}"
            # Optional watchlist (data/probe_watchlist.json {mac: name}).
            watchlist_hits: List[Dict[str, str]] = []
            wl_path = PROJECT_ROOT / "data" / "probe_watchlist.json"
            if wl_path.exists():
                try:
                    wl = json.loads(wl_path.read_text(encoding="utf-8"))
                    for mac, name in (wl or {}).items():
                        if mac.upper() in pnl:
                            watchlist_hits.append({"mac": mac.upper(), "name": name})
                except (OSError, json.JSONDecodeError):
                    pass
            # Serialise sets -> sorted lists for JSON.
            pnl_out = []
            for mac, rec in pnl.items():
                pnl_out.append({
                    "mac": mac, "vendor": rec["vendor"],
                    "probed_ssids": sorted(rec["probed_ssids"]),
                    "rssi_samples": rec["rssi_samples"][-8:],
                    "is_randomized": rec["is_randomized"],
                })
            ok = bool(pnl_out)
            return _finalize(self.recon["probe_profile"], started, ok=ok,
                             data={"clients_profiled": len(pnl_out),
                                   "pnl": pnl_out,
                                   "shared_ownership_clusters": shared,
                                   "watchlist_hits": watchlist_hits,
                                   "scapy": scapy_note})
        except Exception as e:  # noqa: BLE001 — never raise
            return _finalize(self.recon["probe_profile"], started,
                             ok=False, error=str(e))

    # ------------------------------------------------------------------
    # Probe 2: hidden-SSID reveal (wifi-security-toolkit / pineapple-suite)
    # ------------------------------------------------------------------
    def _hidden_ssid(self) -> Dict[str, Any]:
        """Passively reveal a hidden SSID from probe-responses /
        association-requests / probe-requests in a BSSID-locked pcap
        (tshark). Active deauth-to-force-reveal stays in the gated
        ``mt7921e_inject deauth`` action — this step only observes."""
        started = time.time()
        try:
            if not self.bssid:
                return _finalize(self.recon["hidden_ssid"], started,
                                 ok=False, error="no bssid in target")
            pcap = self._fresh_airodump_pcap(duration_s=15)
            if not pcap:
                return _finalize(self.recon["hidden_ssid"], started,
                                 ok=False, error="airodump-ng pcap capture failed")
            revealed = None
            source_frame = None
            client_mac = None
            if shutil.which("tshark"):
                # Probe-resp(5) / Assoc-req(0) / Probe-req(4) carry the
                # cleartext SSID even when beacons blank it.
                out = self._tshark([
                    "-r", pcap,
                    "-Y", ("wlan.fc.type_subtype==0x0005 || "
                           "wlan.fc.type_subtype==0x0000 || "
                           "wlan.fc.type_subtype==0x0004"),
                    "-Tfields", "-e", "wlan.ssid", "-e", "wlan.bssid",
                    "-e", "wlan.sa", "-e", "wlan.fc.type_subtype",
                ], timeout=15)
                _SUB = {"0": "assoc-req", "4": "probe-req", "5": "probe-resp"}
                for cols in self._parse_tshark_table(out or ""):
                    ssid = cols[0].strip() if len(cols) > 0 else ""
                    bssid = cols[1].strip().upper() if len(cols) > 1 else ""
                    sa = cols[2].strip() if len(cols) > 2 else ""
                    sub = cols[3].strip() if len(cols) > 3 else ""
                    if bssid == self.bssid and ssid:
                        revealed = ssid
                        source_frame = _SUB.get(sub, sub)
                        client_mac = sa or None
                        break
            # hidden = every beacon for this BSSID has an empty SSID.
            hidden = True
            if shutil.which("tshark"):
                out = self._tshark([
                    "-r", pcap, "-Y",
                    f"wlan.fc.type_subtype==0x0008 && wlan.bssid=={self.bssid}",
                    "-Tfields", "-e", "wlan.ssid",
                ], timeout=15)
                for cols in self._parse_tshark_table(out or ""):
                    if cols and cols[0].strip():
                        hidden = False
                        break
            else:
                hidden = revealed is None  # unknown without tshark
            return _finalize(self.recon["hidden_ssid"], started, ok=True,
                             data={"hidden": hidden,
                                   "revealed_ssid": revealed,
                                   "source_frame": source_frame,
                                   "client_mac": client_mac,
                                   "pcap": pcap})
        except Exception as e:  # noqa: BLE001
            return _finalize(self.recon["hidden_ssid"], started,
                             ok=False, error=str(e))

    # ------------------------------------------------------------------
    # Probe 3: signal map + RF exposure (Spectre / airprowl)
    # ------------------------------------------------------------------
    def _signal_map(self) -> Dict[str, Any]:
        """Map per-AP RSSI with EMA smoothing, log-distance path-loss
        distance estimate, a confidence label, and a physically-correct
        total RF-exposure dBm via linear power summation (Spectre)."""
        started = time.time()
        try:
            aps: List[Dict[str, Any]] = []
            try:
                aps = (self.recon["clients"].get("data") or {}).get("aps") or []
            except Exception:  # noqa: BLE001
                aps = []
            if not aps:
                csv = self._fresh_airodump_csv(duration_s=10)
                if csv:
                    aps = self._parse_aps_csv(csv)
            if not aps:
                return _finalize(self.recon["signal_map"], started,
                                 ok=False, error="no AP entries to map")
            ref = _PATHLOSS_REF_RSSI
            n = _PATHLOSS_N
            if self.settings:
                try:
                    ref = int(self.settings.get_setting("wifi.pathloss.ref_rssi") or ref)
                    n = float(self.settings.get_setting("wifi.pathloss.n") or n)
                except Exception:  # noqa: BLE001
                    pass
            entries: List[Dict[str, Any]] = []
            all_rssi: List[float] = []
            for ap in aps:
                try:
                    rssi = int(ap.get("power") or 0)
                except ValueError:
                    continue
                if rssi == 0:
                    continue
                mac = (ap.get("bssid") or "").upper()
                prev = self._sig_cache.get(mac)
                ema = rssi if prev is None else 0.4 * rssi + 0.6 * prev
                self._sig_cache[mac] = ema
                # log-distance: distance = 10**((rssi-ref)/(10*n))
                try:
                    dist = 10 ** ((rssi - ref) / (10 * n))
                except Exception:  # noqa: BLE001
                    dist = None
                if rssi >= -55:
                    conf = "high"
                elif rssi >= -70:
                    conf = "med"
                else:
                    conf = "low"
                entries.append({
                    "mac": mac, "ssid": ap.get("ssid") or "",
                    "channel": ap.get("channel") or "",
                    "rssi_dbm": rssi, "rssi_ema": round(ema, 1),
                    "distance_m": round(dist, 1) if dist else None,
                    "confidence": conf,
                })
                all_rssi.append(rssi)
            # Linear power summation (mW) -> back to dBm.
            total = None
            if all_rssi:
                try:
                    mw = sum(10 ** (r / 10) for r in all_rssi)
                    total = round(10 * math.log10(mw), 1) if mw > 0 else None
                except Exception:  # noqa: BLE001
                    total = None
            ok = bool(entries)
            return _finalize(self.recon["signal_map"], started, ok=ok,
                             data={"entries": entries,
                                   "total_exposure_dbm": total})
        except Exception as e:  # noqa: BLE101
            return _finalize(self.recon["signal_map"], started,
                             ok=False, error=str(e))

    # ------------------------------------------------------------------
    # Probe 4: handshake harvest (wifi-security-toolkit)
    # ------------------------------------------------------------------
    def _handshake_harvest(self) -> Dict[str, Any]:
        """Passively detect EAPOL M1-M4 frames in a BSSID-locked pcap and
        score PMKID capture feasibility (RSN + PSK AKM + PMKID-friendly
        vendor). Does NOT run hcxdumptool or force a deauth — those are
        the gated ``pmkid`` / ``mt7921e_inject`` chain actions."""
        started = time.time()
        try:
            if not self.bssid:
                return _finalize(self.recon["handshake_harvest"], started,
                                 ok=False, error="no bssid in target")
            pcap = self._fresh_airodump_pcap(duration_s=15)
            if not pcap:
                return _finalize(self.recon["handshake_harvest"], started,
                                 ok=False, error="airodump-ng pcap capture failed")
            msgs: List[str] = []
            eapol_count = 0
            if shutil.which("tshark"):
                out = self._tshark([
                    "-r", pcap, "-Y", "eapol",
                    "-Tfields", "-e", "wlan.sa", "-e", "wlan.da",
                    "-e", "eapol.type", "-e", "eapol.key.key_type",
                    "-e", "eapol.key.installed",
                ], timeout=15)
                for cols in self._parse_tshark_table(out or ""):
                    eapol_count += 1
                    ktype = cols[3].strip() if len(cols) > 3 else ""
                    inst = cols[4].strip() if len(cols) > 4 else ""
                    # Best-effort M1-M4 classification from key info.
                    # M1/M4 share key_type=0; M2/M3 share key_type=1, so the
                    # installed bit disambiguates: installed=1 -> M3 or M4,
                    # installed=0/"" -> M1 or M2. Check installed first.
                    if ktype in ("1",) and inst in ("1", "True"):
                        msgs.append("M3")
                    elif ktype in ("1",) and inst in ("0", "False", ""):
                        msgs.append("M2")
                    elif ktype in ("0", "") and inst in ("1", "True"):
                        msgs.append("M4")
                    elif ktype in ("0", ""):
                        msgs.append("M1")
            have = set(msgs)
            handshake_complete = {"M1", "M2", "M3", "M4"}.issubset(have) if msgs else False
            # PMKID feasibility (best-effort RSN/AKM read).
            pmkid_feasible: Optional[bool] = None
            if shutil.which("tshark"):
                out = self._tshark([
                    "-r", pcap, "-Y",
                    f"wlan.fc.type_subtype==0x0008 && wlan.bssid=={self.bssid}",
                    "-Tfields", "-e", "wlan.rsn.akm", "-e", "wlan.rsn.pcs",
                ], timeout=15)
                akms: List[str] = []
                for cols in self._parse_tshark_table(out or ""):
                    akms.append(cols[0].strip() if cols else "")
                akm_set = set("".join(akms).replace(",", " ").split())
                pmid_ok = {"1"} & akm_set  # PSK
                pmk_friendly_vendor = self.vendor in {"TP-Link", "Netgear",
                                                      "D-Link", "ASUS"}
                pmkid_feasible = bool(pmid_ok) and pmk_friendly_vendor
            return _finalize(self.recon["handshake_harvest"], started, ok=True,
                             data={"eapol_frames": eapol_count,
                                   "eapol_messages": sorted(have),
                                   "handshake_complete": handshake_complete,
                                   "pmkid_feasible": pmkid_feasible,
                                   "pcap": pcap})
        except Exception as e:  # noqa: BLE001
            return _finalize(self.recon["handshake_harvest"], started,
                             ok=False, error=str(e))

    # ------------------------------------------------------------------
    # Probe 5: EAP / 802.1X monitor (wifi-security-toolkit)
    # ------------------------------------------------------------------
    def _eapol_monitor(self) -> Dict[str, Any]:
        """Extract EAP method types and cleartext identities (usernames /
        realms) from an 802.1X enterprise exchange to flag
        ``is_enterprise`` and identify the auth method (PEAP/TTLS/FAST/
        LEAP/MD5)."""
        started = time.time()
        try:
            # Reuse the handshake_harvest pcap if present, else capture.
            pcap = None
            try:
                hh = self.recon["handshake_harvest"].get("data") or {}
                p = hh.get("pcap")
                if p and os.path.exists(p):
                    pcap = p
            except Exception:  # noqa: BLE001
                pcap = None
            if not pcap:
                pcap = self._fresh_airodump_pcap(duration_s=15)
            if not pcap:
                return _finalize(self.recon["eapol_monitor"], started,
                                 ok=False, error="no pcap to analyse")
            if not shutil.which("tshark"):
                return _finalize(self.recon["eapol_monitor"], started,
                                 ok=False, error="tshark not installed")
            out = self._tshark([
                "-r", pcap, "-Y", "eap || eapol",
                "-Tfields", "-e", "eap.code", "-e", "eap.type",
                "-e", "eap.identity", "-e", "wlan.bssid",
            ], timeout=15)
            methods: List[Dict[str, Any]] = []
            identities: List[str] = []
            eapol_count = 0
            seen_methods: set = set()
            for cols in self._parse_tshark_table(out or ""):
                eapol_count += 1
                code = cols[0].strip() if len(cols) > 0 else ""
                etype = cols[1].strip() if len(cols) > 1 else ""
                ident = cols[2].strip() if len(cols) > 2 else ""
                if etype and etype.isdigit() and int(etype) in _EAP_TYPES:
                    name = _EAP_TYPES[int(etype)]
                    if name not in seen_methods:
                        seen_methods.add(name)
                        methods.append({"code": int(etype), "name": name})
                if ident:
                    identities.append(ident)
            enterprise_types = {"PEAP", "TTLS", "FAST", "LEAP", "GTC"}
            is_ent = bool(seen_methods & enterprise_types) or bool(identities)
            return _finalize(self.recon["eapol_monitor"], started, ok=True,
                             data={"eapol_count": eapol_count,
                                   "eap_methods": methods,
                                   "eap_identities": identities,
                                   "is_enterprise": is_ent,
                                   "pcap": pcap})
        except Exception as e:  # noqa: BLE001
            return _finalize(self.recon["eapol_monitor"], started,
                             ok=False, error=str(e))

    # ------------------------------------------------------------------
    # Probe 6: channel congestion + hop plan (wifi-security-toolkit /
    # airprowl / pineapple-suite)
    # ------------------------------------------------------------------
    def _channel_plan(self) -> Dict[str, Any]:
        """Survey channel congestion across 2.4+5 GHz and produce a
        recommended channel-hop dwell plan (dwell scaled by AP density),
        with the target channel pinned first."""
        started = time.time()
        try:
            csv = self._fresh_airodump_csv(band="abg", duration_s=15)
            if not csv:
                return _finalize(self.recon["channel_plan"], started,
                                 ok=False, error="airodump-ng survey failed")
            aps = self._parse_aps_csv(csv)
            if not aps:
                return _finalize(self.recon["channel_plan"], started,
                                 ok=False, error="no APs in survey")
            per_chan: Dict[str, List[Dict[str, Any]]] = {}
            for ap in aps:
                ch = str(ap.get("channel") or "").strip()
                if not ch or ch in ("-1", "-2"):
                    continue
                per_chan.setdefault(ch, []).append(ap)
            channels: List[Dict[str, Any]] = []
            for ch, lst in per_chan.items():
                rssi_vals = []
                for ap in lst:
                    try:
                        rssi_vals.append(int(ap.get("power") or 0))
                    except ValueError:
                        pass
                max_rssi = max(rssi_vals) if rssi_vals else None
                ci = _chan_freq(ch)
                # Congestion: APs on same channel + adjacent 20MHz chans.
                adjacent = 0
                try:
                    chi = int(ch)
                except ValueError:
                    chi = None
                if chi is not None and not _is_band_5ghz(chi):
                    for och in per_chan:
                        try:
                            oci = int(och)
                        except ValueError:
                            continue
                        if abs(oci - chi) <= 2 and not _is_band_5ghz(oci):
                            adjacent += len(per_chan[och])
                congestion = len(lst) + adjacent
                channels.append({
                    "channel": ch, "band": "5GHz" if _is_band_5ghz(ch) else "2.4GHz",
                    "freq_mhz": ci, "ap_count": len(lst),
                    "max_rssi": max_rssi, "congestion": congestion,
                })
            channels.sort(key=lambda c: (c["congestion"], -(c["max_rssi"] or -200)),
                          reverse=True)
            hop = []
            for c in channels:
                dwell = max(2, min(8, 2 + c["ap_count"]))
                hop.append({"channel": c["channel"], "dwell_s": dwell})
            if self.channel:
                hop.insert(0, {"channel": str(self.channel), "dwell_s": 10})
            tgt_congestion = None
            tgt = next((c for c in channels if c["channel"] == str(self.channel)),
                       None)
            if tgt:
                tgt_congestion = tgt["congestion"]
            return _finalize(self.recon["channel_plan"], started, ok=True,
                             data={"channels": channels,
                                   "recommended_hop_plan": hop,
                                   "target_channel_congestion": tgt_congestion})
        except Exception as e:  # noqa: BLE001
            return _finalize(self.recon["channel_plan"], started,
                             ok=False, error=str(e))

    # ------------------------------------------------------------------
    # Probe 7: deauth / disassoc / probe flood + evil-twin detect
    # (wifi-security-toolkit / pineapple-suite)
    # ------------------------------------------------------------------
    def _deauth_detect(self) -> Dict[str, Any]:
        """Passively count deauth/disassoc/probe frames over a 20s window
        to flag a deauth flood (>=15), a probe flood (>=50), and
        evil-twin candidates (same SSID on >=2 distinct BSSIDs). Uses
        scapy if available, else tshark live capture."""
        started = time.time()
        try:
            deauth_count = 0
            disassoc_count = 0
            probe_count = 0
            ssid_bssids: Dict[str, set] = {}
            client_macs: set = set()
            have_sniffer = False
            # Prefer scapy (richer per-frame access).
            try:
                from scapy.all import sniff, Dot11Deauth, Dot11Disas, \
                    Dot11ProbeReq, Dot11, Dot11Beacon, Dot11ProbeResp  # type: ignore

                def _cb(p):
                    nonlocal deauth_count, disassoc_count, probe_count
                    try:
                        if p.haslayer(Dot11Deauth):
                            deauth_count += 1
                        if p.haslayer(Dot11Disas):
                            disassoc_count += 1
                        if p.haslayer(Dot11ProbeReq):
                            probe_count += 1
                            d = p.getlayer(Dot11)
                            mac = (getattr(d, "addr2", "") or "").upper()
                            if mac:
                                client_macs.add(mac)
                        if p.haslayer(Dot11Beacon) or p.haslayer(Dot11ProbeResp):
                            d = p.getlayer(Dot11)
                            ssid = getattr(p, "info", "") or ""
                            bssid = (getattr(d, "addr3", "") or getattr(d, "addr2", "") or "").upper()
                            if ssid and bssid:
                                ssid_bssids.setdefault(ssid, set()).add(bssid)
                    except Exception:  # noqa: BLE001
                        pass

                sniff(iface=self.interface, timeout=20, store=0, prn=_cb,
                      lfilter=lambda p: p.haslayer(Dot11))
                have_sniffer = True
            except ImportError:
                pass
            except Exception:  # noqa: BLE001
                # scapy present but sniff failed (bad iface, perms) — fall
                # back to tshark if available. ``have_sniffer`` stays
                # False so the post-sniff branch can short-circuit to
                # the tshark path or the honest-degrade error.
                pass
            if not have_sniffer and shutil.which("tshark"):
                out = self._tshark([
                    "-i", self.interface, "-a", "duration:20",
                    "-Y", ("wlan.fc.type_subtype==0x000c || "
                           "wlan.fc.type_subtype==0x000a || "
                           "wlan.fc.type_subtype==0x0004"),
                    "-Tfields", "-e", "wlan.bssid", "-e", "wlan.ssid",
                    "-e", "wlan.fc.type_subtype", "-e", "wlan.sa",
                ], timeout=25)
                for cols in self._parse_tshark_table(out or ""):
                    sub = cols[2].strip() if len(cols) > 2 else ""
                    ssid = cols[1].strip() if len(cols) > 1 else ""
                    bssid = cols[0].strip().upper() if len(cols) > 0 else ""
                    sa = cols[3].strip().upper() if len(cols) > 3 else ""
                    if sub == "0x000c":
                        deauth_count += 1
                    elif sub == "0x000a":
                        disassoc_count += 1
                    elif sub == "0x0004":
                        probe_count += 1
                        if sa:
                            client_macs.add(sa)
                    if ssid and bssid:
                        ssid_bssids.setdefault(ssid, set()).add(bssid)
                have_sniffer = True
            if not have_sniffer:
                return _finalize(self.recon["deauth_detect"], started,
                                 ok=False, error="no frame sniffer available")
            evil_twin = [
                {"ssid": ssid, "bssids": sorted(bssids)}
                for ssid, bssids in ssid_bssids.items() if len(bssids) >= 2
            ]
            return _finalize(self.recon["deauth_detect"], started, ok=True,
                             data={"deauth_count": deauth_count,
                                   "deauth_flood": deauth_count >= 15,
                                   "disassoc_count": disassoc_count,
                                   "probe_count": probe_count,
                                   "probe_flood": probe_count >= 50,
                                   "evil_twin_candidates": evil_twin,
                                   "mac_churn": len(client_macs)})
        except Exception as e:  # noqa: BLE001
            return _finalize(self.recon["deauth_detect"], started,
                             ok=False, error=str(e))

    # ------------------------------------------------------------------
    # Probe 8: GPS wardrive + WiGLE CSV + offline fusion
    # (iSniff-GPS-ng / airspace-mapper / wifi-hawk / wifi-security-toolkit)
    # ------------------------------------------------------------------
    def _gps_wardrive(self) -> Dict[str, Any]:
        """Tag discovered APs with a GPS fix (gpspipe/gpsd) and emit a
        WiGLE-1.4 CSV; if the target carries offline artifacts
        (a .22000 hash file + a signal TSV + a GPX track), fuse them into
        geo-located targets by nearest-trackpoint-within-±300s."""
        started = time.time()
        try:
            # Live GPS fix.
            gps: Dict[str, Any] = {"lat": None, "lon": None, "fix": "no_gpsd"}
            if shutil.which("gpspipe"):
                try:
                    r = subprocess.run(["gpspipe", "-w", "-n", "1"],
                                       capture_output=True, text=True, timeout=5)
                    for ln in (r.stdout or "").splitlines():
                        try:
                            obj = json.loads(ln)
                        except (json.JSONDecodeError, ValueError):
                            continue
                        if "lat" in obj and "lon" in obj and obj.get("mode", 0) >= 2:
                            gps = {"lat": obj["lat"], "lon": obj["lon"],
                                   "fix": "gpsd", "alt": obj.get("alt")}
                            break
                except Exception:  # noqa: BLE001
                    gps["fix"] = "gpspipe_error"
            # AP list (reuse client_enum APs, else fresh survey).
            aps: List[Dict[str, Any]] = []
            try:
                aps = (self.recon["clients"].get("data") or {}).get("aps") or []
            except Exception:  # noqa: BLE001
                aps = []
            csv_path = None
            if aps:
                try:
                    self.outdir.mkdir(parents=True, exist_ok=True)
                    ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
                    csv_path = self.outdir / f"wigle_{ts}.csv"
                    lines = ["WigleWifi-1.4,appRelease=kfiosa,model=cli,"
                             "release=kfiosa,device=kfiosa,board=,"
                             "brand=kfiosa,star=Sol,Moon,Moon "
                             "phase,radio=kfiosa,uuid=kfiosa"]
                    lines.append(
                        "MAC,SSID,AuthMode,FirstSeen,Channel,RSSI,"
                        "CurrentLatitude,CurrentLongitude,AltitudeMeters,"
                        "AccuracyMeters,Type")
                    for ap in aps:
                        lines.append(",".join([
                            ap.get("bssid", ""),
                            (ap.get("ssid") or "").replace(",", " "),
                            ap.get("privacy", "") or "[ESS]",
                            ap.get("first_seen", "") or ts,
                            ap.get("channel", ""),
                            ap.get("power", ""),
                            str(gps.get("lat") or ""),
                            str(gps.get("lon") or ""),
                            str(gps.get("alt") or ""),
                            "0", "WIFI"
                        ]))
                    csv_path.write_text("\n".join(lines) + "\n",
                                        encoding="utf-8")
                    csv_path = str(csv_path)
                except Exception as e:  # noqa: BLE001
                    csv_path = None
            # Offline fusion (.22000 + TSV + GPX) if artifacts supplied.
            fused: List[Dict[str, Any]] = []
            artifacts = self.target.get("artifacts") or {}
            hfile = artifacts.get("h22000")
            tsv = artifacts.get("tsv")
            gpx = artifacts.get("gpx")
            if hfile and os.path.exists(hfile):
                fused = self._fuse_wardrive_artifacts(hfile, tsv, gpx)
            note = "gps+wigle" if csv_path else ("no APs to emit" if not aps
                                                 else "wigle write failed")
            return _finalize(self.recon["gps_wardrive"], started, ok=True,
                             data={"gps": gps, "wigle_csv": csv_path,
                                   "fused_targets": fused, "note": note})
        except Exception as e:  # noqa: BLE001
            return _finalize(self.recon["gps_wardrive"], started,
                             ok=False, error=str(e))

    def _fuse_wardrive_artifacts(self, hfile: str,
                                 tsv: Optional[str],
                                 gpx: Optional[str]) -> List[Dict[str, Any]]:
        """Fuse a hashcat .22000 file (AP MAC + SSID), a signal TSV
        (timestamp\\tsignal\\tmac), and a GPX track into geo-located
        targets. Nearest GPX trkpt within ±300s of each MAC's earliest
        TSV timestamp. Best-effort; never raises."""
        out: List[Dict[str, Any]] = []
        try:
            def _norm_mac(m: str) -> str:
                return (m or "").upper().replace(":", "").replace("-", "").replace(".", "")

            seen: Dict[str, Dict[str, Any]] = {}
            with open(hfile, "r", encoding="utf-8", errors="replace") as fh:
                for ln in fh:
                    parts = ln.strip().split("*")
                    if len(parts) < 6:
                        continue
                    mac = _norm_mac(parts[3])
                    ssid_hex = parts[5] or ""
                    try:
                        ssid = bytes.fromhex(ssid_hex).decode(
                            "utf-8", errors="replace")
                    except ValueError:
                        ssid = ssid_hex
                    if mac:
                        seen[mac] = {"ssid": ssid, "mac": mac,
                                     "vendor": _vendor_for_bssid(mac, self.oui_path)}
            # Strongest signal per MAC from TSV (normalize so colon and
            # no-colon forms match the .22000 keys).
            if tsv and os.path.exists(tsv):
                best_sig: Dict[str, int] = {}
                best_ts: Dict[str, float] = {}
                with open(tsv, "r", encoding="utf-8", errors="replace") as fh:
                    for ln in fh:
                        c = ln.strip().split("\t")
                        if len(c) < 3:
                            continue
                        try:
                            ts = float(c[0]); sig = int(c[1])
                        except ValueError:
                            continue
                        mac = _norm_mac(c[2])
                        if mac not in best_sig or sig > best_sig[mac]:
                            best_sig[mac] = sig
                            best_ts[mac] = ts
                for mac, info in seen.items():
                    info["rssi"] = best_sig.get(mac, -100)
                    info["ts"] = best_ts.get(mac)
            # Nearest GPX trackpoint within ±300s.
            if gpx and os.path.exists(gpx):
                trkpts = self._parse_gpx(gpx)
                for mac, info in seen.items():
                    ts = info.get("ts")
                    if ts is None or not trkpts:
                        continue
                    nearest = min(trkpts, key=lambda t: abs(t["time"] - ts))
                    if abs(nearest["time"] - ts) <= 300:
                        info["lat"] = nearest["lat"]
                        info["lon"] = nearest["lon"]
            out = list(seen.values())
        except Exception as e:  # noqa: BLE001
            logger.debug("wardrive fusion failed: %s", e)
        return out

    @staticmethod
    def _parse_gpx(path: str) -> List[Dict[str, Any]]:
        """Minimal GPX <trkpt lat= lon=><time>…</time></trkpt> parse to
        ``[{lat,lon,time}]`` (time as epoch seconds). Returns [] on any
        failure. Never raises."""
        try:
            import xml.etree.ElementTree as ET
            from datetime import datetime, timezone
            tree = ET.parse(path)
            pts: List[Dict[str, Any]] = []
            for tp in tree.iter("trkpt"):
                lat = tp.get("lat"); lon = tp.get("lon")
                te = tp.find("time")
                if lat is None or lon is None or te is None or not te.text:
                    continue
                try:
                    dt = datetime.fromisoformat(te.text.replace("Z", "+00:00"))
                    epoch = dt.timestamp()
                except ValueError:
                    continue
                pts.append({"lat": float(lat), "lon": float(lon),
                            "time": epoch})
            return pts
        except Exception:  # noqa: BLE001
            return []

    # ------------------------------------------------------------------
    # Probe 9: beacon / RSN IE parse (blockade-recon / wifi-recon /
    # Wavescout / wifi-security-toolkit)
    # ------------------------------------------------------------------
    def _beacon_parse(self) -> Dict[str, Any]:
        """Decode the target AP's beacon RSN/RSN IE: group & pairwise
        ciphers, AKM(s), PMF state, WPS presence, WPA3 (SAE/OWE)
        detection, channel width, and a stable fingerprint hash — all
        passive, from tshark on a BSSID-locked capture."""
        started = time.time()
        try:
            if not self.bssid:
                return _finalize(self.recon["beacon_parse"], started,
                                 ok=False, error="no bssid in target")
            if not shutil.which("tshark"):
                return _finalize(self.recon["beacon_parse"], started,
                                 ok=False, error="tshark not installed")
            # Prefer a live capture on the target's beacon stream.
            out = self._tshark([
                "-i", self.interface, "-a", "duration:8",
                "-Y", f"wlan.fc.type_subtype==0x0008 && wlan.bssid=={self.bssid}",
                "-Tfields", "-e", "wlan.ssid", "-e", "wlan.bssid",
                "-e", "wlan.rsn.gcs", "-e", "wlan.rsn.pcs",
                "-e", "wlan.rsn.akm", "-e", "wlan.fixed.capabilities.pmf",
                "-e", "wlan.fc.channel",
            ], timeout=12)
            rows = self._parse_tshark_table(out or "")
            if not rows:
                # Fall back to any handshake_harvest pcap we already have.
                try:
                    pcap = (self.recon["handshake_harvest"].get("data") or {}).get("pcap")
                except Exception:  # noqa: BLE001
                    pcap = None
                if pcap and os.path.exists(pcap):
                    out = self._tshark([
                        "-r", pcap, "-Y",
                        f"wlan.fc.type_subtype==0x0008 && wlan.bssid=={self.bssid}",
                        "-Tfields", "-e", "wlan.ssid", "-e", "wlan.bssid",
                        "-e", "wlan.rsn.gcs", "-e", "wlan.rsn.pcs",
                        "-e", "wlan.rsn.akm",
                        "-e", "wlan.fixed.capabilities.pmf",
                        "-e", "wlan.fc.channel",
                    ], timeout=12)
                    rows = self._parse_tshark_table(out or "")
            if not rows:
                return _finalize(self.recon["beacon_parse"], started,
                                 ok=False, error="no beacon frames captured")
            cols = rows[0]
            ssid = cols[0].strip() if len(cols) > 0 else ""
            gcs = cols[2].strip() if len(cols) > 2 else ""
            pcs_raw = cols[3].strip() if len(cols) > 3 else ""
            akm_raw = cols[4].strip() if len(cols) > 4 else ""
            pmf_raw = cols[5].strip() if len(cols) > 5 else ""
            ch = cols[6].strip() if len(cols) > 6 else str(self.channel or "")
            akms = [a for a in re.split(r"[,\s]+", akm_raw) if a]
            akm_names = [_AKM_CODES.get(a, a) for a in akms]
            pcs = [p for p in re.split(r"[,\s]+", pcs_raw) if p]
            pcs_names = [_CIPHER_CODES.get(p, p) for p in pcs]
            is_wpa3 = any(a in {"8", "9", "12", "18"} for a in akms)
            pmf_state = {"0": "disabled", "1": "capable",
                         "2": "required"}.get(pmf_raw, "unknown")
            # WPS = vendor-specific tag with WPS OUI 00:37:2A.
            wps = False
            wps_out = self._tshark([
                "-i", self.interface, "-a", "duration:6",
                "-Y", f"wlan.fc.type_subtype==0x0008 && wlan.bssid=={self.bssid}",
                "-Tfields", "-e", "wlan.tag.number",
            ], timeout=10) if shutil.which("tshark") else None
            for tcols in self._parse_tshark_table(wps_out or ""):
                if tcols and "221" in (tcols[0] or ""):
                    wps = True
                    break
            import hashlib
            fp = hashlib.sha1("|".join([
                self.bssid, ssid, gcs, pcs_raw, akm_raw, pmf_raw, str(ch),
            ]).encode("utf-8", errors="replace")).hexdigest()[:12]
            return _finalize(self.recon["beacon_parse"], started, ok=True,
                             data={"ap": {
                                 "ssid": ssid, "bssid": self.bssid,
                                 "channel": ch, "width": "20",
                                 "group_cipher": _CIPHER_CODES.get(gcs, gcs),
                                 "pairwise_ciphers": pcs_names,
                                 "akms": akm_names, "is_wpa3": is_wpa3,
                                 "pmf": pmf_state, "wps": wps,
                             }, "fingerprint_hash": fp})
        except Exception as e:  # noqa: BLE001
            return _finalize(self.recon["beacon_parse"], started,
                             ok=False, error=str(e))

    # ------------------------------------------------------------------
    # Probe dispatch
    # ------------------------------------------------------------------
    #: The 6 core recon steps (also run bundled by :meth:`run`), surfaced
    #: individually so the AI chain can drive them as gated ``recon_probe``
    #: steps. Map ``method`` -> the implementing ``self._<fn>`` name (the
    #: core steps pre-date the ``_<method>`` naming convention).
    _CORE_STEP_FNS: Dict[str, str] = {
        "wps": "_wps_probe",
        "clients": "_client_enum",
        "cves": "_cve_search",
        "weakpass": "_weakpass_wordlist",
        "kb_hits": "_kb_search",
        "catalog_runs": "_catalog_iter",
    }

    #: All dispatchable recon_probe methods: the 6 core steps + the 9
    #: novel passive probes, in stable order.
    RECON_PROBE_METHODS: Tuple[str, ...] = (
        "wps", "clients", "cves", "weakpass", "kb_hits", "catalog_runs",
        "probe_profile", "hidden_ssid", "signal_map", "handshake_harvest",
        "eapol_monitor", "channel_plan", "deauth_detect", "gps_wardrive",
        "beacon_parse",
    )

    def run_probe(self, method: str) -> Dict[str, Any]:
        """Run a single recon probe by name. Returns that probe's step
        dict (the same shape stored in ``self.recon[method]``). Accepts
        the 6 core steps (wps/clients/cves/weakpass/kb_hits/catalog_runs)
        and the 9 novel passive probes. Unknown method ->
        {ok:false, error:'unknown probe method'}. Never raises."""
        m = (method or "").strip()
        if m not in self.RECON_PROBE_METHODS:
            step = self.recon.get(m) or _step(m)
            return _finalize(step, time.time(), ok=False,
                             error=f"unknown probe method: {method!r}")
        fn_name = self._CORE_STEP_FNS.get(m, f"_{m}")
        fn = getattr(self, fn_name)
        try:
            return fn()
        except Exception as e:  # noqa: BLE001 — defensive double-net
            step = self.recon[m]
            step["ok"] = False
            step["error"] = f"unhandled: {e}"
            return step

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------
    def run(self, with_probes: bool = False) -> Dict[str, Any]:
        """Run the six core recon steps sequentially, then optionally the
        nine novel passive probes. Returns the full recon dict.

        Each step is best-effort: a failure in one step does not block
        the rest. ``with_probes=False`` (default) keeps the original
        six-step pre-chain pass byte-identical; ``with_probes=True``
        also runs the nine ``recon_probe`` algorithms so the operator
        gets the enhanced passive recon pass in one shot. The nine
        probes are always available individually via
        :meth:`run_probe` / the ``recon_probe`` chain action.
        """
        steps = (
            ("wps", self._wps_probe),
            ("clients", self._client_enum),
            ("cves", self._cve_search),
            ("weakpass", self._weakpass_wordlist),
            ("kb_hits", self._kb_search),
            ("catalog_runs", self._catalog_iter),
        )
        if with_probes:
            # Novel probes only — core steps already listed above with their
            # legacy method names (_wps_probe, not _wps). Re-deriving via
            # f"_{m}" for m in RECON_PROBE_METHODS blew up with
            # AttributeError: 'CatalogRecon' object has no attribute '_wps'
            # and aborted the entire recon pass before any step ran.
            core = set(self._CORE_STEP_FNS)
            novel = []
            for m in self.RECON_PROBE_METHODS:
                if m in core:
                    continue
                fn = getattr(self, f"_{m}", None)
                if callable(fn):
                    novel.append((m, fn))
                else:
                    logger.warning(
                        "recon probe %r has no method _%s; skipping", m, m
                    )
            steps = steps + tuple(novel)
        for name, fn in steps:
            try:
                fn()
            except Exception as e:
                # Defensive: a step should not raise, but if it does, log
                # and continue with the rest.
                logger.exception("recon step %s raised: %s", name, e)
                self.recon[name]["ok"] = False
                self.recon[name]["error"] = f"unhandled: {e}"
        self.recon["finished_at"] = time.time()
        self.recon["duration_s"] = round(
            self.recon["finished_at"] - self.recon["started_at"], 3
        )
        self._persist()
        return self.recon

    def _persist(self) -> Optional[str]:
        """Write the recon report to ``logs/recon/<bssid>_<ts>.json``."""
        try:
            self.outdir.mkdir(parents=True, exist_ok=True)
            ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
            path = self.outdir / f"{self.bssid.replace(':', '')}_{ts}.json"
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(self.recon, fh, indent=2, default=str)
            return str(path)
        except (OSError, TypeError) as e:
            logger.debug("recon persist: %s", e)
            return None


# ---------------------------------------------------------------------------
# Module-level probe registry + entrypoint (used by the MCP wrappers in
# core/mcp/tools.py and the orchestrator's recon_probe dispatch — both
# route here, so the algorithm lives in this module, not in a wrapper).
# ---------------------------------------------------------------------------
RECON_PROBES: List[Dict[str, Any]] = [
    # --- 6 core recon steps (also run bundled by CatalogRecon.run());
    # surfaced individually so the AI chain can drive them as gated
    # recon_probe steps. read-only, no injection, no root. ---
    {
        "method": "wps",
        "name": "recon_probe_wps",
        "description": (
            "WPS probe: wash/reaver passive WPS discovery on the target "
            "BSSID — WPS locked state, model, version. Read-only."),
        "input_schema": {"type": "object", "properties": {
            "bssid": {"type": "string"}, "channel": {"type": "string"},
            "interface": {"type": "string"},
        }, "required": ["bssid"]},
        "examples": ["recon_probe(method='wps', bssid='EC:08:6B:11:22:33')"],
        "risk_level": "read", "requires_root": False,
    },
    {
        "method": "clients",
        "name": "recon_probe_clients",
        "description": (
            "Client enumeration: airodump-ng station CSV — associated "
            "client MACs, vendor, signal, probed SSIDs. Read-only."),
        "input_schema": {"type": "object", "properties": {
            "bssid": {"type": "string"}, "channel": {"type": "string"},
            "interface": {"type": "string"},
        }, "required": ["bssid"]},
        "examples": ["recon_probe(method='clients', bssid='EC:08:6B:11:22:33')"],
        "risk_level": "read", "requires_root": False,
    },
    {
        "method": "cves",
        "name": "recon_probe_cves",
        "description": (
            "CVE search: vendor/model/firmware -> NVD (operator-provided "
            "API key) candidate CVE list. Real NVD query; no fabricated "
            "CVE identifiers."),
        "input_schema": {"type": "object", "properties": {
            "bssid": {"type": "string"}, "vendor": {"type": "string"},
            "model": {"type": "string"}, "firmware": {"type": "string"},
        }},
        "examples": ["recon_probe(method='cves', bssid='EC:08:6B:11:22:33')"],
        "risk_level": "read", "requires_root": False,
    },
    {
        "method": "weakpass",
        "name": "recon_probe_weakpass",
        "description": (
            "Weakpass wordlist selection: pick the best weakpass_*.txt "
            "wordlist for the target (SSID/vendor-derived hints). "
            "Read-only filesystem scan."),
        "input_schema": {"type": "object", "properties": {
            "bssid": {"type": "string"}, "ssid": {"type": "string"},
            "vendor": {"type": "string"},
        }},
        "examples": ["recon_probe(method='weakpass', ssid='HomeNet')"],
        "risk_level": "read", "requires_root": False,
    },
    {
        "method": "kb_hits",
        "name": "recon_probe_kb_hits",
        "description": (
            "Knowledge-base hits: look up the target BSSID/vendor/SSID "
            "in the local KB for prior findings. Read-only."),
        "input_schema": {"type": "object", "properties": {
            "bssid": {"type": "string"}, "ssid": {"type": "string"},
            "vendor": {"type": "string"},
        }},
        "examples": ["recon_probe(method='kb_hits', bssid='EC:08:6B:11:22:33')"],
        "risk_level": "read", "requires_root": False,
    },
    {
        "method": "catalog_runs",
        "name": "recon_probe_catalog_runs",
        "description": (
            "Catalog iteration: enumerate the local catalog for tools "
            "matching the target profile (vendor/encryption/WPS). "
            "Read-only catalog scan."),
        "input_schema": {"type": "object", "properties": {
            "bssid": {"type": "string"}, "vendor": {"type": "string"},
            "encryption": {"type": "string"}, "wps": {"type": "boolean"},
        }},
        "examples": ["recon_probe(method='catalog_runs', vendor='TP-Link')"],
        "risk_level": "read", "requires_root": False,
    },
    {
        "method": "probe_profile",
        "name": "recon_probe_profile",
        "description": (
            "Passive probe-request profiler: builds each client's "
            "Preferred Network List, flags randomized MACs, and clusters "
            "clients sharing >=60% probed-SSID overlap. Reuses the "
            "airodump-ng station CSV."),
        "input_schema": {"type": "object", "properties": {
            "bssid": {"type": "string"}, "ssid": {"type": "string"},
            "channel": {"type": "string"}, "interface": {"type": "string"},
        }},
        "examples": ["recon_probe(method='probe_profile', bssid='EC:08:6B:11:22:33')"],
        "risk_level": "read", "requires_root": False,
    },
    {
        "method": "hidden_ssid",
        "name": "recon_probe_hidden_ssid",
        "description": (
            "Passively reveal a hidden SSID from probe-resp / assoc-req / "
            "probe-req frames in a BSSID-locked pcap (tshark). No deauth."),
        "input_schema": {"type": "object", "properties": {
            "bssid": {"type": "string"}, "channel": {"type": "string"},
            "interface": {"type": "string"},
        }, "required": ["bssid"]},
        "examples": ["recon_probe(method='hidden_ssid', bssid='EC:08:6B:11:22:33', channel='6')"],
        "risk_level": "read", "requires_root": False,
    },
    {
        "method": "signal_map",
        "name": "recon_probe_signal_map",
        "description": (
            "Map per-AP RSSI with EMA smoothing, log-distance path-loss "
            "distance + confidence label, and total RF exposure dBm "
            "(linear power summation). Reuses airodump-ng AP rows."),
        "input_schema": {"type": "object", "properties": {
            "bssid": {"type": "string"}, "interface": {"type": "string"},
        }},
        "examples": ["recon_probe(method='signal_map')"],
        "risk_level": "read", "requires_root": False,
    },
    {
        "method": "handshake_harvest",
        "name": "recon_probe_handshake_harvest",
        "description": (
            "Passively detect EAPOL M1-M4 in a BSSID-locked pcap and score "
            "PMKID capture feasibility (RSN+PSK+PMKID-friendly vendor). "
            "No hcxdumptool, no deauth."),
        "input_schema": {"type": "object", "properties": {
            "bssid": {"type": "string"}, "channel": {"type": "string"},
            "interface": {"type": "string"},
        }, "required": ["bssid"]},
        "examples": ["recon_probe(method='handshake_harvest', bssid='EC:08:6B:11:22:33')"],
        "risk_level": "read", "requires_root": False,
    },
    {
        "method": "eapol_monitor",
        "name": "recon_probe_eapol_monitor",
        "description": (
            "Extract EAP method types and cleartext identities (usernames/"
            "realms) from an 802.1X exchange; flags is_enterprise and "
            "names the method (PEAP/TTLS/FAST/LEAP/MD5)."),
        "input_schema": {"type": "object", "properties": {
            "bssid": {"type": "string"}, "interface": {"type": "string"},
        }, "required": ["bssid"]},
        "examples": ["recon_probe(method='eapol_monitor', bssid='EC:08:6B:11:22:33')"],
        "risk_level": "read", "requires_root": False,
    },
    {
        "method": "channel_plan",
        "name": "recon_probe_channel_plan",
        "description": (
            "Survey 2.4+5 GHz channel congestion and emit a recommended "
            "channel-hop dwell plan, target channel pinned first."),
        "input_schema": {"type": "object", "properties": {
            "channel": {"type": "string"}, "interface": {"type": "string"},
        }},
        "examples": ["recon_probe(method='channel_plan')"],
        "risk_level": "read", "requires_root": False,
    },
    {
        "method": "deauth_detect",
        "name": "recon_probe_deauth_detect",
        "description": (
            "Passive 20s frame watch: flags deauth flood (>=15), probe "
            "flood (>=50), and evil-twin candidates (same SSID on >=2 "
            "BSSIDs). scapy preferred, tshark fallback."),
        "input_schema": {"type": "object", "properties": {
            "interface": {"type": "string"},
        }},
        "examples": ["recon_probe(method='deauth_detect')"],
        "risk_level": "read", "requires_root": False,
    },
    {
        "method": "gps_wardrive",
        "name": "recon_probe_gps_wardrive",
        "description": (
            "Tag APs with a gpsd fix, emit a WiGLE-1.4 CSV, and (given "
            "offline .22000+TSV+GPX artifacts) fuse geo-located targets."),
        "input_schema": {"type": "object", "properties": {
            "interface": {"type": "string"},
            "artifacts": {"type": "object"},
        }},
        "examples": ["recon_probe(method='gps_wardrive')"],
        "risk_level": "read", "requires_root": False,
    },
    {
        "method": "beacon_parse",
        "name": "recon_probe_beacon_parse",
        "description": (
            "Decode the target beacon RSN IE: group/pairwise ciphers, "
            "AKM(s), PMF state, WPS presence, WPA3 (SAE/OWE) detection, "
            "and a stable fingerprint hash — passive, via tshark."),
        "input_schema": {"type": "object", "properties": {
            "bssid": {"type": "string"}, "channel": {"type": "string"},
            "interface": {"type": "string"},
        }, "required": ["bssid"]},
        "examples": ["recon_probe(method='beacon_parse', bssid='EC:08:6B:11:22:33')"],
        "risk_level": "read", "requires_root": False,
    },
]


def run_probe(method: str, target: Optional[Dict[str, Any]] = None,
              settings: Optional[Any] = None,
              oui_path: Optional[Path] = None,
              weakpass_outdir: Optional[Path] = None,
              **_: Any) -> Dict[str, Any]:
    """Module-level single-probe entrypoint: construct a one-shot
    :class:`CatalogRecon` for ``target`` and run the named probe.
    Returns the probe's step dict. Used by the MCP wrappers and the
    orchestrator's ``recon_probe`` dispatch so the algorithm stays in
    this module. Never raises."""
    outdir = weakpass_outdir or (PROJECT_ROOT / "logs" / "recon")
    try:
        recon = CatalogRecon(target=target or {}, settings=settings,
                             oui_path=oui_path, weakpass_outdir=outdir)
        return recon.run_probe(method)
    except Exception as e:  # noqa: BLE001
        return {"name": method, "ok": False, "error": str(e),
                "data": None, "duration_s": 0.0}


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _have_requests() -> bool:
    try:
        import requests  # noqa: F401
        return True
    except ImportError:
        return False
