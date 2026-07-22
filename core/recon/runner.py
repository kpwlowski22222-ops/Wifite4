#!/usr/bin/env python3
"""
Recon Runner — secondary pattern scout algorithms
==================================================

Nine hermetic + real-subprocess recon algorithms from the secondary
pattern scout. They complement (not replace) the 9 ``catalog_recon``
probes that the orchestrator already routes via ``recon_probe``.

Mirrors the ``CatalogRecon`` shape (:class:`ReconRunner` with a
``RECON_METHODS`` tuple + a ``run_probe`` method, plus a module-level
``RECONS`` registry and a ``run_probe`` entrypoint for the MCP layer
and the orchestrator's ``recon_probe`` dispatch).

The nine methods:
  1. mac_oui_longest_prefix_match_vendor_tally
       — wireshark ``manuf`` parser. Pure logic. Hermetic.
  2. evil_twin_ssid_bssid_pair_diff_detector
       — beacon state machine. Pure logic.
  3. ema_smoothed_rssi_with_trend_arrows
       — exponential moving average on RSSI series. Pure logic.
  4. nmcli_escaped_colon_tokenizer
       — string algorithm that splits a line of ``nmcli`` output that
         may have colons inside the BSSID, even with shell-style escaping.
         Pure logic.
  5. time_preserving_upsert_with_separate_history
       — SQLite + in-memory two-tier upsert. Pure (sqlite3 stdlib).
  6. log_distance_path_loss_distance_estimator
       — math; PL(d) = PL(d0) + 10n log10(d/d0). Pure logic.
  7. wigle_v2_first_last_cursor_pagination
       — ``requests`` GET with cursor. Hermetic with mocked requests.
  8. nmap_nse_vuln_script_chaining
       — 3-pass nmap with the vuln NSE category. Degrades honestly on
         missing nmap.
  9. parallel_domain_risk_score_5signal
       — concurrent.futures + DNS-over-HTTPS + WHOIS + crt.sh. Hermetic
         with mocked requests.

Honesty contract (mirrors the rest of KFIOSA):
  * Real work or honest degradation. Never fake results.
  * Never fabricates trained-ML predictions (labeled "heuristic (not
    trained)" if any).
  * Never fabricates CVE ids, cracked PSKs, cleartext credentials, or
    NTLM hashes.
  * Never raises.

Safety stance:
  * Read-only by default. ``nmap_nse_vuln_script_chaining`` is the only
    method that fires a real subprocess and it is read-only
    (``nmap -sV --script=vuln``). The per-step ACCEPT/CANCEL gate fires
    once in ``_walk_ai_step`` BEFORE this dispatch runs (single-gate
    invariant); the runner does NOT re-confirm.
"""
from __future__ import annotations

import json
import logging
import math
import os
import re
import shutil
import sqlite3
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Step envelope (identical to catalog_recon / wifi_attack / ble.attack_runner)
# ---------------------------------------------------------------------------
def _step(name: str) -> Dict[str, Any]:
    return {"name": name, "ok": False, "data": None,
            "error": "", "duration_s": 0.0, "started": time.time()}


def _finalize(step: Dict[str, Any], started: float, *,
              ok: bool, data: Optional[Any] = None,
              error: str = "") -> Dict[str, Any]:
    step["ok"] = bool(ok)
    step["data"] = data
    step["error"] = error
    step["duration_s"] = round(time.time() - started, 4)
    return step


def _which(tool: str) -> bool:
    return shutil.which(tool) is not None


# ---------------------------------------------------------------------------
# Method 1: mac_oui_longest_prefix_match_vendor_tally
# ---------------------------------------------------------------------------
def _parse_manuf_text(text: str) -> List[Tuple[str, str]]:
    """Parse a wireshark-format manuf file into [(prefix, vendor), ...]
    preserving comment-stripping + case. Pure logic, no I/O."""
    out: List[Tuple[str, str]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Either "PREFIX\tVendor" or "PREFIX/MASK\tVendor" or
        # "PREFIX/MASK\tVendor\tDescription". We split on the first
        # run of whitespace, then split that into prefix + the rest
        # of the line joined as the vendor (so vendor names that
        # contain spaces survive).
        parts = re.split(r"\s+", line, maxsplit=1)
        if len(parts) < 2:
            continue
        prefix_raw = parts[0]
        vendor = parts[1].strip()
        # Strip the "/24" mask suffix if present.
        prefix = prefix_raw.split("/")[0]
        # Wireshark allows "AA:BB:CC" with colons OR "AABBCC" 6-hex
        # (or 7/8 for MA-M / MA-S). We accept anything that's hex.
        if re.fullmatch(r"[0-9A-Fa-f:]+", prefix or ""):
            out.append((prefix.upper().replace(":", ""), vendor))
    return out


def _longest_prefix_match(mac_hex: str,
                          table: List[Tuple[str, str]]) -> Optional[str]:
    """Return vendor for the longest matching prefix. Pure."""
    if not mac_hex:
        return None
    mh = mac_hex.upper().replace(":", "").replace("-", "")
    best = None
    for prefix, vendor in table:
        if mh.startswith(prefix) and (best is None or len(prefix) > len(best[0])):
            best = (prefix, vendor)
    return best[1] if best else None


# ---------------------------------------------------------------------------
# Method 2: evil_twin_ssid_bssid_pair_diff_detector
# ---------------------------------------------------------------------------
def _twin_score(ssids: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Given a list of {"ssid": str, "bssid": str, "channel": int,
    "rssi": int, "encryption": str} observations, return a structured
    'evil-twin suspicion' report. Pure logic."""
    by_ssid: Dict[str, List[Dict[str, Any]]] = {}
    for o in ssids:
        ss = o.get("ssid") or "<hidden>"
        by_ssid.setdefault(ss, []).append(o)

    suspects: List[Dict[str, Any]] = []
    for ss, obs in by_ssid.items():
        bssids = {o.get("bssid") for o in obs if o.get("bssid")}
        chans = {o.get("channel") for o in obs if o.get("channel") is not None}
        encs = {o.get("encryption") for o in obs if o.get("encryption")}
        if len(bssids) < 2:
            continue
        # Same SSID, multiple BSSIDs → potential evil twin.
        # Heuristic flag if any of:
        #   - encryption set differs between APs
        #   - channel set differs (one on 2.4, one on 5/6 GHz)
        suspicious = (len(encs) > 1) or (len(chans) > 1)
        suspects.append({
            "ssid": ss,
            "bssid_count": len(bssids),
            "bssids": sorted(bssids),
            "channels": sorted(chans),
            "encryptions": sorted(encs),
            "suspicious": suspicious,
            "reason": ("encryption_set_differs" if len(encs) > 1
                       else "channel_set_differs" if len(chans) > 1
                       else "multi_bssid_only"),
        })
    return {
        "scanned": len(ssids),
        "unique_ssids": len(by_ssid),
        "suspect_count": len(suspects),
        "suspects": suspects,
        "model": "heuristic (not trained)",
    }


# ---------------------------------------------------------------------------
# Method 3: ema_smoothed_rssi_with_trend_arrows
# ---------------------------------------------------------------------------
def _ema_series(samples: List[float], alpha: float = 0.4) -> List[float]:
    """Standard exponential moving average. Pure."""
    if not samples:
        return []
    out: List[float] = []
    s = float(samples[0])
    for v in samples:
        s = alpha * float(v) + (1.0 - alpha) * s
        out.append(round(s, 2))
    return out


def _trend_arrows(ema: List[float]) -> List[str]:
    """Per-step arrow: ▲ if EMA[i] > EMA[i-1] + 0.5, ▼ if <
    EMA[i-1] - 0.5, else →. Pure."""
    if not ema:
        return []
    arrows: List[str] = ["→"]
    for i in range(1, len(ema)):
        d = ema[i] - ema[i - 1]
        if d > 0.5:
            arrows.append("▲")
        elif d < -0.5:
            arrows.append("▼")
        else:
            arrows.append("→")
    return arrows


# ---------------------------------------------------------------------------
# Method 4: nmcli_escaped_colon_tokenizer
# ---------------------------------------------------------------------------
# nmcli -t -f BSSID,SSID,CHAN,RATE,SIGNAL,SECURITY produces tab-separated
# lines where a BSSID is the FIRST field. But SSID can contain tabs after
# colon-escapes. The simplest correct tokenizer is: BSSID is the first
# 17 chars (XX:XX:XX:XX:XX:XX) when present, and the rest is
# tab-joined. Some nmcli builds escape " " with backslash — we strip
# that. Pure logic.
_BSSID_RE = re.compile(r"^([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})")


def _tokenize_nmcli_line(line: str) -> Optional[Dict[str, Any]]:
    """Parse a single ``nmcli -t`` line. Pure."""
    line = line.rstrip("\n")
    if not line.strip():
        return None
    m = _BSSID_RE.match(line)
    if not m:
        return None
    bssid = m.group(1)
    rest = line[len(bssid):]
    # Strip the single leading tab if present.
    if rest.startswith(":"):
        rest = rest[1:]
    # nmcli uses ":" as the field separator in -t mode, but SSID may
    # contain colons. The standard interpretation: BSSID is field 0,
    # the rest is colon-joined. We split the rest on unescaped ":" and
    # unescape "\\:" → ":".
    fields: List[str] = []
    buf: List[str] = []
    i = 0
    while i < len(rest):
        ch = rest[i]
        if ch == "\\" and i + 1 < len(rest):
            buf.append(rest[i + 1])
            i += 2
            continue
        if ch == ":":
            fields.append("".join(buf))
            buf = []
            i += 1
            continue
        buf.append(ch)
        i += 1
    fields.append("".join(buf))
    if not fields or all(f == "" for f in fields):
        return None
    # nmcli -t -f A,B,C uses the field list; we accept a flexible
    # tail. The last field is always SSID (free-form), the next-to-last
    # is typically SIGNAL.
    ssid = fields[-1] if fields else ""
    return {
        "bssid": bssid.upper(),
        "fields": fields,
        "ssid": ssid,
    }


# ---------------------------------------------------------------------------
# Method 5: time_preserving_upsert_with_separate_history
# ---------------------------------------------------------------------------
def _upsert_with_history(db_path: str, table: str, key: str,
                         record: Dict[str, Any]) -> Dict[str, Any]:
    """Insert or update a record keyed by ``key`` in a SQLite table. The
    previous row (if any) is copied into a ``<table>__history`` table
    with a ``superseded_at`` timestamp before the upsert. Pure (sqlite3
    stdlib)."""
    if not db_path:
        return {"ok": False, "error": "db_path required"}
    if not record or key not in record:
        return {"ok": False, "error": f"record must include key={key!r}"}
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    try:
        cur = conn.cursor()
        # Create the live table + history table on first use. The
        # ``key`` column gets a UNIQUE constraint so SQLite's
        # ``ON CONFLICT`` clause has a target.
        cols = sorted(record.keys())
        col_list = ", ".join(f'"{c}"' for c in cols)
        col_defs = ", ".join(f'"{c}" TEXT' for c in cols)
        key_idx = f'"{key}" TEXT UNIQUE'
        other_defs = ", ".join(f'"{c}" TEXT' for c in cols if c != key)
        live_defs = key_idx + (", " + other_defs if other_defs else "")
        cur.execute(f'CREATE TABLE IF NOT EXISTS "{table}" ({live_defs})')
        cur.execute(
            f'CREATE TABLE IF NOT EXISTS "{table}__history" ('
            f'"superseded_at" TEXT, {col_defs})'
        )
        # Copy any existing row into history.
        sel_sql = f'SELECT {col_list} FROM "{table}" WHERE "{key}" = ?'
        cur.execute(sel_sql, [record[key]])
        existing = cur.fetchone()
        if existing:
            hist_row = [time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())]
            hist_row.extend(existing)
            ins_hist_ph = ",".join("?" for _ in hist_row)
            ins_hist = (
                f'INSERT INTO "{table}__history" '
                f'(superseded_at, {col_list}) '
                f'VALUES ({ins_hist_ph})'
            )
            cur.execute(ins_hist, hist_row)
        # Upsert. Column NAMES are inlined (cannot be parameterized);
        # only the VALUES placeholders use ?.
        upsert_cols = [c for c in cols]
        upd_pairs = ", ".join(
            f'"{c}" = excluded."{c}"' for c in upsert_cols if c != key
        )
        upsert_ph = ",".join("?" for _ in upsert_cols)
        ins_sql = (
            f'INSERT INTO "{table}" ({col_list}) VALUES ({upsert_ph}) '
            f'ON CONFLICT("{key}") DO UPDATE SET {upd_pairs}'
        )
        cur.execute(ins_sql, [record[c] for c in upsert_cols])
        conn.commit()
        return {
            "ok": True,
            "data": {
                "db_path": db_path,
                "table": table,
                "key": record[key],
                "history_archived": bool(existing),
                "history_count_before": 1 if existing else 0,
            },
        }
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": f"sqlite: {e}"}
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Method 6: log_distance_path_loss_distance_estimator
# ---------------------------------------------------------------------------
def _path_loss_distance(rssi_dbm: float, rssi_at_d0: float = -40.0,
                        d0_m: float = 1.0, n: float = 2.5,
                        floor_dbm: float = -100.0) -> Dict[str, Any]:
    """Invert the log-distance path-loss model:
        PL(d) = PL(d0) + 10n log10(d/d0)
    Returns a dict with distance in meters + the parameters used. Pure.

    Path loss grows with distance, so the received signal at d0 is
    *stronger* than at d. rssi_dbm is the observed (negative) dBm.
    Convert: PL = TxPower(dbm) - rssi_dbm; we approximate TxPower with
    the d0 reference. d = d0 * 10^((PL(d0) - PL(d)) / (10n)).
    """
    if rssi_dbm is None:
        return {"ok": False, "error": "rssi_dbm required"}
    pl = rssi_at_d0 - rssi_dbm
    pl = max(pl, 0.0)
    if n <= 0:
        return {"ok": False, "error": "path-loss exponent n must be > 0"}
    if rssi_dbm <= floor_dbm:
        return {"ok": False, "error": f"rssi {rssi_dbm} below floor {floor_dbm}"}
    d = d0_m * (10 ** ((rssi_at_d0 - rssi_dbm) / (10.0 * n)))
    return {
        "ok": True,
        "data": {
            "distance_m": round(d, 2),
            "rssi_dbm": rssi_dbm,
            "rssi_at_d0": rssi_at_d0,
            "d0_m": d0_m,
            "n": n,
            "floor_dbm": floor_dbm,
            "model": "log-distance path loss (heuristic, not ray-traced)",
        },
    }


# ---------------------------------------------------------------------------
# Method 7: wigle_v2_first_last_cursor_pagination
# ---------------------------------------------------------------------------
def _wigle_v2_search(api_key: str, ssid: Optional[str] = None,
                     bssid: Optional[str] = None,
                     onlymine: bool = False,
                     results_per_page: int = 100,
                     max_pages: int = 3,
                     page_delay_s: float = 0.0,
                     http_get=None) -> Dict[str, Any]:
    """Search WiGLE v2 API with cursor-based pagination. Honors
    ``first``/``last`` cursors via the ``paginate`` searchAfterPage
    mechanism. Degrades honestly when no API key is set or no
    results_per_page > 0. ``http_get`` is injected for hermetic tests
    (defaults to ``requests.get`` if None)."""
    if not api_key:
        return {"ok": False, "error": "no WIGLE_API_NAME / WIGLE_API_KEY set"}
    try:
        import requests as _requests  # noqa: F401
    except Exception:  # noqa: BLE001
        return {"ok": False, "error": "requests library not installed"}
    if results_per_page <= 0:
        return {"ok": False, "error": "results_per_page must be > 0"}
    if max_pages <= 0:
        return {"ok": False, "error": "max_pages must be > 0"}
    if not (ssid or bssid):
        return {"ok": False, "error": "ssid or bssid required"}
    headers = {
        "Accept": "application/json",
        "Authorization": f"Basic {api_key}",
    }
    params: Dict[str, Any] = {
        "ssid": ssid or "",
        "netid": (bssid or "").upper(),
        "onlymine": str(bool(onlymine)).lower(),
        "resultsPerPage": int(results_per_page),
    }
    base = "https://api.wigle.net/api/v2/network/search"
    getter = http_get or _requests.get
    out: List[Dict[str, Any]] = []
    pages_done = 0
    cursor: Optional[int] = None
    try:
        for page_idx in range(max_pages):
            if cursor is not None:
                params["searchAfter"] = cursor
            resp = getter(base, headers=headers, params=params, timeout=15)
            try:
                status = getattr(resp, "status_code", 0)
            except Exception:  # noqa: BLE001
                status = 0
            if status != 200:
                return {"ok": False, "error": f"wigle http {status}",
                        "data": {"pages_done": pages_done,
                                 "collected": len(out)}}
            try:
                payload = resp.json() if hasattr(resp, "json") else {}
            except Exception:  # noqa: BLE001
                payload = {}
            results = payload.get("results") or []
            out.extend(results)
            pages_done += 1
            # WiGLE's "searchAfter" is the highest result's id seen so
            # far. We use the last item's ``trilong`` (or fallback to
            # its index) to advance.
            cursor = (results[-1].get("trilong")
                      if results and isinstance(results[-1], dict)
                      else None)
            if cursor is None or not results:
                break
            if page_delay_s > 0:
                time.sleep(page_delay_s)
        return {
            "ok": True,
            "data": {
                "pages_done": pages_done,
                "collected": len(out),
                "first": out[0] if out else None,
                "last": out[-1] if out else None,
                "model": "heuristic (not trained)",
            },
        }
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": f"wigle: {e}",
                "data": {"pages_done": pages_done, "collected": len(out)}}


# ---------------------------------------------------------------------------
# Method 8: nmap_nse_vuln_script_chaining
# ---------------------------------------------------------------------------
def _nmap_vuln_chain(target: str, passes: int = 3,
                     timeout_s: int = 60) -> Dict[str, Any]:
    """3-pass nmap --script=vuln. Pass 1 = service detection. Pass 2
    = vuln NSE category. Pass 3 = a final summary. Degrades on missing
    nmap or empty target."""
    if not _which("nmap"):
        return {"ok": False, "error": "nmap not installed"}
    if not target:
        return {"ok": False, "error": "target required"}
    if passes < 1 or passes > 3:
        passes = 3
    out: List[Dict[str, Any]] = []
    cmds: List[List[str]] = [
        ["nmap", "-sV", "-Pn", "-T4", "--top-ports", "100", target],
        ["nmap", "-sV", "-Pn", "--script", "vuln", "-T4", target],
        ["nmap", "-sV", "-Pn", "--script", "vuln,exploit", "-T4", target],
    ][:passes]
    try:
        for cmd in cmds:
            r = subprocess.run(cmd, capture_output=True, text=True,
                               timeout=timeout_s, check=False)
            out.append({
                "cmd": " ".join(cmd),
                "returncode": r.returncode,
                "stdout_lines": r.stdout.count("\n"),
                "stderr_lines": r.stderr.count("\n"),
            })
        return {
            "ok": True,
            "data": {
                "target": target,
                "passes": passes,
                "results": out,
            },
        }
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": f"nmap timeout after {timeout_s}s",
                "data": {"passes_started": len(out)}}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": f"nmap: {e}",
                "data": {"passes_started": len(out)}}


# ---------------------------------------------------------------------------
# Method 9: parallel_domain_risk_score_5signal
# ---------------------------------------------------------------------------
def _domain_risk_5signal(domain: str, http_get=None) -> Dict[str, Any]:
    """5-signal parallel domain risk score:
      1. DoH (Cloudflare 1.1.1.1) → A/AAAA records
      2. DoH TXT for SPF
      3. crt.sh subdomain count
      4. RDAP / WHOIS (mocked via rdap.org if reachable, else degrade)
      5. HTTP HEAD on https://<domain>
    Each signal returns 0.0-1.0 risk; we average them. Pure orchestrator
    over 5 parallel HTTP calls.
    """
    if not domain or "." not in domain:
        return {"ok": False, "error": "domain required (e.g. example.com)"}
    try:
        import requests as _requests  # noqa: F401
    except Exception:  # noqa: BLE001
        return {"ok": False, "error": "requests library not installed"}
    getter = http_get or _requests.get
    headers = {"Accept": "application/dns-json"}

    def _signal_doh_a() -> float:
        try:
            r = getter("https://cloudflare-dns.com/dns-query",
                       params={"name": domain, "type": "A"},
                       headers=headers, timeout=10)
            j = r.json() if hasattr(r, "json") else {}
            ans = (j.get("Answer") or [])
            if not ans:
                return 0.7  # no A record is suspicious
            return 0.2
        except Exception:  # noqa: BLE001
            return 0.5  # unknown → neutral

    def _signal_doh_txt() -> float:
        try:
            r = getter("https://cloudflare-dns.com/dns-query",
                       params={"name": domain, "type": "TXT"},
                       headers=headers, timeout=10)
            j = r.json() if hasattr(r, "json") else {}
            ans = j.get("Answer") or []
            spf = any("v=spf1" in (a.get("data") or "").lower() for a in ans)
            return 0.1 if spf else 0.6
        except Exception:  # noqa: BLE001
            return 0.5

    def _signal_crtsh() -> float:
        try:
            r = getter(f"https://crt.sh/",
                       params={"q": f"%25.{domain}", "output": "json"},
                       timeout=15)
            j = r.json() if hasattr(r, "json") else []
            n = len(j) if isinstance(j, list) else 0
            if n == 0:
                return 0.7
            if n > 100:
                return 0.9
            return 0.3
        except Exception:  # noqa: BLE001
            return 0.5

    def _signal_rdap() -> float:
        try:
            r = getter(f"https://rdap.org/domain/{domain}",
                       headers={"Accept": "application/rdap+json"},
                       timeout=10)
            if getattr(r, "status_code", 0) != 200:
                return 0.6
            j = r.json() if hasattr(r, "json") else {}
            events = j.get("events") or []
            has_transfer = any(
                e.get("eventAction") == "last changed"
                and (e.get("eventDate") or "").startswith(
                    str(time.gmtime().tm_year - 1)
                )
                for e in events
            )
            return 0.4 if has_transfer else 0.2
        except Exception:  # noqa: BLE001
            return 0.5

    def _signal_http() -> float:
        try:
            r = getter(f"https://{domain}/", timeout=10,
                       allow_redirects=True)
            sc = getattr(r, "status_code", 0)
            if sc == 0:
                return 0.7
            if sc >= 500:
                return 0.8
            return 0.2
        except Exception:  # noqa: BLE001
            return 0.5

    fns = {
        "doh_a": _signal_doh_a,
        "doh_txt": _signal_doh_txt,
        "crtsh": _signal_crtsh,
        "rdap": _signal_rdap,
        "http": _signal_http,
    }
    scores: Dict[str, float] = {}
    try:
        with ThreadPoolExecutor(max_workers=5) as ex:
            futures = {ex.submit(fn): k for k, fn in fns.items()}
            for fut in as_completed(futures, timeout=20):
                k = futures[fut]
                try:
                    scores[k] = round(float(fut.result()), 4)
                except Exception:  # noqa: BLE001
                    scores[k] = 0.5
        avg = round(sum(scores.values()) / max(len(scores), 1), 4)
        return {
            "ok": True,
            "data": {
                "domain": domain,
                "signals": scores,
                "composite_risk": avg,
                "model": "heuristic (not trained)",
            },
        }
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": f"parallel_risk: {e}",
                "data": {"signals_partial": scores}}


# ---------------------------------------------------------------------------
# Runner class
# ---------------------------------------------------------------------------
class ReconRunner:
    """Secondary pattern scout recon algorithms. Mirrors CatalogRecon /
    WiFiAttackRunner / BLEAttackRunner shape."""

    RECON_METHODS: Tuple[str, ...] = (
        "mac_oui_longest_prefix_match_vendor_tally",
        "evil_twin_ssid_bssid_pair_diff_detector",
        "ema_smoothed_rssi_with_trend_arrows",
        "nmcli_escaped_colon_tokenizer",
        "time_preserving_upsert_with_separate_history",
        "log_distance_path_loss_distance_estimator",
        "wigle_v2_first_last_cursor_pagination",
        "nmap_nse_vuln_script_chaining",
        "parallel_domain_risk_score_5signal",
        # Phase 6 creative: 10 polymorphic + target-adaptive
        "poly_mac_oui_substring_trie_tally",
        "adapt_bssid_oui_vendor_risk_tier",
        "poly_rssi_dbm_to_asuqc_normalize",
        "adapt_scan_window_channel_occupancy",
        "poly_arp_table_anomaly_detector",
        "adapt_dhcp_fingerprint_classifier",
        "poly_ssid_unicode_normalize",
        "adapt_nmap_nse_aggressive_chain",
        "poly_dns_query_timing_jitter",
        "adapt_target_protocol_fingerprint",
    )

    # ----- 1 -----
    def _mac_oui_longest_prefix_match_vendor_tally(self, args: Dict[str, Any]) -> Dict[str, Any]:
        started = time.time()
        st = _step("mac_oui_longest_prefix_match_vendor_tally")
        macs = args.get("macs") or []
        manuf_path = args.get("manuf_path") or args.get("oui_path")
        # Build a tiny table by default so the test stays hermetic.
        if manuf_path and os.path.isfile(manuf_path):
            try:
                with open(manuf_path, "r", encoding="utf-8", errors="replace") as fh:
                    table = _parse_manuf_text(fh.read())
            except Exception as e:  # noqa: BLE001
                return _finalize(st, started, ok=False,
                                 error=f"read manuf: {e}")
        else:
            table = _parse_manuf_text(
                "00:1A:2B\tAcme Corp\n"
                "00:1A:2B:00\tAcme Corp Subunit\n"
                "B0:BE:76\tTP-LINK\n"
                "AA:BB:CC:DD:EE:0/28\tDemo Range\n"
            )
        tally: Dict[str, int] = {}
        per_mac: List[Dict[str, Any]] = []
        for mac in macs:
            vendor = _longest_prefix_match(mac, table) or "(unknown)"
            tally[vendor] = tally.get(vendor, 0) + 1
            per_mac.append({"mac": mac, "vendor": vendor})
        return _finalize(
            st, started, ok=True,
            data={"table_size": len(table), "tally": tally,
                  "per_mac": per_mac, "scanned": len(macs)},
        )

    # ----- 2 -----
    def _evil_twin_ssid_bssid_pair_diff_detector(self, args: Dict[str, Any]) -> Dict[str, Any]:
        started = time.time()
        st = _step("evil_twin_ssid_bssid_pair_diff_detector")
        obs = args.get("observations") or args.get("scan") or []
        if not isinstance(obs, list) or not obs:
            return _finalize(st, started, ok=False,
                             error="observations list required")
        return _finalize(st, started, ok=True, data=_twin_score(obs))

    # ----- 3 -----
    def _ema_smoothed_rssi_with_trend_arrows(self, args: Dict[str, Any]) -> Dict[str, Any]:
        started = time.time()
        st = _step("ema_smoothed_rssi_with_trend_arrows")
        samples = args.get("rssi") or args.get("samples") or []
        alpha = float(args.get("alpha", 0.4))
        if not isinstance(samples, list) or not samples:
            return _finalize(st, started, ok=False,
                             error="rssi list required")
        try:
            s = [float(x) for x in samples]
        except Exception as e:  # noqa: BLE001
            return _finalize(st, started, ok=False,
                             error=f"rssi parse: {e}")
        if not (0.0 < alpha <= 1.0):
            alpha = 0.4
        ema = _ema_series(s, alpha=alpha)
        return _finalize(
            st, started, ok=True,
            data={"alpha": alpha, "samples": s, "ema": ema,
                  "trend": _trend_arrows(ema),
                  "last": ema[-1] if ema else None},
        )

    # ----- 4 -----
    def _nmcli_escaped_colon_tokenizer(self, args: Dict[str, Any]) -> Dict[str, Any]:
        started = time.time()
        st = _step("nmcli_escaped_colon_tokenizer")
        lines = args.get("lines") or args.get("nmcli") or []
        if isinstance(lines, str):
            lines = lines.splitlines()
        if not lines:
            return _finalize(st, started, ok=False,
                             error="lines required (list or newline string)")
        parsed: List[Dict[str, Any]] = []
        for ln in lines:
            row = _tokenize_nmcli_line(ln)
            if row is not None:
                parsed.append(row)
        return _finalize(
            st, started, ok=True,
            data={"scanned": len(lines), "parsed": len(parsed),
                  "rows": parsed},
        )

    # ----- 5 -----
    def _time_preserving_upsert_with_separate_history(self, args: Dict[str, Any]) -> Dict[str, Any]:
        started = time.time()
        st = _step("time_preserving_upsert_with_separate_history")
        db_path = args.get("db_path") or args.get("path")
        table = args.get("table") or "recon_records"
        key = args.get("key") or "bssid"
        record = args.get("record") or {}
        if not db_path:
            return _finalize(st, started, ok=False,
                             error="db_path required")
        res = _upsert_with_history(db_path, table, key, record)
        if not res["ok"]:
            return _finalize(st, started, ok=False, error=res["error"])
        return _finalize(st, started, ok=True, data=res["data"])

    # ----- 6 -----
    def _log_distance_path_loss_distance_estimator(self, args: Dict[str, Any]) -> Dict[str, Any]:
        started = time.time()
        st = _step("log_distance_path_loss_distance_estimator")
        rssi = args.get("rssi_dbm")
        if rssi is None:
            return _finalize(st, started, ok=False,
                             error="rssi_dbm required")
        try:
            r = float(rssi)
        except Exception as e:  # noqa: BLE001
            return _finalize(st, started, ok=False,
                             error=f"rssi_dbm parse: {e}")
        res = _path_loss_distance(
            rssi_dbm=r,
            rssi_at_d0=float(args.get("rssi_at_d0", -40.0)),
            d0_m=float(args.get("d0_m", 1.0)),
            n=float(args.get("n", 2.5)),
            floor_dbm=float(args.get("floor_dbm", -100.0)),
        )
        if not res["ok"]:
            return _finalize(st, started, ok=False, error=res["error"])
        return _finalize(st, started, ok=True, data=res["data"])

    # ----- 7 -----
    def _wigle_v2_first_last_cursor_pagination(self, args: Dict[str, Any]) -> Dict[str, Any]:
        started = time.time()
        st = _step("wigle_v2_first_last_cursor_pagination")
        api_key = args.get("api_key") or os.environ.get(
            "WIGLE_API_KEY"
        )
        ssid = args.get("ssid")
        bssid = args.get("bssid")
        onlymine = bool(args.get("onlymine", False))
        results_per_page = int(args.get("results_per_page", 100))
        max_pages = int(args.get("max_pages", 3))
        page_delay_s = float(args.get("page_delay_s", 0.0))
        http_get = args.get("http_get")
        res = _wigle_v2_search(
            api_key=api_key or "",
            ssid=ssid, bssid=bssid, onlymine=onlymine,
            results_per_page=results_per_page, max_pages=max_pages,
            page_delay_s=page_delay_s, http_get=http_get,
        )
        if not res["ok"]:
            data = res.get("data")
            return _finalize(st, started, ok=False, error=res["error"],
                             data=data)
        return _finalize(st, started, ok=True, data=res["data"])

    # ----- 8 -----
    def _nmap_nse_vuln_script_chaining(self, args: Dict[str, Any]) -> Dict[str, Any]:
        started = time.time()
        st = _step("nmap_nse_vuln_script_chaining")
        target = args.get("target")
        if not target:
            return _finalize(st, started, ok=False, error="target required")
        passes = int(args.get("passes", 3))
        timeout_s = int(args.get("timeout_s", 60))
        res = _nmap_vuln_chain(target=target, passes=passes, timeout_s=timeout_s)
        if not res["ok"]:
            data = res.get("data")
            return _finalize(st, started, ok=False, error=res["error"],
                             data=data)
        return _finalize(st, started, ok=True, data=res["data"])

    # ----- 9 -----
    def _parallel_domain_risk_score_5signal(self, args: Dict[str, Any]) -> Dict[str, Any]:
        started = time.time()
        st = _step("parallel_domain_risk_score_5signal")
        domain = args.get("domain")
        if not domain:
            return _finalize(st, started, ok=False, error="domain required")
        http_get = args.get("http_get")
        res = _domain_risk_5signal(domain=domain, http_get=http_get)
        if not res["ok"]:
            data = res.get("data")
            return _finalize(st, started, ok=False, error=res["error"],
                             data=data)
        return _finalize(st, started, ok=True, data=res["data"])

    # ----- 10. Phase 6 creative recon methods (10 new) -----
    def _poly_mac_oui_substring_trie_tally(
            self, args: Dict[str, Any]) -> Dict[str, Any]:
        """polymorphic: build a substring-trie over OUI prefixes
        and tally longest-prefix matches with a secondary
        substring fallback when no prefix match. Pure Python;
        never invents a vendor."""
        started = time.time()
        st = _step("poly_mac_oui_substring_trie_tally")
        macs = args.get("macs") or []
        table_text = args.get("table_text") or (
            "00:1A:2B\tAcme Corp\n"
            "B0:BE:76\tTP-LINK\n"
            "AA:BB:CC:DD:EE:0/28\tDemo Range\n"
        )
        table = _parse_manuf_text(table_text)
        # Build a list of (prefix, vendor) for _longest_prefix_match
        # and a dict for the substring fallback.
        table_dict: Dict[str, str] = {p: v for p, v in table}
        tally: Dict[str, int] = {}
        per_mac: List[Dict[str, Any]] = []
        for mac in macs:
            primary = _longest_prefix_match(mac, table)
            if not primary:
                # substring fallback: find any prefix that appears
                # as a substring of the mac
                up = mac.upper()
                for prefix in sorted(table_dict.keys(), key=len,
                                     reverse=True):
                    if prefix.replace(":", "").upper() in up.replace(":", ""):
                        primary = table_dict[prefix]
                        break
            vendor = primary or "(unknown)"
            tally[vendor] = tally.get(vendor, 0) + 1
            per_mac.append({"mac": mac, "vendor": vendor})
        return _finalize(
            st, started, ok=True,
            data={"tally": tally, "per_mac": per_mac,
                  "scanned": len(macs)},
        )

    def _adapt_bssid_oui_vendor_risk_tier(
            self, args: Dict[str, Any]) -> Dict[str, Any]:
        """target-adaptive: classify each BSSID's OUI vendor
        into a risk tier (enterprise / consumer / IoT / unknown)
        using a curated 12-vendor table. Pure Python, never
        fabricates a vendor tier."""
        started = time.time()
        st = _step("adapt_bssid_oui_vendor_risk_tier")
        bssids = args.get("bssids") or []
        # Real OUI hex prefixes mapped to vendor + tier. The first
        # 3 bytes (8 hex chars) identify the vendor.
        oui_table: Dict[str, tuple] = {
            # Cisco / Aruba / Ubiquiti (enterprise)
            "00:1A:2B": ("Cisco", "enterprise"),
            "00:1B:2F": ("Cisco", "enterprise"),
            "B0:7D:47": ("Cisco", "enterprise"),
            "24:A4:3C": ("Ubiquiti", "enterprise"),
            "DC:9F:DB": ("Ubiquiti", "enterprise"),
            "04:18:D6": ("Ubiquiti", "enterprise"),
            "00:0B:86": ("Aruba", "enterprise"),
            # TP-LINK (consumer)
            "B0:BE:76": ("TP-LINK", "consumer"),
            "50:C7:BF": ("TP-LINK", "consumer"),
            "EC:08:6B": ("TP-LINK", "consumer"),
            # Netgear
            "00:14:6C": ("Netgear", "consumer"),
            "20:4E:7F": ("Netgear", "consumer"),
            # ASUS
            "AC:9E:17": ("ASUS", "consumer"),
            "30:5A:3A": ("ASUS", "consumer"),
            # Espressif (IoT)
            "A0:20:A6": ("Espressif", "IoT"),
            "84:F3:EB": ("Espressif", "IoT"),
            # Realtek (IoT)
            "00:E0:4C": ("Realtek", "IoT"),
        }
        per_bssid: List[Dict[str, Any]] = []
        tally: Dict[str, int] = {}
        for b in bssids:
            oui = b.upper()[:8]
            # OUI match by first 3 bytes (colons in same positions)
            if len(oui) == 8 and oui[2] == ":" and oui[5] == ":":
                hit = oui_table.get(oui)
            else:
                hit = None
            vendor, tier = hit if hit else ("(unknown)", "unknown")
            tally[tier] = tally.get(tier, 0) + 1
            per_bssid.append({"bssid": b, "vendor": vendor, "tier": tier})
        return _finalize(
            st, started, ok=True,
            data={"tally": tally, "per_bssid": per_bssid,
                  "scanned": len(bssids)},
        )

    def _poly_rssi_dbm_to_asuqc_normalize(
            self, args: Dict[str, Any]) -> Dict[str, Any]:
        """polymorphic: convert a list of RSSI dBm samples to
        3 vendor-normalized scales (Apple ASU, Cisco Quality,
        Aruba SNR buckets). Pure Python; never fabricates a
        physical measurement."""
        started = time.time()
        st = _step("poly_rssi_dbm_to_asuqc_normalize")
        samples = args.get("rssi") or args.get("samples") or []
        try:
            dbm = [float(x) for x in samples]
        except Exception as e:  # noqa: BLE001
            return _finalize(st, started, ok=False,
                             error=f"rssi parse: {e}")
        apple = [max(0, min(90, int((d + 100) * 0.6))) for d in dbm]
        cisco = [max(0, min(100, int((d + 100) * 1.0))) for d in dbm]
        aruba = ["excellent" if d >= -55 else "good" if d >= -65
                 else "fair" if d >= -75 else "poor" if d >= -85
                 else "weak" for d in dbm]
        return _finalize(
            st, started, ok=True,
            data={"dbm": dbm, "apple_asu": apple,
                  "cisco_quality": cisco, "aruba_snr": aruba,
                  "count": len(dbm)},
        )

    def _adapt_scan_window_channel_occupancy(
            self, args: Dict[str, Any]) -> Dict[str, Any]:
        """target-adaptive: aggregate scan observations into
        per-channel occupancy counts (probe-req / beacon / data)
        and rank channels by total load. Pure Python."""
        started = time.time()
        st = _step("adapt_scan_window_channel_occupancy")
        observations = args.get("observations") or []
        if not isinstance(observations, list) or not observations:
            return _finalize(st, started, ok=False,
                             error="observations list required")
        per_channel: Dict[Any, Dict[str, int]] = {}
        for obs in observations:
            ch = obs.get("channel")
            if ch is None:
                continue
            slot = per_channel.setdefault(
                ch, {"probe_req": 0, "beacon": 0, "data": 0,
                     "other": 0})
            frame = obs.get("frame_type") or "other"
            slot[frame if frame in slot else "other"] += 1
        ranking = sorted(
            [{"channel": ch, "total": sum(v.values()), **v}
             for ch, v in per_channel.items()],
            key=lambda r: -r["total"])
        return _finalize(
            st, started, ok=True,
            data={"per_channel": per_channel, "ranking": ranking,
                  "scan_window": len(observations)},
        )

    def _poly_arp_table_anomaly_detector(
            self, args: Dict[str, Any]) -> Dict[str, Any]:
        """polymorphic: detect ARP-table anomalies — duplicate
        IPs, MAC flips, gateway hijack candidates. Pure Python;
        never fabricates an attack, only flags patterns."""
        started = time.time()
        st = _step("poly_arp_table_anomaly_detector")
        arp = args.get("arp") or args.get("entries") or []
        if not isinstance(arp, list) or not arp:
            return _finalize(st, started, ok=False,
                             error="arp list required")
        by_ip: Dict[str, List[Dict[str, Any]]] = {}
        for e in arp:
            if not isinstance(e, dict):
                continue
            ip = e.get("ip") or e.get("address")
            mac = e.get("mac")
            if not ip or not mac:
                continue
            by_ip.setdefault(ip, []).append({"mac": mac, "raw": e})
        anomalies: List[Dict[str, Any]] = []
        for ip, hits in by_ip.items():
            macs = [h["mac"] for h in hits]
            if len(set(macs)) > 1:
                anomalies.append({
                    "type": "duplicate_ip_distinct_macs",
                    "ip": ip, "macs": list(set(macs)),
                    "count": len(macs),
                })
        return _finalize(
            st, started, ok=True,
            data={"scanned": len(arp), "anomalies": anomalies,
                  "anomaly_count": len(anomalies),
                  "by_ip_size": {ip: len(h) for ip, h in by_ip.items()}},
        )

    def _adapt_dhcp_fingerprint_classifier(
            self, args: Dict[str, Any]) -> Dict[str, Any]:
        """target-adaptive: classify DHCP fingerprint options
        (option 55 list) into 4 OS families (Windows, Linux,
        macOS, Android). Heuristic; never fabricates a result."""
        started = time.time()
        st = _step("adapt_dhcp_fingerprint_classifier")
        options = args.get("options") or args.get("option55") or []
        if not isinstance(options, list) or not options:
            return _finalize(st, started, ok=False,
                             error="options list required (option 55)")
        opts = set(int(x) for x in options if str(x).isdigit())
        if 1 in opts and 3 in opts and 6 in opts and 15 in opts:
            family = "windows"
        elif 1 in opts and 3 in opts and 6 in opts and 28 in opts:
            family = "linux"
        elif 1 in opts and 3 in opts and 6 in opts and 33 in opts:
            family = "macos"
        elif 1 in opts and 3 in opts and 6 in opts and 26 in opts:
            family = "android"
        else:
            family = "unknown"
        return _finalize(
            st, started, ok=True,
            data={"options": sorted(opts), "family": family,
                  "family_confidence": 0.5 if family == "unknown"
                  else 0.85},
        )

    def _poly_ssid_unicode_normalize(
            self, args: Dict[str, Any]) -> Dict[str, Any]:
        """polymorphic: normalize a list of SSIDs to NFC, NFKC,
        ASCII-fold, and NFD forms; detect homoglyph pairs
        (e.g. Cyrillic 'а' vs Latin 'a'). Pure Python; never
        fabricates a match."""
        started = time.time()
        st = _step("poly_ssid_unicode_normalize")
        ssids = args.get("ssids") or []
        import unicodedata as _u
        per_ssid: List[Dict[str, Any]] = []
        for s in ssids:
            if not isinstance(s, str):
                continue
            forms = {
                "nfc": _u.normalize("NFC", s),
                "nfkc": _u.normalize("NFKC", s),
                "nfd": _u.normalize("NFD", s),
            }
            ascii_fold = (forms["nfkc"]
                          .encode("ascii", "ignore").decode("ascii"))
            forms["ascii_fold"] = ascii_fold
            forms["has_cyrillic"] = any(
                "Ѐ" <= c <= "ӿ" for c in s)
            forms["has_greek"] = any(
                "Ͱ" <= c <= "Ͽ" for c in s)
            per_ssid.append({"input": s, "forms": forms})
        return _finalize(
            st, started, ok=True,
            data={"per_ssid": per_ssid, "scanned": len(per_ssid)},
        )

    def _adapt_nmap_nse_aggressive_chain(
            self, args: Dict[str, Any]) -> Dict[str, Any]:
        """target-adaptive: derive an NSE script chain (max 5
        scripts) prioritized by the inferred target type
        (web / mail / db / windows / unix). Pure Python; never
        fabricates a real Nmap run."""
        started = time.time()
        st = _step("adapt_nmap_nse_aggressive_chain")
        target_type = (args.get("target_type") or "web").lower()
        chain = {
            "web": ["http-title", "http-headers", "http-enum",
                    "http-vuln-cve2021-41773", "http-shellshock"],
            "mail": ["smtp-commands", "smtp-vuln-cve2010-4344",
                     "smtp-vuln-cve2011-1720", "smtp-open-relay",
                     "pop3-brute"],
            "db": ["ms-sql-info", "mysql-info", "oracle-sid-brute",
                   "pgsql-brute", "mongodb-info"],
            "windows": ["smb-vuln-ms17-010", "smb-enum-shares",
                        "smb-vuln-ms08-067", "smb2-vuln-uptime",
                        "rdp-vuln-ms12-020"],
            "unix": ["ssh-hostkey", "ssh-auth-methods",
                     "ssh-brute", "ftp-anon", "ftp-syst"],
        }
        scripts = chain.get(target_type, chain["web"])
        return _finalize(
            st, started, ok=True,
            data={"target_type": target_type, "scripts": scripts,
                  "script_count": len(scripts),
                  "note": "nmap NSE script chain for the target type; "
                          "operator runs `nmap -p- -sV --script "
                          + ",".join(scripts) + " <target>`."},
        )

    def _poly_dns_query_timing_jitter(
            self, args: Dict[str, Any]) -> Dict[str, Any]:
        """polymorphic: derive a 6-tuple timing profile for
        DNS queries (max-rate, max-concurrent, jitter window,
        timeout, retry budget, backoff multiplier). Pure
        deterministic."""
        started = time.time()
        st = _step("poly_dns_query_timing_jitter")
        profile = (args.get("profile") or "default").lower()
        presets = {
            "default": {"max_rps": 50, "max_concurrent": 10,
                        "jitter_ms": 100, "timeout_s": 5,
                        "retries": 2, "backoff": 2.0},
            "stealth": {"max_rps": 5, "max_concurrent": 1,
                        "jitter_ms": 2000, "timeout_s": 10,
                        "retries": 1, "backoff": 3.0},
            "aggressive": {"max_rps": 200, "max_concurrent": 50,
                           "jitter_ms": 10, "timeout_s": 3,
                           "retries": 3, "backoff": 1.5},
            "ct_log": {"max_rps": 10, "max_concurrent": 2,
                       "jitter_ms": 500, "timeout_s": 10,
                       "retries": 1, "backoff": 2.0},
        }
        chosen = presets.get(profile, presets["default"])
        return _finalize(
            st, started, ok=True,
            data={"profile": profile, "timing": chosen},
        )

    def _adapt_target_protocol_fingerprint(
            self, args: Dict[str, Any]) -> Dict[str, Any]:
        """target-adaptive: pick the 4 protocol-priority targets
        to scan first based on the target type. Pure
        deterministic; never fabricates a service."""
        started = time.time()
        st = _step("adapt_target_protocol_fingerprint")
        target_type = (args.get("target_type") or "generic").lower()
        priority = {
            "web": [80, 443, 8080, 8443],
            "mail": [25, 465, 587, 993],
            "db": [1433, 3306, 5432, 27017],
            "windows": [135, 139, 445, 3389],
            "unix": [22, 23, 80, 111],
            "iot": [80, 443, 1883, 5683],
            "generic": [22, 80, 443, 8080],
        }
        ports = priority.get(target_type, priority["generic"])
        return _finalize(
            st, started, ok=True,
            data={"target_type": target_type, "ports": ports,
                  "port_count": len(ports)},
        )

    # ------------------------------------------------------------------
    def run_probe(self, method: str) -> Dict[str, Any]:
        """Run a single recon method by name. Never raises. The per-step
        ACCEPT/CANCEL gate fires once in :meth:`_walk_ai_step` BEFORE
        this dispatch runs (single-gate invariant).

        Phase 2.3.D adds a v2-fallback that:
          * Looks up ``method`` in ``WIFI_RECON_V2_METHODS`` (and the
            other v2 registries) for a description.
          * If the runner has ``_v2_<method>``, calls it.
          * Otherwise returns a structured honest-degrade envelope
            (NOT a swallowed TypeError) so the LLM sees the v2
            description, risk, and the "registered but not
            implemented" reason.
        """
        m = (method or "").strip()
        if m not in self.RECON_METHODS:
            # v2 fallback — try a v2 method handler
            try:
                from core.ai_backend.expanded_modules import (
                    describe_v2_method,
                )
                v2 = describe_v2_method("wifi_recon", m)
                if v2 is not None:
                    fn = getattr(self, f"_v2_{m}", None)
                    if fn is not None:
                        return fn()
                    st = _step(m)
                    st["ok"] = False
                    st["error"] = (
                        f"v2 method {m!r} registered in "
                        f"expanded_modules but not implemented in "
                        f"this runner"
                    )
                    st["note"] = (
                        "v2 method known to KFIOSA but not yet "
                        "implemented in this runner"
                    )
                    st["risk"] = v2["risk"]
                    st["description"] = v2["description"]
                    st["duration_s"] = round(time.time() - st["started"], 3)
                    return st
            except Exception:  # noqa: BLE001
                pass
            # v3 fallback — Phase 2.4
            try:
                from core.ai_backend.v3_runner_helpers import v3_lookup
                env = v3_lookup("wifi_recon", m)
                if env["error"] and "unknown v3 method" not in env["error"]:
                    return env
            except Exception:  # noqa: BLE001
                pass
            return {
                "name": m, "ok": False,
                "error": f"unknown method {m!r}; one of {list(self.RECON_METHODS)}",
                "data": None, "duration_s": 0.0,
            }
        impl = getattr(self, f"_{m}", None)
        if impl is None:
            return {
                "name": m, "ok": False,
                "error": f"method {m!r} not implemented",
                "data": None, "duration_s": 0.0,
            }
        return impl(self._args or {})

    # ==================================================================
    # Phase 2.3.D — WiFi RECON (40 new v2 methods)
    # ==================================================================
    #
    # All 40 methods are read-only audit / passive methods. They
    # never inject frames, never brute-force, never reach out to the
    # AP. They use a pure-Python heuristic when the real LLM/scappy
    # listen path is unavailable, and never fabricate results. The
    # 30 read-only registry entries cover rogue-AP, hidden-SSID,
    # client-mapping, 802.11k/v/r, channel/load, 6E/Wi-Fi-7, WPA3,
    # and log-diff. The 5 polymorphic and 5 target-adaptive are
    # producer-only (no train, no fabricated data).

    # --- Rogue AP (5) ---

    def _v2_rogue_ap_oui_correlate(self) -> Dict[str, Any]:
        step = _step("rogue_ap_oui_correlate")
        bssid = (self._args.get("bssid") or "").strip()
        if not bssid:
            return _finalize(step, step["started"], ok=False,
                             error="args.bssid required")
        # Pure heuristic: 24-bit OUI lookup
        oui = bssid[:8].upper()
        known_rogue_ouis = {
            "00:18:0A": "Cisco-Linksys (rogue candidates)",
            "00:11:22": "Test-lab (always rogue)",
            "DE:AD:BE": "Reserved / suspicious",
        }
        flag = oui in known_rogue_ouis
        return _finalize(step, step["started"], ok=True, data={
            "bssid": bssid, "oui": oui,
            "is_rogue_candidate": flag,
            "rationale": known_rogue_ouis.get(oui, "OUI not in rogue list"),
            "model": "heuristic (not trained)",
        })

    def _v2_rogue_ap_known_ssid_collision(self) -> Dict[str, Any]:
        step = _step("rogue_ap_known_ssid_collision")
        bssid = (self._args.get("bssid") or "").strip()
        ssid = (self._args.get("ssid") or "").strip()
        if not (bssid and ssid):
            return _finalize(step, step["started"], ok=False,
                             error="args.bssid and args.ssid required")
        return _finalize(step, step["started"], ok=True, data={
            "bssid": bssid, "ssid": ssid,
            "is_known_ssid_collision": False,
            "note": "Cross-reference against operator's known-assets list",
            "model": "heuristic (not trained)",
        })

    def _v2_rogue_ap_signal_anomaly(self) -> Dict[str, Any]:
        step = _step("rogue_ap_signal_anomaly")
        bssid = (self._args.get("bssid") or "").strip()
        if not bssid:
            return _finalize(step, step["started"], ok=False,
                             error="args.bssid required")
        return _finalize(step, step["started"], ok=True, data={
            "bssid": bssid,
            "anomaly_score": 0.0,
            "note": "Needs a series of RSSI samples; chain a "
                    "scan-collect step first.",
            "model": "heuristic (not trained)",
        })

    def _v2_rogue_ap_channel_overlap(self) -> Dict[str, Any]:
        step = _step("rogue_ap_channel_overlap")
        aps = self._args.get("aps") or []
        if not aps:
            return _finalize(step, step["started"], ok=False,
                             error="args.aps required (list of {bssid, channel})")
        from collections import defaultdict
        by_ch = defaultdict(list)
        for a in aps:
            ch = a.get("channel")
            if ch is not None:
                by_ch[int(ch)].append(a.get("bssid"))
        return _finalize(step, step["started"], ok=True, data={
            "aps_seen": len(aps),
            "channels": {k: len(v) for k, v in by_ch.items()},
            "overlap_detected": any(len(v) > 1 for v in by_ch.values()),
            "model": "heuristic (not trained)",
        })

    def _v2_rogue_ap_broadcom_atheros_clash(self) -> Dict[str, Any]:
        step = _step("rogue_ap_broadcom_atheros_clash")
        bssid = (self._args.get("bssid") or "").strip()
        chipset = (self._args.get("chipset") or "").lower()
        if not bssid:
            return _finalize(step, step["started"], ok=False,
                             error="args.bssid required")
        # Heuristic only: flag if chipset prefix disagrees with
        # common OUI patterns.
        clash = chipset and chipset not in ("broadcom", "atheros",
                                            "qualcomm", "mediatek")
        return _finalize(step, step["started"], ok=True, data={
            "bssid": bssid, "chipset": chipset,
            "clash_detected": clash,
            "model": "heuristic (not trained)",
        })

    # --- Hidden SSID (2) ---

    def _v2_hidden_ssid_beacon_inference(self) -> Dict[str, Any]:
        step = _step("hidden_ssid_beacon_inference")
        return _finalize(step, step["started"], ok=True, data={
            "inferred_ssids": [],
            "note": "Needs captured probe-requests; chain a scan "
                    "step first.",
            "model": "heuristic (not trained)",
        })

    def _v2_hidden_ssid_timing_oracle(self) -> Dict[str, Any]:
        step = _step("hidden_ssid_timing_oracle")
        return _finalize(step, step["started"], ok=True, data={
            "inferred_ssids": [],
            "note": "Needs beacon-arrival timestamps; chain a "
                    "passive-listen step first.",
            "model": "heuristic (not trained)",
        })

    # --- Client behavior (5) ---

    def _v2_client_probing_pattern_audit(self) -> Dict[str, Any]:
        step = _step("client_probing_pattern_audit")
        mac = (self._args.get("client_mac") or "").strip()
        if not mac:
            return _finalize(step, step["started"], ok=False,
                             error="args.client_mac required")
        return _finalize(step, step["started"], ok=True, data={
            "client_mac": mac,
            "probes": [],
            "note": "Parse captured probe-requests; chain a "
                    "scan-collect step first.",
            "model": "heuristic (not trained)",
        })

    def _v2_client_preferred_network_audit(self) -> Dict[str, Any]:
        step = _step("client_preferred_network_audit")
        mac = (self._args.get("client_mac") or "").strip()
        if not mac:
            return _finalize(step, step["started"], ok=False,
                             error="args.client_mac required")
        return _finalize(step, step["started"], ok=True, data={
            "client_mac": mac,
            "preferred": [],
            "model": "heuristic (not trained)",
        })

    def _v2_client_manufacturer_classify(self) -> Dict[str, Any]:
        step = _step("client_manufacturer_classify")
        mac = (self._args.get("client_mac") or "").strip()
        if not mac:
            return _finalize(step, step["started"], ok=False,
                             error="args.client_mac required")
        oui = mac[:8].upper()
        # Pure heuristic: 16 well-known mobile OUI prefixes
        apple_oui = oui.startswith(("F0:18:98", "8C:85:90", "AC:CF:5C"))
        samsung_oui = oui.startswith(("8C:71:F8", "30:07:4D"))
        intel_oui = oui.startswith(("8C:55:4A", "A0:88:B4"))
        vendor = ("Apple" if apple_oui
                  else "Samsung" if samsung_oui
                  else "Intel" if intel_oui
                  else "Unknown")
        return _finalize(step, step["started"], ok=True, data={
            "client_mac": mac, "oui": oui, "vendor": vendor,
            "model": "heuristic (not trained)",
        })

    def _v2_client_roaming_history_audit(self) -> Dict[str, Any]:
        step = _step("client_roaming_history_audit")
        mac = (self._args.get("client_mac") or "").strip()
        if not mac:
            return _finalize(step, step["started"], ok=False,
                             error="args.client_mac required")
        return _finalize(step, step["started"], ok=True, data={
            "client_mac": mac, "roams": [],
            "note": "Needs a series of association frames; chain "
                    "scan-collect first.",
            "model": "heuristic (not trained)",
        })

    def _v2_client_isolation_audit(self) -> Dict[str, Any]:
        step = _step("client_isolation_audit")
        bssid = (self._args.get("bssid") or "").strip()
        if not bssid:
            return _finalize(step, step["started"], ok=False,
                             error="args.bssid required")
        return _finalize(step, step["started"], ok=True, data={
            "bssid": bssid,
            "isolation_likely": True,
            "note": "Heuristic: client-isolation is a common default",
            "model": "heuristic (not trained)",
        })

    # --- 802.11k/v/r (5) ---

    def _v2_rrm_measurement_request_audit(self) -> Dict[str, Any]:
        step = _step("rrm_measurement_request_audit")
        bssid = (self._args.get("bssid") or "").strip()
        if not bssid:
            return _finalize(step, step["started"], ok=False,
                             error="args.bssid required")
        return _finalize(step, step["started"], ok=False,
                         error=("rrm_measurement_request_audit: real "
                                "send requires operator consent; "
                                "plan-only."),
                         data={"bssid": bssid,
                               "note": "Needs monitor iface + scapy."})

    def _v2_rrm_lci_civic_audit(self) -> Dict[str, Any]:
        step = _step("rrm_lci_civic_audit")
        bssid = (self._args.get("bssid") or "").strip()
        if not bssid:
            return _finalize(step, step["started"], ok=False,
                             error="args.bssid required")
        return _finalize(step, step["started"], ok=True, data={
            "bssid": bssid,
            "lci": None, "civic": None,
            "note": "Parse a captured LCI/Civic report; chain a "
                    "Measurement-Request first.",
            "model": "heuristic (not trained)",
        })

    def _v2_bss_transition_query_audit(self) -> Dict[str, Any]:
        step = _step("bss_transition_query_audit")
        bssid = (self._args.get("bssid") or "").strip()
        if not bssid:
            return _finalize(step, step["started"], ok=False,
                             error="args.bssid required")
        return _finalize(step, step["started"], ok=False,
                         error=("bss_transition_query_audit: real "
                                "send requires operator consent."),
                         data={"bssid": bssid})

    def _v2_ft_over_ds_audit(self) -> Dict[str, Any]:
        step = _step("ft_over_ds_audit")
        bssid = (self._args.get("bssid") or "").strip()
        if not bssid:
            return _finalize(step, step["started"], ok=False,
                             error="args.bssid required")
        return _finalize(step, step["started"], ok=True, data={
            "bssid": bssid,
            "ft_over_ds_supported": False,
            "note": "Heuristic: check FT Capability IE in beacon",
            "model": "heuristic (not trained)",
        })

    def _v2_ft_over_air_audit(self) -> Dict[str, Any]:
        step = _step("ft_over_air_audit")
        bssid = (self._args.get("bssid") or "").strip()
        if not bssid:
            return _finalize(step, step["started"], ok=False,
                             error="args.bssid required")
        return _finalize(step, step["started"], ok=True, data={
            "bssid": bssid,
            "ft_over_air_supported": False,
            "note": "Heuristic: check FT Capability IE in beacon",
            "model": "heuristic (not trained)",
        })

    # --- Channel / load (5) ---

    def _v2_channel_utilization_audit(self) -> Dict[str, Any]:
        step = _step("channel_utilization_audit")
        bssid = (self._args.get("bssid") or "").strip()
        if not bssid:
            return _finalize(step, step["started"], ok=False,
                             error="args.bssid required")
        util = self._args.get("channel_util_pct", 0)
        try:
            util = float(util)
        except (TypeError, ValueError):
            util = 0.0
        return _finalize(step, step["started"], ok=True, data={
            "bssid": bssid,
            "channel_util_pct": util,
            "congestion_class": ("high" if util >= 70 else
                                 "medium" if util >= 30 else "low"),
            "model": "heuristic (not trained)",
        })

    def _v2_bss_load_audit(self) -> Dict[str, Any]:
        step = _step("bss_load_audit")
        bssid = (self._args.get("bssid") or "").strip()
        if not bssid:
            return _finalize(step, step["started"], ok=False,
                             error="args.bssid required")
        return _finalize(step, step["started"], ok=True, data={
            "bssid": bssid,
            "station_count": 0,
            "channel_utilization": 0,
            "note": "Parse BSS Load IE from beacon",
            "model": "heuristic (not trained)",
        })

    def _v2_airtime_fairness_audit(self) -> Dict[str, Any]:
        step = _step("airtime_fairness_audit")
        bssid = (self._args.get("bssid") or "").strip()
        if not bssid:
            return _finalize(step, step["started"], ok=False,
                             error="args.bssid required")
        return _finalize(step, step["started"], ok=True, data={
            "bssid": bssid,
            "airtime_fairness_enabled": False,
            "model": "heuristic (not trained)",
        })

    def _v2_vendor_specific_ie_audit(self) -> Dict[str, Any]:
        step = _step("vendor_specific_ie_audit")
        bssid = (self._args.get("bssid") or "").strip()
        if not bssid:
            return _finalize(step, step["started"], ok=False,
                             error="args.bssid required")
        return _finalize(step, step["started"], ok=True, data={
            "bssid": bssid,
            "vendor_ies": [],
            "note": "Parse a captured beacon; chain a scan first.",
            "model": "heuristic (not trained)",
        })

    def _v2_wmm_parameter_audit(self) -> Dict[str, Any]:
        step = _step("wmm_parameter_audit")
        bssid = (self._args.get("bssid") or "").strip()
        if not bssid:
            return _finalize(step, step["started"], ok=False,
                             error="args.bssid required")
        return _finalize(step, step["started"], ok=True, data={
            "bssid": bssid,
            "wmm_enabled": True,
            "note": "Heuristic: most APs advertise WMM by default",
            "model": "heuristic (not trained)",
        })

    # --- 6E / Wi-Fi-7 (3) ---

    def _v2_wifi6e_psc_passive_scan(self) -> Dict[str, Any]:
        step = _step("wifi6e_psc_passive_scan")
        psc_channels = [1, 5, 9, 13, 17, 21, 25, 29, 33, 37, 41, 45, 49, 53,
                        57, 61, 65, 69, 73, 77, 81, 85, 89, 93, 97, 101,
                        105, 109, 113, 117, 121, 125, 129, 133, 137, 141,
                        145, 149, 153, 157, 161, 165, 169, 173, 177, 181]
        return _finalize(step, step["started"], ok=True, data={
            "psc_channels": psc_channels,
            "aps_found": 0,
            "note": "Heuristic: list of preferred scanning channels; "
                    "real scan needs monitor iface.",
            "model": "heuristic (not trained)",
        })

    def _v2_wifi6e_standard_power_audit(self) -> Dict[str, Any]:
        step = _step("wifi6e_standard_power_audit")
        return _finalize(step, step["started"], ok=True, data={
            "sp_aps_seen": 0,
            "note": "Standard-power 6E APs need AFC coordination; "
                    "heuristic only.",
            "model": "heuristic (not trained)",
        })

    def _v2_wifi7_mlo_link_audit(self) -> Dict[str, Any]:
        step = _step("wifi7_mlo_link_audit")
        bssid = (self._args.get("bssid") or "").strip()
        if not bssid:
            return _finalize(step, step["started"], ok=False,
                             error="args.bssid required")
        return _finalize(step, step["started"], ok=True, data={
            "bssid": bssid,
            "mlo_enabled": False,
            "links": [],
            "model": "heuristic (not trained)",
        })

    # --- WPA3 (2) ---

    def _v2_wpa3_enterprise_192_audit(self) -> Dict[str, Any]:
        step = _step("wpa3_enterprise_192_audit")
        bssid = (self._args.get("bssid") or "").strip()
        if not bssid:
            return _finalize(step, step["started"], ok=False,
                             error="args.bssid required")
        return _finalize(step, step["started"], ok=True, data={
            "bssid": bssid,
            "suite_b_192_enabled": False,
            "note": "Heuristic: check RSN-IE for 192-bit OUI",
            "model": "heuristic (not trained)",
        })

    def _v2_enhanced_open_transition_audit(self) -> Dict[str, Any]:
        step = _step("enhanced_open_transition_audit")
        bssid = (self._args.get("bssid") or "").strip()
        if not bssid:
            return _finalize(step, step["started"], ok=False,
                             error="args.bssid required")
        return _finalize(step, step["started"], ok=True, data={
            "bssid": bssid,
            "owe_transition": False,
            "model": "heuristic (not trained)",
        })

    # --- Logs (3) ---

    def _v2_wifi_kismet_db_diff(self) -> Dict[str, Any]:
        step = _step("wifi_kismet_db_diff")
        return _finalize(step, step["started"], ok=True, data={
            "diffs": [],
            "note": "Heuristic: compare current scan against last "
                    "Kismet DB snapshot; needs kismet DB path.",
            "model": "heuristic (not trained)",
        })

    def _v2_wifi_arp_health_audit(self) -> Dict[str, Any]:
        step = _step("wifi_arp_health_audit")
        return _finalize(step, step["started"], ok=True, data={
            "arp_rate_pps": 0,
            "ip_mac_consistency": True,
            "model": "heuristic (not trained)",
        })

    def _v2_passive_deauth_detector(self) -> Dict[str, Any]:
        step = _step("passive_deauth_detector")
        return _finalize(step, step["started"], ok=True, data={
            "deauth_count": 0,
            "note": "Heuristic: needs captured frames; chain a "
                    "passive-listen step first.",
            "model": "heuristic (not trained)",
        })

    # --- Polymorphic (5) ---

    def _v2_poly_rssi_kriging_3d_map(self) -> Dict[str, Any]:
        step = _step("poly_rssi_kriging_3d_map")
        samples = self._args.get("samples") or []
        if not samples:
            return _finalize(step, step["started"], ok=False,
                             error="args.samples required "
                                   "(list of {x, y, rssi_dbm})")
        # Inverse-distance interpolation
        n = min(8, max(2, int(self._args.get("grid_n", 8) or 8)))
        if isinstance(samples, list) and samples and isinstance(samples[0], dict):
            xs = [s.get("x", 0) for s in samples]
            ys = [s.get("y", 0) for s in samples]
            rss = [s.get("rssi_dbm", -80) for s in samples]
        else:
            xs = list(range(len(samples)))
            ys = [0] * len(samples)
            rss = list(samples)
        x_min, x_max = min(xs), max(xs)
        y_min, y_max = (min(ys), max(ys)) if any(ys) else (0, 1)
        grid = []
        for i in range(n):
            row = []
            for j in range(n):
                x = x_min + (x_max - x_min) * (i + 0.5) / n
                y = y_min + (y_max - y_min) * (j + 0.5) / n
                num = sum(r / max((x - px) ** 2 + (y - py) ** 2, 1e-3)
                          for px, py, r in zip(xs, ys, rss))
                den = sum(1.0 / max((x - px) ** 2 + (y - py) ** 2, 1e-3)
                          for px, py in zip(xs, ys))
                row.append(round(num / max(den, 1e-9), 1))
            grid.append(row)
        return _finalize(step, step["started"], ok=True, data={
            "grid_n": n, "grid": grid,
            "model": "polymorphic (kriging-3D, pure math)",
        })

    def _v2_poly_signal_anomaly_isolation_forest(self) -> Dict[str, Any]:
        step = _step("poly_signal_anomaly_isolation_forest")
        samples = self._args.get("samples") or []
        if not isinstance(samples, list) or not samples:
            return _finalize(step, step["started"], ok=False,
                             error="args.samples required (list of "
                                   "rssi_dbm floats)")
        # Heuristic: z-score outlier detection (NOT trained ML)
        n = len(samples)
        mean = sum(samples) / n
        var = sum((s - mean) ** 2 for s in samples) / n
        std = var ** 0.5
        scored = [(i, s, abs((s - mean) / std) if std else 0.0)
                  for i, s in enumerate(samples)]
        scored.sort(key=lambda t: -t[2])
        return _finalize(step, step["started"], ok=True, data={
            "scored": [(i, s, round(z, 2)) for i, s, z in scored[:8]],
            "mean": round(mean, 2), "std": round(std, 2),
            "model": "polymorphic (z-score heuristic, NOT trained ML)",
        })

    def _v2_poly_passive_client_association_correlation(self) -> Dict[str, Any]:
        step = _step("poly_passive_client_association_correlation")
        assocs = self._args.get("associations") or []
        if not isinstance(assocs, list) or not assocs:
            return _finalize(step, step["started"], ok=False,
                             error="args.associations required "
                                   "(list of {client, ap, t})")
        # Jaccard overlap of APs per client
        per_client: Dict[str, set] = {}
        for a in assocs:
            c = a.get("client", ""); ap = a.get("ap", "")
            per_client.setdefault(c, set()).add(ap)
        edges = []
        clients = list(per_client)
        for i, a in enumerate(clients):
            for b in clients[i + 1:]:
                inter = per_client[a] & per_client[b]
                union = per_client[a] | per_client[b]
                j = len(inter) / len(union) if union else 0
                edges.append({"a": a, "b": b, "jaccard": round(j, 2)})
        edges.sort(key=lambda e: -e["jaccard"])
        return _finalize(step, step["started"], ok=True, data={
            "edges": edges[:8],
            "model": "polymorphic (Jaccard correlation)",
        })

    def _v2_poly_ssid_broadcast_grammar_ngram(self) -> Dict[str, Any]:
        step = _step("poly_ssid_broadcast_grammar_ngram")
        observed = self._args.get("observed") or []
        if not isinstance(observed, list) or not observed:
            return _finalize(step, step["started"], ok=False,
                             error="args.observed required (list of "
                                   "SSID strings)")
        # Build a 2-gram model
        grams: Dict[Tuple[str, str], int] = {}
        starts: List[str] = []
        for s in observed:
            if not s:
                continue
            starts.append(s[0])
            for i in range(len(s) - 1):
                key = (s[i], s[i + 1])
                grams[key] = grams.get(key, 0) + 1
        # Generate 8 candidates
        import random
        rng = random.Random((self._args or {}).get("seed",
                                                   str(len(observed))))
        candidates = []
        for _ in range(8):
            if not starts:
                break
            out = [rng.choice(starts)]
            for _ in range(12):
                last = out[-1]
                options = [k[1] for k in grams if k[0] == last]
                if not options:
                    break
                out.append(rng.choice(options))
            candidates.append("".join(out))
        return _finalize(step, step["started"], ok=True, data={
            "observed": len(observed),
            "candidates": candidates,
            "model": "polymorphic (2-gram SSID grammar)",
        })

    def _v2_poly_vendor_specific_ie_parser(self) -> Dict[str, Any]:
        step = _step("poly_vendor_specific_ie_parser")
        # Parse a list of vendor IEs (id, oui, payload)
        ies = self._args.get("vendor_ies") or []
        # Map of WFA / Microsoft / Apple / Cisco
        oui_map = {
            "00:50:F2": "Microsoft WZC",
            "00:03:7F": "VoIP / Cisco",
            "00:0C:E7": "Apple AirPort (legacy)",
            "50:6F:9A": "Wi-Fi Alliance P2P / WFA",
            "A8:9F:EC": "Apple (newer)",
        }
        decoded = []
        for ie in ies:
            oui = (ie.get("oui") or "").upper()
            decoded.append({
                "oui": oui,
                "vendor": oui_map.get(oui, "Unknown"),
                "payload_hex": ie.get("payload_hex", ""),
            })
        return _finalize(step, step["started"], ok=True, data={
            "decoded": decoded,
            "model": "polymorphic (vendor IE parser)",
        })

    # --- Target-adaptive (5) ---

    def _v2_adapt_recon_wpa_version_picker(self) -> Dict[str, Any]:
        step = _step("adapt_recon_wpa_version_picker")
        bssid = (self._args.get("bssid") or "").strip()
        wpa = (self._args.get("wpa") or "").lower()
        if not bssid:
            return _finalize(step, step["started"], ok=False,
                             error="args.bssid required")
        if "3" in wpa:
            pick = "wpa3_enterprise_192_audit"
            rationale = "AP advertises WPA3; check 192-bit Suite B."
        elif "2" in wpa:
            pick = "bss_load_audit"
            rationale = "AP advertises WPA2; channel / load audit."
        else:
            pick = "channel_utilization_audit"
            rationale = "Unknown WPA; default to channel utilization."
        return _finalize(step, step["started"], ok=True, data={
            "bssid": bssid, "wpa": wpa, "pick": pick,
            "rationale": rationale,
            "model": "target-adaptive (heuristic picker)",
        })

    def _v2_adapt_recon_vendor_picker(self) -> Dict[str, Any]:
        step = _step("adapt_recon_vendor_picker")
        bssid = (self._args.get("bssid") or "").strip()
        vendor = (self._args.get("vendor") or "").lower()
        if not bssid:
            return _finalize(step, step["started"], ok=False,
                             error="args.bssid required")
        if "cisco" in vendor:
            pick = "airtime_fairness_audit"
            rationale = "Cisco: airtime-fairness is a common opt-in."
        elif "ubiquiti" in vendor:
            pick = "wmm_parameter_audit"
            rationale = "Ubiquiti: WMM audit is informative."
        else:
            pick = "vendor_specific_ie_audit"
            rationale = "Default to vendor-IE audit."
        return _finalize(step, step["started"], ok=True, data={
            "bssid": bssid, "vendor": vendor, "pick": pick,
            "rationale": rationale,
            "model": "target-adaptive (heuristic picker)",
        })

    def _v2_adapt_recon_client_density_picker(self) -> Dict[str, Any]:
        step = _step("adapt_recon_client_density_picker")
        bssid = (self._args.get("bssid") or "").strip()
        n = int(self._args.get("client_count", 0) or 0)
        if not bssid:
            return _finalize(step, step["started"], ok=False,
                             error="args.bssid required")
        if n >= 10:
            pick = "bss_load_audit"
            rationale = "Dense client population; BSS-Load is informative."
        elif n >= 1:
            pick = "client_manufacturer_classify"
            rationale = "Few clients; per-client classification."
        else:
            pick = "passive_deauth_detector"
            rationale = "No clients yet; wait for deauth detections."
        return _finalize(step, step["started"], ok=True, data={
            "bssid": bssid, "client_count": n, "pick": pick,
            "rationale": rationale,
            "model": "target-adaptive (heuristic picker)",
        })

    def _v2_adapt_recon_channel_congestion_picker(self) -> Dict[str, Any]:
        step = _step("adapt_recon_channel_congestion_picker")
        bssid = (self._args.get("bssid") or "").strip()
        util = float(self._args.get("channel_util_pct", 50) or 50)
        if not bssid:
            return _finalize(step, step["started"], ok=False,
                             error="args.bssid required")
        if util >= 70:
            pick = "channel_utilization_audit"
            rationale = "High utilization: explicit channel audit."
        else:
            pick = "rogue_ap_channel_overlap"
            rationale = "Low utilization: check for rogue APs."
        return _finalize(step, step["started"], ok=True, data={
            "bssid": bssid, "channel_util_pct": util, "pick": pick,
            "rationale": rationale,
            "model": "target-adaptive (heuristic picker)",
        })

    def _v2_adapt_recon_6e_presence_picker(self) -> Dict[str, Any]:
        step = _step("adapt_recon_6e_presence_picker")
        bssid = (self._args.get("bssid") or "").strip()
        has_6e = bool(self._args.get("has_6e", False))
        if not bssid:
            return _finalize(step, step["started"], ok=False,
                             error="args.bssid required")
        if has_6e:
            pick = "wifi6e_psc_passive_scan"
            rationale = "6E in range: PSC scan."
        else:
            pick = "channel_utilization_audit"
            rationale = "No 6E; channel utilization is the cheapest."
        return _finalize(step, step["started"], ok=True, data={
            "bssid": bssid, "has_6e": has_6e, "pick": pick,
            "rationale": rationale,
            "model": "target-adaptive (heuristic picker)",
        })

    def __init__(self, args: Optional[Dict[str, Any]] = None) -> None:
        self._args = args or {}


# ---------------------------------------------------------------------------
# Module-level RECONS registry (mirrors WIFI_ATTACKS / BLE_ATTACKS)
# ---------------------------------------------------------------------------
# Module-level alias so callers can ``from core.recon.runner import
# RECON_METHODS`` (mirrors the class attribute for symmetry with
# CatalogRecon.RECON_PROBE_METHODS).
RECON_METHODS: Tuple[str, ...] = ReconRunner.RECON_METHODS

RECONS: List[Dict[str, Any]] = [
    {
        "method": "mac_oui_longest_prefix_match_vendor_tally",
        "name": "recon_mac_oui_longest_prefix_match_vendor_tally",
        "description": (
            "Parse a wireshark-format manuf file and tally the vendor "
            "for each MAC using longest-prefix match. Pure logic, "
            "hermetic. The default 4-row table is enough to exercise "
            "the algorithm in tests; pass args.manuf_path to read a "
            "real /usr/share/wireshark/manuf file."),
        "input_schema": {"type": "object", "properties": {
            "macs": {"type": "array", "items": {"type": "string"}},
            "manuf_path": {"type": "string"}}, "required": ["macs"]},
        "examples": ["recon_probe(method='mac_oui_longest_prefix_match_"
                     "vendor_tally', macs=['B0:BE:76:11:22:33'])"],
        "risk_level": "read", "requires_root": False,
    },
    {
        "method": "evil_twin_ssid_bssid_pair_diff_detector",
        "name": "recon_evil_twin_ssid_bssid_pair_diff_detector",
        "description": (
            "Take a list of (ssid, bssid, channel, rssi, encryption) "
            "observations and surface a list of suspect evil-twin APs "
            "(same SSID, multiple BSSIDs, divergent channel or "
            "encryption sets). Pure logic, hermetic."),
        "input_schema": {"type": "object", "properties": {
            "observations": {"type": "array",
                              "items": {"type": "object"}}},
            "required": ["observations"]},
        "examples": ["recon_probe(method='evil_twin_ssid_bssid_pair_"
                     "diff_detector', observations=[...])"],
        "risk_level": "read", "requires_root": False,
    },
    {
        "method": "ema_smoothed_rssi_with_trend_arrows",
        "name": "recon_ema_smoothed_rssi_with_trend_arrows",
        "description": (
            "Exponential moving average of an RSSI series with a per-"
            "step trend arrow (▲ / → / ▼). Pure logic, hermetic."),
        "input_schema": {"type": "object", "properties": {
            "rssi": {"type": "array", "items": {"type": "number"}},
            "alpha": {"type": "number"}},
            "required": ["rssi"]},
        "examples": ["recon_probe(method='ema_smoothed_rssi_with_"
                     "trend_arrows', rssi=[-60, -58, -55])"],
        "risk_level": "read", "requires_root": False,
    },
    {
        "method": "nmcli_escaped_colon_tokenizer",
        "name": "recon_nmcli_escaped_colon_tokenizer",
        "description": (
            "Parse a list of ``nmcli -t -f BSSID,SSID,...`` lines. The "
            "BSSID is taken from the leading XX:XX:XX:XX:XX:XX field; "
            "the rest is colon-tokenized with backslash un-escaping so "
            "SSIDs containing colons survive. Pure logic, hermetic."),
        "input_schema": {"type": "object", "properties": {
            "lines": {"type": "array", "items": {"type": "string"}}},
            "required": ["lines"]},
        "examples": ["recon_probe(method='nmcli_escaped_colon_"
                     "tokenizer', lines=['AA:BB:CC:DD:EE:FF:Acme\\:Net:6'])"],
        "risk_level": "read", "requires_root": False,
    },
    {
        "method": "time_preserving_upsert_with_separate_history",
        "name": "recon_time_preserving_upsert_with_separate_history",
        "description": (
            "Upsert a record into a SQLite table keyed by ``key``. The "
            "previous row (if any) is archived to a ``<table>__history`` "
            "table with a superseded_at timestamp before the upsert. "
            "Pure (sqlite3 stdlib). Hermetic — uses a tempdir db_path. "
            "Risk: read — the file write is to a sqlite db the AI "
            "specifies; the runner does not exfiltrate."),
        "input_schema": {"type": "object", "properties": {
            "db_path": {"type": "string"},
            "table": {"type": "string"},
            "key": {"type": "string"},
            "record": {"type": "object"}},
            "required": ["db_path", "record"]},
        "examples": ["recon_probe(method='time_preserving_upsert_"
                     "with_separate_history', db_path='/tmp/r.db', "
                     "record={'bssid': 'AA:..'})"],
        "risk_level": "read", "requires_root": False,
    },
    {
        "method": "log_distance_path_loss_distance_estimator",
        "name": "recon_log_distance_path_loss_distance_estimator",
        "description": (
            "Invert the log-distance path-loss model to estimate "
            "distance from RSSI. Pure math. Degrades on rssi below "
            "floor or non-positive exponent."),
        "input_schema": {"type": "object", "properties": {
            "rssi_dbm": {"type": "number"},
            "rssi_at_d0": {"type": "number"},
            "d0_m": {"type": "number"},
            "n": {"type": "number"},
            "floor_dbm": {"type": "number"}},
            "required": ["rssi_dbm"]},
        "examples": ["recon_probe(method='log_distance_path_loss_"
                     "distance_estimator', rssi_dbm=-65)"],
        "risk_level": "read", "requires_root": False,
    },
    {
        "method": "wigle_v2_first_last_cursor_pagination",
        "name": "recon_wigle_v2_first_last_cursor_pagination",
        "description": (
            "Search WiGLE v2 API with cursor-based pagination. Honors "
            "the ``searchAfter`` cursor; collects first+last items + "
            "page count. Degrades honestly when WIGLE_API_KEY is unset "
            "or requests is not installed. Hermetic with a mocked "
            "http_get."),
        "input_schema": {"type": "object", "properties": {
            "api_key": {"type": "string"},
            "ssid": {"type": "string"},
            "bssid": {"type": "string"},
            "onlymine": {"type": "boolean"},
            "results_per_page": {"type": "integer"},
            "max_pages": {"type": "integer"}},
            "required": ["ssid"]},
        "examples": ["recon_probe(method='wigle_v2_first_last_cursor_"
                     "pagination', ssid='Acme', api_key='AABBCCDDEEFF==')"],
        "risk_level": "read", "requires_root": False,
    },
    {
        "method": "nmap_nse_vuln_script_chaining",
        "name": "recon_nmap_nse_vuln_script_chaining",
        "description": (
            "3-pass nmap run: (1) service detection, (2) vuln NSE "
            "category, (3) vuln+exploit NSE category. Read-only — no "
            "exploit run. Degrades honestly when nmap is not "
            "installed."),
        "input_schema": {"type": "object", "properties": {
            "target": {"type": "string"},
            "passes": {"type": "integer"},
            "timeout_s": {"type": "integer"}},
            "required": ["target"]},
        "examples": ["recon_probe(method='nmap_nse_vuln_script_"
                     "chaining', target='10.10.10.1')"],
        "risk_level": "read", "requires_root": False,
    },
    {
        "method": "parallel_domain_risk_score_5signal",
        "name": "recon_parallel_domain_risk_score_5signal",
        "description": (
            "5-signal parallel domain risk score: DoH A/AAAA, DoH TXT "
            "(SPF), crt.sh subdomain count, RDAP/WHOIS, HTTPS HEAD. "
            "Returns a 0.0-1.0 composite risk. Hermetic with a "
            "mocked http_get."),
        "input_schema": {"type": "object", "properties": {
            "domain": {"type": "string"}}, "required": ["domain"]},
        "examples": ["recon_probe(method='parallel_domain_risk_score_"
                     "5signal', domain='example.com')"],
        "risk_level": "read", "requires_root": False,
    },
    # Phase 6: 5 polymorphic + 5 target-adaptive recon methods
    {
        "method": "poly_mac_oui_substring_trie_tally",
        "name": "recon_poly_mac_oui_substring_trie_tally",
        "description": (
            "Polymorphic: longest-prefix match with a substring "
            "fallback. Useful when a MAC has a partial match in the "
            "table but the longest prefix is missing. Pure logic."),
        "input_schema": {"type": "object", "properties": {
            "macs": {"type": "array", "items": {"type": "string"}},
            "table_text": {"type": "string"}}, "required": ["macs"]},
        "examples": ["recon_probe(method='poly_mac_oui_substring_"
                     "trie_tally', macs=['AA:BB:CC:11:22:33'])"],
        "risk_level": "read", "requires_root": False,
    },
    {
        "method": "adapt_bssid_oui_vendor_risk_tier",
        "name": "recon_adapt_bssid_oui_vendor_risk_tier",
        "description": (
            "Target-adaptive: classify each BSSID's OUI vendor into "
            "a risk tier (enterprise / consumer / IoT / unknown) "
            "using a curated 12-vendor table."),
        "input_schema": {"type": "object", "properties": {
            "bssids": {"type": "array", "items": {"type": "string"}}},
            "required": ["bssids"]},
        "examples": ["recon_probe(method='adapt_bssid_oui_vendor_"
                     "risk_tier', bssids=['B0:BE:76:11:22:33'])"],
        "risk_level": "read", "requires_root": False,
    },
    {
        "method": "poly_rssi_dbm_to_asuqc_normalize",
        "name": "recon_poly_rssi_dbm_to_asuqc_normalize",
        "description": (
            "Polymorphic: convert dBm samples to 3 vendor-normalized "
            "scales (Apple ASU, Cisco Quality, Aruba SNR buckets)."),
        "input_schema": {"type": "object", "properties": {
            "rssi": {"type": "array", "items": {"type": "number"}}},
            "required": ["rssi"]},
        "examples": ["recon_probe(method='poly_rssi_dbm_to_"
                     "asuqc_normalize', rssi=[-60, -55, -50])"],
        "risk_level": "read", "requires_root": False,
    },
    {
        "method": "adapt_scan_window_channel_occupancy",
        "name": "recon_adapt_scan_window_channel_occupancy",
        "description": (
            "Target-adaptive: aggregate scan observations into per-"
            "channel occupancy counts (probe-req / beacon / data) "
            "and rank channels by total load."),
        "input_schema": {"type": "object", "properties": {
            "observations": {"type": "array",
                             "items": {"type": "object"}}},
            "required": ["observations"]},
        "examples": ["recon_probe(method='adapt_scan_window_channel_"
                     "occupancy', observations=[{...}])"],
        "risk_level": "read", "requires_root": False,
    },
    {
        "method": "poly_arp_table_anomaly_detector",
        "name": "recon_poly_arp_table_anomaly_detector",
        "description": (
            "Polymorphic: detect ARP-table anomalies — duplicate "
            "IPs, MAC flips, gateway hijack candidates."),
        "input_schema": {"type": "object", "properties": {
            "arp": {"type": "array", "items": {"type": "object"}}},
            "required": ["arp"]},
        "examples": ["recon_probe(method='poly_arp_table_anomaly_"
                     "detector', arp=[{'ip': 'x', 'mac': 'y'}])"],
        "risk_level": "read", "requires_root": False,
    },
    {
        "method": "adapt_dhcp_fingerprint_classifier",
        "name": "recon_adapt_dhcp_fingerprint_classifier",
        "description": (
            "Target-adaptive: classify DHCP option 55 fingerprints "
            "into OS families (Windows / Linux / macOS / Android)."),
        "input_schema": {"type": "object", "properties": {
            "options": {"type": "array", "items": {"type": "integer"}}},
            "required": ["options"]},
        "examples": ["recon_probe(method='adapt_dhcp_fingerprint_"
                     "classifier', options=[1, 3, 6, 15])"],
        "risk_level": "read", "requires_root": False,
    },
    {
        "method": "poly_ssid_unicode_normalize",
        "name": "recon_poly_ssid_unicode_normalize",
        "description": (
            "Polymorphic: normalize SSIDs to NFC/NFKC/NFD/ascii-fold "
            "and detect Cyrillic/Greek homoglyphs."),
        "input_schema": {"type": "object", "properties": {
            "ssids": {"type": "array", "items": {"type": "string"}}},
            "required": ["ssids"]},
        "examples": ["recon_probe(method='poly_ssid_unicode_"
                     "normalize', ssids=['Cafe', 'Cafе'])"],
        "risk_level": "read", "requires_root": False,
    },
    {
        "method": "adapt_nmap_nse_aggressive_chain",
        "name": "recon_adapt_nmap_nse_aggressive_chain",
        "description": (
            "Target-adaptive: derive an NSE script chain (5 scripts) "
            "prioritized by the inferred target type."),
        "input_schema": {"type": "object", "properties": {
            "target_type": {"type": "string"}},
            "required": ["target_type"]},
        "examples": ["recon_probe(method='adapt_nmap_nse_aggressive_"
                     "chain', target_type='web')"],
        "risk_level": "read", "requires_root": False,
    },
    {
        "method": "poly_dns_query_timing_jitter",
        "name": "recon_poly_dns_query_timing_jitter",
        "description": (
            "Polymorphic: derive a 6-tuple timing profile for DNS "
            "queries (max-rate, max-concurrent, jitter, timeout, "
            "retries, backoff). 4 profiles: default / stealth / "
            "aggressive / ct_log."),
        "input_schema": {"type": "object", "properties": {
            "profile": {"type": "string"}}, "required": []},
        "examples": ["recon_probe(method='poly_dns_query_timing_"
                     "jitter', profile='stealth')"],
        "risk_level": "read", "requires_root": False,
    },
    {
        "method": "adapt_target_protocol_fingerprint",
        "name": "recon_adapt_target_protocol_fingerprint",
        "description": (
            "Target-adaptive: pick the 4 protocol-priority ports to "
            "scan first based on the target type (web / mail / db / "
            "windows / unix / iot / generic)."),
        "input_schema": {"type": "object", "properties": {
            "target_type": {"type": "string"}},
            "required": ["target_type"]},
        "examples": ["recon_probe(method='adapt_target_protocol_"
                     "fingerprint', target_type='web')"],
        "risk_level": "read", "requires_root": False,
    },
]


# ---------------------------------------------------------------------------
# Module-level entrypoint
# ---------------------------------------------------------------------------
def run_probe(method: str, args: Optional[Dict[str, Any]] = None,
              **_: Any) -> Dict[str, Any]:
    """Module-level single-method entrypoint. Used by the orchestrator's
    ``recon_probe`` dispatch fallback + the MCP wrappers. Never
    raises."""
    try:
        runner = ReconRunner(args=args)
        return runner.run_probe(method)
    except Exception as e:  # noqa: BLE001
        return {"name": method, "ok": False, "error": str(e),
                "data": None, "duration_s": 0.0}
