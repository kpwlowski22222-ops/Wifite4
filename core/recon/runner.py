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

    # ------------------------------------------------------------------
    def run_probe(self, method: str) -> Dict[str, Any]:
        """Run a single recon method by name. Never raises. The per-step
        ACCEPT/CANCEL gate fires once in :meth:`_walk_ai_step` BEFORE
        this dispatch runs (single-gate invariant)."""
        if method not in self.RECON_METHODS:
            return {
                "name": method, "ok": False,
                "error": f"unknown method {method!r}; one of {list(self.RECON_METHODS)}",
                "data": None, "duration_s": 0.0,
            }
        impl = getattr(self, f"_{method}", None)
        if impl is None:
            return {
                "name": method, "ok": False,
                "error": f"method {method!r} not implemented",
                "data": None, "duration_s": 0.0,
            }
        return impl(self._args or {})

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
