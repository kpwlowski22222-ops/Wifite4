"""core.post_access_tui.rat_ext.aggregate — Phase 2.4 §B.6.

Cross-session aggregate views.

Endpoints:
  GET /api/transport_summary
      Single JSON: BLE session count, network session count,
      latest handshake status, latest credential-dump status,
      total exfil bytes pending.
  GET /aggregate
      HTML: sortable table per session with transport, target,
      achieved_count, capability_count, last_activity, risk_max.
"""
from __future__ import annotations

import time
from typing import Any, Dict, List, Optional


def build_transport_summary(sessions: List[Dict[str, Any]]
                            ) -> Dict[str, Any]:
    """Build the cross-session summary JSON."""
    ble_count = 0
    net_count = 0
    last_handshake = None
    last_cred = None
    exfil_bytes = 0
    for s in sessions or []:
        transport = (s.get("transport") or s.get("kind") or "").lower()
        if transport in ("ble", "bluetooth", "gatt"):
            ble_count += 1
        elif transport in ("network", "tcp", "udp", "wifi", "host",
                           "ssh", "msf", "msfconsole", "wpa", "wpa2", "wpa3"):
            net_count += 1
        cap = s.get("capabilities") or {}
        for c in cap.values() if isinstance(cap, dict) else []:
            if not isinstance(c, dict):
                continue
            name = c.get("name", "")
            if "handshake" in name and c.get("achieved"):
                last_handshake = c.get("achieved_at") or time.time()
            if "credential" in name.lower() and c.get("achieved"):
                last_cred = c.get("achieved_at") or time.time()
        exfil = s.get("exfil_pending_bytes")
        if isinstance(exfil, (int, float)):
            exfil_bytes += int(exfil)
    return {
        "ok": True,
        "ble_sessions": ble_count,
        "network_sessions": net_count,
        "total_sessions": len(sessions or []),
        "last_handshake_ts": last_handshake,
        "last_credential_dump_ts": last_cred,
        "exfil_pending_bytes": exfil_bytes,
        "ts": time.time(),
    }


def build_aggregate_html(sessions: List[Dict[str, Any]]) -> bytes:
    """Render the cross-session aggregate page.

    Layout: dark monospace palette, single accent colour, one
    row per session, sortable by clicking the column header
    (handled client-side via JS). The footer is a hash of the
    session list (matches PDF export)."""
    import html as _html
    rows: List[str] = []
    rows.append('<tr>'
                '<th>session</th><th>transport</th><th>target</th>'
                '<th>achieved</th><th>capabilities</th>'
                '<th>last_activity</th><th>risk_max</th>'
                '<th>PDF</th></tr>')
    for s in sessions or []:
        sid = _html.escape(str(s.get("session_id") or s.get("id") or "?"))
        transport = _html.escape(str(s.get("transport") or "-"))
        target = _html.escape(str(s.get("target") or "-"))
        achieved = len(s.get("achieved") or [])
        caps = len(s.get("capabilities") or [])
        last = s.get("last_activity") or "-"
        if isinstance(last, (int, float)):
            last = time.strftime("%Y-%m-%d %H:%M:%S",
                                 time.localtime(float(last)))
        risk_max = s.get("risk_max") or "read"
        pdf = f'<a href="/api/session/{sid}/report.pdf">PDF</a>'
        rows.append(
            f'<tr><td>{sid}</td><td>{transport}</td><td>{target}</td>'
            f'<td>{achieved}</td><td>{caps}</td>'
            f'<td>{last}</td><td>{risk_max}</td><td>{pdf}</td></tr>'
        )
    body = (
        '<!doctype html><html><head><meta charset="utf-8"><title>'
        'KFIOSA sessions</title>'
        '<style>body{font-family:monospace;background:#0a0a0a;'
        'color:#e0e0e0;padding:1em;}h1{color:#3a86ff;}'
        'table{border-collapse:collapse;width:100%;}'
        'th,td{border:1px solid #333;padding:0.4em;text-align:left;}'
        'th{background:#1a1a1a;color:#3a86ff;cursor:pointer;}'
        'tr:nth-child(even){background:#0f0f0f;}'
        'a{color:#3a86ff;text-decoration:none;}'
        'a:hover{text-decoration:underline;}'
        '</style></head><body>'
        f'<h1>KFIOSA sessions ({len(sessions or [])})</h1>'
        '<table id="agg">' + "".join(rows) + '</table>'
        '<script>document.querySelectorAll("th").forEach(h => '
        'h.addEventListener("click", () => {'
        'const t = h.parentElement.parentElement;'
        'const idx = [...h.parentElement.children].indexOf(h);'
        'const rows = [...t.querySelectorAll("tr")].slice(1);'
        'rows.sort((a, b) => a.children[idx].textContent.'
        'localeCompare(b.children[idx].textContent));'
        'rows.forEach(r => t.appendChild(r));}));'
        '</script></body></html>'
    )
    return body.encode("utf-8")


__all__ = [
    "build_transport_summary",
    "build_aggregate_html",
]
