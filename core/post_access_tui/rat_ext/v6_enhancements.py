"""core.post_access_tui.rat_ext.v6_enhancements — dashboard polish + anti-lag.

v6 goals:
  * **Anti-lag poll** — adaptive intervals, backoff when idle, visibility API
  * **Polymorphic capability filter** — surface only feature-compatible caps
  * **UI shell CSS/JS inject** — smoother dark UI, sticky header, drawer
  * **Situational recommend** — wire poly_runtime into recommender hints
  * Never invent sessions/creds; never inline secrets

Works with stdlib WSGI dashboard (Flask optional).
"""
from __future__ import annotations

import json
import os
import time
from typing import Any, Dict, List, Optional

_STARTED = time.time()


def adaptive_poll_config(
    *,
    sessions: Optional[List[Dict[str, Any]]] = None,
    idle: bool = False,
) -> Dict[str, Any]:
    """Poll intervals that slow down when idle / few sessions (anti-lag).

    Browser should honour ``document.hidden`` → use ``hidden_ms``.
    """
    n = len(sessions or [])
    base_state = 8000
    base_ai = 15000
    base_health = 20000
    if n == 0 or idle:
        base_state = 20000
        base_ai = 30000
        base_health = 45000
    elif n >= 8:
        # Many cards — don't thrash the main thread
        base_state = 12000
        base_ai = 20000

    def _env_ms(name: str, default: int) -> int:
        raw = (os.environ.get(name) or "").strip()
        try:
            v = int(raw) if raw else default
        except ValueError:
            v = default
        return max(2000, min(v, 120_000))

    return {
        "ok": True,
        "attack_state_ms": _env_ms("KFIOSA_DASH_STATE_POLL_MS", base_state),
        "ai_status_ms": _env_ms("KFIOSA_DASH_AI_POLL_MS", base_ai),
        "health_ms": _env_ms("KFIOSA_DASH_HEALTH_POLL_MS", base_health),
        "hidden_ms": 60000,
        "backoff_on_error_ms": 30000,
        "max_concurrent_fetches": 2,
        "debounce_filter_ms": 180,
        "model": "rat-dashboard-v6",
        "sessions": n,
        "idle": idle,
        "ts": time.time(),
    }


def polymorphic_capability_filter(
    capabilities: List[Dict[str, Any]],
    session: Optional[Dict[str, Any]] = None,
    surface: str = "",
) -> Dict[str, Any]:
    """Keep capabilities that match session features / attack surface.

    Uses :func:`core.utils.poly_runtime.situational_pick` when domain can
    be inferred; falls back to achievement intersection only.
    """
    sess = session if isinstance(session, dict) else {}
    achieved = set(sess.get("achieved") or [])
    kind = str(
        sess.get("kind") or sess.get("transport") or surface or ""
    ).lower()
    domain = "wifi"
    if kind in ("ble", "bluetooth"):
        domain = "ble"
    elif kind in ("host", "network", "shell"):
        domain = "post_exploitation"
    elif kind in ("osint",):
        domain = "osint"

    poly_pick = None
    try:
        from core.utils.poly_runtime import situational_pick
        env = situational_pick(domain, context=sess, phase="any")
        poly_pick = env.get("pick")
    except Exception:  # noqa: BLE001
        poly_pick = None

    kept: List[Dict[str, Any]] = []
    dropped: List[str] = []
    for cap in capabilities or []:
        if not isinstance(cap, dict):
            continue
        name = str(cap.get("name") or cap.get("id") or "")
        req = set(cap.get("required_achievements") or [])
        if req and not req.issubset(achieved):
            dropped.append(name)
            continue
        # Soft boost annotation for poly-compatible caps
        labels = " ".join(
            str(cap.get(k) or "")
            for k in ("name", "label", "description", "tags")
        ).lower()
        if poly_pick and poly_pick.lower() in labels:
            cap = dict(cap)
            cap["poly_boost"] = True
            cap["poly_pick"] = poly_pick
        kept.append(cap)

    return {
        "ok": True,
        "capabilities": kept,
        "dropped": dropped,
        "poly_pick": poly_pick,
        "domain": domain,
        "count": len(kept),
        "model": "rat-dashboard-v6-poly",
    }


def situational_recommend(
    session: Optional[Dict[str, Any]] = None,
    candidates: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """AI-situational next capability hint (no secrets)."""
    sess = session if isinstance(session, dict) else {}
    kind = str(sess.get("kind") or sess.get("transport") or "wifi").lower()
    domain = {
        "ble": "ble",
        "bluetooth": "ble",
        "host": "post_exploitation",
        "network": "post_exploitation",
        "osint": "osint",
    }.get(kind, "wifi")
    try:
        from core.utils.poly_runtime import situational_pick
        env = situational_pick(domain, context=sess, phase="any")
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": str(e)[:160], "model": "rat-dashboard-v6"}

    pick = env.get("pick")
    scored: List[Dict[str, Any]] = []
    for a in env.get("alternatives") or []:
        scored.append({
            "cap": a.get("name"),
            "score": a.get("score"),
            "rationale": a.get("description") or env.get("rationale"),
        })
    if candidates:
        # Prefer candidates that match poly alternatives
        cand_set = {str(c).lower() for c in candidates}
        scored = [
            s for s in scored
            if str(s.get("cap") or "").lower() in cand_set
        ] or scored

    return {
        "ok": True,
        "pick": pick,
        "recommendations": scored[:8],
        "poly_kind": env.get("poly_kind"),
        "rationale": env.get("rationale"),
        "model": "rat-dashboard-v6-situational",
    }


def ui_shell_assets() -> Dict[str, str]:
    """Inline CSS + JS snippets to inject into the dashboard shell.

    Designed for zero external CDN (offline lab). Anti-lag patterns:
    request coalescing, visibility pause, debounced filter, rAF batching.
    """
    css = """
:root{--bg:#0d1117;--panel:#161b22;--fg:#e6edf3;--muted:#8b949e;
--accent:#3fb950;--warn:#d29922;--danger:#f85149;--line:#30363d}
html,body{margin:0;background:var(--bg);color:var(--fg);
font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
font-size:13px}
header.kf-top{position:sticky;top:0;z-index:40;background:rgba(13,17,23,.92);
backdrop-filter:blur(8px);border-bottom:1px solid var(--line);
padding:.55rem .9rem;display:flex;gap:1rem;align-items:center;flex-wrap:wrap}
header.kf-top .pill{border:1px solid var(--line);border-radius:999px;
padding:.15rem .55rem;color:var(--muted)}
header.kf-top .pill.ok{border-color:var(--accent);color:var(--accent)}
header.kf-top .pill.bad{border-color:var(--danger);color:var(--danger)}
.kf-stats{display:flex;gap:.6rem;flex-wrap:wrap;padding:.5rem .9rem}
.kf-stats .card{background:var(--panel);border:1px solid var(--line);
border-radius:8px;padding:.4rem .7rem;min-width:5.5rem}
.kf-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));
gap:.75rem;padding:.75rem .9rem 5rem}
.kf-card{background:var(--panel);border:1px solid var(--line);border-radius:10px;
padding:.7rem;transition:border-color .12s,transform .12s}
.kf-card:hover{border-color:var(--accent);transform:translateY(-1px)}
.kf-card.focus{outline:1px solid var(--accent)}
.kf-drawer{position:fixed;right:0;top:0;bottom:0;width:min(420px,100%);
background:#0b0f14;border-left:1px solid var(--line);transform:translateX(100%);
transition:transform .18s ease;z-index:50;overflow:auto;padding:1rem}
.kf-drawer.open{transform:translateX(0)}
.kf-drawer pre{white-space:pre-wrap;word-break:break-word;color:var(--muted)}
.empty{max-width:36rem;margin:3rem auto;padding:1.2rem;border:1px dashed var(--line);
border-radius:10px;color:var(--muted)}
kbd{background:#21262d;border:1px solid var(--line);border-radius:4px;
padding:0 .3rem}
a{color:#58a6ff}
""".strip()

    js = """
(function(){
  const cfg = window.__KFIOSA_POLL__ || {attack_state_ms:8000,ai_status_ms:15000,
    health_ms:20000,hidden_ms:60000,backoff_on_error_ms:30000,
    max_concurrent_fetches:2,debounce_filter_ms:180};
  let inflight = 0;
  let errBackoff = 0;
  const timers = {};
  function visible(){ return !document.hidden; }
  function interval(key){
    if(!visible()) return cfg.hidden_ms;
    return (cfg[key]||10000) + errBackoff;
  }
  async function fetchJSON(url){
    if(inflight >= (cfg.max_concurrent_fetches||2)) return null;
    inflight++;
    try{
      const r = await fetch(url, {headers:{'Accept':'application/json'}});
      if(!r.ok) throw new Error('http '+r.status);
      errBackoff = 0;
      return await r.json();
    }catch(e){
      errBackoff = Math.min((errBackoff||0)+cfg.backoff_on_error_ms, 90000);
      return null;
    }finally{ inflight--; }
  }
  function schedule(key, url, apply){
    clearTimeout(timers[key]);
    const tick = async ()=>{
      const data = await fetchJSON(url);
      if(data && apply) apply(data);
      timers[key] = setTimeout(tick, interval(key));
    };
    timers[key] = setTimeout(tick, 400);
  }
  window.kfiosaDash = {
    start(){
      schedule('attack_state_ms','/api/attack_state', d=>{
        const el = document.querySelector('[data-pill=attack]');
        if(el) el.textContent = 'atk '+(d.active_count||d.count||0);
        if(el) el.className = 'pill '+(d.ok!==false?'ok':'bad');
      });
      schedule('ai_status_ms','/api/v4/ai_status', d=>{
        const el = document.querySelector('[data-pill=ai]');
        if(el) el.textContent = 'ai '+(d.active||d.model||'?');
        if(el) el.className = 'pill '+(d.ok||d.reachable?'ok':'bad');
      });
      schedule('health_ms','/api/v5/health', d=>{
        const el = document.querySelector('[data-pill=health]');
        if(el) el.textContent = 'up '+(d.uptime_s||0)+'s';
      });
    },
    debounce(fn, ms){
      let t; return function(){ clearTimeout(t); const a=arguments, th=this;
        t=setTimeout(()=>fn.apply(th,a), ms||cfg.debounce_filter_ms); };
    },
    openDrawer(text){
      let d = document.getElementById('kf-drawer');
      if(!d){ d=document.createElement('div'); d.id='kf-drawer';
        d.className='kf-drawer'; document.body.appendChild(d); }
      d.innerHTML = '<button type="button" id="kf-drawer-x">close</button><pre></pre>';
      d.querySelector('pre').textContent = text||'';
      d.classList.add('open');
      d.querySelector('#kf-drawer-x').onclick=()=>d.classList.remove('open');
    }
  };
  document.addEventListener('visibilitychange', ()=>{ /* next tick uses hidden_ms */ });
  if(document.readyState==='loading')
    document.addEventListener('DOMContentLoaded', ()=>window.kfiosaDash.start());
  else window.kfiosaDash.start();
})();
""".strip()
    return {"css": css, "js": js, "model": "rat-dashboard-v6"}


def inject_shell(html: str, sessions: Optional[List[Dict[str, Any]]] = None) -> str:
    """Inject v6 CSS/JS + poll config into an existing dashboard HTML string."""
    if not isinstance(html, str) or not html:
        return html
    assets = ui_shell_assets()
    poll = adaptive_poll_config(sessions=sessions)
    head = (
        f"<style id='kf-v6-css'>{assets['css']}</style>"
        f"<script>window.__KFIOSA_POLL__={json.dumps(poll)};</script>"
        f"<script id='kf-v6-js'>{assets['js']}</script>"
    )
    # Soft header pills if missing
    pills = (
        "<header class='kf-top' id='kf-v6-header'>"
        "<strong>KFIOSA RAT</strong>"
        "<span class='pill' data-pill='ai'>ai …</span>"
        "<span class='pill' data-pill='attack'>atk …</span>"
        "<span class='pill' data-pill='health'>up …</span>"
        "<a href='/api/v6/poll'>poll cfg</a>"
        "<a href='/api/v5/health'>health</a>"
        "<a href='/aggregate'>aggregate</a>"
        "</header>"
    )
    out = html
    if "</head>" in out.lower():
        # case-insensitive replace of first </head>
        idx = out.lower().rfind("</head>")
        out = out[:idx] + head + out[idx:]
    else:
        out = head + out
    if "kf-v6-header" not in out and "<body" in out.lower():
        b = out.lower().find("<body")
        gt = out.find(">", b)
        if gt != -1:
            out = out[: gt + 1] + pills + out[gt + 1 :]
    return out


def health_v6(sessions: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    """Extend v5 health with poly + poll diagnostics."""
    try:
        from . import v5_enhancements as v5
        base = v5.dashboard_health(sessions)
    except Exception:  # noqa: BLE001
        base = {"ok": True, "sessions": len(sessions or [])}
    base["poll"] = adaptive_poll_config(sessions=sessions)
    base["poly"] = {"runtime": "core.utils.poly_runtime", "ok": True}
    try:
        from core.utils.hot_cache import GLOBAL_CACHE
        base["cache"] = GLOBAL_CACHE.stats()
    except Exception:  # noqa: BLE001
        base["cache"] = {}
    base["model"] = "rat-dashboard-v6"
    base["uptime_s"] = round(time.time() - _STARTED, 1)
    return base


__all__ = [
    "adaptive_poll_config",
    "polymorphic_capability_filter",
    "situational_recommend",
    "ui_shell_assets",
    "inject_shell",
    "health_v6",
]
