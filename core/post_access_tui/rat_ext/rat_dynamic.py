"""Dynamic RAT-like session control for the Flask/WSGI dashboard.

Goal: after access is gained, present a **friendly-named**, capability-
matched operator console that can switch between WiFi / BLE / host
(network) sessions and show the **actual** attack state in detail.

Honesty rules (unchanged):
  * Never invent sessions, creds, or achieved primitives.
  * Only surface actions whose ``required_achievements`` are subset of
    the session's real ``achieved`` set (plus always-safe read probes).
  * Destructive actions stay labeled as such; ACCEPT gate remains with
    the orchestrator / capability_runner.
"""
from __future__ import annotations

import threading
import time
from typing import Any, Dict, List, Optional, Set, Tuple


# ---------------------------------------------------------------------------
# Kind labels (operator-facing)
# ---------------------------------------------------------------------------

KIND_WIFI = "wifi"
KIND_BLE = "ble"
KIND_HOST = "host"          # network/SSH/MSF shell on a host
KIND_NETWORK = "network"    # alias → host
KIND_UNKNOWN = "unknown"

KIND_FRIENDLY = {
    KIND_WIFI: "Wi-Fi access point",
    KIND_BLE: "Bluetooth device",
    KIND_HOST: "Host / network session",
    KIND_NETWORK: "Host / network session",
    KIND_UNKNOWN: "Unknown link",
}

TRANSPORT_TO_KIND = {
    "wifi": KIND_WIFI,
    "wpa": KIND_WIFI,
    "wpa2": KIND_WIFI,
    "wpa3": KIND_WIFI,
    "ble": KIND_BLE,
    "bluetooth": KIND_BLE,
    "gatt": KIND_BLE,
    "network": KIND_HOST,
    "host": KIND_HOST,
    "tcp": KIND_HOST,
    "ssh": KIND_HOST,
    "msf": KIND_HOST,
    "msfconsole": KIND_HOST,
    "meterpreter": KIND_HOST,
    "shell": KIND_HOST,
}


def normalize_kind(session: Dict[str, Any]) -> str:
    """Map a session dict to a canonical kind."""
    if not isinstance(session, dict):
        return KIND_UNKNOWN
    raw = (
        session.get("kind")
        or session.get("attack_surface")
        or session.get("transport")
        or ""
    )
    k = str(raw).lower().strip()
    if k in (KIND_WIFI, KIND_BLE, KIND_HOST, KIND_NETWORK):
        return KIND_HOST if k == KIND_NETWORK else k
    return TRANSPORT_TO_KIND.get(k, KIND_UNKNOWN)


def kind_label(kind: str) -> str:
    return KIND_FRIENDLY.get(kind, KIND_FRIENDLY[KIND_UNKNOWN])


# ---------------------------------------------------------------------------
# Friendly RAT action catalog (matched against achieved set)
# ---------------------------------------------------------------------------

# Each action: id, friendly label, kinds it applies to, required achieved
# tags, risk, description. IDs map to existing capability names where
# possible so /cap/<sid>/<id> keeps working.

_RAT_ACTIONS: List[Dict[str, Any]] = [
    # ---- host / network ----
    {
        "id": "shell",
        "label": "Open remote shell",
        "kinds": {KIND_HOST},
        "required": ("shell",),
        "risk": "destructive",
        "group": "Control",
        "description": "Interactive shell on the compromised host.",
    },
    {
        "id": "file_get",
        "label": "Download file from host",
        "kinds": {KIND_HOST},
        "required": ("shell",),
        "risk": "read",
        "group": "Files",
        "description": "Pull a file from the host to the operator machine.",
    },
    {
        "id": "file_put",
        "label": "Upload file to host",
        "kinds": {KIND_HOST},
        "required": ("shell",),
        "risk": "destructive",
        "group": "Files",
        "description": "Push a file onto the host.",
    },
    {
        "id": "portfwd_add",
        "label": "Tunnel a local port",
        "kinds": {KIND_HOST},
        "required": ("shell",),
        "risk": "destructive",
        "group": "Pivot",
        "description": "Add a port-forward through this session.",
    },
    {
        "id": "socks_start",
        "label": "Start SOCKS proxy",
        "kinds": {KIND_HOST},
        "required": ("shell",),
        "risk": "destructive",
        "group": "Pivot",
        "description": "Route browser/tools through the host.",
    },
    {
        "id": "lateral_picker",
        "label": "Pick next internal host",
        "kinds": {KIND_HOST},
        "required": ("shell", "lateral_target_pool"),
        "risk": "read",
        "group": "Lateral",
        "description": "Choose a lateral target from harvested pool.",
    },
    {
        "id": "hash_dump",
        "label": "Show harvested credentials",
        "kinds": {KIND_HOST},
        "required": ("creds_dump",),
        "risk": "destructive",
        "group": "Loot",
        "description": "List shapes of dumped hashes (values not inlined).",
    },
    {
        "id": "persistence",
        "label": "Manage persistence",
        "kinds": {KIND_HOST},
        "required": ("shell", "persistence_mechanism"),
        "risk": "destructive",
        "group": "Stay",
        "description": "Install or remove a persistence mechanism.",
    },
    {
        "id": "antiforensic",
        "label": "Cover tracks (anti-forensics)",
        "kinds": {KIND_HOST},
        "required": ("shell", "antiforensic"),
        "risk": "destructive",
        "group": "OPSEC",
        "description": "Timestomp / log hygiene / clean-up actions.",
    },
    {
        "id": "keylogger",
        "label": "Toggle keylogger",
        "kinds": {KIND_HOST},
        "required": ("shell",),
        "risk": "destructive",
        "group": "Surveillance",
        "description": "Start/stop keylogging if the chain earned it.",
    },
    {
        "id": "bloodhound",
        "label": "Domain map (BloodHound view)",
        "kinds": {KIND_HOST},
        "required": ("bloodhound_audit",),
        "risk": "read",
        "group": "Recon",
        "description": "Summarize domain relationships already collected.",
    },
    {
        "id": "exfil_picker",
        "label": "Exfiltrate data",
        "kinds": {KIND_HOST},
        "required": ("shell", "exfil_channel"),
        "risk": "destructive",
        "group": "Loot",
        "description": "Pick a channel to move data off the host.",
    },
    # ---- BLE ----
    {
        "id": "gatt_browse",
        "label": "Browse Bluetooth services",
        "kinds": {KIND_BLE},
        "required": ("gatt_connect",),
        "risk": "read",
        "group": "Device",
        "description": "List GATT services and characteristics.",
    },
    {
        "id": "gatt_read",
        "label": "Read device value",
        "kinds": {KIND_BLE},
        "required": ("gatt_connect",),
        "risk": "read",
        "group": "Device",
        "description": "Read a characteristic by handle/UUID.",
    },
    {
        "id": "gatt_write",
        "label": "Write device value",
        "kinds": {KIND_BLE},
        "required": ("gatt_connect", "gatt_write"),
        "risk": "destructive",
        "group": "Device",
        "description": "Write a characteristic (earned earlier).",
    },
    {
        "id": "gatt_notify",
        "label": "Live notifications",
        "kinds": {KIND_BLE},
        "required": ("gatt_connect", "gatt_notify"),
        "risk": "read",
        "group": "Device",
        "description": "Subscribe to notifications from the peripheral.",
    },
    {
        "id": "hid_inject",
        "label": "Inject keystrokes (HID)",
        "kinds": {KIND_BLE},
        "required": ("hid_inject",),
        "risk": "destructive",
        "group": "Attack",
        "description": "BLE HID injection against the paired host.",
    },
    {
        "id": "rssi_track",
        "label": "Track signal strength",
        "kinds": {KIND_BLE},
        "required": ("rssi_sample",),
        "risk": "read",
        "group": "Recon",
        "description": "Live RSSI samples for proximity/movement.",
    },
    {
        "id": "channel_map",
        "label": "Radio channel map",
        "kinds": {KIND_BLE},
        "required": (),
        "risk": "read",
        "group": "Recon",
        "description": "Read-only channel occupancy report.",
    },
    {
        "id": "whitelist_clone",
        "label": "Clone bonding list",
        "kinds": {KIND_BLE},
        "required": ("bond_dump",),
        "risk": "destructive",
        "group": "Attack",
        "description": "Reuse bonded IRKs/LTKs on another adapter.",
    },
    # ---- Wi-Fi AP access ----
    {
        "id": "wifi_clients",
        "label": "List Wi-Fi clients",
        "kinds": {KIND_WIFI},
        "required": ("wifi_access", "client_enum"),
        "risk": "read",
        "group": "Recon",
        "description": "Associated stations on the compromised AP/LAN.",
    },
    {
        "id": "wifi_lan_scan",
        "label": "Scan LAN behind AP",
        "kinds": {KIND_WIFI},
        "required": ("wifi_access",),
        "risk": "read",
        "group": "Recon",
        "description": "Discover hosts on the Wi-Fi LAN after association.",
    },
    {
        "id": "wifi_dns_spoof",
        "label": "DNS spoof / captive pivot",
        "kinds": {KIND_WIFI},
        "required": ("wifi_access", "lan_pivot"),
        "risk": "destructive",
        "group": "Attack",
        "description": "Redirect clients (only if chain earned lan_pivot).",
    },
    {
        "id": "wifi_handshake_store",
        "label": "Show captured handshakes",
        "kinds": {KIND_WIFI},
        "required": ("handshake",),
        "risk": "read",
        "group": "Loot",
        "description": "Paths/status of captured EAPOL/PMKID material.",
    },
    {
        "id": "shell",
        "label": "Shell on LAN host",
        "kinds": {KIND_WIFI},
        "required": ("shell",),
        "risk": "destructive",
        "group": "Control",
        "description": "If a host shell was gained via the Wi-Fi path.",
    },
]


def rat_menu_for_session(session: Dict[str, Any]) -> Dict[str, Any]:
    """Build friendly-named RAT options for one session from real achievements.

    Returns ``{ok, session_id, kind, kind_label, groups: [{group, actions}]}``.
    """
    if not isinstance(session, dict):
        return {"ok": False, "error": "session must be a dict", "groups": []}
    kind = normalize_kind(session)
    achieved: Set[str] = set(session.get("achieved") or [])
    # Also accept achievements nested under capabilities
    caps = session.get("capabilities")
    if isinstance(caps, dict):
        for c in caps.values():
            if isinstance(c, dict) and c.get("achieved"):
                n = c.get("name") or c.get("id")
                if n:
                    achieved.add(str(n))
    sid = session.get("id") or session.get("session_id") or ""
    groups: Dict[str, List[Dict[str, Any]]] = {}
    for act in _RAT_ACTIONS:
        if kind not in act["kinds"]:
            continue
        req = tuple(act.get("required") or ())
        if req and not all(r in achieved for r in req):
            continue
        groups.setdefault(act["group"], []).append({
            "id": act["id"],
            "label": act["label"],
            "risk": act["risk"],
            "description": act["description"],
            "required": list(req),
            "href": f"/cap/{sid}/{act['id']}",
        })
    ordered = [
        {"group": g, "actions": acts}
        for g, acts in groups.items()
    ]
    return {
        "ok": True,
        "session_id": sid,
        "kind": kind,
        "kind_label": kind_label(kind),
        "target": session.get("target") or "",
        "achieved": sorted(achieved),
        "access_gained": bool(achieved) or bool(session.get("session_id")),
        "groups": ordered,
        "action_count": sum(len(g["actions"]) for g in ordered),
        "ts": time.time(),
    }


# ---------------------------------------------------------------------------
# Attack state (detailed, non-fabricated)
# ---------------------------------------------------------------------------

def build_attack_state(
    sessions: List[Dict[str, Any]],
    *,
    active_session_id: Optional[str] = None,
    chain_status: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Snapshot of multi-session attack posture for the dashboard."""
    sessions = list(sessions or [])
    by_kind: Dict[str, int] = {}
    detail: List[Dict[str, Any]] = []
    for s in sessions:
        if not isinstance(s, dict):
            continue
        kind = normalize_kind(s)
        by_kind[kind] = by_kind.get(kind, 0) + 1
        achieved = list(s.get("achieved") or [])
        sid = s.get("id") or s.get("session_id") or ""
        phase = s.get("phase") or s.get("attack_phase") or (
            "post_access" if achieved else "recon"
        )
        detail.append({
            "id": sid,
            "kind": kind,
            "kind_label": kind_label(kind),
            "target": s.get("target") or "",
            "transport": s.get("transport") or kind,
            "phase": phase,
            "achieved": achieved,
            "achieved_count": len(achieved),
            "risk_max": s.get("risk_max") or _risk_max_from_achieved(achieved),
            "last_activity": s.get("last_activity"),
            "active": bool(active_session_id and sid == active_session_id),
            "note": s.get("note") or "",
            "meta": s.get("meta") or {},
        })
    chain = chain_status if isinstance(chain_status, dict) else {}
    return {
        "ok": True,
        "total_sessions": len(detail),
        "by_kind": by_kind,
        "active_session_id": active_session_id,
        "sessions": detail,
        "chain": {
            "status": chain.get("status") or "idle",
            "step_count": len(chain.get("steps") or []),
            "current_step": chain.get("current_step"),
            "domain": chain.get("domain"),
        },
        "ts": time.time(),
        "note": "State is derived from real session records only.",
    }


def _risk_max_from_achieved(achieved: List[str]) -> str:
    destructive_tags = {
        "shell", "hid_inject", "gatt_write", "persistence_mechanism",
        "antiforensic", "creds_dump", "exfil_channel", "wifi_access",
    }
    if any(a in destructive_tags for a in achieved):
        return "destructive"
    if achieved:
        return "read"
    return "none"


# ---------------------------------------------------------------------------
# Session switcher registry (in-process, thread-safe)
# ---------------------------------------------------------------------------

class SessionRegistry:
    """In-process multi-session store for the RAT dashboard.

    Holds sessions of any kind; tracks the active session id for
    BLE ↔ network ↔ WiFi switching in the UI.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._sessions: Dict[str, Dict[str, Any]] = {}
        self._active: Optional[str] = None
        self._chain: Dict[str, Any] = {}

    def load(self, sessions: List[Dict[str, Any]]) -> None:
        with self._lock:
            self._sessions.clear()
            for s in sessions or []:
                if not isinstance(s, dict):
                    continue
                sid = str(s.get("id") or s.get("session_id") or "")
                if not sid:
                    continue
                rec = dict(s)
                rec["id"] = sid
                rec["kind"] = normalize_kind(rec)
                self._sessions[sid] = rec
            if self._active not in self._sessions:
                self._active = next(iter(self._sessions), None)

    def list_sessions(self, kind: Optional[str] = None) -> List[Dict[str, Any]]:
        with self._lock:
            out = list(self._sessions.values())
        if kind:
            k = kind.lower()
            if k == "network":
                k = KIND_HOST
            out = [s for s in out if normalize_kind(s) == k]
        return out

    def get(self, sid: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            s = self._sessions.get(sid)
            return dict(s) if s else None

    def switch(self, sid: str) -> Dict[str, Any]:
        with self._lock:
            if sid not in self._sessions:
                return {
                    "ok": False,
                    "error": f"unknown session {sid!r}",
                    "known": list(self._sessions.keys()),
                }
            self._active = sid
            s = dict(self._sessions[sid])
        return {
            "ok": True,
            "active_session_id": sid,
            "kind": normalize_kind(s),
            "kind_label": kind_label(normalize_kind(s)),
            "target": s.get("target") or "",
            "ts": time.time(),
        }

    def active(self) -> Optional[Dict[str, Any]]:
        with self._lock:
            if not self._active:
                return None
            s = self._sessions.get(self._active)
            return dict(s) if s else None

    def set_chain_status(self, status: Dict[str, Any]) -> None:
        with self._lock:
            self._chain = dict(status or {})

    def attack_state(self) -> Dict[str, Any]:
        with self._lock:
            sessions = list(self._sessions.values())
            active = self._active
            chain = dict(self._chain)
        return build_attack_state(
            sessions, active_session_id=active, chain_status=chain,
        )


# Module-level registry used by the WSGI app when sessions are loaded.
GLOBAL_REGISTRY = SessionRegistry()


def enrich_roster_entry(entry: Dict[str, Any], raw_session: Dict[str, Any]) -> Dict[str, Any]:
    """Add kind + rat_menu fields onto a build_session_roster entry."""
    out = dict(entry)
    kind = normalize_kind(raw_session if raw_session else entry)
    out["kind"] = kind
    out["kind_label"] = kind_label(kind)
    menu = rat_menu_for_session({**raw_session, **entry, "kind": kind})
    out["rat_menu"] = menu
    out["access_gained"] = bool(menu.get("access_gained"))
    return out


def build_rat_dashboard_html(
    roster: List[Dict[str, Any]],
    *,
    attack_state: Optional[Dict[str, Any]] = None,
    active_session_id: Optional[str] = None,
) -> str:
    """RAT-like HTML: kind tabs, active session, friendly action groups."""
    def esc(s: Any) -> str:
        t = str(s if s is not None else "")
        return (t.replace("&", "&amp;").replace("<", "&lt;")
                 .replace(">", "&gt;").replace('"', "&quot;"))

    state = attack_state or {}
    by_kind = state.get("by_kind") or {}
    # Best-effort AI status for the header pill (never blocks render).
    ai_pill = "AI n/a"
    try:
        from . import v4_enhancements as _v4
        ai = _v4.ai_status()
        model = ai.get("model") or "unknown"
        if len(str(model)) > 28:
            model = str(model)[:25] + "…"
        reach = "up" if ai.get("reachable") else "down"
        prov = ai.get("provider") or ai.get("active") or "?"
        ai_pill = f"AI {esc(prov)} {esc(reach)} · {esc(model)}"
    except Exception:
        ai_pill = "AI n/a"
    parts = [
        "<!doctype html><html><head><meta charset='utf-8'>",
        # Title keeps legacy "KFIOSA RAT dashboard" substring for tests.
        "<title>KFIOSA RAT dashboard</title><style>",
        "body{font-family:ui-monospace,monospace;background:#0b0d10;color:#e8eaed;",
        "margin:0;padding:1rem;}h1{color:#5eead4;margin:0 0 .5rem 0;font-size:1.4rem;}",
        ".bar{display:flex;flex-wrap:wrap;gap:.75rem;align-items:center;margin-bottom:1rem;}",
        ".pill{background:#1a1f26;border:1px solid #334;border-radius:999px;padding:.25rem .75rem;",
        "color:#9ca3af;font-size:.85rem;} .pill b{color:#5eead4;}",
        ".pill.ai{border-color:#0e7490;color:#67e8f9;}",
        ".tabs a,.nav a{display:inline-block;margin:0 .35rem .35rem 0;padding:.35rem .8rem;",
        "border-radius:6px;border:1px solid #333;color:#cbd5e1;text-decoration:none;",
        "background:#12161c;font-size:.85rem;}",
        ".tabs a.on{border-color:#5eead4;color:#5eead4;}",
        ".nav{margin:.6rem 0 1rem;padding:.6rem;background:#0f1318;border:1px solid #1f2937;",
        "border-radius:8px;}",
        ".nav .lbl{color:#64748b;font-size:.7rem;text-transform:uppercase;letter-spacing:.08em;",
        "margin:0 0 .35rem 0;display:block;}",
        ".sess{border:1px solid #2a3038;border-radius:8px;padding:.75rem;margin:.6rem 0;",
        "background:#10141a;} .sess.active{border-color:#5eead4;box-shadow:0 0 0 1px #5eead455;}",
        ".sess h2{margin:0 0 .4rem 0;font-size:1.05rem;color:#f1f5f9;}",
        ".meta{color:#6b7280;font-size:.85rem;} .ach{color:#fbbf24;font-size:.85rem;margin:.3rem 0;}",
        ".grp{margin:.5rem 0 .2rem;color:#94a3b8;font-size:.75rem;text-transform:uppercase;",
        "letter-spacing:.06em;}",
        ".cap{display:inline-block;margin:3px;padding:6px 10px;border-radius:4px;",
        "background:#1a1f26;border:1px solid #3f3f46;color:#e5e7eb;text-decoration:none;",
        "font-size:.9rem;} .cap.read{border-color:#166534;} .cap.destructive{border-color:#991b1b;}",
        ".cap:hover{background:#222831;} a.link{color:#5eead4;margin-right:1rem;}",
        ".phase{display:inline-block;background:#1e293b;color:#7dd3fc;padding:2px 8px;",
        "border-radius:4px;font-size:.75rem;margin-left:.4rem;}",
        ".search{margin:.5rem 0;} .search input{background:#0f1318;border:1px solid #334;",
        "color:#e8eaed;padding:.4rem .6rem;border-radius:6px;width:min(360px,90%);}",
        "</style></head><body>",
        "<h1>KFIOSA RAT dashboard · control centre</h1>",
        "<div class='bar'>",
        f"<span class='pill'>sessions <b>{state.get('total_sessions', len(roster))}</b></span>",
        f"<span class='pill'>Wi‑Fi <b>{by_kind.get('wifi', 0)}</b></span>",
        f"<span class='pill'>BLE <b>{by_kind.get('ble', 0)}</b></span>",
        f"<span class='pill'>Host <b>{by_kind.get('host', 0)}</b></span>",
        f"<span class='pill'>chain <b>{esc((state.get('chain') or {}).get('status', 'idle'))}</b></span>",
        f"<span class='pill ai' id='ai-pill' title='live /api/v4/ai_status'>{ai_pill}</span>",
        "</div>",
        "<div class='tabs'>",
        "<a class='on' href='/'>All</a>",
        "<a href='/api/sessions?kind=wifi'>Wi‑Fi only</a>",
        "<a href='/api/sessions?kind=ble'>BLE only</a>",
        "<a href='/api/sessions?kind=host'>Host only</a>",
        "<a href='/api/attack_state'>Attack state JSON</a>",
        "<a href='/aggregate'>Aggregate</a>",
        "<a href='/api/transport_summary'>Transport summary</a>",
        "</div>",
        # SQL + v4 tooling (required by tests + operator workflow)
        "<div class='nav'>",
        "<span class='lbl'>Persistence · SQL</span>",
        "<a href='/api/sql/snapshot/default'>SQL snapshot</a>",
        "<a href='/api/sql/log/default'>SQL log</a>",
        "<a href='/api/sql/history/default'>SQL history</a>",
        "<a href='/api/sql/exfil/default'>SQL exfil</a>",
        "<a href='/api/sql/sessions'>SQL sessions</a>",
        "<a href='/api/sql_health'>SQL health</a>",
        "</div>",
        "<div class='nav'>",
        "<span class='lbl'>v4 · polymorphic scans · AI</span>",
        "<a href='/api/v4/scan_options?surface=wifi'>scan · wifi</a>",
        "<a href='/api/v4/scan_options?surface=ble'>scan · ble</a>",
        "<a href='/api/v4/scan_options?surface=http'>scan · http</a>",
        "<a href='/api/v4/scan_options?surface=smb'>scan · smb</a>",
        "<a href='/api/v4/scan_options?surface=ssh'>scan · ssh</a>",
        "<a href='/api/v4/ai_status'>AI status JSON</a>",
        "<a href='/api/v4/hardware'>operator hardware</a>",
        "<a href='/api/sessions?compact=1'>sessions compact</a>",
        "</div>",
        "<div class='search'>",
        "<form method='get' action='/api/sessions'>",
        "<input name='q' placeholder='filter sessions (id, tag, surface)…' ",
        "aria-label='session filter'/> ",
        "<button type='submit' style='background:#134e4a;color:#ccfbf1;border:0;",
        "padding:.4rem .7rem;border-radius:6px;cursor:pointer;'>Search</button>",
        "</form></div>",
    ]
    if not roster:
        parts.append(
            "<p class='meta'>No active sessions yet. Gain access from the "
            "Wi‑Fi / BLE chain (ACCEPT-gated); this panel then unlocks "
            "options matching what was actually achieved.</p>"
        )
    for s in roster:
        sid = s.get("id") or ""
        kind = s.get("kind") or normalize_kind(s)
        active = bool(active_session_id and sid == active_session_id)
        cls = "sess active" if active else "sess"
        parts.append(f"<div class='{cls}' id='s-{esc(sid)}'>")
        parts.append(
            f"<h2>{esc(s.get('kind_label') or kind_label(kind))} · "
            f"{esc(sid)} "
            f"<span class='meta'>({esc(kind)} → {esc(s.get('target') or '?')})</span>"
            f"<span class='phase'>{'ACTIVE' if active else 'idle'}</span></h2>"
        )
        parts.append(
            f"<div class='meta'>"
            f"<a class='link' href='/api/session/{esc(sid)}/switch'>[switch here]</a>"
            f"<a class='link' href='/api/session/{esc(sid)}/rat_menu'>[RAT menu JSON]</a>"
            f"<a class='link' href='/api/session/{esc(sid)}/recommend'>[recommend]</a>"
            f"<a class='link pdf-btn' href='/api/session/{esc(sid)}/report.pdf'>"
            f"[export PDF]</a>"
            f"<a class='link' href='/api/session/{esc(sid)}/exfil'>[exfil]</a>"
            f"<a class='link' href='/api/session/{esc(sid)}/persistence'>"
            f"[persistence]</a>"
            f"<a class='link' href='/api/session/{esc(sid)}/live_tail'>[live tail]</a>"
            f"<a class='link' href='/api/sql/snapshot/{esc(sid)}'>[SQL snapshot]</a>"
            f"<a class='link' href='/stream/{esc(sid)}'>[stream]</a>"
            f"</div>"
        )
        achieved = s.get("achieved") or []
        if achieved:
            parts.append(
                f"<div class='ach'>Gained: {esc(', '.join(achieved))}</div>"
            )
        else:
            parts.append(
                "<div class='meta'><em>No post-access primitives earned yet — "
                "only basic recon actions may appear.</em></div>"
            )
        menu = s.get("rat_menu") or {}
        groups = menu.get("groups") or []
        if not groups:
            # Fall back to flat capabilities list
            caps = s.get("capabilities") or []
            if caps:
                parts.append("<div class='grp'>Available</div>")
                for c in caps:
                    risk = c.get("risk") or "read"
                    parts.append(
                        f"<a class='cap {esc(risk)}' href='/cap/{esc(sid)}/"
                        f"{esc(c.get('name') or '')}' title='{esc(c.get('description') or '')}'>"
                        f"{esc(c.get('label') or c.get('name') or '?')}</a>"
                    )
            else:
                parts.append(
                    "<p class='meta'>No RAT options unlocked for this session.</p>"
                )
        for g in groups:
            parts.append(f"<div class='grp'>{esc(g.get('group') or 'Actions')}</div>")
            for a in g.get("actions") or []:
                risk = a.get("risk") or "read"
                href = a.get("href") or f"/cap/{sid}/{a.get('id')}"
                parts.append(
                    f"<a class='cap {esc(risk)}' href='{esc(href)}' "
                    f"title='{esc(a.get('description') or '')}'>"
                    f"{esc(a.get('label') or a.get('id'))}</a>"
                )
        parts.append("</div>")
    parts.append(
        "<p class='meta'>Destructive actions are red-bordered. "
        "Capability execution still goes through the operator ACCEPT gate "
        "at chain time; this UI only shows what was really earned.</p>"
        "<script>"
        "(function(){"
        "var el=document.getElementById('ai-pill');"
        "if(!el)return;"
        "fetch('/api/v4/ai_status').then(function(r){return r.json()}).then(function(j){"
        "if(!j||!j.ok)return;"
        "var m=(j.model||'?');if(m.length>28)m=m.slice(0,25)+'\\u2026';"
        "el.textContent='AI '+(j.provider||j.active||'?')+' '"
        "+(j.reachable?'up':'down')+' · '+m;"
        "}).catch(function(){});"
        "})();"
        "</script>"
        "</body></html>"
    )
    return "".join(parts)


__all__ = [
    "KIND_WIFI", "KIND_BLE", "KIND_HOST", "KIND_NETWORK",
    "normalize_kind", "kind_label", "rat_menu_for_session",
    "build_attack_state", "SessionRegistry", "GLOBAL_REGISTRY",
    "enrich_roster_entry", "build_rat_dashboard_html",
]
