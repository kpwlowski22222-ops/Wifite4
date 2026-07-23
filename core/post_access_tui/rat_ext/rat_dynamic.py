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
        "<title>KFIOSA RAT dashboard</title>",
        "<link rel='preconnect' href='https://fonts.googleapis.com'>",
        "<link rel='preconnect' href='https://fonts.gstatic.com' crossorigin>",
        "<link href='https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600&family=Outfit:wght@400;500;600;700&display=swap' rel='stylesheet'>",
        "<style>",
        ":root{--bg-dark:#07090e;--bg-card:rgba(18,24,35,0.75);--bg-card-active:rgba(22,32,46,0.9);--border:rgba(255,255,255,0.08);--accent-cyan:#5eead4;--accent-blue:#38bdf8;--accent-amber:#fbbf24;--accent-rose:#f87171;--text-main:#f1f5f9;--text-sub:#94a3b8;}",
        "body{font-family:'Outfit',-apple-system,BlinkMacSystemFont,sans-serif;background:radial-gradient(circle at 10% 20%,rgba(14,116,144,0.15) 0%,transparent 40%),radial-gradient(circle at 90% 80%,rgba(94,234,212,0.1) 0%,transparent 40%),var(--bg-dark);color:var(--text-main);margin:0;padding:1.5rem;min-height:100vh;box-sizing:border-box;}",
        "h1{font-family:'Outfit',sans-serif;font-weight:700;background:linear-gradient(135deg,#5eead4 0%,#38bdf8 100%);-webkit-background-clip:text;-webkit-text-fill-color:transparent;margin:0 0 1rem 0;font-size:1.6rem;letter-spacing:-0.02em;display:flex;align-items:center;gap:0.6rem;}",
        "h1::before{content:'';display:inline-block;width:12px;height:12px;background:#5eead4;border-radius:50%;box-shadow:0 0 12px #5eead4;animation:pulse-glow 2s infinite;}",
        "@keyframes pulse-glow{0%{transform:scale(0.95);box-shadow:0 0 0 0 rgba(94,234,212,0.7);}70%{transform:scale(1.05);box-shadow:0 0 0 10px rgba(94,234,212,0);}100%{transform:scale(0.95);box-shadow:0 0 0 0 rgba(94,234,212,0);}}",
        ".bar{display:flex;flex-wrap:wrap;gap:0.75rem;align-items:center;margin-bottom:1.2rem;}",
        ".pill{background:rgba(26,31,38,0.7);backdrop-filter:blur(8px);border:1px solid var(--border);border-radius:999px;padding:0.35rem 0.9rem;color:var(--text-sub);font-size:0.85rem;font-family:'JetBrains Mono',monospace;transition:all 0.2s ease;}",
        ".pill:hover{border-color:rgba(94,234,212,0.3);transform:translateY(-1px);}",
        ".pill b{color:var(--accent-cyan);}",
        ".pill.ai{border-color:rgba(14,116,144,0.5);color:#67e8f9;background:rgba(14,116,144,0.15);}",
        ".tabs a,.nav a{display:inline-block;margin:0 0.35rem 0.35rem 0;padding:0.4rem 0.9rem;border-radius:8px;border:1px solid var(--border);color:#cbd5e1;text-decoration:none;background:rgba(18,22,28,0.8);font-size:0.85rem;font-family:'JetBrains Mono',monospace;transition:all 0.2s ease;}",
        ".tabs a:hover,.nav a:hover{background:rgba(30,41,59,0.8);border-color:var(--accent-cyan);color:var(--accent-cyan);transform:translateY(-1px);}",
        ".tabs a.on{border-color:var(--accent-cyan);color:var(--accent-cyan);background:rgba(94,234,212,0.1);box-shadow:0 0 10px rgba(94,234,212,0.15);}",
        ".nav{margin:0.8rem 0 1.2rem;padding:0.8rem 1rem;background:rgba(15,19,24,0.7);backdrop-filter:blur(12px);border:1px solid rgba(255,255,255,0.06);border-radius:12px;}",
        ".nav .lbl{color:#64748b;font-size:0.72rem;font-weight:600;text-transform:uppercase;letter-spacing:0.08em;margin:0 0 0.5rem 0;display:block;}",
        ".sess{border:1px solid var(--border);border-radius:12px;padding:1.1rem;margin:1rem 0;background:var(--bg-card);backdrop-filter:blur(12px);transition:all 0.25s cubic-bezier(0.4,0,0.2,1);position:relative;overflow:hidden;}",
        ".sess::before{content:'';position:absolute;top:0;left:0;width:4px;height:100%;background:rgba(255,255,255,0.1);transition:all 0.2s ease;}",
        ".sess.active{border-color:var(--accent-cyan);background:var(--bg-card-active);box-shadow:0 8px 32px rgba(0,0,0,0.4),0 0 20px rgba(94,234,212,0.15);}",
        ".sess.active::before{background:var(--accent-cyan);}",
        ".sess h2{margin:0 0 0.6rem 0;font-size:1.15rem;color:var(--text-main);font-family:'Outfit',sans-serif;display:flex;align-items:center;flex-wrap:wrap;gap:0.5rem;}",
        ".meta{color:var(--text-sub);font-size:0.85rem;font-family:'JetBrains Mono',monospace;}",
        ".meta a.link{color:var(--accent-cyan);margin-right:1rem;text-decoration:none;transition:all 0.2s ease;display:inline-flex;align-items:center;}",
        ".meta a.link:hover{color:#99f6e4;text-decoration:underline;}",
        ".ach{color:var(--accent-amber);font-size:0.85rem;font-family:'JetBrains Mono',monospace;margin:0.6rem 0;padding:0.4rem 0.75rem;background:rgba(251,191,36,0.08);border:1px dashed rgba(251,191,36,0.3);border-radius:6px;}",
        ".grp{margin:0.8rem 0 0.3rem;color:#94a3b8;font-size:0.75rem;font-weight:600;text-transform:uppercase;letter-spacing:0.06em;}",
        ".cap{display:inline-block;margin:3px;padding:7px 12px;border-radius:6px;background:rgba(26,31,38,0.9);border:1px solid rgba(255,255,255,0.1);color:#e5e7eb;text-decoration:none;font-size:0.88rem;font-family:'JetBrains Mono',monospace;transition:all 0.2s ease;}",
        ".cap.read{border-color:rgba(52,211,153,0.4);color:#a7f3d0;}",
        ".cap.read:hover{background:rgba(16,185,129,0.2);border-color:#34d399;box-shadow:0 0 12px rgba(52,211,153,0.3);transform:translateY(-2px);}",
        ".cap.destructive{border-color:rgba(248,113,113,0.4);color:#fecaca;}",
        ".cap.destructive:hover{background:rgba(239,68,68,0.2);border-color:#f87171;box-shadow:0 0 12px rgba(248,113,113,0.3);transform:translateY(-2px);}",
        ".phase{display:inline-block;background:rgba(30,41,59,0.8);color:#7dd3fc;padding:2px 8px;border-radius:4px;font-size:0.75rem;margin-left:0.4rem;font-family:'JetBrains Mono',monospace;}",
        ".search{margin:0.8rem 0;}",
        ".search input{background:rgba(15,19,24,0.9);border:1px solid rgba(255,255,255,0.12);color:#e8eaed;padding:0.5rem 0.8rem;border-radius:8px;width:min(380px,90%);font-family:'JetBrains Mono',monospace;font-size:0.88rem;transition:all 0.2s ease;}",
        ".search input:focus{outline:none;border-color:var(--accent-cyan);box-shadow:0 0 12px rgba(94,234,212,0.2);}",
        ".search button{background:linear-gradient(135deg,#0d9488 0%,#0891b2 100%);color:#ccfbf1;border:0;padding:0.5rem 1rem;border-radius:8px;cursor:pointer;font-family:'Outfit',sans-serif;font-weight:500;transition:all 0.2s ease;}",
        ".search button:hover{box-shadow:0 0 12px rgba(94,234,212,0.4);transform:translateY(-1px);}",
        "#drawer{display:none;position:fixed;bottom:20px;right:20px;width:min(600px,90vw);max-height:50vh;background:rgba(15,23,42,0.95);backdrop-filter:blur(16px);border:1px solid var(--accent-cyan);border-radius:12px;box-shadow:0 20px 50px rgba(0,0,0,0.8);padding:1rem;z-index:9999;overflow-y:auto;font-family:'JetBrains Mono',monospace;}",
        "#drawer header{display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid rgba(255,255,255,0.1);padding-bottom:0.5rem;margin-bottom:0.5rem;}",
        "#drawer h3{margin:0;font-size:1rem;color:var(--accent-cyan);}",
        "#drawer .close{cursor:pointer;color:var(--text-sub);font-size:1.2rem;border:none;background:none;}",
        "#drawer pre{margin:0;white-space:pre-wrap;word-break:break-all;color:#e2e8f0;font-size:0.85rem;}",
        ".empty{max-width:560px;margin:2rem auto;padding:1.5rem 1.75rem;border:1px solid var(--border);border-radius:14px;background:var(--bg-card);}",
        ".empty h2{margin:0 0 0.6rem;color:var(--accent-cyan);font-size:1.2rem;}",
        ".empty ul{color:var(--text-sub);line-height:1.6;}",
        "kbd{background:#1e293b;border:1px solid #334155;border-radius:4px;padding:1px 6px;font-family:'JetBrains Mono',monospace;font-size:0.8rem;}",
        "#help{display:none;position:fixed;top:50%;left:50%;transform:translate(-50%,-50%);width:min(420px,92vw);background:rgba(15,23,42,0.98);border:1px solid var(--accent-cyan);border-radius:12px;padding:1.2rem;z-index:10000;box-shadow:0 20px 60px rgba(0,0,0,0.7);}",
        "#help h3{margin:0 0 0.6rem;color:var(--accent-cyan);}",
        "#help dl{margin:0;display:grid;grid-template-columns:auto 1fr;gap:0.35rem 1rem;font-size:0.88rem;}",
        "#help dt{color:var(--accent-amber);font-family:'JetBrains Mono',monospace;}",
        "#help dd{margin:0;color:var(--text-sub);}",
        "#toast{position:fixed;bottom:24px;left:50%;transform:translateX(-50%);background:#0f172a;border:1px solid var(--accent-cyan);color:#e2e8f0;padding:0.55rem 1.1rem;border-radius:999px;font-size:0.85rem;opacity:0;pointer-events:none;transition:opacity 0.25s;z-index:10001;}",
        "#toast.show{opacity:1;}",
        ".health-ok{color:#6ee7b7;} .health-bad{color:#fca5a5;}",
        ".sess:focus-within,.sess.focused{outline:2px solid rgba(94,234,212,0.45);outline-offset:2px;}",
        "</style></head><body>",
        "<h1>KFIOSA RAT dashboard · control centre</h1>",
        "<div class='bar'>",
        f"<span class='pill' id='pill-sessions'>sessions <b>{state.get('total_sessions', len(roster))}</b></span>",
        f"<span class='pill' id='pill-wifi'>Wi‑Fi <b>{by_kind.get('wifi', 0)}</b></span>",
        f"<span class='pill' id='pill-ble'>BLE <b>{by_kind.get('ble', 0)}</b></span>",
        f"<span class='pill' id='pill-host'>Host <b>{by_kind.get('host', 0)}</b></span>",
        f"<span class='pill' id='pill-chain'>chain <b>{esc((state.get('chain') or {}).get('status', 'idle'))}</b></span>",
        f"<span class='pill ai' id='ai-pill' title='live /api/v4/ai_status'>{ai_pill}</span>",
        "<span class='pill' id='health-pill' title='/api/v5/health'>sys …</span>",
        "<span class='pill' id='scan-pill' title='long-range scan defaults'>scan …</span>",
        "</div>",
        "<div class='tabs'>",
        "<a class='on' href='/' data-kind='all'>All</a>",
        "<a href='/api/sessions?kind=wifi' data-kind='wifi'>Wi‑Fi only</a>",
        "<a href='/api/sessions?kind=ble' data-kind='ble'>BLE only</a>",
        "<a href='/api/sessions?kind=host' data-kind='host'>Host only</a>",
        "<a href='/api/attack_state'>Attack state JSON</a>",
        "<a href='/aggregate'>Aggregate</a>",
        "<a href='/api/v5/health'>Health</a>",
        "<a href='/api/transport_summary'>Transport summary</a>",
        "</div>",
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
        "<span class='lbl'>v4 · polymorphic scans · AI · v5 UX</span>",
        "<a href='/api/v4/scan_options?surface=wifi'>scan · wifi</a>",
        "<a href='/api/v4/scan_options?surface=ble'>scan · ble</a>",
        "<a href='/api/v4/scan_options?surface=http'>scan · http</a>",
        "<a href='/api/v4/scan_options?surface=smb'>scan · smb</a>",
        "<a href='/api/v4/scan_options?surface=ssh'>scan · ssh</a>",
        "<a href='/api/v4/ai_status'>AI status JSON</a>",
        "<a href='/api/v4/hardware'>operator hardware</a>",
        "<a href='/api/v5/summary'>session summary</a>",
        "<a href='/api/sessions?compact=1'>sessions compact</a>",
        "</div>",
        "<div class='search'>",
        "<form method='get' action='/api/sessions' id='filter-form'>",
        "<input id='filter-input' name='q' placeholder='filter sessions (id, tag, surface)…  [/]' ",
        "aria-label='session filter' autocomplete='off'/> ",
        "<button type='submit'>Search</button>",
        "<button type='button' id='help-btn' title='keyboard shortcuts'>?</button>",
        "</form></div>",
        "<div id='drawer'><header><h3 id='drawer-title'>Output</h3><button class='close' type='button' id='drawer-close'>&times;</button></header><pre id='drawer-body'></pre></div>",
        "<div id='help'><h3>Keyboard shortcuts</h3><dl id='help-dl'></dl>"
        "<p class='meta' style='margin-top:0.8rem'>Press <kbd>Esc</kbd> or <kbd>?</kbd> to close</p></div>",
        "<div id='toast'></div>",
    ]
    if not roster:
        try:
            from . import v5_enhancements as _v5
            parts.append(_v5.empty_state_html())
        except Exception:
            parts.append(
                "<p class='meta'>No active sessions yet. Gain access from the "
                "Wi‑Fi / BLE chain (ACCEPT-gated).</p>"
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
        "at chain time; this UI only shows what was really earned. "
        "Click a capability to open the live output drawer (AJAX).</p>"
        "<script>"
        "(function(){"
        "function toast(m){var t=document.getElementById('toast');if(!t)return;"
        "t.textContent=m;t.classList.add('show');"
        "setTimeout(function(){t.classList.remove('show')},2200);}"
        "function openDrawer(title,body){"
        "var d=document.getElementById('drawer');"
        "document.getElementById('drawer-title').textContent=title||'Output';"
        "document.getElementById('drawer-body').textContent=body||'';"
        "d.style.display='block';}"
        "function closeDrawer(){var d=document.getElementById('drawer');if(d)d.style.display='none';}"
        "var dc=document.getElementById('drawer-close');"
        "if(dc)dc.onclick=closeDrawer;"
        "function refreshAI(){var el=document.getElementById('ai-pill');if(!el)return;"
        "fetch('/api/v4/ai_status').then(function(r){return r.json()}).then(function(j){"
        "if(!j||!j.ok)return;"
        "var m=(j.model||'?');if(m.length>28)m=m.slice(0,25)+'\\u2026';"
        "el.textContent='AI '+(j.provider||j.active||'?')+' '"
        "+(j.reachable?'up':'down')+' \\u00b7 '+m;"
        "el.className='pill ai '+(j.reachable?'health-ok':'health-bad');"
        "}).catch(function(){});}"
        "function refreshHealth(){"
        "fetch('/api/v5/health').then(function(r){return r.json()}).then(function(j){"
        "if(!j)return;"
        "var hp=document.getElementById('health-pill');"
        "var sp=document.getElementById('scan-pill');"
        "if(hp){var sql=j.sql&&j.sql.ok;var ai=j.ai&&j.ai.reachable;"
        "hp.innerHTML='sys <b class=\"'+(sql&&ai?'health-ok':'health-bad')+'\">'+"
        "(ai?'AI':'AI\\u2193')+' \\u00b7 '+(sql?'SQL':'SQL\\u2193')+'</b>';"
        "hp.title='uptime '+j.uptime_s+'s';}"
        "if(sp&&j.scan){sp.innerHTML='scan <b>wifi '+ (j.scan.wifi_default_s||'?')+"
        "s \\u00b7 ble '+(j.scan.ble_default_s||'?')+'s</b>';}"
        "}).catch(function(){});}"
        "function refreshState(){"
        "fetch('/api/attack_state').then(function(r){return r.json()}).then(function(j){"
        "if(!j)return;var bk=j.by_kind||{};"
        "function set(id,lab,n){var e=document.getElementById(id);if(e)e.innerHTML=lab+' <b>'+n+'</b>';}"
        "set('pill-sessions','sessions',j.total_sessions!=null?j.total_sessions:'?');"
        "set('pill-wifi','Wi-Fi',bk.wifi||0);set('pill-ble','BLE',bk.ble||0);"
        "set('pill-host','Host',bk.host||0);"
        "var ch=(j.chain&&j.chain.status)||'idle';"
        "var pc=document.getElementById('pill-chain');if(pc)pc.innerHTML='chain <b>'+ch+'</b>';"
        "}).catch(function(){});}"
        "var inp=document.getElementById('filter-input');"
        "if(inp){inp.addEventListener('input',function(){"
        "var q=inp.value.toLowerCase().trim();"
        "document.querySelectorAll('.sess').forEach(function(card){"
        "var txt=card.textContent.toLowerCase();"
        "card.style.display=(!q||txt.indexOf(q)!==-1)?'block':'none';"
        "});});}"
        "document.addEventListener('click',function(ev){"
        "var a=ev.target.closest('a.cap');if(!a)return;"
        "var href=a.getAttribute('href')||'';"
        "if(href.indexOf('/cap/')!==0)return;"
        "ev.preventDefault();"
        "openDrawer(a.textContent.trim()||'Capability','Running...');"
        "fetch(href,{headers:{'Accept':'application/json'}})"
        ".then(function(r){return r.text()})"
        ".then(function(t){"
        "try{var j=JSON.parse(t);openDrawer(a.textContent.trim(),"
        "(j.pretty||JSON.stringify(j,null,2)));}"
        "catch(e){openDrawer(a.textContent.trim(),t.slice(0,12000));}"
        "toast('capability finished');"
        "}).catch(function(e){openDrawer('Error',String(e));});"
        "});"
        "var cards=[],ci=-1;"
        "function visibleCards(){return Array.prototype.slice.call("
        "document.querySelectorAll('.sess')).filter(function(c){"
        "return c.style.display!=='none';});}"
        "function focusCard(i){cards=visibleCards();if(!cards.length)return;"
        "cards.forEach(function(c){c.classList.remove('focused')});"
        "ci=(i+cards.length)%cards.length;cards[ci].classList.add('focused');"
        "cards[ci].scrollIntoView({block:'nearest',behavior:'smooth'});}"
        "var help=document.getElementById('help');"
        "var hb=document.getElementById('help-btn');"
        "if(hb)hb.onclick=function(){help.style.display=help.style.display==='block'?'none':'block';};"
        "fetch('/api/v5/shortcuts').then(function(r){return r.json()}).then(function(j){"
        "var dl=document.getElementById('help-dl');if(!dl||!j||!j.shortcuts)return;"
        "Object.keys(j.shortcuts).forEach(function(k){"
        "var dt=document.createElement('dt');dt.textContent=k;"
        "var dd=document.createElement('dd');dd.textContent=j.shortcuts[k];"
        "dl.appendChild(dt);dl.appendChild(dd);});"
        "}).catch(function(){});"
        "document.addEventListener('keydown',function(ev){"
        "var tag=(ev.target&&ev.target.tagName||'').toLowerCase();"
        "var typing=tag==='input'||tag==='textarea';"
        "if(ev.key==='Escape'){closeDrawer();if(help)help.style.display='none';return;}"
        "if(ev.key==='?'||(ev.key==='/'&&!typing&&ev.shiftKey)){"
        "if(!typing){ev.preventDefault();if(help)help.style.display="
        "help.style.display==='block'?'none':'block';}return;}"
        "if(ev.key==='/'&&!typing){ev.preventDefault();if(inp)inp.focus();return;}"
        "if(typing)return;"
        "if(ev.key==='j'){ev.preventDefault();focusCard(ci+1);}"
        "if(ev.key==='k'){ev.preventDefault();focusCard(ci-1);}"
        "if(ev.key==='r'){refreshState();refreshAI();refreshHealth();toast('refreshed');}"
        "if(ev.key==='Enter'&&ci>=0){cards=visibleCards();var c=cards[ci];"
        "if(c){var cap=c.querySelector('a.cap');if(cap)cap.click();}}"
        "if(ev.key==='0')location.href='/';"
        "if(ev.key==='1')location.href='/api/sessions?kind=wifi';"
        "if(ev.key==='2')location.href='/api/sessions?kind=ble';"
        "if(ev.key==='3')location.href='/api/sessions?kind=host';"
        "});"
        "var conf={ai_status_ms:15000,attack_state_ms:8000,health_ms:20000};"
        "fetch('/api/v5/refresh').then(function(r){return r.json()}).then(function(j){"
        "if(j&&j.ok)conf=j;}).catch(function(){}).then(function(){"
        "refreshAI();refreshHealth();refreshState();"
        "setInterval(refreshAI,conf.ai_status_ms||15000);"
        "setInterval(refreshHealth,conf.health_ms||20000);"
        "setInterval(refreshState,conf.attack_state_ms||8000);"
        "});"
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
