"""core.post_access_tui.rat_ext — RAT-like external browser dashboard.

When the orchestrator gains access to a target, the operator can choose
to spawn a browser-based dashboard that:

  * Lists every active session (BLE or Network) with the capabilities
    that were ACTUALLY ACHIEVED during the attack chain.
  * Lets the operator pick a session + capability and run it (each
    capability call is wrapped by the same ACCEPT/CANCEL gate as
    every other chain step).
  * Dynamically builds the capability roster per session — if the
    chain never ran ``mimikatz``, the "view harvested hashes"
    capability is NOT shown for that session.
  * Bound to 127.0.0.1 by default; ``RAT_DASHBOARD_HOST=0.0.0.0``
    only on operator-initiated opt-in.

Implementation notes:
  * Uses an in-process WSGI/HTTP server (Flask if available, otherwise
    the stdlib ``wsgiref.simple_server``) so the same module works
    whether or not Flask is installed.
  * Templates are stored as plain Python strings in
    ``templates_text.py`` so the dashboard runs without filesystem
    layout surprises.
  * Capabilities are registered in a flat ``SessionCapability`` list
    and matched per-session based on the session's ``achieved``
    attribute set (populated by the chain step that gained access).

Safety stance (carried over):
  * Every capability call wraps the existing
    ``_v2_*`` runner methods; the runner still returns the honest-
    degrade envelope when the target is unreachable / no consent.
  * The dashboard never inlines harvested credential values; it only
    displays the names of capabilities and the structured envelopes.
  * The Flask/WSGI server runs in a separate process; the chain step
    that opened the dashboard is the one place where the per-step
    ACCEPT gate fires (the dashboard itself does NOT re-confirm
    individual capability calls — those are the operator's choice
    after the dashboard is up).
"""
from __future__ import annotations

import os
import socket
import threading
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

# Public surface (re-exported by __init__.py)
__all__ = [
    "SessionCapability",
    "RatDashboardServer",
    "spawn_rat_dashboard",
    "is_rat_dashboard_available",
    "BLUETOOTH_CAPABILITIES",
    "NETWORK_CAPABILITIES",
    "build_session_roster",
    "default_dashboard_html",
]


# ---------------------------------------------------------------------------
# Capability base
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SessionCapability:
    """A single browser-dashboard capability.

    name        — short id used in the URL/path
    label       — what the operator sees in the browser
    transport   — "ble" or "network" — where this capability belongs
    required_achievements — set of strings that must be in the
                             session's ``achieved`` set to surface
    risk        — "read" or "destructive" — mirrors the v2 registry
    description — one-line summary shown in the dashboard
    """

    name: str
    label: str
    transport: str
    required_achievements: Tuple[str, ...]
    risk: str
    description: str


# ---------------------------------------------------------------------------
# Bluetooth capabilities (~12)
# ---------------------------------------------------------------------------


BLUETOOTH_CAPABILITIES: List[SessionCapability] = [
    SessionCapability(
        name="gatt_browse",
        label="Browse GATT services",
        transport="ble",
        required_achievements=("gatt_connect",),
        risk="read",
        description="Enumerate primary services + characteristics "
                    "on the connected peripheral.",
    ),
    SessionCapability(
        name="gatt_read",
        label="Read characteristic",
        transport="ble",
        required_achievements=("gatt_connect",),
        risk="read",
        description="Read a single characteristic by handle/UUID.",
    ),
    SessionCapability(
        name="gatt_write",
        label="Write characteristic",
        transport="ble",
        required_achievements=("gatt_connect", "gatt_write"),
        risk="destructive",
        description="Write a single characteristic; the gatt_write "
                    "achievement was earned earlier in the chain.",
    ),
    SessionCapability(
        name="gatt_notify",
        label="Subscribe to notifications",
        transport="ble",
        required_achievements=("gatt_connect", "gatt_notify"),
        risk="read",
        description="Subscribe to a CCCD and stream notifications.",
    ),
    SessionCapability(
        name="hid_inject",
        label="HID injection",
        transport="ble",
        required_achievements=("hid_inject",),
        risk="destructive",
        description="Inject keystrokes via the HID over GATT "
                    "primitive (chain must have earned it).",
    ),
    SessionCapability(
        name="ota_downgrade",
        label="OTA firmware downgrade",
        transport="ble",
        required_achievements=("ota_downgrade",),
        risk="destructive",
        description="Downgrade firmware via the OTA profile (chain "
                    "must have earned the primitive).",
    ),
    SessionCapability(
        name="battery_drain",
        label="Battery-drain loop",
        transport="ble",
        required_achievements=("gatt_write",),
        risk="destructive",
        description="Loop a GATT write that keeps the radio busy.",
    ),
    SessionCapability(
        name="whitelist_clone",
        label="Clone bonding whitelist",
        transport="ble",
        required_achievements=("bond_dump",),
        risk="destructive",
        description="Read bonded IRKs / LTKs and re-inject into a "
                    "second adapter.",
    ),
    SessionCapability(
        name="mesh_infiltrate",
        label="Mesh node infiltrate",
        transport="ble",
        required_achievements=("mesh_provision",),
        risk="destructive",
        description="Provision a malicious node into the mesh.",
    ),
    SessionCapability(
        name="rssi_track",
        label="RSSI track",
        transport="ble",
        required_achievements=("rssi_sample",),
        risk="read",
        description="Live RSSI samples for movement classification.",
    ),
    SessionCapability(
        name="addr_resolve",
        label="Resolve RPA",
        transport="ble",
        required_achievements=("rpa_capture",),
        risk="read",
        description="Resolve a Resolvable Private Address from a "
                    "captured IRK.",
    ),
    SessionCapability(
        name="channel_map",
        label="Channel map report",
        transport="ble",
        required_achievements=(),
        risk="read",
        description="Read-only channel-occupancy report.",
    ),
]


# ---------------------------------------------------------------------------
# Network capabilities (~14)
# ---------------------------------------------------------------------------


NETWORK_CAPABILITIES: List[SessionCapability] = [
    SessionCapability(
        name="shell",
        label="Live shell",
        transport="network",
        required_achievements=("shell",),
        risk="destructive",
        description="Open a shell on the compromised target "
                    "(Meterpreter / SSH / WMI exec).",
    ),
    SessionCapability(
        name="file_get",
        label="File GET",
        transport="network",
        required_achievements=("shell",),
        risk="read",
        description="Download a file from the target to the "
                    "operator's machine.",
    ),
    SessionCapability(
        name="file_put",
        label="File PUT",
        transport="network",
        required_achievements=("shell",),
        risk="destructive",
        description="Upload a file to the target.",
    ),
    SessionCapability(
        name="portfwd_add",
        label="Add port-forward",
        transport="network",
        required_achievements=("shell",),
        risk="destructive",
        description="Add a port-forward through the compromised "
                    "session.",
    ),
    SessionCapability(
        name="socks_start",
        label="Start SOCKS proxy",
        transport="network",
        required_achievements=("shell",),
        risk="destructive",
        description="Bring up a SOCKS proxy through the session.",
    ),
    SessionCapability(
        name="lateral_picker",
        label="Lateral target picker",
        transport="network",
        required_achievements=("shell", "lateral_target_pool"),
        risk="read",
        description="Pick a lateral target from the harvested pool.",
    ),
    SessionCapability(
        name="exfil_picker",
        label="Exfiltration channel picker",
        transport="network",
        required_achievements=("shell", "exfil_channel"),
        risk="destructive",
        description="Pick a channel to exfil data through.",
    ),
    SessionCapability(
        name="persistence",
        label="Persistence manager",
        transport="network",
        required_achievements=("shell", "persistence_mechanism"),
        risk="destructive",
        description="Install / remove a persistence mechanism.",
    ),
    SessionCapability(
        name="antiforensic",
        label="Anti-forensic trigger",
        transport="network",
        required_achievements=("shell", "antiforensic"),
        risk="destructive",
        description="Trigger a clean-up action (syslog clear, "
                    "timestomp, etc).",
    ),
    SessionCapability(
        name="keylogger",
        label="Keylogger toggle",
        transport="network",
        required_achievements=("shell",),
        risk="destructive",
        description="Toggle the keylogger (if the chain earned it).",
    ),
    SessionCapability(
        name="hash_dump",
        label="View harvested hashes",
        transport="network",
        required_achievements=("creds_dump",),
        risk="destructive",
        description="List hashes dumped by mimikatz / pypykatz / "
                    "secretsdump. Values are NEVER inlined; only "
                    "shape (username@domain) is shown.",
    ),
    SessionCapability(
        name="bloodhound",
        label="BloodHound viewer",
        transport="network",
        required_achievements=("bloodhound_audit",),
        risk="read",
        description="View a BloodHound-style audit summary.",
    ),
    SessionCapability(
        name="broadcast",
        label="Broadcast cmd",
        transport="network",
        required_achievements=("shell",),
        risk="destructive",
        description="Send one command to every active session.",
    ),
    SessionCapability(
        name="portfwd_kill",
        label="Kill port-forwards",
        transport="network",
        required_achievements=("shell",),
        risk="destructive",
        description="Tear down every port-forward on the session.",
    ),
]


# ---------------------------------------------------------------------------
# Roster builder
# ---------------------------------------------------------------------------


def build_session_roster(
    sessions: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Return the dashboard roster given a list of session dicts.

    Each session dict must have at least:
      * ``id`` (str) — unique session id
      * ``transport`` (str) — "ble" or "network"
      * ``achieved`` (set[str] or list[str]) — the achievements earned
        during the attack chain
      * ``target`` (str) — BSSID / address / hostname
      * ``meta`` (dict) — free-form metadata (lat/lon, model, etc.)

    The returned list contains one entry per session, each entry
    listing the capabilities that should be shown for that session
    based on its ``achieved`` set.
    """
    roster: List[Dict[str, Any]] = []
    for s in sessions or []:
        sid = s.get("id") or ""
        transport = (s.get("transport") or "network").lower()
        achieved = set(s.get("achieved") or [])
        if transport == "ble":
            pool = BLUETOOTH_CAPABILITIES
        else:
            pool = NETWORK_CAPABILITIES
        visible = []
        for cap in pool:
            if not cap.required_achievements:
                # Always available (e.g. RSSI track, channel map)
                visible.append({
                    "name": cap.name,
                    "label": cap.label,
                    "risk": cap.risk,
                    "description": cap.description,
                    "required": list(cap.required_achievements),
                })
                continue
            if all(req in achieved for req in cap.required_achievements):
                visible.append({
                    "name": cap.name,
                    "label": cap.label,
                    "risk": cap.risk,
                    "description": cap.description,
                    "required": list(cap.required_achievements),
                })
        roster.append({
            "id": sid,
            "transport": transport,
            "target": s.get("target", ""),
            "meta": s.get("meta", {}),
            "achieved": sorted(achieved),
            "capabilities": visible,
        })
    return roster


# ---------------------------------------------------------------------------
# HTML rendering (no Flask dependency)
# ---------------------------------------------------------------------------


def _esc(s: str) -> str:
    """Minimal HTML escaper."""
    return (s.replace("&", "&amp;")
             .replace("<", "&lt;")
             .replace(">", "&gt;")
             .replace('"', "&quot;")
             .replace("'", "&#39;"))


def default_dashboard_html(roster: List[Dict[str, Any]]) -> str:
    """Render the dashboard HTML for the given session roster.

    Returns a single self-contained HTML string with inline CSS.
    No external assets are loaded. Phase 2.4 §B.10 — dark
    monospace palette, single accent colour, one-line table
    layout, per-session PDF report button.
    """
    parts = [
        "<!doctype html>",
        "<html><head><meta charset='utf-8'>",
        "<title>KFIOSA RAT dashboard</title>",
        "<style>",
        "body { font-family: monospace; background: #111; color: #eee; "
        "margin: 1em; }",
        "h1 { color: #4ec; }",
        ".session { border: 1px solid #444; margin: 0.5em 0; "
        "padding: 0.5em; border-radius: 4px; }",
        ".cap { display: inline-block; margin: 2px; padding: 4px 8px; "
        "background: #222; border: 1px solid #555; border-radius: 3px; "
        "text-decoration: none; color: #ccc; cursor: pointer; }",
        ".cap.read { border-color: #284; }",
        ".cap.destructive { border-color: #a44; }",
        ".meta { color: #888; font-size: 0.9em; }",
        ".achieved { color: #fb5; font-size: 0.9em; }",
        ".pdf-btn { display: inline-block; padding: 4px 10px; "
        "background: #222; border: 1px solid #4ec; border-radius: 3px; "
        "color: #4ec; text-decoration: none; margin-left: 0.5em; }",
        ".topbar { margin-bottom: 1em; }",
        ".topbar a { color: #4ec; margin-right: 1em; }",
        "</style></head><body>",
        "<h1>KFIOSA RAT dashboard</h1>",
        "<div class='topbar'>",
        f"<span class='meta'>{len(roster)} active session(s)</span>",
        "<a href='/aggregate'>[aggregate view]</a>",
        "<a href='/api/transport_summary'>[transport summary JSON]</a>",
        "<a href='/api/sql_health'>[SQL health]</a>",
        "<a href='/api/sql/sessions'>[SQL sessions]</a>",
        "<a href='/api/sql/snapshot/default'>[SQL snapshot (default sid)]</a>",
        "<a href='/api/sql/log/default?limit=20'>[SQL log (default sid)]</a>",
        "<a href='/api/sql/history/default?limit=20'>[SQL history (default sid)]</a>",
        "</div>",
    ]
    if not roster:
        parts.append("<p><em>No active sessions.</em></p>")
    for s in roster:
        parts.append("<div class='session'>")
        parts.append(
            f"<h2>{_esc(s.get('id', '?'))} "
            f"<span class='meta'>({_esc(s.get('transport', '?'))} → "
            f"{_esc(s.get('target', '?'))})</span>"
            f"<a class='pdf-btn' href='/api/session/"
            f"{_esc(s.get('id', ''))}/report.pdf'>[export PDF]</a>"
            f"<a class='pdf-btn' href='/api/session/"
            f"{_esc(s.get('id', ''))}/recommend'>[recommend]</a>"
            f"<a class='pdf-btn' href='/api/session/"
            f"{_esc(s.get('id', ''))}/exfil'>[exfil]</a>"
            f"<a class='pdf-btn' href='/api/session/"
            f"{_esc(s.get('id', ''))}/persistence'>[persistence]</a>"
            f"<a class='pdf-btn' href='/stream/"
            f"{_esc(s.get('id', ''))}'>[stream]</a>"
            "</h2>"
        )
        achieved = s.get("achieved") or []
        if achieved:
            parts.append(
                "<div class='achieved'>achieved: "
                f"{_esc(', '.join(achieved))}</div>"
            )
        caps = s.get("capabilities") or []
        if not caps:
            parts.append("<p class='meta'><em>No capabilities earned "
                         "yet for this session.</em></p>")
        for c in caps:
            parts.append(
                f"<a class='cap {_esc(c.get('risk', 'read'))}' "
                f"href='/cap/{_esc(s.get('id', ''))}"
                f"/{_esc(c.get('name', ''))}' "
                f"title='{_esc(c.get('description', ''))}'>"
                f"{_esc(c.get('label', '?'))}</a>"
            )
        parts.append("</div>")
    parts.append("</body></html>")
    return "".join(parts)


# ---------------------------------------------------------------------------
# WSGI app
# ---------------------------------------------------------------------------


def _build_wsgi_app(roster: List[Dict[str, Any]],
                    capability_runner: Optional[
                        Callable[[str, str], Dict[str, Any]]
                    ] = None,
                    sessions: Optional[List[Dict[str, Any]]] = None):
    """Build a WSGI-callable app for the dashboard.

    Routes (Phase 2.4 §B):
      GET  /                                            — dashboard HTML
      GET  /aggregate                                   — cross-session table
      GET  /api/transport_summary                       — JSON aggregate
      GET  /cap/<sid>/<cap>                             — invoke a capability
      GET  /api/session/<sid>/recommend                 — capability hint
      GET  /api/session/<sid>/exfil                     — exfil queue
      POST /api/session/<sid>/exfil/<job_id>/cancel     — operator cancel
      GET  /api/session/<sid>/persistence               — installed mech
      POST /api/session/<sid>/persistence/<m>/remove    — operator remove
      GET  /api/session/<sid>/history                   — JSONL history
      POST /api/session/<sid>/replay                    — replay cmd
      GET  /api/session/<sid>/ls?path=<rel>             — read-only ls
      GET  /api/session/<sid>/get?path=<rel>            — read-only get
      GET  /api/session/<sid>/report.pdf                — PDF report
      GET  /api/session/<sid>/screens                   — screenshot list
      GET  /stream/<sid>                                — SSE event stream
      GET  /stream/<sid>/log?since=<ts>                 — JSONL polling
      POST /upload/<sid>                                — screenshot upload
      GET  /login                                       — login page
      POST /login                                       — bearer submit
    """
    from . import auth as _auth
    from . import file_browser as _fb
    from . import sse as _sse
    from . import history as _hist
    from . import screenshot as _screen
    from . import aggregate as _agg
    from . import recommender as _rec
    from . import exfil_queue as _exfil
    from . import persistence_ui as _pers
    from . import pdf_export as _pdf

    sessions_list = sessions if sessions is not None else [
        r for r in (roster or [])
    ]
    sessions_by_sid: Dict[str, Dict[str, Any]] = {
        (s.get("session_id") or s.get("id") or ""): s
        for s in sessions_list if isinstance(s, dict)
    }
    auth_state = _auth.AuthState()

    def _require_auth(environ) -> bool:
        """True if the request is authenticated (or no auth required)."""
        host = (environ.get("HTTP_HOST") or "").split(":")[0]
        # Auth only required when bound to 0.0.0.0
        if not _auth.is_token_required(environ.get("SERVER_NAME", host)):
            return True
        cookie = _auth.parse_cookie(environ.get("HTTP_COOKIE"))
        ok, _reason = auth_state.check_token(cookie)
        return ok

    def app(environ, start_response):
        import json as _json_mod
        from urllib.parse import unquote as _unquote

        def _json(payload, status="200 OK"):
            body = _json_mod.dumps(payload, default=str).encode("utf-8")
            start_response(status, [
                ("Content-Type", "application/json"),
                ("Content-Length", str(len(body))),
            ])
            return [body]

        def _bytes(body, content_type, status="200 OK"):
            start_response(status, [
                ("Content-Type", content_type),
                ("Content-Length", str(len(body))),
            ])
            return [body]

        def _err(message, status="404 Not Found", content_type="text/plain"):
            body = message.encode("utf-8")
            start_response(status, [
                ("Content-Type", content_type),
                ("Content-Length", str(len(body))),
            ])
            return [body]

        def _qs(environ):
            qs = environ.get("QUERY_STRING", "")
            out = {}
            for kv in qs.split("&"):
                if "=" in kv:
                    k, v = kv.split("=", 1)
                    out[k] = _unquote(v)
            return out

        path = (environ.get("PATH_INFO") or "/").strip("/")
        method = (environ.get("REQUEST_METHOD") or "GET").upper()
        if not path:
            if not _require_auth(environ):
                body = _auth.build_login_html()
                return _bytes(body, "text/html; charset=utf-8", "401")
            body = default_dashboard_html(roster).encode("utf-8")
            return _bytes(body, "text/html; charset=utf-8")
        parts = path.split("/")
        # Login routes (B.1)
        if parts[0] == "login" and method == "GET":
            return _bytes(_auth.build_login_html(), "text/html; charset=utf-8")
        if parts[0] == "login" and method == "POST":
            try:
                size = int(environ.get("CONTENT_LENGTH", 0) or 0)
                body = environ["wsgi.input"].read(size).decode("utf-8")
            except Exception:  # noqa: BLE001
                body = ""
            token = None
            for piece in body.split("&"):
                if piece.startswith("token="):
                    from urllib.parse import unquote
                    token = unquote(piece[6:].replace("+", " "))
                    break
            ok, reason = auth_state.check_token(token)
            if not ok:
                return _bytes(_auth.build_login_html(reason),
                              "text/html; charset=utf-8", "401")
            start_response(
                "302 Found",
                [("Location", "/"),
                 ("Set-Cookie", _auth.build_set_cookie(token or ""))],
            )
            return [b""]
        # Aggregate (B.6)
        if parts[0] == "aggregate" and method == "GET":
            return _bytes(_agg.build_aggregate_html(sessions_list),
                          "text/html; charset=utf-8")
        if (parts[0] == "api" and len(parts) >= 2
                and parts[1] == "transport_summary"):
            return _json(_agg.build_transport_summary(sessions_list))
        # SQL store (B.11 / v3) — read-only view of the
        # persistent log + history + exfil + persistence rows.
        # The /api/sql_health endpoint reports the active
        # backend (sqlite default; sqlalchemy opt-in via
        # KFIOSA_SQL_URL). The /api/sql/sessions endpoint
        # mirrors the in-memory roster but survives a process
        # restart, which is the whole point of the SQL
        # integration.
        if (parts[0] == "api" and len(parts) >= 2
                and parts[1] == "sql_health"):
            try:
                from core.db import sqlstore
                return _json({
                    "ok": True,
                    "store": sqlstore.health(),
                    "backend": sqlstore.backend_from_env(),
                    "model": "rat-dashboard-v3",
                })
            except Exception as e:  # noqa: BLE001
                return _json({"ok": False, "error": str(e)})
        if (parts[0] == "api" and len(parts) >= 2
                and parts[1] == "sql" and len(parts) >= 3
                and parts[2] == "sessions" and method == "GET"):
            try:
                from core.db import sqlstore
                return _json({
                    "ok": True,
                    "sessions": sqlstore.list_sessions(),
                    "model": "rat-dashboard-v3",
                })
            except Exception as e:  # noqa: BLE001
                return _json({"ok": False, "error": str(e)})
        # SQL log read (v3 enhancement) — returns the last N
        # log rows for a given session so the operator can
        # audit chain steps that happened in a previous
        # process. Read-only; the per-step ACCEPT gate stays
        # in place for any write.
        if (parts[0] == "api" and len(parts) >= 2
                and parts[1] == "sql" and len(parts) >= 3
                and parts[2] == "log" and method == "GET"):
            sid = parts[3] if len(parts) >= 4 else "default"
            q = _qs(environ)
            try:
                limit = int(q.get("limit", "50"))
            except Exception:  # noqa: BLE001
                limit = 50
            limit = max(1, min(limit, 500))
            try:
                from core.db import sqlstore
                return _json({
                    "ok": True,
                    "sid": sid,
                    "limit": limit,
                    "log": sqlstore.list_log(sid, limit=limit),
                    "model": "rat-dashboard-v3",
                })
            except Exception as e:  # noqa: BLE001
                return _json({"ok": False, "error": str(e)})
        # SQL history read (v3 enhancement) — returns the
        # last N history rows for a given session.
        if (parts[0] == "api" and len(parts) >= 2
                and parts[1] == "sql" and len(parts) >= 3
                and parts[2] == "history" and method == "GET"):
            sid = parts[3] if len(parts) >= 4 else "default"
            q = _qs(environ)
            try:
                limit = int(q.get("limit", "50"))
            except Exception:  # noqa: BLE001
                limit = 50
            limit = max(1, min(limit, 500))
            try:
                from core.db import sqlstore
                return _json({
                    "ok": True,
                    "sid": sid,
                    "limit": limit,
                    "history": sqlstore.list_history(sid, limit=limit),
                    "model": "rat-dashboard-v3",
                })
            except Exception as e:  # noqa: BLE001
                return _json({"ok": False, "error": str(e)})
        # SQL exfil read (v3 enhancement) — the persistent
        # exfil queue survives a process restart.
        if (parts[0] == "api" and len(parts) >= 2
                and parts[1] == "sql" and len(parts) >= 3
                and parts[2] == "exfil" and method == "GET"):
            sid = parts[3] if len(parts) >= 4 else "default"
            try:
                from core.db import sqlstore
                return _json({
                    "ok": True,
                    "sid": sid,
                    "exfil": sqlstore.list_exfil(sid),
                    "model": "rat-dashboard-v3",
                })
            except Exception as e:  # noqa: BLE001
                return _json({"ok": False, "error": str(e)})
        # SQL persistence read (v3 enhancement) — the
        # persistent persistence-mechanism list.
        if (parts[0] == "api" and len(parts) >= 2
                and parts[1] == "sql" and len(parts) >= 3
                and parts[2] == "persistence" and method == "GET"):
            sid = parts[3] if len(parts) >= 4 else "default"
            try:
                from core.db import sqlstore
                return _json({
                    "ok": True,
                    "sid": sid,
                    "persistence": sqlstore.list_persistence(sid),
                    "model": "rat-dashboard-v3",
                })
            except Exception as e:  # noqa: BLE001
                return _json({"ok": False, "error": str(e)})
        # SQL sessions aggregate (v3 enhancement) — a one-
        # shot aggregate so the operator doesn't need to
        # make 4 separate /api/sql/* calls.
        if (parts[0] == "api" and len(parts) >= 2
                and parts[1] == "sql" and len(parts) >= 3
                and parts[2] == "snapshot" and method == "GET"):
            sid = parts[3] if len(parts) >= 4 else "default"
            try:
                from core.db import sqlstore
                return _json({
                    "ok": True,
                    "sid": sid,
                    "log": sqlstore.list_log(sid, limit=20),
                    "history": sqlstore.list_history(sid, limit=20),
                    "exfil": sqlstore.list_exfil(sid),
                    "persistence": sqlstore.list_persistence(sid),
                    "model": "rat-dashboard-v3",
                })
            except Exception as e:  # noqa: BLE001
                return _json({"ok": False, "error": str(e)})
        # SSE (B.3)
        if parts[0] == "stream":
            sid = parts[1] if len(parts) >= 2 else ""
            sess = sessions_by_sid.get(sid, {})
            if len(parts) >= 3 and parts[2] == "log":
                q = _qs(environ)
                since_ts = None
                if "since" in q:
                    try:
                        since_ts = float(q["since"])
                    except Exception:  # noqa: BLE001
                        pass
                ct, body = _sse.poll_session_log(sid, sess, since_ts=since_ts)
                return _bytes(body.encode("utf-8"), ct)
            ct, body = _sse.stream_session(sid, sess)
            return _bytes(body.encode("utf-8"), ct)
        # Upload (B.5)
        if parts[0] == "upload" and method == "POST":
            sid = parts[1] if len(parts) >= 2 else "default"
            try:
                size = int(environ.get("CONTENT_LENGTH", 0) or 0)
                raw = environ["wsgi.input"].read(size)
            except Exception as e:  # noqa: BLE001
                return _json({"ok": False, "error": f"read failed: {e}"})
            mime = environ.get("CONTENT_TYPE", "image/png").split(";")[0].strip()
            res = _screen.save_screenshot(sid, raw, declared_mime=mime)
            return _json(res)
        # Legacy capability route
        if len(parts) >= 3 and parts[0] == "cap":
            sid = parts[1]
            cap = parts[2]
            if capability_runner is not None:
                payload = capability_runner(sid, cap)
            else:
                payload = {
                    "ok": False,
                    "error": "no capability runner configured "
                             "(dashboard is in view-only mode)",
                    "session_id": sid,
                    "capability": cap,
                }
            return _json(payload)
        # Per-session API routes
        if parts[0] == "api" and len(parts) >= 3 and parts[1] == "session":
            sid = parts[2]
            sess = sessions_by_sid.get(sid, {})
            if not sess:
                return _json({"ok": False,
                              "error": f"unknown session {sid!r}"},
                             status="404 Not Found")
            # /api/session/<sid>/...
            if len(parts) >= 4:
                sub = parts[3]
                if sub == "recommend":
                    return _json(_rec.recommend_for_session(sess))
                if sub == "exfil":
                    if method == "GET":
                        payload = _exfil.list_jobs(sess)
                        # Mirror exfil jobs to SQL so a process
                        # restart doesn't lose the queue state.
                        try:
                            from core.db import sqlstore
                            sqlstore.record_session(
                                sid, kind=str(sess.get("transport", "auto")),
                                target=str(sess.get("target", "")),
                                meta=sess)
                            for job in payload.get("jobs", []) or []:
                                sqlstore.add_exfil(
                                    sid,
                                    channel=str(job.get("channel", "unknown")),
                                    bytes_pending=int(
                                        job.get("bytes_pending", 0) or 0),
                                    status=str(job.get("status", "pending")))
                        except Exception:  # noqa: BLE001
                            pass
                        return _json(payload)
                    if method == "POST" and len(parts) >= 6 and parts[5] == "cancel":
                        job_id = parts[4]
                        envelope = _exfil.build_cancel_envelope(
                            sid, job_id, sess)
                        # Mirror the cancel into SQL.
                        try:
                            from core.db import sqlstore
                            try:
                                jid = int(job_id)
                                sqlstore.cancel_exfil(sid, jid)
                            except (TypeError, ValueError):
                                pass
                        except Exception:  # noqa: BLE001
                            pass
                        return _json(envelope)
                if sub == "persistence":
                    if method == "GET":
                        payload = _pers.list_mechanisms(sess)
                        # Mirror installed mechanisms to SQL.
                        try:
                            from core.db import sqlstore
                            sqlstore.record_session(
                                sid, kind=str(sess.get("transport", "auto")),
                                target=str(sess.get("target", "")),
                                meta=sess)
                            for mech in payload.get("mechanisms", []) or []:
                                sqlstore.add_persistence(
                                    sid,
                                    mech_id=str(mech.get("id", "unknown")),
                                    kind=str(mech.get("kind", "unknown")),
                                    state=str(mech.get("state", "installed")))
                        except Exception:  # noqa: BLE001
                            pass
                        return _json(payload)
                    if method == "POST" and len(parts) >= 6 and parts[5] == "remove":
                        mech_id = parts[4]
                        envelope = _pers.build_remove_envelope(
                            sid, mech_id, sess)
                        # Mirror the removal into SQL.
                        try:
                            from core.db import sqlstore
                            sqlstore.remove_persistence(sid, mech_id)
                        except Exception:  # noqa: BLE001
                            pass
                        return _json(envelope)
                if sub == "history" and method == "GET":
                    q = _qs(environ)
                    limit = int(q.get("limit", "50") or "50")
                    since_ts = None
                    if "since" in q:
                        try:
                            since_ts = float(q["since"])
                        except Exception:  # noqa: BLE001
                            pass
                    payload = _hist.paginate(sid, limit=limit,
                                             since_ts=since_ts)
                    # Phase 2.4+ v3 — mirror the session into the
                    # SQL store so the history survives a process
                    # restart. The mirror is best-effort and
                    # never raises.
                    try:
                        from core.db import sqlstore
                        sqlstore.record_session(
                            sid, kind=str(sess.get("transport", "auto")),
                            target=str(sess.get("target", "")),
                            meta=sess)
                        for ev in payload.get("events", []) or []:
                            sqlstore.append_history(
                                sid, "read",
                                {"msg": ev.get("msg", ""),
                                 "kind": ev.get("kind", "log"),
                                 "ts": ev.get("ts")})
                    except Exception:  # noqa: BLE001
                        pass
                    return _json(payload)
                if sub == "replay" and method == "POST":
                    # Body is the original event dict as JSON
                    try:
                        size = int(environ.get("CONTENT_LENGTH", 0) or 0)
                        raw = environ["wsgi.input"].read(size)
                        event = _json_mod.loads(raw) if raw else {}
                    except Exception:  # noqa: BLE001
                        event = {}
                    return _json(_hist.build_replay_envelope(sid, event))
                if sub == "ls" and method == "GET":
                    q = _qs(environ)
                    return _json(_fb.ls(q.get("path", ""),
                                        sess.get("allowed_paths")))
                if sub == "get" and method == "GET":
                    q = _qs(environ)
                    return _json(_fb.get(q.get("path", ""),
                                         sess.get("allowed_paths")))
                if sub == "screens" and method == "GET":
                    q = _qs(environ)
                    since_ts = None
                    if "since" in q:
                        try:
                            since_ts = float(q["since"])
                        except Exception:  # noqa: BLE001
                            pass
                    return _json(_screen.list_screens(sid, since_ts=since_ts))
                if sub == "report.pdf" and method == "GET":
                    body, ct = _pdf.build_session_report_bytes(sess)
                    return _bytes(body, ct)
        return _err("404 not found")
    return app


# ---------------------------------------------------------------------------
# Server
# ---------------------------------------------------------------------------


@dataclass
class RatDashboardServer:
    """In-process HTTP server for the dashboard.

    Use :meth:`serve_thread` to start it in a background thread
    (handy for tests). Use :meth:`try_serve` to start it on a free
    port; returns ``(port, thread)`` or ``None`` on failure.
    """

    roster: List[Dict[str, Any]] = field(default_factory=list)
    host: str = "127.0.0.1"
    port: int = 0  # 0 = OS picks a free port
    capability_runner: Optional[Callable[[str, str], Dict[str, Any]]] = None
    _sessions: Optional[List[Dict[str, Any]]] = None
    _server: Optional[Any] = None
    _thread: Optional[threading.Thread] = None

    def _build(self):
        from wsgiref.simple_server import make_server, WSGIRequestHandler

        app = _build_wsgi_app(
            self.roster, self.capability_runner,
            sessions=self._sessions if self._sessions is not None
                     else self.roster,
        )

        class _SilentHandler(WSGIRequestHandler):
            def log_message(self, *_a, **_k):  # noqa: D401
                return

        return make_server(self.host, self.port, app,
                           handler_class=_SilentHandler)

    def try_serve(self) -> Optional[Tuple[int, threading.Thread]]:
        """Start serving on a free port; return (port, thread) or None."""
        # Try to pick a free port
        try:
            with socket.socket(socket.AF_INET,
                               socket.SOCK_STREAM) as s:
                s.bind((self.host, 0))
                self.port = s.getsockname()[1]
        except OSError:
            return None
        try:
            self._server = self._build()
        except OSError:
            return None
        actual_port = self._server.server_address[1]
        t = threading.Thread(target=self._server.serve_forever,
                             daemon=True)
        t.start()
        self._thread = t
        return actual_port, t

    def shutdown(self) -> None:
        if self._server is not None:
            try:
                self._server.shutdown()
            except Exception:  # noqa: BLE001
                pass
            self._server = None
        self._thread = None


# ---------------------------------------------------------------------------
# Spawner
# ---------------------------------------------------------------------------


def is_rat_dashboard_available() -> bool:
    """Return True if the dashboard can be spawned in this env.

    The dashboard uses only the stdlib (wsgiref + jinja2 not even
    required); we always return True. The orchestrator may still
    decline to spawn if the chain step fails the per-step ACCEPT
    gate.
    """
    return True


def spawn_rat_dashboard(
    sessions: List[Dict[str, Any]],
    capability_runner: Optional[Callable[[str, str], Dict[str, Any]]] = None,
    host: Optional[str] = None,
) -> Dict[str, Any]:
    """Spawn the RAT dashboard and return a status envelope.

    Returns ``{ok, port, thread, host, manual, error}``. The
    operator can browse to ``http://<host>:<port>/`` to interact
    with the dashboard.

    The dashboard runs in a daemon thread on the operator's
    machine. The chain step that called this function is the only
    place the per-step ACCEPT gate fires; the dashboard itself
    does NOT re-confirm individual capability calls.

    When the bind host is ``0.0.0.0`` (remote access), the env
    var ``RAT_DASHBOARD_TOKEN`` is REQUIRED — without it the
    server refuses to start. Bind to ``127.0.0.1`` for local
    development (no token required).
    """
    from . import auth as _auth
    roster = build_session_roster(sessions or [])
    bind_host = (host if host is not None
                 else os.environ.get("RAT_DASHBOARD_HOST", "127.0.0.1"))
    if bind_host in ("0.0.0.0", "::") and not _auth.get_required_token():
        return {
            "ok": False,
            "error": ("RAT_DASHBOARD_TOKEN env var is required when "
                      "binding to 0.0.0.0 (hostile interface)"),
            "host": bind_host,
        }
    server = RatDashboardServer(
        roster=roster,
        host=bind_host,
        port=0,
        capability_runner=capability_runner,
    )
    server._sessions = list(sessions or [])
    started = server.try_serve()
    if started is None:
        return {
            "ok": False,
            "error": ("failed to bind dashboard port; refusing to "
                      "spawn on a hostile interface"),
            "host": bind_host,
        }
    actual_port, _t = started
    return {
        "ok": True,
        "port": actual_port,
        "host": bind_host,
        "url": f"http://{bind_host}:{actual_port}/",
        "sessions": len(roster),
        "manual": (f"open {bind_host}:{actual_port} in your browser "
                   "(localhost only; remote access is "
                   "operator-initiated via "
                   "RAT_DASHBOARD_HOST=0.0.0.0)"),
    }
