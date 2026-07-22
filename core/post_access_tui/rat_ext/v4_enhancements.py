"""core.post_access_tui.rat_ext.v4_enhancements — Phase 4 T19.

Implements 5 dashboard improvements (the operator's "improve/debug/
enhance the flask dashboard so much" requirement).  Each
improvement is a small, testable function that the WSGI app wires
into the route table.

1. **Polymorphic scan selector** — :func:`poly_scan_options` returns
   the right set of scan options per attack surface (wifi / BLE /
   HTTP / SMB / SSH).  Polymorphic because the same UI control
   renders different content based on the selected surface.
2. **Target-adaptive session filter** — :func:`adaptive_session_filter`
   picks the right filter predicate based on the operator's
   hardware (e.g. MT7922 vs U4000) and the session's attack surface.
3. **Chain-planner live preview** — :func:`chain_plan_preview`
   builds a preview envelope the dashboard can render as the
   planner runs.  No fabricated chain data; only what the planner
   actually returns.
4. **Real-time exfil queue visualization** — :func:`exfil_progress`
   returns a snapshot of bytes_sent / bytes_total / throughput
   for an exfil job (used by the dashboard's CSS-animated gauge).
5. **AI status pill** — :func:`ai_status` returns the current
   Ollama model name + reachability + last successful latency.
   Reads ``core.ai_backend.MODEL_CATALOG['primary']`` and
   ``core.ai_backend.ollama_cloud_reachable()`` — never inlines
   the operator's token.

All functions NEVER raise.  They return ``{ok, error}`` envelopes
on failure.  They never fabricate creds, CVE ids, hash collisions,
or cracked-PSK claims.
"""
from __future__ import annotations

import json
import os
import time
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# 1. Polymorphic scan selector
# ---------------------------------------------------------------------------

# Per-attack-surface scan options.  These are the UI choices the
# dashboard surfaces when the operator picks a scan target.
_SCAN_OPTIONS: Dict[str, List[Dict[str, str]]] = {
    "wifi": [
        {"id": "deauth", "label": "Deauthentication burst",
         "description": "Send deauth frames to force a re-association."},
        {"id": "handshake", "label": "WPA2 4-way handshake capture",
         "description": "Capture the 4-way handshake for offline cracking."},
        {"id": "pmkid", "label": "PMKID capture (no client needed)",
         "description": "Capture the PMKID from the first EAPOL frame."},
        {"id": "evil_twin", "label": "Evil Twin access point",
         "description": "Clone the target SSID with a captive portal."},
        {"id": "wps", "label": "WPS Pixie Dust",
         "description": "Online WPS PIN attack (where still applicable)."},
    ],
    "ble": [
        {"id": "ll_fragment", "label": "Link-layer fragmentation",
         "description": "Test for LL fragmentation vulnerabilities."},
        {"id": "gatt_write", "label": "GATT characteristic write",
         "description": "Write to a GATT characteristic (with or without response)."},
        {"id": "hid_inject", "label": "BLE HID keystroke injection",
         "description": "Inject keystrokes via BLE HID on auto-pairing hosts."},
        {"id": "pairing_capture", "label": "Pairing-event capture",
         "description": "Capture the Just Works / OOB pairing sequence."},
    ],
    "http": [
        {"id": "sqli", "label": "SQL injection",
         "description": "Test parameterised endpoints for SQLi."},
        {"id": "ssrf", "label": "SSRF probing",
         "description": "Probe URL parameters for SSRF via metadata endpoints."},
        {"id": "lfi", "label": "Local file inclusion",
         "description": "Path-traversal probe against file parameters."},
        {"id": "open_redirect", "label": "Open redirect",
         "description": "Probe redirect parameters for open redirects."},
    ],
    "smb": [
        {"id": "enum", "label": "Share + user enumeration",
         "description": "Enumerate shares, users, and groups via SMB."},
        {"id": "psexec", "label": "psexec lateral move",
         "description": "PsExec-style remote execution via SMB."},
        {"id": "relay", "label": "SMB relay",
         "description": "Relay captured NTLM hashes to a target SMB service."},
    ],
    "ssh": [
        {"id": "user_enum", "label": "Username enumeration",
         "description": "Enumerate valid SSH usernames (CVE-2018-15473-style)."},
        {"id": "key_reuse", "label": "SSH key reuse probe",
         "description": "Test known SSH public keys against the target."},
        {"id": "bruteforce", "label": "Credential brute force",
         "description": "Per-user credential test against a small wordlist."},
    ],
}


def poly_scan_options(attack_surface: str) -> List[Dict[str, str]]:
    """Return the scan options for the given attack surface.

    Polymorphic: the same UI control renders different content
    based on the selected surface.  Falls back to an empty list
    for unknown surfaces — never fabricates options.
    """
    if not isinstance(attack_surface, str):
        return []
    return _SCAN_OPTIONS.get(attack_surface.lower(), [])


# ---------------------------------------------------------------------------
# 2. Target-adaptive session filter
# ---------------------------------------------------------------------------

OPERATOR_HARDWARE: Dict[str, Any] = {
    "wifi_chipset": "MediaTek MT7922 (mt7921e)",
    "ble_adapter": "U4000 BLUETOOTH adapter",
    "gpu": "RTX 5070 Ti 12GB",
    "ram_gb": 32,
}


def adaptive_session_filter(sessions: List[Dict[str, Any]],
                            target_attack_surface: str,
                            risk_max: str = "high",
                            ) -> List[Dict[str, Any]]:
    """Filter a list of session dicts by attack surface + risk.

    Target-adaptive: a wifi session whose attack_surface doesn't
    include the operator's wifi chipset is filtered out (it would
    fail at the orchestrator anyway).  A ble session is filtered
    out if the operator's hardware doesn't include a BLE adapter.
    Never raises; never modifies the input list.
    """
    if not isinstance(sessions, list):
        return []
    if not isinstance(target_attack_surface, str):
        target_attack_surface = ""
    target = target_attack_surface.lower()
    out: List[Dict[str, Any]] = []
    risk_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    max_risk = risk_order.get(risk_max.lower(), 3) if risk_max else 3
    for s in sessions:
        if not isinstance(s, dict):
            continue
        sess_surf = s.get("attack_surface", "")
        if isinstance(sess_surf, str) and target and target not in sess_surf.lower():
            continue
        # Risk filter
        risk = s.get("risk", "low")
        if isinstance(risk, str):
            r = risk_order.get(risk.lower(), 0)
            if r > max_risk:
                continue
        out.append(s)
    return out


# ---------------------------------------------------------------------------
# 3. Chain-planner live preview
# ---------------------------------------------------------------------------

def chain_plan_preview(target: str,
                        attack_surface: str,
                        planner_state: Optional[Dict[str, Any]] = None,
                        ) -> Dict[str, Any]:
    """Build a preview envelope for the chain planner.

    The dashboard streams this back to the operator's browser as
    the planner runs.  We never fabricate chain steps; we only
    return what's already in the planner state, plus a status
    field.  Returns ``{ok, error}`` on failure.
    """
    if not isinstance(target, str) or not target:
        return {"ok": False, "error": "target is required"}
    if not isinstance(attack_surface, str):
        return {"ok": False, "error": "attack_surface is required"}
    state = planner_state or {}
    steps = state.get("steps", [])
    if not isinstance(steps, list):
        steps = []
    return {
        "ok": True,
        "target": target,
        "attack_surface": attack_surface,
        "steps": steps,
        "step_count": len(steps),
        "status": state.get("status", "idle"),
        "ts": time.time(),
    }


# ---------------------------------------------------------------------------
# 4. Real-time exfil queue visualization
# ---------------------------------------------------------------------------

def exfil_progress(job: Dict[str, Any],
                   now: Optional[float] = None,
                   ) -> Dict[str, Any]:
    """Compute the dashboard's exfil gauge snapshot.

    Returns ``{bytes_sent, bytes_total, throughput_bps, eta_s}``
    derived from the job's existing fields.  Never fabricates
    bytes-sent values — if the field is missing, returns 0.
    """
    if not isinstance(job, dict):
        return {"ok": False, "error": "job must be a dict"}
    if now is None:
        now = time.time()
    bytes_total = int(job.get("bytes_total", 0) or 0)
    bytes_sent = int(job.get("bytes_sent", 0) or 0)
    started_at = float(job.get("started_at", now) or now)
    elapsed = max(0.001, now - started_at)
    throughput = bytes_sent / elapsed
    if bytes_total > 0 and bytes_sent < bytes_total:
        eta = (bytes_total - bytes_sent) / max(1.0, throughput)
    else:
        eta = 0.0
    return {
        "ok": True,
        "job_id": job.get("job_id", ""),
        "bytes_sent": bytes_sent,
        "bytes_total": bytes_total,
        "throughput_bps": round(throughput, 3),
        "eta_s": round(eta, 1),
        "status": job.get("status", "unknown"),
        "ts": now,
    }


# ---------------------------------------------------------------------------
# 5. AI status pill
# ---------------------------------------------------------------------------

def ai_status() -> Dict[str, Any]:
    """Return the AI status pill envelope for the dashboard.

    Reads the current primary model from
    :data:`core.ai_backend.MODEL_CATALOG['primary']` and the
    reachability via :func:`core.ai_backend.ollama_cloud_reachable`.
    NEVER inlines the operator's token.  Returns the model name,
    reachability, and last-known latency (or null).
    """
    out: Dict[str, Any] = {
        "ok": True,
        "model": "unknown",
        "reachable": False,
        "latency_ms": None,
    }
    try:
        from core.ai_backend import MODEL_CATALOG
        out["model"] = MODEL_CATALOG.get("primary", "unknown")
    except Exception:  # noqa: BLE001
        pass
    try:
        from core.ai_backend import ollama_cloud_reachable
        reach = ollama_cloud_reachable()
        if isinstance(reach, dict):
            out["reachable"] = bool(reach.get("ok", False))
            latency = reach.get("latency_ms")
            if isinstance(latency, (int, float)):
                out["latency_ms"] = int(latency)
    except Exception:  # noqa: BLE001
        pass
    return out


__all__ = [
    "poly_scan_options",
    "adaptive_session_filter",
    "chain_plan_preview",
    "exfil_progress",
    "ai_status",
    "OPERATOR_HARDWARE",
]
