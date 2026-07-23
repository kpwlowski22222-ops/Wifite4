"""core.post_access_tui.rat_ext.v5_enhancements — Flask dashboard UX upgrade.

Adds operator-facing improvements on top of v3/v4:

1. **System health** — AI + SQL + scan limits + process uptime
2. **Session summary cards** — counts by kind / risk / access
3. **Capability response formatter** — human drawer text (no secrets)
4. **Live refresh config** — poll intervals for the browser shell
5. **Keyboard shortcuts** — documented binding map for the UI

Never fabricates sessions, credentials, or scan results.
"""
from __future__ import annotations

import os
import time
from typing import Any, Dict, List, Optional

_STARTED_AT = time.time()


def dashboard_health(
    sessions: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Aggregate health for the dashboard header / status page.

    Honest probes only — missing SQL or Ollama → reachable=false.
    """
    out: Dict[str, Any] = {
        "ok": True,
        "uptime_s": round(time.time() - _STARTED_AT, 1),
        "sessions": len(sessions or []),
        "ai": {},
        "sql": {"ok": False},
        "scan": {},
        "bind": {
            "host": os.environ.get("RAT_DASHBOARD_HOST", "127.0.0.1"),
            "port": os.environ.get("RAT_DASHBOARD_PORT", "auto"),
        },
        "model": "rat-dashboard-v5",
        "ts": time.time(),
    }
    try:
        from . import v4_enhancements as _v4
        out["ai"] = _v4.ai_status()
    except Exception as e:  # noqa: BLE001
        out["ai"] = {"ok": False, "error": str(e)[:120]}
    try:
        from core.db import sqlstore
        h = sqlstore.health() if hasattr(sqlstore, "health") else {}
        out["sql"] = h if isinstance(h, dict) else {"ok": bool(h)}
    except Exception as e:  # noqa: BLE001
        out["sql"] = {"ok": False, "error": str(e)[:120]}
    try:
        from core.scanners.scan_limits import (
            DEFAULT_BLE_SCAN_S,
            DEFAULT_WIFI_SCAN_S,
            MAX_SCAN_S,
            ble_scan_s,
            wifi_scan_s,
        )
        out["scan"] = {
            "wifi_default_s": wifi_scan_s(None),
            "ble_default_s": ble_scan_s(None),
            "max_s": MAX_SCAN_S,
            "catalog_wifi_default": DEFAULT_WIFI_SCAN_S,
            "catalog_ble_default": DEFAULT_BLE_SCAN_S,
            "note": "long-range multi-band WiFi + long BLE discovery",
        }
    except Exception as e:  # noqa: BLE001
        out["scan"] = {"error": str(e)[:120]}
    return out


def session_summary(sessions: Optional[List[Dict[str, Any]]] = None
                    ) -> Dict[str, Any]:
    """Counts for the dashboard stats strip."""
    by_kind: Dict[str, int] = {}
    by_risk: Dict[str, int] = {}
    with_access = 0
    for s in sessions or []:
        if not isinstance(s, dict):
            continue
        kind = str(
            s.get("kind") or s.get("transport") or "unknown"
        ).lower()
        by_kind[kind] = by_kind.get(kind, 0) + 1
        risk = str(s.get("risk") or "read").lower()
        by_risk[risk] = by_risk.get(risk, 0) + 1
        ach = s.get("achieved") or []
        if ach or s.get("access_gained"):
            with_access += 1
    return {
        "ok": True,
        "total": len(sessions or []),
        "by_kind": by_kind,
        "by_risk": by_risk,
        "with_access": with_access,
        "model": "rat-dashboard-v5",
    }


def format_capability_result(result: Any) -> Dict[str, Any]:
    """Shape a capability runner result for the AJAX drawer.

    Strips obvious secret keys; never invents success data.
    """
    if not isinstance(result, dict):
        return {
            "ok": False,
            "error": "non-dict result",
            "pretty": str(result)[:2000],
        }
    scrubbed = {}
    for k, v in result.items():
        kl = str(k).lower()
        if any(x in kl for x in (
            "password", "secret", "token", "api_key", "authorization",
            "hash", "ntlm", "cleartext",
        )):
            scrubbed[k] = "[redacted]"
        else:
            scrubbed[k] = v
    ok = bool(scrubbed.get("ok", True))
    err = scrubbed.get("error") or ""
    import json
    try:
        pretty = json.dumps(scrubbed, indent=2, default=str)[:12000]
    except Exception:  # noqa: BLE001
        pretty = str(scrubbed)[:12000]
    return {
        "ok": ok,
        "error": err or None,
        "pretty": pretty,
        "model": "rat-dashboard-v5",
    }


def live_refresh_config() -> Dict[str, Any]:
    """Browser poll intervals (ms) — tunable via env."""
    def _ms(name: str, default: int) -> int:
        raw = (os.environ.get(name) or "").strip()
        try:
            v = int(raw) if raw else default
        except ValueError:
            v = default
        return max(1000, min(v, 120_000))

    return {
        "ok": True,
        "ai_status_ms": _ms("KFIOSA_DASH_AI_POLL_MS", 15000),
        "attack_state_ms": _ms("KFIOSA_DASH_STATE_POLL_MS", 8000),
        "health_ms": _ms("KFIOSA_DASH_HEALTH_POLL_MS", 20000),
        "model": "rat-dashboard-v5",
    }


def keyboard_shortcuts() -> Dict[str, str]:
    """Documented shortcuts rendered in the UI help panel."""
    return {
        "/": "Focus session filter",
        "j / k": "Next / previous session card",
        "Enter": "Open first capability on focused card",
        "Esc": "Close output drawer",
        "?": "Toggle this help",
        "r": "Refresh attack-state pills",
        "1": "Jump to Wi‑Fi filter",
        "2": "Jump to BLE filter",
        "3": "Jump to Host filter",
        "0": "Show all sessions",
    }


def empty_state_html() -> str:
    """Friendly empty roster message (HTML fragment)."""
    return (
        "<div class='empty'>"
        "<h2>No active sessions</h2>"
        "<p>Gain access from the Wi‑Fi / BLE chain (ACCEPT-gated). "
        "This dashboard then unlocks only the capabilities that were "
        "<em>actually earned</em> — nothing is fabricated.</p>"
        "<ul>"
        "<li>Long-range scans: multi-band Wi‑Fi + extended BLE discovery</li>"
        "<li>AI pill (header) shows Ollama / cloud reachability</li>"
        "<li>Press <kbd>?</kbd> for keyboard shortcuts</li>"
        "</ul>"
        "<p class='meta'><a href='/api/v5/health'>System health JSON</a> · "
        "<a href='/api/v4/ai_status'>AI status</a> · "
        "<a href='/api/attack_state'>Attack state</a></p>"
        "</div>"
    )


__all__ = [
    "dashboard_health",
    "session_summary",
    "format_capability_result",
    "live_refresh_config",
    "keyboard_shortcuts",
    "empty_state_html",
]
