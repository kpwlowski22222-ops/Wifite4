"""core.post_access_tui.rat_ext.v3_enhancements — Phase 3 expansion T6.

Implements the 7 dashboard improvements the operator asked for.
Each improvement is a small, testable function that the WSGI app
wires into the route table.

1. **Capability search + filter** — `filter_sessions()` matches a
   query against tag/attack_surface/phase.
2. **Pagination on history/exfil/log** — `paginate_with_offset()`
   adds `?offset=` and `?since=ts` support.
3. **CSRF protection on POSTs** — `csrf_token_for()` /
   `verify_csrf()` generate + verify an HMAC token over sid+ts.
4. **Compact mode** — `is_compact_mode()` reads the `?compact=1`
   query param.
5. **Better 404 page** — `best_match_sid()` returns the closest
   matching sid by Levenshtein distance (≤2).
6. **WebSocket live tail** — `live_tail_lines()` reads the latest
   log + history rows for a session (HTTP-poll based; the
   browser opens `/api/session/<sid>/live_tail?since=ts`).
7. **Chain-planner integration** — `chain_plan_from_session()` builds
   a JSON envelope the chain planner can consume directly.

None of these functions ever fabricate data. If the inputs are
absent or malformed, they return safe defaults.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import time
from typing import Any, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# 1. Capability search + filter
# ---------------------------------------------------------------------------


def filter_sessions(
    sessions: List[Dict[str, Any]],
    query: str,
) -> List[Dict[str, Any]]:
    """Filter sessions by a free-text query.

    Matches against ``session_id``, ``target``, ``transport``,
    ``attack_surface`` (list/str), ``phase_hint``, and any of
    ``tags`` (list). Returns the matching subset (preserving order)
    or the original list if the query is empty.
    """
    q = (query or "").strip().lower()
    if not q:
        return list(sessions or [])
    out: List[Dict[str, Any]] = []
    for s in (sessions or []):
        if not isinstance(s, dict):
            continue
        haystack_parts: List[str] = []
        for k in ("session_id", "id", "target", "transport", "phase_hint"):
            v = s.get(k)
            if v is not None:
                haystack_parts.append(str(v).lower())
        asurf = s.get("attack_surface")
        if isinstance(asurf, list):
            haystack_parts.extend(str(x).lower() for x in asurf)
        elif isinstance(asurf, str):
            haystack_parts.append(asurf.lower())
        tags = s.get("tags") or []
        if isinstance(tags, list):
            haystack_parts.extend(str(t).lower() for t in tags)
        haystack = " ".join(haystack_parts)
        if q in haystack:
            out.append(s)
    return out


# ---------------------------------------------------------------------------
# 2. Pagination on history/exfil/log
# ---------------------------------------------------------------------------


def paginate_with_offset(
    rows: List[Dict[str, Any]],
    limit: int = 50,
    offset: int = 0,
) -> Dict[str, Any]:
    """Slice a list of rows with limit+offset.

    Returns ``{ok, rows, limit, offset, total, has_more}``."""
    if not isinstance(rows, list):
        rows = []
    try:
        limit = max(1, min(int(limit), 1000))
    except Exception:
        limit = 50
    try:
        offset = max(0, int(offset))
    except Exception:
        offset = 0
    total = len(rows)
    end = offset + limit
    page = rows[offset:end]
    return {
        "ok": True,
        "rows": page,
        "limit": limit,
        "offset": offset,
        "total": total,
        "has_more": end < total,
    }


def since_filter(
    rows: List[Dict[str, Any]],
    since_ts: Optional[float],
    ts_key: str = "ts",
) -> List[Dict[str, Any]]:
    """Return rows whose ``ts_key`` field is >= ``since_ts``."""
    if since_ts is None:
        return list(rows or [])
    out: List[Dict[str, Any]] = []
    for r in (rows or []):
        if not isinstance(r, dict):
            continue
        try:
            t = float(r.get(ts_key, 0) or 0)
        except Exception:
            continue
        if t >= since_ts:
            out.append(r)
    return out


# ---------------------------------------------------------------------------
# 3. CSRF protection on POSTs
# ---------------------------------------------------------------------------

# HMAC secret derived from the process start time + a constant.
# This is a per-process secret — good enough to prevent trivial CSRF
# from a hostile page in the same browser. For a production-grade
# deployment the operator would replace this with a constant from
# KFIOSA_CSRF_SECRET in the env.
_CSRF_SECRET = hashlib.sha256(
    f"kfiosa-csrf-{os.getpid()}-{time.time()}".encode("utf-8"),
).hexdigest().encode("utf-8")


def csrf_token_for(sid: str, ts: Optional[float] = None) -> str:
    """Generate a CSRF token for a session+ts pair.

    The token is an HMAC-SHA256 over ``sid || ts`` truncated to
    16 hex chars. The client must echo the token in the
    ``X-CSRF-Token`` header on POSTs.

    Format: ``"<int_ts>:<mac16>"`` (colon separator so the float
    timestamp string never collides with the HMAC bytes)."""
    sid = str(sid or "")
    ts_int = int(float(ts or time.time()))
    mac = hmac.new(_CSRF_SECRET, f"{sid}|{ts_int}".encode("utf-8"),
                   hashlib.sha256).hexdigest()
    return f"{ts_int}:{mac[:16]}"


def verify_csrf(sid: str, token: str,
                max_age_s: float = 600.0) -> Tuple[bool, str]:
    """Verify a CSRF token. Returns ``(ok, reason)``."""
    if not token or ":" not in token:
        return False, "missing or malformed token"
    ts_str, provided = token.split(":", 1)
    try:
        ts = int(ts_str)
    except ValueError:
        return False, "non-numeric timestamp"
    if abs(time.time() - ts) > max_age_s:
        return False, "token expired"
    expected = csrf_token_for(sid, ts=ts).split(":", 1)[1]
    if not hmac.compare_digest(provided, expected):
        return False, "token mismatch"
    return True, "ok"


# ---------------------------------------------------------------------------
# 4. Compact mode
# ---------------------------------------------------------------------------


def is_compact_mode(qs: Dict[str, str]) -> bool:
    """Return True if the query string requests compact mode."""
    return (qs.get("compact") or "").strip() in ("1", "true", "yes")


# ---------------------------------------------------------------------------
# 5. Better 404 page — Levenshtein ≤ 2 nearest sids
# ---------------------------------------------------------------------------


def _levenshtein(a: str, b: str) -> int:
    """Tiny Levenshtein implementation (O(|a|*|b|) memory+time)."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            cur[j] = min(
                cur[j - 1] + 1,        # insert
                prev[j] + 1,           # delete
                prev[j - 1] + cost,    # substitute
            )
        prev = cur
    return prev[-1]


def best_match_sid(query: str, candidates: List[str],
                   max_dist: int = 2) -> List[Tuple[str, int]]:
    """Return ``[(candidate, distance), ...]`` for candidates within
    ``max_dist`` of the query, sorted by distance ascending."""
    if not query or not candidates:
        return []
    out: List[Tuple[str, int]] = []
    for c in candidates:
        if not isinstance(c, str):
            continue
        d = _levenshtein(query, c)
        if d <= max_dist:
            out.append((c, d))
    out.sort(key=lambda t: (t[1], t[0]))
    return out[:5]  # cap to top 5


# ---------------------------------------------------------------------------
# 6. WebSocket-ish live tail (HTTP-poll; the browser hits the
#    endpoint repeatedly with an incrementing `since` param)
# ---------------------------------------------------------------------------


def live_tail_lines(
    log_rows: List[Dict[str, Any]],
    history_rows: List[Dict[str, Any]],
    since_ts: Optional[float] = None,
) -> Dict[str, Any]:
    """Return log + history rows newer than ``since_ts``.

    Used by ``/api/session/<sid>/live_tail?since=ts`` so the
    browser can poll without re-fetching the full set.

    The two lists are merged, sorted by ``ts`` ascending, and
    annotated with a ``source`` field so the browser can colour
    them differently.
    """
    merged: List[Dict[str, Any]] = []
    for r in (log_rows or []):
        if isinstance(r, dict):
            merged.append({**r, "source": "log"})
    for r in (history_rows or []):
        if isinstance(r, dict):
            merged.append({**r, "source": "history"})
    if since_ts is not None:
        merged = since_filter(merged, since_ts, ts_key="ts")
    merged.sort(key=lambda r: float(r.get("ts", 0) or 0))
    latest_ts = (merged[-1].get("ts") if merged else since_ts) or 0
    return {
        "ok": True,
        "lines": merged,
        "count": len(merged),
        "latest_ts": float(latest_ts) if latest_ts else 0.0,
    }


# ---------------------------------------------------------------------------
# 7. Chain-planner integration
# ---------------------------------------------------------------------------


def chain_plan_from_session(
    sess: Dict[str, Any],
    capability: str,
    chain_planner_runner: Optional[Any] = None,
) -> Dict[str, Any]:
    """Build a chain-plan envelope for a session + capability.

    If ``chain_planner_runner`` is supplied, it is called with
    ``(sess, capability)`` and its return value is wrapped in
    ``{ok, plan, source}``. Otherwise we synthesize a stub plan
    derived from the session's attack_surface + phase_hint — no
    fabrication of real CVEs / hashes / cleartext.

    The envelope is what the chain planner itself produces, so
    the dashboard can feed it directly into the next step.
    """
    if not isinstance(sess, dict):
        sess = {}
    cap = str(capability or "").strip()
    if not cap:
        return {"ok": False, "error": "missing capability"}
    if chain_planner_runner is not None:
        try:
            plan = chain_planner_runner(sess, cap)
            if isinstance(plan, dict):
                return {
                    "ok": True,
                    "sid": sess.get("session_id") or sess.get("id") or "",
                    "capability": cap,
                    "plan": plan,
                    "source": "chain_planner",
                }
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "error": f"planner error: {e}"}
    # Stub plan derived from session metadata only.
    asurf = sess.get("attack_surface")
    if isinstance(asurf, list):
        asurf_str = ",".join(str(x) for x in asurf)
    else:
        asurf_str = str(asurf or "")
    return {
        "ok": True,
        "sid": sess.get("session_id") or sess.get("id") or "",
        "capability": cap,
        "plan": {
            "steps": [
                {
                    "name": cap,
                    "attack_surface": asurf_str,
                    "phase_hint": str(sess.get("phase_hint") or ""),
                    "note": ("Stub step — install a chain_planner_runner "
                             "for real plan generation."),
                }
            ],
            "stub": True,
        },
        "source": "stub",
    }
