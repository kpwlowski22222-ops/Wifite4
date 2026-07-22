"""core.post_access_tui.rat_ext.sse — Phase 2.4 §B.3.

Server-Sent Events stream + HTTP-polling fallback. The dashboard
exposes ``GET /stream/<sid>`` (text/event-stream, 30s heartbeat)
and a back-compat ``GET /stream/<sid>/log?since=<ts>`` (JSONL
poll) for clients that don't support SSE.

Both endpoints read from a session's ``context.log_buffer`` and
``context.step_envelope_history`` (whatever the chain step
already maintains). They never block the WSGI thread; each
request is a one-shot snapshot.
"""
from __future__ import annotations

import json
import time
from typing import Any, Dict, Iterable, List, Optional, Tuple


# Heartbeat interval — keeps proxies happy
HEARTBEAT_S = 30


def _format_sse(event: str, payload: Dict[str, Any]) -> str:
    """Format one SSE event. ``payload`` is serialised as JSON."""
    data = json.dumps(payload, default=str)
    return f"event: {event}\ndata: {data}\n\n"


def build_heartbeat() -> str:
    """Build a single heartbeat comment line for SSE keep-alive."""
    return ":heartbeat\n\n"


def build_sse_envelope(events: Iterable[Tuple[str, Dict[str, Any]]],
                       start_ts: float, end_ts: Optional[float] = None
                       ) -> str:
    """Build a text/event-stream body for ``events``.

    A heartbeat is appended every ``HEARTBEAT_S`` so the
    connection doesn't time out at the proxy. The body ends
    with a ``done`` event so the client knows the snapshot
    is complete.
    """
    out: List[str] = []
    last_heartbeat = time.time()
    for event, payload in events:
        out.append(_format_sse(event, payload))
        now = time.time()
        if now - last_heartbeat > HEARTBEAT_S:
            out.append(":heartbeat\n\n")
            last_heartbeat = now
    out.append(_format_sse("done", {
        "ts": end_ts or time.time(),
        "start_ts": start_ts,
    }))
    return "".join(out)


def stream_session(sid: str, session_meta: Optional[Dict[str, Any]] = None,
                   since_ts: Optional[float] = None
                   ) -> Tuple[str, str]:
    """Build the SSE body for ``sid``.

    Returns ``(content_type, body)``. The body is a complete
    snapshot of the session's log + step envelopes since
    ``since_ts`` (or all of them if None).
    """
    events: List[Tuple[str, Dict[str, Any]]] = []
    if session_meta is None:
        session_meta = {}
    log_buffer = session_meta.get("log_buffer") or []
    step_history = session_meta.get("step_envelope_history") or []
    now = time.time()
    for entry in log_buffer:
        ts = float(entry.get("ts", 0) or 0)
        if since_ts and ts <= since_ts:
            continue
        events.append(("log", {
            "ts": ts,
            "kind": entry.get("kind", "log"),
            "msg": entry.get("msg", ""),
        }))
    for entry in step_history:
        ts = float(entry.get("ts", 0) or 0)
        if since_ts and ts <= since_ts:
            continue
        events.append(("step", {
            "ts": ts,
            "name": entry.get("name") or entry.get("desc") or "step",
            "ok": entry.get("ok"),
            "risk": entry.get("risk"),
        }))
    body = build_sse_envelope(events, start_ts=now, end_ts=now)
    return "text/event-stream; charset=utf-8", body


def poll_session_log(sid: str, session_meta: Optional[Dict[str, Any]] = None,
                     since_ts: Optional[float] = None,
                     limit: int = 200
                     ) -> Tuple[str, str]:
    """JSONL fallback. Returns ``(content_type, body)``."""
    if session_meta is None:
        session_meta = {}
    log_buffer = session_meta.get("log_buffer") or []
    out: List[str] = []
    sent = 0
    for entry in log_buffer:
        ts = float(entry.get("ts", 0) or 0)
        if since_ts and ts <= since_ts:
            continue
        out.append(json.dumps({
            "ts": ts,
            "kind": entry.get("kind", "log"),
            "msg": entry.get("msg", ""),
        }, default=str))
        sent += 1
        if sent >= limit:
            break
    if not out:
        out.append(json.dumps({"ts": time.time(), "kind": "heartbeat"}))
    return "application/x-ndjson; charset=utf-8", "\n".join(out) + "\n"


__all__ = [
    "HEARTBEAT_S",
    "build_heartbeat",
    "build_sse_envelope",
    "stream_session",
    "poll_session_log",
]
