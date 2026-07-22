"""core.post_access_tui.rat_ext.exfil_queue — Phase 2.4 §B.8.

Read-only exfil queue + operator-initiated cancel. The dashboard
exposes:
  GET  /api/session/<sid>/exfil
      List jobs with id, channel, bytes_pending, status.
  POST /api/session/<sid>/exfil/<job_id>/cancel
      Operator-initiated cancel. The job is marked ``cancelled``
      in the session's exfil_pending_bytes and the chain planner
      stops the next retry tick.
"""
from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List, Optional


_VALID_CHANNELS = {"http", "https", "dns", "icmp", "smb",
                   "sftp", "tor", "websocket"}


def list_jobs(session: Optional[Dict[str, Any]] = None
              ) -> Dict[str, Any]:
    """List exfil jobs for the session."""
    session = session or {}
    raw = session.get("exfil_jobs") or []
    jobs: List[Dict[str, Any]] = []
    pending = 0
    for j in raw:
        if not isinstance(j, dict):
            continue
        ch = j.get("channel", "http")
        if ch not in _VALID_CHANNELS:
            ch = "http"
        bytes_pending = int(j.get("bytes_pending", 0) or 0)
        if j.get("status") != "cancelled":
            pending += bytes_pending
        jobs.append({
            "id": j.get("id") or j.get("job_id"),
            "channel": ch,
            "bytes_pending": bytes_pending,
            "bytes_total": j.get("bytes_total"),
            "status": j.get("status", "queued"),
            "queued_at": j.get("queued_at"),
            "last_error": j.get("last_error"),
        })
    return {
        "ok": True,
        "session_id": session.get("session_id") or session.get("id"),
        "jobs": jobs,
        "count": len(jobs),
        "total_pending_bytes": pending,
    }


def build_cancel_envelope(sid: str, job_id: str,
                          session: Optional[Dict[str, Any]] = None
                          ) -> Dict[str, Any]:
    """Build the cancel envelope. The actual cancel call lives
    in :mod:`core.post_exploit.runner_ext` (or the chain
    planner). The dashboard just records the intent + returns
    a verifiable envelope."""
    if not job_id:
        return {"ok": False, "error": "missing job_id"}
    session = session or {}
    raw = session.get("exfil_jobs") or []
    target: Optional[Dict[str, Any]] = None
    for j in raw:
        if not isinstance(j, dict):
            continue
        if (j.get("id") or j.get("job_id")) == job_id:
            target = j
            break
    if target is None:
        return {"ok": False, "error": f"job {job_id!r} not found"}
    return {
        "ok": True,
        "session_id": sid,
        "job_id": job_id,
        "action": "cancel_exfil",
        "cancelled_at": time.time(),
        "cancellation_token": uuid.uuid4().hex,
        "note": ("operator-initiated cancel; the chain planner "
                 "stops the next retry tick on the matching job_id"),
    }


__all__ = [
    "_VALID_CHANNELS",
    "list_jobs",
    "build_cancel_envelope",
]
