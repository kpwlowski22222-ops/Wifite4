"""core.post_access_tui.rat_ext.persistence_ui — Phase 2.4 §B.8.

Persistence manager view. The dashboard exposes:
  GET  /api/session/<sid>/persistence
      List installed persistence mechanisms.
  POST /api/session/<sid>/persistence/<mech_id>/remove
      Call :func:`poly_persistence_mechanism_drift(rollback=True)`
      to undo the mechanism.
"""
from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List, Optional


def list_mechanisms(session: Optional[Dict[str, Any]] = None
                    ) -> Dict[str, Any]:
    """List installed persistence mechanisms for the session."""
    session = session or {}
    raw = session.get("persistence_mechanisms") or []
    mechs: List[Dict[str, Any]] = []
    for m in raw:
        if not isinstance(m, dict):
            continue
        mechs.append({
            "id": m.get("id") or m.get("mech_id") or m.get("name"),
            "name": m.get("name") or m.get("kind"),
            "target_os": m.get("target_os"),
            "installed_at": m.get("installed_at"),
            "status": m.get("status", "active"),
        })
    return {
        "ok": True,
        "session_id": session.get("session_id") or session.get("id"),
        "mechanisms": mechs,
        "count": len(mechs),
    }


def build_remove_envelope(sid: str, mech_id: str,
                          session: Optional[Dict[str, Any]] = None
                          ) -> Dict[str, Any]:
    """Build the remove envelope. The actual rollback call lives
    in :mod:`core.post_exploit.runner_ext` (or the chain
    planner). The dashboard just records the intent + returns
    a verifiable envelope."""
    if not mech_id:
        return {"ok": False, "error": "missing mech_id"}
    session = session or {}
    raw = session.get("persistence_mechanisms") or []
    target: Optional[Dict[str, Any]] = None
    for m in raw:
        if not isinstance(m, dict):
            continue
        if (m.get("id") or m.get("mech_id") or m.get("name")) == mech_id:
            target = m
            break
    if target is None:
        return {"ok": False, "error": f"mechanism {mech_id!r} not found"}
    return {
        "ok": True,
        "session_id": sid,
        "mech_id": mech_id,
        "action": "remove_persistence",
        "removed_at": time.time(),
        "rollback_token": uuid.uuid4().hex,
        "note": ("operator-initiated remove; the chain planner "
                 "calls poly_persistence_mechanism_drift("
                 "rollback=True) on the matching mech_id"),
    }


__all__ = [
    "list_mechanisms",
    "build_remove_envelope",
]
