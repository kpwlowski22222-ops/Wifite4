"""core.post_access_tui.rat_ext.history — Phase 2.4 §B.4.

Per-session command history, JSONL-persisted to
``~/.kfiosa/rat_history/<sid>.jsonl`` (with ``os.umask(0o077)``
so the file is owner-readable only).

Endpoints:
  GET  /api/session/<sid>/history?limit=50&since=<ts>
  POST /api/session/<sid>/replay  (re-runs a stored command
        envelope; the original chain step's ACCEPT gate covers
        all replays — no re-prompt)
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


HISTORY_DIR = Path.home() / ".kfiosa" / "rat_history"


def _ensure_dir() -> None:
    HISTORY_DIR.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(HISTORY_DIR, 0o700)
    except Exception:  # noqa: BLE001
        pass


def _path_for(sid: str) -> Path:
    # Sanitize sid for the filesystem
    safe = "".join(c for c in sid if c.isalnum() or c in "-_.") or "default"
    return HISTORY_DIR / f"{safe}.jsonl"


def append_event(sid: str, event: Dict[str, Any]) -> Dict[str, Any]:
    """Append one event to the session's history file.

    The file is created with mode 0o600 (owner-only). The
    write is line-buffered JSON; one event per line."""
    _ensure_dir()
    path = _path_for(sid)
    event = dict(event)
    event.setdefault("ts", time.time())
    line = json.dumps(event, default=str) + "\n"
    # Use append mode + umask to keep the file owner-only
    prev_umask = os.umask(0o077)
    try:
        with open(path, "a") as f:
            f.write(line)
    finally:
        os.umask(prev_umask)
    try:
        os.chmod(path, 0o600)
    except Exception:  # noqa: BLE001
        pass
    return {"ok": True, "path": str(path)}


def read_history(sid: str, limit: int = 50, since_ts: Optional[float] = None
                 ) -> List[Dict[str, Any]]:
    """Read the last ``limit`` events for ``sid`` after ``since_ts``."""
    path = _path_for(sid)
    if not path.exists():
        return []
    events: List[Dict[str, Any]] = []
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    e = json.loads(line)
                except Exception:  # noqa: BLE001
                    continue
                ts = float(e.get("ts", 0) or 0)
                if since_ts is not None and ts <= since_ts:
                    continue
                events.append(e)
    except Exception:  # noqa: BLE001
        return []
    return events[-limit:]


def paginate(sid: str, limit: int = 50, since_ts: Optional[float] = None
             ) -> Dict[str, Any]:
    """Return the paginated history for the GET endpoint."""
    events = read_history(sid, limit=limit, since_ts=since_ts)
    return {
        "ok": True,
        "session_id": sid,
        "events": events,
        "count": len(events),
        "next_since_ts": (events[-1]["ts"]
                          if events else since_ts),
    }


def build_replay_envelope(sid: str, event: Dict[str, Any]
                          ) -> Dict[str, Any]:
    """Build the envelope that the chain step consumes when the
    operator clicks 'Replay' on a history row.

    The original step's ACCEPT gate covers all replays — no
    re-prompt. The envelope is a real ChainStep-like dict so
    the chain planner can re-run it."""
    if not event or not isinstance(event, dict):
        return {"ok": False, "error": "missing or empty event payload"}
    return {
        "ok": True,
        "action": "replay_history",
        "session_id": sid,
        "replayed_at": time.time(),
        "original": event,
        "note": ("replay uses the original chain step's ACCEPT "
                 "gate; no re-prompt"),
    }


__all__ = [
    "HISTORY_DIR",
    "append_event",
    "read_history",
    "paginate",
    "build_replay_envelope",
]
