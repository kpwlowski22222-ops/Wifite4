"""core.live_edit.log — JSONL audit log of every patch (apply, refuse, revert).

The log is a single JSONL file. Each line is one event with a timestamp.
"""
from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from typing import Any


_LOG_PATH = Path(__file__).parent / "overlays" / "_log.json"
_OVERLAY_LOG: list[dict] = []
_lock = threading.Lock()


def _ensure_log() -> None:
    _LOG_PATH.parent.mkdir(parents=True, exist_ok=True)


def _append_log(entry: dict) -> None:
    with _lock:
        e = dict(entry)
        e.setdefault("ts", time.time())
        _OVERLAY_LOG.append(e)
        _ensure_log()
        try:
            with _LOG_PATH.open("a") as f:
                f.write(json.dumps(e, default=str) + "\n")
        except OSError:
            # log-write failure is non-fatal
            pass


def get_patch_log() -> list[dict]:
    """Return an in-memory copy of the patch log (most recent last)."""
    with _lock:
        return list(_OVERLAY_LOG)
