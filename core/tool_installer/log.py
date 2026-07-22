"""core.tool_installer.log — JSONL audit log for installs."""
from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from typing import Any


_LOG_PATH = Path(__file__).parent / "_log.json"
_LOG: list[dict] = []
_lock = threading.Lock()


def _ensure_log() -> None:
    _LOG_PATH.parent.mkdir(parents=True, exist_ok=True)


def _append_log(entry: dict) -> None:
    with _lock:
        e = dict(entry)
        e.setdefault("ts", time.time())
        _LOG.append(e)
        _ensure_log()
        try:
            with _LOG_PATH.open("a") as f:
                f.write(json.dumps(e, default=str) + "\n")
        except OSError:
            pass


def list_install_log() -> list[dict]:
    with _lock:
        return list(_LOG)
