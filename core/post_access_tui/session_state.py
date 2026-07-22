"""core.post_access_tui.session_state — active-session descriptor + audit log.

The SessionState is a small dataclass that carries everything the
PostAccessRunner needs to talk to a single active session: the meterpreter
session_id (when the access came via msf), the captured creds (when
access came via PSK/plaintext), the target IP/hostname, the transport
(msfconsole / ssh / scp / local) and a started_at timestamp.

The JSONL audit log ``_log.json`` records every operator action
(ACCEPT/CANCEL, the command, the exit code). Same shape as
``core.tool_installer.log`` and ``core.live_edit.log``.
"""
from __future__ import annotations

import base64
import dataclasses
import json
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional


#: Path to the JSONL audit log (operator-auditable).
_LOG_PATH: Path = Path(__file__).parent / "_log.json"
_LOG: List[Dict[str, Any]] = []
_LOCK = threading.Lock()


#: Recognized transport values.
TRANSPORT_MSF = "msfconsole"
TRANSPORT_SSH = "ssh"
TRANSPORT_LOCAL = "local"
TRANSPORT_UNKNOWN = "unknown"


def _now() -> float:
    """Local now() (avoids dataclass.field defaulting to time.time in
    the test where we monkey-patch time.time)."""
    return time.time()


def _b64_encode(s: str) -> str:
    """Encode a string as base64 (utf-8). Never raises — non-utf-8
    bytes are replaced via ``errors='replace'``."""
    if not isinstance(s, str):
        return ""
    return base64.b64encode(s.encode("utf-8", errors="replace")).decode("ascii")


def _b64_decode(s: str) -> str:
    """Decode a base64 string back to a string. Returns "" on any error
    (malformed, non-base64, etc.) — never raises."""
    if not isinstance(s, str) or not s:
        return ""
    try:
        return base64.b64decode(s.encode("ascii"), validate=False).decode(
            "utf-8", errors="replace"
        )
    except Exception:  # noqa: BLE001
        return ""


@dataclasses.dataclass
class SessionState:
    """The active session the post-access TUI is talking to.

    Attributes:
        session_id:  meterpreter session id (int/str) when transport
                     is ``msfconsole``; ``None`` for ssh/local.
        target:      target IP/hostname (str); "" if unknown.
        creds_b64:   base64-encoded captured creds (PSK/password/pin);
                     empty string when no creds.
        transport:   one of TRANSPORT_MSF / TRANSPORT_SSH / TRANSPORT_LOCAL /
                     TRANSPORT_UNKNOWN.
        started_at:  unix timestamp the session was captured.
        note:        free-text note (e.g. "captured via PMKID on BSSID X").
    """
    session_id: Optional[Any] = None
    target: str = ""
    creds_b64: str = ""
    transport: str = TRANSPORT_UNKNOWN
    started_at: float = dataclasses.field(default_factory=_now)
    note: str = ""

    # -- (de)serialization (JSON-safe) ----------------------------------
    def to_dict(self) -> Dict[str, Any]:
        d = dataclasses.asdict(self)
        # dataclasses.asdict already produced a JSON-safe dict (str/int/float/None)
        return d

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "SessionState":
        if not isinstance(d, dict):
            return cls()
        return cls(
            session_id=d.get("session_id"),
            target=str(d.get("target", "") or ""),
            creds_b64=str(d.get("creds_b64", "") or ""),
            transport=str(d.get("transport", TRANSPORT_UNKNOWN) or TRANSPORT_UNKNOWN),
            started_at=float(d.get("started_at", 0.0) or 0.0),
            note=str(d.get("note", "") or ""),
        )

    # -- helper views ---------------------------------------------------
    def has_session(self) -> bool:
        """True if we have a msf session id OR creds (ssh-able)."""
        return bool(self.session_id) or bool(self.creds_b64)

    def creds_plain(self) -> str:
        """Return creds (decoded). Returns "" if no creds stored."""
        return _b64_decode(self.creds_b64)

    def transport_label(self) -> str:
        return {
            TRANSPORT_MSF: "msfconsole",
            TRANSPORT_SSH: "ssh",
            TRANSPORT_LOCAL: "local",
        }.get(self.transport, self.transport or "unknown")

    @classmethod
    def from_access_report(cls, access: Optional[Dict[str, Any]]) -> "SessionState":
        """Build a SessionState from a ``report["access"]`` dict.
        ``access`` may be ``None``; returns an empty SessionState in
        that case (caller must check ``has_session()``)."""
        if not isinstance(access, dict):
            return cls()
        sid = access.get("session_id")
        creds = access.get("creds")
        if creds is None:
            creds_b64 = ""
        else:
            creds_b64 = _b64_encode(str(creds))
        transport = TRANSPORT_MSF if sid else (
            TRANSPORT_SSH if creds_b64 else TRANSPORT_UNKNOWN
        )
        return cls(
            session_id=sid,
            target="",  # the orchestrator fills this from seed["target"]
            creds_b64=creds_b64,
            transport=transport,
            started_at=_now(),
        )


# ---------------------------------------------------------------------------
# JSONL audit log (mirrors core.tool_installer.log / core.live_edit.log)
# ---------------------------------------------------------------------------

def _ensure_log() -> None:
    _LOG_PATH.parent.mkdir(parents=True, exist_ok=True)


def _append_log(entry: Dict[str, Any]) -> None:
    """Append one entry to the JSONL audit log. Thread-safe. Never
    raises — log write failures are swallowed (the operator still sees
    the in-memory log)."""
    with _LOCK:
        e = dict(entry)
        e.setdefault("ts", _now())
        _LOG.append(e)
        _ensure_log()
        try:
            with _LOG_PATH.open("a") as f:
                f.write(json.dumps(e, default=str) + "\n")
        except OSError:
            pass


def get_log() -> List[Dict[str, Any]]:
    """Return a copy of the in-memory log (read-only)."""
    with _LOCK:
        return list(_LOG)


def get_log_path() -> Path:
    """Return the path to the JSONL log file."""
    return _LOG_PATH
