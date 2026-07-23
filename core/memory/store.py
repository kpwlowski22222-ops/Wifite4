"""Working memory store — markdown notes + index file (local-first).

Inspired by holaOS durable memory, reimplemented for KFIOSA engagements.
Never stores raw API keys/tokens (redacted). Never fabricates findings.
"""
from __future__ import annotations

import json
import os
import re
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

_REDACT_ENV_KEYS = (
    "OLLAMA_CLOUD_TOKEN", "NVD_API_KEY", "KISMET_API_KEY", "SHODAN_API_KEY",
    "GROQ_API_KEY", "DEEPSEEK_API_KEY", "GEMINI_API_KEY", "HF_TOKEN",
    "NVIDIA_API_KEY", "GROK_API_KEY", "XAI_API_KEY", "HIBP_API_KEY",
    "RAT_DASHBOARD_TOKEN", "MSF_PASSWORD",
)


def memory_enabled() -> bool:
    raw = (os.environ.get("KFIOSA_MEMORY") or "1").strip().lower()
    return raw not in ("0", "false", "no", "off")


def memory_root() -> Path:
    raw = (os.environ.get("KFIOSA_MEMORY_ROOT") or "").strip()
    if raw:
        return Path(raw).expanduser()
    return Path(__file__).resolve().parents[2] / "data" / "memory"


def _redact(text: str) -> str:
    out = str(text)
    for key in _REDACT_ENV_KEYS:
        val = os.environ.get(key) or ""
        if len(val) >= 8 and val in out:
            out = out.replace(val, "***")
    # common key patterns
    out = re.sub(r"(?i)(api[_-]?key|token|password|secret)\s*[:=]\s*\S+",
                 r"\1=***", out)
    return out


def _index_path() -> Path:
    return memory_root() / "index.jsonl"


def ingest(
    kind: str,
    text: str,
    *,
    domain: str = "",
    target_key: str = "",
    tags: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Append a memory note (markdown + index line)."""
    if not memory_enabled():
        return {"ok": True, "skipped": "memory_disabled"}
    root = memory_root()
    root.mkdir(parents=True, exist_ok=True)
    kind = (kind or "note").strip().lower()
    body = _redact((text or "").strip())
    if not body:
        return {"ok": False, "error": "empty memory text"}
    mid = uuid.uuid4().hex[:12]
    ts = time.time()
    day = time.strftime("%Y-%m-%d", time.localtime(ts))
    md_dir = root / "notes" / day
    md_dir.mkdir(parents=True, exist_ok=True)
    md_path = md_dir / f"{mid}.md"
    header = (
        f"# {kind}\n\n"
        f"- id: `{mid}`\n"
        f"- domain: `{domain or '-'}`\n"
        f"- target_key: `{target_key or '-'}`\n"
        f"- ts: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ts))}\n\n"
    )
    md_path.write_text(header + body + "\n", encoding="utf-8")
    rec = {
        "id": mid,
        "kind": kind,
        "domain": domain or "",
        "target_key": target_key or "",
        "tags": list(tags or []),
        "path": str(md_path.relative_to(root)) if str(md_path).startswith(str(root)) else str(md_path),
        "text": body[:2000],
        "ts": ts,
    }
    with open(_index_path(), "a", encoding="utf-8") as fh:
        fh.write(json.dumps(rec, default=str) + "\n")
    # Best-effort SQL mirror
    try:
        from core.db import sqlstore
        sqlstore.init()
        sqlstore.append_history(
            f"mem-{mid}", "memory_ingest",
            {"kind": kind, "domain": domain, "target_key": target_key,
             "text": body[:500]},
        )
    except Exception:
        pass
    return {"ok": True, "id": mid, "path": str(md_path)}


def list_notes(
    *,
    domain: str = "",
    target_key: str = "",
    kind: str = "",
    limit: int = 50,
) -> List[Dict[str, Any]]:
    path = _index_path()
    if not path.is_file():
        return []
    rows: List[Dict[str, Any]] = []
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception:
        return []
    for line in reversed(lines):
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except Exception:
            continue
        if domain and rec.get("domain") != domain:
            continue
        if target_key and rec.get("target_key") != target_key:
            continue
        if kind and rec.get("kind") != kind:
            continue
        rows.append(rec)
        if len(rows) >= limit:
            break
    return rows


def clear_memory(*, confirm: bool = False) -> Dict[str, Any]:
    """Delete index only unless confirm=True (then wipe notes dir)."""
    if not confirm:
        return {"ok": False, "error": "pass confirm=True to wipe"}
    root = memory_root()
    idx = _index_path()
    n = 0
    if idx.is_file():
        idx.unlink()
        n += 1
    notes = root / "notes"
    if notes.is_dir():
        for p in notes.rglob("*"):
            if p.is_file():
                try:
                    p.unlink()
                    n += 1
                except Exception:
                    pass
    return {"ok": True, "removed_files": n}
