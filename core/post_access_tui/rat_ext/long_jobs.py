#!/usr/bin/env python3
"""Long-running people/website jobs for the Flask dashboard.

Stores job JSON under ``~/.kfiosa/rat_jobs/`` (override with
``KFIOSA_RAT_JOBS``). Never fabricates results — status only reflects
what the OSINT/web pipeline actually wrote.
"""
from __future__ import annotations

import json
import os
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional


def jobs_dir() -> Path:
    root = Path(
        os.environ.get("KFIOSA_RAT_JOBS")
        or (Path.home() / ".kfiosa" / "rat_jobs")
    )
    root.mkdir(parents=True, exist_ok=True)
    return root


def _write(job: Dict[str, Any]) -> Path:
    jid = job.get("id") or uuid.uuid4().hex[:12]
    job["id"] = jid
    job.setdefault("updated_at", time.time())
    path = jobs_dir() / f"{jid}.json"
    path.write_text(json.dumps(job, ensure_ascii=False, default=str), encoding="utf-8")
    return path


def _read(path: Path) -> Dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def enqueue_people_job(
    query: str,
    *,
    status: str = "queued",
    report: Any = None,
    meta: Optional[Dict[str, Any]] = None,
) -> str:
    job = {
        "id": uuid.uuid4().hex[:12],
        "kind": "people",
        "label": f"People: {query}",
        "query": query,
        "status": status,
        "created_at": time.time(),
        "updated_at": time.time(),
        "report": report if isinstance(report, dict) else None,
        "meta": meta or {},
        "achieved": ["osint_profile"] if status in ("done", "running", "attached") else [],
        "transport": "people",
        "attack_surface": "people",
    }
    _write(job)
    return job["id"]


def enqueue_website_session(
    url: str,
    *,
    status: str = "attached",
    report: Any = None,
    meta: Optional[Dict[str, Any]] = None,
) -> str:
    job = {
        "id": uuid.uuid4().hex[:12],
        "kind": "website",
        "label": f"Site: {url}",
        "url": url,
        "query": url,
        "status": status,
        "created_at": time.time(),
        "updated_at": time.time(),
        "report": report if isinstance(report, dict) else None,
        "meta": meta or {},
        "achieved": ["web_session"] if status in ("attached", "done", "running") else [],
        "transport": "website",
        "attack_surface": "website",
    }
    _write(job)
    return job["id"]


def update_job(job_id: str, **fields: Any) -> Optional[Dict[str, Any]]:
    path = jobs_dir() / f"{job_id}.json"
    if not path.is_file():
        return None
    job = _read(path)
    job.update(fields)
    job["updated_at"] = time.time()
    _write(job)
    return job


def list_jobs(
    kind: Optional[str] = None,
    *,
    limit: int = 100,
) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for p in sorted(jobs_dir().glob("*.json"), key=lambda x: x.stat().st_mtime, reverse=True):
        j = _read(p)
        if not j:
            continue
        if kind and j.get("kind") != kind:
            continue
        out.append(j)
        if len(out) >= limit:
            break
    return out


def jobs_as_sessions(kind: Optional[str] = None) -> List[Dict[str, Any]]:
    """Map long jobs to session-shaped dicts for RAT UI tabs."""
    sessions = []
    for j in list_jobs(kind=kind):
        sessions.append({
            "id": j.get("id"),
            "session_id": j.get("id"),
            "kind": j.get("kind"),
            "transport": j.get("transport") or j.get("kind"),
            "attack_surface": j.get("attack_surface") or j.get("kind"),
            "label": j.get("label"),
            "host": j.get("url") or j.get("query"),
            "status": j.get("status"),
            "achieved": list(j.get("achieved") or []),
            "created_at": j.get("created_at"),
            "updated_at": j.get("updated_at"),
            "meta": j.get("meta") or {},
        })
    return sessions
