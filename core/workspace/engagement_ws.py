"""Engagement workspaces (holaOS-inspired artifact layout).

Plans, findings, and decisions live as markdown under
``data/workspaces/<id>/`` so long engagements do not drown in the TUI log
and can be resumed later.
"""
from __future__ import annotations

import json
import os
import re
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional


def workspace_root() -> Path:
    raw = (os.environ.get("KFIOSA_WORKSPACE_ROOT") or "").strip()
    if raw:
        return Path(raw).expanduser()
    # repo-relative default
    root = Path(__file__).resolve().parents[2]
    return root / "data" / "workspaces"


def _slug(s: str, n: int = 24) -> str:
    s = re.sub(r"[^a-zA-Z0-9._-]+", "-", (s or "eng").strip())[:n]
    return s.strip("-") or "eng"


def create_workspace(
    domain: str,
    target: Optional[Dict[str, Any]] = None,
    *,
    label: str = "",
) -> Dict[str, Any]:
    """Create a new engagement workspace directory."""
    t = dict(target or {})
    label = label or str(
        t.get("ssid") or t.get("name") or t.get("query")
        or t.get("url") or t.get("bssid") or t.get("address") or "engagement"
    )
    wid = f"{_slug(domain, 12)}-{_slug(label, 16)}-{uuid.uuid4().hex[:8]}"
    base = workspace_root() / wid
    base.mkdir(parents=True, exist_ok=True)
    (base / "artifacts").mkdir(exist_ok=True)
    now = time.time()
    meta = {
        "id": wid,
        "domain": (domain or "wifi").lower(),
        "label": label,
        "target": {k: t.get(k) for k in (
            "ssid", "bssid", "name", "address", "query", "url", "channel",
            "encryption",
        ) if t.get(k) is not None},
        "status": "open",
        "created_at": now,
        "updated_at": now,
    }
    (base / "meta.json").write_text(
        json.dumps(meta, indent=2, default=str), encoding="utf-8",
    )
    for name, body in (
        ("plan.md", f"# Plan — {label}\n\n_No plan written yet._\n"),
        ("findings.md", f"# Findings — {label}\n\n"),
        ("decisions.md", f"# Decisions — {label}\n\n"),
        ("next_steps.md", f"# Next steps — {label}\n\n- Start recon\n"),
    ):
        p = base / name
        if not p.is_file():
            p.write_text(body, encoding="utf-8")
    return {"ok": True, "id": wid, "path": str(base), "meta": meta}


def load_workspace(wid: str) -> Dict[str, Any]:
    base = workspace_root() / wid
    if not base.is_dir():
        return {"ok": False, "error": f"workspace not found: {wid}"}
    meta: Dict[str, Any] = {}
    try:
        meta = json.loads((base / "meta.json").read_text(encoding="utf-8"))
    except Exception:
        meta = {"id": wid}
    files = {}
    for name in ("plan.md", "findings.md", "decisions.md", "next_steps.md"):
        p = base / name
        try:
            files[name] = p.read_text(encoding="utf-8") if p.is_file() else ""
        except Exception:
            files[name] = ""
    return {"ok": True, "id": wid, "path": str(base), "meta": meta, "files": files}


def _touch_meta(base: Path, **fields: Any) -> None:
    meta_path = base / "meta.json"
    try:
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
    except Exception:
        meta = {"id": base.name}
    meta.update(fields)
    meta["updated_at"] = time.time()
    meta_path.write_text(json.dumps(meta, indent=2, default=str), encoding="utf-8")


def append_finding(wid: str, text: str) -> Dict[str, Any]:
    base = workspace_root() / wid
    if not base.is_dir():
        return {"ok": False, "error": "missing workspace"}
    line = f"- [{time.strftime('%Y-%m-%d %H:%M:%S')}] {text.strip()}\n"
    with open(base / "findings.md", "a", encoding="utf-8") as fh:
        fh.write(line)
    _touch_meta(base)
    return {"ok": True, "id": wid}


def append_decision(wid: str, text: str) -> Dict[str, Any]:
    base = workspace_root() / wid
    if not base.is_dir():
        return {"ok": False, "error": "missing workspace"}
    line = f"- [{time.strftime('%Y-%m-%d %H:%M:%S')}] {text.strip()}\n"
    with open(base / "decisions.md", "a", encoding="utf-8") as fh:
        fh.write(line)
    _touch_meta(base)
    return {"ok": True, "id": wid}


def set_plan(wid: str, plan_text: str) -> Dict[str, Any]:
    base = workspace_root() / wid
    if not base.is_dir():
        return {"ok": False, "error": "missing workspace"}
    (base / "plan.md").write_text(
        f"# Plan\n\n{plan_text.strip()}\n", encoding="utf-8",
    )
    _touch_meta(base, status="planned")
    return {"ok": True, "id": wid}


def set_next_steps(wid: str, steps: List[str]) -> Dict[str, Any]:
    base = workspace_root() / wid
    if not base.is_dir():
        return {"ok": False, "error": "missing workspace"}
    body = "# Next steps\n\n" + "".join(f"- {s}\n" for s in steps)
    (base / "next_steps.md").write_text(body, encoding="utf-8")
    _touch_meta(base)
    return {"ok": True, "id": wid}


def list_recent(limit: int = 20) -> List[Dict[str, Any]]:
    root = workspace_root()
    if not root.is_dir():
        return []
    items = []
    for p in root.iterdir():
        if not p.is_dir():
            continue
        meta_path = p / "meta.json"
        meta: Dict[str, Any] = {"id": p.name, "path": str(p)}
        if meta_path.is_file():
            try:
                meta.update(json.loads(meta_path.read_text(encoding="utf-8")))
            except Exception:
                pass
        meta.setdefault("path", str(p))
        items.append(meta)
    items.sort(key=lambda m: float(m.get("updated_at") or 0), reverse=True)
    return items[: max(1, int(limit))]
