"""Live-time UI labels: what / why / predictable / coords / PNG crop.

Builds an operator+AI index of on-screen controls for keyboard/mouse
automation (holo / ui_navigator). Best-effort screenshots; honest if tools missing.
"""
from __future__ import annotations

import json
import os
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple


def labels_root() -> Path:
    raw = (os.environ.get("KFIOSA_UI_LABELS_ROOT") or "").strip()
    if raw:
        return Path(raw).expanduser()
    return Path(__file__).resolve().parents[2] / "data" / "ui_labels"


def _index_path() -> Path:
    return labels_root() / "labels_index.json"


def _load_index() -> Dict[str, Any]:
    p = _index_path()
    if not p.is_file():
        return {"labels": {}, "updated_at": 0}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return {"labels": {}, "updated_at": 0}


def _save_index(idx: Dict[str, Any]) -> None:
    root = labels_root()
    root.mkdir(parents=True, exist_ok=True)
    idx["updated_at"] = time.time()
    _index_path().write_text(json.dumps(idx, indent=2, default=str), encoding="utf-8")


def upsert_label(
    name: str,
    *,
    what_for: str,
    why: str,
    predictable: str,
    bbox: Sequence[float],
    png_path: str = "",
    label_id: str = "",
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Create/update a label with coordinates and metadata."""
    if len(bbox) < 4:
        return {"ok": False, "error": "bbox needs [x,y,w,h]"}
    x, y, w, h = [float(bbox[i]) for i in range(4)]
    lid = label_id or f"lbl-{uuid.uuid4().hex[:10]}"
    center = [x + w / 2.0, y + h / 2.0]
    rec = {
        "id": lid,
        "name": name,
        "what_for": what_for,
        "why": why,
        "predictable": predictable,
        "bbox": [x, y, w, h],
        "center": center,
        "png": png_path,
        "ts": time.time(),
        **(extra or {}),
    }
    idx = _load_index()
    labels = idx.setdefault("labels", {})
    labels[lid] = rec
    _save_index(idx)
    try:
        from core.memory.store import ingest
        ingest(
            "ui_label",
            f"{name}: {what_for} @ {center}",
            tags=["ui_label", lid],
        )
    except Exception:
        pass
    return {"ok": True, "label": rec}


def list_labels() -> List[Dict[str, Any]]:
    idx = _load_index()
    return list((idx.get("labels") or {}).values())


def get_label(label_id: str) -> Optional[Dict[str, Any]]:
    return (_load_index().get("labels") or {}).get(label_id)


def capture_screen(out_path: Optional[Path] = None) -> Dict[str, Any]:
    """Best-effort full screenshot for labeling."""
    root = labels_root()
    root.mkdir(parents=True, exist_ok=True)
    out = Path(out_path or root / f"screen-{int(time.time())}.png")
    try:
        from core.utils.ui_navigator import UINavigator
        nav = UINavigator()
        # Prefer navigator API if it exposes capture
        cap = getattr(nav, "capture_screen", None) or getattr(nav, "screenshot", None)
        if callable(cap):
            res = cap(str(out))
            if isinstance(res, dict):
                return res
            if out.is_file():
                return {"ok": True, "path": str(out)}
    except Exception as e:
        last = str(e)
    else:
        last = ""
    import shutil
    import subprocess
    if shutil.which("gnome-screenshot"):
        r = subprocess.run(
            ["gnome-screenshot", "-f", str(out)],
            capture_output=True, text=True, timeout=15,
        )
        if r.returncode == 0 and out.is_file():
            return {"ok": True, "path": str(out)}
        last = r.stderr or r.stdout or "gnome-screenshot failed"
    if shutil.which("import"):
        r = subprocess.run(
            ["import", "-window", "root", str(out)],
            capture_output=True, text=True, timeout=15,
        )
        if r.returncode == 0 and out.is_file():
            return {"ok": True, "path": str(out)}
        last = r.stderr or "import failed"
    return {"ok": False, "error": last or "no screenshot tool"}


def register_builtin_tui_labels() -> Dict[str, Any]:
    """Seed logical labels for main TUI actions (coords filled at runtime by OS)."""
    builtins = [
        ("Scan Networks", "Discover live APs/devices",
         "Need targets before engagement",
         "Opens triple windows; bus selection starts engagement"),
        ("Start engagement", "Run recon→attack→PE until access",
         "Primary AI-driven machine path",
         "ACCEPT gates on intrusive steps; PE auto-attached"),
        ("OPEN DASHBOARD", "Universal RAT control plane",
         "Manage wifi/ble/osint tasks and sessions",
         "Starts Flask/WSGI on localhost; SQL-persisted"),
        ("Settings", "Configure AI, memory, terminal, auto mode",
         "Tune creativity, narrative, full-auto flags",
         "Writes env/settings; no network attacks"),
    ]
    out = []
    for i, (name, what, why, pred) in enumerate(builtins):
        # Placeholder bbox — live capture overwrites when available
        r = upsert_label(
            name,
            what_for=what,
            why=why,
            predictable=pred,
            bbox=[20, 80 + i * 40, 280, 28],
            label_id=f"tui-{i}-{name.lower().replace(' ', '-')[:20]}",
            extra={"source": "builtin_tui", "input": "keyboard"},
        )
        if r.get("ok"):
            out.append(r["label"])
    return {"ok": True, "count": len(out), "labels": out}


def click_label(
    label_id: str,
    *,
    confirm_fn=None,
    dry_run: bool = False,
) -> Dict[str, Any]:
    """Click label center via holo (mouse) — gated."""
    lab = get_label(label_id)
    if not lab:
        return {"ok": False, "error": f"unknown label {label_id}"}
    cx, cy = lab.get("center") or [0, 0]
    task = (
        f"Move the mouse to screen coordinates ({int(cx)}, {int(cy)}) and "
        f"left-click once. Target control: {lab.get('name')} — "
        f"{lab.get('what_for')}."
    )
    if dry_run:
        return {"ok": True, "dry_run": True, "task": task, "label": lab}
    try:
        from core.desktop.holo_agent import run_holo_task
        return run_holo_task(task, confirm_fn=confirm_fn)
    except Exception as e:
        return {"ok": False, "error": str(e), "label": lab}
