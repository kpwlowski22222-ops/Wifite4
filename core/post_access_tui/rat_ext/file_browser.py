"""core.post_access_tui.rat_ext.file_browser — Phase 2.4 §B.2.

Read-only file tree viewer. The operator may browse a glob of
``RAT_ALLOWED_PATHS`` directories; anything outside the glob
returns 403. Write endpoints are NOT exposed — uploads go
through the dedicated screenshot upload route.

Endpoints (mounted at the dashboard's ``/api/session/<sid>/...``
namespace):
  GET  /api/session/<sid>/ls?path=<rel>
        → list of {name, type, size, mtime}
  GET  /api/session/<sid>/get?path=<rel>
        → for image MIME, returns base64 thumbnail (≤ 256px on
          the longest edge). For text MIME, returns the file
          contents (capped at 64 KB). For binary, returns 415.
  GET  /api/session/<sid>/put → 403 (rejected by design)

The session's ``context.allowed_paths`` (if set) overrides
``RAT_ALLOWED_PATHS``. If neither is set, all read endpoints
return 403 (deny by default).
"""
from __future__ import annotations

import base64
import io
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


TEXT_MIMES = {
    "text/plain", "text/html", "text/csv", "text/xml", "text/markdown",
    "application/json", "application/xml", "application/x-yaml",
    "application/yaml",
}
IMAGE_MIMES = {
    "image/png", "image/jpeg", "image/gif", "image/webp", "image/bmp",
}
MAX_TEXT_BYTES = 64 * 1024
MAX_THUMB_BYTES = 64 * 1024


def _allowed_roots() -> List[Path]:
    """Read the glob from env. Return absolute paths only."""
    raw = os.environ.get("RAT_ALLOWED_PATHS", "")
    roots = []
    for piece in raw.split(":"):
        piece = piece.strip()
        if not piece:
            continue
        try:
            p = Path(piece).resolve()
            if p.is_dir():
                roots.append(p)
        except Exception:  # noqa: BLE001
            pass
    return roots


def _resolve(rel: str, session_allowed: Optional[List[str]] = None
             ) -> Optional[Path]:
    """Resolve ``rel`` against the allow-list. Returns the absolute
    path if it's inside a permitted root, else None.

    The ``rel`` arg must not contain ``..`` segments (rejected
    on the input side too)."""
    if not rel or ".." in Path(rel).parts:
        return None
    roots = _allowed_roots()
    if session_allowed:
        for piece in session_allowed:
            try:
                p = Path(piece).resolve()
                if p.is_dir():
                    roots.append(p)
            except Exception:  # noqa: BLE001
                pass
    if not roots:
        return None
    for root in roots:
        candidate = (root / rel).resolve()
        try:
            candidate.relative_to(root)
        except ValueError:
            continue
        if candidate.exists():
            return candidate
    return None


def ls(rel: str, session_allowed: Optional[List[str]] = None
       ) -> Dict[str, Any]:
    """List ``rel`` directory contents.

    Returns ``{ok, entries, error}``."""
    # Phase 2.4 §B.2 — explicit traversal rejection
    if rel and ".." in Path(rel).parts:
        return {
            "ok": False,
            "error": ("path traversal denied (rel contains '..')"),
        }
    p = _resolve(rel, session_allowed)
    if p is None:
        return {
            "ok": False,
            "error": ("path not in allow-list (set "
                      "RAT_ALLOWED_PATHS or session.allowed_paths)"),
        }
    if not p.is_dir():
        return {"ok": False, "error": "not a directory"}
    entries: List[Dict[str, Any]] = []
    try:
        for child in sorted(p.iterdir()):
            try:
                entries.append({
                    "name": child.name,
                    "type": "dir" if child.is_dir() else "file",
                    "size": (child.stat().st_size
                             if child.is_file() else None),
                    "mtime": child.stat().st_mtime,
                })
            except Exception:  # noqa: BLE001
                continue
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": f"iterdir failed: {e}"}
    return {"ok": True, "rel": rel, "entries": entries, "count": len(entries)}


def _detect_mime(path: Path) -> str:
    """Naive MIME detect by extension. Does not import ``mimetypes``
    to keep the module lightweight."""
    ext = path.suffix.lower()
    table = {
        ".txt": "text/plain", ".md": "text/markdown",
        ".html": "text/html", ".htm": "text/html",
        ".json": "application/json", ".yaml": "application/yaml",
        ".yml": "application/yaml", ".xml": "application/xml",
        ".csv": "text/csv",
        ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
        ".gif": "image/gif", ".webp": "image/webp", ".bmp": "image/bmp",
    }
    return table.get(ext, "application/octet-stream")


def get(rel: str, session_allowed: Optional[List[str]] = None
        ) -> Dict[str, Any]:
    """Read ``rel``. Returns the file contents or a thumbnail."""
    if rel and ".." in Path(rel).parts:
        return {
            "ok": False,
            "error": ("path traversal denied (rel contains '..')"),
        }
    p = _resolve(rel, session_allowed)
    if p is None:
        return {
            "ok": False,
            "error": ("path not in allow-list (set "
                      "RAT_ALLOWED_PATHS or session.allowed_paths)"),
        }
    if not p.is_file():
        return {"ok": False, "error": "not a file"}
    mime = _detect_mime(p)
    if mime in TEXT_MIMES:
        try:
            data = p.read_bytes()[:MAX_TEXT_BYTES]
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "error": f"read failed: {e}"}
        return {
            "ok": True, "rel": rel, "mime": mime, "size": len(data),
            "text": data.decode("utf-8", errors="replace"),
        }
    if mime in IMAGE_MIMES:
        # Thumbnail via Pillow if available; else raw bytes (capped)
        try:
            from PIL import Image  # type: ignore
        except ImportError:
            return {
                "ok": False,
                "error": ("Pillow not installed; cannot thumbnail. "
                          "Install via the per-step tool_installer."),
                "mime": mime,
            }
        try:
            with Image.open(p) as im:
                im.thumbnail((256, 256))
                buf = io.BytesIO()
                im.save(buf, format="PNG")
                thumb = buf.getvalue()
            return {
                "ok": True, "rel": rel, "mime": "image/png",
                "size": len(thumb),
                "thumb_b64": base64.b64encode(thumb).decode("ascii"),
                "original_mime": mime,
            }
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "error": f"thumbnail failed: {e}"}
    return {
        "ok": False, "error": f"unsupported mime {mime}", "mime": mime,
    }


def put_blocked() -> Dict[str, Any]:
    """Write endpoints are NOT exposed. The screenshot upload is
    the only file-write path, and it goes to
    ``~/.kfiosa/rat_screens/<sid>/<ts>.png`` (not the user tree)."""
    return {
        "ok": False,
        "error": ("write endpoints are not exposed; use "
                  "POST /upload/<sid> for screenshot uploads"),
    }


__all__ = [
    "ls", "get", "put_blocked",
    "TEXT_MIMES", "IMAGE_MIMES", "MAX_TEXT_BYTES", "MAX_THUMB_BYTES",
]
