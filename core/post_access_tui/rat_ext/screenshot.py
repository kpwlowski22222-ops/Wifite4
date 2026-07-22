"""core.post_access_tui.rat_ext.screenshot — Phase 2.4 §B.5.

Screenshot upload endpoint. The dashboard exposes
``POST /upload/<sid>`` with multipart ``image/png`` or
``image/jpeg``, ≤ 5 MB. Pillow's ``verify()`` checks the
file is a real image; ``Image.save()`` re-encodes the file
which strips EXIF. The saved file goes to
``~/.kfiosa/rat_screens/<sid>/<ts>.png`` and a 256px
thumbnail is generated.

Endpoints:
  POST /upload/<sid>          — multipart upload
  GET  /api/session/<sid>/screens?since=<ts>
"""
from __future__ import annotations

import os
import re
import time
import uuid
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

# Hard cap — the operator's contract: 5 MB
MAX_BYTES = 5 * 1024 * 1024

# Storage root
SCREENS_DIR = Path.home() / ".kfiosa" / "rat_screens"

# Allowed MIME types
ALLOWED_MIMES = {"image/png", "image/jpeg"}


def _ensure_dir(sid: str) -> Path:
    safe = re.sub(r"[^A-Za-z0-9_\-.]", "_", sid) or "default"
    d = SCREENS_DIR / safe
    d.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(d, 0o700)
    except Exception:  # noqa: BLE001
        pass
    return d


def save_screenshot(sid: str, raw_bytes: bytes,
                    declared_mime: str = "image/png"
                    ) -> Dict[str, Any]:
    """Validate + strip EXIF + save the screenshot.

    Returns ``{ok, path, thumb_path, mime, size, ts}`` or an
    error envelope. The file is stored as PNG (re-encoded by
    Pillow; EXIF is dropped).
    """
    if not raw_bytes:
        return {"ok": False, "error": "empty upload"}
    if len(raw_bytes) > MAX_BYTES:
        return {
            "ok": False,
            "error": (f"file too large: {len(raw_bytes)} > "
                      f"{MAX_BYTES} bytes"),
        }
    mime = declared_mime.lower().strip()
    if mime not in ALLOWED_MIMES:
        return {
            "ok": False,
            "error": (f"unsupported mime {mime!r}; allowed: "
                      f"{sorted(ALLOWED_MIMES)}"),
        }
    try:
        from PIL import Image  # type: ignore
    except ImportError:
        return {
            "ok": False,
            "error": ("Pillow not installed; cannot strip EXIF. "
                      "Install via the per-step tool_installer."),
        }
    try:
        import io as _io
        with Image.open(_io.BytesIO(raw_bytes)) as im:
            im.verify()  # re-open + verify
        # verify() closes the image; re-open to actually save
        with Image.open(_io.BytesIO(raw_bytes)) as im:
            ts = time.time()
            uid = uuid.uuid4().hex[:8]
            d = _ensure_dir(sid)
            out_path = d / f"{int(ts)}_{uid}.png"
            im_no_exif = Image.new(im.mode, im.size)
            im_no_exif.putdata(list(im.getdata()))
            if im.mode in ("RGBA", "P"):
                im_no_exif = im_no_exif.convert("RGB")
            im_no_exif.save(out_path, format="PNG")
            # Thumbnail
            im_thumb = im_no_exif.copy()
            im_thumb.thumbnail((256, 256))
            thumb_path = d / f"{int(ts)}_{uid}_thumb.png"
            im_thumb.save(thumb_path, format="PNG")
            try:
                os.chmod(out_path, 0o600)
                os.chmod(thumb_path, 0o600)
            except Exception:  # noqa: BLE001
                pass
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": f"image processing failed: {e}"}
    return {
        "ok": True,
        "session_id": sid,
        "ts": ts,
        "mime": "image/png",
        "path": str(out_path),
        "thumb_path": str(thumb_path),
        "size": out_path.stat().st_size,
    }


def list_screens(sid: str, since_ts: Optional[float] = None
                 ) -> Dict[str, Any]:
    """List all screenshot files for ``sid`` (optionally after
    ``since_ts``)."""
    d = _ensure_dir(sid)
    entries = []
    for child in sorted(d.glob("*.png")):
        if child.name.endswith("_thumb.png"):
            continue
        try:
            st = child.stat()
        except Exception:  # noqa: BLE001
            continue
        # Filename pattern: <ts>_<uid>.png
        m = re.match(r"^(\d+)_", child.name)
        ts = float(m.group(1)) if m else st.st_mtime
        if since_ts is not None and ts <= since_ts:
            continue
        thumb = child.with_name(child.stem + "_thumb.png")
        entries.append({
            "ts": ts,
            "name": child.name,
            "path": str(child),
            "thumb_path": str(thumb) if thumb.exists() else None,
            "size": st.st_size,
        })
    return {
        "ok": True,
        "session_id": sid,
        "screens": entries,
        "count": len(entries),
    }


__all__ = [
    "MAX_BYTES",
    "SCREENS_DIR",
    "ALLOWED_MIMES",
    "save_screenshot",
    "list_screens",
]
