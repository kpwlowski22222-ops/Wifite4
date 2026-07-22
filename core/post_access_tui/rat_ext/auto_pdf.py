"""core.post_access_tui.rat_ext.auto_pdf — Phase 2.4 §B.11.

Automatic PDF export after every finished attack. The post-access
TUI's :func:`run_full_auto` and :func:`menu_loop.curses_free_loop`
call :func:`export_full_report` on exit. Output goes to
``~/.kfiosa/reports/<timestamp>_<chain>.pdf``.

The dashboard's :func:`spawn_rat_dashboard` is also called
automatically (by the chain step) when the chain finishes, but
the per-spawn sentinel
``report["access"]["rat_dashboard_opened"]`` prevents re-plan
loops from re-spawning it.
"""
from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


REPORTS_DIR = Path.home() / ".kfiosa" / "reports"


def _ensure_dir() -> Path:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(REPORTS_DIR, 0o700)
    except Exception:  # noqa: BLE001
        pass
    return REPORTS_DIR


def build_report_path(chain: str = "post_exploit") -> Path:
    """Build a path like ``~/.kfiosa/reports/<ts>_<chain>.pdf``."""
    d = _ensure_dir()
    ts = time.strftime("%Y%m%d_%H%M%S")
    safe = "".join(c for c in chain if c.isalnum() or c in "-_") or "chain"
    return d / f"{ts}_{safe}.pdf"


def export_full_report(sessions: List[Dict[str, Any]],
                       out_path: Optional[Path] = None,
                       chain: str = "post_exploit"
                       ) -> Dict[str, Any]:
    """Export the full-attack PDF report.

    Returns ``{ok, path, size, sessions, chain}`` or an error
    envelope if the write failed. If ``out_path`` is None a
    default timestamped path is used."""
    from .pdf_export import build_full_report_bytes
    if out_path is None:
        out_path = build_report_path(chain=chain)
    try:
        body, content_type = build_full_report_bytes(sessions or [])
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": f"build failed: {e}"}
    try:
        with open(out_path, "wb") as f:
            f.write(body)
        try:
            os.chmod(out_path, 0o600)
        except Exception:  # noqa: BLE001
            pass
    except Exception as e:  # noqa: BLE001
        return {
            "ok": False,
            "error": f"write failed: {e}",
            "path": str(out_path),
        }
    return {
        "ok": True,
        "path": str(out_path),
        "size": out_path.stat().st_size,
        "sessions": len(sessions or []),
        "chain": chain,
        "content_type": content_type,
        "ts": time.time(),
    }


__all__ = [
    "REPORTS_DIR",
    "build_report_path",
    "export_full_report",
]
