"""core.live_edit.reload — reload a runner module with its live overlays.

Each overlay module re-imports the original runner, subclasses it, and
exposes `LiveOverlay<Rclass>` + `_get_runner()`. Reloading the runner
module re-imports its top-level names; the orchestrator is then responsible
for rebinding the Runner class to the live version.

This function is intentionally minimal: it imports the overlay (which
imports the original), and returns the module. The orchestrator's
dispatcher code is what decides which class to instantiate.
"""
from __future__ import annotations

import importlib
import sys
from pathlib import Path
from typing import Optional


_OVERLAY_ROOT = Path(__file__).parent / "overlays"


def _iter_overlays(runner_module_name: str) -> list[Path]:
    safe = runner_module_name.replace(".", "_")
    target_dir = _OVERLAY_ROOT / safe
    if not target_dir.exists():
        return []
    return sorted(target_dir.glob("__live_*.py"))


def reload_runner_with_overlays(runner_module_name: str) -> Optional[object]:
    """Re-import the runner module and apply any live overlays.

    Returns the new runner class (or whatever the latest overlay's
    `_get_runner()` returns), or the original Runner class if there are
    no overlays. Returns None on import failure.
    """
    try:
        runner_module = importlib.import_module(runner_module_name)
        importlib.reload(runner_module)
    except Exception:
        return None

    overlays = _iter_overlays(runner_module_name)
    if not overlays:
        return runner_module

    # import the latest overlay (lexicographic = highest timestamp)
    latest = overlays[-1]
    modname = latest.stem + "_overlay"
    full_modname = f"core.live_edit.overlays.{runner_module_name.replace('.', '_')}.{modname}"
    spec = importlib.util.spec_from_file_location(full_modname, str(latest))
    if spec is None or spec.loader is None:
        return runner_module
    mod = importlib.util.module_from_spec(spec)
    sys.modules[full_modname] = mod
    try:
        spec.loader.exec_module(mod)
    except Exception:
        return runner_module

    get = getattr(mod, "_get_runner", None)
    if callable(get):
        return get()
    return runner_module
