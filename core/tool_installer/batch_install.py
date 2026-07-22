"""core.tool_installer.batch_install — install multiple tools in one go.

Phase 2.4 — `install_missing(tools, auto, confirm_fn)` takes a
list of tool names from ``TOOL_CATALOG`` and tries to install
each via the existing ``maybe_install`` path. Returns an
aggregate envelope ``{ok, installed, skipped, failed}``.

The function never raises. Each tool's install attempt is wrapped
in try/except so a single failure doesn't abort the whole batch.
"""
from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional, Set

from .catalog import TOOL_CATALOG, skipped_tools, is_skipped, InstallSpec


def install_missing(tools: List[str],
                    auto: bool = False,
                    confirm_fn: Optional[Callable[[str, InstallSpec], bool]] = None
                    ) -> Dict[str, Any]:
    """Try to install each tool in ``tools`` that is in the catalog.

    Args:
        tools: tool names (must be keys of ``TOOL_CATALOG``).
        auto: if True, skip the per-tool confirm prompt.
        confirm_fn: optional callable ``(tool_name, install_spec)
            -> bool`` invoked for each tool that has
            ``confirm_required=True``. If it returns True the
            install proceeds. If False the tool is added to
            ``skipped``. Required when ``auto=False`` and the
            tool is confirm-required.

    Returns:
        ``{ok, installed: [tool, ...], skipped: [tool, ...],
        failed: [{tool, error: str}, ...], counts: {...},
        model: "batch-install"}``
    """
    installed: List[str] = []
    skipped: List[str] = []
    failed: List[Dict[str, str]] = []
    seen: Set[str] = set()

    for tool in tools:
        if tool in seen:
            continue
        seen.add(tool)
        if is_skipped(tool):
            skipped.append(tool)
            continue
        spec = TOOL_CATALOG.get(tool)
        if spec is None:
            failed.append({"tool": tool, "error": "not in catalog"})
            continue
        if spec.confirm_required and not auto:
            if confirm_fn is None:
                skipped.append(tool)
                continue
            try:
                ok = bool(confirm_fn(tool, spec))
            except Exception as e:  # noqa: BLE001
                failed.append({"tool": tool,
                               "error": f"confirm_fn raised: {e}"})
                continue
            if not ok:
                skipped.append(tool)
                continue
        # Try the install via maybe_install (lazy import to avoid
        # circular import with catalog module)
        try:
            from .install import maybe_install
            ok = bool(maybe_install(tool))
        except Exception as e:  # noqa: BLE001
            ok = False
            failed.append({"tool": tool, "error": f"maybe_install: {e}"})
        if ok:
            installed.append(tool)
        else:
            failed.append({"tool": tool, "error":
                           "maybe_install returned False (tool not "
                           "present on disk after install attempt)"})

    return {"ok": not failed,
            "installed": installed,
            "skipped": skipped,
            "failed": failed,
            "counts": {
                "installed": len(installed),
                "skipped": len(skipped),
                "failed": len(failed),
            },
            "model": "batch-install"}


__all__ = ["install_missing"]
