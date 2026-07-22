# core.replan.visibility
#
# Assemble a context dict the chain planner sees when a step's ok=False.
# The dict includes:
#   - the failed step's full result (dict)
#   - the runner module's __file__ path + a SHA-256 of the *method's current
#     source* (not the whole file — just the bytes of the def statement)
#   - the list of available safe-patches (from core.live_edit.test_patches)
#   - the list of tools that were missing when the step ran (heuristic —
#     look at the step's args for tool fields, or accept an explicit list
#     from the runner)
#
# This is the bridge between the runtime failure and the planner's re-plan
# loop: with this context, the LLM can name a safe-patch by id (e.g.
# "swap_retry_count") and the orchestrator can apply it via core.live_edit.
from __future__ import annotations

import ast
import hashlib
import importlib
import inspect
from pathlib import Path
from typing import Any, Optional


def _method_source_and_sha(runner_module_name: str, method_name: str) -> tuple[Optional[str], Optional[str]]:
    """Return (source_of_method_def, sha256_hex) for `method_name` in `runner_module_name`.

    Both are None if the method can't be located.
    """
    try:
        mod = importlib.import_module(runner_module_name)
    except ImportError:
        return None, None
    file_path = getattr(mod, "__file__", None)
    if not file_path:
        return None, None
    src_path = Path(file_path)
    try:
        source = src_path.read_text()
    except OSError:
        return None, None
    try:
        tree = ast.parse(source, filename=str(src_path))
    except SyntaxError:
        return None, None
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            for item in node.body:
                if isinstance(item, ast.FunctionDef) and item.name == method_name:
                    method_src = ast.get_source_segment(source, item) or ast.unparse(item)
                    sha = hashlib.sha256(method_src.encode()).hexdigest()
                    return method_src, sha
    return None, None


def gather_failure_context(
    *,
    step: dict,
    runner_module: Optional[str] = None,
    method_name: Optional[str] = None,
    result: Optional[dict] = None,
    missing_tools: Optional[list[str]] = None,
) -> dict:
    """Build the failure-context dict for the re-planner.

    Args:
        step: the failed step dict (action, method, args, ...)
        runner_module: dotted module path of the runner that owns the
                       failed method (e.g. "core.wifi_attack.runner")
        method_name: the `_method` that failed
        result: the result dict the step returned (may be None)
        missing_tools: optional explicit list of tools that were missing
                       when the step ran. The re-planner can request
                       installs for any of these.

    Returns:
        A dict with keys: failed_step, source_path, source_sha256,
        method_source_excerpt, available_patches, missing_tools.
    """
    method_src, sha = (None, None)
    source_path = None
    if runner_module is not None:
        try:
            mod = importlib.import_module(runner_module)
            source_path = getattr(mod, "__file__", None)
        except ImportError:
            source_path = None
        if method_name is not None:
            method_src, sha = _method_source_and_sha(runner_module, method_name)

    if missing_tools is None:
        # heuristic: look at step["args"] for "tool"/"which" hints
        missing_tools = _extract_missing_tools(result)

    from core.live_edit import list_available_patches
    available_patches = list_available_patches()

    return {
        "failed_step": dict(step) if step else {},
        "result": dict(result) if result else {},
        "runner_module": runner_module,
        "method_name": method_name,
        "source_path": source_path,
        "source_sha256": sha,
        "method_source_excerpt": method_src,
        "available_patches": available_patches,
        "missing_tools": missing_tools,
    }


def _extract_missing_tools(result: Optional[dict]) -> list[str]:
    """Look for an explicit `missing_tools` list in the result; else [].

    Some runners (when wired with core.tool_installer) will record what
    they wanted but couldn't find. Otherwise empty.
    """
    if not result:
        return []
    if isinstance(result, dict):
        mt = result.get("missing_tools")
        if isinstance(mt, list):
            return [str(t) for t in mt]
    return []
