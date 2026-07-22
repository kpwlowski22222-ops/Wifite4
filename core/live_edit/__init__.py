"""core.live_edit — AI-driven runtime AST patching of KFIOSA runner methods.

The chain planner can request a patch by name + parameters; the patch is a
parameterized AST transform from `core.live_edit.test_patches`, NOT arbitrary
string-of-code. The patch is validated, applied to a frozen copy of the runner
source, written to `core/live_edit/overlays/<runner>/__live_<ts>.py`, and the
runner is reloaded with the overlay shadowing the original method. The original
is preserved at `runner._<method>__original` for revert.

Every applied patch is logged to `core/live_edit/overlays/_log.json` with the
rationale, the operator's gate verdict, the timestamp, and a SHA-256 of the
original source for audit.

Public surface (the AI may name these by id):
    validate_patch(spec) -> (ok: bool, reason: str)
    apply_patch(spec, *, confirm_fn=None) -> str path | None
    revert_patch(path) -> bool
    reload_runner_with_overlays(runner_module) -> module
    list_available_patches() -> List[str]
    get_patch_log() -> List[dict]
"""

from .patch import (
    PatchSpec,
    validate_patch,
    list_available_patches,
    _AVAILABLE_PATCH_IDS,
)
from .apply import apply_patch, revert_patch
from .reload import reload_runner_with_overlays
from .log import get_patch_log, _OVERLAY_LOG
from . import test_patches  # registers the safe-patch catalog

__all__ = [
    "PatchSpec",
    "validate_patch",
    "apply_patch",
    "revert_patch",
    "reload_runner_with_overlays",
    "list_available_patches",
    "get_patch_log",
]
