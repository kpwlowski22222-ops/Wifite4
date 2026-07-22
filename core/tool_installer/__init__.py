"""core.tool_installer — auto-install missing tools the AI needs.

When a runner's `shutil.which(tool)` returns None, the runner can call
`maybe_install(tool)` to install it from the catalog. The catalog maps
tool-name → (apt, pip, git, brew). Installers run as subprocesses; the
install prompt goes through the per-step gate (default-deny 300s).

Every install attempt is logged to `core/tool_installer/_log.json` for
operator audit. The installer is opt-in per runner (no global monkey-patch).

Public surface:
    TOOL_CATALOG: dict[str, InstallSpec]
    maybe_install(tool, *, auto=False, confirm_fn=None) -> bool
    list_install_log() -> list[dict]
    install_missing(tools, auto=False, confirm_fn=None) -> dict   (Phase 2.4)
    is_sdr_available() -> bool                                     (Phase 2.4)
    sdr_status() -> dict                                           (Phase 2.4)
"""
from .catalog import TOOL_CATALOG, InstallSpec
from .install import maybe_install
from .log import list_install_log
from .batch_install import install_missing
from .check_sdr import is_sdr_available, sdr_status

__all__ = [
    "TOOL_CATALOG",
    "InstallSpec",
    "maybe_install",
    "list_install_log",
    "install_missing",
    "is_sdr_available",
    "sdr_status",
]
