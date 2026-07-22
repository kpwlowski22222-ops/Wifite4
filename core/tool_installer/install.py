"""core.tool_installer.install — install a tool from the catalog.

Strategy:
    1. Look up TOOL_CATALOG[tool]
    2. If not present → return False (degrade honestly)
    3. If `confirm_required` and no auto/confirmation → return False
       (the gate is the operator's decision; the runner surfaces the
       "install X?" sub-prompt via confirm_fn if provided)
    4. Try apt first (Kali standard). If apt succeeds (returncode 0 and
       the binary now exists) → True. Else fall through.
    5. Try pip. Same rule.
    6. Try git clone. Same rule.
    7. Final check: `shutil.which(tool)` — True only if it's there.

Every attempt is logged via `core.tool_installer.log`.
"""
from __future__ import annotations

import dataclasses
import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Callable, Optional

from .catalog import TOOL_CATALOG, InstallSpec, is_skipped
from .log import _append_log


_DEFAULT_TIMEOUT = 600  # 10 min for apt/pip installs (large downloads)


def _run(cmd: list[str], timeout: int) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired as e:
        return -1, "", f"timeout after {timeout}s: {e}"
    except FileNotFoundError as e:
        return -1, "", f"binary not found: {e}"
    except Exception as e:
        return -1, "", f"subprocess error: {e!r}"


def _try_apt(pkg: str, *, timeout: int) -> bool:
    """Run `apt-get install -y <pkg>`. Return True if tool now on PATH."""
    # check both apt-get and apt (some systems)
    apt_get = shutil.which("apt-get")
    if not apt_get:
        return False
    # require root for apt (we never assume sudo availability)
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        rc, out, err = _run(["sudo", "-n", apt_get, "install", "-y", pkg], timeout=timeout)
    else:
        rc, out, err = _run([apt_get, "install", "-y", pkg], timeout=timeout)
    return rc == 0


def _try_pip(pkg: str, *, timeout: int) -> bool:
    pip = shutil.which("pip3") or shutil.which("pip")
    if not pip:
        return False
    rc, out, err = _run([pip, "install", "--user", pkg], timeout=timeout)
    return rc == 0


def _try_git(repo: str, target: str, *, timeout: int) -> bool:
    git = shutil.which("git")
    if not git:
        return False
    target_path = Path(target)
    if target_path.exists() and any(target_path.iterdir() if target_path.is_dir() else [target_path]):
        # already cloned; consider success
        return True
    target_path.parent.mkdir(parents=True, exist_ok=True)
    rc, out, err = _run([git, "clone", "--depth", "1", repo, str(target_path)], timeout=timeout)
    return rc == 0


def maybe_install(
    tool: str,
    *,
    auto: bool = False,
    confirm_fn: Optional[Callable[[str], bool]] = None,
    timeout: int = _DEFAULT_TIMEOUT,
) -> bool:
    """Install `tool` from the catalog.

    Args:
        tool: the binary name (looked up in TOOL_CATALOG)
        auto: bypass the per-step gate (use ONLY when the operator has
              already approved a list of installs, e.g. a pre-approved
              bootstrap). Default False.
        confirm_fn: the operator's gate; takes a description, returns bool.
                    Required when `confirm_required=True` and `auto=False`.
        timeout: subprocess timeout (seconds).

    Returns:
        True iff the tool is on PATH after the call.
    """
    spec = TOOL_CATALOG.get(tool)
    if spec is None:
        _append_log({
            "event": "miss",
            "tool": tool,
            "reason": "not in catalog",
        })
        return False

    # operator skip list (Phase 2.3.B) — e.g. SDR-only hardware
    # that the operator's setup does not include.
    if is_skipped(tool):
        _append_log({
            "event": "skip",
            "tool": tool,
            "reason": "in operator's skip list (e.g. SDR hardware)",
        })
        return False

    # gate
    if spec.confirm_required and not auto:
        if confirm_fn is None:
            _append_log({
                "event": "refuse",
                "tool": tool,
                "reason": "confirm_required but no confirm_fn supplied",
            })
            return False
        prompt = (
            f"ACCEPT auto-install? tool={tool!r} sources=[{spec.describe()}]. "
            f"Adds a package to the system; logged to core/tool_installer/_log.json."
        )
        if not confirm_fn(prompt):
            _append_log({
                "event": "refuse",
                "tool": tool,
                "reason": "operator CANCELLED",
            })
            return False

    if shutil.which(tool):
        _append_log({"event": "already_present", "tool": tool})
        return True

    # try sources in order
    tried = []
    if spec.apt:
        tried.append(("apt", spec.apt))
        _append_log({"event": "attempt", "tool": tool, "source": "apt", "pkg": spec.apt})
        if _try_apt(spec.apt, timeout=timeout) and shutil.which(tool):
            _append_log({"event": "ok", "tool": tool, "source": "apt", "pkg": spec.apt})
            return True
    if spec.pip:
        tried.append(("pip", spec.pip))
        _append_log({"event": "attempt", "tool": tool, "source": "pip", "pkg": spec.pip})
        if _try_pip(spec.pip, timeout=timeout) and shutil.which(tool):
            _append_log({"event": "ok", "tool": tool, "source": "pip", "pkg": spec.pip})
            return True
    if spec.git:
        repo, target = spec.git
        tried.append(("git", repo))
        _append_log({"event": "attempt", "tool": tool, "source": "git", "repo": repo})
        if _try_git(repo, target, timeout=timeout):
            # the binary may not be on PATH yet, but the clone succeeded
            _append_log({"event": "ok", "tool": tool, "source": "git", "target": target})
            return shutil.which(tool) is not None

    _append_log({
        "event": "fail",
        "tool": tool,
        "tried": tried,
        "reason": "no source produced an on-PATH binary",
    })
    return False
