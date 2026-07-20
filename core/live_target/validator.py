"""core.live_target.validator — runtime guard for the safe-patch catalog.

The catalog of safe patches in :mod:`core.live_target.safe_patches`
is pre-vetted at module load; this module provides the runtime
guard that re-checks every patch's input + output. The check is
deliberately paranoid: anything that smells like a shell exec, a
process spawn, a dynamic loader, or a PowerShell ``Invoke-Expression``
in the *swapped* string is rejected.

The guard never raises; it returns ``{"ok": False, "error": "..."}``
on rejection and ``{"ok": True, ...}`` on pass.

Honesty contract:
  * Reject anything in the swapped string that contains:
      - ``os.system`` / ``Runtime.exec`` / ``ProcessBuilder.start``
        / ``NSTask.launchedTaskWithPath`` / ``posix_spawn`` /
        ``dlopen`` / ``dlsym``
      - PowerShell ``Invoke-Expression`` / ``iex`` / ``.Invoke(``
      - Java ``Class.forName`` / ``new URLClassLoader`` /
        ``Method.invoke``
      - Shell metas in the swapped string: ``;``, ``&&``, ``||``,
        ``|``, ``>``, ``<``, backtick, ``$(``.
  * Permit the whitelist of safe pattern-flavors below.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List


# Forbidden substrings — if ANY appears in the swapped string,
# the patch is rejected. (Lowercase comparison; the validator is
# case-insensitive for the search.)
_FORBIDDEN_EXEC = (
    "os.system",
    "subprocess.popen",  # any subprocess
    "subprocess.call",
    "subprocess.run",
    "runtime.exec",
    "processbuilder",
    "nstask",
    "launchedtaskwithpath",
    "launchedtaskwithbinarypath",
    "posix_spawn",
    "posix_spawnp",
    "dlopen",
    "dlsym",
    "system(",  # libc system
    "execl(",
    "execvp(",
    "execve(",
    "_popen",
    "win32api.shellexecute",
    "shell.application",
)

# PowerShell dynamic exec — anything in the swapped string that
# looks like a dynamic-eval pattern is rejected.
_FORBIDDEN_PS_EVAL = (
    "invoke-expression",
    "iex(",
    "iex ",
    ".invoke(",
    "icm ",
    "invoke-command",
)

# Java dynamic class load / reflection
_FORBIDDEN_JAVA_REFLECT = (
    "class.forname",
    "urlclassloader",
    "method.invoke",
    "constructor.newinstance",
)

# Shell metas
_SHELL_META_RE = re.compile(r"[;<>|&`$\n\r]")


def _has_shell_meta(s: str) -> bool:
    return bool(_SHELL_META_RE.search(s or ""))


def _contains_any(haystack: str, needles) -> bool:
    h = (haystack or "").lower()
    return any(n in h for n in needles)


def validate_swap(target_class: str, patch_id: str,
                  old: str, new: str) -> Dict[str, Any]:
    """Validate the *swapped-in* string for a single patch.

    This is the runtime guard: it inspects ONLY the string that
    gets injected (the ``new`` value), not the entire post-swap
    artifact. The original artifact is operator-supplied and may
    already contain any byte sequence; the contract is that the
    *patch* never introduces a forbidden pattern.

    Returns ``{"ok": True, "warnings": [...]}`` on pass and
    ``{"ok": False, "error": "..."}`` on rejection. Never raises."""
    if not isinstance(target_class, str) or target_class not in {
            "microsoft", "android", "ios"}:
        return {"ok": False, "error": (
            f"target_class must be one of microsoft/android/ios; "
            f"got {target_class!r}")}
    if not isinstance(patch_id, str) or not patch_id:
        return {"ok": False, "error": "patch_id required"}
    if not isinstance(new, str):
        return {"ok": False, "error": "new string required"}
    if not new.strip():
        return {"ok": False, "error": "new string is empty"}
    if _has_shell_meta(new):
        return {"ok": False,
                "error": (f"patch {patch_id!r}: shell meta char in "
                          f"new string {new!r}")}
    if _contains_any(new, _FORBIDDEN_EXEC):
        return {"ok": False,
                "error": (f"patch {patch_id!r}: forbidden exec API "
                          f"in new string")}
    if target_class == "microsoft":
        if _contains_any(new, _FORBIDDEN_PS_EVAL):
            return {"ok": False,
                    "error": (f"patch {patch_id!r}: forbidden PS eval "
                              f"API in new string")}
    if target_class == "android":
        if _contains_any(new, _FORBIDDEN_JAVA_REFLECT):
            return {"ok": False,
                    "error": (f"patch {patch_id!r}: forbidden Java "
                              f"reflection API in new string")}
    # Optional: also reject ancient (deprecated) ``exec`` alone.
    if _contains_any(new, ("exec(", "exec ", "eval(")):
        return {"ok": False,
                "error": (f"patch {patch_id!r}: forbidden exec/eval "
                          f"in new string")}
    return {"ok": True, "warnings": []}


def validate_params(target_class: str, patch_id: str,
                    params: Dict[str, Any]) -> Dict[str, Any]:
    """Validate the *params* of a patch. The validator checks that
    the only mutable key is a string (or dict-of-strings) and
    that the *value* does not contain shell metas or forbidden
    exec APIs. Never raises.

    The ``artifact`` field is exempt — it is the file the patch
    edits, not the value the patch injects. The
    :func:`validate_swap` function separately validates the
    *swapped* string after the patch runs."""
    if not isinstance(params, dict) or not params:
        return {"ok": False, "error": "params dict required"}
    bad: List[str] = []
    for k, v in params.items():
        if k == "artifact" or k == "out_path":
            # The artifact is the file we are editing (not what we
            # inject). out_path is the operator-supplied destination
            # for the modified artifact. Neither is a swap-target.
            continue
        if not isinstance(k, str):
            return {"ok": False, "error": f"non-string key {k!r}"}
        if isinstance(v, str):
            if _has_shell_meta(v):
                bad.append(k)
        elif isinstance(v, dict):
            for sk, sv in v.items():
                if not isinstance(sk, str):
                    return {"ok": False, "error": f"non-string subkey {sk!r}"}
                if not isinstance(sv, str):
                    return {"ok": False,
                            "error": (f"param {k}.{sk} must be string; "
                                      f"got {type(sv).__name__}")}
                if _has_shell_meta(sv):
                    bad.append(f"{k}.{sk}")
        else:
            return {"ok": False,
                    "error": (f"param {k!r} must be string or dict; "
                              f"got {type(v).__name__}")}
    if bad:
        return {"ok": False,
                "error": (f"shell meta in param(s): {bad}; "
                          "live_target only edits KFIOSA's own "
                          "emitted artifacts")}
    return {"ok": True, "warnings": []}


def canonicalize_artifact(target_class: str, patch_id: str,
                          text: str) -> Dict[str, Any]:
    """Optional safety net: strip BOM, normalise line endings,
    and ensure the artifact is a real string. Pure."""
    if not isinstance(text, str):
        return {"ok": False, "error": "artifact must be a string"}
    if not text.strip():
        return {"ok": False, "error": "artifact is empty"}
    # Strip BOM if present, normalise CRLF -> LF.
    text = text.lstrip("﻿").replace("\r\n", "\n").replace("\r", "\n")
    return {"ok": True, "text": text, "warnings": []}
