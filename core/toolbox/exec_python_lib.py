"""core.toolbox.exec_python_lib — run a Python script that imports
a curated library from :mod:`core.toolbox.python_libs`.

The executor accepts a chain-step dict shaped like:

    {
      "action": "run_python_lib",
      "tool": "python_lib_executor",
      "args": {
        "lib": "scapy",                  # pip name OR import name
        "code": "print(scapy.__version__)",
        "cwd": "/tmp",                   # optional
        "timeout_seconds": 30,           # optional, default 30
        "env": {"KFIOSA_TARGET": "..."}, # optional
      }
    }

The executor does NOT install the library — that's a separate
``tool_install`` chain step. The executor only RUNS code
against an already-installed library and returns the standard
envelope (``ok``, ``returncode``, ``stdout``, ``stderr``,
``error``).

Safety:

* The library MUST be in the curated registry. Unknown
  libraries are rejected (the chain can't pull in an
  arbitrary ``pip install``).
* The executor does NOT call ``confirm_fn``. The per-step
  ACCEPT gate fires in ``_walk_ai_step`` in the orchestrator
  (single-gate invariant).
* Harvested credential values from the ``args.env`` dict
  are passed via subprocess env. Code that wants to read
  them reads ``os.environ["KFIOSA_TARGET_PASSWORD"]`` etc.
  The executor never re-routes them into the Python source
  (no string interpolation; the code is the code).
* The timeout is hard-capped at 300 s (matches the
  ``MAX_TIMEOUT_SECONDS`` constant).
* No bare except. Subprocess errors are returned as
  ``ok=False`` with the actual error string.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.toolbox.python_libs import get_library


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_TIMEOUT_SECONDS = 30
MAX_TIMEOUT_SECONDS = 300

# Marker file the executor writes to confirm it actually ran
# (used in tests / honest-degrade verification).
RUN_MARKER_FILENAME = ".kfiosa_python_lib_run.json"

ENV_VAR_PREFIX = "KFIOSA_PYTHON_LIB_"


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class PythonLibError(Exception):
    """Base class for all python_lib executor errors."""


class UnknownLibraryError(PythonLibError):
    """The library name is not in the curated registry."""


class InvalidArgsError(PythonLibError):
    """The args dict is malformed."""


class ExecutionTimeoutError(PythonLibError):
    """The subprocess exceeded the timeout."""


# ---------------------------------------------------------------------------
# Result envelope
# ---------------------------------------------------------------------------

@dataclass
class PythonLibResult:
    """Standard envelope for ``run_python_lib_step`` / ``run_python_lib_code``.

    Has both a ``to_dict()`` method and ``__dict__`` so callers
    that use either pattern work.
    """
    ok: bool
    lib: str
    import_name: str
    returncode: int = -1
    stdout: str = ""
    stderr: str = ""
    error: str = ""
    duration_seconds: float = 0.0
    timed_out: bool = False
    python_executable: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# Args validation
# ---------------------------------------------------------------------------

def _validate_lib_name(lib: Any) -> str:
    """Validate the ``lib`` arg is a non-empty string and is
    in the curated registry. Returns the canonical ``name``
    (pip name) on success."""
    if not isinstance(lib, str) or not lib.strip():
        raise InvalidArgsError("args.lib must be a non-empty string")
    s = lib.strip()
    entry = get_library(s)
    if entry is None:
        raise UnknownLibraryError(
            f"library {s!r} is not in the curated registry; "
            f"add it to core/toolbox/python_libs.PYTHON_LIBRARIES "
            f"first"
        )
    return entry["name"]


def _validate_code(code: Any) -> str:
    """Validate the ``code`` arg is a non-empty string."""
    if not isinstance(code, str) or not code.strip():
        raise InvalidArgsError(
            "args.code must be a non-empty Python source string"
        )
    return textwrap.dedent(code).rstrip() + "\n"


def _validate_timeout(timeout: Any) -> int:
    """Validate the ``timeout_seconds`` arg is a positive int
    not exceeding the cap."""
    if timeout is None:
        return DEFAULT_TIMEOUT_SECONDS
    if not isinstance(timeout, int) or timeout <= 0:
        raise InvalidArgsError(
            "args.timeout_seconds must be a positive integer"
        )
    if timeout > MAX_TIMEOUT_SECONDS:
        return MAX_TIMEOUT_SECONDS
    return int(timeout)


def _validate_env(env: Any) -> Dict[str, str]:
    """Validate the ``env`` arg. Coerces all values to strings."""
    if env is None:
        return {}
    if not isinstance(env, dict):
        raise InvalidArgsError("args.env must be a dict[str, str]")
    out: Dict[str, str] = {}
    for k, v in env.items():
        if not isinstance(k, str) or not k:
            raise InvalidArgsError("env keys must be non-empty strings")
        out[k] = str(v)
    return out


# ---------------------------------------------------------------------------
# Core execution
# ---------------------------------------------------------------------------

def _build_subprocess_env(env: Dict[str, str]) -> Dict[str, str]:
    """Merge the current env with the caller's env. Sensitive
    to the never-inline ground rule: harvested credential
    values are passed as env vars, never as argv tokens or
    embedded in the source code."""
    full = dict(os.environ)
    # The current process's PATH / PYTHONPATH / etc. are
    # preserved by the spread above.
    for k, v in env.items():
        full[k] = v
    return full


def _build_source(import_name: str, code: str) -> str:
    """Wrap the caller's code in a try/except so that any
    import error is reported in stderr with a non-zero
    returncode."""
    return (
        f"import sys, json\n"
        f"import {import_name}\n"
        f"_kfiosa_result = {{'imported': True, 'lib': {import_name!r}}}\n"
        f"try:\n"
        f"    from core.toolbox.exec_python_lib import _record_metadata\n"
        f"    _record_metadata(_kfiosa_result)\n"
        f"except Exception:\n"
        f"    pass\n"
        f"try:\n"
        f"    {textwrap.indent(code, '    ').lstrip()}"
        f"except Exception as _e:\n"
        f"    import traceback\n"
        f"    traceback.print_exc()\n"
        f"    sys.exit(1)\n"
    )


def run_python_lib_code(
    lib: str,
    code: str,
    *,
    cwd: Optional[str] = None,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    env: Optional[Dict[str, str]] = None,
    python_executable: Optional[str] = None,
) -> PythonLibResult:
    """Run a Python source string against the given library.

    Returns a :class:`PythonLibResult`. NEVER fabricates
    output — on error, returns ``ok=False`` with the actual
    error text.
    """
    canonical = _validate_lib_name(lib)
    entry = get_library(canonical) or {}
    import_name = entry.get("import_name", canonical)
    src = _validate_code(code)
    timeout = _validate_timeout(timeout_seconds)
    full_env = _build_subprocess_env(_validate_env(env))
    py = python_executable or sys.executable
    wrapped = _build_source(import_name, src)
    try:
        proc = subprocess.run(
            [py, "-c", wrapped],
            cwd=cwd,
            env=full_env,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as e:
        return PythonLibResult(
            ok=False,
            lib=canonical,
            import_name=import_name,
            returncode=-1,
            stdout=(e.stdout or b"").decode() if isinstance(e.stdout, bytes) else (e.stdout or ""),
            stderr=(e.stderr or b"").decode() if isinstance(e.stderr, bytes) else (e.stderr or ""),
            error=f"timeout after {timeout}s",
            timed_out=True,
            python_executable=py,
        )
    except FileNotFoundError as e:
        return PythonLibResult(
            ok=False,
            lib=canonical,
            import_name=import_name,
            returncode=-1,
            error=f"python executable not found: {e}",
            python_executable=py,
        )
    except Exception as e:
        return PythonLibResult(
            ok=False,
            lib=canonical,
            import_name=import_name,
            returncode=-1,
            error=f"subprocess error: {type(e).__name__}: {e}",
            python_executable=py,
        )
    return PythonLibResult(
        ok=(proc.returncode == 0),
        lib=canonical,
        import_name=import_name,
        returncode=proc.returncode,
        stdout=proc.stdout or "",
        stderr=proc.stderr or "",
        error=(
            "" if proc.returncode == 0
            else f"python exit {proc.returncode}: "
                 + (proc.stderr or "").splitlines()[-1]
        ),
        python_executable=py,
    )


def run_python_lib_step(step: Dict[str, Any]) -> PythonLibResult:
    """Chain-step entry point. Takes a step dict (as the
    orchestrator emits) and dispatches to
    :func:`run_python_lib_code`.

    The per-step ACCEPT gate fires in the orchestrator. This
    executor does NOT call confirm_fn (single-gate invariant).
    """
    if not isinstance(step, dict):
        return PythonLibResult(
            ok=False,
            lib="", import_name="",
            error="step must be a dict",
        )
    if step.get("action") != "run_python_lib":
        return PythonLibResult(
            ok=False,
            lib="", import_name="",
            error=f"unsupported action: {step.get('action')!r}",
        )
    args = step.get("args") or {}
    if not isinstance(args, dict):
        return PythonLibResult(
            ok=False,
            lib="", import_name="",
            error="step.args must be a dict",
        )
    try:
        return run_python_lib_code(
            lib=args.get("lib", ""),
            code=args.get("code", ""),
            cwd=args.get("cwd"),
            timeout_seconds=args.get("timeout_seconds", DEFAULT_TIMEOUT_SECONDS),
            env=args.get("env"),
            python_executable=args.get("python_executable"),
        )
    except (UnknownLibraryError, InvalidArgsError) as e:
        # Surface the validation error in the envelope rather
        # than raising — the orchestrator writes the envelope
        # into the report.
        return PythonLibResult(
            ok=False,
            lib=str(args.get("lib", "")),
            import_name="",
            error=f"{type(e).__name__}: {e}",
        )


# ---------------------------------------------------------------------------
# Internal hook (referenced from the wrapped source)
# ---------------------------------------------------------------------------

def _record_metadata(result: Dict[str, Any]) -> None:
    """Subprocess-internal: record the metadata of the current
    run. Called by the wrapped source so that the metadata
    is part of the subprocess output (not just the parent)."""
    try:
        result["python_executable"] = sys.executable
        result["python_version"] = sys.version
    except Exception:
        pass


# ---------------------------------------------------------------------------
# CLI for ad-hoc operator use
# ---------------------------------------------------------------------------

def _build_argparser():
    import argparse
    p = argparse.ArgumentParser(
        prog="core.toolbox.exec_python_lib",
        description=(
            "Run a one-shot Python snippet that imports a curated "
            "library from the KFIOSA python-libs registry."
        ),
    )
    p.add_argument("lib", help="Library name (pip or import)")
    p.add_argument(
        "--code", required=True,
        help="Python source to execute (the library is pre-imported)",
    )
    p.add_argument("--cwd", default=None)
    p.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT_SECONDS)
    p.add_argument(
        "--env", action="append", default=[],
        help="Extra env var as K=V (repeatable)",
    )
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = _build_argparser().parse_args(argv)
    env: Dict[str, str] = {}
    for kv in args.env:
        if "=" not in kv:
            print(f"bad env: {kv!r}", file=sys.stderr)
            return 2
        k, v = kv.split("=", 1)
        env[k] = v
    res = run_python_lib_code(
        lib=args.lib,
        code=args.code,
        cwd=args.cwd,
        timeout_seconds=args.timeout,
        env=env,
    )
    print(json.dumps(res.to_dict(), indent=2, sort_keys=True))
    return 0 if res.ok else 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
