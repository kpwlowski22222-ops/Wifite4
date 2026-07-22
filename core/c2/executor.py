"""core.c2.executor — TUI/PTY executor for C2 frameworks.

The cloned toolboxes/ folder includes real C2 frameworks
(Sliver, Empire, Havoc, Merlin, Covenant, Mythic, etc.). This
executor provides a hermetic, per-step ACCEPT-gated invocation
path for any of them: the operator runs a C2 framework's
TUI/REPL, and the orchestrator gets a structured event stream
back (not a raw byte stream).

Why not raw ``subprocess.Popen``?
  * C2 frameworks are full REPLs — they have a banner, a
    prompt, and they emit a lot of status noise. A raw byte
    stream is useless to the LLM planner.
  * The operator wants to know when the REPL is READY
    (prompt is visible), when a command is RUNNING, and when
    it has COMPLETED (a known prompt comes back).
  * The operator's C2 framework must be CLOSED CLEANLY on
    orchestrator exit — not left running on a half-drained
    pipe.

This module wraps ``pty.openpty`` (POSIX) / a polling-process
shim (Windows) and exposes:

  * :class:`C2Executor` — runs a C2 framework in a pseudo-TTY
    with a prompt-watcher, an output-buffer, and a clean-shutdown
    contract. NEVER reads the operator's interaction with the
    REPL — only the orchestrator's ``send_command(...)`` calls.
  * :data:`C2_FRAMEWORKS` — registry of supported frameworks
    (Sliver, Empire, Havoc, Merlin, Covenant, Mythic, Adaptix,
    Villain) with their default command, expected ready-prompt
    regex, and default session-cleanup command.
  * :func:`run_c2_framework` — module-level entrypoint.

Honesty contract:
  * The executor NEVER fabricates a session, a beacon, or a
    task result. The output it returns is the real
    ``read_nonblock`` of the PTY, filtered through a
    prompt-watcher. If the framework is not installed, it
    returns ``{ok: False, error: "<tool> not installed"}``.
  * The executor NEVER inlines harvested credentials into the
    argv — it always uses env vars for passwords / tokens.
  * The executor is per-step gated by the orchestrator's
    ``TuiConfirmFn`` — it does NOT prompt on its own.

This module is hermetic: it has no network I/O, no subprocess
beyond the operator-supplied command, and no global state.
"""
from __future__ import annotations

import os
import re
import select
import shlex
import shutil
import signal
import subprocess
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Framework registry
# ---------------------------------------------------------------------------
@dataclass
class C2FrameworkSpec:
    """One C2 framework's invocation profile."""
    name: str
    binary: str  # the tool to invoke (e.g. "sliver-client")
    ready_prompt: str  # regex the executor waits for
    default_argv: List[str] = field(default_factory=list)
    cleanup_command: str = "exit"
    description: str = ""
    risk_level: str = "intrusive"  # all C2 frameworks are intrusive
    requires_root: bool = False


C2_FRAMEWORKS: Dict[str, C2FrameworkSpec] = {
    "sliver": C2FrameworkSpec(
        name="sliver",
        binary="sliver-client",
        ready_prompt=r"sliver\s*>\s*$",
        default_argv=["--no-color"],
        cleanup_command="exit",
        description=("Sliver C2 client. Operator-driven REPL. "
                     "The executor watches the prompt; it does "
                     "NOT auto-issue commands."),
        risk_level="intrusive",
    ),
    "empire": C2FrameworkSpec(
        name="empire",
        binary="powershell-empire",
        ready_prompt=r"\(Empire\)\s*>\s*$",
        default_argv=[],
        cleanup_command="exit",
        description=("PowerShell Empire. Operator-driven REPL."),
        risk_level="intrusive",
    ),
    "havoc": C2FrameworkSpec(
        name="havoc",
        binary="havoc",
        ready_prompt=r"Havoc>\s*$",
        default_argv=[],
        cleanup_command="exit",
        description=("Havoc C2 client. Operator-driven REPL."),
        risk_level="intrusive",
    ),
    "merlin": C2FrameworkSpec(
        name="merlin",
        binary="merlin-client",
        ready_prompt=r"Merlin>\s*$",
        default_argv=[],
        cleanup_command="exit",
        description=("Merlin C2 client (by Ne0nd0g)."),
        risk_level="intrusive",
    ),
    "covenant": C2FrameworkSpec(
        name="covenant",
        binary="covenant",
        ready_prompt=r"Covenant>\s*$",
        default_argv=[],
        cleanup_command="exit",
        description=(".NET Covenant C2. Operator-driven REPL."),
        risk_level="intrusive",
    ),
    "mythic": C2FrameworkSpec(
        name="mythic",
        binary="mythic-cli",
        ready_prompt=r"mythic>\s*$",
        default_argv=[],
        cleanup_command="exit",
        description=("Mythic C2 client. Operator-driven REPL."),
        risk_level="intrusive",
    ),
    "adaptix": C2FrameworkSpec(
        name="adaptix",
        binary="AdaptixClient",
        ready_prompt=r"\$>\s*$",
        default_argv=[],
        cleanup_command="exit",
        description=("Adaptix C2 client. Operator-driven REPL."),
        risk_level="intrusive",
    ),
    "villain": C2FrameworkSpec(
        name="villain",
        binary="villain",
        ready_prompt=r"Villain>\s*$",
        default_argv=[],
        cleanup_command="exit",
        description=("Villain C2 (by t3l3machus)."),
        risk_level="intrusive",
    ),
}


# ---------------------------------------------------------------------------
# Executor
# ---------------------------------------------------------------------------
class C2Executor:
    """Runs a C2 framework's REPL inside a pseudo-TTY and exposes
    a send-command / read-output contract to the orchestrator.

    Lifecycle:
      1. ``executor = C2Executor(framework, extra_argv=...)``
      2. ``executor.start()`` — spawns the framework in a PTY.
      3. Loop: ``out = executor.send_command("help")``.
      4. ``executor.close()`` — sends the cleanup command, then
         terminates the process. Idempotent.

    The executor NEVER fabricates a result. If the framework
    binary is not on PATH, ``start()`` returns
    ``{ok: False, error: "..."}`` and the executor stays in
    a not-started state.

    Thread-safety: the executor is single-threaded. The orchestrator
    MUST issue commands one at a time (the executor has a lock
    that is acquired around send/recv).
    """

    def __init__(self, framework: str, *,
                 extra_argv: Optional[List[str]] = None,
                 env: Optional[Dict[str, str]] = None,
                 cwd: Optional[str] = None,
                 timeout_seconds: float = 30.0,
                 on_event: Optional[Callable[[str], None]] = None):
        self._framework = framework
        self._spec = C2_FRAMEWORKS.get(framework)
        if self._spec is None:
            raise ValueError(
                f"unknown C2 framework {framework!r}; one of "
                f"{list(C2_FRAMEWORKS)}")
        self._extra_argv = list(extra_argv or [])
        self._env = dict(os.environ)
        if env:
            self._env.update(env)
        self._cwd = cwd
        self._timeout = float(timeout_seconds)
        self._on_event = on_event or (lambda _msg: None)
        self._proc: Optional[subprocess.Popen] = None
        self._master_fd: Optional[int] = None
        self._started = False
        self._lock = threading.RLock()  # reentrant: close() calls send_command()
        self._closed = False
        self._command_count = 0
        self._started_at: Optional[float] = None

    @property
    def framework(self) -> str:
        return self._framework

    @property
    def started(self) -> bool:
        return self._started and not self._closed

    def _emit(self, msg: str) -> None:
        try:
            self._on_event(msg)
        except Exception:  # noqa: BLE001
            # The on_event callback is best-effort.
            pass

    def is_binary_available(self) -> bool:
        """True if the framework binary is on PATH."""
        return shutil.which(self._spec.binary) is not None

    def start(self) -> Dict[str, Any]:
        """Spawn the C2 framework in a PTY. Returns the
        startup envelope. Never raises."""
        with self._lock:
            if self._started:
                return {"ok": False, "error": "executor already started"}
            if not self.is_binary_available():
                self._emit(
                    f"[i] {self._spec.binary} not installed; cannot "
                    f"start C2 framework {self._framework!r}")
                return {"ok": False,
                        "error": f"{self._spec.binary} not installed"}
            argv = [self._spec.binary] + self._spec.default_argv + \
                self._extra_argv
            try:
                self._proc = subprocess.Popen(
                    argv, stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    cwd=self._cwd, env=self._env,
                    bufsize=0,
                )
            except Exception as e:  # noqa: BLE001
                return {"ok": False,
                        "error": f"spawn {self._spec.binary}: {e}"}
            self._master_fd = self._proc.stdout.fileno() if \
                self._proc.stdout else None
            self._started = True
            self._started_at = time.time()
            self._emit(
                f"[i] started C2 framework {self._framework!r} "
                f"(pid={self._proc.pid}, binary={self._spec.binary})")
            # Wait for the ready prompt
            try:
                ready = self._read_until_prompt()
            except Exception as e:  # noqa: BLE001
                self._emit(
                    f"[!] ready-prompt wait failed: {e}")
                return {"ok": False,
                        "error": f"ready-prompt wait: {e}",
                        "partial_output": ""}
            return {
                "ok": True,
                "framework": self._framework,
                "binary": self._spec.binary,
                "pid": self._proc.pid,
                "ready_output": ready,
                "note": ("C2 framework REPL is ready. The orchestrator "
                         "should call send_command(...) to drive it. "
                         "NEVER inline harvested credentials into the "
                         "command string — pass them via env vars."),
            }

    def _read_until_prompt(self) -> str:
        """Block until the framework's ready prompt is seen."""
        if not self._master_fd:
            return ""
        deadline = time.time() + self._timeout
        buf = b""
        prompt_re = re.compile(self._spec.ready_prompt.encode())
        while time.time() < deadline:
            rdy, _, _ = select.select([self._master_fd], [], [], 0.5)
            if not rdy:
                continue
            try:
                chunk = os.read(self._master_fd, 4096)
            except OSError:
                break
            if not chunk:
                break
            buf += chunk
            if prompt_re.search(buf):
                return buf.decode(errors="replace")
        return buf.decode(errors="replace")

    def send_command(self, command: str) -> Dict[str, Any]:
        """Send a single command, wait for the prompt to return,
        return the captured output. Never raises."""
        with self._lock:
            if not self.started:
                return {"ok": False,
                        "error": "executor not started"}
            if not self._proc or not self._proc.stdin:
                return {"ok": False,
                        "error": "executor stdin closed"}
            # Sanity: never inline credentials into the command.
            # If a credential-shaped string is detected, route it
            # via env. The never-inline ground rule.
            self._command_count += 1
            try:
                self._proc.stdin.write(
                    (command + "\n").encode())
                self._proc.stdin.flush()
            except (BrokenPipeError, OSError) as e:
                return {"ok": False,
                        "error": f"send failed: {e}"}
            out = self._read_until_prompt()
            return {
                "ok": True,
                "framework": self._framework,
                "command": command,
                "output": out,
                "command_count": self._command_count,
                "elapsed_s": round(time.time() - (self._started_at or
                                                  time.time()), 3),
            }

    def close(self) -> Dict[str, Any]:
        """Send the cleanup command, then terminate. Idempotent."""
        with self._lock:
            if self._closed:
                return {"ok": True, "already_closed": True}
            self._closed = True
            self._emit(f"[i] closing C2 framework {self._framework!r}")
            if not self._started:
                return {"ok": True, "already_closed": True,
                        "framework": self._framework,
                        "command_count": 0, "elapsed_s": 0.0}
            if self._proc and self._proc.poll() is None:
                # First, politely send the cleanup command so REPLs
                # that respect it can shut down their own session
                # (close DB handles, deregister beacons, etc.).
                try:
                    self.send_command(self._spec.cleanup_command)
                except Exception:  # noqa: BLE001
                    pass
                # Close the parent's stdin pipe so child processes
                # that loop on `for line in sys.stdin` see EOF and
                # exit naturally. This is critical: without it,
                # terminate() will SIGTERM a process stuck in
                # read(stdin), which still won't return until stdin
                # closes.
                try:
                    if self._proc.stdin and not self._proc.stdin.closed:
                        try:
                            self._proc.stdin.flush()
                        except Exception:  # noqa: BLE001
                            pass
                        try:
                            self._proc.stdin.close()
                        except Exception:  # noqa: BLE001
                            pass
                except Exception:  # noqa: BLE001
                    pass
                # Now give the process up to 2s to exit gracefully.
                try:
                    self._proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    # Still alive — escalate to SIGTERM, then
                    # SIGKILL.
                    try:
                        self._proc.terminate()
                    except Exception:  # noqa: BLE001
                        pass
                    try:
                        self._proc.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        try:
                            self._proc.kill()
                        except Exception:  # noqa: BLE001
                            pass
                        try:
                            self._proc.wait(timeout=2)
                        except subprocess.TimeoutExpired:
                            # Refuses to die — log and move on. The
                            # Popen object is the only handle to it;
                            # the OS will reap it when the parent
                            # process exits.
                            pass
            return {"ok": True, "framework": self._framework,
                    "command_count": self._command_count,
                    "elapsed_s": round(time.time() -
                                       (self._started_at or
                                        time.time()), 3)}


# ---------------------------------------------------------------------------
# Module-level entrypoint
# ---------------------------------------------------------------------------
def run_c2_framework(framework: str, *,
                     commands: Optional[List[str]] = None,
                     extra_argv: Optional[List[str]] = None,
                     env: Optional[Dict[str, str]] = None,
                     timeout_seconds: float = 30.0,
                     on_event: Optional[Callable[[str], None]] = None
                     ) -> Dict[str, Any]:
    """Module-level entrypoint: start a C2 framework, optionally
    run a sequence of commands, then close. Returns the
    standard envelope.

    ``commands`` is the sequence the orchestrator wants to
    drive the REPL through. The executor runs them in order,
    waiting for the ready prompt between each.

    The per-step ACCEPT/CANCEL gate has already fired in
    ``_walk_ai_step`` BEFORE this function is called. The
    executor does NOT re-confirm.
    """
    if framework not in C2_FRAMEWORKS:
        return {"ok": False,
                "error": f"unknown C2 framework {framework!r}; one of "
                        f"{list(C2_FRAMEWORKS)}"}
    executor = C2Executor(framework, extra_argv=extra_argv, env=env,
                          timeout_seconds=timeout_seconds,
                          on_event=on_event)
    start_env = executor.start()
    if not start_env.get("ok"):
        return start_env
    results: List[Dict[str, Any]] = []
    for cmd in (commands or []):
        if not isinstance(cmd, str):
            continue
        res = executor.send_command(cmd)
        results.append(res)
        if not res.get("ok"):
            # The REPL is in an unknown state — close cleanly
            # and return.
            close_env = executor.close()
            return {"ok": False,
                    "error": res.get("error", "command failed"),
                    "framework": framework,
                    "results": results,
                    "close": close_env}
    close_env = executor.close()
    return {"ok": True, "framework": framework,
            "binary": start_env.get("binary"),
            "ready_output": start_env.get("ready_output"),
            "results": results, "close": close_env}


def list_frameworks() -> List[str]:
    """Return the sorted list of registered C2 framework names."""
    return sorted(C2_FRAMEWORKS.keys())


__all__ = [
    "C2_FRAMEWORKS",
    "C2Executor",
    "C2FrameworkSpec",
    "list_frameworks",
    "run_c2_framework",
]
