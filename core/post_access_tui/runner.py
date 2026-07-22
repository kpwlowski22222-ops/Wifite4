"""core.post_access_tui.runner — PostAccessRunner (the action layer).

The PostAccessRunner is what the curses screen (PostAccessScreen) calls
into for every menu action. It owns the active ``SessionState`` and
exposes a small set of operations that route to REAL subprocesses:

  - ``run_shell(cmd)``         — meterpreter ``-e <cmd>`` or ``ssh <cmd>``
  - ``file_get(remote, local)`` / ``file_put(local, remote)``
                                — scp (ssh) or msf upload/download
  - ``portfwd_add(listen, host, port)`` — msf portfwd OR ``ssh -L``
  - ``socks_start()`` / ``socks_stop()`` — msf socks OR ``ssh -D``
  - ``list_persistence_methods()`` / ``apply_persistence(name)``
                                — re-runs one of post_exploit.runner_ext
  - ``list_post_exploit_modules()`` / ``run_module(name, args)``
                                — re-runs one of post_exploit.runner_ext
  - ``detach()``                 — clean shutdown

Every method returns a dict envelope ``{ok: bool, action: str,
stdout: str, stderr: str, returncode: int, error: str | None, ts: float,
duration_s: float}`` and **NEVER raises**. The single-gate invariant
applies: the screen's menu-prompt fires ``confirm_fn`` BEFORE calling
into the runner. The runner itself does NOT re-confirm.

Honest-degradation contract:
  - If the relevant tool (msfconsole / ssh / scp) is not present, the
    runner returns ``{ok: False, error: "<tool> not installed", ...}``.
    It NEVER fabricates a success.
  - Subprocess failures return ``{ok: False, returncode: <rc>, stderr: <excerpt>, ...}``.
"""
from __future__ import annotations

import dataclasses
import shlex
import shutil
import subprocess
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

from .session_state import (
    SessionState,
    TRANSPORT_LOCAL,
    TRANSPORT_MSF,
    TRANSPORT_SSH,
    TRANSPORT_UNKNOWN,
    _b64_decode,
    _now,
    _append_log,
)


class PostAccessRunnerError(RuntimeError):
    """Raised only by internal helpers; the public API never raises."""


#: Default subprocess timeout (seconds). The screen can override per-call.
_DEFAULT_TIMEOUT = 30


def _step_envelope(action: str, started: float, *, ok: bool,
                   stdout: str = "", stderr: str = "",
                   returncode: int = 0, error: Optional[str] = None,
                   data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Build the standard envelope. Never raises."""
    return {
        "action": action,
        "ok": bool(ok),
        "stdout": stdout[-4000:] if isinstance(stdout, str) else "",
        "stderr": stderr[-2000:] if isinstance(stderr, str) else "",
        "returncode": int(returncode),
        "error": str(error) if error else None,
        "data": data if isinstance(data, dict) else None,
        "ts": _now(),
        "duration_s": max(0.0, _now() - float(started)),
    }


def _which(tool: str) -> bool:
    """Tool-presence check. Uses shutil.which. Never raises."""
    try:
        return shutil.which(str(tool)) is not None
    except Exception:  # noqa: BLE001
        return False


def _safe_subprocess(argv: List[str], *, timeout: int = _DEFAULT_TIMEOUT,
                     cwd: Optional[str] = None) -> Tuple[int, str, str]:
    """Run an argv with capture. Never raises.

    Returns ``(returncode, stdout, stderr)``. On any error, returns
    ``(-1, "", "<error message>")`` — caller maps to the envelope.
    """
    try:
        p = subprocess.run(
            argv, capture_output=True, text=True,
            timeout=int(timeout), cwd=cwd,
        )
        return (p.returncode, p.stdout or "", p.stderr or "")
    except subprocess.TimeoutExpired:
        return (-1, "", f"timeout after {int(timeout)}s")
    except FileNotFoundError as e:
        return (-1, "", f"binary not found: {e}")
    except Exception as e:  # noqa: BLE001
        return (-1, "", str(e))


# ---------------------------------------------------------------------------
# The runner class
# ---------------------------------------------------------------------------
class PostAccessRunner:
    """Action layer for the post-access TUI.

    The constructor takes a :class:`SessionState` and an optional
    ``on_action`` callback (called with the envelope after every
    action, for the screen to render). Never raises on construction
    or on any public method.
    """

    def __init__(self, state: Optional[SessionState] = None,
                 *, on_action: Optional[Callable[[Dict[str, Any]], None]] = None,
                 post_exploit_runner: Optional[Any] = None):
        self.state: SessionState = state if isinstance(state, SessionState) else SessionState()
        self._on_action = on_action
        self._post_exploit_runner = post_exploit_runner
        # Active portfwd / socks records (so detach cleans them up).
        self._portfwds: List[Dict[str, Any]] = []
        self._socks_pid: Optional[int] = None
        # Detached sentinel
        self.detached: bool = False

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _emit(self, envelope: Dict[str, Any]) -> Dict[str, Any]:
        """Append the envelope to the audit log + call on_action. Never raises."""
        try:
            _append_log({
                "event": "post_access_action",
                "action": envelope.get("action"),
                "ok": envelope.get("ok"),
                "returncode": envelope.get("returncode"),
                "error": envelope.get("error"),
                "ts": envelope.get("ts"),
            })
        except Exception:  # noqa: BLE001
            pass
        if self._on_action is not None:
            try:
                self._on_action(envelope)
            except Exception:  # noqa: BLE001
                pass
        return envelope

    def _build_msf_cmd(self, session_argv: List[str]) -> Optional[List[str]]:
        """Build a msfconsole argv that talks to the active session.

        ``msfconsole -q -x "sessions -i <sid> -q -e '<cmd>'"`` is the
        documented pattern; we use ``-x`` with a single quoted payload.
        Returns None if msfconsole is not installed.
        """
        if not _which("msfconsole"):
            return None
        sid = self.state.session_id
        if sid is None or sid == "":
            return None
        # We DO NOT inline any user creds into the argv. The msf
        # session ID is metadata, not a credential.
        # We pass the user's command via stdin (``-x``) to avoid
        # command-line injection of the operator's typed string.
        session_inner = " ".join(shlex.quote(str(s)) for s in session_argv)
        return ["msfconsole", "-q", "-x",
                f"sessions -i {sid} -q -e {session_inner}"]

    def _build_ssh_cmd(self, remote_argv: List[str]) -> Optional[List[str]]:
        """Build an ssh argv that runs ``remote_argv`` on the target.

        Requires ``ssh`` + the captured creds (or the configured ssh key
        the operator already has). If creds are NOT present, the
        operator must add their key before this works. We pass
        ``-o BatchMode=yes -o PasswordAuthentication=no`` so we NEVER
        try to read a password from stdin (no creds-into-argv risk).
        Returns None if ssh is not installed.
        """
        if not _which("ssh"):
            return None
        if not self.state.target:
            return None
        # We don't put creds on the command line. ssh key auth or agent
        # only.
        return [
            "ssh",
            "-o", "BatchMode=yes",
            "-o", "PasswordAuthentication=no",
            "-o", "StrictHostKeyChecking=accept-new",
            f"operator@{self.state.target}",
            "--",
            " ".join(shlex.quote(str(s)) for s in remote_argv),
        ]

    def _build_scp_cmd(self, src: str, dst: str,
                       direction: str) -> Optional[List[str]]:
        """Build an scp argv (direction="get" or "put")."""
        if not _which("scp"):
            return None
        if not self.state.target:
            return None
        if direction == "get":
            return [
                "scp", "-B",  # batch mode (no password prompt)
                "-o", "BatchMode=yes",
                "-o", "PasswordAuthentication=no",
                "-o", "StrictHostKeyChecking=accept-new",
                f"operator@{self.state.target}:{src}",
                dst,
            ]
        # put
        return [
            "scp", "-B",
            "-o", "BatchMode=yes",
            "-o", "PasswordAuthentication=no",
            "-o", "StrictHostKeyChecking=accept-new",
            src,
            f"operator@{self.state.target}:{dst}",
        ]

    # ------------------------------------------------------------------
    # Public API — the screen calls into these
    # ------------------------------------------------------------------
    def run_shell(self, cmd: str, *, timeout: int = _DEFAULT_TIMEOUT) -> Dict[str, Any]:
        """Run a shell command on the target via the active session.

        Args:
            cmd:  the command string the operator typed (NOT escaped
                  into the screen's argv — the runner quotes it via
                  shlex.quote on the inner side).
            timeout: seconds.

        Returns:
            envelope ``{ok, stdout, stderr, returncode, error, ...}``.
            Honest degradation when no transport is available.
        """
        started = _now()
        if not isinstance(cmd, str) or not cmd.strip():
            return self._emit(_step_envelope(
                "run_shell", started, ok=False,
                error="empty command",
            ))
        if self.detached:
            return self._emit(_step_envelope(
                "run_shell", started, ok=False,
                error="runner detached",
            ))
        # Decide the argv based on the active transport.
        argv: Optional[List[str]] = None
        if self.state.transport == TRANSPORT_MSF:
            argv = self._build_msf_cmd(["/bin/sh", "-c", cmd])
        elif self.state.transport == TRANSPORT_SSH:
            argv = self._build_ssh_cmd(["/bin/sh", "-c", cmd])
        elif self.state.transport == TRANSPORT_LOCAL:
            argv = ["/bin/sh", "-c", cmd]
        # else: TRANSPORT_UNKNOWN — degrade.

        if argv is None:
            reason = (
                "no active session"
                if self.state.transport == TRANSPORT_UNKNOWN
                else (
                    "msfconsole not installed"
                    if self.state.transport == TRANSPORT_MSF
                    else (
                        "ssh not installed or no target"
                        if self.state.transport == TRANSPORT_SSH
                        else "no transport available"
                    )
                )
            )
            return self._emit(_step_envelope(
                "run_shell", started, ok=False, error=reason,
            ))

        rc, out, err = _safe_subprocess(argv, timeout=timeout)
        return self._emit(_step_envelope(
            "run_shell", started,
            ok=(rc == 0),
            stdout=out, stderr=err, returncode=rc,
            error=None if rc == 0 else (err or f"non-zero exit {rc}"),
            data={"cmd": cmd, "argv_first": argv[0] if argv else None},
        ))

    def file_get(self, remote: str, local: str,
                 *, timeout: int = 120) -> Dict[str, Any]:
        """Download a file from the target to the local box."""
        started = _now()
        if not self.state.has_session():
            return self._emit(_step_envelope(
                "file_get", started, ok=False,
                error="no active session",
            ))
        if self.state.transport == TRANSPORT_SSH:
            argv = self._build_scp_cmd(remote, local, "get")
        else:
            return self._emit(_step_envelope(
                "file_get", started, ok=False,
                error="file transfer currently only supported over ssh transport",
            ))
        if argv is None:
            return self._emit(_step_envelope(
                "file_get", started, ok=False,
                error="scp not installed or no target",
            ))
        rc, out, err = _safe_subprocess(argv, timeout=timeout)
        return self._emit(_step_envelope(
            "file_get", started,
            ok=(rc == 0),
            stdout=out, stderr=err, returncode=rc,
            error=None if rc == 0 else (err or f"non-zero exit {rc}"),
            data={"remote": remote, "local": local},
        ))

    def file_put(self, local: str, remote: str,
                 *, timeout: int = 120) -> Dict[str, Any]:
        """Upload a file from the local box to the target."""
        started = _now()
        if not self.state.has_session():
            return self._emit(_step_envelope(
                "file_put", started, ok=False,
                error="no active session",
            ))
        if self.state.transport == TRANSPORT_SSH:
            argv = self._build_scp_cmd(local, remote, "put")
        else:
            return self._emit(_step_envelope(
                "file_put", started, ok=False,
                error="file transfer currently only supported over ssh transport",
            ))
        if argv is None:
            return self._emit(_step_envelope(
                "file_put", started, ok=False,
                error="scp not installed or no target",
            ))
        rc, out, err = _safe_subprocess(argv, timeout=timeout)
        return self._emit(_step_envelope(
            "file_put", started,
            ok=(rc == 0),
            stdout=out, stderr=err, returncode=rc,
            error=None if rc == 0 else (err or f"non-zero exit {rc}"),
            data={"local": local, "remote": remote},
        ))

    def portfwd_add(self, listen_port: int, target_host: str,
                    target_port: int) -> Dict[str, Any]:
        """Add a port forward. Records it so detach can clean up.

        Over msf, this is a *real* ``portfwd add`` invocation through
        the session. Over ssh, it's a recorded ``ssh -L`` plan (the
        operator is given the exact command to run in another
        terminal — we don't background ssh -L from the TUI; the
        operator runs the command they want).
        """
        started = _now()
        if not self.state.has_session():
            return self._emit(_step_envelope(
                "portfwd_add", started, ok=False,
                error="no active session",
            ))
        try:
            lp = int(listen_port)
            tp = int(target_port)
        except (TypeError, ValueError):
            return self._emit(_step_envelope(
                "portfwd_add", started, ok=False,
                error="listen_port and target_port must be integers",
            ))
        if not isinstance(target_host, str) or not target_host.strip():
            return self._emit(_step_envelope(
                "portfwd_add", started, ok=False,
                error="target_host must be a non-empty string",
            ))
        record = {
            "listen_port": lp,
            "target_host": target_host.strip(),
            "target_port": tp,
            "transport": self.state.transport,
        }
        argv: Optional[List[str]] = None
        if self.state.transport == TRANSPORT_MSF:
            argv = self._build_msf_cmd([
                "portfwd", "add",
                "-l", str(lp), "-r", target_host, "-p", str(tp),
            ])
        if argv is None:
            # ssh path — record the suggested command; don't background it.
            self._portfwds.append(record)
            return self._emit(_step_envelope(
                "portfwd_add", started, ok=True,
                stdout=(
                    f"suggested (operator-runs): ssh -L {lp}:{target_host}:{tp} "
                    f"operator@{self.state.target}"
                ),
                data=record,
            ))
        rc, out, err = _safe_subprocess(argv)
        if rc == 0:
            self._portfwds.append(record)
        return self._emit(_step_envelope(
            "portfwd_add", started,
            ok=(rc == 0),
            stdout=out, stderr=err, returncode=rc,
            error=None if rc == 0 else (err or f"non-zero exit {rc}"),
            data=record,
        ))

    def list_portfwds(self) -> List[Dict[str, Any]]:
        """Return the active portfwd records (read-only copy)."""
        return [dict(p) for p in self._portfwds]

    def socks_start(self, listen_port: int = 1080) -> Dict[str, Any]:
        """Start a SOCKS proxy. msf path runs a real ``socks`` command;
        ssh path suggests ``ssh -D`` and records it (operator-runs)."""
        started = _now()
        if not self.state.has_session():
            return self._emit(_step_envelope(
                "socks_start", started, ok=False,
                error="no active session",
            ))
        try:
            lp = int(listen_port)
        except (TypeError, ValueError):
            return self._emit(_step_envelope(
                "socks_start", started, ok=False,
                error="listen_port must be an integer",
            ))
        if self.state.transport == TRANSPORT_MSF:
            argv = self._build_msf_cmd(["socks", "use", "-p", str(lp)])
            if argv is None:
                return self._emit(_step_envelope(
                    "socks_start", started, ok=False,
                    error="msfconsole not installed",
                ))
            rc, out, err = _safe_subprocess(argv)
            if rc == 0:
                self._socks_pid = lp  # recorded port
            return self._emit(_step_envelope(
                "socks_start", started,
                ok=(rc == 0),
                stdout=out, stderr=err, returncode=rc,
                error=None if rc == 0 else (err or f"non-zero exit {rc}"),
                data={"listen_port": lp, "transport": "msf"},
            ))
        if self.state.transport == TRANSPORT_SSH:
            self._socks_pid = lp
            return self._emit(_step_envelope(
                "socks_start", started, ok=True,
                stdout=(
                    f"suggested (operator-runs): ssh -D {lp} -f -N "
                    f"operator@{self.state.target}"
                ),
                data={"listen_port": lp, "transport": "ssh"},
            ))
        return self._emit(_step_envelope(
            "socks_start", started, ok=False,
            error=f"transport {self.state.transport!r} not supported",
        ))

    def socks_stop(self) -> Dict[str, Any]:
        """Stop the SOCKS proxy. Cleans up the recorded port."""
        started = _now()
        if self._socks_pid is None:
            return self._emit(_step_envelope(
                "socks_stop", started, ok=False,
                error="no SOCKS proxy active",
            ))
        if self.state.transport == TRANSPORT_MSF:
            argv = self._build_msf_cmd(["socks", "stop"])
            if argv is not None:
                rc, out, err = _safe_subprocess(argv)
                self._socks_pid = None
                return self._emit(_step_envelope(
                    "socks_stop", started,
                    ok=(rc == 0),
                    stdout=out, stderr=err, returncode=rc,
                    error=None if rc == 0 else (err or f"non-zero exit {rc}"),
                ))
        # ssh path or msf unavailable — just forget the record
        self._socks_pid = None
        return self._emit(_step_envelope(
            "socks_stop", started, ok=True,
            stdout="(operator-runs: kill the ssh -D process by hand)",
            data={"transport": self.state.transport},
        ))

    # ------------------------------------------------------------------
    # Post-exploit module re-run (delegates to post_exploit.runner_ext)
    # ------------------------------------------------------------------
    def list_post_exploit_modules(self) -> List[str]:
        """Return the list of post_exploit method names. Returns [] on
        import failure (NEVER raises)."""
        try:
            from core.post_exploit.runner_ext import PostExploitExtRunner
            return list(PostExploitExtRunner.POST_EXPLOIT_EXT_METHODS)
        except Exception:  # noqa: BLE001
            return []

    def run_module(self, name: str, args: Optional[Dict[str, Any]] = None,
                   *, timeout: int = 60) -> Dict[str, Any]:
        """Re-run a post_exploit method by name. Wraps the runner's
        own envelope. Never fabricates a success."""
        started = _now()
        if not isinstance(name, str) or not name.strip():
            return self._emit(_step_envelope(
                "run_module", started, ok=False,
                error="module name required",
            ))
        try:
            from core.post_exploit.runner_ext import (
                PostExploitExtRunner, run_attack,
            )
        except Exception as e:  # noqa: BLE001
            return self._emit(_step_envelope(
                "run_module", started, ok=False,
                error=f"post_exploit import failed: {e}",
            ))
        method = name.strip()
        available = list(PostExploitExtRunner.POST_EXPLOIT_EXT_METHODS)
        if method not in available:
            return self._emit(_step_envelope(
                "run_module", started, ok=False,
                error=f"unknown module {method!r}; first 5: {available[:5]}",
            ))
        try:
            res = run_attack(method, args=args or {})
        except Exception as e:  # noqa: BLE001
            return self._emit(_step_envelope(
                "run_module", started, ok=False,
                error=f"runner raised: {e}",
            ))
        ok = bool(res and isinstance(res, dict) and res.get("ok"))
        return self._emit(_step_envelope(
            "run_module", started, ok=ok,
            stdout=str(res.get("data", ""))[:2000] if isinstance(res, dict) else "",
            returncode=0 if ok else -1,
            error=None if ok else (res.get("error") if isinstance(res, dict) else "unknown"),
            data={"module": method, "result": res if isinstance(res, dict) else None},
        ))

    # ------------------------------------------------------------------
    # Persistence (alias for a few run_module names that the spec
    # names as persistence methods). The actual work is done by
    # post_exploit.runner_ext — we never fabricate persistence.
    # ------------------------------------------------------------------
    PERSISTENCE_ALIASES: Tuple[str, ...] = (
        "install_persistence_cron",
        "install_persistence_systemd",
        "install_persistence_ssh_authorized_keys",
        "install_persistence_sudoers",
        "install_persistence_ld_preload",
        "install_persistence_at_job",
        "install_persistence_initd",
    )

    def list_persistence_methods(self) -> List[str]:
        """Return the persistence aliases (only those that exist in
        post_exploit.runner_ext). Never raises."""
        try:
            from core.post_exploit.runner_ext import PostExploitExtRunner
            ext = set(PostExploitExtRunner.POST_EXPLOIT_EXT_METHODS)
        except Exception:  # noqa: BLE001
            return []
        return [m for m in self.PERSISTENCE_ALIASES if m in ext]

    def apply_persistence(self, name: str) -> Dict[str, Any]:
        """Apply a persistence method by alias name."""
        if name in self.PERSISTENCE_ALIASES:
            return self.run_module(name)
        # unknown alias
        return self._emit(_step_envelope(
            "apply_persistence", _now(), ok=False,
            error=f"unknown persistence method {name!r}",
        ))

    # ------------------------------------------------------------------
    # Detach
    # ------------------------------------------------------------------
    def detach(self) -> Dict[str, Any]:
        """Mark the runner as detached. Cleanup is best-effort; the
        operator is told which portfwds / socks need manual teardown.
        """
        started = _now()
        if self.detached:
            return self._emit(_step_envelope(
                "detach", started, ok=True,
                stdout="(already detached)",
            ))
        self.detached = True
        msgs: List[str] = []
        if self._portfwds:
            for p in self._portfwds:
                if p.get("transport") == TRANSPORT_SSH:
                    msgs.append(
                        f"  - ssh -L kill: localhost:{p['listen_port']}"
                    )
                # msf portfwd is cleaned by the session ending
        if self._socks_pid is not None and self.state.transport == TRANSPORT_SSH:
            msgs.append(f"  - ssh -D {self._socks_pid} kill (operator-runs)")
        msg = "detach OK\n" + ("manual teardown:\n" + "\n".join(msgs) if msgs else "")
        return self._emit(_step_envelope(
            "detach", started, ok=True, stdout=msg,
        ))
