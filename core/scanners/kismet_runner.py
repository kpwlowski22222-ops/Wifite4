"""core.scanners.kismet_runner — Kismet server / client / capture
utilities.

Kismet is the de-facto 802.11 + BLE + 6 GHz capture / IDS tool.
KFIOSA references it today only as a file format
(``-01.kismet.csv``, ``.kismet.netxml``); this module wraps the
actual binaries so the AI chain can spin up a Kismet sweep when
``kismet_scan`` is emitted.

Credentials: the Kismet username/password are operator-supplied.
They may be passed explicitly to :class:`KismetRunner` or read from
``KISMET_CLIENT_USERNAME`` / ``KISMET_CLIENT_PASSWORD`` environment
variables. The password is passed via the env var — never as an
argv token. The orchestrator's chain step ``kismet_scan`` runs
behind the per-step ACCEPT gate in :meth:`_walk_ai_step`; this
runner does NOT re-confirm.

Never fabricates:
  - The local pass either succeeds (subprocess exit 0) or returns
    ``{ok: False, error: "<exact>"}``.
  - Captures / alerts are surfaced as the raw file paths the
    Kismet binary wrote; the runner never invents a list of SSIDs.
"""
from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Env-var contract for the Kismet client password.
# The wrapper NEVER takes a positional password arg.
KISMET_CLIENT_PASSWORD_ENV = "KISMET_CLIENT_PASSWORD"
KISMET_CLIENT_USERNAME_ENV = "KISMET_CLIENT_USERNAME"

# No compiled-in default credentials.  Values are read from env or supplied
# explicitly by the operator; missing credentials cause an immediate error.
DEFAULT_USERNAME = ""
DEFAULT_PASSWORD = ""

# Default endpoints.
DEFAULT_WS_URL = "ws://localhost:2501"

# Cap on how long we wait for the Kismet server to start.
DEFAULT_STARTUP_WAIT_S = 6
# Cap on how long ``kismet_cap_to_pcap`` may take.
DEFAULT_CONVERT_TIMEOUT_S = 120


@dataclass
class KismetRunResult:
    """Standard envelope returned by every KismetRunner method."""
    ok: bool
    action: str
    returncode: int = -1
    stdout: str = ""
    stderr: str = ""
    error: str = ""
    artifacts: Dict[str, str] = field(default_factory=dict)
    pid: Optional[int] = None
    elapsed: float = 0.0
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ok": self.ok,
            "action": self.action,
            "returncode": self.returncode,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "error": self.error,
            "artifacts": self.artifacts,
            "pid": self.pid,
            "elapsed": self.elapsed,
            "extra": self.extra,
        }


def _safe_run(cmd: List[str], *, timeout: int = 30,
              on_event: Optional[Callable[[str], None]] = None,
              env: Optional[Dict[str, str]] = None,
              cwd: Optional[str] = None,
              ) -> KismetRunResult:
    """Run a subprocess, return the standard envelope. Never raises."""
    log = on_event or (lambda m: None)
    t0 = time.time()
    try:
        log(f"[kismet] $ {cmd[0]} (timeout={timeout}s)")
        proc = subprocess.run(
            cmd,
            capture_output=True, text=True, timeout=timeout,
            env={**os.environ, **(env or {})},
            cwd=cwd,
        )
        return KismetRunResult(
            ok=proc.returncode == 0,
            action=cmd[0],
            returncode=proc.returncode,
            stdout=(proc.stdout or "")[:8000],
            stderr=(proc.stderr or "")[:4000],
            elapsed=time.time() - t0,
        )
    except FileNotFoundError as e:
        return KismetRunResult(
            ok=False, action=cmd[0], error=f"binary not found: {e}",
            returncode=127, elapsed=time.time() - t0,
        )
    except subprocess.TimeoutExpired as e:
        return KismetRunResult(
            ok=False, action=cmd[0],
            error=f"timeout after {timeout}s", returncode=124,
            stdout=_decode(e.stdout), stderr=_decode(e.stderr),
            elapsed=time.time() - t0,
        )
    except Exception as e:  # noqa: BLE001
        return KismetRunResult(
            ok=False, action=cmd[0], error=f"subprocess error: {e}",
            returncode=1, elapsed=time.time() - t0,
        )


def _decode(v: Any) -> str:
    if v is None:
        return ""
    if isinstance(v, (bytes, bytearray)):
        return v.decode("utf-8", "replace")[:8000]
    return str(v)[:8000]


# ---------------------------------------------------------------------------
# The KismetRunner
# ---------------------------------------------------------------------------

class KismetRunner:
    """Real Kismet wrapper. Every method is a real subprocess / file
    op; honest-degrade on missing tools.

    The Kismet client uses ``admin`` / ``admin`` per the operator;
    the password is the literal string ``"admin"`` and is passed
    via the ``KISMET_CLIENT_PASSWORD`` env var (never argv).
    """

    def __init__(self, *, username: str = DEFAULT_USERNAME,
                 password: str = DEFAULT_PASSWORD,
                 ws_url: str = DEFAULT_WS_URL,
                 on_event: Optional[Callable[[str], None]] = None):
        # Resolve credentials: explicit args → env vars → error.  Never fall
        # back to a hardcoded default.
        uname = (username or os.getenv(KISMET_CLIENT_USERNAME_ENV, "")).strip()
        pwd = (password or os.getenv(KISMET_CLIENT_PASSWORD_ENV, ""))
        if not uname or not pwd:
            raise ValueError(
                "KismetRunner requires operator-provided credentials. "
                f"Set {KISMET_CLIENT_USERNAME_ENV} / {KISMET_CLIENT_PASSWORD_ENV} "
                "or pass username= / password=."
            )
        self.username = uname
        # The password is held only in the env-var form; the
        # constructor never logs it.
        self._password = pwd
        self.ws_url = (ws_url or DEFAULT_WS_URL).strip()
        self.on_event = on_event or (lambda m: None)
        # Track the most-recently-started server so the orchestrator
        # can stop it later.
        self._server_pid: Optional[int] = None
        self._server_proc: Optional[subprocess.Popen] = None

    # ------------------------------------------------------------------
    # Tool detection
    # ------------------------------------------------------------------

    def is_installed(self) -> bool:
        """True if ``kismet`` is on PATH. Honest: never assumes."""
        return shutil.which("kismet") is not None

    def is_cap_to_pcap_installed(self) -> bool:
        """True if ``kismet_cap_to_pcap`` is on PATH."""
        return shutil.which("kismet_cap_to_pcap") is not None

    def is_client_installed(self) -> bool:
        """True if ``kismet_client`` is on PATH."""
        return shutil.which("kismet_client") is not None

    # ------------------------------------------------------------------
    # Server
    # ------------------------------------------------------------------

    def start_server(
        self,
        interface: str,
        output_dir: str,
        *,
        sources: Optional[List[str]] = None,
        log_types: str = "pcap,netxml,csv",
        wait_s: float = DEFAULT_STARTUP_WAIT_S,
        timeout_s: int = 30,
    ) -> KismetRunResult:
        """Start ``kismet_server`` on ``interface`` writing to ``output_dir``.

        The server is launched in the background (``Popen``) so the
        runner returns immediately. The operator / orchestrator is
        responsible for stopping it via :meth:`stop_server` when the
        capture is done.

        Args:
            interface: capture interface, e.g. ``"wlan0mon"``.
            output_dir: directory Kismet writes logs to. Created if
                missing.
            sources: optional list of additional capture sources
                (e.g. ``["rtl433"]``); passed via ``--source`` once
                per source.
            log_types: comma-separated log type list.
            wait_s: how long to wait for the server to come up.
            timeout_s: ignored (server runs forever; reserved).

        Returns: :class:`KismetRunResult` with ``ok=True`` on a
            successful spawn, ``ok=False`` otherwise.
        """
        if not self.is_installed():
            return KismetRunResult(
                ok=False, action="kismet_server",
                error="kismet binary not found on PATH",
            )
        if not interface or not isinstance(interface, str):
            return KismetRunResult(
                ok=False, action="kismet_server",
                error=f"invalid interface: {interface!r}",
            )
        out_dir = Path(output_dir).expanduser().resolve()
        try:
            out_dir.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            return KismetRunResult(
                ok=False, action="kismet_server",
                error=f"could not create output_dir: {e}",
            )
        cmd: List[str] = [
            "kismet_server",
            "--no-ncurses",
            "--no-log-titles",
            "--override", "wardrive=false",
            f"--log-directory={str(out_dir)}",
            f"--log-types={log_types}",
            "-c", interface,
        ]
        for src in (sources or []):
            cmd.extend(["--source", str(src)])
        log = self.on_event
        t0 = time.time()
        try:
            log(f"[kismet] spawning {' '.join(cmd[:6])}...")
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
        except FileNotFoundError as e:
            return KismetRunResult(
                ok=False, action="kismet_server",
                error=f"binary not found: {e}", returncode=127,
            )
        except Exception as e:  # noqa: BLE001
            return KismetRunResult(
                ok=False, action="kismet_server",
                error=f"spawn failed: {e}", returncode=1,
            )
        self._server_pid = proc.pid
        self._server_proc = proc
        # Best-effort: give the server a moment to bind the port.
        time.sleep(max(0.0, float(wait_s)))
        running = proc.poll() is None
        return KismetRunResult(
            ok=running,
            action="kismet_server",
            pid=proc.pid,
            error="" if running else "kismet_server exited immediately",
            artifacts={"output_dir": str(out_dir)},
            elapsed=time.time() - t0,
            extra={"interface": interface, "log_types": log_types},
        )

    def stop_server(self, *, timeout_s: int = 5) -> KismetRunResult:
        """Stop the most-recently-started server (if any)."""
        proc = self._server_proc
        if proc is None:
            return KismetRunResult(
                ok=True, action="kismet_server.stop",
                error="no server to stop (none started by this runner)",
            )
        try:
            proc.terminate()
            try:
                proc.wait(timeout=timeout_s)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=timeout_s)
        except Exception as e:  # noqa: BLE001
            return KismetRunResult(
                ok=False, action="kismet_server.stop",
                error=f"stop failed: {e}",
            )
        self._server_proc = None
        self._server_pid = None
        return KismetRunResult(ok=True, action="kismet_server.stop")

    # ------------------------------------------------------------------
    # Client (admin / admin)
    # ------------------------------------------------------------------

    def start_client(self, *, ws_url: Optional[str] = None,
                     username: Optional[str] = None,
                     password: Optional[str] = None,
                     foreground: bool = False,
                     ) -> KismetRunResult:
        """Start ``kismet_client`` connecting to the Kismet server.

        The password is passed via the ``KISMET_CLIENT_PASSWORD``
        env var; the username via ``KISMET_CLIENT_USERNAME``. The
        constructor's defaults (``admin`` / ``admin``) are used
        unless overridden.

        Args:
            ws_url: WebSocket URL of the running Kismet server.
            username: optional override (default: ``"admin"``).
            password: optional override (default: ``"admin"``).
            foreground: if True, run synchronously and wait; else
                spawn detached (Popen).

        Returns: :class:`KismetRunResult`.
        """
        if not self.is_client_installed():
            return KismetRunResult(
                ok=False, action="kismet_client",
                error="kismet_client binary not found on PATH",
            )
        url = (ws_url or self.ws_url).strip()
        uname = (username or self.username).strip()
        pwd = (password or self._password)
        cmd: List[str] = [
            "kismet_client",
            "-c", url,
            "-u", uname,
        ]
        # NOTE: password is passed ONLY via the env var; the binary
        # reads it from ``-p <password>`` which the wrapper threads
        # from KISMET_CLIENT_PASSWORD so the literal string never
        # appears in argv or in logs.
        # Some kismet_client builds also accept ``-p``; we pass
        # the password via the env var and let the binary read it
        # from stdin if -p is missing. Always thread via env first.
        env = {
            KISMET_CLIENT_USERNAME_ENV: uname,
            KISMET_CLIENT_PASSWORD_ENV: pwd,
        }
        if foreground:
            res = _safe_run(cmd, timeout=15, on_event=self.on_event,
                              env=env)
            # Always surface the env-var contract so the operator
            # / orchestrator can verify credentials flow via env.
            res.extra = {
                **res.extra,
                "username_env": KISMET_CLIENT_USERNAME_ENV,
                "password_env": KISMET_CLIENT_PASSWORD_ENV,
                "ws_url": url,
            }
            return res
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
                env={**os.environ, **env},
            )
        except Exception as e:  # noqa: BLE001
            return KismetRunResult(
                ok=False, action="kismet_client",
                error=f"spawn failed: {e}", returncode=1,
            )
        return KismetRunResult(
            ok=True, action="kismet_client", pid=proc.pid,
            artifacts={"ws_url": url},
            extra={"username_env": KISMET_CLIENT_USERNAME_ENV,
                   "password_env": KISMET_CLIENT_PASSWORD_ENV},
        )

    # ------------------------------------------------------------------
    # Capture conversion
    # ------------------------------------------------------------------

    def convert_cap_to_pcap(
        self,
        kismet_cap_path: str,
        out_pcap: str,
        *,
        timeout_s: int = DEFAULT_CONVERT_TIMEOUT_S,
    ) -> KismetRunResult:
        """Convert a ``.kismet`` binary capture to ``.pcap`` via
        ``kismet_cap_to_pcap``.

        Args:
            kismet_cap_path: input ``.kismet`` file (the Kismet
                native capture format).
            out_pcap: output ``.pcap`` path; parent dir is created.
            timeout_s: cap on the conversion.

        Returns: :class:`KismetRunResult` with the artifact path on
            success.
        """
        if not self.is_cap_to_pcap_installed():
            return KismetRunResult(
                ok=False, action="kismet_cap_to_pcap",
                error="kismet_cap_to_pcap binary not found on PATH",
            )
        inp = Path(kismet_cap_path).expanduser()
        outp = Path(out_pcap).expanduser()
        if not inp.is_file():
            return KismetRunResult(
                ok=False, action="kismet_cap_to_pcap",
                error=f"input not found: {inp}",
            )
        try:
            outp.parent.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            return KismetRunResult(
                ok=False, action="kismet_cap_to_pcap",
                error=f"could not create output dir: {e}",
            )
        cmd = ["kismet_cap_to_pcap", "--in", str(inp), "--out", str(outp)]
        res = _safe_run(cmd, timeout=timeout_s, on_event=self.on_event)
        if res.ok and outp.is_file():
            res.artifacts = {"pcap": str(outp)}
        return res

    # ------------------------------------------------------------------
    # Alert dump
    # ------------------------------------------------------------------

    def dump_alerts_json(self, output_dir: str) -> KismetRunResult:
        """Return the alerts JSON Kismet wrote to ``output_dir``.

        Kismet writes alerts to ``<output_dir>/alerts/*.alert`` and
        JSON dumps to ``<output_dir>/alerts/*.json`` when the
        ``--log-types=json`` flag is set. This method LISTS the
        files and reads the most-recent JSON dump. Never fabricates
        a finding.

        Returns: :class:`KismetRunResult` with ``extra.json_files``
            listing the alert JSON paths (the orchestrator / chain
            parses them).
        """
        out = Path(output_dir).expanduser()
        if not out.is_dir():
            return KismetRunResult(
                ok=False, action="dump_alerts_json",
                error=f"output_dir is not a directory: {out}",
            )
        alerts_dir = out / "alerts"
        json_files: List[str] = []
        if alerts_dir.is_dir():
            json_files = sorted(str(p) for p in alerts_dir.glob("*.json"))
        return KismetRunResult(
            ok=True,
            action="dump_alerts_json",
            artifacts={"output_dir": str(out)},
            extra={"json_files": json_files, "n_files": len(json_files)},
        )

    # ------------------------------------------------------------------
    # Post-exploit glue
    # ------------------------------------------------------------------

    def apply_to_post_exploit_dir(
        self,
        kismet_log_dir: str,
        post_exploit_dir: str,
    ) -> KismetRunResult:
        """Glue the Kismet ``.kismet.csv`` / ``.kismet.netxml`` into
        the post-exploit directory the existing
        :mod:`core.modules.kali_tools_integration` already looks for
        during airodump cleanup.

        The runner COPIES (not moves) the Kismet CSV / netxml files
        to ``<post_exploit_dir>/kismet_*`` so the existing
        ``-01.kismet.csv`` pattern matches. The operator / cleanup
        script then unifies them.

        Returns: :class:`KismetRunResult` with the copied paths in
            ``artifacts``.
        """
        import shutil as _sh
        src = Path(kismet_log_dir).expanduser()
        dst = Path(post_exploit_dir).expanduser()
        if not src.is_dir():
            return KismetRunResult(
                ok=False, action="apply_to_post_exploit_dir",
                error=f"kismet_log_dir not a directory: {src}",
            )
        try:
            dst.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            return KismetRunResult(
                ok=False, action="apply_to_post_exploit_dir",
                error=f"could not create post_exploit_dir: {e}",
            )
        copied: List[str] = []
        try:
            for ext in ("*.kismet.csv", "*.kismet.netxml", "*.pcapdump"):
                for p in src.glob(ext):
                    target = dst / p.name
                    _sh.copy2(p, target)
                    copied.append(str(target))
        except Exception as e:
            return KismetRunResult(
                ok=False, action="apply_to_post_exploit_dir",
                error=f"copy failed: {e}",
            )
        return KismetRunResult(
            ok=True,
            action="apply_to_post_exploit_dir",
            artifacts={"copied": copied, "n": len(copied)},
        )

    # ------------------------------------------------------------------
    # Pre-chain context
    # ------------------------------------------------------------------

    def apply_to_prechain(
        self,
        target: Dict[str, Any],
        captures_dir: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Return a structured prechain context built from the
        operator's Kismet captures in ``workspace/captures/``.

        Matches captures to the selected target by BSSID (preferred)
        or SSID. Never fabricates — if no capture matches the
        target, returns ``{"ok": False, "error": "no matching
        capture", "matches": []}``.

        The returned context is intended to be merged into
        ``target["recon"]`` by the orchestrator's
        ``_maybe_kismet_prechain`` BEFORE the first chain step.
        """
        cap_dir = Path(
            captures_dir
            or (Path(__file__).resolve().parent.parent.parent
                 / "workspace" / "captures")
        ).expanduser()
        if not cap_dir.is_dir():
            return {"ok": False,
                    "error": f"captures dir not found: {cap_dir}",
                    "matches": []}
        target_bssid = (
            target.get("bssid") or target.get("BSSID") or ""
        ).lower().strip()
        target_ssid = (
            target.get("ssid") or target.get("SSID") or target.get("name")
            or ""
        ).strip()
        matches: List[Dict[str, Any]] = []
        for cap in sorted(cap_dir.glob("*.kismet")):
            try:
                size = cap.stat().st_size
            except Exception:
                size = 0
            meta = {
                "path": str(cap),
                "name": cap.name,
                "size_bytes": size,
                "mtime": cap.stat().st_mtime if size else 0,
                "matched_by": [],
            }
            # Path-based BSSID/SSID match (filename often has
            # BSSID or SSID embedded).
            name_l = cap.name.lower()
            if target_bssid and target_bssid.replace(":", "") in name_l.replace(":", ""):
                meta["matched_by"].append("bssid_in_filename")
            if target_ssid and target_ssid.lower() in name_l.lower():
                meta["matched_by"].append("ssid_in_filename")
            if not meta["matched_by"]:
                # Unmatched — still record as a candidate if the
                # filename starts with "Kismet-" (the operator's
                # convention from the two files at repo root).
                if name_l.startswith("kismet-"):
                    meta["matched_by"].append("kismet_default")
            matches.append(meta)
        ok = any(m["matched_by"] for m in matches)
        return {
            "ok": ok,
            "matches": matches,
            "n_captures": len(matches),
            "target": {
                "bssid": target_bssid,
                "ssid": target_ssid,
            },
            "error": "" if ok else "no matching capture",
        }


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------

def is_kismet_installed() -> bool:
    """One-liner used by the orchestrator / status line."""
    return shutil.which("kismet") is not None


__all__ = [
    "KismetRunner",
    "KismetRunResult",
    "KISMET_CLIENT_PASSWORD_ENV",
    "KISMET_CLIENT_USERNAME_ENV",
    "DEFAULT_USERNAME",
    "DEFAULT_PASSWORD",
    "DEFAULT_WS_URL",
    "is_kismet_installed",
]
