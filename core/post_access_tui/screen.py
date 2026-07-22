"""core.post_access_tui.screen — PostAccessScreen (curses menu UI).

This is the curses screen the operator interacts with. It's deliberately
simple — a flat menu with key shortcuts (S/F/N/P/M/R/H/X) and a
sub-screen per action that collects one parameter (e.g. a command, a
remote path) and dispatches to :class:`PostAccessRunner`.

Single-gate invariant:
  Every menu action wraps its dispatch in
  ``self.confirm_fn(prompt)`` BEFORE the runner call. The runner
  itself does NOT re-confirm (it's the action layer, not the gate
  layer). The screen is the only thing that fires ``confirm_fn``.

Curses-free path:
  The screen is fully exercised in hermetic tests via the
  ``input_fn`` and ``thread_runner`` injection seams inherited from
  :class:`core.tui.base_screen.BaseScreen`. No real curses required.

Detach (F12 / Esc / X):
  The screen returns cleanly; the cli / spawner loop ends; the main
  chain keeps running (the spawner is a SEPARATE process).
"""
from __future__ import annotations

import logging
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

from core.tui.base_screen import BaseScreen

from .runner import PostAccessRunner
from .session_state import SessionState, _now

logger = logging.getLogger(__name__)


#: Menu definition (label, key, action_name). Order is the on-screen order.
MENU: List[Tuple[str, str, str]] = [
    ("[S]hell — run a command on the target", "s", "shell"),
    ("[F]ile transfer — get/put a file", "f", "file"),
    ("[N]etwork ops — portfwd / socks (parent runner)", "n", "network"),
    ("[Y] Sessions — network session multiplexer (panel)", "y", "sessions"),
    ("[B]luetooth — BLE RAT-like device control", "b", "ble"),
    ("[W]iFi — WiFi RAT-like attack panel", "w", "wifi"),
    ("[P]ersistence — install a persistence method", "p", "persistence"),
    ("[M]odules — re-run a post_exploit method", "m", "modules"),
    ("[R]eports — show last action envelopes", "r", "reports"),
    ("[H]elp — show menu + key bindings", "h", "help"),
    ("[X] / Esc / F12 — Detach (returns to main chain)", "x", "detach"),
]

#: Key → action map.
KEY_MAP: Dict[str, str] = {k: a for _, k, a in MENU}


class PostAccessScreen(BaseScreen):
    """Curses screen for the post-access TUI.

    Constructor args:
        stdscr:    curses window (None in tests — input_fn is used instead)
        state:     the SessionState passed in by the spawner
        runner:    the PostAccessRunner (or None to construct one)
        confirm_fn: a callable ``str -> bool`` for the per-step gate.
                    In production this is the orchestrator's TuiConfirmFn;
                    in tests it's a lambda that returns True/False on demand.
        on_event:  optional callback ``str -> None`` for logging
        activity_log: optional shared log list (the main TUI's log)
        on_action: optional callback ``envelope -> None`` for the runner
                    to call after each action (we wire it from the runner
                    to render the last action's envelope on the screen).
    """

    def __init__(self, stdscr, state: SessionState,
                 runner: Optional[PostAccessRunner] = None,
                 *, confirm_fn: Optional[Callable[[str], bool]] = None,
                 on_event: Optional[Callable[[str], None]] = None,
                 activity_log: Optional[List[str]] = None,
                 **kwargs):
        super().__init__(
            stdscr, parent_callback=None,
            activity_log=activity_log or [],
            ai_backend=None, kb=None, post_runner=None,
            settings_manager=None, dashboard=None,
            **kwargs,
        )
        self.state: SessionState = state
        self.confirm_fn: Callable[[str], bool] = confirm_fn or (lambda _p: True)
        self._on_event = on_event
        self.last_envelopes: List[Dict[str, Any]] = []
        self._cancelled: bool = False
        self._result: Dict[str, Any] = {"ok": True, "detached": False}
        # The runner. We attach on_action so every action's envelope is
        # also pushed into last_envelopes for the [R]eports screen.
        if runner is None:
            self.runner: PostAccessRunner = PostAccessRunner(
                state=state, on_action=self._push_envelope,
            )
        else:
            self.runner = runner
            # Re-wire on_action
            self.runner._on_action = self._push_envelope  # type: ignore[attr-defined]
        self.title = (
            f"Post-Access TUI  |  transport: {state.transport_label()}  |  "
            f"target: {state.target or '(none)'}  |  "
            f"session: {state.session_id or '(none)'}"
        )

    # ------------------------------------------------------------------
    # Logging / envelope helpers
    # ------------------------------------------------------------------
    def _push_envelope(self, envelope: Dict[str, Any]) -> None:
        """Called by the runner after every action. We push to
        last_envelopes (capped) and to the activity log."""
        self.last_envelopes.append(envelope)
        if len(self.last_envelopes) > 200:
            self.last_envelopes = self.last_envelopes[-200:]
        try:
            line = (f"[{envelope.get('action')}] "
                    f"ok={envelope.get('ok')} "
                    f"rc={envelope.get('returncode')} "
                    f"err={envelope.get('error')}")
            if self._on_event is not None:
                self._on_event(line)
            if self.activity_log is not None:
                self.activity_log.append(line)
        except Exception:  # noqa: BLE001
            pass

    def _emit(self, msg: str) -> None:
        if self._on_event is not None:
            try:
                self._on_event(msg)
            except Exception:  # noqa: BLE001
                pass

    def _gate(self, prompt: str) -> bool:
        """The single-gate entrypoint for the screen. Routes to the
        injected confirm_fn; the runner is NEVER called from the
        dispatcher without going through here. Always returns a bool;
        never raises."""
        try:
            return bool(self.confirm_fn(prompt))
        except Exception:  # noqa: BLE001
            return False

    # ------------------------------------------------------------------
    # Curses-free test path
    # ------------------------------------------------------------------
    def run_curses_free(self) -> Dict[str, Any]:
        """A pure-Python loop that doesn't need a real terminal.

        Used by hermetic tests: the screen reads one char per iteration
        from ``input_fn`` (a callable that returns a string), dispatches
        the action, and returns the final result. The test can pipe a
        sequence of keys and assert the result / envelopes.

        Returns the same dict as :meth:`run` would.
        """
        try:
            self._emit(self.title)
            self._emit("[H]elp — type ? for menu")
            while not self._cancelled and not self.runner.detached:
                # Read one key (test: input_fn returns the next char).
                key = (self.input_fn("") if self.input_fn is not None else "")
                if not key:
                    return self._result
                self._handle_key(key)
        except Exception as e:  # noqa: BLE001
            logger.error("run_curses_free failed: %s", e)
            self._result = {"ok": False, "error": str(e)}
        return self._result

    def _handle_key(self, key: str) -> None:
        """Dispatch a single keypress. Always returns; never raises.

        F12 / Esc / x all map to detach (the spec)."""
        if not isinstance(key, str):
            return
        k = key.lower()
        if k in ("x", "q", "\x1b", "KEY_F12", "f12"):
            self._action_detach()
            return
        action = KEY_MAP.get(k)
        if action is None:
            return
        if action == "shell":
            self._action_shell()
        elif action == "file":
            self._action_file()
        elif action == "network":
            self._action_network()
        elif action == "sessions":
            self._action_sessions()
        elif action == "ble":
            self._action_ble()
        elif action == "wifi":
            self._action_wifi()
        elif action == "persistence":
            self._action_persistence()
        elif action == "modules":
            self._action_modules()
        elif action == "reports":
            self._action_reports()
        elif action == "help":
            self._action_help()
        elif action == "detach":
            self._action_detach()

    # ------------------------------------------------------------------
    # Menu actions (all single-gated)
    # ------------------------------------------------------------------
    def _action_shell(self) -> None:
        cmd = (self.input_fn("shell> ") if self.input_fn is not None else "")
        if not isinstance(cmd, str) or not cmd.strip():
            return
        prompt = (f"ACCEPT INTRUSIVE? run_shell on target {self.state.target or '?'}"
                  f": {cmd!r}")
        if not self._gate(prompt):
            self._emit("CANCELLED: run_shell")
            return
        env = self.runner.run_shell(cmd)
        self._emit(
            f"run_shell rc={env.get('returncode')} ok={env.get('ok')}"
        )

    def _action_file(self) -> None:
        # Ask get/put; one param each.
        op = (self.input_fn("[g]et or [p]ut? ") if self.input_fn is not None else "")
        if not isinstance(op, str) or not op:
            return
        op = op.lower().strip()[:1]
        if op not in ("g", "p"):
            return
        if op == "g":
            remote = (self.input_fn("remote path> ") if self.input_fn is not None else "")
            local = (self.input_fn("local path> ") if self.input_fn is not None else "")
            if not remote or not local:
                return
            if not self._gate(f"ACCEPT INTRUSIVE? file_get {remote} -> {local}"):
                self._emit("CANCELLED: file_get"); return
            env = self.runner.file_get(remote, local)
        else:
            local = (self.input_fn("local path> ") if self.input_fn is not None else "")
            remote = (self.input_fn("remote path> ") if self.input_fn is not None else "")
            if not remote or not local:
                return
            if not self._gate(f"ACCEPT INTRUSIVE? file_put {local} -> {remote}"):
                self._emit("CANCELLED: file_put"); return
            env = self.runner.file_put(local, remote)
        self._emit(
            f"{'file_get' if op == 'g' else 'file_put'} "
            f"rc={env.get('returncode')} ok={env.get('ok')}"
        )

    def _action_network(self) -> None:
        # Submenu: portfwd add / socks start / socks stop / list.
        sub = (self.input_fn("[a]dd portfwd / [s]ocks / [l]ist / [k]ill socks > ")
               if self.input_fn is not None else "")
        if not isinstance(sub, str) or not sub:
            return
        sub = sub.lower().strip()[:1]
        if sub == "a":
            lp = (self.input_fn("listen port> ") if self.input_fn is not None else "")
            host = (self.input_fn("target host> ") if self.input_fn is not None else "")
            tp = (self.input_fn("target port> ") if self.input_fn is not None else "")
            try:
                lp_i, tp_i = int(lp), int(tp)
            except (TypeError, ValueError):
                self._emit("portfwd: bad ports"); return
            if not isinstance(host, str) or not host.strip():
                return
            if not self._gate(f"ACCEPT INTRUSIVE? portfwd_add :{lp_i} -> {host}:{tp_i}"):
                self._emit("CANCELLED: portfwd_add"); return
            env = self.runner.portfwd_add(lp_i, host, tp_i)
            self._emit(f"portfwd_add ok={env.get('ok')}")
        elif sub == "s":
            port = (self.input_fn("listen port (default 1080)> ")
                    if self.input_fn is not None else "1080")
            try:
                port_i = int(port)
            except (TypeError, ValueError):
                port_i = 1080
            if not self._gate(f"ACCEPT INTRUSIVE? socks_start :{port_i}"):
                self._emit("CANCELLED: socks_start"); return
            env = self.runner.socks_start(port_i)
            self._emit(f"socks_start ok={env.get('ok')}")
        elif sub == "l":
            pf = self.runner.list_portfwds()
            for p in pf:
                self._emit(f"  portfwd {p}")
        elif sub == "k":
            if not self._gate("ACCEPT INTRUSIVE? socks_stop"):
                self._emit("CANCELLED: socks_stop"); return
            env = self.runner.socks_stop()
            self._emit(f"socks_stop ok={env.get('ok')}")

    def _action_ble(self) -> None:
        """Open the BLE RAT-like panel (core.post_access_tui.ble_panel).

        Single-gate: the BLE panel does NOT re-confirm — this
        ``_action_ble`` is the only gate. The panel reuses
        ``self.confirm_fn`` for its high-risk actions (write,
        notify, bleshell).
        """
        # Lazy import: ble_panel pulls in re and dataclasses; we keep
        # the import local so unrelated TUI runs don't pay the cost.
        from .ble_panel import BLEPanel, ble_dispatch

        # Lazily build the panel. We pass self.confirm_fn,
        # self.input_fn, and self._on_event so the panel integrates
        # with this screen's hooks.
        panel = BLEPanel(
            client=None,  # default = real gatttool backend
            confirm_fn=self.confirm_fn,
            on_event=self._on_event,
            input_fn=self.input_fn,
            state=self.state,
        )
        result = ble_dispatch(self, panel)
        # The panel's last envelope (or the exit envelope) is
        # pushed to last_envelopes so [R]eports surfaces it.
        if isinstance(result, dict):
            self.last_envelopes.append({
                "action": "ble_panel",
                "ok": result.get("ok", False),
                "error": result.get("error", ""),
                "returncode": 0,
            })
        self._emit(
            f"ble panel exit: ok={result.get('ok') if isinstance(result, dict) else '?'}"
        )

    def _action_wifi(self) -> None:
        """Open the WiFi RAT-like panel (core.post_access_tui.wifi_panel).

        Single-gate: the WiFi panel does NOT re-confirm — this
        ``_action_wifi`` is the only gate. The panel reuses
        ``self.confirm_fn`` for its high-risk actions (deauth,
        evil-twin, karma, etc.).
        """
        # Lazy import to keep unrelated TUI runs cheap.
        from .wifi_panel import WiFiPanel, wifi_dispatch

        panel = WiFiPanel(
            client=None,  # default = real airmon/airodump backend
            confirm_fn=self.confirm_fn,
            on_event=self._on_event,
            input_fn=self.input_fn,
            state=self.state,
        )
        result = wifi_dispatch(self, panel)
        if isinstance(result, dict):
            self.last_envelopes.append({
                "action": "wifi_panel",
                "ok": result.get("ok", False),
                "error": result.get("error", ""),
                "returncode": 0,
            })
        self._emit(
            f"wifi panel exit: ok={result.get('ok') if isinstance(result, dict) else '?'}"
        )

    def _action_sessions(self) -> None:
        """Open the network session multiplexer panel
        (core.post_access_tui.network_panel).

        Single-gate: the network panel does NOT re-confirm — this
        ``_action_sessions`` is the only gate. The panel reuses
        ``self.confirm_fn`` for its high-risk actions (shell, file
        transfer, broadcast, kill, socks start/stop, etc.).
        """
        # Lazy import to keep unrelated TUI runs cheap.
        from .network_panel import NetworkPanel, network_dispatch

        panel = NetworkPanel(
            client=None,  # default = real ssh/msfconsole/chisel/socat backend
            confirm_fn=self.confirm_fn,
            on_event=self._on_event,
            input_fn=self.input_fn,
            state=self.state,
        )
        result = network_dispatch(self, panel)
        if isinstance(result, dict):
            self.last_envelopes.append({
                "action": "network_panel",
                "ok": result.get("ok", False),
                "error": result.get("error", ""),
                "returncode": 0,
            })
        self._emit(
            f"network panel exit: ok={result.get('ok') if isinstance(result, dict) else '?'}"
        )

    def _action_persistence(self) -> None:
        methods = self.runner.list_persistence_methods()
        if not methods:
            self._emit("no persistence methods available in post_exploit.runner_ext")
            return
        self._emit("persistence methods: " + ", ".join(methods))
        choice = (self.input_fn("method> ") if self.input_fn is not None else "")
        if not isinstance(choice, str) or not choice.strip():
            return
        name = choice.strip()
        if name not in methods:
            self._emit(f"unknown persistence method {name!r}"); return
        if not self._gate(f"ACCEPT INTRUSIVE? apply_persistence {name}"):
            self._emit("CANCELLED: apply_persistence"); return
        env = self.runner.apply_persistence(name)
        self._emit(f"apply_persistence {name} ok={env.get('ok')}")

    def _action_modules(self) -> None:
        mods = self.runner.list_post_exploit_modules()
        if not mods:
            self._emit("no post_exploit modules available")
            return
        # Print only the first 50 to keep the log readable.
        self._emit(f"post_exploit modules ({len(mods)}): " + ", ".join(mods[:50]))
        choice = (self.input_fn("module> ") if self.input_fn is not None else "")
        if not isinstance(choice, str) or not choice.strip():
            return
        name = choice.strip()
        if name not in mods:
            self._emit(f"unknown module {name!r}"); return
        if not self._gate(f"ACCEPT INTRUSIVE? run_module {name}"):
            self._emit("CANCELLED: run_module"); return
        env = self.runner.run_module(name)
        self._emit(f"run_module {name} ok={env.get('ok')}")

    def _action_reports(self) -> None:
        if not self.last_envelopes:
            self._emit("(no actions yet)")
            return
        # Print the last 10 envelopes (compact form).
        for env in self.last_envelopes[-10:]:
            self._emit(
                f"  [{env.get('action')}] ok={env.get('ok')} "
                f"rc={env.get('returncode')} err={env.get('error')}"
            )

    def _action_help(self) -> None:
        for label, key, _ in MENU:
            self._emit(f"  {label}  (key: {key})")
        self._emit("  F12 / Esc — Detach (single-gate: ACCEPT/CANCEL still required)")

    def _action_detach(self) -> None:
        # Detach is non-destructive; we do NOT gate it (the operator
        # explicitly pressed F12). The runner.detach() emits a "detach"
        # envelope so the audit log captures it.
        env = self.runner.detach()
        self._result = {"ok": True, "detached": True, "last": env}
        self._cancelled = True
        self._emit("detached; main chain continues")
