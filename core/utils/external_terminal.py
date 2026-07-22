"""
External Terminal Helpers
=========================
Auto-detect and launch an external terminal for long-running WiFi steps
(airodump capture, aireplay deauth, hashcat crack, hostapd evil-twin,
msfconsole). The operator can watch live logs in the spawned terminal
and abort with Ctrl-C, like airgeddon / wifite2.

Detection chain (in order, falls through on missing binary):

    xterm -> gnome-terminal -> konsole -> xfce4-terminal
    -> alacritty -> kitty -> foot -> tmux -> "tail"

The winner is persisted in ``config/dashboard_settings.json`` under the
``terminal`` key so we don't re-probe every step. ``"tail"`` is the
final fallback — no external terminal is required, the caller just
tails the log file in the activity log.

Public API
----------
- :func:`detect` -- pick (or revalidate) the persisted terminal choice.
- :func:`launch` -- spawn the chosen terminal with a command, return Popen.
- :func:`list_available` -- return the full chain in order (for diagnostics).
"""

import logging
import os
import shlex
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Order matters: first hit on PATH wins. Final "tail" is the no-terminal fallback.
TERMINAL_CHAIN: List[str] = [
    "xterm",
    "gnome-terminal",
    "konsole",
    "xfce4-terminal",
    "alacritty",
    "kitty",
    "foot",
    "tmux",
    "tail",  # always-present POSIX utility; sentinel for "no terminal"
]

# Sentinel return value when no real terminal is available.
NO_TERMINAL = "tail"

# Persisted-settings key (top-level in dashboard_settings.json).
SETTINGS_KEY = "terminal"

# Window-title patterns for the per-step launcher. Keys are the AI's
# `step["action"]` values (or the canonical tool name) and the format
# is a Python str-format template receiving the step's fields.
# A step with no matching entry falls back to a generic title.
STEP_WINDOW_TITLES: Dict[str, str] = {
    "airodump":        "KFIOSA: airodump-ng capture — {bssid}",
    "deauth":          "KFIOSA: deauth — {bssid}",
    "aireplay":        "KFIOSA: aireplay-ng — {bssid}",
    "aircrack":        "KFIOSA: aircrack-ng crack — {cap_file}",
    "hashcat":         "KFIOSA: hashcat — {hash_file}",
    "hcx":             "KFIOSA: hcxtools — {hash_file}",
    "wash":            "KFIOSA: wash WPS probe — {iface}",
    "reaver":          "KFIOSA: reaver — {bssid}",
    "bully":           "KFIOSA: bully — {bssid}",
    "evil_twin":       "KFIOSA: evil-twin (hostapd+dnsmasq) — {ssid}",
    "msfconsole":      "KFIOSA: msfconsole session — {target}",
    "auto_post":       "KFIOSA: post-exploit chain — {target}",
    "c2_beacon":       "KFIOSA: C2 beacon — {addr}",
    "mt7921e_inject":    "KFIOSA: mt7921e inject — {bssid}",
    "mt7921e_test":      "KFIOSA: mt7921e test_injection — {iface}",
    "mt7921e_channel":   "KFIOSA: mt7921e set_channel — {channel}",
    "mt7921e_txpower":   "KFIOSA: mt7921e set_txpower — {dbm}dBm",
}

# Threshold above which a step is automatically routed through an
# external terminal rather than the in-process worker thread. The
# orchestrator can override per-step by setting ``step["external"]:
# True|False``.
EXTERNAL_TERMINAL_RUNTIME_THRESHOLD = 5  # seconds

# Default log directory for per-step outputs (created on demand).
LOG_DIR = Path("logs") / "steps"


def step_title(step: Dict[str, Any]) -> str:
    """Build a window title for a chain step from ``STEP_WINDOW_TITLES``.

    Falls back to a generic ``"KFIOSA: <action> <target-or-iface>"`` if
    no template matches.
    """
    action = step.get("action") or step.get("tool") or "step"
    template = STEP_WINDOW_TITLES.get(action)
    fields = {
        "bssid": step.get("bssid") or step.get("target") or "?",
        "ssid": step.get("ssid") or "?",
        "iface": step.get("iface") or step.get("interface") or "?",
        "target": step.get("target") or step.get("bssid") or "?",
        "cap_file": step.get("cap_file") or step.get("output") or "?",
        "hash_file": step.get("hash_file") or "?",
        "channel": step.get("channel") or "?",
        "dbm": step.get("dbm") or "?",
        "addr": step.get("addr") or step.get("target") or "?",
    }
    if template:
        try:
            return template.format(**fields)
        except (KeyError, IndexError):
            pass
    return f"KFIOSA: {action} — {fields['target']}"


def list_available() -> List[str]:
    """Return the chain in order, annotated with availability on this host.

    Useful for the Settings screen "which terminals can I use" listing.
    """
    out: List[str] = []
    for term in TERMINAL_CHAIN:
        if term == NO_TERMINAL or shutil.which(term):
            out.append(term)
    return out


def _probe() -> str:
    """Walk the chain and return the first available terminal name.

    Always returns a string from ``TERMINAL_CHAIN``; never raises. If
    nothing in the chain is present, returns ``NO_TERMINAL`` so the
    caller can fall back to a plain log tail.
    """
    for term in TERMINAL_CHAIN:
        if term == NO_TERMINAL:
            return NO_TERMINAL
        if shutil.which(term):
            return term
    return NO_TERMINAL


def _persist(choice: str, settings) -> bool:
    """Persist ``choice`` to the settings file. Best-effort; never raises."""
    try:
        if settings is None:
            return False
        return bool(settings.update_setting(SETTINGS_KEY, choice))
    except Exception as e:
        logger.debug("persist terminal choice %r: %s", choice, e)
        return False


def detect(settings=None) -> str:
    """Return the persisted terminal choice, revalidating that the binary
    still exists. Falls through the chain on a stale or missing entry and
    persists the new winner. Always returns a value from
    :data:`TERMINAL_CHAIN`.

    Args:
        settings: an optional ``SettingsManager``-like object (has
            ``get_setting`` and ``update_setting``). When ``None`` the
            function still probes the chain but does not persist.

    Returns:
        The terminal name to use. ``"tail"`` means no terminal
        available; the caller should just tail the log file.
    """
    saved: Optional[str] = None
    if settings is not None:
        try:
            saved = settings.get_setting(SETTINGS_KEY)
        except Exception as e:
            logger.debug("settings.get_setting(%s): %s", SETTINGS_KEY, e)
            saved = None

    # Re-validate the saved choice.
    if saved in TERMINAL_CHAIN:
        if saved == NO_TERMINAL:
            return NO_TERMINAL
        if shutil.which(saved):
            return saved
        logger.info(
            "persisted terminal %r is no longer on PATH; re-probing", saved,
        )

    # Probe and persist the new winner.
    winner = _probe()
    if winner != saved:
        _persist(winner, settings)
    return winner


# ---------------------------------------------------------------------------
# launch(): build the right incantation for each terminal type
# ---------------------------------------------------------------------------

# When True, per-step external windows stay open after the wrapped command
# finishes (a "step complete — close this window" prompt + ``exec bash``)
# so the operator can review the output before closing. Hermetic tests
# that mock launch_real_step never reach this wrapper. Set to False to
# restore the old auto-close behaviour.
KEEP_OPEN_STEP_WINDOWS = True


def _wrap_for_terminal(term: str, cmd: List[str], log_path: str,
                       keep_open: Optional[bool] = None) -> List[str]:
    """Wrap ``cmd`` so its stdout/stderr stream to ``log_path`` while also
    being visible in the terminal window.

    All wrapped commands ``tee`` their output so the operator can see the
    log live AND we keep a copy on disk for the orchestrator to tail.

    When ``keep_open`` (default :data:`KEEP_OPEN_STEP_WINDOWS`) is True the
    window stays open after the command exits: a completion banner is
    printed and ``exec bash`` replaces the process so the operator can
    inspect output and close the window themselves. The ``tail`` fallback
    path never reaches this wrapper, so the flag only affects real
    terminals.
    """
    if keep_open is None:
        keep_open = KEEP_OPEN_STEP_WINDOWS
    # Build a shell-safe string from cmd; the terminal shells out to bash.
    cmd_str = " ".join(shlex.quote(c) for c in cmd)
    # `tee -a` appends and shows live. `2>&1` merges stderr.
    inner = f"({cmd_str}) 2>&1 | tee -a {shlex.quote(log_path)}"
    if keep_open:
        # Keep the window open for the operator to close. ``exec bash``
        # (not ``exit``) so interactive-session windows that already ran
        # `sessions -i <id>` aren't sent an exit on top.
        inner += ("; printf '\\n[step complete — close this window when done]\\n'; "
                  "exec bash")
    return ["bash", "-c", inner]


def launch(cmd: List[str], log_path: str, settings=None,
           title: Optional[str] = None) -> subprocess.Popen:
    """Spawn ``cmd`` inside the detected external terminal, streaming
    output to ``log_path``.

    Args:
        cmd: the command (argv list) to run inside the terminal.
        log_path: file path to tee the command's output to. Parent
            directories are created.
        settings: optional settings manager; used for terminal selection
            if no cached choice is available.
        title: optional window/tab title.

    Returns:
        The :class:`subprocess.Popen` of the terminal process. The caller
        decides whether to ``wait()``, ``poll()``, or just leave it
        running. On the ``"tail"`` fallback, the returned Popen is the
        ``tail -f`` process.

    Notes:
        - The terminal process is detached (``start_new_session=True``)
          so it survives even if the parent TUI exits.
        - If no log file's parent exists, it is created.
        - Title defaults to the binary name from ``cmd[0]``.
    """
    # Ensure the log file's parent dir exists.
    try:
        Path(log_path).parent.mkdir(parents=True, exist_ok=True)
    except Exception as e:
        logger.warning("could not create log parent dir for %s: %s", log_path, e)

    # Session-only override wins over persisted setting.
    term = os.environ.get("KFIOSA_TERMINAL") or detect(settings)

    title = title or (cmd[0] if cmd else "kfiosa")
    wrapped = _wrap_for_terminal(term, cmd, log_path)

    if term == "xterm":
        argv = ["xterm", "-T", title, "-e", *wrapped]
    elif term == "gnome-terminal":
        # gnome-terminal accepts a single -- argument followed by the command.
        argv = ["gnome-terminal", "--title", title, "--", *wrapped]
    elif term == "konsole":
        argv = ["konsole", "-p", f"tabtitle={title}", "-e", *wrapped]
    elif term == "xfce4-terminal":
        argv = ["xfce4-terminal", "--title", title, "-e",
                " ".join(shlex.quote(c) for c in wrapped)]
    elif term == "alacritty":
        argv = ["alacritty", "--title", title, "-e", *wrapped]
    elif term == "kitty":
        argv = ["kitty", "--title", title, *wrapped]
    elif term == "foot":
        argv = ["foot", "--title", title, *wrapped]
    elif term == "tmux":
        # New window inside the current tmux session if there is one,
        # otherwise a detached session.
        session = f"kfiosa-{int(time.time())}"
        if os.environ.get("TMUX"):
            argv = ["tmux", "new-window", "-n", title, *wrapped]
        else:
            argv = ["tmux", "new-session", "-d", "-s", session, "-n", title,
                    *wrapped]
    else:
        # NO_TERMINAL fallback: just tail the log file in the background.
        # Caller is expected to have already started the real cmd
        # somewhere (or to use the result as a no-op).
        argv = ["tail", "-f", log_path]

    logger.info("launching %s in %s (log=%s)", cmd[0] if cmd else "<cmd>", term, log_path)
    try:
        return subprocess.Popen(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
    except FileNotFoundError:
        # The persisted terminal vanished mid-run. Fall through to tail.
        logger.warning("terminal %r not found at launch; falling back to tail", term)
        return subprocess.Popen(
            ["tail", "-f", log_path],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )


# ---------------------------------------------------------------------------
# Per-step launcher: pick a window title and decide external-vs-inline.
# ---------------------------------------------------------------------------

def is_real_backend(obj: Any = None) -> bool:
    """Return True if ``obj`` is a real external-terminal backend (i.e.
    not the ``always_tail`` / ``tail`` sentinel).

    The orchestrator calls this to decide whether per-step windows can be
    spawned. When no terminal could be auto-detected, the dashboard wires
    :meth:`ExternalTerminalBackend.always_tail`, whose ``term`` is
    ``"tail"`` — the no-terminal sentinel. In that case we return False so
    the orchestrator falls back to inline ``subprocess.run``.

    ``obj`` may be:
      - ``None``: returns False (defensive — no backend wired at all).
      - an :class:`ExternalTerminalBackend` (or duck-typed object with a
        ``term`` attribute): True iff ``term != "tail"``.
      - a string: True iff it is in :data:`TERMINAL_CHAIN` and not
        :data:`NO_TERMINAL`.
    """
    if obj is None:
        return False
    term = getattr(obj, "term", None)
    if term is not None:
        return term != NO_TERMINAL
    if isinstance(obj, str):
        return obj != NO_TERMINAL
    # Unknown object type: assume real if it has a ``launch`` callable.
    return callable(getattr(obj, "launch", None))


def should_use_external_terminal(step: Dict[str, Any],
                                 backend_present: bool = False) -> bool:
    """Decide whether a step is routed through the external terminal.

    When ``backend_present`` is True (a real terminal backend is wired,
    see :func:`is_real_backend`), **any real (non-info) step** qualifies:
    info-only steps (``step["kind"] == "info"`` or ``step["info"] is
    True``) are skipped, everything else returns True. This is the
    per-step-window policy from Part C: every ACCEPTed real step opens
    its own external window when a terminal is available.

    When ``backend_present`` is False/unknown, the legacy heuristic
    applies — a step uses the external terminal if any of:
      - ``step["external"] is True``
      - ``step["external"]`` is not set AND
        ``step.get("expected_runtime_seconds", 0) >=
        EXTERNAL_TERMINAL_RUNTIME_THRESHOLD``
      - the step's ``action`` is in ``STEP_WINDOW_TITLES`` and the step
        is not explicitly marked ``inline``.
    """
    if backend_present:
        # An explicit opt-out always wins, even with a backend.
        if step.get("external") is False or step.get("inline"):
            return False
        # Info-only steps never open a window.
        if step.get("kind") == "info" or step.get("info") is True:
            return False
        return True
    # Legacy fallback (no real backend wired).
    if step.get("external") is True:
        return True
    if step.get("external") is False:
        return False
    runtime = step.get("expected_runtime_seconds")
    if runtime is not None and runtime >= EXTERNAL_TERMINAL_RUNTIME_THRESHOLD:
        return True
    if step.get("action") in STEP_WINDOW_TITLES and not step.get("inline"):
        return True
    return False


def launch_real_step(step: Dict[str, Any], cmd: Any,
                     log_path: Optional[str] = None,
                     title: Optional[str] = None) -> Dict[str, Any]:
    """Generic per-step launcher the orchestrator calls for every real
    (non-info) ACCEPTed step.

    Builds a window title from :data:`STEP_WINDOW_TITLES` (keyed by
    ``step["action"]`` / ``step["tool"]``, falling back to
    ``step.get("action", "step")``) and delegates to :func:`launch` to
    spawn ``cmd`` in an external terminal window.

    Args:
        step: the chain-step dict (used for the title and log filename).
        cmd: the command to run. May be a list-of-str argv (preferred) or
            a shell string. A list is joined shell-safe for the
            terminal's ``bash -c`` wrapping, matching how :func:`launch`
            handles argv via :func:`shlex.quote`.
        log_path: optional log file path (tee'd in the terminal). When
            ``None``, a stable path under :data:`LOG_DIR` is derived from
            the title (matching :func:`launch_step`).
        title: optional window title override; defaults to
            :func:`step_title`.

    Returns:
        ``{"ok": True, "pid": <popen pid>}`` on success, or
        ``{"ok": False, "error": "<message>"}`` on failure. Never raises.
    """
    try:
        # Normalize cmd to an argv list, matching how `launch` handles
        # argv (it shells out via `bash -c` with shlex.quote on each
        # element). A string is split with shlex; a list is taken as-is.
        if isinstance(cmd, str):
            cmd_list = shlex.split(cmd)
        else:
            cmd_list = [str(c) for c in (cmd or [])]
        if not cmd_list:
            return {"ok": False, "error": "empty command"}

        if title is None:
            title = step_title(step)
        if log_path is None:
            safe = "".join(
                c if c.isalnum() or c in "-_." else "_" for c in title
            )[:80]
            log_path = str(LOG_DIR / f"{safe}.log")

        popen = launch(cmd_list, log_path, settings=None, title=title)
        return {"ok": True, "pid": popen.pid}
    except Exception as e:
        logger.warning("launch_real_step failed for %r: %s",
                       step.get("action"), e)
        return {"ok": False, "error": str(e)}


def launch_step(step: Dict[str, Any], settings=None) -> "subprocess.Popen | TerminalRun":
    """Build a command for ``step`` and launch it in the external terminal.

    ``step`` is the AI's chain-step dict with at least:

    - ``action`` or ``tool``: drives the window title and the command.
    - ``cmd``: list-of-str argv the orchestrator built for the step
      (e.g. ``["airodump-ng", "-c", "6", "--bssid", "AA:BB:..",
      "-w", "/tmp/cap", "wlan0mon"]``). If absent, ``launch_step`` builds
      one from the canonical tool + ``args`` dict.

    Returns the :class:`subprocess.Popen` (or :class:`TerminalRun` for
    fakes). The log file is created in ``logs/steps/`` and tee'd to the
    terminal so the operator can ``tail -f`` it later.

    Never raises on tool absence — returns a Popen of the ``tail -f``
    fallback instead.
    """
    cmd = step.get("cmd")
    if not cmd:
        # Build a minimal argv from `tool` + `args`. This is the path
        # taken when the AI's step doesn't pre-build a full command
        # (e.g. `mt7921e.set_channel` style steps).
        tool = step.get("tool") or step.get("action")
        args = step.get("args") or {}
        if tool:
            argv = [str(tool)]
            for k, v in args.items():
                argv.extend([f"--{k.replace('_', '-')}", str(v)])
            cmd = argv
        else:
            cmd = ["echo", f"no command for step {step.get('action')}"]

    # Build a stable log path.
    title = step_title(step)
    safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in title)[:80]
    log_path = str(LOG_DIR / f"{safe}.log")

    return launch(cmd, log_path, settings=settings, title=title)


# ---------------------------------------------------------------------------
# Convenience: helper for tests / fakes
# ---------------------------------------------------------------------------

class TerminalRun:
    """Lightweight handle returned by :class:`FakeExternalTerminal` so
    tests can introspect what was launched without spawning anything."""

    def __init__(self, cmd: List[str], log_path: str, term: str,
                 title: Optional[str] = None):
        self.cmd = list(cmd)
        self.log_path = log_path
        self.term = term
        self.title = title or (cmd[0] if cmd else "kfiosa")
        self.returncode: Optional[int] = None
        self.finished = False

    def wait(self, timeout: Optional[float] = None) -> int:
        # Fake: mark finished and return a synthetic rc.
        self.finished = True
        self.returncode = 0
        return 0

    def abort(self) -> None:
        self.finished = True
        self.returncode = 130  # 128 + SIGINT(2) for "user aborted"

    def __repr__(self) -> str:
        return (
            f"TerminalRun(term={self.term!r}, title={self.title!r}, "
            f"log_path={self.log_path!r}, cmd={self.cmd!r})"
        )


class FakeExternalTerminal:
    """Test double that records every ``launch`` call and returns a
    :class:`TerminalRun` that the test can assert against. Never spawns
    a real process."""

    def __init__(self, term: str = "xterm"):
        self.term = term
        self.calls: List[Dict] = []

    def detect(self, settings=None) -> str:
        return self.term

    def launch(self, cmd: List[str], log_path: str, settings=None,
               title: Optional[str] = None) -> TerminalRun:
        self.calls.append({
            "cmd": list(cmd), "log_path": log_path, "title": title,
        })
        return TerminalRun(cmd, log_path, self.term, title=title)

    def launch_step(self, step: Dict[str, Any], settings=None) -> TerminalRun:
        """Same contract as the real :func:`launch_step`; uses
        :func:`should_use_external_terminal` to gate and
        :func:`step_title` for the title."""
        from core.utils.external_terminal import step_title
        title = step_title(step)
        cmd = step.get("cmd") or [step.get("tool") or "echo", "<no-cmd>"]
        log_path = f"/tmp/kfiosa-fake/{title.replace(' ', '_')}.log"
        self.calls.append({
            "cmd": list(cmd), "log_path": log_path, "title": title,
            "step_action": step.get("action"),
        })
        return TerminalRun(cmd, log_path, self.term, title=title)

    def list_available(self) -> List[str]:
        return [self.term]


class ExternalTerminalBackend:
    """Dashboard-side wrapper that the dashboard holds and shares with
    sub-screens. Wraps the free :func:`detect` / :func:`launch` helpers
    so callers don't need to pass ``settings`` every time.

    Use :meth:`launch` to spawn a tool in the operator's terminal of
    choice, or :meth:`term` to read the currently detected terminal
    name.
    """

    def __init__(self, settings=None, term: Optional[str] = None):
        self._settings = settings
        self.term = term or detect(settings)
        # Re-validate the persisted term at construction so callers can
        # rely on ``self.term`` being installable right now.
        if self.term not in ("tail",) and not shutil.which(self.term):
            self.term = _probe()
            if settings is not None:
                _persist(self.term, settings)

    @classmethod
    def always_tail(cls) -> "ExternalTerminalBackend":
        """Return a backend that always uses the ``tail`` fallback. Useful
        for tests, headless environments, and graceful degradation when
        no terminal can be auto-detected."""
        b = cls.__new__(cls)
        b._settings = None
        b.term = "tail"
        return b

    def launch(self, cmd: List[str], log_path: str,
               title: Optional[str] = None) -> "subprocess.Popen | TerminalRun":
        return launch(cmd, log_path, self._settings, title=title)

    def launch_step(self, step: Dict[str, Any]) -> "subprocess.Popen | TerminalRun":
        """Per-step launcher (see :func:`launch_step` for the contract)."""
        return launch_step(step, self._settings)

    def detect(self) -> str:
        return detect(self._settings)

    def list_available(self) -> List[str]:
        return list_available()

    def __repr__(self) -> str:
        return f"ExternalTerminalBackend(term={self.term!r})"
