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
from typing import Any, Dict, List, Optional, Tuple

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

# Font scale applied to scanner windows (WiFi/BLE live scan TUI) so the
# operator can enlarge the display when reading from across the room.
# 1.0 = the terminal's own default (same density as the main KFIOSA TUI).
# The earlier 4.0 default made the windows so large that only a few words
# fit per line; 1.0 restores a normal, information-dense scan window that
# behaves like the main TUI. Override per-launch with
# ``KFIOSA_SCAN_FONT_SCALE`` (e.g. ``KFIOSA_SCAN_FONT_SCALE=2.0``).
def _parse_scan_font_scale(raw: Optional[str] = None) -> float:
    """Parse a font-scale value; invalid/non-positive → 1.0."""
    if raw is None:
        return 1.0
    try:
        val = float(raw)
    except (TypeError, ValueError):
        return 1.0
    if val != val or val <= 0.0:  # NaN or non-positive
        return 1.0
    return val


def get_scan_font_scale(settings=None) -> float:
    """Effective scan-window font scale.

    Precedence: ``KFIOSA_SCAN_FONT_SCALE`` env (when set) →
    ``settings.scanning.font_scale`` → ``1.0``.
    """
    env = os.environ.get("KFIOSA_SCAN_FONT_SCALE")
    if env is not None and str(env).strip() != "":
        return _parse_scan_font_scale(env)
    if settings is not None:
        try:
            saved = settings.get_setting("scanning.font_scale", None)
            if saved is not None and str(saved).strip() != "":
                return _parse_scan_font_scale(str(saved))
        except Exception:
            pass
    return 1.0


def set_scan_font_scale(value, settings=None) -> float:
    """Persist scan font scale (settings + process env) and return the
    clamped value used by subsequent launches in this process."""
    global SCAN_WINDOW_FONT_SCALE
    val = _parse_scan_font_scale(str(value))
    os.environ["KFIOSA_SCAN_FONT_SCALE"] = str(val)
    SCAN_WINDOW_FONT_SCALE = val
    if settings is not None:
        try:
            settings.update_setting("scanning.font_scale", val)
        except Exception as e:
            logger.debug("persist scanning.font_scale: %s", e)
    return val


# Default at import (env or 1.0). Prefer :func:`get_scan_font_scale` when a
# settings manager is available so operator UI changes take effect.
SCAN_WINDOW_FONT_SCALE = get_scan_font_scale()

# Approximate default point size each terminal ships with, used as the
# base that ``font_scale`` multiplies. Only terminals with a reliable
# command-line font knob are scaled; the rest inherit the host font.
_BASE_FONT_SIZE: Dict[str, int] = {
    "xterm": 8,
    "kitty": 11,
    "foot": 12,
    "alacritty": 12,
}

# Approximate pixel cell size (w, h) for each terminal's *base* font, used
# by :func:`geometry_string` to turn a screen-slot pixel rect into a
# ``COLSxROWS`` terminal geometry. When ``font_scale`` > 1 the cell
# grows proportionally so the window still fits its slot instead of
# overflowing off-screen (which was why a 4x font showed only a few
# words — the geometry kept 120 columns that no longer fit).
_BASE_CELL_PX: Dict[str, Tuple[int, int]] = {
    "xterm": (8, 16),
    "kitty": (8, 16),
    "foot": (9, 18),
    "alacritty": (9, 18),
}


def font_argv(term: str, font_scale: Optional[float] = None) -> List[str]:
    """Return extra argv to scale ``term``'s font by ``font_scale``.

    ``font_scale`` of ``None`` or ``<= 1.0`` means "no change" → empty
    list. Only terminals with a reliable CLI font knob are handled
    (``xterm``, ``kitty``, ``foot``, ``alacritty``); ``gnome-terminal``,
    ``konsole``, ``xfce4-terminal`` and ``tmux`` have no stable CLI
    font-size flag, so they inherit the host terminal's font and this
    returns ``[]`` (the caller still launches normally).

    Examples::

        font_argv("xterm", 4.0)    -> ["-fa", "Mono", "-fs", "32"]
        font_argv("kitty", 4.0)     -> ["-o", "font_size=44"]
        font_argv("foot", 4.0)      -> ["--font", "Mono:size=48"]
        font_argv("alacritty", 4.0) -> ["-o", "font.size=48"]
        font_argv("xterm", None)    -> []
        font_argv("gnome-terminal", 4.0) -> []
    """
    if not font_scale or font_scale <= 1.0:
        return []
    base = _BASE_FONT_SIZE.get(term)
    if base is None:
        return []
    size = max(2, int(round(base * float(font_scale))))
    if term == "xterm":
        return ["-fa", "Mono", "-fs", str(size)]
    if term == "kitty":
        return ["-o", f"font_size={size}"]
    if term == "foot":
        return ["--font", f"Mono:size={size}"]
    if term == "alacritty":
        return ["-o", f"font.size={size}"]
    return []


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


def screen_size() -> tuple:
    """Return (width, height) in pixels. Fallback 1920x1080."""
    # env override for tests / headless
    env_w = os.environ.get("KFIOSA_SCREEN_W")
    env_h = os.environ.get("KFIOSA_SCREEN_H")
    if env_w and env_h:
        try:
            return int(env_w), int(env_h)
        except ValueError:
            pass
    try:
        r = subprocess.run(
            ["xdpyinfo"], capture_output=True, text=True, timeout=2,
        )
        for line in (r.stdout or "").splitlines():
            if "dimensions:" in line:
                # dimensions:    1920x1080 pixels
                part = line.split("dimensions:")[-1].strip().split()[0]
                w, h = part.lower().split("x")
                return int(w), int(h)
    except Exception:
        pass
    return 1920, 1080


def screen_layout_rects() -> Dict[str, Dict[str, int]]:
    """Pixel rects for triple scan windows (topleft / topright / bottomright).

    Each value: {x, y, w, h} in pixels. Char geometry derived in
    :func:`geometry_string`.
    """
    sw, sh = screen_size()
    half_w, half_h = sw // 2, sh // 2
    return {
        "topleft": {"x": 0, "y": 0, "w": half_w, "h": half_h},
        "topright": {"x": half_w, "y": 0, "w": half_w, "h": half_h},
        "bottomright": {"x": half_w, "y": half_h, "w": half_w, "h": half_h},
        "bottomleft": {"x": 0, "y": half_h, "w": half_w, "h": half_h},
    }


def _effective_cell_size(term: str, font_scale: Optional[float]) -> Tuple[int, int]:
    """Return the (width, height) in pixels of one terminal cell for
    ``term`` given ``font_scale``.

    The cell grows proportionally with the font scale so a window placed
    in a fixed screen slot always fits: at ``font_scale=4.0`` a cell is
    ~4× wider/taller, so :func:`geometry_string` emits ~4× fewer
    columns/rows for the same slot. This is what makes a scaled scanner
    window show a few large lines instead of overflowing off-screen.
    """
    base_w, base_h = _BASE_CELL_PX.get(term, (8, 16))
    scale = float(font_scale) if font_scale and font_scale > 1.0 else 1.0
    return max(2, int(round(base_w * scale))), max(4, int(round(base_h * scale)))


def geometry_string(
    position: str,
    *,
    cell_w: Optional[int] = None,
    cell_h: Optional[int] = None,
    font_scale: Optional[float] = None,
    term: Optional[str] = None,
) -> str:
    """Return X11-style ``COLSxROWS+X+Y`` for *position* slot.

    When ``cell_w`` / ``cell_h`` are not supplied they are derived from
    ``font_scale`` and ``term`` (see :func:`_effective_cell_size`) so the
    window fits its screen slot at any font scale. Pass explicit cell
    sizes to override (legacy behaviour).
    """
    rects = screen_layout_rects()
    r = rects.get(position) or rects["topleft"]
    if cell_w is None or cell_h is None:
        ew, eh = _effective_cell_size(term or "", font_scale)
        cell_w = cell_w if cell_w is not None else ew
        cell_h = cell_h if cell_h is not None else eh
    # Fit the pixel slot exactly. Never force floors that overflow at
    # large font_scale (old max(40, …)/max(12, …) made 3×–4× fonts spill
    # past the quadrant: 40×32px cells = 1280px on a 960px half-screen).
    cols = max(1, r["w"] // max(cell_w, 1))
    rows = max(1, r["h"] // max(cell_h, 1))
    # xterm uses pixel offsets in +X+Y
    return f"{cols}x{rows}+{r['x']}+{r['y']}"


def launch(cmd: List[str], log_path: str, settings=None,
           title: Optional[str] = None,
           font_scale: Optional[float] = None,
           geometry: Optional[str] = None,
           position: Optional[str] = None) -> subprocess.Popen:
    """Spawn ``cmd`` inside the detected external terminal, streaming
    output to ``log_path``.

    Args:
        cmd: the command (argv list) to run inside the terminal.
        log_path: file path to tee the command's output to. Parent
            directories are created.
        settings: optional settings manager; used for terminal selection
            if no cached choice is available.
        title: optional window/tab title.
        font_scale: optional multiplier on the terminal's base font size
            (e.g. ``4.0`` for a 4x-bigger scanner window, per the operator's
            request). Only terminals with a reliable CLI font knob are
            scaled (see :func:`font_argv`); others inherit the host font.
            ``None``/``<= 1.0`` leaves the font unchanged.
        geometry: optional ``COLSxROWS+X+Y`` (overrides *position*).
        position: optional slot ``topleft|topright|bottomright|bottomleft``.

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
    fargv = font_argv(term, font_scale)
    if geometry is None and position:
        try:
            geometry = geometry_string(position, font_scale=font_scale, term=term)
        except Exception:
            geometry = None
    gargv: List[str] = []
    if geometry:
        if term == "xterm":
            gargv = ["-geometry", geometry]
        elif term == "gnome-terminal":
            # cols x rows only (position not reliable)
            cols_rows = geometry.split("+")[0]
            gargv = [f"--geometry={cols_rows}"]
        elif term == "xfce4-terminal":
            gargv = [f"--geometry={geometry}"]
        elif term == "konsole":
            cols_rows = geometry.split("+")[0]
            gargv = ["-p", f"LocalTabTitleFormat={title}"]
            # konsole geometry is limited
            if "x" in cols_rows:
                try:
                    c, r = cols_rows.lower().split("x")
                    gargv.extend(["-p", f"TerminalColumns={c}", "-p", f"TerminalRows={r}"])
                except ValueError:
                    pass
        elif term == "alacritty":
            # alacritty --option window.dimensions / position via -o
            try:
                body = geometry.split("+")[0]
                c, r = body.lower().split("x")
                gargv = ["-o", f"window.dimensions.columns={c}",
                         "-o", f"window.dimensions.lines={r}"]
                parts = geometry.split("+")
                if len(parts) >= 3:
                    gargv.extend([
                        "-o", f"window.position.x={parts[1]}",
                        "-o", f"window.position.y={parts[2]}",
                    ])
            except Exception:
                gargv = []
        elif term == "kitty":
            try:
                body = geometry.split("+")[0]
                c, r = body.lower().split("x")
                gargv = ["-o", f"initial_window_width={c}c",
                         "-o", f"initial_window_height={r}c"]
            except Exception:
                gargv = []
        elif term == "foot":
            gargv = ["-W", geometry.split("+")[0]] if geometry else []

    if term == "xterm":
        argv = ["xterm", "-T", title, *gargv, *fargv, "-e", *wrapped]
    elif term == "gnome-terminal":
        # gnome-terminal accepts a single -- argument followed by the command.
        argv = ["gnome-terminal", "--title", title, *gargv, "--", *wrapped]
    elif term == "konsole":
        argv = ["konsole", "-p", f"tabtitle={title}", *gargv, "-e", *wrapped]
    elif term == "xfce4-terminal":
        argv = ["xfce4-terminal", "--title", title, *gargv, "-e",
                " ".join(shlex.quote(c) for c in wrapped)]
    elif term == "alacritty":
        argv = ["alacritty", "--title", title, *gargv, *fargv, "-e", *wrapped]
    elif term == "kitty":
        argv = ["kitty", "--title", title, *gargv, *fargv, *wrapped]
    elif term == "foot":
        argv = ["foot", "--title", title, *gargv, *fargv, *wrapped]
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

    logger.info(
        "launching %s in %s (log=%s geom=%s)",
        cmd[0] if cmd else "<cmd>", term, log_path, geometry or "-",
    )
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


def launch_placed(
    cmd: List[str],
    log_path: str,
    *,
    title: Optional[str] = None,
    position: str = "topleft",
    font_scale: Optional[float] = None,
    settings=None,
) -> subprocess.Popen:
    """Launch with screen-slot placement (topleft/topright/bottomright/…)."""
    return launch(
        cmd, log_path, settings=settings, title=title,
        font_scale=font_scale, position=position,
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
               title: Optional[str] = None,
               font_scale: Optional[float] = None,
               geometry: Optional[str] = None,
               position: Optional[str] = None) -> TerminalRun:
        self.calls.append({
            "cmd": list(cmd), "log_path": log_path, "title": title,
            "font_scale": font_scale,
            "geometry": geometry,
            "position": position,
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

    def launch_script_in_project_root(
        self,
        cmd_argv: List[str],
        log_path: str,
        title: Optional[str] = None,
        font_scale: float = SCAN_WINDOW_FONT_SCALE,
        wait_prompt: bool = True,
        settings=None,
        position: Optional[str] = None,
    ) -> TerminalRun:
        """Fake mirror of :func:`launch_script_in_project_root` that records
        the call and returns a :class:`TerminalRun` for test inspection."""
        self.calls.append({
            "cmd": list(cmd_argv),
            "log_path": log_path,
            "title": title,
            "font_scale": font_scale,
            "wait_prompt": wait_prompt,
            "position": position,
        })
        return TerminalRun(
            list(cmd_argv), log_path, self.term, title=title or (cmd_argv[0] if cmd_argv else "kfiosa")
        )

    def list_available(self) -> List[str]:
        return [self.term]


def launch_script_in_project_root(
    cmd_argv: List[str],
    log_path: str,
    title: Optional[str] = None,
    font_scale: float = SCAN_WINDOW_FONT_SCALE,
    wait_prompt: bool = True,
    settings=None,
    position: Optional[str] = None,
) -> subprocess.Popen:
    """Launch a Python module/script from the project root in an external terminal.

    This is the shared helper used by the WiFi/BLE scan screens. It builds a
    shell command that:

    - ``cd``s to the project root (two parents of this file),
    - sets ``TERM=xterm-256color`` so curses works,
    - prepends the project root to ``PYTHONPATH``,
    - runs ``cmd_argv``,
    - optionally prints a "close window" prompt and waits for Enter so the
      operator can review the scan output.

    It then delegates to :func:`launch` for terminal detection, font scaling,
    slot placement, and ``tee`` wrapping. The returned :class:`subprocess.Popen`
    is detached (``start_new_session=True``).

    Args:
        cmd_argv: the command as an argv list (e.g.
            ``[sys.executable, "-m", "core.tui.wifi_scan_external", ...]``).
        log_path: path to tee the command output to.
        title: window title; defaults to the first element of ``cmd_argv``.
        font_scale: font-size multiplier; defaults to
            :data:`SCAN_WINDOW_FONT_SCALE`.
        wait_prompt: when True, keep the terminal open after the scan with
            a prompt and ``read _``.
        settings: optional settings manager for terminal choice persistence.
        position: optional screen slot (``topleft`` / ``topright`` / …)
            so single-window scan fallbacks still land in a known quadrant.

    Returns:
        The :class:`subprocess.Popen` returned by :func:`launch`.
    """
    root = str(Path(__file__).resolve().parents[2])
    cmd_str = " ".join(shlex.quote(c) for c in cmd_argv)
    inner = (
        f"cd {shlex.quote(root)} && "
        f"export TERM=xterm-256color && "
        f"export PYTHONPATH={shlex.quote(root)}"
        f"${{PYTHONPATH:+:$PYTHONPATH}} && "
        f"{cmd_str}"
    )
    if wait_prompt:
        inner += "; echo; echo '[scan done — close window or press Enter]'; read _"
    wrapped = ["bash", "-lc", inner]
    return launch(
        wrapped,
        log_path,
        settings=settings,
        title=title,
        font_scale=font_scale,
        position=position,
    )


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
               title: Optional[str] = None,
               font_scale: Optional[float] = None,
               geometry: Optional[str] = None,
               position: Optional[str] = None,
               ) -> "subprocess.Popen | TerminalRun":
        return launch(
            cmd, log_path, self._settings, title=title,
            font_scale=font_scale, geometry=geometry, position=position,
        )

    def launch_step(self, step: Dict[str, Any]) -> "subprocess.Popen | TerminalRun":
        """Per-step launcher (see :func:`launch_step` for the contract)."""
        return launch_step(step, self._settings)

    def launch_script_in_project_root(
        self,
        cmd_argv: List[str],
        log_path: str,
        title: Optional[str] = None,
        font_scale: float = SCAN_WINDOW_FONT_SCALE,
        wait_prompt: bool = True,
        position: Optional[str] = None,
    ) -> "subprocess.Popen | TerminalRun":
        """Convenience wrapper around :func:`launch_script_in_project_root`
        using this backend's settings for terminal detection."""
        return launch_script_in_project_root(
            cmd_argv,
            log_path,
            title=title,
            font_scale=font_scale,
            wait_prompt=wait_prompt,
            settings=self._settings,
            position=position,
        )

    def detect(self) -> str:
        return detect(self._settings)

    def list_available(self) -> List[str]:
        return list_available()

    def __repr__(self) -> str:
        return f"ExternalTerminalBackend(term={self.term!r})"
