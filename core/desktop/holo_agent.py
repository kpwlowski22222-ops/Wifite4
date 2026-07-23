"""Holo Desktop CLI bridge — OS navigation for tools & AI models.

Wraps `holo-desktop-cli` (https://github.com/hcompai/holo-desktop-cli)
so KFIOSA can:

  * Drive real desktop apps (terminals, browsers, Ollama UI, settings)
  * Install / pull / switch AI models via the OS when CLI is insufficient
  * Open and configure pentest tools under operator ACCEPT

Safety:
  * Real desktop control is **default-deny** without ``confirm_fn``
  * Never fabricates success — missing ``holo`` binary → honest error
  * ``holo stop`` is always available as a kill switch

Primary path shells out to the ``holo`` CLI (works with installed
consumer install under ``~/.holo``). Optional Python API is used when
``holo_desktop`` is importable (editable / pip install).
"""
from __future__ import annotations

import logging
import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)

# Preset natural-language tasks for common KFIOSA desktop goals.
# These are *instructions* for Holo, not fabricated tool outputs.
TASK_PRESETS: Dict[str, str] = {
    "open_terminal": (
        "Open a terminal emulator (gnome-terminal, xterm, or konsole). "
        "Bring it to the foreground and leave a shell ready."
    ),
    "ollama_list": (
        "Open a terminal and run `ollama list`. Wait for the table of "
        "local models to appear so the operator can see what is installed."
    ),
    "ollama_serve": (
        "Open a terminal and ensure `ollama serve` is running in the "
        "background (or confirm the API is already up on 127.0.0.1:11434)."
    ),
    "ollama_pull_primary": (
        "Open a terminal and run `ollama pull` for the operator's primary "
        "local model (prefer xploiter/pentester:latest or the first listed "
        "pentester/uncensored model). Show progress until complete or error."
    ),
    "open_settings": (
        "Open the system settings / preferences application so the operator "
        "can adjust display, privacy, or network options."
    ),
    "open_browser_ollama": (
        "Open a web browser and navigate to http://127.0.0.1:11434 if the "
        "Ollama web UI is available, otherwise open the Ollama docs."
    ),
    "install_holo": (
        "Open a terminal and show the install command for holo-desktop-cli "
        "from https://github.com/hcompai/holo-desktop-cli (do not pipe "
        "curl|bash unless the operator confirms)."
    ),
    "wifi_monitor_help": (
        "Open a terminal and run `iw dev` then `airmon-ng` so the operator "
        "can see wireless interfaces and monitor-mode readiness."
    ),
    "ble_adapter_help": (
        "Open a terminal and run `rfkill list bluetooth; bluetoothctl power on; "
        "bluetoothctl show; hciconfig -a` so the operator can see BLE "
        "adapter state, soft-blocks, and powered controllers."
    ),
    # --- Long-range BLE / WiFi OS-agent assists (used by TUI + CLI) ---
    "ble_long_range_prep": (
        "Open a terminal and prepare the Bluetooth controller for maximum "
        "BLE discovery range: `rfkill unblock bluetooth`, "
        "`bluetoothctl power on`, `btmgmt le on` (if present), then "
        "`hciconfig hci0 up` or the first available hciN. Show final "
        "`bluetoothctl show` output. Do not start a long scan yet."
    ),
    "ble_scan_cli": (
        "Open a terminal in the KFIOSA project directory if visible, then "
        "run a long-range BLE discovery: "
        "`python3 -m core.tui.ble_scan_external --text --seconds 20 --pulse 8`. "
        "If that fails, fall back to `bluetoothctl scan on` for ~15s then "
        "`bluetoothctl devices`. Show discovered devices honestly."
    ),
    "ble_system_settings": (
        "Open the desktop Bluetooth / wireless settings panel (GNOME "
        "Settings → Bluetooth, or blueman-manager, or plasma-nm) so the "
        "operator can power the adapter and pair devices via the OS UI."
    ),
    "wifi_monitor_prep": (
        "Open a terminal and prepare WiFi monitor mode for scanning: run "
        "`iw dev`, identify the best wireless interface, then "
        "`airmon-ng check kill` only if the operator already confirmed "
        "destructive prep is allowed; otherwise just show `airmon-ng` and "
        "`iw list | head`. Report monitor-ready interface names."
    ),
    "wifi_scan_cli": (
        "Open a terminal in the KFIOSA project directory if visible and run "
        "`python3 -m core.tui.wifi_scan_external --text --seconds 12` on the "
        "monitor interface if known (else print how to pass --iface). "
        "Show AP list honestly; never invent networks."
    ),
    "kfiosa_dashboard": (
        "Open a terminal and show how to launch the KFIOSA dashboard with "
        "`sudo python main.py` or `./run_tui.sh` from the project root. "
        "Do not enter credentials."
    ),
    "install_ble_stack": (
        "Open a terminal and check for bleak/bluez tools: "
        "`python3 -c 'import bleak; print(bleak.__version__)'`, "
        "`which bluetoothctl hcitool btmgmt`. If bleak is missing, show "
        "`pip install bleak` (do not run pip unless operator confirms)."
    ),
    # --- Engagement / simplified TUI assists ---
    "wifi_scan_windows_layout": (
        "Open three terminal windows if possible and arrange them roughly "
        "as a 2x2 grid leaving bottom-left free: top-left for live APs, "
        "top-right for associated clients, bottom-right for offline APs. "
        "Do not invent networks; leave shells ready for KFIOSA scan modules."
    ),
    "post_access_browser_dashboard": (
        "Open a web browser and navigate to the local KFIOSA Flask RAT "
        "dashboard if known (try http://127.0.0.1:8765 or "
        "http://127.0.0.1:5000). If neither loads, open a terminal and show "
        "how to start the dashboard from the KFIOSA project. Never invent "
        "sessions or credentials."
    ),
    "engagement_tool_prep": (
        "Open a terminal in the KFIOSA project directory if visible. Check "
        "that ollama is reachable (`curl -s http://127.0.0.1:11434/api/tags` "
        "or `ollama list`), and that common kali tools exist "
        "(`which aircrack-ng airodump-ng hashcat nmap`). Report honestly."
    ),
}


def _find_holo_bin() -> str:
    """Locate the holo binary (PATH + common install locations)."""
    which = shutil.which("holo")
    if which:
        return which
    home = Path.home()
    candidates = [
        home / ".holo" / "bin" / "holo",
        home / ".local" / "bin" / "holo",
        Path("/usr/local/bin/holo"),
        Path("/usr/bin/holo"),
    ]
    sudo_user = os.environ.get("SUDO_USER") or ""
    if sudo_user:
        candidates.insert(0, Path(f"/home/{sudo_user}/.holo/bin/holo"))
        candidates.insert(1, Path(f"/home/{sudo_user}/.local/bin/holo"))
    for c in candidates:
        if c.is_file() and os.access(c, os.X_OK):
            return str(c)
    return ""


def holo_status() -> Dict[str, Any]:
    """Probe whether Holo is installed and ready (no side effects)."""
    bin_path = _find_holo_bin()
    out: Dict[str, Any] = {
        "ok": bool(bin_path),
        "holo_bin": bin_path or "",
        "version": "",
        "runtime_dir": str(Path.home() / ".holo" / "runtime"),
        "env_file": str(Path.home() / ".holo" / ".env"),
        "logged_in_hint": False,
        "python_api": False,
        "install_hint": (
            "curl -fsSL https://install.hcompany.ai/install.sh | bash\n"
            "  or: pip install holo-desktop-cli  "
            "(see https://github.com/hcompai/holo-desktop-cli)"
        ),
        "error": "" if bin_path else "holo binary not found on PATH",
        "model": "holo-desktop-bridge",
    }
    if bin_path:
        try:
            p = subprocess.run(
                [bin_path, "--version"],
                capture_output=True, text=True, timeout=8,
            )
            out["version"] = (p.stdout or p.stderr or "").strip()[:200]
        except Exception as e:  # noqa: BLE001
            out["version"] = f"(probe failed: {e})"
        env_path = Path.home() / ".holo" / ".env"
        out["logged_in_hint"] = env_path.is_file() and env_path.stat().st_size > 0
    try:
        import holo_desktop  # type: ignore  # noqa: F401
        out["python_api"] = True
    except Exception:  # noqa: BLE001
        out["python_api"] = False
    return out


def build_desktop_task(
    goal: str,
    *,
    tool: str = "",
    model: str = "",
    extra: str = "",
) -> str:
    """Build a natural-language desktop task for Holo.

    ``goal`` may be a preset key from :data:`TASK_PRESETS` or free text.
    Never invents that the task already succeeded.
    """
    g = (goal or "").strip()
    preset = TASK_PRESETS.get(g.lower().replace("-", "_").replace(" ", "_"))
    if preset:
        task = preset
    else:
        task = g or "Describe the visible desktop and list open windows."

    bits = [task]
    if tool:
        bits.append(
            f" Focus on the tool/application named {tool!r}: open it if "
            f"needed, bring it to the foreground, and prepare it for use."
        )
    if model:
        bits.append(
            f" Regarding AI model {model!r}: ensure it is available "
            f"(ollama list / pull / select) without deleting other models."
        )
    if extra:
        bits.append(" " + extra.strip())
    bits.append(
        " Do not type secrets or passwords. Stop when the goal is visible "
        "on screen or an honest error is shown."
    )
    return "".join(bits)


def stop_holo(*, force: bool = False) -> Dict[str, Any]:
    """Ask Holo to stop the current turn (or force-kill the runtime)."""
    bin_path = _find_holo_bin()
    if not bin_path:
        return {
            "ok": False,
            "error": "holo not installed",
            "install_hint": holo_status().get("install_hint"),
        }
    cmd = [bin_path, "stop"]
    if force:
        cmd.append("--force")
    try:
        p = subprocess.run(
            cmd, capture_output=True, text=True, timeout=20,
        )
        return {
            "ok": p.returncode == 0,
            "rc": p.returncode,
            "stdout": (p.stdout or "")[:4000],
            "stderr": (p.stderr or "")[:2000],
            "force": force,
        }
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": str(e), "force": force}


def run_holo_task(
    task: str,
    *,
    confirm_fn: Optional[Callable[[str], bool]] = None,
    max_steps: Optional[int] = None,
    max_time_s: Optional[float] = None,
    model: Optional[str] = None,
    base_url: Optional[str] = None,
    quiet: bool = True,
    fake: bool = False,
    timeout_s: Optional[float] = None,
    dry_run: bool = False,
) -> Dict[str, Any]:
    """Run a one-shot Holo desktop task (gated).

    Args:
        task: natural-language instruction for the desktop agent.
        confirm_fn: operator ACCEPT/CANCEL. Required unless ``fake`` or
            ``dry_run`` (dry_run only prints the planned argv).
        max_steps / max_time_s: Holo limits.
        model / base_url: optional Holo3 / local OpenAI-compatible server
            (e.g. local vLLM serving Holo3 weights).
        fake: ``holo run --fake`` (no desktop / model — for tests).
        dry_run: build argv only; do not execute.
    """
    t0 = time.time()
    task = (task or "").strip()
    if not task:
        return {"ok": False, "error": "task is required", "duration_s": 0.0}

    st = holo_status()
    if not st.get("ok") and not dry_run:
        return {
            "ok": False,
            "error": st.get("error") or "holo not available",
            "status": st,
            "duration_s": 0.0,
        }

    # Default-deny for real desktop control
    if not fake and not dry_run:
        if confirm_fn is None:
            return {
                "ok": False,
                "error": (
                    "no confirm_fn — desktop control blocked (default-deny). "
                    "Pass the TUI ACCEPT gate."
                ),
                "task": task[:500],
                "duration_s": 0.0,
            }
        preview = task if len(task) <= 280 else task[:277] + "…"
        if not confirm_fn(
            f"ACCEPT holo desktop control?\n  task: {preview}\n"
            f"  [y] run  [n] cancel  (double-Esc / holo stop aborts)"
        ):
            return {
                "ok": False,
                "error": "operator CANCELLED",
                "task": task[:500],
                "duration_s": round(time.time() - t0, 3),
            }

    bin_path = st.get("holo_bin") or "holo"
    cmd: List[str] = [bin_path, "run", task]
    if quiet:
        cmd.append("-q")
    if model:
        cmd.extend(["--model", str(model)])
    if base_url:
        cmd.extend(["--base-url", str(base_url)])
    if max_steps is not None:
        cmd.extend(["--max-steps", str(int(max_steps))])
    if max_time_s is not None:
        cmd.extend(["--max-time-s", str(float(max_time_s))])
    if fake:
        cmd.append("--fake")

    # Env: prefer local model URL from KFIOSA if set
    env = os.environ.copy()
    if base_url:
        env.setdefault("HOLO_BASE_URL", base_url)

    if dry_run:
        return {
            "ok": True,
            "dry_run": True,
            "cmd": cmd,
            "task": task,
            "status": st,
            "duration_s": 0.0,
        }

    # Wall-clock timeout for the subprocess (Holo also has max_time_s)
    wall = timeout_s
    if wall is None:
        wall = float(max_time_s) + 60.0 if max_time_s else 900.0
    wall = max(30.0, min(float(wall), 3600.0))

    try:
        p = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=wall,
            env=env,
        )
        stdout = (p.stdout or "")[:12000]
        stderr = (p.stderr or "")[:4000]
        return {
            "ok": p.returncode == 0,
            "rc": p.returncode,
            "task": task[:500],
            "cmd": cmd[:3] + ["…"] if len(cmd) > 3 else cmd,
            "stdout": stdout,
            "stderr": stderr,
            "duration_s": round(time.time() - t0, 3),
            "status": st,
            "model": "holo-desktop-bridge",
        }
    except subprocess.TimeoutExpired:
        # Best-effort stop so the agent does not keep clicking
        stop_holo(force=False)
        return {
            "ok": False,
            "error": f"holo run timed out after {wall}s (stop signal sent)",
            "task": task[:500],
            "duration_s": round(time.time() - t0, 3),
        }
    except FileNotFoundError:
        return {
            "ok": False,
            "error": "holo binary disappeared during run",
            "status": holo_status(),
            "duration_s": round(time.time() - t0, 3),
        }
    except Exception as e:  # noqa: BLE001
        return {
            "ok": False,
            "error": str(e),
            "task": task[:500],
            "duration_s": round(time.time() - t0, 3),
        }


def _holo_plan_to_task(plan: Dict[str, Any]) -> str:
    """Compose a predict→act→read→label desktop task from a structured AI
    plan (the deep holo OS-agent integration).

    ``plan`` keys (all optional, AI-decided):
      * ``what_to_click`` / ``where``: the control / coordinates to act on
      * ``what_for``: the human-meaningful goal of the click
      * ``predicted_outcome``: what the AI predicts will happen (verified
        against the post-action screen read — never fabricated)
      * ``goal`` / ``tool`` / ``model``: legacy preset passthrough
      * ``extra``: free-form extra instruction

    The instruction is honest text — never invents that the action
    already succeeded. Holo is told to *perform* the action then stop.
    """
    bits: List[str] = []
    wtc = str(plan.get("what_to_click") or "").strip()
    where = str(plan.get("where") or "").strip()
    what_for = str(plan.get("what_for") or "").strip()
    predicted = str(plan.get("predicted_outcome") or "").strip()

    goal = str(plan.get("goal") or "").strip()
    tool = str(plan.get("tool") or "").strip()
    model = str(plan.get("model") or "").strip()
    extra = str(plan.get("extra") or "").strip()

    if goal:
        preset = TASK_PRESETS.get(
            goal.lower().replace("-", "_").replace(" ", "_")
        )
        if preset:
            bits.append(preset)

    # Predict step: state the intention so the read/label loop can verify.
    head = []
    if what_for:
        head.append(f"Goal: {what_for}.")
    if wtc or where:
        loc = wtc or where
        head.append(f"Locate and activate {loc!r}.")
    if predicted:
        head.append(
            f"Predicted outcome (heuristic, verify after acting): {predicted}."
        )
    if head:
        bits.append(" ".join(head))

    if tool:
        bits.append(
            f" Focus on tool/application {tool!r}: open it if needed and "
            f"bring it to the foreground."
        )
    if model:
        bits.append(
            f" Regarding AI model {model!r}: ensure it is available "
            f"(ollama list / pull / select) without deleting other models."
        )
    if extra:
        bits.append(" " + extra.strip())
    if not bits:
        return "Describe the visible desktop and list open windows."
    bits.append(
        " Perform the intended action, then STOP when the result is visible "
        "on screen or an honest error is shown. Do not type secrets or "
        "passwords."
    )
    return "".join(bits)


def run_holo_plan(
    plan: Dict[str, Any],
    *,
    confirm_fn: Optional[Callable[[str], bool]] = None,
    max_steps: Optional[int] = None,
    max_time_s: Optional[float] = None,
    model: Optional[str] = None,
    base_url: Optional[str] = None,
    fake: bool = False,
    dry_run: bool = False,
    read_labels: bool = True,
    label_duration_s: float = 6.0,
) -> Dict[str, Any]:
    """Execute an AI-decided desktop plan: predict → act → read screen →
    verify the prediction → optionally live-label.

    This is the deep holo OS-agent integration: the AI decides *what to
    click, where, what for, and what will happen* (predict), then KFIOSA
    reads the screen afterwards and checks whether the predicted outcome
    actually appeared (heuristic token overlap — labelled
    ``model: "holo-ai-decide (heuristic)"``, never a trained classifier).

    Args:
        plan: dict with ``what_to_click`` / ``where`` / ``what_for`` /
            ``predicted_outcome`` (and optional ``goal``/``tool``/``model``/
            ``extra`` passthrough). May be empty → honest no-op.
        confirm_fn: operator ACCEPT/CANCEL gate (required unless fake /
            dry_run).
        read_labels: after the action, call
            :func:`core.utils.ui_navigator.HostVisionNavigator.read_screen_content`
            to capture the post-action screen text/labels.
        label_duration_s: when ``read_labels`` and the action succeeded,
            run a short live-labeling sweep so the AI loop has fresh
            labels for the next plan.

    Returns an envelope with ``plan``, ``predicted_outcome``, ``observed``
    (screen read), ``prediction_match`` (heuristic bool), ``labels``,
    and ``model: "holo-ai-decide (heuristic)"``.
    """
    t0 = time.time()
    if not isinstance(plan, dict):
        return {
            "ok": False,
            "error": "plan must be a dict",
            "duration_s": 0.0,
        }

    predicted = str(plan.get("predicted_outcome") or "").strip()
    task = _holo_plan_to_task(plan)

    acted = run_holo_task(
        task,
        confirm_fn=confirm_fn,
        max_steps=max_steps,
        max_time_s=max_time_s,
        model=model,
        base_url=base_url,
        fake=fake,
        dry_run=dry_run,
    )

    envelope: Dict[str, Any] = {
        "ok": bool(acted.get("ok")),
        "plan": plan,
        "task": task[:800],
        "predicted_outcome": predicted,
        "action": {k: v for k, v in acted.items() if k != "status"},
        "observed": None,
        "prediction_match": None,
        "labels": [],
        "model": "holo-ai-decide (heuristic)",
        "duration_s": round(time.time() - t0, 3),
    }
    # Propagate the action's error/cancellation up so callers can see why.
    if not acted.get("ok"):
        envelope["error"] = acted.get("error") or acted.get("stderr") or "holo action failed"

    if not read_labels or dry_run or fake:
        # Dry-run / fake / read disabled must never touch the real screen.
        envelope["observed"] = {
            "ok": False,
            "error": "dry_run" if (dry_run or fake) else "read_disabled",
            "labels": [],
            "text": "",
        }
        return envelope

    # Read the screen AFTER the action so the prediction can be verified.
    observed: Dict[str, Any] = {"ok": False, "labels": [], "text": ""}
    try:
        from core.utils.ui_navigator import navigator  # local import (cycle-safe)
        observed = navigator.read_screen_content() or observed
    except Exception as e:  # noqa: BLE001
        observed = {"ok": False, "error": f"navigator read failed: {e}",
                    "labels": [], "text": ""}
    envelope["observed"] = observed

    # Heuristic prediction verification: any predicted token (len>=4)
    # appears in the observed screen text/labels. Honest — if either side
    # is empty, match is None (not False), so we never claim a mismatch
    # we cannot actually measure.
    text_blob = (
        str(observed.get("text") or "") + " "
        + " ".join(str(x) for x in (observed.get("labels") or []))
    ).lower()
    if predicted and text_blob.strip():
        preds = [w for w in predicted.lower().split() if len(w) >= 4]
        matched = [w for w in preds if w and w in text_blob]
        envelope["prediction_match"] = bool(matched) if preds else None
        envelope["prediction_matched_tokens"] = matched
    else:
        envelope["prediction_match"] = None
        envelope["prediction_matched_tokens"] = []

    envelope["labels"] = observed.get("labels") or []

    # Optional live-labeling sweep for the next AI plan iteration.
    if acted.get("ok") and label_duration_s > 0:
        try:
            from core.utils.ui_navigator import navigator
            sweep = navigator.label_screen_live(duration_s=label_duration_s)
            envelope["live_labels"] = sweep.get("labels") or []
            envelope["live_labels_count"] = sweep.get("labels_count") or 0
        except Exception:  # noqa: BLE001
            envelope["live_labels"] = []
            envelope["live_labels_count"] = 0

    envelope["duration_s"] = round(time.time() - t0, 3)
    return envelope


class HoloDesktopBridge:
    """Object-oriented façade used by orchestrator / TUI / navigator."""

    def __init__(
        self,
        confirm_fn: Optional[Callable[[str], bool]] = None,
        settings: Any = None,
    ) -> None:
        self.confirm_fn = confirm_fn
        self.settings = settings

    def status(self) -> Dict[str, Any]:
        return holo_status()

    def _cfg(self) -> Dict[str, Any]:
        """Read holo.* settings if a settings manager is wired."""
        cfg: Dict[str, Any] = {
            "base_url": os.environ.get("HOLO_BASE_URL")
            or os.environ.get("KFIOSA_HOLO_BASE_URL")
            or "",
            "model": os.environ.get("HOLO_MODEL")
            or os.environ.get("KFIOSA_HOLO_MODEL")
            or "",
            "max_steps": None,
            "max_time_s": 600.0,
        }
        sm = self.settings
        if sm is not None:
            try:
                get = getattr(sm, "get_setting", None)
                if callable(get):
                    cfg["base_url"] = get("holo.base_url", cfg["base_url"]) or cfg["base_url"]
                    cfg["model"] = get("holo.model", cfg["model"]) or cfg["model"]
                    ms = get("holo.max_steps", None)
                    if ms not in (None, ""):
                        cfg["max_steps"] = int(ms)
                    mt = get("holo.max_time_s", cfg["max_time_s"])
                    if mt not in (None, ""):
                        cfg["max_time_s"] = float(mt)
            except Exception:  # noqa: BLE001
                pass
        return cfg

    def run_preset(
        self,
        preset: str,
        *,
        dry_run: bool = False,
        fake: bool = False,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """Convenience: run a TASK_PRESETS key (or free-text goal)."""
        return self.run(goal=preset, dry_run=dry_run, fake=fake, **kwargs)

    def run(
        self,
        task: str = "",
        *,
        goal: str = "",
        tool: str = "",
        model_name: str = "",
        extra: str = "",
        max_steps: Optional[int] = None,
        max_time_s: Optional[float] = None,
        fake: bool = False,
        dry_run: bool = False,
    ) -> Dict[str, Any]:
        """Run a desktop task; expand presets via ``goal`` if ``task`` empty."""
        if not task:
            task = build_desktop_task(
                goal or "open_terminal",
                tool=tool,
                model=model_name,
                extra=extra,
            )
        cfg = self._cfg()
        return run_holo_task(
            task,
            confirm_fn=self.confirm_fn,
            max_steps=max_steps if max_steps is not None else cfg.get("max_steps"),
            max_time_s=max_time_s if max_time_s is not None else cfg.get("max_time_s"),
            model=cfg.get("model") or None,
            base_url=cfg.get("base_url") or None,
            fake=fake,
            dry_run=dry_run,
        )

    def navigate_tool(self, tool: str, action: str = "open") -> Dict[str, Any]:
        """Open / prepare a named tool on the desktop."""
        return self.run(
            goal="open_terminal" if action == "open" else action,
            tool=tool,
            extra=f"Complete action {action!r} for tool {tool!r}.",
        )

    def navigate_model(self, model: str, action: str = "ensure") -> Dict[str, Any]:
        """Ensure an AI model is available via desktop/terminal automation."""
        if action in ("list", "ollama_list"):
            return self.run(goal="ollama_list")
        if action in ("serve", "ollama_serve"):
            return self.run(goal="ollama_serve")
        if action in ("pull", "ensure", "ollama_pull"):
            return self.run(
                goal="ollama_pull_primary" if not model else "",
                task="" if not model else build_desktop_task(
                    "ollama_pull_primary", model=model,
                ),
                model_name=model,
            )
        return self.run(model_name=model, extra=f"Action: {action}")

    def stop(self, force: bool = False) -> Dict[str, Any]:
        return stop_holo(force=force)

    def click(self, label: str) -> Dict[str, Any]:
        """Click a discovered OS control by label (HostVisionNavigator).

        Used by the OS-agent loop once ``read_screen_content`` /
        ``label_screen_live`` have surfaced a target. Delegates to
        :class:`core.utils.ui_navigator.HostVisionNavigator.click_label`
        so we do not pay for a full Holo subprocess when the AI
        already knows what to click.
        """
        try:
            from core.utils.ui_navigator import navigator  # local import
        except Exception as e:  # noqa: BLE001
            return {
                "ok": False,
                "error": f"navigator unavailable: {e}",
                "label": label,
            }
        return navigator.click_label(label)

    def run_plan(
        self,
        plan: Dict[str, Any],
        *,
        max_steps: Optional[int] = None,
        max_time_s: Optional[float] = None,
        fake: bool = False,
        dry_run: bool = False,
        read_labels: bool = True,
        label_duration_s: float = 6.0,
    ) -> Dict[str, Any]:
        """Execute an AI-decided predict→act→read→label desktop plan.

        Delegates to :func:`run_holo_plan` with this bridge's
        ``confirm_fn`` + holo settings (base_url/model/limits).
        """
        cfg = self._cfg()
        return run_holo_plan(
            plan,
            confirm_fn=self.confirm_fn,
            max_steps=max_steps if max_steps is not None else cfg.get("max_steps"),
            max_time_s=max_time_s if max_time_s is not None else cfg.get("max_time_s"),
            model=cfg.get("model") or None,
            base_url=cfg.get("base_url") or None,
            fake=fake,
            dry_run=dry_run,
            read_labels=read_labels,
            label_duration_s=label_duration_s,
        )


__all__ = [
    "TASK_PRESETS",
    "HoloDesktopBridge",
    "build_desktop_task",
    "holo_status",
    "run_holo_task",
    "run_holo_plan",
    "stop_holo",
]
