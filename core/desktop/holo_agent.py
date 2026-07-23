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
        "Open a terminal and run `bluetoothctl show` and `hciconfig -a` "
        "so the operator can see BLE adapter state."
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


__all__ = [
    "TASK_PRESETS",
    "HoloDesktopBridge",
    "build_desktop_task",
    "holo_status",
    "run_holo_task",
    "stop_holo",
]
