#!/usr/bin/env python3
"""Agentic TUI debugger for KFIOSA.

Launches the real dashboard under a pseudo-TTY::

    sudo -E python main.py

then drives it autonomously with arrows / Enter / Space / Backspace / q / F
and other hotkeys. On each step it:

1. Captures the screen (ANSI-stripped terminal dump).
2. Runs **deterministic oracles** (expected banners, menu labels, crash
   signatures, freeze / flip-flop patterns).
3. Optionally asks an **agent brain** (DeepSeek API preferred when online,
   else local Ollama offline models) whether behaviour looks correct and
   which key to press next.
4. Writes a JSON + human report under ``logs/agentic_tui_debug/``.

Usage (from repo root)::

    # full scripted walk + agentic decisions where useful
    python scripts/agentic_tui_debug.py

    # force local Ollama only (no cloud)
    python scripts/agentic_tui_debug.py --brain ollama

    # force DeepSeek
    python scripts/agentic_tui_debug.py --brain deepseek

    # dry-run: preflight + brain smoke only (no sudo TUI)
    python scripts/agentic_tui_debug.py --preflight-only

    # shorter run
    python scripts/agentic_tui_debug.py --max-steps 40 --no-agent-explore

Safety: never ACCEPTs gated offensive steps. Stays on navigation / pick /
settings surfaces and backs out of confirm prompts with q / Backspace / CANCEL.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

# ---------------------------------------------------------------------------
# Paths / env
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

try:
    from dotenv import load_dotenv  # type: ignore

    load_dotenv(REPO_ROOT / ".env")
except Exception:
    pass

# Prefer project venv python when available (same as run_tui.sh).
_VENV_PY = REPO_ROOT / ".venv" / "bin" / "python"
DEFAULT_PYTHON = str(_VENV_PY) if _VENV_PY.is_file() else sys.executable

DEFAULT_OLLAMA = os.getenv("OLLAMA_HOST", "http://127.0.0.1:11434").rstrip("/")
if "://" not in DEFAULT_OLLAMA:
    DEFAULT_OLLAMA = "http://" + DEFAULT_OLLAMA

# Local offline preference order (tags that match this operator's pulls).
OLLAMA_DEBUG_MODELS: Tuple[str, ...] = (
    os.getenv("KFIOSA_DEBUG_OLLAMA_MODEL", "").strip(),
    "llama3.1:8b",
    "wizard-vicuna-uncensored:latest",
    "llama2-uncensored:latest",
    "huihui_ai/phi4-abliterated:latest",
    "hf.co/mradermacher/Qwen3.5-9B-Claude-4.6-HighIQ-THINKING-HERETIC-UNCENSORED-GGUF:latest",
)
OLLAMA_DEBUG_MODELS = tuple(m for m in OLLAMA_DEBUG_MODELS if m)

DEEPSEEK_MODELS: Tuple[str, ...] = (
    os.getenv("DEEPSEEK_MODEL", "deepseek-chat").strip() or "deepseek-chat",
    "deepseek-chat",
    "deepseek-reasoner",
)

# Keys the agent may emit (canonical names → bytes / pexpect send).
KEYMAP: Dict[str, bytes] = {
    "up": b"\x1b[A",
    "down": b"\x1b[B",
    "left": b"\x1b[D",
    "right": b"\x1b[C",
    "enter": b"\r",
    "space": b" ",
    "backspace": b"\x7f",
    "escape": b"\x1b",
    "q": b"q",
    "Q": b"Q",
    "f": b"f",
    "F": b"F",
    "j": b"j",
    "k": b"k",
    "tab": b"\t",
    "1": b"1",
    "2": b"2",
    "3": b"3",
    "4": b"4",
    "5": b"5",
    "6": b"6",
    "7": b"7",
    "8": b"8",
    "9": b"9",
    "0": b"0",
    "c": b"c",  # cancel / cancel-ish prompts
    "n": b"n",
}

ANSI_RE = re.compile(r"\x1b(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")


# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------


@dataclass
class Finding:
    severity: str  # ok | info | warn | anomaly | fail
    code: str
    message: str
    screen_excerpt: str = ""
    step: int = 0

    def as_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class StepRecord:
    step: int
    action: str
    reason: str
    screen_hash: str
    screen_excerpt: str
    findings: List[Dict[str, Any]] = field(default_factory=list)
    brain: str = ""
    elapsed_ms: int = 0

    def as_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class RunReport:
    started_at: str
    finished_at: str = ""
    exit_code: int = 0
    sudo: bool = True
    python: str = ""
    cmd: List[str] = field(default_factory=list)
    brain_mode: str = "auto"
    brain_used: List[str] = field(default_factory=list)
    providers: Dict[str, Any] = field(default_factory=dict)
    steps: List[Dict[str, Any]] = field(default_factory=list)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    summary: Dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# Screen helpers
# ---------------------------------------------------------------------------


def strip_ansi(text: str) -> str:
    return ANSI_RE.sub("", text or "")


def screen_lines(raw: str, cols: int = 120, rows: int = 40) -> List[str]:
    """Best-effort screen reconstruction without pyte.

    Curses often redraws with cursor addressing; we keep printable lines
    and collapse empties for oracle matching.
    """
    clean = strip_ansi(raw)
    # Replace common control chars.
    clean = clean.replace("\r", "\n").replace("\x00", "")
    # Drop leftover CSI fragments.
    clean = re.sub(r"\x1b.", "", clean)
    lines = []
    for ln in clean.splitlines():
        # keep printable + spaces
        ln = "".join(ch if (ch.isprintable() or ch in "\t ") else " " for ch in ln)
        ln = ln.rstrip()
        if ln.strip():
            lines.append(ln[:cols])
    # Dedup consecutive identical lines (curses redraw spam).
    out: List[str] = []
    for ln in lines:
        if not out or out[-1] != ln:
            out.append(ln)
    return out[-rows:]


def screen_text(raw: str) -> str:
    return "\n".join(screen_lines(raw))


def screen_hash(text: str) -> str:
    import hashlib

    return hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Oracles — expected UI / anomaly detectors
# ---------------------------------------------------------------------------

# Strings that should appear at some point during a healthy boot.
EXPECTED_BOOT = (
    "KFIOSA",
    "Main Control Menu",
    "WiFi Scan",
    "BLE Scan",
    "OSINT",
    "Settings",
    "Quit",
)

# Crash / hard-fail signatures.
CRASH_PATTERNS = (
    re.compile(r"Traceback \(most recent call last\)", re.I),
    re.compile(r"_curses\.error", re.I),
    re.compile(r"cbreak\(\) returned ERR", re.I),
    re.compile(r"Segmentation fault", re.I),
    re.compile(r"Fatal Python error", re.I),
    re.compile(r"Killed", re.I),
)

# Gated / offensive confirmations — agent must NOT accept.
GATE_PATTERNS = (
    re.compile(r"\bACCEPT\b"),
    re.compile(r"\bCANCEL\b"),
    re.compile(r"type\s+ACCEPT", re.I),
    re.compile(r"confirm\s*\(", re.I),
)

# Iface pick / monitor flip-flop (the bug we just fixed).
MONITOR_ON = re.compile(r"Monitor mode ACTIVE|currently monitor|type monitor", re.I)
MANAGED_ON = re.compile(r"Managed mode ACTIVE|currently managed", re.I)
PICK_IFACE = re.compile(
    r"Pick Wireless Interface|Wireless Adapters|Detecting wireless", re.I
)

# Sub-screen banners (also match dump headers: ## state=wifi).
WIFI_MARKERS = re.compile(
    r"WIFI|WiFi Operations|Scan Networks|AIO ATTACK|state=wifi\b", re.I
)
BLE_MARKERS = re.compile(
    r"BLE|Bluetooth|Pick Bluetooth|state=ble\b", re.I
)
OSINT_MARKERS = re.compile(r"OSINT|state=osint\b", re.I)
SETTINGS_MARKERS = re.compile(
    r"Settings|Ollama|DeepSeek|timeout|state=settings\b", re.I
)
MAIN_MARKERS = re.compile(
    r"Main Control Menu|state=main_menu\b", re.I
)


def oracle_screen(
    text: str,
    *,
    step: int,
    expected_view: Optional[str] = None,
    prev_mode: Optional[str] = None,
) -> Tuple[List[Finding], Optional[str]]:
    """Return findings + inferred iface mode (monitor|managed|None)."""
    findings: List[Finding] = []
    excerpt = text[:800]

    for pat in CRASH_PATTERNS:
        if pat.search(text):
            findings.append(
                Finding(
                    "fail",
                    "crash_signature",
                    f"Crash/error signature matched: {pat.pattern}",
                    excerpt,
                    step,
                )
            )

    # Gate: never leave ACCEPT prompts unhandled as ok.
    if any(p.search(text) for p in GATE_PATTERNS):
        findings.append(
            Finding(
                "warn",
                "gate_prompt_visible",
                "ACCEPT/CANCEL gate visible — agent must CANCEL / back out",
                excerpt,
                step,
            )
        )

    mode: Optional[str] = prev_mode
    mon = bool(MONITOR_ON.search(text))
    man = bool(MANAGED_ON.search(text))
    if mon and man:
        # Same screen claiming both shortly is the enter-bounce bug.
        findings.append(
            Finding(
                "anomaly",
                "monitor_managed_flipflop",
                "Screen mentions both monitor ACTIVE and managed ACTIVE "
                "(possible leftover-ENTER bounce after iface pick)",
                excerpt,
                step,
            )
        )
        mode = "ambiguous"
    elif mon:
        if prev_mode == "monitor":
            pass
        mode = "monitor"
    elif man:
        if prev_mode == "monitor":
            findings.append(
                Finding(
                    "anomaly",
                    "unexpected_managed_after_monitor",
                    "Iface was monitor, now managed without an intentional toggle step",
                    excerpt,
                    step,
                )
            )
        mode = "managed"

    if expected_view == "main":
        if MAIN_MARKERS.search(text) or all(
            s in text for s in ("WiFi Scan", "BLE Scan", "Quit")
        ):
            findings.append(
                Finding(
                    "ok",
                    "main_menu_ok",
                    "Main Control Menu markers present",
                    "",
                    step,
                )
            )
        elif "KFIOSA" not in text and "state=" not in text:
            missing = [s for s in EXPECTED_BOOT if s not in text]
            findings.append(
                Finding(
                    "anomaly",
                    "main_menu_missing",
                    f"Main menu expected but missing markers: {missing[:5]}",
                    excerpt,
                    step,
                )
            )
    elif expected_view == "wifi" and not (
        WIFI_MARKERS.search(text)
        or "state=picker" in text
        or "Wireless Adapters" in text
    ):
        findings.append(
            Finding(
                "anomaly",
                "wifi_view_missing",
                "Expected WiFi screen markers not found",
                excerpt,
                step,
            )
        )
    elif expected_view == "ble" and not BLE_MARKERS.search(text):
        findings.append(
            Finding(
                "anomaly",
                "ble_view_missing",
                "Expected BLE screen markers not found",
                excerpt,
                step,
            )
        )
    elif expected_view == "osint" and not OSINT_MARKERS.search(text):
        findings.append(
            Finding(
                "anomaly",
                "osint_view_missing",
                "Expected OSINT screen markers not found",
                excerpt,
                step,
            )
        )
    elif expected_view == "settings" and not SETTINGS_MARKERS.search(text):
        findings.append(
            Finding(
                "anomaly",
                "settings_view_missing",
                "Expected Settings markers not found",
                excerpt,
                step,
            )
        )

    if "Terminal too small" in text:
        findings.append(
            Finding(
                "fail",
                "terminal_too_small",
                "TUI reports terminal too small — increase rows/cols",
                excerpt,
                step,
            )
        )

    return findings, mode


# ---------------------------------------------------------------------------
# Brain: DeepSeek + Ollama
# ---------------------------------------------------------------------------


class AgentBrain:
    """Decide next key / judge screen via DeepSeek (API) or local Ollama."""

    def __init__(self, mode: str = "auto", timeout: int = 45):
        self.mode = mode  # auto | deepseek | ollama | none
        self.timeout = timeout
        self.used: List[str] = []
        self.deepseek_key = os.getenv("DEEPSEEK_API_KEY", "").strip()
        self.deepseek_model = (
            os.getenv("DEEPSEEK_MODEL", "deepseek-chat").strip() or "deepseek-chat"
        )
        self.ollama_endpoint = DEFAULT_OLLAMA
        self._ollama_models: Optional[List[str]] = None

    def providers_status(self) -> Dict[str, Any]:
        ollama_ok, models = self._ollama_list()
        ds_ok = bool(self.deepseek_key)
        return {
            "deepseek": {
                "ok": ds_ok,
                "model": self.deepseek_model,
                "candidates": list(DEEPSEEK_MODELS),
            },
            "ollama": {
                "ok": ollama_ok,
                "endpoint": self.ollama_endpoint,
                "models_available": models[:30],
                "preferred": list(OLLAMA_DEBUG_MODELS),
            },
            "mode": self.mode,
        }

    def _ollama_list(self) -> Tuple[bool, List[str]]:
        if self._ollama_models is not None:
            return True, self._ollama_models
        try:
            import requests

            r = requests.get(f"{self.ollama_endpoint}/api/tags", timeout=5)
            if r.status_code != 200:
                return False, []
            models = [m.get("name", "") for m in r.json().get("models", []) if m.get("name")]
            self._ollama_models = models
            return True, models
        except Exception:
            return False, []

    def _pick_ollama_model(self) -> Optional[str]:
        ok, models = self._ollama_list()
        if not ok:
            return None
        # Exact match first.
        for pref in OLLAMA_DEBUG_MODELS:
            if pref in models:
                return pref
        # Fuzzy: tag without registry prefix.
        for pref in OLLAMA_DEBUG_MODELS:
            short = pref.split("/")[-1]
            for m in models:
                if m == short or m.endswith(":" + short.split(":")[-1]) or short in m:
                    return m
        # Any local non-cloud model.
        for m in models:
            if "cloud" not in m.lower():
                return m
        return models[0] if models else None

    def _chat_deepseek(self, system: str, user: str) -> Optional[str]:
        if not self.deepseek_key:
            return None
        import requests

        for model in DEEPSEEK_MODELS:
            try:
                r = requests.post(
                    "https://api.deepseek.com/chat/completions",
                    headers={
                        "Authorization": f"Bearer {self.deepseek_key}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "model": model,
                        "messages": [
                            {"role": "system", "content": system},
                            {"role": "user", "content": user},
                        ],
                        "temperature": 0.2,
                        "max_tokens": 600,
                    },
                    timeout=self.timeout,
                )
                if r.status_code == 200:
                    msg = r.json()["choices"][0]["message"]["content"]
                    if msg and msg.strip():
                        self.used.append(f"deepseek:{model}")
                        return msg.strip()
            except Exception:
                continue
        return None

    def _chat_ollama(self, system: str, user: str) -> Optional[str]:
        model = self._pick_ollama_model()
        if not model:
            return None
        import requests

        try:
            r = requests.post(
                f"{self.ollama_endpoint}/api/generate",
                json={
                    "model": model,
                    "system": system,
                    "prompt": user,
                    "stream": False,
                    "options": {"temperature": 0.2, "num_predict": 400},
                },
                timeout=self.timeout,
            )
            if r.status_code == 200:
                msg = (r.json().get("response") or "").strip()
                if msg:
                    self.used.append(f"ollama:{model}")
                    return msg
        except Exception:
            return None
        return None

    def chat(self, system: str, user: str) -> Tuple[Optional[str], str]:
        """Return (reply, provider_label)."""
        if self.mode == "none":
            return None, "none"
        order: List[str]
        if self.mode == "deepseek":
            order = ["deepseek"]
        elif self.mode == "ollama":
            order = ["ollama"]
        else:
            # auto: prefer local offline when reachable, else DeepSeek API.
            ok, _ = self._ollama_list()
            order = ["ollama", "deepseek"] if ok else ["deepseek", "ollama"]

        for who in order:
            if who == "deepseek":
                msg = self._chat_deepseek(system, user)
                if msg:
                    return msg, "deepseek"
            else:
                msg = self._chat_ollama(system, user)
                if msg:
                    return msg, "ollama"
        return None, "none"

    def judge_and_act(
        self,
        screen: str,
        goal: str,
        allowed_keys: Sequence[str],
        scripted_hint: str = "",
    ) -> Dict[str, Any]:
        """Ask the model for JSON: verdict + next_key + reason + anomalies."""
        system = (
            "You are a QA agent debugging a curses pentest TUI (KFIOSA). "
            "You only navigate with keys; you never approve offensive actions. "
            "If you see ACCEPT/CANCEL, always choose cancel/back (q or backspace). "
            "Reply with ONLY compact JSON (no markdown):\n"
            "{"
            '"verdict":"ok|anomaly|fail|unknown",'
            '"next_key":"<one of allowed keys>",'
            '"reason":"<short>",'
            '"anomalies":["..."]'
            "}"
        )
        user = (
            f"GOAL: {goal}\n"
            f"ALLOWED_KEYS: {list(allowed_keys)}\n"
            f"SCRIPTED_HINT: {scripted_hint or '(none)'}\n"
            f"SCREEN:\n```\n{screen[:3500]}\n```\n"
            "Pick next_key from ALLOWED_KEYS. Prefer scripted hint when screen matches."
        )
        raw, provider = self.chat(system, user)
        if not raw:
            return {
                "verdict": "unknown",
                "next_key": scripted_hint or "enter",
                "reason": "no brain response — using scripted/fallback",
                "anomalies": [],
                "provider": provider,
                "raw": "",
            }
        data = _parse_json_object(raw)
        if not data:
            return {
                "verdict": "unknown",
                "next_key": scripted_hint or "enter",
                "reason": f"unparseable brain reply: {raw[:200]}",
                "anomalies": ["brain_json_parse_failed"],
                "provider": provider,
                "raw": raw[:500],
            }
        key = str(data.get("next_key") or scripted_hint or "enter").strip().lower()
        if key not in KEYMAP and key not in allowed_keys:
            # normalize synonyms
            synonyms = {
                "return": "enter",
                "ret": "enter",
                "esc": "escape",
                "bksp": "backspace",
                "bs": "backspace",
                "back": "backspace",
            }
            key = synonyms.get(key, key)
        if key not in KEYMAP:
            key = scripted_hint if scripted_hint in KEYMAP else "enter"
        anomalies = data.get("anomalies") or []
        if not isinstance(anomalies, list):
            anomalies = [str(anomalies)]
        return {
            "verdict": str(data.get("verdict") or "unknown").lower(),
            "next_key": key,
            "reason": str(data.get("reason") or "")[:300],
            "anomalies": [str(a)[:200] for a in anomalies][:10],
            "provider": provider,
            "raw": raw[:500],
        }


def _parse_json_object(text: str) -> Optional[Dict[str, Any]]:
    text = (text or "").strip()
    if not text:
        return None
    # Strip markdown fences if present.
    if "```" in text:
        m = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.S)
        if m:
            text = m.group(1)
    # First {...} block.
    m = re.search(r"\{.*\}", text, re.S)
    if not m:
        return None
    try:
        obj = json.loads(m.group(0))
        return obj if isinstance(obj, dict) else None
    except Exception:
        # Trailing commas / single quotes — light repair.
        frag = m.group(0).replace("'", '"')
        frag = re.sub(r",\s*}", "}", frag)
        frag = re.sub(r",\s*]", "]", frag)
        try:
            obj = json.loads(frag)
            return obj if isinstance(obj, dict) else None
        except Exception:
            return None


# ---------------------------------------------------------------------------
# TUI session (pexpect)
# ---------------------------------------------------------------------------


class TuiSession:
    def __init__(
        self,
        *,
        python: str,
        use_sudo: bool = True,
        rows: int = 40,
        cols: int = 120,
        cwd: Optional[Path] = None,
        env: Optional[Dict[str, str]] = None,
        dump_path: Optional[Path] = None,
    ):
        self.python = python
        self.use_sudo = use_sudo
        self.rows = rows
        self.cols = cols
        self.cwd = str(cwd or REPO_ROOT)
        self.env = env or os.environ.copy()
        # Force larger terminal + non-focus noise off if needed.
        self.env.setdefault("TERM", "xterm-256color")
        self.env["LINES"] = str(rows)
        self.env["COLUMNS"] = str(cols)
        # Keep MCP autostart quiet if possible.
        self.env.setdefault("KFIOSA_MCP_AUTOSTART", "0")
        # Plain-text dump written by dashboard._maybe_dump_screen (curses instr).
        # Prefer /tmp so sudo-root writer and user-reader both can access.
        self.dump_path = Path(
            dump_path
            or self.env.get("KFIOSA_TUI_SCREEN_DUMP")
            or f"/tmp/kfiosa_tui_screen_{os.getpid()}.txt"
        )
        try:
            self.dump_path.parent.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass
        self.env["KFIOSA_TUI_SCREEN_DUMP"] = str(self.dump_path)
        # Fresh dump file so we do not read a stale previous run.
        try:
            if self.dump_path.exists():
                self.dump_path.unlink()
        except Exception:
            pass
        self.child = None
        self.cmd: List[str] = []
        self._buf = ""
        self._last_dump = ""

    def start(self, timeout: float = 45.0) -> None:
        import pexpect

        main_py = str(REPO_ROOT / "main.py")
        if self.use_sudo:
            # -E preserves DEEPSEEK/OLLAMA env; -n fails fast if password needed.
            self.cmd = [
                "sudo",
                "-n",
                "-E",
                self.python,
                main_py,
            ]
        else:
            self.cmd = [self.python, main_py]

        self.child = pexpect.spawn(
            self.cmd[0],
            self.cmd[1:],
            cwd=self.cwd,
            env=self.env,
            encoding=None,  # bytes mode
            timeout=timeout,
            dimensions=(self.rows, self.cols),
        )
        self.child.setwinsize(self.rows, self.cols)
        # Drain boot / preflight text; wait until dump file appears (curses up).
        self.wait_idle(max_s=3.0)
        deadline = time.time() + min(timeout, 30.0)
        while time.time() < deadline:
            if self.dump_path.is_file() and self.dump_path.stat().st_size > 20:
                break
            self.wait_idle(max_s=0.4, quiet_s=0.1)
            if not self.alive():
                break
        # Extra settle for shared resource init log lines.
        time.sleep(0.8)

    def alive(self) -> bool:
        return self.child is not None and self.child.isalive()

    def wait_idle(self, max_s: float = 2.0, quiet_s: float = 0.35) -> str:
        """Read until no new bytes for quiet_s or max_s elapsed."""
        if not self.child:
            return self._buf
        deadline = time.time() + max_s
        last_data = time.time()
        while time.time() < deadline:
            try:
                chunk = self.child.read_nonblocking(size=4096, timeout=0.15)
                if chunk:
                    if isinstance(chunk, str):
                        chunk = chunk.encode("utf-8", errors="ignore")
                    self._buf += chunk.decode("utf-8", errors="replace")
                    # Cap buffer.
                    if len(self._buf) > 200_000:
                        self._buf = self._buf[-100_000:]
                    last_data = time.time()
            except Exception:
                # timeout / EOF
                if not self.child.isalive():
                    break
            if time.time() - last_data >= quiet_s:
                break
        return self._buf

    def _read_dump(self) -> str:
        try:
            if self.dump_path.is_file():
                text = self.dump_path.read_text(encoding="utf-8", errors="replace")
                if text.strip():
                    self._last_dump = text
                    return text
        except Exception:
            pass
        return self._last_dump

    def screen(self) -> str:
        """Prefer dashboard dump (true curses view); fall back to pty bytes."""
        self.wait_idle(max_s=0.6, quiet_s=0.15)
        # Give the TUI a couple of frames to rewrite the dump after a key.
        for _ in range(8):
            dump = self._read_dump()
            if dump and (
                "KFIOSA" in dump
                or "state=" in dump
                or "Wireless" in dump
                or "Main Control" in dump
            ):
                return dump
            time.sleep(0.12)
        dump = self._read_dump()
        if dump:
            return dump
        return screen_text(self._buf)

    def send_key(self, name: str) -> None:
        if not self.child:
            raise RuntimeError("session not started")
        payload = KEYMAP.get(name)
        if payload is None:
            # allow raw single char
            if len(name) == 1:
                payload = name.encode("utf-8")
            else:
                raise ValueError(f"unknown key: {name}")
        self.child.send(payload)
        time.sleep(0.12)

    def send_keys(self, names: Sequence[str], pause: float = 0.25) -> None:
        for n in names:
            self.send_key(n)
            time.sleep(pause)

    def close(self, force_q: bool = True) -> int:
        if not self.child:
            return 0
        try:
            if force_q and self.child.isalive():
                # Best-effort clean quit from main menu.
                for _ in range(6):
                    self.child.send(KEYMAP["backspace"])
                    time.sleep(0.1)
                self.child.send(KEYMAP["q"])
                time.sleep(0.4)
            if self.child.isalive():
                self.child.terminate(force=True)
            self.child.close(force=True)
            return int(self.child.exitstatus or 0)
        except Exception:
            try:
                self.child.close(force=True)
            except Exception:
                pass
            return 1


# ---------------------------------------------------------------------------
# Scripted scenarios (deterministic skeleton)
# ---------------------------------------------------------------------------

# Each step: (key, expected_view, goal, use_brain?)
ScriptStep = Tuple[str, Optional[str], str, bool]


def build_script(max_explore: int = 0) -> List[ScriptStep]:
    """Safe navigation script covering main + sub-screens + iface pick path.

    Prefer ``j``/``k`` over CSI arrows: under pexpect+sudo the arrow escape
    sequences are often not assembled into curses KEY_DOWN/UP, while plain
    j/k always work (wired in dashboard + base_screen).
    """
    steps: List[ScriptStep] = [
        ("", "main", "Wait for main menu after boot", False),
        # Enter WiFi
        ("enter", "wifi", "Open WiFi Scan (first menu item)", True),
        # Primary → Advanced… (item index 6 of 8: 6× j)
        ("j", "wifi", "Move down WiFi primary menu", False),
        ("j", "wifi", "Move down WiFi primary menu", False),
        ("j", "wifi", "Move down WiFi primary menu", False),
        ("j", "wifi", "Move down WiFi primary menu", False),
        ("j", "wifi", "Move down WiFi primary menu", False),
        ("j", "wifi", "Move toward Advanced…", False),
        ("enter", "wifi", "Open Advanced submenu if highlighted", True),
        # Item 0 is Pick Wireless Interface — enter once only
        ("enter", "wifi", "Open wireless iface picker (single ENTER)", True),
        # If picker: wait / maybe j then enter once
        ("", "wifi", "Observe picker or monitor engage", True),
        ("enter", "wifi", "Confirm iface selection if picker still open", True),
        ("", "wifi", "Observe post-pick state (must stay monitor if engaged)", True),
        # Back to primary
        ("backspace", "wifi", "Back from Advanced/picker", False),
        ("backspace", "main", "Back to main menu", True),
        # BLE
        ("j", "main", "Highlight BLE Scan", False),
        ("enter", "ble", "Open BLE screen", True),
        ("enter", "ble", "Try first BLE action (pick adapter) carefully", True),
        ("", "ble", "Observe BLE pick/power result", True),
        ("backspace", "main", "Back to main from BLE", True),
        # OSINT
        ("j", "main", "Highlight OSINT", False),
        ("enter", "osint", "Open OSINT screen", True),
        ("backspace", "main", "Back to main from OSINT", True),
        # Settings
        ("j", "main", "Highlight Settings", False),
        ("enter", "settings", "Open Settings (AI provider status)", True),
        ("", "settings", "Verify DeepSeek/Ollama status lines if present", True),
        ("backspace", "main", "Back to main from Settings", True),
        # Focus toggle
        ("f", "main", "Toggle Focus Mode", False),
        ("f", "main", "Toggle Focus Mode back", False),
        # Quit last
        ("j", "main", "Move toward Quit", False),
        ("j", "main", "Move toward Quit", False),
        ("j", "main", "Move toward Quit", False),
        ("j", "main", "Highlight Quit", False),
        ("enter", "main", "Quit dashboard cleanly", False),
    ]
    if max_explore > 0:
        # Agent free-explore slots before quit.
        explore = [
            ("", "main", "Agent free explore — stay safe, no ACCEPT", True)
        ] * max_explore
        # Insert before final quit sequence (last 5 steps).
        steps = steps[:-5] + explore + steps[-5:]
    return steps


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------


def preflight_providers(brain: AgentBrain) -> Dict[str, Any]:
    st = brain.providers_status()
    # Also surface KFIOSA AIBackend.status() if importable.
    try:
        from core.ai_backend import AIBackend
        from core.settings import settings_manager

        try:
            settings_manager.load_settings()
        except Exception:
            pass
        ab = AIBackend(settings=settings_manager)
        st["kifiosa_ai_backend"] = ab.status()
    except Exception as e:
        st["kifiosa_ai_backend"] = {"error": str(e)}
    return st


def run_debug(args: argparse.Namespace) -> RunReport:
    started = datetime.now(timezone.utc).isoformat()
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    brain = AgentBrain(mode=args.brain, timeout=args.brain_timeout)
    providers = preflight_providers(brain)

    report = RunReport(
        started_at=started,
        sudo=not args.no_sudo,
        python=args.python,
        brain_mode=args.brain,
        providers=providers,
    )

    # Brain smoke: can we get a JSON reply?
    if not args.skip_brain_smoke and args.brain != "none":
        sample, prov = brain.chat(
            "Reply with ONLY JSON: {\"pong\": true, \"provider_check\": true}",
            "health check",
        )
        report.findings.append(
            Finding(
                "ok" if sample else "warn",
                "brain_smoke",
                f"brain smoke via {prov}: "
                + ("ok" if sample else "no response — scripted mode only"),
            ).as_dict()
        )

    if args.preflight_only:
        report.finished_at = datetime.now(timezone.utc).isoformat()
        report.brain_used = list(brain.used)
        report.summary = _summarize(report)
        _write_report(out_dir, report)
        return report

    # Ensure sudo works non-interactively when required.
    if not args.no_sudo:
        rc = subprocess.call(
            ["sudo", "-n", "true"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if rc != 0:
            report.findings.append(
                Finding(
                    "fail",
                    "sudo_required",
                    "sudo -n failed — configure passwordless sudo or pass --no-sudo "
                    "(monitor-mode paths need root)",
                ).as_dict()
            )
            report.exit_code = 2
            report.finished_at = datetime.now(timezone.utc).isoformat()
            report.summary = _summarize(report)
            _write_report(out_dir, report)
            return report

    if not shutil.which("python3") and not Path(args.python).exists():
        report.findings.append(
            Finding("fail", "python_missing", f"python not found: {args.python}").as_dict()
        )
        report.exit_code = 2
        report.finished_at = datetime.now(timezone.utc).isoformat()
        report.summary = _summarize(report)
        _write_report(out_dir, report)
        return report

    session = TuiSession(
        python=args.python,
        use_sudo=not args.no_sudo,
        rows=args.rows,
        cols=args.cols,
    )
    report.cmd = list(session.cmd) if session.cmd else (
        ["sudo", "-n", "-E", args.python, str(REPO_ROOT / "main.py")]
        if not args.no_sudo
        else [args.python, str(REPO_ROOT / "main.py")]
    )

    iface_mode: Optional[str] = None
    prev_hash = ""
    freeze_count = 0
    all_findings: List[Finding] = []

    try:
        session.start(timeout=args.boot_timeout)
        report.cmd = list(session.cmd)
        script = build_script(max_explore=args.explore_steps if args.agent_explore else 0)
        if args.max_steps > 0:
            script = script[: args.max_steps]

        for i, (hint_key, expected_view, goal, use_brain) in enumerate(script):
            if not session.alive():
                all_findings.append(
                    Finding(
                        "fail",
                        "process_died",
                        f"TUI process exited before step {i}",
                        step=i,
                    )
                )
                break

            t0 = time.time()
            scr = session.screen()
            h = screen_hash(scr)

            ofindings, iface_mode = oracle_screen(
                scr, step=i, expected_view=expected_view, prev_mode=iface_mode
            )
            all_findings.extend(ofindings)

            # Gate visible → force cancel path, never enter/ACCEPT.
            force_cancel = any(f.code == "gate_prompt_visible" for f in ofindings)

            action = hint_key
            reason = "scripted"
            brain_label = ""
            allowed = list(KEYMAP.keys())

            if force_cancel:
                action = "q"
                reason = "gate visible — cancel/quit key"
            elif use_brain and args.brain != "none" and not args.no_agent_decisions:
                decision = brain.judge_and_act(
                    scr,
                    goal=goal,
                    allowed_keys=allowed,
                    scripted_hint=hint_key or "enter",
                )
                brain_label = decision.get("provider") or ""
                action = decision.get("next_key") or hint_key or "enter"
                reason = decision.get("reason") or "brain"
                verdict = decision.get("verdict") or "unknown"
                for a in decision.get("anomalies") or []:
                    all_findings.append(
                        Finding("anomaly", "brain_flagged", str(a), scr[:400], i)
                    )
                if verdict in ("anomaly", "fail"):
                    all_findings.append(
                        Finding(
                            "anomaly" if verdict == "anomaly" else "fail",
                            "brain_verdict",
                            f"brain verdict={verdict}: {reason}",
                            scr[:400],
                            i,
                        )
                    )
                # Safety: never send enter if gate markers present.
                if force_cancel or "ACCEPT" in scr:
                    action = "backspace"
                    reason = "override: refuse ACCEPT path"
            elif not action:
                reason = "observe-only"

            # Observe-only step: no key.
            if action:
                try:
                    session.send_key(action)
                except Exception as e:
                    all_findings.append(
                        Finding("fail", "send_key_failed", f"{action}: {e}", step=i)
                    )

            # Let UI settle (longer after enter — airmon / pick).
            settle = 2.5 if action in ("enter",) else 0.6
            if PICK_IFACE.search(scr) or "Engaging monitor" in scr:
                settle = max(settle, 4.0)
            time.sleep(settle)
            scr_after = session.screen()
            of2, iface_mode = oracle_screen(
                scr_after, step=i, expected_view=expected_view, prev_mode=iface_mode
            )
            # Only keep new severities.
            all_findings.extend(of2)

            # Freeze = same step action did not change headers/content.
            def _hdr_token(text: str) -> str:
                hdrs = [ln for ln in text.splitlines() if ln.startswith("## ")][:3]
                return "|".join(hdrs) if hdrs else screen_hash(text)

            before_tok = _hdr_token(scr)
            after_tok = _hdr_token(scr_after)
            if (
                action
                and action not in ("",)
                and before_tok == after_tok
                and action in ("j", "k", "down", "up", "enter", "space", "backspace")
            ):
                freeze_count += 1
            else:
                freeze_count = 0
            if freeze_count >= 4:
                all_findings.append(
                    Finding(
                        "anomaly",
                        "screen_frozen",
                        f"Action {action!r} left screen unchanged "
                        f"{freeze_count}× ({after_tok[:120]})",
                        scr_after[:600],
                        i,
                    )
                )

            # Detect bounce: monitor then managed on same step after single enter.
            if (
                MONITOR_ON.search(scr)
                and MANAGED_ON.search(scr_after)
                and action == "enter"
            ):
                all_findings.append(
                    Finding(
                        "anomaly",
                        "enter_bounce_monitor_to_managed",
                        "After ENTER, screen went from monitor to managed "
                        "(leftover key / double-fire)",
                        scr_after[:600],
                        i,
                    )
                )

            rec = StepRecord(
                step=i,
                action=action or "observe",
                reason=f"{goal} | {reason}",
                screen_hash=screen_hash(scr_after),
                screen_excerpt="\n".join(
                    [ln for ln in scr_after.splitlines() if ln.startswith("## ")][:3]
                    + screen_lines(scr_after)[:22]
                ),
                findings=[f.as_dict() for f in ofindings + of2],
                brain=brain_label,
                elapsed_ms=int((time.time() - t0) * 1000),
            )
            report.steps.append(rec.as_dict())
            prev_hash = after_tok

            if not session.alive():
                break
            # Early stop if hard fail
            if any(f.severity == "fail" and f.code == "crash_signature" for f in of2):
                break

    except Exception as e:
        all_findings.append(
            Finding("fail", "runner_exception", f"{type(e).__name__}: {e}")
        )
    finally:
        code = session.close(force_q=True)
        report.exit_code = code

    # Deduplicate findings by code+message.
    seen = set()
    for f in all_findings:
        key = (f.severity, f.code, f.message)
        if key in seen:
            continue
        seen.add(key)
        report.findings.append(f.as_dict())

    report.brain_used = list(brain.used)
    report.finished_at = datetime.now(timezone.utc).isoformat()
    report.summary = _summarize(report)
    _write_report(out_dir, report)
    return report


def _summarize(report: RunReport) -> Dict[str, Any]:
    counts: Dict[str, int] = {}
    for f in report.findings:
        sev = f.get("severity", "info")
        counts[sev] = counts.get(sev, 0) + 1
    anomaly_codes = sorted(
        {
            f.get("code", "")
            for f in report.findings
            if f.get("severity") in ("anomaly", "fail", "warn")
        }
    )
    ok = counts.get("fail", 0) == 0 and counts.get("anomaly", 0) == 0
    return {
        "as_designed": ok,
        "counts": counts,
        "anomaly_codes": anomaly_codes,
        "steps": len(report.steps),
        "brain_used": report.brain_used,
        "providers_active": {
            "deepseek": bool(
                (report.providers.get("deepseek") or {}).get("ok")
            ),
            "ollama": bool((report.providers.get("ollama") or {}).get("ok")),
            "kifiosa_active": (report.providers.get("kifiosa_ai_backend") or {}).get(
                "active"
            ),
        },
    }


def _write_report(out_dir: Path, report: RunReport) -> Tuple[Path, Path]:
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    json_path = out_dir / f"agentic_tui_debug_{ts}.json"
    txt_path = out_dir / f"agentic_tui_debug_{ts}.txt"
    data = report.as_dict()
    json_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    # Human summary
    lines = [
        "KFIOSA agentic TUI debug report",
        f"started:  {report.started_at}",
        f"finished: {report.finished_at}",
        f"cmd:      {' '.join(report.cmd)}",
        f"brain:    {report.brain_mode} used={report.brain_used}",
        f"summary:  {json.dumps(report.summary, indent=2)}",
        "",
        "=== Findings ===",
    ]
    for f in report.findings:
        lines.append(
            f"[{f.get('severity')}] {f.get('code')}: {f.get('message')} (step={f.get('step')})"
        )
    lines.append("")
    lines.append("=== Steps (abbrev) ===")
    for s in report.steps:
        lines.append(
            f"#{s['step']:02d} key={s['action']!r} brain={s.get('brain') or '-'} "
            f"| {s['reason'][:80]}"
        )
    txt_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    # latest symlink-ish copies
    (out_dir / "latest.json").write_text(json.dumps(data, indent=2), encoding="utf-8")
    (out_dir / "latest.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return json_path, txt_path


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Agentic KFIOSA TUI debugger (sudo python main.py + key driver)",
    )
    p.add_argument(
        "--python",
        default=DEFAULT_PYTHON,
        help=f"Python interpreter (default: {DEFAULT_PYTHON})",
    )
    p.add_argument(
        "--no-sudo",
        action="store_true",
        help="Do not prefix with sudo -n -E (not recommended for wifi monitor)",
    )
    p.add_argument(
        "--brain",
        choices=("auto", "deepseek", "ollama", "none"),
        default="auto",
        help="Agent brain: auto prefers local Ollama then DeepSeek API",
    )
    p.add_argument(
        "--brain-timeout",
        type=int,
        default=45,
        help="Seconds per brain HTTP call",
    )
    p.add_argument(
        "--preflight-only",
        action="store_true",
        help="Only check DeepSeek/Ollama/AIBackend status; do not launch TUI",
    )
    p.add_argument(
        "--skip-brain-smoke",
        action="store_true",
        help="Skip the brain health-check chat",
    )
    p.add_argument(
        "--no-agent-decisions",
        action="store_true",
        help="Scripted keys only (oracles still run)",
    )
    p.add_argument(
        "--agent-explore",
        action="store_true",
        help="Insert free-explore steps for the brain",
    )
    p.add_argument(
        "--explore-steps",
        type=int,
        default=5,
        help="Free-explore step count when --agent-explore",
    )
    p.add_argument("--max-steps", type=int, default=0, help="Cap script steps (0=all)")
    p.add_argument("--rows", type=int, default=40)
    p.add_argument("--cols", type=int, default=120)
    p.add_argument("--boot-timeout", type=float, default=60.0)
    p.add_argument(
        "--out-dir",
        default=str(REPO_ROOT / "logs" / "agentic_tui_debug"),
        help="Report output directory",
    )
    return p


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_argparser().parse_args(argv)
    print("[*] KFIOSA agentic TUI debugger")
    print(f"    repo:   {REPO_ROOT}")
    print(f"    python: {args.python}")
    print(f"    sudo:   {not args.no_sudo}")
    print(f"    brain:  {args.brain}")
    print(f"    out:    {args.out_dir}")

    report = run_debug(args)
    summary = report.summary or {}
    print()
    print("=== RESULT ===")
    print(f"  as_designed: {summary.get('as_designed')}")
    print(f"  counts:      {summary.get('counts')}")
    print(f"  anomalies:   {summary.get('anomaly_codes')}")
    print(f"  brain_used:  {summary.get('brain_used')}")
    print(f"  providers:   {summary.get('providers_active')}")
    print(f"  steps:       {summary.get('steps')}")
    print(f"  reports:     {args.out_dir}/latest.{{json,txt}}")

    if not summary.get("as_designed", False):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
