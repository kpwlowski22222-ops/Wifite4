#!/usr/bin/env python3
"""
Settings Screen TUI
Settings & AI configuration sub-menu. View API Key presence, adjust parameters,
or view active configuration profile.
"""

import os
import logging
from typing import List

from core.tui.base_screen import BaseScreen
from core.settings import SettingsManager

logger = logging.getLogger(__name__)

class SettingsScreen(BaseScreen):
    def __init__(self, stdscr, parent_callback, activity_log: List[str], **kwargs):
        super().__init__(stdscr, parent_callback, activity_log, **kwargs)
        self.title = "Settings & AI Configuration"
        # Prefer the shared settings manager from the dashboard.
        self.settings_manager = kwargs.get("settings_manager") or SettingsManager()
        self.settings = self.settings_manager.load_settings()

        # Keep Settings short and practical — power features live under Advanced.
        self.menu_items = [
            ("AI status (Ollama + models)", self.view_ollama_status),
            ("API keys presence (.env)", self.view_api_keys_status),
            ("Set Ollama endpoint", self.set_ollama_endpoint),
            ("Model per domain (wifi/ble/osint/…)", self.select_domain_model),
            ("Plan creativity (balanced/high/max)", self.configure_plan_creativity),
            ("Narrative live story (on/off)", self.configure_narrative_log),
            ("Engagement memory (on/off)", self.configure_engagement_memory),
            ("Session compaction (on/off)", self.configure_session_compact),
            ("Scan timeouts (wifi / ble)", self.adjust_timeouts),
            ("External terminal", self.configure_external_terminal),
            ("Scan window font scale", self.configure_scan_font_scale),
            ("Advanced…", self._show_advanced_settings),
            ("Back to Main Menu", self.parent_callback),
        ]
        self._advanced_items = [
            ("Memory status / recent notes", self.view_memory_status),
            ("holaOS external status (optional)", self.holaos_external_status),
            ("Pull models (info)", self.pull_models_info),
            ("Holo desktop agent — status", self.holo_os_agent_status),
            ("Holo — dry-run task", self.holo_os_agent_dry_run),
            ("Holo — AI plan", self.holo_os_agent_plan),
            ("Toggle holo.enabled", self.toggle_holo_enabled),
            ("Fetch tool repos (toolboxes/)", self.fetch_toolboxes),
            ("Prepare toolboxes (deps)", self.prepare_toolboxes),
            ("Rebuild tool registry", self.rebuild_registry),
            ("MCP server info", self.mcp_info),
            ("KB re-categorize (info)", self.kb_recategorize_info),
            ("AI engine & model status", self.view_model_status),
            ("Vision OS learning toggle", self.toggle_vision_os_learning),
            ("Print full settings JSON", self.print_settings),
            ("Reset configuration", self.reset_settings),
            ("Back to simple Settings", self._show_simple_settings),
        ]

    def _show_advanced_settings(self):
        self.menu_items = list(self._advanced_items)
        self.menu_index = 0
        self.activity_log.append("[i] Settings → Advanced (power-user tools)")

    def _show_simple_settings(self):
        self.menu_items = [
            ("AI status (Ollama + models)", self.view_ollama_status),
            ("API keys presence (.env)", self.view_api_keys_status),
            ("Set Ollama endpoint", self.set_ollama_endpoint),
            ("Model per domain (wifi/ble/osint/…)", self.select_domain_model),
            ("Plan creativity (balanced/high/max)", self.configure_plan_creativity),
            ("Narrative live story (on/off)", self.configure_narrative_log),
            ("Engagement memory (on/off)", self.configure_engagement_memory),
            ("Session compaction (on/off)", self.configure_session_compact),
            ("Scan timeouts (wifi / ble)", self.adjust_timeouts),
            ("External terminal", self.configure_external_terminal),
            ("Scan window font scale", self.configure_scan_font_scale),
            ("Advanced…", self._show_advanced_settings),
            ("Back to Main Menu", self.parent_callback),
        ]
        self.menu_index = 0
        self.activity_log.append("[i] Settings → simple list")

    def configure_engagement_memory(self):
        cur = (os.environ.get("KFIOSA_MEMORY") or "1").strip().lower()
        on = cur not in ("0", "false", "no", "off")
        raw = self.get_input(
            f"Engagement memory [{'on' if on else 'off'}] (on/off; blank=toggle)"
        ).strip().lower()
        if not raw:
            on = not on
        elif raw in ("on", "1", "true", "yes"):
            on = True
        elif raw in ("off", "0", "false", "no"):
            on = False
        else:
            self.activity_log.append("[!] Use on or off.")
            return
        os.environ["KFIOSA_MEMORY"] = "1" if on else "0"
        self.activity_log.append(
            f"[+] Engagement memory {'ON' if on else 'OFF'} "
            "(local notes under data/memory/)."
        )

    def configure_session_compact(self):
        cur = (os.environ.get("KFIOSA_SESSION_COMPACT") or "1").strip().lower()
        on = cur not in ("0", "false", "no", "off")
        raw = self.get_input(
            f"Session compaction [{'on' if on else 'off'}] (on/off; blank=toggle)"
        ).strip().lower()
        if not raw:
            on = not on
        elif raw in ("on", "1", "true", "yes"):
            on = True
        elif raw in ("off", "0", "false", "no"):
            on = False
        else:
            self.activity_log.append("[!] Use on or off.")
            return
        os.environ["KFIOSA_SESSION_COMPACT"] = "1" if on else "0"
        self.activity_log.append(
            f"[+] Session compaction {'ON' if on else 'OFF'} "
            "(long re-plans use a compact checkpoint)."
        )

    def view_memory_status(self):
        try:
            from core.memory.store import list_notes, memory_root, memory_enabled
            from core.workspace.engagement_ws import list_recent, workspace_root
            self.activity_log.append("=== Engagement memory / workspaces ===")
            self.activity_log.append(
                f"[i] memory={'on' if memory_enabled() else 'off'} "
                f"root={memory_root()}"
            )
            notes = list_notes(limit=8)
            self.activity_log.append(f"[i] recent notes: {len(notes)}")
            for n in notes[:5]:
                self.activity_log.append(
                    f"  · [{n.get('kind')}] {(n.get('text') or '')[:80]}"
                )
            self.activity_log.append(f"[i] workspaces: {workspace_root()}")
            for w in list_recent(5):
                self.activity_log.append(
                    f"  · {w.get('id')} domain={w.get('domain')} "
                    f"label={w.get('label')}"
                )
        except Exception as e:
            self.activity_log.append(f"[!] memory status: {e}")

    def holaos_external_status(self):
        """Detect optional external holaOS install (not required)."""
        import pathlib
        candidates = []
        env_home = (os.environ.get("HOLAOS_HOME") or "").strip()
        if env_home:
            candidates.append(pathlib.Path(env_home))
        home = pathlib.Path.home()
        candidates.extend([
            home / "holaboss-ai",
            home / "holaOS",
            home / "holaos",
        ])
        self.activity_log.append("=== holaOS (external, optional) ===")
        self.activity_log.append(
            "[i] KFIOSA ports memory/workspace/compaction concepts natively."
        )
        self.activity_log.append(
            "[i] Full product: https://github.com/holaboss-ai/holaOS"
        )
        found = None
        for p in candidates:
            if p.is_dir() and (p / "package.json").is_file():
                found = p
                break
        if found:
            self.activity_log.append(f"[+] Found install at {found}")
        else:
            self.activity_log.append(
                "[i] No local holaOS tree found (OK — not required)."
            )
        # Distinguish from holo-desktop-cli
        try:
            from core.desktop.holo_agent import holo_status
            st = holo_status()
            self.activity_log.append(
                f"[i] holo-desktop-cli (GUI driver): "
                f"{'found' if st.get('holo_bin') else 'missing'} "
                f"{st.get('holo_bin') or ''}"
            )
        except Exception as e:
            self.activity_log.append(f"[i] holo-desktop probe: {e}")

    def configure_plan_creativity(self):
        """Set AI plan creativity: balanced | high | max."""
        cur = (os.environ.get("KFIOSA_PLAN_CREATIVITY") or "high").strip().lower()
        self.activity_log.append(f"[i] Plan creativity now: {cur}")
        raw = self.get_input(
            f"Creativity [{cur}] (balanced / high / max; blank=keep)"
        ).strip().lower()
        if not raw:
            self.activity_log.append("[i] Creativity unchanged.")
            return
        if raw not in ("balanced", "high", "max"):
            self.activity_log.append("[!] Use balanced, high, or max.")
            return
        os.environ["KFIOSA_PLAN_CREATIVITY"] = raw
        try:
            self.settings_manager.update_setting("ai.plan_creativity", raw)
        except Exception:
            pass
        self.activity_log.append(
            f"[+] Plan creativity set to {raw} "
            "(more creative chains; ACCEPT gates still apply)."
        )

    def configure_narrative_log(self):
        """Toggle human-language live story panel."""
        cur = (os.environ.get("KFIOSA_NARRATIVE_LOG") or "1").strip().lower()
        on = cur not in ("0", "false", "no", "off")
        self.activity_log.append(
            f"[i] Narrative live story is {'ON' if on else 'OFF'}"
        )
        raw = self.get_input(
            f"Narrative log [{'on' if on else 'off'}] (on/off; blank=toggle)"
        ).strip().lower()
        if not raw:
            on = not on
        elif raw in ("on", "1", "true", "yes"):
            on = True
        elif raw in ("off", "0", "false", "no"):
            on = False
        else:
            self.activity_log.append("[!] Use on or off.")
            return
        os.environ["KFIOSA_NARRATIVE_LOG"] = "1" if on else "0"
        self.activity_log.append(
            f"[+] Narrative live story {'ON' if on else 'OFF'} "
            "(right-side story panel)."
        )

    def holo_os_agent_status(self):
        """Probe holo-desktop-cli (OS agentic tool) without driving the desktop."""
        self.activity_log.append("=== OS Agentic CLI (holo-desktop-cli) ===")
        try:
            from core.desktop.holo_agent import TASK_PRESETS, holo_status
            st = holo_status()
        except Exception as e:
            self.activity_log.append(f"[!] holo bridge unavailable: {e}")
            return
        enabled = True
        try:
            enabled = bool(
                self.settings_manager.get_setting("holo.enabled", True)
            )
        except Exception:
            pass
        self.activity_log.append(
            f"[{'+' if st.get('ok') else '!'}] binary={st.get('holo_bin') or 'NOT FOUND'} "
            f"enabled={enabled}"
        )
        if st.get("version"):
            self.activity_log.append(f"[i] version: {st.get('version')}")
        self.activity_log.append(
            f"[i] logged_in_hint={st.get('logged_in_hint')} "
            f"python_api={st.get('python_api')}"
        )
        if st.get("error"):
            self.activity_log.append(f"[!] {st.get('error')}")
            self.activity_log.append(
                "[i] Install: pip install holo-desktop-cli  "
                "or see https://github.com/hcompai/holo-desktop-cli"
            )
        self.activity_log.append(
            f"[i] presets: {len(TASK_PRESETS)} "
            f"(ble_long_range_prep, ble_scan_cli, wifi_scan_cli, …)"
        )
        self.activity_log.append(
            "[i] CLI: python main.py --cli holo status | "
            "python main.py --cli holo run --goal ble_long_range_prep --yes"
        )
        self.activity_log.append(
            "[i] Kill switch: python main.py --cli holo stop"
        )

    def holo_os_agent_dry_run(self):
        """Build a Holo desktop argv without executing (safe for tests)."""
        goal = self.get_input(
            "Holo preset/goal (e.g. ble_long_range_prep, ollama_list, open_terminal)"
        ).strip()
        if not goal:
            goal = "ble_adapter_help"
        self.activity_log.append(f"[*] Holo dry-run goal={goal!r}…")
        try:
            from core.desktop.holo_agent import HoloDesktopBridge
            # Dry-run: no desktop action executes, but the bridge still gets a
            # default-deny gate so an accidental dry_run=False refactor cannot
            # auto-ACCEPT real desktop control.
            bridge = HoloDesktopBridge(
                confirm_fn=lambda _p: False,
                settings=self.settings_manager,
            )
            result = bridge.run(goal=goal, dry_run=True)
            self.activity_log.append(
                f"[{'+' if result.get('ok') else '!'}] dry_run ok={result.get('ok')}"
            )
            if result.get("cmd"):
                self.activity_log.append(f"[i] cmd: {result['cmd']}")
            if result.get("task"):
                for line in str(result["task"]).splitlines()[:4]:
                    self.activity_log.append(f"    {line[:100]}")
            if result.get("error"):
                self.activity_log.append(f"[!] {result['error']}")
        except Exception as e:
            self.activity_log.append(f"[!] holo dry-run error: {e}")

    def holo_os_agent_plan(self):
        """Run an AI-decided Holo desktop plan: predict→act→read→label.

        Collects what/where/what_for/predicted_outcome from the operator,
        then executes via :class:`core.desktop.holo_agent.HoloDesktopBridge`
        behind the shared TUI ACCEPT/CANCEL gate. Results (observed labels,
        prediction match, errors) are appended to the activity log.
        """
        what = self.get_input("What to click / do (e.g. 'terminal icon')").strip()
        where = self.get_input("Where on screen (e.g. 'top-left dock')").strip()
        what_for = self.get_input("What is this for (e.g. 'open a shell')").strip()
        predicted = self.get_input(
            "Predicted outcome (e.g. 'terminal window appears')"
        ).strip()
        goal = self.get_input(
            "Holo preset/goal (optional, e.g. open_terminal)"
        ).strip()
        tool = self.get_input("Tool focus (optional)").strip()
        model = self.get_input("Model focus (optional)").strip()

        max_steps_str = self.get_input("Max steps (default 5)").strip()
        try:
            max_steps = int(max_steps_str) if max_steps_str else 5
        except ValueError:
            max_steps = 5

        read_labels = (
            self.get_input("Read/label screen after action? [Y/n]").strip().lower()
            != "n"
        )
        label_duration_str = self.get_input(
            "Label duration seconds (default 6)"
        ).strip()
        try:
            label_duration_s = float(label_duration_str) if label_duration_str else 6.0
        except ValueError:
            label_duration_s = 6.0

        dry_run = (
            self.get_input("Dry-run only? [y/N]").strip().lower() == "y"
        )

        plan = {
            "what_to_click": what,
            "where": where,
            "what_for": what_for,
            "predicted_outcome": predicted,
            "goal": goal,
            "tool": tool,
            "model": model,
        }

        confirm_fn = (
            self.tui_confirm.confirm if self.tui_confirm is not None else None
        )
        summary = what_for or goal or "desktop action"
        self.activity_log.append(f"[*] Holo plan: {summary} …")

        def _run():
            try:
                from core.desktop.holo_agent import HoloDesktopBridge
                bridge = HoloDesktopBridge(
                    confirm_fn=confirm_fn,
                    settings=self.settings_manager,
                )
                result = bridge.run_plan(
                    plan,
                    max_steps=max_steps,
                    read_labels=read_labels,
                    label_duration_s=label_duration_s,
                    dry_run=dry_run,
                )
                self.activity_log.append(
                    f"[{'+' if result.get('ok') else '!'}] Holo plan "
                    f"{'dry-run' if dry_run else 'finished'} "
                    f"ok={result.get('ok')}"
                )
                if result.get("predicted_outcome"):
                    self.activity_log.append(
                        f"[i] predicted: {result['predicted_outcome']}"
                    )
                observed = result.get("observed") or {}
                if observed.get("ok"):
                    self.activity_log.append(
                        f"[i] observed {observed.get('count', 0)} labels"
                    )
                elif observed.get("error"):
                    self.activity_log.append(
                        f"[!] observed error: {observed['error']}"
                    )
                match = result.get("prediction_match")
                if match is True:
                    self.activity_log.append("[+] prediction verified")
                elif match is False:
                    self.activity_log.append("[-] prediction NOT verified")
                if result.get("live_labels_count"):
                    self.activity_log.append(
                        f"[i] live labels: {result['live_labels_count']}"
                    )
                if result.get("error"):
                    self.activity_log.append(f"[!] {result['error']}")
            except Exception as e:
                self.activity_log.append(f"[!] Holo plan error: {e}")

        self._spawn(_run)

    def toggle_holo_enabled(self):
        """Flip settings holo.enabled (chain dispatch still ACCEPT-gated)."""
        try:
            cur = bool(self.settings_manager.get_setting("holo.enabled", True))
        except Exception:
            cur = True
        new = not cur
        try:
            self.settings_manager.update_setting("holo.enabled", new)
        except Exception as e:
            self.activity_log.append(f"[!] cannot update holo.enabled: {e}")
            return
        self.activity_log.append(
            f"[+] holo.enabled = {new} "
            f"(desktop steps still require ACCEPT; CLI uses --yes)"
        )

    def view_ollama_status(self):
        """Show Ollama reachability + pulled models + per-domain mapping."""
        self.activity_log.append("=== Ollama Backend Status ===")
        backend = self.ai_backend
        if backend is None:
            self.activity_log.append("[!] AI backend not initialized")
            return
        st = backend.status()
        if st["ollama"]:
            self.activity_log.append(
                f"[+] Ollama reachable @ {st['ollama_endpoint']} "
                f"({len(st['ollama_models'])} models)"
            )
            for m in st["ollama_models"]:
                self.activity_log.append(f"    · {m}")
        else:
            self.activity_log.append(f"[!] Ollama unreachable @ {st['ollama_endpoint']}")
        # Per-domain mapping
        dm = (self.settings.get("ollama", {}) or {}).get("domain_models", {}) \
            if isinstance(self.settings, dict) else {}
        from core.ai_backend import MODEL_CATALOG
        self.activity_log.append("[i] Per-domain model mapping:")
        for dom in ("wifi", "ble", "osint", "post_exploitation", "c2"):
            chosen = dm.get(dom) or MODEL_CATALOG.get(dom) or "?"
            installed = "installed" if chosen in st.get("ollama_models", []) else "NOT pulled"
            self.activity_log.append(f"    {dom:18} -> {chosen}  [{installed}]")
        self.activity_log.append(f"[i] Active provider: {st['active']}")

    def set_ollama_endpoint(self):
        ep = self.get_input("Ollama endpoint (e.g. http://127.0.0.1:11434)")
        if not ep:
            return
        self.settings_manager.update_setting("ollama.endpoint", ep.strip())
        # Rebind the shared backend so the change takes effect immediately.
        if self.ai_backend is not None:
            self.ai_backend.ollama.endpoint = ep.strip()
            if "://" not in self.ai_backend.ollama.endpoint:
                self.ai_backend.ollama.endpoint = "http://" + self.ai_backend.ollama.endpoint
        self.activity_log.append(f"[+] Ollama endpoint set to {ep}")

    def select_domain_model(self):
        from core.ai_backend import MODEL_CATALOG
        domains = ["wifi", "ble", "osint", "post_exploitation", "c2"]
        dom = self.get_input(f"Domain ({', '.join(domains)})")
        if dom not in domains:
            self.activity_log.append(f"[!] Unknown domain: {dom!r}")
            return
        current = ((self.settings.get("ollama", {}) or {}).get("domain_models", {})
                   if isinstance(self.settings, dict) else {}).get(dom, MODEL_CATALOG.get(dom))
        model = self.get_input(f"Model tag for {dom} (enter=keep {current})")
        if not model:
            return
        # Write nested key via dot notation.
        self.settings_manager.update_setting(f"ollama.domain_models.{dom}", model.strip())
        self.activity_log.append(f"[+] {dom} -> {model}")

    def pull_models_info(self):
        self.activity_log.append("[i] Pull models via CLI:")
        self.activity_log.append("    python scripts/model_downloader.py pull")
        self.activity_log.append("    python scripts/model_downloader.py list")

    def fetch_toolboxes(self):
        """Clone the most-useful repos from the KB into toolboxes/<domain>/.

        Runs in a daemon thread so the curses UI stays responsive; progress is
        streamed to the activity log. No per-tool Python wrappers are created —
        the real upstream repos land on disk under toolboxes/.
        """
        dom = self.get_input(
            "Domain to fetch (wifi/ble/osint/post_exploitation/c2) or blank=all"
        ).strip().lower()
        limit_s = self.get_input("Top-N repos per domain (e.g. 15)").strip()
        try:
            limit = int(limit_s) if limit_s else 15
        except ValueError:
            limit = 15
        args = []
        if dom:
            args.append(dom)
        else:
            args.append("--all")
        args += ["--limit", str(limit)]
        self.activity_log.append(
            f"[*] Fetching tool repos ({'all' if not dom else dom}, "
            f"limit {limit}) into toolboxes/ ..."
        )

        def run():
            try:
                import subprocess as _sp
                import sys as _sys
                p = _sp.run(
                    [_sys.executable, "scripts/fetch_toolboxes.py"] + args,
                    cwd=os.path.dirname(os.path.dirname(os.path.dirname(
                        os.path.abspath(__file__)))),
                    capture_output=True, text=True,
                )
                for line in (p.stdout or "").splitlines():
                    if line.strip():
                        self.activity_log.append(f"  {line.strip()}")
                if p.returncode != 0 and p.stderr:
                    self.activity_log.append(f"[!] {p.stderr.strip()[:200]}")
                self.activity_log.append(
                    "[+] Fetch complete — repos are under toolboxes/<domain>/."
                )
            except Exception as e:
                self.activity_log.append(f"[!] fetch error: {e}")

        self._spawn(run)

    def prepare_toolboxes(self):
        """Install per-repo requirements + chmod scripts so cloned tools run.

        Resumable; per-repo pip installs run in a daemon thread.
        """
        dom = self.get_input(
            "Domain to prepare (wifi/ble/...) or blank=all"
        ).strip().lower()
        args = []
        if dom:
            args.append(dom)
        else:
            args.append("--all")
        self.activity_log.append(
            f"[*] Preparing toolboxes ({'all' if not dom else dom}): "
            "chmod + pip install -r requirements.txt ..."
        )

        def run():
            try:
                import subprocess as _sp
                import sys as _sys
                p = _sp.run(
                    [_sys.executable, "scripts/prepare_toolboxes.py"] + args,
                    cwd=os.path.dirname(os.path.dirname(os.path.dirname(
                        os.path.abspath(__file__)))),
                    capture_output=True, text=True,
                )
                for line in (p.stdout or "").splitlines():
                    if line.strip():
                        self.activity_log.append(f"  {line.strip()}")
                if p.returncode != 0 and p.stderr:
                    self.activity_log.append(f"[!] {p.stderr.strip()[:200]}")
                # Rebuild the registry so newly-prepared entry points surface.
                try:
                    from core.tool_registry import ToolRegistry
                    st = ToolRegistry().build()
                    self.activity_log.append(
                        f"[+] Registry rebuilt: {st['total']} tools "
                        f"(toolbox={st['toolbox']}, kali={st['kali']}, "
                        f"venv={st['venv']})"
                    )
                except Exception as e:
                    self.activity_log.append(f"[!] registry rebuild: {e}")
            except Exception as e:
                self.activity_log.append(f"[!] prepare error: {e}")

        self._spawn(run)

    def rebuild_registry(self):
        """Scan toolboxes + Kali + venv and rebuild the AI tool registry."""
        self.activity_log.append("[*] Rebuilding tool registry ...")

        def run():
            try:
                from core.tool_registry import ToolRegistry
                st = ToolRegistry().build()
                self.activity_log.append(
                    f"[+] Registry: {st['total']} tools "
                    f"(toolbox={st['toolbox']}, kali={st['kali']}, venv={st['venv']})"
                )
                self.activity_log.append(
                    "[i] by domain: "
                    + ", ".join(f"{k}={v}" for k, v in list(st['by_domain'].items())[:8])
                )
            except Exception as e:
                self.activity_log.append(f"[!] registry error: {e}")

        self._spawn(run)

    def mcp_info(self):
        """Tell the operator how to expose the registry to AI clients via MCP."""
        self.activity_log.append("=== MCP Server (AI client bridge) ===")
        self.activity_log.append(
            "[i] A dependency-free stdio MCP server exposes the tool"
        )
        self.activity_log.append(
            "    registry to any MCP-aware AI client (Claude Desktop,"
        )
        self.activity_log.append(
            "    an Ollama MCP bridge, custom agents). It offers:"
        )
        self.activity_log.append("    tools: list_tools, search_tools, get_tool_usage, run_tool")
        self.activity_log.append("    resources: registry://summary, tool://<source>/<name>")
        self.activity_log.append("[i] Start it in a separate terminal:")
        self.activity_log.append("    source .venv/bin/activate && python -m core.mcp_server")
        self.activity_log.append("[i] Self-test (no client needed):")
        self.activity_log.append("    python -m core.mcp_server --self-test")
        self.activity_log.append(
            "[!] run_tool is gated (default-deny); enable with"
        )
        self.activity_log.append("    KFIOSA_MCP_ALLOW_EXEC=1 python -m core.mcp_server")

    def kb_recategorize_info(self):
        self.activity_log.append("[i] Re-categorize the KB via CLI:")
        self.activity_log.append("    python scripts/kb_recategorize.py --dry-run")
        self.activity_log.append("    python scripts/kb_recategorize.py --apply")

    def toggle_vision_os_learning(self):
        """Toggle Host OS Screen Vision, crop region indexing, and Gemini auto-labeling."""
        import threading
        cfg = self.settings.get("vision_os_learning", {}) or {}
        curr = bool(cfg.get("enabled", False))
        new_state = not curr
        self.settings_manager.update_setting("vision_os_learning.enabled", new_state)
        self.activity_log.append("=== AI Vision OS Navigation & UI Auto-Labeling ===")
        self.activity_log.append(f"[+] Status: {'ENABLED' if new_state else 'DISABLED'}")
        self.activity_log.append("[i] Screenshot & cropping cache: logs/screen_cache/")
        self.activity_log.append(f"[i] Vision model: {self.settings.get('gemini', {}).get('model', 'gemini-2.5-flash')}")
        self.activity_log.append("[i] Scans host controls across Kali, auto-labels regions & stores in ui_labels_index.json.")

        if new_state:
            from core.utils.ui_navigator import navigator
            self.activity_log.append(
                "[i] Active learning started: Navigating host OS & auto-labeling UI controls..."
            )

            def _log_cb(msg: str):
                self.activity_log.append(msg)

            def _run_learning():
                try:
                    navigator.start_learning_session(steps=3, callback=_log_cb)
                except Exception as e:
                    self.activity_log.append(f"[!] Vision learning note: {e}")

            tr = getattr(self, "thread_runner", None)
            if callable(tr):
                tr(_run_learning)
            else:
                t = threading.Thread(target=_run_learning, daemon=True)
                t.start()
        else:
            self.activity_log.append("[i] Vision learning mode disabled.")


    def enrich_kb(self):
        """Fetch real GitHub READMEs + run Ollama extraction on a small batch.

        Long-running; dispatched in a daemon thread so the curses UI stays
        responsive. Set GITHUB_TOKEN in the env to raise the rate limit from
        60/hr to 5000/hr. Runs are resumable (already-enriched repos skip).
        """
        limit_s = self.get_input("How many repos to enrich (e.g. 20)?")
        try:
            limit = int(limit_s.strip() or "20")
        except ValueError:
            limit = 20
        self.activity_log.append(
            f"[*] Enriching {limit} repos (GitHub fetch + Ollama). "
            f"Set GITHUB_TOKEN to raise the rate limit."
        )

        def run():
            try:
                import subprocess, sys as _sys
                self.activity_log.append(
                    f"[i] running: python scripts/enrich_repos.py --limit {limit}"
                )
                p = subprocess.run(
                    [_sys.executable, "scripts/enrich_repos.py",
                     "--limit", str(limit), "--verify"],
                    cwd=os.path.dirname(os.path.dirname(os.path.dirname(
                        os.path.abspath(__file__)))),
                    capture_output=True, text=True,
                )
                for line in (p.stdout or "").splitlines():
                    if line.strip():
                        self.activity_log.append(f"  {line.strip()}")
                if p.returncode != 0 and p.stderr:
                    self.activity_log.append(f"[!] {p.stderr.strip()[:200]}")
            except Exception as e:
                self.activity_log.append(f"[!] enrichment error: {e}")

        self._spawn(run)

    def kb_enrichment_stats(self):
        try:
            from core.exploit_knowledge_base import ExploitKnowledgeBase
            kb = ExploitKnowledgeBase()
            st = kb.enriched_stats()
            self.activity_log.append("=== KB Enrichment Stats ===")
            self.activity_log.append(
                f"[i] enriched {st['enriched']} / {st['total']} repos"
            )
            by_cat = st.get("by_category_ai", {})
            if by_cat:
                self.activity_log.append("[i] by AI category:")
                for cat, n in list(by_cat.items())[:15]:
                    self.activity_log.append(f"    {cat:14s} x{n}")
            else:
                self.activity_log.append(
                    "[i] none yet — run 'Enrich KB' (or scripts/enrich_repos.py)."
                )
        except Exception as e:
            self.activity_log.append(f"[!] stats error: {e}")

    def view_model_status(self):
        """Show current AI Model Backend details"""
        self.settings = self.settings_manager.load_settings()
        models = self.settings.get("ai_models", {})

        self.activity_log.append("=== AI Backend Status ===")
        
        # Check NVIDIA setup
        nvidia_key = os.getenv("NVIDIA_API_KEY") or os.getenv("NGC_API_KEY")
        if nvidia_key:
            self.activity_log.append(f"[+] NVIDIA NIM/API Engine: ACTIVE (Model: {os.getenv('NVIDIA_MODEL', 'z-ai/glm-5.2')}, Endpoint: {os.getenv('NVIDIA_BASE_URL', 'https://integrate.api.nvidia.com/v1')})")
        else:
            self.activity_log.append("[!] NVIDIA NIM/API Engine: INACTIVE (No API key found in env/.env)")

        # Check Groq setup
        groq_key = os.getenv("GROQ_API_KEY")
        if groq_key:
            self.activity_log.append(f"[+] Groq API Engine: ACTIVE (Model: {os.getenv('GROQ_MODEL', 'openai/gpt-oss-120b')})")
        else:
            self.activity_log.append("[!] Groq API Engine: INACTIVE (No API key found in env/.env)")

        # Check Local models
        self.activity_log.append("[i] Local Hugging Face Models Configured:")
        for name, cfg in models.items():
            self.activity_log.append(f"  · {name}: {cfg.get('model_path')} (Max Len: {cfg.get('max_length')})")

    def view_api_keys_status(self):
        """Verify API keys presence in the system env"""
        self.activity_log.append("=== API Keys Presence ===")
        
        keys = {
            "NVIDIA_API_KEY": "NVIDIA NIM/API",
            "DEEPSEEK_API_KEY": "DeepSeek Engine",
            "GEMINI_API_KEY": "Google Gemini (next to DeepSeek)",
            "GROQ_API_KEY": "Groq Engine",
            "SHODAN_API_KEY": "Shodan Scanner",
            "NVD_API_KEY": "NVD CVE Lookup",
            "GOOGLE_PROJECT_ID": "Google Cloud Platform"
        }
        
        for env_var, desc in keys.items():
            val = os.getenv(env_var)
            if env_var == "NVIDIA_API_KEY" and not val:
                val = os.getenv("NGC_API_KEY")
            if val:
                masked = val[:6] + "..." + val[-4:] if len(val) > 10 else "PRESENT"
                self.activity_log.append(f"  [+] {desc} ({env_var}): {masked}")
            else:
                self.activity_log.append(f"  [!] {desc} ({env_var}): MISSING")

    def adjust_timeouts(self):
        """Prompt to change timeouts"""
        wifi_t = self.get_input("Enter new WiFi scan timeout (seconds)")
        ble_t = self.get_input("Enter new BLE scan timeout (seconds)")
        
        try:
            if wifi_t:
                self.settings_manager.update_setting("scanning.wifi_timeout", int(wifi_t))
                self.activity_log.append(f"[+] WiFi timeout set to {wifi_t}s")
            if ble_t:
                self.settings_manager.update_setting("scanning.ble_timeout", int(ble_t))
                self.activity_log.append(f"[+] BLE timeout set to {ble_t}s")
        except ValueError:
            self.activity_log.append("[!] Invalid timeout value. Please enter numbers.")

    def configure_external_terminal(self):
        """Show available external terminals and let the operator pick one."""
        try:
            from core.utils.external_terminal import (
                list_available, detect, SETTINGS_KEY, NO_TERMINAL,
            )
        except Exception as e:
            self.activity_log.append(f"[!] external terminal helpers: {e}")
            return
        current = detect(self.settings_manager)
        avail = list_available()
        self.activity_log.append("=== External Terminal ===")
        self.activity_log.append(f"[i] Current: {current}")
        self.activity_log.append(
            f"[i] Available: {', '.join(avail) if avail else '(none — tail fallback)'}"
        )
        self.activity_log.append(
            f"[i] '{NO_TERMINAL}' = no GUI window (tail log only)"
        )
        choice = self.get_input(
            f"Terminal name [{current}] (blank=keep, auto=re-probe)"
        ).strip()
        if not choice:
            self.activity_log.append("[i] Terminal unchanged.")
            return
        if choice.lower() == "auto":
            # Clear saved choice so detect re-probes PATH.
            try:
                self.settings_manager.update_setting(SETTINGS_KEY, "")
            except Exception:
                pass
            winner = detect(self.settings_manager)
            self.activity_log.append(f"[+] Auto-detected terminal: {winner}")
            return
        # Accept any name in the chain or currently on PATH.
        import shutil
        known = set(avail) | {NO_TERMINAL, "tail"}
        if choice not in known and not shutil.which(choice):
            self.activity_log.append(
                f"[!] '{choice}' not on PATH and not in known list. "
                f"Try: {', '.join(avail) or NO_TERMINAL}"
            )
            return
        self.settings_manager.update_setting(SETTINGS_KEY, choice)
        # Re-validate via detect so invalid binary falls through cleanly.
        winner = detect(self.settings_manager)
        self.activity_log.append(f"[+] External terminal set to: {winner}")

    def configure_scan_font_scale(self):
        """Set font multiplier for triple/single external scan windows."""
        try:
            from core.utils.external_terminal import (
                get_scan_font_scale, set_scan_font_scale,
            )
        except Exception as e:
            self.activity_log.append(f"[!] font scale helpers: {e}")
            return
        current = get_scan_font_scale(self.settings_manager)
        self.activity_log.append("=== Scan Window Font Scale ===")
        self.activity_log.append(
            f"[i] Current: {current}×  "
            "(1.0 = same density as main TUI; 2.0 = larger)"
        )
        self.activity_log.append(
            "[i] Geometry shrinks with scale so windows stay in their "
            "screen slots. Env KFIOSA_SCAN_FONT_SCALE overrides settings."
        )
        raw = self.get_input(
            f"Font scale [{current}] (e.g. 1.0, 1.5, 2.0; blank=keep)"
        ).strip()
        if not raw:
            self.activity_log.append("[i] Font scale unchanged.")
            return
        try:
            val = float(raw)
        except ValueError:
            self.activity_log.append("[!] Enter a number, e.g. 1.0 or 2.0.")
            return
        if val <= 0:
            self.activity_log.append("[!] Scale must be positive.")
            return
        applied = set_scan_font_scale(val, self.settings_manager)
        self.activity_log.append(
            f"[+] Scan window font scale set to {applied}× "
            "(applies to next WiFi/BLE scan launch)"
        )

    def print_settings(self):
        """Print full JSON configuration to log window"""
        self.settings = self.settings_manager.load_settings()
        self.activity_log.append("=== Current Configuration Profile ===")
        
        # Display settings cleanly
        import json
        dump = json.dumps(self.settings, indent=2)
        for line in dump.split("\n"):
            self.activity_log.append(line)

    def reset_settings(self):
        """Reset dashboard_settings.json to default values"""
        confirm = self.get_input("Type RESET to confirm config factory reset")
        if confirm == "RESET":
            self.settings_manager.reset_to_defaults()
            self.settings = self.settings_manager.load_settings()
            self.activity_log.append("[+] Configuration reset to default system values.")
        else:
            self.activity_log.append("[i] Reset canceled.")
