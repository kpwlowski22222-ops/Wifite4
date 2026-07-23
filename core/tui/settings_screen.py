#!/usr/bin/env python3
"""
Settings Screen TUI
Settings & AI configuration sub-menu. View API Key presence, adjust parameters,
or view active configuration profile.
"""

import os
import logging
import threading
from typing import List, Dict, Any

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

        self.menu_items = [
            ("Ollama Backend Status & Model List", self.view_ollama_status),
            ("Set Ollama Endpoint", self.set_ollama_endpoint),
            ("Select Model per Domain", self.select_domain_model),
            ("Pull Models (info)", self.pull_models_info),
            ("Fetch Tool Repos into toolboxes/ (git clone)", self.fetch_toolboxes),
            ("Prepare Toolbox Tools (install deps, chmod)", self.prepare_toolboxes),
            ("Rebuild Tool Registry (toolboxes+Kali+venv)", self.rebuild_registry),
            ("MCP Server info (AI client bridge)", self.mcp_info),
            ("Run KB Re-categorization (info)", self.kb_recategorize_info),
            ("View AI Engine & Model Status", self.view_model_status),
            ("View API Keys Presence Status", self.view_api_keys_status),
            ("AI Vision OS Navigation & UI Auto-Labeling", self.toggle_vision_os_learning),
            ("Adjust Scan Timeouts", self.adjust_timeouts),
            ("Print Current Settings Profile", self.print_settings),
            ("Reset Configuration to Defaults", self.reset_settings),
            ("Back to Main Menu", self.parent_callback)
        ]

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
            from core.ai_backend import AIBackend
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
                    f"[i] by domain: "
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
        self.activity_log.append(f"[i] Screenshot & cropping cache: logs/screen_cache/")
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
