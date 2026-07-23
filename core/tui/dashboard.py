#!/usr/bin/env python3
"""
Main Dashboard Screen
State manager that handles switching between WiFi, OSINT, BLE, and Settings screens.
"""

import atexit
import curses
import logging
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import List, Dict, Any, Optional

from core.tui.base_screen import BaseScreen
from core.tui.wifi_screen import WiFiScreen
from core.tui.osint_screen import OSINTScreen
from core.tui.osint_people_screen import OSINTPeopleScreen
from core.tui.osint_web_screen import OSINTWebScreen
from core.tui.post_exploit_screen import PostExploitScreen
from core.tui.ble_screen import BLEScreen
from core.tui.settings_screen import SettingsScreen
from core.ai_backend.zero_day_exploit import (
    ZeroDayExploitStore,
    ZeroDayExploitBuilder,
    ZeroDayExploitRunner,
    ZeroDayClassifier,
)
from core.ai_backend.zero_day_dataset import ZeroDayDataset

logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent

class KfiosaDashboard:
    def __init__(self, stdscr):
        self.stdscr = stdscr
        self.running = True
        self.state = "main_menu"
        self.activity_log = ["[+] KFIOSA Pentesting TUI Dashboard Initialized"]

        # Menu index for main menu
        self.menu_index = 0
        # Simplified main menu (few operator-facing options).
        # Post-exploit is NOT a main-menu mode: it is attached automatically
        # to WiFi/BLE engagement chains (attach_post_exploit=True) and run
        # via gain-access hooks. See orchestrator + chain planner.
        self.menu_items = [
            ("WiFi", "wifi"),
            ("BLE", "ble"),
            ("OSINT People", "osint_people"),
            ("OSINT Web", "osint_web"),
            ("OPEN DASHBOARD", "open_dashboard"),
            ("Settings", "settings"),
            ("Quit", "quit"),
        ]
        # Shared activity log panel state (PgUp/PgDn scroll; 0 = live tail)
        self.log_scroll: int = 0
        self._log_follow: bool = True
        self._log_len_seen: int = 1

        # Post-access TUI status: filled in by the orchestrator when a
        # chain step achieves access. The dashboard pill reads this so
        # the operator can see the session id + transport at a glance.
        # Read-only: the orchestrator owns the canonical access report.
        self.post_access_status: Dict[str, Any] = {}

        # CVE lookup + exploit-generation status: filled in by the
        # orchestrator when those MCP tools fire. Read-only here.
        self.cve_lookup_status: Dict[str, Any] = {}
        self.exploit_gen_status: Dict[str, Any] = {}

        # Lazy screen instances
        self.screens = {}

        # Shared resources — created once, reused by every screen so the
        # Ollama HTTP session and the SQLite KB connection pool are not
        # re-opened per navigation.
        self.settings_manager = None
        self.ai_backend = None
        self.kb = None
        self.post_runner = None
        self.osint_runner = None
        self.orchestrator = None
        self.tui_confirm = None
        self.exploit_gen_manager = None  # uncensored model puller
        # Adaptive WiFi pentest: catalog-driven recon (ungated) and
        # external-terminal launcher (xterm/gnome-terminal/tmux/tail)
        # for long-running steps. Both are shared across screens.
        self.external_terminal = None
        self.catalog_recon_factory = None  # callable: target -> CatalogRecon
        self.wifi_pentest_runner = None    # placeholder for future per-screen orchestrator
        # MCP background service handle (loopback TCP). Started once the
        # shared resources are up so AI clients can connect to the tool
        # registry while the dashboard runs. See _start_mcp / _stop_mcp.
        self._mcp_proc = None
        self._mcp_port: Optional[int] = None
        self._mcp_log_fh = None
        # Shared adapter tracker — set by WiFiScreen.pick_interface when
        # airmon-ng creates a monitor vif (e.g. wlan0mon). The quit path
        # (run() + atexit) tears the vif down via _stop_monitor_iface so
        # the operator never leaks a monitor interface on exit.
        self.monitor_iface: Optional[str] = None
        self.original_iface: Optional[str] = None
        self._init_shared()

        # Initialize color system if terminal supports it
        self._init_colors()

        # Setup curses options
        try:
            curses.curs_set(0)
        except Exception:
            pass
        self.stdscr.nodelay(True)
        self.stdscr.timeout(100)
        self.stdscr.keypad(True)

        # Catalog SQL bg counts / incremental ingest (optional NPU accel)
        try:
            if os.getenv("KFIOSA_CATALOG_BG", "0").strip().lower() in (
                "1", "true", "yes", "on",
            ):
                from core.catalog.bg_stats import start_background
                bg = start_background(interval_s=180.0)
                self.activity_log.append(
                    f"[i] Catalog SQL bg stats "
                    f"accel={bg.get('accel')} interval=180s"
                )
        except Exception as e:
            logger.debug("catalog bg start: %s", e)

        # Auto-start the MCP server in the background (unless disabled).
        # Done last so a failure here never blocks the TUI from coming up.
        self._start_mcp()
        atexit.register(self._stop_mcp)
        atexit.register(self._stop_monitor_iface)

    def _init_shared(self):
        """Build the shared AI backend + knowledge base + settings."""
        try:
            from core.settings import settings_manager
            settings_manager.load_settings()
            self.settings_manager = settings_manager
        except Exception as e:
            logger.warning(f"settings manager unavailable: {e}")
        # The ACCEPT/CANCEL gate is created FIRST so every offensive runner
        # (post-exploit, OSINT, orchestrator) shares the same TUI-backed
        # confirm_fn. Without this, the runners fall back to _default_deny
        # and the operator's ACCEPT can never reach real execution.
        try:
            from core.orchestrator.autonomous_orchestrator import TuiConfirmFn
            self.tui_confirm = TuiConfirmFn()
        except Exception as e:
            logger.error(f"TuiConfirmFn init failed: {e}")
            self.tui_confirm = None
        confirm_fn = self.tui_confirm.confirm if self.tui_confirm else None
        try:
            from core.ai_backend import AIBackend
            self.ai_backend = AIBackend(settings=self.settings_manager)
            self.activity_log.append(
                f"[i] AI backend: {self.ai_backend.status()['active']}"
            )
        except Exception as e:
            logger.error(f"AI backend init failed: {e}")
            self.activity_log.append(f"[!] AI backend init failed: {e}")
        try:
            from core.exploit_knowledge_base import ExploitKnowledgeBase
            self.kb = ExploitKnowledgeBase()
            self.activity_log.append(f"[+] KB loaded: {self.kb.count()} repos")
        except Exception as e:
            logger.error(f"KB init failed: {e}")
            self.activity_log.append(f"[!] KB init failed: {e}")
        try:
            from core.post_exploit.runner import PostExploitRunner
            self.post_runner = PostExploitRunner(
                ai_backend=self.ai_backend, kb=self.kb, confirm_fn=confirm_fn
            )
            self.activity_log.append("[+] Post-exploit runner ready (gated)")
        except Exception as e:
            logger.error(f"post-exploit runner init failed: {e}")
            self.post_runner = None
        # Exploit-generation model manager — used by the AIChainPlanner
        # when the primary per-domain model refuses offensive targets.
        # Best-effort; missing ollama or HF registry is non-fatal.
        try:
            from core.ai_backend.exploit_generator import ExploitGenModelManager
            self.exploit_gen_manager = ExploitGenModelManager(
                on_event=lambda m: self.activity_log.append(m),
            )
            self.activity_log.append(
                "[+] Exploit-gen model manager ready "
                "(uncensored HF pull on demand)"
            )
        except Exception as e:
            logger.debug("ExploitGenModelManager init failed: %s", e)
            self.exploit_gen_manager = None
        try:
            from core.osint.runner import OSINTRunner
            from core.osint_catalog import OSINTCatalog
            self.osint_runner = OSINTRunner(
                catalog=OSINTCatalog(), confirm_fn=confirm_fn
            )
            self.activity_log.append("[+] OSINT runner ready (gated)")
        except Exception as e:
            logger.error(f"osint runner init failed: {e}")
            self.osint_runner = None
        # External-terminal launcher MUST be built before the orchestrator
        # so the chain can spawn airodump/hashcat/airgeddon-style windows.
        try:
            from core.utils.external_terminal import ExternalTerminalBackend
            self.external_terminal = ExternalTerminalBackend(
                settings=self.settings_manager
            )
            self.activity_log.append(
                f"[+] External terminal: {self.external_terminal.term}"
            )
        except Exception as e:
            logger.warning(f"external terminal init failed: {e}")
            try:
                from core.utils.external_terminal import ExternalTerminalBackend
                self.external_terminal = ExternalTerminalBackend.always_tail()
            except Exception:
                self.external_terminal = None

        # Ensure Ollama is serving and preferred models are available
        # BEFORE the AI chain / orchestrator bind (so model picker works).
        try:
            from core.bootstrap import ensure_ollama_ready
            orep = ensure_ollama_ready(
                settings=self.settings_manager,
                on_event=lambda m: self.activity_log.append(m),
            )
            if orep.get("reachable"):
                self.activity_log.append(
                    f"[+] Ollama ready ({len(orep.get('models') or [])} models)"
                )
                # Apply best available domain→model map so the orchestrator
                # and AIBackend pick models that actually exist locally.
                dmap = orep.get("domain_model_map") or {}
                if dmap and self.settings_manager is not None:
                    for dom, tag in dmap.items():
                        try:
                            self.settings_manager.update_setting(
                                f"ollama.domain_models.{dom}", tag
                            )
                        except Exception:
                            pass
                    if self.ai_backend is not None and hasattr(
                        self.ai_backend, "domain_models"
                    ):
                        try:
                            self.ai_backend.domain_models.update(dmap)
                        except Exception:
                            pass
                    wifi_m = dmap.get("wifi") or dmap.get("primary")
                    if wifi_m:
                        self.activity_log.append(
                            f"[+] Domain model map: wifi→{wifi_m}"
                        )
            else:
                self.activity_log.append(
                    f"[!] Ollama not ready: {orep.get('error') or 'unreachable'}"
                )
        except Exception as e:
            logger.warning(f"ensure_ollama_ready failed: {e}")
            self.activity_log.append(f"[!] Ollama bootstrap: {e}")

        try:
            from core.orchestrator.autonomous_orchestrator import (
                AutonomousOrchestrator,
            )
            # Build the AI-chain DI pieces (all best-effort; missing
            # pieces just disable the new path and the orchestrator
            # silently falls back to the legacy hardcoded ladder).
            # BUGFIX: use self.exploit_gen_manager (was bare NameError →
            # orchestrator always None → "Orchestrator unavailable").
            _egm = self.exploit_gen_manager
            chain_planner = None
            try:
                from core.ai_backend.chain import AIChainPlanner
                chain_planner = AIChainPlanner(
                    ai_backend=self.ai_backend,
                    exploit_gen_manager=_egm,
                    mcp_client=None,  # wired below if available
                    on_event=lambda m: self.activity_log.append(m),
                )
            except Exception as e:
                logger.debug("AIChainPlanner init failed: %s", e)
            mcp_client = None
            try:
                # The MCP "client" is a thin wrapper around the
                # in-process tool dispatcher (no real network call).
                # Prefer core.mcp.tools (source of truth); fall back to
                # the package re-export for older import styles.
                try:
                    from core.mcp.tools import call_mcp_tool as _call_mcp_tool
                except Exception:
                    from core.mcp import call_mcp_tool as _call_mcp_tool
                class _InProcessMCPClient:
                    def call(self, tool, args):
                        return _call_mcp_tool(tool, args or {})
                mcp_client = _InProcessMCPClient()
                self.activity_log.append(
                    "[+] In-process MCP client wired (call_mcp_tool)"
                )
            except Exception as e:
                logger.debug("in-process MCP client init failed: %s", e)
                self.activity_log.append(
                    f"[!] In-process MCP client unavailable: {e}"
                )
            zero_day_proposer = None
            try:
                from core.ai_backend.zero_day import (
                    ZeroDayProposer, ZeroDayDraftStore,
                )
                zero_day_proposer = ZeroDayProposer(
                    ai_backend=self.ai_backend,
                    store=ZeroDayDraftStore(),
                    on_event=lambda m: self.activity_log.append(m),
                )
            except Exception as e:
                logger.debug("ZeroDayProposer init failed: %s", e)
            # 0-day exploit builder + runner + classifier (Stage 3).
            # The builder and runner share ONE ZeroDayExploitStore so an
            # exploit built in one step is retrievable in the next. The
            # classifier is best-effort — a missing ``transformers``
            # must not break dashboard boot, so its construction is
            # guarded separately.
            zero_day_exploit_builder = None
            zero_day_exploit_runner = None
            zero_day_classifier = None
            try:
                zero_day_exploit_store = ZeroDayExploitStore()
                zero_day_exploit_builder = ZeroDayExploitBuilder(
                    ai_backend=self.ai_backend,
                    store=zero_day_exploit_store,
                    on_event=lambda m: self.activity_log.append(m),
                    # Dedicated uncensored coding model for 0-day PoC
                    # generation + Zero_Day dataset grounding.
                    exploit_gen_manager=_egm,
                    zero_day_dataset=ZeroDayDataset(
                        on_event=lambda m: self.activity_log.append(m)),
                )
                zero_day_exploit_runner = ZeroDayExploitRunner(
                    store=zero_day_exploit_store,
                    on_event=lambda m: self.activity_log.append(m),
                )
                self.activity_log.append(
                    "[+] 0-day exploit builder + runner ready (gated)"
                )
            except Exception as e:
                logger.debug("ZeroDayExploit builder/runner init failed: %s", e)
            try:
                zero_day_classifier = ZeroDayClassifier(
                    on_event=lambda m: self.activity_log.append(m),
                )
            except Exception as e:
                logger.debug("ZeroDayClassifier init failed: %s", e)
                zero_day_classifier = None
            self.orchestrator = AutonomousOrchestrator(
                ai_backend=self.ai_backend, kb=self.kb,
                msf_runner=self.post_runner, osint_runner=self.osint_runner,
                on_event=lambda m: self.activity_log.append(m),
                confirm_fn=confirm_fn,
                settings=self.settings_manager,
                external_terminal=self.external_terminal,
                # New AI chain DI
                chain_planner=chain_planner,
                mcp_client=mcp_client,
                exploit_gen_manager=_egm,
                zero_day_proposer=zero_day_proposer,
                zero_day_exploit_builder=zero_day_exploit_builder,
                zero_day_exploit_runner=zero_day_exploit_runner,
                zero_day_classifier=zero_day_classifier,
                # Wire the post-exploit runner explicitly so gain-access
                # end-of-chain hooks (auto post-exploit) use the shared
                # runner instead of lazily building one (Part C).
                post_exploit_runner=self.post_runner,
            )
            self.activity_log.append("[+] Autonomous orchestrator ready (gated)")
            if chain_planner is not None:
                self.activity_log.append(
                    "[+] AIChainPlanner wired — use_ai_chain=True will route through it"
                )
        except Exception as e:
            logger.error(f"orchestrator init failed: {e}")
            self.activity_log.append(f"[!] Orchestrator init failed: {e}")
            self.orchestrator = None

        # Catalog-recon factory: a callable that takes a target dict and
        # returns a fully-wired CatalogRecon. Sub-screens (WiFiScreen)
        # call this in their recon pass. We don't construct the recon
        # here because it needs the live target dict from the picker.
        try:
            from core.modules.catalog_recon import CatalogRecon
            from core.utils.catalog_loader import get_catalog

            def _factory(target):
                return CatalogRecon(
                    target=target,
                    catalog_index={e.id: e for e in get_catalog().wifi_entries(limit=50)},
                    nvd_cfg=(
                        self.settings_manager.get_setting("nvd")
                        if self.settings_manager else {}
                    ),
                    weakpass_outdir=PROJECT_ROOT / "logs" / "recon",
                    kb=self.kb,
                    settings=self.settings_manager,
                )
            self.catalog_recon_factory = _factory
            self.activity_log.append("[+] Catalog recon factory ready (ungated)")
        except Exception as e:
            logger.warning(f"catalog recon factory init failed: {e}")
            self.catalog_recon_factory = None

        # Holo OS-agent readiness (honest probe; never blocks boot)
        try:
            from core.desktop.holo_agent import holo_status, TASK_PRESETS
            st = holo_status()
            self.holo_status = st
            if st.get("ok"):
                self.activity_log.append(
                    f"[holo] ready bin={st.get('holo_bin')} "
                    f"presets={len(TASK_PRESETS)} "
                    f"(chain action: holo_desktop)"
                )
            else:
                self.activity_log.append(
                    "[holo] binary missing — CLI path only; "
                    "install holo-desktop-cli or Settings → OS Agentic CLI"
                )
        except Exception as e:
            self.holo_status = {"ok": False, "error": str(e)}
            logger.debug("holo status at boot: %s", e)

    def _init_colors(self):
        try:
            from core.tui.ui_theme import apply_theme, load_theme_from_env
            initial_theme = load_theme_from_env()
            apply_theme(self.stdscr, theme=initial_theme)
        except Exception as e:
            logger.warning(f"Failed to initialize curses colors via ui_theme: {e}")
            # Fallback: hardcoded legacy pairs so the TUI is never completely blank.
            try:
                if curses.has_colors():
                    curses.start_color()
                    curses.use_default_colors()
                    curses.init_pair(1, curses.COLOR_GREEN, -1)
                    curses.init_pair(2, curses.COLOR_RED, -1)
                    curses.init_pair(3, curses.COLOR_YELLOW, -1)
                    curses.init_pair(4, curses.COLOR_CYAN, -1)
                    curses.init_pair(5, curses.COLOR_MAGENTA, -1)
                    curses.init_pair(6, curses.COLOR_WHITE, -1)
            except Exception as e2:
                logger.warning(f"Fallback color init also failed: {e2}")

    # ------------------------------------------------------------------
    # MCP background service (loopback TCP)
    # ------------------------------------------------------------------
    def _start_mcp(self):
        """Launch the KFIOSA MCP server as a background TCP service.

        The stdio MCP transport is point-to-point (the client spawns the
        server and connects to its stdin/stdout), so a dashboard-hosted
        long-lived service uses loopback TCP instead — multiple AI clients
        can connect to the tool registry while the tool runs.

        Env overrides:
            KFIOSA_MCP_AUTOSTART=0  — do not auto-start
            KFIOSA_MCP_PORT=<n>     — bind port (default 12700)
            KFIOSA_MCP_HOST=<addr>  — bind host (default 127.0.0.1)

        Failures are logged but never fatal — the TUI stays usable.
        """
        if os.getenv("KFIOSA_MCP_AUTOSTART", "1") != "1":
            self.activity_log.append("[i] MCP autostart disabled (KFIOSA_MCP_AUTOSTART=0)")
            return
        try:
            port = int(os.getenv("KFIOSA_MCP_PORT", "12700"))
            host = os.getenv("KFIOSA_MCP_HOST", "127.0.0.1")
        except ValueError:
            port, host = 12700, "127.0.0.1"

        log_dir = PROJECT_ROOT / "output"
        try:
            log_dir.mkdir(parents=True, exist_ok=True)
        except Exception:
            log_dir = None
        log_path = str(log_dir / "mcp_server.log") if log_dir else os.devnull

        try:
            # Keep the stderr file handle on self so we can close it in
            # _stop_mcp — otherwise Popen's stderr=open(...) leaks an fd in
            # the parent for the lifetime of the process.
            self._mcp_log_fh = open(log_path, "a")
            # Detach the child so it survives the dashboard's stdin/stdout.
            self._mcp_proc = subprocess.Popen(
                [sys.executable, "-m", "core.mcp_server",
                 "--host", host, "--port", str(port)],
                cwd=str(PROJECT_ROOT),
                stdout=subprocess.DEVNULL,
                stderr=self._mcp_log_fh,
                stdin=subprocess.DEVNULL,
                # New process group so we can clean it up cleanly on exit.
                start_new_session=True,
            )
            self._mcp_port = port
            self.activity_log.append(
                f"[+] MCP server running in background at {host}:{port}"
            )
            self.activity_log.append(
                f"[i] MCP log: {log_path}  (stop with KFIOSA_MCP_AUTOSTART=0)"
            )
        except Exception as e:
            logger.warning(f"MCP autostart failed: {e}")
            self.activity_log.append(f"[!] MCP autostart failed: {e}")
            self._mcp_proc = None
            try:
                if self._mcp_log_fh is not None:
                    self._mcp_log_fh.close()
                    self._mcp_log_fh = None
            except Exception:
                pass

    def _stop_mcp(self):
        """Terminate the background MCP service (called on exit + atexit)."""
        proc = self._mcp_proc
        self._mcp_proc = None
        if proc is not None and proc.poll() is None:
            try:
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
            except Exception as e:
                logger.debug(f"MCP stop error: {e}")
        # Close the leaked stderr handle now that the child is gone.
        try:
            if self._mcp_log_fh is not None:
                self._mcp_log_fh.close()
                self._mcp_log_fh = None
        except Exception:
            pass

    def _stop_monitor_iface(self):
        """Tear down the airmon-ng monitor vif (called on quit + atexit).

        Idempotent: a no-op when no monitor interface is tracked. Mirrors
        ``_stop_mcp``'s logging style — never raises, logs the outcome
        through the dashboard activity log so the operator sees the vif
        come down even on Ctrl-C.
        """
        monitor_iface = self.monitor_iface
        self.monitor_iface = None
        if not monitor_iface:
            return
        try:
            from core.utils.airmon import airmon_stop
            res = airmon_stop(monitor_iface)
        except Exception as e:  # noqa: BLE001 — teardown must never raise
            logger.debug(f"monitor iface stop error: {e}")
            self.activity_log.append(
                f"[!] airmon-ng stop {monitor_iface} failed: {e}"
            )
            return
        if res.get("ok"):
            self.activity_log.append(
                f"[+] airmon-ng stop {monitor_iface}: vif removed"
            )
        else:
            err = res.get("error") or "unknown error"
            logger.debug(f"monitor iface stop error: {err}")
            self.activity_log.append(
                f"[!] airmon-ng stop {monitor_iface} failed: {err}"
            )

    def _maybe_dump_screen(self) -> None:
        """Plain-text screen dump for the agentic TUI debugger.

        When ``$KFIOSA_TUI_SCREEN_DUMP`` is set to a filesystem path, write
        the current curses window contents (via ``instr``) plus a short
        state header. The agentic debugger (``scripts/agentic_tui_debug.py``)
        reads this file because raw pexpect bytes cannot reconstruct a
        curses alternate-screen UI. Best-effort; never raises into the
        main loop.
        """
        path = os.environ.get("KFIOSA_TUI_SCREEN_DUMP", "").strip()
        if not path:
            return
        try:
            h, w = self.stdscr.getmaxyx()
            lines: List[str] = [
                f"## state={self.state} menu_index={self.menu_index} "
                f"monitor_iface={self.monitor_iface} "
                f"original_iface={self.original_iface}",
            ]
            # Sub-screen extras when present.
            try:
                sub = self.screens.get(self.state)
                if sub is not None:
                    lines.append(
                        f"## sub_iface={getattr(sub, 'interface', None)} "
                        f"sub_mode={getattr(sub, 'interface_mode', None)} "
                        f"flow={getattr(sub, 'flow_state', None)} "
                        f"sub_menu_index={getattr(sub, 'menu_index', None)}"
                    )
            except Exception:
                pass
            for y in range(max(0, h)):
                try:
                    raw = self.stdscr.instr(y, 0, max(0, w - 1))
                    if isinstance(raw, bytes):
                        raw = raw.decode("utf-8", errors="replace")
                    lines.append((raw or "").rstrip())
                except Exception:
                    lines.append("")
            # Activity log tail (source of truth for monitor/managed messages).
            lines.append("## activity_log_tail")
            for entry in (self.activity_log or [])[-20:]:
                lines.append(str(entry)[:240])
            tmp = path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                fh.write("\n".join(lines) + "\n")
            os.replace(tmp, path)
        except Exception as e:  # noqa: BLE001 — never break TUI for dump
            logger.debug("screen dump failed: %s", e)

    def run(self):
        """Main event loop"""
        while self.running:
            try:
                self.stdscr.erase()
                height, width = self.stdscr.getmaxyx()

                if height < 20 or width < 70:
                    self.stdscr.addstr(0, 0, "Terminal window too small. Expand it.")
                    self.stdscr.refresh()
                    self._maybe_dump_screen()
                    time.sleep(0.5)
                    continue

                # ACCEPT/CANCEL confirm dialog takes priority when an
                # orchestrator worker is waiting on the operator. ``poll()``
                # promotes a queued prompt into ``_current`` so the dialog
                # shows the real step text and ``respond()`` can deliver the
                # operator's answer — without it the worker deadlocks.
                if self.tui_confirm is not None and self.tui_confirm.has_pending():
                    self.tui_confirm.poll(self.stdscr, self.activity_log)
                    self.render_confirm_dialog()
                    self.handle_confirm_input()
                    self.stdscr.refresh()
                    self._maybe_dump_screen()
                    time.sleep(0.02)
                    continue

                if self.state == "main_menu":
                    self.render_main_menu()
                    self.handle_main_menu_input()
                else:
                    self.render_sub_screen()

                self.stdscr.refresh()
                self._maybe_dump_screen()
                time.sleep(0.02)
            except KeyboardInterrupt:
                self.running = False
            except Exception as e:
                logger.error(f"Error in TUI main loop: {e}")
                self.running = False

        # Loop exited — tear down the monitor vif first (so the adapter
        # is restored even on normal quit), then the background MCP
        # service. atexit is the backstop for Ctrl-C / unexpected exit.
        self._stop_monitor_iface()
        self._stop_mcp()

    def render_confirm_dialog(self):
        """Render the ACCEPT / CANCEL / AUTO→access prompt from a waiting worker."""
        prompt = self.tui_confirm.current_prompt or ""
        height, width = self.stdscr.getmaxyx()
        try:
            # box
            top = max(2, height // 2 - 4)
            self.stdscr.attron(curses.color_pair(3) | curses.A_BOLD)
            self.stdscr.addstr(top, max(0, (width - 60) // 2),
                               " ACCEPT / CANCEL / AUTO ".center(60, "-")[:width-1])
            self.stdscr.attroff(curses.color_pair(3) | curses.A_BOLD)
            # wrap prompt
            words = prompt.split()
            line, y = "", top + 1
            for w in words:
                if len(line) + len(w) + 1 > width - 4:
                    self.stdscr.addstr(y, 2, line[:width-4]); y += 1; line = w
                else:
                    line = (line + " " + w).strip()
            if line:
                self.stdscr.addstr(y, 2, line[:width-4]); y += 1
            self.stdscr.attron(curses.color_pair(1) | curses.A_BOLD)
            self.stdscr.addstr(y + 1, 2, "[y/ENTER] ACCEPT")
            self.stdscr.attroff(curses.color_pair(1) | curses.A_BOLD)
            self.stdscr.attron(curses.color_pair(2) | curses.A_BOLD)
            self.stdscr.addstr(y + 1, 22, "[n/ESC] CANCEL")
            self.stdscr.attroff(curses.color_pair(2) | curses.A_BOLD)
            # Third option: one keystroke auto-runs until access is gained.
            try:
                self.stdscr.attron(curses.color_pair(3) | curses.A_BOLD)
                self.stdscr.addstr(
                    y + 1, 42,
                    "[a] AUTO→access"[: max(0, width - 44)],
                )
                self.stdscr.attroff(curses.color_pair(3) | curses.A_BOLD)
            except Exception:
                # Narrow terminals: fall back to a second line.
                self.stdscr.addstr(
                    y + 2, 2,
                    "[a] AUTO until access (no more prompts)"[: width - 4],
                )
            auto_on = bool(getattr(self.tui_confirm, "auto_until_access", False))
            if auto_on:
                self.stdscr.addstr(
                    y + 3, 2,
                    "AUTO→access is ON (this should not still be prompting)"[: width - 4],
                )
        except Exception as e:
            logger.debug(f"confirm render: {e}")

    def handle_confirm_input(self):
        try:
            from core.tui.base_screen import read_curses_key
            key = read_curses_key(self.stdscr)
        except Exception:
            key = self.stdscr.getch()
        if key == -1:
            return
        if key in (ord('y'), ord('Y'), curses.KEY_ENTER, 10, 13):
            self.tui_confirm.respond(True)
        elif key in (ord('a'), ord('A')):
            # One-shot autonomous path: accept this step + auto-ACCEPT
            # remaining confirms until access (creds/session) is achieved.
            if hasattr(self.tui_confirm, "respond_auto"):
                self.tui_confirm.respond_auto()
            else:
                self.tui_confirm.respond(True)
            try:
                self.activity_log.append(
                    "[i] AUTO→access: remaining steps will auto-ACCEPT "
                    "until access is achieved"
                )
            except Exception:
                pass
        elif key in (ord('n'), ord('N'), 27, ord('q'), ord('Q'),
                     curses.KEY_BACKSPACE, 127, 8):
            self.tui_confirm.respond(False)

    def render_main_menu(self):
        """Draw main menu layout using the centralised ui_theme palette."""
        height, width = self.stdscr.getmaxyx()

        try:
            from core.tui.ui_theme import (
                ThemePair, attr_for, safe_addstr, draw_focus_badge, is_focus_mode
            )
            _theme_ok = True
        except Exception:
            _theme_ok = False

        # ── Header / ASCII banner ─────────────────────────────────────────
        try:
            in_focus = _theme_ok and is_focus_mode()

            if not in_focus:
                # Full banner in standard mode
                self.stdscr.attron(curses.color_pair(5) | curses.A_BOLD)
                banner = [
                    " ╔══════════════════════════════════════════════════════════╗",
                    " ║         KFIOSA — AI OFFENSIVE PENTEST TOOLKIT            ║",
                    " ║                  v3.0 · wifite4 style                    ║",
                    " ╚══════════════════════════════════════════════════════════╝"
                ]
                for i, line in enumerate(banner):
                    self.stdscr.addstr(i, max(0, (width - len(line)) // 2), line[:width-1])
                self.stdscr.attroff(curses.color_pair(5) | curses.A_BOLD)
            else:
                # Focus Mode: single compact header row, no decorative borders
                hdr = " KFIOSA  v3.0"
                self.stdscr.attron(curses.color_pair(7) | curses.A_BOLD)
                self.stdscr.addstr(0, 0, " " * (width - 1))
                self.stdscr.addstr(0, 1, hdr[:width - 2])
                self.stdscr.attroff(curses.color_pair(7) | curses.A_BOLD)

            # Focus badge rendered on top of header (noop in standard mode)
            if _theme_ok:
                draw_focus_badge(self.stdscr)

            # Status line
            iface = self._status_iface()
            ai    = self._status_ai()
            pa    = self._status_post_access()
            cve   = self._status_cve_lookup()
            exp   = self._status_exploit_gen()
            status = f" [ Interface: {iface} ] [ AI: {ai} ] [ Status: Ready ]{pa}{cve}{exp} "
            status_row = 1 if in_focus else 4
            self.stdscr.attron(curses.color_pair(4))
            self.stdscr.addstr(status_row,
                               max(0, (width - len(status)) // 2),
                               status[:width - 1])
            self.stdscr.attroff(curses.color_pair(4))

            separator_row = status_row + 1
            self.stdscr.addstr(separator_row, 0, "─" * (width - 1))
        except Exception:
            pass

        # ── Split layout: menu left · live story right ────────────────────
        try:
            from core.tui.layout import layout_panels
            lay = layout_panels(height, width, header_h=5, status_h=1)
        except Exception:
            lay = None

        menu_start = 4 if (_theme_ok and is_focus_mode()) else 6
        left_w = width
        if lay is not None and lay.mode == "split":
            left_w = lay.left.w
            menu_start = max(menu_start, lay.left.y + 1)

        try:
            self.stdscr.attron(curses.color_pair(4) | curses.A_BOLD)
            self.stdscr.addstr(menu_start - 1, 2, "Main Control Menu:"[: max(8, left_w - 4)])
            self.stdscr.attroff(curses.color_pair(4) | curses.A_BOLD)

            for i, (label, _) in enumerate(self.menu_items):
                y = menu_start + i
                if y < height - 2:
                    selected = (i == self.menu_index)
                    marker = "[>]" if selected else "   "
                    if selected:
                        self.stdscr.attron(curses.A_REVERSE | curses.color_pair(1))
                    else:
                        self.stdscr.attron(curses.color_pair(6))
                    line = f"{marker} {label}".ljust(left_w - 3)[: max(8, left_w - 3)]
                    self.stdscr.addstr(y, 2, line)
                    self.stdscr.attroff(
                        curses.A_REVERSE | curses.color_pair(1) | curses.color_pair(6)
                    )
        except Exception:
            pass

        # Activity narrative (right panel when split; else under menu)
        try:
            from core.tui.activity_log_view import draw_activity_log as _draw_log
            n = len(self.activity_log)
            if n > getattr(self, "_log_len_seen", 0) and getattr(self, "_log_follow", True):
                self.log_scroll = 0
            self._log_len_seen = n
            if lay is not None and lay.mode == "split":
                self.log_scroll = _draw_log(
                    self.stdscr,
                    self.activity_log,
                    lay.right.y,
                    lay.right.h,
                    scroll_from_end=int(getattr(self, "log_scroll", 0) or 0),
                    wrap=True,
                    title="Live story",
                    start_x=lay.right.x,
                    panel_width=lay.right.w,
                )
            else:
                log_y = menu_start + len(self.menu_items) + 2
                log_h = height - log_y - 2
                self.log_scroll = _draw_log(
                    self.stdscr,
                    self.activity_log,
                    log_y,
                    log_h,
                    scroll_from_end=int(getattr(self, "log_scroll", 0) or 0),
                    wrap=True,
                    title="Live story",
                )
        except Exception:
            try:
                dummy_screen = BaseScreen(self.stdscr, None, self.activity_log)
                dummy_screen.draw_activity_log(menu_start + len(self.menu_items) + 2, 8)
            except Exception:
                pass

        # Status bar — show [F] Focus Mode + log scroll hints
        try:
            in_focus = _theme_ok and is_focus_mode()
            hint = "[F] Focus OFF" if in_focus else "[F] Focus ON"
            scroll_hint = "PgUp/PgDn Log"
            if getattr(self, "log_scroll", 0):
                scroll_hint = f"PgUp/PgDn Log↑{self.log_scroll} End=live"
            hint_full = (
                f"  ↑↓ Nav  ENTER Select  Q Quit  {scroll_hint}  {hint}"
            )
            self.stdscr.attron(curses.color_pair(6))
            self.stdscr.addstr(height - 1, 0,
                               hint_full.ljust(width - 1)[:width - 1])
            self.stdscr.attroff(curses.color_pair(6))
        except Exception:
            try:
                BaseScreen(self.stdscr, None, self.activity_log).draw_status_bar()
            except Exception:
                pass

    def handle_main_menu_input(self):
        """Handle keyboard input on main menu"""
        try:
            from core.tui.base_screen import read_curses_key
            key = read_curses_key(self.stdscr)
        except Exception:
            key = self.stdscr.getch()
        if key == -1:
            return

        # Activity log scroll
        try:
            from core.tui.activity_log_view import handle_log_scroll_key
            new_scroll = handle_log_scroll_key(
                key, int(getattr(self, "log_scroll", 0) or 0), page=6,
            )
            if new_scroll is not None:
                self.log_scroll = max(0, int(new_scroll))
                self._log_follow = (self.log_scroll == 0)
                return
        except Exception:
            pass

        if key in (curses.KEY_UP, ord("k"), ord("K")):
            self.menu_index = (self.menu_index - 1) % len(self.menu_items)
        elif key in (curses.KEY_DOWN, ord("j"), ord("J")):
            self.menu_index = (self.menu_index + 1) % len(self.menu_items)
        elif key in (curses.KEY_ENTER, 10, 13, ord(" ")):
            # Select state
            _, target_state = self.menu_items[self.menu_index]
            if target_state == "quit":
                self.running = False
            elif target_state == "open_dashboard":
                self.open_universal_dashboard()
            else:
                self.state = target_state
                self.activity_log.append(f"[i] Navigating to {target_state.upper()} Operations")
        elif key in (ord('q'), ord('Q')):
            self.running = False
        elif key in (ord('f'), ord('F')):
            # Toggle ADHD Focus Mode
            try:
                from core.tui.ui_theme import toggle_focus_mode, save_theme_to_env, is_focus_mode
                new_theme = toggle_focus_mode(self.stdscr)
                save_theme_to_env(new_theme)
                label = "ON" if is_focus_mode() else "OFF"
                self.activity_log.append(f"[i] Focus Mode {label} — press F to toggle")
            except Exception as _e:
                logger.debug(f"focus mode toggle error: {_e}")

    def _status_iface(self):
        """Detected default interface for the status line (no hardcoding)."""
        try:
            import core.bootstrap as b
            tools = b.check_tools()
            # Prefer a monitor-capable adapter if iw is present.
            if tools.get("iw"):
                import subprocess
                out = subprocess.run(
                    ["iw", "dev"], capture_output=True, text=True, timeout=3
                ).stdout
                ifaces = [
                    l.split("interface", 1)[1].strip()
                    for l in out.splitlines()
                    if "Interface" in l
                ]
                if ifaces:
                    return ifaces[0]
        except Exception:
            pass
        return "auto-detect"

    def _status_ai(self):
        """Active AI provider label for the status line."""
        try:
            if self.ai_backend:
                return self.ai_backend.status()["active"]
        except Exception:
            pass
        return "off"

    def _status_post_access(self):
        """Post-access TUI status pill for the status line.

        Returns a short string like:
          - "[ POST-ACCESS TUI: open (sid=1, msf) ]" when access has been
            achieved and the post-access TUI is opened
          - "[ POST-ACCESS TUI: ready (sid=1) ]" when access has been
            achieved but the TUI hasn't been spawned yet
          - "" (empty) when access has not been achieved

        Reads :attr:`post_access_status`, populated by the orchestrator
        when a step achieves access. The dashboard pill is read-only —
        the canonical state lives in ``orchestrator.report['access']``.
        """
        try:
            access = self.post_access_status or {}
            if not access.get("achieved"):
                return ""
            sid = access.get("session_id", "")
            transport = access.get("transport", "")
            if access.get("tui_opened"):
                tail = f"sid={sid}" if sid else "no-sid"
                if transport:
                    tail += f", {transport}"
                return f" [ POST-ACCESS TUI: open ({tail}) ]"
            tail = f"sid={sid}" if sid else "no-sid"
            return f" [ POST-ACCESS TUI: ready ({tail}) ]"
        except Exception:
            return ""

    def _status_cve_lookup(self) -> str:
        """CVE lookup status pill for the status line.

        Returns a short string when at least one lookup has happened;
        "" (empty) otherwise. The pill shows the last query and a
        brief outcome (hits / empty / failed).
        """
        try:
            s = self.cve_lookup_status or {}
            if not s:
                return ""
            q = s.get("last_query", "")
            short = q.split(",")[0].strip() if q else ""
            # Cap to 24 chars to keep the pill compact.
            if len(short) > 24:
                short = short[:21] + "..."
            if s.get("ok") is False:
                return f" [ CVE: failed {short} ]"
            count = int(s.get("last_count", 0) or 0)
            if count <= 0:
                return f" [ CVE: empty {short} ]"
            plural = "s" if count != 1 else ""
            return f" [ CVE: {count} hit{plural} {short} ]"
        except Exception:
            return ""

    def _status_exploit_gen(self) -> str:
        """Exploit-generation status pill for the status line.

        Returns a short string when at least one ``cve_to_exploit`` step
        has fired; "" (empty) otherwise. The pill surfaces the model
        tag (truncated) and CVE id so the operator can see at a glance
        which model the AI is using to draft exploits.
        """
        try:
            s = self.exploit_gen_status or {}
            if not s:
                return ""
            cve = s.get("last_cve_id", "")
            model = s.get("last_model", "")
            # Cap each to keep the pill compact.
            if len(model) > 32:
                model = model[:29] + "..."
            if len(cve) > 18:
                cve = cve[:15] + "..."
            if s.get("ok") is False:
                return f" [ EXPLOIT: failed cve={cve} ]"
            return f" [ EXPLOIT: model={model} cve={cve} ]"
        except Exception:
            return ""

    def open_universal_dashboard(self):
        """Open the Flask/WSGI RAT dashboard (wifi/ble/osint kinds + SQL tasks).

        Stays on the main menu. Tasks persist in the SQL store and can run
        until success (access + post-exploit + connection).
        """
        try:
            from core.db import sqlstore
            sqlstore.init()
        except Exception as e:
            self.activity_log.append(f"[i] SQL store: {e}")
        try:
            from core.post_access_tui.rat_ext import (
                spawn_rat_dashboard, set_dashboard_orchestrator,
            )
            if self.orchestrator is not None:
                set_dashboard_orchestrator(self.orchestrator)
            sessions = []
            try:
                from core.db import sqlstore
                for row in sqlstore.list_sessions(limit=100) or []:
                    if not isinstance(row, dict):
                        continue
                    sid = row.get("sid") or row.get("id")
                    if not sid:
                        continue
                    sessions.append({
                        "id": sid,
                        "kind": row.get("kind") or "unknown",
                        "label": row.get("target") or sid,
                        "transport": row.get("kind") or "",
                        "achieved": {"restored"},
                    })
            except Exception:
                pass
            rep = spawn_rat_dashboard(
                sessions=sessions,
                orchestrator=self.orchestrator,
            )
            if isinstance(rep, dict) and rep.get("ok"):
                url = rep.get("url") or (
                    f"http://{rep.get('host', '127.0.0.1')}:{rep.get('port')}/"
                )
                self.activity_log.append(f"[+] OPEN DASHBOARD → {url}")
                self.activity_log.append(
                    "[*] Tabs: WiFi · BLE · OSINT Web · OSINT People — "
                    "tasks run until success (SQL-persisted)."
                )
                # Best-effort open browser for the operator
                try:
                    import webbrowser
                    webbrowser.open(url)
                except Exception:
                    pass
            else:
                err = (rep or {}).get("error") if isinstance(rep, dict) else rep
                self.activity_log.append(f"[!] Dashboard open failed: {err}")
        except Exception as e:
            self.activity_log.append(f"[!] Dashboard open: {e}")

    def _shared_kwargs(self):
        """Shared resources passed into every sub-screen constructor."""
        return {
            "ai_backend": self.ai_backend,
            "kb": self.kb,
            "post_runner": self.post_runner,
            "osint_runner": self.osint_runner,
            "orchestrator": self.orchestrator,
            "tui_confirm": self.tui_confirm,
            "settings_manager": self.settings_manager,
            "dashboard": self,
            # Adaptive WiFi pentest: external terminal launcher + recon
            # factory are passed through so WiFiScreen can wire them.
            "external_terminal": self.external_terminal,
            "catalog_recon_factory": self.catalog_recon_factory,
        }

    def render_sub_screen(self):
        """Delegates rendering to active sub-screen"""
        screen_class_map = {
            "wifi": WiFiScreen,
            "osint": OSINTScreen,  # legacy full OSINT (reachable via Settings if needed)
            "osint_people": OSINTPeopleScreen,
            "osint_web": OSINTWebScreen,
            "post_exploit": PostExploitScreen,
            "ble": BLEScreen,
            "settings": SettingsScreen,
        }

        if self.state not in self.screens:
            # Instantiate screen lazily with shared resources.
            screen_class = screen_class_map.get(self.state)
            if screen_class:
                try:
                    self.screens[self.state] = screen_class(
                        self.stdscr, self.go_back, self.activity_log,
                        **self._shared_kwargs()
                    )
                except TypeError:
                    # Screen still uses the old 3-arg signature.
                    self.screens[self.state] = screen_class(
                        self.stdscr, self.go_back, self.activity_log
                    )

        sub_screen = self.screens.get(self.state)
        if sub_screen:
            # Keep log scroll position in sync (shared activity_log list)
            try:
                sub_screen.log_scroll = int(getattr(self, "log_scroll", 0) or 0)
                sub_screen._log_follow = bool(getattr(self, "_log_follow", True))
            except Exception:
                pass
            sub_screen.render()
            res = sub_screen.handle_input()
            try:
                self.log_scroll = int(getattr(sub_screen, "log_scroll", 0) or 0)
                self._log_follow = bool(getattr(sub_screen, "_log_follow", True))
            except Exception:
                pass
            if res == "back":
                self.go_back()

    def go_back(self):
        """Return to main menu"""
        self.state = "main_menu"
        try:
            from core.tui.activity_log_view import append_log
            append_log(self.activity_log, "[i] Returned to Main Menu")
        except Exception:
            self.activity_log.append("[i] Returned to Main Menu")
