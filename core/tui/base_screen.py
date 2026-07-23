#!/usr/bin/env python3
"""
Base Screen
Implements shared TUI features, curses helper methods, menu navigation,
scrolling, input collection, log display, and the wifite-style flow state
machine (menu → targets → advanced). Also exposes the testability seams
(``input_fn``, ``thread_runner``, ``scanner_cls``) so every screen action is
curses-free callable from pytest.
"""

import curses
import logging
import threading
import time
from typing import List, Dict, Any, Tuple, Optional, Callable

logger = logging.getLogger(__name__)

class BaseScreen:
    def __init__(self, stdscr, parent_callback, activity_log: List[str],
                 ai_backend=None, kb=None, post_runner=None,
                 settings_manager=None, dashboard=None, **kwargs):
        self.stdscr = stdscr
        self.parent_callback = parent_callback
        self.activity_log = activity_log
        self.ai_backend = ai_backend
        self.kb = kb
        self.post_runner = post_runner
        self.settings_manager = settings_manager
        self.dashboard = dashboard
        self.menu_index = 0
        self.menu_items: List[Tuple[str, Any]] = []
        self.title = "Screen"

        # ---- wifite-style flow state ----
        # "menu"      — primary operations (Scan / Run All / Report / Advanced / Back)
        # "targets"   — numbered scan-results list; number keys + ENTER select
        # "advanced"  — less-common actions submenu
        self.flow_state = "menu"
        self.primary_items: List[Tuple[str, Any]] = []
        self.advanced_items: List[Tuple[str, Any]] = []
        self.targets: List[Any] = []
        self.selected_target: Optional[Any] = None
        self._last_report: Optional[Dict[str, Any]] = None

        # ---- testability seams (None in prod → real curses + real threads) ----
        self.input_fn: Optional[Callable[[str], str]] = kwargs.get("input_fn")
        self.thread_runner: Optional[Callable[[Callable], Any]] = kwargs.get("thread_runner")
        self.scanner_cls = kwargs.get("scanner_cls")

    # ------------------------------------------------------------------
    # Testability helpers
    # ------------------------------------------------------------------
    def _spawn(self, fn: Callable) -> None:
        """Run ``fn`` either via the injected ``thread_runner`` (tests: sync)
        or a real daemon thread (prod). Tests pass ``sync_thread_runner`` so
        the action completes before the assertion runs."""
        runner = self.thread_runner
        if runner is not None:
            try:
                runner(fn)
            except Exception as e:
                logger.error(f"injected thread_runner raised: {e}")
            return
        threading.Thread(target=fn, daemon=True).start()

    def get_input(self, prompt: str) -> str:
        """Collect a string from the operator.

        When ``input_fn`` is injected (tests), route through it directly — no
        curses needed. Otherwise use the curses blocking-getstr path below.
        """
        if self.input_fn is not None:
            try:
                val = self.input_fn(prompt)
                return (val or "").strip() if isinstance(val, str) else ""
            except Exception as e:
                logger.error(f"injected input_fn raised: {e}")
                return ""

        try:
            height, width = self.stdscr.getmaxyx()
            input_y = height - 2
            prompt_str = f"{prompt}: "
            field_x = 2 + len(prompt_str)

            # Clear input line and render the prompt.
            self.stdscr.move(input_y, 0)
            self.stdscr.clrtoeol()
            self.stdscr.attron(curses.color_pair(3) | curses.A_BOLD)
            self.stdscr.addstr(input_y, 2, prompt_str[:width - 3])
            self.stdscr.attroff(curses.color_pair(3) | curses.A_BOLD)
            self.stdscr.refresh()

            # Switch to blocking mode so getstr waits for ENTER.
            self.stdscr.nodelay(False)
            self.stdscr.timeout(-1)
            curses.echo()
            curses.curs_set(1)

            try:
                input_str_bytes = self.stdscr.getstr(input_y, field_x,
                                                     width - field_x - 1)
            finally:
                # Always restore non-blocking mode + hide cursor, even on error.
                curses.noecho()
                curses.curs_set(0)
                self.stdscr.nodelay(True)
                self.stdscr.timeout(100)

            input_str = input_str_bytes.decode('utf-8', errors='ignore').strip()

            # Clear input line after reading.
            self.stdscr.move(input_y, 0)
            self.stdscr.clrtoeol()
            self.stdscr.refresh()
            return input_str
        except Exception as e:
            # Defensive: make sure we never leave the window in blocking mode.
            try:
                self.stdscr.nodelay(True)
                self.stdscr.timeout(100)
                curses.noecho()
                curses.curs_set(0)
            except Exception:
                pass
            logger.error(f"Error getting TUI input: {e}")
            return ""

    # ------------------------------------------------------------------
    # Wifite-style flow / target selection (curses-free core)
    # ------------------------------------------------------------------
    def select_target_by_index(self, idx: int) -> bool:
        """Pure, curses-free target selection by 0-based index.

        Reads ``self.targets`` (populated by the screen's scan action).
        Screens override ``_on_target_selected`` to log a human label.
        Returns True when a target was selected.
        """
        if not self.targets:
            self.activity_log.append("[!] Scan for targets first.")
            return False
        if not 0 <= idx < len(self.targets):
            self.activity_log.append(
                f"[!] No target #{idx + 1} (valid 1-{len(self.targets)})."
            )
            return False
        self.selected_target = self.targets[idx]
        self._on_target_selected(idx)
        # Return to the primary menu after a selection.
        self._show_primary()
        return True

    def _on_target_selected(self, idx: int) -> None:
        """Screens override to emit a human-friendly log line. Default no-op."""
        pass

    def _target_label(self, idx: int, target: Any) -> str:
        """Screens override to format a scan result for the numbered list."""
        return f"{idx + 1}. {target}"

    def _enter_targets_view(self) -> None:
        """Build a numbered-target menu from ``self.targets`` and switch the
        flow state so render()/handle_input treat it as the target list."""
        if not self.targets:
            self.activity_log.append("[!] No targets to show — scan first.")
            return
        self.menu_items = [
            (self._target_label(i, t), self._make_select_handler(i))
            for i, t in enumerate(self.targets)
        ]
        self.menu_index = 0
        self.flow_state = "targets"

    def _make_select_handler(self, idx: int) -> Callable:
        return lambda: self.select_target_by_index(idx)

    def _select_target_prompt(self) -> None:
        """Primary-menu entry: show the numbered target list (if any)."""
        if not self.targets:
            self.activity_log.append("[!] Scan first — no targets discovered yet.")
            return
        self._enter_targets_view()

    def _show_primary(self) -> None:
        """Swap back to the primary operations menu."""
        self.menu_items = list(self.primary_items)
        self.menu_index = 0
        self.flow_state = "menu"

    def _show_advanced(self) -> None:
        """Swap to the advanced-operations submenu."""
        if not self.advanced_items:
            self.activity_log.append("[i] No advanced operations for this screen.")
            return
        self.menu_items = list(self.advanced_items)
        self.menu_index = 0
        self.flow_state = "advanced"

    def show_report(self) -> None:
        """Default report: re-emit the last engagement summary. Screens may
        override with a richer domain-specific report."""
        self.activity_log.append("=== Last Engagement Report ===")
        if self.selected_target is not None:
            self.activity_log.append(f"[i] Target: {self.selected_target}")
        else:
            self.activity_log.append("[i] Target: (none selected)")
        self.activity_log.append(
            "[i] Step-by-step output (ACCEPT/CANCEL gated) is in the activity log above."
        )

    def _status_iface(self):
        if self.dashboard is not None:
            try:
                return self.dashboard._status_iface()
            except Exception:
                pass
        return "auto-detect"

    def _status_ai(self):
        if self.ai_backend is not None:
            try:
                return self.ai_backend.status()["active"]
            except Exception:
                pass
        return "off"

    def draw_header(self, title: str):
        """Draw top banner matching the unified wifite style"""
        try:
            height, width = self.stdscr.getmaxyx()
            self.stdscr.attron(curses.color_pair(5) | curses.A_BOLD)
            banner = f" ╔══════════════════════════════════════════════════════════╗"
            banner2 = f" ║          KFIOSA — {title.upper().center(30)}          ║"
            banner3 = f" ╚══════════════════════════════════════════════════════════╝"

            self.stdscr.addstr(0, max(0, (width - len(banner)) // 2), banner[:width-1])
            self.stdscr.addstr(1, max(0, (width - len(banner2)) // 2), banner2[:width-1])
            self.stdscr.addstr(2, max(0, (width - len(banner3)) // 2), banner3[:width-1])
            self.stdscr.attroff(curses.color_pair(5) | curses.A_BOLD)

            # Status line — dynamic (no hardcoded interface / provider)
            iface = self._status_iface()
            ai = self._status_ai()
            status = f" [ Interface: {iface} ] [ AI: {ai} ] [ Status: Ready ] "
            self.stdscr.attron(curses.color_pair(4))
            self.stdscr.addstr(3, max(0, (width - len(status)) // 2), status[:width-1])
            self.stdscr.attroff(curses.color_pair(4))

            # Divider
            self.stdscr.addstr(4, 0, "-" * width)
        except Exception as e:
            logger.debug(f"Error drawing header: {e}")

    def draw_menu(self, start_y: int = 6):
        """Draw selectable menu options"""
        try:
            height, width = self.stdscr.getmaxyx()
            self.stdscr.attron(curses.color_pair(4) | curses.A_BOLD)
            if self.flow_state == "targets":
                label = "Select Target (number keys or UP/DOWN + ENTER):"
            elif self.flow_state == "advanced":
                label = "Advanced Operations:"
            else:
                label = "Select Operation:"
            self.stdscr.addstr(start_y - 1, 2, label)
            self.stdscr.attroff(curses.color_pair(4) | curses.A_BOLD)

            for i, (label, _) in enumerate(self.menu_items):
                y = start_y + i
                if y < height - 6:
                    selected = (i == self.menu_index)
                    marker = "[>]" if selected else "   "

                    # Highlight selected line
                    if selected:
                        self.stdscr.attron(curses.A_REVERSE | curses.color_pair(1))
                    else:
                        self.stdscr.attron(curses.color_pair(6))

                    self.stdscr.addstr(y, 2, f"{marker} {label}".ljust(width - 5)[:width-4])
                    self.stdscr.attroff(curses.A_REVERSE | curses.color_pair(1) | curses.color_pair(6))
        except Exception as e:
            logger.debug(f"Error drawing menu: {e}")

    def draw_activity_log(self, start_y: int, max_height: int):
        """Render shared activity log log panel at bottom"""
        try:
            height, width = self.stdscr.getmaxyx()
            log_height = min(max_height, height - start_y - 3)
            if log_height <= 0:
                return

            self.stdscr.attron(curses.color_pair(4) | curses.A_BOLD)
            self.stdscr.addstr(start_y, 2, "Activity Log:")
            self.stdscr.attroff(curses.color_pair(4) | curses.A_BOLD)

            logs_to_show = self.activity_log[-log_height:]
            for i, log_line in enumerate(logs_to_show):
                y = start_y + 1 + i
                if y < height - 2:
                    # Clean up long lines
                    display_line = log_line.replace("\n", " ").replace("\t", "    ")[:width-6]

                    self.stdscr.addstr(y, 2, " ")
                    if "[+]" in display_line:
                        self.stdscr.attron(curses.color_pair(1) | curses.A_BOLD)
                        self.stdscr.addstr(y, 3, "[+]")
                        self.stdscr.attroff(curses.color_pair(1) | curses.A_BOLD)
                        self.stdscr.addstr(y, 6, display_line[display_line.find("[+]")+3:])
                    elif "[!]" in display_line:
                        self.stdscr.attron(curses.color_pair(2) | curses.A_BOLD)
                        self.stdscr.addstr(y, 3, "[!]")
                        self.stdscr.attroff(curses.color_pair(2) | curses.A_BOLD)
                        self.stdscr.addstr(y, 6, display_line[display_line.find("[!]" )+3:])
                    elif "[*]" in display_line:
                        self.stdscr.attron(curses.color_pair(3) | curses.A_BOLD)
                        self.stdscr.addstr(y, 3, "[*]")
                        self.stdscr.attroff(curses.color_pair(3) | curses.A_BOLD)
                        self.stdscr.addstr(y, 6, display_line[display_line.find("[*]")+3:])
                    elif "[i]" in display_line:
                        self.stdscr.attron(curses.color_pair(4) | curses.A_BOLD)
                        self.stdscr.addstr(y, 3, "[i]")
                        self.stdscr.attroff(curses.color_pair(4) | curses.A_BOLD)
                        self.stdscr.addstr(y, 6, display_line[display_line.find("[i]")+3:])
                    else:
                        self.stdscr.addstr(y, 3, display_line)
        except Exception as e:
            logger.debug(f"Error drawing activity log: {e}")

    def render_kb_tool(self, t: dict):
        """Append one KB tool entry to the activity log."""
        owner = t.get("owner", "")
        repo = t.get("repo_name", "")
        cat = t.get("category") or ""
        self.activity_log.append(
            f"  · https://github.com/{owner}/{repo} [{cat}]"
        )

    def fetch_domain_repos(self, domain: str, limit: int = 15):
        """Clone the top-N KB repos for ``domain`` into toolboxes/<domain>/.

        Runs via ``self._spawn`` (daemon thread in prod, sync in tests).
        The real upstream repos land on disk — no Python wrappers generated.
        """
        import os as _os
        import subprocess as _sp
        import sys as _sys
        self.activity_log.append(
            f"[*] Fetching top {limit} {domain} repos into toolboxes/{domain}/ ..."
        )
        project_root = _os.path.dirname(_os.path.dirname(
            _os.path.dirname(_os.path.abspath(__file__))))

        def run():
            try:
                p = _sp.run(
                    [_sys.executable, "scripts/fetch_toolboxes.py",
                     domain, "--limit", str(limit)],
                    cwd=project_root, capture_output=True, text=True,
                )
                for line in (p.stdout or "").splitlines():
                    if line.strip():
                        self.activity_log.append(f"  {line.strip()}")
                if p.returncode != 0 and p.stderr:
                    self.activity_log.append(f"[!] {p.stderr.strip()[:200]}")
                self.activity_log.append(
                    f"[+] toolboxes/{domain}/ ready."
                )
            except Exception as e:
                self.activity_log.append(f"[!] fetch error: {e}")

        self._spawn(run)

    def prepare_domain_tools(self, domain: str):
        """Install one domain's toolbox repos' deps + chmod scripts."""
        import os as _os
        import subprocess as _sp
        import sys as _sys
        self.activity_log.append(
            f"[*] Preparing {domain} toolboxes (chmod + pip install -r) ..."
        )
        project_root = _os.path.dirname(_os.path.dirname(
            _os.path.dirname(_os.path.abspath(__file__))))

        def run():
            try:
                p = _sp.run(
                    [_sys.executable, "scripts/prepare_toolboxes.py", domain],
                    cwd=project_root, capture_output=True, text=True,
                )
                for line in (p.stdout or "").splitlines():
                    if line.strip():
                        self.activity_log.append(f"  {line.strip()}")
                if p.returncode != 0 and p.stderr:
                    self.activity_log.append(f"[!] {p.stderr.strip()[:200]}")
                self.activity_log.append(f"[+] {domain} toolboxes prepared.")
            except Exception as e:
                self.activity_log.append(f"[!] prepare error: {e}")

        self._spawn(run)

    def draw_status_bar(self):
        """Status instructions bar"""
        try:
            height, width = self.stdscr.getmaxyx()
            if self.flow_state == "targets":
                status_text = " 1-9: Select Target | ENTER: Select Highlighted | BACK/Q: Back"
            elif self.flow_state == "advanced":
                status_text = " UP/DOWN: Navigate | ENTER: Select | BACK/Q: Back to Primary"
            else:
                status_text = " UP/DOWN: Navigate | ENTER: Select | BACKSPACE: Go Back | Q: Quit Screen"
            self.stdscr.attron(curses.color_pair(6))
            self.stdscr.addstr(height - 1, 0, status_text.ljust(width)[:width-1])
            self.stdscr.attroff(curses.color_pair(6))
        except Exception as e:
            logger.debug(f"Error drawing status bar: {e}")

    def _flush_input_queue(self) -> None:
        """Discard pending keypresses so slow handlers cannot re-fire."""
        try:
            from core.tui.interface_picker import flush_curses_input
            flush_curses_input(self.stdscr)
        except Exception:
            try:
                curses.flushinp()
            except Exception:
                pass

    # ---- input handling (key dispatch) ----

    def handle_input(self) -> Optional[str]:
        """Process keyboard keys. Dispatches by ``flow_state``:
        - ``targets``: digit keys select; UP/DOWN/ENTER/SPACE navigate & select; Q/BACK exits.
        - ``menu``/``advanced``: standard menu nav; Q/BACK from advanced
          returns to primary, from primary returns "back" (exit screen).
        """
        if self.stdscr is None:
            return None
        key = read_curses_key(self.stdscr)
        if key == -1:
            return None

        # ---- target-selection view ----
        if self.flow_state == "targets":
            ch = chr(key) if 0 <= key < 256 else ""
            if ch.isdigit():
                n = int(ch)
                idx = n - 1 if n >= 1 else 9  # '1'..'9' -> 0..8, '0' -> 9 (10th)
                self.select_target_by_index(idx)
                return None
            if key in (curses.KEY_UP, ord("k"), ord("K")):
                self.menu_index = max(0, self.menu_index - 1)
                return None
            if key in (curses.KEY_DOWN, ord("j"), ord("J")):
                self.menu_index = min(len(self.menu_items) - 1,
                                      self.menu_index + 1) if self.menu_items else 0
                return None
            if key in (curses.KEY_ENTER, 10, 13, ord(" ")):
                if 0 <= self.menu_index < len(self.menu_items):
                    _, handler = self.menu_items[self.menu_index]
                    if handler:
                        try:
                            handler()
                        except Exception as e:
                            logger.error(f"Error in target handler: {e}")
                            self.activity_log.append(f"[!] Handler error: {e}")
                        finally:
                            self._flush_input_queue()
                return None
            if key in (curses.KEY_BACKSPACE, 127, 8, ord('q'), ord('Q')):
                self._show_primary()
                return None
            return None

        # ---- menu / advanced view ----
        # j/k are vim-style aliases (also used by the agentic TUI debugger
        # when CSI arrow sequences are unreliable under pexpect/sudo).
        if key in (curses.KEY_UP, ord("k"), ord("K")):
            self.menu_index = (self.menu_index - 1) % len(self.menu_items) if self.menu_items else 0
        elif key in (curses.KEY_DOWN, ord("j"), ord("J")):
            self.menu_index = (self.menu_index + 1) % len(self.menu_items) if self.menu_items else 0
        elif key in (curses.KEY_ENTER, 10, 13, ord(" ")):
            # Execute selected menu handler
            if 0 <= self.menu_index < len(self.menu_items):
                _, handler = self.menu_items[self.menu_index]
                if handler:
                    try:
                        handler()
                    except Exception as e:
                        logger.error(f"Error in menu handler: {e}")
                        self.activity_log.append(f"[!] Handler error: {e}")
                    finally:
                        # Drop keys mashed while the handler blocked
                        # (airmon, probes, nested pickers). Without this,
                        # a leftover ENTER re-fires the same item — e.g.
                        # immediately flips monitor → managed after pick.
                        self._flush_input_queue()
        elif key in (curses.KEY_BACKSPACE, 127, 8, ord('q'), ord('Q')):
            if self.flow_state == "advanced":
                self._show_primary()
                return None
            return "back"

        return None

    def render(self):
        """Default full render method for screens"""
        height, width = self.stdscr.getmaxyx()
        if height < 20 or width < 70:
            self.stdscr.erase()
            self.stdscr.addstr(0, 0, "Terminal too small. Minimize font or enlarge window (Need 80x24+).")
            self.stdscr.refresh()
            time.sleep(0.5)
            return

        self.draw_header(self.title)
        self.draw_menu(start_y=6)

        # Log panel height calculation
        menu_height = len(self.menu_items)
        log_y = 6 + menu_height + 1
        log_h = height - log_y - 2
        self.draw_activity_log(start_y=log_y, max_height=log_h)

        self.draw_status_bar()


# ── Module-level helper ───────────────────────────────────────────────
def read_curses_key(stdscr, timeout_ms: int = -1) -> int:
    """Read a key from curses stdscr with ANSI escape sequence fallback.

    Handles ANSI escape sequences for arrow keys (\\x1b[A, \\x1b[B, \\x1b[C, \\x1b[D,
    \\x1bOA, \\x1bOB, \\x1bOC, \\x1bOD) when keypad(True) is unsupported or unmapped by terminfo.
    Returns curses.KEY_UP, curses.KEY_DOWN, curses.KEY_RIGHT, curses.KEY_LEFT,
    or the original key code.
    """
    if stdscr is None:
        return -1
    try:
        key = stdscr.getch()
    except Exception:
        return -1

    if key == 27:  # ESC character — check if ANSI arrow key sequence follows
        try:
            stdscr.timeout(0)
            ch1 = stdscr.getch()
            if ch1 in (ord("["), ord("O")):
                ch2 = stdscr.getch()
                if ch2 in (ord("A"), ord("a")):
                    return curses.KEY_UP
                elif ch2 in (ord("B"), ord("b")):
                    return curses.KEY_DOWN
                elif ch2 in (ord("C"), ord("c")):
                    return curses.KEY_RIGHT
                elif ch2 in (ord("D"), ord("d")):
                    return curses.KEY_LEFT
        except Exception:
            pass
        finally:
            try:
                if timeout_ms >= 0:
                    stdscr.timeout(timeout_ms)
                else:
                    stdscr.nodelay(False)
            except Exception:
                pass
    return key