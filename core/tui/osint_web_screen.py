#!/usr/bin/env python3
"""OSINT Web — dorking / vulnerable sites / optional post-access attach."""
from __future__ import annotations

import logging
import threading
from typing import Any, List, Optional

from core.tui.base_screen import BaseScreen

logger = logging.getLogger(__name__)


class OSINTWebScreen(BaseScreen):
    """Friendly web OSINT + gated offensive web chain options."""

    def __init__(self, stdscr, parent_callback, activity_log: List[str], **kwargs):
        super().__init__(stdscr, parent_callback, activity_log, **kwargs)
        self.title = "OSINT Web"
        self.orchestrator = kwargs.get("orchestrator")
        self.osint_runner = kwargs.get("osint_runner")
        self.query: Optional[str] = None
        self._last_report: Any = None
        self._last_url: Optional[str] = None

        self.primary_items = [
            ("Dork / find sites", self.dork_sites),
            ("Domain deep recon", self.domain_recon),
            ("Probe site (safe recon only)", self.probe_site),
            ("Plan offensive web chain (gated)", self.plan_offensive),
            ("Attach website session to dashboard", self.attach_website),
            ("Show last report", self.show_report),
            ("Back", self.parent_callback),
        ]
        self.menu_items = list(self.primary_items)
        self._show_primary()

    def _show_primary(self):
        self.menu_items = list(self.primary_items)
        self.menu_index = 0

    def _prompt(self, label: str) -> str:
        try:
            return str(self.get_input(label) or "").strip()
        except Exception:
            self.activity_log.append(f"[i] Prompt: {label}")
            return ""

    def _engage(self, mode: str, query: str, *, offensive: bool = False) -> None:
        if not query:
            self.activity_log.append("[!] Empty query — try again.")
            return
        self.query = query
        target = {
            "query": query,
            "target": query,
            "url": query if query.startswith("http") else "",
            "domain": query,
            "osint_mode": "web",
            "web_mode": mode,
            "use_ai_chain": True,
            "offensive": offensive,
            "dashboard_kind": "website",
        }
        self.activity_log.append(f"[web] {mode}: {query!r}")

        def run():
            try:
                from core.orchestrator.engagement_engine import EngagementEngine
                eng = EngagementEngine(
                    self.orchestrator,
                    on_event=lambda m: self.activity_log.append(m),
                    until_access=bool(offensive),
                    enable_bg_zero_day=bool(offensive),
                )
                rep = eng.run("osint_web", target)
                self._last_report = rep
                ok = bool((rep or {}).get("ok"))
                # Auto-attach website session for probe/domain/offensive success
                if ok and mode in ("probe", "domain_recon", "offensive_plan", "dork"):
                    try:
                        from core.post_access_tui.rat_ext.long_jobs import (
                            enqueue_website_session,
                        )
                        url = query if query.startswith("http") else f"https://{query}" if "." in query else query
                        sid = enqueue_website_session(
                            url or query,
                            status="attached" if ok else "error",
                            report=rep if isinstance(rep, dict) else None,
                        )
                        self.activity_log.append(
                            f"[+] Website session {sid} → Flask (kind=website)"
                        )
                    except Exception as e:
                        self.activity_log.append(f"[i] website session: {e}")
                self.activity_log.append(
                    f"[{'+' if ok else '!'}] Web OSINT done mode={mode}"
                )
            except Exception as e:
                self.activity_log.append(f"[!] web engagement: {e}")

        if hasattr(self, "_spawn") and callable(self._spawn):
            self._spawn(run)
        else:
            threading.Thread(target=run, daemon=True).start()

    def dork_sites(self):
        q = self._prompt("Dork / keywords: ")
        self._engage("dork", q)

    def domain_recon(self):
        q = self._prompt("Domain: ")
        self._engage("domain_recon", q)

    def probe_site(self):
        q = self._prompt("URL or host (safe recon): ")
        self._last_url = q
        self._engage("probe", q, offensive=False)

    def plan_offensive(self):
        q = self._prompt("Target site/domain (gated chain): ")
        self._last_url = q
        self._engage("offensive_plan", q, offensive=True)

    def attach_website(self):
        q = self._last_url or self._prompt("Website URL to attach: ")
        if not q:
            self.activity_log.append("[!] No URL.")
            return
        try:
            from core.post_access_tui.rat_ext.long_jobs import (
                enqueue_website_session,
            )
            sid = enqueue_website_session(
                q, report=self._last_report, status="attached"
            )
            self.activity_log.append(
                f"[+] Website session {sid} attached (kind=website) → Flask"
            )
        except Exception as e:
            self.activity_log.append(f"[!] attach website: {e}")

    def show_report(self):
        self.activity_log.append("=== OSINT Web Report ===")
        self.activity_log.append(f"[i] Last query: {self.query or '(none)'}")
        self.activity_log.append(f"[i] Last URL: {self._last_url or '(none)'}")
        if self._last_report:
            self.activity_log.append(f"[i] ok={self._last_report.get('ok')}")
        else:
            self.activity_log.append("[i] No report yet.")
