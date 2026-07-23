#!/usr/bin/env python3
"""OSINT People — friendly, AI-driven people-search sub-menu."""
from __future__ import annotations

import logging
import threading
from typing import Any, Dict, List, Optional

from core.tui.base_screen import BaseScreen

logger = logging.getLogger(__name__)


class OSINTPeopleScreen(BaseScreen):
    """Simple people OSINT options; heavy lifting is AI/orchestrator-driven."""

    def __init__(self, stdscr, parent_callback, activity_log: List[str], **kwargs):
        super().__init__(stdscr, parent_callback, activity_log, **kwargs)
        self.title = "OSINT People"
        self.ai_backend = kwargs.get("ai_backend") or self.ai_backend
        self.orchestrator = kwargs.get("orchestrator")
        self.osint_runner = kwargs.get("osint_runner")
        self.tui_confirm = kwargs.get("tui_confirm")
        self.query: Optional[str] = None
        self._last_report: Any = None

        self.primary_items = [
            ("Find someone (name / username)", self.find_someone),
            ("Check email footprint", self.check_email),
            ("Phone (PL-aware, no-key)", self.check_phone),
            ("Full people profile (long-running → dashboard)", self.full_profile),
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
            self.activity_log.append(f"[i] Enter value: {label}")
            return ""

    def _engage(self, mode: str, query: str, *, long_running: bool = False) -> None:
        if not query:
            self.activity_log.append("[!] Empty query — try again.")
            return
        self.query = query
        target = {
            "query": query,
            "target": query,
            "value": query,
            "osint_mode": "people",
            "people_mode": mode,
            "use_ai_chain": True,
            "long_running": long_running,
            "dashboard_kind": "people",
        }
        self.activity_log.append(
            f"[people] {mode}: {query!r} (AI-driven, ACCEPT-gated where needed)"
        )

        def run():
            jid = None
            try:
                from core.post_access_tui.rat_ext.long_jobs import (
                    enqueue_people_job,
                    update_job,
                )
                if long_running:
                    jid = enqueue_people_job(query, status="queued")
                    self.activity_log.append(
                        f"[people] long job {jid} queued → Flask (kind=people)"
                    )
                    update_job(jid, status="running")
            except Exception as e:
                self.activity_log.append(f"[i] dashboard job note: {e}")
            try:
                from core.orchestrator.engagement_engine import EngagementEngine
                eng = EngagementEngine(
                    self.orchestrator,
                    on_event=lambda m: self.activity_log.append(m),
                    until_access=False,
                    enable_bg_zero_day=False,
                )
                rep = eng.run("osint_people", target)
                self._last_report = rep
                ok = bool((rep or {}).get("ok"))
                if jid:
                    try:
                        from core.post_access_tui.rat_ext.long_jobs import update_job
                        update_job(
                            jid,
                            status="done" if ok else "error",
                            report=rep if isinstance(rep, dict) else None,
                            achieved=["osint_profile"] if ok else [],
                        )
                        self.activity_log.append(
                            f"[+] People job {jid} → {'done' if ok else 'error'}"
                        )
                    except Exception as e:
                        self.activity_log.append(f"[i] job update: {e}")
                elif not long_running and ok:
                    # Short runs also surface a people session on the dashboard
                    try:
                        from core.post_access_tui.rat_ext.long_jobs import (
                            enqueue_people_job,
                        )
                        sid = enqueue_people_job(
                            query, status="done", report=rep
                        )
                        self.activity_log.append(
                            f"[+] People session {sid} on Flask dashboard"
                        )
                    except Exception:
                        pass
                self.activity_log.append(
                    f"[{'+' if ok else '!'}] People OSINT done ok={ok}"
                )
            except Exception as e:
                if jid:
                    try:
                        from core.post_access_tui.rat_ext.long_jobs import update_job
                        update_job(jid, status="error", error=str(e)[:200])
                    except Exception:
                        pass
                self.activity_log.append(f"[!] people engagement: {e}")

        if hasattr(self, "_spawn") and callable(self._spawn):
            self._spawn(run)
        else:
            threading.Thread(target=run, daemon=True).start()

    def find_someone(self):
        q = self._prompt("Name or username: ")
        self._engage("find", q)

    def check_email(self):
        q = self._prompt("Email address: ")
        self._engage("email", q)

    def check_phone(self):
        q = self._prompt("Phone (PL-aware OK): ")
        self._engage("phone", q)

    def full_profile(self):
        q = self._prompt("Subject (name/user/email): ")
        self._engage("full_profile", q, long_running=True)

    def show_report(self):
        self.activity_log.append("=== OSINT People Report ===")
        self.activity_log.append(f"[i] Last query: {self.query or '(none)'}")
        if self._last_report:
            self.activity_log.append(
                f"[i] ok={self._last_report.get('ok')} "
                f"phases={len(self._last_report.get('phases') or [])}"
            )
        else:
            self.activity_log.append("[i] No report yet.")
