#!/usr/bin/env python3
"""
OSINT Screen TUI
OSINT gathering sub-menu (wifite-style primary flow + Advanced submenu).
Integrates curated OSINT catalog, Shodan API scans, NVD CVE lookup, and
AI-assisted autonomous tool selection. All runners are real — if a tool is
not installed, an honest error is shown (no fake results). All actions are
curses-free callable for pytest.
"""

import logging
import os
import shutil
import subprocess
from typing import List, Dict, Any

from core.tui.base_screen import BaseScreen
from core.osint_catalog import OSINTCatalog
from core.ai_backend import AIBackend
from core.exploit_knowledge_base import ExploitKnowledgeBase

logger = logging.getLogger(__name__)


class OSINTScreen(BaseScreen):
    def __init__(self, stdscr, parent_callback, activity_log: List[str], **kwargs):
        super().__init__(stdscr, parent_callback, activity_log, **kwargs)
        self.title = "OSINT Gathering"

        self.catalog = OSINTCatalog()
        # Reuse shared instances from the dashboard when provided.
        self.ai_backend = self.ai_backend or AIBackend(
            settings=kwargs.get("settings_manager")
        )
        self.kb = self.kb or ExploitKnowledgeBase()
        self.post_runner = kwargs.get("post_runner")
        self.orchestrator = kwargs.get("orchestrator")
        self.osint_runner = kwargs.get("osint_runner")
        self.tui_confirm = kwargs.get("tui_confirm")

        self.target = None
        self.osint_findings: List[Dict[str, Any]] = []  # numbered-findings list
        self._post_plan = None  # last computed post-exploit plan
        self._last_report = None

        # ---- wifite-style primary flow ----
        self.primary_items = [
            ("Set OSINT Target (Domain / Email / User / Phone)", self.set_osint_target),
            ("Auto OSINT (classify + multi-category)", self.run_auto_osint),
            ("Run All OSINT + Attack Chain (AI-orchestrated)", self.run_full_osint_chain),
            ("Show Findings (numbered list)", self._show_findings_view),
            ("Show Report (last engagement)", self.show_report),
            ("Advanced…", self._show_advanced),
            ("Back to Main Menu", self.parent_callback),
        ]
        self.advanced_items = [
            ("People Search (username + social + phone)", self.run_people_search),
            ("Email OSINT (holehe)", self.run_email_osint),
            ("Username OSINT (sherlock / maigret)", self.run_username_osint),
            ("Domain & Port OSINT (shodan)", self.run_domain_osint),
            ("CVE Lookup (NVD)", self.run_cve_lookup),
            ("Social Media OSINT (toutatis)", self.run_social_osint),
            ("Breach check (HIBP / heuristic)", self.run_breach_check),
            ("AI-Driven Autonomous OSINT Chaining", self.run_autonomous_osint),
            ("Post-Exploit Plan from OSINT (AI+KB)", self.plan_post_exploit),
            ("Post-Exploit: Execute Plan (gated)", self.execute_post_exploit),
            ("Search Curated OSINT Tools Directory", self.search_tools_catalog),
            ("Fetch OSINT tool repos (clone into toolboxes/)", lambda: self.fetch_domain_repos("osint")),
            ("Prepare OSINT tools (install deps)", lambda: self.prepare_domain_tools("osint")),
            ("Back to Primary", self._show_primary),
        ]
        self._show_primary()

    # ------------------------------------------------------------------
    # Wifite flow hooks (findings = numbered "targets")
    # ------------------------------------------------------------------
    def _target_label(self, idx, target):
        if isinstance(target, dict):
            return f"{idx + 1}. [{target.get('type', '?')}] {target.get('value')}"
        return f"{idx + 1}. {target}"

    def _on_target_selected(self, idx):
        f = self.selected_target
        if isinstance(f, dict):
            self.activity_log.append(
                f"[+] Finding #{idx + 1} selected: [{f.get('type', '?')}] {f.get('value')}"
            )
        else:
            self.activity_log.append(f"[+] Finding #{idx + 1} selected: {f}")

    def _show_findings_view(self):
        """Primary-menu entry: show the numbered findings list (if any)."""
        self.targets = list(self.osint_findings)
        if not self.targets:
            self.activity_log.append("[i] No findings yet — run OSINT first.")
            return
        self._enter_targets_view()

    def show_report(self):
        self.activity_log.append("=== Last OSINT Engagement Report ===")
        self.activity_log.append(f"[i] Target: {self.target or '(none set)'}")
        self.activity_log.append(f"[i] Findings collected: {len(self.osint_findings)}")
        if self._last_report is not None:
            self.activity_log.append(
                f"[i] Attack chain domain: {self._last_report.get('domain', '?')}"
            )
        self.activity_log.append(
            "[i] Step-by-step output (ACCEPT/CANCEL gated) is in the activity log above."
        )

    # ------------------------------------------------------------------
    # Primary-flow actions
    # ------------------------------------------------------------------
    def run_full_osint_chain(self):
        """Run people-search first (collects findings), then the AI-orchestrated
        OSINT attack chain via the orchestrator (Shodan + NVD + MSF exploit +
        post_exploit + info:phishing), step-by-step ACCEPT/CANCEL."""
        if not self.target:
            self.activity_log.append("[!] Set an OSINT target first.")
            return
        if not self.orchestrator:
            self.activity_log.append("[!] Orchestrator unavailable.")
            return
        target = {"target": self.target}
        runner = self._osint_runner()
        self.activity_log.append(
            f"[*] Full OSINT chain for '{self.target}' (people search → AI attack chain)..."
        )

        def run():
            try:
                # 1) People search to seed findings (best-effort; non-fatal).
                try:
                    res = runner.run_people(self.target, timeout=90)
                    self._absorb_people_findings(res)
                except Exception as e:
                    self.activity_log.append(f"[!] people-search skipped: {e}")
                # 2) AI-orchestrated attack chain. New path: route
                # through AIChainPlanner when wired in; the legacy
                # hardcoded ladder is the no-planner fallback.
                self.orchestrator.run("osint", target, use_ai_chain=True)
                self._last_report = {"domain": "osint", "target": target}
            except Exception as e:
                self.activity_log.append(f"[!] OSINT chain error: {e}")

        self._spawn(run)

    def _absorb_people_findings(self, res: Dict[str, Any]) -> None:
        """Flatten a people-search result into ``self.osint_findings``."""
        if not isinstance(res, dict):
            return
        before = len(self.osint_findings)
        seen = {
            (f.get("type"), f.get("value"))
            for f in self.osint_findings
            if isinstance(f, dict)
        }
        bucket = list(res.get("findings") or [])
        for cat, r in (res.get("categories") or {}).items():
            if isinstance(r, dict):
                for f in r.get("findings") or []:
                    bucket.append(f)
        for f in bucket:
            if not isinstance(f, dict):
                continue
            key = (f.get("type"), f.get("value"))
            if key in seen:
                continue
            seen.add(key)
            self.osint_findings.append({
                "type": f.get("type", "finding"),
                "value": f.get("value", ""),
                "source": f.get("source", ""),
            })
        added = len(self.osint_findings) - before
        if added:
            self.activity_log.append(
                f"[+] Collected +{added} OSINT finding(s) "
                f"(total {len(self.osint_findings)}) — view via 'Show Findings'."
            )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _osint_runner(self):
        # Prefer the shared, TUI-gated runner from the dashboard. Fall back to
        # a runner wired with the shared confirm_fn so ACCEPT/CANCEL still works.
        if self.osint_runner is not None:
            return self.osint_runner
        from core.osint.runner import OSINTRunner
        confirm = getattr(self.tui_confirm, "confirm", None) if self.tui_confirm else None
        return OSINTRunner(catalog=self.catalog, confirm_fn=confirm)

    def _nvd_key(self) -> str:
        from core.ai_backend import get_nvd_key
        return get_nvd_key(self.settings_manager)

    def _run_cli(self, argv: List[str], timeout: int = 60) -> Dict[str, Any]:
        """Run a real CLI; return {rc, stdout, stderr}. Never fakes output."""
        try:
            p = subprocess.run(
                argv, capture_output=True, text=True, timeout=timeout
            )
            return {"rc": p.returncode, "stdout": p.stdout, "stderr": p.stderr}
        except FileNotFoundError:
            return {"rc": 127, "stdout": "", "stderr": f"{argv[0]}: not found"}
        except subprocess.TimeoutExpired:
            return {"rc": 124, "stdout": "", "stderr": "timeout"}

    # ------------------------------------------------------------------
    # Target + runners
    # ------------------------------------------------------------------
    def set_osint_target(self):
        target = self.get_input("Enter target (e.g. target.com, admin@target.com, admin1337)")
        if target:
            self.target = target
            self.osint_findings = []  # reset findings for the new target
            try:
                from core.osint.runner import classify_osint_target
                cls = classify_osint_target(target)
                self.activity_log.append(
                    f"[+] Active OSINT target set to: {self.target} "
                    f"(kind={cls.get('kind')}, normalized={cls.get('normalized')})"
                )
            except Exception:
                self.activity_log.append(f"[+] Active OSINT target set to: {self.target}")

    def run_auto_osint(self):
        """Classify target and run the best multi-category OSINT plan."""
        if not self.target:
            self.activity_log.append("[!] Set an OSINT target first.")
            return
        self.activity_log.append(f"[*] Auto OSINT for '{self.target}'...")
        runner = self._osint_runner()

        def run():
            res = runner.run_auto(self.target, timeout=90)
            cls = res.get("classification") or {}
            self.activity_log.append(
                f"[i] Classified as {cls.get('kind')} → plan={res.get('plan')}"
            )
            if res.get("adapt_pick"):
                self.activity_log.append(f"[i] Adapt pick: {res['adapt_pick']}")
            total = 0
            for cat, r in (res.get("categories") or {}).items():
                findings = r.get("findings") or []
                total += len(findings)
                if r.get("error"):
                    self.activity_log.append(f"[!] {cat}: {r['error']}")
                    continue
                tool = r.get("ran_tool") or "—"
                self.activity_log.append(
                    f"[+] {cat} via {tool}: {len(findings)} finding(s)"
                )
                for f in findings[:20]:
                    self.activity_log.append(
                        f"    [{f.get('type')}] {f.get('value')}"
                    )
            for name, probe in (res.get("local_probes") or {}).items():
                self.activity_log.append(
                    f"[i] local {name}: {probe.get('type') or name}"
                )
            self._absorb_people_findings(res)
            agg = res.get("aggregate") or {}
            self.activity_log.append(
                f"[i] Auto OSINT complete: {agg.get('count', total)} unique finding(s)."
            )

        self._spawn(run)

    def run_breach_check(self):
        """HIBP (if keyed) or honest risk-indicator breach correlate."""
        if not self.target:
            self.activity_log.append("[!] Set an OSINT target first.")
            return
        runner = self._osint_runner()

        def run():
            res = runner._correlate_breach_data(self.target)
            val = res.get("value") or {}
            self.activity_log.append(
                f"[i] Breach likelihood: {val.get('breach_likelihood')} "
                f"({val.get('source_note')})"
            )
            for ind in val.get("risk_indicators") or []:
                self.activity_log.append(f"    indicator: {ind}")
            breaches = val.get("identified_breaches") or []
            if breaches:
                for b in breaches[:15]:
                    if isinstance(b, dict):
                        self.activity_log.append(
                            f"    [breach] {b.get('Name')} "
                            f"({b.get('BreachDate') or '?'})"
                        )
                    else:
                        self.activity_log.append(f"    [breach] {b}")
            else:
                self.activity_log.append(
                    "[i] No live breach names "
                    "(set KFIOSA_HIBP_KEY for HIBP API)."
                )
            if val.get("recommendation"):
                self.activity_log.append(f"[i] {val['recommendation']}")

        self._spawn(run)

    def run_people_search(self):
        """Search for a person across username + social + phone (real CLIs)."""
        if not self.target:
            self.activity_log.append("[!] Set a target (username/email/phone) first.")
            return
        self.activity_log.append(f"[*] People search for '{self.target}'...")
        runner = self._osint_runner()

        def run():
            res = runner.run_people(self.target, timeout=90)
            cls = res.get("classification") or {}
            if cls:
                self.activity_log.append(
                    f"[i] Classified as {cls.get('kind')} plan={res.get('plan')}"
                )
            total = 0
            for cat, r in res.get("categories", {}).items():
                findings = r.get("findings", [])
                total += len(findings)
                tool = r.get("ran_tool") or "—"
                if r.get("error"):
                    self.activity_log.append(f"[!] {cat}: {r['error']}")
                    continue
                self.activity_log.append(
                    f"[+] {cat} via {tool}: {len(findings)} finding(s)"
                )
                for f in findings[:25]:
                    self.activity_log.append(f"    [{f['type']}] {f['value']}")
            self._absorb_people_findings(res)
            agg = res.get("aggregate") or {}
            self.activity_log.append(
                f"[i] People search complete: "
                f"{agg.get('count', total)} unique finding(s)."
            )

        self._spawn(run)
    def plan_post_exploit(self):
        if not self.target:
            self.activity_log.append("[!] Set an OSINT target first.")
            return
        if not self.post_runner:
            self.activity_log.append("[!] Post-exploit runner unavailable.")
            return
        session_id = self.get_input("Live MSF session id (blank = plan only, no execution)")
        session = None
        if session_id and session_id.strip():
            session = {"id": session_id.strip(), "os": "linux", "type": "post"}
        self.activity_log.append("[*] Planning post-exploit from OSINT (AI + KB)...")
        target = {"target": self.target}

        def run():
            plan = self.post_runner.plan("osint", target, session=session)
            self._post_plan = plan
            if plan.get("ai_plan"):
                self.activity_log.append("=== AI OSINT Post-Exploit Plan ===")
                for line in plan["ai_plan"].splitlines():
                    if line.strip():
                        self.activity_log.append(line)
            if plan.get("error") and not plan.get("ai_plan"):
                self.activity_log.append(f"[!] {plan['error']}")
            if plan.get("kb_tools"):
                self.activity_log.append(
                    f"[i] KB tools ({len(plan['kb_tools'])}): "
                    + ", ".join(t.get("repo_name", "") for t in plan["kb_tools"][:6])
                )
            if plan.get("msf_plan") and plan["msf_plan"].get("steps"):
                self.activity_log.append(
                    f"[+] MSF plan: {len(plan['msf_plan']['steps'])} steps "
                    "(execute via Advanced → Post-Exploit Execute)."
                )
            else:
                self.activity_log.append(
                    "[i] No executable MSF steps (provide a real live session id)."
                )

        self._spawn(run)

    def execute_post_exploit(self):
        """Execute the last MSF plan, each step gated by ACCEPT/CANCEL."""
        if not self.post_runner:
            self.activity_log.append("[!] Post-exploit runner unavailable.")
            return
        if not self._post_plan or not self._post_plan.get("msf_plan"):
            self.activity_log.append(
                "[!] No MSF plan to execute — run 'Post-Exploit Plan' first "
                "(requires a real live session)."
            )
            return
        self.activity_log.append("[*] Executing MSF plan — each step prompts ACCEPT/CANCEL...")

        def run():
            results = self.post_runner.execute(self._post_plan)
            for r in results:
                self.activity_log.append(f"[i] step: {r}")

        self._spawn(run)

    def run_email_osint(self):
        if not self.target:
            self.activity_log.append("[!] Please set target email first.")
            return
        if "@" not in self.target:
            self.activity_log.append("[!] Target does not appear to be an email.")
            return
        if not shutil.which("holehe"):
            self.activity_log.append(
                "[!] holehe not installed — `pip install holehe` (no fake results)."
            )
            return
        self.activity_log.append(f"[*] holehe {self.target} ...")

        def run():
            res = self._run_cli(["holehe", self.target], timeout=90)
            self.activity_log.append(f"[i] holehe rc={res['rc']}")
            for line in (res["stdout"] or "").splitlines():
                if line.strip():
                    self.activity_log.append(f"  {line.strip()}")
            if res["stderr"].strip():
                self.activity_log.append(f"[!] {res['stderr'].strip()[:160]}")

        self._spawn(run)

    def run_username_osint(self):
        if not self.target:
            self.activity_log.append("[!] Please set target username first.")
            return
        tool = next((t for t in ("sherlock", "nexfil") if shutil.which(t)), None)
        if not tool:
            self.activity_log.append(
                "[!] Neither sherlock nor nexfil installed (no fake results)."
            )
            return
        self.activity_log.append(f"[*] {tool} {self.target} ...")

        def run():
            res = self._run_cli([tool, self.target, "--timeout", "30"], timeout=120)
            self.activity_log.append(f"[i] {tool} rc={res['rc']}")
            for line in (res["stdout"] or "").splitlines()[:40]:
                if line.strip():
                    self.activity_log.append(f"  {line.strip()}")

        self._spawn(run)

    def run_domain_osint(self):
        if not self.target:
            self.activity_log.append("[!] Please set target domain first.")
            return
        self.activity_log.append(f"[*] Fetching Shodan intelligence for {self.target}...")

        def scan_shodan():
            try:
                from core.integrations.shodan_integration import ShodanIntegration
                shodan = ShodanIntegration(settings=self.settings_manager)
                if hasattr(shodan, "initialize"):
                    shodan.initialize()
                results = shodan.search_host(self.target) if hasattr(shodan, "search_host") else shodan.host_lookup(self.target)
                if isinstance(results, dict) and results.get("error"):
                    self.activity_log.append(f"[!] Shodan: {results['error']}")
                    return
                self.activity_log.append(f"[+] Shodan host info for {self.target}:")
                self.activity_log.append(f"  IP: {results.get('ip_str') or results.get('ip')}")
                self.activity_log.append(f"  OS: {results.get('os', 'Unknown')}")
                ports = results.get("ports", [])
                if ports:
                    self.activity_log.append(f"  Open Ports: {', '.join(str(p) for p in ports)}")
                    self.osint_findings.append(
                        {"type": "open_port", "value": ", ".join(str(p) for p in ports)}
                    )
                vulns = results.get("vulns", [])
                if vulns:
                    self.activity_log.append(f"  [!] Vulnerabilities: {', '.join(map(str, vulns))}")
                    for v in vulns:
                        self.osint_findings.append({"type": "shodan_vuln", "value": str(v)})
            except Exception as e:
                logger.error(f"Shodan scanner failed: {e}")
                self.activity_log.append(f"[!] Shodan check failed: {e}")

        self._spawn(scan_shodan)

    def run_cve_lookup(self):
        """Real NVD CVE lookup using the configured API key."""
        cve = self.get_input("Enter CVE-ID (e.g. CVE-2021-44228) or blank for target")
        q = cve.strip() or self.target
        if not q:
            self.activity_log.append("[!] No CVE or target set.")
            return
        self.activity_log.append(f"[*] NVD lookup: {q}")

        def run():
            try:
                import requests
                key = self._nvd_key()
                headers = {"apiKey": key} if key else {}
                # NVD CVE API: cveId exact match, else keywordSearch.
                if q.upper().startswith("CVE-"):
                    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
                    params = {"cveId": q.upper()}
                else:
                    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
                    params = {"keywordSearch": q, "resultsPerPage": 10}
                r = requests.get(url, headers=headers, params=params, timeout=20)
                if r.status_code != 200:
                    self.activity_log.append(f"[!] NVD HTTP {r.status_code}")
                    return
                data = r.json()
                vulns = data.get("vulnerabilities", [])
                self.activity_log.append(f"[+] NVD returned {len(vulns)} CVE(s)")
                for v in vulns[:10]:
                    c = v.get("cve", {})
                    cid = c.get("id", "?")
                    descs = c.get("descriptions", [])
                    desc = next((d.get("value", "") for d in descs if d.get("lang") == "en"), "")
                    self.activity_log.append(f"  · {cid}: {desc[:140]}")
                    self.osint_findings.append({"type": "cve", "value": cid})
                # KB cross-ref
                if self.kb and vulns:
                    cid = vulns[0].get("cve", {}).get("id")
                    if cid:
                        repos = self.kb.get_cve_repos(cid, limit=5)
                        if repos:
                            self.activity_log.append(f"[i] KB repos referencing {cid}:")
                            for rp in repos:
                                self.activity_log.append(
                                    f"    - https://github.com/{rp['owner']}/{rp['repo_name']}"
                                )
            except Exception as e:
                self.activity_log.append(f"[!] NVD lookup error: {e}")

        self._spawn(run)

    def run_social_osint(self):
        if not self.target:
            self.activity_log.append("[!] Please set target username first.")
            return
        if not shutil.which("toutatis"):
            self.activity_log.append(
                "[!] toutatis not installed (no fake social results)."
            )
            return
        self.activity_log.append(f"[*] toutatis {self.target} ...")

        def run():
            res = self._run_cli(["toutatis", "-u", self.target], timeout=60)
            self.activity_log.append(f"[i] toutatis rc={res['rc']}")
            for line in (res["stdout"] or "").splitlines()[:30]:
                if line.strip():
                    self.activity_log.append(f"  {line.strip()}")

        self._spawn(run)

    def run_autonomous_osint(self):
        if not self.target:
            self.activity_log.append("[!] Please set target first.")
            return
        self.activity_log.append(f"[*] AI autonomous OSINT chaining for: {self.target}...")

        def run_ai():
            target_info = {"target_name": self.target}
            tools = self.ai_backend.autonomous_tool_selection("osint", target_info)
            self.activity_log.append(f"[+] AI recommended tool sequence: {' -> '.join(tools)}")
            prompt = (
                f"Develop a detailed reconnaissance and OSINT capture strategy targeting: "
                f"'{self.target}'. Suggest exact command strings and variables."
            )
            ai_plan = self.ai_backend.query("osint", prompt)
            self.activity_log.append("=== AI Autonomous OSINT Workflow ===")
            for line in ai_plan.split("\n"):
                if line.strip():
                    self.activity_log.append(line)

        self._spawn(run_ai)

    def search_tools_catalog(self):
        query = self.get_input("Enter search query (e.g. maltego, email, phone)")
        if not query:
            return
        self.activity_log.append(f"[*] Searching catalog for '{query}'...")
        results = self.catalog.search_tools(query)
        if results:
            self.activity_log.append(f"[+] Found {len(results)} matching tools:")
            for tool in results:
                self.activity_log.append(f"  · {tool['name']} ({tool['repo']}): {tool['description']}")
                self.activity_log.append(f"    Install: {tool['install']} | Usage: {tool['usage']}")
        else:
            self.activity_log.append("[!] No matching tools in catalog — searching exploit KB...")
            kb_results = self.kb.search(query, category="osint", limit=5)
            if kb_results:
                self.activity_log.append(f"[+] Found {len(kb_results)} related repos in KB:")
                for repo in kb_results:
                    self.activity_log.append(f"  · https://github.com/{repo['owner']}/{repo['repo_name']}")
            else:
                self.activity_log.append("[!] No results in exploit knowledge base either.")