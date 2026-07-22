#!/usr/bin/env python3
"""
BLE Screen TUI
Bluetooth Low Energy scanner sub-menu (wifite-style primary flow + Advanced
submenu). Integrates BLE bleak scanning and AI-assisted device risk
assessment. All actions are curses-free callable for pytest.
"""

import logging
from typing import List, Dict, Any

from core.tui.base_screen import BaseScreen
from core.ai_backend import AIBackend

logger = logging.getLogger(__name__)

class BLEScreen(BaseScreen):
    def __init__(self, stdscr, parent_callback, activity_log: List[str], **kwargs):
        super().__init__(stdscr, parent_callback, activity_log, **kwargs)
        self.title = "BLE Scanning & Analysis"

        # Reuse shared instances from the dashboard when provided.
        self.ai_backend = self.ai_backend or AIBackend(
            settings=kwargs.get("settings_manager")
        )
        self.post_runner = kwargs.get("post_runner")
        self.orchestrator = kwargs.get("orchestrator")

        self.ble_devices: List[Dict[str, Any]] = []
        self.selected_device = None
        self.interface = None  # BLE adapter — detected at runtime
        self._post_plan = None  # last computed post-exploit plan
        self._last_report = None

        # ---- wifite-style primary flow ----
        self.primary_items = [
            ("Scan for BLE Devices (AI-Enhanced)", self.scan_ble_devices),
            ("Select Target (number keys)", self._select_target_prompt),
            ("Run All Attacks (AI-orchestrated, ACCEPT/CANCEL)", self.run_attack_chain),
            ("Show Report (last engagement)", self.show_report),
            ("Advanced…", self._show_advanced),
            ("Back to Main Menu", self.parent_callback),
        ]
        self.advanced_items = [
            ("Pick Bluetooth Adapter (auto-detect)", self.pick_adapter),
            ("Connect to Device / Enumerate GATT", self.connect_and_enumerate),
            ("AI Device Vulnerability Assessment", self.run_ai_risk_assessment),
            ("Post-Exploit Plan (AI+KB)", self.plan_post_exploit),
            ("Post-Exploit: Execute Plan (gated)", self.execute_post_exploit),
            ("Show KB Tools for BLE", self.show_kb_tools),
            ("Fetch BLE tool repos (clone into toolboxes/)", lambda: self.fetch_domain_repos("ble")),
            ("Prepare BLE tools (install deps)", lambda: self.prepare_domain_tools("ble")),
            ("Back to Primary", self._show_primary),
        ]
        self._show_primary()

    # ------------------------------------------------------------------
    # Wifite flow hooks
    # ------------------------------------------------------------------
    def _target_label(self, idx, target):
        return (f"{idx + 1}. {target.get('name') or '<unknown>'} "
                f"[{target.get('address')}] RSSI {target.get('rssi')}dBm")

    def _on_target_selected(self, idx):
        d = self.selected_target
        self.activity_log.append(
            f"[+] BLE target #{idx + 1} selected: {d.get('name')} "
            f"({d.get('address')}) — Run All Attacks to engage."
        )

    def show_report(self):
        self.activity_log.append("=== Last BLE Engagement Report ===")
        if self.selected_target is not None:
            d = self.selected_target
            self.activity_log.append(
                f"[i] Target: {d.get('name')} ({d.get('address')}) "
                f"RSSI {d.get('rssi')}dBm"
            )
        else:
            self.activity_log.append("[i] Target: (none selected)")
        self.activity_log.append(f"[i] Devices discovered last scan: {len(self.ble_devices)}")
        self.activity_log.append(
            "[i] Step-by-step output (ACCEPT/CANCEL gated) is in the activity log above."
        )

    # selected_device is the canonical BLE target; keep selected_target in sync.
    def select_target_by_index(self, idx):
        ok = super().select_target_by_index(idx)
        if ok:
            self.selected_device = self.selected_target
        return ok

    # ------------------------------------------------------------------
    # Primary-flow actions
    # ------------------------------------------------------------------
    def run_attack_chain(self):
        if not self.selected_device:
            self.activity_log.append("[!] Select a BLE device first (Scan → number key).")
            return
        if not self.orchestrator:
            self.activity_log.append("[!] Orchestrator unavailable.")
            return
        target = dict(self.selected_device)

        def run():
            try:
                # New: route through AIChainPlanner when the planner
                # is wired in. Falls back to the legacy ladder when
                # chain_planner is None on the orchestrator.
                self.orchestrator.run("ble", target, use_ai_chain=True)
                self._last_report = {"domain": "ble", "target": target}
            except Exception as e:
                self.activity_log.append(f"[!] attack chain error: {e}")

        self._spawn(run)

    def scan_ble_devices(self):
        """Perform a real BLE scan (bleak → bluetoothctl → hcitool; no fake
        devices). On success, populate ``self.targets`` and enter the
        numbered-targets view."""
        self.activity_log.append("[*] Scanning for local Bluetooth Low Energy devices...")

        def run_scan():
            try:
                scanner_cls = self.scanner_cls
                if scanner_cls is not None:
                    scanner = scanner_cls()
                else:
                    from core.scanners.enhanced_ble_scanner import EnhancedBLEScanner
                    scanner = EnhancedBLEScanner()
                if hasattr(scanner, "initialize"):
                    scanner.initialize()

                scan_data = scanner.scan(duration=8)
                devices = scan_data.get("devices", [])
                error = scan_data.get("error")

                if error:
                    self.activity_log.append(f"[!] Scan error: {error}")
                if not devices:
                    if not error:
                        self.activity_log.append("[i] No BLE devices discovered.")
                    self.ble_devices = []
                    self.targets = []
                    return

                self.ble_devices = devices
                self.targets = list(devices)
                self.activity_log.append(f"[+] Found {len(self.ble_devices)} BLE devices:")
                for dev in self.ble_devices:
                    self.activity_log.append(
                        f"  · {dev.get('name')} [{dev.get('address')}] "
                        f"(RSSI: {dev.get('rssi')}dBm)"
                    )
                self._enter_targets_view()
            except Exception as e:
                logger.error(f"BLE scanner error: {e}")
                self.activity_log.append(f"[!] Scan error: {e}")
                self.ble_devices = []
                self.targets = []

        self._spawn(run_scan)

    # ------------------------------------------------------------------
    # Advanced actions
    # ------------------------------------------------------------------
    def plan_post_exploit(self):
        if not self.selected_device:
            self.activity_log.append("[!] Select a BLE device first.")
            return
        if not self.post_runner:
            self.activity_log.append("[!] Post-exploit runner unavailable.")
            return
        session_id = self.get_input("Live MSF session id (blank = plan only, no execution)")
        session = None
        if session_id and session_id.strip():
            session = {"id": session_id.strip(), "os": "linux", "type": "post"}
        self.activity_log.append("[*] Planning post-exploit (AI + KB)...")
        target = dict(self.selected_device)

        def run():
            plan = self.post_runner.plan("ble", target, session=session)
            self._post_plan = plan
            if plan.get("ai_plan"):
                self.activity_log.append("=== AI BLE Post-Exploit Plan ===")
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
        """Execute the last MSF plan, each step gated (default-deny)."""
        if not self.post_runner:
            self.activity_log.append("[!] Post-exploit runner unavailable.")
            return
        if not self._post_plan or not self._post_plan.get("msf_plan"):
            self.activity_log.append(
                "[!] No MSF plan to execute — run 'Post-Exploit Plan' first "
                "(requires a live session)."
            )
            return
        self.activity_log.append("[*] Executing MSF plan — each step prompts ACCEPT/CANCEL...")

        def run():
            results = self.post_runner.execute(self._post_plan)
            for r in results:
                self.activity_log.append(f"[i] step: {r}")

        self._spawn(run)

    def show_kb_tools(self):
        if not self.kb:
            self.activity_log.append("[!] KB unavailable.")
            return
        tools = self.kb.get_tools_for_domain("ble")
        self.activity_log.append(f"[+] KB BLE tools ({len(tools)}):")
        for t in tools[:15]:
            self.render_kb_tool(t)

    def pick_adapter(self):
        """Pick BLE adapter, power it on if needed, record adaptive plan."""
        try:
            import importlib
            # import_module honours sys.modules patches used by tests
            _ip = importlib.import_module("core.tui.interface_picker")
            pick_ble_interface = _ip.pick_ble_interface
        except Exception as e:
            self.activity_log.append(f"[!] interface picker unavailable: {e}")
            return
        iface = pick_ble_interface(self.stdscr, self.activity_log)
        if not iface:
            self.activity_log.append("[i] No adapter selected.")
            return
        self.interface = iface
        self.activity_log.append(f"[+] Selected BLE adapter: {iface}")
        # Stamp polymorphic power strategy for the chain (best-effort).
        try:
            from core.refactors.poly_adapt_companions import (
                adapt_ble_adapter_power_picker,
            )
            detect = getattr(_ip, "detect_ble_interfaces", None)
            ads = detect() if callable(detect) else []
            match = next((a for a in ads if a.get("name") == iface), {}) or {}
            plan = adapt_ble_adapter_power_picker({
                "powered": match.get("powered"),
                "note": match.get("note"),
                "name": iface,
                "address": match.get("address"),
            })
            data = (plan or {}).get("data") or {}
            self.activity_log.append(
                f"[i] BLE adapter plan: {data.get('pick')} — {data.get('rationale')}"
            )
        except Exception as e:
            self.activity_log.append(f"[i] BLE adapter plan skip: {e}")

    def connect_and_enumerate(self):
        """Real GATT enumeration via gatttool/bluetoothctl (no fake services)."""
        if not self.ble_devices:
            self.activity_log.append("[!] Please perform BLE scan first.")
            return

        addr = self.get_input("Enter BLE MAC Address to connect")
        if not addr:
            return

        matched = None
        for dev in self.ble_devices:
            if dev.get("address", "").lower() == addr.lower():
                matched = dev
                break
        if not matched:
            self.activity_log.append(f"[!] Device {addr} not found in scan results.")
            return

        self.selected_device = matched
        self.selected_target = matched
        self.activity_log.append(
            f"[*] Enumerating GATT on {matched.get('name')} ({addr})..."
        )

        def run():
            import shutil
            import subprocess
            try:
                if shutil.which("gatttool"):
                    out = subprocess.run(
                        ["gatttool", "-b", addr, "--characteristics"],
                        capture_output=True, text=True, timeout=10,
                    )
                    self.activity_log.append(
                        f"[i] gatttool rc={out.returncode} "
                        f"(stderr: {out.stderr.strip()[:120]})"
                    )
                    for line in out.stdout.splitlines()[:20]:
                        self.activity_log.append(f"  {line.strip()}")
                else:
                    self.activity_log.append(
                        "[!] gatttool not installed — install bluez to enumerate GATT."
                    )
            except Exception as e:
                self.activity_log.append(f"[!] GATT enum error: {e}")

        self._spawn(run)

    def run_ai_risk_assessment(self):
        """Invoke AI backend to analyze BLE targets for vulnerabilities"""
        device = self.selected_device
        if not device and self.ble_devices:
            device = self.ble_devices[0] # Fallback to first discovered device

        if not device:
            self.activity_log.append("[!] Run scan first to assess BLE devices.")
            return

        self.activity_log.append(f"[*] Performing AI Risk Assessment on BLE target: {device.get('name')}...")

        def run_ai():
            prompt = f"Assess the security profile and potential vulnerabilities of a BLE target device named '{device.get('name')}' by manufacturer '{device.get('company', 'Unknown')}', advertising services: {device.get('services')}. Suggest exploitation strategies."
            ai_assess = self.ai_backend.query("ble", prompt)

            self.activity_log.append("=== AI BLE Risk Profile ===")
            for line in ai_assess.split("\n"):
                if line.strip():
                    self.activity_log.append(line)

        self._spawn(run_ai)