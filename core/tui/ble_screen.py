#!/usr/bin/env python3
"""
BLE Screen TUI
Bluetooth Low Energy scanner sub-menu (wifite-style primary flow + Advanced
submenu). Integrates long-range multi-backend BLE scanning (external live TUI
mirroring WiFi), and AI-assisted device risk assessment. All actions are
curses-free callable for pytest.
"""

import logging
import sys
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
        self.external_terminal = kwargs.get("external_terminal")
        self.tui_confirm = kwargs.get("tui_confirm")
        self.settings_manager = kwargs.get("settings_manager") or getattr(
            self, "settings_manager", None
        )

        self.ble_devices: List[Dict[str, Any]] = []
        self.selected_device = None
        self.interface = None  # BLE adapter — detected at runtime
        self._post_plan = None  # last computed post-exploit plan
        self._last_report = None
        self._no_external_load = False

        # ---- simplified primary flow (triple windows → engagement) ----
        self.primary_items = [
            ("Pick Bluetooth adapter", self.pick_adapter),
            ("Scan Devices (3 live windows UL/UR/BR)", self.scan_ble_devices),
            ("▶ Start engagement (selected device)", self.aio_attack),
            ("Show Report", self.show_report),
            ("Advanced…", self._show_advanced),
            ("Back", self.parent_callback),
        ]
        self.advanced_items = [
            ("Pick Bluetooth Adapter (auto-detect)", self.pick_adapter),
            ("OS Agent: long-range BLE prep (Holo CLI)", self.holo_ble_long_range_prep),
            ("OS Agent: open Bluetooth system settings", self.holo_ble_system_settings),
            ("OS Agent: diagnose BLE stack (dry-run OK)", self.holo_ble_adapter_help),
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
            f"({d.get('address')}) — Run All Attacks / AIO to engage."
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
    def adaptive_until_access(self):
        """BLE target-adaptive loop until access (bounded cycles)."""
        if not self.selected_device and not self._load_external_scan_selection():
            self.activity_log.append("[!] Select a BLE device first (Scan → number key).")
            return
        if not self.selected_device and self.selected_target:
            self.selected_device = self.selected_target
        if not self.orchestrator:
            self.activity_log.append("[!] Orchestrator unavailable.")
            return
        self._run_adaptive(until_access=True)

    def aio_attack(self):
        """AIO ATTACK: load external selection if needed, then adaptive until-access."""
        if not self.selected_device:
            self._load_external_scan_selection()
        if not self.selected_device and self.selected_target:
            self.selected_device = self.selected_target
        if not self.selected_device:
            self.activity_log.append(
                "[!] Select a BLE device first (Scan → ENTER/SPACE or number key)."
            )
            return
        if not self.orchestrator:
            self.activity_log.append("[!] Orchestrator unavailable.")
            return
        d = self.selected_device
        self.activity_log.append(
            f"[AIO] BLE adaptive until-access on {d.get('name')} "
            f"[{d.get('address')}] (ACCEPT/CANCEL gated)."
        )
        self._run_adaptive(until_access=True)

    def run_attack_chain(self):
        if not self.selected_device and not self._load_external_scan_selection():
            self.activity_log.append("[!] Select a BLE device first (Scan → number key).")
            return
        if not self.selected_device and self.selected_target:
            self.selected_device = self.selected_target
        if not self.orchestrator:
            self.activity_log.append("[!] Orchestrator unavailable.")
            return
        self._run_adaptive(until_access=False)

    def _run_adaptive(self, *, until_access: bool) -> None:
        target = dict(self.selected_device or self.selected_target or {})
        if self.interface:
            target.setdefault("adapter", self.interface)
            target.setdefault("ble_adapter", self.interface)
        target.setdefault("from_external_scan", True)
        target.setdefault("aio", True)
        target.setdefault("polymorphic", True)

        def run():
            try:
                from core.orchestrator.engagement_engine import EngagementEngine
                eng = EngagementEngine(
                    self.orchestrator,
                    catalog_recon_factory=None,
                    on_event=lambda m: self.activity_log.append(m),
                    until_access=until_access,
                    enable_bg_zero_day=True,
                    enable_holo_prep=True,
                )
                report = eng.run(
                    "ble", target,
                    until_access=until_access,
                    attach_zero_day=True,
                )
                self._last_report = report
                access = (report or {}).get("access") or {}
                if access.get("achieved"):
                    self.activity_log.append(
                        f"[+] BLE engagement ACCESS: session={access.get('session_id')}"
                    )
                else:
                    cycles = ((report or {}).get("adaptive") or {}).get("cycles") or []
                    self.activity_log.append(
                        f"[i] BLE engagement finished without access "
                        f"({len(cycles)} cycle(s))"
                    )
            except Exception as e:
                self.activity_log.append(f"[!] engagement engine error: {e}")

        self._spawn(run)

    def _load_external_scan_selection(self) -> bool:
        """Load target written by ``ble_scan_external`` if present."""
        if getattr(self, "_no_external_load", False):
            return False
        from pathlib import Path
        import json
        path = Path("logs") / "ble_scan_selection.json"
        if not path.is_file():
            return False
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return False
        sel = data.get("selected")
        if not isinstance(sel, dict) or not sel.get("address"):
            return False
        self.selected_target = sel
        self.selected_device = sel
        devices = data.get("devices") or data.get("networks") or []
        if devices:
            self.ble_devices = list(devices)
            self.targets = list(devices)
        self.activity_log.append(
            f"[+] Loaded external BLE selection: {sel.get('name')} "
            f"[{sel.get('address')}] aio={bool(data.get('aio_attack'))}"
        )
        return True

    def scan_ble_devices(self):
        """Open external live long-range BLE scan TUI (like WiFi), then load
        selection. Tests inject ``scanner_cls`` → hermetic in-process path."""
        # Tests: injected scanner_cls → hermetic in-process path
        if self.scanner_cls is not None:
            return self._scan_ble_inprocess()

        # Best-effort auto-pick adapter when none selected
        if not getattr(self, "interface", None):
            try:
                from core.ble.adapter_select import resolve_default_adapter
                self.interface = resolve_default_adapter()
                if self.interface:
                    self.activity_log.append(
                        f"[+] Auto-selected BLE adapter: {self.interface}"
                    )
            except Exception:
                pass

        out_path = "logs/ble_scan_selection.json"
        try:
            from pathlib import Path
            Path("logs").mkdir(parents=True, exist_ok=True)
            p = Path(out_path)
            if p.is_file():
                p.unlink()
        except Exception:
            pass

        # Prefer triple external windows: UL=online, UR=detail, BR=offline.
        try:
            from core.tui import ble_scan_bus as scan_bus
            from core.utils.external_terminal import get_scan_font_scale
            sm = getattr(self, "settings_manager", None)
            trip = scan_bus.launch_triple_ble_windows(
                self.interface,
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
                    f"[+] Triple BLE windows (adapter={self.interface or 'auto'}) "
                    f"{n_ok}/3 bus={bus_dir}"
                )
                self.activity_log.append(
                    "[*] UL: devices live ↑↓ ENTER/SPACE · "
                    "UR: detail · BR: offline + timestamps · Ctrl+C quit"
                )

                def _wait_triple():
                    import json
                    from pathlib import Path
                    sel = scan_bus.wait_for_selection(
                        Path(bus_dir), timeout_s=600.0
                    )
                    if not sel:
                        self.activity_log.append(
                            "[i] No BLE device selected (quit/timeout)."
                        )
                        return
                    sel = dict(sel)
                    sel["from_external_scan"] = True
                    if self.interface:
                        sel.setdefault("adapter", self.interface)
                    self.selected_device = sel
                    self.selected_target = sel
                    try:
                        Path("logs").mkdir(parents=True, exist_ok=True)
                        Path(out_path).write_text(
                            json.dumps({
                                "selected": sel,
                                "aio_attack": True,
                                "devices": [sel],
                                "ts": __import__("time").time(),
                            }, ensure_ascii=False, default=str),
                            encoding="utf-8",
                        )
                    except Exception:
                        pass
                    self.activity_log.append(
                        f"[+] Selected BLE: {sel.get('name')} "
                        f"[{sel.get('address')}] — starting engagement"
                    )
                    self.aio_attack()

                self._spawn(_wait_triple)
                return
        except Exception as e:
            self.activity_log.append(f"[i] Triple BLE launch: {e}")

        from core.utils.external_terminal import get_scan_font_scale
        cmd_argv = [
            sys.executable, "-m", "core.tui.ble_scan_external",
            "--out", out_path,
            "--seconds", "40",
            "--pulse", "12",
            "--long-range",
        ]
        if self.interface:
            cmd_argv += ["--adapter", str(self.interface)]
        log_path = "logs/steps/ble_scan_external.log"
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
                        title=f"KFIOSA BLE Scan — {self.interface or 'auto'}",
                        font_scale=get_scan_font_scale(sm),
                        position="topleft",
                    )
                    launched = True
            except Exception as e:
                self.activity_log.append(f"[i] External terminal launch: {e}")

        if launched:
            self.activity_log.append(
                f"[+] External BLE scan window opened "
                f"(adapter={self.interface or 'auto'}). "
                "Use ↑↓, SPACE/ENTER to select, A for AIO engagement, q when done."
            )

            def _wait_selection():
                import time
                from pathlib import Path
                deadline = time.time() + 300
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
            "[i] No external terminal — falling back to in-dashboard long-range scan."
        )
        self._scan_ble_inprocess()

    def _scan_ble_inprocess(self):
        """In-dashboard long-range scan (also used by pytest via scanner_cls)."""
        self.activity_log.append(
            "[*] Scanning for local Bluetooth Low Energy devices "
            "(long-range multi-backend)..."
        )

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

                try:
                    from core.scanners.scan_limits import ble_scan_s
                    _ble_s = ble_scan_s(None)
                except Exception:
                    _ble_s = 300
                self.activity_log.append(
                    f"[*] Long-range BLE scan ({_ble_s}s; "
                    f"override KFIOSA_BLE_SCAN_S)..."
                )
                scan_data = scanner.scan(
                    duration=_ble_s, adapter=self.interface
                )
                devices = scan_data.get("devices", [])
                error = scan_data.get("error")
                backend = scan_data.get("backend")
                if backend:
                    self.activity_log.append(f"[i] Scan backend: {backend}")
                if scan_data.get("prep_notes"):
                    for n in (scan_data.get("prep_notes") or [])[:4]:
                        self.activity_log.append(f"[i] prep: {n}")

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
                self.activity_log.append(
                    f"[+] Found {len(self.ble_devices)} BLE devices:"
                )
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

    def _run_holo_goal(self, goal: str, *, dry_run_default: bool = False) -> None:
        """Drive or dry-run the OS agentic CLI (holo-desktop-cli)."""
        # Prefer dry-run when holo is missing so Advanced menu stays useful.
        try:
            from core.desktop.holo_agent import HoloDesktopBridge, holo_status
        except Exception as e:
            self.activity_log.append(f"[!] holo bridge unavailable: {e}")
            return
        st = holo_status()
        dry = dry_run_default or not st.get("ok")
        if dry and not st.get("ok"):
            self.activity_log.append(
                "[i] holo binary not found — dry-run only. "
                "Install: pip install holo-desktop-cli  "
                "or: python main.py --cli holo status"
            )
        confirm = None
        if not dry:
            # Use orchestrator/TUI confirm when available
            tc = getattr(self, "tui_confirm", None) or getattr(
                self, "orchestrator", None
            )
            if tc is not None and hasattr(tc, "confirm"):
                confirm = tc.confirm
            elif callable(getattr(self, "tui_confirm", None)):
                confirm = self.tui_confirm
            else:
                # Fallback: prompt via get_input
                ans = self.get_input(
                    f"ACCEPT Holo desktop control for {goal}? [y/N]"
                ).strip().lower()
                confirm = lambda _p, a=ans: a in ("y", "yes")

        self.activity_log.append(
            f"[*] OS agent goal={goal!r} dry_run={dry}…"
        )

        def run():
            try:
                # Dry-run paths must never use an auto-ACCEPT gate. Pass the
                # real gate only when we are actually going to execute.
                if dry:
                    assert dry is True, "dry_run must be True for default-deny gate"
                    holo_confirm_fn = lambda _p: False
                else:
                    holo_confirm_fn = confirm
                bridge = HoloDesktopBridge(
                    confirm_fn=holo_confirm_fn,
                    settings=getattr(self, "settings_manager", None),
                )
                result = bridge.run(goal=goal, dry_run=dry)
                ok = bool(result.get("ok"))
                self.activity_log.append(
                    f"[{'+' if ok else '!'}] holo {goal}: ok={ok}"
                )
                if result.get("error"):
                    self.activity_log.append(f"[!] {result['error'][:160]}")
                if result.get("cmd"):
                    self.activity_log.append(f"[i] cmd: {result['cmd']}")
                if result.get("stdout"):
                    for line in str(result["stdout"]).splitlines()[:8]:
                        if line.strip():
                            self.activity_log.append(f"  {line[:120]}")
            except Exception as e:
                self.activity_log.append(f"[!] holo error: {e}")

        self._spawn(run)

    def holo_ble_long_range_prep(self):
        """OS agent: unblock + power + LE prep for max BLE range."""
        self._run_holo_goal("ble_long_range_prep")

    def holo_ble_system_settings(self):
        """OS agent: open desktop Bluetooth settings panel."""
        self._run_holo_goal("ble_system_settings")

    def holo_ble_adapter_help(self):
        """OS agent: diagnose BLE adapters (dry-run if holo missing)."""
        self._run_holo_goal("ble_adapter_help", dry_run_default=False)

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
            device = self.ble_devices[0]  # Fallback to first discovered device

        if not device:
            self.activity_log.append("[!] Run scan first to assess BLE devices.")
            return

        self.activity_log.append(
            f"[*] Performing AI Risk Assessment on BLE target: {device.get('name')}..."
        )

        def run_ai():
            prompt = (
                f"Assess the security profile and potential vulnerabilities of a BLE "
                f"target device named '{device.get('name')}' by manufacturer "
                f"'{device.get('company') or device.get('vendor') or 'Unknown'}', "
                f"advertising services: {device.get('services')}. "
                f"Suggest exploitation strategies."
            )
            ai_assess = self.ai_backend.query("ble", prompt)

            self.activity_log.append("=== AI BLE Risk Profile ===")
            for line in ai_assess.split("\n"):
                if line.strip():
                    self.activity_log.append(line)

        self._spawn(run_ai)
