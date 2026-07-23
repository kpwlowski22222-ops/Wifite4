#!/usr/bin/env python3
"""Unified EngagementEngine — single entry for simplified TUI domains.

Wraps AdaptiveEngagement with:
  * Holo OS-agent readiness / optional prep
  * Catalog + toolboxes + kali context for AI planners
  * Background 0-day propose → build → docker_sim thread
  * Bounded try-until-access cycles (never fabricate success)
  * Post-access RAT dashboard spawn hook

All offensive steps remain ACCEPT/CANCEL gated via the orchestrator.
"""
from __future__ import annotations

import logging
import os
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)

EmitFn = Callable[[str], None]

# Engagement system context injected into seeds for AI chain planners.
ENGAGEMENT_TOOL_CONTEXT = """
KFIOSA engagement context (authorized lab only):
- Prefer tools from toolboxes/ and catalog/github_*.json via run_toolbox / MCP.
- Prefer installed Kali binaries (airodump-ng, hashcat, nmap, bettercap, …)
  via mcp_call when present; never silent apt.
- Use poly_adapt / situational_pick before heavy steps.
- Use holo_desktop / desktop_nav when adapter, GUI, or OS prep is blocked.
- CVE lookup via get_nvd_key() only — never invent CVEs or PSKs.
- zero_day_docker_sim before any real 0-day execute path.
- Honest degrade: missing tool → skip + replan, never fake success.
""".strip()

DEFAULT_MAX_CYCLES = 8
HOLO_PREP_BY_DOMAIN = {
    "wifi": "wifi_monitor_help",
    "ble": "ble_long_range_prep",
    "osint": "engagement_tool_prep",
    "osint_people": "engagement_tool_prep",
    "osint_web": "engagement_tool_prep",
    "post_exploit": "post_access_browser_dashboard",
}


def _emit(on_event: Optional[EmitFn], msg: str) -> None:
    try:
        if on_event:
            on_event(msg)
    except Exception:  # noqa: BLE001
        pass
    logger.info(msg)


class EngagementEngine:
    """Single pipeline: recon → CVE → plan → attack → access → post.

    Parameters
    ----------
    orchestrator
        AutonomousOrchestrator (or duck-typed) with confirm_fn.
    catalog_recon_factory
        Optional ``target -> CatalogRecon`` for WiFi deep recon.
    on_event
        Activity-log callback.
    holo_bridge
        Optional HoloDesktopBridge; status is always probed.
    """

    def __init__(
        self,
        orchestrator: Any = None,
        *,
        catalog_recon_factory: Optional[Callable[[Dict[str, Any]], Any]] = None,
        on_event: Optional[EmitFn] = None,
        holo_bridge: Any = None,
        max_cycles: int = DEFAULT_MAX_CYCLES,
        until_access: bool = True,
        enable_bg_zero_day: bool = True,
        enable_holo_prep: bool = True,
    ) -> None:
        self.orch = orchestrator
        self.catalog_recon_factory = catalog_recon_factory
        self.on_event = on_event
        self.holo_bridge = holo_bridge
        self.max_cycles = max(1, int(max_cycles))
        self.until_access = until_access
        self.enable_bg_zero_day = enable_bg_zero_day
        self.enable_holo_prep = enable_holo_prep
        self._bg_threads: List[threading.Thread] = []

    def log(self, msg: str) -> None:
        _emit(self.on_event, msg)

    # ------------------------------------------------------------------
    # Public entry
    # ------------------------------------------------------------------
    def run(
        self,
        domain: str,
        target: Dict[str, Any],
        *,
        until_access: Optional[bool] = None,
        max_cycles: Optional[int] = None,
        attach_zero_day: bool = True,
        skip_holo_prep: bool = False,
    ) -> Dict[str, Any]:
        domain = (domain or "wifi").lower().strip()
        seed = dict(target or {})
        ua = self.until_access if until_access is None else bool(until_access)
        cycles = int(max_cycles or self.max_cycles)

        report: Dict[str, Any] = {
            "ok": True,
            "domain": domain,
            "engine": "EngagementEngine",
            "started": time.time(),
            "holo": None,
            "zero_day_bg": None,
            "adaptive": None,
            "access": {"achieved": False},
            "phases": [],
        }

        # 0) Enrich seed for AI planners (catalog/toolboxes/kali/holo)
        seed["engagement_context"] = ENGAGEMENT_TOOL_CONTEXT
        seed["use_ai_chain"] = True
        seed["polymorphic"] = True
        seed["target_adaptive"] = True
        seed["prefer_holo_when_blocked"] = True
        seed["attach_zero_day"] = bool(attach_zero_day)
        seed["attach_post_exploit"] = True
        seed["post_exploit"] = True
        seed["domain"] = domain
        seed.setdefault("anti_forensics", True)
        seed.setdefault("aio", True)
        # Holo preset hints for the chain planner / models
        seed.setdefault(
            "holo_presets",
            list(HOLO_PREP_BY_DOMAIN.values()) + [
                "wifi_scan_windows_layout",
                "engagement_tool_prep",
                "post_access_browser_dashboard",
                "ollama_list",
            ],
        )
        if domain in ("osint_people", "osint"):
            seed.setdefault("osint_mode", "people")
        if domain == "osint_web":
            seed.setdefault("osint_mode", "web")

        tgt_label = (
            seed.get("ssid") or seed.get("name") or seed.get("bssid")
            or seed.get("address") or seed.get("query") or seed.get("url")
            or "?"
        )
        # holaOS-inspired: workspace + memory recall for continuity
        try:
            from core.workspace.engagement_ws import create_workspace, append_decision
            from core.memory.recall import recall, target_key_from
            from core.memory.store import ingest, memory_enabled
            tkey = target_key_from(seed)
            if not seed.get("workspace_id"):
                ws = create_workspace(domain, seed, label=str(tgt_label))
                if ws.get("ok"):
                    seed["workspace_id"] = ws.get("id")
                    seed["workspace_path"] = ws.get("path")
                    self.log(
                        f"Note: engagement workspace ready at {ws.get('path')}"
                    )
            if memory_enabled():
                mem = recall(
                    str(tgt_label), domain=domain, target_key=tkey, limit=6,
                )
                if mem.get("count"):
                    seed["memory_context"] = mem.get("summary") or ""
                    seed["memory_hits"] = mem.get("hits") or []
                    self.log(
                        f"Remembered {mem.get('count')} note(s) about "
                        f"“{tgt_label}” — loading them into the plan."
                    )
                ingest(
                    "target",
                    f"Engagement start domain={domain} target={tgt_label}",
                    domain=domain, target_key=tkey, tags=["start"],
                )
                if seed.get("workspace_id"):
                    append_decision(
                        seed["workspace_id"],
                        f"start domain={domain} until_access={ua}",
                    )
        except Exception as e:
            self.log(f"[i] workspace/memory continuity skipped: {e}")

        # Friendly narrative + live polymorphic pick for this target
        try:
            from core.tui.narrative_log import step_begin, step_adapt, narrate
            self.log(step_begin(domain, seed))
        except Exception:
            self.log(
                f"[*] EngagementEngine domain={domain} until_access={ua} "
                f"max_cycles={cycles} target={tgt_label}"
            )
        try:
            from core.poly.live_adapt import react, poly_pre_step
            adapt = react(domain, seed, None)
            seed["live_adapt"] = adapt
            seed["poly_pre_step"] = poly_pre_step(domain, seed)
            try:
                from core.tui.narrative_log import step_adapt as _sa
                self.log(_sa(
                    adapt.get("rationale") or "target features scored",
                    adapt.get("method") or "adaptive recon",
                ))
            except Exception:
                self.log(
                    f"[poly] live_adapt → {adapt.get('method')}: "
                    f"{adapt.get('rationale')}"
                )
            if seed.get("workspace_id"):
                try:
                    from core.workspace.engagement_ws import append_decision
                    append_decision(
                        seed["workspace_id"],
                        f"live_adapt {adapt.get('method')}: {adapt.get('rationale')}",
                    )
                except Exception:
                    pass
        except Exception as e:
            self.log(f"[i] live_adapt skipped: {e}")

        # Detect blocked adapter/iface so Holo prep can fire when useful
        blocked = self._detect_adapter_blocked(domain, seed)
        if blocked:
            seed["adapter_blocked"] = True
            seed.setdefault("holo_prep", True)
            self.log(f"[holo] adapter/iface looks blocked — will try OS-agent prep")

        # 1) Holo readiness + optional prep
        holo_out = self._phase_holo(domain, seed, skip=skip_holo_prep)
        report["holo"] = holo_out
        report["phases"].append({"phase": "holo", **holo_out})

        # 2) Background 0-day generation (daemon thread — never blocks chain)
        if self.enable_bg_zero_day and attach_zero_day and domain in (
            "wifi", "ble", "osint_web",
        ):
            bg = self._start_bg_zero_day(seed, domain)
            report["zero_day_bg"] = bg
            report["phases"].append({"phase": "zero_day_bg_start", **bg})

        # 3) Domain dispatch
        if domain in ("wifi", "ble"):
            adaptive = self._run_adaptive(
                domain, seed, until_access=ua, max_cycles=cycles,
                attach_zero_day=attach_zero_day,
            )
            report["adaptive"] = adaptive
            report["access"] = (adaptive or {}).get("access") or report["access"]
            report["phases"].append({
                "phase": "adaptive",
                "ok": bool((adaptive or {}).get("ok")),
                "access": report["access"],
                "cycles": len((adaptive or {}).get("cycles") or []),
            })
            # Promote client post plans / RAT from adaptive report
            if isinstance(adaptive, dict):
                if adaptive.get("wifi_client_post"):
                    report["wifi_client_post"] = adaptive["wifi_client_post"]
                if adaptive.get("rat"):
                    report["rat"] = adaptive["rat"]
        elif domain in ("osint", "osint_people", "osint_web"):
            orep = self._run_osint(domain, seed)
            report["osint"] = orep
            report["phases"].append({"phase": "osint", **(orep or {})})
        elif domain in ("post_exploit", "post"):
            prep = self._run_post_exploit(seed)
            report["post_exploit"] = prep
            report["phases"].append({"phase": "post_exploit", **(prep or {})})
        else:
            report["ok"] = False
            report["error"] = f"unsupported domain {domain!r}"
            self.log(f"[!] {report['error']}")

        report["duration_s"] = round(time.time() - report["started"], 3)
        report["workspace_id"] = seed.get("workspace_id")
        access = report.get("access") or {}
        achieved = bool(access.get("achieved"))
        self.log(
            f"[*] EngagementEngine done ok={report.get('ok')} "
            f"access={achieved} "
            f"in {report['duration_s']}s"
        )
        # Persist continuity (memory + workspace findings)
        try:
            from core.memory.store import ingest
            from core.memory.recall import target_key_from
            from core.workspace.engagement_ws import (
                append_finding, set_next_steps, append_decision,
            )
            tkey = target_key_from(seed)
            summary = (
                f"Engagement finished domain={domain} access={achieved} "
                f"session={access.get('session_id') or '-'} "
                f"duration_s={report.get('duration_s')}"
            )
            ingest(
                "finding" if achieved else "lesson",
                summary,
                domain=domain, target_key=tkey,
                tags=["end", "access" if achieved else "no_access"],
            )
            wid = seed.get("workspace_id")
            if wid:
                append_finding(wid, summary)
                if achieved:
                    append_decision(wid, "access achieved — PE/dashboard path")
                    set_next_steps(wid, [
                        "post-exploit OPSEC",
                        "keep session / open Flask dashboard",
                        "export findings from workspace",
                    ])
                else:
                    set_next_steps(wid, [
                        "retry with different poly_adapt variant",
                        "verify adapter / monitor / BLE power",
                        "review findings.md for failed paths",
                    ])
        except Exception:
            pass
        return report

    # ------------------------------------------------------------------
    # Adapter / Holo helpers
    # ------------------------------------------------------------------
    def _detect_adapter_blocked(
        self, domain: str, seed: Dict[str, Any]
    ) -> bool:
        """Heuristic: iface missing, not monitor, or BLE adapter down.

        Never invents hardware state — only sysfs/iw/rfkill when available.
        Explicit seed flags win.
        """
        if seed.get("adapter_blocked") or seed.get("holo_prep"):
            return True
        if domain in ("wifi",):
            iface = (
                seed.get("interface") or seed.get("iface")
                or seed.get("monitor_iface") or ""
            )
            if not iface:
                return True
            try:
                from core.utils.airmon import _iw_is_monitor
                if not _iw_is_monitor(str(iface)):
                    # managed iface still usable for some steps but prep helps
                    return bool(seed.get("require_monitor", True))
            except Exception:  # noqa: BLE001
                # If we cannot probe, do not force holo
                return False
            # Check carrier / operstate when possible
            try:
                op = Path(f"/sys/class/net/{iface}/operstate")
                if op.is_file() and op.read_text().strip() in ("down", "dormant"):
                    return True
            except Exception:  # noqa: BLE001
                pass
            return False
        if domain in ("ble",):
            adapter = (
                seed.get("adapter") or seed.get("ble_adapter")
                or seed.get("hci") or seed.get("interface") or ""
            )
            if not adapter:
                # Try soft-block probe
                try:
                    import subprocess as sp
                    r = sp.run(
                        ["rfkill", "list", "bluetooth"],
                        capture_output=True, text=True, timeout=3,
                    )
                    blob = (r.stdout or "").lower()
                    if "soft blocked: yes" in blob or "hard blocked: yes" in blob:
                        return True
                except Exception:  # noqa: BLE001
                    pass
                return False
            return False
        return False

    # ------------------------------------------------------------------
    # Holo
    # ------------------------------------------------------------------
    def _phase_holo(
        self, domain: str, seed: Dict[str, Any], *, skip: bool
    ) -> Dict[str, Any]:
        out: Dict[str, Any] = {"ok": False, "status": None, "prep": None}
        try:
            from core.desktop.holo_agent import holo_status
            st = holo_status()
            out["status"] = {
                "ok": st.get("ok"),
                "holo_bin": st.get("holo_bin") or "",
                "version": (st.get("version") or "")[:80],
            }
            if st.get("ok"):
                self.log(f"[holo] ready bin={st.get('holo_bin')}")
                out["ok"] = True
            else:
                self.log(
                    "[holo] binary missing — continuing CLI path "
                    f"({(st.get('error') or 'not found')[:60]})"
                )
            seed["holo_status"] = out["status"]
            seed.setdefault("prefer_holo_when_blocked", True)
        except Exception as e:  # noqa: BLE001
            out["error"] = str(e)[:200]
            self.log(f"[holo] status probe failed: {e}")
            return out

        if skip or not self.enable_holo_prep:
            return out
        if not (out.get("status") or {}).get("ok"):
            return out

        # Auto-prep when adapter looks blocked / operator asked
        want = bool(seed.get("holo_prep") or seed.get("adapter_blocked"))
        if not want:
            return out

        preset = HOLO_PREP_BY_DOMAIN.get(domain) or "engagement_tool_prep"
        # Prefer dry-run unless operator set holo_execute=True (still ACCEPT-gated)
        dry = not bool(seed.get("holo_execute"))
        try:
            bridge = self.holo_bridge
            if bridge is None:
                from core.desktop.holo_agent import HoloDesktopBridge
                confirm = None
                if self.orch is not None:
                    confirm = getattr(self.orch, "confirm_fn", None)
                bridge = HoloDesktopBridge(confirm_fn=confirm)
            self.log(
                f"[holo] prep preset={preset} dry_run={dry} "
                f"(ACCEPT if live desktop control)"
            )
            if hasattr(bridge, "run"):
                prep = bridge.run(goal=preset, dry_run=dry)
            else:
                from core.desktop.holo_agent import run_holo_task, build_desktop_task
                prep = run_holo_task(
                    build_desktop_task(preset),
                    confirm_fn=getattr(self.orch, "confirm_fn", None),
                    dry_run=dry,
                )
            out["prep"] = {
                "preset": preset,
                "dry_run": dry,
                "ok": bool((prep or {}).get("ok")),
                "error": (prep or {}).get("error"),
            }
            if out["prep"]["ok"]:
                self.log(f"[holo] prep ok preset={preset}")
            else:
                self.log(
                    f"[holo] prep skipped/failed: "
                    f"{(out['prep'].get('error') or 'denied/unavailable')[:80]}"
                )
        except Exception as e:  # noqa: BLE001
            out["prep"] = {"ok": False, "error": str(e)[:200]}
            self.log(f"[holo] prep failed: {e}")
        return out

    # ------------------------------------------------------------------
    # Adaptive WiFi / BLE
    # ------------------------------------------------------------------
    def _run_adaptive(
        self,
        domain: str,
        seed: Dict[str, Any],
        *,
        until_access: bool,
        max_cycles: int,
        attach_zero_day: bool,
    ) -> Dict[str, Any]:
        if self.orch is None:
            self.log("[!] Orchestrator unavailable — cannot engage")
            return {"ok": False, "error": "orchestrator unavailable"}
        try:
            from core.orchestrator.adaptive_engagement import AdaptiveEngagement
            eng = AdaptiveEngagement(
                self.orch,
                catalog_recon_factory=self.catalog_recon_factory,
                on_event=self.on_event,
                until_access=until_access,
                max_cycles=max_cycles,
                enable_cve_code=True,
                enable_reverse_stubs=True,
            )
            return eng.run(
                domain, seed, attach_zero_day=attach_zero_day,
            )
        except Exception as e:  # noqa: BLE001
            self.log(f"[!] adaptive engagement error: {e}")
            return {"ok": False, "error": str(e)[:300]}

    # ------------------------------------------------------------------
    # OSINT
    # ------------------------------------------------------------------
    def _run_osint(self, domain: str, seed: Dict[str, Any]) -> Dict[str, Any]:
        if self.orch is None:
            return {"ok": False, "error": "orchestrator unavailable"}
        mode = seed.get("osint_mode") or (
            "people" if "people" in domain else "web"
        )
        query = (
            seed.get("query") or seed.get("target") or seed.get("value")
            or seed.get("name") or seed.get("url") or seed.get("domain") or ""
        )
        people_mode = seed.get("people_mode") or seed.get("web_mode") or ""
        self.log(f"[osint] mode={mode} sub={people_mode!r} query={str(query)[:80]!r}")

        # Prefer dedicated osint_runner methods when present (friendly TUI paths)
        runner = getattr(self.orch, "osint_runner", None)
        if runner is not None and mode == "people":
            try:
                rep = self._osint_people_runner(runner, str(query), people_mode)
                if rep is not None:
                    rep.setdefault("mode", mode)
                    return rep
            except Exception as e:  # noqa: BLE001
                self.log(f"[osint] people runner note: {e}")
        if runner is not None and mode == "web":
            try:
                rep = self._osint_web_runner(runner, str(query), people_mode)
                if rep is not None:
                    rep.setdefault("mode", mode)
                    return rep
            except Exception as e:  # noqa: BLE001
                self.log(f"[osint] web runner note: {e}")

        try:
            # Orchestrator domain=osint AI chain
            if hasattr(self.orch, "run"):
                t = dict(seed)
                t["domain"] = "osint"
                t["osint_mode"] = mode
                t.setdefault("target", query)
                t.setdefault("use_ai_chain", True)
                return self.orch.run("osint", t) or {"ok": True, "mode": mode}
        except TypeError:
            try:
                return self.orch.run(seed) or {"ok": True, "mode": mode}
            except Exception as e:  # noqa: BLE001
                return {"ok": False, "error": str(e)[:300], "mode": mode}
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "error": str(e)[:300], "mode": mode}

        if runner is None:
            return {
                "ok": False,
                "error": "no osint path on orchestrator",
                "mode": mode,
            }
        try:
            if hasattr(runner, "run_auto"):
                return runner.run_auto(str(query), mode=mode)
            if hasattr(runner, "plan"):
                return {"ok": True, "plan": runner.plan(str(query)), "mode": mode}
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "error": str(e)[:300], "mode": mode}
        return {"ok": False, "error": "osint runner has no run/plan", "mode": mode}

    def _osint_people_runner(
        self, runner: Any, query: str, people_mode: str
    ) -> Optional[Dict[str, Any]]:
        """Map friendly TUI modes onto real OSINTRunner methods when present."""
        pm = (people_mode or "find").lower()
        # Prefer explicit methods; never invent results
        method_map = {
            "email": ("run_email", "email_osint", "holehe"),
            "phone": ("run_phone", "phone_osint", "phone"),
            "find": ("run_username", "username_osint", "people_search", "run_auto"),
            "full_profile": ("run_auto", "people_profile", "run_people"),
        }
        names = method_map.get(pm) or method_map["find"]
        for name in names:
            fn = getattr(runner, name, None)
            if callable(fn):
                self.log(f"[osint] people via runner.{name}")
                try:
                    return fn(query) if name != "run_auto" else fn(query, mode="people")
                except TypeError:
                    try:
                        return fn(query)
                    except Exception:
                        continue
        return None

    def _osint_web_runner(
        self, runner: Any, query: str, web_mode: str
    ) -> Optional[Dict[str, Any]]:
        wm = (web_mode or "dork").lower()
        method_map = {
            "dork": ("run_dork", "dork", "run_auto"),
            "domain_recon": ("run_domain", "domain_osint", "run_auto"),
            "probe": ("probe_site", "run_probe", "run_auto"),
            "offensive_plan": ("plan_offensive", "run_auto"),
        }
        names = method_map.get(wm) or method_map["dork"]
        for name in names:
            fn = getattr(runner, name, None)
            if callable(fn):
                self.log(f"[osint] web via runner.{name}")
                try:
                    return fn(query) if name != "run_auto" else fn(query, mode="web")
                except TypeError:
                    try:
                        return fn(query)
                    except Exception:
                        continue
        return None

    # ------------------------------------------------------------------
    # Post-exploit
    # ------------------------------------------------------------------
    def _run_post_exploit(self, seed: Dict[str, Any]) -> Dict[str, Any]:
        runner = None
        if self.orch is not None:
            runner = getattr(self.orch, "post_exploit_runner", None) or getattr(
                self.orch, "msf_runner", None
            )
        if runner is None:
            return {"ok": False, "error": "post_exploit runner unavailable"}
        try:
            if hasattr(runner, "plan"):
                plan = runner.plan(seed)
                self.log(f"[post] plan ready keys={list((plan or {}).keys())[:8]}")
                return {"ok": True, "plan": plan}
            if hasattr(runner, "run"):
                return runner.run(seed) or {"ok": True}
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "error": str(e)[:300]}
        return {"ok": False, "error": "post runner has no plan/run"}

    # ------------------------------------------------------------------
    # Background 0-day
    # ------------------------------------------------------------------
    def _start_bg_zero_day(
        self, seed: Dict[str, Any], domain: str
    ) -> Dict[str, Any]:
        """Daemon thread: propose → build → docker_sim (skip real execute)."""
        if self.orch is None:
            return {"ok": False, "started": False, "error": "no orchestrator"}

        def _worker() -> None:
            try:
                self.log("[0day-bg] starting propose/build/docker_sim thread")
                proposer = getattr(self.orch, "zero_day_proposer", None)
                builder = getattr(self.orch, "zero_day_exploit_builder", None)
                draft = None
                if proposer is not None and hasattr(proposer, "propose"):
                    try:
                        draft = proposer.propose(seed)
                        self.log(
                            f"[0day-bg] propose ok={bool((draft or {}).get('ok'))}"
                        )
                    except Exception as e:  # noqa: BLE001
                        self.log(f"[0day-bg] propose: {e}")
                if builder is not None and hasattr(builder, "build"):
                    try:
                        built = builder.build(seed if draft is None else draft)
                        self.log(
                            f"[0day-bg] build ok={bool((built or {}).get('ok'))}"
                        )
                    except Exception as e:  # noqa: BLE001
                        self.log(f"[0day-bg] build: {e}")
                # Docker sim path (honest skip if unavailable)
                try:
                    from core.zero_day_sandbox import docker_sim
                    if hasattr(docker_sim, "run_sim"):
                        sim = docker_sim.run_sim(seed, skip_real=True)
                        self.log(
                            f"[0day-bg] docker_sim ok={bool((sim or {}).get('ok'))}"
                        )
                except Exception as e:  # noqa: BLE001
                    self.log(f"[0day-bg] docker_sim skip: {e}")
            except Exception as e:  # noqa: BLE001
                self.log(f"[0day-bg] worker error: {e}")

        t = threading.Thread(
            target=_worker,
            name=f"kfiosa-0day-bg-{domain}",
            daemon=True,
        )
        t.start()
        self._bg_threads.append(t)
        return {"ok": True, "started": True, "thread": t.name}


def run_engagement(
    domain: str,
    target: Dict[str, Any],
    *,
    orchestrator: Any = None,
    catalog_recon_factory: Any = None,
    on_event: Optional[EmitFn] = None,
    **kwargs: Any,
) -> Dict[str, Any]:
    """Module-level convenience wrapper."""
    eng = EngagementEngine(
        orchestrator,
        catalog_recon_factory=catalog_recon_factory,
        on_event=on_event,
    )
    return eng.run(domain, target, **kwargs)
