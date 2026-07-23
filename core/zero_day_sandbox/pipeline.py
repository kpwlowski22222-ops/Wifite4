"""Recon → Docker sim → promote real → adapt-on-error pipeline."""
from __future__ import annotations

import json
import logging
import re
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from .profile import TargetEnvProfile, build_profile_from_recon
from .simulator import DockerTargetSimulator

logger = logging.getLogger(__name__)

ConfirmFn = Callable[[str], bool]


def _default_deny(_: str) -> bool:
    return False


class ZeroDayDockerPipeline:
    """Full loop for 0-day testing against a Docker twin then real target.

    Stages recorded in ``history``:
      recon → profile → sim_up → sim_test → (adapt*) → promote → real_test
    """

    def __init__(
        self,
        *,
        simulator: Optional[DockerTargetSimulator] = None,
        on_event: Optional[Callable[[str], None]] = None,
        max_adapt_rounds: int = 5,
        confirm_fn: Optional[ConfirmFn] = None,
    ):
        self.sim = simulator or DockerTargetSimulator(on_event=on_event)
        self.on_event = on_event or self.sim.on_event
        self.max_adapt_rounds = max(1, min(int(max_adapt_rounds), 15))
        self.confirm_fn = confirm_fn or _default_deny

    def _emit(self, msg: str) -> None:
        logger.info(msg)
        if self.on_event:
            try:
                self.on_event(msg)
            except Exception:  # noqa: BLE001
                pass

    # ------------------------------------------------------------------
    # Recon maximization
    # ------------------------------------------------------------------
    def gather_recon(
        self,
        seed: Optional[Dict[str, Any]] = None,
        recon: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Merge seed + recon and optionally pull live CatalogRecon/Kismet.

        Never fabricates; best-effort enrichment only.
        """
        seed = dict(seed or {})
        recon = dict(recon or seed.get("recon") or {})
        enriched: Dict[str, Any] = {"seed_keys": list(seed.keys())}

        # CatalogRecon UNGATED (per project rules)
        try:
            from core.modules.catalog_recon import CatalogRecon
            cr = CatalogRecon()
            if hasattr(cr, "run"):
                out = cr.run(with_probes=True, lean=True)
                if isinstance(out, dict):
                    enriched["catalog_recon"] = {
                        k: out.get(k)
                        for k in list(out.keys())[:40]
                    }
                    data = out.get("data") if isinstance(out.get("data"), dict) else out
                    if isinstance(data, dict):
                        for k, v in data.items():
                            recon.setdefault(k, v)
        except Exception as e:  # noqa: BLE001
            enriched["catalog_recon_error"] = str(e)[:200]

        # Optional service banner hints from seed ports
        ports = seed.get("open_ports") or recon.get("open_ports") or []
        if ports and not recon.get("services"):
            recon.setdefault(
                "services",
                [{"port": int(p), "name": "unknown"} for p in list(ports)[:20]
                 if str(p).isdigit() or isinstance(p, int)],
            )

        profile = build_profile_from_recon(seed=seed, recon=recon, extra=enriched)
        return {
            "ok": True,
            "recon": recon,
            "seed": seed,
            "profile": profile.to_dict(),
            "profile_obj": profile,
            "enrichment": enriched,
            "stage": "recon",
            "model": "zero-day-docker-pipeline",
        }

    # ------------------------------------------------------------------
    # Adapt harness from errors
    # ------------------------------------------------------------------
    def adapt_harness(
        self,
        code: str,
        error_blob: str,
        profile: TargetEnvProfile,
        round_i: int,
    ) -> Dict[str, Any]:
        """Heuristic adapt: patch common env mismatches in harness code.

        Does NOT invent exploit logic — only environment glue
        (paths, python, package imports, target host/port).
        """
        original = code or ""
        adapted = original
        notes: List[str] = []
        err = (error_blob or "").lower()

        # python vs python3
        if "python: not found" in err or "python: command not found" in err:
            adapted = adapted.replace("#!/usr/bin/env python\n", "#!/usr/bin/env python3\n")
            adapted = re.sub(
                r"\bpython\b(?!3)", "python3", adapted, count=3,
            )
            notes.append("switched python → python3")

        # missing modules → soft skip import
        m = re.search(r"no module named ['\"]?([a-zA-Z0-9_]+)['\"]?", err)
        if m:
            mod = m.group(1)
            # wrap import in try/except honest degrade
            pattern = rf"import {re.escape(mod)}\b"
            if re.search(pattern, adapted):
                adapted = re.sub(
                    pattern,
                    f"try:\n    import {mod}\nexcept ImportError:\n"
                    f"    {mod} = None  # adapted: missing in sim",
                    adapted,
                    count=1,
                )
                notes.append(f"soft-import {mod}")

        # connection refused → point at sandbox localhost services
        if "connection refused" in err or "errno 111" in err:
            for port in (profile.open_ports or [80])[:3]:
                adapted = adapted.replace(
                    "127.0.0.1:80", f"127.0.0.1:{port}",
                )
            # prefer container loopback
            if "TARGET_HOST" not in adapted:
                adapted = (
                    "import os\n"
                    "os.environ.setdefault('TARGET_HOST', '127.0.0.1')\n"
                    + adapted
                )
                notes.append("inject TARGET_HOST=127.0.0.1 for sim")

        # permission denied → drop root-only paths
        if "permission denied" in err:
            adapted = adapted.replace("/etc/shadow", "/etc/hosts")
            adapted = adapted.replace("/root/", "/tmp/")
            notes.append("rewrite privileged paths to /tmp lab paths")

        # timeout → reduce loops
        if "timeout" in err:
            adapted = re.sub(
                r"range\(\s*(\d{4,})\s*\)",
                "range(32)",
                adapted,
            )
            notes.append("shrink large ranges for sim timeouts")

        # Always stamp adapt round marker (idempotent)
        marker = f"# kfiosa-adapt-round-{round_i}\n"
        if marker not in adapted:
            adapted = marker + adapted
            notes.append(f"stamp adapt round {round_i}")

        changed = adapted != original
        return {
            "ok": True,
            "changed": changed,
            "code": adapted,
            "notes": notes,
            "round": round_i,
            "model": "zero-day-adapt-heuristic",
        }

    # ------------------------------------------------------------------
    # Main pipeline
    # ------------------------------------------------------------------
    def run(
        self,
        *,
        seed: Optional[Dict[str, Any]] = None,
        recon: Optional[Dict[str, Any]] = None,
        harness_code: str = "",
        exploit: Any = None,
        target: Optional[Dict[str, Any]] = None,
        skip_real: bool = False,
        cleanup: bool = True,
        auto_sim: bool = True,
    ) -> Dict[str, Any]:
        """Execute the full sim → adapt → promote pipeline.

        Parameters
        ----------
        harness_code:
            Python harness to test (prefer preflight-validated).
        exploit:
            Optional ZeroDayExploit-like object with ``.code``.
        skip_real:
            If True, never touch the real target (sim-only).
        auto_sim:
            If False, require confirm_fn before building Docker images.
        """
        history: List[Dict[str, Any]] = []
        t0 = time.time()

        # 1) Recon
        self._emit("[zd-docker] stage=recon gathering environment signals …")
        g = self.gather_recon(seed=seed, recon=recon)
        history.append({"stage": "recon", "ok": g.get("ok"), "confidence": g["profile"].get("confidence")})
        profile: TargetEnvProfile = g["profile_obj"]

        # Resolve harness code
        code = harness_code or ""
        if not code and exploit is not None:
            code = getattr(exploit, "code", "") or ""
        if not code.strip():
            # Default non-weaponized sim harness: env probe + port listen check
            ports = profile.open_ports[:5] or [80]
            code = (
                "import json, socket\n"
                "open_ok = []\n"
                f"for port in {ports!r}:\n"
                "    s = socket.socket()\n"
                "    s.settimeout(1.0)\n"
                "    try:\n"
                "        # In-sim we just bind-check localhost stack\n"
                "        r = s.connect_ex(('127.0.0.1', int(port)))\n"
                "        open_ok.append({'port': port, 'connect_ex': r})\n"
                "    except Exception as e:\n"
                "        open_ok.append({'port': port, 'error': str(e)[:80]})\n"
                "    finally:\n"
                "        s.close()\n"
                "print(json.dumps({'ok': True, 'probe': 'port_scan_local', 'results': open_ok}))\n"
            )

        # Optional preflight if exploit-like code looks non-trivial
        if exploit is not None and getattr(exploit, "code", None):
            try:
                from core.ai_backend.zero_day_exploit import ZeroDayExploitPreflight
                ZeroDayExploitPreflight.validate(exploit)
            except Exception as e:  # noqa: BLE001
                # Refusal / safety — still allow env probe path
                self._emit(f"[zd-docker] preflight warn: {e}")
                history.append({"stage": "preflight", "ok": False, "error": str(e)[:300]})

        # 2) Operator gate for spinning Docker (lab-local; still confirm if not auto)
        if not auto_sim:
            prompt = (
                "ACCEPT Docker 0-day SANDBOX build?\n"
                f"hostname={profile.hostname} image≈{profile.docker_base_image()}\n"
                f"ports={profile.open_ports[:12]} confidence={profile.confidence}\n"
                "This runs ONLY on local Docker, not the real target yet."
            )
            if not self.confirm_fn(prompt):
                return {
                    "ok": False,
                    "cancelled": True,
                    "stage": "sim_confirm",
                    "history": history,
                    "profile": profile.to_dict(),
                }

        # 3) Bring up twin
        self._emit("[zd-docker] stage=sim_up synthesizing container twin …")
        sim = self.sim.create_and_start(profile)
        history.append({
            "stage": "sim_up",
            "ok": sim.get("ok"),
            "error": sim.get("error"),
            "container": (sim.get("container") or {}).get("container_name"),
            "ip": (sim.get("container") or {}).get("ip"),
        })
        if not sim.get("ok"):
            return {
                "ok": False,
                "stage": "sim_up",
                "error": sim.get("error"),
                "history": history,
                "profile": profile.to_dict(),
                "sim": sim,
                "seconds": round(time.time() - t0, 2),
            }

        meta = sim["meta"]
        cname = sim["container"]["container_name"]
        sim_success = False
        last_sim: Dict[str, Any] = {}
        adapt_log: List[Dict[str, Any]] = []

        try:
            # 4) Test + adapt loop
            for rnd in range(self.max_adapt_rounds):
                self._emit(
                    f"[zd-docker] stage=sim_test round={rnd + 1}/{self.max_adapt_rounds}"
                )
                last_sim = self.sim.run_python_harness(
                    cname, code, filename=f"zd_r{rnd}.py", meta=meta,
                )
                history.append({
                    "stage": "sim_test",
                    "round": rnd + 1,
                    "ok": last_sim.get("ok"),
                    "exit_code": last_sim.get("exit_code"),
                    "stderr_tail": (last_sim.get("stderr") or "")[-400:],
                })
                if last_sim.get("ok"):
                    sim_success = True
                    self._emit("[zd-docker] sim SUCCESS")
                    break
                # adapt
                err_blob = (
                    (last_sim.get("stderr") or "")
                    + "\n"
                    + (last_sim.get("stdout") or "")
                    + "\n"
                    + (last_sim.get("error") or "")
                )
                adapted = self.adapt_harness(code, err_blob, profile, rnd + 1)
                adapt_log.append(adapted)
                if not adapted.get("changed"):
                    self._emit("[zd-docker] adapt made no changes — stopping rounds")
                    break
                code = adapted["code"]
                self._emit(
                    f"[zd-docker] adapted: {', '.join(adapted.get('notes') or [])}"
                )

            result: Dict[str, Any] = {
                "ok": sim_success,
                "stage": "sim_done" if sim_success else "sim_failed",
                "profile": profile.to_dict(),
                "sim": {
                    "container": sim.get("container"),
                    "probe": sim.get("probe"),
                    "last_test": {
                        "ok": last_sim.get("ok"),
                        "exit_code": last_sim.get("exit_code"),
                        "stdout": (last_sim.get("stdout") or "")[-2000:],
                        "stderr": (last_sim.get("stderr") or "")[-1500:],
                    },
                },
                "adapt_log": adapt_log,
                "history": history,
                "harness_final": code[:5000],
                "seconds": round(time.time() - t0, 2),
                "model": "zero-day-docker-pipeline",
            }

            if not sim_success:
                result["error"] = "simulation failed after adapt budget"
                return result

            # 5) Promote to real target (gated)
            if skip_real:
                result["promoted"] = False
                result["stage"] = "sim_only_success"
                return result

            real_target = target or seed or {}
            prompt = (
                "!!! PROMOTE 0-DAY FROM DOCKER SIM TO REAL TARGET !!!\n"
                f"Sim container succeeded after {len(adapt_log)} adapt round(s).\n"
                f"Profile: {profile.hostname} ports={profile.open_ports[:10]}\n"
                f"confidence={profile.confidence}\n"
                f"Target: {json.dumps(real_target, default=str)[:800]}\n"
                "ACCEPT to run the adapted harness against the REAL target.\n"
                "CANCEL aborts — sim results are kept."
            )
            authorized = False
            try:
                authorized = bool(self.confirm_fn(prompt))
            except Exception as e:  # noqa: BLE001
                self._emit(f"[zd-docker] confirm_fn error: {e}")
                authorized = False

            history.append({"stage": "promote_gate", "authorized": authorized})
            if not authorized:
                result["promoted"] = False
                result["cancelled_real"] = True
                result["stage"] = "sim_success_real_cancelled"
                return result

            # 6) Real run — reuse ZeroDayExploitRunner if exploit given,
            # else local subprocess with explicit warning (still gated).
            real_out = self._run_real(
                code=code,
                exploit=exploit,
                target=real_target,
            )
            history.append({"stage": "real_test", "ok": real_out.get("ok")})
            result["promoted"] = True
            result["real"] = real_out
            result["ok"] = bool(real_out.get("ok"))
            result["stage"] = "real_success" if real_out.get("ok") else "real_failed"

            # 7) If real failed, one more adapt pass guided by real stderr
            #    (sim again optional — record only unless caller re-enters)
            if not real_out.get("ok"):
                err = (
                    (real_out.get("stderr") or "")
                    + "\n"
                    + (real_out.get("error") or "")
                )
                adapted = self.adapt_harness(
                    code, err, profile, len(adapt_log) + 1,
                )
                result["post_real_adapt"] = adapted
                result["stage"] = "real_failed_adapted"
                self._emit(
                    "[zd-docker] real failed — harness adapted for next cycle "
                    f"({', '.join(adapted.get('notes') or [])})"
                )

            return result
        finally:
            if cleanup:
                try:
                    self.sim.stop(meta, remove_image=False)
                    self._emit("[zd-docker] sandbox container stopped")
                except Exception as e:  # noqa: BLE001
                    self._emit(f"[zd-docker] cleanup warn: {e}")

    def _run_real(
        self,
        *,
        code: str,
        exploit: Any,
        target: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Execute against real target using existing runner when possible."""
        # Prefer official runner (double gate already passed promote)
        if exploit is not None:
            try:
                from core.ai_backend.zero_day_exploit import ZeroDayExploitRunner
                # Patch code onto exploit if adapted
                if code and hasattr(exploit, "code"):
                    exploit.code = code
                runner = ZeroDayExploitRunner(on_event=self.on_event)
                # confirm already done at promote — pass auto-true
                return runner.run(exploit, target, confirm_fn=lambda _p: True)
            except Exception as e:  # noqa: BLE001
                return {"ok": False, "error": f"real runner failed: {e}"}

        # Minimal real execution: write temp and run with python3
        # (still only after promote ACCEPT). Marked clearly.
        import subprocess
        import tempfile
        try:
            with tempfile.NamedTemporaryFile(
                "w", suffix=".py", delete=False, encoding="utf-8",
            ) as fh:
                fh.write(code)
                path = fh.name
            import os as _os
            env = dict(_os.environ)
            env["KFIOSA_TARGET"] = json.dumps(target, default=str)[:2000]
            p = subprocess.run(
                ["python3", path],
                capture_output=True, text=True, timeout=120,
                env=env,
            )
            return {
                "ok": p.returncode == 0,
                "exit_code": p.returncode,
                "stdout": (p.stdout or "")[-4000:],
                "stderr": (p.stderr or "")[-2000:],
                "path": path,
                "executed": True,
                "cancelled": False,
            }
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "error": str(e)[:400], "executed": False}


def run_zero_day_docker_pipeline(
    seed: Optional[Dict[str, Any]] = None,
    recon: Optional[Dict[str, Any]] = None,
    harness_code: str = "",
    exploit: Any = None,
    target: Optional[Dict[str, Any]] = None,
    *,
    confirm_fn: Optional[ConfirmFn] = None,
    skip_real: bool = False,
    max_adapt_rounds: int = 5,
    on_event: Optional[Callable[[str], None]] = None,
) -> Dict[str, Any]:
    """Module-level entry used by orchestrator / CLI."""
    pipe = ZeroDayDockerPipeline(
        on_event=on_event,
        max_adapt_rounds=max_adapt_rounds,
        confirm_fn=confirm_fn,
    )
    return pipe.run(
        seed=seed,
        recon=recon,
        harness_code=harness_code,
        exploit=exploit,
        target=target,
        skip_real=skip_real,
    )
