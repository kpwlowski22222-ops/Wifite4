"""Learn session: simulate targets → poly plans → SFT data → fine-tune → MemOS."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from core.learn.domains import LEARN_MODES, get_mode
from core.learn.simulate import simulate_batch

Emit = Optional[Callable[[str], None]]
ROOT = Path(__file__).resolve().parents[2]


def _emit(cb: Emit, msg: str) -> None:
    if cb:
        try:
            cb(msg)
        except Exception:
            pass


def learn_data_dir(mode_key: str) -> Path:
    return ROOT / "data" / "finetune" / "learn" / mode_key


def adapter_registry_path() -> Path:
    return ROOT / "models" / "finetuned" / "learn_adapters.json"


def _load_registry() -> Dict[str, Any]:
    p = adapter_registry_path()
    if not p.is_file():
        return {"adapters": {}, "updated_at": 0}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return {"adapters": {}, "updated_at": 0}


def _save_registry(reg: Dict[str, Any]) -> None:
    p = adapter_registry_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    reg["updated_at"] = time.time()
    p.write_text(json.dumps(reg, indent=2, default=str), encoding="utf-8")


def plan_for_target(
    mode: Dict[str, Any],
    target: Dict[str, Any],
    *,
    ai_backend: Any = None,
    on_event: Emit = None,
) -> Dict[str, Any]:
    """Generate an offensive/recon plan for a simulated target."""
    domain = mode.get("domain") or "wifi"
    # Live poly pre-pick
    poly_pick: Dict[str, Any] = {}
    try:
        from core.poly.live_adapt import react
        poly_pick = react(domain, target, None)
        target = dict(target)
        target["poly_pre"] = poly_pick
        if domain == "wifi":
            try:
                from core.poly.offensive_inject import pick_inject_mode
                target["inject_pick"] = pick_inject_mode(target)
            except Exception:
                pass
    except Exception as e:
        poly_pick = {"error": str(e)[:80]}

    steps: List[Dict[str, Any]] = []
    source = "none"
    force_heur = (os.environ.get("KFIOSA_LEARN_HEURISTIC") or "").strip().lower() in (
        "1", "true", "yes", "on",
    )
    # Skip multi-model LLM ladder when no backend (tests / offline)
    if ai_backend is None or force_heur:
        try:
            from core.ai_backend.chain import _heuristic_for_domain
            steps = _heuristic_for_domain(domain, target) or []
            source = "heuristic"
        except Exception as e2:
            steps = [{
                "action": "parse",
                "tool": "operator_manual",
                "args": {"domain": domain, "target": target},
                "rationale": f"fallback: {e2}",
            }]
            source = "fallback"
    else:
        try:
            from core.ai_backend.chain import AIChainPlanner
            planner = AIChainPlanner(
                ai_backend=ai_backend,
                on_event=on_event,
            )
            steps = planner.plan(domain, target) or []
            source = "ai_chain_planner"
        except Exception as e:
            _emit(on_event, f"[learn] planner failed: {e} — heuristic poly plan")
            try:
                from core.ai_backend.chain import _heuristic_for_domain
                steps = _heuristic_for_domain(domain, target) or []
                source = "heuristic"
            except Exception as e2:
                steps = [{
                    "action": "parse",
                    "tool": "operator_manual",
                    "args": {"domain": domain, "target": target},
                    "rationale": f"fallback: {e2}",
                }]
                source = "fallback"

    # Narrative goal string for SFT
    plan_text = {
        "goal": mode.get("goal"),
        "domain": domain,
        "phase": mode.get("phase"),
        "poly": poly_pick,
        "steps": [
            {
                "action": s.get("action"),
                "tool": s.get("tool"),
                "args": s.get("args") or {},
                "rationale": s.get("rationale") or "",
                "risk_level": s.get("risk_level") or s.get("risk") or "",
            }
            for s in (steps or [])[:24]
            if isinstance(s, dict)
        ],
    }
    return {
        "ok": True,
        "source": source,
        "n_steps": len(plan_text["steps"]),
        "plan": plan_text,
        "target": {
            k: target.get(k)
            for k in (
                "sim_id", "domain", "bssid", "ssid", "address", "name",
                "url", "query", "host", "encryption", "vendor", "channel",
            )
            if target.get(k) is not None
        },
    }


def samples_from_plan(
    mode: Dict[str, Any],
    target: Dict[str, Any],
    plan_result: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """Build chat-style SFT rows from a plan (Ollama/QLoRA compatible)."""
    system = mode.get("system") or "You are a pentest planner for authorized labs."
    tgt = plan_result.get("target") or target
    user = (
        f"Mode: {mode.get('label')}\n"
        f"Goal: {mode.get('goal')}\n"
        f"Simulated target (lab only): {json.dumps(tgt, default=str)}\n"
        f"Produce a full access-seeking plan with concrete steps."
    )
    assistant = json.dumps(plan_result.get("plan") or {}, indent=2, default=str)
    return [{
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
            {"role": "assistant", "content": assistant},
        ],
        "meta": {
            "learn_mode": mode.get("label"),
            "domain": mode.get("domain"),
            "sim_id": target.get("sim_id"),
            "n_steps": plan_result.get("n_steps"),
            "source": plan_result.get("source"),
        },
    }]


def run_learn_session(
    mode_key: str,
    *,
    n_targets: int = 3,
    max_samples: int = 0,
    run_finetune: bool = True,
    epochs: int = 1,
    ai_backend: Any = None,
    on_event: Emit = None,
    base_seed: int = 0,
) -> Dict[str, Any]:
    """Full learn loop for one curriculum mode."""
    mode = get_mode(mode_key)
    if not mode:
        return {"ok": False, "error": f"unknown mode {mode_key}"}

    _emit(on_event, f"[learn] === {mode.get('label')} ===")
    _emit(on_event, f"[learn] goal: {mode.get('goal')}")

    targets = simulate_batch(mode_key, n=n_targets, base_seed=base_seed)
    _emit(on_event, f"[learn] simulated {len(targets)} polymorphic target(s)")

    all_samples: List[Dict[str, Any]] = []
    plans: List[Dict[str, Any]] = []
    for i, tgt in enumerate(targets):
        _emit(
            on_event,
            f"[learn] ({i+1}/{len(targets)}) planning for "
            f"{tgt.get('ssid') or tgt.get('name') or tgt.get('sim_id')}…",
        )
        pr = plan_for_target(mode, tgt, ai_backend=ai_backend, on_event=on_event)
        plans.append(pr)
        rows = samples_from_plan(mode, tgt, pr)
        all_samples.extend(rows)
        _emit(on_event, f"[learn] plan source={pr.get('source')} steps={pr.get('n_steps')}")

        # Long-term memory: L1 trace + L2 skill crystallize
        try:
            from core.memory.memos_ltm import (
                add_memory, crystallize_skill, ensure_cube,
            )
            cube = mode.get("cube") or f"learn_{mode_key}"
            ensure_cube(cube, name=mode.get("label") or mode_key, domain=mode.get("domain") or "")
            add_memory(
                json.dumps({
                    "target": pr.get("target"),
                    "plan": pr.get("plan"),
                    "source": pr.get("source"),
                }, default=str)[:4000],
                cube_id=cube,
                layer="L1_trace",
                kind="learn_plan",
                domain=str(mode.get("domain") or ""),
                target_key=str(tgt.get("sim_id") or ""),
                tags=["learn", mode_key, "plan"],
                meta={"n_steps": pr.get("n_steps")},
            )
            if (pr.get("n_steps") or 0) >= 3:
                crystallize_skill(
                    f"Skill for {mode.get('label')}: "
                    f"{json.dumps((pr.get('plan') or {}).get('steps') or [], default=str)[:2000]}",
                    cube_id=cube,
                    domain=str(mode.get("domain") or ""),
                    tags=["learn", mode_key, "poly"],
                    meta={"sim_id": tgt.get("sim_id")},
                )
        except Exception as e:
            _emit(on_event, f"[learn] memos: {e}")

    # Persist SFT jsonl (long-term training corpus)
    out_dir = learn_data_dir(mode_key)
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = time.strftime("%Y%m%d_%H%M%S")
    jsonl_path = out_dir / f"session_{ts}.jsonl"
    with open(jsonl_path, "w", encoding="utf-8") as fh:
        for row in all_samples:
            fh.write(json.dumps(row, ensure_ascii=False, default=str) + "\n")
    # Append to rolling train.jsonl
    roll = out_dir / "train.jsonl"
    with open(roll, "a", encoding="utf-8") as fh:
        for row in all_samples:
            fh.write(json.dumps(row, ensure_ascii=False, default=str) + "\n")

    _emit(on_event, f"[learn] saved {len(all_samples)} samples → {jsonl_path}")

    # Optional QLoRA fine-tune (persists adapters under models/finetuned/)
    ft_result: Dict[str, Any] = {"ok": False, "skipped": True}
    if run_finetune:
        ft_result = _run_finetune(
            mode,
            mode_key,
            jsonl_path,
            max_samples=max_samples or max(50, len(all_samples) * 20),
            epochs=epochs,
            on_event=on_event,
        )
    else:
        _emit(on_event, "[learn] fine-tune skipped (dataset saved for later)")

    # Registry for future plan() routing
    reg = _load_registry()
    adapters = reg.setdefault("adapters", {})
    adapters[mode_key] = {
        "label": mode.get("label"),
        "domain": mode.get("domain"),
        "finetune_domain": mode.get("finetune_domain"),
        "last_session": ts,
        "samples_path": str(jsonl_path),
        "train_jsonl": str(roll),
        "n_samples_session": len(all_samples),
        "finetune": ft_result,
        "cube": mode.get("cube"),
        "updated_at": time.time(),
    }
    _save_registry(reg)

    # L3 policy note
    try:
        from core.memory.memos_ltm import add_memory
        add_memory(
            f"Learn session {mode_key} @ {ts}: {len(all_samples)} samples, "
            f"finetune_ok={ft_result.get('ok')}, path={jsonl_path}",
            cube_id=mode.get("cube") or f"learn_{mode_key}",
            layer="L3_policy",
            kind="learn_session",
            domain=str(mode.get("domain") or ""),
            tags=["learn", "session", mode_key],
            meta={"ft": ft_result},
            score=5.0,
        )
    except Exception:
        pass

    return {
        "ok": True,
        "mode": mode_key,
        "label": mode.get("label"),
        "n_targets": len(targets),
        "n_samples": len(all_samples),
        "jsonl": str(jsonl_path),
        "train_jsonl": str(roll),
        "plans": [
            {"sim": p.get("target"), "steps": p.get("n_steps"), "source": p.get("source")}
            for p in plans
        ],
        "finetune": ft_result,
        "memos_cube": mode.get("cube"),
        "registry": str(adapter_registry_path()),
    }


def _run_finetune(
    mode: Dict[str, Any],
    mode_key: str,
    jsonl_path: Path,
    *,
    max_samples: int,
    epochs: int,
    on_event: Emit,
) -> Dict[str, Any]:
    """Invoke QLoRA script when available; always record durable artifacts."""
    script = ROOT / "scripts" / "run_qlora_finetune.py"
    ft_domain = mode.get("finetune_domain") or "wifi"
    out_dir = ROOT / "models" / "finetuned" / f"learn_{mode_key}"
    out_dir.mkdir(parents=True, exist_ok=True)

    # Copy/merge learn samples into domain local path for the finetuner
    domain_extra = ROOT / "data" / "finetune" / "learn" / mode_key / "for_qlora.jsonl"
    try:
        # Prefer learn samples first
        lines = jsonl_path.read_text(encoding="utf-8").splitlines()
        domain_extra.write_text("\n".join(lines) + "\n", encoding="utf-8")
    except Exception as e:
        return {"ok": False, "error": f"prepare samples: {e}"}

    if not script.is_file():
        _emit(on_event, "[learn] QLoRA script missing — samples saved only")
        return {
            "ok": True,
            "mode": "dataset_only",
            "samples": str(domain_extra),
            "note": "run scripts/run_qlora_finetune.py later",
        }

    # Dry environment check — if no torch/cuda, skip heavy train
    heavy = (os.environ.get("KFIOSA_LEARN_HEAVY") or "0").strip().lower() in (
        "1", "true", "yes", "on",
    )
    if not heavy:
        # Do NOT import torch here — it can hang for minutes on some systems.
        _emit(
            on_event,
            "[learn] KFIOSA_LEARN_HEAVY=0 — dataset saved for further fine-tune; "
            "set KFIOSA_LEARN_HEAVY=1 to run QLoRA now",
        )
        return {
            "ok": True,
            "mode": "dataset_only",
            "samples": str(domain_extra),
            "adapter_dir": str(out_dir),
            "note": "enable KFIOSA_LEARN_HEAVY=1 for GPU QLoRA",
        }

    cmd = [
        sys.executable, str(script),
        "--domains", str(ft_domain),
        "--max-samples", str(max(50, int(max_samples))),
        "--epochs", str(max(1, int(epochs))),
        "--out", str(out_dir),
    ]
    # Pass learn jsonl via env consumed if script supports it later
    env = os.environ.copy()
    env["KFIOSA_LEARN_JSONL"] = str(domain_extra)
    _emit(on_event, f"[learn] QLoRA: {' '.join(cmd)}")
    try:
        p = subprocess.run(
            cmd,
            cwd=str(ROOT),
            env=env,
            capture_output=True,
            text=True,
            timeout=int(os.environ.get("KFIOSA_LEARN_FT_TIMEOUT") or "7200"),
        )
        log_path = out_dir / "learn_finetune.log"
        log_path.write_text(
            (p.stdout or "") + "\n" + (p.stderr or ""),
            encoding="utf-8",
        )
        ok = p.returncode == 0
        _emit(
            on_event,
            f"[learn] QLoRA finished rc={p.returncode} log={log_path}",
        )
        return {
            "ok": ok,
            "mode": "qlora",
            "returncode": p.returncode,
            "adapter_dir": str(out_dir),
            "log": str(log_path),
            "samples": str(domain_extra),
        }
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "finetune timeout", "adapter_dir": str(out_dir)}
    except Exception as e:
        return {"ok": False, "error": str(e)[:200], "adapter_dir": str(out_dir)}


def list_saved_adapters() -> Dict[str, Any]:
    return _load_registry()
