"""Safe session compaction for long engagement chains (holaOS-inspired).

Preserves goals/constraints/progress/decisions/failures/next_steps while
dropping bulk raw step dumps from planner prompts.
"""
from __future__ import annotations

import os
from typing import Any, Dict, List, Optional


def compaction_enabled() -> bool:
    raw = (os.environ.get("KFIOSA_SESSION_COMPACT") or "1").strip().lower()
    return raw not in ("0", "false", "no", "off")


def _keep_recent() -> int:
    try:
        return max(1, int(os.environ.get("KFIOSA_COMPACT_KEEP_RECENT") or "4"))
    except ValueError:
        return 4


def _threshold() -> int:
    try:
        return max(2, int(os.environ.get("KFIOSA_COMPACT_AFTER_STEPS") or "8"))
    except ValueError:
        return 8


def compact_prior(
    prior_results: Optional[List[Dict[str, Any]]] = None,
    *,
    seed: Optional[Dict[str, Any]] = None,
    domain: str = "",
) -> Dict[str, Any]:
    """Build a checkpoint + recent raw tail for replan prompts."""
    prior = [p for p in (prior_results or []) if isinstance(p, dict)]
    seed = dict(seed or {})
    keep = _keep_recent()
    if not compaction_enabled() or len(prior) <= _threshold():
        return {
            "ok": True,
            "compacted": False,
            "checkpoint": None,
            "recent": prior,
            "dropped": 0,
        }

    older, recent = prior[:-keep], prior[-keep:]
    progress: List[str] = []
    failures: List[str] = []
    decisions: List[str] = []
    for e in older:
        action = e.get("action") or e.get("desc") or e.get("tool") or "step"
        result = e.get("result") if isinstance(e.get("result"), dict) else {}
        ok = result.get("ok") if result else e.get("ok")
        if ok is False or e.get("cancelled") or result.get("error"):
            failures.append(
                f"{action}: {result.get('error') or e.get('error') or 'failed'}"
            )
        elif ok is True or result:
            progress.append(f"{action}: ok")
        args = e.get("args") if isinstance(e.get("args"), dict) else {}
        if args.get("method"):
            decisions.append(f"{action} method={args.get('method')}")

    goal = (
        seed.get("goal")
        or f"engage {domain or seed.get('domain') or 'target'} until access"
    )
    constraints = [
        "ACCEPT/CANCEL gates on intrusive steps",
        "never invent PSKs/creds/access",
        "prefer poly_adapt before heavy inject/capture",
    ]
    if seed.get("pmf") or seed.get("is_sae"):
        constraints.append("PMF/SAE — avoid classic open deauth")
    next_steps: List[str] = []
    if not (seed.get("access") or {}).get("achieved"):
        next_steps.append("continue recon/attack until access")
        next_steps.append("on access: post_exploit + connection + dashboard")
    else:
        next_steps.append("post_exploit / OPSEC / open dashboard")

    # Live adapt hint
    la = seed.get("live_adapt") if isinstance(seed.get("live_adapt"), dict) else {}
    if la.get("method"):
        decisions.append(f"live_adapt={la.get('method')}: {la.get('rationale')}")

    checkpoint = {
        "goal": goal,
        "constraints": constraints,
        "progress": progress[-20:],
        "failures": failures[-15:],
        "decisions": decisions[-15:],
        "next_steps": next_steps,
        "domain": domain or seed.get("domain") or "",
        "target_key": (
            seed.get("bssid") or seed.get("address")
            or seed.get("url") or seed.get("query") or seed.get("ssid") or ""
        ),
        "workspace_id": seed.get("workspace_id") or "",
        "n_older_steps": len(older),
    }
    return {
        "ok": True,
        "compacted": True,
        "checkpoint": checkpoint,
        "recent": recent,
        "dropped": len(older),
    }


def checkpoint_prompt_block(compact: Dict[str, Any]) -> str:
    """Render compact result as planner prompt text."""
    if not compact or not compact.get("compacted"):
        return ""
    cp = compact.get("checkpoint") or {}
    lines = [
        "PRIOR CHECKPOINT (compacted older steps — do not re-do completed work):",
        f"  goal: {cp.get('goal')}",
        f"  domain: {cp.get('domain')} target_key: {cp.get('target_key')}",
        f"  older_steps_folded: {cp.get('n_older_steps')}",
        "  constraints:",
    ]
    for c in cp.get("constraints") or []:
        lines.append(f"    - {c}")
    if cp.get("progress"):
        lines.append("  progress:")
        for p in cp["progress"][-12:]:
            lines.append(f"    - {p}")
    if cp.get("failures"):
        lines.append("  failures (adapt away from these):")
        for f in cp["failures"][-10:]:
            lines.append(f"    - {f}")
    if cp.get("decisions"):
        lines.append("  decisions:")
        for d in cp["decisions"][-10:]:
            lines.append(f"    - {d}")
    if cp.get("next_steps"):
        lines.append("  suggested next:")
        for n in cp["next_steps"]:
            lines.append(f"    - {n}")
    if cp.get("workspace_id"):
        lines.append(f"  workspace_id: {cp.get('workspace_id')}")
    lines.append(
        "Emit ONLY the next 1-5 steps. Skip already-succeeded work. "
        "React to failures with a different poly_adapt variant."
    )
    return "\n".join(lines) + "\n"
