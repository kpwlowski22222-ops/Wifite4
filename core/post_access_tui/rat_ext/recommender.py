"""core.post_access_tui.rat_ext.recommender — Phase 2.4 §B.7.

Capability recommendation engine. The dashboard exposes
``GET /api/session/<sid>/recommend`` which calls the chain
planner with a constrained envelope and returns a ranked list
of capabilities to invoke next.

The recommendation is a *hint*; the per-step ACCEPT gate
still fires when the operator actually triggers the
capability. The recommender never makes a destructive call.
"""
from __future__ import annotations

import time
from typing import Any, Dict, List, Optional, Tuple


# Risk levels that we recommend (read-only + intrusive). The
# recommender NEVER surfaces destructive capabilities — the
# operator must invoke those by hand.
_RECOMMEND_RISKS = {"read", "intrusive"}


def _score_capability(cap: Dict[str, Any], achieved: List[str],
                      last_activity: Optional[float]
                      ) -> Tuple[float, str]:
    """Score a single capability.

    Heuristics:
      - already achieved → score 0 (don't recommend)
      - low risk → higher score (safer first)
      - recently updated / fresh → higher score
      - chains off a recently-achieved capability → higher
    """
    if not isinstance(cap, dict):
        return 0.0, "not a dict"
    name = cap.get("name") or cap.get("id") or "?"
    if name in achieved:
        return 0.0, "already achieved"
    risk = cap.get("risk", "intrusive")
    if risk not in _RECOMMEND_RISKS:
        return 0.0, f"risk={risk} is not recommendable"
    score = 0.5  # base
    if risk == "read":
        score += 0.3
    req = cap.get("required_achievements") or []
    if req and all(r in achieved for r in req):
        score += 0.2
    rationale = (
        f"risk={risk}; chain-req={'met' if not req else 'check'} "
        f"({len(req)} deps)"
    )
    if last_activity:
        # Boost capabilities tagged with the same transport
        score += 0.05
    return min(score, 1.0), rationale


def recommend_for_session(session: Optional[Dict[str, Any]] = None,
                          limit: int = 5
                          ) -> Dict[str, Any]:
    """Build the recommendation list for a session.

    ``session`` is the same dict shape as
    :func:`core.post_access_tui.rat_ext.build_session_roster`
    consumes. Returns a ranked list (descending score)."""
    session = session or {}
    caps = session.get("capabilities") or {}
    achieved = list(session.get("achieved") or [])
    last_activity = session.get("last_activity")
    if isinstance(caps, dict):
        cap_list = list(caps.values())
    else:
        cap_list = list(caps)
    scored: List[Dict[str, Any]] = []
    for cap in cap_list:
        if not isinstance(cap, dict):
            continue
        s, why = _score_capability(cap, achieved, last_activity)
        if s <= 0:
            continue
        scored.append({
            "name": cap.get("name") or cap.get("id"),
            "score": round(s, 3),
            "rationale": why,
            "risk": cap.get("risk"),
        })
    scored.sort(key=lambda x: x["score"], reverse=True)
    top = scored[:limit]
    return {
        "ok": True,
        "session_id": session.get("session_id") or session.get("id"),
        "recommendations": top,
        "count": len(top),
        "ts": time.time(),
        "note": ("recommendation is a hint; the per-step ACCEPT "
                 "gate fires when the capability is invoked"),
    }


__all__ = ["recommend_for_session", "_score_capability"]
