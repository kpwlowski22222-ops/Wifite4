"""core.ai_backend.v3_runner_helpers — shared v3 method envelope builder.

When a runner's v2 fallback is asked to dispatch a v3 method, it
calls ``v3_method_envelope(method, category)`` which builds a
structured envelope that the chain planner / operator can act on.

The v3 methods are by design *declarative*: they are registered in
``core.ai_backend.v3_methods`` with a risk level + description, but
most do not have a full runner implementation yet (the runner
work is Phase 5 — refactor existing methods to add v2_poly/v2_adapt
companions and then layer the v3 on top).

The envelope shape is:

    {
        "ok": False,
        "name": "<method>",
        "error": "v3 method registered in v3_methods but no impl in this runner",
        "note": "v3 method known to KFIOSA but not yet implemented in this runner",
        "risk": "<risk>",
        "description": "<description>",
        "data": {
            "category": "<category>",
            "v3": True,
            "honest_degrade": True,
        },
        "duration_s": 0.0,
    }

The chain planner uses ``risk`` to drive the per-step ACCEPT gate;
the planner uses ``description`` to plan the next step.

This is intentionally symmetric with the v2 fallback in
``core.wifi_attack.runner`` (and the equivalent in the other
runners). Adding v3 dispatch in a runner is a 5-line patch:

    from core.ai_backend.v3_runner_helpers import v3_method_envelope
    if m in (list of v3 method names):
        v3 = describe_v3_method(category, m)
        if v3 is not None:
            return v3_method_envelope(m, category, v3)
"""
from __future__ import annotations

import time
from typing import Any, Dict


def _step(name: str) -> Dict[str, Any]:
    """Return a fresh step envelope with sensible defaults."""
    return {
        "name": name,
        "ok": False,
        "data": None,
        "error": None,
        "started": time.time(),
    }


def v3_method_envelope(method: str, category: str,
                       v3_descriptor: Dict[str, str]) -> Dict[str, Any]:
    """Build the v3 fallback envelope for a method that is registered
    in ``core.ai_backend.v3_methods`` but has no implementation in
    the current runner.

    Args:
        method: the v3 method name (e.g. ``"wifi_ap_blacklist_bypass"``).
        category: the v3 category (e.g. ``"wifi_attack"``).
        v3_descriptor: the ``describe_v3_method(category, method)``
            dict with keys ``name``, ``risk``, ``description``.

    Returns:
        A dict literal envelope (NOT _finalize — see the v2 fallback
        for the same pattern and the rationale).
    """
    st = _step(method)
    st["ok"] = False
    st["error"] = (
        f"v3 method {method!r} registered in v3_methods but not "
        f"implemented in this runner"
    )
    st["note"] = (
        "v3 method known to KFIOSA but not yet implemented in this "
        "runner. Use it as a planning step; the chain planner can "
        "route the actual execution through a poly/adapt companion."
    )
    st["risk"] = v3_descriptor.get("risk", "read")
    st["description"] = v3_descriptor.get("description", "")
    st["data"] = {
        "category": category,
        "v3": True,
        "honest_degrade": True,
    }
    st["duration_s"] = round(time.time() - st.get("started", time.time()), 3)
    return st


def v3_lookup(category: str, method: str) -> Dict[str, Any]:
    """Convenience: import v3_methods lazily and build the envelope.

    Used by the v3 fallback in each runner so the runner code stays
    a one-liner.
    """
    from .v3_methods import describe_v3_method
    v3 = describe_v3_method(category, method)
    if v3 is None:
        return {
            "name": method, "ok": False,
            "error": f"unknown v3 method {method!r} in {category!r}",
            "data": None, "duration_s": 0.0,
        }
    return v3_method_envelope(method, category, v3)


__all__ = ["v3_method_envelope", "v3_lookup"]
