"""core.utils.poly_adapt — polymorphic + target-adaptive picker mixins.

Phase 2.4 — generalised companion-method pattern (see plan
``tingly-mixing-hammock.md``). Additive: existing universal methods
stay; ``_v2_poly_<name>`` and ``_v2_adapt_<name>`` are new methods
the LLM can pick when it has the necessary context.

Polymorphic methods
    A polymorphic method takes a ``context`` dict and returns a
    *grammar* — a list of variant parameter sets, plus a single
    ``picked`` choice. The envelope shape is::

        {ok: True, data: {variants: [...], picked: "<name>",
                          picked_params: {...}}, model:
         "polymorphic (heuristic)"}

Target-adaptive methods
    A target-adaptive method takes a ``context`` dict and returns
    a single concrete universal method name to call next, plus a
    ``rationale``. The envelope shape is::

        {ok: True, data: {pick: "<universal_method>", rationale:
                          "...", family: "..."}, model:
         "target-adaptive (heuristic)"}

Both are heuristic (not trained-ML) — the v2 registries must be
labelled accordingly and never produce a fake prediction.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Polymorphic grammar runner
# ---------------------------------------------------------------------------


class PolyGrammarRunner:
    """Mixin: produces a parameter grammar given a context.

    Subclasses implement ``_poly_<family>(self, context)`` returning
    a list of (name, params) tuples. The LLM (or chain planner) then
    picks one of those names; the runner's ``_v2_poly_<family>``
    returns a single envelope with ``variants`` + ``picked`` (the
    default pick — the first variant).
    """

    def _poly_grammar(self, family: str, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Default: produce a single-variant grammar from the family name.

        Subclasses override to inject real parameter sweeps.
        """
        return [{"name": family, "params": dict(context or {}),
                 "score": 0.5, "rationale": "default variant"}]

    def _v2_poly_dispatch(self, family: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Public polymorphic dispatch — returns a polymorphic envelope.

        Never raises. On any error returns ``{ok: False, error: "..."}``.
        """
        context = context or {}
        try:
            variants = self._poly_grammar(family, context)
            if not variants:
                return {"ok": False, "family": family,
                        "error": f"poly_grammar {family!r} returned 0 variants",
                        "model": "polymorphic (heuristic)"}
            picked = variants[0]
            return {"ok": True,
                    "data": {"variants": variants,
                             "picked": picked.get("name"),
                             "picked_params": picked.get("params", {})},
                    "family": family,
                    "model": "polymorphic (heuristic)"}
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "family": family,
                    "error": f"poly_dispatch failed: {e}",
                    "model": "polymorphic (heuristic)"}


# ---------------------------------------------------------------------------
# Target-adaptive picker
# ---------------------------------------------------------------------------


class TargetAdaptivePicker:
    """Mixin: picks the best universal method for a target.

    Subclasses implement ``_adapt_pick(self, family, context)``
    returning a single (method, rationale, score) tuple. The LLM
    (or chain planner) then either calls that method directly or
    asks the human to accept it.
    """

    def _adapt_pick(self, family: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Default: a no-op picker that returns the family as the
        universal method name (so the chain continues). Subclasses
        override to inject target-specific logic.
        """
        return {"method": family, "rationale":
                f"default pick for family {family!r}", "score": 0.5}

    def _v2_adapt_dispatch(self, family: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Public target-adaptive dispatch — returns a pick envelope.

        Never raises. On any error returns ``{ok: False, error: "..."}``.
        """
        context = context or {}
        try:
            pick = self._adapt_pick(family, context)
            return {"ok": True,
                    "data": {"pick": pick.get("method"),
                             "rationale": pick.get("rationale", ""),
                             "score": pick.get("score", 0.5),
                             "family": family},
                    "family": family,
                    "model": "target-adaptive (heuristic)"}
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "family": family,
                    "error": f"adapt_dispatch failed: {e}",
                    "model": "target-adaptive (heuristic)"}


# ---------------------------------------------------------------------------
# Convenience: build a polymorphic + target-adaptive combo
# ---------------------------------------------------------------------------


def build_poly_adapt_envelope(family: str, picked_method: str,
                              rationale: str = "", score: float = 0.5,
                              variants: Optional[List[Dict[str, Any]]] = None,
                              model: str = "polymorphic (heuristic)"
                              ) -> Dict[str, Any]:
    """Build a polymorphic OR target-adaptive envelope from caller inputs.

    Used by the v2 runner methods to keep envelope shape uniform. If
    ``variants`` is supplied the envelope is polymorphic; otherwise it
    is target-adaptive.
    """
    if variants is not None:
        return {"ok": True,
                "data": {"variants": variants,
                         "picked": picked_method,
                         "picked_params": {}},
                "family": family,
                "model": model}
    return {"ok": True,
            "data": {"pick": picked_method,
                     "rationale": rationale,
                     "score": score,
                     "family": family},
            "family": family,
            "model": model}


__all__ = ["PolyGrammarRunner", "TargetAdaptivePicker",
           "build_poly_adapt_envelope"]
