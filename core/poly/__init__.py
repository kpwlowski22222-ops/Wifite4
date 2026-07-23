"""Polymorphic / target-adaptive helpers for live engagements.

Includes plum-dispatch multiple dispatch (Python ≥3.10) via
:mod:`core.poly.plum_adapt` for typed target adaptation.
"""
from core.poly.live_adapt import (  # noqa: F401
    observe,
    pick,
    plan_creativity,
    poly_pre_step,
    react,
)
from core.poly.offensive_inject import (  # noqa: F401
    build_offensive_chain,
    merge_offensive_prefix,
    pick_inject_mode,
    pick_priv_esc,
    react_inject,
)

try:
    from core.poly.plum_adapt import (  # noqa: F401
        adapt_target,
        coerce_target,
        plum_available,
        plum_prompt_block,
    )
except Exception:  # pragma: no cover
    pass

try:
    from core.poly.multi_engine import (  # noqa: F401
        ensemble_adapt,
        enabled_engines,
        engines_status,
        multi_engine_prompt_block,
    )
except Exception:  # pragma: no cover
    pass
