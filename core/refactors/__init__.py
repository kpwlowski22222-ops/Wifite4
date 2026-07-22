"""core.refactors — Phase 2.4 Phase 5.

Refactored polymorphic / target-adaptive companion methods.
"""
from .poly_adapt_companions import (
    POLY_ADAPT_REGISTRY,
    POLY_ADAPT_RISK,
    POLY_ADAPT_DESCRIPTIONS,
    list_poly_adapt_methods,
    describe_poly_adapt_method,
    run_poly_adapt,
    build_poly_adapt_prompt_stanza,
)

__all__ = [
    "POLY_ADAPT_REGISTRY",
    "POLY_ADAPT_RISK",
    "POLY_ADAPT_DESCRIPTIONS",
    "list_poly_adapt_methods",
    "describe_poly_adapt_method",
    "run_poly_adapt",
    "build_poly_adapt_prompt_stanza",
]
