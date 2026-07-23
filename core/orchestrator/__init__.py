"""core.orchestrator — AI-driven autonomous attack orchestrator with
step-by-step ACCEPT/CANCEL gating."""

from .autonomous_orchestrator import AutonomousOrchestrator, TuiConfirmFn  # noqa: F401
from . import autonomous_orchestrator  # noqa: F401
from .adaptive_engagement import (  # noqa: F401
    AdaptiveEngagement,
    run_adaptive_engagement,
    score_recon,
    generate_reverse_stubs,
)

__all__ = [
    "AutonomousOrchestrator",
    "TuiConfirmFn",
    "autonomous_orchestrator",
    "AdaptiveEngagement",
    "run_adaptive_engagement",
    "score_recon",
    "generate_reverse_stubs",
]
