"""core.replan — failure-context visibility for the polymorphic re-plan loop.

When a step's `ok=False`, the re-planner sees the failure + the runner's
current source SHA + a list of available safe-patches + a list of missing
tools. The chain planner can then propose:
    - a fresh `action`/`method` combination
    - a `live_edit` request (named safe-patch + parameters)
    - a `tool_install` request (tool name + confirm)
    - re-dispatch with modified args
    - abort

MAX_REPLANS is raised from 25 → 50 to give the loop enough room for
target-adaptive real-world tuning.

Public surface:
    MAX_REPLANS
    gather_failure_context(step, runner_module, method_name, result) -> dict
    REPLAN_FAILURE_PROMPT_TEMPLATE
    format_replan_prompt(step, runner_module, method_name, result) -> str
"""
from .max_replans import MAX_REPLANS
from .visibility import gather_failure_context
from .prompts import REPLAN_FAILURE_PROMPT_TEMPLATE, format_replan_prompt

__all__ = [
    "MAX_REPLANS",
    "gather_failure_context",
    "REPLAN_FAILURE_PROMPT_TEMPLATE",
    "format_replan_prompt",
]
