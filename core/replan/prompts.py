# core.replan.prompts
#
# The prompt fragment the chain planner receives when a step's ok=False.
# It carries the failure + the source visibility + the available safe-patches
# + the missing tools, and instructs the LLM to propose a follow-up.
from __future__ import annotations

import textwrap
from typing import Any, Optional

from .visibility import gather_failure_context


REPLAN_FAILURE_PROMPT_TEMPLATE = textwrap.dedent("""\
    === REPLAN ON FAILURE ===
    The previous step failed. Below is everything you need to adapt the plan
    to the target's actual behavior.

    Failed step:
    {failed_step_json}

    Result:
    {result_json}

    Runner module: {runner_module}
    Method:        {method_name}
    Source path:   {source_path}
    Source SHA:    {source_sha256}

    Current method source (excerpt):
    ```python
    {method_source_excerpt}
    ```

    Available safe-patches you may NAME by id (NOT write yourself):
    {available_patches_json}

    Tools that were missing when the step ran:
    {missing_tools_json}

    Your options (pick ONE per replan step, NOT a freeform rewrite):
      (a) Propose a fresh step with `action` + `method` + `args` for a
          different attack module that fits the target's behavior.
      (b) Propose a `live_edit` step: {{"action": "live_edit", "params":
          {{"patch_id": "<id from available_patches>", "target_runner":
          "{runner_module}", "target_method": "{method_name}", "params":
          {{...}}, "rationale": "..."}}}}. The operator will see the patch
          and the rationale; CANCEL leaves the original method intact.
      (c) Propose a `tool_install` step: {{"action": "tool_install",
          "params": {{"tool": "<name from missing_tools>"}}}}. The
          installer will go through the per-step gate.
      (d) Re-dispatch the same step with modified args (e.g. retry_count
          3x, longer timeout, different mode).

    Each replan step still passes through the per-step ACCEPT/CANCEL gate.
    Never propose code that isn't an allowlisted safe-patch.
    === END REPLAN ON FAILURE ===
""")


def format_replan_prompt(
    step: dict,
    runner_module: Optional[str] = None,
    method_name: Optional[str] = None,
    result: Optional[dict] = None,
    missing_tools: Optional[list[str]] = None,
) -> str:
    """Convenience: build the context dict and format the prompt."""
    import json

    ctx = gather_failure_context(
        step=step,
        runner_module=runner_module,
        method_name=method_name,
        result=result,
        missing_tools=missing_tools,
    )
    return REPLAN_FAILURE_PROMPT_TEMPLATE.format(
        failed_step_json=json.dumps(ctx["failed_step"], indent=2, default=str),
        result_json=json.dumps(ctx["result"], indent=2, default=str),
        runner_module=ctx["runner_module"] or "<unknown>",
        method_name=ctx["method_name"] or "<unknown>",
        source_path=ctx["source_path"] or "<unknown>",
        source_sha256=ctx["source_sha256"] or "<unknown>",
        method_source_excerpt=(ctx["method_source_excerpt"] or "")[:1500],
        available_patches_json=json.dumps(ctx["available_patches"], indent=2),
        missing_tools_json=json.dumps(ctx["missing_tools"], indent=2),
    )
