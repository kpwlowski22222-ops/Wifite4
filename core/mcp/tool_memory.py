"""Long-term tool-call memory: learn what works and what to avoid.

Every MCP tool invocation can record an honest outcome into MemOS LTM
cubes so later AI plans avoid known-bad combinations and prefer
successful patterns.

Layers::

  L1_trace   — every call (compact)
  L2_skill   — successful reusable patterns
  L2_anti    — failures / "do not repeat" lessons (stored as L2_skill kind=anti)
  L3_policy  — domain-level policies distilled from clusters

Never fabricates outcomes; never stores secrets.
"""
from __future__ import annotations

import json
import time
from typing import Any, Dict, List, Optional

CUBE = "mcp_tool_flow"


def _cube_for(domain: str = "") -> str:
    d = (domain or "").strip().lower()
    if d in ("wifi", "ble", "osint", "osint_web", "osint_people", "post_exploit", "c2"):
        return f"mcp_tools_{d}"
    return CUBE


def record_tool_outcome(
    tool: str,
    *,
    ok: bool,
    args: Optional[Dict[str, Any]] = None,
    error: str = "",
    domain: str = "",
    target_key: str = "",
    duration_s: float = 0.0,
    source: str = "mcp",
    meta: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Persist one tool outcome for future fluent planning."""
    tool = (tool or "").strip()
    if not tool:
        return {"ok": False, "error": "tool name required"}
    try:
        from core.memory.memos_ltm import add_memory, crystallize_skill, ensure_cube
    except Exception as e:
        return {"ok": False, "error": f"memos unavailable: {e}"}

    cube = _cube_for(domain)
    ensure_cube(cube, name=f"MCP tools {domain or 'all'}", domain=domain or "mcp")
    ensure_cube(CUBE, name="MCP tool flow (global)", domain="mcp")

    # Compact args for memory (no secrets, bounded)
    slim_args: Dict[str, Any] = {}
    for k, v in (args or {}).items():
        if k.lower() in ("password", "token", "api_key", "secret", "key"):
            slim_args[k] = "***"
        elif isinstance(v, (str, int, float, bool)) or v is None:
            slim_args[k] = v if not isinstance(v, str) or len(v) < 200 else v[:200]
        else:
            slim_args[k] = f"<{type(v).__name__}>"

    err = (error or "")[:300]
    content = {
        "tool": tool,
        "ok": bool(ok),
        "error": err,
        "args": slim_args,
        "domain": domain,
        "target_key": target_key,
        "duration_s": round(float(duration_s or 0), 3),
        "source": source,
        "ts": time.time(),
        **(meta or {}),
    }
    text = json.dumps(content, ensure_ascii=False, default=str)[:3500]
    tags = ["mcp", "tool_call", tool.split(".")[0], "ok" if ok else "fail"]
    if domain:
        tags.append(domain)

    # L1 always
    r1 = add_memory(
        text,
        cube_id=cube,
        layer="L1_trace",
        kind="tool_ok" if ok else "tool_fail",
        domain=domain or "mcp",
        target_key=target_key,
        tags=tags,
        meta={"tool": tool, "ok": ok},
        score=1.0 if ok else 0.5,
    )
    # Mirror to global cube for cross-domain avoid lists
    if cube != CUBE:
        add_memory(
            text,
            cube_id=CUBE,
            layer="L1_trace",
            kind="tool_ok" if ok else "tool_fail",
            domain=domain or "mcp",
            target_key=target_key,
            tags=tags,
            score=1.0 if ok else 0.5,
        )

    out: Dict[str, Any] = {"ok": True, "trace": r1, "tool": tool, "success": ok}

    if ok:
        # L2 skill — short reusable pattern
        skill = (
            f"WORKS: {tool} domain={domain or '*'} "
            f"args_keys={list(slim_args.keys())[:8]} "
            f"duration_s={content['duration_s']}"
        )
        out["skill"] = crystallize_skill(
            skill,
            cube_id=cube,
            domain=domain or "mcp",
            tags=tags + ["success_pattern"],
            meta={"tool": tool, "args_keys": list(slim_args.keys())[:12]},
        )
    else:
        # L2 anti-pattern — what NOT to do
        anti = (
            f"AVOID: tool={tool} domain={domain or '*'} "
            f"error={err or 'failed'} "
            f"args={json.dumps(slim_args, default=str)[:240]}"
        )
        out["anti"] = add_memory(
            anti,
            cube_id=cube,
            layer="L2_skill",
            kind="anti_pattern",
            domain=domain or "mcp",
            target_key=target_key,
            tags=tags + ["avoid", "anti_pattern", "do_not_repeat"],
            meta={"tool": tool, "error": err},
            score=8.0,  # high priority in search
        )
        # Also global avoid cube
        add_memory(
            anti,
            cube_id=CUBE,
            layer="L2_skill",
            kind="anti_pattern",
            domain=domain or "mcp",
            tags=tags + ["avoid", "anti_pattern"],
            score=8.0,
            meta={"tool": tool, "error": err},
        )

    return out


def lessons_for(
    query: str = "",
    *,
    tool: str = "",
    domain: str = "",
    only_avoid: bool = False,
    only_success: bool = False,
    limit: int = 12,
) -> Dict[str, Any]:
    """Retrieve success patterns and avoid-lessons for fluent planning."""
    try:
        from core.memory.memos_ltm import search_memory
    except Exception as e:
        return {"ok": False, "error": str(e), "lessons": [], "avoid": [], "works": []}

    q_parts = []
    if tool:
        q_parts.append(tool)
    if domain:
        q_parts.append(domain)
    if query:
        q_parts.append(query)
    if only_avoid:
        q_parts.append("AVOID")
    if only_success:
        q_parts.append("WORKS")
    q = " ".join(q_parts).strip() or "mcp tool"

    cubes = [_cube_for(domain), CUBE]
    seen = set()
    avoid: List[Dict[str, Any]] = []
    works: List[Dict[str, Any]] = []
    other: List[Dict[str, Any]] = []

    for cube in cubes:
        r = search_memory(q, cube_id=cube, limit=limit)
        for row in r.get("results") or []:
            mid = row.get("mem_id")
            if mid in seen:
                continue
            seen.add(mid)
            kind = (row.get("kind") or "").lower()
            content = row.get("content") or ""
            item = {
                "mem_id": mid,
                "kind": kind,
                "layer": row.get("layer"),
                "content": content[:500],
                "domain": row.get("domain"),
                "score": row.get("score"),
            }
            if kind == "anti_pattern" or content.startswith("AVOID"):
                avoid.append(item)
            elif kind == "skill" or content.startswith("WORKS"):
                works.append(item)
            else:
                other.append(item)

    return {
        "ok": True,
        "query": q,
        "avoid": avoid[:limit],
        "works": works[:limit],
        "traces": other[: max(3, limit // 2)],
        "count_avoid": len(avoid),
        "count_works": len(works),
    }


def avoid_list_for_prompt(
    *,
    domain: str = "",
    tools: Optional[List[str]] = None,
    limit: int = 8,
) -> str:
    """Compact anti-pattern block for chain planner / MCP context."""
    r = lessons_for(domain=domain, only_avoid=True, limit=limit * 2)
    lines = []
    tool_set = {t.lower() for t in (tools or []) if t}
    for a in r.get("avoid") or []:
        c = a.get("content") or ""
        if tool_set and not any(t in c.lower() for t in tool_set):
            # still include domain-level avoids
            if domain and domain not in c.lower():
                continue
        lines.append(f"- {c[:180]}")
        if len(lines) >= limit:
            break
    if not lines:
        return ""
    return (
        "DO NOT REPEAT (learned failures from prior MCP/tool runs):\n"
        + "\n".join(lines)
    )


def works_list_for_prompt(
    *,
    domain: str = "",
    limit: int = 6,
) -> str:
    r = lessons_for(domain=domain, only_success=True, limit=limit)
    lines = []
    for w in r.get("works") or []:
        lines.append(f"- {(w.get('content') or '')[:160]}")
    if not lines:
        return ""
    return (
        "PREFERRED PATTERNS (learned successes):\n"
        + "\n".join(lines)
    )


def distill_domain_policy(domain: str) -> Dict[str, Any]:
    """Write an L3 policy summary from recent avoid/works for a domain."""
    r = lessons_for(domain=domain, limit=20)
    avoid_n = r.get("count_avoid") or 0
    works_n = r.get("count_works") or 0
    summary = (
        f"MCP domain policy for {domain or 'all'}: "
        f"{works_n} success patterns, {avoid_n} avoid rules. "
        f"Prefer tools marked WORKS; skip combos marked AVOID."
    )
    try:
        from core.memory.memos_ltm import add_memory, ensure_cube
        cube = _cube_for(domain)
        ensure_cube(cube, domain=domain or "mcp")
        return add_memory(
            summary
            + "\nAVOID:\n"
            + "\n".join((a.get("content") or "")[:120] for a in (r.get("avoid") or [])[:5])
            + "\nWORKS:\n"
            + "\n".join((w.get("content") or "")[:120] for w in (r.get("works") or [])[:5]),
            cube_id=cube,
            layer="L3_policy",
            kind="mcp_policy",
            domain=domain or "mcp",
            tags=["policy", "mcp", domain or "all"],
            score=6.0,
        )
    except Exception as e:
        return {"ok": False, "error": str(e)}


def record_from_result(
    tool: str,
    result: Any,
    *,
    args: Optional[Dict[str, Any]] = None,
    domain: str = "",
    target_key: str = "",
    duration_s: float = 0.0,
    source: str = "orchestrator",
) -> Dict[str, Any]:
    """Best-effort LTM record from any tool result dict (orchestrator / chain)."""
    if not tool:
        return {"ok": False, "error": "no tool"}
    ok = True
    err = ""
    if isinstance(result, dict):
        if result.get("ok") is False or result.get("blocked") or result.get("error"):
            ok = False
        if "rc" in result and result.get("rc") not in (0, None):
            ok = False
        err = str(
            result.get("error") or result.get("reason") or result.get("stderr") or ""
        )[:300]
        if not ok and not err:
            err = "failed"
    elif result is None:
        ok = False
        err = "null result"
    return record_tool_outcome(
        tool,
        ok=ok,
        args=args,
        error=err,
        domain=domain,
        target_key=target_key,
        duration_s=duration_s,
        source=source,
    )
