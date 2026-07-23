"""Fluent, optimized MCP tool data-flow for AI agents.

Single entry points so models can call tools smoothly without
hand-routing between catalog/SQL/registry/wrappers:

  recommend(goal, domain)  → ranked tools + memory lessons
  invoke(name, args)       → unified call + auto LTM record
  pipeline([{name,args}])  → sequential chain with stop-on-fail
  prepare_context(domain)  → prompt block: tools + WORKS + AVOID

Hot-path optimizations: hot_cache for recommend/search, compact
envelopes, SQL catalog preferred, failure short-circuit in pipeline.
"""
from __future__ import annotations

import os
import time
from typing import Any, Dict, List, Optional, Sequence

from core.mcp.tool_memory import (
    avoid_list_for_prompt,
    lessons_for,
    record_tool_outcome,
    works_list_for_prompt,
)


def _compact(result: Any, *, max_str: int = 4000) -> Any:
    """Trim large payloads for fluent AI consumption."""
    if isinstance(result, dict):
        out = {}
        for k, v in result.items():
            if k in ("payload_json", "exploit_code") and isinstance(v, str) and len(v) > 800:
                out[k] = v[:800] + f"…(+{len(v)-800}b)"
            elif isinstance(v, str) and len(v) > max_str:
                out[k] = v[:max_str] + "…"
            elif isinstance(v, list) and len(v) > 40:
                out[k] = v[:40]
                out[f"{k}_truncated"] = len(v)
            else:
                out[k] = _compact(v, max_str=max_str)
        return out
    if isinstance(result, list) and len(result) > 40:
        return result[:40]
    return result


def invoke(
    name: str,
    args: Optional[Dict[str, Any]] = None,
    *,
    domain: str = "",
    target_key: str = "",
    timeout: int = 120,
    record: bool = True,
    remember_domain: str = "",
) -> Dict[str, Any]:
    """Call any MCP/catalog/registry tool and optionally remember outcome."""
    name = (name or "").strip()
    args = dict(args or {})
    domain = remember_domain or domain or str(args.pop("_domain", "") or "")
    target_key = target_key or str(args.pop("_target_key", "") or "")
    t0 = time.time()
    out: Dict[str, Any]

    # Check avoid memory first (soft warn, does not block)
    avoid_hit = None
    try:
        lessons = lessons_for(tool=name, domain=domain, only_avoid=True, limit=3)
        if lessons.get("avoid"):
            avoid_hit = lessons["avoid"][0]
    except Exception:
        pass

    try:
        out = _dispatch(name, args, timeout=timeout)
    except Exception as e:
        out = {"ok": False, "error": str(e)[:200], "tool": name}

    ok = _is_ok(out)
    duration = time.time() - t0
    err = ""
    if not ok:
        err = str(
            (out or {}).get("error")
            or (out or {}).get("reason")
            or (out or {}).get("stderr")
            or "failed"
        )[:300]

    mem: Dict[str, Any] = {}
    if record:
        try:
            mem = record_tool_outcome(
                name,
                ok=ok,
                args=args,
                error=err,
                domain=domain,
                target_key=target_key,
                duration_s=duration,
                source="flow.invoke",
            )
        except Exception as e:
            mem = {"ok": False, "error": str(e)[:80]}

    envelope = {
        "ok": ok,
        "tool": name,
        "duration_s": round(duration, 3),
        "result": _compact(out),
        "memory": {
            "recorded": bool(mem.get("ok")),
            "anti": bool(mem.get("anti")),
            "skill": bool(mem.get("skill")),
        },
    }
    if avoid_hit:
        envelope["prior_avoid_warning"] = (avoid_hit.get("content") or "")[:200]
    if not ok:
        envelope["error"] = err
        # Suggest alternatives from success memory
        try:
            alts = lessons_for(domain=domain, only_success=True, limit=4)
            envelope["try_instead"] = [
                (w.get("content") or "")[:160] for w in (alts.get("works") or [])[:3]
            ]
        except Exception:
            pass
    return envelope


def _is_ok(out: Any) -> bool:
    if not isinstance(out, dict):
        return True
    if out.get("blocked"):
        return False
    if out.get("error") and out.get("ok") is not True:
        return False
    if out.get("ok") is False:
        return False
    if "rc" in out and out.get("rc") not in (0, None):
        return False
    return True


def _dispatch(name: str, args: Dict[str, Any], *, timeout: int) -> Dict[str, Any]:
    """Route to the fastest honest backend for this tool name."""
    # Meta flow tools (avoid recursion)
    if name in (
        "flow_invoke", "flow_pipeline", "flow_recommend",
        "memory_lessons", "memory_avoid", "memory_works",
    ):
        return {"ok": False, "error": "use dedicated MCP meta-tool handlers"}

    # Catalog path
    if (
        name.startswith("catalog.")
        or name.startswith("github:")
        or name.startswith("kali:")
        or name in (
            "catalog_list", "catalog_search", "catalog_get", "catalog_run",
            "catalog_stats", "catalog_sync", "catalog_count", "catalog_page",
            "catalog_random", "catalog_by_kind", "catalog_by_tag",
            "catalog_export_ids", "catalog_surfaces", "catalog_merge_registry",
        )
    ):
        from core.mcp import _TOOL_DISPATCH
        if name in _TOOL_DISPATCH:
            return _TOOL_DISPATCH[name](args)
        from core.mcp.catalog_bridge import run_catalog_tool, get_catalog_tool
        if name.startswith("catalog.") or get_catalog_tool(name).get("ok"):
            return run_catalog_tool(
                name, args=args, timeout=timeout,
                command=str(args.get("command") or ""),
            )

    # Schema'd wrappers (record=False: flow.invoke records once)
    try:
        from core.mcp.tools import call_mcp_tool, get_mcp_tool
        if get_mcp_tool(name) is not None:
            return call_mcp_tool(name, args, timeout=timeout, record=False)
    except Exception:
        pass

    # Core MCP handlers
    try:
        from core.mcp import _TOOL_DISPATCH
        if name in _TOOL_DISPATCH:
            return _TOOL_DISPATCH[name](args)
    except Exception:
        pass

    # Last resort: catalog name match
    try:
        from core.mcp.catalog_bridge import run_catalog_tool, get_catalog_tool
        if get_catalog_tool(name).get("ok"):
            return run_catalog_tool(name, args=args, timeout=timeout)
    except Exception as e:
        return {"ok": False, "error": f"dispatch: {e}"}

    return {"ok": False, "error": f"unknown tool: {name}"}


# Keys auto-forwarded from prior tool result into next step args (when missing).
_FLOW_FORWARD_KEYS = (
    "bssid", "essid", "ssid", "channel", "iface", "interface", "cap_file",
    "capture", "target", "target_key", "cve_id", "cve", "host", "ip",
    "port", "mac", "addr", "address", "session_id", "url", "path", "output",
    "write", "wordlist", "hash_file", "domain",
)


def _flatten_result(result: Any) -> Dict[str, Any]:
    """Pull useful scalar fields out of a nested tool result for fluent flow."""
    flat: Dict[str, Any] = {}
    if not isinstance(result, dict):
        return flat

    def _walk(obj: Any, depth: int = 0) -> None:
        if depth > 3 or not isinstance(obj, dict):
            return
        for k, v in obj.items():
            if k in _FLOW_FORWARD_KEYS and k not in flat:
                if isinstance(v, (str, int, float, bool)) or v is None:
                    flat[k] = v
            if isinstance(v, dict):
                _walk(v, depth + 1)
            elif isinstance(v, list) and v and isinstance(v[0], dict):
                _walk(v[0], depth + 1)

    _walk(result)
    return flat


def _resolve_templates(value: Any, prior: Any, ctx: Dict[str, Any]) -> Any:
    """Resolve $prior / $prior.key / $ctx.step_N.key string templates."""
    if isinstance(value, dict):
        return {k: _resolve_templates(v, prior, ctx) for k, v in value.items()}
    if isinstance(value, list):
        return [_resolve_templates(v, prior, ctx) for v in value]
    if not isinstance(value, str) or not value.startswith("$"):
        return value
    # $prior  → whole prior result
    if value == "$prior":
        return prior
    # $prior.key or $prior.a.b
    if value.startswith("$prior."):
        cur: Any = prior
        for part in value[7:].split("."):
            if isinstance(cur, dict):
                cur = cur.get(part)
            else:
                return value
        return cur if cur is not None else value
    # $ctx.step_0.tool etc.
    if value.startswith("$ctx."):
        cur = ctx
        for part in value[5:].split("."):
            if isinstance(cur, dict):
                cur = cur.get(part)
            else:
                return value
        return cur if cur is not None else value
    return value


def pipeline(
    steps: Sequence[Dict[str, Any]],
    *,
    domain: str = "",
    target_key: str = "",
    stop_on_fail: bool = True,
    record: bool = True,
    auto_forward: bool = True,
) -> Dict[str, Any]:
    """Run a sequence of tool calls with fluent inter-step data flow.

    Each step may:
      - set ``pass_result: true`` → inject prior result as ``_prior``
      - use ``$prior`` / ``$prior.field`` templates in any arg value
      - auto-forward common keys (bssid, channel, iface, …) when missing
    """
    results: List[Dict[str, Any]] = []
    ctx: Dict[str, Any] = {"domain": domain, "target_key": target_key}
    flowing: Dict[str, Any] = {}  # accumulated forwarded fields
    t0 = time.time()

    for i, step in enumerate(steps or []):
        if not isinstance(step, dict):
            results.append({"ok": False, "error": "step must be object", "index": i})
            if stop_on_fail:
                break
            continue
        name = step.get("name") or step.get("tool") or ""
        args = dict(step.get("args") or step.get("arguments") or {})
        prior_result = results[-1].get("result") if results else None

        # 1) Resolve $prior / $ctx templates
        args = _resolve_templates(args, prior_result, ctx)

        # 2) Explicit prior inject
        if step.get("pass_result") and prior_result is not None:
            args.setdefault("_prior", prior_result)

        # 3) Auto-forward common recon/attack fields into missing args
        if auto_forward and step.get("auto_forward", True) and flowing:
            for k, v in flowing.items():
                if k not in args and v is not None and v != "":
                    args[k] = v

        if domain and "_domain" not in args:
            args["_domain"] = domain
        if target_key and "target_key" not in args:
            args.setdefault("target_key", target_key)

        env = invoke(
            name, args,
            domain=domain,
            target_key=target_key,
            timeout=int(step.get("timeout") or 120),
            record=record,
        )
        env["index"] = i
        results.append(env)

        # Update fluent context from this step's result
        flat = _flatten_result(env.get("result"))
        if flat:
            flowing.update(flat)
        ctx[f"step_{i}"] = {
            "tool": name,
            "ok": env.get("ok"),
            "fields": flat,
            "error": env.get("error"),
        }
        ctx["last"] = ctx[f"step_{i}"]
        ctx["flow"] = dict(flowing)

        if stop_on_fail and not env.get("ok"):
            break

    ok_n = sum(1 for r in results if r.get("ok"))
    return {
        "ok": ok_n == len(results) and len(results) > 0,
        "steps": len(results),
        "ok_count": ok_n,
        "fail_count": len(results) - ok_n,
        "results": results,
        "context": ctx,
        "flow": flowing,
        "duration_s": round(time.time() - t0, 3),
        "stopped_early": stop_on_fail and any(not r.get("ok") for r in results),
    }


def recommend(
    goal: str,
    *,
    domain: str = "",
    limit: int = 12,
) -> Dict[str, Any]:
    """Rank tools for a goal using catalog SQL + registry + memory."""
    goal = (goal or "").strip()
    limit = max(1, min(int(limit or 12), 40))

    def _build() -> Dict[str, Any]:
        tools: List[Dict[str, Any]] = []
        # Catalog FTS
        try:
            from core.mcp.catalog_bridge import list_catalog_tools
            cat = list_catalog_tools(
                text=goal, domain=domain, surface=domain, limit=limit,
            )
            for t in cat.get("tools") or []:
                tools.append({
                    "name": t.get("mcp_name") or t.get("name"),
                    "source": "catalog",
                    "domain": t.get("domain"),
                    "description": (t.get("description") or "")[:160],
                    "score": 10,
                })
        except Exception:
            pass
        # Registry
        try:
            from core.tool_registry import ToolRegistry
            reg = ToolRegistry()
            reg.load()
            for t in reg.search(goal, limit=limit):
                tools.append({
                    "name": t.get("name"),
                    "source": t.get("source"),
                    "domain": t.get("domain"),
                    "description": (t.get("description") or "")[:160],
                    "score": 8,
                })
        except Exception:
            pass
        # Schema wrappers
        try:
            from core.mcp.tools import list_mcp_tools
            for t in list_mcp_tools(domain=domain or None):
                desc = (t.get("description") or "").lower()
                if goal.lower() in desc or goal.lower() in (t.get("name") or "").lower() or not goal:
                    tools.append({
                        "name": t.get("name"),
                        "source": "mcp_wrapper",
                        "risk_level": t.get("risk_level"),
                        "description": (t.get("description") or "")[:160],
                        "score": 12,
                    })
        except Exception:
            pass

        # Boost WORKS / demote AVOID
        lessons = lessons_for(query=goal, domain=domain, limit=20)
        avoid_text = " ".join(
            (a.get("content") or "").lower() for a in (lessons.get("avoid") or [])
        )
        works_text = " ".join(
            (w.get("content") or "").lower() for w in (lessons.get("works") or [])
        )
        for t in tools:
            n = (t.get("name") or "").lower()
            if n and n in works_text:
                t["score"] = int(t.get("score") or 0) + 15
                t["memory"] = "works"
            if n and n in avoid_text:
                t["score"] = int(t.get("score") or 0) - 20
                t["memory"] = "avoid"

        # Dedupe by name keep highest score
        best: Dict[str, Dict[str, Any]] = {}
        for t in tools:
            n = t.get("name") or ""
            if not n:
                continue
            if n not in best or (t.get("score") or 0) > (best[n].get("score") or 0):
                best[n] = t
        ranked = sorted(best.values(), key=lambda x: -int(x.get("score") or 0))
        # Filter hard avoids unless no alternatives
        preferred = [t for t in ranked if t.get("memory") != "avoid"]
        final = (preferred or ranked)[:limit]

        return {
            "ok": True,
            "goal": goal,
            "domain": domain,
            "tools": final,
            "count": len(final),
            "avoid_lessons": [
                (a.get("content") or "")[:180] for a in (lessons.get("avoid") or [])[:5]
            ],
            "works_lessons": [
                (w.get("content") or "")[:180] for w in (lessons.get("works") or [])[:5]
            ],
            "next": (
                f"Call flow_invoke with name={final[0]['name']}" if final
                else "Broaden goal or catalog_sync"
            ),
        }

    try:
        from core.utils.hot_cache import GLOBAL_CACHE
        return GLOBAL_CACHE.get_or_set(
            "flow_recommend",
            (goal, domain, limit),
            _build,
            ttl_s=20.0,
        )
    except Exception:
        return _build()


def prepare_context(domain: str = "", *, tool_limit: int = 20) -> str:
    """Compact fluent context for chain planner / AI system prompts."""
    parts: List[str] = []
    try:
        from core.mcp.tools import mcp_tools_context_block
        block = mcp_tools_context_block(domain=domain or None, limit=tool_limit)
        if block:
            parts.append("MCP TOOLS (schemas):\n" + block)
    except Exception:
        pass
    w = works_list_for_prompt(domain=domain, limit=5)
    a = avoid_list_for_prompt(domain=domain, limit=6)
    if w:
        parts.append(w)
    if a:
        parts.append(a)
    parts.append(
        "FLUENT FLOW: use flow_recommend(goal) → flow_invoke(name,args) "
        "or flow_pipeline([{name,args},…]). Failures are remembered as AVOID."
    )
    return "\n\n".join(parts)


def wire_into_chain_context(domain: str = "") -> Dict[str, Any]:
    """Hook for AIChainPlanner — returns dict fields to merge into plan ctx."""
    return {
        "mcp_flow_context": prepare_context(domain),
        "mcp_avoid": avoid_list_for_prompt(domain=domain),
        "mcp_works": works_list_for_prompt(domain=domain),
    }
