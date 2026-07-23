#!/usr/bin/env python3
"""
KFIOSA MCP Server (Model Context Protocol)
============================================
A **dependency-free** stdio MCP server that exposes the KFIOSA tool registry
to AI models / MCP clients. Any MCP-aware client (Claude Desktop, an Ollama
MCP bridge, a custom agent) can connect to this server over stdio and:

  - discover what tools are available (toolboxes cloned under ``toolboxes/``,
    installed Kali packages, and ``.venv`` Python libraries),
  - learn *how* and *when* to use each one (README-derived usage + entry
    points),
  - search the catalog, and
  - **run** a tool (gated — off unless ``KFIOSA_MCP_ALLOW_EXEC=1``).

Protocol: JSON-RPC 2.0 over newline-delimited stdio (the standard MCP stdio
transport, spec revision 2024-11-05). No third-party SDK required, so it runs
in the existing ``.venv`` without extra installs.

Run:
    python -m core.mcp_server                 # stdio server (connect a client)
    python -m core.mcp_server --self-test      # exercise every method locally
    python -m core.mcp_server --host 127.0.0.1 --port 12700
                                               # loopback TCP server (long-lived
                                               # background service the KFIOSA
                                               # dashboard auto-starts so AI
                                               # clients can connect while the
                                               # tool runs)

Exposed tools (MCP ``tools/call``):
    list_tools(domain?, source?, limit?)      -> compact tool list
    search_tools(query, limit?)                -> scored search
    get_tool_usage(name, source?)              -> full record (usage/entry points)
    run_tool(command, timeout?, cwd?)          -> gated subprocess execution
    call_tool(name, args?)                     -> schema'd Kali/mt7921e/cve wrappers
    catalog_sync / catalog_stats / catalog_list / catalog_search /
    catalog_get / catalog_run / catalog_surfaces / catalog_merge_registry /
    catalog_count / catalog_by_kind / catalog_by_tag / catalog_random /
    catalog_export_ids / catalog_page
    catalog.<name>                             -> per-entry virtual tools (dynamic tools/list)

Exposed resources (MCP ``resources/read``):
    registry://summary                         -> build stats
    tool://<source>/<name>                     -> one tool record
    catalog://summary                          -> SQL/json catalog stats
    catalog://entry/<id>                       -> one catalog entry
"""

import json
import logging
import os
import shlex
import subprocess
import sys
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

PROTOCOL_VERSION = "2024-11-05"
SERVER_INFO = {"name": "kfiosa-tool-mcp", "version": "1.2.0"}


# ---------------------------------------------------------------------------
# Registry access (lazy singleton)
# ---------------------------------------------------------------------------
_REGISTRY = None
_REGISTRY_LOCK = threading.Lock()


def _registry():
    global _REGISTRY
    with _REGISTRY_LOCK:
        if _REGISTRY is None:
            from core.tool_registry import ToolRegistry
            _REGISTRY = ToolRegistry()
            _REGISTRY.load()
        return _REGISTRY


def _public_record(t: Dict[str, Any]) -> Dict[str, Any]:
    """Trim a tool record for client consumption."""
    return {
        "name": t.get("name"),
        "source": t.get("source"),
        "domain": t.get("domain"),
        "path": t.get("path"),
        "url": t.get("url"),
        "description": t.get("description"),
        "usage": t.get("usage") or [],
        "entry_points": t.get("entry_points") or [],
        "language": t.get("language"),
    }


# ---------------------------------------------------------------------------
# MCP tool handlers
# ---------------------------------------------------------------------------
def t_list_tools(args: Dict[str, Any]) -> Dict[str, Any]:
    reg = _registry()
    domain = args.get("domain")
    source = args.get("source")
    limit = int(args.get("limit", 50))
    include_catalog = str(args.get("include_catalog", "1")).lower() not in (
        "0", "false", "no", "off",
    )
    tools = reg.tools
    if domain:
        tools = [t for t in tools if t.get("domain") == domain]
    if source:
        tools = [t for t in tools if t.get("source") == source]
    out = [_public_record(t) for t in tools[:limit]]
    # Schema'd MCP tool wrappers (Kali + mt7921e.* + cve_lookup).
    try:
        from core.mcp.tools import list_mcp_tools
        out.extend(list_mcp_tools(domain=domain))
    except Exception as e:
        logger.debug(f"mcp.tools.list_mcp_tools failed: {e}")
    # Every catalog entry from SQL/json (paginated)
    catalog_meta = {}
    if include_catalog and (not source or source == "catalog"):
        try:
            from core.mcp.catalog_bridge import list_catalog_tools
            cat = list_catalog_tools(
                domain=domain or "",
                limit=min(limit, 500),
                offset=int(args.get("catalog_offset") or 0),
            )
            catalog_meta = {
                "catalog_source": cat.get("source"),
                "catalog_total_estimate": cat.get("total_estimate"),
                "catalog_count": cat.get("count"),
            }
            for t in cat.get("tools") or []:
                out.append({
                    "name": t.get("mcp_name") or t.get("name"),
                    "source": "catalog",
                    "domain": t.get("domain"),
                    "path": t.get("toolbox_path") or t.get("path"),
                    "url": t.get("url"),
                    "description": t.get("description"),
                    "usage": t.get("usage") or [],
                    "entry_points": t.get("entry_points") or [],
                    "id": t.get("id"),
                    "kind": t.get("kind"),
                    "attack_surface": t.get("attack_surface"),
                })
        except Exception as e:
            logger.debug(f"catalog list failed: {e}")
            catalog_meta = {"catalog_error": str(e)[:120]}
    return {
        "count": len(out[: max(limit, 500)]),
        "tools": out[: max(limit, 500)],
        **catalog_meta,
    }


def t_search_tools(args: Dict[str, Any]) -> Dict[str, Any]:
    query = args.get("query", "")
    if not query:
        return {"error": "query required"}
    limit = int(args.get("limit", 20))
    reg = _registry()
    results = reg.search(query, limit=limit)
    out = [_public_record(t) for t in results]
    # Catalog SQL/json FTS
    try:
        from core.mcp.catalog_bridge import list_catalog_tools
        cat = list_catalog_tools(text=query, limit=limit)
        for t in cat.get("tools") or []:
            out.append({
                "name": t.get("mcp_name") or t.get("name"),
                "source": "catalog",
                "domain": t.get("domain"),
                "path": t.get("toolbox_path") or t.get("path"),
                "url": t.get("url"),
                "description": t.get("description"),
                "usage": t.get("usage") or [],
                "entry_points": t.get("entry_points") or [],
                "id": t.get("id"),
                "kind": t.get("kind"),
            })
    except Exception as e:
        logger.debug(f"catalog search failed: {e}")
    # Dedupe by name+source
    seen = set()
    deduped = []
    for t in out:
        key = f"{t.get('source')}:{t.get('name')}"
        if key in seen:
            continue
        seen.add(key)
        deduped.append(t)
    return {
        "query": query,
        "count": len(deduped[:limit]),
        "tools": deduped[:limit],
    }


def t_get_tool_usage(args: Dict[str, Any]) -> Dict[str, Any]:
    name = args.get("name")
    if not name:
        return {"error": "name required"}
    source = args.get("source")
    # Schema'd MCP tool wrappers first (Kali + mt7921e.* + cve_lookup).
    try:
        from core.mcp.tools import get_mcp_tool
        rec = get_mcp_tool(name)
        if rec is not None:
            return rec
    except Exception as e:
        logger.debug(f"mcp.tools.get_mcp_tool failed: {e}")
    # Catalog entry (id or catalog.name)
    if (source in (None, "", "catalog")
            or str(name).startswith("catalog.")
            or ":" in str(name)
            or str(name).startswith("github")):
        try:
            from core.mcp.catalog_bridge import get_catalog_tool
            got = get_catalog_tool(name)
            if got.get("ok"):
                return {"ok": True, **(got.get("tool") or {}), "source": "catalog"}
        except Exception as e:
            logger.debug(f"catalog get failed: {e}")
    reg = _registry()
    # Match by name, optionally narrowed by source.
    for t in reg.tools:
        if t.get("name") == name and (not source or t.get("source") == source):
            return _public_record(t)
        if t.get("mcp_name") == name:
            return _public_record(t)
    return {"error": f"tool not found: {name}"}


def t_call_tool(args: Dict[str, Any]) -> Dict[str, Any]:
    """Invoke a schema'd MCP tool (Kali / mt7921e.* / cve) or catalog entry."""
    name = args.get("name")
    if not name:
        return {"error": "name required"}
    tool_args = args.get("args") or {}
    timeout = int(args.get("timeout", 30))
    # Catalog virtual tools
    if str(name).startswith("catalog.") or str(name).startswith("github:"):
        try:
            from core.mcp.catalog_bridge import run_catalog_tool
            return run_catalog_tool(
                name, args=tool_args, timeout=timeout,
                command=str(tool_args.get("command") or ""),
            )
        except Exception as e:
            return {"ok": False, "error": str(e)[:160]}
    try:
        from core.mcp.tools import call_mcp_tool, get_mcp_tool
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": f"mcp.tools import: {e}"}
    if get_mcp_tool(name) is not None:
        return call_mcp_tool(name, tool_args, timeout=timeout)
    # Fallback: treat as catalog name
    try:
        from core.mcp.catalog_bridge import run_catalog_tool, get_catalog_tool
        if get_catalog_tool(name).get("ok"):
            return run_catalog_tool(
                name, args=tool_args, timeout=timeout,
                command=str(tool_args.get("command") or ""),
            )
    except Exception:
        pass
    return call_mcp_tool(name, tool_args, timeout=timeout)


def t_run_tool(args: Dict[str, Any]) -> Dict[str, Any]:
    """Gated subprocess execution for an MCP client.

    Off by default — a runaway or hostile prompt could otherwise run arbitrary
    commands. Enable explicitly with ``KFIOSA_MCP_ALLOW_EXEC=1`` (lab use).
    """
    command = args.get("command")
    if not command:
        return {"error": "command required"}
    if os.getenv("KFIOSA_MCP_ALLOW_EXEC") != "1":
        return {
            "blocked": True,
            "reason": "execution is gated; set KFIOSA_MCP_ALLOW_EXEC=1 to allow",
            "would_run": command,
        }
    timeout = int(args.get("timeout", 120))
    cwd = args.get("cwd") or str(PROJECT_ROOT)
    try:
        argv = shlex.split(command)
    except ValueError as e:
        return {"error": f"bad command: {e}"}
    try:
        p = subprocess.run(
            argv, capture_output=True, text=True,
            timeout=timeout, cwd=cwd,
        )
        return {
            "rc": p.returncode,
            "stdout": p.stdout[-4000:],
            "stderr": p.stderr[-2000:],
        }
    except subprocess.TimeoutExpired:
        return {"error": "timeout", "timeout": timeout}
    except FileNotFoundError:
        return {"error": f"not found: {argv[0]}"}
    except Exception as e:
        return {"error": str(e)}


MCP_TOOLS: List[Dict[str, Any]] = [
    {
        "name": "list_tools",
        "description": "List tools the AI can call from the KFIOSA registry "
                       "(cloned toolboxes, installed Kali packages, .venv libs).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string",
                           "description": "filter by domain: wifi/ble/osint/post_exploitation/c2/exploit/recon/web/mobile"},
                "source": {"type": "string",
                           "description": "filter by source: toolbox/kali/kali-dpkg/venv"},
                "limit": {"type": "integer", "default": 50},
            },
        },
    },
    {
        "name": "search_tools",
        "description": "Scored search of the tool catalog by keyword.",
        "inputSchema": {
            "type": "object",
            "required": ["query"],
            "properties": {
                "query": {"type": "string"},
                "limit": {"type": "integer", "default": 20},
            },
        },
    },
    {
        "name": "get_tool_usage",
        "description": "Get full usage info, entry points, and path for one tool.",
        "inputSchema": {
            "type": "object",
            "required": ["name"],
            "properties": {
                "name": {"type": "string"},
                "source": {"type": "string"},
            },
        },
    },
    {
        "name": "run_tool",
        "description": "Run a command (gated; off unless KFIOSA_MCP_ALLOW_EXEC=1).",
        "inputSchema": {
            "type": "object",
            "required": ["command"],
            "properties": {
                "command": {"type": "string", "description": "shell command to execute"},
                "timeout": {"type": "integer", "default": 120},
                "cwd": {"type": "string"},
            },
        },
    },
    {
        "name": "call_tool",
        "description": "Invoke a schema'd wrapper (Kali/mt7921e/cve) or catalog tool.",
        "inputSchema": {
            "type": "object",
            "required": ["name"],
            "properties": {
                "name": {"type": "string"},
                "args": {"type": "object"},
                "timeout": {"type": "integer", "default": 120},
            },
        },
    },
    {
        "name": "catalog_sync",
        "description": "Ingest all catalog/*.json into SQLite for fast MCP listing.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "force": {"type": "boolean", "default": False},
                "max_files": {"type": "integer", "default": 0},
            },
        },
    },
    {
        "name": "catalog_stats",
        "description": "Catalog coverage stats (SQL vs disk file count).",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "catalog_list",
        "description": "List every catalog tool from SQL/json (paginated).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string"},
                "surface": {"type": "string"},
                "kind": {"type": "string"},
                "text": {"type": "string"},
                "limit": {"type": "integer", "default": 100},
                "offset": {"type": "integer", "default": 0},
                "prefer": {"type": "string", "description": "sql|memory|json"},
            },
        },
    },
    {
        "name": "catalog_search",
        "description": "FTS/search across all catalog tools (SQL preferred).",
        "inputSchema": {
            "type": "object",
            "required": ["query"],
            "properties": {
                "query": {"type": "string"},
                "surface": {"type": "string"},
                "limit": {"type": "integer", "default": 30},
            },
        },
    },
    {
        "name": "catalog_get",
        "description": "Get one catalog entry by id, name, or catalog.* mcp name.",
        "inputSchema": {
            "type": "object",
            "required": ["name"],
            "properties": {"name": {"type": "string"}},
        },
    },
    {
        "name": "catalog_run",
        "description": "Run a catalog tool entry point (gated: KFIOSA_MCP_ALLOW_EXEC=1).",
        "inputSchema": {
            "type": "object",
            "required": ["name"],
            "properties": {
                "name": {"type": "string"},
                "argv": {"type": "string"},
                "command": {"type": "string"},
                "timeout": {"type": "integer", "default": 120},
            },
        },
    },
    {
        "name": "catalog_surfaces",
        "description": "List attack_surface buckets and counts from catalog SQL.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "catalog_merge_registry",
        "description": "Merge all catalog tools into data/tool_registry.json.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "catalog_count",
        "description": "Fast counts (total / by kind / by surface / filtered).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "surface": {"type": "string"},
                "kind": {"type": "string"},
                "text": {"type": "string"},
            },
        },
    },
    {
        "name": "catalog_by_kind",
        "description": "List catalog tools filtered by kind (e.g. external_repository).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "kind": {"type": "string"},
                "limit": {"type": "integer", "default": 50},
                "offset": {"type": "integer", "default": 0},
            },
        },
    },
    {
        "name": "catalog_by_tag",
        "description": "List catalog tools matching a tag/keyword.",
        "inputSchema": {
            "type": "object",
            "required": ["tag"],
            "properties": {
                "tag": {"type": "string"},
                "limit": {"type": "integer", "default": 50},
            },
        },
    },
    {
        "name": "catalog_random",
        "description": "Sample random catalog tools (discovery / poly pick).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "n": {"type": "integer", "default": 5},
                "surface": {"type": "string"},
            },
        },
    },
    {
        "name": "catalog_export_ids",
        "description": "Export entry ids + mcp_names for bulk AI routing.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "surface": {"type": "string"},
                "kind": {"type": "string"},
                "limit": {"type": "integer", "default": 5000},
            },
        },
    },
    {
        "name": "catalog_page",
        "description": "1-based paginated catalog browser.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "page": {"type": "integer", "default": 1},
                "page_size": {"type": "integer", "default": 100},
                "surface": {"type": "string"},
                "kind": {"type": "string"},
                "text": {"type": "string"},
            },
        },
    },
]

# Append schema'd wrappers (Kali tools, mt7921e.*, cve_lookup) at module
# import time so `tools/list` returns them alongside the legacy entries.
# Best-effort: a failure here must not break the MCP server.
try:  # noqa: E402
    from core.mcp.tools import list_mcp_tools as _list_mcp_tools
    # list_mcp_tools() already returns MCP-record dicts; append verbatim.
    for _rec in _list_mcp_tools():
        if isinstance(_rec, dict) and _rec.get("name"):
            MCP_TOOLS.append(_rec)
except Exception:
    # core.mcp.tools not importable (missing dependency, partial install).
    # The legacy `run_tool` path is still usable.
    pass

# Static catalog virtual tools are NOT expanded at import (too heavy /
# stale). tools/list rebuilds them dynamically from SQL via
# dynamic_mcp_tools_list().


def t_catalog_sync(args: Dict[str, Any]) -> Dict[str, Any]:
    from core.mcp.catalog_bridge import sync_catalog_to_sql
    return sync_catalog_to_sql(
        force=bool(args.get("force")),
        max_files=int(args.get("max_files") or 0),
    )


def t_catalog_stats(args: Dict[str, Any]) -> Dict[str, Any]:
    from core.mcp.catalog_bridge import catalog_source_stats
    return catalog_source_stats()


def t_catalog_list(args: Dict[str, Any]) -> Dict[str, Any]:
    from core.mcp.catalog_bridge import list_catalog_tools
    return list_catalog_tools(
        domain=str(args.get("domain") or ""),
        surface=str(args.get("surface") or ""),
        kind=str(args.get("kind") or ""),
        text=str(args.get("text") or ""),
        limit=int(args.get("limit") or 100),
        offset=int(args.get("offset") or 0),
        prefer=str(args.get("prefer") or ""),
    )


def t_catalog_search(args: Dict[str, Any]) -> Dict[str, Any]:
    q = args.get("query") or args.get("text") or ""
    if not q:
        return {"error": "query required"}
    from core.mcp.catalog_bridge import list_catalog_tools
    return list_catalog_tools(
        text=str(q),
        surface=str(args.get("surface") or ""),
        limit=int(args.get("limit") or 30),
    )


def t_catalog_get(args: Dict[str, Any]) -> Dict[str, Any]:
    from core.mcp.catalog_bridge import get_catalog_tool
    return get_catalog_tool(str(args.get("name") or ""))


def t_catalog_run(args: Dict[str, Any]) -> Dict[str, Any]:
    from core.mcp.catalog_bridge import run_catalog_tool
    return run_catalog_tool(
        str(args.get("name") or ""),
        args={"argv": args.get("argv")},
        timeout=int(args.get("timeout") or 120),
        command=str(args.get("command") or ""),
    )


def t_catalog_surfaces(args: Dict[str, Any]) -> Dict[str, Any]:
    try:
        from core.catalog.sql_store import list_surfaces, sql_ready
        if sql_ready():
            return {"ok": True, "source": "sql", "surfaces": list_surfaces()}
    except Exception as e:
        return {"ok": False, "error": str(e)[:160]}
    st = t_catalog_stats({})
    return {"ok": True, "source": st.get("source"), "stats": st}


def t_catalog_merge_registry(args: Dict[str, Any]) -> Dict[str, Any]:
    from core.mcp.catalog_bridge import merge_into_registry
    return merge_into_registry()


def t_catalog_count(args: Dict[str, Any]) -> Dict[str, Any]:
    from core.mcp.catalog_bridge import catalog_count
    return catalog_count(
        surface=str(args.get("surface") or ""),
        kind=str(args.get("kind") or ""),
        text=str(args.get("text") or ""),
    )


def t_catalog_by_kind(args: Dict[str, Any]) -> Dict[str, Any]:
    from core.mcp.catalog_bridge import catalog_by_kind
    return catalog_by_kind(
        str(args.get("kind") or ""),
        limit=int(args.get("limit") or 50),
        offset=int(args.get("offset") or 0),
    )


def t_catalog_by_tag(args: Dict[str, Any]) -> Dict[str, Any]:
    from core.mcp.catalog_bridge import catalog_by_tag
    return catalog_by_tag(
        str(args.get("tag") or ""),
        limit=int(args.get("limit") or 50),
    )


def t_catalog_random(args: Dict[str, Any]) -> Dict[str, Any]:
    from core.mcp.catalog_bridge import catalog_random
    return catalog_random(
        n=int(args.get("n") or 5),
        surface=str(args.get("surface") or ""),
    )


def t_catalog_export_ids(args: Dict[str, Any]) -> Dict[str, Any]:
    from core.mcp.catalog_bridge import catalog_export_ids
    return catalog_export_ids(
        surface=str(args.get("surface") or ""),
        kind=str(args.get("kind") or ""),
        limit=int(args.get("limit") or 5000),
    )


def t_catalog_page(args: Dict[str, Any]) -> Dict[str, Any]:
    from core.mcp.catalog_bridge import catalog_page
    return catalog_page(
        page=int(args.get("page") or 1),
        page_size=int(args.get("page_size") or 100),
        surface=str(args.get("surface") or ""),
        kind=str(args.get("kind") or ""),
        text=str(args.get("text") or ""),
    )


_TOOL_DISPATCH = {
    "list_tools": t_list_tools,
    "search_tools": t_search_tools,
    "get_tool_usage": t_get_tool_usage,
    "run_tool": t_run_tool,
    "call_tool": t_call_tool,
    "catalog_sync": t_catalog_sync,
    "catalog_stats": t_catalog_stats,
    "catalog_list": t_catalog_list,
    "catalog_search": t_catalog_search,
    "catalog_get": t_catalog_get,
    "catalog_run": t_catalog_run,
    "catalog_surfaces": t_catalog_surfaces,
    "catalog_merge_registry": t_catalog_merge_registry,
    "catalog_count": t_catalog_count,
    "catalog_by_kind": t_catalog_by_kind,
    "catalog_by_tag": t_catalog_by_tag,
    "catalog_random": t_catalog_random,
    "catalog_export_ids": t_catalog_export_ids,
    "catalog_page": t_catalog_page,
}


def _all_mcp_tools_for_list() -> List[Dict[str, Any]]:
    """Meta + schema wrappers + live catalog virtual tools from SQL."""
    tools = list(MCP_TOOLS)
    try:
        from core.mcp.catalog_bridge import dynamic_mcp_tools_list
        seen = {t.get("name") for t in tools if isinstance(t, dict)}
        for rec in dynamic_mcp_tools_list():
            n = rec.get("name") if isinstance(rec, dict) else None
            if n and n not in seen:
                tools.append(rec)
                seen.add(n)
    except Exception as e:
        logger.debug("dynamic catalog tools: %s", e)
    return tools


# ---------------------------------------------------------------------------
# Resource handlers
# ---------------------------------------------------------------------------
def resources_list() -> List[Dict[str, Any]]:
    reg = _registry()
    out = [
        {"uri": "registry://summary", "name": "Registry summary"},
        {"uri": "catalog://summary", "name": "Catalog SQL/json summary"},
    ]
    for t in reg.tools[:500]:  # cap to keep the list manageable
        src = t.get("source", "x")
        name = t.get("name", "?")
        out.append({
            "uri": f"tool://{src}/{name}",
            "name": f"{src}:{name}",
            "mimeType": "application/json",
        })
    # Catalog entries as resources
    try:
        from core.mcp.catalog_bridge import list_catalog_tools
        cat = list_catalog_tools(limit=300)
        for t in cat.get("tools") or []:
            eid = t.get("id") or t.get("name") or "?"
            out.append({
                "uri": f"catalog://entry/{eid}",
                "name": t.get("mcp_name") or eid,
                "mimeType": "application/json",
            })
    except Exception:
        pass
    return out


def resources_read(uri: str) -> str:
    reg = _registry()
    if uri == "registry://summary":
        return json.dumps({
            "total": len(reg.tools),
            "by_domain": reg._by_domain_counts(),
            "sources": {s: sum(1 for t in reg.tools if t.get("source") == s)
                        for s in ("toolbox", "kali", "kali-dpkg", "venv", "catalog")},
        }, indent=2)
    if uri == "catalog://summary":
        try:
            from core.mcp.catalog_bridge import catalog_source_stats
            return json.dumps(catalog_source_stats(), indent=2, default=str)
        except Exception as e:
            return json.dumps({"error": str(e)})
    if uri.startswith("catalog://entry/"):
        eid = uri[len("catalog://entry/"):]
        try:
            from core.mcp.catalog_bridge import get_catalog_tool
            return json.dumps(get_catalog_tool(eid), indent=2, default=str)
        except Exception as e:
            return json.dumps({"error": str(e)})
    if uri.startswith("tool://"):
        rest = uri[len("tool://"):]
        if "/" in rest:
            src, name = rest.split("/", 1)
            for t in reg.tools:
                if t.get("source") == src and t.get("name") == name:
                    return json.dumps(_public_record(t), indent=2)
            if src == "catalog":
                try:
                    from core.mcp.catalog_bridge import get_catalog_tool
                    return json.dumps(get_catalog_tool(name), indent=2, default=str)
                except Exception as e:
                    return json.dumps({"error": str(e)})
        return json.dumps({"error": "resource not found"})
    return json.dumps({"error": "unknown resource"})


# ---------------------------------------------------------------------------
# JSON-RPC dispatch
# ---------------------------------------------------------------------------
def _result(req_id: Any, result: Any) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def _error(req_id: Any, code: int, message: str, data: Any = None) -> Dict[str, Any]:
    err = {"code": code, "message": message}
    if data is not None:
        err["data"] = data
    return {"jsonrpc": "2.0", "id": req_id, "error": err}


def handle_request(req: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Return a response dict, or None for notifications (no response)."""
    method = req.get("method")
    req_id = req.get("id")
    params = req.get("params") or {}
    args = params.get("arguments") or {} if isinstance(params, dict) else {}

    # --- lifecycle ---
    if method == "initialize":
        return _result(req_id, {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {
                "tools": {},
                "resources": {},
            },
            "serverInfo": SERVER_INFO,
        })
    if method == "notifications/initialized":
        return None  # notification — no response
    if method == "ping":
        return _result(req_id, {})

    # --- tools ---
    if method == "tools/list":
        # Dynamic: meta tools + wrappers + every catalog entry from SQL
        return _result(req_id, {"tools": _all_mcp_tools_for_list()})
    if method == "tools/call":
        name = params.get("name")
        try:
            if name in _TOOL_DISPATCH:
                out = _TOOL_DISPATCH[name](args)
            elif name and (
                str(name).startswith("catalog.")
                or str(name).startswith("github:")
                or str(name).startswith("kali:")
            ):
                # Virtual per-entry catalog tool
                from core.mcp.catalog_bridge import run_catalog_tool
                out = run_catalog_tool(
                    name,
                    args=args if isinstance(args, dict) else {},
                    timeout=int((args or {}).get("timeout") or 120),
                    command=str((args or {}).get("command") or ""),
                )
            else:
                # Try schema'd wrappers then catalog by plain name
                try:
                    from core.mcp.tools import call_mcp_tool, get_mcp_tool
                    if get_mcp_tool(name) is not None:
                        out = call_mcp_tool(
                            name,
                            args if isinstance(args, dict) else {},
                            timeout=int((args or {}).get("timeout") or 30),
                        )
                    else:
                        from core.mcp.catalog_bridge import (
                            run_catalog_tool, get_catalog_tool,
                        )
                        if get_catalog_tool(name).get("ok"):
                            out = run_catalog_tool(
                                name,
                                args=args if isinstance(args, dict) else {},
                                timeout=int((args or {}).get("timeout") or 120),
                                command=str((args or {}).get("command") or ""),
                            )
                        else:
                            return _error(req_id, -32602, f"unknown tool: {name}")
                except Exception:
                    return _error(req_id, -32602, f"unknown tool: {name}")
            # MCP expects content blocks; wrap structured data as text.
            return _result(req_id, {
                "content": [{"type": "text",
                             "text": json.dumps(out, indent=2, default=str)}],
                "isError": bool(
                    isinstance(out, dict)
                    and (out.get("error") or out.get("blocked"))
                ),
            })
        except Exception as e:
            logger.exception("tool call failed")
            return _error(req_id, -32603, f"tool error: {e}")

    # --- resources ---
    if method == "resources/list":
        return _result(req_id, {"resources": resources_list()})
    if method == "resources/read":
        uri = params.get("uri") or args.get("uri")
        if not uri:
            return _error(req_id, -32602, "uri required")
        return _result(req_id, {
            "contents": [{"uri": uri, "mimeType": "application/json",
                          "text": resources_read(uri)}]
        })

    return _error(req_id, -32601, f"method not found: {method}")


# ---------------------------------------------------------------------------
# Stdio loop
# ---------------------------------------------------------------------------
def _read_line() -> Optional[Dict[str, Any]]:
    line = sys.stdin.readline()
    if not line:
        return None
    line = line.strip()
    if not line:
        return {}
    try:
        return json.loads(line)
    except json.JSONDecodeError:
        return {"__bad_json": line}


def serve():
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s",
                        stream=sys.stderr)
    logger.info("KFIOSA MCP server up (stdio); protocol %s", PROTOCOL_VERSION)
    while True:
        req = _read_line()
        if req is None:
            break  # EOF — client gone
        if not req or req.get("__bad_json"):
            if req and req.get("__bad_json"):
                resp = _error(None, -32700, "parse error",
                              data=req["__bad_json"][:200])
                sys.stdout.write(json.dumps(resp) + "\n")
                sys.stdout.flush()
            continue
        resp = handle_request(req)
        if resp is not None:
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()


def _handle_conn(conn, addr):
    """Serve one TCP client: newline-delimited JSON-RPC."""
    import threading as _t
    try:
        f = conn.makefile("rwb")
        for raw in f:
            line = raw.decode("utf-8", "replace").strip()
            if not line:
                continue
            try:
                req = json.loads(line)
            except json.JSONDecodeError:
                conn.sendall((json.dumps(_error(None, -32700, "parse error",
                                                data=line[:200])) + "\n").encode())
                continue
            resp = handle_request(req)
            if resp is not None:
                conn.sendall((json.dumps(resp) + "\n").encode())
    except Exception as e:
        logger.debug(f"tcp conn {addr} ended: {e}")
    finally:
        try:
            conn.close()
        except Exception:
            pass


def serve_tcp(host: str = "127.0.0.1", port: int = 12700):
    """Long-lived loopback TCP MCP server (multi-client, threaded).

    Each client speaks newline-delimited JSON-RPC 2.0 over its socket — same
    protocol as the stdio server. The KFIOSA dashboard auto-starts this so AI
    clients can connect while the tool runs (env overrides:
    KFIOSA_MCP_HOST, KFIOSA_MCP_PORT).
    """
    import socket
    import threading as _t
    host = os.getenv("KFIOSA_MCP_HOST", host)
    port = int(os.getenv("KFIOSA_MCP_PORT", str(port)))
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind((host, port))
    except OSError as e:
        logger.error("cannot bind %s:%d — %s", host, port, e)
        sys.stderr.write(f"KFIOSA MCP: bind failed {host}:{port}: {e}\n")
        return
    srv.listen(16)
    srv.settimeout(1.0)
    logger.info("KFIOSA MCP server up (tcp) on %s:%d; protocol %s",
                host, port, PROTOCOL_VERSION)
    sys.stderr.write(f"KFIOSA MCP tcp listening on {host}:{port}\n")
    sys.stderr.flush()
    # Lightweight readiness ping printed for the launcher to detect.
    while True:
        try:
            conn, addr = srv.accept()
        except socket.timeout:
            # idle tick — lets a signal/cooperative shutdown be added later
            continue
        except OSError:
            break
        _t.Thread(target=_handle_conn, args=(conn, addr), daemon=True).start()


# ---------------------------------------------------------------------------
# Self-test (no client needed)
# ---------------------------------------------------------------------------
def self_test() -> int:
    """Exercise every method in-process so the server is debuggable standalone."""
    print("=== initialize ===")
    print(json.dumps(handle_request({"jsonrpc": "2.0", "id": 1,
                                     "method": "initialize"})["result"]["serverInfo"]))
    print("=== tools/list ===")
    print([t["name"] for t in handle_request({"jsonrpc": "2.0", "id": 2,
            "method": "tools/list"})["result"]["tools"]])
    print("=== tools/call list_tools(domain=wifi, limit=3) ===")
    r = handle_request({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                        "params": {"name": "list_tools",
                                   "arguments": {"domain": "wifi", "limit": 3}}})
    print(json.loads(r["result"]["content"][0]["text"])["count"], "wifi tools")
    print("=== tools/call search_tools(query=aircrack) ===")
    r = handle_request({"jsonrpc": "2.0", "id": 4, "method": "tools/call",
                        "params": {"name": "search_tools",
                                   "arguments": {"query": "aircrack", "limit": 3}}})
    print(json.loads(r["result"]["content"][0]["text"])["count"], "matches")
    print("=== tools/call get_tool_usage(name=aircrack-ng) ===")
    r = handle_request({"jsonrpc": "2.0", "id": 5, "method": "tools/call",
                        "params": {"name": "get_tool_usage",
                                   "arguments": {"name": "aircrack-ng",
                                                 "source": "kali"}}})
    rec = json.loads(r["result"]["content"][0]["text"])
    print("name:", rec.get("name"), "| usage:", rec.get("usage"))
    print("=== tools/call run_tool(blocked by default) ===")
    r = handle_request({"jsonrpc": "2.0", "id": 6, "method": "tools/call",
                        "params": {"name": "run_tool",
                                   "arguments": {"command": "echo hi"}}})
    print(json.loads(r["result"]["content"][0]["text"]))
    print("=== tools/call catalog_stats ===")
    r = handle_request({"jsonrpc": "2.0", "id": 9, "method": "tools/call",
                        "params": {"name": "catalog_stats", "arguments": {}}})
    print(json.loads(r["result"]["content"][0]["text"]))
    print("=== tools/call catalog_list(limit=2) ===")
    r = handle_request({"jsonrpc": "2.0", "id": 10, "method": "tools/call",
                        "params": {"name": "catalog_list",
                                   "arguments": {"limit": 2}}})
    print("catalog_list count",
          json.loads(r["result"]["content"][0]["text"]).get("count"))
    print("=== resources/list (first 3) ===")
    print(handle_request({"jsonrpc": "2.0", "id": 7,
                          "method": "resources/list"})["result"]["resources"][:3])
    print("=== resources/read registry://summary ===")
    r = handle_request({"jsonrpc": "2.0", "id": 8,
                        "method": "resources/read",
                        "params": {"uri": "registry://summary"}})
    print(r["result"]["contents"][0]["text"][:200])
    print("=== resources/read catalog://summary ===")
    r = handle_request({"jsonrpc": "2.0", "id": 11,
                        "method": "resources/read",
                        "params": {"uri": "catalog://summary"}})
    print(r["result"]["contents"][0]["text"][:200])
    print("=== notifications/initialized (should be None) ===")
    print(handle_request({"jsonrpc": "2.0", "method": "notifications/initialized"}))
    print("SELF-TEST OK")
    return 0


def _parse_tcp_args(argv: List[str]) -> Tuple[bool, str, int]:
    """Return (use_tcp, host, port) parsed from argv."""
    use_tcp = False
    host = "127.0.0.1"
    port = 12700
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--host":
            use_tcp = True
            host = argv[i + 1] if i + 1 < len(argv) else host
            i += 2
            continue
        if a == "--port":
            use_tcp = True
            port = int(argv[i + 1]) if i + 1 < len(argv) else port
            i += 2
            continue
        if a.startswith("--host="):
            use_tcp = True
            host = a.split("=", 1)[1]
        elif a.startswith("--port="):
            use_tcp = True
            port = int(a.split("=", 1)[1])
        i += 1
    return use_tcp, host, port


def main(argv: Optional[List[str]] = None) -> int:
    argv = argv or sys.argv[1:]
    if "--self-test" in argv:
        return self_test()
    use_tcp, host, port = _parse_tcp_args(argv)
    if use_tcp:
        serve_tcp(host=host, port=port)
    else:
        serve()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


# ---------------------------------------------------------------------------
# Convenience re-exports for dashboard / orchestrator DI
# ---------------------------------------------------------------------------
def call_mcp_tool(name: str, args: Optional[Dict[str, Any]] = None,
                  timeout: int = 30) -> Dict[str, Any]:
    """In-process MCP tool dispatch (Kali / mt7921e / recon / …).

    Re-exported from :mod:`core.mcp.tools` so callers can write
    ``from core.mcp import call_mcp_tool`` (the dashboard MCP client
    wiring depends on this). Lazy import avoids import cycles.
    """
    from core.mcp.tools import call_mcp_tool as _call
    return _call(name, args or {}, timeout=timeout)


# ---------------------------------------------------------------------------
# 4-touchpoint pattern: explicit public surface.
# ---------------------------------------------------------------------------
__all__ = [
    # Constants
    "MCP_TOOLS",
    "PROTOCOL_VERSION",
    "PROJECT_ROOT",
    "SERVER_INFO",
    # Tool handlers
    "t_call_tool",
    "t_get_tool_usage",
    "t_list_tools",
    "t_run_tool",
    "t_search_tools",
    # In-process tool dispatch (dashboard / orchestrator)
    "call_mcp_tool",
    # Resource handlers
    "resources_list",
    "resources_read",
    # Request / server lifecycle
    "handle_request",
    "self_test",
    "serve",
    "serve_tcp",
    "main",
    # Submodule
    "tools",
]