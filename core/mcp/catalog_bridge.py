"""MCP bridge: every catalog/ entry (+ SQL projection) as AI-callable tools.

Sources (router picks fastest)::

  * SQLite catalog DB (``core.catalog.sql_store``) when ingested
  * On-disk ``catalog/*.json`` / memory index otherwise
  * Tool registry (toolboxes / Kali / venv) remains separate

MCP meta-tools (always registered)::

  catalog_sync, catalog_stats, catalog_list, catalog_search,
  catalog_get, catalog_run, catalog_surfaces

Each catalog entry can also appear as a virtual tool name::

  catalog.<sanitized_id>

Execution is gated (``KFIOSA_MCP_ALLOW_EXEC=1``) and only runs real
entry points under ``toolboxes/`` or PATH binaries — never fabricates
output.
"""
from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

PROJECT_ROOT = Path(__file__).resolve().parents[2]
_CATALOG_DIR = PROJECT_ROOT / "catalog"
_SKIP = frozenset({
    "catalog.schema.json", "catalog.txt", "catalog.min.json",
})

_SAFE = re.compile(r"[^a-zA-Z0-9_.-]+")


def _safe_name(entry_id: str, name: str = "") -> str:
    base = (name or entry_id or "tool").strip()
    base = base.replace("/", "_").replace(":", "_").replace(" ", "_")
    base = _SAFE.sub("_", base).strip("._")[:64] or "tool"
    return f"catalog.{base}"


def _first(val: Any) -> str:
    if isinstance(val, list) and val:
        return str(val[0])
    if isinstance(val, str):
        return val
    return ""


def _entry_to_tool(entry: Dict[str, Any], *, path: str = "") -> Dict[str, Any]:
    """Normalize a catalog JSON object into a registry-like tool record."""
    eid = str(entry.get("id") or path or entry.get("name") or "unknown")
    name = str(entry.get("name") or eid.split("/")[-1] or eid)
    surface = _first(entry.get("attack_surface")).lower()
    phase = _first(entry.get("phase_hint")).lower()
    tags = entry.get("tags") if isinstance(entry.get("tags"), list) else []
    # Domain mapping from attack surface
    domain = surface or "misc"
    if domain in ("post", "post-exploit"):
        domain = "post_exploitation"
    if domain in ("wireless", "wlan"):
        domain = "wifi"
    docs = entry.get("documentation") if isinstance(entry.get("documentation"), dict) else {}
    usage: List[str] = []
    for u in (docs.get("usage_sections") or entry.get("command_examples") or [])[:8]:
        if isinstance(u, str) and u.strip():
            usage.append(u.strip()[:300])
        elif isinstance(u, dict) and u.get("command"):
            usage.append(str(u["command"])[:300])
        elif isinstance(u, dict) and u.get("name"):
            usage.append(str(u.get("name"))[:80])
    # Entry points from toolbox_path
    entry_points: List[str] = []
    tb = entry.get("toolbox_path") or entry.get("path") or ""
    if tb:
        entry_points.append(str(tb))
    for ep in entry.get("entry_points") or []:
        if isinstance(ep, str):
            entry_points.append(ep)
        elif isinstance(ep, dict) and ep.get("path"):
            entry_points.append(str(ep["path"]))
    # install / packages
    cmds = entry.get("commands") or entry.get("install") or []
    if isinstance(cmds, list):
        for c in cmds[:5]:
            if isinstance(c, str):
                usage.append(c[:200])
            elif isinstance(c, dict) and c.get("cmd"):
                usage.append(str(c["cmd"])[:200])

    desc = (
        entry.get("summary")
        or entry.get("description")
        or entry.get("title")
        or ""
    )
    if isinstance(desc, str) and len(desc) > 400:
        desc = desc[:400] + "…"

    return {
        "name": name,
        "mcp_name": _safe_name(eid, name),
        "id": eid,
        "source": "catalog",
        "domain": domain,
        "path": path or str(entry.get("toolbox_path") or ""),
        "url": entry.get("url") or entry.get("homepage") or "",
        "description": desc,
        "usage": usage,
        "entry_points": entry_points,
        "language": entry.get("language") or "",
        "kind": entry.get("kind") or "",
        "category": entry.get("category") or "",
        "attack_surface": surface,
        "phase_hint": phase,
        "tags": tags,
        "full_name": entry.get("full_name") or "",
        "toolbox_path": entry.get("toolbox_path") or "",
    }


# ---------------------------------------------------------------------------
# Source: SQL preferred, JSON fallback
# ---------------------------------------------------------------------------
def catalog_source_stats() -> Dict[str, Any]:
    try:
        from core.catalog.sql_store import sql_ready, count_stats
        if sql_ready():
            st = count_stats(refresh=False)
            return {
                "ok": True,
                "source": "sql",
                "total": st.get("total") or 0,
                "by_kind": st.get("by_kind") or {},
                "by_surface": st.get("by_surface") or {},
            }
    except Exception as e:
        sql_err = str(e)[:80]
    else:
        sql_err = ""
    # disk count
    n = 0
    if _CATALOG_DIR.is_dir():
        n = sum(1 for p in _CATALOG_DIR.glob("*.json") if p.name not in _SKIP)
    return {
        "ok": True,
        "source": "json",
        "total": n,
        "sql_ready": False,
        "sql_error": sql_err,
    }


def sync_catalog_to_sql(*, force: bool = False, max_files: int = 0) -> Dict[str, Any]:
    """Ingest catalog/*.json into SQL so MCP can serve every tool fast."""
    try:
        from core.catalog.sql_store import ingest_catalog
        return ingest_catalog(
            _CATALOG_DIR, force=force, max_files=max_files or 0,
        )
    except Exception as e:
        return {"ok": False, "error": str(e)[:200]}


def list_catalog_tools(
    *,
    domain: str = "",
    surface: str = "",
    kind: str = "",
    text: str = "",
    limit: int = 200,
    offset: int = 0,
    prefer: str = "",
) -> Dict[str, Any]:
    """List tools from SQL catalog (or file index). Paginated."""
    limit = max(1, min(int(limit or 200), 2000))
    offset = max(0, int(offset or 0))
    t0 = time.time()

    # Prefer SQL
    use_sql = (prefer or "").lower() in ("", "sql", "auto")
    if use_sql:
        try:
            from core.catalog.sql_store import search_sql, sql_ready, count_stats
            if sql_ready():
                # fetch a page — SQL search doesn't offset; over-fetch then slice
                need = offset + limit
                r = search_sql(
                    attack_surface=surface or domain,
                    kind=kind,
                    text=text,
                    limit=min(need, 2000),
                    include_payload=True,
                )
                if r.get("ok"):
                    raw = r.get("results") or []
                    tools = [
                        _entry_to_tool(e, path=str(e.get("_path") or ""))
                        for e in raw
                        if isinstance(e, dict)
                    ]
                    # domain filter soft-match
                    if domain and not surface:
                        d = domain.lower()
                        tools = [
                            t for t in tools
                            if d in (t.get("domain") or "")
                            or d in (t.get("attack_surface") or "")
                            or d in (t.get("category") or "").lower()
                        ]
                    page = tools[offset: offset + limit]
                    total = count_stats(refresh=False).get("total") or len(tools)
                    return {
                        "ok": True,
                        "source": "sql",
                        "count": len(page),
                        "total_estimate": total,
                        "offset": offset,
                        "limit": limit,
                        "tools": page,
                        "took_s": round(time.time() - t0, 4),
                    }
        except Exception as e:
            sql_fallback = str(e)[:120]
    else:
        sql_fallback = ""

    # Router / memory index
    try:
        from core.catalog.source_router import fetch
        r = fetch(
            text=text,
            attack_surface=surface or domain,
            kind=kind,
            limit=offset + limit,
            prefer=prefer or "memory",
            catalog_dir=_CATALOG_DIR,
        )
        raw = r.get("results") or []
        tools = [_entry_to_tool(e) for e in raw if isinstance(e, dict)]
        page = tools[offset: offset + limit]
        return {
            "ok": True,
            "source": r.get("source_used") or "json",
            "count": len(page),
            "total_estimate": len(tools),
            "offset": offset,
            "limit": limit,
            "tools": page,
            "took_s": round(time.time() - t0, 4),
            "note": sql_fallback or None,
        }
    except Exception as e:
        return {"ok": False, "error": str(e)[:200], "tools": []}


def get_catalog_tool(name_or_id: str) -> Dict[str, Any]:
    """Resolve by id, mcp_name, name, or filename."""
    q = (name_or_id or "").strip()
    if not q:
        return {"ok": False, "error": "name required"}
    # strip catalog. prefix
    bare = q[8:] if q.startswith("catalog.") else q

    # SQL by id
    try:
        from core.catalog.sql_store import get_by_id, get_by_path, search_sql, sql_ready
        if sql_ready():
            ent = get_by_id(q) or get_by_id(bare)
            if ent is None and "/" not in bare:
                # try github:Owner/Repo style
                ent = get_by_id(f"github:{bare.replace('_', '/')}")
            if ent is None:
                ent = get_by_path(bare) or get_by_path(q)
            if ent is None:
                # FTS name
                r = search_sql(text=bare.replace("_", " "), limit=5)
                for e in r.get("results") or []:
                    t = _entry_to_tool(e)
                    if (
                        t.get("name", "").lower() == bare.lower()
                        or t.get("mcp_name") == q
                        or bare.lower() in (t.get("id") or "").lower()
                    ):
                        return {"ok": True, "tool": t, "entry": e, "source": "sql"}
                if r.get("results"):
                    e = r["results"][0]
                    return {"ok": True, "tool": _entry_to_tool(e), "entry": e, "source": "sql"}
            if ent:
                return {"ok": True, "tool": _entry_to_tool(ent), "entry": ent, "source": "sql"}
    except Exception as e:
        err = str(e)[:100]
    else:
        err = ""

    # JSON file walk (slow path)
    if _CATALOG_DIR.is_dir():
        # exact file
        for p in _CATALOG_DIR.glob("*.json"):
            if p.name in _SKIP:
                continue
            if bare in p.stem or q in p.stem:
                try:
                    ent = json.loads(p.read_text(encoding="utf-8"))
                    return {
                        "ok": True,
                        "tool": _entry_to_tool(ent, path=str(p)),
                        "entry": ent,
                        "source": "json",
                    }
                except Exception:
                    continue
    return {"ok": False, "error": f"not found: {q}", "detail": err}


def run_catalog_tool(
    name_or_id: str,
    *,
    args: Optional[Dict[str, Any]] = None,
    timeout: int = 120,
    command: str = "",
) -> Dict[str, Any]:
    """Execute a catalog tool entry point (gated).

    Modes:
      * ``command`` — explicit argv string (must relate to tool path)
      * auto — first runnable entry point under toolbox_path
    """
    if os.getenv("KFIOSA_MCP_ALLOW_EXEC") != "1":
        return {
            "ok": False,
            "blocked": True,
            "reason": "set KFIOSA_MCP_ALLOW_EXEC=1 to allow catalog tool execution",
            "tool": name_or_id,
        }
    got = get_catalog_tool(name_or_id)
    if not got.get("ok"):
        return got
    tool = got["tool"]
    args = args or {}

    # Explicit command
    if command:
        return _run_argv(command, timeout=timeout, cwd=str(PROJECT_ROOT))

    # Build from toolbox
    tb = tool.get("toolbox_path") or tool.get("path") or ""
    tb_path = Path(tb)
    if not tb_path.is_absolute():
        tb_path = PROJECT_ROOT / tb
    if tb_path.is_dir():
        # Prefer known entry scripts
        candidates = []
        for pat in ("*.py", "*.sh", "main.py", "cli.py", "run.py"):
            candidates.extend(sorted(tb_path.glob(pat))[:5])
        for c in candidates:
            if c.name.startswith("test"):
                continue
            if c.suffix == ".py":
                argv = f"{os.environ.get('KFIOSA_PYTHON') or 'python3'} {c}"
            else:
                argv = str(c)
            # Pass through simple args
            extra = args.get("argv") or args.get("args")
            if isinstance(extra, str) and extra.strip():
                argv = f"{argv} {extra}"
            elif isinstance(extra, list):
                argv = argv + " " + " ".join(shlex.quote(str(x)) for x in extra)
            return _run_argv(argv, timeout=timeout, cwd=str(tb_path))

    # PATH binary by name
    name = tool.get("name") or ""
    if name:
        extra = args.get("argv") or ""
        if isinstance(extra, list):
            extra = " ".join(shlex.quote(str(x)) for x in extra)
        cmd = f"{name} {extra}".strip()
        return _run_argv(cmd, timeout=timeout, cwd=str(PROJECT_ROOT))

    return {
        "ok": False,
        "error": "no runnable entry point (clone toolbox or pass command=)",
        "tool": tool.get("mcp_name"),
        "toolbox_path": tb,
    }


def _run_argv(command: str, *, timeout: int, cwd: str) -> Dict[str, Any]:
    try:
        argv = shlex.split(command)
    except ValueError as e:
        return {"ok": False, "error": f"bad command: {e}"}
    try:
        p = subprocess.run(
            argv, capture_output=True, text=True,
            timeout=timeout, cwd=cwd,
        )
        return {
            "ok": p.returncode == 0,
            "rc": p.returncode,
            "stdout": (p.stdout or "")[-6000:],
            "stderr": (p.stderr or "")[-3000:],
            "command": command,
        }
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "timeout", "timeout": timeout, "command": command}
    except FileNotFoundError:
        return {"ok": False, "error": f"not found: {argv[0]}", "command": command}
    except Exception as e:
        return {"ok": False, "error": str(e)[:200], "command": command}


def expand_mcp_tool_records(
    *,
    limit: int = 500,
    domain: str = "",
) -> List[Dict[str, Any]]:
    """Build MCP tools/list records for catalog entries (virtual tools)."""
    limit = max(1, min(int(limit or 500), 2000))
    listed = list_catalog_tools(domain=domain, limit=limit)
    out: List[Dict[str, Any]] = []
    for t in listed.get("tools") or []:
        mcp_name = t.get("mcp_name") or _safe_name(t.get("id") or "", t.get("name") or "")
        desc = (t.get("description") or t.get("name") or mcp_name)[:200]
        out.append({
            "name": mcp_name,
            "description": (
                f"[catalog/{t.get('source', 'catalog')}] {desc} "
                f"(surface={t.get('attack_surface') or '-'}, "
                f"kind={t.get('kind') or '-'})"
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "argv": {
                        "type": "string",
                        "description": "extra CLI arguments",
                    },
                    "timeout": {"type": "integer", "default": 120},
                    "command": {
                        "type": "string",
                        "description": "override full command (gated)",
                    },
                },
            },
            "_catalog_id": t.get("id"),
            "_catalog_name": t.get("name"),
        })
    return out


def merge_into_registry() -> Dict[str, Any]:
    """Merge catalog tools into ToolRegistry and persist."""
    try:
        from core.tool_registry import ToolRegistry
        reg = ToolRegistry()
        reg.load()
        # Remove previous catalog source entries
        reg.tools = [t for t in reg.tools if t.get("source") != "catalog"]
        listed = list_catalog_tools(limit=5000)
        added = 0
        for t in listed.get("tools") or []:
            rec = {
                "name": t.get("name"),
                "source": "catalog",
                "domain": t.get("domain") or "misc",
                "path": t.get("toolbox_path") or t.get("path") or "",
                "url": t.get("url") or "",
                "description": t.get("description") or "",
                "usage": t.get("usage") or [],
                "entry_points": t.get("entry_points") or [],
                "language": t.get("language") or "",
                "id": t.get("id"),
                "mcp_name": t.get("mcp_name"),
                "kind": t.get("kind"),
                "category": t.get("category"),
                "attack_surface": t.get("attack_surface"),
            }
            reg.tools.append(rec)
            added += 1
        reg._reindex()
        reg._save()
        return {
            "ok": True,
            "added": added,
            "total": len(reg.tools),
            "source": listed.get("source"),
        }
    except Exception as e:
        return {"ok": False, "error": str(e)[:200]}
