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

Exposed resources (MCP ``resources/read``):
    registry://summary                         -> build stats
    tool://<source>/<name>                     -> one tool record
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
SERVER_INFO = {"name": "kfiosa-tool-mcp", "version": "1.0.0"}


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
    tools = reg.tools
    if domain:
        tools = [t for t in tools if t.get("domain") == domain]
    if source:
        tools = [t for t in tools if t.get("source") == source]
    out = [_public_record(t) for t in tools[:limit]]
    # Also surface the schema'd MCP tool wrappers (Kali + mt7921e.* +
    # cve_lookup). The new AI chain uses these directly.
    try:
        from core.mcp.tools import list_mcp_tools
        out.extend(list_mcp_tools(domain=domain))
    except Exception as e:
        logger.debug(f"mcp.tools.list_mcp_tools failed: {e}")
    return {"count": len(out[:limit]), "tools": out[:limit]}


def t_search_tools(args: Dict[str, Any]) -> Dict[str, Any]:
    query = args.get("query", "")
    if not query:
        return {"error": "query required"}
    reg = _registry()
    results = reg.search(query, limit=int(args.get("limit", 20)))
    return {"query": query, "count": len(results),
            "tools": [_public_record(t) for t in results]}


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
    reg = _registry()
    # Match by name, optionally narrowed by source.
    for t in reg.tools:
        if t.get("name") == name and (not source or t.get("source") == source):
            return _public_record(t)
    return {"error": f"tool not found: {name}"}


def t_call_tool(args: Dict[str, Any]) -> Dict[str, Any]:
    """Invoke a schema'd MCP tool (Kali / mt7921e.* / cve_lookup)."""
    name = args.get("name")
    if not name:
        return {"error": "name required"}
    try:
        from core.mcp.tools import call_mcp_tool
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": f"mcp.tools import: {e}"}
    tool_args = args.get("args") or {}
    timeout = int(args.get("timeout", 30))
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

_TOOL_DISPATCH = {
    "list_tools": t_list_tools,
    "search_tools": t_search_tools,
    "get_tool_usage": t_get_tool_usage,
    "run_tool": t_run_tool,
    "call_tool": t_call_tool,
}


# ---------------------------------------------------------------------------
# Resource handlers
# ---------------------------------------------------------------------------
def resources_list() -> List[Dict[str, Any]]:
    reg = _registry()
    out = [{"uri": "registry://summary", "name": "Registry summary"}]
    for t in reg.tools[:500]:  # cap to keep the list manageable
        src = t.get("source", "x")
        name = t.get("name", "?")
        out.append({
            "uri": f"tool://{src}/{name}",
            "name": f"{src}:{name}",
            "mimeType": "application/json",
        })
    return out


def resources_read(uri: str) -> str:
    reg = _registry()
    if uri == "registry://summary":
        return json.dumps({
            "total": len(reg.tools),
            "by_domain": reg._by_domain_counts(),
            "sources": {s: sum(1 for t in reg.tools if t.get("source") == s)
                        for s in ("toolbox", "kali", "kali-dpkg", "venv")},
        }, indent=2)
    if uri.startswith("tool://"):
        rest = uri[len("tool://"):]
        if "/" in rest:
            src, name = rest.split("/", 1)
            for t in reg.tools:
                if t.get("source") == src and t.get("name") == name:
                    return json.dumps(_public_record(t), indent=2)
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
        return _result(req_id, {"tools": MCP_TOOLS})
    if method == "tools/call":
        name = params.get("name")
        if name not in _TOOL_DISPATCH:
            return _error(req_id, -32602, f"unknown tool: {name}")
        try:
            out = _TOOL_DISPATCH[name](args)
            # MCP expects content blocks; wrap structured data as text.
            return _result(req_id, {
                "content": [{"type": "text",
                             "text": json.dumps(out, indent=2, default=str)}],
                "isError": bool(isinstance(out, dict) and out.get("error")),
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
    print("=== resources/list (first 3) ===")
    print(handle_request({"jsonrpc": "2.0", "id": 7,
                          "method": "resources/list"})["result"]["resources"][:3])
    print("=== resources/read registry://summary ===")
    r = handle_request({"jsonrpc": "2.0", "id": 8,
                        "method": "resources/read",
                        "params": {"uri": "registry://summary"}})
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