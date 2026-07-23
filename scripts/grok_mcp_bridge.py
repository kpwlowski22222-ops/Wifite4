#!/usr/bin/env python3
"""
Grok Agent MCP Co-Worker Bridge
================================
Enables collaborative co-working with xAI's Grok agent powered by the KFIOSA
Model Context Protocol (MCP) server.

The Grok agent receives KFIOSA's full tool definitions (Kali pentest tools,
mt7921e injection frame tools, CVE lookups, OSINT, and recon probes) via MCP
and executes tools safely through the KFIOSA MCP server.

Usage:
    python3 scripts/grok_mcp_bridge.py --prompt "Audit network for vulnerable targets"
    python3 scripts/grok_mcp_bridge.py --interactive
"""

import argparse
import json
import logging
import os
import sys
import requests
from pathlib import Path
from typing import Any, Dict, List, Optional

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.mcp.tools import KALI_TOOL_WRAPPERS, call_mcp_tool
from core.ai_backend import AIBackend

logging.basicConfig(level=logging.INFO, format="[GrokMCP] %(levelname)s: %(message)s")
logger = logging.getLogger("grok_mcp_bridge")

XAI_API_ENDPOINT = "https://api.x.ai/v1/chat/completions"


def get_grok_api_key() -> str:
    key = os.getenv("GROK_API_KEY") or os.getenv("XAI_API_KEY") or ""
    if not key:
        logger.warning(
            "Neither GROK_API_KEY nor XAI_API_KEY is set in environment. "
            "Set GROK_API_KEY to communicate with xAI Grok models."
        )
    return key


def mcp_tools_to_openai_tools(domain: Optional[str] = None, limit: int = 30) -> List[Dict[str, Any]]:
    """Convert KFIOSA MCP tools into OpenAI/Grok function call schema format."""
    tools = []
    count = 0
    for name, wrapper in KALI_TOOL_WRAPPERS.items():
        if limit and count >= limit:
            break
        rec = wrapper.as_mcp_record()
        schema = rec.get("inputSchema") or {"type": "object", "properties": {}}
        tools.append({
            "type": "function",
            "function": {
                "name": name,
                "description": rec.get("description") or f"KFIOSA MCP tool {name}",
                "parameters": schema,
            }
        })
        count += 1
    return tools


def run_grok_cowork_session(prompt: str, model: str = "grok-2-latest", max_turns: int = 10):
    """Run a co-working loop between the user prompt and Grok via MCP tool calls."""
    api_key = get_grok_api_key()
    if not api_key:
        print("\n[!] Cannot start Grok API session without GROK_API_KEY or XAI_API_KEY.")
        print("[!] Please export GROK_API_KEY='your-xai-key' and try again.\n")
        return False

    print(f"\n[+] Starting Grok Co-Worker Session (Model: {model})")
    print(f"[+] User Prompt: {prompt}\n")

    mcp_tools = mcp_tools_to_openai_tools(limit=40)
    messages = [
        {
            "role": "system",
            "content": (
                "You are an expert AI security analyst co-working with the operator inside KFIOSA. "
                "You have access to real security tools via Model Context Protocol (MCP). "
                "Use the available MCP tools to scan, investigate, and perform security analysis. "
                "Be thorough, structured, and report findings clearly."
            ),
        },
        {"role": "user", "content": prompt},
    ]

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}",
    }

    for turn in range(1, max_turns + 1):
        print(f"--- [Turn {turn}/{max_turns}] Querying Grok ---")
        payload = {
            "model": model,
            "messages": messages,
            "tools": mcp_tools,
            "temperature": 0.2,
        }

        try:
            resp = requests.post(XAI_API_ENDPOINT, headers=headers, json=payload, timeout=45)
            if resp.status_code != 200:
                print(f"[!] Grok API returned status {resp.status_code}: {resp.text[:300]}")
                break

            data = resp.json()
            choice = data["choices"][0]
            msg = choice["message"]
            messages.append(msg)

            content = msg.get("content")
            if content:
                print(f"\n[Grok Agent Response]:\n{content}\n")

            tool_calls = msg.get("tool_calls")
            if not tool_calls:
                print("[+] Grok completed response without further tool calls.")
                break

            for tc in tool_calls:
                fn_name = tc["function"]["name"]
                fn_args_raw = tc["function"].get("arguments", "{}")
                try:
                    fn_args = json.loads(fn_args_raw) if isinstance(fn_args_raw, str) else fn_args_raw
                except Exception:
                    fn_args = {}

                print(f"[+] Executing MCP Tool Call: {fn_name}({fn_args})")
                result = call_mcp_tool(fn_name, fn_args)

                result_str = json.dumps(result, indent=2)
                if len(result_str) > 4000:
                    result_str = result_str[:4000] + "\n...[truncated]"

                messages.append({
                    "role": "tool",
                    "tool_call_id": tc["id"],
                    "content": result_str,
                })

        except Exception as e:
            print(f"[!] Error during Grok co-working iteration: {e}")
            break

    print("\n[+] Grok Co-Worker Session finished.\n")
    return True


def main():
    parser = argparse.ArgumentParser(description="Grok Agent MCP Co-Worker Bridge")
    parser.add_argument("--prompt", type=str, help="Initial prompt / instruction for Grok")
    parser.add_argument("--model", type=str, default="grok-2-latest", help="Grok model name (default: grok-2-latest)")
    parser.add_argument("--interactive", action="store_true", help="Interactive terminal mode")

    args = parser.parse_args()

    if args.interactive or not args.prompt:
        prompt = input("Enter instruction for Grok Agent Co-Worker: ").strip()
        if not prompt:
            prompt = "Perform initial security status check and list available MCP capabilities."
    else:
        prompt = args.prompt

    run_grok_cowork_session(prompt=prompt, model=args.model)


if __name__ == "__main__":
    main()
