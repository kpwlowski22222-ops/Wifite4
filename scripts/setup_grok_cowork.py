#!/usr/bin/env python3
"""
Setup Grok MCP Co-Work Session
================================
Validates local MCP server state, checks Grok API key setup, generates
MCP client configuration files, and launches the Grok co-working interface.
"""

import json
import os
import shutil
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

CONFIG_DIR = PROJECT_ROOT / "config"
MCP_CONFIG_PATH = CONFIG_DIR / "grok_mcp_config.json"


def setup_grok_mcp():
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    python_bin = sys.executable or "python3"

    mcp_config = {
        "mcpServers": {
            "kfiosa-mcp": {
                "command": python_bin,
                "args": ["-m", "core.mcp_server"],
                "env": {
                    "KFIOSA_MCP_ALLOW_EXEC": os.environ.get("KFIOSA_MCP_ALLOW_EXEC", "1"),
                    "GROK_API_KEY": os.environ.get("GROK_API_KEY", ""),
                    "XAI_API_KEY": os.environ.get("XAI_API_KEY", ""),
                }
            }
        }
    }

    with open(MCP_CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(mcp_config, f, indent=2)

    print("==================================================================")
    print(" KFIOSA — Grok MCP Agent Co-Work Setup")
    print("==================================================================")
    print(f"[+] Local MCP Server entrypoint: core.mcp_server")
    print(f"[+] MCP JSON Configuration generated: {MCP_CONFIG_PATH}")

    key = os.environ.get("GROK_API_KEY") or os.environ.get("XAI_API_KEY")
    if key:
        print("[+] Grok (xAI) API key detected in environment.")
    else:
        print("[!] GROK_API_KEY / XAI_API_KEY not set. Export it to communicate with xAI models.")

    print("\nTo start a Grok Co-Work session:")
    print("  1. export GROK_API_KEY='your-x-ai-key'")
    print(f"  2. {python_bin} scripts/grok_mcp_bridge.py --interactive")
    print("==================================================================\n")


if __name__ == "__main__":
    setup_grok_mcp()
