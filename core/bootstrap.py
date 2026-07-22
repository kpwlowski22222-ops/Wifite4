#!/usr/bin/env python3
"""
KFIOSA Bootstrap / Preflight
=============================
Detects the runtime environment before curses takes over: optional Python
deps, Ollama reachability + pulled models, and the full offensive toolchain
(aircrack-ng suite, hcxtools, hostapd, bluez, Metasploit, OSINT CLIs, …).

The returned tool map drives the orchestrator: a step whose tool is missing
errors out rather than faking execution.
"""

import logging
import os
import shutil
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

# Hard-fail (TUI cannot function) vs degrade (feature disabled).
_HARD_DEPS = ["requests", "curses"]
_SOFT_DEPS = ["dotenv", "bleak", "shodan", "aiohttp"]

# Every real CLI the offensive chains rely on.
_TOOLCHAIN: List[str] = [
    # WiFi
    "iw", "ip", "airodump-ng", "aireplay-ng", "aircrack-ng",
    "hcxdumptool", "hcxpcapngtool", "hashcat", "hostapd", "dnsmasq",
    "wash", "reaver", "bully", "pixiewps",
    # BLE
    "bluetoothctl", "hcitool", "gatttool", "bettercap",
    # Exploitation / post
    "msfconsole", "msfvenom", "nmap",
    # OSINT
    "sherlock", "holehe", "toutatis", "phoneinfoga",
    "theHarvester", "subfinder", "amass", "shodan",
]


def check_requirements() -> Dict[str, bool]:
    """Return a {dep: present} map. Hard deps missing → caller may abort."""
    out: Dict[str, bool] = {}
    for dep in _HARD_DEPS + _SOFT_DEPS:
        try:
            if dep == "dotenv":
                import importlib
                importlib.import_module("dotenv")
            else:
                __import__(dep)
            out[dep] = True
        except Exception:
            out[dep] = False
    return out


def check_tools() -> Dict[str, bool]:
    """Return a {tool: installed} map for the offensive CLI toolchain."""
    return {tool: bool(shutil.which(tool)) for tool in _TOOLCHAIN}


def check_ollama(endpoint: str = "http://127.0.0.1:11434") -> Dict[str, Any]:
    """Probe a local Ollama instance.

    Returns {reachable, models, endpoint}.
    """
    info: Dict[str, Any] = {"reachable": False, "models": [], "endpoint": endpoint}
    try:
        import requests
        ep = endpoint
        if ep and "://" not in ep:
            ep = "http://" + ep
        r = requests.get(f"{ep.rstrip('/')}/api/tags", timeout=5)
        if r.status_code == 200:
            info["reachable"] = True
            info["models"] = [
                m.get("name", "")
                for m in r.json().get("models", [])
                if m.get("name")
            ]
    except Exception as e:
        logger.debug(f"Ollama probe failed: {e}")
    return info


def preflight(settings: Any = None) -> Dict[str, Any]:
    """Run all checks and return a single report dict.

    Args:
        settings: a SettingsManager (or None) — used to read the configured
            Ollama endpoint.
    Prints a human-readable present/missing table to stdout (pre-curses).
    """
    deps = check_requirements()
    tools = check_tools()

    endpoint = "http://127.0.0.1:11434"
    if settings is not None:
        try:
            endpoint = settings.get_setting("ollama.endpoint", endpoint) or endpoint
        except Exception:
            pass
    endpoint = os.getenv("OLLAMA_HOST", endpoint)
    ollama = check_ollama(endpoint)

    # Pretty-print before curses.
    print("=" * 64)
    print(" KFIOSA PREFLIGHT")
    print("=" * 64)

    print("\n[Python deps]")
    for dep in _HARD_DEPS + _SOFT_DEPS:
        mark = "OK " if deps.get(dep) else "MISSING"
        label = " (required)" if dep in _HARD_DEPS else " (optional)"
        print(f"  {mark:8} {dep}{label}")

    print("\n[Ollama]")
    if ollama["reachable"]:
        print(f"  OK       endpoint {ollama['endpoint']}  ({len(ollama['models'])} models)")
        for m in ollama["models"]:
            print(f"             - {m}")
    else:
        print(f"  UNREACHABLE  {ollama['endpoint']}  (AI will fall back to Groq/heuristic)")

    print("\n[Offensive toolchain]")
    present = [t for t, ok in tools.items() if ok]
    missing = [t for t, ok in tools.items() if not ok]
    if present:
        print(f"  present ({len(present)}): {', '.join(present)}")
    if missing:
        print(f"  missing ({len(missing)}): {', '.join(missing)}")
    if not missing:
        print("  all toolchain binaries found on PATH")

    hard_missing = [d for d in _HARD_DEPS if not deps.get(d)]
    print("\n" + "=" * 64)
    if hard_missing:
        print(f"  [!] Hard deps missing: {', '.join(hard_missing)} — TUI may fail.")
    else:
        print("  [+] Ready to launch the dashboard.")
    print("=" * 64 + "\n")

    return {
        "deps": deps,
        "tools": tools,
        "ollama": ollama,
        "hard_missing": hard_missing,
    }


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    preflight()