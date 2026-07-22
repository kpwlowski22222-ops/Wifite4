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


def _ollama_endpoint(settings: Any = None) -> str:
    endpoint = "http://127.0.0.1:11434"
    if settings is not None:
        try:
            endpoint = settings.get_setting("ollama.endpoint", endpoint) or endpoint
        except Exception:
            pass
    endpoint = os.getenv("OLLAMA_HOST", endpoint) or endpoint
    if endpoint and "://" not in endpoint:
        endpoint = "http://" + endpoint
    return endpoint.rstrip("/")


def _model_present(pulled: List[str], wanted: str) -> bool:
    """Loose match: exact, basename, or either side contains the other."""
    if not wanted:
        return False
    w = wanted.lower().strip()
    w_base = w.split("/")[-1]
    for m in pulled:
        ml = (m or "").lower()
        if not ml:
            continue
        if ml == w or ml.split(":")[0] == w.split(":")[0]:
            return True
        if w_base and (w_base in ml or ml.split("/")[-1] in w):
            return True
        # hf.co/... vs short tag
        if w.replace("hf.co/", "") in ml or ml.replace("hf.co/", "") in w:
            return True
    return False


def ensure_ollama_ready(
    settings: Any = None,
    on_event=None,
    pull_missing: bool = False,
    start_serve: bool = True,
) -> Dict[str, Any]:
    """Start ``ollama serve`` if needed and verify preferred models.

    Preferred models come from:
      1. settings ``ollama.domain_models`` values
      2. ``core.ai_backend.MODEL_CATALOG`` core domains (wifi, primary, …)

    By default does **not** auto-pull large models (can take hours). Set
    ``pull_missing=True`` or env ``KFIOSA_OLLAMA_PULL=1`` to pull missing
    tags. Always attempts to start the daemon when unreachable.
    """
    log = on_event or (lambda _m: None)
    endpoint = _ollama_endpoint(settings)
    report: Dict[str, Any] = {
        "endpoint": endpoint,
        "reachable": False,
        "started_serve": False,
        "models": [],
        "missing": [],
        "present_preferred": [],
        "error": "",
    }

    info = check_ollama(endpoint)
    if not info["reachable"] and start_serve and shutil.which("ollama"):
        log("[*] Ollama unreachable — starting `ollama serve` in background…")
        try:
            import subprocess
            subprocess.Popen(
                ["ollama", "serve"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL,
                start_new_session=True,
            )
            report["started_serve"] = True
            # Wait briefly for the API.
            import time
            for _ in range(20):
                time.sleep(0.5)
                info = check_ollama(endpoint)
                if info["reachable"]:
                    break
        except Exception as e:
            report["error"] = f"ollama serve failed: {e}"
            log(f"[!] {report['error']}")

    report["reachable"] = bool(info.get("reachable"))
    report["models"] = list(info.get("models") or [])
    if not report["reachable"]:
        report["error"] = report["error"] or "Ollama API unreachable"
        return report

    # Build preferred model list.
    preferred: List[str] = []
    if settings is not None:
        try:
            dm = settings.get_setting("ollama.domain_models", {}) or {}
            if isinstance(dm, dict):
                preferred.extend(str(v) for v in dm.values() if v)
        except Exception:
            pass
    try:
        from core.ai_backend import MODEL_CATALOG
        for key in (
            "primary", "wifi", "ble", "osint", "post_exploitation",
            "c2", "anti_forensics", "fallback", "tier1_local_fallback",
        ):
            tag = MODEL_CATALOG.get(key)
            if tag:
                preferred.append(tag)
    except Exception:
        pass
    # de-dupe preserve order
    seen = set()
    uniq: List[str] = []
    for p in preferred:
        if p not in seen:
            seen.add(p)
            uniq.append(p)
    preferred = uniq

    pulled = report["models"]
    missing = [p for p in preferred if not _model_present(pulled, p)]
    present = [p for p in preferred if _model_present(pulled, p)]
    report["missing"] = missing
    report["present_preferred"] = present

    do_pull = pull_missing or os.getenv("KFIOSA_OLLAMA_PULL", "0") == "1"
    if missing:
        log(f"[i] Preferred models missing ({len(missing)}): "
            f"{', '.join(missing[:5])}{'…' if len(missing) > 5 else ''}")
        if do_pull and shutil.which("ollama"):
            import subprocess
            for tag in missing[:3]:  # cap auto-pulls
                log(f"[*] ollama pull {tag} …")
                try:
                    subprocess.run(
                        ["ollama", "pull", tag],
                        timeout=600,
                        capture_output=True,
                        text=True,
                    )
                except Exception as e:
                    log(f"[!] pull {tag}: {e}")
            info = check_ollama(endpoint)
            report["models"] = list(info.get("models") or [])
        else:
            log("[i] Skipping auto-pull (set KFIOSA_OLLAMA_PULL=1 to pull). "
                "Using best available local model for each domain.")
    else:
        log("[+] All preferred Ollama models present (or aliased).")

    # Best-model map for orchestrator: domain → first available match.
    report["domain_model_map"] = _resolve_domain_models(report["models"], settings)
    return report


def _resolve_domain_models(
    pulled: List[str], settings: Any = None
) -> Dict[str, str]:
    """Pick the best available model per domain from what is actually pulled.

    Priority per domain:
      settings override → MODEL_CATALOG domain tag → primary → wifi/pentester
      → any uncensored → first pulled.
    """
    out: Dict[str, str] = {}
    try:
        from core.ai_backend import MODEL_CATALOG
    except Exception:
        MODEL_CATALOG = {}

    domains = (
        "wifi", "ble", "osint", "post_exploitation", "c2",
        "forensics", "anti_forensics", "primary",
    )
    overrides: Dict[str, str] = {}
    if settings is not None:
        try:
            overrides = dict(settings.get_setting("ollama.domain_models", {}) or {})
        except Exception:
            overrides = {}

    def first_match(candidates: List[str]) -> str:
        for c in candidates:
            if _model_present(pulled, c):
                # return the actual pulled name when possible
                cl = c.lower()
                for m in pulled:
                    ml = (m or "").lower()
                    if ml == cl or cl.split(":")[0] in ml or ml.split(":")[0] in cl:
                        return m
                    if c.split("/")[-1].lower() in ml:
                        return m
                return c
        return ""

    fallbacks = [
        MODEL_CATALOG.get("primary", ""),
        MODEL_CATALOG.get("wifi", "xploiter/pentester:latest"),
        "xploiter/pentester:latest",
        "supergoatscriptguy/mythos-sec:24b",
        "wizard-vicuna-uncensored:latest",
        "llama2-uncensored:latest",
    ]
    any_uncen = next(
        (m for m in pulled if "uncensor" in m.lower() or "pentester" in m.lower()
         or "mythos" in m.lower() or "abliterat" in m.lower()),
        pulled[0] if pulled else "",
    )

    for dom in domains:
        cands = [
            overrides.get(dom, ""),
            MODEL_CATALOG.get(dom, ""),
            *fallbacks,
            any_uncen,
        ]
        pick = first_match([c for c in cands if c])
        if pick:
            out[dom] = pick
    return out


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