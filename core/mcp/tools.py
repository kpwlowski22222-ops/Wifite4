#!/usr/bin/env python3
"""
MCP Tool Wrappers
==================
Per-tool MCP function-call wrappers for the AI chain. Each tool gets:

- a JSON Schema for its arguments,
- a description (when to use, what it returns),
- a risk level that drives the ACCEPT/CANCEL gate wording,
- a ``run`` implementation that actually invokes the underlying
  subprocess / function.

Three families are exposed:

1. ``KALI_TOOL_WRAPPERS`` — one wrapper per entry in
   :data:`core.tool_registry.KALI_TOOL_ALLOWLIST`. These produce
   schema'd MCP functions for the AI to call by name (instead of
   using the generic ``run_tool`` subprocess path).
2. ``mt7921e.*`` — the MediaTek MT7922 (mt7921e) packet-injection surface
   (:mod:`core.modules.mt7921e_tools`). Surfaced as the AI's
   driver-specific affordance for raw 802.11 frame injection.
3. ``cve_lookup`` — wraps :mod:`core.modules.cve_lookup` so the AI can
   ask for CVE data as part of the chain.

The wrappers are *not* the orchestrator's execution path. They are
listed/exposed via the MCP server (``core.mcp_server``) so external
clients and the chain planner can both see the same surface.
"""

from __future__ import annotations

import base64
import logging
import os
import shlex
import shutil
import subprocess
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Risk levels (drive the ACCEPT/CANCEL gate wording in the orchestrator)
# ---------------------------------------------------------------------------
RISK_READ = "read"          # passive recon; no side effect
RISK_INTRUSIVE = "intrusive"  # sends frames / packets; visible to target
RISK_DESTRUCTIVE = "destructive"  # may lock accounts, crash, exfil data


# ---------------------------------------------------------------------------
# Generic Kali tool wrapper
# ---------------------------------------------------------------------------
class KaliToolWrapper:
    """Schema'd MCP function for a Kali CLI tool.

    Each wrapper is a thin layer over a real subprocess call to the
    tool's binary. Args are validated against ``input_schema`` (light
    validation — JSON Schema is documented, not strictly enforced,
    because the AI's JSON output is best-effort and the orchestrator
    re-validates via its own gate).
    """

    def __init__(self, name: str, binary: str, description: str,
                 input_schema: Dict[str, Any], examples: List[str],
                 risk_level: str = RISK_INTRUSIVE,
                 requires_root: bool = True,
                 runner: Optional[Callable[..., Dict[str, Any]]] = None):
        self.name = name
        self.binary = binary
        self.description = description
        self.input_schema = input_schema
        self.examples = examples
        self.risk_level = risk_level
        self.requires_root = requires_root
        self._runner = runner

    def as_mcp_record(self) -> Dict[str, Any]:
        """Serialize to the public MCP ``tools/list`` record."""
        return {
            "name": self.name,
            "description": self.description,
            "inputSchema": self.input_schema,
            "risk_level": self.risk_level,
            "requires_root": self.requires_root,
            "examples": self.examples,
            "binary": self.binary,
        }

    def run(self, args: Dict[str, Any], timeout: int = 120,
            cwd: Optional[str] = None) -> Dict[str, Any]:
        """Invoke the underlying tool. ``args`` is a flat dict whose
        keys become ``--key value`` argv. Returns ``{ok, stdout,
        stderr, returncode}``."""
        if self._runner is not None:
            return self._runner(args, timeout=timeout, cwd=cwd)
        if not shutil.which(self.binary):
            return {"ok": False, "error": f"{self.binary} not installed",
                    "stdout": "", "stderr": "", "returncode": -1}
        if self.requires_root and os.geteuid() != 0:
            return {"ok": False, "error": "needs root",
                    "stdout": "", "stderr": "", "returncode": -1}
        argv = [self.binary]
        for k, v in (args or {}).items():
            flag = "--" + k.replace("_", "-")
            if isinstance(v, bool):
                if v:
                    argv.append(flag)
            elif v is None:
                continue
            else:
                argv.extend([flag, str(v)])
        try:
            p = subprocess.run(
                argv, capture_output=True, text=True,
                timeout=timeout, cwd=cwd,
            )
            return {
                "ok": p.returncode == 0,
                "stdout": p.stdout[-4000:],
                "stderr": p.stderr[-2000:],
                "returncode": p.returncode,
            }
        except subprocess.TimeoutExpired:
            return {"ok": False, "error": f"timeout after {timeout}s",
                    "stdout": "", "stderr": "", "returncode": -1}
        except FileNotFoundError:
            return {"ok": False, "error": f"{self.binary} not found at exec",
                    "stdout": "", "stderr": "", "returncode": -1}
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "error": str(e),
                    "stdout": "", "stderr": "", "returncode": -1}


# ---------------------------------------------------------------------------
# Wrappers for the most-used Kali tools (schema'd MCP functions)
# ---------------------------------------------------------------------------
def _make_kali_wrappers() -> Dict[str, KaliToolWrapper]:
    """Build a dict of name -> KaliToolWrapper for the most-used
    wifi/ble/osint/post-exploit Kali tools.

    Per-tool args schemas are deliberately minimal — the AI sees
    enough to construct reasonable invocations. The orchestrator
    does the final safety gate.
    """
    out: Dict[str, KaliToolWrapper] = {}

    # ----- WiFi
    out["airodump-ng"] = KaliToolWrapper(
        name="airodump-ng", binary="airodump-ng",
        description="Capture 802.11 frames and AP/client metadata. "
                    "Use as the first step in any wifi chain.",
        input_schema={
            "type": "object",
            "properties": {
                "channel": {"type": "integer",
                            "description": "channel to lock on (1-196)"},
                "bssid": {"type": "string",
                          "description": "target BSSID (xx:xx:xx:xx:xx:xx)"},
                "write": {"type": "string",
                          "description": "output file prefix"},
                "interface": {"type": "string",
                              "description": "monitor-mode interface (e.g. wlan0mon)"},
                "output_format": {"type": "string", "enum": ["csv", "pcap", "both"],
                                  "default": "both"},
            },
            "required": ["interface"],
        },
        examples=[
            "airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:01 -w cap wlan0mon",
            "airodump-ng wlan0mon",
        ],
        risk_level=RISK_INTRUSIVE,
    )
    out["aireplay-ng"] = KaliToolWrapper(
        name="aireplay-ng", binary="aireplay-ng",
        description="Inject 802.11 frames: deauth, fakeauth, replay, ARP "
                    "injection, fragmentation. Use after airodump confirms "
                    "the target AP and clients.",
        input_schema={
            "type": "object",
            "properties": {
                "deauth": {"type": "integer",
                           "description": "number of deauth frames (0 = broadcast infinite)"},
                "fakeauth": {"type": "integer", "description": "fake-auth delay"},
                "replay": {"type": "string", "description": "capture file to replay"},
                "arpreplay": {"type": "boolean",
                              "description": "ARP replay mode (-3)"},
                "fragment": {"type": "boolean",
                             "description": "fragmentation attack (-5)"},
                "bssid": {"type": "string"},
                "client": {"type": "string",
                           "description": "target client MAC (optional)"},
                "interface": {"type": "string"},
            },
            "required": ["interface"],
        },
        examples=[
            "aireplay-ng -0 5 -a AA:BB:CC:DD:EE:01 wlan0mon",
            "aireplay-ng --arpreplay -b AA:BB:CC:DD:EE:01 -w arp wlan0mon",
        ],
        risk_level=RISK_DESTRUCTIVE,
    )
    out["aircrack-ng"] = KaliToolWrapper(
        name="aircrack-ng", binary="aircrack-ng",
        description="Offline WEP/WPA-PSK key recovery from a capture file. "
                    "Use after airodump captured a handshake.",
        input_schema={
            "type": "object",
            "properties": {
                "wordlist": {"type": "string"},
                "bssid": {"type": "string"},
                "capture": {"type": "string", "description": ".cap or .hccapx file"},
            },
            "required": ["capture"],
        },
        examples=["aircrack-ng -w rockyou.txt -b AA:BB:CC:DD:EE:01 handshake.cap"],
        risk_level=RISK_READ,
    )
    out["wash"] = KaliToolWrapper(
        name="wash", binary="wash",
        description="Probe WPS-enabled APs. Use as a fast scan before reaver/bully.",
        input_schema={"type": "object", "properties": {
            "interface": {"type": "string"},
            "scan_time": {"type": "integer", "default": 30},
        }, "required": ["interface"]},
        examples=["wash -i wlan0mon"],
        risk_level=RISK_INTRUSIVE,
    )
    out["reaver"] = KaliToolWrapper(
        name="reaver", binary="reaver",
        description="WPS Pixie-Dust / online PIN attack.",
        input_schema={"type": "object", "properties": {
            "interface": {"type": "string"},
            "bssid": {"type": "string"},
            "pixie_dust": {"type": "boolean", "default": True},
        }, "required": ["interface", "bssid"]},
        examples=["reaver -i wlan0mon -b AA:BB:CC:DD:EE:01 -vv -K 1"],
        risk_level=RISK_INTRUSIVE,
    )

    # ----- BLE
    out["gatttool"] = KaliToolWrapper(
        name="gatttool", binary="gatttool",
        description="GATT enumeration / characteristic read+write. Use on "
                    "BLE targets after hcitool/bettercap recon.",
        input_schema={"type": "object", "properties": {
            "address": {"type": "string"},
            "interactive": {"type": "boolean", "default": True},
        }, "required": ["address"]},
        examples=["gatttool -b AA:BB:CC:DD:EE:F1 -I"],
        risk_level=RISK_INTRUSIVE,
    )

    # ----- OSINT
    out["nmap"] = KaliToolWrapper(
        name="nmap", binary="nmap",
        description="Network/port/service recon. Use on any IP target.",
        input_schema={"type": "object", "properties": {
            "target": {"type": "string"},
            "ports": {"type": "string", "default": "1-65535"},
            "service_detection": {"type": "boolean", "default": True},
            "scripts": {"type": "string", "description": "nmap script category"},
        }, "required": ["target"]},
        examples=["nmap -sV -p- 192.168.1.1"],
        risk_level=RISK_INTRUSIVE,
    )

    # ----- Hash cracking
    out["hashcat"] = KaliToolWrapper(
        name="hashcat", binary="hashcat",
        description="GPU/CPU hash cracker. Use on aircrack-ng output, "
                    "hash dumps, or any recovered hash.",
        input_schema={"type": "object", "properties": {
            "hash_file": {"type": "string"},
            "mode": {"type": "integer", "description": "hashcat -m mode"},
            "wordlist": {"type": "string"},
        }, "required": ["hash_file", "mode"]},
        examples=["hashcat -m 22000 -a 0 cap.hc22000 rockyou.txt"],
        risk_level=RISK_READ,
    )

    # ----- Post-exploit
    out["msfconsole"] = KaliToolWrapper(
        name="msfconsole", binary="msfconsole",
        description="Metasploit console. Use for exploit + post-exploit. "
                    "Always gated by confirm_fn; the orchestrator should "
                    "prefer build_msf_script + run_msfconsole_script for "
                    "automated flows.",
        input_schema={"type": "object", "properties": {
            "resource": {"type": "string",
                         "description": ".rc resource file"},
            "execute": {"type": "string",
                        "description": "inline -x command string"},
            "quiet": {"type": "boolean", "default": True},
        }},
        examples=["msfconsole -q -x 'use auxiliary/scanner/...'"],
        risk_level=RISK_DESTRUCTIVE,
    )

    return out


# ---------------------------------------------------------------------------
# mt7921e MCP function group
# ---------------------------------------------------------------------------
def _make_mt7921e_wrappers() -> Dict[str, KaliToolWrapper]:
    """mt7921e-specific MCP functions. The runner calls the real
    :mod:`core.modules.mt7921e_tools` functions so we don't duplicate
    subprocess plumbing."""
    from core.modules import mt7921e_tools

    def _runner(fn):
        def _r(args, timeout=30, cwd=None):
            try:
                return fn(args, timeout=timeout)
            except Exception as e:  # noqa: BLE001
                return {"ok": False, "error": str(e)}
        return _r

    out: Dict[str, KaliToolWrapper] = {}
    out["mt7921e.detect"] = KaliToolWrapper(
        name="mt7921e.detect", binary="mt7921e_tools.detect_mt7921e_interfaces",
        description="Detect MediaTek MT7922 (mt7921e / mt7921u) Wi-Fi adapters "
                    "(MediaTek MT7922 Wi-Fi 6E M.2 card via the in-tree "
                    "mt7921e driver). "
                    "Use when the operator's adapter is one of these.",
        input_schema={"type": "object", "properties": {}},
        examples=["mt7921e.detect()"],
        risk_level=RISK_READ, requires_root=False,
        runner=_runner(lambda args, timeout: {
            "ok": True,
            "interfaces": [a.as_dict()
                           for a in mt7921e_tools.detect_mt7921e_interfaces()],
        }),
    )
    out["mt7921e.test_injection"] = KaliToolWrapper(
        name="mt7921e.test_injection", binary="aireplay-ng",
        description="Runtime injection-quality test (aireplay-ng --test). "
                    "Reports a 0-100 quality score. Use before any "
                    "injection-heavy step.",
        input_schema={"type": "object", "properties": {
            "iface": {"type": "string"},
            "bssid": {"type": "string", "default": "FF:FF:FF:FF:FF:FF"},
        }, "required": ["iface"]},
        examples=["mt7921e.test_injection(iface='wlan1mon')"],
        risk_level=RISK_INTRUSIVE,
        runner=_runner(lambda args, timeout: mt7921e_tools.test_injection(
            iface=args["iface"],
            bssid=args.get("bssid", "FF:FF:FF:FF:FF:FF"),
            timeout=timeout,
        )),
    )
    out["mt7921e.set_channel"] = KaliToolWrapper(
        name="mt7921e.set_channel", binary="iw",
        description="Set the mt7921e interface to a specific channel. "
                    "Use to follow a target BSSID's channel hop.",
        input_schema={"type": "object", "properties": {
            "iface": {"type": "string"},
            "channel": {"type": "integer"},
        }, "required": ["iface", "channel"]},
        examples=["mt7921e.set_channel(iface='wlan1mon', channel=6)"],
        risk_level=RISK_INTRUSIVE,
        runner=_runner(lambda args, timeout: mt7921e_tools.set_channel(
            iface=args["iface"], channel=int(args["channel"]),
        )),
    )
    out["mt7921e.set_txpower"] = KaliToolWrapper(
        name="mt7921e.set_txpower", binary="iw",
        description="Set transmit power in dBm. Falls back to 'auto' on "
                    "out-of-range / unsupported hardware.",
        input_schema={"type": "object", "properties": {
            "iface": {"type": "string"},
            "dbm": {"type": "integer"},
        }, "required": ["iface", "dbm"]},
        examples=["mt7921e.set_txpower(iface='wlan1mon', dbm=20)"],
        risk_level=RISK_INTRUSIVE,
        runner=_runner(lambda args, timeout: mt7921e_tools.set_txpower(
            iface=args["iface"], dbm=int(args["dbm"]),
        )),
    )
    out["mt7921e.inject_frame"] = KaliToolWrapper(
        name="mt7921e.inject_frame", binary="scapy",
        description="Send a raw 802.11 frame on the mt7921e interface. "
                    "Frame bytes may be passed base64-encoded via the "
                    "``frame_b64`` field. Falls back to a clear error "
                    "when scapy is not installed.",
        input_schema={"type": "object", "properties": {
            "iface": {"type": "string"},
            "frame_b64": {"type": "string",
                          "description": "base64-encoded 802.11 frame"},
            "channel": {"type": "integer", "description": "optional"},
        }, "required": ["iface", "frame_b64"]},
        examples=["mt7921e.inject_frame(iface='wlan1mon', frame_b64='<base64>')"],
        risk_level=RISK_DESTRUCTIVE,
        runner=_runner(lambda args, timeout: mt7921e_tools.inject_raw_frame(
            iface=args["iface"],
            frame_bytes=args.get("frame_b64", ""),
            channel=args.get("channel"),
            b64=True,
        )),
    )
    return out


# ---------------------------------------------------------------------------
# cve_lookup MCP wrapper
# ---------------------------------------------------------------------------
def _make_cve_wrapper() -> KaliToolWrapper:
    """Wrap :mod:`core.modules.cve_lookup.CVELookup` as an MCP function.

    Looks up CVEs by keyword / CPE via the NVD API. Uses the
    centralized key resolution from :func:`core.ai_backend.get_nvd_key`.
    """
    def _runner(args, timeout=30, cwd=None):
        try:
            from core.ai_backend import get_nvd_key
            from core.modules.cve_lookup import CVELookup
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "error": f"import: {e}"}
        key = get_nvd_key()
        if not key:
            return {"ok": False, "error": "no NVD key configured",
                    "hint": "set NVD_API_KEY env or settings.nvd.api_key"}
        # CVELookup.__init__(self, config) wants a config dict; the NVD
        # key reaches the request via the ``apiKey`` header
        # (cve_lookup.py:63 reads config["nvd_api_key"]).
        try:
            lookup = CVELookup(config={"nvd_api_key": key})
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "error": f"CVELookup init: {e}"}
        # search_cves is an async coroutine (cve_lookup.py:41) — run it
        # to completion on a fresh loop, then close the aiohttp session.
        import asyncio
        keyword = args.get("keyword", "")
        limit = int(args.get("limit", 5))
        try:
            try:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                results = loop.run_until_complete(
                    lookup.search_cves(keyword, limit=limit))
            finally:
                try:
                    loop.run_until_complete(lookup.close())
                except Exception:  # noqa: BLE001 — best-effort close
                    pass
                loop.close()
            return {"ok": True, "count": len(results) if results else 0,
                    "cves": results, "results": results}
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "error": str(e)}

    return KaliToolWrapper(
        name="cve_lookup", binary="NVD",
        description="Look up CVEs by keyword / CPE from the NVD API. "
                    "Use to enrich a target with known CVEs before planning "
                    "an exploit chain.",
        input_schema={"type": "object", "properties": {
            "keyword": {"type": "string"},
            "limit": {"type": "integer", "default": 5},
        }, "required": ["keyword"]},
        examples=["cve_lookup(keyword='MediaTek MT7922', limit=5)"],
        risk_level=RISK_READ, requires_root=False,
        runner=_runner,
    )


# ---------------------------------------------------------------------------
# CVE -> exploit pipeline wrapper
# ---------------------------------------------------------------------------
def _run_cve_to_exploit(args: Dict[str, Any]) -> Dict[str, Any]:
    """Run the CVE -> exploit pipeline for a single CVE.

    Routes through :func:`core.cve_to_exploit.cve_to_exploit_pipeline`.
    The pipeline is honest: when NVD is unreachable, the model is
    unavailable, or the model refuses, the wrapper returns
    ``{"ok": False, "error": "..."}`` with the full result envelope.
    Never raises.

    Note: the per-step ACCEPT/CANCEL gate fires in the orchestrator's
    ``_walk_ai_step`` BEFORE this runner is called — this runner does
    not re-confirm (single-gate invariant).
    """
    cve_id = (args.get("cve_id") or "").strip()
    if not cve_id:
        return {"ok": False, "error": "cve_to_exploit: cve_id is required"}
    try:
        from core.cve_to_exploit import cve_to_exploit_pipeline
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": f"cve_to_exploit import: {e}"}
    try:
        result = cve_to_exploit_pipeline(cve_id)
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": f"cve_to_exploit raised: {e}"}
    # The pipeline already returns CveToExploitResult. Use the
    # dataclass's to_dict() when present; else construct the dict.
    if hasattr(result, "to_dict"):
        d = result.to_dict()
    else:
        d = {
            "cve_id": getattr(result, "cve_id", cve_id),
            "ok": bool(getattr(result, "ok", False)),
            "exploit_code": getattr(result, "exploit_code", "") or "",
            "model_used": getattr(result, "model_used", None),
            "nvd_meta": getattr(result, "nvd_meta", None),
            "prompt": getattr(result, "prompt", "") or "",
            "error": getattr(result, "error", None),
            "ts": getattr(result, "ts", 0.0),
            "affected": getattr(result, "affected", []),
            "cvss_score": getattr(result, "cvss_score", None),
        }
    return d


def _make_cve_to_exploit_wrappers() -> Dict[str, "KaliToolWrapper"]:
    return {
        "cve_to_exploit": KaliToolWrapper(
            name="cve_to_exploit",
            binary="core.cve_to_exploit",
            description="CVE -> exploit pipeline. Given a CVE id, looks up "
                        "the affected vendor/product/version + CVSS via the "
                        "NVD API (using NVD_API_KEY from env), ensures an "
                        "uncensored code-architect model is available in "
                        "Ollama (ollama pull hf.co/<repo>), and asks the "
                        "model to draft a working Python exploit. Returns "
                        "the raw model text — never claims success when the "
                        "model refused or errored.",
            input_schema={
                "type": "object",
                "properties": {
                    "cve_id": {
                        "type": "string",
                        "description": "CVE id (e.g. 'CVE-2024-1234').",
                    },
                },
                "required": ["cve_id"],
            },
            examples=["cve_to_exploit(cve_id='CVE-2024-1234')"],
            risk_level=RISK_INTRUSIVE,
            requires_root=False,
            runner=_run_cve_to_exploit,
        ),
    }


# ---------------------------------------------------------------------------
# External injection toolbox wrappers (toolboxes/wifi/*)
# ---------------------------------------------------------------------------
def _make_external_injection_wrappers() -> Dict[str, KaliToolWrapper]:
    """Wrap the standalone injection tools in
    :mod:`core.modules.external_injection` as schema'd MCP functions so
    the AI chain can emit ``external_inject`` steps that drive nemesis /
    fksvs-inject / wpr_tx / cse508 DNS injection / mt7921e firmware
    build. The runner calls the real Python entrypoints — no subprocess
    plumbing is duplicated here."""
    from core.modules import external_injection as ext

    def _runner(fn):
        def _r(args, timeout=120, cwd=None):
            try:
                return fn(timeout=timeout, **(args or {}))
            except TypeError:
                # some entrypoints take positional args (protocol/iface)
                # — re-try with the legacy flat call shape.
                try:
                    return fn(**(args or {}))
                except Exception as e:  # noqa: BLE001
                    return {"ok": False, "error": str(e)}
            except Exception as e:  # noqa: BLE001
                return {"ok": False, "error": str(e)}
        return _r

    out: Dict[str, KaliToolWrapper] = {}
    for spec in ext.EXTERNAL_INJECTION_TOOLS:
        entrypoint = getattr(ext, spec["entrypoint"])
        out[spec["name"]] = KaliToolWrapper(
            name=spec["name"], binary=spec["binary"],
            description=spec["description"],
            input_schema=spec["input_schema"],
            examples=spec["examples"],
            risk_level=spec.get("risk_level", RISK_INTRUSIVE),
            requires_root=spec.get("requires_root", True),
            runner=_runner(entrypoint),
        )
    return out


# ---------------------------------------------------------------------------
# MCP tools context block — rendered into the chain planner prompt so
# the AI sees each tool's schema, examples and risk level (not just a
# flat name list). Lazy JSON import; never raises.
# ---------------------------------------------------------------------------
def mcp_tools_context_block(domain: Optional[str] = None,
                            limit: int = 30) -> str:
    """Render up to ``limit`` MCP tool records (from
    :func:`list_mcp_tools`) as a compact text block:

        - <name> (risk=<risk_level>): <description>
            schema: <json>
            examples: <ex1>; <ex2>

    Returns ``""`` on any failure (never raises). The chain planner
    injects this so the LLM can pick a tool whose schema matches the
    target/CVE and inherit its ``risk_level``."""
    try:
        import json as _json
        tools = list_mcp_tools(domain)
        lines: List[str] = []
        for t in tools[:limit]:
            schema = t.get("inputSchema") or {}
            try:
                schema_s = _json.dumps(schema) if schema else "{}"
            except Exception:  # noqa: BLE001
                schema_s = str(schema)[:200]
            ex = t.get("examples") or []
            ex_s = "; ".join(str(e) for e in ex[:2])
            desc = (t.get("description") or "").strip().replace("\n", " ")
            lines.append(
                f"- {t.get('name')} (risk={t.get('risk_level')}): "
                f"{desc[:160]}"
            )
            lines.append(f"    schema: {schema_s[:300]}")
            if ex_s:
                lines.append(f"    examples: {ex_s[:200]}")
        return "\n".join(lines)
    except Exception:  # noqa: BLE001 — never raise; empty block is safe
        return ""


# ---------------------------------------------------------------------------
# Recon-probe wrappers (core/modules/catalog_recon.py — the 9 novel
# passive recon algorithms implemented IN the recon module, surfaced here
# as schema'd MCP tools so the AI chain can drive them via ``mcp_call``.
# Unlike the external-injection wrappers these do NOT shell out to a
# fetched binary — the runner calls ``catalog_recon.run_probe``, which
# runs the Python algorithm (airodump-ng/tshark/scapy/gpspipe + custom
# parse) in-module. Risk is ``read`` for all (passive).
# ---------------------------------------------------------------------------
def _make_recon_probe_wrappers() -> Dict[str, KaliToolWrapper]:
    from core.modules.catalog_recon import RECON_PROBES, run_probe as _run_probe
    # Phase 1.6.E: also surface the 9 new recon methods from
    # core.recon.runner (secondary pattern scout). They share the
    # ``recon_probe`` action and risk=read. The runner dispatches
    # both sets through the same orchestrator action.
    try:
        from core.recon.runner import RECONS as RECON_NEW, \
            run_probe as _run_recon_new
    except Exception:  # noqa: BLE001 — never raise out of MCP factory
        RECON_NEW, _run_recon_new = [], None

    def _runner(method: str):
        def _r(args: Dict[str, Any], timeout: int = 120,
               cwd: Optional[str] = None) -> Dict[str, Any]:
            try:
                # ``args`` carries the target fields (bssid/ssid/channel/
                # interface/artifacts) the AI set; run_probe builds a
                # one-shot CatalogRecon from them.
                return _run_probe(method=method, target=args or {})
            except Exception as e:  # noqa: BLE001 — never raise out of MCP
                return {"ok": False, "error": str(e)}
        return _r

    def _runner_new(method: str):
        def _r(args: Dict[str, Any], timeout: int = 120,
               cwd: Optional[str] = None) -> Dict[str, Any]:
            if _run_recon_new is None:
                return {"ok": False,
                        "error": "core.recon.runner not importable"}
            try:
                return _run_recon_new(method=method, args=args or {})
            except Exception as e:  # noqa: BLE001 — never raise out of MCP
                return {"ok": False, "error": str(e)}
        return _r

    out: Dict[str, KaliToolWrapper] = {}
    for spec in RECON_PROBES:
        out[spec["name"]] = KaliToolWrapper(
            name=spec["name"],
            binary="catalog_recon",
            description=spec["description"],
            input_schema=spec["input_schema"],
            examples=spec["examples"],
            risk_level=spec.get("risk_level", RISK_READ),
            requires_root=spec.get("requires_root", False),
            runner=_runner(spec["method"]),
        )
    # Phase 1.6.E: 9 new methods from core.recon.runner.
    for spec in RECON_NEW:
        if spec["name"] in out:
            # Don't shadow a catalog_recon method that happens to
            # share a name (defensive — names should be unique).
            continue
        out[spec["name"]] = KaliToolWrapper(
            name=spec["name"],
            binary="core.recon.runner",
            description=spec["description"],
            input_schema=spec["input_schema"],
            examples=spec["examples"],
            risk_level=spec.get("risk_level", RISK_READ),
            requires_root=spec.get("requires_root", False),
            runner=_runner_new(spec["method"]),
        )
    return out


# ---------------------------------------------------------------------------
# BLE-probe wrappers (core/ble/runner.py — the passive BLE recon
# algorithms from implementacja.txt, implemented IN the BLE module and
# surfaced here as schema'd MCP tools so the AI chain drives them via
# ``mcp_call``. Same shape as the recon-probe wrappers; risk=read (passive).
# ---------------------------------------------------------------------------
def _make_ble_probe_wrappers() -> Dict[str, KaliToolWrapper]:
    from core.ble.runner import BLE_PROBES, run_probe as _run_ble_probe

    def _runner(method: str):
        def _r(args: Dict[str, Any], timeout: int = 120,
               cwd: Optional[str] = None) -> Dict[str, Any]:
            try:
                # ``args`` may carry ``adapter`` (default hci0 = UB500 Plus)
                # plus per-probe inputs (e.g. wifi_mac/ble_mac for
                # cross_device_linker_ble) — pass the whole dict through.
                return _run_ble_probe(method=method,
                                      adapter=(args or {}).get("adapter"),
                                      args=(args or {}))
            except Exception as e:  # noqa: BLE001 — never raise out of MCP
                return {"ok": False, "error": str(e)}
        return _r

    out: Dict[str, KaliToolWrapper] = {}
    for spec in BLE_PROBES:
        out[spec["name"]] = KaliToolWrapper(
            name=spec["name"],
            binary="core.ble.runner",
            description=spec["description"],
            input_schema=spec["input_schema"],
            examples=spec["examples"],
            risk_level=spec.get("risk_level", RISK_READ),
            requires_root=spec.get("requires_root", False),
            runner=_runner(spec["method"]),
        )
    return out


def _make_ble_attack_wrappers() -> Dict[str, KaliToolWrapper]:
    from core.ble.attack_runner import BLE_ATTACKS, run_attack as _run_ble_attack

    def _runner(method: str):
        def _r(args: Dict[str, Any], timeout: int = 120,
               cwd: Optional[str] = None) -> Dict[str, Any]:
            try:
                # ``args`` carries adapter + per-attack inputs (address,
                # uuid, payload, pin_list, session). Pass the whole dict.
                return _run_ble_attack(method=method,
                                       adapter=(args or {}).get("adapter"),
                                       args=(args or {}))
            except Exception as e:  # noqa: BLE001 — never raise out of MCP
                return {"ok": False, "error": str(e)}
        return _r

    out: Dict[str, KaliToolWrapper] = {}
    for spec in BLE_ATTACKS:
        out[spec["name"]] = KaliToolWrapper(
            name=spec["name"],
            binary="core.ble.attack_runner",
            description=spec["description"],
            input_schema=spec["input_schema"],
            examples=spec["examples"],
            risk_level=spec.get("risk_level", RISK_INTRUSIVE),
            requires_root=spec.get("requires_root", False),
            runner=_runner(spec["method"]),
        )
    return out


def _make_wifi_attack_wrappers() -> Dict[str, KaliToolWrapper]:
    from core.wifi_attack.runner import WIFI_ATTACKS, run_attack as _run_wifi_attack

    def _runner(method: str):
        def _r(args: Dict[str, Any], timeout: int = 120,
               cwd: Optional[str] = None) -> Dict[str, Any]:
            try:
                # ``args`` carries adapter (monitor iface, e.g. wlan0mon) +
                # per-attack inputs (interface, bssid, channel, station,
                # cap_file, hash_file, wordlist, plan_steps). Pass the
                # whole dict through.
                return _run_wifi_attack(method=method,
                                        adapter=(args or {}).get("adapter"),
                                        args=(args or {}))
            except Exception as e:  # noqa: BLE001 — never raise out of MCP
                return {"ok": False, "error": str(e)}
        return _r

    out: Dict[str, KaliToolWrapper] = {}
    for spec in WIFI_ATTACKS:
        out[spec["name"]] = KaliToolWrapper(
            name=spec["name"],
            binary="core.wifi_attack.runner",
            description=spec["description"],
            input_schema=spec["input_schema"],
            examples=spec["examples"],
            risk_level=spec.get("risk_level", RISK_INTRUSIVE),
            requires_root=spec.get("requires_root", False),
            runner=_runner(spec["method"]),
        )
    return out


def _make_post_exploit_ext_wrappers() -> Dict[str, KaliToolWrapper]:
    from core.post_exploit.runner_ext import (POST_EXPLOIT_EXT_ATTACKS,
                                                run_attack as _run_pext)

    def _runner(method: str):
        def _r(args: Dict[str, Any], timeout: int = 120,
               cwd: Optional[str] = None) -> Dict[str, Any]:
            try:
                # ``args`` carries adapter + per-attack inputs (target, user,
                # pass, domain, share, out_path, ...). Pass the whole dict.
                return _run_pext(method=method,
                                  adapter=(args or {}).get("adapter"),
                                  args=(args or {}))
            except Exception as e:  # noqa: BLE001 — never raise out of MCP
                return {"ok": False, "error": str(e)}
        return _r

    out: Dict[str, KaliToolWrapper] = {}
    for spec in POST_EXPLOIT_EXT_ATTACKS:
        out[spec["name"]] = KaliToolWrapper(
            name=spec["name"],
            binary="core.post_exploit.runner_ext",
            description=spec["description"],
            input_schema=spec["input_schema"],
            examples=spec["examples"],
            risk_level=spec.get("risk_level", RISK_INTRUSIVE),
            requires_root=spec.get("requires_root", False),
            runner=_runner(spec["method"]),
        )
    return out


# ---------------------------------------------------------------------------
# Microsoft target-class wrappers (Phase 2.0.M0+M1)
# ---------------------------------------------------------------------------
def _make_microsoft_attack_wrappers() -> Dict[str, KaliToolWrapper]:
    """Surface the 8 Microsoft attack-surface read methods as MCP
    wrappers. Read-only (risk=READ). The intrusive / destructive
    surface (impacket psexec, mimikatz, PetitPotam coerce, DCSync)
    is composed from core.post_exploit.runner_ext in Phase 2.0.M2
    and is exposed via the post_exploit_ext wrappers — not these."""
    try:
        from core.microsoft.runner import (
            MICROSOFT_ATTACKS, run_attack as _run_ms)
    except Exception:  # noqa: BLE001
        return {}

    def _runner(method: str):
        def _r(args: Dict[str, Any], timeout: int = 120,
               cwd: Optional[str] = None) -> Dict[str, Any]:
            try:
                return _run_ms(method=method, args=(args or {}))
            except Exception as e:  # noqa: BLE001 — never raise out of MCP
                return {"ok": False, "error": str(e)}
        return _r

    out: Dict[str, KaliToolWrapper] = {}
    for spec in MICROSOFT_ATTACKS:
        out[spec["name"]] = KaliToolWrapper(
            name=spec["name"],
            binary="core.microsoft.runner",
            description=spec["description"],
            input_schema=spec["input_schema"],
            examples=spec["examples"],
            risk_level=spec.get("risk_level", RISK_READ),
            requires_root=spec.get("requires_root", False),
            runner=_runner(spec["method"]),
        )
    return out


# ---------------------------------------------------------------------------
# Android target-class wrappers (Phase 2.0.A0+A1)
# ---------------------------------------------------------------------------
def _make_android_attack_wrappers() -> Dict[str, KaliToolWrapper]:
    """Surface the 8 Android target-class read methods as MCP
    wrappers. Read-only (risk=READ). The 4 intrusive methods
    (frida_trace_attach_method, apktool_repack_with_frida_gadget,
    adb_logcat_pull, drozer_content_provider_enum) are layered on
    in Phase 2.0.A2."""
    try:
        from core.android.runner import (
            ANDROID_ATTACKS, run_attack as _run_android)
    except Exception:  # noqa: BLE001
        return {}

    def _runner(method: str):
        def _r(args: Dict[str, Any], timeout: int = 120,
               cwd: Optional[str] = None) -> Dict[str, Any]:
            try:
                return _run_android(method=method, args=(args or {}))
            except Exception as e:  # noqa: BLE001
                return {"ok": False, "error": str(e)}
        return _r

    out: Dict[str, KaliToolWrapper] = {}
    for spec in ANDROID_ATTACKS:
        out[spec["name"]] = KaliToolWrapper(
            name=spec["name"],
            binary="core.android.runner",
            description=spec["description"],
            input_schema=spec["input_schema"],
            examples=spec["examples"],
            risk_level=spec.get("risk_level", RISK_READ),
            requires_root=spec.get("requires_root", False),
            runner=_runner(spec["method"]),
        )
    return out


# ---------------------------------------------------------------------------
# iOS target-class wrappers (Phase 2.0.I0+I1)
# ---------------------------------------------------------------------------
def _make_ios_attack_wrappers() -> Dict[str, KaliToolWrapper]:
    """Surface the 8 iOS target-class read methods as MCP wrappers.
    Read-only (risk=READ). The 4 intrusive methods
    (ssl_kill_switch_attach, objection_run_method,
    frida_trace_class, idevicebackup2_extract) are layered on in
    Phase 2.0.I2."""
    try:
        from core.ios.runner import (
            IOS_ATTACKS, run_attack as _run_ios)
    except Exception:  # noqa: BLE001
        return {}

    def _runner(method: str):
        def _r(args: Dict[str, Any], timeout: int = 120,
               cwd: Optional[str] = None) -> Dict[str, Any]:
            try:
                return _run_ios(method=method, args=(args or {}))
            except Exception as e:  # noqa: BLE001
                return {"ok": False, "error": str(e)}
        return _r

    out: Dict[str, KaliToolWrapper] = {}
    for spec in IOS_ATTACKS:
        out[spec["name"]] = KaliToolWrapper(
            name=spec["name"],
            binary="core.ios.runner",
            description=spec["description"],
            input_schema=spec["input_schema"],
            examples=spec["examples"],
            risk_level=spec.get("risk_level", RISK_READ),
            requires_root=spec.get("requires_root", False),
            runner=_runner(spec["method"]),
        )
    return out


# ---------------------------------------------------------------------------
# live_target wrappers (Phase 2.0.L)
# ---------------------------------------------------------------------------
def _make_live_target_wrappers() -> Dict[str, KaliToolWrapper]:
    """Surface the 9 whitelist-only polyglot safe-patch
    identifiers (PowerShell / C# / Java / Smali / Swift / plist /
    Mach-O / Frida / BloodHound cypher) as MCP wrappers. The
    live_target module edits KFIOSA's own emitted artifacts (a
    saved .cypher, a Frida .js, a .plist snippet, a .ps1 wrapper)
    — NOT the target machine's code. risk=WRITE."""
    try:
        from core.live_target import (LIVE_TARGET_PATCHES,
                                       run_patch as _run_live)
    except Exception:  # noqa: BLE001
        return {}

    def _runner(patch_id: str):
        def _r(args: Dict[str, Any], timeout: int = 120,
               cwd: Optional[str] = None) -> Dict[str, Any]:
            try:
                return _run_live(patch_id=patch_id,
                                 target_class=(args or {}).get(
                                     "target_class", ""),
                                 params=(args or {}).get("params") or {})
            except Exception as e:  # noqa: BLE001
                return {"ok": False, "error": str(e)}
        return _r

    out: Dict[str, KaliToolWrapper] = {}
    for spec in LIVE_TARGET_PATCHES:
        out[spec["name"]] = KaliToolWrapper(
            name=spec["name"],
            binary="core.live_target",
            description=spec["description"],
            input_schema=spec["input_schema"],
            examples=spec["examples"],
            risk_level=spec.get("risk_level", RISK_INTRUSIVE),
            requires_root=spec.get("requires_root", False),
            runner=_runner(spec["patch_id"]),
        )
    return out


def _make_extended_wifi_wrappers() -> Dict[str, KaliToolWrapper]:
    from core.extended_wifi.runner import (EXT_WIFI_ATTACKS,
                                            run_attack as _run_extwifi)

    def _runner(method: str):
        def _r(args: Dict[str, Any], timeout: int = 120,
               cwd: Optional[str] = None) -> Dict[str, Any]:
            try:
                # ``args`` carries adapter + per-attack inputs (bssid,
                # station, peer, cap_file, channel, count, ssids, ...).
                # Pass the whole dict.
                return _run_extwifi(method=method,
                                     adapter=(args or {}).get("adapter"),
                                     args=(args or {}))
            except Exception as e:  # noqa: BLE001 — never raise out of MCP
                return {"ok": False, "error": str(e)}
        return _r

    out: Dict[str, KaliToolWrapper] = {}
    for spec in EXT_WIFI_ATTACKS:
        out[spec["name"]] = KaliToolWrapper(
            name=spec["name"],
            binary="core.extended_wifi.runner",
            description=spec["description"],
            input_schema=spec["input_schema"],
            examples=spec["examples"],
            risk_level=spec.get("risk_level", RISK_INTRUSIVE),
            requires_root=spec.get("requires_root", False),
            runner=_runner(spec["method"]),
        )
    return out


def _make_ble_post_exploit_wrappers() -> Dict[str, KaliToolWrapper]:
    from core.ble_post_exploit.runner import (BLE_POST_ATTACKS,
                                              run_attack as _run_bpe)

    def _runner(method: str):
        def _r(args: Dict[str, Any], timeout: int = 120,
               cwd: Optional[str] = None) -> Dict[str, Any]:
            try:
                # ``args`` carries adapter + per-attack inputs (addr,
                # target, payload, uuid, plan, ...). Pass the whole dict.
                return _run_bpe(method=method,
                                 adapter=(args or {}).get("adapter"),
                                 args=(args or {}))
            except Exception as e:  # noqa: BLE001 — never raise out of MCP
                return {"ok": False, "error": str(e)}
        return _r

    out: Dict[str, KaliToolWrapper] = {}
    for spec in BLE_POST_ATTACKS:
        out[spec["name"]] = KaliToolWrapper(
            name=spec["name"],
            binary="core.ble_post_exploit.runner",
            description=spec["description"],
            input_schema=spec["input_schema"],
            examples=spec["examples"],
            risk_level=spec.get("risk_level", RISK_INTRUSIVE),
            requires_root=spec.get("requires_root", False),
            runner=_runner(spec["method"]),
        )
    return out


# ---------------------------------------------------------------------------
# OSINT and Post-Exploitation probe wrappers
# ---------------------------------------------------------------------------
def _make_osint_probe_wrappers() -> Dict[str, KaliToolWrapper]:
    from core.osint.runner import OSINTRunner
    from core.algorithm_registry import algo_registry

    def _runner(algo_name: str, arg_key: str):
        def _r(args: Dict[str, Any], timeout: int = 120,
               cwd: Optional[str] = None) -> Dict[str, Any]:
            try:
                runner = OSINTRunner()
                func = algo_registry.get(algo_name)
                if func is None:
                    return {
                        "ok": False,
                        "error": f"Algorithm {algo_name} not registered"
                    }
                val = args.get(arg_key)
                res = func(runner, val)
                return {"ok": True, "result": res}
            except Exception as e:  # noqa: BLE001
                return {"ok": False, "error": str(e)}
        return _r

    specs = [
        {
            "name": "osint_probe_username_patterns",
            "algo": "username_patterns",
            "arg": "username",
            "desc": "Analyze username patterns across platforms to predict "
                    "likely usernames on other services.",
            "schema": {
                "type": "object",
                "properties": {
                    "username": {
                        "type": "string",
                        "description": "target username"
                    }
                },
                "required": ["username"]
            },
            "examples": ["osint_probe_username_patterns(username='admin')"]
        },
        {
            "name": "osint_probe_breach_correlate",
            "algo": "breach_correlate",
            "arg": "email_or_username",
            "desc": "Correlate email or username against local breach "
                    "intelligence dataset heuristics.",
            "schema": {
                "type": "object",
                "properties": {
                    "email_or_username": {
                        "type": "string",
                        "description": "email address or username"
                    }
                },
                "required": ["email_or_username"]
            },
            "examples": [
                "osint_probe_breach_correlate("
                "email_or_username='user@example.com')"
            ]
        },
        {
            "name": "osint_probe_phone_carrier",
            "algo": "phone_carrier",
            "arg": "phone_number",
            "desc": "Infer carrier and region details based on phone number "
                    "structure and country codes.",
            "schema": {
                "type": "object",
                "properties": {
                    "phone_number": {
                        "type": "string",
                        "description": "phone number in E.164 format or raw"
                    }
                },
                "required": ["phone_number"]
            },
            "examples": ["osint_probe_phone_carrier(phone_number='+15550199')"]
        },
        {
            "name": "osint_probe_social_graph",
            "algo": "social_graph",
            "arg": "social_handle",
            "desc": "Infer a social graph of relationships based on social "
                    "handle variations and connections.",
            "schema": {
                "type": "object",
                "properties": {
                    "social_handle": {
                        "type": "string",
                        "description": "social handle or account name"
                    }
                },
                "required": ["social_handle"]
            },
            "examples": ["osint_probe_social_graph(social_handle='johndoe')"]
        }
    ]

    out: Dict[str, KaliToolWrapper] = {}
    for spec in specs:
        out[spec["name"]] = KaliToolWrapper(
            name=spec["name"],
            binary="osint_runner",
            description=spec["desc"],
            input_schema=spec["schema"],
            examples=spec["examples"],
            risk_level=RISK_READ,
            requires_root=False,
            runner=_runner(spec["algo"], spec["arg"])
        )
    return out


def _make_osint_ext_wrappers() -> Dict[str, KaliToolWrapper]:
    """OSINT extension (~40 modules) — passive. Wraps the
    module-level ``run_probe`` entrypoint so the AI can drive any
    osint_ext method via ``mcp_call osint_ext_<method>(args=...)``.
    """
    from core.osint.runner_ext import OSINT_EXT_PROBES, run_probe

    def _runner(algo_name: str):
        def _r(args: Dict[str, Any], timeout: int = 120,
               cwd: Optional[str] = None) -> Dict[str, Any]:
            return run_probe(algo_name, args=args or {})
        return _r

    out: Dict[str, KaliToolWrapper] = {}
    for spec in OSINT_EXT_PROBES:
        out[spec["name"]] = KaliToolWrapper(
            name=spec["name"],
            binary="osint_ext_runner",
            description=spec["description"],
            input_schema=spec["input_schema"],
            examples=spec["examples"],
            risk_level=RISK_READ,
            requires_root=False,
            runner=_runner(spec["method"]),
        )
    return out


def _make_extended_ble_wrappers() -> Dict[str, KaliToolWrapper]:
    """BLE 5.x extended (30 modules, INTRUSIVE) — wraps
    :func:`core.extended_ble.runner.run_attack` so the AI can drive any
    extended_ble method via ``mcp_call extended_ble_<method>(args=...)``.
    All methods are INTRUSIVE; the per-step ACCEPT gate fires before the
    orchestrator routes to ``run_attack``; MCP callers (e.g. an external
    LLM) also see ``risk_level='intrusive'`` so the risk is visible.
    """
    from core.extended_ble.runner import (EXTENDED_BLE_ATTACKS,
                                          run_attack as _run_eb)

    def _runner(method: str):
        def _r(args: Dict[str, Any], timeout: int = 120,
               cwd: Optional[str] = None) -> Dict[str, Any]:
            try:
                return _run_eb(method=method,
                               adapter=(args or {}).get("adapter"),
                               args=(args or {}))
            except Exception as e:  # noqa: BLE001 — never raise out of MCP
                return {"ok": False, "error": str(e)}
        return _r

    out: Dict[str, KaliToolWrapper] = {}
    for spec in EXTENDED_BLE_ATTACKS:
        out[spec["name"]] = KaliToolWrapper(
            name=spec["name"],
            binary="core.extended_ble.runner",
            description=spec["description"],
            input_schema=spec["input_schema"],
            examples=spec["examples"],
            risk_level=spec.get("risk_level", RISK_INTRUSIVE),
            requires_root=spec.get("requires_root", False),
            runner=_runner(spec["method"]),
        )
    return out


def _make_post_exploit_probe_wrappers() -> Dict[str, KaliToolWrapper]:
    from core.post_exploit.runner import PostExploitRunner
    from core.algorithm_registry import algo_registry

    def _runner(algo_name: str):
        def _r(args: Dict[str, Any], timeout: int = 120,
               cwd: Optional[str] = None) -> Dict[str, Any]:
            try:
                runner = PostExploitRunner()
                func = algo_registry.get(algo_name)
                if func is None:
                    return {
                        "ok": False,
                        "error": f"Algorithm {algo_name} not registered"
                    }
                target_info = args.get("target_info", {})
                res = func(runner, target_info)
                return {"ok": True, "result": res}
            except Exception as e:  # noqa: BLE001
                return {"ok": False, "error": str(e)}
        return _r

    specs = [
        {
            "name": "post_exploit_probe_priv_esc_check",
            "algo": "priv_esc_check",
            "desc": "Check for common privilege escalation vectors based on "
                    "target information.",
            "schema": {
                "type": "object",
                "properties": {
                    "target_info": {
                        "type": "object",
                        "description": "structured target details"
                    }
                },
                "required": ["target_info"]
            },
            "examples": [
                "post_exploit_probe_priv_esc_check("
                "target_info={'details': {'os': 'linux'}})"
            ]
        },
        {
            "name": "post_exploit_probe_cred_enumerate",
            "algo": "cred_enumerate",
            "desc": "Enumerate potential credential sources on the target.",
            "schema": {
                "type": "object",
                "properties": {
                    "target_info": {
                        "type": "object",
                        "description": "structured target details"
                    }
                },
                "required": ["target_info"]
            },
            "examples": [
                "post_exploit_probe_cred_enumerate("
                "target_info={'details': {'services': []}})"
            ]
        },
        {
            "name": "post_exploit_probe_lateral_movement",
            "algo": "lateral_movement",
            "desc": "Assess lateral movement opportunities based on trusts "
                    "and active sessions.",
            "schema": {
                "type": "object",
                "properties": {
                    "target_info": {
                        "type": "object",
                        "description": "structured target details"
                    }
                },
                "required": ["target_info"]
            },
            "examples": [
                "post_exploit_probe_lateral_movement("
                "target_info={'details': {'shares': []}})"
            ]
        },
        {
            "name": "post_exploit_probe_persistence_id",
            "algo": "persistence_id",
            "desc": "Identify potential persistence mechanisms and locations.",
            "schema": {
                "type": "object",
                "properties": {
                    "target_info": {
                        "type": "object",
                        "description": "structured target details"
                    }
                },
                "required": ["target_info"]
            },
            "examples": [
                "post_exploit_probe_persistence_id("
                "target_info={'details': {'os': 'windows'}})"
            ]
        }
    ]

    out: Dict[str, KaliToolWrapper] = {}
    for spec in specs:
        out[spec["name"]] = KaliToolWrapper(
            name=spec["name"],
            binary="post_exploit_runner",
            description=spec["desc"],
            input_schema=spec["schema"],
            examples=spec["examples"],
            risk_level=RISK_READ,
            requires_root=False,
            runner=_runner(spec["algo"])
        )
    return out


# ---------------------------------------------------------------------------
# Live-edit + tool-installer wrappers (not Kali binaries — they call
# in-process core.live_edit / core.tool_installer functions)
# ---------------------------------------------------------------------------
def _make_live_edit_wrappers() -> Dict[str, KaliToolWrapper]:
    """Expose the core.live_edit package as MCP functions the AI can call
    by name. Wrappers route through the same KaliToolWrapper shape used
    for the rest of the tool surface (so the chain planner / external
    client can introspect them) but the actual work is in-process.
    """

    def _run_apply_live_edit(args: Dict[str, Any], timeout: int = 30,
                              cwd: Optional[str] = None) -> Dict[str, Any]:
        from core.live_edit import PatchSpec
        from core.live_edit.apply import apply_patch

        try:
            spec = PatchSpec(
                target_runner=str(args["target_runner"]),
                target_method=str(args["target_method"]),
                patch_id=str(args["patch_id"]),
                params=dict(args.get("params") or {}),
                rationale=str(args.get("rationale", "")),
            )
        except KeyError as e:
            return {"ok": False, "error": f"missing arg {e}",
                    "stdout": "", "stderr": "", "returncode": -1}
        # Caller is the orchestrator: the per-step gate already fired
        # for the surrounding step. The dispatcher's inner confirm is
        # the operator's gate at the patch granularity.
        overlay_path = apply_patch(spec, confirm_fn=None)
        if overlay_path is None:
            return {"ok": False, "error": "patch refused (validation or cancel)",
                    "stdout": "", "stderr": "", "returncode": -1}
        return {"ok": True, "stdout": overlay_path,
                "stderr": "", "returncode": 0}

    def _run_revert_live_edit(args: Dict[str, Any], timeout: int = 30,
                               cwd: Optional[str] = None) -> Dict[str, Any]:
        from core.live_edit.apply import revert_patch

        p = str(args.get("overlay_path", ""))
        if not p:
            return {"ok": False, "error": "overlay_path required",
                    "stdout": "", "stderr": "", "returncode": -1}
        ok = revert_patch(p)
        return {"ok": ok, "stdout": str(ok),
                "stderr": "" if ok else "revert failed",
                "returncode": 0 if ok else -1}

    def _run_list_available_patches(args: Dict[str, Any], timeout: int = 30,
                                     cwd: Optional[str] = None) -> Dict[str, Any]:
        from core.live_edit.patch import list_available_patches

        names = list_available_patches()
        return {"ok": True, "stdout": ",".join(names),
                "stderr": "", "returncode": 0}

    out: Dict[str, KaliToolWrapper] = {
        "live_edit_apply": KaliToolWrapper(
            name="live_edit_apply",
            binary="core.live_edit.apply",
            description=(
                "Apply a safe AST patch to a KFIOSA runner method. The "
                "patch_id must be one of core.live_edit.test_patches "
                "(e.g. 'add_logging', 'add_optional_arg', "
                "'swap_retry_count', 'set_which_fail_to_real'). The patch "
                "is validated against a whitelist (no os.system, no "
                "__import__, no eval, no exec) and the original method's "
                "own dangerous calls are tolerated. Returns the overlay "
                "module path on success, an error envelope on refusal."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "target_runner": {
                        "type": "string",
                        "description": "dotted module path, e.g. "
                                       "'core.wifi_attack.runner'",
                    },
                    "target_method": {
                        "type": "string",
                        "description": "private method name (must start with '_')",
                    },
                    "patch_id": {
                        "type": "string",
                        "description": "registered safe-patch id",
                    },
                    "params": {
                        "type": "object",
                        "description": "parameters for the patch callable",
                    },
                    "rationale": {
                        "type": "string",
                        "description": "free-text reason (audited)",
                    },
                },
                "required": ["target_runner", "target_method", "patch_id"],
            },
            examples=[
                "live_edit_apply(target_runner='core.wifi_attack.runner', "
                "target_method='_evil_twin_automated', patch_id='add_logging', "
                "rationale='bump logging for the failing case')",
            ],
            risk_level=RISK_INTRUSIVE,
            requires_root=False,
            runner=_run_apply_live_edit,
        ),
        "live_edit_revert": KaliToolWrapper(
            name="live_edit_revert",
            binary="core.live_edit.apply",
            description="Delete a previously applied live-edit overlay.",
            input_schema={
                "type": "object",
                "properties": {
                    "overlay_path": {
                        "type": "string",
                        "description": "overlay path returned by live_edit_apply",
                    },
                },
                "required": ["overlay_path"],
            },
            examples=["live_edit_revert(overlay_path='.../overlays/__live_*.py')"],
            risk_level=RISK_READ,
            requires_root=False,
            runner=_run_revert_live_edit,
        ),
        "live_edit_list_patches": KaliToolWrapper(
            name="live_edit_list_patches",
            binary="core.live_edit.patch",
            description=(
                "List the safe-patch ids the AI may name in a live_edit "
                "step. Use this before proposing a patch to confirm a "
                "patch_id is registered."
            ),
            input_schema={"type": "object", "properties": {}},
            examples=["live_edit_list_patches()"],
            risk_level=RISK_READ,
            requires_root=False,
            runner=_run_list_available_patches,
        ),
    }
    return out


def _make_tool_installer_wrappers() -> Dict[str, KaliToolWrapper]:
    """Expose core.tool_installer as MCP functions the AI can call."""

    def _run_install_tool(args: Dict[str, Any], timeout: int = 600,
                          cwd: Optional[str] = None) -> Dict[str, Any]:
        from core.tool_installer.install import maybe_install

        tool = str(args.get("tool", ""))
        if not tool:
            return {"ok": False, "error": "tool required",
                    "stdout": "", "stderr": "", "returncode": -1}
        ok = maybe_install(tool, auto=bool(args.get("auto", False)))
        return {"ok": ok,
                "stdout": f"installed {tool}" if ok else f"install failed for {tool}",
                "stderr": "", "returncode": 0 if ok else -1}

    def _run_list_install_log(args: Dict[str, Any], timeout: int = 30,
                              cwd: Optional[str] = None) -> Dict[str, Any]:
        from core.tool_installer.log import list_install_log

        entries = list_install_log()
        # Return the last N entries (default 20) as a single stdout blob.
        n = int(args.get("last", 20)) if isinstance(args.get("last"), int) else 20
        tail = entries[-n:] if entries else []
        import json as _json
        return {"ok": True,
                "stdout": "\n".join(_json.dumps(e) for e in tail),
                "stderr": "", "returncode": 0}

    out: Dict[str, KaliToolWrapper] = {
        "install_tool": KaliToolWrapper(
            name="install_tool",
            binary="core.tool_installer.install",
            description=(
                "Install a missing tool. Tool must be in "
                "core.tool_installer.catalog.TOOL_CATALOG (apt / pip / "
                "git entries). Set auto=True to skip the per-install "
                "confirm gate (the per-step gate in the orchestrator is "
                "the operator's gate; auto=True means the step was "
                "approved with auto-install included). Returns ok=True "
                "only if shutil.which(tool) is True after install."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "tool": {
                        "type": "string",
                        "description": "tool name (must be in TOOL_CATALOG)",
                    },
                    "auto": {
                        "type": "boolean",
                        "description": "skip per-install confirm (default false)",
                        "default": False,
                    },
                },
                "required": ["tool"],
            },
            examples=["install_tool(tool='gatttool', auto=True)"],
            risk_level=RISK_INTRUSIVE,
            requires_root=True,
            runner=_run_install_tool,
        ),
        "list_install_log": KaliToolWrapper(
            name="list_install_log",
            binary="core.tool_installer.log",
            description="Return recent install attempts and outcomes from "
                        "core.tool_installer._log.json (auditable).",
            input_schema={
                "type": "object",
                "properties": {
                    "last": {
                        "type": "integer",
                        "description": "how many tail entries to return (default 20)",
                        "default": 20,
                    },
                },
            },
            examples=["list_install_log(last=10)"],
            risk_level=RISK_READ,
            requires_root=False,
            runner=_run_list_install_log,
        ),
    }
    return out


# ---------------------------------------------------------------------------
# Post-access external TUI
# ---------------------------------------------------------------------------
def _run_open_post_access_tui(args: Dict[str, Any]) -> Dict[str, Any]:
    """In-process spawner for the post-access external TUI.

    Routes through ``core.post_access_tui.spawner.spawn_post_access_tui``
    using a NULL external terminal backend (we're inside the same
    process tree). The orchestrator's ``_dispatch_open_post_access_tui``
    is the proper call-site when an actual terminal backend is wired;
    this MCP wrapper exists so the AI can request a spawn via mcp_call
    too. Single-gate invariant: the per-step ACCEPT prompt has already
    fired by the time we get here — never re-confirm.
    """
    from core.post_access_tui.spawner import spawn_post_access_tui
    report = args.get("report") or {}
    if not isinstance(report, dict):
        return {"ok": False, "error": "open_post_access_tui: 'report' must be a dict"}
    return spawn_post_access_tui(report, external_terminal=None)


def _make_post_access_tui_wrappers() -> Dict[str, "KaliToolWrapper"]:
    return {
        "open_post_access_tui": KaliToolWrapper(
            name="open_post_access_tui",
            binary="core.post_access_tui.spawner",
            description="Spawn the external post-access TUI in a new "
                        "terminal window for shell/file/network/module "
                        "control over an active session. Single-gate: the "
                        "per-step ACCEPT prompt has already fired; the "
                        "wrapper does NOT re-confirm.",
            input_schema={
                "type": "object",
                "properties": {
                    "report": {
                        "type": "object",
                        "description": "Chain report dict (must contain "
                                        "report['access']['achieved']=True "
                                        "and a session_id or creds).",
                    },
                },
                "required": ["report"],
            },
            examples=[
                "open_post_access_tui(report=current_chain_report)",
            ],
            risk_level=RISK_INTRUSIVE,
            requires_root=False,
            runner=_run_open_post_access_tui,
        ),
    }


# ---------------------------------------------------------------------------
# Python-library wrappers — one MCP function per curated library
# in core.toolbox.python_libs (116 entries). Each wrapper runs a
# Python snippet that imports the library via the executor in
# core.toolbox.exec_python_lib.
# ---------------------------------------------------------------------------
def _make_python_lib_wrappers() -> Dict[str, KaliToolWrapper]:
    """Build a dict of ``pylib_<name>`` -> :class:`KaliToolWrapper`
    for the curated Python-libs registry.

    Each wrapper delegates to
    :func:`core.toolbox.exec_python_lib.run_python_lib_code` with
    the library name + a small code snippet. The chain step is
    per-step ACCEPT-gated (the library's
    ``requires_explicit_authorization`` flag drives the risk
    level).
    """
    try:
        from core.toolbox.python_libs import PYTHON_LIBRARIES
    except Exception:
        return {}
    out: Dict[str, KaliToolWrapper] = {}
    for lib in PYTHON_LIBRARIES:
        name = lib["name"]
        requires_gate = bool(lib.get("requires_gate", False))
        risk = (
            RISK_DESTRUCTIVE
            if lib.get("risk_level") == "critical"
            else (RISK_INTRUSIVE if requires_gate else RISK_READ)
        )

        def _runner(lib=lib):
            def _r(args: Dict[str, Any], timeout: int = 30,
                   cwd: Optional[str] = None) -> Dict[str, Any]:
                try:
                    from core.toolbox import run_python_lib_code
                    code = (args.get("code") or "").strip() or (
                        f"print({lib.get('import_name', lib['name'])}"
                        f".__name__)"
                    )
                    res = run_python_lib_code(
                        lib=lib["name"],
                        code=code,
                        cwd=args.get("cwd") or cwd,
                        timeout_seconds=int(
                            args.get("timeout_seconds") or timeout
                        ),
                        env=args.get("env") or {},
                    )
                    return res.to_dict()
                except Exception as e:  # noqa: BLE001
                    return {
                        "ok": False,
                        "error": f"pylib_runner: {type(e).__name__}: {e}",
                    }
            return _r

        out[f"pylib_{name}"] = KaliToolWrapper(
            name=f"pylib_{name}",
            binary="python3",
            description=(
                f"Run a Python snippet that imports ``{name}`` "
                f"(category={lib.get('category', 'utility')}, "
                f"import={lib.get('import_name', name)}). "
                f"{lib.get('summary', '')}"
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "code": {
                        "type": "string",
                        "description": (
                            "Python source to run. The library is "
                            "pre-imported under its import_name. "
                            "Use os.environ['KFIOSA_TARGET_*'] for "
                            "harvested credentials (never inline)."
                        ),
                    },
                    "cwd": {"type": "string"},
                    "timeout_seconds": {
                        "type": "integer",
                        "default": 30,
                        "maximum": 300,
                    },
                    "env": {
                        "type": "object",
                        "description": (
                            "Extra env vars. KFIOSA_TARGET_PASSWORD / "
                            "KFIOSA_TARGET_PSK / KFIOSA_TARGET_TOKEN "
                            "are routed here (never inline)."
                        ),
                    },
                },
                "required": [],
            },
            examples=[
                f"pylib_{name}("
                f"code='print({lib.get('import_name', name)}"
                f".__name__)')"
            ],
            risk_level=risk,
            requires_root=requires_gate,
            runner=_runner(),
        )
    return out


# ---------------------------------------------------------------------------
# Aggregate registry
# ---------------------------------------------------------------------------
KALI_TOOL_WRAPPERS: Dict[str, KaliToolWrapper] = {
    **_make_kali_wrappers(),
    **_make_mt7921e_wrappers(),
    **_make_external_injection_wrappers(),
    **_make_recon_probe_wrappers(),
    **_make_ble_probe_wrappers(),
    **_make_ble_attack_wrappers(),
    **_make_wifi_attack_wrappers(),
    **_make_post_exploit_ext_wrappers(),
    **_make_microsoft_attack_wrappers(),
    **_make_android_attack_wrappers(),
    **_make_ios_attack_wrappers(),
    **_make_live_target_wrappers(),
    **_make_extended_wifi_wrappers(),
    **_make_ble_post_exploit_wrappers(),
    **_make_extended_ble_wrappers(),
    **_make_osint_probe_wrappers(),
    **_make_osint_ext_wrappers(),
    **_make_post_exploit_probe_wrappers(),
    **_make_live_edit_wrappers(),
    **_make_tool_installer_wrappers(),
    **_make_post_access_tui_wrappers(),
    **_make_cve_to_exploit_wrappers(),
    "cve_lookup": _make_cve_wrapper(),
    **_make_python_lib_wrappers(),
}


def list_mcp_tools(domain: Optional[str] = None) -> List[Dict[str, Any]]:
    """Return the public MCP ``tools/list`` records, optionally filtered
    by domain. The mt7921e.* functions are tagged ``wifi``; cve_lookup is
    tagged ``exploit``; everything else uses its first-level key in
    :data:`core.tool_registry.KALI_TOOL_ALLOWLIST`."""
    from core.tool_registry import KALI_TOOL_ALLOWLIST

    # Reverse-index wrapper name -> domain. For mt7921e.* / cve_lookup /
    # external-injection tools we hardcode the domain since they live
    # outside the binary allowlist.
    name_to_domain: Dict[str, str] = {}
    for d, names in KALI_TOOL_ALLOWLIST.items():
        for n in names:
            name_to_domain[n] = d
    name_to_domain.setdefault("cve_lookup", "exploit")
    name_to_domain.setdefault("cve_to_exploit", "exploit")
    for name in KALI_TOOL_WRAPPERS:
        if name.startswith("osint_probe_"):
            name_to_domain.setdefault(name, "osint")
        elif name.startswith("osint_ext_"):
            name_to_domain.setdefault(name, "osint")
        elif name.startswith("post_exploit_probe_"):
            name_to_domain.setdefault(name, "post_exploitation")
        elif name.startswith("post_exploit_ext_"):
            name_to_domain.setdefault(name, "post_exploitation")
        elif name.startswith("ble_probe_"):
            name_to_domain.setdefault(name, "ble")
        elif name.startswith("ble_attack_"):
            name_to_domain.setdefault(name, "ble")
        elif name.startswith("wifi_attack_"):
            name_to_domain.setdefault(name, "wifi")
        elif name.startswith("ext_wifi_"):
            name_to_domain.setdefault(name, "wifi")
        elif name.startswith("ble_post_exploit_"):
            name_to_domain.setdefault(name, "post_exploitation")
        elif name.startswith("extended_ble_"):
            name_to_domain.setdefault(name, "ble")
        elif name.startswith("live_edit_") or name in ("install_tool", "list_install_log"):
            # live-edit + tool-installer are cross-cutting infrastructure;
            # tag as "infra" so the chain planner's LIVE_EDIT_PROMPT_STANZA /
            # TOOL_INSTALL_PROMPT_STANZA surfaces them.
            name_to_domain.setdefault(name, "infra")
        elif name == "open_post_access_tui":
            # post-access TUI is post-exploitation; surfaces in the
            # POST_EXPLOIT_PROMPT_STANZA so the AI knows the AI-driven
            # path is available.
            name_to_domain.setdefault(name, "post_exploitation")
        elif name.startswith("microsoft_attack_"):
            # Microsoft target-class read methods; surfaces in
            # MICROSOFT_PROMPT_STANZA so the AI knows the AI-driven
            # path is available for AD / Windows / M365 / ADCS.
            name_to_domain.setdefault(name, "microsoft")
        elif name.startswith("android_attack_"):
            # Android target-class read methods; surfaces in
            # ANDROID_PROMPT_STANZA.
            name_to_domain.setdefault(name, "android")
        elif name.startswith("ios_attack_"):
            # iOS target-class read methods; surfaces in
            # IOS_PROMPT_STANZA.
            name_to_domain.setdefault(name, "ios")
        elif name.startswith("live_target_"):
            # Live-target polyglot safe-patch wrappers; surfaces in
            # LIVE_TARGET_PROMPT_STANZA.
            name_to_domain.setdefault(name, "live_target")
    # External injection toolbox tools are all wifi-domain for now.
    try:
        from core.modules.external_injection import EXTERNAL_INJECTION_TOOLS
        for spec in EXTERNAL_INJECTION_TOOLS:
            name_to_domain.setdefault(spec["name"], spec.get("domain", "wifi"))
    except Exception:  # noqa: BLE001 — best-effort domain tag
        pass
    # Recon-probe tools (catalog_recon) are passive wifi recon — tag
    # them wifi so the wifi-domain planner prompt surfaces them.
    try:
        from core.modules.catalog_recon import RECON_PROBES
        for spec in RECON_PROBES:
            name_to_domain.setdefault(spec["name"], "wifi")
    except Exception:  # noqa: BLE001 — best-effort domain tag
        pass

    out: List[Dict[str, Any]] = []
    for name, w in KALI_TOOL_WRAPPERS.items():
        if domain and name_to_domain.get(name) != domain:
            continue
        rec = w.as_mcp_record()
        rec["domain"] = name_to_domain.get(name, "unknown")
        out.append(rec)
    return out


def get_mcp_tool(name: str) -> Optional[Dict[str, Any]]:
    """Return the public record for a single MCP tool name, or None."""
    w = KALI_TOOL_WRAPPERS.get(name)
    if w is None:
        return None
    rec = w.as_mcp_record()
    rec["domain"] = "unknown"
    return rec


def call_mcp_tool(name: str, args: Dict[str, Any],
                  timeout: int = 30) -> Dict[str, Any]:
    """Dispatch an MCP tool call to its wrapper. Returns the wrapper's
    ``run()`` result dict."""
    w = KALI_TOOL_WRAPPERS.get(name)
    if w is None:
        return {"ok": False, "error": f"unknown MCP tool: {name}"}
    return w.run(args, timeout=timeout)
