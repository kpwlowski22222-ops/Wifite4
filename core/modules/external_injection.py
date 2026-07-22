#!/usr/bin/env python3
"""
External packet-injection toolbox
==================================
Python wrappers for the standalone injection / crafting tools fetched
into ``toolboxes/wifi/`` so the AI chain can drive them as first-class
methods alongside the mt7921e / aireplay-ng path.

Wrapped tools (each lives under ``toolboxes/wifi/<owner__repo>/``):

- **nemesis** (``libnet__nemesis``) — a portable L2/L3 packet crafter &
  injector (ARP/RARP, DNS, ETHERNET, ICMP, IGMP, IP, OSPF, RIP, TCP,
  UDP, DHCP). Used for wired-side / evil-twin L2 forging (ARP spoof,
  DHCP starvation, ICMP redirect, TCP RST) once the operator has a
  bridged evil-twin or a foothold on the target's L2.
- **inject** (``fksvs__inject``) — a compact C L2/L3
  craft+inject+sniff CLI (eth/arp/ip/icmp/tcp/udp). Same role as
  nemesis, lighter dependency footprint (no libnet).
- **wpr_tx** (``RuhanSA079__WiFiPacketRadio``) — a C radiotap-based raw
  802.11 TX/RX binary that transmits arbitrary payloads over monitor
  mode (developed on RTL8812EU). A non-scapy raw-802.11 injection path
  complementary to the mt7921e scapy path — useful when the adapter is
  not mt7921e but is injection-capable (e.g. RTL8812AU/EU).
- **cse508_dns_inject** (``saishsali__cse508`` hw4) — a scapy-based DNS
  injection script (spoofed DNS responses). Used on a bridged evil-twin
  or MITM position to redirect target DNS.
- **mt7921e_research_firmware** — a firmware / driver research recipe for
  the operator's MediaTek MT7922 (``mt7921e``). The MT7922 ships a closed
  MediaTek binary firmware blob, so the recipe targets the open in-tree
  ``mt76`` / ``mt7921e`` driver source (for driver-level vuln hunting) plus
  the closed firmware blob (for offline reverse engineering). Live device
  reflash is NOT supported (legacy open WiFi firmware ``use_dev_fw`` + rollback
  trick does not apply to the closed MediaTek firmware). NOT a runtime
  injection tool.

Every public function returns a dict and **never raises** — missing
binary, missing root, bad args, or subprocess failure all degrade to
``{"ok": False, "error": "..."}`` exactly like
:mod:`core.modules.mt7921e_tools`. The orchestrator branches on
``{"error": ...}`` the same way it does for the other Kali wrappers in
:mod:`core.mcp.tools`.

These wrappers only *build and offer* the command. Execution against a
real target is always routed through the orchestrator's mandatory
per-step ACCEPT/CANCEL gate (``TuiConfirmFn``) — no wrapper here auto-
runs anything destructive without the caller (the orchestrator) having
already obtained operator consent.
"""

from __future__ import annotations

import logging
import os
import shlex
import shutil
import subprocess
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Root of the fetched toolbox (this file is at core/modules/external_injection.py).
_REPO_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), os.pardir, os.pardir)
)
_TOOLBOX_WIFI = os.path.join(_REPO_ROOT, "toolboxes", "wifi")


# ---------------------------------------------------------------------------
# Per-toolbox binary locations (built artifacts live beside the source).
# ---------------------------------------------------------------------------
_TOOLBOX_BINS: Dict[str, str] = {
    "nemesis": os.path.join(_TOOLBOX_WIFI, "libnet__nemesis", "nemesis"),
    "inject": os.path.join(_TOOLBOX_WIFI, "fksvs__inject", "inject"),
    "wpr_tx_rx": os.path.join(_TOOLBOX_WIFI, "RuhanSA079__WiFiPacketRadio",
                              "bin", "wpr_tx_rx"),
    "dnsinject": os.path.join(_TOOLBOX_WIFI, "saishsali__cse508", "hw4",
                              "dnsinject.py"),
}

# Supported protocol subcommands per tool (validated before exec).
NEMESIS_PROTOCOLS: tuple = (
    "arp", "dns", "ethernet", "icmp", "igmp", "ip", "ospf", "rip",
    "tcp", "udp", "dhcp",
)
INJECT_TOOL_PROTOCOLS: tuple = (
    "eth", "arp", "ip", "icmp", "tcp", "udp", "sniff",
)

# Curated alias → flag maps so the AI can pass readable arg names and the
# wrapper emits the exact flag each CLI expects. Anything not in the map
# is passed through generically (see ``_args_to_flags``).
_NEMESIS_ALIASES: Dict[str, str] = {
    "src_ip": "S", "dst_ip": "D", "src_mac": "M", "dst_mac": "D",
    "iface": "d", "device": "d", "count": "x", "payload": "P",
    "payload_file": "P", "ttl": "T", "id": "I", "gateway": "G",
    "src_port": "x", "dst_port": "y", "seq": "s", "ack": "a",
    "flags": "f", "window": "w", "urg": "u", "tos": "O",
    "data": "D", "type": "i", "code": "c", "group": "g",
    "request": "R", "response": "A", "length": "l",
}
_INJECT_TOOL_ALIASES: Dict[str, str] = {
    "src_ip": "S", "dst_ip": "D", "src_mac": "K", "dst_mac": "M",
    "iface": "i", "count": "c", "ttl": "T", "payload_file": "a",
    "payload": "a", "src_port": "o", "dst_port": "d", "seq": "s",
    "flags": "f", "request": "r", "verbose": "v",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _resolve_bin(name: str) -> Optional[str]:
    """Return the path to ``name``: prefer ``$PATH`` (installed), else the
    in-toolbox built artifact. Returns ``None`` when neither exists."""
    p = shutil.which(name)
    if p:
        return p
    tb = _TOOLBOX_BINS.get(name)
    if tb and os.path.exists(tb):
        return tb
    return None


def _run(cmd: List[str], *, timeout: int = 30,
         root_required: bool = True) -> Dict[str, Any]:
    """Run ``cmd``; return ``{ok, stdout, stderr, returncode, error}``.

    When ``root_required`` is True and the process is not root, returns a
    clear ``needs root`` error without execing. Never raises.
    """
    if not cmd or not cmd[0]:
        return {"ok": False, "error": "empty command", "stdout": "",
                "stderr": "", "returncode": -1}
    if not shutil.which(cmd[0]) and not os.path.exists(cmd[0]):
        return {"ok": False, "error": f"{cmd[0]} not installed",
                "stdout": "", "stderr": "", "returncode": -1}
    if root_required and os.geteuid() != 0:
        return {"ok": False, "error": "needs root", "stdout": "",
                "stderr": "", "returncode": -1}
    try:
        p = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout)
        return {
            "ok": p.returncode == 0,
            "stdout": p.stdout[-4000:],
            "stderr": p.stderr[-2000:],
            "returncode": p.returncode,
            "error": "" if p.returncode == 0 else (
                (p.stderr or "").strip()[:300] or f"{cmd[0]} exit {p.returncode}"
            ),
        }
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": f"timeout after {timeout}s",
                "stdout": "", "stderr": "", "returncode": -1}
    except Exception as e:  # noqa: BLE001 — degrade, never raise
        return {"ok": False, "error": str(e), "stdout": "",
                "stderr": "", "returncode": -1}


def _args_to_flags(args: Optional[Dict[str, Any]],
                   aliases: Dict[str, str]) -> List[str]:
    """Convert an ``args`` dict into a flat ``[-flag, value, ...]`` list.

    Resolution per key:

    - an alias key (e.g. ``src_ip``) → the mapped single-char flag
      (``-S``);
    - a key already starting with ``-`` → used verbatim;
    - a single-char key → ``-<key>``;
    - any other key → ``--<key>`` (generic pass-through).

    Bool values emit the bare flag when True and are skipped when False.
    ``None`` values are skipped. Never raises.
    """
    out: List[str] = []
    for k, v in (args or {}).items():
        if v is None:
            continue
        if k in aliases:
            flag = "-" + aliases[k]
        elif k.startswith("-"):
            flag = k
        elif len(k) == 1:
            flag = "-" + k
        else:
            flag = "--" + k.replace("_", "-")
        if isinstance(v, bool):
            if v:
                out.append(flag)
        else:
            out.extend([flag, str(v)])
    return out


# ---------------------------------------------------------------------------
# Availability probe
# ---------------------------------------------------------------------------
def probe_external_injection_tools() -> Dict[str, Any]:
    """Report which external injection tools are available (binary path
    or ``None``). Never raises. The chain planner / AI uses this to know
    which tools it can actually emit ``external_inject`` steps for."""
    out: Dict[str, Any] = {}
    for name in ("nemesis", "inject", "wpr_tx_rx", "dnsinject"):
        out[name] = _resolve_bin(name)
    out["python3"] = shutil.which("python3")
    out["docker"] = shutil.which("docker")
    return out


# ---------------------------------------------------------------------------
# nemesis (libnet__nemesis) — L2/L3 packet crafter/injector
# ---------------------------------------------------------------------------
def nemesis_inject(protocol: str, *, iface: Optional[str] = None,
                   args: Optional[Dict[str, Any]] = None,
                   timeout: int = 30) -> Dict[str, Any]:
    """Run ``nemesis <protocol> [flags]``.

    ``protocol`` is one of :data:`NEMESIS_PROTOCOLS`. ``iface`` (if
    given) becomes ``-d <iface>`` (nemesis device flag). ``args`` is a
    flat dict; see :data:`_NEMESIS_ALIASES` for readable aliases (e.g.
    ``src_ip`` → ``-S``) — unknown keys pass through as ``--key value``.

    Root required (raw sockets). Returns
    ``{ok, method, protocol, cmd, stdout, stderr, returncode, error}``.
    Never raises.
    """
    proto = (protocol or "").lower()
    if proto not in NEMESIS_PROTOCOLS:
        return {"ok": False, "method": "nemesis", "protocol": proto,
                "error": f"unsupported nemesis protocol {proto!r}; "
                         f"one of {NEMESIS_PROTOCOLS}"}
    binpath = _resolve_bin("nemesis")
    if not binpath:
        return {"ok": False, "method": "nemesis", "protocol": proto,
                "error": "nemesis not installed (build toolboxes/wifi/"
                         "libnet__nemesis or apt install nemesis)"}
    cmd = [binpath, proto]
    if iface:
        cmd.extend(["-d", str(iface)])
    cmd.extend(_args_to_flags(args, _NEMESIS_ALIASES))
    r = _run(cmd, timeout=timeout, root_required=True)
    r.update({"method": "nemesis", "protocol": proto,
              "cmd": " ".join(shlex.quote(c) for c in cmd)})
    return r


# ---------------------------------------------------------------------------
# inject (fksvs__inject) — compact L2/L3 craft+inject+sniff
# ---------------------------------------------------------------------------
def inject_tool_inject(protocol: str, *, iface: Optional[str] = None,
                       args: Optional[Dict[str, Any]] = None,
                       timeout: int = 30) -> Dict[str, Any]:
    """Run ``inject <protocol> -i <iface> [flags]`` (fksvs/inject).

    ``protocol`` is one of :data:`INJECT_TOOL_PROTOCOLS`. ``iface``
    becomes ``-i <iface>``. ``args`` is a flat dict; see
    :data:`_INJECT_TOOL_ALIASES` (e.g. ``src_ip`` → ``-S``, ``flags`` →
    ``-f syn``). Unknown keys pass through as ``--key value``.

    Root required. Returns
    ``{ok, method, protocol, cmd, stdout, stderr, returncode, error}``.
    Never raises.
    """
    proto = (protocol or "").lower()
    if proto not in INJECT_TOOL_PROTOCOLS:
        return {"ok": False, "method": "inject", "protocol": proto,
                "error": f"unsupported inject protocol {proto!r}; one of "
                         f"{INJECT_TOOL_PROTOCOLS}"}
    binpath = _resolve_bin("inject")
    if not binpath:
        return {"ok": False, "method": "inject", "protocol": proto,
                "error": "inject not installed (cd toolboxes/wifi/"
                         "fksvs__inject && make)"}
    cmd = [binpath, proto]
    if iface:
        cmd.extend(["-i", str(iface)])
    cmd.extend(_args_to_flags(args, _INJECT_TOOL_ALIASES))
    r = _run(cmd, timeout=timeout, root_required=True)
    r.update({"method": "inject", "protocol": proto,
              "cmd": " ".join(shlex.quote(c) for c in cmd)})
    return r


# ---------------------------------------------------------------------------
# wpr_tx (RuhanSA079__WiFiPacketRadio) — radiotap raw 802.11 TX/RX
# ---------------------------------------------------------------------------
def wpr_tx(*, iface: Optional[str] = None,
           payload_file: Optional[str] = None,
           channel: Optional[int] = None,
           count: Optional[int] = None,
           extra_args: Optional[List[str]] = None,
           timeout: int = 120) -> Dict[str, Any]:
    """Run the WiFiPacketRadio ``wpr_tx_rx`` binary.

    The upstream binary is config-driven (RADIO_IFACE / channel are
    compile-time constants rather than getopt flags), so this wrapper
    runs the built binary with the operator's parameters surfaced via
    environment overrides where the build supports them, and otherwise
    reports the exact command to run by hand. It is a non-scapy raw
    802.11 injection path for non-mt7921e injection-capable adapters
    (e.g. RTL8812EU).

    Root required (monitor-mode raw socket). Returns
    ``{ok, method, cmd, stdout, stderr, returncode, error}``. Never
    raises.
    """
    binpath = _resolve_bin("wpr_tx_rx")
    if not binpath:
        return {"ok": False, "method": "wpr_tx",
                "error": "wpr_tx_rx not built (cd toolboxes/wifi/"
                         "RuhanSA079__WiFiPacketRadio && ./build.sh; "
                         "needs libcodec2 libpcap libasound)"}
    cmd = [binpath]
    if extra_args:
        cmd.extend([str(a) for a in extra_args])
    env = dict(os.environ)
    if iface:
        env["WPR_RADIO_IFACE"] = str(iface)
    if channel is not None:
        env["WPR_CHANNEL"] = str(channel)
    if payload_file:
        env["WPR_PAYLOAD_FILE"] = str(payload_file)
    if count is not None:
        env["WPR_TX_COUNT"] = str(count)
    if os.geteuid() != 0:
        return {"ok": False, "method": "wpr_tx", "error": "needs root",
                "cmd": " ".join(shlex.quote(c) for c in cmd)}
    try:
        p = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout, env=env)
        return {
            "ok": p.returncode == 0, "method": "wpr_tx",
            "cmd": " ".join(shlex.quote(c) for c in cmd),
            "stdout": p.stdout[-4000:], "stderr": p.stderr[-2000:],
            "returncode": p.returncode,
            "error": "" if p.returncode == 0 else (
                (p.stderr or "").strip()[:300]
                or f"wpr_tx_rx exit {p.returncode}"
            ),
        }
    except subprocess.TimeoutExpired:
        return {"ok": False, "method": "wpr_tx",
                "error": f"timeout after {timeout}s",
                "cmd": " ".join(shlex.quote(c) for c in cmd)}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "method": "wpr_tx", "error": str(e),
                "cmd": " ".join(shlex.quote(c) for c in cmd)}


# ---------------------------------------------------------------------------
# cse508_dns_inject (saishsali__cse508 hw4) — scapy DNS injection
# ---------------------------------------------------------------------------
def cse508_dns_inject(*, iface: str,
                      hostnames: Optional[str] = None,
                      expression: Optional[str] = None,
                      timeout: int = 120) -> Dict[str, Any]:
    """Run the hw4 scapy DNS-injection script.

    ``python3 dnsinject.py -i <iface> [-e <bpf>] <hostnames>`` —
    sniff DNS queries on ``iface`` and inject spoofed responses for the
    hostnames listed in the ``hostnames`` file (``host`` A ``ip`` per
    line). Use on a bridged evil-twin / MITM position.

    Root required (scapy raw sniff). Returns
    ``{ok, method, cmd, stdout, stderr, returncode, error}``. Never
    raises.
    """
    if not iface:
        return {"ok": False, "method": "cse508_dns_inject",
                "error": "iface required"}
    py = shutil.which("python3")
    script = _resolve_bin("dnsinject")
    if not py or not script:
        return {"ok": False, "method": "cse508_dns_inject",
                "error": "python3 or dnsinject.py not available"}
    cmd = [py, script, "-i", str(iface)]
    if expression:
        cmd.extend(["-e", str(expression)])
    if hostnames:
        cmd.append(str(hostnames))
    r = _run(cmd, timeout=timeout, root_required=True)
    r.update({"method": "cse508_dns_inject",
              "cmd": " ".join(shlex.quote(c) for c in cmd)})
    return r


# ---------------------------------------------------------------------------
# mt7921e_research_firmware — MediaTek MT7922 (mt7921e) firmware / driver
# research enablement. Unlike legacy open WiFi dongle firmware (which could
# be rebuilt and reflashed), the MT7922 ships a closed MediaTek binary
# firmware blob; research is driver-source + firmware-blob level only.
# ---------------------------------------------------------------------------
def mt7921e_research_firmware(*, target: str = "mt7922",
                              live_test: bool = False,
                              timeout: int = 600) -> Dict[str, Any]:
    """Surface the MediaTek MT7922 (``mt7921e``) firmware / driver research
    recipe.

    This is **not** a runtime injection tool — it is a firmware-level
    research enablement step. The MT7922 firmware is a closed MediaTek
    binary blob shipped in ``linux-firmware`` (not user-rebuildable, unlike
    the legacy open WiFi firmware). By default (``live_test=False``)
    it returns the research recipe — clone the in-tree ``mt76`` / ``mt7921``
    driver source for driver-level vuln hunting and locate the closed
    firmware blob for offline reverse engineering — without executing
    anything (``risk_level=read``).

    ``live_test=True`` is **not supported** for the MT7922: the closed
    MediaTek firmware cannot be rebuilt or safely reflashed on the live
    card (the legacy ``use_dev_fw=1`` + 30 s rollback trick does not
    apply). It returns ``ok=False`` with an explanatory error so the chain
    surfaces the limitation instead of silently doing nothing.

    Returns ``{ok, method, target, recipe, live_test, error, ...}``.
    Never raises.
    """
    recipe = (
        "1. Driver-source research (open, in-tree mt76/mt7921e):\n"
        "   git clone --depth 1 --filter=blob:none --sparse "
        "https://github.com/torvalds/linux ~/src/linux && "
        "cd ~/src/linux && git sparse-checkout set "
        "drivers/net/wireless/mediatek/mt76/mt7921\n"
        "2. Inspect the mt7921e MAC/BB state machines, command/event\n"
        "   ring, and TX/RX paths for the 0-day tail:\n"
        "   grep -rnE 'mt7921e|mt7921_' drivers/net/wireless/mediatek/mt76/\n"
        "3. Closed MediaTek firmware blob (offline RE only, NOT\n"
        "   rebuildable): locate it in the linux-firmware tree —\n"
        "   git clone --depth 1 https://git.kernel.org/pub/scm/linux/kernel/git/firmware/linux-firmware.git ~/src/linux-firmware\n"
        "   find ~/src/linux-firmware/mediatek -iname '*7921*' -o -iname '*7922*'\n"
        "4. Offline RE: binwalk -e <blob> && strings -a <blob> | less\n"
        "   (Ghidra headless for structured disassembly; see iot_re_forge.py).\n"
        "5. NOTE: live device reflash is NOT supported for the MT7922 —\n"
        "   the firmware is a closed MediaTek binary. Do NOT attempt\n"
        "   `use_dev_fw`-style reflashing; it bricks the card. Research is\n"
        "   source-level (mt76 driver) + offline blob RE only."
    )
    if not live_test:
        return {"ok": True, "method": "mt7921e_research_firmware",
                "target": target, "live_test": False,
                "recipe": recipe, "error": ""}
    # live_test path: MT7922 closed firmware — not safely reflashable.
    return {"ok": False, "method": "mt7921e_research_firmware",
            "target": target, "live_test": True,
            "recipe": recipe,
            "error": ("MT7922 firmware is a closed MediaTek binary blob — "
                      "live reflash is not supported (the legacy "
                      "use_dev_fw + 30s rollback trick does not apply). "
                      "Use the recipe for offline driver-source / "
                      "firmware-blob research only.")}


# ---------------------------------------------------------------------------
# Tool registry — consumed by core.mcp.tools to surface these to the AI.
# Each record matches KaliToolWrapper's fields so the MCP layer can wrap
# them uniformly (name/binary/description/input_schema/examples/risk_level/
# requires_root) plus the python entrypoint the runner calls.
# ---------------------------------------------------------------------------
EXTERNAL_INJECTION_TOOLS: List[Dict[str, Any]] = [
    {
        "name": "nemesis_inject",
        "binary": "nemesis",
        "description": (
            "L2/L3 packet crafter & injector (ARP/DHCP/DNS/ICMP/IGMP/IP/"
            "OSPF/RIP/TCP/UDP/ETHERNET). Use for wired-side or evil-twin "
            "L2 forging — ARP spoof, DHCP starvation, ICMP redirect, "
            "TCP RST injection — once you have a foothold on the "
            "target's L2. Requires root."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "protocol": {"type": "string", "enum": list(NEMESIS_PROTOCOLS)},
                "iface": {"type": "string", "description": "tx interface"},
                "args": {"type": "object", "description": (
                    "flag dict; aliases: src_ip→-S, dst_ip→-D, "
                    "src_mac→-M, count→-x, payload_file→-P, ttl→-T")},
            },
            "required": ["protocol"],
        },
        "examples": [
            "nemesis_inject(protocol='arp', iface='eth0', "
            "args={'S':'192.168.1.50','D':'192.168.1.1','M':'00:11:22:33:44:55'})",
            "nemesis_inject(protocol='dhcp', iface='eth0', args={'d':True})",
        ],
        "risk_level": "destructive",
        "requires_root": True,
        "domain": "wifi",
        "entrypoint": "nemesis_inject",
    },
    {
        "name": "inject_tool_inject",
        "binary": "inject",
        "description": (
            "Compact C L2/L3 craft+inject+sniff (eth/arp/ip/icmp/tcp/udp/"
            "sniff). Lighter than nemesis (no libnet). Same wired-side / "
            "evil-twin L2 forging role. Requires root."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "protocol": {"type": "string",
                             "enum": list(INJECT_TOOL_PROTOCOLS)},
                "iface": {"type": "string"},
                "args": {"type": "object", "description": (
                    "flag dict; aliases: src_ip→-S, dst_ip→-D, "
                    "src_mac→-K, dst_mac→-M, count→-c, ttl→-T, "
                    "flags→-f (syn/ack/rst/fin/psh/urg), "
                    "src_port→-o, dst_port→-d, payload_file→-a")},
            },
            "required": ["protocol"],
        },
        "examples": [
            "inject_tool_inject(protocol='tcp', iface='eth0', "
            "args={'S':'192.168.1.50','D':'192.168.1.1','o':'4444',"
            "'d':'80','f':'syn'})",
            "inject_tool_inject(protocol='arp', iface='eth0', "
            "args={'K':'00:11:22:33:44:55','S':'192.168.1.50',"
            "'D':'192.168.0.1','r':'1'})",
        ],
        "risk_level": "destructive",
        "requires_root": True,
        "domain": "wifi",
        "entrypoint": "inject_tool_inject",
    },
    {
        "name": "wpr_tx",
        "binary": "wpr_tx_rx",
        "description": (
            "Radiotap raw 802.11 TX/RX (WiFiPacketRadio). Non-scapy raw-"
            "frame injection path for non-mt7921e injection-capable "
            "adapters (e.g. RTL8812EU). Use when the adapter supports "
            "injection but is not mt7921e and the mt7921e scapy path is "
            "unavailable. Requires root + monitor mode."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "iface": {"type": "string", "description": "monitor iface"},
                "channel": {"type": "integer"},
                "payload_file": {"type": "string"},
                "count": {"type": "integer"},
                "extra_args": {"type": "array", "items": {"type": "string"}},
            },
        },
        "examples": [
            "wpr_tx(iface='wlan1mon', channel=6, payload_file='/tmp/frame.bin')",
        ],
        "risk_level": "destructive",
        "requires_root": True,
        "domain": "wifi",
        "entrypoint": "wpr_tx",
    },
    {
        "name": "cse508_dns_inject",
        "binary": "dnsinject",
        "description": (
            "Scapy DNS injection (spoofed DNS responses). Use on a "
            "bridged evil-twin / MITM position to redirect target DNS. "
            "Requires root."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "iface": {"type": "string"},
                "hostnames": {"type": "string",
                              "description": "host A ip file (per line)"},
                "expression": {"type": "string",
                               "description": "BPF filter (optional)"},
            },
            "required": ["iface"],
        },
        "examples": [
            "cse508_dns_inject(iface='at0', "
            "hostnames='toolboxes/wifi/saishsali__cse508/hw4/hostnames')",
        ],
        "risk_level": "intrusive",
        "requires_root": True,
        "domain": "wifi",
        "entrypoint": "cse508_dns_inject",
    },
    {
        "name": "mt7921e_research_firmware",
        "binary": "linux-firmware",
        "description": (
            "MediaTek MT7922 (mt7921e) firmware / driver research recipe. "
            "The MT7922 firmware is a closed MediaTek binary blob — the "
            "recipe clones the open in-tree mt76/mt7921e driver source "
            "(driver-level vuln hunting) and locates the closed firmware "
            "blob for offline reverse engineering. NOT runtime injection; "
            "live device reflash is NOT supported (returns ok=False with "
            "live_test=True). Defaults to returning the recipe (read)."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string",
                           "default": "mt7922"},
                "live_test": {"type": "boolean", "default": False},
            },
        },
        "examples": [
            "mt7921e_research_firmware(target='mt7922')",
            "mt7921e_research_firmware(live_test=True)",
        ],
        "risk_level": "read",
        "requires_root": False,
        "domain": "wifi",
        "entrypoint": "mt7921e_research_firmware",
    },
]