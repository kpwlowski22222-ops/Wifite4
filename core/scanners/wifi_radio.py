"""WiFi radio pre-flight for reliable airodump / iw scans.

Real-world scanning fails when:

* NetworkManager / wpa_supplicant hold the phy
* two monitor VIFs share one radio (common after repeated airmon starts)
* the caller keeps the *pre*-airmon name while airodump needs ``*mon``
* the interface is managed/down but airodump is started anyway

These helpers fix that best-effort when the process is root, and return
honest errors when not. Never fabricates APs.
"""
from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


def _run(cmd: List[str], timeout: float = 12) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd, capture_output=True, text=True, timeout=timeout,
    )


def is_root() -> bool:
    try:
        return os.geteuid() == 0
    except Exception:
        return False


def list_wireless_ifaces() -> List[str]:
    """Return wireless netdev names via ``iw dev`` (no elev required)."""
    if not shutil.which("iw"):
        return []
    try:
        p = _run(["iw", "dev"], timeout=8)
    except Exception as e:
        logger.debug("iw dev failed: %s", e)
        return []
    names: List[str] = []
    for line in (p.stdout or "").splitlines():
        m = re.match(r"^\s*Interface\s+(\S+)\s*$", line)
        if m:
            names.append(m.group(1))
    return names


def iface_mode(iface: str) -> str:
    try:
        from core.utils.wifi_iface import iface_current_mode
        return iface_current_mode(iface)
    except Exception:
        return "error"


def kill_rf_interferers() -> Dict[str, Any]:
    """Stop NetworkManager / wpa_supplicant that steal the radio.

    Uses ``airmon-ng check kill`` when available + root. Non-root → no-op
    with an honest note. Safe to call repeatedly.
    """
    out: Dict[str, Any] = {"ok": False, "killed": [], "note": ""}
    if not is_root():
        out["note"] = "not root — cannot stop NetworkManager/wpa_supplicant"
        return out
    if shutil.which("airmon-ng"):
        try:
            p = _run(["airmon-ng", "check", "kill"], timeout=20)
            out["ok"] = True
            out["stdout"] = (p.stdout or "")[-500:]
            # Parse "PID Name" section lightly
            for line in (p.stdout or "").splitlines():
                m = re.match(r"\s*(\d+)\s+(\S+)", line)
                if m:
                    out["killed"].append({"pid": m.group(1), "name": m.group(2)})
            return out
        except Exception as e:
            out["note"] = f"airmon-ng check kill: {e}"
    # Fallback: systemctl stop (best-effort)
    for svc in ("NetworkManager", "wpa_supplicant", "iwd"):
        try:
            p = _run(["systemctl", "stop", svc], timeout=10)
            if p.returncode == 0:
                out["killed"].append({"name": svc, "via": "systemctl"})
                out["ok"] = True
        except Exception:
            pass
    if not out["ok"] and not out["note"]:
        out["note"] = "no airmon-ng / systemctl stop available"
    return out


def collapse_duplicate_monitor_vifs(prefer: Optional[str] = None) -> Dict[str, Any]:
    """If multiple monitor VIFs share a phy, keep one (prefer ``prefer``).

    Dual monitor interfaces on the same chipset often yield *zero* beacons
    in airodump even though the radio is fine in managed ``iw scan``.
    """
    result: Dict[str, Any] = {"ok": True, "removed": [], "kept": None}
    if not is_root() or not shutil.which("iw"):
        result["ok"] = False
        result["note"] = "need root + iw to collapse monitor VIFs"
        return result

    mon: List[str] = []
    for name in list_wireless_ifaces():
        if iface_mode(name) == "monitor":
            mon.append(name)
    if len(mon) <= 1:
        result["kept"] = mon[0] if mon else prefer
        return result

    keep = prefer if prefer in mon else mon[0]
    # Prefer names ending in mon when prefer not set / not monitor
    if prefer not in mon:
        mon_named = [n for n in mon if n.endswith("mon")]
        if mon_named:
            keep = mon_named[0]
    result["kept"] = keep
    for name in mon:
        if name == keep:
            continue
        try:
            _run(["ip", "link", "set", name, "down"], timeout=6)
            p = _run(["iw", "dev", name, "del"], timeout=6)
            if p.returncode == 0:
                result["removed"].append(name)
            else:
                # Some drivers cannot del primary; flip to managed instead
                _run(["iw", "dev", name, "set", "type", "managed"], timeout=6)
                result["removed"].append(f"{name}->managed")
        except Exception as e:
            logger.debug("collapse mon %s: %s", name, e)
    return result


def ensure_iface_up_monitor(iface: str) -> Dict[str, Any]:
    """Ensure ``iface`` exists, is up, and in monitor mode (root)."""
    if not iface:
        return {"error": "no interface"}
    mode = iface_mode(iface)
    if mode == "monitor":
        # Ensure link is up
        if is_root() and shutil.which("ip"):
            try:
                _run(["ip", "link", "set", iface, "up"], timeout=6)
            except Exception:
                pass
        return {"ok": True, "interface": iface, "mode": "monitor", "method": "already"}

    if not is_root():
        return {
            "error": (
                f"{iface} is '{mode}' (need monitor + root). "
                f"Run: sudo airmon-ng start {iface}"
            ),
            "interface": iface,
            "mode": mode,
        }

    # Prefer airmon-ng start
    if shutil.which("airmon-ng") and mode == "managed":
        try:
            p = _run(["airmon-ng", "start", iface], timeout=20)
            out = (p.stdout or "") + "\n" + (p.stderr or "")
            m = re.search(r"\]\s*(\S+mon)\b", out) or re.search(
                r"enabled on (\S+)", out
            )
            if m:
                new_iface = m.group(1)
                try:
                    _run(["ip", "link", "set", new_iface, "up"], timeout=6)
                except Exception:
                    pass
                return {
                    "ok": True,
                    "interface": new_iface,
                    "mode": "monitor",
                    "method": "airmon",
                    "from": iface,
                }
        except Exception as e:
            logger.debug("airmon-ng start %s: %s", iface, e)

    # In-place iw flip
    if shutil.which("iw") and shutil.which("ip"):
        try:
            for cmd in (
                ["ip", "link", "set", iface, "down"],
                ["iw", "dev", iface, "set", "type", "monitor"],
                ["ip", "link", "set", iface, "up"],
            ):
                p = _run(cmd, timeout=8)
                if p.returncode != 0 and "type" in cmd:
                    return {
                        "error": (
                            f"iw set type monitor failed: "
                            f"{(p.stderr or '').strip() or p.returncode}"
                        ),
                        "interface": iface,
                    }
            return {
                "ok": True,
                "interface": iface,
                "mode": "monitor",
                "method": "iw",
            }
        except Exception as e:
            return {"error": str(e), "interface": iface}

    return {
        "error": f"cannot put {iface} into monitor mode",
        "interface": iface,
        "mode": mode,
    }


def pick_best_scan_iface(requested: Optional[str] = None) -> Optional[str]:
    """Pick the best iface for scanning: requested if monitor, else any mon, else requested/first."""
    ifaces = list_wireless_ifaces()
    if not ifaces:
        return requested
    if requested and requested in ifaces and iface_mode(requested) == "monitor":
        return requested
    for name in ifaces:
        if iface_mode(name) == "monitor":
            return name
    if requested and requested in ifaces:
        return requested
    return ifaces[0]


def prep_for_wifi_scan(
    iface: Optional[str] = None,
    *,
    kill_interferers: bool = True,
    collapse_dups: bool = True,
) -> Dict[str, Any]:
    """Full pre-flight before airodump / live scan.

    Returns::

        {
          "ok": bool,
          "interface": str,   # use THIS name for airodump
          "mode": str,
          "notes": [str, ...],
          "error": optional str,
          "kill": {...},
          "collapse": {...},
        }
    """
    notes: List[str] = []
    kill_info: Dict[str, Any] = {}
    collapse_info: Dict[str, Any] = {}

    chosen = pick_best_scan_iface(iface)
    if not chosen:
        return {
            "ok": False,
            "error": "no wireless interface detected (iw dev)",
            "interface": iface,
            "notes": notes,
        }

    if kill_interferers:
        kill_info = kill_rf_interferers()
        if kill_info.get("killed"):
            notes.append(
                "stopped RF interferers: "
                + ", ".join(
                    k.get("name", "?") for k in kill_info["killed"][:8]
                )
            )
        elif kill_info.get("note"):
            notes.append(kill_info["note"])

    if collapse_dups:
        collapse_info = collapse_duplicate_monitor_vifs(prefer=chosen)
        if collapse_info.get("removed"):
            notes.append(
                "removed duplicate monitor VIFs: "
                + ", ".join(collapse_info["removed"])
            )
        if collapse_info.get("kept"):
            chosen = collapse_info["kept"]

    mon = ensure_iface_up_monitor(chosen)
    if mon.get("error"):
        return {
            "ok": False,
            "error": mon["error"],
            "interface": chosen,
            "mode": mon.get("mode") or iface_mode(chosen),
            "notes": notes,
            "kill": kill_info,
            "collapse": collapse_info,
        }

    final = mon.get("interface") or chosen
    # Re-collapse if airmon created a second mon
    if collapse_dups:
        c2 = collapse_duplicate_monitor_vifs(prefer=final)
        if c2.get("kept"):
            final = c2["kept"]
        if c2.get("removed"):
            notes.append(
                "post-airmon collapse: " + ", ".join(c2["removed"])
            )
            collapse_info = c2

    return {
        "ok": True,
        "interface": final,
        "mode": "monitor",
        "method": mon.get("method"),
        "notes": notes,
        "kill": kill_info,
        "collapse": collapse_info,
    }


def airodump_cmd(
    iface: str,
    prefix: str,
    *,
    berlin: int = 300,
    multi_band: bool = True,
) -> List[List[str]]:
    """Return preferred airodump command variants (multi-band first)."""
    base = [
        "airodump-ng",
        iface,
        "-w", prefix,
        "--write-interval", "1",
        "--output-format", "csv",
        "--berlin", str(max(int(berlin), 120)),
    ]
    variants: List[List[str]] = []
    if multi_band:
        variants.append(base + ["--band", "abg"])
    variants.append(list(base))
    return variants
