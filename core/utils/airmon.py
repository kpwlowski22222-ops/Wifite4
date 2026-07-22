"""Thin airmon-ng wrapper for monitor-mode vif lifecycle.

Reusable adapter start/stop lifted from ``WiFiScanner._start_monitor_airmon``
(``core/scanners/wifi_scanner.py``): the same subprocess+timeout pattern and
the same monitor-iface name parse (regexes ``r"\\]\\s*(\\S+mon)\\b"`` and
``r"enabled on (\\S+)"``). Unlike the scanner, this wrapper is happy to
invoke ``sudo`` when the process is unprivileged so the dashboard TUI can
engage ``airmon-ng`` without already being root.

Both functions return dicts and never raise — callers (the dashboard quit
path, the WiFi screen adapter-selection path) branch on ``["ok"]`` exactly
the same way they do for the other Kali wrappers.
"""

from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


def _airmon_cmd(parts: list) -> list:
    """Prefix ``sudo`` when not running as root (mirrors the dashboard
    convention: airmon-ng mutates adapter state, so we either are root or
    delegate to sudo)."""
    if os.geteuid() == 0:
        return list(parts)
    return ["sudo"] + list(parts)


def _sudo_cmd(parts: list) -> list:
    """Prefix ``sudo`` when not running as root (generic helper for the
    ip/iw monitor-mode flip). Same convention as :func:`_airmon_cmd`."""
    if os.geteuid() == 0:
        return list(parts)
    return ["sudo"] + list(parts)


def _iw_dev_info(iface: str, timeout: int = 5) -> str:
    """Return ``iw dev <iface> info`` stdout (empty on any failure)."""
    if not shutil.which("iw"):
        return ""
    try:
        p = subprocess.run(_sudo_cmd(["iw", "dev", iface, "info"]),
                           capture_output=True, text=True, timeout=timeout)
        return p.stdout or ""
    except Exception:  # noqa: BLE001 — degrade, never raise
        return ""


def _iw_is_monitor(iface: str) -> bool:
    """True iff ``iw dev <iface> info`` reports ``type monitor``.

    This is the runtime ground-truth that monitor mode actually engaged —
    critical for the MediaTek MT7922 (``mt7921e`` / mac80211 / mt76), where
    ``airmon-ng start`` can report success (and even print a monitor vif
    name) without the interface actually being in monitor mode, e.g. when
    NetworkManager / wpa_supplicant re-grab the interface, or when the
    mt76 driver leaves the original interface in managed mode.
    """
    info = _iw_dev_info(iface)
    # `iw dev <iface> info` prints a line like:
    #     Interface wlan0mon
    #         ifindex 4
    #         wdev 0x2
    #         addr ...
    #         type monitor
    #         channel ...
    return "type monitor" in info


def _iw_flip_to_monitor(iface: str, timeout: int = 10) -> Dict[str, Any]:
    """In-place iw+ip flip of ``iface`` to monitor mode (no separate vif).

    Used as the fallback for the MT7922 / mt7921e (and any mac80211 card)
    when ``airmon-ng start`` does not actually engage monitor mode. The
    mt7921e driver supports monitor mode on the main interface via the
    standard mac80211 path, so no ``wlanXmon`` vif is required::

        ip link set <iface> down
        iw dev <iface> set type monitor
        ip link set <iface> up

    Returns ``{ok, monitor_iface, method, error}``. Never raises.
    """
    out: Dict[str, Any] = {"ok": False, "monitor_iface": None,
                           "method": "iw_flip", "error": ""}
    if not shutil.which("iw") or not shutil.which("ip"):
        out["error"] = "iw or ip not installed — cannot flip to monitor mode"
        return out
    for parts in (
        ["ip", "link", "set", iface, "down"],
        ["iw", "dev", iface, "set", "type", "monitor"],
        ["ip", "link", "set", iface, "up"],
    ):
        try:
            p = subprocess.run(_sudo_cmd(parts), capture_output=True,
                                text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            out["error"] = f"monitor flip timed out at: {' '.join(parts)}"
            return out
        except Exception as e:  # noqa: BLE001 — degrade, never raise
            out["error"] = f"monitor flip {' '.join(parts)}: {e}"
            return out
        if p.returncode != 0:
            out["error"] = (f"monitor flip {' '.join(parts)} rc={p.returncode}: "
                            + (p.stderr or "").strip()[:200])
            return out
    # Verify monitor mode actually engaged (ground-truth for mt7921e).
    if _iw_is_monitor(iface):
        out["ok"] = True
        out["monitor_iface"] = iface
        return out
    out["error"] = (f"monitor flip ran but {iface} is not in monitor mode "
                    "(NetworkManager/wpa_supplicant may be re-managing it; "
                    "run `sudo airmon-ng check kill` and retry)")
    return out


def airmon_start(iface: str, timeout: int = 20) -> Dict[str, Any]:
    """Engage monitor mode on ``iface`` and return the monitor interface name.

    Primary path: ``airmon-ng start <iface>`` (produces the conventional
    ``wlan[id]mon`` vif). For the MediaTek MT7922 (``mt7921e`` / mac80211 /
    mt76) — and any adapter where airmon-ng silently fails to actually put
    the interface into monitor mode — we **verify** the result with
    ``iw dev <iface> info`` (``type monitor``) and fall back to an in-place
    ``ip link set down`` → ``iw dev <iface> set type monitor`` →
    ``ip link set up`` flip on the original interface. This is the fix for
    mt7921e monitor-mode enablement: airmon-ng's exit code is not trusted
    alone; the runtime ``type monitor`` ground-truth is.

    Returns a dict with the keys ``ok``, ``monitor_iface``, ``original_iface``,
    ``method`` (``airmon`` or ``iw_flip``), ``returncode``, ``stdout``,
    ``stderr``, ``error``. Never raises; subprocess timeouts and unexpected
    errors are caught and surfaced via ``error``.
    """
    result: Dict[str, Any] = {
        "ok": False,
        "monitor_iface": None,
        "original_iface": iface,
        "method": "airmon",
        "returncode": -1,
        "stdout": "",
        "stderr": "",
        "error": "",
    }
    if not shutil.which("airmon-ng"):
        # airmon-ng absent — try the iw flip directly so the MT7922 still
        # gets monitor mode on boxes without the aircrack-ng suite.
        flip = _iw_flip_to_monitor(iface)
        if flip.get("ok"):
            result.update(ok=True, monitor_iface=flip["monitor_iface"],
                           method="iw_flip")
            return result
        result["error"] = "airmon-ng not installed"
        return result
    cmd = _airmon_cmd(["airmon-ng", "start", iface])
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        result["error"] = f"airmon-ng start timed out after {timeout}s"
        return result
    except Exception as e:  # noqa: BLE001 — broad on purpose, we degrade
        result["error"] = f"airmon-ng: {e}"
        return result
    result["returncode"] = p.returncode
    result["stdout"] = p.stdout or ""
    result["stderr"] = p.stderr or ""
    out = p.stdout or ""
    mon_iface: Optional[str] = None
    if p.returncode == 0:
        # airmon-ng prints a line like:
        #   (mac80211 monitor mode vif enabled on [phy0]wlan0mon)
        # or, on older versions:
        #   monitor mode enabled on wlan0mon
        m = re.search(r"\]\s*(\S+mon)\b", out) or re.search(r"enabled on (\S+)", out)
        if m:
            mon_iface = m.group(1)
        else:
            # Parse failed but airmon-ng reported success — assume <iface>mon.
            logger.debug("airmon_start: could not parse monitor iface from stdout=%r", out)
            mon_iface = f"{iface}mon"
    # Verify monitor mode actually engaged (mt7921e ground-truth). If the
    # airmon-ng vif is genuinely in monitor mode, we are done.
    if mon_iface and _iw_is_monitor(mon_iface):
        result["monitor_iface"] = mon_iface
        result["ok"] = True
        return result
    # airmon-ng did not produce a verified monitor interface (rc!=0, parse
    # miss, or the vif is not actually in monitor mode — common on mt7921e
    # when NetworkManager re-manages it). Fall back to the iw flip on the
    # original interface.
    logger.debug("airmon_start: airmon-ng did not verify monitor on %r; "
                 "falling back to iw flip on %r", mon_iface, iface)
    flip = _iw_flip_to_monitor(iface)
    if flip.get("ok"):
        result.update(ok=True, monitor_iface=flip["monitor_iface"],
                       method="iw_flip")
        return result
    # Both paths failed — surface a concrete error.
    if p.returncode != 0:
        result["error"] = (p.stderr or "").strip() or f"airmon-ng rc={p.returncode}"
        result["error"] += f" | iw_flip: {flip.get('error')}"
    else:
        result["error"] = (f"monitor mode not engaged on {iface} "
                           f"(airmon-ng rc=0 but type!=monitor; iw_flip: "
                           f"{flip.get('error')})")
    return result


def airmon_stop(monitor_iface: str, timeout: int = 15) -> Dict[str, Any]:
    """Run ``airmon-ng stop <monitor_iface>`` and tear down the vif.

    Returns a dict with ``ok``, ``returncode``, ``stdout``, ``stderr``,
    ``error``. Never raises; on failure ``error`` carries a remediation
    string telling the operator to run the stop command manually.
    """
    result: Dict[str, Any] = {
        "ok": False,
        "returncode": -1,
        "stdout": "",
        "stderr": "",
        "error": "",
    }
    if not shutil.which("airmon-ng"):
        result["error"] = (
            "airmon-ng not installed — run "
            f"`sudo airmon-ng stop {monitor_iface}` manually"
        )
        return result
    cmd = _airmon_cmd(["airmon-ng", "stop", monitor_iface])
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        result["error"] = (
            f"airmon-ng stop timed out after {timeout}s — run "
            f"`sudo airmon-ng stop {monitor_iface}` manually"
        )
        return result
    except Exception as e:  # noqa: BLE001 — broad on purpose, we degrade
        result["error"] = (
            f"airmon-ng: {e} — run "
            f"`sudo airmon-ng stop {monitor_iface}` manually"
        )
        return result
    result["returncode"] = p.returncode
    result["stdout"] = p.stdout or ""
    result["stderr"] = p.stderr or ""
    if p.returncode != 0:
        result["error"] = (
            (p.stderr or "").strip()
            or f"airmon-ng rc={p.returncode}"
        ) + f" — run `sudo airmon-ng stop {monitor_iface}` manually"
        return result
    result["ok"] = True
    return result