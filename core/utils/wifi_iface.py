"""
WiFi Interface Helpers
=====================
Helpers for inspecting and asserting the current mode of a wireless
interface. The dashboard's WiFi flows require the operator to put the
interface into monitor mode externally before any offensive work runs;
this module detects whether monitor mode is active and refuses to
proceed with a clear remediation message when it is not.

Monitor mode cannot be set programmatically from the unprivileged
``KFIOSA`` process — the user must run one of the suggested commands
themselves in a root terminal. We never fake a monitor-mode result.
"""

import logging
import re
import shutil
import subprocess
from typing import Optional

logger = logging.getLogger(__name__)


class MonitorModeRequired(RuntimeError):
    """Raised when an interface is not in monitor mode but the caller
    requires it.

    The ``commands`` attribute holds one or more shell command strings
    the operator can run in a root terminal to enable monitor mode.
    """

    def __init__(self, iface: str, current_mode: str):
        self.iface = iface
        self.current_mode = current_mode
        self.commands = [
            # airmon-ng is the canonical, opinionated way
            f"sudo airmon-ng start {iface}",
            # or, manually with iw + ip
            f"sudo ip link set {iface} down && "
            f"sudo iw dev {iface} set type monitor && "
            f"sudo ip link set {iface} up",
        ]
        msg = (
            f"Interface '{iface}' is in '{current_mode}' mode. "
            f"Monitor mode is required for WiFi pentest operations. "
            f"Run one of these in a root terminal:\n  "
            f"{self.commands[0]}\n  {self.commands[1]}"
        )
        super().__init__(msg)


def iface_current_mode(iface: str) -> str:
    """Return the current mode of a wireless interface.

    Parses ``iw dev <iface> info`` (works whether or not the iface is up).
    Returns one of: ``"monitor"``, ``"managed"``, ``"unknown"``,
    or ``"error"`` if iw is missing / the iface does not exist /
    the call fails.

    Never raises — failures degrade to ``"error"`` so callers can
    branch on the return value.
    """
    if not iface:
        return "error"
    if not shutil.which("iw"):
        logger.debug("iw not installed; cannot read interface mode")
        return "error"
    try:
        p = subprocess.run(
            ["iw", "dev", iface, "info"],
            capture_output=True, text=True, timeout=8,
        )
    except subprocess.TimeoutExpired:
        logger.warning("iw dev %s info timed out", iface)
        return "error"
    except FileNotFoundError:
        return "error"
    except Exception as e:
        logger.debug("iw dev %s info: %s", iface, e)
        return "error"

    if p.returncode != 0:
        # iw returns non-zero if iface is gone / unknown; treat as error
        # rather than guessing.
        return "error"

    # `iw dev <iface> info` lines we care about:
    #   Interface wlan0
    #       ifindex 3
    #       type managed        <-- or "monitor"
    #       wiphy 0
    #       ...
    m = re.search(r"^\s*type\s+(\S+)\s*$", p.stdout, re.MULTILINE)
    if not m:
        return "unknown"
    mode = m.group(1).strip().lower()
    if mode in ("monitor", "managed", "mesh", "ad-hoc", "ibss", "ap"):
        return mode
    return "unknown"


def assert_monitor_mode(iface: str) -> str:
    """Assert that ``iface`` is in monitor mode. Returns the mode string
    on success; raises :class:`MonitorModeRequired` on failure with the
    exact remediation commands the operator can run.

    The dashboard calls this at the top of any WiFi offensive step.
    """
    mode = iface_current_mode(iface)
    if mode == "monitor":
        return mode
    raise MonitorModeRequired(iface, mode)


def is_monitor_capable(iface: str) -> bool:
    """Best-effort check whether the underlying phy supports monitor mode.

    Reuses :mod:`core.tui.interface_picker` when available. Returns
    ``False`` on any error so callers default to "not supported".
    """
    try:
        from core.tui.interface_picker import detect_wireless_interfaces
    except Exception as e:
        logger.debug("interface_picker import failed: %s", e)
        return False
    try:
        ifaces = detect_wireless_interfaces()
    except Exception as e:
        logger.debug("detect_wireless_interfaces failed: %s", e)
        return False
    for row in ifaces or []:
        if row.get("name") == iface:
            return bool(row.get("monitor"))
    return False
