"""core.tool_installer.check_sdr — detect whether SDR hardware is available.

Phase 2.4 — operator's setup: only internal ``wlan0`` (mt7921e with
packet injection) and ``hci0`` (U4000 BLUETOOTH adapter). All SDR /
HackRF / Ubertooth / BladeRF / LimeSDR / USRP paths are skipped.
This module reports ``sdr_available: false`` so any module
requiring SDR honest-degrades with a clear reason.
"""
from __future__ import annotations

import shutil
from typing import Any, Dict, List


# Tools that imply SDR hardware is required. If any of them is
# installed, we still return ``sdr_available: false`` because the
# operator has explicitly said to skip SDR. We just list the
# presence of these binaries for the audit.
_SDR_BINARIES: List[str] = [
    "hackrf_info", "hackrf_transfer",
    "rtl_sdr", "rtl_test",
    "gqrx", "cubic-sdr",
    "kalibrate-rtl", "multimon-ng",
    "ubertooth-util", "ubertooth-bt", "ubertooth-fw",
    "bladerf-cli", "LimeSuite", "uhd_find_devices",
    "gnuradio-companion",
]


def is_sdr_available() -> bool:
    """Operator policy: SDR is *never* available. Returns False.

    We never use SDR hardware. This function is a sentinel so any
    code path that asks "is SDR available?" gets a clear No.
    """
    return False


def sdr_status() -> Dict[str, Any]:
    """Return a status dict::

        {sdr_available: False, installed_sd binaries: [<name>...],
         policy: "skip-sdr"}

    The ``installed_sd binaries`` field lists SDR binaries that
    happen to be on PATH (informational; we don't use them).
    """
    installed = [b for b in _SDR_BINARIES if shutil.which(b)]
    return {"sdr_available": False,
            "policy": "skip-sdr",
            "installed_sdr_binaries": installed,
            "note": "operator setup excludes SDR / HackRF / Ubertooth / "
                    "BladeRF / LimeSDR / USRP hardware. Only internal "
                    "wlan0 (mt7921e) and hci0 (U4000 BLUETOOTH adapter) are used."}


__all__ = ["is_sdr_available", "sdr_status"]
