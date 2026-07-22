"""core.refactors.poly_adapt_integration — Phase 3 expansion T7.

Wires the polymorphic / target-adaptive companions from
:mod:`core.refactors.poly_adapt_companions` into the existing
algorithm runners:

* :mod:`core.wifi_attack.frames` — frame-burst pattern picker
* :mod:`core.ble.attack_runner` — BLE scan window picker
* :mod:`core.osint.osint_modules` — email-pattern picker
* :mod:`core.forensics.forensic_modules` — disk-carve picker
* :mod:`core.post_exploit.anti_forensic` — lateral-movement picker

The integration is **additive** — the existing helpers are
unchanged. The new ``poly_*_for_*`` wrappers call
``run_poly_adapt`` and return the result alongside the existing
return value.

Nothing here ever fabricates data. Every wrapper returns the
real envelope from ``run_poly_adapt`` — heuristic, never ML.
"""
from __future__ import annotations

from typing import Any, Dict

from core.refactors.poly_adapt_companions import run_poly_adapt


# ---------------------------------------------------------------------------
# WiFi — frame-burst pattern picker (T7.1)
# ---------------------------------------------------------------------------


def poly_deauth_burst_for_wifi(target_bssid: str = "",
                                client_count: int = 0,
                                pmf_supported: bool = False,
                                ) -> Dict[str, Any]:
    """Wrap :func:`run_poly_adapt` for the WiFi deauth-burst path.

    Returns the same envelope as ``run_poly_adapt`` — the next
    real chain step then uses ``data.primary`` to drive the
    actual frame injection.
    """
    return run_poly_adapt("poly_deauth_burst_pattern_grammar", {
        "seed": target_bssid or "wifi-burst",
        "bssid": target_bssid,
    })


def adapt_wifi_chipset_for_runner(chipset: str = "unknown") -> Dict[str, Any]:
    """Pick the monitor-mode driver from the detected chipset."""
    return run_poly_adapt("adapt_wifi_chipset_picker", {
        "chipset": chipset,
    })


def adapt_wifi_channel_width_for_runner(
    band: str = "",
    target: str = "",
) -> Dict[str, Any]:
    """Pick the channel width (20/40/80/160 MHz)."""
    return run_poly_adapt("adapt_wifi_channel_width_picker", {
        "band": band,
        "target": target,
    })


# ---------------------------------------------------------------------------
# BLE — scan window + chipset pickers (T7.2)
# ---------------------------------------------------------------------------


def adapt_ble_chipset_for_runner(chipset: str = "unknown") -> Dict[str, Any]:
    """Pick a BLE strategy from the detected chipset.

    For the operator's hardware (MediaTek MT7922 builtin + U4000
    BLUETOOTH adapter), this returns ``mediatek_via_bluetoothctl``
    for the built-in or ``realtek_via_btmon`` for the U4000.
    """
    return run_poly_adapt("adapt_ble_chipset_picker", {
        "chipset": chipset,
    })


def adapt_ble_pairing_for_runner(
    io_cap: str = "",
    auth_required: bool = False,
) -> Dict[str, Any]:
    """Pick a BLE pairing method from advertised IO capabilities."""
    return run_poly_adapt("adapt_ble_pairing_method_picker", {
        "io_cap": io_cap,
        "auth_required": auth_required,
    })


# ---------------------------------------------------------------------------
# OSINT — email pattern + jurisdiction (T7.3)
# ---------------------------------------------------------------------------


def poly_email_pattern_for_runner(
    target_domain: str = "",
    target_kind: str = "person",
) -> Dict[str, Any]:
    """Pick an email-pattern heuristic for an OSINT target.

    The returned ``variants`` are templates (placeholders like
    ``at_domain``) — never real emails.
    """
    return run_poly_adapt("poly_email_pattern_grammar", {
        "seed": target_domain or target_kind or "osint",
    })


def adapt_osint_jurisdiction_for_runner(jurisdiction: str = "") -> Dict[str, Any]:
    """Pick an OSINT source from the target's jurisdiction.

    Falls back to no-key sources (GitHub + nameday + HIBP)
    when the jurisdiction is unknown — never fabricates APIs.
    """
    return run_poly_adapt("adapt_osint_jurisdiction_picker", {
        "jurisdiction": jurisdiction,
    })


# ---------------------------------------------------------------------------
# Forensics — disk carve + image format (T7.4)
# ---------------------------------------------------------------------------


def poly_disk_carve_signature_for_runner(
    image_path: str = "",
    target_ext: str = "",
) -> Dict[str, Any]:
    """Pick a file-carving signature for the next carve step."""
    return run_poly_adapt("poly_disk_carve_signature_grammar", {
        "seed": image_path or target_ext or "carve",
    })


def adapt_forensics_image_format_for_runner(
    audience: str = "",
    has_ewf: bool = False,
) -> Dict[str, Any]:
    """Pick a forensic image format from audience + tool availability."""
    return run_poly_adapt("adapt_forensics_image_format_picker", {
        "audience": audience,
        "has_ewf": has_ewf,
    })


def adapt_forensics_timeline_format_for_runner(audience: str = "") -> Dict[str, Any]:
    """Pick a timeline format for the IR/forensic audience."""
    return run_poly_adapt("adapt_forensics_timeline_format_picker", {
        "audience": audience,
    })


# ---------------------------------------------------------------------------
# Post-exploit — lateral movement + persistence (T7.5)
# ---------------------------------------------------------------------------


def poly_lateral_movement_for_runner(
    target_os: str = "windows",
    has_smb: bool = True,
    has_winrm: bool = True,
) -> Dict[str, Any]:
    """Pick a lateral-movement vector variant.

    The returned ``variants`` are vector names; the next real
    step uses the primary one.
    """
    return run_poly_adapt("poly_lateral_movement_grammar", {
        "seed": target_os or "lateral",
    })


def poly_persistence_for_runner(target_os: str = "windows") -> Dict[str, Any]:
    """Pick a persistence-mechanism variant for the target OS."""
    return run_poly_adapt("poly_persistence_registry_grammar", {
        "seed": target_os or "persist",
    })


def adapt_persistence_mechanism_for_runner(
    target_os: str = "windows",
    survive_reboot: bool = True,
) -> Dict[str, Any]:
    """Pick a persistence mechanism based on target OS + reboot tolerance."""
    return run_poly_adapt("adapt_persistence_mechanism_picker", {
        "target_os": target_os,
        "survive_reboot": survive_reboot,
    })


def adapt_exfil_channel_for_runner(
    egress: str = "default",
    size_kb: int = 0,
) -> Dict[str, Any]:
    """Pick an exfiltration channel from egress posture."""
    return run_poly_adapt("adapt_exfil_channel_picker", {
        "egress": egress,
        "size_kb": size_kb,
    })
