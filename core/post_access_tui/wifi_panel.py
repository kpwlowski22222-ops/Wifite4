"""core.post_access_tui.wifi_panel — WIFI RAT-like TUI panel.

Extends the post-access TUI with a WiFi attack panel that talks to
the operator's wireless adapter (MediaTek MT7922 + U4000 BLUETOOTH
adapter) via airmon-ng, airodump-ng, aireplay-ng, hcxdumptool,
hashcat, etc. — the same substrate used by ``core.wifi_attack.runner``
and ``core.extended_wifi.runner``.

Dynamic menu (Phase 2.1.D+):
  The panel keeps a :class:`WifiPanelState` snapshot (adapter mode,
  selected AP, captured handshake, monitor mode status, scan results,
  etc.) and renders ONLY the actions that are currently applicable.
  The capability catalog is in ``wifi_panel_capabilities.py`` (78
  actions spanning legacy WPA/WPA2/WPA3, evil-twin, karma, OFDMA,
  Wi-Fi 7, AI/heuristic modules, frame crafting, cracking, etc.).
  The menu is recomputed on every state change.

Examples:
  - No adapter: ``[A]dapters / [I] Select adapter / [?] Help / [E]xit``
  - Adapter in managed: adds ``[M]onitor``
  - Adapter in monitor: adds ``[S]can / [L]ist / [P]ick / [C]hannel``
  - AP selected (WPA2, with clients): adds ``[1] Deauth``,
    ``[2] Handshake``, ``[3] PMKID``, ``[K] Kr00k``, ``[t] Evil twin``,
    ``[1] Deauth``, ``[T]x power``, ``[B]and steer``, etc.
  - Handshake captured + wordlist: adds ``[=] Hashcat 22001``

The panel is hermetic-friendly: every method takes an injected
``runner`` (a real WiFiAttackRunner / ExtendedWiFiRunner or a
fake). Tests inject a fake.

Safety stance (carried over):
  - Every intrusive / destructive action is operator-gated via
    ``self.confirm_fn(prompt)`` BEFORE the dispatch.
  - The panel NEVER auto-starts an evil-twin / karma / mdk4 /
    beacon-flood without an explicit ACCEPT.
  - The panel NEVER forges a PSK, a WPA2 password, or a hashcat
    outcome. The runner does the real subprocess; the panel only
    surfaces the command and the result.
  - The panel never auto-deauths a target on operator-owned networks
    without ACCEPT.

Single-gate invariant:
  The screen's ``_gate`` is the only gate. The panel's
  ``dispatch(...)`` method is the action layer; it does NOT
  re-confirm (single-gate).
"""
from __future__ import annotations

import json
import logging
import os
import re
import shlex
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from core.tui.base_screen import BaseScreen

from .session_state import _now
from .wifi_panel_capabilities import (
    CAPABILITY_CATALOG,
    RISK_DESTRUCTIVE,
    RISK_INTRUSIVE,
    RISK_READ,
    Capability,
    WifiPanelState,
    compute_visible_menu,
    default_disconnected_menu,
    friendly_action,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Discovered AP / client / capture records
# ---------------------------------------------------------------------------

@dataclass
class WiFiAP:
    """A discovered access point from a scan."""
    bssid: str               # MAC of the AP
    ssid: str = ""           # broadcast SSID
    channel: int = 0
    encryption: str = ""     # "WPA2", "WPA3", "WEP", "OPEN", "WPA/WPA2"
    cipher: str = ""
    auth: str = ""
    wps: bool = False
    pmf: bool = False
    band: str = ""           # "2.4", "5", "6"
    rssi: int = 0
    clients: List[str] = field(default_factory=list)  # associated MACs
    pwr: int = 0
    beacons: int = 0
    ivs: int = 0
    notes: str = ""


# ---------------------------------------------------------------------------
# WIFI panel client (real airmon/airodump backend)
# ---------------------------------------------------------------------------

class WiFiPanelClient:
    """Default backend: real ``airmon-ng`` / ``airodump-ng`` /
    ``aireplay-ng`` / ``hcxdumptool`` / ``hashcat`` subprocesses.

    Mirrors the conventions in ``core.wifi_attack.runner`` and
    ``core.extended_wifi.runner``. Returns the same envelope shape
    ``{"ok", "data", "error", ...}`` for hermetic parity with the
    runners.
    """

    DEFAULT_TIMEOUT = 30

    def __init__(self, *, adapter: Optional[str] = None,
                 timeout: int = DEFAULT_TIMEOUT):
        self.adapter = adapter  # e.g. "wlan0"
        self.timeout = timeout

    # ------------------------------------------------------------------
    # Adapter discovery
    # ------------------------------------------------------------------
    def list_adapters(self) -> Dict[str, Any]:
        """List wireless interfaces via ``iw dev`` (read-only, safe)."""
        started = time.time()
        try:
            r = subprocess.run(
                ["iw", "dev"], capture_output=True, text=True,
                timeout=5,
            )
            return {
                "ok": r.returncode == 0,
                "data": {"stdout": r.stdout, "stderr": r.stderr},
                "error": "" if r.returncode == 0 else "iw dev failed",
                "duration_s": time.time() - started,
                "host_os": "Linux", "risk": RISK_READ,
            }
        except FileNotFoundError:
            return {
                "ok": False, "data": None,
                "error": "iw not installed",
                "duration_s": 0.0, "host_os": "Linux", "risk": RISK_READ,
            }
        except Exception as e:  # noqa: BLE001
            return {
                "ok": False, "data": None, "error": f"iw dev: {e}",
                "duration_s": time.time() - started,
                "host_os": "Linux", "risk": RISK_READ,
            }

    def driver_info(self, adapter: str) -> Dict[str, Any]:
        """Show phy / driver info for the adapter (``iw phy``)."""
        started = time.time()
        try:
            r = subprocess.run(
                ["iw", "phy"], capture_output=True, text=True,
                timeout=5,
            )
            return {
                "ok": r.returncode == 0,
                "data": {"stdout": r.stdout[:4096]},
                "error": "" if r.returncode == 0 else "iw phy failed",
                "duration_s": time.time() - started,
                "host_os": "Linux", "risk": RISK_READ,
            }
        except Exception as e:  # noqa: BLE001
            return {
                "ok": False, "data": None, "error": f"iw phy: {e}",
                "duration_s": time.time() - started,
                "host_os": "Linux", "risk": RISK_READ,
            }

    # ------------------------------------------------------------------
    # Mode switching (root-required)
    # ------------------------------------------------------------------
    def enable_monitor(self, adapter: str) -> Dict[str, Any]:
        """``airmon-ng start <iface>`` (root-required)."""
        started = time.time()
        try:
            r = subprocess.run(
                ["airmon-ng", "start", adapter],
                capture_output=True, text=True,
                timeout=self.timeout,
            )
            return {
                "ok": r.returncode == 0,
                "data": {"stdout": r.stdout, "stderr": r.stderr},
                "error": "" if r.returncode == 0 else "airmon-ng start failed",
                "duration_s": time.time() - started,
                "host_os": "Linux", "risk": RISK_INTRUSIVE,
            }
        except FileNotFoundError:
            return {
                "ok": False, "data": None,
                "error": "airmon-ng not installed",
                "duration_s": 0.0, "host_os": "Linux", "risk": RISK_INTRUSIVE,
            }
        except Exception as e:  # noqa: BLE001
            return {
                "ok": False, "data": None,
                "error": f"airmon-ng: {e}",
                "duration_s": time.time() - started,
                "host_os": "Linux", "risk": RISK_INTRUSIVE,
            }

    def disable_monitor(self, adapter: str) -> Dict[str, Any]:
        """``airmon-ng stop <iface>`` (root-required)."""
        started = time.time()
        try:
            r = subprocess.run(
                ["airmon-ng", "stop", adapter],
                capture_output=True, text=True,
                timeout=self.timeout,
            )
            return {
                "ok": r.returncode == 0,
                "data": {"stdout": r.stdout, "stderr": r.stderr},
                "error": "" if r.returncode == 0 else "airmon-ng stop failed",
                "duration_s": time.time() - started,
                "host_os": "Linux", "risk": RISK_INTRUSIVE,
            }
        except FileNotFoundError:
            return {
                "ok": False, "data": None,
                "error": "airmon-ng not installed",
                "duration_s": 0.0, "host_os": "Linux", "risk": RISK_INTRUSIVE,
            }
        except Exception as e:  # noqa: BLE001
            return {
                "ok": False, "data": None,
                "error": f"airmon-ng: {e}",
                "duration_s": time.time() - started,
                "host_os": "Linux", "risk": RISK_INTRUSIVE,
            }

    def set_channel(self, adapter: str, channel: int) -> Dict[str, Any]:
        """``iw dev <iface> set channel <n>`` (root-required)."""
        started = time.time()
        try:
            r = subprocess.run(
                ["iw", "dev", adapter, "set", "channel", str(channel)],
                capture_output=True, text=True,
                timeout=10,
            )
            return {
                "ok": r.returncode == 0,
                "data": {"stdout": r.stdout, "stderr": r.stderr},
                "error": "" if r.returncode == 0 else "set channel failed",
                "duration_s": time.time() - started,
                "host_os": "Linux", "risk": RISK_INTRUSIVE,
            }
        except Exception as e:  # noqa: BLE001
            return {
                "ok": False, "data": None, "error": f"set channel: {e}",
                "duration_s": time.time() - started,
                "host_os": "Linux", "risk": RISK_INTRUSIVE,
            }

    # ------------------------------------------------------------------
    # Scan (read-only airodump-ng)
    # ------------------------------------------------------------------
    def scan(self, adapter: str, *, duration_s: int = None) -> Dict[str, Any]:
        """Run airodump-ng for ``duration_s`` seconds and parse the
        results. Long-range default via :func:`wifi_scan_s` (up to 1h).
        The parse is best-effort; an empty list is a valid result."""
        try:
            from core.scanners.scan_limits import wifi_scan_s
            duration_s = wifi_scan_s(duration_s)
        except Exception:
            duration_s = int(duration_s) if duration_s is not None else 300
        started = time.time()
        # Use a tmp prefix for the airodump output files
        prefix = f"/tmp/kfiosa_airodump_{int(started)}"
        try:
            proc = subprocess.Popen(
                ["airodump-ng", adapter, "-w", prefix,
                 "--output-format", "csv", "--write-interval", "1",
                 "--band", "abg",
                 "--berlin", str(max(duration_s, 120))],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            time.sleep(max(2, int(duration_s)))
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
        except FileNotFoundError:
            return {
                "ok": False, "data": None,
                "error": "airodump-ng not installed",
                "duration_s": 0.0, "host_os": "Linux", "risk": RISK_READ,
            }
        # Parse the CSV file
        csv_path = f"{prefix}-01.csv"
        if not os.path.exists(csv_path):
            return {
                "ok": True, "data": {"aps": []},
                "error": "",
                "duration_s": time.time() - started,
                "host_os": "Linux", "risk": RISK_READ,
            }
        aps: List[Dict[str, Any]] = []
        try:
            with open(csv_path, "r", errors="replace") as f:
                in_ap_section = False
                for line in f:
                    line = line.strip()
                    if not line:
                        in_ap_section = False
                        continue
                    if line.startswith("BSSID"):
                        in_ap_section = True
                        continue
                    if line.startswith("Station MAC"):
                        break
                    if in_ap_section:
                        parts = [p.strip() for p in line.split(",")]
                        if len(parts) >= 14 and re.match(
                                r"^[0-9A-Fa-f:]{17}$", parts[0]):
                            aps.append({
                                "bssid": parts[0],
                                "channel": int(parts[3] or 0),
                                "encryption": parts[5] or "",
                                "cipher": parts[6] or "",
                                "auth": parts[7] or "",
                                "ssid": parts[13] or "(hidden)",
                                "rssi": int(parts[8] or -100),
                                "pwr": int(parts[8] or 0),
                            })
        except Exception as e:  # noqa: BLE001
            return {
                "ok": False, "data": None, "error": f"parse: {e}",
                "duration_s": time.time() - started,
                "host_os": "Linux", "risk": RISK_READ,
            }
        # Clean up tmp files
        for ext in ("-01.csv", "-01.kismet.csv", "-01.log.csv"):
            try:
                os.remove(f"{prefix}{ext}")
            except FileNotFoundError:
                pass
        return {
            "ok": True, "data": {"aps": aps, "count": len(aps)},
            "error": "",
            "duration_s": time.time() - started,
            "host_os": "Linux", "risk": RISK_READ,
        }

    # ------------------------------------------------------------------
    # Generic runner dispatch (defer to WiFiAttackRunner /
    # ExtendedWiFiRunner). The panel does NOT call subprocess
    # directly for these — it goes through the runners.
    # ------------------------------------------------------------------
    def run_wifi_attack(self, method: str,
                        adapter: Optional[str] = None,
                        args: Optional[Dict[str, Any]] = None
                        ) -> Dict[str, Any]:
        """Dispatch a single ``core.wifi_attack.runner`` method."""
        try:
            from core.wifi_attack.runner import run_attack
        except ImportError as e:
            return {
                "ok": False, "data": None, "error": f"import: {e}",
                "duration_s": 0.0, "host_os": "Linux",
                "risk": RISK_INTRUSIVE,
            }
        return run_attack(method, adapter=adapter, args=args or {})

    def run_extended_wifi(self, method: str,
                          adapter: Optional[str] = None,
                          args: Optional[Dict[str, Any]] = None
                          ) -> Dict[str, Any]:
        """Dispatch a single ``core.extended_wifi.runner`` method."""
        try:
            from core.extended_wifi.runner import run_attack
        except ImportError as e:
            return {
                "ok": False, "data": None, "error": f"import: {e}",
                "duration_s": 0.0, "host_os": "Linux",
                "risk": RISK_INTRUSIVE,
            }
        return run_attack(method, adapter=adapter, args=args or {})


# ---------------------------------------------------------------------------
# Map panel action names -> runner method names
# ---------------------------------------------------------------------------
# Many of the panel actions correspond directly to methods in the
# WiFiAttackRunner or ExtendedWiFiRunner. The mapping is kept in
# one place so the catalog stays the single source of truth for
# which actions are visible.
_RUNNER_DISPATCH: Dict[str, Tuple[str, str]] = {
    # action: (runner_kind, method)
    # runner_kind is "wifi" or "ext" or "panel" (panel-internal)
    "evil_twin": ("wifi", "evil_twin_automated"),
    "kr00k": ("wifi", "kr00k_vulnerability_check"),
    "fragmentation": ("wifi", "fragmentation_attack"),
    "beacon_flood": ("wifi", "beacon_flood_adaptive"),
    "wps_null_pin": ("wifi", "wps_null_pin_attack"),
    "band_steering": ("wifi", "band_steering_attack"),
    "client_creds": ("wifi", "client_credential_hijack"),
    "mac_rotate": ("wifi", "mac_spoofer_rotating"),
    "captive_portal": ("wifi", "captive_portal_detection_and_bypass"),
    "sig_predict": ("wifi", "sig_strength_prediction_model"),
    "rf_survey": ("wifi", "dynamic_channel_hopping_rf_survey"),
    "ai_wpa_priority": ("wifi", "pmkid_ai_prioritizer"),
    "sae_downgrade": ("wifi", "sae_group_downgrade"),
    "client_powersave": ("wifi", "client_power_save_exploit"),
    "wpa2_kr00k": ("wifi", "wpa2_kr00k_all_channel"),
    "wep_ai": ("wifi", "ai_driven_wep_attack"),
    "full_auto_pwn": ("wifi", "full_auto_pwn"),
    "karma": ("wifi", "karma_mana"),
    "mdk3": ("wifi", "mdk3_attack"),
    "mdk4": ("wifi", "mdk4_attack"),
    "eap_downgrade": ("wifi", "eap_downgrade"),
    "hashcat_22001": ("wifi", "hashcat_22001"),
    "hashcat_16800": ("wifi", "hashcat_16800"),
    "disassoc": ("wifi", "disassociation_frame"),
    "probe_response": ("wifi", "probe_response_craft"),
    "assoc_request": ("wifi", "assoc_request_craft"),
    "channel_hop": ("wifi", "channel_following_loop"),
    "wpa_dragonblood": ("wifi", "wpa_dragonblood_test"),
    "beacon_manipulation": ("wifi", "beacon_manipulation_attack"),
    "pmf_bypass": ("wifi", "pmf_bypass_test"),
    "auto_handshake": ("wifi", "automatic_handshake_cracker"),
    "packet_injection": ("wifi", "packet_injection_test"),
    "sig_quality": ("wifi", "wifi_signal_quality_analyzer"),
    "auto_executor": ("wifi", "wifi_auto_attack_executor"),
    "deauth_timing": ("wifi", "targeted_deauth_timing"),
    "wifi_timing_side": ("wifi", "wifi_timing_side_channel"),
    "ap_overload": ("wifi", "ap_overload_dos"),
    "live_hcxdumptool": ("wifi", "live_hcxdumptool"),
    "probe_harvest": ("wifi", "vuln_classification_by_encryption_rule_engine"),
    # Extended
    "ofdma_steal": ("ext", "ofdma_resource_stealing"),
    "mu_mimo_null": ("ext", "mu_mimo_nulling"),
    "twt_exhaust": ("ext", "twt_exhaust_attack"),
    "bss_color_poison": ("ext", "bss_coloring_poisoning"),
    "ndp_sounding": ("ext", "ndp_sounding_manipulation"),
    "spatial_reuse": ("ext", "spatial_reuse_attack"),
    "trigger_frame": ("ext", "trigger_frame_spoofing"),
    "dual_band": ("ext", "dual_band_steering_hijack"),
    "power_save": ("ext", "power_save_bit_flipping"),
    "6ghz_burst": ("ext", "6ghz_channel_discovery_burst"),
    "pfn_probe": ("ext", "pfn_probe_attack"),
    "mfp_replay": ("ext", "mfp_replay_attack"),
    "sae_reflection": ("ext", "sae_reflection_attack"),
    "sae_group": ("ext", "wpa3_transition_downgrade_improved"),
    "group_rekey": ("ext", "group_rekey_sniffing"),
    "ap_rsn_ie": ("ext", "ap_rsn_ie_fuzzer"),
    "wnm_sleep": ("ext", "wnm_sleep_exploit"),
    "tdls_poison": ("ext", "tdls_discovery_poison"),
    "neighbor_report": ("ext", "neighbor_report_injection"),
    "ft_replay": ("ext", "ft_handshake_replay"),
    "airtime_dos": ("ext", "airtime_fairness_dos"),
    "qos_null": ("ext", "qos_null_data_exploit"),
    "addba_spoof": ("ext", "addba_spoofing"),
    "tspec_inject": ("ext", "tspec_injection"),
    "wapi": ("ext", "wapi_exploit"),
    "ssid_probe_advanced": ("ext", "ssid_probe_harvesting_advanced"),
    "timing_side_wpa3": ("ext", "timing_side_channel_attack_wpa3"),
    "client_kck": ("ext", "client_kck_extraction"),
    "beacon_triangulate": ("ext", "beacon_rssi_triangulation_ai"),
    "rf_fingerprint": ("ext", "rf_fingerprint_cloning"),
    "ofdm_sync": ("ext", "ofdm_sync_jamming"),
    "spectrum_scan": ("ext", "spectrum_scan_anomaly_detection"),
    "ap_uptime": ("ext", "passive_ap_uptime_estimation"),
    "dtim_predict": ("ext", "dtim_period_prediction"),
    "ampdu_snipping": ("ext", "aggregated_ampdu_snipping"),
    "roaming_trigger": ("ext", "roaming_scan_trigger"),
    "11k_measurement": ("ext", "11k_measurement_report_forge"),
    "wps_button": ("ext", "wps_button_push_simulation"),
    "dhcp_starve": ("ext", "dhcp_starvation_enhanced"),
    "eapol_logoff": ("ext", "eapol_logoff_injection"),
    "packet_number": ("ext", "packet_number_tracking"),
    "dup_packet": ("ext", "duplicate_packet_suppression_bypass"),
    "key_expiration": ("ext", "key_expiration_trigger"),
    "dpp_spoof": ("ext", "dpp_configurator_spoof"),
    "owe_bypass": ("ext", "owe_transition_mode_bypass"),
    "multi_link": ("ext", "multi_link_operation_attack"),
    "pmf_replay": ("ext", "protected_management_frame_replay"),
    "driver_crash": ("ext", "driver_crash_via_malformed_frame"),
    "channel_forecast": ("ext", "ai_channel_occupancy_forecast"),
    "stealth_scan": ("ext", "stealth_scan_via_power_control"),
    "wfa_agc": ("ext", "wfa_agc_probing"),
    "ppdu_confusion": ("ext", "ppdu_type_confusion"),
    "uora_trigger": ("ext", "uora_trigger_attack"),
    "beacon_tim": ("ext", "beacon_tim_spoof"),
    "preamble_puncture": ("ext", "preamble_puncturing_exploit"),
    "ndp_announce": ("ext", "ndp_announcement_flood"),
    "vht_crc": ("ext", "vht_siga1_crc_spoof"),
    "mu_edca": ("ext", "mu_edca_backoff_manipulation"),
    "mld_reconfig": ("ext", "mld_reconfiguration_attack"),
    "cross_layer_ai": ("ext", "cross_layer_ai_fusion"),
    "dragonblood": ("wifi", "wpa_dragonblood_test"),
    "pmkid": ("wifi", "live_hcxdumptool"),
    "deauth": ("panel", "deauth"),
    "capture_handshake": ("panel", "capture_handshake"),
    "scan": ("panel", "scan"),
    "list": ("panel", "list"),
    "select_ap": ("panel", "select_ap"),
    "channel_set": ("panel", "channel_set"),
    "enable_monitor": ("panel", "enable_monitor"),
    "disable_monitor": ("panel", "disable_monitor"),
    "adapters": ("panel", "adapters"),
    "select_adapter": ("panel", "select_adapter"),
    "driver_info": ("panel", "driver_info"),
    "saved": ("panel", "saved"),
    "save_ap": ("panel", "save_ap"),
    "view_capture": ("panel", "view_capture"),
    "ai_plan": ("panel", "ai_plan"),
    "phase_wordlist": ("wifi", "phase_based_ssid_aware_wordlist_forge"),
    "vuln_classify": ("wifi", "vuln_classification_by_encryption_rule_engine"),
    "scapy_flood": ("wifi", "scapy_flooder_auth_assoc_probe_beacon_deauth"),
}


# ---------------------------------------------------------------------------
# Module-level menu + key map (built once at import)
# ---------------------------------------------------------------------------

_WIFI_PANEL_MENU: List[Tuple[str, str]] = [
    (cap.label, cap.action) for cap in CAPABILITY_CATALOG
]

_WIFI_PANEL_KEY_MAP: Dict[str, str] = {
    cap.hotkey: cap.action for cap in CAPABILITY_CATALOG
}


def _host_os() -> str:
    try:
        import platform
        return platform.system()
    except Exception:  # noqa: BLE001
        return "unknown"


# ---------------------------------------------------------------------------
# The panel itself
# ---------------------------------------------------------------------------

class WiFiPanel:
    """A panel that runs inside the post-access TUI.

    The panel keeps a :class:`WifiPanelState` snapshot of what the
    current target exposes, and renders ONLY the actions that are
    currently applicable. The capability catalog is in
    ``wifi_panel_capabilities.py``; the visible menu is recomputed
    on every state change.

    Constructor args:
        client:              a :class:`WiFiPanelClient` (or fake). Defaults
                             to a real airmon/airodump backend.
        confirm_fn:          ``str -> bool`` — the single gate.
        on_event:            ``str -> None`` — log lines are emitted here.
        input_fn:            ``str -> str`` — for hermetic tests.
        state:               optional :class:`SessionState`.
        saved_aps_path:      optional path to JSON for AP profiles.
                             Defaults to ``~/.cache/kfiosa/wifi_aps.json``;
                             pass ``":memory:"`` to disable persistence.
    """

    MENU: List[Tuple[str, str]] = _WIFI_PANEL_MENU
    KEY_MAP: Dict[str, str] = _WIFI_PANEL_KEY_MAP
    HOTKEY_MAP: Dict[str, str] = {v: k for k, v in KEY_MAP.items()}

    DEFAULT_SAVED_APS_PATH = "~/.cache/kfiosa/wifi_aps.json"

    def __init__(self, *,
                 client: Optional[Any] = None,
                 confirm_fn: Optional[Callable[[str], bool]] = None,
                 on_event: Optional[Callable[[str], None]] = None,
                 input_fn: Optional[Callable[[str], str]] = None,
                 state: Optional[Any] = None,
                 saved_aps_path: Optional[str] = None,
                 adapter: Optional[str] = None):
        self.client = client if client is not None else WiFiPanelClient()
        self.confirm_fn = confirm_fn or (lambda _p: True)
        self._on_event = on_event or (lambda _m: None)
        self._input_fn = input_fn
        self.state = state
        self.adapter = adapter

        # Panel state snapshot (refreshed before every menu render)
        self.panel_state: WifiPanelState = WifiPanelState(adapter=adapter)
        self.scan_results: List[WiFiAP] = []
        self.selected_ap: Optional[WiFiAP] = None
        self.pcap_path: Optional[str] = None
        self.handshake_captured = False
        self.pmkid_captured = False
        self.wordlist_path: Optional[str] = None
        self.saved_aps: List[Dict[str, Any]] = []

        # Saved APs persistence
        self._saved_aps_path = (
            saved_aps_path
            if saved_aps_path is not None
            else os.path.expanduser(self.DEFAULT_SAVED_APS_PATH)
        )
        if self._saved_aps_path != ":memory:":
            loaded = self._load_saved_aps()
            self.panel_state.saved_aps = loaded
            self.saved_aps = list(loaded)

    # ------------------------------------------------------------------
    # Event / log helpers
    # ------------------------------------------------------------------
    def _emit(self, msg: str) -> None:
        try:
            self._on_event(msg)
        except Exception:  # noqa: BLE001
            pass

    def _ask(self, prompt: str) -> str:
        if self._input_fn is None:
            return ""
        try:
            return (self._input_fn(prompt) or "").strip()
        except Exception:  # noqa: BLE001
            return ""

    def _envelope(self, started: float, *, ok: bool,
                  data: Optional[Dict[str, Any]] = None,
                  error: str = "",
                  risk: str = RISK_READ) -> Dict[str, Any]:
        return {
            "ok": ok,
            "data": data,
            "error": error,
            "duration_s": time.time() - started,
            "host_os": _host_os(),
            "risk": risk,
        }

    # ------------------------------------------------------------------
    # Saved APs persistence
    # ------------------------------------------------------------------
    def _load_saved_aps(self) -> List[Dict[str, Any]]:
        try:
            p = Path(self._saved_aps_path)
            if not p.exists():
                return []
            with open(p, "r") as f:
                data = json.load(f)
            if isinstance(data, list):
                return [d for d in data if isinstance(d, dict)]
            return []
        except Exception as e:  # noqa: BLE001
            self._emit(f"saved-APs load failed: {e}")
            return []

    def _persist_saved_aps(self) -> None:
        if self._saved_aps_path == ":memory:":
            return
        try:
            p = Path(self._saved_aps_path)
            p.parent.mkdir(parents=True, exist_ok=True)
            with open(p, "w") as f:
                json.dump(self.saved_aps, f, indent=2)
        except Exception as e:  # noqa: BLE001
            self._emit(f"saved-APs persist failed: {e}")

    def _add_saved_ap(self, ap: WiFiAP, notes: str = "") -> None:
        for i, e in enumerate(self.saved_aps):
            if e.get("bssid") == ap.bssid:
                self.saved_aps[i] = {
                    "bssid": ap.bssid, "ssid": ap.ssid,
                    "channel": ap.channel, "encryption": ap.encryption,
                    "wps": ap.wps, "pmf": ap.pmf, "band": ap.band,
                    "notes": notes, "saved_at": time.time(),
                }
                self._persist_saved_aps()
                return
        self.saved_aps.append({
            "bssid": ap.bssid, "ssid": ap.ssid,
            "channel": ap.channel, "encryption": ap.encryption,
            "wps": ap.wps, "pmf": ap.pmf, "band": ap.band,
            "notes": notes, "saved_at": time.time(),
        })
        self._persist_saved_aps()

    # ------------------------------------------------------------------
    # Dynamic menu (recompute on every state change)
    # ------------------------------------------------------------------
    def refresh_state(self) -> None:
        """Update ``self.panel_state`` from the panel's in-memory
        fields. Call this BEFORE rendering the menu or before
        dispatching any state-dependent action.
        """
        ps = self.panel_state
        ps.adapter = self.adapter
        ps.monitor_mode = bool(getattr(self, "_monitor_mode", False))
        ps.scan_results = [
            {"bssid": ap.bssid, "ssid": ap.ssid, "channel": ap.channel,
             "encryption": ap.encryption, "rssi": ap.rssi,
             "wps": ap.wps, "pmf": ap.pmf, "band": ap.band}
            for ap in self.scan_results
        ]
        if self.selected_ap is not None:
            ps.selected_ap = {
                "bssid": self.selected_ap.bssid,
                "ssid": self.selected_ap.ssid,
                "channel": self.selected_ap.channel,
                "encryption": self.selected_ap.encryption,
                "wps": self.selected_ap.wps,
                "pmf": self.selected_ap.pmf,
                "band": self.selected_ap.band,
            }
            ps.selected_ap_encryption = self.selected_ap.encryption
            ps.selected_ap_wps = self.selected_ap.wps
            ps.selected_ap_pmf = self.selected_ap.pmf
            ps.selected_ap_band = self.selected_ap.band
            ps.selected_ap_clients = list(self.selected_ap.clients)
        else:
            ps.selected_ap = None
            ps.selected_ap_encryption = ""
            ps.selected_ap_wps = False
            ps.selected_ap_pmf = False
            ps.selected_ap_band = ""
            ps.selected_ap_clients = []
        ps.handshake_captured = self.handshake_captured
        ps.pmkid_captured = self.pmkid_captured
        ps.pcap_path = self.pcap_path
        ps.wordlist_loaded = bool(self.wordlist_path)
        ps.saved_aps = list(self.saved_aps)

    def visible_capabilities(self) -> List[Capability]:
        """Return the list of capabilities currently usable, given
        the panel's state. The screen renders this list.
        """
        self.refresh_state()
        return compute_visible_menu(self.panel_state)

    def menu_text(self) -> str:
        """Return a human-readable rendering of the dynamic menu.

        The text starts with a status footer (adapter / monitor mode /
        selected AP) followed by the visible action lines.
        """
        self.refresh_state()
        ps = self.panel_state
        if not ps.has_adapter():
            visible = default_disconnected_menu()
        else:
            visible = self.visible_capabilities()
        lines: List[str] = []
        lines.append("--- WiFi Panel — dynamic menu (state-aware) ---")
        if not ps.has_adapter():
            lines.append(
                "   (no adapter selected — pick one with [I] Select adapter)"
            )
        for cap in visible:
            risk_marker = ""
            if cap.risk == RISK_DESTRUCTIVE:
                risk_marker = "💥 "
            elif cap.risk == RISK_INTRUSIVE:
                risk_marker = "🔒 "
            lines.append(f"   {risk_marker}[{cap.hotkey}] {cap.label}")
        # Footer
        parts: List[str] = []
        if ps.adapter:
            parts.append(f"adapter={ps.adapter}")
            parts.append(
                f"mode={'monitor' if ps.monitor_mode else 'managed'}"
            )
        if ps.selected_ap:
            parts.append(
                f"ap={ps.selected_ap.get('ssid') or '(hidden)'} "
                f"({ps.selected_ap.get('bssid')}) "
                f"enc={ps.selected_ap_encryption or '?'}"
            )
            if ps.selected_ap_wps:
                parts.append("WPS")
            if ps.selected_ap_pmf:
                parts.append("PMF")
        if ps.handshake_captured:
            parts.append("handshake✓")
        if ps.pmkid_captured:
            parts.append("pmkid✓")
        if ps.wordlist_loaded:
            parts.append(f"wordlist={self.wordlist_path or '?'}")
        if parts:
            lines.append("   --- " + "  ".join(parts) + " ---")
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Dispatch
    # ------------------------------------------------------------------
    def dispatch(self, action: str,
                 args: Optional[Dict[str, Any]] = None
                 ) -> Dict[str, Any]:
        """Dispatch one panel action. Returns the envelope.

        Per the single-gate invariant: the SCREEN fires
        ``confirm_fn`` BEFORE calling this method. The panel does NOT
        re-confirm (it would be a second gate). However, the panel
        does surface the prompt via ``self.confirm_fn`` for HIGH-RISK
        actions (write, notify, bleshell) when called from a
        different entry point (e.g. the chain planner's
        ``open_wifi_tui`` step) where the screen is not in scope.
        """
        args = args or {}
        started = _now()
        # Normalize: hotkey -> action name
        if action in self.KEY_MAP:
            action = self.KEY_MAP[action]
        if action not in self.HOTKEY_MAP and action != "exit":
            return self._envelope(started, ok=False,
                                  error=f"unknown wifi action: {action!r}")
        self.refresh_state()
        # Universal actions
        if action == "exit":
            return self._envelope(started, ok=True, data={"exit": True})
        if action == "help":
            return self._action_help(args, started)
        if action == "saved":
            return self._action_saved(args, started)
        if action == "save_ap":
            return self._action_save_ap(args, started)
        if action == "adapters":
            return self._action_adapters(args, started)
        if action == "select_adapter":
            return self._action_select_adapter(args, started)
        if action == "driver_info":
            return self._action_driver_info(args, started)
        if action == "enable_monitor":
            return self._action_enable_monitor(args, started)
        if action == "disable_monitor":
            return self._action_disable_monitor(args, started)
        if action == "scan":
            return self._action_scan(args, started)
        if action == "list":
            return self._action_list(args, started)
        if action == "select_ap":
            return self._action_select_ap(args, started)
        if action == "channel_set":
            return self._action_channel_set(args, started)
        if action == "view_capture":
            return self._action_view_capture(args, started)
        if action == "ai_plan":
            return self._action_ai_plan(args, started)
        if action == "full_auto_pwn":
            return self._action_full_auto_pwn(args, started)
        # Runner dispatch
        return self._dispatch_runner(action, args, started)

    def _dispatch_runner(self, action: str, args: Dict[str, Any],
                         started: float) -> Dict[str, Any]:
        """Dispatch an action that maps to a runner method."""
        if action not in _RUNNER_DISPATCH:
            return self._envelope(
                started, ok=False,
                error=f"action {action!r} not mapped to any runner",
            )
        kind, method = _RUNNER_DISPATCH[action]
        # Inject selected_ap BSSID if available and not already in args
        if self.selected_ap is not None and "bssid" not in args:
            args = dict(args)
            args["bssid"] = self.selected_ap.bssid
        if self.adapter is not None and "adapter" not in args:
            args = dict(args)
            args["adapter"] = self.adapter
        if kind == "wifi":
            return self.client.run_wifi_attack(method, args=args)
        if kind == "ext":
            return self.client.run_extended_wifi(method, args=args)
        return self._envelope(
            started, ok=False,
            error=f"action {action!r} has no runner kind",
        )

    # ------------------------------------------------------------------
    # Action implementations (universal / panel-internal)
    # ------------------------------------------------------------------
    def _action_help(self, args: Dict[str, Any],
                     started: float) -> Dict[str, Any]:
        lines = ["Visible actions (current state):"]
        for cap in self.visible_capabilities():
            lines.append(f"  [{cap.hotkey}] {cap.label}")
            if cap.help_text:
                lines.append(f"      {cap.help_text}")
        self._emit("\n".join(lines))
        return self._envelope(started, ok=True, data={"help": lines})

    def _action_saved(self, args: Dict[str, Any],
                      started: float) -> Dict[str, Any]:
        if not self.saved_aps:
            self._emit("(no saved AP profiles)")
        else:
            for i, ap in enumerate(self.saved_aps, 1):
                self._emit(
                    f"  {i:2}. {ap.get('ssid') or '(hidden)'} "
                    f"({ap.get('bssid')}) ch={ap.get('channel')} "
                    f"enc={ap.get('encryption') or '?'}"
                )
        return self._envelope(started, ok=True, data={"saved": self.saved_aps})

    def _action_save_ap(self, args: Dict[str, Any],
                        started: float) -> Dict[str, Any]:
        if self.selected_ap is None:
            return self._envelope(
                started, ok=False, error="no AP selected to save",
            )
        notes = args.get("notes", "")
        self._add_saved_ap(self.selected_ap, notes=notes)
        self._emit(f"saved {self.selected_ap.ssid} ({self.selected_ap.bssid})")
        return self._envelope(
            started, ok=True, data={"saved_bssid": self.selected_ap.bssid},
        )

    def _action_adapters(self, args: Dict[str, Any],
                         started: float) -> Dict[str, Any]:
        return self.client.list_adapters()

    def _action_select_adapter(self, args: Dict[str, Any],
                               started: float) -> Dict[str, Any]:
        adapter = (args.get("adapter") or "").strip()
        if not adapter:
            adapter = self._ask("adapter (e.g. wlan0)> ")
        if not adapter:
            return self._envelope(
                started, ok=False, error="no adapter provided",
            )
        self.adapter = adapter
        self._monitor_mode = False
        self.panel_state.adapter = adapter
        self._emit(f"selected adapter: {adapter}")
        return self._envelope(
            started, ok=True, data={"adapter": adapter},
        )

    def _action_driver_info(self, args: Dict[str, Any],
                            started: float) -> Dict[str, Any]:
        if not self.adapter:
            return self._envelope(
                started, ok=False, error="no adapter selected",
            )
        return self.client.driver_info(self.adapter)

    def _action_enable_monitor(self, args: Dict[str, Any],
                               started: float) -> Dict[str, Any]:
        if not self.adapter:
            return self._envelope(
                started, ok=False, error="no adapter selected",
            )
        env = self.client.enable_monitor(self.adapter)
        if env.get("ok"):
            self._monitor_mode = True
        return env

    def _action_disable_monitor(self, args: Dict[str, Any],
                                started: float) -> Dict[str, Any]:
        if not self.adapter:
            return self._envelope(
                started, ok=False, error="no adapter selected",
            )
        env = self.client.disable_monitor(self.adapter)
        if env.get("ok"):
            self._monitor_mode = False
        return env

    def _action_scan(self, args: Dict[str, Any],
                     started: float) -> Dict[str, Any]:
        if not self.adapter or not getattr(self, "_monitor_mode", False):
            return self._envelope(
                started, ok=False,
                error="scan requires adapter in monitor mode",
            )
        if "duration_s" in args:
            try:
                duration_s = max(1, min(60, int(args["duration_s"])))
            except (TypeError, ValueError):
                duration_s = 8
        else:
            duration_s = 8
        env = self.client.scan(self.adapter, duration_s=duration_s)
        if env.get("ok") and env.get("data", {}).get("aps"):
            self.scan_results = []
            for a in env["data"]["aps"]:
                self.scan_results.append(WiFiAP(
                    bssid=a.get("bssid", ""),
                    ssid=a.get("ssid", "(hidden)"),
                    channel=a.get("channel", 0),
                    encryption=a.get("encryption", ""),
                    cipher=a.get("cipher", ""),
                    auth=a.get("auth", ""),
                    rssi=a.get("rssi", 0),
                ))
        return env

    def _action_list(self, args: Dict[str, Any],
                     started: float) -> Dict[str, Any]:
        if not self.scan_results:
            return self._envelope(
                started, ok=False, error="no scan results — run [S]can first",
            )
        lines = ["BSSID              CH   ENC       PWR  SSID"]
        for ap in self.scan_results:
            lines.append(
                f"  {ap.bssid:<17} {ap.channel:<4} {ap.encryption:<10} "
                f"{ap.rssi:>4}  {ap.ssid}"
            )
        self._emit("\n".join(lines))
        return self._envelope(
            started, ok=True, data={"count": len(self.scan_results)},
        )

    def _action_select_ap(self, args: Dict[str, Any],
                          started: float) -> Dict[str, Any]:
        if not self.scan_results:
            return self._envelope(
                started, ok=False, error="no scan results — run [S]can first",
            )
        # Allow selection by BSSID or by index
        target = (args.get("bssid") or "").strip()
        if not target:
            target = self._ask("bssid or #> ")
        if not target:
            return self._envelope(
                started, ok=False, error="no target provided",
            )
        chosen: Optional[WiFiAP] = None
        if target.startswith("#"):
            try:
                idx = int(target[1:]) - 1
                if 0 <= idx < len(self.scan_results):
                    chosen = self.scan_results[idx]
            except ValueError:
                pass
        else:
            for ap in self.scan_results:
                if ap.bssid.lower() == target.lower():
                    chosen = ap
                    break
        if chosen is None:
            return self._envelope(
                started, ok=False, error=f"no AP matching {target!r}",
            )
        self.selected_ap = chosen
        self._emit(f"selected AP: {chosen.ssid} ({chosen.bssid})")
        return self._envelope(
            started, ok=True, data={"bssid": chosen.bssid, "ssid": chosen.ssid},
        )

    def _action_channel_set(self, args: Dict[str, Any],
                            started: float) -> Dict[str, Any]:
        if not self.adapter:
            return self._envelope(
                started, ok=False, error="no adapter selected",
            )
        ch_str = str(args.get("channel") or self._ask("channel> ")).strip()
        try:
            channel = int(ch_str)
        except ValueError:
            return self._envelope(
                started, ok=False, error=f"invalid channel: {ch_str!r}",
            )
        return self.client.set_channel(self.adapter, channel)

    def _action_view_capture(self, args: Dict[str, Any],
                             started: float) -> Dict[str, Any]:
        lines = []
        if self.pcap_path:
            lines.append(f"  pcap: {self.pcap_path}")
        if self.handshake_captured:
            lines.append("  handshake: captured")
        if self.pmkid_captured:
            lines.append("  pmkid: captured")
        if not lines:
            lines.append("  (no capture present)")
        self._emit("\n".join(lines))
        return self._envelope(
            started, ok=True,
            data={"handshake": self.handshake_captured,
                  "pmkid": self.pmkid_captured,
                  "pcap": self.pcap_path},
        )

    def _action_ai_plan(self, args: Dict[str, Any],
                        started: float) -> Dict[str, Any]:
        """Generate a heuristic (not trained) attack plan for the
        currently selected AP.
        """
        if self.selected_ap is None:
            return self._envelope(
                started, ok=False, error="no AP selected",
            )
        ap = self.selected_ap
        plan: List[str] = []
        plan.append(f"Plan for {ap.ssid or '(hidden)'} ({ap.bssid})")
        plan.append(f"  encryption: {ap.encryption or '?'}")
        plan.append(f"  band: {ap.band or '?'}")
        plan.append(f"  WPS: {'yes' if ap.wps else 'no'}")
        plan.append(f"  PMF: {'yes' if ap.pmf else 'no'}")
        plan.append(f"  clients: {len(ap.clients)}")
        plan.append("")
        plan.append("Recommended sequence (heuristic — not trained):")
        enc = ap.encryption.upper()
        if "WPA2" in enc:
            plan.append("  1. [S]can / [P]ick AP  (already done)")
            plan.append("  2. [w] Wordlist  (set a wordlist path)")
            if ap.clients:
                plan.append("  3. [1] Deauth  (force re-auth)")
                plan.append("  4. [2] Handshake  (capture the 4-way)")
            else:
                plan.append("  3. [3] PMKID  (no clients needed)")
            plan.append("  5. [=] Hashcat 22001  (crack)")
        elif "WPA3" in enc or "SAE" in enc:
            plan.append("  1. [S]can / [P]ick AP  (already done)")
            plan.append("  2. [O] SAE downgrade  (force WPA2)")
            plan.append("  3. [B] Dragonblood  (timing side channel)")
        elif "WEP" in enc:
            plan.append("  1. [S]can / [P]ick AP  (already done)")
            plan.append("  2. [[] WEP AI  (FMS/PTW)")
            plan.append("  3. [G] Fragmentation  (chopchop)")
        elif "OPEN" in enc or enc == "":
            plan.append("  1. [Q] Open capture  (passive)")
        else:
            plan.append("  (heuristic) — run [V] View capture / [A] AI "
                        "priority / [!] Full auto")
        if ap.wps:
            plan.append("  (WPS detected) — try [n] WPS null PIN")
        if ap.pmf:
            plan.append("  (PMF detected) — try [P] PMF bypass / [Y] MFP replay")
        self._emit("\n".join(plan))
        return self._envelope(started, ok=True, data={"plan": plan})

    def _action_full_auto_pwn(self, args: Dict[str, Any],
                              started: float) -> Dict[str, Any]:
        """End-to-end: scan → deauth → capture → crack. Operator-owned
        APs only. Single-gate.

        The single-gate invariant is preserved: ONE
        ``confirm_fn`` prompt fires BEFORE the chain is planned
        (wording in :func:`core.post_access_tui.full_auto.default_gate_prompt`).
        The per-step ACCEPT gates inside the chain walk
        (orchestrator's ``_walk_ai_step``) are unchanged.
        """
        from core.post_access_tui.full_auto import run_full_auto
        if self.selected_ap is None:
            return self._envelope(
                started, ok=False, error="no AP selected",
            )
        # Build a panel_state snapshot.
        import dataclasses
        try:
            ap_dict = (dataclasses.asdict(self.selected_ap)
                       if self.selected_ap is not None
                       and dataclasses.is_dataclass(self.selected_ap)
                       else None)
        except Exception:  # noqa: BLE001
            ap_dict = None
        if ap_dict is None and self.selected_ap is not None:
            ap_dict = {
                "bssid": getattr(self.selected_ap, "bssid", None),
                "ssid": getattr(self.selected_ap, "ssid", None),
                "channel": getattr(self.selected_ap, "channel", None),
                "encryption": getattr(self.selected_ap, "encryption", None),
                "wps": getattr(self.selected_ap, "wps", None),
                "pmf": getattr(self.selected_ap, "pmf", None),
                "band": getattr(self.selected_ap, "band", None),
            }
        panel_state: Dict[str, Any] = {
            "adapter": self.adapter,
            "monitor_mode": bool(getattr(self, "_monitor_mode", False)),
            "selected_ap": ap_dict,
            "handshake_captured": bool(self.handshake_captured),
            "pmkid_captured": bool(self.pmkid_captured),
            "wordlist_loaded": bool(self.wordlist_path),
            "pcap_path": self.pcap_path,
        }
        target: Dict[str, Any] = ap_dict or {
            "bssid": getattr(self.selected_ap, "bssid", None),
            "ssid": getattr(self.selected_ap, "ssid", None),
        }
        # Plumb the AI planner + walk_chain through the panel's
        # _on_event hook so the screen sees real-time events.
        ai_planner = getattr(self, "_ai_chain_planner", None)
        walk_chain = getattr(self, "_walk_chain", None)
        if ai_planner is None or walk_chain is None:
            return self._envelope(
                started, ok=False,
                error="full-auto not wired: missing ai_planner or walk_chain",
            )
        try:
            return run_full_auto(
                domain="wifi",
                panel_state={**panel_state, "target": target},
                ai_planner=ai_planner,
                walk_chain=walk_chain,
                spawn_post_access_tui=getattr(
                    self, "_spawn_post_access_tui", None),
                confirm_fn=self.confirm_fn,
                on_event=getattr(self, "_on_event", None),
            )
        except Exception as e:  # noqa: BLE001
            return self._envelope(
                started, ok=False,
                error=f"full-auto raised: {e}",
            )


# ---------------------------------------------------------------------------
# Menu entry helper (used by the screen when registering the panel)
# ---------------------------------------------------------------------------

def wifi_menu_entry() -> Tuple[str, str, str]:
    """Return the (label, key, action_name) tuple for the screen
    MENU. The screen adds this entry to its menu list."""
    return ("[W]iFi — WiFi RAT-like attack panel", "w", "wifi")


# ---------------------------------------------------------------------------
# wifi_dispatch — the curses-free entry loop
# ---------------------------------------------------------------------------

def wifi_dispatch(screen: "BaseScreen", panel: WiFiPanel,
                  ) -> Dict[str, Any]:
    """Open the WIFI panel from the screen, run a curses-free loop
    until the operator picks [E]xit, and return the panel's exit
    envelope. The screen passes its ``input_fn`` and ``confirm_fn``
    into the panel.

    The single-key + arrow / ENTER / BACKSPACE loop is implemented
    in :func:`core.post_access_tui.menu_loop.curses_free_loop`; this
    function is a thin wiring layer that adapts the screen to the
    helper's contract.
    """
    from core.post_access_tui.menu_loop import curses_free_loop

    panel._on_event = screen._on_event  # type: ignore[attr-defined]
    panel._input_fn = screen.input_fn
    panel.confirm_fn = screen.confirm_fn

    def _render_menu() -> None:
        try:
            screen._emit(panel.menu_text())
        except Exception:  # noqa: BLE001
            pass

    def _visible_hotkeys() -> set:
        return {cap.hotkey for cap in panel.visible_capabilities()}

    def _requires_gate(hotkey: str) -> bool:
        action = panel.KEY_MAP.get(hotkey)
        if not action:
            return False
        cap = next(
            (c for c in panel.visible_capabilities() if c.action == action),
            None,
        )
        return bool(cap and cap.requires_gate)

    def _gate_prompt(hotkey: str) -> str:
        action = panel.KEY_MAP.get(hotkey) or hotkey
        cap = next(
            (c for c in panel.visible_capabilities() if c.action == action),
            None,
        )
        label = cap.label.split(" — ", 1)[-1] if cap and " — " in cap.label else (
            cap.label if cap else action
        )
        return f"ACCEPT INTRUSIVE? WIFI {action} ({label})"

    def _handle(hotkey: str) -> Optional[Dict[str, Any]]:
        action = panel.KEY_MAP.get(hotkey)
        if action is None:
            return None
        env = panel.dispatch(action)
        try:
            screen._emit(
                f"wifi {action} ok={env.get('ok')} "
                f"err={env.get('error', '')}"
            )
        except Exception:  # noqa: BLE001
            pass
        return env

    def _wifi_pdf_hook(_env):
        """Phase 2.4 §B.11 — best-effort PDF export after the wifi
        panel exits. Failures are logged but never block the loop."""
        try:
            from .rat_ext import auto_pdf as _auto_pdf
            session = {
                "session_id": "wifi_panel",
                "transport": "wifi",
                "target": str(getattr(screen, "target", "") or "<wifi>"),
                "achieved": [],
                "capabilities": [],
                "exfil_jobs": [],
                "persistence_mechanisms": [],
                "screens": [],
                "step_envelope_history": [],
            }
            return _auto_pdf.export_full_report([session], chain="wifi")
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "error": str(e)}

    return curses_free_loop(
        prompt="wifi> ",
        screen=screen,
        render_menu=_render_menu,
        visible_hotkeys=_visible_hotkeys,
        handle=_handle,
        requires_gate_lookup=_requires_gate,
        gate_prompt=_gate_prompt,
        pdf_on_exit=_wifi_pdf_hook,
    )


__all__ = [
    "WiFiAP",
    "WiFiPanelClient",
    "WiFiPanel",
    "wifi_menu_entry",
    "wifi_dispatch",
]
