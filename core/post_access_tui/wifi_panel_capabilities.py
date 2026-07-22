"""core.post_access_tui.wifi_panel_capabilities — WIFI capability catalog.

Same pattern as ``ble_panel_capabilities.py``:

  - :class:`WifiPanelState` snapshot of the panel's world (adapter mode,
    selected AP, captured handshake, monitor mode status, scan results,
    etc.). The panel refreshes this snapshot before every render.
  - :class:`Capability` describes one user-facing action (hotkey, label,
    risk, requires_gate, availability_fn(state) -> bool, needs list,
    help_text).
  - :data:`CAPABILITY_CATALOG` lists all known capabilities, ~70+
    entries spanning the legacy WiFiAttackRunner (40+ methods) and the
    ExtendedWiFiRunner (60+ methods).
  - :func:`compute_visible_menu(state)` filters the catalog by state and
    returns only the actions currently applicable to the target.

The menu is DYNAMIC. Example:
  - No monitor mode: ``[M]onitor / [S]can / [L]ist / [?] Help / [E]xit``
  - Monitor mode on, no AP selected: ``[M]onitor / [S]can / [L]ist / [R]econ / [?] Help / [E]xit``
  - AP selected, WPA2, handshake captured: adds
    ``[C]rack / [D]eauth / [P]mkid / [H]ashcat / [V]iew capture``

Capability actions are registered against the WiFiAttackRunner /
ExtendedWiFiRunner registries in ``wifi_panel.py`` (the dispatcher
calls ``runner.run_attack(method)``). The catalog is purely a
state-to-menu filter, not the executor.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

# ---------------------------------------------------------------------------
# Risk levels (match ble_panel_capabilities)
# ---------------------------------------------------------------------------
RISK_READ = "read"
RISK_INTRUSIVE = "intrusive"
RISK_DESTRUCTIVE = "destructive"


# ---------------------------------------------------------------------------
# WifiPanelState
# ---------------------------------------------------------------------------
@dataclass
class WifiPanelState:
    """A snapshot of the panel's world.

    The panel keeps one of these and refreshes it before every menu
    render. The capabilities inspect this state via their
    ``availability_fn``.
    """
    # Adapter / mode
    adapter: Optional[str] = None          # e.g. "wlan0", "wlan0mon"
    monitor_mode: bool = False              # True if iface is in monitor mode
    phy_supports_monitor: bool = True       # False if adapter can't monitor
    channel: int = 0                        # current channel (0 = all)
    tx_power_dbm: int = 0                   # current TX power (0 = default)
    # Scan results
    scan_results: List[Dict[str, Any]] = field(default_factory=list)
    # Selected AP (None = none yet)
    selected_ap: Optional[Dict[str, Any]] = None
    # AP features detected from probe/beacon
    selected_ap_encryption: str = ""        # "WPA2", "WPA3", "WEP", "OPEN"
    selected_ap_wps: bool = False
    selected_ap_pmf: bool = False
    selected_ap_band: str = ""              # "2.4", "5", "6"
    selected_ap_clients: List[str] = field(default_factory=list)  # MACs
    # Capture state
    handshake_captured: bool = False
    pmkid_captured: bool = False
    pcap_path: Optional[str] = None
    # Cracking state
    wordlist_loaded: bool = False
    hashcat_running: bool = False
    # Saved profiles
    saved_aps: List[Dict[str, Any]] = field(default_factory=list)
    # Anonymity / OPSEC flags
    anonymity_required: bool = False

    # ------------------------------------------------------------------
    # Helpers used by availability_fn
    # ------------------------------------------------------------------
    def has_adapter(self) -> bool:
        return bool(self.adapter) and self.adapter != ""

    def has_scan_results(self) -> bool:
        return len(self.scan_results) > 0

    def has_selected_ap(self) -> bool:
        return self.selected_ap is not None

    def has_clients(self) -> bool:
        return self.has_selected_ap() and len(self.selected_ap_clients) > 0

    def is_wpa2(self) -> bool:
        return self.selected_ap_encryption.upper() == "WPA2"

    def is_wpa3(self) -> bool:
        return self.selected_ap_encryption.upper() == "WPA3"

    def is_wep(self) -> bool:
        return self.selected_ap_encryption.upper() == "WEP"

    def is_open(self) -> bool:
        return self.selected_ap_encryption.upper() == "OPEN"

    def is_2_4ghz(self) -> bool:
        return self.selected_ap_band == "2.4"

    def is_5ghz(self) -> bool:
        return self.selected_ap_band == "5"

    def is_6ghz(self) -> bool:
        return self.selected_ap_band == "6"

    def has_handshake(self) -> bool:
        return self.handshake_captured

    def has_pmkid(self) -> bool:
        return self.pmkid_captured

    def has_capture(self) -> bool:
        return self.has_handshake() or self.has_pmkid() or bool(self.pcap_path)

    def has_wordlist(self) -> bool:
        return self.wordlist_loaded


# ---------------------------------------------------------------------------
# Capability
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Capability:
    action: str
    hotkey: str
    label: str
    risk: str
    requires_gate: bool
    availability_fn: Callable[[WifiPanelState], bool]
    needs: Tuple[str, ...] = ()
    help_text: str = ""


# ---------------------------------------------------------------------------
# Helper factory functions for common availability patterns
# ---------------------------------------------------------------------------
def _always(_s: WifiPanelState) -> bool:
    return True


def _has_adapter(s: WifiPanelState) -> bool:
    return s.has_adapter()


def _not_in_monitor(s: WifiPanelState) -> bool:
    return s.has_adapter() and not s.monitor_mode


def _in_monitor(s: WifiPanelState) -> bool:
    return s.has_adapter() and s.monitor_mode


def _has_scan(s: WifiPanelState) -> bool:
    return _in_monitor(s) and s.has_scan_results()


def _has_ap(s: WifiPanelState) -> bool:
    return _in_monitor(s) and s.has_selected_ap()


def _has_clients(s: WifiPanelState) -> bool:
    return _has_ap(s) and s.has_clients()


def _is_wpa2(s: WifiPanelState) -> bool:
    return _has_ap(s) and s.is_wpa2()


def _is_wpa3(s: WifiPanelState) -> bool:
    return _has_ap(s) and s.is_wpa3()


def _is_wep(s: WifiPanelState) -> bool:
    return _has_ap(s) and s.is_wep()


def _is_open(s: WifiPanelState) -> bool:
    return _has_ap(s) and s.is_open()


def _is_2_4ghz(s: WifiPanelState) -> bool:
    return _has_ap(s) and s.is_2_4ghz()


def _is_5ghz(s: WifiPanelState) -> bool:
    return _has_ap(s) and s.is_5ghz()


def _is_6ghz(s: WifiPanelState) -> bool:
    return _has_ap(s) and s.is_6ghz()


def _has_wps(s: WifiPanelState) -> bool:
    return _has_ap(s) and s.selected_ap_wps


def _has_pmf(s: WifiPanelState) -> bool:
    return _has_ap(s) and s.selected_ap_pmf


def _has_handshake(s: WifiPanelState) -> bool:
    return _has_ap(s) and s.has_handshake()


def _has_pmkid(s: WifiPanelState) -> bool:
    return _has_ap(s) and s.has_pmkid()


def _has_capture(s: WifiPanelState) -> bool:
    return _has_ap(s) and s.has_capture()


def _ready_to_crack(s: WifiPanelState) -> bool:
    return _has_capture(s) and s.has_wordlist()


def _ready_to_crack_handshake(s: WifiPanelState) -> bool:
    return (_has_ap(s) and s.has_handshake()
            and s.has_wordlist())


def _ready_to_crack_pmkid(s: WifiPanelState) -> bool:
    return (_has_ap(s) and s.has_pmkid()
            and s.has_wordlist())


# ---------------------------------------------------------------------------
# CAPABILITY_CATALOG
# ---------------------------------------------------------------------------
CAPABILITY_CATALOG: Tuple[Capability, ...] = (
    # ---- Universal (always visible) --------------------------------
    Capability("help", "?", "Help — list all visible actions",
               RISK_READ, False, _always,
               help_text="Show every action currently applicable to the "
                         "selected target."),
    Capability("exit", "e", "Exit — return to the post-access menu",
               RISK_READ, False, _always,
               help_text="Close the WIFI panel and return to the screen."),

    # ---- Adapter discovery (no adapter yet) -----------------------
    Capability("adapters", "a", "Adapters — list wireless interfaces",
               RISK_READ, False, _always,
               help_text="Run `iw dev` / `ip link` to list wireless "
                         "interfaces. Useful when no adapter is selected."),
    Capability("select_adapter", "i", "Select adapter — pick iface by name",
               RISK_READ, False, _always,
               help_text="Switch the active adapter (e.g. wlan0). Required "
                         "before any monitor-mode or scan action."),
    Capability("driver_info", "d", "Driver info — show phy/caps for adapter",
               RISK_READ, False, _has_adapter,
               help_text="Run `iw phy` to inspect monitor/capability info."),

    # ---- Mode switching (not in monitor yet) ----------------------
    Capability("enable_monitor", "m", "Monitor — switch to monitor mode",
               RISK_INTRUSIVE, True, _not_in_monitor,
               needs=("adapter",),
               help_text="`airmon-ng start <iface>` (or `iw dev <iface> "
                         "set type monitor`). Root-gated; tears the iface "
                         "down then up."),
    Capability("disable_monitor", "M", "Managed — return to managed mode",
               RISK_INTRUSIVE, True, _in_monitor,
               needs=("adapter",),
               help_text="`airmon-ng stop <iface>` / `iw dev set type "
                         "managed`. Required before associating."),

    # ---- In-monitor: scanning -------------------------------------
    Capability("scan", "s", "Scan — discover nearby APs (airodump)",
               RISK_READ, False, _in_monitor,
               needs=("adapter",),
               help_text="Start airodump-ng on the current channel. "
                         "Result is parsed into scan_results."),
    Capability("list", "l", "List — show scan results",
               RISK_READ, False, _has_scan,
               help_text="Pretty-print the parsed scan_results table."),
    Capability("select_ap", "p", "Pick AP — choose a target from scan",
               RISK_READ, False, _has_scan,
               needs=("scan_results",),
               help_text="Set selected_ap. Many attacks require an AP."),
    Capability("channel_set", "c", "Channel — lock to a specific channel",
               RISK_INTRUSIVE, True, _in_monitor,
               needs=("adapter",),
               help_text="`iw dev <iface> set channel <n>`. Required for "
                         "channel-locked captures."),

    # ---- Recon (no AP selected) -----------------------------------
    Capability("probe_harvest", "h", "Probe harvest — collect probe reqs",
               RISK_READ, False, _in_monitor,
               help_text="Tshark-based passive probe collection. Used for "
                         "SSID-aware wordlists."),
    Capability("rf_survey", "f", "RF survey — channel utilization",
               RISK_READ, False, _in_monitor,
               help_text="Dynamic channel hopping RF survey. Heuristic "
                         "(not trained)."),
    Capability("spectrum_scan", "J", "Spectrum scan — anomaly detection",
               RISK_READ, False, _in_monitor,
               help_text="Spectrum anomaly VAE. Heuristic (not trained)."),
    # ---- With AP selected: per-encryption actions -----------------
    # WPA2 / WPA3
    Capability("deauth", "1", "Deauth — targeted deauth frame",
               RISK_INTRUSIVE, True, _has_clients,
               needs=("selected_ap", "client"),
               help_text="`aireplay-ng -0 <n>`. Boots clients off; required "
                         "to capture a 4-way handshake."),
    Capability("capture_handshake", "2", "Handshake — wait for EAPOL 4-way",
               RISK_READ, False, _is_wpa2,
               needs=("selected_ap", "monitor"),
               help_text="Airodump-ng on the AP's channel; auto-detects "
                         "the 4-way handshake. Marks handshake_captured."),
    Capability("pmkid", "3", "PMKID — hcxdumptool PMKID attack",
               RISK_INTRUSIVE, True, _is_wpa2,
               needs=("selected_ap", "monitor"),
               help_text="`hcxdumptool`. Extracts PMKID without clients. "
                         "Marks pmkid_captured."),
    Capability("wpa2_kr00k", "K", "Kr00k — WPA2 all-channel kr00k",
               RISK_INTRUSIVE, True, _is_wpa2,
               needs=("selected_ap", "monitor"),
               help_text="CVE-2019-15126 kr00k across all channels. "
                         "Requires vulnerable AP firmware."),
    # WEP
    Capability("wep_ai", "[", "WEP AI — AI-driven WEP attack",
               RISK_INTRUSIVE, True, _is_wep,
               needs=("selected_ap", "monitor"),
               help_text="AI-driven FMS/PTW. Heuristic (not trained)."),
    Capability("wep_fragment", "G", "Fragmentation — WEP chopchop/frag",
               RISK_INTRUSIVE, True, _is_wep,
               needs=("selected_ap", "monitor"),
               help_text="WEP chopchop + fragmentation. Older attack; "
                         "left for legacy WEP networks."),
    # WPA3
    Capability("sae_downgrade", "O", "SAE downgrade — transition attack",
               RISK_INTRUSIVE, True, _is_wpa3,
               needs=("selected_ap", "monitor"),
               help_text="Force transition mode to WPA2 (downgrade). "
                         "SAE-only APs are not vulnerable."),
    Capability("sae_reflection", "X", "SAE reflection — group downgrade",
               RISK_INTRUSIVE, True, _is_wpa3,
               needs=("selected_ap", "monitor"),
               help_text="CVE-2019-9494 group downgrade."),
    Capability("dragonblood", "B", "DragonBlood — timing/cache side channel",
               RISK_READ, False, _is_wpa3,
               needs=("selected_ap",),
               help_text="Timing-based side channel. Heuristic (not trained)."),
    # OPEN
    Capability("open_capture", "Q", "Open capture — passive capture",
               RISK_READ, False, _is_open,
               needs=("selected_ap", "monitor"),
               help_text="Capture all traffic on an open AP (no encryption)."),

    # ---- WPS (only if WPS detected) -------------------------------
    Capability("wps_null_pin", "n", "WPS null PIN — pixie dust variant",
               RISK_INTRUSIVE, True, _has_wps,
               needs=("selected_ap",),
               help_text="Test for WPS PIN vulnerabilities. "
                         "Reaver/Bully fallback if null PIN fails."),
    Capability("wps_button", "N", "WPS button — virtual push simulation",
               RISK_INTRUSIVE, True, _has_wps,
               needs=("selected_ap",),
               help_text="Simulate a WPS button press."),

    # ---- PMF (only if PMF detected) -------------------------------
    Capability("pmf_bypass", "P", "PMF bypass — test MFP off-path",
               RISK_INTRUSIVE, True, _has_pmf,
               needs=("selected_ap", "monitor"),
               help_text="Test PMF off-path bypass (CVE-2019-...)."),
    Capability("mfp_replay", "Y", "MFP replay — protected mgmt frame replay",
               RISK_INTRUSIVE, True, _has_pmf,
               needs=("selected_ap", "monitor"),
               help_text="Replay protected mgmt frames against an MFP AP."),

    # ---- Evil twin / clients (any encryption with clients) --------
    Capability("evil_twin", "t", "Evil twin — hostapd + dnsmasq AP",
               RISK_DESTRUCTIVE, True, _has_ap,
               needs=("selected_ap",),
               help_text="Stand up an evil-twin AP with the same SSID. "
                         "Hosts a captive portal to harvest creds. "
                         "Operator-owned APs only."),
    Capability("karma", ">", "Karma/Mana — preferred-network attack",
               RISK_DESTRUCTIVE, True, _has_ap,
               needs=("selected_ap",),
               help_text="Run a Karma/Mana responder. Steals probes. "
                         "Operator-owned APs only."),
    Capability("captive_portal", "C", "Captive portal — captive bypass",
               RISK_INTRUSIVE, True, _has_ap,
               needs=("selected_ap",),
               help_text="Detect & bypass captive portals. Heuristic "
                         "(not trained)."),
    Capability("band_steering", "b", "Band steering — force 2.4/5 flip",
               RISK_INTRUSIVE, True, _has_clients,
               needs=("selected_ap", "client"),
               help_text="Push clients off the current band. Useful for "
                         "dual-band APs."),
    Capability("client_creds", "$", "Client creds — hijack creds via twin",
               RISK_DESTRUCTIVE, True, _has_clients,
               needs=("selected_ap", "client"),
               help_text="Steal HTTP/FTP/Telnet creds via evil-twin. "
                         "Operator-owned APs only."),
    Capability("client_powersave", "z", "Power-save exploit — drain client",
               RISK_INTRUSIVE, True, _has_clients,
               needs=("selected_ap", "client"),
               help_text="Force client into power-save; drain battery."),

    # ---- 5 GHz / 6 GHz (extended) ---------------------------------
    Capability("ofdma_steal", "o", "OFDMA steal — HE resource stealing",
               RISK_INTRUSIVE, True, _is_5ghz,
               needs=("selected_ap", "monitor"),
               help_text="Wi-Fi 6 OFDMA resource stealing. Requires HE AP."),
    Capability("mu_mimo_null", "u", "MU-MIMO nulling — beamforming attack",
               RISK_INTRUSIVE, True, _is_5ghz,
               needs=("selected_ap", "monitor"),
               help_text="Spoof MU-MIMO null data to disrupt beamforming."),
    Capability("twt_exhaust", "T", "TWT exhaust — target wake time flood",
               RISK_INTRUSIVE, True, _is_5ghz,
               needs=("selected_ap", "monitor"),
               help_text="Flood TWT requests to exhaust AP scheduling."),
    Capability("dual_band", "x", "Dual-band — steer 2.4↔5 hijack",
               RISK_INTRUSIVE, True, _has_clients,
               needs=("selected_ap", "client"),
               help_text="Band steering to force dual-band clients to "
                         "associate to attacker twin."),
    Capability("6ghz_burst", "6", "6 GHz burst — channel discovery",
               RISK_READ, False, _is_6ghz,
               needs=("selected_ap", "monitor"),
               help_text="Wi-Fi 6E 6 GHz channel discovery burst."),
    Capability("preamble_puncture", ";", "Preamble puncture exploit",
               RISK_INTRUSIVE, True, _is_5ghz,
               needs=("selected_ap", "monitor"),
               help_text="Wi-Fi 7 preamble puncturing exploit."),

    # ---- Cracking (capture present) -------------------------------
    Capability("wordlist", "w", "Wordlist — set/load cracking wordlist",
               RISK_READ, False, _in_monitor,
               help_text="Pick a wordlist path (rockyou.txt etc.). Sets "
                         "wordlist_loaded."),
    Capability("hashcat_22001", "=", "Hashcat WPA2 (22001) — crack handshake",
               RISK_INTRUSIVE, True, _ready_to_crack_handshake,
               needs=("handshake", "wordlist"),
               help_text="`hashcat -m 22001 <pcap> <wordlist>`. "
                         "Honest-degrade if no GPU or hashcat absent."),
    Capability("hashcat_16800", "+", "Hashcat PMKID (16800) — crack PMKID",
               RISK_INTRUSIVE, True, _ready_to_crack_pmkid,
               needs=("pmkid", "wordlist"),
               help_text="`hashcat -m 16800 <pmkid> <wordlist>`."),
    Capability("ai_wpa_priority", "A", "AI priority — PMKID/handshake ranker",
               RISK_READ, False, _has_capture,
               needs=("capture",),
               help_text="Heuristic (not trained) — rank candidates for "
                         "cracking by AP/SSID/entropy."),
    Capability("view_capture", "%", "View capture — show capture path",
               RISK_READ, False, _has_capture,
               help_text="Display pcap_path / handshake_captured / "
                         "pmkid_captured state."),

    # ---- Anonymity / OPSEC (always optional) ----------------------
    Capability("mac_rotate", "r", "MAC rotate — spoof rotating MAC",
               RISK_INTRUSIVE, True, _has_adapter,
               help_text="Set a fresh random MAC on the iface. OPSEC."),
    Capability("tx_power", "y", "TX power — adjust transmit power (dBm)",
               RISK_INTRUSIVE, True, _has_adapter,
               help_text="`iw dev <iface> set txpower <dBm>`. Stealthier "
                         "low-power or stronger DoS at high power."),
    Capability("stealth_scan", "j", "Stealth scan — low-power passive",
               RISK_READ, False, _in_monitor,
               help_text="Power-controlled stealth scan."),

    # ---- Saved profiles (always) ----------------------------------
    Capability("saved", "v", "View saved — list saved AP profiles",
               RISK_READ, False, _always,
               help_text="Show saved AP profiles (SSID/bssid/notes)."),
    Capability("save_ap", "*", "Save AP — remember current selection",
               RISK_READ, False, _has_ap,
               help_text="Persist selected_ap into saved_aps for later runs."),

    # ---- AI / orchestration ---------------------------------------
    Capability("ai_plan", "Z", "AI plan — generate a full attack plan",
               RISK_READ, False, _has_ap,
               help_text="Heuristic (not trained) — generate a full "
                         "attack plan based on AP features."),
    Capability("full_auto_pwn", "!", "Full auto — AI-driven end-to-end pwn",
               RISK_DESTRUCTIVE, True, _has_ap,
               needs=("selected_ap",),
               help_text="End-to-end: scan → deauth → capture → crack. "
                         "Heuristic (not trained). Operator-owned APs only. "
                         "Single-gate."),

    # ---- Adapter cleanup (always) ---------------------------------
    Capability("reset_adapter", "R", "Reset adapter — bring iface down/up",
               RISK_INTRUSIVE, True, _has_adapter,
               help_text="`ip link set <iface> down && up`. Recovery action."),

    # ---- Channel-hopping (in-monitor) -----------------------------
    Capability("channel_hop", "H", "Channel hop — automated RF survey",
               RISK_READ, False, _in_monitor,
               help_text="Automated channel hopping + RF survey. Heuristic "
                         "(not trained)."),

    # ---- Frame crafting (in-monitor) ------------------------------
    Capability("beacon_flood", "L", "Beacon flood — adaptive beacon flood",
               RISK_DESTRUCTIVE, True, _in_monitor,
               help_text="mdk4 / scapy adaptive beacon flood. OPSEC-required."),
    Capability("mdk3", "E", "MDK3 — legacy mdk3 attack",
               RISK_DESTRUCTIVE, True, _in_monitor,
               help_text="Legacy mdk3 broadcast DoS. OPSEC-required."),
    Capability("mdk4", "&", "MDK4 — modern mdk4 attack",
               RISK_DESTRUCTIVE, True, _in_monitor,
               help_text="Modern mdk4 DoS. OPSEC-required."),
    Capability("ap_overload", "0", "AP overload — connection DoS",
               RISK_DESTRUCTIVE, True, _has_ap,
               needs=("selected_ap",),
               help_text="Association flood against the selected AP. "
                         "OPSEC-required."),

    # ---- Selected-AP analytics (with AP) --------------------------
    Capability("sig_predict", "g", "Sig predict — RSSI model (heuristic)",
               RISK_READ, False, _has_ap,
               help_text="Heuristic (not trained) signal strength prediction."),
    Capability("beacon_triangulate", "/", "Triangulate — beacon RSSI",
               RISK_READ, False, _has_ap,
               help_text="Beacon RSSI triangulation. Heuristic (not trained)."),
    Capability("rf_fingerprint", "~", "RF fingerprint — clone the AP",
               RISK_READ, False, _has_ap,
               help_text="Clone the AP's RF fingerprint for later replay. "
                         "Heuristic (not trained)."),
    Capability("ap_uptime", "U", "AP uptime — passive uptime estimate",
               RISK_READ, False, _has_ap,
               help_text="Passive AP uptime estimate from beacon drift."),
    Capability("dtim_predict", ":", "DTIM predict — predict DTIM period",
               RISK_READ, False, _has_ap,
               help_text="Predict the AP's DTIM period. Heuristic (not trained)."),
    Capability("channel_forecast", "#", "Channel forecast — occupancy LSTM",
               RISK_READ, False, _in_monitor,
               help_text="Channel occupancy LSTM. Heuristic (not trained)."),
    Capability("cross_layer_ai", "_", "Cross-layer AI — fusion inference",
               RISK_READ, False, _has_ap,
               help_text="Cross-layer Transformer inference. Heuristic "
                         "(not trained)."),

    # ---- Protocol corner cases (in-monitor) -----------------------
    Capability("eap_downgrade", "8", "EAP downgrade — force weak EAP",
               RISK_INTRUSIVE, True, _has_ap,
               needs=("selected_ap", "monitor"),
               help_text="Force EAP type downgrade. 802.1X APs only."),
    Capability("eapol_logoff", "9", "EAPOL logoff — logoff injection",
               RISK_INTRUSIVE, True, _has_clients,
               needs=("selected_ap", "client", "monitor"),
               help_text="Send EAPOL-Logoff to drop a client. "
                         "Client disconnect test."),
    Capability("dhcp_starve", "I", "DHCP starvation — exhaust DHCP pool",
               RISK_INTRUSIVE, True, _has_ap,
               needs=("selected_ap", "monitor"),
               help_text="Exhaust the AP's DHCP pool."),

    # ---- Frame injection (in-monitor) ----------------------------
    Capability("disassoc", "D", "Disassoc — disassociation frame",
               RISK_INTRUSIVE, True, _has_clients,
               needs=("selected_ap", "client", "monitor"),
               help_text="Targeted disassociation frame. Lighter than "
                         "deauth; some clients respond to it."),
    Capability("probe_response", "7", "Probe resp — craft probe response",
               RISK_INTRUSIVE, True, _in_monitor,
               help_text="Scapy-crafted probe response. Pull clients."),
    Capability("assoc_request", ".", "Assoc req — craft assoc request",
               RISK_INTRUSIVE, True, _in_monitor,
               help_text="Scapy-crafted assoc request. Fingerprint APs."),

    # ---- 802.11w / management frames ------------------------------
    Capability("wnm_sleep", "F", "WNM sleep — push client to sleep",
               RISK_INTRUSIVE, True, _has_clients,
               needs=("selected_ap", "client"),
               help_text="Send WNM-Sleep to put a client into sleep mode."),
    Capability("neighbor_report", "q", "Neighbor report — inject 11k",
               RISK_INTRUSIVE, True, _has_ap,
               needs=("selected_ap", "monitor"),
               help_text="Inject a forged 11k neighbor report."),
    Capability("ft_replay", "k", "FT replay — fast-transition replay",
               RISK_INTRUSIVE, True, _has_ap,
               needs=("selected_ap", "monitor"),
               help_text="Fast BSS transition (FT) handshake replay."),
    Capability("bss_color_poison", "W", "BSS color — poison HE color",
               RISK_INTRUSIVE, True, _is_5ghz,
               needs=("selected_ap", "monitor"),
               help_text="BSS coloring poisoning. HE APs only."),

    # ---- Phase 1.6 secondary patterns ----------------------------
    Capability("vuln_classify", "V", "Vuln classify — encryption rule engine",
               RISK_READ, False, _has_ap,
               help_text="Heuristic (not trained) vulnerability classifier."),
    Capability("phase_wordlist", "@", "Phase wordlist — SSID-aware forge",
               RISK_READ, False, _has_ap,
               help_text="Generate a phase-based SSID-aware wordlist."),
    Capability("scapy_flood", "S", "Scapy flood — auth/assoc/probe flood",
               RISK_DESTRUCTIVE, True, _in_monitor,
               help_text="Scapy-crafted auth/assoc/probe/beacon/deauth "
                         "flood. OPSEC-required."),
)


# ---------------------------------------------------------------------------
# compute_visible_menu
# ---------------------------------------------------------------------------
def compute_visible_menu(state: WifiPanelState) -> List[Capability]:
    """Return the capabilities that are currently applicable.

    Filters ``CAPABILITY_CATALOG`` by each entry's
    ``availability_fn(state)``. Robust to buggy availability_fn: a
    raising availability_fn causes the capability to be hidden, not
    the whole menu to crash.
    """
    out: List[Capability] = []
    for cap in CAPABILITY_CATALOG:
        try:
            if cap.availability_fn(state):
                out.append(cap)
        except Exception:  # noqa: BLE001
            # Hide the capability on any error — never crash the menu.
            continue
    return out


def friendly_action(action: str) -> str:
    """Best-effort friendly label for an action name."""
    for cap in CAPABILITY_CATALOG:
        if cap.action == action:
            return cap.label
    return action


# ---------------------------------------------------------------------------
# Default menu (top-N) shown when no scan has happened
# ---------------------------------------------------------------------------
def default_disconnected_menu() -> List[Capability]:
    """The menu shown before the operator has selected an adapter."""
    return [
        cap for cap in CAPABILITY_CATALOG
        if cap.action in {
            "adapters", "select_adapter", "help", "exit",
        }
    ]
