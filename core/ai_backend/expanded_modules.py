"""core.ai_backend.expanded_modules — second-wave (Phase 3) modules.

The operator's request: 50+ new modules per type (wifi, ble, wifi-recon,
ble-recon, osint, post-exploit, forensics, anti-forensics), 120 new
toolboxes, and richer algorithms throughout. This module is the
*registry* of new method names + descriptions + risk levels + per-type
subcategories. It does NOT re-implement the underlying subprocesses
(which already live in :mod:`core.wifi_attack.runner`,
:mod:`core.ble.runner`, :mod:`core.osint.runner`,
:mod:`core.post_exploit.runner`, :mod:`core.post_exploit.anti_forensic`).
Instead it extends each runner with a v2 of new method names that
plumb through the existing dispatcher.

The expanded registry doubles as a prompt-stanza the LLM can use to
select creative new chains: each entry has a 1-3 line description of
what the method does and when to use it.

Honesty contract (mirrors zero_day_algorithms):
  * Every entry is a real method the underlying runner can dispatch.
  * Each entry has a risk level; gated steps fire the operator's
    ACCEPT prompt; read-only steps do not.
  * Never fabricates a CVE id, cracked PSK, cleartext credential, or
    NTLM hash. The new methods only ENUMERATE / DESCRIBE — they
    never pretend to have cracked a password or popped a shell.

Public surface:
  * ``WIFI_V2_METHODS``         — 50+ new wifi-attack method names
  * ``WIFI_RECON_V2_METHODS``   — 50+ new wifi-recon method names
  * ``BLE_V2_METHODS``          — 50+ new ble-attack method names
  * ``BLE_RECON_V2_METHODS``    — 50+ new ble-recon method names
  * ``OSINT_V2_METHODS``        — 50+ new osint method names
  * ``POST_EXPLOIT_V2_METHODS`` — 50+ new post-exploit method names
  * ``FORENSICS_V2_METHODS``    — 50+ new forensics method names
  * ``ANTI_FORENSICS_V2_METHODS`` — 50+ new anti-forensic method names
  * ``V2_REGISTRY``            — the single dict that maps category -> methods
  * ``list_v2_methods(category)``
  * ``describe_v2_method(category, method)``
  * ``describe_v2_category(category)``
  * ``all_v2_method_names()``
  * ``build_v2_prompt_stanza()`` — the LLM prompt stanza
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Common shape
# ---------------------------------------------------------------------------
# Each entry in a category list is a (name, risk, description) tuple.
# Risk: "read" | "intrusive" | "destructive"
# Description: a 1-3 line description of what the method does, in
# language the LLM can use to decide when to chain it.


# ---------------------------------------------------------------------------
# WiFi attack (creative, modern 802.11 / 6E / WPA3 / mesh / WFD)
# ---------------------------------------------------------------------------
WIFI_V2_METHODS: List[Tuple[str, str, str]] = [
    # === 802.11ax / WiFi 6E / 6 GHz surface ===
    ("wifi6e_ofdma_trigger_flood", "intrusive",
     "Flood an AP's OFDMA trigger frame queue to deny access to "
     "stations on the 6 GHz band. Real scapy / hostapd_cli."),
    ("wifi6e_he_capabilities_audit", "read",
     "Audit an AP's HE capabilities for insecure HE-MCS / Nss "
     "combinations and missing TB-PPDU ack policies. Pure LLM + parse."),
    ("wifi6_ofdma_ru_allocation_dos", "intrusive",
     "Send bogus RU-allocation triggers to starve stations. "
     "Real scapy."),
    ("wifi6_he_action_frame_fuzz", "intrusive",
     "Fuzz HE action frames (BSRP, BFRP, MU-BAR) to find state-"
     "machine confusion in target AP. Real scapy, controlled burst."),
    ("wifi6e_psc_scanning_audit", "intrusive",
     "Probe Preferred Scanning Channels (PSCs) for hidden 6E "
     "networks. Real scapy + filter."),
    ("wifi6_mimo_feedback_spoof", "intrusive",
     "Spoof MU-MIMO feedback to misallocate spatial streams. "
     "Real scapy framecraft."),
    ("wifi7_mlo_channel_access_dos", "intrusive",
     "Exploit Multi-Link Operation (MLO) channel-access unfairness "
     "to deny a victim station access across all links. Real scapy."),
    ("wifi7_eht_tb_sounding_fuzz", "intrusive",
     "Fuzz EHT TB sounding frames for parsing bugs. Real scapy."),
    ("wifi7_mlo_reconfig_dos", "intrusive",
     "Force MLO reconfiguration storms to drop victim traffic. "
     "Real scapy."),
    # === WPA3 / SAE / OWE ===
    ("wpa3_sae_password_element_fuzz", "intrusive",
     "Fuzz the SAE password-element parsing for stack overflow / "
     "integer overflow. Real scapy + hostapd log inspection."),
    ("wpa3_sae_anti_clogging_dos", "intrusive",
     "Send many simultaneous SAE commit frames to a single AP, "
     "exhausting its anti-clogging-token cache. Real scapy."),
    ("wpa3_sae_commit_reflect", "intrusive",
     "Reflect a victim's SAE commit back to it (if it accepts a "
     "transition disable). Real scapy."),
    ("wpa3_owe_transition_bypass", "intrusive",
     "Test whether an AP that advertises both OWE and OPEN allows "
     "downgrade to OPEN. Real wpa_supplicant / scapy probe."),
    ("wpa3_suite_b_192_curve_audit", "read",
     "Audit the negotiated Suite B 192-bit curves for weak / "
     "deprecated NIST groups. Pure LLM + parse of beacon IEs."),
    # === 802.11w / PMF ===
    ("pmf_sa_query_flood", "intrusive",
     "Flood SA-Query requests to force the AP to drop legitimate "
     "associations during a transition window. Real scapy."),
    ("pmf_bip_replay_attack", "intrusive",
     "Capture a valid BIP-protected management frame, replay with "
     "modified IPN. Real scapy, controlled test."),
    ("pmf_robust_action_audit", "read",
     "Parse beacons + assoc-resp for Robust Action frame policy and "
     "compare to 802.11w spec. LLM scoring."),
    # === Mesh / WDS / 802.11s ===
    ("mesh_peering_open_audit", "read",
     "Detect mesh APs advertising OPEN peering. LLM scoring + parse."),
    ("mesh_gate_announcement_fuzz", "intrusive",
     "Fuzz mesh gate-announcement frames for routing-table "
     "corruption. Real scapy."),
    ("mesh_hwmp_rrep_inject", "intrusive",
     "Inject a forged HWMP RREP to redirect mesh traffic through "
     "an attacker. Real scapy."),
    # === WFD / Wi-Fi Direct / P2P ===
    ("wifi_p2p_invite_replay", "intrusive",
     "Replay a captured P2P Invitation to a peer to force a "
     "re-association. Real scapy."),
    ("wifi_p2p_go_negotiation_fuzz", "intrusive",
     "Fuzz P2P GO-Negotiation-Request frames for parsing bugs. "
     "Real scapy."),
    ("wifi_p2p_provision_disc_audit", "read",
     "Audit Wi-Fi Direct Provision-Discovery frames for cleartext "
     "WPS credentials. LLM scoring + parse."),
    ("wifi_p2p_cross_connect_dos", "intrusive",
     "Force a Wi-Fi Direct group owner to disassociate its "
     "clients via deauth frame. Real scapy."),
    # === Hotspot 2.0 / Passpoint / 802.11u ===
    ("passpoint_anqp_fuzz", "intrusive",
     "Fuzz ANQP / HS2.0 elements for parsing bugs. Real scapy."),
    ("passpoint_osu_server_dos", "intrusive",
     "Deny the Online Sign-Up server by exhausting the OSU "
     "association quota. Real scapy + SOAP."),
    ("passpoint_3gpp_plmn_audit", "read",
     "Audit 3GPP-PLMN credentials for insecure storage / "
     "transmission. Pure LLM + parse."),
    # === Timing / ML evasion ===
    ("wifi_timing_oracle_dos", "intrusive",
     "Exploit the timing channel that a defense uses to detect "
     "deauth storms. Real scapy + ts."),
    ("wifi_ml_evasion_probe", "intrusive",
     "Generate frames that evade a target AP's ML-based "
     "intrusion-detection model (GAN-style noise). Real scapy."),
    ("wifi_channel_state_info_sidechannel", "read",
     "Read CSI from a research driver (nexmon / mt7921e) to "
     "infer keystrokes / presence. Pure parse + LLM."),
    # === Hotspot / evil-twin variations ===
    ("evil_twin_wpa3_only", "intrusive",
     "Run a WPA3-only evil-twin to harvest SAE handshake material "
     "for offline dictionary attack. Real hostapd + scapy."),
    ("evil_twin_passpoint", "intrusive",
     "Run a Passpoint evil-twin to capture OSU traffic. "
     "Real hostapd-wpa3 + dnsmasq."),
    ("evil_twin_6ghz_psc", "intrusive",
     "Stand up an evil-twin on a 6 GHz PSC channel. "
     "Real hostapd + iw."),
    ("evil_twin_captive_portal_advanced", "intrusive",
     "Captive-portal evil-twin with custom phishing pages for "
     "each target SSID. Real nginx + dnsmasq."),
    # === Beacon / probe tricks ===
    ("beacon_protected_tunnel_audit", "read",
     "Parse a target's beacon for BSS-TM / Power-Constraint / "
     "LSB-related IEs. LLM scoring."),
    ("probe_response_ssdp_amplification", "intrusive",
     "Use a probe-response storm to amplify on a single channel. "
     "Real scapy."),
    ("beacon_flood_with_legit_ssid_clones", "intrusive",
     "Beacon-flood a workspace with hundreds of clones of "
     "legit SSIDs. Real scapy."),
    # === Rate-limiting / WMM / power-save ===
    ("wmm_admission_control_dos", "intrusive",
     "Exhaust WMM admission-control bandwidth to deny a victim "
     "voice / video priority. Real scapy."),
    ("power_save_buffer_overflow", "intrusive",
     "Flood TIM / DTIM beacons to overflow the station's "
     "power-save buffer. Real scapy, controlled test."),
    ("power_save_tim_steal", "intrusive",
     "Steal a victim's queued traffic by impersonating its AID. "
     "Real scapy, lab test."),
    # === Long-range / outdoor / 802.11ah ===
    ("wifi_halow_s1g_audit", "read",
     "Audit 802.11ah (HaLow) beacon / association for "
     "insecure S1G channels. LLM + parse."),
    ("wifi_halow_ampdu_reassembly_fuzz", "intrusive",
     "Fuzz A-MPDU reassembly on 802.11ah. Real scapy."),
    # === WNM / BSS-TM ===
    ("wnm_bss_transition_dos", "intrusive",
     "Force a victim to roam to a fake / load-only BSS via "
     "BSS-TM-Request. Real scapy."),
    ("wnm_sleep_mode_audit", "read",
     "Audit WNM-Sleep-Mode negotiation. LLM scoring + parse."),
    # === Tunneled / NAN / OCV ===
    ("nan_action_frame_fuzz", "intrusive",
     "Fuzz Neighbor-Awareness-Networking action frames. "
     "Real scapy, controlled burst."),
    ("ocv_operating_channel_audit", "read",
     "Audit Operating Channel Validation for off-channel "
     "transition vulnerabilities. LLM + parse."),
    # === Other / novel ===
    ("wifi_phy_jamming_burst", "intrusive",
     "Wide-band physical-layer jamming via SDR (HackRF / "
     "bladeRF). Real osmosdr / soapy."),
    ("wifi_phy_dsss_preamble_inject", "intrusive",
     "Inject DSSS preamble to disrupt 802.11b/g legacy "
     "associations. Real scapy."),
    ("wifi_phy_ofdm_legacy_misuse", "intrusive",
     "Send OFDM-legacy training fields to confuse newer "
     "stations. Real scapy."),
    ("wifi_security_audit_passive", "read",
     "Passive-only audit of beacon / probe-resp security "
     "indicators (RSN, PMF, MFP-required). LLM scoring."),
    ("wifi_realtime_spectrum_audit", "read",
     "Run a real-time spectrum analysis via iw / aircrack-ng + "
     "LLM scoring of interference patterns."),
    ("wifi_enterprise_eap_method_audit", "read",
     "Audit the supported EAP methods of an enterprise AP. "
     "LLM scoring + parse."),
    ("wifi_enterprise_8021x_replay", "intrusive",
     "Replay captured EAPOL frames in an enterprise 802.1X "
     "environment (lab only). Real scapy."),
    ("wifi_enterprise_peap_mschapv2_dos", "intrusive",
     "Deny PEAP/MSCHAPv2 by exhausting inner-auth attempts. "
     "Real hostapd-wpe + freeradius."),
    ("wifi_enterprise_outer_identity_leak", "read",
     "Detect outer-identity leakage in EAP. LLM + parse of "
     "captured EAP-Identity-Request."),
    # === Phase 2.3.D polymorphic (5) ===
    ("poly_deauth_interval_ai", "intrusive",
     "Polymorphic deauth interval grammar. Produces a deterministic "
     "ramp of intervals 50-200ms with backoff. Pure Python heuristic."),
    ("poly_beacon_flood_ssid_grammar", "intrusive",
     "Polymorphic SSID grammar for beacon flood. Appends random "
     "ascii suffixes to a base SSID. Pure Python heuristic."),
    ("poly_evil_twin_captive_html_ai", "intrusive",
     "Polymorphic captive-portal HTML template. Returns a minimal "
     "HTML form scaffold; NEVER inlines harvested creds."),
    ("poly_krack_replay_counter_drift", "intrusive",
     "Polymorphic replay-counter grammar for KRACK-style replay. "
     "Produces 16 random nonces per chain. Pure Python heuristic."),
    ("poly_pmkid_rule_chain_drift", "intrusive",
     "Polymorphic PMKID rule-chain grammar. Returns a re-orderable "
     "capture→hash→crack chain. Pure Python heuristic."),
    # === Phase 2.3.D target-adaptive (5) ===
    ("adapt_attack_wpa_version_picker", "read",
     "Pick the best attack primitive based on the AP's advertised "
     "WPA version. Pure heuristic, no train."),
    ("adapt_attack_vendor_picker", "read",
     "Pick the best attack primitive based on the AP's OUI vendor. "
     "Pure heuristic, no train."),
    ("adapt_attack_client_count_picker", "read",
     "Pick the best attack primitive based on the AP's client count. "
     "Pure heuristic, no train."),
    ("adapt_attack_channel_congestion_picker", "read",
     "Pick the best attack primitive based on channel utilization. "
     "Pure heuristic, no train."),
    ("adapt_attack_client_pmf_picker", "read",
     "Pick the best attack primitive based on PMF enforcement. "
     "Pure heuristic, no train."),
    # === Phase 2.3.D full-chain / orchestrator (2) ===
    ("wifi_attack_full_chain", "intrusive",
     "Full chain orchestrator: deauth + capture + PMKID + crack + "
     "evil-twin. Each substep is itself gated."),
    ("wifi_attack_orchestrator", "read",
     "Top-level orchestrator that picks the best attack primitive "
     "for the current target's behaviour. Returns the picker list."),
]


# ---------------------------------------------------------------------------
# WiFi recon (passive / listen-only, broad)
# ---------------------------------------------------------------------------
WIFI_RECON_V2_METHODS: List[Tuple[str, str, str]] = [
    # === Rogue AP / evil-twin detection ===
    ("rogue_ap_oui_correlate", "read",
     "Correlate an AP's BSSID OUI against a known-vendor list to "
     "flag candidates for rogue AP. Pure LLM + parse."),
    ("rogue_ap_known_ssid_collision", "read",
     "Detect BSSIDs advertising a known SSID that the operator's "
     "assets don't own. LLM + parse."),
    ("rogue_ap_signal_anomaly", "read",
     "Detect signal-strength anomalies that suggest an "
     "evil-twin. Pure LLM + airodump."),
    ("rogue_ap_channel_overlap", "read",
     "Map AP channel overlap and flag unexpected co-channel "
     "interference. Pure parse + LLM."),
    ("rogue_ap_broadcom_atheros_clash", "read",
     "Detect a chipset-class clash (Broadcom advertising an "
     "SSID that should be Atheros). LLM + parse."),
    # === Hidden SSID / privacy ===
    ("hidden_ssid_beacon_inference", "read",
     "Infer hidden SSIDs from probe-requests by clients. "
     "Pure scapy listen + LLM."),
    ("hidden_ssid_timing_oracle", "read",
     "Infer hidden SSIDs from frame timing correlations. "
     "Pure scapy listen + LLM."),
    ("ssid_privacy_prober", "read",
     "Actively send probe-requests to elicit hidden-SSID "
     "probe-responses. Real scapy."),
    # === Client mapping ===
    ("client_probing_pattern_audit", "read",
     "Map probe-request patterns of clients to infer their "
     "preferred networks. Pure parse + LLM."),
    ("client_preferred_network_audit", "read",
     "Identify the preferred network list of a client. "
     "LLM + parse."),
    ("client_manufacturer_classify", "read",
     "Classify clients by manufacturer via OUI + probe-request "
     "fingerprint. LLM + parse."),
    ("client_roaming_history_audit", "read",
     "Map a client's roaming history across multiple BSSIDs. "
     "Pure parse + LLM."),
    # === 802.11k/v/r (RRM / BSS-TM / FT) ===
    ("rrm_measurement_request_audit", "read",
     "Send an 802.11k Measurement-Request to elicit a report "
     "from the AP. Real scapy, read-only."),
    ("rrm_lci_civic_audit", "read",
     "Parse 802.11k LCI / Civic Location reports. LLM + parse."),
    ("bss_transition_query_audit", "read",
     "Send a BSS-TM-Query to elicit candidate-list. Real scapy, "
     "read-only."),
    ("ft_over_ds_audit", "read",
     "Test whether an AP supports FT-over-DS (potential downgrade "
     "vulnerability). Real scapy, read-only."),
    ("ft_over_air_audit", "read",
     "Test whether an AP supports FT-over-Air. Real scapy, "
     "read-only."),
    # === Channel utilization / load ===
    ("channel_utilization_audit", "read",
     "Parse QBSS Load IE for channel-utilization and station "
     "count. LLM + parse."),
    ("bss_load_audit", "read",
     "Parse 802.11e BSS Load. LLM + parse."),
    ("airtime_fairness_audit", "read",
     "Infer airtime fairness from frame-size distribution. "
     "Pure parse + LLM."),
    # === Vendor-specific IE / WFA / WMM ===
    ("vendor_specific_ie_audit", "read",
     "Audit vendor-specific IEs (Broadcom, Qualcomm, Intel). "
     "LLM + parse."),
    ("wmm_parameter_audit", "read",
     "Parse WMM Parameter Element for AC / CWmin / CWmax. "
     "LLM + parse."),
    ("wfa_wifi_certified_audit", "read",
     "Audit WFA Wi-Fi-Certified IEs. LLM + parse."),
    # === Passive behavior analysis ===
    ("passive_deauth_detector", "read",
     "Detect a deauth storm from passive capture (without "
     "transmitting). Pure scapy listen + parse."),
    ("passive_disassoc_detector", "read",
     "Detect disassoc anomalies. Pure scapy listen + parse."),
    ("passive_auth_failure_detector", "read",
     "Detect auth-failure storms. Pure scapy listen + parse."),
    ("passive_beacon_rate_audit", "read",
     "Audit beacon-rate variance (TBTT jitter) to detect "
     "interference. Pure parse + LLM."),
    ("passive_dfs_radar_audit", "read",
     "Detect DFS radar events from passive capture. "
     "Pure scapy listen + LLM."),
    # === 6 GHz / 6E passive ===
    ("wifi6e_psc_passive_scan", "read",
     "Passive scan only the Preferred Scanning Channels (PSCs) "
     "in 6 GHz. Real scapy listen."),
    ("wifi6e_standard_power_audit", "read",
     "Audit standard-power vs LPI vs SP mode of a 6 GHz AP. "
     "LLM + parse."),
    # === Client-side detection ===
    ("client_isolation_audit", "read",
     "Detect whether an AP enforces client isolation. "
     "Pure scapy probe."),
    ("client_dhcp_lease_audit", "read",
     "Observe DHCP lease behavior to map subnet. "
     "Pure scapy + LLM."),
    ("client_arp_audit", "read",
     "ARP-table audit via passive sniff. Pure scapy listen."),
    # === WPA3 / Enhanced Open ===
    ("enhanced_open_transition_audit", "read",
     "Detect whether an AP supports OWE-Transition-Mode. "
     "LLM + parse."),
    ("sae_pwd_ie_audit", "read",
     "Audit SAE Password ID IEs for insecure IDs. LLM + parse."),
    # === Frame analysis ===
    ("frame_type_distribution_audit", "read",
     "Classify captured frame types and flag unusual distributions. "
     "Pure scapy + LLM."),
    ("frame_size_distribution_audit", "read",
     "Analyze frame-size distribution for traffic-class inference. "
     "Pure scapy + LLM."),
    ("retry_rate_audit", "read",
     "High retry-rate implies interference. Pure scapy + LLM."),
    ("rts_cts_ratio_audit", "read",
     "RTS/CTS ratio for hidden-node inference. Pure scapy + LLM."),
    ("fragmentation_rate_audit", "read",
     "Fragmentation rate inference. Pure scapy + LLM."),
    # === Adjacent-channel / non-WiFi ===
    ("non_wifi_rf_audit", "read",
     "Detect non-802.11 interference (BT, microwave, ZigBee) "
     "from passive capture. Pure parse + LLM."),
    ("ble_wifi_coexistence_audit", "read",
     "Detect coexistence issues between BLE and WiFi. "
     "Pure parse + LLM."),
    # === Multi-band / global ===
    ("tri_band_audit", "read",
     "Audit a tri-band AP's 2.4 / 5 / 6 GHz configuration. "
     "LLM + parse."),
    ("wifi7_mlo_link_audit", "read",
     "Audit an MLO AP's link configuration. LLM + parse."),
    # === WPA3-Enterprise / 192-bit ===
    ("wpa3_enterprise_192_audit", "read",
     "Audit Suite B 192-bit configuration. LLM + parse."),
    ("wpa3_enterprise_aes_gcmp_audit", "read",
     "Audit GCMP-256 / GMAC-256 in use. LLM + parse."),
    # === Modern / WNM / SCS ===
    ("wnm_notification_audit", "read",
     "Audit WNM-Notification subscription. LLM + parse."),
    ("scs_descriptor_audit", "read",
     "Audit SCS (Stream Classification Service) descriptors. "
     "LLM + parse."),
    # === Defensive posture ===
    ("wifi_defense_in_depth_audit", "read",
     "Composite audit of PMF, MFP-required, transition-disable, "
     "SAE. Pure LLM + parse."),
    # === Lab / experimental ===
    ("wifi_kismet_db_diff", "read",
     "Diff today's kismet DB against yesterday's. Pure parse."),
    ("wifi_chronicle_log_diff", "read",
     "Diff the operator's capture log files. Pure parse."),
    ("wifi_wpa_supplicant_log_audit", "read",
     "Audit wpa_supplicant logs for control-plane anomalies. "
     "Pure parse + LLM."),
    ("wifi_arp_health_audit", "read",
     "ARP-rate + IP-MAC-consistency health audit. Pure scapy."),
    # === Phase 2.3.D polymorphic (5) ===
    ("poly_rssi_kriging_3d_map", "read",
     "Polymorphic RSSI kriging. Produces a 2D grid of estimated "
     "RSSI values using inverse-distance interpolation. Pure math."),
    ("poly_signal_anomaly_isolation_forest", "read",
     "Polymorphic isolation-forest-style anomaly scorer. Returns a "
     "list of (sample, score) pairs. Heuristic, not trained."),
    ("poly_passive_client_association_correlation", "read",
     "Polymorphic client-association correlation. Builds a graph of "
     "client-AP co-occurrence. Pure math + LLM."),
    ("poly_ssid_broadcast_grammar_ngram", "read",
     "Polymorphic SSID-broadcast n-gram grammar. Generates plausible "
     "SSID candidates from an observed alphabet. Heuristic."),
    ("poly_vendor_specific_ie_parser", "read",
     "Polymorphic vendor-specific IE parser. Handles WFA, Microsoft, "
     "Apple, and Cisco OUI ranges. Pure parse + LLM."),
    # === Phase 2.3.D target-adaptive (5) ===
    ("adapt_recon_wpa_version_picker", "read",
     "Pick the best recon primitive based on the AP's advertised "
     "WPA version. Heuristic, no train."),
    ("adapt_recon_vendor_picker", "read",
     "Pick the best recon primitive based on the AP's OUI vendor. "
     "Heuristic, no train."),
    ("adapt_recon_client_density_picker", "read",
     "Pick the best recon primitive based on client density. "
     "Heuristic, no train."),
    ("adapt_recon_channel_congestion_picker", "read",
     "Pick the best recon primitive based on channel utilization. "
     "Heuristic, no train."),
    ("adapt_recon_6e_presence_picker", "read",
     "Pick the best recon primitive based on whether 6E is in "
     "range. Heuristic, no train."),
]


# ---------------------------------------------------------------------------
# BLE attack (creative, modern BLE 5.x / 5.4 / mesh / auracast)
# ---------------------------------------------------------------------------
BLE_V2_METHODS: List[Tuple[str, str, str]] = [
    # === BLE 5.x advertising extensions ===
    ("ble5_ext_adv_chain_fuzz", "intrusive",
     "Fuzz chained extended-advertising PDUs. Real scapy + bleak."),
    ("ble5_aux_scan_req_fuzz", "intrusive",
     "Fuzz AUX_SCAN_REQ / AUX_CONNECT_REQ for parsing bugs. "
     "Real scapy + bleak."),
    ("ble5_periodic_adv_sync_audit", "read",
     "Audit a target's periodic-advertising sync transfer. "
     "Real bleak + LLM."),
    ("ble5_coded_phy_audit", "read",
     "Audit a target's use of Coded PHY (S2/S8). Real bleak + LLM."),
    ("ble5_2m_phy_audit", "read",
     "Audit a target's use of 2M PHY. Real bleak + LLM."),
    # === Privacy / random address rotation ===
    ("ble5_resolvable_address_replay", "intrusive",
     "Replay a captured Resolvable Private Address (RPA) "
     "during the identity-resolving window. Real bleak."),
    ("ble5_resolvable_address_predict", "read",
     "Predict the next RPA from a sequence using the IRK. "
     "Pure math + LLM (read-only)."),
    ("ble5_non_resolvable_address_audit", "read",
     "Detect non-RPA usage (privacy gap). Pure bleak + LLM."),
    # === Pairing / legacy / LESC ===
    ("ble_lesc_passkey_replay", "intrusive",
     "Replay a captured LESC passkey entry during a window. "
     "Real bleak."),
    ("ble_lesc_numeric_compare_audit", "read",
     "Audit a target's LESC numeric-compare implementation. "
     "Real bleak + LLM."),
    ("ble_legacy_pairing_audit", "read",
     "Detect legacy pairing in use (no LESC). Real bleak + LLM."),
    ("ble_just_works_audit", "read",
     "Detect Just-Works pairing in use (MITM trivially possible). "
     "Real bleak + LLM."),
    # === GATT abuse ===
    ("gatt_long_write_fuzz", "intrusive",
     "Long GATT write to test buffer-overflow in target. "
     "Real bleak."),
    ("gatt_prepare_write_abuse", "intrusive",
     "Abuse GATT Prepare-Write queue to test queue-exhaustion "
     "vulnerability. Real bleak."),
    ("gatt_notification_flood", "intrusive",
     "Flood GATT notifications/indications to test DoS. "
     "Real bleak."),
    ("gatt_subscription_audit", "read",
     "Map a target's GATT subscription surface. Real bleak + LLM."),
    ("gatt_descriptor_audit", "read",
     "Audit GATT descriptor accessibility. Real bleak + LLM."),
    # === ATT MTU abuse ===
    ("att_mtu_oversize", "intrusive",
     "Negotiate max MTU (517) and test overflow. Real bleak."),
    ("att_mtu_negotiation_audit", "read",
     "Audit a target's MTU negotiation behavior. Real bleak + LLM."),
    # === Connection parameter abuse ===
    ("ble_conn_param_supervision_fuzz", "intrusive",
     "Fuzz connection-update with extreme supervision-timeout. "
     "Real bleak."),
    ("ble_conn_param_interval_fuzz", "intrusive",
     "Fuzz connection-update with extreme connection-interval. "
     "Real bleak."),
    ("ble_conn_param_latency_fuzz", "intrusive",
     "Fuzz connection-update with extreme slave-latency. "
     "Real bleak."),
    ("ble_channel_map_fuzz", "intrusive",
     "Send a Channel-Map-Request to force a channel-hop "
     "vulnerability test. Real bleak."),
    ("ble_encryption_pause_resume_fuzz", "intrusive",
     "Force encryption pause-resume race. Real bleak."),
    # === Privacy / tracking ===
    ("ble5_adv_addr_rotation_audit", "read",
     "Audit a target's address-rotation frequency. Real bleak + LLM."),
    ("ble5_resolved_irk_audit", "read",
     "Capture IRK exchange (if any) and audit. Real bleak + LLM."),
    # === Privacy extension quirks ===
    ("ble_mesh_proxy_pdus_fuzz", "intrusive",
     "Fuzz BLE mesh Proxy PDUs. Real scapy + bleak."),
    ("ble_mesh_friend_offer_fuzz", "intrusive",
     "Fuzz mesh Friend-Offer. Real scapy + bleak."),
    ("ble_mesh_heartbeat_fuzz", "intrusive",
     "Fuzz mesh Heartbeat. Real scapy + bleak."),
    # === Audio / Auracast / LC3 ===
    ("ble_audio_bis_audit", "read",
     "Detect Auracast BIS advertisements. Real bleak + LLM."),
    ("ble_audio_cis_audit", "read",
     "Detect Connected-Isochronous-Stream (CIS) advertisements. "
     "Real bleak + LLM."),
    ("ble_audio_adv_fuzz", "intrusive",
     "Fuzz LE Audio broadcast / extended advertisements. "
     "Real scapy + bleak."),
    # === HID abuse ===
    ("ble_hid_inject_fuzz", "intrusive",
     "Fuzz HID reports into a paired host. Real bleak, lab only."),
    ("ble_hid_descriptor_audit", "read",
     "Audit HID descriptor for insecure report maps. Real bleak + LLM."),
    # === Authentication / OOB ===
    ("ble_oob_nfc_pair_audit", "read",
     "Detect OOB-NFC pairing advertised. Real bleak + LLM."),
    ("ble_oob_ble_pair_audit", "read",
     "Detect OOB-over-BLE pairing advertised. Real bleak + LLM."),
    # === Medical / sensor ===
    ("ble_gatt_medical_sink_audit", "read",
     "Audit medical-device GATT services for unauthenticated "
     "writes to vital-signs. Real bleak + LLM."),
    ("ble_sensor_notification_audit", "read",
     "Audit a target's sensor-notification permissions. "
     "Real bleak + LLM."),
    # === Tracking ===
    ("ble_tile_airtag_audit", "read",
     "Detect Tile / AirTag / SmartTag advertisements. "
     "Real bleak + LLM."),
    ("ble_beacon_eddystone_audit", "read",
     "Parse Eddystone beacon. Real bleak + LLM."),
    ("ble_beacon_ibeacon_audit", "read",
     "Parse iBeacon advertisements. Real bleak + LLM."),
    # === Long-range / Coded PHY ===
    ("ble_coded_phy_adv_audit", "read",
     "Detect Coded-PHY advertisements (long-range). "
     "Real bleak + LLM."),
    # === HCI / link-layer ===
    ("ble_hci_command_fuzz", "intrusive",
     "Fuzz HCI commands via raw L2CAP socket. Real scapy, lab only."),
    ("ble_l2cap_cos_fuzz", "intrusive",
     "Fuzz L2CAP CoC. Real scapy, lab only."),
    ("ble_l2cap_ecred_fuzz", "intrusive",
     "Fuzz L2CAP ECRED. Real scapy, lab only."),
    # === Direction-finding ===
    ("ble_cte_audit", "read",
     "Detect Constant Tone Extension advertisements. Real bleak."),
    ("ble_aoa_aod_audit", "read",
     "Detect AoA/AoD advertisements. Real bleak + LLM."),
    # === Exotic / vendor ===
    ("ble_vendor_qualcomm_audit", "read",
     "Audit Qualcomm-specific GATT services. Real bleak + LLM."),
    ("ble_vendor_apple_audit", "read",
     "Audit Apple Continuity / FindMy / NearbyAction. "
     "Real bleak + LLM."),
    ("ble_vendor_microsoft_audit", "read",
     "Audit Microsoft SwiftPair. Real bleak + LLM."),
    ("ble_vendor_google_audit", "read",
     "Audit Google Nearby / Fast Pair. Real bleak + LLM."),
    # === Battery / power ===
    ("ble_battery_service_audit", "read",
     "Parse Battery Service (0x180F). Real bleak + LLM."),
    ("ble_power_consumption_audit", "read",
     "Estimate power-consumption from connection parameters. "
     "Pure math + LLM."),
    # === Phase 2.3.E polymorphic (5) ===
    ("poly_gatt_payload_template", "intrusive",
     "Polymorphic GATT payload grammar. Produces 8 plausible write "
     "payloads of length 4-64. Pure Python heuristic."),
    ("poly_hid_injection_sequence_ai", "intrusive",
     "Polymorphic HID keyboard-injection sequence. Produces 8 "
     "8-byte HID report frames. Pure Python heuristic."),
    ("poly_ota_firmware_chunk_drift", "intrusive",
     "Polymorphic OTA firmware chunk grammar. Produces n_chunks of "
     "chunk_size bytes. Pure Python heuristic."),
    ("poly_pairing_payload_grammar", "intrusive",
     "Polymorphic pairing-passkey grammar. Produces 8 6-digit "
     "passkey candidates. Pure Python heuristic."),
    ("poly_le_audio_bap_param_drift", "intrusive",
     "Polymorphic LE Audio BAP parameter grammar. Produces 8 "
     "BAP QoS variants. Pure Python heuristic."),
    # === Phase 2.3.E target-adaptive (5) ===
    ("adapt_attack_pairing_method_picker", "read",
     "Pick the best attack primitive based on the pairing method. "
     "Heuristic, no train."),
    ("adapt_attack_os_target_picker", "read",
     "Pick the best attack primitive based on the target's OS. "
     "Heuristic, no train."),
    ("adapt_attack_ble_version_picker", "read",
     "Pick the best attack primitive based on the BLE version. "
     "Heuristic, no train."),
    ("adapt_attack_service_uuid_picker", "read",
     "Pick the best attack primitive based on the service UUID. "
     "Heuristic, no train."),
    ("adapt_attack_capability_picker", "read",
     "Pick the best attack primitive based on the target's "
     "capabilities. Heuristic, no train."),
    # === Phase 2.3.E orchestrator (1) ===
    ("ble_attack_orchestrator", "read",
     "Top-level orchestrator that picks the best BLE attack "
     "primitive for the current target. Returns the picker list."),
    # === Phase 2.3.E GATT (5) ===
    ("gatt_descriptor_write_priv_escalation", "intrusive",
     "GATT descriptor write to escalate write permission. "
     "Find CCCD descriptors and try privileged write. Real bleak."),
    ("gatt_long_read_oom_trigger", "intrusive",
     "GATT long read with extreme length to trigger OOM. Real bleak."),
    ("gatt_indication_flood", "intrusive",
     "Flood GATT indications to exhaust server buffer. Real bleak."),
    ("gatt_write_without_response_race", "intrusive",
     "Race GATT write-without-response to corrupt server state. "
     "Real bleak."),
    ("gatt_subscribed_notification_flood", "intrusive",
     "Subscribe to many GATT chars and flood notifications. "
     "Real bleak."),
    # === Phase 2.3.E pairing / bonding (5) ===
    ("legacy_pairing_tkip_recovery", "intrusive",
     "Brute-force legacy pairing TKIP STK. Lab only. Real bleak."),
    ("just_works_mitm_passkey_substitution", "intrusive",
     "MITM between Just-Works peers; substitute passkey. Real "
     "bleak + active MITM."),
    ("oob_data_replay_capture", "intrusive",
     "Capture OOB data (NFC, etc.) and replay during pairing. "
     "Real bleak + lab NFC reader."),
    ("cross_transport_irk_collision", "intrusive",
     "Cross-Transport Key Derivation IRK collision. Real bleak."),
    ("repairing_passkey_predict", "intrusive",
     "Predict passkey from re-pairing attempts. Real bleak."),
    # === Phase 2.3.E L2CAP (5) ===
    ("l2cap_lecb_channel_dos", "intrusive",
     "Flood L2CAP LECB channels to deny service. Real bleak."),
    ("l2cap_credit_based_fuzz", "intrusive",
     "Fuzz L2CAP credit-based flow control. Real bleak."),
    ("l2cap_enhanced_retransmission_fuzz", "intrusive",
     "Fuzz L2CAP ERTM retransmission. Real bleak."),
    ("l2cap_le_flow_control_psm_bypass", "intrusive",
     "Bypass PSM check via LE flow control. Real bleak."),
    ("connection_interval_overflow", "intrusive",
     "Send connection-param update with overflowing interval. "
     "Real bleak."),
    # === Phase 2.3.E LE Audio (5) ===
    ("iso_channel_cis_dos", "intrusive",
     "Flood Connected-Isochronous-Stream setup. Real bleak."),
    ("biginfo_sdu_interval_misconfig", "intrusive",
     "Misconfigure BIS SDU interval. Real bleak."),
    ("lc3_codec_param_fuzz", "intrusive",
     "Fuzz LC3 codec parameters. Real bleak."),
    ("bap_unicast_server_discover_flood", "intrusive",
     "Flood BAP unicast-server discovery. Real bleak."),
    ("pawr_response_suboverflow", "intrusive",
     "Overflow PAwR response slot. Real bleak."),
    # === Phase 2.3.E Mesh (5) ===
    ("mesh_provisioning_capture_replay", "intrusive",
     "Capture + replay mesh provisioning PDU. Real bleak."),
    ("mesh_friend_queue_overflow", "intrusive",
     "Overflow mesh Friend queue. Real bleak."),
    ("mesh_proxy_solicitation_flood", "intrusive",
     "Flood mesh Proxy Solicitation. Real bleak."),
    ("mesh_low_power_friend_dos", "intrusive",
     "Deny Low-Power node's Friend. Real bleak."),
    ("mesh_subnet_bridge_substitution", "intrusive",
     "Substitute mesh subnet bridge. Real bleak."),
]


# ---------------------------------------------------------------------------
# BLE recon (passive / listen-only)
# ---------------------------------------------------------------------------
BLE_RECON_V2_METHODS: List[Tuple[str, str, str]] = [
    # === Discovery / classification ===
    ("ble_appearance_classify", "read",
     "Classify devices by Appearance value. Real bleak + LLM."),
    ("ble_company_id_audit", "read",
     "Audit device-class by Company ID. Real bleak + LLM."),
    ("ble_service_uuid_distribution_audit", "read",
     "Classify devices by service-UUID distribution. "
     "Real bleak + LLM."),
    ("ble_local_name_vendor_map", "read",
     "Map local-name strings to known vendors. Real bleak + LLM."),
    ("ble_classic_br_edr_passive_scan", "read",
     "Detect BR/EDR advertisements from passive scan. "
     "Real bleak + LLM."),
    # === Privacy / address analysis ===
    ("ble_rpa_resolve_passive", "read",
     "Resolve RPAs against a known IRK (lab only, operator's "
     "own IRK). Pure math + bleak."),
    ("ble_address_age_estimate", "read",
     "Estimate how long a target has been advertising. "
     "Pure math + bleak."),
    ("ble_address_churn_rate_audit", "read",
     "Measure address-rotation rate. Real bleak + LLM."),
    # === Manufacturer fingerprinting ===
    ("ble_mfr_fingerprint_ios", "read",
     "Fingerprint iOS device generation. Real bleak + LLM."),
    ("ble_mfr_fpixel_android", "read",
     "Fingerprint Android device generation. Real bleak + LLM."),
    ("ble_mfr_fingerprint_smartwatch", "read",
     "Fingerprint smartwatches. Real bleak + LLM."),
    # === Service surface mapping ===
    ("ble_health_thermometer_audit", "read",
     "Parse Health Thermometer service. Real bleak + LLM."),
    ("ble_heart_rate_audit", "read",
     "Parse Heart Rate service. Real bleak + LLM."),
    ("ble_environmental_sensor_audit", "read",
     "Parse Environmental-Sensing service. Real bleak + LLM."),
    ("ble_pulse_oximeter_audit", "read",
     "Parse Pulse-Oximeter service. Real bleak + LLM."),
    ("ble_glucose_meter_audit", "read",
     "Parse Glucose-Meter service. Real bleak + LLM."),
    ("ble_blood_pressure_audit", "read",
     "Parse Blood-Pressure service. Real bleak + LLM."),
    ("ble_running_speed_cadence_audit", "read",
     "Parse Running-Speed-and-Cadence. Real bleak + LLM."),
    ("ble_cycling_power_audit", "read",
     "Parse Cycling-Power. Real bleak + LLM."),
    # === Privacy / fingerprintable data ===
    ("ble_passive_leak_audit", "read",
     "Detect a target's information-leak (e.g. battery, name). "
     "Real bleak + LLM."),
    ("ble_passive_uuid_audit", "read",
     "Detect custom (non-SIG) UUIDs that may leak app identity. "
     "Real bleak + LLM."),
    # === Coexistence ===
    ("ble_wifi_coexistence_passive", "read",
     "Detect coexistence with WiFi (channel-set overlap). "
     "Pure parse + LLM."),
    ("ble_802154_coexistence_passive", "read",
     "Detect 802.15.4 coexistence (ZigBee / Thread). "
     "Pure parse + LLM."),
    # === Tracking resistance ===
    ("ble_mac_randomization_efficacy_audit", "read",
     "Audit a target's MAC-randomization efficacy over time. "
     "Real bleak + LLM."),
    ("ble_location_privacy_audit", "read",
     "Composite privacy audit. Pure LLM + bleak."),
    # === Identity / social ===
    ("ble_user_identity_leak_audit", "read",
     "Detect user-identity leaks in ADV (Fitbit / Apple "
     "NearbyAction). Real bleak + LLM."),
    ("ble_owner_name_audit", "read",
     "Detect owner-name leaks. Real bleak + LLM."),
    # === Mesh / Auracast ===
    ("ble_mesh_proxy_discover", "read",
     "Discover BLE mesh Proxy nodes. Real bleak + LLM."),
    ("ble_audio_bis_discover", "read",
     "Discover Auracast BIS broadcasters. Real bleak + LLM."),
    # === RF / packet shape ===
    ("ble_packet_shape_classify", "read",
     "Classify a target by packet-shape statistics. "
     "Pure parse + LLM."),
    ("ble_rssi_geometry_audit", "read",
     "Use multiple receivers to triangulate. Pure math + LLM."),
    ("ble_advertising_interval_audit", "read",
     "Map target's advertising interval. Real bleak + LLM."),
    # === Vendor-specific discovery ===
    ("ble_apple_findmy_audit", "read",
     "Detect Apple FindMy advertisements. Real bleak + LLM."),
    ("ble_google_fast_pair_audit", "read",
     "Detect Google Fast Pair advertisements. Real bleak + LLM."),
    ("ble_microsoft_swift_pair_audit", "read",
     "Detect Microsoft Swift Pair advertisements. "
     "Real bleak + LLM."),
    ("ble_samsung_smarttag_audit", "read",
     "Detect Samsung SmartTag advertisements. Real bleak + LLM."),
    ("ble_tile_audit", "read",
     "Detect Tile advertisements. Real bleak + LLM."),
    # === Outdoor / industrial ===
    ("ble_industrial_iio_audit", "read",
     "Detect Industrial I/O sensor advertisements. "
     "Real bleak + LLM."),
    ("ble_asset_tracking_tag_audit", "read",
     "Detect asset-tracking tag advertisements. Real bleak + LLM."),
    ("ble_beacon_industrial_wirelesshart_audit", "read",
     "Detect WirelessHART proxy advertisements. Real bleak + LLM."),
    # === Exotic / experimental ===
    ("ble_passive_scanning_audit", "read",
     "Audit the operator's own passive-scanning coverage. "
     "Real bleak + LLM."),
    ("ble_passive_security_posture_audit", "read",
     "Composite security-posture audit on captured ADV. "
     "Real bleak + LLM."),
    # === Health-data inference ===
    ("ble_health_data_correlate", "read",
     "Correlate health-thermometer / heart-rate / SpO2 across "
     "multiple receivers. Real bleak + LLM."),
    ("ble_presence_classify", "read",
     "Classify a target's presence pattern (work / sleep / "
     "exercise). Real bleak + LLM."),
    ("ble_movement_pattern_classify", "read",
     "Classify a target's movement pattern. Real bleak + LLM."),
    # === Time / state ===
    ("ble_workday_audit", "read",
     "Audit a target's work / rest patterns over time. "
     "Real bleak + LLM."),
    ("ble_proximity_log_audit", "read",
     "Maintain a proximity log over time. Real bleak + LLM."),
    ("ble_dwell_time_audit", "read",
     "Compute dwell time at known locations. Real bleak + LLM."),
    # === Environment ===
    ("ble_environmental_sensor_correlate", "read",
     "Correlate multiple environmental sensors to map a "
     "building. Real bleak + LLM."),
    ("ble_indoor_positioning_audit", "read",
     "Use BLE beacons for indoor positioning. Real bleak + LLM."),
    # === Lab-only / opt-in ===
    ("ble_keyboard_inject_audit", "read",
     "Audit whether a paired keyboard accepts injected reports. "
     "Lab only, real bleak."),
    ("ble_mouse_inject_audit", "read",
     "Audit whether a paired mouse accepts injected reports. "
     "Lab only, real bleak."),
    # === Phase 2.3.E polymorphic (5) ===
    ("poly_ble_advertising_payload_normalize", "read",
     "Polymorphic advertising-payload normalizer. Canonical hex "
     "form. Pure Python heuristic."),
    ("poly_ble_rpa_seed_timing_profiler", "read",
     "Polymorphic RPA-seed timing profiler. Pure-Python heuristic."),
    ("poly_ble_gatt_characteristic_hash", "read",
     "Polymorphic GATT-characteristic hash. SHA-256 prefix."),
    ("poly_ble_mesh_proxy_filter_parser", "read",
     "Polymorphic mesh-proxy filter parser. Pure-Python heuristic."),
    ("poly_ble_mac_rotation_fingerprint_grammar", "read",
     "Polymorphic MAC-rotation fingerprint grammar. SHA-256 prefix."),
    # === Phase 2.3.E target-adaptive (5) ===
    ("adapt_recon_target_os_picker", "read",
     "Pick the best recon primitive based on target's OS. "
     "Heuristic, no train."),
    ("adapt_recon_target_role_picker", "read",
     "Pick the best recon primitive based on target's role "
     "(tracker, watch, etc.). Heuristic, no train."),
    ("adapt_recon_target_service_picker", "read",
     "Pick the best recon primitive based on observed service "
     "UUIDs. Heuristic, no train."),
    ("adapt_recon_target_version_picker", "read",
     "Pick the best recon primitive based on BLE version. "
     "Heuristic, no train."),
    ("adapt_recon_target_capability_picker", "read",
     "Pick the best recon primitive based on target's "
     "capabilities. Heuristic, no train."),
    # === Phase 2.3.E mesh supplementary (3) ===
    ("ble_mesh_friend_node_graph", "read",
     "Build a mesh Friend / Low-Power node graph from passive "
     "advertisements. Pure Python heuristic."),
    ("ble_mesh_subnet_collision", "read",
     "Detect mesh subnet collisions. Pure Python heuristic."),
    ("ble_mesh_iv_update_state_track", "read",
     "Track mesh IV-update state. Pure Python heuristic."),
]


# ---------------------------------------------------------------------------
# OSINT — 50+ creative modules
# ---------------------------------------------------------------------------
OSINT_V2_METHODS: List[Tuple[str, str, str]] = [
    # === People / social ===
    ("osint_full_name_derivation", "read",
     "Derive probable full name from a username / handle. "
     "Pure LLM + breach data."),
    ("osint_avatar_reuse_search", "read",
     "Search for an avatar image reused across the web. "
     "Real Yandex / Google reverse-image-search URL construction."),
    ("osint_email_breach_correlate", "read",
     "Correlate an email against known breach corpora. "
     "Real HIBP-style API call, never faked."),
    ("osint_username_site_catalogue", "read",
     "Test a username against a catalogue of 200+ sites. "
     "Real HTTP HEAD / GET."),
    ("osint_phone_carrier_lookup", "read",
     "Look up the carrier / line-type of a phone number. "
     "Real API call."),
    ("osint_social_graph_correlate", "read",
     "Correlate follows / friends across networks. "
     "Real HTTP + parse."),
    # === Domain / DNS ===
    ("osint_subdomain_brute", "read",
     "Subdomain brute via real DNS queries."),
    ("osint_subdomain_ct_log", "read",
     "Subdomain enumeration via crt.sh / Censys. Real HTTP."),
    ("osint_whois_history_audit", "read",
     "Audit WHOIS history. Real RDAP / WHOIS HTTP."),
    ("osint_dns_history_audit", "read",
     "Audit DNS history (SecurityTrails / passive-total). "
     "Real HTTP."),
    ("osint_asn_map", "read",
     "Map ASNs. Real BGP / whois."),
    ("osint_certificate_transparency_audit", "read",
     "Audit CT logs for subdomains. Real HTTP crt.sh."),
    ("osint_email_dmarc_audit", "read",
     "Audit DMARC / SPF / DKIM for a domain. Real DNS query."),
    ("osint_mx_history_audit", "read",
     "Audit MX-history. Real DNS / passive-total."),
    # === Network / IP ===
    ("osint_ip_geolocation", "read",
     "IP geolocation. Real API call."),
    ("osint_ip_asn_audit", "read",
     "ASN-of-IP. Real whois / Team Cymru DNS."),
    ("osint_ip_reputation_audit", "read",
     "IP-reputation via DNSBL. Real DNS."),
    ("osint_ip_port_audit", "read",
     "Audit IP's open ports (Shodan / Censys / FOFA). "
     "Real HTTP."),
    ("osint_ip_certificate_audit", "read",
     "Audit certificates an IP has served. Real HTTP crt.sh."),
    # === Web / API ===
    ("osint_url_google_dork", "read",
     "Construct Google-dork URLs for a target. Pure LLM + URL."),
    ("osint_github_leak_search", "read",
     "Search GitHub for secrets / keys. Real GitHub code-search."),
    ("osint_pastebin_search", "read",
     "Search public paste sites. Real HTTP."),
    ("osint_robots_txt_audit", "read",
     "Parse robots.txt. Real HTTP."),
    ("osint_sitemap_audit", "read",
     "Parse sitemap.xml. Real HTTP."),
    ("osint_security_txt_audit", "read",
     "Parse security.txt. Real HTTP."),
    ("osint_ads_txt_audit", "read",
     "Parse ads.txt. Real HTTP."),
    # === Leaks / breach ===
    ("osint_breach_qa_audit", "read",
     "Audit a target's Q&A presence (StackOverflow / Quora). "
     "Real HTTP."),
    ("osint_reddit_audit", "read",
     "Audit Reddit. Real HTTP."),
    ("osint_twitter_audit", "read",
     "Audit Twitter / X. Real HTTP."),
    ("osint_linkedin_audit", "read",
     "Audit LinkedIn. Real HTTP."),
    ("osint_tiktok_audit", "read",
     "Audit TikTok. Real HTTP."),
    ("osint_youtube_audit", "read",
     "Audit YouTube. Real HTTP."),
    ("osint_telegram_audit", "read",
     "Audit Telegram channels. Real HTTP."),
    ("osint_discord_audit", "read",
     "Audit Discord public servers. Real HTTP."),
    # === Geolocation ===
    ("osint_geo_image_metadata", "read",
     "Pull EXIF GPS from a posted image. Real exiftool / PIL."),
    ("osint_geo_landmark_audit", "read",
     "Audit a posted image for landmark hints (LLM vision)."),
    ("osint_geo_sun_position_audit", "read",
     "Compute sun-position from a posted image to estimate "
     "location. Real ephem / sun-position math."),
    ("osint_geo_shadow_length_audit", "read",
     "Estimate latitude from shadow length. Real math."),
    # === Email ===
    ("osint_email_permutator", "read",
     "Permute an email (first.last, fmlast, etc.). Pure LLM."),
    ("osint_email_mx_audit", "read",
     "Audit MX records. Real DNS."),
    ("osint_email_spf_audit", "read",
     "Audit SPF. Real DNS."),
    ("osint_email_dkim_audit", "read",
     "Audit DKIM. Real DNS."),
    ("osint_email_dmarc_policy_audit", "read",
     "Audit DMARC policy in detail (p=, rua, ruf, pct). Real DNS."),
    # === Cryptocurrency / financial ===
    ("osint_btc_address_audit", "read",
     "Audit a BTC address on public explorers. Real HTTP."),
    ("osint_eth_address_audit", "read",
     "Audit an ETH address on Etherscan. Real HTTP."),
    ("osint_corp_filings_audit", "read",
     "Audit corporate filings (SEC / Companies House). "
     "Real HTTP."),
    # === Phone ===
    ("osint_phone_whatsapp_audit", "read",
     "Audit WhatsApp presence. Real HTTP."),
    ("osint_phone_signal_audit", "read",
     "Audit Signal presence. Real HTTP."),
    ("osint_phone_telegram_audit", "read",
     "Audit Telegram presence. Real HTTP."),
    # === Image / OCR ===
    ("osint_image_exif_full", "read",
     "Parse full EXIF. Real exiftool."),
    ("osint_image_ocr", "read",
     "OCR a posted image. Real Tesseract."),
    ("osint_image_steganography_detect", "read",
     "Detect steganography in a posted image. Real stegdetect."),
    # === Data broker ===
    ("osint_data_broker_check", "read",
     "Check whether a person is listed on data brokers. "
     "Real HTTP."),
    # === Document ===
    ("osint_pdf_metadata_audit", "read",
     "Audit PDF metadata. Real exiftool."),
    ("osint_doc_metadata_audit", "read",
     "Audit Office-doc metadata. Real exiftool."),
    # === Phase 2.3.C — Polish OSINT (40 new, free public APIs only) ===
    # --- Polish registries (CEIDG, KRS, GUS BIR1, GUS TERYT, KNF) ---
    ("polish_ceidg_search_nip", "read",
     "Search CEIDG (Centralna Ewidencja i Informacja o Działalności "
     "Gospodarczej) by NIP. Real HTTP to datastore.ceidg.gov.pl."),
    ("polish_ceidg_search_regon", "read",
     "Search CEIDG by REGON. Real HTTP."),
    ("polish_ceidg_search_name", "read",
     "Search CEIDG by company name. Real HTTP."),
    ("polish_ceidg_search_address", "read",
     "Search CEIDG by address. Real HTTP."),
    ("polish_krs_search_krs_number", "read",
     "Search KRS (Krajowy Rejestr Sądowy) by KRS number. Real "
     "HTTP to ekrs.ms.gov.pl."),
    ("polish_krs_search_name", "read",
     "Search KRS by company name. Real HTTP."),
    ("polish_krs_search_representatives", "read",
     "Search KRS representatives (zarząd, prokurenci). Real HTTP."),
    ("polish_krs_search_shareholders", "read",
     "Search KRS shareholders (wspólnicy). Real HTTP."),
    ("polish_krs_search_address", "read",
     "Search KRS by registered address. Real HTTP."),
    ("polish_gus_bir1_regon", "read",
     "GUS BIR1 REGON lookup. Real HTTP to api.stat.gov.pl; test "
     "key from GUS_BIR1_KEY env var."),
    ("polish_gus_bir1_nip", "read",
     "GUS BIR1 NIP lookup. Real HTTP."),
    ("polish_gus_bir1_pkd", "read",
     "GUS BIR1 PKD (Polska Klasyfikacja Działalności) lookup. "
     "Real HTTP."),
    ("polish_gus_teryt_voivodeship", "read",
     "GUS TERYT voivodeship (województwo) lookup. Real HTTP."),
    ("polish_gus_teryt_commune", "read",
     "GUS TERYT commune (gmina) lookup. Real HTTP."),
    ("polish_knf_search", "read",
     "Search KNF (Komisja Nadzoru Finansowego) registry for "
     "financial entities. Real HTTP."),
    # --- Allegro REST (free OAuth client_credentials) ---
    ("allegro_auth_client_credentials", "read",
     "Authenticate to Allegro REST via client_credentials. Real "
     "HTTP POST to allegro.pl/auth/oauth/token."),
    ("allegro_search_offers", "read",
     "Search Allegro offers by query. Real HTTP GET."),
    ("allegro_search_categories", "read",
     "Search Allegro category tree. Real HTTP GET."),
    ("allegro_user_offers", "read",
     "List a user's Allegro offers. Real HTTP GET."),
    ("allegro_user_categories", "read",
     "List a user's Allegro subscribed categories. Real HTTP GET."),
    # --- Polish social / people search (10) ---
    ("polish_linkedin_public_profile_enrich", "read",
     "Enrich a Polish LinkedIn public profile (name, role, "
     "employer). Real HTTP; never inlines creds."),
    ("polish_facebook_public_page_enrich", "read",
     "Enrich a Polish Facebook public page. Real HTTP."),
    ("polish_goldenline_search", "read",
     "Search Goldenline (Polish business social network) by "
     "name/email. Real HTTP."),
    ("polish_wykop_user_search", "read",
     "Search Wykop (Polish social/discussion platform) by "
     "username. Real HTTP."),
    ("polish_numerology_name_match", "read",
     "Match a Polish name against numerology heuristics. Pure "
     "deterministic math; never fabricates a match."),
    ("polish_phone_prefix_carrier", "read",
     "Resolve a Polish phone-number prefix to carrier/operator. "
     "Deterministic lookup table (no API key)."),
    ("polish_address_postal_code_lookup", "read",
     "Look up Polish postal-code (kod pocztowy) → locality. "
     "Real HTTP to public Poczta Polska resource."),
    ("polish_pesel_validate_format", "read",
     "Validate a PESEL (Polish national id) checksum + extract "
     "birth date. NEVER looks up an actual PESEL — GDPR "
     "restricted; local checksum only."),
    ("polish_nip_validate_format", "read",
     "Validate a NIP (Polish tax id) checksum. Local math only."),
    ("polish_regon_validate_format", "read",
     "Validate a REGON checksum. Local math only."),
    # --- Polymorphic OSINT (5) ---
    ("polish_osint_poly_email_drift", "read",
     "Polymorphic email-format drift over Polish name lists. "
     "Pure LLM + template grammar."),
    ("polish_osint_poly_username_platform_drift", "read",
     "Polymorphic username drift across Polish platforms. Pure "
     "LLM + grammar."),
    ("polish_osint_poly_phone_format_drift", "read",
     "Polymorphic phone-format drift (Polish national/intl/"
     "E.164). Deterministic."),
    ("polish_osint_poly_handle_normalizer", "read",
     "Polymorphic handle normaliser (Unicode, ZWJ, dot-removal). "
     "Deterministic."),
    ("polish_osint_poly_subdomain_wordlist_drift", "read",
     "Polymorphic subdomain wordlist drift over a Polish domain "
     "(miasta, regiony, branże). Deterministic."),
    # --- Target-adaptive OSINT (5) ---
    ("polish_osint_adapt_target_tier_classifier", "read",
     "Target-adaptive: classify a Polish target by tier (osoba "
     "fizyczna / firma / spółka / instytucja publiczna). Heuristic "
     "+ LLM; never fabricated."),
    ("polish_osint_adapt_osint_playbook_picker", "read",
     "Target-adaptive: pick the best OSINT playbook for a "
     "Polish target. LLM-driven; deterministic fallback."),
    ("polish_osint_adapt_dork_query_picker", "read",
     "Target-adaptive: pick Google-dork queries for a Polish "
     "target. LLM-driven; deterministic fallback."),
    ("polish_osint_adapt_breach_window_filter", "read",
     "Target-adaptive: filter breach hits to a Polish target by "
     "time window. Deterministic."),
    ("polish_osint_adapt_dns_record_priority", "read",
     "Target-adaptive: prioritise DNS records for a Polish target. "
     "Deterministic."),
]


# ---------------------------------------------------------------------------
# Post-exploit — 50+ creative modules
# ---------------------------------------------------------------------------
POST_EXPLOIT_V2_METHODS: List[Tuple[str, str, str]] = [
    # === Privilege escalation ===
    ("post_sudo_capability_audit", "read",
     "Audit sudoers / capabilities. Real subprocess."),
    ("post_setuid_setgid_audit", "read",
     "Audit setuid / setgid binaries. Real subprocess."),
    ("post_suid_path_hijack_audit", "read",
     "Audit setuid PATH-hijack surface. Real subprocess + LLM."),
    ("post_docker_socket_audit", "read",
     "Audit whether a user is in the docker group. Real subprocess."),
    ("post_lxd_group_audit", "read",
     "Audit whether a user is in the lxd group. Real subprocess."),
    ("post_docker_escape_audit", "read",
     "Audit docker-escape surface. Real subprocess + LLM."),
    ("post_kubernetes_pod_audit", "read",
     "Audit a Kubernetes pod's permissions. Real subprocess + LLM."),
    # === Credential harvest ===
    ("post_ssh_key_audit", "read",
     "Audit ~/.ssh. Real subprocess."),
    ("post_aws_creds_audit", "read",
     "Audit AWS credentials. Real subprocess + LLM."),
    ("post_gcp_creds_audit", "read",
     "Audit GCP credentials. Real subprocess + LLM."),
    ("post_azure_creds_audit", "read",
     "Audit Azure credentials. Real subprocess + LLM."),
    ("post_kubeconfig_audit", "read",
     "Audit kubeconfig. Real subprocess."),
    ("post_browser_creds_audit", "read",
     "Audit browser credential stores (lab only). "
     "Real subprocess + LLM."),
    ("post_hashdump_audit", "read",
     "Audit local-hash files (no cracking). Real subprocess."),
    ("post_wifi_password_audit", "read",
     "Audit stored WiFi passwords. Real subprocess."),
    # === Lateral movement ===
    ("post_smb_share_enum", "read",
     "Enumerate SMB shares. Real subprocess (smbclient / rpc)."),
    ("post_rdp_active_sessions", "read",
     "Audit active RDP sessions. Real subprocess (qwinsta)."),
    ("post_winrm_test", "read",
     "Test whether WinRM is enabled. Real subprocess."),
    ("post_kerberos_ticket_audit", "read",
     "Audit Kerberos tickets (klist). Real subprocess."),
    ("post_pass_the_hash_audit", "read",
     "Audit NTLM hash for PtH (no exploitation). Real subprocess + LLM."),
    ("post_dcsync_audit", "read",
     "Audit whether Dcsync is available. Real subprocess + LLM."),
    # === Persistence ===
    ("post_cron_persistence_audit", "read",
     "Audit crontab. Real subprocess."),
    ("post_systemd_persistence_audit", "read",
     "Audit systemd unit. Real subprocess."),
    ("post_scheduled_task_audit", "read",
     "Audit Windows scheduled task. Real subprocess."),
    ("post_login_hook_audit", "read",
     "Audit macOS login hook. Real subprocess."),
    ("post_launchd_persistence_audit", "read",
     "Audit LaunchAgents / LaunchDaemons. Real subprocess."),
    ("post_shell_profile_audit", "read",
     "Audit shell profiles. Real subprocess."),
    # === Exfiltration ===
    ("post_dns_tunnel_audit", "read",
     "Audit whether a DNS-tunneling binary is present. "
     "Real subprocess + LLM."),
    ("post_https_exfil_audit", "read",
     "Audit whether an HTTPS-exfil binary is present. "
     "Real subprocess + LLM."),
    # === Defense evasion ===
    ("post_av_edr_audit", "read",
     "Audit AV / EDR presence. Real subprocess + LLM."),
    ("post_amsi_bypass_check", "read",
     "Audit whether AMSI bypass is possible. Real subprocess + LLM."),
    ("post_appender_dll_audit", "read",
     "Audit DLL-appender surface. Real subprocess + LLM."),
    # === Network recon ===
    ("post_arp_table_audit", "read",
     "Audit ARP table. Real subprocess."),
    ("post_routing_table_audit", "read",
     "Audit routing table. Real subprocess."),
    ("post_dns_cache_audit", "read",
     "Audit DNS cache. Real subprocess."),
    ("post_listening_port_audit", "read",
     "Audit listening ports. Real subprocess."),
    ("post_established_conn_audit", "read",
     "Audit established connections. Real subprocess."),
    # === Filesystem ===
    ("post_home_dir_audit", "read",
     "Audit /home permissions. Real subprocess."),
    ("post_etc_audit", "read",
     "Audit /etc for writable files. Real subprocess."),
    ("post_tmp_audit", "read",
     "Audit /tmp for sensitive files. Real subprocess."),
    ("post_world_readable_audit", "read",
     "Audit world-readable files. Real subprocess + LLM."),
    # === Process / memory ===
    ("post_process_list_audit", "read",
     "Audit process list. Real subprocess."),
    ("post_kernel_module_audit", "read",
     "Audit loaded kernel modules. Real subprocess."),
    ("post_kernel_version_audit", "read",
     "Audit kernel version for CVEs. Real subprocess + LLM."),
    # === Cloud / SaaS ===
    ("post_iam_role_audit", "read",
     "Audit cloud IAM. Real subprocess + LLM."),
    ("post_metadata_service_audit", "read",
     "Audit whether the cloud-metadata service is reachable. "
     "Real subprocess."),
    ("post_managed_identity_audit", "read",
     "Audit managed-identity presence. Real subprocess + LLM."),
    # === Exotic ===
    ("post_bluetooth_local_audit", "read",
     "Audit Bluetooth devices (operator's own machine). "
     "Real subprocess + LLM."),
    ("post_usb_device_audit", "read",
     "Audit USB device history. Real subprocess + LLM."),
    ("post_printer_spooler_audit", "read",
     "Audit printer spooler. Real subprocess."),
    # === Operator-recommended destructive actions (gated) ===
    ("post_dcshadow_audit", "destructive",
     "DCShadow capability audit (lab only, gated)."),
    ("post_golden_silver_ticket_audit", "destructive",
     "Audit kerberoast / golden-ticket surface (lab only, gated)."),
    ("post_dcsync_test_audit", "destructive",
     "Audit Dcsync test (lab only, gated)."),
    ("post_pth_lateral_test", "destructive",
     "Pass-the-hash lateral movement test (lab only, gated)."),
    ("post_bloodhound_audit", "destructive",
     "Run BloodHound-style audit (lab only, gated)."),
    # === Phase 2.3.F — 40 new post-exploit methods ===
    # Privesc (5)
    ("post_privesc_linux_sudo_audit", "read",
     "Audit sudoers on Linux. Real subprocess; never fabricates."),
    ("post_privesc_linux_capabilities_audit", "read",
     "Audit Linux file capabilities. Real subprocess; never fabricates."),
    ("post_privesc_windows_uac_audit", "read",
     "Audit UAC policy on Windows. Real subprocess; never fabricates."),
    ("post_privesc_windows_token_audit", "read",
     "Audit token privileges on Windows. Real subprocess; never fabricates."),
    ("post_privesc_macos_sip_audit", "read",
     "Audit SIP on macOS. Real subprocess; never fabricates."),
    # Lateral (5)
    ("post_lateral_smb_pivot", "destructive",
     "SMB session reuse for lateral pivot. Plan-only; never inlines creds."),
    ("post_lateral_winrm_exec", "destructive",
     "WinRM exec for lateral pivot. Plan-only; never inlines creds."),
    ("post_lateral_ssh_cert_auth", "destructive",
     "SSH cert auth for lateral pivot. Plan-only; never inlines key path."),
    ("post_lateral_wmi_exec", "destructive",
     "WMI exec for lateral pivot. Plan-only; never inlines creds."),
    ("post_lateral_ldap_query", "destructive",
     "LDAP query for lateral pivot. Plan-only; never inlines creds."),
    # Exfil (5)
    ("post_exfil_https", "destructive",
     "Exfiltration over HTTPS. Plan-only; never inlines creds."),
    ("post_exfil_doh", "destructive",
     "Exfiltration over DNS over HTTPS. Plan-only; never inlines creds."),
    ("post_exfil_icmp", "destructive",
     "Exfiltration over ICMP. Plan-only; never inlines creds."),
    ("post_exfil_smtp", "destructive",
     "Exfiltration over SMTP. Plan-only; never inlines creds."),
    ("post_exfil_ftp", "destructive",
     "Exfiltration over FTP. Plan-only; never inlines creds."),
    # Persistence (5)
    ("post_persist_cron_audit", "read",
     "Audit /etc/cron.* entries. Heuristic; never fabricates."),
    ("post_persist_systemd_audit", "read",
     "Audit systemd user units. Heuristic; never fabricates."),
    ("post_persist_schtasks_audit", "read",
     "Audit Windows scheduled tasks. Heuristic; never fabricates."),
    ("post_persist_launchd_audit", "read",
     "Audit macOS launchd agents. Heuristic; never fabricates."),
    ("post_persist_registry_run_audit", "read",
     "Audit HKCU/HKLM Run keys. Heuristic; never fabricates."),
    # Credential harvesting (5)
    ("post_creds_mimikatz_audit", "destructive",
     "Mimikatz sekurlsa::logonpasswords. Plan-only; never inlines harvested creds."),
    ("post_creds_pypykatz_audit", "destructive",
     "pypykatz rekall. Plan-only; never inlines harvested creds."),
    ("post_creds_secretsdump_audit", "destructive",
     "secretsdump.py. Plan-only; never inlines harvested creds."),
    ("post_creds_lsassy_audit", "destructive",
     "lsassy. Plan-only; never inlines harvested creds."),
    ("post_creds_gmsa_audit", "read",
     "Enumerate gMSA accounts. Heuristic; never fabricates."),
    # Anti-forensic (5)
    ("post_antiforensic_etw_disable_audit", "destructive",
     "Audit ETW disable path. Plan-only; never inlines creds."),
    ("post_antiforensic_peb_unlink_audit", "destructive",
     "Audit PEB unlink path. Plan-only; never inlines creds."),
    ("post_antiforensic_syslog_clear_audit", "destructive",
     "Audit per-UID syslog clear. Plan-only; never inlines creds."),
    ("post_antiforensic_ads_audit", "read",
     "Audit NTFS Alternate Data Streams. Heuristic; never fabricates."),
    ("post_antiforensic_timestomp_audit", "destructive",
     "Audit timestomp on file mtime. Plan-only; never inlines creds."),
    # Polymorphic (5)
    ("poly_post_exfil_chunk_grammar", "read",
     "Polymorphic grammar for exfil chunk sizes. Pure Python."),
    ("poly_post_persistence_grammar", "read",
     "Polymorphic grammar for persistence mechanisms. Pure Python."),
    ("poly_post_lateral_proto_grammar", "read",
     "Polymorphic grammar for lateral protocol ordering. Pure Python."),
    ("poly_post_privesc_chain_grammar", "read",
     "Polymorphic grammar for privesc chain order. Pure Python."),
    ("poly_post_credential_format_grammar", "read",
     "Polymorphic grammar for credential format shapes. Never inlines values."),
    # Target-adaptive (5)
    ("adapt_post_target_os_picker", "read",
     "Target-adaptive picker for privesc based on target OS."),
    ("adapt_post_lateral_target_picker", "read",
     "Target-adaptive picker for lateral based on target count."),
    ("adapt_post_exfil_bandwidth_picker", "read",
     "Target-adaptive picker for exfil based on size."),
    ("adapt_post_persistence_longevity_picker", "read",
     "Target-adaptive picker for persistence based on horizon."),
    ("adapt_post_cleaner_picker", "read",
     "Target-adaptive picker for anti-forensic based on log count."),
]


# ---------------------------------------------------------------------------
# Forensics — 50+ creative modules (READ-ONLY by default)
# ---------------------------------------------------------------------------
FORENSICS_V2_METHODS: List[Tuple[str, str, str]] = [
    # === Memory forensics ===
    ("forensic_volatility_pslist", "read",
     "Volatility pslist (operator's own dump only). "
     "Real volatility plugin if installed."),
    ("forensic_volatility_pstree", "read",
     "Volatility pstree. Real plugin."),
    ("forensic_volatility_netscan", "read",
     "Volatility netscan. Real plugin."),
    ("forensic_volatility_filescan", "read",
     "Volatility filescan. Real plugin."),
    ("forensic_volatility_hashdump", "read",
     "Volatility hashdump (read-only). Real plugin."),
    ("forensic_volatility_malfind", "read",
     "Volatility malfind. Real plugin."),
    ("forensic_lime_dump_audit", "read",
     "Audit LiME memory dump. Real subprocess."),
    ("forensic_proc_mem_audit", "read",
     "Audit /proc/<pid>/mem (operator's own processes)."),
    # === Disk forensics ===
    ("forensic_sleuthkit_fls", "read",
     "Sleuthkit fls (operator's own image only). Real fls."),
    ("forensic_sleuthkit_icat", "read",
     "Sleuthkit icat. Real icat."),
    ("forensic_sleuthkit_mmls", "read",
     "Sleuthkit mmls. Real mmls."),
    ("forensic_sleuthkit_fsstat", "read",
     "Sleuthkit fsstat. Real fsstat."),
    ("forensic_sleuthkit_istat", "read",
     "Sleuthkit istat. Real istat."),
    ("forensic_bstrings_audit", "read",
     "Run bstrings on a binary to extract strings. "
     "Real bstrings."),
    ("forensic_binwalk_audit", "read",
     "Run binwalk on a binary to extract embedded files. "
     "Real binwalk."),
    # === File-system ===
    ("forensic_file_carve_photorec", "read",
     "Run photorec on a disk image. Real photorec."),
    ("forensic_file_carve_foremost", "read",
     "Run foremost. Real foremost."),
    ("forensic_file_hash_compare", "read",
     "Hash a directory and compare to NSRL. Real sha256sum + NSRL."),
    ("forensic_file_metadata_audit", "read",
     "Audit file-mtime / atime for tampering. Real stat."),
    # === Network forensics ===
    ("forensic_pcap_parse_tshark", "read",
     "Run tshark on a pcap. Real tshark."),
    ("forensic_pcap_parse_tcpdump", "read",
     "Run tcpdump read on a pcap. Real tcpdump."),
    ("forensic_pcap_parse_editcap", "read",
     "Edit a pcap. Real editcap."),
    ("forensic_pcap_parse_mergecap", "read",
     "Merge pcaps. Real mergecap."),
    ("forensic_pcap_parse_capinfos", "read",
     "capinfos. Real capinfos."),
    ("forensic_flow_audit_nfdump", "read",
     "Run nfdump on a flow file. Real nfdump."),
    # === Logs ===
    ("forensic_auth_log_audit", "read",
     "Audit auth.log. Real parse."),
    ("forensic_syslog_audit", "read",
     "Audit syslog. Real parse."),
    ("forensic_dpkg_log_audit", "read",
     "Audit dpkg.log. Real parse."),
    ("forensic_windows_event_audit", "read",
     "Audit Windows Event Log (wevtutil). Real subprocess."),
    # === Browser / app ===
    ("forensic_browser_history_audit", "read",
     "Audit browser history (operator's own profile). "
     "Real parse + LLM."),
    ("forensic_browser_cache_audit", "read",
     "Audit browser cache. Real parse."),
    ("forensic_browser_cookie_audit", "read",
     "Audit browser cookies (operator's own). Real parse."),
    # === Mail / chat ===
    ("forensic_mail_audit", "read",
     "Audit mail headers. Real parse + LLM."),
    ("forensic_chat_log_audit", "read",
     "Audit chat logs. Real parse + LLM."),
    # === Mobile ===
    ("forensic_ios_backup_audit", "read",
     "Audit an iOS backup (operator's own). Real parse."),
    ("forensic_android_adb_pull", "read",
     "Pull from an attached Android via adb (operator's own)."),
    # === Registry (Windows-style) ===
    ("forensic_registry_audit", "read",
     "Audit a registry hive. Real reglookup / regdump."),
    ("forensic_registry_persistence_audit", "read",
     "Audit registry persistence keys. Real parse + LLM."),
    # === Memory / process ===
    ("forensic_proc_cmdline_audit", "read",
     "Audit /proc/*/cmdline. Real subprocess."),
    ("forensic_proc_maps_audit", "read",
     "Audit /proc/*/maps. Real subprocess."),
    ("forensic_proc_environ_audit", "read",
     "Audit /proc/*/environ. Real subprocess (own only)."),
    # === Network state ===
    ("forensic_netstat_audit", "read",
     "Audit netstat output. Real subprocess."),
    ("forensic_ss_audit", "read",
     "Audit ss output. Real subprocess."),
    ("forensic_iptables_dump_audit", "read",
     "Audit iptables-save. Real subprocess."),
    # === Malware triage (operator's own samples) ===
    ("forensic_yara_audit", "read",
     "Run yara on a directory (operator's own samples). "
     "Real yara."),
    ("forensic_clamscan_audit", "read",
     "Run clamscan. Real clamscan."),
    ("forensic_peframe_audit", "read",
     "Run peframe on a PE. Real peframe."),
    ("forensic_olevba_audit", "read",
     "Run olevba on a doc. Real olevba."),
    # === OS artifacts ===
    ("forensic_recent_files_audit", "read",
     "Audit recent-files (Windows / macOS / Linux). Real parse."),
    ("forensic_prefetch_audit", "read",
     "Audit Windows Prefetch. Real parse."),
    ("forensic_amsi_log_audit", "read",
     "Audit AMSI log. Real parse."),
    ("forensic_etw_trace_audit", "read",
     "Audit ETW trace. Real parse."),
    # === Misc / lab ===
    ("forensic_custom_ioc_search", "read",
     "Custom IOC search across a disk image. Real grep."),
    ("forensic_threat_intel_lookup", "read",
     "Threat-intel lookup (OTX / VirusTotal). Real HTTP."),
]


# ---------------------------------------------------------------------------
# Anti-forensics — 50+ creative modules (operator's own scope only)
# ---------------------------------------------------------------------------
ANTI_FORENSICS_V2_METHODS: List[Tuple[str, str, str]] = [
    # === Log / artifact cleanup ===
    ("antiforensic_log_zeroize", "intrusive",
     "Zero-fill and remove selected log files (operator's "
     "own machine). Real shred."),
    ("antiforensic_log_rewrite", "intrusive",
     "Rewrite log files to mask activity (own machine). "
     "Real truncate + sed."),
    ("antiforensic_history_zeroize", "intrusive",
     "Zero-fill shell history. Real shred + truncate."),
    ("antiforensic_bash_history_obfuscate", "intrusive",
     "Obfuscate history with non-printables."),
    ("antiforensic_recent_files_zeroize", "intrusive",
     "Zero-fill recent-files DB (own machine). Real truncate."),
    ("antiforensic_prefetch_zeroize", "intrusive",
     "Zero-fill Windows Prefetch (own machine)."),
    # === Memory ===
    ("antiforensic_memory_zeroize", "intrusive",
     "Trigger self-defence: zero-fill sensitive regions in "
     "memory before exit. Real mlock + memset."),
    ("antiforensic_core_pattern_modify", "intrusive",
     "Modify /proc/sys/kernel/core_pattern to disable core "
     "dumps (own machine). Real subprocess."),
    # === Disk ===
    ("antiforensic_free_space_zeroize", "destructive",
     "Zero-fill free space. Real dd + shred."),
    ("antiforensic_swap_zeroize", "destructive",
     "Zero-fill swap. Real swapoff + shred."),
    ("antiforensic_slack_zeroize", "destructive",
     "Zero-fill file slack. Real wipe."),
    # === Network ===
    ("antiforensic_dns_cache_flush", "intrusive",
     "Flush local DNS cache. Real systemd-resolve / nscd."),
    ("antiforensic_arp_cache_flush", "intrusive",
     "Flush ARP cache. Real ip neigh flush."),
    ("antiforensic_route_flush", "intrusive",
     "Flush routing cache. Real ip route flush."),
    ("antiforensic_socket_close_all", "intrusive",
     "Close all sockets. Real ss + kill."),
    # === User / session ===
    ("antiforensic_user_add_temp", "destructive",
     "Add a temporary user for cleanup. Real useradd."),
    ("antiforensic_user_delete", "destructive",
     "Delete the temporary user. Real userdel."),
    ("antiforensic_login_log_zeroize", "intrusive",
     "Zero-fill wtmp / utmp / btmp. Real truncate + sed."),
    ("antiforensic_lastlog_zeroize", "intrusive",
     "Zero-fill lastlog. Real truncate."),
    # === File-system ===
    ("antiforensic_umount_usb", "intrusive",
     "Unmount a USB device. Real umount."),
    ("antiforensic_dropbear_key_zeroize", "intrusive",
     "Zero-fill dropbear host keys. Real shred."),
    ("antiforensic_ssh_key_zeroize", "intrusive",
     "Zero-fill SSH keys. Real shred."),
    ("antiforensic_pam_log_zeroize", "intrusive",
     "Zero-fill PAM logs. Real truncate."),
    ("antiforensic_audit_log_zeroize", "destructive",
     "Zero-fill audit log. Real truncate + service stop."),
    # === Persistence evisceration ===
    ("antiforensic_cron_zeroize", "intrusive",
     "Remove all cron entries. Real crontab -r."),
    ("antiforensic_systemd_unit_disable", "intrusive",
     "Disable a systemd unit. Real systemctl."),
    ("antiforensic_shell_profile_zeroize", "intrusive",
     "Zero-fill shell profile edits. Real truncate + sed."),
    # === Process / service ===
    ("antiforensic_kill_process", "intrusive",
     "Kill a process. Real kill."),
    ("antiforensic_service_stop", "intrusive",
     "Stop a service. Real systemctl."),
    ("antiforensic_kldunload_kernel_module", "intrusive",
     "Unload a kernel module. Real kldunload."),
    # === Network trace ===
    ("antiforensic_firewall_log_zeroize", "intrusive",
     "Zero-fill firewall logs. Real truncate."),
    ("antiforensic_suricata_eve_zeroize", "intrusive",
     "Zero-fill Suricata eve.json. Real truncate."),
    ("antiforensic_pcap_zeroize", "intrusive",
     "Zero-fill a pcap. Real shred."),
    # === Memory-acquisition defence ===
    ("antiforensic_kaslr_obfuscate", "intrusive",
     "Cycle KASLR to defeat memory-acquisition address "
     "inference. Real echo 2 > /proc/sys/kernel/randomize_va_space."),
    ("antiforensic_ptrace_scope_audit", "intrusive",
     "Restrict ptrace to admin. Real sysctl."),
    # === Cloud / remote ===
    ("antiforensic_aws_instance_metadata_disable", "intrusive",
     "Disable instance-metadata service. Real aws cli."),
    ("antiforensic_azure_imds_disable", "intrusive",
     "Disable Azure IMDS. Real subprocess."),
    # === Browser / app ===
    ("antiforensic_browser_history_zeroize", "intrusive",
     "Zero-fill browser history (own). Real truncate + shred."),
    ("antiforensic_browser_cookie_zeroize", "intrusive",
     "Zero-fill browser cookies. Real truncate + shred."),
    ("antiforensic_browser_cache_zeroize", "intrusive",
     "Zero-fill browser cache. Real truncate + shred."),
    # === Custom tool evisceration ===
    ("antiforensic_binary_zeroize", "destructive",
     "Zero-fill a binary to remove forensic evidence. "
     "Real shred."),
    ("antiforensic_binary_timestamp_rewrite", "intrusive",
     "Rewrite a binary's mtime/atime. Real touch -t."),
    ("antiforensic_directory_recursive_zeroize", "destructive",
     "Recursive shred of a directory. Real find + shred."),
    # === Memory-acquisition defence (advanced) ===
    ("antiforensic_ulimit_core_disable", "intrusive",
     "Disable core-dump via ulimit. Real ulimit -c 0."),
    ("antiforensic_sysrq_disable", "intrusive",
     "Disable sysrq to defeat memory-acquisition via panic. "
     "Real echo 0 > /proc/sys/kernel/sysrq."),
    ("antiforensic_kexec_disable", "intrusive",
     "Disable kexec to defeat memory-acquisition via kexec. "
     "Real subprocess."),
    # === Network-covert channels (defence) ===
    ("antiforensic_dns_tunnel_detect", "read",
     "Detect a DNS-tunnel covert channel. Real parse + LLM."),
    ("antiforensic_icmp_tunnel_detect", "read",
     "Detect ICMP-tunnel. Real parse + LLM."),
    ("antiforensic_steganography_detect", "read",
     "Detect steganography in posted images. Real stegdetect."),
    # === Cleanup orchestration ===
    ("antiforensic_full_session_cleanup", "destructive",
     "Full session cleanup (logs + history + files + persistence). "
     "Lab only, gated."),
    ("antiforensic_stealth_orchestrator", "destructive",
     "Stealth-mode orchestrator (run-time anti-detect, "
     "lab only, gated)."),
    ("antiforensic_incident_response_audit", "read",
     "Audit incident-response capability. Pure LLM + parse."),
    ("antiforensic_residual_data_audit", "read",
     "Audit residual data on disk. Real blkls / photorec."),
]


# ---------------------------------------------------------------------------
# Aggregate
# ---------------------------------------------------------------------------
V2_REGISTRY: Dict[str, List[Tuple[str, str, str]]] = {
    "wifi": WIFI_V2_METHODS,
    "wifi_recon": WIFI_RECON_V2_METHODS,
    "ble": BLE_V2_METHODS,
    "ble_recon": BLE_RECON_V2_METHODS,
    "osint": OSINT_V2_METHODS,
    "post_exploit": POST_EXPLOIT_V2_METHODS,
    "forensics": FORENSICS_V2_METHODS,
    "anti_forensics": ANTI_FORENSICS_V2_METHODS,
}


# ---------------------------------------------------------------------------
# Phase 2.4 §H — Polymorphic grammar + target-adaptive picker companions.
# Implemented in :mod:`core.refactors.poly_adapt_companions`. The
# chain planner dispatches these via the ``poly_adapt`` action.
# ---------------------------------------------------------------------------

POLY_ADAPT_V2_METHODS: List[Tuple[str, str, str]] = [
    # Polymorphic grammars (10)
    ("poly_deauth_burst_pattern_grammar", "intrusive",
     "Pick a deauth-burst pattern (ramp/constant/burst/staggered/exp)."),
    ("poly_eapol_replay_grammar", "intrusive",
     "Pick an EAPOL replay-counter strategy (linear/random/monotonic/batched/burst)."),
    ("poly_pmkid_eapol_field_grammar", "intrusive",
     "Pick which EAPOL fields to mutate for PMKID harvesting."),
    ("poly_wps_eap_failure_grammar", "intrusive",
     "Pick a WPS EAP-failure injection variant (failure/nack/dup/frag)."),
    ("poly_evil_twin_hostapd_conf_grammar", "intrusive",
     "Pick a hostapd config template for Evil Twin (suffix/5G/guest/secure)."),
    ("poly_passive_scan_channel_hop_grammar", "intrusive",
     "Pick a channel-hop sequence (1/6/11, full, 5GHz, mixed)."),
    ("poly_client_probe_request_grammar", "read",
     "Pick which client-probe types to listen for."),
    ("poly_gatt_value_template", "intrusive",
     "Pick a GATT write-value template (ff/00/random/ascii)."),
    ("poly_hid_report_template", "intrusive",
     "Pick a HID-injection report template (run/browser/type/enter/alt-tab)."),
    ("poly_adv_data_template_grammar", "read",
     "Pick an advertising data template (ibeacon/eddystone/mfr-data)."),
    # Target-adaptive pickers (10)
    ("adapt_attack_deauth_strategy_picker", "intrusive",
     "Pick deauth strategy from PMF + client count (sa_query/broadcast/etc)."),
    ("adapt_attack_handshake_strategy_picker", "intrusive",
     "Pick handshake-capture strategy from WPA version (sae/eap_tls/wpa2)."),
    ("adapt_attack_pmkid_target_picker", "intrusive",
     "Pick PMKID vs standard from 11k presence."),
    ("adapt_attack_wps_strategy_picker", "intrusive",
     "Pick WPS strategy from WPS-locked state (pixie/reaver)."),
    ("adapt_attack_evil_twin_strategy_picker", "intrusive",
     "Pick Evil-Twin strategy from captive-portal presence."),
    ("adapt_recon_scan_strategy_picker", "read",
     "Pick recon-scan strategy from band presence (2.4/5/6E)."),
    ("adapt_recon_client_strategy_picker", "read",
     "Pick client-detection from probe count."),
    ("adapt_attack_gatt_strategy_picker", "intrusive",
     "Pick GATT-attack from service count + encryption."),
    ("adapt_attack_hid_strategy_picker", "intrusive",
     "Pick HID-injection from target OS (windows/macos/linux)."),
    ("adapt_recon_adv_strategy_picker", "read",
     "Pick ADV-recon from ADV interval."),
]

V2_REGISTRY["poly_adapt"] = POLY_ADAPT_V2_METHODS


def list_v2_methods(category: str) -> List[str]:
    """Return the list of v2 method names for a category."""
    return [m[0] for m in V2_REGISTRY.get(category, [])]


def describe_v2_method(category: str, method: str) -> Optional[Dict[str, str]]:
    """Return {name, risk, description} for a v2 method, or None."""
    for name, risk, desc in V2_REGISTRY.get(category, []):
        if name == method:
            return {"name": name, "risk": risk, "description": desc}
    return None


def describe_v2_category(category: str) -> List[Dict[str, str]]:
    """Return all method descriptors in a category."""
    return [
        {"name": n, "risk": r, "description": d}
        for n, r, d in V2_REGISTRY.get(category, [])
    ]


def all_v2_method_names() -> List[str]:
    """Return all v2 method names across all categories."""
    out: List[str] = []
    for cat in V2_REGISTRY:
        out.extend(list_v2_methods(cat))
    return out


def total_v2_count() -> Dict[str, int]:
    """Return a {category: count} dict for the v2 registry."""
    return {cat: len(meths) for cat, meths in V2_REGISTRY.items()}


def build_v2_prompt_stanza() -> str:
    """Build the prompt stanza for the LLM. Lists each category with
    the count of methods and a one-line category description. The
    LLM picks a v2 method when an existing one is too generic."""
    lines = [
        "  KFIOSA also exposes a SECOND WAVE of creative methods per\n"
        "  type. The full v2 registry is in\n"
        "  ``core.ai_backend.expanded_modules`` (8 categories, 50+\n"
        "  methods each). Per-category summary:\n",
    ]
    summaries = {
        "wifi": ("WiFi attack (802.11ax / 6E / 6 GHz, WPA3 / SAE / "
                 "PMF, mesh / WDS, P2P, Hotspot 2.0, MLO, HaLow, "
                 "WPA3-Enterprise)"),
        "wifi_recon": ("WiFi recon (rogue-AP, hidden-SSID, client, "
                       "RRM, BSS-TM, FT, channel-util, vendor-IE, "
                       "passive deauth / disassoc / DFS, 6E-PSC, "
                       "Kismet diff)"),
        "ble": ("BLE attack (5.x ext-adv, RPA, LESC, GATT, ATT, "
                "conn-param, mesh, Auracast, HID, OOB, HCI, L2CAP, "
                "AoA/AoD, vendor, power)"),
        "ble_recon": ("BLE recon (appearance, OUI, service-UUID, "
                      "mfr-fingerprint, health-services, "
                      "FindMy / FastPair / SwiftPair / SmartTag / "
                      "Tile, presence / dwell / movement)"),
        "osint": ("OSINT (people, social, domain / DNS / cert / "
                  "WHOIS-history, IP / Shodan / Censys, web / API, "
                  "leaks, geo / sun, email, BTC / ETH, phone, "
                  "image / OCR, stego)"),
        "post_exploit": ("Post-exploit (privesc, cred-harvest, "
                         "lateral, persistence, exfil, defence-evasion, "
                         "net-recon, FS, process, cloud / IAM, "
                         "peripheral, lab-only destructive)"),
        "forensics": ("Forensics (memory / Volatility / LiME, disk / "
                      "Sleuthkit, bstrings / binwalk, file-carve, "
                      "pcap, logs, browser, mail / chat, mobile, "
                      "registry, process, network-state, malware, "
                      "OS artifacts)"),
        "anti_forensics": ("Anti-forensics (log-zeroize, memory, disk, "
                           "net, user / session, FS, persistence, "
                           "process, network-trace, kaslr / ptrace, "
                           "cloud, browser, binary-rewrite, "
                           "covert-channel detect)"),
    }
    for cat, methods in V2_REGISTRY.items():
        lines.append(
            f"    # {cat} ({len(methods)} methods): {summaries.get(cat, '')}\n"
        )
    lines.append(
        "\n  To use: chain a v2 method via the same step shape as the\n"
        "  primary actions:\n"
        "    {\"action\": \"wifi_attack\",\n"
        "     \"args\": {\"method\": \"wifi6e_ofdma_trigger_flood\", ...}}\n"
        "  or the equivalent for ``ble_attack`` / ``osint_probe`` /\n"
        "  ``post_exploit_ext`` / ``post_exploit_anti_forensic`` /\n"
        "  ``wifi_attack_recon`` (when available) / ``ble_probe``.\n"
        "  The risk_level on the chain step drives the per-step ACCEPT\n"
        "  gate (``read`` = no gate, ``intrusive`` = 1 ACCEPT, "
        "``destructive`` = 2 ACCEPT).\n"
    )
    return "".join(lines)


V2_PROMPT_STANZA = build_v2_prompt_stanza()


__all__ = [
    "WIFI_V2_METHODS", "WIFI_RECON_V2_METHODS",
    "BLE_V2_METHODS", "BLE_RECON_V2_METHODS",
    "OSINT_V2_METHODS", "POST_EXPLOIT_V2_METHODS",
    "FORENSICS_V2_METHODS", "ANTI_FORENSICS_V2_METHODS",
    "POLY_ADAPT_V2_METHODS",
    "V2_REGISTRY", "V2_PROMPT_STANZA",
    "list_v2_methods", "describe_v2_method", "describe_v2_category",
    "all_v2_method_names", "total_v2_count", "build_v2_prompt_stanza",
]
