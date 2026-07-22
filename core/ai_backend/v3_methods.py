"""core.ai_backend.v3_methods — Phase 2.4 expansion: 280 new v3 methods.

40 entries each across 7 categories:

  * ``wifi_attack_v3`` — 40 AA-series universal methods
  * ``wifi_recon_v3`` — 40 RR-series universal methods
  * ``ble_attack_v3`` — 40 BB-series universal methods
  * ``ble_recon_v3`` — 40 BRR-series universal methods
  * ``osint_web_v3`` — 40 OW-series universal methods (no-key only)
  * ``osint_people_v3`` — 40 OP-series universal methods (no-key only)
  * ``post_exploit_v3`` — 40 PP-series universal methods

Each entry is a ``(name, risk, description)`` tuple, matching the
shape of the existing ``*_V2_METHODS`` tuples. The runtime
impls live in the runner modules (or in the corresponding
``v3_methods_runner.py`` next to this file for runners we don't
own).

The v3 registry is exposed via ``V3_REGISTRY`` and ``build_v3_prompt_stanza``
so the LLM prompt can teach the new names. ``describe_v3_method`` mirrors
``describe_v2_method``.

Honest-degrade contract: we never fabricate CVE ids, stargazer counts,
or library versions in the descriptions. The v3 names are operator-
curated; the descriptions are short factual summaries of what the
method does.
"""
from __future__ import annotations

from typing import Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# WiFi attack (AA1-AA40)
# ---------------------------------------------------------------------------

WIFI_ATTACK_V3_METHODS: List[Tuple[str, str, str]] = [
    ("wifi_ap_blacklist_bypass", "intrusive",
     "Scan associated MACs, predict allowed OUI, MAC-clone onto wlan0mon."),
    ("wifi_channel_switch_jamming", "intrusive",
     "Forge CSA beacons with random new-channel numbers."),
    ("wifi_wpa3_owe_fake_ap", "intrusive",
     "OWE Evil-Twin; capture DH handshake; offline crack with cryptography."),
    ("wifi_eapol_start_flood", "intrusive",
     "Flood EAPOL-Start frames with measured pacing."),
    ("wifi_beacon_interval_mutation", "intrusive",
     "Emit beacons with mutated interval (100-500 TU)."),
    ("wifi_80211w_dos_mitigation_test", "intrusive",
     "Random-nonce SA-Query; report if AP accepts the spoof."),
    ("wifi_mfp_bypass_replay", "intrusive",
     "Replay pre-PMF Disassoc frames; report if AP accepts."),
    ("wifi_4way_handshake_injection", "intrusive",
     "Inject 1/4 frame; harvest ANonce."),
    ("wifi_radius_coa_attack", "intrusive",
     "Forged RADIUS CoA with credential_pattern_ai."),
    ("wifi_wps_external_registrar_flood", "intrusive",
     "Wash/reaver flood; detect AP WPS lockout."),
    ("wifi_wps_ap_pin_offline", "intrusive",
     "Pixiewps offline PIN crack against captured WPS exchanges."),
    ("wifi_hostapd_wpe_advanced", "intrusive",
     "hostapd-wpe + asleap to capture enterprise creds."),
    ("wifi_rogue_dhcp", "intrusive",
     "Dnsmasq rogue DHCP on Evil-Twin to push attacker DNS."),
    ("wifi_wpad_attack", "intrusive",
     "WPAD injection via rogue DHCP/DNS responses."),
    ("wifi_ntlm_relay_ap", "intrusive",
     "ntlmrelayx over Evil-Twin to capture NTLM hashes."),
    ("wifi_llmnr_poison", "intrusive",
     "LLMNR/NBT-NS poisoning on the operator subnet."),
    ("wifi_dns_spoofing_advanced", "intrusive",
     "AI-picked bank-domain spoofing; capture cleartext creds."),
    ("wifi_ssl_stripping", "intrusive",
     "sslstrip on HTTP traffic flowing through the rogue AP."),
    ("wifi_arpspoof_auto", "intrusive",
     "Auto ARP spoof + IP-forward to MITM the target."),
    ("wifi_tcp_session_hijack", "destructive",
     "Sequence-number learning + injection (operator-confirm)."),
    ("wifi_captive_portal_custom", "intrusive",
     "SSID-themed captive portal HTML for credential harvest."),
    ("wifi_cookie_stealer", "intrusive",
     "HTTP cookie harvest via the captive portal flow."),
    ("wifi_credential_injection", "intrusive",
     "Auto-fill form with cred-pattern from leaked corpus."),
    ("wifi_javascript_injection", "intrusive",
     "JS injection into plain HTTP responses (mitmproxy)."),
    ("wifi_http_redirect_phishing", "intrusive",
     "HTTP→phishing server redirect via response rewrite."),
    ("wifi_ota_firmware_downgrade", "destructive",
     "Trigger OTA firmware downgrade (operator-confirm)."),
    ("wifi_snmp_bruteforce", "intrusive",
     "SNMP public/private community brute against the AP."),
    ("wifi_telnet_bruteforce", "intrusive",
     "Telnet library brute against the AP management."),
    ("wifi_ssh_bruteforce_ap", "intrusive",
     "Paramiko SSH brute against the AP management."),
    ("wifi_web_admin_bruteforce", "intrusive",
     "/admin brute against the AP web UI."),
    ("wifi_cve_exploit_runner", "destructive",
     "NVD→PoC runner using the local uncensored Qwen2.5-Coder model."),
    ("wifi_cve_metasploit_auto", "destructive",
     "msfconsole .rc from a CVE; runs under operator ACCEPT."),
    ("wifi_killer_dos", "destructive",
     "Bad-FCS frame flood for denial-of-service."),
    ("wifi_netgear_rce", "destructive",
     "Netgear RCE PoC runner (CVE-2021-34981)."),
    ("wifi_tplink_rce", "destructive",
     "TP-Link RCE PoC runner (CVE-2020-26880)."),
    ("wifi_router_reset", "destructive",
     "Admin reset CGI call (operator-confirm)."),
    ("wifi_ssid_bleed", "intrusive",
     "Long-SSID probe buffer overflow against the AP."),
    ("wifi_malformed_assoc", "intrusive",
     "Malformed-IE association request fuzzer."),
    ("wifi_ap_firmware_custom", "destructive",
     "Upload custom firmware to the AP (operator-confirm)."),
    ("wifi_full_auto_adaptive_attack", "intrusive",
     "AI orchestrator that picks the right AA1-AA39 sequence."),
]


# ---------------------------------------------------------------------------
# WiFi recon (RR1-RR40)
# ---------------------------------------------------------------------------

WIFI_RECON_V3_METHODS: List[Tuple[str, str, str]] = [
    ("wifi_client_ap_association_timing", "read",
     "Measure client→AP association timing to fingerprint device class."),
    ("wifi_ap_mobility_classifier", "read",
     "Classify APs as fixed/portable/mobile via RSSI variance."),
    ("wifi_client_rssi_heatmap", "read",
     "Build a 2D RSSI heatmap of the operator's position."),
    ("wifi_channel_quality_index", "read",
     "Compute a per-channel quality index from kismet observations."),
    ("wifi_beacon_fingerprint", "read",
     "Fingerprint APs by beacon IE layout (vendor + capability)."),
    ("wifi_ap_physical_location", "read",
     "Triangulate AP physical location from 3+ RSSI samples."),
    ("wifi_client_movement_tracking", "read",
     "Track a single client's movement across observations."),
    ("wifi_ap_load_prediction", "read",
     "Predict AP load via probe-response counts over time."),
    ("wifi_signal_strength_forecast", "read",
     "Forecast future RSSI for a given AP (heuristic)."),
    ("wifi_ssid_change_detection", "read",
     "Detect when an AP's SSID changes between scans."),
    ("wifi_bssid_conflict_detection", "read",
     "Detect BSSID conflicts (same MAC, different SSID)."),
    ("wifi_wps_bruteforce_resistance", "read",
     "Score WPS-bruteforce resistance from WPS IE fields."),
    ("wifi_ap_firmware_version_enum", "read",
     "Best-effort AP firmware version enumeration from vendor IEs."),
    ("wifi_ap_vulnerability_score", "read",
     "AP vulnerability score from NVD keyword search (heuristic)."),
    ("wifi_client_preference_change", "read",
     "Detect changes in client BSSID preference over time."),
    ("wifi_ap_encryption_weakness", "read",
     "Score encryption weakness from RSN IE fields."),
    ("wifi_beacon_tim_entropy", "read",
     "Measure TIM entropy to fingerprint device sleep patterns."),
    ("wifi_dtim_anomaly", "read",
     "Detect DTIM interval anomalies per AP."),
    ("wifi_ap_radio_degradation", "read",
     "Score AP radio degradation from rate over time."),
    ("wifi_client_os_detection_advanced", "read",
     "Advanced client-OS detection from probe-request content."),
    ("wifi_client_browser_fingerprint", "read",
     "Client browser fingerprint from HTTP probes if observed."),
    ("wifi_arp_cache_poison_detection", "read",
     "Detect ARP-cache poisoning on the local subnet."),
    ("wifi_dhcp_rogue_detection", "read",
     "Detect rogue DHCP servers on the operator subnet."),
    ("wifi_dns_spoof_detection", "read",
     "Detect DNS spoofing via response-time analysis."),
    ("wifi_rogue_ap_detection", "read",
     "Detect rogue APs from BSSID/SSID anomaly scoring."),
    ("wifi_deauth_flood_detection", "read",
     "Detect deauth-flood attacks in real time."),
    ("wifi_ap_honeypot_detection", "read",
     "Score the probability a given AP is a honeypot."),
    ("wifi_client_behavior_anomaly", "read",
     "Score client-behavior anomaly from probe timeline."),
    ("wifi_traffic_classification", "read",
     "Classify observed traffic by application type."),
    ("wifi_voip_detection", "read",
     "Detect VoIP traffic from packet size + timing."),
    ("wifi_video_streaming_detection", "read",
     "Detect video-streaming traffic from throughput bursts."),
    ("wifi_iot_device_identification", "read",
     "Identify IoT devices from probe-request patterns."),
    ("wifi_home_automation_detection", "read",
     "Detect home-automation protocols (Zigbee bridge, etc.)."),
    ("wifi_printer_detection", "read",
     "Detect network printers from mDNS / Bonjour."),
    ("wifi_camera_detection", "read",
     "Detect IP cameras from RTSP / ONVIF probes."),
    ("wifi_nas_detection", "read",
     "Detect NAS devices from SMB / AFP traffic."),
    ("wifi_ap_radio_temperature", "read",
     "Approximate AP radio temperature from duty-cycle."),
    ("wifi_ap_clock_drift", "read",
     "Measure AP TSF clock drift across observations."),
    ("wifi_ap_frequency_stability", "read",
     "Score frequency stability from beacon timing."),
    ("wifi_full_auto_adaptive_recon", "read",
     "AI orchestrator that picks the right RR1-RR39 sequence."),
]


# ---------------------------------------------------------------------------
# BLE attack (BB1-BB40)
# ---------------------------------------------------------------------------

BLE_ATTACK_V3_METHODS: List[Tuple[str, str, str]] = [
    ("ble_pairing_interval_abuse", "intrusive",
     "Abuse connection interval to drain battery."),
    ("ble_scan_response_spoof", "intrusive",
     "Spoof scan response to advertise attacker GATT services."),
    ("ble_connection_param_dos", "destructive",
     "Force aggressive connection params to lock the target."),
    ("ble_gatt_char_bruteforce", "intrusive",
     "Bruteforce GATT characteristic handles via error heuristics."),
    ("ble_handle_bruteforce", "intrusive",
     "Bruteforce GATT handle values within the discovered range."),
    ("ble_ccc_confusion", "intrusive",
     "Confuse CCC descriptors to enable notifications on the wrong chars."),
    ("ble_ead_irk_bruteforce", "intrusive",
     "Best-effort IRK bruteforce on EAD-resolvable targets."),
    ("ble_ltk_bruteforce", "intrusive",
     "Best-effort LTK bruteforce from a captured pairing."),
    ("ble_smp_flood", "intrusive",
     "Flood SMP pairing requests to exhaust the target."),
    ("ble_att_flood", "intrusive",
     "Flood ATT requests to deplete the target's buffers."),
    ("ble_supervision_timeout", "destructive",
     "Force supervision timeout to disconnect repeatedly."),
    ("ble_mtu_dos", "intrusive",
     "Request max MTU to starve target RAM."),
    ("ble_l2cap_credit_drain", "intrusive",
     "Drain L2CAP credit-based flow control credits."),
    ("ble_l2cap_cid_dos", "intrusive",
     "Reserve L2CAP CIDs to deplete target resources."),
    ("ble_psm_probe", "intrusive",
     "PSM probe scan to map classic-BR/EDR L2CAP services."),
    ("ble_sdp_flood", "intrusive",
     "SDP flood against the target."),
    ("ble_battery_spoof", "intrusive",
     "Spoof Battery Service to low percentage."),
    ("ble_device_info_spoof", "intrusive",
     "Spoof Device Information Service fields."),
    ("ble_ota_abuse", "destructive",
     "Trigger OTA abuse path to crash or downgrade firmware."),
    ("ble_ota_downgrade", "destructive",
     "Force OTA downgrade to a known-vulnerable build."),
    ("ble_ota_crash", "destructive",
     "Trigger OTA crash via malformed descriptor write."),
    ("ble_spp_emul", "intrusive",
     "Emulate a Serial Port Profile service to harvest data."),
    ("ble_hid_injection", "destructive",
     "Inject HID reports to control the target (operator-confirm)."),
    ("ble_hid_keyboard_layout", "destructive",
     "Switch keyboard layout for HID payload encoding."),
    ("ble_hid_mouse_jitter", "destructive",
     "Inject mouse-jitter HID reports to disrupt the user."),
    ("ble_heart_rate_spoof", "intrusive",
     "Spoof Heart Rate Measurement characteristic."),
    ("ble_blood_pressure_spoof", "intrusive",
     "Spoof Blood Pressure Measurement characteristic."),
    ("ble_temperature_spoof", "intrusive",
     "Spoof Environmental Sensing / Temperature characteristic."),
    ("ble_humidity_spoof", "intrusive",
     "Spoof Humidity characteristic."),
    ("ble_ibeacon_spoof", "intrusive",
     "Spoof an iBeacon with attacker-supplied payload."),
    ("ble_eddystone_proximity", "intrusive",
     "Spoof an Eddystone proximity beacon."),
    ("ble_mesh_pin", "intrusive",
     "Best-effort mesh network PIN attack."),
    ("ble_mesh_flood", "destructive",
     "Flood a mesh network to disrupt routing."),
    ("ble_friendship_abuse", "destructive",
     "Abuse the friendship model to drop a node's relay path."),
    ("ble_key_refresh_abuse", "destructive",
     "Force key-refresh at bad times to disrupt a friend node."),
    ("ble_audio_bis_hijack", "destructive",
     "Attempt to hijack a broadcast audio stream."),
    ("ble_audio_sink_spoof", "destructive",
     "Spoof an audio sink to receive a BIS the target started."),
    ("ble_l2cap_cos_dos", "intrusive",
     "Force L2CAP COS connection to drain target."),
    ("ble_adv_flood", "intrusive",
     "Flood advertising reports to overflow the scanner."),
    ("ble_full_auto_adaptive_attack", "intrusive",
     "AI orchestrator that picks the right BB1-BB39 sequence."),
]


# ---------------------------------------------------------------------------
# BLE recon (BRR1-BRR40)
# ---------------------------------------------------------------------------

BLE_RECON_V3_METHODS: List[Tuple[str, str, str]] = [
    ("ble_adv_rssi_histogram", "read",
     "Build an RSSI histogram per target device."),
    ("ble_adv_packet_loss", "read",
     "Measure packet-loss ratio from the expected adv interval."),
    ("ble_adv_duplicate_ratio", "read",
     "Compute duplicate-advertising ratio per device."),
    ("ble_channel_rssi_map", "read",
     "Build a per-channel RSSI map per device."),
    ("ble_tx_power_variation", "read",
     "Track TX power variation from extended-adv fields."),
    ("ble_interval_variation", "read",
     "Track adv-interval variation per device."),
    ("ble_payload_entropy", "read",
     "Compute payload entropy to detect padded/pseudo-random payloads."),
    ("ble_uuid_frequency", "read",
     "Histogram of service-UUID frequency per device."),
    ("ble_battery_state", "read",
     "Read battery state from Battery Service if present."),
    ("ble_movement_state", "read",
     "Infer movement from RSSI deltas (heuristic)."),
    ("ble_orientation_inference", "read",
     "Infer orientation from antenna-pattern shifts (heuristic)."),
    ("ble_device_class_ml", "read",
     "Classify device class via heuristic on advertising patterns."),
    ("ble_brand_confidence", "read",
     "Compute brand confidence from OUI + service-UUID."),
    ("ble_firmware_version_enum", "read",
     "Best-effort firmware-version enumeration from vendor-specific data."),
    ("ble_serial_extraction", "read",
     "Extract serial number from Device Information Service."),
    ("ble_public_key_capture", "read",
     "Capture public key from LESC pairing if observable."),
    ("ble_resolvable_address_check", "read",
     "Test whether a target's address is RPA-resolvable."),
    ("ble_mac_rotation_window", "read",
     "Estimate the MAC rotation window from RPA history."),
    ("ble_activity_cycle", "read",
     "Estimate activity cycle from adv-timestamp gaps."),
    ("ble_connected_devices", "read",
     "List connected devices observed during a passive scan."),
    ("ble_trusted_devices", "read",
     "List trusted (bonded) devices from GATT-bond DB if accessible."),
    ("ble_pairing_history", "read",
     "Approximate pairing history from observed SMP traffic."),
    ("ble_gatt_service_list", "read",
     "Enumerate GATT services seen on the target."),
    ("ble_gatt_char_list", "read",
     "Enumerate GATT characteristics per service."),
    ("ble_gatt_descriptor_list", "read",
     "Enumerate GATT descriptors per characteristic."),
    ("ble_gatt_full_graph", "read",
     "Build a full service→char→descriptor graph."),
    ("ble_gatt_security_flags", "read",
     "Read GATT security flags from CCC descriptors."),
    ("ble_io_caps", "read",
     "Read IO capabilities from the SMP pairing exchange."),
    ("ble_auth_req", "read",
     "Read authentication requirements from the SMP pairing exchange."),
    ("ble_bonding_status", "read",
     "Infer bonding status from reconnection pattern."),
    ("ble_encryption_status", "read",
     "Infer encryption status from connection-state timing."),
    ("ble_le_phy", "read",
     "Determine LE PHY (1M / 2M / Coded) in use."),
    ("ble_connection_interval", "read",
     "Measure connection interval from observed packets."),
    ("ble_connection_latency", "read",
     "Measure connection latency from observed packets."),
    ("ble_supervision_timeout_value", "read",
     "Read supervision timeout from LL connection parameters."),
    ("ble_mtu_negotiated", "read",
     "Read the MTU value negotiated for the connection."),
    ("ble_credit_based_flow", "read",
     "Read L2CAP credit-based flow control parameters."),
    ("ble_audio_codec_caps", "read",
     "Read LC3 codec capabilities from CAP records if present."),
    ("ble_bis_info", "read",
     "Read BIS broadcast info from advertising or CAP."),
    ("ble_full_auto_adaptive_recon", "read",
     "AI orchestrator that picks the right BRR1-BRR39 sequence."),
]


# ---------------------------------------------------------------------------
# OSINT - Web (OW1-OW40) — NO-KEY ONLY (per operator's revision)
# ---------------------------------------------------------------------------

OSINT_WEB_V3_METHODS: List[Tuple[str, str, str]] = [
    ("osint_web_google_dorks_pl", "read",
     "Polish Google dork construction (no API)."),
    ("osint_web_polish_company_db", "read",
     "CEIDG SOAP no-auth + KRS HTML scrape (honest-degrade on captcha)."),
    ("osint_web_polish_court_db", "read",
     "Polish court rulings HTML scrape (no API)."),
    ("osint_web_polish_media", "read",
     "Polish media mention scraper (no API)."),
    ("osint_web_social_media_pl", "read",
     "Polish social-media name search (honest-degrade on no API)."),
    ("osint_web_email_verification_pl", "read",
     "Email MX/RCPT-TO verification (no API)."),
    ("osint_web_phone_pl", "read",
     "Polish phone-number HTML scrape + UKE prefix table lookup."),
    ("osint_web_geolocation_nominatim", "read",
     "OSM Nominatim forward/reverse geocoding (no key, 1 req/s)."),
    ("osint_web_ip_location", "read",
     "ip-api.com geolocation (no key, 45 req/min)."),
    ("osint_web_domain_history", "read",
     "SecurityTrails free HTML scrape (no key)."),
    ("osint_web_subdomain_bruteforce", "read",
     "crt.sh subdomain discovery (no key)."),
    ("osint_web_certificate_transparency", "read",
     "crt.sh JSON certificate-transparency query (no key)."),
    ("osint_web_shodan_free", "read",
     "Shodan HTML search (no key)."),
    ("osint_web_virustotal_free", "read",
     "VirusTotal HTML search (no key)."),
    ("osint_web_dns_dumpster", "read",
     "DNS dumpster aggregator (no key)."),
    ("osint_web_public_leaks_haveibeenpwned", "read",
     "HIBP k-anonymity breach lookup (no key, 5 req/15s)."),
    ("osint_web_pastebin_search", "read",
     "Pastebin HTML scrape (no key, no login)."),
    ("osint_web_github_code_search", "read",
     "GitHub REST 60/h unauth code search."),
    ("osint_web_darkweb_tor", "read",
     "Tor SOCKS darkweb probe (optional, no key)."),
    ("osint_web_whois_history", "read",
     "Whoxy free HTML whois-history scrape (no key)."),
    ("osint_web_http_headers_analyze", "read",
     "HTTP-headers analysis (pure parse, no API)."),
    ("osint_web_ssl_analyze", "read",
     "SSL/TLS configuration analysis (pure parse, no API)."),
    ("osint_web_robots_txt", "read",
     "robots.txt parse (no API)."),
    ("osint_web_sitemap_xml", "read",
     "sitemap.xml parse (no API)."),
    ("osint_web_crawling_depth", "read",
     "Crawling-depth measurement (no API)."),
    ("osint_web_meta_tags", "read",
     "Meta-tags extraction (no API)."),
    ("osint_web_open_graph", "read",
     "Open-Graph metadata extraction (no API)."),
    ("osint_web_email_spider", "read",
     "Email regex spider on a target domain (no API)."),
    ("osint_web_phone_spider", "read",
     "Phone regex spider on a target domain (no API)."),
    ("osint_web_social_links", "read",
     "Social-link extraction from page anchors (no API)."),
    ("osint_web_wordpress_detection", "read",
     "WordPress detection from /wp-content/ and headers (no API)."),
    ("osint_web_cms_detection", "read",
     "CMS detection from headers + meta tags (no API)."),
    ("osint_web_framework_detection", "read",
     "Web-framework detection from headers + cookies (no API)."),
    ("osint_web_cloud_detection", "read",
     "Cloud-provider detection from DNS + headers (no API)."),
    ("osint_web_waf_detection", "read",
     "WAF detection from response codes + headers (no API)."),
    ("osint_web_admin_panel_finder", "read",
     "Admin-panel URL bruteforce on a target (no API)."),
    ("osint_web_version_detection", "read",
     "Web-app version detection from known-version fingerprints (no API)."),
    ("osint_web_cve_mapping", "read",
     "NVD CVE mapping using get_nvd_key() (never inline)."),
    ("osint_web_exploit_db_search", "read",
     "Exploit-DB HTML scrape (no key)."),
    ("osint_web_full_auto_adaptive", "intrusive",
     "AI orchestrator that picks the right OW1-OW39 sequence."),
]


# ---------------------------------------------------------------------------
# OSINT - People (OP1-OP40) — NO-KEY ONLY
# ---------------------------------------------------------------------------

OSINT_PEOPLE_V3_METHODS: List[Tuple[str, str, str]] = [
    ("osint_people_name_to_ceidg", "read",
     "CEIDG SOAP no-auth company lookup by owner name."),
    ("osint_people_name_to_krs", "read",
     "KRS HTML scrape (honest-degrade on captcha)."),
    ("osint_people_name_to_court", "read",
     "Polish court rulings HTML scrape (no API)."),
    ("osint_people_name_to_facebook", "read",
     "Facebook public search HTML scrape (no login)."),
    ("osint_people_name_to_linkedin", "read",
     "LinkedIn lookup — honest-degrade (no public API)."),
    ("osint_people_name_to_goldenline", "read",
     "Goldenline lookup — honest-degrade (no public API)."),
    ("osint_people_name_to_wykop", "read",
     "Wykop lookup — honest-degrade (needs Daisy tier)."),
    ("osint_people_phone_to_name", "read",
     "Phone-number reverse via HTML scrape + UKE prefix table."),
    ("osint_people_email_to_name", "read",
     "Email reverse via HIBP k-anonymity + Gravatar (no key)."),
    ("osint_people_image_reverse", "read",
     "Image reverse via Google dork + TinEye HTML scrape (no key)."),
    ("osint_people_face_recognition", "read",
     "Optional local face_recognition (uninstalled by default)."),
    ("osint_people_name_day", "read",
     "nameday.abalin.net (no key, JSON)."),
    ("osint_people_address_postal_code", "read",
     "pocztapolska GitHub CSV mirror (no key)."),
    ("osint_people_regon_validate", "read",
     "Pure-Python REGON-9 checksum validator (no key, no network)."),
    ("osint_people_pesel_validate", "read",
     "Pure-Python PESEL checksum validator (GDPR-safe, no network)."),
    ("osint_people_nip_validate", "read",
     "Pure-Python NIP checksum validator (no key, no network)."),
    ("osint_people_regon14_validate", "read",
     "Pure-Python REGON-14 checksum validator (no key, no network)."),
    ("osint_people_phone_carrier_pl", "read",
     "Polish phone prefix → carrier lookup (UKE + static 200+ table)."),
    ("osint_people_teryt_locality", "read",
     "TERYT locality lookup — honest-degrade (needs free key)."),
    ("osint_people_allegro_username", "read",
     "Allegro username lookup — honest-degrade (needs client_credentials)."),
    ("osint_people_email_breach_check", "read",
     "HIBP k-anonymity breach check on a target email."),
    ("osint_people_username_search", "read",
     "Username search via GitHub 60/h + sherlock local (no key)."),
    ("osint_people_darkweb_mention", "read",
     "Tor + pastebin HTML scrape for a target name/email."),
    ("osint_people_news_mention", "read",
     "Polish media mention scraper for a target name."),
    ("osint_people_facebook_public_album", "read",
     "Facebook public album HTML scrape (no login)."),
    ("osint_people_instagram_public", "read",
     "Instagram public profile HTML scrape (no key)."),
    ("osint_people_youtube_channel", "read",
     "YouTube channel HTML scrape (no key)."),
    ("osint_people_twitter_public", "read",
     "Twitter/X public profile HTML scrape (no key)."),
    ("osint_people_github_repos", "read",
     "GitHub REST 60/h unauth repo enumeration."),
    ("osint_people_linkedin_google_dork", "read",
     "LinkedIn lookup via Google dork HTML (no key)."),
    ("osint_people_relationship_inference", "read",
     "Relationship graph from co-authors + co-emails (no API)."),
    ("osint_people_pkd_activity", "read",
     "PKD activity lookup — honest-degrade (GUS BIR1 needs key)."),
    ("osint_people_knf_warning_check", "read",
     "KNF no-auth warning list XML parser."),
    ("osint_people_polish_media_count", "read",
     "Polish media mention count for a target name (no API)."),
    ("osint_people_political_exposed_check", "read",
     "PEP lookup — honest-degrade (no public API)."),
    ("osint_people_sanctions_check", "read",
     "OpenSanctions public search (no key)."),
    ("osint_people_property_search", "read",
     "Property search — honest-degrade (MSWiA no public API)."),
    ("osint_people_vehicle_history", "read",
     "CEPiK historia-pojazdu URL builder (honest-degrade on captcha)."),
    ("osint_people_full_report", "read",
     "Aggregate OP1-OP38 into a single JSON report."),
    ("osint_people_full_auto_adaptive", "intrusive",
     "AI orchestrator that picks the right OP1-OP39 sequence."),
]


# ---------------------------------------------------------------------------
# Post-Exploit (PP1-PP40)
# ---------------------------------------------------------------------------

POST_EXPLOIT_V3_METHODS: List[Tuple[str, str, str]] = [
    ("post_exploit_persistence_wmi", "intrusive",
     "WMI event subscription persistence (operator-confirm)."),
    ("post_exploit_persistence_schtasks", "intrusive",
     "Scheduled task persistence via schtasks (operator-confirm)."),
    ("post_exploit_persistence_registry", "intrusive",
     "Run/RunOnce registry persistence (operator-confirm)."),
    ("post_exploit_persistence_mbr", "destructive",
     "MBR persistence (operator-confirm; destructive)."),
    ("post_exploit_persistence_uefi", "destructive",
     "UEFI persistence (operator-confirm; destructive)."),
    ("post_exploit_persistence_hide_service", "intrusive",
     "Hide a malicious service from services.msc (operator-confirm)."),
    ("post_exploit_persistence_hide_process", "intrusive",
     "Hide a process from tasklist (operator-confirm)."),
    ("post_exploit_persistence_hide_file", "intrusive",
     "Hide a file from explorer via NTFS alternate data streams."),
    ("post_exploit_persistence_rootkit_install", "destructive",
     "Rootkit install (operator-confirm; destructive)."),
    ("post_exploit_anti_forensic_audit", "read",
     "Audit anti-forensic capabilities installed on the target."),
    ("post_exploit_av_edr_evasion", "intrusive",
     "AV/EDR evasion via known-bypass techniques (operator-confirm)."),
    ("post_exploit_sandbox_detection", "read",
     "Detect sandbox/Cuckoo via heuristic checks."),
    ("post_exploit_lateral_smb", "intrusive",
     "Lateral movement via SMB."),
    ("post_exploit_lateral_wmi", "intrusive",
     "Lateral movement via WMI."),
    ("post_exploit_lateral_winrm", "intrusive",
     "Lateral movement via WinRM."),
    ("post_exploit_lateral_ssh", "intrusive",
     "Lateral movement via SSH."),
    ("post_exploit_lateral_psremoting", "intrusive",
     "Lateral movement via PowerShell remoting."),
    ("post_exploit_lateral_rdp", "intrusive",
     "Lateral movement via RDP (operator-confirm)."),
    ("post_exploit_cred_lsass", "destructive",
     "LSASS credential dump (operator-confirm; destructive)."),
    ("post_exploit_cred_hashcat", "intrusive",
     "Hashcat against captured NT hashes."),
    ("post_exploit_cred_ticket_extract", "destructive",
     "Kerberos ticket extract (operator-confirm; destructive)."),
    ("post_exploit_cred_bloodhound", "intrusive",
     "BloodHound ingestor run against the target AD."),
    ("post_exploit_cred_sam", "destructive",
     "SAM hive dump (operator-confirm; destructive)."),
    ("post_exploit_cred_ntds", "destructive",
     "NTDS.dit extraction (operator-confirm; destructive)."),
    ("post_exploit_dcsync", "destructive",
     "DCSync (operator-confirm; destructive)."),
    ("post_exploit_golden_ticket", "destructive",
     "Golden-ticket forge (operator-confirm; destructive)."),
    ("post_exploit_silver_ticket", "destructive",
     "Silver-ticket forge (operator-confirm; destructive)."),
    ("post_exploit_skeleton_key", "destructive",
     "Skeleton-key install (operator-confirm; destructive)."),
    ("post_exploit_kerberoast", "intrusive",
     "Kerberoast against the target SPNs."),
    ("post_exploit_asrep_roast", "intrusive",
     "AS-REP roast against the target users."),
    ("post_exploit_ptt", "intrusive",
     "Pass-the-ticket (operator-confirm)."),
    ("post_exploit_ptk", "intrusive",
     "Pass-the-key (operator-confirm)."),
    ("post_exploit_john_ssh", "intrusive",
     "John the Ripper SSH-key cracking."),
    ("post_exploit_browser_creds", "intrusive",
     "Browser credential extraction (operator-confirm)."),
    ("post_exploit_email_creds", "intrusive",
     "Email credential extraction (operator-confirm)."),
    ("post_exploit_vpn_creds", "intrusive",
     "VPN credential extraction (operator-confirm)."),
    ("post_exploit_wifi_creds", "intrusive",
     "WiFi credential extraction (operator-confirm)."),
    ("post_exploit_exfil_http", "intrusive",
     "HTTP exfil channel (operator-confirm)."),
    ("post_exploit_exfil_dns", "intrusive",
     "DNS exfil channel (operator-confirm)."),
    ("post_exploit_full_auto_adaptive", "intrusive",
     "AI orchestrator that picks the right PP1-PP39 sequence."),
]


# ---------------------------------------------------------------------------
# Aggregate
# ---------------------------------------------------------------------------

V3_REGISTRY: Dict[str, List[Tuple[str, str, str]]] = {
    "wifi_attack": WIFI_ATTACK_V3_METHODS,
    "wifi_recon": WIFI_RECON_V3_METHODS,
    "ble_attack": BLE_ATTACK_V3_METHODS,
    "ble_recon": BLE_RECON_V3_METHODS,
    "osint_web": OSINT_WEB_V3_METHODS,
    "osint_people": OSINT_PEOPLE_V3_METHODS,
    "post_exploit": POST_EXPLOIT_V3_METHODS,
}


def list_v3_methods(category: str) -> List[str]:
    """Return the list of v3 method names for a category."""
    return [m[0] for m in V3_REGISTRY.get(category, [])]


def describe_v3_method(category: str, method: str) -> Optional[Dict[str, str]]:
    """Return {name, risk, description} for a v3 method, or None."""
    for name, risk, desc in V3_REGISTRY.get(category, []):
        if name == method:
            return {"name": name, "risk": risk, "description": desc}
    return None


def describe_v3_category(category: str) -> List[Dict[str, str]]:
    """Return all method descriptors in a v3 category."""
    return [
        {"name": n, "risk": r, "description": d}
        for n, r, d in V3_REGISTRY.get(category, [])
    ]


def all_v3_method_names() -> List[str]:
    """Return all v3 method names across all categories."""
    out: List[str] = []
    for cat in V3_REGISTRY:
        out.extend(list_v3_methods(cat))
    return out


def total_v3_count() -> Dict[str, int]:
    """Return a {category: count} dict for the v3 registry."""
    return {cat: len(meths) for cat, meths in V3_REGISTRY.items()}


def build_v3_prompt_stanza() -> str:
    """Build the prompt stanza for the LLM. Lists each v3 category
    with the count of methods and a one-line category description."""
    lines: List[str] = ["# Phase 2.4 v3 method registry (280 new methods, 40 × 7)\n"]
    summaries: Dict[str, str] = {
        "wifi_attack": ("WiFi attack v3 (AA1-AA40) — 40 polymorphic / "
                        "target-adaptive / universal methods"),
        "wifi_recon": ("WiFi recon v3 (RR1-RR40) — 40 universal methods "
                       "+ orchestrator"),
        "ble_attack": ("BLE attack v3 (BB1-BB40) — 40 universal methods "
                       "+ orchestrator"),
        "ble_recon": ("BLE recon v3 (BRR1-BRR40) — 40 universal methods "
                      "+ orchestrator"),
        "osint_web": ("OSINT web v3 (OW1-OW40) — no-key only "
                      "(CEIDG/KNF/HIBP/OSM Nominatim/crt.sh)"),
        "osint_people": ("OSINT people v3 (OP1-OP40) — no-key only "
                         "(PESEL/NIP/REGON/KRS/Phone_PL pure-algorithm "
                         "validators; honest-degrade for GUS/Allegro/"
                         "Wykop/LinkedIn)"),
        "post_exploit": ("Post-exploit v3 (PP1-PP40) — persistence + "
                         "lateral + cred-harvest + exfil + orchestrator"),
    }
    for cat, methods in V3_REGISTRY.items():
        lines.append(
            f"  # {cat} ({len(methods)} methods): {summaries.get(cat, '')}\n"
        )
    lines.append(
        "\n  To use: same chain-step shape as v2 methods:\n"
        "    {\"action\": \"wifi_attack\", \"args\": {\"method\": "
        "\"wifi_ap_blacklist_bypass\", ...}}\n"
        "  Risk levels drive the per-step ACCEPT gate.\n"
    )
    return "".join(lines)


V3_PROMPT_STANZA = build_v3_prompt_stanza()


__all__ = [
    "WIFI_ATTACK_V3_METHODS", "WIFI_RECON_V3_METHODS",
    "BLE_ATTACK_V3_METHODS", "BLE_RECON_V3_METHODS",
    "OSINT_WEB_V3_METHODS", "OSINT_PEOPLE_V3_METHODS",
    "POST_EXPLOIT_V3_METHODS",
    "V3_REGISTRY", "V3_PROMPT_STANZA",
    "list_v3_methods", "describe_v3_method", "describe_v3_category",
    "all_v3_method_names", "total_v3_count", "build_v3_prompt_stanza",
]
