"""
AIChainPlanner
==============
End-to-end AI-driven attack-chain synthesizer.

The orchestrator (``core/orchestrator/autonomous_orchestrator.py``)
historically used a hardcoded step ladder. The planner replaces that
with: ask the LLM to *generate* the step list from the target
description + KB CVE hits + matched tools, parse the JSON response,
and fall back through three layers when the LLM refuses or returns
unparseable output:

  1. ``AIBackend.query(domain, prompt, context=target)`` using the
     per-domain model from ``MODEL_CATALOG``. Strict JSON-only
     response schema enforced via the system prompt.
  2. On refusal or unparseable JSON, swap to the
     ``ExploitGenModelManager`` uncensored model
     (``core.ai_backend.exploit_generator``) so we don't get
     vendor-aligned refusals on offensive targets. The swap is
     one-shot — we ask the same prompt, get a fresh answer.
  3. On total LLM failure (no model reachable, both calls errored),
     fall back to a deterministic heuristic chain. This is the same
     pattern the legacy ``AIBackend._heuristic`` used, but emits the
     new ``ChainStep`` shape so the orchestrator can treat AI and
     heuristic output uniformly.

The planner also gets a 0-day concept path (``zero_day`` module):
when a chain ends without a working CVE / KB exploit, the planner
can add a single ``zero_day.propose`` step that asks the LLM to
draft a 0-day concept (technique hypothesis + indicators + draft
PoC outline). Operator ACK is required before the draft is saved
to ``data/zero_day_drafts/`` — never automatic.

Never fakes success: if the LLM returns garbage, the planner raises
``ChainPlanError`` after the heuristic has had its turn. The
orchestrator can then surface the error to the operator and stop.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)


class ChainPlanError(RuntimeError):
    """Raised when the planner cannot produce a usable chain after all
    fallbacks have been exhausted. The orchestrator should surface the
    error to the operator and stop the chain."""


# JSON schema for the chain step we ask the LLM to produce. Kept
# permissive (additionalProperties allowed) so the LLM can add fields
# like ``notes`` that we just ignore.
_CHAIN_STEP_SCHEMA_HINT = """{
  "chain": [
    {
      "action": "<one of: mcp_call, post_exploit, external_terminal, zero_day_propose, zero_day_build, zero_day_execute, mt7921e_test_injection, mt7921e_inject, external_inject, recon_probe, ble_probe, ble_attack, wifi_attack, post_exploit_ext, extended_wifi, ble_post_exploit, osint_ext, extended_ble, open_shell, open_post_access_tui, cve_to_exploit, crack, crack_gpu, pmkid, wps_pixie, wps_online, join_network, host_discovery, deploy_payload, run_tool, parse, decide, osint_probe, post_exploit_probe, live_edit, tool_install>",
      "tool": "<canonical tool name, e.g. airodump-ng, aireplay-ng, msfconsole, mt7921e.test_injection, cve_lookup>",
      "args": { ... tool-specific args ... },
      "rationale": "<one-sentence why this step>",
      "expected_outcome": "<what success looks like>",
      "risk_level": "<read | intrusive | destructive>",
      "expected_runtime_seconds": <int>
    },
    ...
  ]
}"""


# Live-edit directive — teach the LLM about runtime AST patching
LIVE_EDIT_PROMPT_STANZA = (
    "  - live_edit (risk INTRUSIVE, GATED) applies a runtime AST patch to\n"
    "    one runner method. The patch is from a SAFE-PATCH CATALOG in\n"
    "    core.live_edit.test_patches; you NAME it by id, you do NOT write\n"
    "    code. Available safe-patches:\n"
    "      * add_optional_arg(method, arg_name, default) — add a new kwarg\n"
    "      * set_which_fail_to_real(method, tool_name, real_path) — early-OK a which() check\n"
    "      * swap_retry_count(method, new_count) — multiply a range() bound\n"
    "      * add_logging(method) — mark data['live_edited']=True at the top\n"
    "    Step shape: {\"action\": \"live_edit\", \"args\": {\"patch_id\": <id>,\n"
    "    \"target_runner\": \"core.wifi_attack.runner\", \"target_method\":\n"
    "    \"_pmkid_capture\", \"params\": {...}, \"rationale\": \"...\"}}.\n"
    "    The per-step ACCEPT gate already fired in _walk_ai_step — these\n"
    "    steps do NOT re-confirm. The validator in core.live_edit.patch\n"
    "    rejects any patch that touches os.system / subprocess.call /\n"
    "    __import__ / eval / exec / shell metas in string literals.\n"
)

# Tool-install directive — teach the LLM about auto-installing missing tools
TOOL_INSTALL_PROMPT_STANZA = (
    "  - tool_install (risk INTRUSIVE, GATED) installs a missing tool from\n"
    "    core.tool_installer.TOOL_CATALOG (apt/pip/git). Step shape:\n"
    "    {\"action\": \"tool_install\", \"args\": {\"tool\": \"<name>\"}}. The\n"
    "    catalog covers gatttool→bluez, hashcat→hashcat, mimikatz→git,\n"
    "    iw/airodump-ng/aireplay-ng/aircrack-ng→aircrack-ng,\n"
    "    hcx*→hcxtools, mdk3/mdk4, bully/reaver, responder/impacket/*→pip,\n"
    "    mimikatz/routersploit/empire/sliver/etc→git clone into toolboxes/.\n"
    "    The per-step ACCEPT gate already fired in _walk_ai_step; the\n"
    "    install goes through and is logged to core/tool_installer/_log.json\n"
    "    for audit. If install fails the runner degrades honestly.\n"
)

# osint_ext action — AI-driven extended OSINT
OSINT_EXT_PROMPT_STANZA = (
    "  - osint_ext (risk READ, GATED) runs one of the extended OSINT\n"
    "    algorithms in core/osint/runner_ext.py. The set covers people\n"
    "    graph deep walks, email pattern mining, leaked-credential breach\n"
    "    search (without ever inlining harvested creds into shell argv),\n"
    "    domain/IP WHOIS, cert transparency, ASN footprint, social-media\n"
    "    cross-reference, dark-web mention monitoring, geolocation\n"
    "    triangulation, image EXIF/metadata extraction, and the LLM\n"
    "    coordinator osint_ext_full_auto. Every step is per-step ACCEPT\n"
    "    gated. You may also drive these via mcp_call with the per-method\n"
    "    tool names (osint_ext_people_graph_deep, ...). Method names\n"
    "    (set args.method to one of): see core/osint/runner_ext.py\n"
    "    OSINT_EXT_METHODS. Phase 1.6 additions (all READ; degrade on\n"
    "    missing SHODAN_API_KEY or bs4/requests):\n"
    "    shodan_exploitdb_download_eid (shodan.exploitdb.download —\n"
    "    fetches raw exploit source by ExploitDB id; NEVER auto-runs),\n"
    "    ct_log_subdomain_miner_dedup_with_isactive (crt.sh JSON query\n"
    "    + dedup by not_after — passive subdomain discovery,\n"
    "    complementary to subfinder/amass),\n"
    "    shodan_wps_bssid_google_geolocation (BSSID -> (lat, lon) via\n"
    "    shodan WPS — independent of Wigle for two-source scoring),\n"
    "    shodan_dataloss_db_filtered_search (shodan dataloss DB with\n"
    "    structured breach metadata), and\n"
    "    exploits_shodan_bs4_scrape_cve_to_exploit_links (HTML scrape\n"
    "    fallback for cve_to_exploit when SHODAN_API_KEY is absent).\n"
)

# extended_ble action — AI-driven extended BLE 5.x
EXTENDED_BLE_PROMPT_STANZA = (
    "  - extended_ble (risk INTRUSIVE, GATED) runs one of the extended\n"
    "    BLE 5.x algorithms in core/extended_ble/runner.py. The set\n"
    "    covers LE Coded PHY long-range, LE 2M PHY, LE Audio, periodic\n"
    "    advertising, extended advertising, channel sounding, and the\n"
    "    LLM coordinator extended_ble_full_auto. Every step is per-step\n"
    "    ACCEPT gated. You may also drive these via mcp_call with the\n"
    "    per-method tool names (extended_ble_*). Method names (set\n"
    "    args.method to one of): see core/extended_ble/runner.py\n"
    "    EXTENDED_BLE_METHODS. Phase 1.6 additions:\n"
    "    ble_multi_encoding_value_auto_decode_pipeline (PURE PYTHON,\n"
    "    READ — runs a payload through 4 encoders + 12 numeric decoders\n"
    "    + battery percent heuristic; emit when a GATT notification\n"
    "    yields a vendor-proprietary payload you need to interpret),\n"
    "    ble_handle_0x0003_local_name_writable_classifier (INTRUSIVE —\n"
    "    gatttool write-probe of GAP Device Name handle 0x0003;\n"
    "    vulnerable-firmware-class fingerprint), and\n"
    "    ble_writable_char_black_box_audit (INTRUSIVE — bleak\n"
    "    enumerate+write-probe of every char; surfaces open writes\n"
    "    without authorization).\n"
)

# cve_to_exploit action — AI-driven CVE-to-exploit generation
CVE_TO_EXPLOIT_PROMPT_STANZA = (
    "  - cve_to_exploit (risk INTRUSIVE, GATED) drives the NVD-keyed\n"
    "    CVE -> exploit generation pipeline in core/cve_to_exploit/pipeline.py.\n"
    "    Step shape: {\"action\": \"cve_to_exploit\", \"args\": {\"cve_id\":\n"
    "    \"CVE-YYYY-NNNN\"}}. The pipeline calls NVD with the operator-\n"
    "    provided key (get_nvd_key()), then prompts an uncensored code-\n"
    "    architect model via ollama (selected by ExploitGenModelManager,\n"
    "    default fallback order in core.ai_backend.exploit_generator) and\n"
    "    writes the result to seed['exploits'] and report['exploits'].\n"
    "    When a vendor vuln scan or CVE-bearing recon step lands a real\n"
    "    CVE id, you SHOULD emit a follow-up cve_to_exploit step before\n"
    "    pivoting to a crack / zero_day tail — the AI-generated code is\n"
    "    ALWAYS drafted, NEVER auto-executed: every cve_to_exploit step\n"
    "    is per-step ACCEPT gated at run time, and the post-exploitation\n"
    "    that uses the draft is itself a separate gated step. NEVER\n"
    "    fabricate CVE ids, cracked PSKs, cleartext creds, or NTLM\n"
    "    hashes. The pipeline never raises; on NVD error / model\n"
    "    refusal / ollama unreachable it returns ok=False with an\n"
    "    error string. You may also drive this via mcp_call with the\n"
    "    tool name cve_to_exploit.\n"
)


_SYSTEM_PROMPT = (
    "You are an expert penetration tester. Given a target and the\n"
    "available tools, produce a concrete, ordered attack chain as\n"
    "strict JSON matching this schema:\n\n"
    f"{_CHAIN_STEP_SCHEMA_HINT}\n\n"
    "Rules:\n"
    "  - The chain is a JSON object with a single top-level key 'chain'\n"
    "    whose value is a list of step objects.\n"
    "  - Steps are ordered; each step's success enables the next.\n"
    "  - Prefer the smallest set of steps that achieves the goal.\n"
    "  - Use the 'tool' field to name a real Kali tool or an MCP\n"
    "    function ('mt7921e.*', 'cve_lookup', etc.) that exists in the\n"
    "    available tools list provided in [CONTEXT].\n"
    "  - risk_level is 'read' (no side effect), 'intrusive' (touches\n"
    "    the target, e.g. deauth, capture), or 'destructive' (modifies\n"
    "    state, e.g. hostapd, msfconsole session open).\n"
    "  - expected_runtime_seconds is a conservative estimate (>= 1).\n"
    "  - If you cannot produce a chain, return exactly: {\"refusal\": true, \"reason\": \"<why>\"}\n"
    "  - Do NOT include any prose outside the JSON object.\n"
    "  - You MAY emit mt7921e_test_injection / mt7921e_inject steps when the\n"
    "    [CONTEXT] target indicates an mt7921e adapter with packet-injection\n"
    "    capability. mt7921e_test_injection is intrusive (aireplay-ng --test\n"
    "    injection-quality probe); mt7921e_inject is destructive (raw 802.11\n"
    "    frame injection, e.g. deauth).\n"
    "  - The AVAILABLE MCP TOOLS list shows each tool's schema, examples,\n"
    "    and risk_level. You MUST pick a tool whose schema matches the\n"
    "    target/CVE and set the step's risk_level from that tool's\n"
    "    risk_level. For mt7921e_inject, args.mode is one of\n"
    "    deauth|fakeauth|beacon_flood|arp_replay|chopchop|fragmentation|\n"
    "    cts_rts — choose the mode appropriate for the target (e.g.\n"
    "    deauth when a client is associated, fakeauth to force a handshake\n"
    "    when no client is present, beacon_flood for hidden-SSID reveal,\n"
    "    arp_replay for WEP).\n"
    "  - open_shell (risk intrusive) opens an interactive shell with the\n"
    "    target using captured credentials; args =\n"
    "    {protocol: \"ssh\"|\"telnet\"|\"http\"|\"nc\", host, user?, cred?}.\n"
    "    Emit open_shell ONLY after access is achieved (a prior step's\n"
    "    data carried creds or a session_id).\n"
    "  - external_inject drives a standalone injection tool from the\n"
    "    AVAILABLE MCP TOOLS list (nemesis_inject, inject_tool_inject,\n"
    "    wpr_tx, cse508_dns_inject, mt7921e_research_firmware). Set ``tool``\n"
    "    to the MCP tool name and ``args`` to that tool's schema. Use\n"
    "    nemesis_inject / inject_tool_inject for wired-side or evil-twin\n"
    "    L2 forging (ARP/DHCP/ICMP/TCP) once you have a foothold on the\n"
    "    target's L2; wpr_tx for raw 802.11 TX on non-mt7921e injection-\n"
    "    capable adapters; cse508_dns_inject for DNS spoofing on a\n"
    "    bridged evil-twin; mt7921e_research_firmware (risk read) for\n"
    "    firmware/driver-level research on the operator's MediaTek MT7922\n"
    "    (mt7921e) card — closed-firmware offline RE; live_test is NOT\n"
    "    supported. These\n"
    "    are destructive (frame/packet injection) unless noted — inherit\n"
    "    the tool's risk_level.\n"
    "  - recon_probe (risk read, PASSIVE) runs one of the 6 core recon\n"
    "    steps OR the 9 novel WiFi recon algorithms implemented in\n"
    "    catalog_recon. Set args.method to one of: wps | clients | cves |\n"
    "    weakpass | kb_hits | catalog_runs | probe_profile | hidden_ssid |\n"
    "    signal_map | handshake_harvest | eapol_monitor | channel_plan |\n"
    "    deauth_detect | gps_wardrive | beacon_parse, plus target fields\n"
    "    (bssid, channel, interface). The 6 core steps are the same ones\n"
    "    CatalogRecon.run() runs pre-chain (now individually dispatchable):\n"
    "    wps -> wash/reaver WPS discovery (locked state, model, version);\n"
    "    clients -> airodump-ng station CSV (associated client MACs,\n"
    "    vendor, signal, probed SSIDs);\n"
    "    cves -> vendor/model/firmware -> NVD candidate CVE list (real NVD\n"
    "    query via the operator-provided key; never fabricated CVE ids);\n"
    "    weakpass -> best weakpass_*.txt wordlist for the target;\n"
    "    kb_hits -> local KB lookup of BSSID/vendor/SSID prior findings;\n"
    "    catalog_runs -> catalog tool enumeration for the target profile.\n"
    "    The 9 novel probes are pre-attack 'what is the target telling us'\n"
    "    probes — NO deauth, NO active PMKID capture, NO injection:\n"
    "    probe_profile -> each client's Preferred Network List + randomized-\n"
    "    MAC flag + shared-ownership clusters (Jaccard>=0.6);\n"
    "    hidden_ssid -> reveal a cloaked SSID from probe-resp/assoc-req;\n"
    "    signal_map -> per-AP RSSI EMA + log-distance distance + total RF\n"
    "    exposure dBm (linear power summation);\n"
    "    handshake_harvest -> detect EAPOL M1-M4 + PMKID feasibility\n"
    "    (RSN+PSK+PMKID-friendly vendor) — tells you whether to emit the\n"
    "    gated 'pmkid' step next;\n"
    "    eapol_monitor -> EAP method + cleartext identity (flags\n"
    "    is_enterprise: PEAP/TTLS/FAST/LEAP/MD5);\n"
    "    channel_plan -> 2.4+5GHz congestion survey + channel-hop dwell\n"
    "    plan with the target channel pinned;\n"
    "    deauth_detect -> 20s passive watch: deauth flood (>=15), probe\n"
    "    flood (>=50), evil-twin candidates (same SSID on >=2 BSSIDs);\n"
    "    gps_wardrive -> gpsd fix + WiGLE-1.4 CSV + offline .22000/TSV/\n"
    "    GPX fusion (pass args.artifacts);\n"
    "    beacon_parse -> RSN IE decode: group/pairwise ciphers, AKM(s),\n"
    "    PMF state, WPS, WPA3 (SAE/OWE) flag + fingerprint hash.\n"
    "    Emit recon_probe steps EARLY (before the attack chain) to enrich\n"
    "    the target — e.g. beacon_parse + handshake_harvest + eapol_monitor\n"
    "    first, then branch: handshake_harvest.pmkid_feasible=true -> emit\n"
    "    'pmkid'; eapol_monitor.is_enterprise=true -> route to 802.1x /\n"
    "    EAP-downgrade or a zero_day tail instead of a PSK crack;\n"
    "    beacon_parse.is_wpa3=true -> note SAE defeats the PMK handshake,\n"
    "    attempt PMKID, else route to dragonblood CVEs / zero_day tail.\n"
    "    You may also drive the same probes via mcp_call with the per-\n"
    "    method tool names shown in AVAILABLE MCP TOOLS\n"
    "    (recon_probe_profile, recon_probe_hidden_ssid, ...).\n"
    "    Phase 1.6.E added 9 more recon methods in core/recon/runner.py,\n"
    "    dispatched through the same recon_probe action:\n"
    "    mac_oui_longest_prefix_match_vendor_tally -> wireshark manuf\n"
    "    longest-prefix OUI lookup + per-vendor tally (pure logic;\n"
    "    hermetic; falls back to a 4-row demo table when\n"
    "    args.manuf_path is missing);\n"
    "    evil_twin_ssid_bssid_pair_diff_detector -> same-SSID multi-\n"
    "    BSSID detector; flags divergent channel or encryption sets\n"
    "    (pure logic; hermetic; use after a beacon_parse-style scan);\n"
    "    ema_smoothed_rssi_with_trend_arrows -> exponential moving\n"
    "    average of an RSSI series + per-step ▲/→/▼ trend arrow (pure\n"
    "    logic; hermetic; useful for live signal-quality display);\n"
    "    nmcli_escaped_colon_tokenizer -> robustly parse a list of\n"
    "    'nmcli -t -f BSSID,SSID,...' lines that may have colons or\n"
    "    backslash-escaped colons in the SSID (pure logic; hermetic);\n"
    "    time_preserving_upsert_with_separate_history -> SQLite upsert\n"
    "    keyed by args.key; previous row archived to <table>__history\n"
    "    with a superseded_at timestamp before the upsert (pure\n"
    "    sqlite3 stdlib; hermetic; passes back history_archived);\n"
    "    log_distance_path_loss_distance_estimator -> invert the log-\n"
    "    distance path-loss model to estimate distance in meters from\n"
    "    RSSI (pure math; hermetic; degrades on rssi below floor);\n"
    "    wigle_v2_first_last_cursor_pagination -> WiGLE v2 API search\n"
    "    with 'searchAfter' cursor pagination; collects first+last\n"
    "    items + page count (real subprocess; degrades when\n"
    "    WIGLE_API_KEY is unset or requests is missing; hermetic with\n"
    "    a mocked http_get);\n"
    "    nmap_nse_vuln_script_chaining -> 3-pass nmap: (1) service\n"
    "    detection, (2) vuln NSE category, (3) vuln+exploit NSE\n"
    "    category — read-only (degrades when nmap is not installed);\n"
    "    parallel_domain_risk_score_5signal -> parallel 5-signal\n"
    "    domain risk score (DoH A, DoH TXT/SPF, crt.sh, RDAP, HTTPS\n"
    "    HEAD); returns a 0.0-1.0 composite (real subprocess over\n"
    "    cloudflare-dns / crt.sh / rdap.org; hermetic with a mocked\n"
    "    http_get). Prefer emitting these after the catalog_recon\n"
    "    probes (beacon_parse, signal_map, channel_plan) so the new\n"
    "    methods can build on the already-enriched seed.\n"    "  - ble_probe (risk read, PASSIVE) runs one of 16 BLE recon algorithms\n"
    "    implemented in core/ble/runner.py (TP-LINK UB500 Plus / hci0). Set\n"
    "    args.method to one of: parse_advertising_data | manufacturer_oracle |\n"
    "    analyze_location_leak | estimate_battery_profile | map_gatt_services |\n"
    "    connection_graph_active | calculate_exfil_potential |\n"
    "    predict_pairing_vulnerability | recon_ota_update |\n"
    "    assess_mitm_feasibility | firmware_version_predictor |\n"
    "    cross_device_linker_ble | ble_anomaly_detector | hid_recon |\n"
    "    smarthome_enumerator | tracking_resistance_test;\n"
    "    args.adapter defaults to hci0 (the UB500 Plus dongle);\n"
    "    cross_device_linker_ble also needs args.wifi_mac + args.ble_mac.\n"
    "    These are pre-attack 'what is the BLE target telling us' probes —\n"
    "    NO pairing, NO write, NO active GATT writes:\n"
    "    parse_advertising_data -> decode AD structures (Flags, Local Name,\n"
    "    MFR data, service UUIDs) from raw advert bytes;\n"
    "    manufacturer_oracle -> company-id + OUI vendor + iBeacon decode\n"
    "    (model is a heuristic, NOT a trained ML prediction);\n"
    "    analyze_location_leak -> flag iBeacons leaking a fixed UUID and\n"
    "    the operator's location fingerprint;\n"
    "    estimate_battery_profile -> read 0x2A19 battery level via gatttool\n"
    "    (degrades cleanly when gatttool absent);\n"
    "    map_gatt_services -> map discovered service UUIDs to named GATT\n"
    "    profiles (Battery, DIS, HID, etc.);\n"
    "    connection_graph_active -> co-appearance graph of devices seen in\n"
    "    the same scan window (entity clusters);\n"
    "    calculate_exfil_potential -> per-device exfil bandwidth from advert\n"
    "    payload size + interval (pure arithmetic);\n"
    "    predict_pairing_vulnerability -> Just-Works / SSP-Downgrade\n"
    "    heuristic (labeled 'heuristic (not trained)', never a fabricated\n"
    "    ML score);\n"
    "    recon_ota_update -> surface OTA/DFU service UUIDs + read DIS\n"
    "    firmware/model strings via gatttool (passive — no firmware download);\n"
    "    assess_mitm_feasibility -> RSSI-spread MITM feasibility heuristic\n"
    "    (Secure-Connections needs a pairing exchange — noted);\n"
    "    firmware_version_predictor -> DIS firmware-revision read +\n"
    "    Levenshtein fuzzy match to a known-versions table (heuristic, no\n"
    "    fabricated CVE list);\n"
    "    cross_device_linker_ble -> OUI-agreement same-device test for a\n"
    "    WiFi MAC + BLE MAC pair (args.wifi_mac + args.ble_mac);\n"
    "    ble_anomaly_detector -> passive background-traffic stats + MAC-flood\n"
    "    threshold heuristic (Autoencoder not trained — labeled);\n"
    "    hid_recon -> HID device detect (service 0x1812 / Appearance) +\n"
    "    optional Report Map (0x2A4B) read;\n"
    "    smarthome_enumerator -> hub/bridge fingerprint (Hue, TRÅDFRI,\n"
    "    Xiaomi, Tuya) by name/UUID/company-id/OUI;\n"
    "    tracking_resistance_test -> address-type observation (public =\n"
    "    trackable, random/RPA = privacy); IRK recovery not trained.\n"
    "    Emit ble_probe steps EARLY for BLE targets (before any\n"
    "    BLE attack chain) to enrich the target — e.g.\n"
    "    parse_advertising_data + manufacturer_oracle first, then branch:\n"
    "    ibeacon present -> analyze_location_leak; GATT services mapped ->\n"
    "    estimate_battery_profile + map_gatt_services; OTA surface ->\n"
    "    recon_ota_update + firmware_version_predictor; HID -> hid_recon;\n"
    "    hub -> smarthome_enumerator; random-address +\n"
    "    Just-Works -> route to the gated BLE attack / zero_day tail. You\n"
    "    may also drive these via mcp_call with the per-method tool names\n"
    "    (ble_probe_parse_advertising_data, ble_probe_manufacturer_oracle, ...).\n"
    "  - ble_attack (risk INTRUSIVE, GATED) runs one of 19 BLE attack /\n"
    "    post-exploitation algorithms in core/ble/attack_runner.py. Set\n"
    "    args.method to one of: gatt_write_exploit | firmware_dump_via_gatt |\n"
    "    write_led | write_lock | pairing_pin_bruteforce | export_session |\n"
    "    ble_long_range_scan | ble_adv_data_injection |\n"
    "    ble_connection_hijacking | ble_man_in_the_middle_attack |\n"
    "    ble_audio_sniffing | ble_temperature_spoofing |\n"
    "    ble_keyboard_injection | ble_energy_drain |\n"
    "    ble_multi_connection_pivot | ble_whitelist_bypass |\n"
    "    ble_swarm_coordinator | ble_auto_root |\n"
    "    ble_auto_attack_executor;\n"
    "    args.address is the target BLE MAC (required for all but\n"
    "    export_session, ble_auto_attack_executor (uses plan_steps),\n"
    "    ble_audio_sniffing, ble_long_range_scan, ble_whitelist_bypass,\n"
    "    and ble_swarm_coordinator which take addresses/adapters lists).\n"
    "    Real gatttool/bluetoothctl/hcitool/btmgmt/btmon subprocess;\n"
    "    degrades cleanly when the tool is absent or the device is\n"
    "    unreachable — it NEVER fabricates an 'exploit succeeded'\n"
    "    verdict (acceptance is the gatttool return code + 'Write\n"
    "    successful' line; pairing success is bluetoothctl's 'Pairing\n"
    "    successful' line; the audio sniffer records what btmon actually\n"
    "    captured; the LLM-coordinator ble_auto_attack_executor returns\n"
    "    ok=False 'requires plan' if no plan_steps is given). Emit AFTER\n"
    "    ble_probe recon has enriched the target:\n"
    "    gatt_write_exploit -> write probe payloads to each WRITE\n"
    "    characteristic (args.uuids / args.payloads override defaults);\n"
    "    firmware_dump_via_gatt -> block-read a firmware characteristic\n"
    "    (args.handle, args.max_blocks, args.out_path) and reconstruct bytes;\n"
    "    write_led -> write 0x01/0x00 to LED (0x2A44 or args.uuid);\n"
    "    write_lock -> write 0x00 to Lock State (0x2A1D) to unlock;\n"
    "    pairing_pin_bruteforce -> loop a candidate PIN list via\n"
    "    bluetoothctl (args.pin_list, args.max_attempts=10); bounded;\n"
    "    export_session -> serialize args.session to args.out_path (read);\n"
    "    ble_long_range_scan -> enable LE Coded PHY via btmgmt + scan;\n"
    "    ble_adv_data_injection -> build a scapy BTLE_ADV frame;\n"
    "    ble_connection_hijacking -> replay a captured CONNECT_REQ\n"
    "    (args.pdu_b64 required); ble_man_in_the_middle_attack -> plan\n"
    "    a gatttool+btproxy MITM relay (NEVER auto-started);\n"
    "    ble_audio_sniffing -> btmon btsnoop LE Audio capture\n"
    "    (args.timeout, args.out_path);\n"
    "    ble_temperature_spoofing -> write Health Thermometer 0x2A1C;\n"
    "    ble_keyboard_injection -> inject HID over GATT (0x2A4D) reports;\n"
    "    ble_energy_drain -> plan a sustained L2CAP 7.5ms drain\n"
    "    (NEVER auto-lecup; plan only);\n"
    "    ble_multi_connection_pivot -> parallel hcitool lecc across\n"
    "    args.addresses; ble_whitelist_bypass -> sample hcitool lerand\n"
    "    (heuristic; NEVER fabricates an IRK recovery);\n"
    "    ble_swarm_coordinator -> drive a sub_method from up to N hci\n"
    "    adapters (per-adapter envelopes, never a fabricated swarm\n"
    "    success); ble_auto_root -> chain pairing_pin_bruteforce +\n"
    "    gatt_write_exploit + firmware_dump_via_gatt (ok=True only when\n"
    "    ALL stages succeeded; partial success is ok=False with per-stage\n"
    "    errors); ble_auto_attack_executor -> LLM-coordinator that\n"
    "    dispatches a caller-supplied args.plan_steps (returns ok=False\n"
    "    'requires plan' if no plan is given; never fabricates a plan of\n"
    "    its own).\n"
    "    These are INTRUSIVE — every ble_attack step is per-step\n"
    "    ACCEPT-gated at run time (the orchestrator fires the gate BEFORE\n"
    "    dispatch; default-deny). You may also drive these via mcp_call with\n"
    "    the per-method tool names (ble_attack_gatt_write_exploit, ...).\n"
    "  - wifi_attack (risk INTRUSIVE/DESTRUCTIVE, GATED) runs one of 41\n"
    "    WiFi attack algorithms in core/wifi_attack/runner.py (MT7922 /\n"
    "    mt7921e). Set args.method to one of: evil_twin_automated |\n"
    "    wpa_dragonblood_test | kr00k_vulnerability_check | fragmentation_attack\n"
    "    | beacon_manipulation_attack | pmf_bypass_test | wps_null_pin_attack\n"
    "    | band_steering_attack | client_credential_hijack |\n"
    "    automatic_handshake_cracker | mac_spoofer_rotating |\n"
    "    captive_portal_detection_and_bypass | sig_strength_prediction_model\n"
    "    | dynamic_channel_hopping_rf_survey | packet_injection_test |\n"
    "    wifi_signal_quality_analyzer | wifi_auto_attack_executor |\n"
    "    pmkid_ai_prioritizer | sae_group_downgrade | targeted_deauth_timing |\n"
    "    beacon_flood_adaptive | client_power_save_exploit |\n"
    "    wifi_timing_side_channel | ap_overload_dos | wpa2_kr00k_all_channel |\n"
    "    ai_driven_wep_attack | full_auto_pwn | karma_mana | mdk3_attack |\n"
    "    mdk4_attack | eap_downgrade | hashcat_16800 | hashcat_22001 |\n"
    "    live_hcxdumptool | channel_following_loop | disassociation_frame |\n"
    "    probe_response_craft | assoc_request_craft |\n"
    "    vuln_classification_by_encryption_rule_engine (PURE LOGIC, READ —\n"
    "    maps encryption to applicable attack vectors; emit EARLY to plan\n"
    "    the rest of the chain) |\n"
    "    phase_based_ssid_aware_wordlist_forge (PURE LOCAL I/O, READ —\n"
    "    4-phase SSID-aware wordlist generator; emit before any\n"
    "    automatic_handshake_cracker / hashcat_* step) |\n"
    "    scapy_flooder_auth_assoc_probe_beacon_deauth (INTRUSIVE, builds\n"
    "    802.11 mgmt frames for any subtype — auth/assoc/reassoc/probe/\n"
    "    beacon/deauth/disassoc; real send requires monitor-mode iface);\n"
    "    args.interface defaults to wlan0mon; args.bssid/channel/station for\n"
    "    RF/injection attacks; args.cap_file/hash_file/wordlist for crack\n"
    "    pipelines; args.plan_steps (list of {method,args}) for the LLM-\n"
    "    coordinated executors. Real subprocess/scapy/parse; NEVER fabricates\n"
    "    a verdict, a CVE id, or a cracked PSK — EDB/CVE ids come only from\n"
    "    real searchsploit output, cracked_psk only from real hashcat stdout;\n"
    "    the TRAINED-ML modules (sig_strength_prediction_model,\n"
    "    pmkid_ai_prioritizer) report data.model='heuristic (not trained)'.\n"
    "    Emit AFTER recon_probe has enriched the target and branch on the\n"
    "    signal, e.g. beacon_parse.is_wpa3=true -> sae_group_downgrade /\n"
    "    wpa_dragonblood_test; handshake_harvest.pmkid_feasible=true ->\n"
    "    hashcat_16800 (PMKID) else live_hcxdumptool + hashcat_22001;\n"
    "    eapol_monitor.is_enterprise=true -> eap_downgrade; WEP target ->\n"
    "    ai_driven_wep_attack (arp_replay/chopchop/fragmentation). Many are\n"
    "    DESTRUCTIVE (evil_twin_automated, karma_mana, mdk3/mdk4_attack,\n"
    "    mac_spoofer_rotating, beacon_flood_adaptive, disassoc/probe/assoc\n"
    "    craft) — every wifi_attack step is per-step ACCEPT-gated at run time\n"
    "    (the orchestrator fires the gate BEFORE dispatch; default-deny).\n"
    "    You may also drive these via mcp_call with the per-method tool names\n"
    "    (wifi_attack_evil_twin_automated, ...).\n"
    "  - PERSISTENCE: keep attacking until access is achieved AND then\n"
    "    continue through auto post-exploitation. Do NOT stop the chain on\n"
    "    a failed step — re-plan an alternate strategy from the live\n"
    "    outcome (failed crack -> crack_gpu / pmkid / wps_pixie; failed\n"
    "    pmkid -> handshake capture; failed BLE pairing -> alternate device\n"
    "    / zero_day tail). Only stop when access is achieved AND the post-\n"
    "    exploitation sequence has run. A recovered creds/PSK/PIN/session\n"
    "    flips report['access']['achieved']; then emit join_network ->\n"
    "    host_discovery -> deploy_payload -> open_shell, and the post-\n"
    "    exploitation probes (post_exploit_probe_*). Each re-planned step\n"
    "    is still per-step ACCEPT-gated at run time."
    "  - crack (risk intrusive) runs aircrack-ng dictionary attack on a\n"
    "    captured handshake; args = {cap_file, bssid?, wep?}. The orchestrator\n"
    "    resolves the wordlist automatically (weakpass → rockyou) — you do\n"
    "    NOT need to set args.wordlist unless you want a specific one. A\n"
    "    recovered PSK is propagated so later steps see access achieved.\n"
    "  - crack_gpu (risk intrusive) runs hashcat GPU mask bruteforce,\n"
    "    `-m 22000 -a 3 <mask>`; args = {cap_file|hash_file, mask?}. Emit it\n"
    "    AFTER a dictionary crack fails (fan-out), or for short numeric\n"
    "    PSKs. Default mask is 8 digits; emit common masks (?d?d?d?d?d?d?d?d,\n"
    "    ?l?l?l?l?l?l?l?l, ?d?d?d?d?d?d?d?d?d?d) as separate optional steps.\n"
    "  - pmkid (risk intrusive) runs the clientless PMKID attack (hashcat\n"
    "    -m 22000) — prefer it when the target has NO associated client.\n"
    "    args = {cap_file|hash_file, bssid?}.\n"
    "  - wps_pixie (risk intrusive) runs the Pixie-Dust WPS attack (reaver\n"
    "    -K); wps_online runs the slower online PIN brute (bully/reaver).\n"
    "    Emit these FIRST when target.wps is true — they often yield the\n"
    "    PSK without a handshake. args = {bssid, interface?}. A recovered\n"
    "    PIN/PSK is propagated.\n"
    "  - Per-encryption strategy: WEP → mt7921e_inject arp_replay + chopchop\n"
    "    (the modes already exist) then crack with wep=true; WPA/WPA2 →\n"
    "    pmkid (clientless) else airodump+deauth+crack, plus crack_gpu as a\n"
    "    fan-out; WPS → wps_pixie then wps_online; WPA3 → note SAE/Dragonfly\n"
    "    defeats the PMK handshake path, attempt PMKID, else route to\n"
    "    dragonblood CVEs / a zero_day tail. Keep attacking until access is\n"
    "    gained — a recovered creds/PSK/PIN flips report['access'].\n"
    "  - Once access is achieved (a prior step carried creds/PSK/PIN), emit\n"
    "    the post-access lateral-movement sequence in order:\n"
    "    join_network (wpa_supplicant associate with the recovered PSK;\n"
    "    args = {ssid, psk?, interface?} — psk defaults to the recovered\n"
    "    cred) → host_discovery (arp-scan/nmap -sn the joined subnet; args\n"
    "    = {subnet?, iface?}) → deploy_payload (stage a polymorphic\n"
    "    payload + multi/handler per discovered device, one persistent\n"
    "    window each; args = {devices?, lhost?, lport?, payload?} — devices\n"
    "    default to report['access']['devices']) → open_shell per device\n"
    "    (ssh/telnet/http/nc using the recovered creds). This makes the\n"
    "    connection between the operator's host and the attacked network's\n"
    "    devices. Each step is per-step ACCEPT-gated at run time.\n"
    "  - osint_probe (risk read, PASSIVE) runs one of 4 OSINT intelligence\n"
    "    algorithms implemented in core/osint/runner.py. Set args.method to\n"
    "    one of: username_patterns, breach_correlate, phone_carrier,\n"
    "    social_graph. Set args.target to the subject (username/email/phone/\n"
    "    handle). Emit EARLY in OSINT engagements to enrich target profile\n"
    "    before any active scanning. All probes are offline-safe and never\n"
    "    raise exceptions. You may also call these via mcp_call with tool\n"
    "    names osint_probe_username_patterns, osint_probe_breach_correlate,\n"
    "    osint_probe_phone_carrier, osint_probe_social_graph.\n"
    "  - post_exploit_probe (risk intrusive) runs one of 4 post-exploitation\n"
    "    analysis algorithms in core/post_exploit/runner.py. Set args.method\n"
    "    to one of: priv_esc_check, cred_enumerate, lateral_movement,\n"
    "    persistence_id. Set args.target_info to the session/target dict\n"
    "    (keys: details.os, details.services, details.shares,\n"
    "    details.remote_management, details.trusts). Emit AFTER access is\n"
    "    achieved (access.achieved=True) to drive the post-exploitation\n"
    "    phase. You may also call these via mcp_call with tool names\n"
    "    post_exploit_probe_priv_esc_check, post_exploit_probe_cred_enumerate,\n"
    "    post_exploit_probe_lateral_movement, post_exploit_probe_persistence_id.\n"
    "  - post_exploit_ext (risk INTRUSIVE/DESTRUCTIVE, GATED) runs one of\n"
    "    52 post-exploitation extension algorithms in\n"
    "    core/post_exploit/runner_ext.py. Set args.method to one of:\n"
    "    nmap_full_scan | nmap_vuln_scan | smbclient_enum | ldapsearch_enum\n"
    "    | dns_zone_walk | snmpwalk_enum | crackmapexec_enum | gobuster_enum\n"
    "    | enum4linux_enum | rpcclient_enum | arpspoof_capture |\n"
    "    dnsspoof_capture | tcpdump_capture | ntlmrelayx_capture |\n"
    "    impacket_secretsdump_capture | responder_capture | bettercap_capture\n"
    "    | ettercap_capture | ssldump_capture | tshark_capture |\n"
    "    impacket_psexec | impacket_wmiexec | impacket_smbexec |\n"
    "    impacket_atexec | evil_winrm_exec | hydra_smb_bruteforce |\n"
    "    mimikatz_sekurlsa | mimikatz_lsadump | dcomexec | mssqlclient_exec |\n"
    "    linpeas_privesc | winpeas_privesc | powerup_privesc |\n"
    "    mimikatz_dcsync | mimikatz_skeleton_key | crackmapexec_lateral |\n"
    "    impacket_secretsdump | proxychains_tunnel | chisel_tunnel |\n"
    "    socat_tunnel | tar_exfil | dnscat2_exfil | icmp_exfil | curl_exfil |\n"
    "    schtasks_persist | cron_persist | authorized_keys_persist |\n"
    "    webshell_drop | logrotate_backdoor | touch_timestamp |\n"
    "    bloodhound_collect | llm_report_synth;\n"
    "    args.target/rhost is the accessed post-exploit target; auth-bearing\n"
    "    modules (impacket_*, evil_winrm_exec, hydra_smb_bruteforce,\n"
    "    crackmapexec_lateral, schtasks_persist) need args.user + args.pass\n"
    "    (operator-supplied, NEVER harvested+inlined by the runner — the\n"
    "    never-inline ground rule). Real subprocess / Impacket / Responder\n"
    "    / CrackMapExec / mimikatz / msfvenom / nmap / smbclient / ldapsearch\n"
    "    / dig / snmpwalk / gobuster / LinPEAS / bloodhound-python; degrades\n"
    "    cleanly when the tool is absent. NEVER fabricates a cracked\n"
    "    credential, a privilege escalation verdict, a session token, a\n"
    "    captured NTLM hash, or a 'pwned' verdict — verdicts come from the\n"
    "    tool's return code + parsed stdout. Emit AFTER access is achieved,\n"
    "    branched on the recon: open ports -> nmap_full_scan / nmap_vuln_scan;\n"
    "    SMB open -> smbclient_enum / crackmapexec_enum / rpcclient_enum /\n"
    "    enum4linux_enum; LDAP -> ldapsearch_enum; DNS -> dns_zone_walk;\n"
    "    HTTP -> gobuster_enum; user/pass available -> impacket_psexec / smbexec\n"
    "    / wmiexec / atexec / dcomexec / evil_winrm_exec / mssqlclient_exec;\n"
    "    cred dump -> mimikatz_sekurlsa / mimikatz_lsadump; lateral ->\n"
    "    crackmapexec_lateral / impacket_secretsdump; escalation ->\n"
    "    linpeas_privesc / winpeas_privesc / powerup_privesc / mimikatz_dcsync;\n"
    "    pivot -> chisel_tunnel / proxychains_tunnel / socat_tunnel;\n"
    "    exfil -> tar_exfil / curl_exfil; persist -> schtasks_persist /\n"
    "    cron_persist / authorized_keys_persist / webshell_drop /\n"
    "    logrotate_backdoor; report -> bloodhound_collect /\n"
    "    llm_report_synth. Every post_exploit_ext step is per-step\n"
    "    ACCEPT-gated at run time (default-deny). You may also drive these\n"
    "    via mcp_call with the per-method tool names\n"
    "    (post_exploit_ext_nmap_full_scan, ...). Phase 1.6 additions:\n"
    "    lsass_granted_access_mask_correlator (pure-Python EVTX triage —\n"
    "    scans Sysmon EID 10/1/11 for LSASS access masks + dump-tool\n"
    "    parents + non-temp .dmp creates; emits a finding list, NEVER\n"
    "    a fabricated detection) and\n"
    "    log4j_jndi_waf_bypass_wordlist_forge (pure-Python payload\n"
    "    forge — generates env-var / lower-upper lookup / '::-' / secret-\n"
    "    leak variants; output is a wordlist, NEVER a send).\n"
    "  - extended_wifi (risk INTRUSIVE/DESTRUCTIVE, GATED) runs one of 60\n"
    "    advanced WiFi (HE / Wi-Fi 6 / 7 / WPA3 / AI) algorithms in\n"
    "    core/extended_wifi/runner.py. The set covers HE/6E/7 frame\n"
    "    crafting (ofdma_resource_stealing, mu_mimo_nulling, bss_coloring\n"
    "    _poisoning, trigger_frame_spoofing, multi_link_operation_attack,\n"
    "    preamble_puncturing_exploit, ...), advanced WPA3/EAP (mfp_replay\n"
    "    _attack, wpa3_transition_downgrade_improved, sae_reflection\n"
    "    _attack, owe_transition_mode_bypass, dpp_configurator_spoof, ...),\n"
    "    fuzz + corner cases (ap_rsn_ie_fuzzer, driver_crash_via_malformed\n"
    "    _frame, beacon_tim_spoof, packet_number_tracking, ...), and six\n"
    "    TRAINED-ML heuristics (beacon_rssi_triangulation_ai, rf_fingerprint\n"
    "    _cloning, spectrum_scan_anomaly_detection, dtim_period_prediction,\n"
    "    ai_channel_occupancy_forecast, cross_layer_ai_fusion) labelled\n"
    "    'heuristic (not trained)' — NEVER a fabricated trained prediction.\n"
    "    Many legitimately degrade on the MT7922 (no HE/EHT/AoA); that\n"
    "    honest degradation is the contract. Every extended_wifi step is\n"
    "    per-step ACCEPT-gated at run time (default-deny). You may also\n"
    "    drive these via mcp_call with the per-method tool names\n"
    "    (ext_wifi_ofdma_resource_stealing, ...). Method names (set\n"
    "    args.method to one of): ofdma_resource_stealing, mu_mimo_nulling,\n"
    "    twt_exhaustion_attack, bss_coloring_poisoning,\n"
    "    ndp_sounding_manipulation, spatial_reuse_attack,\n"
    "    trigger_frame_spoofing, dual_band_steering_hijack,\n"
    "    power_save_bit_flipping, 6ghz_channel_discovery_burst,\n"
    "    pfn_probe_attack, mfp_replay_attack,\n"
    "    wpa3_transition_downgrade_improved, sae_reflection_attack,\n"
    "    group_rekey_sniffing, ap_rsn_ie_fuzzer, wnm_sleep_exploit,\n"
    "    tdls_discovery_poison, neighbor_report_injection,\n"
    "    ft_handshake_replay, airtime_fairness_dos, qos_null_data_exploit,\n"
    "    addba_spoofing, tspec_injection, wapi_exploit,\n"
    "    ssid_probe_harvesting_advanced,\n"
    "    timing_side_channel_attack_wpa3, client_kck_extraction,\n"
    "    beacon_rssi_triangulation_ai, rf_fingerprint_cloning,\n"
    "    ofdm_sync_jamming, spectrum_scan_anomaly_detection,\n"
    "    passive_ap_uptime_estimation, dtim_period_prediction,\n"
    "    aggregated_ampdu_snipping, roaming_scan_trigger,\n"
    "    11k_measurement_report_forge, wps_button_push_simulation,\n"
    "    dhcp_starvation_enhanced, eapol_logoff_injection,\n"
    "    packet_number_tracking, duplicate_packet_suppression_bypass,\n"
    "    key_expiration_trigger, dpp_configurator_spoof,\n"
    "    owe_transition_mode_bypass, multi_link_operation_attack,\n"
    "    protected_management_frame_replay,\n"
    "    driver_crash_via_malformed_frame,\n"
    "    ai_channel_occupancy_forecast, stealth_scan_via_power_control,\n"
    "    wfa_agc_probing, ppdu_type_confusion, uora_trigger_attack,\n"
    "    beacon_tim_spoof, preamble_puncturing_exploit,\n"
    "    ndp_announcement_flood, vht_siga1_crc_spoof,\n"
    "    mu_edca_backoff_manipulation, mld_reconfiguration_attack,\n"
    "    cross_layer_ai_fusion.\n"
    "  - ble_post_exploit (risk INTRUSIVE, GATED) runs one of 12 BLE\n"
    "    post-exploitation algorithms in core/ble_post_exploit/runner.py.\n"
    "    The set covers LE credential forcing (le_credential_forcing),\n"
    "    FW version squatting (firmware_version_squatting), LTK/SC\n"
    "    derivation (le_ltk_derivation_attack, le_sc_debug_key_exploit),\n"
    "    mesh infiltration/abuse (mesh_network_infiltration,\n"
    "    mesh_friendship_abuse, proxy_protocol_hijack), GATT cache /\n"
    "    attribute table attacks (gatt_caching_bypass, attr_table\n"
    "    _integrity_attack), privacy-mode abuse (privacy_mode_switch\n"
    "    _spoof), LE audio codec manipulation (le_audio_codec_manipulation),\n"
    "    and the LLM coordinator (ble_ai_full_auto_pwn) which executes a\n"
    "    multi-step plan. All are INTRUSIVE — every ble_post_exploit step\n"
    "    is per-step ACCEPT-gated at run time (default-deny). You may also\n"
    "    drive these via mcp_call with the per-method tool names\n"
    "    (ble_post_exploit_le_credential_forcing, ...). Method names (set\n"
    "    args.method to one of): le_credential_forcing,\n"
    "    firmware_version_squatting, le_ltk_derivation_attack,\n"
    "    le_sc_debug_key_exploit, mesh_network_infiltration,\n"
    "    mesh_friendship_abuse, proxy_protocol_hijack, gatt_caching_bypass,\n"
    "    attr_table_integrity_attack, privacy_mode_switch_spoof,\n"
    "    le_audio_codec_manipulation, ble_ai_full_auto_pwn.\n"
    f"{LIVE_EDIT_PROMPT_STANZA}\n"
    f"{TOOL_INSTALL_PROMPT_STANZA}\n"
    f"{OSINT_EXT_PROMPT_STANZA}\n"
    f"{EXTENDED_BLE_PROMPT_STANZA}\n"
    f"{CVE_TO_EXPLOIT_PROMPT_STANZA}\n"
)
# Heuristic fallback — used only when both LLM attempts fail. Mirrors
# the existing ``AIBackend._heuristic`` in spirit but emits the new
# ChainStep shape. Reused for any domain; per-domain logic is in
# ``_heuristic_for_domain``.
def _heuristic_for_domain(domain: str, target: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Deterministic fallback chain when no LLM is reachable.

    WiFi targets get a scan→capture→crack chain. Other domains get
    a minimal 'no automated chain available' response so the operator
    sees a clean failure rather than a fake success.
    """
    if domain != "wifi":
        return [{
            "action": "parse",
            "tool": None,
            "args": {},
            "rationale": (
                f"AI unavailable; no heuristic chain implemented for "
                f"domain={domain}. Operator must drive this chain manually."
            ),
            "expected_outcome": "operator-driven chain",
            "risk_level": "read",
            "expected_runtime_seconds": 1,
        }]

    bssid = target.get("bssid", "TARGET_BSSID")
    channel = target.get("channel", 1)
    iface = target.get("interface", "wlan0mon")
    essid = target.get("essid", "TARGET_ESSID")

    steps: List[Dict[str, Any]] = []
    # mt7921e adapter: run an injection-quality probe before attacking so
    # the operator gets a 0-100 reading (and the chain can branch on it).
    # Only prepended when the mt7921e capability is present, so non-mt7921e
    # chains stay byte-identical to the legacy heuristic.
    if target.get("adapter_caps", {}).get("mt7921e"):
        steps.append({
            "action": "mt7921e_test_injection",
            "tool": "mt7921e_tools",
            "args": {},
            "rationale": (
                "mt7921e adapter detected: run aireplay-ng --test to verify "
                "packet injection quality before attacking."
            ),
            "expected_outcome": "injection quality 0-100 reported",
            "risk_level": "intrusive",
            "expected_runtime_seconds": 20,
        })
        # When a client is associated with the target, a directed deauth
        # before the capture often surfaces the EAPOL handshake faster.
        # Minimal and defensive: only emitted when mt7921e is present AND
        # a client is reported. Non-mt7921e paths stay byte-identical.
        _clients = target.get("clients")
        if not _clients:
            _clients = target.get("recon", {}).get(
                "clients", {}).get("data", {})
        client_count = 0
        if isinstance(_clients, list):
            client_count = len(_clients)
        elif isinstance(_clients, dict):
            client_count = int(_clients.get("count", 0) or 0)
        if client_count > 0:
            steps.append({
                "action": "mt7921e_inject",
                "tool": "mt7921e_tools",
                "args": {"mode": "deauth", "bssid": bssid},
                "rationale": (
                    "mt7921e adapter + associated client detected: emit a "
                    "directed deauth to force the client to reconnect "
                    "and surface a fresh EAPOL handshake for capture."
                ),
                "expected_outcome": "client reconnect; EAPOL handshake visible",
                "risk_level": "destructive",
                "expected_runtime_seconds": 10,
            })

    # Per-encryption strategy. The orchestrator resolves the wordlist
    # (weakpass → rockyou), so we leave args.wordlist unset unless the
    # operator wants a specific one.
    enc = (target.get("encryption") or target.get("cipher")
           or target.get("enc") or "wpa2").lower()
    has_wps = bool(target.get("wps"))
    has_pmkid = bool(target.get("pmkid"))
    cap_path = f"/tmp/kfiosa-{bssid.replace(':', '')}-01.cap"

    # WPS first — often yields the PSK with no handshake.
    if has_wps:
        steps.extend([
            {
                "action": "wps_pixie",
                "tool": "reaver",
                "args": {"bssid": bssid, "interface": iface},
                "rationale": "Target advertises WPS: try Pixie-Dust first "
                             "(fast, often no handshake needed).",
                "expected_outcome": "WPS PIN + WPA PSK recovered",
                "risk_level": "intrusive",
                "expected_runtime_seconds": 120,
            },
            {
                "action": "wps_online",
                "tool": "reaver",
                "args": {"bssid": bssid, "interface": iface},
                "rationale": "If pixie fails, fall back to an online WPS PIN "
                             "bruteforce (slower).",
                "expected_outcome": "WPS PIN/PSK recovered",
                "risk_level": "intrusive",
                "expected_runtime_seconds": 900,
            },
        ])

    if enc in ("wep",):
        # WEP: replay ARP to grow IVs, then crack with aircrack -a 1.
        if target.get("adapter_caps", {}).get("mt7921e"):
            for mode in ("arp_replay", "chopchop", "fragmentation"):
                steps.append({
                    "action": "mt7921e_inject",
                    "tool": "mt7921e_tools",
                    "args": {"mode": mode, "bssid": bssid},
                    "rationale": f"WEP target: {mode} to gather IVs / decrypt "
                                 f"frames.",
                    "expected_outcome": "sufficient IVs / decrypted frame",
                    "risk_level": "destructive",
                    "expected_runtime_seconds": 60,
                })
        steps.append({
            "action": "crack",
            "tool": "aircrack-ng",
            "args": {"cap_file": cap_path, "bssid": bssid, "wep": True},
            "rationale": "Crack the WEP capture with aircrack-ng (-a 1).",
            "expected_outcome": "WEP key recovered",
            "risk_level": "intrusive",
            "expected_runtime_seconds": 120,
        })
        return steps

    # WPA / WPA2 / WPA3 default path.
    steps.append({
        "action": "mcp_call",
        "tool": "airodump-ng",
        "args": {
            "channel": channel,
            "bssid": bssid,
            "write": f"/tmp/kfiosa-{bssid.replace(':', '')}",
            "interface": iface,
            "output_format": "both",
        },
        "rationale": f"Lock onto {bssid} on ch{channel} and capture WPA handshake.",
        "expected_outcome": "handshake captured in .cap file",
        "risk_level": "intrusive",
        "expected_runtime_seconds": 30,
    })
    # Clientless PMKID first when indicated (or when no client is
    # associated — PMKID needs no handshake).
    if has_pmkid:
        steps.append({
            "action": "pmkid",
            "tool": "hashcat",
            "args": {"cap_file": cap_path, "bssid": bssid},
            "rationale": "PMKID available: clientless attack via hashcat "
                         "-m 22000 (no handshake needed).",
            "expected_outcome": "WPA PSK recovered from PMKID",
            "risk_level": "intrusive",
            "expected_runtime_seconds": 120,
        })
    # Dictionary crack (the orchestrator resolves weakpass → rockyou).
    steps.append({
        "action": "crack",
        "tool": "aircrack-ng",
        "args": {"cap_file": cap_path, "bssid": bssid},
        "rationale": "Crack the captured handshake with aircrack-ng + "
                     "resolved wordlist (weakpass → rockyou).",
        "expected_outcome": "WPA PSK recovered",
        "risk_level": "intrusive",
        "expected_runtime_seconds": 120,
    })
    # GPU mask bruteforce fan-out — optional, emitted so the re-plan
    # loop can reach access when dictionary fails. Common 8-10 digit
    # numeric masks first (default), then a lowercase-letters mask.
    for mask, rt in (("?d?d?d?d?d?d?d?d", 300),
                     ("?d?d?d?d?d?d?d?d?d?d", 900),
                     ("?l?l?l?l?l?l?l?l", 900)):
        steps.append({
            "action": "crack_gpu",
            "tool": "hashcat",
            "args": {"cap_file": cap_path, "mask": mask},
            "rationale": f"Dictionary may fail: GPU mask bruteforce "
                         f"({mask}) as a fan-out to reach access.",
            "expected_outcome": "WPA PSK recovered via hashcat -a 3",
            "risk_level": "intrusive",
            "expected_runtime_seconds": rt,
        })
    if enc.startswith("wpa3"):
        # SAE/Dragonfly defeats the standard PMK handshake.
        steps.append({
            "action": "parse",
            "tool": None,
            "args": {},
            "rationale": "WPA3 SAE/Dragonfly defeats the PMK handshake path; "
                         "attempt PMKID, else route to dragonblood CVEs / "
                         "a zero_day tail.",
            "expected_outcome": "operator notes SAE; route to CVE/0-day",
            "risk_level": "read",
            "expected_runtime_seconds": 1,
        })
    return steps


def _zero_day_tail(target: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Optional 0-day exploit-generator tail appended to a chain when
    the operator opts in (``attach_zero_day=True``).

    Each step is marked ``optional: True`` and is independently gated
    by the orchestrator's per-step ACCEPT/CANCEL prompt, so the
    operator can CANCEL the tail at any point. The steps do NOT
    hardcode ``draft_id`` / ``exploit_id`` — those are resolved at
    runtime by the orchestrator (most-recent ACK'd concept /
    most-recent drafted exploit for the target), so the tail flows:

        propose -> (operator ACKs the concept) -> build -> execute

    The tail is the *exploit generator* (build + execute) plus the
    propose step that feeds it a concept. It is appended only on
    explicit opt-in so the default chain shape is unchanged.
    """
    tref = {k: target.get(k) for k in (
        "bssid", "ssid", "essid", "vendor", "ip", "host", "name", "target"
    ) if target.get(k)}
    return [
        {
            "action": "zero_day_propose",
            "tool": "zero_day_proposer",
            "args": {"target": tref},
            "rationale": (
                "OPTIONAL: draft a 0-day concept for this target when no "
                "known CVE/KB exploit succeeded. Operator must ACK the "
                "concept before build."
            ),
            "expected_outcome": "a pending 0-day concept draft",
            "risk_level": "read",
            "expected_runtime_seconds": 30,
            "optional": True,
        },
        {
            "action": "zero_day_build",
            "tool": "zero_day_exploit_builder",
            "args": {"target": tref, "recon": tref},
            "rationale": (
                "OPTIONAL: generate a unique, target-specific PoC from "
                "the most recent ACK'd concept (recon + NVD + available "
                "tools grounded). Operator must ACK before execute."
            ),
            "expected_outcome": "a drafted 0-day exploit (status=drafted)",
            "risk_level": "intrusive",
            "expected_runtime_seconds": 60,
            "optional": True,
        },
        {
            "action": "zero_day_execute",
            "tool": "zero_day_exploit_runner",
            "args": {"target": tref},
            "rationale": (
                "OPTIONAL: run the most recent drafted PoC against the "
                "target. DESTRUCTIVE — operator ACCEPT gate required."
            ),
            "expected_outcome": "PoC executed; stdout/stderr/exit captured",
            "risk_level": "destructive",
            "expected_runtime_seconds": 120,
            "optional": True,
        },
    ]


def _strip_code_fence(text: str) -> str:
    """Strip a leading ``\\`\\`\\`json ... \\`\\`\\`` code fence, common
    in Ollama responses. Returns the inside (or the original text if
    no fence is present). Never raises.
    """
    s = (text or "").strip()
    if not s.startswith("```"):
        return s
    # Drop the opening fence and optional language tag.
    s = re.sub(r"^```[a-zA-Z0-9_+-]*\n?", "", s)
    # Drop the closing fence.
    s = re.sub(r"\n?```\s*$", "", s)
    return s.strip()


def _parse_chain_json(text: str) -> List[Dict[str, Any]]:
    """Parse the LLM's JSON chain. Raises ``ChainPlanError`` on failure.

    Accepts:
      - strict ``{"chain": [...]}``
      - bare ``[...]`` (we wrap it)
      - a ``{"refusal": true, ...}`` (raises so the caller can swap models)
    """
    raw = _strip_code_fence(text)
    if not raw:
        raise ChainPlanError("LLM returned empty response")
    try:
        obj = json.loads(raw)
    except json.JSONDecodeError as e:
        raise ChainPlanError(f"LLM returned non-JSON: {e}") from e

    if isinstance(obj, dict) and obj.get("refusal") is True:
        raise ChainPlanError(
            f"LLM refused: {obj.get('reason', 'no reason given')}"
        )

    if isinstance(obj, list):
        steps = obj
    elif isinstance(obj, dict) and isinstance(obj.get("chain"), list):
        steps = obj["chain"]
    else:
        raise ChainPlanError(
            "LLM JSON did not contain a 'chain' list "
            f"(got keys={list(obj.keys()) if isinstance(obj, dict) else type(obj).__name__})"
        )

    if not steps:
        raise ChainPlanError("LLM returned an empty chain")

    # Normalize: ensure every step has the fields the orchestrator
    # expects. Missing fields get safe defaults; invalid types are
    # coerced or dropped.
    out: List[Dict[str, Any]] = []
    for i, s in enumerate(steps):
        if not isinstance(s, dict):
            logger.debug(f"chain step {i} not a dict: {s!r}")
            continue
        out.append({
            "action": s.get("action", "mcp_call"),
            "tool": s.get("tool"),
            "args": s.get("args", {}) or {},
            "rationale": s.get("rationale", ""),
            "expected_outcome": s.get("expected_outcome", ""),
            "risk_level": s.get("risk_level", "intrusive"),
            "expected_runtime_seconds": int(s.get("expected_runtime_seconds", 30) or 30),
        })
    if not out:
        raise ChainPlanError("LLM chain had no valid step objects")
    return out


class AIChainPlanner:
    """Plan an attack chain for ``target`` using the AI backend.

    Args:
        ai_backend: an :class:`core.ai_backend.AIBackend` (or duck-typed
            with ``.query(domain, prompt, context=...)``). Used for the
            primary per-domain model.
        exploit_gen_manager: an
            :class:`core.ai_backend.exploit_generator.ExploitGenModelManager`
            (or ``None`` to skip the uncensored fallback). When set, the
            planner asks the manager to ensure an uncensored model is
            available on total failure of the primary call.
        mcp_client: an MCP client (``core.mcp.tools.call_mcp_tool`` or a
            duck-type with ``.call(tool, args)``). Currently only used
            to enrich the prompt with the tool catalog; the actual
            invocation happens in the orchestrator.
        on_event: optional ``callable(str)`` for activity log lines.
    """

    def __init__(self, ai_backend=None, exploit_gen_manager=None,
                 mcp_client=None, on_event=None):
        self.ai_backend = ai_backend
        self.exploit_gen_manager = exploit_gen_manager
        self.mcp_client = mcp_client
        self.on_event = on_event
        # Introspection: the context dict from the most recent plan()
        # call. The orchestrator reads ``_last_context.get("uncensored_swap")``
        # to detect which fallback produced the chain; setting it here
        # (previously never set) unblocks that branch. Also retains the
        # prior step outcomes fed to the last re-plan call.
        self._last_context: Dict[str, Any] = {}
        self._last_prior_results: Optional[List[Dict[str, Any]]] = None

    # ------------------------------------------------------------------
    # Public
    # ------------------------------------------------------------------
    def plan(self, domain: str, target: Dict[str, Any],
             cves: Optional[List[Dict[str, Any]]] = None,
             kb_tools: Optional[List[Dict[str, Any]]] = None,
             context: Optional[Dict[str, Any]] = None,
             attach_zero_day: bool = False,
             prior_results: Optional[List[Dict[str, Any]]] = None
             ) -> List[Dict[str, Any]]:
        """Produce an ordered attack chain for ``target``.

        Returns a list of step dicts. Raises :class:`ChainPlanError`
        only when the heuristic fallback is empty (the LLM is down
        and the domain has no heuristic chain). Never fakes success.

        When ``attach_zero_day`` is True, an OPTIONAL 0-day exploit-
        generator tail (propose -> build -> execute) is appended to the
        chain. Every tail step is marked ``optional: True`` and is
        independently gated by the operator's per-step ACCEPT/CANCEL
        prompt, so the operator can CANCEL the tail at any point. This
        is opt-in so the default chain shape is unchanged.

        When ``prior_results`` is non-empty (the polymorphic re-plan
        path), a ``PRIOR STEP OUTCOMES`` section is appended to the
        prompt with the most recent live step outcomes and a directive
        to emit only the NEXT 1-3 steps (not the whole chain), skip
        already-succeeded steps, and move to post_exploit/open_shell
        once access is achieved. The 3-layer fallback is preserved.
        """
        cves = cves or []
        kb_tools = kb_tools or []
        ctx = dict(context or {})
        ctx.update({
            "target": target,
            "matched_cves": cves,
            "kb_tools": kb_tools[:20],  # cap so the prompt stays small
        })

        # Surface the MCP tool registry (schemas + examples + risk) to
        # the LLM so it can pick tools whose schema matches the target
        # and emit external_inject / mcp_call / mt7921e_inject steps with
        # the right args + risk_level. Best-effort: an empty block is
        # harmless (the system prompt still describes the actions).
        mcp_block = ""
        try:
            from core.mcp.tools import mcp_tools_context_block
            mcp_block = mcp_tools_context_block(domain, limit=30)
        except Exception:  # noqa: BLE001 — optional dependency
            mcp_block = ""
        ctx["mcp_tools"] = mcp_block

        # Polymorphic re-plan: when the orchestrator feeds back live step
        # outcomes, surface them (most recent first, capped) with a
        # directive to emit only the next 1-3 steps. Skipped when no
        # prior results (default chain shape unchanged).
        prior_block = ""
        if prior_results:
            try:
                recent = list(reversed(prior_results[-12:]))
                prior_block = (
                    "PRIOR STEP OUTCOMES (live, most recent first):\n"
                    + json.dumps(recent, default=str)[:2000]
                    + "\n\nGiven those live outcomes, emit the NEXT 1-3 steps "
                      "only (not the whole chain). Do NOT repeat steps that "
                      "already succeeded (same action+tool). If a CVE/exploit "
                      "step failed, try the next CVE or an alternate path. If "
                      "access is achieved (a step's data has creds or "
                      "session_id), emit post_exploit and/or open_shell next.\n"
                )
            except Exception:  # noqa: BLE001 — never break planning on serialization
                prior_block = ""

        prompt = (
            f"Build an attack chain for domain={domain}.\n"
            f"Target: {json.dumps(target, default=str)[:1200]}\n"
            f"Matched CVEs (top {len(cves)}): "
            f"{json.dumps(cves[:10], default=str)[:1500]}\n"
            f"KB-suggested tools (top {len(kb_tools)}): "
            f"{json.dumps(kb_tools[:10], default=str)[:1000]}\n"
            + (f"AVAILABLE MCP TOOLS (schemas + examples + risk):\n"
               f"{mcp_block}\n" if mcp_block else "")
            + prior_block
        )

        steps: Optional[List[Dict[str, Any]]] = None

        # 1) Primary LLM call.
        try:
            text = self._query_primary(domain, prompt, ctx)
            steps = _parse_chain_json(text)
        except ChainPlanError as e:
            self._emit(f"[chain-planner] primary LLM failed: {e}")
        except Exception as e:  # noqa: BLE001
            self._emit(f"[chain-planner] primary LLM errored: {e}")

        # 2) Uncensored model swap (if the manager is wired in).
        if steps is None and self.exploit_gen_manager is not None:
            try:
                tag = self.exploit_gen_manager.ensure_exploit_model()
                if tag:
                    self._emit(
                        f"[chain-planner] retrying with uncensored model: {tag}"
                    )
                    # The manager pulled the model; the next query()
                    # call won't auto-use it (MODEL_CATALOG still points
                    # at the per-domain model), so we re-issue with a
                    # note in the context that the operator approved
                    # the uncensored swap.
                    ctx["uncensored_swap"] = tag
                    text = self._query_primary(domain, prompt, ctx)
                    steps = _parse_chain_json(text)
            except ChainPlanError as e:
                self._emit(
                    f"[chain-planner] uncensored model also failed: {e}"
                )
            except Exception as e:  # noqa: BLE001
                self._emit(f"[chain-planner] uncensored model errored: {e}")

        # 3) Deterministic heuristic fallback.
        if steps is None:
            steps = _heuristic_for_domain(domain, target)
            if not steps:
                raise ChainPlanError(
                    f"no LLM reachable and no heuristic chain for domain={domain}"
                )
            self._emit(
                f"[chain-planner] using heuristic chain ({len(steps)} steps); "
                f"AI was unavailable"
            )

        # Optional 0-day exploit-generator tail (opt-in). Each step is
        # operator-gated; appended only when the operator opts in.
        if attach_zero_day:
            tail = _zero_day_tail(target)
            if tail:
                steps = steps + tail
                self._emit(
                    f"[chain-planner] appended optional 0-day exploit "
                    f"tail ({len(tail)} steps); each is operator-gated"
                )
        # Stash the context for introspection (the orchestrator reads
        # ``_last_context.get("uncensored_swap")`` to label the chain
        # source; this was previously a dead branch because _last_context
        # was never set).
        self._last_context = ctx
        self._last_prior_results = prior_results
        # Enrich mt7921e_inject steps that have no args.mode with the
        # quality-aware strategy from choose_injection_strategy(caps, recon).
        # Done BEFORE the steps return so the per-step ACCEPT prompt shows
        # the auto-chosen mode to the operator (no post-gate arg mutation).
        steps = [self._enrich_inject_step(s, ctx) for s in steps]
        return steps

    def _enrich_inject_step(self, step: Dict[str, Any],
                            ctx: Dict[str, Any]) -> Dict[str, Any]:
        """If ``step`` is an mt7921e_inject step with no ``args.mode``, set
        ``args.mode`` from :func:`choose_injection_strategy` using the
        adapter caps + recon in ``ctx``. Returns the (possibly mutated)
        step. Never raises — on any error the step is returned unchanged."""
        try:
            if not isinstance(step, dict) or step.get("action") != "mt7921e_inject":
                return step
            args = step.setdefault("args", {})
            if not isinstance(args, dict):
                return step
            if args.get("mode") or args.get("frame_b64"):
                return step  # explicit mode or raw frame — leave as-is
            from core.modules.mt7921e_tools import choose_injection_strategy
            caps = ctx.get("adapter_caps", {}) or {}
            recon = ctx.get("recon", {}) or {}
            mode = choose_injection_strategy(caps, recon)
            args["mode"] = mode
            step["risk_level"] = step.get("risk_level") or "destructive"
            note = step.get("note", "")
            step["note"] = (note + " " if note else "") + (
                f"[auto-strategy: mode={mode} from choose_injection_strategy"
                f"(caps, recon)]"
            )
        except Exception:  # noqa: BLE001 — enrichment is best-effort
            pass
        return step

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------
    def _emit(self, msg: str) -> None:
        if self.on_event is None:
            return
        try:
            self.on_event(msg)
        except Exception:
            pass

    def _query_primary(self, domain: str, prompt: str,
                       context: Dict[str, Any]) -> str:
        """Run the primary LLM call. Returns the raw text response.

        Raises ``ChainPlanError`` if no backend is wired in. Other
        backend errors propagate so the caller can decide whether to
        swap models.
        """
        if self.ai_backend is None:
            raise ChainPlanError("no AI backend wired into the planner")
        # Inject the strict JSON system prompt by reusing the backend's
        # domain prompt as a prefix (the backend's prompt already
        # establishes the persona); the strict schema is appended as
        # extra system context via a wrapper.
        original = getattr(self.ai_backend, "domain_prompts", {}) or {}
        if domain not in original:
            try:
                self.ai_backend.domain_prompts[domain] = (
                    original.get(domain, "")
                    + "\n\n" + _SYSTEM_PROMPT
                )
                restore = True
            except Exception:
                restore = False
        else:
            restore = False
        try:
            return self.ai_backend.query(domain, prompt, context=context)
        finally:
            if restore:
                try:
                    self.ai_backend.domain_prompts.pop(domain, None)
                except Exception:
                    pass
