"""core.refactors.poly_adapt_companions — Phase 2.4 Phase 5.

Adds polymorphic (grammar) and target-adaptive (picker) companion
methods for 20 existing universal methods. The companions are
ADDS — they never replace the universal method. When the LLM
sees a `poly_*` or `adapt_*` step, it dispatches to these
methods; the envelope carries ``data.model = "polymorphic
(heuristic)"`` or ``"target-adaptive (heuristic)"`` so the
operator and the LLM always know whether the result was a
deterministic universal action or a heuristic variation.

The 20 refactored methods (mirrors the Phase 2.4 plan §H.1):

POLYMORPHIC (10):
  1.  poly_deauth_burst_pattern_grammar          (wifi_attack)
  2.  poly_eapol_replay_grammar                  (wifi_attack)
  3.  poly_pmkid_eapol_field_grammar             (wifi_attack)
  4.  poly_wps_eap_failure_grammar               (wifi_attack)
  5.  poly_evil_twin_hostapd_conf_grammar        (wifi_attack)
  6.  poly_passive_scan_channel_hop_grammar      (wifi_recon)
  7.  poly_client_probe_request_grammar          (wifi_recon)
  8.  poly_gatt_value_template                   (ble_attack)
  9.  poly_hid_report_template                   (ble_attack)
 10.  poly_adv_data_template_grammar             (ble_recon)

TARGET-ADAPTIVE (10):
 11.  adapt_attack_deauth_strategy_picker        (wifi_attack)
 12.  adapt_attack_handshake_strategy_picker     (wifi_attack)
 13.  adapt_attack_pmkid_target_picker           (wifi_attack)
 14.  adapt_attack_wps_strategy_picker           (wifi_attack)
 15.  adapt_attack_evil_twin_strategy_picker     (wifi_attack)
 16.  adapt_recon_scan_strategy_picker           (wifi_recon)
 17.  adapt_recon_client_strategy_picker         (wifi_recon)
 18.  adapt_attack_gatt_strategy_picker          (ble_attack)
 19.  adapt_attack_hid_strategy_picker           (ble_attack)
 20.  adapt_recon_adv_strategy_picker            (ble_recon)

Each method returns a real envelope — never fakes results. The
grammar returns candidate variants; the picker returns a
recommended action and the rationale. The decision is then
applied by the LLM to the next real step.
"""
from __future__ import annotations

import time
from typing import Any, Dict, List, Optional


def _step(name: str) -> Dict[str, Any]:
    return {
        "name": name,
        "ok": False,
        "data": None,
        "error": None,
        "started": time.time(),
    }


def _ok(step: Dict[str, Any], data: Dict[str, Any]) -> Dict[str, Any]:
    step["ok"] = True
    step["data"] = data
    step["duration_s"] = round(time.time() - step.get("started", time.time()), 3)
    return step


def _err(step: Dict[str, Any], msg: str) -> Dict[str, Any]:
    step["ok"] = False
    step["error"] = msg
    step["duration_s"] = round(time.time() - step.get("started", time.time()), 3)
    return step


# ---------------------------------------------------------------------------
# POLYMORPHIC (10)
# ---------------------------------------------------------------------------

def poly_deauth_burst_pattern_grammar(args: Dict[str, Any]) -> Dict[str, Any]:
    """Pick a deauth-burst pattern variant based on the args seed."""
    import random
    step = _step("poly_deauth_burst_pattern_grammar")
    seed = (args or {}).get("seed") or (args or {}).get("bssid") or "default"
    rng = random.Random(str(seed))
    patterns = [
        "ramp_50_200", "constant_100", "burst_three_30",
        "staggered_50_150", "exponential_backoff",
    ]
    # Grammar: pick 3 patterns with non-uniform weights (prefer ramp+constant)
    weights = [3, 3, 2, 2, 1]
    picked = rng.choices(patterns, weights=weights, k=3)
    return _ok(step, {
        "grammar": "deauth_burst_pattern",
        "variants": picked,
        "primary": picked[0],
        "model": "polymorphic (heuristic)",
        "note": "Use the primary pattern for the next deauth chain step.",
    })


def poly_eapol_replay_grammar(args: Dict[str, Any]) -> Dict[str, Any]:
    """Pick an EAPOL replay counter strategy."""
    import random
    step = _step("poly_eapol_replay_grammar")
    seed = (args or {}).get("seed") or "eapol"
    rng = random.Random(str(seed))
    strategies = [
        "linear_increment", "random_reseed", "monotonic_skip",
        "batched_4x_then_pause", "burst_until_anonce_seen",
    ]
    picked = rng.sample(strategies, k=3)
    return _ok(step, {
        "grammar": "eapol_replay",
        "variants": picked,
        "primary": picked[0],
        "model": "polymorphic (heuristic)",
    })


def poly_pmkid_eapol_field_grammar(args: Dict[str, Any]) -> Dict[str, Any]:
    """Pick which EAPOL fields to mutate for PMKID harvesting."""
    step = _step("poly_pmkid_eapol_field_grammar")
    variants = [
        "key_info_clear", "key_data_random_pad", "replay_counter_increment",
        "mic_zero_then_random", "wpa_ssid_replay",
    ]
    return _ok(step, {
        "grammar": "pmkid_eapol_field",
        "variants": variants,
        "primary": variants[0],
        "model": "polymorphic (heuristic)",
        "note": "Always try the first variant; mutate if no PMKID after 3s.",
    })


def poly_wps_eap_failure_grammar(args: Dict[str, Any]) -> Dict[str, Any]:
    """Pick a WPS EAP failure injection variant."""
    step = _step("poly_wps_eap_failure_grammar")
    variants = [
        "eap_failure_msg", "wps_nack_msg", "eap_duplicate_msg",
        "wps_frag_reassemble", "eap_fragmentation",
    ]
    return _ok(step, {
        "grammar": "wps_eap_failure",
        "variants": variants,
        "primary": variants[0],
        "model": "polymorphic (heuristic)",
    })


def poly_evil_twin_hostapd_conf_grammar(args: Dict[str, Any]) -> Dict[str, Any]:
    """Pick a hostapd config template for Evil Twin."""
    step = _step("poly_evil_twin_hostapd_conf_grammar")
    base_ssid = (args or {}).get("ssid") or "Free_WiFi"
    variants = [
        f"{base_ssid}",
        f"{base_ssid}_5G",
        f"{base_ssid}-Guest",
        f"{base_ssid}_secure",
    ]
    return _ok(step, {
        "grammar": "evil_twin_hostapd_conf",
        "variants": variants,
        "primary": variants[0],
        "model": "polymorphic (heuristic)",
    })


def poly_passive_scan_channel_hop_grammar(args: Dict[str, Any]) -> Dict[str, Any]:
    """Pick a channel-hop sequence for passive scan."""
    step = _step("poly_passive_scan_channel_hop_grammar")
    sequences = [
        [1, 6, 11], [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11],
        [36, 40, 44, 48], [1, 36, 6, 40, 11, 44],
    ]
    return _ok(step, {
        "grammar": "passive_scan_channel_hop",
        "variants": sequences,
        "primary": sequences[0],
        "model": "polymorphic (heuristic)",
    })


def poly_client_probe_request_grammar(args: Dict[str, Any]) -> Dict[str, Any]:
    """Pick which client probe types to listen for."""
    step = _step("poly_client_probe_request_grammar")
    variants = ["directed", "wildcard", "ssid_list", "mesh_probe", "6e_probe"]
    return _ok(step, {
        "grammar": "client_probe_request",
        "variants": variants,
        "primary": "wildcard",
        "model": "polymorphic (heuristic)",
    })


def poly_gatt_value_template(args: Dict[str, Any]) -> Dict[str, Any]:
    """Pick a GATT write value template."""
    step = _step("poly_gatt_value_template")
    templates = [
        "ff" * 8, "00" * 8, "0a0b0c0d0e0f",
        "01", "ascii_HELLO", "ascii_TEST",
    ]
    return _ok(step, {
        "grammar": "gatt_value",
        "variants": templates,
        "primary": templates[0],
        "model": "polymorphic (heuristic)",
    })


def poly_hid_report_template(args: Dict[str, Any]) -> Dict[str, Any]:
    """Pick a HID report template."""
    step = _step("poly_hid_report_template")
    templates = [
        "ascii_run_cmd", "ascii_open_browser",
        "ascii_type_url", "ascii_press_enter",
        "ascii_alt_tab",
    ]
    return _ok(step, {
        "grammar": "hid_report",
        "variants": templates,
        "primary": templates[0],
        "model": "polymorphic (heuristic)",
    })


def poly_adv_data_template_grammar(args: Dict[str, Any]) -> Dict[str, Any]:
    """Pick an advertising data template."""
    step = _step("poly_adv_data_template_grammar")
    templates = [
        "ibeacon", "eddystone_uid", "eddystone_url",
        "manufacturer_specific", "service_data_16bit", "service_data_128bit",
    ]
    return _ok(step, {
        "grammar": "adv_data_template",
        "variants": templates,
        "primary": templates[0],
        "model": "polymorphic (heuristic)",
    })


# ---------------------------------------------------------------------------
# TARGET-ADAPTIVE (10)
# ---------------------------------------------------------------------------

def _pick_step(name: str) -> Dict[str, Any]:
    return _step(name)


def adapt_attack_deauth_strategy_picker(args: Dict[str, Any]) -> Dict[str, Any]:
    """Pick a deauth strategy based on observed state."""
    step = _pick_step("adapt_attack_deauth_strategy_picker")
    pmf_supported = bool((args or {}).get("pmf_supported", False))
    client_count = int((args or {}).get("client_count", 0))
    if pmf_supported and client_count < 3:
        pick, rationale = "sa_query_flood", "PMF on + few clients → SA-Query flood"
    elif pmf_supported:
        pick, rationale = "krack_like_replay", "PMF on + many clients → KRACK-like"
    elif client_count >= 5:
        pick, rationale = "broadcast_deauth_burst", "no PMF + many clients → broadcast"
    else:
        pick, rationale = "directed_deauth", "no PMF + few clients → directed"
    return _ok(step, {
        "pick": pick,
        "rationale": rationale,
        "model": "target-adaptive (heuristic)",
    })


def adapt_attack_handshake_strategy_picker(args: Dict[str, Any]) -> Dict[str, Any]:
    """Pick a handshake-capture strategy."""
    step = _pick_step("adapt_attack_handshake_strategy_picker")
    wpa_version = (args or {}).get("wpa_version", "wpa2")
    if wpa_version == "wpa3":
        pick, rationale = "sae_handshake_capture", "WPA3 → SAE capture + dragonblood"
    elif wpa_version == "wpa2_enterprise":
        pick, rationale = "eap_tls_capture", "WPA2-Enterprise → EAP-TLS capture"
    else:
        pick, rationale = "wpa2_4way_capture", "WPA2 → standard 4-way capture"
    return _ok(step, {
        "pick": pick,
        "rationale": rationale,
        "model": "target-adaptive (heuristic)",
    })


def adapt_attack_pmkid_target_picker(args: Dict[str, Any]) -> Dict[str, Any]:
    """Pick whether to focus on PMKID vs standard handshake."""
    step = _pick_step("adapt_attack_pmkid_target_picker")
    has_11k = bool((args or {}).get("ieee80211k", False))
    if has_11k:
        pick, rationale = "pmkid_first", "11k present → PMKID has higher yield"
    else:
        pick, rationale = "standard_handshake", "no 11k → standard 4-way"
    return _ok(step, {
        "pick": pick,
        "rationale": rationale,
        "model": "target-adaptive (heuristic)",
    })


def adapt_attack_wps_strategy_picker(args: Dict[str, Any]) -> Dict[str, Any]:
    """Pick a WPS strategy."""
    step = _pick_step("adapt_attack_wps_strategy_picker")
    locked = bool((args or {}).get("wps_locked", False))
    if locked:
        pick, rationale = "reaver_aggressive", "WPS locked → reaver with -L 0"
    else:
        pick, rationale = "pixie_dust", "WPS unlocked → pixie dust"
    return _ok(step, {
        "pick": pick,
        "rationale": rationale,
        "model": "target-adaptive (heuristic)",
    })


def adapt_attack_evil_twin_strategy_picker(args: Dict[str, Any]) -> Dict[str, Any]:
    """Pick an Evil-Twin strategy."""
    step = _pick_step("adapt_attack_evil_twin_strategy_picker")
    captive_present = bool((args or {}).get("captive_portal", False))
    if captive_present:
        pick, rationale = "captive_portal_phish", "captive portal → phish with login page"
    else:
        pick, rationale = "wpa2_psk_grab", "no captive → grab WPA2 PSK via handshake"
    return _ok(step, {
        "pick": pick,
        "rationale": rationale,
        "model": "target-adaptive (heuristic)",
    })


def adapt_recon_scan_strategy_picker(args: Dict[str, Any]) -> Dict[str, Any]:
    """Pick a recon scan strategy."""
    step = _pick_step("adapt_recon_scan_strategy_picker")
    band_2_4 = bool((args or {}).get("2_4ghz_present", True))
    band_5ghz = bool((args or {}).get("5ghz_present", False))
    band_6ghz = bool((args or {}).get("6ghz_present", False))
    if band_6ghz:
        pick, rationale = "wifi_6e_full_band_scan", "6 GHz present → full-band scan"
    elif band_5ghz and band_2_4:
        pick, rationale = "dual_band_sequential", "dual-band → sequential"
    elif band_2_4:
        pick, rationale = "wifi_2_4_only", "2.4 only → channels 1-13"
    else:
        pick, rationale = "passive_listen", "no APs → passive listen"
    return _ok(step, {
        "pick": pick,
        "rationale": rationale,
        "model": "target-adaptive (heuristic)",
    })


def adapt_recon_client_strategy_picker(args: Dict[str, Any]) -> Dict[str, Any]:
    """Pick a client-detection strategy."""
    step = _pick_step("adapt_recon_client_strategy_picker")
    active_probes = int((args or {}).get("active_probes", 0))
    if active_probes > 10:
        pick, rationale = "directed_probe_listener", "many directed probes → list SSIDs"
    elif active_probes > 0:
        pick, rationale = "wildcard_listener", "few probes → wildcard listener"
    else:
        pick, rationale = "passive_only", "no probes → passive only"
    return _ok(step, {
        "pick": pick,
        "rationale": rationale,
        "model": "target-adaptive (heuristic)",
    })


def adapt_attack_gatt_strategy_picker(args: Dict[str, Any]) -> Dict[str, Any]:
    """Pick a GATT attack strategy."""
    step = _pick_step("adapt_attack_gatt_strategy_picker")
    services = int((args or {}).get("service_count", 0))
    encrypted = bool((args or {}).get("encrypted", False))
    if encrypted:
        pick, rationale = "long_read_attack", "encrypted → long-read for key material"
    elif services > 8:
        pick, rationale = "service_bruteforce", "many services → enumerate UUIDs"
    else:
        pick, rationale = "characteristic_write", "few services → direct write"
    return _ok(step, {
        "pick": pick,
        "rationale": rationale,
        "model": "target-adaptive (heuristic)",
    })


def adapt_attack_hid_strategy_picker(args: Dict[str, Any]) -> Dict[str, Any]:
    """Pick a HID injection strategy."""
    step = _pick_step("adapt_attack_hid_strategy_picker")
    target_os = (args or {}).get("target_os", "linux")
    if target_os == "windows":
        pick, rationale = "win_r_win_r_cmd", "Windows → Win+R cmd"
    elif target_os == "macos":
        pick, rationale = "spotlight_cmd", "macOS → Cmd+Space terminal"
    else:
        pick, rationale = "ctrl_alt_t", "Linux → Ctrl+Alt+T"
    return _ok(step, {
        "pick": pick,
        "rationale": rationale,
        "model": "target-adaptive (heuristic)",
    })


def adapt_recon_adv_strategy_picker(args: Dict[str, Any]) -> Dict[str, Any]:
    """Pick an advertising recon strategy."""
    step = _pick_step("adapt_recon_adv_strategy_picker")
    adv_rate_ms = int((args or {}).get("adv_interval_ms", 100))
    if adv_rate_ms < 50:
        pick, rationale = "passive_capture_burst", "fast ADV → capture burst (200ms window)"
    elif adv_rate_ms < 200:
        pick, rationale = "rolling_capture", "medium ADV → rolling 5s capture"
    else:
        pick, rationale = "extended_capture", "slow ADV → extended 30s capture"
    return _ok(step, {
        "pick": pick,
        "rationale": rationale,
        "model": "target-adaptive (heuristic)",
    })


# ---------------------------------------------------------------------------
# POLYMORPHIC v2 — forensics / post-exploit / OSINT / C2 (Phase 2.4 §H.2)
# ---------------------------------------------------------------------------

def poly_nmap_script_grammar(args: Dict[str, Any]) -> Dict[str, Any]:
    """Pick an NSE script category variant for nmap -sV scanning."""
    step = _step("poly_nmap_script_grammar")
    variants = [
        "vuln", "exploit", "auth", "brute", "discovery",
        "safe", "intrusive", "malware", "version", "fuzzer",
    ]
    import random
    rng = random.Random((args or {}).get("seed") or "nmap")
    picked = rng.sample(variants, k=3)
    return _ok(step, {
        "grammar": "nmap_script_category",
        "variants": picked,
        "primary": picked[0],
        "model": "polymorphic (heuristic)",
        "note": "Apply via: nmap -sV --script=<primary>,<variants> <target>",
    })


def poly_metasploit_module_grammar(args: Dict[str, Any]) -> Dict[str, Any]:
    """Pick a Metasploit module family for chained exploitation."""
    step = _step("poly_metasploit_module_grammar")
    families = [
        "exploit/windows/smb", "exploit/linux/http",
        "exploit/multi/handler", "post/windows/gather",
        "post/linux/gather", "auxiliary/scanner",
        "exploit/windows/http", "exploit/multi/http",
    ]
    import random
    rng = random.Random((args or {}).get("seed") or "msf")
    picked = rng.sample(families, k=3)
    return _ok(step, {
        "grammar": "msf_module_family",
        "variants": picked,
        "primary": picked[0],
        "model": "polymorphic (heuristic)",
    })


def poly_impacket_command_grammar(args: Dict[str, Any]) -> Dict[str, Any]:
    """Pick an impacket command family for lateral movement."""
    step = _step("poly_impacket_command_grammar")
    variants = [
        "psexec", "wmiexec", "smbexec", "atexec", "dcomexec",
        "secretsdump", "ntlmrelayx", "mssqlclient", "rpcdump",
    ]
    return _ok(step, {
        "grammar": "impacket_command",
        "variants": variants,
        "primary": variants[0],
        "model": "polymorphic (heuristic)",
        "note": "Always start with psexec if SMB open; fall back to wmiexec.",
    })


def poly_mimikatz_module_grammar(args: Dict[str, Any]) -> Dict[str, Any]:
    """Pick a mimikatz module for credential extraction."""
    step = _step("poly_mimikatz_module_grammar")
    variants = [
        "sekurlsa::logonpasswords", "lsadump::sam",
        "lsadump::dcsync", "lsadump::cache",
        "sekurlsa::tickets /export", "vault::cred",
        "crypto::exportPFX", "token::elevate",
    ]
    return _ok(step, {
        "grammar": "mimikatz_module",
        "variants": variants,
        "primary": variants[0],
        "model": "polymorphic (heuristic)",
    })


def poly_volatility_plugin_grammar(args: Dict[str, Any]) -> Dict[str, Any]:
    """Pick a Volatility plugin for memory forensics."""
    step = _step("poly_volatility_plugin_grammar")
    variants = [
        "windows.pslist", "windows.psscan", "windows.netscan",
        "windows.hashdump", "windows.lsadump", "windows.cachedump",
        "windows.cmdline", "windows.dlllist", "windows.handles",
        "windows.malfind", "windows.modules", "windows.sockets",
    ]
    return _ok(step, {
        "grammar": "volatility_plugin",
        "variants": variants,
        "primary": variants[0],
        "model": "polymorphic (heuristic)",
    })


def poly_disk_carving_grammar(args: Dict[str, Any]) -> Dict[str, Any]:
    """Pick a file-carving strategy for disk forensics."""
    step = _step("poly_disk_carving_grammar")
    variants = [
        "foremost_jpeg_pdf_doc", "binwalk_recursive",
        "photorec_bulk", "scalpel_yml", "bulk_extractor_zip",
    ]
    return _ok(step, {
        "grammar": "disk_carving",
        "variants": variants,
        "primary": variants[0],
        "model": "polymorphic (heuristic)",
    })


def poly_sleuthkit_cmd_grammar(args: Dict[str, Any]) -> Dict[str, Any]:
    """Pick a Sleuth Kit command for filesystem analysis."""
    step = _step("poly_sleuthkit_cmd_grammar")
    variants = [
        "fls -r /dev/sda1", "icat /dev/sda1 INODE",
        "mmls /dev/sda", "fsstat /dev/sda1",
        "istat /dev/sda1 INODE", "ils /dev/sda1",
    ]
    return _ok(step, {
        "grammar": "sleuthkit_cmd",
        "variants": variants,
        "primary": variants[0],
        "model": "polymorphic (heuristic)",
    })


def poly_persistence_mechanism_grammar(args: Dict[str, Any]) -> Dict[str, Any]:
    """Pick a persistence mechanism for a target OS."""
    step = _step("poly_persistence_mechanism_grammar")
    variants = [
        "windows:reg_run", "windows:scheduled_task",
        "windows:service", "windows:wmi_event",
        "linux:cron", "linux:systemd_unit",
        "linux:bashrc", "macos:launchd_plist",
    ]
    return _ok(step, {
        "grammar": "persistence_mechanism",
        "variants": variants,
        "primary": variants[0],
        "model": "polymorphic (heuristic)",
    })


def poly_exfil_channel_grammar(args: Dict[str, Any]) -> Dict[str, Any]:
    """Pick an exfiltration channel variant."""
    step = _step("poly_exfil_channel_grammar")
    variants = [
        "https_post_chunked", "dns_txt_subdomain",
        "icmp_echo_payload", "smtp_attachment", "ftp_stor",
        "telegram_bot_api", "dropbox_api", "pastebin_paste",
    ]
    return _ok(step, {
        "grammar": "exfil_channel",
        "variants": variants,
        "primary": variants[0],
        "model": "polymorphic (heuristic)",
    })


def poly_osint_user_agent_grammar(args: Dict[str, Any]) -> Dict[str, Any]:
    """Pick a User-Agent string variant for OSINT scraping."""
    step = _step("poly_osint_user_agent_grammar")
    variants = [
        "firefox_120_win", "chrome_120_mac", "safari_17_iphone",
        "edge_120_win", "curl_8_5_0", "python_requests_2_31",
        "googlebot_desktop", "tor_browser", "headless_chromium",
    ]
    import random
    rng = random.Random((args or {}).get("seed") or "ua")
    picked = rng.sample(variants, k=3)
    return _ok(step, {
        "grammar": "user_agent",
        "variants": picked,
        "primary": picked[0],
        "model": "polymorphic (heuristic)",
    })


# ---------------------------------------------------------------------------
# TARGET-ADAPTIVE v2 — multi-OS / C2 / OSINT picker companions
# ---------------------------------------------------------------------------

def adapt_target_os_picker(args: Dict[str, Any]) -> Dict[str, Any]:
    """Pick attack strategy based on target OS fingerprint."""
    step = _pick_step("adapt_target_os_picker")
    target_os = ((args or {}).get("os") or "unknown").lower()
    if "windows" in target_os:
        pick, rationale = "windows_smb_rdp", "Windows → SMB/RDP via impacket"
    elif "linux" in target_os:
        pick, rationale = "linux_ssh_https", "Linux → SSH/HTTP service abuse"
    elif "darwin" in target_os or "macos" in target_os or "osx" in target_os:
        pick, rationale = "macos_https_launchd", "macOS → HTTPS + launchd persist"
    elif "android" in target_os:
        pick, rationale = "android_adb_apk", "Android → adb / APK sideload"
    elif "ios" in target_os:
        pick, rationale = "ios_mdm_profile", "iOS → MDM / profile abuse"
    else:
        pick, rationale = "generic_https_enum", "Unknown OS → generic HTTPS enum"
    return _ok(step, {
        "pick": pick,
        "rationale": rationale,
        "detected_os": target_os,
        "model": "target-adaptive (heuristic)",
    })


def adapt_windows_version_picker(args: Dict[str, Any]) -> Dict[str, Any]:
    """Pick Windows exploit based on detected version."""
    step = _pick_step("adapt_windows_version_picker")
    win_ver = ((args or {}).get("version") or "").lower()
    # Order matters: most-specific to least-specific.
    # (Check for 8/7 in non-server, then server 2008/2003 separately.)
    if "11" in win_ver or "10" in win_ver:
        pick, rationale = (
            "msf_exploit_smb_eternalblue_or_ms17_010",
            f"Win {win_ver} → try MS17-010 / EternalBlue",
        )
    elif "server 2019" in win_ver or "server 2016" in win_ver or \
         "2016" in win_ver:
        pick, rationale = (
            "zerologon_or_printnightmare",
            f"Win Server {win_ver} → Zerologon / PrintNightmare",
        )
    elif "server 2008" in win_ver or "2003" in win_ver:
        pick, rationale = (
            "ms08_067_conficker",
            f"Legacy Win {win_ver} → MS08-067",
        )
    elif "8" in win_ver or "7" in win_ver:
        pick, rationale = (
            "ms17_010_eternalblue",
            f"Win {win_ver} → MS17-010 / EternalBlue",
        )
    else:
        pick, rationale = (
            "msf_recon_then_vuln_scan",
            f"Unknown Win {win_ver} → recon + vuln scan first",
        )
    return _ok(step, {
        "pick": pick,
        "rationale": rationale,
        "detected_version": win_ver,
        "model": "target-adaptive (heuristic)",
    })


def adapt_linux_distro_picker(args: Dict[str, Any]) -> Dict[str, Any]:
    """Pick Linux privesc strategy based on distro."""
    step = _pick_step("adapt_linux_distro_picker")
    distro = ((args or {}).get("distro") or "").lower()
    if "ubuntu" in distro:
        pick, rationale = (
            "linpeas + overlayfs_cve_2023_2640",
            "Ubuntu → overlayfs CVE-2023-2640 / CVE-2023-32629",
        )
    elif "debian" in distro:
        pick, rationale = (
            "linpeas + polkit_cve_2021_4034",
            "Debian → PwnKit (CVE-2021-4034)",
        )
    elif "centos" in distro or "rhel" in distro or "rocky" in distro:
        pick, rationale = (
            "linpeas + polkit + dirty_pipe",
            "RHEL family → PwnKit + DirtyPipe (CVE-2022-0847)",
        )
    elif "arch" in distro:
        pick, rationale = (
            "linpeas + sudo_pkexec",
            "Arch → linpeas + PwnKit",
        )
    elif "kali" in distro:
        pick, rationale = (
            "post_exploit_native",
            "Kali → run native post-exploit modules",
        )
    else:
        pick, rationale = (
            "linpeas_generic",
            f"Unknown {distro} → linpeas + sudo -l",
        )
    return _ok(step, {
        "pick": pick,
        "rationale": rationale,
        "detected_distro": distro,
        "model": "target-adaptive (heuristic)",
    })


def adapt_android_version_picker(args: Dict[str, Any]) -> Dict[str, Any]:
    """Pick Android exploit based on detected version."""
    step = _pick_step("adapt_android_version_picker")
    sdk = int((args or {}).get("sdk") or 0)
    if sdk and sdk < 26:
        pick, rationale = (
            "stagefright_or_root_su",
            f"Android SDK {sdk} (<26) → Stagefright / root",
        )
    elif sdk and sdk < 30:
        pick, rationale = (
            "blueborne_or_pileup",
            f"Android SDK {sdk} (26-29) → BlueBorne / PileUp",
        )
    else:
        pick, rationale = (
            "adb_install_frida",
            f"Android SDK {sdk} (>=30) → adb + Frida runtime",
        )
    return _ok(step, {
        "pick": pick,
        "rationale": rationale,
        "detected_sdk": sdk,
        "model": "target-adaptive (heuristic)",
    })


def adapt_ios_version_picker(args: Dict[str, Any]) -> Dict[str, Any]:
    """Pick iOS post-exploit based on detected version."""
    step = _pick_step("adapt_ios_version_picker")
    ios = ((args or {}).get("version") or "").lower()
    if "15" in ios or "16" in ios:
        pick, rationale = (
            "checkm8_or_forcedentry",
            f"iOS {ios} → checkm8 / FORCEDENTRY (older devices)",
        )
    elif "17" in ios or "18" in ios:
        pick, rationale = (
            "mdm_profile_abuse",
            f"iOS {ios} → MDM profile / supervised-mode abuse",
        )
    else:
        pick, rationale = (
            "ios_recon_backup",
            f"iOS {ios} → encrypted backup extraction first",
        )
    return _ok(step, {
        "pick": pick,
        "rationale": rationale,
        "detected_ios": ios,
        "model": "target-adaptive (heuristic)",
    })


def adapt_macos_version_picker(args: Dict[str, Any]) -> Dict[str, Any]:
    """Pick macOS post-exploit strategy based on detected version."""
    step = _pick_step("adapt_macos_version_picker")
    mac = ((args or {}).get("version") or "").lower()
    if "10.14" in mac or "10.15" in mac:
        pick, rationale = (
            "keysteal_or_keychaindump",
            f"macOS {mac} → Keysteal / keychaindump",
        )
    elif "11" in mac or "12" in mac or "13" in mac:
        pick, rationale = (
            "cfprefsd_or_dyld",
            f"macOS {mac} → cfprefsd / dyld abuse",
        )
    elif "14" in mac or "15" in mac:
        pick, rationale = (
            "tcc_bypass_launchd",
            f"macOS {mac} → TCC bypass / launchd persist",
        )
    else:
        pick, rationale = (
            "macos_recon_first",
            f"Unknown macOS {mac} → recon before exploit",
        )
    return _ok(step, {
        "pick": pick,
        "rationale": rationale,
        "detected_macos": mac,
        "model": "target-adaptive (heuristic)",
    })


def adapt_c2_transport_picker(args: Dict[str, Any]) -> Dict[str, Any]:
    """Pick a C2 transport based on network constraints."""
    step = _pick_step("adapt_c2_transport_picker")
    has_https = bool((args or {}).get("https_egress"))
    has_dns = bool((args or {}).get("dns_egress"))
    has_icmp = bool((args or {}).get("icmp_egress"))
    if has_https:
        pick, rationale = "https_c2", "HTTPS egress available → HTTPS C2"
    elif has_dns:
        pick, rationale = "dns_tunnel_c2", "DNS only → DNS-tunnel C2"
    elif has_icmp:
        pick, rationale = "icmp_c2", "ICMP only → ICMP C2"
    else:
        pick, rationale = "tor_hidden_service", "No clear egress → Tor HS"
    return _ok(step, {
        "pick": pick,
        "rationale": rationale,
        "model": "target-adaptive (heuristic)",
    })


def adapt_c2_framework_picker(args: Dict[str, Any]) -> Dict[str, Any]:
    """Pick a C2 framework based on target + operator skill."""
    step = _pick_step("adapt_c2_framework_picker")
    target_os = ((args or {}).get("target_os") or "").lower()
    skill = ((args or {}).get("operator_skill") or "intermediate").lower()
    if "windows" in target_os and skill in ("expert", "advanced"):
        pick, rationale = (
            "covenant_or_merlin",
            "Windows + expert operator → C# Covenant / Merlin",
        )
    elif "linux" in target_os:
        pick, rationale = (
            "sliver_or_mythic",
            "Linux → Sliver / Mythic (Go agents)",
        )
    elif "macos" in target_os or "darwin" in target_os:
        pick, rationale = (
            "sliver_or_empire",
            "macOS → Sliver (Go) or Empire (JXA)",
        )
    elif "android" in target_os:
        pick, rationale = (
            "mobsf_or_objection",
            "Android → MobSF / objection (runtime)",
        )
    elif skill == "beginner":
        pick, rationale = (
            "metasploit_msfvenom",
            "Beginner operator → Metasploit + msfvenom",
        )
    else:
        pick, rationale = (
            "sliver_default",
            "Default → Sliver (cross-platform Go C2)",
        )
    return _ok(step, {
        "pick": pick,
        "rationale": rationale,
        "model": "target-adaptive (heuristic)",
    })


def adapt_osint_source_picker(args: Dict[str, Any]) -> Dict[str, Any]:
    """Pick an OSINT source based on target type."""
    step = _pick_step("adapt_osint_source_picker")
    target_type = ((args or {}).get("target_type") or "person").lower()
    if target_type == "person":
        pick, rationale = (
            "github_sherlock_hibp_nameday",
            "Person → GitHub + Sherlock + HIBP + nameday",
        )
    elif target_type == "domain":
        pick, rationale = (
            "amass_subfinder_dnsrecon",
            "Domain → amass + subfinder + dnsrecon",
        )
    elif target_type == "email":
        pick, rationale = (
            "hibp_gravatar_ghunt",
            "Email → HIBP + Gravatar + GHunt",
        )
    elif target_type == "company":
        pick, rationale = (
            "ceidg_knf_shodan_censys",
            "Company → CEIDG/KNF + Shodan + Censys",
        )
    elif target_type == "ip":
        pick, rationale = (
            "shodan_censys_nmap",
            "IP → Shodan + Censys + nmap",
        )
    else:
        pick, rationale = (
            "github_recon_ng",
            f"Unknown {target_type} → recon-ng baseline",
        )
    return _ok(step, {
        "pick": pick,
        "rationale": rationale,
        "detected_target_type": target_type,
        "model": "target-adaptive (heuristic)",
    })


def adapt_evidence_format_picker(args: Dict[str, Any]) -> Dict[str, Any]:
    """Pick a forensic evidence output format."""
    step = _pick_step("adapt_evidence_format_picker")
    audience = ((args or {}).get("audience") or "internal").lower()
    if audience == "court":
        pick, rationale = "e01_ewf_with_chain_of_custody", "Court → EWF/E01 with chain-of-custody"
    elif audience == "law_enforcement":
        pick, rationale = "raw_dd_with_sha256", "LE → raw dd + SHA-256 manifest"
    elif audience == "ir_team":
        pick, rationale = "triage_plaso_csv", "IR team → Plaso CSV timeline"
    elif audience == "auditor":
        pick, rationale = "pdf_report_fpdf2", "Auditor → PDF report via fpdf2"
    else:
        pick, rationale = "json_timeline", "Internal → JSON timeline"
    return _ok(step, {
        "pick": pick,
        "rationale": rationale,
        "detected_audience": audience,
        "model": "target-adaptive (heuristic)",
    })


# ---------------------------------------------------------------------------
# Registry — Phase 5
# ---------------------------------------------------------------------------

POLY_ADAPT_REGISTRY: Dict[str, Any] = {
    # Polymorphic
    "poly_deauth_burst_pattern_grammar": poly_deauth_burst_pattern_grammar,
    "poly_eapol_replay_grammar": poly_eapol_replay_grammar,
    "poly_pmkid_eapol_field_grammar": poly_pmkid_eapol_field_grammar,
    "poly_wps_eap_failure_grammar": poly_wps_eap_failure_grammar,
    "poly_evil_twin_hostapd_conf_grammar": poly_evil_twin_hostapd_conf_grammar,
    "poly_passive_scan_channel_hop_grammar": poly_passive_scan_channel_hop_grammar,
    "poly_client_probe_request_grammar": poly_client_probe_request_grammar,
    "poly_gatt_value_template": poly_gatt_value_template,
    "poly_hid_report_template": poly_hid_report_template,
    "poly_adv_data_template_grammar": poly_adv_data_template_grammar,
    # Polymorphic v2 (Phase 2.4 §H.2)
    "poly_nmap_script_grammar": poly_nmap_script_grammar,
    "poly_metasploit_module_grammar": poly_metasploit_module_grammar,
    "poly_impacket_command_grammar": poly_impacket_command_grammar,
    "poly_mimikatz_module_grammar": poly_mimikatz_module_grammar,
    "poly_volatility_plugin_grammar": poly_volatility_plugin_grammar,
    "poly_disk_carving_grammar": poly_disk_carving_grammar,
    "poly_sleuthkit_cmd_grammar": poly_sleuthkit_cmd_grammar,
    "poly_persistence_mechanism_grammar": poly_persistence_mechanism_grammar,
    "poly_exfil_channel_grammar": poly_exfil_channel_grammar,
    "poly_osint_user_agent_grammar": poly_osint_user_agent_grammar,
    # Target-adaptive
    "adapt_attack_deauth_strategy_picker": adapt_attack_deauth_strategy_picker,
    "adapt_attack_handshake_strategy_picker": adapt_attack_handshake_strategy_picker,
    "adapt_attack_pmkid_target_picker": adapt_attack_pmkid_target_picker,
    "adapt_attack_wps_strategy_picker": adapt_attack_wps_strategy_picker,
    "adapt_attack_evil_twin_strategy_picker": adapt_attack_evil_twin_strategy_picker,
    "adapt_recon_scan_strategy_picker": adapt_recon_scan_strategy_picker,
    "adapt_recon_client_strategy_picker": adapt_recon_client_strategy_picker,
    "adapt_attack_gatt_strategy_picker": adapt_attack_gatt_strategy_picker,
    "adapt_attack_hid_strategy_picker": adapt_attack_hid_strategy_picker,
    "adapt_recon_adv_strategy_picker": adapt_recon_adv_strategy_picker,
    # Target-adaptive v2 (Phase 2.4 §H.2)
    "adapt_target_os_picker": adapt_target_os_picker,
    "adapt_windows_version_picker": adapt_windows_version_picker,
    "adapt_linux_distro_picker": adapt_linux_distro_picker,
    "adapt_android_version_picker": adapt_android_version_picker,
    "adapt_ios_version_picker": adapt_ios_version_picker,
    "adapt_macos_version_picker": adapt_macos_version_picker,
    "adapt_c2_transport_picker": adapt_c2_transport_picker,
    "adapt_c2_framework_picker": adapt_c2_framework_picker,
    "adapt_osint_source_picker": adapt_osint_source_picker,
    "adapt_evidence_format_picker": adapt_evidence_format_picker,
}


# Risk levels for the chain gate (destructive = gated ACCEPT)
POLY_ADAPT_RISK: Dict[str, str] = {
    # Polymorphic — never destructive
    **{k: "intrusive" for k in [
        "poly_deauth_burst_pattern_grammar", "poly_eapol_replay_grammar",
        "poly_pmkid_eapol_field_grammar", "poly_wps_eap_failure_grammar",
        "poly_evil_twin_hostapd_conf_grammar",
        "poly_passive_scan_channel_hop_grammar",
        "poly_client_probe_request_grammar", "poly_gatt_value_template",
        "poly_hid_report_template", "poly_adv_data_template_grammar",
        # Polymorphic v2
        "poly_nmap_script_grammar", "poly_metasploit_module_grammar",
        "poly_impacket_command_grammar", "poly_mimikatz_module_grammar",
        "poly_volatility_plugin_grammar", "poly_disk_carving_grammar",
        "poly_sleuthkit_cmd_grammar", "poly_persistence_mechanism_grammar",
        "poly_exfil_channel_grammar", "poly_osint_user_agent_grammar",
    ]},
    # Target-adaptive — never destructive
    **{k: "intrusive" for k in [
        "adapt_attack_deauth_strategy_picker",
        "adapt_attack_handshake_strategy_picker",
        "adapt_attack_pmkid_target_picker",
        "adapt_attack_wps_strategy_picker",
        "adapt_attack_evil_twin_strategy_picker",
        "adapt_recon_scan_strategy_picker",
        "adapt_recon_client_strategy_picker",
        "adapt_attack_gatt_strategy_picker",
        "adapt_attack_hid_strategy_picker",
        "adapt_recon_adv_strategy_picker",
        # Target-adaptive v2
        "adapt_target_os_picker", "adapt_windows_version_picker",
        "adapt_linux_distro_picker", "adapt_android_version_picker",
        "adapt_ios_version_picker", "adapt_macos_version_picker",
        "adapt_c2_transport_picker", "adapt_c2_framework_picker",
        "adapt_osint_source_picker", "adapt_evidence_format_picker",
    ]},
}


# Description for the LLM (used by prompt stanza)
POLY_ADAPT_DESCRIPTIONS: Dict[str, str] = {
    "poly_deauth_burst_pattern_grammar":
        "Pick a deauth-burst pattern (ramp, constant, exponential, etc).",
    "poly_eapol_replay_grammar":
        "Pick an EAPOL replay-counter strategy.",
    "poly_pmkid_eapol_field_grammar":
        "Pick which EAPOL fields to mutate for PMKID harvesting.",
    "poly_wps_eap_failure_grammar":
        "Pick a WPS EAP-failure injection variant.",
    "poly_evil_twin_hostapd_conf_grammar":
        "Pick a hostapd config template for Evil Twin.",
    "poly_passive_scan_channel_hop_grammar":
        "Pick a channel-hop sequence for passive scan.",
    "poly_client_probe_request_grammar":
        "Pick which client-probe types to listen for.",
    "poly_gatt_value_template":
        "Pick a GATT write-value template.",
    "poly_hid_report_template":
        "Pick a HID-injection report template.",
    "poly_adv_data_template_grammar":
        "Pick an advertising data template.",
    "adapt_attack_deauth_strategy_picker":
        "Pick deauth strategy from PMF + client count.",
    "adapt_attack_handshake_strategy_picker":
        "Pick handshake-capture strategy from WPA version.",
    "adapt_attack_pmkid_target_picker":
        "Pick PMKID vs standard from 11k presence.",
    "adapt_attack_wps_strategy_picker":
        "Pick WPS strategy from WPS-locked state.",
    "adapt_attack_evil_twin_strategy_picker":
        "Pick Evil-Twin strategy from captive portal presence.",
    "adapt_recon_scan_strategy_picker":
        "Pick recon-scan strategy from band presence.",
    "adapt_recon_client_strategy_picker":
        "Pick client-detection from probe count.",
    "adapt_attack_gatt_strategy_picker":
        "Pick GATT-attack from service count + encryption.",
    "adapt_attack_hid_strategy_picker":
        "Pick HID-injection from target OS.",
    "adapt_recon_adv_strategy_picker":
        "Pick ADV-recon from ADV interval.",
    # Polymorphic v2
    "poly_nmap_script_grammar":
        "Pick NSE script category for nmap -sV.",
    "poly_metasploit_module_grammar":
        "Pick Metasploit module family for chained exploit.",
    "poly_impacket_command_grammar":
        "Pick impacket command family for lateral movement.",
    "poly_mimikatz_module_grammar":
        "Pick mimikatz module for credential extraction.",
    "poly_volatility_plugin_grammar":
        "Pick Volatility plugin for memory forensics.",
    "poly_disk_carving_grammar":
        "Pick file-carving strategy (foremost/binwalk/photorec).",
    "poly_sleuthkit_cmd_grammar":
        "Pick Sleuth Kit command (fls/icat/mmls/istat).",
    "poly_persistence_mechanism_grammar":
        "Pick persistence mechanism for target OS.",
    "poly_exfil_channel_grammar":
        "Pick exfiltration channel variant.",
    "poly_osint_user_agent_grammar":
        "Pick User-Agent variant for OSINT scraping.",
    # Target-adaptive v2
    "adapt_target_os_picker":
        "Pick attack strategy from target OS fingerprint.",
    "adapt_windows_version_picker":
        "Pick Windows exploit from detected version.",
    "adapt_linux_distro_picker":
        "Pick Linux privesc strategy from detected distro.",
    "adapt_android_version_picker":
        "Pick Android exploit from detected SDK version.",
    "adapt_ios_version_picker":
        "Pick iOS post-exploit from detected iOS version.",
    "adapt_macos_version_picker":
        "Pick macOS post-exploit from detected version.",
    "adapt_c2_transport_picker":
        "Pick C2 transport (HTTPS/DNS/ICMP/Tor) from egress.",
    "adapt_c2_framework_picker":
        "Pick C2 framework (Sliver/Empire/MSF) from target+skill.",
    "adapt_osint_source_picker":
        "Pick OSINT source from target type.",
    "adapt_evidence_format_picker":
        "Pick forensic evidence format from audience.",
}


def list_poly_adapt_methods() -> List[str]:
    return list(POLY_ADAPT_REGISTRY.keys())


def describe_poly_adapt_method(name: str) -> Optional[Dict[str, str]]:
    if name not in POLY_ADAPT_REGISTRY:
        return None
    return {
        "name": name,
        "risk": POLY_ADAPT_RISK.get(name, "intrusive"),
        "description": POLY_ADAPT_DESCRIPTIONS.get(name, ""),
    }


def run_poly_adapt(name: str, args: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Dispatch a polymorphic / target-adaptive method by name."""
    fn = POLY_ADAPT_REGISTRY.get(name)
    if fn is None:
        return {
            "name": name, "ok": False,
            "error": f"unknown poly_adapt method {name!r}",
            "data": None, "duration_s": 0.0,
        }
    try:
        return fn(args or {})
    except Exception as e:  # noqa: BLE001
        step = _step(name)
        step["ok"] = False
        step["error"] = f"unhandled: {e}"
        step["duration_s"] = round(time.time() - step.get("started", time.time()), 3)
        return step


# Phase 5 prompt stanza
def build_poly_adapt_prompt_stanza() -> str:
    """Build a stanza that the LLM can read to discover the poly/adapt
    companions. The list is split into polymorphic (grammar) and
    target-adaptive (picker) sections."""
    poly = [m for m in POLY_ADAPT_REGISTRY if m.startswith("poly_")]
    adapt = [m for m in POLY_ADAPT_REGISTRY if m.startswith("adapt_")]
    lines = [
        "POLYMORPHIC GRAMMAR COMPANIONS (Phase 2.4 §H):",
        *["  - " + m for m in poly],
        "",
        "TARGET-ADAPTIVE PICKER COMPANIONS (Phase 2.4 §H):",
        *["  - " + m for m in adapt],
        "",
        "Use these companions to derive a recommended action from",
        "observed state. The companion returns a {pick, rationale}",
        "envelope (or a {variants, primary} for grammars). The",
        "next real chain step then uses the picked variant.",
        "NEVER fabricate CVEs / hashes / cracked PSKs / cleartext",
        "credentials. The companion is a heuristic, not a trained",
        "ML model — envelope data.model is always",
        "'polymorphic (heuristic)' or 'target-adaptive (heuristic)'.",
    ]
    return "\n".join(lines)


__all__ = [
    "POLY_ADAPT_REGISTRY",
    "POLY_ADAPT_RISK",
    "POLY_ADAPT_DESCRIPTIONS",
    "list_poly_adapt_methods",
    "describe_poly_adapt_method",
    "run_poly_adapt",
    "build_poly_adapt_prompt_stanza",
]
