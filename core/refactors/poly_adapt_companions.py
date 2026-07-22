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
# POLYMORPHIC v3 (Phase 3 expansion) — 10 more grammars (2 per category)
# ---------------------------------------------------------------------------

def poly_wpa3_sae_grammar(args: Dict[str, Any]) -> Dict[str, Any]:
    """Pick a WPA3-SAE attack variant.

    Variants are real WPA3 attack research categories. None of them
    produce a cracked PSK — they describe the protocol-level pattern
    the next chain step would apply.
    """
    import random
    step = _step("poly_wpa3_sae_grammar")
    seed = (args or {}).get("seed") or "sae"
    rng = random.Random(str(seed))
    patterns = [
        "sae_commit_flood_dos",
        "sae_side_channel_timing",
        "sae_antipattern_legacy_overlap",
        "sae_zero_password_drag",
        "sae_handshake_drown",
    ]
    weights = [3, 3, 2, 2, 1]
    picked = rng.choices(patterns, weights=weights, k=3)
    return _ok(step, {
        "grammar": "wpa3_sae",
        "variants": picked,
        "primary": picked[0],
        "model": "polymorphic (heuristic)",
        "note": "Use the primary variant for the next SAE chain step.",
    })


def poly_eapol_key_replay_grammar(args: Dict[str, Any]) -> Dict[str, Any]:
    """Pick an EAPOL-Key replay counter-mutation strategy.

    Mirrors the patterns in the original KRACK research. The LLM
    uses the picked variant to drive a 4-way handshake step.
    """
    import random
    step = _step("poly_eapol_key_replay_grammar")
    seed = (args or {}).get("seed") or "krack"
    rng = random.Random(str(seed))
    patterns = [
        "replay_msg3_installer",
        "replay_msg3_group_key",
        "replay_msg4_ack_mismatch",
        "replay_msg1_key_reinstall",
    ]
    weights = [3, 3, 2, 2]
    picked = rng.choices(patterns, weights=weights, k=3)
    return _ok(step, {
        "grammar": "eapol_key_replay",
        "variants": picked,
        "primary": picked[0],
        "model": "polymorphic (heuristic)",
        "note": "Use the primary pattern for the next EAPOL replay step.",
    })


def poly_ble_ll_fragment_grammar(args: Dict[str, Any]) -> Dict[str, Any]:
    """Pick a BLE Link-Layer fragment-reassembly pattern."""
    import random
    step = _step("poly_ble_ll_fragment_grammar")
    seed = (args or {}).get("seed") or "ble_ll"
    rng = random.Random(str(seed))
    patterns = [
        "fragment_overlap_inject",
        "fragment_order_swap",
        "fragment_replay_old",
        "fragment_length_extension",
    ]
    weights = [2, 2, 3, 2]
    picked = rng.choices(patterns, weights=weights, k=3)
    return _ok(step, {
        "grammar": "ble_ll_fragment",
        "variants": picked,
        "primary": picked[0],
        "model": "polymorphic (heuristic)",
        "note": "Use the primary pattern for the next LL step.",
    })


def poly_gatt_write_payload_grammar(args: Dict[str, Any]) -> Dict[str, Any]:
    """Pick a GATT-write payload template for fuzzing."""
    import random
    step = _step("poly_gatt_write_payload_grammar")
    seed = (args or {}).get("seed") or "gatt"
    rng = random.Random(str(seed))
    patterns = [
        "long_write_split_at_mtu",
        "write_prepare_reliable",
        "write_unsigned_vs_signed",
        "write_value_0xff_storm",
        "write_value_incrementing",
    ]
    weights = [3, 3, 2, 1, 2]
    picked = rng.choices(patterns, weights=weights, k=3)
    return _ok(step, {
        "grammar": "gatt_write_payload",
        "variants": picked,
        "primary": picked[0],
        "model": "polymorphic (heuristic)",
        "note": "Use the primary payload for the next GATT write.",
    })


def poly_email_pattern_grammar(args: Dict[str, Any]) -> Dict[str, Any]:
    """Pick an email-pattern heuristic for OSINT discovery.

    No real emails are produced. The 'variants' are search-pattern
    templates the LLM can run against an OSINT source it already
    has credentials/keys for (per the OSINT safety rules).
    """
    import random
    step = _step("poly_email_pattern_grammar")
    seed = (args or {}).get("seed") or "email"
    rng = random.Random(str(seed))
    patterns = [
        "firstname_lastname_at_domain",
        "f_lastname_at_domain",
        "firstnamel_at_domain",
        "lastnamef_at_domain",
        "role_based_admin_at_domain",
    ]
    weights = [3, 3, 2, 2, 2]
    picked = rng.choices(patterns, weights=weights, k=3)
    return _ok(step, {
        "grammar": "email_pattern",
        "variants": picked,
        "primary": picked[0],
        "model": "polymorphic (heuristic)",
        "note": "Use the primary pattern to query the OSINT source.",
    })


def poly_dorking_query_grammar(args: Dict[str, Any]) -> Dict[str, Any]:
    """Pick a Google-dorking query template for OSINT.

    The 'variants' are Google dork *templates* (not pre-filled
    queries). They contain placeholders the operator/LLM fills
    at chain-step time.
    """
    import random
    step = _step("poly_dorking_query_grammar")
    seed = (args or {}).get("seed") or "dork"
    rng = random.Random(str(seed))
    patterns = [
        "site:{target} filetype:{ext} {keyword}",
        'inurl:{target} "{keyword}"',
        "intitle:{keyword} site:{target}",
        "{keyword} ext:sql | ext:csv | ext:log site:{target}",
        "cache:{target} {keyword}",
    ]
    weights = [3, 3, 2, 1, 2]
    picked = rng.choices(patterns, weights=weights, k=3)
    return _ok(step, {
        "grammar": "dorking_query",
        "variants": picked,
        "primary": picked[0],
        "model": "polymorphic (heuristic)",
        "note": "Fill {target} / {ext} / {keyword} at step time.",
    })


def poly_disk_carve_signature_grammar(args: Dict[str, Any]) -> Dict[str, Any]:
    """Pick a file-carving signature for forensic recovery."""
    import random
    step = _step("poly_disk_carve_signature_grammar")
    seed = (args or {}).get("seed") or "carve"
    rng = random.Random(str(seed))
    patterns = [
        "header_footer_jpeg_png_pdf",
        "magic_bytes_kdbx_zip_7z",
        "ntfs_mft_resident",
        "ext4_inode_journal",
        "registry_hive_cells",
    ]
    weights = [3, 3, 2, 1, 2]
    picked = rng.choices(patterns, weights=weights, k=3)
    return _ok(step, {
        "grammar": "disk_carve_signature",
        "variants": picked,
        "primary": picked[0],
        "model": "polymorphic (heuristic)",
        "note": "Use the primary signature for the next carve step.",
    })


def poly_memory_yara_pattern_grammar(args: Dict[str, Any]) -> Dict[str, Any]:
    """Pick a YARA pattern style for memory forensics."""
    import random
    step = _step("poly_memory_yara_pattern_grammar")
    seed = (args or {}).get("seed") or "yara"
    rng = random.Random(str(seed))
    patterns = [
        "ascii_string_mimikatz",
        "wide_string_powershell",
        "hex_pattern_pe_header",
        "regex_url_c2",
        "pe_section_name_anomaly",
    ]
    weights = [3, 3, 2, 2, 2]
    picked = rng.choices(patterns, weights=weights, k=3)
    return _ok(step, {
        "grammar": "memory_yara",
        "variants": picked,
        "primary": picked[0],
        "model": "polymorphic (heuristic)",
        "note": "Use the primary pattern for the next YARA scan.",
    })


def poly_lateral_movement_grammar(args: Dict[str, Any]) -> Dict[str, Any]:
    """Pick a lateral-movement vector variant.

    No real credentials are produced. The variant is a *category*
    the LLM chains into the next step.
    """
    import random
    step = _step("poly_lateral_movement_grammar")
    seed = (args or {}).get("seed") or "lateral"
    rng = random.Random(str(seed))
    patterns = [
        "psexec_service_install",
        "wmi_exec_remote",
        "winrm_ps_remoting",
        "rdp_pass_the_hash",
        "smb_exec_at_exec",
        "ssh_key_pivot",
    ]
    weights = [3, 3, 3, 2, 2, 2]
    picked = rng.choices(patterns, weights=weights, k=3)
    return _ok(step, {
        "grammar": "lateral_movement",
        "variants": picked,
        "primary": picked[0],
        "model": "polymorphic (heuristic)",
        "note": "Use the primary vector for the next pivot step.",
    })


def poly_persistence_registry_grammar(args: Dict[str, Any]) -> Dict[str, Any]:
    """Pick a Windows-Registry persistence Run-key variant."""
    import random
    step = _step("poly_persistence_registry_grammar")
    seed = (args or {}).get("seed") or "persist"
    rng = random.Random(str(seed))
    patterns = [
        "hkcu_software_microsoft_windows_currentversion_run",
        "hklm_software_microsoft_windows_currentversion_run",
        "hklm_system_currentcontrolset_services",
        "hkcu_environment_userinit",
        "hklm_software_microsoft_windows_nt_currentversion_winlogon",
    ]
    weights = [3, 2, 2, 1, 1]
    picked = rng.choices(patterns, weights=weights, k=3)
    return _ok(step, {
        "grammar": "persistence_registry",
        "variants": picked,
        "primary": picked[0],
        "model": "polymorphic (heuristic)",
        "note": "Use the primary key for the next persistence step.",
    })


# ---------------------------------------------------------------------------
# TARGET-ADAPTIVE v3 (Phase 3 expansion) — 10 more pickers (2 per category)
# ---------------------------------------------------------------------------

def adapt_wifi_chipset_picker(args: Dict[str, Any]) -> Dict[str, Any]:
    """Pick a monitor-mode driver based on the detected WiFi chipset."""
    step = _step("adapt_wifi_chipset_picker")
    chipset = (str((args or {}).get("chipset") or "")).lower()
    if "mt7922" in chipset or "mt7921" in chipset:
        pick, rationale = "mt7921e_nexmon_monitor", "MediaTek MT7922 — use mt7921e + nexmon monitor shim"
    elif "ath10k" in chipset or "ath9k" in chipset:
        pick, rationale = "ath10k_testmode", "Qualcomm Atheros — use ath10k testmode"
    elif "iwlwifi" in chipset or "intel" in chipset:
        pick, rationale = "iwlwifi_monitor_restricted", "Intel — iwlwifi monitor mode is restricted to 5 GHz on most firmwares"
    elif "rtw88" in chipset or "realtek" in chipset:
        pick, rationale = "rtw88_monitor", "Realtek — use rtw88 driver monitor mode"
    elif "brcm" in chipset or "broadcom" in chipset:
        pick, rationale = "b43_monitor", "Broadcom — use b43 with b43-fwcutter"
    else:
        pick, rationale = "generic_nl80211_monitor", f"Unknown chipset {chipset!r} — fall back to generic nl80211 monitor"
    return _ok(step, {
        "pick": pick,
        "rationale": rationale,
        "detected_chipset": chipset or "unknown",
        "model": "target-adaptive (heuristic)",
    })


def adapt_wifi_channel_width_picker(args: Dict[str, Any]) -> Dict[str, Any]:
    """Pick the channel width for the next scan / attack step."""
    step = _step("adapt_wifi_channel_width_picker")
    band = (str((args or {}).get("band") or "")).lower()
    target = (str((args or {}).get("target") or "")).lower()
    if "6e" in band or "6ghz" in band or "wifi6e" in target or "wifi7" in target:
        pick, rationale = "160mhz", "WiFi 6E/7 — 160 MHz channels available"
    elif "5ghz" in band or "5g" in band:
        pick, rationale = "80mhz", "5 GHz — 80 MHz is the common width"
    elif "2_4" in band or "2.4" in band or "2g" in band:
        pick, rationale = "20mhz", "2.4 GHz — 20 MHz to avoid overlap"
    else:
        pick, rationale = "20mhz", f"Unknown band {band!r} — default 20 MHz"
    return _ok(step, {
        "pick": pick,
        "rationale": rationale,
        "detected_band": band or "unknown",
        "model": "target-adaptive (heuristic)",
    })


def adapt_ble_chipset_picker(args: Dict[str, Any]) -> Dict[str, Any]:
    """Pick a BLE strategy based on the detected chipset."""
    step = _step("adapt_ble_chipset_picker")
    chip = (str((args or {}).get("chipset") or "")).lower()
    if "mt7922" in chip or "mt7921" in chip:
        pick, rationale = "mediatek_via_bluetoothctl", "MT7922 — use bluetoothctl / btmon for scan, no promiscuous mode"
    elif ("u4000" in chip or "ub500" in chip or "cambridge" in chip
          or "realtek" in chip):
        # The operator's hardware is the U4000 BLUETOOTH adapter
        # (Realtek chipset). The substring matcher is intentionally
        # tolerant of older "ub500" / "ub500 Plus" labels too.
        pick, rationale = "realtek_via_btmon", "U4000 BLUETOOTH adapter (Realtek) — btmon can capture ADV + some LL data"
    elif "intel" in chip or "ax200" in chip or "ax210" in chip:
        pick, rationale = "intel_via_bluetoothctl", "Intel AX200/AX210 — use bluetoothctl + hcitool lescan"
    else:
        pick, rationale = "generic_hcitool_lescan", f"Unknown BLE chipset {chip!r} — fall back to hcitool lescan"
    return _ok(step, {
        "pick": pick,
        "rationale": rationale,
        "detected_chipset": chip or "unknown",
        "model": "target-adaptive (heuristic)",
    })


def adapt_ble_pairing_method_picker(args: Dict[str, Any]) -> Dict[str, Any]:
    """Pick a BLE pairing method based on advertised IO capabilities."""
    step = _step("adapt_ble_pairing_method_picker")
    io = (str((args or {}).get("io_cap") or "")).lower()
    auth = bool((args or {}).get("auth_required"))
    if auth and ("display" in io or "keyboard" in io):
        pick, rationale = "passcode_entry", "Display/Keyboard + auth → passcode entry (LE Secure Connections)"
    elif "out" in io or "none" in io:
        pick, rationale = "just_works", "NoInput/NoOutput → Just Works pairing"
    elif "display" in io:
        pick, rationale = "numeric_compare", "DisplayOnly → numeric compare"
    elif "keyboard" in io:
        pick, rationale = "passkey_entry", "KeyboardOnly → passkey entry"
    else:
        pick, rationale = "legacy_007", f"Unknown IO {io!r} — default to legacy pairing (BR/EDR fallback or 0x07)"
    return _ok(step, {
        "pick": pick,
        "rationale": rationale,
        "detected_io_cap": io or "unknown",
        "model": "target-adaptive (heuristic)",
    })


def adapt_osint_jurisdiction_picker(args: Dict[str, Any]) -> Dict[str, Any]:
    """Pick an OSINT source by jurisdiction.

    Only sources the OSINT catalog already integrates with are
    emitted (no fabricated APIs).
    """
    step = _step("adapt_osint_jurisdiction_picker")
    jur = (str((args or {}).get("jurisdiction") or "")).lower()
    if "pl" in jur or "poland" in jur or "polish" in jur:
        pick, rationale = "ceidg_knf", "PL — CEIDG (firms) + KNF (finance)"
    elif "eu" in jur:
        pick, rationale = "eur_company_registry_vat", "EU — VAT validation + national registries"
    elif "us" in jur or "usa" in jur:
        pick, rationale = "github_nameday_hibp", "US — GitHub (no key) + nameday + HIBP k-anonymity"
    elif "cn" in jur or "china" in jur:
        pick, rationale = "github_nameday", "CN — GitHub (no key) + nameday; no fabricated Chinese APIs"
    else:
        pick, rationale = "github_nameday_hibp", f"Unknown jurisdiction {jur!r} — fall back to no-key sources (GitHub + nameday + HIBP)"
    return _ok(step, {
        "pick": pick,
        "rationale": rationale,
        "detected_jurisdiction": jur or "unknown",
        "model": "target-adaptive (heuristic)",
    })


def adapt_osint_query_language_picker(args: Dict[str, Any]) -> Dict[str, Any]:
    """Pick a query language for the OSINT source."""
    step = _step("adapt_osint_query_language_picker")
    target = (str((args or {}).get("target") or "")).lower()
    if "github" in target or "code" in target:
        pick, rationale = "github_search_qualifiers", "GitHub — use search qualifiers (repo:org language:python)"
    elif "email" in target or "people" in target:
        pick, rationale = "boolean", "People-search — use boolean (AND/OR/NOT)"
    elif "graph" in target or "entity" in target:
        pick, rationale = "cypher", "Graph source — use Cypher (Neo4j-style)"
    else:
        pick, rationale = "natural", f"Unknown target {target!r} — use natural-language query"
    return _ok(step, {
        "pick": pick,
        "rationale": rationale,
        "detected_target": target or "unknown",
        "model": "target-adaptive (heuristic)",
    })


def adapt_forensics_image_format_picker(args: Dict[str, Any]) -> Dict[str, Any]:
    """Pick a forensic image format from audience + tool availability."""
    step = _step("adapt_forensics_image_format_picker")
    audience = (str((args or {}).get("audience") or "")).lower()
    has_ewf = bool((args or {}).get("has_ewf"))
    if "court" in audience or "law_enforcement" in audience or has_ewf:
        pick, rationale = "ewf_e01", "Court/LE — EWF/E01 (requires libewf)"
    elif "raw" in audience:
        pick, rationale = "raw_dd", "raw dd image + SHA-256"
    elif "triage" in audience:
        pick, rationale = "aff4", "Triage — AFF4 (Google's streaming image format)"
    elif "vm" in audience:
        pick, rationale = "vhd_vmdk", "VM audience — VHD/VMDK"
    else:
        pick, rationale = "raw_dd", f"Unknown audience {audience!r} — default to raw dd"
    return _ok(step, {
        "pick": pick,
        "rationale": rationale,
        "detected_audience": audience or "unknown",
        "model": "target-adaptive (heuristic)",
    })


def adapt_forensics_timeline_format_picker(args: Dict[str, Any]) -> Dict[str, Any]:
    """Pick a timeline format for the IR/forensic audience."""
    step = _step("adapt_forensics_timeline_format_picker")
    audience = (str((args or {}).get("audience") or "")).lower()
    if "ir" in audience or "triage" in audience:
        pick, rationale = "plaso_csv", "IR — Plaso CSV (log2timeline + psort)"
    elif "audit" in audience:
        pick, rationale = "jsonl_audit", "Audit — JSONL (one event per line)"
    elif "court" in audience:
        pick, rationale = "pdf_with_chain_of_custody", "Court — PDF + chain of custody"
    else:
        pick, rationale = "jsonl", f"Unknown audience {audience!r} — default JSONL"
    return _ok(step, {
        "pick": pick,
        "rationale": rationale,
        "detected_audience": audience or "unknown",
        "model": "target-adaptive (heuristic)",
    })


def adapt_persistence_mechanism_picker(args: Dict[str, Any]) -> Dict[str, Any]:
    """Pick a persistence mechanism based on target OS + reboot tolerance."""
    step = _step("adapt_persistence_mechanism_picker")
    os_name = (str((args or {}).get("target_os") or "")).lower()
    persistent = bool((args or {}).get("survive_reboot"))
    if "windows" in os_name:
        if persistent:
            pick, rationale = "registry_run_key_hklm", "Windows + survive_reboot — registry HKLM Run key"
        else:
            pick, rationale = "scheduled_task_at_1min", "Windows + transient — Scheduled Task (AT 1min)"
    elif "linux" in os_name:
        if persistent:
            pick, rationale = "systemd_service_user", "Linux + survive_reboot — systemd user service"
        else:
            pick, rationale = "cron_d_user", "Linux + transient — cron.d user job"
    elif "macos" in os_name or "darwin" in os_name:
        if persistent:
            pick, rationale = "launchd_user_agent", "macOS + survive_reboot — LaunchAgent"
        else:
            pick, rationale = "login_items_appleevent", "macOS + transient — login items + AppleEvent"
    elif "android" in os_name:
        pick, rationale = "boot_completed_receiver", "Android — boot-completed BroadcastReceiver"
    elif "ios" in os_name:
        pick, rationale = "config_profile", "iOS — MDM-style config profile (requires enterprise cert)"
    else:
        if not persistent:
            pick, rationale = "fileless_in_memory", f"Unknown OS {os_name!r} + transient — fileless in-memory"
        else:
            pick, rationale = "registry_run_key_hklm", f"Unknown OS {os_name!r} + survive_reboot — fall back to Windows registry"
    return _ok(step, {
        "pick": pick,
        "rationale": rationale,
        "detected_target_os": os_name or "unknown",
        "model": "target-adaptive (heuristic)",
    })


def adapt_exfil_channel_picker(args: Dict[str, Any]) -> Dict[str, Any]:
    """Pick an exfiltration channel based on egress posture.

    The LLM then chains the picked channel into the next real
    step. No data is ever actually exfiltrated by this helper.
    """
    step = _step("adapt_exfil_channel_picker")
    egress = (str((args or {}).get("egress") or "")).lower()
    size_kb = int((args or {}).get("size_kb") or 0)
    if "blocked_https" in egress or egress == "https_blocked":
        pick, rationale = "dns_tunnel", "HTTPS blocked → DNS tunnel"
    elif "blocked_dns" in egress or egress == "dns_blocked":
        pick, rationale = "icmp_covert", "DNS blocked → ICMP covert channel"
    elif "blocked_egress" in egress or egress == "airgap":
        pick, rationale = "sneakernet_usb", "Air-gapped → sneakernet (USB)"
    elif size_kb > 10_000:
        pick, rationale = "smb_to_dropbox_lookalike", f"Large payload ({size_kb} KB) → SMB / chunked to a dropbox-lookalike"
    else:
        pick, rationale = "https_get_post", f"Default → HTTPS GET/POST (small payload {size_kb} KB)"
    return _ok(step, {
        "pick": pick,
        "rationale": rationale,
        "detected_egress": egress or "unknown",
        "size_kb": size_kb,
        "model": "target-adaptive (heuristic)",
    })


# ---------------------------------------------------------------------------
# T7 expansion: cloud + mobile + OT + RE grammars + pickers (Phase 3)
# ---------------------------------------------------------------------------


def poly_aws_iam_enumeration_grammar(args: Dict[str, Any]) -> Dict[str, Any]:
    """Polymorphic grammar for AWS IAM enumeration strategy.

    Picks a strategy variant (full enum / least-privilege / assume-role
    chain) for the next AWS recon step. The picked variant is
    forwarded to a real Pacu/ScoutSuite enumerator — never executed
    by this helper.
    """
    step = _step("poly_aws_iam_enumeration_grammar")
    seed = (args or {}).get("seed") or "aws-iam"
    import random
    rng = random.Random(str(seed))
    variants = [
        "full_user_role_enum", "least_privilege_diff",
        "assume_role_chain", "cross_account_role_pivot",
        "access_key_age_audit", "mfa_status_enum",
    ]
    picked = rng.sample(variants, k=min(4, len(variants)))
    return _ok(step, {
        "grammar": "aws_iam_enumeration",
        "variants": picked,
        "primary": picked[0],
        "model": "polymorphic (heuristic)",
        "note": "Forward primary to Pacu / enumerate_iam / ScoutSuite.",
    })


def poly_k8s_lateral_movement_grammar(args: Dict[str, Any]) -> Dict[str, Any]:
    """Polymorphic grammar for Kubernetes lateral-movement vector."""
    step = _step("poly_k8s_lateral_movement_grammar")
    variants = [
        "service_account_token_steal", "configmap_secret_pivot",
        "kubectl_exec_to_pod", "nodeport_abuse",
        "etcd_snapshot_dump", "rbac_privilege_escalation",
    ]
    return _ok(step, {
        "grammar": "k8s_lateral_movement",
        "variants": variants,
        "primary": variants[0],
        "model": "polymorphic (heuristic)",
        "note": "Forward primary to peirates / kube-hound.",
    })


def poly_mobile_frida_hook_grammar(args: Dict[str, Any]) -> Dict[str, Any]:
    """Polymorphic grammar for Frida hook script (Android / iOS)."""
    step = _step("poly_mobile_frida_hook_grammar")
    seed = (args or {}).get("seed") or "frida"
    import random
    rng = random.Random(str(seed))
    variants = [
        "ssl_pinning_bypass", "root_detection_bypass",
        "biometric_bypass", "frida_gadget_inject",
        "method_trace_class", "constructor_hook_objection",
    ]
    picked = rng.sample(variants, k=min(4, len(variants)))
    return _ok(step, {
        "grammar": "mobile_frida_hook",
        "variants": picked,
        "primary": picked[0],
        "model": "polymorphic (heuristic)",
        "note": "Forward primary to a Frida / objection script template.",
    })


def poly_ics_modbus_payload_grammar(args: Dict[str, Any]) -> Dict[str, Any]:
    """Polymorphic grammar for ICS / Modbus / S7 payload strategy."""
    step = _step("poly_ics_modbus_payload_grammar")
    variants = [
        "modbus_read_coils", "modbus_write_single_coil",
        "s7_read_szl", "s7_plc_stop", "s7_plc_hot_restart",
        "dnp3_unsolicited_response", "iec104_interrogation",
    ]
    return _ok(step, {
        "grammar": "ics_modbus_payload",
        "variants": variants,
        "primary": variants[0],
        "model": "polymorphic (heuristic)",
        "note": ("ICS payloads are destructive — the orchestrator "
                 "will gate every step via the ACCEPT/CANCEL prompt."),
    })


def poly_re_yara_rule_grammar(args: Dict[str, Any]) -> Dict[str, Any]:
    """Polymorphic grammar for YARA / reverse-engineering rule shape."""
    step = _step("poly_re_yara_rule_grammar")
    variants = [
        "string_at_offset", "import_hash_pe",
        "section_entropy_high", "imports_anomaly",
        "wide_string_match", "byte_sequence_unique",
    ]
    return _ok(step, {
        "grammar": "re_yara_rule",
        "variants": variants,
        "primary": variants[0],
        "model": "polymorphic (heuristic)",
        "note": "Forward primary to a YARA rule template.",
    })


# --- target-adaptive pickers (cloud + mobile + OT + RE) -------------------


def adapt_cloud_provider_picker(args: Dict[str, Any]) -> Dict[str, Any]:
    """Pick a cloud-OSINT tool from the target provider."""
    step = _step("adapt_cloud_provider_picker")
    provider = (str((args or {}).get("provider") or "")).lower()
    if "aws" in provider:
        pick, rationale = "pacu_or_scoutsuite", "AWS → Pacu (offensive) or ScoutSuite (audit)"
    elif "azure" in provider or "entra" in provider:
        pick, rationale = "roadtools_or_microburst", "Azure → ROADtools / MicroBurst"
    elif "gcp" in provider or "google" in provider:
        pick, rationale = "gcp_scanner_or_iam_enum", "GCP → GCP scanner / IAM privilege escalation"
    elif "k8s" in provider or "kubernetes" in provider:
        pick, rationale = "peirates_or_kubehound", "K8s → Peirates (offensive) or KubeHound (graph)"
    else:
        pick, rationale = "generic_cloud_enum", f"Unknown provider {provider!r} — fall back to generic cloud enum"
    return _ok(step, {
        "pick": pick,
        "rationale": rationale,
        "detected_provider": provider or "unknown",
        "model": "target-adaptive (heuristic)",
    })


def adapt_mobile_target_picker(args: Dict[str, Any]) -> Dict[str, Any]:
    """Pick a mobile-assessment strategy from OS + version."""
    step = _step("adapt_mobile_target_picker")
    os_kind = (str((args or {}).get("mobile_os") or "")).lower()
    jailbroken = bool((args or {}).get("jailbroken")) or bool((args or {}).get("rooted"))
    if "ios" in os_kind:
        if jailbroken:
            pick, rationale = "frida_gadget_full_hook", "iOS jailbroken → Frida gadget with full hook"
        else:
            pick, rationale = "objection_nonjailbroken", "iOS non-jailbroken → objection (Frida-based runtime)"
    elif "android" in os_kind:
        if jailbroken:
            pick, rationale = "apktool_smali_patch", "Android rooted → apktool smali patch + repackage"
        else:
            pick, rationale = "frida_objection_android", "Android non-rooted → Frida / objection with universal SSL bypass"
    else:
        pick, rationale = "unknown_mobile_os", f"Unknown mobile OS {os_kind!r}"
    return _ok(step, {
        "pick": pick,
        "rationale": rationale,
        "detected_os": os_kind or "unknown",
        "jailbroken": jailbroken,
        "model": "target-adaptive (heuristic)",
    })


def adapt_ot_protocol_picker(args: Dict[str, Any]) -> Dict[str, Any]:
    """Pick an OT/ICS tool from the target protocol."""
    step = _step("adapt_ot_protocol_picker")
    proto = (str((args or {}).get("protocol") or "")).lower()
    if "modbus" in proto:
        pick, rationale = "pymodbus_tcp_scan", "Modbus → pymodbus (TCP/UDP/Serial)"
    elif "s7" in proto or "siemens" in proto:
        pick, rationale = "python_snap7_plc_enum", "Siemens S7 → python-snap7"
    elif "dnp3" in proto:
        pick, rationale = "dnp3_enum_script", "DNP3 → custom enum script (opendnp3 / pydnp3)"
    elif "enip" in proto or "ethernetip" in proto:
        pick, rationale = "enip_enum_cip", "EtherNet/IP → CIP enum (pycomm3)"
    else:
        pick, rationale = "isf_framework_generic", f"Unknown OT protocol {proto!r} → ISF framework"
    return _ok(step, {
        "pick": pick,
        "rationale": rationale,
        "detected_protocol": proto or "unknown",
        "model": "target-adaptive (heuristic)",
    })


def adapt_re_tool_picker(args: Dict[str, Any]) -> Dict[str, Any]:
    """Pick a reverse-engineering tool from binary kind + size."""
    step = _step("adapt_re_tool_picker")
    binary_kind = (str((args or {}).get("binary_kind") or "")).lower()
    if "apk" in binary_kind or "android" in binary_kind:
        pick, rationale = "apktool_jadx", "Android APK → apktool (decode/res) + jadx (decompile)"
    elif "ios" in binary_kind or "macho" in binary_kind or "ipa" in binary_kind:
        pick, rationale = "ipsw_frida", "iOS IPA / Mach-O → ipsw (parse) + frida (runtime)"
    elif "pe" in binary_kind or "exe" in binary_kind or "windows" in binary_kind:
        pick, rationale = "ghidra_or_radare2", "PE/EXE → Ghidra (decompile) or radare2 (RE)"
    else:
        pick, rationale = "radare2_generic", f"Unknown binary kind {binary_kind!r} → radare2 generic"
    return _ok(step, {
        "pick": pick,
        "rationale": rationale,
        "detected_binary": binary_kind or "unknown",
        "model": "target-adaptive (heuristic)",
    })


def adapt_attack_chain_order_picker(args: Dict[str, Any]) -> Dict[str, Any]:
    """Pick the chain order: recon → exploit → post-exploit → exfil.

    Uses the attack_surface + phase_hint to decide the optimal
    next step in the chain. Used by the chain planner to choose
    the right tool from a polymorphic bundle.
    """
    step = _step("adapt_attack_chain_order_picker")
    surface = (str((args or {}).get("attack_surface") or "")).lower()
    phase = (str((args or {}).get("phase_hint") or "")).lower()
    if "wireless" in surface or "wifi" in surface or "ble" in surface:
        if phase == "recon":
            pick, rationale = "wireless_recon_first", "wireless surface + recon → start with scan / handshake / probe"
        else:
            pick, rationale = "wireless_attack_after_recon", "wireless + attack phase → deauth / handshake / GATT write"
    elif "cloud" in surface or "aws" in surface or "azure" in surface:
        if phase == "recon":
            pick, rationale = "cloud_recon_first", "cloud surface + recon → enumerate IAM / RBAC / public assets"
        else:
            pick, rationale = "cloud_privilege_escalation", "cloud + exploit → privilege escalation / lateral move"
    elif "mobile" in surface or "android" in surface or "ios" in surface:
        if phase == "recon":
            pick, rationale = "mobile_recon_first", "mobile + recon → static analysis (apktool / jadx)"
        else:
            pick, rationale = "mobile_runtime_hook", "mobile + exploit → Frida hook (SSL pinning / root bypass)"
    else:
        pick, rationale = "default_recon_then_exploit", f"Generic {surface}/{phase} → recon first, exploit after"
    return _ok(step, {
        "pick": pick,
        "rationale": rationale,
        "detected_surface": surface or "unknown",
        "detected_phase": phase or "unknown",
        "model": "target-adaptive (heuristic)",
    })


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
    # Polymorphic v3 (Phase 3 expansion) — 10 more
    "poly_wpa3_sae_grammar": poly_wpa3_sae_grammar,
    "poly_eapol_key_replay_grammar": poly_eapol_key_replay_grammar,
    "poly_ble_ll_fragment_grammar": poly_ble_ll_fragment_grammar,
    "poly_gatt_write_payload_grammar": poly_gatt_write_payload_grammar,
    "poly_email_pattern_grammar": poly_email_pattern_grammar,
    "poly_dorking_query_grammar": poly_dorking_query_grammar,
    "poly_disk_carve_signature_grammar": poly_disk_carve_signature_grammar,
    "poly_memory_yara_pattern_grammar": poly_memory_yara_pattern_grammar,
    "poly_lateral_movement_grammar": poly_lateral_movement_grammar,
    "poly_persistence_registry_grammar": poly_persistence_registry_grammar,
    # Target-adaptive v3 (Phase 3 expansion) — 10 more
    "adapt_wifi_chipset_picker": adapt_wifi_chipset_picker,
    "adapt_wifi_channel_width_picker": adapt_wifi_channel_width_picker,
    "adapt_ble_chipset_picker": adapt_ble_chipset_picker,
    "adapt_ble_pairing_method_picker": adapt_ble_pairing_method_picker,
    "adapt_osint_jurisdiction_picker": adapt_osint_jurisdiction_picker,
    "adapt_osint_query_language_picker": adapt_osint_query_language_picker,
    "adapt_forensics_image_format_picker": adapt_forensics_image_format_picker,
    "adapt_forensics_timeline_format_picker": adapt_forensics_timeline_format_picker,
    "adapt_persistence_mechanism_picker": adapt_persistence_mechanism_picker,
    "adapt_exfil_channel_picker": adapt_exfil_channel_picker,
    # T7 expansion (Phase 3) — cloud + mobile + OT + RE
    "poly_aws_iam_enumeration_grammar": poly_aws_iam_enumeration_grammar,
    "poly_k8s_lateral_movement_grammar": poly_k8s_lateral_movement_grammar,
    "poly_mobile_frida_hook_grammar": poly_mobile_frida_hook_grammar,
    "poly_ics_modbus_payload_grammar": poly_ics_modbus_payload_grammar,
    "poly_re_yara_rule_grammar": poly_re_yara_rule_grammar,
    "adapt_cloud_provider_picker": adapt_cloud_provider_picker,
    "adapt_mobile_target_picker": adapt_mobile_target_picker,
    "adapt_ot_protocol_picker": adapt_ot_protocol_picker,
    "adapt_re_tool_picker": adapt_re_tool_picker,
    "adapt_attack_chain_order_picker": adapt_attack_chain_order_picker,
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
        # Polymorphic v3
        "poly_wpa3_sae_grammar", "poly_eapol_key_replay_grammar",
        "poly_ble_ll_fragment_grammar", "poly_gatt_write_payload_grammar",
        "poly_email_pattern_grammar", "poly_dorking_query_grammar",
        "poly_disk_carve_signature_grammar", "poly_memory_yara_pattern_grammar",
        "poly_lateral_movement_grammar", "poly_persistence_registry_grammar",
        # Polymorphic T7 (Phase 3)
        "poly_aws_iam_enumeration_grammar", "poly_k8s_lateral_movement_grammar",
        "poly_mobile_frida_hook_grammar", "poly_ics_modbus_payload_grammar",
        "poly_re_yara_rule_grammar",
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
        # Target-adaptive v3
        "adapt_wifi_chipset_picker", "adapt_wifi_channel_width_picker",
        "adapt_ble_chipset_picker", "adapt_ble_pairing_method_picker",
        "adapt_osint_jurisdiction_picker", "adapt_osint_query_language_picker",
        "adapt_forensics_image_format_picker", "adapt_forensics_timeline_format_picker",
        "adapt_persistence_mechanism_picker", "adapt_exfil_channel_picker",
        # Target-adaptive T7 (Phase 3)
        "adapt_cloud_provider_picker", "adapt_mobile_target_picker",
        "adapt_ot_protocol_picker", "adapt_re_tool_picker",
        "adapt_attack_chain_order_picker",
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
    # Polymorphic v3
    "poly_wpa3_sae_grammar":
        "Pick a WPA3-SAE attack variant (commit-flood, timing, etc).",
    "poly_eapol_key_replay_grammar":
        "Pick an EAPOL-Key replay counter-mutation strategy.",
    "poly_ble_ll_fragment_grammar":
        "Pick a BLE Link-Layer fragment-reassembly pattern.",
    "poly_gatt_write_payload_grammar":
        "Pick a GATT-write payload template (long, prepare, signed, etc).",
    "poly_email_pattern_grammar":
        "Pick an email-pattern heuristic for OSINT discovery.",
    "poly_dorking_query_grammar":
        "Pick a Google-dorking query template (placeholders filled at step time).",
    "poly_disk_carve_signature_grammar":
        "Pick a file-carving signature (header/footer, magic, NTFS, ext4).",
    "poly_memory_yara_pattern_grammar":
        "Pick a YARA pattern style for memory forensics.",
    "poly_lateral_movement_grammar":
        "Pick a lateral-movement vector (psexec/wmi/winrm/rdp/smb/ssh).",
    "poly_persistence_registry_grammar":
        "Pick a Windows-Registry Run-key variant for persistence.",
    # Target-adaptive v3
    "adapt_wifi_chipset_picker":
        "Pick a monitor-mode driver from detected WiFi chipset.",
    "adapt_wifi_channel_width_picker":
        "Pick the channel width (20/40/80/160 MHz) from band.",
    "adapt_ble_chipset_picker":
        "Pick a BLE strategy from detected chipset (MT7922 / U4000 / Intel).",
    "adapt_ble_pairing_method_picker":
        "Pick a BLE pairing method from advertised IO capabilities.",
    "adapt_osint_jurisdiction_picker":
        "Pick an OSINT source by jurisdiction (PL/EU/US/CN).",
    "adapt_osint_query_language_picker":
        "Pick a query language for the OSINT source (boolean/cypher/natural).",
    "adapt_forensics_image_format_picker":
        "Pick a forensic image format from audience + tool availability.",
    "adapt_forensics_timeline_format_picker":
        "Pick a timeline format (plaso/jsonl/pdf) from audience.",
    "adapt_persistence_mechanism_picker":
        "Pick a persistence mechanism from target OS + reboot tolerance.",
    "adapt_exfil_channel_picker":
        "Pick an exfiltration channel (DNS/ICMP/HTTPS/SMB) from egress posture.",
    # T7 expansion (Phase 3) — cloud + mobile + OT + RE
    "poly_aws_iam_enumeration_grammar":
        "Polymorphic grammar for AWS IAM enum (full/least-priv/assume-role chain).",
    "poly_k8s_lateral_movement_grammar":
        "Polymorphic grammar for K8s lateral movement (SA token / configmap / exec).",
    "poly_mobile_frida_hook_grammar":
        "Polymorphic grammar for Frida hook script (SSL pin / root / biometric).",
    "poly_ics_modbus_payload_grammar":
        "Polymorphic grammar for ICS payload (modbus / S7 / DNP3 — gated ACCEPT).",
    "poly_re_yara_rule_grammar":
        "Polymorphic grammar for YARA / RE rule shape (entropy / imphash / str).",
    "adapt_cloud_provider_picker":
        "Pick a cloud-OSINT tool from provider (aws/azure/gcp/k8s).",
    "adapt_mobile_target_picker":
        "Pick a mobile strategy from OS + jailbreak/root state.",
    "adapt_ot_protocol_picker":
        "Pick an OT/ICS tool from protocol (modbus/s7/dnp3/enip).",
    "adapt_re_tool_picker":
        "Pick a reverse-engineering tool from binary kind (apk/ipa/pe).",
    "adapt_attack_chain_order_picker":
        "Pick the next chain step from attack_surface + phase_hint.",
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
