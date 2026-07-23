"""tests.test_poly_adapt_v2 — Phase 2.4 §H.2 polymorphic + target-adaptive v2.

Extends Phase 5 (wifi/ble) with:
  - Polymorphic v2: nmap / msf / impacket / mimikatz / volatility /
    disk carving / sleuthkit / persistence / exfil / osint UA
  - Target-adaptive v2: target_os / windows version / linux distro /
    android / iOS / macOS / C2 transport / C2 framework / OSINT source /
    evidence format

All companions return a {ok, data} envelope, never fake results.
"""

from core.refactors.poly_adapt_companions import (
    POLY_ADAPT_REGISTRY,
    POLY_ADAPT_RISK,
    POLY_ADAPT_DESCRIPTIONS,
    list_poly_adapt_methods,
    describe_poly_adapt_method,
    run_poly_adapt,
    build_poly_adapt_prompt_stanza,
)


# ---------------------------------------------------------------------------
# Registry counts
# ---------------------------------------------------------------------------


class TestRegistryCounts:
    def test_total_at_least_40(self):
        names = list_poly_adapt_methods()
        assert len(names) >= 40, f"only {len(names)} methods"

    def test_polymorphic_count(self):
        # Phase 4 T20: 35 (pre-Phase 4) + 26 new poly = 55
        poly = [n for n in list_poly_adapt_methods() if n.startswith("poly_")]
        assert len(poly) == 55, f"poly={len(poly)}"

    def test_adaptive_count(self):
        # Phase 4 T20: 35 (pre-Phase 4) + 11 new adapt = 45
        adapt = [n for n in list_poly_adapt_methods() if n.startswith("adapt_")]
        assert len(adapt) == 48, f"adapt={len(adapt)}"

    def test_risk_dict_covers_all(self):
        names = set(list_poly_adapt_methods())
        for n in names:
            assert n in POLY_ADAPT_RISK, f"missing risk for {n}"
            assert POLY_ADAPT_RISK[n] in ("intrusive", "destructive")

    def test_descriptions_dict_covers_all(self):
        names = set(list_poly_adapt_methods())
        for n in names:
            assert n in POLY_ADAPT_DESCRIPTIONS
            assert len(POLY_ADAPT_DESCRIPTIONS[n]) > 0

    def test_no_duplicate_names(self):
        names = list_poly_adapt_methods()
        assert len(names) == len(set(names)), f"dup: {names}"


# ---------------------------------------------------------------------------
# Polymorphic v2 smoke tests
# ---------------------------------------------------------------------------


class TestPolymorphicV2:
    def test_nmap_script_grammar(self):
        r = run_poly_adapt("poly_nmap_script_grammar", {"seed": "abc"})
        assert r["ok"] is True
        assert r["data"]["grammar"] == "nmap_script_category"
        assert "primary" in r["data"]
        assert r["data"]["model"] == "polymorphic (heuristic)"

    def test_metasploit_module_grammar(self):
        r = run_poly_adapt("poly_metasploit_module_grammar", {})
        assert r["ok"] is True
        assert r["data"]["grammar"] == "msf_module_family"
        assert any("exploit" in v or "post" in v or "auxiliary" in v
                   for v in r["data"]["variants"])

    def test_impacket_command_grammar(self):
        r = run_poly_adapt("poly_impacket_command_grammar", {})
        assert r["ok"] is True
        assert r["data"]["primary"] == "psexec"
        assert "wmiexec" in r["data"]["variants"]

    def test_mimikatz_module_grammar(self):
        r = run_poly_adapt("poly_mimikatz_module_grammar", {})
        assert r["ok"] is True
        assert "sekurlsa::logonpasswords" in r["data"]["variants"]

    def test_volatility_plugin_grammar(self):
        r = run_poly_adapt("poly_volatility_plugin_grammar", {})
        assert r["ok"] is True
        assert any("windows.pslist" in v for v in r["data"]["variants"])
        assert any("windows.hashdump" in v for v in r["data"]["variants"])

    def test_disk_carving_grammar(self):
        r = run_poly_adapt("poly_disk_carving_grammar", {})
        assert r["ok"] is True
        assert "foremost" in str(r["data"]).lower()

    def test_sleuthkit_cmd_grammar(self):
        r = run_poly_adapt("poly_sleuthkit_cmd_grammar", {})
        assert r["ok"] is True
        assert "fls" in r["data"]["primary"]

    def test_persistence_mechanism_grammar(self):
        r = run_poly_adapt("poly_persistence_mechanism_grammar", {})
        assert r["ok"] is True
        assert any("cron" in v for v in r["data"]["variants"])
        assert any("launchd" in v for v in r["data"]["variants"])

    def test_exfil_channel_grammar(self):
        r = run_poly_adapt("poly_exfil_channel_grammar", {})
        assert r["ok"] is True
        assert "https_post_chunked" in r["data"]["variants"]
        assert "dns_txt_subdomain" in r["data"]["variants"]

    def test_osint_user_agent_grammar(self):
        r = run_poly_adapt("poly_osint_user_agent_grammar", {"seed": "x"})
        assert r["ok"] is True
        assert r["data"]["grammar"] == "user_agent"
        assert len(r["data"]["variants"]) == 3


# ---------------------------------------------------------------------------
# Target-adaptive v2 smoke tests
# ---------------------------------------------------------------------------


class TestTargetAdaptiveV2:
    def test_target_os_picker_windows(self):
        r = run_poly_adapt("adapt_target_os_picker", {"os": "Windows 11"})
        assert r["ok"] is True
        assert r["data"]["pick"] == "windows_smb_rdp"
        assert "smb" in r["data"]["rationale"].lower() or "rdp" in r["data"]["rationale"].lower()

    def test_target_os_picker_linux(self):
        r = run_poly_adapt("adapt_target_os_picker", {"os": "Linux Ubuntu 22"})
        assert r["ok"] is True
        assert r["data"]["pick"] == "linux_ssh_https"

    def test_target_os_picker_macos(self):
        r = run_poly_adapt("adapt_target_os_picker", {"os": "Darwin 23.0"})
        assert r["ok"] is True
        assert r["data"]["pick"] == "macos_https_launchd"

    def test_target_os_picker_android(self):
        r = run_poly_adapt("adapt_target_os_picker", {"os": "Android 14"})
        assert r["ok"] is True
        assert r["data"]["pick"] == "android_adb_apk"

    def test_target_os_picker_ios(self):
        r = run_poly_adapt("adapt_target_os_picker", {"os": "iOS 17.4"})
        assert r["ok"] is True
        assert r["data"]["pick"] == "ios_mdm_profile"

    def test_windows_version_picker_10_11(self):
        r = run_poly_adapt("adapt_windows_version_picker", {"version": "10"})
        assert r["ok"] is True
        assert "ms17" in r["data"]["pick"].lower() or "eternalblue" in r["data"]["pick"].lower()

    def test_windows_version_picker_server_2019(self):
        r = run_poly_adapt("adapt_windows_version_picker", {"version": "Server 2019"})
        assert r["ok"] is True
        assert "zerologon" in r["data"]["pick"].lower() or "printnightmare" in r["data"]["pick"].lower()

    def test_windows_version_picker_legacy(self):
        r = run_poly_adapt("adapt_windows_version_picker", {"version": "Server 2008"})
        assert r["ok"] is True
        assert "ms08" in r["data"]["pick"].lower()

    def test_linux_distro_picker_ubuntu(self):
        r = run_poly_adapt("adapt_linux_distro_picker", {"distro": "Ubuntu 22.04"})
        assert r["ok"] is True
        assert "overlayfs" in r["data"]["pick"] or "linpeas" in r["data"]["pick"]

    def test_linux_distro_picker_debian(self):
        r = run_poly_adapt("adapt_linux_distro_picker", {"distro": "Debian 11"})
        assert r["ok"] is True
        assert "pwnkit" in r["data"]["pick"] or "polkit" in r["data"]["pick"]

    def test_linux_distro_picker_centos(self):
        r = run_poly_adapt("adapt_linux_distro_picker", {"distro": "CentOS 8"})
        assert r["ok"] is True
        assert "dirty_pipe" in r["data"]["pick"] or "polkit" in r["data"]["pick"]

    def test_android_version_picker_legacy(self):
        r = run_poly_adapt("adapt_android_version_picker", {"sdk": 24})
        assert r["ok"] is True
        assert "stagefright" in r["data"]["pick"].lower() or "root" in r["data"]["pick"].lower()

    def test_android_version_picker_modern(self):
        r = run_poly_adapt("adapt_android_version_picker", {"sdk": 33})
        assert r["ok"] is True
        assert "frida" in r["data"]["pick"].lower() or "adb" in r["data"]["pick"].lower()

    def test_ios_version_picker_modern(self):
        r = run_poly_adapt("adapt_ios_version_picker", {"version": "17.5"})
        assert r["ok"] is True
        assert "mdm" in r["data"]["pick"].lower() or "supervised" in r["data"]["pick"].lower()

    def test_ios_version_picker_legacy(self):
        r = run_poly_adapt("adapt_ios_version_picker", {"version": "15.8"})
        assert r["ok"] is True
        assert "checkm8" in r["data"]["pick"].lower() or "forcedentry" in r["data"]["pick"].lower()

    def test_macos_version_picker_legacy(self):
        r = run_poly_adapt("adapt_macos_version_picker", {"version": "10.14.6"})
        assert r["ok"] is True
        assert "keysteal" in r["data"]["pick"].lower() or "keychain" in r["data"]["pick"].lower()

    def test_macos_version_picker_modern(self):
        r = run_poly_adapt("adapt_macos_version_picker", {"version": "14.5"})
        assert r["ok"] is True
        assert "tcc" in r["data"]["pick"].lower() or "launchd" in r["data"]["pick"].lower()

    def test_c2_transport_picker_https(self):
        r = run_poly_adapt("adapt_c2_transport_picker", {"https_egress": True})
        assert r["ok"] is True
        assert r["data"]["pick"] == "https_c2"

    def test_c2_transport_picker_dns(self):
        r = run_poly_adapt("adapt_c2_transport_picker", {"dns_egress": True})
        assert r["ok"] is True
        assert "dns" in r["data"]["pick"]

    def test_c2_transport_picker_no_egress(self):
        r = run_poly_adapt("adapt_c2_transport_picker", {})
        assert r["ok"] is True
        assert r["data"]["pick"] == "tor_hidden_service"

    def test_c2_framework_picker_linux_expert(self):
        r = run_poly_adapt("adapt_c2_framework_picker",
                           {"target_os": "linux", "operator_skill": "expert"})
        assert r["ok"] is True
        assert "sliver" in r["data"]["pick"] or "mythic" in r["data"]["pick"]

    def test_c2_framework_picker_windows_beginner(self):
        r = run_poly_adapt("adapt_c2_framework_picker",
                           {"target_os": "windows", "operator_skill": "beginner"})
        assert r["ok"] is True
        assert "metasploit" in r["data"]["pick"].lower() or "msfvenom" in r["data"]["pick"].lower()

    def test_osint_source_picker_person(self):
        r = run_poly_adapt("adapt_osint_source_picker", {"target_type": "person"})
        assert r["ok"] is True
        assert "sherlock" in r["data"]["pick"] or "hibp" in r["data"]["pick"]

    def test_osint_source_picker_domain(self):
        r = run_poly_adapt("adapt_osint_source_picker", {"target_type": "domain"})
        assert r["ok"] is True
        assert "amass" in r["data"]["pick"] or "subfinder" in r["data"]["pick"]

    def test_osint_source_picker_email(self):
        r = run_poly_adapt("adapt_osint_source_picker", {"target_type": "email"})
        assert r["ok"] is True
        assert "hibp" in r["data"]["pick"] or "gravatar" in r["data"]["pick"]

    def test_osint_source_picker_company(self):
        r = run_poly_adapt("adapt_osint_source_picker", {"target_type": "company"})
        assert r["ok"] is True
        assert "shodan" in r["data"]["pick"] or "ceidg" in r["data"]["pick"]

    def test_evidence_format_picker_court(self):
        r = run_poly_adapt("adapt_evidence_format_picker", {"audience": "court"})
        assert r["ok"] is True
        assert "e01" in r["data"]["pick"] or "ewf" in r["data"]["pick"].lower()

    def test_evidence_format_picker_auditor(self):
        r = run_poly_adapt("adapt_evidence_format_picker", {"audience": "auditor"})
        assert r["ok"] is True
        assert "pdf" in r["data"]["pick"].lower()


# ---------------------------------------------------------------------------
# Adversarial
# ---------------------------------------------------------------------------


class TestAdversarialV2:
    def test_unknown_method_returns_error(self):
        r = run_poly_adapt("poly_does_not_exist", {})
        assert r["ok"] is False
        assert "unknown" in r["error"].lower()

    def test_describe_unknown_returns_none(self):
        assert describe_poly_adapt_method("poly_does_not_exist") is None

    def test_describe_known_returns_risk_and_desc(self):
        d = describe_poly_adapt_method("poly_nmap_script_grammar")
        assert d is not None
        assert d["name"] == "poly_nmap_script_grammar"
        assert d["risk"] in ("intrusive", "destructive")
        assert len(d["description"]) > 0

    def test_no_method_fakes_results(self):
        # All v2 methods return model=heuristic, never ML claim
        for name in list_poly_adapt_methods():
            r = run_poly_adapt(name, {})
            if r["ok"]:
                m = r["data"].get("model", "")
                assert "heuristic" in m, (
                    f"{name} claims model={m!r}, must be heuristic"
                )

    def test_prompt_stanza_lists_all(self):
        stanza = build_poly_adapt_prompt_stanza()
        # Must mention all 30 poly + 30 adapt (registry now at 60 methods)
        for n in list_poly_adapt_methods():
            assert n in stanza, f"{n} missing from prompt stanza"
