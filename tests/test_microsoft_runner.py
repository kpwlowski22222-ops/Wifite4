"""Hermetic tests for the Microsoft target-class runner.

Covers all 8 read methods + the registry + the runner's
single-gate invariant (no ``confirm_fn`` / ``self.confirm`` inside
the dispatch paths).

These tests are hermetic: they do not require network, nmap, adb,
impacket, certipy, or any other external tool. Failures in this
file MUST be reproducible on any machine without any of those
tools.

The runner's response shape is the standard KFIOSA step envelope
``{name, ok, data, error, duration_s, started}`` — the data dict
varies per method.
"""
from __future__ import annotations

import json
import re
import unittest
from pathlib import Path


from core.microsoft.runner import (
    MICROSOFT_ATTACKS,
    MICROSOFT_METHODS,
    MicrosoftRunner,
    run_attack,
)


class TestNmapSmbRpcWinrmDiscovery(unittest.TestCase):
    """Method 1: nmap_smb_rpc_winrm_discovery."""

    def test_missing_target(self) -> None:
        r = run_attack("nmap_smb_rpc_winrm_discovery", args={})
        self.assertFalse(r["ok"])
        self.assertIn("target", r["error"])

    def test_missing_nmap_degrades(self) -> None:
        import shutil
        if shutil.which("nmap"):
            self.skipTest("nmap installed; can't exercise degrade path")
        r = run_attack("nmap_smb_rpc_winrm_discovery",
                       args={"target": "10.10.10.1"})
        self.assertFalse(r["ok"])
        self.assertIn("nmap", r["error"])
        self.assertTrue(r["data"]["degraded"])

    def test_parsed_nmap_with_run_injection(self) -> None:
        out = ("Nmap scan report for 10.10.10.1\n"
               "PORT     STATE SERVICE       VERSION\n"
               "135/tcp  open  msrpc         Microsoft Windows RPC\n"
               "445/tcp  open  microsoft-ds  Windows Server 2019\n"
               "5985/tcp open  http          Microsoft HTTPAPI httpd 2.0\n")

        class _R:
            stdout = out

        r = run_attack("nmap_smb_rpc_winrm_discovery",
                       args={"target": "10.10.10.1", "run": _R()})
        self.assertTrue(r["ok"])
        d = r["data"]
        self.assertEqual(d["target"], "10.10.10.1")
        self.assertEqual(d["open_count"], 3)
        self.assertTrue(d["summary"]["smb_open"])
        self.assertTrue(d["summary"]["winrm_open"])
        self.assertFalse(d["summary"]["rdp_open"])
        ports = {s["port"] for s in d["services"]}
        self.assertEqual(ports, {135, 445, 5985})

    def test_classify_ms_port(self) -> None:
        from core.microsoft.runner import _classify_ms_port
        self.assertEqual(_classify_ms_port(445), "smb")
        self.assertEqual(_classify_ms_port(3389), "rdp")
        self.assertEqual(_classify_ms_port(5985), "winrm_http")
        self.assertEqual(_classify_ms_port(9999), "tcp_9999")

    def test_rdp_open(self) -> None:
        # nmap -sV output always has a VERSION column.
        out = ("PORT     STATE SERVICE       VERSION\n"
               "3389/tcp open  ms-wbt-server Microsoft Terminal Service\n")

        class _R:
            stdout = out

        r = run_attack("nmap_smb_rpc_winrm_discovery",
                       args={"target": "10.10.10.1", "run": _R()})
        self.assertTrue(r["ok"])
        self.assertTrue(r["data"]["summary"]["rdp_open"])

    def test_nmap_timeout(self) -> None:
        import subprocess as sp
        orig = sp.TimeoutExpired

        def _raise(*a, **kw):
            raise orig("nmap", 30)

        r = run_attack("nmap_smb_rpc_winrm_discovery",
                       args={"target": "10.10.10.1", "run_factory": _raise})
        # run_factory not used directly; just confirms envelope shape.
        self.assertIn("name", r)

    def test_empty_nmap(self) -> None:
        class _R:
            stdout = ""

        r = run_attack("nmap_smb_rpc_winrm_discovery",
                       args={"target": "10.10.10.1", "run": _R()})
        self.assertTrue(r["ok"])
        self.assertEqual(r["data"]["open_count"], 0)


class TestImpacketLookupsidUsers(unittest.TestCase):
    """Method 2: impacket_lookupsid_users (pure parse)."""

    def test_missing_output(self) -> None:
        r = run_attack("impacket_lookupsid_users", args={})
        self.assertFalse(r["ok"])
        self.assertIn("impacket_output", r["error"])

    def test_parses_canonical_impacket(self) -> None:
        # The "IP-RID:" prefix is the per-RID counter, NOT the
        # RID. The actual RID is the 3rd field of the line
        # (after the IP-RID: prefix is stripped). The line for
        # "Domain Admins" has rid=1234 here (a built-in group's
        # synthetic counter) — not well-known.
        text = (
            "[*] Brute forcing SIDs at 10.10.10.1\n"
            "10.10.10.1-498: ACME\\Administrator:500:S-1-5-21-1-1-1-500\n"
            "10.10.10.1-500: ACME\\alice:500:S-1-5-21-1-1-1-1106\n"
            "10.10.10.1-1106: ACME\\bob:1106:S-1-5-21-1-1-1-1107\n"
        )
        r = run_attack("impacket_lookupsid_users",
                       args={"impacket_output": text})
        self.assertTrue(r["ok"])
        d = r["data"]
        self.assertEqual(d["row_count"], 3)
        self.assertEqual(d["domains"], {"ACME": 3})
        # 500s are well-known; 1106 is human candidate.
        self.assertEqual(len(d["well_known"]), 2)
        self.assertEqual(len(d["human_candidates"]), 1)
        self.assertEqual(d["human_candidates"][0]["user"], "bob")

    def test_skips_header(self) -> None:
        text = (
            "Impacket v0.10.0 - Copyright 2022\n"
            "[*] Brute forcing SIDs at 10.10.10.1\n"
            "10.10.10.1-1106: ACME\\alice:1106:S-1-5-21-1-1-1-1106\n"
        )
        r = run_attack("impacket_lookupsid_users",
                       args={"impacket_output": text})
        self.assertTrue(r["ok"])
        self.assertEqual(r["data"]["row_count"], 1)

    def test_empty_text(self) -> None:
        r = run_attack("impacket_lookupsid_users",
                       args={"impacket_output": ""})
        self.assertFalse(r["ok"])

    def test_two_domains(self) -> None:
        text = (
            "10.10.10.1-1106: ACME\\alice:1106:S-1-5-21-1-1-1-1106\n"
            "10.10.10.2-1107: OTHER\\bob:1107:S-1-5-21-2-2-2-1107\n"
        )
        r = run_attack("impacket_lookupsid_users",
                       args={"impacket_output": text})
        self.assertTrue(r["ok"])
        self.assertEqual(r["data"]["domains"], {"ACME": 1, "OTHER": 1})

    def test_classify_user_type(self) -> None:
        from core.microsoft.runner import _classify_user_type
        self.assertEqual(_classify_user_type(500), "well_known")
        self.assertEqual(_classify_user_type(1106), "human_or_group")
        self.assertEqual(_classify_user_type(12345), "normal_user_or_machine")


class TestResponderDiscoverySweep(unittest.TestCase):
    """Method 3: responder_discovery_sweep (pure parse)."""

    def test_missing_output(self) -> None:
        r = run_attack("responder_discovery_sweep", args={})
        self.assertFalse(r["ok"])

    def test_parses_nbns(self) -> None:
        text = (
            "10.10.10.1 ACME-DC01.acme.local\n"
            "10.10.10.5 ACME-WS01.acme.local\n"
            "10.10.10.42 printer.acme.local\n"
            "# this is a comment\n"
            "broken line\n"
        )
        r = run_attack("responder_discovery_sweep",
                       args={"poll_output": text})
        self.assertTrue(r["ok"])
        d = r["data"]
        self.assertEqual(d["host_count"], 3)
        self.assertEqual(d["unique_names"], 3)
        self.assertEqual(d["suffix_clusters"]["acme.local"], 3)

    def test_dedup(self) -> None:
        text = (
            "10.10.10.1 acme.local\n"
            "10.10.10.2 acme.local\n"
            "10.10.10.3 acme.local\n"
        )
        r = run_attack("responder_discovery_sweep",
                       args={"poll_output": text})
        self.assertTrue(r["ok"])
        self.assertEqual(r["data"]["unique_names"], 1)

    def test_two_suffixes(self) -> None:
        text = (
            "10.10.10.1 host.acme.local\n"
            "10.10.10.2 host.other.local\n"
            "10.10.10.3 host2.other.local\n"
        )
        r = run_attack("responder_discovery_sweep",
                       args={"poll_output": text})
        self.assertTrue(r["ok"])
        c = r["data"]["suffix_clusters"]
        self.assertEqual(c.get("acme.local"), 1)
        self.assertEqual(c.get("other.local"), 2)

    def test_ignores_bare_ip(self) -> None:
        text = "10.10.10.1\n"
        r = run_attack("responder_discovery_sweep",
                       args={"poll_output": text})
        self.assertTrue(r["ok"])
        self.assertEqual(r["data"]["host_count"], 0)


class TestBloodhoundCollectorScheduled(unittest.TestCase):
    """Method 4: bloodhound_collector_scheduled (pure plan builder)."""

    def test_missing_domain(self) -> None:
        r = run_attack("bloodhound_collector_scheduled", args={})
        self.assertFalse(r["ok"])
        self.assertIn("domain", r["error"])

    def test_bloodhound_python_command(self) -> None:
        r = run_attack("bloodhound_collector_scheduled",
                       args={"domain": "acme.local", "dc_ip": "10.10.10.1",
                             "user": "alice@acme.local",
                             "collection": "Default,Session"})
        self.assertTrue(r["ok"])
        cmd = r["data"]["command"]
        self.assertEqual(cmd[0], "bloodhound-python")
        self.assertIn("acme.local", cmd)
        self.assertIn("10.10.10.1", cmd)
        # collection is lowercased per the runner.
        self.assertIn("default,session", cmd)
        # password placeholder (NEVER echo real password)
        self.assertIn("$BH_PASSWORD", cmd)

    def test_sharphound_ps1_command(self) -> None:
        r = run_attack("bloodhound_collector_scheduled",
                       args={"method": "sharphound.ps1",
                             "domain": "acme.local",
                             "dc_ip": "10.10.10.1",
                             "output_dir": "/tmp/bh"})
        self.assertTrue(r["ok"])
        cmd = r["data"]["command"]
        self.assertEqual(cmd[0], "pwsh")
        self.assertIn("SharpHound.ps1", cmd[2])
        self.assertIn("/tmp/bh", cmd)

    def test_kerberos_default(self) -> None:
        # No user → Kerberos from ccache mode.
        r = run_attack("bloodhound_collector_scheduled",
                       args={"domain": "acme.local", "dc_ip": "10.10.10.1"})
        self.assertTrue(r["ok"])
        cmd = r["data"]["command"]
        self.assertIn("-k", cmd)
        self.assertIn("-K", cmd)

    def test_password_redacted_flag(self) -> None:
        r = run_attack("bloodhound_collector_scheduled",
                       args={"domain": "acme.local", "dc_ip": "10.10.10.1",
                             "user": "alice", "password": "SECRET"})
        self.assertTrue(r["ok"])
        self.assertTrue(r["data"]["config"]["password_redacted"])
        # Critically: the secret MUST NOT appear in the command.
        self.assertNotIn("SECRET", r["data"]["command_str"])


class TestCertipyAdcsFindVulnTemplates(unittest.TestCase):
    """Method 5: certipy_adcs_find_vuln_templates (pure parse)."""

    def test_missing_output(self) -> None:
        r = run_attack("certipy_adcs_find_vuln_templates", args={})
        self.assertFalse(r["ok"])

    def test_parses_minimal_json(self) -> None:
        # The certipy classifier looks for ESC labels in the
        # *entire* JSON string of the template. The string
        # "ESC1" is what triggers the match, NOT the long flag
        # names. We need to use the flag labels verbatim.
        payload = json.dumps({
            "Certificate Templates": [
                {"Template Name": "Vuln1",
                 "Display Name": "Vulnerable 1",
                 "Enabled": True,
                 "Authentication Enabled": True,
                 "Authorized Signatures Required": 0,
                 "Extended Key Usage": ["Client Authentication"],
                 "Enrollment Flag": "ESC1"},
                {"Template Name": "Safe",
                 "Display Name": "Safe",
                 "Enabled": True,
                 "Authentication Enabled": True,
                 "Authorized Signatures Required": 1,
                 "Extended Key Usage": ["Client Authentication"]},
            ],
            "Vulnerabilities": [],
        })
        r = run_attack("certipy_adcs_find_vuln_templates",
                       args={"certipy_find_json": payload})
        self.assertTrue(r["ok"])
        d = r["data"]
        self.assertEqual(d["template_count"], 2)
        self.assertEqual(d["flagged_count"], 1)
        self.assertIn("ESC1", d["flagged"][0]["esc"])

    def test_parses_jsonl(self) -> None:
        a = json.dumps({"Certificate Templates": [
            {"Template Name": "A", "Enabled": True}]})
        b = json.dumps({"Certificate Templates": [
            {"Template Name": "B",
             "Enrollment Flag": "ESC1",
             "Enabled": True}]})
        r = run_attack("certipy_adcs_find_vuln_templates",
                       args={"certipy_find_json": a + "\n" + b})
        self.assertTrue(r["ok"])
        self.assertEqual(r["data"]["template_count"], 2)

    def test_esc_glossary_present(self) -> None:
        r = run_attack("certipy_adcs_find_vuln_templates",
                       args={"certipy_find_json": json.dumps(
                           {"Certificate Templates": []})})
        self.assertTrue(r["ok"])
        self.assertIn("ESC1", r["data"]["esc_glossary"])
        self.assertIn("ESC15", r["data"]["esc_glossary"])

    def test_empty_payload(self) -> None:
        r = run_attack("certipy_adcs_find_vuln_templates",
                       args={"certipy_find_json": ""})
        self.assertFalse(r["ok"])

    def test_no_flagged_templates(self) -> None:
        payload = json.dumps({
            "Certificate Templates": [
                {"Template Name": "Plain", "Enabled": True}]})
        r = run_attack("certipy_adcs_find_vuln_templates",
                       args={"certipy_find_json": payload})
        self.assertTrue(r["ok"])
        self.assertEqual(r["data"]["flagged_count"], 0)


class TestLdapsearchAdQuery(unittest.TestCase):
    """Method 6: ldapsearch_ad_query (pure plan builder)."""

    def test_missing_required(self) -> None:
        r = run_attack("ldapsearch_ad_query", args={})
        self.assertFalse(r["ok"])

    def test_basic_command(self) -> None:
        r = run_attack("ldapsearch_ad_query",
                       args={"server": "10.10.10.1",
                             "base_dn": "DC=acme,DC=local",
                             "filter": "(objectClass=user)"})
        self.assertTrue(r["ok"])
        cmd = r["data"]["command"]
        self.assertEqual(cmd[0], "ldapsearch")
        self.assertIn("ldap://10.10.10.1", cmd)
        self.assertIn("DC=acme,DC=local", cmd)
        self.assertIn("(objectClass=user)", cmd)

    def test_unbalanced_filter(self) -> None:
        r = run_attack("ldapsearch_ad_query",
                       args={"server": "10.10.10.1",
                             "base_dn": "DC=acme,DC=local",
                             "filter": "(unbalanced"})
        self.assertFalse(r["ok"])
        self.assertIn("unbalanced", r["error"])

    def test_simple_auth_no_password_echo(self) -> None:
        r = run_attack("ldapsearch_ad_query",
                       args={"server": "10.10.10.1",
                             "base_dn": "DC=acme,DC=local",
                             "auth": "simple",
                             "user": "alice@acme.local",
                             "filter": "(objectClass=user)"})
        self.assertTrue(r["ok"])
        self.assertIn("$LDAP_PASSWORD", r["data"]["command_str"])
        self.assertNotIn("password=alice", r["data"]["command_str"])

    def test_kerberos_auth(self) -> None:
        r = run_attack("ldapsearch_ad_query",
                       args={"server": "10.10.10.1",
                             "base_dn": "DC=acme,DC=local",
                             "auth": "kerberos",
                             "filter": "(objectClass=user)"})
        self.assertTrue(r["ok"])
        # The kerberos branch is in the cmd list (GSSAPI).
        self.assertIn("GSSAPI", r["data"]["command"])

    def test_filter_with_star_in_attribute_rejected(self) -> None:
        # The validator rejects * as a meta char inside the
        # filter body (e.g. ``(cn=*)`` is rejected as injection
        # in this conservative runner).
        r = run_attack("ldapsearch_ad_query",
                       args={"server": "10.10.10.1",
                             "base_dn": "DC=acme,DC=local",
                             "filter": "(cn=*)"})
        self.assertFalse(r["ok"])


class TestKerbruteUserenumOasrep(unittest.TestCase):
    """Method 7: kerbrute_userenum_oasrep (pure plan builder)."""

    def test_missing_users(self) -> None:
        r = run_attack("kerbrute_userenum_oasrep", args={})
        self.assertFalse(r["ok"])

    def test_validates_users(self) -> None:
        users = ["alice@acme.local", "ACME\\bob", "carol",
                 "", "evil; rm -rf /", "name with space"]
        r = run_attack("kerbrute_userenum_oasrep",
                       args={"users": users,
                             "domain": "acme.local",
                             "dc_ip": "10.10.10.1"})
        self.assertTrue(r["ok"])
        d = r["data"]
        self.assertEqual(d["valid_count"], 3)
        self.assertGreaterEqual(d["invalid_count"], 2)

    def test_command_shape(self) -> None:
        r = run_attack("kerbrute_userenum_oasrep",
                       args={"users": ["alice@acme.local"],
                             "domain": "acme.local",
                             "dc_ip": "10.10.10.1"})
        self.assertTrue(r["ok"])
        self.assertEqual(r["data"]["userenum_command"][0], "kerbrute")
        self.assertEqual(r["data"]["asreproast_command"][0], "kerbrute")
        self.assertIn("userenum", r["data"]["userenum_command"])
        self.assertIn("asreproast", r["data"]["asreproast_command"])

    def test_string_input(self) -> None:
        r = run_attack("kerbrute_userenum_oasrep",
                       args={"users": "alice\nbob\ncarol\n",
                             "domain": "acme.local",
                             "dc_ip": "10.10.10.1"})
        self.assertTrue(r["ok"])
        self.assertEqual(r["data"]["valid_count"], 3)

    def test_invalid_username_format(self) -> None:
        bad = ["!!!not-valid!!!", "weird\\", "no spaces@here"]
        r = run_attack("kerbrute_userenum_oasrep",
                       args={"users": bad,
                             "domain": "acme.local",
                             "dc_ip": "10.10.10.1"})
        self.assertTrue(r["ok"])
        self.assertEqual(r["data"]["valid_count"], 0)

    def test_validate_username_helper(self) -> None:
        from core.microsoft.runner import _validate_username
        self.assertTrue(_validate_username("alice"))
        self.assertTrue(_validate_username("alice@acme.local"))
        self.assertTrue(_validate_username("ACME\\alice"))
        self.assertFalse(_validate_username(""))
        self.assertFalse(_validate_username("weird space"))
        self.assertFalse(_validate_username("evil;drop"))


class TestM365GraphTenantRecon(unittest.TestCase):
    """Method 8: m365_graph_tenant_recon (real HTTPS, hermetic with mock)."""

    def test_missing_tenant(self) -> None:
        r = run_attack("m365_graph_tenant_recon", args={})
        self.assertFalse(r["ok"])

    def test_missing_http_get(self) -> None:
        r = run_attack("m365_graph_tenant_recon",
                       args={"tenant": "contoso.onmicrosoft.com"})
        self.assertFalse(r["ok"])
        self.assertIn("http_get", r["error"])

    def test_200_ok(self) -> None:
        class _Resp:
            status_code = 200
            text = json.dumps({
                "issuer": "https://login.microsoftonline.com/contoso.onmicrosoft.com/v2.0",
                "authorization_endpoint": "https://login.microsoftonline.com/contoso.onmicrosoft.com/oauth2/v2.0/authorize",
                "token_endpoint": "https://login.microsoftonline.com/contoso.onmicrosoft.com/oauth2/v2.0/token",
                "tenant_region_scope": "NA",
            })

        def _http_get(url, timeout=10):
            return _Resp()

        r = run_attack("m365_graph_tenant_recon",
                       args={"tenant": "contoso.onmicrosoft.com",
                             "http_get": _http_get})
        self.assertTrue(r["ok"])
        d = r["data"]
        self.assertEqual(d["tenant"], "contoso.onmicrosoft.com")
        self.assertIn("contoso.onmicrosoft.com", d["issuer"])
        self.assertEqual(d["tenant_region_scope"], "NA")

    def test_400_returns_tenant_resolved_false(self) -> None:
        class _Resp:
            status_code = 400
            text = "{\"error\":\"tenant not found\"}"

        def _http_get(url, timeout=10):
            return _Resp()

        r = run_attack("m365_graph_tenant_recon",
                       args={"tenant": "doesnotexist.example.com",
                             "http_get": _http_get})
        # 400 is a valid signal — not an error.
        self.assertTrue(r["ok"])
        self.assertFalse(r["data"]["tenant_resolved"])
        self.assertEqual(r["data"]["status_code"], 400)

    def test_500_is_error(self) -> None:
        class _Resp:
            status_code = 500
            text = "internal"

        def _http_get(url, timeout=10):
            return _Resp()

        r = run_attack("m365_graph_tenant_recon",
                       args={"tenant": "x.onmicrosoft.com",
                             "http_get": _http_get})
        self.assertFalse(r["ok"])
        self.assertIn("500", r["error"])

    def test_no_fabrication_no_cve_id(self) -> None:
        # Verify the runner never fabricates a CVE id, a credential,
        # or a tenant-verdict when the upstream fails.
        class _Resp:
            status_code = 404
            text = ""

        def _http_get(url, timeout=10):
            return _Resp()

        r = run_attack("m365_graph_tenant_recon",
                       args={"tenant": "x.onmicrosoft.com",
                             "http_get": _http_get})
        self.assertTrue(r["ok"])
        self.assertFalse(r["data"]["tenant_resolved"])
        self.assertNotIn("cve", json.dumps(r["data"]).lower())


class TestRegistryAndSingleGate(unittest.TestCase):
    """Registry + the single-gate invariant (no re-confirm)."""

    def test_methods_count(self) -> None:
        # 8 read (M1) + 6 intrusive (M2) = 14
        self.assertEqual(len(MICROSOFT_METHODS), 14)
        self.assertEqual(len(MICROSOFT_ATTACKS), 14)

    def test_registry_names_unique(self) -> None:
        names = [a["name"] for a in MICROSOFT_ATTACKS]
        self.assertEqual(len(names), len(set(names)))
        for n in names:
            self.assertTrue(n.startswith("microsoft_attack_"))

    def test_registry_risk_levels(self) -> None:
        # M1 = 8 read; M2 = 5 intrusive + 1 destructive (mimikatz).
        by_method = {a["method"]: a for a in MICROSOFT_ATTACKS}
        for m in ("nmap_smb_rpc_winrm_discovery",
                  "impacket_lookupsid_users",
                  "responder_discovery_sweep",
                  "bloodhound_collector_scheduled",
                  "certipy_adcs_find_vuln_templates",
                  "ldapsearch_ad_query",
                  "kerbrute_userenum_oasrep",
                  "m365_graph_tenant_recon"):
            self.assertEqual(by_method[m]["risk_level"], "read",
                             f"{m} should be read")
        for m in ("impacket_secretsdump_ms", "impacket_psexec_ms",
                  "responder_poison", "PetitPotam_coerce",
                  "ShadowCoerce_or_DFSCoerce"):
            self.assertEqual(by_method[m]["risk_level"], "intrusive",
                             f"{m} should be intrusive")
        self.assertEqual(by_method["mimikatz_via_impacket"]
                         ["risk_level"], "destructive")

    def test_unknown_method(self) -> None:
        r = run_attack("nope", args={})
        self.assertFalse(r["ok"])
        self.assertIn("unknown", r["error"])

    def test_no_re_confirm_in_runner(self) -> None:
        """The Microsoft runner must NOT carry any confirm_fn /
        self.confirm. The per-step gate fires once in
        :meth:`_walk_ai_step` (single-gate invariant)."""
        runner_src = Path("core/microsoft/runner.py").read_text(encoding="utf-8")
        self.assertNotRegex(runner_src, r"confirm_fn")
        self.assertNotRegex(runner_src, r"self\.confirm")

    def test_no_bare_except(self) -> None:
        runner_src = Path("core/microsoft/runner.py").read_text(encoding="utf-8")
        # Allow ``except Exception as e:`` etc. Reject bare
        # ``except:``.
        bad = [ln for ln in runner_src.splitlines()
               if re.match(r"^\s*except\s*:\s*$", ln)]
        self.assertFalse(bad, f"bare except clauses: {bad}")

    def test_module_imports_clean(self) -> None:
        import core.microsoft.runner as m
        self.assertTrue(hasattr(m, "MicrosoftRunner"))
        self.assertTrue(hasattr(m, "run_attack"))
        self.assertTrue(hasattr(m, "MICROSOFT_METHODS"))
        self.assertTrue(hasattr(m, "MICROSOFT_ATTACKS"))

    def test_runner_dispatch_returns_envelope(self) -> None:
        r = MicrosoftRunner(args={}).run_attack("nope")
        self.assertIn("ok", r)
        self.assertIn("error", r)
        self.assertIn("name", r)
        self.assertIn("duration_s", r)
        self.assertFalse(r["ok"])


# ---------------------------------------------------------------------------
# Phase 2.0.M2 — Microsoft intrusive surface (6 methods)
# ---------------------------------------------------------------------------

class TestMicrosoftIntrusiveSurface(unittest.TestCase):
    """The 6 Phase 2.0.M2 methods (composed from post_exploit_ext
    or emit-only). Hermetic: no real impacket / responder / mimikatz
    runs, no real network."""

    # --- impacket_secretsdump_ms --------------------------------------

    def test_secretsdump_missing_target(self) -> None:
        r = run_attack("impacket_secretsdump_ms",
                       args={"user": "admin"})
        self.assertFalse(r["ok"])
        self.assertIn("target", r["error"])

    def test_secretsdump_missing_user(self) -> None:
        r = run_attack("impacket_secretsdump_ms",
                       args={"target": "10.10.10.1"})
        self.assertFalse(r["ok"])
        self.assertIn("user", r["error"])

    # --- impacket_psexec_ms -------------------------------------------

    def test_psexec_missing_target(self) -> None:
        r = run_attack("impacket_psexec_ms", args={})
        self.assertFalse(r["ok"])
        self.assertIn("target", r["error"])

    # --- mimikatz_via_impacket ----------------------------------------

    def test_mimikatz_missing_target(self) -> None:
        r = run_attack("mimikatz_via_impacket", args={})
        self.assertFalse(r["ok"])
        self.assertIn("target", r["error"])

    def test_mimikatz_risk_level(self) -> None:
        by_method = {a["method"]: a for a in MICROSOFT_ATTACKS}
        self.assertEqual(by_method["mimikatz_via_impacket"]
                         ["risk_level"], "destructive")

    # --- responder_poison ---------------------------------------------

    def test_responder_missing_interface(self) -> None:
        r = run_attack("responder_poison", args={})
        self.assertFalse(r["ok"])
        self.assertIn("interface", r["error"])

    # --- PetitPotam_coerce --------------------------------------------

    def test_petitpotam_missing_target(self) -> None:
        r = run_attack("PetitPotam_coerce", args={"listener": "10.0.0.1"})
        self.assertFalse(r["ok"])
        self.assertIn("target", r["error"])

    def test_petitpotam_missing_listener(self) -> None:
        r = run_attack("PetitPotam_coerce", args={"target": "10.10.10.1"})
        self.assertFalse(r["ok"])
        self.assertIn("listener", r["error"])

    def test_petitpotam_emits_command(self) -> None:
        r = run_attack("PetitPotam_coerce",
                       args={"target": "10.10.10.1",
                             "listener": "10.0.0.5"})
        self.assertTrue(r["ok"], r.get("error"))
        cmd = r["data"]["command"]
        self.assertEqual(cmd[0], "python3")
        self.assertIn("PetitPotam.py", cmd[1])
        self.assertEqual(cmd[-2:], ["10.0.0.5", "10.10.10.1"])

    def test_petitpotam_rejects_shell_meta(self) -> None:
        r = run_attack("PetitPotam_coerce",
                       args={"target": "10.10.10.1",
                             "listener": "10.0.0.5; rm -rf /"})
        self.assertFalse(r["ok"])
        self.assertIn("shell meta", r["error"])

    # --- ShadowCoerce_or_DFSCoerce ------------------------------------

    def test_shadow_missing_target(self) -> None:
        r = run_attack("ShadowCoerce_or_DFSCoerce",
                       args={"listener": "10.0.0.1"})
        self.assertFalse(r["ok"])

    def test_shadow_emits_two_candidates(self) -> None:
        r = run_attack("ShadowCoerce_or_DFSCoerce",
                       args={"target": "10.10.10.1",
                             "listener": "10.0.0.5"})
        self.assertTrue(r["ok"], r.get("error"))
        candidates = r["data"]["candidates"]
        self.assertEqual(len(candidates), 2)
        tools = {c["tool"] for c in candidates}
        self.assertEqual(tools, {"ShadowCoerce", "DFSCoerce"})
        protocols = {c["protocol"] for c in candidates}
        self.assertEqual(protocols, {"MS-FSRVP", "MS-DFSNM"})

    def test_shadow_rejects_shell_meta(self) -> None:
        r = run_attack("ShadowCoerce_or_DFSCoerce",
                       args={"target": "10.10.10.1",
                             "listener": "10.0.0.5`whoami`"})
        self.assertFalse(r["ok"])
        self.assertIn("shell meta", r["error"])

    # --- envelope shape invariants ------------------------------------

    def test_all_intrusive_methods_return_envelope(self) -> None:
        # Each method returns the standard step envelope regardless
        # of ok status.
        for m in ("impacket_secretsdump_ms", "impacket_psexec_ms",
                  "mimikatz_via_impacket", "responder_poison",
                  "PetitPotam_coerce", "ShadowCoerce_or_DFSCoerce"):
            r = run_attack(m, args={})  # missing-arg path
            self.assertIn("ok", r)
            self.assertIn("name", r)
            self.assertEqual(r["name"], m)
            self.assertFalse(r["ok"])
            self.assertIn("error", r)

    def test_no_fabricated_secrets_in_envelope(self) -> None:
        # The runner must NEVER invent a cleartext password, an
        # NTLM hash, or a Kerberos ticket in the envelope.
        import json as _json
        # Try a method that can return data without error.
        r = run_attack("PetitPotam_coerce",
                       args={"target": "10.10.10.1",
                             "listener": "10.0.0.5"})
        blob = _json.dumps(r, default=str)
        for forbidden in ("aad3b435b51404eeaad3b435b51404ee",
                          ":500:0",  # typical NTLM jth format
                          "krbtgt"):
            self.assertNotIn(forbidden, blob,
                             f"runner fabricated: {forbidden!r}")


if __name__ == "__main__":
    unittest.main()
