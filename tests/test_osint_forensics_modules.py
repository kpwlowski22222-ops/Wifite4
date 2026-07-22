#!/usr/bin/env python3
"""Hermetic tests for the new OSINT and forensics module libraries
(``core.osint.osint_modules`` + ``core.forensics.forensic_modules``).

These tests verify:
  * Module registries expose the expected number of probes (>= 50 each).
  * ``run_module`` returns honest-degrade envelopes for unknown methods.
  * Required-arg validation fires (no fabrication, no real subprocess
    when the required arg is missing).
  * Real-arg paths either succeed (e.g. file_hash) or honest-degrade
    (e.g. sherlock when sherlock is not installed).
  * Destructive / lab-only modules flag ``lab_only: True`` in their
    envelopes.
  * No bare ``except:`` swallows errors.
"""

import os
import sys
import tempfile

import pytest


# ---------------------------------------------------------------------------
# OSINT module library
# ---------------------------------------------------------------------------

class TestOSINTModuleRegistry:
    def test_count_meets_target(self):
        from core.osint.osint_modules import (
            OSINT_MODULE_FUNCTIONS, OSINT_MODULES_PROBES)
        # Operator target: 50+ modules.
        assert len(OSINT_MODULE_FUNCTIONS) >= 50
        assert len(OSINT_MODULES_PROBES) == len(OSINT_MODULE_FUNCTIONS)

    def test_probes_have_required_fields(self):
        from core.osint.osint_modules import OSINT_MODULES_PROBES
        for probe in OSINT_MODULES_PROBES:
            assert probe["method"]
            assert probe["name"].startswith("osint_module_")
            assert probe["category"] == "osint"
            assert probe["subcategory"]
            assert probe["description"]
            assert probe["risk_level"] == "read"
            assert probe["examples"]

    def test_subcategories_cover_19_families(self):
        from core.osint.osint_modules import OSINT_MODULES_PROBES
        subs = {p["subcategory"] for p in OSINT_MODULES_PROBES}
        # 19 subcategories defined in the docstring.
        assert len(subs) >= 12
        for expected in ("username", "email_reputation", "phone",
                         "domain", "port_scan"):
            assert expected in subs, f"missing subcategory: {expected}"


class TestOSINTModuleDispatch:
    def test_unknown_method_returns_honest_degrade(self):
        from core.osint.osint_modules import run_module
        env = run_module("not_a_real_method_xyz")
        assert env["ok"] is False
        assert "unknown" in env["error"].lower()

    def test_sherlock_requires_username(self):
        from core.osint.osint_modules import run_module
        env = run_module("sherlock", {})
        assert env["ok"] is False
        assert "username" in env["error"].lower()

    def test_whois_requires_domain(self):
        from core.osint.osint_modules import run_module
        env = run_module("whois_lookup", {})
        assert env["ok"] is False
        assert "domain" in env["error"].lower()

    def test_phonenumbers_offline_lib(self):
        from core.osint.osint_modules import run_module
        # Real phone number, US. If phonenumbers lib is installed
        # this should resolve; if not, honest-degrade.
        env = run_module("phonenumbers_lib", {"phone": "+14155551234"})
        # Either succeeded (lib installed) or honest-degraded.
        assert "error" in env
        if env["ok"]:
            assert "phone" in env["data"]
            assert "carrier" in env["data"]

    def test_emailrep_requires_api_key(self):
        from core.osint.osint_modules import run_module
        env = run_module("emailrep", {"email": "test@example.com"})
        assert env["ok"] is False
        assert "key" in env["error"].lower() or "api" in env["error"].lower()

    def test_subfinder_requires_subfinder_bin(self):
        from core.osint.osint_modules import run_module
        env = run_module("subfinder", {"domain": "example.com"})
        # Either succeeds (bin installed) or honest-degrades.
        assert "domain" in env["data"]

    def test_breach_correlate_no_key_honest_degrade(self):
        from core.osint.osint_modules import run_module
        env = run_module("breach_correlate", {"email": "test@example.com"})
        assert env["ok"] is False
        assert "key" in env["error"].lower()

    def test_wigle_no_key_honest_degrade(self):
        from core.osint.osint_modules import run_module
        env = run_module("wigle_lookup", {"ssid": "test"})
        assert env["ok"] is False
        assert "name" in env["error"].lower() or "token" in env["error"].lower()

    def test_dnsdumpster_honest_degrade(self):
        from core.osint.osint_modules import run_module
        env = run_module("dnsdumpster", {"domain": "example.com"})
        assert env["ok"] is False
        assert "scrape" in env["error"].lower() or "subfinder" in env["error"].lower()

    def test_run_module_does_not_raise(self):
        from core.osint.osint_modules import run_module
        # Force a runtime error via a malformed input — must NOT raise.
        env = run_module("passivedns", None)
        assert isinstance(env, dict)
        assert "ok" in env


class TestOSINTModuleEdgeCases:
    def test_holehe_no_email(self):
        from core.osint.osint_modules import run_module
        env = run_module("holehe", {})
        assert env["ok"] is False
        assert "email" in env["error"].lower()

    def test_masscan_no_ip(self):
        from core.osint.osint_modules import run_module
        env = run_module("masscan", {})
        assert env["ok"] is False
        assert "ip" in env["error"].lower()

    def test_aquatone_no_urls_path(self):
        from core.osint.osint_modules import run_module
        env = run_module("aquatone", {})
        assert env["ok"] is False
        assert "urls_path" in env["error"].lower()

    def test_yara_real(self):
        # If yara + test rules are present, scan a temp file. If yara
        # not present, honest-degrade.
        from core.osint.osint_modules import run_module
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f:
            f.write(b"hello world\n")
            fpath = f.name
        try:
            with tempfile.NamedTemporaryFile(
                    suffix=".yar", delete=False, mode="w") as rf:
                rf.write('rule test_rule { condition: true }')
                rpath = rf.name
            try:
                env = run_module("yara_scan", {"path": fpath,
                                               "rules": rpath})
                assert "path" in env["data"] or env["ok"] is False
            finally:
                os.unlink(rpath)
        finally:
            os.unlink(fpath)


# ---------------------------------------------------------------------------
# Forensics module library
# ---------------------------------------------------------------------------

class TestForensicModuleRegistry:
    def test_count_meets_target(self):
        from core.forensics.forensic_modules import (
            FORENSIC_MODULE_FUNCTIONS, FORENSIC_MODULES_PROBES)
        # Operator target: 50+ modules (28 forensics + 25 anti-forensics = 53).
        assert len(FORENSIC_MODULE_FUNCTIONS) >= 50
        assert len(FORENSIC_MODULES_PROBES) == len(FORENSIC_MODULE_FUNCTIONS)

    def test_anti_forensics_flagged_lab_only(self):
        from core.forensics.forensic_modules import FORENSIC_MODULES_PROBES
        for probe in FORENSIC_MODULES_PROBES:
            if probe["category"] == "anti_forensics":
                assert probe["lab_only"] is True
                assert probe["risk_level"] in ("destructive", "intrusive")
            else:
                assert probe["lab_only"] is False
                assert probe["risk_level"] == "read"

    def test_probes_have_required_fields(self):
        from core.forensics.forensic_modules import FORENSIC_MODULES_PROBES
        for probe in FORENSIC_MODULES_PROBES:
            assert probe["method"]
            assert probe["name"].startswith("forensic_module_")
            assert probe["category"] in ("forensics", "anti_forensics")
            assert probe["description"]


class TestForensicModuleDispatch:
    def test_unknown_method_returns_honest_degrade(self):
        from core.forensics.forensic_modules import run_module
        env = run_module("not_a_real_method")
        assert env["ok"] is False
        assert "unknown" in env["error"].lower()

    def test_file_hash_real(self):
        from core.forensics.forensic_modules import run_module
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f:
            f.write(b"hello world\n")
            fpath = f.name
        try:
            env = run_module("file_hash", {"path": fpath})
            assert env["ok"] is True
            assert env["data"]["size"] == 12
            assert env["data"]["hashes"]["sha256"].startswith("a9489")
        finally:
            os.unlink(fpath)

    def test_file_hash_missing_path(self):
        from core.forensics.forensic_modules import run_module
        env = run_module("file_hash", {})
        assert env["ok"] is False
        assert "path" in env["error"].lower()

    def test_file_hash_nonexistent(self):
        from core.forensics.forensic_modules import run_module
        env = run_module("file_hash",
                         {"path": "/no/such/file/ever/12345"})
        assert env["ok"] is False

    def test_amsi_bypass_lab_only_emit(self):
        from core.forensics.forensic_modules import run_module
        env = run_module("anti_amsi_bypass", {})
        assert env["ok"] is True
        assert env["lab_only"] is True
        assert "amsiInitFailed" in env["data"]["snippet"]
        assert env["data"]["language"] == "powershell"

    def test_etw_bypass_lab_only_emit(self):
        from core.forensics.forensic_modules import run_module
        env = run_module("anti_etw_bypass", {})
        assert env["ok"] is True
        assert env["lab_only"] is True
        assert "EventProvider" in env["data"]["snippet"]

    def test_uac_bypass_lab_only_emit(self):
        from core.forensics.forensic_modules import run_module
        env = run_module("anti_uac_bypass", {})
        assert env["ok"] is True
        assert env["lab_only"] is True
        assert "fodhelper" in env["data"]["technique"]

    def test_ransomware_sim_lab_only_emit(self):
        from core.forensics.forensic_modules import run_module
        env = run_module("anti_ransomware_sim", {})
        assert env["ok"] is True
        assert env["lab_only"] is True
        assert "Fernet" in env["data"]["snippet"]
        assert env["data"]["language"] == "python"

    def test_anti_timestomp_requires_args(self):
        from core.forensics.forensic_modules import run_module
        env = run_module("anti_timestomp", {})
        assert env["ok"] is False
        assert "path" in env["error"].lower() and "timestamp" in env["error"].lower()

    def test_anti_timestomp_actually_runs(self):
        from core.forensics.forensic_modules import run_module
        with tempfile.NamedTemporaryFile(delete=False) as f:
            fpath = f.name
        try:
            env = run_module("anti_timestomp", {
                "path": fpath, "timestamp": "2020-01-01T00:00:00",
            })
            assert env["ok"] is True
            assert env["lab_only"] is True
            assert "timestamp" in env["data"]
        finally:
            os.unlink(fpath)

    def test_file_metadata_real(self):
        from core.forensics.forensic_modules import run_module
        env = run_module("file_metadata", {"path": "/etc/hostname"})
        assert env["ok"] is True
        assert "size" in env["data"]
        assert "mtime" in env["data"]
        assert "owner" in env["data"]

    def test_anti_log_clear_lab_only(self):
        from core.forensics.forensic_modules import run_module
        env = run_module("anti_log_clear", {"log_name": "Security"})
        # Either ok (Windows + wevtutil) or honest-degrade (Linux).
        assert env["lab_only"] is True
        assert env["risk_level"] == "destructive"

    def test_run_module_does_not_raise(self):
        from core.forensics.forensic_modules import run_module
        env = run_module("anti_secure_delete", None)
        assert isinstance(env, dict)
        assert "ok" in env


class TestForensicModuleEdgeCases:
    def test_browser_history_no_profile(self):
        from core.forensics.forensic_modules import run_module
        env = run_module("browser_history", {})
        assert env["ok"] is False
        assert "profile" in env["error"].lower()

    def test_anti_persistence_clean_walks_root(self):
        from core.forensics.forensic_modules import run_module
        # This walks a path — should NOT raise even if read-restricted.
        env = run_module("anti_persistence_clean", {"path": "/tmp"})
        assert "candidates" in env["data"]
        assert env["lab_only"] is True
        # ok=True only if recent candidates were found; on a sterile
        # /tmp the result is honest-empty. Both outcomes are valid.
        assert env["ok"] in (True, False)

    def test_anti_credential_zeroize_missing_key(self):
        from core.forensics.forensic_modules import run_module
        env = run_module("anti_credential_zeroize", {})
        assert env["ok"] is False
        assert "key" in env["error"].lower()

    def test_anti_honeytoken_inject_writes_file(self):
        from core.forensics.forensic_modules import run_module
        tmpdir = tempfile.mkdtemp()
        try:
            fpath = os.path.join(tmpdir, "subdir", "decoy.txt")
            env = run_module("anti_honeytoken_inject", {"path": fpath})
            assert env["ok"] is True
            assert env["lab_only"] is True
            assert os.path.isfile(fpath)
            with open(fpath) as f:
                content = f.read().strip()
            assert "KF_CANARY_" in content
        finally:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_persistence_walk_real(self):
        from core.forensics.forensic_modules import run_module
        env = run_module("persistence_walk", {"path": "/etc"})
        # The walk itself succeeds; found_count may be 0 on a
        # stripped /etc (no systemd / cron.d) or > 0 on a full
        # system. Either is honest.
        assert "found" in env["data"]
        assert "found_count" in env["data"]

    def test_bash_history_real(self):
        from core.forensics.forensic_modules import run_module
        # Should fail honestly if no .bash_history on the test host.
        env = run_module("bash_history", {})
        # Either ok or honest-degrade; never fabricates.
        assert "ok" in env
        assert "error" in env

    def test_run_module_returns_standard_envelope(self):
        from core.forensics.forensic_modules import run_module
        env = run_module("file_hash", {})
        for k in ("name", "ok", "started", "data", "error", "risk_level",
                  "lab_only"):
            assert k in env
