"""OSINTScreen actions — curses-free, one test per action."""

import shutil
import subprocess
import sys
import types

import pytest

from core.tui.osint_screen import OSINTScreen
from tests.conftest import _make_screen
from tests.fakes import (
    FakeConfirmFn, FakeInput, FakeKB, FakeOSINTRunner, FakeOrchestrator,
    FakePostRunner, sync_thread_runner,
)


def _osint(log, **over):
    return _make_screen(OSINTScreen, log, **over)


# ---- target + primary flow ----

def test_set_osint_target(log):
    sc = _osint(log, input_fn=FakeInput(["example.com"]))
    sc.set_osint_target()
    assert sc.target == "example.com"
    assert sc.osint_findings == []
    assert any("OSINT target set" in l for l in log)


def test_run_full_osint_chain_calls_orchestrator_and_collects_findings(log):
    orch = FakeOrchestrator()
    sc = _osint(log, orchestrator=orch, osint_runner=FakeOSINTRunner())
    sc.target = "alice"
    sc.run_full_osint_chain()
    assert orch.runs and orch.runs[0]["domain"] == "osint"
    assert sc._last_report["domain"] == "osint"
    # people-search findings were absorbed
    assert sc.osint_findings


def test_run_full_osint_chain_no_target(log):
    sc = _osint(log)
    sc.run_full_osint_chain()
    assert any("Set an OSINT target first" in l for l in log)


def test_show_findings_view(log):
    sc = _osint(log)
    sc.osint_findings = [{"type": "email", "value": "a@b.com"},
                        {"type": "cve", "value": "CVE-2021-44228"}]
    sc._show_findings_view()
    assert sc.flow_state == "targets"
    assert sc.menu_items[0][0].startswith("1. [email] a@b.com")


def test_show_findings_empty(log):
    sc = _osint(log)
    sc._show_findings_view()
    assert any("No findings yet" in l for l in log)


def test_show_report(log):
    sc = _osint(log)
    sc.target = "x.com"
    sc._last_report = {"domain": "osint"}
    sc.show_report()
    assert any("Last OSINT Engagement Report" in l for l in log)


# ---- people search ----

def test_run_people_search(log):
    sc = _osint(log, osint_runner=FakeOSINTRunner())
    sc.target = "alice"
    sc.run_people_search()
    assert any("People search complete" in l for l in log)
    assert sc.osint_findings  # absorbed


def test_run_people_search_no_target(log):
    sc = _osint(log)
    sc.run_people_search()
    assert any("Set a target" in l for l in log)


# ---- email OSINT (holehe) ----

def test_run_email_osint(log, monkeypatch):
    sc = _osint(log, input_fn=FakeInput([]))
    sc.target = "alice@example.com"
    monkeypatch.setattr(shutil, "which", lambda n: "/usr/bin/holehe" if n == "holehe" else None)

    class FakeCP:
        returncode = 0
        stdout = "[+] github: account exists"
        stderr = ""

    monkeypatch.setattr(subprocess, "run", lambda *a, **k: FakeCP())
    sc.run_email_osint()
    assert any("holehe rc=0" in l for l in log)


def test_run_email_osint_not_email(log):
    sc = _osint(log)
    sc.target = "not-an-email"
    sc.run_email_osint()
    assert any("does not appear to be an email" in l for l in log)


def test_run_email_osint_tool_missing(log, monkeypatch):
    sc = _osint(log)
    sc.target = "a@b.com"
    monkeypatch.setattr(shutil, "which", lambda n: None)
    sc.run_email_osint()
    assert any("holehe not installed" in l for l in log)


# ---- username OSINT ----

def test_run_username_osint(log, monkeypatch):
    sc = _osint(log)
    sc.target = "alice"
    monkeypatch.setattr(shutil, "which", lambda n: "/usr/bin/sherlock" if n == "sherlock" else None)

    class FakeCP:
        returncode = 0
        stdout = "Found x.com/alice"
        stderr = ""

    monkeypatch.setattr(subprocess, "run", lambda *a, **k: FakeCP())
    sc.run_username_osint()
    assert any("sherlock rc=0" in l for l in log)


def test_run_username_osint_no_tools(log, monkeypatch):
    sc = _osint(log)
    sc.target = "alice"
    monkeypatch.setattr(shutil, "which", lambda n: None)
    sc.run_username_osint()
    assert any("Neither sherlock nor nexfil" in l for l in log)


# ---- domain OSINT (shodan) ----

def test_run_domain_osint(log, monkeypatch):
    fake_mod = types.ModuleType("core.integrations.shodan_integration")

    class FakeShodan:
        def __init__(self, settings=None):
            self.settings = settings

        def initialize(self):
            pass

        def search_host(self, target):
            return {"ip_str": "1.2.3.4", "os": "Linux",
                    "ports": [22, 80], "vulns": ["CVE-2021-1"]}

    fake_mod.ShodanIntegration = FakeShodan
    monkeypatch.setitem(sys.modules, "core.integrations.shodan_integration", fake_mod)
    sc = _osint(log)
    sc.target = "example.com"
    sc.run_domain_osint()
    assert any("Shodan host info" in l for l in log)
    assert any("Open Ports" in l for l in log)
    assert any(f for f in sc.osint_findings if f["type"] == "open_port")


def test_run_domain_osint_no_target(log):
    sc = _osint(log)
    sc.run_domain_osint()
    assert any("set target domain first" in l for l in log)


# ---- CVE lookup (NVD) ----

def test_run_cve_lookup(log, monkeypatch):
    import requests

    class FakeResp:
        status_code = 200

        def json(self):
            return {"vulnerabilities": [
                {"cve": {"id": "CVE-2021-44228",
                          "descriptions": [{"lang": "en", "value": "RCE via JNDI"}]}}
            ]}

    monkeypatch.setattr(requests, "get", lambda *a, **k: FakeResp())
    sc = _osint(log, input_fn=FakeInput(["CVE-2021-44228"]), kb=FakeKB())
    sc.run_cve_lookup()
    assert any("NVD returned 1 CVE" in l for l in log)
    assert any(f for f in sc.osint_findings if f["type"] == "cve")


def test_run_cve_lookup_no_query(log):
    sc = _osint(log, input_fn=FakeInput([""]))
    sc.run_cve_lookup()
    assert any("No CVE or target set" in l for l in log)


# ---- social OSINT ----

def test_run_social_osint(log, monkeypatch):
    sc = _osint(log)
    sc.target = "alice"
    monkeypatch.setattr(shutil, "which", lambda n: "/usr/bin/toutatis" if n == "toutatis" else None)

    class FakeCP:
        returncode = 0
        stdout = "user_id: 12345"
        stderr = ""

    monkeypatch.setattr(subprocess, "run", lambda *a, **k: FakeCP())
    sc.run_social_osint()
    assert any("toutatis rc=0" in l for l in log)


def test_run_social_osint_missing(log, monkeypatch):
    sc = _osint(log)
    sc.target = "alice"
    monkeypatch.setattr(shutil, "which", lambda n: None)
    sc.run_social_osint()
    assert any("toutatis not installed" in l for l in log)


# ---- autonomous OSINT ----

def test_run_autonomous_osint(log):
    sc = _osint(log)
    sc.target = "alice"
    sc.run_autonomous_osint()
    assert any("AI Autonomous OSINT Workflow" in l for l in log)
    assert any("AI recommended tool sequence" in l for l in log)


# ---- post-exploit + catalog ----

def test_plan_post_exploit_with_session(log):
    sc = _osint(log, post_runner=FakePostRunner(msf_steps=[{"desc": "s1"}]),
               input_fn=FakeInput(["sess-1"]))
    sc.target = "example.com"
    sc.plan_post_exploit()
    assert sc._post_plan["msf_plan"] is not None


def test_execute_post_exploit_no_plan(log):
    sc = _osint(log)
    sc.execute_post_exploit()
    assert any("No MSF plan to execute" in l for l in log)


def test_search_tools_catalog(log):
    sc = _osint(log, input_fn=FakeInput(["email"]))
    sc.search_tools_catalog()
    assert any("Found" in l for l in log)