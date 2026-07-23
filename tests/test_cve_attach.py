"""CVE attach-to-target + SQL history + one-time coded PoC."""
from __future__ import annotations

import pytest

from core.cve_attach import (
    already_coded,
    attach_cves_to_target,
    list_history_cve_ids,
    mark_cve_coded,
    normalize_cve_id,
    rank_cves_for_target,
    score_cve_for_target,
    target_context_for_prompt,
    target_key,
)


@pytest.fixture
def hermetic_sql(tmp_path, monkeypatch):
    db = tmp_path / "cve_attach.db"
    monkeypatch.setenv("KFIOSA_SQL_URL", "")  # force sqlite
    # Point sqlite at tmp by init(db_path=...)
    from core.db import sqlstore
    sqlstore.init(db_path=db)
    yield db


def test_normalize_cve_id():
    assert normalize_cve_id("cve-2021-44228") == "CVE-2021-44228"
    assert "CVE-2017-13077" in normalize_cve_id("see CVE-2017-13077 fixed")


def test_score_wifi_cve_higher_than_unrelated():
    target = {
        "domain": "wifi",
        "vendor": "MediaTek",
        "encryption": "WPA2",
        "bssid": "AA:BB:CC:DD:EE:01",
    }
    wifi_cve = {
        "id": "CVE-2017-13077",
        "description": "WPA2 wifi 802.11 KRACK attack on wireless access point",
        "cvss": 8.1,
    }
    junk = {
        "id": "CVE-1999-0001",
        "description": "unrelated printer firmware bug",
        "cvss": 2.0,
    }
    assert score_cve_for_target(wifi_cve, target) > score_cve_for_target(junk, target)


def test_rank_and_attach_persists_history(hermetic_sql, tmp_path, monkeypatch):
    monkeypatch.setenv("KFIOSA_CVE_POC_ROOT", str(tmp_path / "pocs"))
    target = {
        "domain": "wifi",
        "bssid": "AA:BB:CC:DD:EE:FF",
        "ssid": "lab",
        "vendor": "Broadcom",
        "encryption": "WPA2",
        "workspace_id": "ws-test-cve-1",
    }
    cves = [
        {
            "id": "CVE-2017-13077",
            "description": "WPA2 wireless KRACK key reinstallation",
            "cvss": 8.1,
            "refs": ["https://example.com/1"],
        },
        {
            "id": "CVE-2021-44228",
            "description": "Log4j remote code execution",
            "cvss": 10.0,
        },
    ]
    att = attach_cves_to_target(
        target, cves, sid="ws-test-cve-1", domain="wifi", top_n=5,
    )
    assert att["ok"] is True
    assert "CVE-2017-13077" in att["cve_ids"]
    # WiFi-related should rank above log4j for a wifi AP target
    assert att["attached"][0]["cve_id"] == "CVE-2017-13077"
    ids = list_history_cve_ids("ws-test-cve-1")
    assert "CVE-2017-13077" in ids


def test_mark_coded_once_and_reuse(hermetic_sql, tmp_path, monkeypatch):
    monkeypatch.setenv("KFIOSA_CVE_POC_ROOT", str(tmp_path / "pocs"))
    target = {
        "domain": "wifi",
        "bssid": "11:22:33:44:55:66",
        "workspace_id": "ws-code-1",
    }
    attach_cves_to_target(
        target,
        [{"id": "CVE-2019-15126", "description": "wifi kr00k", "cvss": 7.5}],
        sid="ws-code-1",
        domain="wifi",
    )
    code = "def pwn(bssid='11:22:33:44:55:66'):\n    return True\n"
    m = mark_cve_coded(
        target,
        "CVE-2019-15126",
        exploit_code=code,
        model_used="test-model",
        ok=True,
        sid="ws-code-1",
    )
    assert m["ok"] and m["coded"]
    assert m.get("exploit_path")
    # Seed updated
    prior = already_coded(m["target"], "CVE-2019-15126")
    assert prior is not None
    assert prior.get("exploit_code") == code
    # History has cve_coded
    ids = list_history_cve_ids("ws-code-1")
    assert "CVE-2019-15126" in ids


def test_target_context_for_prompt():
    ctx = target_context_for_prompt({
        "domain": "wifi",
        "bssid": "AA:BB",
        "channel": 6,
        "interface": "wlan0mon",
    })
    assert "bssid=AA:BB" in ctx
    assert "channel=6" in ctx


def test_pipeline_template_includes_target_ctx():
    from core.cve_to_exploit.pipeline import CVE_TO_EXPLOIT_PROMPT_TEMPLATE
    assert "{target_ctx}" in CVE_TO_EXPLOIT_PROMPT_TEMPLATE
    prompt = CVE_TO_EXPLOIT_PROMPT_TEMPLATE.format(
        cve_id="CVE-1",
        description="d",
        vendor="v",
        product="p",
        version="1",
        cvss="9.0",
        refs="none",
        target_ctx="bssid=AA:BB; channel=6",
    )
    assert "bssid=AA:BB" in prompt
    assert "Live target" in prompt


def test_pipeline_passes_target_into_prompt(monkeypatch):
    from core.cve_to_exploit import cve_to_exploit_pipeline

    captured = {}

    def nvd(cve_id):
        return {
            "id": cve_id,
            "description": "test wifi vuln",
            "cvss": 7.0,
            "affected": [{"vendor": "V", "product": "P", "version": "1"}],
            "refs": [],
        }

    def ollama(model, prompt, **kw):
        captured["prompt"] = prompt
        return "def exploit():\n    pass\n"

    class Mgr:
        def ensure_exploit_model(self):
            return "fake-model"

    res = cve_to_exploit_pipeline(
        "CVE-2020-0001",
        nvd_lookup_fn=nvd,
        ollama_call_fn=ollama,
        exploit_gen_manager=Mgr(),
        target={"bssid": "DE:AD:BE:EF:00:01", "channel": 11, "domain": "wifi"},
    )
    assert res.ok is True
    assert "DE:AD:BE:EF:00:01" in captured["prompt"]
