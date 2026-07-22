"""External injection toolbox wrappers — hermetic unit tests.

No network, no real subprocess against devices, no root required. We
monkeypatch ``subprocess.run`` / ``shutil.which`` / ``os.geteuid`` /
``_resolve_bin`` so the wrappers' command construction and never-raise
contract can be asserted without building the C binaries.
"""

import os
import subprocess

import pytest

from core.modules import external_injection as ext


def _fake_bins(monkeypatch):
    """Make ``_run``'s existence check believe any fake binary path
    resolves, so tests reach the root gate / subprocess.run call
    instead of bailing on ``not installed``."""
    monkeypatch.setattr(ext.shutil, "which", lambda name: name)
    monkeypatch.setattr(ext.os.path, "exists", lambda p: True)


# ---------------------------------------------------------------------------
# probe + registry
# ---------------------------------------------------------------------------
def test_probe_returns_expected_keys():
    p = ext.probe_external_injection_tools()
    for k in ("nemesis", "inject", "wpr_tx_rx", "dnsinject",
              "python3", "docker"):
        assert k in p


def test_registry_has_five_tools_with_required_fields():
    names = {t["name"] for t in ext.EXTERNAL_INJECTION_TOOLS}
    assert names == {"nemesis_inject", "inject_tool_inject", "wpr_tx",
                     "cse508_dns_inject", "mt7921e_research_firmware"}
    for t in ext.EXTERNAL_INJECTION_TOOLS:
        for f in ("name", "binary", "description", "input_schema",
                  "examples", "risk_level", "requires_root", "domain",
                  "entrypoint"):
            assert f in t, f"{t['name']} missing {f}"
        assert callable(getattr(ext, t["entrypoint"]))


# ---------------------------------------------------------------------------
# _args_to_flags
# ---------------------------------------------------------------------------
def test_args_to_flags_alias_and_passthrough_and_bool():
    out = ext._args_to_flags(
        {"src_ip": "1.2.3.4", "count": 5, "verbose": True, "quiet": False,
         "-z": "9", "K": "00:11"},
        ext._NEMESIS_ALIASES,
    )
    # src_ip -> -S, count -> -x, verbose -> bare -v (well, alias map has no
    # verbose for nemesis so it becomes --verbose), quiet skipped, -z verbatim,
    # single-char K -> -K.
    assert "-S" in out and "1.2.3.4" in out
    assert "-x" in out and "5" in out
    assert "-z" in out and "9" in out
    assert "-K" in out and "00:11" in out
    # bool False skipped, True emits bare flag.
    assert "quiet" not in out
    assert "--verbose" in out  # bare flag for True


# ---------------------------------------------------------------------------
# nemesis
# ---------------------------------------------------------------------------
def test_nemesis_rejects_unknown_protocol():
    r = ext.nemesis_inject("foo", iface="eth0")
    assert r["ok"] is False
    assert "unsupported nemesis protocol" in r["error"]


def test_nemesis_missing_binary(monkeypatch):
    monkeypatch.setattr(ext, "_resolve_bin", lambda name: None)
    r = ext.nemesis_inject("arp", iface="eth0")
    assert r["ok"] is False
    assert "nemesis not installed" in r["error"]


def test_nemesis_builds_cmd_and_runs(monkeypatch):
    _fake_bins(monkeypatch)
    monkeypatch.setattr(ext, "_resolve_bin", lambda name: "/fake/nemesis")
    monkeypatch.setattr(ext.os, "geteuid", lambda: 0)
    captured = {}

    class FakeCP:
        returncode = 0
        stdout = "ok"
        stderr = ""

    def fake_run(cmd, **kw):
        captured["cmd"] = cmd
        return FakeCP()

    monkeypatch.setattr(ext.subprocess, "run", fake_run)
    r = ext.nemesis_inject("arp", iface="eth0",
                           args={"src_ip": "1.2.3.4", "dst_ip": "10.0.0.1"})
    assert r["ok"] is True
    assert r["method"] == "nemesis"
    assert r["protocol"] == "arp"
    cmd = captured["cmd"]
    assert cmd[0] == "/fake/nemesis"
    assert cmd[1] == "arp"
    assert "-d" in cmd and "eth0" in cmd  # iface
    assert "-S" in cmd and "1.2.3.4" in cmd  # src_ip alias
    assert "-D" in cmd and "10.0.0.1" in cmd  # dst_ip alias
    assert " ".join(r["cmd"].split())  # cmd string rendered


def test_nemesis_never_raises_on_subprocess_error(monkeypatch):
    _fake_bins(monkeypatch)
    monkeypatch.setattr(ext, "_resolve_bin", lambda name: "/fake/nemesis")
    monkeypatch.setattr(ext.os, "geteuid", lambda: 0)

    def boom(cmd, **kw):
        raise RuntimeError("boom")

    monkeypatch.setattr(ext.subprocess, "run", boom)
    r = ext.nemesis_inject("icmp")
    assert r["ok"] is False
    assert "boom" in r["error"]


# ---------------------------------------------------------------------------
# inject (fksvs)
# ---------------------------------------------------------------------------
def test_inject_tool_rejects_unknown_protocol():
    r = ext.inject_tool_inject("foo", iface="eth0")
    assert r["ok"] is False
    assert "unsupported inject protocol" in r["error"]


def test_inject_tool_builds_tcp_cmd(monkeypatch):
    _fake_bins(monkeypatch)
    monkeypatch.setattr(ext, "_resolve_bin", lambda name: "/fake/inject")
    monkeypatch.setattr(ext.os, "geteuid", lambda: 0)
    captured = {}

    class FakeCP:
        returncode = 0
        stdout = ""
        stderr = ""

    monkeypatch.setattr(ext.subprocess, "run",
                        lambda cmd, **k: captured.__setitem__("cmd", cmd)
                        or FakeCP())
    r = ext.inject_tool_inject("tcp", iface="eth0",
                               args={"src_ip": "1.2.3.4", "dst_ip": "10.0.0.1",
                                     "src_port": "4444", "dst_port": "80",
                                     "flags": "syn"})
    assert r["ok"] is True
    cmd = captured["cmd"]
    assert cmd[0] == "/fake/inject"
    assert cmd[1] == "tcp"
    assert "-i" in cmd and "eth0" in cmd
    assert "-S" in cmd and "1.2.3.4" in cmd
    assert "-o" in cmd and "4444" in cmd   # src_port alias
    assert "-d" in cmd and "80" in cmd     # dst_port alias
    assert "-f" in cmd and "syn" in cmd    # flags alias


# ---------------------------------------------------------------------------
# root gate
# ---------------------------------------------------------------------------
def test_root_gate_blocks_exec(monkeypatch):
    _fake_bins(monkeypatch)
    monkeypatch.setattr(ext, "_resolve_bin", lambda name: "/fake/nemesis")
    monkeypatch.setattr(ext.os, "geteuid", lambda: 1000)
    ran = []
    monkeypatch.setattr(ext.subprocess, "run",
                        lambda cmd, **k: ran.append(cmd) or subprocess.CompletedProcess(
                            cmd, 0, "", ""))
    r = ext.nemesis_inject("arp", iface="eth0")
    assert r["ok"] is False
    assert r["error"] == "needs root"
    assert ran == []  # never execed


# ---------------------------------------------------------------------------
# wpr_tx
# ---------------------------------------------------------------------------
def test_wpr_tx_missing_binary(monkeypatch):
    monkeypatch.setattr(ext, "_resolve_bin", lambda name: None)
    r = ext.wpr_tx(iface="wlan1mon", channel=6)
    assert r["ok"] is False
    assert "wpr_tx_rx not built" in r["error"]


def test_wpr_tx_root_gate(monkeypatch):
    monkeypatch.setattr(ext, "_resolve_bin", lambda name: "/fake/wpr_tx_rx")
    monkeypatch.setattr(ext.os, "geteuid", lambda: 1000)
    r = ext.wpr_tx(iface="wlan1mon")
    assert r["ok"] is False
    assert r["error"] == "needs root"


def test_wpr_tx_runs_with_env_overrides(monkeypatch):
    monkeypatch.setattr(ext, "_resolve_bin", lambda name: "/fake/wpr_tx_rx")
    monkeypatch.setattr(ext.os, "geteuid", lambda: 0)
    captured = {}

    class FakeCP:
        returncode = 0
        stdout = ""
        stderr = ""

    def fake_run(cmd, **kw):
        captured["cmd"] = cmd
        captured["env"] = kw.get("env", {})
        return FakeCP()

    monkeypatch.setattr(ext.subprocess, "run", fake_run)
    r = ext.wpr_tx(iface="wlan1mon", channel=6, payload_file="/tmp/f",
                   count=3)
    assert r["ok"] is True
    assert r["method"] == "wpr_tx"
    env = captured["env"]
    assert env["WPR_RADIO_IFACE"] == "wlan1mon"
    assert env["WPR_CHANNEL"] == "6"
    assert env["WPR_PAYLOAD_FILE"] == "/tmp/f"
    assert env["WPR_TX_COUNT"] == "3"


# ---------------------------------------------------------------------------
# cse508 DNS inject
# ---------------------------------------------------------------------------
def test_cse508_dns_inject_requires_iface():
    r = ext.cse508_dns_inject(iface="")
    assert r["ok"] is False
    assert "iface required" in r["error"]


def test_cse508_dns_inject_builds_cmd(monkeypatch):
    _fake_bins(monkeypatch)
    monkeypatch.setattr(ext.shutil, "which",
                        lambda name: "/fake/python3" if name == "python3"
                        else None)
    monkeypatch.setattr(ext, "_resolve_bin",
                        lambda name: "/fake/dnsinject.py"
                        if name == "dnsinject" else None)
    monkeypatch.setattr(ext.os, "geteuid", lambda: 0)
    captured = {}

    class FakeCP:
        returncode = 0
        stdout = ""
        stderr = ""

    monkeypatch.setattr(ext.subprocess, "run",
                        lambda cmd, **k: captured.__setitem__("cmd", cmd)
                        or FakeCP())
    r = ext.cse508_dns_inject(iface="at0",
                              hostnames="/tmp/hosts",
                              expression="udp port 53")
    assert r["ok"] is True
    cmd = captured["cmd"]
    assert cmd[0] == "/fake/python3"
    assert cmd[1] == "/fake/dnsinject.py"
    assert "-i" in cmd and "at0" in cmd
    assert "-e" in cmd and "udp port 53" in cmd
    assert "/tmp/hosts" in cmd


# ---------------------------------------------------------------------------
# mt7921e firmware / driver research (MT7922 closed MediaTek firmware)
# ---------------------------------------------------------------------------
def test_mt7921e_research_firmware_default_returns_recipe_no_exec(monkeypatch):
    ran = []
    monkeypatch.setattr(ext.subprocess, "run",
                        lambda cmd, **k: ran.append(cmd)
                        or subprocess.CompletedProcess(cmd, 0, "", ""))
    r = ext.mt7921e_research_firmware(target="mt7922")
    assert r["ok"] is True
    assert r["live_test"] is False
    # Recipe targets the open mt76/mt7921e driver source + the closed
    # MediaTek firmware blob (offline RE) — no legacy sovereign refs.
    assert "mt76" in r["recipe"] or "mt7921" in r["recipe"]
    assert "linux-firmware" in r["recipe"]
    assert ran == []  # no exec in guidance mode


def test_mt7921e_research_firmware_live_test_unsupported_closed_firmware(monkeypatch):
    """MT7922 firmware is a closed MediaTek binary blob — live reflash is
    NOT supported (the legacy use_dev_fw + 30s rollback trick does
    not apply). live_test=True must surface ok=False with an explanatory
    error and NEVER invoke a subprocess."""
    ran = []
    monkeypatch.setattr(ext.subprocess, "run",
                        lambda cmd, **k: ran.append(cmd)
                        or subprocess.CompletedProcess(cmd, 0, "", ""))
    r = ext.mt7921e_research_firmware(live_test=True)
    assert r["ok"] is False
    assert r["live_test"] is True
    assert "closed" in r["error"].lower()
    assert "reflash" in r["error"].lower()
    assert ran == []  # never shells out for the closed-firmware path


def test_mt7921e_research_firmware_recipe_warns_no_reflash(monkeypatch):
    """The recipe must explicitly warn against live reflash (bricks the
    MT7922) and point at offline RE only."""
    r = ext.mt7921e_research_firmware()
    assert r["ok"] is True
    assert "NOT supported" in r["recipe"] or "NOT" in r["recipe"]
    assert "bricks" in r["recipe"].lower() or "reflash" in r["recipe"].lower()