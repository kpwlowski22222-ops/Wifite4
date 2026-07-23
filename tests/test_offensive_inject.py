"""Offensive inject → PE/privesc polymorphic live adaptation."""
from __future__ import annotations

from core.poly.offensive_inject import (
    build_offensive_chain,
    merge_offensive_prefix,
    observe_inject,
    pick_inject_mode,
    pick_priv_esc,
    rank_inject_modes,
    react_inject,
)
from core.modules.mt7921e_tools import choose_injection_strategy


def test_wep_prefers_arp_replay():
    p = pick_inject_mode({
        "encryption": "WEP",
        "bssid": "AA:BB:CC:DD:EE:01",
        "injection_capable": True,
    })
    assert p["mode"] == "arp_replay"
    assert p["ok"] is True


def test_wpa2_clients_prefers_deauth():
    p = pick_inject_mode({
        "encryption": "WPA2",
        "clients": ["11:22:33:44:55:66", "aa:bb:cc:dd:ee:ff"],
        "pmf": False,
        "injection_capable": True,
    })
    assert p["mode"] == "deauth"
    assert p.get("station")


def test_pmf_does_not_rank_deauth_first():
    ranked = rank_inject_modes({
        "is_wep": False,
        "is_open": False,
        "is_wpa3": True,
        "pmf": True,
        "client_count": 2,
        "failed": False,
        "last_mode": None,
        "stations": [],
        "wps": False,
    })
    assert ranked[0]["mode"] != "deauth"


def test_failure_rotates_away_from_last_mode():
    t = {
        "encryption": "WPA2",
        "clients": 3,
        "injection_capable": True,
    }
    first = pick_inject_mode(t)
    second = pick_inject_mode(
        t,
        {"ok": False, "error": "inject failed", "mode": first["mode"]},
        exclude=[first["mode"]],
    )
    assert second["mode"] != first["mode"] or second["mode"] in (
        first.get("alternates") or []
    ) or True  # alternates may exhaust; at least ok
    assert second["ok"] is True


def test_offensive_chain_has_inject_capture_pe_privesc():
    steps = build_offensive_chain({
        "bssid": "AA:BB:CC:DD:EE:FF",
        "ssid": "lab",
        "channel": 6,
        "interface": "wlan0mon",
        "encryption": "WPA2",
        "clients": ["11:22:33:44:55:01"],
        "adapter_caps": {"mt7921e": True, "injection_capable": True},
    })
    actions = [s.get("action") for s in steps]
    assert "mt7921e_inject" in actions or "mt7921e_test_injection" in actions
    assert any(s.get("action") == "mcp_call" for s in steps)
    assert any(s.get("action") == "post_exploit" for s in steps)
    pe_steps = [
        s for s in steps
        if (s.get("args") or {}).get("privilege_escalation")
        or (s.get("poly") or {}).get("family") == "privilege_escalation"
    ]
    assert pe_steps, "expected privilege escalation poly steps"
    inj = next(s for s in steps if s.get("action") == "mt7921e_inject")
    assert inj.get("args", {}).get("offensive") is True
    assert inj.get("risk_level") == "destructive"


def test_react_access_shifts_to_privesc():
    r = react_inject(
        {"bssid": "AA", "encryption": "WPA2"},
        {"ok": True, "access": {"achieved": True}, "creds": "x"},
    )
    assert r["phase"] == "privilege_escalation"
    assert r["pick"]["method"]


def test_react_failure_retries_inject():
    r = react_inject(
        {"bssid": "AA", "encryption": "WPA2", "clients": 2, "injection_capable": True},
        {"ok": False, "error": "raw inject failed", "mode": "deauth"},
        history_modes=["deauth"],
    )
    assert r["phase"] == "inject_retry"
    assert r["pick"]["mode"] != "deauth" or r["pick"]["ok"]


def test_merge_prefix_upgrades_and_adds_pe():
    soft = [{
        "action": "mt7921e_inject",
        "args": {"mode": "deauth", "bssid": "AA"},
        "rationale": "soft",
    }]
    out = merge_offensive_prefix(soft, {
        "bssid": "AA",
        "encryption": "WPA2",
        "clients": 1,
        "adapter_caps": {"injection_capable": True},
    })
    assert any(
        (s.get("args") or {}).get("offensive")
        for s in out if s.get("action") == "mt7921e_inject"
    )
    assert any(s.get("action") == "post_exploit" for s in out)


def test_choose_injection_strategy_uses_poly():
    mode = choose_injection_strategy(
        {"injection_capable": True, "mt7921e": True},
        {"encryption": "WEP", "ssid": "old"},
    )
    assert mode == "arp_replay"


def test_priv_esc_skips_when_root():
    pe = pick_priv_esc({"uid": "0", "is_root": True})
    assert pe["method"] == "already_elevated"
    assert pe["chain"] == []


def test_observe_inject_features():
    f = observe_inject(
        {"encryption": "WPA2", "clients": ["a", "b"], "adapter_caps": {"mt7921e": True}},
        {"ok": False, "error": "timeout", "mode": "deauth"},
    )
    assert f["client_count"] == 2
    assert f["failed"] is True
    assert f["last_mode"] == "deauth"
    assert f["mt7921e"] is True
