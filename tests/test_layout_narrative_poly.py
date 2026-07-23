"""Layout split, narrative log, and live_adapt polymorphism."""
from __future__ import annotations

from core.tui.layout import layout_panels, MIN_SPLIT_WIDTH
from core.tui.narrative_log import humanize_event, step_begin, narrate
from core.poly.live_adapt import observe, pick, react, poly_pre_step


def test_layout_split_on_wide_terminal():
    lay = layout_panels(40, 120)
    assert lay.mode == "split"
    assert lay.left.w >= 32
    assert lay.right.w >= 36
    assert lay.left.w + lay.right.w == 120
    assert lay.right.x == lay.left.w


def test_layout_stack_on_narrow_terminal():
    lay = layout_panels(30, MIN_SPLIT_WIDTH - 10)
    assert lay.mode == "stack"


def test_narrative_humanizes_tags():
    out = humanize_event("[+] Triple scan windows on wlan0mon")
    assert "Progress" in out or "scan" in out.lower() or "windows" in out.lower()
    out2 = humanize_event("[!] injection failed")
    assert "snag" in out2.lower() or "failed" in out2.lower()


def test_step_begin_wifi():
    s = step_begin("wifi", {"ssid": "lab"})
    assert "lab" in s and "Wi" in s


def test_live_adapt_pmf_avoids_raw_deauth_first():
    feats = observe(
        {"encryption": "WPA3-SAE", "pmf": True, "adapter_caps": {"injection_capable": True}},
        domain="wifi",
    )
    assert feats["is_sae"] or feats["pmf"]
    choice = pick("wifi", feats)
    assert "deauth" not in (choice.get("method") or "").lower() or "sae" in (
        choice.get("rationale") or ""
    ).lower()


def test_live_adapt_react_and_pre_step():
    r = react("ble", {"name": "sensor", "rssi": -90, "connectable": True})
    assert r.get("method")
    assert r.get("features")
    pre = poly_pre_step("wifi", {"ssid": "x", "encryption": "WPA2"})
    assert pre.get("action") == "poly_adapt"


def test_narrate_passthrough_when_disabled(monkeypatch):
    monkeypatch.setenv("KFIOSA_NARRATIVE_LOG", "0")
    assert narrate("[+] raw") == "[+] raw"
    monkeypatch.setenv("KFIOSA_NARRATIVE_LOG", "1")
    assert narrate("[+] raw") != "[+] raw" or "Progress" in narrate("[+] hello")
