"""Live polymorphic target enrichment for scanners."""
from __future__ import annotations

import time


def test_parse_wifi_flags_wpa3_pmf():
    from core.scanners.live_enrich import parse_wifi_flags, passive_enrich_wifi
    f = parse_wifi_flags("WPA3 SAE CCMP")
    assert f["is_wpa3"] and f["is_sae"] and f["pmf_supported"]
    f2 = parse_wifi_flags("OPN")
    assert f2["is_open"]
    f3 = parse_wifi_flags("WPA2 WPA CCMP MGT")
    assert f3["is_enterprise"]


def test_passive_enrich_hidden_and_badges():
    from core.scanners.live_enrich import passive_enrich_wifi
    ap = {
        "bssid": "AA:BB:CC:DD:EE:FF",
        "ssid": "<hidden>",
        "channel": 6,
        "encryption": "WPA2 CCMP",
        "power": -50,
        "clients": ["11:22:33:44:55:66"],
    }
    passive_enrich_wifi(ap)
    assert ap["hidden"] is True
    assert ap["band"] == "2.4GHz"
    assert ap["is_wpa2"] is True
    assert "HID" in (ap.get("recon_badges") or [])
    assert isinstance(ap.get("clients"), list)
    assert ap["clients"][0].get("mac") == "11:22:33:44:55:66"


def test_pick_deep_probes_prefers_hidden():
    from core.scanners.live_enrich import pick_wifi_deep_probes
    ap = {"ssid": "<hidden>", "bssid": "AA", "encryption": "WPA2"}
    probes = pick_wifi_deep_probes(ap)
    assert "hidden_ssid" in probes
    # already done → not re-picked first
    ap["enrich_methods"] = ["hidden_ssid"]
    probes2 = pick_wifi_deep_probes(ap)
    assert "hidden_ssid" not in probes2


def test_apply_probe_revealed_ssid():
    from core.scanners.live_enrich import apply_probe_result, passive_enrich_wifi
    ap = {"bssid": "AA:BB:CC:DD:EE:FF", "ssid": "<hidden>", "encryption": "WPA2"}
    passive_enrich_wifi(ap)
    apply_probe_result(ap, "hidden_ssid", {
        "ok": True,
        "data": {"hidden": True, "revealed_ssid": "HomeLab", "source_frame": "probe-resp"},
    })
    assert ap["ssid"] == "HomeLab"
    assert ap["revealed_ssid"] == "HomeLab"
    assert ap["hidden"] is False
    assert "hidden_ssid" in ap["enrich_methods"]


def test_passive_enrich_ble():
    from core.scanners.live_enrich import passive_enrich_ble
    dev = {"address": "11:22:33:44:55:66", "rssi": -60, "connectable": True}
    passive_enrich_ble(dev)
    assert dev.get("name_missing") is True
    assert "CONN" in (dev.get("recon_badges") or [])


def test_enricher_passive_tick():
    from core.scanners.live_enrich import LiveTargetEnricher
    bag = [{
        "bssid": "AA:BB:CC:DD:EE:01",
        "ssid": "x",
        "channel": 36,
        "encryption": "WPA3 SAE",
        "power": -40,
    }]
    en = LiveTargetEnricher(
        domain="wifi",
        interface="",
        get_targets=lambda: bag,
        deep_interval_s=0.5,
        max_deep_per_tick=0,  # passive only
        max_deep_total=0,
    )
    en.start()
    time.sleep(0.8)
    en.stop()
    assert bag[0].get("is_wpa3") is True
    assert bag[0].get("band") == "5GHz"
    assert en.stats["passive_ticks"] >= 1


def test_formatters_show_badges():
    from core.tui.scan_window_shell import format_wifi_online, detail_for_item
    ap = {
        "bssid": "AA:BB:CC:DD:EE:FF",
        "ssid": "<hidden>",
        "revealed_ssid": "LabNet",
        "channel": 6,
        "encryption": "WPA2",
        "power": -55,
        "clients_count": 2,
        "vendor": "TP-Link",
        "recon_badges": ["WPA2", "PMF"],
        "pmf": True,
        "enrich_methods": ["flags", "oui"],
    }
    line = format_wifi_online(ap)
    assert "LabNet" in line
    assert "AA:BB:CC:DD:EE:FF" in line
    d = detail_for_item(ap, "wifi")
    assert "ssid=LabNet" in d or "revealed=LabNet" in d
