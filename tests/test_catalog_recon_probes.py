"""Tests for the 9 novel passive recon probes in
``core.modules.catalog_recon`` (+ the AP-section parser, the run_probe
dispatch, and the with_probes run() mode).

Hermetic: ``shutil.which`` is mocked so the real Kali binaries
(tshark/airodump-ng/gpspipe are installed on the dev host) are never
invoked. tshark/airodump output is faked by overriding the instance
helpers ``_tshark`` / ``_fresh_airodump_pcap`` / ``_fresh_airodump_csv``.
scapy is not installed in the venv, so the scapy enrichment paths
naturally ImportError. No real interface, no root.
"""

import json
import os
import unittest.mock as mock

import pytest

from core.modules.catalog_recon import (
    CatalogRecon, RECON_PROBES,
)
import core.modules.catalog_recon as cr


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

def _target(**over):
    t = {
        "ssid": "TestNet", "bssid": "EC:08:6B:11:22:33",
        "channel": "6", "interface": "wlan0mon", "encryption": "WPA2",
    }
    t.update(over)
    return t


def _recon(**over):
    return CatalogRecon(target=_target(**over), nvd_cfg={"api_key": ""},
                        weakpass_outdir="/tmp")


def _which(*installed):
    """Fake shutil.which: returns a path for names in ``installed``,
    ``None`` otherwise."""
    inst = set(installed)

    def _w(name, *a, **k):
        return "/usr/bin/" + name if name in inst else None
    return _w


def _write_csv(tmp_path, aps_csv, stations_csv):
    """Write a synthetic airodump-ng CSV (AP section + station section)
    and return its path."""
    p = tmp_path / "scan-01.csv"
    p.write_text(aps_csv + "\n" + stations_csv + "\n", encoding="utf-8")
    return str(p)


# ---------------------------------------------------------------------------
# Registry / dispatch
# ---------------------------------------------------------------------------

def test_recon_probes_registry_shape():
    # 6 core recon steps + 9 novel passive probes = 15.
    assert len(RECON_PROBES) == 15
    names = {s["name"] for s in RECON_PROBES}
    assert len(names) == 15
    methods = {s["method"] for s in RECON_PROBES}
    assert methods == set(CatalogRecon.RECON_PROBE_METHODS)
    for s in RECON_PROBES:
        assert s["name"].startswith("recon_probe_")
        assert s["method"] and s["description"] and s["input_schema"]
        assert s["risk_level"] == "read"      # all passive
        assert s["requires_root"] is False
        assert s["examples"]


def test_run_probe_unknown_method_degrades():
    r = _recon()
    res = r.run_probe("bogus")
    assert res["ok"] is False
    assert "unknown probe method" in (res.get("error") or "")


def test_module_level_run_probe_unknown():
    res = cr.run_probe(method="nope", target=_target())
    assert res["ok"] is False


def _core_step_fns():
    """Legacy method names for the 6 core recon steps."""
    return [
        "_wps_probe", "_client_enum", "_cve_search",
        "_weakpass_wordlist", "_kb_search", "_catalog_iter",
    ]


def _novel_probe_fns():
    """``_method`` names for the 9 novel probes only (not core aliases)."""
    core = set(CatalogRecon._CORE_STEP_FNS)
    return [f"_{m}" for m in CatalogRecon.RECON_PROBE_METHODS if m not in core]


def test_run_default_does_not_run_probes():
    r = _recon()
    core = _core_step_fns()
    novel = _novel_probe_fns()
    mocks = {n: mock.MagicMock() for n in core + novel}
    for n, m in mocks.items():
        setattr(r, n, m)
    r.run()
    for n in core:
        mocks[n].assert_called_once()
    for n in novel:
        mocks[n].assert_not_called()


def test_run_with_probes_runs_all_15(tmp_path):
    """with_probes=True runs 6 core + 9 novel = 15 steps.

    Core steps use legacy names (_wps_probe, not _wps). Novel probes use
    _<method>. Must not AttributeError on missing _wps.
    """
    r = _recon()
    r.outdir = tmp_path
    core = _core_step_fns()
    novel = _novel_probe_fns()
    assert len(core) == 6
    assert len(novel) == 9
    mocks = {n: mock.MagicMock() for n in core + novel}
    for n, m in mocks.items():
        setattr(r, n, m)
    report = r.run(with_probes=True)
    for n in core + novel:
        mocks[n].assert_called_once()
    # Sanity: report still has every recon key.
    for k in list(CatalogRecon.RECON_PROBE_METHODS):
        assert k in report


def test_run_with_probes_no_attribute_error_on_core_aliases(tmp_path):
    """Regression: wifi_screen calls run(with_probes=True); must not raise
    'CatalogRecon' object has no attribute '_wps'."""
    r = _recon()
    r.outdir = tmp_path
    # Leave real methods; stub only subprocess-heavy cores that need tools.
    for name in _core_step_fns():
        setattr(r, name, mock.MagicMock(return_value={"ok": True}))
    for name in _novel_probe_fns():
        setattr(r, name, mock.MagicMock(return_value={"ok": True}))
    # Must not raise AttributeError.
    report = r.run(with_probes=True)
    assert "finished_at" in report
    assert report.get("duration_s") is not None


# ---------------------------------------------------------------------------
# AP-section parser + airodump helpers
# ---------------------------------------------------------------------------

_APS = ("BSSID, First time seen, Last time seen, channel, Speed, Privacy, "
        "Cipher, Authentication, Power, # beacons, # IV, LAN IP, "
        "ID-length, ESSID, Key\n"
        "EC:08:6B:11:22:33, 2026-07-15, 2026-07-15, 6, 270, WPA2, CCMP, "
        "PSK, -45, 120, 0, 0.0.0.0, 7, TestNet, \n"
        "AA:BB:CC:DD:EE:01, 2026-07-15, 2026-07-15, 1, 270, OPN, , , "
        "-55, 80, 0, 0.0.0.0, 4, Open, \n")
_STATIONS = ("Station MAC, First time seen, Last time seen, Power, "
             "# packets, BSSID, ESSID, Probes\n"
             "11:22:33:44:55:66, t, t, -50, 30, EC:08:6B:11:22:33, , \n")


def test_parse_aps_csv_returns_ap_rows(tmp_path):
    p = _write_csv(tmp_path, _APS, _STATIONS)
    aps = CatalogRecon._parse_aps_csv(p)
    assert len(aps) == 2
    assert aps[0]["bssid"] == "EC:08:6B:11:22:33"
    assert aps[0]["ssid"] == "TestNet"
    assert aps[0]["channel"] == "6"
    assert aps[0]["power"] == "-45"


def test_parse_aps_csv_missing_file():
    assert CatalogRecon._parse_aps_csv("/no/such/file.csv") == []


def test_airodump_csv_path_resolves_existing(tmp_path):
    p = _write_csv(tmp_path, _APS, _STATIONS)
    r = _recon()
    r.recon["clients"]["data"] = {"csv": p}
    assert r._airodump_csv_path() == p


def test_airodump_csv_path_none_when_missing():
    r = _recon()
    r.recon["clients"]["data"] = {"csv": "/no/such.csv"}
    assert r._airodump_csv_path() is None


def test_chan_freq_and_band():
    assert cr._chan_freq(1) == 2412
    assert cr._chan_freq(6) == 2437   # 2412 + (6-1)*5
    assert cr._chan_freq(36) == 5180
    assert cr._chan_freq("abc") is None
    assert cr._is_band_5ghz(36) is True
    assert cr._is_band_5ghz(6) is False


# ---------------------------------------------------------------------------
# Probe 1: probe_profile
# ---------------------------------------------------------------------------

def test_probe_profile_pnl_and_clusters(tmp_path):
    r = _recon()
    csv = _write_csv(tmp_path, _APS, _STATIONS)
    r.recon["clients"]["data"] = {"csv": csv}
    # Override the station parser to feed crafted PNL rows (cols[5]=probes
    # per the existing parser's positional assumption). Two MACs share
    # the same probed SSID set (Jaccard=1.0 -> one cluster); one has a
    # locally-administered (randomized) MAC.
    stations = [
        {"mac": "1A:22:33:44:55:66", "bssid": "", "power": "-50",
         "probes": "HomeNet", "packets": ""},
        {"mac": "1A:22:33:44:55:66", "bssid": "", "power": "-51",
         "probes": "FreeWiFi", "packets": ""},
        {"mac": "2A:22:33:44:55:66", "bssid": "", "power": "-52",
         "probes": "HomeNet", "packets": ""},
        {"mac": "2A:22:33:44:55:66", "bssid": "", "power": "-53",
         "probes": "FreeWiFi", "packets": ""},
        {"mac": "99:88:77:66:55:44", "bssid": "", "power": "-60",
         "probes": "Lonely", "packets": ""},
    ]
    r._parse_clients_csv = lambda path: stations
    res = r._probe_profile()
    assert res["ok"] is True
    data = res["data"]
    assert data["clients_profiled"] == 3
    pnl = {p["mac"]: p for p in data["pnl"]}
    # 1A... second nibble 'A' -> randomized; 2A... 'A' -> randomized;
    # 99... second nibble '9' -> not randomized.
    assert pnl["1A:22:33:44:55:66"]["is_randomized"] is True
    assert pnl["2A:22:33:44:55:66"]["is_randomized"] is True
    assert pnl["99:88:77:66:55:44"]["is_randomized"] is False
    assert set(pnl["1A:22:33:44:55:66"]["probed_ssids"]) == {"HomeNet", "FreeWiFi"}
    # The two PNL-sharing MACs cluster; the lonely one does not.
    clusters = data["shared_ownership_clusters"]
    flat = [m for c in clusters for m in c]
    assert "1A:22:33:44:55:66" in flat
    assert "2A:22:33:44:55:66" in flat
    assert "99:88:77:66:55:44" not in flat


def test_probe_profile_no_csv_degrades():
    r = _recon()
    with mock.patch.object(cr.shutil, "which", _which()):
        res = r._probe_profile()
    assert res["ok"] is False
    assert "no airodump-ng CSV" in (res.get("error") or "")


# ---------------------------------------------------------------------------
# Probe 2: hidden_ssid
# ---------------------------------------------------------------------------

def test_hidden_ssid_reveals_via_tshark(tmp_path):
    r = _recon()
    pcap = str(tmp_path / "cap-01.cap")
    open(pcap, "w").close()
    r._fresh_airodump_pcap = lambda *, duration_s=15: pcap
    # First _tshark call: probe-resp with a non-empty SSID for our BSSID.
    # Second _tshark call: beacon SSID empty -> hidden stays True, but
    # revealed_ssid is set from the probe-resp.
    calls = {"i": 0}
    canned = [
        "TestNet\tEC:08:6B:11:22:33\t11:22:33:44:55:66\t5\n",  # reveal
        "\tEC:08:6B:11:22:33\t\t8\n",                          # beacons
    ]

    def fake_tshark(args, timeout=15):
        i = calls["i"]; calls["i"] += 1
        return canned[i] if i < len(canned) else ""
    r._tshark = fake_tshark
    with mock.patch.object(cr.shutil, "which", _which("tshark")):
        res = r._hidden_ssid()
    assert res["ok"] is True
    assert res["data"]["revealed_ssid"] == "TestNet"
    assert res["data"]["source_frame"] == "probe-resp"
    assert res["data"]["client_mac"] == "11:22:33:44:55:66"
    assert res["data"]["hidden"] is True


def test_hidden_ssid_no_bssid():
    r = _recon(bssid="")
    res = r._hidden_ssid()
    assert res["ok"] is False
    assert "no bssid" in (res.get("error") or "")


# ---------------------------------------------------------------------------
# Probe 3: signal_map
# ---------------------------------------------------------------------------

def test_signal_map_math_and_exposure():
    r = _recon()
    r.recon["clients"]["data"] = {"aps": [
        {"bssid": "EC:08:6B:11:22:33", "ssid": "TestNet",
         "channel": "6", "power": "-45"},
        {"bssid": "AA:BB:CC:DD:EE:01", "ssid": "Open",
         "channel": "1", "power": "-65"},
        {"bssid": "AA:BB:CC:DD:EE:02", "ssid": "Far",
         "channel": "1", "power": "-75"},
    ]}
    res = r._signal_map()
    assert res["ok"] is True
    entries = {e["mac"]: e for e in res["data"]["entries"]}
    assert entries["EC:08:6B:11:22:33"]["confidence"] == "high"   # -45>=-55
    assert entries["AA:BB:CC:DD:EE:01"]["confidence"] == "med"    # -65 in [-70,-55)
    assert entries["AA:BB:CC:DD:EE:02"]["confidence"] == "low"    # -75<-70
    assert entries["EC:08:6B:11:22:33"]["distance_m"] > 0
    # total exposure = 10*log10(10^-4.5 + 10^-6.5 + 10^-7.5)
    import math
    expected = round(10 * math.log10(
        10 ** (-4.5) + 10 ** (-6.5) + 10 ** (-7.5)), 1)
    assert res["data"]["total_exposure_dbm"] == expected


def test_signal_map_no_aps_degrades():
    r = _recon()
    r.recon["clients"]["data"] = {"aps": []}
    with mock.patch.object(cr.shutil, "which", _which()):
        res = r._signal_map()
    assert res["ok"] is False


# ---------------------------------------------------------------------------
# Probe 4: handshake_harvest
# ---------------------------------------------------------------------------

def test_handshake_harvest_full_handshake_and_pmkid_feasible(tmp_path):
    r = _recon()
    pcap = str(tmp_path / "cap-01.cap")
    open(pcap, "w").close()
    r._fresh_airodump_pcap = lambda *, duration_s=15: pcap
    # EAPOL rows: fields sa\tda\teapol.type\tkey_type\tinstalled.
    # M1(ktype 0,inst ""), M2(ktype 1,inst 0), M3(ktype 1,inst 1),
    # M4(ktype 0,inst 1) -> complete 4-way. RSN AKM=1 (PSK).
    eapol = ("a\tb\t3\t0\t\n"      # M1
             "a\tb\t3\t1\t0\n"     # M2
             "a\tb\t3\t1\t1\n"     # M3
             "a\tb\t3\t0\t1\n")    # M4
    rsn = "1\tCCMP\n"
    calls = {"i": 0}
    canned = [eapol, rsn]

    def fake_tshark(args, timeout=15):
        i = calls["i"]; calls["i"] += 1
        return canned[i] if i < len(canned) else ""
    r._tshark = fake_tshark
    with mock.patch.object(cr.shutil, "which", _which("tshark")):
        res = r._handshake_harvest()
    assert res["ok"] is True
    assert res["data"]["eapol_frames"] == 4
    assert res["data"]["handshake_complete"] is True
    assert set(res["data"]["eapol_messages"]) == {"M1", "M2", "M3", "M4"}
    # vendor TP-Link + AKM PSK -> pmkid feasible.
    assert res["data"]["pmkid_feasible"] is True


def test_handshake_harvest_no_bssid():
    r = _recon(bssid="")
    res = r._handshake_harvest()
    assert res["ok"] is False
    assert "no bssid" in (res.get("error") or "")


# ---------------------------------------------------------------------------
# Probe 5: eapol_monitor
# ---------------------------------------------------------------------------

def test_eapol_monitor_detects_enterprise_peap(tmp_path):
    r = _recon()
    pcap = str(tmp_path / "cap-01.cap")
    open(pcap, "w").close()
    # Reuse a pcap path already in handshake_harvest data.
    r.recon["handshake_harvest"]["data"] = {"pcap": pcap}
    # eap rows: type 13 (PEAP) with an identity.
    r._tshark = lambda args, timeout=15: (
        "2\t13\talice@corp.local\tEC:08:6B:11:22:33\n"
        "1\t4\t\tEC:08:6B:11:22:33\n")
    with mock.patch.object(cr.shutil, "which", _which("tshark")):
        res = r._eapol_monitor()
    assert res["ok"] is True
    assert res["data"]["is_enterprise"] is True
    names = {m["name"] for m in res["data"]["eap_methods"]}
    assert "PEAP" in names
    assert "alice@corp.local" in res["data"]["eap_identities"]


def test_eapol_monitor_no_tshark(tmp_path):
    r = _recon()
    pcap = str(tmp_path / "cap-01.cap")
    open(pcap, "w").close()
    r.recon["handshake_harvest"]["data"] = {"pcap": pcap}
    with mock.patch.object(cr.shutil, "which", _which()):
        res = r._eapol_monitor()
    assert res["ok"] is False
    assert "tshark" in (res.get("error") or "")


# ---------------------------------------------------------------------------
# Probe 6: channel_plan
# ---------------------------------------------------------------------------

def test_channel_plan_hop_order_and_target_congestion(tmp_path):
    r = _recon()
    csv = _write_csv(tmp_path, _APS, _STATIONS)
    r._fresh_airodump_csv = lambda *, band="", duration_s=15: csv
    res = r._channel_plan()
    assert res["ok"] is True
    data = res["data"]
    chans = {c["channel"]: c for c in data["channels"]}
    assert "6" in chans and "1" in chans
    hop = data["recommended_hop_plan"]
    # Target channel (6) pinned first with dwell 10.
    assert hop[0]["channel"] == "6" and hop[0]["dwell_s"] == 10
    assert data["target_channel_congestion"] == chans["6"]["congestion"]


def test_channel_plan_no_aps_degrades(tmp_path):
    r = _recon()
    r._fresh_airodump_csv = lambda *, band="", duration_s=15: None
    res = r._channel_plan()
    assert res["ok"] is False


# ---------------------------------------------------------------------------
# Probe 7: deauth_detect
# ---------------------------------------------------------------------------

def test_deauth_detect_flood_and_evil_twin(tmp_path):
    r = _recon()
    # scapy is not installed in the venv -> ImportError -> tshark fallback.
    # 15 deauth frames + same SSID on two BSSIDs (evil twin).
    rows = []
    for _ in range(15):
        rows.append("EC:08:6B:11:22:33\tCorpNet\t0x000c\t11:22:33:44:55:66")
    rows.append("AA:BB:CC:DD:EE:99\tCorpNet\t0x000c\t22:22:33:44:55:66")
    r._tshark = lambda args, timeout=25: "\n".join(rows) + "\n"
    with mock.patch.object(cr.shutil, "which", _which("tshark")):
        res = r._deauth_detect()
    assert res["ok"] is True
    assert res["data"]["deauth_count"] == 16
    assert res["data"]["deauth_flood"] is True
    evil = res["data"]["evil_twin_candidates"]
    assert any(e["ssid"] == "CorpNet" and len(e["bssids"]) >= 2 for e in evil)


def test_deauth_detect_no_sniffer_degrades():
    r = _recon()
    with mock.patch.object(cr.shutil, "which", _which()):
        res = r._deauth_detect()
    assert res["ok"] is False
    assert "no frame sniffer" in (res.get("error") or "")


# ---------------------------------------------------------------------------
# Probe 8: gps_wardrive
# ---------------------------------------------------------------------------

def test_gps_wardrive_wigle_csv(tmp_path):
    r = _recon()
    r.outdir = tmp_path
    r.recon["clients"]["data"] = {"aps": [
        {"bssid": "EC:08:6B:11:22:33", "ssid": "TestNet",
         "privacy": "WPA2", "channel": "6", "power": "-45",
         "first_seen": "2026-07-15"},
    ]}
    with mock.patch.object(cr.shutil, "which", _which()):  # no gpspipe
        res = r._gps_wardrive()
    assert res["ok"] is True
    assert res["data"]["gps"]["fix"] == "no_gpsd"
    csv_path = res["data"]["wigle_csv"]
    assert csv_path and os.path.exists(csv_path)
    text = open(csv_path).read()
    assert "WigleWifi-1.4" in text
    assert "EC:08:6B:11:22:33" in text
    assert res["data"]["fused_targets"] == []


def test_gps_wardrive_offline_fusion(tmp_path):
    r = _recon()
    r.outdir = tmp_path
    # .22000 hash file: fields split on '*'; parts[3]=AP MAC, parts[5]=ssid hex.
    # Need >=6 parts. MAC is no-colon here; TSV uses colons -> tests the
    # normalization added to _fuse_wardrive_artifacts.
    ssid_hex = "TestNet".encode().hex()
    hfile = tmp_path / "hash.22000"
    hfile.write_text(
        f"WPA*02*aa*EC086B112233*EC086B112233*{ssid_hex}*tail\n")
    # TSV: timestamp\tsignal\tmac
    tsv = tmp_path / "sig.tsv"
    tsv.write_text("1000\t-42\tEC:08:6B:11:22:33\n")
    # GPX with one trkpt at t=1000.
    gpx = tmp_path / "track.gpx"
    gpx.write_text(
        '<?xml version="1.0"?><gpx><trk><trkseg>'
        '<trkpt lat="52.0" lon="21.0"><time>1970-01-01T00:16:40Z</time>'
        '</trkpt></trkseg></trk></gpx>')
    r.target["artifacts"] = {"h22000": str(hfile), "tsv": str(tsv),
                             "gpx": str(gpx)}
    with mock.patch.object(cr.shutil, "which", _which()):
        res = r._gps_wardrive()
    assert res["ok"] is True
    fused = res["data"]["fused_targets"]
    assert len(fused) == 1
    assert fused[0]["ssid"] == "TestNet"
    assert fused[0]["rssi"] == -42
    assert fused[0]["lat"] == 52.0
    assert fused[0]["lon"] == 21.0


def test_parse_gpx_bad_xml():
    assert CatalogRecon._parse_gpx("/no/such.gpx") == []


# ---------------------------------------------------------------------------
# Probe 9: beacon_parse
# ---------------------------------------------------------------------------

def test_beacon_parse_wpa3_sae_pmf(tmp_path):
    r = _recon()
    # akm=8 (SAE -> WPA3), gcs=4 (CCMP), pmf=1 (capable).
    beacon = "TestNet\tEC:08:6B:11:22:33\t4\t4\t8\t1\t6\n"
    wps_rows = "221\n"  # vendor-specific tag -> WPS
    calls = {"i": 0}
    canned = [beacon, wps_rows]

    def fake_tshark(args, timeout=15):
        i = calls["i"]; calls["i"] += 1
        return canned[i] if i < len(canned) else ""
    r._tshark = fake_tshark
    with mock.patch.object(cr.shutil, "which", _which("tshark")):
        res = r._beacon_parse()
    assert res["ok"] is True
    ap = res["data"]["ap"]
    assert ap["is_wpa3"] is True
    assert ap["group_cipher"] == "CCMP"
    assert ap["pmf"] == "capable"
    assert "SAE" in ap["akms"]
    assert ap["wps"] is True
    assert len(res["data"]["fingerprint_hash"]) == 12


def test_beacon_parse_no_bssid():
    r = _recon(bssid="")
    res = r._beacon_parse()
    assert res["ok"] is False
    assert "no bssid" in (res.get("error") or "")


def test_beacon_parse_no_tshark():
    r = _recon()
    with mock.patch.object(cr.shutil, "which", _which()):
        res = r._beacon_parse()
    assert res["ok"] is False
    assert "tshark" in (res.get("error") or "")


# ---------------------------------------------------------------------------
# Every probe degrades gracefully when its toolchain is entirely absent
# (never raises, returns {ok:false,error}).
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("method", list(CatalogRecon.RECON_PROBE_METHODS))
def test_every_probe_never_raises_without_tools(method):
    r = _recon()
    with mock.patch.object(cr.shutil, "which", _which()):
        res = r.run_probe(method)
    assert isinstance(res, dict)
    assert "ok" in res and "error" in res
    # With no tools and no prior capture, each is either ok=False (most)
    # or, for gps_wardrive, ok=True with an empty result. Both are valid
    # graceful outcomes — the contract is "never raise + envelope shape".
    assert res["ok"] in (False, True)