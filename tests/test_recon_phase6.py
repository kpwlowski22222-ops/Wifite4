"""Hermetic tests for the 10 new Phase 6 polymorphic +
target-adaptive recon methods in ``core/recon/runner.py``.
"""
import pytest

from core.recon.runner import ReconRunner, RECON_METHODS, RECONS


# ---------------------------------------------------------------------------
# Registry: 19 methods total = 9 originals + 10 Phase 6
# ---------------------------------------------------------------------------
def test_registry_count():
    assert len(RECON_METHODS) == 19
    assert len(RECONS) == 19
    assert {e["method"] for e in RECONS} == set(RECON_METHODS)


def test_phase6_methods_listed():
    expected = {
        "poly_mac_oui_substring_trie_tally",
        "adapt_bssid_oui_vendor_risk_tier",
        "poly_rssi_dbm_to_asuqc_normalize",
        "adapt_scan_window_channel_occupancy",
        "poly_arp_table_anomaly_detector",
        "adapt_dhcp_fingerprint_classifier",
        "poly_ssid_unicode_normalize",
        "adapt_nmap_nse_aggressive_chain",
        "poly_dns_query_timing_jitter",
        "adapt_target_protocol_fingerprint",
    }
    assert expected <= set(RECON_METHODS)


# ---------------------------------------------------------------------------
# Polymorphic
# ---------------------------------------------------------------------------
class TestPolyMacOuiSubstringTrieTally:
    def test_basic(self):
        r = ReconRunner({"macs": ["AA:BB:CC:11:22:33",
                                   "B0:BE:76:11:22:33"]})
        impl = getattr(r, "_poly_mac_oui_substring_trie_tally")
        res = impl({"macs": ["AA:BB:CC:11:22:33",
                             "B0:BE:76:11:22:33"]})
        assert res["ok"] is True
        assert res["data"]["scanned"] == 2
        assert isinstance(res["data"]["tally"], dict)


class TestPolyRssiDbmToAsuqcNormalize:
    def test_basic(self):
        r = ReconRunner({})
        impl = getattr(r, "_poly_rssi_dbm_to_asuqc_normalize")
        res = impl({"rssi": [-60, -55, -50, -45]})
        assert res["ok"] is True
        d = res["data"]
        assert d["count"] == 4
        assert d["apple_asu"][0] == 24  # (-60+100)*0.6
        # -60 -> "good" (threshold is -65)
        assert d["aruba_snr"][0] == "good"
        # -50 -> "excellent"
        assert d["aruba_snr"][2] == "excellent"

    def test_missing(self):
        # Empty input is honest-degrade to ok=True with empty
        # data — there's nothing to process, but no failure either.
        impl = ReconRunner({})._poly_rssi_dbm_to_asuqc_normalize
        res = impl({})
        assert res["ok"] is True
        assert res["data"]["count"] == 0

    def test_invalid(self):
        impl = ReconRunner({})._poly_rssi_dbm_to_asuqc_normalize
        res = impl({"rssi": ["not_a_number"]})
        assert res["ok"] is False


class TestPolyArpTableAnomalyDetector:
    def test_duplicate_ip(self):
        impl = ReconRunner({})._poly_arp_table_anomaly_detector
        res = impl({"arp": [
            {"ip": "10.0.0.1", "mac": "AA:BB:CC:11:22:33"},
            {"ip": "10.0.0.1", "mac": "DD:EE:FF:11:22:33"},
        ]})
        assert res["ok"] is True
        d = res["data"]
        assert d["anomaly_count"] == 1
        assert d["anomalies"][0]["type"] == "duplicate_ip_distinct_macs"

    def test_clean(self):
        impl = ReconRunner({})._poly_arp_table_anomaly_detector
        res = impl({"arp": [
            {"ip": "10.0.0.1", "mac": "AA:BB:CC:11:22:33"},
            {"ip": "10.0.0.2", "mac": "AA:BB:CC:11:22:33"},
        ]})
        assert res["ok"] is True
        assert res["data"]["anomaly_count"] == 0

    def test_missing(self):
        impl = ReconRunner({})._poly_arp_table_anomaly_detector
        res = impl({})
        assert res["ok"] is False


class TestPolySsidUnicodeNormalize:
    def test_cyrillic(self):
        impl = ReconRunner({})._poly_ssid_unicode_normalize
        # Cyrillic 'а' looks like Latin 'a'
        res = impl({"ssids": ["Cafe", "Cafе"]})
        assert res["ok"] is True
        d = res["data"]
        # At least one of them has a Cyrillic char
        assert any("has_cyrillic" in p["forms"] and p["forms"]["has_cyrillic"]
                   for p in d["per_ssid"])

    def test_ascii(self):
        impl = ReconRunner({})._poly_ssid_unicode_normalize
        res = impl({"ssids": ["HomeWiFi", "Guest5G"]})
        assert res["ok"] is True


class TestPolyDnsQueryTimingJitter:
    def test_stealth(self):
        impl = ReconRunner({})._poly_dns_query_timing_jitter
        res = impl({"profile": "stealth"})
        assert res["ok"] is True
        assert res["data"]["timing"]["max_rps"] == 5
        assert res["data"]["timing"]["max_concurrent"] == 1

    def test_aggressive(self):
        impl = ReconRunner({})._poly_dns_query_timing_jitter
        res = impl({"profile": "aggressive"})
        assert res["ok"] is True
        assert res["data"]["timing"]["max_rps"] == 200

    def test_default(self):
        impl = ReconRunner({})._poly_dns_query_timing_jitter
        res = impl({})
        assert res["ok"] is True
        assert res["data"]["profile"] == "default"


# ---------------------------------------------------------------------------
# Target-adaptive
# ---------------------------------------------------------------------------
class TestAdaptBssidOuiVendorRiskTier:
    def test_basic(self):
        impl = ReconRunner({})._adapt_bssid_oui_vendor_risk_tier
        res = impl({"bssids": ["B0:BE:76:11:22:33",
                                "AA:BB:CC:11:22:33"]})
        assert res["ok"] is True
        d = res["data"]
        assert d["scanned"] == 2
        # B0:BE:76 maps to TP-LINK
        tp = [p for p in d["per_bssid"]
              if p["bssid"] == "B0:BE:76:11:22:33"][0]
        assert tp["vendor"] == "TP-LINK"
        assert tp["tier"] == "consumer"

    def test_empty(self):
        impl = ReconRunner({})._adapt_bssid_oui_vendor_risk_tier
        res = impl({})
        assert res["ok"] is True
        assert res["data"]["scanned"] == 0


class TestAdaptScanWindowChannelOccupancy:
    def test_basic(self):
        impl = ReconRunner({})._adapt_scan_window_channel_occupancy
        res = impl({"observations": [
            {"channel": 1, "frame_type": "beacon"},
            {"channel": 1, "frame_type": "probe_req"},
            {"channel": 6, "frame_type": "beacon"},
        ]})
        assert res["ok"] is True
        d = res["data"]
        assert d["scan_window"] == 3
        assert d["ranking"][0]["channel"] == 1
        assert d["ranking"][0]["total"] == 2

    def test_missing(self):
        impl = ReconRunner({})._adapt_scan_window_channel_occupancy
        res = impl({})
        assert res["ok"] is False


class TestAdaptDhcpFingerprintClassifier:
    @pytest.mark.parametrize("options,expected", [
        ([1, 3, 6, 15], "windows"),
        ([1, 3, 6, 28], "linux"),
        ([1, 3, 6, 33], "macos"),
        ([1, 3, 6, 26], "android"),
        ([1, 3], "unknown"),
    ])
    def test_classify(self, options, expected):
        impl = ReconRunner({})._adapt_dhcp_fingerprint_classifier
        res = impl({"options": options})
        assert res["ok"] is True
        assert res["data"]["family"] == expected

    def test_missing(self):
        impl = ReconRunner({})._adapt_dhcp_fingerprint_classifier
        res = impl({})
        assert res["ok"] is False


class TestAdaptNmapNseAggressiveChain:
    @pytest.mark.parametrize("target_type,scripts", [
        ("web", ["http-title", "http-headers"]),
        ("mail", ["smtp-commands"]),
        ("db", ["ms-sql-info"]),
        ("windows", ["smb-vuln-ms17-010"]),
        ("unix", ["ssh-hostkey"]),
    ])
    def test_chain(self, target_type, scripts):
        impl = ReconRunner({})._adapt_nmap_nse_aggressive_chain
        res = impl({"target_type": target_type})
        assert res["ok"] is True
        assert res["data"]["script_count"] == 5
        for s in scripts:
            assert s in res["data"]["scripts"]


class TestAdaptTargetProtocolFingerprint:
    def test_web(self):
        impl = ReconRunner({})._adapt_target_protocol_fingerprint
        res = impl({"target_type": "web"})
        assert res["ok"] is True
        assert res["data"]["ports"] == [80, 443, 8080, 8443]

    def test_iot(self):
        impl = ReconRunner({})._adapt_target_protocol_fingerprint
        res = impl({"target_type": "iot"})
        assert res["ok"] is True
        assert 1883 in res["data"]["ports"]  # MQTT

    def test_default(self):
        impl = ReconRunner({})._adapt_target_protocol_fingerprint
        res = impl({})
        assert res["ok"] is True
        assert res["data"]["target_type"] == "generic"
