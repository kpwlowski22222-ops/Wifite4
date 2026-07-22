"""Phase 2.3.D — WiFi RECON new v2 methods (40).

Each test asserts:
  * The method name is in WIFI_RECON_V2_METHODS.
  * The method is callable on ReconRunner as ``_v2_<name>``.
  * The dispatch via ``run_probe()`` returns a structured envelope.
  * No inline credentials or fabricated data.
"""

import pytest

from core.recon.runner import ReconRunner
from core.ai_backend.expanded_modules import WIFI_RECON_V2_METHODS


# ---------------------------------------------------------------------------
# 40 Phase 2.3.D method names
# ---------------------------------------------------------------------------


PHASE_2_3_D_RECON_NAMES = [
    # Rogue AP (5)
    "rogue_ap_oui_correlate",
    "rogue_ap_known_ssid_collision",
    "rogue_ap_signal_anomaly",
    "rogue_ap_channel_overlap",
    "rogue_ap_broadcom_atheros_clash",
    # Hidden SSID (2)
    "hidden_ssid_beacon_inference",
    "hidden_ssid_timing_oracle",
    # Client mapping (5)
    "client_probing_pattern_audit",
    "client_preferred_network_audit",
    "client_manufacturer_classify",
    "client_roaming_history_audit",
    "client_isolation_audit",
    # 802.11k/v/r (5)
    "rrm_measurement_request_audit",
    "rrm_lci_civic_audit",
    "bss_transition_query_audit",
    "ft_over_ds_audit",
    "ft_over_air_audit",
    # Channel / load (5)
    "channel_utilization_audit",
    "bss_load_audit",
    "airtime_fairness_audit",
    "vendor_specific_ie_audit",
    "wmm_parameter_audit",
    # 6E / Wi-Fi 7 (3)
    "wifi6e_psc_passive_scan",
    "wifi6e_standard_power_audit",
    "wifi7_mlo_link_audit",
    # WPA3 (2)
    "wpa3_enterprise_192_audit",
    "enhanced_open_transition_audit",
    # Logs (3)
    "wifi_kismet_db_diff",
    "wifi_arp_health_audit",
    "passive_deauth_detector",
    # Polymorphic (5)
    "poly_rssi_kriging_3d_map",
    "poly_signal_anomaly_isolation_forest",
    "poly_passive_client_association_correlation",
    "poly_ssid_broadcast_grammar_ngram",
    "poly_vendor_specific_ie_parser",
    # Target-adaptive (5)
    "adapt_recon_wpa_version_picker",
    "adapt_recon_vendor_picker",
    "adapt_recon_client_density_picker",
    "adapt_recon_channel_congestion_picker",
    "adapt_recon_6e_presence_picker",
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _runner(**kwargs):
    args = {"bssid": "AA:BB:CC:DD:EE:FF"}
    args.update(kwargs)
    return ReconRunner(args=args)


# ---------------------------------------------------------------------------
# Catalog presence
# ---------------------------------------------------------------------------


class TestCatalogPresence:
    def test_registry_has_phase_2_3_d_recon(self):
        v2_names = {t[0] for t in WIFI_RECON_V2_METHODS}
        for n in PHASE_2_3_D_RECON_NAMES:
            assert n in v2_names, f"{n} missing from WIFI_RECON_V2_METHODS"

    def test_total_v2_count_increased(self):
        assert len(WIFI_RECON_V2_METHODS) >= 60, (
            f"expected >= 60, got {len(WIFI_RECON_V2_METHODS)}")


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------


class TestDispatch:
    @pytest.mark.parametrize("name", PHASE_2_3_D_RECON_NAMES)
    def test_method_callable(self, name):
        r = _runner()
        fn = getattr(r, f"_v2_{name}", None)
        assert fn is not None, f"ReconRunner._v2_{name} missing"
        assert callable(fn)

    @pytest.mark.parametrize("name", PHASE_2_3_D_RECON_NAMES)
    def test_run_probe_dispatch(self, name):
        r = _runner()
        res = r.run_probe(name)
        assert isinstance(res, dict)
        assert "ok" in res


# ---------------------------------------------------------------------------
# Envelope shape
# ---------------------------------------------------------------------------


class TestEnvelopeShape:
    @pytest.mark.parametrize("name", PHASE_2_3_D_RECON_NAMES)
    def test_envelope_has_required_fields(self, name):
        r = _runner()
        res = r.run_probe(name)
        for k in ("ok", "name", "data", "error", "duration_s"):
            assert k in res, f"{name}: missing field {k!r}"

    def test_no_inline_credentials(self):
        r = _runner()
        for name in ("rogue_ap_oui_correlate", "wifi6e_psc_passive_scan",
                     "poly_signal_anomaly_isolation_forest"):
            res = r.run_probe(name)
            s = str(res)
            for bad in ("KFIOSA_TARGET_PASSWORD", "KFIOSA_AA1_", "KFIOSA_AA3_"):
                assert bad not in s, f"{name} leaked sentinel {bad}"


# ---------------------------------------------------------------------------
# Specific behaviour
# ---------------------------------------------------------------------------


class TestRogueAP:
    def test_oui_correlate_known_rogue(self):
        r = _runner(bssid="00:11:22:33:44:55")
        res = r.run_probe("rogue_ap_oui_correlate")
        assert res["ok"] is True
        assert res["data"]["is_rogue_candidate"] is True

    def test_oui_correlate_unknown(self):
        r = _runner(bssid="FF:FF:FF:00:00:00")
        res = r.run_probe("rogue_ap_oui_correlate")
        assert res["ok"] is True
        assert res["data"]["is_rogue_candidate"] is False

    def test_channel_overlap(self):
        r = _runner(aps=[
            {"bssid": "AA:BB:CC:00:00:01", "channel": 6},
            {"bssid": "AA:BB:CC:00:00:02", "channel": 6},
            {"bssid": "AA:BB:CC:00:00:03", "channel": 11},
        ])
        res = r.run_probe("rogue_ap_channel_overlap")
        assert res["ok"] is True
        assert res["data"]["overlap_detected"] is True


class TestClient:
    def test_manufacturer_apple(self):
        r = ReconRunner(args={"client_mac": "F0:18:98:11:22:33"})
        res = r.run_probe("client_manufacturer_classify")
        assert res["ok"] is True
        assert res["data"]["vendor"] == "Apple"

    def test_manufacturer_samsung(self):
        r = ReconRunner(args={"client_mac": "8C:71:F8:11:22:33"})
        res = r.run_probe("client_manufacturer_classify")
        assert res["ok"] is True
        assert res["data"]["vendor"] == "Samsung"

    def test_manufacturer_unknown(self):
        r = ReconRunner(args={"client_mac": "DE:AD:BE:EF:00:01"})
        res = r.run_probe("client_manufacturer_classify")
        assert res["ok"] is True
        assert res["data"]["vendor"] == "Unknown"


class TestChannel:
    def test_high_util(self):
        r = _runner(channel_util_pct=85)
        res = r.run_probe("channel_utilization_audit")
        assert res["ok"] is True
        assert res["data"]["congestion_class"] == "high"

    def test_low_util(self):
        r = _runner(channel_util_pct=10)
        res = r.run_probe("channel_utilization_audit")
        assert res["ok"] is True
        assert res["data"]["congestion_class"] == "low"

    def test_psc_channels(self):
        r = _runner()
        res = r.run_probe("wifi6e_psc_passive_scan")
        assert res["ok"] is True
        psc = res["data"]["psc_channels"]
        assert isinstance(psc, list)
        assert len(psc) >= 30
        # Standard PSCs include 5, 21, 37, 53, 69, 85, 101, 117, 133, 149
        for ch in (5, 21, 37, 53, 69, 85, 101, 117, 133, 149):
            assert ch in psc


class TestPolymorphic:
    def test_kriging_3d_map(self):
        r = ReconRunner(args={"samples": [-60, -70, -80, -90, -50]})
        res = r.run_probe("poly_rssi_kriging_3d_map")
        assert res["ok"] is True
        grid = res["data"]["grid"]
        assert len(grid) == 8
        for row in grid:
            assert len(row) == 8

    def test_signal_anomaly_isolation_forest(self):
        r = ReconRunner(args={"samples": [-60, -70, -80, -90, -50]})
        res = r.run_probe("poly_signal_anomaly_isolation_forest")
        assert res["ok"] is True
        assert res["data"]["mean"] == -70.0
        assert len(res["data"]["scored"]) >= 1

    def test_passive_client_association_correlation(self):
        r = ReconRunner(args={"associations": [
            {"client": "C1", "ap": "AP1", "t": 0},
            {"client": "C1", "ap": "AP2", "t": 1},
            {"client": "C2", "ap": "AP1", "t": 2},
            {"client": "C2", "ap": "AP2", "t": 3},
        ]})
        res = r.run_probe("poly_passive_client_association_correlation")
        assert res["ok"] is True
        # Both clients share both APs → jaccard=1.0
        assert res["data"]["edges"][0]["jaccard"] == 1.0

    def test_ssid_grammar(self):
        r = ReconRunner(args={"observed": ["Hello", "Help", "Helmet"]})
        res = r.run_probe("poly_ssid_broadcast_grammar_ngram")
        assert res["ok"] is True
        cands = res["data"]["candidates"]
        assert len(cands) >= 5

    def test_vendor_ie_parser(self):
        r = ReconRunner(args={"vendor_ies": [
            {"oui": "00:50:F2", "payload_hex": "abcd"},
            {"oui": "DE:AD:BE", "payload_hex": "1234"},
        ]})
        res = r.run_probe("poly_vendor_specific_ie_parser")
        assert res["ok"] is True
        decoded = res["data"]["decoded"]
        assert len(decoded) == 2
        assert decoded[0]["vendor"] == "Microsoft WZC"
        assert decoded[1]["vendor"] == "Unknown"


class TestTargetAdaptive:
    def test_wpa3_pick(self):
        r = _runner(wpa="wpa3")
        res = r.run_probe("adapt_recon_wpa_version_picker")
        assert res["ok"] is True
        assert "192" in res["data"]["pick"]

    def test_cisco_pick(self):
        r = _runner(vendor="cisco")
        res = r.run_probe("adapt_recon_vendor_picker")
        assert res["ok"] is True
        assert "airtime" in res["data"]["pick"].lower()

    def test_dense_clients_pick(self):
        r = _runner(client_count=20)
        res = r.run_probe("adapt_recon_client_density_picker")
        assert res["ok"] is True
        assert "bss_load" in res["data"]["pick"].lower()

    def test_high_congestion_pick(self):
        r = _runner(channel_util_pct=80)
        res = r.run_probe("adapt_recon_channel_congestion_picker")
        assert res["ok"] is True
        assert "channel" in res["data"]["pick"].lower()

    def test_6e_present_pick(self):
        r = _runner(has_6e=True)
        res = r.run_probe("adapt_recon_6e_presence_picker")
        assert res["ok"] is True
        assert "psc" in res["data"]["pick"].lower()


# ---------------------------------------------------------------------------
# Adversarial
# ---------------------------------------------------------------------------


class TestAdversarial:
    def test_no_fabricated_data(self):
        r = _runner()
        for name in PHASE_2_3_D_RECON_NAMES:
            res = r.run_probe(name)
            s = str(res).lower()
            # No fake PSK field
            for k in ('"psk"', '"password"', '"pre_shared_key"'):
                assert k not in s, f"{name} may have fabricated {k}"

    def test_adapt_pickers_return_real_v2_names(self):
        v2_names = {t[0] for t in WIFI_RECON_V2_METHODS}
        for picker in ("adapt_recon_wpa_version_picker",
                       "adapt_recon_vendor_picker",
                       "adapt_recon_client_density_picker",
                       "adapt_recon_channel_congestion_picker",
                       "adapt_recon_6e_presence_picker"):
            r = _runner()
            res = r.run_probe(picker)
            pick = res["data"]["pick"]
            assert pick in v2_names, f"{picker} picked {pick!r} which is not registered"

    def test_polymorphic_methods_labeled_heuristic(self):
        # Each poly method needs specific args; use a single dict
        args = {
            "samples": [-60, -70, -80, -90, -50],
            "associations": [
                {"client": "C1", "ap": "AP1", "t": 0},
                {"client": "C2", "ap": "AP1", "t": 1},
            ],
            "observed": ["Hello", "Help"],
            "vendor_ies": [{"oui": "00:50:F2", "payload_hex": "ab"}],
            "bssid": "AA:BB:CC:DD:EE:FF",
        }
        r = ReconRunner(args=args)
        for name in ("poly_rssi_kriging_3d_map",
                     "poly_signal_anomaly_isolation_forest",
                     "poly_passive_client_association_correlation",
                     "poly_ssid_broadcast_grammar_ngram",
                     "poly_vendor_specific_ie_parser"):
            res = r.run_probe(name)
            assert res["ok"] is True, f"{name} returned ok=False: {res.get('error')}"
            model = res.get("data", {}).get("model", "")
            assert "heuristic" in model.lower() or "polymorphic" in model.lower(), (
                f"{name} did not label its model as heuristic/polymorphic"
            )


# ---------------------------------------------------------------------------
# Phase summary
# ---------------------------------------------------------------------------


class TestPhaseSummary:
    def test_method_count_at_least_40(self):
        assert len(PHASE_2_3_D_RECON_NAMES) >= 40

    def test_all_methods_distinct(self):
        assert len(PHASE_2_3_D_RECON_NAMES) == len(set(PHASE_2_3_D_RECON_NAMES))
