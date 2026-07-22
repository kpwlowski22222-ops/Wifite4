"""Phase 2.3.E — BLE RECON new v2 methods (40)."""

import pytest

from core.ble.runner import BLEProbeRunner
from core.ai_backend.expanded_modules import BLE_RECON_V2_METHODS


# ---------------------------------------------------------------------------
# 40 Phase 2.3.E method names
# ---------------------------------------------------------------------------


PHASE_2_3_E_BLE_RECON_NAMES = [
    # Discovery / classification (5)
    "ble_appearance_classify",
    "ble_company_id_audit",
    "ble_service_uuid_distribution_audit",
    "ble_local_name_vendor_map",
    "ble_classic_br_edr_passive_scan",
    # RPA / address (5)
    "ble_rpa_resolve_passive",
    "ble_address_age_estimate",
    "ble_address_churn_rate_audit",
    "ble_mac_randomization_efficacy_audit",
    "ble_location_privacy_audit",
    # Sensor / health (5)
    "ble_health_thermometer_audit",
    "ble_heart_rate_audit",
    "ble_environmental_sensor_audit",
    "ble_pulse_oximeter_audit",
    "ble_glucose_meter_audit",
    # Mesh / LE Audio (5)
    "ble_mesh_proxy_discover",
    "ble_audio_bis_discover",
    "ble_mesh_friend_node_graph",
    "ble_mesh_subnet_collision",
    "ble_mesh_iv_update_state_track",
    # Identity / privacy (5)
    "ble_user_identity_leak_audit",
    "ble_owner_name_audit",
    "ble_apple_findmy_audit",
    "ble_google_fast_pair_audit",
    "ble_microsoft_swift_pair_audit",
    # Presence / behaviour (5)
    "ble_presence_classify",
    "ble_movement_pattern_classify",
    "ble_workday_audit",
    "ble_proximity_log_audit",
    "ble_dwell_time_audit",
    # Polymorphic (5)
    "poly_ble_advertising_payload_normalize",
    "poly_ble_rpa_seed_timing_profiler",
    "poly_ble_gatt_characteristic_hash",
    "poly_ble_mesh_proxy_filter_parser",
    "poly_ble_mac_rotation_fingerprint_grammar",
    # Target-adaptive (5)
    "adapt_recon_target_os_picker",
    "adapt_recon_target_role_picker",
    "adapt_recon_target_service_picker",
    "adapt_recon_target_version_picker",
    "adapt_recon_target_capability_picker",
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _runner(**kwargs):
    args = {"address": "AA:BB:CC:DD:EE:FF"}
    args.update(kwargs)
    return BLEProbeRunner(adapter="hci0", args=args)


# ---------------------------------------------------------------------------
# Catalog presence
# ---------------------------------------------------------------------------


class TestCatalogPresence:
    def test_registry_has_phase_2_3_e_recon(self):
        v2_names = {t[0] for t in BLE_RECON_V2_METHODS}
        for n in PHASE_2_3_E_BLE_RECON_NAMES:
            assert n in v2_names, f"{n} missing from BLE_RECON_V2_METHODS"

    def test_total_v2_count_increased(self):
        assert len(BLE_RECON_V2_METHODS) >= 60, (
            f"expected >= 60, got {len(BLE_RECON_V2_METHODS)}")


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------


class TestDispatch:
    @pytest.mark.parametrize("name", PHASE_2_3_E_BLE_RECON_NAMES)
    def test_method_callable(self, name):
        r = _runner()
        fn = getattr(r, f"_v2_{name}", None)
        assert fn is not None, f"BLEProbeRunner._v2_{name} missing"
        assert callable(fn)

    @pytest.mark.parametrize("name", PHASE_2_3_E_BLE_RECON_NAMES)
    def test_run_probe_dispatch(self, name):
        r = _runner()
        res = r.run_probe(name)
        assert isinstance(res, dict)
        assert "ok" in res


# ---------------------------------------------------------------------------
# Envelope shape
# ---------------------------------------------------------------------------


class TestEnvelopeShape:
    @pytest.mark.parametrize("name", PHASE_2_3_E_BLE_RECON_NAMES)
    def test_envelope_has_required_fields(self, name):
        r = _runner()
        res = r.run_probe(name)
        for k in ("ok", "name", "data", "error", "duration_s"):
            assert k in res, f"{name}: missing field {k!r}"

    def test_no_inline_credentials(self):
        r = _runner()
        for name in ("poly_ble_advertising_payload_normalize",
                     "poly_ble_gatt_characteristic_hash",
                     "ble_apple_findmy_audit"):
            res = r.run_probe(name)
            s = str(res)
            for bad in ("KFIOSA_TARGET_PASSWORD", "KFIOSA_AA1_", "KFIOSA_AA3_"):
                assert bad not in s, f"{name} leaked sentinel {bad}"


# ---------------------------------------------------------------------------
# Specific behaviour
# ---------------------------------------------------------------------------


class TestClassification:
    def test_appearance_classify_phone(self):
        r = _runner(appearance=64)
        res = r.run_probe("ble_appearance_classify")
        assert res["ok"] is True
        assert res["data"]["category"][1] == "Phone"

    def test_appearance_classify_watch(self):
        r = _runner(appearance=192)
        res = r.run_probe("ble_appearance_classify")
        assert res["ok"] is True
        assert res["data"]["category"][1] == "Watch"

    def test_company_id_apple(self):
        r = _runner(company_id=0x004C)
        res = r.run_probe("ble_company_id_audit")
        assert res["ok"] is True
        assert "Apple" in res["data"]["vendor"]

    def test_company_id_unknown(self):
        r = _runner(company_id=0xFFFF)
        res = r.run_probe("ble_company_id_audit")
        assert res["ok"] is True
        assert res["data"]["vendor"] == "Unknown"

    def test_local_name_tile(self):
        r = _runner(local_name="Tile-12345")
        res = r.run_probe("ble_local_name_vendor_map")
        assert res["ok"] is True
        assert res["data"]["vendor"] == "Tile"

    def test_local_name_airtag(self):
        r = _runner(local_name="AirTag-ABC")
        res = r.run_probe("ble_local_name_vendor_map")
        assert res["ok"] is True
        assert res["data"]["vendor"] == "Apple"

    def test_service_uuid_distribution(self):
        r = _runner(service_uuids=["180D", "180D", "180F", "180A"])
        res = r.run_probe("ble_service_uuid_distribution_audit")
        assert res["ok"] is True
        top = res["data"]["top_5"]
        assert top[0][0] == "180d"
        assert top[0][1] == 2


class TestAddressHygiene:
    def test_rpa_resolve(self):
        r = _runner(address="AA:40:11:22:33:44")  # bit 1 of byte 1 set
        res = r.run_probe("ble_rpa_resolve_passive")
        assert res["ok"] is True
        assert res["data"]["is_rpa"] is True

    def test_rpa_resolve_static(self):
        r = _runner(address="AA:00:11:22:33:44")
        res = r.run_probe("ble_rpa_resolve_passive")
        assert res["ok"] is True
        assert res["data"]["is_rpa"] is False

    def test_address_churn_high(self):
        r = _runner(sightings=[
            {"address": f"AA:BB:CC:00:00:{i:02X}", "t": i} for i in range(10)
        ])
        res = r.run_probe("ble_address_churn_rate_audit")
        assert res["ok"] is True
        assert res["data"]["churn_rate"] == 1.0  # all unique

    def test_address_churn_zero(self):
        r = _runner(sightings=[
            {"address": "AA:BB:CC:00:00:01", "t": i} for i in range(10)
        ])
        res = r.run_probe("ble_address_churn_rate_audit")
        assert res["ok"] is True
        assert res["data"]["churn_rate"] == 0.1

    def test_mac_randomization_efficacy(self):
        r = _runner(sightings=[
            {"address": f"AA:BB:CC:00:00:{i:02X}", "t": i} for i in range(10)
        ])
        res = r.run_probe("ble_mac_randomization_efficacy_audit")
        assert res["ok"] is True
        assert res["data"]["mac_randomization_efficacy"] == 0.0  # all unique = 0 efficacy


class TestPresence:
    def test_presence_stable(self):
        r = _runner(rssi_samples=[-60, -61, -60, -59, -60])
        res = r.run_probe("ble_presence_classify")
        assert res["ok"] is True
        assert res["data"]["presence_class"] == "stable"

    def test_presence_mobile(self):
        r = _runner(rssi_samples=[-60, -90, -50, -85, -55])
        res = r.run_probe("ble_presence_classify")
        assert res["ok"] is True
        assert res["data"]["presence_class"] == "mobile"

    def test_movement_stationary(self):
        r = _runner(rssi_series=[-60, -60, -60, -61, -60])
        res = r.run_probe("ble_movement_pattern_classify")
        assert res["ok"] is True
        assert res["data"]["movement_pattern"] == "stationary"

    def test_movement_walking(self):
        r = _runner(rssi_series=[-60, -65, -62, -68, -65, -70])
        res = r.run_probe("ble_movement_pattern_classify")
        assert res["ok"] is True
        assert res["data"]["movement_pattern"] in ("walking", "running")

    def test_dwell_time(self):
        r = _runner(sightings=[
            {"address": "AA:BB:CC:00:00:01", "t": 100},
            {"address": "AA:BB:CC:00:00:01", "t": 200},
            {"address": "AA:BB:CC:00:00:01", "t": 350},
        ])
        res = r.run_probe("ble_dwell_time_audit")
        assert res["ok"] is True
        assert res["data"]["dwell_time_s"] == 250


class TestPolymorphic:
    def test_advertising_payload_normalize(self):
        r = _runner(payloads=["AB CD EF", "010203"])
        res = r.run_probe("poly_ble_advertising_payload_normalize")
        assert res["ok"] is True
        norm = res["data"]["normalized"]
        assert len(norm) == 2

    def test_rpa_seed_timing(self):
        r = _runner()
        res = r.run_probe("poly_ble_rpa_seed_timing_profiler")
        assert res["ok"] is True
        ivs = res["data"]["intervals_s"]
        assert len(ivs) == 16
        for v in ivs:
            assert 60 <= v <= 900

    def test_gatt_characteristic_hash(self):
        r = _runner(uuids=["180D", "180F"])
        res = r.run_probe("poly_ble_gatt_characteristic_hash")
        assert res["ok"] is True
        h = res["data"]["hashes"]
        assert "180d" in h
        assert "180f" in h
        assert h["180d"] != h["180f"]
        assert len(h["180d"]) == 16

    def test_mesh_proxy_filter(self):
        r = _runner(proxy_pdu_hex="40 01 00 00 00")
        res = r.run_probe("poly_ble_mesh_proxy_filter_parser")
        assert res["ok"] is True
        assert res["data"]["msg_type"] == 0

    def test_mac_rotation_fingerprint(self):
        r = _runner(observations=[
            "AA:BB:CC:00:00:01", "AA:BB:CC:00:00:02", "AA:BB:CC:00:00:03"
        ])
        res = r.run_probe("poly_ble_mac_rotation_fingerprint_grammar")
        assert res["ok"] is True
        assert len(res["data"]["fingerprint"]) == 8


class TestTargetAdaptive:
    def test_ios_pick(self):
        r = _runner(os="ios")
        res = r.run_probe("adapt_recon_target_os_picker")
        assert res["ok"] is True
        assert "findmy" in res["data"]["pick"].lower()

    def test_android_pick(self):
        r = _runner(os="android")
        res = r.run_probe("adapt_recon_target_os_picker")
        assert res["ok"] is True
        assert "fast_pair" in res["data"]["pick"].lower()

    def test_windows_pick(self):
        r = _runner(os="windows")
        res = r.run_probe("adapt_recon_target_os_picker")
        assert res["ok"] is True
        assert "swift" in res["data"]["pick"].lower()

    def test_tracker_role_pick(self):
        r = _runner(role="tracker")
        res = r.run_probe("adapt_recon_target_role_picker")
        assert res["ok"] is True
        assert "findmy" in res["data"]["pick"].lower()

    def test_wearable_role_pick(self):
        r = _runner(role="wearable")
        res = r.run_probe("adapt_recon_target_role_picker")
        assert res["ok"] is True
        assert "heart" in res["data"]["pick"].lower()

    def test_heart_rate_service_pick(self):
        r = _runner(service_uuids=["180D"])
        res = r.run_probe("adapt_recon_target_service_picker")
        assert res["ok"] is True
        assert "heart_rate" in res["data"]["pick"]

    def test_ble_5_4_pick(self):
        r = _runner(ble_version="5.4")
        res = r.run_probe("adapt_recon_target_version_picker")
        assert res["ok"] is True
        assert "audio" in res["data"]["pick"].lower() or "bis" in res["data"]["pick"].lower()

    def test_mesh_capability_pick(self):
        r = _runner(capabilities=["mesh"])
        res = r.run_probe("adapt_recon_target_capability_picker")
        assert res["ok"] is True
        assert "mesh" in res["data"]["pick"].lower()


# ---------------------------------------------------------------------------
# Adversarial
# ---------------------------------------------------------------------------


class TestAdversarial:
    def test_no_fabricated_data(self):
        r = _runner()
        for name in PHASE_2_3_E_BLE_RECON_NAMES:
            res = r.run_probe(name)
            s = str(res).lower()
            for k in ('"psk"', '"pin"', '"password"', '"pre_shared_key"'):
                assert k not in s, f"{name} may have fabricated {k}"

    def test_polymorphic_methods_labeled_heuristic(self):
        r = _runner(payloads=["ABCD"], uuids=["180D"], observations=["x"])
        for name in ("poly_ble_advertising_payload_normalize",
                     "poly_ble_rpa_seed_timing_profiler",
                     "poly_ble_gatt_characteristic_hash",
                     "poly_ble_mac_rotation_fingerprint_grammar"):
            res = r.run_probe(name)
            model = res.get("data", {}).get("model", "")
            assert "heuristic" in model.lower() or "polymorphic" in model.lower(), (
                f"{name} did not label its model as heuristic/polymorphic"
            )

    def test_adapt_pickers_return_real_v2_names(self):
        v2_names = {t[0] for t in BLE_RECON_V2_METHODS}
        for picker in ("adapt_recon_target_os_picker",
                       "adapt_recon_target_role_picker",
                       "adapt_recon_target_service_picker",
                       "adapt_recon_target_version_picker",
                       "adapt_recon_target_capability_picker"):
            r = _runner()
            res = r.run_probe(picker)
            pick = res["data"]["pick"]
            assert pick in v2_names, f"{picker} picked {pick!r} which is not registered"


# ---------------------------------------------------------------------------
# Phase summary
# ---------------------------------------------------------------------------


class TestPhaseSummary:
    def test_method_count_at_least_40(self):
        assert len(PHASE_2_3_E_BLE_RECON_NAMES) >= 40

    def test_all_methods_distinct(self):
        assert len(PHASE_2_3_E_BLE_RECON_NAMES) == len(set(PHASE_2_3_E_BLE_RECON_NAMES))
