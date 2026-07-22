"""Phase 2.3.E — BLE ATTACK new v2 methods (40)."""

import pytest

from core.ble.attack_runner import BLEAttackRunner
from core.ai_backend.expanded_modules import BLE_V2_METHODS


# ---------------------------------------------------------------------------
# 40 Phase 2.3.E method names
# ---------------------------------------------------------------------------


PHASE_2_3_E_BLE_ATTACK_NAMES = [
    # GATT (5)
    "gatt_descriptor_write_priv_escalation",
    "gatt_long_read_oom_trigger",
    "gatt_indication_flood",
    "gatt_write_without_response_race",
    "gatt_subscribed_notification_flood",
    # Pairing / bonding (5)
    "legacy_pairing_tkip_recovery",
    "just_works_mitm_passkey_substitution",
    "oob_data_replay_capture",
    "cross_transport_irk_collision",
    "repairing_passkey_predict",
    # L2CAP / connection (5)
    "l2cap_lecb_channel_dos",
    "l2cap_credit_based_fuzz",
    "l2cap_enhanced_retransmission_fuzz",
    "l2cap_le_flow_control_psm_bypass",
    "connection_interval_overflow",
    # LE Audio / Isochronous (5)
    "iso_channel_cis_dos",
    "biginfo_sdu_interval_misconfig",
    "lc3_codec_param_fuzz",
    "bap_unicast_server_discover_flood",
    "pawr_response_suboverflow",
    # Mesh / PAwR (5)
    "mesh_provisioning_capture_replay",
    "mesh_friend_queue_overflow",
    "mesh_proxy_solicitation_flood",
    "mesh_low_power_friend_dos",
    "mesh_subnet_bridge_substitution",
    # Polymorphic (5)
    "poly_gatt_payload_template",
    "poly_hid_injection_sequence_ai",
    "poly_ota_firmware_chunk_drift",
    "poly_pairing_payload_grammar",
    "poly_le_audio_bap_param_drift",
    # Target-adaptive (5)
    "adapt_attack_pairing_method_picker",
    "adapt_attack_os_target_picker",
    "adapt_attack_ble_version_picker",
    "adapt_attack_service_uuid_picker",
    "adapt_attack_capability_picker",
    # Read-only / orchestrator (5)
    "gatt_long_write_fuzz",
    "gatt_prepare_write_abuse",
    "gatt_notification_flood",
    "ble_lesc_passkey_replay",
    "ble_attack_orchestrator",
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _runner(**kwargs):
    args = {"address": "AA:BB:CC:DD:EE:FF"}
    args.update(kwargs)
    return BLEAttackRunner(adapter="hci0", args=args)


# ---------------------------------------------------------------------------
# Catalog presence
# ---------------------------------------------------------------------------


class TestCatalogPresence:
    def test_registry_has_phase_2_3_e(self):
        v2_names = {t[0] for t in BLE_V2_METHODS}
        for n in PHASE_2_3_E_BLE_ATTACK_NAMES:
            assert n in v2_names, f"{n} missing from BLE_V2_METHODS"

    def test_total_v2_count_increased(self):
        assert len(BLE_V2_METHODS) >= 60, (
            f"expected >= 60, got {len(BLE_V2_METHODS)}")


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------


class TestDispatch:
    @pytest.mark.parametrize("name", PHASE_2_3_E_BLE_ATTACK_NAMES)
    def test_method_callable(self, name):
        r = _runner()
        fn = getattr(r, f"_v2_{name}", None)
        assert fn is not None, f"BLEAttackRunner._v2_{name} missing"
        assert callable(fn)

    @pytest.mark.parametrize("name", PHASE_2_3_E_BLE_ATTACK_NAMES)
    def test_run_attack_dispatch(self, name):
        r = _runner()
        res = r.run_attack(name)
        assert isinstance(res, dict)
        assert "ok" in res


# ---------------------------------------------------------------------------
# Envelope shape
# ---------------------------------------------------------------------------


class TestEnvelopeShape:
    @pytest.mark.parametrize("name", PHASE_2_3_E_BLE_ATTACK_NAMES)
    def test_envelope_has_required_fields(self, name):
        r = _runner()
        res = r.run_attack(name)
        for k in ("ok", "name", "data", "error", "duration_s"):
            assert k in res, f"{name}: missing field {k!r}"

    def test_no_inline_credentials(self):
        r = _runner()
        for name in ("poly_pairing_payload_grammar",
                     "poly_gatt_payload_template",
                     "poly_hid_injection_sequence_ai"):
            res = r.run_attack(name)
            s = str(res)
            for bad in ("KFIOSA_TARGET_PASSWORD", "KFIOSA_AA1_", "KFIOSA_AA3_"):
                assert bad not in s, f"{name} leaked sentinel {bad}"


# ---------------------------------------------------------------------------
# Specific behaviour
# ---------------------------------------------------------------------------


class TestPolymorphic:
    def test_gatt_payload_template(self):
        r = _runner(uuid="180F")
        res = r.run_attack("poly_gatt_payload_template")
        assert res["ok"] is True
        ts = res["data"]["templates"]
        assert len(ts) == 8
        for t in ts:
            assert t["uuid"] == "180F"
            assert 4 <= t["length"] <= 64

    def test_hid_injection_sequence(self):
        r = _runner()
        res = r.run_attack("poly_hid_injection_sequence_ai")
        assert res["ok"] is True
        seqs = res["data"]["sequences"]
        assert len(seqs) == 8
        for s in seqs:
            assert len(s) == 8

    def test_ota_firmware_chunk_drift(self):
        r = _runner(chunk_size=256, n_chunks=4)
        res = r.run_attack("poly_ota_firmware_chunk_drift")
        assert res["ok"] is True
        chunks = res["data"]["chunks"]
        assert len(chunks) == 4
        assert chunks[0]["offset"] == 0
        assert chunks[1]["offset"] == 256

    def test_pairing_passkey_grammar(self):
        r = _runner()
        res = r.run_attack("poly_pairing_payload_grammar")
        assert res["ok"] is True
        cands = res["data"]["candidates"]
        assert len(cands) == 8
        for c in cands:
            assert len(c) == 6
            assert c.isdigit()

    def test_bap_param_drift(self):
        r = _runner()
        res = r.run_attack("poly_le_audio_bap_param_drift")
        assert res["ok"] is True
        variants = res["data"]["variants"]
        assert len(variants) == 8
        for v in variants:
            assert v["sample_rate_hz"] in (8000, 16000, 24000, 32000, 44100, 48000)
            assert v["frame_duration_us"] in (7500, 10000)


class TestTargetAdaptive:
    def test_legacy_pairing_pick(self):
        r = _runner(pairing_method="legacy")
        res = r.run_attack("adapt_attack_pairing_method_picker")
        assert res["ok"] is True
        assert "legacy" in res["data"]["pick"].lower()

    def test_just_works_pick(self):
        r = _runner(pairing_method="just_works")
        res = r.run_attack("adapt_attack_pairing_method_picker")
        assert res["ok"] is True
        assert "just_works" in res["data"]["pick"].lower()

    def test_ios_pick(self):
        r = _runner(os="ios")
        res = r.run_attack("adapt_attack_os_target_picker")
        assert res["ok"] is True
        assert "indication" in res["data"]["pick"].lower() or "vendor" in res["data"]["pick"].lower()

    def test_android_pick(self):
        r = _runner(os="android")
        res = r.run_attack("adapt_attack_os_target_picker")
        assert res["ok"] is True
        assert "long_write" in res["data"]["pick"].lower()

    def test_ble_5_4_pick(self):
        r = _runner(ble_version="5.4")
        res = r.run_attack("adapt_attack_ble_version_picker")
        assert res["ok"] is True
        assert "cis" in res["data"]["pick"].lower()

    def test_ble_5_0_pick(self):
        r = _runner(ble_version="5.0")
        res = r.run_attack("adapt_attack_ble_version_picker")
        assert res["ok"] is True
        assert "long_read" in res["data"]["pick"].lower()

    def test_battery_service_pick(self):
        r = _runner(service_uuid="180F")
        res = r.run_attack("adapt_attack_service_uuid_picker")
        assert res["ok"] is True
        assert "battery" in res["data"]["pick"].lower() or "template" in res["data"]["pick"].lower()

    def test_hid_service_pick(self):
        r = _runner(service_uuid="1812")
        res = r.run_attack("adapt_attack_service_uuid_picker")
        assert res["ok"] is True
        assert "long_write" in res["data"]["pick"].lower()

    def test_lesc_capability_pick(self):
        r = _runner(capabilities=["lesc"])
        res = r.run_attack("adapt_attack_capability_picker")
        assert res["ok"] is True
        assert "lesc" in res["data"]["pick"].lower()

    def test_mesh_capability_pick(self):
        r = _runner(capabilities=["mesh"])
        res = r.run_attack("adapt_attack_capability_picker")
        assert res["ok"] is True
        assert "friend" in res["data"]["pick"].lower()


class TestOrchestrator:
    def test_ble_attack_orchestrator(self):
        r = _runner()
        res = r.run_attack("ble_attack_orchestrator")
        assert res["ok"] is True
        picks = res["data"]["picks"]
        assert len(picks) == 5
        for p in picks:
            assert p in {t[0] for t in BLE_V2_METHODS}


# ---------------------------------------------------------------------------
# Args validation
# ---------------------------------------------------------------------------


class TestArgsValidation:
    @pytest.mark.parametrize("name", [
        "gatt_descriptor_write_priv_escalation",
        "gatt_long_read_oom_trigger",
        "gatt_indication_flood",
        "gatt_write_without_response_race",
        "gatt_subscribed_notification_flood",
        "l2cap_lecb_channel_dos",
        "iso_channel_cis_dos",
        "mesh_provisioning_capture_replay",
    ])
    def test_address_required(self, name):
        r = BLEAttackRunner(adapter="hci0", args={})
        res = r.run_attack(name)
        assert res["ok"] is False
        assert "address" in res["error"].lower()


# ---------------------------------------------------------------------------
# Adversarial
# ---------------------------------------------------------------------------


class TestAdversarial:
    def test_no_fabricated_data(self):
        r = _runner()
        for name in PHASE_2_3_E_BLE_ATTACK_NAMES:
            res = r.run_attack(name)
            s = str(res).lower()
            for k in ('"psk"', '"pin"', '"password"', '"pre_shared_key"'):
                assert k not in s, f"{name} may have fabricated {k}"

    def test_intrusive_methods_have_error_string(self):
        r = _runner()
        for name in ("gatt_long_write_fuzz", "gatt_prepare_write_abuse",
                     "gatt_notification_flood", "ble_lesc_passkey_replay",
                     "iso_channel_cis_dos"):
            res = r.run_attack(name)
            assert res["ok"] is False, f"{name} returned ok=True without root"
            assert "operator" in res["error"].lower()

    def test_adapt_pickers_return_real_v2_names(self):
        v2_names = {t[0] for t in BLE_V2_METHODS}
        for picker in ("adapt_attack_pairing_method_picker",
                       "adapt_attack_os_target_picker",
                       "adapt_attack_ble_version_picker",
                       "adapt_attack_service_uuid_picker",
                       "adapt_attack_capability_picker"):
            r = _runner()
            res = r.run_attack(picker)
            pick = res["data"]["pick"]
            assert pick in v2_names, f"{picker} picked {pick!r} which is not registered"


# ---------------------------------------------------------------------------
# Phase summary
# ---------------------------------------------------------------------------


class TestPhaseSummary:
    def test_method_count_at_least_40(self):
        assert len(PHASE_2_3_E_BLE_ATTACK_NAMES) >= 40

    def test_all_methods_distinct(self):
        assert len(PHASE_2_3_E_BLE_ATTACK_NAMES) == len(set(PHASE_2_3_E_BLE_ATTACK_NAMES))
