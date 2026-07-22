"""Hermetic tests for the extended-BLE 5.x runner
(``core/extended_ble/runner.py``).

31 BLE 5.x extended modules (30 primitives + 1 LLM coordinator), each
real ``gatttool`` / ``btmgmt`` / ``bluez`` / ``hcitool lescan`` /
``bluetoothctl`` subprocess + parse or a clear degrade. The
parametrized shape test asserts every method returns a valid envelope
and never raises — and never returns a fabricated ``ok=True`` when the
backing tool is absent (``shutil.which`` mocked empty).

Crucial never-fake invariants exercised here:
  * Address-bearing methods degrade to ``ok=False`` when ``args.addr``
    is absent — they NEVER fabricate a result.
  * Tool-bearing methods degrade cleanly when ``gatttool`` /
    ``hcitool`` / ``bluetoothctl`` is absent — never a forged success.
  * The TRAINED-ML-heuristic methods (le_connection_rssi_fingerprinting,
    le_data_packet_length_fingerprinting) report
    ``data["model"] == "heuristic (not trained)"`` and
    ``data["trained"] is False`` — never a fabricated trained
    prediction.
  * The LLM-coordinator ``ble_ai_full_auto_pwn`` returns ok=False with
    the "requires plan" message — it does NOT fabricate sub-results.

Hermeticity: ``shutil.which`` is monkeypatched to no-tool for the
shape test, so no real gatttool / hcitool / bluetoothctl is invoked.
Per-method happy paths use a fake ``subprocess.run`` /
``_gatttool_char_read`` to drive a successful path.
"""
import json
import os
import subprocess
import unittest.mock as mock

import pytest

from core.extended_ble.runner import (EXTENDED_BLE_ATTACKS,
                                      EXTENDED_BLE_METHODS,
                                      ExtendedBLERunner,
                                      run_attack)
from tests.fakes import FakeAIBackend, FakeKB, FakeConfirmFn


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _no_tool(name: str, *_, **__):
    return None


class _FakeCompleted:
    def __init__(self, rc=0, out=""):
        self.returncode = rc
        self.stdout = out
        self.stderr = ""


def _gatt_read_ok(*_a, **_k):
    return {"ok": True, "value_hex": "deadbeef",
            "value_bytes": b"\xde\xad\xbe\xef"}


def _gatt_read_fail(*_a, **_k):
    return {"ok": False, "error": "characteristic not present"}


def _gatt_write_ok(*_a, **_k):
    return (0, "Characteristic value was written successfully")


def _gatt_write_fail(*_a, **_k):
    return (1, "Error: Write failed")


# Common args — every method has at least one of these. Most methods
# require an addr (the runner degrades on missing addr).
def _common_args() -> dict:
    return {
        "adapter": "hci0",
        "addr": "AA:BB:CC:DD:EE:FF",
        "address": "AA:BB:CC:DD:EE:FF",
        "target": "AA:BB:CC:DD:EE:FF",
        "probes": 3,
        "loops": 2,
        "duration_s": 2,
        "rssi_samples": [-45, -50, -55, -60, -58],
        "packet_length_samples": [27, 80, 200, 30, 250, 100, 27],
        "candidate_irks": ["00112233445566778899aabbccddeeff"],
        "adapters": "hci0",
        "phys": ["1M", "2M", "Coded"],
        "max_probe": 2,
        "max_attempts": 2,
    }


# ---------------------------------------------------------------------------
# 1. Class shape + EXTENDED_BLE_METHODS
# ---------------------------------------------------------------------------
class TestExtendedBLERunner:
    def test_class_exists(self):
        assert ExtendedBLERunner is not None

    def test_has_extended_ble_methods_tuple(self):
        assert hasattr(ExtendedBLERunner, "EXTENDED_BLE_METHODS")
        assert isinstance(ExtendedBLERunner.EXTENDED_BLE_METHODS, tuple)

    def test_extended_ble_methods_count(self):
        # 30 primitives + 1 AI coordinator + 3 Phase 1.6 patterns = 34
        assert len(ExtendedBLERunner.EXTENDED_BLE_METHODS) == 34

    def test_ai_coordinator_present(self):
        assert "ble_ai_full_auto_pwn" in ExtendedBLERunner.EXTENDED_BLE_METHODS

    def test_all_spec_methods_present(self):
        """The 30 spec modules from implementacja.txt lines 4934-5058
        must be present in the tuple."""
        spec = (
            "identify_irk_via_timing",
            "scanner_filter_bypass",
            "periodic_advertising_train_poison",
            "le_audio_bis_sync_jamming",
            "power_side_channel_ble",
            "adv_data_extension_exhaustion",
            "ble_5_2_isochronous_channels_scan",
            "channel_map_update_attack",
            "connection_event_counter_wraparound",
            "rssi_based_zone_bypass",
            "connection_supervision_timeout_trigger",
            "le_connection_rssi_fingerprinting",
            "advertising_data_poisoning",
            "irk_collision_bruteforce",
            "le_audio_codec_manipulation",
            "battery_drain_via_pairing_loop",
            "le_data_packet_length_fingerprinting",
            "privacy_mode_switch_spoof",
            "link_layer_timeout_racing",
            "bd_addr_inquiry_rssi_map",
            "multi_role_simultaneous_scan",
            "le_credential_forcing",
            "firmware_version_squatting",
            "advertising_interval_exhaustion",
            "gatt_indication_confusion",
            "ccc_table_flood",
            "le_2m_coded_phy_transition_attack",
            "sm_smp_timeout_dos",
            "mesh_iv_index_update_spoof",
            "proxy_solicitation_flood",
        )
        for m in spec:
            assert m in ExtendedBLERunner.EXTENDED_BLE_METHODS, m

    def test_every_method_callable(self):
        runner = ExtendedBLERunner(adapter="hci0", args={})
        for m in ExtendedBLERunner.EXTENDED_BLE_METHODS:
            fn = getattr(runner, "_" + m, None)
            assert fn is not None, f"missing _method for {m}"
            assert callable(fn), f"_{m} is not callable"


# ---------------------------------------------------------------------------
# 2. Parametrized envelope test — every method returns a valid envelope.
# ---------------------------------------------------------------------------
class TestAllMethodsReturnEnvelope:
    @pytest.mark.parametrize("method",
                             list(ExtendedBLERunner.EXTENDED_BLE_METHODS))
    def test_envelope_shape(self, method, monkeypatch):
        """With shutil.which mocked empty and subprocess.run returning
        a failure, every method must return a dict with ok in
        {True, False}, error a str, data dict-or-None, and must NEVER
        raise."""
        monkeypatch.setattr("core.extended_ble.runner.shutil.which",
                            _no_tool)
        monkeypatch.setattr("core.extended_ble.runner.subprocess.run",
                            lambda *a, **k: _FakeCompleted(1, ""))
        runner = ExtendedBLERunner(adapter="hci0", args=_common_args())
        res = runner.run_attack(method)
        assert isinstance(res, dict), method
        assert "ok" in res, method
        assert isinstance(res["ok"], bool), method
        assert "name" in res, method
        assert res["name"] == method, method
        assert "error" in res, method
        assert isinstance(res["error"], str), method
        assert "data" in res, method
        assert res["data"] is None or isinstance(res["data"], dict), method
        assert "duration_s" in res, method
        assert isinstance(res["duration_s"], (int, float)), method
        assert res["duration_s"] >= 0, method

    @pytest.mark.parametrize("method",
                             list(ExtendedBLERunner.EXTENDED_BLE_METHODS))
    def test_never_raises(self, method, monkeypatch):
        """No method ever raises — even with a wild exception in
        the underlying subprocess, the dispatch catches and returns
        a step dict. The heuristic methods (rssi/packet-length
        fingerprinting, irk_collision_bruteforce) do not call
        subprocess, so they may return ok=True. We patch the
        gatttool helpers too so the never-raises test is uniform."""
        monkeypatch.setattr("core.extended_ble.runner.shutil.which",
                            _no_tool)

        def boom(*_a, **_k):
            raise RuntimeError(f"boom in {method}")
        monkeypatch.setattr("core.extended_ble.runner.subprocess.run", boom)
        runner = ExtendedBLERunner(adapter="hci0", args=_common_args())
        # Force the gatttool helpers to a no-op degrade as well —
        # makes the never-raises test uniformly assert structural
        # invariants without depending on which methods touch
        # subprocess.
        def _boom_gatt(*_a, **_k):
            raise RuntimeError("gatttool boom")
        runner._gatttool_read = _boom_gatt
        runner._gatttool_write = _boom_gatt
        runner._gatttool_char_read = _boom_gatt
        res = runner.run_attack(method)
        # The contract is "never propagates". We only assert
        # the step-dict shape.
        assert isinstance(res, dict)
        assert "ok" in res
        assert "name" in res
        assert "error" in res
        assert "duration_s" in res


# ---------------------------------------------------------------------------
# 3. Honest degradation — tool-absent → ok=False; subprocess non-zero →
#    ok=False with stderr excerpt; never fabricated.
# ---------------------------------------------------------------------------
class TestHonestDegradation:
    def test_no_tool_returns_error(self, monkeypatch):
        """When gatttool is absent, methods that need it return
        ok=False with an error mentioning gatttool."""
        monkeypatch.setattr("core.extended_ble.runner.shutil.which",
                            _no_tool)
        runner = ExtendedBLERunner(adapter="hci0", args=_common_args())
        res = runner.run_attack("rssi_based_zone_bypass")
        assert res["ok"] is False
        assert "gatttool" in res["error"].lower()

    def test_hcitool_absent_for_scan(self, monkeypatch):
        monkeypatch.setattr("core.extended_ble.runner.shutil.which",
                            _no_tool)
        runner = ExtendedBLERunner(adapter="hci0", args=_common_args())
        res = runner.run_attack("bd_addr_inquiry_rssi_map")
        assert res["ok"] is False
        assert "hcitool" in res["error"].lower()

    def test_bluetoothctl_absent_for_battery_drain(self, monkeypatch):
        monkeypatch.setattr("core.extended_ble.runner.shutil.which",
                            _no_tool)
        runner = ExtendedBLERunner(adapter="hci0", args=_common_args())
        res = runner.run_attack("battery_drain_via_pairing_loop")
        assert res["ok"] is False
        # First degrade on gatttool (before bluetoothctl)
        assert "gatttool" in res["error"].lower() or \
               "bluetoothctl" in res["error"].lower()

    def test_missing_addr_for_target_methods(self, monkeypatch):
        """Methods that take an addr must degrade when none is
        supplied."""
        monkeypatch.setattr("core.extended_ble.runner.shutil.which",
                            lambda *a, **k: "/fake/gatttool")
        runner = ExtendedBLERunner(adapter="hci0", args={})
        for m in ("rssi_based_zone_bypass",
                  "le_credential_forcing",
                  "firmware_version_squatting"):
            res = runner.run_attack(m)
            assert res["ok"] is False, m
            assert "addr" in res["error"], m

    def test_subprocess_nonzero_reports_error(self, monkeypatch):
        """When subprocess.run returns non-zero, the method should
        report the failure — not fabricate a success."""
        monkeypatch.setattr("core.extended_ble.runner.shutil.which",
                            lambda *a, **k: "/fake/gatttool")
        monkeypatch.setattr("core.extended_ble.runner.subprocess.run",
                            lambda *a, **k: _FakeCompleted(1, ""))
        runner = ExtendedBLERunner(adapter="hci0", args=_common_args())
        res = runner.run_attack("rssi_based_zone_bypass")
        # With gatttool "present" but no real device + non-zero rc
        # on read, the method degrades on the char-not-present.
        assert res["ok"] is False
        assert res["error"]


# ---------------------------------------------------------------------------
# 4. No bare except: clause in the runner source
# ---------------------------------------------------------------------------
class TestNoBareExcept:
    def test_no_bare_except(self):
        runner_path = ("/home/user/Pulpit/kfiosa/core/extended_ble/"
                       "runner.py")
        with open(runner_path, "r", encoding="utf-8") as f:
            src = f.read()
        # Count bare ``except:`` (no exception type, no 'as' clause).
        # Walk the source and look for `except:` that isn't `except
        # SomeException` or `except (...) as e:`.
        import re
        bare = re.findall(r"^\s*except\s*:\s*$", src, re.MULTILINE)
        assert bare == [], f"found {len(bare)} bare except: in runner.py: {bare!r}"


# ---------------------------------------------------------------------------
# 5. Never-fake — when tool is absent, no method returns ok=True with
#    a made-up data dict.
# ---------------------------------------------------------------------------
class TestNeverFakes:
    @pytest.mark.parametrize("method",
                             list(ExtendedBLERunner.EXTENDED_BLE_METHODS))
    def test_no_fabrication_when_tool_absent(self, method, monkeypatch):
        """No method may report ok=True with a fabricated data dict
        when no tool is present. The honest-degrade contract. We
        only check DATA VALUES (not the explanatory note string)."""
        monkeypatch.setattr("core.extended_ble.runner.shutil.which",
                            _no_tool)
        monkeypatch.setattr("core.extended_ble.runner.subprocess.run",
                            lambda *a, **k: _FakeCompleted(1, ""))
        runner = ExtendedBLERunner(adapter="hci0", args=_common_args())
        res = runner.run_attack(method)
        # If ok=True, the data must be a heuristic / presence-only
        # report (no fabricated cracked keys / coords / sessions).
        if res["ok"] is True and res.get("data"):
            d = res["data"]
            # Strip the explanatory note so we only check values.
            d2 = {k: v for k, v in d.items() if k != "note"}
            data_str = json.dumps(d2).lower()
            for bad in ("cracked_irk", "session_token",
                        "drained_battery", "fab_coord", "password123"):
                assert bad not in data_str, \
                    f"fabricated '{bad}' in {method}: {d2}"


# ---------------------------------------------------------------------------
# 6. Registry
# ---------------------------------------------------------------------------
class TestRegistry:
    def test_registry_exists(self):
        assert EXTENDED_BLE_ATTACKS is not None
        assert isinstance(EXTENDED_BLE_ATTACKS, list)

    def test_registry_one_entry_per_method(self):
        methods = list(ExtendedBLERunner.EXTENDED_BLE_METHODS)
        assert len(EXTENDED_BLE_ATTACKS) == len(methods), \
            f"registry {len(EXTENDED_BLE_ATTACKS)} != methods {len(methods)}"
        reg_methods = {s["method"] for s in EXTENDED_BLE_ATTACKS}
        assert reg_methods == set(methods)

    def test_each_entry_has_required_fields(self):
        for spec in EXTENDED_BLE_ATTACKS:
            assert spec.get("name"), spec
            assert spec.get("description"), spec
            assert isinstance(spec.get("input_schema"), dict), spec
            assert spec.get("examples"), spec
            assert spec.get("risk_level") in ("read", "intrusive",
                                              "destructive"), spec
            assert isinstance(spec.get("requires_root"), bool), spec

    def test_ai_coordinator_is_read_risk(self):
        """The AI coordinator stub is risk_level='read' — it does
        no real work when called directly."""
        for spec in EXTENDED_BLE_ATTACKS:
            if spec["method"] == "ble_ai_full_auto_pwn":
                assert spec["risk_level"] == "read", spec
                assert spec["requires_root"] is False, spec
                break
        else:
            pytest.fail("ble_ai_full_auto_pwn not in registry")

    def test_primitives_are_intrusive(self):
        """All 30 primitive methods are risk_level='intrusive'."""
        ai = {"ble_ai_full_auto_pwn"}
        for spec in EXTENDED_BLE_ATTACKS:
            if spec["method"] in ai:
                continue
            assert spec["risk_level"] == "intrusive", spec

    def test_names_prefix_extended_ble(self):
        for spec in EXTENDED_BLE_ATTACKS:
            assert spec["name"].startswith("extended_ble_"), spec


# ---------------------------------------------------------------------------
# 7. Module-level entrypoint
# ---------------------------------------------------------------------------
class TestModuleEntrypoint:
    def test_run_attack_returns_envelope(self, monkeypatch):
        monkeypatch.setattr("core.extended_ble.runner.shutil.which",
                            _no_tool)
        res = run_attack("rssi_based_zone_bypass",
                          adapter="hci0", args=_common_args())
        assert isinstance(res, dict)
        assert "ok" in res
        assert "name" in res
        assert res["ok"] is False  # no gatttool

    def test_run_attack_unknown_method(self, monkeypatch):
        monkeypatch.setattr("core.extended_ble.runner.shutil.which",
                            _no_tool)
        res = run_attack("totally_bogus", args={})
        assert res["ok"] is False
        assert "unknown attack method" in res["error"]

    def test_run_attack_never_raises_on_constructor(self, monkeypatch):
        """If the runner constructor itself raises, the module-level
        entrypoint catches and returns an error envelope."""
        def boom(*_a, **_k):
            raise RuntimeError("constructor boom")
        monkeypatch.setattr("core.extended_ble.runner.ExtendedBLERunner", boom)
        res = run_attack("rssi_based_zone_bypass", args={})
        assert res["ok"] is False
        assert "constructor boom" in (res.get("error") or "")

    @pytest.mark.parametrize("method",
                             list(ExtendedBLERunner.EXTENDED_BLE_METHODS))
    def test_run_attack_dispatches_every_method(self, method, monkeypatch):
        """The module-level run_attack dispatches every registered
        method without raising."""
        monkeypatch.setattr("core.extended_ble.runner.shutil.which",
                            _no_tool)
        monkeypatch.setattr("core.extended_ble.runner.subprocess.run",
                            lambda *a, **k: _FakeCompleted(1, ""))
        res = run_attack(method, adapter="hci0", args=_common_args())
        assert isinstance(res, dict)
        assert "ok" in res


# ---------------------------------------------------------------------------
# 8. Edge cases
# ---------------------------------------------------------------------------
class TestEdgeCases:
    def test_unknown_method_returns_ok_false(self):
        runner = ExtendedBLERunner(adapter="hci0", args={})
        res = runner.run_attack("totally_bogus")
        assert res["ok"] is False
        assert "unknown attack method" in res["error"]

    def test_empty_method_returns_ok_false(self):
        runner = ExtendedBLERunner(adapter="hci0", args={})
        res = runner.run_attack("")
        assert res["ok"] is False

    def test_none_method_returns_ok_false(self):
        runner = ExtendedBLERunner(adapter="hci0", args={})
        res = runner.run_attack(None)  # type: ignore[arg-type]
        assert res["ok"] is False

    def test_whitespace_method_returns_ok_false(self):
        runner = ExtendedBLERunner(adapter="hci0", args={})
        res = runner.run_attack("   ")
        assert res["ok"] is False

    def test_dispatch_swallows_unhandled_exception(self, monkeypatch):
        """If a method body raises, the dispatch catches and returns
        a step dict — never propagates."""
        def boom(self):
            raise RuntimeError("method body boom")
        # Patch a method that does not normally call any tools.
        monkeypatch.setattr(ExtendedBLERunner, "_power_side_channel_ble",
                            boom)
        res = run_attack("power_side_channel_ble", args={})
        assert res["ok"] is False
        assert "method body boom" in (res.get("error") or "") or \
               "unhandled" in (res.get("error") or "")


# ---------------------------------------------------------------------------
# 9. LLM coordinator
# ---------------------------------------------------------------------------
class TestAIcoordinator:
    def test_ai_coordinator_degrades_without_plan(self, monkeypatch):
        """ble_ai_full_auto_pwn is a no-op stub when called directly —
        it does NOT fabricate sub-results."""
        monkeypatch.setattr("core.extended_ble.runner.shutil.which",
                            _no_tool)
        runner = ExtendedBLERunner(adapter="hci0", args={})
        res = runner.run_attack("ble_ai_full_auto_pwn")
        assert res["ok"] is False
        assert "plan" in res["error"].lower()
        assert "chain planner" in res["error"].lower() or \
               "requires" in res["error"].lower()

    def test_ai_coordinator_no_fabrication_even_with_args(self, monkeypatch):
        """The AI coordinator never fabricates sub-results — even
        when given arbitrary args."""
        monkeypatch.setattr("core.extended_ble.runner.shutil.which",
                            lambda *a, **k: "/fake/gatttool")
        runner = ExtendedBLERunner(adapter="hci0",
                                    args={"plan": [{"method":
                                                    "rssi_based_zone_bypass",
                                                    "args": {}}]})
        res = runner.run_attack("ble_ai_full_auto_pwn")
        # The stub is a no-op even with a plan — the orchestrator
        # is what drives the chain.
        assert res["ok"] is False
        assert "plan" in res["error"].lower() or \
               "chain" in res["error"].lower()

    def test_ai_coordinator_via_module_entrypoint(self, monkeypatch):
        monkeypatch.setattr("core.extended_ble.runner.shutil.which",
                            _no_tool)
        res = run_attack("ble_ai_full_auto_pwn", args={})
        assert res["ok"] is False
        assert "plan" in res["error"].lower()


# ---------------------------------------------------------------------------
# 10. Smoke
# ---------------------------------------------------------------------------
class TestSmoke:
    def test_runner_instantiation(self):
        r = ExtendedBLERunner(adapter="hci0", args={})
        assert r is not None
        assert r.adapter == "hci0"
        assert r.args == {}

    def test_runner_no_args(self):
        r = ExtendedBLERunner()
        assert r is not None

    def test_finalize_with_sample_data(self):
        """The module-level _step + _finalize helpers produce a
        well-formed step dict."""
        from core.extended_ble.runner import _step, _finalize
        step = _step("test_method")
        # step['started'] is a float; we use it as the started
        # timestamp to keep duration_s >= 0.
        out = _finalize(step, step["started"], ok=True,
                         data={"key": "value"}, error="")
        assert out["name"] == "test_method"
        assert out["ok"] is True
        assert out["data"] == {"key": "value"}
        assert out["error"] == ""
        assert isinstance(out["duration_s"], float)
        assert out["duration_s"] >= 0.0

    def test_finalize_with_error(self):
        from core.extended_ble.runner import _step, _finalize
        step = _step("err_method")
        out = _finalize(step, step["started"], ok=False,
                         data=None, error="boom")
        assert out["ok"] is False
        assert out["data"] is None
        assert out["error"] == "boom"
        assert out["name"] == "err_method"

    def test_which_helper(self, monkeypatch):
        """The _which helper returns True if shutil.which returns
        a path, else False."""
        from core.extended_ble.runner import _which
        monkeypatch.setattr("core.extended_ble.runner.shutil.which",
                            _no_tool)
        assert _which("gatttool") is False
        monkeypatch.setattr("core.extended_ble.runner.shutil.which",
                            lambda *a, **k: "/usr/bin/gatttool")
        assert _which("gatttool") is True


# ---------------------------------------------------------------------------
# 11. Per-method happy paths (proves the runner does real work when
#     tools are present and the device responds).
# ---------------------------------------------------------------------------
class TestHappyPaths:
    def test_firmware_version_squatting_read_only(self, monkeypatch):
        """firmware_version_squatting with no squatted_version: real
        gatttool read → ok=True with verbatim value."""
        from core.extended_ble.runner import ExtendedBLERunner
        monkeypatch.setattr("core.extended_ble.runner.shutil.which",
                            lambda *a, **k: "/fake/gatttool")
        # Patch the instance method directly so the gatttool_read
        # helper returns a fake result.
        runner = ExtendedBLERunner(adapter="hci0", args=_common_args())
        monkeypatch.setattr(runner, "_gatttool_char_read", _gatt_read_ok)
        res = runner.run_attack("firmware_version_squatting")
        assert res["ok"] is True
        assert res["data"]["squat_attempted"] is False
        assert res["data"]["current_firmware_version_hex"] == "deadbeef"

    def test_firmware_version_squatting_with_version(self, monkeypatch):
        """With a squatted_version, the runner attempts a real write."""
        from core.extended_ble.runner import ExtendedBLERunner
        monkeypatch.setattr("core.extended_ble.runner.shutil.which",
                            lambda *a, **k: "/fake/gatttool")
        runner = ExtendedBLERunner(adapter="hci0",
                                    args={**_common_args(),
                                          "squatted_version": "v9.9.9"})
        monkeypatch.setattr(runner, "_gatttool_char_read", _gatt_read_ok)
        monkeypatch.setattr(runner, "_gatttool_write", _gatt_write_ok)
        res = runner.run_attack("firmware_version_squatting")
        assert res["ok"] is True
        assert res["data"]["squat_attempted"] is True
        assert res["data"]["squat_ok"] is True

    def test_privacy_mode_switch_spoof_present(self, monkeypatch):
        from core.extended_ble.runner import ExtendedBLERunner
        monkeypatch.setattr("core.extended_ble.runner.shutil.which",
                            lambda *a, **k: "/fake/gatttool")
        runner = ExtendedBLERunner(adapter="hci0", args=_common_args())
        monkeypatch.setattr(runner, "_gatttool_char_read", _gatt_read_ok)
        res = runner.run_attack("privacy_mode_switch_spoof")
        assert res["ok"] is True
        assert res["data"]["reconnection_address_hex"] == "deadbeef"

    def test_privacy_mode_absent_char(self, monkeypatch):
        from core.extended_ble.runner import ExtendedBLERunner
        monkeypatch.setattr("core.extended_ble.runner.shutil.which",
                            lambda *a, **k: "/fake/gatttool")
        runner = ExtendedBLERunner(adapter="hci0", args=_common_args())
        monkeypatch.setattr(runner, "_gatttool_char_read", _gatt_read_fail)
        res = runner.run_attack("privacy_mode_switch_spoof")
        assert res["ok"] is False
        assert "0x2A03" in res["error"]

    def test_le_connection_rssi_fingerprinting_uses_heuristic(self,
                                                               monkeypatch):
        """TRAINED-ML heuristic: the rssi fingerprinting must report
        'heuristic (not trained)' — never a fabricated prediction."""
        runner = ExtendedBLERunner(adapter="hci0", args=_common_args())
        res = runner.run_attack("le_connection_rssi_fingerprinting")
        assert res["ok"] is True
        d = res["data"]
        assert d["model"] == "heuristic (not trained)"
        assert d["trained"] is False
        assert d["sample_count"] == 5
        assert isinstance(d["mean_dbm"], (int, float))

    def test_le_data_packet_length_fingerprinting_uses_heuristic(self):
        """TRAINED-ML heuristic: the packet-length fingerprinting
        must report 'heuristic (not trained)'."""
        runner = ExtendedBLERunner(adapter="hci0", args=_common_args())
        res = runner.run_attack("le_data_packet_length_fingerprinting")
        assert res["ok"] is True
        d = res["data"]
        assert d["model"] == "heuristic (not trained)"
        assert d["trained"] is False
        assert d["sample_count"] == 7
        assert sum(d["bins"].values()) == 7

    def test_power_side_channel_ble_never_fakes(self, monkeypatch):
        """power_side_channel_ble needs physical access; the runner
        must degrade honestly."""
        runner = ExtendedBLERunner(adapter="hci0", args=_common_args())
        res = runner.run_attack("power_side_channel_ble")
        assert res["ok"] is False
        assert "physical" in res["error"].lower() or \
               "current probe" in res["error"].lower()

    def test_irk_collision_bruteforce_never_fabricates(self, monkeypatch):
        """irk_collision_bruteforce must NOT report a cracked IRK."""
        runner = ExtendedBLERunner(adapter="hci0", args=_common_args())
        res = runner.run_attack("irk_collision_bruteforce")
        # It returns ok=True (the candidate-list-size report) but
        # data must NOT contain a fabricated cracked IRK.
        d = res["data"]
        d2 = {k: v for k, v in d.items() if k != "note"}
        assert "cracked" not in json.dumps(d2).lower()
        assert "candidate_count" in d
        assert d["candidate_count"] >= 1

    def test_battery_drain_pairing_no_tool(self, monkeypatch):
        """battery_drain_via_pairing_loop: no gatttool + no
        bluetoothctl → degrade."""
        monkeypatch.setattr("core.extended_ble.runner.shutil.which",
                            _no_tool)
        runner = ExtendedBLERunner(adapter="hci0", args=_common_args())
        res = runner.run_attack("battery_drain_via_pairing_loop")
        assert res["ok"] is False
        assert "gatttool" in res["error"].lower() or \
               "bluetoothctl" in res["error"].lower()


# ---------------------------------------------------------------------------
# 12. Subprocess helper coverage
# ---------------------------------------------------------------------------
class TestSubprocessHelpers:
    def test_run_returns_rc_and_output(self, monkeypatch):
        from core.extended_ble.runner import _run
        monkeypatch.setattr("core.extended_ble.runner.subprocess.run",
                            lambda *a, **k: _FakeCompleted(0, "ok"))
        rc, out = _run(["echo", "hi"], timeout=5)
        assert rc == 0
        assert "ok" in out

    def test_run_swallows_timeout(self, monkeypatch):
        from core.extended_ble.runner import _run
        def boom(*a, **k):
            raise subprocess.TimeoutExpired(cmd=["sleep"], timeout=5)
        monkeypatch.setattr("core.extended_ble.runner.subprocess.run", boom)
        rc, out = _run(["sleep", "5"], timeout=5)
        assert rc == 1
        assert out == ""

    def test_run_swallows_filenotfound(self, monkeypatch):
        from core.extended_ble.runner import _run
        def boom(*a, **k):
            raise FileNotFoundError("nope")
        monkeypatch.setattr("core.extended_ble.runner.subprocess.run", boom)
        rc, out = _run(["nope"], timeout=5)
        assert rc == 1
        assert out == ""

    def test_run_swallows_oserror(self, monkeypatch):
        from core.extended_ble.runner import _run
        def boom(*a, **k):
            raise OSError("nope")
        monkeypatch.setattr("core.extended_ble.runner.subprocess.run", boom)
        rc, out = _run(["x"], timeout=5)
        assert rc == 1
        assert out == ""

    def test_run_swallows_generic(self, monkeypatch):
        from core.extended_ble.runner import _run
        def boom(*a, **k):
            raise RuntimeError("nope")
        monkeypatch.setattr("core.extended_ble.runner.subprocess.run", boom)
        rc, out = _run(["x"], timeout=5)
        assert rc == 1
        assert out == ""


# ---------------------------------------------------------------------------
# Phase 1.6: ble_multi_encoding_value_auto_decode_pipeline
# ---------------------------------------------------------------------------
class TestMultiEncodingDecoder:
    def test_decode_hex_payload(self):
        """Pure-Python: runs 4 encoders + 12 numeric decoders + battery
        heuristic over a 4-byte payload. No subprocess called."""
        r = run_attack("ble_multi_encoding_value_auto_decode_pipeline",
                       args={"payload_hex": "DEADBEEF"})
        assert r["ok"] is True
        d = r["data"]
        assert d["len"] == 4
        assert d["hex"] == "deadbeef"
        # All 4 text encoders present
        for enc in ("utf-8", "utf-16-le", "latin1", "ascii"):
            assert f"text_{enc}" in d
        # Numeric decoders for 4-byte payload
        assert d["uint8"] == 0xDE
        assert d["int8"] == -34  # 0xDE = 222 -> signed -34
        # payload[0]=DE, payload[1]=AD -> LE = 0xADDE, BE = 0xDEAD
        assert d["uint16_le"] == 0xADDE
        assert d["uint16_be"] == 0xDEAD
        assert d["uint32_be"] == 0xDEADBEEF
        # Battery percent heuristic
        assert d["battery_pct_heuristic"]["direct"] == 0xDE
        assert d["battery_pct_heuristic"]["bitmask_0x7f"] == 0x5E

    def test_decode_value_bytes(self):
        """Accepts args.value as bytes / bytearray / str hex."""
        r = run_attack("ble_multi_encoding_value_auto_decode_pipeline",
                       args={"value": b"AB"})
        assert r["ok"] is True
        assert r["data"]["len"] == 2
        assert r["data"]["uint8"] == 0x41  # 'A'
        # 'A','B' -> BE = 0x4142
        assert r["data"]["uint16_be"] == 0x4142

    def test_decode_short_payload_only_uint8(self):
        """1-byte payload: only uint8/int8 + battery (not uint16 etc.)."""
        r = run_attack("ble_multi_encoding_value_auto_decode_pipeline",
                       args={"payload_hex": "FF"})
        assert r["ok"] is True
        assert r["data"]["len"] == 1
        assert r["data"]["uint8"] == 0xFF
        assert r["data"]["int8"] == -1
        # uint16 is NOT in the result (insufficient bytes)
        assert "uint16_le" not in r["data"]
        # Battery heuristic
        assert r["data"]["battery_pct_heuristic"]["direct"] == 0xFF

    def test_decode_empty_payload_degrades(self):
        r = run_attack("ble_multi_encoding_value_auto_decode_pipeline",
                       args={"payload_hex": ""})
        assert r["ok"] is False
        assert "empty" in r["error"].lower() or "required" in r["error"].lower()

    def test_decode_invalid_hex_degrades(self):
        r = run_attack("ble_multi_encoding_value_auto_decode_pipeline",
                       args={"payload_hex": "not_hex"})
        assert r["ok"] is False
        assert "hex" in r["error"].lower()

    def test_decode_no_payload_or_value_degrades(self):
        r = run_attack("ble_multi_encoding_value_auto_decode_pipeline",
                       args={})
        assert r["ok"] is False
        assert "required" in r["error"].lower()

    def test_decode_text_utf8_roundtrip(self):
        """UTF-8 encoding of ASCII text should round-trip cleanly."""
        r = run_attack("ble_multi_encoding_value_auto_decode_pipeline",
                       args={"payload_hex": b"hello".hex()})
        assert r["ok"] is True
        assert r["data"]["text_utf-8"] == "hello"

    def test_decode_no_subprocess_called(self, monkeypatch):
        def _fail(*a, **k):
            raise AssertionError("subprocess must not be called")
        monkeypatch.setattr("core.extended_ble.runner.subprocess.run", _fail)
        r = run_attack("ble_multi_encoding_value_auto_decode_pipeline",
                       args={"payload_hex": "0102"})
        assert r["ok"] is True


# ---------------------------------------------------------------------------
# Phase 1.6: ble_handle_0x0003_local_name_writable_classifier
# ---------------------------------------------------------------------------
class TestHandle0003WritableClassifier:
    def test_classifier_degrades_when_gatttool_absent(self, monkeypatch):
        monkeypatch.setattr("core.extended_ble.runner.shutil.which",
                            lambda n: None)
        r = run_attack("ble_handle_0x0003_local_name_writable_classifier",
                       args={"addr": "AA:BB:CC:DD:EE:01"})
        assert r["ok"] is False
        assert "gatttool" in r["error"]

    def test_classifier_requires_addr(self, monkeypatch):
        def _which_all(n):
            return "/usr/bin/" + n  # pretend gatttool exists
        monkeypatch.setattr("core.extended_ble.runner.shutil.which", _which_all)
        r = run_attack("ble_handle_0x0003_local_name_writable_classifier",
                       args={})
        assert r["ok"] is False
        assert "addr" in r["error"]

    def test_classifier_write_accepted_yields_vulnerable_class(
            self, monkeypatch):
        """When gatttool --char-write-req returns rc=0, the classifier
        labels the device as vulnerable_firmware_class."""
        monkeypatch.setattr("core.extended_ble.runner.shutil.which",
                            lambda n: "/usr/bin/" + n)
        def fake_run(cmd, timeout=20):
            if "--char-read" in cmd:
                return (0, "Characteristic value/descriptor: VENDOR-DEV-1")
            if "--char-write-req" in cmd:
                return (0, "Characteristic value was written successfully")
            return (1, "")
        monkeypatch.setattr("core.extended_ble.runner._run", fake_run)
        r = run_attack("ble_handle_0x0003_local_name_writable_classifier",
                       args={"addr": "AA:BB:CC:DD:EE:01",
                             "new_name": "kfiosa_test"})
        assert r["ok"] is True
        assert r["data"]["writable_classifier"] == "vulnerable_firmware_class"
        assert r["data"]["write_rc"] == 0

    def test_classifier_write_rejected_yields_secure_label(
            self, monkeypatch):
        """When gatttool --char-write-req returns rc!=0, the classifier
        labels the device as secure_no_accept — never fabricates."""
        monkeypatch.setattr("core.extended_ble.runner.shutil.which",
                            lambda n: "/usr/bin/" + n)
        def fake_run(cmd, timeout=20):
            if "--char-read" in cmd:
                return (0, "Characteristic value/descriptor: SECURE-DEV")
            if "--char-write-req" in cmd:
                return (1, "Write not permitted")
            return (1, "")
        monkeypatch.setattr("core.extended_ble.runner._run", fake_run)
        r = run_attack("ble_handle_0x0003_local_name_writable_classifier",
                       args={"addr": "AA:BB:CC:DD:EE:01"})
        assert r["ok"] is True
        assert r["data"]["writable_classifier"] == "secure_no_accept"
        assert r["data"]["write_rc"] == 1


# ---------------------------------------------------------------------------
# Phase 1.6: ble_writable_char_black_box_audit
# ---------------------------------------------------------------------------
class TestWritableCharBlackBoxAudit:
    def test_audit_degrades_when_bleak_absent(self, monkeypatch):
        import sys
        # Force bleak import to fail.
        orig_import = __builtins__.__import__ if hasattr(__builtins__,
                                                          "__import__") else \
            __import__
        def fake_import(name, *a, **k):
            if name == "bleak" or name.startswith("bleak."):
                raise ImportError("bleak not installed")
            return orig_import(name, *a, **k)
        monkeypatch.setattr("builtins.__import__", fake_import)
        r = run_attack("ble_writable_char_black_box_audit",
                       args={"addr": "AA:BB:CC:DD:EE:01"})
        assert r["ok"] is False
        assert "bleak" in r["error"].lower()

    def test_audit_requires_addr(self, monkeypatch):
        # We can only check this if bleak is actually importable. If not,
        # the addr check is skipped. So we don't assert anything here.
        try:
            import bleak  # noqa: F401
        except Exception:  # noqa: BLE001
            return  # skip — bleak not installed
        r = run_attack("ble_writable_char_black_box_audit", args={})
        assert r["ok"] is False
        assert "addr" in r["error"]
