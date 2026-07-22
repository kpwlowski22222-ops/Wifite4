"""Tests for v3 method dispatch in all 8 runners (Phase 2.4).

Each runner is exercised with a known v3 method from its category
and the envelope shape is asserted.
"""
from __future__ import annotations

import pytest


# ---------------------------------------------------------------------------
# WiFi ATTACK runner
# ---------------------------------------------------------------------------

class TestWiFiAttackV3Dispatch:
    def test_v3_method_honest_degrade(self):
        from core.wifi_attack.runner import WiFiAttackRunner
        r = WiFiAttackRunner().run_attack("wifi_ap_blacklist_bypass")
        assert r["ok"] is False
        assert r["name"] == "wifi_ap_blacklist_bypass"
        assert r["data"]["v3"] is True
        assert r["data"]["category"] == "wifi_attack"
        assert "registered in v3_methods" in r["error"]

    def test_v3_destructive_keeps_risk(self):
        from core.wifi_attack.runner import WiFiAttackRunner
        r = WiFiAttackRunner().run_attack("wifi_netgear_rce")
        assert r["risk"] == "destructive"


# ---------------------------------------------------------------------------
# WiFi RECON runner (extended_wifi)
# ---------------------------------------------------------------------------

class TestExtendedWiFiV3Dispatch:
    def test_v3_method_honest_degrade(self):
        from core.extended_wifi.runner import ExtendedWiFiRunner
        r = ExtendedWiFiRunner().run_attack("wifi_client_rssi_heatmap")
        assert r["ok"] is False
        assert r["data"]["v3"] is True
        # The runner checks wifi_attack first, then wifi_recon — both
        # are valid categories for this runner.
        assert r["data"]["category"] in ("wifi_attack", "wifi_recon")

    def test_unknown_returns_error(self):
        from core.extended_wifi.runner import ExtendedWiFiRunner
        r = ExtendedWiFiRunner().run_attack("totally_made_up_zzz")
        assert r["ok"] is False
        assert "unknown" in r["error"]


# ---------------------------------------------------------------------------
# Recon runner (wifi_recon)
# ---------------------------------------------------------------------------

class TestReconV3Dispatch:
    def test_v3_method_honest_degrade(self):
        from core.recon.runner import ReconRunner
        r = ReconRunner().run_probe("wifi_client_rssi_heatmap")
        assert r["ok"] is False
        assert r["data"]["v3"] is True
        assert r["data"]["category"] == "wifi_recon"

    def test_v3_unknown_category(self):
        from core.recon.runner import ReconRunner
        r = ReconRunner().run_probe("totally_made_up_zzz")
        assert r["ok"] is False


# ---------------------------------------------------------------------------
# BLE runner
# ---------------------------------------------------------------------------

class TestBleRunnerV3Dispatch:
    def test_v3_method_honest_degrade(self):
        from core.ble.runner import BLEProbeRunner
        r = BLEProbeRunner().run_probe("ble_adv_rssi_histogram")
        assert r["ok"] is False
        assert r["data"]["v3"] is True
        assert r["data"]["category"] == "ble_recon"

    def test_unknown_returns_error(self):
        from core.ble.runner import BLEProbeRunner
        r = BLEProbeRunner().run_probe("totally_made_up_zzz")
        assert r["ok"] is False
        assert "unknown" in r["error"]


# ---------------------------------------------------------------------------
# BLE attack runner
# ---------------------------------------------------------------------------

class TestBleAttackRunnerV3Dispatch:
    def test_v3_method_honest_degrade(self):
        from core.ble.attack_runner import BLEAttackRunner
        r = BLEAttackRunner().run_attack("ble_gatt_char_bruteforce")
        assert r["ok"] is False
        assert r["data"]["v3"] is True
        assert r["data"]["category"] == "ble_attack"

    def test_v3_destructive_keeps_risk(self):
        from core.ble.attack_runner import BLEAttackRunner
        r = BLEAttackRunner().run_attack("ble_audio_bis_hijack")
        assert r["risk"] == "destructive"


# ---------------------------------------------------------------------------
# Extended BLE runner
# ---------------------------------------------------------------------------

class TestExtendedBleV3Dispatch:
    def test_v3_method_honest_degrade(self):
        from core.extended_ble.runner import ExtendedBLERunner
        r = ExtendedBLERunner().run_attack("ble_gatt_char_bruteforce")
        assert r["ok"] is False
        assert r["data"]["v3"] is True
        assert r["data"]["category"] == "ble_attack"


# ---------------------------------------------------------------------------
# BLE post-exploit runner (checks BOTH ble_attack and post_exploit v3)
# ---------------------------------------------------------------------------

class TestBlePostExploitV3Dispatch:
    def test_ble_attack_v3(self):
        from core.ble_post_exploit.runner import run_attack
        r = run_attack("ble_gatt_char_bruteforce", adapter="hci0")
        assert r["ok"] is False
        assert r["data"]["v3"] is True
        assert r["data"]["category"] == "ble_attack"

    def test_post_exploit_v3(self):
        from core.ble_post_exploit.runner import run_attack
        r = run_attack("post_exploit_dcsync", adapter="hci0")
        assert r["ok"] is False
        assert r["data"]["v3"] is True
        assert r["data"]["category"] == "post_exploit"

    def test_post_exploit_destructive_keeps_risk(self):
        from core.ble_post_exploit.runner import run_attack
        r = run_attack("post_exploit_golden_ticket", adapter="hci0")
        assert r["risk"] == "destructive"


# ---------------------------------------------------------------------------
# OSINT runner
# ---------------------------------------------------------------------------

class TestOsintV3Dispatch:
    def test_web_v3_method_honest_degrade(self):
        from core.osint.runner_ext import OSINTExtRunner
        r = OSINTExtRunner().run_probe("osint_web_cve_mapping")
        assert r["ok"] is False
        assert r["data"]["v3"] is True
        assert r["data"]["category"] == "osint_web"

    def test_people_v3_method_honest_degrade(self):
        # Phase 2.4 §C/D: the polish subpackage dispatch
        # handles ``osint_people_pesel_validate`` BEFORE the
        # generic v3 honest-degrade (it has a real impl in
        # ``core.osint.polish.validators``). Verify the
        # polish dispatch fires.
        from core.osint.runner_ext import OSINTExtRunner
        r = OSINTExtRunner(args={"value": "02070803628"}).run_probe(
            "osint_people_pesel_validate")
        # Polish dispatch returns ok=True with valid=True
        assert r["ok"] is True
        assert r["data"]["valid"] is True
        assert r["data"]["kind"] == "pesel"
        # And a method that does NOT have a polish impl still
        # falls through to the v3 honest-degrade.
        r2 = OSINTExtRunner().run_probe("osint_people_unknown_method")
        assert r2["ok"] is False
        assert "unknown probe method" in (r2.get("error") or "")


# ---------------------------------------------------------------------------
# Post-exploit runner
# ---------------------------------------------------------------------------

class TestPostExploitV3Dispatch:
    def test_v3_method_honest_degrade(self):
        from core.post_exploit.runner_ext import PostExploitExtRunner
        r = PostExploitExtRunner().run_attack("post_exploit_dcsync")
        assert r["ok"] is False
        assert r["data"]["v3"] is True
        assert r["data"]["category"] == "post_exploit"

    def test_v3_destructive_keeps_risk(self):
        from core.post_exploit.runner_ext import PostExploitExtRunner
        r = PostExploitExtRunner().run_attack("post_exploit_golden_ticket")
        assert r["risk"] == "destructive"

    def test_v3_persistence_method(self):
        from core.post_exploit.runner_ext import PostExploitExtRunner
        r = PostExploitExtRunner().run_attack("post_exploit_persistence_mbr")
        assert r["ok"] is False
        assert r["risk"] == "destructive"
