"""tests.test_poly_adapt_integration — Phase 3 expansion T7.

Verifies the integration helpers in
:mod:`core.refactors.poly_adapt_integration` produce the
expected envelopes and stay heuristic (no trained-ML claim,
no fabricated creds).
"""

import json

from core.refactors.poly_adapt_integration import (
    poly_deauth_burst_for_wifi,
    adapt_wifi_chipset_for_runner,
    adapt_wifi_channel_width_for_runner,
    adapt_ble_chipset_for_runner,
    adapt_ble_pairing_for_runner,
    poly_email_pattern_for_runner,
    adapt_osint_jurisdiction_for_runner,
    poly_disk_carve_signature_for_runner,
    adapt_forensics_image_format_for_runner,
    adapt_forensics_timeline_format_for_runner,
    poly_lateral_movement_for_runner,
    poly_persistence_for_runner,
    adapt_persistence_mechanism_for_runner,
    adapt_exfil_channel_for_runner,
)


# ---------------------------------------------------------------------------
# WiFi integration
# ---------------------------------------------------------------------------


class TestWifiIntegration:
    def test_deauth_burst_for_wifi(self):
        r = poly_deauth_burst_for_wifi(target_bssid="aa:bb:cc:dd:ee:ff",
                                       client_count=3)
        assert r["ok"] is True
        assert r["data"]["model"] == "polymorphic (heuristic)"
        assert "primary" in r["data"]
        assert "variants" in r["data"]

    def test_deauth_burst_with_empty_args(self):
        r = poly_deauth_burst_for_wifi()
        assert r["ok"] is True

    def test_chipset_mt7922(self):
        r = adapt_wifi_chipset_for_runner("mt7922")
        assert r["ok"] is True
        assert r["data"]["pick"] == "mt7921e_nexmon_monitor"

    def test_chipset_u4000_unaffected(self):
        """U4000 BLUETOOTH adapter is not a WiFi chipset — fall back."""
        r = adapt_wifi_chipset_for_runner("u4000")
        assert r["ok"] is True
        # Falls through to "generic_nl80211_monitor"
        assert "generic" in r["data"]["pick"]

    def test_chipset_ub500_unaffected(self):
        """Legacy "ub500" string is a BLE adapter, not WiFi — fall back."""
        r = adapt_wifi_chipset_for_runner("ub500")
        assert r["ok"] is True
        assert "generic" in r["data"]["pick"]

    def test_channel_width_6e(self):
        r = adapt_wifi_channel_width_for_runner(band="6ghz", target="")
        assert r["ok"] is True
        assert r["data"]["pick"] == "160mhz"


# ---------------------------------------------------------------------------
# BLE integration
# ---------------------------------------------------------------------------


class TestBleIntegration:
    def test_chipset_u4000_returns_realtek(self):
        r = adapt_ble_chipset_for_runner("u4000")
        assert r["ok"] is True
        # U4000 BLUETOOTH adapter (Realtek chipset) → realtek_via_btmon
        assert "realtek" in r["data"]["pick"]

    def test_chipset_ub500_still_works_legacy(self):
        # Older "UB500" / "UB500 Plus" labels still resolve to realtek —
        # the picker is intentionally tolerant of either spelling.
        r = adapt_ble_chipset_for_runner("ub500")
        assert r["ok"] is True
        assert "realtek" in r["data"]["pick"]

    def test_chipset_mt7922_returns_mediatek(self):
        r = adapt_ble_chipset_for_runner("mt7922")
        assert r["ok"] is True
        assert "mediatek" in r["data"]["pick"]

    def test_pairing_just_works(self):
        r = adapt_ble_pairing_for_runner(io_cap="NoInputNoOutput",
                                         auth_required=False)
        assert r["ok"] is True
        assert r["data"]["pick"] == "just_works"


# ---------------------------------------------------------------------------
# OSINT integration
# ---------------------------------------------------------------------------


class TestOsintIntegration:
    def test_email_pattern(self):
        r = poly_email_pattern_for_runner(target_domain="example.com",
                                         target_kind="person")
        assert r["ok"] is True
        for v in r["data"]["variants"]:
            assert "at_domain" in v  # template, not real email

    def test_jurisdiction_pl(self):
        r = adapt_osint_jurisdiction_for_runner("PL")
        assert r["ok"] is True
        assert "ceidg" in r["data"]["pick"]


# ---------------------------------------------------------------------------
# Forensics integration
# ---------------------------------------------------------------------------


class TestForensicsIntegration:
    def test_disk_carve(self):
        r = poly_disk_carve_signature_for_runner(image_path="/tmp/img.raw",
                                                  target_ext="jpg")
        assert r["ok"] is True

    def test_image_format_court(self):
        r = adapt_forensics_image_format_for_runner(audience="court",
                                                     has_ewf=True)
        assert r["ok"] is True
        assert "e01" in r["data"]["pick"] or "ewf" in r["data"]["pick"]

    def test_timeline_ir(self):
        r = adapt_forensics_timeline_format_for_runner(audience="ir_team")
        assert r["ok"] is True
        assert "plaso" in r["data"]["pick"]


# ---------------------------------------------------------------------------
# Post-exploit integration
# ---------------------------------------------------------------------------


class TestPostExploitIntegration:
    def test_lateral_movement(self):
        r = poly_lateral_movement_for_runner(target_os="windows",
                                              has_smb=True, has_winrm=True)
        assert r["ok"] is True
        assert "primary" in r["data"]

    def test_persistence_windows(self):
        r = poly_persistence_for_runner(target_os="windows")
        assert r["ok"] is True
        # Variants are registry keys
        for v in r["data"]["variants"]:
            assert isinstance(v, str)

    def test_persistence_mechanism_picker(self):
        r = adapt_persistence_mechanism_for_runner(target_os="linux",
                                                    survive_reboot=True)
        assert r["ok"] is True
        assert "systemd" in r["data"]["pick"]

    def test_exfil_airgap(self):
        r = adapt_exfil_channel_for_runner(egress="airgap", size_kb=500)
        assert r["ok"] is True
        assert "sneakernet" in r["data"]["pick"]


# ---------------------------------------------------------------------------
# Adversarial — never fabricate
# ---------------------------------------------------------------------------


class TestAdversarial:
    def test_no_integration_fabricates_cve(self):
        """All integration helpers — no CVE in the output."""
        import re
        helpers = [
            (poly_deauth_burst_for_wifi, {}),
            (adapt_wifi_chipset_for_runner, {"chipset": "mt7922"}),
            (adapt_ble_chipset_for_runner, {"chipset": "u4000"}),
            (poly_email_pattern_for_runner, {"target_domain": "x.com"}),
            (adapt_osint_jurisdiction_for_runner, {"jurisdiction": "PL"}),
            (poly_lateral_movement_for_runner, {"target_os": "windows"}),
            (poly_persistence_for_runner, {"target_os": "windows"}),
            (adapt_persistence_mechanism_for_runner, {"target_os": "linux"}),
            (adapt_exfil_channel_for_runner, {"egress": "airgap"}),
        ]
        for fn, args in helpers:
            r = fn(**args)
            if r["ok"]:
                blob = json.dumps(r["data"]).lower()
                cves = re.findall(r"cve-\d{4}-\d+", blob)
                assert not cves, f"{fn.__name__} fabricated CVE"

    def test_no_integration_fabricates_credentials(self):
        """No password=/hash=/ntlm: in any integration envelope."""
        helpers = [
            (poly_lateral_movement_for_runner, {"target_os": "windows"}),
            (poly_persistence_for_runner, {"target_os": "windows"}),
            (adapt_persistence_mechanism_for_runner, {"target_os": "linux"}),
            (adapt_exfil_channel_for_runner, {"egress": "airgap"}),
            (poly_email_pattern_for_runner, {"target_domain": "x.com"}),
        ]
        for fn, args in helpers:
            r = fn(**args)
            if r["ok"]:
                blob = json.dumps(r["data"]).lower()
                for bad in ("password=", "ntlm:", "hash="):
                    assert bad not in blob, (
                        f"{fn.__name__} envelope contains {bad!r}"
                    )

    def test_all_integration_uses_heuristic_model(self):
        """Every integration helper stays at 'heuristic', never ML."""
        helpers = [
            (poly_deauth_burst_for_wifi, {}),
            (adapt_wifi_chipset_for_runner, {"chipset": "mt7922"}),
            (adapt_ble_chipset_for_runner, {"chipset": "u4000"}),
            (poly_email_pattern_for_runner, {"target_domain": "x.com"}),
            (poly_disk_carve_signature_for_runner, {"image_path": "/tmp/x"}),
            (poly_lateral_movement_for_runner, {"target_os": "windows"}),
            (poly_persistence_for_runner, {"target_os": "windows"}),
            (adapt_persistence_mechanism_for_runner, {"target_os": "linux"}),
            (adapt_exfil_channel_for_runner, {"egress": "default"}),
        ]
        for fn, args in helpers:
            r = fn(**args)
            if r["ok"]:
                m = r["data"].get("model", "")
                assert "heuristic" in m, (
                    f"{fn.__name__} claims model={m!r}"
                )
