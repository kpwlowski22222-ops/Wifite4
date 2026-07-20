"""Hermetic tests for the iOS target-class runner.

Covers all 8 read methods + the registry + the runner's
single-gate invariant (no ``confirm_fn`` / ``self.confirm`` inside
the dispatch paths).

Hermetic: no idevice_id, no usbmuxd, no frida, no objection
required. All subprocess calls are exercised through a
``run=CompletedProcess-like`` mock injected via ``args.run``.
"""
from __future__ import annotations

import json
import re
import unittest
from pathlib import Path


from core.ios.runner import (
    IOS_ATTACKS,
    IOS_METHODS,
    IOSRunner,
    run_attack,
)


class TestLibimobiledeviceListDevices(unittest.TestCase):
    """Method 1: libimobiledevice_list_devices (pure parse)."""

    def test_missing_output(self) -> None:
        r = run_attack("libimobiledevice_list_devices", args={})
        self.assertFalse(r["ok"])

    def test_parses_canonical_udids(self) -> None:
        # UDIDs are 40 hex chars (when stripped of dashes).
        # We use 40-char flat hex to satisfy the regex.
        text = ("00008101001234567890abcdef0102030a0b0c0d\n"
                "00008110001a2b3c4d5e6f70801020300a0b0c0d\n")
        r = run_attack("libimobiledevice_list_devices",
                       args={"idevice_id_output": text})
        self.assertTrue(r["ok"])
        d = r["data"]
        self.assertEqual(d["device_count"], 2)
        # UDIDs are normalised to 40-hex (no dashes, lowercase).
        self.assertEqual(d["devices"][0]["udid"],
                         "00008101001234567890abcdef0102030a0b0c0d")
        self.assertEqual(d["devices"][1]["udid"],
                         "00008110001a2b3c4d5e6f70801020300a0b0c0d")

    def test_no_devices(self) -> None:
        r = run_attack("libimobiledevice_list_devices",
                       args={"idevice_id_output": ""})
        self.assertFalse(r["ok"])

    def test_ignores_invalid_udid(self) -> None:
        text = "not-a-udid\n00008101001234567890abcdef0102030a0b0c0d\n"
        r = run_attack("libimobiledevice_list_devices",
                       args={"idevice_id_output": text})
        self.assertTrue(r["ok"])
        self.assertEqual(r["data"]["device_count"], 1)

    def test_dashed_udid_format(self) -> None:
        # Apple's printed format includes dashes; the parser
        # strips them and expects 40 hex chars total.
        # Build: 8-4-4-4-16 = 40 hex (UUID5).
        flat = "00008101001234567890abcdef0102030a0b0c0d"
        dashed = (flat[0:8] + "-" + flat[8:12] + "-" + flat[12:16] +
                  "-" + flat[16:20] + "-" + flat[20:40])
        text = dashed + "\n"
        r = run_attack("libimobiledevice_list_devices",
                       args={"idevice_id_output": text})
        self.assertTrue(r["ok"])
        self.assertEqual(r["data"]["device_count"], 1)
        self.assertEqual(r["data"]["devices"][0]["udid"], flat)


class TestUsbmuxdListConnected(unittest.TestCase):
    """Method 2: usbmuxd_list_connected (pure parse)."""

    def test_missing_output(self) -> None:
        r = run_attack("usbmuxd_list_connected", args={})
        self.assertFalse(r["ok"])

    def test_parses_whitespace_listing(self) -> None:
        text = ("00008101001234567890abcdef0102030a0b0c0d  C02ABCDEFGH5\n"
                "00008110001a2b3c4d5e6f70801020300a0b0c0d  C02XYZWVUT0P\n")
        r = run_attack("usbmuxd_list_connected",
                       args={"usbmuxd_output": text})
        self.assertTrue(r["ok"])
        d = r["data"]
        self.assertEqual(d["device_count"], 2)
        self.assertEqual(d["devices"][0]["udid"],
                         "00008101001234567890abcdef0102030a0b0c0d")
        self.assertEqual(d["devices"][0]["serial"], "C02ABCDEFGH5")

    def test_parses_json_listing(self) -> None:
        text = json.dumps([
            {"DeviceID": "00008101001234567890abcdef0102030a0b0c0d",
             "SerialNumber": "C02ABCDEFGH5",
             "ProductID": "0x12a8",
             "LocationID": "0x14100000"},
            {"DeviceID": "00008110001a2b3c4d5e6f70801020300a0b0c0d",
             "SerialNumber": "C02XYZWVUT0P"},
        ])
        r = run_attack("usbmuxd_list_connected",
                       args={"usbmuxd_output": text})
        self.assertTrue(r["ok"])
        d = r["data"]
        self.assertEqual(d["device_count"], 2)
        self.assertEqual(d["devices"][0]["udid"],
                         "00008101001234567890abcdef0102030a0b0c0d")
        self.assertEqual(d["devices"][0]["product_id"], "0x12a8")
        self.assertEqual(d["devices"][0]["location_id"], "0x14100000")
        # Second device has no product/location.
        self.assertEqual(d["devices"][1]["product_id"], "")

    def test_invalid_json_falls_back(self) -> None:
        # JSON-prefixed but invalid → falls back to whitespace
        # parser.
        text = "[invalid\n00008101001234567890abcdef0102030a0b0c0d\n"
        r = run_attack("usbmuxd_list_connected",
                       args={"usbmuxd_output": text})
        self.assertTrue(r["ok"])
        self.assertEqual(r["data"]["device_count"], 1)

    def test_empty(self) -> None:
        # Empty / whitespace-only → no devices.
        r = run_attack("usbmuxd_list_connected",
                       args={"usbmuxd_output": ""})
        self.assertFalse(r["ok"])


class TestIdeviceinfoDump(unittest.TestCase):
    """Method 3: ideviceinfo_dump (pure parse)."""

    def test_missing_output(self) -> None:
        r = run_attack("ideviceinfo_dump", args={})
        self.assertFalse(r["ok"])

    def test_parses_canonical(self) -> None:
        text = ("DeviceName: Test iPhone\n"
                "ProductType: iPhone15,2\n"
                "ProductVersion: 17.0\n"
                "BuildVersion: 21A328\n"
                "ModelNumber: MQ9G3LL/A\n"
                "SerialNumber: F4LXX0YXP7J\n"
                "UniqueDeviceID: 00008101001234567890abcdef0102030a0b0c0d\n"
                "InternationalMobileEquipmentIdentity: 123456789012345\n")
        r = run_attack("ideviceinfo_dump",
                       args={"ideviceinfo_output": text})
        self.assertTrue(r["ok"])
        d = r["data"]
        self.assertEqual(d["device_name"], "Test iPhone")
        self.assertEqual(d["product_type"], "iPhone15,2")
        self.assertEqual(d["product_version"], "17.0")
        self.assertEqual(d["version_class"], "ios_17_plus")
        self.assertEqual(d["build_version"], "21A328")
        self.assertEqual(d["model"], "MQ9G3LL/A")
        self.assertEqual(d["serial"], "F4LXX0YXP7J")
        self.assertEqual(d["udid"], "00008101001234567890abcdef0102030a0b0c0d")
        self.assertEqual(d["imei"], "123456789012345")

    def test_classify_ios_versions(self) -> None:
        from core.ios.runner import _classify_ios_version
        self.assertEqual(_classify_ios_version("17.0"), "ios_17_plus")
        self.assertEqual(_classify_ios_version("16.5"), "ios_16_plus")
        self.assertEqual(_classify_ios_version("15.4"), "ios_15_plus")
        self.assertEqual(_classify_ios_version("14.0"), "ios_14_plus")
        self.assertEqual(_classify_ios_version("13.7"), "ios_13_plus")
        self.assertEqual(_classify_ios_version("12.5"), "ios_12_plus")
        self.assertEqual(_classify_ios_version(""), "unknown")
        self.assertEqual(_classify_ios_version("garbage"), "unknown")

    def test_no_kv_pairs(self) -> None:
        r = run_attack("ideviceinfo_dump",
                       args={"ideviceinfo_output": "garbage lines\n"})
        self.assertFalse(r["ok"])
        self.assertIn("no key/value", r["error"])

    def test_duplicate_keys_first_wins(self) -> None:
        text = ("DeviceName: First\n"
                "DeviceName: Second\n")
        r = run_attack("ideviceinfo_dump",
                       args={"ideviceinfo_output": text})
        self.assertTrue(r["ok"])
        self.assertEqual(r["data"]["device_name"], "First")


class TestIdevicedebugAppsList(unittest.TestCase):
    """Method 4: idevicedebug_apps_list (pure parse)."""

    def test_missing_output(self) -> None:
        r = run_attack("idevicedebug_apps_list", args={})
        self.assertFalse(r["ok"])

    def test_parses_canonical(self) -> None:
        text = ("Applications and Services\n"
                "-------------------------\n"
                "  com.apple.example\n"
                "  com.example.app\n"
                "  com.example.debug\n"
                "(1) Some Service Header\n")  # parenthesized → skip
        r = run_attack("idevicedebug_apps_list",
                       args={"debugserver_output": text})
        self.assertTrue(r["ok"])
        d = r["data"]
        self.assertEqual(d["app_count"], 3)
        ids = {a["bundle_id"] for a in d["apps"]}
        self.assertEqual(ids, {"com.apple.example", "com.example.app",
                               "com.example.debug"})

    def test_no_apps(self) -> None:
        text = "Applications and Services\n-------------------------\n"
        r = run_attack("idevicedebug_apps_list",
                       args={"debugserver_output": text})
        self.assertTrue(r["ok"])
        self.assertEqual(r["data"]["app_count"], 0)

    def test_caps_at_50(self) -> None:
        text = "Applications and Services\n" + "com.app.bundle.id\n" * 60
        r = run_attack("idevicedebug_apps_list",
                       args={"debugserver_output": text})
        self.assertTrue(r["ok"])
        self.assertEqual(r["data"]["app_count"], 60)
        self.assertEqual(len(r["data"]["apps"]), 50)


class TestIdevicebackup2List(unittest.TestCase):
    """Method 5: idevicebackup2_list (pure parse)."""

    def test_missing_output(self) -> None:
        r = run_attack("idevicebackup2_list", args={})
        self.assertFalse(r["ok"])

    def test_parses_one_backup(self) -> None:
        text = ("Backup directory: /tmp/backup1\n"
                "Unique Identifier: 00008101001234567890abcdef0102030a0b0c0d\n"
                "Target Identifier: 00008101001234567890abcdef0102030a0b0c0d\n"
                "Product Version: 16.5\n"
                "Backup Time: 1696420000\n")
        r = run_attack("idevicebackup2_list",
                       args={"backup2_output": text})
        self.assertTrue(r["ok"])
        d = r["data"]
        self.assertEqual(d["backup_count"], 1)
        b = d["backups"][0]
        self.assertEqual(b["backup_directory"], "/tmp/backup1")
        self.assertEqual(b["unique_identifier"],
                         "00008101001234567890abcdef0102030a0b0c0d")
        self.assertEqual(b["product_version"], "16.5")
        self.assertEqual(b["backup_time"], "1696420000")

    def test_parses_multiple_backups(self) -> None:
        text = ("Backup directory: /tmp/backup1\n"
                "Unique Identifier: 00008101001234567890abcdef0102030a0b0c0d\n"
                "\n"
                "Backup directory: /tmp/backup2\n"
                "Unique Identifier: 00008110-001A2B3C4D5E6F708\n"
                "\n")
        r = run_attack("idevicebackup2_list",
                       args={"backup2_output": text})
        self.assertTrue(r["ok"])
        self.assertEqual(r["data"]["backup_count"], 2)


class TestFridaIosDumpBundleId(unittest.TestCase):
    """Method 6: frida_ios_dump_bundle_id (pure parse)."""

    def test_missing_output(self) -> None:
        r = run_attack("frida_ios_dump_bundle_id", args={})
        self.assertFalse(r["ok"])

    def test_parses_plain(self) -> None:
        text = "com.apple.example\ncom.example.app\n"
        r = run_attack("frida_ios_dump_bundle_id",
                       args={"frida_ios_dump_output": text})
        self.assertTrue(r["ok"])
        d = r["data"]
        self.assertEqual(d["app_count"], 2)
        ids = {a["bundle_id"] for a in d["apps"]}
        self.assertEqual(ids, {"com.apple.example", "com.example.app"})

    def test_parses_with_pid_prefix(self) -> None:
        text = ("[iPhone::PID::1234] com.apple.example\n"
                "[iPhone::PID::1235] com.example.app\n")
        r = run_attack("frida_ios_dump_bundle_id",
                       args={"frida_ios_dump_output": text})
        self.assertTrue(r["ok"])
        self.assertEqual(r["data"]["app_count"], 2)

    def test_dedup(self) -> None:
        text = "com.example.app\ncom.example.app\ncom.example.app\n"
        r = run_attack("frida_ios_dump_bundle_id",
                       args={"frida_ios_dump_output": text})
        self.assertTrue(r["ok"])
        self.assertEqual(r["data"]["app_count"], 1)


class TestObjectionEnvironmentInventory(unittest.TestCase):
    """Method 7: objection_environment_inventory (pure parse)."""

    def test_missing_output(self) -> None:
        r = run_attack("objection_environment_inventory", args={})
        self.assertFalse(r["ok"])

    def test_parses_canonical(self) -> None:
        text = ("Bundle Identifier: com.example.app\n"
                "Version: 1.2.3\n"
                "Platform: ios\n"
                "Arch: arm64\n"
                "Linked Frameworks: UIKit, Foundation, Security\n"
                "Jailbroken: false\n"
                "Simulator: false\n"
                "Encrypted: true\n"
                "Canary: false\n")
        r = run_attack("objection_environment_inventory",
                       args={"objection_output": text})
        self.assertTrue(r["ok"])
        d = r["data"]
        self.assertEqual(d["bundle_id"], "com.example.app")
        self.assertEqual(d["version"], "1.2.3")
        self.assertEqual(d["platform"], "ios")
        self.assertEqual(d["arch"], "arm64")
        self.assertEqual(d["linked_frameworks"],
                         ["UIKit", "Foundation", "Security"])
        self.assertFalse(d["jailbroken"])
        self.assertFalse(d["simulator"])
        self.assertTrue(d["encrypted"])
        self.assertFalse(d["canary"])

    def test_jailbroken_true(self) -> None:
        text = ("Jailbroken: true\n"
                "Simulator: yes\n")
        r = run_attack("objection_environment_inventory",
                       args={"objection_output": text})
        self.assertTrue(r["ok"])
        self.assertTrue(r["data"]["jailbroken"])
        self.assertTrue(r["data"]["simulator"])

    def test_empty_output(self) -> None:
        r = run_attack("objection_environment_inventory",
                       args={"objection_output": ""})
        self.assertFalse(r["ok"])


class TestNmapAppleMdnsDiscovery(unittest.TestCase):
    """Method 8: nmap_apple_mdns_discovery."""

    def test_missing_target(self) -> None:
        r = run_attack("nmap_apple_mdns_discovery", args={})
        self.assertFalse(r["ok"])
        self.assertIn("target", r["error"])

    def test_missing_nmap_degrades(self) -> None:
        import shutil
        if shutil.which("nmap"):
            self.skipTest("nmap installed; can't exercise degrade path")
        r = run_attack("nmap_apple_mdns_discovery",
                       args={"target": "192.168.1.50"})
        self.assertFalse(r["ok"])
        self.assertIn("nmap", r["error"])
        self.assertTrue(r["data"]["degraded"])

    def test_parsed_with_run_injection(self) -> None:
        out = ("PORT     STATE SERVICE VERSION\n"
               "5353/tcp open  mdns    mDNS\n"
               "62078/tcp open  iphone-sync Apple iPhone sync\n")

        class _R:
            stdout = out

        r = run_attack("nmap_apple_mdns_discovery",
                       args={"target": "192.168.1.50", "run": _R()})
        self.assertTrue(r["ok"])
        d = r["data"]
        self.assertEqual(d["target"], "192.168.1.50")
        self.assertTrue(d["mdns_open"])
        self.assertTrue(d["itunes_sync_open"])
        self.assertEqual(len(d["services"]), 2)

    def test_only_mdns(self) -> None:
        out = ("PORT     STATE SERVICE VERSION\n"
               "5353/tcp open  mdns    mDNS\n")

        class _R:
            stdout = out

        r = run_attack("nmap_apple_mdns_discovery",
                       args={"target": "192.168.1.50", "run": _R()})
        self.assertTrue(r["ok"])
        self.assertTrue(r["data"]["mdns_open"])
        self.assertFalse(r["data"]["itunes_sync_open"])

    def test_empty_nmap(self) -> None:
        class _R:
            stdout = ""

        r = run_attack("nmap_apple_mdns_discovery",
                       args={"target": "192.168.1.50", "run": _R()})
        self.assertTrue(r["ok"])
        self.assertEqual(len(r["data"]["services"]), 0)


class TestRegistryAndSingleGate(unittest.TestCase):
    """Registry + the single-gate invariant."""

    def test_methods_count(self) -> None:
        self.assertEqual(len(IOS_METHODS), 8)
        self.assertEqual(len(IOS_ATTACKS), 8)

    def test_registry_names_unique(self) -> None:
        names = [a["name"] for a in IOS_ATTACKS]
        self.assertEqual(len(names), len(set(names)))
        for n in names:
            self.assertTrue(n.startswith("ios_attack_"))

    def test_registry_risk_level_read(self) -> None:
        for a in IOS_ATTACKS:
            self.assertEqual(a["risk_level"], "read")

    def test_unknown_method(self) -> None:
        r = run_attack("nope", args={})
        self.assertFalse(r["ok"])
        self.assertIn("unknown", r["error"])

    def test_no_re_confirm(self) -> None:
        runner_src = Path("core/ios/runner.py").read_text(encoding="utf-8")
        self.assertNotRegex(runner_src, r"confirm_fn")
        self.assertNotRegex(runner_src, r"self\.confirm")

    def test_no_bare_except(self) -> None:
        runner_src = Path("core/ios/runner.py").read_text(encoding="utf-8")
        bad = [ln for ln in runner_src.splitlines()
               if re.match(r"^\s*except\s*:\s*$", ln)]
        self.assertFalse(bad, f"bare except clauses: {bad}")

    def test_module_imports_clean(self) -> None:
        import core.ios.runner as m
        self.assertTrue(hasattr(m, "IOSRunner"))
        self.assertTrue(hasattr(m, "run_attack"))
        self.assertTrue(hasattr(m, "IOS_METHODS"))
        self.assertTrue(hasattr(m, "IOS_ATTACKS"))

    def test_runner_dispatch_envelope(self) -> None:
        r = IOSRunner(args={}).run_attack("nope")
        self.assertIn("ok", r)
        self.assertIn("error", r)
        self.assertIn("name", r)
        self.assertIn("duration_s", r)
        self.assertFalse(r["ok"])


if __name__ == "__main__":
    unittest.main()
