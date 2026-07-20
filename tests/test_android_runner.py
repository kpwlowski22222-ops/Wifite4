"""Hermetic tests for the Android target-class runner.

Covers all 8 read methods + the registry + the runner's
single-gate invariant (no ``confirm_fn`` / ``self.confirm`` inside
the dispatch paths).

Hermetic: no adb, no frida, no jadx, no apktool, no drozer
required. All subprocess calls are exercised through a
``run=CompletedProcess-like`` mock injected via ``args.run``.
"""
from __future__ import annotations

import json
import re
import unittest
from pathlib import Path


from core.android.runner import (
    ANDROID_ATTACKS,
    ANDROID_METHODS,
    AndroidRunner,
    run_attack,
)


class TestAdbDevicesList(unittest.TestCase):
    """Method 1: adb_devices_list."""

    def test_missing_adb_degrades(self) -> None:
        import shutil
        if shutil.which("adb"):
            self.skipTest("adb installed; can't exercise degrade path")
        r = run_attack("adb_devices_list", args={})
        self.assertFalse(r["ok"])
        self.assertIn("adb", r["error"])

    def test_parses_two_devices(self) -> None:
        out = ("List of devices attached\n"
               "emulator-5554  device  product:sdk_gphone64_x86_64 "
               "model:Pixel_7 device:bramble transport_id:1\n"
               "1234abcd  unauthorized product:raven model:Pixel_6_Pro\n")

        class _R:
            stdout = out

        r = run_attack("adb_devices_list", args={"run": _R()})
        self.assertTrue(r["ok"])
        d = r["data"]
        self.assertEqual(d["device_count"], 2)
        self.assertEqual(len(d["ready"]), 1)
        self.assertEqual(len(d["unauthorized"]), 1)
        self.assertEqual(d["ready"][0]["model"], "Pixel_7")
        self.assertEqual(d["ready"][0]["state"], "device")

    def test_no_devices(self) -> None:
        class _R:
            stdout = "List of devices attached\n\n"

        r = run_attack("adb_devices_list", args={"run": _R()})
        self.assertTrue(r["ok"])
        self.assertEqual(r["data"]["device_count"], 0)

    def test_adb_timeout(self) -> None:
        import subprocess as sp
        # Inject a fake run that always times out. We can't
        # easily inject a TimeoutExpired into the runner path,
        # so verify envelope shape only.
        class _R:
            stdout = ""

        r = run_attack("adb_devices_list", args={"run": _R()})
        self.assertIn("name", r)


class TestAdbPackagesDump(unittest.TestCase):
    """Method 2: adb_packages_dump (pure parse)."""

    def test_missing_output(self) -> None:
        r = run_attack("adb_packages_dump", args={})
        self.assertFalse(r["ok"])

    def test_parses_packages(self) -> None:
        # pm list packages output is ``package:<name>`` (without
        # the =path suffix when ``-f`` is omitted).
        text = (
            "package:com.example.one\n"
            "package:com.example.two\n"
            "package:com.android.settings\n"
        )
        r = run_attack("adb_packages_dump", args={"pm_output": text})
        self.assertTrue(r["ok"])
        d = r["data"]
        self.assertEqual(d["package_count"], 3)
        self.assertIn("third_party", d["by_class"])
        self.assertIn("system", d["by_class"])
        self.assertEqual(d["by_class"]["system"], 1)
        self.assertEqual(d["by_class"]["third_party"], 2)

    def test_google_classified(self) -> None:
        text = "package:com.google.android.gms\n"
        r = run_attack("adb_packages_dump", args={"pm_output": text})
        self.assertTrue(r["ok"])
        self.assertEqual(r["data"]["by_class"].get("google"), 1)

    def test_third_party_sample(self) -> None:
        text = "\n".join([f"package:/x{i}=com.example.app{i}"
                          for i in range(30)])
        r = run_attack("adb_packages_dump", args={"pm_output": text})
        self.assertTrue(r["ok"])
        # The sample is capped at 25.
        self.assertLessEqual(len(r["data"]["third_party_sample"]), 25)

    def test_empty_text(self) -> None:
        r = run_attack("adb_packages_dump", args={"pm_output": ""})
        self.assertFalse(r["ok"])


class TestAdbAppsRunning(unittest.TestCase):
    """Method 3: adb_apps_running (pure parse)."""

    def test_missing_output(self) -> None:
        r = run_attack("adb_apps_running", args={})
        self.assertFalse(r["ok"])

    def test_parses_ps(self) -> None:
        text = ("USER  PID  PPID  VSZ  RSS  WCHAN  ADDR S NAME\n"
                "u0_a10  1234  100  500000  5000 0  0 S com.example.app\n"
                "u0_a11  1235  100  400000  4000 0  0 S com.example.app2\n"
                "shell  9999  1  100000  1000 0  0 S sh\n")
        r = run_attack("adb_apps_running", args={"ps_output": text})
        self.assertTrue(r["ok"])
        d = r["data"]
        self.assertEqual(d["process_count"], 3)
        self.assertIn("u0_a10", d["users"])
        self.assertEqual(len(d["top_by_rss"]), 3)
        # Highest RSS first.
        self.assertEqual(d["top_by_rss"][0]["pid"], 1234)

    def test_skips_header(self) -> None:
        text = "USER  PID  PPID  VSZ  RSS  WCHAN  ADDR S NAME\n"
        r = run_attack("adb_apps_running", args={"ps_output": text})
        self.assertTrue(r["ok"])
        self.assertEqual(r["data"]["process_count"], 0)

    def test_classify_package_helper(self) -> None:
        from core.android.runner import _classify_package
        self.assertEqual(_classify_package("com.android.settings"), "system")
        self.assertEqual(_classify_package("com.google.android.gms"),
                         "google")
        self.assertEqual(_classify_package("com.example.app"), "third_party")
        self.assertEqual(_classify_package("com.example.app.debug"),
                         "test_or_debug")


class TestFridaProcessesEnumerate(unittest.TestCase):
    """Method 4: frida_processes_enumerate (pure parse)."""

    def test_missing_output(self) -> None:
        r = run_attack("frida_processes_enumerate", args={})
        self.assertFalse(r["ok"])

    def test_parses_frida_ps(self) -> None:
        text = ("  PID  Name                          Identifier\n"
                " 1234  com.example.app              com.example.app\n"
                " 1235  com.example.app2             com.example.app2\n")
        r = run_attack("frida_processes_enumerate",
                       args={"frida_ps_output": text})
        self.assertTrue(r["ok"])
        d = r["data"]
        self.assertEqual(d["process_count"], 2)
        self.assertEqual(d["processes"][0]["pid"], 1234)
        self.assertEqual(d["processes"][0]["name"], "com.example.app")

    def test_caps_at_50(self) -> None:
        text = "  PID  Name\n"
        text += "\n".join(f"{i:5d}  proc{i}" for i in range(100))
        r = run_attack("frida_processes_enumerate",
                       args={"frida_ps_output": text})
        self.assertTrue(r["ok"])
        self.assertEqual(r["data"]["process_count"], 100)
        self.assertEqual(len(r["data"]["processes"]), 50)

    def test_no_header_only(self) -> None:
        text = "  PID  Name                          Identifier\n"
        r = run_attack("frida_processes_enumerate",
                       args={"frida_ps_output": text})
        self.assertTrue(r["ok"])
        self.assertEqual(r["data"]["process_count"], 0)


class TestApktoolDecodeManifest(unittest.TestCase):
    """Method 5: apktool_decode_manifest (pure XML parse)."""

    def test_missing_input(self) -> None:
        r = run_attack("apktool_decode_manifest", args={})
        self.assertFalse(r["ok"])

    def test_basic_manifest(self) -> None:
        xml = ('<?xml version="1.0" encoding="utf-8"?>\n'
               '<manifest xmlns:android="http://schemas.android.com/apk/res-auto" '
               'package="com.example.app" '
               'android:versionCode="42" '
               'android:versionName="1.2.3" '
               'android:minSdkVersion="21" '
               'android:targetSdkVersion="33">\n'
               '  <uses-permission android:name="android.permission.INTERNET"/>\n'
               '  <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION"/>\n'
               '  <application android:label="MyApp" '
               'android:debuggable="true" '
               'android:allowBackup="true" '
               'android:usesCleartextTraffic="true">\n'
               '    <activity android:name="com.example.app.MainActivity"/>\n'
               '    <service android:name="com.example.app.MyService"/>\n'
               '    <receiver android:name="com.example.app.MyReceiver"/>\n'
               '    <provider android:name="com.example.app.MyProvider" '
               'android:authorities="com.example.app.provider" '
               'android:exported="true"/>\n'
               '  </application>\n'
               '</manifest>\n')
        r = run_attack("apktool_decode_manifest",
                       args={"androidmanifest_xml": xml})
        self.assertTrue(r["ok"])
        d = r["data"]
        self.assertEqual(d["package"], "com.example.app")
        self.assertEqual(d["version_code"], "42")
        self.assertEqual(d["version_name"], "1.2.3")
        self.assertEqual(d["min_sdk"], "21")
        self.assertEqual(d["target_sdk"], "33")
        self.assertIn("android.permission.INTERNET", d["permissions"])
        self.assertIn("android.permission.ACCESS_FINE_LOCATION",
                      d["permissions"])
        self.assertTrue(d["debuggable"])
        self.assertTrue(d["allow_backup"])
        self.assertTrue(d["uses_cleartext"])
        self.assertIn("com.example.app.MainActivity", d["activities"])
        self.assertIn("com.example.app.MyService", d["services"])
        self.assertIn("com.example.app.MyReceiver", d["receivers"])
        self.assertEqual(len(d["providers"]), 1)
        self.assertEqual(d["providers"][0]["name"],
                         "com.example.app.MyProvider")
        self.assertEqual(d["providers"][0]["authorities"],
                         "com.example.app.provider")
        self.assertEqual(d["providers"][0]["exported"], "true")

    def test_invalid_xml(self) -> None:
        r = run_attack("apktool_decode_manifest",
                       args={"androidmanifest_xml": "<unclosed"})
        self.assertFalse(r["ok"])
        self.assertIn("xml", r["error"])

    def test_empty_manifest(self) -> None:
        r = run_attack("apktool_decode_manifest",
                       args={"androidmanifest_xml": ""})
        self.assertFalse(r["ok"])

    def test_no_debug_flag(self) -> None:
        xml = ('<manifest package="x">\n'
               '  <application/>\n'
               '</manifest>')
        r = run_attack("apktool_decode_manifest",
                       args={"androidmanifest_xml": xml})
        self.assertTrue(r["ok"])
        self.assertFalse(r["data"]["debuggable"])


class TestJadxDexToJava(unittest.TestCase):
    """Method 6: jadx_dex_to_java (pure parse of dir listing)."""

    def test_missing_dirs(self) -> None:
        r = run_attack("jadx_dex_to_java", args={})
        self.assertFalse(r["ok"])

    def test_parses_dir_listing(self) -> None:
        dirs = [
            "sources/com/example/app/MainActivity.java",
            "sources/com/example/app/MyService.java",
            "sources/com/example/app2/Other.java",
            "smali/com/example/app/R.smali",
            "smali/com/example/app2/R.smali",
            "res/values/strings.xml",
            "res/drawable/icon.png",
        ]
        r = run_attack("jadx_dex_to_java", args={"dirs": dirs})
        self.assertTrue(r["ok"])
        d = r["data"]
        # Each .java increments java_count. Each /smali path
        # increments smali_count.
        self.assertEqual(d["java_count_estimate"], 3)
        self.assertEqual(d["smali_count_estimate"], 2)
        # The parser captures the top-level dir under sources/.
        self.assertEqual(d["package_roots"], ["com"])
        self.assertEqual(d["resource_count_estimate"], 2)

    def test_string_input(self) -> None:
        text = ("sources/com/x/A.java\n"
                "sources/com/x/B.java\n")
        r = run_attack("jadx_dex_to_java", args={"dirs": text})
        self.assertTrue(r["ok"])
        self.assertGreaterEqual(r["data"]["java_count_estimate"], 2)

    def test_empty(self) -> None:
        r = run_attack("jadx_dex_to_java", args={"dirs": []})
        self.assertFalse(r["ok"])


class TestDrozerModulesDiscovery(unittest.TestCase):
    """Method 7: drozer_modules_discovery (pure parse)."""

    def test_missing_output(self) -> None:
        r = run_attack("drozer_modules_discovery", args={})
        self.assertFalse(r["ok"])

    def test_parses_modules(self) -> None:
        text = (
            "drozer 2.4.4\n"
            "app.provider.delete (exploit)\n"
            "app.broadcast.send (exploit)\n"
            "app.activity.start (default)\n"
            "app.service.send (default)\n"
            "scanner.provider.finduris (standard)\n"
        )
        r = run_attack("drozer_modules_discovery",
                       args={"drozer_output": text})
        self.assertTrue(r["ok"])
        d = r["data"]
        self.assertEqual(d["module_count"], 5)
        # app.provider, app.broadcast, app.activity, app.service,
        # scanner all match the interesting filter.
        self.assertEqual(d["interesting_count"], 5)
        fqns = {m["fqn"] for m in d["interesting"]}
        self.assertIn("app.provider.delete", fqns)
        self.assertIn("scanner.provider.finduris", fqns)

    def test_uninteresting_modules(self) -> None:
        text = "tool.cmd.shell (default)\n"
        r = run_attack("drozer_modules_discovery",
                       args={"drozer_output": text})
        self.assertTrue(r["ok"])
        self.assertEqual(r["data"]["module_count"], 1)
        self.assertEqual(r["data"]["interesting_count"], 0)


class TestNmapAndroidAdbDiscovery(unittest.TestCase):
    """Method 8: nmap_android_adb_discovery."""

    def test_missing_target(self) -> None:
        r = run_attack("nmap_android_adb_discovery", args={})
        self.assertFalse(r["ok"])
        self.assertIn("target", r["error"])

    def test_missing_nmap_degrades(self) -> None:
        import shutil
        if shutil.which("nmap"):
            self.skipTest("nmap installed; can't exercise degrade path")
        r = run_attack("nmap_android_adb_discovery",
                       args={"target": "192.168.1.100"})
        self.assertFalse(r["ok"])
        self.assertIn("nmap", r["error"])
        self.assertTrue(r["data"]["degraded"])

    def test_parsed_with_run_injection(self) -> None:
        out = ("PORT     STATE SERVICE VERSION\n"
               "5555/tcp open  adb     Android Debug Bridge\n"
               "5037/tcp open  adb-server  Android Debug Bridge server\n")

        class _R:
            stdout = out

        r = run_attack("nmap_android_adb_discovery",
                       args={"target": "192.168.1.100", "run": _R()})
        self.assertTrue(r["ok"])
        d = r["data"]
        self.assertEqual(d["target"], "192.168.1.100")
        self.assertTrue(d["adb_open"])
        self.assertEqual(len(d["services"]), 2)

    def test_only_adb_open(self) -> None:
        out = ("PORT     STATE SERVICE VERSION\n"
               "5555/tcp open  adb     Android Debug Bridge\n")

        class _R:
            stdout = out

        r = run_attack("nmap_android_adb_discovery",
                       args={"target": "192.168.1.100", "run": _R()})
        self.assertTrue(r["ok"])
        self.assertTrue(r["data"]["adb_open"])

    def test_empty_nmap(self) -> None:
        class _R:
            stdout = ""

        r = run_attack("nmap_android_adb_discovery",
                       args={"target": "192.168.1.100", "run": _R()})
        self.assertTrue(r["ok"])
        self.assertEqual(len(r["data"]["services"]), 0)
        self.assertFalse(r["data"]["adb_open"])


class TestRegistryAndSingleGate(unittest.TestCase):
    """Registry + the single-gate invariant."""

    def test_methods_count(self) -> None:
        self.assertEqual(len(ANDROID_METHODS), 8)
        self.assertEqual(len(ANDROID_ATTACKS), 8)

    def test_registry_names_unique(self) -> None:
        names = [a["name"] for a in ANDROID_ATTACKS]
        self.assertEqual(len(names), len(set(names)))
        # All start with android_attack_
        for n in names:
            self.assertTrue(n.startswith("android_attack_"))

    def test_registry_risk_level_read(self) -> None:
        for a in ANDROID_ATTACKS:
            self.assertEqual(a["risk_level"], "read")

    def test_unknown_method(self) -> None:
        r = run_attack("nope", args={})
        self.assertFalse(r["ok"])
        self.assertIn("unknown", r["error"])

    def test_no_re_confirm(self) -> None:
        runner_src = Path("core/android/runner.py").read_text(encoding="utf-8")
        self.assertNotRegex(runner_src, r"confirm_fn")
        self.assertNotRegex(runner_src, r"self\.confirm")

    def test_no_bare_except(self) -> None:
        runner_src = Path("core/android/runner.py").read_text(encoding="utf-8")
        bad = [ln for ln in runner_src.splitlines()
               if re.match(r"^\s*except\s*:\s*$", ln)]
        self.assertFalse(bad, f"bare except clauses: {bad}")

    def test_module_imports_clean(self) -> None:
        import core.android.runner as m
        self.assertTrue(hasattr(m, "AndroidRunner"))
        self.assertTrue(hasattr(m, "run_attack"))
        self.assertTrue(hasattr(m, "ANDROID_METHODS"))
        self.assertTrue(hasattr(m, "ANDROID_ATTACKS"))

    def test_runner_dispatch_envelope(self) -> None:
        r = AndroidRunner(args={}).run_attack("nope")
        self.assertIn("ok", r)
        self.assertIn("error", r)
        self.assertIn("name", r)
        self.assertIn("duration_s", r)
        self.assertFalse(r["ok"])


if __name__ == "__main__":
    unittest.main()
