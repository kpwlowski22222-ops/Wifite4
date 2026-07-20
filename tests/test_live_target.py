"""Hermetic tests for the core.live_target module.

Covers:
  * 9 safe patches (3 per target class)
  * The validator (shell metas, forbidden exec APIs)
  * The run_patch entrypoint
  * Round-trip data shape

Hermetic: no PowerShell, no Frida, no apktool, no plistlib, no
Cypher. Pure text operations.
"""
from __future__ import annotations

import os
import re
import tempfile
import unittest
from pathlib import Path

from core.live_target import (
    LIVE_TARGET_PATCHES,
    run_patch,
)
from core.live_target.validator import (
    validate_params,
    validate_swap,
    canonicalize_artifact,
)


class TestValidator(unittest.TestCase):
    """The validator's rejection paths."""

    def test_validate_swap_rejects_shell_meta(self) -> None:
        # The new string is what gets injected. A shell meta
        # in the new value must be rejected.
        v = validate_swap("microsoft", "swap_powerview_filter",
                          "*", "evil; drop tables")
        self.assertFalse(v["ok"])
        self.assertIn("shell", v["error"])

    def test_validate_swap_rejects_backtick(self) -> None:
        v = validate_swap("microsoft", "swap_powerview_filter",
                          "*", "evil`uname`")
        self.assertFalse(v["ok"])

    def test_validate_swap_rejects_pipe(self) -> None:
        v = validate_swap("microsoft", "swap_powerview_filter",
                          "*", "evil|cat")
        self.assertFalse(v["ok"])

    def test_validate_swap_accepts_safe(self) -> None:
        v = validate_swap("microsoft", "swap_powerview_filter",
                          "*", "samaccountname=admin")
        self.assertTrue(v["ok"])

    def test_validate_swap_rejects_powershell_iex(self) -> None:
        # Use a string that doesn't contain shell metas but
        # matches the PS-eval blacklist.
        v = validate_swap("microsoft", "swap_powerview_filter",
                          "*", "iex evil")
        self.assertFalse(v["ok"])
        self.assertIn("PS eval", v["error"])

    def test_validate_swap_rejects_java_runtime_exec(self) -> None:
        # No shell metas; the lowercase match catches
        # "runtime.exec".
        v = validate_swap("android", "swap_frida_script_steal_method",
                          "*", "runtime.exec sh")
        self.assertFalse(v["ok"])
        self.assertIn("forbidden", v["error"])

    def test_validate_swap_rejects_nstask(self) -> None:
        v = validate_swap("ios", "swap_plist_key_value",
                          "*", "nstask launch")
        self.assertFalse(v["ok"])
        self.assertIn("forbidden", v["error"])

    def test_validate_swap_rejects_dlopen(self) -> None:
        v = validate_swap("ios", "swap_plist_key_value",
                          "*", "dlopen usr")
        self.assertFalse(v["ok"])
        self.assertIn("forbidden", v["error"])

    def test_canonicalize_artifact(self) -> None:
        # BOM and CRLF normalization.
        text = "﻿\r\nhello\r\nworld\r\n"
        c = canonicalize_artifact("microsoft", "swap_powerview_filter",
                                  text)
        self.assertTrue(c["ok"])
        # BOM stripped, CRLF normalized.
        self.assertFalse(c["text"].startswith("﻿"))
        self.assertNotIn("\r", c["text"])


class TestBloodhoundCypherParam(unittest.TestCase):
    """microsoft::swap_bloodhound_query_param."""

    PATCH = "microsoft::swap_bloodhound_query_param"

    def test_swap_cypher_param(self) -> None:
        artifact = "MATCH (n:User {name:$alice}) RETURN n\n"
        r = run_patch(self.PATCH, params={
            "artifact": artifact,
            "old_param": "alice",
            "new_param": "bob",
        })
        self.assertTrue(r["ok"], r.get("error"))
        self.assertIn("$bob", r["data"]["new_text"])
        self.assertNotIn("$alice", r["data"]["new_text"])

    def test_missing_artifact(self) -> None:
        r = run_patch(self.PATCH, params={
            "old_param": "alice", "new_param": "bob"})
        self.assertFalse(r["ok"])

    def test_invalid_new_param(self) -> None:
        r = run_patch(self.PATCH, params={
            "artifact": "MATCH (n) RETURN n",
            "old_param": "alice",
            "new_param": "1bad;",
        })
        self.assertFalse(r["ok"])

    def test_old_param_not_found(self) -> None:
        r = run_patch(self.PATCH, params={
            "artifact": "MATCH (n) RETURN n",
            "old_param": "alice",
            "new_param": "bob",
        })
        self.assertFalse(r["ok"])


class TestPowerviewFilterSwap(unittest.TestCase):
    """microsoft::swap_powerview_filter."""

    PATCH = "microsoft::swap_powerview_filter"

    def test_swap_filter(self) -> None:
        artifact = "Get-DomainUser -Filter 'samaccountname=alice'\n"
        r = run_patch(self.PATCH, params={
            "artifact": artifact,
            "old": "samaccountname=alice",
            "new": "samaccountname=bob",
        })
        self.assertTrue(r["ok"], r.get("error"))
        self.assertIn("samaccountname=bob", r["data"]["new_text"])

    def test_unquoted_old(self) -> None:
        # When the caller passes the bare unquoted old, the
        # patch wraps it in single-quotes for matching.
        artifact = "Get-DomainUser -Filter 'samaccountname=alice'\n"
        r = run_patch(self.PATCH, params={
            "artifact": artifact,
            "old": "samaccountname=alice",
            "new": "samaccountname=bob",
        })
        self.assertTrue(r["ok"], r.get("error"))
        # The new value is wrapped in single-quotes by the patch.
        self.assertIn("'samaccountname=bob'", r["data"]["new_text"])


class TestCertipyTemplateSwap(unittest.TestCase):
    """microsoft::swap_certipy_template."""

    PATCH = "microsoft::swap_certipy_template"

    def test_swap_template(self) -> None:
        artifact = "certipy req -template 'VulnTpl' -ca acme-DC01-CA\n"
        r = run_patch(self.PATCH, params={
            "artifact": artifact,
            "old": "VulnTpl",
            "new": "OtherTpl",
        })
        self.assertTrue(r["ok"], r.get("error"))
        self.assertIn("OtherTpl", r["data"]["new_text"])


class TestFridaScriptStealMethod(unittest.TestCase):
    """android::swap_frida_script_steal_method."""

    PATCH = "android::swap_frida_script_steal_method"

    def test_swap_java_choose(self) -> None:
        artifact = ("Java.choose('com.example.OldClass', {\n"
                    "  onComplete: function() {}\n"
                    "})\n")
        r = run_patch(self.PATCH, params={
            "artifact": artifact,
            "old": "com.example.OldClass",
            "new": "com.example.NewClass",
        })
        self.assertTrue(r["ok"], r.get("error"))
        self.assertIn("com.example.NewClass", r["data"]["new_text"])
        self.assertNotIn("com.example.OldClass", r["data"]["new_text"])

    def test_double_quoted_class(self) -> None:
        artifact = 'Java.choose("com.example.OldClass", {})\n'
        r = run_patch(self.PATCH, params={
            "artifact": artifact,
            "old": "com.example.OldClass",
            "new": "com.example.NewClass",
        })
        self.assertTrue(r["ok"], r.get("error"))


class TestApkPackageIdSwap(unittest.TestCase):
    """android::swap_apk_package_id."""

    PATCH = "android::swap_apk_package_id"

    def test_swap_package(self) -> None:
        artifact = ('<manifest xmlns:android="http://x" '
                    'package="com.example.old" '
                    'android:versionCode="1">\n</manifest>')
        r = run_patch(self.PATCH, params={
            "artifact": artifact,
            "old": "com.example.old",
            "new": "com.example.new",
        })
        self.assertTrue(r["ok"], r.get("error"))
        self.assertIn('package="com.example.new"', r["data"]["new_text"])

    def test_invalid_new_package(self) -> None:
        r = run_patch(self.PATCH, params={
            "artifact": '<manifest package="x"/>',
            "old": "x",
            "new": "Not_A_Package",
        })
        self.assertFalse(r["ok"])


class TestMagiskModulePropSwap(unittest.TestCase):
    """android::swap_magisk_module_prop."""

    PATCH = "android::swap_magisk_module_prop"

    def test_swap_id(self) -> None:
        artifact = "id=oldmod\nname=Old Mod\nversion=v1\n"
        r = run_patch(self.PATCH, params={
            "artifact": artifact,
            "field": "id",
            "old": "oldmod",
            "new": "newmod",
        })
        self.assertTrue(r["ok"], r.get("error"))
        self.assertIn("id=newmod", r["data"]["new_text"])

    def test_swap_name(self) -> None:
        # The patch's value validator allows [A-Za-z0-9_\-\.]+
        # so no spaces in the value.
        artifact = "id=m\nname=Old_Mod\n"
        r = run_patch(self.PATCH, params={
            "artifact": artifact,
            "field": "name",
            "old": "Old_Mod",
            "new": "New_Mod",
        })
        self.assertTrue(r["ok"], r.get("error"))
        self.assertIn("name=New_Mod", r["data"]["new_text"])

    def test_invalid_field(self) -> None:
        r = run_patch(self.PATCH, params={
            "artifact": "id=x\n",
            "field": "dangerous_field",
            "old": "x",
            "new": "y",
        })
        self.assertFalse(r["ok"])


class TestPlistKeyValueSwap(unittest.TestCase):
    """ios::swap_plist_key_value."""

    PATCH = "ios::swap_plist_key_value"

    def test_swap_key_and_value(self) -> None:
        artifact = ("<key>OldKey</key>\n"
                    "<string>OldValue</string>\n")
        r = run_patch(self.PATCH, params={
            "artifact": artifact,
            "old_key": "OldKey",
            "new_key": "NewKey",
            "old_value": "OldValue",
            "new_value": "NewValue",
        })
        self.assertTrue(r["ok"], r.get("error"))
        d = r["data"]["new_text"]
        self.assertIn("NewKey", d)
        self.assertIn("NewValue", d)

    def test_swap_key_only(self) -> None:
        artifact = "<key>OldKey</key>\n<string>SomeVal</string>\n"
        r = run_patch(self.PATCH, params={
            "artifact": artifact,
            "old_key": "OldKey",
            "new_key": "NewKey",
            "new_value": "SomeVal",
        })
        self.assertTrue(r["ok"], r.get("error"))


class TestFridaIosDumpBundleIdSwap(unittest.TestCase):
    """ios::swap_frida_ios_dump_bundle_id."""

    PATCH = "ios::swap_frida_ios_dump_bundle_id"

    def test_swap_bundle_id(self) -> None:
        artifact = 'var old_bundle = "com.example.old"\n'
        r = run_patch(self.PATCH, params={
            "artifact": artifact,
            "old": "com.example.old",
            "new": "com.example.new",
        })
        self.assertTrue(r["ok"], r.get("error"))
        self.assertIn("com.example.new", r["data"]["new_text"])
        self.assertNotIn("com.example.old", r["data"]["new_text"])


class TestCheckm8ArgsSwap(unittest.TestCase):
    """ios::swap_checkm8_args."""

    PATCH = "ios::swap_checkm8_args"

    def test_swap_payload(self) -> None:
        artifact = "#!/bin/sh\n./ipwnder -p old_payload.bin\n"
        r = run_patch(self.PATCH, params={
            "artifact": artifact,
            "old": "old_payload.bin",
            "new": "new_payload.bin",
        })
        self.assertTrue(r["ok"], r.get("error"))
        self.assertIn("new_payload.bin", r["data"]["new_text"])
        self.assertNotIn("old_payload.bin", r["data"]["new_text"])


class TestRunPatchBehavior(unittest.TestCase):
    """run_patch entrypoint + catalog + out_path handling."""

    def test_unknown_patch_id(self) -> None:
        r = run_patch("microsoft::nope",
                      params={"artifact": "x",
                              "old": "a", "new": "b"})
        self.assertFalse(r["ok"])
        self.assertIn("unknown", r["error"])

    def test_resolve_by_method_only(self) -> None:
        # Patch method only (no target class).
        r = run_patch("swap_powerview_filter",
                      target_class="microsoft",
                      params={"artifact": "-Filter 'a'",
                              "old": "a", "new": "b"})
        self.assertTrue(r["ok"], r.get("error"))

    def test_out_path_writes_file(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            out = os.path.join(td, "out.cypher")
            r = run_patch("microsoft::swap_bloodhound_query_param",
                          params={"artifact": "MATCH (n:$alice) RETURN n",
                                  "old_param": "alice",
                                  "new_param": "bob",
                                  "out_path": out})
            self.assertTrue(r["ok"], r.get("error"))
            self.assertTrue(r["data"]["wrote_file"])
            self.assertTrue(os.path.exists(out))
            with open(out, "r", encoding="utf-8") as fh:
                content = fh.read()
            self.assertIn("$bob", content)

    def test_no_out_path_no_write(self) -> None:
        r = run_patch("microsoft::swap_bloodhound_query_param",
                      params={"artifact": "MATCH (n:$alice) RETURN n",
                              "old_param": "alice",
                              "new_param": "bob"})
        self.assertTrue(r["ok"])
        self.assertFalse(r["data"]["wrote_file"])
        self.assertEqual(r["data"]["out_path"], "")

    def test_catalog_complete(self) -> None:
        self.assertEqual(len(LIVE_TARGET_PATCHES), 9)
        # 3 per target class.
        tc_counts = {}
        for s in LIVE_TARGET_PATCHES:
            tc_counts[s["target_class"]] = tc_counts.get(
                s["target_class"], 0) + 1
        self.assertEqual(tc_counts, {"microsoft": 3, "android": 3, "ios": 3})

    def test_catalog_unique_patch_ids(self) -> None:
        ids = [s["patch_id"] for s in LIVE_TARGET_PATCHES]
        self.assertEqual(len(ids), len(set(ids)))

    def test_all_patches_have_fn(self) -> None:
        for s in LIVE_TARGET_PATCHES:
            self.assertTrue(callable(s["fn"]))

    def test_invalid_target_class_filter(self) -> None:
        # Method that exists, but with a wrong target_class.
        r = run_patch("swap_powerview_filter",
                      target_class="ios",
                      params={"artifact": "-Filter 'a'",
                              "old": "a", "new": "b"})
        # The patch is filtered out by target_class mismatch,
        # so it falls through to "unknown".
        self.assertFalse(r["ok"])

    def test_validate_params_rejects_shell_meta(self) -> None:
        v = validate_params("microsoft", "swap_powerview_filter",
                            {"old": "a", "new": "x;y",
                             "artifact": "x"})
        self.assertFalse(v["ok"])


if __name__ == "__main__":
    unittest.main()
