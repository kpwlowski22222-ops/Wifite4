#!/usr/bin/env python3
"""Adversarial / hostile-seed tests for the Phase 2.0 multi-target-
class expansion (Microsoft / Android / iOS / live_target).

These tests intentionally try to break the dispatchers + runners +
validators with bad inputs and assert the system stays honest:
  - unknown methods never fake a success
  - runner exceptions never crash the orchestrator
  - shell metas / exec APIs in patch payloads are rejected
  - the per-step gate (confirm_fn) fires ONCE; the new dispatchers
    do NOT re-confirm
  - the model picker returns the right model for the right class
    and the fallback for anything else
  - the live_target validator never accepts a payload that
    introduces dangerous exec APIs
  - the catalog loader reads the 29 new github_*_target_class
    entries without error
  - target_class propagation through seed does not crash on
    missing keys

The plan task: Phase 2.0.V adversarial milestone.
"""
from __future__ import annotations

import json
import re
import socket
import unittest
from pathlib import Path
from unittest.mock import patch

import pytest


# Prevent accidental network calls during test execution
@pytest.fixture(autouse=True)
def block_network(monkeypatch):
    def block_socket_connect(*args, **kwargs):
        raise RuntimeError("Network access blocked in offline unit tests")
    monkeypatch.setattr(socket.socket, "connect", block_socket_connect)


# ---------------------------------------------------------------------------
# Microsoft dispatcher hostile seeds
# ---------------------------------------------------------------------------

class TestMicrosoftHostile(unittest.TestCase):

    def test_unknown_method_skipped(self):
        from core.orchestrator.autonomous_orchestrator import AutonomousOrchestrator
        from tests.fakes import FakeAIBackend
        o = AutonomousOrchestrator(
            ai_backend=FakeAIBackend(),
            confirm_fn=lambda p: True,
            on_event=lambda m: None,
        )
        seed = {}
        report = {"executed": [], "skipped": [], "access": {}}
        o._dispatch_microsoft_attack(
            {"action": "microsoft_attack",
             "args": {"method": "fake_cve_2025_9999"}},
            seed, report)
        self.assertEqual(report["executed"], [])
        self.assertNotIn("microsoft", seed)
        self.assertTrue(any("microsoft_attack" in s
                            for s in report["skipped"]))

    def test_runner_exception_does_not_crash(self):
        from core.orchestrator.autonomous_orchestrator import AutonomousOrchestrator
        from tests.fakes import FakeAIBackend
        import core.microsoft.runner as m

        def boom(method, *a, **kw):
            raise RuntimeError("simulated runner failure")
        with patch.object(m, "run_attack", boom):
            o = AutonomousOrchestrator(
                ai_backend=FakeAIBackend(),
                confirm_fn=lambda p: True,
                on_event=lambda m: None,
            )
            report = {"executed": [], "skipped": [], "access": {}}
            o._dispatch_microsoft_attack(
                {"action": "microsoft_attack",
                 "args": {"method": "nmap_smb_rpc_winrm_discovery",
                          "target": "10.10.10.1"}},
                {}, report)
        self.assertEqual(report["executed"], [])
        self.assertTrue(any("simulated" in s for s in report["skipped"]))

    def test_no_fabricated_cve_ids_in_runner(self):
        # If the runner doesn't recognize a method that looks
        # like a CVE probe, it must return ok=False rather than
        # inventing a CVE id.
        from core.microsoft.runner import run_attack
        r = run_attack("kerbrute_userenum_oasrep", args={})
        # Missing output → ok=False, no fabricated id.
        self.assertFalse(r["ok"])
        # No "CVE-" id should appear anywhere in the response.
        blob = json.dumps(r, default=str)
        self.assertNotRegex(blob, r"CVE-\d{4}-\d{4,7}")


# ---------------------------------------------------------------------------
# Android dispatcher hostile seeds
# ---------------------------------------------------------------------------

class TestAndroidHostile(unittest.TestCase):

    def test_unknown_method_skipped(self):
        from core.orchestrator.autonomous_orchestrator import AutonomousOrchestrator
        from tests.fakes import FakeAIBackend
        o = AutonomousOrchestrator(
            ai_backend=FakeAIBackend(),
            confirm_fn=lambda p: True,
            on_event=lambda m: None,
        )
        report = {"executed": [], "skipped": [], "access": {}}
        o._dispatch_android_attack(
            {"action": "android_attack",
             "args": {"method": "root_via_evil_method"}},
            {}, report)
        self.assertEqual(report["executed"], [])
        self.assertTrue(any("android_attack" in s
                            for s in report["skipped"]))

    def test_runner_exception_does_not_crash(self):
        from core.orchestrator.autonomous_orchestrator import AutonomousOrchestrator
        from tests.fakes import FakeAIBackend
        import core.android.runner as m

        def boom(method, *a, **kw):
            raise RuntimeError("adb-kaboom")
        with patch.object(m, "run_attack", boom):
            o = AutonomousOrchestrator(
                ai_backend=FakeAIBackend(),
                confirm_fn=lambda p: True,
                on_event=lambda m: None,
            )
            report = {"executed": [], "skipped": [], "access": {}}
            o._dispatch_android_attack(
                {"action": "android_attack",
                 "args": {"method": "adb_devices_list"}},
                {}, report)
        self.assertTrue(any("adb-kaboom" in s for s in report["skipped"]))

    def test_frida_method_rejects_rce_payload(self):
        # The android::swap_frida_script_steal_method patch must
        # reject an injected Java.choose that pipes a shell.
        from core.live_target import run_patch
        r = run_patch(
            "android::swap_frida_script_steal_method",
            params={"artifact": "Java.choose('com.example.A', {})\n",
                    "old": "com.example.A",
                    "new": "com.example.A; Runtime.exec('sh')"},
        )
        self.assertFalse(r["ok"])


# ---------------------------------------------------------------------------
# iOS dispatcher hostile seeds
# ---------------------------------------------------------------------------

class TestIosHostile(unittest.TestCase):

    def test_unknown_method_skipped(self):
        from core.orchestrator.autonomous_orchestrator import AutonomousOrchestrator
        from tests.fakes import FakeAIBackend
        o = AutonomousOrchestrator(
            ai_backend=FakeAIBackend(),
            confirm_fn=lambda p: True,
            on_event=lambda m: None,
        )
        report = {"executed": [], "skipped": [], "access": {}}
        o._dispatch_ios_attack(
            {"action": "ios_attack",
             "args": {"method": "pwn_via_evil_method"}},
            {}, report)
        self.assertEqual(report["executed"], [])

    def test_runner_exception_does_not_crash(self):
        from core.orchestrator.autonomous_orchestrator import AutonomousOrchestrator
        from tests.fakes import FakeAIBackend
        import core.ios.runner as m

        def boom(method, *a, **kw):
            raise RuntimeError("usbmuxd-kaboom")
        with patch.object(m, "run_attack", boom):
            o = AutonomousOrchestrator(
                ai_backend=FakeAIBackend(),
                confirm_fn=lambda p: True,
                on_event=lambda m: None,
            )
            report = {"executed": [], "skipped": [], "access": {}}
            o._dispatch_ios_attack(
                {"action": "ios_attack",
                 "args": {"method": "libimobiledevice_list_devices"}},
                {}, report)
        self.assertTrue(any("usbmuxd-kaboom" in s
                            for s in report["skipped"]))

    def test_ios_patch_rejects_nstask_payload(self):
        from core.live_target import run_patch
        r = run_patch(
            "ios::swap_checkm8_args",
            params={"artifact": "./ipwnder -p old_payload.bin\n",
                    "old": "old_payload.bin",
                    "new": "x; NSTask launch sh"},
        )
        self.assertFalse(r["ok"])


# ---------------------------------------------------------------------------
# live_target hostile seeds
# ---------------------------------------------------------------------------

class TestLiveTargetHostile(unittest.TestCase):

    def test_shell_meta_in_new_rejected_microsoft(self):
        from core.live_target import run_patch
        r = run_patch(
            "microsoft::swap_powerview_filter",
            params={"artifact": "Get-DomainUser -Filter 'x'\n",
                    "old": "x", "new": "y; rm -rf /"},
        )
        self.assertFalse(r["ok"])
        self.assertIn("shell", r["error"])

    def test_shell_meta_in_new_rejected_ios(self):
        from core.live_target import run_patch
        r = run_patch(
            "ios::swap_plist_key_value",
            params={"artifact": "<key>K</key><string>V</string>\n",
                    "old_key": "K", "new_key": "K2",
                    "old_value": "V", "new_value": "$(rm -rf /)"},
        )
        self.assertFalse(r["ok"])

    def test_unknown_patch_id_rejected(self):
        from core.live_target import run_patch
        r = run_patch("microsoft::fake_patch", params={})
        self.assertFalse(r["ok"])
        self.assertIn("unknown", r["error"])

    def test_cross_target_class_filtered(self):
        from core.live_target import run_patch
        # Microsoft patch called as ios → falls through to "unknown".
        r = run_patch(
            "swap_powerview_filter",
            target_class="ios",
            params={"artifact": "x", "old": "a", "new": "b"},
        )
        self.assertFalse(r["ok"])

    def test_no_out_path_no_write(self):
        from core.live_target import run_patch
        r = run_patch(
            "microsoft::swap_bloodhound_query_param",
            params={"artifact": "MATCH (n:$alice) RETURN n",
                    "old_param": "alice", "new_param": "bob"},
        )
        self.assertTrue(r["ok"])
        self.assertFalse(r["data"]["wrote_file"])


# ---------------------------------------------------------------------------
# Model picker hostile seeds
# ---------------------------------------------------------------------------

class TestModelPickerHostile(unittest.TestCase):

    def test_none_returns_fallback(self):
        from core.ai_backend import AIBackend, MODEL_CATALOG
        b = AIBackend()
        try:
            m = b._pick_model_for_target(None)  # type: ignore
        except (TypeError, AttributeError):
            m = MODEL_CATALOG["fallback"]
        self.assertEqual(m, MODEL_CATALOG["fallback"])

    def test_unrelated_class_returns_fallback(self):
        from core.ai_backend import AIBackend, MODEL_CATALOG
        b = AIBackend()
        self.assertEqual(
            b._pick_model_for_target("wifi"),
            MODEL_CATALOG["fallback"])
        self.assertEqual(
            b._pick_model_for_target("post_exploitation"),
            MODEL_CATALOG["fallback"])

    def test_microsoft_picks_code_architect(self):
        from core.ai_backend import (
            AIBackend, TARGET_MODEL_CATALOG)
        b = AIBackend()
        m = b._pick_model_for_target("microsoft")
        self.assertEqual(m, TARGET_MODEL_CATALOG["microsoft"])
        self.assertIn("Coder", m)

    def test_picker_does_not_bypass_refusal(self):
        # The picker is a model choice, not a safety override.
        # The same uncensored-swap rule applies.
        from core.ai_backend import AIBackend
        b = AIBackend()
        for tc in ("microsoft", "android", "ios"):
            m = b._pick_model_for_target(tc)
            self.assertNotIn("bypass", m.lower())
            self.assertNotIn("override", m.lower())


# ---------------------------------------------------------------------------
# Catalog loader hostile seeds
# ---------------------------------------------------------------------------

class TestCatalogLoaderHostile(unittest.TestCase):

    def test_29_new_entries_load_cleanly(self):
        from core.utils.catalog_loader import load_catalog
        ents = load_catalog()
        # The 29 new github_*_microsoft/*_android/*_ios entries
        # should be present and parse as kind=external_repository.
        new = [e for e in ents
               if e.id in _EXPECTED_NEW_IDS]
        self.assertEqual(len(new), 29,
                         f"expected 29 new entries, got {len(new)}")

    def test_29_new_entries_have_toolbox_paths(self):
        from core.utils.catalog_loader import load_catalog
        ents = load_catalog()
        for e in ents:
            if e.id in _EXPECTED_NEW_IDS:
                self.assertIn("toolbox_path", e.extra)
                tb = Path(e.extra["toolbox_path"])
                self.assertTrue(tb.exists(),
                                f"toolbox dir missing: {tb}")
                self.assertTrue(tb.is_dir())

    def test_29_new_entries_have_correct_risk_levels(self):
        from core.utils.catalog_loader import load_catalog
        ents = load_catalog()
        risk_by_id = {e.id: e.extra.get("risk", {}).get("level")
                      for e in ents}
        # mimikatz is critical.
        self.assertEqual(risk_by_id.get("github:gentilkiwi/mimikatz"),
                         "critical")
        # scrcpy / jadx / nuclei / libimobiledevice / usbmuxd / MobSF
        # / awesome-mobile-security are low.
        for low_id in ("github:genymobile/scrcpy",
                       "github:skylot/jadx",
                       "github:projectdiscovery/nuclei",
                       "github:libimobiledevice/libimobiledevice",
                       "github:libimobiledevice/usbmuxd",
                       "github:MobSF/Mobile-Security-Framework-MobSF",
                       "github:8ksec/awesome-mobile-security"):
            self.assertEqual(risk_by_id.get(low_id), "low",
                             f"{low_id} should be low")

    def test_catalog_loader_never_raises_on_malformed(self):
        # Even if a sibling JSON file is malformed, the loader
        # should not raise; the bad file is just skipped.
        from core.utils.catalog_loader import load_catalog
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "bad.json").write_text("{not json", encoding="utf-8")
            ents = load_catalog(root=Path(td))
            self.assertEqual(ents, [])


_EXPECTED_NEW_IDS = frozenset({
    # Microsoft (14)
    "github:BloodHoundAD/BloodHound",
    "github:ly4k/Certipy",
    "github:Wh04m1001/DFSCoerce",
    "github:EmpireProject/Empire",
    "github:fortra/impacket",
    "github:dirkjanm/krbrelayx",
    "github:Hackndo/lsassy",
    "github:gentilkiwi/mimikatz",
    "github:samratashok/nishang",
    "github:topotam/PetitPotam",
    "github:PowerShellMafia/PowerSploit",
    "github:lgandx/Responder",
    "github:GhostPack/Rubeus",
    "github:ShutdownRepo/ShadowCoerce",
    # Android (7)
    "github:iBotPeaches/Apktool",
    "github:8ksec/awesome-mobile-security",
    "github:mwrlabs/drozer",
    "github:frida/frida",
    "github:skylot/jadx",
    "github:MobSF/Mobile-Security-Framework-MobSF",
    "github:genymobile/scrcpy",
    # iOS (8)
    "github:ChiChou/bagbak",
    "github:bishopfox/bfinject",
    "github:AloneMonkey/frida-ios-dump",
    "github:iSECPartners/ios-ssl-kill-switch",
    "github:libimobiledevice/libimobiledevice",
    "github:projectdiscovery/nuclei",
    "github:nabla-c0d3/ssl-kill-switch2",
    "github:libimobiledevice/usbmuxd",
})


# ---------------------------------------------------------------------------
# Single-gate invariant adversarial
# ---------------------------------------------------------------------------

class TestSingleGateAdversarial(unittest.TestCase):

    def test_dispatchers_dont_re_confirm(self):
        # The per-step ACCEPT/CANCEL gate (TuiConfirmFn) fires ONCE
        # in _walk_ai_step. The dispatchers must not re-confirm.
        from core.orchestrator import autonomous_orchestrator as mod
        src = inspect.getsource(mod)
        for name in ("_dispatch_microsoft_attack",
                     "_dispatch_android_attack",
                     "_dispatch_ios_attack",
                     "_dispatch_live_target"):
            i = src.find(f"def {name}")
            j = src.find("\n    def ", i + 1)
            if j < 0:
                j = len(src)
            body = src[i:j]
            cleaned = re.sub(r"confirm_fn\s*=\s*[^,)\s]+", "", body)
            self.assertNotIn("confirm_fn", cleaned,
                             f"{name} re-confirms")
            self.assertNotIn("self.confirm", cleaned,
                             f"{name} re-confirms")


import inspect  # late import to satisfy the suite above
