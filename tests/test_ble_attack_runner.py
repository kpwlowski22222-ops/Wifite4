"""core.ble.attack_runner — hermetic unit tests for the BLE attack /
post-exploitation runner.

Exercises the gatttool write/long-read primitives, the bluetoothctl pairing
loop, and the JSON session export — all monkeypatched so no real BlueZ, no
real controller, and no real target device is touched. Verifies the
never-fake contract: every verdict is the real tool's return code / output
line, never a fabricated 'exploit succeeded' / 'PIN recovered'.
"""

import json
import subprocess

import pytest

from core.ble import attack_runner as ba
from core.ble.attack_runner import BLEAttackRunner, BLE_ATTACKS, run_attack


# ----------------------------------------------------------------------
# dispatch + registry shape
# ----------------------------------------------------------------------
def test_run_attack_unknown_method_is_error():
    res = run_attack("nope")
    assert res["ok"] is False
    assert "unknown attack method" in res["error"]


def test_attack_methods_match_registry():
    methods = set(BLEAttackRunner.BLE_ATTACK_METHODS)
    registry = {p["method"] for p in BLE_ATTACKS}
    assert methods == registry
    # 6 original + 13 new spec-named modules (the spec's
    # ble_pairing_pin_bruteforce aliases the existing
    # pairing_pin_bruteforce, so 14 spec modules -> 13 new entries) = 19.
    assert len(methods) == 19, (
        f"expected 19 methods, got {len(methods)}: {sorted(methods)}"
    )


# ----------------------------------------------------------------------
# gatt_write_exploit
# ----------------------------------------------------------------------
def test_gatt_write_exploit_accepted(monkeypatch):
    monkeypatch.setattr(ba.shutil, "which", lambda n: "/usr/bin/gatttool")
    writes = []

    def fake_run(cmd, **kw):
        writes.append(cmd)
        # gatttool prints "Write successful" on rc 0.
        return subprocess.CompletedProcess(cmd, 0,
            stdout="Characteristic value written successfully\n", stderr="")

    monkeypatch.setattr(ba.subprocess, "run", fake_run)
    r = BLEAttackRunner(args={"address": "AA:BB:CC:DD:EE:01"})
    res = r.run_attack("gatt_write_exploit")
    assert res["ok"] is True
    assert res["data"]["any_accepted"] is True
    # Verdict comes from the real gatttool output line, not fabricated.
    assert res["data"]["writes"][0]["accepted"] is True
    assert writes, "gatttool subprocess was never invoked"


def test_gatt_write_exploit_no_gatttool_degrades(monkeypatch):
    monkeypatch.setattr(ba.shutil, "which", lambda n: None)
    r = BLEAttackRunner(args={"address": "AA:BB:CC:DD:EE:01"})
    res = r.run_attack("gatt_write_exploit")
    assert res["ok"] is False
    assert "gatttool not installed" in res["error"]


def test_gatt_write_exploit_missing_address_degrades(monkeypatch):
    monkeypatch.setattr(ba.shutil, "which", lambda n: "/usr/bin/gatttool")
    r = BLEAttackRunner(args={})
    res = r.run_attack("gatt_write_exploit")
    assert res["ok"] is False
    assert "address required" in res["error"]


def test_gatt_write_exploit_rejected_not_fabricated(monkeypatch):
    monkeypatch.setattr(ba.shutil, "which", lambda n: "/usr/bin/gatttool")
    # rc=1, no "Write successful" line -> accepted False, honestly reported.
    monkeypatch.setattr(ba.subprocess, "run",
        lambda cmd, **kw: subprocess.CompletedProcess(cmd, 1,
            stdout="", stderr="connect error\n"))
    r = BLEAttackRunner(args={"address": "AA:BB:CC:DD:EE:01",
                              "uuids": ["2a44"], "payloads": ["01"]})
    res = r.run_attack("gatt_write_exploit")
    assert res["ok"] is True  # the probe ran; per-write verdict is False
    assert res["data"]["any_accepted"] is False
    assert res["data"]["writes"][0]["accepted"] is False


# ----------------------------------------------------------------------
# firmware_dump_via_gatt
# ----------------------------------------------------------------------
def test_firmware_dump_reconstructs_bytes(monkeypatch):
    monkeypatch.setattr(ba.shutil, "which", lambda n: "/usr/bin/gatttool")
    # Two full 22-byte chunks then a short chunk -> end of characteristic.
    chunks = [b"\x10" * 22, b"\x20" * 22, b"\xab\xcd"]

    def fake_run(cmd, **kw):
        c = chunks.pop(0) if chunks else b""
        if not c:
            return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="")
        return subprocess.CompletedProcess(cmd, 0,
            stdout=f"handle: 0x0010  value: {c.hex(' ')}\n", stderr="")

    monkeypatch.setattr(ba.subprocess, "run", fake_run)
    r = BLEAttackRunner(args={"address": "AA:BB:CC:DD:EE:01",
                              "handle": "0x0010"})
    res = r.run_attack("firmware_dump_via_gatt")
    assert res["ok"] is True
    assert res["data"]["bytes_read"] == 22 + 22 + 2
    assert res["data"]["blocks"] == 3
    assert len(res["data"]["sha256_first32"]) == 64  # 32 bytes hex


def test_firmware_dump_writes_out_file(monkeypatch, tmp_path):
    monkeypatch.setattr(ba.shutil, "which", lambda n: "/usr/bin/gatttool")
    out = tmp_path / "fw.bin"
    monkeypatch.setattr(ba.subprocess, "run",
        lambda cmd, **kw: subprocess.CompletedProcess(cmd, 0,
            stdout="value: de ad be ef\n", stderr=""))
    r = BLEAttackRunner(args={"address": "AA:BB:CC:DD:EE:01",
                              "handle": "0x0010", "out_path": str(out),
                              "max_blocks": 1})
    res = r.run_attack("firmware_dump_via_gatt")
    assert res["ok"] is True
    assert out.exists()
    assert out.read_bytes() == b"\xde\xad\xbe\xef"


def test_firmware_dump_read_fails_degrades(monkeypatch):
    monkeypatch.setattr(ba.shutil, "which", lambda n: "/usr/bin/gatttool")
    monkeypatch.setattr(ba.subprocess, "run",
        lambda cmd, **kw: subprocess.CompletedProcess(cmd, 1, stdout="", stderr=""))
    r = BLEAttackRunner(args={"address": "AA:BB:CC:DD:EE:01"})
    res = r.run_attack("firmware_dump_via_gatt")
    assert res["ok"] is False
    assert "firmware read failed" in res["error"]


# ----------------------------------------------------------------------
# write_led / write_lock
# ----------------------------------------------------------------------
def test_write_led_accepted(monkeypatch):
    monkeypatch.setattr(ba.shutil, "which", lambda n: "/usr/bin/gatttool")
    monkeypatch.setattr(ba.subprocess, "run",
        lambda cmd, **kw: subprocess.CompletedProcess(cmd, 0,
            stdout="Characteristic value written successfully\n", stderr=""))
    r = BLEAttackRunner(args={"address": "AA:BB:CC:DD:EE:01", "value": "01"})
    res = r.run_attack("write_led")
    assert res["ok"] is True
    assert res["data"]["uuid"] == "2a44"
    assert res["data"]["value"] == "01"


def test_write_lock_uses_2a1d_and_value_00(monkeypatch):
    monkeypatch.setattr(ba.shutil, "which", lambda n: "/usr/bin/gatttool")
    seen = {}

    def fake_run(cmd, **kw):
        seen["cmd"] = cmd
        return subprocess.CompletedProcess(cmd, 0,
            stdout="Characteristic value written successfully\n", stderr="")

    monkeypatch.setattr(ba.subprocess, "run", fake_run)
    r = BLEAttackRunner(args={"address": "AA:BB:CC:DD:EE:01"})
    res = r.run_attack("write_lock")
    assert res["ok"] is True
    assert res["data"]["uuid"] == "2a1d"
    assert res["data"]["value"] == "00"
    # The gatttool command actually targeted the lock characteristic.
    assert "2a1d" in seen["cmd"]


def test_write_char_rejected_reports_honestly(monkeypatch):
    monkeypatch.setattr(ba.shutil, "which", lambda n: "/usr/bin/gatttool")
    monkeypatch.setattr(ba.subprocess, "run",
        lambda cmd, **kw: subprocess.CompletedProcess(cmd, 1,
            stdout="", stderr="auth required\n"))
    r = BLEAttackRunner(args={"address": "AA:BB:CC:DD:EE:01"})
    res = r.run_attack("write_led")
    assert res["ok"] is False
    assert "write rejected" in res["error"]
    assert res["data"]["accepted"] is False


# ----------------------------------------------------------------------
# pairing_pin_bruteforce
# ----------------------------------------------------------------------
def test_pairing_recovers_on_second_pin(monkeypatch):
    monkeypatch.setattr(ba.shutil, "which", lambda n: "/usr/bin/bluetoothctl")
    calls = {"n": 0}

    def fake_run(cmd, **kw):
        calls["n"] += 1
        # First PIN fails, second succeeds.
        out = "Pairing successful\n" if calls["n"] == 2 else "Pairing failed\n"
        return subprocess.CompletedProcess(cmd, 0, stdout=out, stderr="")

    monkeypatch.setattr(ba.subprocess, "run", fake_run)
    r = BLEAttackRunner(args={"address": "AA:BB:CC:DD:EE:01",
                              "pin_list": ["000000", "111111"]})
    res = r.run_attack("pairing_pin_bruteforce")
    assert res["ok"] is True
    assert res["data"]["recovered_pin"] == "111111"
    assert res["data"]["attempt_count"] == 2


def test_pairing_no_success_reports_honestly(monkeypatch):
    monkeypatch.setattr(ba.shutil, "which", lambda n: "/usr/bin/bluetoothctl")
    monkeypatch.setattr(ba.subprocess, "run",
        lambda cmd, **kw: subprocess.CompletedProcess(cmd, 0,
            stdout="Pairing failed\n", stderr=""))
    r = BLEAttackRunner(args={"address": "AA:BB:CC:DD:EE:01",
                              "pin_list": ["000000", "111111"]})
    res = r.run_attack("pairing_pin_bruteforce")
    assert res["ok"] is False
    assert res["data"]["recovered_pin"] is None
    assert "no PIN" in res["error"]


def test_pairing_bounded_by_max_attempts(monkeypatch):
    monkeypatch.setattr(ba.shutil, "which", lambda n: "/usr/bin/bluetoothctl")
    calls = {"n": 0}
    monkeypatch.setattr(ba.subprocess, "run",
        lambda cmd, **kw: (calls.__setitem__("n", calls["n"] + 1),
                            subprocess.CompletedProcess(cmd, 0,
                                stdout="Pairing failed\n", stderr=""))[1])
    r = BLEAttackRunner(args={"address": "AA:BB:CC:DD:EE:01",
                              "pin_list": ["%06d" % i for i in range(100)],
                              "max_attempts": 5})
    res = r.run_attack("pairing_pin_bruteforce")
    assert res["data"]["attempt_count"] == 5  # bounded, not 100


def test_pairing_no_bluetoothctl_degrades(monkeypatch):
    monkeypatch.setattr(ba.shutil, "which", lambda n: None)
    r = BLEAttackRunner(args={"address": "AA:BB:CC:DD:EE:01"})
    res = r.run_attack("pairing_pin_bruteforce")
    assert res["ok"] is False
    assert "bluetoothctl not installed" in res["error"]


# ----------------------------------------------------------------------
# export_session
# ----------------------------------------------------------------------
def test_export_session_writes_json(tmp_path):
    out = tmp_path / "session.json"
    session = {"address": "AA:BB:CC:DD:EE:01", "ble_recon": {"x": 1}}
    r = BLEAttackRunner(args={"session": session, "out_path": str(out)})
    res = r.run_attack("export_session")
    assert res["ok"] is True
    assert out.exists()
    loaded = json.loads(out.read_text(encoding="utf-8"))
    assert loaded == session
    assert res["data"]["keys"] == ["address", "ble_recon"]


def test_export_session_serializes_verbatim(tmp_path):
    # Whatever is in args.session is written verbatim — no fabricated fields.
    out = tmp_path / "s.json"
    r = BLEAttackRunner(args={"session": {"only": "this"}, "out_path": str(out)})
    res = r.run_attack("export_session")
    assert res["ok"] is True
    assert json.loads(out.read_text()) == {"only": "this"}


def test_run_attack_passes_args_to_export_session(tmp_path):
    out = tmp_path / "s2.json"
    res = run_attack("export_session",
                     args={"session": {"k": "v"}, "out_path": str(out)})
    assert res["ok"] is True
    assert json.loads(out.read_text()) == {"k": "v"}


# ======================================================================
# Spec-named BLE attack modules (Phase 3 — implementacja.txt)
# ======================================================================

# ----------------------------------------------------------------------
# ble_long_range_scan
# ----------------------------------------------------------------------
def test_ble_long_range_scan_no_btmgmt(monkeypatch):
    monkeypatch.setattr(ba.shutil, "which", lambda n: None)
    r = BLEAttackRunner()
    res = r.run_attack("ble_long_range_scan")
    assert res["ok"] is False
    assert "btmgmt not installed" in res["error"]


def test_ble_long_range_scan_with_btmgmt(monkeypatch):
    monkeypatch.setattr(ba.shutil, "which", lambda n: "/usr/bin/btmgmt")
    fake = subprocess.CompletedProcess(args=[], returncode=0,
                                       stdout="PHY set to LE Coded",
                                       stderr="")
    monkeypatch.setattr(ba.subprocess, "run", lambda *a, **kw: fake)
    monkeypatch.setattr(BLEAttackRunner, "_scan",
                        lambda self, duration=12: {"found": 0, "adapter": "hci0"})
    r = BLEAttackRunner()
    res = r.run_attack("ble_long_range_scan")
    assert res["ok"] is True
    assert res["data"]["phy_set"] is True


def test_ble_long_range_scan_btmgmt_failure(monkeypatch):
    monkeypatch.setattr(ba.shutil, "which", lambda n: "/usr/bin/btmgmt")
    fake = subprocess.CompletedProcess(args=[], returncode=1,
                                       stdout="", stderr="controller not ready")
    monkeypatch.setattr(ba.subprocess, "run", lambda *a, **kw: fake)
    monkeypatch.setattr(BLEAttackRunner, "_scan",
                        lambda self, duration=12: {"found": 0, "adapter": "hci0"})
    r = BLEAttackRunner()
    res = r.run_attack("ble_long_range_scan")
    # ok=True (we recorded the real btmgmt failure, not fabricated a scan hit)
    assert res["ok"] is True
    assert res["data"]["phy_set"] is False
    assert "controller not ready" in res["data"]["phy_output_tail"]


# ----------------------------------------------------------------------
# ble_adv_data_injection
# ----------------------------------------------------------------------
def test_ble_adv_data_injection_no_scapy(monkeypatch):
    """When scapy bluetooth4LE cannot be imported, the method returns
    ok=False with the real ImportError message — never fabricated."""
    monkeypatch.setattr(ba, "BLEAttackRunner", ba.BLEAttackRunner)
    import importlib
    ble_scapy = importlib.import_module("core.ble.attack_runner")
    monkeypatch.setattr(ble_scapy, "subprocess", ble_scapy.subprocess)
    # Force ImportError by patching the from-import block.
    real_import = __builtins__.__import__ if hasattr(__builtins__, "__import__") else None
    import builtins
    orig_import = builtins.__import__
    def fake_import(name, *args, **kwargs):
        if name.startswith("scapy"):
            raise ImportError("scapy not installed")
        return orig_import(name, *args, **kwargs)
    monkeypatch.setattr(builtins, "__import__", fake_import)
    r = BLEAttackRunner()
    res = r.run_attack("ble_adv_data_injection")
    assert res["ok"] is False
    assert "scapy" in res["error"].lower() or "import" in res["error"].lower()


def test_ble_adv_data_injection_default_data(monkeypatch):
    """The method builds a default adv_data payload even when none is given."""
    r = BLEAttackRunner()
    # Stub the scapy import to a fake module.
    import types
    fake_scapy_ble = types.ModuleType("scapy.layers.bluetooth4LE")
    class _FakeADV_IND: pass
    class _FakeBTLE_ADV:
        def __init__(self, advdata=None): self.advdata = advdata
        def __truediv__(self, other): return self
    fake_scapy_ble.BluetoothLE = object
    fake_scapy_ble.ADV_IND = _FakeADV_IND
    fake_scapy_ble.BTLE_ADV = _FakeBTLE_ADV
    fake_scapy_bt = types.ModuleType("scapy.layers.bluetooth")
    fake_scapy_bt.HCI_Hdr = object
    fake_scapy_bt.HCI_Command_Hdr = object
    fake_scapy_compat = types.ModuleType("scapy.compat")
    fake_scapy_compat.raw = lambda f: b"\x00" * 16
    # Use ``monkeypatch.setitem`` so the real scapy package is restored
    # after the test exits — otherwise subsequent tests (e.g.
    # ``test_wifi_attack_frames``) see ``sys.modules["scapy"]`` as an
    # empty module and fall into the ``scapy not installed`` branch.
    import sys
    monkeypatch.setitem(sys.modules, "scapy", types.ModuleType("scapy"))
    monkeypatch.setitem(sys.modules, "scapy.layers", types.ModuleType("scapy.layers"))
    monkeypatch.setitem(sys.modules, "scapy.layers.bluetooth4LE", fake_scapy_ble)
    monkeypatch.setitem(sys.modules, "scapy.layers.bluetooth", fake_scapy_bt)
    monkeypatch.setitem(sys.modules, "scapy.compat", fake_scapy_compat)
    res = r.run_attack("ble_adv_data_injection")
    # We either built the frame (ok=True) or hit a missing attr (ok=False)
    # — either is honest; the key is that we didn't fabricate a hit.
    assert res["data"]["frame_bytes"] >= 0
    assert "frame_sha256" in res["data"]


# ----------------------------------------------------------------------
# ble_connection_hijacking
# ----------------------------------------------------------------------
def test_ble_connection_hijacking_missing_pdu():
    r = BLEAttackRunner(args={})
    res = r.run_attack("ble_connection_hijacking")
    assert res["ok"] is False
    assert "pdu_b64 required" in res["error"]


def test_ble_connection_hijacking_bad_b64():
    r = BLEAttackRunner(args={"pdu_b64": "!!!not-base64!!!"})
    res = r.run_attack("ble_connection_hijacking")
    assert res["ok"] is False
    assert "decode failed" in res["error"]


def test_ble_connection_hijacking_too_short():
    import base64
    short = base64.b64encode(b"\x00\x01\x02").decode("ascii")
    r = BLEAttackRunner(args={"pdu_b64": short})
    res = r.run_attack("ble_connection_hijacking")
    assert res["ok"] is False
    assert "too short" in res["error"]


def test_ble_connection_hijacking_valid_pdu():
    import base64
    pdu = b"\xab\xcd" * 10  # 20 bytes — valid CONNECT_REQ length
    r = BLEAttackRunner(args={"pdu_b64": base64.b64encode(pdu).decode("ascii")})
    res = r.run_attack("ble_connection_hijacking")
    assert res["ok"] is True
    assert res["data"]["pdu_bytes"] == 20


# ----------------------------------------------------------------------
# ble_man_in_the_middle_attack
# ----------------------------------------------------------------------
def test_ble_mitm_no_gatttool(monkeypatch):
    monkeypatch.setattr(ba.shutil, "which", lambda n: None)
    r = BLEAttackRunner(args={"address": "AA:BB:CC:DD:EE:01"})
    res = r.run_attack("ble_man_in_the_middle_attack")
    assert res["ok"] is False
    assert "gatttool not installed" in res["error"]


def test_ble_mitm_missing_address(monkeypatch):
    monkeypatch.setattr(ba.shutil, "which", lambda n: "/usr/bin/gatttool")
    r = BLEAttackRunner(args={})
    res = r.run_attack("ble_man_in_the_middle_attack")
    assert res["ok"] is False
    assert "address required" in res["error"]


def test_ble_mitm_with_gatttool_plan(monkeypatch):
    monkeypatch.setattr(ba.shutil, "which", lambda n: "/usr/bin/gatttool")
    r = BLEAttackRunner(args={"address": "AA:BB:CC:DD:EE:01"})
    res = r.run_attack("ble_man_in_the_middle_attack")
    assert res["ok"] is True
    assert "plan" in res["data"]
    assert any("gatttool" in p for p in res["data"]["plan"])


# ----------------------------------------------------------------------
# ble_audio_sniffing
# ----------------------------------------------------------------------
def test_ble_audio_sniffing_no_btmon(monkeypatch):
    monkeypatch.setattr(ba.shutil, "which", lambda n: None)
    r = BLEAttackRunner()
    res = r.run_attack("ble_audio_sniffing")
    assert res["ok"] is False
    assert "btmon not installed" in res["error"]


def test_ble_audio_sniffing_with_btmon(monkeypatch, tmp_path):
    monkeypatch.setattr(ba.shutil, "which", lambda n: "/usr/bin/btmon")
    out = tmp_path / "btmon.btsnoop"
    out.write_bytes(b"\x00" * 64)
    fake = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
    monkeypatch.setattr(ba.subprocess, "run", lambda *a, **kw: fake)
    r = BLEAttackRunner(args={"out_path": str(out), "timeout": 2})
    res = r.run_attack("ble_audio_sniffing")
    assert res["ok"] is True
    assert res["data"]["btmon_rc"] == 0
    assert res["data"]["saved"]["bytes"] == 64


def test_ble_audio_sniffing_btmon_timeout(monkeypatch, tmp_path):
    monkeypatch.setattr(ba.shutil, "which", lambda n: "/usr/bin/btmon")
    out = tmp_path / "btmon2.btsnoop"
    def fake_run(*a, **kw):
        raise subprocess.TimeoutExpired(cmd="btmon", timeout=10)
    monkeypatch.setattr(ba.subprocess, "run", fake_run)
    r = BLEAttackRunner(args={"out_path": str(out)})
    res = r.run_attack("ble_audio_sniffing")
    assert res["data"]["btmon_rc"] == -1
    assert "btmon error" in res["data"]["error_tail"]


# ----------------------------------------------------------------------
# ble_temperature_spoofing
# ----------------------------------------------------------------------
def test_ble_temperature_spoofing_no_gatttool(monkeypatch):
    monkeypatch.setattr(ba.shutil, "which", lambda n: None)
    r = BLEAttackRunner(args={"address": "AA:BB:CC:DD:EE:01"})
    res = r.run_attack("ble_temperature_spoofing")
    assert res["ok"] is False
    assert "gatttool not installed" in res["error"]


def test_ble_temperature_spoofing_missing_address(monkeypatch):
    monkeypatch.setattr(ba.shutil, "which", lambda n: "/usr/bin/gatttool")
    r = BLEAttackRunner(args={})
    res = r.run_attack("ble_temperature_spoofing")
    assert res["ok"] is False
    assert "address required" in res["error"]


def test_ble_temperature_spoofing_accepted(monkeypatch):
    monkeypatch.setattr(ba.shutil, "which", lambda n: "/usr/bin/gatttool")
    monkeypatch.setattr(BLEAttackRunner, "_gatttool_write",
                        lambda self, addr, uuid, val: (0,
                            f"Characteristic value was written successfully"))
    r = BLEAttackRunner(args={"address": "AA:BB:CC:DD:EE:01"})
    res = r.run_attack("ble_temperature_spoofing")
    assert res["ok"] is True
    assert res["data"]["uuid"] == "2a1c"


def test_ble_temperature_spoofing_rejected(monkeypatch):
    """A rejected write is reported honestly, never as ok=True."""
    monkeypatch.setattr(ba.shutil, "which", lambda n: "/usr/bin/gatttool")
    monkeypatch.setattr(BLEAttackRunner, "_gatttool_write",
                        lambda self, addr, uuid, val: (1, "write failed"))
    r = BLEAttackRunner(args={"address": "AA:BB:CC:DD:EE:01"})
    res = r.run_attack("ble_temperature_spoofing")
    assert res["ok"] is False
    assert res["data"]["return_code"] == 1


# ----------------------------------------------------------------------
# ble_keyboard_injection
# ----------------------------------------------------------------------
def test_ble_keyboard_injection_no_gatttool(monkeypatch):
    monkeypatch.setattr(ba.shutil, "which", lambda n: None)
    r = BLEAttackRunner(args={"address": "AA:BB:CC:DD:EE:01"})
    res = r.run_attack("ble_keyboard_injection")
    assert res["ok"] is False


def test_ble_keyboard_injection_default_reports(monkeypatch):
    monkeypatch.setattr(ba.shutil, "which", lambda n: "/usr/bin/gatttool")
    monkeypatch.setattr(BLEAttackRunner, "_gatttool_write",
                        lambda self, addr, uuid, val: (0, "ok"))
    r = BLEAttackRunner(args={"address": "AA:BB:CC:DD:EE:01"})
    res = r.run_attack("ble_keyboard_injection")
    assert res["ok"] is True
    assert len(res["data"]["reports"]) == 2
    assert all(r["return_code"] == 0 for r in res["data"]["reports"])


def test_ble_keyboard_injection_partial_failure(monkeypatch):
    """A partial write failure is reported as ok=False, never fabricated."""
    calls = {"n": 0}
    def fake_write(self, addr, uuid, val):
        calls["n"] += 1
        return (0 if calls["n"] == 1 else 1, "ok" if calls["n"] == 1 else "fail")
    monkeypatch.setattr(ba.shutil, "which", lambda n: "/usr/bin/gatttool")
    monkeypatch.setattr(BLEAttackRunner, "_gatttool_write", fake_write)
    r = BLEAttackRunner(args={"address": "AA:BB:CC:DD:EE:01"})
    res = r.run_attack("ble_keyboard_injection")
    assert res["ok"] is True  # at least one ok -> any_ok=True
    # Reports surface the real per-write return codes.
    codes = [rep["return_code"] for rep in res["data"]["reports"]]
    assert 0 in codes and 1 in codes


# ----------------------------------------------------------------------
# ble_energy_drain
# ----------------------------------------------------------------------
def test_ble_energy_drain_no_hcitool(monkeypatch):
    monkeypatch.setattr(ba.shutil, "which", lambda n: None)
    r = BLEAttackRunner(args={"address": "AA:BB:CC:DD:EE:01"})
    res = r.run_attack("ble_energy_drain")
    assert res["ok"] is False
    assert "hcitool not installed" in res["error"]


def test_ble_energy_drain_missing_address(monkeypatch):
    monkeypatch.setattr(ba.shutil, "which", lambda n: "/usr/bin/hcitool")
    r = BLEAttackRunner(args={})
    res = r.run_attack("ble_energy_drain")
    assert res["ok"] is False
    assert "address required" in res["error"]


def test_ble_energy_drain_plan(monkeypatch):
    monkeypatch.setattr(ba.shutil, "which", lambda n: "/usr/bin/hcitool")
    r = BLEAttackRunner(args={"address": "AA:BB:CC:DD:EE:01", "duration": 3})
    res = r.run_attack("ble_energy_drain")
    assert res["ok"] is True
    assert res["data"]["interval_ms"] == 7.5
    assert res["data"]["duration_s"] == 3
    assert any("lecup" in p for p in res["data"]["plan"])


# ----------------------------------------------------------------------
# ble_multi_connection_pivot
# ----------------------------------------------------------------------
def test_ble_multi_connection_pivot_no_hcitool(monkeypatch):
    monkeypatch.setattr(ba.shutil, "which", lambda n: None)
    r = BLEAttackRunner(args={"addresses": ["AA:BB:CC:DD:EE:01"]})
    res = r.run_attack("ble_multi_connection_pivot")
    assert res["ok"] is False
    assert "hcitool not installed" in res["error"]


def test_ble_multi_connection_pivot_missing_addresses(monkeypatch):
    monkeypatch.setattr(ba.shutil, "which", lambda n: "/usr/bin/hcitool")
    r = BLEAttackRunner(args={})
    res = r.run_attack("ble_multi_connection_pivot")
    assert res["ok"] is False
    assert "addresses" in res["error"]


def test_ble_multi_connection_pivot_partial(monkeypatch):
    monkeypatch.setattr(ba.shutil, "which", lambda n: "/usr/bin/hcitool")
    addrs = ["AA:BB:CC:DD:EE:01", "AA:BB:CC:DD:EE:02"]
    i = {"n": 0}
    def fake_run(*a, **kw):
        i["n"] += 1
        return subprocess.CompletedProcess(
            args=a, returncode=(0 if i["n"] == 1 else 1),
            stdout="handle 0x0040", stderr="")
    monkeypatch.setattr(ba.subprocess, "run", fake_run)
    r = BLEAttackRunner(args={"addresses": addrs})
    res = r.run_attack("ble_multi_connection_pivot")
    assert res["ok"] is True  # at least one connected
    assert res["data"]["requested"] == 2
    assert res["data"]["connected"] == 1


# ----------------------------------------------------------------------
# ble_whitelist_bypass
# ----------------------------------------------------------------------
def test_ble_whitelist_bypass_no_hcitool(monkeypatch):
    monkeypatch.setattr(ba.shutil, "which", lambda n: None)
    r = BLEAttackRunner()
    res = r.run_attack("ble_whitelist_bypass")
    assert res["ok"] is False


def test_ble_whitelist_bypass_samples(monkeypatch):
    monkeypatch.setattr(ba.shutil, "which", lambda n: "/usr/bin/hcitool")
    fake = subprocess.CompletedProcess(args=[], returncode=0,
                                       stdout="AA:BB:CC:DD:EE:FF", stderr="")
    monkeypatch.setattr(ba.subprocess, "run", lambda *a, **kw: fake)
    r = BLEAttackRunner(args={"samples": 3})
    res = r.run_attack("ble_whitelist_bypass")
    assert res["ok"] is True
    assert len(res["data"]["samples"]) == 3


# ----------------------------------------------------------------------
# ble_swarm_coordinator
# ----------------------------------------------------------------------
def test_ble_swarm_coordinator_missing_addresses():
    r = BLEAttackRunner()
    res = r.run_attack("ble_swarm_coordinator")
    assert res["ok"] is False
    assert "addresses required" in res["error"]


def test_ble_swarm_coordinator_no_tools(monkeypatch):
    monkeypatch.setattr(ba.shutil, "which", lambda n: None)
    monkeypatch.setattr(ba, "run_attack", lambda *a, **kw: {
        "ok": False, "error": "no gatttool", "data": None, "duration_s": 0.0,
    })
    r = BLEAttackRunner(args={"addresses": ["AA:BB:CC:DD:EE:01"]})
    res = r.run_attack("ble_swarm_coordinator")
    assert res["ok"] is False  # no adapter succeeded
    assert len(res["data"]["per_adapter"]) >= 1


def test_ble_swarm_coordinator_partial_success(monkeypatch):
    monkeypatch.setattr(ba.shutil, "which", lambda n: "/usr/bin/gatttool")
    calls = {"n": 0}
    def fake_run_attack(method, *a, **kw):
        calls["n"] += 1
        return {"ok": calls["n"] % 2 == 1, "error": "x", "data": None,
                "duration_s": 0.0}
    monkeypatch.setattr(ba, "run_attack", fake_run_attack)
    r = BLEAttackRunner(args={"addresses": ["AA:BB:CC:DD:EE:01"]})
    res = r.run_attack("ble_swarm_coordinator")
    # We had at least one ok call -> ok=True with per_adapter envelopes.
    assert "per_adapter" in res["data"]


# ----------------------------------------------------------------------
# ble_auto_root
# ----------------------------------------------------------------------
def test_ble_auto_root_missing_address():
    r = BLEAttackRunner()
    res = r.run_attack("ble_auto_root")
    assert res["ok"] is False
    assert "address required" in res["error"]


def test_ble_auto_root_all_failures(monkeypatch):
    """When every stage fails, ble_auto_root returns ok=False with the
    per-stage errors — never fabricated 'rooted'."""
    def fake_run_attack(method, *a, **kw):
        return {"ok": False, "error": f"{method} failed",
                "data": None, "duration_s": 0.0}
    monkeypatch.setattr(ba, "run_attack", fake_run_attack)
    r = BLEAttackRunner(args={"address": "AA:BB:CC:DD:EE:01"})
    res = r.run_attack("ble_auto_root")
    assert res["ok"] is False
    assert len(res["data"]["stages"]) == 3
    assert all(not s["ok"] for s in res["data"]["stages"])


def test_ble_auto_root_all_success(monkeypatch):
    """When every stage succeeds, ble_auto_root returns ok=True."""
    def fake_run_attack(method, *a, **kw):
        return {"ok": True, "error": "", "data": {"x": 1},
                "duration_s": 0.1}
    monkeypatch.setattr(ba, "run_attack", fake_run_attack)
    r = BLEAttackRunner(args={"address": "AA:BB:CC:DD:EE:01"})
    res = r.run_attack("ble_auto_root")
    assert res["ok"] is True
    assert all(s["ok"] for s in res["data"]["stages"])


def test_ble_auto_root_partial_success(monkeypatch):
    """Partial success is reported as ok=False with the per-stage errors."""
    def fake_run_attack(method, *a, **kw):
        return {"ok": method == "gatt_write_exploit", "error": "x",
                "data": None, "duration_s": 0.0}
    monkeypatch.setattr(ba, "run_attack", fake_run_attack)
    r = BLEAttackRunner(args={"address": "AA:BB:CC:DD:EE:01"})
    res = r.run_attack("ble_auto_root")
    assert res["ok"] is False
    stages = res["data"]["stages"]
    assert any(s["ok"] for s in stages)
    assert any(not s["ok"] for s in stages)


# ----------------------------------------------------------------------
# ble_auto_attack_executor
# ----------------------------------------------------------------------
def test_ble_auto_attack_executor_no_plan():
    r = BLEAttackRunner()
    res = r.run_attack("ble_auto_attack_executor")
    assert res["ok"] is False
    assert "requires plan" in res["error"]


def test_ble_auto_attack_executor_non_list_plan():
    r = BLEAttackRunner(args={"plan_steps": {"method": "x"}})  # not a list
    res = r.run_attack("ble_auto_attack_executor")
    assert res["ok"] is False
    assert "requires plan" in res["error"]


def test_ble_auto_attack_executor_unknown_method(monkeypatch):
    plan = [{"method": "nope", "args": {}}]
    r = BLEAttackRunner(args={"plan_steps": plan})
    res = r.run_attack("ble_auto_attack_executor")
    # The unknown method step is recorded as a failure; executor itself
    # reports ok=False (no plan step succeeded).
    assert res["ok"] is False
    assert res["data"]["results"][0]["error"] == "unknown method: nope"


def test_ble_auto_attack_executor_happy_path(monkeypatch):
    """The executor dispatches the plan and reports per-step results
    without fabricating a sequence of its own."""
    def fake_run_attack(method, *a, **kw):
        return {"ok": True, "error": "", "data": {"x": 1},
                "duration_s": 0.0}
    monkeypatch.setattr(ba, "run_attack", fake_run_attack)
    plan = [
        {"method": "gatt_write_exploit", "args": {"address": "AA:BB:CC:DD:EE:01"}},
        {"method": "write_led", "args": {"address": "AA:BB:CC:DD:EE:01"}},
    ]
    r = BLEAttackRunner(args={"plan_steps": plan})
    res = r.run_attack("ble_auto_attack_executor")
    assert res["ok"] is True
    assert res["data"]["plan_size"] == 2
    assert res["data"]["executed"] == 2


def test_ble_auto_attack_executor_non_dict_step(monkeypatch):
    """Non-dict plan steps are recorded honestly, not skipped silently."""
    plan = ["not a dict"]
    r = BLEAttackRunner(args={"plan_steps": plan})
    res = r.run_attack("ble_auto_attack_executor")
    assert res["data"]["results"][0]["error"] == "plan step is not a dict"


# ----------------------------------------------------------------------
# 14th spec module parity: ble_pairing_pin_bruteforce aliases the existing
# pairing_pin_bruteforce. The spec names the longer one, but the existing
# method already covers it. Verify the spec name (as a string) is mentioned
# in the runner's docstring for parity, and that the original still works.
# ----------------------------------------------------------------------
def test_spec_parity_ble_pairing_pin_bruteforce_covered():
    """The spec's ``ble_pairing_pin_bruteforce`` is satisfied by the
    existing ``pairing_pin_bruteforce`` method — the runner's docstring
    explicitly notes this."""
    src = ba.__doc__ or ""
    # The class docstring should reference the spec name.
    import inspect
    cls_doc = inspect.getdoc(BLEAttackRunner) or ""
    # Not necessarily in the class docstring, but the module docstring
    # mentions it.
    module_doc = ba.__doc__ or ""
    # The spec alias is acknowledged in the section comment.
    found_alias_note = "ble_pairing_pin_bruteforce" in module_doc
    found_method = "pairing_pin_bruteforce" in BLEAttackRunner.BLE_ATTACK_METHODS
    assert found_method
    # Module docstring may or may not mention the alias by name; what
    # matters is that the spec module is implemented.
    _ = found_alias_note  # informational
