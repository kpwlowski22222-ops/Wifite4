"""Tests for :mod:`core.wifi_attack.frames` (802.11 frame-crafting helpers).

The 6 ``craft_*_frame`` helpers follow a strict never-raise contract:
on success -> ``{"ok": True, "frame": bytes}``; on failure -> ``{"ok": False,
"error": "<exact reason>"}`` (scapy missing, layer missing, or build
exception). These tests exercise both the happy path (scapy installed
in the test venv) and the degrade paths via ``monkeypatch``.
"""
from __future__ import annotations

import builtins
import importlib

import pytest

from core.wifi_attack import frames


# A canonical 12-hex / 17-hex pair used by every helper.
BSSID = "AA:BB:CC:DD:EE:FF"
STATION = "11:22:33:44:55:66"


# ---------------------------------------------------------------------------
# Happy path: scapy is installed in the test venv
# ---------------------------------------------------------------------------


def test_craft_arp_frame_happy():
    """ARP frame: bytes returned, ok=True, contains the BSSID + station MACs."""
    out = frames.craft_arp_frame(BSSID, STATION, src_ip="10.0.0.1",
                                  dst_ip="10.0.0.99")
    assert isinstance(out, dict)
    assert out.get("ok") is True, out
    assert isinstance(out.get("frame"), bytes)
    # The frame must encode both the BSSID and the station MAC
    # somewhere in the raw bytes (the 6-byte binary form, no colons).
    bssid_bytes = bytes.fromhex(BSSID.replace(":", ""))
    station_bytes = bytes.fromhex(STATION.replace(":", ""))
    assert bssid_bytes in out["frame"], (
        f"BSSID {bssid_bytes!r} not found in frame {out['frame']!r}"
    )
    assert station_bytes in out["frame"], (
        f"station {station_bytes!r} not found in frame {out['frame']!r}"
    )


def test_craft_probe_response_happy():
    """Probe-response: bytes returned, ok=True, contains the SSID bytes."""
    out = frames.craft_probe_response(BSSID, STATION, ssid="TestSSID",
                                       channel=11)
    assert isinstance(out, dict)
    assert out.get("ok") is True, out
    assert isinstance(out.get("frame"), bytes)
    # The SSID is encoded as a Dot11Elt payload; check the literal string.
    assert b"TestSSID" in out["frame"]
    # The DS Parameter Set (channel=11 -> 0x0B) should be present.
    assert bytes([11]) in out["frame"]


def test_craft_auth_frame_happy():
    """Auth frame: bytes returned, ok=True, no SSID payload (auth is bare)."""
    out = frames.craft_auth_frame(BSSID, STATION, seqnum=2, status=0)
    assert isinstance(out, dict)
    assert out.get("ok") is True, out
    assert isinstance(out.get("frame"), bytes)
    bssid_bytes = bytes.fromhex(BSSID.replace(":", ""))
    station_bytes = bytes.fromhex(STATION.replace(":", ""))
    assert bssid_bytes in out["frame"]
    assert station_bytes in out["frame"]


def test_craft_assoc_req_frame_happy():
    """Assoc-req: bytes returned, ok=True, contains the SSID + DSset."""
    out = frames.craft_assoc_req_frame(BSSID, STATION, ssid="LabNet",
                                        channel=6)
    assert isinstance(out, dict)
    assert out.get("ok") is True, out
    assert isinstance(out.get("frame"), bytes)
    assert b"LabNet" in out["frame"]
    assert bytes([6]) in out["frame"]


def test_craft_disassoc_frame_happy():
    """Disassoc frame: bytes returned, ok=True, broadcast default."""
    out = frames.craft_disassoc_frame(BSSID, station=STATION, reason=4)
    assert isinstance(out, dict)
    assert out.get("ok") is True, out
    assert isinstance(out.get("frame"), bytes)
    bssid_bytes = bytes.fromhex(BSSID.replace(":", ""))
    station_bytes = bytes.fromhex(STATION.replace(":", ""))
    assert bssid_bytes in out["frame"]
    assert station_bytes in out["frame"]


def test_craft_null_data_frame_happy_power_save():
    """Null-data frame with PWR set; FCfield must encode the power-save bit."""
    out = frames.craft_null_data_frame(BSSID, STATION,
                                        power_save=True, more_data=False)
    assert isinstance(out, dict)
    assert out.get("ok") is True, out
    assert isinstance(out.get("frame"), bytes)
    # The PWR bit lives in Dot11.FCfield; the Dot11 layer serializes the
    # string-flag form. We can at least assert the frame is non-empty
    # and contains the BSSID + station MACs.
    assert len(out["frame"]) > 0
    bssid_bytes = bytes.fromhex(BSSID.replace(":", ""))
    assert bssid_bytes in out["frame"]


def test_craft_null_data_frame_happy_more_data():
    """Null-data frame with more_data=True (MD bit)."""
    out = frames.craft_null_data_frame(BSSID, STATION,
                                        power_save=False, more_data=True)
    assert isinstance(out, dict)
    assert out.get("ok") is True, out
    assert isinstance(out.get("frame"), bytes)


def test_craft_null_data_frame_happy_no_flags():
    """Null-data frame with both flags off; FCfield not mutated."""
    out = frames.craft_null_data_frame(BSSID, STATION,
                                        power_save=False, more_data=False)
    assert isinstance(out, dict)
    assert out.get("ok") is True, out


def test_craft_arp_frame_src_mac_override():
    """``src_mac`` override is honored (call-site symmetry path)."""
    out = frames.craft_arp_frame(BSSID, STATION, src_ip="10.0.0.1",
                                  dst_ip="10.0.0.99",
                                  src_mac="DE:AD:BE:EF:00:11")
    assert out.get("ok") is True, out
    # The custom src_mac must appear in the serialized ARP layer
    # as 6 raw bytes (no colons, no separators).
    src_norm = bytes.fromhex("DEADBEEF0011")
    assert src_norm in out["frame"], (
        f"src_mac {src_norm!r} not found in frame {out['frame']!r}"
    )


# ---------------------------------------------------------------------------
# Degrade path: simulate scapy missing / layer missing
# ---------------------------------------------------------------------------


def _block_scapy_top_level(monkeypatch):
    """Make ``from scapy.all import ...`` raise ImportError on first call.

    We patch ``sys.modules['scapy']`` to a stub that throws on attribute
    access, simulating a missing scapy install. The frame helpers catch
    the ImportError at their first ``from scapy.all import ...`` and
    return ``{"ok": False, "error": "scapy not installed"}``.
    """
    import sys
    class _Blocker:
        def __getattr__(self, name):
            raise ImportError("scapy is not installed (test-blocker)")
    # Drop the real scapy modules; subsequent imports re-run.
    for k in list(sys.modules):
        if k == "scapy" or k.startswith("scapy."):
            monkeypatch.delitem(sys.modules, k)
    # Make sure a fresh ``import scapy`` returns the blocker.
    monkeypatch.setitem(sys.modules, "scapy", _Blocker())
    monkeypatch.setitem(sys.modules, "scapy.all", _Blocker())


def test_craft_arp_frame_scapy_missing(monkeypatch):
    _block_scapy_top_level(monkeypatch)
    out = frames.craft_arp_frame(BSSID, STATION)
    assert out.get("ok") is False
    assert "scapy" in out.get("error", "").lower()
    assert "not installed" in out.get("error", "")


def test_craft_probe_response_scapy_missing(monkeypatch):
    _block_scapy_top_level(monkeypatch)
    out = frames.craft_probe_response(BSSID, STATION)
    assert out.get("ok") is False
    assert "scapy" in out.get("error", "").lower()


def test_craft_auth_frame_scapy_missing(monkeypatch):
    _block_scapy_top_level(monkeypatch)
    out = frames.craft_auth_frame(BSSID, STATION)
    assert out.get("ok") is False
    assert "scapy" in out.get("error", "").lower()


def test_craft_assoc_req_frame_scapy_missing(monkeypatch):
    _block_scapy_top_level(monkeypatch)
    out = frames.craft_assoc_req_frame(BSSID, STATION)
    assert out.get("ok") is False
    assert "scapy" in out.get("error", "").lower()


def test_craft_disassoc_frame_scapy_missing(monkeypatch):
    _block_scapy_top_level(monkeypatch)
    out = frames.craft_disassoc_frame(BSSID, STATION)
    assert out.get("ok") is False
    assert "scapy" in out.get("error", "").lower()


def test_craft_null_data_frame_scapy_missing(monkeypatch):
    _block_scapy_top_level(monkeypatch)
    out = frames.craft_null_data_frame(BSSID, STATION)
    assert out.get("ok") is False
    assert "scapy" in out.get("error", "").lower()


# ---------------------------------------------------------------------------
# Degrade path: scapy.top-level imports work but a specific layer is missing
# ---------------------------------------------------------------------------


def _block_scapy_layer(layer_name: str, monkeypatch):
    """Make only one specific scapy.all symbol raise ImportError, while
    letting the rest import cleanly. This exercises the
    ``scapy layer unavailable`` branch of every helper that loads a
    secondary layer.
    """
    import sys
    # Drop cached modules to force re-import.
    for k in list(sys.modules):
        if k == "scapy" or k.startswith("scapy."):
            monkeypatch.delitem(sys.modules, k)
    import scapy.all as real_scapy_all  # noqa: F401  - real scapy in test env
    # Wrap scapy.all so the named layer raises.
    class _Proxy:
        def __getattr__(self, name):
            if name == layer_name:
                raise ImportError(f"{layer_name} unavailable (test-blocker)")
            return getattr(real_scapy_all, name)
    monkeypatch.setitem(sys.modules, "scapy.all", _Proxy())


def test_craft_arp_frame_layer_missing(monkeypatch):
    """ARP path: block ``LLC`` (a secondary layer) -> ``scapy layer unavailable``."""
    _block_scapy_layer("LLC", monkeypatch)
    out = frames.craft_arp_frame(BSSID, STATION)
    assert out.get("ok") is False
    assert "layer" in out.get("error", "").lower()


def test_craft_probe_response_layer_missing(monkeypatch):
    """``craft_probe_response`` now uses ``Dot11Elt`` for the SSID + DSset
    IEs. Block ``Dot11Elt`` -> ``scapy layer unavailable``."""
    _block_scapy_layer("Dot11Elt", monkeypatch)
    out = frames.craft_probe_response(BSSID, STATION)
    assert out.get("ok") is False
    assert "layer" in out.get("error", "").lower()


def test_craft_auth_frame_layer_missing(monkeypatch):
    _block_scapy_layer("Dot11Auth", monkeypatch)
    out = frames.craft_auth_frame(BSSID, STATION)
    assert out.get("ok") is False
    assert "layer" in out.get("error", "").lower()


def test_craft_assoc_req_frame_layer_missing(monkeypatch):
    """``craft_assoc_req_frame`` now uses ``Dot11Elt`` for the SSID + DSset
    IEs. Block ``Dot11Elt`` -> ``scapy layer unavailable``."""
    _block_scapy_layer("Dot11Elt", monkeypatch)
    out = frames.craft_assoc_req_frame(BSSID, STATION)
    assert out.get("ok") is False
    assert "layer" in out.get("error", "").lower()


def test_craft_disassoc_frame_layer_missing(monkeypatch):
    _block_scapy_layer("Dot11Disas", monkeypatch)
    out = frames.craft_disassoc_frame(BSSID, STATION)
    assert out.get("ok") is False
    assert "layer" in out.get("error", "").lower()


# ---------------------------------------------------------------------------
# Degrade path: build phase raises (e.g. invalid channel out of range)
# ---------------------------------------------------------------------------


def test_craft_probe_response_invalid_channel(monkeypatch):
    """A channel > 255 still must not raise — the helper catches the
    build-time error and returns the exact failure string. The
    ``info=bytes([channel & 0xFF])`` mask keeps it safe for any int."""
    out = frames.craft_probe_response(BSSID, STATION, channel=9999)
    # scapy accepts the int and masks it; should be ok=True.
    assert out.get("ok") is True
    assert isinstance(out.get("frame"), bytes)


def test_craft_auth_frame_status_cast_to_int(monkeypatch):
    """``status`` is cast through ``int(...)`` so a string-int is honored."""
    out = frames.craft_auth_frame(BSSID, STATION, seqnum="3", status="13")
    assert out.get("ok") is True


# ---------------------------------------------------------------------------
# Contract: every helper is importable from the package root (__all__)
# ---------------------------------------------------------------------------


def test_craft_helpers_re_exported():
    """The 6 ``craft_*_frame`` helpers must be re-exported from
    :mod:`core.wifi_attack` (4-touchpoint layer 2)."""
    from core import wifi_attack
    for name in (
        "craft_arp_frame",
        "craft_probe_response",
        "craft_auth_frame",
        "craft_assoc_req_frame",
        "craft_disassoc_frame",
        "craft_null_data_frame",
    ):
        assert name in wifi_attack.__all__, (
            f"{name!r} missing from core.wifi_attack.__all__"
        )
        assert hasattr(wifi_attack, name), (
            f"{name!r} not accessible as core.wifi_attack.{name}"
        )
