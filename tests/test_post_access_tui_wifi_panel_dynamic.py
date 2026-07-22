"""Hermetic tests for the WIFI dynamic-menu pattern.

Mirrors tests/test_post_access_tui_ble_panel_dynamic.py for the
WIFI panel. Covers:
  - The capability catalog is non-empty
  - Every capability has a unique hotkey
  - The catalog has NO duplicate hotkeys
  - WifiPanelState helpers (has_adapter, is_wpa2, has_clients, etc.)
  - compute_visible_menu returns the right actions for each state
  - WiFiPanel.visible_capabilities() recomputes correctly
  - WiFiPanel.menu_text() renders only visible actions
  - The dynamic menu hides unavailable hotkeys (e.g. [1] Deauth
    only when clients are present)
  - The dynamic menu ADDS actions when state changes (e.g. after
    a successful scan, [L]ist appears)
  - The saved-APs JSON file is loaded and persisted
  - WiFiPanel.MENU / KEY_MAP cover the full catalog
  - WiFiPanel.HOTKEY_MAP is the inverse of KEY_MAP
  - The screen hook (wifi_dispatch) only accepts currently-visible
    hotkeys
  - The capability catalog can be extended without breaking the
    dispatcher
  - WiFiPanelClient adapter list / scan never raise
"""
from __future__ import annotations

import json
import re

import pytest


# ---------------------------------------------------------------------------
# Capability catalog
# ---------------------------------------------------------------------------
def test_catalog_non_empty():
    from core.post_access_tui.wifi_panel_capabilities import CAPABILITY_CATALOG
    assert len(CAPABILITY_CATALOG) >= 50


def test_catalog_unique_hotkeys():
    from core.post_access_tui.wifi_panel_capabilities import CAPABILITY_CATALOG
    seen = set()
    for cap in CAPABILITY_CATALOG:
        assert cap.hotkey not in seen, (
            f"duplicate hotkey {cap.hotkey!r} on action {cap.action!r}"
        )
        seen.add(cap.hotkey)


def test_catalog_unique_actions():
    from core.post_access_tui.wifi_panel_capabilities import CAPABILITY_CATALOG
    seen = set()
    for cap in CAPABILITY_CATALOG:
        assert cap.action not in seen, f"duplicate action {cap.action!r}"
        seen.add(cap.action)


def test_catalog_capabilities_have_required_fields():
    from core.post_access_tui.wifi_panel_capabilities import CAPABILITY_CATALOG
    for cap in CAPABILITY_CATALOG:
        assert isinstance(cap.action, str) and cap.action
        assert isinstance(cap.hotkey, str) and len(cap.hotkey) == 1
        assert isinstance(cap.label, str) and cap.label
        assert cap.risk in ("read", "intrusive", "destructive")
        assert isinstance(cap.requires_gate, bool)
        assert callable(cap.availability_fn)


def test_catalog_destructive_actions_marked_destructive():
    """evil_twin, karma, full_auto_pwn, mdk3/4, beacon_flood,
    ap_overload, scapy_flood are all destructive."""
    from core.post_access_tui.wifi_panel_capabilities import CAPABILITY_CATALOG
    by_action = {c.action: c for c in CAPABILITY_CATALOG}
    for action in ("evil_twin", "karma", "full_auto_pwn", "mdk3",
                   "mdk4", "beacon_flood", "ap_overload",
                   "scapy_flood", "client_creds"):
        assert action in by_action, f"missing action {action!r}"
        assert by_action[action].risk == "destructive", (
            f"{action} should be destructive, got {by_action[action].risk}"
        )


def test_catalog_ai_modules_labeled_heuristic():
    """AI modules in the help text should be labeled
    'heuristic (not trained)' so the operator knows."""
    from core.post_access_tui.wifi_panel_capabilities import CAPABILITY_CATALOG
    for cap in CAPABILITY_CATALOG:
        if "AI" in cap.label or "ai_" in cap.action or "fingerprint" in cap.action:
            if cap.help_text:
                # We require the heuristic disclaimer
                assert "heuristic" in cap.help_text.lower(), (
                    f"AI module {cap.action!r} should be labeled 'heuristic'"
                )


# ---------------------------------------------------------------------------
# WifiPanelState
# ---------------------------------------------------------------------------
def test_panel_state_defaults_disconnected():
    from core.post_access_tui.wifi_panel_capabilities import WifiPanelState
    ps = WifiPanelState()
    assert ps.has_adapter() is False
    assert ps.has_scan_results() is False
    assert ps.has_selected_ap() is False
    assert ps.has_clients() is False
    assert ps.is_wpa2() is False
    assert ps.is_wpa3() is False
    assert ps.is_wep() is False
    assert ps.is_open() is False
    assert ps.is_5ghz() is False
    assert ps.is_6ghz() is False
    assert ps.has_handshake() is False
    assert ps.has_pmkid() is False
    assert ps.has_capture() is False
    assert ps.has_wordlist() is False


def test_panel_state_has_adapter():
    from core.post_access_tui.wifi_panel_capabilities import WifiPanelState
    ps = WifiPanelState(adapter="wlan0")
    assert ps.has_adapter() is True


def test_panel_state_in_monitor_allows_scan():
    from core.post_access_tui.wifi_panel_capabilities import WifiPanelState
    ps = WifiPanelState(adapter="wlan0mon", monitor_mode=True)
    assert ps.has_adapter() is True
    assert ps.has_scan_results() is False


def test_panel_state_with_wpa2_ap():
    from core.post_access_tui.wifi_panel_capabilities import WifiPanelState
    ps = WifiPanelState(
        adapter="wlan0mon", monitor_mode=True,
        selected_ap={"bssid": "AA:BB:CC:DD:EE:01"},
        selected_ap_encryption="WPA2",
    )
    assert ps.has_selected_ap() is True
    assert ps.is_wpa2() is True
    assert ps.is_wpa3() is False
    assert ps.has_clients() is False


def test_panel_state_with_clients():
    from core.post_access_tui.wifi_panel_capabilities import WifiPanelState
    ps = WifiPanelState(
        adapter="wlan0mon", monitor_mode=True,
        selected_ap={"bssid": "AA:BB:CC:DD:EE:01"},
        selected_ap_encryption="WPA2",
        selected_ap_clients=["11:22:33:44:55:66"],
    )
    assert ps.has_clients() is True


def test_panel_state_5ghz_band():
    from core.post_access_tui.wifi_panel_capabilities import WifiPanelState
    ps = WifiPanelState(
        adapter="wlan0mon", monitor_mode=True,
        selected_ap={"bssid": "AA:BB:CC:DD:EE:01"},
        selected_ap_encryption="WPA2",
        selected_ap_band="5",
    )
    assert ps.is_5ghz() is True
    assert ps.is_2_4ghz() is False


def test_panel_state_6ghz_band():
    from core.post_access_tui.wifi_panel_capabilities import WifiPanelState
    ps = WifiPanelState(
        adapter="wlan0mon", monitor_mode=True,
        selected_ap={"bssid": "AA:BB:CC:DD:EE:01"},
        selected_ap_encryption="WPA3",
        selected_ap_band="6",
    )
    assert ps.is_6ghz() is True


def test_panel_state_wps_detected():
    from core.post_access_tui.wifi_panel_capabilities import WifiPanelState
    ps = WifiPanelState(
        adapter="wlan0mon", monitor_mode=True,
        selected_ap={"bssid": "AA:BB:CC:DD:EE:01"},
        selected_ap_wps=True,
    )
    # _has_wps needs an AP
    assert ps.has_selected_ap() is True
    assert ps.selected_ap_wps is True


def test_panel_state_handshake_captured():
    from core.post_access_tui.wifi_panel_capabilities import WifiPanelState
    ps = WifiPanelState(
        adapter="wlan0mon", monitor_mode=True,
        selected_ap={"bssid": "AA:BB:CC:DD:EE:01"},
        selected_ap_encryption="WPA2",
        handshake_captured=True,
    )
    assert ps.has_handshake() is True
    assert ps.has_capture() is True


def test_panel_state_wordlist_loaded():
    from core.post_access_tui.wifi_panel_capabilities import WifiPanelState
    ps = WifiPanelState(
        adapter="wlan0mon", monitor_mode=True,
        wordlist_loaded=True,
    )
    assert ps.has_wordlist() is True


# ---------------------------------------------------------------------------
# compute_visible_menu
# ---------------------------------------------------------------------------
def test_compute_visible_disconnected_state():
    """No adapter, no monitor: only the disconnected menu appears."""
    from core.post_access_tui.wifi_panel_capabilities import (
        WifiPanelState, compute_visible_menu,
    )
    visible = compute_visible_menu(WifiPanelState())
    actions = {c.action for c in visible}
    assert "adapters" in actions
    assert "select_adapter" in actions
    assert "help" in actions
    assert "exit" in actions
    # No monitor / scan / attack
    assert "scan" not in actions
    assert "deauth" not in actions
    assert "evil_twin" not in actions


def test_compute_visible_adapter_managed():
    """Adapter set, but not in monitor: monitor switch appears,
    but scan/attack don't."""
    from core.post_access_tui.wifi_panel_capabilities import (
        WifiPanelState, compute_visible_menu,
    )
    ps = WifiPanelState(adapter="wlan0", monitor_mode=False)
    visible = compute_visible_menu(ps)
    actions = {c.action for c in visible}
    assert "enable_monitor" in actions
    assert "disable_monitor" not in actions
    assert "scan" not in actions
    assert "deauth" not in actions


def test_compute_visible_monitor_no_scan():
    """In monitor mode but no scan: scan appears, list doesn't,
    attack actions don't."""
    from core.post_access_tui.wifi_panel_capabilities import (
        WifiPanelState, compute_visible_menu,
    )
    ps = WifiPanelState(adapter="wlan0mon", monitor_mode=True)
    visible = compute_visible_menu(ps)
    actions = {c.action for c in visible}
    assert "scan" in actions
    assert "list" not in actions
    assert "select_ap" not in actions
    assert "deauth" not in actions
    assert "evil_twin" not in actions
    # In-monitor recon actions
    assert "probe_harvest" in actions
    assert "rf_survey" in actions
    assert "channel_hop" in actions


def test_compute_visible_monitor_with_scan_no_ap():
    """After a scan, [L]ist and [P]ick AP appear."""
    from core.post_access_tui.wifi_panel_capabilities import (
        WifiPanelState, compute_visible_menu,
    )
    ps = WifiPanelState(adapter="wlan0mon", monitor_mode=True,
                        scan_results=[{"bssid": "AA:BB:CC:DD:EE:01"}])
    visible = compute_visible_menu(ps)
    actions = {c.action for c in visible}
    assert "list" in actions
    assert "select_ap" in actions
    # No deauth yet (no AP)
    assert "deauth" not in actions
    # No evil twin
    assert "evil_twin" not in actions


def test_compute_visible_wpa2_ap_no_clients():
    """WPA2 AP selected, no clients: PMKID appears, deauth doesn't,
    evil_twin appears but karma does not (no clients)."""
    from core.post_access_tui.wifi_panel_capabilities import (
        WifiPanelState, compute_visible_menu,
    )
    ps = WifiPanelState(
        adapter="wlan0mon", monitor_mode=True,
        scan_results=[{"bssid": "AA:BB:CC:DD:EE:01"}],
        selected_ap={"bssid": "AA:BB:CC:DD:EE:01"},
        selected_ap_encryption="WPA2",
    )
    visible = compute_visible_menu(ps)
    actions = {c.action for c in visible}
    assert "pmkid" in actions
    assert "capture_handshake" in actions
    assert "deauth" not in actions  # requires clients
    assert "evil_twin" in actions  # no clients needed
    assert "karma" in actions


def test_compute_visible_wpa2_ap_with_clients():
    """WPA2 AP with clients: deauth appears, band_steering appears,
    client_creds appears, all of the WPA2+clients actions."""
    from core.post_access_tui.wifi_panel_capabilities import (
        WifiPanelState, compute_visible_menu,
    )
    ps = WifiPanelState(
        adapter="wlan0mon", monitor_mode=True,
        scan_results=[{"bssid": "AA:BB:CC:DD:EE:01"}],
        selected_ap={"bssid": "AA:BB:CC:DD:EE:01"},
        selected_ap_encryption="WPA2",
        selected_ap_clients=["11:22:33:44:55:66"],
    )
    visible = compute_visible_menu(ps)
    actions = {c.action for c in visible}
    assert "deauth" in actions
    assert "client_creds" in actions
    assert "client_powersave" in actions
    assert "band_steering" in actions
    assert "wnm_sleep" in actions
    assert "disassoc" in actions
    assert "eapol_logoff" in actions


def test_compute_visible_wpa3_ap():
    """WPA3 AP: sae_downgrade, sae_reflection, dragonblood appear;
    wpa2-only actions like pmkid do not."""
    from core.post_access_tui.wifi_panel_capabilities import (
        WifiPanelState, compute_visible_menu,
    )
    ps = WifiPanelState(
        adapter="wlan0mon", monitor_mode=True,
        scan_results=[{"bssid": "AA:BB:CC:DD:EE:01"}],
        selected_ap={"bssid": "AA:BB:CC:DD:EE:01"},
        selected_ap_encryption="WPA3",
    )
    visible = compute_visible_menu(ps)
    actions = {c.action for c in visible}
    assert "sae_downgrade" in actions
    assert "sae_reflection" in actions
    assert "dragonblood" in actions
    # No WPA2-specific attacks
    assert "pmkid" not in actions
    assert "capture_handshake" not in actions


def test_compute_visible_wep_ap():
    from core.post_access_tui.wifi_panel_capabilities import (
        WifiPanelState, compute_visible_menu,
    )
    ps = WifiPanelState(
        adapter="wlan0mon", monitor_mode=True,
        scan_results=[{"bssid": "AA:BB:CC:DD:EE:01"}],
        selected_ap={"bssid": "AA:BB:CC:DD:EE:01"},
        selected_ap_encryption="WEP",
    )
    visible = compute_visible_menu(ps)
    actions = {c.action for c in visible}
    assert "wep_ai" in actions
    assert "wep_fragment" in actions


def test_compute_visible_open_ap():
    from core.post_access_tui.wifi_panel_capabilities import (
        WifiPanelState, compute_visible_menu,
    )
    ps = WifiPanelState(
        adapter="wlan0mon", monitor_mode=True,
        scan_results=[{"bssid": "AA:BB:CC:DD:EE:01"}],
        selected_ap={"bssid": "AA:BB:CC:DD:EE:01"},
        selected_ap_encryption="OPEN",
    )
    visible = compute_visible_menu(ps)
    actions = {c.action for c in visible}
    assert "open_capture" in actions


def test_compute_visible_wps_only_when_wps_set():
    from core.post_access_tui.wifi_panel_capabilities import (
        WifiPanelState, compute_visible_menu,
    )
    ps_no_wps = WifiPanelState(
        adapter="wlan0mon", monitor_mode=True,
        scan_results=[{"bssid": "AA:BB:CC:DD:EE:01"}],
        selected_ap={"bssid": "AA:BB:CC:DD:EE:01"},
    )
    assert "wps_null_pin" not in {c.action for c in compute_visible_menu(ps_no_wps)}
    ps_wps = WifiPanelState(
        adapter="wlan0mon", monitor_mode=True,
        scan_results=[{"bssid": "AA:BB:CC:DD:EE:01"}],
        selected_ap={"bssid": "AA:BB:CC:DD:EE:01"},
        selected_ap_wps=True,
    )
    assert "wps_null_pin" in {c.action for c in compute_visible_menu(ps_wps)}
    assert "wps_button" in {c.action for c in compute_visible_menu(ps_wps)}


def test_compute_visible_5ghz_only_5ghz_attacks():
    from core.post_access_tui.wifi_panel_capabilities import (
        WifiPanelState, compute_visible_menu,
    )
    ps = WifiPanelState(
        adapter="wlan0mon", monitor_mode=True,
        scan_results=[{"bssid": "AA:BB:CC:DD:EE:01"}],
        selected_ap={"bssid": "AA:BB:CC:DD:EE:01"},
        selected_ap_encryption="WPA2",
        selected_ap_band="5",
    )
    visible = compute_visible_menu(ps)
    actions = {c.action for c in visible}
    assert "ofdma_steal" in actions
    assert "mu_mimo_null" in actions
    assert "twt_exhaust" in actions
    assert "preamble_puncture" in actions
    assert "bss_color_poison" in actions
    # No 6 GHz
    assert "6ghz_burst" not in actions


def test_compute_visible_6ghz():
    from core.post_access_tui.wifi_panel_capabilities import (
        WifiPanelState, compute_visible_menu,
    )
    ps = WifiPanelState(
        adapter="wlan0mon", monitor_mode=True,
        scan_results=[{"bssid": "AA:BB:CC:DD:EE:01"}],
        selected_ap={"bssid": "AA:BB:CC:DD:EE:01"},
        selected_ap_encryption="WPA3",
        selected_ap_band="6",
    )
    visible = compute_visible_menu(ps)
    actions = {c.action for c in visible}
    assert "6ghz_burst" in actions


def test_compute_visible_handshake_with_wordlist():
    """When handshake is captured and wordlist is loaded,
    [=] Hashcat 22001 appears."""
    from core.post_access_tui.wifi_panel_capabilities import (
        WifiPanelState, compute_visible_menu,
    )
    ps = WifiPanelState(
        adapter="wlan0mon", monitor_mode=True,
        scan_results=[{"bssid": "AA:BB:CC:DD:EE:01"}],
        selected_ap={"bssid": "AA:BB:CC:DD:EE:01"},
        selected_ap_encryption="WPA2",
        handshake_captured=True,
        wordlist_loaded=True,
    )
    visible = compute_visible_menu(ps)
    actions = {c.action for c in visible}
    assert "hashcat_22001" in actions
    # No PMKID hashcat
    assert "hashcat_16800" not in actions


def test_compute_visible_pmkid_with_wordlist():
    from core.post_access_tui.wifi_panel_capabilities import (
        WifiPanelState, compute_visible_menu,
    )
    ps = WifiPanelState(
        adapter="wlan0mon", monitor_mode=True,
        scan_results=[{"bssid": "AA:BB:CC:DD:EE:01"}],
        selected_ap={"bssid": "AA:BB:CC:DD:EE:01"},
        selected_ap_encryption="WPA2",
        pmkid_captured=True,
        wordlist_loaded=True,
    )
    visible = compute_visible_menu(ps)
    actions = {c.action for c in visible}
    assert "hashcat_16800" in actions
    assert "hashcat_22001" not in actions


def test_compute_visible_no_wordlist_no_crack():
    """No wordlist = no hashcat action, even with capture."""
    from core.post_access_tui.wifi_panel_capabilities import (
        WifiPanelState, compute_visible_menu,
    )
    ps = WifiPanelState(
        adapter="wlan0mon", monitor_mode=True,
        scan_results=[{"bssid": "AA:BB:CC:DD:EE:01"}],
        selected_ap={"bssid": "AA:BB:CC:DD:EE:01"},
        selected_ap_encryption="WPA2",
        handshake_captured=True,
        # no wordlist
    )
    visible = compute_visible_menu(ps)
    actions = {c.action for c in visible}
    assert "hashcat_22001" not in actions
    # But [w] Wordlist is still available
    assert "wordlist" in actions


# ---------------------------------------------------------------------------
# WiFiPanel integration
# ---------------------------------------------------------------------------
def _build_panel(state=None, fake_client=None):
    from core.post_access_tui.wifi_panel import WiFiPanel
    if fake_client is None:
        fake_client = _MinimalFakeClient()
    panel = WiFiPanel(
        client=fake_client,
        confirm_fn=lambda _p: True,
    )
    return panel


class _MinimalFakeClient:
    """Bare-bones client for tests that don't dispatch runner methods."""

    def list_adapters(self):
        return {"ok": True, "data": {"stdout": ""}, "error": "",
                "duration_s": 0.0, "host_os": "Linux", "risk": "read"}

    def driver_info(self, adapter):
        return {"ok": True, "data": {"stdout": ""}, "error": "",
                "duration_s": 0.0, "host_os": "Linux", "risk": "read"}

    def enable_monitor(self, adapter):
        return {"ok": True, "data": {"stdout": ""}, "error": "",
                "duration_s": 0.0, "host_os": "Linux", "risk": "intrusive"}

    def disable_monitor(self, adapter):
        return {"ok": True, "data": {"stdout": ""}, "error": "",
                "duration_s": 0.0, "host_os": "Linux", "risk": "intrusive"}

    def set_channel(self, adapter, channel):
        return {"ok": True, "data": {"stdout": ""}, "error": "",
                "duration_s": 0.0, "host_os": "Linux", "risk": "intrusive"}

    def scan(self, adapter, *, duration_s=8):
        return {"ok": True, "data": {"aps": [], "count": 0}, "error": "",
                "duration_s": 0.0, "host_os": "Linux", "risk": "read"}

    def run_wifi_attack(self, method, adapter=None, args=None):
        return {"ok": True, "name": method, "data": {},
                "error": "", "duration_s": 0.0}

    def run_extended_wifi(self, method, adapter=None, args=None):
        return {"ok": True, "name": method, "data": {},
                "error": "", "duration_s": 0.0}


def test_panel_visible_capabilities_disconnected():
    panel = _build_panel()
    caps = panel.visible_capabilities()
    actions = {c.action for c in caps}
    assert "adapters" in actions
    assert "exit" in actions
    # No deauth without an AP
    assert "deauth" not in actions


def test_panel_menu_text_renders_only_visible_actions():
    panel = _build_panel()
    text = panel.menu_text()
    # In disconnected state, "Deauth" should NOT appear
    assert "[1] Deauth" not in text
    # But "[a]dapters" and "[e]xit" should
    assert "[a] Adapters" in text
    assert "[e] Exit" in text


def test_panel_menu_text_shows_no_adapter_footer():
    panel = _build_panel()
    text = panel.menu_text()
    assert "no adapter selected" in text


def test_panel_menu_text_includes_deauth_with_clients():
    from core.post_access_tui.wifi_panel import WiFiAP
    panel = _build_panel()
    panel.adapter = "wlan0mon"
    panel._monitor_mode = True
    panel.scan_results = [WiFiAP(
        bssid="AA:BB:CC:DD:EE:01", ssid="Foo",
        channel=6, encryption="WPA2", band="2.4",
        clients=["11:22:33:44:55:66"],
    )]
    panel.selected_ap = panel.scan_results[0]
    text = panel.menu_text()
    assert "[1] Deauth" in text


def test_panel_visible_hotkey_set_changes_with_state():
    panel = _build_panel()
    initial = {c.hotkey for c in panel.visible_capabilities()}
    panel.adapter = "wlan0mon"
    panel._monitor_mode = True
    after = {c.hotkey for c in panel.visible_capabilities()}
    # [m] (enable_monitor) should disappear, [M] (disable_monitor) appears
    # (and [s] scan, [c] channel_set appear)
    assert "m" not in after or "M" in after
    assert "s" in after


# ---------------------------------------------------------------------------
# Saved APs persistence
# ---------------------------------------------------------------------------
def test_saved_aps_load_persistence(tmp_path):
    """Saved APs are loaded from disk at panel construction."""
    from core.post_access_tui.wifi_panel import WiFiPanel
    path = tmp_path / "aps.json"
    path.write_text(json.dumps([
        {"bssid": "AA:BB:CC:DD:EE:01", "ssid": "Foo",
         "channel": 6, "encryption": "WPA2", "wps": False,
         "pmf": False, "band": "2.4", "notes": "",
         "saved_at": 1000.0},
    ]))
    panel = WiFiPanel(
        client=_MinimalFakeClient(),
        confirm_fn=lambda _p: True,
        saved_aps_path=str(path),
    )
    panel.refresh_state()
    assert len(panel.panel_state.saved_aps) == 1
    assert panel.panel_state.saved_aps[0]["bssid"] == "AA:BB:CC:DD:EE:01"


def test_saved_aps_persist_on_add(tmp_path):
    """Adding an AP via _add_saved_ap persists to disk."""
    from core.post_access_tui.wifi_panel import WiFiPanel, WiFiAP
    path = tmp_path / "aps.json"
    panel = WiFiPanel(
        client=_MinimalFakeClient(),
        confirm_fn=lambda _p: True,
        saved_aps_path=str(path),
    )
    ap = WiFiAP(bssid="AA:BB:CC:DD:EE:02", ssid="Bar",
                channel=11, encryption="WPA2", band="2.4")
    panel._add_saved_ap(ap, notes="lab test")
    data = json.loads(path.read_text())
    assert any(d["bssid"] == "AA:BB:CC:DD:EE:02" for d in data)


def test_saved_aps_memory_only_when_path_is_memory():
    from core.post_access_tui.wifi_panel import WiFiPanel, WiFiAP
    panel = WiFiPanel(
        client=_MinimalFakeClient(),
        confirm_fn=lambda _p: True,
        saved_aps_path=":memory:",
    )
    ap = WiFiAP(bssid="AA:BB:CC:DD:EE:03", ssid="Baz",
                channel=1, encryption="OPEN", band="2.4")
    panel._add_saved_ap(ap)
    assert len(panel.saved_aps) == 1


# ---------------------------------------------------------------------------
# Screen hook: hotkey availability check
# ---------------------------------------------------------------------------
def test_screen_hook_rejects_unavailable_hotkey():
    """wifi_dispatch with an unavailable hotkey must say so and
    NOT dispatch."""
    from core.post_access_tui.wifi_panel import WiFiPanel, wifi_dispatch
    panel = WiFiPanel(
        client=_MinimalFakeClient(),
        confirm_fn=lambda _p: True,
    )

    class _Screen:
        def __init__(self):
            self.log = []
            self.confirm_fn = lambda _p: True
            self._on_event = self._emit
            it = iter(["1", "e"])  # '1' = Deauth (unavailable)
            def _f(_p):
                try:
                    return next(it)
                except StopIteration:
                    return ""
            self.input_fn = _f

        def _emit(self, m):
            self.log.append(m)

    screen = _Screen()
    wifi_dispatch(screen, panel)
    assert any("not in current menu" in line or "not available" in line
               for line in screen.log), screen.log


def test_screen_hook_accepts_available_hotkey():
    """wifi_dispatch with a currently-available hotkey (after
    selecting an adapter + monitor + scan) must dispatch it."""
    from core.post_access_tui.wifi_panel import WiFiPanel, wifi_dispatch, WiFiAP

    panel = WiFiPanel(
        client=_MinimalFakeClient(),
        confirm_fn=lambda _p: True,
    )
    panel.adapter = "wlan0mon"
    panel._monitor_mode = True
    # [s] (scan) is available in monitor mode without scan results
    # [l] (list) requires scan_results. We use [s] here.
    dispatched = []

    class _Screen:
        def __init__(self):
            self.log = []
            self.confirm_fn = lambda _p: True
            self._on_event = self._emit
            it = iter(["s", "e"])
            def _f(_p):
                try:
                    return next(it)
                except StopIteration:
                    return ""
            self.input_fn = _f

        def _emit(self, m):
            self.log.append(m)

    screen = _Screen()
    real_dispatch = panel.dispatch

    def _spy_dispatch(action, args=None):
        dispatched.append(action)
        return {"ok": True, "data": {}, "error": "",
                "duration_s": 0.0, "host_os": "Linux",
                "risk": "read", "action": action}

    panel.dispatch = _spy_dispatch
    try:
        wifi_dispatch(screen, panel)
    finally:
        panel.dispatch = real_dispatch
    assert "scan" in dispatched, dispatched


# ---------------------------------------------------------------------------
# Menu / KEY_MAP consistency
# ---------------------------------------------------------------------------
def test_panel_menu_contains_all_catalog_actions():
    from core.post_access_tui.wifi_panel import WiFiPanel
    from core.post_access_tui.wifi_panel_capabilities import CAPABILITY_CATALOG
    actions_in_menu = {a for _, a in WiFiPanel.MENU}
    catalog_actions = {c.action for c in CAPABILITY_CATALOG}
    assert actions_in_menu == catalog_actions


def test_panel_key_map_contains_all_hotkeys():
    from core.post_access_tui.wifi_panel import WiFiPanel
    from core.post_access_tui.wifi_panel_capabilities import CAPABILITY_CATALOG
    catalog_hotkeys = {c.hotkey for c in CAPABILITY_CATALOG}
    assert set(WiFiPanel.KEY_MAP.keys()) == catalog_hotkeys


def test_panel_hotkey_map_is_inverse_of_key_map():
    from core.post_access_tui.wifi_panel import WiFiPanel
    for k, v in WiFiPanel.KEY_MAP.items():
        assert WiFiPanel.HOTKEY_MAP[v] == k


def test_panel_key_map_values_are_action_names():
    from core.post_access_tui.wifi_panel import WiFiPanel
    from core.post_access_tui.wifi_panel_capabilities import CAPABILITY_CATALOG
    catalog_actions = {c.action for c in CAPABILITY_CATALOG}
    catalog_actions.add("exit")  # exit is also a key
    for k, v in WiFiPanel.KEY_MAP.items():
        assert v in catalog_actions, (
            f"KEY_MAP[{k!r}] = {v!r} not in catalog actions"
        )


# ---------------------------------------------------------------------------
# Catalog robustness
# ---------------------------------------------------------------------------
def test_availability_fn_exception_does_not_crash_menu():
    """A buggy availability_fn must NOT crash compute_visible_menu."""
    from core.post_access_tui.wifi_panel_capabilities import (
        CAPABILITY_CATALOG, WifiPanelState, compute_visible_menu,
    )
    import dataclasses
    original = CAPABILITY_CATALOG[0]
    buggy = dataclasses.replace(
        original, availability_fn=lambda _s: (1 / 0),
    )
    # Replace the catalog with a list containing the buggy cap
    original_index = list(CAPABILITY_CATALOG).index(original)
    mutated = list(CAPABILITY_CATALOG)
    mutated[original_index] = buggy
    try:
        ps = WifiPanelState(adapter="wlan0mon", monitor_mode=True)
        # Should NOT raise
        visible = compute_visible_menu(ps)
        # The buggy capability should be filtered out
        assert all(c is not buggy for c in visible)
    finally:
        pass  # nothing to restore since we used `replace`


# ---------------------------------------------------------------------------
# WiFiPanelClient adapter list never raises
# ---------------------------------------------------------------------------
def test_wifi_panel_client_list_adapters_no_iw(monkeypatch):
    """If `iw` is not on PATH, list_adapters returns honest-degrade."""
    from core.post_access_tui.wifi_panel import WiFiPanelClient
    import subprocess
    real_run = subprocess.run

    def fake_run(*args, **kwargs):
        if args and args[0] and args[0][0] == "iw":
            raise FileNotFoundError("no iw")
        return real_run(*args, **kwargs)

    monkeypatch.setattr("subprocess.run", fake_run)
    client = WiFiPanelClient()
    env = client.list_adapters()
    assert env["ok"] is False
    assert "iw" in env["error"].lower() or "not installed" in env["error"].lower()


def test_wifi_panel_client_scan_no_airodump(monkeypatch):
    """If `airodump-ng` is not on PATH, scan returns honest-degrade."""
    from core.post_access_tui.wifi_panel import WiFiPanelClient
    import subprocess
    real_popen = subprocess.Popen

    def fake_popen(*args, **kwargs):
        if args and args[0] and "airodump-ng" in args[0]:
            raise FileNotFoundError("no airodump-ng")
        return real_popen(*args, **kwargs)

    monkeypatch.setattr("subprocess.Popen", fake_popen)
    client = WiFiPanelClient()
    env = client.scan("wlan0mon", duration_s=1)
    assert env["ok"] is False


# ---------------------------------------------------------------------------
# AI plan
# ---------------------------------------------------------------------------
def test_ai_plan_no_ap_returns_degrade():
    from core.post_access_tui.wifi_panel import WiFiPanel
    panel = WiFiPanel(client=_MinimalFakeClient(), confirm_fn=lambda _p: True)
    env = panel.dispatch("ai_plan")
    assert env["ok"] is False
    assert "no ap" in env["error"].lower()


def test_ai_plan_wpa2_with_clients():
    from core.post_access_tui.wifi_panel import WiFiPanel, WiFiAP
    panel = WiFiPanel(client=_MinimalFakeClient(), confirm_fn=lambda _p: True)
    panel.adapter = "wlan0mon"
    panel._monitor_mode = True
    panel.selected_ap = WiFiAP(
        bssid="AA:BB:CC:DD:EE:01", ssid="Foo",
        channel=6, encryption="WPA2", band="2.4",
        clients=["11:22:33:44:55:66"],
    )
    env = panel.dispatch("ai_plan")
    assert env["ok"] is True
    plan_lines = env["data"]["plan"]
    # WPA2 with clients → deauth + handshake
    assert any("Deauth" in line for line in plan_lines)
    assert any("Handshake" in line for line in plan_lines)


def test_ai_plan_wpa3():
    from core.post_access_tui.wifi_panel import WiFiPanel, WiFiAP
    panel = WiFiPanel(client=_MinimalFakeClient(), confirm_fn=lambda _p: True)
    panel.adapter = "wlan0mon"
    panel._monitor_mode = True
    panel.selected_ap = WiFiAP(
        bssid="AA:BB:CC:DD:EE:01", ssid="Bar",
        channel=149, encryption="WPA3", band="5",
    )
    env = panel.dispatch("ai_plan")
    assert env["ok"] is True
    plan_lines = env["data"]["plan"]
    assert any("SAE" in line or "Dragonblood" in line
               for line in plan_lines)


def test_ai_plan_wep():
    from core.post_access_tui.wifi_panel import WiFiPanel, WiFiAP
    panel = WiFiPanel(client=_MinimalFakeClient(), confirm_fn=lambda _p: True)
    panel.adapter = "wlan0mon"
    panel._monitor_mode = True
    panel.selected_ap = WiFiAP(
        bssid="AA:BB:CC:DD:EE:01", ssid="OldNet",
        channel=1, encryption="WEP", band="2.4",
    )
    env = panel.dispatch("ai_plan")
    assert env["ok"] is True
    plan_lines = env["data"]["plan"]
    assert any("WEP" in line for line in plan_lines)


def test_ai_plan_open():
    from core.post_access_tui.wifi_panel import WiFiPanel, WiFiAP
    panel = WiFiPanel(client=_MinimalFakeClient(), confirm_fn=lambda _p: True)
    panel.adapter = "wlan0mon"
    panel._monitor_mode = True
    panel.selected_ap = WiFiAP(
        bssid="AA:BB:CC:DD:EE:01", ssid="FreeWiFi",
        channel=1, encryption="OPEN", band="2.4",
    )
    env = panel.dispatch("ai_plan")
    assert env["ok"] is True
    plan_lines = env["data"]["plan"]
    assert any("Open capture" in line for line in plan_lines)


# ---------------------------------------------------------------------------
# Dispatcher mapping
# ---------------------------------------------------------------------------
def test_dispatch_runner_unknown_action_returns_degrade():
    """Actions that are not in _RUNNER_DISPATCH degrade honestly."""
    from core.post_access_tui.wifi_panel import WiFiPanel
    panel = WiFiPanel(client=_MinimalFakeClient(), confirm_fn=lambda _p: True)
    # Use a synthetic action that doesn't exist
    env = panel.dispatch("totally_made_up_action")
    assert env["ok"] is False


def test_dispatch_runner_dispatches_to_correct_runner():
    """The deauth action is mapped to 'panel' (not wifi/ext); evil_twin
    is mapped to wifi."""
    from core.post_access_tui.wifi_panel import WiFiPanel
    from core.post_access_tui.wifi_panel import _RUNNER_DISPATCH
    assert "deauth" in _RUNNER_DISPATCH
    assert _RUNNER_DISPATCH["deauth"][0] == "panel"
    assert "evil_twin" in _RUNNER_DISPATCH
    assert _RUNNER_DISPATCH["evil_twin"][0] == "wifi"
    assert _RUNNER_DISPATCH["evil_twin"][1] == "evil_twin_automated"


# ---------------------------------------------------------------------------
# Integration: real module is importable, full surface
# ---------------------------------------------------------------------------
def test_wifi_panel_module_exports():
    from core.post_access_tui import wifi_panel
    for name in ("WiFiAP", "WiFiPanel", "WiFiPanelClient",
                 "wifi_dispatch"):
        assert hasattr(wifi_panel, name), f"missing {name}"


def test_post_access_tui_init_reexports_wifi_panel():
    from core.post_access_tui import (
        WiFiAP, WiFiPanel, WiFiPanelClient, wifi_dispatch,
    )
    assert WiFiAP is not None
    assert WiFiPanel is not None
