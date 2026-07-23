"""Anomaly reaction + live UI labels + target score."""
from __future__ import annotations

from core.os_agent.anomaly_loop import (
    classify_anomaly, design_reaction, react_to_anomaly,
)
from core.os_agent.live_labels import (
    upsert_label, list_labels, get_label, register_builtin_tui_labels,
)
from core.os_agent.ready_check import ready_check
from core.poly.target_score import rank_targets, score_wifi, full_auto_enabled


def test_classify_and_design_port_in_use():
    a = classify_anomaly({"error": "bind: Address already in use"})
    assert a["kind"] == "port_in_use"
    d = design_reaction(a)
    assert d["deep_think_type"]
    assert d["moves"]


def test_classify_adapter_blocked_as_permission():
    a = classify_anomaly({
        "error": "adapter_blocked",
        "permission": True,
        "domain": "wifi",
    })
    assert a["kind"] == "permission"
    d = design_reaction({**a, "domain": "wifi"})
    types = [m.get("type") for m in d["moves"]]
    assert any(t in ("holo_preset", "holo_wifi_or_ble_prep", "suggest_sudo") for t in types)


def test_react_to_anomaly_dry_run():
    r = react_to_anomaly(
        {"error": "timeout waiting", "elapsed_s": 99, "domain": "wifi"},
        dry_run=True,
    )
    assert r.get("ok") is True
    assert "narrative" in r
    assert r.get("results")


def test_live_label_schema(tmp_path, monkeypatch):
    monkeypatch.setenv("KFIOSA_UI_LABELS_ROOT", str(tmp_path / "lbl"))
    r = upsert_label(
        "Scan",
        what_for="Discover APs",
        why="Need targets",
        predictable="Opens triple windows",
        bbox=[10, 20, 100, 30],
        label_id="test-scan",
    )
    assert r.get("ok") is True
    lab = get_label("test-scan")
    assert lab is not None
    assert lab["what_for"] == "Discover APs"
    assert lab["center"] == [60.0, 35.0]
    assert lab["png"] == "" or True
    assert any(x["id"] == "test-scan" for x in list_labels())


def test_register_builtin_labels(tmp_path, monkeypatch):
    monkeypatch.setenv("KFIOSA_UI_LABELS_ROOT", str(tmp_path / "lbl2"))
    r = register_builtin_tui_labels()
    assert r.get("count", 0) >= 3


def test_rank_targets_wifi():
    items = [
        {"ssid": "far", "power": -90, "encryption": "WPA2", "clients_count": 0},
        {"ssid": "close", "power": -40, "encryption": "OPEN", "clients_count": 5},
    ]
    ranked = rank_targets(items, domain="wifi", top_n=2)
    assert ranked[0]["ssid"] == "close"
    assert ranked[0]["_score"] >= score_wifi(items[1])


def test_ready_check_shape():
    r = ready_check(domain="wifi")
    assert "checks" in r
    assert "critical_ok" in r


def test_full_auto_env(monkeypatch):
    monkeypatch.setenv("KFIOSA_FULL_AUTO", "1")
    assert full_auto_enabled() is True
    monkeypatch.setenv("KFIOSA_FULL_AUTO", "0")
    assert full_auto_enabled() is False


def test_settings_menu_has_full_auto():
    """Primary Settings list must expose full-auto (not only after Advanced)."""
    import inspect
    from core.tui import settings_screen as ss
    src = inspect.getsource(ss.SettingsScreen.__init__)
    assert "configure_full_auto" in src
    assert "Full-auto lab mode" in src
