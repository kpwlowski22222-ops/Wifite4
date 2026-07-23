"""Learn mode: sim targets, plans, MemOS LTM, session dry-run."""
from __future__ import annotations

import json
from pathlib import Path

import pytest


def test_learn_modes_cover_required():
    from core.learn.domains import LEARN_MODES, mode_keys
    keys = set(mode_keys())
    for k in (
        "wifi_attack", "wifi_recon", "ble_attack", "ble_recon",
        "osint_web", "osint_people", "post_exploit",
    ):
        assert k in keys
        assert LEARN_MODES[k]["label"]
        assert LEARN_MODES[k]["finetune_domain"]


def test_simulate_wifi_and_ble():
    from core.learn.simulate import simulate_batch, simulate_target
    w = simulate_target("wifi_attack", seed=42)
    assert w["simulated"] and w["bssid"] and w["domain"] == "wifi"
    b = simulate_batch("ble_recon", n=2, base_seed=1)
    assert len(b) == 2 and b[0].get("address")
    pe = simulate_target("post_exploit", seed=7)
    assert pe.get("host") and pe.get("access_achieved")


def test_memos_ltm_add_search(tmp_path, monkeypatch):
    monkeypatch.setenv("KFIOSA_MEMOS_DB", str(tmp_path / "m.db"))
    monkeypatch.setenv("KFIOSA_MEMOS_ROOT", str(tmp_path / "memos"))
    from core.memory import memos_ltm as m

    # reset thread conn
    m._local.c = None
    m.init()
    m.ensure_cube("learn_test", domain="wifi")
    r = m.add_memory(
        "poly wifi deauth then capture plan for sim AP",
        cube_id="learn_test",
        layer="L2_skill",
        kind="skill",
        domain="wifi",
        tags=["wifi", "deauth"],
    )
    assert r["ok"] and r["mem_id"]
    s = m.search_memory("deauth", cube_id="learn_test")
    assert s["ok"] and s["count"] >= 1
    st = m.stats()
    assert st["total"] >= 1


def test_run_learn_session_dataset_only(tmp_path, monkeypatch):
    monkeypatch.setenv("KFIOSA_LEARN_HEAVY", "0")
    monkeypatch.setenv("KFIOSA_MEMOS_DB", str(tmp_path / "m2.db"))
    monkeypatch.setenv("KFIOSA_MEMOS_ROOT", str(tmp_path / "memos2"))
    # Point finetune/learn under tmp by patching ROOT is hard; use real data dir
    from core.memory import memos_ltm as m
    m._local.c = None
    logs = []
    from core.learn.session import run_learn_session
    res = run_learn_session(
        "wifi_recon",
        n_targets=1,
        run_finetune=True,
        ai_backend=None,  # heuristic plans
        on_event=logs.append,
        base_seed=99,
    )
    assert res["ok"] is True
    assert res["n_samples"] >= 1
    assert Path(res["jsonl"]).is_file()
    row = json.loads(Path(res["jsonl"]).read_text(encoding="utf-8").splitlines()[0])
    assert "messages" in row and len(row["messages"]) == 3
    assert any("learn" in (x or "").lower() or "plan" in (x or "").lower() for x in logs)


def test_learn_screen_menu():
    from core.tui.learn_screen import LearnScreen
    log = []
    sc = LearnScreen(None, lambda: None, log, input_fn=lambda p: "")
    labels = [x[0] for x in sc.menu_items]
    assert any("WiFi" in L or "wifi" in L.lower() or "attacks" in L for L in labels)
    assert any("Post-exploit" in L for L in labels)
    assert any("MemOS" in L for L in labels)
