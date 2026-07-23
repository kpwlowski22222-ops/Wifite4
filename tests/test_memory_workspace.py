"""holaOS-inspired workspace, memory, and session compaction."""
from __future__ import annotations

import os
from pathlib import Path

from core.workspace.engagement_ws import (
    create_workspace, load_workspace, append_finding, list_recent, set_plan,
)
from core.memory.store import ingest, list_notes, memory_enabled
from core.memory.recall import recall, target_key_from
from core.memory.compaction import compact_prior, checkpoint_prompt_block


def test_create_workspace_and_finding(tmp_path, monkeypatch):
    monkeypatch.setenv("KFIOSA_WORKSPACE_ROOT", str(tmp_path / "ws"))
    r = create_workspace("wifi", {"ssid": "lab", "bssid": "AA:BB:CC:DD:EE:FF"})
    assert r.get("ok") is True
    wid = r["id"]
    assert (Path(r["path"]) / "plan.md").is_file()
    append_finding(wid, "PMF enabled on lab")
    loaded = load_workspace(wid)
    assert loaded.get("ok") is True
    assert "PMF" in (loaded.get("files") or {}).get("findings.md", "")
    recent = list_recent(5)
    assert any(x.get("id") == wid for x in recent)


def test_memory_ingest_and_recall(tmp_path, monkeypatch):
    monkeypatch.setenv("KFIOSA_MEMORY", "1")
    monkeypatch.setenv("KFIOSA_MEMORY_ROOT", str(tmp_path / "mem"))
    r = ingest(
        "finding",
        "AP lab has PMF and SAE",
        domain="wifi",
        target_key="aa:bb:cc:dd:ee:ff",
    )
    assert r.get("ok") is True
    notes = list_notes(domain="wifi", limit=10)
    assert notes
    mem = recall("lab PMF", domain="wifi", target_key="aa:bb:cc:dd:ee:ff")
    assert mem.get("count", 0) >= 1
    assert "PMF" in (mem.get("summary") or "") or mem.get("hits")


def test_memory_redacts_env_secrets(tmp_path, monkeypatch):
    monkeypatch.setenv("KFIOSA_MEMORY", "1")
    monkeypatch.setenv("KFIOSA_MEMORY_ROOT", str(tmp_path / "mem2"))
    monkeypatch.setenv("NVD_API_KEY", "supersecretnvdkey12345")
    r = ingest("note", "key=supersecretnvdkey12345 used", domain="wifi")
    assert r.get("ok") is True
    notes = list_notes(limit=5)
    assert notes
    assert "supersecretnvdkey12345" not in (notes[0].get("text") or "")


def test_compact_prior_long_history():
    prior = []
    for i in range(12):
        prior.append({
            "action": f"step_{i}",
            "tool": "t",
            "result": {"ok": i % 3 != 0, "error": "fail" if i % 3 == 0 else ""},
            "args": {"method": f"m{i}"},
        })
    out = compact_prior(prior, seed={"ssid": "x", "domain": "wifi"}, domain="wifi")
    assert out.get("ok") is True
    assert out.get("compacted") is True
    assert out.get("checkpoint")
    assert len(out.get("recent") or []) <= 4
    block = checkpoint_prompt_block(out)
    assert "PRIOR CHECKPOINT" in block
    assert "goal" in block.lower() or "GOAL" in block or "goal:" in block


def test_target_key_from():
    assert target_key_from({"bssid": "AA:BB"}) == "aa:bb"
    assert "example" in target_key_from({"url": "https://example.com"})
