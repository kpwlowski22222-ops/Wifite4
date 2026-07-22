"""ZeroDayDataset (captainblastoff2026/Zero_Day) — hermetic load +
relevance ranking; graceful degradation when datasets is absent."""

import json
import os

from core.ai_backend.zero_day_dataset import ZeroDayDataset, _tokens


class _FakeHFRow(dict):
    pass


class _FakeDataset:
    column_names = ["text"]

    def __init__(self, texts):
        self._rows = [{"text": t} for t in texts]

    def __iter__(self):
        return iter(self._rows)


def _install_fake_load_dataset(monkeypatch, texts):
    import sys
    import types
    mod = types.ModuleType("datasets")
    mod.load_dataset = lambda dataset_id: _FakeDataset(texts)
    monkeypatch.setitem(sys.modules, "datasets", mod)


def test_tokens_basic():
    assert _tokens("WPA2-PSK, dragonfly!") == {"wpa2", "psk", "dragonfly"}


def test_load_from_hf_and_caches(monkeypatch, tmp_path):
    _install_fake_load_dataset(monkeypatch, [
        "WPA2 handshake cracking with rockyou",
        "PMKID clientless attack on SAE networks",
        "Unrelated recipe text",
    ])
    ds = ZeroDayDataset(cache_dir=str(tmp_path))
    res = ds.load()
    assert res["available"] is True
    assert res["count"] == 3
    # Cache file written.
    assert os.path.exists(ds._cache_path())


def test_load_reads_cache_when_present(monkeypatch, tmp_path):
    cache_dir = str(tmp_path)
    os.makedirs(cache_dir, exist_ok=True)
    with open(os.path.join(cache_dir, "cache.json"), "w") as fh:
        json.dump({"dataset_id": "x", "entries": [{"text": "cached entry"}]}, fh)
    # If load_dataset were called it would raise; cache short-circuits it.
    import sys, types
    mod = types.ModuleType("datasets")
    mod.load_dataset = lambda *a, **k: (_ for _ in ()).throw(AssertionError("no HF"))
    monkeypatch.setitem(sys.modules, "datasets", mod)
    ds = ZeroDayDataset(cache_dir=cache_dir)
    res = ds.load()
    assert res["available"] is True
    assert res["count"] == 1


def test_load_graceful_when_datasets_missing(monkeypatch, tmp_path):
    import sys
    # Ensure `datasets` import fails.
    monkeypatch.setitem(sys.modules, "datasets", None)
    ds = ZeroDayDataset(cache_dir=str(tmp_path))
    res = ds.load()
    assert res["available"] is False
    assert res["count"] == 0


def test_relevant_entries_ranked_by_overlap(monkeypatch, tmp_path):
    _install_fake_load_dataset(monkeypatch, [
        "WPA2 handshake cracking with rockyou wordlist",
        "PMKID clientless attack on SAE dragonfly networks",
        "cooking pasta recipes for dinner",
    ])
    ds = ZeroDayDataset(cache_dir=str(tmp_path))
    ds.load()
    rel = ds.relevant_entries("WPA2 handshake crack", k=2)
    assert rel
    assert "handshake" in rel[0]["text"].lower() or "wpa2" in rel[0]["text"].lower()
    # The pasta entry must not be in the top results.
    assert all("pasta" not in e["text"] for e in rel)


def test_grounding_block_empty_when_unavailable(monkeypatch, tmp_path):
    import sys
    monkeypatch.setitem(sys.modules, "datasets", None)
    ds = ZeroDayDataset(cache_dir=str(tmp_path))
    assert ds.grounding_block("WPA2", k=3) == ""


def test_grounding_block_rendes_entries(monkeypatch, tmp_path):
    _install_fake_load_dataset(monkeypatch, ["WPA2 dragonblood CVE details"])
    ds = ZeroDayDataset(cache_dir=str(tmp_path))
    block = ds.grounding_block("WPA2 dragonblood", k=1)
    assert "ZERO_DAY DATASET GROUNDING" in block
    assert "dragonblood" in block.lower()