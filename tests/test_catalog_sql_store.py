"""Catalog SQL ingest + source router (json vs sql)."""
from __future__ import annotations

import json
from pathlib import Path

import pytest


@pytest.fixture
def tiny_catalog(tmp_path):
    cat = tmp_path / "catalog"
    cat.mkdir()
    samples = [
        {
            "id": "github:Test/BloodHound",
            "kind": "external_repository",
            "name": "BloodHound",
            "full_name": "Test/BloodHound",
            "category": "Active Directory",
            "summary": "AD attack path mapper bloodhound",
            "attack_surface": ["post_exploitation"],
            "phase_hint": ["post"],
            "tags": ["ad", "bloodhound"],
        },
        {
            "id": "github:Test/WifiTool",
            "kind": "external_repository",
            "name": "WifiTool",
            "full_name": "Test/WifiTool",
            "category": "WiFi",
            "summary": "wifi 802.11 scanner",
            "attack_surface": ["wifi"],
            "phase_hint": ["recon"],
            "tags": ["wifi", "wireless"],
        },
        {
            "id": "kali:aircrack-ng",
            "kind": "kali_source_package",
            "name": "aircrack-ng",
            "summary": "wpa cracking suite",
            "attack_surface": ["wifi"],
            "phase_hint": ["attack"],
            "tags": ["wifi", "crack"],
        },
    ]
    for s in samples:
        safe = s["id"].replace(":", "_").replace("/", "_")
        (cat / f"{safe}.json").write_text(json.dumps(s), encoding="utf-8")
    (cat / "catalog.schema.json").write_text("{}", encoding="utf-8")
    return cat


def test_ingest_and_search_sql(tiny_catalog, tmp_path, monkeypatch):
    db = tmp_path / "catalog.db"
    monkeypatch.setenv("KFIOSA_CATALOG_DB", str(db))
    from core.catalog import sql_store

    # reset thread-local connections for new path
    sql_store._conn_local.conns = {}

    r = sql_store.ingest_catalog(tiny_catalog, force=True)
    assert r["ok"] is True
    assert r["inserted"] + r["updated"] >= 3
    assert sql_store.sql_ready()

    st = sql_store.count_stats(refresh=True)
    assert st["total"] >= 3
    assert st["by_surface"].get("wifi", 0) >= 2

    found = sql_store.search_sql(text="bloodhound", limit=10)
    assert found["ok"] and found["count"] >= 1
    names = [e.get("name") for e in found["results"]]
    assert "BloodHound" in names

    by_surf = sql_store.search_sql(attack_surface="wifi", limit=10)
    assert by_surf["count"] >= 2


def test_router_prefers_sql_when_ready(tiny_catalog, tmp_path, monkeypatch):
    db = tmp_path / "catalog2.db"
    monkeypatch.setenv("KFIOSA_CATALOG_DB", str(db))
    from core.catalog import sql_store, bg_stats, source_router

    sql_store._conn_local.conns = {}
    sql_store.ingest_catalog(tiny_catalog, force=True)
    bg_stats.refresh_all(tiny_catalog)

    d = source_router.decide(text="wifi", attack_surface="wifi")
    assert d["source"] in ("sql", "memory", "json")

    r = source_router.fetch(
        text="bloodhound", prefer="sql", catalog_dir=tiny_catalog, limit=5,
    )
    assert r["ok"] is True
    assert r["source_used"] == "sql"
    assert r["count"] >= 1


def test_router_count_only_sql(tiny_catalog, tmp_path, monkeypatch):
    db = tmp_path / "catalog3.db"
    monkeypatch.setenv("KFIOSA_CATALOG_DB", str(db))
    from core.catalog import sql_store, bg_stats, source_router

    sql_store._conn_local.conns = {}
    sql_store.ingest_catalog(tiny_catalog, force=True)
    bg_stats.refresh_all(tiny_catalog)

    r = source_router.fetch(count_only=True, prefer="sql")
    assert r["ok"] and r["count"] >= 3
    assert r["source_used"] == "sql"


def test_incremental_skip(tiny_catalog, tmp_path, monkeypatch):
    db = tmp_path / "catalog4.db"
    monkeypatch.setenv("KFIOSA_CATALOG_DB", str(db))
    from core.catalog import sql_store

    sql_store._conn_local.conns = {}
    r1 = sql_store.ingest_catalog(tiny_catalog, force=True)
    r2 = sql_store.ingest_catalog(tiny_catalog, force=False)
    assert r2["ok"]
    assert r2["skipped"] >= 3
    assert r2["inserted"] == 0


def test_probe_accel_shape():
    from core.catalog.bg_stats import probe_accel
    a = probe_accel()
    assert a["ok"] and a["accel"] in ("cpu", "npu", "gpu")


def test_direct_json_path_decision(tiny_catalog):
    from core.catalog.source_router import decide
    d = decide(path=str(tiny_catalog / "github_Test_BloodHound.json"))
    assert d["source"] == "json"
