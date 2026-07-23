"""MCP catalog bridge — list/search/get from SQL or json."""
from __future__ import annotations

import json
from pathlib import Path

import pytest


@pytest.fixture
def tiny_cat(tmp_path, monkeypatch):
    cat = tmp_path / "catalog"
    cat.mkdir()
    for rec in (
        {
            "id": "github:TestOrg/BloodHound",
            "kind": "external_repository",
            "name": "BloodHound",
            "summary": "AD path mapper",
            "attack_surface": ["post_exploitation"],
            "phase_hint": ["post"],
            "tags": ["ad"],
            "toolbox_path": "toolboxes/microsoft/BloodHound",
            "url": "https://github.com/TestOrg/BloodHound",
        },
        {
            "id": "github:TestOrg/WifiScan",
            "kind": "external_repository",
            "name": "WifiScan",
            "summary": "wifi scanner tool",
            "attack_surface": ["wifi"],
            "tags": ["wifi"],
            "toolbox_path": "toolboxes/wifi/WifiScan",
        },
    ):
        safe = rec["id"].replace(":", "_").replace("/", "_")
        (cat / f"{safe}.json").write_text(json.dumps(rec), encoding="utf-8")
    db = tmp_path / "c.db"
    monkeypatch.setenv("KFIOSA_CATALOG_DB", str(db))
    # Point bridge catalog dir
    import core.mcp.catalog_bridge as cb
    monkeypatch.setattr(cb, "_CATALOG_DIR", cat)
    from core.catalog import sql_store
    sql_store._conn_local.conns = {}
    r = sql_store.ingest_catalog(cat, force=True)
    assert r.get("ok")
    return cat


def test_list_and_search(tiny_cat):
    from core.mcp.catalog_bridge import list_catalog_tools, get_catalog_tool
    r = list_catalog_tools(limit=10)
    assert r["ok"] and r["count"] >= 2
    assert any(t.get("name") == "BloodHound" for t in r["tools"])
    s = list_catalog_tools(text="wifi", limit=5)
    assert s["ok"] and s["count"] >= 1
    g = get_catalog_tool("github:TestOrg/BloodHound")
    assert g["ok"] and g["tool"]["name"] == "BloodHound"
    g2 = get_catalog_tool("catalog.BloodHound")
    assert g2["ok"]


def test_run_gated(tiny_cat, monkeypatch):
    from core.mcp.catalog_bridge import run_catalog_tool
    monkeypatch.delenv("KFIOSA_MCP_ALLOW_EXEC", raising=False)
    r = run_catalog_tool("BloodHound")
    assert r.get("blocked") is True


def test_mcp_handlers(tiny_cat, monkeypatch):
    monkeypatch.setenv("KFIOSA_MCP_EXPAND_CATALOG", "0")
    # reimport dispatch tools
    from core.mcp import (
        t_catalog_list, t_catalog_search, t_catalog_stats,
        t_catalog_count, t_catalog_random, t_catalog_export_ids,
        t_catalog_page, t_list_tools, handle_request,
    )
    st = t_catalog_stats({})
    assert st.get("ok")
    listed = t_catalog_list({"limit": 5})
    assert listed.get("ok") and listed.get("count") >= 1
    found = t_catalog_search({"query": "blood", "limit": 5})
    assert found.get("ok")
    # list_tools includes catalog
    lt = t_list_tools({"limit": 20, "include_catalog": "1"})
    assert lt.get("count") >= 1
    # JSON-RPC path
    r = handle_request({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "catalog_list", "arguments": {"limit": 2}},
    })
    body = json.loads(r["result"]["content"][0]["text"])
    assert body.get("ok") is True
    cnt = t_catalog_count({})
    assert cnt.get("ok") and cnt.get("count") >= 2
    rnd = t_catalog_random({"n": 2})
    assert rnd.get("ok") and rnd.get("count") >= 1
    ids = t_catalog_export_ids({"limit": 10})
    assert ids.get("ok") and ids.get("count") >= 1
    page = t_catalog_page({"page": 1, "page_size": 1})
    assert page.get("ok") and page.get("page") == 1


def test_dynamic_tools_list_includes_catalog(tiny_cat, monkeypatch):
    monkeypatch.setenv("KFIOSA_MCP_EXPAND_CATALOG", "1")
    monkeypatch.setenv("KFIOSA_MCP_CATALOG_EXPAND_LIMIT", "50")
    from core.mcp import handle_request
    r = handle_request({
        "jsonrpc": "2.0", "id": 2, "method": "tools/list",
    })
    tools = r["result"]["tools"]
    names = [t["name"] for t in tools]
    assert "catalog_sync" in names
    assert "catalog_count" in names
    assert any(n.startswith("catalog.") for n in names)
