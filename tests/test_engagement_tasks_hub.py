"""Engagement tasks + universal RAT hub (SQL-persisted)."""
from __future__ import annotations

import json
import urllib.request

from core.engagement_tasks import (
    create_task, list_tasks, start_task, get_task, KINDS,
)
from core.post_access_tui.rat_ext import spawn_rat_dashboard
from core.post_access_tui.rat_ext import dashboard_hub


def test_kinds_constant():
    assert "wifi" in KINDS and "ble" in KINDS
    assert "osint_web" in KINDS and "osint_people" in KINDS


def test_create_list_osint_task():
    r = create_task("osint_web", {"url": "https://example.org"}, label="ex")
    assert r.get("ok") is True
    tid = r["task"]["id"]
    assert tid.startswith("task-")
    found = [t for t in list_tasks(kind="osint_web") if t.get("id") == tid]
    assert found
    assert found[0].get("status") in ("queued", "running", "success")


def test_start_osint_people_until_success():
    r = create_task("osint_people", {"query": "test person"}, label="tp")
    tid = r["task"]["id"]
    s = start_task(tid)
    assert s.get("ok") is True
    import time
    for _ in range(30):
        t = get_task(tid)
        if t and t.get("status") in ("success", "failed"):
            break
        time.sleep(0.1)
    t = get_task(tid)
    assert t is not None
    assert t.get("status") == "success"


def test_hub_html_has_kind_tabs():
    html = dashboard_hub.hub_html(sessions=[], tasks=[], active_kind="ble")
    assert "Wi" in html and "BLE" in html
    assert "OSINT" in html
    assert "panel-ble" in html


def test_dashboard_serves_hub_and_tasks_api():
    rep = spawn_rat_dashboard(sessions=[])
    assert rep.get("ok") is True
    base = rep["url"].rstrip("/")
    with urllib.request.urlopen(base + "/", timeout=3) as resp:
        body = resp.read().decode("utf-8", errors="replace")
        assert resp.status == 200
        assert "RAT" in body or "task" in body.lower()
    with urllib.request.urlopen(base + "/api/tasks", timeout=3) as resp:
        data = json.loads(resp.read().decode())
        assert data.get("ok") is True
        assert "tasks" in data
    with urllib.request.urlopen(base + "/api/kinds", timeout=3) as resp:
        data = json.loads(resp.read().decode())
        assert data.get("ok") is True
        assert "wifi" in (data.get("kinds") or {})
