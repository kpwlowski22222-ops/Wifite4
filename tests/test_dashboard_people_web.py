"""People/website kinds + long jobs for Flask RAT dashboard."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.post_access_tui.rat_ext.long_jobs import (
    enqueue_people_job,
    enqueue_website_session,
    jobs_as_sessions,
    list_jobs,
)
from core.post_access_tui.rat_ext.rat_dynamic import (
    KIND_PEOPLE,
    KIND_WEBSITE,
    kind_label,
    normalize_kind,
    rat_menu_for_session,
)


@pytest.fixture()
def jobs_tmpdir(tmp_path, monkeypatch):
    monkeypatch.setenv("KFIOSA_RAT_JOBS", str(tmp_path / "jobs"))
    return tmp_path / "jobs"


def test_kind_normalize_people_website():
    assert normalize_kind({"kind": "people"}) == KIND_PEOPLE
    assert normalize_kind({"transport": "website"}) == KIND_WEBSITE
    assert "People" in kind_label(KIND_PEOPLE)
    assert "Website" in kind_label(KIND_WEBSITE) or "web" in kind_label(KIND_WEBSITE).lower()


def test_enqueue_people_and_website(jobs_tmpdir):
    from core.post_access_tui.rat_ext.long_jobs import update_job

    pid = enqueue_people_job("alice", status="queued")
    update_job(pid, status="running")
    update_job(pid, status="done", achieved=["osint_profile"])
    wid = enqueue_website_session("https://example.test", status="attached")
    assert pid and wid
    people = list_jobs(kind="people")
    sites = list_jobs(kind="website")
    alice = next(j for j in people if j["id"] == pid)
    assert alice["status"] == "done"
    assert any(j["id"] == wid for j in sites)
    sess = jobs_as_sessions()
    kinds = {s["kind"] for s in sess}
    assert "people" in kinds and "website" in kinds


def test_rat_menu_for_people_and_website():
    people = {
        "id": "p1",
        "kind": "people",
        "achieved": ["osint_profile"],
        "target": "bob",
    }
    site = {
        "id": "w1",
        "kind": "website",
        "achieved": ["web_session"],
        "target": "https://lab.example",
    }
    mp = rat_menu_for_session(people)
    mw = rat_menu_for_session(site)
    assert mp["ok"] and mp["kind"] == "people"
    assert mw["ok"] and mw["kind"] == "website"
    assert mp["action_count"] >= 1
    assert mw["action_count"] >= 1


def test_build_roster_includes_long_jobs(jobs_tmpdir):
    enqueue_people_job("carol", status="done")
    from core.post_access_tui.rat_ext import build_session_roster
    roster = build_session_roster([])
    assert any(
        (r.get("transport") == "people" or r.get("kind") == "people")
        for r in roster
    )


def test_dashboard_html_has_people_website_tabs():
    from core.post_access_tui.rat_ext.rat_dynamic import build_rat_dashboard_html
    html = build_rat_dashboard_html([
        {"id": "p1", "kind": "people", "transport": "people",
         "target": "x", "achieved": ["osint_profile"]},
        {"id": "w1", "kind": "website", "transport": "website",
         "target": "https://x", "achieved": ["web_session"]},
    ])
    assert "People" in html
    assert "Websites" in html or "website" in html.lower()
