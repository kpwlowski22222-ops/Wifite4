"""tests.test_toolbox_fetch — verify ``core.toolbox.fetch``.

Coverage:
  - parse_list: comments, blank lines, valid URLs
  - parse_github_url: valid, trailing .git, non-github, malformed
  - target_dir: shape (``<root>/<cat>/<owner>__<name>``)
  - plan_fetches: dry-run, skip_exists, skip_bad_url
  - run_fetches: dry-run default, clone gate (refuses without
    confirm_count), clone gate (mismatched count), real clone
    (with a fake ``subprocess.run`` so we never hit the network)
  - ALLOWED_CATEGORIES: only the operator-curated set
  - main() CLI: --list, --category, --clone gate, --help
"""
from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any, Dict, List
from unittest import mock

import pytest


# ---------------------------------------------------------------------------
# parse_list
# ---------------------------------------------------------------------------

def test_parse_list_strips_comments_and_blanks():
    from core.toolbox.fetch import parse_list
    text = """
    # comment
    https://github.com/a/b

    # another comment
    https://github.com/c/d
    """
    assert parse_list(text) == [
        "https://github.com/a/b",
        "https://github.com/c/d",
    ]


def test_parse_list_handles_inline_trailing_whitespace():
    from core.toolbox.fetch import parse_list
    text = "  https://github.com/a/b  \n  https://github.com/c/d  \n"
    assert parse_list(text) == [
        "https://github.com/a/b",
        "https://github.com/c/d",
    ]


def test_parse_list_empty_returns_empty():
    from core.toolbox.fetch import parse_list
    assert parse_list("") == []
    assert parse_list("# only comment\n\n# more\n") == []


# ---------------------------------------------------------------------------
# parse_github_url
# ---------------------------------------------------------------------------

def test_parse_github_url_valid():
    from core.toolbox.fetch import parse_github_url
    assert parse_github_url("https://github.com/a/b") == ("a", "b")


def test_parse_github_url_trailing_git():
    from core.toolbox.fetch import parse_github_url
    assert parse_github_url("https://github.com/a/b.git") == ("a", "b")


def test_parse_github_url_with_subpath():
    from core.toolbox.fetch import parse_github_url
    # Subpaths are stripped to the first two parts.
    assert parse_github_url("https://github.com/a/b/tree/main") == ("a", "b")


def test_parse_github_url_www():
    from core.toolbox.fetch import parse_github_url
    assert parse_github_url("https://www.github.com/a/b") == ("a", "b")


def test_parse_github_url_non_github_returns_none():
    from core.toolbox.fetch import parse_github_url
    assert parse_github_url("https://gitlab.com/a/b") is None
    assert parse_github_url("https://example.com/a/b") is None
    assert parse_github_url("https://github.com/") is None
    assert parse_github_url("not a url at all") is None


def test_parse_github_url_invalid_chars_returns_none():
    from core.toolbox.fetch import parse_github_url
    # Owner / name must match [A-Za-z0-9_.-]+
    assert parse_github_url("https://github.com/a b/c") is None
    assert parse_github_url("https://github.com/a/b$c") is None


# ---------------------------------------------------------------------------
# target_dir
# ---------------------------------------------------------------------------

def test_target_dir_shape(tmp_path):
    from core.toolbox.fetch import target_dir
    d = target_dir(tmp_path, "exploit", "evil", "tool")
    assert d == tmp_path / "exploit" / "evil__tool"


def test_target_dir_uses_owner__name_convention(tmp_path):
    from core.toolbox.fetch import target_dir
    d = target_dir(tmp_path, "wifi", "z3r0", "hcxdumptool")
    parts = d.parts
    assert parts[-1] == "z3r0__hcxdumptool"
    assert parts[-2] == "wifi"


# ---------------------------------------------------------------------------
# ALLOWED_CATEGORIES
# ---------------------------------------------------------------------------

def test_allowed_categories_set():
    from core.toolbox.fetch import ALLOWED_CATEGORIES, is_allowed_category
    assert "exploit" in ALLOWED_CATEGORIES
    assert "wifi" in ALLOWED_CATEGORIES
    assert "ble" in ALLOWED_CATEGORIES
    assert "c2" in ALLOWED_CATEGORIES
    # Defense: not everything is allowed.
    assert "kernel" not in ALLOWED_CATEGORIES
    assert "rootkit" not in ALLOWED_CATEGORIES
    assert is_allowed_category("exploit") is True
    assert is_allowed_category("kernel") is False


# ---------------------------------------------------------------------------
# plan_fetches (dry-run)
# ---------------------------------------------------------------------------

def test_plan_fetches_dry_run_no_existing(tmp_path):
    from core.toolbox.fetch import plan_fetches
    plan = plan_fetches(
        ["https://github.com/a/b", "https://github.com/c/d"],
        toolboxes_root=tmp_path, category="exploit",
    )
    assert len(plan) == 2
    assert plan[0]["action"] == "clone"
    assert plan[0]["owner"] == "a"
    assert plan[0]["name"] == "b"
    assert plan[1]["action"] == "clone"


def test_plan_fetches_skip_exists(tmp_path):
    from core.toolbox.fetch import plan_fetches, target_dir
    target_dir(tmp_path, "exploit", "a", "b").mkdir(parents=True)
    plan = plan_fetches(
        ["https://github.com/a/b", "https://github.com/c/d"],
        toolboxes_root=tmp_path, category="exploit",
    )
    assert plan[0]["action"] == "skip_exists"
    assert plan[1]["action"] == "clone"


def test_plan_fetches_skip_bad_url(tmp_path):
    from core.toolbox.fetch import plan_fetches
    plan = plan_fetches(
        ["https://github.com/a/b", "https://gitlab.com/x/y"],
        toolboxes_root=tmp_path, category="exploit",
    )
    assert plan[0]["action"] == "clone"
    assert plan[1]["action"] == "skip_bad_url"
    assert "not a github.com" in plan[1]["error"]


# ---------------------------------------------------------------------------
# run_fetches
# ---------------------------------------------------------------------------

def test_run_fetches_dry_run_returns_plan(tmp_path):
    from core.toolbox.fetch import plan_fetches, run_fetches
    plan = plan_fetches(
        ["https://github.com/a/b"],
        toolboxes_root=tmp_path, category="exploit",
    )
    res = run_fetches(plan, toolboxes_root=tmp_path, clone=False)
    assert res["ok"] is True
    assert res["n_cloned"] == 0
    assert "dry-run" in res["error"]


def test_run_fetches_refuses_without_confirm_count(tmp_path):
    from core.toolbox.fetch import plan_fetches, run_fetches
    plan = plan_fetches(
        ["https://github.com/a/b"],
        toolboxes_root=tmp_path, category="exploit",
    )
    res = run_fetches(
        plan, toolboxes_root=tmp_path, clone=True,
        confirm_count=None,
    )
    assert res["ok"] is False
    assert "operator gate" in res["error"]


def test_run_fetches_refuses_mismatched_confirm_count(tmp_path):
    from core.toolbox.fetch import plan_fetches, run_fetches
    plan = plan_fetches(
        ["https://github.com/a/b", "https://github.com/c/d"],
        toolboxes_root=tmp_path, category="exploit",
    )
    res = run_fetches(
        plan, toolboxes_root=tmp_path, clone=True,
        confirm_count=1,  # expects 2
    )
    assert res["ok"] is False
    assert "does not match" in res["error"]


def test_run_fetches_actual_clone_uses_runner(tmp_path):
    """A real clone with a fake ``subprocess.run`` — never hits
    the network. Verifies the runner is called with the right
    args, and the cloned dir exists after."""
    from core.toolbox.fetch import plan_fetches, run_fetches
    calls: List[List[str]] = []

    def fake_runner(args, **kwargs):
        calls.append(list(args))
        # Create the dest dir so skip_exists on the next pass.
        dest = Path(args[-1])
        dest.mkdir(parents=True, exist_ok=True)
        cp = mock.MagicMock()
        cp.returncode = 0
        cp.stderr = ""
        return cp

    plan = plan_fetches(
        ["https://github.com/a/b"],
        toolboxes_root=tmp_path, category="exploit",
    )
    res = run_fetches(
        plan, toolboxes_root=tmp_path, clone=True,
        runner=fake_runner, confirm_count=1,
    )
    assert res["ok"] is True
    assert res["n_cloned"] == 1
    assert len(calls) == 1
    assert calls[0][:3] == ["git", "clone", "--depth"]
    # The dest dir was created by the fake runner.
    assert (tmp_path / "exploit" / "a__b").is_dir()


def test_run_fetches_clone_failure_records_error(tmp_path):
    """When ``git clone`` returns non-zero, the entry is flagged
    with the error string and the plan is preserved."""
    from core.toolbox.fetch import plan_fetches, run_fetches

    def fake_runner(args, **kwargs):
        cp = mock.MagicMock()
        cp.returncode = 128
        cp.stderr = "fatal: repository not found"
        return cp

    plan = plan_fetches(
        ["https://github.com/a/b"],
        toolboxes_root=tmp_path, category="exploit",
    )
    res = run_fetches(
        plan, toolboxes_root=tmp_path, clone=True,
        runner=fake_runner, confirm_count=1,
    )
    assert res["ok"] is False
    assert res["n_cloned"] == 0
    assert res["n_errors"] == 1
    assert "fatal" in res["plan"][0]["error"]


def test_run_fetches_runner_exception_handled(tmp_path):
    """When ``subprocess.run`` raises (e.g. timeout), the entry
    is flagged with the exception and the plan continues."""
    from core.toolbox.fetch import plan_fetches, run_fetches

    def fake_runner(args, **kwargs):
        raise RuntimeError("network unreachable")

    plan = plan_fetches(
        ["https://github.com/a/b"],
        toolboxes_root=tmp_path, category="exploit",
    )
    res = run_fetches(
        plan, toolboxes_root=tmp_path, clone=True,
        runner=fake_runner, confirm_count=1,
    )
    assert res["ok"] is False
    assert res["n_errors"] == 1
    assert "raised" in res["plan"][0]["error"]
    assert "network unreachable" in res["plan"][0]["error"]


def test_run_fetches_idempotent_skip_exists(tmp_path):
    """If the dest already exists, the plan says skip_exists and
    no clone is performed."""
    from core.toolbox.fetch import plan_fetches, run_fetches, target_dir
    target_dir(tmp_path, "exploit", "a", "b").mkdir(parents=True)
    calls: List[List[str]] = []

    def fake_runner(args, **kwargs):
        calls.append(list(args))
        cp = mock.MagicMock()
        cp.returncode = 0
        cp.stderr = ""
        return cp

    plan = plan_fetches(
        ["https://github.com/a/b"],
        toolboxes_root=tmp_path, category="exploit",
    )
    res = run_fetches(
        plan, toolboxes_root=tmp_path, clone=True,
        runner=fake_runner, confirm_count=0,
    )
    assert res["ok"] is True
    assert res["n_cloned"] == 0
    assert res["n_skipped"] == 1
    assert calls == []


# ---------------------------------------------------------------------------
# main() CLI
# ---------------------------------------------------------------------------

def test_main_dry_run_prints_summary(tmp_path, capsys):
    from core.toolbox.fetch import main
    list_path = tmp_path / "repos.txt"
    list_path.write_text(
        "https://github.com/a/b\n"
        "https://github.com/c/d\n"
        "# comment\n",
        encoding="utf-8",
    )
    rc = main([
        "--list", str(list_path),
        "--category", "exploit",
        "--toolboxes-root", str(tmp_path),
    ])
    assert rc == 0
    captured = capsys.readouterr()
    assert "plan for category='exploit'" in captured.out
    assert "DRY-RUN" in captured.out
    assert "2 new" in captured.out


def test_main_refuses_disallowed_category(tmp_path, capsys):
    from core.toolbox.fetch import main
    list_path = tmp_path / "repos.txt"
    list_path.write_text(
        "https://github.com/a/b\n", encoding="utf-8",
    )
    rc = main([
        "--list", str(list_path),
        "--category", "kernel",
        "--toolboxes-root", str(tmp_path),
    ])
    assert rc == 2
    captured = capsys.readouterr()
    assert "not in ALLOWED_CATEGORIES" in captured.err


def test_main_refuses_missing_list_file(tmp_path, capsys):
    from core.toolbox.fetch import main
    rc = main([
        "--list", str(tmp_path / "no_such.txt"),
        "--category", "exploit",
        "--toolboxes-root", str(tmp_path),
    ])
    assert rc == 2
    captured = capsys.readouterr()
    assert "not found" in captured.err


def test_main_refuses_empty_list_file(tmp_path, capsys):
    from core.toolbox.fetch import main
    list_path = tmp_path / "empty.txt"
    list_path.write_text("# only comments\n\n", encoding="utf-8")
    rc = main([
        "--list", str(list_path),
        "--category", "exploit",
        "--toolboxes-root", str(tmp_path),
    ])
    assert rc == 2


def test_main_clone_with_correct_gate(tmp_path, capsys):
    """The full CLI flow with a fake runner — never hits the
    network. Verifies the operator-gate enforcement."""
    from core.toolbox.fetch import main
    list_path = tmp_path / "repos.txt"
    list_path.write_text(
        "https://github.com/a/b\n", encoding="utf-8",
    )

    def fake_runner(args, **kwargs):
        dest = Path(args[-1])
        dest.mkdir(parents=True, exist_ok=True)
        cp = mock.MagicMock()
        cp.returncode = 0
        cp.stderr = ""
        return cp

    with mock.patch(
        "core.toolbox.fetch.subprocess.run", side_effect=fake_runner,
    ):
        rc = main([
            "--list", str(list_path),
            "--category", "exploit",
            "--toolboxes-root", str(tmp_path),
            "--clone",
            "--i-am-sure-i-want-to-clone-N-repos", "1",
        ])
    assert rc == 0
    captured = capsys.readouterr()
    assert "cloned 1" in captured.out


def test_main_clone_wrong_gate_refuses(tmp_path, capsys):
    from core.toolbox.fetch import main
    list_path = tmp_path / "repos.txt"
    list_path.write_text(
        "https://github.com/a/b\n", encoding="utf-8",
    )
    rc = main([
        "--list", str(list_path),
        "--category", "exploit",
        "--toolboxes-root", str(tmp_path),
        "--clone",
        "--i-am-sure-i-want-to-clone-N-repos", "99",
    ])
    assert rc == 1
    captured = capsys.readouterr()
    assert "does not match" in captured.err


# ---------------------------------------------------------------------------
# fetch_lists
# ---------------------------------------------------------------------------

def test_fetch_lists_exist_and_parseable():
    """The 3 curated fetch lists parse and have valid URLs only."""
    from core.toolbox.fetch import parse_list, parse_github_url

    for name in (
        "kali_frameworks.txt",
        "fresh_cves.txt",
        "wireless_ble_ext.txt",
    ):
        path = (
            Path(__file__).resolve().parent.parent
            / "core" / "toolbox" / "fetch_lists" / name
        )
        assert path.is_file(), f"missing {path}"
        urls = parse_list(path.read_text(encoding="utf-8"))
        assert len(urls) >= 5, f"{name} has too few URLs"
        for u in urls:
            assert parse_github_url(u) is not None, (
                f"bad URL in {name}: {u}"
            )


# ---------------------------------------------------------------------------
# Phase 4 — 120+ offensive toolboxes (operator's 2026-07-20 request)
# ---------------------------------------------------------------------------

def test_phase4_offensive_list_exists_and_parses():
    """The phase4 list exists, parses, and exposes 100+ unique URLs."""
    from core.toolbox.fetch import parse_list, parse_github_url

    path = (
        Path(__file__).resolve().parent.parent
        / "core" / "toolbox" / "fetch_lists" / "phase4_offensive.txt"
    )
    assert path.is_file(), f"missing {path}"
    text = path.read_text(encoding="utf-8")
    urls = parse_list(text)
    assert len(urls) >= 100, (
        f"phase4 has {len(urls)} URLs; operator target is 120+")
    for u in urls:
        assert parse_github_url(u) is not None, f"bad URL: {u}"


def test_phase4_inline_categories():
    """The phase4 list includes inline '# cat: <cat>' hints that the
    fetch CLI uses for per-URL routing."""
    from core.toolbox.fetch import parse_list_with_categories

    path = (
        Path(__file__).resolve().parent.parent
        / "core" / "toolbox" / "fetch_lists" / "phase4_offensive.txt"
    )
    text = path.read_text(encoding="utf-8")
    entries = parse_list_with_categories(text)
    assert len(entries) >= 100
    # Each entry has a category (operator curated).
    cats = [c for u, c in entries]
    assert all(c is not None for c in cats), (
        "phase4 is supposed to have inline category hints on every "
        "line; some are missing")
    # The 11 categories map to the 11 ALLOWED_CATEGORIES.
    from collections import Counter
    counts = Counter(cats)
    assert len(counts) >= 8, f"only {len(counts)} categories: {counts}"
    # microsoft / wifi / ble / c2 / exploit / web / osint / recon /
    # post_exploitation / android / ios — the canonical 11.
    for expected in ("microsoft", "wifi", "ble", "c2", "exploit",
                    "web", "osint", "recon", "post_exploitation",
                    "android", "ios"):
        assert expected in counts, (
            f"missing category in phase4: {expected}")


def test_all_fetch_lists_have_unique_urls():
    """Across all 5 fetch lists, the set of unique URLs is 250+."""
    from core.toolbox.fetch import parse_list

    root = (
        Path(__file__).resolve().parent.parent
        / "core" / "toolbox" / "fetch_lists"
    )
    seen: set = set()
    for txt in sorted(root.glob("*.txt")):
        for u in parse_list(txt.read_text(encoding="utf-8")):
            seen.add(u)
    # The 5 lists together should expose 250+ unique repos.
    assert len(seen) >= 250, (
        f"only {len(seen)} unique URLs across all fetch lists")


def test_fetch_lists_total_meets_target():
    """The 5 fetch lists together expose 250+ unique URLs."""
    from core.toolbox.fetch import parse_list

    root = (
        Path(__file__).resolve().parent.parent
        / "core" / "toolbox" / "fetch_lists"
    )
    total = 0
    for txt in sorted(root.glob("*.txt")):
        total += len(parse_list(txt.read_text(encoding="utf-8")))
    assert total >= 250, f"only {total} URLs across all fetch lists"
