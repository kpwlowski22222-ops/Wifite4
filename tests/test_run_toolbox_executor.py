"""tests.test_run_toolbox_executor — hermetic test suite for
:mod:`core.toolbox.executor`.

Coverage:
  - repo resolution: 5 tests (path traversal, unknown category,
    missing repo, owner/name, bare name, owner__name convention)
  - entry detection: 4 tests (explicit, run.sh priority,
    no-entry degradation, Makefile sentinel, setup.py sentinel)
  - argv / env handling: 5 tests (basic argv, credential auto-route,
    forbidden-key re-route, env_ prefix, list values)
  - run_toolbox_repo: 8 tests (happy path, missing interpreter,
    timeout, non-zero rc, fake subprocess via env, never-inline)
  - run_toolbox_step: 5 tests (missing repo_id, missing category,
    full happy path, env_ merging, credential routing)
  - manifest cache: 2 tests (touch_index_mtime, list_repos /
    find_repo consistency)
  - safety / never-fabricate: 4 tests (no fabrication on missing
    repo, no fabrication on missing entry, no fabrication on
    timeout, no fabrication on subprocess error)
"""
from __future__ import annotations

import json
import os
import subprocess
import textwrap
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest import mock

import pytest

from core.toolbox import (
    ALLOWED_CATEGORIES,
    NoEntryScriptError,
    PathTraversalError,
    RepoNotFoundError,
    RunResult,
    ToolboxError,
    UnknownCategoryError,
    build_repo_index,
    detect_entry_script,
    find_repo,
    get_repo_index,
    list_categories,
    list_repos,
    run_toolbox_repo,
    run_toolbox_step,
    touch_index_mtime,
)
from core.toolbox.executor import (
    CREDENTIAL_KEY_PATTERNS,
    ENV_VAR_PREFIX,
    _split_args,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_fake_repo(tmp_path: Path, name: str = "fake_repo",
                    *, with_run: bool = True,
                    entry_name: str = "run.sh",
                    entry_body: str = "#!/bin/sh\necho ok\n",
                    category: str = "exploit") -> Path:
    """Create a fake cloned repo at ``tmp_path/<category>/<name>``."""
    cat_dir = tmp_path / category
    cat_dir.mkdir(parents=True, exist_ok=True)
    repo_dir = cat_dir / name
    repo_dir.mkdir(parents=True, exist_ok=True)
    (repo_dir / "README.md").write_text(f"# {name}\nA fake repo for tests.\n")
    if with_run:
        entry = repo_dir / entry_name
        entry.write_text(entry_body)
        if entry_name.endswith(".sh") or entry_name == "run.sh":
            os.chmod(entry, 0o755)
    return repo_dir


def _patch_toolboxes(monkeypatch, tmp_path: Path):
    """Point TOOLBOXES_DIR at ``tmp_path`` so the executor sees our
    fake repos. Returns the new toolboxes root."""
    from core.toolbox import executor as exe
    monkeypatch.setattr(exe, "TOOLBOXES_DIR", tmp_path)
    # Also reset the cached index so the new root takes effect.
    exe._TOOLBOX_REPO_INDEX = None
    return tmp_path


# ---------------------------------------------------------------------------
# Repo resolution
# ---------------------------------------------------------------------------

def test_path_traversal_in_repo_id_rejected(tmp_path):
    for bad in ("../../etc/passwd", "/etc/passwd", "owner/..",
                "owner/name/../../escape", "~/.ssh/id_rsa"):
        with pytest.raises((PathTraversalError, RepoNotFoundError)):
            from core.toolbox.executor import _resolve_repo_path
            _resolve_repo_path(bad, "exploit")


def test_unknown_category_rejected(tmp_path):
    from core.toolbox.executor import _resolve_repo_path
    with pytest.raises(UnknownCategoryError):
        _resolve_repo_path("x/y", "kernel")


def test_missing_repo_raises_not_found(tmp_path, monkeypatch):
    _patch_toolboxes(monkeypatch, tmp_path)
    from core.toolbox.executor import _resolve_repo_path
    with pytest.raises(RepoNotFoundError):
        _resolve_repo_path("owner/missing", "exploit")


def test_repo_resolution_owner_name(tmp_path, monkeypatch):
    _patch_toolboxes(monkeypatch, tmp_path)
    _make_fake_repo(tmp_path, name="threat9/routersploit")
    from core.toolbox.executor import _resolve_repo_path
    p = _resolve_repo_path("threat9/routersploit", "exploit")
    assert p == (tmp_path / "exploit" / "threat9" / "routersploit").resolve()


def test_repo_resolution_owner_double_underscore_name(tmp_path, monkeypatch):
    """Our clone convention is ``<owner>__<name>`` when the repo dir
    is one flat name."""
    _patch_toolboxes(monkeypatch, tmp_path)
    _make_fake_repo(tmp_path, name="threat9__routersploit")
    from core.toolbox.executor import _resolve_repo_path
    p = _resolve_repo_path("threat9/routersploit", "exploit")
    assert p == (tmp_path / "exploit" / "threat9__routersploit").resolve()


def test_repo_resolution_bare_name(tmp_path, monkeypatch):
    _patch_toolboxes(monkeypatch, tmp_path)
    _make_fake_repo(tmp_path, name="routersploit")
    from core.toolbox.executor import _resolve_repo_path
    p = _resolve_repo_path("routersploit", "exploit")
    assert p == (tmp_path / "exploit" / "routersploit").resolve()


# ---------------------------------------------------------------------------
# Entry-script detection
# ---------------------------------------------------------------------------

def test_detect_explicit_entry(tmp_path):
    _make_fake_repo(tmp_path, name="r1")
    p = detect_entry_script(
        tmp_path / "exploit" / "r1", explicit="run.sh",
    )
    assert p.name == "run.sh"


def test_detect_priority_order(tmp_path):
    """run.sh must beat run.py when both exist."""
    repo = _make_fake_repo(tmp_path, name="r1", entry_name="run.sh")
    (repo / "run.py").write_text("print('hi')")
    p = detect_entry_script(repo)
    assert p.name == "run.sh"


def test_detect_no_entry_raises(tmp_path):
    repo = tmp_path / "exploit" / "r1"
    repo.mkdir(parents=True)
    with pytest.raises(NoEntryScriptError):
        detect_entry_script(repo)


def test_detect_makefile_sentinel(tmp_path):
    """No run.sh / run.py / etc., but Makefile exists -> Makefile is
    the entry (the executor will run ``make``)."""
    repo = tmp_path / "exploit" / "r1"
    repo.mkdir(parents=True)
    (repo / "Makefile").write_text("all:\n\techo ok\n")
    p = detect_entry_script(repo)
    assert p.name == "Makefile"


def test_detect_setup_py_sentinel(tmp_path):
    repo = tmp_path / "exploit" / "r1"
    repo.mkdir(parents=True)
    (repo / "setup.py").write_text("from setuptools import setup\nsetup()\n")
    p = detect_entry_script(repo)
    assert p.name == "setup.py"


def test_detect_path_traversal_in_explicit_rejected(tmp_path):
    repo = _make_fake_repo(tmp_path, name="r1")
    with pytest.raises(NoEntryScriptError):
        detect_entry_script(repo, explicit="../../etc/passwd")


# ---------------------------------------------------------------------------
# Argv / env handling
# ---------------------------------------------------------------------------

def test_split_args_basic_argv():
    argv, env = _split_args({
        "target": "10.0.0.1", "lport": 4444,
        "verbose": True, "dry_run": False,
    })
    assert "--target" in argv and "10.0.0.1" in argv
    assert "--lport" in argv and "4444" in argv
    assert "--verbose" in argv
    assert "--dry-run" not in argv  # False values are skipped
    assert env == {}


def test_split_args_credential_auto_route():
    """password / hash / token / secret / psk / apikey -> env vars."""
    argv, env = _split_args({
        "target": "10.0.0.1",
        "password": "sup3rSecret!",  # never inline
        "hash": "a" * 32,
        "token": "tok-1234",
    })
    assert "10.0.0.1" in argv
    assert "sup3rSecret!" not in argv
    assert "a" * 32 not in argv
    assert "tok-1234" not in argv
    assert env[f"{ENV_VAR_PREFIX}PASSWORD"] == "sup3rSecret!"
    assert env[f"{ENV_VAR_PREFIX}HASH"] == "a" * 32
    assert env[f"{ENV_VAR_PREFIX}TOKEN"] == "tok-1234"


def test_split_args_env_prefix_routing():
    argv, env = _split_args({
        "target": "x",
        "env_FOO": "bar",
        "env_DEBUG_LEVEL": "9",
    })
    assert env["FOO"] == "bar"
    assert env["DEBUG_LEVEL"] == "9"
    # The ``env_``-prefixed keys are NOT in argv.
    assert not any("bar" in a for a in argv)


def test_split_args_list_values():
    argv, env = _split_args({
        "ports": [80, 443, 8080],
    })
    # Should produce 3 --ports values
    n = sum(1 for a in argv if a == "--ports")
    assert n == 3
    assert "80" in argv and "443" in argv and "8080" in argv


def test_split_args_empty():
    argv, env = _split_args(None)
    assert argv == [] and env == {}
    argv, env = _split_args({})
    assert argv == [] and env == {}


# ---------------------------------------------------------------------------
# run_toolbox_repo
# ---------------------------------------------------------------------------

def test_run_toolbox_repo_happy_path(tmp_path, monkeypatch):
    _patch_toolboxes(monkeypatch, tmp_path)
    _make_fake_repo(tmp_path, name="r1", entry_name="run.sh",
                      entry_body="#!/bin/sh\necho ok rc=0\nexit 0\n")
    res = run_toolbox_repo("r1", category="exploit")
    assert res.ok is True
    assert res.returncode == 0
    assert "ok" in res.stdout
    assert res.repo_id == "r1"
    assert res.category == "exploit"


def test_run_toolbox_repo_explicit_entry(tmp_path, monkeypatch):
    _patch_toolboxes(monkeypatch, tmp_path)
    _make_fake_repo(tmp_path, name="r1", entry_name="run.sh",
                      entry_body="#!/bin/sh\necho main\n")
    (tmp_path / "exploit" / "r1" / "alt.sh").write_text(
        "#!/bin/sh\necho alt\nexit 0\n"
    )
    os.chmod(tmp_path / "exploit" / "r1" / "alt.sh", 0o755)
    res = run_toolbox_repo("r1", category="exploit", entry="alt.sh")
    assert res.ok is True
    assert "alt" in res.stdout


def test_run_toolbox_repo_no_entry(tmp_path, monkeypatch):
    _patch_toolboxes(monkeypatch, tmp_path)
    repo = tmp_path / "exploit" / "r1"
    repo.mkdir(parents=True)
    (repo / "README.md").write_text("# readme")
    res = run_toolbox_repo("r1", category="exploit")
    assert res.ok is False
    assert "entry detection failed" in res.error


def test_run_toolbox_repo_missing_repo(tmp_path, monkeypatch):
    _patch_toolboxes(monkeypatch, tmp_path)
    res = run_toolbox_repo("nonexistent", category="exploit")
    assert res.ok is False
    assert "repo resolution failed" in res.error


def test_run_toolbox_repo_timeout(tmp_path, monkeypatch):
    _patch_toolboxes(monkeypatch, tmp_path)
    _make_fake_repo(tmp_path, name="r1", entry_name="run.sh",
                      entry_body="#!/bin/sh\nsleep 30\nexit 0\n")
    res = run_toolbox_repo("r1", category="exploit", timeout_seconds=1)
    assert res.ok is False
    assert "timeout" in res.error
    assert res.returncode == 124


def test_run_toolbox_repo_nonzero_rc(tmp_path, monkeypatch):
    _patch_toolboxes(monkeypatch, tmp_path)
    _make_fake_repo(tmp_path, name="r1", entry_name="run.sh",
                      entry_body="#!/bin/sh\necho nope >&2\nexit 7\n")
    res = run_toolbox_repo("r1", category="exploit")
    assert res.ok is False
    assert res.returncode == 7
    assert "nope" in res.stderr


def test_run_toolbox_repo_never_inline_credentials(tmp_path, monkeypatch):
    """Credentials passed via env vars must reach the script."""
    _patch_toolboxes(monkeypatch, tmp_path)
    _make_fake_repo(tmp_path, name="r1", entry_name="run.sh",
                      entry_body=(
                          "#!/bin/sh\n"
                          "echo TARGET=$KFIOSA_TARGET_PASSWORD\n"
                          "exit 0\n"
                      ))
    res = run_toolbox_repo("r1", category="exploit",
                            env={"KFIOSA_TARGET_PASSWORD": "sup3rSecret!"})
    assert res.ok is True
    assert "sup3rSecret!" in res.stdout
    # And it must NOT appear in argv.
    assert "sup3rSecret!" not in res.argv


def test_run_toolbox_repo_path_traversal_blocked(tmp_path, monkeypatch):
    _patch_toolboxes(monkeypatch, tmp_path)
    res = run_toolbox_repo("../../etc/passwd", category="exploit")
    assert res.ok is False
    assert "repo resolution failed" in res.error


def test_run_toolbox_repo_unknown_category(tmp_path, monkeypatch):
    _patch_toolboxes(monkeypatch, tmp_path)
    res = run_toolbox_repo("x", category="kernel")
    assert res.ok is False
    assert "repo resolution failed" in res.error


# ---------------------------------------------------------------------------
# run_toolbox_step
# ---------------------------------------------------------------------------

def test_run_toolbox_step_missing_repo_id(tmp_path, monkeypatch):
    _patch_toolboxes(monkeypatch, tmp_path)
    res = run_toolbox_step({"action": "run_toolbox", "args": {}})
    assert res.ok is False
    assert "repo_id" in res.error


def test_run_toolbox_step_missing_category(tmp_path, monkeypatch):
    _patch_toolboxes(monkeypatch, tmp_path)
    res = run_toolbox_step({"action": "run_toolbox",
                              "args": {"repo_id": "x"}})
    assert res.ok is False
    assert "category" in res.error


def test_run_toolbox_step_happy_path(tmp_path, monkeypatch):
    _patch_toolboxes(monkeypatch, tmp_path)
    _make_fake_repo(tmp_path, name="r1", entry_name="run.sh",
                      entry_body="#!/bin/sh\necho $1 $2\nexit 0\n")
    res = run_toolbox_step({
        "action": "run_toolbox",
        "args": {
            "repo_id": "r1",
            "category": "exploit",
            "argv": ["hello", "world"],
        },
    })
    assert res.ok is True
    assert "hello world" in res.stdout


def test_run_toolbox_step_credential_routing(tmp_path, monkeypatch):
    _patch_toolboxes(monkeypatch, tmp_path)
    _make_fake_repo(tmp_path, name="r1", entry_name="run.sh",
                      entry_body=(
                          "#!/bin/sh\n"
                          "echo PW=$KFIOSA_TARGET_PASSWORD\n"
                          "exit 0\n"
                      ))
    res = run_toolbox_step({
        "action": "run_toolbox",
        "args": {
            "repo_id": "r1",
            "category": "exploit",
            "password": "sup3rSecret!",  # auto-routes to env
        },
    })
    assert res.ok is True
    assert "sup3rSecret!" in res.stdout
    assert "sup3rSecret!" not in res.argv


def test_run_toolbox_step_explicit_env_merge(tmp_path, monkeypatch):
    """``args.env`` and ``args.env_<X>`` keys are merged."""
    _patch_toolboxes(monkeypatch, tmp_path)
    _make_fake_repo(tmp_path, name="r1", entry_name="run.sh",
                      entry_body=(
                          "#!/bin/sh\n"
                          "echo A=$KFIOSA_TARGET_PASSWORD B=$DEBUG\n"
                          "exit 0\n"
                      ))
    res = run_toolbox_step({
        "action": "run_toolbox",
        "args": {
            "repo_id": "r1",
            "category": "exploit",
            "env": {"DEBUG": "1"},
            "password": "hunter2",
        },
    })
    assert res.ok is True
    assert "A=hunter2" in res.stdout
    assert "B=1" in res.stdout


# ---------------------------------------------------------------------------
# Manifest / list helpers
# ---------------------------------------------------------------------------

def test_list_categories_returns_only_categories_with_repos(tmp_path, monkeypatch):
    _patch_toolboxes(monkeypatch, tmp_path)
    _make_fake_repo(tmp_path, name="r1", category="exploit")
    _make_fake_repo(tmp_path, name="r2", category="wifi")
    cats = list_categories()
    assert "exploit" in cats
    assert "wifi" in cats


def test_list_repos_filter_by_category(tmp_path, monkeypatch):
    _patch_toolboxes(monkeypatch, tmp_path)
    _make_fake_repo(tmp_path, name="r1", category="exploit")
    _make_fake_repo(tmp_path, name="r2", category="wifi")
    repos = list_repos(category="exploit")
    assert any(r["repo_id"] == "r1" and r["category"] == "exploit"
                for r in repos)


def test_find_repo_by_id(tmp_path, monkeypatch):
    _patch_toolboxes(monkeypatch, tmp_path)
    _make_fake_repo(tmp_path, name="r1", category="exploit")
    e = find_repo("r1", category="exploit")
    assert e is not None
    assert e.category == "exploit"
    assert e.repo_id == "r1"


def test_find_repo_missing(tmp_path, monkeypatch):
    _patch_toolboxes(monkeypatch, tmp_path)
    e = find_repo("nonexistent", category="exploit")
    assert e is None


def test_touch_index_mtime_creates_sentinel(tmp_path, monkeypatch):
    from core.toolbox import executor as exe
    monkeypatch.setattr(exe, "CATALOG_DIR", tmp_path)
    touch_index_mtime()
    assert (tmp_path / ".index_mtime").exists()


# ---------------------------------------------------------------------------
# Safety / never-fabricate
# ---------------------------------------------------------------------------

def test_never_fabricate_missing_repo(tmp_path, monkeypatch):
    _patch_toolboxes(monkeypatch, tmp_path)
    res = run_toolbox_repo("does_not_exist", category="exploit")
    assert res.ok is False
    assert "error" in res.to_dict()
    # stdout/stderr must be empty — no fabrication.
    assert res.stdout == ""
    assert res.stderr == ""


def test_never_fabricate_no_entry(tmp_path, monkeypatch):
    _patch_toolboxes(monkeypatch, tmp_path)
    repo = tmp_path / "exploit" / "r1"
    repo.mkdir(parents=True)
    res = run_toolbox_repo("r1", category="exploit")
    assert res.ok is False
    assert res.stdout == ""
    assert "entry detection" in res.error


def test_never_fabricate_timeout(tmp_path, monkeypatch):
    _patch_toolboxes(monkeypatch, tmp_path)
    _make_fake_repo(tmp_path, name="r1", entry_name="run.sh",
                      entry_body="#!/bin/sh\nsleep 5\nexit 0\n")
    res = run_toolbox_repo("r1", category="exploit", timeout_seconds=1)
    assert res.ok is False
    assert res.returncode == 124
    assert "timeout" in res.error


def test_no_bare_except_in_executor():
    """No bare ``except:`` clauses in the executor — defense-in-depth."""
    from core.toolbox import executor as exe
    src = Path(exe.__file__).read_text(encoding="utf-8")
    bad = [line for line in src.splitlines() if "except:" in line]
    # ``except Exception:`` is allowed; ``except:`` alone is the
    # ground rule we are guarding.
    bare = [b for b in bad if b.strip() == "except:" or b.strip() == "except:  # noqa"]
    assert not bare, f"bare except in executor: {bare}"


def test_never_inline_credential_key_in_argv():
    """The auto-router MUST move the credential out of argv. Verify
    by checking that a credential value never ends up in any argv
    position."""
    argv, env = _split_args({
        "target": "x",
        "password": "shhh",
        "private_key": "k",
        "auth_header": "Bearer xxx",
    })
    flat = " ".join(argv)
    assert "shhh" not in flat
    assert "Bearer xxx" not in flat
    assert "k" not in argv
    # All credential values are in env.
    assert env[f"{ENV_VAR_PREFIX}PASSWORD"] == "shhh"
    assert env[f"{ENV_VAR_PREFIX}PRIVATE_KEY"] == "k"
    assert env[f"{ENV_VAR_PREFIX}AUTH_HEADER"] == "Bearer xxx"
