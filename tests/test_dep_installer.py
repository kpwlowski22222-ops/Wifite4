"""Tests for the tool installer catalog expansion (Phase 2.3.B).

These tests are hermetic — they patch ``subprocess.run`` via
``monkeypatch`` so no real apt/pip/git is invoked, and they assert:

  * The catalog has the expected new entries (Flask ecosystem,
    Polish OSINT helpers, post-exploit tools).
  * The ``_skipped.txt`` file enumerates SDR-only tools.
  * ``maybe_install`` honours the per-step gate (refuses without
    ``confirm_fn`` when ``confirm_required=True``).
  * ``maybe_install`` is idempotent (already-present tool returns
    True without trying to install).
  * ``maybe_install`` tries apt → pip → git in order and logs each
    attempt.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import List, Tuple

import pytest

from core.tool_installer.catalog import (
    TOOL_CATALOG,
    InstallSpec,
    _skipped_path,
    is_skipped,
    skipped_tools,
)
from core.tool_installer.install import maybe_install, _try_apt, _try_pip, _try_git


# ---------------------------------------------------------------------------
# Catalog coverage
# ---------------------------------------------------------------------------

class TestCatalogExpansion:
    """The new entries promised by Phase 2.3.B."""

    def test_flask_ecosystem(self):
        for name in ("flask", "werkzeug", "jinja2", "flask-cors",
                     "itsdangerous", "markupsafe", "click"):
            assert name in TOOL_CATALOG, f"missing {name}"
            spec = TOOL_CATALOG[name]
            # Should be pip-installable
            assert spec.pip is not None
            assert spec.confirm_required is True

    def test_polish_osint_helpers(self):
        for name in ("phonenumbers", "email-validator", "python-dateutil",
                     "lxml", "beautifulsoup4", "requests-html", "furl"):
            assert name in TOOL_CATALOG, f"missing {name}"

    def test_post_exploit_additions(self):
        assert "mimikatz" in TOOL_CATALOG
        mimi = TOOL_CATALOG["mimikatz"]
        assert mimi.git is not None
        assert mimi.confirm_required is True
        for name in ("RDP-Checker", "sprayingtoolkit", "krbrelayx",
                     "certipy", "mitm6", "bloodhound"):
            assert name in TOOL_CATALOG, f"missing {name}"

    def test_apt_lookup_helpers(self):
        for name in ("whois", "dig", "nslookup"):
            assert name in TOOL_CATALOG

    def test_catalog_grew(self):
        """The catalog should be substantially bigger than the Phase 2.2
        baseline. We assert a lower bound rather than an exact number so
        future additions don't break this test."""
        assert len(TOOL_CATALOG) >= 200, (
            f"catalog has {len(TOOL_CATALOG)} entries, expected >= 200"
        )


# ---------------------------------------------------------------------------
# SDR skip file
# ---------------------------------------------------------------------------

class TestSkippedFile:
    def test_skipped_file_exists(self):
        p = _skipped_path()
        assert p.exists()
        assert p.is_file()

    def test_skipped_file_lists_sdr_tools(self):
        for name in ("hackrf", "rtl-sdr", "bladerf", "ubertooth"):
            assert is_skipped(name), f"{name} should be marked skipped"

    def test_skipped_returns_set(self):
        skipped = skipped_tools()
        assert isinstance(skipped, (set, frozenset, list))
        assert "hackrf" in skipped

    def test_non_sdr_not_skipped(self):
        for name in ("flask", "nmap", "scapy"):
            assert not is_skipped(name)


# ---------------------------------------------------------------------------
# maybe_install — hermetic
# ---------------------------------------------------------------------------

class TestMaybeInstall:
    def test_miss_returns_false(self, monkeypatch):
        # Tool not in catalog
        r = maybe_install("not_a_real_tool_xyz123", auto=True)
        assert r is False

    def test_refuses_without_confirm(self, monkeypatch):
        """When confirm_required=True and no confirm_fn is supplied,
        maybe_install must refuse (per the operator's per-step gate)."""
        # Even with auto=False, the default-refuse path runs.
        r = maybe_install("flask", auto=False, confirm_fn=None)
        assert r is False

    def test_confirm_fn_can_approve(self, monkeypatch):
        """When confirm_fn returns True, maybe_install proceeds.
        The pip call itself is faked."""
        # Pretend flask is already on PATH (fakes the success check)
        monkeypatch.setattr(
            "core.tool_installer.install.shutil.which",
            lambda x: "/usr/bin/flask" if x == "flask" else None,
        )
        r = maybe_install("flask", auto=False, confirm_fn=lambda _p: True)
        assert r is True

    def test_confirm_fn_can_decline(self, monkeypatch):
        def decline(_prompt):
            return False
        r = maybe_install("flask", auto=False, confirm_fn=decline)
        assert r is False

    def test_already_present_no_attempt(self, monkeypatch):
        # If shutil.which returns True, no install attempt
        attempts = []
        def fake_run(*a, **kw):
            attempts.append(a)
            return subprocess.CompletedProcess(args=a, returncode=0, stdout="", stderr="")
        monkeypatch.setattr("core.tool_installer.install.subprocess.run", fake_run)
        monkeypatch.setattr(
            "core.tool_installer.install.shutil.which",
            lambda x: "/usr/bin/flask" if x == "flask" else None,
        )
        r = maybe_install("flask", auto=True)
        assert r is True
        assert not attempts  # no install was attempted

    def test_tries_apt_then_pip_then_git(self, monkeypatch):
        """The order is: if spec.apt -> try apt first; if it fails,
        try spec.pip; if that fails, try spec.git."""
        from core.tool_installer import install
        # Use a tool with all 3 sources
        all3 = InstallSpec(
            apt="libx", pip="pylibx",
            git=("https://github.com/foo/x", "toolboxes/x"),
            confirm_required=False,
        )
        TOOL_CATALOG["_test_all3"] = all3
        try:
            calls = []
            def fake_apt(pkg, *, timeout):
                calls.append(("apt", pkg))
                return False
            def fake_pip(pkg, *, timeout):
                calls.append(("pip", pkg))
                return False
            def fake_git(repo, target, *, timeout):
                calls.append(("git", repo))
                return False
            monkeypatch.setattr(install, "_try_apt", fake_apt)
            monkeypatch.setattr(install, "_try_pip", fake_pip)
            monkeypatch.setattr(install, "_try_git", fake_git)
            monkeypatch.setattr(
                "core.tool_installer.install.shutil.which",
                lambda x: None,  # never on PATH
            )
            r = maybe_install("_test_all3", auto=True, timeout=10)
            assert r is False
            assert [c[0] for c in calls] == ["apt", "pip", "git"]
        finally:
            TOOL_CATALOG.pop("_test_all3", None)

    def test_apt_success_short_circuits(self, monkeypatch):
        """If apt succeeds and the tool is on PATH after, no pip/git
        is tried."""
        from core.tool_installer import install
        all3 = InstallSpec(
            apt="libx", pip="pylibx",
            git=("https://github.com/foo/x", "toolboxes/x"),
            confirm_required=False,
        )
        TOOL_CATALOG["_test_all3"] = all3
        try:
            calls = []
            def fake_apt(pkg, *, timeout):
                calls.append(("apt", pkg))
                return True  # apt succeeded
            def fake_pip(pkg, *, timeout):
                calls.append(("pip", pkg))
                return False
            def fake_git(repo, target, *, timeout):
                calls.append(("git", repo))
                return False
            monkeypatch.setattr(install, "_try_apt", fake_apt)
            monkeypatch.setattr(install, "_try_pip", fake_pip)
            monkeypatch.setattr(install, "_try_git", fake_git)
            # Simulate the tool being NOT on PATH initially, then on
            # PATH after apt succeeded. This requires a stateful fake.
            state = {"on_path": False}
            def fake_which(x):
                if x == "_test_all3" and state["on_path"]:
                    return "/usr/bin/_test_all3"
                return None
            monkeypatch.setattr(
                "core.tool_installer.install.shutil.which", fake_which,
            )
            # Hook: as soon as apt is called, mark on_path True
            def fake_apt_stateful(pkg, *, timeout):
                calls.append(("apt", pkg))
                state["on_path"] = True
                return True
            monkeypatch.setattr(install, "_try_apt", fake_apt_stateful)
            r = maybe_install("_test_all3", auto=True, timeout=10)
            assert r is True
            # Only apt was tried (pip/git not even attempted)
            assert [c[0] for c in calls] == ["apt"]
        finally:
            TOOL_CATALOG.pop("_test_all3", None)

    def test_idempotent_after_install(self, monkeypatch, tmp_path):
        """If the tool is already on PATH, maybe_install returns True
        immediately, even with auto=True and no confirm_fn."""
        monkeypatch.setattr(
            "core.tool_installer.install.shutil.which",
            lambda x: "/usr/bin/flask" if x == "flask" else None,
        )
        r = maybe_install("flask", auto=True)
        assert r is True


# ---------------------------------------------------------------------------
# Adversarial: never inline / never fabricate
# ---------------------------------------------------------------------------

class TestAdversarialInstaller:
    def test_no_credentials_in_catalog(self):
        """The catalog should never contain inline credentials (we use
        KFIOSA_* env-var sentinels at the runner level, not here)."""
        for name, spec in TOOL_CATALOG.items():
            for src in (spec.apt, spec.pip, spec.brew):
                if src:
                    assert "password" not in src.lower()
            if spec.git:
                repo, target = spec.git
                assert "password" not in repo.lower()
                assert "password" not in target.lower()

    def test_no_destructive_git_targets(self):
        """Git clone targets must be under toolboxes/."""
        for name, spec in TOOL_CATALOG.items():
            if spec.git:
                _repo, target = spec.git
                assert target.startswith("toolboxes/"), (
                    f"unsafe target: {target!r} for {name!r}"
                )
