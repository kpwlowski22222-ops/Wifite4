"""Tests for core.tool_installer.batch_install (Phase 2.4)."""
from __future__ import annotations

from unittest.mock import patch

import pytest

from core.tool_installer import batch_install
from core.tool_installer.batch_install import install_missing
from core.tool_installer.catalog import (
    InstallSpec,
    TOOL_CATALOG,
    reset_skipped_cache,
    skipped_tools,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _stub_maybe_install(return_value=True):
    """Replace maybe_install inside the .install module so no
    real subprocess runs. Returns the patch object so the test can
    assert call counts. The batch_install module imports
    maybe_install lazily inside install_missing(), so we patch
    the source module."""
    from core.tool_installer import install
    return patch.object(install, "maybe_install",
                        return_value=return_value)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestInstallMissing:
    def test_returns_envelope_shape(self):
        r = install_missing([])
        assert "ok" in r
        assert "installed" in r
        assert "skipped" in r
        assert "failed" in r
        assert "counts" in r
        assert r["model"] == "batch-install"
        assert r["installed"] == []
        assert r["skipped"] == []
        assert r["failed"] == []

    def test_unknown_tool_fails(self):
        r = install_missing(["definitely_not_in_catalog_xyz"])
        assert r["ok"] is False
        assert any("not in catalog" in f["error"] for f in r["failed"])
        assert "definitely_not_in_catalog_xyz" in [f["tool"] for f in r["failed"]]

    def test_empty_list_noop(self):
        r = install_missing([])
        assert r["ok"] is True
        assert r["counts"] == {"installed": 0, "skipped": 0, "failed": 0}

    def test_dedupes_repeated_tools(self):
        with _stub_maybe_install(return_value=True):
            r = install_missing(["x_undefined_1", "x_undefined_1"])
        # The dedup means the second occurrence is dropped, so we
        # only see one entry in failed.
        assert len([f for f in r["failed"] if f["tool"] == "x_undefined_1"]) == 1

    def test_skipped_tool_short_circuits(self):
        # Patch is_skipped in the batch_install namespace to treat
        # our tool as skipped.
        with patch.object(batch_install, "is_skipped", return_value=True):
            r = install_missing(["fake_skipped_tool"])
            assert "fake_skipped_tool" in r["skipped"]

    def test_confirm_required_without_confirm_fn_skips(self):
        confirm_tools = [
            name for name, spec in TOOL_CATALOG.items()
            if isinstance(spec, InstallSpec) and spec.confirm_required
        ]
        if not confirm_tools:
            pytest.skip("No confirm_required tools in catalog")
        tool = confirm_tools[0]
        r = install_missing([tool])
        assert tool in r["skipped"]

    def test_confirm_required_with_confirm_true_proceeds(self):
        confirm_tools = [
            name for name, spec in TOOL_CATALOG.items()
            if isinstance(spec, InstallSpec) and spec.confirm_required
        ]
        if not confirm_tools:
            pytest.skip("No confirm_required tools in catalog")
        tool = confirm_tools[0]
        with _stub_maybe_install(return_value=True):
            r = install_missing(
                [tool],
                auto=False,
                confirm_fn=lambda n, s: True,
            )
        assert tool in r["installed"]

    def test_confirm_required_with_confirm_false_skips(self):
        confirm_tools = [
            name for name, spec in TOOL_CATALOG.items()
            if isinstance(spec, InstallSpec) and spec.confirm_required
        ]
        if not confirm_tools:
            pytest.skip("No confirm_required tools in catalog")
        tool = confirm_tools[0]
        r = install_missing(
            [tool],
            auto=False,
            confirm_fn=lambda n, s: False,
        )
        assert tool in r["skipped"]

    def test_confirm_fn_exception_is_failure(self):
        confirm_tools = [
            name for name, spec in TOOL_CATALOG.items()
            if isinstance(spec, InstallSpec) and spec.confirm_required
        ]
        if not confirm_tools:
            pytest.skip("No confirm_required tools in catalog")
        tool = confirm_tools[0]
        def boom(n, s):
            raise RuntimeError("nope")
        r = install_missing([tool], confirm_fn=boom)
        match = [f for f in r["failed"] if f["tool"] == tool]
        assert match
        assert "confirm_fn raised" in match[0]["error"]

    def test_maybe_install_false_marks_failed(self):
        # Pick a non-confirm tool from the catalog.
        non_confirm = [
            name for name, spec in TOOL_CATALOG.items()
            if isinstance(spec, InstallSpec) and not spec.confirm_required
        ]
        if not non_confirm:
            pytest.skip("No non-confirm tools in catalog")
        tool = non_confirm[0]
        with _stub_maybe_install(return_value=False):
            r = install_missing([tool], auto=True)
        match = [f for f in r["failed"] if f["tool"] == tool]
        assert match
        assert "maybe_install returned False" in match[0]["error"]

    def test_maybe_install_raises_marked_failed(self):
        non_confirm = [
            name for name, spec in TOOL_CATALOG.items()
            if isinstance(spec, InstallSpec) and not spec.confirm_required
        ]
        if not non_confirm:
            pytest.skip("No non-confirm tools in catalog")
        tool = non_confirm[0]
        from core.tool_installer import install
        def boom(name):
            raise RuntimeError("apt exploded")
        with patch.object(install, "maybe_install", side_effect=boom):
            r = install_missing([tool], auto=True)
        match = [f for f in r["failed"] if f["tool"] == tool]
        assert match
        assert "maybe_install:" in match[0]["error"]


class TestBatchInstallExports:
    def test_install_missing_exported_from_package(self):
        from core.tool_installer import install_missing as im2
        assert im2 is install_missing

    def test_sdr_helpers_exported(self):
        from core.tool_installer import is_sdr_available, sdr_status
        assert callable(is_sdr_available)
        assert callable(sdr_status)
        # is_sdr_available must be False in our setup (no SDR).
        assert is_sdr_available() is False
        s = sdr_status()
        assert isinstance(s, dict)
        assert s["policy"] == "skip-sdr"
