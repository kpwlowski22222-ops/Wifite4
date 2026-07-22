"""tests.test_kismet_prechain_orchestrator — verify the
``_maybe_kismet_prechain`` orchestrator hook.

Coverage:
  - method exists on the orchestrator
  - missing tool → honest-degrade log line
  - missing dir → honest-degrade log line
  - no match → honest-degrade log line
  - happy path: target['recon']['kismet_prechain'] is populated
  - happy path: report['kismet_prechain'] is populated
  - non-dict target → skipped
  - failures (KismetRunner raises) don't crash the orchestrator
"""
from __future__ import annotations

import os
from typing import Any, Dict, List, Optional
from unittest import mock

import pytest


def test_orchestrator_has_maybe_kismet_prechain():
    from core.orchestrator.autonomous_orchestrator import (
        AutonomousOrchestrator,
    )
    assert hasattr(AutonomousOrchestrator, "_maybe_kismet_prechain")


def test_prechain_missing_tool_degrades(tmp_path, monkeypatch):
    """When kismet is not on PATH, the prechain logs and
    returns without modifying the seed."""
    from core.orchestrator.autonomous_orchestrator import (
        AutonomousOrchestrator,
    )
    # Strip PATH so is_installed() returns False.
    monkeypatch.setenv("PATH", str(tmp_path / "empty"))
    (tmp_path / "empty").mkdir(exist_ok=True)
    orch = AutonomousOrchestrator.__new__(AutonomousOrchestrator)
    # Avoid running __init__ (it touches hardware); just attach _emit.
    orch._emit = lambda m: None  # type: ignore[attr-defined]
    seed = {"target": {"bssid": "00:11:22:33:44:55"},
            "captures_dir": str(tmp_path / "captures")}
    report: Dict[str, Any] = {}
    orch._maybe_kismet_prechain(seed, report)
    # Seed.target.recon is NOT modified
    assert "recon" not in seed["target"]
    # Report has no kismet_prechain key
    assert "kismet_prechain" not in report


def test_prechain_missing_dir_degrades(tmp_path, monkeypatch):
    """When the captures dir does not exist, the prechain logs
    and returns without modifying the seed."""
    from core.orchestrator.autonomous_orchestrator import (
        AutonomousOrchestrator,
    )
    # Patch is_installed to True so the path forward is "exists?"
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    (fake_bin / "kismet").write_text("#!/bin/sh\nexit 0\n")
    os.chmod(fake_bin / "kismet", 0o755)
    monkeypatch.setenv("PATH", f"{fake_bin}:{os.environ['PATH']}")
    orch = AutonomousOrchestrator.__new__(AutonomousOrchestrator)
    orch._emit = lambda m: None  # type: ignore[attr-defined]
    seed = {"target": {"bssid": "00:11:22:33:44:55"},
            "captures_dir": str(tmp_path / "no_such_captures")}
    report: Dict[str, Any] = {}
    orch._maybe_kismet_prechain(seed, report)
    assert "recon" not in seed["target"]


def test_prechain_no_match_degrades(tmp_path, monkeypatch):
    """A captures dir with files but no match → honest-degrade."""
    from core.orchestrator.autonomous_orchestrator import (
        AutonomousOrchestrator,
    )
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    (fake_bin / "kismet").write_text("#!/bin/sh\nexit 0\n")
    os.chmod(fake_bin / "kismet", 0o755)
    monkeypatch.setenv("PATH", f"{fake_bin}:{os.environ['PATH']}")
    orch = AutonomousOrchestrator.__new__(AutonomousOrchestrator)
    orch._emit = lambda m: None  # type: ignore[attr-defined]
    cap_dir = tmp_path / "captures"
    cap_dir.mkdir()
    (cap_dir / "random.bin").write_bytes(b"x")
    seed = {"target": {"bssid": "00:11:22:33:44:55"},
            "captures_dir": str(cap_dir)}
    report: Dict[str, Any] = {}
    orch._maybe_kismet_prechain(seed, report)
    assert "recon" not in seed["target"]


def test_prechain_happy_path(tmp_path, monkeypatch):
    """A captures dir with a matching file ingests the prechain
    into seed.target.recon and report['kismet_prechain']."""
    from core.orchestrator.autonomous_orchestrator import (
        AutonomousOrchestrator,
    )
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    (fake_bin / "kismet").write_text("#!/bin/sh\nexit 0\n")
    os.chmod(fake_bin / "kismet", 0o755)
    monkeypatch.setenv("PATH", f"{fake_bin}:{os.environ['PATH']}")
    orch = AutonomousOrchestrator.__new__(AutonomousOrchestrator)
    log: List[str] = []
    orch._emit = lambda m: log.append(m)  # type: ignore[attr-defined]
    cap_dir = tmp_path / "captures"
    cap_dir.mkdir()
    (cap_dir / "Kismet-20260720-001122-AA-BB-001122334455.kismet"
     ).write_bytes(b"FAKE")
    seed = {
        "target": {"bssid": "00:11:22:33:44:55", "ssid": "lab"},
        "captures_dir": str(cap_dir),
    }
    report: Dict[str, Any] = {}
    orch._maybe_kismet_prechain(seed, report)
    assert "recon" in seed["target"]
    assert "kismet_prechain" in seed["target"]["recon"]
    assert seed["target"]["recon"]["kismet_prechain"]["ok"] is True
    assert report["kismet_prechain"]["ok"] is True
    # Log line was emitted
    assert any("kismet prechain" in m and "1 capture" in m for m in log), log


def test_prechain_non_dict_target_skips(tmp_path, monkeypatch):
    """A non-dict target in seed is skipped, no crash."""
    from core.orchestrator.autonomous_orchestrator import (
        AutonomousOrchestrator,
    )
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    (fake_bin / "kismet").write_text("#!/bin/sh\nexit 0\n")
    os.chmod(fake_bin / "kismet", 0o755)
    monkeypatch.setenv("PATH", f"{fake_bin}:{os.environ['PATH']}")
    orch = AutonomousOrchestrator.__new__(AutonomousOrchestrator)
    orch._emit = lambda m: None  # type: ignore[attr-defined]
    seed: Dict[str, Any] = {"target": "not a dict"}
    report: Dict[str, Any] = {}
    orch._maybe_kismet_prechain(seed, report)
    # No crash; no report key added.


def test_prechain_runner_import_failure_does_not_crash(tmp_path, monkeypatch):
    """If KismetRunner fails to import, the prechain logs and
    returns without crashing."""
    from core.orchestrator.autonomous_orchestrator import (
        AutonomousOrchestrator,
    )
    orch = AutonomousOrchestrator.__new__(AutonomousOrchestrator)
    log: List[str] = []
    orch._emit = lambda m: log.append(m)  # type: ignore[attr-defined]
    seed = {"target": {"bssid": "00:11:22:33:44:55"},
            "captures_dir": str(tmp_path)}
    report: Dict[str, Any] = {}
    with mock.patch.dict("sys.modules", {
        "core.scanners.kismet_runner": None,
    }):
        orch._maybe_kismet_prechain(seed, report)
    # No crash; no modification.
    assert "recon" not in seed["target"]


def test_prechain_runner_raises_does_not_crash(tmp_path, monkeypatch):
    """If KismetRunner.apply_to_prechain raises, the prechain
    must not crash the chain walk."""
    from core.orchestrator.autonomous_orchestrator import (
        AutonomousOrchestrator,
    )
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    (fake_bin / "kismet").write_text("#!/bin/sh\nexit 0\n")
    os.chmod(fake_bin / "kismet", 0o755)
    monkeypatch.setenv("PATH", f"{fake_bin}:{os.environ['PATH']}")
    orch = AutonomousOrchestrator.__new__(AutonomousOrchestrator)
    orch._emit = lambda m: None  # type: ignore[attr-defined]
    seed = {"target": {"bssid": "00:11:22:33:44:55"},
            "captures_dir": str(tmp_path / "captures")}
    report: Dict[str, Any] = {}
    # Patch the import to a fake that raises.
    fake_mod = mock.MagicMock()
    fake_mod.KismetRunner.return_value.apply_to_prechain.side_effect = (
        RuntimeError("boom")
    )
    with mock.patch.dict("sys.modules", {
        "core.scanners.kismet_runner": fake_mod,
    }):
        # The prechain must not raise out.
        orch._maybe_kismet_prechain(seed, report)
    # No modification.
    assert "recon" not in seed["target"]


def test_prechain_uses_default_captures_dir(tmp_path, monkeypatch):
    """When ``seed['captures_dir']`` is missing, the prechain
    falls back to ``workspace/captures``. The prechain must
    not crash on this fallback path."""
    from core.orchestrator.autonomous_orchestrator import (
        AutonomousOrchestrator,
    )
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    (fake_bin / "kismet").write_text("#!/bin/sh\nexit 0\n")
    os.chmod(fake_bin / "kismet", 0o755)
    monkeypatch.setenv("PATH", f"{fake_bin}:{os.environ['PATH']}")
    # Create a default captures dir relative to cwd
    monkeypatch.chdir(tmp_path)
    default = tmp_path / "workspace" / "captures"
    default.mkdir(parents=True)
    # Create a file that does NOT match the default (no Kismet- prefix)
    (default / "random_other.bin").write_bytes(b"x")
    orch = AutonomousOrchestrator.__new__(AutonomousOrchestrator)
    log: List[str] = []
    orch._emit = lambda m: log.append(m)  # type: ignore[attr-defined]
    seed = {"target": {"bssid": "00:11:22:33:44:55"}}
    report: Dict[str, Any] = {}
    orch._maybe_kismet_prechain(seed, report)
    # No match (no Kismet- prefix in filename), so no modification.
    assert "recon" not in seed["target"]
    # Prechain ran (no crash).


def test_prechain_called_from_walk_chain_with_replan():
    """The prechain is invoked from _walk_chain_with_replan."""
    from core.orchestrator import autonomous_orchestrator as ao
    src = open(ao.__file__, "r", encoding="utf-8").read()
    assert "_maybe_kismet_prechain" in src
    # It's called at the top of _walk_chain_with_replan
    walk_idx = src.find("def _walk_chain_with_replan")
    prechain_idx = src.find("_maybe_kismet_prechain", walk_idx)
    assert walk_idx >= 0
    assert prechain_idx > walk_idx
