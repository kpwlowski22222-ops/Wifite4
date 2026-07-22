"""tests.test_kismet_prechain — verify ``kismet_scan`` is wired into
the chain planner and the orchestrator's prechain hook is callable.
"""
from __future__ import annotations

import os
import shutil
import tempfile
from pathlib import Path
from unittest import mock

import pytest

from core.ai_backend.chain import (
    KISMET_PROMPT_STANZA,
    _CHAIN_STEP_SCHEMA_HINT,
    _SYSTEM_PROMPT,
)


def test_kismet_scan_in_schema_hint():
    assert "kismet_scan" in _CHAIN_STEP_SCHEMA_HINT


def test_kismet_scan_in_kismet_stanza():
    assert "kismet_scan" in KISMET_PROMPT_STANZA


def test_kismet_scan_in_system_prompt():
    assert "kismet_scan" in _SYSTEM_PROMPT


def test_stanza_documents_admin_admin_credentials():
    """The Kismet client uses admin / admin (operator-provided)."""
    assert "admin" in KISMET_PROMPT_STANZA
    assert "KISMET_CLIENT_PASSWORD" in KISMET_PROMPT_STANZA


def test_stanza_documents_chain_followup():
    """The stanza tells the LLM the follow-up pattern: kismet ->
    convert to pcap -> chain to tshark / aircrack-ng."""
    for marker in ("convert_cap_to_pcap", "pcap", "tshark",
                    "aircrack-ng"):
        assert marker in KISMET_PROMPT_STANZA, marker


def test_stanza_distinguishes_from_airodump():
    """The stanza explains when to prefer Kismet over airodump."""
    assert "airodump" in KISMET_PROMPT_STANZA
    assert "hidden" in KISMET_PROMPT_STANZA or "6 GHz" in KISMET_PROMPT_STANZA


# ---------------------------------------------------------------------------
# Prechain context (apply_to_prechain)
# ---------------------------------------------------------------------------

def test_prechain_returns_structured_context(tmp_path):
    """A live captures dir with a Kismet file matching the target
    must return a structured context, not a fake fabricated one."""
    from core.scanners.kismet_runner import KismetRunner
    cap_dir = tmp_path / "captures"
    cap_dir.mkdir()
    (cap_dir / "Kismet-20260720-AA-BB-001122334455.kismet"
     ).write_bytes(b"FAKE")
    runner = KismetRunner()
    res = runner.apply_to_prechain(
        target={"bssid": "00:11:22:33:44:55", "ssid": "lab"},
        captures_dir=str(cap_dir),
    )
    assert res["ok"] is True
    assert res["n_captures"] == 1
    assert "bssid_in_filename" in res["matches"][0]["matched_by"]


def test_prechain_no_fabricated_match(tmp_path):
    """Empty / unrelated captures dir must return ok=False with a
    clear 'no matching capture' message — never a fabricated match."""
    from core.scanners.kismet_runner import KismetRunner
    cap_dir = tmp_path / "captures"
    cap_dir.mkdir()
    runner = KismetRunner()
    res = runner.apply_to_prechain(
        target={"bssid": "00:11:22:33:44:55", "ssid": "lab"},
        captures_dir=str(cap_dir),
    )
    assert res["ok"] is False
    assert "no matching capture" in res["error"]


# ---------------------------------------------------------------------------
# Tool catalog
# ---------------------------------------------------------------------------

def test_kismet_in_tool_installer_catalog():
    from core.tool_installer.catalog import TOOL_CATALOG
    assert "kismet" in TOOL_CATALOG
    spec = TOOL_CATALOG["kismet"]
    # Operator-gated install (apt) — confirm_required=True.
    assert spec.apt == "kismet"
    assert spec.confirm_required is True


# ---------------------------------------------------------------------------
# Orchestrator dispatch
# ---------------------------------------------------------------------------

def test_orchestrator_dispatches_kismet_scan():
    from core.orchestrator.autonomous_orchestrator import (
        AutonomousOrchestrator,
    )
    assert hasattr(AutonomousOrchestrator, "_dispatch_kismet_scan")


def test_orchestrator_routes_kismet_scan_in_walk_ai_step():
    from core.orchestrator import autonomous_orchestrator as ao
    src = Path(ao.__file__).read_text(encoding="utf-8")
    assert '"kismet_scan"' in src
    assert "_dispatch_kismet_scan" in src
