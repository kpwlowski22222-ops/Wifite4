"""tests.test_chain_zero_day_integration — verify the
Phase 2.2.G tighter zero-day chain integration.

Coverage:
  - KFIOSA_ZERO_DAY_TAIL_AUTO env-var hook: default off, opt-in
    via 1/true/yes/on
  - _heuristic_for_domain: auto-appends the 3-step tail on
    KFIOSA_ZERO_DAY_TAIL_AUTO=1
  - _heuristic_for_domain: does NOT auto-append when env-var is
    unset (legacy behavior preserved)
  - _resolve_zero_day_draft_id: returns None on empty target
  - _resolve_zero_day_draft_id: returns the draft_id of the most
    recent ACK'd concept whose target shares at least one
    fingerprint key
  - _resolve_zero_day_draft_id: tie-breaks on created_at
  - _resolve_zero_day_draft_id: ignores rejected + pending concepts
  - Orchestrator: zero_day_execute resolves a fingerprint-matching
    ACK'd concept when the LLM didn't name a specific exploit
  - Orchestrator: zero_day_execute honest-degrades when fingerprint
    match found an ACK'd concept but no exploit was built for it
  - Orchestrator: zero_day_execute falls back to recency when
    fingerprint resolution returns None
  - End-to-end: heuristic chain with env-var on produces a chain
    whose last 3 steps are zero_day_propose / build / execute
"""
from __future__ import annotations

import os
from typing import Any, Dict, List, Optional
from unittest import mock

import pytest


# ---------------------------------------------------------------------------
# env-var hook
# ---------------------------------------------------------------------------

def test_zero_day_tail_auto_disabled_by_default(monkeypatch):
    """When KFIOSA_ZERO_DAY_TAIL_AUTO is not set, the hook returns
    False so the legacy chain shape is preserved."""
    monkeypatch.delenv("KFIOSA_ZERO_DAY_TAIL_AUTO", raising=False)
    from core.ai_backend.chain import _zero_day_tail_auto_enabled
    assert _zero_day_tail_auto_enabled() is False


@pytest.mark.parametrize("value", ["1", "true", "yes", "on", "TRUE", "Yes"])
def test_zero_day_tail_auto_enabled_truthy(monkeypatch, value):
    """The hook accepts a variety of truthy spellings."""
    monkeypatch.setenv("KFIOSA_ZERO_DAY_TAIL_AUTO", value)
    from core.ai_backend.chain import _zero_day_tail_auto_enabled
    assert _zero_day_tail_auto_enabled() is True


@pytest.mark.parametrize("value", ["0", "false", "no", "off", "", "anything"])
def test_zero_day_tail_auto_disabled_falsy(monkeypatch, value):
    """Anything else is treated as off."""
    monkeypatch.setenv("KFIOSA_ZERO_DAY_TAIL_AUTO", value)
    from core.ai_backend.chain import _zero_day_tail_auto_enabled
    assert _zero_day_tail_auto_enabled() is False


# ---------------------------------------------------------------------------
# _heuristic_for_domain auto-tail
# ---------------------------------------------------------------------------

def test_heuristic_wifi_no_tail_when_env_unset(monkeypatch):
    """Default behavior: no zero-day tail appended."""
    monkeypatch.delenv("KFIOSA_ZERO_DAY_TAIL_AUTO", raising=False)
    from core.ai_backend.chain import _heuristic_for_domain
    chain = _heuristic_for_domain(
        "wifi",
        {"bssid": "AA:BB:CC:DD:EE:FF", "channel": 6, "encryption": "wpa2"},
    )
    actions = [s["action"] for s in chain]
    assert "zero_day_propose" not in actions
    assert "zero_day_build" not in actions
    assert "zero_day_execute" not in actions


def test_heuristic_wifi_appends_tail_when_env_on(monkeypatch):
    """When the env-var is set, the chain ends with the 3-step
    optional tail."""
    monkeypatch.setenv("KFIOSA_ZERO_DAY_TAIL_AUTO", "1")
    from core.ai_backend.chain import _heuristic_for_domain
    chain = _heuristic_for_domain(
        "wifi",
        {"bssid": "AA:BB:CC:DD:EE:FF", "channel": 6, "encryption": "wpa2"},
    )
    actions = [s["action"] for s in chain]
    assert "zero_day_propose" in actions
    assert "zero_day_build" in actions
    assert "zero_day_execute" in actions
    # The last 3 must be the tail in order.
    assert actions[-3:] == [
        "zero_day_propose", "zero_day_build", "zero_day_execute",
    ]
    # Each tail step is marked optional so the orchestrator's
    # per-step ACCEPT gate is the only gate.
    for s in chain[-3:]:
        assert s.get("optional") is True


def test_heuristic_non_wifi_does_not_get_tail(monkeypatch):
    """The env-var hook is only added to the wifi domain; other
    domains still return their no-heuristic response."""
    monkeypatch.setenv("KFIOSA_ZERO_DAY_TAIL_AUTO", "1")
    from core.ai_backend.chain import _heuristic_for_domain
    chain = _heuristic_for_domain(
        "microsoft",
        {"host": "10.0.0.5", "vendor": "Microsoft"},
    )
    # Non-wifi domains only get a 'parse' step.
    assert len(chain) == 1
    assert chain[0]["action"] == "parse"


# ---------------------------------------------------------------------------
# _resolve_zero_day_draft_id
# ---------------------------------------------------------------------------

def test_resolve_returns_none_for_empty_target(tmp_path, monkeypatch):
    """An empty target can't match anything."""
    from core.ai_backend.zero_day import ZeroDayDraftStore
    monkeypatch.setattr(
        "core.ai_backend.zero_day.DEFAULT_DRAFTS_DIR", tmp_path,
    )
    from core.ai_backend.chain import _resolve_zero_day_draft_id
    assert _resolve_zero_day_draft_id({}) is None


def test_resolve_returns_none_when_no_concepts(tmp_path, monkeypatch):
    """No concepts on disk -> no match."""
    from core.ai_backend.zero_day import ZeroDayDraftStore
    monkeypatch.setattr(
        "core.ai_backend.zero_day.DEFAULT_DRAFTS_DIR", tmp_path,
    )
    from core.ai_backend.chain import _resolve_zero_day_draft_id
    assert _resolve_zero_day_draft_id({"vendor": "linksys"}) is None


def test_resolve_returns_matching_acked_concept(tmp_path, monkeypatch):
    """An ACK'd concept whose target shares at least one
    fingerprint key wins."""
    from core.ai_backend.zero_day import (
        ZeroDayConcept, ZeroDayDraftStore, ack_draft,
    )
    monkeypatch.setattr(
        "core.ai_backend.zero_day.DEFAULT_DRAFTS_DIR", tmp_path,
    )
    store = ZeroDayDraftStore(root_dir=tmp_path)
    c = ZeroDayConcept(
        draft_id="d-matching",
        target={"vendor": "linksys", "model": "WRT54G"},
        title="t", hypothesis="h", vulnerability_class="heap_overflow",
        technique="t", indicators=[], entry_point="e", tooling=[],
        draft_poc_outline="o", risk_notes="r", cve_hint="",
        confidence="low", recon_context={},
    )
    store.save(c)
    ack_draft(store, "d-matching")
    from core.ai_backend.chain import _resolve_zero_day_draft_id
    resolved = _resolve_zero_day_draft_id({"vendor": "linksys"})
    assert resolved == "d-matching"


def test_resolve_ignores_pending_and_rejected(tmp_path, monkeypatch):
    """Only ACK'd concepts are returned."""
    from core.ai_backend.zero_day import (
        ZeroDayConcept, ZeroDayDraftStore,
    )
    monkeypatch.setattr(
        "core.ai_backend.zero_day.DEFAULT_DRAFTS_DIR", tmp_path,
    )
    store = ZeroDayDraftStore(root_dir=tmp_path)
    pending = ZeroDayConcept(
        draft_id="d-pending",
        target={"vendor": "linksys"},
        title="t", hypothesis="h", vulnerability_class="v",
        technique="t", indicators=[], entry_point="e", tooling=[],
        draft_poc_outline="o", risk_notes="r", cve_hint="",
        confidence="low", recon_context={},
    )
    rejected = ZeroDayConcept(
        draft_id="d-rejected",
        target={"vendor": "linksys"},
        title="t", hypothesis="h", vulnerability_class="v",
        technique="t", indicators=[], entry_point="e", tooling=[],
        draft_poc_outline="o", risk_notes="r", cve_hint="",
        confidence="low", recon_context={},
    )
    store.save(pending)
    store.save(rejected)
    from core.ai_backend.chain import _resolve_zero_day_draft_id
    assert _resolve_zero_day_draft_id({"vendor": "linksys"}) is None


def test_resolve_tie_breaks_on_most_recent(tmp_path, monkeypatch):
    """Two ACK'd concepts matching the same target; the more
    recently created wins."""
    from core.ai_backend.zero_day import (
        ZeroDayConcept, ZeroDayDraftStore, ack_draft,
    )
    monkeypatch.setattr(
        "core.ai_backend.zero_day.DEFAULT_DRAFTS_DIR", tmp_path,
    )
    store = ZeroDayDraftStore(root_dir=tmp_path)
    old = ZeroDayConcept(
        draft_id="d-old",
        target={"vendor": "linksys", "bssid": "AA:BB:CC:DD:EE:FF"},
        title="t", hypothesis="h", vulnerability_class="v",
        technique="t", indicators=[], entry_point="e", tooling=[],
        draft_poc_outline="o", risk_notes="r", cve_hint="",
        confidence="low", recon_context={},
        created_at=100.0,
    )
    new = ZeroDayConcept(
        draft_id="d-new",
        target={"vendor": "linksys", "bssid": "AA:BB:CC:DD:EE:FF"},
        title="t", hypothesis="h", vulnerability_class="v",
        technique="t", indicators=[], entry_point="e", tooling=[],
        draft_poc_outline="o", risk_notes="r", cve_hint="",
        confidence="low", recon_context={},
        created_at=200.0,
    )
    store.save(old)
    store.save(new)
    ack_draft(store, "d-old")
    ack_draft(store, "d-new")
    from core.ai_backend.chain import _resolve_zero_day_draft_id
    resolved = _resolve_zero_day_draft_id({
        "vendor": "linksys", "bssid": "AA:BB:CC:DD:EE:FF",
    })
    assert resolved == "d-new"


def test_resolve_skips_concepts_with_no_fingerprint_overlap(tmp_path, monkeypatch):
    """A concept whose target shares ZERO fingerprint keys is
    not returned (avoids wrong-target execution)."""
    from core.ai_backend.zero_day import (
        ZeroDayConcept, ZeroDayDraftStore, ack_draft,
    )
    monkeypatch.setattr(
        "core.ai_backend.zero_day.DEFAULT_DRAFTS_DIR", tmp_path,
    )
    store = ZeroDayDraftStore(root_dir=tmp_path)
    other = ZeroDayConcept(
        draft_id="d-other",
        target={"vendor": "cisco", "model": "ASA-5505"},
        title="t", hypothesis="h", vulnerability_class="v",
        technique="t", indicators=[], entry_point="e", tooling=[],
        draft_poc_outline="o", risk_notes="r", cve_hint="",
        confidence="low", recon_context={},
    )
    store.save(other)
    ack_draft(store, "d-other")
    from core.ai_backend.chain import _resolve_zero_day_draft_id
    # Asking for a linksys target with a cisco concept on disk
    # must not match.
    assert _resolve_zero_day_draft_id({"vendor": "linksys"}) is None


# ---------------------------------------------------------------------------
# Orchestrator: zero_day_execute fingerprint resolution
# ---------------------------------------------------------------------------

def _build_orchestrator_with_builder(*, builder) -> "object":
    """Construct an AutonomousOrchestrator without running __init__.
    The test injects the dependencies it needs."""
    from core.orchestrator.autonomous_orchestrator import (
        AutonomousOrchestrator,
    )
    orch = AutonomousOrchestrator.__new__(AutonomousOrchestrator)
    orch._emit = lambda m: None  # type: ignore[attr-defined]
    orch.zero_day_exploit_builder = builder
    orch.zero_day_exploit_runner = mock.MagicMock()
    orch.confirm_fn = lambda *a, **k: True
    return orch


def test_orchestrator_resolves_fingerprint_draft_id(tmp_path, monkeypatch):
    """When the LLM emits a zero_day_execute step with a target
    but no draft_id / exploit_id, the orchestrator must look up
    the most-recent ACK'd concept for the same target
    fingerprint."""
    from core.ai_backend.zero_day import (
        ZeroDayConcept, ZeroDayDraftStore, ack_draft,
    )
    from core.ai_backend.zero_day_exploit import (
        ZeroDayExploit, ZeroDayExploitBuilder, ZeroDayExploitStore,
    )
    drafts_dir = tmp_path / "drafts"
    exploits_dir = tmp_path / "exploits"
    drafts_dir.mkdir()
    exploits_dir.mkdir()
    monkeypatch.setattr(
        "core.ai_backend.zero_day.DEFAULT_DRAFTS_DIR", drafts_dir,
    )
    monkeypatch.setattr(
        "core.ai_backend.zero_day_exploit.DEFAULT_EXPLOITS_DIR", exploits_dir,
    )
    store = ZeroDayDraftStore(root_dir=drafts_dir)
    c = ZeroDayConcept(
        draft_id="d-fp-iso",
        target={"vendor": "linksys-fp-iso",
                "bssid": "AA:BB:CC:DD:EE:01"},
        title="t", hypothesis="h", vulnerability_class="v",
        technique="t", indicators=[], entry_point="e", tooling=[],
        draft_poc_outline="o", risk_notes="r", cve_hint="",
        confidence="low", recon_context={},
    )
    store.save(c)
    ack_draft(store, "d-fp-iso")
    # Build a corresponding exploit
    exploit = ZeroDayExploit(
        exploit_id="e-fp-iso",
        draft_id="d-fp-iso",
        target={"vendor": "linksys-fp-iso"},
        language="python",
        code="print('hello')",
        title="exploit-1",
        expected_effect="rce",
        safety_notes="",
        status="drafted",
    )
    estore = ZeroDayExploitStore(root_dir=exploits_dir)
    estore.save(exploit)
    builder = mock.MagicMock()
    builder.store = estore
    orch = _build_orchestrator_with_builder(builder=builder)
    report: Dict[str, Any] = {"executed": [], "skipped": []}
    step = {
        "action": "zero_day_execute",
        "tool": "zero_day_exploit_runner",
        "args": {
            "target": {"vendor": "linksys-fp-iso",
                       "bssid": "AA:BB:CC:DD:EE:01"},
        },
    }
    seed: Dict[str, Any] = {}
    orch._dispatch_zero_day_execute(step, seed, report)
    # The runner was called with the resolved exploit
    orch.zero_day_exploit_runner.run.assert_called_once()
    call_exploit = orch.zero_day_exploit_runner.run.call_args[0][0]
    assert call_exploit.exploit_id == "e-fp-iso"
    # The report captured the run
    assert len(report["executed"]) == 1
    entry = report["executed"][0]
    assert entry["action"] == "zero_day_execute"
    assert "result" in entry


def test_orchestrator_honest_degrade_when_no_built_exploit(
    tmp_path, monkeypatch,
):
    """When fingerprint resolution finds an ACK'd concept but
    no exploit was built for it, the orchestrator must
    honest-degrade and not call the runner."""
    from core.ai_backend.zero_day import (
        ZeroDayConcept, ZeroDayDraftStore, ack_draft,
    )
    # Use separate subdirs to ensure no cross-test contamination
    drafts_dir = tmp_path / "drafts"
    exploits_dir = tmp_path / "exploits"
    drafts_dir.mkdir()
    exploits_dir.mkdir()
    monkeypatch.setattr(
        "core.ai_backend.zero_day.DEFAULT_DRAFTS_DIR", drafts_dir,
    )
    monkeypatch.setattr(
        "core.ai_backend.zero_day_exploit.DEFAULT_EXPLOITS_DIR", exploits_dir,
    )
    store = ZeroDayDraftStore(root_dir=drafts_dir)
    c = ZeroDayConcept(
        draft_id="d-nobuild",
        target={"vendor": "linksys-isolated-test"},
        title="t", hypothesis="h", vulnerability_class="v",
        technique="t", indicators=[], entry_point="e", tooling=[],
        draft_poc_outline="o", risk_notes="r", cve_hint="",
        confidence="low", recon_context={},
    )
    store.save(c)
    ack_draft(store, "d-nobuild")
    # Empty exploit store (no built exploit for d-nobuild)
    from core.ai_backend.zero_day_exploit import (
        ZeroDayExploitStore,
    )
    estore = ZeroDayExploitStore(root_dir=exploits_dir)
    builder = mock.MagicMock()
    builder.store = estore
    orch = _build_orchestrator_with_builder(builder=builder)
    report: Dict[str, Any] = {"executed": [], "skipped": []}
    step = {
        "action": "zero_day_execute",
        "tool": "zero_day_exploit_runner",
        "args": {
            "target": {"vendor": "linksys-isolated-test"},
        },
    }
    seed: Dict[str, Any] = {}
    orch._dispatch_zero_day_execute(step, seed, report)
    # Runner was NOT called.
    orch.zero_day_exploit_runner.run.assert_not_called()
    # Report captures the honest-degrade.
    assert any("no built exploit" in s for s in report["skipped"])


def test_orchestrator_falls_back_to_recency(tmp_path, monkeypatch):
    """When no fingerprint match (no ACK'd concept for the
    target), the orchestrator falls back to the most-recent
    drafted/acked exploit (legacy behavior preserved)."""
    from core.ai_backend.zero_day_exploit import (
        ZeroDayExploit, ZeroDayExploitStore,
    )
    exploits_dir = tmp_path / "exploits"
    exploits_dir.mkdir()
    monkeypatch.setattr(
        "core.ai_backend.zero_day_exploit.DEFAULT_EXPLOITS_DIR", exploits_dir,
    )
    estore = ZeroDayExploitStore(root_dir=exploits_dir)
    exploit = ZeroDayExploit(
        exploit_id="e-recency-iso",
        draft_id="d-some",
        target={"vendor": "cisco"},
        language="python",
        code="print('a')",
        title="recency-exploit",
        expected_effect="rce",
        safety_notes="",
        status="drafted",
    )
    estore.save(exploit)
    builder = mock.MagicMock()
    builder.store = estore
    orch = _build_orchestrator_with_builder(builder=builder)
    report: Dict[str, Any] = {"executed": [], "skipped": []}
    step = {
        "action": "zero_day_execute",
        "tool": "zero_day_exploit_runner",
        "args": {
            "target": {"vendor": "linksys-recency-isolated"},  # no matching concept
        },
    }
    seed: Dict[str, Any] = {}
    orch._dispatch_zero_day_execute(step, seed, report)
    # Runner was called with the recency-picked exploit.
    orch.zero_day_exploit_runner.run.assert_called_once()
    call_exploit = orch.zero_day_exploit_runner.run.call_args[0][0]
    assert call_exploit.exploit_id == "e-recency-iso"


# ---------------------------------------------------------------------------
# Default wiring
# ---------------------------------------------------------------------------

def test_orchestrator_auto_wires_zero_day_pipeline_with_ai_backend():
    """When an AI backend is supplied and no 0-day components are
    injected, the orchestrator creates default proposer/builder/runner
    instances so the optional 0-day tail is functional."""
    from core.orchestrator.autonomous_orchestrator import AutonomousOrchestrator
    from core.ai_backend.zero_day import ZeroDayProposer
    from core.ai_backend.zero_day_exploit import (
        ZeroDayExploitBuilder,
        ZeroDayExploitRunner,
    )

    class FakeAI:
        def query(self, *a, **k):
            return "{}"

    orch = AutonomousOrchestrator(
        ai_backend=FakeAI(),
        confirm_fn=lambda p: True,
    )
    assert isinstance(orch.zero_day_proposer, ZeroDayProposer)
    assert isinstance(orch.zero_day_exploit_builder, ZeroDayExploitBuilder)
    assert isinstance(orch.zero_day_exploit_runner, ZeroDayExploitRunner)


def test_orchestrator_does_not_wire_zero_day_without_ai_backend():
    """Without an AI backend, the optional 0-day pipeline stays None so
    the tail is skipped gracefully (no failures)."""
    from core.orchestrator.autonomous_orchestrator import AutonomousOrchestrator
    orch = AutonomousOrchestrator(confirm_fn=lambda p: True)
    assert orch.zero_day_proposer is None
    assert orch.zero_day_exploit_builder is None
    assert orch.zero_day_exploit_runner is None


# ---------------------------------------------------------------------------
# End-to-end heuristic chain shape
# ---------------------------------------------------------------------------

def test_heuristic_wifi_e2e_with_tail_optional_flag(monkeypatch):
    """End-to-end: the auto-appended zero-day tail's 3 steps are
    all marked ``optional: True`` so the orchestrator's per-step
    ACCEPT gate is the only operator control."""
    monkeypatch.setenv("KFIOSA_ZERO_DAY_TAIL_AUTO", "1")
    from core.ai_backend.chain import _heuristic_for_domain
    chain = _heuristic_for_domain(
        "wifi",
        {"bssid": "AA:BB:CC:DD:EE:FF", "channel": 6, "encryption": "wpa2"},
    )
    tail = chain[-3:]
    for step in tail:
        assert step.get("optional") is True
        assert step.get("rationale", "").startswith("OPTIONAL")
    # Each step has a risk_level
    for step in tail:
        assert step.get("risk_level") in ("read", "intrusive", "destructive")
    # The execute step is destructive
    assert tail[-1]["risk_level"] == "destructive"
