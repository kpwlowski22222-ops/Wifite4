"""ZeroDayProposer + ZeroDayDraftStore — concept drafting, persistence, ack/reject."""

import json
import os
import tempfile

import pytest

from core.ai_backend.zero_day import (
    ZeroDayConcept, ZeroDayDraftStore, ZeroDayProposer,
    ZeroDayRefusal, ack_draft, reject_draft,
)


# ----------------------------------------------------------------------
# Concept validation
# ----------------------------------------------------------------------

def _valid_kwargs():
    return dict(
        title="cmd injection in /cgi-bin/luci",
        hypothesis="admin password concatenated into shell call unescaped",
        vulnerability_class="command injection",
        technique="fuzzing + source review",
        indicators=["/cgi-bin/luci", "admin_pwd", "/bin/sh"],
        entry_point="httpd request handler",
        tooling=["ffuf", "gdb", "radare2"],
        draft_poc_outline="1) Map endpoints 2) Inject `;id` 3) Capture shell",
        risk_notes="May brick device",
        cve_hint="CVE-2027-12345",
        confidence="medium",
    )


def test_concept_is_valid_when_complete():
    c = ZeroDayConcept(draft_id="x", target={"bssid": "AA"}, **_valid_kwargs())
    assert c.is_valid()


def test_concept_invalid_when_title_empty():
    c = ZeroDayConcept(draft_id="x", target={"bssid": "AA"},
                       **{**_valid_kwargs(), "title": ""})
    assert not c.is_valid()


def test_concept_invalid_when_hypothesis_empty():
    c = ZeroDayConcept(draft_id="x", target={"bssid": "AA"},
                       **{**_valid_kwargs(), "hypothesis": ""})
    assert not c.is_valid()


def test_concept_invalid_when_target_empty():
    c = ZeroDayConcept(draft_id="x", target={}, **_valid_kwargs())
    assert not c.is_valid()


def test_concept_invalid_when_class_or_outline_empty():
    for empty_field in ("vulnerability_class", "technique", "draft_poc_outline"):
        c = ZeroDayConcept(draft_id="x", target={"bssid": "AA"},
                           **{**_valid_kwargs(), empty_field: ""})
        assert not c.is_valid(), f"should be invalid when {empty_field} empty"


# ----------------------------------------------------------------------
# Draft store — round-trip
# ----------------------------------------------------------------------

def test_store_save_and_get_round_trip():
    with tempfile.TemporaryDirectory() as td:
        store = ZeroDayDraftStore(root_dir=os.path.join(td, "drafts"))
        c = ZeroDayConcept(draft_id="abc", target={"bssid": "AA"},
                           **_valid_kwargs())
        store.save(c)
        loaded = store.get("abc")
        assert loaded is not None
        assert loaded.title == c.title
        assert loaded.indicators == c.indicators
        assert loaded.status == "pending"


def test_store_get_missing_returns_none():
    with tempfile.TemporaryDirectory() as td:
        store = ZeroDayDraftStore(root_dir=os.path.join(td, "drafts"))
        assert store.get("does-not-exist") is None


def test_store_list_filters_by_status():
    with tempfile.TemporaryDirectory() as td:
        store = ZeroDayDraftStore(root_dir=os.path.join(td, "drafts"))
        for i, status in enumerate(["pending", "acked", "rejected"]):
            c = ZeroDayConcept(draft_id=f"d{i}", target={"bssid": "AA"},
                               **_valid_kwargs())
            c.status = status
            store.save(c)
        assert len(store.list("pending")) == 1
        assert len(store.list("acked")) == 1
        assert len(store.list("rejected")) == 1
        assert len(store.list()) == 3


# ----------------------------------------------------------------------
# ack / reject
# ----------------------------------------------------------------------

def test_ack_draft_flips_status_and_sets_timestamp():
    with tempfile.TemporaryDirectory() as td:
        store = ZeroDayDraftStore(root_dir=os.path.join(td, "drafts"))
        c = ZeroDayConcept(draft_id="x", target={"bssid": "AA"},
                           **_valid_kwargs())
        store.save(c)
        acked = ack_draft(store, "x")
        assert acked is not None
        assert acked.status == "acked"
        assert acked.acked_at is not None
        assert acked.acked_at > 0
        # Persisted
        reloaded = store.get("x")
        assert reloaded.status == "acked"


def test_ack_draft_missing_returns_none():
    with tempfile.TemporaryDirectory() as td:
        store = ZeroDayDraftStore(root_dir=os.path.join(td, "drafts"))
        assert ack_draft(store, "nope") is None


def test_reject_draft_records_reason():
    with tempfile.TemporaryDirectory() as td:
        store = ZeroDayDraftStore(root_dir=os.path.join(td, "drafts"))
        c = ZeroDayConcept(draft_id="x", target={"bssid": "AA"},
                           **_valid_kwargs())
        store.save(c)
        rejected = reject_draft(store, "x", reason="out of scope")
        assert rejected is not None
        assert rejected.status == "rejected"
        assert rejected.rejected_reason == "out of scope"


def test_reject_draft_default_reason():
    with tempfile.TemporaryDirectory() as td:
        store = ZeroDayDraftStore(root_dir=os.path.join(td, "drafts"))
        c = ZeroDayConcept(draft_id="x", target={"bssid": "AA"},
                           **_valid_kwargs())
        store.save(c)
        rejected = reject_draft(store, "x")
        assert rejected.rejected_reason == "operator cancelled"


# ----------------------------------------------------------------------
# Proposer
# ----------------------------------------------------------------------

class FakeAIBackend:
    def __init__(self, responses=None, raises=False):
        self.responses = list(responses or [])
        self.domain_prompts = {}
        self.calls = 0
        self.raise_on_call = raises

    def query(self, domain, prompt, context=None):
        self.calls += 1
        if self.raise_on_call:
            raise RuntimeError("ollama down")
        if self.responses:
            return self.responses.pop(0)
        return json.dumps(_valid_kwargs())


def test_proposer_no_backend_raises_runtime_error():
    p = ZeroDayProposer(ai_backend=None)
    with pytest.raises(RuntimeError) as e:
        p.propose({"bssid": "AA"})
    assert "no AI backend" in str(e.value)


def test_proposer_creates_pending_draft():
    with tempfile.TemporaryDirectory() as td:
        store = ZeroDayDraftStore(root_dir=os.path.join(td, "drafts"))
        backend = FakeAIBackend()
        p = ZeroDayProposer(ai_backend=backend, store=store)
        concept = p.propose(
            target={"bssid": "AA", "essid": "TestNet"},
            recon={"vendor": "TP-Link", "firmware": "3.14"},
        )
        assert concept.status == "pending"
        assert concept.title == "cmd injection in /cgi-bin/luci"
        # Persisted
        loaded = store.get(concept.draft_id)
        assert loaded is not None
        assert loaded.recon_context == {"vendor": "TP-Link", "firmware": "3.14"}


def test_proposer_refusal_raises_zeroday_refusal():
    with tempfile.TemporaryDirectory() as td:
        store = ZeroDayDraftStore(root_dir=os.path.join(td, "drafts"))
        backend = FakeAIBackend(responses=[
            json.dumps({"refusal": True, "reason": "recon too thin"}),
        ])
        p = ZeroDayProposer(ai_backend=backend, store=store)
        with pytest.raises(ZeroDayRefusal) as e:
            p.propose({"bssid": "AA"}, recon={"vendor": "?"})
        assert "recon too thin" in str(e.value)


def test_proposer_empty_response_raises_refusal():
    with tempfile.TemporaryDirectory() as td:
        store = ZeroDayDraftStore(root_dir=os.path.join(td, "drafts"))
        backend = FakeAIBackend(responses=[""])
        p = ZeroDayProposer(ai_backend=backend, store=store)
        with pytest.raises(ZeroDayRefusal):
            p.propose({"bssid": "AA"})


def test_proposer_non_json_raises_refusal():
    with tempfile.TemporaryDirectory() as td:
        store = ZeroDayDraftStore(root_dir=os.path.join(td, "drafts"))
        backend = FakeAIBackend(responses=["totally not json"])
        p = ZeroDayProposer(ai_backend=backend, store=store)
        with pytest.raises(ZeroDayRefusal) as e:
            p.propose({"bssid": "AA"})
        assert "non-JSON" in str(e.value)


def test_proposer_strips_code_fence():
    with tempfile.TemporaryDirectory() as td:
        store = ZeroDayDraftStore(root_dir=os.path.join(td, "drafts"))
        body = json.dumps(_valid_kwargs())
        backend = FakeAIBackend(responses=[f"```json\n{body}\n```"])
        p = ZeroDayProposer(ai_backend=backend, store=store)
        concept = p.propose({"bssid": "AA"})
        assert concept.title == "cmd injection in /cgi-bin/luci"


def test_proposer_invalid_concept_raises_refusal():
    """If the AI returns JSON missing required fields, refuse rather
    than persist a half-baked draft."""
    with tempfile.TemporaryDirectory() as td:
        store = ZeroDayDraftStore(root_dir=os.path.join(td, "drafts"))
        backend = FakeAIBackend(responses=[
            json.dumps({"title": "x"}),  # missing everything else
        ])
        p = ZeroDayProposer(ai_backend=backend, store=store)
        with pytest.raises(ZeroDayRefusal) as e:
            p.propose({"bssid": "AA"})
        assert "missing required fields" in str(e.value)
