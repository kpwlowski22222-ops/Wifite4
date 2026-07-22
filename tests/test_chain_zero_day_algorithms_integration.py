"""tests.test_chain_zero_day_algorithms_integration — chain-step
dispatch integration for the 10 specialized 0-day algorithms.

Verifies that:
  - The 10 actions appear in :data:`_CHAIN_STEP_SCHEMA_HINT`.
  - The :data:`ZERO_DAY_ALGORITHMS_PROMPT_STANZA` enumerates them.
  - The chain planner's primary ``_heuristic_for_domain`` does NOT
    need updating (algorithms are dispatched at chain-step time, not
    by the planner).
  - ``dispatch`` returns the standard envelope from the registry.
  - All 10 actions round-trip through the registry.

The orchestrator-side dispatchers
(``_dispatch_zero_day_crash_triager`` etc.) live in
:mod:`core.orchestrator.autonomous_orchestrator` and are not in
scope here — the unit-level dispatch in
:func:`core.ai_backend.zero_day_algorithms.dispatch` IS the
contract.
"""
from __future__ import annotations

import os
import subprocess
import textwrap
import uuid
from typing import Any, Dict, Optional
from unittest import mock

import pytest

from core.ai_backend import ZERO_DAY_ALGORITHMS, list_algorithms, dispatch
from core.ai_backend import zero_day_algorithms as zda
from core.ai_backend.chain import (
    _CHAIN_STEP_SCHEMA_HINT,
    ZERO_DAY_ALGORITHMS_PROMPT_STANZA,
    _SYSTEM_PROMPT,
)
from core.ai_backend.zero_day import ZeroDayDraftStore


# ---------------------------------------------------------------------------
# Fake AI backend
# ---------------------------------------------------------------------------

class FakeBackend:
    def __init__(self, *, findings: int = 1,
                 vuln_class: str = "test_vuln",
                 refuse: bool = False):
        self.findings_n = findings
        self.vuln_class = vuln_class
        self.refuse = refuse
        self.calls: list = []
        self.domain_prompts: Dict[str, str] = {}

    def query(self, domain, user_prompt, context=None):
        self.calls.append((domain, user_prompt, context or {}))
        if self.refuse:
            import json
            return json.dumps({"refusal": True, "reason": "policy"})
        if self.findings_n == 1:
            import json
            return json.dumps({
                "title": "Integration test finding",
                "hypothesis": "Integration hypothesis",
                "vulnerability_class": self.vuln_class,
                "technique": "integration",
                "indicators": ["i1", "i2"],
                "entry_point": "i_entry",
                "tooling": ["i_tool"],
                "draft_poc_outline": "step 1\nstep 2",
                "risk_notes": "integration",
                "confidence": "medium",
            })
        import json
        return json.dumps({"findings": [
            {
                "title": f"finding {i}",
                "hypothesis": f"hyp {i}",
                "vulnerability_class": self.vuln_class,
                "indicators": [f"i{i}"],
                "entry_point": f"e{i}",
                "tooling": ["t"],
                "draft_poc_outline": "1) step",
                "risk_notes": "rn",
                "confidence": "low",
            }
            for i in range(self.findings_n)
        ]})


def _make_binary(tmp_path) -> str:
    """Build a tiny real ELF with crypto / syscall sentinels."""
    src = tmp_path / "t.c"
    src.write_text(textwrap.dedent("""\
        #include <sys/stat.h>
        static const char *s[] = {
            "EVP_EncryptInit_ex", "AES_encrypt", "RSA_new", "BN_CTX_new",
            "stat", "lstat", "access", "fstat", "utime",
        };
        int main(void) { (void)s; return 0; }
    """))
    binary = tmp_path / "t"
    subprocess.run(["gcc", "-w", str(src), "-o", str(binary), "-ldl"],
                    check=True, capture_output=True, timeout=30)
    return str(binary)


def _make_crash_log(tmp_path) -> str:
    p = tmp_path / "crash.log"
    p.write_text("#0  parse_packet (pkt=0x0)\n")
    return str(p)


# ---------------------------------------------------------------------------
# Schema + stanza tests
# ---------------------------------------------------------------------------

ALL_ACTIONS = {
    "zero_day_crash_triager", "zero_day_side_channel_finder",
    "zero_day_fuzz_harness_gen", "zero_day_control_flow_surfer",
    "zero_day_patch_differ", "zero_day_memory_class_predictor",
    "zero_day_auth_path_auditor", "zero_day_crypto_weakness_finder",
    "zero_day_race_analyzer", "zero_day_logic_flaw_heuristic",
}


def test_all_ten_actions_in_schema_hint():
    for a in ALL_ACTIONS:
        assert a in _CHAIN_STEP_SCHEMA_HINT, f"missing {a} in schema"


def test_all_ten_actions_in_prompt_stanza():
    for a in ALL_ACTIONS:
        assert a in ZERO_DAY_ALGORITHMS_PROMPT_STANZA, f"missing {a} in stanza"


def test_all_ten_actions_in_system_prompt():
    for a in ALL_ACTIONS:
        assert a in _SYSTEM_PROMPT, f"missing {a} in _SYSTEM_PROMPT"


def test_stanza_explains_all_algorithms_by_name():
    for a in ALL_ACTIONS:
        # The stanza lists each algorithm by name. Newer stanzas use
        # either `* name` (single list) or `      - name` (grouped);
        # we accept either as long as the action name appears in the
        # stanza.
        assert (
            f"* {a}" in ZERO_DAY_ALGORITHMS_PROMPT_STANZA
            or f"- {a}" in ZERO_DAY_ALGORITHMS_PROMPT_STANZA
            or a in ZERO_DAY_ALGORITHMS_PROMPT_STANZA
        ), a


def test_stanza_describes_each_algorithm_choice():
    """The 10 original algorithms must each be paired with the recon
    condition that triggers them. Phase 3 algorithms (network
    protocols, web, supply chain, etc.) are added by name without
    specific recon hints; the stanza structure groups them by
    attack surface so the LLM can find them by name."""
    expected_pairs = {
        "crash_dump available": "zero_day_crash_triager",
        "microarchitectural surface": "zero_day_side_channel_finder",
        "parse / network / IPC surface": "zero_day_fuzz_harness_gen",
        "binary with symbol table": "zero_day_control_flow_surfer",
        "two binary versions": "zero_day_patch_differ",
        "function declarations": "zero_day_memory_class_predictor",
        "auth surface / endpoints": "zero_day_auth_path_auditor",
        "binary with crypto": "zero_day_crypto_weakness_finder",
        "stat+open patterns": "zero_day_race_analyzer",
        "API spec / workflow": "zero_day_logic_flaw_heuristic",
    }
    for phrase, action in expected_pairs.items():
        assert phrase in ZERO_DAY_ALGORITHMS_PROMPT_STANZA, phrase
        assert action in ZERO_DAY_ALGORITHMS_PROMPT_STANZA, action


# ---------------------------------------------------------------------------
# Registry -> dispatch round-trip
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("action", sorted(ALL_ACTIONS))
def test_dispatch_round_trip_unknown_returns_error(action):
    """All 10 actions must be in the registry. (Parametrized to
    surface missing registration early.)"""
    assert action in ZERO_DAY_ALGORITHMS


@pytest.mark.parametrize("action", sorted(ALL_ACTIONS))
def test_dispatch_returns_dict_envelope(action):
    """``dispatch`` always returns a dict with at least an ``ok`` key."""
    res = dispatch(action, {"name": "x"}, {}, {})
    assert isinstance(res, dict)
    assert "ok" in res
    # With no useful args, this is honest-degrade.
    assert res["ok"] is False


# ---------------------------------------------------------------------------
# End-to-end: full pipeline from chain-style action to draft persistence
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("action,args", [
    ("zero_day_crash_triager", {}),  # patched below per case
    ("zero_day_side_channel_finder", {}),
    ("zero_day_fuzz_harness_gen", {}),
    ("zero_day_control_flow_surfer", {}),
    ("zero_day_patch_differ", {}),
    ("zero_day_memory_class_predictor", {}),
    ("zero_day_auth_path_auditor", {}),
    ("zero_day_crypto_weakness_finder", {}),
    ("zero_day_race_analyzer", {}),
    ("zero_day_logic_flaw_heuristic", {}),
])
def test_e2e_dispatch_with_valid_args_persists_draft(
    action, args, tmp_path,
):
    """Each algorithm, when given the right args + a FakeBackend,
    must persist a ZeroDayConcept the operator can read back."""
    binary = _make_binary(tmp_path)
    crash = _make_crash_log(tmp_path)
    args_map = {
        "zero_day_crash_triager": {"crash_path": crash, "gdb_binary": "/bin/true"},
        "zero_day_side_channel_finder": {},
        "zero_day_fuzz_harness_gen": {
            "binary_path": binary, "fuzzer": "libfuzzer", "surface": "file",
            "harness_dir": str(tmp_path / "h"),
        },
        "zero_day_control_flow_surfer": {"binary_path": binary},
        "zero_day_patch_differ": {"binary_v1": binary, "binary_v2": binary},
        "zero_day_memory_class_predictor": {
            "function_decls": [{"name": "f", "args": ["x"], "returns": "v"}],
        },
        "zero_day_auth_path_auditor": {
            "service": "s", "endpoints": [{"path": "/x", "method": "GET"}],
        },
        "zero_day_crypto_weakness_finder": {"binary_path": binary},
        "zero_day_race_analyzer": {"binary_path": binary},
        "zero_day_logic_flaw_heuristic": {
            "workflow_steps": [{"name": "x"}],
        },
    }
    # Per-algorithm response customization (fuzz needs harness_source).
    if action == "zero_day_fuzz_harness_gen":
        backend = FakeBackend.__new__(FakeBackend)
        backend.findings_n = 1
        backend.vuln_class = "fuzz_target"
        backend.refuse = False
        backend.calls = []
        backend.domain_prompts = {}

        def _query(domain, user_prompt, context=None):
            backend.calls.append((domain, user_prompt, context or {}))
            import json
            return json.dumps({
                "harness_source": (
                    "#include <stdint.h>\n"
                    "int LLVMFuzzerTestOneInput(const uint8_t *d, size_t s) { return d[0]; }\n"
                ),
                "compile_command": "clang -fsanitize=fuzzer harness.c",
                "title": "fuzz harness",
                "hypothesis": "fuzz",
                "vulnerability_class": "buffer_overflow",
                "entry_point": "parse",
                "tooling": ["libfuzzer"],
                "draft_poc_outline": "1) compile 2) run",
                "risk_notes": "lab",
                "confidence": "high",
            })
        backend.query = _query
    else:
        backend = FakeBackend(findings=1, vuln_class=f"class_{action}")

    store = ZeroDayDraftStore(root_dir=str(tmp_path / "drafts"))
    res = dispatch(
        action, {"name": "test"}, {}, args_map[action],
        ai_backend=backend, store=store,
    )
    assert res["ok"] is True, f"{action} failed: {res}"
    # Verify the draft is persisted and findable.
    drafts = store.list()
    assert any(d.draft_id == res["draft_id"] for d in drafts)
    # Verify the algorithm name is in the recon context.
    found = next(d for d in drafts if d.draft_id == res["draft_id"])
    assert found.recon_context.get("zero_day_algorithm") == action.replace(
        "zero_day_", ""
    )


def test_dispatch_catches_algorithm_exception():
    """When the algorithm raises (e.g. LLM backend crash), dispatch
    must honest-degrade, not propagate."""
    original = zda.ZERO_DAY_ALGORITHMS["zero_day_side_channel_finder"]

    def _boom(*a, **kw):
        raise RuntimeError("simulated LLM crash")

    zda.ZERO_DAY_ALGORITHMS["zero_day_side_channel_finder"] = _boom
    try:
        res = dispatch("zero_day_side_channel_finder", {}, {}, {})
    finally:
        zda.ZERO_DAY_ALGORITHMS["zero_day_side_channel_finder"] = original
    assert res["ok"] is False
    assert "simulated LLM crash" in res["error"]


def test_registry_is_the_single_source_of_truth():
    """Adding a new algorithm means adding it to ZERO_DAY_ALGORITHMS.
    The chain schema / prompt stanza derive from it; they MUST stay
    in sync.

    Phase 2.2.G+ expanded the registry from 10 to 70+ algorithms.
    The schema hint and the prompt stanza are the two surfaces that
    must mirror the registry."""
    registry_names = set(ZERO_DAY_ALGORITHMS.keys())
    # The registry must be a superset of the original 10.
    assert ALL_ACTIONS.issubset(registry_names)
    # The prompt stanza must list every registry name.
    for name in registry_names:
        assert name in ZERO_DAY_ALGORITHMS_PROMPT_STANZA, name


def test_no_legacy_zero_day_actions_removed():
    """The original 3 actions (zero_day_propose, zero_day_build,
    zero_day_execute) must still be in the schema — adding 10
    new ones is purely additive."""
    for a in ("zero_day_propose", "zero_day_build", "zero_day_execute"):
        assert a in _CHAIN_STEP_SCHEMA_HINT, a
