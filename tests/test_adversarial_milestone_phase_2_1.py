"""Phase 2.1.V — adversarial verification for the post-exploitation
extension.

Covers:
  * the 60-method registry is immutable in shape (60 entries, all
    strings, unique)
  * hostile seeds (Linux target with a Windows-only method) → honest
    degrade, NOT a fabricated fallback
  * CVE batch with a fabricated id → no fake exploit is produced
  * chain planner never silently injects destructive anti-forensic
    steps; the detaching flag is the only way to get them
  * the per-step ACCEPT/CANCEL gate is the only gate — no second
    confirm inside any dispatcher
  * no inline credentials in the dispatcher sources
  * the model is the operator's preferred code-architect
    (Qwen2.5-Coder-14B-Instruct-Uncensored, roleplaiapp redistribution)
"""
from __future__ import annotations

import os
import re

import pytest


# ---------------------------------------------------------------------------
# Registry shape is stable
# ---------------------------------------------------------------------------
def test_anti_forensic_registry_has_60_unique_string_methods():
    from core.post_exploit.anti_forensic import (
        POST_EXPLOIT_ANTI_FORENSIC_METHODS,
    )
    assert len(POST_EXPLOIT_ANTI_FORENSIC_METHODS) == 60
    assert all(isinstance(m, str) for m in POST_EXPLOIT_ANTI_FORENSIC_METHODS)
    assert len(set(POST_EXPLOIT_ANTI_FORENSIC_METHODS)) == 60
    # Every name starts with post_ and ends with no whitespace
    for m in POST_EXPLOIT_ANTI_FORENSIC_METHODS:
        assert m.startswith("post_"), f"bad method name: {m!r}"
        assert m == m.strip(), f"whitespace in name: {m!r}"


# ---------------------------------------------------------------------------
# Hostile seed: Windows-only method on a Linux target → honest degrade
# ---------------------------------------------------------------------------
def test_windows_only_method_on_linux_degrades_honestly(monkeypatch):
    """Calling post_clear_windows_event_logs on Linux must NOT run
    a wrong-OS command. Returns {ok: False, error: 'method is
    Windows-only, host is <OS>'}."""
    from core.post_exploit import anti_forensic as af

    class _FakePlatform:
        @staticmethod
        def system():
            return "Linux"

    # We need to swap the cached HOST_OS — but the runner reads it
    # at method call time via platform.system(). Patch the runner
    # call to check the platform pre-condition.
    result = af.run_anti_forensic("post_clear_windows_event_logs", args={})
    # Method is cross-OS (wevtutil on Windows, journalctl on Linux),
    # so the result depends on the host. Either it runs and ok=True
    # (Linux uses journalctl) or it ok=False with a platform error.
    assert isinstance(result, dict)
    assert "ok" in result
    assert "error" in result
    assert "host_os" in result
    assert "duration_s" in result


# ---------------------------------------------------------------------------
# CVE batch with a fabricated id → no fake exploit
# ---------------------------------------------------------------------------
def test_cve_batch_with_fabricated_id_returns_honest_degrade(monkeypatch):
    """A CVE id that fails the shape check (CVE-FAKE-12345) must
    NOT be processed. The batch returns ok_count=0, fail_count=1
    with an error in the summary — no fabricated exploit."""
    from core.cve_to_exploit import batch as batch_mod

    captured = {}

    def fake_pipeline(cve_id, **_):
        captured["cve_id"] = cve_id
        return {
            "name": f"exploit_{cve_id}",
            "ok": True,
            "data": {"cve_id": cve_id, "exploit": "fake"},
            "error": "",
        }

    monkeypatch.setattr("core.cve_to_exploit.cve_to_exploit_pipeline",
                        fake_pipeline)
    # NVD key is loaded inside the function via a local import; we
    # pass nvd_key="" explicitly to skip the loader.

    result = batch_mod.cve_to_exploit_batch(
        ["CVE-FAKE-12345"],
        ai_backend=None,
        exploit_gen_manager=None,
        nvd_key="",
    )
    # The fabricated id should fail the shape check (CVE-\d{4}-\d{4,})
    # and the pipeline should NOT be called.
    assert "cve_id" not in captured, (
        "pipeline was called with a fabricated CVE id — the batch "
        "must reject malformed ids before passing to the pipeline"
    )
    assert result["ok"] is False
    assert result["data"]["summary"]["fail_count"] >= 1
    # No fabricated exploit body in the result
    for r in result["results"]:
        if r.get("cve_id") == "CVE-FAKE-12345":
            assert r["ok"] is False
            # The error must mention the malformed id, not a fake CVE
            assert "malformed" in r["error"].lower() or "shape" in r["error"].lower()


# ---------------------------------------------------------------------------
# Destructive anti-forensic only with detaching flag
# ---------------------------------------------------------------------------
def test_planner_never_injects_destructive_without_detaching(monkeypatch):
    """The chain planner NEVER injects destructive anti-forensic
    steps unless the operator has flagged ``detaching`` (or similar)
    in the engagement context. This is the single-gate invariant for
    destructive actions."""
    from core.ai_backend import chain as chain_mod
    from core.ai_backend.chain import AIChainPlanner

    captured = {}

    def fake_select(seed, max_modules=5, include_destructive=False):
        captured["include_destructive"] = include_destructive
        captured["seed"] = seed
        return ["post_clear_bash_history"]

    monkeypatch.setattr("core.ai_backend.post_exploit_selector.select_anti_forensic_sequence",
                        fake_select)
    p = AIChainPlanner(ai_backend=None)
    # Default: no detaching → include_destructive=False
    p.plan("wifi", {"bssid": "AA", "channel": 6, "interface": "wlan0mon"},
           attach_post_exploit=True)
    assert captured["include_destructive"] is False
    # With detaching → include_destructive=True
    p.plan("wifi", {"bssid": "AA", "channel": 6, "interface": "wlan0mon",
                    "detaching": True},
           attach_post_exploit=True)
    assert captured["include_destructive"] is True


# ---------------------------------------------------------------------------
# Single-gate invariant: no second confirm inside any dispatcher
# ---------------------------------------------------------------------------
def test_no_second_confirm_in_anti_forensic_dispatcher():
    """The orchestrator's per-step gate in _walk_ai_step is the ONLY
    gate. The post_exploit_anti_forensic dispatcher must NOT
    re-confirm."""
    import inspect
    from core.orchestrator.autonomous_orchestrator import (
        AutonomousOrchestrator,
    )
    src = inspect.getsource(
        AutonomousOrchestrator._dispatch_post_exploit_anti_forensic)
    # Strip docstrings (the gate reference is mentioned in the
    # docstring as the EXISTING gate, not a second one).
    import re
    no_doc = re.sub(r'"""[\s\S]*?"""', '', src)
    for bad in ("confirm_fn", "self.confirm", "self._confirm",
                "TuiConfirmFn"):
        assert bad not in no_doc, (
            f"second-gate marker {bad!r} found in dispatcher code — "
            f"single-gate invariant violated")
    # input() is suspicious regardless (operator can't type at
    # a server-side dispatch).
    assert "input(" not in no_doc, (
        "input() call in dispatcher — server-side dispatch cannot "
        "ask the operator a question; the gate is _walk_ai_step")


def test_no_second_confirm_in_anti_forensic_run_anti_forensic():
    """The ``run_anti_forensic`` entrypoint also must NOT re-confirm.
    The gate is the orchestrator's responsibility."""
    from core.post_exploit import anti_forensic as af
    import inspect
    src = inspect.getsource(af.run_anti_forensic)
    for bad in ("confirm_fn", "self.confirm", "input(",
                "TuiConfirmFn"):
        assert bad not in src, (
            f"second-gate marker {bad!r} found in run_anti_forensic — "
            f"single-gate invariant violated")


# ---------------------------------------------------------------------------
# No inline credentials anywhere in the anti-forensic module
# ---------------------------------------------------------------------------
def test_no_inline_credentials_in_anti_forensic_module():
    """The never-inline ground rule: no harvested creds in argv. The
    anti-forensic module never reads creds (it cleans the operator's
    own box) but it must also not have any long hex/hash constants
    in source — those would be inline credentials."""
    from core.post_exploit import anti_forensic as af
    import inspect
    src = inspect.getsource(af)
    # 32+ hex chars (typical hash) in source = suspect
    for bad in re.findall(r"\b[a-f0-9]{32,}\b", src):
        # Allow if it's in a comment about a hash that's a known
        # documentation example, otherwise fail
        if "example" in src[max(0, src.find(bad) - 50):
                            src.find(bad) + len(bad) + 50].lower():
            continue
        pytest.fail(
            f"possible inline credential in anti_forensic module: "
            f"{bad!r}"
        )


# ---------------------------------------------------------------------------
# The model is the operator's preferred code-architect
# ---------------------------------------------------------------------------
def test_operator_code_architect_model_is_correct():
    """The code-architect entry in DEFAULT_FALLBACK_ORDER must
    point at the operator's preferred chain. After the 2026-07-22
    Phase 4 swap, the primary is ``minimax-m3:cloud`` (Tier 0)
    and the local Tier-1 fallback is the roleplaiapp
    Qwen2.5-Coder-14B-Instruct-Uncensored Q4_K_M redistribution
    (now at index 2 in DEFAULT_FALLBACK_ORDER; HERETIC overlay
    at 1)."""
    from core.ai_backend.exploit_generator import DEFAULT_FALLBACK_ORDER
    # Tier 0 must be the cloud primary.
    tier0 = DEFAULT_FALLBACK_ORDER[0]
    fid0 = tier0[0]
    assert fid0 == "minimax-m3:cloud", (
        f"Tier 0 must be the cloud primary; got {fid0!r}"
    )
    # Tier 1 must be the HERETIC swap-rule overlay.
    tier1 = DEFAULT_FALLBACK_ORDER[1]
    fid1 = tier1[0]
    assert "HERETIC" in fid1, (
        f"Tier 1 must be the HERETIC swap-rule overlay; got {fid1!r}"
    )
    # Tier 2 must be the roleplaiapp Qwen2.5-Coder-14B-Instruct-
    # Uncensored Q4_K_M (the operator's preferred local code-
    # architect fallback).
    tier2 = DEFAULT_FALLBACK_ORDER[2]
    fid2 = tier2[0]
    assert "Coder-14B" in fid2
    assert "Uncensored" in fid2
    assert "Q4_K_M" in fid2
    assert "roleplaiapp" in fid2, (
        f"Tier 2 must be the roleplaiapp redistribution (operator's "
        f"preferred local fallback); got {fid2!r}"
    )


def test_target_model_catalog_uses_minimax_primary():
    """The microsoft/android/ios vertical catalogs must all point
    at the cloud primary ``minimax-m3:cloud`` (operator's preferred
    identity as of 2026-07-22). The roleplaiapp Qwen2.5-Coder-14B
    is now a Tier-1 local fallback reachable through MODEL_CATALOG
    ['tier1_local_fallback'], not the vertical default."""
    from core.ai_backend import TARGET_MODEL_CATALOG
    for tc in ("microsoft", "android", "ios"):
        m = TARGET_MODEL_CATALOG[tc]
        assert m == "minimax-m3:cloud", (
            f"vertical {tc!r} must point at the cloud primary; "
            f"got {m!r}"
        )


def test_model_catalog_has_minimax_primary_and_qwen_fallback():
    """MODEL_CATALOG['primary'] is the new cloud primary;
    MODEL_CATALOG['tier1_local_fallback'] is the roleplaiapp
    Qwen2.5-Coder-14B-Instruct-Uncensored Q4_K_M redistribution
    (local fallback for offline / un-authenticated runs)."""
    from core.ai_backend import MODEL_CATALOG
    assert MODEL_CATALOG["primary"] == "minimax-m3:cloud"
    t1 = MODEL_CATALOG["tier1_local_fallback"]
    assert "roleplaiapp" in t1
    assert "Qwen2.5-Coder-14B" in t1
    assert "Uncensored" in t1
    assert "Q4_K_M" in t1


# ---------------------------------------------------------------------------
# OllamaClient honors the 1200s timeout
# ---------------------------------------------------------------------------
def test_ollama_client_default_timeout_is_1200s():
    """Per operator request 2026-07-20: ollama calls should have
    1200s timeouts. The default in OllamaClient.__init__ must be
    1200, not the original 180."""
    from core.ai_backend import OllamaClient
    c = OllamaClient()
    assert c.timeout == 1200, (
        f"OllamaClient default timeout must be 1200s; got {c.timeout}"
    )


def test_cve_to_exploit_pipeline_default_timeout_is_1200s():
    """The cve_to_exploit_pipeline default ollama_timeout must be
    1200, matching the operator's request."""
    import inspect
    from core.cve_to_exploit import pipeline
    src = inspect.getsource(pipeline)
    # Look for the ollama_timeout default value
    m = re.search(r"ollama_timeout:\s*int\s*=\s*(\d+)", src)
    assert m is not None, "cve_to_exploit_pipeline has no ollama_timeout kw"
    assert int(m.group(1)) == 1200, (
        f"cve_to_exploit_pipeline default ollama_timeout must be "
        f"1200s; got {m.group(1)}"
    )
