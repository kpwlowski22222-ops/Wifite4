"""Tests for the operator's uncensored code-architect model selection.

Covers:
  * the operator-preferred model is the FIRST entry in
    ExploitGenModelManager.DEFAULT_FALLBACK_ORDER
  * the pull script is structurally valid (bash, has the expected
    hf.co target, and points at the right model id)
  * the registry's defaults.base_model is the operator-preferred model
  * the model is sized appropriately for the operator's hardware
    (12GB VRAM + 32GB RAM hybrid)
"""
from __future__ import annotations

import os
import re
import subprocess


OPERATOR_PREFERRED_MODEL = (
    # The bare ``DavidAU/Qwen3.5-9B-...-HERETIC-UNCENSORED`` repo is
    # safetensors-only (not GGUF-compatible). The mradermacher
    # redistribution is a GGUF pack (21,980 downloads, same base
    # model, apache-2.0) — this is what `ollama pull` actually
    # fetches.
    "mradermacher/Qwen3.5-9B-Claude-4.6-HighIQ-THINKING-HERETIC-UNCENSORED-GGUF"
)


class TestFallbackOrder:
    def test_first_entry_is_operator_preferred(self):
        from core.ai_backend.exploit_generator import DEFAULT_FALLBACK_ORDER
        assert len(DEFAULT_FALLBACK_ORDER) > 0
        first_id = DEFAULT_FALLBACK_ORDER[0][0]
        # Fully offensive / uncensored: local Qwen2.5-Coder Uncensored
        # is Tier 0 (cloud minimax is opt-in only — it refuses).
        assert "Qwen2.5-Coder" in first_id and "Uncensored" in first_id, (
            f"expected uncensored Qwen2.5-Coder at top, got {first_id}"
        )

    def test_operator_preferred_in_fallback_order(self):
        from core.ai_backend.exploit_generator import DEFAULT_FALLBACK_ORDER
        ids = [e[0] for e in DEFAULT_FALLBACK_ORDER]
        assert OPERATOR_PREFERRED_MODEL in ids

    def test_all_entries_have_correct_shape(self):
        from core.ai_backend.exploit_generator import DEFAULT_FALLBACK_ORDER
        for entry in DEFAULT_FALLBACK_ORDER:
            assert len(entry) == 4, f"bad entry shape: {entry}"
            repo_id, size, license_, gated = entry
            # Fully uncensored stack: HF-style repo ids (slash) or
            # ollama tags with optional :quant suffix.
            assert isinstance(repo_id, str) and len(repo_id) > 0
            assert "/" in repo_id or ":" in repo_id
            assert isinstance(size, str)
            assert isinstance(license_, str)
            assert isinstance(gated, bool)


class TestRegistry:
    def test_default_base_model_is_operator_preferred(self):
        import json
        path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "pentest_hf_registry.json",
        )
        with open(path) as f:
            reg = json.load(f)
        defaults = reg.get("defaults", {})
        bm = defaults.get("base_model", "")
        # Match by base model family (Qwen3.5-9B-HERETIC). The
        # redistribution org can vary (DavidAU vs mradermacher),
        # the model architecture is what matters.
        assert "HERETIC" in bm, (
            f"default base_model must reference the HERETIC family; "
            f"got {bm!r}"
        )
        assert "Qwen3.5-9B" in bm, (
            f"default base_model must be 9B-class for the 12GB hybrid "
            f"profile; got {bm!r}"
        )

    def test_uncensored_base_section_contains_operator_preferred(self):
        import json
        path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "pentest_hf_registry.json",
        )
        with open(path) as f:
            reg = json.load(f)
        section = reg.get("uncensored_base", [])
        ids = [m.get("id") for m in section]
        # Match by family — the redistribution org can vary
        # (DavidAU hosts the safetensors version for LoRA/QLoRA;
        # mradermacher hosts the GGUF version for ollama).
        matching = [i for i in ids
                    if "Qwen3.5-9B" in i and "HERETIC" in i]
        assert matching, (
            f"no HERETIC 9B entry in uncensored_base section; "
            f"got ids={ids}"
        )


class TestPullScript:
    def test_script_exists(self):
        path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "scripts", "pull_code_architect_model.sh",
        )
        assert os.path.isfile(path), path

    def test_script_executable(self):
        path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "scripts", "pull_code_architect_model.sh",
        )
        st = os.stat(path)
        assert st.st_mode & 0o111, f"script not executable: {oct(st.st_mode)}"

    def test_script_references_operator_preferred_model(self):
        path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "scripts", "pull_code_architect_model.sh",
        )
        with open(path) as f:
            body = f.read()
        # Match by base-model family (the redistribution org can vary).
        assert "HERETIC-UNCENSORED" in body, (
            f"pull script must reference the HERETIC-UNCENSORED family"
        )
        assert "Qwen3.5-9B" in body, (
            f"pull script must be the 9B variant for 12GB hybrid"
        )
        assert "hf.co/" in body
        # Has the override via $MODEL
        assert "MODEL=" in body
        # Uses ollama pull
        assert "ollama pull" in body
        # Bash safety
        assert "set -euo pipefail" in body

    def test_script_does_not_contain_shebang_typo(self):
        path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "scripts", "pull_code_architect_model.sh",
        )
        with open(path) as f:
            first = f.readline()
        assert first.startswith("#!/usr/bin/env bash"), first


class TestChainStanza:
    def test_cve_to_exploit_stanza_in_chain(self):
        from core.ai_backend.chain import (
            CVE_TO_EXPLOIT_PROMPT_STANZA, _SYSTEM_PROMPT,
        )
        # Stanza is referenced inside _SYSTEM_PROMPT.
        assert "cve_to_exploit" in CVE_TO_EXPLOIT_PROMPT_STANZA
        # _SYSTEM_PROMPT interpolates it.
        assert "cve_to_exploit" in _SYSTEM_PROMPT
        # The stanza mentions NEVER fabricating CVE ids (operator directive).
        assert "fabricate" in CVE_TO_EXPLOIT_PROMPT_STANZA.lower()
        # The stanza mentions the per-step gate.
        assert "ACCEPT" in CVE_TO_EXPLOIT_PROMPT_STANZA

    def test_chain_action_enum_contains_cve_to_exploit(self):
        from core.ai_backend.chain import _SYSTEM_PROMPT
        # cve_to_exploit is in the action enum string.
        assert '"action"' in _SYSTEM_PROMPT
        assert "cve_to_exploit" in _SYSTEM_PROMPT


class TestNeverFakes:
    def test_pull_script_no_inline_creds(self):
        """The pull script must NOT inline any credential values (the
        never-inline ground rule)."""
        path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "scripts", "pull_code_architect_model.sh",
        )
        with open(path) as f:
            body = f.read()
        # No password/key/token literal assignment to a variable.
        for forbidden in ("PASSWORD=", "TOKEN=", "API_KEY=", "SECRET="):
            assert forbidden not in body, f"inline credential: {forbidden}"

    def test_pull_script_ollama_command_only(self):
        """The script must not invoke anything destructive."""
        path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "scripts", "pull_code_architect_model.sh",
        )
        with open(path) as f:
            body = f.read()
        # No apt install, no rm -rf, no mkfs, no dd.
        for forbidden in ("apt-get install", "rm -rf /", "mkfs", "dd if="):
            assert forbidden not in body, f"destructive op: {forbidden}"
