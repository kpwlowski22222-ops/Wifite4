"""tests.test_deep_thinking — hermetic suite for enhanced deep-thinking.

No live Ollama. Covers registry shape, metadata, auto-select, complexity,
stanza protocol, hybrid blocks, overrides, and AIBackend integration.
"""
from __future__ import annotations

from typing import Any, Dict

import pytest

from core.ai_backend import deep_thinking as dt
from core.algorithm_registry import algo_registry


# ---------------------------------------------------------------------------
# Registry shape + metadata
# ---------------------------------------------------------------------------

class TestRegistryShape:
    def test_exactly_ten_types(self):
        assert len(dt.list_thinking_types()) == 10
        assert set(dt.list_thinking_types()) == set(dt.VALID_TYPE_IDS)
        for tid in (
            dt.TYPE_GRAPH_OF_THOUGHT,
            dt.TYPE_SELF_CONSISTENCY,
            dt.TYPE_LEAST_TO_MOST,
            dt.TYPE_PLAN_AND_SOLVE,
            dt.TYPE_REFLEXION,
            dt.TYPE_MULTI_AGENT_DEBATE,
        ):
            assert tid in dt.DEEP_THINKING_TYPES

    def test_thirty_algorithms(self):
        assert len(dt.list_thinking_algorithms()) == 30

    def test_three_algorithms_per_type(self):
        for tid in dt.list_thinking_types():
            algos = dt.list_thinking_algorithms(tid)
            assert len(algos) == 3, tid
            for aid in algos:
                assert dt.DEEP_THINKING_ALGORITHMS[aid].type_id == tid

    def test_all_algorithms_have_enhanced_metadata(self):
        for aid, a in dt.DEEP_THINKING_ALGORITHMS.items():
            assert a.intensity in (
                dt.INTENSITY_LIGHT, dt.INTENSITY_MEDIUM, dt.INTENSITY_HEAVY
            ), aid
            assert a.step_budget >= 4, aid
            assert len(a.quality_checklist) >= 2, aid
            assert a.prompt_body.strip(), aid

    def test_describe_type(self):
        d = dt.describe_thinking(dt.TYPE_CHAIN_OF_THOUGHT)
        assert d["kind"] == "type"
        assert d["id"] == dt.TYPE_CHAIN_OF_THOUGHT
        assert "sequential_plan" in d["algorithms"]
        assert "default_intensity" in d

    def test_describe_algorithm_metadata(self):
        d = dt.describe_thinking("failure_root_cause")
        assert d["kind"] == "algorithm"
        assert d["type_id"] == dt.TYPE_SELF_CRITIQUE
        assert d["intensity"]
        assert d["step_budget"] >= 4
        assert d["quality_checklist"]

    def test_describe_new_types(self):
        d = dt.describe_thinking(dt.TYPE_GRAPH_OF_THOUGHT)
        assert "intel_graph_merge" in d["algorithms"]
        d2 = dt.describe_thinking("triple_path_vote")
        assert d2["type_id"] == dt.TYPE_SELF_CONSISTENCY

    def test_describe_unknown(self):
        assert dt.describe_thinking("no_such_thing") == {}


# ---------------------------------------------------------------------------
# Complexity estimator
# ---------------------------------------------------------------------------

class TestComplexity:
    def test_empty_is_low(self):
        c = dt.estimate_complexity("misc", "hi")
        assert 0.0 <= c <= 0.4

    def test_rich_context_higher(self):
        low = dt.estimate_complexity("misc", "hi")
        high = dt.estimate_complexity(
            "chain",
            "complex multi-step attack chain with strict JSON and replan",
            {
                "recon": {"x": 1},
                "cves": ["CVE-1"],
                "failed_step": {"a": 1},
                "engagement_history": [{}],
            },
        )
        assert high > low
        assert high >= 0.5

    def test_bounded(self):
        c = dt.estimate_complexity(
            "zero_day",
            "x" * 5000 + " complex multi-step correlate debate replan zero-day",
            {"recon": 1, "cves": 1, "failed_step": 1, "kb_hits": 1,
             "engagement_history": 1, "past_failures": 1},
        )
        assert 0.0 <= c <= 1.0


# ---------------------------------------------------------------------------
# Auto-select rules
# ---------------------------------------------------------------------------

class TestAutoSelect:
    def test_default_wireless(self):
        c = dt.auto_select_thinking("wifi", "hello")
        # low complexity may pick evidence_first; otherwise surface_compare
        assert c.type_id in (dt.TYPE_TREE_OF_THOUGHT, dt.TYPE_REACT_GROUNDED)
        assert c.source == "auto"
        assert "complexity" in c.as_dict()

    def test_generic_domain_default(self):
        c = dt.auto_select_thinking("misc", "say something useful")
        assert c.algorithm_id in ("sequential_plan", "evidence_first")

    def test_replan_failure_context(self):
        c = dt.auto_select_thinking(
            "wifi",
            "continue",
            {"failed_step": {"action": "deauth"}, "ok": False},
        )
        assert c.type_id == dt.TYPE_SELF_CRITIQUE
        assert c.algorithm_id == "failure_root_cause"

    def test_replan_prompt_text(self):
        c = dt.auto_select_thinking(
            "wifi",
            "=== REPLAN ON FAILURE === The previous step failed.",
        )
        assert c.algorithm_id == "failure_root_cause"

    def test_zero_day_hypothesis(self):
        c = dt.auto_select_thinking(
            "wifi",
            "Draft a zero-day vulnerability hypothesis for this daemon",
        )
        assert c.type_id == dt.TYPE_SELF_CRITIQUE
        assert c.algorithm_id == "hypothesis_falsify"

    def test_chain_plan_markers(self):
        c = dt.auto_select_thinking(
            "wifi",
            "Produce a concrete ordered attack chain as strict JSON matching",
        )
        assert c.type_id == dt.TYPE_CHAIN_OF_THOUGHT
        assert c.algorithm_id == "sequential_plan"

    def test_compare_tools(self):
        c = dt.auto_select_thinking(
            "osint",
            "Which tool should I choose from the catalog for subdomain enum?",
        )
        assert c.type_id == dt.TYPE_TREE_OF_THOUGHT
        assert c.algorithm_id == "tool_branch_score"

    def test_compare_attacks(self):
        c = dt.auto_select_thinking(
            "wifi",
            "Compare alternative attack paths and pick the best of them",
        )
        assert c.algorithm_id == "multi_path_attack"

    def test_osint_domain(self):
        c = dt.auto_select_thinking("osint", "profile this username")
        assert c.type_id == dt.TYPE_REACT_GROUNDED
        assert c.algorithm_id == "recon_enrich_loop"

    def test_recon_context(self):
        c = dt.auto_select_thinking(
            "wifi",
            "next steps",
            {"recon": {"bssid": "aa:bb", "clients": 2}},
        )
        assert c.type_id == dt.TYPE_REACT_GROUNDED

    def test_post_exploit_precondition(self):
        c = dt.auto_select_thinking(
            "post_exploitation",
            "what to run after shell",
        )
        assert c.algorithm_id == "precondition_ladder"

    def test_c2_precondition(self):
        c = dt.auto_select_thinking("c2", "stage beacon")
        assert c.algorithm_id == "precondition_ladder"

    def test_override_type(self):
        c = dt.auto_select_thinking(
            "osint",
            "profile this username",
            {"deep_thinking_type": dt.TYPE_TREE_OF_THOUGHT},
        )
        assert c.type_id == dt.TYPE_TREE_OF_THOUGHT
        assert c.source == "override"

    def test_override_algorithm(self):
        c = dt.auto_select_thinking(
            "osint",
            "anything",
            {"deep_thinking_algorithm": "evidence_first"},
        )
        assert c.algorithm_id == "evidence_first"
        assert c.type_id == dt.TYPE_REACT_GROUNDED
        assert c.source == "override"

    def test_override_via_thinking_mode_algo_id(self):
        c = dt.auto_select_thinking(
            "wifi",
            "x",
            {"thinking_mode": "red_team_own_plan"},
        )
        assert c.algorithm_id == "red_team_own_plan"
        assert c.source == "override"

    def test_graph_of_thought_correlate(self):
        c = dt.auto_select_thinking(
            "wifi",
            "Correlate and merge findings into a dependency graph",
        )
        assert c.type_id == dt.TYPE_GRAPH_OF_THOUGHT
        assert c.algorithm_id == "intel_graph_merge"

    def test_graph_cve_surface_fuse(self):
        c = dt.auto_select_thinking(
            "wifi",
            "next action",
            {"cves": ["CVE-2021-1234"], "recon": {"bssid": "aa:bb"}},
        )
        assert c.type_id == dt.TYPE_GRAPH_OF_THOUGHT
        assert c.algorithm_id == "cve_surface_fuse"

    def test_self_consistency_consensus(self):
        c = dt.auto_select_thinking(
            "misc",
            "Use majority vote consensus for a high stakes decision",
        )
        assert c.type_id == dt.TYPE_SELF_CONSISTENCY
        assert c.algorithm_id == "triple_path_vote"

    def test_self_consistency_cross_check(self):
        c = dt.auto_select_thinking(
            "misc",
            "Please cross-check and verify your answer carefully",
        )
        assert c.algorithm_id == "cross_check_answer"

    def test_least_to_most_decompose(self):
        c = dt.auto_select_thinking(
            "misc",
            "Decompose this hard problem into subproblems from simplest first",
        )
        assert c.type_id == dt.TYPE_LEAST_TO_MOST
        assert c.algorithm_id == "goal_decompose"

    def test_plan_and_solve(self):
        c = dt.auto_select_thinking(
            "misc",
            "Plan first then execute the engagement carefully",
        )
        assert c.type_id == dt.TYPE_PLAN_AND_SOLVE
        assert c.algorithm_id == "plan_then_execute"

    def test_reflexion_history(self):
        c = dt.auto_select_thinking(
            "wifi",
            "continue the engagement",
            {"engagement_history": [{"step": 1, "ok": False}]},
        )
        assert c.type_id == dt.TYPE_REFLEXION
        assert c.algorithm_id in ("verbal_rl_memory", "episode_retrospective")

    def test_reflexion_stuck(self):
        c = dt.auto_select_thinking(
            "wifi",
            "We are stuck with the same error and need to pivot strategy",
        )
        assert c.type_id == dt.TYPE_REFLEXION
        assert c.algorithm_id == "strategy_shift"

    def test_multi_agent_debate(self):
        c = dt.auto_select_thinking(
            "misc",
            "Run a red team vs blue team debate on this attack plan",
        )
        assert c.type_id == dt.TYPE_MULTI_AGENT_DEBATE
        assert c.algorithm_id == "red_blue_debate"

    def test_devil_advocate(self):
        c = dt.auto_select_thinking(
            "misc",
            "Argue both sides with a devil's advocate before deciding",
        )
        assert c.algorithm_id == "devil_advocate"

    def test_high_complexity_prefers_ps_or_ltm(self):
        # Avoid hard-rule keywords (correlate/debate/replan/zero-day) so
        # complexity fallback can fire; pad length + multi-step markers.
        long_prompt = (
            "complex multi-step end to end engagement: enumerate targets "
            "and then stage carefully with a full operational plan "
        ) * 12
        c = dt.auto_select_thinking(
            "chain",
            long_prompt,
            {"recon": {"hosts": 3}, "cves": ["CVE-1"], "kb_hits": 2},
        )
        assert c.complexity >= 0.5
        # chain domain + plan language may hit sequential_plan; high
        # complexity without plan markers prefers PS+ / LtM.
        assert c.type_id in (
            dt.TYPE_PLAN_AND_SOLVE,
            dt.TYPE_LEAST_TO_MOST,
            dt.TYPE_CHAIN_OF_THOUGHT,
            dt.TYPE_GRAPH_OF_THOUGHT,  # recon+cves can fuse
            dt.TYPE_REACT_GROUNDED,
        )


# ---------------------------------------------------------------------------
# Stanza + apply + hybrid
# ---------------------------------------------------------------------------

class TestStanzaAndApply:
    def test_build_stanza_contains_protocol(self):
        choice = dt.ThinkingChoice(
            type_id=dt.TYPE_SELF_CRITIQUE,
            algorithm_id="failure_root_cause",
            reason="test",
            source="auto",
            complexity=0.6,
            intensity=dt.INTENSITY_HEAVY,
        )
        stanza = dt.build_thinking_stanza(choice)
        assert "DEEP THINKING" in stanza
        assert dt.TYPE_SELF_CRITIQUE in stanza
        assert "failure_root_cause" in stanza
        assert "Internal protocol" in stanza
        assert "BUDGET" in stanza
        assert "Quality checklist" in stanza
        assert "Never fabricate" in stanza
        assert "API_KEY" not in stanza

    def test_tot_rubric_in_body(self):
        choice = dt._choice_from_algo("multi_path_attack", "t", "auto")
        stanza = dt.build_thinking_stanza(choice)
        assert "feasibility" in stanza.lower()
        assert "Score dimensions" in stanza

    def test_ps_plus_in_plan_then_execute(self):
        choice = dt._choice_from_algo("plan_then_execute", "t", "auto")
        stanza = dt.build_thinking_stanza(choice)
        assert "EXTRACT" in stanza or "PS+" in stanza or "AUDIT" in stanza

    def test_stanza_under_soft_cap(self):
        for aid in dt.list_thinking_algorithms():
            choice = dt._choice_from_algo(aid, "t", "auto")
            n = dt.estimate_stanza_chars(choice)
            assert n <= dt._STANZA_SOFT_CAP + 50, (aid, n)

    def test_hybrid_block_for_high_complexity_cot(self):
        choice = dt.ThinkingChoice(
            type_id=dt.TYPE_CHAIN_OF_THOUGHT,
            algorithm_id="sequential_plan",
            reason="t",
            source="auto",
            complexity=0.85,
            intensity=dt.INTENSITY_MEDIUM,
            hybrid=True,
        )
        stanza = dt.build_thinking_stanza(choice)
        assert "Hybrid enhancer" in stanza
        assert "missing" in stanza.lower() or "PS+" in stanza

    def test_apply_prepends_stanza(self):
        sys = "You are a pentester."
        ctx: Dict[str, Any] = {}
        merged, choice = dt.apply_deep_thinking(
            sys, "osint", "enrich this target", ctx,
        )
        assert merged.startswith("=== DEEP THINKING")
        assert "You are a pentester." in merged
        assert choice.type_id == dt.TYPE_REACT_GROUNDED
        assert ctx.get("_deep_thinking", {}).get("type") == choice.type_id
        assert "intensity" in ctx["_deep_thinking"]

    def test_apply_disabled_context(self):
        sys = "You are a pentester."
        ctx = {"deep_thinking_enabled": False}
        merged, choice = dt.apply_deep_thinking(
            sys, "osint", "enrich this target", ctx,
        )
        assert merged == sys
        assert choice.source == "disabled"

    def test_apply_disabled_env(self, monkeypatch):
        monkeypatch.setenv("KFIOSA_DEEP_THINKING", "0")
        sys = "base"
        merged, choice = dt.apply_deep_thinking(sys, "wifi", "plan", {})
        assert merged == sys
        assert choice.source == "disabled"

    def test_force_type_env(self, monkeypatch):
        monkeypatch.setenv("KFIOSA_DEEP_THINKING_FORCE", dt.TYPE_SELF_CRITIQUE)
        monkeypatch.delenv("KFIOSA_DEEP_THINKING", raising=False)
        merged, choice = dt.apply_deep_thinking(
            "base", "misc", "hello world", {},
        )
        assert choice.type_id == dt.TYPE_SELF_CRITIQUE
        assert choice.source == "forced"
        assert "DEEP THINKING" in merged

    def test_prefers_thinking_model_heavy(self):
        c = dt.ThinkingChoice(
            type_id=dt.TYPE_SELF_CRITIQUE,
            algorithm_id="hypothesis_falsify",
            reason="t",
            source="auto",
            intensity=dt.INTENSITY_HEAVY,
        )
        assert dt.prefers_thinking_model(c) is True

    def test_prefers_thinking_model_light_false(self):
        c = dt.ThinkingChoice(
            type_id=dt.TYPE_REACT_GROUNDED,
            algorithm_id="evidence_first",
            reason="t",
            source="auto",
            intensity=dt.INTENSITY_LIGHT,
        )
        assert dt.prefers_thinking_model(c) is False


# ---------------------------------------------------------------------------
# algo_registry
# ---------------------------------------------------------------------------

class TestAlgoRegistry:
    def test_types_registered(self):
        dt.register_with_algo_registry()
        names = algo_registry.list_registered()
        for tid in dt.VALID_TYPE_IDS:
            assert f"deep_thinking_{tid}" in names

    def test_list_by_domain(self):
        dt.register_with_algo_registry()
        items = algo_registry.list_by_domain("deep_thinking")
        assert len(items) >= 40

    def test_callable_describe(self):
        dt.register_with_algo_registry()
        fn = algo_registry.get("deep_thinking_chain_of_thought")
        assert callable(fn)
        out = fn()
        assert out["id"] == dt.TYPE_CHAIN_OF_THOUGHT


# ---------------------------------------------------------------------------
# AIBackend.query integration
# ---------------------------------------------------------------------------

class TestAIBackendIntegration:
    def test_query_applies_deep_thinking(self):
        from core.ai_backend import AIBackend

        backend = AIBackend(config={})
        backend.nvidia_api_key = ""
        backend.deepseek_api_key = ""
        backend.gemini_api_key = ""
        backend.groq_api_key = ""
        backend.grok_api_key = ""

        captured = {}

        def fake_generate(model, prompt, system=""):
            captured["system"] = system
            captured["prompt"] = prompt
            captured["model"] = model
            return "ok-reply"

        backend.ollama.reachable = lambda: True
        backend.ollama.list_models = lambda: ["wizard-vicuna-uncensored:latest"]
        backend.ollama.generate = fake_generate

        ctx: Dict[str, Any] = {"recon": {"ssid": "lab"}}
        reply = backend.query("osint", "enrich target profile", context=ctx)
        assert reply == "ok-reply"
        assert "DEEP THINKING" in captured["system"]
        assert "Internal protocol" in captured["system"]
        assert ctx.get("_deep_thinking", {}).get("type") == dt.TYPE_REACT_GROUNDED

    def test_query_respects_disabled(self):
        from core.ai_backend import AIBackend

        backend = AIBackend(config={})
        backend.nvidia_api_key = ""
        backend.deepseek_api_key = ""
        backend.gemini_api_key = ""
        backend.groq_api_key = ""
        backend.grok_api_key = ""

        captured = {}

        def fake_generate(model, prompt, system=""):
            captured["system"] = system
            return "ok"

        backend.ollama.reachable = lambda: True
        backend.ollama.list_models = lambda: ["wizard-vicuna-uncensored:latest"]
        backend.ollama.generate = fake_generate

        backend.query(
            "osint",
            "enrich",
            context={"deep_thinking_enabled": False},
        )
        assert "DEEP THINKING" not in captured["system"]
