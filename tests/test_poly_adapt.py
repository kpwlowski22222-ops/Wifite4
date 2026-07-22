"""Tests for core.utils.poly_adapt — Phase 4 T22 coverage."""
from __future__ import annotations

import importlib

import pytest


def _import_mod():
    return importlib.import_module("core.utils.poly_adapt")


mod = _import_mod()


# ---------------------------------------------------------------------------
# PolyGrammarRunner
# ---------------------------------------------------------------------------

class TestPolyGrammarRunner:
    def test_default_grammar(self):
        runner = mod.PolyGrammarRunner()
        out = runner._poly_grammar("any_family", {"k": "v"})
        assert isinstance(out, list)
        assert len(out) == 1
        assert out[0]["name"] == "any_family"
        assert out[0]["params"] == {"k": "v"}
        assert out[0]["score"] == 0.5

    def test_default_grammar_with_none_context(self):
        runner = mod.PolyGrammarRunner()
        out = runner._poly_grammar("f", None)
        assert out[0]["params"] == {}

    def test_dispatch_default(self):
        runner = mod.PolyGrammarRunner()
        out = runner._v2_poly_dispatch("test_family", {"x": 1})
        assert out["ok"] is True
        assert out["family"] == "test_family"
        assert out["model"] == "polymorphic (heuristic)"
        assert out["data"]["picked"] == "test_family"
        assert out["data"]["picked_params"] == {"x": 1}

    def test_dispatch_with_no_context(self):
        runner = mod.PolyGrammarRunner()
        out = runner._v2_poly_dispatch("f", None)
        assert out["ok"] is True

    def test_dispatch_returns_envelope_shape(self):
        runner = mod.PolyGrammarRunner()
        out = runner._v2_poly_dispatch("f", {})
        # Required keys per docstring
        for k in ("ok", "data", "family", "model"):
            assert k in out
        for k in ("variants", "picked", "picked_params"):
            assert k in out["data"]

    def test_dispatch_handles_empty_variants(self):
        class Empty(mod.PolyGrammarRunner):
            def _poly_grammar(self, family, context):
                return []
        runner = Empty()
        out = runner._v2_poly_dispatch("f", {})
        assert out["ok"] is False
        assert "0 variants" in out["error"]

    def test_dispatch_handles_raising_subclass(self):
        class Bad(mod.PolyGrammarRunner):
            def _poly_grammar(self, family, context):
                raise RuntimeError("boom")
        runner = Bad()
        out = runner._v2_poly_dispatch("f", {})
        assert out["ok"] is False
        assert "boom" in out["error"]


# ---------------------------------------------------------------------------
# TargetAdaptivePicker
# ---------------------------------------------------------------------------

class TestTargetAdaptivePicker:
    def test_default_pick(self):
        picker = mod.TargetAdaptivePicker()
        out = picker._adapt_pick("family_name", {"x": 1})
        assert out["method"] == "family_name"
        assert "family_name" in out["rationale"]
        assert out["score"] == 0.5

    def test_dispatch_default(self):
        picker = mod.TargetAdaptivePicker()
        out = picker._v2_adapt_dispatch("any_family", {"k": "v"})
        assert out["ok"] is True
        assert out["family"] == "any_family"
        assert out["model"] == "target-adaptive (heuristic)"
        assert out["data"]["pick"] == "any_family"
        assert out["data"]["family"] == "any_family"

    def test_dispatch_with_none_context(self):
        picker = mod.TargetAdaptivePicker()
        out = picker._v2_adapt_dispatch("f", None)
        assert out["ok"] is True

    def test_dispatch_envelope_shape(self):
        picker = mod.TargetAdaptivePicker()
        out = picker._v2_adapt_dispatch("f", {})
        for k in ("ok", "data", "family", "model"):
            assert k in out
        for k in ("pick", "rationale", "score", "family"):
            assert k in out["data"]

    def test_dispatch_handles_raising_subclass(self):
        class Bad(mod.TargetAdaptivePicker):
            def _adapt_pick(self, family, context):
                raise ValueError("nope")
        picker = Bad()
        out = picker._v2_adapt_dispatch("f", {})
        assert out["ok"] is False
        assert "nope" in out["error"]


# ---------------------------------------------------------------------------
# build_poly_adapt_envelope
# ---------------------------------------------------------------------------

class TestBuildEnvelope:
    def test_polymorphic_with_variants(self):
        out = mod.build_poly_adapt_envelope(
            "family", "picked_method",
            variants=[{"name": "a", "params": {}}],
        )
        assert out["ok"] is True
        assert out["family"] == "family"
        assert out["model"] == "polymorphic (heuristic)"
        assert "variants" in out["data"]
        assert out["data"]["picked"] == "picked_method"

    def test_target_adaptive_without_variants(self):
        out = mod.build_poly_adapt_envelope(
            "family", "picked_method", rationale="why", score=0.8,
        )
        assert out["ok"] is True
        assert out["family"] == "family"
        assert "pick" in out["data"]
        assert out["data"]["pick"] == "picked_method"
        assert out["data"]["rationale"] == "why"
        assert out["data"]["score"] == 0.8

    def test_custom_model(self):
        out = mod.build_poly_adapt_envelope(
            "f", "m", model="custom (heuristic)",
        )
        assert out["model"] == "custom (heuristic)"

    def test_default_rationale(self):
        out = mod.build_poly_adapt_envelope("f", "m")
        assert out["data"]["rationale"] == ""

    def test_default_score(self):
        out = mod.build_poly_adapt_envelope("f", "m")
        assert out["data"]["score"] == 0.5

    def test_explicit_empty_variants_treated_as_polymorphic(self):
        # variants=[] is falsy but explicitly passed → polymorphic
        out = mod.build_poly_adapt_envelope("f", "m", variants=[])
        assert "variants" in out["data"]


# ---------------------------------------------------------------------------
# Module exports
# ---------------------------------------------------------------------------

class TestExports:
    def test_all_exports(self):
        for name in ("PolyGrammarRunner", "TargetAdaptivePicker",
                     "build_poly_adapt_envelope"):
            assert name in mod.__all__


# ---------------------------------------------------------------------------
# No fabrication
# ---------------------------------------------------------------------------

class TestNoFabrication:
    def test_heuristic_label_present(self):
        runner = mod.PolyGrammarRunner()
        out = runner._v2_poly_dispatch("f", {})
        # Honest-degrade contract: must be labelled as heuristic
        assert "heuristic" in out["model"]

        picker = mod.TargetAdaptivePicker()
        out = picker._v2_adapt_dispatch("f", {})
        assert "heuristic" in out["model"]

    def test_no_creds_in_outputs(self):
        runner = mod.PolyGrammarRunner()
        out = runner._v2_poly_dispatch("f", {})
        text = str(out)
        for forbidden in ("ecf51ee2-938d", "f40bec4b664a40a9a",
                          "CE38F76832CFA1F6", "password=", "secret="):
            assert forbidden not in text, f"leaked {forbidden!r}"
