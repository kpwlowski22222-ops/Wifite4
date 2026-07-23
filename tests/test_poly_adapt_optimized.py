"""Tests for target-adaptive scoring + optimized poly/adapt dispatch.

Covers Phase poly-opt:
  * extract_target_features
  * score_variants / pick_best_variant
  * context-aware poly grammars (deauth, pmkid, channel hop)
  * deepened adapt pickers
  * run_poly_adapt memo + feature merge
"""
from __future__ import annotations

import importlib

import pytest


@pytest.fixture(autouse=True)
def _clear_memo():
    mod = importlib.import_module("core.utils.poly_adapt")
    mod.clear_poly_adapt_memo()
    yield
    mod.clear_poly_adapt_memo()


# ---------------------------------------------------------------------------
# Feature extraction
# ---------------------------------------------------------------------------


class TestExtractTargetFeatures:
    def test_empty(self):
        from core.utils.poly_adapt import extract_target_features
        f = extract_target_features(None)
        assert f["wpa_version"] == ""
        assert f["client_count"] == 0
        assert f["pmf_supported"] is False

    def test_encryption_wpa3_sae(self):
        from core.utils.poly_adapt import extract_target_features
        f = extract_target_features({"encryption": "WPA3-SAE"})
        assert f["wpa_version"] == "wpa3"
        assert f["pmf_supported"] is True

    def test_encryption_enterprise(self):
        from core.utils.poly_adapt import extract_target_features
        f = extract_target_features({"enc": "WPA2-Enterprise"})
        assert f["wpa_version"] == "wpa2_enterprise"

    def test_clients_list(self):
        from core.utils.poly_adapt import extract_target_features
        f = extract_target_features({"clients": ["aa", "bb", "cc"]})
        assert f["client_count"] == 3

    def test_channel_infers_band(self):
        from core.utils.poly_adapt import extract_target_features
        f24 = extract_target_features({"channel": 6})
        assert f24["band"] == "2.4"
        f5 = extract_target_features({"channel": 36})
        assert f5["band"] == "5"

    def test_nested_seed_recon(self):
        from core.utils.poly_adapt import extract_target_features
        f = extract_target_features({
            "seed": {"bssid": "aa:bb:cc:dd:ee:ff", "encryption": "WPA2"},
            "recon": {"wps": {"ok": True}},
        })
        assert f["bssid"] == "aa:bb:cc:dd:ee:ff"
        assert f["wpa_version"] == "wpa2"
        assert f["wps"] is True


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------


class TestScoreVariants:
    def test_ranks_by_score(self):
        from core.utils.poly_adapt import score_variants
        ranked = score_variants([
            {"name": "low", "score": 0.2},
            {"name": "high", "score": 0.9},
            {"name": "mid", "score": 0.5},
        ])
        assert [v["name"] for v in ranked] == ["high", "mid", "low"]

    def test_string_variants(self):
        from core.utils.poly_adapt import score_variants
        ranked = score_variants(["a", "b"])
        assert all("name" in v and "score" in v for v in ranked)

    def test_deauth_rules_prefer_sa_query_when_pmf(self):
        from core.utils.poly_adapt import (
            pick_best_variant, wifi_deauth_score_rules,
        )
        best, ranked = pick_best_variant(
            [
                {"name": "broadcast_deauth_burst", "score": 0.5},
                {"name": "sa_query_flood", "score": 0.4},
                {"name": "constant_100", "score": 0.5},
            ],
            features={"pmf_supported": True, "client_count": 1},
            rules=wifi_deauth_score_rules(),
        )
        assert best is not None
        assert best["name"] == "sa_query_flood"
        assert ranked[0]["name"] == "sa_query_flood"

    def test_pmkid_clientless_boosts_key_info(self):
        from core.utils.poly_adapt import (
            pick_best_variant, wifi_pmkid_score_rules,
        )
        best, _ = pick_best_variant(
            [
                {"name": "key_data_random_pad", "score": 0.5},
                {"name": "key_info_clear", "score": 0.5},
            ],
            features={"client_count": 0, "wpa_version": "wpa2"},
            rules=wifi_pmkid_score_rules(),
        )
        assert best["name"] == "key_info_clear"


# ---------------------------------------------------------------------------
# PolyGrammarRunner score-based pick
# ---------------------------------------------------------------------------


class TestPolyGrammarRunnerScoring:
    def test_picks_highest_score_not_first(self):
        from core.utils.poly_adapt import PolyGrammarRunner

        class R(PolyGrammarRunner):
            def _poly_grammar(self, family, context):
                return [
                    {"name": "first_low", "params": {}, "score": 0.1},
                    {"name": "second_high", "params": {"x": 1}, "score": 0.95},
                ]

        out = R()._v2_poly_dispatch("f", {})
        assert out["ok"] is True
        assert out["data"]["picked"] == "second_high"
        assert out["data"]["picked_score"] >= 0.9


# ---------------------------------------------------------------------------
# Live companions — target adaptive
# ---------------------------------------------------------------------------


class TestContextAwareCompanions:
    def test_deauth_pmf_prefers_sa_or_backoff(self):
        from core.refactors.poly_adapt_companions import run_poly_adapt
        r = run_poly_adapt("poly_deauth_burst_pattern_grammar", {
            "pmf_supported": True,
            "client_count": 1,
            "seed": "test-pmf",
        }, use_memo=False)
        assert r["ok"] is True
        primary = r["data"]["primary"]
        assert primary in (
            "sa_query_flood", "exponential_backoff", "staggered_50_150",
            "directed_deauth", "ramp_50_200",
        )
        # With PMF, broadcast/constant should not win
        assert primary not in ("broadcast_deauth_burst", "constant_100")
        assert "variant_scores" in r["data"]
        assert "features_used" in r["data"]

    def test_deauth_many_clients_no_pmf_prefers_burst(self):
        from core.refactors.poly_adapt_companions import run_poly_adapt
        r = run_poly_adapt("poly_deauth_burst_pattern_grammar", {
            "pmf_supported": False,
            "client_count": 12,
            "seed": "busy-ap",
        }, use_memo=False)
        assert r["ok"] is True
        primary = r["data"]["primary"]
        assert primary in (
            "broadcast_deauth_burst", "ramp_50_200", "burst_three_30",
            "constant_100", "staggered_50_150",
        )

    def test_adapt_deauth_pmf_few_clients(self):
        from core.refactors.poly_adapt_companions import run_poly_adapt
        r = run_poly_adapt(
            "adapt_attack_deauth_strategy_picker",
            {"pmf_supported": True, "client_count": 1},
            use_memo=False,
        )
        assert r["ok"] is True
        assert r["data"]["pick"] == "sa_query_flood"
        assert r["data"]["score"] >= 0.8
        assert r["data"]["features"]["pmf_supported"] is True

    def test_adapt_handshake_from_encryption_string(self):
        """Feature merge: only encryption given → wpa_version inferred."""
        from core.refactors.poly_adapt_companions import run_poly_adapt
        r = run_poly_adapt(
            "adapt_attack_handshake_strategy_picker",
            {"encryption": "WPA3-SAE"},
            use_memo=False,
        )
        assert r["ok"] is True
        assert "sae" in r["data"]["pick"].lower()

    def test_adapt_handshake_transition_mode(self):
        from core.refactors.poly_adapt_companions import run_poly_adapt
        r = run_poly_adapt(
            "adapt_attack_handshake_strategy_picker",
            {"encryption": "WPA3", "transition_mode": True},
            use_memo=False,
        )
        assert r["ok"] is True
        assert "transition" in r["data"]["pick"].lower() or "sae" in r["data"]["pick"].lower()

    def test_adapt_handshake_clientless_pmkid(self):
        from core.refactors.poly_adapt_companions import run_poly_adapt
        r = run_poly_adapt(
            "adapt_attack_handshake_strategy_picker",
            {"encryption": "WPA2", "client_count": 0, "pmf": False},
            use_memo=False,
        )
        assert r["ok"] is True
        assert "pmkid" in r["data"]["pick"].lower()

    def test_channel_hop_5ghz(self):
        from core.refactors.poly_adapt_companions import run_poly_adapt
        r = run_poly_adapt(
            "poly_passive_scan_channel_hop_grammar",
            {"channel": 40, "band": "5"},
            use_memo=False,
        )
        assert r["ok"] is True
        primary = r["data"]["primary"]
        assert isinstance(primary, list)
        # 5 GHz path should prefer UNII / interleaved over pure 1-11
        assert primary[0] >= 36 or 36 in primary

    def test_pmkid_grammar_clientless(self):
        from core.refactors.poly_adapt_companions import run_poly_adapt
        r = run_poly_adapt(
            "poly_pmkid_eapol_field_grammar",
            {"client_count": 0, "encryption": "WPA2"},
            use_memo=False,
        )
        assert r["ok"] is True
        assert r["data"]["primary"] in ("key_info_clear", "rsn_ie_request", "wpa_ssid_replay")


# ---------------------------------------------------------------------------
# Memo cache
# ---------------------------------------------------------------------------


class TestMemo:
    def test_second_call_is_cached(self):
        from core.refactors.poly_adapt_companions import run_poly_adapt
        args = {"pmf_supported": True, "client_count": 2, "seed": "memo-test"}
        r1 = run_poly_adapt("poly_deauth_burst_pattern_grammar", args, use_memo=True)
        r2 = run_poly_adapt("poly_deauth_burst_pattern_grammar", args, use_memo=True)
        assert r1["ok"] and r2["ok"]
        assert r2.get("cached") is True
        assert r1["data"]["primary"] == r2["data"]["primary"]

    def test_use_memo_false_skips_cache(self):
        from core.refactors.poly_adapt_companions import run_poly_adapt
        args = {"seed": "no-memo"}
        r1 = run_poly_adapt("poly_deauth_burst_pattern_grammar", args, use_memo=False)
        r2 = run_poly_adapt("poly_deauth_burst_pattern_grammar", args, use_memo=False)
        assert r1["ok"] and r2["ok"]
        assert r2.get("cached") is not True


# ---------------------------------------------------------------------------
# adaptive_engagement poly mutate
# ---------------------------------------------------------------------------


class TestPolyMutateSteps:
    def test_injects_features_and_resolves_poly(self):
        from core.orchestrator.adaptive_engagement import _poly_mutate_steps
        steps = [
            {"action": "recon", "tool": "scan"},
            {
                "action": "poly_adapt",
                "method": "poly_deauth_burst_pattern_grammar",
                "args": {},
            },
            {"action": "wifi_attack", "tool": "deauth"},
        ]
        seed = {
            "bssid": "11:22:33:44:55:66",
            "encryption": "WPA2",
            "clients": ["a", "b", "c", "d", "e", "f"],
            "channel": 6,
        }
        out = _poly_mutate_steps(steps, seed, "wifi", cycle=0)
        assert len(out) == 3
        poly_step = next(s for s in out if (s.get("action") or "") == "poly_adapt")
        assert poly_step["args"].get("bssid") == "11:22:33:44:55:66"
        assert poly_step["args"].get("client_count") == 6
        assert poly_step["poly"].get("target_adaptive") is True
        # Resolved pick optional but expected when registry works
        if poly_step["poly"].get("resolved_pick"):
            assert isinstance(poly_step["poly"]["resolved_pick"], str)
