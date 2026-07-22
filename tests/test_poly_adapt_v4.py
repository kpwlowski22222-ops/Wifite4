"""tests.test_poly_adapt_v4 — T7 expansion: 10 cloud+mobile+OT+RE methods.

Adds smoke + adversarial tests for the 5 new polymorphic grammars
and 5 new target-adaptive pickers. All companions must:

* Return a real envelope {ok, data} — never fakes.
* Mark model as ``heuristic`` — never trained-ML.
* Stay at risk="intrusive" (never destructive).

Each method also gets at least one happy-path test that exercises
its primary pick/branch.
"""

import json

from core.refactors.poly_adapt_companions import (
    POLY_ADAPT_REGISTRY,
    POLY_ADAPT_RISK,
    POLY_ADAPT_DESCRIPTIONS,
    list_poly_adapt_methods,
    describe_poly_adapt_method,
    run_poly_adapt,
    build_poly_adapt_prompt_stanza,
)


# 5 polymorphic + 5 target-adaptive for the T7 expansion
V4_NAMES = [
    "poly_aws_iam_enumeration_grammar",
    "poly_k8s_lateral_movement_grammar",
    "poly_mobile_frida_hook_grammar",
    "poly_ics_modbus_payload_grammar",
    "poly_re_yara_rule_grammar",
    "adapt_cloud_provider_picker",
    "adapt_mobile_target_picker",
    "adapt_ot_protocol_picker",
    "adapt_re_tool_picker",
    "adapt_attack_chain_order_picker",
]


# ---------------------------------------------------------------------------
# Registry counts
# ---------------------------------------------------------------------------


class TestRegistryCounts:
    def test_total_at_least_70(self):
        # T7 expansion: 60 → 70 methods (35 poly + 35 adapt)
        assert len(POLY_ADAPT_REGISTRY) >= 70

    def test_v4_polymorphic_count(self):
        v4_poly = [n for n in POLY_ADAPT_REGISTRY if n in V4_NAMES and n.startswith("poly_")]
        assert len(v4_poly) == 5, f"v4 poly={len(v4_poly)}"

    def test_v4_adaptive_count(self):
        v4_adapt = [n for n in POLY_ADAPT_REGISTRY if n in V4_NAMES and n.startswith("adapt_")]
        assert len(v4_adapt) == 5, f"v4 adapt={len(v4_adapt)}"

    def test_v4_all_in_registry(self):
        for n in V4_NAMES:
            assert n in POLY_ADAPT_REGISTRY, f"{n} not registered"

    def test_v4_all_have_risk(self):
        for n in V4_NAMES:
            assert n in POLY_ADAPT_RISK, f"{n} has no risk entry"
            assert POLY_ADAPT_RISK[n] == "intrusive", (
                f"{n} risk should be intrusive, got {POLY_ADAPT_RISK[n]!r}"
            )

    def test_v4_all_have_descriptions(self):
        for n in V4_NAMES:
            d = POLY_ADAPT_DESCRIPTIONS.get(n, "")
            assert d, f"{n} missing description"
            assert len(d) > 10, f"{n} description too short: {d!r}"


# ---------------------------------------------------------------------------
# Polymorphic v4 happy-path tests
# ---------------------------------------------------------------------------


class TestPolymorphicV4:
    def test_poly_aws_iam(self):
        r = run_poly_adapt("poly_aws_iam_enumeration_grammar", {"seed": "x"})
        assert r["ok"] is True
        assert r["data"]["grammar"] == "aws_iam_enumeration"
        assert r["data"]["variants"]
        assert r["data"]["primary"] in r["data"]["variants"]
        assert r["data"]["model"] == "polymorphic (heuristic)"

    def test_poly_aws_iam_no_fabricated_creds(self):
        r = run_poly_adapt("poly_aws_iam_enumeration_grammar", {"seed": "y"})
        blob = json.dumps(r["data"]).lower()
        for bad in ("password=", "ntlm:", "hash=", "secret_key="):
            assert bad not in blob, f"fabricated {bad!r} in envelope"

    def test_poly_k8s_lateral(self):
        r = run_poly_adapt("poly_k8s_lateral_movement_grammar", {})
        assert r["ok"] is True
        assert "service_account_token_steal" in r["data"]["variants"]

    def test_poly_mobile_frida(self):
        r = run_poly_adapt("poly_mobile_frida_hook_grammar", {"seed": "fr"})
        assert r["ok"] is True
        assert "ssl_pinning_bypass" in r["data"]["variants"]
        assert r["data"]["primary"] in r["data"]["variants"]

    def test_poly_ics_modbus(self):
        r = run_poly_adapt("poly_ics_modbus_payload_grammar", {})
        assert r["ok"] is True
        assert "modbus_read_coils" in r["data"]["variants"]
        assert "s7_plc_stop" in r["data"]["variants"]
        # Gating note must always be present
        assert "ACCEPT" in r["data"]["note"] or "gate" in r["data"]["note"].lower()

    def test_poly_re_yara(self):
        r = run_poly_adapt("poly_re_yara_rule_grammar", {})
        assert r["ok"] is True
        assert "string_at_offset" in r["data"]["variants"]


# ---------------------------------------------------------------------------
# Target-adaptive v4 happy-path tests
# ---------------------------------------------------------------------------


class TestAdaptiveV4:
    def test_adapt_cloud_aws(self):
        r = run_poly_adapt("adapt_cloud_provider_picker", {"provider": "aws"})
        assert r["ok"] is True
        assert r["data"]["pick"] in ("pacu_or_scoutsuite", "pacu")

    def test_adapt_cloud_azure(self):
        r = run_poly_adapt("adapt_cloud_provider_picker", {"provider": "azure"})
        assert r["ok"] is True
        assert "roadtools" in r["data"]["pick"] or "microburst" in r["data"]["pick"]

    def test_adapt_cloud_gcp(self):
        r = run_poly_adapt("adapt_cloud_provider_picker", {"provider": "gcp"})
        assert r["ok"] is True
        assert "gcp" in r["data"]["pick"] or "iam" in r["data"]["pick"]

    def test_adapt_cloud_k8s(self):
        r = run_poly_adapt("adapt_cloud_provider_picker", {"provider": "k8s"})
        assert r["ok"] is True
        assert "peirates" in r["data"]["pick"] or "kubehound" in r["data"]["pick"]

    def test_adapt_cloud_unknown_falls_back(self):
        r = run_poly_adapt("adapt_cloud_provider_picker", {"provider": "wat"})
        assert r["ok"] is True
        assert "generic" in r["data"]["pick"] or "unknown" in r["data"]["rationale"].lower()

    def test_adapt_mobile_ios_jailbroken(self):
        r = run_poly_adapt("adapt_mobile_target_picker",
                           {"mobile_os": "ios", "jailbroken": True})
        assert r["ok"] is True
        assert "frida" in r["data"]["pick"]
        assert r["data"]["jailbroken"] is True

    def test_adapt_mobile_ios_nonjailbroken(self):
        r = run_poly_adapt("adapt_mobile_target_picker",
                           {"mobile_os": "ios", "jailbroken": False})
        assert r["ok"] is True
        assert "objection" in r["data"]["pick"]

    def test_adapt_mobile_android_rooted(self):
        r = run_poly_adapt("adapt_mobile_target_picker",
                           {"mobile_os": "android", "rooted": True})
        assert r["ok"] is True
        assert "apktool" in r["data"]["pick"]

    def test_adapt_ot_modbus(self):
        r = run_poly_adapt("adapt_ot_protocol_picker", {"protocol": "modbus"})
        assert r["ok"] is True
        assert "pymodbus" in r["data"]["pick"]

    def test_adapt_ot_s7(self):
        r = run_poly_adapt("adapt_ot_protocol_picker", {"protocol": "s7"})
        assert r["ok"] is True
        assert "snap7" in r["data"]["pick"]

    def test_adapt_ot_dnp3(self):
        r = run_poly_adapt("adapt_ot_protocol_picker", {"protocol": "dnp3"})
        assert r["ok"] is True

    def test_adapt_ot_enip(self):
        r = run_poly_adapt("adapt_ot_protocol_picker", {"protocol": "enip"})
        assert r["ok"] is True
        assert "cip" in r["data"]["pick"] or "pycomm" in r["data"]["pick"]

    def test_adapt_re_apk(self):
        r = run_poly_adapt("adapt_re_tool_picker", {"binary_kind": "apk"})
        assert r["ok"] is True
        assert "apktool" in r["data"]["pick"] and "jadx" in r["data"]["pick"]

    def test_adapt_re_ios(self):
        r = run_poly_adapt("adapt_re_tool_picker", {"binary_kind": "ios"})
        assert r["ok"] is True
        assert "ipsw" in r["data"]["pick"] or "frida" in r["data"]["pick"]

    def test_adapt_re_pe(self):
        r = run_poly_adapt("adapt_re_tool_picker", {"binary_kind": "pe"})
        assert r["ok"] is True
        assert "ghidra" in r["data"]["pick"] or "radare2" in r["data"]["pick"]

    def test_adapt_re_unknown(self):
        r = run_poly_adapt("adapt_re_tool_picker", {"binary_kind": "wat"})
        assert r["ok"] is True
        assert "radare2" in r["data"]["pick"]

    def test_adapt_chain_order_wireless_recon(self):
        r = run_poly_adapt("adapt_attack_chain_order_picker",
                           {"attack_surface": "wireless", "phase_hint": "recon"})
        assert r["ok"] is True
        assert "wireless" in r["data"]["pick"]
        assert "recon" in r["data"]["rationale"].lower()

    def test_adapt_chain_order_cloud_exploit(self):
        r = run_poly_adapt("adapt_attack_chain_order_picker",
                           {"attack_surface": "cloud", "phase_hint": "exploit"})
        assert r["ok"] is True
        assert "escalation" in r["data"]["pick"] or "lateral" in r["data"]["pick"]


# ---------------------------------------------------------------------------
# Adversarial
# ---------------------------------------------------------------------------


class TestAdversarialV4:
    def test_no_fabricated_creds_in_any_v4(self):
        for n in V4_NAMES:
            r = run_poly_adapt(n, {})
            assert r["ok"] is True, f"{n} returned not-ok: {r}"
            blob = json.dumps(r["data"]).lower()
            for bad in ("password=", "ntlm:", "hash=", "secret_key=",
                        "aws_access_key_id=", "bearer "):
                assert bad not in blob, (
                    f"{n} envelope contains {bad!r} — fabricated cred"
                )

    def test_no_trained_ml_label(self):
        for n in V4_NAMES:
            r = run_poly_adapt(n, {})
            model = r["data"].get("model", "")
            assert "trained" not in model.lower(), (
                f"{n} claims trained model: {model!r}"
            )

    def test_v4_describe_known(self):
        for n in V4_NAMES:
            d = describe_poly_adapt_method(n)
            assert d is not None
            assert d["name"] == n
            assert d["risk"] in ("intrusive", "destructive")
            assert d["description"]

    def test_prompt_stanza_lists_all_v4(self):
        stanza = build_poly_adapt_prompt_stanza()
        for n in V4_NAMES:
            assert n in stanza, f"{n} missing from prompt stanza"

    def test_no_unknown_method(self):
        r = run_poly_adapt("poly_does_not_exist", {})
        assert r["ok"] is False

    def test_list_methods_contains_v4(self):
        names = list_poly_adapt_methods()
        for n in V4_NAMES:
            assert n in names, f"{n} not in list_poly_adapt_methods()"
