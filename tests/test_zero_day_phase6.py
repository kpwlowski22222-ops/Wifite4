"""Hermetic tests for the 10 new Phase 6 polymorphic +
target-adaptive zero-day algorithms in
``core/ai_backend/zero_day_algorithms.py``.

These algorithms are PURE-DETERMINISTIC: they never call the LLM.
They return ``ok=True`` with a concept that the operator can
ACK before any destructive PoC attempt.
"""
import pytest

from core.ai_backend.zero_day_algorithms import (
    ZERO_DAY_ALGORITHMS, _build_registry,
    analyze_poly_buffer_boundary_prober,
    analyze_poly_crypto_primitive_combiner,
    analyze_poly_auth_flow_chain,
    analyze_poly_kernel_syscall_probe,
    analyze_poly_iot_protocol_fuzz,
    analyze_adapt_firmware_audit_strategy,
    analyze_adapt_api_endpoint_priority,
    analyze_adapt_cloud_misconfig_audit,
    analyze_adapt_supply_chain_audit,
    analyze_adapt_target_skill_path,
)


def test_10_phase6_algorithms_registered():
    _build_registry()
    expected = {
        "zero_day_poly_buffer_boundary_prober",
        "zero_day_poly_crypto_primitive_combiner",
        "zero_day_poly_auth_flow_chain",
        "zero_day_poly_kernel_syscall_probe",
        "zero_day_poly_iot_protocol_fuzz",
        "zero_day_adapt_firmware_audit_strategy",
        "zero_day_adapt_api_endpoint_priority",
        "zero_day_adapt_cloud_misconfig_audit",
        "zero_day_adapt_supply_chain_audit",
        "zero_day_adapt_target_skill_path",
    }
    assert expected <= set(ZERO_DAY_ALGORITHMS)


# ---------------------------------------------------------------------------
# Polymorphic
# ---------------------------------------------------------------------------
class TestPolyBufferBoundaryProber:
    def test_basic(self):
        res = analyze_poly_buffer_boundary_prober(
            {"name": "libfoo"}, {},
            {"signature": "void f(char *p, int n)"})
        assert res["ok"] is True
        assert "draft_id" in res
        assert res["vulnerability_class"] == "buffer_overflow"
        # concept has 6 vectors
        concept = res["concept"]
        assert "polymorphic boundary" in concept["title"].lower() or \
               "polymorphic" in concept["title"].lower()


class TestPolyCryptoPrimitiveCombiner:
    def test_basic(self):
        res = analyze_poly_crypto_primitive_combiner(
            {"name": "libcrypto"}, {}, {})
        assert res["ok"] is True
        assert res["vulnerability_class"] == "crypto_weakness"
        # 6 patterns enumerated
        assert len(res["concept"]["indicators"]) == 6


class TestPolyAuthFlowChain:
    def test_basic(self):
        res = analyze_poly_auth_flow_chain(
            {"name": "auth-service"}, {}, {})
        assert res["ok"] is True
        assert res["vulnerability_class"] == "auth_bypass"
        assert len(res["concept"]["indicators"]) == 8


class TestPolyKernelSyscallProbe:
    def test_basic(self):
        res = analyze_poly_kernel_syscall_probe(
            {"name": "linux-6.x"}, {}, {})
        assert res["ok"] is True
        assert res["vulnerability_class"] == "kernel_lpe"
        assert len(res["concept"]["indicators"]) == 6


class TestPolyIotProtocolFuzz:
    def test_basic(self):
        res = analyze_poly_iot_protocol_fuzz(
            {"name": "iot-camera"}, {}, {})
        assert res["ok"] is True
        assert res["vulnerability_class"] == "iot_protocol"
        assert len(res["concept"]["indicators"]) == 6


# ---------------------------------------------------------------------------
# Target-adaptive
# ---------------------------------------------------------------------------
class TestAdaptFirmwareAuditStrategy:
    @pytest.mark.parametrize("device_class,expected", [
        ("router", "web_admin_auth"),
        ("camera", "rtsp_auth"),
        ("printer", "pjl_cmd_inject"),
        ("iot", "mqtt_topic_acl"),
    ])
    def test_picker(self, device_class, expected):
        res = analyze_adapt_firmware_audit_strategy(
            {"name": "fw"}, {}, {"device_class": device_class})
        assert res["ok"] is True
        assert expected in res["concept"]["indicators"]


class TestAdaptApiEndpointPriority:
    @pytest.mark.parametrize("api_style,expected", [
        ("rest", "/admin"),
        ("graphql", "/graphql (introspection)"),
        ("grpc", "/grpc.reflection.v1alpha.ServerReflection"),
        ("soap", "/wsdl"),
    ])
    def test_picker(self, api_style, expected):
        res = analyze_adapt_api_endpoint_priority(
            {"name": "api"}, {}, {"api_style": api_style})
        assert res["ok"] is True
        assert expected in res["concept"]["indicators"]


class TestAdaptCloudMisconfigAudit:
    @pytest.mark.parametrize("cloud,expected", [
        ("aws", "S3 public-bucket"),
        ("azure", "Blob public access"),
        ("gcp", "GCS uniform-bucket-level access"),
        ("alibaba", "OSS public-bucket"),
    ])
    def test_picker(self, cloud, expected):
        res = analyze_adapt_cloud_misconfig_audit(
            {"name": "cloud"}, {}, {"cloud": cloud})
        assert res["ok"] is True
        assert expected in res["concept"]["indicators"]


class TestAdaptSupplyChainAudit:
    @pytest.mark.parametrize("eco,expected", [
        ("python", "pip install name confusion"),
        ("npm", "postinstall script"),
        ("maven", "pom.xml plugin"),
        ("go", "go module proxy"),
        ("cargo", "build.rs exec"),
    ])
    def test_picker(self, eco, expected):
        res = analyze_adapt_supply_chain_audit(
            {"name": "pkg"}, {}, {"ecosystem": eco})
        assert res["ok"] is True
        assert expected in res["concept"]["indicators"]


class TestAdaptTargetSkillPath:
    @pytest.mark.parametrize("target_class,expected", [
        ("web", "jwt_alg_confusion"),
        ("network", "ipv6_extension_header_fuzz"),
        ("iot", "mqtt_topic_acl"),
        ("cloud", "S3 public-bucket"),
        ("mobile", "mobile_intent"),
    ])
    def test_picker(self, target_class, expected):
        res = analyze_adapt_target_skill_path(
            {"name": "target"}, {}, {"target_class": target_class})
        assert res["ok"] is True
        assert expected in res["concept"]["indicators"]


# ---------------------------------------------------------------------------
# Never-fabricate
# ---------------------------------------------------------------------------
class TestNeverFabricate:
    """Phase 6 algorithms are deterministic — they never call the
    LLM, so they always return ok=True. But they must NEVER
    fabricate a real exploit / CVE / hash / credential. The
    concept they emit is always a plan / vector list, never a
    claim of a real bug."""

    def test_poly_buffer_boundary_no_cve(self):
        res = analyze_poly_buffer_boundary_prober(
            {"name": "x"}, {}, {"signature": "void f(char *p, int n)"})
        assert res["ok"] is True
        assert res["concept"]["cve_hint"] == ""
        assert "CVE-" not in res["concept"]["hypothesis"]

    def test_poly_crypto_no_real_weakness_claim(self):
        res = analyze_poly_crypto_primitive_combiner(
            {"name": "x"}, {}, {})
        assert res["ok"] is True
        # The hypothesis is about MAY (possibility), not a real claim
        assert "may" in res["concept"]["hypothesis"].lower()

    def test_adapt_no_cve_fabrication(self):
        res = analyze_adapt_firmware_audit_strategy(
            {"name": "x"}, {}, {"device_class": "router"})
        assert res["ok"] is True
        assert res["concept"]["cve_hint"] == ""
