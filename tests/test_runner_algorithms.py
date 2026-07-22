#!/usr/bin/env python3
"""
Unit tests for the registered runner algorithms.
Verifies the 8 OSINT & post-exploitation algorithms, their registry
registration, and that they all run safely offline.
"""

import socket
import pytest
from core.algorithm_registry import algo_registry
from core.osint.runner import OSINTRunner
from core.post_exploit.runner import PostExploitRunner


# Prevent any accidental network calls during test execution
@pytest.fixture(autouse=True)
def block_network(monkeypatch):
    def block_socket_connect(*args, **kwargs):
        raise RuntimeError("Network access blocked in offline unit tests")
    monkeypatch.setattr(socket.socket, "connect", block_socket_connect)


def test_algorithm_registration():
    """Verify that all 8 algorithms are registered in algo_registry."""
    expected_algos = {
        "username_patterns",
        "breach_correlate",
        "phone_carrier",
        "social_graph",
        "priv_esc_check",
        "cred_enumerate",
        "lateral_movement",
        "persistence_id"
    }
    registered = algo_registry.list_registered()
    for algo in expected_algos:
        assert algo in registered, f"Algorithm {algo} not registered"

        # Verify metadata is populated
        metadata = algo_registry.get_metadata(algo)
        assert metadata is not None
        assert metadata["name"] == algo
        assert metadata["func"] is not None
        assert metadata["description"] is not None

    # Verify domains and list_by_domain
    osint_algos = {
        "username_patterns", "breach_correlate",
        "phone_carrier", "social_graph"
    }
    post_expl_algos = {
        "priv_esc_check", "cred_enumerate",
        "lateral_movement", "persistence_id"
    }

    for algo in osint_algos:
        metadata = algo_registry.get_metadata(algo)
        assert metadata["domain"] == "osint"

    for algo in post_expl_algos:
        metadata = algo_registry.get_metadata(algo)
        assert metadata["domain"] == "post_exploitation"

    osint_list = algo_registry.list_by_domain("osint")
    assert len(osint_list) == len(osint_algos)
    assert {m["name"] for m in osint_list} == osint_algos

    post_expl_list = algo_registry.list_by_domain("post_exploitation")
    assert len(post_expl_list) == len(post_expl_algos)
    assert {m["name"] for m in post_expl_list} == post_expl_algos


def test_osint_username_patterns():
    """Test the username_patterns algorithm."""
    runner = OSINTRunner()
    func = algo_registry.get("username_patterns")
    assert func is not None

    # Normal case
    res = func(runner, "AdminUser")
    assert res["type"] == "username_patterns"
    assert res["source"] == "_analyze_username_patterns"
    val = res["value"]
    assert val["original"] == "AdminUser"
    assert "adminuser" in val["patterns"]
    assert val["pattern_count"] > 0

    # Edge case: short/empty username
    res_empty = func(runner, "")
    assert res_empty["value"]["original"] == ""
    assert res_empty["value"]["pattern_count"] > 0


def test_osint_breach_correlate():
    """Test the breach_correlate algorithm."""
    runner = OSINTRunner()
    func = algo_registry.get("breach_correlate")
    assert func is not None

    # Target with numbers
    res_nums = func(runner, "test1234")
    assert res_nums["type"] == "breach_correlation"
    assert res_nums["value"]["target"] == "test1234"
    assert "contains_numbers" in res_nums["value"]["risk_indicators"]

    # Short target
    res_short = func(runner, "abc")
    assert "short_length" in res_short["value"]["risk_indicators"]


def test_osint_phone_carrier():
    """Test the phone_carrier algorithm."""
    runner = OSINTRunner()
    func = algo_registry.get("phone_carrier")
    assert func is not None

    # US Carrier check
    res_us = func(runner, "+12015551234")
    assert res_us["type"] == "phone_carrier_inference"
    assert res_us["value"]["carrier"] == "AT&T"
    assert res_us["value"]["area_code"] == "201"

    # International Carrier check
    res_intl = func(runner, "+331234567")
    assert res_intl["value"]["country_code"] == "33"
    assert "Orange/France Telecom" in res_intl["value"]["carrier"]

    # Invalid carrier check
    res_unknown = func(runner, "abc")
    assert res_unknown["value"]["carrier"] == "Unknown"


def test_osint_social_graph():
    """Test the social_graph algorithm."""
    runner = OSINTRunner()
    func = algo_registry.get("social_graph")
    assert func is not None

    # Handle with underscore
    res_underscore = func(runner, "@alice_bob")
    assert res_underscore["type"] == "social_relationship_mapping"
    relationships = res_underscore["value"]["identified_relationships"]
    assert any(r["type"] == "potential_collaboration" for r in relationships)

    # Handle with number suffix
    res_suffix = func(runner, "@charlie123")
    relationships = res_suffix["value"]["identified_relationships"]
    assert any(r["type"] == "sequential_account" for r in relationships)


def test_post_exploit_priv_esc_check():
    """Test the priv_esc_check algorithm with dictionary service lists."""
    runner = PostExploitRunner()
    func = algo_registry.get("priv_esc_check")
    assert func is not None

    # Mock target info
    target_info = {
        "details": {
            "os": "Linux",
            "kernel_version": "2.6.32",
            "services": [
                {"name": "mysql", "requires_auth": False},
                {"name": "ssh", "requires_auth": True}
            ],
            "sudo_rights": ["ALL NOPASSWD: ALL"]
        }
    }
    res = func(runner, target_info)
    assert res["type"] == "privilege_escalation_assessment"
    val = res["value"]
    assert val["target_os"] == "linux"

    vectors = val["privilege_escalation_vectors"]
    assert any(v["vector"] == "kernel_exploit" for v in vectors)
    assert any(v["vector"] == "unauthenticated_service" for v in vectors)
    assert any(v["vector"] == "misconfigured_sudo" for v in vectors)


def test_post_exploit_cred_enumerate():
    """Test the cred_enumerate algorithm."""
    runner = PostExploitRunner()
    func = algo_registry.get("cred_enumerate")
    assert func is not None

    target_info = {
        "details": {
            "is_linux": True,
            "services": [
                {"name": "telnet", "port": 23}
            ]
        }
    }
    res = func(runner, target_info)
    assert res["type"] == "credential_enumeration"
    val = res["value"]
    assert val["target_type"] == "linux"

    sources = val["credential_sources"]
    assert any("telnet" in s["location"] for s in sources)


def test_post_exploit_lateral_movement():
    """Test the lateral_movement algorithm."""
    runner = PostExploitRunner()
    func = algo_registry.get("lateral_movement")
    assert func is not None

    target_info = {
        "details": {
            "is_windows": True,
            "shares": [
                {"path": "\\\\target\\ADMIN$", "permissions": "full_control"}
            ],
            "trusts": [
                {"type": "domain", "transitive": True, "target": "other.local"}
            ]
        }
    }
    res = func(runner, target_info)
    assert res["type"] == "lateral_movement_assessment"
    val = res["value"]

    opps = val["lateral_movement_opportunities"]
    assert any(o["opportunity"] == "network_share" for o in opps)
    assert any(o["opportunity"] == "trust_relationship" for o in opps)


def test_post_exploit_persistence_id():
    """Test the persistence_id algorithm."""
    runner = PostExploitRunner()
    func = algo_registry.get("persistence_id")
    assert func is not None

    target_info = {
        "details": {
            "os": "Windows Server 2019"
        }
    }
    res = func(runner, target_info)
    assert res["type"] == "persistence_identification"
    val = res["value"]
    assert val["target_os"] == "windows server 2019"
    assert val["mechanism_count"] > 0


def test_comprehensive_adversarial_hardening():
    """Validate that calling all 8 functions with None, empty inputs,
    type mismatches, and nested null/missing keys returns a valid dict.
    """
    osint_runner = OSINTRunner()
    post_expl_runner = PostExploitRunner()

    osint_algos = [
        "username_patterns", "breach_correlate",
        "phone_carrier", "social_graph"
    ]
    post_expl_algos = [
        "priv_esc_check", "cred_enumerate",
        "lateral_movement", "persistence_id"
    ]

    # 1. Adversarial inputs for OSINT algorithms (None, int, empty, list)
    adversarial_inputs = [None, 12345, "", [], {}]
    for algo_name in osint_algos:
        func = algo_registry.get(algo_name)
        assert func is not None
        for adv_input in adversarial_inputs:
            res = func(osint_runner, adv_input)
            assert isinstance(res, dict)
            assert "type" in res
            assert "value" in res
            assert "source" in res

    # 2. Adversarial inputs for Post-Exploitation algorithms (None, empty,
    # type mismatches, nested nulls/missing keys)
    post_expl_adversarial_inputs = [
        None,
        {},
        {"details": None},
        {"details": "malformed"},
        {"details": {
            "services": None, "shares": None,
            "remote_management": None, "sudo_rights": None
        }},
        {"details": {
            "services": ["not_a_dict"], "shares": [123],
            "remote_management": ["not_dict"], "sudo_rights": [None, 123]
        }},
        {"details": {
            "services": [None], "shares": [None],
            "remote_management": [None], "sudo_rights": None
        }},
        {"details": {
            "services": [{"name": None, "requires_auth": None}],
            "shares": [{"permissions": None}],
            "remote_management": [{"enabled": None}]
        }},
        {"details": {
            "os": 123, "architecture": None,
            "kernel_version": {}, "domain_or_workgroup": []
        }},
        {"details": {"is_linux": "yes", "is_windows": 1, "is_unix": []}},
    ]

    for algo_name in post_expl_algos:
        func = algo_registry.get(algo_name)
        assert func is not None
        for adv_input in post_expl_adversarial_inputs:
            res = func(post_expl_runner, adv_input)
            assert isinstance(res, dict)
            assert "type" in res
            assert "value" in res
            assert "source" in res
