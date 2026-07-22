#!/usr/bin/env python3
"""
Adversarial and Edge Case Tests for Milestone 1 Ported Algorithms & Registry.
Tests type mismatches, empty values, None inputs, extremely long strings,
and invalid nested types for the registered OSINT and Post-Exploitation
runner algorithms.
Verifies that calling all 8 functions returns a valid dictionary response
without raising unhandled exceptions.
"""

import socket
import pytest
from core.algorithm_registry import algo_registry
from core.osint.runner import OSINTRunner
from core.post_exploit.runner import PostExploitRunner


# Prevent accidental network calls during test execution
@pytest.fixture(autouse=True)
def block_network(monkeypatch):
    def block_socket_connect(*args, **kwargs):
        raise RuntimeError("Network access blocked in offline unit tests")
    monkeypatch.setattr(socket.socket, "connect", block_socket_connect)


# ==============================================================================
# OSINT ALGORITHMS ADVERSARIAL TESTS
# ==============================================================================

def test_osint_username_patterns_adversarial():
    runner = OSINTRunner()
    func = algo_registry.get("username_patterns")
    assert func is not None

    # 1. None input (should handle gracefully)
    res_none = func(runner, None)
    assert isinstance(res_none, dict)
    assert res_none["value"]["original"] == ""

    # 2. Integer input (unexpected type, should handle gracefully)
    res_int = func(runner, 12345)
    assert isinstance(res_int, dict)
    assert res_int["value"]["original"] == ""

    # 3. Extremely long string (stress test)
    long_username = "A" * 10000
    res = func(runner, long_username)
    assert res["value"]["original"] == long_username
    assert res["value"]["pattern_count"] > 0

    # 4. Unicode / Special characters
    unicode_username = "user_@_ñ_京_🔥"
    res_unicode = func(runner, unicode_username)
    assert res_unicode["value"]["original"] == unicode_username
    assert res_unicode["value"]["pattern_count"] > 0


def test_osint_breach_correlate_adversarial():
    runner = OSINTRunner()
    func = algo_registry.get("breach_correlate")
    assert func is not None

    # 1. None input
    res_none = func(runner, None)
    assert isinstance(res_none, dict)
    assert res_none["value"]["target"] == ""

    # 2. Integer input
    res_int = func(runner, 12345)
    assert isinstance(res_int, dict)
    assert res_int["value"]["target"] == ""

    # 3. Extremely long string
    long_input = "test" * 5000
    res = func(runner, long_input)
    assert res["value"]["target"] == long_input

    # 4. Special characters
    res_special = func(runner, "!@#$%^&*()_+{}|:\"<>?`-=[]\\;',./")
    assert "special_chars" in res_special["value"]["risk_indicators"]


def test_osint_phone_carrier_adversarial():
    runner = OSINTRunner()
    func = algo_registry.get("phone_carrier")
    assert func is not None

    # 1. None input
    res_none = func(runner, None)
    assert isinstance(res_none, dict)
    assert res_none["value"]["phone_number"] == ""

    # 2. Integer input
    res_int = func(runner, 12345)
    assert isinstance(res_int, dict)
    assert res_int["value"]["phone_number"] == ""

    # 3. Non-digit string (e.g. alphabetic)
    res_alpha = func(runner, "invalid_phone_number")
    assert res_alpha["value"]["carrier"] == "Unknown"
    assert res_alpha["value"]["country_code"] == "Unknown"

    # 4. Extremely long phone number
    long_number = "1" * 10000
    res_long = func(runner, long_number)
    assert res_long["value"]["cleaned_number"] == long_number


def test_osint_social_graph_adversarial():
    runner = OSINTRunner()
    func = algo_registry.get("social_graph")
    assert func is not None

    # 1. None input
    res_none = func(runner, None)
    assert isinstance(res_none, dict)
    assert res_none["value"]["social_handle"] == ""

    # 2. Integer input
    res_int = func(runner, 12345)
    assert isinstance(res_int, dict)
    assert res_int["value"]["social_handle"] == ""

    # 3. Extremely long handle
    long_handle = "@" + "a" * 10000
    res = func(runner, long_handle)
    assert res["value"]["cleaned_handle"] == "a" * 10000


# ==============================================================================
# POST-EXPLOITATION ALGORITHMS ADVERSARIAL TESTS
# ==============================================================================

def test_post_exploit_priv_esc_check_adversarial():
    runner = PostExploitRunner()
    func = algo_registry.get("priv_esc_check")
    assert func is not None

    # 1. None input
    res_none = func(runner, None)
    assert isinstance(res_none, dict)
    assert res_none["value"]["target_os"] == "unknown"

    # 2. Empty dict
    res_empty = func(runner, {})
    assert res_empty["value"]["target_os"] == "unknown"
    assert res_empty["value"]["privilege_escalation_vectors"] == []

    # 3. Non-dict nested details
    res_non_dict = func(runner, {"details": "not_a_dict"})
    assert isinstance(res_non_dict, dict)
    assert res_non_dict["value"]["target_os"] == "unknown"

    # 4. Service list of strings instead of list of dicts
    res_list_strings = func(
        runner, {"details": {"services": ["ssh", "mysql"]}}
    )
    assert isinstance(res_list_strings, dict)
    assert res_list_strings["value"]["privilege_escalation_vectors"] == []

    # 5. Service list with None element
    res_list_none = func(runner, {"details": {"services": [None]}})
    assert isinstance(res_list_none, dict)
    assert res_list_none["value"]["privilege_escalation_vectors"] == []

    # 6. Sudo rights with None element
    res_sudo_none = func(runner, {"details": {"sudo_rights": [None]}})
    assert isinstance(res_sudo_none, dict)
    assert res_sudo_none["value"]["privilege_escalation_vectors"] == []

    # 7. Sudo rights as a non-iterable (e.g. integer)
    res_sudo_int = func(runner, {"details": {"sudo_rights": 12345}})
    assert isinstance(res_sudo_int, dict)
    assert res_sudo_int["value"]["privilege_escalation_vectors"] == []


def test_post_exploit_cred_enumerate_adversarial():
    runner = PostExploitRunner()
    func = algo_registry.get("cred_enumerate")
    assert func is not None

    # 1. None input
    res_none = func(runner, None)
    assert isinstance(res_none, dict)
    assert res_none["value"]["target_type"] == "unknown"

    # 2. Empty dict
    res_empty = func(runner, {})
    assert res_empty["value"]["target_type"] == "unknown"

    # 3. Services list containing string
    res_srv_str = func(
        runner, {"details": {"is_linux": True, "services": ["telnet"]}}
    )
    assert isinstance(res_srv_str, dict)

    # 4. Services list containing None
    res_srv_none = func(
        runner, {"details": {"is_linux": True, "services": [None]}}
    )
    assert isinstance(res_srv_none, dict)


def test_post_exploit_lateral_movement_adversarial():
    runner = PostExploitRunner()
    func = algo_registry.get("lateral_movement")
    assert func is not None

    # 1. None input
    res_none = func(runner, None)
    assert isinstance(res_none, dict)

    # 2. Empty dict
    res_empty = func(runner, {})
    # opportunity_count includes common default techniques
    assert res_empty["value"]["opportunity_count"] > 0

    # 3. Shares list containing None
    res_shares_none = func(runner, {"details": {"shares": [None]}})
    assert isinstance(res_shares_none, dict)

    # 4. Trusts list containing None
    res_trusts_none = func(
        runner, {"details": {"is_windows": True, "trusts": [None]}}
    )
    assert isinstance(res_trusts_none, dict)

    # 5. Remote management list containing None
    res_rm_none = func(runner, {"details": {"remote_management": [None]}})
    assert isinstance(res_rm_none, dict)


def test_post_exploit_persistence_id_adversarial():
    runner = PostExploitRunner()
    func = algo_registry.get("persistence_id")
    assert func is not None

    # 1. None input
    res_none = func(runner, None)
    assert isinstance(res_none, dict)
    assert res_none["value"]["target_os"] == "unknown"

    # 2. Empty dict
    res_empty = func(runner, {})
    # cross_platform is always present
    assert res_empty["value"]["persistence_mechanisms"] != []

    # 3. details containing non-string OS
    res_os_int = func(runner, {"details": {"os": 12345}})
    assert isinstance(res_os_int, dict)
    assert res_os_int["value"]["target_os"] == "12345"
