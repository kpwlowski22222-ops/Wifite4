#!/usr/bin/env python3
"""
Unit tests for the OSINT and Post-Exploitation MCP tool wrappers.
"""

from core.mcp import tools as mcp_tools


def test_custom_probes_list():
    """Verify that all 8 custom probes are in list_mcp_tools."""
    records = mcp_tools.list_mcp_tools()
    names = {r["name"] for r in records}

    expected_osint = {
        "osint_probe_username_patterns",
        "osint_probe_breach_correlate",
        "osint_probe_phone_carrier",
        "osint_probe_social_graph"
    }
    expected_post_expl = {
        "post_exploit_probe_priv_esc_check",
        "post_exploit_probe_cred_enumerate",
        "post_exploit_probe_lateral_movement",
        "post_exploit_probe_persistence_id"
    }

    for name in expected_osint:
        assert name in names
        rec = mcp_tools.get_mcp_tool(name)
        assert rec is not None
        assert rec["risk_level"] == "read"

    for name in expected_post_expl:
        assert name in names
        rec = mcp_tools.get_mcp_tool(name)
        assert rec is not None
        assert rec["risk_level"] == "read"


def test_custom_probes_filtering():
    """Verify list_mcp_tools domain filtering for custom probes."""
    osint_records = mcp_tools.list_mcp_tools(domain="osint")
    osint_names = {r["name"] for r in osint_records}
    assert "osint_probe_username_patterns" in osint_names
    assert "post_exploit_probe_priv_esc_check" not in osint_names

    post_expl_records = mcp_tools.list_mcp_tools(domain="post_exploitation")
    post_expl_names = {r["name"] for r in post_expl_records}
    assert "post_exploit_probe_priv_esc_check" in post_expl_names
    assert "osint_probe_username_patterns" not in post_expl_names


def test_call_osint_mcp_tools():
    """Verify execution of OSINT MCP tools via call_mcp_tool."""
    # 1. username_patterns
    res = mcp_tools.call_mcp_tool(
        "osint_probe_username_patterns",
        {"username": "test_user"}
    )
    assert res.get("ok") is True
    assert "test_user" in res["result"]["value"]["patterns"]

    # 2. breach_correlate
    res = mcp_tools.call_mcp_tool(
        "osint_probe_breach_correlate",
        {"email_or_username": "user@example.com"}
    )
    assert res.get("ok") is True
    assert "result" in res

    # 3. phone_carrier
    res = mcp_tools.call_mcp_tool(
        "osint_probe_phone_carrier",
        {"phone_number": "+15550199"}
    )
    assert res.get("ok") is True
    assert "result" in res

    # 4. social_graph
    res = mcp_tools.call_mcp_tool(
        "osint_probe_social_graph",
        {"social_handle": "test_handle"}
    )
    assert res.get("ok") is True
    assert "result" in res


def test_call_post_expl_mcp_tools():
    """Verify execution of Post-Exploitation MCP tools via call_mcp_tool."""
    target_info = {
        "details": {
            "os": "Linux",
            "services": [{"name": "mysql", "requires_auth": False}]
        }
    }

    # 1. priv_esc_check
    res = mcp_tools.call_mcp_tool(
        "post_exploit_probe_priv_esc_check",
        {"target_info": target_info}
    )
    assert res.get("ok") is True
    assert res["result"]["value"]["target_os"] == "linux"

    # 2. cred_enumerate
    res = mcp_tools.call_mcp_tool(
        "post_exploit_probe_cred_enumerate",
        {"target_info": target_info}
    )
    assert res.get("ok") is True

    # 3. lateral_movement
    res = mcp_tools.call_mcp_tool(
        "post_exploit_probe_lateral_movement",
        {"target_info": target_info}
    )
    assert res.get("ok") is True

    # 4. persistence_id
    res = mcp_tools.call_mcp_tool(
        "post_exploit_probe_persistence_id",
        {"target_info": target_info}
    )
    assert res.get("ok") is True
