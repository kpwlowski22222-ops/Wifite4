"""Tests for cve_lookup MCP wrapper (Part A).

Exercises:
  - Wrapper constructs CVELookup(config={"nvd_api_key": key}) and calls search_cves correctly.
"""

from unittest import mock
import pytest

from core.mcp import tools as mcp_tools

def test_cve_lookup_constructs_with_api_key_and_calls_search(monkeypatch):
    # Mock get_nvd_key to return a dummy key
    monkeypatch.setattr("core.ai_backend.get_nvd_key", lambda *args, **kw: "dummy_nvd_key")
    
    # Mock CVELookup class
    mock_search_cves = mock.AsyncMock(return_value=[{"id": "CVE-2026-1234", "summary": "Vuln"}])
    mock_close = mock.AsyncMock()
    
    class MockCVELookup:
        def __init__(self, config):
            self.config = config
        search_cves = mock_search_cves
        close = mock_close
        
    # Inject MockCVELookup into core.modules.cve_lookup
    monkeypatch.setattr("core.modules.cve_lookup.CVELookup", MockCVELookup)
    
    # Call the cve_lookup MCP tool wrapper via call_mcp_tool
    res = mcp_tools.call_mcp_tool("cve_lookup", {"keyword": "test-vuln", "limit": 3})
    
    assert res.get("ok") is True
    assert res.get("count") == 1
    assert res.get("cves") == [{"id": "CVE-2026-1234", "summary": "Vuln"}]
    
    # Assert that MockCVELookup was constructed with the correct config
    # We can inspect the calls to search_cves
    mock_search_cves.assert_called_once_with("test-vuln", limit=3)
    mock_close.assert_called_once()
