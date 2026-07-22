"""Tests for Tool Awareness (Part A).

Exercises:
  - mcp_tools_context_block renders tool's input_schema, examples, and risk_level.
  - Enriched catalog block renders command's usage, example, and risk.
"""

import pytest
from core.mcp.tools import mcp_tools_context_block
from core.utils.catalog_loader import CatalogEntry, Catalog

def test_mcp_tools_context_block_contains_metadata():
    block = mcp_tools_context_block(domain="wifi", limit=10)
    # The block should not be empty
    assert block != ""
    # Should contain some expected tools like airodump-ng
    assert "airodump-ng" in block
    assert "risk=" in block
    assert "schema:" in block
    assert "examples:" in block

def test_enriched_catalog_block_renders_commands():
    # Construct a sample CatalogEntry
    entry = CatalogEntry(
        id_="kali:wifite",
        kind="kali_source_package",
        name="wifite",
        title="wifite",
        summary="Automated wireless auditor",
        metapackages=["kali-tools-wireless"],
        install_apt="wifite",
        commands=[
            {
                "name": "wifite",
                "usage": "Attack surrounding wireless networks",
                "example": "wifite --dict wordlist.txt",
                "risk_level": "intrusive"
            }
        ],
        source_path="fake",
        extra={}
    )
    
    # Check that prompt_line renders the command metadata correctly
    line = entry.prompt_line()
    assert "wifite" in line
    assert "install=wifite" in line
    assert "cmd wifite:" in line
    assert "Attack surrounding wireless networks" in line
    assert "(risk=intrusive)" in line
    assert "ex: wifite --dict wordlist.txt" in line

    # Create a dummy Catalog and check context_block output
    cat = Catalog(entries=[entry])
    context = cat.context_block()
    assert "AVAILABLE KALI PACKAGES" in context
    assert "cmd wifite:" in context
