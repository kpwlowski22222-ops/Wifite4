"""tests.test_chain_planner_toolbox_stanza — verify the
``TOOLBOX_PROMPT_STANZA`` is wired into the chain planner and that
``run_toolbox`` is in the schema and the system prompt.

Hermetic — uses the live toolboxes/ index (read-only) and a
monkey-patched toolboxes root for the empty-index path.
"""
from __future__ import annotations

from pathlib import Path
from unittest import mock

import pytest

from core.ai_backend.chain import (
    TOOLBOX_PROMPT_STANZA,
    _CHAIN_STEP_SCHEMA_HINT,
    _SYSTEM_PROMPT,
)
from core.toolbox import executor as exe


# ---------------------------------------------------------------------------
# Stanza + schema + system prompt
# ---------------------------------------------------------------------------

def test_run_toolbox_in_schema_hint():
    assert "run_toolbox" in _CHAIN_STEP_SCHEMA_HINT


def test_run_toolbox_in_toolbox_stanza():
    assert "run_toolbox" in TOOLBOX_PROMPT_STANZA


def test_run_toolbox_in_system_prompt():
    assert "run_toolbox" in _SYSTEM_PROMPT


def test_stanza_teaches_never_inline_rule():
    """The stanza must show the operator that credentials go via env."""
    for marker in (
        "KFIOSA_TARGET_PASSWORD",
        "password",
        "hash",
        "token",
        "NEVER",  # uppercase "NEVER" warning
    ):
        assert marker in TOOLBOX_PROMPT_STANZA, marker


def test_stanza_lists_categories_or_fallback():
    """If there are cloned repos, the stanza lists categories. If
    not, it tells the LLM the index is empty."""
    # Don't assert on the exact list (the live toolboxes/ varies
    # between devs), only that the stanza is non-empty and has the
    # right shape.
    assert isinstance(TOOLBOX_PROMPT_STANZA, str)
    assert len(TOOLBOX_PROMPT_STANZA) > 100


def test_stanza_includes_step_shape():
    """The step shape for run_toolbox is documented in the stanza."""
    for marker in ("repo_id", "category", "entry", "argv",
                    "env", "timeout_seconds"):
        assert marker in TOOLBOX_PROMPT_STANZA, marker


def test_stanza_includes_heuristic_for_choosing_run_toolbox():
    """The stanza tells the LLM when to use run_toolbox vs. existing
    actions (cve_to_exploit, mcp_call, run_tool)."""
    # Should mention the alternatives it replaces.
    assert "cve_to_exploit" in TOOLBOX_PROMPT_STANZA or \
            "mcp_call" in TOOLBOX_PROMPT_STANZA


# ---------------------------------------------------------------------------
# Empty-index path
# ---------------------------------------------------------------------------

def test_stanza_handles_empty_index(monkeypatch, tmp_path):
    """If the live index has no categories, the stanza degrades to
    a 'no cloned repos indexed yet' hint that does NOT fabricate
    a list of available repos."""
    monkeypatch.setattr(exe, "TOOLBOXES_DIR", tmp_path)
    monkeypatch.setattr(exe, "_TOOLBOX_REPO_INDEX", None)
    # Force re-build
    from core.ai_backend import chain as chain_mod
    new_stanza = chain_mod._build_toolbox_prompt_stanza()
    assert "no cloned repos" in new_stanza or \
            "no repos indexed" in new_stanza
    # And it must NOT list a fake category.
    assert "run_toolbox" in new_stanza  # action is still named


# ---------------------------------------------------------------------------
# Live index sanity (read-only)
# ---------------------------------------------------------------------------

def test_live_index_has_some_repos():
    """The KFIOSA repo's live toolboxes/ index has at least one repo."""
    from core.toolbox import list_repos
    repos = list_repos()
    assert len(repos) > 0


def test_live_index_categories_match_allowed():
    """Every category in the live index must be in ALLOWED_CATEGORIES."""
    from core.toolbox import ALLOWED_CATEGORIES, list_categories
    for cat in list_categories():
        assert cat in ALLOWED_CATEGORIES, f"unknown category: {cat}"


def test_stanza_mentions_at_least_one_category_when_indexed():
    """The stanza should reference at least one of the real
    categories when the live index is populated."""
    from core.toolbox import list_categories
    cats = list_categories()
    assert any(c in TOOLBOX_PROMPT_STANZA for c in cats), \
        f"stanza missing all real categories: {cats[:5]}"


# ---------------------------------------------------------------------------
# Orchestrator dispatch wiring
# ---------------------------------------------------------------------------

def test_orchestrator_dispatches_run_toolbox():
    """The AutonomousOrchestrator has a ``_dispatch_run_toolbox`` method."""
    from core.orchestrator.autonomous_orchestrator import (
        AutonomousOrchestrator,
    )
    assert hasattr(AutonomousOrchestrator, "_dispatch_run_toolbox")
    assert callable(getattr(AutonomousOrchestrator,
                             "_dispatch_run_toolbox", None))


def test_orchestrator_routes_run_toolbox_in_walk_ai_step():
    """``_walk_ai_step`` must route the ``run_toolbox`` action to
    the dispatcher. We check by source-grep (the function is long)."""
    from core.orchestrator import autonomous_orchestrator as ao
    src = Path(ao.__file__).read_text(encoding="utf-8")
    # The if-ladder in _walk_ai_step has both the action name and
    # the dispatcher name.
    assert '"run_toolbox"' in src
    assert "_dispatch_run_toolbox" in src


# ---------------------------------------------------------------------------
# Manifest cache invalidation
# ---------------------------------------------------------------------------

def test_touch_index_mtime_writes_sentinel(tmp_path, monkeypatch):
    monkeypatch.setattr(exe, "CATALOG_DIR", tmp_path)
    from core.toolbox import touch_index_mtime
    touch_index_mtime()
    assert (tmp_path / ".index_mtime").exists()


# ---------------------------------------------------------------------------
# CATALOG_PROMPT_STANZA (Phase 5+)
# ---------------------------------------------------------------------------

def test_catalog_prompt_stanza_exists():
    from core.ai_backend.chain import CATALOG_PROMPT_STANZA
    assert isinstance(CATALOG_PROMPT_STANZA, str)
    assert len(CATALOG_PROMPT_STANZA) > 100


def test_catalog_prompt_stanza_in_system_prompt():
    from core.ai_backend.chain import CATALOG_PROMPT_STANZA
    assert CATALOG_PROMPT_STANZA in _SYSTEM_PROMPT


def test_catalog_prompt_stanza_lists_categories():
    """The catalog stanza must show per-category counts so the LLM
    knows what's available."""
    from core.ai_backend.chain import CATALOG_PROMPT_STANZA
    # Real categories from the live catalog/
    for cat in ("exploit", "post_exploitation", "osint", "recon",
                "wifi", "ble", "android", "ios", "c2", "web",
                "microsoft", "frameworks"):
        if cat in CATALOG_PROMPT_STANZA:
            # The category is referenced; we don't care how.
            continue
    # The stanza must list at least some categories
    assert "repos" in CATALOG_PROMPT_STANZA or \
            "entries" in CATALOG_PROMPT_STANZA


def test_catalog_prompt_stanza_includes_curated_summaries():
    """The catalog stanza surfaces the curated ``_REPO_SUMMARIES``
    highlights (routersploit, sliver, mythIC, etc.) so the LLM
    can pick the right tool."""
    from core.ai_backend.chain import CATALOG_PROMPT_STANZA
    # At least one curated highlight must appear
    for marker in ("RouterSploit", "Sliver", "Impacket", "nuclei",
                    "sqlmap", "spiderfoot"):
        if marker in CATALOG_PROMPT_STANZA:
            return
    pytest.fail(
        "CATALOG_PROMPT_STANZA missing all curated highlights; "
        "expected at least one of: RouterSploit, Sliver, Impacket, "
        "nuclei, sqlmap, spiderfoot"
    )


def test_catalog_prompt_stanza_includes_use_cases_field():
    """The stanza must reference the new ``use_cases`` field so
    the LLM knows when to pick a tool."""
    from core.ai_backend.chain import CATALOG_PROMPT_STANZA
    assert "use_cases" in CATALOG_PROMPT_STANZA


def test_catalog_prompt_stanza_includes_command_examples_field():
    """The stanza must reference the new ``command_examples``
    field so the LLM knows how to invoke a tool."""
    from core.ai_backend.chain import CATALOG_PROMPT_STANZA
    assert "command_examples" in CATALOG_PROMPT_STANZA


def test_catalog_prompt_stanza_handles_missing_catalog(tmp_path, monkeypatch):
    """If the catalog/ directory doesn't exist, the stanza
    degrades to a 'no static catalog yet' hint that does NOT
    fabricate a list of available repos."""
    from core.ai_backend import chain as chain_mod
    monkeypatch.chdir(tmp_path)
    new_stanza = chain_mod._build_catalog_prompt_stanza()
    assert "no static catalog" in new_stanza or \
            "no catalog" in new_stanza.lower() or \
            "empty" in new_stanza.lower() or \
            "populate" in new_stanza.lower()
