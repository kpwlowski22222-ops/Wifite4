"""Catalog enhancement for KFIOSA.

The 884 ``catalog/github_*.json`` entries currently have
minimal metadata: ``summary: null``, ``tags: []`` (1-2 entries),
no ``use_cases`` / ``command_examples`` / ``risk.signals`` arrays.

This module enriches each entry IN PLACE — never modifying
``id``, ``kind``, ``full_name``, ``url``, ``category`` (anything
that breaks the catalog schema). It is idempotent: re-running on
an already-enriched file is a no-op.

The enrichment follows these rules (locked with the operator):

  * ``summary`` — 2-3 sentence description inferred from the
    ``name`` and ``category``. NEVER fabricates versions, CVEs,
    release dates. Defaults to a generic-but-honest description
    like: "Repository indexing entry for the ``<name>`` project
    in the ``<category>`` catalog. Review provenance, code,
    releases, and licence before use."

  * ``tags`` — expanded to 5-8 tags inferred from the
    category, name, and full_name. NO LIVING CVEs, NO library
    versions.

  * ``use_cases`` — 3-5 operator-curated-style hints for the
    LLM (e.g. "use after CVE fingerprint match on the
    associated vendor"). These are templates, not exploits.

  * ``command_examples`` — 3-5 argv examples for the
    ``run_toolbox`` step. NEVER inlines credentials. Uses
    ``$KFIOSA_TARGET_PASSWORD`` env-var style (a literal
    string marker, not the real variable expansion) so the
    LLM knows to substitute at runtime via env. Each example
    is a sanitized argv shape.

  * ``documentation.readme`` — first 4 KB if available (we
    never fabricate content here; we copy the existing or
    leave null).

  * ``trust.reviewed`` — keeps ``false`` for the auto-generated
    ones (we never claim to have reviewed code we haven't).

  * ``risk.signals`` — array of standardised signals
    ("offensive_tool", "intrinsic", "exploit", "credential",
    "remote", "local", "passive", "active") inferred from
    category.

  * ``metadata_status`` — "index_only" (default), "enriched"
    after this module touches it. The schema's three states
    ("index_only" | "toolbox_ready" | "enriched") are all
    supported; we only ever transition ``index_only`` →
    ``enriched``.

The module is hermetic: it never makes network calls, never
imports anything from outside ``core/``, never touches the
operator's working tree outside ``catalog/``.

Usage:
    >>> from pathlib import Path
    >>> from core.catalog.enhance import enhance_all
    >>> enhance_all(Path("catalog"))
    884

CLI:
    .venv/bin/python -m core.catalog.enhance --check
    .venv/bin/python -m core.catalog.enhance --apply
"""
from .enhance import (
    SCHEMA_VERSION,
    ENHANCED_TAG,
    enhance_file,
    enhance_all,
    build_enrichment_prompt_stanza,
    is_enhanced,
    DEFAULT_RISK_SIGNALS_BY_CATEGORY,
    CATEGORY_DESCRIPTORS,
)
from .enhance_v2 import reenhance_all, enhance_pending, reenhance_one
from .validate import validate_catalog
from .audit import audit_enhancements
from .github_generate import (
    generate_unlisted,
    find_unlisted,
    build_entry,
)

__all__ = [
    "SCHEMA_VERSION",
    "ENHANCED_TAG",
    "enhance_file",
    "enhance_all",
    "build_enrichment_prompt_stanza",
    "is_enhanced",
    "DEFAULT_RISK_SIGNALS_BY_CATEGORY",
    "CATEGORY_DESCRIPTORS",
    "reenhance_all",
    "enhance_pending",
    "reenhance_one",
    "validate_catalog",
    "audit_enhancements",
    "generate_unlisted",
    "find_unlisted",
    "build_entry",
]
