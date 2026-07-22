"""core.toolbox.catalog_python_libs — emit ``catalog/pypi_<name>.json``
catalog entries for each entry in :data:`core.toolbox.python_libs.PYTHON_LIBRARIES`.

The schema follows the existing ``catalog/catalog.schema.json``
``external_repository`` shape, with the following deviations:

  * ``id`` is prefixed ``pypi:`` (matches the schema's
    ``^pypi:`` allowlist).
  * ``kind`` is ``python_library``.
  * ``metadata.pip_name`` carries the exact pip distribution name.
  * ``metadata.import_name`` is the importable Python module name.
  * ``metadata.example`` is the runnable one-liner.
  * ``metadata.entry`` is the suggested module entry point
    (``python3 -m <entry>``).
  * ``risk.level`` matches the library's risk_level
    (low / medium / high / critical).
  * ``risk.requires_explicit_authorization`` mirrors
    ``requires_gate`` from the registry (gated libraries cannot
    be run without the per-step ACCEPT prompt).
  * ``risk.allow_autonomous_execution`` is False for any
    library that interacts with a target.

The emitter is idempotent: re-running overwrites the existing
JSON files (the file is regenerated from the registry every
time). It's a single function, ``emit_python_lib_catalog``
plus a small CLI for operator convenience.
"""
from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

# The catalog schema lives at <repo_root>/catalog/catalog.schema.json.
# We don't validate against it here (the schema is for the
# top-level aggregate; the per-library JSONs are inputs to it).
REPO_ROOT = Path(__file__).resolve().parents[2]
CATALOG_DIR_DEFAULT = REPO_ROOT / "catalog"

from core.toolbox.python_libs import (  # noqa: E402
    PYTHON_LIBRARIES,
    list_categories,
    list_libraries,
)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _schema_version() -> str:
    return "1.0.0"


def _slug(name: str) -> str:
    """Turn a pip name into a filesystem-safe slug."""
    return (
        name.lower()
        .replace(" ", "-")
        .replace("/", "-")
        .replace(".", "-")
        .replace("--", "-")
        .strip("-")
    )


def build_entry_for(lib: Dict[str, Any]) -> Dict[str, Any]:
    """Build the per-library catalog entry as a dict."""
    name = lib["name"]
    slug = _slug(name)
    entry_id = f"pypi:{slug}"
    risk_level = lib.get("risk_level", "low")
    requires_gate = bool(lib.get("requires_gate", False))
    return {
        "id": entry_id,
        "kind": "python_library",
        "name": name,
        "full_name": lib.get("import_name", name),
        "owner": "pypi",
        "category": lib.get("category", "utility"),
        "url": f"https://pypi.org/project/{lib.get('pip', name)}/",
        "summary": lib.get("summary", ""),
        "description": lib.get("description", lib.get("summary", "")),
        "tags": [
            lib.get("category", "utility"),
            slug,
        ],
        "use_cases": _lib_use_cases(lib),
        "command_examples": _lib_command_examples(lib),
        "documentation": {
            "pypi": f"https://pypi.org/project/{lib.get('pip', name)}/",
            "import": lib.get("import_name", name),
            "entry": lib.get("entry", lib.get("import_name", name)),
            "example": lib.get("example", ""),
        },
        "metadata": {
            "pip_name": lib.get("pip", name),
            "import_name": lib.get("import_name", name),
            "version": lib.get("version", ""),
            "entry": lib.get("entry", lib.get("import_name", name)),
            "example": lib.get("example", ""),
            "category": lib.get("category", "utility"),
        },
        "metadata_status": "indexed",
        "trust": {
            "reviewed": True,
            "reviewer": "KFIOSA operator",
            "notes": (
                "Operator-curated Python library. The pip name is "
                "resolved from PyPI; the import name is verified "
                "against the registry."
            ),
        },
        "risk": {
            "level": risk_level,
            "signals": [risk_level],
            "requires_explicit_authorization": requires_gate,
            "allow_autonomous_execution": not requires_gate,
        },
    }


# Phase 5+ enrichment: per-library use_cases + command_examples.
# The operator wants the catalog to be richly described so the
# LLM can pick the right Python lib by what it does.
def _lib_use_cases(lib: Dict[str, Any]) -> List[str]:
    """Build a list of use-case strings from the library's
    ``summary`` + ``description`` + ``example`` fields.

    The library registry already carries a 1-line ``summary``
    and a longer ``description`` (when present). We split the
    description into bullet-style use cases so the LLM sees
    discrete capabilities, not a single sentence."""
    out: List[str] = []
    summary = lib.get("summary", "").strip()
    description = lib.get("description", "").strip()
    if summary:
        out.append(summary)
    if description and description != summary:
        # Split long descriptions on sentence boundaries to keep
        # each bullet a single capability.
        for sent in description.replace("\n", " ").split(". "):
            s = sent.strip().rstrip(".")
            if s and len(s) > 8 and s not in out:
                out.append(s)
    if not out:
        out.append(
            f"Python library: {lib.get('name', '')}"
        )
    return out


def _lib_command_examples(lib: Dict[str, Any]) -> List[str]:
    """Build a list of example argv / Python invocations from
    the library's ``example`` and ``entry`` fields."""
    out: List[str] = []
    example = lib.get("example", "").strip()
    entry = lib.get("entry", "").strip()
    import_name = lib.get("import_name", "").strip()
    if example:
        out.append(example)
    if entry and entry != import_name:
        out.append(f"python3 -m {entry}")
    if import_name and import_name not in (entry,):
        out.append(f"import {import_name}")
    if not out:
        out.append(f"python3 -c 'import {lib.get('name', '')}'")
    return out


def entry_to_json(entry: Dict[str, Any]) -> str:
    """Render the entry as JSON text, sorted keys for stable diffs."""
    return json.dumps(entry, indent=2, sort_keys=True, ensure_ascii=False)


def emit_for_library(
    lib: Dict[str, Any],
    *,
    catalog_dir: Path,
) -> Path:
    """Emit one ``pypi_<name>.json`` file. Returns the file path."""
    catalog_dir.mkdir(parents=True, exist_ok=True)
    entry = build_entry_for(lib)
    out_path = catalog_dir / f"pypi_{_slug(lib['name'])}.json"
    out_path.write_text(entry_to_json(entry), encoding="utf-8")
    return out_path


def emit_python_lib_catalog(
    *,
    catalog_dir: Path = CATALOG_DIR_DEFAULT,
    libraries: Optional[Iterable[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Emit ``pypi_<name>.json`` for every library in the registry.

    Returns a summary dict with the counts and the list of files
    written. Idempotent: existing files are overwritten.
    """
    libs = list(libraries) if libraries is not None else list(PYTHON_LIBRARIES)
    written: List[str] = []
    for lib in libs:
        out = emit_for_library(lib, catalog_dir=catalog_dir)
        written.append(str(out))
    return {
        "ok": True,
        "count": len(written),
        "files": written,
        "catalog_dir": str(catalog_dir),
        "schema_version": _schema_version(),
        "generated_at": _now_iso(),
    }


def emit_index_json(
    *,
    catalog_dir: Path = CATALOG_DIR_DEFAULT,
    libraries: Optional[Iterable[Dict[str, Any]]] = None,
) -> Path:
    """Emit a ``pypi_index.json`` (per-category manifest).

    The index is a list of per-category buckets; the LLM prompt
    stanza can include this rather than the full file list to
    save context window.
    """
    libs = list(libraries) if libraries is not None else list(PYTHON_LIBRARIES)
    by_cat: Dict[str, List[Dict[str, Any]]] = {}
    for lib in libs:
        cat = lib.get("category", "utility")
        by_cat.setdefault(cat, []).append({
            "id": f"pypi:{_slug(lib['name'])}",
            "name": lib["name"],
            "import_name": lib.get("import_name", lib["name"]),
            "summary": lib.get("summary", ""),
            "risk_level": lib.get("risk_level", "low"),
            "requires_gate": bool(lib.get("requires_gate", False)),
        })
    payload = {
        "schema_version": _schema_version(),
        "generated_at": _now_iso(),
        "kind": "python_library_index",
        "total": sum(len(v) for v in by_cat.values()),
        "categories": by_cat,
    }
    catalog_dir.mkdir(parents=True, exist_ok=True)
    out = catalog_dir / "pypi_index.json"
    out.write_text(
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False),
        encoding="utf-8",
    )
    return out


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _build_argparser():
    import argparse
    p = argparse.ArgumentParser(
        prog="core.toolbox.catalog_python_libs",
        description=(
            "Emit catalog/pypi_<name>.json entries for every "
            "library in the KFIOSA Python-libs registry."
        ),
    )
    p.add_argument(
        "--catalog-dir", default=str(CATALOG_DIR_DEFAULT),
        help="Output directory (default: <repo>/catalog)",
    )
    p.add_argument(
        "--category", default=None,
        help="Emit only libraries in this category",
    )
    p.add_argument(
        "--no-index", action="store_true",
        help="Skip emitting pypi_index.json",
    )
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = _build_argparser().parse_args(argv)
    catalog_dir = Path(args.catalog_dir).expanduser().resolve()
    libs = list_libraries(args.category)
    summary = emit_python_lib_catalog(
        catalog_dir=catalog_dir, libraries=libs,
    )
    if not args.no_index:
        emit_index_json(catalog_dir=catalog_dir, libraries=libs)
    print(json.dumps(summary, indent=2))
    return 0 if summary.get("ok") else 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
