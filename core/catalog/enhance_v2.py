"""core.catalog.enhance_v2 — phase 2.4 catalog re-enhancement.

The base ``core.catalog.enhance`` is the canonical single-pass
enricher. This module provides:

- ``reenhance_all(catalog_dir, level="full")`` — re-run enrichment
  for entries already on schema 1.0.0 to bring them up to 1.1.0
  (adding the new fields without overwriting existing content).

- ``enhance_pending(catalog_dir)`` — re-enhance only entries that
  have not yet been bumped to schema 1.1.0.

- The schema_version sentinel is ``_kfiosa_enriched_schema``. If
  the file already has it, the new fields are merged in; if it
  has a different value, the entry is re-enhanced in place.

Honest-degrade: we never fabricate CVE ids, stargazer counts, or
release versions. Anything we cannot compute from the entry's own
fields is omitted.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from .enhance import (
    SCHEMA_VERSION,
    _enrich_tags,
    _enrich_use_cases,
    _enrich_command_examples,
    _enrich_risk_signals,
    _enrich_attack_surface,
    _enrich_phase_hint,
    _enrich_requires_hardware,
    _enrich_polymorphic_strategies,
    _enrich_target_adaptive_targets,
)


def _maybe_reenhance(data: Dict[str, Any], level: str = "full") -> bool:
    """Apply the new v2 enrichers to ``data`` in place.

    Returns True if the entry was modified. ``level="full"`` always
    re-runs every enricher; ``level="light"`` only adds the new
    fields if missing.
    """
    if not isinstance(data, dict):
        return False
    current = data.get("_kfiosa_enriched_schema")
    modified = False

    # Pull the inputs the enrichers need.
    category = data.get("category", "") or ""
    name = data.get("name", "") or ""
    full_name = data.get("full_name", "") or ""

    if level == "full" or current != SCHEMA_VERSION:
        # Re-run the existing enrichers so all fields meet v2 mins.
        new_tags = _enrich_tags(data, category, name, full_name)
        if new_tags is not None:
            data["tags"] = new_tags
            modified = True
        new_uc = _enrich_use_cases(data, category)
        if new_uc is not None:
            data["use_cases"] = new_uc
            modified = True
        new_ce = _enrich_command_examples(data, category, name)
        if new_ce is not None:
            data["command_examples"] = new_ce
            modified = True
        new_rs = _enrich_risk_signals(data, category)
        if new_rs is not None:
            data.setdefault("risk", {})["signals"] = new_rs
            modified = True

    # New fields — always (re)compute. They are derived from
    # existing content so they never fabricate.
    new_as = _enrich_attack_surface(data, category, name)
    if new_as is not None:
        data["attack_surface"] = new_as
        modified = True
    new_ph = _enrich_phase_hint(data, category)
    if new_ph is not None:
        data["phase_hint"] = new_ph
        modified = True
    new_rh = _enrich_requires_hardware(data, category)
    if new_rh is not None:
        data["requires_hardware"] = new_rh
        modified = True
    new_ps = _enrich_polymorphic_strategies(data, category)
    if new_ps is not None:
        data["polymorphic_strategies"] = new_ps
        modified = True
    new_ta = _enrich_target_adaptive_targets(data, category)
    if new_ta is not None:
        data["target_adaptive_targets"] = new_ta
        modified = True

    if modified:
        # Preserve a newer deep-enhance stamp (e.g. 1.2.0) so reenhance
        # does not downgrade entries that already have 4x documentation.
        prev = str(current or "")
        if prev and prev > SCHEMA_VERSION:
            data["_kfiosa_enriched_schema"] = prev
        else:
            data["_kfiosa_enriched_schema"] = SCHEMA_VERSION
    return modified


def reenhance_one(path: Path, level: str = "full") -> Dict[str, Any]:
    """Re-enhance a single catalog file. Returns an envelope."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        return {"ok": False, "file": path.name, "error": f"read/parse: {e}"}
    if not isinstance(data, dict):
        return {"ok": False, "file": path.name, "error": "not an object"}
    # Snapshot before mutate so we can skip disk I/O when enrichers
    # are idempotent (common on re-runs of level=full).
    before = json.dumps(data, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    changed = _maybe_reenhance(data, level=level)
    if changed:
        after = json.dumps(data, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
        if after == before:
            # Enrichers flipped the modified flag but produced identical payload.
            changed = False
        else:
            try:
                path.write_text(
                    json.dumps(data, indent=2, ensure_ascii=False),
                    encoding="utf-8",
                )
            except OSError as e:
                return {"ok": False, "file": path.name, "error": f"write: {e}"}
    return {"ok": True, "file": path.name, "changed": changed,
            "schema": data.get("_kfiosa_enriched_schema")}


def reenhance_all(catalog_dir: Path, level: str = "full") -> Dict[str, Any]:
    """Re-enhance every entry in ``catalog_dir``.

    Returns ``{ok, total, changed, failed: [{file, error}], model}``.
    """
    catalog_dir = Path(catalog_dir)
    if not catalog_dir.exists():
        return {"ok": False, "total": 0, "error": f"not found: {catalog_dir}"}
    # Only github_*.json tool entries — skip catalog.schema.json / meta.
    files = sorted(catalog_dir.glob("github_*.json"))
    changed = 0
    failed: List[Dict[str, str]] = []
    for path in files:
        r = reenhance_one(path, level=level)
        if not r["ok"]:
            failed.append({"file": r["file"], "error": r["error"]})
        elif r["changed"]:
            changed += 1
    return {
        "ok": not failed,
        "total": len(files),
        "changed": changed,
        "failed": failed,
        "model": "enhance-v2",
    }


def enhance_pending(catalog_dir: Path) -> Dict[str, Any]:
    """Re-enhance only entries whose schema is not yet 1.1.0."""
    catalog_dir = Path(catalog_dir)
    if not catalog_dir.exists():
        return {"ok": False, "total": 0, "error": f"not found: {catalog_dir}"}
    files = sorted(catalog_dir.glob("github_*.json"))
    pending = 0
    changed = 0
    failed: List[Dict[str, str]] = []
    for path in files:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            failed.append({"file": path.name, "error": f"read/parse: {e}"})
            continue
        if not isinstance(data, dict):
            continue
        # Already at or above the base schema (1.1.0 / 1.2.0) → skip.
        cur = str(data.get("_kfiosa_enriched_schema") or "")
        if cur and cur >= SCHEMA_VERSION:
            continue
        pending += 1
        r = reenhance_one(path, level="full")
        if not r["ok"]:
            failed.append({"file": r["file"], "error": r["error"]})
        elif r["changed"]:
            changed += 1
    return {
        "ok": not failed,
        "pending": pending,
        "changed": changed,
        "failed": failed,
        "model": "enhance-pending",
    }


__all__ = ["reenhance_all", "enhance_pending", "reenhance_one"]
