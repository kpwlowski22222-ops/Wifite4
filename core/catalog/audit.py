"""core.catalog.audit — audit enhancements in the catalog.

Phase 2.4 — ``audit_enhancements(catalog_dir)`` returns a JSON
envelope with per-entry summary stats: tag count, use-case count,
command-example count, risk-signal count, presence of new fields
(``attack_surface``, ``phase_hint``, ``requires_hardware``,
``polymorphic_strategies``, ``target_adaptive_targets``).
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List


_NEW_FIELDS = (
    "attack_surface", "phase_hint", "requires_hardware",
    "polymorphic_strategies", "target_adaptive_targets",
)


def _entry_stats(path: Path, data: Any) -> Dict[str, Any]:
    tags = data.get("tags") if isinstance(data, dict) else None
    uc = data.get("use_cases") if isinstance(data, dict) else None
    ce = data.get("command_examples") if isinstance(data, dict) else None
    risk = data.get("risk") if isinstance(data, dict) else None
    signals = risk.get("signals") if isinstance(risk, dict) else None
    new_fields_present = {
        f: isinstance(data, dict) and f in data
        for f in _NEW_FIELDS
    }
    return {
        "file": path.name,
        "category": data.get("category") if isinstance(data, dict) else None,
        "schema_version": data.get("_kfiosa_enriched_schema")
            if isinstance(data, dict) else None,
        "tag_count": len(tags) if isinstance(tags, list) else 0,
        "use_case_count": len(uc) if isinstance(uc, list) else 0,
        "command_example_count": len(ce) if isinstance(ce, list) else 0,
        "risk_signal_count": len(signals) if isinstance(signals, list) else 0,
        "new_fields_present": new_fields_present,
    }


def audit_enhancements(catalog_dir: Path) -> Dict[str, Any]:
    """Walk ``catalog_dir`` and return aggregate stats.

    Returns ``{ok, files, total, schema_v1_1_0_count, by_category: {...},
    mean_counts: {...}, missing_new_fields: {field: [file, ...]}}``.
    """
    catalog_dir = Path(catalog_dir)
    if not catalog_dir.exists():
        return {"ok": False, "files": 0, "error": f"not found: {catalog_dir}"}

    files = sorted(catalog_dir.glob("*.json"))
    per_entry: List[Dict[str, Any]] = []
    by_category: Dict[str, int] = {}
    schema_v1_1_0 = 0
    sum_tags = sum_uc = sum_ce = sum_rs = 0
    missing: Dict[str, List[str]] = {f: [] for f in _NEW_FIELDS}
    failed: List[str] = []

    for path in files:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            failed.append(f"{path.name}: {e}")
            continue
        s = _entry_stats(path, data)
        per_entry.append(s)
        cat = s["category"] or "Other"
        by_category[cat] = by_category.get(cat, 0) + 1
        if s["schema_version"] == "1.1.0":
            schema_v1_1_0 += 1
        sum_tags += s["tag_count"]
        sum_uc += s["use_case_count"]
        sum_ce += s["command_example_count"]
        sum_rs += s["risk_signal_count"]
        for f, present in s["new_fields_present"].items():
            if not present:
                missing[f].append(path.name)

    n = max(len(per_entry), 1)
    return {
        "ok": not failed,
        "files": len(files),
        "parsed": len(per_entry),
        "failed": failed,
        "total": len(per_entry),
        "schema_v1_1_0_count": schema_v1_1_0,
        "by_category": by_category,
        "mean_counts": {
            "tags": round(sum_tags / n, 2),
            "use_cases": round(sum_uc / n, 2),
            "command_examples": round(sum_ce / n, 2),
            "risk_signals": round(sum_rs / n, 2),
        },
        "missing_new_fields": missing,
        "model": "catalog-audit",
    }


__all__ = ["audit_enhancements"]
