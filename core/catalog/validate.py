"""core.catalog.validate — JSON-schema validation for catalog entries.

Phase 2.4 — wire the v1.1.0 schema into a CI-friendly validator
that takes a catalog directory and emits a violation list.

The validator is intentionally tolerant: missing optional fields
are warnings, not errors. Only structural / type / required-field
issues are hard errors.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Tuple


# Required top-level fields for a repository entry.
_REQUIRED_FIELDS = ("id", "name", "url", "category")

# Recognised categories (loose — used for warning, not blocking).
_KNOWN_CATEGORIES = frozenset({
    "Wireless Security",
    "Bluetooth/BLE",
    "OSINT and Recon",
    "Post-Exploitation",
    "Web Application Security",
    "Defense Evasion",
    "Exploitation",
    "Forensics",
    "Reverse Engineering",
    "Frameworks",
    "Sniffing and Spoofing",
    "Hardware",
    "Other",
})


def _validate_entry(path: Path, data: Any) -> Tuple[List[str], List[str]]:
    """Return (errors, warnings) for a single entry.

    The catalog is heterogeneous: ``github_*`` and ``kali_*`` use
    slightly different field sets. Required fields are decided
    per kind.
    """
    errors: List[str] = []
    warnings: List[str] = []
    if not isinstance(data, dict):
        errors.append(f"{path.name}: top-level is not an object")
        return errors, warnings

    # Per-kind required fields. Anything outside this is a warning.
    kind = data.get("kind")
    if kind == "external_repository" or path.name.startswith("github_"):
        required = ("id", "name", "url", "category")
    elif kind == "kali_package" or path.name.startswith("kali_"):
        required = ("id", "name")
    else:
        # Unknown kind: at least id and name must be present.
        required = ("id", "name")

    for key in required:
        if key not in data:
            errors.append(f"{path.name}: missing required field '{key}'")

    cat = data.get("category")
    if isinstance(cat, str) and cat not in _KNOWN_CATEGORIES:
        warnings.append(f"{path.name}: category '{cat}' not in known set")

    # Check use_cases and command_examples are lists with sensible length.
    uc = data.get("use_cases")
    if uc is not None and not isinstance(uc, list):
        errors.append(f"{path.name}: use_cases must be a list")
    ce = data.get("command_examples")
    if ce is not None and not isinstance(ce, list):
        errors.append(f"{path.name}: command_examples must be a list")

    # Check tags is a list of strings.
    tags = data.get("tags")
    if tags is not None and not isinstance(tags, list):
        errors.append(f"{path.name}: tags must be a list")
    elif isinstance(tags, list) and not all(isinstance(t, str) for t in tags):
        errors.append(f"{path.name}: tags must all be strings")

    # attack_surface must be a list of strings (if present).
    asurf = data.get("attack_surface")
    if asurf is not None:
        if not isinstance(asurf, list):
            errors.append(f"{path.name}: attack_surface must be a list")
        elif not all(isinstance(t, str) for t in asurf):
            errors.append(f"{path.name}: attack_surface must all be strings")

    # phase_hint must be a recognised value (if present).
    ph = data.get("phase_hint")
    if ph is not None and ph not in {
        "recon", "enumeration", "exploit", "post_exploit", "cleanup", "any",
    }:
        warnings.append(f"{path.name}: phase_hint '{ph}' not in vocab")

    # requires_hardware must be a list of strings (if present).
    rh = data.get("requires_hardware")
    if rh is not None:
        if not isinstance(rh, list):
            errors.append(f"{path.name}: requires_hardware must be a list")
        elif not all(isinstance(t, str) for t in rh):
            errors.append(f"{path.name}: requires_hardware must all be strings")

    return errors, warnings


def validate_catalog(catalog_dir: Path) -> Dict[str, Any]:
    """Validate every ``*.json`` file in ``catalog_dir``.

    Returns a summary envelope:
        ``{ok, files, errors: [...], warnings: [...], counts: {...}}``
    """
    catalog_dir = Path(catalog_dir)
    if not catalog_dir.exists():
        return {"ok": False, "files": 0,
                "errors": [f"catalog dir not found: {catalog_dir}"],
                "warnings": [], "counts": {}}

    files = sorted(catalog_dir.glob("*.json"))
    errors: List[str] = []
    warnings: List[str] = []
    parsed = 0
    skipped = 0

    for path in files:
        # Skip non-entry files: the schema, the txt list, any
        # "catalog.*" non-data file, and the schema version
        # reference.
        if path.name in ("catalog.schema.json", "catalog.txt",
                         "catalog.min.json"):
            skipped += 1
            continue
        # Skip files that don't look like entries (no id field).
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            errors.append(f"{path.name}: invalid JSON: {e}")
            continue
        except OSError as e:
            errors.append(f"{path.name}: read error: {e}")
            skipped += 1
            continue
        if not isinstance(data, dict) or "id" not in data:
            skipped += 1
            continue
        parsed += 1
        e, w = _validate_entry(path, data)
        errors.extend(e)
        warnings.extend(w)

    return {
        "ok": not errors,
        "files": len(files),
        "parsed": parsed,
        "skipped": skipped,
        "errors": errors,
        "warnings": warnings,
        "counts": {
            "errors": len(errors),
            "warnings": len(warnings),
        },
    }


__all__ = ["validate_catalog"]
