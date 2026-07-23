"""core.catalog.index — Phase 4 T21 optimization #1: catalog search index.

The catalog has 1461+ ``github_*.json`` entries. Naive search
(O(n) over all entries) becomes slow as the catalog grows.
This module builds an in-memory ``(attack_surface, phase_hint,
tag)`` triple-index for O(1) lookups.

The index is built once at import time (when ``build_index()``
runs) and refreshed on-demand by callers that mutate the catalog.

Per the never-fabricate rule: this module NEVER fakes CVE ids,
hash collisions, or cracked PSKs. The index is a pure data
structure over the existing catalog files.
"""
from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


# Module-level cache: triple_index[(surface, phase)] -> [entry_paths]
#   tag_index[tag] -> [entry_paths]
#   fulltext_index[lower_word] -> [entry_paths]
_INDEX: Dict[str, Any] = {
    "triple": {},       # (surface, phase) -> [paths]
    "tag": {},          # tag -> [paths]
    "fulltext": {},     # word -> [paths]
    "all": [],          # all paths
    "by_path": {},      # path -> entry dict
    "built_at": 0.0,
    "count": 0,
}
_INDEX_LOCK = threading.Lock()
_DEFAULT_CATALOG_DIR = Path(__file__).resolve().parents[2] / "catalog"


def _entry_payload(entry: Dict[str, Any]) -> Tuple[str, str, List[str], str]:
    """Extract (surface, phase, tags, fulltext) from a catalog entry."""
    surface = ""
    phase = ""
    tags: List[str] = []
    fulltext_parts: List[str] = []
    # attack_surface can be a list or a string
    surf = entry.get("attack_surface")
    if isinstance(surf, list) and surf:
        surface = str(surf[0]).lower()
    elif isinstance(surf, str):
        surface = surf.lower()
    # phase_hint
    ph = entry.get("phase_hint")
    if isinstance(ph, list) and ph:
        phase = str(ph[0]).lower()
    elif isinstance(ph, str):
        phase = ph.lower()
    # tags
    raw_tags = entry.get("tags")
    if isinstance(raw_tags, list):
        for t in raw_tags:
            if isinstance(t, str):
                tags.append(t.lower())
    # fulltext corpus: name, summary, full_name, category, description
    for key in ("name", "summary", "full_name", "category",
                "description", "kind"):
        v = entry.get(key)
        if isinstance(v, str):
            fulltext_parts.append(v.lower())
    fulltext = " ".join(fulltext_parts)
    return surface, phase, tags, fulltext


def _index_one(path: Path, data: Dict[str, Any]) -> None:
    """Add one entry to the index."""
    _INDEX["all"].append(str(path))
    _INDEX["by_path"][str(path)] = data
    surface, phase, tags, fulltext = _entry_payload(data)
    # Triple index: (surface, phase) -> [paths]
    if surface or phase:
        key = f"{surface}|{phase}"
        _INDEX["triple"].setdefault(key, []).append(str(path))
    # Tag index
    for tag in tags:
        _INDEX["tag"].setdefault(tag, []).append(str(path))
    # Fulltext index: split on whitespace, lowercase, drop tiny words
    for word in fulltext.split():
        w = word.strip(".,:;()[]{}<>?!\"'`")
        if len(w) >= 3:
            _INDEX["fulltext"].setdefault(w, []).append(str(path))


def build_index(catalog_dir: Optional[Path] = None,
                force: bool = False) -> Dict[str, Any]:
    """Build (or rebuild) the catalog search index.

    Returns a summary envelope ``{ok, count, built_at, took_s}``.
    Never raises; returns ``{ok: False, error}`` on failure.
    """
    global _INDEX
    catalog_dir = catalog_dir or _DEFAULT_CATALOG_DIR
    if not force and _INDEX.get("count", 0) > 0 and (
            _INDEX.get("catalog_dir") == str(catalog_dir)):
        return {
            "ok": True,
            "count": _INDEX["count"],
            "built_at": _INDEX["built_at"],
            "took_s": 0.0,
            "cached": True,
        }
    t0 = time.time()
    new_index: Dict[str, Any] = {
        "triple": {},
        "tag": {},
        "fulltext": {},
        "all": [],
        "by_path": {},
        "built_at": 0.0,
        "count": 0,
        "catalog_dir": str(catalog_dir),
    }
    old_index = _INDEX
    try:
        _INDEX = new_index
        if not catalog_dir.exists():
            return {"ok": False, "error": f"catalog dir not found: {catalog_dir}"}
        count = 0
        # Index all catalog JSON (github_*, kali_*, pypi_*, …) except schema
        _skip = {"catalog.schema.json", "catalog.txt", "catalog.min.json"}
        for path in catalog_dir.glob("*.json"):
            if path.name in _skip:
                continue
            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
            except Exception:  # noqa: BLE001
                continue
            _index_one(path, data)
            count += 1
        _INDEX["count"] = count
        _INDEX["built_at"] = time.time()
        took = time.time() - t0
        return {
            "ok": True,
            "count": count,
            "built_at": _INDEX["built_at"],
            "took_s": round(took, 3),
            "cached": False,
        }
    except Exception as e:  # noqa: BLE001
        _INDEX = old_index
        return {"ok": False, "error": f"build_index: {e}"}


def search_memory(attack_surface: str = "",
                  phase_hint: str = "",
                  tag: str = "",
                  text: str = "",
                  limit: int = 50,
                  catalog_dir: Optional[Path] = None) -> List[Dict[str, Any]]:
    """In-memory index search only (no SQL router — safe for internal use)."""
    if _INDEX.get("count", 0) == 0:
        build_index(catalog_dir)
    return _search_memory_impl(
        attack_surface=attack_surface,
        phase_hint=phase_hint,
        tag=tag,
        text=text,
        limit=limit,
    )


def _search_memory_impl(
    *,
    attack_surface: str = "",
    phase_hint: str = "",
    tag: str = "",
    text: str = "",
    limit: int = 50,
) -> List[Dict[str, Any]]:
    paths: Optional[List[str]] = None
    if attack_surface and phase_hint:
        key = f"{attack_surface.lower()}|{phase_hint.lower()}"
        paths = list(_INDEX["triple"].get(key, []))
    elif attack_surface:
        # match any phase with that surface
        for k, v in _INDEX["triple"].items():
            if k.startswith(attack_surface.lower() + "|"):
                paths = (paths or []) + v
    elif phase_hint:
        # match any surface with that phase
        for k, v in _INDEX["triple"].items():
            if k.endswith("|" + phase_hint.lower()):
                paths = (paths or []) + v
    if tag:
        tag_paths = set(_INDEX["tag"].get(tag.lower(), []))
        paths = [p for p in (paths or _INDEX["all"]) if p in tag_paths]
    if text:
        text_lower = text.lower()
        # all words in text must appear in the fulltext index
        words = [w.strip(".,:;()[]{}<>?!\"'`")
                 for w in text_lower.split() if len(w) >= 3]
        if not words:
            words = [text_lower]
        candidate_sets = [set(_INDEX["fulltext"].get(w, [])) for w in words]
        if candidate_sets:
            text_paths = set.intersection(*candidate_sets) if len(candidate_sets) > 1 else candidate_sets[0]
        else:
            text_paths = set()
        paths = [p for p in (paths or _INDEX["all"]) if p in text_paths]
    if paths is None:
        paths = list(_INDEX["all"])
    # Dedupe while preserving order
    seen = set()
    out: List[Dict[str, Any]] = []
    for p in paths:
        if p in seen:
            continue
        seen.add(p)
        entry = _INDEX["by_path"].get(p)
        if entry is not None:
            out.append(entry)
        if len(out) >= limit:
            break
    return out


def search(attack_surface: str = "",
           phase_hint: str = "",
           tag: str = "",
           text: str = "",
           limit: int = 50,
           catalog_dir: Optional[Path] = None,
           prefer: str = "") -> List[Dict[str, Any]]:
    """Search catalog — SQL when ready (router), else in-memory index.

    Set ``prefer`` to ``sql`` / ``memory`` / ``json`` to force a source.
    """
    prefer = (prefer or "").strip().lower()
    if prefer in ("memory", "json"):
        return search_memory(
            attack_surface=attack_surface,
            phase_hint=phase_hint,
            tag=tag,
            text=text,
            limit=limit,
            catalog_dir=catalog_dir,
        )
    # Prefer SQL via router (no recursion — fetch uses search_memory)
    try:
        from core.catalog.source_router import fetch as catalog_fetch
        routed = catalog_fetch(
            attack_surface=attack_surface,
            phase_hint=phase_hint,
            tag=tag,
            text=text,
            limit=limit,
            prefer=prefer or "",
            catalog_dir=catalog_dir,
        )
        if routed.get("ok") and routed.get("source_used") == "sql":
            return list(routed.get("results") or [])
        if routed.get("ok") and routed.get("results") is not None:
            return list(routed.get("results") or [])
    except Exception:  # noqa: BLE001
        pass
    return search_memory(
        attack_surface=attack_surface,
        phase_hint=phase_hint,
        tag=tag,
        text=text,
        limit=limit,
        catalog_dir=catalog_dir,
    )


def index_stats() -> Dict[str, Any]:
    """Return index stats for the dashboard."""
    return {
        "ok": True,
        "count": _INDEX.get("count", 0),
        "built_at": _INDEX.get("built_at", 0.0),
        "triple_buckets": len(_INDEX.get("triple", {})),
        "tag_buckets": len(_INDEX.get("tag", {})),
        "fulltext_buckets": len(_INDEX.get("fulltext", {})),
    }


def reset() -> None:
    """Reset the index (test helper)."""
    global _INDEX
    _INDEX = {
        "triple": {},
        "tag": {},
        "fulltext": {},
        "all": [],
        "by_path": {},
        "built_at": 0.0,
        "count": 0,
    }


__all__ = [
    "build_index",
    "search",
    "index_stats",
    "reset",
]
