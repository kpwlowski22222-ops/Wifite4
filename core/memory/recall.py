"""Keyword recall over working memory (RAG-lite, no hard ML dependency)."""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from core.memory.store import list_notes, memory_enabled


def _tokens(s: str) -> List[str]:
    return [t for t in re.split(r"[^a-z0-9]+", (s or "").lower()) if len(t) >= 2]


def recall(
    query: str,
    *,
    domain: str = "",
    target_key: str = "",
    limit: int = 8,
) -> Dict[str, Any]:
    """Retrieve relevant memory notes for planner/TUI continuity."""
    if not memory_enabled():
        return {"ok": True, "hits": [], "skipped": "memory_disabled"}
    q = (query or "").strip()
    q_toks = set(_tokens(q + " " + target_key + " " + domain))
    notes = list_notes(domain=domain or "", target_key="", limit=200)
    # Prefer exact target_key matches first
    scored: List[Dict[str, Any]] = []
    for n in notes:
        text = f"{n.get('text', '')} {n.get('target_key', '')} {n.get('kind', '')}"
        n_toks = set(_tokens(text))
        score = 0
        if target_key and n.get("target_key") == target_key:
            score += 10
        if domain and n.get("domain") == domain:
            score += 3
        score += len(q_toks & n_toks)
        if score <= 0 and not target_key:
            continue
        if score <= 0 and target_key and n.get("target_key") != target_key:
            continue
        scored.append({**n, "score": score})
    scored.sort(key=lambda r: (r.get("score", 0), r.get("ts", 0)), reverse=True)
    hits = scored[: max(1, int(limit))]
    # Human summary for narrative / prompt
    snippets = []
    for h in hits:
        snippets.append(
            f"[{h.get('kind')}] {str(h.get('text') or '')[:180]}"
        )
    return {
        "ok": True,
        "hits": hits,
        "summary": "\n".join(snippets),
        "count": len(hits),
    }


def target_key_from(target: Optional[Dict[str, Any]]) -> str:
    t = dict(target or {})
    for k in ("bssid", "address", "url", "query", "ssid", "name", "email"):
        if t.get(k):
            return str(t.get(k)).strip().lower()
    return ""
