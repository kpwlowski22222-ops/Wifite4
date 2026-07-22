"""core.osint.polish.postal_codes — pocztapolska GitHub CSV mirror.

Phase 2.4 — the Polish postal code list is published on GitHub at
``pocztapolska/numery-kodow-pocztowych`` (no key, public). We fetch
the CSV lazily and cache in-memory. The data is the official
postal-code -> locality mapping. NEVER fabricates.
"""
from __future__ import annotations

import io
import csv
from typing import Any, Dict, Optional

from core.utils.http_xml import http_get_text, DEFAULT_TIMEOUT_S


POSTAL_CODES_CSV_URL = (
    "https://raw.githubusercontent.com/pocztapolska/"
    "numery-kodow-pocztowych/master/kody.csv"
)


_CACHE: Dict[str, Any] = {}


def _load(timeout_s: int = DEFAULT_TIMEOUT_S) -> Dict[str, Any]:
    """Fetch + parse the postal-code CSV. Cached after first load."""
    if _CACHE.get("loaded"):
        return _CACHE
    r = http_get_text(POSTAL_CODES_CSV_URL, timeout_s=timeout_s)
    if not r.get("ok", False):
        _CACHE["loaded"] = True
        _CACHE["error"] = r.get("error", "unknown")
        _CACHE["rows"] = []
        return _CACHE
    text = r.get("text", "")
    rows = []
    if text:
        try:
            reader = csv.DictReader(io.StringIO(text), delimiter=";")
            for row in reader:
                rows.append({k: (v or "").strip() for k, v in row.items()})
        except (csv.Error, KeyError):
            rows = []
    _CACHE["loaded"] = True
    _CACHE["rows"] = rows
    _CACHE["url"] = r.get("url", POSTAL_CODES_CSV_URL)
    return _CACHE


def lookup_postal(code: str,
                  timeout_s: int = DEFAULT_TIMEOUT_S) -> Dict[str, Any]:
    """Look up a Polish postal code (e.g. ``00-001``) and return the
    matching locality rows. NEVER fabricates."""
    if not code:
        return {"ok": False, "error": "postal code is required",
                "model": "postal-codes (honest-degrade)"}
    code = code.strip()
    data = _load(timeout_s=timeout_s)
    if data.get("error"):
        return {"ok": False, "error": data["error"],
                "url": data.get("url", POSTAL_CODES_CSV_URL),
                "model": "postal-codes (honest-degrade)"}
    rows = data.get("rows", [])
    matches = [r for r in rows if r.get("kod") == code
               or r.get("Kod") == code or r.get("KOD") == code
               or code in (r.get("kod") or r.get("Kod") or r.get("KOD") or "")]
    return {"ok": True,
            "data": {"code": code, "matches": matches[:20]},
            "url": data.get("url", POSTAL_CODES_CSV_URL),
            "count": len(matches),
            "model": "postal-codes (real)"}


def search_locality(locality: str,
                    timeout_s: int = DEFAULT_TIMEOUT_S) -> Dict[str, Any]:
    """Search for a locality (case-insensitive substring match)."""
    if not locality:
        return {"ok": False, "error": "locality is required",
                "model": "postal-codes (honest-degrade)"}
    needle = locality.strip().lower()
    data = _load(timeout_s=timeout_s)
    if data.get("error"):
        return {"ok": False, "error": data["error"],
                "url": data.get("url", POSTAL_CODES_CSV_URL),
                "model": "postal-codes (honest-degrade)"}
    rows = data.get("rows", [])
    matches = []
    for r in rows:
        text = " ".join(str(v) for v in r.values()).lower()
        if needle in text:
            matches.append(r)
            if len(matches) >= 20:
                break
    return {"ok": True,
            "data": {"locality": locality, "matches": matches},
            "url": data.get("url", POSTAL_CODES_CSV_URL),
            "count": len(matches),
            "model": "postal-codes (real)"}


__all__ = ["lookup_postal", "search_locality", "POSTAL_CODES_CSV_URL"]
