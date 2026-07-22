"""core.osint.polish.nameday — nameday.abalin.net client.

Phase 2.4 — ``nameday.abalin.net`` is a public no-auth, CORS-enabled
JSON API. We wrap the GET and return the nameday list for a given
date. NEVER fabricates.
"""
from __future__ import annotations

from typing import Any, Dict, Optional

from core.utils.http_xml import http_get, DEFAULT_TIMEOUT_S


NAMEDAY_URL = "https://nameday.abalin.net/api/today"
NAMEDAY_URL_ANY = "https://nameday.abalin.net/api"


def nameday_today(country: str = "pl",
                  timeout_s: int = DEFAULT_TIMEOUT_S) -> Dict[str, Any]:
    """Fetch today's nameday for the given country (default ``pl``)."""
    params = {"country": country}
    r = http_get(NAMEDAY_URL, params=params, timeout_s=timeout_s)
    if not r.get("ok", False):
        return r
    data = r.get("json") or {}
    return {"ok": True,
            "data": data,
            "url": r.get("url", NAMEDAY_URL),
            "country": country,
            "model": "nameday (real)"}


def nameday_on(date_iso: str, country: str = "pl",
               timeout_s: int = DEFAULT_TIMEOUT_S) -> Dict[str, Any]:
    """Fetch the nameday for a specific date (``YYYY-MM-DD``)."""
    if not date_iso:
        return {"ok": False, "error": "date_iso is required",
                "model": "nameday (honest-degrade)"}
    url = f"{NAMEDAY_URL_ANY}/{date_iso}"
    params = {"country": country}
    r = http_get(url, params=params, timeout_s=timeout_s)
    if not r.get("ok", False):
        return r
    data = r.get("json") or {}
    return {"ok": True,
            "data": data,
            "date": date_iso,
            "country": country,
            "url": r.get("url", url),
            "model": "nameday (real)"}


__all__ = ["nameday_today", "nameday_on", "NAMEDAY_URL", "NAMEDAY_URL_ANY"]
