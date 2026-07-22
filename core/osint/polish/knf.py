"""core.osint.polish.knf — KNF API XML parser.

Phase 2.4 — KNF (Komisja Nadzoru Finansowego) supervision warnings
are public, no auth required, but the endpoint requires an explicit
User-Agent (the default Python UA is rejected with 403).

Endpoint:
``https://api.knf.gov.pl/SupervisionWarning?dateFrom=YYYY-MM-DD&dateTo=YYYY-MM-DD``

We parse the response as XML and extract a flat list of warning
records. NEVER fabricates.
"""
from __future__ import annotations

from datetime import date, timedelta
from typing import Any, Dict, List, Optional
from xml.etree import ElementTree as ET

from core.utils.http_xml import http_get, DEFAULT_TIMEOUT_S


KNF_URL = "https://api.knf.gov.pl/SupervisionWarning"


def _strip_ns(tag: str) -> str:
    if "}" in tag:
        return tag.split("}", 1)[1]
    return tag


def _parse_warnings_xml(xml_text: str) -> List[Dict[str, Any]]:
    """Parse the KNF XML response into a list of warning dicts."""
    if not xml_text or not xml_text.strip():
        return []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return []
    items: List[Dict[str, Any]] = []
    # KNF returns a structure with <item> or <warning> children
    for child in root.iter():
        tag = _strip_ns(child.tag).lower()
        if tag in ("item", "warning", "entitywarning"):
            rec: Dict[str, Any] = {}
            for sub in child:
                rec[_strip_ns(sub.tag)] = (sub.text or "").strip()
            if rec:
                items.append(rec)
    return items


def query_warnings(date_from: Optional[str] = None,
                   date_to: Optional[str] = None,
                   timeout_s: int = DEFAULT_TIMEOUT_S) -> Dict[str, Any]:
    """Query KNF supervision warnings between ``date_from`` and
    ``date_to`` (YYYY-MM-DD). Defaults to the last 30 days. NEVER
    fabricates."""
    if not date_to:
        date_to = date.today().isoformat()
    if not date_from:
        d = date.today() - timedelta(days=30)
        date_from = d.isoformat()
    params = {"dateFrom": date_from, "dateTo": date_to}
    r = http_get(KNF_URL, params=params, timeout_s=timeout_s,
                 headers={"Accept": "application/xml, text/xml, */*",
                          "User-Agent":
                          "KFIOSA/2.4 (+polish-osint, honest-degrade)"})
    if not r.get("ok", False):
        return r
    text = r.get("text") or r.get("json") or {}
    if isinstance(text, dict):
        # Already JSON
        items = text.get("items") or text.get("warnings") or []
        return {"ok": True, "items": items, "url": r.get("url", KNF_URL),
                "date_from": date_from, "date_to": date_to,
                "count": len(items),
                "model": "knf (real)"}
    items = _parse_warnings_xml(str(text))
    return {"ok": True, "items": items, "url": r.get("url", KNF_URL),
            "date_from": date_from, "date_to": date_to,
            "count": len(items),
            "model": "knf (real)"}


__all__ = ["query_warnings", "KNF_URL"]
