"""core.utils.http_xml — minimal SOAP/XML helpers for OSINT.

Phase 2.4 — replaces the ``zeep`` dependency with ``lxml`` +
``requests``. The CEIDG, KNF, GUS endpoints accept well-formed
SOAP envelopes; we just need to build them, send them, and parse
the response. We use namespace-stripped XPath to avoid deep tree
traversal.

Honest-degrade contract: on any network / parse failure, callers
get a dict ``{ok: False, error: "<reason>", url: "<browse_url>"}``
so the LLM and the operator can route to the browser instead of
fabricating data.
"""
from __future__ import annotations

import time
from typing import Any, Dict, Optional
from xml.etree import ElementTree as ET

import requests


DEFAULT_USER_AGENT = "KFIOSA/2.4 (+polish-osint, honest-degrade)"
DEFAULT_TIMEOUT_S = 15


def _strip_ns(tag: str) -> str:
    """Strip XML namespace from a tag, e.g. ``{ns}foo`` -> ``foo``."""
    if "}" in tag:
        return tag.split("}", 1)[1]
    return tag


def parse_soap_response(xml_text: str) -> Dict[str, Any]:
    """Parse a SOAP response into a flat dict.

    Returns ``{tag: text, ...}`` for the first level of children of
    the root element. On parse error returns ``{ok: False, error:
    "<reason>", raw: "<first 512 chars>"}`` so the caller can
    honest-degrade with the raw response.
    """
    if not xml_text or not xml_text.strip():
        return {"ok": False, "error": "empty SOAP response", "raw": ""}
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as e:
        return {"ok": False, "error": f"SOAP parse error: {e}",
                "raw": xml_text[:512]}
    body = root
    # Walk to SOAP body if present
    for child in root:
        tag = _strip_ns(child.tag).lower()
        if tag.endswith("body") or tag == "body":
            body = child
            break
    out: Dict[str, Any] = {"ok": True, "_root": _strip_ns(root.tag)}
    for el in body:
        out[_strip_ns(el.tag)] = (el.text or "").strip()
    return out


def post_soap(url: str, soap_envelope: str,
              headers: Optional[Dict[str, str]] = None,
              timeout_s: int = DEFAULT_TIMEOUT_S,
              user_agent: str = DEFAULT_USER_AGENT,
              ) -> Dict[str, Any]:
    """POST a SOAP envelope to ``url``; return the parsed body.

    Always returns a dict. On error: ``{ok: False, error: "<reason>",
    raw: "<first 512 chars>", url: url}``.
    """
    hdrs = {"Content-Type": "text/xml; charset=utf-8",
            "User-Agent": user_agent,
            "SOAPAction": '""'}
    if headers:
        hdrs.update(headers)
    started = time.time()
    try:
        r = requests.post(url, data=soap_envelope.encode("utf-8"),
                          headers=hdrs, timeout=timeout_s)
    except requests.RequestException as e:
        return {"ok": False, "error": f"SOAP POST failed: {e}",
                "url": url, "duration_s": round(time.time() - started, 3)}
    raw = r.text
    if r.status_code != 200:
        return {"ok": False, "error": f"SOAP HTTP {r.status_code}",
                "raw": raw[:512], "url": url,
                "duration_s": round(time.time() - started, 3)}
    parsed = parse_soap_response(raw)
    if not parsed.get("ok", False):
        parsed["url"] = url
        parsed["duration_s"] = round(time.time() - started, 3)
        return parsed
    parsed["url"] = url
    parsed["duration_s"] = round(time.time() - started, 3)
    return parsed


def http_get(url: str, params: Optional[Dict[str, Any]] = None,
             headers: Optional[Dict[str, str]] = None,
             timeout_s: int = DEFAULT_TIMEOUT_S,
             user_agent: str = DEFAULT_USER_AGENT,
             ) -> Dict[str, Any]:
    """GET ``url`` and return ``{ok, status, json, text, url}``.

    On error: ``{ok: False, error: "<reason>", url: url}``.
    """
    hdrs = {"User-Agent": user_agent, "Accept": "application/json, text/plain, */*"}
    if headers:
        hdrs.update(headers)
    started = time.time()
    try:
        r = requests.get(url, params=params or {}, headers=hdrs,
                          timeout=timeout_s)
    except requests.RequestException as e:
        return {"ok": False, "error": f"GET failed: {e}",
                "url": url, "duration_s": round(time.time() - started, 3)}
    out: Dict[str, Any] = {"ok": True, "status": r.status_code,
                           "url": r.url,
                           "duration_s": round(time.time() - started, 3)}
    try:
        out["json"] = r.json()
    except ValueError:
        out["json"] = None
        out["text"] = r.text
    return out


def http_get_text(url: str, params: Optional[Dict[str, Any]] = None,
                  headers: Optional[Dict[str, str]] = None,
                  timeout_s: int = DEFAULT_TIMEOUT_S,
                  user_agent: str = DEFAULT_USER_AGENT,
                  ) -> Dict[str, Any]:
    """GET ``url`` and return ``{ok, status, text, url}``.

    Like ``http_get`` but always returns the text body (for HTML
    scraping). On error: ``{ok: False, error: "<reason>", url: url}``.
    """
    hdrs = {"User-Agent": user_agent, "Accept": "text/html, */*"}
    if headers:
        hdrs.update(headers)
    started = time.time()
    try:
        r = requests.get(url, params=params or {}, headers=hdrs,
                          timeout=timeout_s)
    except requests.RequestException as e:
        return {"ok": False, "error": f"GET failed: {e}",
                "url": url, "duration_s": round(time.time() - started, 3)}
    return {"ok": True, "status": r.status_code, "url": r.url,
            "text": r.text,
            "duration_s": round(time.time() - started, 3)}


__all__ = ["post_soap", "parse_soap_response", "http_get",
           "http_get_text", "DEFAULT_USER_AGENT", "DEFAULT_TIMEOUT_S"]
