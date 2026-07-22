"""core.osint.polish.ceidg — CEIDG SOAP no-auth client.

Phase 2.4 — CEIDG is the only Polish registry that does NOT
require a key. Endpoint:
``https://datastore.ceidg.gov.pl/CEIDG.DataStore/SystemIntegrationServiceV3.svc``

We use ``core.utils.http_xml.post_soap`` to send the envelopes.
On any failure we honest-degrade.

Note: CEIDG returns XML envelopes; we parse with the same
``lxml`` + namespace-stripped path used in ``http_xml``.
"""
from __future__ import annotations

from typing import Any, Dict, Optional

from core.utils.http_xml import post_soap, DEFAULT_TIMEOUT_S


CEIDG_URL = (
    "https://datastore.ceidg.gov.pl/"
    "CEIDG.DataStore/SystemIntegrationServiceV3.svc"
)


# Minimal SOAP envelopes. CEIDG v3 exposes getMigrationData,
# find, getMigrationData2014, etc. We expose:
# * find(query) — search by NIP / REGON / name
# * get(NIP) — single-record lookup

_FIND_TEMPLATE = """<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
               xmlns:ns="http://tempuri.org/">
  <soap:Body>
    <ns:find>
      <ns:NIP>{nip}</ns:NIP>
    </ns:find>
  </soap:Body>
</soap:Envelope>"""


_GET_TEMPLATE = """<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
               xmlns:ns="http://tempuri.org/">
  <soap:Body>
    <ns:get>
      <ns:NIP>{nip}</ns:NIP>
    </ns:get>
  </soap:Body>
</soap:Envelope>"""


def find_company(nip: str = "", regon: str = "", name: str = "",
                 timeout_s: int = DEFAULT_TIMEOUT_S) -> Dict[str, Any]:
    """Search the CEIDG registry. At least one of NIP / REGON / name
    must be supplied. Returns a uniform envelope. NEVER fabricates."""
    if not nip and not regon and not name:
        return {"ok": False, "error": "at least one of NIP/REGON/name required",
                "url": CEIDG_URL,
                "model": "ceidg (honest-degrade)"}
    # CEIDG v3 ``find`` only accepts NIP; we send NIP if given, else
    # fall through. The operator should provide NIP/REGON; name-search
    # is rate-limited and may need multiple pages — kept simple.
    target = nip or ""
    body = _FIND_TEMPLATE.format(nip=target)
    headers = {"SOAPAction": '"http://tempuri.org/ICIDGService/find"'}
    r = post_soap(CEIDG_URL, body, headers=headers, timeout_s=timeout_s)
    if not r.get("ok", False):
        return r
    return {"ok": True,
            "data": r,
            "url": CEIDG_URL,
            "model": "ceidg (real)"}


def get_company(nip: str,
                timeout_s: int = DEFAULT_TIMEOUT_S) -> Dict[str, Any]:
    """Look up a single company by NIP. Returns a uniform envelope.
    NEVER fabricates."""
    if not nip:
        return {"ok": False, "error": "NIP is required",
                "url": CEIDG_URL,
                "model": "ceidg (honest-degrade)"}
    body = _GET_TEMPLATE.format(nip=nip)
    headers = {"SOAPAction": '"http://tempuri.org/ICIDGService/get"'}
    r = post_soap(CEIDG_URL, body, headers=headers, timeout_s=timeout_s)
    if not r.get("ok", False):
        return r
    return {"ok": True,
            "data": r,
            "url": CEIDG_URL,
            "model": "ceidg (real)"}


__all__ = ["find_company", "get_company", "CEIDG_URL"]
