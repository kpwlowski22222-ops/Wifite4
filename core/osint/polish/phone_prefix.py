"""core.osint.polish.phone_prefix — static Polish mobile-carrier prefix
table.

Phase 2.4 — operator's revision: no live UKE API; static table is
sufficient. We never call numeracja.uke.gov.pl. The static table
covers the 4 major Polish mobile carriers (Orange, Plus, Play,
T-Mobile) and Cyfrowy Polsat, plus a few MVNOs.

The mapping is intentionally *not* exhaustive — it's a heuristic
that returns the *most likely* carrier for a given 9-digit Polish
mobile number (after the +48 country code). The operator should
verify the carrier with their own telecom contract; we do not
fabricate exact portability data.
"""
from __future__ import annotations

from typing import Any, Dict, Optional


# Static prefix -> carrier mapping. Keys are 2- or 3-digit prefixes
# (the leading digits of the 9-digit number after +48). Values are
# carrier names. Order matters: more-specific (3-digit) prefixes
# take precedence over 2-digit ones (the lookup walks the longest
# matching prefix first).
_PREFIX_CARRIER: Dict[str, str] = {
    # Orange Polska (50x, 51x, 53x-mvno)
    "500": "Orange", "501": "Orange", "502": "Orange", "503": "Orange",
    "504": "Orange", "505": "Orange", "506": "Orange", "507": "Orange",
    "508": "Orange", "509": "Orange",
    "510": "Orange", "511": "Orange", "512": "Orange", "513": "Orange",
    "514": "Orange", "515": "Orange", "516": "Orange", "517": "Orange",
    "518": "Orange", "519": "Orange",
    "530": "Orange (MVNO)", "531": "Orange (MVNO)",
    "532": "Orange (MVNO)", "533": "Orange (MVNO)",
    # Plus (Polkomtel): 60x, 66x, 69x, 72x, 78x
    "600": "Plus", "601": "Plus", "602": "Plus", "603": "Plus",
    "604": "Plus", "605": "Plus", "606": "Plus", "607": "Plus",
    "608": "Plus", "609": "Plus",
    "660": "Plus", "661": "Plus", "662": "Plus", "663": "Plus",
    "664": "Plus", "665": "Plus", "666": "Plus", "667": "Plus",
    "668": "Plus", "669": "Plus",
    "690": "Plus", "691": "Plus", "692": "Plus", "693": "Plus",
    "694": "Plus", "695": "Plus", "696": "Plus", "697": "Plus",
    "698": "Plus", "699": "Plus",
    "720": "Plus", "721": "Plus", "722": "Plus", "723": "Plus",
    "724": "Plus", "725": "Plus", "726": "Plus", "727": "Plus",
    "728": "Plus", "729": "Plus",
    "780": "Plus", "781": "Plus", "782": "Plus", "783": "Plus",
    "784": "Plus", "785": "Plus", "786": "Plus", "787": "Plus",
    "788": "Plus", "789": "Plus",
    # Play (P4): 73x, 74x, 75x, 76x, 77x, 79x
    "730": "Play", "731": "Play", "732": "Play", "733": "Play",
    "734": "Play", "735": "Play", "736": "Play", "737": "Play",
    "738": "Play", "739": "Play",
    "740": "Play", "741": "Play", "742": "Play", "743": "Play",
    "744": "Play", "745": "Play", "746": "Play", "747": "Play",
    "748": "Play", "749": "Play",
    "750": "Play", "751": "Play", "752": "Play", "753": "Play",
    "754": "Play", "755": "Play", "756": "Play", "757": "Play",
    "758": "Play", "759": "Play",
    "760": "Play", "761": "Play", "762": "Play", "763": "Play",
    "764": "Play", "765": "Play", "766": "Play", "767": "Play",
    "768": "Play", "769": "Play",
    "770": "Play", "771": "Play", "772": "Play", "773": "Play",
    "774": "Play", "775": "Play", "776": "Play", "777": "Play",
    "778": "Play", "779": "Play",
    "790": "Play", "791": "Play", "792": "Play", "793": "Play",
    "794": "Play", "795": "Play", "796": "Play", "797": "Play",
    "798": "Play", "799": "Play",
    # T-Mobile (Era): 73x, 88x
    "880": "T-Mobile", "881": "T-Mobile", "882": "T-Mobile",
    "883": "T-Mobile", "884": "T-Mobile", "885": "T-Mobile",
    "886": "T-Mobile", "887": "T-Mobile", "888": "T-Mobile",
    "889": "T-Mobile",
    "700": "T-Mobile (MVNO)", "701": "T-Mobile (MVNO)",
    "702": "T-Mobile (MVNO)", "703": "T-Mobile (MVNO)",
    "704": "T-Mobile (MVNO)", "705": "T-Mobile (MVNO)",
    # Cyfrowy Polsat: 45x, 46x
    "450": "Cyfrowy Polsat", "451": "Cyfrowy Polsat",
    "452": "Cyfrowy Polsat", "453": "Cyfrowy Polsat",
    "454": "Cyfrowy Polsat", "455": "Cyfrowy Polsat",
    "456": "Cyfrowy Polsat", "457": "Cyfrowy Polsat",
    "458": "Cyfrowy Polsat", "459": "Cyfrowy Polsat",
    "460": "Cyfrowy Polsat", "461": "Cyfrowy Polsat",
    "462": "Cyfrowy Polsat", "463": "Cyfrowy Polsat",
    "464": "Cyfrowy Polsat", "465": "Cyfrowy Polsat",
    "466": "Cyfrowy Polsat", "467": "Cyfrowy Polsat",
    "468": "Cyfrowy Polsat", "469": "Cyfrowy Polsat",
}


def lookup_carrier(phone9: str) -> Dict[str, Any]:
    """Look up the most likely carrier for a 9-digit Polish mobile
    number. Returns ``{ok, carrier, prefix, model: "phone-prefix
    (heuristic, static table)"}``. NEVER returns fabricated exact
    data — only the *most likely* carrier from a static table.
    """
    if not isinstance(phone9, str):
        return {"ok": False, "error": "phone must be a string",
                "model": "phone-prefix (heuristic)"}
    p = phone9.strip().lstrip("+").replace(" ", "")
    if p.startswith("48") and len(p) == 11:
        p = p[2:]
    if len(p) != 9 or not p.isdigit():
        return {"ok": False, "error":
                "phone must be 9 digits after +48",
                "model": "phone-prefix (heuristic)"}
    # Try longest first
    for length in (3, 2):
        prefix = p[:length]
        carrier = _PREFIX_CARRIER.get(prefix)
        if carrier:
            return {"ok": True, "carrier": carrier, "prefix": prefix,
                    "value": "***" + p[-3:],
                    "model": "phone-prefix (heuristic, static table)"}
    return {"ok": True, "carrier": "unknown", "prefix": p[:2],
            "value": "***" + p[-3:],
            "model": "phone-prefix (heuristic, static table)"}


__all__ = ["lookup_carrier"]
