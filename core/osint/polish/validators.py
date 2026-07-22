"""core.osint.polish.validators — pure-Python Polish format validators.

Phase 2.4 — these are GDPR-safe local-checksum algorithms. They
NEVER look up the actual entity. They ONLY validate that the
identifier the operator already possesses has a valid checksum.
GDPR-safe because we never query a registry with the identifier.

Algorithms:
* NIP         — 10 digits, weights 6,5,7,2,3,4,5,6,7
* REGON9      — 9 digits, weights 8,9,2,3,4,5,6,7
* REGON14     — 14 digits, weights 2,4,8,5,0,9,7,3,6,1,2,4,8
* PESEL       — 11 digits, weights 1,3,7,9,1,3,7,9,1,3
* KRS         — 10 digits, no checksum (just digit count + range)
* IBAN_PL     — 28 chars, PL + 24 digits, mod-97 checksum
* Phone_PL    — 9 digits after the +48 country code; mobile /
                landline prefix range
"""
from __future__ import annotations

import re
from typing import Any, Dict, Optional


_NIP_RE = re.compile(r"^\d{10}$")
_REGON9_RE = re.compile(r"^\d{9}$")
_REGON14_RE = re.compile(r"^\d{14}$")
_PESEL_RE = re.compile(r"^\d{11}$")
_KRS_RE = re.compile(r"^\d{10}$")
_IBAN_PL_RE = re.compile(r"^PL\d{24}$", re.IGNORECASE)
_PHONE_PL_RE = re.compile(r"^\d{9}$")


def _safe_int(s: str) -> Optional[int]:
    try:
        return int(s)
    except (TypeError, ValueError):
        return None


def nip_checksum_ok(nip: str) -> bool:
    """Validate NIP checksum. NIP = 10 digits; weights
    6,5,7,2,3,4,5,6,7; check digit = (sum mod 11) mod 10.

    Rejects all-same-digit NIPs (``0000000000``, ``1111111111``)
    conventionally even though they technically pass the
    weighted-sum check — no real entity has them."""
    if not isinstance(nip, str) or not _NIP_RE.match(nip):
        return False
    if len(set(nip)) == 1:
        return False
    weights = [6, 5, 7, 2, 3, 4, 5, 6, 7]
    s = sum(int(nip[i]) * weights[i] for i in range(9))
    check = (s % 11) % 10
    return check == int(nip[9])


def regon9_checksum_ok(regon: str) -> bool:
    """Validate REGON9 checksum. weights 8,9,2,3,4,5,6,7.

    Rejects all-same-digit REGONs conventionally even
    though they technically pass the weighted-sum check."""
    if not isinstance(regon, str) or not _REGON9_RE.match(regon):
        return False
    if len(set(regon)) == 1:
        return False
    weights = [8, 9, 2, 3, 4, 5, 6, 7]
    s = sum(int(regon[i]) * weights[i] for i in range(8))
    check = (s % 11) % 10
    return check == int(regon[8])


def regon14_checksum_ok(regon: str) -> bool:
    """Validate REGON14 checksum. weights 2,4,8,5,0,9,7,3,6,1,2,4,8.

    Rejects all-same-digit REGONs conventionally even
    though they technically pass the weighted-sum check."""
    if not isinstance(regon, str) or not _REGON14_RE.match(regon):
        return False
    if len(set(regon)) == 1:
        return False
    weights = [2, 4, 8, 5, 0, 9, 7, 3, 6, 1, 2, 4, 8]
    s = sum(int(regon[i]) * weights[i] for i in range(13))
    check = (s % 11) % 10
    return check == int(regon[13])


def pesel_checksum_ok(pesel: str) -> bool:
    """Validate PESEL checksum. weights 1,3,7,9,1,3,7,9,1,3.

    All-zero PESEL (``00000000000``) is conventionally invalid
    even though it technically passes the weighted-sum check —
    no real person has it. We reject it explicitly so the
    operator never gets a "valid" all-zero PESEL back."""
    if not isinstance(pesel, str) or not _PESEL_RE.match(pesel):
        return False
    if pesel == "00000000000":
        return False
    weights = [1, 3, 7, 9, 1, 3, 7, 9, 1, 3]
    s = sum(int(pesel[i]) * weights[i] for i in range(10))
    check = (10 - s % 10) % 10
    return check == int(pesel[10])


def krs_format_ok(krs: str) -> bool:
    """KRS is 10 digits. No checksum; just digit count + range."""
    if not isinstance(krs, str) or not _KRS_RE.match(krs):
        return False
    n = int(krs)
    return 100000 <= n <= 9999999999


def iban_pl_checksum_ok(iban: str) -> bool:
    """Validate Polish IBAN: ``PL`` + 24 digits, mod-97 == 1."""
    if not isinstance(iban, str):
        return False
    s = iban.upper().replace(" ", "")
    if not _IBAN_PL_RE.match(s):
        return False
    rearranged = s[4:] + s[:4]
    # Convert letters to digits
    digits = ""
    for ch in rearranged:
        if ch.isdigit():
            digits += ch
        else:
            digits += str(ord(ch) - 55)
    # mod-97
    rem = 0
    for d in digits:
        rem = (rem * 10 + int(d)) % 97
    return rem == 1


def phone_pl_format_ok(phone9: str) -> bool:
    """Validate Polish 9-digit phone (after +48). Mobile (4-9) or
    landline (1-3 area codes)."""
    if not isinstance(phone9, str) or not _PHONE_PL_RE.match(phone9):
        return False
    n = int(phone9)
    return 100000000 <= n <= 999999999


# ---------------------------------------------------------------------------
# Aggregated helper
# ---------------------------------------------------------------------------


def validate_polish_id(kind: str, value: str) -> Dict[str, Any]:
    """Validate any Polish identifier. Returns a uniform envelope::

        {ok: bool, kind: str, value: <redacted>, error: str, model: "..."}

    Never raises. Always returns a dict.
    """
    kind = (kind or "").lower().strip()
    fn = {
        "nip": nip_checksum_ok,
        "regon9": regon9_checksum_ok,
        "regon14": regon14_checksum_ok,
        "pesel": pesel_checksum_ok,
        "krs": krs_format_ok,
        "iban_pl": iban_pl_checksum_ok,
        "phone_pl": phone_pl_format_ok,
    }.get(kind)
    if fn is None:
        return {"ok": False, "kind": kind, "error":
                f"unknown identifier kind: {kind!r}",
                "model": "polish-validator (heuristic)"}
    is_valid = bool(fn(value))
    return {"ok": True, "kind": kind, "valid": is_valid,
            "value": (str(value)[:4] + "***" if value and
                      str(value) and len(str(value)) > 4 else ""),
            "model": "polish-validator (heuristic)"}


__all__ = [
    "nip_checksum_ok", "regon9_checksum_ok", "regon14_checksum_ok",
    "pesel_checksum_ok", "krs_format_ok", "iban_pl_checksum_ok",
    "phone_pl_format_ok", "validate_polish_id",
]
