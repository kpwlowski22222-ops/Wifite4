"""core.osint.polish.pesel_decode — GDPR-safe PESEL metadata decoder.

Phase 2.4 — pure-Python PESEL -> {birthdate, sex, century} decoder.

GDPR-safe: we only operate on PESELs the operator already has. We
do NOT look the person up in any registry. The output is a
*format* signal (date-of-birth derived from the leading digits
per the PESEL spec) and a *sex* signal (even = female, odd =
male, per the 10th digit).
"""
from __future__ import annotations

import re
from datetime import date
from typing import Any, Dict, Optional

from .validators import pesel_checksum_ok


_PESEL_RE = re.compile(r"^\d{11}$")


# Century encoding per PESEL spec (digits 1-2 are YY; digit 3 is
# the century marker):
#   0,1,2,3,4,5 -> 1900 + YY
#   6,7,8,9     -> 2000 + YY
#   Actually:
#   80-92 -> 1800-1899
#   00-19 -> 1900-1999
#   20-59 -> 2000-2059
#   60-79 -> 2200-2279
_CENTURY_MAP = {
    **{i: 1800 + (i * 100 - 80) for i in range(0, 0)},
}
# Build it cleanly:
_CENTURY_MAP = {}
for i in range(0, 100):
    if 80 <= i <= 99:
        century = 1800
    elif 0 <= i <= 19:
        century = 1900
    elif 20 <= i <= 59:
        century = 2000
    elif 60 <= i <= 79:
        century = 2200
    else:
        century = 1900
    _CENTURY_MAP[i] = century


def pesel_to_birthdate(pesel: str) -> Optional[date]:
    """Extract date-of-birth from a PESEL. Returns None on parse fail."""
    if not isinstance(pesel, str) or not _PESEL_RE.match(pesel):
        return None
    yy = int(pesel[0:2])
    mm = int(pesel[2:4])
    dd = int(pesel[4:6])
    if 1 <= mm <= 12:
        century = 1900
    elif 21 <= mm <= 32:
        century = 2000
        mm -= 20
    elif 41 <= mm <= 52:
        century = 2100
        mm -= 40
    elif 61 <= mm <= 72:
        century = 2200
        mm -= 60
    elif 81 <= mm <= 92:
        century = 1800
        mm -= 80
    else:
        return None
    try:
        return date(century + yy, mm, dd)
    except ValueError:
        return None


def pesel_to_sex(pesel: str) -> Optional[str]:
    """Extract sex from a PESEL. ``F`` for female, ``M`` for male.
    Per PESEL spec the 10th digit (index 9) is even for female,
    odd for male. Returns None on parse fail."""
    if not isinstance(pesel, str) or not _PESEL_RE.match(pesel):
        return None
    tenth = int(pesel[9])
    return "F" if tenth % 2 == 0 else "M"


def decode_pesel(pesel: str) -> Dict[str, Any]:
    """GDPR-safe PESEL -> {birthdate, sex, valid} decoder.

    Returns ``{ok: bool, value: "<redacted>", birthdate: <iso>,
    sex: "F"/"M", valid: bool, model: "pesel-decode (heuristic)"}``.
    Never raises.
    """
    if not isinstance(pesel, str) or not _PESEL_RE.match(pesel):
        return {"ok": False, "valid": False,
                "error": "PESEL must be 11 digits",
                "model": "pesel-decode (heuristic)"}
    valid = pesel_checksum_ok(pesel)
    bd = pesel_to_birthdate(pesel)
    sex = pesel_to_sex(pesel)
    return {"ok": True, "valid": valid,
            "value": (pesel[:4] + "***" if len(pesel) > 4 else ""),
            "birthdate": bd.isoformat() if bd else None,
            "sex": sex,
            "model": "pesel-decode (heuristic)"}


__all__ = ["pesel_to_birthdate", "pesel_to_sex", "decode_pesel"]
