"""Score live scan targets for autonomous pick order."""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence


def score_wifi(ap: Dict[str, Any], *, inject: bool = False) -> float:
    s = 0.0
    try:
        pwr = float(ap.get("power") if ap.get("power") is not None else -100)
        # stronger signal (less negative / higher) → higher score
        s += max(0.0, min(40.0, (pwr + 100) * 0.5))
    except (TypeError, ValueError):
        pass
    try:
        s += min(20.0, float(ap.get("clients_count") or len(ap.get("clients") or [])) * 3)
    except (TypeError, ValueError):
        pass
    enc = str(ap.get("encryption") or ap.get("enc") or "").upper()
    if "OPEN" in enc or enc in ("", "?", "OPN"):
        s += 25
    elif "WEP" in enc:
        s += 20
    elif "WPA3" in enc or "SAE" in enc:
        s += 8  # harder but still interesting
    elif "WPA2" in enc or "WPA" in enc:
        s += 12
    if ap.get("pmf") or ap.get("pmf_supported"):
        s += 3
    if inject:
        s += 5
    if ap.get("from_memory") or ap.get("memory_boost"):
        s += 10
    return s


def score_ble(dev: Dict[str, Any]) -> float:
    s = 0.0
    try:
        rssi = float(dev.get("rssi") if dev.get("rssi") is not None else -100)
        s += max(0.0, min(40.0, (rssi + 100) * 0.5))
    except (TypeError, ValueError):
        pass
    if dev.get("connectable"):
        s += 15
    if dev.get("name") or dev.get("local_name"):
        s += 5
    if dev.get("from_memory") or dev.get("memory_boost"):
        s += 10
    return s


def rank_targets(
    items: Sequence[Dict[str, Any]],
    *,
    domain: str = "wifi",
    inject: bool = False,
    top_n: int = 5,
) -> List[Dict[str, Any]]:
    domain = (domain or "wifi").lower()
    scored = []
    for it in items or []:
        if not isinstance(it, dict):
            continue
        sc = score_wifi(it, inject=inject) if domain == "wifi" else score_ble(it)
        row = dict(it)
        row["_score"] = sc
        scored.append(row)
    scored.sort(key=lambda x: float(x.get("_score") or 0), reverse=True)
    return scored[: max(1, int(top_n))]


def full_auto_enabled() -> bool:
    import os
    raw = (os.environ.get("KFIOSA_FULL_AUTO") or "0").strip().lower()
    return raw in ("1", "true", "yes", "on")
