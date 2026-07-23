"""Human-language activity narrative for the TUI.

Technical events from the orchestrator are turned into friendly prose so
operators can follow every step without reading tag soup. Errors stay
honest — never softened into fake success.

Toggle: ``KFIOSA_NARRATIVE_LOG`` (default on). ``0`` / ``false`` keeps raw.
"""
from __future__ import annotations

import os
import re
from typing import Any, Callable, Dict, List, Optional

_Emit = Callable[[str], None]


def narrative_enabled() -> bool:
    raw = (os.environ.get("KFIOSA_NARRATIVE_LOG") or "1").strip().lower()
    return raw not in ("0", "false", "no", "off")


def _label_target(target: Any) -> str:
    if not isinstance(target, dict):
        return str(target or "the target")
    for k in ("ssid", "name", "query", "url", "label", "bssid", "address"):
        v = target.get(k)
        if v:
            return str(v)
    return "the target"


def humanize_event(msg: str, *, domain: str = "", target: Any = None) -> str:
    """Map a technical log line to friendlier prose when possible."""
    if not msg:
        return msg
    raw = str(msg).rstrip()
    # Strip leading timestamp for classification
    body = re.sub(r"^\d{2}:\d{2}:\d{2}\s+", "", raw)
    low = body.lower()
    tname = _label_target(target)

    # Already narrative-looking (no tech tag) — keep
    if not body.startswith("[") and not body.startswith("==="):
        return raw

    # Access / success
    if "access achieved" in low or "engagement access" in low:
        return f"We're in on {tname}. Locking the path and preparing post-exploit."
    if "flask dashboard" in low and ("http://" in low or "https://" in low):
        m = re.search(r"https?://\S+", body)
        url = m.group(0) if m else "the dashboard"
        return f"Control panel is open: {url}"
    if body.startswith("[+]") or body.startswith("[AIO]"):
        rest = re.sub(r"^\[(\+|AIO)\]\s*", "", body).strip()
        if "plan" in low:
            return f"Plan ready: {rest}"
        if "selected" in low or "loaded" in low:
            return f"Target locked: {rest}"
        return f"Progress: {rest}"

    # Failures — keep reason
    if body.startswith("[!]") or "failed" in low or "error" in low:
        rest = re.sub(r"^\[!\]\s*", "", body).strip()
        return f"That step hit a snag ({rest}). We'll adapt and try another angle."

    # Recon / scan
    if "[recon]" in low or "recon" in low and "budget" in low:
        return f"Recon on {tname}: gathering what the air (or site) will tell us…"
    if "scanning" in low or "scan" in low and ("window" in low or "triple" in low):
        return f"Live scan windows are up — pick a target when you see a good one."
    if "no access" in low or "without access" in low:
        return f"Still no foothold on {tname}. Re-planning with what we learned…"

    # Poly / adapt
    if "[poly]" in low or "poly_adapt" in low or "polymorphic" in low:
        rest = re.sub(r"^\[poly\]\s*", "", body, flags=re.I).strip()
        return f"Adapting tactics: {rest or 'choosing a better variant for this target.'}"
    if "re-plan" in low or "replan" in low:
        return f"Plan changed mid-flight — reacting to how {tname} behaves."

    # Post-exploit
    if "post-exploit" in low or "post_exploit" in low or "[post]" in low:
        return f"Access held — running post-exploit and securing our connection."
    if "auto post-exploit" in low:
        return "Foothold confirmed — automatic post-exploit chain is starting (you'll still approve risky steps)."

    # PE cancel
    if "cancelled" in low:
        rest = re.sub(r"^\[.?\]\s*", "", body).strip()
        return f"Stopped on purpose: {rest}"

    # Generic tags → soften
    for tag, phrase in (
        (r"^\[\+\]\s*", "Done: "),
        (r"^\[\*\]\s*", "Working: "),
        (r"^\[i\]\s*", "Note: "),
        (r"^\[plan\]\s*", "Plan: "),
        (r"^\[AIO\]\s*", "All-in-one: "),
        (r"^\[0day[^\]]*\]\s*", "Zero-day path: "),
        (r"^\[CVE[^\]]*\]\s*", "CVE: "),
        (r"^\[people\]\s*", "People OSINT: "),
        (r"^\[web\]\s*", "Web OSINT: "),
    ):
        if re.match(tag, body, re.I):
            rest = re.sub(tag, "", body, flags=re.I).strip()
            return f"{phrase}{rest}"

    return raw


def step_begin(domain: str, target: Any = None, phase: str = "engage") -> str:
    name = _label_target(target)
    d = (domain or "target").lower()
    if d in ("wifi", "wlan"):
        return f"Starting on Wi‑Fi “{name}” — recon first, then a creative attack plan."
    if d == "ble":
        return f"Starting on BLE device “{name}” — map services, then adapt the approach."
    if d in ("osint_people", "people"):
        return f"Looking up person “{name}” — public signals only, building a dossier."
    if d in ("osint_web", "web", "website"):
        return f"Examining web target “{name}” — fingerprint, then follow useful paths."
    return f"Engaging “{name}” ({phase})."


def step_adapt(reason: str, next_action: str = "") -> str:
    r = (reason or "target behaviour changed").strip()
    n = (next_action or "a better-fitting technique").strip()
    return f"Adapting live: {r}. Next up — {n}."


def step_ok(summary: str) -> str:
    return f"Good news: {(summary or 'step completed').strip()}"


def step_fail(err: str) -> str:
    e = (err or "unknown error").strip()
    return f"That path failed ({e}). Switching tactics…"


def step_pe() -> str:
    return (
        "Foothold is real — attaching post-exploit, locking the session, "
        "and keeping the control path ready."
    )


def narrate(msg: str, *, domain: str = "", target: Any = None) -> str:
    if not narrative_enabled():
        return str(msg)
    return humanize_event(str(msg), domain=domain, target=target)


def wrap_emit(
    emit: Optional[_Emit],
    *,
    domain: str = "",
    target: Any = None,
) -> _Emit:
    """Return an emit callback that humanizes messages when enabled."""

    def _out(msg: str) -> None:
        text = narrate(msg, domain=domain, target=target)
        if emit:
            try:
                emit(text)
            except Exception:
                pass

    return _out
