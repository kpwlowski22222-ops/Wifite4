"""core.osint.polish.captcha_wall — shared honest-degrade envelope
builder for captcha-walled / no-key endpoints.

Phase 2.4 — operator's revision: when a Polish API needs a key
(GUS BIR1, TERYT, Allegro client_credentials, Wykop Daisy tier)
or is captcha-walled (LinkedIn, NK.pl, KRD, ERIF, InfoMonitor
3rd-party, CEPiK vehicle history), the OSINT method honest-degrades
with an explicit ``error="<reason>_needs_*"`` and a ``url`` to the
browser. NEVER fabricates data.
"""
from __future__ import annotations

from typing import Any, Dict, Optional


def needs_key(name: str, browse_url: str = "", key_name: str = "") -> Dict[str, Any]:
    """Honest-degrade: endpoint needs a key that the operator has not
    provided."""
    return {"ok": False,
            "error": f"{name}_needs_key",
            "fix": f"set {key_name}" if key_name else f"set {name} API key",
            "url": browse_url,
            "model": f"{name} (honest-degrade)"}


def captcha_protected(name: str, browse_url: str = "") -> Dict[str, Any]:
    """Honest-degrade: endpoint is captcha-walled; the operator should
    visit the URL in a browser."""
    return {"ok": False,
            "error": f"{name}_captcha_protected",
            "url": browse_url,
            "fix": "visit the URL in a browser",
            "model": f"{name} (honest-degrade)"}


def no_public_api(name: str, browse_url: str = "") -> Dict[str, Any]:
    """Honest-degrade: endpoint has no public API; HTML scrape is the
    only path and may be captcha-walled."""
    return {"ok": False,
            "error": f"{name}_no_public_api",
            "url": browse_url,
            "fix": "HTML scrape only; visit URL in a browser",
            "model": f"{name} (honest-degrade)"}


def degrades(*, error: str, browse_url: str = "",
             data: Optional[Dict[str, Any]] = None,
             fix: str = "", name: str = "") -> Dict[str, Any]:
    """Generic honest-degrade builder."""
    return {"ok": False, "error": error, "url": browse_url,
            "data": data or {}, "fix": fix,
            "model": (name or "polish-osint") + " (honest-degrade)"}


__all__ = ["needs_key", "captcha_protected", "no_public_api", "degrades"]
