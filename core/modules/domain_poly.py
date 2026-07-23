"""Public facade: all domain modules are polymorphic / target-adaptive / AI-ready.

Import this module (or :mod:`core.poly.domain_adapt`) when the AI or TUI
needs a single place to prepare WiFi / BLE / OSINT / post-exploit actions.

Example::

    from core.modules.domain_poly import prepare, pick, plan, run_domain
    prep = prepare("wifi", {"bssid": "...", "encryption": "WPA3"})
    p = pick("wifi", {"encryption": "WPA3-SAE", "pmf": True})
    # p["method"] → e.g. sae_group_downgrade
"""
from __future__ import annotations

from typing import Any, Dict, Optional

from core.poly.domain_adapt import (  # noqa: F401
    DOMAIN_BLE,
    DOMAIN_OSINT,
    DOMAIN_OSINT_PEOPLE,
    DOMAIN_OSINT_WEB,
    DOMAIN_POST,
    DOMAIN_WIFI,
    describe_domains,
    domain_poly_enabled,
    inject_args,
    list_domain_methods,
    list_domains,
    normalize_domain,
    pick,
    plan,
    prepare,
    prepare_run,
    stamp_result,
    target_from_args,
)


def run_domain(
    domain: str,
    method: str = "",
    *,
    args: Optional[Dict[str, Any]] = None,
    adapter: Optional[str] = None,
) -> Dict[str, Any]:
    """Dispatch one adaptive action to the right domain runner."""
    d = normalize_domain(domain)
    a = dict(args or {})
    m, a, meta = prepare_run(d, method, a, phase=(
        "recon" if d.startswith("osint") else
        "post_exploit" if d == DOMAIN_POST else "exploit"
    ))
    try:
        if d == DOMAIN_WIFI:
            from core.wifi_attack.runner import run_attack
            return stamp_result(
                run_attack(m, adapter=adapter or a.get("interface"), args=a),
                meta,
            )
        if d == DOMAIN_BLE:
            from core.ble.attack_runner import run_attack
            return stamp_result(
                run_attack(m, adapter=adapter or a.get("adapter"), args=a),
                meta,
            )
        if d in (DOMAIN_OSINT, DOMAIN_OSINT_PEOPLE, DOMAIN_OSINT_WEB):
            from core.osint.runner_ext import run_probe
            return stamp_result(run_probe(m, args=a), meta)
        if d == DOMAIN_POST:
            from core.post_exploit.runner_ext import run_attack
            return stamp_result(run_attack(m, adapter=adapter, args=a), meta)
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": str(e)[:200], "domain": d, "method": m,
                "domain_poly": meta}
    return {"ok": False, "error": f"unknown domain {d!r}", "method": m}


__all__ = [
    "prepare", "pick", "plan", "prepare_run", "run_domain",
    "describe_domains", "list_domains", "list_domain_methods",
    "DOMAIN_WIFI", "DOMAIN_BLE", "DOMAIN_OSINT", "DOMAIN_OSINT_PEOPLE",
    "DOMAIN_OSINT_WEB", "DOMAIN_POST",
    "domain_poly_enabled",
]
