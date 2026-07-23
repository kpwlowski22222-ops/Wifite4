"""Live-time target-adaptive polymorphism.

observe(target, last_result) → features
pick(domain, features) → method / params / rationale
on_failure → re-pick excluding failed methods

Heuristic only — never fabricates attack success. Used by the engagement
engine and orchestrator to react to PMF, clients, RSSI, failures, etc.
"""
from __future__ import annotations

import os
from typing import Any, Dict, List, Optional, Sequence, Set


def plan_creativity() -> str:
    raw = (os.environ.get("KFIOSA_PLAN_CREATIVITY") or "high").strip().lower()
    if raw in ("balanced", "high", "max"):
        return raw
    return "high"


def _client_count(t: Dict[str, Any], data: Dict[str, Any]) -> int:
    for src in (t.get("clients"), data.get("clients"), t.get("client_count"), data.get("client_count")):
        if isinstance(src, list):
            return len(src)
        if isinstance(src, dict):
            try:
                return int((src.get("data") or src).get("count") or src.get("count") or 0)
            except Exception:
                return 0
        if src is not None and src != "":
            try:
                return int(src)
            except (TypeError, ValueError):
                continue
    return 0


def observe(
    target: Optional[Dict[str, Any]] = None,
    last_result: Optional[Dict[str, Any]] = None,
    *,
    domain: str = "wifi",
) -> Dict[str, Any]:
    """Extract live features from target seed + last step result."""
    t = dict(target or {})
    lr = dict(last_result or {})
    data = lr.get("data") if isinstance(lr.get("data"), dict) else {}
    feats: Dict[str, Any] = {
        "domain": (domain or t.get("domain") or "wifi").lower(),
        "pmf": bool(t.get("pmf") or t.get("pmf_supported") or data.get("pmf")),
        "is_sae": bool(
            t.get("is_sae")
            or "sae" in str(t.get("encryption") or t.get("enc") or "").lower()
            or "wpa3" in str(t.get("encryption") or "").lower()
        ),
        "clients": _client_count(t, data),
        "rssi": t.get("rssi") or data.get("rssi"),
        "injection": bool(
            (t.get("adapter_caps") or {}).get("injection_capable")
            or t.get("injection_capable")
            or data.get("injection_capable")
        ),
        "mt7921e": bool((t.get("adapter_caps") or {}).get("mt7921e") or t.get("mt7921e")),
        "failed": bool(lr.get("ok") is False or lr.get("error") or lr.get("failed")),
        "error": str(lr.get("error") or data.get("error") or "")[:200],
        "access": bool(
            (lr.get("access") or {}).get("achieved")
            if isinstance(lr.get("access"), dict)
            else lr.get("access_achieved")
        ),
        "encryption": str(t.get("encryption") or t.get("enc") or ""),
        "connectable": t.get("connectable", data.get("connectable")),
        "has_url": bool(t.get("url") or t.get("website")),
        "has_query": bool(t.get("query") or t.get("email") or t.get("name")),
    }
    try:
        if feats["rssi"] is not None:
            feats["rssi"] = int(feats["rssi"])
    except (TypeError, ValueError):
        feats["rssi"] = None
    return feats


def pick(
    domain: str,
    features: Dict[str, Any],
    *,
    exclude: Optional[Sequence[str]] = None,
) -> Dict[str, Any]:
    """Pick next poly/adapt method for domain given live features."""
    domain = (domain or features.get("domain") or "wifi").lower()
    ban: Set[str] = set(exclude or [])
    creat = plan_creativity()

    if domain in ("wifi", "wlan"):
        return _pick_wifi(features, ban, creat)
    if domain == "ble":
        return _pick_ble(features, ban, creat)
    if domain in ("osint_people", "people"):
        return _pick_people(features, ban, creat)
    if domain in ("osint_web", "web", "website"):
        return _pick_web(features, ban, creat)
    if domain in ("post_exploit", "post"):
        return _pick_pe(features, ban, creat)
    return {
        "ok": True,
        "method": "recon_probe",
        "params": {},
        "rationale": "generic adaptive recon",
        "family": "recon",
    }


def _first(cands: List[Dict[str, Any]], ban: Set[str]) -> Dict[str, Any]:
    for c in cands:
        m = c.get("method") or ""
        if m not in ban:
            c = dict(c)
            c["ok"] = True
            return c
    return {
        "ok": True,
        "method": "recon_probe",
        "params": {},
        "rationale": "all preferred tactics exhausted — soft recon",
        "family": "recon",
    }


def _pick_wifi(f: Dict[str, Any], ban: Set[str], creat: str) -> Dict[str, Any]:
    cands: List[Dict[str, Any]] = []
    # Offensive inject → capture → PE is the primary path when the radio
    # can put frames on the air (or when we just failed an inject).
    if f.get("injection") or f.get("failed"):
        try:
            from core.poly.offensive_inject import pick_inject_mode
            inj = pick_inject_mode(
                {
                    "pmf": f.get("pmf"),
                    "pmf_supported": f.get("pmf"),
                    "encryption": f.get("encryption"),
                    "clients": f.get("clients"),
                    "client_count": f.get("clients"),
                    "mt7921e": f.get("mt7921e"),
                    "injection_capable": f.get("injection"),
                    "adapter_caps": {
                        "injection_capable": f.get("injection"),
                        "mt7921e": f.get("mt7921e"),
                    },
                },
                {
                    "ok": not f.get("failed"),
                    "error": f.get("error"),
                    "mode": None,
                },
                exclude=list(ban),
            )
            cands.append({
                "method": f"offensive_inject_{inj.get('mode') or 'deauth'}",
                "params": {
                    "mode": inj.get("mode"),
                    "offensive": True,
                    "station": inj.get("station"),
                    "alternates": inj.get("alternates") or [],
                },
                "rationale": (
                    f"OFFENSIVE live inject: {inj.get('rationale')} "
                    "→ capture → crack → PE/privesc"
                ),
                "family": "wifi_offensive_inject",
            })
        except Exception:
            pass
    if f.get("pmf") or f.get("is_sae"):
        cands.append({
            "method": "adapt_wpa3_sae_one_click_plan",
            "params": {"pmf": True},
            "rationale": "PMF/SAE — avoid classic deauth; use SAE-aware plan",
            "family": "wifi_sae",
        })
        cands.append({
            "method": "poly_wpa3_sae_grammar",
            "params": {},
            "rationale": "polymorphic SAE capture variants",
            "family": "wifi_sae",
        })
    if f.get("injection") and not f.get("pmf"):
        cands.append({
            "method": "poly_deauth_burst_pattern_grammar",
            "params": {"clients": f.get("clients") or 0, "offensive": True},
            "rationale": "injection OK, no PMF — offensive deauth burst grammar",
            "family": "wifi_deauth",
        })
    if (f.get("clients") or 0) >= 2:
        cands.append({
            "method": "adapt_wifi_client_count_picker",
            "params": {"clients": f.get("clients")},
            "rationale": "multiple clients — prefer targeted client paths",
            "family": "wifi_clients",
        })
    if f.get("failed") and "inject" in (f.get("error") or "").lower():
        cands.append({
            "method": "adapt_wifi_chipset_picker",
            "params": {"mt7921e": f.get("mt7921e")},
            "rationale": "injection failed — re-pick chipset/monitor path",
            "family": "wifi_radio",
        })
    cands.append({
        "method": "poly_pmkid_vs_handshake_grammar",
        "params": {},
        "rationale": "choose PMKID vs full handshake for this AP",
        "family": "wifi_capture",
    })
    if creat == "max":
        cands.insert(0, {
            "method": "poly_evil_twin_vs_capture_grammar",
            "params": {},
            "rationale": "creative branch: evil-twin vs passive capture",
            "family": "wifi_creative",
        })
    cands.append({
        "method": "recon_probe",
        "params": {},
        "rationale": "fallback recon",
        "family": "recon",
    })
    return _first(cands, ban)


def _pick_ble(f: Dict[str, Any], ban: Set[str], creat: str) -> Dict[str, Any]:
    cands: List[Dict[str, Any]] = []
    rssi = f.get("rssi")
    if rssi is not None and rssi < -85:
        cands.append({
            "method": "adapt_ble_long_range_picker",
            "params": {"rssi": rssi},
            "rationale": "weak RSSI — long-range / slower scan window",
            "family": "ble_range",
        })
    if f.get("connectable"):
        cands.append({
            "method": "adapt_ble_connect_vs_sniff",
            "params": {},
            "rationale": "device connectable — try GATT enum first",
            "family": "ble_connect",
        })
    cands.append({
        "method": "poly_ble_scan_window_grammar",
        "params": {},
        "rationale": "polymorphic scan window",
        "family": "ble_scan",
    })
    if creat in ("high", "max"):
        cands.append({
            "method": "poly_ble_pairing_attack_grammar",
            "params": {},
            "rationale": "creative pairing / bond variants",
            "family": "ble_pair",
        })
    cands.append({
        "method": "ble_probe",
        "params": {},
        "rationale": "generic BLE probe",
        "family": "ble_recon",
    })
    return _first(cands, ban)


def _pick_people(f: Dict[str, Any], ban: Set[str], creat: str) -> Dict[str, Any]:
    cands = [
        {
            "method": "poly_osint_people_order_grammar",
            "params": {},
            "rationale": "order public identity probes by signal strength",
            "family": "osint_people",
        },
        {
            "method": "osint_probe",
            "params": {},
            "rationale": "standard people OSINT probe",
            "family": "osint_people",
        },
    ]
    return _first(cands, ban)


def _pick_web(f: Dict[str, Any], ban: Set[str], creat: str) -> Dict[str, Any]:
    cands = [
        {
            "method": "poly_osint_web_fingerprint_grammar",
            "params": {},
            "rationale": "fingerprint stack before CVE map",
            "family": "osint_web",
        },
        {
            "method": "osint_probe",
            "params": {},
            "rationale": "web OSINT probe",
            "family": "osint_web",
        },
    ]
    return _first(cands, ban)


def _pick_pe(f: Dict[str, Any], ban: Set[str], creat: str) -> Dict[str, Any]:
    cands: List[Dict[str, Any]] = []
    try:
        from core.poly.offensive_inject import pick_priv_esc
        pe = pick_priv_esc(
            {"os": f.get("host_os"), "uid": f.get("uid"), "is_root": f.get("is_root")},
            {"ok": not f.get("failed"), "error": f.get("error"), "access": f.get("access")},
            exclude=list(ban),
        )
        for m in pe.get("chain") or [pe.get("method")]:
            if not m or m == "already_elevated":
                continue
            cands.append({
                "method": m,
                "params": {"privilege_escalation": True, "offensive": True},
                "rationale": pe.get("rationale") or f"poly privesc: {m}",
                "family": "privilege_escalation",
            })
    except Exception:
        pass
    cands.append({
        "method": "adapt_post_exploit_opsec_order",
        "params": {},
        "rationale": "adaptive OPSEC / PE module order",
        "family": "post_exploit",
    })
    cands.append({
        "method": "post_exploit_probe",
        "params": {},
        "rationale": "standard PE probe",
        "family": "post_exploit",
    })
    return _first(cands, ban)


def react(
    domain: str,
    target: Optional[Dict[str, Any]] = None,
    last_result: Optional[Dict[str, Any]] = None,
    *,
    history: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """One live adaptation cycle: observe → pick (excluding history)."""
    feats = observe(target, last_result, domain=domain)
    choice = pick(domain, feats, exclude=history or [])
    choice["features"] = feats
    return choice


def poly_pre_step(domain: str, target: Dict[str, Any]) -> Dict[str, Any]:
    """Build a chain-ready poly_adapt step dict for insertion."""
    choice = react(domain, target, None)
    return {
        "action": "poly_adapt",
        "tool": choice.get("method") or "poly_adapt",
        "args": {
            "method": choice.get("method"),
            "params": choice.get("params") or {},
            **(choice.get("params") or {}),
        },
        "rationale": choice.get("rationale") or "live target-adaptive pick",
        "expected_outcome": "variant/params chosen for this target",
        "risk": "read",
    }
