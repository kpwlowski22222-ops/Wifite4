"""Unified polymorphic / target-adaptive / AI-driven facade for all domains.

Surfaces prepared for AI orchestration::

  wifi | ble | osint | osint_people | osint_web | post_exploit
  | forensics | anti_forensics

Every domain action can flow through:

  prepare(domain, target)  → features + multi-engine ensemble + live_adapt
  pick(domain, target)     → method + params + rationale (target-adaptive)
  plan(domain, target)     → ordered steps (poly_adapt first, then domain)
  run(domain, method, …)   → execute with poly knobs injected into args

Entry points for wifi_attack / ble_attack / osint_* / post_exploit call
:func:`prepare_run` so modules are polymorphic without rewriting every
algorithm body.

Honesty: never fabricates success/CVEs/PSKs. Heuristic + multi-engine
ensemble labelled ``target-adaptive (poly ensemble)``.
Disable: ``KFIOSA_DOMAIN_POLY=0``.
"""
from __future__ import annotations

import os
import time
from typing import Any, Dict, List, Optional, Sequence, Tuple

# ---------------------------------------------------------------------------
# Domain taxonomy
# ---------------------------------------------------------------------------

DOMAIN_WIFI = "wifi"
DOMAIN_BLE = "ble"
DOMAIN_OSINT = "osint"
DOMAIN_OSINT_PEOPLE = "osint_people"
DOMAIN_OSINT_WEB = "osint_web"
DOMAIN_POST = "post_exploit"
DOMAIN_FORENSICS = "forensics"
DOMAIN_ANTI_FORENSICS = "anti_forensics"

_ALIASES = {
    "wlan": DOMAIN_WIFI,
    "wireless": DOMAIN_WIFI,
    "wifi_attack": DOMAIN_WIFI,
    "bluetooth": DOMAIN_BLE,
    "ble_attack": DOMAIN_BLE,
    "people": DOMAIN_OSINT_PEOPLE,
    "osint_person": DOMAIN_OSINT_PEOPLE,
    "web": DOMAIN_OSINT_WEB,
    "website": DOMAIN_OSINT_WEB,
    "osint_web": DOMAIN_OSINT_WEB,
    "post": DOMAIN_POST,
    "post_exploitation": DOMAIN_POST,
    "post-exploit": DOMAIN_POST,
    "pe": DOMAIN_POST,
    "forensic": DOMAIN_FORENSICS,
    "forensic_module": DOMAIN_FORENSICS,
    "dfir": DOMAIN_FORENSICS,
    "anti_forensic": DOMAIN_ANTI_FORENSICS,
    "antiforensics": DOMAIN_ANTI_FORENSICS,
    "anti-forensics": DOMAIN_ANTI_FORENSICS,
    "opsec": DOMAIN_ANTI_FORENSICS,
    "post_exploit_anti_forensic": DOMAIN_ANTI_FORENSICS,
}


def domain_poly_enabled() -> bool:
    raw = (os.environ.get("KFIOSA_DOMAIN_POLY") or "1").strip().lower()
    return raw not in ("0", "false", "off", "no")


def normalize_domain(domain: Any) -> str:
    d = str(domain or "").strip().lower().replace("-", "_")
    return _ALIASES.get(d, d or DOMAIN_WIFI)


def list_domains() -> List[str]:
    return [
        DOMAIN_WIFI, DOMAIN_BLE, DOMAIN_OSINT,
        DOMAIN_OSINT_PEOPLE, DOMAIN_OSINT_WEB, DOMAIN_POST,
        DOMAIN_FORENSICS, DOMAIN_ANTI_FORENSICS,
    ]


# ---------------------------------------------------------------------------
# Method inventories (lazy — avoid import cycles)
# ---------------------------------------------------------------------------


def list_domain_methods(domain: str) -> List[str]:
    """Return known method names for a domain (best-effort)."""
    d = normalize_domain(domain)
    try:
        if d == DOMAIN_WIFI:
            from core.wifi_attack.runner import WiFiAttackRunner
            return list(WiFiAttackRunner.WIFI_ATTACK_METHODS)
        if d == DOMAIN_BLE:
            from core.ble.attack_runner import BLEAttackRunner
            return list(BLEAttackRunner.BLE_ATTACK_METHODS)
        if d in (DOMAIN_OSINT, DOMAIN_OSINT_PEOPLE, DOMAIN_OSINT_WEB):
            try:
                from core.osint.runner_ext import OSINTExtRunner
                return list(OSINTExtRunner.OSINT_EXT_METHODS)
            except Exception:
                from core.osint.runner import OSINT_PROBE_METHODS  # type: ignore
                return list(OSINT_PROBE_METHODS)
        if d == DOMAIN_POST:
            try:
                from core.post_exploit.runner_ext import PostExploitExtRunner
                return list(PostExploitExtRunner.POST_EXPLOIT_EXT_METHODS)
            except Exception:
                from core.post_exploit.runner import POST_EXPLOIT_PROBE_METHODS
                return list(POST_EXPLOIT_PROBE_METHODS)
        if d == DOMAIN_FORENSICS:
            from core.forensics.forensic_modules import FORENSIC_MODULE_FUNCTIONS
            # Passive/read forensics only (exclude anti_* which are destructive)
            return [m for m in FORENSIC_MODULE_FUNCTIONS if not m.startswith("anti_")]
        if d == DOMAIN_ANTI_FORENSICS:
            # Prefer dedicated 60-module OPSEC runner; also expose anti_* from forensic_modules
            methods: List[str] = []
            try:
                from core.post_exploit.anti_forensic import (
                    POST_EXPLOIT_ANTI_FORENSIC_METHODS,
                )
                methods.extend(list(POST_EXPLOIT_ANTI_FORENSIC_METHODS))
            except Exception:
                pass
            try:
                from core.forensics.forensic_modules import FORENSIC_MODULE_FUNCTIONS
                methods.extend(
                    m for m in FORENSIC_MODULE_FUNCTIONS if m.startswith("anti_")
                )
            except Exception:
                pass
            # de-dupe preserve order
            seen = set()
            out: List[str] = []
            for m in methods:
                if m not in seen:
                    seen.add(m)
                    out.append(m)
            return out
    except Exception:
        pass
    return []


# ---------------------------------------------------------------------------
# Target bag helpers
# ---------------------------------------------------------------------------


def target_from_args(
    domain: str,
    args: Optional[Dict[str, Any]] = None,
    *,
    seed: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Build a feature-friendly target dict from step args + seed."""
    t: Dict[str, Any] = {}
    if isinstance(seed, dict):
        t.update(seed)
    if isinstance(args, dict):
        # session often embeds prior recon
        sess = args.get("session")
        if isinstance(sess, dict):
            for k, v in sess.items():
                if k not in t or t.get(k) in (None, "", [], {}):
                    t[k] = v
        for k, v in args.items():
            if k in ("session", "args"):
                continue
            if v is not None and v != "":
                t[k] = v
    t["domain"] = normalize_domain(domain or t.get("domain"))
    return t


# ---------------------------------------------------------------------------
# Core API
# ---------------------------------------------------------------------------


def prepare(
    domain: str,
    target: Optional[Dict[str, Any]] = None,
    *,
    recon: Optional[Dict[str, Any]] = None,
    phase: str = "exploit",
) -> Dict[str, Any]:
    """Extract features + multi-engine ensemble + live adaptive pick."""
    d = normalize_domain(domain)
    tgt = dict(target or {})
    if recon and isinstance(recon, dict):
        for k, v in recon.items():
            if k not in tgt or tgt.get(k) in (None, "", [], {}):
                tgt[k] = v
    tgt.setdefault("domain", d)

    features: Dict[str, Any] = {}
    try:
        from core.utils.poly_adapt import extract_target_features
        features = extract_target_features(tgt)
    except Exception:
        features = {}
    # Preserve domain-specific keys poly_adapt may not flatten
    for k in (
        "encryption", "bssid", "ssid", "channel", "address",
        "url", "email", "query", "os", "host_os", "session_id",
        "path", "file", "pcap", "image", "disk", "memory",
        "opsec", "cleanup", "lab_only",
    ):
        if tgt.get(k) not in (None, "") and features.get(k) in (None, ""):
            features[k] = tgt[k]
    # Infer path from common forensic args
    if not features.get("path"):
        for k in ("file", "pcap", "image", "disk", "target_path"):
            if tgt.get(k):
                features["path"] = tgt[k]
                break

    ensemble: Dict[str, Any] = {}
    try:
        from core.poly.multi_engine import ensemble_adapt
        ensemble = ensemble_adapt(tgt, recon=recon, domain=d)
    except Exception as e:
        ensemble = {"ok": False, "error": str(e)[:120]}

    live: Dict[str, Any] = {}
    try:
        from core.poly.live_adapt import react
        live = react(d, tgt, None)
    except Exception as e:
        live = {"ok": False, "error": str(e)[:120]}

    plum: Dict[str, Any] = {}
    try:
        from core.poly.plum_adapt import adapt_target
        plum = adapt_target(tgt, recon=recon, domain=d)
    except Exception:
        plum = {}

    return {
        "ok": True,
        "domain": d,
        "phase": phase,
        "features": features,
        "ensemble": ensemble,
        "live": live,
        "plum": plum,
        "model": "target-adaptive (poly ensemble + live + plum)",
        "engines": (ensemble or {}).get("engines_used") or [],
        "ts": time.time(),
    }


def pick(
    domain: str,
    target: Optional[Dict[str, Any]] = None,
    *,
    phase: str = "exploit",
    method_hint: str = "",
    exclude: Optional[Sequence[str]] = None,
    ai_hint: str = "",
) -> Dict[str, Any]:
    """Target-adaptive method pick for the domain."""
    d = normalize_domain(domain)
    prep = prepare(d, target, phase=phase)
    methods = list_domain_methods(d)
    ban = {str(x) for x in (exclude or []) if x}

    # 1) Explicit hint if valid
    hint = (method_hint or ai_hint or "").strip()
    if hint.startswith(f"{d}_"):
        hint = hint[len(d) + 1:]
    for pfx in ("wifi_attack_", "ble_attack_", "osint_ext_", "post_exploit_"):
        if hint.startswith(pfx):
            hint = hint[len(pfx):]
    if hint and hint not in ban and (not methods or hint in methods or hint in (
        "auto", "poly", "adaptive", "situational",
    )):
        if hint not in ("auto", "poly", "adaptive", "situational"):
            return {
                "ok": True,
                "method": hint,
                "params": _params_from_prep(prep),
                "rationale": f"explicit method hint {hint!r}",
                "source": "hint",
                "prepare": prep,
                "alternatives": [m for m in methods if m != hint][:8],
            }

    # 2) poly_runtime situational / AI-driven
    pick_name = ""
    rationale = ""
    try:
        from core.utils.poly_runtime import situational_pick, ai_driven_pick
        env = (
            ai_driven_pick(d, context=target, ai_hint=ai_hint or method_hint, phase=phase)
            if (ai_hint or method_hint)
            else situational_pick(
                d,
                features=prep.get("features"),
                phase=phase,
                context=target,
                ai_hint=ai_hint or None,
            )
        )
        pick_name = str(env.get("pick") or "")
        rationale = str(env.get("rationale") or "")
    except Exception as e:
        rationale = f"situational unavailable: {e}"

    # 3) live_adapt / ensemble method names
    live_m = str((prep.get("live") or {}).get("method") or "")
    ens_m = str((prep.get("ensemble") or {}).get("method") or "")

    # Map generic poly names → domain methods when possible
    candidates: List[Tuple[float, str, str]] = []
    for score, name, src in (
        (3.0, pick_name, "situational"),
        (2.5, live_m, "live_adapt"),
        (2.0, ens_m, "ensemble"),
    ):
        mapped = _map_to_domain_method(d, name, methods)
        if mapped and mapped not in ban:
            candidates.append((score, mapped, src))

    # 4) Heuristic domain-specific defaults from features
    for score, name, src in _heuristic_candidates(d, prep.get("features") or {}, methods):
        if name and name not in ban:
            candidates.append((score, name, src))

    # 5) Fall back to first method not banned
    if not candidates and methods:
        for m in methods:
            if m not in ban:
                candidates.append((0.5, m, "inventory"))
                break

    candidates.sort(key=lambda t: -t[0])
    if not candidates:
        return {
            "ok": False,
            "error": f"no methods for domain {d!r}",
            "method": "",
            "params": {},
            "prepare": prep,
        }

    best_score, best, src = candidates[0]
    alts = [{"method": m, "score": s, "source": src2} for s, m, src2 in candidates[1:8]]
    return {
        "ok": True,
        "method": best,
        "params": _params_from_prep(prep),
        "rationale": rationale or f"{src} → {best} (score={best_score:.2f})",
        "source": src,
        "score": best_score,
        "prepare": prep,
        "alternatives": alts,
        "model": "target-adaptive (poly + AI-capable)",
    }


def _params_from_prep(prep: Dict[str, Any]) -> Dict[str, Any]:
    ens = prep.get("ensemble") if isinstance(prep.get("ensemble"), dict) else {}
    live = prep.get("live") if isinstance(prep.get("live"), dict) else {}
    plum = prep.get("plum") if isinstance(prep.get("plum"), dict) else {}
    params: Dict[str, Any] = {
        "poly_depth": ens.get("depth") or plum.get("depth") or "medium",
        "poly_focus": ens.get("focus") or plum.get("focus") or "balanced",
        "poly_engines": list(ens.get("engines_used") or prep.get("engines") or []),
        "poly_model": prep.get("model"),
    }
    if ens.get("tool_order"):
        params["tool_order"] = list(ens["tool_order"])
    if ens.get("boosts"):
        params["poly_boosts"] = dict(ens["boosts"])
    if live.get("params") and isinstance(live["params"], dict):
        for k, v in live["params"].items():
            params.setdefault(k, v)
    if plum.get("params") and isinstance(plum["params"], dict):
        for k, v in plum["params"].items():
            params.setdefault(k, v)
    return params


def _map_to_domain_method(
    domain: str, name: str, methods: Sequence[str],
) -> str:
    """Map poly/live method names onto a concrete domain method if possible."""
    n = (name or "").strip()
    if not n:
        return ""
    if n in methods:
        return n
    # Loose contains match
    nl = n.lower().replace("-", "_")
    for m in methods:
        ml = m.lower()
        if nl in ml or ml in nl:
            return m
    # Keyword bridges
    bridges = {
        DOMAIN_WIFI: {
            "wpa3_sae": "sae_group_downgrade",
            "sae": "sae_group_downgrade",
            "pmkid": "pmkid_ai_prioritizer",
            "deauth": "targeted_deauth_timing",
            "handshake": "automatic_handshake_cracker",
            "evil_twin": "evil_twin_automated",
            "wep": "ai_driven_wep_attack",
            "wps": "wps_null_pin_attack",
            "recon": "wifi_signal_quality_analyzer",
        },
        DOMAIN_BLE: {
            "gatt": "gatt_write_exploit",
            "pair": "pairing_pin_bruteforce",
            "hid": "ble_keyboard_injection",
            "recon": "ble_long_range_scan",
            "mesh": "ble_swarm_coordinator",
            "mitm": "ble_man_in_the_middle_attack",
            "audio": "ble_audio_sniffing",
        },
        DOMAIN_OSINT: {
            "email": "email_harvest",
            "username": "username_enum",
            "domain": "domain_enum",
            "breach": "breach_correlate",
            "phone": "phone_carrier",
        },
        DOMAIN_OSINT_PEOPLE: {
            "email": "email_harvest",
            "username": "username_enum",
            "phone": "phone_carrier",
            "breach": "breach_correlate",
        },
        DOMAIN_OSINT_WEB: {
            "domain": "domain_enum",
            "subdomain": "subdomain_enum",
            "url": "web_fingerprint",
        },
        DOMAIN_POST: {
            "lateral": "lateral_movement",
            "persist": "persistence",
            "cred": "credential_dump",
            "exfil": "exfiltration",
            "enum": "situational_awareness",
            "privesc": "privilege_escalation",
        },
        DOMAIN_FORENSICS: {
            "hash": "file_hash",
            "metadata": "file_metadata",
            "exif": "exif_extract",
            "strings": "strings_extract",
            "pcap": "pcap_summary",
            "memory": "memory_image_identify",
            "registry": "registry_hive_parse",
            "eventlog": "eventlog_parse",
            "browser": "browser_history",
            "mft": "mft_parse",
            "disk": "disk_image_info",
            "history": "bash_history",
            "yara": "yara_scan",
            "wifi": "wifi_password_dump",
            "ssh": "ssh_known_hosts",
            "persist": "persistence_walk",
            "autorun": "autoruns_walk",
            "prefetch": "prefetch_parse",
            "recycle": "recycle_bin_parse",
        },
        DOMAIN_ANTI_FORENSICS: {
            "log": "post_clear_linux_syslog",
            "history": "post_clear_bash_history",
            "bash": "post_clear_bash_history",
            "event": "post_clear_windows_event_logs",
            "shred": "post_secure_delete_file",
            "wipe": "post_wipe_free_space",
            "timestomp": "post_timestomp_file",
            "mac": "post_randomize_mac_address",
            "dns": "post_clear_dns_cache",
            "arp": "post_clear_arp_cache",
            "ssh": "post_clear_ssh_known_hosts",
            "tor": "post_use_tor_for_exfil",
            "encrypt": "post_encrypt_exfiltrated_data",
            "opsec": "anti_opsec_clean",
            "amsi": "anti_amsi_bypass",
            "etw": "post_disable_etw",
            "self_destruct": "post_self_destruct",
        },
    }
    table = bridges.get(domain) or {}
    for kw, method in table.items():
        if kw in nl:
            # prefer actual inventory match
            for m in methods:
                if method in m or m == method:
                    return m
            if method in methods:
                return method
            # fuzzy
            for m in methods:
                if kw in m.lower():
                    return m
    return ""


def _heuristic_candidates(
    domain: str,
    features: Dict[str, Any],
    methods: Sequence[str],
) -> List[Tuple[float, str, str]]:
    out: List[Tuple[float, str, str]] = []
    enc = str(features.get("encryption") or features.get("wpa_version") or "").lower()
    pmf = bool(features.get("pmf_supported") or features.get("pmf"))
    clients = int(features.get("client_count") or 0)
    has_url = bool(features.get("has_url") or features.get("url"))
    has_creds = bool(features.get("has_creds"))

    def add(score: float, key: str) -> None:
        m = _map_to_domain_method(domain, key, methods)
        if m:
            out.append((score, m, "heuristic"))

    if domain == DOMAIN_WIFI:
        if "wpa3" in enc or "sae" in enc or pmf:
            add(4.0, "sae")
        elif clients <= 1:
            add(3.5, "pmkid")
        elif clients >= 1:
            add(3.0, "deauth")
        else:
            add(2.0, "recon")
    elif domain == DOMAIN_BLE:
        if features.get("connectable"):
            add(3.5, "gatt")
        else:
            add(2.5, "recon")
    elif domain in (DOMAIN_OSINT, DOMAIN_OSINT_PEOPLE):
        qt = str(features.get("query_type") or "").lower()
        if "email" in qt or features.get("email"):
            add(3.5, "email")
        elif "phone" in qt:
            add(3.5, "phone")
        else:
            add(3.0, "username")
    elif domain == DOMAIN_OSINT_WEB:
        if has_url:
            add(3.5, "url")
        else:
            add(3.0, "domain")
    elif domain == DOMAIN_POST:
        if has_creds:
            add(4.0, "lateral")
        else:
            add(3.0, "enum")
    elif domain == DOMAIN_FORENSICS:
        path = str(features.get("path") or features.get("file") or "")
        low = path.lower()
        if low.endswith((".pcap", ".pcapng", ".cap")):
            add(4.5, "pcap")
        elif low.endswith((".jpg", ".jpeg", ".png", ".tiff", ".heic")):
            add(4.0, "exif")
        elif low.endswith((".raw", ".mem", ".dmp", ".vmem")):
            add(4.0, "memory")
        elif low.endswith((".e01", ".dd", ".img", ".vmdk")):
            add(4.0, "disk")
        elif low.endswith((".evtx", ".evt")):
            add(4.0, "eventlog")
        elif "registry" in low or low.endswith((".dat", "ntuser.dat", "system")):
            add(3.5, "registry")
        elif path:
            add(3.5, "hash")
            add(3.0, "metadata")
            add(2.5, "strings")
        else:
            add(3.0, "bash")
            add(2.5, "persist")
            add(2.0, "ssh")
    elif domain == DOMAIN_ANTI_FORENSICS:
        os_s = str(features.get("os") or features.get("host_os") or "").lower()
        if "win" in os_s:
            add(4.0, "event")
            add(3.0, "history")
        elif "darwin" in os_s or "mac" in os_s:
            add(3.5, "history")
            add(3.0, "log")
        else:
            add(4.0, "bash")
            add(3.5, "log")
        if features.get("path") or features.get("file"):
            add(3.5, "shred")
            add(3.0, "timestomp")
        if features.get("cleanup") or features.get("opsec"):
            add(3.0, "opsec")
            add(2.5, "dns")
            add(2.5, "arp")
    return out


def inject_args(
    args: Optional[Dict[str, Any]],
    *,
    prepare_ctx: Optional[Dict[str, Any]] = None,
    pick_ctx: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Merge poly knobs into attack/probe args (non-destructive)."""
    out = dict(args or {})
    params = {}
    if pick_ctx and isinstance(pick_ctx.get("params"), dict):
        params.update(pick_ctx["params"])
    elif prepare_ctx:
        params.update(_params_from_prep(prepare_ctx))
    for k, v in params.items():
        out.setdefault(k, v)
    out.setdefault("_poly", {})
    if isinstance(out["_poly"], dict):
        poly = dict(out["_poly"])
        if pick_ctx:
            poly["method"] = pick_ctx.get("method")
            poly["source"] = pick_ctx.get("source")
            poly["rationale"] = (pick_ctx.get("rationale") or "")[:200]
        if prepare_ctx:
            poly["engines"] = prepare_ctx.get("engines")
            poly["domain"] = prepare_ctx.get("domain")
            ens = prepare_ctx.get("ensemble") or {}
            poly["focus"] = ens.get("focus") or poly.get("focus")
            poly["depth"] = ens.get("depth") or poly.get("depth")
        out["_poly"] = poly
    out.setdefault("poly_variant", out.get("poly_focus") or (pick_ctx or {}).get("method"))
    return out


def prepare_run(
    domain: str,
    method: str = "",
    args: Optional[Dict[str, Any]] = None,
    *,
    seed: Optional[Dict[str, Any]] = None,
    phase: str = "exploit",
    auto_pick: bool = True,
) -> Tuple[str, Dict[str, Any], Dict[str, Any]]:
    """Prepare method + args for a domain runner.

    Returns ``(method, args, meta)`` where meta holds prepare/pick envelopes.
    """
    if not domain_poly_enabled():
        return (method or "").strip(), dict(args or {}), {"enabled": False}

    d = normalize_domain(domain)
    a = dict(args or {})
    target = target_from_args(d, a, seed=seed)
    m = (method or a.get("method") or "").strip()

    auto_names = {"", "auto", "poly", "adaptive", "situational", "pick"}
    do_pick = auto_pick and (m.lower() in auto_names or a.get("poly_auto"))
    pick_ctx: Dict[str, Any] = {}
    prep = prepare(d, target, phase=phase)

    if do_pick:
        pick_ctx = pick(
            d, target, phase=phase,
            method_hint=str(a.get("poly_hint") or a.get("ai_hint") or ""),
            ai_hint=str(a.get("ai_hint") or ""),
            exclude=a.get("poly_exclude") if isinstance(a.get("poly_exclude"), list) else None,
        )
        if pick_ctx.get("ok") and pick_ctx.get("method"):
            m = str(pick_ctx["method"])
    elif m:
        # Still prepare + inject; keep explicit method
        pick_ctx = {
            "ok": True,
            "method": m,
            "params": _params_from_prep(prep),
            "rationale": "explicit method",
            "source": "caller",
            "prepare": prep,
        }
    else:
        pick_ctx = pick(d, target, phase=phase)
        if pick_ctx.get("method"):
            m = str(pick_ctx["method"])

    a = inject_args(a, prepare_ctx=prep, pick_ctx=pick_ctx)
    a["method"] = m
    a.setdefault("domain", d)
    meta = {
        "enabled": True,
        "domain": d,
        "prepare": prep,
        "pick": pick_ctx,
        "model": "target-adaptive (poly ensemble + AI-capable)",
    }
    return m, a, meta


def stamp_result(result: Any, meta: Optional[Dict[str, Any]] = None) -> Any:
    """Attach domain poly metadata to a result envelope."""
    if not isinstance(result, dict):
        return {"ok": True, "result": result, "domain_poly": meta or {}}
    out = dict(result)
    if meta and meta.get("enabled") is not False:
        pick = meta.get("pick") or {}
        prep = meta.get("prepare") or {}
        out["domain_poly"] = {
            "domain": meta.get("domain"),
            "method": pick.get("method") or out.get("name"),
            "source": pick.get("source"),
            "rationale": (pick.get("rationale") or "")[:200],
            "engines": prep.get("engines") or [],
            "focus": (prep.get("ensemble") or {}).get("focus"),
            "depth": (prep.get("ensemble") or {}).get("depth"),
            "model": meta.get("model"),
        }
    return out


def plan(
    domain: str,
    target: Optional[Dict[str, Any]] = None,
    *,
    n_steps: int = 4,
    phase: str = "exploit",
) -> Dict[str, Any]:
    """Build a short adaptive plan: poly_adapt → domain methods."""
    d = normalize_domain(domain)
    prep = prepare(d, target, phase=phase)
    methods = list_domain_methods(d)
    steps: List[Dict[str, Any]] = []

    # Always lead with poly_adapt situational
    live_m = str((prep.get("live") or {}).get("method") or "situational_pick")
    steps.append({
        "action": "poly_adapt",
        "tool": live_m,
        "args": {
            "method": live_m,
            **((prep.get("live") or {}).get("params") or {}),
            "domain": d,
        },
        "rationale": (prep.get("live") or {}).get("rationale")
        or "live target-adaptive pick",
        "risk": "read",
    })

    used: List[str] = []
    for i in range(max(1, int(n_steps))):
        p = pick(d, target, phase=phase, exclude=used)
        if not p.get("ok") or not p.get("method"):
            break
        m = str(p["method"])
        used.append(m)
        action = {
            DOMAIN_WIFI: "wifi_attack",
            DOMAIN_BLE: "ble_attack",
            DOMAIN_OSINT: "osint_ext",
            DOMAIN_OSINT_PEOPLE: "osint_ext",
            DOMAIN_OSINT_WEB: "osint_ext",
            DOMAIN_POST: "post_exploit_ext",
            DOMAIN_FORENSICS: "forensic_module",
            DOMAIN_ANTI_FORENSICS: "post_exploit_anti_forensic",
        }.get(d, "mcp_call")
        risk = "read"
        if d in (DOMAIN_WIFI, DOMAIN_BLE, DOMAIN_POST):
            risk = "intrusive"
        elif d == DOMAIN_ANTI_FORENSICS:
            risk = "destructive" if "wipe" in m or "destruct" in m or "secure_delete" in m else "intrusive"
        elif d == DOMAIN_FORENSICS and m.startswith("anti_"):
            risk = "destructive"
        steps.append({
            "action": action,
            "tool": m,
            "args": inject_args(
                {"method": m, "domain": d},
                prepare_ctx=prep,
                pick_ctx=p,
            ),
            "rationale": p.get("rationale") or f"adaptive {m}",
            "risk": risk,
        })

    return {
        "ok": True,
        "domain": d,
        "steps": steps,
        "prepare": {
            "engines": prep.get("engines"),
            "focus": (prep.get("ensemble") or {}).get("focus"),
            "depth": (prep.get("ensemble") or {}).get("depth"),
        },
        "methods_available": len(methods),
        "model": "target-adaptive AI plan (poly-first)",
    }


def describe_domains() -> Dict[str, Any]:
    """Introspection for TUI / MCP / AI."""
    out = {"ok": True, "enabled": domain_poly_enabled(), "domains": {}}
    for d in list_domains():
        methods = list_domain_methods(d)
        out["domains"][d] = {
            "method_count": len(methods),
            "sample_methods": methods[:8],
            "poly": True,
            "target_adaptive": True,
            "ai_driven": True,
        }
    try:
        from core.poly.multi_engine import engines_status
        out["engines"] = engines_status()
    except Exception:
        out["engines"] = {}
    return out


__all__ = [
    "DOMAIN_WIFI", "DOMAIN_BLE", "DOMAIN_OSINT", "DOMAIN_OSINT_PEOPLE",
    "DOMAIN_OSINT_WEB", "DOMAIN_POST",
    "DOMAIN_FORENSICS", "DOMAIN_ANTI_FORENSICS",
    "normalize_domain", "list_domains", "list_domain_methods",
    "prepare", "pick", "plan", "prepare_run", "inject_args",
    "stamp_result", "target_from_args", "describe_domains",
    "domain_poly_enabled",
]
