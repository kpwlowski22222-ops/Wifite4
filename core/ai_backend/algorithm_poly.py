"""Universal polymorphism for *every* KFIOSA algorithm.

Wraps zero-day algorithms (and any callable with the same signature) so
each invocation:

  1. extracts live target features,
  2. classifies the algorithm into a surface family,
  3. ranks polymorphic *variants* (grammar / depth / tool order / focus),
  4. mutates ``args`` with the picked variant knobs,
  5. stamps ``polymorphic`` metadata on the result envelope,
  6. on failure, can re-pick excluding the failed variant.

Heuristic only — labelled ``polymorphic (heuristic)``. Never fabricates
CVEs, PSKs, or attack success. Disable with ``KFIOSA_ALGO_POLY=0``.
"""
from __future__ import annotations

import hashlib
import os
import time
from dataclasses import dataclass, field
from functools import lru_cache, wraps
from typing import Any, Callable, Dict, List, Optional, Sequence, Set, Tuple

# ---------------------------------------------------------------------------
# Feature helpers (reuse poly_adapt when available)
# ---------------------------------------------------------------------------


def _features(target: Optional[Dict[str, Any]],
              recon: Optional[Dict[str, Any]] = None,
              args: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    bag: Dict[str, Any] = {}
    for src in (target or {}, recon or {}, args or {}):
        if isinstance(src, dict):
            bag.update(src)
    try:
        from core.utils.poly_adapt import extract_target_features
        return extract_target_features(bag)
    except Exception:  # noqa: BLE001
        pass
    # Minimal honest fallback
    return {
        "encryption": str(bag.get("encryption") or bag.get("enc") or "").lower(),
        "pmf_supported": bool(bag.get("pmf") or bag.get("pmf_supported")),
        "client_count": int(bag.get("clients") or bag.get("client_count") or 0)
        if str(bag.get("clients") or bag.get("client_count") or "0").lstrip("-").isdigit()
        else 0,
        "rssi": bag.get("rssi") or bag.get("signal"),
        "os": str(bag.get("os") or bag.get("platform") or "").lower(),
        "has_url": bool(bag.get("url") or bag.get("website")),
        "has_binary": bool(bag.get("binary") or bag.get("firmware") or bag.get("path")),
        "domain": str(bag.get("domain") or "").lower(),
        "service": str(bag.get("service") or bag.get("port") or "").lower(),
        "protocol": str(bag.get("protocol") or "").lower(),
    }


def poly_enabled() -> bool:
    raw = (os.environ.get("KFIOSA_ALGO_POLY") or "1").strip().lower()
    return raw not in ("0", "false", "off", "no")


# ---------------------------------------------------------------------------
# Families + variant grammars
# ---------------------------------------------------------------------------

# Keyword → family (first match wins; order = priority)
_FAMILY_RULES: Tuple[Tuple[str, Tuple[str, ...]], ...] = (
    ("wifi", ("wifi", "wpa", "sae", "pmkid", "deauth", "eapol", "802.11", "aircrack")),
    ("ble", ("ble", "bluetooth", "gatt", "lmp", "hid", "smp", "adv_")),
    ("crypto", ("crypto", "tls", "ssh_kex", "jwt", "saml", "oauth", "tpm", "cipher")),
    ("memory", (
        "memory", "heap", "stack", "uaf", "use_after", "integer_overflow",
        "format_string", "null_deref", "uninit", "double_fetch", "buffer",
    )),
    ("network", (
        "ipv6", "dns", "smb", "kerberos", "radius", "ldap", "ntp", "sip",
        "http2", "quic", "dhcp", "arp", "icmp", "mdns", "zeroconf", "modbus",
        "can_bus",
    )),
    ("web", (
        "xss", "ssrf", "graphql", "template", "path_traversal", "prototype",
        "deserialize", "xpath", "nosql", "xml_external", "jwt", "oauth",
    )),
    ("binary", (
        "binary", "kernel", "firmware", "container", "hypervisor", "dll",
        "office", "pdf", "iot_firmware", "crash", "patch_differ", "control_flow",
        "fuzz_harness",
    )),
    ("auth", ("auth", "session", "pairing", "preauth", "login", "saml")),
    ("cloud", ("aws", "cloud", "iam", "s3", "lambda", "ci_cd", "supply_chain",
               "dependency")),
    ("iot", ("iot", "modbus", "can_bus", "scada", "dlt", "mqtt", "coap")),
    ("mobile", ("mobile", "intent", "apk", "ios", "android")),
    ("side_channel", ("side_channel", "timing", "power", "em_", "rowhammer")),
    ("race", ("race", "toctou", "concurrency")),
    ("logic", ("logic_flaw", "business", "workflow")),
    ("ml_ai", ("ml_model", "prompt_injection", "pickle")),
    ("smart_contract", ("smart_contract", "solidity", "evm")),
    ("browser", ("browser", "js_engine")),
    ("osint", ("osint", "recon", "people", "web_")),
    ("post_exploit", ("post_exploit", "lateral", "persist", "exfil", "cred")),
    ("thinking", ("chain_of_thought", "tree_of_thought", "self_critique",
                  "react_grounded", "graph_of_thought", "self_consistency",
                  "least_to_most", "plan_and_solve", "reflexion",
                  "multi_agent", "thinking")),
)


@lru_cache(maxsize=256)
def classify_family(action: str) -> str:
    """Map algorithm / action name → surface family (cached)."""
    raw = action or ""
    a = raw.lower()
    # Strip common prefixes
    for pfx in ("zero_day_", "analyze_", "poly_", "adapt_", "algo_"):
        if a.startswith(pfx):
            a = a[len(pfx):]
    for family, keys in _FAMILY_RULES:
        for k in keys:
            if k in a:
                return family
    if "poly" in raw.lower():
        return "polymorphic"
    if "adapt" in raw.lower():
        return "adaptive"
    return "generic"


# Per-family variant grammars: name → knobs injected into args["_poly"]
_FAMILY_VARIANTS: Dict[str, List[Dict[str, Any]]] = {
    "wifi": [
        {"name": "pmkid_first", "depth": "medium", "focus": "pmkid",
         "tool_order": ["hcxdumptool", "airodump-ng", "aircrack-ng"],
         "timing": "burst", "weight": 1.1},
        {"name": "handshake_deauth", "depth": "deep", "focus": "handshake",
         "tool_order": ["aireplay-ng", "airodump-ng", "aircrack-ng"],
         "timing": "aggressive", "weight": 1.0},
        {"name": "passive_long", "depth": "shallow", "focus": "passive",
         "tool_order": ["airodump-ng", "kismet"], "timing": "slow",
         "weight": 0.9},
        {"name": "sae_commit", "depth": "deep", "focus": "sae",
         "tool_order": ["hcxdumptool", "hostapd-mana"], "timing": "stealth",
         "weight": 1.15},
        {"name": "evil_twin_branch", "depth": "deep", "focus": "evil_twin",
         "tool_order": ["hostapd", "dnsmasq"], "timing": "stealth",
         "weight": 0.85},
    ],
    "ble": [
        {"name": "gatt_enum", "depth": "medium", "focus": "gatt",
         "tool_order": ["gatttool", "bluetoothctl"], "weight": 1.0},
        {"name": "adv_sniff", "depth": "shallow", "focus": "advertising",
         "tool_order": ["hcitool", "btmon"], "weight": 0.95},
        {"name": "pairing_probe", "depth": "deep", "focus": "smp",
         "tool_order": ["bettercap", "gatttool"], "weight": 1.05},
        {"name": "l2cap_fuzz", "depth": "deep", "focus": "l2cap",
         "tool_order": ["l2ping", "bluesnarfer"], "weight": 0.9},
    ],
    "crypto": [
        {"name": "primitive_audit", "depth": "medium", "focus": "primitives",
         "patterns": ["MD5", "SHA1", "DES", "RC4", "ECB"], "weight": 1.0},
        {"name": "protocol_state", "depth": "deep", "focus": "state_machine",
         "patterns": ["downgrade", "renegotiation", "nonce_reuse"], "weight": 1.1},
        {"name": "sidechannel_hints", "depth": "deep", "focus": "timing",
         "patterns": ["constant_time", "padding_oracle"], "weight": 0.95},
        {"name": "jwt_confusion", "depth": "medium", "focus": "jwt",
         "patterns": ["alg:none", "RS256_to_HS256"], "weight": 1.05},
    ],
    "memory": [
        {"name": "bounds_prober", "depth": "deep", "focus": "bounds",
         "vectors": ["0", "1", "max-1", "max", "max+1", "neg"], "weight": 1.1},
        {"name": "lifetime_uaf", "depth": "deep", "focus": "lifetime",
         "vectors": ["free_then_use", "double_free"], "weight": 1.05},
        {"name": "type_confusion", "depth": "medium", "focus": "types",
         "vectors": ["signed_overflow", "width_trunc"], "weight": 0.95},
        {"name": "asan_guided", "depth": "shallow", "focus": "sanitizer",
         "vectors": ["asan", "ubsan"], "weight": 0.9},
    ],
    "network": [
        {"name": "malformed_pdu", "depth": "deep", "focus": "parse",
         "mutations": ["trunc", "overflow", "nested"], "weight": 1.1},
        {"name": "state_desync", "depth": "deep", "focus": "state",
         "mutations": ["reorder", "replay", "dup"], "weight": 1.05},
        {"name": "option_soup", "depth": "medium", "focus": "options",
         "mutations": ["unknown_opt", "long_opt"], "weight": 0.95},
        {"name": "timing_race", "depth": "medium", "focus": "race",
         "mutations": ["parallel", "slowloris"], "weight": 0.9},
    ],
    "web": [
        {"name": "polyglot_payload", "depth": "deep", "focus": "injection",
         "encodings": ["url", "html", "unicode", "double"], "weight": 1.1},
        {"name": "auth_chain", "depth": "deep", "focus": "auth",
         "encodings": ["jwt", "cookie", "cors"], "weight": 1.05},
        {"name": "ssrf_chain", "depth": "medium", "focus": "ssrf",
         "encodings": ["ip_literal", "dns_rebinding"], "weight": 1.0},
        {"name": "logic_workflow", "depth": "shallow", "focus": "business",
         "encodings": ["step_skip", "price_tamper"], "weight": 0.9},
    ],
    "binary": [
        {"name": "static_strings", "depth": "shallow", "focus": "static",
         "tools": ["strings", "nm", "readelf"], "weight": 0.95},
        {"name": "cfg_surf", "depth": "deep", "focus": "cfg",
         "tools": ["ghidra", "radare2", "objdump"], "weight": 1.1},
        {"name": "diff_patch", "depth": "medium", "focus": "diff",
         "tools": ["bindiff", "radiff2"], "weight": 1.0},
        {"name": "harness_gen", "depth": "deep", "focus": "fuzz",
         "tools": ["afl++", "libfuzzer", "honggfuzz"], "weight": 1.05},
    ],
    "auth": [
        {"name": "session_fixation", "depth": "medium", "focus": "session",
         "weight": 1.0},
        {"name": "token_confusion", "depth": "deep", "focus": "token",
         "weight": 1.1},
        {"name": "mfa_bypass", "depth": "deep", "focus": "mfa", "weight": 1.05},
        {"name": "oauth_redirect", "depth": "medium", "focus": "oauth",
         "weight": 0.95},
    ],
    "cloud": [
        {"name": "iam_wildcards", "depth": "medium", "focus": "iam",
         "weight": 1.1},
        {"name": "metadata_ssrf", "depth": "deep", "focus": "imds",
         "weight": 1.05},
        {"name": "public_bucket", "depth": "shallow", "focus": "storage",
         "weight": 0.95},
        {"name": "ci_secrets", "depth": "medium", "focus": "ci", "weight": 1.0},
    ],
    "iot": [
        {"name": "firmware_extract", "depth": "deep", "focus": "firmware",
         "weight": 1.1},
        {"name": "protocol_fuzz", "depth": "deep", "focus": "protocol",
         "weight": 1.05},
        {"name": "default_creds", "depth": "shallow", "focus": "creds",
         "weight": 0.9},
        {"name": "ota_tamper", "depth": "medium", "focus": "ota", "weight": 0.95},
    ],
    "mobile": [
        {"name": "intent_abuse", "depth": "medium", "focus": "intent",
         "weight": 1.05},
        {"name": "ssl_pin_bypass", "depth": "deep", "focus": "tls",
         "weight": 1.0},
        {"name": "storage_secrets", "depth": "shallow", "focus": "storage",
         "weight": 0.95},
    ],
    "side_channel": [
        {"name": "timing_class", "depth": "deep", "focus": "timing",
         "weight": 1.1},
        {"name": "cache_prime", "depth": "deep", "focus": "cache",
         "weight": 1.05},
        {"name": "power_trace", "depth": "medium", "focus": "power",
         "weight": 0.9},
    ],
    "race": [
        {"name": "toctou_window", "depth": "deep", "focus": "toctou",
         "weight": 1.1},
        {"name": "double_fetch", "depth": "deep", "focus": "double_fetch",
         "weight": 1.05},
        {"name": "lock_order", "depth": "medium", "focus": "deadlock",
         "weight": 0.9},
    ],
    "logic": [
        {"name": "step_skip", "depth": "medium", "focus": "workflow",
         "weight": 1.0},
        {"name": "privilege_confusion", "depth": "deep", "focus": "priv",
         "weight": 1.1},
        {"name": "idempotency", "depth": "shallow", "focus": "replay",
         "weight": 0.9},
    ],
    "ml_ai": [
        {"name": "prompt_jailbreak", "depth": "deep", "focus": "prompt",
         "weight": 1.1},
        {"name": "pickle_rce", "depth": "medium", "focus": "serialize",
         "weight": 1.05},
        {"name": "model_extract", "depth": "shallow", "focus": "extract",
         "weight": 0.9},
    ],
    "smart_contract": [
        {"name": "reentrancy", "depth": "deep", "focus": "reentrancy",
         "weight": 1.15},
        {"name": "oracle_manip", "depth": "deep", "focus": "oracle",
         "weight": 1.05},
        {"name": "access_control", "depth": "medium", "focus": "acl",
         "weight": 1.0},
    ],
    "browser": [
        {"name": "type_confusion", "depth": "deep", "focus": "types",
         "weight": 1.1},
        {"name": "sandbox_escape", "depth": "deep", "focus": "sandbox",
         "weight": 1.05},
        {"name": "uxss", "depth": "medium", "focus": "uxss", "weight": 0.95},
    ],
    "osint": [
        {"name": "passive_first", "depth": "shallow", "focus": "passive",
         "weight": 1.0},
        {"name": "breach_pivot", "depth": "medium", "focus": "breach",
         "weight": 1.05},
        {"name": "graph_expand", "depth": "deep", "focus": "graph",
         "weight": 1.1},
    ],
    "post_exploit": [
        {"name": "enum_then_creds", "depth": "medium", "focus": "enum",
         "weight": 1.0},
        {"name": "lateral_first", "depth": "deep", "focus": "lateral",
         "weight": 1.05},
        {"name": "persist_quiet", "depth": "medium", "focus": "persist",
         "weight": 0.95},
        {"name": "exfil_covert", "depth": "deep", "focus": "exfil",
         "weight": 1.0},
    ],
    "thinking": [
        {"name": "cot_scratch", "depth": "medium", "focus": "steps",
         "weight": 1.0},
        {"name": "tot_branch", "depth": "deep", "focus": "branches",
         "weight": 1.1},
        {"name": "critique_loop", "depth": "medium", "focus": "critique",
         "weight": 1.05},
        {"name": "plan_solve", "depth": "shallow", "focus": "plan",
         "weight": 0.95},
    ],
    "polymorphic": [
        {"name": "grammar_rotate", "depth": "deep", "focus": "grammar",
         "weight": 1.15},
        {"name": "seed_shuffle", "depth": "medium", "focus": "seed",
         "weight": 1.0},
        {"name": "depth_escalate", "depth": "deep", "focus": "escalate",
         "weight": 1.05},
    ],
    "adaptive": [
        {"name": "feature_rank", "depth": "medium", "focus": "features",
         "weight": 1.1},
        {"name": "skill_path", "depth": "shallow", "focus": "skills",
         "weight": 1.0},
        {"name": "ecosystem_pick", "depth": "medium", "focus": "ecosystem",
         "weight": 1.05},
    ],
    "generic": [
        {"name": "shallow_pass", "depth": "shallow", "focus": "overview",
         "weight": 0.9},
        {"name": "medium_pass", "depth": "medium", "focus": "balanced",
         "weight": 1.0},
        {"name": "deep_pass", "depth": "deep", "focus": "exhaustive",
         "weight": 1.05},
        {"name": "stealth_pass", "depth": "medium", "focus": "stealth",
         "timing": "slow", "weight": 0.95},
        {"name": "aggressive_pass", "depth": "deep", "focus": "aggressive",
         "timing": "burst", "weight": 0.9},
    ],
}


def _score_variant(variant: Dict[str, Any], features: Dict[str, Any],
                   family: str) -> float:
    """Heuristic score: base weight + feature affinity. Never invents facts."""
    s = float(variant.get("weight") or 1.0)
    focus = str(variant.get("focus") or "").lower()
    enc = str(features.get("encryption") or features.get("wpa_version") or "").lower()
    pmf = bool(features.get("pmf_supported") or features.get("pmf"))
    clients = int(features.get("client_count") or 0)
    has_bin = bool(
        features.get("has_binary") or features.get("binary")
        or features.get("firmware_path")
    )
    has_url = bool(features.get("has_url") or features.get("url"))
    os_s = str(features.get("os") or "").lower()

    if family == "wifi":
        if focus == "sae" and ("wpa3" in enc or "sae" in enc or pmf):
            s += 0.35
        if focus == "pmkid" and clients <= 1:
            s += 0.25
        if focus == "handshake" and clients >= 1:
            s += 0.2
        if focus == "passive" and not features.get("injection_capable"):
            s += 0.15
        if focus == "evil_twin" and pmf:
            s -= 0.1
    if family == "ble":
        rssi = features.get("rssi")
        if focus == "advertising" and rssi is not None:
            try:
                if int(rssi) < -80:
                    s += 0.2
            except (TypeError, ValueError):
                pass
        if focus == "gatt" and features.get("connectable"):
            s += 0.2
    if family in ("binary", "memory") and has_bin:
        if focus in ("cfg", "bounds", "fuzz", "static"):
            s += 0.15
    if family == "web" and has_url:
        s += 0.1
    if family == "cloud" and ("aws" in os_s or features.get("cloud")):
        s += 0.15
    if variant.get("depth") == "deep" and features.get("failed"):
        s += 0.1  # escalate after failure
    if variant.get("timing") == "stealth" and features.get("noisy"):
        s += 0.1
    return s


@dataclass
class PolyPick:
    action: str
    family: str
    variant: str
    knobs: Dict[str, Any] = field(default_factory=dict)
    score: float = 0.0
    alternatives: List[Dict[str, Any]] = field(default_factory=list)
    features: Dict[str, Any] = field(default_factory=dict)
    seed: str = ""

    def as_dict(self) -> Dict[str, Any]:
        eng = str(self.knobs.get("plum_engine") or "")
        model = (
            "polymorphic (plum heuristic)"
            if eng.startswith("plum")
            else "polymorphic (heuristic)"
        )
        return {
            "enabled": True,
            "action": self.action,
            "family": self.family,
            "variant": self.variant,
            "score": round(self.score, 4),
            "knobs": {
                k: v for k, v in self.knobs.items()
                if k not in ("weight", "name")
            },
            "alternatives": self.alternatives[:6],
            "seed": self.seed,
            "model": model,
            "plum_target_type": self.features.get("plum_target_type"),
        }


def pick_variant(
    action: str,
    target: Optional[Dict[str, Any]] = None,
    recon: Optional[Dict[str, Any]] = None,
    args: Optional[Dict[str, Any]] = None,
    *,
    exclude: Optional[Sequence[str]] = None,
    force_variant: str = "",
) -> PolyPick:
    """Pick the best polymorphic variant for this algorithm + target.

    Uses plum-dispatch multiple dispatch (Python ≥3.10) to adapt to the
    *typed* target first, then re-ranks family grammars with those boosts
    so AI plans land on the right depth/focus/tool_order for the surface.
    """
    family = classify_family(action)
    feats = _features(target, recon, args)
    ban: Set[str] = {str(x) for x in (exclude or []) if x}
    variants = list(_FAMILY_VARIANTS.get(family) or _FAMILY_VARIANTS["generic"])

    # Plum multiple-dispatch adaptation (typed target → boosts / depth / tools)
    plum_env: Dict[str, Any] = {}
    plum_boosts: Dict[str, float] = {}
    try:
        from core.poly.plum_adapt import adapt_target, apply_boosts_to_scores
        dom = str(
            (args or {}).get("domain")
            or (target or {}).get("domain")
            or family
            or ""
        )
        plum_env = adapt_target(target, recon=recon, domain=dom)
        plum_boosts = dict(plum_env.get("boosts") or {})
        # Align family with plum when algorithm family is generic
        if family in ("generic", "adaptive", "polymorphic") and plum_env.get("family"):
            family = str(plum_env["family"])
            variants = list(
                _FAMILY_VARIANTS.get(family) or _FAMILY_VARIANTS["generic"]
            )
    except Exception:  # noqa: BLE001
        apply_boosts_to_scores = None  # type: ignore

    # Operator / chain may force a variant name
    forced = (force_variant or (args or {}).get("poly_variant") or "").strip()
    ranked: List[Tuple[float, Dict[str, Any]]] = []
    for v in variants:
        name = str(v.get("name") or "")
        if name in ban:
            continue
        sc = _score_variant(v, feats, family)
        # Prefer plum depth when present
        if plum_env.get("depth") and v.get("depth") == plum_env.get("depth"):
            sc += 0.12
        if plum_env.get("focus") and v.get("focus") == plum_env.get("focus"):
            sc += 0.18
        if forced and name == forced:
            sc += 10.0
        ranked.append((sc, v))
    if not ranked:
        # all banned — fall back to generic medium
        v = {"name": "medium_pass", "depth": "medium", "focus": "balanced",
             "weight": 1.0}
        ranked = [(1.0, v)]
        family = family or "generic"

    ranked.sort(key=lambda t: (-t[0], t[1].get("name") or ""))
    if plum_boosts and apply_boosts_to_scores is not None:
        try:
            ranked = apply_boosts_to_scores(ranked, plum_boosts)
        except Exception:  # noqa: BLE001
            pass

    best_score, best = ranked[0]
    # Merge plum tool_order into knobs when variant lacks one
    knobs = {k: v for k, v in best.items() if k not in ("weight",)}
    if plum_env.get("tool_order") and not knobs.get("tool_order"):
        knobs["tool_order"] = list(plum_env["tool_order"])
    if plum_env.get("method"):
        knobs["plum_method"] = plum_env["method"]
    if plum_env.get("engine"):
        knobs["plum_engine"] = plum_env["engine"]

    # Stable-but-live seed for reproducible mutation within a step
    seed_src = (
        f"{action}|{best.get('name')}|{feats.get('encryption')}|"
        f"{feats.get('client_count')}|{plum_env.get('target_type')}|"
        f"{int(time.time()) // 30}"
    )
    seed = hashlib.sha1(seed_src.encode()).hexdigest()[:12]

    alts = [
        {"name": v.get("name"), "score": round(sc, 4), "focus": v.get("focus")}
        for sc, v in ranked[1:7]
    ]
    feat_out = {
        k: feats.get(k)
        for k in (
            "encryption", "pmf_supported", "client_count", "rssi",
            "os", "has_url", "domain", "service",
        )
        if feats.get(k) not in (None, "", [], {})
    }
    if plum_env.get("target_type"):
        feat_out["plum_target_type"] = plum_env["target_type"]
    return PolyPick(
        action=action,
        family=family,
        variant=str(best.get("name") or "medium_pass"),
        knobs=knobs,
        score=best_score,
        alternatives=alts,
        features=feat_out,
        seed=seed,
    )


def apply_poly_args(
    args: Optional[Dict[str, Any]],
    pick: PolyPick,
) -> Dict[str, Any]:
    """Inject poly knobs into algorithm args (non-destructive merge)."""
    out = dict(args or {})
    # Do not override operator-explicit keys except nested _poly
    poly_blob = {
        "variant": pick.variant,
        "family": pick.family,
        "seed": pick.seed,
        "score": round(pick.score, 4),
        **pick.knobs,
    }
    existing = out.get("_poly") if isinstance(out.get("_poly"), dict) else {}
    merged = dict(poly_blob)
    merged.update(existing)  # operator overrides win
    out["_poly"] = merged
    # Convenient top-level mirrors when not already set
    if "poly_variant" not in out:
        out["poly_variant"] = pick.variant
    if "poly_depth" not in out and pick.knobs.get("depth"):
        out["poly_depth"] = pick.knobs["depth"]
    if "poly_focus" not in out and pick.knobs.get("focus"):
        out["poly_focus"] = pick.knobs["focus"]
    # Tool order hint for algorithms that consult args
    if pick.knobs.get("tool_order") and "tool_order" not in out:
        out["tool_order"] = list(pick.knobs["tool_order"])
    if pick.knobs.get("patterns") and "patterns" not in out:
        out["patterns"] = list(pick.knobs["patterns"])
    if pick.knobs.get("vectors") and "vectors" not in out:
        out["vectors"] = list(pick.knobs["vectors"])
    if pick.knobs.get("mutations") and "mutations" not in out:
        out["mutations"] = list(pick.knobs["mutations"])
    if pick.knobs.get("encodings") and "encodings" not in out:
        out["encodings"] = list(pick.knobs["encodings"])
    if pick.knobs.get("tools") and "preferred_tools" not in out:
        out["preferred_tools"] = list(pick.knobs["tools"])
    return out


def stamp_result(result: Any, pick: PolyPick) -> Any:
    """Attach polymorphic metadata to a result envelope."""
    if not isinstance(result, dict):
        return {
            "ok": True,
            "result": result,
            "polymorphic": pick.as_dict(),
        }
    out = dict(result)
    out["polymorphic"] = pick.as_dict()
    # Promote family into concept metadata when present
    concept = out.get("concept")
    if isinstance(concept, dict):
        concept = dict(concept)
        meta = dict(concept.get("meta") or {})
        meta["polymorphic"] = {
            "variant": pick.variant,
            "family": pick.family,
            "seed": pick.seed,
        }
        concept["meta"] = meta
        # Tag technique if empty-ish
        tech = str(concept.get("technique") or "")
        if tech and "polymorphic" not in tech.lower():
            concept["technique"] = f"{tech} [poly:{pick.variant}]"
        out["concept"] = concept
    return out


def wrap_algorithm(
    action: str,
    fn: Callable[..., Dict[str, Any]],
) -> Callable[..., Dict[str, Any]]:
    """Return a polymorphic wrapper around an algorithm callable.

    Signature preserved: ``fn(target, recon, args, **kwargs)``.
    """
    if getattr(fn, "_kfiosa_poly_wrapped", False):
        return fn

    @wraps(fn)
    def _wrapped(
        target: Optional[Dict[str, Any]] = None,
        recon: Optional[Dict[str, Any]] = None,
        args: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        if not poly_enabled() or (args or {}).get("poly_disable"):
            return fn(target, recon, args, **kwargs)

        exclude = []
        if isinstance(args, dict) and args.get("poly_exclude"):
            ex = args.get("poly_exclude")
            if isinstance(ex, (list, tuple, set)):
                exclude = list(ex)
            elif isinstance(ex, str):
                exclude = [ex]

        pick = pick_variant(
            action, target, recon, args,
            exclude=exclude,
            force_variant=str((args or {}).get("poly_variant") or ""),
        )
        poly_args = apply_poly_args(args, pick)

        # Optional on_event notify
        on_event = kwargs.get("on_event")
        if callable(on_event):
            try:
                on_event(
                    f"[poly] {action} → family={pick.family} "
                    f"variant={pick.variant} score={pick.score:.2f}"
                )
            except Exception:  # noqa: BLE001
                pass

        try:
            result = fn(target, recon, poly_args, **kwargs)
        except Exception as e:  # noqa: BLE001 — stamp then re-raise policy
            # Algorithms usually return envelopes; if they raise, wrap.
            return stamp_result(
                {"ok": False, "error": f"algorithm raised: {e}"},
                pick,
            )

        stamped = stamp_result(result, pick)

        # Auto re-pick once on hard failure when not already retrying
        if (
            isinstance(stamped, dict)
            and stamped.get("ok") is False
            and not (args or {}).get("_poly_retry")
            and pick.alternatives
        ):
            alt = pick.alternatives[0].get("name")
            if alt and alt != pick.variant:
                retry_args = dict(poly_args)
                retry_args["poly_variant"] = alt
                retry_args["poly_exclude"] = list(exclude) + [pick.variant]
                retry_args["_poly_retry"] = True
                try:
                    result2 = fn(target, recon, retry_args, **kwargs)
                    pick2 = pick_variant(
                        action, target, recon, retry_args,
                        force_variant=str(alt),
                    )
                    stamped2 = stamp_result(result2, pick2)
                    if isinstance(stamped2, dict):
                        stamped2["polymorphic_retry"] = {
                            "from": pick.variant,
                            "to": alt,
                            "prior_error": stamped.get("error"),
                        }
                        if stamped2.get("ok"):
                            return stamped2
                except Exception:  # noqa: BLE001
                    pass
        return stamped

    _wrapped._kfiosa_poly_wrapped = True  # type: ignore[attr-defined]
    _wrapped._kfiosa_poly_action = action  # type: ignore[attr-defined]
    _wrapped.__wrapped_algo__ = fn  # type: ignore[attr-defined]
    return _wrapped


def ensure_all_polymorphic(
    registry: Dict[str, Callable[..., Dict[str, Any]]],
) -> Dict[str, Callable[..., Dict[str, Any]]]:
    """In-place wrap every algorithm in a name→callable registry."""
    for name, fn in list(registry.items()):
        if not callable(fn):
            continue
        if getattr(fn, "_kfiosa_poly_wrapped", False):
            continue
        registry[name] = wrap_algorithm(name, fn)
    return registry


def describe_algorithm_poly(action: str) -> Dict[str, Any]:
    """Introspection helper for TUI / MCP / tests."""
    family = classify_family(action)
    variants = _FAMILY_VARIANTS.get(family) or _FAMILY_VARIANTS["generic"]
    return {
        "ok": True,
        "action": action,
        "family": family,
        "variant_count": len(variants),
        "variants": [
            {
                "name": v.get("name"),
                "depth": v.get("depth"),
                "focus": v.get("focus"),
                "weight": v.get("weight"),
            }
            for v in variants
        ],
        "enabled": poly_enabled(),
        "model": "polymorphic (heuristic)",
    }


def poly_prompt_addon(args: Optional[Dict[str, Any]]) -> str:
    """Compact prompt fragment algorithms can append to LLM queries."""
    if not isinstance(args, dict):
        return ""
    poly = args.get("_poly") if isinstance(args.get("_poly"), dict) else {}
    if not poly:
        return ""
    parts = [
        f"Polymorphic variant: {poly.get('variant') or args.get('poly_variant')}",
        f"Family: {poly.get('family')}",
        f"Focus: {poly.get('focus') or args.get('poly_focus')}",
        f"Depth: {poly.get('depth') or args.get('poly_depth')}",
    ]
    if poly.get("tool_order"):
        parts.append(f"Preferred tool order: {poly.get('tool_order')}")
    if poly.get("patterns"):
        parts.append(f"Pattern set: {poly.get('patterns')}")
    if poly.get("vectors"):
        parts.append(f"Probe vectors: {poly.get('vectors')}")
    parts.append(
        "Vary technique presentation under this variant; still never invent "
        "CVEs/PSKs/hashes. Prefer real tools from context."
    )
    return "\n".join(parts)


def register_algorithms_as_strategies(
    action_names: Sequence[str],
) -> int:
    """Register zero-day algorithms into poly_runtime DEFAULT_REGISTRY."""
    try:
        from core.utils.poly_runtime import (
            Domain, Phase, Strategy, register_domain_strategy,
        )
    except Exception:  # noqa: BLE001
        return 0
    n = 0
    for name in action_names:
        family = classify_family(name)
        short = name.replace("zero_day_", "")[:40]
        try:
            register_domain_strategy(Strategy(
                name=short,
                domain=Domain.ZERO_DAY,
                phase=Phase.ENUMERATION,
                keywords=(family, short.split("_")[0]),
                weight=0.75,
                description=f"polymorphic algorithm {name} [{family}]",
            ))
            n += 1
        except Exception:  # noqa: BLE001
            continue
    return n


__all__ = [
    "PolyPick",
    "classify_family",
    "pick_variant",
    "apply_poly_args",
    "stamp_result",
    "wrap_algorithm",
    "ensure_all_polymorphic",
    "describe_algorithm_poly",
    "poly_prompt_addon",
    "poly_enabled",
    "register_algorithms_as_strategies",
]
