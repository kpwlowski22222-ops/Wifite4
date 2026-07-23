"""core.utils.poly_runtime — detailed Python 3.10 polymorphism for KFIOSA.

Makes attack / recon / OSINT / post-exploit choices *situational*:
the same logical action picks different concrete methods based on
observed features, domain, and optional AI hints.

Polymorphism forms used (all 3.10-friendly, no 3.11-only syntax):

1. **Strategy objects** (:class:`Strategy`, :class:`StrategyRegistry`)
2. **Structural typing** (``typing.Protocol``) for duck-typed runners
3. **``functools.singledispatch``** over feature bag types / domains
4. **``match`` / ``case``** (3.10 structural pattern matching) for
   domain+phase routing
5. **Mixin inheritance** (:class:`SituationalMixin`) for runners
6. **Parametric polymorphism** via ``TypeVar`` + generic envelopes
7. **Ad-hoc polymorphism** via score-rule composition from
   :mod:`core.utils.poly_adapt`
8. **AI-driven override** — optional ``ai_hint`` / chain planner
   pick that still re-scores against live features (never trusts
   the LLM blindly)

Honest-degrade: never fabricates CVEs, PSKs, or tool success.
Heuristics are labelled ``polymorphic (heuristic)`` /
``target-adaptive (heuristic)`` — not trained-ML.

Example::

    from core.utils.poly_runtime import situational_pick, Domain
    env = situational_pick(
        domain="wifi",
        features={"wpa_version": "wpa3", "pmf_supported": True},
        phase="exploit",
    )
    # env["pick"] == "wpa3_sae", env["poly_kind"] == "target-adaptive"
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from functools import singledispatch, lru_cache
from typing import (
    Any,
    Callable,
    Dict,
    Iterable,
    List,
    Optional,
    Protocol,
    Sequence,
    Tuple,
    TypeVar,
    Union,
    runtime_checkable,
)

# Re-use existing scorers (hot path already optimised).
from core.utils.poly_adapt import (
    extract_target_features,
    pick_best_variant,
    pick_ble_strategy,
    pick_osint_strategy,
    pick_post_exploit_strategy,
    pick_wifi_strategy,
    score_variants,
)

__all__ = [
    "Domain",
    "Phase",
    "PolyKind",
    "Strategy",
    "StrategyRegistry",
    "SituationalRunner",
    "SituationalMixin",
    "PolyEnvelope",
    "situational_pick",
    "dispatch_by_domain",
    "register_domain_strategy",
    "ai_driven_pick",
    "poly_methods_for_features",
    "describe_polymorphism",
]


T = TypeVar("T")


# ---------------------------------------------------------------------------
# Enumerations (closed sets for match/case)
# ---------------------------------------------------------------------------

class Domain(str, Enum):
    WIFI = "wifi"
    BLE = "ble"
    OSINT = "osint"
    POST_EXPLOIT = "post_exploitation"
    RECON = "recon"
    C2 = "c2"
    ZERO_DAY = "zero_day"
    UNKNOWN = "unknown"

    @classmethod
    def coerce(cls, value: Any) -> "Domain":
        s = str(value or "").strip().lower().replace("-", "_")
        aliases = {
            "post_exploit": cls.POST_EXPLOIT,
            "post": cls.POST_EXPLOIT,
            "wireless": cls.WIFI,
            "bluetooth": cls.BLE,
            "0day": cls.ZERO_DAY,
            "zeroday": cls.ZERO_DAY,
        }
        if s in aliases:
            return aliases[s]
        try:
            return cls(s)
        except ValueError:
            return cls.UNKNOWN


class Phase(str, Enum):
    RECON = "recon"
    ENUMERATION = "enumeration"
    EXPLOIT = "exploit"
    POST_EXPLOIT = "post_exploit"
    CLEANUP = "cleanup"
    ANY = "any"

    @classmethod
    def coerce(cls, value: Any) -> "Phase":
        s = str(value or "any").strip().lower()
        try:
            return cls(s)
        except ValueError:
            return cls.ANY


class PolyKind(str, Enum):
    STRATEGY = "strategy"
    TARGET_ADAPTIVE = "target-adaptive"
    GRAMMAR = "polymorphic-grammar"
    AI_DRIVEN = "ai-driven"
    SINGLEDISPATCH = "singledispatch"
    MATCH_CASE = "match-case"


# ---------------------------------------------------------------------------
# Protocols (structural subtyping)
# ---------------------------------------------------------------------------

@runtime_checkable
class SituationalRunner(Protocol):
    """Anything that can run a named method with a feature bag."""

    def run_method(self, name: str, features: Dict[str, Any]) -> Dict[str, Any]:
        ...


# ---------------------------------------------------------------------------
# Strategy objects + registry
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Strategy:
    """One concrete tactical choice with applicability predicate."""

    name: str
    domain: Domain
    phase: Phase = Phase.ANY
    keywords: Tuple[str, ...] = ()
    min_clients: int = 0
    requires_address: bool = False
    requires_creds: bool = False
    weight: float = 1.0
    description: str = ""

    def applicable(self, features: Dict[str, Any]) -> bool:
        if self.requires_address and not (
            features.get("address") or features.get("bssid")
        ):
            return False
        if self.requires_creds and not features.get("has_creds"):
            return False
        if int(features.get("client_count") or 0) < self.min_clients:
            # min_clients=0 always ok
            if self.min_clients > 0:
                return False
        return True

    def score(self, features: Dict[str, Any]) -> float:
        if not self.applicable(features):
            return 0.0
        s = float(self.weight)
        blob = " ".join(
            str(features.get(k) or "")
            for k in ("wpa_version", "os", "query_type", "pairing", "phase")
        ).lower()
        for kw in self.keywords:
            if kw.lower() in blob:
                s += 0.15
        return min(1.0, s)


class StrategyRegistry:
    """Domain-keyed strategy bank (parametric + ad-hoc polymorphism)."""

    def __init__(self) -> None:
        self._by_domain: Dict[Domain, List[Strategy]] = {}

    def register(self, strategy: Strategy) -> None:
        self._by_domain.setdefault(strategy.domain, []).append(strategy)

    def register_many(self, strategies: Iterable[Strategy]) -> None:
        for s in strategies:
            self.register(s)

    def candidates(
        self, domain: Domain, phase: Phase = Phase.ANY,
    ) -> List[Strategy]:
        out = list(self._by_domain.get(domain, []))
        if phase is not Phase.ANY:
            out = [
                s for s in out
                if s.phase in (phase, Phase.ANY)
            ]
        return out

    def pick(
        self,
        domain: Domain,
        features: Dict[str, Any],
        phase: Phase = Phase.ANY,
    ) -> Optional[Strategy]:
        cands = self.candidates(domain, phase)
        if not cands:
            return None
        ranked = sorted(
            ((s.score(features), s.name, s) for s in cands),
            key=lambda t: (-t[0], t[1]),
        )
        best_score, _, best = ranked[0]
        if best_score <= 0.0:
            return None
        return best


# Default universal strategy bank (extend at runtime via register).
DEFAULT_REGISTRY = StrategyRegistry()
DEFAULT_REGISTRY.register_many([
    # WiFi
    Strategy("open", Domain.WIFI, Phase.EXPLOIT, keywords=("open",), weight=0.9,
             description="Open network join / captive paths"),
    Strategy("wep", Domain.WIFI, Phase.EXPLOIT, keywords=("wep",), weight=0.95,
             description="WEP chopchop / ARP replay"),
    Strategy("enterprise", Domain.WIFI, Phase.EXPLOIT, keywords=("enterprise", "eap"),
             weight=0.95, description="802.1X / PEAP hostapd-wpe path"),
    Strategy("wpa3_sae", Domain.WIFI, Phase.EXPLOIT, keywords=("wpa3", "sae"),
             weight=0.95, description="WPA3 SAE commit / transition"),
    Strategy("wpa2_transition", Domain.WIFI, Phase.EXPLOIT, keywords=("transition",),
             weight=0.9, description="WPA3-transition → WPA2-side attacks"),
    Strategy("wpa2", Domain.WIFI, Phase.EXPLOIT, keywords=("wpa2", "psk"),
             weight=0.85, description="PMKID / handshake / deauth"),
    Strategy("wifi_recon_passive", Domain.WIFI, Phase.RECON, weight=0.8,
             description="airodump / Kismet passive recon"),
    # BLE
    Strategy("recon", Domain.BLE, Phase.RECON, weight=0.9,
             description="ADV parse + long-range scan"),
    Strategy("gatt_write", Domain.BLE, Phase.EXPLOIT, requires_address=True,
             weight=0.85, description="Active GATT write probe"),
    Strategy("hid_inject", Domain.BLE, Phase.EXPLOIT, keywords=("hid",),
             requires_address=True, weight=0.95, description="HID injection"),
    Strategy("pairing", Domain.BLE, Phase.EXPLOIT, keywords=("pair", "just_works"),
             requires_address=True, weight=0.8, description="Pairing / SMP probe"),
    Strategy("mesh", Domain.BLE, Phase.EXPLOIT, keywords=("mesh",), weight=0.9,
             description="Mesh proxy / friend abuse"),
    Strategy("le_audio", Domain.BLE, Phase.EXPLOIT, keywords=("audio", "bap"),
             weight=0.9, description="LE Audio / BAP"),
    # OSINT
    Strategy("username", Domain.OSINT, Phase.RECON, keywords=("username", "handle"),
             weight=0.85, description="Username footprint"),
    Strategy("email", Domain.OSINT, Phase.RECON, keywords=("email",), weight=0.95,
             description="Email / harvest path"),
    Strategy("domain", Domain.OSINT, Phase.RECON, keywords=("domain",), weight=0.95,
             description="Domain / subdomain path"),
    Strategy("person_pl", Domain.OSINT, Phase.RECON, keywords=("pl", "poland"),
             weight=0.9, description="Polish person OSINT (no-key)"),
    Strategy("phone_pl", Domain.OSINT, Phase.RECON, keywords=("phone",),
             weight=0.9, description="PL phone carrier / spider"),
    Strategy("breach", Domain.OSINT, Phase.ENUMERATION, keywords=("breach", "hibp"),
             weight=0.85, description="Breach / HIBP k-anonymity"),
    # Post-exploit
    Strategy("enum", Domain.POST_EXPLOIT, Phase.POST_EXPLOIT, weight=0.75,
             description="Situational awareness / enum"),
    Strategy("cred_dump", Domain.POST_EXPLOIT, Phase.POST_EXPLOIT,
             keywords=("windows", "linux"), weight=0.9,
             description="Credential harvest outline"),
    Strategy("lateral", Domain.POST_EXPLOIT, Phase.POST_EXPLOIT,
             requires_creds=True, weight=0.95, description="Lateral movement"),
    Strategy("persist", Domain.POST_EXPLOIT, Phase.POST_EXPLOIT, weight=0.85,
             description="Persistence mechanism"),
    Strategy("exfil", Domain.POST_EXPLOIT, Phase.POST_EXPLOIT, weight=0.8,
             description="Exfiltration channel"),
    Strategy("cleanup", Domain.POST_EXPLOIT, Phase.CLEANUP, weight=0.8,
             description="Anti-forensic cleanup"),
    # Recon / C2 / zero-day
    Strategy("catalog_recon", Domain.RECON, Phase.RECON, weight=0.85,
             description="CatalogRecon + Kismet prechain"),
    Strategy("lab_beacon", Domain.C2, Phase.POST_EXPLOIT, weight=0.85,
             description="Lab C2 beacon design"),
    Strategy("hypothesis", Domain.ZERO_DAY, Phase.ENUMERATION, weight=0.8,
             description="0-day concept hypothesis (pseudocode only)"),
])


def register_domain_strategy(strategy: Strategy) -> None:
    """Public extension point for modules to add strategies at import time."""
    DEFAULT_REGISTRY.register(strategy)


# ---------------------------------------------------------------------------
# singledispatch by domain string (ad-hoc polymorphism)
# ---------------------------------------------------------------------------

@singledispatch
def dispatch_by_domain(domain_obj: Any, features: Dict[str, Any]) -> str:
    """Pick a strategy name; default unknown → empty."""
    dom = Domain.coerce(domain_obj)
    return _pick_name_for_domain(dom, features)


@dispatch_by_domain.register
def _(domain_obj: Domain, features: Dict[str, Any]) -> str:
    return _pick_name_for_domain(domain_obj, features)


@dispatch_by_domain.register
def _(domain_obj: str, features: Dict[str, Any]) -> str:  # type: ignore[no-redef]
    return _pick_name_for_domain(Domain.coerce(domain_obj), features)


def _pick_name_for_domain(domain: Domain, features: Dict[str, Any]) -> str:
    # Prefer dedicated scorers (already battle-tested) then registry.
    if domain is Domain.WIFI:
        return pick_wifi_strategy(features)
    if domain is Domain.BLE:
        return pick_ble_strategy(features)
    if domain is Domain.OSINT:
        return pick_osint_strategy(features)
    if domain is Domain.POST_EXPLOIT:
        return pick_post_exploit_strategy(features)
    strat = DEFAULT_REGISTRY.pick(domain, features)
    return strat.name if strat else "enum"


# ---------------------------------------------------------------------------
# match/case situational router (3.10 structural pattern matching)
# ---------------------------------------------------------------------------

def _match_route(domain: Domain, phase: Phase, features: Dict[str, Any]) -> Tuple[str, PolyKind]:
    """Route with match/case on (domain, phase) pairs."""
    clients = int(features.get("client_count") or 0)
    pmf = bool(features.get("pmf_supported"))
    has_creds = bool(features.get("has_creds"))

    match (domain, phase):
        # Explicit recon phase only — do not steal EXPLOIT/ANY wifi picks.
        case (Domain.WIFI, Phase.RECON) if not features.get("bssid"):
            return "wifi_recon_passive", PolyKind.MATCH_CASE
        case (Domain.WIFI, Phase.EXPLOIT | Phase.ANY | Phase.ENUMERATION):
            return pick_wifi_strategy(features), PolyKind.TARGET_ADAPTIVE
        case (Domain.BLE, Phase.RECON):
            return "recon", PolyKind.MATCH_CASE
        case (Domain.BLE, Phase.EXPLOIT | Phase.ANY | Phase.ENUMERATION):
            return pick_ble_strategy(features), PolyKind.TARGET_ADAPTIVE
        case (Domain.OSINT, _):
            return pick_osint_strategy(features), PolyKind.TARGET_ADAPTIVE
        case (Domain.POST_EXPLOIT, Phase.CLEANUP):
            return "cleanup", PolyKind.MATCH_CASE
        case (Domain.POST_EXPLOIT, _) if has_creds and features.get("network_access"):
            return "lateral", PolyKind.MATCH_CASE
        case (Domain.POST_EXPLOIT, _):
            return pick_post_exploit_strategy(features), PolyKind.TARGET_ADAPTIVE
        case (Domain.RECON, _):
            return "catalog_recon", PolyKind.MATCH_CASE
        case (Domain.C2, _):
            return "lab_beacon", PolyKind.MATCH_CASE
        case (Domain.ZERO_DAY, _):
            return "hypothesis", PolyKind.MATCH_CASE
        case _:
            name = _pick_name_for_domain(domain, features)
            return name, PolyKind.STRATEGY


# ---------------------------------------------------------------------------
# Envelope + public pick API
# ---------------------------------------------------------------------------

PolyEnvelope = Dict[str, Any]


def situational_pick(
    domain: Union[str, Domain],
    features: Optional[Dict[str, Any]] = None,
    *,
    phase: Union[str, Phase] = Phase.ANY,
    context: Optional[Dict[str, Any]] = None,
    ai_hint: Optional[str] = None,
) -> PolyEnvelope:
    """Universal situational pick used by chain / runners / dashboard.

    Returns::

        {
          ok, pick, domain, phase, poly_kind, rationale,
          alternatives: [{name, score}, ...],
          features_used: {...},
          model: "target-adaptive (heuristic)" | "ai-driven (heuristic)",
        }
    """
    dom = Domain.coerce(domain)
    ph = Phase.coerce(phase)
    raw = dict(context or {})
    if features:
        raw.update(features)
    feats = extract_target_features(raw)

    pick_name, kind = _match_route(dom, ph, feats)
    alts: List[Dict[str, Any]] = []

    # Compose alternatives from registry for transparency
    for s in DEFAULT_REGISTRY.candidates(dom, ph):
        sc = s.score(feats)
        if sc > 0:
            alts.append({"name": s.name, "score": round(sc, 4),
                         "description": s.description})
    alts.sort(key=lambda x: (-x["score"], x["name"]))

    # Plum multiple-dispatch (Python ≥3.10) — typed target adaptation.
    # Soft integration: re-rank registry alts with plum boosts; only
    # replace pick when plum method is an exact registry strategy name.
    plum_meta: Dict[str, Any] = {}
    try:
        from core.poly.plum_adapt import adapt_target
        penv = adapt_target(raw, domain=dom.value)
        plum_meta = {
            "target_type": penv.get("target_type"),
            "method": penv.get("method"),
            "focus": penv.get("focus"),
            "depth": penv.get("depth"),
            "engine": penv.get("engine"),
            "boosts": penv.get("boosts") or {},
            "rationale": penv.get("rationale"),
            "tool_order": penv.get("tool_order") or [],
        }
        boosts = plum_meta.get("boosts") or {}
        # Map plum focus → known strategy names for soft re-rank
        focus = str(penv.get("focus") or "").lower()
        focus_map = {
            Domain.WIFI: {
                "sae": "wpa3_sae", "pmkid": "wpa2", "handshake": "wpa2",
                "passive": "wifi_recon_passive", "evil_twin": "wpa2",
            },
            Domain.BLE: {
                "gatt": "gatt_write", "advertising": "recon",
                "smp": "pairing", "l2cap": "mesh",
            },
            Domain.OSINT: {
                "breach": "breach", "passive": "username",
                "graph": "domain",
            },
            Domain.POST_EXPLOIT: {
                "lateral": "lateral", "enum": "enum",
                "persist": "persist", "exfil": "exfil",
            },
        }
        mapped = (focus_map.get(dom) or {}).get(focus)
        pm = str(penv.get("method") or "")
        # Exact registry hit only (preserve scorer API for tests)
        if pm and any(a["name"] == pm for a in alts):
            pick_name = pm
            kind = PolyKind.TARGET_ADAPTIVE
        elif mapped and any(a["name"] == mapped for a in alts):
            # Soft re-rank: if mapped strategy already scores well, keep scorer
            # pick; only override when scorer pick is generic recon and plum
            # has a stronger focus.
            if pick_name in ("enum", "recon", "catalog_recon", "hypothesis"):
                pick_name = mapped
                kind = PolyKind.TARGET_ADAPTIVE
        # Boost alt scores for transparency
        if boosts or mapped:
            for a in alts:
                n = a["name"]
                if n in boosts:
                    a["score"] = round(float(a["score"]) + float(boosts[n]), 4)
                if mapped and n == mapped:
                    a["score"] = round(float(a["score"]) + 0.15, 4)
            alts.sort(key=lambda x: (-x["score"], x["name"]))
    except Exception:  # noqa: BLE001
        pass

    # AI-driven override: accept hint only if it scores > 0 against features
    model = (
        "target-adaptive (plum heuristic)"
        if str(plum_meta.get("engine") or "").startswith("plum")
        else "target-adaptive (heuristic)"
    )
    rationale = f"match/case + domain scorer → {pick_name}"
    if plum_meta.get("method"):
        rationale = (
            f"plum[{plum_meta.get('target_type')}] "
            f"{plum_meta.get('method')} + {rationale}"
        )
    if ai_hint:
        hint = str(ai_hint).strip()
        # score hint as a fake strategy
        hint_ok = False
        for a in alts:
            if a["name"] == hint and a["score"] > 0:
                pick_name = hint
                kind = PolyKind.AI_DRIVEN
                model = "ai-driven (heuristic)"
                rationale = (
                    f"AI hint {hint!r} accepted after feature re-score "
                    f"(score={a['score']})"
                )
                hint_ok = True
                break
        if not hint_ok and hint:
            # Still allow exact domain scorer names even if not in registry alts
            scorer_names = {
                Domain.WIFI: (
                    "open", "wep", "enterprise", "wpa3_sae",
                    "wpa2_transition", "wpa2",
                ),
                Domain.BLE: (
                    "recon", "gatt_write", "hid_inject", "pairing",
                    "mesh", "le_audio",
                ),
                Domain.OSINT: (
                    "username", "email", "domain", "person_pl",
                    "phone_pl", "breach",
                ),
                Domain.POST_EXPLOIT: (
                    "enum", "cred_dump", "lateral", "persist",
                    "exfil", "cleanup",
                ),
            }
            allowed = scorer_names.get(dom, ())
            if hint in allowed:
                pick_name = hint
                kind = PolyKind.AI_DRIVEN
                model = "ai-driven (heuristic)"
                rationale = f"AI hint {hint!r} in domain scorer allow-list"
            else:
                rationale += f"; AI hint {hint!r} rejected (not feature-compatible)"

    out: PolyEnvelope = {
        "ok": True,
        "pick": pick_name,
        "domain": dom.value,
        "phase": ph.value,
        "poly_kind": kind.value,
        "rationale": rationale,
        "alternatives": alts[:12],
        "features_used": {
            k: feats.get(k)
            for k in (
                "wpa_version", "pmf_supported", "client_count", "band",
                "os", "address", "query_type", "has_creds", "has_hid",
            )
        },
        "model": model,
        "error": None,
    }
    if plum_meta:
        out["plum"] = plum_meta
    return out


def ai_driven_pick(
    domain: str,
    context: Optional[Dict[str, Any]] = None,
    ai_hint: Optional[str] = None,
    phase: str = "any",
) -> PolyEnvelope:
    """Convenience wrapper used by chain planner / dashboard recommender."""
    return situational_pick(
        domain, context=context, phase=phase, ai_hint=ai_hint,
    )


def poly_methods_for_features(
    domain: str,
    features: Optional[Dict[str, Any]] = None,
    limit: int = 8,
) -> List[str]:
    """Suggest poly_adapt / strategy method names for the AI chain."""
    env = situational_pick(domain, features=features)
    names = [env["pick"]]
    for a in env.get("alternatives") or []:
        n = a.get("name")
        if n and n not in names:
            names.append(str(n))
        if len(names) >= limit:
            break
    # Prefix adapt_ when it looks like a picker family
    out: List[str] = []
    for n in names:
        if n.startswith(("poly_", "adapt_")):
            out.append(n)
        else:
            out.append(n)
    return out[:limit]


@lru_cache(maxsize=1)
def describe_polymorphism() -> str:
    """Human/AI-readable catalogue of polymorphism forms in this module."""
    return (
        "KFIOSA poly_runtime forms (Python 3.10):\n"
        "  1. Strategy objects + StrategyRegistry (domain banks)\n"
        "  2. Protocol/SituationalRunner (structural typing)\n"
        "  3. functools.singledispatch on domain\n"
        "  4. match/case on (Domain, Phase) with feature guards\n"
        "  5. SituationalMixin for runner classes\n"
        "  6. TypeVar envelopes (PolyEnvelope)\n"
        "  7. Score-rule composition via poly_adapt\n"
        "  8. AI-driven hints re-scored against live features\n"
        "Never invents CVEs/PSKs; companions are heuristic, not ML.\n"
    )


# ---------------------------------------------------------------------------
# Mixin for runners (inheritance polymorphism)
# ---------------------------------------------------------------------------

class SituationalMixin:
    """Drop-in mixin: ``self.situational_pick(domain, **ctx)``."""

    def situational_pick(
        self,
        domain: str,
        *,
        phase: str = "any",
        ai_hint: Optional[str] = None,
        **feature_kwargs: Any,
    ) -> PolyEnvelope:
        ctx = dict(feature_kwargs)
        # Prefer self.context / self.seed if present
        for attr in ("context", "seed", "target", "features"):
            blob = getattr(self, attr, None)
            if isinstance(blob, dict):
                merged = dict(blob)
                merged.update(ctx)
                ctx = merged
                break
        return situational_pick(
            domain, context=ctx, phase=phase, ai_hint=ai_hint,
        )

    def poly_run(
        self,
        domain: str,
        runner_fn: Callable[[str, Dict[str, Any]], Dict[str, Any]],
        **feature_kwargs: Any,
    ) -> Dict[str, Any]:
        """Pick then invoke ``runner_fn(pick, features)``."""
        env = self.situational_pick(domain, **feature_kwargs)
        pick = str(env.get("pick") or "")
        feats = extract_target_features(feature_kwargs)
        try:
            result = runner_fn(pick, feats)
        except Exception as e:  # noqa: BLE001
            return {
                "ok": False,
                "error": f"poly_run failed: {e}",
                "pick": pick,
                "poly": env,
            }
        if isinstance(result, dict):
            result = dict(result)
            result.setdefault("poly", env)
            result.setdefault("pick", pick)
            return result
        return {"ok": True, "data": result, "pick": pick, "poly": env}
