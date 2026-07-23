"""core.utils.poly_adapt — polymorphic + target-adaptive picker mixins.

Phase 2.4 — generalised companion-method pattern (see plan
``tingly-mixing-hammock.md``). Additive: existing universal methods
stay; ``_v2_poly_<name>`` and ``_v2_adapt_<name>`` are new methods
the LLM can pick when it has the necessary context.

Polymorphic methods
    A polymorphic method takes a ``context`` dict and returns a
    *grammar* — a list of variant parameter sets, plus a single
    ``picked`` choice. The envelope shape is::

        {ok: True, data: {variants: [...], picked: "<name>",
                          picked_params: {...}}, model:
         "polymorphic (heuristic)"}

Target-adaptive methods
    A target-adaptive method takes a ``context`` dict and returns
    a single concrete universal method name to call next, plus a
    ``rationale``. The envelope shape is::

        {ok: True, data: {pick: "<universal_method>", rationale:
                          "...", family: "..."}, model:
         "target-adaptive (heuristic)"}

Both are heuristic (not trained-ML) — the v2 registries must be
labelled accordingly and never produce a fake prediction.

Phase poly-opt (2026-07):
    Shared target-feature extraction, score-based variant ranking,
    and a short-TTL memo cache so companions become truly
    target-adaptive instead of always returning ``variants[0]``.
"""
from __future__ import annotations

import hashlib
import json
import threading
import time
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple


# ---------------------------------------------------------------------------
# Target feature extraction (shared by poly grammars + adapt pickers)
# ---------------------------------------------------------------------------

_BOOL_TRUE = frozenset({"1", "true", "yes", "on", "y"})


def _as_bool(v: Any) -> bool:
    if isinstance(v, bool):
        return v
    if v is None:
        return False
    if isinstance(v, (int, float)):
        return bool(v)
    return str(v).strip().lower() in _BOOL_TRUE


def _as_int(v: Any, default: int = 0) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


def _lower(v: Any) -> str:
    return str(v or "").strip().lower()


def extract_target_features(context: Optional[Dict[str, Any]] = None
                            ) -> Dict[str, Any]:
    """Normalise a seed / step-args dict into a flat feature bag.

    Never invents network facts — only re-keys and coerces what is
    already present. Safe for empty / None input.
    """
    ctx = dict(context or {})
    # Nested recon / seed blobs common in orchestrator paths
    recon = ctx.get("recon") if isinstance(ctx.get("recon"), dict) else {}
    seed = ctx.get("seed") if isinstance(ctx.get("seed"), dict) else {}
    # Flatten one level: seed/recon values fill missing top-level keys
    for blob in (seed, recon):
        for k, v in blob.items():
            if k not in ctx or ctx.get(k) in (None, "", [], {}):
                ctx[k] = v

    enc = _lower(ctx.get("encryption") or ctx.get("enc") or ctx.get("security"))
    wpa_version = _lower(ctx.get("wpa_version") or "")
    if not wpa_version:
        if "wpa3" in enc or "sae" in enc:
            wpa_version = "wpa3"
        elif "enterprise" in enc or "wpa2-eap" in enc or "802.1x" in enc:
            wpa_version = "wpa2_enterprise"
        elif "wpa2" in enc or enc in ("wpa", "rsn", "wpa2-psk"):
            wpa_version = "wpa2"
        elif "wep" in enc:
            wpa_version = "wep"
        elif enc in ("open", "none", "opn"):
            wpa_version = "open"

    clients = ctx.get("clients")
    if isinstance(clients, list):
        client_count = len(clients)
    else:
        client_count = _as_int(ctx.get("client_count"), 0)

    pmf = (
        _as_bool(ctx.get("pmf_supported"))
        or _as_bool(ctx.get("pmf"))
        or "pmf" in enc
        or "mfp" in enc
        or wpa_version == "wpa3"
    )
    transition = (
        _as_bool(ctx.get("transition"))
        or _as_bool(ctx.get("transition_mode"))
        or ("wpa2" in enc and "wpa3" in enc)
        or ("sae" in enc and "psk" in enc)
    )
    band = _lower(ctx.get("band") or "")
    channel = _as_int(ctx.get("channel"), 0)
    if not band and channel:
        if channel >= 1 and channel <= 14:
            band = "2.4"
        elif channel >= 36:
            band = "5" if channel < 200 else "6"

    signal = ctx.get("signal")
    if signal is None:
        signal = ctx.get("rssi")
    try:
        signal_i = int(signal) if signal is not None else None
    except (TypeError, ValueError):
        signal_i = None

    features: Dict[str, Any] = {
        "bssid": str(ctx.get("bssid") or ctx.get("ap_bssid") or ""),
        "ssid": str(ctx.get("ssid") or ctx.get("essid") or ""),
        "encryption": enc,
        "wpa_version": wpa_version,
        "pmf_supported": pmf,
        "transition_mode": transition,
        "client_count": client_count,
        "channel": channel,
        "band": band,
        "signal": signal_i,
        "chipset": _lower(ctx.get("chipset") or ctx.get("driver") or ""),
        "iface": str(ctx.get("iface") or ctx.get("interface") or ctx.get("name") or ""),
        "mode": _lower(ctx.get("mode") or ""),
        "os": _lower(ctx.get("os") or ctx.get("target_os") or ""),
        "distro": _lower(ctx.get("distro") or ctx.get("linux_distro") or ""),
        "address": str(
            ctx.get("address") or ctx.get("addr") or ctx.get("mac") or ""
        ),
        "io_cap": _lower(ctx.get("io_cap") or ctx.get("iocap") or ""),
        "auth_required": _as_bool(ctx.get("auth_required")),
        "jurisdiction": _lower(ctx.get("jurisdiction") or ctx.get("country") or ""),
        "injection_capable": _as_bool(
            ctx.get("injection_capable")
            if ctx.get("injection_capable") is not None
            else (
                (ctx.get("adapter_caps") or {}).get("injection_capable")
                if isinstance(ctx.get("adapter_caps"), dict)
                else False
            )
        ),
        "wps": (
            _as_bool(ctx.get("wps"))
            or "wps" in enc
            or (
                isinstance(recon.get("wps"), dict)
                and _as_bool(recon["wps"].get("ok"))
            )
        ),
        "has_pcap": bool(ctx.get("cap_file") or ctx.get("pcap") or ctx.get("handshake")),
        "has_wordlist": bool(ctx.get("wordlist") or ctx.get("weakpass")),
        "domain": _lower(ctx.get("domain") or ctx.get("attack_surface") or ""),
        "phase": _lower(ctx.get("phase") or ctx.get("chain_phase") or ""),
        "seed": str(ctx.get("seed") or ctx.get("bssid") or ctx.get("ssid") or "default"),
        # Pass-through raw for advanced scorers
        "_raw": ctx,
    }
    return features


# ---------------------------------------------------------------------------
# Variant scoring / ranking
# ---------------------------------------------------------------------------

Variant = Dict[str, Any]
ScoreRule = Callable[[Variant, Dict[str, Any]], float]


def _variant_name(v: Any) -> str:
    if isinstance(v, dict):
        return str(v.get("name") or v.get("id") or v.get("variant") or "")
    return str(v)


def _variant_as_dict(v: Any, default_score: float = 0.5) -> Dict[str, Any]:
    if isinstance(v, dict):
        out = dict(v)
        out.setdefault("name", _variant_name(v) or "unnamed")
        out.setdefault("score", float(out.get("score", default_score)))
        return out
    return {"name": str(v), "score": float(default_score), "params": {}}


def score_variants(
    variants: Sequence[Any],
    features: Optional[Dict[str, Any]] = None,
    rules: Optional[Sequence[ScoreRule]] = None,
    base_score: float = 0.5,
) -> List[Dict[str, Any]]:
    """Score and sort variants (highest first).

    Each rule is ``(variant_dict, features) -> delta``.  Final score is
    clamped to ``[0.0, 1.0]``.  Deterministic: stable sort by
    ``(-score, name)``.
    """
    feats = features or {}
    scored: List[Dict[str, Any]] = []
    for v in variants or []:
        item = _variant_as_dict(v, default_score=base_score)
        score = float(item.get("score", base_score))
        if rules:
            for rule in rules:
                try:
                    score += float(rule(item, feats) or 0.0)
                except Exception:  # noqa: BLE001
                    continue
        item["score"] = max(0.0, min(1.0, round(score, 4)))
        scored.append(item)
    scored.sort(key=lambda x: (-float(x.get("score", 0)), _variant_name(x)))
    return scored


def pick_best_variant(
    variants: Sequence[Any],
    features: Optional[Dict[str, Any]] = None,
    rules: Optional[Sequence[ScoreRule]] = None,
) -> Tuple[Optional[Dict[str, Any]], List[Dict[str, Any]]]:
    """Return ``(best, ranked_list)``. Empty input → ``(None, [])``."""
    ranked = score_variants(variants, features=features, rules=rules)
    if not ranked:
        return None, []
    return ranked[0], ranked


def wifi_deauth_score_rules() -> List[ScoreRule]:
    """Domain rules for deauth-burst pattern grammars."""

    def _rule(v: Dict[str, Any], f: Dict[str, Any]) -> float:
        name = _variant_name(v).lower()
        delta = 0.0
        pmf = bool(f.get("pmf_supported"))
        clients = int(f.get("client_count") or 0)
        if pmf:
            if "sa_query" in name or "krack" in name or "backoff" in name:
                delta += 0.25
            if "broadcast" in name or "constant" in name:
                delta -= 0.2
        else:
            if clients >= 5 and ("broadcast" in name or "burst" in name or "ramp" in name):
                delta += 0.2
            if clients < 3 and ("directed" in name or "staggered" in name):
                delta += 0.15
            if "exponential" in name and clients <= 1:
                delta += 0.05
        if f.get("signal") is not None and int(f["signal"]) < -75:
            if "backoff" in name or "staggered" in name:
                delta += 0.1
        return delta

    return [_rule]


def wifi_handshake_score_rules() -> List[ScoreRule]:
    def _rule(v: Dict[str, Any], f: Dict[str, Any]) -> float:
        name = _variant_name(v).lower()
        wv = f.get("wpa_version") or ""
        delta = 0.0
        if wv == "wpa3":
            if "sae" in name or "dragon" in name or "commit" in name:
                delta += 0.3
            if "4way" in name or "wpa2" in name:
                delta -= 0.15
        elif wv == "wpa2_enterprise":
            if "eap" in name or "tls" in name or "enterprise" in name:
                delta += 0.3
        else:
            if "4way" in name or "anonce" in name or "eapol" in name:
                delta += 0.2
            if "sae" in name:
                delta -= 0.1
        if f.get("has_pcap") and ("replay" in name or "offline" in name):
            delta += 0.1
        if f.get("pmf_supported") and "deauth" in name:
            delta -= 0.15
        return delta

    return [_rule]


def wifi_pmkid_score_rules() -> List[ScoreRule]:
    def _rule(v: Dict[str, Any], f: Dict[str, Any]) -> float:
        name = _variant_name(v).lower()
        delta = 0.0
        if f.get("wpa_version") == "wpa3":
            # PMKID less useful on pure SAE; prefer transition/downgrade
            if "ssid" in name or "transition" in name:
                delta += 0.15
            if "key_info" in name:
                delta -= 0.05
        if f.get("client_count", 0) == 0:
            # Client-less PMKID harvest prefers RSN IE / key_info paths
            if "key_info" in name or "rsn" in name:
                delta += 0.2
        if f.get("has_pcap") and "replay" in name:
            delta += 0.1
        return delta

    return [_rule]


def generic_keyword_boost(
    keyword_weights: Dict[str, float],
    feature_flags: Optional[Dict[str, Sequence[str]]] = None,
) -> ScoreRule:
    """Build a rule: when a feature flag is truthy, boost variants whose
    name contains any of the listed keywords.
    """
    feature_flags = feature_flags or {}

    def _rule(v: Dict[str, Any], f: Dict[str, Any]) -> float:
        name = _variant_name(v).lower()
        delta = 0.0
        for kw, w in keyword_weights.items():
            if kw in name:
                delta += w
        for feat, kws in feature_flags.items():
            if not f.get(feat):
                continue
            for kw in kws:
                if kw in name:
                    delta += 0.15
        return delta

    return _rule


# ---------------------------------------------------------------------------
# Memo cache (short TTL) for pure heuristic dispatches
# ---------------------------------------------------------------------------

_MEMO: Dict[str, Tuple[float, Dict[str, Any]]] = {}
_MEMO_LOCK = threading.Lock()
_MEMO_TTL_S = 15.0
_MEMO_MAX = 256


def _memo_key(family: str, context: Dict[str, Any]) -> str:
    # Drop non-deterministic / bulky keys
    slim = {
        k: context.get(k)
        for k in sorted(context.keys())
        if k not in ("_raw", "started", "duration_s", "recon")
        and not callable(context.get(k))
    }
    try:
        blob = json.dumps(slim, sort_keys=True, default=str)
    except Exception:  # noqa: BLE001
        blob = repr(sorted(slim.items()))
    h = hashlib.sha256(blob.encode("utf-8", errors="replace")).hexdigest()[:24]
    return f"{family}:{h}"


def memo_get(family: str, context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    key = _memo_key(family, context)
    now = time.time()
    with _MEMO_LOCK:
        hit = _MEMO.get(key)
        if hit is None:
            return None
        ts, val = hit
        if now - ts > _MEMO_TTL_S:
            _MEMO.pop(key, None)
            return None
        out = dict(val)
        out["cached"] = True
        out["cache_age_s"] = round(now - ts, 3)
        return out


def memo_put(family: str, context: Dict[str, Any], value: Dict[str, Any]) -> None:
    key = _memo_key(family, context)
    with _MEMO_LOCK:
        if len(_MEMO) >= _MEMO_MAX:
            # Drop oldest ~25 %
            items = sorted(_MEMO.items(), key=lambda kv: kv[1][0])
            for k, _ in items[: max(1, _MEMO_MAX // 4)]:
                _MEMO.pop(k, None)
        # Never store the cached flag itself
        store = {k: v for k, v in value.items() if k not in ("cached", "cache_age_s")}
        _MEMO[key] = (time.time(), store)


def clear_poly_adapt_memo() -> None:
    with _MEMO_LOCK:
        _MEMO.clear()


# ---------------------------------------------------------------------------
# Polymorphic grammar runner
# ---------------------------------------------------------------------------


class PolyGrammarRunner:
    """Mixin: produces a parameter grammar given a context.

    Subclasses implement ``_poly_<family>(self, context)`` returning
    a list of (name, params) tuples. The LLM (or chain planner) then
    picks one of those names; the runner's ``_v2_poly_<family>``
    returns a single envelope with ``variants`` + ``picked`` (the
    **highest-scored** variant after target-adaptive ranking).
    """

    def _poly_score_rules(self, family: str) -> List[ScoreRule]:
        """Optional per-family score rules. Override in subclasses."""
        return []

    def _poly_grammar(self, family: str, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Default: produce a single-variant grammar from the family name.

        Subclasses override to inject real parameter sweeps.
        """
        return [{"name": family, "params": dict(context or {}),
                 "score": 0.5, "rationale": "default variant"}]

    def _v2_poly_dispatch(self, family: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Public polymorphic dispatch — returns a polymorphic envelope.

        Never raises. On any error returns ``{ok: False, error: "..."}``.
        Picks the **best-scored** variant (not blindly the first).
        """
        context = context or {}
        features = extract_target_features(context)
        try:
            raw = self._poly_grammar(family, context)
            if not raw:
                return {"ok": False, "family": family,
                        "error": f"poly_grammar {family!r} returned 0 variants",
                        "model": "polymorphic (heuristic)"}
            rules = self._poly_score_rules(family)
            best, ranked = pick_best_variant(raw, features=features, rules=rules)
            assert best is not None
            return {"ok": True,
                    "data": {"variants": ranked,
                             "picked": best.get("name"),
                             "picked_params": best.get("params", {}),
                             "picked_score": best.get("score", 0.5),
                             "features_used": {
                                 k: features.get(k)
                                 for k in (
                                     "wpa_version", "pmf_supported",
                                     "client_count", "band", "chipset",
                                 )
                             }},
                    "family": family,
                    "model": "polymorphic (heuristic)"}
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "family": family,
                    "error": f"poly_dispatch failed: {e}",
                    "model": "polymorphic (heuristic)"}


# ---------------------------------------------------------------------------
# Target-adaptive picker
# ---------------------------------------------------------------------------


class TargetAdaptivePicker:
    """Mixin: picks the best universal method for a target.

    Subclasses implement ``_adapt_pick(self, family, context)``
    returning a single (method, rationale, score) tuple. The LLM
    (or chain planner) then either calls that method directly or
    asks the human to accept it.
    """

    def _adapt_pick(self, family: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Default: a no-op picker that returns the family as the
        universal method name (so the chain continues). Subclasses
        override to inject target-specific logic.
        """
        feats = extract_target_features(context)
        return {
            "method": family,
            "rationale": (
                f"default pick for family {family!r} "
                f"(wpa={feats.get('wpa_version') or 'n/a'}, "
                f"clients={feats.get('client_count', 0)})"
            ),
            "score": 0.5,
            "features": {
                k: feats.get(k)
                for k in ("wpa_version", "pmf_supported", "client_count", "os")
            },
        }

    def _v2_adapt_dispatch(self, family: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Public target-adaptive dispatch — returns a pick envelope.

        Never raises. On any error returns ``{ok: False, error: "..."}``.
        """
        context = context or {}
        try:
            pick = self._adapt_pick(family, context)
            return {"ok": True,
                    "data": {"pick": pick.get("method"),
                             "rationale": pick.get("rationale", ""),
                             "score": pick.get("score", 0.5),
                             "family": family,
                             "features": pick.get("features") or {}},
                    "family": family,
                    "model": "target-adaptive (heuristic)"}
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "family": family,
                    "error": f"adapt_dispatch failed: {e}",
                    "model": "target-adaptive (heuristic)"}


# ---------------------------------------------------------------------------
# Convenience: build a polymorphic + target-adaptive combo
# ---------------------------------------------------------------------------


def build_poly_adapt_envelope(family: str, picked_method: str,
                              rationale: str = "", score: float = 0.5,
                              variants: Optional[List[Dict[str, Any]]] = None,
                              model: str = "polymorphic (heuristic)"
                              ) -> Dict[str, Any]:
    """Build a polymorphic OR target-adaptive envelope from caller inputs.

    Used by the v2 runner methods to keep envelope shape uniform. If
    ``variants`` is supplied the envelope is polymorphic; otherwise it
    is target-adaptive.
    """
    if variants is not None:
        return {"ok": True,
                "data": {"variants": variants,
                         "picked": picked_method,
                         "picked_params": {}},
                "family": family,
                "model": model}
    return {"ok": True,
            "data": {"pick": picked_method,
                     "rationale": rationale,
                     "score": score,
                     "family": family},
            "family": family,
            "model": model}


def enrich_poly_result(
    result: Dict[str, Any],
    features: Dict[str, Any],
    rules: Optional[Sequence[ScoreRule]] = None,
) -> Dict[str, Any]:
    """Post-process a companion envelope: rank ``data.variants`` and
    set ``primary`` / ``picked`` to the best-scored entry.

    No-op when there are no variants. Preserves all other keys.
    """
    if not isinstance(result, dict):
        return result
    data = result.get("data")
    if not isinstance(data, dict):
        return result
    variants = data.get("variants")
    if not isinstance(variants, list) or not variants:
        return result
    best, ranked = pick_best_variant(variants, features=features, rules=rules)
    if best is None:
        return result
    # Keep original string form for string-list variants when possible
    if ranked and all(isinstance(v, dict) for v in ranked):
        # If originals were plain strings, expose names list too
        if variants and all(isinstance(x, str) for x in variants):
            data["variants"] = [_variant_name(v) for v in ranked]
            data["variant_scores"] = [
                {"name": _variant_name(v), "score": v.get("score")} for v in ranked
            ]
        else:
            data["variants"] = ranked
    name = _variant_name(best)
    data["primary"] = name
    data["picked"] = name
    data["picked_score"] = best.get("score", 0.5)
    if "picked_params" not in data:
        data["picked_params"] = best.get("params", {}) if isinstance(best, dict) else {}
    data.setdefault("features_used", {
        k: features.get(k)
        for k in ("wpa_version", "pmf_supported", "client_count", "band", "os")
    })
    return result


def rules_for_method(name: str) -> List[ScoreRule]:
    """Map a poly_* method name to domain score rules."""
    n = (name or "").lower()
    if "deauth" in n or "burst" in n:
        return wifi_deauth_score_rules()
    if "handshake" in n or "eapol_replay" in n or "eapol_key" in n:
        return wifi_handshake_score_rules()
    if "pmkid" in n:
        return wifi_pmkid_score_rules()
    if "sae" in n or "wpa3" in n:
        return wifi_handshake_score_rules()
    if "wps" in n:
        return [generic_keyword_boost(
            {},
            {"wps": ("pixie", "pin", "null", "eap_failure", "nack")},
        )]
    if "gatt" in n or "hid" in n or "ble" in n or "adv" in n:
        return [generic_keyword_boost(
            {},
            {
                "auth_required": ("auth", "pair", "secure"),
                "injection_capable": ("write", "inject", "flood"),
            },
        )]
    if "lateral" in n or "persistence" in n or "exfil" in n:
        return [generic_keyword_boost(
            {},
            {
                "os": (),  # filled below via name match on features["os"]
            },
        )]
    return []


def apply_os_boost(features: Dict[str, Any]) -> ScoreRule:
    """Boost variants that mention the detected OS in their name."""
    os_name = (features.get("os") or "").lower()

    def _rule(v: Dict[str, Any], f: Dict[str, Any]) -> float:
        if not os_name:
            return 0.0
        name = _variant_name(v).lower()
        if os_name in name:
            return 0.25
        # family aliases
        aliases = {
            "windows": ("win", "powershell", "registry", "wmi", "mimikatz"),
            "linux": ("bash", "systemd", "cron", "ssh", "elf"),
            "macos": ("osx", "launchd", "apple"),
            "android": ("apk", "adb", "smali", "frida"),
            "ios": ("ipa", "frida", "ios"),
        }
        for key, words in aliases.items():
            if key in os_name or os_name in key:
                if any(w in name for w in words):
                    return 0.2
        return 0.0

    return _rule


__all__ = [
    "PolyGrammarRunner",
    "TargetAdaptivePicker",
    "build_poly_adapt_envelope",
    "extract_target_features",
    "score_variants",
    "pick_best_variant",
    "enrich_poly_result",
    "rules_for_method",
    "apply_os_boost",
    "wifi_deauth_score_rules",
    "wifi_handshake_score_rules",
    "wifi_pmkid_score_rules",
    "generic_keyword_boost",
    "memo_get",
    "memo_put",
    "clear_poly_adapt_memo",
]
