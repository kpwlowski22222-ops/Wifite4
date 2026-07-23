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

    Creative: short-TTL flyweight via :mod:`core.utils.hot_cache` keyed
    by a content fingerprint of the fields that drive feature
    extraction (never raw ``id()`` — object ids are recycled by the GC
    and would return stale bags across tests/engagements).
    """
    ctx: Dict[str, Any] = dict(context or {})
    # Nested recon / seed blobs common in orchestrator paths — flatten
    # BEFORE fingerprint/cache so nested-only seeds are distinct keys.
    recon = ctx.get("recon") if isinstance(ctx.get("recon"), dict) else {}
    seed = ctx.get("seed") if isinstance(ctx.get("seed"), dict) else {}
    for blob in (seed, recon):
        for k, v in blob.items():
            if k not in ctx or ctx.get(k) in (None, "", [], {}):
                ctx[k] = v

    cache_key = None
    if ctx:
        try:
            from core.utils.hot_cache import GLOBAL_CACHE, fingerprint
            _FEAT_KEYS = (
                "encryption", "enc", "security", "wpa_version", "clients",
                "client_count", "pmf_supported", "pmf", "transition",
                "transition_mode", "band", "channel", "signal", "rssi",
                "chipset", "driver", "iface", "interface", "name", "mode",
                "os", "target_os", "address", "addr", "mac", "io_cap",
                "iocap", "auth_required", "jurisdiction", "country",
                "injection_capable", "wps", "wps_enabled", "cap_file",
                "pcap", "handshake", "wordlist", "weakpass", "domain",
                "phase", "query", "username", "email", "phone", "person",
                "services", "gatt_services", "has_hid", "has_mesh",
                "has_le_audio", "pairing", "pairing_mode", "privs",
                "privileges", "uid", "has_creds", "credentials", "hashes",
                "network_access", "lateral_possible", "bssid", "ssid",
                "essid", "device_class", "profile", "query_type",
            )
            slim_src = {k: ctx.get(k) for k in _FEAT_KEYS if k in ctx}
            # Nested wps ok flag (recon.wps.ok)
            wps_blob = ctx.get("wps")
            if isinstance(wps_blob, dict):
                slim_src["wps.ok"] = wps_blob.get("ok")
            ac = ctx.get("adapter_caps")
            if isinstance(ac, dict):
                slim_src["adapter_caps.injection_capable"] = ac.get(
                    "injection_capable"
                )
            if slim_src:
                cache_key = fingerprint(slim_src)
                hit = GLOBAL_CACHE.get("target_features", cache_key)
                from core.utils import hot_cache as _hc
                if hit is not _hc._MISS and isinstance(hit, dict):
                    out = dict(hit)
                    out["_raw"] = ctx
                    return out
        except Exception:  # noqa: BLE001
            cache_key = None

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
        # BLE / OSINT / post-exploit feature keys (never invented)
        "services": ctx.get("services") or ctx.get("gatt_services") or [],
        "has_hid": (
            _as_bool(ctx.get("has_hid"))
            or "hid" in _lower(ctx.get("device_class") or "")
            or "1812" in str(ctx.get("services") or ctx.get("gatt_services") or "").lower()
        ),
        "has_mesh": (
            _as_bool(ctx.get("has_mesh"))
            or "mesh" in _lower(ctx.get("device_class") or ctx.get("profile") or "")
        ),
        "has_le_audio": (
            _as_bool(ctx.get("has_le_audio"))
            or "audio" in _lower(ctx.get("profile") or "")
            or "bap" in _lower(ctx.get("profile") or "")
        ),
        "pairing": _lower(ctx.get("pairing") or ctx.get("pairing_mode") or ""),
        "query_type": _lower(
            ctx.get("query_type")
            or (
                "email" if "@" in str(ctx.get("query") or ctx.get("email") or "")
                else "domain" if "." in str(ctx.get("domain") or ctx.get("query") or "")
                and "@" not in str(ctx.get("query") or "")
                else "phone" if str(ctx.get("phone") or "").replace("+", "").isdigit()
                else "person" if ctx.get("name") or ctx.get("person")
                else "username" if ctx.get("username") or ctx.get("query")
                else ""
            )
        ),
        "query": str(
            ctx.get("query") or ctx.get("username") or ctx.get("email")
            or ctx.get("domain") or ctx.get("target") or ""
        ),
        "privs": _lower(ctx.get("privs") or ctx.get("privileges") or ctx.get("uid") or ""),
        "has_creds": _as_bool(
            ctx.get("has_creds")
            or ctx.get("credentials")
            or ctx.get("hashes")
            or ctx.get("tickets")
        ),
        "network_access": _as_bool(
            ctx.get("network_access")
            if ctx.get("network_access") is not None
            else ctx.get("lateral_possible")
        ),
        # Pass-through raw for advanced scorers
        "_raw": ctx,
    }
    if cache_key is not None:
        try:
            from core.utils.hot_cache import GLOBAL_CACHE
            # Store without _raw to keep cache small; re-bind on hit.
            slim = {k: v for k, v in features.items() if k != "_raw"}
            GLOBAL_CACHE.put("target_features", cache_key, slim, ttl_s=8.0)
        except Exception:  # noqa: BLE001
            pass
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
    if not variants:
        return []
    feats = features or {}
    rule_list = rules or ()
    n_rules = len(rule_list)
    scored: List[Dict[str, Any]] = []
    append = scored.append
    for v in variants:
        item = _variant_as_dict(v, default_score=base_score)
        score = float(item.get("score", base_score))
        if n_rules:
            for rule in rule_list:
                try:
                    delta = rule(item, feats)
                    if delta:
                        score += float(delta)
                except Exception:  # noqa: BLE001
                    continue
        # clamp without round() on every intermediate; one round at end
        if score < 0.0:
            score = 0.0
        elif score > 1.0:
            score = 1.0
        item["score"] = round(score, 4)
        append(item)
    scored.sort(key=lambda x: (-x["score"], _variant_name(x)))
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


_MEMO_DROP_KEYS = frozenset(("_raw", "started", "duration_s", "recon", "screenshot"))


def _memo_key(family: str, context: Dict[str, Any]) -> str:
    # Drop non-deterministic / bulky keys. Prefer a fast path for
    # small feature bags (strategy pickers) without full json.dumps.
    slim_items = []
    for k in sorted(context.keys()):
        if k in _MEMO_DROP_KEYS:
            continue
        v = context.get(k)
        if callable(v):
            continue
        slim_items.append((k, v))
    if len(slim_items) <= 12 and all(
        isinstance(v, (str, int, float, bool, type(None))) for _, v in slim_items
    ):
        blob = "|".join(f"{k}={v!s}" for k, v in slim_items)
    else:
        try:
            blob = json.dumps(dict(slim_items), sort_keys=True, default=str)
        except Exception:  # noqa: BLE001
            blob = repr(slim_items)
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


def _wifi_strategy_score(v: Dict[str, Any], f: Dict[str, Any]) -> float:
    name = _variant_name(v).lower()
    wv = _lower(f.get("wpa_version"))
    enc = _lower(f.get("encryption"))
    has_wps = _as_bool(f.get("wps") or f.get("wps_enabled"))
    transition = _as_bool(f.get("transition_mode"))

    if name in ("open", "open_network"):
        return 1.0 if wv == "open" or enc in ("open", "none", "opn") else 0.0
    if name == "wep":
        return 1.0 if wv == "wep" or enc == "wep" else 0.0
    if name in ("enterprise", "wpa2_enterprise"):
        return 1.0 if wv == "wpa2_enterprise" or "enterprise" in enc else 0.0
    if name in ("wpa3_sae", "wpa3", "sae"):
        return 1.0 if wv == "wpa3" and not transition else 0.0
    if name == "wpa2_transition":
        return 0.9 if transition else 0.0
    if name == "wpa2":
        if wv == "wpa2" and not transition:
            return 0.8
        if transition:
            return 0.4
        return 0.0
    if name in ("wps", "wps_pixie"):
        return 0.95 if has_wps and (wv != "wpa3" or transition) else 0.0
    if name in ("mt7921e", "mt7921e_inject"):
        return 0.1
    return 0.0


# Precomputed once — pick_*_strategy is on the planner hot path.
_WIFI_STRATEGY_VARIANTS: Tuple[Dict[str, str], ...] = (
    {"name": "open"},
    {"name": "wep"},
    {"name": "enterprise"},
    {"name": "wpa3_sae"},
    {"name": "wpa2_transition"},
    {"name": "wpa2"},
)
_WIFI_STRATEGY_RULES: List[ScoreRule] = [_wifi_strategy_score]


def wifi_strategy_score_rules() -> List[ScoreRule]:
    """Score WiFi attack-strategy variants based on target features.

    Variants are strategy names like ``open``, ``wep``, ``enterprise``,
    ``wpa3_sae``, ``wpa2_transition``, ``wpa2``. The highest-scoring
    strategy drives :func:`_heuristic_wifi` branch selection in
    ``core.ai_backend.chain``.
    """
    return _WIFI_STRATEGY_RULES


def pick_wifi_strategy(features: Dict[str, Any]) -> str:
    """Target-adaptive WiFi strategy pick (polymorphic branch selector).

    Returns one of: ``open``, ``wep``, ``enterprise``, ``wpa3_sae``,
    ``wpa2_transition``, ``wpa2``. Falls back to ``wpa2``.
    """
    ranked = score_variants(
        _WIFI_STRATEGY_VARIANTS, features=features,
        rules=_WIFI_STRATEGY_RULES, base_score=0.0,
    )
    best = ranked[0] if ranked else None
    if not best or float(best.get("score", 0.0)) <= 0.0:
        return "wpa2"
    return _variant_name(best) or "wpa2"


def _ble_strategy_score(v: Dict[str, Any], f: Dict[str, Any]) -> float:
    name = _variant_name(v).lower()
    has_hid = _as_bool(f.get("has_hid"))
    has_mesh = _as_bool(f.get("has_mesh"))
    has_audio = _as_bool(f.get("has_le_audio"))
    addr = str(f.get("address") or "")
    pairing = _lower(f.get("pairing"))
    auth = _as_bool(f.get("auth_required"))
    services = f.get("services") or []
    if isinstance(services, list):
        svc_blob = " ".join(str(s) for s in services).lower()
    else:
        svc_blob = str(services).lower()

    if name in ("recon", "adv", "scan"):
        return 0.9 if not addr else 0.4
    if name in ("gatt_write", "gatt"):
        if not addr:
            return 0.0
        if "gatt" in svc_blob or services:
            return 0.85
        return 0.55
    if name in ("hid_inject", "hid"):
        return 0.95 if has_hid or "1812" in svc_blob or "hid" in svc_blob else 0.0
    if name in ("pairing", "pair", "smp"):
        if pairing in ("just_works", "legacy", "none", ""):
            return 0.8 if addr else 0.2
        if auth:
            return 0.3
        return 0.5 if addr else 0.0
    if name == "mesh":
        return 0.95 if has_mesh or "mesh" in svc_blob else 0.0
    if name in ("le_audio", "audio", "bap"):
        return 0.95 if has_audio or "bap" in svc_blob or "audio" in svc_blob else 0.0
    return 0.0


_BLE_STRATEGY_VARIANTS: Tuple[Dict[str, str], ...] = (
    {"name": "recon"},
    {"name": "gatt_write"},
    {"name": "hid_inject"},
    {"name": "pairing"},
    {"name": "mesh"},
    {"name": "le_audio"},
)
_BLE_STRATEGY_RULES: List[ScoreRule] = [_ble_strategy_score]


def ble_strategy_score_rules() -> List[ScoreRule]:
    """Score BLE attack-strategy variants from observed device features.

    Variants: ``recon``, ``gatt_write``, ``hid_inject``, ``pairing``,
    ``mesh``, ``le_audio``. Heuristic only (not trained-ML).
    """
    return _BLE_STRATEGY_RULES


def pick_ble_strategy(features: Dict[str, Any]) -> str:
    """Target-adaptive BLE strategy pick. Fallback: ``recon``."""
    ranked = score_variants(
        _BLE_STRATEGY_VARIANTS, features=features,
        rules=_BLE_STRATEGY_RULES, base_score=0.0,
    )
    best = ranked[0] if ranked else None
    if not best or float(best.get("score", 0.0)) <= 0.0:
        return "recon"
    return _variant_name(best) or "recon"


def _osint_strategy_score(v: Dict[str, Any], f: Dict[str, Any]) -> float:
    name = _variant_name(v).lower()
    qt = _lower(f.get("query_type"))
    q = str(f.get("query") or "")
    juris = _lower(f.get("jurisdiction"))
    is_pl = juris in ("pl", "poland", "polska", "pl-pl")

    if name in ("username", "handle"):
        return 1.0 if qt in ("username", "person", "") and "@" not in q else 0.2
    if name == "email":
        return 1.0 if qt == "email" or "@" in q else 0.0
    if name in ("domain", "subdomain"):
        return 1.0 if qt == "domain" or (
            "." in q and "@" not in q and not q.replace(".", "").isdigit()
        ) else 0.1
    if name in ("person_pl", "polish_person"):
        return 0.95 if is_pl and qt in ("person", "username", "name", "") else (
            0.4 if is_pl else 0.0
        )
    if name in ("phone_pl", "phone"):
        return 1.0 if qt == "phone" else (0.3 if is_pl else 0.0)
    if name in ("breach", "leak", "hibp"):
        return 0.85 if qt in ("email", "username") or "@" in q else 0.25
    return 0.0


_OSINT_STRATEGY_VARIANTS: Tuple[Dict[str, str], ...] = (
    {"name": "username"},
    {"name": "email"},
    {"name": "domain"},
    {"name": "person_pl"},
    {"name": "phone_pl"},
    {"name": "breach"},
)
_OSINT_STRATEGY_RULES: List[ScoreRule] = [_osint_strategy_score]


def osint_strategy_score_rules() -> List[ScoreRule]:
    """Score OSINT source strategies from query shape / jurisdiction.

    Variants: ``username``, ``email``, ``domain``, ``person_pl``,
    ``phone_pl``, ``breach``.
    """
    return _OSINT_STRATEGY_RULES


def pick_osint_strategy(features: Dict[str, Any]) -> str:
    """Target-adaptive OSINT strategy pick. Fallback: ``username``."""
    ranked = score_variants(
        _OSINT_STRATEGY_VARIANTS, features=features,
        rules=_OSINT_STRATEGY_RULES, base_score=0.0,
    )
    best = ranked[0] if ranked else None
    if not best or float(best.get("score", 0.0)) <= 0.0:
        return "username"
    return _variant_name(best) or "username"


_ELEVATED_PRIV_MARKERS = ("root", "system", "admin", "uid=0", "high")


def _post_exploit_strategy_score(v: Dict[str, Any], f: Dict[str, Any]) -> float:
    name = _variant_name(v).lower()
    os_name = _lower(f.get("os"))
    privs = _lower(f.get("privs"))
    has_creds = _as_bool(f.get("has_creds"))
    net = _as_bool(f.get("network_access"))
    elevated = any(t in privs for t in _ELEVATED_PRIV_MARKERS)

    if name in ("enum", "recon", "situational"):
        return 0.7 if not elevated and not has_creds else 0.35
    if name in ("cred_dump", "creds", "mimikatz", "lsass"):
        if "windows" in os_name or "win" in os_name:
            return 0.95 if elevated else 0.55
        if "linux" in os_name:
            return 0.7 if elevated else 0.4
        return 0.5
    if name in ("lateral", "psexec", "smb", "winrm"):
        return 0.9 if (has_creds and net) else (0.4 if net else 0.1)
    if name in ("persist", "persistence"):
        return 0.85 if elevated else 0.45
    if name in ("exfil", "exfiltration"):
        return 0.8 if has_creds or elevated else 0.3
    if name in ("cleanup", "anti_forensic"):
        return 0.75 if elevated else 0.2
    return 0.0


_POST_EXPLOIT_STRATEGY_VARIANTS: Tuple[Dict[str, str], ...] = (
    {"name": "enum"},
    {"name": "cred_dump"},
    {"name": "lateral"},
    {"name": "persist"},
    {"name": "exfil"},
    {"name": "cleanup"},
)
_POST_EXPLOIT_STRATEGY_RULES: List[ScoreRule] = [_post_exploit_strategy_score]


def post_exploit_strategy_score_rules() -> List[ScoreRule]:
    """Score post-exploit next-step strategies from OS / privs / creds.

    Variants: ``enum``, ``cred_dump``, ``lateral``, ``persist``,
    ``exfil``, ``cleanup``.
    """
    return _POST_EXPLOIT_STRATEGY_RULES


def pick_post_exploit_strategy(features: Dict[str, Any]) -> str:
    """Target-adaptive post-exploit strategy pick. Fallback: ``enum``."""
    ranked = score_variants(
        _POST_EXPLOIT_STRATEGY_VARIANTS, features=features,
        rules=_POST_EXPLOIT_STRATEGY_RULES, base_score=0.0,
    )
    best = ranked[0] if ranked else None
    if not best or float(best.get("score", 0.0)) <= 0.0:
        return "enum"
    return _variant_name(best) or "enum"


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
    if "gatt" in n or "hid" in n or "ble" in n or "adv" in n or "mesh" in n:
        return ble_strategy_score_rules()
    if "osint" in n or "sherlock" in n or "harvester" in n or "breach" in n:
        return osint_strategy_score_rules()
    if "lateral" in n or "persistence" in n or "exfil" in n or "mimikatz" in n or "psexec" in n:
        return post_exploit_strategy_score_rules()
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


def situational_pick(*args: Any, **kwargs: Any) -> Dict[str, Any]:
    """Bridge to :func:`core.utils.poly_runtime.situational_pick`.

    Kept here so existing ``from core.utils.poly_adapt import …``
    call sites get the full Python-3.10 polymorphic runtime without
    a second import path.
    """
    from core.utils.poly_runtime import situational_pick as _sp
    return _sp(*args, **kwargs)


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
    "wifi_strategy_score_rules",
    "pick_wifi_strategy",
    "ble_strategy_score_rules",
    "pick_ble_strategy",
    "osint_strategy_score_rules",
    "pick_osint_strategy",
    "post_exploit_strategy_score_rules",
    "pick_post_exploit_strategy",
    "situational_pick",
    "generic_keyword_boost",
    "memo_get",
    "memo_put",
    "clear_poly_adapt_memo",
]
