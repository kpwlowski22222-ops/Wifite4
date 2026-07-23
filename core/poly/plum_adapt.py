"""Plum-powered multiple dispatch for target-adaptive polymorphism.

Uses `plum-dispatch` (https://github.com/beartype/plum) — requires
Python ≥3.10. Multiple dispatch routes AI/algorithm adaptation on the
*typed* target shape so the right grammar, depth, and tool order fire
for wifi vs ble vs web vs binary without sprawling if-ladders.

Fallback: if plum is unavailable, pure-Python match/case coercion still
works and returns the same envelope shape.

Never fabricates attack success; heuristics only.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any, Dict, List, Optional, Tuple, Union

# ---------------------------------------------------------------------------
# Typed target views (positional dispatch keys for plum)
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class TargetView:
    """Base typed bag — always holds the raw dict + normalized features."""

    raw: Dict[str, Any] = field(default_factory=dict)
    features: Dict[str, Any] = field(default_factory=dict)
    domain: str = "unknown"

    def get(self, key: str, default: Any = None) -> Any:
        if key in self.features and self.features[key] not in (None, ""):
            return self.features[key]
        return self.raw.get(key, default)


@dataclass(slots=True)
class WifiTarget(TargetView):
    domain: str = "wifi"


@dataclass(slots=True)
class BleTarget(TargetView):
    domain: str = "ble"


@dataclass(slots=True)
class WebTarget(TargetView):
    domain: str = "web"


@dataclass(slots=True)
class BinaryTarget(TargetView):
    domain: str = "binary"


@dataclass(slots=True)
class NetworkTarget(TargetView):
    domain: str = "network"


@dataclass(slots=True)
class CloudTarget(TargetView):
    domain: str = "cloud"


@dataclass(slots=True)
class OsintTarget(TargetView):
    domain: str = "osint"


@dataclass(slots=True)
class PostExploitTarget(TargetView):
    domain: str = "post_exploit"


@dataclass(slots=True)
class ZeroDayTarget(TargetView):
    domain: str = "zero_day"


# ---------------------------------------------------------------------------
# Coercion (optimized: fingerprint + lru)
# ---------------------------------------------------------------------------


def _feat_bag(raw: Dict[str, Any]) -> Dict[str, Any]:
    try:
        from core.utils.poly_adapt import extract_target_features
        return extract_target_features(raw)
    except Exception:  # noqa: BLE001
        return dict(raw)


def _domain_hint(raw: Dict[str, Any], feats: Dict[str, Any],
                 preferred: str = "") -> str:
    d = (preferred or raw.get("domain") or feats.get("domain") or "").lower()
    if d in ("wifi", "wlan", "wireless"):
        return "wifi"
    if d in ("ble", "bluetooth"):
        return "ble"
    if d in ("osint", "osint_people", "osint_web", "people", "web"):
        if d in ("osint_web", "web") or raw.get("url") or raw.get("website"):
            return "web" if (raw.get("url") or raw.get("website")) and d != "osint" else "osint"
        return "osint"
    if d in ("post_exploit", "post_exploitation", "post"):
        return "post_exploit"
    if d in ("zero_day", "0day", "zeroday"):
        return "zero_day"
    if d in ("cloud", "aws", "azure", "gcp"):
        return "cloud"
    # Infer from keys (honest — only from present fields)
    if raw.get("bssid") or raw.get("ssid") or feats.get("encryption") or feats.get("wpa_version"):
        return "wifi"
    if raw.get("address") and (
        raw.get("connectable") is not None or "ble" in str(raw.get("type") or "").lower()
    ):
        return "ble"
    if raw.get("url") or raw.get("website") or raw.get("endpoint"):
        return "web"
    if raw.get("binary") or raw.get("firmware") or raw.get("elf") or raw.get("crash_path"):
        return "binary"
    if raw.get("host") or raw.get("ip") or raw.get("port"):
        return "network"
    if raw.get("aws_account") or raw.get("s3") or raw.get("iam"):
        return "cloud"
    if raw.get("session_id") or raw.get("shell") or raw.get("creds"):
        return "post_exploit"
    if raw.get("query") or raw.get("email") or raw.get("username"):
        return "osint"
    return d or "unknown"


_CLASS_MAP = {
    "wifi": WifiTarget,
    "ble": BleTarget,
    "web": WebTarget,
    "binary": BinaryTarget,
    "network": NetworkTarget,
    "cloud": CloudTarget,
    "osint": OsintTarget,
    "post_exploit": PostExploitTarget,
    "zero_day": ZeroDayTarget,
}


@lru_cache(maxsize=512)
def _coerce_cached(fp: str, preferred: str) -> TargetView:
    """Internal cache keyed by content fingerprint (not object id)."""
    # fp encodes preferred + sorted items; reconstruct is not needed —
    # this path is only for empty/minimal; real coerce uses uncached path
    # with hot_cache when available.
    return TargetView(raw={}, features={}, domain=preferred or "unknown")


def coerce_target(
    target: Optional[Dict[str, Any]] = None,
    *,
    recon: Optional[Dict[str, Any]] = None,
    domain: str = "",
) -> TargetView:
    """Turn a free-form seed dict into a typed TargetView for plum dispatch."""
    if isinstance(target, TargetView):
        return target
    raw: Dict[str, Any] = {}
    if isinstance(target, dict):
        raw.update(target)
    if isinstance(recon, dict):
        for k, v in recon.items():
            if k not in raw or raw.get(k) in (None, "", [], {}):
                raw[k] = v

    def _build() -> TargetView:
        feats = _feat_bag(raw)
        dom = _domain_hint(raw, feats, preferred=domain)
        cls = _CLASS_MAP.get(dom, TargetView)
        return cls(raw=raw, features=feats, domain=dom)

    try:
        from core.utils.hot_cache import GLOBAL_CACHE, fingerprint
        return GLOBAL_CACHE.get_or_set(
            "plum_coerce",
            fingerprint(raw, domain or ""),
            _build,
            ttl_s=30.0,
        )
    except Exception:  # noqa: BLE001
        return _build()


# ---------------------------------------------------------------------------
# Plum multiple dispatch — adapt_for(target) → strategy envelope
# ---------------------------------------------------------------------------

_PLUM_OK = False
try:
    from plum import dispatch as plum_dispatch
    _PLUM_OK = True
except Exception:  # noqa: BLE001
    plum_dispatch = None  # type: ignore


def plum_available() -> bool:
    if (os.environ.get("KFIOSA_PLUM") or "1").strip().lower() in (
        "0", "false", "off", "no",
    ):
        return False
    return bool(_PLUM_OK)


def _envelope(
    *,
    method: str,
    family: str,
    focus: str,
    depth: str,
    rationale: str,
    params: Optional[Dict[str, Any]] = None,
    boosts: Optional[Dict[str, float]] = None,
    tool_order: Optional[List[str]] = None,
    domain: str = "",
) -> Dict[str, Any]:
    return {
        "ok": True,
        "method": method,
        "family": family,
        "focus": focus,
        "depth": depth,
        "rationale": rationale,
        "params": params or {},
        "boosts": boosts or {},
        "tool_order": tool_order or [],
        "domain": domain,
        "engine": "plum-dispatch" if plum_available() else "fallback",
        "model": "polymorphic (plum multiple-dispatch)" if plum_available()
        else "polymorphic (heuristic fallback)",
    }


if _PLUM_OK:

    @plum_dispatch
    def adapt_for(target: WifiTarget) -> Dict[str, Any]:
        f = target.features
        enc = str(f.get("encryption") or f.get("wpa_version") or "").lower()
        pmf = bool(f.get("pmf_supported") or f.get("pmf") or target.raw.get("pmf"))
        clients = int(f.get("client_count") or 0)
        if "wpa3" in enc or "sae" in enc or pmf:
            return _envelope(
                method="poly_wpa3_sae_grammar",
                family="wifi", focus="sae", depth="deep",
                rationale="plum: WifiTarget + SAE/PMF → SAE-aware poly grammar",
                boosts={"sae_commit": 0.4, "pmkid_first": 0.25, "evil_twin_branch": -0.1},
                tool_order=["hcxdumptool", "airodump-ng", "aircrack-ng"],
                domain="wifi",
                params={"pmf": True, "is_sae": True},
            )
        if clients <= 1:
            return _envelope(
                method="poly_pmkid_vs_handshake_grammar",
                family="wifi", focus="pmkid", depth="medium",
                rationale="plum: WifiTarget low clients → PMKID-first",
                boosts={"pmkid_first": 0.35, "handshake_deauth": 0.1},
                tool_order=["hcxdumptool", "airodump-ng"],
                domain="wifi",
            )
        inj = bool(
            (target.raw.get("adapter_caps") or {}).get("injection_capable")
            or target.raw.get("injection_capable")
        )
        if inj and not pmf:
            return _envelope(
                method="poly_deauth_burst_pattern_grammar",
                family="wifi", focus="handshake", depth="deep",
                rationale="plum: WifiTarget injection + clients → deauth grammar",
                boosts={"handshake_deauth": 0.35, "pmkid_first": 0.1},
                tool_order=["aireplay-ng", "airodump-ng", "aircrack-ng"],
                domain="wifi",
                params={"clients": clients, "offensive": True},
            )
        return _envelope(
            method="wifi_recon_passive",
            family="wifi", focus="passive", depth="shallow",
            rationale="plum: WifiTarget default passive recon",
            boosts={"passive_long": 0.3},
            tool_order=["airodump-ng", "kismet"],
            domain="wifi",
        )

    @plum_dispatch
    def adapt_for(target: BleTarget) -> Dict[str, Any]:  # type: ignore[no-redef]
        f = target.features
        rssi = f.get("rssi") or target.raw.get("rssi")
        connectable = target.raw.get("connectable", f.get("connectable"))
        try:
            weak = rssi is not None and int(rssi) < -85
        except (TypeError, ValueError):
            weak = False
        if weak:
            return _envelope(
                method="adapt_ble_long_range_picker",
                family="ble", focus="advertising", depth="shallow",
                rationale="plum: BleTarget weak RSSI → long-range / adv sniff",
                boosts={"adv_sniff": 0.35, "gatt_enum": 0.05},
                tool_order=["hcitool", "btmon", "bluetoothctl"],
                domain="ble",
                params={"rssi": rssi},
            )
        if connectable:
            return _envelope(
                method="adapt_ble_connect_vs_sniff",
                family="ble", focus="gatt", depth="medium",
                rationale="plum: BleTarget connectable → GATT enum first",
                boosts={"gatt_enum": 0.35, "pairing_probe": 0.15},
                tool_order=["gatttool", "bluetoothctl", "bettercap"],
                domain="ble",
            )
        return _envelope(
            method="poly_ble_scan_window_grammar",
            family="ble", focus="advertising", depth="medium",
            rationale="plum: BleTarget default polymorphic scan window",
            boosts={"adv_sniff": 0.25},
            tool_order=["hcitool", "btmon"],
            domain="ble",
        )

    @plum_dispatch
    def adapt_for(target: WebTarget) -> Dict[str, Any]:  # type: ignore[no-redef]
        return _envelope(
            method="poly_nmap_script_grammar",
            family="web", focus="injection", depth="deep",
            rationale="plum: WebTarget → polyglot / auth-chain web path",
            boosts={"polyglot_payload": 0.35, "auth_chain": 0.25, "ssrf_chain": 0.15},
            tool_order=["nuclei", "ffuf", "sqlmap"],
            domain="web",
            params={"url": target.raw.get("url") or target.raw.get("website")},
        )

    @plum_dispatch
    def adapt_for(target: BinaryTarget) -> Dict[str, Any]:  # type: ignore[no-redef]
        has_crash = bool(target.raw.get("crash_path") or target.raw.get("core"))
        if has_crash:
            return _envelope(
                method="zero_day_crash_triager",
                family="binary", focus="static", depth="deep",
                rationale="plum: BinaryTarget with crash → crash triager",
                boosts={"bounds_prober": 0.2, "cfg_surf": 0.25, "asan_guided": 0.15},
                tool_order=["gdb", "ghidra", "radare2"],
                domain="binary",
            )
        return _envelope(
            method="zero_day_control_flow_surfer",
            family="binary", focus="cfg", depth="deep",
            rationale="plum: BinaryTarget → CFG / harness path",
            boosts={"cfg_surf": 0.35, "harness_gen": 0.25, "static_strings": 0.1},
            tool_order=["ghidra", "radare2", "afl++"],
            domain="binary",
        )

    @plum_dispatch
    def adapt_for(target: NetworkTarget) -> Dict[str, Any]:  # type: ignore[no-redef]
        return _envelope(
            method="poly_nmap_script_grammar",
            family="network", focus="parse", depth="deep",
            rationale="plum: NetworkTarget → malformed PDU / state desync",
            boosts={"malformed_pdu": 0.35, "state_desync": 0.25, "option_soup": 0.15},
            tool_order=["nmap", "scapy", "tshark"],
            domain="network",
            params={"host": target.raw.get("host") or target.raw.get("ip")},
        )

    @plum_dispatch
    def adapt_for(target: CloudTarget) -> Dict[str, Any]:  # type: ignore[no-redef]
        return _envelope(
            method="zero_day_aws_iam",
            family="cloud", focus="iam", depth="medium",
            rationale="plum: CloudTarget → IAM / metadata SSRF priorities",
            boosts={"iam_wildcards": 0.35, "metadata_ssrf": 0.3, "public_bucket": 0.15},
            tool_order=["pacu", "scoutsuite", "prowler"],
            domain="cloud",
        )

    @plum_dispatch
    def adapt_for(target: OsintTarget) -> Dict[str, Any]:  # type: ignore[no-redef]
        if target.raw.get("email"):
            focus, method = "breach", "poly_email_pattern_grammar"
        elif target.raw.get("domain") or target.raw.get("website"):
            focus, method = "graph", "poly_osint_user_agent_grammar"
        else:
            focus, method = "passive", "poly_osint_user_agent_grammar"
        return _envelope(
            method=method,
            family="osint", focus=focus, depth="medium",
            rationale=f"plum: OsintTarget → {focus} OSINT grammar",
            boosts={"passive_first": 0.2, "breach_pivot": 0.25, "graph_expand": 0.2},
            domain="osint",
        )

    @plum_dispatch
    def adapt_for(target: PostExploitTarget) -> Dict[str, Any]:  # type: ignore[no-redef]
        has_creds = bool(
            target.raw.get("creds") or target.raw.get("password")
            or target.features.get("has_creds")
        )
        if has_creds:
            return _envelope(
                method="poly_lateral_movement_grammar",
                family="post_exploit", focus="lateral", depth="deep",
                rationale="plum: PostExploitTarget + creds → lateral first",
                boosts={"lateral_first": 0.4, "enum_then_creds": 0.1},
                domain="post_exploit",
            )
        return _envelope(
            method="poly_persistence_registry_grammar",
            family="post_exploit", focus="enum", depth="medium",
            rationale="plum: PostExploitTarget → enum then persist",
            boosts={"enum_then_creds": 0.35, "persist_quiet": 0.2},
            domain="post_exploit",
        )

    @plum_dispatch
    def adapt_for(target: ZeroDayTarget) -> Dict[str, Any]:  # type: ignore[no-redef]
        return _envelope(
            method="zero_day_logic_flaw_heuristic",
            family="logic", focus="workflow", depth="deep",
            rationale="plum: ZeroDayTarget → logic/hypothesis deep path",
            boosts={"deep_pass": 0.3, "step_skip": 0.2},
            domain="zero_day",
        )

    @plum_dispatch
    def adapt_for(target: TargetView) -> Dict[str, Any]:  # type: ignore[no-redef]
        return _envelope(
            method="recon_probe",
            family="generic", focus="balanced", depth="medium",
            rationale="plum: generic TargetView → balanced medium pass",
            boosts={"medium_pass": 0.25, "deep_pass": 0.1},
            domain=target.domain or "unknown",
        )

else:
    # Fallback without plum: same API via type checks
    def adapt_for(target: TargetView) -> Dict[str, Any]:  # type: ignore[misc]
        if isinstance(target, WifiTarget):
            return _envelope(
                method="wifi_recon_passive", family="wifi", focus="passive",
                depth="medium", rationale="fallback WifiTarget", domain="wifi",
                boosts={"pmkid_first": 0.2},
            )
        if isinstance(target, BleTarget):
            return _envelope(
                method="poly_ble_scan_window_grammar", family="ble",
                focus="advertising", depth="medium",
                rationale="fallback BleTarget", domain="ble",
                boosts={"gatt_enum": 0.2},
            )
        return _envelope(
            method="recon_probe", family="generic", focus="balanced",
            depth="medium", rationale="fallback TargetView",
            domain=getattr(target, "domain", "unknown") or "unknown",
            boosts={"medium_pass": 0.2},
        )


def adapt_target(
    target: Optional[Dict[str, Any]] = None,
    *,
    recon: Optional[Dict[str, Any]] = None,
    domain: str = "",
) -> Dict[str, Any]:
    """Public entry: coerce free-form target → plum-dispatched adaptation."""
    view = coerce_target(target, recon=recon, domain=domain)
    try:
        env = adapt_for(view)
    except Exception as e:  # noqa: BLE001
        env = _envelope(
            method="recon_probe",
            family="generic",
            focus="balanced",
            depth="medium",
            rationale=f"adapt_for failed: {e}",
            domain=view.domain,
        )
    env["target_type"] = type(view).__name__
    env["features"] = {
        k: view.features.get(k)
        for k in (
            "encryption", "wpa_version", "pmf_supported", "client_count",
            "rssi", "os", "has_url", "has_creds",
        )
        if view.features.get(k) not in (None, "", [], {})
    }
    return env


def apply_boosts_to_scores(
    ranked: List[Tuple[float, Dict[str, Any]]],
    boosts: Dict[str, float],
) -> List[Tuple[float, Dict[str, Any]]]:
    """Apply plum boost map onto (score, variant) pairs — O(n)."""
    if not boosts:
        return ranked
    out: List[Tuple[float, Dict[str, Any]]] = []
    for sc, v in ranked:
        name = str(v.get("name") or "")
        sc2 = sc + float(boosts.get(name) or 0.0)
        out.append((sc2, v))
    out.sort(key=lambda t: (-t[0], t[1].get("name") or ""))
    return out


def plum_prompt_block(
    target: Optional[Dict[str, Any]] = None,
    *,
    domain: str = "",
) -> str:
    """Compact block for chain planner / AI system prompts."""
    env = adapt_target(target, domain=domain)
    lines = [
        "PLUM TARGET ADAPT (multiple-dispatch):",
        f"  type={env.get('target_type')} domain={env.get('domain')}",
        f"  method={env.get('method')} focus={env.get('focus')} "
        f"depth={env.get('depth')}",
        f"  rationale={env.get('rationale')}",
        f"  engine={env.get('engine')}",
    ]
    if env.get("tool_order"):
        lines.append(f"  tool_order={env.get('tool_order')}")
    if env.get("boosts"):
        top = sorted(env["boosts"].items(), key=lambda x: -x[1])[:4]
        lines.append("  variant_boosts=" + ", ".join(f"{k}:{v:+.2f}" for k, v in top))
    lines.append(
        "  Prefer this adaptation when planning steps; still never invent "
        "CVEs/PSKs/access."
    )
    return "\n".join(lines)


__all__ = [
    "TargetView",
    "WifiTarget",
    "BleTarget",
    "WebTarget",
    "BinaryTarget",
    "NetworkTarget",
    "CloudTarget",
    "OsintTarget",
    "PostExploitTarget",
    "ZeroDayTarget",
    "coerce_target",
    "adapt_for",
    "adapt_target",
    "apply_boosts_to_scores",
    "plum_prompt_block",
    "plum_available",
]
