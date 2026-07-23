"""Multi-library polymorphism engines for Python ≥3.10.

Combines several GitHub / stdlib approaches so every algorithm can adapt
to the target through different dispatch styles:

| Engine              | Library / source                          | Style                    |
|---------------------|-------------------------------------------|--------------------------|
| plum                | beartype/plum (plum-dispatch)             | Julia-like multi-dispatch|
| multimethod         | coady/multimethod                         | cached multi-arg dispatch|
| multipledispatch    | mrocklin/multipledispatch                 | namespace multi-dispatch |
| singledispatch      | functools (stdlib PEP 443)                | single-arg generic       |
| match_case          | Python 3.10 structural pattern matching   | domain+phase router      |
| strategy            | core.utils.poly_runtime StrategyRegistry  | strategy objects         |

``ensemble_adapt()`` runs available engines, merges boosts / depth / focus
(majority + weight), and returns one envelope for algorithm_poly.

Never fabricates attack success. Disable engines via::

    KFIOSA_POLY_ENGINES=plum,multimethod,match_case   # subset
    KFIOSA_POLY_ENGINES=0                             # all off
"""
from __future__ import annotations

import os
from collections import Counter
from dataclasses import dataclass, field
from functools import lru_cache, singledispatch
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

# ---------------------------------------------------------------------------
# Availability probes (import once)
# ---------------------------------------------------------------------------

_ENGINES_STATUS: Dict[str, bool] = {}


def _probe() -> Dict[str, bool]:
    global _ENGINES_STATUS
    if _ENGINES_STATUS:
        return _ENGINES_STATUS
    st = {
        "plum": False,
        "multimethod": False,
        "multipledispatch": False,
        "singledispatch": True,   # stdlib
        "match_case": True,      # 3.10+
        "strategy": True,        # local
    }
    try:
        from plum import dispatch as _  # noqa: F401
        st["plum"] = True
    except Exception:
        pass
    try:
        from multimethod import multimethod as _  # noqa: F401
        st["multimethod"] = True
    except Exception:
        pass
    try:
        from multipledispatch import dispatch as _  # noqa: F401
        st["multipledispatch"] = True
    except Exception:
        pass
    _ENGINES_STATUS = st
    return st


def enabled_engines() -> List[str]:
    raw = (os.environ.get("KFIOSA_POLY_ENGINES") or "").strip()
    st = _probe()
    if raw in ("0", "false", "off", "no", "none"):
        return []
    if raw:
        wanted = {x.strip().lower() for x in raw.split(",") if x.strip()}
        return [e for e in st if e in wanted and st[e]]
    return [e for e, ok in st.items() if ok]


def engines_status() -> Dict[str, Any]:
    st = _probe()
    return {
        "ok": True,
        "available": st,
        "enabled": enabled_engines(),
        "python_requires": ">=3.10",
        "libraries": {
            "plum": "https://github.com/beartype/plum",
            "multimethod": "https://github.com/coady/multimethod",
            "multipledispatch": "https://github.com/mrocklin/multipledispatch",
            "singledispatch": "https://docs.python.org/3/library/functools.html",
            "match_case": "https://docs.python.org/3/reference/compound_stmts.html#match",
            "strategy": "core.utils.poly_runtime",
        },
    }


# ---------------------------------------------------------------------------
# Shared envelope
# ---------------------------------------------------------------------------


def _env(
    *,
    engine: str,
    method: str = "",
    family: str = "generic",
    focus: str = "balanced",
    depth: str = "medium",
    boosts: Optional[Dict[str, float]] = None,
    tool_order: Optional[List[str]] = None,
    rationale: str = "",
    weight: float = 1.0,
) -> Dict[str, Any]:
    return {
        "ok": True,
        "engine": engine,
        "method": method,
        "family": family,
        "focus": focus,
        "depth": depth,
        "boosts": dict(boosts or {}),
        "tool_order": list(tool_order or []),
        "rationale": rationale or f"{engine} adaptation",
        "weight": float(weight),
        "model": f"polymorphic ({engine})",
    }


# ---------------------------------------------------------------------------
# Domain markers for multipledispatch (type-based)
# ---------------------------------------------------------------------------


class _D:
    """Marker base for multipledispatch domain types."""


class D_wifi(_D):
    pass


class D_ble(_D):
    pass


class D_web(_D):
    pass


class D_binary(_D):
    pass


class D_network(_D):
    pass


class D_cloud(_D):
    pass


class D_osint(_D):
    pass


class D_post(_D):
    pass


class D_zero(_D):
    pass


class D_generic(_D):
    pass


_DOMAIN_MARKERS = {
    "wifi": D_wifi,
    "wlan": D_wifi,
    "wireless": D_wifi,
    "ble": D_ble,
    "bluetooth": D_ble,
    "web": D_web,
    "osint_web": D_web,
    "binary": D_binary,
    "network": D_network,
    "cloud": D_cloud,
    "osint": D_osint,
    "osint_people": D_osint,
    "post_exploit": D_post,
    "post_exploitation": D_post,
    "post": D_post,
    "zero_day": D_zero,
    "0day": D_zero,
}


def _marker(domain: str) -> _D:
    cls = _DOMAIN_MARKERS.get((domain or "").lower(), D_generic)
    return cls()


# ---------------------------------------------------------------------------
# Engine: multipledispatch (mrocklin)
# ---------------------------------------------------------------------------

_md_dispatcher = None
_md_ready = False


def _init_multipledispatch() -> None:
    """Register type→adapt handlers via mrocklin/multipledispatch Dispatcher."""
    global _md_dispatcher, _md_ready
    if _md_ready:
        return
    _md_ready = True
    try:
        from multipledispatch import Dispatcher
    except Exception:
        return

    md = Dispatcher("kfiosa_md_adapt")

    @md.register(D_wifi)
    def _wifi(d):
        return _env(
            engine="multipledispatch",
            method="poly_wpa3_sae_grammar",
            family="wifi", focus="sae", depth="deep",
            boosts={"sae_commit": 0.3, "pmkid_first": 0.2, "handshake_deauth": 0.15},
            tool_order=["hcxdumptool", "airodump-ng", "aircrack-ng"],
            rationale="multipledispatch: D_wifi → wifi capture grammar",
            weight=1.0,
        )

    @md.register(D_ble)
    def _ble(d):
        return _env(
            engine="multipledispatch",
            method="poly_ble_scan_window_grammar",
            family="ble", focus="gatt", depth="medium",
            boosts={"gatt_enum": 0.3, "adv_sniff": 0.2, "pairing_probe": 0.15},
            tool_order=["gatttool", "bluetoothctl"],
            rationale="multipledispatch: D_ble → BLE scan/GATT",
            weight=1.0,
        )

    @md.register(D_web)
    def _web(d):
        return _env(
            engine="multipledispatch",
            method="poly_nmap_script_grammar",
            family="web", focus="injection", depth="deep",
            boosts={"polyglot_payload": 0.3, "auth_chain": 0.25, "ssrf_chain": 0.15},
            tool_order=["nuclei", "ffuf"],
            rationale="multipledispatch: D_web → web polyglot",
            weight=1.0,
        )

    @md.register(D_binary)
    def _binary(d):
        return _env(
            engine="multipledispatch",
            method="zero_day_control_flow_surfer",
            family="binary", focus="cfg", depth="deep",
            boosts={"cfg_surf": 0.3, "bounds_prober": 0.25, "harness_gen": 0.2},
            tool_order=["ghidra", "radare2", "afl++"],
            rationale="multipledispatch: D_binary → CFG/fuzz",
            weight=1.0,
        )

    @md.register(D_network)
    def _network(d):
        return _env(
            engine="multipledispatch",
            method="poly_nmap_script_grammar",
            family="network", focus="parse", depth="deep",
            boosts={"malformed_pdu": 0.3, "state_desync": 0.25},
            tool_order=["nmap", "scapy"],
            rationale="multipledispatch: D_network → PDU fuzz",
            weight=1.0,
        )

    @md.register(D_cloud)
    def _cloud(d):
        return _env(
            engine="multipledispatch",
            method="zero_day_aws_iam",
            family="cloud", focus="iam", depth="medium",
            boosts={"iam_wildcards": 0.3, "metadata_ssrf": 0.25},
            tool_order=["pacu", "scoutsuite"],
            rationale="multipledispatch: D_cloud → IAM/SSRF",
            weight=1.0,
        )

    @md.register(D_osint)
    def _osint(d):
        return _env(
            engine="multipledispatch",
            method="poly_osint_user_agent_grammar",
            family="osint", focus="passive", depth="medium",
            boosts={"passive_first": 0.25, "breach_pivot": 0.2, "graph_expand": 0.2},
            rationale="multipledispatch: D_osint → passive OSINT",
            weight=1.0,
        )

    @md.register(D_post)
    def _post(d):
        return _env(
            engine="multipledispatch",
            method="poly_lateral_movement_grammar",
            family="post_exploit", focus="lateral", depth="deep",
            boosts={"lateral_first": 0.3, "enum_then_creds": 0.2, "persist_quiet": 0.15},
            rationale="multipledispatch: D_post → lateral/enum",
            weight=1.0,
        )

    @md.register(D_zero)
    def _zero(d):
        return _env(
            engine="multipledispatch",
            method="zero_day_logic_flaw_heuristic",
            family="logic", focus="workflow", depth="deep",
            boosts={"deep_pass": 0.25, "step_skip": 0.2},
            rationale="multipledispatch: D_zero → logic flaw",
            weight=1.0,
        )

    @md.register(D_generic)
    def _generic(d):
        return _env(
            engine="multipledispatch",
            method="recon_probe",
            family="generic", focus="balanced", depth="medium",
            boosts={"medium_pass": 0.2},
            rationale="multipledispatch: D_generic fallback",
            weight=0.7,
        )

    _md_dispatcher = md


def _run_multipledispatch(domain: str, **_kw: Any) -> Dict[str, Any]:
    _init_multipledispatch()
    if _md_dispatcher is None:
        return _env(
            engine="multipledispatch",
            rationale="multipledispatch unavailable",
            weight=0.0,
        )
    try:
        return _md_dispatcher(_marker(domain))
    except Exception as e:  # noqa: BLE001
        # fall back to generic marker
        try:
            return _md_dispatcher(D_generic())
        except Exception:
            return _env(
                engine="multipledispatch",
                rationale=f"multipledispatch error: {e}",
                weight=0.0,
            )


# ---------------------------------------------------------------------------
# Engine: multimethod (coady)
# ---------------------------------------------------------------------------

_mm_fn = None
_mm_ready = False


def _init_multimethod() -> None:
    """Register multimethod handlers with concrete types (no postponed annos).

    ``from __future__ import annotations`` would leave type names as strings
    that multimethod cannot resolve inside this nested scope — so we attach
    ``__annotations__`` with real classes after each ``def``.
    """
    global _mm_fn, _mm_ready
    if _mm_ready:
        return
    _mm_ready = True
    try:
        from multimethod import multimethod
        from core.poly.plum_adapt import (
            WifiTarget, BleTarget, WebTarget, BinaryTarget, NetworkTarget,
            CloudTarget, OsintTarget, PostExploitTarget, ZeroDayTarget,
            TargetView,
        )
    except Exception:
        return

    def _fallback(target: object) -> Dict[str, Any]:
        return _env(
            engine="multimethod", method="recon_probe",
            family="generic", focus="balanced", depth="medium",
            boosts={"medium_pass": 0.2},
            rationale="multimethod: fallback",
            weight=0.7,
        )

    _fallback.__annotations__ = {"target": object, "return": Dict[str, Any]}
    mm_adapt = multimethod(_fallback)

    def _reg(typ: type, fn: Callable[..., Dict[str, Any]]) -> None:
        fn.__annotations__ = {"target": typ, "return": Dict[str, Any]}
        mm_adapt.register(fn)

    def _wifi(target: object) -> Dict[str, Any]:
        f = getattr(target, "features", {}) or {}
        raw = getattr(target, "raw", {}) or {}
        pmf = bool(f.get("pmf_supported") or raw.get("pmf"))
        enc = str(f.get("encryption") or "").lower()
        if pmf or "wpa3" in enc or "sae" in enc:
            return _env(
                engine="multimethod", method="poly_wpa3_sae_grammar",
                family="wifi", focus="sae", depth="deep",
                boosts={"sae_commit": 0.35, "pmkid_first": 0.2},
                tool_order=["hcxdumptool", "airodump-ng"],
                rationale="multimethod: WifiTarget SAE/PMF",
                weight=1.1,
            )
        clients = int(f.get("client_count") or 0)
        if clients <= 1:
            return _env(
                engine="multimethod", method="poly_pmkid_vs_handshake_grammar",
                family="wifi", focus="pmkid", depth="medium",
                boosts={"pmkid_first": 0.35},
                rationale="multimethod: WifiTarget low clients → PMKID",
                weight=1.05,
            )
        return _env(
            engine="multimethod", method="poly_deauth_burst_pattern_grammar",
            family="wifi", focus="handshake", depth="deep",
            boosts={"handshake_deauth": 0.3},
            tool_order=["aireplay-ng", "airodump-ng"],
            rationale="multimethod: WifiTarget multi-client deauth",
            weight=1.0,
        )

    def _ble(target: object) -> Dict[str, Any]:
        return _env(
            engine="multimethod", method="adapt_ble_connect_vs_sniff",
            family="ble", focus="gatt", depth="medium",
            boosts={"gatt_enum": 0.35, "adv_sniff": 0.15},
            tool_order=["gatttool", "btmon"],
            rationale="multimethod: BleTarget GATT path",
            weight=1.05,
        )

    def _web(target: object) -> Dict[str, Any]:
        return _env(
            engine="multimethod", method="poly_nmap_script_grammar",
            family="web", focus="injection", depth="deep",
            boosts={"polyglot_payload": 0.35, "auth_chain": 0.2},
            rationale="multimethod: WebTarget injection",
            weight=1.05,
        )

    def _binary(target: object) -> Dict[str, Any]:
        return _env(
            engine="multimethod", method="zero_day_crash_triager",
            family="binary", focus="bounds", depth="deep",
            boosts={"bounds_prober": 0.3, "cfg_surf": 0.25},
            tool_order=["gdb", "ghidra"],
            rationale="multimethod: BinaryTarget bounds/CFG",
            weight=1.05,
        )

    def _network(target: object) -> Dict[str, Any]:
        return _env(
            engine="multimethod", method="poly_nmap_script_grammar",
            family="network", focus="parse", depth="deep",
            boosts={"malformed_pdu": 0.3, "option_soup": 0.2},
            rationale="multimethod: NetworkTarget parse fuzz",
            weight=1.0,
        )

    def _cloud(target: object) -> Dict[str, Any]:
        return _env(
            engine="multimethod", method="zero_day_aws_iam",
            family="cloud", focus="iam", depth="medium",
            boosts={"iam_wildcards": 0.3, "ci_secrets": 0.2},
            rationale="multimethod: CloudTarget IAM",
            weight=1.0,
        )

    def _osint(target: object) -> Dict[str, Any]:
        return _env(
            engine="multimethod", method="poly_email_pattern_grammar",
            family="osint", focus="breach", depth="medium",
            boosts={"breach_pivot": 0.3, "graph_expand": 0.2},
            rationale="multimethod: OsintTarget breach/graph",
            weight=1.0,
        )

    def _post(target: object) -> Dict[str, Any]:
        return _env(
            engine="multimethod", method="poly_persistence_registry_grammar",
            family="post_exploit", focus="enum", depth="medium",
            boosts={"enum_then_creds": 0.3, "lateral_first": 0.2},
            rationale="multimethod: PostExploitTarget enum",
            weight=1.0,
        )

    def _zero(target: object) -> Dict[str, Any]:
        return _env(
            engine="multimethod", method="zero_day_logic_flaw_heuristic",
            family="logic", focus="workflow", depth="deep",
            boosts={"deep_pass": 0.3},
            rationale="multimethod: ZeroDayTarget logic",
            weight=1.0,
        )

    def _view(target: object) -> Dict[str, Any]:
        return _env(
            engine="multimethod", method="recon_probe",
            family="generic", focus="balanced", depth="medium",
            boosts={"medium_pass": 0.2},
            rationale="multimethod: TargetView fallback",
            weight=0.7,
        )

    for typ, fn in (
        (WifiTarget, _wifi),
        (BleTarget, _ble),
        (WebTarget, _web),
        (BinaryTarget, _binary),
        (NetworkTarget, _network),
        (CloudTarget, _cloud),
        (OsintTarget, _osint),
        (PostExploitTarget, _post),
        (ZeroDayTarget, _zero),
        (TargetView, _view),
    ):
        _reg(typ, fn)

    _mm_fn = mm_adapt


def _run_multimethod(view: Any, **_kw: Any) -> Dict[str, Any]:
    _init_multimethod()
    if _mm_fn is None:
        return _env(engine="multimethod", rationale="multimethod unavailable", weight=0.0)
    try:
        return _mm_fn(view)
    except Exception as e:  # noqa: BLE001
        return _env(engine="multimethod", rationale=f"multimethod error: {e}", weight=0.0)


# ---------------------------------------------------------------------------
# Engine: functools.singledispatch (stdlib)
# ---------------------------------------------------------------------------


@singledispatch
def _sd_adapt(view: Any) -> Dict[str, Any]:
    return _env(
        engine="singledispatch", method="recon_probe",
        family="generic", focus="balanced", depth="medium",
        boosts={"medium_pass": 0.15},
        rationale="singledispatch: default",
        weight=0.6,
    )


def _register_singledispatch() -> None:
    try:
        from core.poly.plum_adapt import (
            WifiTarget, BleTarget, WebTarget, BinaryTarget, NetworkTarget,
            CloudTarget, OsintTarget, PostExploitTarget, ZeroDayTarget,
            TargetView,
        )
    except Exception:
        return

    @_sd_adapt.register(WifiTarget)
    def _(view: WifiTarget) -> Dict[str, Any]:
        return _env(
            engine="singledispatch", method="wifi_recon_passive",
            family="wifi", focus="passive", depth="shallow",
            boosts={"passive_long": 0.25, "pmkid_first": 0.15},
            tool_order=["airodump-ng", "kismet"],
            rationale="singledispatch: WifiTarget passive-first",
            weight=0.9,
        )

    @_sd_adapt.register(BleTarget)
    def _(view: BleTarget) -> Dict[str, Any]:
        return _env(
            engine="singledispatch", method="poly_ble_scan_window_grammar",
            family="ble", focus="advertising", depth="shallow",
            boosts={"adv_sniff": 0.25},
            rationale="singledispatch: BleTarget adv",
            weight=0.9,
        )

    @_sd_adapt.register(WebTarget)
    def _(view: WebTarget) -> Dict[str, Any]:
        return _env(
            engine="singledispatch", method="poly_nmap_script_grammar",
            family="web", focus="auth", depth="medium",
            boosts={"auth_chain": 0.25, "logic_workflow": 0.15},
            rationale="singledispatch: WebTarget auth",
            weight=0.9,
        )

    @_sd_adapt.register(BinaryTarget)
    def _(view: BinaryTarget) -> Dict[str, Any]:
        return _env(
            engine="singledispatch", method="zero_day_control_flow_surfer",
            family="binary", focus="static", depth="medium",
            boosts={"static_strings": 0.25, "cfg_surf": 0.2},
            rationale="singledispatch: BinaryTarget static",
            weight=0.9,
        )

    @_sd_adapt.register(NetworkTarget)
    def _(view: NetworkTarget) -> Dict[str, Any]:
        return _env(
            engine="singledispatch", method="poly_nmap_script_grammar",
            family="network", focus="state", depth="medium",
            boosts={"state_desync": 0.25},
            rationale="singledispatch: NetworkTarget state",
            weight=0.9,
        )

    @_sd_adapt.register(CloudTarget)
    def _(view: CloudTarget) -> Dict[str, Any]:
        return _env(
            engine="singledispatch", method="zero_day_aws_iam",
            family="cloud", focus="storage", depth="shallow",
            boosts={"public_bucket": 0.25},
            rationale="singledispatch: CloudTarget storage",
            weight=0.85,
        )

    @_sd_adapt.register(OsintTarget)
    def _(view: OsintTarget) -> Dict[str, Any]:
        return _env(
            engine="singledispatch", method="poly_osint_user_agent_grammar",
            family="osint", focus="passive", depth="shallow",
            boosts={"passive_first": 0.25},
            rationale="singledispatch: OsintTarget passive",
            weight=0.85,
        )

    @_sd_adapt.register(PostExploitTarget)
    def _(view: PostExploitTarget) -> Dict[str, Any]:
        return _env(
            engine="singledispatch", method="poly_exfil_channel_grammar",
            family="post_exploit", focus="exfil", depth="medium",
            boosts={"exfil_covert": 0.25, "persist_quiet": 0.15},
            rationale="singledispatch: PostExploitTarget exfil",
            weight=0.9,
        )

    @_sd_adapt.register(ZeroDayTarget)
    def _(view: ZeroDayTarget) -> Dict[str, Any]:
        return _env(
            engine="singledispatch", method="zero_day_side_channel_finder",
            family="side_channel", focus="timing", depth="medium",
            boosts={"timing_class": 0.2},
            rationale="singledispatch: ZeroDayTarget side-channel",
            weight=0.85,
        )

    @_sd_adapt.register(TargetView)
    def _(view: TargetView) -> Dict[str, Any]:
        return _env(
            engine="singledispatch", method="recon_probe",
            family="generic", focus="balanced", depth="medium",
            boosts={"medium_pass": 0.15},
            rationale="singledispatch: TargetView",
            weight=0.6,
        )


_register_singledispatch()


def _run_singledispatch(view: Any, **_kw: Any) -> Dict[str, Any]:
    try:
        return _sd_adapt(view)
    except Exception as e:  # noqa: BLE001
        return _env(engine="singledispatch", rationale=f"sd error: {e}", weight=0.0)


# ---------------------------------------------------------------------------
# Engine: match/case (Python 3.10)
# ---------------------------------------------------------------------------


def _run_match_case(
    domain: str,
    family: str = "",
    features: Optional[Dict[str, Any]] = None,
    **_kw: Any,
) -> Dict[str, Any]:
    feats = features or {}
    dom = (domain or family or "unknown").lower()
    clients = int(feats.get("client_count") or 0)
    pmf = bool(feats.get("pmf_supported") or feats.get("pmf"))
    enc = str(feats.get("encryption") or feats.get("wpa_version") or "").lower()
    has_url = bool(feats.get("has_url") or feats.get("url"))
    has_creds = bool(feats.get("has_creds"))

    match (dom, pmf, clients > 0, has_url, has_creds):
        case (("wifi" | "wlan" | "wireless"), True, _, _, _):
            return _env(
                engine="match_case", method="poly_wpa3_sae_grammar",
                family="wifi", focus="sae", depth="deep",
                boosts={"sae_commit": 0.4},
                rationale="match/case: wifi+pmf → SAE",
                weight=1.0,
            )
        case (("wifi" | "wlan" | "wireless"), False, False, _, _):
            return _env(
                engine="match_case", method="poly_pmkid_vs_handshake_grammar",
                family="wifi", focus="pmkid", depth="medium",
                boosts={"pmkid_first": 0.35},
                rationale="match/case: wifi no clients → PMKID",
                weight=1.0,
            )
        case (("wifi" | "wlan" | "wireless"), False, True, _, _):
            return _env(
                engine="match_case", method="poly_deauth_burst_pattern_grammar",
                family="wifi", focus="handshake", depth="deep",
                boosts={"handshake_deauth": 0.3},
                rationale="match/case: wifi+clients → deauth",
                weight=1.0,
            )
        case (("ble" | "bluetooth"), _, _, _, _):
            return _env(
                engine="match_case", method="poly_ble_scan_window_grammar",
                family="ble", focus="gatt", depth="medium",
                boosts={"gatt_enum": 0.3},
                rationale="match/case: ble",
                weight=1.0,
            )
        case (("web" | "osint_web"), _, _, True, _):
            return _env(
                engine="match_case", method="poly_nmap_script_grammar",
                family="web", focus="injection", depth="deep",
                boosts={"polyglot_payload": 0.3},
                rationale="match/case: web+url",
                weight=1.0,
            )
        case (("post_exploit" | "post" | "post_exploitation"), _, _, _, True):
            return _env(
                engine="match_case", method="poly_lateral_movement_grammar",
                family="post_exploit", focus="lateral", depth="deep",
                boosts={"lateral_first": 0.35},
                rationale="match/case: post+creds → lateral",
                weight=1.0,
            )
        case (("binary" | "zero_day" | "0day"), _, _, _, _):
            return _env(
                engine="match_case", method="zero_day_control_flow_surfer",
                family="binary", focus="cfg", depth="deep",
                boosts={"cfg_surf": 0.3},
                rationale="match/case: binary/0day",
                weight=1.0,
            )
        case (("cloud",), _, _, _, _):
            return _env(
                engine="match_case", method="zero_day_aws_iam",
                family="cloud", focus="iam", depth="medium",
                boosts={"iam_wildcards": 0.3},
                rationale="match/case: cloud",
                weight=1.0,
            )
        case (("osint" | "osint_people"), _, _, _, _):
            return _env(
                engine="match_case", method="poly_osint_user_agent_grammar",
                family="osint", focus="passive", depth="medium",
                boosts={"passive_first": 0.25},
                rationale="match/case: osint",
                weight=1.0,
            )
        case _:
            # secondary match on encryption string for wifi mis-domain
            if "wpa3" in enc or "sae" in enc:
                return _env(
                    engine="match_case", method="poly_wpa3_sae_grammar",
                    family="wifi", focus="sae", depth="deep",
                    boosts={"sae_commit": 0.25},
                    rationale="match/case: enc-hint SAE",
                    weight=0.8,
                )
            return _env(
                engine="match_case", method="recon_probe",
                family="generic", focus="balanced", depth="medium",
                boosts={"medium_pass": 0.15},
                rationale="match/case: default",
                weight=0.6,
            )


# ---------------------------------------------------------------------------
# Engine: strategy registry (local poly_runtime)
# ---------------------------------------------------------------------------


def _run_strategy(
    domain: str,
    features: Optional[Dict[str, Any]] = None,
    **_kw: Any,
) -> Dict[str, Any]:
    try:
        from core.utils.poly_runtime import (
            Domain, Phase, DEFAULT_REGISTRY, situational_pick,
        )
        # Avoid recursion: call registry pick only, not full situational_pick
        dom = Domain.coerce(domain)
        feats = dict(features or {})
        strat = DEFAULT_REGISTRY.pick(dom, feats, Phase.ANY)
        if strat is None:
            return _env(
                engine="strategy", method="enum",
                family=dom.value if hasattr(dom, "value") else str(domain),
                focus="balanced", depth="medium",
                boosts={"medium_pass": 0.1},
                rationale="strategy: no candidate",
                weight=0.5,
            )
        return _env(
            engine="strategy",
            method=strat.name,
            family=dom.value if hasattr(dom, "value") else str(domain),
            focus=strat.name,
            depth="medium",
            boosts={strat.name: 0.2},
            rationale=f"strategy: {strat.description or strat.name}",
            weight=0.95,
        )
    except Exception as e:  # noqa: BLE001
        return _env(engine="strategy", rationale=f"strategy error: {e}", weight=0.0)


# ---------------------------------------------------------------------------
# Engine: plum (existing module)
# ---------------------------------------------------------------------------


def _run_plum(
    target: Optional[Dict[str, Any]] = None,
    recon: Optional[Dict[str, Any]] = None,
    domain: str = "",
    **_kw: Any,
) -> Dict[str, Any]:
    try:
        from core.poly.plum_adapt import adapt_target
        penv = adapt_target(target, recon=recon, domain=domain)
        return _env(
            engine="plum",
            method=str(penv.get("method") or ""),
            family=str(penv.get("family") or "generic"),
            focus=str(penv.get("focus") or "balanced"),
            depth=str(penv.get("depth") or "medium"),
            boosts=dict(penv.get("boosts") or {}),
            tool_order=list(penv.get("tool_order") or []),
            rationale=str(penv.get("rationale") or "plum adapt"),
            weight=1.15,  # slightly prefer plum when present
        )
    except Exception as e:  # noqa: BLE001
        return _env(engine="plum", rationale=f"plum error: {e}", weight=0.0)


# ---------------------------------------------------------------------------
# Ensemble
# ---------------------------------------------------------------------------


@dataclass
class EnsembleResult:
    method: str = "recon_probe"
    family: str = "generic"
    focus: str = "balanced"
    depth: str = "medium"
    boosts: Dict[str, float] = field(default_factory=dict)
    tool_order: List[str] = field(default_factory=list)
    engines_used: List[str] = field(default_factory=list)
    votes: List[Dict[str, Any]] = field(default_factory=list)
    rationale: str = ""
    model: str = "polymorphic (multi-engine ensemble)"

    def as_dict(self) -> Dict[str, Any]:
        return {
            "ok": True,
            "method": self.method,
            "family": self.family,
            "focus": self.focus,
            "depth": self.depth,
            "boosts": self.boosts,
            "tool_order": self.tool_order,
            "engines_used": self.engines_used,
            "engine_count": len(self.engines_used),
            "votes": [
                {
                    "engine": v.get("engine"),
                    "method": v.get("method"),
                    "focus": v.get("focus"),
                    "depth": v.get("depth"),
                    "weight": v.get("weight"),
                }
                for v in self.votes
            ],
            "rationale": self.rationale,
            "model": self.model,
        }


def ensemble_adapt(
    target: Optional[Dict[str, Any]] = None,
    *,
    recon: Optional[Dict[str, Any]] = None,
    domain: str = "",
    family: str = "",
) -> Dict[str, Any]:
    """Run all enabled polymorphism engines and merge results."""
    engines = enabled_engines()
    if not engines:
        return EnsembleResult(
            rationale="all poly engines disabled",
            model="polymorphic (disabled)",
        ).as_dict()

    # Coerce typed view once (shared by multimethod / singledispatch / plum)
    view = None
    feats: Dict[str, Any] = {}
    try:
        from core.poly.plum_adapt import coerce_target
        view = coerce_target(target, recon=recon, domain=domain or family)
        feats = dict(view.features or {})
        if not domain:
            domain = view.domain or domain
    except Exception:  # noqa: BLE001
        if isinstance(target, dict):
            feats = dict(target)
        domain = domain or family or "unknown"

    votes: List[Dict[str, Any]] = []
    used: List[str] = []

    runners: Dict[str, Callable[..., Dict[str, Any]]] = {
        "plum": lambda: _run_plum(target, recon=recon, domain=domain),
        "multimethod": lambda: _run_multimethod(view if view is not None else target),
        "multipledispatch": lambda: _run_multipledispatch(domain or family),
        "singledispatch": lambda: _run_singledispatch(
            view if view is not None else target
        ),
        "match_case": lambda: _run_match_case(
            domain or family, family=family, features=feats,
        ),
        "strategy": lambda: _run_strategy(domain or family, features=feats),
    }

    for name in engines:
        run = runners.get(name)
        if not run:
            continue
        try:
            v = run()
            if isinstance(v, dict) and float(v.get("weight") or 0) > 0:
                votes.append(v)
                used.append(name)
        except Exception:  # noqa: BLE001
            continue

    if not votes:
        return EnsembleResult(
            engines_used=[],
            rationale="no engine produced a vote",
        ).as_dict()

    # Weighted majority for focus / depth / method / family
    def _majority(key: str, default: str) -> str:
        c: Counter = Counter()
        for v in votes:
            val = str(v.get(key) or default)
            w = float(v.get("weight") or 1.0)
            c[val] += w
        if not c:
            return default
        return c.most_common(1)[0][0]

    focus = _majority("focus", "balanced")
    depth = _majority("depth", "medium")
    method = _majority("method", "recon_probe")
    fam = _majority("family", family or "generic")

    # Merge boosts (weighted sum, then normalize lightly)
    boosts: Dict[str, float] = {}
    for v in votes:
        w = float(v.get("weight") or 1.0)
        for k, b in (v.get("boosts") or {}).items():
            try:
                boosts[k] = boosts.get(k, 0.0) + float(b) * w
            except (TypeError, ValueError):
                continue
    if boosts:
        # dampen so scores stay in reasonable range
        mx = max(abs(x) for x in boosts.values()) or 1.0
        if mx > 0.8:
            scale = 0.8 / mx
            boosts = {k: round(v * scale, 4) for k, v in boosts.items()}
        else:
            boosts = {k: round(v, 4) for k, v in boosts.items()}

    # Prefer tool_order from highest-weight vote that has one
    tool_order: List[str] = []
    best_w = -1.0
    for v in votes:
        w = float(v.get("weight") or 0)
        to = v.get("tool_order") or []
        if to and w > best_w:
            tool_order = list(to)
            best_w = w

    rationales = [
        f"{v.get('engine')}:{v.get('focus')}/{v.get('depth')}"
        for v in votes
    ]
    result = EnsembleResult(
        method=method,
        family=fam,
        focus=focus,
        depth=depth,
        boosts=boosts,
        tool_order=tool_order,
        engines_used=used,
        votes=votes,
        rationale=(
            f"ensemble[{','.join(used)}] focus={focus} depth={depth} "
            f"method={method} (" + "; ".join(rationales[:6]) + ")"
        ),
        model=f"polymorphic (ensemble:{','.join(used)})",
    )
    return result.as_dict()


def multi_engine_prompt_block(
    target: Optional[Dict[str, Any]] = None,
    *,
    domain: str = "",
) -> str:
    """Compact prompt for chain planner / AI."""
    env = ensemble_adapt(target, domain=domain)
    lines = [
        "MULTI-ENGINE POLY (Python≥3.10):",
        f"  engines={env.get('engines_used')} count={env.get('engine_count')}",
        f"  method={env.get('method')} family={env.get('family')} "
        f"focus={env.get('focus')} depth={env.get('depth')}",
        f"  model={env.get('model')}",
    ]
    if env.get("tool_order"):
        lines.append(f"  tool_order={env.get('tool_order')}")
    if env.get("boosts"):
        top = sorted(
            (env.get("boosts") or {}).items(), key=lambda x: -abs(x[1]),
        )[:5]
        lines.append(
            "  boosts=" + ", ".join(f"{k}:{v:+.2f}" for k, v in top)
        )
    lines.append(
        "  Libraries: plum (beartype/plum), multimethod (coady), "
        "multipledispatch (mrocklin), functools.singledispatch, "
        "match/case, strategy registry."
    )
    lines.append(
        "  Prefer ensemble focus/depth when planning; never invent "
        "CVEs/PSKs/access."
    )
    return "\n".join(lines)


__all__ = [
    "ensemble_adapt",
    "enabled_engines",
    "engines_status",
    "multi_engine_prompt_block",
    "EnsembleResult",
]
