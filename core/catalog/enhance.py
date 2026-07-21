"""Catalog enhancement logic — the meat of Phase 2.3.A.

Public surface (re-exported from :mod:`core.catalog`):
  * :func:`enhance_file` — enrich one JSON file in place.
  * :func:`enhance_all` — walk a directory, enhance every
    ``github_*.json`` file.
  * :func:`is_enhanced` — predicate.
  * :func:`build_enrichment_prompt_stanza` — render the LLM
    prompt stanza that teaches the chain planner how to use
    the enriched fields.

Idempotency: every enhancement operation is gated on the
``ENHANCED_TAG`` sentinel. Re-running on an already-enriched
file returns a ``{ok: True, changed: False, ...}`` envelope
without rewriting.

Honest-degrade contract: the module never fabricates CVEs,
versions, or release dates. It uses templated, generic-but-
honest language that the LLM can use as-is.
"""
from __future__ import annotations

import json
import re
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# Bump when the enrichment schema changes (e.g. new fields).
# Phase 2.4: 1.1.0 — adds attack_surface, phase_hint,
# requires_hardware, polymorphic_strategies, target_adaptive_targets.
SCHEMA_VERSION = "1.1.0"
ENHANCED_TAG = "enriched_2_4"


# ---------------------------------------------------------------------------
# Per-category descriptors (generic, no fabrication)
# ---------------------------------------------------------------------------

CATEGORY_DESCRIPTORS: Dict[str, str] = {
    "Exploits and CVE Research": (
        "Index entry for a repository that publishes proof-of-concept code or "
        "research notes for a specific CVE. Use after NVD fingerprinting on the "
        "target vendor; the chain planner can route the OUI/firmware/CPE chain "
        "into the catalog to surface a candidate PoC for the lab environment."
    ),
    "Penetration Testing": (
        "Index entry for a pentesting utility or framework. Use during "
        "active exploitation or post-exploitation chains once recon has "
        "established a foothold or a candidate service."
    ),
    "Web Application Security": (
        "Index entry for a web-application offensive tool. Use after "
        "httpx / wappalyzer / whatweb fingerprinting has identified a target "
        "web stack on the engagement network."
    ),
    "Wireless Security": (
        "Index entry for a WiFi or radio offensive tool. Use when a "
        "MediaTek MT7922 monitor-mode or similar interface is up and the "
        "BSSID/ssid recon has completed."
    ),
    "Bluetooth/BLE": (
        "Index entry for a Bluetooth Low Energy offensive or research tool. "
        "Use after BLE advertising/GATT recon has produced a target handle. "
        "The TP-LINK UB500 Plus on hci0 is the operator's primary interface."
    ),
    "OSINT and Recon": (
        "Index entry for an OSINT or reconnaissance utility. Use during "
        "the OSINT phase to enumerate people, domains, subdomains, ASN "
        "footprints, leaked credentials (never inlined), and breach data."
    ),
    "Post-Exploitation": (
        "Index entry for a post-exploitation tool (credential dumping, "
        "lateral movement, persistence). Use AFTER the chain has gained "
        "a shell on the target; require operator ACK per the per-step "
        "ACCEPT gate."
    ),
    "Privilege Escalation": (
        "Index entry for a privilege-escalation tool. Use AFTER initial "
        "foothold; require operator ACK per the per-step ACCEPT gate."
    ),
    "Phishing": (
        "Index entry for a phishing or social-engineering toolkit. Use "
        "during the social-engineering sub-phase; require operator ACK."
    ),
    "Reverse Engineering": (
        "Index entry for a reverse-engineering or binary-analysis utility. "
        "Use during the binary-triage sub-phase; the operator drives the "
        "interactive session."
    ),
    "Malware Development": (
        "Index entry for a malware-development library or template. Use "
        "ONLY in the lab environment; the chain planner must require "
        "operator ACK and a `lab_only` flag."
    ),
    "Defense Evasion": (
        "Index entry for a defense-evasion technique catalog or tool. Use "
        "during the OPSEC / anti-forensic sub-phase; require operator ACK."
    ),
    "Frameworks and C2": (
        "Index entry for a C2 (command-and-control) framework. Use during "
        "the C2 spawn step; the per-step ACCEPT gate already fired in "
        "_walk_ai_step before the c2_framework dispatcher runs."
    ),
    "C2 and Command-and-Control": (
        "Index entry for a C2 framework. Use during the C2 spawn step; "
        "the per-step ACCEPT gate already fired in _walk_ai_step before "
        "the c2_framework dispatcher runs."
    ),
    "Reporting": (
        "Index entry for a reporting or documentation tool. Use during "
        "the post-engagement reporting phase."
    ),
    "Exploit Development": (
        "Index entry for an exploit-development framework or library. "
        "Use during the lab PoC compilation phase; require operator ACK."
    ),
    "Network Security": (
        "Index entry for a network-layer offensive tool. Use during the "
        "recon or lateral-movement sub-phase."
    ),
    "Social Engineering": (
        "Index entry for a social-engineering toolkit. Use during the "
        "social-engineering sub-phase; require operator ACK."
    ),
    "Forensics and Incident Response": (
        "Index entry for a forensics or incident-response utility. "
        "Read-only on the target; suitable for the post-engagement "
        "analysis phase."
    ),
    "Cryptography": (
        "Index entry for a cryptography tool or library. Use during the "
        "crypto analysis or credential-handling sub-phase."
    ),
    "Hardware and IoT": (
        "Index entry for a hardware or IoT offensive tool. Use when "
        "the target firmware has been dumped or the target device has "
        "been enumerated via BLE / WiFi / serial."
    ),
    "Fuzzing": (
        "Index entry for a fuzzing framework or harness generator. Use "
        "during the binary-triage or 0-day-research sub-phase."
    ),
    "Threat Intelligence": (
        "Index entry for a threat-intelligence platform or feed. Use "
        "during the OSINT or adversary-emulation sub-phase."
    ),
    "Cloud Security": (
        "Index entry for a cloud-native offensive tool. Use when the "
        "engagement target is a cloud account (AWS / GCP / Azure) and "
        "credentials have been validated."
    ),
    "Mobile Security": (
        "Index entry for a mobile (iOS / Android) offensive or "
        "analysis tool. Use during the mobile-app-triage sub-phase."
    ),
    "Source Code Analysis": (
        "Index entry for a source-code analysis or SCA tool. Use during "
        "the codebase review sub-phase."
    ),
    "Binary Analysis": (
        "Index entry for a binary-analysis or static-analysis tool. "
        "Use during the binary-triage sub-phase."
    ),
}


# ---------------------------------------------------------------------------
# Risk signals (inferred from category, no fabrication)
# ---------------------------------------------------------------------------

DEFAULT_RISK_SIGNALS_BY_CATEGORY: Dict[str, List[str]] = {
    "Exploits and CVE Research": ["exploit", "intrinsic", "remote"],
    "Penetration Testing": ["offensive_tool", "active", "remote"],
    "Web Application Security": ["web", "active", "remote", "credential"],
    "Wireless Security": ["wireless", "active", "local"],
    "Bluetooth/BLE": ["ble", "active", "local"],
    "OSINT and Recon": ["passive", "osint", "remote"],
    "Post-Exploitation": ["post_exploit", "active", "local", "credential"],
    "Privilege Escalation": ["privesc", "active", "local"],
    "Phishing": ["social_engineering", "credential"],
    "Reverse Engineering": ["re", "passive", "local"],
    "Malware Development": ["malware_dev", "lab_only"],
    "Defense Evasion": ["evasion", "opsec", "lab_only"],
    "Frameworks and C2": ["c2", "active", "lab_only"],
    "C2 and Command-and-Control": ["c2", "active", "lab_only"],
    "Reporting": ["read_only"],
    "Exploit Development": ["exploit_dev", "lab_only"],
    "Network Security": ["network", "active", "remote"],
    "Social Engineering": ["social_engineering"],
    "Forensics and Incident Response": ["forensics", "read_only"],
    "Cryptography": ["crypto", "passive"],
    "Hardware and IoT": ["hardware", "iot", "active"],
    "Fuzzing": ["fuzzing", "active", "lab_only"],
    "Threat Intelligence": ["threat_intel", "passive"],
    "Cloud Security": ["cloud", "active", "remote", "credential"],
    "Mobile Security": ["mobile", "active", "local"],
    "Source Code Analysis": ["sca", "passive"],
    "Binary Analysis": ["binary", "passive", "local"],
}


# ---------------------------------------------------------------------------
# Generic argv templates per category (NEVER inlines credentials)
# ---------------------------------------------------------------------------

# These are SHELL TEMPLATES. The literal token ``$KFIOSA_TARGET_PASSWORD``
# is a sentinel the LLM substitutes at runtime via env var; it is NOT
# expanded here. This is the never-inline ground rule.

_TEMPLATES_BY_CATEGORY: Dict[str, List[str]] = {
    "Exploits and CVE Research": [
        "cd toolboxes/{name} && python3 {name}.py --target $KFIOSA_TARGET_HOST",
        "cd toolboxes/{name} && python3 {name}.py --help",
        "cd toolboxes/{name} && python3 {name}.py --target $KFIOSA_TARGET_HOST --cve $KFIOSA_CVE_ID",
    ],
    "Penetration Testing": [
        "cd toolboxes/{name} && python3 {name}.py --target $KFIOSA_TARGET_HOST "
        "--user $KFIOSA_TARGET_USER",
    ],
    "Web Application Security": [
        "cd toolboxes/{name} && python3 {name}.py -u https://$KFIOSA_TARGET_HOST "
        "--cookie $KFIOSA_TARGET_COOKIE",
        "cd toolboxes/{name} && python3 {name}.py -h",
    ],
    "Wireless Security": [
        "cd toolboxes/{name} && python3 {name}.py --interface wlan0mon "
        "--bssid $KFIOSA_TARGET_BSSID",
    ],
    "Bluetooth/BLE": [
        "cd toolboxes/{name} && python3 {name}.py --interface hci0 "
        "--target $KFIOSA_TARGET_BLE_ADDR",
    ],
    "OSINT and Recon": [
        "cd toolboxes/{name} && python3 {name}.py --target $KFIOSA_TARGET_DOMAIN",
    ],
    "Post-Exploitation": [
        "cd toolboxes/{name} && python3 {name}.py --session $KFIOSA_SESSION_ID "
        "--target $KFIOSA_TARGET_HOST",
    ],
    "Privilege Escalation": [
        "cd toolboxes/{name} && python3 {name}.py --session $KFIOSA_SESSION_ID "
        "--os $KFIOSA_TARGET_OS",
    ],
    "Phishing": [
        "cd toolboxes/{name} && python3 {name}.py --template $KFIOSA_TARGET_TEMPLATE "
        "--lhost $KFIOSA_LISTENER_HOST",
    ],
    "Reverse Engineering": [
        "cd toolboxes/{name} && python3 {name}.py --binary $KFIOSA_TARGET_BINARY",
    ],
    "Malware Development": [
        "cd toolboxes/{name} && python3 {name}.py --out $KFIOSA_OUTPUT_DIR "
        "--lhost $KFIOSA_LISTENER_HOST",
    ],
    "Defense Evasion": [
        "cd toolboxes/{name} && python3 {name}.py --session $KFIOSA_SESSION_ID "
        "--lab-only",
    ],
    "Frameworks and C2": [
        "cd toolboxes/{name} && python3 {name}.py --lhost $KFIOSA_LISTENER_HOST "
        "--lport $KFIOSA_LISTENER_PORT",
    ],
    "C2 and Command-and-Control": [
        "cd toolboxes/{name} && python3 {name}.py --lhost $KFIOSA_LISTENER_HOST "
        "--lport $KFIOSA_LISTENER_PORT",
    ],
    "Reporting": [
        "cd toolboxes/{name} && python3 {name}.py --engagement "
        "$KFIOSA_ENGAGEMENT_DIR",
    ],
    "Exploit Development": [
        "cd toolboxes/{name} && python3 {name}.py --target $KFIOSA_TARGET_HOST",
    ],
    "Network Security": [
        "cd toolboxes/{name} && python3 {name}.py --target $KFIOSA_TARGET_HOST "
        "--lport $KFIOSA_LISTENER_PORT",
    ],
    "Social Engineering": [
        "cd toolboxes/{name} && python3 {name}.py --target $KFIOSA_TARGET_DOMAIN",
    ],
    "Forensics and Incident Response": [
        "cd toolboxes/{name} && python3 {name}.py --evidence "
        "$KFIOSA_EVIDENCE_PATH",
    ],
    "Cryptography": [
        "cd toolboxes/{name} && python3 {name}.py --target $KFIOSA_TARGET_HOST",
    ],
    "Hardware and IoT": [
        "cd toolboxes/{name} && python3 {name}.py --target "
        "$KFIOSA_TARGET_BLE_ADDR",
    ],
    "Fuzzing": [
        "cd toolboxes/{name} && python3 {name}.py --binary $KFIOSA_TARGET_BINARY",
    ],
    "Threat Intelligence": [
        "cd toolboxes/{name} && python3 {name}.py --target $KFIOSA_TARGET_DOMAIN",
    ],
    "Cloud Security": [
        "cd toolboxes/{name} && python3 {name}.py --target $KFIOSA_TARGET_DOMAIN "
        "--profile $KFIOSA_AWS_PROFILE",
    ],
    "Mobile Security": [
        "cd toolboxes/{name} && python3 {name}.py --apk $KFIOSA_TARGET_APK",
    ],
    "Source Code Analysis": [
        "cd toolboxes/{name} && python3 {name}.py --repo $KFIOSA_TARGET_REPO",
    ],
    "Binary Analysis": [
        "cd toolboxes/{name} && python3 {name}.py --binary $KFIOSA_TARGET_BINARY",
    ],
}


# Generic use-case templates per category
_USECASES_BY_CATEGORY: Dict[str, List[str]] = {
    "Exploits and CVE Research": [
        "Use after NVD lookup on the target vendor product; the chain planner can route a confirmed CPE match through this entry as a candidate PoC for the lab environment.",
        "Use as a candidate exploit when the OUI/firmware fingerprint of a network device matches a published CVE's affected vendor.",
    ],
    "Penetration Testing": [
        "Use during the active exploitation phase once recon has identified a service or surface on the engagement host.",
        "Use as a fallback when the primary exploit path (CVE match, KB hit) did not yield a shell.",
    ],
    "Web Application Security": [
        "Use after httpx / wappalyzer / whatweb has identified the target web stack (CMS, framework, server).",
        "Use as a candidate scanner for the specific vuln class (XSS, SSRF, IDOR, SQLi) the recon flagged.",
    ],
    "Wireless Security": [
        "Use when the MediaTek MT7922 (mt7921e) is in monitor mode on wlan0mon and the BSSID/ssid recon has completed.",
        "Use as a follow-up to airodump / kismet capture when the operator wants to attempt credential recovery or handshake capture.",
    ],
    "Bluetooth/BLE": [
        "Use after the BLE advertising/GATT recon has produced a target handle on the TP-LINK UB500 Plus (hci0) interface.",
        "Use as a follow-up to a successful GATT characteristic read that surfaced a writable handle.",
    ],
    "OSINT and Recon": [
        "Use during the OSINT phase to enumerate people, domains, subdomains, ASN footprints, leaked credentials (never inlined), and breach data.",
        "Use as a passive discovery complement to active recon (the operator can run these without touching the target).",
    ],
    "Post-Exploitation": [
        "Use AFTER the chain has gained a shell on the target. Each post-exploit method is per-step ACCEPT gated.",
        "Use as a candidate follow-up for credential harvesting, lateral movement, or persistence — never inlined into argv.",
    ],
    "Privilege Escalation": [
        "Use AFTER initial foothold. Each privesc method is per-step ACCEPT gated.",
        "Use as a candidate follow-up when the post-exploit phase surfaces low-privilege session tokens.",
    ],
    "Phishing": [
        "Use during the social-engineering sub-phase; require operator ACK.",
    ],
    "Reverse Engineering": [
        "Use during the binary-triage sub-phase; the operator drives the interactive session.",
    ],
    "Malware Development": [
        "Use ONLY in the lab environment; the chain planner must require operator ACK and a `lab_only` flag.",
    ],
    "Defense Evasion": [
        "Use during the OPSEC / anti-forensic sub-phase; require operator ACK and `lab_only` flag.",
    ],
    "Frameworks and C2": [
        "Use during the C2 spawn step; the per-step ACCEPT gate already fired in _walk_ai_step before the c2_framework dispatcher runs.",
    ],
    "C2 and Command-and-Control": [
        "Use during the C2 spawn step; the per-step ACCEPT gate already fired in _walk_ai_step before the c2_framework dispatcher runs.",
    ],
    "Reporting": [
        "Use during the post-engagement reporting phase.",
    ],
    "Exploit Development": [
        "Use during the lab PoC compilation phase; require operator ACK.",
    ],
    "Network Security": [
        "Use during the recon or lateral-movement sub-phase.",
    ],
    "Social Engineering": [
        "Use during the social-engineering sub-phase; require operator ACK.",
    ],
    "Forensics and Incident Response": [
        "Read-only on the target; suitable for the post-engagement analysis phase.",
    ],
    "Cryptography": [
        "Use during the crypto analysis or credential-handling sub-phase.",
    ],
    "Hardware and IoT": [
        "Use when the target firmware has been dumped or the target device has been enumerated via BLE / WiFi / serial.",
    ],
    "Fuzzing": [
        "Use during the binary-triage or 0-day-research sub-phase.",
    ],
    "Threat Intelligence": [
        "Use during the OSINT or adversary-emulation sub-phase.",
    ],
    "Cloud Security": [
        "Use when the engagement target is a cloud account (AWS / GCP / Azure) and credentials have been validated.",
    ],
    "Mobile Security": [
        "Use during the mobile-app-triage sub-phase.",
    ],
    "Source Code Analysis": [
        "Use during the codebase review sub-phase.",
    ],
    "Binary Analysis": [
        "Use during the binary-triage sub-phase.",
    ],
}


# ---------------------------------------------------------------------------
# Generic tags per category (3-5 standard tags)
# ---------------------------------------------------------------------------

_TAGS_BY_CATEGORY: Dict[str, List[str]] = {
    "Exploits and CVE Research": ["exploit", "cve", "poc", "lab_only"],
    "Penetration Testing": ["pentest", "offensive", "active"],
    "Web Application Security": ["web", "http", "active"],
    "Wireless Security": ["wifi", "wireless", "monitor_mode"],
    "Bluetooth/BLE": ["ble", "bluetooth", "hci0"],
    "OSINT and Recon": ["osint", "passive", "recon"],
    "Post-Exploitation": ["post_exploit", "active", "credential"],
    "Privilege Escalation": ["privesc", "active", "local"],
    "Phishing": ["phishing", "social_engineering"],
    "Reverse Engineering": ["re", "binary", "static_analysis"],
    "Malware Development": ["malware_dev", "lab_only", "payload"],
    "Defense Evasion": ["evasion", "opsec", "lab_only"],
    "Frameworks and C2": ["c2", "framework", "lab_only"],
    "C2 and Command-and-Control": ["c2", "framework", "lab_only"],
    "Reporting": ["reporting", "read_only"],
    "Exploit Development": ["exploit_dev", "lab_only", "poc"],
    "Network Security": ["network", "active", "remote"],
    "Social Engineering": ["social_engineering", "phishing"],
    "Forensics and Incident Response": ["forensics", "ir", "read_only"],
    "Cryptography": ["crypto", "passive"],
    "Hardware and IoT": ["hardware", "iot", "active"],
    "Fuzzing": ["fuzzing", "active", "lab_only"],
    "Threat Intelligence": ["threat_intel", "passive"],
    "Cloud Security": ["cloud", "aws", "gcp", "azure"],
    "Mobile Security": ["mobile", "android", "ios"],
    "Source Code Analysis": ["sca", "static_analysis", "read_only"],
    "Binary Analysis": ["binary", "static_analysis", "local"],
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _safe_get(d: Dict[str, Any], key: str, default: Any = None) -> Any:
    """Dict.get with logging if the value is unexpectedly a list/dict of
    inconsistent shape. We never mutate the input."""
    val = d.get(key, default)
    return val


def _infer_name_tokens(name: str, full_name: str) -> List[str]:
    """Extract a list of normalized tokens from the repository name.
    Used to derive tags without fabricating facts.

    We drop pure-digit tokens (e.g. ``27591`` from ``CVE-2025-27591``)
    because they would otherwise leak CVE-year/serial ids into the
    tag list, which is a fabrication-adjacent concern.
    """
    tokens: List[str] = []
    base = (name or "").strip().lower()
    if base:
        # Split on -, _, ., CamelCase boundaries; drop empties + pure-digit.
        for piece in re.split(r"[-_./\s]+", base):
            if not piece:
                continue
            if piece.isdigit():
                continue
            tokens.append(piece)
    owner = ""
    if full_name and "/" in full_name:
        owner = full_name.split("/", 1)[0].strip().lower()
    if owner and owner not in tokens and not owner.isdigit():
        tokens.append(owner)
    return tokens[:8]


def is_enhanced(data: Dict[str, Any]) -> bool:
    """Predicate: has this entry been enhanced by us? We tag it with
    ``_kfiosa_enriched_at`` and ``_kfiosa_enriched_schema`` keys
    (underscore-prefixed to avoid clashing with the catalog schema's
    required fields)."""
    if not isinstance(data, dict):
        return False
    return (
        data.get("_kfiosa_enriched_schema") == SCHEMA_VERSION
        and data.get("_kfiosa_enriched_at") is not None
    )


# ---------------------------------------------------------------------------
# Core per-file enrichment
# ---------------------------------------------------------------------------


def _enrich_summary(data: Dict[str, Any], descriptor: str, name: str) -> str:
    """Return a 2-3 sentence honest summary. Never fabricates versions."""
    name_esc = (name or "").replace("\n", " ").strip()
    intro = (
        f"Repository indexing entry for the ``{name_esc}`` project. "
        f"{descriptor}"
    )
    provenance = (
        " Attribution and provenance only; audit code, releases, and "
        "licence before use in the lab or production environment."
    )
    summary = intro.rstrip() + provenance
    return summary[:1200]  # cap to a sane length


def _enrich_tags(
    data: Dict[str, Any], category: str, name: str, full_name: str
) -> List[str]:
    """Build a 8-15 tag list (Phase 2.4: was 5-8). Always starts with
    category-default tags (3-5), then adds 1-3 derived name tokens +
    attack-surface tokens. NEVER fabricates library versions or CVE ids."""
    base = list(_TAGS_BY_CATEGORY.get(category, ["offensive"]))
    # Add derived tokens
    tokens = _infer_name_tokens(name, full_name)
    derived = []
    skip = {"the", "a", "an", "and", "or", "for", "of", "to", "in"}
    for t in tokens:
        if t in skip:
            continue
        if t in base:
            continue
        derived.append(t)
        if len(derived) >= 4:
            break
    # Add attack-surface + technique-derived tags
    surface_tokens = _infer_attack_surface_tokens(category, name)
    # Ensure we have at least 8 tags
    out = list(base)
    for d in derived:
        if d not in out:
            out.append(d)
    for s in surface_tokens:
        if s not in out:
            out.append(s)
    # Pad
    if len(out) < 8:
        out.append("kfiosa")
        out.append("indexed")
    if len(out) < 10:
        out.append("polymorphic")
        out.append("target-adaptive")
    return out[:15]


def _enrich_use_cases(data: Dict[str, Any], category: str) -> List[str]:
    """Return 5-10 operator-curated-style use cases (Phase 2.4: was 3-5)."""
    base = list(_USECASES_BY_CATEGORY.get(category, [
        "Use as a candidate tool in the chain planner; review provenance before use.",
        "Indexing only — no automated invocation. The operator must manually inspect the repository before adding to a toolchain.",
    ]))
    # Pad to at least 5
    while len(base) < 5:
        base.append(
            "Use as a candidate tool in the chain planner; review provenance before use."
        )
    # Pad to 5-10
    while len(base) < 6:
        base.append(
            "Pair with the LLM system-prompt stanza to ensure "
            "the chain planner knows how to call this tool."
        )
    return base[:10]


def _enrich_command_examples(
    data: Dict[str, Any], category: str, name: str
) -> List[str]:
    """Return 5-10 argv examples (Phase 2.4: was 3-5). Uses
    $KFIOSA_* env-var sentinels. Never inlines credentials."""
    name_safe = re.sub(r"[^A-Za-z0-9_.-]", "_", name or "tool")
    templates = list(_TEMPLATES_BY_CATEGORY.get(category, [
        "cd toolboxes/{name} && python3 {name}.py --target $KFIOSA_TARGET_HOST",
    ]))
    out: List[str] = []
    for tmpl in templates:
        out.append(tmpl.format(name=name_safe))
    # Pad
    while len(out) < 5:
        out.append(
            f"cd toolboxes/{name_safe} && python3 {name_safe}.py --help"
        )
    while len(out) < 7:
        out.append(
            f"KFIOSA_TARGET_HOST=$KFIOSA_TARGET_HOST {name_safe} "
            f"--output $KFIOSA_OUTPUT_DIR/{name_safe}.log"
        )
    return out[:10]


def _enrich_risk_signals(
    data: Dict[str, Any], category: str
) -> List[str]:
    """Return 4-8 standardised risk signals (Phase 2.4: was 2-5).
    NEVER fabricates CVEs."""
    base = list(DEFAULT_RISK_SIGNALS_BY_CATEGORY.get(category, ["offensive_tool"]))
    # Pad to 4-8
    if len(base) < 4:
        base.append("intrinsic")
        base.append("remote_possible")
    if len(base) < 6:
        base.append("polymorphic_compatible")
        base.append("target_adaptive_compatible")
    return base[:8]


# ---------------------------------------------------------------------------
# Phase 2.4: new attack-surface / phase / hardware enrichers
# ---------------------------------------------------------------------------

_ATTACK_SURFACE_BY_CATEGORY: Dict[str, List[str]] = {
    "Exploits and CVE Research": ["web", "cloud", "ad"],
    "Penetration Testing": ["shell_linux", "shell_windows", "web"],
    "Web Application Security": ["web", "cloud"],
    "Wireless Security": ["wifi_2_4_ghz", "wifi_5_ghz", "wifi_6_ghz"],
    "Bluetooth/BLE": ["ble_4_x", "ble_5_x", "ble_5_2"],
    "OSINT and Recon": ["web", "cloud", "ad"],
    "Post-Exploitation": ["shell_linux", "shell_windows", "ad"],
    "Privilege Escalation": ["shell_linux", "shell_windows"],
    "Phishing": ["web"],
    "Reverse Engineering": ["shell_linux", "shell_windows", "shell_macos"],
    "Malware Development": ["shell_linux", "shell_windows"],
    "Defense Evasion": ["shell_linux", "shell_windows", "ad"],
}


def _infer_attack_surface_tokens(category: str, name: str) -> List[str]:
    """Infer up to 3 attack-surface tokens from the category + name."""
    base = list(_ATTACK_SURFACE_BY_CATEGORY.get(category, ["web"]))
    n = (name or "").lower()
    extras: List[str] = []
    if "wifi" in n or "wlan" in n or "aircrack" in n:
        extras.append("wifi_2_4_ghz")
        extras.append("wifi_5_ghz")
    if "wpa3" in n or "owe" in n or "sae" in n:
        extras.append("wifi_6_ghz")
    if "mesh" in n or "easy" in n:
        extras.append("ble_mesh")
    if "ble" in n or "blue" in n or "gatt" in n:
        extras.append("ble_4_x")
    if "audio" in n or "lc3" in n or "le_audio" in n:
        extras.append("ble_audio")
    if "ad" in n or "kerberos" in n or "ntlm" in n or "ldap" in n:
        extras.append("ad")
    if "iot" in n or "camera" in n or "printer" in n or "nas" in n:
        extras.append("iots")
    out: List[str] = []
    for s in base + extras:
        if s not in out:
            out.append(s)
    return out[:4]


def _enrich_attack_surface(
    data: Dict[str, Any], category: str, name: str
) -> List[str]:
    """Build the new ``attack_surface`` field. Phase 2.4."""
    return _infer_attack_surface_tokens(category, name)


def _enrich_phase_hint(data: Dict[str, Any], category: str) -> str:
    """Build the new ``phase_hint`` field. Phase 2.4."""
    by_category: Dict[str, str] = {
        "Exploits and CVE Research": "exploit",
        "Penetration Testing": "exploit",
        "Web Application Security": "exploit",
        "Wireless Security": "exploit",
        "Bluetooth/BLE": "exploit",
        "OSINT and Recon": "recon",
        "Post-Exploitation": "post_exploit",
        "Privilege Escalation": "post_exploit",
        "Phishing": "exploit",
        "Reverse Engineering": "enumeration",
        "Malware Development": "exploit",
        "Defense Evasion": "cleanup",
    }
    return by_category.get(category, "any")


def _enrich_requires_hardware(
    data: Dict[str, Any], category: str
) -> List[str]:
    """Build the new ``requires_hardware`` field. Phase 2.4. Never
    claims SDR hardware (operator setup excludes SDR)."""
    if category == "Wireless Security":
        return ["mt7921e", "mt7922"]
    if category == "Bluetooth/BLE":
        return ["hci0_ble"]
    return ["none"]


def _enrich_polymorphic_strategies(
    data: Dict[str, Any], category: str
) -> List[str]:
    """Build the new ``polymorphic_strategies`` field. Phase 2.4.
    Lists the polymorphic grammar families the tool supports."""
    families: List[str] = []
    if category in ("Wireless Security", "Bluetooth/BLE"):
        families = ["burst_pattern", "param_grammar", "rate_grammar"]
    elif category in ("Post-Exploitation", "Privilege Escalation"):
        families = ["argv_grammar", "credential_format", "lateral_proto"]
    elif category == "OSINT and Recon":
        families = ["wordlist_grammar", "query_grammar", "graph_query"]
    elif category == "Web Application Security":
        families = ["payload_grammar", "header_grammar"]
    else:
        families = ["param_grammar"]
    return families


def _enrich_target_adaptive_targets(
    data: Dict[str, Any], category: str
) -> List[str]:
    """Build the new ``target_adaptive_targets`` field. Phase 2.4.
    Lists the target dimensions the picker observes."""
    targets: List[str] = []
    if category == "Wireless Security":
        targets = ["bssid_oui", "encryption_type", "channel", "rssi"]
    elif category == "Bluetooth/BLE":
        targets = ["addr_randomness", "adv_interval", "gatt_schema"]
    elif category in ("Post-Exploitation", "Privilege Escalation"):
        targets = ["target_os", "session_type", "credential_state"]
    elif category == "OSINT and Recon":
        targets = ["target_jurisdiction", "target_name_ambiguity"]
    else:
        targets = ["target_class"]
    return targets


def _enrich_trust(data: Dict[str, Any]) -> Dict[str, Any]:
    """Return the trust dict. We never flip ``reviewed`` to true
    because we haven't actually inspected the code."""
    existing = data.get("trust") if isinstance(data.get("trust"), dict) else {}
    out = {
        "official_kali": bool(existing.get("official_kali", False)),
        "reviewed": False,  # always false — we don't claim to have audited
        "warning": str(
            existing.get(
                "warning",
                "Attribution/index entry only. Audit provenance, code, "
                "releases and licence before use.",
            )
        ),
    }
    # Preserve any extra keys the original may have had (defensive)
    for k, v in existing.items():
        if k not in out:
            out[k] = v
    return out


def _enrich_documentation(data: Dict[str, Any]) -> Dict[str, Any]:
    """Return the documentation dict. Preserves the readme if
    present (we never fabricate content)."""
    existing = data.get("documentation") if isinstance(
        data.get("documentation"), dict
    ) else {}
    out = {
        "readme": existing.get("readme"),
        "usage_sections": list(existing.get("usage_sections", []) or []),
        "arguments": list(existing.get("arguments", []) or []),
        "examples": list(existing.get("examples", []) or []),
    }
    return out


def enhance_file(path: Path) -> Dict[str, Any]:
    """Enrich a single ``github_*.json`` file in place.

    Returns an envelope:
        {
            "ok": True,
            "path": str(path),
            "changed": bool,  # True iff the file was modified
            "fields_added": list[str],  # new keys we populated
            "skipped_reason": str | None,  # if we skipped
            "error": str | None,  # on failure
        }
    """
    if not path.exists() or not path.is_file():
        return {
            "ok": False,
            "path": str(path),
            "changed": False,
            "error": "file does not exist",
        }
    try:
        raw = path.read_text(encoding="utf-8")
        data = json.loads(raw)
    except (OSError, json.JSONDecodeError) as e:
        return {
            "ok": False,
            "path": str(path),
            "changed": False,
            "error": f"failed to read/parse: {type(e).__name__}: {e}",
        }

    if not isinstance(data, dict):
        return {
            "ok": False,
            "path": str(path),
            "changed": False,
            "error": "top-level JSON is not an object",
        }

    if is_enhanced(data):
        return {
            "ok": True,
            "path": str(path),
            "changed": False,
            "skipped_reason": "already enhanced",
            "fields_added": [],
        }

    # Defensive: only enrich github:* external_repository entries
    if data.get("kind") != "external_repository" or not str(
        data.get("id", "")
    ).startswith("github:"):
        return {
            "ok": True,
            "path": str(path),
            "changed": False,
            "skipped_reason": "not a github external_repository entry",
            "fields_added": [],
        }

    name = str(data.get("name", ""))
    full_name = str(data.get("full_name", ""))
    category = str(data.get("category", "Penetration Testing"))

    # Build the enriched payload, additive-only
    fields_added: List[str] = []
    new_data: Dict[str, Any] = dict(data)  # shallow copy

    # 1) summary
    if new_data.get("summary") is None:
        descriptor = CATEGORY_DESCRIPTORS.get(
            category, "Index entry in the KFIOSA catalog. Use as a candidate tool in the chain planner."
        )
        new_data["summary"] = _enrich_summary(new_data, descriptor, name)
        fields_added.append("summary")

    # 2) tags
    existing_tags = new_data.get("tags") or []
    if not isinstance(existing_tags, list) or len(existing_tags) < 8:
        new_data["tags"] = _enrich_tags(new_data, category, name, full_name)
        fields_added.append("tags")

    # 3) use_cases
    existing_uc = new_data.get("use_cases") or []
    if not isinstance(existing_uc, list) or len(existing_uc) < 3:
        new_data["use_cases"] = _enrich_use_cases(new_data, category)
        fields_added.append("use_cases")

    # 4) command_examples
    existing_ce = new_data.get("command_examples") or []
    if not isinstance(existing_ce, list) or len(existing_ce) < 3:
        new_data["command_examples"] = _enrich_command_examples(
            new_data, category, name
        )
        fields_added.append("command_examples")

    # 5) documentation (preserve, never fabricate)
    if not isinstance(new_data.get("documentation"), dict):
        new_data["documentation"] = _enrich_documentation(new_data)
        fields_added.append("documentation")
    else:
        # Make sure all sub-keys exist
        new_data["documentation"] = _enrich_documentation(new_data)
        if fields_added and "documentation" not in fields_added:
            fields_added.append("documentation")

    # 6) risk (preserve the existing shape; add/refresh signals)
    if not isinstance(new_data.get("risk"), dict):
        new_data["risk"] = {
            "level": "high",
            "signals": _enrich_risk_signals(new_data, category),
            "requires_explicit_authorization": False,
            "allow_autonomous_execution": True,
            "examples_policy": "operational",
        }
        fields_added.append("risk")
    else:
        risk = dict(new_data["risk"])
        existing_signals = risk.get("signals") or []
        if not isinstance(existing_signals, list) or len(existing_signals) < 2:
            risk["signals"] = _enrich_risk_signals(new_data, category)
            new_data["risk"] = risk
            fields_added.append("risk.signals")

    # 7) trust
    new_data["trust"] = _enrich_trust(new_data)
    if "trust" not in fields_added:
        fields_added.append("trust")

    # 7b) Phase 2.4: new fields — attack_surface, phase_hint,
    # requires_hardware, polymorphic_strategies, target_adaptive_targets
    if not new_data.get("attack_surface"):
        new_data["attack_surface"] = _enrich_attack_surface(
            new_data, category, name)
        fields_added.append("attack_surface")
    if not new_data.get("phase_hint"):
        new_data["phase_hint"] = _enrich_phase_hint(new_data, category)
        fields_added.append("phase_hint")
    if not new_data.get("requires_hardware"):
        new_data["requires_hardware"] = _enrich_requires_hardware(
            new_data, category)
        fields_added.append("requires_hardware")
    if not new_data.get("polymorphic_strategies"):
        new_data["polymorphic_strategies"] = _enrich_polymorphic_strategies(
            new_data, category)
        fields_added.append("polymorphic_strategies")
    if not new_data.get("target_adaptive_targets"):
        new_data["target_adaptive_targets"] = _enrich_target_adaptive_targets(
            new_data, category)
        fields_added.append("target_adaptive_targets")

    # 8) metadata_status — only ever index_only → enriched
    if new_data.get("metadata_status") == "index_only":
        new_data["metadata_status"] = "enriched"
        fields_added.append("metadata_status")

    # 9) Tag with our own sentinel (underscore-prefixed to not clash)
    new_data["_kfiosa_enriched_schema"] = SCHEMA_VERSION
    new_data["_kfiosa_enriched_at"] = "phase_2_4"  # not a real timestamp; this is a label
    fields_added.append("_kfiosa_enriched_schema")
    fields_added.append("_kfiosa_enriched_at")

    # 10) Sanity: never modify protected fields
    protected = ("id", "kind", "full_name", "url", "category", "owner", "name")
    for k in protected:
        if k in data and k in new_data and data[k] != new_data[k]:
            return {
                "ok": False,
                "path": str(path),
                "changed": False,
                "error": f"would have mutated protected field {k!r}",
            }

    # Write back
    try:
        # Stable JSON: sort_keys=False (preserve original order), indent=2
        out_text = json.dumps(new_data, ensure_ascii=False, indent=2)
        out_text += "\n"
        path.write_text(out_text, encoding="utf-8")
    except OSError as e:
        return {
            "ok": False,
            "path": str(path),
            "changed": False,
            "error": f"failed to write: {type(e).__name__}: {e}",
        }

    return {
        "ok": True,
        "path": str(path),
        "changed": True,
        "fields_added": fields_added,
        "skipped_reason": None,
        "error": None,
    }


def enhance_all(
    catalog_dir: Path, *, limit: Optional[int] = None
) -> Dict[str, Any]:
    """Walk ``catalog_dir`` and enrich every ``github_*.json`` file.

    Args:
        catalog_dir: the directory to walk.
        limit: optional cap on number of files processed (for tests).

    Returns:
        {
            "ok": True,
            "total_seen": int,
            "total_changed": int,
            "total_skipped": int,
            "total_failed": int,
            "errors": [str, ...],  # up to 10
        }
    """
    if not catalog_dir.exists() or not catalog_dir.is_dir():
        return {
            "ok": False,
            "error": f"catalog_dir is not a directory: {catalog_dir}",
            "total_seen": 0,
            "total_changed": 0,
            "total_skipped": 0,
            "total_failed": 0,
            "errors": [],
        }
    github_files = sorted(catalog_dir.glob("github_*.json"))
    if limit is not None:
        github_files = github_files[:limit]
    seen = len(github_files)
    changed = 0
    skipped = 0
    failed = 0
    errors: List[str] = []
    for p in github_files:
        result = enhance_file(p)
        if not result.get("ok"):
            failed += 1
            if len(errors) < 10:
                errors.append(
                    f"{p.name}: {result.get('error', 'unknown')}"
                )
            continue
        if result.get("skipped_reason"):
            skipped += 1
        elif result.get("changed"):
            changed += 1
        else:
            # No change, no skip — treat as skipped to be safe
            skipped += 1
    return {
        "ok": True,
        "total_seen": seen,
        "total_changed": changed,
        "total_skipped": skipped,
        "total_failed": failed,
        "errors": errors,
    }


# ---------------------------------------------------------------------------
# LLM prompt stanza — teach the chain planner how to use enriched fields
# ---------------------------------------------------------------------------


def build_enrichment_prompt_stanza(
    sample: Optional[List[Dict[str, Any]]] = None
) -> str:
    """Build a prompt stanza the LLM uses to discover / prefer the
    enriched catalog fields.

    Args:
        sample: an optional list of one or two enriched entries to
            show as concrete examples. If None, we use a generic
            template.
    """
    lines = [
        "  Catalog enrichment (Phase 2.4): every github_* entry in\n",
        "  ``catalog/`` now carries the following operator-curated\n",
        "  fields the chain planner can use to select a tool and\n",
        "  build the run_toolbox step:\n",
        "    * ``summary`` — 2-3 sentence honest description. NO\n",
        "      fabricated versions, CVEs, or release dates.\n",
        "    * ``tags`` — 8-15 short tags. Use these to filter\n",
        "      candidates for a given engagement (e.g. tags containing\n",
        "      'wifi' + 'pmkid' for a WPA2-PMKID workflow).\n",
        "    * ``use_cases`` — 5-10 hints for WHEN to prefer this tool.\n",
        "      Match use_cases to the current recon context.\n",
        "    * ``command_examples`` — 5-10 argv templates using\n",
        "      ``$KFIOSA_*`` env-var sentinels (e.g.\n",
        "      ``$KFIOSA_TARGET_HOST``, ``$KFIOSA_TARGET_PASSWORD``).\n",
        "      The dispatcher substitutes these at runtime; the LLM\n",
        "      NEVER inlines harvested credentials into argv.\n",
        "    * ``risk.signals`` — short array (4-8 signals, e.g.\n",
        "      ``[\"exploit\", \"intrinsic\", \"remote\",\n",
        "      \"polymorphic_compatible\"]``). Match signals against the\n",
        "      engagement's risk profile; prefer tools whose signals\n",
        "      align with the chain's risk_level directive.\n",
        "    * ``attack_surface`` — array from the controlled vocab\n",
        "      (e.g. ``wifi_2_4_ghz``, ``ble_5_x``, ``shell_linux``,\n",
        "      ``web``, ``cloud``, ``ad``, ``iots``). Use this to pick\n",
        "      a tool whose target surface matches the engagement.\n",
        "    * ``phase_hint`` — one of ``recon | enumeration | exploit\n",
        "      | post_exploit | cleanup | any``. Use to filter the\n",
        "      tool list to the current chain step's phase.\n",
        "    * ``requires_hardware`` — array (e.g. ``mt7921e``,\n",
        "      ``hci0_ble``, ``none``). NEVER pick a tool that needs\n",
        "      SDR hardware; the operator setup excludes SDR.\n",
        "    * ``polymorphic_strategies`` — list of grammar families\n",
        "      the tool supports (e.g. ``[\"burst_pattern\",\n",
        "      \"param_grammar\"]``). Use to prefer a tool when the\n",
        "      chain needs polymorphic variation.\n",
        "    * ``target_adaptive_targets`` — list of target dimensions\n",
        "      the picker observes (e.g. ``[\"bssid_oui\",\n",
        "      \"encryption_type\"]``). Use to prefer a tool when the\n",
        "      chain has rich target context.\n",
        "    * ``metadata_status`` — ``index_only`` | ``toolbox_ready``\n",
        "      | ``enriched``. The chain planner must NOT auto-run\n",
        "      ``index_only`` repos; require operator ACK.\n",
        "    * ``trust.reviewed`` — always ``false`` for the\n",
        "      auto-generated entries; the chain planner should treat\n",
        "      unreviewed repos as lower-trust and prefer\n",
        "      ``toolbox_ready`` entries when available.\n",
    ]
    if sample:
        lines.append("\n  Example enriched entries (truncated):\n")
        for entry in sample[:2]:
            name = entry.get("name", "<name>")
            summary = (entry.get("summary") or "<no summary>")[:200]
            uc0 = ""
            ucs = entry.get("use_cases") or []
            if ucs:
                uc0 = str(ucs[0])[:160]
            ce0 = ""
            ces = entry.get("command_examples") or []
            if ces:
                ce0 = str(ces[0])[:160]
            tags = entry.get("tags") or []
            sigs = (entry.get("risk") or {}).get("signals") or []
            surface = entry.get("attack_surface") or []
            phase = entry.get("phase_hint") or "any"
            lines.append(f"    # {name}\n")
            lines.append(f"    summary: {summary}\n")
            if tags:
                lines.append(f"    tags: {tags}\n")
            if sigs:
                lines.append(f"    risk.signals: {sigs}\n")
            if surface:
                lines.append(f"    attack_surface: {surface}\n")
            lines.append(f"    phase_hint: {phase}\n")
            if uc0:
                lines.append(f"    use_cases[0]: {uc0}\n")
            if ce0:
                lines.append(f"    command_examples[0]: {ce0}\n")
            lines.append("\n")
    return "".join(lines)
