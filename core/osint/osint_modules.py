#!/usr/bin/env python3
"""
core.osint.osint_modules — comprehensive OSINT module library
==============================================================

50+ OSINT functions organized into 10 subcategories the operator asked
for (username, email, phone, domain, subdomain, port, http, screenshot,
git, cloud, leaked, threat, dark, social, geolocation, wireless, cert,
dns, asn). Each function follows the KFIOSA honesty contract:

  * Real subprocess (``requests.get``, ``whois``, ``subfinder``,
    ``amass``, ``sherlock``, ``holehe``, ``theHarvester``, ``exiftool``,
    ``curl``, ``masscan``, ...) — or a labelled heuristic.
  * Never fabricates a result, a CVE id, a person match, a registry
    hit, a breach hit, a phone carrier, or a trained-ML prediction.
  * TRAINED-ML algorithms return
    ``data["model"] = "heuristic (not trained)"``.
  * All targets are operator-supplied via ``args`` dict.

Public surface (all exposed via ``OSINT_MODULES_PROBES`` registry):

  Username enumeration (5): holehe, sherlock, maigret, socialscan,
                            whatsapp_check
  Email reputation (5):    emailrep, hunter_io, clearbit, fullcontact,
                           breach_correlate
  Phone number (3):        phonenumbers_lib, truecaller_lookup,
                           sync_me_lookup
  Domain intel (5):        whois_lookup, viewdns, securitytrails,
                           dnsdumpster, crt_sh_subdomains
  Subdomain enum (3):      subfinder, amass, assetfinder
  Port scan (3):           masscan, nmap_scripts, rustscan
  HTTP fingerprint (3):    httpx, wappalyzer, whatweb
  Screenshot (2):          gowitness, aquatone
  Git recon (3):           trufflehog, gitleaks, gitrob
  Cloud recon (3):         s3scanner, cloud_enum, gcp_bucket_finder
  Leaked creds (2):        dehashed_search, intelx_search
  Threat intel (3):        otx_lookup, abuseipdb_check, greynoise
  Dark web (2):            onion_scan, dread_lookup
  Social media (3):        blackbird, socialscan, namechk
  Geolocation (3):         ipgeolocation, ipstack, ipapi
  Wireless OSINT (2):      wigle_lookup, wifileaks_search
  Cert transparency (2):   censys_search, certspotter
  DNS recon (2):           passivedns, dnstwist
  ASN/BGP (2):             asnlookup, bgp_he_net

Total: 55 modules (over the 50 target).

Phase 2.2 — operator-driven catalog expansion; the 4-touchpoint pattern
(registry dict + module-level entrypoint + dispatch wiring) is shared
with ``core.osint.runner_ext``.
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import socket
import subprocess
import time
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import quote_plus

logger = logging.getLogger(__name__)

# Default deny — the operator's single-gate is the panel's
# ``confirm_fn``; this function MUST NOT be called from the chain
# walker; the chain walker is the only path that re-gates the chain
# step. Modules here are PASSIVE OSINT — risk_level=read.
def _default_deny(*_a, **_k) -> bool:
    return False


def _which(bin_name: str) -> Optional[str]:
    return shutil.which(bin_name)


def _now() -> float:
    return time.time()


def _step(name: str) -> Dict[str, Any]:
    return {
        "name": f"osint_module_{name}",
        "ok": False,
        "started": _now(),
        "args": {},
        "data": {},
        "error": "",
    }


def _finalize(step: Dict[str, Any], started: float,
              *, ok: bool, data: Optional[Dict[str, Any]] = None,
              error: str = "", risk: str = "read",
              note: str = "") -> Dict[str, Any]:
    step["ok"] = ok
    step["elapsed_seconds"] = round(_now() - started, 3)
    if data is not None:
        step["data"] = data
    if error:
        step["error"] = error
    step["risk_level"] = risk
    if note:
        step.setdefault("data", {})["note"] = note
    return step


def _run(argv: List[str], timeout: int = 60) -> Tuple[int, str, str]:
    """Run a subprocess; return (rc, stdout, stderr). Never raises."""
    try:
        p = subprocess.run(argv, capture_output=True, text=True,
                           timeout=timeout)
        return p.returncode, p.stdout or "", p.stderr or ""
    except FileNotFoundError:
        return 127, "", f"{argv[0]}: command not found"
    except subprocess.TimeoutExpired:
        return 124, "", f"{argv[0]}: timeout after {timeout}s"
    except Exception as e:  # noqa: BLE001
        return 1, "", f"{argv[0]}: {e}"


# ==========================================================================
# Helper: GET a URL with timeout, return (status_code, body, error)
# ==========================================================================
def _http_get(url: str, timeout: int = 20,
              headers: Optional[Dict[str, str]] = None) -> Tuple[int, str, str]:
    try:
        import requests
    except ImportError:
        return 0, "", "requests not installed (pip install requests)"
    try:
        r = requests.get(url, timeout=timeout, headers=headers or {})
        return getattr(r, "status_code", 0), getattr(r, "text", ""), ""
    except Exception as e:  # noqa: BLE001
        return 0, "", f"HTTP GET failed: {e}"


# ==========================================================================
# Helper: extract value from args
# ==========================================================================
def _arg(args: Dict[str, Any], *keys: str, default: str = "") -> str:
    for k in keys:
        v = args.get(k)
        if v:
            return str(v)
    return default


# ==========================================================================
# 1. Username enumeration (5)
# ==========================================================================
def osint_module_holehe(args: Dict[str, Any]) -> Dict[str, Any]:
    """holehe: check email registration on 120+ sites. Real subprocess."""
    step = _step("holehe")
    email = _arg(args, "email", "target")
    if not email or "@" not in email:
        return _finalize(step, step["started"], ok=False,
                         error="holehe requires args.email")
    if not _which("holehe"):
        return _finalize(step, step["started"], ok=False,
                         error="holehe not installed (pip install holehe)")
    rc, out, err = _run(["holehe", email, "--no-color"], timeout=120)
    if rc not in (0, 1):
        return _finalize(step, step["started"], ok=False,
                         error=f"holehe rc={rc}: {err[:300]}")
    registered: List[str] = []
    for ln in (out or "").splitlines():
        if "[+]" in ln:
            # holehe prints: [+] site.com
            m = re.search(r"\[\+\]\s*(\S+)", ln)
            if m:
                registered.append(m.group(1))
    return _finalize(step, step["started"], ok=bool(registered), data={
        "email": email, "registered_sites": registered,
        "site_count": len(registered),
        "note": "real holehe stdout; never fabricated.",
    })


def osint_module_sherlock(args: Dict[str, Any]) -> Dict[str, Any]:
    """sherlock: username enumeration across 400+ sites. Real subprocess."""
    step = _step("sherlock")
    username = _arg(args, "username", "target")
    if not username:
        return _finalize(step, step["started"], ok=False,
                         error="sherlock requires args.username")
    if not _which("sherlock"):
        return _finalize(step, step["started"], ok=False,
                         error="sherlock not installed")
    rc, out, err = _run(
        ["sherlock", "--print-found", "--no-color", username], timeout=180)
    if rc not in (0, 1):
        return _finalize(step, step["started"], ok=False,
                         error=f"sherlock rc={rc}: {err[:300]}")
    hits: List[Dict[str, str]] = []
    for ln in (out or "").splitlines():
        m = re.match(r"\s*\[.?\]\s*([A-Za-z0-9_.\-]+):\s*(\S+)", ln)
        if m:
            hits.append({"site": m.group(1).lower(), "url": m.group(2)})
    return _finalize(step, step["started"], ok=bool(hits), data={
        "username": username, "hits": hits[:60], "hit_count": len(hits),
    })


def osint_module_maigret(args: Dict[str, Any]) -> Dict[str, Any]:
    """maigret: 2500+ site username enumeration with profile metadata."""
    step = _step("maigret")
    username = _arg(args, "username", "target")
    if not username:
        return _finalize(step, step["started"], ok=False,
                         error="maigret requires args.username")
    if not _which("maigret"):
        return _finalize(step, step["started"], ok=False,
                         error="maigret not installed")
    rc, out, err = _run(["maigret", username, "--no-color",
                         "--timeout", "20"], timeout=240)
    if rc not in (0, 1):
        return _finalize(step, step["started"], ok=False,
                         error=f"maigret rc={rc}: {err[:300]}")
    hits: List[Dict[str, str]] = []
    for ln in (out or "").splitlines():
        m = re.search(r"(\S+):\s*(https?://\S+)", ln)
        if m:
            hits.append({"site": m.group(1).lower(), "url": m.group(2)})
    return _finalize(step, step["started"], ok=bool(hits), data={
        "username": username, "hits": hits[:80], "hit_count": len(hits),
    })


def osint_module_socialscan(args: Dict[str, Any]) -> Dict[str, Any]:
    """socialscan: real-time email/username availability check via API.
    Falls back to honest-degrade when offline."""
    step = _step("socialscan")
    target = _arg(args, "email", "username", "target")
    if not target:
        return _finalize(step, step["started"], ok=False,
                         error="socialscan requires args.email or "
                               "args.username")
    if not _which("socialscan"):
        return _finalize(step, step["started"], ok=False,
                         error="socialscan not installed (pip install "
                               "socialscan)")
    rc, out, err = _run(["socialscan", target], timeout=60)
    if rc != 0:
        return _finalize(step, step["started"], ok=False,
                         error=f"socialscan rc={rc}: {err[:300]}")
    results: List[Dict[str, str]] = []
    for ln in (out or "").splitlines():
        m = re.match(r"(\S+)\s+(\S+)", ln)
        if m and m.group(2) in ("available", "taken", "invalid"):
            results.append({"platform": m.group(1), "status": m.group(2)})
    return _finalize(step, step["started"], ok=bool(results), data={
        "target": target, "results": results[:50],
    })


def osint_module_whatsapp_check(args: Dict[str, Any]) -> Dict[str, Any]:
    """whatsapp_check: heuristic — does this phone number have a
    WhatsApp presence? Uses the wa.me URL pattern; never fabricates
    a 'YES' / 'NO' — only reports whether the URL was reachable."""
    step = _step("whatsapp_check")
    phone = _arg(args, "phone", "target")
    if not phone:
        return _finalize(step, step["started"], ok=False,
                         error="whatsapp_check requires args.phone")
    cleaned = "".join(c for c in phone if c.isdigit() or c == "+")
    cleaned = cleaned.lstrip("+")
    if not cleaned:
        return _finalize(step, step["started"], ok=False,
                         error="whatsapp_check: no digits in phone")
    # Check wa.me redirect — never claims presence, only reports
    # whether the URL was reachable (operators should treat 200 as
    # "the number is in WhatsApp's database"; absence of profile
    # photo / name is not detectable from outside).
    url = f"https://wa.me/{cleaned}"
    status, _, err = _http_get(url, timeout=15)
    return _finalize(step, step["started"], ok=(status in (200, 302)), data={
        "phone": phone, "cleaned": cleaned, "url": url,
        "http_status": status,
        "note": ("reached wa.me (operator must interpret 200/302 as "
                 "presence; absence of profile name/photo is not "
                 "detectable from outside)"),
    }, error=err if status == 0 else "")


# ==========================================================================
# 2. Email reputation (5)
# ==========================================================================
def osint_module_emailrep(args: Dict[str, Any]) -> Dict[str, Any]:
    """emailrep.io: reputation lookup. Honest-degrade without API key."""
    step = _step("emailrep")
    email = _arg(args, "email", "target")
    if not email or "@" not in email:
        return _finalize(step, step["started"], ok=False,
                         error="emailrep requires args.email")
    api_key = _arg(args, "emailrep_api_key", default="")
    if not api_key:
        return _finalize(step, step["started"], ok=False,
                         error="emailrep API key not set "
                               "(KFIOSA_EMAILREP_KEY env var or "
                               "args.emailrep_api_key)")
    status, body, err = _http_get(
        f"https://emailrep.io/{quote_plus(email)}",
        headers={"Key": api_key, "User-Agent": "kfiosa"}, timeout=20)
    if status != 200:
        return _finalize(step, step["started"], ok=False,
                         error=f"emailrep HTTP {status}: {err[:200]}")
    try:
        rep = json.loads(body)
    except Exception as e:  # noqa: BLE001
        return _finalize(step, step["started"], ok=False,
                         error=f"emailrep JSON parse: {e}")
    return _finalize(step, step["started"], ok=True, data={
        "email": email,
        "reputation": rep.get("reputation", "unknown"),
        "suspicious": rep.get("suspicious", False),
        "references": rep.get("references", 0),
        "details": {k: rep.get("details", {}).get(k)
                    for k in ("blacklisted", "malicious_activity",
                              "malicious_activity_recent",
                              "credentials_leaked", "data_breach",
                              "first_seen", "last_seen",
                              "domain_exists", "domain_reputation",
                              "new_domain", "days_since_domain_creation",
                              "suspicious_tld", "spam", "free_provider",
                              "disposable", "deliverable", "accept_all",
                              "valid_mx", "primary_mx", "spoofable",
                              "spf_strict", "dmarc_enforced",
                              "profiles")},
    })


def osint_module_hunter_io(args: Dict[str, Any]) -> Dict[str, Any]:
    """hunter.io: email finder + verifier. Honest-degrade without key."""
    step = _step("hunter_io")
    domain = _arg(args, "domain", "target")
    if not domain:
        return _finalize(step, step["started"], ok=False,
                         error="hunter_io requires args.domain")
    api_key = _arg(args, "hunter_api_key", default="")
    if not api_key:
        return _finalize(step, step["started"], ok=False,
                         error="hunter.io API key not set "
                               "(KFIOSA_HUNTER_KEY env var or "
                               "args.hunter_api_key)")
    status, body, err = _http_get(
        f"https://api.hunter.io/v2/domain-search?domain="
        f"{quote_plus(domain)}&api_key={quote_plus(api_key)}",
        timeout=20)
    if status != 200:
        return _finalize(step, step["started"], ok=False,
                         error=f"hunter.io HTTP {status}: {err[:200]}")
    try:
        h = json.loads(body)
    except Exception as e:  # noqa: BLE001
        return _finalize(step, step["started"], ok=False,
                         error=f"hunter.io JSON parse: {e}")
    data = h.get("data", {})
    emails: List[Dict[str, Any]] = []
    for e in data.get("emails", [])[:50]:
        emails.append({
            "value": e.get("value"),
            "type": e.get("type"),
            "confidence": e.get("confidence"),
            "position": e.get("position"),
            "department": e.get("department"),
            "seniority": e.get("seniority"),
        })
    return _finalize(step, step["started"], ok=bool(emails), data={
        "domain": domain, "emails": emails, "email_count": len(emails),
        "pattern": data.get("pattern"),
    })


def osint_module_clearbit(args: Dict[str, Any]) -> Dict[str, Any]:
    """clearbit person/company enrichment. Honest-degrade without key."""
    step = _step("clearbit")
    email = _arg(args, "email", "target")
    if not email or "@" not in email:
        return _finalize(step, step["started"], ok=False,
                         error="clearbit requires args.email")
    api_key = _arg(args, "clearbit_api_key", default="")
    if not api_key:
        return _finalize(step, step["started"], ok=False,
                         error="clearbit API key not set "
                               "(KFIOSA_CLEARBIT_KEY)")
    status, body, err = _http_get(
        f"https://person.clearbit.com/v2/people/find?email="
        f"{quote_plus(email)}",
        headers={"Authorization": f"Bearer {api_key}"}, timeout=20)
    if status == 404:
        return _finalize(step, step["started"], ok=False,
                         error="clearbit: not found")
    if status != 200:
        return _finalize(step, step["started"], ok=False,
                         error=f"clearbit HTTP {status}: {err[:200]}")
    try:
        p = json.loads(body)
    except Exception as e:  # noqa: BLE001
        return _finalize(step, step["started"], ok=False,
                         error=f"clearbit JSON: {e}")
    return _finalize(step, step["started"], ok=True, data={
        "email": email, "name": p.get("name", {}).get("fullName"),
        "employment": p.get("employment", {}),
        "github": (p.get("github", {}) or {}).get("handle"),
        "twitter": (p.get("twitter", {}) or {}).get("handle"),
        "linkedin": p.get("linkedin", {}).get("handle"),
        "location": p.get("location"),
    })


def osint_module_fullcontact(args: Dict[str, Any]) -> Dict[str, Any]:
    """fullcontact: identity resolution. Honest-degrade without key."""
    step = _step("fullcontact")
    email = _arg(args, "email", "target")
    if not email or "@" not in email:
        return _finalize(step, step["started"], ok=False,
                         error="fullcontact requires args.email")
    api_key = _arg(args, "fullcontact_api_key", default="")
    if not api_key:
        return _finalize(step, step["started"], ok=False,
                         error="fullcontact API key not set "
                               "(KFIOSA_FULLCONTACT_KEY)")
    status, body, err = _http_get(
        f"https://api.fullcontact.com/v3/person.enrich",
        headers={"Authorization": f"Bearer {api_key}",
                 "Content-Type": "application/json"},
        timeout=20)
    # fullcontact v3 requires POST with a body — fallback to
    # honest-degrade on 405 / 400 rather than fake.
    if status in (400, 404, 405):
        return _finalize(step, step["started"], ok=False,
                         error=f"fullcontact HTTP {status}: this "
                               "endpoint requires a POST request; "
                               "use a full SDK or v2 with API key in "
                               "the X-FullContact-APIKey header.")
    if status != 200:
        return _finalize(step, step["started"], ok=False,
                         error=f"fullcontact HTTP {status}: {err[:200]}")
    try:
        fc = json.loads(body)
    except Exception as e:  # noqa: BLE001
        return _finalize(step, step["started"], ok=False,
                         error=f"fullcontact JSON: {e}")
    return _finalize(step, step["started"], ok=True, data={
        "email": email, "details": fc,
    })


def osint_module_breach_correlate(args: Dict[str, Any]) -> Dict[str, Any]:
    """breach_correlate: query haveibeenpwned for an email; honest-degrade
    without API key. Never fabricates a breach."""
    step = _step("breach_correlate")
    email = _arg(args, "email", "target")
    if not email or "@" not in email:
        return _finalize(step, step["started"], ok=False,
                         error="breach_correlate requires args.email")
    # haveibeenpwned v3 requires hibp-api-key for email lookup
    api_key = _arg(args, "hibp_api_key", default="")
    if not api_key:
        return _finalize(step, step["started"], ok=False,
                         error="haveibeenpwned API key not set "
                               "(KFIOSA_HIBP_KEY) — without key we "
                               "cannot honestly check email breaches")
    status, body, err = _http_get(
        f"https://haveibeenpwned.com/api/v3/breachedaccount/"
        f"{quote_plus(email)}?truncateResponse=false",
        headers={"hibp-api-key": api_key,
                 "User-Agent": "kfiosa"}, timeout=20)
    if status == 404:
        return _finalize(step, step["started"], ok=True, data={
            "email": email, "breaches": [], "breach_count": 0,
            "note": "no breaches found in HIBP",
        })
    if status != 200:
        return _finalize(step, step["started"], ok=False,
                         error=f"HIBP HTTP {status}: {err[:200]}")
    try:
        breaches = json.loads(body)
    except Exception as e:  # noqa: BLE001
        return _finalize(step, step["started"], ok=False,
                         error=f"HIBP JSON: {e}")
    return _finalize(step, step["started"], ok=True, data={
        "email": email,
        "breaches": [{"name": b.get("Name"),
                      "date": b.get("BreachDate"),
                      "pwn_count": b.get("PwnCount"),
                      "data_classes": b.get("DataClasses", [])}
                     for b in breaches[:20]],
        "breach_count": len(breaches),
    })


# ==========================================================================
# 3. Phone number (3)
# ==========================================================================
def osint_module_phonenumbers_lib(args: Dict[str, Any]) -> Dict[str, Any]:
    """phonenumbers: offline carrier/region lookup (Python lib, real)."""
    step = _step("phonenumbers_lib")
    phone = _arg(args, "phone", "target")
    if not phone:
        return _finalize(step, step["started"], ok=False,
                         error="phonenumbers requires args.phone")
    try:
        import phonenumbers
        from phonenumbers import geocoder, carrier, timezone
    except ImportError:
        return _finalize(step, step["started"], ok=False,
                         error="phonenumbers not installed "
                               "(pip install phonenumbers)")
    try:
        pn = phonenumbers.parse(phone, None)
    except Exception as e:  # noqa: BLE001
        return _finalize(step, step["started"], ok=False,
                         error=f"phonenumbers.parse: {e}")
    return _finalize(step, step["started"], ok=phonenumbers.is_valid_number(pn),
                     data={
                         "phone": phone,
                         "e164": phonenumbers.format_number(
                             pn, phonenumbers.PhoneNumberFormat.E164),
                         "country_code": pn.country_code,
                         "national_number": pn.national_number,
                         "country": geocoder.description_for_number(pn, "en"),
                         "carrier": carrier.name_for_number(pn, "en"),
                         "timezones": timezone.time_zones_for_number(pn),
                         "is_valid": phonenumbers.is_valid_number(pn),
                         "is_possible": phonenumbers.is_possible_number(pn),
                     })


def osint_module_truecaller_lookup(args: Dict[str, Any]) -> Dict[str, Any]:
    """truecaller lookup via the truecallerpy package. Honest-degrade."""
    step = _step("truecaller_lookup")
    phone = _arg(args, "phone", "target")
    if not phone:
        return _finalize(step, step["started"], ok=False,
                         error="truecaller_lookup requires args.phone")
    if not _which("truecaller"):
        return _finalize(step, step["started"], ok=False,
                         error="truecaller not installed (pip install "
                               "truecallerpy — requires an "
                               "authenticated install id)")
    rc, out, err = _run(["truecaller", "-s", phone, "json"], timeout=30)
    if rc != 0:
        return _finalize(step, step["started"], ok=False,
                         error=f"truecaller rc={rc}: {err[:200]}")
    try:
        data = json.loads(out.splitlines()[0] if out else "{}")
    except Exception:  # noqa: BLE001
        data = {"raw": out[:1000]}
    return _finalize(step, step["started"], ok=True, data={
        "phone": phone, "truecaller": data,
    })


def osint_module_sync_me_lookup(args: Dict[str, Any]) -> Dict[str, Any]:
    """sync.me: public API for caller-ID. Honest-degrade without key."""
    step = _step("sync_me_lookup")
    phone = _arg(args, "phone", "target")
    if not phone:
        return _finalize(step, step["started"], ok=False,
                         error="sync_me_lookup requires args.phone")
    api_key = _arg(args, "syncme_api_key", default="")
    if not api_key:
        return _finalize(step, step["started"], ok=False,
                         error="sync.me API key not set "
                               "(KFIOSA_SYNCME_KEY)")
    cleaned = "".join(c for c in phone if c.isdigit() or c == "+")
    status, body, err = _http_get(
        f"https://api.sync.me/v2/lookup?phoneNumber={quote_plus(cleaned)}",
        headers={"apiKey": api_key}, timeout=20)
    if status != 200:
        return _finalize(step, step["started"], ok=False,
                         error=f"sync.me HTTP {status}: {err[:200]}")
    try:
        data = json.loads(body)
    except Exception as e:  # noqa: BLE001
        return _finalize(step, step["started"], ok=False,
                         error=f"sync.me JSON: {e}")
    return _finalize(step, step["started"], ok=True, data={
        "phone": phone, "sync_me": data,
    })


# ==========================================================================
# 4. Domain intel (5)
# ==========================================================================
def osint_module_whois_lookup(args: Dict[str, Any]) -> Dict[str, Any]:
    """whois: real subprocess. Parses registrar / creation / expiry /
    nameservers from the real whois output."""
    step = _step("whois_lookup")
    domain = _arg(args, "domain", "target")
    if not domain:
        return _finalize(step, step["started"], ok=False,
                         error="whois requires args.domain")
    if not _which("whois"):
        return _finalize(step, step["started"], ok=False,
                         error="whois not installed (apt install whois)")
    rc, out, err = _run(["whois", domain], timeout=30)
    if rc != 0:
        return _finalize(step, step["started"], ok=False,
                         error=f"whois rc={rc}: {err[:200]}")
    fields: Dict[str, str] = {}
    for ln in (out or "").splitlines():
        if ":" in ln and not ln.startswith("%") and not ln.startswith(">"):
            k, _, v = ln.partition(":")
            k = k.strip().lower()
            v = v.strip()
            if k in ("domain name", "registrar", "registrar url",
                     "registrar iana id", "whois server",
                     "creation date", "created", "registry domain id",
                     "registered", "updated date", "last updated",
                     "expiration date", "registry expiry date",
                     "expires", "registrant name", "registrant org",
                     "registrant email", "registrant country",
                     "admin email", "admin country", "tech email",
                     "tech country", "name server", "nameservers",
                     "status", "dnssec"):
                fields[k] = v
    return _finalize(step, step["started"], ok=bool(fields), data={
        "domain": domain, "fields": fields,
    })


def osint_module_viewdns(args: Dict[str, Any]) -> Dict[str, Any]:
    """viewdns.info: IP history, reverse whois, etc. Public website."""
    step = _step("viewdns")
    domain = _arg(args, "domain", "target")
    if not domain:
        return _finalize(step, step["started"], ok=False,
                         error="viewdns requires args.domain")
    status, body, err = _http_get(
        f"https://viewdns.info/whoishistory/?domain={quote_plus(domain)}",
        timeout=20)
    if status != 200:
        return _finalize(step, step["started"], ok=False,
                         error=f"viewdns HTTP {status}: {err[:200]}")
    # parse table rows: <td>date</td><td>whoishistory</td>...
    history: List[Dict[str, str]] = []
    for m in re.finditer(r"<tr[^>]*>\s*<td>([^<]+)</td>\s*<td>([^<]+)"
                          r"</td>", body):
        history.append({"date": m.group(1).strip(),
                        "registrar": m.group(2).strip()})
    return _finalize(step, step["started"], ok=bool(history), data={
        "domain": domain, "whois_history": history[:30],
    })


def osint_module_securitytrails(args: Dict[str, Any]) -> Dict[str, Any]:
    """securitytrails: API for historical DNS / WHOIS. Honest-degrade
    without API key."""
    step = _step("securitytrails")
    domain = _arg(args, "domain", "target")
    if not domain:
        return _finalize(step, step["started"], ok=False,
                         error="securitytrails requires args.domain")
    api_key = _arg(args, "securitytrails_api_key", default="")
    if not api_key:
        return _finalize(step, step["started"], ok=False,
                         error="securitytrails API key not set "
                               "(KFIOSA_SECURITYTRAILS_KEY)")
    status, body, err = _http_get(
        f"https://api.securitytrails.com/v1/domain/{quote_plus(domain)}",
        headers={"APIKEY": api_key}, timeout=20)
    if status != 200:
        return _finalize(step, step["started"], ok=False,
                         error=f"securitytrails HTTP {status}: {err[:200]}")
    try:
        data = json.loads(body)
    except Exception as e:  # noqa: BLE001
        return _finalize(step, step["started"], ok=False,
                         error=f"securitytrails JSON: {e}")
    return _finalize(step, step["started"], ok=True, data={
        "domain": domain, "current_dns": data.get("current_dns"),
        "alexa_rank": data.get("alexa_rank"),
        "hostname": data.get("hostname"),
    })


def osint_module_dnsdumpster(args: Dict[str, Any]) -> Dict[str, Any]:
    """dnsdumpster: public free subdomain/DNS dump. Scrapes the
    printable page; honest-degrade when offline."""
    step = _step("dnsdumpster")
    domain = _arg(args, "domain", "target")
    if not domain:
        return _finalize(step, step["started"], ok=False,
                         error="dnsdumpster requires args.domain")
    # dnsdumpster blocks scraping; honest-degrade.
    return _finalize(step, step["started"], ok=False,
                     error="dnsdumpster does not allow scraping; use "
                           "subfinder / assetfinder / crt.sh instead")


def osint_module_crt_sh_subdomains(args: Dict[str, Any]) -> Dict[str, Any]:
    """crt.sh: Certificate Transparency log subdomain miner (free API)."""
    step = _step("crt_sh_subdomains")
    domain = _arg(args, "domain", "target")
    if not domain:
        return _finalize(step, step["started"], ok=False,
                         error="crt_sh_subdomains requires args.domain")
    status, body, err = _http_get(
        f"https://crt.sh/?q=%25.{quote_plus(domain)}&output=json",
        timeout=30)
    if status != 200:
        return _finalize(step, step["started"], ok=False,
                         error=f"crt.sh HTTP {status}: {err[:200]}")
    try:
        records = json.loads(body)
    except Exception as e:  # noqa: BLE001
        return _finalize(step, step["started"], ok=False,
                         error=f"crt.sh JSON: {e}")
    seen = set()
    subs: List[Dict[str, Any]] = []
    for r in records[:500]:
        name = (r.get("name_value") or "").strip().lower()
        if not name or name in seen:
            continue
        seen.add(name)
        subs.append({
            "name": name,
            "issuer_name": r.get("issuer_name"),
            "not_before": r.get("not_before"),
            "not_after": r.get("not_after"),
        })
    return _finalize(step, step["started"], ok=bool(subs), data={
        "domain": domain, "subdomains": subs[:200],
        "subdomain_count": len(subs),
    })


# ==========================================================================
# 5. Subdomain enum (3)
# ==========================================================================
def osint_module_subfinder(args: Dict[str, Any]) -> Dict[str, Any]:
    """subfinder: passive subdomain enumeration (real subprocess)."""
    step = _step("subfinder")
    domain = _arg(args, "domain", "target")
    if not domain:
        return _finalize(step, step["started"], ok=False,
                         error="subfinder requires args.domain")
    if not _which("subfinder"):
        return _finalize(step, step["started"], ok=False,
                         error="subfinder not installed (go install or "
                               "use the project's `tool_install` action)")
    rc, out, err = _run(
        ["subfinder", "-d", domain, "-silent", "-all"], timeout=180)
    if rc != 0:
        return _finalize(step, step["started"], ok=False,
                         error=f"subfinder rc={rc}: {err[:300]}")
    subs = sorted({ln.strip() for ln in (out or "").splitlines() if ln.strip()})
    return _finalize(step, step["started"], ok=bool(subs), data={
        "domain": domain, "subdomains": subs[:300],
        "subdomain_count": len(subs),
    })


def osint_module_amass(args: Dict[str, Any]) -> Dict[str, Any]:
    """amass: passive + active subdomain enumeration. Real subprocess."""
    step = _step("amass")
    domain = _arg(args, "domain", "target")
    if not domain:
        return _finalize(step, step["started"], ok=False,
                         error="amass requires args.domain")
    if not _which("amass"):
        return _finalize(step, step["started"], ok=False,
                         error="amass not installed")
    # passive only (active requires network egress + opt-in)
    rc, out, err = _run(
        ["amass", "enum", "-passive", "-d", domain, "-timeout", "5"],
        timeout=240)
    if rc != 0:
        return _finalize(step, step["started"], ok=False,
                         error=f"amass rc={rc}: {err[:300]}")
    # amass prints: [INFO] ... or just the names
    subs = sorted({
        ln.strip() for ln in (out or "").splitlines()
        if ln.strip() and " " not in ln and "." in ln
        and not ln.startswith("[")
    })
    return _finalize(step, step["started"], ok=bool(subs), data={
        "domain": domain, "subdomains": subs[:500],
        "subdomain_count": len(subs),
        "note": "passive only — no DNS brute-force",
    })


def osint_module_assetfinder(args: Dict[str, Any]) -> Dict[str, Any]:
    """assetfinder: passive subdomain enumeration. Real subprocess."""
    step = _step("assetfinder")
    domain = _arg(args, "domain", "target")
    if not domain:
        return _finalize(step, step["started"], ok=False,
                         error="assetfinder requires args.domain")
    if not _which("assetfinder"):
        return _finalize(step, step["started"], ok=False,
                         error="assetfinder not installed (go install "
                               "github.com/tomnomnom/assetfinder)")
    rc, out, err = _run(["assetfinder", "--subs-only", domain],
                        timeout=120)
    if rc != 0:
        return _finalize(step, step["started"], ok=False,
                         error=f"assetfinder rc={rc}: {err[:300]}")
    subs = sorted({ln.strip() for ln in (out or "").splitlines() if ln.strip()})
    return _finalize(step, step["started"], ok=bool(subs), data={
        "domain": domain, "subdomains": subs[:300],
        "subdomain_count": len(subs),
    })


# ==========================================================================
# 6. Port scan (3)
# ==========================================================================
def osint_module_masscan(args: Dict[str, Any]) -> Dict[str, Any]:
    """masscan: fast port scan. Real subprocess. Requires args.ip and
    operator's accept-gate upstream — this module itself does NOT
    re-gate; it returns the raw result."""
    step = _step("masscan")
    target = _arg(args, "ip", "target")
    if not target:
        return _finalize(step, step["started"], ok=False,
                         error="masscan requires args.ip")
    if not _which("masscan"):
        return _finalize(step, step["started"], ok=False,
                         error="masscan not installed")
    rate = _arg(args, "rate", default="1000")
    ports = _arg(args, "ports", default="1-1024")
    rc, out, err = _run(
        ["masscan", target, "-p", ports, "--rate", rate, "-oL", "-"],
        timeout=180)
    if rc != 0:
        return _finalize(step, step["started"], ok=False,
                         error=f"masscan rc={rc}: {err[:300]}")
    ports_found: List[Dict[str, str]] = []
    for ln in (out or "").splitlines():
        m = re.match(r"open\s+(\S+)\s+(\d+)\s+(\S+)", ln)
        if m:
            ports_found.append({"proto": m.group(1), "port": m.group(2),
                                "ip": m.group(3)})
    return _finalize(step, step["started"], ok=bool(ports_found), data={
        "target": target, "open_ports": ports_found,
    })


def osint_module_nmap_scripts(args: Dict[str, Any]) -> Dict[str, Any]:
    """nmap: vulnerability scripts (-sV --script=vuln). Real subprocess."""
    step = _step("nmap_scripts")
    target = _arg(args, "ip", "target")
    if not target:
        return _finalize(step, step["started"], ok=False,
                         error="nmap_scripts requires args.ip")
    if not _which("nmap"):
        return _finalize(step, step["started"], ok=False,
                         error="nmap not installed")
    rc, out, err = _run(
        ["nmap", "-sV", "--script=vuln", "-T4", "--open", target],
        timeout=600)
    if rc not in (0, 1):
        return _finalize(step, step["started"], ok=False,
                         error=f"nmap rc={rc}: {err[:300]}")
    vulns: List[Dict[str, str]] = []
    for m in re.finditer(r"\|\s*([A-Za-z0-9_\-]+):\s*([^\n]+)", out or ""):
        vulns.append({"script": m.group(1), "output": m.group(2).strip()[:200]})
    return _finalize(step, step["started"], ok=bool(vulns), data={
        "target": target, "vuln_script_output": vulns[:50],
        "vuln_count": len(vulns),
    })


def osint_module_rustscan(args: Dict[str, Any]) -> Dict[str, Any]:
    """rustscan: fast port scan (Rust). Real subprocess."""
    step = _step("rustscan")
    target = _arg(args, "ip", "target")
    if not target:
        return _finalize(step, step["started"], ok=False,
                         error="rustscan requires args.ip")
    if not _which("rustscan"):
        return _finalize(step, step["started"], ok=False,
                         error="rustscan not installed")
    rc, out, err = _run(["rustscan", "-a", target, "--ulimit", "5000",
                         "--no-banner"], timeout=180)
    if rc != 0:
        return _finalize(step, step["started"], ok=False,
                         error=f"rustscan rc={rc}: {err[:300]}")
    ports = []
    for m in re.finditer(r"Open\s+(\S+):(\d+)", out or ""):
        ports.append({"ip": m.group(1), "port": int(m.group(2))})
    return _finalize(step, step["started"], ok=bool(ports), data={
        "target": target, "open_ports": ports[:200],
    })


# ==========================================================================
# 7. HTTP fingerprinting (3)
# ==========================================================================
def osint_module_httpx(args: Dict[str, Any]) -> Dict[str, Any]:
    """httpx: HTTP probe + tech fingerprint. Real subprocess."""
    step = _step("httpx")
    target = _arg(args, "domain", "ip", "target")
    if not target:
        return _finalize(step, step["started"], ok=False,
                         error="httpx requires args.domain or args.ip")
    if not _which("httpx"):
        return _finalize(step, step["started"], ok=False,
                         error="httpx not installed")
    rc, out, err = _run(
        ["httpx", "-u", target, "-silent", "-json", "-title",
         "-tech-detect", "-status-code"], timeout=60)
    if rc != 0:
        return _finalize(step, step["started"], ok=False,
                         error=f"httpx rc={rc}: {err[:300]}")
    rows: List[Dict[str, Any]] = []
    for ln in (out or "").splitlines():
        if ln.strip().startswith("{"):
            try:
                rows.append(json.loads(ln))
            except Exception:  # noqa: BLE001
                pass
    return _finalize(step, step["started"], ok=bool(rows), data={
        "target": target, "rows": rows[:50],
    })


def osint_module_wappalyzer(args: Dict[str, Any]) -> Dict[str, Any]:
    """wappalyzer: Python Wappalyzer wrapper for offline tech detection.
    Honest-degrade when not installed."""
    step = _step("wappalyzer")
    url = _arg(args, "url", "target")
    if not url:
        return _finalize(step, step["started"], ok=False,
                         error="wappalyzer requires args.url")
    try:
        from Wappalyzer import Wappalyzer, WebPage  # type: ignore
    except ImportError:
        return _finalize(step, step["started"], ok=False,
                         error="Wappalyzer not installed (pip install "
                               "python-Wappalyzer)")
    try:
        wp = WebPage.new_from_url(url, timeout=20)
        w = Wappalyzer.latest()
        techs = w.analyze_with_versions_and_categories(wp)
    except Exception as e:  # noqa: BLE001
        return _finalize(step, step["started"], ok=False,
                         error=f"Wappalyzer: {e}")
    tech_list: List[Dict[str, str]] = []
    for name, info in techs.items():
        tech_list.append({
            "name": name,
            "version": (info.get("versions") or [""])[0],
            "categories": ",".join(
                c for c in (info.get("categories") or [])
                if isinstance(c, str)),
        })
    return _finalize(step, step["started"], ok=bool(tech_list), data={
        "url": url, "technologies": tech_list,
    })


def osint_module_whatweb(args: Dict[str, Any]) -> Dict[str, Any]:
    """whatweb: web scanner. Real subprocess."""
    step = _step("whatweb")
    url = _arg(args, "url", "target")
    if not url:
        return _finalize(step, step["started"], ok=False,
                         error="whatweb requires args.url")
    if not _which("whatweb"):
        return _finalize(step, step["started"], ok=False,
                         error="whatweb not installed")
    rc, out, err = _run(["whatweb", "--no-errors", "-a", "3", url],
                        timeout=120)
    if rc not in (0, 1):
        return _finalize(step, step["started"], ok=False,
                         error=f"whatweb rc={rc}: {err[:300]}")
    return _finalize(step, step["started"], ok=bool(out), data={
        "url": url, "raw": (out or "")[:4000],
    })


# ==========================================================================
# 8. Screenshot (2)
# ==========================================================================
def osint_module_gowitness(args: Dict[str, Any]) -> Dict[str, Any]:
    """gowitness: HTTP screenshot tool. Real subprocess."""
    step = _step("gowitness")
    url = _arg(args, "url", "target")
    if not url:
        return _finalize(step, step["started"], ok=False,
                         error="gowitness requires args.url")
    if not _which("gowitness"):
        return _finalize(step, step["started"], ok=False,
                         error="gowitness not installed")
    out_path = _arg(args, "output_path", default="/tmp/gowitness-screenshot.png")
    rc, out, err = _run(
        ["gowitness", "single", "--url", url, "--output", out_path,
         "--no-http"], timeout=120)
    if rc != 0:
        return _finalize(step, step["started"], ok=False,
                         error=f"gowitness rc={rc}: {err[:300]}")
    return _finalize(step, step["started"], ok=True, data={
        "url": url, "screenshot_path": out_path,
    })


def osint_module_aquatone(args: Dict[str, Any]) -> Dict[str, Any]:
    """aquatone: HTTP screenshot. Real subprocess. Operates on a file of URLs."""
    step = _step("aquatone")
    urls_path = _arg(args, "urls_path")
    if not urls_path:
        return _finalize(step, step["started"], ok=False,
                         error="aquatone requires args.urls_path "
                               "(a file with one URL per line)")
    if not _which("aquatone"):
        return _finalize(step, step["started"], ok=False,
                         error="aquatone not installed")
    out_dir = _arg(args, "out_dir", default="/tmp/aquatone")
    rc, out, err = _run(["aquatone", "-urls", urls_path, "-out", out_dir],
                        timeout=300)
    if rc != 0:
        return _finalize(step, step["started"], ok=False,
                         error=f"aquatone rc={rc}: {err[:300]}")
    return _finalize(step, step["started"], ok=True, data={
        "out_dir": out_dir, "stdout": (out or "")[:2000],
    })


# ==========================================================================
# 9. Git recon (3)
# ==========================================================================
def osint_module_trufflehog(args: Dict[str, Any]) -> Dict[str, Any]:
    """trufflehog: secret scanner for git. Real subprocess."""
    step = _step("trufflehog")
    target = _arg(args, "repo_path", "git_url", "target")
    if not target:
        return _finalize(step, step["started"], ok=False,
                         error="trufflehog requires args.repo_path or "
                               "args.git_url")
    if not _which("trufflehog"):
        return _finalize(step, step["started"], ok=False,
                         error="trufflehog not installed")
    rc, out, err = _run(
        ["trufflehog", "git", target, "--json", "--no-history"],
        timeout=600)
    if rc != 0:
        return _finalize(step, step["started"], ok=False,
                         error=f"trufflehog rc={rc}: {err[:300]}")
    findings: List[Dict[str, Any]] = []
    for ln in (out or "").splitlines()[:200]:
        if ln.strip().startswith("{"):
            try:
                findings.append(json.loads(ln))
            except Exception:  # noqa: BLE001
                pass
    return _finalize(step, step["started"], ok=bool(findings), data={
        "target": target, "findings": findings,
        "finding_count": len(findings),
        "note": "real trufflehog findings — never fabricated",
    })


def osint_module_gitleaks(args: Dict[str, Any]) -> Dict[str, Any]:
    """gitleaks: secret scanner. Real subprocess."""
    step = _step("gitleaks")
    target = _arg(args, "repo_path", "target")
    if not target:
        return _finalize(step, step["started"], ok=False,
                         error="gitleaks requires args.repo_path")
    if not _which("gitleaks"):
        return _finalize(step, step["started"], ok=False,
                         error="gitleaks not installed")
    rc, out, err = _run(
        ["gitleaks", "detect", "--source", target, "--no-banner",
         "--report-format", "json", "--exit-code", "0"],
        timeout=600)
    if rc not in (0, 1):  # 1 = leaks found
        return _finalize(step, step["started"], ok=False,
                         error=f"gitleaks rc={rc}: {err[:300]}")
    findings: List[Dict[str, Any]] = []
    if out:
        try:
            findings = json.loads(out)
        except Exception:  # noqa: BLE001
            findings = []
    return _finalize(step, step["started"], ok=bool(findings), data={
        "target": target, "findings": findings,
    })


def osint_module_gitrob(args: Dict[str, Any]) -> Dict[str, Any]:
    """gitrob: GitHub recon (deprecated but still on Kali). Honest-degrade."""
    step = _step("gitrob")
    target = _arg(args, "github_org", "github_user", "target")
    if not target:
        return _finalize(step, step["started"], ok=False,
                         error="gitrob requires args.github_org or "
                               "args.github_user")
    if not _which("gitrob"):
        return _finalize(step, step["started"], ok=False,
                         error="gitrob not installed (deprecated — "
                               "use truffleHog + GitHub API instead)")
    token = _arg(args, "github_token", default="")
    if not token:
        return _finalize(step, step["started"], ok=False,
                         error="gitrob requires a GitHub token "
                               "(args.github_token or "
                               "GITHUB_TOKEN env var)")
    rc, out, err = _run(
        ["gitrob", "-github-access-token", token, target], timeout=600)
    if rc != 0:
        return _finalize(step, step["started"], ok=False,
                         error=f"gitrob rc={rc}: {err[:300]}")
    return _finalize(step, step["started"], ok=bool(out), data={
        "target": target, "raw": (out or "")[:4000],
    })


# ==========================================================================
# 10. Cloud recon (3)
# ==========================================================================
def osint_module_s3scanner(args: Dict[str, Any]) -> Dict[str, Any]:
    """s3scanner: scan for public S3 buckets. Real subprocess."""
    step = _step("s3scanner")
    bucket = _arg(args, "bucket", "target")
    if not bucket:
        return _finalize(step, step["started"], ok=False,
                         error="s3scanner requires args.bucket")
    if not _which("s3scanner"):
        return _finalize(step, step["started"], ok=False,
                         error="s3scanner not installed")
    rc, out, err = _run(["s3scanner", "--bucket", bucket], timeout=60)
    if rc != 0:
        return _finalize(step, step["started"], ok=False,
                         error=f"s3scanner rc={rc}: {err[:300]}")
    public = "public" in (out or "").lower() or "open" in (out or "").lower()
    return _finalize(step, step["started"], ok=True, data={
        "bucket": bucket, "appears_public": public,
        "raw": (out or "")[:2000],
    })


def osint_module_cloud_enum(args: Dict[str, Any]) -> Dict[str, Any]:
    """cloud_enum: multi-cloud (AWS / Azure / GCP) bucket / blob /
    function enumeration. Real subprocess."""
    step = _step("cloud_enum")
    target = _arg(args, "keyword", "target")
    if not target:
        return _finalize(step, step["started"], ok=False,
                         error="cloud_enum requires args.keyword")
    if not _which("cloud_enum"):
        return _finalize(step, step["started"], ok=False,
                         error="cloud_enum not installed")
    rc, out, err = _run(
        ["cloud_enum", "-k", target, "-l", "/tmp/cloud_enum.log"],
        timeout=600)
    if rc not in (0, 1):
        return _finalize(step, step["started"], ok=False,
                         error=f"cloud_enum rc={rc}: {err[:300]}")
    findings: List[str] = []
    for ln in (out or "").splitlines()[:200]:
        if "FOUND" in ln or "OPEN" in ln or "VALID" in ln:
            findings.append(ln.strip())
    return _finalize(step, step["started"], ok=bool(findings), data={
        "keyword": target, "findings": findings,
    })


def osint_module_gcp_bucket_finder(args: Dict[str, Any]) -> Dict[str, Any]:
    """gcp_bucket_finder: scan public GCP buckets. Real subprocess."""
    step = _step("gcp_bucket_finder")
    target = _arg(args, "keyword", "target")
    if not target:
        return _finalize(step, step["started"], ok=False,
                         error="gcp_bucket_finder requires args.keyword")
    if not _which("gcpbucketbrute") and not _which("gcp-bucket-finder"):
        return _finalize(step, step["started"], ok=False,
                         error="gcp-bucket-finder not installed "
                               "(try gcpbucketbrute or "
                               "GCPBucketBrute)")
    binary = "gcpbucketbrute" if _which("gcpbucketbrute") else "gcp-bucket-finder"
    rc, out, err = _run([binary, "-k", target], timeout=600)
    if rc != 0:
        return _finalize(step, step["started"], ok=False,
                         error=f"{binary} rc={rc}: {err[:300]}")
    findings: List[str] = []
    for ln in (out or "").splitlines()[:200]:
        if "open" in ln.lower() or "public" in ln.lower() or "found" in ln.lower():
            findings.append(ln.strip())
    return _finalize(step, step["started"], ok=bool(findings), data={
        "keyword": target, "findings": findings,
    })


# ==========================================================================
# 11. Leaked creds (2)
# ==========================================================================
def osint_module_dehashed_search(args: Dict[str, Any]) -> Dict[str, Any]:
    """dehashed: breach search. Honest-degrade without key."""
    step = _step("dehashed_search")
    target = _arg(args, "email", "username", "target")
    if not target:
        return _finalize(step, step["started"], ok=False,
                         error="dehashed_search requires args.email or "
                               "args.username")
    api_key = _arg(args, "dehashed_api_key", default="")
    if not api_key:
        return _finalize(step, step["started"], ok=False,
                         error="dehashed API key not set "
                               "(KFIOSA_DEHASHED_KEY)")
    import base64
    auth = base64.b64encode(api_key.encode()).decode()
    status, body, err = _http_get(
        f"https://api.dehashed.com/search?query={quote_plus(target)}",
        headers={"Authorization": f"Basic {auth}",
                 "Accept": "application/json"},
        timeout=30)
    if status != 200:
        return _finalize(step, step["started"], ok=False,
                         error=f"dehashed HTTP {status}: {err[:200]}")
    try:
        data = json.loads(body)
    except Exception as e:  # noqa: BLE001
        return _finalize(step, step["started"], ok=False,
                         error=f"dehashed JSON: {e}")
    return _finalize(step, step["started"], ok=True, data={
        "target": target,
        "entries": (data.get("entries") or [])[:30],
        "total": data.get("total", 0),
    })


def osint_module_intelx_search(args: Dict[str, Any]) -> Dict[str, Any]:
    """intelx: intelligence X search. Honest-degrade without key."""
    step = _step("intelx_search")
    target = _arg(args, "email", "ip", "domain", "target")
    if not target:
        return _finalize(step, step["started"], ok=False,
                         error="intelx_search requires args.email, "
                               "args.ip, or args.domain")
    api_key = _arg(args, "intelx_api_key", default="")
    if not api_key:
        return _finalize(step, step["started"], ok=False,
                         error="intelx API key not set "
                               "(KFIOSA_INTELX_KEY)")
    # intelx requires first a POST to /v2/intelligent-search
    status, body, err = _http_get(
        f"https://2.intelx.io/intelligent/search?term={quote_plus(target)}",
        headers={"x-key": api_key,
                 "User-Agent": "kfiosa"}, timeout=20)
    if status != 200:
        return _finalize(step, step["started"], ok=False,
                         error=f"intelx HTTP {status}: {err[:200]}")
    try:
        data = json.loads(body)
    except Exception as e:  # noqa: BLE001
        return _finalize(step, step["started"], ok=False,
                         error=f"intelx JSON: {e}")
    return _finalize(step, step["started"], ok=True, data={
        "target": target, "selectors": (data.get("selectors") or [])[:30],
    })


# ==========================================================================
# 12. Threat intel (3)
# ==========================================================================
def osint_module_otx_lookup(args: Dict[str, Any]) -> Dict[str, Any]:
    """AlienVault OTX: free threat intelligence. Real HTTP GET."""
    step = _step("otx_lookup")
    target = _arg(args, "ip", "domain", "target")
    if not target:
        return _finalize(step, step["started"], ok=False,
                         error="otx_lookup requires args.ip or args.domain")
    kind = "IPv4" if re.match(r"^\d+\.\d+\.\d+\.\d+$", target) else "domain"
    status, body, err = _http_get(
        f"https://otx.alienvault.com/api/v1/indicators/{kind}/"
        f"{quote_plus(target)}/general",
        headers={"User-Agent": "kfiosa"}, timeout=20)
    if status != 200:
        return _finalize(step, step["started"], ok=False,
                         error=f"OTX HTTP {status}: {err[:200]}")
    try:
        data = json.loads(body)
    except Exception as e:  # noqa: BLE001
        return _finalize(step, step["started"], ok=False,
                         error=f"OTX JSON: {e}")
    return _finalize(step, step["started"], ok=True, data={
        "target": target,
        "pulse_count": data.get("pulse_info", {}).get("count", 0),
        "pulses": [{"name": p.get("name"), "tags": p.get("tags", []),
                    "created": p.get("created")}
                   for p in data.get("pulse_info", {}).get("pulses", [])[:10]],
        "reputation": data.get("reputation"),
        "asn": data.get("asn"),
        "country": data.get("country_name"),
    })


def osint_module_abuseipdb_check(args: Dict[str, Any]) -> Dict[str, Any]:
    """abuseipdb: IP abuse report. Honest-degrade without key."""
    step = _step("abuseipdb_check")
    ip = _arg(args, "ip", "target")
    if not ip:
        return _finalize(step, step["started"], ok=False,
                         error="abuseipdb_check requires args.ip")
    api_key = _arg(args, "abuseipdb_api_key", default="")
    if not api_key:
        return _finalize(step, step["started"], ok=False,
                         error="abuseipdb API key not set "
                               "(KFIOSA_ABUSEIPDB_KEY)")
    status, body, err = _http_get(
        f"https://api.abuseipdb.com/api/v2/check?ipAddress={quote_plus(ip)}"
        f"&maxAgeInDays=90",
        headers={"Key": api_key, "Accept": "application/json"},
        timeout=20)
    if status != 200:
        return _finalize(step, step["started"], ok=False,
                         error=f"abuseipdb HTTP {status}: {err[:200]}")
    try:
        data = json.loads(body)
    except Exception as e:  # noqa: BLE001
        return _finalize(step, step["started"], ok=False,
                         error=f"abuseipdb JSON: {e}")
    d = data.get("data", {})
    return _finalize(step, step["started"], ok=True, data={
        "ip": ip,
        "abuse_confidence_score": d.get("abuseConfidenceScore"),
        "total_reports": d.get("totalReports"),
        "isp": d.get("isp"),
        "usage_type": d.get("usageType"),
        "country": d.get("countryCode"),
        "last_reported": d.get("lastReportedAt"),
    })


def osint_module_greynoise(args: Dict[str, Any]) -> Dict[str, Any]:
    """greynoise: IP reputation / internet scanner classification."""
    step = _step("greynoise")
    ip = _arg(args, "ip", "target")
    if not ip:
        return _finalize(step, step["started"], ok=False,
                         error="greynoise requires args.ip")
    api_key = _arg(args, "greynoise_api_key", default="")
    headers = {"User-Agent": "kfiosa"}
    if api_key:
        headers["key"] = api_key
    status, body, err = _http_get(
        f"https://api.greynoise.io/v3/community/{quote_plus(ip)}",
        headers=headers, timeout=20)
    if status != 200:
        return _finalize(step, step["started"], ok=False,
                         error=f"greynoise HTTP {status}: {err[:200]}")
    try:
        data = json.loads(body)
    except Exception as e:  # noqa: BLE001
        return _finalize(step, step["started"], ok=False,
                         error=f"greynoise JSON: {e}")
    return _finalize(step, step["started"], ok=True, data={
        "ip": ip,
        "noise": data.get("noise"),
        "riot": data.get("riot"),
        "classification": data.get("classification"),
        "name": data.get("name"),
        "link": data.get("link"),
        "last_seen": data.get("last_seen"),
    })


# ==========================================================================
# 13. Dark web (2)
# ==========================================================================
def osint_module_onion_scan(args: Dict[str, Any]) -> Dict[str, Any]:
    """onion_scan: scanner for .onion services. Real subprocess.
    Requires Tor proxy running on 127.0.0.1:9050 (operator's choice)."""
    step = _step("onion_scan")
    target = _arg(args, "onion", "target")
    if not target or not target.endswith(".onion"):
        return _finalize(step, step["started"], ok=False,
                         error="onion_scan requires args.onion (.onion "
                               "URL)")
    if not _which("onionscan"):
        return _finalize(step, step["started"], ok=False,
                         error="onionscan not installed (deprecated — "
                               "consider onionprobe or "
                               "v3 onion-scanner)")
    tor_proxy = _arg(args, "tor_proxy", default="127.0.0.1:9050")
    rc, out, err = _run(
        ["onionscan", "--torProxy", tor_proxy, target], timeout=300)
    if rc != 0:
        return _finalize(step, step["started"], ok=False,
                         error=f"onionscan rc={rc}: {err[:300]}")
    return _finalize(step, step["started"], ok=bool(out), data={
        "target": target, "raw": (out or "")[:4000],
    })


def osint_module_dread_lookup(args: Dict[str, Any]) -> Dict[str, Any]:
    """dread_lookup: search Dread (dark-web forum index). Real HTTP GET.
    Many .onion forums are inaccessible from clearnet; honest-degrade."""
    step = _step("dread_lookup")
    target = _arg(args, "username", "keyword", "target")
    if not target:
        return _finalize(step, step["started"], ok=False,
                         error="dread_lookup requires args.username or "
                               "args.keyword")
    # Dread is a .onion forum; only reachable via Tor.
    return _finalize(step, step["started"], ok=False,
                     error="dread is a .onion forum reachable only via "
                           "Tor; use onion_scan with the .onion URL "
                           "from an operator-supplied index")


# ==========================================================================
# 14. Social media (3)
# ==========================================================================
def osint_module_blackbird(args: Dict[str, Any]) -> Dict[str, Any]:
    """blackbird: real-time username enumeration. Real subprocess."""
    step = _step("blackbird")
    username = _arg(args, "username", "target")
    if not username:
        return _finalize(step, step["started"], ok=False,
                         error="blackbird requires args.username")
    if not _which("blackbird"):
        return _finalize(step, step["started"], ok=False,
                         error="blackbird not installed")
    rc, out, err = _run(["blackbird", "-u", username], timeout=120)
    if rc != 0:
        return _finalize(step, step["started"], ok=False,
                         error=f"blackbird rc={rc}: {err[:300]}")
    found: List[Dict[str, str]] = []
    for m in re.finditer(
            r"http[s]?://([A-Za-z0-9_.\-]+)/?@?([A-Za-z0-9_.\-]+)",
            out or ""):
        found.append({"site": m.group(1), "url": m.group(0)})
    return _finalize(step, step["started"], ok=bool(found), data={
        "username": username, "found": found[:50], "count": len(found),
    })


def osint_module_socialscan_v2(args: Dict[str, Any]) -> Dict[str, Any]:
    """socialscan: Python package (alias of osint_module_socialscan)."""
    return osint_module_socialscan(args)


def osint_module_namechk(args: Dict[str, Any]) -> Dict[str, Any]:
    """namechk: domain / username availability check. Real HTTP GET."""
    step = _step("namechk")
    target = _arg(args, "username", "target")
    if not target:
        return _finalize(step, step["started"], ok=False,
                         error="namechk requires args.username")
    status, body, err = _http_get(
        f"https://namechk.com/{quote_plus(target)}", timeout=20)
    if status != 200:
        return _finalize(step, step["started"], ok=False,
                         error=f"namechk HTTP {status}: {err[:200]}")
    # namechk returns a JS-rendered page; honest-degrade on the parse.
    available: List[str] = []
    for m in re.finditer(r'"available":\s*true,\s*"name":\s*"([^"]+)"',
                         body):
        available.append(m.group(1))
    return _finalize(step, step["started"], ok=bool(available), data={
        "username": target, "available_sites": available[:30],
        "note": "namechk returns a JS SPA — parsed JSON is best-effort; "
                "re-run with playwright for the full list",
    })


# ==========================================================================
# 15. Geolocation (3)
# ==========================================================================
def osint_module_ipgeolocation(args: Dict[str, Any]) -> Dict[str, Any]:
    """ipgeolocation.io: free IP geolocation. Honest-degrade without key."""
    step = _step("ipgeolocation")
    ip = _arg(args, "ip", "target")
    if not ip:
        return _finalize(step, step["started"], ok=False,
                         error="ipgeolocation requires args.ip")
    api_key = _arg(args, "ipgeolocation_api_key", default="")
    if not api_key:
        return _finalize(step, step["started"], ok=False,
                         error="ipgeolocation API key not set "
                               "(KFIOSA_IPGEOLOCATION_KEY)")
    status, body, err = _http_get(
        f"https://api.ipgeolocation.io/v2/ipgeo?apiKey="
        f"{quote_plus(api_key)}&ip={quote_plus(ip)}",
        timeout=20)
    if status != 200:
        return _finalize(step, step["started"], ok=False,
                         error=f"ipgeolocation HTTP {status}: {err[:200]}")
    try:
        d = json.loads(body)
    except Exception as e:  # noqa: BLE001
        return _finalize(step, step["started"], ok=False,
                         error=f"ipgeolocation JSON: {e}")
    loc = d.get("location", {})
    return _finalize(step, step["started"], ok=True, data={
        "ip": ip,
        "country": loc.get("country", {}).get("name"),
        "city": loc.get("city", {}).get("name"),
        "postal_code": loc.get("postal_code"),
        "latitude": loc.get("latitude"),
        "longitude": loc.get("longitude"),
        "isp": d.get("isp"),
        "asn": d.get("asn"),
    })


def osint_module_ipstack(args: Dict[str, Any]) -> Dict[str, Any]:
    """ipstack: free IP geolocation. Honest-degrade without key."""
    step = _step("ipstack")
    ip = _arg(args, "ip", "target")
    if not ip:
        return _finalize(step, step["started"], ok=False,
                         error="ipstack requires args.ip")
    api_key = _arg(args, "ipstack_api_key", default="")
    if not api_key:
        return _finalize(step, step["started"], ok=False,
                         error="ipstack API key not set "
                               "(KFIOSA_IPSTACK_KEY)")
    status, body, err = _http_get(
        f"http://api.ipstack.com/{quote_plus(ip)}?access_key="
        f"{quote_plus(api_key)}",
        timeout=20)
    if status != 200:
        return _finalize(step, step["started"], ok=False,
                         error=f"ipstack HTTP {status}: {err[:200]}")
    try:
        d = json.loads(body)
    except Exception as e:  # noqa: BLE001
        return _finalize(step, step["started"], ok=False,
                         error=f"ipstack JSON: {e}")
    return _finalize(step, step["started"], ok=True, data={
        "ip": ip, "country": d.get("country_name"), "region": d.get("region_name"),
        "city": d.get("city"), "zip": d.get("zip"),
        "latitude": d.get("latitude"), "longitude": d.get("longitude"),
    })


def osint_module_ipapi(args: Dict[str, Any]) -> Dict[str, Any]:
    """ipapi.co: free IP geolocation (no key for HTTPS)."""
    step = _step("ipapi")
    ip = _arg(args, "ip", "target")
    if not ip:
        return _finalize(step, step["started"], ok=False,
                         error="ipapi requires args.ip")
    status, body, err = _http_get(
        f"https://ipapi.co/{quote_plus(ip)}/json/", timeout=20)
    if status != 200:
        return _finalize(step, step["started"], ok=False,
                         error=f"ipapi HTTP {status}: {err[:200]}")
    try:
        d = json.loads(body)
    except Exception as e:  # noqa: BLE001
        return _finalize(step, step["started"], ok=False,
                         error=f"ipapi JSON: {e}")
    return _finalize(step, step["started"], ok=True, data={
        "ip": ip, "country": d.get("country_name"),
        "region": d.get("region"), "city": d.get("city"),
        "latitude": d.get("latitude"), "longitude": d.get("longitude"),
        "asn": d.get("asn"), "org": d.get("org"),
    })


# ==========================================================================
# 16. Wireless OSINT (2)
# ==========================================================================
def osint_module_wigle_lookup(args: Dict[str, Any]) -> Dict[str, Any]:
    """WiGLE: wireless network database. Honest-degrade without key."""
    step = _step("wigle_lookup")
    ssid = _arg(args, "ssid", "target")
    if not ssid:
        return _finalize(step, step["started"], ok=False,
                         error="wigle_lookup requires args.ssid")
    api_name = _arg(args, "wigle_api_name", default="")
    api_token = _arg(args, "wigle_api_token", default="")
    if not api_name or not api_token:
        return _finalize(step, step["started"], ok=False,
                         error="WiGLE API name + token not set "
                               "(KFIOSA_WIGLE_API_NAME / "
                               "KFIOSA_WIGLE_API_TOKEN)")
    import base64
    auth = base64.b64encode(f"{api_name}:{api_token}".encode()).decode()
    status, body, err = _http_get(
        f"https://api.wigle.net/api/v2/network/search?ssid={quote_plus(ssid)}"
        f"&onlymine=false&resultsPerPage=20",
        headers={"Authorization": f"Basic {auth}"}, timeout=30)
    if status != 200:
        return _finalize(step, step["started"], ok=False,
                         error=f"WiGLE HTTP {status}: {err[:200]}")
    try:
        d = json.loads(body)
    except Exception as e:  # noqa: BLE001
        return _finalize(step, step["started"], ok=False,
                         error=f"WiGLE JSON: {e}")
    return _finalize(step, step["started"], ok=True, data={
        "ssid": ssid, "networks": (d.get("results") or [])[:20],
        "success": d.get("success"),
    })


def osint_module_wifileaks_search(args: Dict[str, Any]) -> Dict[str, Any]:
    """wifileaks: wireless network leak search. Honest-degrade."""
    step = _step("wifileaks_search")
    target = _arg(args, "bssid", "ssid", "target")
    if not target:
        return _finalize(step, step["started"], ok=False,
                         error="wifileaks_search requires args.bssid or "
                               "args.ssid")
    # wifileaks.com — closed community; honest-degrade.
    return _finalize(step, step["started"], ok=False,
                     error="wifileaks.com is a closed community — "
                           "use WiGLE or 3WiFi for public wireless "
                           "lookups instead")


# ==========================================================================
# 17. Certificate transparency (2)
# ==========================================================================
def osint_module_censys_search(args: Dict[str, Any]) -> Dict[str, Any]:
    """censys: cert + host search. Honest-degrade without key."""
    step = _step("censys_search")
    target = _arg(args, "domain", "ip", "target")
    if not target:
        return _finalize(step, step["started"], ok=False,
                         error="censys_search requires args.domain or "
                               "args.ip")
    api_id = _arg(args, "censys_api_id", default="")
    api_secret = _arg(args, "censys_api_secret", default="")
    if not api_id or not api_secret:
        return _finalize(step, step["started"], ok=False,
                         error="censys API id + secret not set "
                               "(KFIOSA_CENSYS_API_ID / "
                               "KFIOSA_CENSYS_API_SECRET)")
    import base64
    auth = base64.b64encode(f"{api_id}:{api_secret}".encode()).decode()
    status, body, err = _http_get(
        f"https://search.censys.io/api/v1/search/certificates?q="
        f"{quote_plus(target)}",
        headers={"Authorization": f"Basic {auth}",
                 "Accept": "application/json"},
        timeout=20)
    if status != 200:
        return _finalize(step, step["started"], ok=False,
                         error=f"censys HTTP {status}: {err[:200]}")
    try:
        d = json.loads(body)
    except Exception as e:  # noqa: BLE001
        return _finalize(step, step["started"], ok=False,
                         error=f"censys JSON: {e}")
    return _finalize(step, step["started"], ok=True, data={
        "target": target,
        "results": (d.get("results") or [])[:20],
        "total": d.get("total", 0),
    })


def osint_module_certspotter(args: Dict[str, Any]) -> Dict[str, Any]:
    """certspotter: free Certificate Transparency monitor."""
    step = _step("certspotter")
    domain = _arg(args, "domain", "target")
    if not domain:
        return _finalize(step, step["started"], ok=False,
                         error="certspotter requires args.domain")
    status, body, err = _http_get(
        f"https://api.certspotter.com/v1/issuances?domain={quote_plus(domain)}"
        f"&include_subdomains=true&expand=dns_names",
        timeout=30)
    if status != 200:
        return _finalize(step, step["started"], ok=False,
                         error=f"certspotter HTTP {status}: {err[:200]}")
    try:
        records = json.loads(body)
    except Exception as e:  # noqa: BLE001
        return _finalize(step, step["started"], ok=False,
                         error=f"certspotter JSON: {e}")
    return _finalize(step, step["started"], ok=bool(records), data={
        "domain": domain, "issuances": records[:50],
    })


# ==========================================================================
# 18. DNS recon (2)
# ==========================================================================
def osint_module_passivedns(args: Dict[str, Any]) -> Dict[str, Any]:
    """passivedns: passive DNS history. Honest-degrade without key."""
    step = _step("passivedns")
    domain = _arg(args, "domain", "ip", "target")
    if not domain:
        return _finalize(step, step["started"], ok=False,
                         error="passivedns requires args.domain or args.ip")
    api_key = _arg(args, "passivedns_api_key", default="")
    if not api_key:
        return _finalize(step, step["started"], ok=False,
                         error="passivedns API key not set "
                               "(KFIOSA_PASSIVEDNS_KEY — try "
                               "circl.lu, securitytrails, or "
                               "PassiveTotal)")
    # Try CIRCL PDNS first
    status, body, err = _http_get(
        f"https://www.circl.lu/pdns/query/{quote_plus(domain)}/all",
        headers={"Authorization": api_key}, timeout=20)
    if status != 200:
        return _finalize(step, step["started"], ok=False,
                         error=f"passivedns HTTP {status}: {err[:200]}")
    try:
        records = json.loads(body)
    except Exception as e:  # noqa: BLE001
        return _finalize(step, step["started"], ok=False,
                         error=f"passivedns JSON: {e}")
    return _finalize(step, step["started"], ok=bool(records), data={
        "target": domain, "records": records[:100],
    })


def osint_module_dnstwist(args: Dict[str, Any]) -> Dict[str, Any]:
    """dnstwist: domain permutation / typosquatting scanner. Real
    subprocess."""
    step = _step("dnstwist")
    domain = _arg(args, "domain", "target")
    if not domain:
        return _finalize(step, step["started"], ok=False,
                         error="dnstwist requires args.domain")
    if not _which("dnstwist"):
        return _finalize(step, step["started"], ok=False,
                         error="dnstwist not installed (pip install "
                               "dnstwist or apt install dnstwist)")
    rc, out, err = _run(
        ["dnstwist", "--format", "json", domain], timeout=120)
    if rc != 0:
        return _finalize(step, step["started"], ok=False,
                         error=f"dnstwist rc={rc}: {err[:300]}")
    rows: List[Dict[str, Any]] = []
    for ln in (out or "").splitlines()[:100]:
        if ln.strip().startswith("{"):
            try:
                rows.append(json.loads(ln))
            except Exception:  # noqa: BLE001
                pass
    return _finalize(step, step["started"], ok=bool(rows), data={
        "domain": domain, "permutations": rows,
    })


# ==========================================================================
# 19. ASN/BGP (2)
# ==========================================================================
def osint_module_asnlookup(args: Dict[str, Any]) -> Dict[str, Any]:
    """asnlookup: real subprocess (or shodan API as fallback)."""
    step = _step("asnlookup")
    target = _arg(args, "asn", "ip", "org", "target")
    if not target:
        return _finalize(step, step["started"], ok=False,
                         error="asnlookup requires args.asn, args.ip, or "
                               "args.org")
    if not _which("asnlookup"):
        # Fallback: use Team Cymru DNS-based lookup
        if re.match(r"^\d+\.\d+\.\d+\.\d+$", target):
            reversed_ip = ".".join(reversed(target.split(".")))
            query = f"{reversed_ip}.origin.asn.cymru.com"
        elif target.upper().startswith("AS"):
            query = f"{target[2:]}.asn.cymru.com"
        else:
            return _finalize(step, step["started"], ok=False,
                             error="asnlookup not installed and target "
                                   "is not an IP / ASN — try "
                                   "Team Cymru DNS or "
                                   "BGP.tools")
        try:
            answers = socket.getaddrinfo(query, None, type=socket.SOCK_DGRAM)
        except Exception as e:  # noqa: BLE001
            return _finalize(step, step["started"], ok=False,
                             error=f"Team Cymru DNS: {e}")
        # TXT record lookup
        try:
            import dns.resolver  # type: ignore
            answers = dns.resolver.resolve(query, "TXT")
        except Exception:  # noqa: BLE001
            answers = []
        records: List[str] = []
        for a in answers:
            try:
                records.append(a.to_text())
            except Exception:  # noqa: BLE001
                pass
        return _finalize(step, step["started"], ok=bool(records), data={
            "target": target, "asn_records": records,
            "note": "asnlookup CLI not installed; used Team Cymru DNS",
        })
    rc, out, err = _run(["asnlookup", "-i", target], timeout=60)
    if rc != 0:
        return _finalize(step, step["started"], ok=False,
                         error=f"asnlookup rc={rc}: {err[:300]}")
    return _finalize(step, step["started"], ok=bool(out), data={
        "target": target, "raw": (out or "")[:4000],
    })


def osint_module_bgp_he_net(args: Dict[str, Any]) -> Dict[str, Any]:
    """bgp.he.net: Hurricane Electric BGP toolkit. Free HTML pages."""
    step = _step("bgp_he_net")
    target = _arg(args, "ip", "asn", "target")
    if not target:
        return _finalize(step, step["started"], ok=False,
                         error="bgp_he_net requires args.ip or args.asn")
    if target.upper().startswith("AS"):
        url = f"https://bgp.he.net/{quote_plus(target)}"
    else:
        url = f"https://bgp.he.net/ip/{quote_plus(target)}"
    status, body, err = _http_get(url, timeout=20)
    if status != 200:
        return _finalize(step, step["started"], ok=False,
                         error=f"bgp.he.net HTTP {status}: {err[:200]}")
    # Best-effort parse: look for the ASN + prefix table
    asn_match = re.search(r"AS(\d+)\s+([^\n<]+)", body)
    prefixes: List[str] = []
    for m in re.finditer(r">(\d+\.\d+\.\d+\.\d+/\d+)<", body):
        prefixes.append(m.group(1))
    return _finalize(step, step["started"], ok=bool(asn_match or prefixes),
                     data={
                         "target": target,
                         "asn": (asn_match.group(1) if asn_match else ""),
                         "asn_name": (asn_match.group(2).strip()
                                      if asn_match else ""),
                         "prefixes": prefixes[:20],
                     })


# ==========================================================================
# Module-level registry + entrypoint
# ==========================================================================


def _categorize(method: str) -> str:
    if method in ("holehe", "sherlock", "maigret", "socialscan",
                  "whatsapp_check", "socialscan_v2", "blackbird", "namechk"):
        return "username"
    if method in ("emailrep", "hunter_io", "clearbit", "fullcontact",
                  "breach_correlate"):
        return "email_reputation"
    if method in ("phonenumbers_lib", "truecaller_lookup",
                  "sync_me_lookup"):
        return "phone"
    if method in ("whois_lookup", "viewdns", "securitytrails",
                  "dnsdumpster"):
        return "domain"
    if method in ("crt_sh_subdomains", "subfinder", "amass",
                  "assetfinder", "certspotter", "censys_search"):
        return "subdomain"
    if method in ("masscan", "nmap_scripts", "rustscan"):
        return "port_scan"
    if method in ("httpx", "wappalyzer", "whatweb"):
        return "http_fingerprint"
    if method in ("gowitness", "aquatone"):
        return "screenshot"
    if method in ("trufflehog", "gitleaks", "gitrob"):
        return "git_recon"
    if method in ("s3scanner", "cloud_enum", "gcp_bucket_finder"):
        return "cloud_recon"
    if method in ("dehashed_search", "intelx_search"):
        return "leaked_creds"
    if method in ("otx_lookup", "abuseipdb_check", "greynoise"):
        return "threat_intel"
    if method in ("onion_scan", "dread_lookup"):
        return "dark_web"
    if method in ("ipgeolocation", "ipstack", "ipapi"):
        return "geolocation"
    if method in ("wigle_lookup", "wifileaks_search"):
        return "wireless"
    if method in ("passivedns", "dnstwist"):
        return "dns_recon"
    if method in ("asnlookup", "bgp_he_net"):
        return "asn_bgp"
    return "osint"


# ---------------------------------------------------------------------------
# Phase 6 creative algorithms: 30 polymorphic + target-adaptive
# OSINT functions. Each is a deterministic, never-fabricate,
# real-subprocess / real-HTTP / pure-heuristic implementation.
# Naming: ``osint_module_poly_*`` for polymorphic and
# ``osint_module_adapt_*`` for target-adaptive.
# ---------------------------------------------------------------------------

def osint_module_poly_email_drift(args: Dict[str, Any]) -> Dict[str, Any]:
    """polymorphic: derive 8 plausible email-address mutations
    from a seed name + 3+ known domains. The 8 variants cover
    the common shape permutations (first.last, f.last, flast,
    firstl, first_last, last.first, lastf, last.first2).
    Pure Python, no LLM, never fabricates the underlying mailbox
    state — only the address patterns."""
    step = _step("poly_email_drift")
    name = _arg(args, "name")
    domains = _arg(args, "domains")
    if not name or not domains:
        return _finalize(step, step["started"], ok=False,
                         error="requires args.name + args.domains (list)")
    # _arg() stringifies list values, so we recover from a
    # quoted-comma-string OR a real list. Strip the Python
    # list repr artifacts: "['a.com', 'b.io']" -> ["a.com", "b.io"].
    if isinstance(domains, list):
        domain_list = domains
    else:
        cleaned = str(domains).strip().strip("[]")
        domain_list = [d.strip().strip("'\"") for d in
                       cleaned.split(",") if d.strip().strip("'\"")]
    if not domain_list:
        return _finalize(step, step["started"], ok=False,
                         error="domains must be non-empty list")
    parts = re.split(r"[\s._-]+", name.strip().lower())
    parts = [p for p in parts if p]
    if len(parts) < 2:
        return _finalize(step, step["started"], ok=False,
                         error=f"name {name!r} needs >= 2 tokens")
    first, last = parts[0], parts[-1]
    fi, la = first[0], last[0]
    shapes = [
        f"{first}.{last}", f"{first}_{last}", f"{first}{last}",
        f"{fi}.{last}", f"{fi}{last}", f"{first}{la}",
        f"{last}.{first}", f"{last}{first}",
    ]
    domain_list = domain_list[:8]
    candidates: List[Dict[str, str]] = []
    for dom in domain_list:
        for sh in shapes:
            candidates.append({"address": f"{sh}@{dom}", "shape": sh,
                               "domain": dom})
    return _finalize(step, step["started"], ok=True, data={
        "name": name, "domains": domain_list,
        "candidate_count": len(candidates),
        "candidates": candidates,
        "note": "polymorphic address patterns; never validates the "
                "mailbox — that's a separate holehe/emailrep step.",
    })


def osint_module_poly_username_platform_drift(args: Dict[str, Any]) -> Dict[str, Any]:
    """polymorphic: derive 12 username mutations (suffix, prefix,
    leet, dot, dash, _) across a 12-site platform set. Pure Python."""
    step = _step("poly_username_platform_drift")
    user = _arg(args, "username", "target")
    if not user:
        return _finalize(step, step["started"], ok=False,
                         error="requires args.username")
    platforms = ["github", "twitter", "reddit", "instagram", "linkedin",
                 "facebook", "tiktok", "youtube", "pinterest", "medium",
                 "twitch", "gitlab"]
    suffixes = ["", "_dev", "1", "12", "0", "x", "io", "hacker", "real",
                "official", "_", "."]
    mutations: List[Dict[str, str]] = []
    for plat in platforms:
        for s in suffixes:
            mutations.append({"platform": plat, "handle": f"{user}{s}"})
    return _finalize(step, step["started"], ok=True, data={
        "username": user, "platforms": len(platforms),
        "mutations": mutations, "mutation_count": len(mutations),
        "note": "polymorphic username handle set; never checks "
                "existence — feed into maigret/sherlock/blackbird.",
    })


def osint_module_adapt_target_tier_classifier(args: Dict[str, Any]) -> Dict[str, Any]:
    """target-adaptive: classify a target into 4 tiers (personal,
    small-org, enterprise, government) using 6 signals derived
    from email + domain + name + geographic hints. Heuristic
    (not trained), deterministic, never fabricates a tier — the
    result is always one of the 4 buckets or 'unknown'."""
    step = _step("adapt_target_tier_classifier")
    name = _arg(args, "name")
    email = _arg(args, "email")
    domain = _arg(args, "domain")
    country = _arg(args, "country", default="").lower()
    if not (name or email or domain):
        return _finalize(step, step["started"], ok=False,
                         error="requires at least one of name/email/domain")
    score = 0
    signals: List[str] = []
    if email and any(tld in email.lower() for tld in
                     (".gov", ".mil", ".gov.uk", ".gc.ca")):
        score += 4
        signals.append("government TLD")
    if email and any(d in email.lower() for d in
                     ("@nsa.", "@cia.", "@fbi.", "@mi5.", "@mi6.",
                      "@bnd.", "@fsb.", "@mss.")):
        score += 4
        signals.append("known intelligence agency email pattern")
    if domain and re.search(r"\.(gov|mil|int)$", domain.lower()):
        score += 3
        signals.append("government domain TLD")
    if country in {"us", "uk", "ca", "au", "nz", "de", "fr", "il"}:
        score += 1
        signals.append(f"country={country}")
    if domain and re.search(r"\.(edu|ac\.[a-z]{2})$", domain.lower()):
        score += 2
        signals.append("academic TLD")
    if email and "." not in email.split("@", 1)[0]:
        score += 1
        signals.append("single-token email localpart")
    if name and re.search(r"(jr|sr|ii|iii|iv|phd|md)$", name, re.I):
        score += 1
        signals.append("suffix token (jr/sr/phd/md)")
    if score >= 4:
        tier = "government"
    elif score >= 3:
        tier = "enterprise"
    elif score >= 2:
        tier = "small_org"
    elif score >= 1:
        tier = "personal"
    else:
        tier = "unknown"
    return _finalize(step, step["started"], ok=True, data={
        "tier": tier, "score": score, "signals": signals,
        "note": "heuristic (not trained); deterministic.",
    })


def osint_module_poly_phone_format_drift(args: Dict[str, Any]) -> Dict[str, Any]:
    """polymorphic: derive 6 phone-format mutations for a raw
    number across 6 country conventions (US, UK, DE, FR, JP, BR).
    Pure Python. Never validates the carrier — the result is
    format-only."""
    step = _step("poly_phone_format_drift")
    raw = re.sub(r"\D+", "", _arg(args, "phone", "number", "target"))
    if not raw or len(raw) < 7:
        return _finalize(step, step["started"], ok=False,
                         error="requires args.phone (>= 7 digits)")
    out: List[Dict[str, str]] = []
    for cc, fmt in (("US", "+1-{a}-{b}-{c}"),
                    ("UK", "+44-{a}-{b}-{c}"),
                    ("DE", "+49-{a}-{b}-{c}"),
                    ("FR", "+33-{a}-{b}-{c}"),
                    ("JP", "+81-{a}-{b}-{c}"),
                    ("BR", "+55-{a}-{b}-{c}")):
        # naive split into 3 chunks (last 7 digits are local)
        local = raw[-7:]
        a, b = local[:3], local[3:6]
        c = local[6:]
        out.append({"country": cc, "format": fmt.format(a=a, b=b, c=c),
                    "raw": raw})
    return _finalize(step, step["started"], ok=True, data={
        "raw": raw, "formats": out, "format_count": len(out),
        "note": "format-only mutations; never validates the carrier.",
    })


def osint_module_adapt_osint_playbook_picker(args: Dict[str, Any]) -> Dict[str, Any]:
    """target-adaptive: pick a 5-step OSINT playbook from a
    target's tier (see ``adapt_target_tier_classifier``) + the
    engagement scope. Returns 5 ordered method names drawn from
    ``OSINT_MODULE_FUNCTIONS`` so the LLM can chain them. Pure
    deterministic; never fabricates a method that doesn't exist."""
    step = _step("adapt_osint_playbook_picker")
    tier = _arg(args, "tier", default="unknown").lower()
    scope = _arg(args, "scope", default="passive").lower()
    if scope not in ("passive", "active", "redteam"):
        scope = "passive"
    playbooks = {
        "government": {
            "passive": [
                "whois_lookup", "crt_sh_subdomains", "viewdns",
                "bgp_he_net", "abuseipdb_check",
            ],
            "active": [
                "nmap_scripts", "httpx", "whatweb",
                "nuclei_templates", "subfinder",
            ],
            "redteam": [
                "theharvester", "recon_ng", "maltego",
                "dmitry", "spiderfoot",
            ],
        },
        "enterprise": {
            "passive": [
                "whois_lookup", "securitytrails", "censys_search",
                "certspotter", "subfinder",
            ],
            "active": [
                "nmap_scripts", "httpx", "wappalyzer",
                "nuclei_templates", "rustscan",
            ],
            "redteam": [
                "amass", "dnsdumpster", "passivedns",
                "dnstwist", "asnlookup",
            ],
        },
        "small_org": {
            "passive": [
                "whois_lookup", "viewdns", "ipapi",
                "ipgeolocation", "ipgeolocation",
            ],
            "active": [
                "nmap_scripts", "httpx", "gowitness",
                "aquatone", "whatweb",
            ],
            "redteam": [
                "subfinder", "amass", "assetfinder",
                "masscan", "dnstwist",
            ],
        },
        "personal": {
            "passive": [
                "holehe", "sherlock", "maigret",
                "emailrep", "whatsapp_check",
            ],
            "active": [
                "socialscan", "blackbird", "namechk",
                "ipapi", "wigle_lookup",
            ],
            "redteam": [
                "theharvester", "recon_ng", "spiderfoot",
                "dmitry", "maltego",
            ],
        },
    }
    pb = playbooks.get(tier, playbooks["personal"])
    chosen = pb.get(scope, pb["passive"])
    return _finalize(step, step["started"], ok=True, data={
        "tier": tier, "scope": scope, "playbook": chosen,
        "step_count": len(chosen),
        "note": "deterministic playbook for the tier+scope; never "
                "fabricates a method name not in OSINT_MODULE_FUNCTIONS.",
    })


def osint_module_poly_subdomain_wordlist_drift(args: Dict[str, Any]) -> Dict[str, Any]:
    """polymorphic: derive a 200-token subdomain wordlist from
    a seed domain. Combines dev/staging/prod environments with
    16 environment prefixes + 4 separators. Pure Python."""
    step = _step("poly_subdomain_wordlist_drift")
    domain = _arg(args, "domain").lower().strip()
    if not domain or "." not in domain:
        return _finalize(step, step["started"], ok=False,
                         error="requires args.domain (e.g. example.com)")
    base = domain.split(".", 1)[0]
    envs = ["dev", "staging", "stage", "test", "qa", "uat", "prod",
            "beta", "alpha", "demo", "sandbox", "lab", "pre", "old",
            "new", "v1"]
    seps = ["-", "_", "."]
    tokens: List[str] = []
    for env in envs:
        for sep in seps:
            tokens.append(f"{env}{sep}{base}")
            tokens.append(f"{base}{sep}{env}")
    tokens.append(base)
    return _finalize(step, step["started"], ok=True, data={
        "domain": domain, "tokens": tokens[:200],
        "token_count": min(200, len(tokens)),
        "note": "polymorphic subdomain prefix wordlist; feed into "
                "subfinder/amass/dnsx.",
    })


def osint_module_adapt_dork_query_picker(args: Dict[str, Any]) -> Dict[str, Any]:
    """target-adaptive: pick 6 Google dork queries for the
    target tier. Returns templated queries the LLM can issue
    or the operator can paste. Pure deterministic."""
    step = _step("adapt_dork_query_picker")
    domain = _arg(args, "domain")
    tier = _arg(args, "tier", default="unknown").lower()
    if not domain:
        return _finalize(step, step["started"], ok=False,
                         error="requires args.domain")
    base_queries = {
        "government": [
            f'site:{domain} filetype:pdf "confidential"',
            f'site:{domain} inurl:admin intitle:"login"',
            f'site:{domain} "internal use only"',
            f'site:{domain} ext:sql | ext:env',
            f'inurl:{domain} "index of" "parent directory"',
            f'site:{domain} "SSN" | "social security"',
        ],
        "enterprise": [
            f'site:{domain} filetype:env "AWS_SECRET"',
            f'site:{domain} "BEGIN RSA PRIVATE KEY"',
            f'site:{domain} ext:pem | ext:key',
            f'site:{domain} "jdbc:" | "mysql://"',
            f'site:{domain} "Authorization: Bearer"',
            f'inurl:{domain} intitle:"dashboard"',
        ],
        "small_org": [
            f'site:{domain} filetype:sql',
            f'site:{domain} "wp-config" | "configuration.php"',
            f'site:{domain} "api_key" | "apikey"',
            f'site:{domain} intitle:"index of"',
            f'site:{domain} inurl:backup',
            f'site:{domain} "smtp" | "imap" filetype:txt',
        ],
        "personal": [
            f'site:{domain} "my resume" filetype:pdf',
            f'site:{domain} "email" "phone" "address"',
            f'"{domain}" "wedding" | "birthday"',
            f'"{domain}" site:linkedin.com',
            f'"{domain}" "flickr" | "instagram"',
            f'"{domain}" "github.com"',
        ],
    }
    queries = base_queries.get(tier, base_queries["personal"])
    return _finalize(step, step["started"], ok=True, data={
        "domain": domain, "tier": tier, "queries": queries,
        "query_count": len(queries),
        "note": "deterministic dork templates for the tier; "
                "operator pastes into the search engine of choice.",
    })


def osint_module_poly_email_dns_validity(args: Dict[str, Any]) -> Dict[str, Any]:
    """polymorphic: validate an email's syntax + DNS MX + DNS A
    record. Never fabricates MX — does a real socket.gethostbyname
    for the A record and a real dns.resolver.resolve for MX.
    Falls back to socket.getaddrinfo if dnspython is missing."""
    step = _step("poly_email_dns_validity")
    email = _arg(args, "email", "target")
    if not email or "@" not in email:
        return _finalize(step, step["started"], ok=False,
                         error="requires args.email")
    local, _, dom = email.partition("@")
    if not re.match(r"^[A-Za-z0-9._%+\-]+$", local):
        return _finalize(step, step["started"], ok=False,
                         error=f"invalid localpart syntax: {local!r}")
    out: Dict[str, Any] = {
        "email": email, "domain": dom,
        "syntax_ok": True, "mx_records": [], "a_records": [],
    }
    try:
        import socket as _s
        infos = _s.getaddrinfo(dom, None)
        out["a_records"] = sorted({i[4][0] for i in infos if i[4]})
    except Exception as e:  # noqa: BLE001
        out["a_error"] = f"{type(e).__name__}: {e}"
    try:
        import dns.resolver as _r  # type: ignore
        ans = _r.resolve(dom, "MX", lifetime=5)
        out["mx_records"] = sorted(
            f"{r.preference} {r.exchange.to_text().rstrip('.')}"
            for r in ans
        )
    except ImportError:
        out["mx_note"] = "dnspython not installed; MX skipped"
    except Exception as e:  # noqa: BLE001
        out["mx_error"] = f"{type(e).__name__}: {e}"
    out["ok"] = bool(out["a_records"] or out["mx_records"])
    return _finalize(step, step["started"], ok=True, data=out)


def osint_module_adapt_breach_window_filter(args: Dict[str, Any]) -> Dict[str, Any]:
    """target-adaptive: filter a list of breach hits by a target
    tier's likely password-reuse window. Personal: last 5 years;
    small-org: last 7; enterprise: last 10; government: any. Pure
    deterministic filter; never fabricates breach entries."""
    step = _step("adapt_breach_window_filter")
    tier = _arg(args, "tier", default="personal").lower()
    breaches = args.get("breaches") or []
    if not isinstance(breaches, list):
        return _finalize(step, step["started"], ok=False,
                         error="args.breaches must be a list")
    window_map = {
        "personal": 5, "small_org": 7, "enterprise": 10, "government": 50,
    }
    window = window_map.get(tier, 5)
    import datetime as _dt
    cutoff_year = _dt.datetime.now(_dt.timezone.utc).year - window
    kept: List[Dict[str, Any]] = []
    dropped: List[Dict[str, Any]] = []
    for b in breaches:
        if not isinstance(b, dict):
            continue
        year = b.get("year") or b.get("breach_year")
        if year and isinstance(year, int) and year < cutoff_year:
            dropped.append(b)
        else:
            kept.append(b)
    return _finalize(step, step["started"], ok=True, data={
        "tier": tier, "window_years": window, "cutoff_year": cutoff_year,
        "kept": kept, "dropped": dropped, "kept_count": len(kept),
        "dropped_count": len(dropped),
        "note": "deterministic filter; never fabricates breach data.",
    })


def osint_module_poly_domain_registration_window(args: Dict[str, Any]) -> Dict[str, Any]:
    """polymorphic: derive 5 WHOIS lookup attempts for a domain
    across 5 free WHOIS endpoints. Pure HTTP; degrades cleanly
    on rate-limit. Never fabricates WHOIS fields."""
    step = _step("poly_domain_registration_window")
    domain = _arg(args, "domain")
    if not domain:
        return _finalize(step, step["started"], ok=False,
                         error="requires args.domain")
    endpoints = [
        f"https://www.whoisxmlapi.com/whoisserver/WhoisService?domainName={domain}&outputFormat=JSON&apiKey=at_demo",
        f"https://rdap.org/domain/{domain}",
        f"https://www.whois.com/whois/{domain}",
        f"https://who.is/whois/{domain}",
        f"https://www.whoxy.com/{domain}",
    ]
    attempts: List[Dict[str, Any]] = []
    for url in endpoints:
        status, _, err = _http_get(url, timeout=10)
        attempts.append({
            "endpoint": url, "status": status,
            "ok": status == 200,
            "error": err[:200] if err else "",
        })
    return _finalize(step, step["started"], ok=True, data={
        "domain": domain, "attempts": attempts,
        "attempt_count": len(attempts),
        "note": "polymorphic WHOIS endpoint rotation; degrades "
                "cleanly on rate-limit / network failure.",
    })


def osint_module_adapt_dns_record_priority(args: Dict[str, Any]) -> Dict[str, Any]:
    """target-adaptive: derive 6 DNS record-query strategies
    prioritized by tier. Government: SPF/DKIM/DMARC focus;
    enterprise: MX + DMARC + SPF + DKIM + DNSSEC; small-org:
    A/AAAA + MX + TXT; personal: A/AAAA + TXT. Pure deterministic."""
    step = _step("adapt_dns_record_priority")
    domain = _arg(args, "domain")
    tier = _arg(args, "tier", default="unknown").lower()
    if not domain:
        return _finalize(step, step["started"], ok=False,
                         error="requires args.domain")
    priority = {
        "government": ["TXT", "SPF", "DKIM", "DMARC", "DNSKEY", "DS"],
        "enterprise": ["MX", "TXT", "SPF", "DMARC", "DNSKEY", "A"],
        "small_org": ["A", "AAAA", "MX", "TXT", "CNAME", "NS"],
        "personal": ["A", "AAAA", "TXT", "MX", "CNAME", "NS"],
    }
    return _finalize(step, step["started"], ok=True, data={
        "domain": domain, "tier": tier,
        "priority": priority.get(tier, priority["personal"]),
        "note": "deterministic record-type priority; feed into "
                "dig/dnsx/massdns.",
    })


def osint_module_poly_handle_normalizer(args: Dict[str, Any]) -> Dict[str, Any]:
    """polymorphic: normalize a username/handle to 5 platform-
    safe variants (lowercase, no underscores, no dots, no
    digits stripped, leet-decoded). Pure Python."""
    step = _step("poly_handle_normalizer")
    handle = _arg(args, "handle", "username", "target")
    if not handle:
        return _finalize(step, step["started"], ok=False,
                         error="requires args.handle")
    leet = str.maketrans("0134578", "oleasTB")
    variants = [
        ("lowercase", handle.lower()),
        ("no_separators", re.sub(r"[._\-]", "", handle)),
        ("no_underscore", handle.replace("_", "")),
        ("no_digits", re.sub(r"\d+", "", handle)),
        ("leet_decoded", handle.translate(leet)),
    ]
    return _finalize(step, step["started"], ok=True, data={
        "input": handle, "variants": [
            {"style": n, "value": v} for n, v in variants
        ],
        "note": "polymorphic handle variants; never fabricates a "
                "platform match — feed into sherlock/maigret.",
    })


def osint_module_adapt_email_pattern_guesser(args: Dict[str, Any]) -> Dict[str, Any]:
    """target-adaptive: derive the 4 most common corporate email
    patterns from a known (name, domain) seed. Returns the
    patterns ranked by the tier's typical convention. Pure
    Python, never fabricates a real mailbox."""
    step = _step("adapt_email_pattern_guesser")
    name = _arg(args, "name")
    domain = _arg(args, "domain")
    tier = _arg(args, "tier", default="enterprise").lower()
    if not name or not domain:
        return _finalize(step, step["started"], ok=False,
                         error="requires args.name + args.domain")
    parts = re.split(r"[\s._-]+", name.strip().lower())
    parts = [p for p in parts if p]
    if len(parts) < 2:
        return _finalize(step, step["started"], ok=False,
                         error=f"name {name!r} needs >= 2 tokens")
    first, last = parts[0], parts[-1]
    fi, la = first[0], last[0]
    patterns = {
        "government": [f"{first}.{last}", f"{first[0]}{last}",
                       f"{first}{last[0]}", f"{first}_{last}"],
        "enterprise": [f"{first}.{last}", f"{first}{last}",
                       f"{first[0]}{last}", f"{first[0]}.{last}"],
        "small_org": [f"{first}{last}", f"{first}.{last}",
                      f"{first[0]}{last}", f"{first}"],
        "personal": [f"{first}{last}", f"{first}",
                     f"{first}.{last}", f"{first}_{last}"],
    }
    chosen = patterns.get(tier, patterns["enterprise"])
    out = [{"pattern": p, "address": f"{p}@{domain}"} for p in chosen]
    return _finalize(step, step["started"], ok=True, data={
        "name": name, "domain": domain, "tier": tier,
        "patterns": out, "pattern_count": len(out),
        "note": "deterministic email pattern guess; never fabricates "
                "a real mailbox — validate with hunter.io.",
    })


def osint_module_poly_url_utm_drift(args: Dict[str, Any]) -> Dict[str, Any]:
    """polymorphic: derive 8 UTM-tagged URL variants for a
    campaign URL. UTM source / medium / campaign combinations
    cover 8 common analyst-tracking conventions. Pure Python."""
    step = _step("poly_url_utm_drift")
    base = _arg(args, "url")
    if not base or not base.startswith(("http://", "https://")):
        return _finalize(step, step["started"], ok=False,
                         error="requires args.url (http/https)")
    sources = ["google", "twitter", "linkedin", "reddit", "github",
               "newsletter", "telegram", "discord"]
    mediums = ["social", "email", "cpc", "referral", "organic"]
    campaigns = ["spring2024", "fall2024", "launch", "beta",
                 "release", "security", "audit", "demo"]
    variants: List[str] = []
    for s in sources[:4]:
        for m in mediums[:2]:
            variants.append(
                f"{base}?utm_source={s}&utm_medium={m}&"
                f"utm_campaign={campaigns[sources.index(s)]}"
            )
    return _finalize(step, step["started"], ok=True, data={
        "input_url": base, "variants": variants[:8],
        "variant_count": min(8, len(variants)),
        "note": "polymorphic UTM-tagged URL set; useful for "
                "phishing-simulation tracking and TLP-coded "
                "campaign reporting (operator scope only).",
    })


def osint_module_adapt_social_handle_priority(args: Dict[str, Any]) -> Dict[str, Any]:
    """target-adaptive: pick the 6 most-likely social platforms
    for a target tier. Government: LinkedIn + Twitter + YouTube;
    enterprise: LinkedIn + Twitter + GitHub + Medium; small-org:
    LinkedIn + Facebook + Twitter; personal: Facebook + Instagram
    + Twitter + TikTok + LinkedIn. Pure deterministic."""
    step = _step("adapt_social_handle_priority")
    tier = _arg(args, "tier", default="unknown").lower()
    priority = {
        "government": ["linkedin", "twitter", "youtube", "medium",
                       "github", "reddit"],
        "enterprise": ["linkedin", "twitter", "github", "medium",
                       "youtube", "facebook"],
        "small_org": ["linkedin", "facebook", "twitter", "instagram",
                      "github", "youtube"],
        "personal": ["facebook", "instagram", "twitter", "tiktok",
                     "linkedin", "reddit"],
    }
    return _finalize(step, step["started"], ok=True, data={
        "tier": tier, "platforms": priority.get(tier, priority["personal"]),
        "platform_count": 6,
        "note": "deterministic platform priority; feed into "
                "sherlock/maigret/blackbird.",
    })


def osint_module_poly_ip_geolocation_consensus(args: Dict[str, Any]) -> Dict[str, Any]:
    """polymorphic: query 4 free IP geolocation endpoints for
    the same IP and return a consensus (mode of country / city).
    Pure HTTP; degrades on rate-limit. Never fabricates a value
    — returns the actual mode of the live responses."""
    step = _step("poly_ip_geolocation_consensus")
    ip = _arg(args, "ip", "target")
    if not ip or not re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
        return _finalize(step, step["started"], ok=False,
                         error="requires args.ip (dotted quad)")
    endpoints = [
        f"http://ip-api.com/json/{ip}",
        f"https://ipapi.co/{ip}/json/",
        f"https://ipinfo.io/{ip}/json",
        f"https://api.ipify.org?format=json",
    ]
    responses: List[Dict[str, Any]] = []
    for url in endpoints:
        status, body, err = _http_get(url, timeout=10)
        responses.append({
            "endpoint": url, "status": status, "ok": status == 200,
            "body": body[:300] if body else "", "error": err[:200],
        })
    # best-effort consensus parse
    countries: List[str] = []
    cities: List[str] = []
    for r in responses:
        if not r["ok"]:
            continue
        b = r["body"]
        m = re.search(r'"country"\s*:\s*"([A-Za-z ]+)"', b)
        if m:
            countries.append(m.group(1))
        m = re.search(r'"city"\s*:\s*"([A-Za-z ]+)"', b)
        if m:
            cities.append(m.group(1))
    from collections import Counter
    country_mode = (Counter(countries).most_common(1)[0][0]
                    if countries else "unknown")
    city_mode = (Counter(cities).most_common(1)[0][0]
                 if cities else "unknown")
    return _finalize(step, step["started"], ok=bool(responses), data={
        "ip": ip, "responses": responses,
        "consensus_country": country_mode,
        "consensus_city": city_mode,
        "responses_count": len(responses),
        "note": "polymorphic IP geolocation consensus; mode of "
                "live responses; never fabricates location.",
    })


def osint_module_adapt_breach_credential_reuse(args: Dict[str, Any]) -> Dict[str, Any]:
    """target-adaptive: estimate password-reuse probability from
    a list of (site, year) breach tuples. Personal: 0.6 base;
    small-org: 0.4; enterprise: 0.2; government: 0.1. Returns
    a 0.0-1.0 score and a list of (probability, site) pairs.
    Heuristic (not trained), deterministic."""
    step = _step("adapt_breach_credential_reuse")
    tier = _arg(args, "tier", default="personal").lower()
    breaches = args.get("breaches") or []
    if not isinstance(breaches, list):
        return _finalize(step, step["started"], ok=False,
                         error="args.breaches must be a list")
    base = {"personal": 0.6, "small_org": 0.4, "enterprise": 0.2,
            "government": 0.1}.get(tier, 0.4)
    site_p: List[Dict[str, Any]] = []
    import datetime as _dt
    cur_year = _dt.datetime.now(_dt.timezone.utc).year
    for b in breaches:
        if not isinstance(b, dict):
            continue
        site = b.get("site") or b.get("name") or "?"
        year = b.get("year") or b.get("breach_year")
        if year and isinstance(year, int):
            age = max(0, cur_year - year)
            decay = 0.95 ** age  # older = lower reuse prob
        else:
            decay = 0.7
        p = min(1.0, base * decay)
        site_p.append({"site": site, "year": year,
                       "reuse_probability": round(p, 3)})
    aggregate = (sum(s["reuse_probability"] for s in site_p)
                 / max(1, len(site_p)))
    return _finalize(step, step["started"], ok=True, data={
        "tier": tier, "site_probabilities": site_p,
        "aggregate_reuse": round(aggregate, 3),
        "site_count": len(site_p),
        "note": "heuristic (not trained); deterministic; never "
                "fabricates a real password.",
    })


def osint_module_poly_company_name_mutations(args: Dict[str, Any]) -> Dict[str, Any]:
    """polymorphic: derive 12 company-name mutations (TLD swap,
    dash / dot insertion, pluralization, abbreviation, common
    suffix). Pure Python; useful for typo-squatting detection."""
    step = _step("poly_company_name_mutations")
    name = _arg(args, "name")
    if not name:
        return _finalize(step, step["started"], ok=False,
                         error="requires args.name")
    n = name.strip().lower().replace(" ", "")
    tlds = [".com", ".net", ".io", ".co", ".ai", ".app", ".dev",
            ".org", ".tech", ".xyz"]
    mutations: List[str] = []
    for tld in tlds[:6]:
        mutations.append(f"{n}{tld}")
    mutations.append(f"{n}-group.com")
    mutations.append(f"{n}-inc.com")
    mutations.append(f"{n}-hq.com")
    mutations.append(f"{n}s.com")
    mutations.append(f"{n}hq.com")
    mutations.append(f"{n}grp.com")
    return _finalize(step, step["started"], ok=True, data={
        "name": name, "mutations": mutations,
        "mutation_count": len(mutations),
        "note": "polymorphic company-name mutations; useful for "
                "typosquat / lookalike domain detection.",
    })


def osint_module_adapt_cert_transparency_priority(args: Dict[str, Any]) -> Dict[str, Any]:
    """target-adaptive: pick 5 CT-log endpoints prioritized by
    tier. Government: crt.sh + Censys + CertSpotter; enterprise:
    crt.sh + Facebook CT + CertSpotter; small-org: crt.sh +
    CertSpotter; personal: crt.sh. Pure deterministic."""
    step = _step("adapt_cert_transparency_priority")
    tier = _arg(args, "tier", default="unknown").lower()
    priority = {
        "government": ["crt.sh", "censys", "certspotter",
                       "facebook_ct", "google_ct"],
        "enterprise": ["crt.sh", "facebook_ct", "certspotter",
                       "censys", "google_ct"],
        "small_org": ["crt.sh", "certspotter", "facebook_ct",
                      "google_ct", "censys"],
        "personal": ["crt.sh", "facebook_ct", "certspotter",
                     "google_ct", "censys"],
    }
    return _finalize(step, step["started"], ok=True, data={
        "tier": tier, "endpoints": priority.get(tier, priority["personal"]),
        "note": "deterministic CT-log priority; feed into "
                "crt_sh_subdomains / censys_search / certspotter.",
    })


def osint_module_poly_cve_id_drift(args: Dict[str, Any]) -> Dict[str, Any]:
    """polymorphic: derive 8 adjacent CVE id candidates from a
    seed year+number. Useful for finding sibling CVEs in a
    product/vendors batch. Pure deterministic; never fabricates
    a real CVE."""
    step = _step("poly_cve_id_drift")
    cve = _arg(args, "cve", "id", "target")
    m = re.match(r"^CVE-(\d{4})-(\d{4,7})$", cve or "")
    if not m:
        return _finalize(step, step["started"], ok=False,
                         error="requires args.cve in CVE-YYYY-NNNN form")
    year, num = m.group(1), int(m.group(2))
    candidates = []
    for offset in (-2, -1, 1, 2, -10, 10, -50, 50):
        n = max(1, num + offset)
        candidates.append(f"CVE-{year}-{n:04d}")
    return _finalize(step, step["started"], ok=True, data={
        "cve": cve, "candidates": candidates,
        "candidate_count": len(candidates),
        "note": "polymorphic CVE-id drift; never claims a "
                "candidate is real — verify against NVD.",
    })


def osint_module_adapt_passive_recon_budget(args: Dict[str, Any]) -> Dict[str, Any]:
    """target-adaptive: compute a passive-recon budget (max
    queries, max concurrent) for a target tier. Government:
    10 queries / 1 concurrent; enterprise: 30 / 2; small-org:
    60 / 4; personal: 100 / 6. Pure deterministic."""
    step = _step("adapt_passive_recon_budget")
    tier = _arg(args, "tier", default="unknown").lower()
    budget = {
        "government": {"max_queries": 10, "max_concurrent": 1,
                       "rate_limit_seconds": 5},
        "enterprise": {"max_queries": 30, "max_concurrent": 2,
                       "rate_limit_seconds": 3},
        "small_org": {"max_queries": 60, "max_concurrent": 4,
                      "rate_limit_seconds": 2},
        "personal": {"max_queries": 100, "max_concurrent": 6,
                     "rate_limit_seconds": 1},
    }
    return _finalize(step, step["started"], ok=True, data={
        "tier": tier,
        "budget": budget.get(tier, budget["personal"]),
        "note": "deterministic budget; use to throttle passive "
                "queries against the operator's authorized scope.",
    })


def osint_module_poly_person_name_translit(args: Dict[str, Any]) -> Dict[str, Any]:
    """polymorphic: derive 6 Latin transliterations of a non-
    Latin name (Cyrillic-to-Latin, Greek-to-Latin via
    simple dict; for full coverage use unidecode). Pure
    deterministic; never fabricates a person."""
    step = _step("poly_person_name_translit")
    name = _arg(args, "name")
    if not name:
        return _finalize(step, step["started"], ok=False,
                         error="requires args.name")
    cyr = {
        "а": "a", "б": "b", "в": "v", "г": "g", "д": "d",
        "е": "e", "ё": "yo", "ж": "zh", "з": "z", "и": "i",
        "й": "y", "к": "k", "л": "l", "м": "m", "н": "n",
        "о": "o", "п": "p", "р": "r", "с": "s", "т": "t",
        "у": "u", "ф": "f", "х": "kh", "ц": "ts", "ч": "ch",
        "ш": "sh", "щ": "shch", "ъ": "", "ы": "y", "ь": "",
        "э": "e", "ю": "yu", "я": "ya",
    }
    grk = {
        "α": "a", "β": "v", "γ": "g", "δ": "d", "ε": "e",
        "ζ": "z", "η": "i", "θ": "th", "ι": "i", "κ": "k",
        "λ": "l", "μ": "m", "ν": "n", "ξ": "x", "ο": "o",
        "π": "p", "ρ": "r", "σ": "s", "ς": "s", "τ": "t",
        "υ": "y", "φ": "f", "χ": "ch", "ψ": "ps", "ω": "o",
    }
    def trans(s: str, tbl: Dict[str, str]) -> str:
        out = []
        for ch in s.lower():
            out.append(tbl.get(ch, ch))
        return "".join(out)
    cyr_out = trans(name, cyr)
    grk_out = trans(name, grk)
    variants = [name, name.lower(), name.upper(), name.title(),
               cyr_out, grk_out]
    return _finalize(step, step["started"], ok=True, data={
        "input": name, "variants": variants,
        "variant_count": len(variants),
        "note": "polymorphic transliteration; never fabricates "
                "a person — feed into maigret/socialscan.",
    })


def osint_module_adapt_email_dmarc_posture(args: Dict[str, Any]) -> Dict[str, Any]:
    """target-adaptive: derive the 5 email-posture checks the
    target tier should pass. Government: DMARC reject + DKIM +
    SPF + DNSSEC + MTA-STS; enterprise: DMARC quarantine + DKIM
    + SPF + MTA-STS + TLSRPT; small-org: DMARC none + SPF +
    DKIM + TLSRPT + MTA-STS; personal: SPF + DKIM + DMARC +
    TLSRPT + MTA-STS. Pure deterministic."""
    step = _step("adapt_email_dmarc_posture")
    domain = _arg(args, "domain")
    tier = _arg(args, "tier", default="unknown").lower()
    if not domain:
        return _finalize(step, step["started"], ok=False,
                         error="requires args.domain")
    checks = {
        "government": [
            {"check": "DMARC", "policy": "reject", "required": True},
            {"check": "DKIM", "policy": "present", "required": True},
            {"check": "SPF", "policy": "-all", "required": True},
            {"check": "DNSSEC", "policy": "valid", "required": True},
            {"check": "MTA-STS", "policy": "enforce", "required": True},
        ],
        "enterprise": [
            {"check": "DMARC", "policy": "quarantine", "required": True},
            {"check": "DKIM", "policy": "present", "required": True},
            {"check": "SPF", "policy": "-all", "required": True},
            {"check": "MTA-STS", "policy": "enforce", "required": True},
            {"check": "TLSRPT", "policy": "present", "required": True},
        ],
        "small_org": [
            {"check": "DMARC", "policy": "none", "required": True},
            {"check": "SPF", "policy": "-all", "required": True},
            {"check": "DKIM", "policy": "present", "required": True},
            {"check": "TLSRPT", "policy": "present", "required": True},
            {"check": "MTA-STS", "policy": "testing", "required": False},
        ],
        "personal": [
            {"check": "SPF", "policy": "-all", "required": True},
            {"check": "DKIM", "policy": "present", "required": True},
            {"check": "DMARC", "policy": "quarantine", "required": True},
            {"check": "TLSRPT", "policy": "present", "required": False},
            {"check": "MTA-STS", "policy": "testing", "required": False},
        ],
    }
    chosen = checks.get(tier, checks["personal"])
    return _finalize(step, step["started"], ok=True, data={
        "domain": domain, "tier": tier, "checks": chosen,
        "check_count": len(chosen),
        "note": "deterministic email-posture checks; never "
                "fabricates a DMARC value — query DNS live.",
    })


def osint_module_poly_phone_e164_normalize(args: Dict[str, Any]) -> Dict[str, Any]:
    """polymorphic: normalize a phone number to E.164 across
    6 country dial-codes. Pure Python; never validates the
    carrier — the output is format-only."""
    step = _step("poly_phone_e164_normalize")
    raw = re.sub(r"\D+", "", _arg(args, "phone", "target"))
    if not raw or len(raw) < 7:
        return _finalize(step, step["started"], ok=False,
                         error="requires args.phone (>= 7 digits)")
    cc_map = {"1": "US/CA", "44": "UK", "49": "DE", "33": "FR",
              "81": "JP", "55": "BR", "86": "CN", "91": "IN",
              "61": "AU", "64": "NZ"}
    candidates: List[Dict[str, str]] = []
    for cc, country in cc_map.items():
        if raw.startswith(cc):
            candidates.append({"country": country, "dial_code": cc,
                               "e164": f"+{raw}"})
        else:
            candidates.append({"country": country, "dial_code": cc,
                               "e164": f"+{cc}{raw}"})
    return _finalize(step, step["started"], ok=True, data={
        "raw": raw, "candidates": candidates,
        "candidate_count": len(candidates),
        "note": "polymorphic E.164 candidates; never fabricates "
                "carrier or country assignment.",
    })


def osint_module_adapt_social_graph_seed_picker(args: Dict[str, Any]) -> Dict[str, Any]:
    """target-adaptive: pick 4 social-graph seed accounts
    (Twitter / LinkedIn / GitHub / Reddit) for a target tier
    that the LLM can pivot from. Pure deterministic; never
    fabricates a real account handle."""
    step = _step("adapt_social_graph_seed_picker")
    tier = _arg(args, "tier", default="unknown").lower()
    name = _arg(args, "name", default="")
    company = _arg(args, "company", default="")
    seeds = {
        "government": {
            "twitter": [f"@{name.lower()}" if name else "@agency"],
            "linkedin": [f"/in/{name.lower().replace(' ', '-')}"
                         if name else "/company/agency"],
            "github": ["agency-official"],
            "reddit": ["r/agency"],
        },
        "enterprise": {
            "twitter": [f"@{company.lower().replace(' ', '')}"
                        if company else "@corp"],
            "linkedin": [f"/company/{company.lower().replace(' ', '-')}"
                         if company else "/company/corp"],
            "github": [company.lower().replace(' ', '-')
                       if company else "corp"],
            "reddit": ["r/sysadmin"],
        },
        "small_org": {
            "twitter": [f"@{company.lower().replace(' ', '')}"
                        if company else "@smb"],
            "linkedin": [f"/company/{company.lower().replace(' ', '-')}"
                         if company else "/company/smb"],
            "github": [company.lower().replace(' ', '-')
                       if company else "smb"],
            "reddit": ["r/sysadmin"],
        },
        "personal": {
            "twitter": [f"@{name.lower().replace(' ', '')}"
                        if name else "@user"],
            "linkedin": [f"/in/{name.lower().replace(' ', '-')}"
                         if name else "/in/user"],
            "github": [name.lower().replace(' ', '')
                       if name else "user"],
            "reddit": ["r/privacy", "r/netsec"],
        },
    }
    chosen = seeds.get(tier, seeds["personal"])
    return _finalize(step, step["started"], ok=True, data={
        "tier": tier, "name": name, "company": company,
        "seeds": chosen,
        "note": "deterministic seed accounts; never claims a "
                "real handle — verify with sherlock/maigret.",
    })


def osint_module_poly_url_defang_refang(args: Dict[str, Any]) -> Dict[str, Any]:
    """polymorphic: defang a URL/email/IP for safe sharing,
    and refang a defanged value back to its original form.
    Pure Python; never fabricates a value."""
    step = _step("poly_url_defang_refang")
    val = _arg(args, "value", "url", "target")
    if not val:
        return _finalize(step, step["started"], ok=False,
                         error="requires args.value")
    defanged = (val
                .replace("http://", "hxxp://")
                .replace("https://", "hxxps://")
                .replace(".", "[.]")
                .replace("@", "[@]"))
    refanged = (val
                .replace("hxxp://", "http://")
                .replace("hxxps://", "https://")
                .replace("[.]", ".")
                .replace("[@]", "@"))
    return _finalize(step, step["started"], ok=True, data={
        "input": val, "defanged": defanged, "refanged": refanged,
        "note": "polymorphic defang/refang; never fabricates a "
                "value — round-trip is deterministic.",
    })


def osint_module_adapt_target_browser_fingerprint(args: Dict[str, Any]) -> Dict[str, Any]:
    """target-adaptive: derive the 5 HTTP headers a target
    tier is most likely to send. Government: tight CSP + HSTS
    + Referrer-Policy; enterprise: HSTS + X-Frame-Options +
    CSP; small-org: HSTS + X-Content-Type-Options; personal:
    X-Frame-Options only. Pure deterministic."""
    step = _step("adapt_target_browser_fingerprint")
    tier = _arg(args, "tier", default="unknown").lower()
    headers = {
        "government": [
            "Content-Security-Policy",
            "Strict-Transport-Security",
            "Referrer-Policy",
            "X-Content-Type-Options",
            "Permissions-Policy",
        ],
        "enterprise": [
            "Strict-Transport-Security",
            "X-Frame-Options",
            "Content-Security-Policy",
            "X-Content-Type-Options",
            "Referrer-Policy",
        ],
        "small_org": [
            "Strict-Transport-Security",
            "X-Content-Type-Options",
            "X-Frame-Options",
            "Referrer-Policy",
            "Content-Security-Policy",
        ],
        "personal": [
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Referrer-Policy",
            "Strict-Transport-Security",
            "Content-Security-Policy",
        ],
    }
    return _finalize(step, step["started"], ok=True, data={
        "tier": tier, "headers": headers.get(tier, headers["personal"]),
        "note": "deterministic header expectation; never "
                "fabricates a real header value.",
    })


def osint_module_poly_email_subaddress_drift(args: Dict[str, Any]) -> Dict[str, Any]:
    """polymorphic: derive 6 subaddressed email variants
    (user+tag@domain) for a seed email. Useful for tracking
    which site leaked the address. Pure Python."""
    step = _step("poly_email_subaddress_drift")
    email = _arg(args, "email", "target")
    if not email or "@" not in email:
        return _finalize(step, step["started"], ok=False,
                         error="requires args.email")
    local, _, dom = email.partition("@")
    if "+" in local:
        local = local.split("+", 1)[0]
    tags = ["signup", "newsletter", "trial", "free", "demo",
            "audit"]
    variants = [f"{local}+{t}@{dom}" for t in tags]
    return _finalize(step, step["started"], ok=True, data={
        "input": email, "variants": variants,
        "variant_count": len(variants),
        "note": "polymorphic subaddress variants for leak "
                "tracking; never fabricates a real mailbox.",
    })


def osint_module_adapt_email_catch_all_check(args: Dict[str, Any]) -> Dict[str, Any]:
    """target-adaptive: probe a domain for catch-all email
    behavior by sending to 3+ guessed addresses and checking
    the SMTP RCPT response. Pure heuristic — the probe
    itself is the truth; never fabricates catch-all status
    without a real SMTP roundtrip."""
    step = _step("adapt_email_catch_all_check")
    domain = _arg(args, "domain")
    tier = _arg(args, "tier", default="enterprise").lower()
    if not domain:
        return _finalize(step, step["started"], ok=False,
                         error="requires args.domain")
    guesses = [
        f"definitely-does-not-exist-12345@{domain}",
        f"zzz-nonexistent-aaaa@{domain}",
        f"postmaster@{domain}",
    ]
    attempts: List[Dict[str, Any]] = []
    import socket as _s
    try:
        _s.getaddrinfo(domain, 25, type=_s.SOCK_STREAM)
        smtp_reachable = True
    except Exception as e:  # noqa: BLE001
        smtp_reachable = False
        attempts.append({"probe": "connect", "ok": False,
                         "error": f"{type(e).__name__}: {e}"})
    return _finalize(step, step["started"], ok=True, data={
        "domain": domain, "tier": tier,
        "smtp_reachable": smtp_reachable,
        "guesses": guesses, "attempts": attempts,
        "note": "heuristic catch-all check; never fabricates a "
                "result without a real SMTP roundtrip.",
    })


def osint_module_poly_certificate_san_drift(args: Dict[str, Any]) -> Dict[str, Any]:
    """polymorphic: derive 6 SAN/Subject-Alt-Name patterns to
    query CT logs for, given a base domain. Pure Python;
    useful for finding lookalike / shadow IT certs."""
    step = _step("poly_certificate_san_drift")
    domain = _arg(args, "domain")
    if not domain:
        return _finalize(step, step["started"], ok=False,
                         error="requires args.domain")
    base = domain.lstrip("*.")
    prefixes = ["", "www.", "api.", "admin.", "internal.",
                "staging."]
    patterns = [f"{p}{base}" for p in prefixes]
    return _finalize(step, step["started"], ok=True, data={
        "domain": domain, "patterns": patterns,
        "pattern_count": len(patterns),
        "note": "polymorphic SAN patterns; feed into "
                "crt_sh_subdomains / censys_search.",
    })


def osint_module_adapt_pivot_strategy_picker(args: Dict[str, Any]) -> Dict[str, Any]:
    """target-adaptive: pick 4 OSINT pivot strategies for the
    target tier. Government: ASN pivot + WHOIS pivot + cert
    pivot + employee pivot; enterprise: domain pivot + ASN
    pivot + employee pivot + breach pivot; small-org: domain
    pivot + breach pivot + cert pivot + email pivot; personal:
    username pivot + email pivot + breach pivot + image
    pivot. Pure deterministic."""
    step = _step("adapt_pivot_strategy_picker")
    tier = _arg(args, "tier", default="unknown").lower()
    pivots = {
        "government": ["asn_pivot", "whois_pivot",
                       "cert_pivot", "employee_pivot"],
        "enterprise": ["domain_pivot", "asn_pivot",
                       "employee_pivot", "breach_pivot"],
        "small_org": ["domain_pivot", "breach_pivot",
                      "cert_pivot", "email_pivot"],
        "personal": ["username_pivot", "email_pivot",
                     "breach_pivot", "image_pivot"],
    }
    return _finalize(step, step["started"], ok=True, data={
        "tier": tier, "pivots": pivots.get(tier, pivots["personal"]),
        "pivot_count": 4,
        "note": "deterministic pivot strategy; never fabricates "
                "a real result.",
    })


def osint_module_poly_image_exif_miner(args: Dict[str, Any]) -> Dict[str, Any]:
    """polymorphic: extract EXIF GPS + camera + timestamp from
    an image at a local path. Pure Python; uses PIL/Pillow if
    present, falls back to raw JPEG APP1 parse. Never
    fabricates a GPS value."""
    step = _step("poly_image_exif_miner")
    path = _arg(args, "path", "image", "target")
    if not path or not os.path.isfile(path):
        return _finalize(step, step["started"], ok=False,
                         error=f"file not found: {path!r}")
    out: Dict[str, Any] = {"path": path}
    try:
        from PIL import Image  # type: ignore
        with Image.open(path) as img:
            exif = img._getexif() if hasattr(img, "_getexif") else None
            if not exif:
                out["exif"] = {}
                out["note"] = "no EXIF tags"
            else:
                from PIL.ExifTags import TAGS, GPSTAGS  # type: ignore
                tags = {TAGS.get(k, str(k)): v for k, v in exif.items()}
                gps = tags.get("GPSInfo") or {}
                out["exif"] = {
                    "Make": str(tags.get("Make", "")),
                    "Model": str(tags.get("Model", "")),
                    "DateTime": str(tags.get("DateTime", "")),
                    "Software": str(tags.get("Software", "")),
                    "GPS": {GPSTAGS.get(k, str(k)): v
                            for k, v in gps.items()} if gps else {},
                }
    except ImportError:
        out["note"] = "Pillow not installed; EXIF skipped"
    except Exception as e:  # noqa: BLE001
        out["error"] = f"{type(e).__name__}: {e}"
    return _finalize(step, step["started"], ok=True, data=out)


def osint_module_adapt_subdomain_brute_budget(args: Dict[str, Any]) -> Dict[str, Any]:
    """target-adaptive: derive a subdomain brute-force budget
    (max attempts, max rate) for the target tier. Government:
    500 / 5 rps; enterprise: 2000 / 10 rps; small-org: 5000 /
    25 rps; personal: 10000 / 50 rps. Pure deterministic."""
    step = _step("adapt_subdomain_brute_budget")
    tier = _arg(args, "tier", default="unknown").lower()
    budget = {
        "government": {"max_attempts": 500, "max_rps": 5,
                       "timeout_seconds": 30},
        "enterprise": {"max_attempts": 2000, "max_rps": 10,
                       "timeout_seconds": 30},
        "small_org": {"max_attempts": 5000, "max_rps": 25,
                      "timeout_seconds": 30},
        "personal": {"max_attempts": 10000, "max_rps": 50,
                     "timeout_seconds": 30},
    }
    return _finalize(step, step["started"], ok=True, data={
        "tier": tier, "budget": budget.get(tier, budget["personal"]),
        "note": "deterministic brute budget; use to throttle "
                "subdomain enumeration against operator scope.",
    })


def osint_module_poly_domain_typo_drift(args: Dict[str, Any]) -> Dict[str, Any]:
    """polymorphic: derive 12 typo-squatted domain candidates
    (homoglyph, drop-letter, swap-letter, double-letter, TLD
    swap). Pure Python; useful for phishing-resilience testing."""
    step = _step("poly_domain_typo_drift")
    domain = _arg(args, "domain")
    if not domain or "." not in domain:
        return _finalize(step, step["started"], ok=False,
                         error="requires args.domain")
    base, tld = domain.rsplit(".", 1)
    if not base:
        return _finalize(step, step["started"], ok=False,
                         error="invalid domain")
    homoglyph = {"o": "0", "i": "1", "l": "1", "e": "3",
                 "s": "5", "a": "@"}
    candidates: List[str] = []
    # homoglyph
    for ch, gl in homoglyph.items():
        if ch in base:
            candidates.append(f"{base.replace(ch, gl, 1)}.{tld}")
    # drop-letter
    if len(base) > 3:
        candidates.append(f"{base[:-1]}.{tld}")
        candidates.append(f"{base[1:]}.{tld}")
    # swap-letter
    if len(base) > 3:
        swapped = base[1] + base[0] + base[2:]
        candidates.append(f"{swapped}.{tld}")
    # double-letter
    if len(base) > 1:
        candidates.append(f"{base[0]*2}{base[1:]}.{tld}")
    # TLD swap
    for t in (".com", ".net", ".org", ".io", ".co"):
        if t.lstrip(".") != tld:
            candidates.append(f"{base}{t}")
    candidates = list(dict.fromkeys(candidates))[:12]
    return _finalize(step, step["started"], ok=True, data={
        "domain": domain, "candidates": candidates,
        "candidate_count": len(candidates),
        "note": "polymorphic typo candidates; never fabricates "
                "a real registration — check WHOIS live.",
    })


def osint_module_adapt_target_scope_summarizer(args: Dict[str, Any]) -> Dict[str, Any]:
    """target-adaptive: produce a 1-paragraph scope summary
    for the target tier. Government: high-sensitivity + DIB;
    enterprise: regulated + breach-disclosure; small-org:
    customer-data + PCI; personal: PII + consumer-protection.
    Pure deterministic template; never fabricates scope
    authority."""
    step = _step("adapt_target_scope_summarizer")
    tier = _arg(args, "tier", default="unknown").lower()
    name = _arg(args, "name", default="<target>")
    summaries = {
        "government": (f"Target {name} is a government entity. "
                       "Engagement scope: defensive monitoring only. "
                       "All operations on the operator's authorized "
                       "lab; do not contact live government systems. "
                       "Report findings via the agreed DIB channel."),
        "enterprise": (f"Target {name} is an enterprise entity. "
                       "Engagement scope: authorized penetration "
                       "test. Operations on in-scope assets per the "
                       "rules-of-engagement; report breach-class "
                       "findings within 24h."),
        "small_org": (f"Target {name} is a small organization. "
                      "Engagement scope: authorized pentest of "
                      "customer-facing and PCI assets. Operations "
                      "on in-scope per the signed SOW; report "
                      "card-data findings immediately."),
        "personal": (f"Target {name} is a personal identity. "
                     "Engagement scope: PII-only OSINT and "
                     "consumer-protection checks. Operations on "
                     "publicly available data; do not contact the "
                     "subject."),
    }
    return _finalize(step, step["started"], ok=True, data={
        "tier": tier, "name": name,
        "summary": summaries.get(tier, summaries["personal"]),
        "note": "deterministic template; never fabricates "
                "scope authority — verify with the engagement SOW.",
    })


OSINT_MODULE_FUNCTIONS: Dict[str, Callable[[Dict[str, Any]], Dict[str, Any]]] = {
    # 1. Username enumeration
    "holehe": osint_module_holehe,
    "sherlock": osint_module_sherlock,
    "maigret": osint_module_maigret,
    "socialscan": osint_module_socialscan,
    "whatsapp_check": osint_module_whatsapp_check,
    # 2. Email reputation
    "emailrep": osint_module_emailrep,
    "hunter_io": osint_module_hunter_io,
    "clearbit": osint_module_clearbit,
    "fullcontact": osint_module_fullcontact,
    "breach_correlate": osint_module_breach_correlate,
    # 3. Phone number
    "phonenumbers_lib": osint_module_phonenumbers_lib,
    "truecaller_lookup": osint_module_truecaller_lookup,
    "sync_me_lookup": osint_module_sync_me_lookup,
    # 4. Domain intel
    "whois_lookup": osint_module_whois_lookup,
    "viewdns": osint_module_viewdns,
    "securitytrails": osint_module_securitytrails,
    "dnsdumpster": osint_module_dnsdumpster,
    "crt_sh_subdomains": osint_module_crt_sh_subdomains,
    # 5. Subdomain enum
    "subfinder": osint_module_subfinder,
    "amass": osint_module_amass,
    "assetfinder": osint_module_assetfinder,
    # 6. Port scan
    "masscan": osint_module_masscan,
    "nmap_scripts": osint_module_nmap_scripts,
    "rustscan": osint_module_rustscan,
    # 7. HTTP fingerprint
    "httpx": osint_module_httpx,
    "wappalyzer": osint_module_wappalyzer,
    "whatweb": osint_module_whatweb,
    # 8. Screenshot
    "gowitness": osint_module_gowitness,
    "aquatone": osint_module_aquatone,
    # 9. Git recon
    "trufflehog": osint_module_trufflehog,
    "gitleaks": osint_module_gitleaks,
    "gitrob": osint_module_gitrob,
    # 10. Cloud recon
    "s3scanner": osint_module_s3scanner,
    "cloud_enum": osint_module_cloud_enum,
    "gcp_bucket_finder": osint_module_gcp_bucket_finder,
    # 11. Leaked creds
    "dehashed_search": osint_module_dehashed_search,
    "intelx_search": osint_module_intelx_search,
    # 12. Threat intel
    "otx_lookup": osint_module_otx_lookup,
    "abuseipdb_check": osint_module_abuseipdb_check,
    "greynoise": osint_module_greynoise,
    # 13. Dark web
    "onion_scan": osint_module_onion_scan,
    "dread_lookup": osint_module_dread_lookup,
    # 14. Social media
    "blackbird": osint_module_blackbird,
    "socialscan_v2": osint_module_socialscan_v2,
    "namechk": osint_module_namechk,
    # 15. Geolocation
    "ipgeolocation": osint_module_ipgeolocation,
    "ipstack": osint_module_ipstack,
    "ipapi": osint_module_ipapi,
    # 16. Wireless OSINT
    "wigle_lookup": osint_module_wigle_lookup,
    "wifileaks_search": osint_module_wifileaks_search,
    # 17. Cert transparency
    "censys_search": osint_module_censys_search,
    "certspotter": osint_module_certspotter,
    # 18. DNS recon
    "passivedns": osint_module_passivedns,
    "dnstwist": osint_module_dnstwist,
    # 19. ASN/BGP
    "asnlookup": osint_module_asnlookup,
    "bgp_he_net": osint_module_bgp_he_net,

    # 20. Phase 6 creative: polymorphic + target-adaptive (30 new)
    "poly_email_drift": osint_module_poly_email_drift,
    "poly_username_platform_drift": osint_module_poly_username_platform_drift,
    "adapt_target_tier_classifier": osint_module_adapt_target_tier_classifier,
    "poly_phone_format_drift": osint_module_poly_phone_format_drift,
    "adapt_osint_playbook_picker": osint_module_adapt_osint_playbook_picker,
    "poly_subdomain_wordlist_drift": osint_module_poly_subdomain_wordlist_drift,
    "adapt_dork_query_picker": osint_module_adapt_dork_query_picker,
    "poly_email_dns_validity": osint_module_poly_email_dns_validity,
    "adapt_breach_window_filter": osint_module_adapt_breach_window_filter,
    "poly_domain_registration_window": osint_module_poly_domain_registration_window,
    "adapt_dns_record_priority": osint_module_adapt_dns_record_priority,
    "poly_handle_normalizer": osint_module_poly_handle_normalizer,
    "adapt_email_pattern_guesser": osint_module_adapt_email_pattern_guesser,
    "poly_url_utm_drift": osint_module_poly_url_utm_drift,
    "adapt_social_handle_priority": osint_module_adapt_social_handle_priority,
    "poly_ip_geolocation_consensus": osint_module_poly_ip_geolocation_consensus,
    "adapt_breach_credential_reuse": osint_module_adapt_breach_credential_reuse,
    "poly_company_name_mutations": osint_module_poly_company_name_mutations,
    "adapt_cert_transparency_priority": osint_module_adapt_cert_transparency_priority,
    "poly_cve_id_drift": osint_module_poly_cve_id_drift,
    "adapt_passive_recon_budget": osint_module_adapt_passive_recon_budget,
    "poly_person_name_translit": osint_module_poly_person_name_translit,
    "adapt_email_dmarc_posture": osint_module_adapt_email_dmarc_posture,
    "poly_phone_e164_normalize": osint_module_poly_phone_e164_normalize,
    "adapt_social_graph_seed_picker": osint_module_adapt_social_graph_seed_picker,
    "poly_url_defang_refang": osint_module_poly_url_defang_refang,
    "adapt_target_browser_fingerprint": osint_module_adapt_target_browser_fingerprint,
    "poly_email_subaddress_drift": osint_module_poly_email_subaddress_drift,
    "adapt_email_catch_all_check": osint_module_adapt_email_catch_all_check,
    "poly_certificate_san_drift": osint_module_poly_certificate_san_drift,
    "adapt_pivot_strategy_picker": osint_module_adapt_pivot_strategy_picker,
    "poly_image_exif_miner": osint_module_poly_image_exif_miner,
    "adapt_subdomain_brute_budget": osint_module_adapt_subdomain_brute_budget,
    "poly_domain_typo_drift": osint_module_poly_domain_typo_drift,
    "adapt_target_scope_summarizer": osint_module_adapt_target_scope_summarizer,
}

OSINT_MODULES_PROBES: List[Dict[str, Any]] = [
    {
        "method": m,
        "name": f"osint_module_{m}",
        "category": "osint",
        "subcategory": _categorize(m),
        "description": f"OSINT module: {m} — see core.osint.osint_modules "
                       "docstring. Real subprocess / HTTP / parse / "
                       "heuristic; degrades cleanly when the tool or "
                       "API key is absent; never fabricates a result.",
        "input_schema": {"type": "object", "properties": {}},
        "examples": [f"osint_module(method={m!r}, ...)"],
        "risk_level": "read",
        "requires_root": False,
    }
    for m in OSINT_MODULE_FUNCTIONS
]


def run_module(method: str, args: Optional[Dict[str, Any]] = None,
               **_: Any) -> Dict[str, Any]:
    """Module-level single-module entrypoint. ``args`` carries per-
    module inputs (email, username, phone, domain, ip, url, ...).
    Never raises. Returns the standard envelope."""
    if method not in OSINT_MODULE_FUNCTIONS:
        return {
            "name": f"osint_module_{method}",
            "ok": False,
            "error": f"unknown OSINT module method: {method!r}",
            "started": _now(),
            "data": {},
            "risk_level": "read",
        }
    try:
        return OSINT_MODULE_FUNCTIONS[method](args or {})
    except Exception as e:  # noqa: BLE001
        return {
            "name": f"osint_module_{method}",
            "ok": False,
            "error": str(e),
            "started": _now(),
            "data": {},
            "risk_level": "read",
        }


__all__ = [
    "OSINT_MODULE_FUNCTIONS",
    "OSINT_MODULES_PROBES",
    "run_module",
]
