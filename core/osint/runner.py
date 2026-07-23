#!/usr/bin/env python3
"""
OSINT Runner
==============
Real subprocess runners for cataloged OSINT CLIs (sherlock, maigret, holehe,
phoneinfoga, toutatis, theHarvester, subfinder, amass, …). Findings are
normalized to a common shape. If a tool is not installed, the runner returns
an explicit error — never fake results.

People-search is first-class: ``run_people`` / ``run_auto`` classify the
target (email / phone / domain / username / url) and chain the right
categories. Breach checks use real HIBP when keyed, otherwise honest
degrade (no random fabricated breach names).
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import urlparse
from core.algorithm_registry import algo_registry

logger = logging.getLogger(__name__)


def _default_deny(*_a, **_k) -> bool:
    return False


# ---------------------------------------------------------------------------
# Target classification
# ---------------------------------------------------------------------------

_EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")
_PHONE_RE = re.compile(r"^\+?[\d\s\-().]{7,20}$")
_DOMAIN_RE = re.compile(
    r"^(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}$"
)
_IPV4_RE = re.compile(
    r"^(?:\d{1,3}\.){3}\d{1,3}$"
)


def classify_osint_target(target: str) -> Dict[str, Any]:
    """Classify an OSINT target string into a kind + normalized form.

    Kinds: ``email``, ``phone``, ``domain``, ``ip``, ``url``, ``username``.
    Never invents attributes beyond what the string implies.
    """
    t = (target or "").strip()
    kind = "username"
    normalized = t
    meta: Dict[str, Any] = {}

    if not t:
        return {"kind": "empty", "normalized": "", "meta": {}}

    # URL
    if t.lower().startswith(("http://", "https://")):
        try:
            u = urlparse(t)
            host = u.hostname or ""
            kind = "url"
            normalized = t
            meta = {"host": host, "path": u.path or ""}
            if host and _DOMAIN_RE.match(host):
                meta["domain"] = host.lstrip("www.")
            return {"kind": kind, "normalized": normalized, "meta": meta}
        except Exception:  # noqa: BLE001
            pass

    if _EMAIL_RE.match(t):
        kind = "email"
        normalized = t.lower()
        meta["domain"] = normalized.split("@", 1)[-1]
        meta["local"] = normalized.split("@", 1)[0]
    elif _IPV4_RE.match(t):
        kind = "ip"
        normalized = t
    elif _DOMAIN_RE.match(t) and not t.startswith("@"):
        kind = "domain"
        normalized = t.lower().lstrip("www.")
    elif _PHONE_RE.match(t) and sum(c.isdigit() for c in t) >= 7:
        kind = "phone"
        digits = "".join(c for c in t if c.isdigit() or c == "+")
        if digits.startswith("00"):
            digits = "+" + digits[2:]
        normalized = digits
        meta["digits"] = "".join(c for c in digits if c.isdigit())
    else:
        kind = "username"
        normalized = t.lstrip("@").strip()
        meta["handle"] = normalized

    return {"kind": kind, "normalized": normalized, "meta": meta}


def aggregate_findings(
    findings: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Dedupe + bucket findings by type. Never invents values."""
    by_type: Dict[str, List[Dict[str, Any]]] = {}
    seen = set()
    unique: List[Dict[str, Any]] = []
    for f in findings or []:
        if not isinstance(f, dict):
            continue
        key = (
            str(f.get("type") or ""),
            str(f.get("value") or ""),
            str(f.get("source") or ""),
        )
        if key in seen:
            continue
        seen.add(key)
        unique.append(f)
        by_type.setdefault(key[0] or "unknown", []).append(f)
    return {
        "count": len(unique),
        "by_type": {k: len(v) for k, v in by_type.items()},
        "findings": unique,
        "profiles": [f for f in unique if f.get("type") in ("profile", "url")],
        "emails": [f for f in unique if f.get("type") in ("email", "email_registered")],
        "phones": [f for f in unique if f.get("type") == "phone_info"],
    }


class OSINTRunner:
    # Available OSINT probe methods
    OSINT_PROBE_METHODS = [
        "_analyze_username_patterns",
        "_correlate_breach_data",
        "_infer_phone_carrier",
        "_map_social_relationships",
    ]

    def __init__(self, catalog=None, confirm_fn: Optional[Callable] = None):
        # catalog: core.osint_catalog.OSINTCatalog instance
        self.catalog = catalog
        self.confirm_fn = confirm_fn or _default_deny

    # ------------------------------------------------------------------
    # Low-level: run one cataloged tool by name
    # ------------------------------------------------------------------
    def run_tool(self, tool_name: str, target: str, timeout: int = 90) -> Dict[str, Any]:
        """Look up a tool in the catalog, build argv from its `usage`
        template, confirm, and run it. Returns normalized findings.
        """
        if self.catalog is None:
            from core.osint_catalog import OSINTCatalog
            self.catalog = OSINTCatalog()
        tool = self.catalog.get_tool_by_name(tool_name)
        if not tool:
            return {"tool": tool_name, "error": f"tool '{tool_name}' not in catalog"}
        bin_name = tool_name.split()[0]
        if not shutil.which(bin_name):
            return {
                "tool": tool_name,
                "error": f"{bin_name} not installed ({tool.get('install', 'install it')})",
            }
        argv = self._build_argv(tool.get("usage", ""), target, bin_name=bin_name)
        if not argv:
            return {"tool": tool_name, "error": "empty argv after template expansion"}
        if not self.confirm_fn(f"Run {bin_name} {' '.join(argv)} ?"):
            return {"tool": tool_name, "status": "blocked by confirm_fn"}
        return self._exec(tool_name, argv, timeout)

    def _build_argv(
        self, usage: str, target: str, bin_name: str = ""
    ) -> List[str]:
        """Build argv from a usage template by substituting placeholders."""
        usage = usage or bin_name or ""
        # Replace common placeholders with the target.
        for tok in (
            "USERNAME", "EMAIL", "DOMAIN", "NUMBER", "PHONE", "TARGET",
            "IMAGE", "IP", "HOST", "QUERY",
        ):
            usage = usage.replace(tok, target)
        # Also support {target} / <target> styles
        usage = usage.replace("{target}", target).replace("<target>", target)
        usage = usage.replace("{email}", target).replace("{username}", target)
        argv = [a for a in usage.split() if a]
        # If template was bare binary name, append target
        if len(argv) == 1 and target:
            # Known flag conventions
            b = (bin_name or argv[0]).lower()
            if b in ("sherlock", "maigret"):
                argv.append(target)
            elif b == "nexfil":
                argv.extend(["-u", target])
            elif b == "holehe":
                argv.append(target)
            elif b == "phoneinfoga":
                argv.extend(["scan", "-n", target])
            elif b == "theharvester":
                argv.extend(["-d", target, "-b", "all", "-l", "50"])
            elif b == "subfinder":
                argv.extend(["-d", target, "-silent"])
            elif b == "amass":
                argv.extend(["enum", "-d", target, "-silent"])
            elif b == "h8mail":
                argv.extend(["-t", target])
            else:
                argv.append(target)
        return argv

    def _exec(self, tool_name: str, argv: List[str], timeout: int) -> Dict[str, Any]:
        t0 = time.time()
        try:
            p = subprocess.run(
                argv, capture_output=True, text=True, timeout=timeout
            )
            findings = self._parse(tool_name, p.stdout or "")
            # Also scan stderr for tools that write there (rare)
            if not findings and p.stderr:
                findings = self._parse(tool_name, p.stderr)
            return {
                "tool": tool_name,
                "target": argv[-1] if argv else "",
                "rc": p.returncode,
                "stdout": p.stdout or "",
                "stderr": p.stderr or "",
                "findings": findings,
                "duration_s": round(time.time() - t0, 3),
                "ok": p.returncode == 0 or bool(findings),
            }
        except FileNotFoundError:
            return {"tool": tool_name, "error": f"{argv[0]} not found", "ok": False}
        except subprocess.TimeoutExpired:
            return {
                "tool": tool_name,
                "error": "timeout",
                "target": argv[-1] if argv else "",
                "ok": False,
            }
        except Exception as e:
            return {"tool": tool_name, "error": str(e), "ok": False}

    # ------------------------------------------------------------------
    # Per-tool parsers -> normalized findings [{type, value, source, raw}]
    # ------------------------------------------------------------------
    def _parse(self, tool_name: str, stdout: str) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        s = stdout or ""
        name = tool_name.split()[0].lower()

        if name in ("sherlock", "maigret", "nexfil"):
            out.extend(self._parse_username_enum(name, s))
        elif name == "holehe":
            for line in s.splitlines():
                ls = line.strip()
                if "[+]" in ls or ls.startswith("[+]"):
                    # holehe: [+] site.com
                    site = ls.replace("[+]", "").strip()
                    out.append({
                        "type": "email_registered",
                        "value": site or ls,
                        "source": "holehe",
                        "raw": ls,
                    })
        elif name in ("h8mail", "infoga"):
            for line in s.splitlines():
                ls = line.strip()
                if not ls:
                    continue
                if "@" in ls:
                    m = re.search(
                        r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}",
                        ls,
                    )
                    if m:
                        out.append({
                            "type": "email",
                            "value": m.group(0),
                            "source": name,
                            "raw": ls,
                        })
                if any(k in ls.lower() for k in ("breach", "leak", "pwned", "paste")):
                    out.append({
                        "type": "breach_mention",
                        "value": ls[:200],
                        "source": name,
                        "raw": ls,
                    })
        elif name == "phoneinfoga":
            for line in s.splitlines():
                ls = line.strip()
                if any(
                    k in ls
                    for k in (
                        "Carrier", "Country", "Line type", "Valid",
                        "Local", "E164", "International",
                    )
                ):
                    out.append({
                        "type": "phone_info",
                        "value": ls,
                        "source": "phoneinfoga",
                        "raw": ls,
                    })
        elif name == "toutatis":
            for line in s.splitlines():
                ls = line.strip()
                if ":" in ls and not ls.startswith(" " * 8):
                    out.append({
                        "type": "social_info",
                        "value": ls,
                        "source": "toutatis",
                        "raw": ls,
                    })
        elif name in ("theharvester", "theHarvester".lower()):
            for line in s.splitlines():
                ls = line.strip()
                if not ls or ls.startswith("*") or ls.startswith("-"):
                    continue
                if "@" in ls:
                    m = re.search(
                        r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}",
                        ls,
                    )
                    if m:
                        out.append({
                            "type": "email",
                            "value": m.group(0),
                            "source": "theHarvester",
                            "raw": ls,
                        })
                elif _DOMAIN_RE.match(ls) or (
                    ls.count(".") >= 1 and " " not in ls and len(ls) < 120
                ):
                    if re.match(r"^[A-Za-z0-9.\-]+$", ls):
                        out.append({
                            "type": "host",
                            "value": ls.lower(),
                            "source": "theHarvester",
                            "raw": ls,
                        })
        elif name in ("subfinder", "amass", "assetfinder", "findomain"):
            for line in s.splitlines():
                ls = line.strip().lower()
                if ls and re.match(r"^[a-z0-9.\-]+$", ls) and "." in ls:
                    out.append({
                        "type": "subdomain",
                        "value": ls,
                        "source": name,
                        "raw": ls,
                    })
        elif name == "ignorant":
            for line in s.splitlines():
                if "[+]" in line:
                    out.append({
                        "type": "phone_registered",
                        "value": line.strip(),
                        "source": "ignorant",
                        "raw": line.strip(),
                    })
        else:
            # Generic: extract emails / urls / hosts from free text
            for line in s.splitlines()[:80]:
                ls = line.strip()
                if not ls:
                    continue
                for em in re.findall(
                    r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}", ls
                ):
                    out.append({
                        "type": "email", "value": em, "source": name, "raw": ls,
                    })
                for url in re.findall(r"https?://\S+", ls):
                    out.append({
                        "type": "url", "value": url.rstrip(".,;)"),
                        "source": name, "raw": ls,
                    })
                if not any(f.get("raw") == ls for f in out):
                    # Keep a short text sample for operator review
                    if len(out) < 40:
                        out.append({
                            "type": "text", "value": ls[:240],
                            "source": name, "raw": ls,
                        })
        return out

    def _parse_username_enum(
        self, name: str, stdout: str
    ) -> List[Dict[str, Any]]:
        """Parse sherlock / maigret / nexfil style profile hits."""
        out: List[Dict[str, Any]] = []
        # Patterns seen in the wild:
        #   [+] Twitter: https://twitter.com/alice
        #   [+] GitHub: https://github.com/alice
        #   [*] Checking username ...
        #   [x] Not Found ...
        #   Twitter - https://...
        patterns = [
            re.compile(
                r"^\s*\[\+\]\s*([A-Za-z0-9_.\- ]+?)\s*:\s*(https?://\S+)?\s*$"
            ),
            re.compile(
                r"^\s*\[\+\]\s*(https?://\S+)\s*$"
            ),
            re.compile(
                r"^\s*([A-Za-z0-9_.\-]+)\s*[-:]\s*(https?://\S+)\s*$"
            ),
            re.compile(
                r"^\s*\[\+\]\s*Found\s+([A-Za-z0-9_.\-]+)\s*:\s*(https?://\S+)?",
                re.I,
            ),
        ]
        for line in stdout.splitlines():
            ls = line.strip()
            if not ls or ls.startswith("[*]") or ls.startswith("[-]") or ls.startswith("[x]"):
                continue
            matched = False
            for pat in patterns:
                m = pat.match(ls)
                if not m:
                    continue
                matched = True
                g = m.groups()
                if len(g) == 1 and str(g[0]).startswith("http"):
                    url = g[0]
                    site = urlparse(url).hostname or url
                    out.append({
                        "type": "url", "value": url, "source": name, "raw": ls,
                    })
                    out.append({
                        "type": "profile", "value": site,
                        "source": name, "raw": ls,
                    })
                else:
                    site = (g[0] or "").strip()
                    url = (g[1] if len(g) > 1 else "") or ""
                    if site:
                        out.append({
                            "type": "profile", "value": site,
                            "source": name, "raw": ls,
                        })
                    if url:
                        out.append({
                            "type": "url", "value": url.rstrip(".,;)"),
                            "source": name, "raw": ls,
                        })
                break
            if not matched and "http" in ls and "[+]" in ls:
                urls = re.findall(r"https?://\S+", ls)
                for url in urls:
                    out.append({
                        "type": "url", "value": url.rstrip(".,;)"),
                        "source": name, "raw": ls,
                    })
        return out

    # ------------------------------------------------------------------
    # High-level: try a category, falling through installed tools
    # ------------------------------------------------------------------
    def _run_category(
        self,
        category: str,
        target: str,
        timeout: int = 90,
        *,
        run_all: bool = False,
        max_tools: int = 3,
    ) -> Dict[str, Any]:
        """Run tools in a catalog category.

        Default: first installed tool that yields findings (or succeeds).
        ``run_all=True``: try up to ``max_tools`` installed tools and merge.
        """
        if self.catalog is None:
            from core.osint_catalog import OSINTCatalog
            self.catalog = OSINTCatalog()
        tools = self.catalog.get_tools_by_category(category)
        attempts: List[Dict[str, Any]] = []
        all_findings: List[Dict[str, Any]] = []
        ran = 0
        for t in tools:
            bin_name = t["name"].split()[0]
            if not shutil.which(bin_name):
                attempts.append({"tool": t["name"], "error": "not installed"})
                continue
            res = self.run_tool(t["name"], target, timeout=timeout)
            attempts.append(res)
            if res.get("status") == "blocked by confirm_fn":
                continue
            if res.get("error") and not res.get("findings"):
                continue
            findings = list(res.get("findings") or [])
            all_findings.extend(findings)
            ran += 1
            if not run_all:
                return {
                    "category": category,
                    "target": target,
                    "ran_tool": t["name"],
                    "attempts": attempts,
                    "findings": findings,
                    "stdout": (res.get("stdout") or "")[:4000],
                    "ok": True,
                }
            if ran >= max_tools:
                break
        if all_findings:
            agg = aggregate_findings(all_findings)
            return {
                "category": category,
                "target": target,
                "ran_tool": "multi",
                "attempts": attempts,
                "findings": agg["findings"],
                "aggregate": {k: agg[k] for k in ("count", "by_type")},
                "ok": True,
            }
        return {
            "category": category,
            "target": target,
            "error": (
                f"no installed tool in '{category}' "
                f"(tried: {', '.join(t['name'] for t in tools)})"
            ),
            "attempts": attempts,
            "ok": False,
        }

    # ------------------------------------------------------------------
    # Target-adaptive high-level runners
    # ------------------------------------------------------------------
    def run_auto(
        self,
        target: str,
        timeout: int = 90,
        *,
        run_all: bool = False,
    ) -> Dict[str, Any]:
        """Classify target and run the best OSINT categories for it.

        Polymorphic / target-adaptive: multi-engine domain_adapt reorders
        the category plan by target kind + ensemble focus.

        Never fabricates findings. Missing tools reported per category.
        """
        cls = classify_osint_target(target)
        kind = cls["kind"]
        norm = cls["normalized"] or target
        plan = self._plan_for_kind(kind)
        domain_poly_meta: Dict[str, Any] = {}
        # Domain adaptive prepare (people vs web vs generic OSINT)
        try:
            from core.poly.domain_adapt import prepare, normalize_domain
            dom = "osint_people" if kind in (
                "email", "phone", "username",
            ) else ("osint_web" if kind in ("url", "domain", "ip") else "osint")
            prep = prepare(
                dom,
                {"query": norm, "query_type": kind, "target": norm, **(cls.get("meta") or {})},
                phase="recon",
            )
            domain_poly_meta = {
                "domain": dom,
                "engines": prep.get("engines"),
                "focus": (prep.get("ensemble") or {}).get("focus"),
                "depth": (prep.get("ensemble") or {}).get("depth"),
            }
            # Soft reorder: prefer categories matching ensemble focus
            focus = str((prep.get("ensemble") or {}).get("focus") or "").lower()
            if focus and plan:
                preferred = [c for c in plan if focus in str(c).lower()]
                rest = [c for c in plan if c not in preferred]
                if preferred:
                    plan = preferred + rest
        except Exception:  # noqa: BLE001
            pass
        # Optional poly_adapt playbook hint
        adapt_pick = None
        try:
            from core.refactors.poly_adapt_companions import run_poly_adapt
            env = run_poly_adapt(
                "adapt_osint_source_picker",
                {
                    "target": norm,
                    "kind": kind,
                    "jurisdiction": os.environ.get("KFIOSA_JURISDICTION", ""),
                },
                use_memo=True,
            )
            if isinstance(env, dict) and env.get("ok"):
                data = env.get("data") or {}
                adapt_pick = data.get("pick") or data.get("primary")
        except Exception:  # noqa: BLE001
            adapt_pick = None

        categories: Dict[str, Any] = {}
        all_findings: List[Dict[str, Any]] = []
        for cat in plan:
            res = self._run_category(
                cat, norm, timeout=timeout, run_all=run_all,
            )
            categories[cat] = res
            all_findings.extend(res.get("findings") or [])

        # Local algorithms (no network) always available
        local_probes: Dict[str, Any] = {}
        if kind in ("username", "email", "url"):
            handle = cls["meta"].get("handle") or cls["meta"].get("local") or norm
            local_probes["username_patterns"] = self._analyze_username_patterns(
                str(handle).split("@")[0]
            )
            local_probes["social_graph"] = self._map_social_relationships(
                str(handle).split("@")[0]
            )
        if kind == "email" or "@" in norm:
            local_probes["breach_correlate"] = self._correlate_breach_data(norm)
        if kind == "phone":
            local_probes["phone_carrier"] = self._infer_phone_carrier(norm)

        agg = aggregate_findings(all_findings)
        return {
            "ok": bool(agg["count"] or local_probes),
            "target": target,
            "normalized": norm,
            "classification": cls,
            "plan": plan,
            "adapt_pick": adapt_pick,
            "categories": categories,
            "local_probes": local_probes,
            "aggregate": agg,
            "findings": agg["findings"],
            "domain_poly": domain_poly_meta or None,
            "model": "target-adaptive (osint poly ensemble)",
        }

    def _plan_for_kind(self, kind: str) -> List[str]:
        """Category order for a classified kind."""
        if kind == "email":
            return ["email", "breach", "username"]
        if kind == "phone":
            return ["phone"]
        if kind == "domain":
            return ["domain", "email"]
        if kind == "ip":
            return ["domain"]
        if kind == "url":
            return ["username", "social_media", "domain"]
        # username / default
        return ["username", "social_media"]

    # ------------------------------------------------------------------
    # People search (first-class): username + social + phone
    # ------------------------------------------------------------------
    def run_people(self, target: str, timeout: int = 90) -> Dict[str, Any]:
        """Search for a person: adaptive multi-category OSINT.

        Classifies the target first. Username → username+social;
        email → email+breach+username patterns; phone → phone.
        No fake results — missing tools are reported per category.
        """
        auto = self.run_auto(target, timeout=timeout, run_all=False)
        # Keep legacy shape used by TUI (categories + target)
        return {
            "target": target,
            "categories": auto.get("categories") or {},
            "classification": auto.get("classification"),
            "local_probes": auto.get("local_probes") or {},
            "aggregate": auto.get("aggregate") or {},
            "findings": auto.get("findings") or [],
            "adapt_pick": auto.get("adapt_pick"),
            "ok": auto.get("ok"),
            "plan": auto.get("plan"),
        }

    def run_email(self, target: str, timeout: int = 90) -> Dict[str, Any]:
        return self._run_category("email", target, timeout)

    def run_username(self, target: str, timeout: int = 90) -> Dict[str, Any]:
        return self._run_category("username", target, timeout)

    def run_domain(self, target: str, timeout: int = 90) -> Dict[str, Any]:
        return self._run_category("domain", target, timeout)

    def run_phone(self, target: str, timeout: int = 90) -> Dict[str, Any]:
        return self._run_category("phone", target, timeout)

    def run_social(self, target: str, timeout: int = 90) -> Dict[str, Any]:
        return self._run_category("social_media", target, timeout)

    # ------------------------------------------------------------------
    # OSINT Probe Methods - Algorithmic implementations
    # ------------------------------------------------------------------
    @algo_registry.register("username_patterns", domain="osint")
    def _analyze_username_patterns(self, username: str) -> Dict[str, Any]:
        """
        Analyze username patterns across platforms to predict likely usernames
        on other services based on observed patterns.
        """
        if not isinstance(username, str):
            username = ""
        username = username.lstrip("@").strip()
        patterns = []

        patterns.append(username)
        patterns.append(username.lower())
        patterns.append(username.upper())

        substitutions = {
            "a": ["4", "@"], "e": ["3"], "i": ["1", "!"],
            "o": ["0"], "s": ["5", "$"], "t": ["7"],
        }

        for char, subs in substitutions.items():
            if char in username.lower():
                for sub in subs:
                    patterns.append(username.lower().replace(char, sub))

        common_affixes = [
            "x", "xx", "xxx", "123", "1234", "_", "__", "___",
            "official", "real", "the", "im", "iam", "hq", "tv",
        ]

        for affix in common_affixes:
            patterns.append(f"{username}{affix}")
            patterns.append(f"{affix}{username}")

        # Dot / underscore split mutations (john.doe → johndoe, john_doe)
        if "." in username or "_" in username or "-" in username:
            base = re.sub(r"[._\-]+", "", username)
            patterns.append(base)
            patterns.append(re.sub(r"[.\-]", "_", username))
            patterns.append(re.sub(r"[_\-]", ".", username))

        seen = set()
        unique_patterns = []
        for pattern in patterns:
            if pattern and pattern not in seen:
                seen.add(pattern)
                unique_patterns.append(pattern)

        return {
            "type": "username_patterns",
            "value": {
                "original": username,
                "patterns": unique_patterns[:20],
                "pattern_count": len(unique_patterns),
            },
            "source": "_analyze_username_patterns",
            "raw": (
                f"Generated {len(unique_patterns)} username patterns "
                f"for '{username}'"
            ),
        }

    @algo_registry.register("breach_correlate", domain="osint")
    def _correlate_breach_data(self, email_or_username: str) -> Dict[str, Any]:
        """Correlate target with breach data — real HIBP when possible.

        * Email + ``HIBP_API_KEY`` / ``KFIOSA_HIBP_KEY`` → live HIBP v3 API
        * No key → risk-indicator heuristic only; ``identified_breaches``
          stays empty (never random-faked breach names)
        """
        if not isinstance(email_or_username, str):
            email_or_username = ""
        target = email_or_username.strip()
        breach_indicators: List[str] = []

        if any(c.isdigit() for c in target):
            breach_indicators.append("contains_numbers")
        if len(target) < 8:
            breach_indicators.append("short_length")
        if "_" in target or "-" in target:
            breach_indicators.append("special_chars")
        if "@" in target:
            breach_indicators.append("email_format")

        identified: List[Dict[str, Any]] = []
        source_note = "heuristic_risk_only"
        api_error = ""

        is_email = bool(_EMAIL_RE.match(target))
        api_key = (
            os.environ.get("KFIOSA_HIBP_KEY")
            or os.environ.get("HIBP_API_KEY")
            or ""
        ).strip()

        if is_email and api_key:
            hits, err = self._hibp_breached_account(target, api_key)
            if err:
                api_error = err
                source_note = f"hibp_error:{err}"
            else:
                identified = hits
                source_note = "hibp_v3"
        elif is_email and not api_key:
            source_note = "no_hibp_key (set KFIOSA_HIBP_KEY for live breach names)"
        else:
            source_note = "non_email_target (HIBP account API needs email)"

        likelihood = "low"
        if identified:
            likelihood = "high" if len(identified) > 1 else "medium"
        elif len(breach_indicators) >= 2:
            likelihood = "medium"

        return {
            "type": "breach_correlation",
            "value": {
                "target": target,
                "breach_likelihood": likelihood,
                "identified_breaches": identified,
                "risk_indicators": breach_indicators,
                "source_note": source_note,
                "api_error": api_error or None,
                "recommendation": (
                    "Rotate passwords and enable 2FA for exposed accounts"
                    if identified
                    else (
                        "No live breach hits "
                        f"({source_note}); risk indicators only"
                    )
                ),
            },
            "source": "_correlate_breach_data",
            "raw": (
                f"Breach correlation for {target}: "
                f"{len(identified)} live hits; indicators={breach_indicators}"
            ),
        }

    def _hibp_breached_account(
        self, email: str, api_key: str
    ) -> Tuple[List[Dict[str, Any]], str]:
        """Call HIBP v3 breachedaccount. Returns (hits, error_string)."""
        try:
            url = (
                "https://haveibeenpwned.com/api/v3/breachedaccount/"
                + urllib.parse.quote(email)
                + "?truncateResponse=false"
            )
            req = urllib.request.Request(
                url,
                headers={
                    "hibp-api-key": api_key,
                    "user-agent": "KFIOSA-OSINTRunner",
                },
                method="GET",
            )
            with urllib.request.urlopen(req, timeout=12) as resp:
                body = resp.read().decode("utf-8", errors="replace")
            data = json.loads(body) if body else []
            hits = []
            if isinstance(data, list):
                for b in data[:50]:
                    if not isinstance(b, dict):
                        continue
                    hits.append({
                        "Name": b.get("Name") or b.get("Title") or "",
                        "BreachDate": b.get("BreachDate") or "",
                        "Domain": b.get("Domain") or "",
                        "DataClasses": b.get("DataClasses") or [],
                    })
            return hits, ""
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return [], ""
            return [], f"HTTP {e.code}"
        except Exception as e:  # noqa: BLE001
            err = str(e)
            if "404" in err:
                return [], ""
            return [], err[:200]

    @algo_registry.register("phone_carrier", domain="osint")
    def _infer_phone_carrier(self, phone_number: str) -> Dict[str, Any]:
        """
        Infer carrier information from phone number patterns.
        Uses number prefix analysis; PL numbers use the static UKE-style table.
        """
        if not isinstance(phone_number, str):
            phone_number = ""
        cleaned = "".join(c for c in phone_number if c.isdigit() or c == "+")

        if cleaned.startswith("+"):
            cleaned_digits = cleaned[1:]
        elif cleaned.startswith("00"):
            cleaned_digits = cleaned[2:]
            cleaned = "+" + cleaned_digits
        else:
            cleaned_digits = cleaned

        carrier = "Unknown"
        country_code = ""
        area_code = ""
        confidence = "low"
        line_type = "Unknown"
        source = "prefix_table"

        # Polish mobile (+48)
        if cleaned_digits.startswith("48") and len(cleaned_digits) >= 11:
            country_code = "48"
            national = cleaned_digits[2:]
            area_code = national[:3] if len(national) >= 3 else national
            try:
                from core.osint.polish.phone_prefix import lookup_carrier
                pl = lookup_carrier(national)
                if isinstance(pl, dict) and pl.get("ok") and pl.get("carrier"):
                    cname = str(pl["carrier"])
                    if cname.lower() != "unknown":
                        carrier = cname
                        confidence = "medium"
                        source = "polish_phone_prefix"
                        line_type = "Mobile"
                        area_code = str(pl.get("prefix") or area_code)
            except Exception:  # noqa: BLE001
                pass
            if carrier == "Unknown":
                try:
                    from core.osint.runner_ext import _polish_phone_carrier
                    c = _polish_phone_carrier(national)
                    if c:
                        carrier = c
                        confidence = "medium"
                        source = "polish_phone_prefix"
                        line_type = "Mobile"
                except Exception:  # noqa: BLE001
                    pass
        else:
            carrier_prefixes = {
                "201": "AT&T", "202": "Verizon", "203": "T-Mobile",
                "204": "Sprint", "205": "AT&T", "206": "Verizon",
                "207": "T-Mobile", "208": "Sprint", "209": "AT&T",
                "210": "Verizon", "211": "T-Mobile", "212": "Sprint",
                "33": "Orange/France Telecom", "34": "Movistar/Spain",
                "39": "TIM/Italy", "44": "EE/Vodafone UK",
                "49": "Deutsche Telekom/Germany", "52": "Telcel/Mexico",
                "55": "Vivo/Brazil", "61": "Telstra/Australia",
                "81": "NTT Docomo/Japan", "86": "China Mobile/China",
            }
            if len(cleaned_digits) >= 10:
                if cleaned_digits.startswith("1"):
                    country_code = "1"
                    area_code = cleaned_digits[1:4] if len(cleaned_digits) >= 4 else ""
                else:
                    area_code = cleaned_digits[:3]
            elif len(cleaned_digits) >= 9:
                for length in (3, 2):
                    if len(cleaned_digits) >= length:
                        potential_cc = cleaned_digits[:length]
                        if potential_cc in carrier_prefixes:
                            country_code = potential_cc
                            area_code = cleaned_digits[length:length + 3]
                            break

            if area_code and area_code in carrier_prefixes:
                carrier = carrier_prefixes[area_code]
                confidence = "medium"
            elif country_code and country_code in carrier_prefixes:
                carrier = carrier_prefixes[country_code]
                confidence = "medium"
            elif len(cleaned_digits) >= 3:
                prefix = cleaned_digits[:3]
                carrier = carrier_prefixes.get(prefix, "Unknown")
                confidence = "medium" if carrier != "Unknown" else "low"

            line_type = "Mobile"
            if len(cleaned_digits) >= 4:
                fourth = cleaned_digits[3]
                if fourth in ("0", "1") and country_code == "1":
                    line_type = "Landline"

        return {
            "type": "phone_carrier_inference",
            "value": {
                "phone_number": phone_number,
                "cleaned_number": cleaned_digits,
                "country_code": country_code or "Unknown",
                "area_code": area_code or "Unknown",
                "carrier": carrier,
                "line_type": line_type,
                "confidence": confidence,
                "source": source,
                "note": "prefix heuristic / static table — not live portability",
            },
            "source": "_infer_phone_carrier",
            "raw": f"Carrier inference for {phone_number}: {carrier} ({line_type})",
        }

    @algo_registry.register("social_graph", domain="osint")
    def _map_social_relationships(self, social_handle: str) -> Dict[str, Any]:
        """
        Map potential social relationships and network connections
        based on social media handle analysis.
        """
        if not isinstance(social_handle, str):
            social_handle = ""
        handle = social_handle.lstrip("@")

        relationships = []

        if "_" in handle:
            parts = handle.split("_")
            if len(parts) >= 2:
                relationships.append({
                    "type": "potential_collaboration",
                    "indicators": parts,
                    "description": (
                        f"Handle suggests connection between "
                        f"{parts[0]} and {parts[1]}"
                    ),
                })

        if "-" in handle:
            parts = handle.split("-")
            if len(parts) >= 2:
                relationships.append({
                    "type": "potential_affiliation",
                    "indicators": parts,
                    "description": (
                        f"Handle suggests affiliation with "
                        f"{parts[0]} or {parts[1]}"
                    ),
                })

        numeric_suffix = re.search(r"(\d+)$", handle)
        if numeric_suffix:
            relationships.append({
                "type": "sequential_account",
                "indicators": [numeric_suffix.group(1)],
                "description": (
                    f"Handle ends with sequence {numeric_suffix.group(1)} "
                    f"suggesting potential sequential account creation"
                ),
            })

        common_names = [
            "john", "jane", "alex", "sam", "chris", "pat", "ry",
            "kat", "max", "zoe",
        ]
        for name in common_names:
            if name in handle.lower():
                relationships.append({
                    "type": "common_name_usage",
                    "indicators": [name],
                    "description": (
                        f"Handle contains common name '{name}' which may "
                        f"aid in social engineering"
                    ),
                })
                break

        # Platform URL suggestions (templates only — not live hits)
        platforms = {
            "github": f"https://github.com/{handle}",
            "twitter": f"https://twitter.com/{handle}",
            "instagram": f"https://instagram.com/{handle}",
            "reddit": f"https://reddit.com/user/{handle}",
            "linkedin": f"https://linkedin.com/in/{handle}",
        }

        mapping_techniques = [
            "Cross-platform username correlation",
            "Network analysis via mutual connections",
            "Geotag correlation from posted content",
            "Timestamp analysis for coordinated activity",
            "Linguistic analysis of posting patterns",
        ]

        return {
            "type": "social_relationship_mapping",
            "value": {
                "social_handle": social_handle,
                "cleaned_handle": handle,
                "identified_relationships": relationships,
                "relationship_count": len(relationships),
                "suggested_mapping_techniques": mapping_techniques,
                "platform_url_templates": platforms,
                "network_potential": (
                    "high" if len(relationships) > 2
                    else "medium" if relationships else "low"
                ),
                "note": (
                    "platform_url_templates are candidate URLs only — "
                    "not verified profile hits"
                ),
            },
            "source": "_map_social_relationships",
            "raw": (
                f"Social relationship mapping for {social_handle}: "
                f"{len(relationships)} potential connections identified"
            ),
        }


