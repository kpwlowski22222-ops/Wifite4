"""core.tool_installer.github_fetch — fetch new tools from GitHub.

Phase 2.4 — operator wants ~30 new tools fetched from GitHub. We
emit stub ``catalog/github_*.json`` files for each. The actual
git-clone is gated by the per-step ACCEPT and goes through
``TOOL_CATALOG``/``maybe_install``.

Honest-degrade contract: we never fabricate stargazer counts,
release versions, or commit hashes. The catalog entry we emit
contains only the curated name + URL + category; the enricher
fills the rest.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional


# Phase 2.4 curated list (30 confirmed good). Keys are the github
# ``owner/repo`` slug; values are (category, short description).
_PHASE_2_4_TOOLS: Dict[str, tuple] = {
    # WiFi (5)
    "v1s1t0r1sh3r3/airgeddon": ("Wireless Security",
                                 "Bash-based WiFi audit / attack script"),
    "derv82/wifite2": ("Wireless Security",
                       "Automated WiFi auditor"),
    "s0lst1c3/eaphammer": ("Wireless Security",
                            "Targeted evil-twin attacks against WPA2-Enterprise"),
    "entropy1337/infernal-twin": ("Wireless Security",
                                   "Automated evil-twin / captive portal"),
    "P0cL4ty/WiFi-Pumpkin": ("Wireless Security",
                              "Rogue AP framework"),
    # BLE (3)
    "n0xa/m5stick-nemo": ("Bluetooth/BLE",
                          "M5StickC nemo firmware for BLE auditing"),
    "virtualabs/btlejack": ("Bluetooth/BLE",
                            "BLE Hijacking / sniffing tool"),
    "seemoo-lab/internalblue": ("Bluetooth/BLE",
                                 "Bluetooth experimentation framework"),
    # OSINT (10)
    "smicallef/spiderfoot": ("OSINT and Recon",
                             "Automated OSINT collection"),
    "laramies/theHarvester": ("OSINT and Recon",
                              "Email / subdomain / name harvester"),
    "tomnomnom/waybackurls": ("OSINT and Recon",
                              "Fetch all URLs known by the Wayback Machine"),
    "tomnomnom/meg": ("OSINT and Recon",
                      "Fetch many paths for many hosts"),
    "lc/gau": ("OSINT and Recon",
               "Get All URLs (Wayback, Common Crawl, OTX, URLScan)"),
    "projectdiscovery/subfinder": ("OSINT and Recon",
                                    "Subdomain discovery"),
    "OJ/gobuster": ("OSINT and Recon",
                    "Directory / DNS / VHost busting"),
    "m4ll0k/SecretFinder": ("OSINT and Recon",
                             "Find sensitive info in JS bundles"),
    "urbanadventurer/WhoDat": ("OSINT and Recon",
                                "Threat intel / domain reputation"),
    "initstring/cloud_enum": ("OSINT and Recon",
                              "Multi-cloud OSINT enumeration"),
    # Post-exploit (5)
    "fortra/impacket": ("Post-Exploitation",
                        "Python network protocol toolkit"),
    "byt3bl33d3r/CrackMapExec": ("Post-Exploitation",
                                  "Post-exploitation / AD auditing"),
    "ly4k/Certipy": ("Post-Exploitation",
                     "Active Directory certificate abuse"),
    "dirkjanm/krbrelayx": ("Post-Exploitation",
                           "Kerberos relaying toolkit"),
    "S1ckB0y1337/Windows-Exploit-Suggester": ("Post-Exploitation",
                                                "Windows hostsuggest tool"),
    # Web (4)
    "OJ/sqlmap": ("Web Application Security",
                  "Automatic SQL injection + database takeover"),
    "projectdiscovery/nuclei": ("Web Application Security",
                                 "Template-based vulnerability scanner"),
    "projectdiscovery/httpx": ("Web Application Security",
                                "Fast multi-purpose HTTP toolkit"),
    "codingo/Interlace": ("Web Application Security",
                          "Multi-threaded orchestration tool"),
    # Defense evasion (3)
    "gentilkiwi/mimikatz": ("Defense Evasion",
                             "Windows credential extraction"),
    "PowerShellMafia/PowerSploit": ("Defense Evasion",
                                     "PowerShell post-exploitation"),
    "BC-SECURITY/Empire": ("Defense Evasion",
                            "PowerShell / Python post-exploitation C2"),
}


def fetch_list() -> List[str]:
    """Return the ordered list of 30 ``owner/repo`` slugs."""
    return list(_PHASE_2_4_TOOLS.keys())


def build_entry(slug: str) -> Optional[Dict[str, Any]]:
    """Build a single github_*.json stub entry for the slug.

    Returns None if the slug is not in the curated list. The
    entry is a minimal honest stub — the enricher fills the
    rest (summary, tags, use_cases, command_examples,
    risk.signals, attack_surface, phase_hint, requires_hardware).
    """
    if slug not in _PHASE_2_4_TOOLS:
        return None
    category, desc = _PHASE_2_4_TOOLS[slug]
    name = slug.split("/", 1)[1]
    return {
        "id": f"github:{slug}",
        "kind": "external_repository",
        "name": name,
        "full_name": slug,
        "owner": slug.split("/", 1)[0],
        "url": f"https://github.com/{slug}",
        "category": category,
        "metadata_status": "index_only",
        "summary": desc,
        "trust": {"official_kali": False, "reviewed": False,
                  "warning": "Phase 2.4 auto-fetch; review provenance."},
    }


def fetch_all_to_catalog(catalog_dir: Path) -> Dict[str, Any]:
    """Write a stub ``github_<slug>.json`` for every curated tool.

    Idempotent: existing files are NOT overwritten (the enricher
    already ran on them). Returns a count summary.
    """
    catalog_dir.mkdir(parents=True, exist_ok=True)
    written = 0
    skipped = 0
    failed: List[str] = []
    for slug in fetch_list():
        path = catalog_dir / f"github_{slug.replace('/', '_')}.json"
        if path.exists():
            skipped += 1
            continue
        entry = build_entry(slug)
        if entry is None:
            failed.append(slug)
            continue
        try:
            path.write_text(json.dumps(entry, indent=2, ensure_ascii=False),
                            encoding="utf-8")
            written += 1
        except OSError as e:
            failed.append(f"{slug}: {e}")
    return {"ok": not failed, "written": written, "skipped": skipped,
            "failed": failed, "total": len(_PHASE_2_4_TOOLS)}


__all__ = ["fetch_list", "build_entry", "fetch_all_to_catalog"]
