#!/usr/bin/env python3
"""
Tool Registry
==============
Builds a unified, AI-consumable catalog of every tool the operator can call:

1. **Toolboxes** — every repo cloned under ``toolboxes/<domain>/<owner>__<repo>``.
   Each is parsed for a description (README), usage hints (## Usage sections,
   fenced code, ``$``/``python``/``pip``/``./`` command lines), entry points
   (``*.sh``, ``setup.py``/``pyproject.toml`` console_scripts, ``package.json``
   ``bin``, ``Makefile``), language, and requirements.
2. **Kali packages** — a curated pentest allowlist resolved with
   ``shutil.which`` (so binaries actually on PATH win) plus a
   ``dpkg -l`` keyword filter for installed security tools.
3. **.venv libraries** — ``pip list --format json`` from the active venv
   interpreter, so the AI knows which Python libraries it can import.

The registry is persisted to ``data/tool_registry.json`` for fast reload and
exposes:

- ``search(query, limit)``  — scored search across name/description/usage/domain.
- ``tools_for_domain(domain)`` — tools relevant to a phase (wifi/ble/...).
- ``context_block(domain, limit)`` — a compact text block injected into AI
  prompts so the models *know which tools are available and how to call them*.

This is the bridge the MCP server (``core/mcp_server.py``) and the AI backend
(``core/ai_backend.py``) both read from.
"""

import json
import logging
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
TOOLBOXES_DIR = PROJECT_ROOT / "toolboxes"
DATA_DIR = PROJECT_ROOT / "data"
REGISTRY_PATH = DATA_DIR / "tool_registry.json"

# Curated pentest tool allowlist — resolved against PATH via shutil.which so
# only *actually installed* tools are listed. Grouped by domain for the AI.
KALI_TOOL_ALLOWLIST: Dict[str, List[str]] = {
    "wifi": ["aircrack-ng", "airodump-ng", "aireplay-ng", "airbase-ng", "airmon-ng",
             "wifite", "wifiphisher", "wifipumpkin3", "reaver", "bully", "wash",
             "hcxdumptool", "hcxhashtool", "hcxpcapngtool", "hcxtools",
             "hostapd", "dnsmasq", "wpa_supplicant", "iw",
             "mdk3", "mdk4", "eapmd5pass", "lighttpd", "cowpatty", "genpmk",
             # mt7921e-specific MCP functions (resolved through
             # core.modules.mt7921e_tools, not as standalone binaries).
             "mt7921e.detect", "mt7921e.test_injection", "mt7921e.set_channel",
             "mt7921e.set_txpower", "mt7921e.inject_frame"],
    "ble": ["bluetoothctl", "hcitool", "gatttool", "bettercap", "btmon"],
    "osint": ["sherlock", "maigret", "holehe", "phoneinfoga", "toutatis", "nexfil",
              "theHarvester", "subfinder", "amass", "maltego", "shodan", "recon-ng"],
    "post_exploitation": ["msfconsole", "msfvenom", "mimikatz", "linpeas",
                          "winpeas", "bloodhound", "crackmapexec", "impacket-smbexec",
                          "impacket-secretsdump", "psexec.py", "evil-winrm",
                          "proxychains", "chisel", "ligolo-ng"],
    "c2": ["sliver", "havoc", "cobalt", "merlin", "mythic"],
    "exploit": ["searchsploit", "exploitdb", "nmap", "masscan", "sqlmap", "nikto",
               "nuclei", "gobuster", "ffuf", "wfuzz", "hydra", "john", "hashcat",
               "metasploit", "msfpc"],
    "recon": ["nmap", "masscan", "rustscan", "naabu", "dnsenum", "dnsrecon",
              "fierce", "theHarvester", "subfinder", "amass"],
    "web": ["sqlmap", "nikto", "nuclei", "gobuster", "ffuf", "wfuzz", "burpsuite",
            "wpscan", "whatweb", "dirb"],
    "mobile": ["frida", "objection", "drozer", "apktool", "jadx", "mobSF"],
}

# dpkg packages whose names/descriptions match these tokens are collected as
# installed Kali tooling (fallback breadth beyond the allowlist).
DPKG_KEYWORDS = (
    "exploit", "scan", "pentest", "pentest", "hack", "wireless", "wifi",
    "bluetooth", "ble", "osint", "recon", "metasploit", "nmap", "sqlmap",
    "burp", "hydra", "john", "hashcat", "frida", "aircrack", "sniffer",
)

_README_NAMES = ("README.md", "README.rst", "README.txt", "README",
                 "readme.md", "readme")


def _read_text(path: Path, limit: int = 8000) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")[:limit]
    except Exception:
        return ""


def _extract_description(readme: str) -> str:
    """First meaningful paragraph (skip title lines / badges)."""
    lines = []
    for ln in readme.splitlines():
        s = ln.strip()
        if not s:
            if lines:
                break
            continue
        if s.startswith("#") or s.startswith("![") or s.startswith("[!") \
                or s.startswith("<") or s.startswith("|"):
            # skip headings, badges, tables, HTML — but keep going until prose
            continue
        lines.append(s)
        if len(lines) >= 3:
            break
    return " ".join(lines)[:300]


_USAGE_HEADERS = re.compile(r"^#{1,6}\s*(usage|install|how to run|getting started|examples?)\b",
                            re.IGNORECASE)
_CMD_LINE = re.compile(r"^\s*(\$|>)\s*(.+)")            # $ cmd  / > cmd
_BARE_CMD = re.compile(r"^\s*((?:python|python3|pip|pip3|./|sudo|bash|sh|git|make)\s+\S.*)")


def _extract_usage(readme: str, limit: int = 8) -> List[str]:
    """Pull likely usage command lines from a README."""
    out: List[str] = []
    in_usage = False
    in_fence = False
    for ln in readme.splitlines():
        s = ln.rstrip()
        if s.strip().startswith("```"):
            in_fence = not in_fence
            continue
        if _USAGE_HEADERS.match(s):
            in_usage = True
            continue
        if in_usage and s.strip().startswith("#") and _USAGE_HEADERS.match(s) is None:
            # next heading ends the usage section
            if out:
                in_usage = False
        if in_usage or in_fence:
            m = _CMD_LINE.match(s)
            if m:
                out.append(m.group(2).strip())
            else:
                m2 = _BARE_CMD.match(s)
                if m2:
                    out.append(m2.group(1).strip())
        if len(out) >= limit:
            break
    # Dedup preserving order
    seen = set()
    uniq = []
    for c in out:
        if c not in seen:
            seen.add(c)
            uniq.append(c)
    return uniq[:limit]


def _detect_language(path: Path) -> str:
    counts: Dict[str, int] = {}
    try:
        for p in path.rglob("*"):
            if not p.is_file() or ".git" in p.parts:
                continue
            ext = p.suffix.lower()
            if ext == ".py":
                counts["python"] = counts.get("python", 0) + 1
            elif ext == ".sh":
                counts["shell"] = counts.get("shell", 0) + 1
            elif ext == ".js":
                counts["javascript"] = counts.get("javascript", 0) + 1
            elif ext == ".go":
                counts["go"] = counts.get("go", 0) + 1
            elif ext == ".c":
                counts["c"] = counts.get("c", 0) + 1
            elif ext in (".cpp", ".cc"):
                counts["cpp"] = counts.get("cpp", 0) + 1
            elif ext == ".rs":
                counts["rust"] = counts.get("rust", 0) + 1
    except Exception:
        pass
    if not counts:
        return "unknown"
    return max(counts, key=counts.get)


def _entry_points(path: Path) -> List[str]:
    """Detect runnable entry points (shell scripts, console_scripts, bins)."""
    eps: List[str] = []
    try:
        for p in path.iterdir():
            if not p.is_file():
                continue
            if p.suffix == ".sh":
                eps.append(f"./{p.name}")
        # setup.py / pyproject console_scripts
        for fn in ("setup.py", "pyproject.toml"):
            fp = path / fn
            if fp.exists():
                txt = _read_text(fp, 4000)
                for m in re.finditer(r'console_scripts.*?["\']([^"\']+)["\']', txt, re.S):
                    eps.append(m.group(1))
        pkg = path / "package.json"
        if pkg.exists():
            try:
                data = json.loads(pkg.read_text(errors="replace"))
                for b in (data.get("bin") or {}).keys():
                    eps.append(b)
            except Exception:
                pass
        mk = path / "Makefile"
        if mk.exists():
            for line in _read_text(mk, 3000).splitlines():
                if re.match(r"^([a-zA-Z0-9_.-]+):\s", line):
                    eps.append(f"make {line.split(':')[0]}")
    except Exception:
        pass
    return list(dict.fromkeys(eps))[:8]


def _parse_toolbox_repo(domain: str, repo_dir: Path) -> Optional[Dict[str, Any]]:
    owner_repo = repo_dir.name  # <owner>__<repo>
    if "__" in owner_repo:
        owner, repo = owner_repo.split("__", 1)
    else:
        owner, repo = "", owner_repo
    # Find README
    readme_path = None
    for cand in _README_NAMES:
        fp = repo_dir / cand
        if fp.exists():
            readme_path = fp
            break
    if readme_path is None:
        # case-insensitive search
        try:
            for p in repo_dir.iterdir():
                if p.is_file() and p.name.lower().startswith("readme"):
                    readme_path = p
                    break
        except Exception:
            pass
    readme = _read_text(readme_path, 12000) if readme_path else ""
    description = _extract_description(readme) or repo.replace("-", " ").replace("_", " ")
    usage = _extract_usage(readme)
    return {
        "name": repo,
        "source": "toolbox",
        "domain": domain,
        "owner": owner,
        "path": str(repo_dir),
        "url": f"https://github.com/{owner}/{repo}" if owner else "",
        "description": description,
        "usage": usage,
        "entry_points": _entry_points(repo_dir),
        "language": _detect_language(repo_dir),
    }


def _scan_toolboxes(root: Path = TOOLBOXES_DIR) -> List[Dict[str, Any]]:
    tools: List[Dict[str, Any]] = []
    if not root.exists():
        return tools
    for domain_dir in sorted(root.iterdir()):
        if not domain_dir.is_dir():
            continue
        domain = domain_dir.name
        for repo_dir in sorted(domain_dir.iterdir()):
            if not repo_dir.is_dir():
                continue
            if repo_dir.name in ("MANIFEST.txt", ".git"):
                continue
            t = _parse_toolbox_repo(domain, repo_dir)
            if t:
                tools.append(t)
    return tools


def _scan_kali() -> List[Dict[str, Any]]:
    tools: List[Dict[str, Any]] = []
    # 1) curated allowlist via shutil.which (PATH-aware → only installed)
    for domain, bins in KALI_TOOL_ALLOWLIST.items():
        for b in bins:
            which = shutil.which(b)
            if which:
                tools.append({
                    "name": b,
                    "source": "kali",
                    "domain": domain,
                    "path": which,
                    "description": f"Installed Kali tool ({b}) — on PATH.",
                    "usage": [f"{b} --help"],
                    "entry_points": [b],
                    "language": "binary",
                })
    # 2) dpkg keyword breadth (dedup by name)
    seen = {t["name"] for t in tools}
    if shutil.which("dpkg"):
        try:
            p = subprocess.run(
                ["dpkg-query", "-W", "-f=${Package}\t${Description}\n"],
                capture_output=True, text=True, timeout=30,
            )
            for line in (p.stdout or "").splitlines():
                if "\t" not in line:
                    continue
                pkg, desc = line.split("\t", 1)
                low = (pkg + " " + desc).lower()
                if any(k in low for k in DPKG_KEYWORDS) and pkg not in seen:
                    seen.add(pkg)
                    tools.append({
                        "name": pkg,
                        "source": "kali-dpkg",
                        "domain": "misc",
                        "path": f"dpkg:{pkg}",
                        "description": desc.strip()[:200],
                        "usage": [f"dpkg -L {pkg}"],
                        "entry_points": [],
                        "language": "package",
                    })
        except Exception as e:
            logger.debug(f"dpkg scan failed: {e}")
    return tools


def _scan_venv() -> List[Dict[str, Any]]:
    tools: List[Dict[str, Any]] = []
    py = sys.executable
    try:
        p = subprocess.run(
            [py, "-m", "pip", "list", "--format=json"],
            capture_output=True, text=True, timeout=60,
        )
        for item in json.loads(p.stdout or "[]"):
            name = item.get("name", "")
            ver = item.get("version", "")
            if not name:
                continue
            tools.append({
                "name": name,
                "source": "venv",
                "domain": "python-lib",
                "path": f"{py}::{name}",
                "description": f"Python library in .venv: {name} {ver}",
                "usage": [f"import {name.replace('-', '_')}"],
                "entry_points": [],
                "language": "python",
            })
    except Exception as e:
        logger.debug(f"pip list failed: {e}")
    return tools


def _score(tool: Dict[str, Any], query: str) -> int:
    q = query.lower()
    name = (tool.get("name") or "").lower()
    desc = (tool.get("description") or "").lower()
    dom = (tool.get("domain") or "").lower()
    usage = " ".join(tool.get("usage") or []).lower()
    score = 0
    if q in name:
        score += 30
    if name.startswith(q):
        score += 15
    if q in desc:
        score += 12
    if q in dom:
        score += 8
    if q in usage:
        score += 6
    return score


class ToolRegistry:
    """Build/load/query the unified tool catalog."""

    def __init__(self, path: Optional[Path] = None):
        self.path = Path(path) if path else REGISTRY_PATH
        self.tools: List[Dict[str, Any]] = []
        self._by_name: Dict[str, Dict[str, Any]] = {}

    # ------------------------------------------------------------------
    # Build / load
    # ------------------------------------------------------------------
    def build(self) -> Dict[str, Any]:
        """Scan all three sources and persist. Returns summary stats."""
        tb = _scan_toolboxes()
        kali = _scan_kali()
        venv = _scan_venv()
        self.tools = tb + kali + venv
        self._reindex()
        self._save()
        stats = {
            "total": len(self.tools),
            "toolbox": len(tb),
            "kali": len(kali),
            "venv": len(venv),
            "by_domain": self._by_domain_counts(),
        }
        logger.info("tool registry built: %s", stats)
        return stats

    def load(self) -> List[Dict[str, Any]]:
        if self.tools:
            return self.tools
        if self.path.exists():
            try:
                self.tools = json.loads(self.path.read_text(encoding="utf-8"))
                self._reindex()
            except Exception as e:
                logger.warning(f"registry load failed: {e}")
                self.tools = []
        if not self.tools:
            self.build()
        return self.tools

    def _save(self):
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(
                json.dumps(self.tools, indent=2), encoding="utf-8"
            )
        except Exception as e:
            logger.warning(f"registry save failed: {e}")

    def _reindex(self):
        self._by_name = {}
        for t in self.tools:
            # unique key: source:name (names can collide across sources)
            key = f"{t.get('source')}:{t.get('name')}"
            self._by_name[key] = t

    def _by_domain_counts(self) -> Dict[str, int]:
        out: Dict[str, int] = {}
        for t in self.tools:
            d = t.get("domain", "misc")
            out[d] = out.get(d, 0) + 1
        return dict(sorted(out.items(), key=lambda x: -x[1]))

    # ------------------------------------------------------------------
    # Query
    # ------------------------------------------------------------------
    def search(self, query: str, limit: int = 20) -> List[Dict[str, Any]]:
        if not query:
            return self.tools[:limit]
        scored = [(_score(t, query), t) for t in self.tools]
        scored = [(s, t) for s, t in scored if s > 0]
        scored.sort(key=lambda x: -x[0])
        return [t for _, t in scored[:limit]]

    def tools_for_domain(self, domain: str, limit: int = 30) -> List[Dict[str, Any]]:
        out = [t for t in self.tools if t.get("domain") == domain]
        # toolbox first, then kali, then venv; stable
        order = {"toolbox": 0, "kali": 1, "kali-dpkg": 2, "venv": 3}
        out.sort(key=lambda t: order.get(t.get("source"), 9))
        return out[:limit]

    def get(self, key: str) -> Optional[Dict[str, Any]]:
        self.load()
        return self._by_name.get(key)

    def context_block(self, domain: Optional[str] = None, limit: int = 25) -> str:
        """Compact text block for AI prompt injection.

        Lists the most relevant available tools (name, source, one-line
        description, first usage hint) so the model knows what it can call.
        """
        self.load()
        if not self.tools:
            return ""
        if domain:
            # Prefer directly-callable installed binaries (kali/kali-dpkg) so
            # the model recommends real commands, then toolbox repos, then libs.
            pool = [t for t in self.tools if t.get("domain") == domain]
            order = {"kali": 0, "kali-dpkg": 1, "toolbox": 2, "venv": 3}
            pool.sort(key=lambda t: order.get(t.get("source"), 9))
            base = pool[:limit]
        else:
            base = self.tools[:limit]
        if not base:
            return ""
        lines = ["AVAILABLE TOOLS YOU CAN CALL/RECOMMEND (already on this host):"]
        for t in base:
            name = t.get("name", "?")
            src = t.get("source", "?")
            desc = (t.get("description") or "").replace("\n", " ").strip()
            if len(desc) > 110:
                desc = desc[:110] + "…"
            usage = (t.get("usage") or [""])[0]
            lines.append(f"- [{src}] {name}: {desc}")
            if usage:
                lines.append(f"    usage: {usage}")
        lines.append(
            "When recommending a step, prefer tools listed here and give the "
            "exact command. If a needed tool is missing, say so explicitly."
        )
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI: build / search / dump
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import argparse
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    ap = argparse.ArgumentParser(description="KFIOSA tool registry")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("build", help="scan toolboxes + Kali + venv")
    s = sub.add_parser("search", help="search tools")
    s.add_argument("query")
    s.add_argument("--limit", type=int, default=20)
    d = sub.add_parser("domain", help="list tools for a domain")
    d.add_argument("domain")
    sub.add_parser("stats", help="print registry stats")
    args = ap.parse_args()

    reg = ToolRegistry()
    if args.cmd == "build":
        print(json.dumps(reg.build(), indent=2))
    elif args.cmd == "search":
        reg.load()
        for t in reg.search(args.query, args.limit):
            print(f"[{t['source']}] {t['name']} ({t.get('domain')}): "
                  f"{(t.get('description') or '')[:80]}")
    elif args.cmd == "domain":
        for t in reg.tools_for_domain(args.domain):
            print(f"[{t['source']}] {t['name']}")
    elif args.cmd == "stats":
        reg.load()
        print(json.dumps({"total": len(reg.tools),
                          "by_domain": reg._by_domain_counts()}, indent=2))