"""core.catalog.os_generate — catalog every installed OS package.

Scans the local Debian/Kali/Parrot package database via ``dpkg-query``
and emits ``catalog/kali_<name>.json`` entries in the existing v1.1.0
schema.  Each entry captures:

  * package name, version, architecture, source
  * installed binaries / commands (from ``dpkg -L``)
  * man-page synopsis (from ``whatis``/``man -f``)
  * short and long descriptions from apt cache
  * install command, tags, metapackage membership

The module is safe to run repeatedly: it updates entries that already
exist and creates entries for newly-installed packages.  It never
removes catalog files.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple


def _run(cmd: List[str], timeout: int = 60) -> Tuple[int, str, str]:
    try:
        r = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            check=False,
        )
        return r.returncode, r.stdout, r.stderr
    except Exception as e:  # noqa: BLE001
        return -1, "", str(e)


def _dpkg_list() -> List[Tuple[str, str, str, str]]:
    """Return [(name, version, arch, description), ...] for installed pkgs."""
    rc, out, _err = _run([
        "dpkg-query", "-W", "-f=${Package}\t${Version}\t${Architecture}\t${Description}\n",
    ])
    if rc != 0:
        return []
    rows = []
    for line in out.strip().splitlines():
        parts = line.split("\t", 3)
        if len(parts) < 4:
            continue
        name, version, arch, desc = parts
        rows.append((name.strip(), version.strip(), arch.strip(), desc.strip()))
    return rows


def _apt_show(name: str) -> Dict[str, Any]:
    """Return apt-cache show fields as a dict."""
    rc, out, _err = _run(["apt-cache", "show", name])
    if rc != 0:
        return {}
    fields: Dict[str, List[str]] = {}
    current_key: Optional[str] = None
    for line in out.splitlines():
        if not line:
            current_key = None
            continue
        if line.startswith(" "):
            if current_key is not None:
                fields[current_key][-1] += "\n" + line.strip()
            continue
        if ":" in line:
            k, v = line.split(":", 1)
            k = k.strip()
            v = v.strip()
            fields.setdefault(k, []).append(v)
            current_key = k
    # Flatten single-value fields
    return {k: v[0] if len(v) == 1 else v for k, v in fields.items()}


def _dpkg_files(name: str) -> List[str]:
    """Return files shipped by the package (only top-level relevant paths)."""
    rc, out, _err = _run(["dpkg", "-L", name])
    if rc != 0:
        return []
    files = []
    for line in out.strip().splitlines():
        line = line.strip()
        if not line or line.endswith("/"):
            continue
        if line.startswith(("/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/")):
            files.append(line)
        elif line.startswith("/usr/share/man/") and line.endswith(".gz"):
            files.append(line)
    return files


def _command_help(path: str) -> str:
    """Try to grab a short help line from a binary."""
    for args in ([path, "--help"], [path, "-h"]):
        rc, out, _err = _run(args, timeout=5)
        if rc == 0 or out:
            first = out.strip().splitlines()[0] if out.strip() else ""
            if first and len(first) < 200:
                return first
    return ""


def _whatis(name: str) -> str:
    """Return the whatis synopsis for a command name if available."""
    rc, out, _err = _run(["whatis", "-l", name], timeout=10)
    if rc == 0 and out.strip():
        line = out.strip().splitlines()[0]
        # whatis output: "name (section) - description"
        m = re.search(r"-\s+(.*)", line)
        if m:
            return m.group(1).strip()
    return ""


def _binaries_for_package(name: str, files: List[str]) -> List[Dict[str, Any]]:
    """Build command metadata for every binary shipped by the package."""
    commands: List[Dict[str, Any]] = []
    seen: Set[str] = set()
    for f in files:
        if not f.startswith(("/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/")):
            continue
        bin_name = Path(f).name
        if bin_name in seen:
            continue
        seen.add(bin_name)
        synopsis = _whatis(bin_name)
        help_line = _command_help(f) if not synopsis else ""
        commands.append({
            "name": bin_name,
            "path": f,
            "description": synopsis or help_line or f"Binary from {name}",
            "usage": f"{bin_name} [options] [args]",
            "arguments": [],
        })
    return commands


def _tags_for_package(name: str, apt: Dict[str, Any]) -> List[str]:
    """Derive tags from package name and section."""
    tags: List[str] = ["os-package"]
    section = apt.get("Section", "").lower()
    if "net" in section or "wireless" in name or "wifi" in name:
        tags.append("networking")
    if "sec" in section or "exploit" in name or "ploit" in name:
        tags.append("security")
    if "forensic" in name or "forensic" in section:
        tags.append("forensics")
    if "osint" in name or "recon" in name:
        tags.append("osint")
    if "post" in name or "exploit" in name:
        tags.append("post-exploit")
    if name.startswith("lib"):
        tags.append("library")
    if "python" in name or "python3-" in name:
        tags.append("python")
    return tags


def build_os_entry(name: str, version: str, arch: str, short_desc: str,
                   catalog_dir: Path) -> Dict[str, Any]:
    """Build a complete catalog entry for an installed OS package."""
    apt = _apt_show(name)
    files = _dpkg_files(name)
    commands = _binaries_for_package(name, files)
    long_desc = apt.get("Description", short_desc)
    homepage = apt.get("Homepage", "")
    source = apt.get("Source", name)

    entry: Dict[str, Any] = {
        "id": f"kali:{name}",
        "kind": "kali_source_package",
        "name": name,
        "title": name,
        "summary": short_desc,
        "description": long_desc,
        "version": version,
        "architectures": [arch],
        "homepage": homepage,
        "repository": homepage,
        "source_package": source,
        "metapackages": [],
        "install": {"apt": f"sudo apt install {name}"},
        "packages": [{"name": name}],
        "commands": commands,
        "files": files[:200],  # cap to keep JSON small
        "tags": _tags_for_package(name, apt),
        "metadata_status": "os_generated",
        "schema_version": "1.1.0",
        "attack_surface": "local",
        "phase_hint": "install",
        "requires_hardware": False,
    }
    return entry


def _security_relevant_filter(rows):
    """Keep only packages that are likely useful for KFIOSA's purpose.

    The full ``dpkg-query`` output is 7,000+ rows; cataloging every
    one is expensive (dpkg -L + whatis for each) and the catalog file
    would balloon.  Filter on substrings: wifi, ble, exploit, nmap,
    python3-*, forensic, etc.  This is a heuristic; users can run
    ``--all`` to skip the filter.
    """
    keywords = (
        "wifi", "ble", "bluetooth", "nmap", "metasploit", "exploit",
        "nuclei", "hydra", "burp", "sqlmap", "wps", "aircrack",
        "scapy", "kismet", "ettercap", "responder", "impacket",
        "bloodhound", "crackmapexec", "netexec", "mimikatz",
        "forensic", "volatility", "sleuthkit", "foremost",
        "stego", "binwalk", "exif", "sdr", "hackrf", "ubertooth",
        "tshark", "wireshark", "tcpdump", "nethogs", "ngrep",
        "masscan", "zmap", "zgrab", "curl", "ncat", "socat",
        "proxychains", "tor", "i2p", "frida", "apktool", "jadx",
        "objection", "mobsf", "androguard", "ghidra", "radare",
        "rizin", "gdb", "strace", "ltrace", "binutils",
        "openssl", "gnutls", "nss", "krb5", "samba", "ldap",
        "postgresql", "mysql", "sql", "python3-", "ruby",
        "perl", "golang", "rustc", "node", "ruby-", "golang-",
        "osint", "shodan", "censys", "dmitry", "maltego",
        "recon-ng", "spiderfoot", "amass", "subfinder",
        "theharvester", "sherlock", "phoneinfoga",
        "wifiphisher", "fluxion", "airgeddon", "bettercap",
        "hostapd", "wpa", "wps", "reaver", "wash", "pixie",
        "cowpatty", "pyrit", "fern", "john", "hashcat",
        "hydra", "medusa", "patator", "cewl", "crunch",
        "rsmangler", "cewl", "dns", "whois", "dig", "host",
        "nslookup", "fierce", "dnsmap", "dnsenum", "dnsrecon",
        "sublist3r", "subjack", "subover",
    )
    out = []
    for row in rows:
        name = row[0]
        n = name.lower()
        if any(k in n for k in keywords):
            out.append(row)
    return out


def generate_all(catalog_dir: Path, *, all_pkgs: bool = False) -> Dict[str, Any]:
    """Generate/update catalog entries for every installed OS package."""
    catalog_dir = Path(catalog_dir)
    catalog_dir.mkdir(parents=True, exist_ok=True)
    rows = _dpkg_list()
    if not all_pkgs:
        rows = _security_relevant_filter(rows)
    created = 0
    updated = 0
    failed = 0
    for name, version, arch, short_desc in rows:
        try:
            entry = build_os_entry(name, version, arch, short_desc, catalog_dir)
            safe_name = re.sub(r"[^a-zA-Z0-9+.-]", "_", name)
            path = catalog_dir / f"kali_{safe_name}.json"
            exists = path.exists()
            path.write_text(
                json.dumps(entry, indent=2, ensure_ascii=False, default=str),
                encoding="utf-8",
            )
            if exists:
                updated += 1
            else:
                created += 1
        except Exception:  # noqa: BLE001
            failed += 1
    return {
        "ok": True,
        "total_packages": len(rows),
        "created": created,
        "updated": updated,
        "failed": failed,
        "catalog_dir": str(catalog_dir),
    }


if __name__ == "__main__":
    import sys
    out_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("catalog")
    all_flag = "--all" in sys.argv
    result = generate_all(out_dir, all_pkgs=all_flag)
    print(json.dumps(result, indent=2))