#!/usr/bin/env python3
"""scripts/enhance_catalog_internet.py — fill every catalog entry with
real, internet/local-sourced documentation detail.

Sources (in order, never fabricates flags/CVEs/versions):
  github_*.json
    1. Local clone under toolboxes/*/<owner>__<repo>/
    2. raw.githubusercontent.com README (HEAD/main/master)
    3. Offline degrade from existing summary/description
  kali_*.json
    1. Local `man <cmd>` when available
    2. manpages.debian.org HTML
    3. Offline degrade from apt description / usage line

Fills / upgrades:
  documentation.readme, arguments, examples, how_to_use, when_to_use,
  why_to_use, usage_sections; top-level summary (if generic),
  use_cases, command_examples; sentinels _kfiosa_enhanced_v3 +
  _enhanced_via.

Usage:
  python3 scripts/enhance_catalog_internet.py              # all
  python3 scripts/enhance_catalog_internet.py --limit 50
  python3 scripts/enhance_catalog_internet.py --only github
  python3 scripts/enhance_catalog_internet.py --force      # re-do v3
  python3 scripts/enhance_catalog_internet.py --workers 24
"""
from __future__ import annotations

import argparse
import concurrent.futures
import html
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "catalog"
TOOLBOXES = ROOT / "toolboxes"
UA = "kfiosa-catalog-enhancer/1.0 (+lab; offline-first)"

# ---------------------------------------------------------------------------
# HTTP / filesystem helpers
# ---------------------------------------------------------------------------

def _http_get(url: str, timeout: float = 12.0) -> Optional[str]:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read(400_000)  # cap ~400KB
            return raw.decode("utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        return None


def _read_local_readme(dir_path: Path) -> Optional[str]:
    for name in (
        "README.md", "README.MD", "Readme.md", "readme.md",
        "README.rst", "README.txt", "README", "docs/README.md",
    ):
        p = dir_path / name
        if p.is_file():
            try:
                text = p.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if len(text.strip()) > 40:
                return text
    return None


def _index_toolboxes() -> Dict[str, Path]:
    """Map 'owner/repo' and 'owner__repo' and lowercase variants → path."""
    idx: Dict[str, Path] = {}
    if not TOOLBOXES.is_dir():
        return idx
    for cat in TOOLBOXES.iterdir():
        if not cat.is_dir():
            continue
        for d in cat.iterdir():
            if not d.is_dir() or "__" not in d.name:
                continue
            owner, repo = d.name.split("__", 1)
            for key in (
                f"{owner}/{repo}",
                f"{owner}__{repo}",
                f"{owner.lower()}/{repo}",
                f"{owner.lower()}/{repo.lower()}",
                d.name,
            ):
                idx.setdefault(key, d)
    return idx


# ---------------------------------------------------------------------------
# README / man parsing
# ---------------------------------------------------------------------------

_FLAG_LINE = re.compile(
    r"^\s{0,8}"
    r"(?P<flags>(?:-{1,2}[\w][\w-]*)(?:\s*,\s*-{1,2}[\w][\w-]*)*)"
    r"(?:\s+(?P<meta>[A-Z][\w./:<>=|-]*|\[[^\]]+\]|<[^>]+>))?"
    r"\s{2,}(?P<desc>\S.*)$",
    re.M,
)
_FLAG_INLINE = re.compile(
    r"(?P<flags>(?:-{1,2}[\w][\w-]{1,40})(?:\s*/\s*-{1,2}[\w][\w-]{1,40})?)"
    r"(?:\s+(?P<meta>[A-Z_]{2,}|<[^>]+>|\[[^\]]+\]))?"
    r"\s*[:\-–—]\s+(?P<desc>[^\n]{8,180})",
)
_ARGPARSE_ADD = re.compile(
    r"""add_argument\(\s*['"](-{1,2}[\w-]+)['"]"""
    r"""(?:\s*,\s*['"](-{1,2}[\w-]+)['"])?"""
    r"""[^)]*?help\s*=\s*['"]([^'"]{3,200})['"]""",
    re.S,
)
_CODE_BLOCK = re.compile(r"```(?:bash|sh|shell|console|cmd|powershell|text|)?\s*\n(.*?)```", re.S | re.I)
_CMD_LINE = re.compile(
    r"^\s*(?:\$\s*|%\s*|>\s*|#\s*)?"
    r"((?:sudo\s+)?[\w./+-]+(?:\s+(?:-{1,2}[\w-]+(?:=[^\s]+)?|[^\s`|;&><]{1,80})){0,20})",
    re.M,
)
_HTML_TAG = re.compile(r"<[^>]+>")
_WS = re.compile(r"\s+")


def _strip_md(text: str) -> str:
    text = _HTML_TAG.sub(" ", text)
    text = re.sub(r"```.*?```", " ", text, flags=re.S)
    text = re.sub(r"`([^`]+)`", r"\1", text)
    text = re.sub(r"!\[[^\]]*\]\([^)]*\)", " ", text)
    text = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", text)
    text = re.sub(r"^#+\s*", "", text, flags=re.M)
    text = re.sub(r"[*_~]{1,3}", "", text)
    text = html.unescape(text)
    return text


def _first_paragraph(text: str, max_chars: int = 900) -> str:
    clean = _strip_md(text)
    # Drop badge/HTML-heavy leading noise
    paras = [p.strip() for p in re.split(r"\n\s*\n", clean) if p.strip()]
    for p in paras:
        p = _WS.sub(" ", p).strip()
        if len(p) < 40:
            continue
        if p.count("http") > 4:
            continue
        if re.match(r"^[\W\d]+$", p):
            continue
        # skip badge/logo-only leftovers
        if re.match(r"^(img|image|logo|badge|build|coverage)\b", p, re.I):
            continue
        # skip pure markdown link soup
        if p.count("](") > 2:
            continue
        return p[:max_chars]
    return (paras[0][:max_chars] if paras else "")[:max_chars]


_MIME_FLAG_DENY = {
    "-type", "-disposition", "-length", "-encoding", "-transfer",
    "-agent", "-control", "-range", "-match", "-none", "-data",
    "-form", "-multipart", "-boundary",
}


def _is_plausible_flag(name: str) -> bool:
    """Reject CVE fragments, MIME headers, and other non-CLI noise."""
    if not name or not name.startswith("-"):
        return False
    if len(name) > 36:
        return False
    bare = name.lstrip("-")
    if not bare:
        return False
    # single-letter short flags
    if len(bare) == 1:
        return bare.isalpha() and bare in "hvqnpVfdxXoOaAtTuUiIcCsSpPrRbBeElLmMwWyYgGkK"
    # must start with a letter
    if not bare[0].isalpha():
        return False
    # reject pure numbers / CVE-ish (-2025-49113)
    if re.fullmatch(r"[\d._-]+", bare):
        return False
    if re.match(r"^\d{4}-", bare):
        return False
    # MIME / HTTP header noise
    if name.lower() in _MIME_FLAG_DENY or bare.lower() in {
        "type", "disposition", "length", "encoding", "boundary",
        "multipart", "form-data", "attachment",
    }:
        return False
    # long flags should look like kebab-case words
    if name.startswith("--"):
        if not re.fullmatch(r"--[a-zA-Z][\w-]{1,34}", name):
            return False
        # reject camelCase MIME like Content-Type fragments already handled
        if bare.count("-") == 0 and bare[0].isupper() and any(c.islower() for c in bare[1:]):
            # e.g. Disposition — not a CLI flag
            return False
    return True


def _extract_args_from_text(text: str) -> List[Dict[str, str]]:
    """Parse CLI flags + descriptions from README/help/man text."""
    found: Dict[str, str] = {}

    def _add(flag: str, desc: str) -> None:
        flag = flag.strip().rstrip(",")
        if not _is_plausible_flag(flag) or flag in found:
            return
        desc = _WS.sub(" ", desc).strip()[:200]
        if len(desc) < 3:
            return
        found[flag] = desc

    for m in _FLAG_LINE.finditer(text):
        flags = [f.strip() for f in m.group("flags").split(",") if f.strip()]
        desc = m.group("desc") or ""
        for f in flags:
            _add(f, desc)

    for m in _FLAG_INLINE.finditer(text):
        flags = re.findall(r"-{1,2}[\w][\w-]*", m.group("flags"))
        desc = m.group("desc") or ""
        for f in flags:
            _add(f, desc)

    for m in _ARGPARSE_ADD.finditer(text):
        for f in (m.group(1), m.group(2)):
            if f:
                _add(f, m.group(3))

    # Prefer lines that look like help/usage option tables (double-dash preferred)
    for line in text.splitlines():
        m = re.match(
            r"^\s{0,6}(--[\w][\w-]{1,40})"
            r"(?:\s*,\s*(-[\w]))?"
            r"(?:\s+[A-Z_<\[].*?)?"
            r"\s{2,}(.{8,200})$",
            line,
        )
        if not m:
            m = re.match(
                r"^\s{0,6}(-[\w])"
                r"(?:\s*,\s*(--[\w][\w-]{1,40}))?"
                r"(?:\s+[A-Z_<\[].*?)?"
                r"\s{2,}(.{8,200})$",
                line,
            )
        if not m:
            continue
        groups = [g for g in m.groups() if g]
        desc = groups[-1]
        for f in groups[:-1]:
            if f.startswith("-"):
                _add(f, desc)

    out: List[Dict[str, str]] = []
    for name in sorted(found.keys(), key=lambda s: (s.lstrip("-").lower(), s)):
        out.append({"name": name, "description": found[name], "source": "docs"})
        if len(out) >= 60:
            break
    return out


_SHELL_BIN_HINT = re.compile(
    r"^(?:sudo\s+)?(?:python3?|ruby|perl|node|go|cargo|dotnet|java|bash|sh|zsh|"
    r"nmap|curl|wget|git|docker|kubectl|ssh|nc|ncat|msfconsole|msfvenom|"
    r"aircrack-ng|airodump-ng|aireplay-ng|hashcat|john|sqlmap|hydra|"
    r"[\w][\w./+-]*\.(?:py|sh|rb|pl|go|js|ps1)|"
    r"\./[\w./+-]+|"
    r"[\w][\w-]{1,40})\b",
    re.I,
)


def _looks_like_command(line: str) -> bool:
    s = line.strip().rstrip("\\").strip()
    if len(s) < 4 or len(s) > 240:
        return False
    if s.startswith("#") or s.startswith("//") or s.startswith("*"):
        return False
    # passwd-file / uname / path-only noise
    if re.match(r"^[\w.-]+::\d+:\d+:", s):  # passwd line
        return False
    if re.match(r"^Linux\s+\S+\s+\d", s):  # uname -a
        return False
    if re.fullmatch(r"[\w./-]+/", s):  # directory alone
        return False
    if re.fullmatch(r"[A-Za-z0-9._/-]+\.(txt|md|json|yml|yaml|csv|log)", s):
        return False
    # man-page NAME line: "nmap - Network exploration tool..."
    if re.match(r"^[\w.+-]+\s+-\s+[A-Za-z]", s) and not re.search(r"\s-", s[s.find(" - ") + 3:] if " - " in s else ""):
        # allow only if it also has flags after the description? usually no
        if not re.search(r"\s-{1,2}[\w]", s):
            return False
    # man header / version banner
    if re.search(r"\b(?:January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{4}\b", s):
        return False
    if re.search(r"\([18]\)\s*$", s):  # man section footer
        return False
    # prose / markdown leftovers
    if re.match(
        r"^(the|this|when|where|which|that|from|with|using|in|for|and|or|"
        r"note|example|output|result|response|see|see also)\b",
        s, re.I,
    ):
        return False
    if s.count("`") >= 2 and not s.startswith("`"):
        return False
    if not _SHELL_BIN_HINT.match(s.lstrip("$").strip()):
        return False
    # reject pure English sentences ending with period
    if s.endswith(".") and " -" not in s and not re.search(r"[/\\]", s):
        words = s.split()
        if len(words) > 8:
            return False
    # "Toolname is a ..." prose sentences starting with capital tool word
    if re.match(r"^[A-Z][\w.+-]*\s+(is|was|are|provides|uses|can|will|default)\b", s):
        return False
    # bare CVE titles / one-token labels
    if re.fullmatch(r"CVE-\d{4}-\d+.*", s, re.I) and " " not in s.strip()[12:]:
        if not re.search(r"[./]", s):
            return False
    # Prefer lines that look like invocations: flags, paths, or placeholders
    if not re.search(r"(?:\s-{1,2}[\w]|[<>{}]|\$[A-Z_]|https?://|/[\w]|=\S|\.(?:py|sh|rb|pl)\b)", s):
        # allow short binary-only if it's clearly a path or has args
        toks = s.split()
        if len(toks) == 1 and ("/" in toks[0] or toks[0].startswith("./")):
            return True
        if len(toks) < 2:
            return False
        # multi-word without flags often prose (e.g. "Nmap uses raw IP...")
        if not re.search(r"[/\\.<>=$]", s):
            return False
    return True


def _extract_examples(text: str, tool_hint: str = "") -> List[str]:
    examples: List[str] = []
    seen = set()
    for block in _CODE_BLOCK.findall(text):
        for line in block.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            line = re.sub(r"^\$\s*", "", line)
            line = re.sub(r"^>\s*", "", line)
            if not _looks_like_command(line):
                continue
            # install lines go to how_to, skip as command_examples unless tool itself
            low = line.lower()
            if any(low.startswith(p) for p in (
                "pip install", "pip3 install", "apt install", "apt-get ",
                "git clone", "docker pull", "npm install", "brew install",
            )):
                continue
            key = line.lower()
            if key in seen:
                continue
            seen.add(key)
            examples.append(line)
            if len(examples) >= 12:
                return examples
    # Fallback: any line starting with the tool name
    if tool_hint and len(examples) < 3:
        hint = tool_hint.lower()
        for line in text.splitlines():
            s = line.strip().lstrip("$").strip()
            if (s.lower().startswith(hint + " ") or s.lower() == hint) and _looks_like_command(s):
                if s.lower() not in seen and 3 < len(s) < 200:
                    seen.add(s.lower())
                    examples.append(s)
            if len(examples) >= 8:
                break
    return examples[:10]


def _usage_sections(text: str) -> List[str]:
    """Pull short usage bullets from README headings Usage/Options/Examples."""
    sections: List[str] = []
    for m in re.finditer(
        r"^#{1,3}\s+(Usage|Options|Installation|Features|Getting Started|"
        r"Quick\s*Start|Synopsis|Description|Examples?|How to)\s*$"
        r"([\s\S]{0,1200}?)(?=^#{1,3}\s+|\Z)",
        text,
        re.M | re.I,
    ):
        body = _strip_md(m.group(2))
        body = _WS.sub(" ", body).strip()
        if len(body) > 40:
            title = m.group(1).strip()
            sections.append(f"{title}: {body[:280]}")
        if len(sections) >= 6:
            break
    if not sections:
        for line in text.splitlines():
            if re.match(r"^\s*[-*+]\s+\S", line):
                bullet = _WS.sub(" ", _strip_md(line)).strip(" -*+")
                if 20 < len(bullet) < 200:
                    sections.append(bullet)
            if len(sections) >= 5:
                break
    return sections[:6]


def _sanitize_cmd(cmd: str) -> str:
    """Replace secrets-looking tokens with $KFIOSA_* placeholders."""
    cmd = re.sub(
        r"(?i)((?:--)?(?:password|passwd|token|api[_-]?key|secret))\s*[:=\s]\s*\S+",
        r"\1=$KFIOSA_SECRET",
        cmd,
    )
    # quoted password-like positional tokens after user@host patterns
    cmd = re.sub(r"'[^']{0,40}[Pp]ass[^']{0,40}'", "'$KFIOSA_SECRET'", cmd)
    cmd = re.sub(r"'P@ss[^']*'", "'$KFIOSA_SECRET'", cmd)
    cmd = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "$KFIOSA_TARGET_HOST", cmd)
    cmd = re.sub(r"https?://[^\s\"']+", "$KFIOSA_TARGET_URL", cmd)
    return cmd


# ---------------------------------------------------------------------------
# Prose generation (from real text only)
# ---------------------------------------------------------------------------

_GENERIC_SUMMARY_RE = re.compile(
    r"^(Index entry for|Repository indexing entry|Curated toolbox entry|"
    r"Kali source package|Package entry)",
    re.I,
)


def _how_to_use(name: str, summary: str, examples: List[str],
                install_bits: List[str], readme_para: str) -> str:
    parts: List[str] = []
    good_ex = [e for e in examples if _looks_like_command(e)]
    if install_bits:
        parts.append("Install/setup: " + "; ".join(install_bits[:2]) + ".")
    if good_ex:
        parts.append(f"Run the primary entrypoint as shown in upstream docs, e.g. `{good_ex[0]}`.")
        more = good_ex[1:3]
        if more:
            parts.append("Further invocations from upstream: " +
                         "; ".join(f"`{e}`" for e in more) + ".")
    if not good_ex and not install_bits:
        parts.append(
            f"Clone or install `{name}` from its upstream repository, then run "
            f"`{name} --help` (or the README entrypoint) to confirm flags."
        )
    # Prefer summary over raw readme for the descriptive tail (less noise)
    tail = summary if summary and not _is_generic_summary(summary) else readme_para
    if tail:
        tail = _WS.sub(" ", _strip_md(tail)).strip()
        if len(tail) > 40:
            parts.append(tail[:320].rstrip(".") + ".")
    return " ".join(parts)[:1200]


def _when_to_use(data: Dict[str, Any], summary: str, category: str) -> str:
    phase = data.get("phase_hint") or "any"
    attack = data.get("attack_surface") or []
    if isinstance(attack, list):
        attack_s = ", ".join(str(a) for a in attack[:4])
    else:
        attack_s = str(attack)
    base = (
        f"Use during the '{phase}' phase"
        + (f" against surfaces [{attack_s}]" if attack_s else "")
        + (f" in the {category} category" if category else "")
        + "."
    )
    if summary and not _GENERIC_SUMMARY_RE.match(summary):
        base += f" Fits when the engagement needs: {summary[:220].rstrip('.')}."
    return base[:700]


def _why_to_use(summary: str, readme_para: str, tags: List[str]) -> str:
    if readme_para and len(readme_para) > 40:
        return (
            "Prefer this tool based on upstream description: "
            + readme_para[:400].rstrip(".") + "."
        )
    if summary and not _GENERIC_SUMMARY_RE.match(summary):
        return "Prefer this tool because: " + summary[:400].rstrip(".") + "."
    tag_s = ", ".join(str(t) for t in (tags or [])[:5])
    return (
        "Use when its cataloged capabilities match the chain planner need"
        + (f" (tags: {tag_s})" if tag_s else "")
        + "."
    )


def _use_cases(name: str, category: str, summary: str,
               examples: List[str], phase: str) -> List[str]:
    out: List[str] = []
    if summary and not _GENERIC_SUMMARY_RE.match(summary):
        out.append(
            f"When you need {category or 'this capability'}, use {name} "
            f"because {summary[:160].rstrip('.')}."
        )
    if phase and phase != "any":
        out.append(
            f"When the engagement is in the {phase} phase, use {name} "
            f"as a cataloged {category or 'lab'} tool with operator ACCEPT/CANCEL gating."
        )
    for ex in examples[:4]:
        out.append(
            f"When you need a concrete invocation, run `{_sanitize_cmd(ex)}` "
            f"as documented upstream for {name}."
        )
    out.append(
        f"When chaining {category or 'related'} tools, pair {name} with "
        f"sibling catalog entries sharing its attack_surface/phase_hint."
    )
    out.append(
        f"When validating lab setup, run `{name} --help` (or the README "
        f"entrypoint) and confirm required hardware/deps from the catalog."
    )
    # dedupe preserve order
    seen = set()
    deduped = []
    for u in out:
        k = u.lower()
        if k in seen:
            continue
        seen.add(k)
        deduped.append(u)
    return deduped[:10]


def _install_bits_from_readme(text: str) -> List[str]:
    bits: List[str] = []
    for line in text.splitlines():
        s = line.strip().lstrip("$").strip()
        low = s.lower()
        if any(low.startswith(p) for p in (
            "pip install", "pip3 install", "cargo install", "go install",
            "npm install", "gem install", "apt install", "apt-get install",
            "brew install", "git clone", "make install", "docker run",
        )):
            if 8 < len(s) < 180:
                bits.append(s)
        if len(bits) >= 4:
            break
    return bits


# ---------------------------------------------------------------------------
# Man page helpers (kali)
# ---------------------------------------------------------------------------

def _local_man(cmd: str) -> Optional[str]:
    env = {
        **os.environ,
        "MANWIDTH": "100",
        "LC_ALL": "C",
        "LANG": "C",
        "LANGUAGE": "en",
    }
    try:
        r = subprocess.run(
            ["man", cmd],
            capture_output=True,
            timeout=6,
            env=env,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if r.returncode != 0 or not r.stdout:
        return None
    try:
        text = r.stdout.decode("utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        return None
    # col -b equivalent for backspaces
    text = re.sub(r".\x08", "", text)
    return text if len(text) > 80 else None


def _fetch_debian_man(package: str, cmd: str) -> Optional[str]:
    urls = [
        f"https://manpages.debian.org/unstable/{package}/{cmd}.1.en.html",
        f"https://manpages.debian.org/unstable/{cmd}/{cmd}.1.en.html",
        f"https://manpages.debian.org/{cmd}.1.en.html",
        f"https://manpages.ubuntu.com/manpages/noble/en/man1/{cmd}.1.html",
        f"https://manpages.debian.org/unstable/{package}/{cmd}.8.en.html",
    ]
    for u in urls:
        html_text = _http_get(u, timeout=10)
        if not html_text or len(html_text) < 200:
            continue
        if "404" in html_text[:200] and "Not Found" in html_text[:400]:
            continue
        # Prefer the pre/tt content
        text = _HTML_TAG.sub(" ", html_text)
        text = html.unescape(text)
        text = _WS.sub(" ", text)
        if len(text) > 200:
            return text
    return None


def _parse_man_args(man_text: str) -> List[Dict[str, str]]:
    """Extract options from man-page style text."""
    args = _extract_args_from_text(man_text)
    if args:
        return args
    # Fallback OPTIONS section pattern:  -f, --foo   description
    found: Dict[str, str] = {}
    for m in re.finditer(
        r"(-{1,2}[\w][\w-]*)(?:\s*,\s*(-{1,2}[\w][\w-]*))?"
        r"(?:\s+\S+){0,3}\s{2,}([A-Za-z][^\n]{8,160})",
        man_text,
    ):
        desc = _WS.sub(" ", m.group(3)).strip()[:200]
        for f in (m.group(1), m.group(2)):
            if f and f not in found:
                found[f] = desc
    return [
        {"name": k, "description": v, "source": "manpage"}
        for k, v in sorted(found.items())
    ][:60]


_MAN_SECTION = re.compile(
    r"^(?:NAME|SYNOPSIS|DESCRIPTION|OPTIONS|EXAMPLES?|SEE ALSO|AUTHORS?|"
    r"FILES|BUGS|COPYRIGHT|REPORTING BUGS|HISTORY|ENVIRONMENT|NOTES|"
    r"EXIT STATUS|DIAGNOSTICS|STANDARDS|SECURITY)\s*$",
    re.M | re.I,
)


def _man_section(man_text: str, title: str) -> str:
    """Return body text of a man section header (line-start match only)."""
    pat = re.compile(
        rf"^{re.escape(title)}\s*$(.*?)(?=^(?:NAME|SYNOPSIS|DESCRIPTION|OPTIONS|"
        rf"EXAMPLES?|SEE ALSO|AUTHORS?|FILES|BUGS|COPYRIGHT|REPORTING BUGS|"
        rf"HISTORY|ENVIRONMENT|NOTES|EXIT STATUS|DIAGNOSTICS|STANDARDS|SECURITY)\s*$|\Z)",
        re.M | re.S | re.I,
    )
    m = pat.search(man_text)
    return m.group(1) if m else ""


def _man_examples(man_text: str, cmd: str) -> List[str]:
    out: List[str] = []
    # Prefer SYNOPSIS block first (section-header aware — do not match [Options])
    for line in _man_section(man_text, "SYNOPSIS").splitlines():
        s = line.strip()
        if not s or len(s) > 220:
            continue
        if cmd and s.lower().startswith(cmd.lower()):
            out.append(s)
        elif re.match(r"^(?:python3?|ruby|perl|java|sudo)\s+", s, re.I):
            out.append(s)
    # EXAMPLES section — only keep lines that invoke the tool / have real flags
    for line in (
        _man_section(man_text, "EXAMPLES").splitlines()
        + _man_section(man_text, "EXAMPLE").splitlines()
    ):
        s = line.strip().lstrip("$").strip()
        if not s:
            continue
        invokes = bool(cmd) and (
            s.lower().startswith(cmd.lower() + " ")
            or s.lower().startswith(cmd.lower() + "\t")
            or s.lower() == cmd.lower()
        )
        has_flags = bool(re.search(r"\s-{1,2}[\w]", s))
        if invokes or (has_flags and _looks_like_command(s) and cmd and cmd.lower() in s.lower()):
            out.append(s)
    if not out:
        out.extend(_extract_examples(man_text, tool_hint=cmd))
    seen = set()
    deduped = []
    for e in out:
        k = e.lower()
        if k in seen:
            continue
        seen.add(k)
        deduped.append(e)
    return deduped[:8]


# ---------------------------------------------------------------------------
# Per-entry enhancement
# ---------------------------------------------------------------------------

def _is_generic_summary(s: str) -> bool:
    if not s or not s.strip():
        return True
    s = s.strip()
    if _GENERIC_SUMMARY_RE.match(s):
        return True
    # prior bad summaries: raw HTML, badge-only, empty markup
    if "<" in s and ">" in s:
        return True
    if re.match(r"^(img|image|logo|badge)\b", s, re.I):
        return True
    if len(s) < 20:
        return True
    return False


def enhance_github(
    data: Dict[str, Any],
    tb_index: Dict[str, Path],
    force: bool = False,
) -> Tuple[Dict[str, Any], str]:
    """Return (data, via) where via is internet_readme|local_readme|offline."""
    if data.get("_kfiosa_enhanced_v3") and not force:
        return data, "skip"

    owner = data.get("owner") or ""
    name = data.get("name") or ""
    full = data.get("full_name") or (f"{owner}/{name}" if owner and name else name)
    if "/" in full:
        owner2, repo = full.split("/", 1)
        owner = owner or owner2
        name = name or repo
    else:
        repo = name

    readme: Optional[str] = None
    via = "offline"

    # 1) local clone
    for key in (
        f"{owner}/{repo}",
        f"{owner}__{repo}",
        f"{owner.lower()}/{repo}",
        f"{owner.lower()}/{repo.lower()}",
        f"{str(owner).lower()}__{str(repo)}",
    ):
        path = tb_index.get(key)
        if path:
            readme = _read_local_readme(path)
            if readme:
                via = "local_readme"
                # Also scan entrypoint sources for argparse
                for py in list(path.glob("*.py"))[:8] + list(path.glob("*/*.py"))[:8]:
                    try:
                        src = py.read_text(encoding="utf-8", errors="replace")[:20000]
                    except OSError:
                        continue
                    readme = readme + "\n" + src
                break

    # 2) internet raw README
    if not readme and owner and repo:
        for branch in ("HEAD", "main", "master"):
            for fname in ("README.md", "readme.md", "README.rst", "README.txt"):
                url = f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{fname}"
                body = _http_get(url)
                if body and len(body.strip()) > 50 and "<!DOCTYPE html>" not in body[:80]:
                    readme = body
                    via = "internet_readme"
                    break
            if readme:
                break

    doc = data.get("documentation")
    if not isinstance(doc, dict):
        doc = {}

    category = data.get("category") or ""
    phase = data.get("phase_hint") or "any"
    tags = data.get("tags") if isinstance(data.get("tags"), list) else []
    existing_summary = (data.get("summary") or "").strip()
    existing_args = doc.get("arguments") if isinstance(doc.get("arguments"), list) else []

    if readme:
        para = _first_paragraph(readme, 900)
        args = _extract_args_from_text(readme)
        examples_raw = _extract_examples(readme, tool_hint=name or repo)
        examples = [
            _sanitize_cmd(e) for e in examples_raw
            if _looks_like_command(e)
        ]
        sections = _usage_sections(readme)
        install_bits = _install_bits_from_readme(readme)

        # Prefer newly parsed real args; merge plausible existing non-stub
        if args:
            by_name = {
                a.get("name"): a for a in args
                if isinstance(a, dict) and _is_plausible_flag(str(a.get("name") or ""))
            }
            for a in existing_args:
                if not isinstance(a, dict):
                    continue
                n = a.get("name")
                if not n or n in by_name or not _is_plausible_flag(str(n)):
                    continue
                desc = a.get("description") or ""
                if any(s in desc for s in (
                    "must come from project docs",
                    "Detected in command_examples",
                    "implementation-defined",
                    "v2_enhancement",
                )):
                    continue
                by_name[n] = a
            doc["arguments"] = list(by_name.values())[:60]
        elif existing_args:
            # Filter prior garbage flags even when no new parse hits
            cleaned = [
                a for a in existing_args
                if isinstance(a, dict) and _is_plausible_flag(str(a.get("name") or ""))
            ]
            if cleaned:
                doc["arguments"] = cleaned[:60]

        doc["readme"] = (para or readme[:1500])[:1500]
        if sections:
            doc["usage_sections"] = sections
        # Prefer cleaned paragraph over prior bad/HTML summary for prose
        clean_summary = para if para else existing_summary
        if (not existing_summary) or _is_generic_summary(existing_summary):
            if para:
                data["summary"] = para[:500]
                clean_summary = data["summary"]
        elif not _is_generic_summary(existing_summary):
            clean_summary = existing_summary

        how = _how_to_use(name or repo, clean_summary, examples, install_bits, para)
        doc["how_to_use"] = how
        doc["when_to_use"] = _when_to_use(data, clean_summary, category)
        doc["why_to_use"] = _why_to_use(clean_summary, para, tags)
        data["use_cases"] = _use_cases(
            name or repo, category, data.get("summary") or clean_summary, examples, phase
        )
        if examples:
            doc["examples"] = examples[:10]
            data["command_examples"] = examples[:10]
        else:
            # scrub prior non-commands
            old = data.get("command_examples") if isinstance(data.get("command_examples"), list) else []
            cleaned = [e for e in old if isinstance(e, str) and _looks_like_command(e)]
            data["command_examples"] = cleaned[:10]
            doc["examples"] = cleaned[:10]
        if not doc.get("function_signatures"):
            doc["function_signatures"] = [{
                "name": "main",
                "signature": f"main({', '.join(a['name'] for a in (doc.get('arguments') or [])[:6])})",
                "file": "README",
                "language": "cli",
                "description": f"CLI entrypoint for {name or repo}",
                "source": via,
            }]
    else:
        # offline degrade — fill prose from existing metadata only
        via = "offline"
        summary = existing_summary
        desc = (data.get("description") or "") if isinstance(data.get("description"), str) else ""
        para = summary or desc
        examples = data.get("command_examples") if isinstance(data.get("command_examples"), list) else []
        examples = [e for e in examples if isinstance(e, str)][:10]
        if not doc.get("how_to_use"):
            doc["how_to_use"] = _how_to_use(name or repo, para, examples, [], "")
        if not doc.get("when_to_use"):
            doc["when_to_use"] = _when_to_use(data, para, category)
        if not doc.get("why_to_use"):
            doc["why_to_use"] = _why_to_use(para, "", tags)
        if not data.get("use_cases"):
            data["use_cases"] = _use_cases(name or repo, category, para, examples, phase)
        # Improve stub arg descriptions with known flags map from deep_enhance_v2
        try:
            from core.catalog.deep_enhance_v2 import _FLAG_DESCRIPTIONS, STUB_DESCRIPTION, GENERIC_STUB
        except Exception:  # noqa: BLE001
            _FLAG_DESCRIPTIONS = {}
            STUB_DESCRIPTION = "Detected in command_examples"
            GENERIC_STUB = "must come from project docs"
        new_args = []
        for a in existing_args:
            if not isinstance(a, dict):
                continue
            a = dict(a)
            desc = a.get("description") or ""
            if STUB_DESCRIPTION in desc or GENERIC_STUB in desc or "implementation-defined" in desc:
                real = _FLAG_DESCRIPTIONS.get(a.get("name", ""))
                if real:
                    a["description"] = real
                    a["source"] = "offline_flag_map"
            new_args.append(a)
        if new_args:
            doc["arguments"] = new_args

    data["documentation"] = doc
    data["_kfiosa_enhanced_v3"] = True
    data["_enhanced_via"] = via
    return data, via


def enhance_kali(
    data: Dict[str, Any],
    force: bool = False,
) -> Tuple[Dict[str, Any], str]:
    if data.get("_kfiosa_enhanced_v3") and not force:
        return data, "skip"

    name = data.get("name") or data.get("source_package") or data.get("title") or ""
    package = data.get("source_package") or name
    description = (data.get("description") or data.get("summary") or "").strip()
    commands = data.get("commands") if isinstance(data.get("commands"), list) else []

    via = "offline"
    man_text: Optional[str] = None
    primary_cmd = None
    if commands and isinstance(commands[0], dict):
        primary_cmd = commands[0].get("name") or None

    if primary_cmd:
        man_text = _local_man(primary_cmd)
        if man_text:
            via = "local_man"
        else:
            man_text = _fetch_debian_man(package, primary_cmd)
            if man_text:
                via = "internet_manpage"

    doc = data.get("documentation")
    if not isinstance(doc, dict):
        doc = {}

    args: List[Dict[str, str]] = []
    examples: List[str] = []
    if man_text:
        args = _parse_man_args(man_text)
        examples = [
            _sanitize_cmd(e) for e in _man_examples(man_text, primary_cmd or name)
            if _looks_like_command(e) or e.strip().lower().startswith((primary_cmd or name or "x").lower())
        ]
        # Prefer NAME section, then DESCRIPTION first para
        name_body = _WS.sub(" ", _man_section(man_text, "NAME")).strip()
        desc_body = _man_section(man_text, "DESCRIPTION")
        if name_body and len(name_body) > 10:
            para = name_body[:700]
        elif desc_body:
            para = _first_paragraph(desc_body, 700)
        else:
            para = _first_paragraph(man_text, 700)
    else:
        para = description
        # Parse usage line from first command if present
        if commands and isinstance(commands[0], dict):
            usage = commands[0].get("usage") or ""
            if usage:
                examples = [_sanitize_cmd(usage)]
                # flags in usage like [-h] [-u USER]
                for fl in re.findall(r"(-{1,2}[\w-]+)", usage):
                    args.append({
                        "name": fl,
                        "description": f"Option present in package usage line for {primary_cmd or name}.",
                        "source": "usage_line",
                    })

    # Write into commands[0].arguments if we have real args
    if args and commands and isinstance(commands[0], dict):
        # Convert to kali-style argument objects when missing/empty
        existing = commands[0].get("arguments") or []
        if force or not existing:
            kali_args = []
            for a in args:
                kali_args.append({
                    "flags": [a["name"]],
                    "metavar": None,
                    "takes_value": False,
                    "description": a["description"],
                    "default": None,
                    "choices": None,
                    "raw": f"{a['name']}  {a['description']}",
                })
            commands[0]["arguments"] = kali_args
            data["commands"] = commands

    doc["arguments"] = [
        {"name": a["name"] if "name" in a else (a.get("flags") or [""])[0],
         "description": a.get("description") or "",
         "source": a.get("source", via)}
        for a in args
    ][:60]
    if examples:
        doc["examples"] = examples
        data["command_examples"] = examples
    else:
        # Drop stale prose that looked like commands from earlier passes
        old_ce = data.get("command_examples") if isinstance(data.get("command_examples"), list) else []
        cleaned_ce = [e for e in old_ce if isinstance(e, str) and _looks_like_command(e)]
        if cleaned_ce:
            data["command_examples"] = cleaned_ce
            doc["examples"] = cleaned_ce
        else:
            data["command_examples"] = []
            doc["examples"] = []
    if para:
        doc["readme"] = para[:1500]
        if (not data.get("summary")) or _is_generic_summary(str(data.get("summary") or "")):
            # strip "cmd - " prefix from man NAME for a cleaner summary
            summ = para
            if primary_cmd and summ.lower().startswith(primary_cmd.lower() + " - "):
                summ = summ[len(primary_cmd) + 3:].strip()
            data["summary"] = summ[:500]
    category = "Kali Linux"
    phase = data.get("phase_hint") or "any"
    tags = data.get("tags") if isinstance(data.get("tags"), list) else []
    tool = primary_cmd or name
    clean_sum = data.get("summary") or description
    doc["how_to_use"] = _how_to_use(
        tool,
        clean_sum,
        examples,
        [f"sudo apt install {package}"] if package else [],
        para or description,
    )
    doc["when_to_use"] = _when_to_use(data, clean_sum, category)
    doc["why_to_use"] = _why_to_use(clean_sum, para or "", tags)
    doc["usage_sections"] = (
        [f"Install with: sudo apt install {package}"] if package else []
    ) + list(doc.get("usage_sections") or [])
    doc["usage_sections"] = doc["usage_sections"][:6]
    data["use_cases"] = _use_cases(
        tool, category, clean_sum, examples, phase
    )
    data["documentation"] = doc
    data["_kfiosa_enhanced_v3"] = True
    data["_enhanced_via"] = via
    return data, via


def enhance_other(data: Dict[str, Any], force: bool = False) -> Tuple[Dict[str, Any], str]:
    """Generic/os entries — fill prose from existing fields only."""
    if data.get("_kfiosa_enhanced_v3") and not force:
        return data, "skip"
    doc = data.get("documentation")
    if not isinstance(doc, dict):
        doc = {}
    name = data.get("name") or data.get("id") or "tool"
    summary = (data.get("summary") or data.get("description") or "").strip()
    category = data.get("category") or data.get("kind") or ""
    examples = data.get("command_examples") if isinstance(data.get("command_examples"), list) else []
    examples = [e for e in examples if isinstance(e, str)]
    if not doc.get("how_to_use"):
        doc["how_to_use"] = _how_to_use(str(name), summary, examples, [], "")
    if not doc.get("when_to_use"):
        doc["when_to_use"] = _when_to_use(data, summary, str(category))
    if not doc.get("why_to_use"):
        doc["why_to_use"] = _why_to_use(summary, "", data.get("tags") or [])
    if not data.get("use_cases"):
        data["use_cases"] = _use_cases(str(name), str(category), summary, examples,
                                       data.get("phase_hint") or "any")
    data["documentation"] = doc
    data["_kfiosa_enhanced_v3"] = True
    data["_enhanced_via"] = "offline"
    return data, "offline"


def process_file(
    path: Path,
    tb_index: Dict[str, Path],
    force: bool = False,
) -> Dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        return {"file": path.name, "status": "error", "error": str(e)}
    if not isinstance(data, dict):
        return {"file": path.name, "status": "error", "error": "not an object"}

    kind = data.get("kind") or ""
    name = path.name
    try:
        if name.startswith("github_") or kind in ("github_repository", "external_repository", "toolbox"):
            data, via = enhance_github(data, tb_index, force=force)
        elif name.startswith("kali_") or kind == "kali_source_package":
            data, via = enhance_kali(data, force=force)
        else:
            data, via = enhance_other(data, force=force)
    except Exception as e:  # noqa: BLE001
        return {"file": path.name, "status": "error", "error": repr(e)}

    if via == "skip":
        return {"file": path.name, "status": "skip", "via": via}

    try:
        path.write_text(
            json.dumps(data, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
    except OSError as e:
        return {"file": path.name, "status": "error", "error": str(e)}

    doc = data.get("documentation") or {}
    n_args = len(doc.get("arguments") or []) if isinstance(doc, dict) else 0
    return {
        "file": path.name,
        "status": "ok",
        "via": via,
        "args": n_args,
        "has_how": bool(isinstance(doc, dict) and doc.get("how_to_use")),
    }


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--limit", type=int, default=0, help="Max files to process (0=all)")
    ap.add_argument("--only", choices=("github", "kali", "other", "all"), default="all")
    ap.add_argument("--force", action="store_true", help="Re-enhance files already v3")
    ap.add_argument("--workers", type=int, default=16)
    ap.add_argument("--catalog", type=Path, default=CATALOG)
    args = ap.parse_args(argv)

    catalog: Path = args.catalog
    files = sorted(catalog.glob("*.json"))
    if args.only == "github":
        files = [p for p in files if p.name.startswith("github_")]
    elif args.only == "kali":
        files = [p for p in files if p.name.startswith("kali_")]
    elif args.only == "other":
        files = [p for p in files if not p.name.startswith(("github_", "kali_"))]
    if args.limit:
        files = files[: args.limit]

    print(f"[enhance] indexing toolboxes under {TOOLBOXES} …", flush=True)
    tb_index = _index_toolboxes()
    print(f"[enhance] toolbox index: {len(tb_index)} keys; files: {len(files)}", flush=True)

    stats = {"ok": 0, "skip": 0, "error": 0, "via": {}}
    t0 = time.time()

    # Sequential batches with a thread pool for I/O-bound fetches.
    # Share tb_index (read-only).
    def _job(p: Path) -> Dict[str, Any]:
        return process_file(p, tb_index, force=args.force)

    done = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.workers)) as ex:
        futs = {ex.submit(_job, p): p for p in files}
        for fut in concurrent.futures.as_completed(futs):
            res = fut.result()
            done += 1
            st = res.get("status", "error")
            stats[st] = stats.get(st, 0) + 1
            via = res.get("via") or "error"
            stats["via"][via] = stats["via"].get(via, 0) + 1
            if done % 100 == 0 or done == len(files):
                elapsed = time.time() - t0
                rate = done / elapsed if elapsed else 0
                print(
                    f"[enhance] {done}/{len(files)}  ok={stats.get('ok',0)} "
                    f"skip={stats.get('skip',0)} err={stats.get('error',0)} "
                    f"via={stats['via']}  {rate:.1f}/s",
                    flush=True,
                )
            if st == "error":
                print(f"  ! {res.get('file')}: {res.get('error')}", flush=True)

    print(json.dumps({"stats": stats, "seconds": round(time.time() - t0, 1)}, indent=2))
    return 0 if stats.get("error", 0) == 0 else 1


if __name__ == "__main__":
    sys.path.insert(0, str(ROOT))
    raise SystemExit(main())
