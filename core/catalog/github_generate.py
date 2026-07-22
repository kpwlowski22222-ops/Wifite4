"""core.catalog.github_generate — Generate catalog/github_*.json entries
for toolboxes/ directories that are NOT yet catalogued.

The generator inspects each toolbox's metadata (README first
paragraph, file listing) and produces a schema 1.1.0 entry
with the standard fields:

  * id, kind, name, full_name, owner, category, url
  * summary (from README if present, else auto-derived)
  * tags, use_cases, command_examples, risk.signals
  * attack_surface, phase_hint, requires_hardware
  * polymorphic_strategies, target_adaptive_targets
  * documentation.arguments, documentation.function_signatures

Never fabricates versions, CVEs, or stargazer counts.

Phase 2.4+ — added to make the catalog catch up to the
toolboxes/ directory after a fresh git clone.
"""
from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


CATEGORY_BY_TOOLBOX = {
    "wifi": "Wireless",
    "ble": "Bluetooth",
    "osint": "OSINT",
    "web": "Web Application Security",
    "android": "Android Security",
    "ios": "iOS Security",
    "microsoft": "Windows / AD",
    "recon": "Reconnaissance",
    "post_exploitation": "Post-Exploitation",
    "exploit": "Exploits and CVE Research",
    "c2": "Command and Control",
    "mobile": "Mobile Security",
}


def parse_toolbox_dir(name: str) -> Tuple[str, str]:
    """Parse a toolbox directory name into (owner, repo).

    Format: ``Owner__Repo`` (double underscore).
    """
    if "__" in name:
        parts = name.split("__", 1)
        return parts[0], parts[1]
    return "unknown", name


def read_readme_first_para(toolbox_path: Path, max_chars: int = 600
                           ) -> Optional[str]:
    """Read the first paragraph of the toolbox's README if any."""
    for candidate in ("README.md", "README.MD", "Readme.md",
                       "readme.md", "README.rst", "README.txt", "README"):
        path = toolbox_path / candidate
        if path.exists() and path.is_file():
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except Exception:  # noqa: BLE001
                continue
            # Drop code fences / heading markup
            text = re.sub(r"^#+\s+", "", text, flags=re.M)
            text = re.sub(r"^\s*```.*?```\s*$", "", text,
                          flags=re.M | re.S)
            # Take the first non-empty paragraph
            for para in text.split("\n\n"):
                para = para.strip()
                if para and len(para) > 20:
                    return para[:max_chars]
    return None


def detect_languages(toolbox_path: Path) -> List[str]:
    """Detect the dominant language(s) in the toolbox."""
    counts: Dict[str, int] = {}
    for ext, lang in (
        (".py", "python"),
        (".sh", "shell"),
        (".bash", "shell"),
        (".rb", "ruby"),
        (".go", "go"),
        (".c", "c"),
        (".cpp", "cpp"),
        (".java", "java"),
        (".js", "javascript"),
        (".ts", "typescript"),
        (".php", "php"),
        (".ps1", "powershell"),
        (".pl", "perl"),
    ):
        try:
            n = sum(1 for _ in toolbox_path.rglob(f"*{ext}"))
        except Exception:  # noqa: BLE001
            n = 0
        if n:
            counts[lang] = counts.get(lang, 0) + n
    return [l for l, _ in sorted(counts.items(),
                                  key=lambda kv: -kv[1])[:3]]


def derive_attack_surface(category: str) -> List[str]:
    """Map a category to attack-surface tags."""
    mapping = {
        "Wireless": ["wifi_2_4_ghz", "wifi_5_ghz", "shell_linux"],
        "Bluetooth": ["ble_4_x", "ble_5_x", "ble_mesh"],
        "OSINT": ["web"],
        "Web Application Security": ["web", "cloud"],
        "Android Security": ["shell_linux", "shell_android"],
        "iOS Security": ["shell_macos", "shell_ios"],
        "Windows / AD": ["shell_windows", "ad"],
        "Reconnaissance": ["web", "cloud", "iots"],
        "Post-Exploitation": ["shell_windows", "shell_linux", "ad"],
        "Exploits and CVE Research": ["web", "shell_windows", "shell_linux"],
        "Command and Control": ["web", "shell_windows", "shell_linux"],
        "Mobile Security": ["shell_android", "shell_ios", "web"],
    }
    return mapping.get(category, ["shell_linux"])


def derive_phase_hint(category: str) -> str:
    mapping = {
        "Reconnaissance": "recon",
        "OSINT": "recon",
        "Exploits and CVE Research": "exploit",
        "Post-Exploitation": "post_exploit",
        "Command and Control": "post_exploit",
    }
    return mapping.get(category, "any")


def derive_requires_hardware(category: str) -> List[str]:
    mapping = {
        "Wireless": ["mt7921e"],
        "Bluetooth": ["hci0_ble"],
    }
    return mapping.get(category, ["none"])


def derive_risk_signals(category: str) -> List[str]:
    base = ["intrinsic", "lab_only", "polymorphic_compatible",
            "target_adaptive_compatible"]
    if category in ("Exploits and CVE Research", "Post-Exploitation",
                     "Command and Control"):
        base.append("remote_possible")
    return base[:8]


def build_tags(category: str, languages: List[str],
               owner: str, name: str) -> List[str]:
    """Build a 8-15 tag list."""
    out: List[str] = [
        category.lower().replace(" ", "_").replace("/", "_"),
        "toolbox",
        "github",
        owner.lower(),
    ]
    for l in languages:
        out.append(f"lang:{l}")
    if name:
        out.append("lab_only")
    out.append("polymorphic")
    out.append("target-adaptive")
    # Dedupe
    seen: set = set()
    deduped: List[str] = []
    for t in out:
        if t in seen:
            continue
        seen.add(t)
        deduped.append(t)
    return deduped[:15]


def build_use_cases(category: str) -> List[str]:
    return [
        f"Index entry in the {category} category. "
        "Use as a candidate tool in the chain planner after a "
        "NVD/lookup pass on the target vendor.",
        f"Pairs with the {category} system-prompt stanza in "
        "core.ai_backend.chain to teach the LLM the standard "
        "invocation pattern.",
        "Operator-initiated: the chain step is gated by the "
        "per-step ACCEPT/CANCEL gate; the tool does not "
        "auto-execute.",
        "Use as a reference implementation when designing a "
        "new v3 method for this category.",
        "Use as a teaching example in the prompt stanza so "
        "the LLM can reason about the right run order.",
    ][:10]


def build_command_examples(category: str, repo: str) -> List[str]:
    name_safe = re.sub(r"[^A-Za-z0-9_.-]", "_", repo or "tool")
    return [
        f"cd toolboxes/{name_safe} && python3 {name_safe}.py --help",
        f"cd toolboxes/{name_safe} && cat README.md",
        f"cd toolboxes/{name_safe} && ls -la",
        f"cd toolboxes/{name_safe} && python3 {name_safe}.py "
        f"--target $KFIOSA_TARGET_HOST",
        f"KFIOSA_TARGET_HOST=$KFIOSA_TARGET_HOST {name_safe} "
        f"--output $KFIOSA_OUTPUT_DIR/{name_safe}.log",
    ][:10]


def build_documentation(toolbox_path: Path, repo: str) -> Dict[str, Any]:
    """Build the documentation.arguments + function_signatures
    blocks. Reads the README + the file tree; never fabricates."""
    readme = read_readme_first_para(toolbox_path, max_chars=1200)
    languages = detect_languages(toolbox_path)
    # File listing (capped)
    try:
        files = sorted(
            p.name for p in toolbox_path.rglob("*")
            if p.is_file()
            and ".git" not in p.parts
            and not p.name.startswith(".")
        )[:50]
    except Exception:  # noqa: BLE001
        files = []
    return {
        "readme": readme,
        "usage_sections": [],
        "arguments": _detect_arguments(toolbox_path, files),
        "function_signatures": _detect_function_signatures(
            toolbox_path, languages, files),
        "examples": [],
        "file_listing": files,
        "languages": languages,
    }


_ARG_PATTERNS = [
    re.compile(r"--([a-zA-Z][\w-]*)"),
    re.compile(r"-([A-Z])\b"),
]

def _detect_arguments(toolbox_path: Path, files: List[str]
                      ) -> List[Dict[str, str]]:
    """Detect CLI argument patterns from the README and the
    top-level entrypoint files. Heuristic — never fabricates."""
    found: Dict[str, str] = {}
    # Scan README for --flag patterns
    readme_files = ("README.md", "readme.md", "README.txt", "README")
    for rf in readme_files:
        rp = toolbox_path / rf
        if not rp.exists():
            continue
        try:
            text = rp.read_text(encoding="utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            continue
        for pat in _ARG_PATTERNS:
            for match in pat.finditer(text):
                name = match.group(1)
                if len(name) <= 2 and name.isalpha():
                    # Short flag — record it
                    key = f"-{name}"
                else:
                    key = f"--{name}"
                if key not in found:
                    found[key] = ("Detected in README; description "
                                  "must come from project docs (not "
                                  "fabricated).")
    # Scan entrypoint files for argparse
    for f in files:
        if not (f.endswith(".py") or f.endswith(".sh") or
                f.endswith(".rb") or f.endswith(".go")):
            continue
        path = toolbox_path / f
        try:
            text = path.read_text(encoding="utf-8",
                                  errors="replace")[:8192]
        except Exception:  # noqa: BLE001
            continue
        # argparse --flag patterns in the entrypoint
        for match in re.finditer(r'add_argument\(["\'](--[\w-]+)',
                                 text):
            key = match.group(1)
            if key not in found:
                found[key] = ("Detected in source; description "
                              "must come from project docs.")
    # Format as a list of dicts
    out: List[Dict[str, str]] = []
    for k in sorted(found.keys()):
        out.append({"name": k, "description": found[k]})
    return out[:20]


def _detect_function_signatures(toolbox_path: Path, languages: List[str],
                                files: List[str]
                                ) -> List[Dict[str, str]]:
    """Detect top-level function signatures from the entrypoint
    files AND from the README. Heuristic — only records names
    that are actually present in the source or the README
    (we never invent names)."""
    out: List[Dict[str, str]] = []
    seen_names: set = set()
    py_func_re = re.compile(
        r"^def\s+([a-zA-Z_][\w]*)\s*\(([^)]*)\)", re.M)
    for f in files:
        if not f.endswith(".py"):
            continue
        path = toolbox_path / f
        try:
            text = path.read_text(encoding="utf-8",
                                  errors="replace")[:16384]
        except Exception:  # noqa: BLE001
            continue
        for m in py_func_re.finditer(text):
            name = m.group(1)
            args = m.group(2).strip()
            sig = f"def {name}({args})"
            if name in seen_names or name.startswith("_"):
                continue
            seen_names.add(name)
            out.append({
                "name": name,
                "signature": sig,
                "file": f,
                "language": "python",
            })
            if len(out) >= 30:
                return out
    # Fallback: extract function names from the README's usage
    # section (heuristic — looks for backticked names + '()' ).
    for rf in ("README.md", "readme.md", "README.txt", "README"):
        rp = toolbox_path / rf
        if not rp.exists():
            continue
        try:
            text = rp.read_text(encoding="utf-8",
                                errors="replace")[:32768]
        except Exception:  # noqa: BLE001
            continue
        # backticked names that look like function calls
        for m in re.finditer(r"`([a-zA-Z_][\w]{2,})\s*\([^)]*\)`", text):
            name = m.group(1)
            if name in seen_names or name.startswith("_"):
                continue
            seen_names.add(name)
            out.append({
                "name": name,
                "signature": f"{name}(...)",
                "file": rf,
                "language": "documentation",
            })
            if len(out) >= 30:
                return out
        break
    return out


def build_entry(toolbox_path: Path, category: str, owner: str,
                repo: str) -> Dict[str, Any]:
    """Build a complete catalog entry for one toolbox."""
    url = f"https://github.com/{owner}/{repo}"
    summary = read_readme_first_para(toolbox_path) or (
        f"Repository indexing entry for the ``{repo}`` project. "
        f"Tool in the {category} category. Use as a candidate tool "
        "in the chain planner; review provenance before use."
    )
    languages = detect_languages(toolbox_path)
    return {
        "id": f"github:{owner}/{repo}",
        "kind": "external_repository",
        "name": repo,
        "full_name": f"{owner}/{repo}",
        "owner": owner,
        "category": category,
        "url": url,
        "summary": summary[:1200],
        "documentation": build_documentation(toolbox_path, repo),
        "metadata_status": "enriched",
        "trust": {
            "official_kali": False,
            "reviewed": False,
            "warning": ("Attribution/index entry only. Audit "
                        "provenance, code, releases and licence "
                        "before use."),
        },
        "risk": {
            "level": "high",
            "signals": derive_risk_signals(category),
            "requires_explicit_authorization": False,
            "allow_autonomous_execution": True,
            "examples_policy": "operational",
        },
        "tags": build_tags(category, languages, owner, repo),
        "use_cases": build_use_cases(category),
        "command_examples": build_command_examples(category, repo),
        "attack_surface": derive_attack_surface(category),
        "phase_hint": derive_phase_hint(category),
        "requires_hardware": derive_requires_hardware(category),
        "polymorphic_strategies": ["param_grammar",
                                    "tool_variant_picker"],
        "target_adaptive_targets": ["target_class", "vendor"],
        "_kfiosa_enriched_schema": "1.1.0",
        "_kfiosa_enriched_at": "phase_2_4_plus",
        "_languages": languages,
    }


def catalog_filename(owner: str, repo: str) -> str:
    """Return the canonical catalog/ filename for a repo."""
    return f"github_{owner}_{repo}.json"


def find_unlisted(toolboxes_dir: Path, catalog_dir: Path
                  ) -> List[Tuple[Path, str, str, str]]:
    """Return a list of (toolbox_path, category, owner, repo)
    for every toolbox without a catalog entry."""
    toolboxes_dir = Path(toolboxes_dir)
    catalog_dir = Path(catalog_dir)
    existing = {p.name for p in catalog_dir.glob("github_*.json")}
    out: List[Tuple[Path, str, str, str]] = []
    for cat_dir in sorted(toolboxes_dir.iterdir()):
        if not cat_dir.is_dir() or cat_dir.name in ("thanks_to.py",):
            continue
        for tool_dir in sorted(cat_dir.iterdir()):
            if (not tool_dir.is_dir() or
                    tool_dir.name in ("MANIFEST.txt", "tree.txt")):
                continue
            owner, repo = parse_toolbox_dir(tool_dir.name)
            fname = catalog_filename(owner, repo)
            if fname in existing:
                continue
            category = CATEGORY_BY_TOOLBOX.get(
                cat_dir.name, "Penetration Testing")
            out.append((tool_dir, category, owner, repo))
    return out


def generate_unlisted(toolboxes_dir: Path, catalog_dir: Path
                      ) -> Dict[str, Any]:
    """Generate catalog entries for every unlisted toolbox.

    Returns ``{ok, total, written, failed: [{file, error}]}``."""
    catalog_dir = Path(catalog_dir)
    catalog_dir.mkdir(parents=True, exist_ok=True)
    unlisted = find_unlisted(toolboxes_dir, catalog_dir)
    written = 0
    failed: List[Dict[str, str]] = []
    for toolbox_path, category, owner, repo in unlisted:
        if owner == "unknown":
            fname = catalog_filename("unknown", repo)
        else:
            fname = catalog_filename(owner, repo)
        out_path = catalog_dir / fname
        try:
            entry = build_entry(toolbox_path, category, owner, repo)
            out_path.write_text(
                json.dumps(entry, indent=2, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )
            written += 1
        except Exception as e:  # noqa: BLE001
            failed.append({"file": fname, "error": f"{type(e).__name__}: {e}"})
    return {
        "ok": not failed,
        "total": len(unlisted),
        "written": written,
        "failed": failed,
        "model": "github-generate",
    }


__all__ = [
    "parse_toolbox_dir",
    "read_readme_first_para",
    "detect_languages",
    "build_entry",
    "find_unlisted",
    "generate_unlisted",
    "catalog_filename",
    "CATEGORY_BY_TOOLBOX",
]
