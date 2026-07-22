"""core.refactors.clone_search_results — collect + dedupe + clone 240 tools.

Reads a list of search-results JSON files (one per Agent invocation),
deduplicates by ``owner/repo``, SKIPS any whose repo is already
represented in the catalog (github_*.json or kali_*.json), and
shallow-clones the rest into ``toolboxes/<category>/<owner>__<repo>``.

The 9 expected input files are produced by the parallel Agent
searches (WiFi offensive, WiFi recon, BLE offensive, BLE recon,
OSINT web, OSINT people, forensics, post-exploit linux/android/ios,
post-exploit macos). Each file is a JSON document of the form
``{"tools": [{owner, repo, url, description, language, tags}, ...]}``
emitted as the final assistant message from the search agent.
"""
from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple


def _read_agents_results(results_dir: Path) -> List[Dict[str, str]]:
    """Walk the agent .output files and extract the last 'tools' JSON
    from each. Falls back to globbing the results dir for *.json."""
    out: List[Dict[str, str]] = []
    for path in results_dir.glob("*.json"):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if isinstance(data, dict) and isinstance(data.get("tools"), list):
            for t in data["tools"]:
                if isinstance(t, dict) and t.get("owner") and t.get("repo"):
                    out.append(t)
    return out


def _existing_catalog_set(catalog_dir: Path) -> Set[str]:
    """Set of owner/repo strings that already have a catalog entry
    (github_*.json or kali_*.json)."""
    names: Set[str] = set()
    for p in catalog_dir.glob("github_*.json"):
        d = _try_read(p)
        if not d:
            continue
        owner = (d.get("owner") or "").lower()
        nm = (d.get("name") or "").lower()
        full = (d.get("full_name") or f"{owner}/{nm}").lower()
        names.add(full)
        # Also add the catalog file stem (which uses owner_repo) as alias
        names.add(p.stem.replace("github_", "").replace("_", "/").lower())
    # Kali entries map to apt-package names; build a lower-case set of them
    for p in catalog_dir.glob("kali_*.json"):
        d = _try_read(p)
        if not d:
            continue
        nm = (d.get("name") or "").lower()
        names.add(nm)
    return names


def _try_read(p: Path) -> Dict[str, Any]:
    try:
        d = json.loads(p.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return {}
    return d if isinstance(d, dict) else {}


def _infer_category(tool: Dict[str, str]) -> str:
    """Map a tool to a toolboxes/<category>/ subdir using its tags."""
    tags = " ".join(t.lower() for t in (tool.get("tags") or []))
    desc = (tool.get("description") or "").lower()
    if "wifi" in tags or "wifi" in desc:
        return "wifi"
    if "ble" in tags or "bluetooth" in tags:
        return "ble"
    if "osint" in tags or "osint" in desc:
        return "osint"
    if "forensic" in tags or "forensic" in desc:
        return "forensics"
    if "post-exploit" in tags or "post-exploit" in desc or \
       "post_exploit" in tags or "post exploit" in desc:
        return "post_exploit"
    if "android" in tags or "ios" in tags or "macos" in desc:
        return "post_exploit"
    return "tools"


def _clone_or_skip(url: str, dst: Path, *, timeout: int = 60) -> Tuple[bool, str]:
    """Shallow-clone ``url`` into ``dst`` if not already present."""
    if dst.exists() and (dst / ".git").exists():
        return False, "already cloned"
    dst.parent.mkdir(parents=True, exist_ok=True)
    try:
        r = subprocess.run(
            ["git", "clone", "--depth", "1", url, str(dst)],
            capture_output=True, text=True, timeout=timeout,
            check=False,
        )
        if r.returncode != 0:
            return False, f"clone failed: {r.stderr.strip()[:120]}"
        return True, "cloned"
    except subprocess.TimeoutExpired:
        return False, "clone timeout"
    except Exception as e:  # noqa: BLE001
        return False, f"clone error: {e}"


def clone_search_results(
    results_dir: Path,
    catalog_dir: Path,
    toolboxes_dir: Path,
    *,
    limit: int = 0,
) -> Dict[str, Any]:
    """Top-level orchestrator.

    Returns a summary envelope: total, unique, skipped_dup,
    already_cloned, cloned, failed, by_category.
    """
    results_dir = Path(results_dir)
    catalog_dir = Path(catalog_dir)
    toolboxes_dir = Path(toolboxes_dir)

    all_tools = _read_agents_results(results_dir)
    if limit:
        all_tools = all_tools[:limit]
    # Dedupe by owner/repo
    seen: Set[str] = set()
    unique: List[Dict[str, str]] = []
    for t in all_tools:
        key = f"{t['owner']}/{t['repo']}".lower()
        if key in seen:
            continue
        seen.add(key)
        unique.append(t)
    # Skip those already in catalog
    existing = _existing_catalog_set(catalog_dir)
    fresh: List[Dict[str, str]] = []
    skipped_dup: List[str] = []
    for t in unique:
        key = f"{t['owner']}/{t['repo']}".lower()
        # Also skip if owner or repo name matches a kali package
        bare = t['repo'].lower()
        if key in existing or bare in existing or t['owner'].lower() in existing:
            skipped_dup.append(key)
            continue
        fresh.append(t)
    # Clone
    cloned: List[str] = []
    already_cloned: List[str] = []
    failed: List[Dict[str, str]] = []
    by_category: Dict[str, int] = {}
    for t in fresh:
        cat = _infer_category(t)
        dst = toolboxes_dir / cat / f"{t['owner']}__{t['repo']}"
        ok, msg = _clone_or_skip(t.get("url") or f"https://github.com/{t['owner']}/{t['repo']}",
                                  dst)
        by_category[cat] = by_category.get(cat, 0) + (1 if ok else 0)
        if ok:
            cloned.append(f"{t['owner']}/{t['repo']}")
        elif msg == "already cloned":
            already_cloned.append(f"{t['owner']}/{t['repo']}")
        else:
            failed.append({"tool": f"{t['owner']}/{t['repo']}", "error": msg})
    return {
        "ok": True,
        "total_search_results": len(all_tools),
        "unique": len(unique),
        "skipped_dup": len(skipped_dup),
        "fresh": len(fresh),
        "cloned": len(cloned),
        "already_cloned": len(already_cloned),
        "failed": len(failed),
        "by_category": by_category,
        "skipped_dup_list": skipped_dup[:20],  # sample
        "cloned_list": cloned,
        "failed_list": failed,
    }


if __name__ == "__main__":
    import sys
    results = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(".claude/search_results")
    cat = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("catalog")
    tb = Path(sys.argv[3]) if len(sys.argv) > 3 else Path("toolboxes")
    print(json.dumps(clone_search_results(results, cat, tb), indent=2))
