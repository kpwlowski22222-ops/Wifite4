#!/usr/bin/env python3
"""scripts/consolidate_search_results.py — merge the per-category
GitHub tool-search JSONs into one master deduped list.

Reads .claude/jobs/search_results/<category>.json (each is
{"tools": [{owner, repo, url, description, language, tags}]}),
maps each search category to a toolboxes/<dir>/ category, dedupes
by owner/repo (case-insensitive), skips GUI-only tools when the
description explicitly says so, and writes:
  .claude/jobs/search_results/_master.json   (full list)
  .claude/jobs/search_results/_clone_plan.tsv (owner<TAB>repo<TAB>toolbox_dir<TAB>url<TAB>description)
"""
from __future__ import annotations
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List

HERE = Path(__file__).resolve().parent
RESULTS = HERE.parent / ".claude/jobs/search_results"

# search-category -> toolboxes/<dir>
TOOLBOX_DIR = {
    "wifi_offensive": "wifi",
    "wifi_recon": "wifi",
    "ble_offensive": "ble",
    "ble_recon": "ble",
    "osint_web": "osint",
    "osint_people": "osint",
    "forensics": "forensics",
    "anti_forensics": "forensics",
    "macos_postexp": "post_exploit",
    "linux_android_ios_postexp": "post_exploit",
    "windows_postexp": "microsoft",
}

GUI_HINT = re.compile(r"\b(GUI[- ]only|no CLI|graphical[- ]only)\b", re.I)


def load(cat: str) -> List[Dict[str, Any]]:
    p = RESULTS / f"{cat}.json"
    if not p.exists():
        return []
    try:
        d = json.loads(p.read_text(encoding="utf-8"))
    except Exception as e:  # noqa: BLE001
        print(f"  [warn] {cat}: parse error {e}", file=sys.stderr)
        return []
    tools = d.get("tools", []) if isinstance(d, dict) else []
    out = []
    for t in tools:
        if not isinstance(t, dict):
            continue
        owner = (t.get("owner") or "").strip()
        repo = (t.get("repo") or "").strip()
        if not owner or not repo or owner == "..." or repo == "...":
            continue
        desc = (t.get("description") or "").strip()
        if GUI_HINT.search(desc):
            continue
        out.append({
            "owner": owner,
            "repo": repo,
            "url": t.get("url") or f"https://github.com/{owner}/{repo}",
            "description": desc,
            "language": t.get("language") or "",
            "tags": t.get("tags") or [],
            "search_category": cat,
            "toolbox_dir": TOOLBOX_DIR.get(cat, "tools"),
        })
    return out


def main() -> int:
    master: List[Dict[str, Any]] = []
    seen: set[str] = set()
    per_cat: Dict[str, int] = {}
    skipped_dup = 0
    for cat in TOOLBOX_DIR:
        tools = load(cat)
        per_cat[cat] = len(tools)
        for t in tools:
            key = f"{t['owner'].lower()}/{t['repo'].lower()}"
            if key in seen:
                skipped_dup += 1
                continue
            seen.add(key)
            master.append(t)

    RESULTS.mkdir(parents=True, exist_ok=True)
    (RESULTS / "_master.json").write_text(
        json.dumps({"total": len(master), "tools": master},
                   indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    # clone plan TSV
    lines = ["owner\trepo\ttoolbox_dir\turl\tdescription"]
    for t in master:
        desc = t["description"].replace("\t", " ").replace("\n", " ")[:200]
        lines.append(f"{t['owner']}\t{t['repo']}\t{t['toolbox_dir']}\t{t['url']}\t{desc}")
    (RESULTS / "_clone_plan.tsv").write_text("\n".join(lines) + "\n",
                                             encoding="utf-8")

    by_dir: Dict[str, int] = {}
    for t in master:
        by_dir[t["toolbox_dir"]] = by_dir.get(t["toolbox_dir"], 0) + 1
    print("=== per search category (raw, before dedupe) ===")
    for c, n in per_cat.items():
        print(f"  {c:30s} {n}")
    print("=== per toolbox dir (after dedupe) ===")
    for d, n in sorted(by_dir.items()):
        print(f"  {d:20s} {n}")
    print(f"=== total unique tools: {len(master)}  (dups skipped: {skipped_dup}) ===")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())