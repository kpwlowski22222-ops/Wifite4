#!/usr/bin/env python3
"""
fetch_toolboxes.py
==================
Clone the most-useful exploit / OSINT / wireless / BLE / post-exploit / C2
repos from the local exploit knowledge base into ``toolboxes/<domain>/`` so
the operator has the *real* upstream tools on disk — not Python wrapper
functions that pretend to be them.

The knowledge base (``core/exploit_knowledge_base.py``) already parsed
``github_exploit_repos.txt`` and scored every repo for relevance. This script
just takes the top-N repos per domain and does a shallow ``git clone``.

Usage:
    python scripts/fetch_toolboxes.py                 # all domains, top 15 each
    python scripts/fetch_toolboxes.py wifi            # one domain
    python scripts/fetch_toolboxes.py wifi ble --limit 25
    python scripts/fetch_toolboxes.py --all --limit 50
    python scripts/fetch_toolboxes.py --list           # show what would clone

Domains (knowledge-base domain keys):
    wifi, ble, osint, post_exploitation, c2, web, mobile, exploit, recon
"""

import argparse
import logging
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Dict, List

# Make ``core.*`` importable when run as a script.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s: %(message)s",
)
logger = logging.getLogger("fetch_toolboxes")

TOOLBOXES_DIR = PROJECT_ROOT / "toolboxes"

ALL_DOMAINS = [
    "wifi", "ble", "osint", "post_exploitation", "c2",
    "web", "mobile", "exploit", "recon",
]


def _clone_dir(domain: str, owner: str, repo: str) -> Path:
    safe_owner = "".join(c if c.isalnum() else "_" for c in owner) or "_"
    safe_repo = "".join(c if c.isalnum() or c in "-._" else "_" for c in repo) or "_"
    return TOOLBOXES_DIR / domain / f"{safe_owner}__{safe_repo}"


def fetch_domain(domain: str, limit: int, dry_run: bool = False) -> Dict[str, int]:
    """Clone the top-``limit`` repos for one domain. Returns a stats dict."""
    from core.exploit_knowledge_base import ExploitKnowledgeBase

    kb = ExploitKnowledgeBase()
    repos = kb.get_tools_for_domain(domain)
    if not repos:
        logger.warning("no repos in KB for domain %r (build the KB first)", domain)
        return {"attempted": 0, "cloned": 0, "skipped": 0, "failed": 0}

    if not shutil.which("git"):
        logger.error("git not installed — cannot clone")
        return {"attempted": 0, "cloned": 0, "skipped": 0, "failed": 0}

    selected = repos[:limit]
    stats = {"attempted": len(selected), "cloned": 0, "skipped": 0, "failed": 0}

    for r in selected:
        owner = r.get("owner", "")
        repo = r.get("repo_name", "")
        url = r.get("url") or f"https://github.com/{owner}/{repo}"
        if not owner or not repo:
            continue
        dest = _clone_dir(domain, owner, repo)

        if dest.exists() and dest.is_dir() and any(dest.iterdir()):
            logger.info("[skip] %s/%s already at %s", owner, repo, dest)
            stats["skipped"] += 1
            continue

        if dry_run:
            logger.info("[dry-run] would clone %s -> %s", url, dest)
            continue

        dest.parent.mkdir(parents=True, exist_ok=True)
        logger.info("[clone] %s/%s (relevance=%s)", owner, repo, r.get("relevance"))
        try:
            subprocess.run(
                ["git", "clone", "--depth", "1", url, str(dest)],
                capture_output=True, text=True, timeout=120,
            )
            if dest.exists() and any(dest.iterdir()):
                stats["cloned"] += 1
            else:
                stats["failed"] += 1
                logger.warning("clone produced empty dir: %s", dest)
        except subprocess.TimeoutExpired:
            stats["failed"] += 1
            logger.warning("clone timed out: %s", url)
        except Exception as e:
            stats["failed"] += 1
            logger.warning("clone failed %s: %s", url, e)

    _write_manifest(domain)
    return stats


def _write_manifest(domain: str):
    """Drop a MANIFEST.txt listing what is on disk for the domain."""
    ddir = TOOLBOXES_DIR / domain
    if not ddir.exists():
        return
    lines = [f"# KFIOSA toolboxes/{domain} — fetched {domain} repos", ""]
    for sub in sorted(p for p in ddir.iterdir() if p.is_dir()):
        lines.append(sub.name)
    (ddir / "MANIFEST.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main(argv: List[str] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("domains", nargs="*",
                    help="domains to fetch (default: all core domains)")
    ap.add_argument("--all", action="store_true",
                    help="fetch every known domain")
    ap.add_argument("--limit", type=int, default=15,
                    help="top-N repos per domain (default: 15)")
    ap.add_argument("--list", action="store_true",
                    help="dry-run: show what would be cloned, clone nothing")
    args = ap.parse_args(argv)

    if args.all or not args.domains:
        domains = ALL_DOMAINS
    else:
        domains = [d for d in args.domains if d in ALL_DOMAINS]
        bad = [d for d in args.domains if d not in ALL_DOMAINS]
        if bad:
            logger.warning("ignoring unknown domains: %s", ", ".join(bad))

    if not domains:
        logger.error("no valid domains selected")
        return 2

    TOOLBOXES_DIR.mkdir(parents=True, exist_ok=True)
    dry = bool(args.list)

    total = {"attempted": 0, "cloned": 0, "skipped": 0, "failed": 0}
    for dom in domains:
        logger.info("=== domain: %s (limit=%d) ===", dom, args.limit)
        st = fetch_domain(dom, args.limit, dry_run=dry)
        for k in total:
            total[k] += st[k]

    logger.info(
        "done: %d attempted, %d cloned, %d skipped, %d failed -> %s",
        total["attempted"], total["cloned"], total["skipped"],
        total["failed"], TOOLBOXES_DIR,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())