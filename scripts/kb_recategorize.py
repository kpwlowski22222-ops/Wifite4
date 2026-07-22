#!/usr/bin/env python3
"""
KB Re-Categorize
================
Lighter re-categorization of the exploit knowledge base's ``misc`` repos
using name + owner heuristics + CamelCase splitting + the expanded
``CATEGORY_PATTERNS`` token set. No README / network fetch.

Usage:
    python scripts/kb_recategorize.py --dry-run          # report only
    python scripts/kb_recategorize.py --apply            # write to DB
    python scripts/kb_recategorize.py --dry-run --all   # re-eval all rows
"""

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.exploit_knowledge_base import ExploitKnowledgeBase


def main(argv=None):
    ap = argparse.ArgumentParser(description="Re-categorize the exploit KB")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--dry-run", action="store_true", default=True,
                   help="report only (default)")
    g.add_argument("--apply", action="store_true",
                   help="write the new categories to the database")
    ap.add_argument("--all", action="store_true",
                    help="re-evaluate all rows (default: only 'misc')")
    ap.add_argument("--json", action="store_true", help="emit JSON report")
    a = ap.parse_args(argv)

    kb = ExploitKnowledgeBase()
    res = kb.recategorize(apply=a.apply, only_misc=not a.all)

    if a.json:
        print(json.dumps(res, indent=2))
        return

    print(f"[i] scanned: {res['scanned']} rows"
          f" ({'all' if a.all else 'misc only'})")
    print(f"[i] would_change: {res['would_change']}")
    if a.apply:
        print(f"[+] applied {res['applied']} category updates")
    print("[i] top transitions:")
    for c in res["changes"]:
        print(f"    {c['from']:14s} -> {c['to']:14s}  x{c['count']}")
    if not res["changes"]:
        print("    (none)")


if __name__ == "__main__":
    main()