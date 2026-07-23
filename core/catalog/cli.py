"""CLI: ingest catalog JSON into SQL and query via the source router.

Examples::

  python -m core.catalog.cli ingest
  python -m core.catalog.cli stats
  python -m core.catalog.cli search --text bloodhound --surface post
  python -m core.catalog.cli bg-start
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="KFIOSA catalog SQL store")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_ing = sub.add_parser("ingest", help="Load catalog/*.json into SQLite")
    p_ing.add_argument("--catalog", default="catalog")
    p_ing.add_argument("--db", default="", help="override KFIOSA_CATALOG_DB")
    p_ing.add_argument("--force", action="store_true")
    p_ing.add_argument("--max", type=int, default=0)

    sub.add_parser("stats", help="Disk + SQL coverage stats")

    p_s = sub.add_parser("search", help="Routed search (sql|memory|json)")
    p_s.add_argument("--text", default="")
    p_s.add_argument("--surface", default="")
    p_s.add_argument("--phase", default="")
    p_s.add_argument("--tag", default="")
    p_s.add_argument("--kind", default="")
    p_s.add_argument("--prefer", default="", choices=["", "sql", "memory", "json"])
    p_s.add_argument("--limit", type=int, default=10)
    p_s.add_argument("--count-only", action="store_true")

    p_bg = sub.add_parser("bg-start", help="Background count/ingest daemon")
    p_bg.add_argument("--interval", type=float, default=120.0)

    args = ap.parse_args(argv)
    if args.cmd == "ingest":
        if args.db:
            import os
            os.environ["KFIOSA_CATALOG_DB"] = args.db
        from core.catalog.sql_store import ingest_catalog
        r = ingest_catalog(
            Path(args.catalog), force=args.force, max_files=args.max,
        )
        print(json.dumps(r, indent=2, default=str))
        return 0 if r.get("ok") else 1

    if args.cmd == "stats":
        from core.catalog.bg_stats import refresh_all, probe_accel
        print(json.dumps({
            "accel": probe_accel(),
            "snapshot": refresh_all(),
        }, indent=2, default=str))
        return 0

    if args.cmd == "search":
        from core.catalog.source_router import fetch
        r = fetch(
            text=args.text,
            attack_surface=args.surface,
            phase_hint=args.phase,
            tag=args.tag,
            kind=args.kind,
            prefer=args.prefer,
            limit=args.limit,
            count_only=args.count_only,
        )
        # trim payloads for CLI readability
        out = dict(r)
        results = []
        for e in (r.get("results") or [])[: args.limit]:
            if isinstance(e, dict):
                results.append({
                    "id": e.get("id"),
                    "name": e.get("name"),
                    "kind": e.get("kind"),
                    "category": e.get("category"),
                    "attack_surface": e.get("attack_surface"),
                })
        out["results"] = results
        print(json.dumps(out, indent=2, default=str))
        return 0 if r.get("ok") else 1

    if args.cmd == "bg-start":
        from core.catalog.bg_stats import start_background
        r = start_background(interval_s=args.interval)
        print(json.dumps(r, indent=2))
        return 0

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
