"""AI/tool router: catalog JSON file vs SQL vs memory index.

Chooses the fastest honest source for a catalog query based on
background stats (file count, SQL coverage, estimated latency).

Policy (high level)::

  * count-only / GROUP BY surface → **sql** (indexes + cached stats)
  * FTS / multi-filter search and SQL coverage ≥ 0.9 → **sql**
  * single known path / filename → **json** (direct open, no DB)
  * memory triple-index warm and small filtered lookup → **memory**
  * SQL empty → **json** (walk via memory index or glob)

Never fabricates results; on failure falls back to the next source.
"""
from __future__ import annotations

import time
from pathlib import Path
from typing import Any, Dict, List, Optional

_DEFAULT_CATALOG = Path(__file__).resolve().parents[2] / "catalog"


def decide(
    *,
    text: str = "",
    attack_surface: str = "",
    phase_hint: str = "",
    tag: str = "",
    kind: str = "",
    path: str = "",
    entry_id: str = "",
    count_only: bool = False,
    limit: int = 50,
    prefer: str = "",
) -> Dict[str, Any]:
    """Return {source, rationale, stats_snapshot}."""
    prefer = (prefer or "").strip().lower()
    if prefer in ("sql", "json", "memory", "file"):
        return {
            "source": "json" if prefer == "file" else prefer,
            "rationale": f"operator prefer={prefer}",
            "stats": {},
        }

    # Direct file fetch
    if path or entry_id.startswith("/") or entry_id.endswith(".json"):
        return {
            "source": "json",
            "rationale": "single path/id file fetch is cheapest as direct JSON",
            "stats": {},
        }

    stats: Dict[str, Any] = {}
    try:
        from core.catalog.bg_stats import get_last_stats, refresh_all
        stats = get_last_stats()
        if not stats:
            stats = refresh_all()
    except Exception as e:
        stats = {"ok": False, "error": str(e)[:80]}

    sql_total = int(((stats.get("sql") or {}).get("total")) or 0)
    disk_n = int(((stats.get("disk") or {}).get("file_count")) or 0)
    cov = float(stats.get("sql_coverage") or 0)
    mem_n = int(stats.get("memory_index_count") or 0)
    sql_ok = sql_total > 0 and cov >= 0.5

    if count_only:
        if sql_ok:
            return {
                "source": "sql",
                "rationale": (
                    f"count/aggregate: SQL has {sql_total} rows "
                    f"(coverage={cov:.0%}) — faster than scanning {disk_n} files"
                ),
                "stats": stats,
            }
        return {
            "source": "json",
            "rationale": "count requested but SQL not ready — disk scan",
            "stats": stats,
        }

    # Filtered search
    filtered = bool(text or attack_surface or phase_hint or tag or kind)
    if filtered and sql_ok and cov >= 0.85:
        return {
            "source": "sql",
            "rationale": (
                f"filtered search: SQL FTS/indexes ({sql_total} rows, "
                f"coverage={cov:.0%})"
            ),
            "stats": stats,
        }

    if mem_n > 0 and (attack_surface or phase_hint or tag or text):
        return {
            "source": "memory",
            "rationale": f"in-memory triple/tag index warm (n={mem_n})",
            "stats": stats,
        }

    if sql_ok:
        return {
            "source": "sql",
            "rationale": f"SQL ready ({sql_total} rows)",
            "stats": stats,
        }

    return {
        "source": "json",
        "rationale": "fallback to catalog/ JSON files",
        "stats": stats,
    }


def fetch(
    *,
    text: str = "",
    attack_surface: str = "",
    phase_hint: str = "",
    tag: str = "",
    kind: str = "",
    path: str = "",
    entry_id: str = "",
    limit: int = 50,
    prefer: str = "",
    catalog_dir: Optional[Path] = None,
    count_only: bool = False,
) -> Dict[str, Any]:
    """Decide source and execute the query. Always sets ``source_used``."""
    t0 = time.time()
    decision = decide(
        text=text,
        attack_surface=attack_surface,
        phase_hint=phase_hint,
        tag=tag,
        kind=kind,
        path=path,
        entry_id=entry_id,
        count_only=count_only,
        limit=limit,
        prefer=prefer,
    )
    source = decision["source"]
    catalog_dir = Path(catalog_dir or _DEFAULT_CATALOG)

    if count_only:
        if source == "sql":
            try:
                from core.catalog.sql_store import count_stats
                st = count_stats(refresh=False)
                return {
                    "ok": bool(st.get("ok")),
                    "source_used": "sql",
                    "decision": decision,
                    "count": st.get("total"),
                    "by_surface": st.get("by_surface"),
                    "by_kind": st.get("by_kind"),
                    "took_s": round(time.time() - t0, 4),
                }
            except Exception as e:
                source = "json"
                decision["fallback"] = str(e)[:80]
        # json/disk count
        try:
            from core.catalog.bg_stats import count_files
            d = count_files(catalog_dir)
            return {
                "ok": d.get("ok"),
                "source_used": "json",
                "decision": decision,
                "count": d.get("file_count"),
                "took_s": round(time.time() - t0, 4),
            }
        except Exception as e:
            return {"ok": False, "error": str(e), "decision": decision}

    # Single entry
    if entry_id or path:
        if source == "sql" or prefer == "sql":
            try:
                from core.catalog.sql_store import get_by_id, get_by_path
                ent = get_by_id(entry_id) if entry_id else None
                if ent is None and path:
                    ent = get_by_path(path)
                if ent is not None:
                    return {
                        "ok": True,
                        "source_used": "sql",
                        "decision": decision,
                        "results": [ent],
                        "count": 1,
                        "took_s": round(time.time() - t0, 4),
                    }
            except Exception:
                pass
        # JSON file
        try:
            p = Path(path) if path else catalog_dir / f"{entry_id}.json"
            if not p.is_file() and entry_id:
                # try stem match
                matches = list(catalog_dir.glob(f"*{entry_id.split('/')[-1]}*.json"))
                p = matches[0] if matches else p
            if p.is_file():
                import json
                data = json.loads(p.read_text(encoding="utf-8"))
                return {
                    "ok": True,
                    "source_used": "json",
                    "decision": decision,
                    "results": [data],
                    "count": 1,
                    "took_s": round(time.time() - t0, 4),
                }
        except Exception as e:
            return {"ok": False, "error": str(e), "decision": decision}

    # Multi search
    order = [source]
    for alt in ("sql", "memory", "json"):
        if alt not in order:
            order.append(alt)

    last_err = ""
    for src in order:
        try:
            if src == "sql":
                from core.catalog.sql_store import search_sql, sql_ready
                if not sql_ready():
                    continue
                r = search_sql(
                    attack_surface=attack_surface,
                    phase_hint=phase_hint,
                    tag=tag,
                    text=text,
                    kind=kind,
                    limit=limit,
                )
                if r.get("ok"):
                    return {
                        "ok": True,
                        "source_used": "sql",
                        "decision": decision,
                        "results": r.get("results") or [],
                        "count": r.get("count") or 0,
                        "took_s": round(time.time() - t0, 4),
                        "sql_took_s": r.get("took_s"),
                    }
                last_err = r.get("error") or "sql search failed"
            elif src == "memory":
                from core.catalog import index as cat_index
                rows = cat_index.search_memory(
                    attack_surface=attack_surface,
                    phase_hint=phase_hint,
                    tag=tag,
                    text=text,
                    limit=limit,
                    catalog_dir=catalog_dir,
                )
                return {
                    "ok": True,
                    "source_used": "memory",
                    "decision": decision,
                    "results": rows,
                    "count": len(rows),
                    "took_s": round(time.time() - t0, 4),
                }
            else:  # json — build in-memory from files (no SQL recursion)
                from core.catalog import index as cat_index
                cat_index.build_index(catalog_dir)
                rows = cat_index.search_memory(
                    attack_surface=attack_surface,
                    phase_hint=phase_hint,
                    tag=tag,
                    text=text,
                    limit=limit,
                    catalog_dir=catalog_dir,
                )
                return {
                    "ok": True,
                    "source_used": "json",
                    "decision": decision,
                    "results": rows,
                    "count": len(rows),
                    "took_s": round(time.time() - t0, 4),
                }
        except Exception as e:
            last_err = str(e)[:160]
            continue

    return {
        "ok": False,
        "error": last_err or "all sources failed",
        "decision": decision,
        "results": [],
        "took_s": round(time.time() - t0, 4),
    }
