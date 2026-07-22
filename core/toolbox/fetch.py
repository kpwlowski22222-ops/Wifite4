"""core.toolbox.fetch — clone a curated list of GitHub repos
into ``toolboxes/<category>/<owner>__<name>/`` (idempotent).

This is the Phase 2.2.A fetch CLI. The operator passes a
``fetch_lists/<list>.txt`` (one ``https://github.com/owner/repo``
URL per line, ``#`` for comments) and a category; we clone
into ``toolboxes/<category>/<owner>__<name>/``.

Defaults: dry-run (no clone). Pass ``--clone`` to actually
fetch. Pass ``--i-am-sure-i-want-to-clone-N-repos`` (with the
exact count) as a safety guard. The fetch NEVER runs unattended
— the operator invokes it explicitly.

The function is hermetic when given a fake ``subprocess.run``
(``git clone`` is mocked); the test suite never hits the
network.
"""
from __future__ import annotations

import argparse
import logging
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


#: Directories the executor refuses (path-traversal guard).
#: Categories outside this set cannot be fetched/cloned.
ALLOWED_CATEGORIES: Set[str] = {
    "exploit", "wifi", "ble", "c2", "osint", "web",
    "post_exploitation", "recon", "android", "ios",
    "microsoft", "mobile", "frameworks", "wireless_ble_ext",
    "fresh_cves",
}


#: Set of categories that are NOT in ALLOWED_CATEGORIES.
def is_allowed_category(cat: str) -> bool:
    return cat in ALLOWED_CATEGORIES


def parse_list(text: str) -> List[str]:
    """Parse a list file. One URL per line. ``#`` is a comment.
    Inline trailing comment ``# cat: <category>`` is stripped from the
    URL but the category hint is NOT returned here (use
    :func:`parse_list_with_categories` for that). Blank lines are
    skipped. Returns the parsed URLs."""
    out: List[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        # Strip inline trailing comment but keep the URL.
        if " #" in line:
            line = line.split(" #", 1)[0].strip()
        out.append(line)
    return out


def parse_list_with_categories(text: str) -> List[Tuple[str, Optional[str]]]:
    """Like :func:`parse_list` but returns ``(url, category_or_None)``
    for each entry. The category hint comes from an inline trailing
    comment ``# cat: <category>`` on the same line. If absent, the
    category is ``None`` and the caller must supply a default
    (typically the ``--category`` CLI arg)."""
    out: List[Tuple[str, Optional[str]]] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        cat: Optional[str] = None
        if " #" in line:
            url_part, _, rest = line.partition(" #")
            line = url_part.strip()
            m = re.search(r"cat:\s*([A-Za-z0-9_]+)", rest)
            if m:
                cat = m.group(1)
        if line:
            out.append((line, cat))
    return out


def parse_github_url(url: str) -> Optional[Tuple[str, str]]:
    """Extract ``(owner, name)`` from a GitHub URL. Returns
    ``None`` if the URL doesn't match a github.com owner/repo
    pattern. Strips trailing ``.git``."""
    try:
        u = urlparse(url.strip())
    except Exception:  # noqa: BLE001
        return None
    if u.netloc not in ("github.com", "www.github.com"):
        return None
    parts = [p for p in u.path.split("/") if p]
    if len(parts) < 2:
        return None
    owner, name = parts[0], parts[1]
    if name.endswith(".git"):
        name = name[:-4]
    # Basic shape checks: owner / name should be [A-Za-z0-9_.-]+
    if not re.match(r"^[A-Za-z0-9_.\-]+$", owner):
        return None
    if not re.match(r"^[A-Za-z0-9_.\-]+$", name):
        return None
    return owner, name


def target_dir(toolboxes_root: Path, category: str,
               owner: str, name: str) -> Path:
    """The directory the repo would be cloned into."""
    return toolboxes_root / category / f"{owner}__{name}"


def plan_fetches(
    urls: List[str],
    *,
    toolboxes_root: Path,
    category: str,
) -> List[Dict[str, Any]]:
    """Plan a fetch. For each URL, return a dict with
    ``url``, ``owner``, ``name``, ``dest`` (absolute path), and
    ``action`` (``"clone"`` or ``"skip_exists"`` or
    ``"skip_bad_url"``). Never invokes git."""
    out: List[Dict[str, Any]] = []
    for url in urls:
        parsed = parse_github_url(url)
        if parsed is None:
            out.append({
                "url": url, "owner": None, "name": None,
                "dest": None, "action": "skip_bad_url",
                "error": f"not a github.com owner/repo URL: {url!r}",
            })
            continue
        owner, name = parsed
        dest = target_dir(toolboxes_root, category, owner, name)
        if dest.exists():
            out.append({
                "url": url, "owner": owner, "name": name,
                "dest": str(dest), "action": "skip_exists",
                "error": "",
            })
            continue
        out.append({
            "url": url, "owner": owner, "name": name,
            "dest": str(dest), "action": "clone",
            "error": "",
        })
    return out


def run_fetches(
    plan: List[Dict[str, Any]],
    *,
    toolboxes_root: Path,
    clone: bool,
    runner: Optional[Any] = None,
    confirm_count: Optional[int] = None,
) -> Dict[str, Any]:
    """Execute a fetch plan. With ``clone=False`` (default),
    returns the plan unchanged. With ``clone=True``, runs
    ``git clone --depth 1 <url> <dest>`` for each entry whose
    action is ``"clone"`` and returns the updated plan with
    ``ok``/``error`` per entry.

    The ``confirm_count`` arg is the operator-typed
    ``--i-am-sure-i-want-to-clone-N-repos`` value; if it
    doesn't match the number of new clones, we refuse.

    Args:
        plan: list of plan dicts from :func:`plan_fetches`.
        toolboxes_root: absolute path of the toolboxes dir.
        clone: whether to actually run ``git clone``.
        runner: optional callable ``(args, **kwargs) -> CompletedProcess``
            (defaults to ``subprocess.run``). The test suite
            injects a fake here.
        confirm_count: required exact count of new clones; the
            operator must type this on the command line.

    Returns:
        ``{"ok": bool, "plan": [...], "n_cloned": int, "n_skipped": int,
        "n_errors": int, "error": "..."}``
    """
    if runner is None:
        runner = subprocess.run
    if not clone:
        return {
            "ok": True, "plan": plan, "n_cloned": 0,
            "n_skipped": sum(1 for p in plan if p["action"] == "skip_exists"),
            "n_errors": sum(1 for p in plan if p["action"] == "skip_bad_url"),
            "error": "dry-run (no clone)",
        }
    n_new = sum(1 for p in plan if p["action"] == "clone")
    if confirm_count is None:
        return {
            "ok": False, "plan": plan, "n_cloned": 0, "n_skipped": 0,
            "n_errors": 0,
            "error": (
                "refusing to clone without "
                "--i-am-sure-i-want-to-clone-N-repos (operator gate)"
            ),
        }
    if confirm_count != n_new:
        return {
            "ok": False, "plan": plan, "n_cloned": 0, "n_skipped": 0,
            "n_errors": 0,
            "error": (
                f"refusing to clone: --i-am-sure-i-want-to-clone-N-repos "
                f"({confirm_count}) does not match the planned count ({n_new})"
            ),
        }
    if not is_allowed_category(_category_from_plan(plan)):
        # Defensive: refuse if the category snuck in.
        return {
            "ok": False, "plan": plan, "n_cloned": 0, "n_skipped": 0,
            "n_errors": 0,
            "error": "category not in ALLOWED_CATEGORIES",
        }
    n_cloned = 0
    n_skipped = sum(1 for p in plan if p["action"] == "skip_exists")
    n_errors = 0
    new_plan: List[Dict[str, Any]] = []
    for entry in plan:
        if entry["action"] != "clone":
            new_plan.append(entry)
            continue
        dest = Path(entry["dest"])
        dest.parent.mkdir(parents=True, exist_ok=True)
        try:
            cp = runner(
                ["git", "clone", "--depth", "1", entry["url"], str(dest)],
                capture_output=True, text=True, timeout=300,
            )
        except Exception as e:  # noqa: BLE001
            entry["ok"] = False
            entry["error"] = f"git clone raised: {e}"
            n_errors += 1
            new_plan.append(entry)
            continue
        if cp.returncode != 0:
            entry["ok"] = False
            entry["error"] = (
                f"git clone rc={cp.returncode} stderr={cp.stderr.strip()[:200]}"
            )
            n_errors += 1
        else:
            entry["ok"] = True
            entry["error"] = ""
            n_cloned += 1
        new_plan.append(entry)
    return {
        "ok": n_errors == 0, "plan": new_plan,
        "n_cloned": n_cloned, "n_skipped": n_skipped,
        "n_errors": n_errors, "error": "",
    }


def _category_from_plan(plan: List[Dict[str, Any]]) -> str:
    """Extract the category from a plan entry's dest path
    (or return an empty string if the plan is empty)."""
    for entry in plan:
        dest = entry.get("dest")
        if not dest:
            continue
        parts = Path(dest).parts
        if len(parts) >= 2:
            return parts[-2]
    return ""


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: Optional[List[str]] = None) -> int:
    """CLI entry point. Returns the process exit code."""
    parser = argparse.ArgumentParser(
        prog="kfiosa-fetch",
        description=(
            "Clone a curated list of GitHub repos into "
            "toolboxes/<category>/<owner>__<name>/. Default: dry-run."
        ),
    )
    parser.add_argument(
        "--list", required=True,
        help="Path to a fetch-list file (one github URL per line).",
    )
    parser.add_argument(
        "--category", required=True,
        help="Category directory under toolboxes/.",
    )
    parser.add_argument(
        "--toolboxes-root", default="toolboxes",
        help="Root toolboxes dir (default: ./toolboxes).",
    )
    parser.add_argument(
        "--clone", action="store_true",
        help="Actually run git clone. Default: dry-run only.",
    )
    parser.add_argument(
        "--i-am-sure-i-want-to-clone-N-repos", type=int, default=None,
        dest="confirm_count",
        help=(
            "Operator gate: the EXACT number of new clones. "
            "The CLI refuses to clone without this. Dry-run prints "
            "the count so you can paste it."
        ),
    )
    parser.add_argument(
        "--use-categories-from-list", action="store_true",
        help=(
            "Read each URL's category from an inline trailing "
            "comment '# cat: <category>'. Each URL is cloned to "
            "toolboxes/<inline-category>/<owner>__<name>/. The "
            "--category flag is then the default for URLs that "
            "have no inline hint."
        ),
    )
    args = parser.parse_args(argv)

    list_path = Path(args.list)
    if not list_path.is_file():
        print(f"[!] list file not found: {list_path}", file=sys.stderr)
        return 2

    text = list_path.read_text(encoding="utf-8", errors="replace")
    if args.use_categories_from_list:
        entries = parse_list_with_categories(text)
        if not entries:
            print(f"[!] no URLs in {list_path}", file=sys.stderr)
            return 2
        # Group by category, validate each is allowed.
        per_cat: Dict[str, List[str]] = {}
        for url, cat in entries:
            chosen = cat or args.category
            if not is_allowed_category(chosen):
                print(
                    f"[!] category {chosen!r} (for {url}) not in "
                    f"ALLOWED_CATEGORIES", file=sys.stderr)
                return 2
            per_cat.setdefault(chosen, []).append(url)
        # Print per-category plan
        root = Path(args.toolboxes_root).resolve()
        all_plans: List[Dict[str, Any]] = []
        n_total_new = 0
        for cat, urls in per_cat.items():
            print(f"[i] plan for category={cat!r} ({len(urls)} URL(s))")
            plan = plan_fetches(
                urls, toolboxes_root=root, category=cat)
            for entry in plan:
                print(f"  - {entry['action']:14s} {entry['url']}")
            all_plans.extend(plan)
            n_total_new += sum(1 for p in plan if p["action"] == "clone")
        n_total_exists = sum(
            1 for p in all_plans if p["action"] == "skip_exists")
        n_total_bad = sum(
            1 for p in all_plans if p["action"] == "skip_bad_url")
        print(f"[i] summary: {n_total_new} new, {n_total_exists} "
              f"exists, {n_total_bad} bad URL(s)")
        if not args.clone:
            print(f"[i] DRY-RUN: pass --clone to actually fetch "
                  f"(also pass --i-am-sure-i-want-to-clone-N-repos="
                  f"{n_total_new} as the operator gate)")
            return 0
        print(f"[i] CLONING — operator gate value: {n_total_new}")
        res = run_fetches(
            all_plans, toolboxes_root=root, clone=True,
            confirm_count=args.confirm_count,
        )
        if not res["ok"]:
            print(f"[!] {res['error']}", file=sys.stderr)
            return 1
        print(f"[*] cloned {res['n_cloned']}, skipped "
              f"{res['n_skipped']}, errors {res['n_errors']}")
        return 0

    if not is_allowed_category(args.category):
        print(f"[!] category {args.category!r} not in ALLOWED_CATEGORIES",
              file=sys.stderr)
        return 2

    urls = parse_list(text)
    if not urls:
        print(f"[!] no URLs in {list_path}", file=sys.stderr)
        return 2

    root = Path(args.toolboxes_root).resolve()
    plan = plan_fetches(urls, toolboxes_root=root, category=args.category)

    print(f"[i] plan for category={args.category!r} "
          f"({len(plan)} URL(s))")
    for entry in plan:
        print(f"  - {entry['action']:14s} {entry['url']}")

    n_new = sum(1 for p in plan if p["action"] == "clone")
    n_exists = sum(1 for p in plan if p["action"] == "skip_exists")
    n_bad = sum(1 for p in plan if p["action"] == "skip_bad_url")
    print(f"[i] summary: {n_new} new, {n_exists} exists, {n_bad} bad URL(s)")
    if not args.clone:
        print(f"[i] DRY-RUN: pass --clone to actually fetch "
              f"(also pass --i-am-sure-i-want-to-clone-N-repos={n_new} "
              f"as the operator gate)")
        return 0
    print(f"[i] CLONING — operator gate value: {n_new}")
    res = run_fetches(
        plan, toolboxes_root=root, clone=True,
        confirm_count=args.confirm_count,
    )
    if not res["ok"]:
        print(f"[!] {res['error']}", file=sys.stderr)
        return 1
    print(f"[*] cloned {res['n_cloned']}, skipped {res['n_skipped']}, "
          f"errors {res['n_errors']}")
    return 0


__all__ = [
    "ALLOWED_CATEGORIES",
    "is_allowed_category",
    "parse_list",
    "parse_list_with_categories",
    "parse_github_url",
    "target_dir",
    "plan_fetches",
    "run_fetches",
    "main",
]


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
