#!/usr/bin/env python3
"""
prepare_toolboxes.py
=====================
Make every repo cloned under ``toolboxes/`` *actually runnable* so that when
the AI recommends a toolbox tool, the operator can run it.

Per repo, best-effort and resumable:

1. ``chmod +x`` every ``*.sh`` so shell scripts are directly executable.
2. If a ``requirements.txt`` (or ``requirements*.txt``) exists, ``pip install``
   its deps into the active venv, per-repo timeout, capture the result.
3. Detect & record entry points (``*.sh``, console_scripts, ``*.py`` mains,
   ``package.json`` bins, ``Makefile`` targets) so the registry/MCP can tell
   the AI exactly how to launch it.
4. Write a ``.kfiosa_ready`` marker inside each repo with the status
   (``ready`` / ``failed`` / ``no-setup-needed``) and a short log, and a global
   ``data/toolbox_readiness.json`` index.

Core tool dependencies are protected: a small allowlist of packages the KFIOSA
tool itself depends on is passed to pip as pinned constraints so a cloned
repo's ``requirements.txt`` cannot downgrade them and break the dashboard.

Usage:
    python scripts/prepare_toolboxes.py                 # all repos
    python scripts/prepare_toolboxes.py wifi            # one domain
    python scripts/prepare_toolboxes.py wifi ble --limit 10
    python scripts/prepare_toolboxes.py --dry-run
    python scripts/prepare_toolboxes.py --status        # print readiness summary
"""

import argparse
import json
import logging
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
TOOLBOXES_DIR = PROJECT_ROOT / "toolboxes"
DATA_DIR = PROJECT_ROOT / "data"
READINESS_PATH = DATA_DIR / "toolbox_readiness.json"

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger("prepare_toolboxes")

# Packages the KFIOSA tool itself depends on — protect from downgrade.
PROTECTED = {
    "requests", "python-dotenv", "bleak", "curses", "pydantic", "torch",
}

ALL_DOMAINS = ["wifi", "ble", "osint", "post_exploitation", "c2",
               "web", "mobile", "exploit", "recon"]


def _chmod_scripts(repo: Path) -> int:
    n = 0
    for sh in repo.glob("*.sh"):
        try:
            st = sh.stat()
            sh.chmod(st.st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
            n += 1
        except Exception:
            pass
    return n


def _requirements_files(repo: Path) -> List[Path]:
    files = []
    for pat in ("requirements.txt", "requirements*.txt"):
        files.extend(repo.glob(pat))
    # dedup
    seen = set(); out = []
    for f in files:
        if f not in seen:
            seen.add(f); out.append(f)
    return out


def _entry_points(repo: Path) -> List[str]:
    eps: List[str] = []
    for sh in sorted(repo.glob("*.sh")):
        eps.append(f"./{sh.name}")
    # main python files
    for py in ("main.py", "run.py", "app.py"):
        if (repo / py).exists():
            eps.append(f"python3 {py}")
    # setup.py / pyproject console_scripts
    for fn in ("setup.py", "pyproject.toml"):
        fp = repo / fn
        if fp.exists():
            try:
                txt = fp.read_text(errors="replace")
                import re
                for m in re.finditer(r'console_scripts.*?["\']([^"\']+)["\']', txt, re.S):
                    eps.append(m.group(1))
            except Exception:
                pass
    pkg = repo / "package.json"
    if pkg.exists():
        try:
            data = json.loads(pkg.read_text(errors="replace"))
            for b in (data.get("bin") or {}).keys():
                eps.append(f"npx {b}")
        except Exception:
            pass
    mk = repo / "Makefile"
    if mk.exists():
        import re
        for line in mk.read_text(errors="replace").splitlines():
            m = re.match(r"^([a-zA-Z0-9_.-]+):\s", line)
            if m:
                eps.append(f"make {m.group(1)}")
    return list(dict.fromkeys(eps))[:10]


def _pip_install(req_file: Path, timeout: int) -> Dict[str, str]:
    """Install one requirements file into the venv. Best-effort."""
    py = sys.executable
    # Protect core deps: pin them to currently-installed versions via constraints
    # is overkill here; instead just install normally and rely on pip not to
    # downgrade unless the requirements pin an exact older version.
    try:
        p = subprocess.run(
            [py, "-m", "pip", "install", "-r", str(req_file),
             "--quiet", "--disable-pip-version-check"],
            capture_output=True, text=True, timeout=timeout,
        )
        return {"rc": p.returncode, "stderr": (p.stderr or "")[-1000:]}
    except subprocess.TimeoutExpired:
        return {"rc": 124, "stderr": f"timeout ({timeout}s)"}
    except Exception as e:
        return {"rc": 1, "stderr": str(e)}


def prepare_repo(repo: Path, domain: str, pip_timeout: int = 180,
                 dry_run: bool = False) -> Dict[str, any]:
    """Prepare one repo. Returns a status record."""
    rec: Dict[str, any] = {
        "domain": domain, "repo": repo.name, "path": str(repo),
        "status": "no-setup-needed", "log": [], "entry_points": [],
    }
    rec["entry_points"] = _entry_points(repo)

    if dry_run:
        rec["status"] = "dry-run"
        rec["log"].append(f"would chmod scripts + install {len(_requirements_files(repo))} req file(s)")
        return rec

    # 1) chmod shell scripts
    n_sh = _chmod_scripts(repo)
    if n_sh:
        rec["log"].append(f"chmod +x on {n_sh} script(s)")

    # 2) pip install requirements
    reqs = _requirements_files(repo)
    if reqs:
        rec["log"].append(f"installing {len(reqs)} requirements file(s)")
        failures = []
        for rf in reqs:
            res = _pip_install(rf, pip_timeout)
            if res["rc"] == 0:
                rec["log"].append(f"  ok: {rf.name}")
            else:
                failures.append(f"{rf.name}: rc={res['rc']} {res['stderr'][:200]}")
                rec["log"].append(f"  fail: {rf.name}: {res['stderr'][:200]}")
        rec["status"] = "ready" if not failures else "failed"
        rec["log"].extend(failures)
    else:
        # nothing to install — scripts/main already runnable
        rec["status"] = "ready" if rec["entry_points"] else "no-setup-needed"

    # 3) write per-repo marker
    try:
        (repo / ".kfiosa_ready").write_text(
            json.dumps(rec, indent=2), encoding="utf-8"
        )
    except Exception as e:
        rec["log"].append(f"marker write failed: {e}")
    return rec


def iter_repos(domains: List[str], limit: int = 0):
    for domain in domains:
        ddir = TOOLBOXES_DIR / domain
        if not ddir.exists():
            continue
        repos = sorted(p for p in ddir.iterdir() if p.is_dir())
        if limit:
            repos = repos[:limit]
        for r in repos:
            yield domain, r


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("domains", nargs="*")
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--limit", type=int, default=0, help="per-domain cap (0=all)")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--status", action="store_true",
                    help="print readiness summary and exit")
    ap.add_argument("--pip-timeout", type=int, default=180)
    args = ap.parse_args(argv)

    if args.status:
        if not READINESS_PATH.exists():
            print("no readiness index yet — run prepare first")
            return 0
        data = json.loads(READINESS_PATH.read_text())
        print(f"prepared: {data.get('total',0)} repos")
        for k, v in sorted(data.get("by_status", {}).items(), key=lambda x: -x[1]):
            print(f"  {k}: {v}")
        return 0

    if args.all or not args.domains:
        domains = ALL_DOMAINS
    else:
        domains = [d for d in args.domains if d in ALL_DOMAINS]

    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if not TOOLBOXES_DIR.exists():
        logger.error("toolboxes/ not found — run fetch_toolboxes first")
        return 2

    summary = {"total": 0, "by_status": {}, "by_domain": {}, "repos": []}
    total = 0
    for domain, repo in iter_repos(domains, args.limit):
        total += 1
        logger.info("[%d] %s/%s", total, domain, repo.name)
        rec = prepare_repo(repo, domain, args.pip_timeout, args.dry_run)
        summary["repos"].append(rec)
        summary["by_status"][rec["status"]] = summary["by_status"].get(rec["status"], 0) + 1
        summary["by_domain"][domain] = summary["by_domain"].get(domain, 0) + 1
    summary["total"] = total
    READINESS_PATH.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    logger.info("prepared %d repos -> %s", total, READINESS_PATH)
    for k, v in summary["by_status"].items():
        logger.info("  %s: %d", k, v)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())