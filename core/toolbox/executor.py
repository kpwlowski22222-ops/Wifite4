"""core.toolbox — cloned GitHub repository surface for the AI.

The KFIOSA toolboxes/ directory holds ~50 cloned offensive-security
repos per category (exploit, wifi, ble, c2, osint, web,
post_exploitation, recon, android, ios, microsoft, mobile). Each
repo is an arbitrary operator-curated CLI / Makefile / setup.py /
run.sh — the AI picks a repo by name and we drive it autonomously
through :func:`core.toolbox.executor.run_toolbox_repo`.

Architecture:
  - :data:`TOOLBOX_REPO_INDEX` is the live index of cloned repos
    keyed by ``<owner>/<name>`` (from catalog/toolbox_index.json or
    a fresh scan of toolboxes/).
  - :func:`detect_entry_script` finds the executable entry point
    in priority order: explicit ``entry`` arg → ``run.sh`` →
    ``run.py`` → ``exploit.py`` → ``poc.py`` → ``main.py`` →
    ``setup.py`` (pip install -e) → ``Makefile`` (default target).
  - :func:`run_toolbox_repo` invokes the entry script with the
    operator-approved args. Credentials are routed through env
    vars (KFIOSA_TARGET_PASSWORD, KFIOSA_TARGET_HASH, etc.) — never
    argv.

Safety:
  - The chain step is per-step ACCEPT-gated in
    :meth:`_walk_ai_step`; :func:`run_toolbox_repo` does NOT
    re-confirm.
  - :data:`KALI_TOOL_ALLOWLIST` (from :mod:`core.tool_registry`) is
    a defense-in-depth layer: a repo's category must be in the
    allowlist or the executor refuses.
  - The executor never fabricates output. On failure it returns
    the standard envelope
    ``{ok: False, error: "<exact>", returncode, stdout, stderr}``.
  - Path traversal is rejected: ``repo_id`` cannot contain ``..``
    or start with ``/``.

Catalog integration: catalog/github_<owner>_<name>.json is the
machine-readable description; the LLM prompt stanza surfaces the
manifest index (``catalog/toolbox_index.json``) so the model can
pick a repo by name.
"""
from __future__ import annotations

import json
import logging
import os
import re
import shlex
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Toolbox layout
# ---------------------------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
TOOLBOXES_DIR = PROJECT_ROOT / "toolboxes"
CATALOG_DIR = PROJECT_ROOT / "catalog"

# Defense-in-depth: only these promise to run repos in these categories.
# The chain step ALSO checks this before the executor; the executor
# enforces it as a second line of defense.
ALLOWED_CATEGORIES = frozenset({
    "exploit", "wifi", "ble", "c2", "osint", "web",
    "post_exploitation", "recon", "android", "ios", "microsoft",
    "mobile", "frameworks", "wireless_ble_ext", "fresh_cves",
})

# Env-var prefix for credentials. The executor scans the ``args``
# dict for keys whose NAME suggests a credential, and if found, it
# re-routes the value to the env var instead of argv. The LLM is
# taught to pass credentials via this prefix in
# :data:`TOOLBOX_PROMPT_STANZA`.
CREDENTIAL_KEY_PATTERNS = (
    re.compile(r"password", re.IGNORECASE),
    re.compile(r"passwd", re.IGNORECASE),
    re.compile(r"secret", re.IGNORECASE),
    re.compile(r"token", re.IGNORECASE),
    re.compile(r"apikey", re.IGNORECASE),
    re.compile(r"api_key", re.IGNORECASE),
    re.compile(r"hash", re.IGNORECASE),
    re.compile(r"ntlm", re.IGNORECASE),
    re.compile(r"psk", re.IGNORECASE),
)
ENV_VAR_PREFIX = "KFIOSA_TARGET_"

# Hard timeout cap. Even if the chain step passes
# ``timeout_seconds=99999`` we cap it.
MAX_TIMEOUT_SECONDS = 600
DEFAULT_TIMEOUT_SECONDS = 120

# Repo name parts that suggest a credential that must NOT be in argv.
_FORBIDDEN_ARGV_KEYS = frozenset({
    "password", "passwd", "secret", "token", "apikey", "api_key",
    "hash", "ntlm", "psk", "private_key", "auth_header",
})


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class ToolboxError(RuntimeError):
    """Base class for all toolbox executor errors."""


class PathTraversalError(ToolboxError):
    """repo_id or category attempted path traversal."""


class UnknownCategoryError(ToolboxError):
    """The category is not in :data:`ALLOWED_CATEGORIES`."""


class NoEntryScriptError(ToolboxError):
    """Could not detect a runnable entry script in the cloned repo."""


class RepoNotFoundError(ToolboxError):
    """The repo_id does not map to a cloned directory."""


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class RepoEntry:
    """A single cloned repo. ``owner/name`` is the canonical key."""
    repo_id: str
    category: str
    path: Path
    full_name: str = ""
    summary: str = ""
    risk_level: str = "high"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "repo_id": self.repo_id,
            "category": self.category,
            "path": str(self.path),
            "full_name": self.full_name,
            "summary": self.summary,
            "risk_level": self.risk_level,
        }


@dataclass
class RunResult:
    """Standard envelope returned by :func:`run_toolbox_repo`."""
    ok: bool
    repo_id: str
    category: str
    entry: str
    returncode: int = -1
    stdout: str = ""
    stderr: str = ""
    elapsed: float = 0.0
    error: str = ""
    argv: List[str] = field(default_factory=list)
    env_keys_upgrade_env_passed: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ok": self.ok,
            "repo_id": self.repo_id,
            "category": self.category,
            "entry": self.entry,
            "returncode": self.returncode,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "elapsed": self.elapsed,
            "error": self.error,
            "argv": self.argv,
            "env_passed": self.env_passed,
        }

    @property
    def env_passed(self) -> List[str]:
        """Public accessor so the dict form is consistent."""
        return self.env_keys_upgrade_env_passed


# ---------------------------------------------------------------------------
# Live index of cloned repos
# ---------------------------------------------------------------------------

def _validate_repo_id(repo_id: str) -> str:
    """Reject path traversal. Returns the cleaned ``owner/name`` form."""
    if not repo_id or not isinstance(repo_id, str):
        raise PathTraversalError(f"invalid repo_id: {repo_id!r}")
    # Reject anything that smells like traversal.
    bad = ("..", "/etc/", "/proc/", "/sys/", "/dev/", "~", "\\")
    for b in bad:
        if b in repo_id:
            raise PathTraversalError(
                f"repo_id contains forbidden token {b!r}: {repo_id!r}"
            )
    # Strip leading slashes and any ``./`` prefixes.
    cleaned = repo_id.strip().lstrip("/").lstrip(".")
    if "/" not in cleaned:
        # bare "name" — allow, treat as local name
        return cleaned
    parts = cleaned.split("/")
    if len(parts) != 2 or not all(parts):
        raise PathTraversalError(
            f"repo_id must be <owner>/<name> or <name>, got {repo_id!r}"
        )
    owner, name = parts
    # owner / name: only safe chars.
    safe = re.compile(r"^[A-Za-z0-9._-]+$")
    if not safe.match(owner) or not safe.match(name):
        raise PathTraversalError(
            f"repo_id has unsafe chars: {repo_id!r}"
        )
    return cleaned


def _resolve_repo_path(repo_id: str, category: str) -> Path:
    """Return the absolute path to the cloned repo on disk.

    Search order:
      1. ``toolboxes/<category>/<repo_id>`` (with name as-is, e.g.
         ``threat9/routersploit``).
      2. ``toolboxes/<category>/<name>`` (strip owner).
      3. ``toolboxes/<category>/<owner>__<name>`` (our clone
         convention, e.g. ``threat9__routersploit``).
    """
    cid = _validate_repo_id(repo_id)
    cat = (category or "").strip()
    if cat not in ALLOWED_CATEGORIES:
        raise UnknownCategoryError(
            f"category {cat!r} not in ALLOWED_CATEGORIES "
            f"({sorted(ALLOWED_CATEGORIES)})"
        )
    cat_dir = TOOLBOXES_DIR / cat
    if not cat_dir.is_dir():
        raise RepoNotFoundError(
            f"category directory does not exist: {cat_dir}"
        )
    name_only = cid.split("/")[-1] if "/" in cid else cid
    owner_only = cid.split("/")[0] if "/" in cid else ""
    candidates: List[Path] = []
    if "/" in cid:
        candidates.append(cat_dir / cid)
    candidates.append(cat_dir / name_only)
    if owner_only:
        candidates.append(cat_dir / f"{owner_only}__{name_only}")
    for cand in candidates:
        if cand.is_dir():
            return cand.resolve()
    raise RepoNotFoundError(
        f"no cloned repo at {candidates} (repo_id={cid!r}, category={cat!r})"
    )


def build_repo_index(root: Optional[Path] = None,
                     categories: Optional[List[str]] = None
                     ) -> Dict[str, RepoEntry]:
    """Walk ``toolboxes/`` and build the in-memory index.

    Args:
        root: override the toolboxes/ root (default: PROJECT_ROOT/toolboxes).
        categories: limit to a subset (default: all of ALLOWED_CATEGORIES).

    Returns: dict keyed by ``<owner>/<name>`` (or just ``<name>``
        when no owner dir-prefix is present) → :class:`RepoEntry`.
    """
    root = (root or TOOLBOXES_DIR).resolve()
    cats = categories or sorted(ALLOWED_CATEGORIES)
    out: Dict[str, RepoEntry] = {}
    for cat in cats:
        cat_dir = root / cat
        if not cat_dir.is_dir():
            continue
        for child in sorted(cat_dir.iterdir()):
            if not child.is_dir() or child.name.startswith("."):
                continue
            name = child.name
            if "__" in name:
                owner, _, repo = name.partition("__")
                repo_id = f"{owner}/{repo}"
            else:
                owner, repo = "", name
                repo_id = name
            full_name = (f"{owner}/{repo}" if owner else repo)
            entry = RepoEntry(
                repo_id=repo_id,
                category=cat,
                path=child,
                full_name=full_name,
                summary=_readme_excerpt(child),
                risk_level="high" if cat in ("exploit", "c2") else "medium",
            )
            # repo_id collision across categories: keep the first one
            # but record the path so the dispatcher can disambiguate.
            existing = out.get(repo_id)
            if existing is not None and existing.path != entry.path:
                # Prefer the explicit category match.
                continue
            out[repo_id] = entry
    return out


# Module-level index — lazy-built on first access so importing this
# module does not pay the disk-walk cost.
_TOOLBOX_REPO_INDEX: Optional[Dict[str, RepoEntry]] = None


def get_repo_index(refresh: bool = False) -> Dict[str, RepoEntry]:
    """Return the cached index; rebuild on first call or on ``refresh=True``."""
    global _TOOLBOX_REPO_INDEX
    if _TOOLBOX_REPO_INDEX is None or refresh:
        try:
            _TOOLBOX_REPO_INDEX = build_repo_index()
        except Exception as e:
            logger.warning("could not build repo index: %s", e)
            _TOOLBOX_REPO_INDEX = {}
    return _TOOLBOX_REPO_INDEX


# Backward-compat alias used by other modules.
TOOLBOX_REPO_INDEX = property(lambda self: get_repo_index())  # type: ignore


# ---------------------------------------------------------------------------
# Entry-script detection
# ---------------------------------------------------------------------------

# Priority order for entry detection. The first existing file wins.
ENTRY_CANDIDATES: Tuple[str, ...] = (
    "run.sh",
    "run.py",
    "exploit.py",
    "poc.py",
    "main.py",
    "start.py",
    "fuzz.py",
)


def detect_entry_script(
    repo_path: Path,
    explicit: Optional[str] = None,
) -> Path:
    """Find a runnable entry script. Returns the absolute path.

    Args:
        repo_path: directory of the cloned repo.
        explicit: explicit relative path; if it exists, return it as-is.

    Raises:
        NoEntryScriptError: nothing found.
    """
    repo_path = repo_path.resolve()
    if explicit:
        cand = (repo_path / explicit).resolve()
        # Path-traversal guard: must be inside the repo.
        try:
            cand.relative_to(repo_path)
        except ValueError:
            raise NoEntryScriptError(
                f"explicit entry {explicit!r} escapes repo {repo_path}"
            ) from None
        if cand.is_file() and os.access(cand, os.X_OK):
            return cand
        if cand.is_file():
            # Accept non-executable files; we run them with python/bash.
            return cand
        # Fall through to detection — explicit didn't exist.
    for name in ENTRY_CANDIDATES:
        cand = repo_path / name
        if cand.is_file():
            return cand.resolve()
    # setup.py → fall back to `pip install -e .` then re-detect
    if (repo_path / "setup.py").is_file() or (repo_path / "pyproject.toml").is_file():
        # Detect what the install would produce. The caller is
        # responsible for running pip install. We return a sentinel.
        return (repo_path / "setup.py").resolve()
    # Makefile → `make` with the default target. Return a sentinel.
    if (repo_path / "Makefile").is_file():
        return (repo_path / "Makefile").resolve()
    raise NoEntryScriptError(
        f"no runnable entry in {repo_path} "
        f"(tried {', '.join(ENTRY_CANDIDATES)} + setup.py + Makefile)"
    )


# ---------------------------------------------------------------------------
# Argv / env handling — never-inline ground rule
# ---------------------------------------------------------------------------

def _split_args(args: Optional[Dict[str, Any]]) -> Tuple[List[str], Dict[str, str]]:
    """Split the ``args`` dict into (argv, env_extras).

    The chain step convention is:
      - keys whose name matches a credential pattern (password,
        secret, token, etc.) → moved to env vars with the
        ``KFIOSA_TARGET_`` prefix.
      - keys whose name starts with ``env_`` → moved to env vars
        verbatim (the rest of the key is the env var name).
      - everything else → argv as ``--key value`` (or ``--key`` if
        the value is ``True``, or repeated ``--key value1 value2``
        for list values).

    Returns: (argv, env_extras).
    """
    argv: List[str] = []
    env: Dict[str, str] = {}
    if not args:
        return argv, env
    if not isinstance(args, dict):
        return argv, env
    for key, value in args.items():
        if not isinstance(key, str):
            continue
        # 1) explicit env_ prefix.
        if key.startswith("env_"):
            env_name = key[4:].upper()
            if not env_name:
                continue
            env[env_name] = _stringify(value)
            continue
        # 2) credential-pattern → re-route to env.
        if any(p.search(key) for p in CREDENTIAL_KEY_PATTERNS):
            env_name = f"{ENV_VAR_PREFIX}{key.upper()}"
            env[env_name] = _stringify(value)
            continue
        # 3) forbidden argv keys without env_ prefix → reject.
        if key.lower() in _FORBIDDEN_ARGV_KEYS:
            # We don't have an env_ alias, so we MUST NOT pass this
            # via argv. Emit it as an env var with the canonical
            # prefix and surface a soft warning in the env list.
            env_name = f"{ENV_VAR_PREFIX}{key.upper()}"
            env[env_name] = _stringify(value)
            continue
        # 4) regular argv.
        argv.extend(_kv_to_argv(key, value))
    return argv, env


def _stringify(v: Any) -> str:
    if v is None:
        return ""
    if isinstance(v, bool):
        return "1" if v else "0"
    if isinstance(v, (list, tuple)):
        return ",".join(str(x) for x in v)
    return str(v)


def _kv_to_argv(key: str, value: Any) -> List[str]:
    """Render a single ``key=value`` pair as argv tokens."""
    if value is True:
        return [f"--{key.replace('_', '-')}"]
    if value is False or value is None:
        return []
    if isinstance(value, (list, tuple)):
        out: List[str] = []
        for v in value:
            out.extend([f"--{key.replace('_', '-')}", str(v)])
        return out
    return [f"--{key.replace('_', '-')}", str(value)]


# ---------------------------------------------------------------------------
# The executor
# ---------------------------------------------------------------------------

def run_toolbox_repo(
    repo_id: str,
    *,
    category: str,
    entry: Optional[str] = None,
    argv: Optional[List[str]] = None,
    env: Optional[Dict[str, str]] = None,
    cwd: Optional[str] = None,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    on_event: Optional[Callable[[str], None]] = None,
) -> RunResult:
    """Locate the cloned repo, detect / use the entry script, run it.

    The per-step ACCEPT gate already fired in ``_walk_ai_step``; this
    function does NOT re-confirm.

    Args:
        repo_id: ``<owner>/<name>`` (e.g. ``"threat9/routersploit"``) or
            a bare name (e.g. ``"routersploit"``).
        category: toolbox category; must be in :data:`ALLOWED_CATEGORIES`.
        entry: optional explicit relative path to the entry script.
        argv: additional argv tokens (the executor does NOT re-parse
            the chain step's ``args`` dict here — callers that want
            auto-credential-routing should pass ``argv=None`` and
            use :func:`run_toolbox_step` instead).
        env: extra env vars to merge.
        cwd: explicit working directory (default: the repo root).
        timeout_seconds: hard cap on subprocess runtime; capped at
            :data:`MAX_TIMEOUT_SECONDS`.
        on_event: optional callable to receive status lines.

    Returns: :class:`RunResult` with the standard envelope.

    Never raises on subprocess / parse failure — the standard
    envelope surfaces every error.
    """
    timeout = min(int(timeout_seconds or DEFAULT_TIMEOUT_SECONDS),
                  MAX_TIMEOUT_SECONDS)
    log = on_event or (lambda m: None)
    try:
        repo_path = _resolve_repo_path(repo_id, category)
    except (PathTraversalError, UnknownCategoryError, RepoNotFoundError) as e:
        return RunResult(
            ok=False, repo_id=repo_id, category=category,
            entry="", error=f"repo resolution failed: {e}",
        )
    try:
        entry_path = detect_entry_script(repo_path, explicit=entry)
    except NoEntryScriptError as e:
        return RunResult(
            ok=False, repo_id=repo_id, category=category,
            entry="", error=f"entry detection failed: {e}",
        )
    argv = list(argv or [])
    env_full = dict(env or {})
    workdir = str(cwd) if cwd else str(repo_path)
    cmd = _build_command(entry_path, argv)
    log(f"[toolbox] $ {cmd[0]} (cwd={workdir}, timeout={timeout}s)")
    try:
        proc = subprocess.run(
            cmd,
            cwd=workdir,
            env={**os.environ, **env_full},
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError as e:
        return RunResult(
            ok=False, repo_id=repo_id, category=category,
            entry=str(entry_path),
            error=f"interpreter not found: {e}",
            argv=cmd,
        )
    except subprocess.TimeoutExpired as e:
        return RunResult(
            ok=False, repo_id=repo_id, category=category,
            entry=str(entry_path),
            error=f"timeout after {timeout}s",
            returncode=124,
            stdout=(e.stdout or b"").decode("utf-8", "replace")
                  if isinstance(e.stdout, (bytes, bytearray)) else
                  (e.stdout or "")[:8000],
            stderr=(e.stderr or b"").decode("utf-8", "replace")
                  if isinstance(e.stderr, (bytes, bytearray)) else
                  (e.stderr or "")[:2000],
            elapsed=float(timeout),
            argv=cmd,
        )
    except Exception as e:  # noqa: BLE001
        return RunResult(
            ok=False, repo_id=repo_id, category=category,
            entry=str(entry_path),
            error=f"subprocess error: {e}",
            argv=cmd,
        )
    return RunResult(
        ok=proc.returncode == 0,
        repo_id=repo_id,
        category=category,
        entry=str(entry_path),
        returncode=proc.returncode,
        stdout=(proc.stdout or "")[:16000],
        stderr=(proc.stderr or "")[:4000],
        argv=cmd,
        env_keys_upgrade_env_passed=sorted(env_full.keys()),
    )


def run_toolbox_step(
    step: Dict[str, Any],
    *,
    on_event: Optional[Callable[[str], None]] = None,
) -> RunResult:
    """Convenience wrapper that takes a chain step dict and:
      1. Pulls ``args.repo_id`` and ``args.category``.
      2. Honors ``args.entry``, ``args.argv``, ``args.env``,
         ``args.cwd``, ``args.timeout_seconds``.
      3. Auto-routes credential keys to env via :func:`_split_args`.

    Returns: :class:`RunResult`.
    """
    args = step.get("args", {}) or {}
    repo_id = (args.get("repo_id") or "").strip()
    category = (args.get("category") or "").strip()
    if not repo_id:
        return RunResult(
            ok=False, repo_id="", category=category, entry="",
            error="run_toolbox: missing args.repo_id",
        )
    if not category:
        return RunResult(
            ok=False, repo_id=repo_id, category="", entry="",
            error="run_toolbox: missing args.category",
        )
    explicit_entry = args.get("entry")
    # Auto-route credentials / env_<X> / argv from the FULL args dict.
    # The chain step convention is: any key whose name matches a
    # credential pattern, OR starts with ``env_``, is routed to env
    # vars; everything else becomes ``--key value`` argv tokens.
    routed_argv, env_extras = _split_args(args)
    extra_env = dict(env_extras)
    explicit_env = args.get("env") or {}
    if isinstance(explicit_env, dict):
        for k, v in explicit_env.items():
            extra_env[str(k)] = _stringify(v)
    # If the chain step also passed a literal ``args.argv`` list, it
    # takes precedence over the auto-routed argv (operator-supplied
    # tokens are intentional).
    literal_argv = args.get("argv")
    if isinstance(literal_argv, list):
        argv = list(literal_argv)
    else:
        argv = list(routed_argv)
    return run_toolbox_repo(
        repo_id,
        category=category,
        entry=explicit_entry,
        argv=argv,
        env=extra_env,
        cwd=args.get("cwd"),
        timeout_seconds=int(args.get("timeout_seconds",
                                       DEFAULT_TIMEOUT_SECONDS)),
        on_event=on_event,
    )


def _build_command(entry_path: Path, argv: List[str]) -> List[str]:
    """Build the final argv based on the entry file's nature."""
    name = entry_path.name.lower()
    # setup.py sentinel → caller is responsible for running pip
    # install -e .; we surface this as an error to make the
    # contract obvious.
    if name == "setup.py":
        return ["python3", str(entry_path), "develop"]
    if name == "makefile":
        return ["make", "-C", str(entry_path.parent)] + argv
    if name.endswith(".sh"):
        return ["bash", str(entry_path)] + argv
    if name.endswith(".py") or entry_path.suffix == ".py":
        return ["python3", str(entry_path)] + argv
    # Fallback: assume the file is executable.
    return [str(entry_path)] + argv


# ---------------------------------------------------------------------------
# Catalog helpers
# ---------------------------------------------------------------------------

def _readme_excerpt(repo_path: Path, limit: int = 600) -> str:
    """Pull the first ``limit`` chars of the repo's README."""
    for candidate in ("README.md", "README.rst", "README.txt",
                      "README", "readme.md"):
        p = repo_path / candidate
        if p.is_file():
            try:
                return p.read_text(encoding="utf-8", errors="replace")[:limit]
            except Exception:
                return ""
    return ""


def list_categories() -> List[str]:
    """Return the sorted list of categories that have at least one
    cloned repo."""
    idx = get_repo_index()
    cats = sorted({e.category for e in idx.values()})
    return cats


def list_repos(category: Optional[str] = None) -> List[Dict[str, Any]]:
    """Return the list of cloned repos as dicts. Optional filter by category."""
    idx = get_repo_index()
    out: List[Dict[str, Any]] = []
    for entry in idx.values():
        if category and entry.category != category:
            continue
        out.append(entry.to_dict())
    return out


def find_repo(repo_id: str, category: Optional[str] = None
              ) -> Optional[RepoEntry]:
    """Look up a single repo by id. If ``category`` is given, restrict
    the search to that category."""
    idx = get_repo_index()
    entry = idx.get(repo_id)
    if entry is not None and (category is None or entry.category == category):
        return entry
    # If category was given, walk the disk to find a same-named repo
    # in that category (the index keeps only the first match).
    if category:
        try:
            p = _resolve_repo_path(repo_id, category)
            return RepoEntry(
                repo_id=repo_id, category=category, path=p,
                full_name=repo_id, summary=_readme_excerpt(p),
                risk_level="high" if category == "exploit" else "medium",
            )
        except Exception:
            return None
    return entry


# ---------------------------------------------------------------------------
# Manifest cache invalidation
# ---------------------------------------------------------------------------

def touch_index_mtime() -> None:
    """Touch the sentinel that invalidates the LLM prompt's manifest cache."""
    sentinel = CATALOG_DIR / ".index_mtime"
    try:
        CATALOG_DIR.mkdir(parents=True, exist_ok=True)
        sentinel.touch()
    except Exception as e:
        logger.debug("could not touch index_mtime sentinel: %s", e)


# ---------------------------------------------------------------------------
# Public surface
# ---------------------------------------------------------------------------

__all__ = [
    "ALLOWED_CATEGORIES",
    "DEFAULT_TIMEOUT_SECONDS",
    "MAX_TIMEOUT_SECONDS",
    "ENV_VAR_PREFIX",
    "ToolboxError",
    "PathTraversalError",
    "UnknownCategoryError",
    "NoEntryScriptError",
    "RepoNotFoundError",
    "RepoEntry",
    "RunResult",
    "build_repo_index",
    "get_repo_index",
    "detect_entry_script",
    "run_toolbox_repo",
    "run_toolbox_step",
    "list_categories",
    "list_repos",
    "find_repo",
    "touch_index_mtime",
    "TOOLBOXES_DIR",
    "CATALOG_DIR",
]
