"""Load project ``.env`` once and expose helpers for API keys / credentials.

Usage from any tool or script::

    from core.env_loader import load_project_env, env, require_env

    load_project_env()           # safe to call repeatedly
    key = env("NVD_API_KEY")     # str or default
    tok = require_env("GROQ_API_KEY")  # raises KeyError if missing/blank

Never log secret values. ``.env`` is gitignored; use ``.env.example`` as template.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, Optional

_LOADED = False
_ROOT: Optional[Path] = None


def project_root() -> Path:
    global _ROOT
    if _ROOT is None:
        _ROOT = Path(__file__).resolve().parents[1]
    return _ROOT


def load_project_env(
    *,
    dotenv_path: Optional[os.PathLike | str] = None,
    override: bool = False,
) -> bool:
    """Load ``.env`` from the repo root into ``os.environ``.

    Returns True if a file was loaded (or already loaded). Never raises.
    """
    global _LOADED
    path = Path(dotenv_path) if dotenv_path else project_root() / ".env"
    try:
        from dotenv import load_dotenv  # type: ignore
    except Exception:
        # Manual fallback: KEY=VAL lines only (no export, no quotes expansion)
        if not path.is_file():
            return _LOADED
        try:
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
                s = line.strip()
                if not s or s.startswith("#") or "=" not in s:
                    continue
                k, _, v = s.partition("=")
                k = k.strip()
                v = v.strip().strip('"').strip("'")
                if not k:
                    continue
                if override or k not in os.environ or os.environ.get(k, "") == "":
                    os.environ[k] = v
            _LOADED = True
            return True
        except Exception:
            return _LOADED
    try:
        if path.is_file():
            load_dotenv(path, override=override)
            _LOADED = True
        # Also load .env.example keys as blanks only if not set? No — never.
    except Exception:
        pass
    return _LOADED


def env(key: str, default: str = "") -> str:
    """Return env var as stripped string (loads .env first)."""
    load_project_env()
    val = os.environ.get(key)
    if val is None:
        return default
    return str(val).strip()


def env_bool(key: str, default: bool = False) -> bool:
    raw = env(key, "")
    if raw == "":
        return default
    return raw.lower() in ("1", "true", "yes", "on", "y")


def env_int(key: str, default: int = 0) -> int:
    raw = env(key, "")
    if raw == "":
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def require_env(key: str) -> str:
    """Return non-empty env value or raise KeyError with a helpful message."""
    val = env(key, "")
    if not val:
        raise KeyError(
            f"Missing required environment variable {key!r}. "
            f"Set it in {project_root() / '.env'} (see .env.example)."
        )
    return val


def credentials_status() -> Dict[str, Any]:
    """Return presence map for known credential keys (never values)."""
    load_project_env()
    keys = [
        "OLLAMA_CLOUD_TOKEN", "OLLAMA_AUTH_TOKEN", "OLLAMA_DEFAULT_MODEL",
        "OLLAMA_HOST",
        "GROQ_API_KEY", "GROQ_MODEL",
        "DEEPSEEK_API_KEY", "DEEPSEEK_MODEL",
        "GEMINI_API_KEY", "GEMINI_MODEL",
        "NVIDIA_API_KEY", "NGC_API_KEY", "NVIDIA_MODEL", "NVIDIA_BASE_URL",
        "GROK_API_KEY", "XAI_API_KEY", "GROK_MODEL",
        "SHODAN_API_KEY", "NVD_API_KEY", "HF_TOKEN",
        "HIBP_API_KEY", "KFIOSA_HIBP_KEY",
        "KISMET_API_KEY", "KISMET_CLIENT_USERNAME", "KISMET_CLIENT_PASSWORD",
        "GUS_BIR1_KEY", "ALLEGRO_CLIENT_ID", "ALLEGRO_CLIENT_SECRET",
        "GOOGLE_PROJECT_ID",
        "RAT_DASHBOARD_TOKEN", "RAT_DASHBOARD_HOST",
        "MSF_PASSWORD", "MSF_USER", "MSF_HOST", "MSF_PORT",
        "KFIOSA_SQL_URL",
    ]
    present = {}
    for k in keys:
        v = os.environ.get(k, "")
        present[k] = bool(str(v).strip())
    return {
        "env_file": str(project_root() / ".env"),
        "env_file_exists": (project_root() / ".env").is_file(),
        "loaded": _LOADED,
        "present": present,
        "present_count": sum(1 for x in present.values() if x),
        "known_count": len(keys),
    }


# Eager load on import so ``os.environ`` is ready for libraries that
# only read env once at import time. Best-effort; never raises.
load_project_env()
