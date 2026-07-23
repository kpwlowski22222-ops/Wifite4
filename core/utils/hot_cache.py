"""core.utils.hot_cache — creative multi-namespace TTL/LRU cache.

Used across KFIOSA hot paths (prompt blocks, feature extraction,
dispatch lookups, poly memo companions) so we don't re-walk catalogs
or re-import heavy modules on every chain step.

Design:
  * Namespaces isolate concerns (``mcp_block``, ``features``, …).
  * TTL expires stale reachability / tool inventory.
  * LRU cap keeps RAM bounded on long engagements (32 GB host still
    benefits — catalog strings are large).
  * Fingerprints prefer cheap stable keys over full json.dumps.
  * Thread-safe for TUI worker + main loop.

Never fabricates values; cache misses recompute honestly.
"""
from __future__ import annotations

import hashlib
import threading
import time
from typing import Any, Callable, Dict, Hashable, Optional, Tuple

__all__ = [
    "HotCache",
    "GLOBAL_CACHE",
    "fingerprint",
    "cached",
]


def fingerprint(*parts: Any, max_parts: int = 24) -> str:
    """Cheap stable fingerprint for cache keys.

    Scalars are joined; dicts use sorted shallow items (no deep walk).
    """
    bits: list = []
    for p in parts[:max_parts]:
        if p is None or isinstance(p, (str, int, float, bool)):
            bits.append(f"{type(p).__name__}:{p!s}")
        elif isinstance(p, dict):
            items = []
            for k in sorted(p.keys(), key=lambda x: str(x))[:32]:
                v = p[k]
                if isinstance(v, (str, int, float, bool)) or v is None:
                    items.append(f"{k}={v!s}")
                else:
                    items.append(f"{k}=<{type(v).__name__}>")
            bits.append("{" + ",".join(items) + "}")
        elif isinstance(p, (list, tuple, set, frozenset)):
            bits.append(f"[{len(p)}:{type(p).__name__}]")
        else:
            bits.append(f"<{type(p).__name__}:{id(p)}>")
    raw = "|".join(bits)
    if len(raw) <= 120:
        return raw
    return hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()[:32]


class HotCache:
    """Namespace → {key → (expires_at, value)} with LRU-ish eviction."""

    def __init__(self, default_ttl_s: float = 30.0, max_entries: int = 512):
        self.default_ttl_s = float(default_ttl_s)
        self.max_entries = int(max_entries)
        self._data: Dict[str, Dict[str, Tuple[float, Any]]] = {}
        self._lock = threading.RLock()
        self.hits = 0
        self.misses = 0

    def get(self, namespace: str, key: Hashable) -> Any:
        now = time.monotonic()
        with self._lock:
            bucket = self._data.get(namespace)
            if not bucket:
                self.misses += 1
                return _MISS
            hit = bucket.get(key)  # type: ignore[arg-type]
            if hit is None:
                self.misses += 1
                return _MISS
            exp, val = hit
            if exp < now:
                bucket.pop(key, None)  # type: ignore[arg-type]
                self.misses += 1
                return _MISS
            self.hits += 1
            return val

    def put(self, namespace: str, key: Hashable, value: Any,
            ttl_s: Optional[float] = None) -> Any:
        ttl = self.default_ttl_s if ttl_s is None else float(ttl_s)
        exp = time.monotonic() + max(0.0, ttl)
        with self._lock:
            bucket = self._data.setdefault(namespace, {})
            if len(bucket) >= self.max_entries and key not in bucket:
                # Evict earliest expiry (cheap approximate LRU)
                try:
                    oldest = min(bucket.items(), key=lambda kv: kv[1][0])
                    bucket.pop(oldest[0], None)
                except ValueError:
                    pass
            bucket[key] = (exp, value)  # type: ignore[index]
        return value

    def get_or_set(
        self,
        namespace: str,
        key: Hashable,
        factory: Callable[[], Any],
        ttl_s: Optional[float] = None,
    ) -> Any:
        val = self.get(namespace, key)
        if val is not _MISS:
            return val
        computed = factory()
        return self.put(namespace, key, computed, ttl_s=ttl_s)

    def clear(self, namespace: Optional[str] = None) -> None:
        with self._lock:
            if namespace is None:
                self._data.clear()
            else:
                self._data.pop(namespace, None)

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            entries = sum(len(b) for b in self._data.values())
            return {
                "hits": self.hits,
                "misses": self.misses,
                "entries": entries,
                "namespaces": sorted(self._data.keys()),
                "hit_rate": (
                    round(self.hits / max(1, self.hits + self.misses), 3)
                ),
            }


class _MissType:
    __slots__ = ()

    def __repr__(self) -> str:
        return "<CACHE_MISS>"


_MISS = _MissType()

# Process-wide shared cache (TUI + orchestrator + planner).
GLOBAL_CACHE = HotCache(default_ttl_s=45.0, max_entries=768)


def cached(
    namespace: str,
    ttl_s: float = 30.0,
    key_fn: Optional[Callable[..., Hashable]] = None,
):
    """Decorator: cache function results in :data:`GLOBAL_CACHE`."""

    def deco(fn: Callable[..., Any]) -> Callable[..., Any]:
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            if key_fn is not None:
                k = key_fn(*args, **kwargs)
            else:
                k = fingerprint(fn.__name__, args, kwargs)
            return GLOBAL_CACHE.get_or_set(
                namespace, k, lambda: fn(*args, **kwargs), ttl_s=ttl_s,
            )

        wrapper.__name__ = getattr(fn, "__name__", "cached")
        wrapper.__doc__ = getattr(fn, "__doc__", None)
        return wrapper

    return deco
