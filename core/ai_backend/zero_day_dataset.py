"""
Zero_Day dataset grounding for 0-day PoC generation
====================================================
Loads the Hugging Face ``captainblastoff2026/Zero_Day`` dataset (the
operator-cited companion to ``cpranavsharma/Zero-Day-Agent``) and injects
the top-K most-relevant entries — by recon / CVE keyword overlap — into
the 0-day exploit builder's prompt as additional grounding.

This is **grounding, not generation**: the dataset is a small markdown
manifesto; its entries seed the prompt with prior-art / phrasing the
uncensored coding model can condition on. The actual PoC still comes
from the generative model (the dedicated uncensored exploit-gen model
pulled by :class:`ExploitGenModelManager`), recon, and matched CVEs.

Graceful degradation: when ``datasets`` / ``huggingface_hub`` are not
installed, or the network / repo is unreachable, the loader returns
``{"available": False, "entries": []}`` and never raises. Hermetic tests
monkeypatch ``datasets.load_dataset``.
"""

from __future__ import annotations

import json
import logging
import os
import re
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

DEFAULT_DATASET_ID = "captainblastoff2026/Zero_Day"
DEFAULT_CACHE_DIR = os.path.join("data", "zero_day_dataset")
DEFAULT_CACHE_FILE = "cache.json"
_TOKEN_RE = re.compile(r"[a-z0-9]+")


def _tokens(text: str) -> set:
    return set(_TOKEN_RE.findall((text or "").lower()))


class ZeroDayDataset:
    """Lazily load + cache the ``captainblastoff2026/Zero_Day`` dataset.

    The first ``load()`` pulls the dataset via ``datasets.load_dataset``
    (gated import) and writes a JSON cache under ``cache_dir`` so later
    loads are offline. Subsequent loads read the cache. ``available``
    is True iff entries were loaded.
    """

    def __init__(self, dataset_id: str = DEFAULT_DATASET_ID,
                 cache_dir: Optional[str] = None,
                 on_event: Optional[Any] = None):
        self.dataset_id = dataset_id
        self.cache_dir = cache_dir or DEFAULT_CACHE_DIR
        self.on_event = on_event
        self._entries: List[Dict[str, Any]] = []
        self._available: Optional[bool] = None

    def _emit(self, msg: str) -> None:
        if self.on_event is None:
            return
        try:
            self.on_event(msg)
        except Exception:  # noqa: BLE001
            pass

    # ------------------------------------------------------------------
    def _cache_path(self) -> str:
        return os.path.join(self.cache_dir, DEFAULT_CACHE_FILE)

    def _load_from_cache(self) -> bool:
        try:
            with open(self._cache_path(), "r", encoding="utf-8") as fh:
                blob = json.load(fh)
            entries = blob.get("entries") if isinstance(blob, dict) else None
            if isinstance(entries, list):
                self._entries = entries
                return True
        except (OSError, ValueError, json.JSONDecodeError):
            pass
        return False

    def _save_cache(self) -> None:
        try:
            os.makedirs(self.cache_dir, exist_ok=True)
            with open(self._cache_path(), "w", encoding="utf-8") as fh:
                json.dump({"dataset_id": self.dataset_id,
                           "entries": self._entries}, fh)
        except Exception as e:  # noqa: BLE001
            logger.debug("zero_day_dataset cache write failed: %s", e)

    def load(self) -> Dict[str, Any]:
        """Load entries (cache → HF). Returns ``{"available", "count"}``.

        Never raises. On any failure ``available`` is False and the
        builder treats the grounding block as absent.
        """
        if self._available is not None:
            return {"available": self._available,
                    "count": len(self._entries)}
        if self._load_from_cache():
            self._available = True
            self._emit(
                f"[zero-day-dataset] loaded {len(self._entries)} entries "
                f"from cache"
            )
            return {"available": True, "count": len(self._entries)}
        try:
            from datasets import load_dataset  # type: ignore
        except Exception as e:  # noqa: BLE001
            logger.warning("datasets unavailable: %s", e)
            self._available = False
            return {"available": False, "count": 0}
        try:
            ds = load_dataset(self.dataset_id)
            entries = self._normalize(ds)
            if not entries:
                self._available = False
                return {"available": False, "count": 0}
            self._entries = entries
            self._available = True
            self._save_cache()
            self._emit(
                f"[zero-day-dataset] loaded {len(entries)} entries from "
                f"{self.dataset_id}"
            )
            return {"available": True, "count": len(entries)}
        except Exception as e:  # noqa: BLE001
            logger.warning("zero_day_dataset load failed: %s", e)
            self._available = False
            return {"available": False, "count": 0}

    @staticmethod
    def _normalize(ds: Any) -> List[Dict[str, Any]]:
        """Flatten a HF dataset (Dataset or DatasetDict) into entry dicts.

        Each entry is ``{"text": <str>}`` — the only field we rely on.
        Tolerates a DatasetDict (pick a split) and any column name that
        looks like free text.
        """
        rows = []
        try:
            if hasattr(ds, "values") and not hasattr(ds, "column_names"):
                # DatasetDict: take the first split.
                parts = list(ds.values())
                ds = parts[0] if parts else None
            if ds is None:
                return []
            cols = list(getattr(ds, "column_names", []) or [])
            text_col = None
            for cand in ("text", "content", "body", "markdown", "doc"):
                if cand in cols:
                    text_col = cand
                    break
            if text_col is None and cols:
                text_col = cols[0]
            if text_col is None:
                return []
            for row in ds:
                if isinstance(row, dict):
                    txt = row.get(text_col)
                else:
                    txt = getattr(row, text_col, None)
                if isinstance(txt, str) and txt.strip():
                    rows.append({"text": txt})
        except Exception as e:  # noqa: BLE001
            logger.debug("zero_day_dataset normalize failed: %s", e)
        return rows

    # ------------------------------------------------------------------
    def relevant_entries(self, query: str, k: int = 3) -> List[Dict[str, Any]]:
        """Return the top-K entries most-relevant to ``query`` by token
        overlap. Loads first (best-effort). Empty when unavailable."""
        if self._available is None:
            self.load()
        if not self._entries:
            return []
        qtok = _tokens(query)
        if not qtok:
            return list(self._entries[:k])
        scored = []
        for e in self._entries:
            toks = _tokens(e.get("text", ""))
            overlap = len(qtok & toks)
            if overlap > 0:
                scored.append((overlap, e))
        scored.sort(key=lambda t: t[0], reverse=True)
        return [e for _, e in scored[:k]]

    def grounding_block(self, query: str, k: int = 3) -> str:
        """Render the top-K relevant entries as a prompt-grounding block,
        or '' when the dataset is unavailable."""
        entries = self.relevant_entries(query, k=k)
        if not entries:
            return ""
        parts = ["ZERO_DAY DATASET GROUNDING (captainblastoff2026/Zero_Day):",
                 "Prior-art / phrasing to condition the PoC on — adapt, do",
                 "not copy verbatim:"]
        for i, e in enumerate(entries, 1):
            snippet = (e.get("text", "") or "")[:600].replace("\n", " ")
            parts.append(f"  [{i}] {snippet}")
        return "\n".join(parts) + "\n"