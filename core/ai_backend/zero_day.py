"""
Zero-Day Concept Path
=====================
"AI proposes, operator ACKs."

KFIOSA's chain runs real CVE exploits first; when none work for the
target (no matched KB exploit, all CVEs patched or wrong version),
the AI proposes a 0-day *concept* — a hypothesis about a
vulnerability class + technique + indicators + a draft PoC outline.
The concept is never executed automatically: the operator gets an
ACCEPT/CANCEL prompt, and only an ACK'd draft is persisted to
``data/zero_day_drafts/`` for later human work.

This is the closest the system gets to autonomous 0-day research
without crossing into research ethics: it produces a hypothesis a
human can take into a lab, not a working exploit. The two URLs the
operator originally cited (cpranavsharma/Zero-Day-Agent,
captainblastoff2026/Zero_Day) don't exist as 0-day generators in
practice — they are a 0.1B classifier and a 27kB markdown manifesto
respectively. We build the real concept path on top of the LLM we
already have (Ollama primary, ExploitGenModelManager uncensored
fallback) and rely on operator judgement for everything else.

Public surface
--------------
- :class:`ZeroDayConcept` — dataclass for a single concept draft.
- :class:`ZeroDayDraftStore` — JSON-file persistence under
  ``data/zero_day_drafts/``.
- :class:`ZeroDayProposer` — the AI-backed drafter; takes recon
  context, returns a concept (or raises).
- :func:`ack_draft` / :func:`reject_draft` — operator decisions
  that move a draft from ``pending`` to ``acked``/``rejected``.
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)


# Default location for 0-day drafts. Created on first save.
DEFAULT_DRAFTS_DIR = Path("data") / "zero_day_drafts"


# Schema for a concept — the LLM is asked to fill these fields.
_CONCEPT_SCHEMA = """{
  "title": "<short, human-readable name>",
  "hypothesis": "<one-sentence vulnerability hypothesis>",
  "target": "<software/hardware/firmware, version if known>",
  "vulnerability_class": "<e.g. use-after-free, integer overflow, race condition, auth bypass, injection>",
  "technique": "<how a researcher would prove the hypothesis — fuzzing, static analysis, code review, side channel, etc.>",
  "indicators": ["<things that would suggest the vuln exists, e.g. specific function names, syscalls, behaviors>"],
  "entry_point": "<where to start the investigation, e.g. specific daemon, service, library>",
  "tooling": ["<concrete tools a researcher would use: afl++, gdb, radare2, etc.>"],
  "draft_poc_outline": "<3-6 step outline of how a PoC would be built; NOT working code>",
  "risk_notes": "<what could go wrong, e.g. bricking a device, alert logs, detection risk>",
  "cve_hint": "<optional, plausible-looking CVE id format like CVE-2027-XXXXX; or empty string>",
  "confidence": "<low | medium | high — the AI's honest self-assessment>"
}"""

_SYSTEM_PROMPT = (
    "You are a senior vulnerability researcher drafting a 0-day\n"
    "concept for a real target. The output is a *hypothesis* and a\n"
    "research plan — NOT a working exploit. The researcher reading\n"
    "this will do the actual work in a lab; your job is to point\n"
    "them in the right direction with a tight, falsifiable idea.\n\n"
    "Output strict JSON matching this schema (no prose outside):\n\n"
    f"{_CONCEPT_SCHEMA}\n\n"
    "Rules:\n"
    "  - Be specific. Generic ideas ('look for buffer overflows') are\n"
    "    useless. Name the function, the daemon, the version.\n"
    "  - draft_poc_outline is 3-6 high-level steps. No working code.\n"
    "  - confidence must be honest. If you have no signal, say 'low'.\n"
    "  - indicators and tooling must be concrete (e.g. 'strace on the\n"
    "    httpd child', not 'dynamic analysis').\n"
    "  - If the recon data is too thin to form any hypothesis, return\n"
    "    exactly: {\"refusal\": true, \"reason\": \"<why>\"}"
)


def _strip_code_fence(text: str) -> str:
    s = (text or "").strip()
    if not s.startswith("```"):
        return s
    s = re.sub(r"^```[a-zA-Z0-9_+-]*\n?", "", s)
    s = re.sub(r"\n?```\s*$", "", s)
    return s.strip()


@dataclass
class ZeroDayConcept:
    """A 0-day concept draft. Mutable; the store updates ``status`` /
    ``acked_at`` when the operator decides."""

    draft_id: str
    target: Dict[str, Any]
    title: str
    hypothesis: str
    vulnerability_class: str
    technique: str
    indicators: List[str]
    entry_point: str
    tooling: List[str]
    draft_poc_outline: str
    risk_notes: str
    cve_hint: str
    confidence: str  # "low" | "medium" | "high"
    recon_context: Dict[str, Any] = field(default_factory=dict)
    status: str = "pending"  # pending | acked | rejected
    created_at: float = field(default_factory=time.time)
    acked_at: Optional[float] = None
    rejected_reason: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "ZeroDayConcept":
        # Be permissive: ignore unknown keys, default missing ones.
        return cls(
            draft_id=d.get("draft_id") or str(uuid.uuid4()),
            target=d.get("target", {}) or {},
            title=d.get("title", ""),
            hypothesis=d.get("hypothesis", ""),
            vulnerability_class=d.get("vulnerability_class", ""),
            technique=d.get("technique", ""),
            indicators=list(d.get("indicators", []) or []),
            entry_point=d.get("entry_point", ""),
            tooling=list(d.get("tooling", []) or []),
            draft_poc_outline=d.get("draft_poc_outline", ""),
            risk_notes=d.get("risk_notes", ""),
            cve_hint=d.get("cve_hint", ""),
            confidence=d.get("confidence", "low"),
            recon_context=d.get("recon_context", {}) or {},
            status=d.get("status", "pending"),
            created_at=float(d.get("created_at", time.time())),
            acked_at=d.get("acked_at"),
            rejected_reason=d.get("rejected_reason"),
        )

    def is_valid(self) -> bool:
        """Minimal completeness check: title, hypothesis, target,
        vulnerability_class, technique, draft_poc_outline non-empty."""
        return all([
            self.title.strip(),
            self.hypothesis.strip(),
            self.target,
            self.vulnerability_class.strip(),
            self.technique.strip(),
            self.draft_poc_outline.strip(),
        ])


class ZeroDayDraftStore:
    """JSON-file persistence for :class:`ZeroDayConcept` drafts.

    Layout: one file per draft, named ``<draft_id>.json`` under
    ``root_dir`` (default ``data/zero_day_drafts/``). The store never
    blocks; saves are atomic (``os.replace``) so a crash mid-write
    can't corrupt an existing draft.
    """

    def __init__(self, root_dir: Optional[Path] = None):
        self.root_dir = Path(root_dir) if root_dir else DEFAULT_DRAFTS_DIR
        try:
            self.root_dir.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            logger.warning("could not create drafts dir %s: %s", self.root_dir, e)

    def _path(self, draft_id: str) -> Path:
        return self.root_dir / f"{draft_id}.json"

    def save(self, concept: ZeroDayConcept) -> Path:
        """Persist the concept. Returns the file path."""
        p = self._path(concept.draft_id)
        tmp = p.with_suffix(".json.tmp")
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(concept.to_dict(), f, indent=2, default=str)
            os.replace(tmp, p)
        except Exception:
            # Clean up the tmp file on failure so it doesn't accumulate.
            try:
                tmp.unlink(missing_ok=True)
            except Exception:
                pass
            raise
        return p

    def get(self, draft_id: str) -> Optional[ZeroDayConcept]:
        p = self._path(draft_id)
        if not p.exists():
            return None
        try:
            with open(p, "r", encoding="utf-8") as f:
                return ZeroDayConcept.from_dict(json.load(f))
        except Exception as e:
            logger.warning("could not read draft %s: %s", p, e)
            return None

    def list(self, status: Optional[str] = None) -> List[ZeroDayConcept]:
        """List drafts, optionally filtered by status (pending/acked/rejected)."""
        out: List[ZeroDayConcept] = []
        try:
            for p in sorted(self.root_dir.glob("*.json")):
                try:
                    with open(p, "r", encoding="utf-8") as f:
                        d = json.load(f)
                except Exception:
                    continue
                c = ZeroDayConcept.from_dict(d)
                if status is None or c.status == status:
                    out.append(c)
        except Exception as e:
            logger.warning("could not list drafts in %s: %s", self.root_dir, e)
        return out


def ack_draft(store: ZeroDayDraftStore, draft_id: str) -> Optional[ZeroDayConcept]:
    """Mark a draft as operator-ACK'd. Returns the updated concept or
    ``None`` if the draft doesn't exist."""
    c = store.get(draft_id)
    if c is None:
        return None
    c.status = "acked"
    c.acked_at = time.time()
    store.save(c)
    return c


def reject_draft(store: ZeroDayDraftStore, draft_id: str,
                 reason: str = "") -> Optional[ZeroDayConcept]:
    """Mark a draft as operator-rejected. Returns the updated concept
    or ``None`` if the draft doesn't exist."""
    c = store.get(draft_id)
    if c is None:
        return None
    c.status = "rejected"
    c.rejected_reason = reason or "operator cancelled"
    store.save(c)
    return c


class ZeroDayRefusal(Exception):
    """The LLM refused to produce a concept (insufficient recon)."""


class ZeroDayProposer:
    """AI-backed 0-day concept drafter.

    Args:
        ai_backend: any object with ``.query(domain, prompt, context=...)``
            and an optional ``.domain_prompts`` dict (we inject our own
            strict JSON prompt).
        store: a :class:`ZeroDayDraftStore`. The proposer never
            ACKs a draft — it just creates ``pending`` drafts.
        domain: which AI domain the query uses (default
            ``"zero_day"``; falls back to ``"post_exploitation"`` if
            the backend has no prompt for it).
        on_event: optional ``callable(str)`` for activity log lines.
    """

    def __init__(self, ai_backend=None, store: Optional[ZeroDayDraftStore] = None,
                 domain: str = "zero_day",
                 on_event: Optional[Callable[[str], None]] = None):
        self.ai_backend = ai_backend
        self.store = store or ZeroDayDraftStore()
        self.domain = domain
        self.on_event = on_event

    def _emit(self, msg: str) -> None:
        if self.on_event is None:
            return
        try:
            self.on_event(msg)
        except Exception:
            pass

    def propose(self, target: Dict[str, Any],
                recon: Optional[Dict[str, Any]] = None,
                draft_id: Optional[str] = None) -> ZeroDayConcept:
        """Ask the LLM to draft a 0-day concept for ``target``.

        Returns a :class:`ZeroDayConcept` with ``status='pending'``;
        the operator must call :func:`ack_draft` to mark it
        operator-approved. Raises :class:`ZeroDayRefusal` when the
        LLM says it can't form a hypothesis. Raises ``RuntimeError``
        on a missing backend (never fakes output).
        """
        if self.ai_backend is None:
            raise RuntimeError("no AI backend wired into ZeroDayProposer")

        recon = recon or {}
        prompt = (
            f"Target: {json.dumps(target, default=str)[:1500]}\n"
            f"Recon: {json.dumps(recon, default=str)[:2500]}\n"
        )

        # Inject the strict JSON system prompt for this domain.
        original = getattr(self.ai_backend, "domain_prompts", {}) or {}
        injected = False
        try:
            if self.domain not in original:
                try:
                    self.ai_backend.domain_prompts[self.domain] = _SYSTEM_PROMPT
                    injected = True
                except Exception:
                    injected = False
            text = self.ai_backend.query(
                self.domain, prompt,
                context={"target": target, "recon": recon},
            )
        finally:
            if injected:
                try:
                    self.ai_backend.domain_prompts.pop(self.domain, None)
                except Exception:
                    pass

        raw = _strip_code_fence(text)
        if not raw:
            raise ZeroDayRefusal("LLM returned empty response")
        try:
            obj = json.loads(raw)
        except json.JSONDecodeError as e:
            raise ZeroDayRefusal(f"LLM returned non-JSON: {e}") from e
        if isinstance(obj, dict) and obj.get("refusal") is True:
            raise ZeroDayRefusal(
                f"LLM refused: {obj.get('reason', 'no reason given')}"
            )
        if not isinstance(obj, dict):
            raise ZeroDayRefusal(f"LLM returned non-dict JSON: {type(obj).__name__}")

        concept = ZeroDayConcept.from_dict({
            "draft_id": draft_id or str(uuid.uuid4()),
            "target": target,
            "recon_context": recon,
            **obj,
        })
        if not concept.is_valid():
            raise ZeroDayRefusal(
                "LLM concept missing required fields: "
                f"title={bool(concept.title)}, "
                f"hypothesis={bool(concept.hypothesis)}, "
                f"vulnerability_class={bool(concept.vulnerability_class)}, "
                f"technique={bool(concept.technique)}, "
                f"draft_poc_outline={bool(concept.draft_poc_outline)}"
            )
        # Persist as pending; the operator decides later.
        try:
            self.store.save(concept)
        except Exception as e:
            self._emit(f"[zero-day] WARNING: could not persist draft: {e}")
        return concept
