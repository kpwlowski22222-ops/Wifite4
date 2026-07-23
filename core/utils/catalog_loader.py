"""
Catalog Loader
==============
Lightweight, tolerant reader for the static Kali / GitHub catalog at
``catalog/`` (1,181 JSON files, schema in ``catalog.schema.json``).

The catalog is a materialized offline knowledge base — the schema is
JSON-Schema 2020-12 and the entries vary in shape (some have ``commands``,
some don't; some have ``metapackages``, some don't). We deliberately
avoid the ``jsonschema`` dependency (it is not in ``requirements.txt``)
and instead use a manual walker that tolerates missing fields.

Public API
----------
- :func:`load_catalog` -- return all catalog entries as :class:`Catalog` instances.
- :func:`filter_by_keywords` -- return entries that match any of the
    given tokens in their name, title, summary, or metapackage names.
- :class:`Catalog.context_block` -- render a compact text block for
    AI prompt injection.
"""

import json
import logging
import re
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
CATALOG_DIR = PROJECT_ROOT / "catalog"

# Hard cap on entries in a single prompt block. The model already has the
# live tool registry; this is a second, richer layer.
DEFAULT_PROMPT_LIMIT = 20
# Hard cap on the per-entry description length in the prompt.
DEFAULT_PROMPT_ENTRY_CHARS = 240
# Max per-entry commands rendered in prompt_line (keeps the block bounded).
DEFAULT_PROMPT_COMMANDS_PER_ENTRY = 4

# Tokens that mean "this is a WiFi / wireless entry" — used to short-list
# catalog entries for the WiFi recon / attack prompt.
WIFI_KEYWORDS = (
    "wifi", "wi-fi", "wireless", "802.11", "wpa", "wep", "wps", "aircrack",
    "airodump", "aireplay", "hostapd", "dnsmasq", "reaver", "bully", "wash",
    "pixiewps", "pmkid", "krack", "cowpatty", "hcxdump", "hcx", "wifite",
    "wifiphisher", "wifipumpkin", "mdk3", "mdk4", "eapmd5", "sparrow",
    "fern", "honeypot", "evil-twin", "evil_twin", "wpa3", "dragonblood",
)


def _truncate(text: str, limit: int) -> str:
    text = (text or "").strip()
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 1)].rstrip() + "…"


def _walk_strings(node, out: List[str], depth: int = 0, max_depth: int = 4):
    """Recursively collect string values from a JSON tree."""
    if depth > max_depth:
        return
    if isinstance(node, str):
        if node:
            out.append(node)
    elif isinstance(node, list):
        for item in node:
            _walk_strings(item, out, depth + 1, max_depth)
    elif isinstance(node, dict):
        for v in node.values():
            _walk_strings(v, out, depth + 1, max_depth)


class CatalogEntry:
    """A single catalog record (Kali package or GitHub repo)."""

    __slots__ = ("id", "kind", "name", "title", "summary", "metapackages",
                 "install_apt", "commands", "source_path", "extra")

    def __init__(self, id_: str, kind: str, name: str, title: str,
                 summary: str, metapackages: List[str], install_apt: str,
                 commands: List[Dict[str, str]], source_path: str,
                 extra: Dict):
        self.id = id_
        self.kind = kind
        self.name = name
        self.title = title or name
        self.summary = summary
        self.metapackages = list(metapackages or [])
        self.install_apt = install_apt
        self.commands = list(commands or [])
        self.source_path = source_path
        self.extra = extra or {}

    @property
    def is_kali(self) -> bool:
        return self.kind == "kali_source_package"

    @property
    def is_github(self) -> bool:
        return self.kind == "external_repository"

    def matches(self, tokens: Iterable[str]) -> bool:
        """True if any token appears in the entry's searchable text.

        Phase 5+: also searches the ``use_cases``,
        ``command_examples``, and ``tags`` arrays in ``extra`` so
        the LLM can find a tool by what it does or how to invoke
        it, not just by name."""
        if not tokens:
            return True
        # Curated summary + name + id
        haystack_parts: List[str] = [
            self.id or "", self.name or "", self.title or "",
            self.summary or "", " ".join(self.metapackages or []),
        ]
        # Phase 5+ enrichment: use_cases + command_examples + tags
        # from the extra blob. These are the fields the operator
        # asked to "describe as much as possible" — searching them
        # by token is what makes the catalog a useful LLM retrieval
        # surface.
        for key in ("use_cases", "command_examples", "tags"):
            v = self.extra.get(key) if isinstance(self.extra, dict) else None
            if isinstance(v, list):
                for item in v:
                    if isinstance(item, str):
                        haystack_parts.append(item)
        haystack = " ".join(haystack_parts).lower()
        for t in tokens:
            if t and t.lower() in haystack:
                return True
        return False

    def prompt_line(self, chars: int = DEFAULT_PROMPT_ENTRY_CHARS) -> str:
        """One-line prompt representation, truncated to ``chars``.

        Renders the entry header (kind + id + install.apt + metapackages +
        summary) on the first line, followed by up to
        :data:`DEFAULT_PROMPT_COMMANDS_PER_ENTRY` compact command lines
        (``cmd {name}: {usage} (risk={risk_level}) ex: {example}``) so
        the AI sees the rich per-command usage/example/risk the catalog
        JSON carries — not just command names. Malformed command records
        are skipped silently.

        Phase 5+: also surfaces the operator-curated ``use_cases`` and
        ``command_examples`` so the LLM sees when to use the tool and
        how to invoke it, not just what it is named.
        """
        bits: List[str] = []
        bits.append(f"- [{self.kind.split('_')[0]}] {self.id}")
        if self.install_apt:
            bits.append(f"install={self.install_apt}")
        if self.metapackages:
            bits.append("metapkgs=" + ",".join(self.metapackages[:3]))
        if self.summary:
            bits.append(_truncate(self.summary, chars))
        line = " ".join(bits)
        # Append up to N compact command lines (one per line, indented).
        for c in (self.commands or [])[:DEFAULT_PROMPT_COMMANDS_PER_ENTRY]:
            if not isinstance(c, dict):
                continue
            name = c.get("name") or ""
            if not name:
                continue
            usage = _truncate(c.get("usage") or "", 80)
            risk_level = c.get("risk_level") or ""
            example = _truncate(c.get("example") or "", 100)
            cmd_bits = [f"    cmd {name}:"]
            if usage:
                cmd_bits.append(usage)
            if risk_level:
                cmd_bits.append(f"(risk={risk_level})")
            if example:
                cmd_bits.append(f"ex: {example}")
            line += "\n" + " ".join(cmd_bits)
        # Phase 5+: surface curated use_cases + command_examples
        # from the extra blob. These are the operator-curated
        # hints the LLM uses to pick the right tool.
        if isinstance(self.extra, dict):
            uc = self.extra.get("use_cases")
            if isinstance(uc, list) and uc:
                line += "\n    use_cases:"
                for u in uc[:2]:
                    if isinstance(u, str):
                        line += f"\n      - {_truncate(u, 100)}"
            ce = self.extra.get("command_examples")
            if isinstance(ce, list) and ce:
                line += "\n    commands:"
                for c in ce[:2]:
                    if isinstance(c, str):
                        line += f"\n      - `{_truncate(c, 100)}`"
        return line

    def __repr__(self) -> str:
        return f"CatalogEntry(id={self.id!r}, kind={self.kind!r})"


def _parse_entry(path: Path, blob: Dict) -> Optional[CatalogEntry]:
    """Parse a single catalog JSON blob into a CatalogEntry. Returns
    ``None`` if the blob is missing required fields or cannot be
    interpreted as a catalog record."""
    if not isinstance(blob, dict):
        return None
    id_ = blob.get("id")
    kind = blob.get("kind")
    if not id_ or not kind:
        return None
    name = (blob.get("name") or id_.split(":", 1)[-1] or "").strip()
    title = (blob.get("title") or name).strip()
    summary = (blob.get("summary") or blob.get("description") or "").strip()
    if summary.startswith("#"):
        # Headings leak into the summary field for some Kali entries;
        # strip the leading markdown.
        summary = re.sub(r"^#+\s*", "", summary).strip()

    metapackages = []
    raw_mp = blob.get("metapackages")
    if isinstance(raw_mp, list):
        for m in raw_mp:
            if isinstance(m, str):
                metapackages.append(m)

    install_apt = ""
    raw_install = blob.get("install")
    if isinstance(raw_install, dict):
        apt = raw_install.get("apt")
        if isinstance(apt, str):
            install_apt = apt

    commands: List[Dict[str, str]] = []
    # Entry-level risk level (fallback for commands that omit their own).
    entry_risk_level = ""
    raw_entry_risk = blob.get("risk")
    if isinstance(raw_entry_risk, dict):
        rl = raw_entry_risk.get("level")
        if isinstance(rl, str):
            entry_risk_level = rl
    raw_cmds = blob.get("commands")
    if isinstance(raw_cmds, list):
        for c in raw_cmds:
            if isinstance(c, dict):
                cname = c.get("name")
                if not isinstance(cname, str) or not cname:
                    continue
                # usage
                usage = c.get("usage")
                if not isinstance(usage, str):
                    usage = ""
                # first example command string
                example = ""
                raw_ex = c.get("examples")
                if isinstance(raw_ex, list) and raw_ex:
                    ex0 = raw_ex[0]
                    if isinstance(ex0, dict):
                        ec = ex0.get("command")
                        if isinstance(ec, str):
                            example = ec.splitlines()[0] if ec else ""
                    elif isinstance(ex0, str):
                        example = ex0.splitlines()[0] if ex0 else ""
                # command risk level (fallback to entry's)
                risk_level = entry_risk_level
                raw_c_risk = c.get("risk")
                if isinstance(raw_c_risk, dict):
                    rl = raw_c_risk.get("level")
                    if isinstance(rl, str):
                        risk_level = rl
                commands.append({
                    "name": cname,
                    "usage": usage,
                    "example": example,
                    "risk_level": risk_level,
                })
            elif isinstance(c, str):
                commands.append({"name": c, "usage": "", "example": "",
                                 "risk_level": entry_risk_level})

    return CatalogEntry(
        id_=id_, kind=kind, name=name, title=title,
        summary=summary, metapackages=metapackages,
        install_apt=install_apt, commands=commands,
        source_path=str(path),
        extra=blob,
    )


def _iter_catalog_files(root: Path) -> Iterable[Path]:
    """Yield every JSON file under ``root`` (one level, no recursion)."""
    if not root.exists() or not root.is_dir():
        return
    for p in sorted(root.glob("*.json")):
        if p.is_file():
            yield p


def load_catalog(root: Path = CATALOG_DIR,
                 kinds: Optional[Tuple[str, ...]] = None,
                 limit: Optional[int] = None
                 ) -> List[CatalogEntry]:
    """Load every catalog entry under ``root``.

    Args:
        root: the catalog directory.
        kinds: if given, only return entries whose ``kind`` is in this
            tuple (e.g. ``("kali_source_package",)``).
        limit: optional max number of entries to return.

    Returns:
        A list of :class:`CatalogEntry` instances. Best-effort:
        malformed files are skipped with a debug log, not raised.
    """
    out: List[CatalogEntry] = []
    for path in _iter_catalog_files(root):
        try:
            blob = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        except (OSError, json.JSONDecodeError) as e:
            logger.debug("skip catalog %s: %s", path.name, e)
            continue
        entry = _parse_entry(path, blob)
        if entry is None:
            continue
        if kinds and entry.kind not in kinds:
            continue
        out.append(entry)
        if limit is not None and len(out) >= limit:
            break
    return out


def filter_by_keywords(entries: Iterable[CatalogEntry],
                       tokens: Iterable[str]) -> List[CatalogEntry]:
    """Return only the entries that match any of the given tokens."""
    return [e for e in entries if e.matches(tokens)]


# ---------------------------------------------------------------------------
# Prompt-block renderer
# ---------------------------------------------------------------------------

class Catalog:
    """Wrapper that holds a loaded catalog and renders prompt blocks."""

    def __init__(self, entries: Optional[List[CatalogEntry]] = None,
                 root: Path = CATALOG_DIR):
        self._entries: List[CatalogEntry] = list(entries or [])
        self._root = root
        self._loaded: bool = bool(entries)

    @classmethod
    def load(cls, root: Path = CATALOG_DIR, kinds=None,
             limit: Optional[int] = None) -> "Catalog":
        return cls(entries=load_catalog(root, kinds=kinds, limit=limit),
                   root=root)

    def entries(self) -> List[CatalogEntry]:
        if not self._loaded:
            self._entries = load_catalog(self._root)
            self._loaded = True
        return self._entries

    def wifi_entries(self, limit: int = DEFAULT_PROMPT_LIMIT
                     ) -> List[CatalogEntry]:
        """Return WiFi-relevant Kali packages (or GitHub repos) up to
        ``limit``. Uses a streaming match so startup does not parse the
        entire catalog tree. Falls back to a capped full load if no
        keyword hits."""
        if self._loaded and self._entries:
            pool = filter_by_keywords(self._entries, WIFI_KEYWORDS)
            if pool:
                return pool[:limit]
        # Fast path: stop once we have ``limit`` WiFi hits
        try:
            pool = load_catalog_matching(WIFI_KEYWORDS, root=self._root,
                                         limit=limit)
        except Exception:  # noqa: BLE001
            pool = []
        if pool:
            return pool
        # Fallback: load at most 4× limit entries then filter
        pool = load_catalog(self._root, limit=max(limit * 4, 50))
        matched = filter_by_keywords(pool, WIFI_KEYWORDS)
        return (matched or pool)[:limit]

    def context_block(self, domain: Optional[str] = None,
                      limit: int = DEFAULT_PROMPT_LIMIT,
                      chars: int = DEFAULT_PROMPT_ENTRY_CHARS) -> str:
        """Render a compact 'AVAILABLE KALI PACKAGES' block for AI
        prompt injection. Returns ``""`` if the catalog directory is
        missing or empty.

        ``domain`` is currently honored for the ``"wifi"`` value; other
        domains return the most relevant Kali entries (limit-capped).
        """
        if domain == "wifi":
            pool = self.wifi_entries(limit=limit)
            header = ("AVAILABLE KALI PACKAGES (WiFi subset, from offline "
                      "catalog/; apt-installable, see install.apt):")
        else:
            pool = self.entries()[:limit]
            header = ("AVAILABLE KALI PACKAGES (from offline catalog/; "
                      "apt-installable, see install.apt):")
        if not pool:
            return ""
        lines: List[str] = [header]
        for e in pool:
            lines.append(e.prompt_line(chars=chars))
        lines.append(
            "When recommending an apt install, prefer the exact install.apt "
            "command shown. If a tool is not in the catalog, say so and "
            "give a concrete install plan."
        )
        return "\n".join(lines)


# Convenience module-level cache so callers don't re-parse 1,181 files
# on every prompt. The cache is invalidated only on process restart.
_CATALOG_CACHE: Optional[Catalog] = None


def load_catalog_matching(
    tokens: Iterable[str],
    root: Path = CATALOG_DIR,
    limit: int = 50,
) -> List[CatalogEntry]:
    """Load only enough catalog files to satisfy ``limit`` keyword hits.

    Avoids parsing thousands of JSON files on TUI startup when the
    caller only needs a small WiFi (or other) subset.
    """
    out: List[CatalogEntry] = []
    tok = tuple(tokens)
    for path in _iter_catalog_files(root):
        try:
            blob = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        except (OSError, json.JSONDecodeError) as e:
            logger.debug("skip catalog %s: %s", path.name, e)
            continue
        entry = _parse_entry(path, blob)
        if entry is None:
            continue
        if not entry.matches(tok):
            continue
        out.append(entry)
        if len(out) >= limit:
            break
    return out


def get_catalog() -> Catalog:
    """Return a process-cached :class:`Catalog` instance.

    First call uses a **lazy** Catalog that does not parse every JSON
    file until :meth:`Catalog.entries` is forced. Use
    :meth:`Catalog.wifi_entries` / :func:`load_catalog_matching` for
    fast partial loads at startup.
    """
    global _CATALOG_CACHE
    if _CATALOG_CACHE is None:
        try:
            # Lazy: empty shell; entries() loads on demand. wifi_entries
            # short-circuits via load_catalog_matching.
            _CATALOG_CACHE = Catalog(entries=None, root=CATALOG_DIR)
            _CATALOG_CACHE._loaded = False
            _CATALOG_CACHE._entries = []
            logger.debug("catalog cache initialized (lazy)")
        except Exception as e:
            logger.warning("catalog load failed: %s", e)
            _CATALOG_CACHE = Catalog(entries=[])
    return _CATALOG_CACHE
