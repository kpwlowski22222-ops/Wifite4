"""core.post_access_tui.rat_ext.pdf_export — Phase 2.4 §B.9.

PDF report generation. The dashboard exposes
``GET /api/session/<sid>/report.pdf`` which aggregates:
  - session commands
  - capability invocations
  - exfil entries
  - persistence mechanisms
  - screen uploads
  - chain-step envelope hashes

Uses ``fpdf2`` (pip). Layout is plain text + tables (no fancy
CSS). The footer line carries a hash of the chain-step
envelopes so the operator can confirm what they saw on screen
matches the audit log.

If ``fpdf2`` is not installed, returns a plaintext stub
(``Content-Type: text/plain``) explaining the missing dep.

The default Courier font only supports Latin-1, so all text
is sanitized to ASCII before being added to the PDF. Non-ASCII
characters are transliterated to their closest ASCII equivalent
(em-dash -> hyphen, etc.) and any remaining non-Latin-1 chars
are replaced with '?'. This keeps the PDF builder robust to
operator-supplied session data that may contain unicode.
"""
from __future__ import annotations

import hashlib
import json
import time
import unicodedata
from typing import Any, Dict, List, Optional, Tuple


def _ascii_safe(text: str) -> str:
    """Sanitize a string for the built-in Courier font.

    Replaces em-dash, en-dash, smart-quotes etc. with ASCII
    equivalents; drops any remaining non-Latin-1 chars to '?'.
    """
    if not text:
        return ""
    # Common Unicode -> ASCII substitutions
    repl = {
        "—": "-",   # em-dash
        "–": "-",   # en-dash
        "‘": "'",   # left single quote
        "’": "'",   # right single quote
        "“": '"',   # left double quote
        "”": '"',   # right double quote
        "…": "...", # ellipsis
        " ": " ",   # non-breaking space
        "·": ".",   # middle dot
        "°": "deg", # degree
        "×": "x",   # multiplication
        "÷": "/",   # division
    }
    for k, v in repl.items():
        text = text.replace(k, v)
    # Drop anything still outside latin-1
    return text.encode("latin-1", errors="replace").decode("latin-1")


def _hash_envelopes(envelopes: List[Dict[str, Any]]) -> str:
    """Stable SHA-256 of the chain-step envelopes, sorted by ts."""
    def _key(e: Dict[str, Any]) -> str:
        return str(e.get("ts") or e.get("started") or "")
    sorted_env = sorted(envelopes, key=_key)
    blob = json.dumps(sorted_env, sort_keys=True, default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]


def build_session_report_bytes(session: Dict[str, Any]
                               ) -> Tuple[bytes, str]:
    """Build the per-session PDF report.

    Returns ``(bytes, content_type)``. The content type is
    ``application/pdf`` on success, or ``text/plain`` when
    fpdf2 is not installed (so the operator gets a clear
    error message instead of a 500)."""
    sid = session.get("session_id") or session.get("id") or "unknown"
    try:
        from fpdf import FPDF  # type: ignore
    except ImportError:
        body = (
            "PDF report unavailable: the 'fpdf2' library is not "
            "installed.\n\n"
            "Install it via the per-step tool_installer:\n"
            "  tool_installer.install('fpdf2')\n\n"
            "Session: " + str(sid) + "\n"
        )
        return body.encode("utf-8"), "text/plain; charset=utf-8"
    pdf = FPDF(orientation="P", unit="mm", format="A4")
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    pdf.set_font("Courier", size=11)
    pdf.cell(0, 8, _ascii_safe(f"KFIOSA session report — {sid}"), ln=1)
    pdf.set_font("Courier", size=8)
    pdf.cell(0, 5, _ascii_safe(f"generated: {time.strftime('%Y-%m-%d %H:%M:%S')}"),
             ln=1)
    pdf.ln(2)
    # Transport + target
    pdf.set_font("Courier", size=10)
    pdf.cell(0, 6, _ascii_safe(f"transport: {session.get('transport', '-')}"), ln=1)
    pdf.cell(0, 6, _ascii_safe(f"target:    {session.get('target', '-')}"), ln=1)
    pdf.cell(0, 6, _ascii_safe(f"achieved:  {len(session.get('achieved') or [])}"),
             ln=1)
    pdf.ln(2)
    # Capability invocations
    pdf.set_font("Courier", "B", size=11)
    pdf.cell(0, 6, _ascii_safe("Capabilities invoked:"), ln=1)
    pdf.set_font("Courier", size=9)
    for c in (session.get("capabilities") or {}).values() if isinstance(
            session.get("capabilities"), dict) else (
            session.get("capabilities") or []):
        if not isinstance(c, dict):
            continue
        line = f"  - {c.get('name') or c.get('id')}"
        if c.get("achieved"):
            line += "  [achieved]"
        if c.get("risk"):
            line += f"  risk={c['risk']}"
        pdf.cell(0, 5, _ascii_safe(line[:120]), ln=1)
    # Exfil
    pdf.ln(2)
    pdf.set_font("Courier", "B", size=11)
    pdf.cell(0, 6, _ascii_safe("Exfil entries:"), ln=1)
    pdf.set_font("Courier", size=9)
    for j in session.get("exfil_jobs") or []:
        if not isinstance(j, dict):
            continue
        pdf.cell(0, 5,
                 _ascii_safe(f"  - {j.get('id') or '?'} channel={j.get('channel')} "
                 f"bytes={j.get('bytes_pending', 0)} "
                 f"status={j.get('status', 'queued')}")[:120], ln=1)
    # Persistence
    pdf.ln(2)
    pdf.set_font("Courier", "B", size=11)
    pdf.cell(0, 6, _ascii_safe("Persistence mechanisms:"), ln=1)
    pdf.set_font("Courier", size=9)
    for m in session.get("persistence_mechanisms") or []:
        if not isinstance(m, dict):
            continue
        pdf.cell(0, 5,
                 _ascii_safe(f"  - {m.get('name') or m.get('kind') or '?'} "
                 f"os={m.get('target_os', '?')} "
                 f"status={m.get('status', 'active')}")[:120], ln=1)
    # Screens
    pdf.ln(2)
    pdf.set_font("Courier", "B", size=11)
    pdf.cell(0, 6, _ascii_safe("Screenshots:"), ln=1)
    pdf.set_font("Courier", size=9)
    for s in session.get("screens") or []:
        if not isinstance(s, dict):
            continue
        pdf.cell(0, 5,
                 _ascii_safe(f"  - {s.get('name', '?')} "
                 f"size={s.get('size', 0)} ts={s.get('ts', 0)}")[:120], ln=1)
    # Footer
    pdf.ln(4)
    pdf.set_font("Courier", size=8)
    env_hash = _hash_envelopes(
        session.get("step_envelope_history") or []
    )
    pdf.cell(0, 5, _ascii_safe(f"chain-step envelope sha256: {env_hash}"), ln=1)
    out = pdf.output(dest="S")
    # fpdf2 may return bytearray or str
    if isinstance(out, str):
        out = out.encode("latin-1")
    return bytes(out), "application/pdf"


def build_full_report_bytes(sessions: List[Dict[str, Any]]
                            ) -> Tuple[bytes, str]:
    """Build a single PDF that contains every session's report.

    Used by :func:`core.post_access_tui.rat_ext.auto_pdf.export_full_report`
    after a chain finishes."""
    try:
        from fpdf import FPDF  # type: ignore
    except ImportError:
        body = (
            "PDF report unavailable: the 'fpdf2' library is not "
            "installed.\n\n"
            "Install it via the per-step tool_installer:\n"
            "  tool_installer.install('fpdf2')\n\n"
            f"Sessions: {len(sessions)}\n"
        )
        return body.encode("utf-8"), "text/plain; charset=utf-8"
    pdf = FPDF(orientation="P", unit="mm", format="A4")
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    pdf.set_font("Courier", size=14)
    pdf.cell(0, 10, _ascii_safe("KFIOSA full attack report"), ln=1)
    pdf.set_font("Courier", size=9)
    pdf.cell(0, 5, _ascii_safe(f"generated: {time.strftime('%Y-%m-%d %H:%M:%S')}"),
             ln=1)
    pdf.cell(0, 5, _ascii_safe(f"sessions: {len(sessions)}"), ln=1)
    pdf.ln(4)
    for s in sessions or []:
        if not isinstance(s, dict):
            continue
        sid = s.get("session_id") or s.get("id") or "?"
        pdf.set_font("Courier", "B", size=11)
        pdf.cell(0, 6, _ascii_safe(f"--- {sid} ---"), ln=1)
        pdf.set_font("Courier", size=9)
        for line in (
            f"  transport:  {s.get('transport', '-')}",
            f"  target:     {s.get('target', '-')}",
            f"  achieved:   {len(s.get('achieved') or [])}",
            f"  caps:       {len(s.get('capabilities') or [])}",
            f"  exfil:      {len(s.get('exfil_jobs') or [])}",
            f"  persist:    {len(s.get('persistence_mechanisms') or [])}",
        ):
            pdf.cell(0, 5, _ascii_safe(line), ln=1)
        env_hash = _hash_envelopes(
            s.get("step_envelope_history") or []
        )
        pdf.cell(0, 5, _ascii_safe(f"  envelope sha256: {env_hash}"), ln=1)
        pdf.ln(2)
    out = pdf.output(dest="S")
    if isinstance(out, str):
        out = out.encode("latin-1")
    return bytes(out), "application/pdf"


__all__ = [
    "_hash_envelopes",
    "build_session_report_bytes",
    "build_full_report_bytes",
]
