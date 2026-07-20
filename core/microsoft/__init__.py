"""core.microsoft — Microsoft / Windows / AD / M365 target-class runner.

This package holds read-only recon + intrusive attack methods for
Microsoft attack surfaces: Windows / Active Directory / AD CS /
M365 / Azure AD. The runner is organised by *target class* (not by
attack surface as the legacy ``post_exploit_ext`` is) because the
Microsoft vertical is structurally a domain that spans LAN-side
(SMB / RPC / WinRM), AD-side (LDAP / Kerberos), and cloud-side
(M365 Graph / Azure AD) attack surfaces that must be composed
inside a single chain.

Honesty contract (mirrors the rest of KFIOSA):
  * Every method does REAL work — pure-Python parsing / local I/O
    or a real subprocess — and returns ``{ok: True, data: ...}``
    only when the work ran.
  * On missing tool, missing key, malformed input → returns
    ``{ok: False, error: "<reason>"}`` (honest degradation). Never
    fabricates a verdict.
  * Never fabricates a CVE id, a cracked PSK, a cleartext
    credential, an NTLM hash, a DCSync result, or a Kerberos
    ticket.
  * Never raises; every code path returns a step dict.
  * The orchestrator's per-step ACCEPT/CANCEL gate fires in
    :meth:`_walk_ai_step` BEFORE this dispatch runs (single-gate
    invariant); the runner does NOT re-confirm.
  * Microsoft-specific: methods that would touch BitLocker recovery
    keys, Windows Hello, AD CS CA private keys, or M365 Graph
    tokens are ``destructive`` and degrade to ``intrusive`` (dry-
    run) when run without an explicit ``live`` flag.
  * Never inline harvested credential values into shell argv
    (never-inline ground rule).
"""

from core.microsoft.runner import (
    MICROSOFT_ATTACKS,
    MICROSOFT_METHODS,
    MicrosoftRunner,
    run_attack,
)

__all__ = [
    "MICROSOFT_ATTACKS",
    "MICROSOFT_METHODS",
    "MicrosoftRunner",
    "run_attack",
]
