"""core.live_target — polyglot runtime-mod for AI-emitted artifacts.

This package holds the whitelist-only safe-patch catalog that lets
the AI chain planner *modify in place* KFIOSA's own emitted
artifacts (a saved .cypher, a Frida .js, a .plist snippet, a
PowerView .ps1 wrapper, an AndroidManifest.xml snippet, a Magisk
module.prop, a checkm8 shell wrapper) without ever touching the
target machine's code.

Why a separate module from :mod:`core.live_edit`:
  * ``core.live_edit`` is Python-only (``ast``-based) and edits the
    KFIOSA runner code itself. It is used to live-mutate the
    attacker's own orchestration layer.
  * ``core.live_target`` is text/byte-patch-based and edits
    KFIOSA's *emitted* artifacts (a query file, a Frida script, a
    plist snippet, a powerShell wrapper). The attacker has already
    decided to send these to the target; this module lets the AI
    re-tailor them after seeing recon results.

Honesty contract (mirrors the rest of KFIOSA):
  * Each patch is a *literal* text/byte swap with a fixed source
    string and a fixed target string. The patch operates inside
    KFIOSA's own artifact files; the runner writes to a
    caller-supplied ``out_path`` (default: same as the input
    artifact), so the operator can review before letting the
    artifact hit a target.
  * The :mod:`validator` rejects any patch that touches
    ``os.system / Runtime.exec / NSTask / posix_spawn / dlopen``
    in the *target string* or that introduces shell metas
    (``;``, ``&&``, ``|``, ``$``, backtick). The patches in the
    catalog are pre-vetted at module load; the validator is the
    runtime guard.
  * Never fabricates a CVE id, a cracked PSK, a cleartext
    credential, or a 'pwned' verdict.
  * Never raises; every code path returns a step dict.

Safety stance:
  * The per-step ACCEPT/CANCEL gate (TuiConfirmFn, default-deny
    300s) fires ONCE in :meth:`_walk_ai_step` before this
    dispatch runs. The runner does NOT re-confirm (single-gate
    invariant).
  * ``out_path`` is always the same as the input artifact
    (operator-reviewable); the runner never writes to a
    target-machine path. The operator's job is to copy the
    modified artifact to the target themselves.
"""

from core.live_target.safe_patches import (
    LIVE_TARGET_PATCHES,
    run_patch,
)

__all__ = [
    "LIVE_TARGET_PATCHES",
    "run_patch",
]
