"""core.ios — iOS target-class runner.

This package holds read-only recon + intrusive attack methods for
the iOS target class: iPhone / iPad, Find My, iCloud, Apple ID,
MDM, lockdownd, IORegistry via usbmuxd, Frida,
libimobiledevice, IPAs, plist manipulation, Mach-O runtime
patches.

The runner is organised by *target class* (iOS) rather than by
attack surface, because the attack surface is tightly bound to a
physical tethered device (libimobiledevice over USB) and to
per-app-class attack paths (Frida, IPA repack, Mach-O patches).
Methods that need a device degrade honestly when no device is
attached.

Honesty contract (mirrors the rest of KFIOSA):
  * Every method does REAL work — pure-Python parsing, real
    subprocess, or local I/O — and returns ``{ok: True, data: ...}``
    only when the work ran.
  * On missing tool, missing device, malformed input → returns
    ``{ok: False, error: "<reason>"}``. Never fabricates a verdict.
  * Never fabricates a CVE id, a cleartext credential, an IPA
    repack, a Frida hook output, a plist key, a Mach-O patch, or
    a 'pwned' verdict.
  * Never raises; every code path returns a step dict.
  * The orchestrator's per-step ACCEPT/CANCEL gate fires in
    :meth:`_walk_ai_step` BEFORE this dispatch runs (single-gate
    invariant); the runner does NOT re-confirm.
  * iOS-specific: ``checkm8`` and ``limera1n`` DFU operations are
    DESTRUCTIVE and require the device to already be in DFU. The
    runner refuses to send the USB reset itself. libimobiledevice
    backup/restore is WRITE; the runner never auto-deletes
    backups (only enumerates).
  * Never inline harvested credential values into shell argv
    (never-inline ground rule).
"""

from core.ios.runner import (
    IOS_ATTACKS,
    IOS_METHODS,
    IOSRunner,
    run_attack,
)

__all__ = [
    "IOS_ATTACKS",
    "IOS_METHODS",
    "IOSRunner",
    "run_attack",
]
