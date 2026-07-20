"""core.android — Android target-class runner.

This package holds read-only recon + intrusive attack methods for
the Android target class: AOSP / Samsung OneUI / Pixel / Xiaomi
MIUI-HyperOS, ADB over USB, Frida dynamic instrumentation, Magisk
root, content providers, intents, accessibility abuse, OEM-specific
attack surfaces.

The runner is organised by *target class* (Android) rather than by
attack surface, because the attack surface is tightly bound to a
physical tethered device (ADB over USB) and to per-app-class attack
paths (Frida, IPA-repack-equivalent for APKs, Magisk boot image
patch). Methods that need a device degrade honestly when no device
is attached.

Honesty contract (mirrors the rest of KFIOSA):
  * Every method does REAL work — pure-Python parsing, real
    subprocess, or local I/O — and returns ``{ok: True, data: ...}``
    only when the work ran.
  * On missing tool, missing device, malformed input → returns
    ``{ok: False, error: "<reason>"}``. Never fabricates a verdict.
  * Never fabricates a CVE id, a cracked PSK, a cleartext
    credential, a Frida hook output, an APK repackage, or a 'pwned'
    verdict.
  * Never raises; every code path returns a step dict.
  * The orchestrator's per-step ACCEPT/CANCEL gate fires in
    :meth:`_walk_ai_step` BEFORE this dispatch runs (single-gate
    invariant); the runner does NOT re-confirm.
  * Android-specific: ``fastboot oem unlock`` and ``magisk boot
    image patch`` are DESTRUCTIVE and live in the intrusive surface
    with explicit device_state + adb_keys guards. Frida-server
    bind is INTRUSIVE but never auto-starts the daemon.
  * Never inline harvested credential values into shell argv
    (never-inline ground rule).
"""

from core.android.runner import (
    ANDROID_ATTACKS,
    ANDROID_METHODS,
    AndroidRunner,
    run_attack,
)

__all__ = [
    "ANDROID_ATTACKS",
    "ANDROID_METHODS",
    "AndroidRunner",
    "run_attack",
]
