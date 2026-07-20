"""core.recon — secondary pattern scout algorithms for the recon domain.

This package holds hermetic + real-subprocess recon algorithms that are
*not* part of the original :mod:`core.modules.catalog_recon` 9-method
``CatalogRecon.RECON_PROBE_METHODS`` set. They are surfaced to the
chain planner + the orchestrator's ``recon_probe`` dispatch the same way
the catalog_recon probes are: a ``RECON_METHODS`` tuple + a
``ReconRunner`` class + a module-level ``run_probe`` entrypoint.

Honesty contract (mirrors catalog_recon / wifi_attack / ble.attack_runner):
  * Every method does REAL work — pure-Python parsing / local I/O / or a
    real subprocess (``nmap``, ``wigle`` API call) — and returns
    ``{ok: True, data: ...}`` only when the work ran.
  * On missing tool, missing key, malformed input → returns
    ``{ok: False, error: "<reason>"}`` (honest degradation). Never
    fabricates a verdict.
  * Never fabricates a CVE id, a cracked PSK, a cleartext credential, an
    NTLM hash, or a trained-ML prediction.
  * Never raises; every code path returns a step dict.
  * The orchestrator's per-step ACCEPT/CANCEL gate fires in
    :meth:`_walk_ai_step` BEFORE this dispatch runs (single-gate
    invariant); the runner does NOT re-confirm.
"""

from core.recon.runner import RECONS, ReconRunner, run_probe

# ``RECON_METHODS`` lives on the class for symmetry with
# CatalogRecon / BLEProbeRunner. We also expose it as a module
# attribute so callers can do ``from core.recon import RECON_METHODS``.
RECON_METHODS = ReconRunner.RECON_METHODS

__all__ = ["RECON_METHODS", "RECONS", "ReconRunner", "run_probe"]
