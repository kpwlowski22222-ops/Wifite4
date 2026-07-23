"""core.zero_day_sandbox — Docker-simulated 0-day lab from live recon.

Pipeline (authorized lab only):

  1. **Recon gather** — maximize environment fingerprint from seed/recon
  2. **Docker sim** — synthesize a container approximating the target
  3. **Test 0-day harness** against the container (not the real host)
  4. **If sim success** → gated attempt on the *real* target
  5. **If errors** → adapt harness / env flags and re-sim until success
     or budget exhausted

Hard rules:
  * Real-target steps stay behind ACCEPT/CANCEL (default-deny).
  * Docker is local-only; no silent ``apt install`` on the host.
  * Never fabricates CVE ids, cracked secrets, or fake sim success.
  * Honest-degrade when Docker daemon is missing/unavailable.
  * Exploit bodies still pass ZeroDayExploitPreflight before any run.
"""
from __future__ import annotations

from .pipeline import ZeroDayDockerPipeline, run_zero_day_docker_pipeline
from .profile import TargetEnvProfile, build_profile_from_recon
from .simulator import DockerTargetSimulator


class docker_sim:
    """Back-compat module-style facade used by engagement_engine 0day-bg.

    Prefer :func:`run_zero_day_docker_pipeline` for new call sites.
    """

    @staticmethod
    def run_sim(seed=None, skip_real=True, **kwargs):
        return run_zero_day_docker_pipeline(
            seed=seed if isinstance(seed, dict) else {},
            skip_real=bool(skip_real),
            **kwargs,
        )


__all__ = [
    "TargetEnvProfile",
    "build_profile_from_recon",
    "DockerTargetSimulator",
    "ZeroDayDockerPipeline",
    "run_zero_day_docker_pipeline",
    "docker_sim",
]
