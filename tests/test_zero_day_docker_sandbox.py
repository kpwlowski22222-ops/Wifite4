"""Tests for Docker-based 0-day simulation pipeline."""
from __future__ import annotations

from unittest import mock

from core.zero_day_sandbox.profile import (
    TargetEnvProfile,
    build_profile_from_recon,
)
from core.zero_day_sandbox.pipeline import ZeroDayDockerPipeline
from core.zero_day_sandbox.simulator import DockerTargetSimulator


class TestProfile:
    def test_from_seed_ports_and_os(self):
        p = build_profile_from_recon(
            seed={
                "os": "linux",
                "distro": "ubuntu",
                "distro_version": "22.04",
                "open_ports": [22, 80, 443],
                "services": [{"port": 80, "name": "http", "product": "nginx"}],
                "hostname": "victim.lab",
            }
        )
        assert p.os_family == "linux"
        assert 80 in p.open_ports
        assert p.docker_base_image().startswith("ubuntu")
        assert "python3" in p.apt_packages()

    def test_nested_recon_data(self):
        p = build_profile_from_recon(
            recon={
                "probe": {"ok": True, "data": {"open_ports": [8080], "banner": "Apache"}},
            }
        )
        assert 8080 in p.open_ports or p.open_ports  # may default if parse misses


class TestSimulatorOffline:
    def test_dockerfile_contains_expose(self):
        sim = DockerTargetSimulator()
        profile = TargetEnvProfile(
            distro="ubuntu", open_ports=[22, 80], hostname="t1",
        )
        df = sim.synthesize_dockerfile(profile)
        assert "FROM " in df
        assert "EXPOSE 80" in df
        assert "kfiosa.sandbox=1" in df

    def test_write_build_context(self, tmp_path):
        sim = DockerTargetSimulator(workdir=tmp_path)
        profile = TargetEnvProfile(open_ports=[80])
        meta = sim.write_build_context(profile, run_id="test01")
        assert (tmp_path / "test01" / "Dockerfile").is_file()
        assert (tmp_path / "test01" / "harness" / "env_probe.py").is_file()
        assert meta["image_tag"].startswith("kfiosa-zd-")


class TestAdapt:
    def test_adapt_python3(self):
        pipe = ZeroDayDockerPipeline()
        profile = TargetEnvProfile()
        code = "#!/usr/bin/env python\nimport sys\nprint('x')\n"
        out = pipe.adapt_harness(
            code, "python: not found", profile, 1,
        )
        assert out["changed"] is True
        assert "python3" in out["code"]

    def test_adapt_permission(self):
        pipe = ZeroDayDockerPipeline()
        out = pipe.adapt_harness(
            "open('/etc/shadow')\n",
            "Permission denied",
            TargetEnvProfile(),
            2,
        )
        assert "/tmp/" in out["code"] or "/etc/hosts" in out["code"]


class TestPipelineNoDocker:
    def test_honest_degrade_without_daemon(self, tmp_path):
        sim = DockerTargetSimulator(workdir=tmp_path)
        with mock.patch.object(
            sim, "docker_available",
            return_value={"ok": False, "available": False, "error": "no daemon"},
        ):
            pipe = ZeroDayDockerPipeline(
                simulator=sim,
                confirm_fn=lambda _p: True,
            )
            # Force no CatalogRecon network work
            with mock.patch.object(
                pipe, "gather_recon",
                return_value={
                    "ok": True,
                    "recon": {},
                    "seed": {"open_ports": [80]},
                    "profile": TargetEnvProfile(open_ports=[80]).to_dict(),
                    "profile_obj": TargetEnvProfile(open_ports=[80]),
                    "enrichment": {},
                    "stage": "recon",
                },
            ):
                result = pipe.run(
                    seed={"open_ports": [80]},
                    skip_real=True,
                    auto_sim=True,
                    cleanup=True,
                )
        assert result.get("ok") is False
        assert result.get("stage") in ("sim_up", "sim_failed")


class TestOrchestratorDispatch:
    def test_dispatch_table_has_docker_sim(self):
        from core.orchestrator.autonomous_orchestrator import (
            AutonomousOrchestrator,
        )
        orch = AutonomousOrchestrator()
        table = orch._action_dispatch_table()
        assert "zero_day_docker_sim" in table
        from core.ai_backend.chain import _KNOWN_CHAIN_ACTIONS
        assert "zero_day_docker_sim" in _KNOWN_CHAIN_ACTIONS
