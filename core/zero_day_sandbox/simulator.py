"""Docker target twin: synthesize + run containers from TargetEnvProfile."""
from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from .profile import TargetEnvProfile

logger = logging.getLogger(__name__)

DEFAULT_WORKDIR = Path("data/zero_day_sandbox")


class DockerTargetSimulator:
    """Build and run a Docker lab twin of a recon-profiled target.

    Isolation:
      * Containers are labeled ``kfiosa.sandbox=1`` and named
        ``kfiosa-zd-<id>``.
      * Network is bridge (default); no ``--privileged`` by default.
      * Host mounts only a per-run work dir (harness scripts).
    """

    def __init__(
        self,
        workdir: Optional[Path] = None,
        on_event: Optional[Callable[[str], None]] = None,
        timeout_s: int = 120,
    ):
        self.workdir = Path(workdir) if workdir else DEFAULT_WORKDIR
        self.workdir.mkdir(parents=True, exist_ok=True)
        self.on_event = on_event
        self.timeout_s = timeout_s

    def _emit(self, msg: str) -> None:
        logger.info(msg)
        if self.on_event:
            try:
                self.on_event(msg)
            except Exception:  # noqa: BLE001
                pass

    def docker_available(self) -> Dict[str, Any]:
        path = shutil.which("docker")
        if not path:
            return {
                "ok": False,
                "available": False,
                "error": "docker binary not found in PATH",
            }
        try:
            p = subprocess.run(
                ["docker", "info", "--format", "{{.ServerVersion}}"],
                capture_output=True, text=True, timeout=15,
            )
            if p.returncode != 0:
                return {
                    "ok": False,
                    "available": False,
                    "error": (p.stderr or p.stdout or "docker info failed")[:300],
                    "path": path,
                }
            return {
                "ok": True,
                "available": True,
                "path": path,
                "server_version": (p.stdout or "").strip(),
            }
        except Exception as e:  # noqa: BLE001
            return {
                "ok": False,
                "available": False,
                "error": str(e)[:300],
                "path": path,
            }

    def synthesize_dockerfile(self, profile: TargetEnvProfile) -> str:
        """Generate a Dockerfile approximating the target stack."""
        base = profile.docker_base_image()
        pkgs = profile.apt_packages()
        # Alpine uses apk; debian/ubuntu use apt-get
        is_alpine = "alpine" in base or profile.distro == "alpine"
        lines = [
            f"# Auto-generated KFIOSA 0-day lab twin for {profile.hostname}",
            f"# confidence={profile.confidence} source={profile.source}",
            f"FROM {base}",
            "LABEL kfiosa.sandbox=1",
            f"LABEL kfiosa.hostname={profile.hostname!r}",
        ]
        if is_alpine:
            pkg_line = " ".join(pkgs) if pkgs else "python3 py3-pip curl"
            lines += [
                "RUN apk add --no-cache " + pkg_line,
            ]
        else:
            pkg_line = " ".join(pkgs)
            lines += [
                "ENV DEBIAN_FRONTEND=noninteractive",
                "RUN apt-get update && apt-get install -y --no-install-recommends "
                + pkg_line
                + " && rm -rf /var/lib/apt/lists/*",
            ]
        # Expose recon ports (capped)
        for port in (profile.open_ports or [80])[:20]:
            lines.append(f"EXPOSE {int(port)}")
        # Simple listening stub so "port open" probes can succeed in-lab
        lines += [
            "WORKDIR /lab",
            "COPY harness/ /lab/harness/",
            "RUN mkdir -p /lab/work && chmod -R a+rX /lab",
            # Default CMD: sleep so we can docker exec probes
            'CMD ["sleep", "infinity"]',
        ]
        return "\n".join(lines) + "\n"

    def write_build_context(
        self,
        profile: TargetEnvProfile,
        run_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Materialize Dockerfile + harness dir on disk."""
        run_id = run_id or uuid.uuid4().hex[:12]
        root = self.workdir / run_id
        harness = root / "harness"
        harness.mkdir(parents=True, exist_ok=True)
        dockerfile = root / "Dockerfile"
        dockerfile.write_text(self.synthesize_dockerfile(profile), encoding="utf-8")
        # Probe harness: non-weaponized environment checks
        probe = harness / "env_probe.py"
        probe.write_text(
            """#!/usr/bin/env python3
import json, os, platform, socket, sys
out = {
  "ok": True,
  "hostname": socket.gethostname(),
  "platform": platform.platform(),
  "python": sys.version.split()[0],
  "cwd": os.getcwd(),
  "uid": os.getuid() if hasattr(os, "getuid") else None,
  "env_keys": sorted(list(os.environ.keys()))[:40],
}
print(json.dumps(out))
""",
            encoding="utf-8",
        )
        # Optional operator-supplied harness copied later
        meta = {
            "run_id": run_id,
            "root": str(root),
            "dockerfile": str(dockerfile),
            "profile": profile.to_dict(),
            "image_tag": f"kfiosa-zd-{run_id}",
            "container_name": f"kfiosa-zd-{run_id}",
        }
        (root / "meta.json").write_text(
            json.dumps(meta, indent=2, default=str), encoding="utf-8",
        )
        return meta

    def build_image(self, meta: Dict[str, Any]) -> Dict[str, Any]:
        avail = self.docker_available()
        if not avail.get("available"):
            return {
                "ok": False,
                "error": avail.get("error") or "docker unavailable",
                "stage": "build",
            }
        root = meta["root"]
        tag = meta["image_tag"]
        self._emit(f"[zd-docker] building image {tag} …")
        try:
            # First image pull can exceed 5m on cold cache; allow 15m.
            build_timeout = int(
                __import__("os").environ.get("KFIOSA_ZD_DOCKER_BUILD_TIMEOUT", "900")
            )
            p = subprocess.run(
                ["docker", "build", "-t", tag, root],
                capture_output=True, text=True,
                timeout=max(self.timeout_s, build_timeout),
            )
            if p.returncode != 0:
                return {
                    "ok": False,
                    "error": (p.stderr or p.stdout or "build failed")[-1500:],
                    "stage": "build",
                    "exit_code": p.returncode,
                }
            return {
                "ok": True,
                "image_tag": tag,
                "stage": "build",
                "log_tail": (p.stdout or "")[-500:],
            }
        except subprocess.TimeoutExpired:
            return {"ok": False, "error": "docker build timeout", "stage": "build"}
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "error": str(e)[:400], "stage": "build"}

    def start_container(
        self,
        meta: Dict[str, Any],
        profile: TargetEnvProfile,
        *,
        publish_ports: bool = True,
    ) -> Dict[str, Any]:
        avail = self.docker_available()
        if not avail.get("available"):
            return {
                "ok": False,
                "error": avail.get("error") or "docker unavailable",
                "stage": "run",
            }
        name = meta["container_name"]
        tag = meta["image_tag"]
        # Remove leftover
        subprocess.run(
            ["docker", "rm", "-f", name],
            capture_output=True, text=True, timeout=30,
        )
        cmd = [
            "docker", "run", "-d",
            "--name", name,
            "--label", "kfiosa.sandbox=1",
            "--label", f"kfiosa.run_id={meta['run_id']}",
            "--restart", "no",
            # Resource caps for notebook (12GB VRAM host; keep RAM modest)
            "--memory", os.environ.get("KFIOSA_ZD_DOCKER_MEM", "1g"),
            "--cpus", os.environ.get("KFIOSA_ZD_DOCKER_CPUS", "1.0"),
        ]
        if publish_ports:
            for port in (profile.open_ports or [])[:12]:
                # Map container port to ephemeral host port
                cmd.extend(["-p", f"{int(port)}"])
        # Mount harness for live edits during adapt loop
        harness_host = str(Path(meta["root"]) / "harness")
        cmd.extend(["-v", f"{harness_host}:/lab/harness:rw"])
        cmd.append(tag)
        self._emit(f"[zd-docker] starting container {name} …")
        try:
            p = subprocess.run(
                cmd, capture_output=True, text=True, timeout=60,
            )
            if p.returncode != 0:
                return {
                    "ok": False,
                    "error": (p.stderr or p.stdout or "run failed")[-1200:],
                    "stage": "run",
                    "exit_code": p.returncode,
                }
            cid = (p.stdout or "").strip()
            # Inspect IP
            ip = ""
            try:
                insp = subprocess.run(
                    [
                        "docker", "inspect",
                        "-f",
                        "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
                        name,
                    ],
                    capture_output=True, text=True, timeout=15,
                )
                ip = (insp.stdout or "").strip()
            except Exception:  # noqa: BLE001
                pass
            ports_map = self._published_ports(name)
            return {
                "ok": True,
                "container_id": cid,
                "container_name": name,
                "ip": ip,
                "published_ports": ports_map,
                "stage": "run",
            }
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "error": str(e)[:400], "stage": "run"}

    def _published_ports(self, name: str) -> Dict[str, str]:
        try:
            p = subprocess.run(
                ["docker", "port", name],
                capture_output=True, text=True, timeout=15,
            )
            out: Dict[str, str] = {}
            for line in (p.stdout or "").splitlines():
                # 80/tcp -> 0.0.0.0:32768
                if "->" in line:
                    left, right = line.split("->", 1)
                    out[left.strip()] = right.strip()
            return out
        except Exception:  # noqa: BLE001
            return {}

    def exec_in(
        self,
        container_name: str,
        argv: List[str],
        *,
        timeout: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Run a command inside the sandbox container."""
        if not argv:
            return {"ok": False, "error": "empty argv", "stage": "exec"}
        cmd = ["docker", "exec", container_name] + list(argv)
        try:
            p = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout or self.timeout_s,
            )
            return {
                "ok": p.returncode == 0,
                "exit_code": p.returncode,
                "stdout": (p.stdout or "")[-8000:],
                "stderr": (p.stderr or "")[-4000:],
                "stage": "exec",
                "argv": argv,
            }
        except subprocess.TimeoutExpired:
            return {
                "ok": False,
                "error": "docker exec timeout",
                "stage": "exec",
                "argv": argv,
            }
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "error": str(e)[:400], "stage": "exec"}

    def run_env_probe(self, container_name: str) -> Dict[str, Any]:
        return self.exec_in(
            container_name,
            ["python3", "/lab/harness/env_probe.py"],
            timeout=30,
        )

    def run_python_harness(
        self,
        container_name: str,
        code: str,
        *,
        filename: str = "zd_harness.py",
        meta: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Write harness into mounted dir and exec it in the container.

        This is the sim-side test of a 0-day harness against the twin —
        NOT the real target. Code should already be preflight-validated
        by the caller.
        """
        if not meta or not meta.get("root"):
            return {
                "ok": False,
                "error": "meta.root required to stage harness",
                "stage": "harness",
            }
        host_path = Path(meta["root"]) / "harness" / filename
        try:
            host_path.write_text(code or "", encoding="utf-8")
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "error": f"write harness: {e}", "stage": "harness"}
        return self.exec_in(
            container_name,
            ["python3", f"/lab/harness/{filename}"],
        )

    def stop(self, meta: Dict[str, Any], *, remove_image: bool = False) -> Dict[str, Any]:
        name = meta.get("container_name") or ""
        tag = meta.get("image_tag") or ""
        out: Dict[str, Any] = {"ok": True, "stopped": False, "removed_image": False}
        if name:
            p = subprocess.run(
                ["docker", "rm", "-f", name],
                capture_output=True, text=True, timeout=30,
            )
            out["stopped"] = p.returncode == 0
            out["stop_stderr"] = (p.stderr or "")[:300]
        if remove_image and tag:
            p2 = subprocess.run(
                ["docker", "rmi", "-f", tag],
                capture_output=True, text=True, timeout=60,
            )
            out["removed_image"] = p2.returncode == 0
        return out

    def create_and_start(self, profile: TargetEnvProfile) -> Dict[str, Any]:
        """Full path: write context → build → start → env probe."""
        meta = self.write_build_context(profile)
        built = self.build_image(meta)
        if not built.get("ok"):
            return {**built, "meta": meta, "profile": profile.to_dict()}
        started = self.start_container(meta, profile)
        if not started.get("ok"):
            return {**started, "meta": meta, "profile": profile.to_dict(), "build": built}
        # Brief settle
        time.sleep(0.4)
        probe = self.run_env_probe(started["container_name"])
        return {
            "ok": True,
            "meta": meta,
            "profile": profile.to_dict(),
            "build": built,
            "container": started,
            "probe": probe,
            "stage": "ready",
            "model": "zero-day-docker-sim",
        }
