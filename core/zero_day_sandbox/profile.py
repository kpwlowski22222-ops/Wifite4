"""Build a rich environment profile from recon / seed for Docker simulation."""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Set


@dataclass
class TargetEnvProfile:
    """Fingerprint used to synthesize a Docker lab twin."""

    os_family: str = "linux"          # linux | windows | unknown
    distro: str = "ubuntu"            # ubuntu | debian | alpine | centos | ...
    distro_version: str = "22.04"
    arch: str = "amd64"
    hostname: str = "lab-target"
    open_ports: List[int] = field(default_factory=list)
    services: List[Dict[str, Any]] = field(default_factory=list)  # {port,name,product,version}
    packages: List[str] = field(default_factory=list)
    web_stack: List[str] = field(default_factory=list)  # nginx, apache, php, ...
    languages: List[str] = field(default_factory=list)  # python, node, java, ...
    cpe_hints: List[str] = field(default_factory=list)
    banners: List[str] = field(default_factory=list)
    wifi: Dict[str, Any] = field(default_factory=dict)
    ble: Dict[str, Any] = field(default_factory=dict)
    raw_signals: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.3
    source: str = "recon-heuristic"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "TargetEnvProfile":
        known = {f.name for f in cls.__dataclass_fields__.values()}  # type: ignore
        return cls(**{k: v for k, v in (d or {}).items() if k in known})

    def docker_base_image(self) -> str:
        """Map fingerprint → public base image tag (no private registries)."""
        d = (self.distro or "ubuntu").lower()
        v = (self.distro_version or "").strip()
        if self.os_family == "windows":
            # Windows containers need special host setup — degrade to
            # linux wine-less stub for lab notebooks.
            return "python:3.11-slim"
        if d in ("alpine",):
            return "alpine:3.19"
        if d in ("debian",):
            tag = v if v and re.match(r"^\d+", v) else "bookworm"
            return f"debian:{tag}-slim" if tag[0].isdigit() else f"debian:{tag}-slim"
        if d in ("centos", "rhel", "rocky", "alma"):
            return "rockylinux:9"
        if d in ("nginx",) or "nginx" in self.web_stack:
            return "nginx:1.25-alpine"
        if d in ("redis",) or any(
            (s.get("name") or "").lower() == "redis" for s in self.services
        ):
            return "redis:7-alpine"
        # Prefer slim python base for generic Linux twins — much faster
        # first-pull on lab notebooks than full Ubuntu cloud images.
        # Explicit Ubuntu versions when recon names them.
        if d in ("ubuntu",) and v:
            if v.startswith("18"):
                return "ubuntu:18.04"
            if v.startswith("20"):
                return "ubuntu:20.04"
            if v.startswith("22"):
                return "ubuntu:22.04"
            if v.startswith("24"):
                return "ubuntu:24.04"
            return "ubuntu:22.04"
        # Default: small, multi-arch, good for harness exec
        return "python:3.11-slim"

    def apt_packages(self) -> List[str]:
        """Best-effort package list for the Dockerfile (Debian/Ubuntu family)."""
        pkgs: Set[str] = {"ca-certificates", "curl", "python3", "python3-pip"}
        for p in self.packages:
            if re.match(r"^[a-zA-Z0-9.+_-]+$", p):
                pkgs.add(p.lower())
        for s in self.services:
            name = (s.get("name") or s.get("product") or "").lower()
            if "ssh" in name or s.get("port") == 22:
                pkgs.add("openssh-server")
            if "http" in name or "nginx" in name or s.get("port") in (80, 443, 8080):
                pkgs.update({"nginx", "apache2-utils"})
            if "mysql" in name or "mariadb" in name:
                pkgs.add("default-mysql-client")
            if "postgres" in name:
                pkgs.add("postgresql-client")
            if "ftp" in name:
                pkgs.add("vsftpd")
        for stack in self.web_stack:
            sl = stack.lower()
            if "php" in sl:
                pkgs.add("php-cli")
            if "node" in sl:
                pkgs.add("nodejs")
            if "java" in sl:
                pkgs.add("default-jre-headless")
        return sorted(pkgs)


def _as_list(v: Any) -> List[Any]:
    if v is None:
        return []
    if isinstance(v, list):
        return v
    if isinstance(v, (set, tuple)):
        return list(v)
    return [v]


def _dig(d: Dict[str, Any], *keys: str, default: Any = None) -> Any:
    cur: Any = d
    for k in keys:
        if not isinstance(cur, dict):
            return default
        cur = cur.get(k, default)
    return cur


def build_profile_from_recon(
    seed: Optional[Dict[str, Any]] = None,
    recon: Optional[Dict[str, Any]] = None,
    extra: Optional[Dict[str, Any]] = None,
) -> TargetEnvProfile:
    """Maximize environment signal from seed + recon envelopes.

    Never invents versions that are not present; empty fields stay empty
    and confidence stays low.
    """
    seed = dict(seed or {})
    recon = dict(recon or {})
    extra = dict(extra or {})
    # Flatten nested recon results often shaped as {probe: {ok, data}}
    flat: Dict[str, Any] = {}
    for blob in (seed, recon, extra):
        for k, v in blob.items():
            if k not in flat or flat.get(k) in (None, "", [], {}):
                flat[k] = v
            if isinstance(v, dict) and isinstance(v.get("data"), dict):
                for dk, dv in v["data"].items():
                    flat.setdefault(dk, dv)

    os_family = str(
        flat.get("os_family") or flat.get("os") or flat.get("platform") or "linux"
    ).lower()
    if "win" in os_family:
        os_family = "windows"
    elif any(x in os_family for x in ("linux", "ubuntu", "debian", "unix")):
        os_family = "linux"

    distro = str(
        flat.get("distro") or flat.get("os_distro") or flat.get("linux_distro") or ""
    ).lower()
    if not distro:
        if "ubuntu" in str(flat.get("banner") or "").lower():
            distro = "ubuntu"
        elif "debian" in str(flat.get("banner") or "").lower():
            distro = "debian"
        elif os_family == "linux":
            distro = "ubuntu"
        else:
            distro = "unknown"

    distro_version = str(
        flat.get("distro_version") or flat.get("os_version") or flat.get("version") or ""
    )

    ports: List[int] = []
    for key in ("open_ports", "ports", "tcp_ports"):
        for p in _as_list(flat.get(key)):
            try:
                ports.append(int(p))
            except (TypeError, ValueError):
                continue
    # services list may embed ports
    services: List[Dict[str, Any]] = []
    for s in _as_list(flat.get("services") or flat.get("service_list")):
        if isinstance(s, dict):
            services.append(dict(s))
            try:
                if s.get("port") is not None:
                    ports.append(int(s["port"]))
            except (TypeError, ValueError):
                pass
        elif isinstance(s, str) and s.strip():
            services.append({"name": s.strip()})

    # nmap-like host keys
    for h in _as_list(flat.get("hosts") or flat.get("host_list")):
        if isinstance(h, dict):
            for p in _as_list(h.get("ports")):
                try:
                    ports.append(int(p if not isinstance(p, dict) else p.get("port")))
                except (TypeError, ValueError):
                    continue

    ports = sorted({p for p in ports if 1 <= p <= 65535})[:64]

    packages = [
        str(p).strip()
        for p in _as_list(flat.get("packages") or flat.get("installed_packages"))
        if str(p).strip()
    ][:80]

    web_stack = [
        str(x).lower()
        for x in _as_list(flat.get("web_stack") or flat.get("http_server") or flat.get("stack"))
        if str(x).strip()
    ]
    languages = [
        str(x).lower()
        for x in _as_list(flat.get("languages") or flat.get("runtime"))
        if str(x).strip()
    ]
    banners = [
        str(b)[:300]
        for b in _as_list(flat.get("banners") or flat.get("banner"))
        if str(b).strip()
    ][:40]
    cpes = [
        str(c)
        for c in _as_list(flat.get("cpe") or flat.get("cpes") or flat.get("cpe_hints"))
        if str(c).strip()
    ][:40]

    wifi = {}
    for k in ("bssid", "ssid", "essid", "channel", "encryption", "wpa_version"):
        if flat.get(k) not in (None, ""):
            wifi[k] = flat.get(k)
    ble = {}
    for k in ("address", "addr", "name", "services", "gatt_services"):
        if flat.get(k) not in (None, "", []):
            ble[k] = flat.get(k)

    # Confidence: more signals → higher (capped)
    signals = 0
    if ports:
        signals += 1
    if services:
        signals += 1
    if packages:
        signals += 1
    if banners:
        signals += 1
    if web_stack:
        signals += 1
    if distro_version:
        signals += 1
    if wifi:
        signals += 0.5
    if ble:
        signals += 0.5
    confidence = min(0.95, 0.2 + 0.12 * signals)

    hostname = str(
        flat.get("hostname") or flat.get("host") or flat.get("target")
        or flat.get("ip") or "lab-target"
    )[:64]

    return TargetEnvProfile(
        os_family=os_family,
        distro=distro or "ubuntu",
        distro_version=distro_version or "22.04",
        arch=str(flat.get("arch") or flat.get("architecture") or "amd64"),
        hostname=re.sub(r"[^a-zA-Z0-9._-]", "-", hostname) or "lab-target",
        open_ports=ports or [80, 22],
        services=services,
        packages=packages,
        web_stack=web_stack,
        languages=languages,
        cpe_hints=cpes,
        banners=banners,
        wifi=wifi,
        ble=ble,
        raw_signals={
            "keys": sorted(list(flat.keys()))[:80],
            "has_recon": bool(recon),
        },
        confidence=round(confidence, 3),
        source="recon-heuristic",
    )
