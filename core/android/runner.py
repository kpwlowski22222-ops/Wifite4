"""AndroidRunner — Android target-class attack surface.

Phase 2.0.A0+A1 — scaffolding + 8 read-only methods. The intrusive
surface (frida_trace_attach_method,
apktool_repack_with_frida_gadget, adb_logcat_pull,
drozer_content_provider_enum) is layered on in Phase 2.0.A2.

The eight read methods (all risk=READ, hermetic where possible):

  1. adb_devices_list
       — list adb-attached devices. Real subprocess; degrades on
         missing adb. Hermetic with mocked run.
  2. adb_packages_dump
       — dump installed packages via ``adb shell pm list packages``.
         Real subprocess. Degrades on missing adb / no device.
  3. adb_apps_running
       — ``adb shell ps -A`` parse. Pure parse of the AI-supplied
         ps output.
  4. frida_processes_enumerate
       — ``frida-ps -Uai`` (USB, all, app-info) parse. Pure parse
         of the AI-supplied output.
  5. apktool_decode_manifest
       — parse an apktool-decoded AndroidManifest.xml. Pure XML
         parse; no subprocess.
  6. jadx_dex_to_java
       — parse jadx ``-d`` output structure (folder layout). Pure.
  7. drozer_modules_discovery
       — parse ``drozer module list`` output. Pure.
  8. nmap_android_adb_discovery
       — nmap NSE for android-adb (port 5555). Real subprocess;
         degrades on missing nmap. Hermetic with mocked run.

Honesty contract (mirrors the rest of KFIOSA):
  * Real work or honest degradation. Never fake results.
  * Never fabricates CVE ids, cracked PSKs, cleartext creds,
    Frida hook output, or 'pwned' verdicts.
  * Read-only by default. The 4 intrusive methods land in
    Phase 2.0.A2 and are gated by the same per-step ACCEPT/CANCEL
    gate as every other step.
  * Never raises; every code path returns a step dict.
"""
from __future__ import annotations

import json
import logging
import os
import re
import shlex
import shutil
import subprocess
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Step envelope (identical to other runners)
# ---------------------------------------------------------------------------
def _step(name: str) -> Dict[str, Any]:
    return {"name": name, "ok": False, "data": None,
            "error": "", "duration_s": 0.0, "started": time.time()}


def _finalize(step: Dict[str, Any], started: float, *,
              ok: bool, data: Optional[Any] = None,
              error: str = "") -> Dict[str, Any]:
    step["ok"] = bool(ok)
    step["data"] = data
    step["error"] = error
    step["duration_s"] = round(time.time() - started, 4)
    return step


def _which(tool: str) -> bool:
    return shutil.which(tool) is not None


# ---------------------------------------------------------------------------
# Method 1: adb_devices_list
# ---------------------------------------------------------------------------
_ADB_DEVICE_RE = re.compile(
    r"^([\w\.\-]+)\s+(device|unauthorized|offline|recovery)\s*(.*)$"
)


def _parse_adb_devices_output(text: str) -> List[Dict[str, Any]]:
    """Parse ``adb devices -l`` output. Pure.

    Lines after the header look like::

        emulator-5554   device  product:sdk_gphone64_x86_64 model:Pixel_7 ...
        1234abcd        unauthorized ...
    """
    out: List[Dict[str, Any]] = []
    seen_header = False
    for line in text.splitlines():
        line = line.rstrip()
        if not line:
            continue
        if not seen_header:
            if line.strip().startswith("List of devices"):
                seen_header = True
            continue
        m = _ADB_DEVICE_RE.match(line.strip())
        if not m:
            continue
        ser = m.group(1).strip()
        state = m.group(2).strip()
        attrs = m.group(3).strip()
        attr_dict: Dict[str, str] = {}
        for kv in attrs.split():
            if ":" in kv:
                k, v = kv.split(":", 1)
                attr_dict[k] = v
        out.append({
            "serial": ser,
            "state": state,
            "product": attr_dict.get("product") or "",
            "model": attr_dict.get("model") or "",
            "device": attr_dict.get("device") or "",
            "transport_id": attr_dict.get("transport_id") or "",
        })
    return out


def _adb_devices_list_impl(args: Dict[str, Any]) -> Dict[str, Any]:
    """List adb-attached devices. Degrades on missing adb. Hermetic
    with a mocked run (run=CompletedProcess-like)."""
    run = args.get("run")
    if run is None:
        if not _which("adb"):
            return {
                "ok": False,
                "error": "adb not installed; install android-tools-adb",
                "data": None,
                "name": "adb_devices_list",
                "duration_s": 0.0,
            }
        try:
            proc = subprocess.run(["adb", "devices", "-l"],
                                  capture_output=True, text=True,
                                  timeout=int(args.get("timeout_s", 10)))
        except subprocess.TimeoutExpired:
            return {
                "ok": False, "error": "adb devices timeout",
                "data": None,
                "name": "adb_devices_list",
                "duration_s": int(args.get("timeout_s", 10))}
        text = proc.stdout or ""
    else:
        text = run.stdout or ""
    devices = _parse_adb_devices_output(text)
    return {
        "ok": True,
        "data": {
            "device_count": len(devices),
            "ready": [d for d in devices if d["state"] == "device"],
            "unauthorized": [d for d in devices
                             if d["state"] == "unauthorized"],
            "all": devices,
        },
        "name": "adb_devices_list",
        "error": "",
        "duration_s": 0.0,
    }


# ---------------------------------------------------------------------------
# Method 2: adb_packages_dump
# ---------------------------------------------------------------------------
_PKG_LINE_RE = re.compile(r"^package:(.+)$")


def _parse_pm_list_packages(text: str) -> List[str]:
    """Parse ``adb shell pm list packages -f -3`` output. Pure."""
    out: List[str] = []
    for line in text.splitlines():
        line = line.strip()
        m = _PKG_LINE_RE.match(line)
        if m:
            out.append(m.group(1).strip())
    return out


def _classify_package(p: str) -> str:
    """Coarse class for a package path / label. Pure."""
    p_lower = p.lower()
    if p_lower.startswith("com.android."):
        return "system"
    if "google" in p_lower or "gms" in p_lower or "gtservice" in p_lower:
        return "google"
    if p_lower.endswith(".debug") or "test" in p_lower:
        return "test_or_debug"
    return "third_party"


def _adb_packages_dump_impl(args: Dict[str, Any]) -> Dict[str, Any]:
    """Dump installed packages. The AI provides the
    ``pm list packages`` output in args.pm_output. Pure parse; no
    adb call from this runner."""
    text = args.get("pm_output") or args.get("adb_output") or ""
    if not text or not isinstance(text, str):
        return {
            "ok": False,
            "error": ("pm_output (string) required; the runner never "
                      "opens adb; pass the AI-supplied pm list output"),
            "data": None,
            "name": "adb_packages_dump",
            "duration_s": 0.0,
        }
    pkgs = _parse_pm_list_packages(text)
    by_class: Dict[str, int] = {}
    for p in pkgs:
        c = _classify_package(p)
        by_class[c] = by_class.get(c, 0) + 1
    return {
        "ok": True,
        "data": {
            "package_count": len(pkgs),
            "by_class": by_class,
            "third_party_sample": [p for p in pkgs
                                   if _classify_package(p) == "third_party"][:25],
        },
        "name": "adb_packages_dump",
        "error": "",
        "duration_s": 0.0,
    }


# ---------------------------------------------------------------------------
# Method 3: adb_apps_running
# ---------------------------------------------------------------------------
_PS_USERPID_RE = re.compile(r"^(\w+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+"
                            r"(\S+)\s+(.+)$")


def _parse_ps_output(text: str) -> List[Dict[str, Any]]:
    """Parse ``adb shell ps -A`` output. Pure.

    Skips the header. Returns ``[{user, pid, ppid, vsz, rss, wchan, name}]``."""
    out: List[Dict[str, Any]] = []
    saw_header = False
    for line in text.splitlines():
        line = line.rstrip()
        if not line:
            continue
        if not saw_header:
            if "PID" in line and "USER" in line:
                saw_header = True
            continue
        m = _PS_USERPID_RE.match(line)
        if m:
            try:
                out.append({
                    "user": m.group(1),
                    "pid": int(m.group(2)),
                    "ppid": int(m.group(3)),
                    "vsz": int(m.group(4)),
                    "rss": int(m.group(5)),
                    "wchan": m.group(6),
                    "name": m.group(7).strip(),
                })
            except ValueError:
                continue
    return out


def _adb_apps_running_impl(args: Dict[str, Any]) -> Dict[str, Any]:
    """Parse ``adb shell ps -A`` output. Pure parse."""
    text = args.get("ps_output") or args.get("adb_output") or ""
    if not text or not isinstance(text, str):
        return {
            "ok": False,
            "error": "ps_output (string) required",
            "data": None,
            "name": "adb_apps_running",
            "duration_s": 0.0,
        }
    procs = _parse_ps_output(text)
    # Heuristic: foreground/visible app is typically a ``.main`` /
    # ``MainActivity`` process owned by u0_a* and in the top RSS
    # bin. We surface the top 10 by RSS.
    top = sorted(procs, key=lambda p: p["rss"], reverse=True)[:10]
    return {
        "ok": True,
        "data": {
            "process_count": len(procs),
            "top_by_rss": top,
            "users": {p["user"] for p in procs},
        },
        "name": "adb_apps_running",
        "error": "",
        "duration_s": 0.0,
    }


# ---------------------------------------------------------------------------
# Method 4: frida_processes_enumerate
# ---------------------------------------------------------------------------
def _parse_frida_ps_output(text: str) -> List[Dict[str, Any]]:
    """Parse ``frida-ps -Uai`` output. Pure.

    Lines look like (columns: pid, name, identifier)::
        1234  com.example.app   com.example.app
    """
    out: List[Dict[str, Any]] = []
    saw_header = False
    for line in text.splitlines():
        line = line.rstrip()
        if not line:
            continue
        if not saw_header:
            if "PID" in line and "Name" in line:
                saw_header = True
            continue
        parts = line.split(None, 2)
        if len(parts) < 2:
            continue
        try:
            pid = int(parts[0])
        except ValueError:
            continue
        name = parts[1]
        ident = parts[2] if len(parts) >= 3 else ""
        out.append({"pid": pid, "name": name, "identifier": ident})
    return out


def _frida_processes_enumerate_impl(args: Dict[str, Any]) -> Dict[str, Any]:
    """Parse ``frida-ps -Uai`` output. Pure parse."""
    text = args.get("frida_ps_output") or args.get("stdout") or ""
    if not text or not isinstance(text, str):
        return {
            "ok": False,
            "error": "frida_ps_output (string) required",
            "data": None,
            "name": "frida_processes_enumerate",
            "duration_s": 0.0,
        }
    procs = _parse_frida_ps_output(text)
    return {
        "ok": True,
        "data": {
            "process_count": len(procs),
            "processes": procs[:50],
        },
        "name": "frida_processes_enumerate",
        "error": "",
        "duration_s": 0.0,
    }


# ---------------------------------------------------------------------------
# Method 5: apktool_decode_manifest
# ---------------------------------------------------------------------------
_NS_ANDROID = "{http://schemas.android.com/apk/res-auto}"


def _parse_axml(xml_text: str) -> Dict[str, Any]:
    """Parse a (possibly apktool-reserialized) AndroidManifest.xml
    into a structured dict. Pure. Handles missing
    ``xmlns:android`` by trying to find the package attribute
    on the root element directly."""
    out: Dict[str, Any] = {
        "package": "", "version_code": None, "version_name": None,
        "min_sdk": None, "target_sdk": None,
        "permissions": [], "activities": [], "services": [],
        "receivers": [], "providers": [],
        "debuggable": False, "allow_backup": None,
        "uses_cleartext": False,
    }
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as e:
        return {"ok": False, "error": f"xml parse: {e}"}
    out["package"] = root.get("package") or root.get("packageName") or ""
    out["version_code"] = (root.get("versionCode")
                            or root.get(_NS_ANDROID + "versionCode"))
    out["version_name"] = (root.get("versionName")
                            or root.get(_NS_ANDROID + "versionName"))
    out["min_sdk"] = (root.get("minSdkVersion")
                       or root.get(_NS_ANDROID + "minSdkVersion"))
    out["target_sdk"] = (root.get("targetSdkVersion")
                          or root.get(_NS_ANDROID + "targetSdkVersion"))
    for el in root.iter():
        tag = el.tag.split("}", 1)[-1] if "}" in el.tag else el.tag
        if tag == "uses-permission":
            name = (el.get("name")
                     or el.get(_NS_ANDROID + "name") or "")
            if name and name not in out["permissions"]:
                out["permissions"].append(name)
        elif tag == "application":
            ab = (el.get("allowBackup")
                  or el.get(_NS_ANDROID + "allowBackup"))
            if ab is not None:
                out["allow_backup"] = (ab.lower() == "true")
            dbg = (el.get("debuggable")
                   or el.get(_NS_ANDROID + "debuggable"))
            if dbg is not None and dbg.lower() == "true":
                out["debuggable"] = True
            uc = (el.get("usesCleartextTraffic")
                  or el.get(_NS_ANDROID + "usesCleartextTraffic"))
            if uc is not None and uc.lower() == "true":
                out["uses_cleartext"] = True
        elif tag == "activity":
            out["activities"].append(
                el.get("name")
                or el.get(_NS_ANDROID + "name") or "")
        elif tag == "service":
            out["services"].append(
                el.get("name")
                or el.get(_NS_ANDROID + "name") or "")
        elif tag == "receiver":
            out["receivers"].append(
                el.get("name")
                or el.get(_NS_ANDROID + "name") or "")
        elif tag == "provider":
            out["providers"].append({
                "name": (el.get("name")
                          or el.get(_NS_ANDROID + "name") or ""),
                "authorities": (el.get("authorities")
                                 or el.get(_NS_ANDROID + "authorities") or ""),
                "exported": (el.get("exported")
                              or el.get(_NS_ANDROID + "exported") or ""),
            })
    return out


def _apktool_decode_manifest_impl(args: Dict[str, Any]) -> Dict[str, Any]:
    """Parse an apktool-decoded AndroidManifest.xml. Pure."""
    text = args.get("androidmanifest_xml") or args.get("xml") or ""
    if not text or not isinstance(text, str):
        return {
            "ok": False,
            "error": "androidmanifest_xml (string) required",
            "data": None,
            "name": "apktool_decode_manifest",
            "duration_s": 0.0,
        }
    parsed = _parse_axml(text)
    if isinstance(parsed, dict) and parsed.get("ok") is False:
        return {
            "ok": False, "error": parsed.get("error") or "xml parse",
            "data": None,
            "name": "apktool_decode_manifest",
            "duration_s": 0.0,
        }
    return {
        "ok": True,
        "data": parsed,
        "name": "apktool_decode_manifest",
        "error": "",
        "duration_s": 0.0,
    }


# ---------------------------------------------------------------------------
# Method 6: jadx_dex_to_java
# ---------------------------------------------------------------------------
def _parse_jadx_dir_listing(dirs: List[str]) -> Dict[str, Any]:
    """Given a jadx ``-d`` output directory listing, summarize the
    sources/smali structure. Pure."""
    java_count = 0
    smali_count = 0
    package_roots: set = set()
    res_count = 0
    for d in dirs:
        if d.endswith(".java") or d.endswith("/"):
            java_count += 1
        if d.endswith(".smali") or "/smali" in d:
            smali_count += 1
        if d.startswith("sources/") and "/" in d[len("sources/"):]:
            pkg = d[len("sources/"):].split("/", 1)[0]
            package_roots.add(pkg)
        if d.startswith("res/") and "/" in d[len("res/"):]:
            res_count += 1
    return {
        "java_count_estimate": java_count,
        "smali_count_estimate": smali_count,
        "resource_count_estimate": res_count,
        "package_roots": sorted(package_roots),
    }


def _jadx_dex_to_java_impl(args: Dict[str, Any]) -> Dict[str, Any]:
    """Summarize a jadx ``-d`` output directory listing. Pure."""
    dirs = args.get("dirs") or args.get("listing")
    if isinstance(dirs, str):
        dirs = [ln.strip() for ln in dirs.splitlines() if ln.strip()]
    if not isinstance(dirs, list) or not dirs:
        return {
            "ok": False,
            "error": "dirs (list of relative paths) required",
            "data": None,
            "name": "jadx_dex_to_java",
            "duration_s": 0.0,
        }
    summary = _parse_jadx_dir_listing(dirs)
    return {
        "ok": True,
        "data": summary,
        "name": "jadx_dex_to_java",
        "error": "",
        "duration_s": 0.0,
    }


# ---------------------------------------------------------------------------
# Method 7: drozer_modules_discovery
# ---------------------------------------------------------------------------
_DROZER_MOD_RE = re.compile(
    r"^\s*(\S+)\.(\S+)\s+\(([a-z\.]+)\)\s*$"
)


def _parse_drozer_module_list(text: str) -> List[Dict[str, Any]]:
    """Parse ``drozer module list`` output. Pure."""
    out: List[Dict[str, Any]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("drozer"):
            continue
        m = _DROZER_MOD_RE.match(line)
        if m:
            out.append({
                "package": m.group(1),
                "module": m.group(2),
                "level": m.group(3),
                "fqn": f"{m.group(1)}.{m.group(2)}",
            })
    return out


def _drozer_modules_discovery_impl(args: Dict[str, Any]) -> Dict[str, Any]:
    """Parse ``drozer module list`` output. Pure."""
    text = args.get("drozer_output") or args.get("stdout") or ""
    if not text or not isinstance(text, str):
        return {
            "ok": False,
            "error": "drozer_output (string) required",
            "data": None,
            "name": "drozer_modules_discovery",
            "duration_s": 0.0,
        }
    mods = _parse_drozer_module_list(text)
    interesting = [m for m in mods
                   if any(p in m["fqn"] for p in
                          ("app.provider", "app.broadcast",
                           "app.activity", "app.service",
                           "exploit", "scanner"))]
    return {
        "ok": True,
        "data": {
            "module_count": len(mods),
            "interesting_count": len(interesting),
            "interesting": interesting[:50],
        },
        "name": "drozer_modules_discovery",
        "error": "",
        "duration_s": 0.0,
    }


# ---------------------------------------------------------------------------
# Method 8: nmap_android_adb_discovery
# ---------------------------------------------------------------------------
_ANDROID_ADB_PORTS = (5555, 5037)


def _nmap_android_adb_discovery_impl(args: Dict[str, Any]) -> Dict[str, Any]:
    """Run nmap against the canonical android-adb port set
    (5555 tcp ADB daemon + 5037 tcp ADB server). Degrades on
    missing nmap."""
    target = args.get("target") or args.get("host")
    if not target:
        return {
            "ok": False, "error": "target (host) required",
            "data": None,
            "name": "nmap_android_adb_discovery",
            "duration_s": 0.0,
        }
    ports = args.get("ports") or list(_ANDROID_ADB_PORTS)
    timeout_s = int(args.get("timeout_s", 20))
    run = args.get("run")
    if run is None:
        if not _which("nmap"):
            return {
                "ok": False,
                "error": "nmap not installed",
                "data": {"degraded": True, "ports": ports,
                         "target": target},
                "name": "nmap_android_adb_discovery",
                "duration_s": 0.0,
            }
        cmd = ["nmap", "-sV", "-Pn", "-p",
               ",".join(str(p) for p in ports), target]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=timeout_s)
        except subprocess.TimeoutExpired:
            return {
                "ok": False,
                "error": f"nmap timeout after {timeout_s}s",
                "data": None,
                "name": "nmap_android_adb_discovery",
                "duration_s": timeout_s,
            }
        text = proc.stdout or ""
    else:
        text = run.stdout or ""
    services = _parse_nmap_service_lines(text)
    adb_open = any(s["port"] in (5555, 5037) and s["state"] == "open"
                   for s in services)
    return {
        "ok": True,
        "data": {
            "target": target,
            "ports_scanned": ports,
            "adb_open": adb_open,
            "services": [{
                "port": s["port"],
                "state": s["state"],
                "service": s["service"],
                "product_version": s["product_version"]}
                for s in services],
        },
        "name": "nmap_android_adb_discovery",
        "error": "",
        "duration_s": 0.0,
    }


# Re-use the nmap-service-line parser from core.microsoft (it's a
# pure function and the format is identical).
try:
    from core.microsoft.runner import _parse_nmap_service_lines
except Exception:  # noqa: BLE001
    def _parse_nmap_service_lines(text: str) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for line in text.splitlines():
            line = line.rstrip()
            m = re.match(r"^(\d+)/tcp\s+(\w+)\s+(\S+)\s+(.*)$", line)
            if m:
                out.append({
                    "port": int(m.group(1)),
                    "state": m.group(2),
                    "service": m.group(3),
                    "product_version": m.group(4).strip(),
                })
        return out


# ---------------------------------------------------------------------------
# Runner class
# ---------------------------------------------------------------------------
class AndroidRunner:
    """Android target-class attack surface runner.

    Mirrors the shape of the other runners
    (``POST_EXPLOIT_EXT_METHODS`` / ``RECON_METHODS`` /
    ``MICROSOFT_METHODS``) — a class attribute tuple + a
    ``run_attack`` dispatch + a module-level registry for the MCP
    factory.
    """

    ANDROID_METHODS: Tuple[str, ...] = (
        "adb_devices_list",
        "adb_packages_dump",
        "adb_apps_running",
        "frida_processes_enumerate",
        "apktool_decode_manifest",
        "jadx_dex_to_java",
        "drozer_modules_discovery",
        "nmap_android_adb_discovery",
        # Phase 2.0.A2 — intrusive surface (4 methods)
        "frida_trace_attach_method",
        "apktool_repack_with_frida_gadget",
        "adb_logcat_pull",
        "drozer_content_provider_enum",
    )

    # ----- 1 -----
    def _adb_devices_list(self, args: Dict[str, Any]) -> Dict[str, Any]:
        started = time.time()
        st = _step("adb_devices_list")
        res = _adb_devices_list_impl(args)
        return _finalize(st, started, ok=res.get("ok", False),
                          data=res.get("data"),
                          error=res.get("error") or "")

    # ----- 2 -----
    def _adb_packages_dump(self, args: Dict[str, Any]) -> Dict[str, Any]:
        started = time.time()
        st = _step("adb_packages_dump")
        res = _adb_packages_dump_impl(args)
        return _finalize(st, started, ok=res.get("ok", False),
                          data=res.get("data"),
                          error=res.get("error") or "")

    # ----- 3 -----
    def _adb_apps_running(self, args: Dict[str, Any]) -> Dict[str, Any]:
        started = time.time()
        st = _step("adb_apps_running")
        res = _adb_apps_running_impl(args)
        return _finalize(st, started, ok=res.get("ok", False),
                          data=res.get("data"),
                          error=res.get("error") or "")

    # ----- 4 -----
    def _frida_processes_enumerate(self, args: Dict[str, Any]) -> Dict[str, Any]:
        started = time.time()
        st = _step("frida_processes_enumerate")
        res = _frida_processes_enumerate_impl(args)
        return _finalize(st, started, ok=res.get("ok", False),
                          data=res.get("data"),
                          error=res.get("error") or "")

    # ----- 5 -----
    def _apktool_decode_manifest(self, args: Dict[str, Any]) -> Dict[str, Any]:
        started = time.time()
        st = _step("apktool_decode_manifest")
        res = _apktool_decode_manifest_impl(args)
        return _finalize(st, started, ok=res.get("ok", False),
                          data=res.get("data"),
                          error=res.get("error") or "")

    # ----- 6 -----
    def _jadx_dex_to_java(self, args: Dict[str, Any]) -> Dict[str, Any]:
        started = time.time()
        st = _step("jadx_dex_to_java")
        res = _jadx_dex_to_java_impl(args)
        return _finalize(st, started, ok=res.get("ok", False),
                          data=res.get("data"),
                          error=res.get("error") or "")

    # ----- 7 -----
    def _drozer_modules_discovery(self, args: Dict[str, Any]) -> Dict[str, Any]:
        started = time.time()
        st = _step("drozer_modules_discovery")
        res = _drozer_modules_discovery_impl(args)
        return _finalize(st, started, ok=res.get("ok", False),
                          data=res.get("data"),
                          error=res.get("error") or "")

    # ----- 8 -----
    def _nmap_android_adb_discovery(self, args: Dict[str, Any]) -> Dict[str, Any]:
        started = time.time()
        st = _step("nmap_android_adb_discovery")
        res = _nmap_android_adb_discovery_impl(args)
        return _finalize(st, started, ok=res.get("ok", False),
                          data=res.get("data"),
                          error=res.get("error") or "")

    # ==================================================================
    # 9-12 Phase 2.0.A2 — intrusive surface
    # All 4 methods are either (a) emit-only (the operator starts
    # the actual Frida / drozer invocation in a separate gated step)
    # or (b) read-style (adb_logcat_pull is a read; the only thing
    # that changes is that the data is sensitive). The runner never
    # auto-runs a destructive or persistent operation.
    # ==================================================================
    def _frida_trace_attach_method(self,
                                   args: Dict[str, Any]) -> Dict[str, Any]:
        """Emit (not run) the frida attach command. Frida-server
        must be running on the target device; the runner does not
        bind or start the daemon. Degrades on missing target/serial.
        Never inlines credentials."""
        started = time.time()
        st = _step("frida_trace_attach_method")
        target_pkg = (args or {}).get("package", "") or ""
        method_name = (args or {}).get("method_name", "") or ""
        if not target_pkg or not method_name:
            return _finalize(st, started, ok=False,
                             error="frida_trace_attach_method: package and method_name required")
        if any(c in target_pkg for c in (";", "&", "|", "`", "$",
                                          " ", "\n", "\r", "\t")):
            return _finalize(st, started, ok=False,
                             error="frida_trace_attach_method: package has shell meta")
        cmd = [
            "frida", "-U", "-f", target_pkg, "-l", "agent.js",
            "--runtime=v8", "-q",
        ]
        return _finalize(st, started, ok=True, data={
            "command": cmd,
            "package": target_pkg,
            "method_name": method_name,
            "note": ("command EMITTED, not run. Operator starts "
                     "frida-server on the device first; this method "
                     "only validates the target package and emits "
                     "the launch command. agent.js is operator-written "
                     "and lives in toolboxes/android/frida/."),
        }, error="")

    def _apktool_repack_with_frida_gadget(self,
                                          args: Dict[str, Any]) -> Dict[str, Any]:
        """Emit (not run) the apktool rebuild + Frida gadget
        injection command line. The actual repack is destructive
        (modifies the target APK) and must run in a separate
        gated step. Degrades on missing input/path."""
        started = time.time()
        st = _step("apktool_repack_with_frida_gadget")
        apk_path = (args or {}).get("apk_path", "") or ""
        out_path = (args or {}).get("out_path", "") or ""
        if not apk_path or not out_path:
            return _finalize(st, started, ok=False,
                             error="apktool_repack_with_frida_gadget: apk_path and out_path required")
        if any(c in apk_path for c in (";", "&", "|", "`", "$",
                                        " ", "\n", "\r", "\t")):
            return _finalize(st, started, ok=False,
                             error="apktool_repack_with_frida_gadget: apk_path has shell meta")
        if any(c in out_path for c in (";", "&", "|", "`", "$",
                                        " ", "\n", "\r", "\t")):
            return _finalize(st, started, ok=False,
                             error="apktool_repack_with_frida_gadget: out_path has shell meta")
        cmd = [
            "apktool", "d", "-f", "-o", out_path, apk_path,
        ]
        return _finalize(st, started, ok=True, data={
            "command": cmd,
            "apk_path": apk_path,
            "out_path": out_path,
            "note": ("command EMITTED, not run. Operator runs the "
                     "decode, copies the frida-gadget .so into "
                     "lib/<abi>/, edits smali/AndroidManifest.xml, "
                     "and re-builds with ``apktool b``. Sources at "
                     "toolboxes/android/Apktool/ + toolboxes/android/frida/."),
        }, error="")

    def _adb_logcat_pull(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Real adb logcat -d (dump) read. Returns the logcat tail
        filtered to operator-supplied grep tokens (read-only;
        ``-d`` is the dump flag, not ``-c`` clear).
        Degrades on missing adb / no device.
        Sensitive: logcat can include GPS, clipboard, notifications,
        and other PII. The runner never filters or scrubs — the
        operator's downstream consumer must."""
        started = time.time()
        st = _step("adb_logcat_pull")
        if not _which("adb"):
            return _finalize(st, started, ok=False,
                             error="adb not installed")
        serial = (args or {}).get("serial", "") or ""
        grep = (args or {}).get("grep", "") or ""
        tail_lines = int((args or {}).get("tail_lines", 200) or 200)
        cmd = ["adb"]
        if serial:
            cmd += ["-s", serial]
        cmd += ["logcat", "-d", "-t", str(max(1, min(tail_lines, 5000)))]
        if grep:
            if any(c in grep for c in (";", "&", "|", "`", "$",
                                        "\n", "\r", "\t")):
                return _finalize(st, started, ok=False,
                                 error="adb_logcat_pull: grep has shell meta")
            cmd += ["|", "grep", "--", grep]  # NB: never run, just emit
        try:
            from subprocess import run as _sr, PIPE, TimeoutExpired
            # When grep is set, the shell pipe can't run; we run
            # the unfiltered logcat and let the runner post-filter.
            run_cmd = [c for c in cmd if c not in ("|",)]
            if grep:
                # Strip the literal pipe marker and run logcat
                # then filter in Python.
                run_cmd = [c for c in cmd if c != "|"]
            proc = _sr(run_cmd, capture_output=True, text=True,
                       timeout=10)
            raw = proc.stdout or ""
            if grep:
                lines = [ln for ln in raw.splitlines() if grep in ln]
            else:
                lines = raw.splitlines()[-tail_lines:]
            return _finalize(st, started, ok=(proc.returncode == 0),
                             data={
                                 "returncode": proc.returncode,
                                 "line_count": len(lines),
                                 "lines": lines[-200:],
                                 "grep": grep,
                                 "serial": serial,
                                 "note": ("real adb logcat -d output; "
                                          "may include PII (GPS, "
                                          "clipboard, notifications); "
                                          "never logcat -c (clear)."),
                             },
                             error="" if proc.returncode == 0 else
                             (proc.stderr or "").strip()[:200])
        except TimeoutExpired:
            return _finalize(st, started, ok=False,
                             error="adb_logcat_pull: adb timeout (10s)")
        except FileNotFoundError:
            return _finalize(st, started, ok=False,
                             error="adb_logcat_pull: adb not installed")
        except Exception as e:  # noqa: BLE001
            return _finalize(st, started, ok=False,
                             error=f"adb_logcat_pull: {e}")

    def _drozer_content_provider_enum(self,
                                      args: Dict[str, Any]) -> Dict[str, Any]:
        """Emit (not run) the drozer provider enumeration
        command. Real subprocess is invasive on the device; the
        operator runs it in a separate gated step. Degrades on
        missing drozer / package name."""
        started = time.time()
        st = _step("drozer_content_provider_enum")
        target_pkg = (args or {}).get("package", "") or ""
        if not target_pkg:
            return _finalize(st, started, ok=False,
                             error="drozer_content_provider_enum: package required")
        if any(c in target_pkg for c in (";", "&", "|", "`", "$",
                                          " ", "\n", "\r", "\t")):
            return _finalize(st, started, ok=False,
                             error="drozer_content_provider_enum: package has shell meta")
        cmd = [
            "drozer", "console", "connect",
            "-c",
            f"run app.provider.finduris {target_pkg}; "
            f"run app.provider.query {target_pkg}; "
            f"run app.provider.info -a {target_pkg}",
        ]
        return _finalize(st, started, ok=True, data={
            "command": cmd,
            "package": target_pkg,
            "note": ("command EMITTED, not run. Operator starts "
                     "drozer-agent on the device and the console "
                     "in a separate gated step. The three run "
                     "lines (finduris / query / info) are the "
                     "canonical provider-enum sequence from "
                     "toolboxes/android/drozer/."),
        }, error="")

    # ------------------------------------------------------------------
    def run_attack(self, method: str) -> Dict[str, Any]:
        """Run a single Android method by name. Never raises. The
        per-step ACCEPT/CANCEL gate already fired in
        :meth:`_walk_ai_step` (single-gate invariant)."""
        if method not in self.ANDROID_METHODS:
            return {
                "name": method, "ok": False,
                "error": f"unknown method {method!r}; one of {list(self.ANDROID_METHODS)}",
                "data": None, "duration_s": 0.0,
            }
        impl = getattr(self, f"_{method}", None)
        if impl is None:
            return {
                "name": method, "ok": False,
                "error": f"method {method!r} not implemented",
                "data": None, "duration_s": 0.0,
            }
        return impl(self._args or {})

    def __init__(self, args: Optional[Dict[str, Any]] = None) -> None:
        self._args = args or {}


# ---------------------------------------------------------------------------
# Module-level registry
# ---------------------------------------------------------------------------
ANDROID_METHODS: Tuple[str, ...] = AndroidRunner.ANDROID_METHODS


def _build_registry() -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    family_schemas = {
        "adb_devices_list": {
            "input_schema": {"type": "object",
                              "properties": {"run": {"type": "object"},
                                              "timeout_s": {"type": "integer"}},
                              "required": []},
            "description": ("adb devices -l. Degrades on missing adb; "
                            "hermetic with a mocked run object."),
        },
        "adb_packages_dump": {
            "input_schema": {"type": "object",
                              "properties": {"pm_output": {"type": "string"}},
                              "required": ["pm_output"]},
            "description": ("Parse adb shell pm list packages -f -3 "
                            "output. Pure parse; never opens adb."),
        },
        "adb_apps_running": {
            "input_schema": {"type": "object",
                              "properties": {"ps_output": {"type": "string"}},
                              "required": ["ps_output"]},
            "description": ("Parse adb shell ps -A output. Pure parse; "
                            "never opens adb."),
        },
        "frida_processes_enumerate": {
            "input_schema": {"type": "object",
                              "properties": {"frida_ps_output":
                                              {"type": "string"}},
                              "required": ["frida_ps_output"]},
            "description": ("Parse frida-ps -Uai output. Pure parse; "
                            "never opens frida."),
        },
        "apktool_decode_manifest": {
            "input_schema": {"type": "object",
                              "properties": {"androidmanifest_xml":
                                              {"type": "string"}},
                              "required": ["androidmanifest_xml"]},
            "description": ("Parse an apktool-decoded AndroidManifest.xml "
                            "(uses / parse). Pure parse."),
        },
        "jadx_dex_to_java": {
            "input_schema": {"type": "object",
                              "properties": {"dirs":
                                              {"type": "array",
                                               "items": {"type": "string"}}},
                              "required": ["dirs"]},
            "description": ("Summarize a jadx -d output directory "
                            "listing. Pure."),
        },
        "drozer_modules_discovery": {
            "input_schema": {"type": "object",
                              "properties": {"drozer_output":
                                              {"type": "string"}},
                              "required": ["drozer_output"]},
            "description": ("Parse drozer module list output. Pure."),
        },
        "nmap_android_adb_discovery": {
            "input_schema": {"type": "object",
                              "properties": {"target": {"type": "string"},
                                              "ports":
                                              {"type": "array",
                                               "items": {"type": "integer"}},
                                              "timeout_s":
                                              {"type": "integer"}},
                              "required": ["target"]},
            "description": ("nmap -sV -Pn against the canonical "
                            "android-adb ports (5555, 5037). Degrades "
                            "on missing nmap."),
        },
        # Phase 2.0.A2 — intrusive surface (4 methods)
        "frida_trace_attach_method": {
            "input_schema": {"type": "object",
                              "properties": {
                                  "package": {"type": "string"},
                                  "method_name": {"type": "string"}},
                              "required": ["package", "method_name"]},
            "description": ("EMIT-ONLY: frida -U -f <pkg> -l agent.js. "
                            "Never binds frida-server. Operator starts "
                            "the actual attach in a separate gated "
                            "step. agent.js lives in "
                            "toolboxes/android/frida/."),
        },
        "apktool_repack_with_frida_gadget": {
            "input_schema": {"type": "object",
                              "properties": {
                                  "apk_path": {"type": "string"},
                                  "out_path": {"type": "string"}},
                              "required": ["apk_path", "out_path"]},
            "description": ("EMIT-ONLY: apktool decode + frida-gadget "
                            "inject + apktool rebuild. Destructive on "
                            "the target APK; operator runs in a "
                            "separate gated step. Sources in "
                            "toolboxes/android/Apktool/ + "
                            "toolboxes/android/frida/."),
        },
        "adb_logcat_pull": {
            "input_schema": {"type": "object",
                              "properties": {
                                  "serial": {"type": "string"},
                                  "grep": {"type": "string"},
                                  "tail_lines": {"type": "integer"}},
                              "required": []},
            "description": ("Real adb logcat -d (dump) read. "
                            "Sensitive: may include GPS, clipboard, "
                            "notifications. NEVER logcat -c (clear). "
                            "Degrades on missing adb / no device."),
        },
        "drozer_content_provider_enum": {
            "input_schema": {"type": "object",
                              "properties": {
                                  "package": {"type": "string"}},
                              "required": ["package"]},
            "description": ("EMIT-ONLY: drozer provider-enum "
                            "sequence (finduris / query / info). "
                            "Invasive on the device; operator runs "
                            "in a separate gated step. Source in "
                            "toolboxes/android/drozer/."),
        },
    }
    # Risk-level overrides for the Phase 2.0.A2 surface.
    family_risk = {
        "frida_trace_attach_method": "intrusive",
        "apktool_repack_with_frida_gadget": "destructive",
        "adb_logcat_pull": "intrusive",  # sensitive read
        "drozer_content_provider_enum": "intrusive",
    }
    for m in AndroidRunner.ANDROID_METHODS:
        meta = family_schemas.get(m, {})
        out.append({
            "method": m,
            "name": f"android_attack_{m}",
            "description": (
                f"Android target-class method: {m}. Real subprocess "
                "/ parse / pure logic / emit-only; degrades cleanly "
                "when adb / frida / apktool / jadx / drozer / nmap "
                "is absent. Never fabricates a Frida hook output, a "
                "cracked PSK, a cleartext credential, or a 'pwned' "
                "verdict. " + meta.get("description", "")),
            "input_schema": meta.get("input_schema",
                                      {"type": "object", "properties": {}}),
            "examples": [f"android_attack(method={m!r}, ...)"],
            "risk_level": family_risk.get(m, "read"),
            "requires_root": False,
        })
    return out


ANDROID_ATTACKS: List[Dict[str, Any]] = _build_registry()


def run_attack(method: str, args: Optional[Dict[str, Any]] = None,
               **_: Any) -> Dict[str, Any]:
    """Module-level single-attack entrypoint. Used by the
    orchestrator's ``android_attack`` dispatch and the MCP
    wrappers. Never raises."""
    try:
        runner = AndroidRunner(args=args)
        return runner.run_attack(method)
    except Exception as e:  # noqa: BLE001
        return {"name": method, "ok": False, "error": str(e),
                "data": None, "duration_s": 0.0}
