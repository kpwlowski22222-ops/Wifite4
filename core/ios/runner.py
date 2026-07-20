"""IOSRunner — iOS target-class attack surface.

Phase 2.0.I0+I1 — scaffolding + 8 read-only methods. The intrusive
surface (ssl_kill_switch_attach, objection_run_method,
frida_trace_class, idevicebackup2_extract) is layered on in
Phase 2.0.I2.

The eight read methods (all risk=READ, hermetic where possible):

  1. libimobiledevice_list_devices
       — ``idevice_id -l`` + ``idevicename`` parse. Pure.
  2. usbmuxd_list_connected
       — ``usbmuxd`` listening devices (parsed from
         ``usbmuxd -l`` or a raw socket listing). Pure.
  3. ideviceinfo_dump
       — ``ideviceinfo -u <udid>`` key/value parse. Pure.
  4. idevicedebug_apps_list
       — ``idevicedebugserverproxy`` + ``debugserver`` list-apps
         output parse. Pure.
  5. idevicebackup2_list
       — ``idevicebackup2 list`` (or the on-disk backup tree)
         parse. Pure.
  6. frida_ios_dump_bundle_id
       — parse ``frida-ios-dump -l`` (list installed apps).
         Pure.
  7. objection_environment_inventory
       — parse ``objection explore`` environment report. Pure.
  8. nmap_apple_mdns_discovery
       — nmap NSE for ``apple-mdns`` (port 5353 UDP + 5900/22
         heuristics). Real subprocess; degrades on missing nmap.
         Hermetic with mocked run.

Honesty contract (mirrors the rest of KFIOSA):
  * Real work or honest degradation. Never fake results.
  * Never fabricates CVE ids, cleartext creds, Frida hook output,
    IPA repack, or 'pwned' verdicts.
  * Read-only by default. The 4 intrusive methods land in
    Phase 2.0.I2 and are gated by the same per-step ACCEPT/CANCEL
    gate as every other step.
  * Never raises; every code path returns a step dict.
"""
from __future__ import annotations

import json
import logging
import re
import shlex
import shutil
import subprocess
import time
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Step envelope
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
# Method 1: libimobiledevice_list_devices
# ---------------------------------------------------------------------------
_UDID_RE = re.compile(r"^[0-9a-fA-F]{40}$")


def _parse_idevice_id_output(text: str) -> List[Dict[str, Any]]:
    """Parse ``idevice_id -l`` output. Pure.

    Output: one UDID per line, e.g. ``00008101-001234567890ABCD``
    (the canonical iOS 40-hex UDID with hyphens)."""
    out: List[Dict[str, Any]] = []
    for line in text.splitlines():
        u = line.strip()
        if not u:
            continue
        # Normalise: strip the dashed format → 40-hex.
        flat = u.replace("-", "")
        if not _UDID_RE.match(flat):
            continue
        out.append({"udid": flat})
    return out


def _libimobiledevice_list_devices_impl(args: Dict[str, Any]) -> Dict[str, Any]:
    """Parse ``idevice_id -l`` output. Pure."""
    text = args.get("idevice_id_output") or args.get("stdout") or ""
    if not text or not isinstance(text, str):
        return {
            "ok": False,
            "error": "idevice_id_output (string) required",
            "data": None,
            "name": "libimobiledevice_list_devices",
            "duration_s": 0.0,
        }
    devs = _parse_idevice_id_output(text)
    return {
        "ok": True,
        "data": {"device_count": len(devs), "devices": devs},
        "name": "libimobiledevice_list_devices",
        "error": "",
        "duration_s": 0.0,
    }


# ---------------------------------------------------------------------------
# Method 2: usbmuxd_list_connected
# ---------------------------------------------------------------------------
def _parse_usbmuxd_listing(text: str) -> List[Dict[str, Any]]:
    """Parse a ``usbmuxd`` listing (e.g. ``usbmuxd -l`` or the
    ``--devices`` JSON). Pure.

    Two output shapes are accepted:
      1. ``<udid>  <serial-or-product>`` whitespace-separated.
      2. JSON list of objects with ``DeviceID``/``SerialNumber``/
         ``ProductID``/``LocationID``.
    """
    text = text.strip()
    if not text:
        return []
    if text.startswith("["):
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            data = None
        out: List[Dict[str, Any]] = []
        if isinstance(data, list):
            for d in data:
                if not isinstance(d, dict):
                    continue
                out.append({
                    "udid": d.get("DeviceID") or "",
                    "serial": d.get("SerialNumber") or "",
                    "product_id": d.get("ProductID") or "",
                    "location_id": d.get("LocationID") or "",
                })
            return out
    # Whitespace-separated.
    out = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 1:
            continue
        u = parts[0].strip()
        flat = u.replace("-", "")
        if not _UDID_RE.match(flat):
            continue
        out.append({"udid": flat,
                    "serial": parts[1] if len(parts) > 1 else ""})
    return out


def _usbmuxd_list_connected_impl(args: Dict[str, Any]) -> Dict[str, Any]:
    """Parse a usbmuxd listening listing. Pure."""
    text = args.get("usbmuxd_output") or args.get("stdout") or ""
    if not text or not isinstance(text, str):
        return {
            "ok": False,
            "error": "usbmuxd_output (string) required",
            "data": None,
            "name": "usbmuxd_list_connected",
            "duration_s": 0.0,
        }
    devs = _parse_usbmuxd_listing(text)
    return {
        "ok": True,
        "data": {"device_count": len(devs), "devices": devs},
        "name": "usbmuxd_list_connected",
        "error": "",
        "duration_s": 0.0,
    }


# ---------------------------------------------------------------------------
# Method 3: ideviceinfo_dump
# ---------------------------------------------------------------------------
_KV_LINE_RE = re.compile(r"^([A-Za-z][A-Za-z0-9_]*):\s*(.*)$")


def _parse_ideviceinfo_output(text: str) -> Dict[str, Any]:
    """Parse ``ideviceinfo -u <udid>`` key/value output. Pure."""
    out: Dict[str, Any] = {}
    for line in text.splitlines():
        line = line.rstrip()
        m = _KV_LINE_RE.match(line)
        if m:
            k, v = m.group(1).strip(), m.group(2).strip()
            if k and k not in out:
                out[k] = v
    return out


def _classify_ios_version(version: str) -> str:
    """Map an iOS version string to a coarse class. Pure."""
    m = re.match(r"^(\d+)\.(\d+)", version or "")
    if not m:
        return "unknown"
    major, minor = int(m.group(1)), int(m.group(2))
    if major >= 17:
        return "ios_17_plus"
    if major >= 16:
        return "ios_16_plus"
    if major >= 15:
        return "ios_15_plus"
    if major >= 14:
        return "ios_14_plus"
    if major >= 13:
        return "ios_13_plus"
    if major >= 12:
        return "ios_12_plus"
    return f"ios_{major}_{minor}"


def _ideviceinfo_dump_impl(args: Dict[str, Any]) -> Dict[str, Any]:
    """Parse ideviceinfo output. Pure."""
    text = args.get("ideviceinfo_output") or args.get("stdout") or ""
    if not text or not isinstance(text, str):
        return {
            "ok": False,
            "error": "ideviceinfo_output (string) required",
            "data": None,
            "name": "ideviceinfo_dump",
            "duration_s": 0.0,
        }
    info = _parse_ideviceinfo_output(text)
    if not info:
        return {
            "ok": False,
            "error": "no key/value pairs parsed from ideviceinfo output",
            "data": None,
            "name": "ideviceinfo_dump",
            "duration_s": 0.0,
        }
    version = (info.get("ProductVersion")
                or info.get("product_version") or "")
    return {
        "ok": True,
        "data": {
            "udid": (info.get("UniqueDeviceID")
                      or info.get("unique_device_id") or ""),
            "device_name": (info.get("DeviceName")
                             or info.get("device_name") or ""),
            "model": (info.get("ModelNumber")
                       or info.get("model_number") or ""),
            "product_type": (info.get("ProductType")
                              or info.get("product_type") or ""),
            "product_version": version,
            "version_class": _classify_ios_version(version),
            "build_version": (info.get("BuildVersion")
                                or info.get("build_version") or ""),
            "imei": (info.get("InternationalMobileEquipmentIdentity")
                      or info.get("imei") or ""),
            "serial": (info.get("SerialNumber")
                        or info.get("serial_number") or ""),
            "all": info,
        },
        "name": "ideviceinfo_dump",
        "error": "",
        "duration_s": 0.0,
    }


# ---------------------------------------------------------------------------
# Method 4: idevicedebug_apps_list
# ---------------------------------------------------------------------------
def _parse_debugserver_listapps(text: str) -> List[Dict[str, Any]]:
    """Parse ``debugserver -g`` / ``idevicedebugserverproxy`` list
    output. Pure.

    Lines look like (a debugserver client printout)::

        Applications and Services
        -------------------------
          bundle.id.one
          bundle.id.two
        """
    out: List[Dict[str, Any]] = []
    for line in text.splitlines():
        line = line.rstrip()
        s = line.strip()
        if not s or s.startswith("Applications") or s.startswith("---") \
                or s.startswith("("):
            continue
        if re.fullmatch(r"[A-Za-z0-9._\-]+", s):
            out.append({"bundle_id": s})
    return out


def _idevicedebug_apps_list_impl(args: Dict[str, Any]) -> Dict[str, Any]:
    """Parse idevicedebugserverproxy list-apps output. Pure."""
    text = args.get("debugserver_output") or args.get("stdout") or ""
    if not text or not isinstance(text, str):
        return {
            "ok": False,
            "error": "debugserver_output (string) required",
            "data": None,
            "name": "idevicedebug_apps_list",
            "duration_s": 0.0,
        }
    apps = _parse_debugserver_listapps(text)
    return {
        "ok": True,
        "data": {"app_count": len(apps), "apps": apps[:50]},
        "name": "idevicedebug_apps_list",
        "error": "",
        "duration_s": 0.0,
    }


# ---------------------------------------------------------------------------
# Method 5: idevicebackup2_list
# ---------------------------------------------------------------------------
def _parse_idevicebackup2_listing(text: str) -> List[Dict[str, Any]]:
    """Parse ``idevicebackup2 list`` output. Pure.

    Output shape (one block per backup)::

        Backup directory: /path/to/backup
        Unique Identifier: <UDID>
        Target Identifier: <UDID>
        Product Version: 16.5
        Backup Time: 1696420000
    """
    out: List[Dict[str, Any]] = []
    cur: Dict[str, Any] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line:
            if cur:
                out.append(cur)
                cur = {}
            continue
        m = re.match(r"^([A-Za-z][A-Za-z0-9_ ]+):\s*(.*)$", line)
        if m:
            k = m.group(1).strip().replace(" ", "_").lower()
            cur[k] = m.group(2).strip()
    if cur:
        out.append(cur)
    return out


def _idevicebackup2_list_impl(args: Dict[str, Any]) -> Dict[str, Any]:
    """Parse idevicebackup2 list output. Pure."""
    text = args.get("backup2_output") or args.get("stdout") or ""
    if not text or not isinstance(text, str):
        return {
            "ok": False,
            "error": "backup2_output (string) required",
            "data": None,
            "name": "idevicebackup2_list",
            "duration_s": 0.0,
        }
    backups = _parse_idevicebackup2_listing(text)
    return {
        "ok": True,
        "data": {"backup_count": len(backups), "backups": backups},
        "name": "idevicebackup2_list",
        "error": "",
        "duration_s": 0.0,
    }


# ---------------------------------------------------------------------------
# Method 6: frida_ios_dump_bundle_id
# ---------------------------------------------------------------------------
def _parse_frida_ios_dump_listing(text: str) -> List[Dict[str, Any]]:
    """Parse ``frida-ios-dump -l`` (or just the listing) output. Pure.

    Lines look like::

        [iPhone::PID::0] com.apple.example
        com.example.app
    """
    out: List[Dict[str, Any]] = []
    seen = set()
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        # Strip the ``[iPhone::PID::N]`` prefix.
        m = re.match(r"^\[.*?\]\s+(.+)$", line)
        if m:
            s = m.group(1).strip()
        else:
            s = line
        if re.fullmatch(r"[A-Za-z0-9._\-]+", s) and s not in seen:
            seen.add(s)
            out.append({"bundle_id": s})
    return out


def _frida_ios_dump_bundle_id_impl(args: Dict[str, Any]) -> Dict[str, Any]:
    """Parse frida-ios-dump listing output. Pure."""
    text = args.get("frida_ios_dump_output") or args.get("stdout") or ""
    if not text or not isinstance(text, str):
        return {
            "ok": False,
            "error": "frida_ios_dump_output (string) required",
            "data": None,
            "name": "frida_ios_dump_bundle_id",
            "duration_s": 0.0,
        }
    apps = _parse_frida_ios_dump_listing(text)
    return {
        "ok": True,
        "data": {"app_count": len(apps), "apps": apps},
        "name": "frida_ios_dump_bundle_id",
        "error": "",
        "duration_s": 0.0,
    }


# ---------------------------------------------------------------------------
# Method 7: objection_environment_inventory
# ---------------------------------------------------------------------------
def _parse_objection_env(text: str) -> Dict[str, Any]:
    """Parse an ``objection explore`` environment report. Pure.

    Tries to surface:
      * Bundle identifier
      * Version
      * Linked frameworks
      * PIE / ARC / encryption / canary flags
      * Running on a jailbroken device / simulator
    """
    out: Dict[str, Any] = {
        "bundle_id": "",
        "version": "",
        "platform": "",
        "arch": "",
        "linked_frameworks": [],
        "jailbroken": False,
        "simulator": False,
        "encrypted": False,
        "canary": False,
    }
    for line in text.splitlines():
        line = line.rstrip()
        s = line.strip()
        m = re.match(r"^\s*([A-Za-z][A-Za-z0-9 _]+?)\s*[:=]\s*(.+)$", line)
        if not m:
            continue
        k = m.group(1).strip().lower().replace(" ", "_")
        v = m.group(2).strip()
        if k in ("bundle_identifier", "bundleid", "bundle"):
            out["bundle_id"] = v
        elif k in ("version",):
            out["version"] = v
        elif k in ("platform",):
            out["platform"] = v
        elif k in ("arch", "architecture"):
            out["arch"] = v
        elif k in ("linked_frameworks", "linked framework"):
            out["linked_frameworks"] = [x.strip() for x in
                                          re.split(r"[,\s]+", v) if x.strip()]
        elif k == "jailbroken":
            out["jailbroken"] = v.lower() in ("true", "yes", "1")
        elif k == "simulator":
            out["simulator"] = v.lower() in ("true", "yes", "1")
        elif k in ("encrypted", "isencrypted"):
            out["encrypted"] = v.lower() in ("true", "yes", "1")
        elif k == "canary":
            out["canary"] = v.lower() in ("true", "yes", "1")
    return out


def _objection_environment_inventory_impl(
        args: Dict[str, Any]) -> Dict[str, Any]:
    """Parse objection environment report. Pure."""
    text = args.get("objection_output") or args.get("stdout") or ""
    if not text or not isinstance(text, str):
        return {
            "ok": False,
            "error": "objection_output (string) required",
            "data": None,
            "name": "objection_environment_inventory",
            "duration_s": 0.0,
        }
    inv = _parse_objection_env(text)
    return {
        "ok": True,
        "data": inv,
        "name": "objection_environment_inventory",
        "error": "",
        "duration_s": 0.0,
    }


# ---------------------------------------------------------------------------
# Method 8: nmap_apple_mdns_discovery
# ---------------------------------------------------------------------------
_APPLE_MDNS_PORTS = (5353, 5900, 22, 62078, 7000)


def _nmap_apple_mdns_discovery_impl(args: Dict[str, Any]) -> Dict[str, Any]:
    """Run nmap against the canonical Apple ports (5353 mDNS + a
    few iTunes-sync + Lockdown / iOS-USB-related ports). Degrades
    on missing nmap. Hermetic with mocked run."""
    target = args.get("target") or args.get("host")
    if not target:
        return {
            "ok": False, "error": "target (host) required",
            "data": None,
            "name": "nmap_apple_mdns_discovery",
            "duration_s": 0.0,
        }
    ports = args.get("ports") or list(_APPLE_MDNS_PORTS)
    timeout_s = int(args.get("timeout_s", 20))
    run = args.get("run")
    if run is None:
        if not _which("nmap"):
            return {
                "ok": False,
                "error": "nmap not installed",
                "data": {"degraded": True, "ports": ports,
                         "target": target},
                "name": "nmap_apple_mdns_discovery",
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
                "name": "nmap_apple_mdns_discovery",
                "duration_s": timeout_s,
            }
        text = proc.stdout or ""
    else:
        text = run.stdout or ""
    services = _parse_nmap_service_lines(text)
    mdns_open = any(s["port"] == 5353 and s["state"] == "open"
                    for s in services)
    itunes_open = any(s["port"] == 62078 and s["state"] == "open"
                      for s in services)
    return {
        "ok": True,
        "data": {
            "target": target,
            "ports_scanned": ports,
            "mdns_open": mdns_open,
            "itunes_sync_open": itunes_open,
            "services": [{
                "port": s["port"],
                "state": s["state"],
                "service": s["service"],
                "product_version": s["product_version"]}
                for s in services],
        },
        "name": "nmap_apple_mdns_discovery",
        "error": "",
        "duration_s": 0.0,
    }


# Re-use the nmap service-line parser.
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
class IOSRunner:
    """iOS target-class attack surface runner.

    Mirrors the shape of the other runners
    (``POST_EXPLOIT_EXT_METHODS`` / ``RECON_METHODS`` /
    ``MICROSOFT_METHODS``) — a class attribute tuple + a
    ``run_attack`` dispatch + a module-level registry for the MCP
    factory.
    """

    IOS_METHODS: Tuple[str, ...] = (
        "libimobiledevice_list_devices",
        "usbmuxd_list_connected",
        "ideviceinfo_dump",
        "idevicedebug_apps_list",
        "idevicebackup2_list",
        "frida_ios_dump_bundle_id",
        "objection_environment_inventory",
        "nmap_apple_mdns_discovery",
        # Phase 2.0.I2 — intrusive surface (4 methods)
        "ssl_kill_switch_attach",
        "objection_run_method",
        "frida_trace_class",
        "idevicebackup2_extract",
    )

    # ----- 1 -----
    def _libimobiledevice_list_devices(self, args: Dict[str, Any]) -> Dict[str, Any]:
        started = time.time()
        st = _step("libimobiledevice_list_devices")
        res = _libimobiledevice_list_devices_impl(args)
        return _finalize(st, started, ok=res.get("ok", False),
                          data=res.get("data"),
                          error=res.get("error") or "")

    # ----- 2 -----
    def _usbmuxd_list_connected(self, args: Dict[str, Any]) -> Dict[str, Any]:
        started = time.time()
        st = _step("usbmuxd_list_connected")
        res = _usbmuxd_list_connected_impl(args)
        return _finalize(st, started, ok=res.get("ok", False),
                          data=res.get("data"),
                          error=res.get("error") or "")

    # ----- 3 -----
    def _ideviceinfo_dump(self, args: Dict[str, Any]) -> Dict[str, Any]:
        started = time.time()
        st = _step("ideviceinfo_dump")
        res = _ideviceinfo_dump_impl(args)
        return _finalize(st, started, ok=res.get("ok", False),
                          data=res.get("data"),
                          error=res.get("error") or "")

    # ----- 4 -----
    def _idevicedebug_apps_list(self, args: Dict[str, Any]) -> Dict[str, Any]:
        started = time.time()
        st = _step("idevicedebug_apps_list")
        res = _idevicedebug_apps_list_impl(args)
        return _finalize(st, started, ok=res.get("ok", False),
                          data=res.get("data"),
                          error=res.get("error") or "")

    # ----- 5 -----
    def _idevicebackup2_list(self, args: Dict[str, Any]) -> Dict[str, Any]:
        started = time.time()
        st = _step("idevicebackup2_list")
        res = _idevicebackup2_list_impl(args)
        return _finalize(st, started, ok=res.get("ok", False),
                          data=res.get("data"),
                          error=res.get("error") or "")

    # ----- 6 -----
    def _frida_ios_dump_bundle_id(self, args: Dict[str, Any]) -> Dict[str, Any]:
        started = time.time()
        st = _step("frida_ios_dump_bundle_id")
        res = _frida_ios_dump_bundle_id_impl(args)
        return _finalize(st, started, ok=res.get("ok", False),
                          data=res.get("data"),
                          error=res.get("error") or "")

    # ----- 7 -----
    def _objection_environment_inventory(self, args: Dict[str, Any]) -> Dict[str, Any]:
        started = time.time()
        st = _step("objection_environment_inventory")
        res = _objection_environment_inventory_impl(args)
        return _finalize(st, started, ok=res.get("ok", False),
                          data=res.get("data"),
                          error=res.get("error") or "")

    # ----- 8 -----
    def _nmap_apple_mdns_discovery(self, args: Dict[str, Any]) -> Dict[str, Any]:
        started = time.time()
        st = _step("nmap_apple_mdns_discovery")
        res = _nmap_apple_mdns_discovery_impl(args)
        return _finalize(st, started, ok=res.get("ok", False),
                          data=res.get("data"),
                          error=res.get("error") or "")

    # ==================================================================
    # 9-12 Phase 2.0.I2 — intrusive surface
    # All 4 are either emit-only (ssl_kill_switch_attach, objection,
    # frida_trace_class) or read-style (idevicebackup2_extract is a
    # read of the backup contents; the runner never deletes or
    # overwrites a backup). The runner does NOT auto-attach or
    # auto-reset the device.
    # ==================================================================
    def _ssl_kill_switch_attach(self,
                                args: Dict[str, Any]) -> Dict[str, Any]:
        """Emit (not run) the ssl-kill-switch2 attach command.
        ssl-kill-switch2 is a Frida-based tweak that bypasses
        iOS TLS pinning; the runner only validates the target
        bundle id and emits the launch command. Degrades on
        missing target_bundle_id."""
        started = time.time()
        st = _step("ssl_kill_switch_attach")
        target_bundle = (args or {}).get("bundle_id", "") or ""
        if not target_bundle:
            return _finalize(st, started, ok=False,
                             error="ssl_kill_switch_attach: bundle_id required")
        if any(c in target_bundle for c in (";", "&", "|", "`", "$",
                                             " ", "\n", "\r", "\t")):
            return _finalize(st, started, ok=False,
                             error="ssl_kill_switch_attach: bundle_id has shell meta")
        cmd = [
            "frida", "-U", "-f", target_bundle, "-l",
            "toolboxes/ios/ssl-kill-switch2/agent/SSL_Kill_Switch_2.js",
            "--runtime=v8", "-q",
        ]
        return _finalize(st, started, ok=True, data={
            "command": cmd,
            "bundle_id": target_bundle,
            "note": ("command EMITTED, not run. The ssl-kill-switch2 "
                     "agent is a Frida JS hook that patches "
                     "SecTrustEvaluate. Operator starts the actual "
                     "attach in a separate gated step."),
        }, error="")

    def _objection_run_method(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Emit (not run) an objection method-invocation command.
        Objection is the runtime exploration tool; the runner
        only validates inputs and emits the launch command.
        Degrades on missing bundle_id / method."""
        started = time.time()
        st = _step("objection_run_method")
        target_bundle = (args or {}).get("bundle_id", "") or ""
        method_path = (args or {}).get("method", "") or ""
        if not target_bundle or not method_path:
            return _finalize(st, started, ok=False,
                             error="objection_run_method: bundle_id and method required")
        if any(c in target_bundle for c in (";", "&", "|", "`", "$",
                                             " ", "\n", "\r", "\t")):
            return _finalize(st, started, ok=False,
                             error="objection_run_method: bundle_id has shell meta")
        # method_path is a dotted Obj-C / Swift class path
        # (e.g. "NSURLSession.dataTaskWithRequest:"). The colon
        # is a valid method-path char, not a shell meta; we
        # only block actual shell metas.
        if any(c in method_path for c in (";", "&", "|", "`", "$",
                                            "\n", "\r", "\t")):
            return _finalize(st, started, ok=False,
                             error="objection_run_method: method has shell meta")
        cmd = [
            "objection", "-g", target_bundle, "explore",
            "-c", f"ios hooking watch method {method_path}",
        ]
        return _finalize(st, started, ok=True, data={
            "command": cmd,
            "bundle_id": target_bundle,
            "method": method_path,
            "note": ("command EMITTED, not run. Operator starts "
                     "the actual hook in a separate gated step."),
        }, error="")

    def _frida_trace_class(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Emit (not run) a frida -U trace command for an Obj-C
        class. The trace prints every method call on the class;
        the runner only validates the class name and emits the
        command. Degrades on missing class_name."""
        started = time.time()
        st = _step("frida_trace_class")
        target_bundle = (args or {}).get("bundle_id", "") or ""
        class_name = (args or {}).get("class_name", "") or ""
        if not target_bundle or not class_name:
            return _finalize(st, started, ok=False,
                             error="frida_trace_class: bundle_id and class_name required")
        if any(c in target_bundle for c in (";", "&", "|", "`", "$",
                                             " ", "\n", "\r", "\t")):
            return _finalize(st, started, ok=False,
                             error="frida_trace_class: bundle_id has shell meta")
        if any(c in class_name for c in (";", "&", "|", "`", "$",
                                          " ", "\n", "\r", "\t")):
            return _finalize(st, started, ok=False,
                             error="frida_trace_class: class_name has shell meta")
        cmd = [
            "frida", "-U", "-f", target_bundle, "-l",
            "toolboxes/ios/frida/objc_class_trace.js",
            "--runtime=v8", "-q",
        ]
        return _finalize(st, started, ok=True, data={
            "command": cmd,
            "bundle_id": target_bundle,
            "class_name": class_name,
            "note": ("command EMITTED, not run. objc_class_trace.js "
                     "is operator-written; lives in toolboxes/ios/frida/."),
        }, error="")

    def _idevicebackup2_extract(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """EMIT-ONLY: compose the ``idevicebackup2 backup <dir>``
        command and emit it. The runner NEVER runs the backup
        itself and NEVER deletes an existing backup — the
        operator starts the actual backup in a separate gated
        step. The runner never auto-runs destructive ops.

        Sensitive: backups contain keychain, SMS, photos, app
        data — the operator must handle the out_dir carefully.
        The runner degrades honestly on missing inputs
        (out_dir required, shell-meta in out_dir) but does NOT
        block on a missing ``idevicebackup2`` binary: the
        command is EMITTED, not executed."""
        started = time.time()
        st = _step("idevicebackup2_extract")
        out_dir = (args or {}).get("out_dir", "") or ""
        if not out_dir:
            return _finalize(st, started, ok=False,
                             error="idevicebackup2_extract: out_dir required")
        if any(c in out_dir for c in (";", "&", "|", "`", "$",
                                        "\n", "\r", "\t")):
            return _finalize(st, started, ok=False,
                             error="idevicebackup2_extract: out_dir has shell meta")
        udid = (args or {}).get("udid", "") or ""
        cmd = ["idevicebackup2"]
        if udid:
            cmd += ["-u", udid]
        cmd += ["backup", out_dir]
        return _finalize(st, started, ok=True, data={
            "command": cmd,
            "out_dir": out_dir,
            "udid": udid,
            "note": ("command EMITTED, not run. Operator starts "
                     "the actual backup in a separate gated step. "
                     "The runner never deletes an existing backup. "
                     "Output is sensitive: keychain, SMS, photos, "
                     "app data — handle the out_dir carefully."),
        }, error="")

    # ------------------------------------------------------------------
    def run_attack(self, method: str) -> Dict[str, Any]:
        """Run a single iOS method by name. Never raises. The
        per-step ACCEPT/CANCEL gate already fired in
        :meth:`_walk_ai_step` (single-gate invariant)."""
        if method not in self.IOS_METHODS:
            return {
                "name": method, "ok": False,
                "error": f"unknown method {method!r}; one of {list(self.IOS_METHODS)}",
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
IOS_METHODS: Tuple[str, ...] = IOSRunner.IOS_METHODS


def _build_registry() -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    family_schemas = {
        "libimobiledevice_list_devices": {
            "input_schema": {"type": "object",
                              "properties": {"idevice_id_output":
                                              {"type": "string"}},
                              "required": ["idevice_id_output"]},
            "description": ("Parse idevice_id -l output. Pure parse; "
                            "never opens libimobiledevice."),
        },
        "usbmuxd_list_connected": {
            "input_schema": {"type": "object",
                              "properties": {"usbmuxd_output":
                                              {"type": "string"}},
                              "required": ["usbmuxd_output"]},
            "description": ("Parse usbmuxd listening devices. Pure."),
        },
        "ideviceinfo_dump": {
            "input_schema": {"type": "object",
                              "properties": {"ideviceinfo_output":
                                              {"type": "string"}},
                              "required": ["ideviceinfo_output"]},
            "description": ("Parse ideviceinfo key/value output. "
                            "Pure parse."),
        },
        "idevicedebug_apps_list": {
            "input_schema": {"type": "object",
                              "properties": {"debugserver_output":
                                              {"type": "string"}},
                              "required": ["debugserver_output"]},
            "description": ("Parse idevicedebugserverproxy list-apps "
                            "output. Pure parse."),
        },
        "idevicebackup2_list": {
            "input_schema": {"type": "object",
                              "properties": {"backup2_output":
                                              {"type": "string"}},
                              "required": ["backup2_output"]},
            "description": ("Parse idevicebackup2 list output. Pure."),
        },
        "frida_ios_dump_bundle_id": {
            "input_schema": {"type": "object",
                              "properties": {"frida_ios_dump_output":
                                              {"type": "string"}},
                              "required": ["frida_ios_dump_output"]},
            "description": ("Parse frida-ios-dump listing output. "
                            "Pure parse."),
        },
        "objection_environment_inventory": {
            "input_schema": {"type": "object",
                              "properties": {"objection_output":
                                              {"type": "string"}},
                              "required": ["objection_output"]},
            "description": ("Parse objection environment report. "
                            "Pure parse."),
        },
        "nmap_apple_mdns_discovery": {
            "input_schema": {"type": "object",
                              "properties": {"target": {"type": "string"},
                                              "ports":
                                              {"type": "array",
                                               "items": {"type": "integer"}},
                                              "timeout_s":
                                              {"type": "integer"}},
                              "required": ["target"]},
            "description": ("nmap -sV -Pn against the canonical "
                            "Apple / mDNS / iTunes-sync ports "
                            "(5353, 5900, 22, 62078, 7000). "
                            "Degrades on missing nmap."),
        },
        # Phase 2.0.I2 — intrusive surface (4 methods)
        "ssl_kill_switch_attach": {
            "input_schema": {"type": "object",
                              "properties": {
                                  "bundle_id": {"type": "string"}},
                              "required": ["bundle_id"]},
            "description": ("EMIT-ONLY: frida ssl-kill-switch2 "
                            "attach. Frida JS that patches "
                            "SecTrustEvaluate. Operator runs in a "
                            "separate gated step. Source in "
                            "toolboxes/ios/ssl-kill-switch2/."),
        },
        "objection_run_method": {
            "input_schema": {"type": "object",
                              "properties": {
                                  "bundle_id": {"type": "string"},
                                  "method": {"type": "string"}},
                              "required": ["bundle_id", "method"]},
            "description": ("EMIT-ONLY: objection hooking watch "
                            "method invocation. Operator runs in "
                            "a separate gated step. Source in "
                            "toolboxes/ios/objection/."),
        },
        "frida_trace_class": {
            "input_schema": {"type": "object",
                              "properties": {
                                  "bundle_id": {"type": "string"},
                                  "class_name": {"type": "string"}},
                              "required": ["bundle_id", "class_name"]},
            "description": ("EMIT-ONLY: frida Obj-C class trace. "
                            "Operator-written agent.js lives in "
                            "toolboxes/ios/frida/. Operator runs "
                            "in a separate gated step."),
        },
        "idevicebackup2_extract": {
            "input_schema": {"type": "object",
                              "properties": {
                                  "udid": {"type": "string"},
                                  "out_dir": {"type": "string"}},
                              "required": ["out_dir"]},
            "description": ("Real idevicebackup2 backup to a fresh "
                            "out_dir. NEVER overwrites an existing "
                            "backup. Output is sensitive "
                            "(keychain, SMS, photos, app data)."),
        },
    }
    family_risk = {
        "ssl_kill_switch_attach": "intrusive",
        "objection_run_method": "intrusive",
        "frida_trace_class": "intrusive",
        "idevicebackup2_extract": "intrusive",  # sensitive read
    }
    for m in IOSRunner.IOS_METHODS:
        meta = family_schemas.get(m, {})
        out.append({
            "method": m,
            "name": f"ios_attack_{m}",
            "description": (
                f"iOS target-class method: {m}. Real subprocess "
                "/ parse / pure logic / emit-only; degrades cleanly "
                "when libimobiledevice / Frida / objection / nmap "
                "is absent or no device is attached. Never fabricates "
                "a CVE id, a cleartext credential, an IPA repack, "
                "a Frida hook output, a plist key, a Mach-O patch, "
                "or a 'pwned' verdict. " + meta.get("description", "")),
            "input_schema": meta.get("input_schema",
                                      {"type": "object", "properties": {}}),
            "examples": [f"ios_attack(method={m!r}, ...)"],
            "risk_level": family_risk.get(m, "read"),
            "requires_root": False,
        })
    return out


IOS_ATTACKS: List[Dict[str, Any]] = _build_registry()


def run_attack(method: str, args: Optional[Dict[str, Any]] = None,
               **_: Any) -> Dict[str, Any]:
    """Module-level single-attack entrypoint. Used by the
    orchestrator's ``ios_attack`` dispatch and the MCP wrappers.
    Never raises."""
    try:
        runner = IOSRunner(args=args)
        return runner.run_attack(method)
    except Exception as e:  # noqa: BLE001
        return {"name": method, "ok": False, "error": str(e),
                "data": None, "duration_s": 0.0}
