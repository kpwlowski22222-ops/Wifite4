#!/usr/bin/env python3
"""Generate catalog/*.json entries for the fetched recon repos from the
classification records produced by the classify-recon-repos workflow.

Input  : a JSON file containing a list of classification records (the
         ``records`` field of the workflow result), each with at least
         ``owner``, ``repo``, ``catalog_summary``, ``risk_level``,
         ``capability_bucket``, ``algorithms``, ``produces``,
         ``dependencies``, ``entrypoint``, ``runnable``.
Output : one ``catalog/github_<owner>_<repo>.json`` per record, matching
``catalog/catalog.schema.json`` (repository flavour). Existing files are
over-written only with ``--force``.

The recon repos are *catalogued* (so the AI knows they exist and where
they live under ``toolboxes/recon/``); the novel algorithms they inspire
are implemented directly in ``core/modules/catalog_recon.py`` — these JSON
entries are the knowledge-base pointer, not a wrapper.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CATALOG = ROOT / "catalog"

# capability_bucket -> catalog category label (human-readable).
CATEGORY = {
    "wps_probe": "WiFi Reconnaissance — WPS",
    "client_enum": "WiFi Reconnaissance — Client Enumeration",
    "pmkid": "WiFi Reconnaissance — PMKID",
    "handshake_harvest": "WiFi Reconnaissance — Handshake Harvest",
    "hidden_ssid": "WiFi Reconnaissance — Hidden SSID",
    "probe_profiling": "WiFi Reconnaissance — Probe Profiling",
    "signal_map": "WiFi Reconnaissance — Signal Mapping",
    "gps_wardrive": "WiFi Reconnaissance — GPS Wardrive",
    "eapol_monitor": "WiFi Reconnaissance — EAPOL Monitor",
    "channel_plan": "WiFi Reconnaissance — Channel Planning",
    "deauth_detect": "WiFi Reconnaissance — Deauth Detection",
    "beacon_parse": "WiFi Reconnaissance — Beacon Parsing",
    "oui_enrich": "WiFi Reconnaissance — OUI Enrichment",
    "eap_auth": "WiFi Reconnaissance — EAP/802.1x Auth",
    "phy_reconstruct": "WiFi Reconnaissance — PHY Reconstruction",
    "pineapple": "WiFi Reconnaissance — Rogue AP / Pineapple",
    "redundant_wrapper": "WiFi Reconnaissance — Aircrack Wrapper",
}


def _safe(s: str) -> str:
    """Filesystem-safe fragment for the catalog filename."""
    return re.sub(r"[^A-Za-z0-9._-]", "_", s or "")


def _signals(rec: dict) -> list:
    sigs = set()
    bucket = rec.get("capability_bucket") or "recon"
    sigs.add(bucket.replace("_", "-"))
    for a in rec.get("algorithms") or []:
        low = a.lower()
        if "deauth" in low:
            sigs.add("deauth")
        if "handshake" in low or "eapol" in low:
            sigs.add("handshake")
        if "pmkid" in low:
            sigs.add("pmkid")
        if "wps" in low:
            sigs.add("wps")
        if "gps" in low or "wardrive" in low:
            sigs.add("gps")
        if "probe" in low:
            sigs.add("probe")
        if "hidden" in low:
            sigs.add("hidden-ssid")
        if "sniff" in low or "beacon" in low:
            sigs.add("sniff")
    return sorted(sigs) or ["recon"]


def _risk(rec: dict) -> dict:
    level = rec.get("risk_level") or "medium"
    # Catalog risk schema fields.
    return {
        "level": level,
        "signals": _signals(rec),
        "requires_explicit_authorization": level in ("high",),
        "allow_autonomous_execution": level == "low",
        "examples_policy": "operational",
    }


def build_entry(rec: dict) -> dict:
    owner = rec.get("owner") or ""
    repo = rec.get("repo") or ""
    full = f"{owner}/{repo}"
    summary = (rec.get("catalog_summary") or rec.get("one_line") or "").strip()
    bucket = rec.get("capability_bucket") or "recon"
    entry = {
        "id": f"github:{full}",
        "kind": "external_repository",
        "name": repo,
        "full_name": full,
        "owner": owner,
        "category": CATEGORY.get(bucket, "WiFi Reconnaissance"),
        "url": rec.get("url") or f"https://github.com/{full}",
        "summary": summary or None,
        "toolbox_path": f"toolboxes/recon/{_safe(owner)}__{_safe(repo)}",
        "documentation": {
            "readme": None,
            "usage_sections": [
                {"section": "entrypoint", "content": rec.get("entrypoint") or ""}
            ] if rec.get("entrypoint") else [],
            "arguments": [],
            "examples": [
                {"status": "operational", "command": rec.get("entrypoint") or ""}
            ] if rec.get("entrypoint") else [],
        },
        "language": rec.get("language") or None,
        "dependencies": rec.get("dependencies") or [],
        "algorithms": rec.get("algorithms") or [],
        "produces": rec.get("produces") or [],
        "capability_bucket": bucket,
        "runnable": bool(rec.get("runnable", False)),
        "novelty": rec.get("novelty") or None,
        "metadata_status": "classified",
        "trust": {
            "official_kali": False,
            "reviewed": False,
            "warning": (
                "External community repo. Audit provenance, code, "
                "releases and licence before use. Catalogued for the "
                "AI's awareness; novel algorithms are implemented in "
                "core/modules/catalog_recon.py, not shelled out to this "
                "repo's binaries."
            ),
        },
        "risk": _risk(rec),
    }
    return entry


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("records_json", help="JSON file: list of records or "
                   "{\"records\": [...]} object")
    ap.add_argument("--force", action="store_true",
                    help="overwrite existing catalog files")
    args = ap.parse_args(argv)

    blob = json.loads(Path(args.records_json).read_text(encoding="utf-8"))
    if isinstance(blob, dict):
        records = blob.get("records") or []
    else:
        records = blob
    if not isinstance(records, list):
        print("records_json must be a list or {records: [...]}", file=sys.stderr)
        return 2

    CATALOG.mkdir(parents=True, exist_ok=True)
    written, skipped = 0, 0
    for rec in records:
        owner = rec.get("owner")
        repo = rec.get("repo")
        if not owner or not repo:
            continue
        fname = f"github_{_safe(owner)}_{_safe(repo)}.json"
        path = CATALOG / fname
        if path.exists() and not args.force:
            skipped += 1
            continue
        entry = build_entry(rec)
        path.write_text(json.dumps(entry, indent=2, ensure_ascii=False) + "\n",
                        encoding="utf-8")
        written += 1
    print(f"wrote {written} catalog entries, skipped {skipped} (exist)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())