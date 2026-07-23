"""Attach CVEs + coded PoCs to engagement targets and persist to SQL history.

Flow::

  1. Lookup CVEs (NVD / recon pool)
  2. Score / rank against live target features
  3. Attach top CVEs onto the target seed (``seed['attached_cves']``)
  4. Code PoC once via cve_to_exploit (target-conditioned prompt)
  5. Persist ``cve_id`` (and coded flag) into SQLite ``history`` for the
     session / target key — so re-runs reuse the attachment

Never fabricates CVEs, CVSS, or exploit success. SQL writes are best-effort
and redacted by the store.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence


CVE_ID_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)


def target_key(target: Optional[Dict[str, Any]] = None) -> str:
    """Stable short key for a target (bssid / addr / url / query)."""
    t = target if isinstance(target, dict) else {}
    for k in (
        "bssid", "address", "addr", "mac", "url", "query",
        "ssid", "name", "host", "ip",
    ):
        v = t.get(k)
        if v:
            return str(v).strip().upper()[:80]
    raw = json.dumps(t, sort_keys=True, default=str)[:200]
    return "tgt-" + hashlib.sha1(raw.encode("utf-8")).hexdigest()[:12]


def session_id_for(target: Optional[Dict[str, Any]] = None, *, sid: str = "") -> str:
    """Session id for SQL history — prefer explicit sid / workspace."""
    if sid:
        return str(sid)[:80]
    t = target if isinstance(target, dict) else {}
    for k in ("session_id", "workspace_id", "sid", "engagement_id"):
        if t.get(k):
            return str(t[k])[:80]
    return "tgt:" + target_key(t)


def normalize_cve_id(raw: Any) -> str:
    s = str(raw or "").strip().upper()
    if not s:
        return ""
    m = CVE_ID_RE.search(s)
    return m.group(0).upper() if m else s


def _target_tokens(target: Dict[str, Any]) -> List[str]:
    toks: List[str] = []
    for k in (
        "vendor", "manufacturer", "chipset", "model", "device_name",
        "ssid", "name", "encryption", "enc", "os", "host_os",
        "product", "firmware", "service",
    ):
        v = target.get(k)
        if v:
            toks.append(str(v).lower())
    recon = target.get("recon") if isinstance(target.get("recon"), dict) else {}
    for sec in recon.values():
        if not isinstance(sec, dict):
            continue
        data = sec.get("data") if isinstance(sec.get("data"), dict) else sec
        for key in ("vendor", "chipset", "model", "device_name", "manufacturer"):
            v = data.get(key) if isinstance(data, dict) else None
            if v:
                toks.append(str(v).lower())
    # domain hints
    domain = str(target.get("domain") or "").lower()
    if domain in ("wifi", "wlan"):
        toks.extend(["wifi", "802.11", "wpa", "wireless"])
    elif domain == "ble":
        toks.extend(["bluetooth", "ble", "gatt"])
    return [t for t in toks if t and t not in ("unknown", "none", "n/a", "?")]


def score_cve_for_target(cve: Dict[str, Any], target: Dict[str, Any]) -> float:
    """Heuristic relevance of a CVE record to this target (0..100)."""
    if not isinstance(cve, dict):
        return 0.0
    score = 0.0
    cid = normalize_cve_id(cve.get("id") or cve.get("cve_id") or "")
    if not cid:
        return 0.0
    desc = str(cve.get("description") or cve.get("summary") or "").lower()
    blob = desc + " " + json.dumps(cve.get("affected") or [], default=str).lower()
    tokens = _target_tokens(target)
    hits = 0
    for tok in tokens:
        if len(tok) < 3:
            continue
        if tok in blob:
            hits += 1
            score += 12
    if hits:
        score += min(20.0, hits * 3)
    # CVSS boost
    try:
        cvss = float(cve.get("cvss") or cve.get("cvss_score") or cve.get("baseScore") or 0)
        score += min(25.0, cvss * 2.5)
    except (TypeError, ValueError):
        pass
    # Domain keyword boost
    domain = str(target.get("domain") or "").lower()
    if domain in ("wifi", "wlan") and any(
        k in blob for k in ("wifi", "802.11", "wpa", "wireless", "router", "access point")
    ):
        score += 15
    if domain == "ble" and any(
        k in blob for k in ("bluetooth", "ble", "gatt", "bluez")
    ):
        score += 15
    # Prefer has-PoC / refs
    refs = cve.get("refs") or cve.get("references") or []
    if refs:
        score += min(10.0, len(refs) * 2)
    if cve.get("exploit_code") or cve.get("poc") or cve.get("coded"):
        score += 20
    return min(100.0, score)


def rank_cves_for_target(
    cves: Sequence[Dict[str, Any]],
    target: Dict[str, Any],
    *,
    top_n: int = 8,
) -> List[Dict[str, Any]]:
    """Return CVEs scored and sorted for this target."""
    out: List[Dict[str, Any]] = []
    seen = set()
    for raw in cves or []:
        if not isinstance(raw, dict):
            continue
        c = dict(raw)
        cid = normalize_cve_id(c.get("id") or c.get("cve_id"))
        if not cid or cid in seen:
            continue
        seen.add(cid)
        c["id"] = cid
        c["_score"] = score_cve_for_target(c, target)
        out.append(c)
    out.sort(key=lambda x: float(x.get("_score") or 0), reverse=True)
    return out[: max(1, int(top_n))]


def _persist_history(
    sid: str,
    action: str,
    payload: Dict[str, Any],
) -> Dict[str, Any]:
    """Best-effort SQL history write (never raises)."""
    try:
        from core.db import sqlstore
        sqlstore.init()
        # Ensure session row exists so history is queryable by sid
        try:
            sqlstore.record_session(
                sid,
                kind=str(payload.get("domain") or payload.get("kind") or "cve"),
                target=str(payload.get("target_key") or payload.get("target") or sid),
                meta={"cve_attach": True},
            )
        except Exception:
            pass
        return sqlstore.append_history(sid, action, payload)
    except Exception as e:
        return {"ok": False, "error": str(e)[:160]}


def attach_cves_to_target(
    target: Dict[str, Any],
    cves: Sequence[Dict[str, Any]],
    *,
    sid: str = "",
    top_n: int = 5,
    domain: str = "",
) -> Dict[str, Any]:
    """Rank CVEs, attach to target seed, persist each CVE id to SQL history.

    Idempotent for the same (sid, cve_id): re-attach updates score/meta
    but history lines remain append-only (audit trail).
    """
    t = dict(target or {})
    if domain:
        t.setdefault("domain", domain)
    ranked = rank_cves_for_target(cves, t, top_n=top_n)
    tkey = target_key(t)
    sess = session_id_for(t, sid=sid)
    attached: List[Dict[str, Any]] = list(t.get("attached_cves") or [])
    by_id = {
        normalize_cve_id(a.get("cve_id") or a.get("id")): a
        for a in attached if isinstance(a, dict)
    }
    new_ids: List[str] = []
    for c in ranked:
        cid = normalize_cve_id(c.get("id"))
        if not cid:
            continue
        rec = {
            "cve_id": cid,
            "id": cid,
            "score": c.get("_score"),
            "cvss": c.get("cvss") or c.get("cvss_score"),
            "description": (c.get("description") or c.get("summary") or "")[:300],
            "attached_at": time.time(),
            "target_key": tkey,
            "coded": bool(by_id.get(cid, {}).get("coded") or c.get("coded")),
            "exploit_path": by_id.get(cid, {}).get("exploit_path") or c.get("exploit_path") or "",
            "poc_bytes": by_id.get(cid, {}).get("poc_bytes") or 0,
        }
        # Preserve prior coded PoC
        if by_id.get(cid, {}).get("exploit_code"):
            rec["exploit_code"] = by_id[cid]["exploit_code"]
            rec["coded"] = True
        by_id[cid] = rec
        new_ids.append(cid)
        _persist_history(sess, "cve_attached", {
            "cve_id": cid,
            "target_key": tkey,
            "score": rec.get("score"),
            "cvss": rec.get("cvss"),
            "domain": t.get("domain") or domain,
            "bssid": t.get("bssid"),
            "address": t.get("address") or t.get("addr"),
            "ssid": t.get("ssid") or t.get("name"),
        })

    attached_list = sorted(
        by_id.values(),
        key=lambda x: float(x.get("score") or 0),
        reverse=True,
    )
    t["attached_cves"] = attached_list
    t["cves"] = ranked  # keep scored pool
    t["cve_target_key"] = tkey
    t["cve_session_id"] = sess
    # Memory note (optional)
    try:
        from core.memory.store import ingest
        if new_ids:
            ingest(
                "cve_attach",
                f"attached {len(new_ids)} CVEs to {tkey}: {', '.join(new_ids[:5])}",
                domain=str(t.get("domain") or ""),
                target_key=tkey,
                tags=["cve"] + new_ids[:8],
            )
    except Exception:
        pass
    return {
        "ok": True,
        "target_key": tkey,
        "session_id": sess,
        "attached": attached_list,
        "count": len(attached_list),
        "cve_ids": [a["cve_id"] for a in attached_list],
        "target": t,
    }


def mark_cve_coded(
    target: Dict[str, Any],
    cve_id: str,
    *,
    exploit_code: str = "",
    model_used: str = "",
    ok: bool = True,
    error: str = "",
    sid: str = "",
    exploit_path: str = "",
) -> Dict[str, Any]:
    """Mark a CVE as coded for this target (one-time) and store in SQL history."""
    t = dict(target or {})
    cid = normalize_cve_id(cve_id)
    if not cid:
        return {"ok": False, "error": "cve_id required"}
    tkey = target_key(t)
    sess = session_id_for(t, sid=sid or str(t.get("cve_session_id") or ""))
    attached = list(t.get("attached_cves") or [])
    found = False
    for a in attached:
        if not isinstance(a, dict):
            continue
        if normalize_cve_id(a.get("cve_id") or a.get("id")) == cid:
            a["coded"] = bool(ok and (exploit_code or a.get("exploit_code")))
            a["coded_at"] = time.time()
            if exploit_code:
                # Keep full code on seed; SQL stores meta only (size)
                a["exploit_code"] = exploit_code
                a["poc_bytes"] = len(exploit_code)
            if model_used:
                a["model_used"] = model_used
            if exploit_path:
                a["exploit_path"] = exploit_path
            if error:
                a["code_error"] = error[:200]
            found = True
            break
    if not found:
        attached.append({
            "cve_id": cid,
            "id": cid,
            "coded": bool(ok and exploit_code),
            "coded_at": time.time(),
            "exploit_code": exploit_code or "",
            "poc_bytes": len(exploit_code or ""),
            "model_used": model_used,
            "exploit_path": exploit_path,
            "target_key": tkey,
            "score": 0,
        })
    t["attached_cves"] = attached
    # Also index under exploits for chain planner
    if ok and exploit_code:
        t.setdefault("exploits", []).append({
            "cve_id": cid,
            "ok": True,
            "exploit_code": exploit_code,
            "model_used": model_used,
            "target_key": tkey,
            "attached": True,
        })
        # Optional on-disk PoC for operator review
        if not exploit_path:
            try:
                root = Path(
                    os.environ.get("KFIOSA_CVE_POC_ROOT")
                    or Path(__file__).resolve().parents[1] / "data" / "cve_pocs"
                )
                root.mkdir(parents=True, exist_ok=True)
                safe = cid.replace("/", "_")
                path = root / f"{safe}_{tkey.replace(':', '')[:16]}.py"
                path.write_text(exploit_code, encoding="utf-8")
                exploit_path = str(path)
                for a in attached:
                    if normalize_cve_id(a.get("cve_id")) == cid:
                        a["exploit_path"] = exploit_path
            except Exception:
                pass

    hist = _persist_history(sess, "cve_coded", {
        "cve_id": cid,
        "target_key": tkey,
        "ok": bool(ok),
        "poc_bytes": len(exploit_code or ""),
        "model_used": model_used or "",
        "exploit_path": exploit_path or "",
        "error": (error or "")[:160],
        "domain": t.get("domain") or "",
        "bssid": t.get("bssid"),
        "address": t.get("address") or t.get("addr"),
    })
    return {
        "ok": True,
        "cve_id": cid,
        "coded": bool(ok and exploit_code),
        "target_key": tkey,
        "session_id": sess,
        "exploit_path": exploit_path,
        "history": hist,
        "target": t,
    }


def already_coded(target: Dict[str, Any], cve_id: str) -> Optional[Dict[str, Any]]:
    """Return attachment record if this CVE already has a PoC for the target."""
    cid = normalize_cve_id(cve_id)
    for a in (target.get("attached_cves") or []):
        if not isinstance(a, dict):
            continue
        if normalize_cve_id(a.get("cve_id") or a.get("id")) != cid:
            continue
        if a.get("coded") and (a.get("exploit_code") or a.get("exploit_path")):
            return a
    return None


def list_history_cve_ids(sid: str, *, limit: int = 100) -> List[str]:
    """CVE ids previously attached/coded for a session (from SQL history)."""
    try:
        from core.db import sqlstore
        sqlstore.init()
        rows = sqlstore.list_history(sid, limit=limit) or []
    except Exception:
        return []
    ids: List[str] = []
    seen = set()
    for row in rows:
        if not isinstance(row, dict):
            continue
        action = str(row.get("action") or "")
        if action not in ("cve_attached", "cve_coded"):
            continue
        payload = row.get("payload") or row.get("payload_json") or {}
        if isinstance(payload, str):
            try:
                payload = json.loads(payload)
            except Exception:
                payload = {}
        cid = normalize_cve_id(
            (payload or {}).get("cve_id") if isinstance(payload, dict) else ""
        )
        if cid and cid not in seen:
            seen.add(cid)
            ids.append(cid)
    return ids


def target_context_for_prompt(target: Dict[str, Any]) -> str:
    """Compact target description for coding the exploit *to* this target."""
    t = target or {}
    parts = []
    for k, label in (
        ("domain", "domain"),
        ("bssid", "bssid"),
        ("ssid", "ssid"),
        ("address", "ble_addr"),
        ("addr", "ble_addr"),
        ("channel", "channel"),
        ("encryption", "enc"),
        ("enc", "enc"),
        ("vendor", "vendor"),
        ("chipset", "chipset"),
        ("interface", "iface"),
        ("os", "os"),
        ("host_os", "os"),
    ):
        if t.get(k) not in (None, "", [], {}):
            parts.append(f"{label}={t.get(k)}")
    return "; ".join(parts[:14]) or "generic lab target"
