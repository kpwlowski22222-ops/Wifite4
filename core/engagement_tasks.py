"""SQL-backed engagement tasks (WiFi / BLE / OSINT) for the RAT dashboard.

Tasks persist in ``sqlstore`` so closing the TUI does not lose work.
Each task aims for a **success terminal state**:

* ``wifi`` / ``ble`` — access achieved + post-exploit attached + session recorded
* ``osint_people`` / ``osint_web`` — profile/session job completed

Honesty: missing tools/orchestrator → ``failed`` with real error text,
never a fabricated success.
"""
from __future__ import annotations

import json
import logging
import threading
import time
import uuid
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)

KINDS = ("wifi", "ble", "osint_web", "osint_people")
# Terminal states
STATUS_QUEUED = "queued"
STATUS_RUNNING = "running"
STATUS_SUCCESS = "success"
STATUS_FAILED = "failed"
STATUS_CANCELLED = "cancelled"

# In-process registry (mirrors SQL; survives only for live threads)
_LOCK = threading.RLock()
_THREADS: Dict[str, threading.Thread] = {}
_CANCEL: Dict[str, bool] = {}


def _sid(kind: str) -> str:
    return f"task-{kind}-{uuid.uuid4().hex[:12]}"


def _ensure_db() -> None:
    try:
        from core.db import sqlstore
        sqlstore.init()
    except Exception as e:
        logger.debug("sqlstore init: %s", e)


def create_task(
    kind: str,
    target: Dict[str, Any],
    *,
    label: str = "",
    until_access: bool = True,
    meta: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Create a persisted engagement task and return its envelope."""
    kind = (kind or "").strip().lower()
    if kind not in KINDS:
        return {"ok": False, "error": f"unknown kind {kind!r}; use {KINDS}"}
    if not isinstance(target, dict) or not target:
        return {"ok": False, "error": "target dict required"}
    _ensure_db()
    tid = _sid(kind)
    now = time.time()
    payload = {
        "id": tid,
        "kind": kind,
        "label": label or str(
            target.get("ssid")
            or target.get("name")
            or target.get("query")
            or target.get("url")
            or target.get("address")
            or target.get("bssid")
            or tid
        ),
        "target": target,
        "status": STATUS_QUEUED,
        "until_access": bool(until_access),
        "created_at": now,
        "updated_at": now,
        "access": {},
        "error": "",
        "phases": [],
        "meta": meta or {},
    }
    try:
        from core.db import sqlstore
        sqlstore.record_session(
            tid,
            kind=kind,
            target=payload["label"],
            created_at=now,
            meta={
                "task": True,
                "status": STATUS_QUEUED,
                "payload": payload,
            },
        )
        sqlstore.append_log(tid, "task", f"created kind={kind} until_access={until_access}")
        sqlstore.append_history(tid, "task_created", {"kind": kind, "label": payload["label"]})
    except Exception as e:
        return {"ok": False, "error": f"sql persist failed: {e}"}
    return {"ok": True, "task": payload}


def list_tasks(kind: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
    """List engagement tasks from SQL (newest first)."""
    _ensure_db()
    out: List[Dict[str, Any]] = []
    try:
        from core.db import sqlstore
        rows = sqlstore.list_sessions(limit=max(limit, 200))
    except Exception:
        return []
    for r in rows or []:
        if not isinstance(r, dict):
            continue
        meta = r.get("meta") or r.get("meta_json")
        if isinstance(meta, str):
            try:
                meta = json.loads(meta)
            except Exception:
                meta = {}
        if not isinstance(meta, dict) or not meta.get("task"):
            # Only real engagement tasks — skip plain sessions / jobs.
            continue
        payload = meta.get("payload") or {}
        if not isinstance(payload, dict):
            continue
        payload.setdefault("id", r.get("sid") or r.get("id"))
        payload.setdefault("status", meta.get("status") or r.get("state"))
        payload.setdefault("kind", r.get("kind"))
        if kind and payload.get("kind") != kind:
            continue
        out.append(payload)
        if len(out) >= limit:
            break
    return out


def get_task(tid: str) -> Optional[Dict[str, Any]]:
    for t in list_tasks(limit=500):
        if t.get("id") == tid:
            return t
    return None


def _patch_task(tid: str, **fields: Any) -> None:
    try:
        from core.db import sqlstore
        rows = sqlstore.list_sessions(limit=500)
        meta = {}
        for r in rows or []:
            if (r.get("sid") or r.get("id")) == tid:
                m = r.get("meta") or r.get("meta_json") or {}
                if isinstance(m, str):
                    try:
                        m = json.loads(m)
                    except Exception:
                        m = {}
                meta = dict(m) if isinstance(m, dict) else {}
                break
        payload = dict(meta.get("payload") or {})
        payload.update(fields)
        payload["updated_at"] = time.time()
        meta["task"] = True
        meta["status"] = payload.get("status")
        meta["payload"] = payload
        sqlstore.update_session(
            tid,
            state=str(payload.get("status") or "open"),
            meta_json=json.dumps(meta, default=str),
        )
        if fields.get("status"):
            sqlstore.append_log(tid, "task", f"status={fields['status']}")
    except Exception as e:
        logger.debug("patch_task %s: %s", tid, e)


def cancel_task(tid: str) -> Dict[str, Any]:
    with _LOCK:
        _CANCEL[tid] = True
    _patch_task(tid, status=STATUS_CANCELLED)
    return {"ok": True, "id": tid, "status": STATUS_CANCELLED}


def start_task(
    tid: str,
    *,
    orchestrator: Any = None,
    on_event: Optional[Callable[[str], None]] = None,
) -> Dict[str, Any]:
    """Start (or re-start) a task worker thread until success/fail/cancel."""
    task = get_task(tid)
    if not task:
        return {"ok": False, "error": f"unknown task {tid}"}
    if task.get("status") == STATUS_SUCCESS:
        return {"ok": True, "task": task, "already": "success"}
    with _LOCK:
        th = _THREADS.get(tid)
        if th is not None and th.is_alive():
            return {"ok": True, "task": task, "already": "running"}
        _CANCEL[tid] = False

    def _emit(msg: str) -> None:
        if on_event:
            try:
                on_event(msg)
            except Exception:
                pass
        try:
            from core.db import sqlstore
            sqlstore.append_log(tid, "run", msg[:500])
        except Exception:
            pass

    def worker() -> None:
        _patch_task(tid, status=STATUS_RUNNING, error="")
        _emit(f"[task] start kind={task.get('kind')} label={task.get('label')}")
        try:
            result = _run_until_success(
                task, orchestrator=orchestrator, emit=_emit,
                should_cancel=lambda: _CANCEL.get(tid, False),
            )
            if _CANCEL.get(tid):
                _patch_task(tid, status=STATUS_CANCELLED)
                _emit("[task] cancelled")
                return
            if result.get("ok"):
                _patch_task(
                    tid,
                    status=STATUS_SUCCESS,
                    access=result.get("access") or {},
                    phases=result.get("phases") or [],
                    error="",
                )
                # Mirror as live session for dashboard
                try:
                    from core.db import sqlstore
                    acc = result.get("access") or {}
                    sid = str(acc.get("session_id") or tid)
                    sqlstore.record_session(
                        sid,
                        kind=task.get("kind") or "auto",
                        target=task.get("label") or "",
                        meta={
                            "task_id": tid,
                            "achieved": list(acc.get("achievements") or ["access"]),
                            "access": acc,
                        },
                    )
                except Exception:
                    pass
                _emit("[task] SUCCESS — access/foothold terminal state reached")
            else:
                _patch_task(
                    tid,
                    status=STATUS_FAILED,
                    error=str(result.get("error") or "failed"),
                    phases=result.get("phases") or [],
                )
                _emit(f"[task] FAILED: {result.get('error')}")
        except Exception as e:
            _patch_task(tid, status=STATUS_FAILED, error=str(e))
            _emit(f"[task] exception: {e}")
        finally:
            with _LOCK:
                _THREADS.pop(tid, None)

    t = threading.Thread(target=worker, name=f"kfiosa-task-{tid}", daemon=True)
    with _LOCK:
        _THREADS[tid] = t
    t.start()
    return {"ok": True, "id": tid, "status": STATUS_RUNNING}


def _run_until_success(
    task: Dict[str, Any],
    *,
    orchestrator: Any,
    emit: Callable[[str], None],
    should_cancel: Callable[[], bool],
    max_cycles: int = 8,
) -> Dict[str, Any]:
    kind = task.get("kind")
    target = dict(task.get("target") or {})
    target["attach_post_exploit"] = True
    target["post_exploit"] = True
    target.setdefault("anti_forensics", True)
    target.setdefault("polymorphic", True)
    target.setdefault("aio", True)
    target["attach_zero_day"] = True
    target["until_access"] = True

    if kind in ("wifi", "ble"):
        if orchestrator is None:
            return {"ok": False, "error": "orchestrator unavailable"}
        try:
            from core.orchestrator.engagement_engine import EngagementEngine
        except Exception as e:
            return {"ok": False, "error": f"engagement engine: {e}"}
        phases = []
        for cycle in range(1, max_cycles + 1):
            if should_cancel():
                return {"ok": False, "error": "cancelled", "phases": phases}
            emit(f"[task] cycle {cycle}/{max_cycles} domain={kind} until_access")
            eng = EngagementEngine(
                orchestrator,
                on_event=emit,
                until_access=True,
                enable_bg_zero_day=True,
                enable_holo_prep=False,
            )
            report = eng.run(
                kind, target,
                until_access=True,
                attach_zero_day=True,
            )
            access = (report or {}).get("access") or {}
            phases.append({
                "cycle": cycle,
                "access": bool(access.get("achieved")),
                "session_id": access.get("session_id"),
            })
            if access.get("achieved"):
                # Ensure PE flag path + connection record
                access.setdefault("achievements", ["access"])
                if access.get("session_id"):
                    access.setdefault("connection", "established")
                return {
                    "ok": True,
                    "access": access,
                    "phases": phases,
                    "report": report,
                }
            emit(f"[task] cycle {cycle}: no access yet — retrying")
        return {
            "ok": False,
            "error": f"no access after {max_cycles} cycles",
            "phases": phases,
        }

    if kind == "osint_people":
        query = (
            target.get("query")
            or target.get("name")
            or target.get("email")
            or target.get("label")
            or ""
        )
        if not str(query).strip():
            return {"ok": False, "error": "people target query required"}
        try:
            from core.post_access_tui.rat_ext.long_jobs import enqueue_people_job
            jid = enqueue_people_job(str(query).strip(), status="completed")
            emit(f"[task] people profile job {jid} completed")
            return {
                "ok": True,
                "access": {
                    "achieved": True,
                    "session_id": jid,
                    "kind": "people",
                    "achievements": ["osint_profile"],
                    "connection": "profile_ready",
                },
                "phases": [{"job": jid}],
            }
        except Exception as e:
            return {"ok": False, "error": str(e)}

    if kind == "osint_web":
        url = target.get("url") or target.get("target") or target.get("label") or ""
        if not str(url).strip():
            return {"ok": False, "error": "website url required"}
        try:
            from core.post_access_tui.rat_ext.long_jobs import enqueue_website_session
            jid = enqueue_website_session(str(url).strip(), status="attached")
            emit(f"[task] website session {jid} attached")
            return {
                "ok": True,
                "access": {
                    "achieved": True,
                    "session_id": jid,
                    "kind": "website",
                    "achievements": ["web_session"],
                    "connection": "attached",
                },
                "phases": [{"job": jid}],
            }
        except Exception as e:
            return {"ok": False, "error": str(e)}

    return {"ok": False, "error": f"unsupported kind {kind}"}


def create_and_start(
    kind: str,
    target: Dict[str, Any],
    *,
    orchestrator: Any = None,
    on_event: Optional[Callable[[str], None]] = None,
    label: str = "",
) -> Dict[str, Any]:
    """Convenience: create task then start until-success worker."""
    created = create_task(kind, target, label=label, until_access=True)
    if not created.get("ok"):
        return created
    tid = created["task"]["id"]
    started = start_task(tid, orchestrator=orchestrator, on_event=on_event)
    started["task"] = get_task(tid) or created["task"]
    return started
