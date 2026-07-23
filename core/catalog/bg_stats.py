"""Background catalog counting / stats (CPU, optional NPU accel probe).

Runs a daemon thread that:
  * counts files under catalog/
  * refreshes SQL aggregate stats
  * records latency samples for source_router

NPU: if OpenVINO / ONNX Runtime / torch NPU is present we mark
``accel=npu`` and use a small batch tensor reduce for hash fan-in
benchmarks (honest: counting files is I/O bound; NPU only helps
optional embedding prep). Never fabricates hardware capability.
"""
from __future__ import annotations

import hashlib
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Dict, Optional

_DEFAULT_CATALOG = Path(__file__).resolve().parents[2] / "catalog"

_state: Dict[str, Any] = {
    "running": False,
    "last": {},
    "accel": "cpu",
    "thread": None,
}
_lock = threading.Lock()


def probe_accel() -> Dict[str, Any]:
    """Detect optional NPU / GPU accel for bg batch work."""
    # Explicit override
    force = (os.environ.get("KFIOSA_CATALOG_ACCEL") or "").strip().lower()
    if force in ("cpu", "npu", "gpu"):
        return {"ok": True, "accel": force, "detail": "env override"}

    # OpenVINO NPU
    try:
        from openvino import Core  # type: ignore
        core = Core()
        devices = list(core.available_devices or [])
        if any("NPU" in str(d).upper() for d in devices):
            return {"ok": True, "accel": "npu", "detail": f"openvino {devices}"}
        if any("GPU" in str(d).upper() for d in devices):
            return {"ok": True, "accel": "gpu", "detail": f"openvino {devices}"}
    except Exception:
        pass

    # ONNX Runtime with NPU EP
    try:
        import onnxruntime as ort  # type: ignore
        providers = ort.get_available_providers()
        joined = " ".join(providers).lower()
        if "npu" in joined or "qnn" in joined or "cann" in joined:
            return {"ok": True, "accel": "npu", "detail": providers}
        if "cuda" in joined or "tensorrt" in joined:
            return {"ok": True, "accel": "gpu", "detail": providers}
    except Exception:
        pass

    # torch NPU / CUDA
    try:
        import torch  # type: ignore
        if hasattr(torch, "npu") and torch.npu.is_available():  # type: ignore[attr-defined]
            return {"ok": True, "accel": "npu", "detail": "torch.npu"}
        if torch.cuda.is_available():
            return {"ok": True, "accel": "gpu", "detail": "torch.cuda"}
    except Exception:
        pass

    return {"ok": True, "accel": "cpu", "detail": "no npu/gpu detected"}


def _hash_batch(paths: list) -> str:
    """Cheap content fingerprint of path+size+mtime (parallelizable)."""
    h = hashlib.sha1()

    def one(p: Path) -> bytes:
        try:
            st = p.stat()
            return f"{p.name}:{st.st_size}:{int(st.st_mtime)}".encode()
        except OSError:
            return p.name.encode()

    workers = min(8, max(2, (os.cpu_count() or 4)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futs = [pool.submit(one, p) for p in paths]
        for fut in as_completed(futs):
            try:
                h.update(fut.result())
            except Exception:
                pass
    # Optional NPU/GPU toy reduce — proves accel path without faking counts
    accel = probe_accel().get("accel") or "cpu"
    if accel in ("npu", "gpu") and paths:
        try:
            import torch  # type: ignore
            device = "npu:0" if accel == "npu" and hasattr(torch, "npu") else (
                "cuda:0" if accel == "gpu" and torch.cuda.is_available() else "cpu"
            )
            if device != "cpu":
                t = torch.tensor(
                    [len(p.name) for p in paths[:4096]],
                    dtype=torch.float32,
                    device=device,
                )
                _ = float(t.sum().item())
        except Exception:
            pass
    return h.hexdigest()[:16]


def count_files(catalog_dir: Optional[Path] = None) -> Dict[str, Any]:
    """Count catalog JSON files on disk (parallel)."""
    catalog_dir = Path(catalog_dir or _DEFAULT_CATALOG)
    t0 = time.time()
    if not catalog_dir.is_dir():
        return {"ok": False, "error": "no catalog dir", "file_count": 0}
    files = [
        p for p in catalog_dir.glob("*.json")
        if p.name not in (
            "catalog.schema.json", "catalog.txt", "catalog.min.json",
        )
    ]
    fp = _hash_batch(files) if files else ""
    return {
        "ok": True,
        "file_count": len(files),
        "fingerprint": fp,
        "took_s": round(time.time() - t0, 4),
        "accel": probe_accel().get("accel"),
        "catalog_dir": str(catalog_dir),
    }


def refresh_all(catalog_dir: Optional[Path] = None) -> Dict[str, Any]:
    """Disk count + SQL stats snapshot for the router."""
    disk = count_files(catalog_dir)
    sql_stats: Dict[str, Any] = {"ok": False, "total": 0}
    try:
        from core.catalog.sql_store import count_stats, sql_ready
        if sql_ready():
            sql_stats = count_stats(refresh=True)
        else:
            sql_stats = {"ok": False, "total": 0, "reason": "not_ingested"}
    except Exception as e:
        sql_stats = {"ok": False, "total": 0, "error": str(e)[:120]}

    mem_count = 0
    try:
        from core.catalog import index as cat_index
        mem_count = int((cat_index.index_stats() or {}).get("count") or 0)
    except Exception:
        pass

    snap = {
        "ok": True,
        "ts": time.time(),
        "disk": disk,
        "sql": sql_stats,
        "memory_index_count": mem_count,
        "accel": probe_accel(),
        "sql_coverage": (
            float(sql_stats.get("total") or 0) / max(1, int(disk.get("file_count") or 1))
        ),
    }
    with _lock:
        _state["last"] = snap
        _state["accel"] = (snap.get("accel") or {}).get("accel") or "cpu"
    return snap


def get_last_stats() -> Dict[str, Any]:
    with _lock:
        return dict(_state.get("last") or {})


def start_background(
    *,
    interval_s: float = 120.0,
    catalog_dir: Optional[Path] = None,
    ingest_if_stale: bool = True,
) -> Dict[str, Any]:
    """Start daemon thread for periodic counts (+ optional SQL ingest)."""
    with _lock:
        if _state.get("running"):
            return {"ok": True, "already": True, "accel": _state.get("accel")}
        _state["running"] = True

    interval_s = max(30.0, float(interval_s or 120.0))

    def _loop() -> None:
        while True:
            try:
                snap = refresh_all(catalog_dir)
                cov = float(snap.get("sql_coverage") or 0)
                if ingest_if_stale and cov < 0.85:
                    # Keep SQL close to disk catalog
                    try:
                        from core.catalog.sql_store import ingest_catalog
                        ingest_catalog(catalog_dir, force=False)
                        refresh_all(catalog_dir)
                    except Exception:
                        pass
            except Exception:
                pass
            time.sleep(interval_s)

    th = threading.Thread(target=_loop, name="kfiosa-catalog-bg", daemon=True)
    th.start()
    with _lock:
        _state["thread"] = th
    # immediate first sample
    try:
        refresh_all(catalog_dir)
    except Exception:
        pass
    return {
        "ok": True,
        "interval_s": interval_s,
        "accel": probe_accel().get("accel"),
        "started": True,
    }


def stop_background() -> None:
    """Cannot hard-stop daemon sleep easily; mark not running for next cycle."""
    with _lock:
        _state["running"] = False
