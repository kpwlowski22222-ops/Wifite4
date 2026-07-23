"""Shared filesystem bus for triple BLE scan windows (single writer).

Layout under ``bus_dir``::

  state.json       online/offline/focus/updated_at
  selection.json   operator-selected device
  control.json     {quit: bool}

Only the online window writes scan state; detail + offline are readers.
"""
from __future__ import annotations

import json
import os
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional


def new_bus_dir(base: Optional[Path] = None) -> Path:
    root = Path(base or os.environ.get("KFIOSA_BLE_SCAN_BUS") or "/tmp/kfiosa_ble_scan")
    d = root / uuid.uuid4().hex[:12]
    d.mkdir(parents=True, exist_ok=True)
    write_json(d / "control.json", {"quit": False})
    write_json(
        d / "state.json",
        {
            "online": [],
            "offline": [],
            "focus_addr": None,
            "selected": None,
            "updated_at": time.time(),
            "adapter": None,
            "error": None,
        },
    )
    return d


def write_json(path: Path, data: Dict[str, Any]) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = json.dumps(data, ensure_ascii=False, default=str)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(raw)
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def read_json(path: Path) -> Dict[str, Any]:
    path = Path(path)
    if not path.is_file():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def update_state(bus_dir: Path, **fields: Any) -> Dict[str, Any]:
    """Merge fields into state.json under a short exclusive lock."""
    bus_dir = Path(bus_dir)
    lock_path = bus_dir / ".state.lock"
    st_path = bus_dir / "state.json"
    try:
        import fcntl
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        with open(lock_path, "a+", encoding="utf-8") as lf:
            fcntl.flock(lf.fileno(), fcntl.LOCK_EX)
            try:
                st = read_json(st_path)
                st.update(fields)
                st["updated_at"] = time.time()
                write_json(st_path, st)
                return st
            finally:
                fcntl.flock(lf.fileno(), fcntl.LOCK_UN)
    except Exception:
        st = read_json(st_path)
        st.update(fields)
        st["updated_at"] = time.time()
        write_json(st_path, st)
        return st


def set_selection(bus_dir: Path, dev: Dict[str, Any]) -> None:
    write_json(Path(bus_dir) / "selection.json", {
        "selected": dev,
        "selected_at": time.time(),
    })
    update_state(bus_dir, selected=dev.get("address") or dev.get("addr"))


def get_selection(bus_dir: Path) -> Optional[Dict[str, Any]]:
    data = read_json(Path(bus_dir) / "selection.json")
    sel = data.get("selected")
    return sel if isinstance(sel, dict) else None


def request_quit(bus_dir: Path) -> None:
    write_json(Path(bus_dir) / "control.json", {"quit": True})


def should_quit(bus_dir: Path) -> bool:
    return bool(read_json(Path(bus_dir) / "control.json").get("quit"))


def wait_for_selection(
    bus_dir: Path,
    *,
    timeout_s: float = 600.0,
    poll_s: float = 0.4,
) -> Optional[Dict[str, Any]]:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        sel = get_selection(bus_dir)
        if sel:
            return sel
        if should_quit(bus_dir):
            return get_selection(bus_dir)
        time.sleep(poll_s)
    return get_selection(bus_dir)


def launch_triple_ble_windows(
    adapter: Optional[str] = None,
    *,
    bus_dir: Optional[Path] = None,
    settings=None,
    font_scale: Optional[float] = None,
) -> Dict[str, Any]:
    """Spawn online (TL), detail (TR), offline (BR) BLE external windows."""
    from core.utils.external_terminal import (
        launch_placed, LOG_DIR, get_scan_font_scale,
    )
    if font_scale is None:
        font_scale = get_scan_font_scale(settings)

    bus = Path(bus_dir) if bus_dir else new_bus_dir()
    update_state(bus, adapter=adapter)
    py = os.environ.get("KFIOSA_PYTHON") or "python3"
    root = Path(__file__).resolve().parents[2]
    ad = adapter or ""

    def _cmd(mod: str) -> List[str]:
        parts = [
            "bash", "-c",
            f"cd {root} && {py} -m {mod} --bus {bus}"
            + (f" --adapter {ad}" if ad else ""),
        ]
        return parts

    logs = Path(LOG_DIR) / "scan"
    logs.mkdir(parents=True, exist_ok=True)
    pops = {}
    specs = (
        ("topleft", "core.tui.ble_scan_online", "KFIOSA: BLE ONLINE"),
        ("topright", "core.tui.ble_scan_detail", "KFIOSA: BLE DETAIL"),
        ("bottomright", "core.tui.ble_scan_offline", "KFIOSA: BLE OFFLINE"),
    )
    for pos, mod, title in specs:
        log = str(logs / f"ble-{pos}-{bus.name}.log")
        try:
            pops[pos] = launch_placed(
                _cmd(mod), log, title=title, position=pos,
                font_scale=font_scale, settings=settings,
            )
        except Exception as e:
            pops[pos] = None
            pops[f"{pos}_error"] = str(e)[:200]
    return {"ok": True, "bus_dir": str(bus), "procs": pops, "adapter": adapter}
