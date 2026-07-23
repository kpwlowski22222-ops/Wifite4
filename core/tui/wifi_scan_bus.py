"""Shared filesystem bus for triple WiFi scan windows (single writer).

Layout under ``bus_dir`` (default ``/tmp/kfiosa_scan/<id>/``)::

  state.json       online/offline/clients/focus/updated_at
  selection.json   operator-selected AP (online window writes)
  control.json     {quit: bool}

Only the online window writes scan state; clients + offline readers poll.
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
    root = Path(base or os.environ.get("KFIOSA_SCAN_BUS") or "/tmp/kfiosa_scan")
    d = root / uuid.uuid4().hex[:12]
    d.mkdir(parents=True, exist_ok=True)
    write_json(d / "control.json", {"quit": False})
    write_json(
        d / "state.json",
        {
            "online": [],
            "offline": [],
            "clients": {},
            "focus_bssid": None,
            "selected": None,
            "updated_at": time.time(),
            "iface": None,
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
    st = read_json(Path(bus_dir) / "state.json")
    st.update(fields)
    st["updated_at"] = time.time()
    write_json(Path(bus_dir) / "state.json", st)
    return st


def set_selection(bus_dir: Path, ap: Dict[str, Any]) -> None:
    write_json(Path(bus_dir) / "selection.json", {
        "selected": ap,
        "selected_at": time.time(),
    })
    update_state(bus_dir, selected=ap.get("bssid"))


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
    """Poll until selection is written, or quit without selection.

    Selection is checked **before** quit so Enter/Space + coordinated
    shutdown never races into a false empty return.
    """
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        sel = get_selection(bus_dir)
        if sel:
            return sel
        if should_quit(bus_dir):
            # Final selection check after quit (writer may have just set it)
            return get_selection(bus_dir)
        time.sleep(poll_s)
    return get_selection(bus_dir)


def launch_triple_wifi_windows(
    iface: str,
    *,
    bus_dir: Optional[Path] = None,
    settings=None,
    font_scale: Optional[float] = None,
) -> Dict[str, Any]:
    """Spawn online (TL), clients (TR), offline (BR) external windows."""
    from core.utils.external_terminal import (
        launch_placed, LOG_DIR, get_scan_font_scale,
    )
    if font_scale is None:
        font_scale = get_scan_font_scale(settings)

    bus = Path(bus_dir) if bus_dir else new_bus_dir()
    update_state(bus, iface=iface)
    py = os.environ.get("KFIOSA_PYTHON") or "python3"
    root = Path(__file__).resolve().parents[2]
    env_prefix = f"KFIOSA_SCAN_BUS={bus}"

    def _cmd(mod: str) -> List[str]:
        return [
            "bash", "-c",
            f"cd {root} && {env_prefix} {py} -m {mod} --bus {bus} --iface {iface}",
        ]

    logs = Path(LOG_DIR) / "scan"
    logs.mkdir(parents=True, exist_ok=True)
    pops = {}
    specs = (
        ("topleft", "core.tui.wifi_scan_online", "KFIOSA: APs ONLINE"),
        ("topright", "core.tui.wifi_scan_clients", "KFIOSA: AP CLIENTS"),
        ("bottomright", "core.tui.wifi_scan_offline", "KFIOSA: APs OFFLINE"),
    )
    for pos, mod, title in specs:
        log = str(logs / f"{pos}-{bus.name}.log")
        try:
            pops[pos] = launch_placed(
                _cmd(mod), log, title=title, position=pos,
                font_scale=font_scale, settings=settings,
            )
        except Exception as e:
            pops[pos] = None
            pops[f"{pos}_error"] = str(e)[:200]
    return {"ok": True, "bus_dir": str(bus), "procs": pops, "iface": iface}
