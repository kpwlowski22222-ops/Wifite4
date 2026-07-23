"""Pre-flight readiness for autonomous engagement."""
from __future__ import annotations

import os
import shutil
from typing import Any, Dict, List


def ready_check(*, domain: str = "wifi") -> Dict[str, Any]:
    """Return honest readiness checklist (never fabricates hardware state)."""
    checks: List[Dict[str, Any]] = []
    domain = (domain or "wifi").lower()

    def add(name: str, ok: bool, detail: str = "", fix: str = "") -> None:
        checks.append({"name": name, "ok": ok, "detail": detail, "fix": fix})

    add("python_env", True, detail="running")
    add("airodump-ng", bool(shutil.which("airodump-ng")),
        fix="apt install aircrack-ng" if domain == "wifi" else "")
    add("iw", bool(shutil.which("iw")), fix="apt install iw")
    add("bluetoothctl", bool(shutil.which("bluetoothctl")),
        fix="apt install bluez" if domain == "ble" else "")
    add("ollama", bool(shutil.which("ollama")), fix="install ollama for AI chains")
    add("xterm_or_terminal", bool(
        shutil.which("xterm") or shutil.which("kitty") or shutil.which("alacritty")
    ), fix="apt install xterm")

    try:
        from core.desktop.holo_agent import holo_status
        st = holo_status()
        add("holo_desktop", bool(st.get("holo_bin")),
            detail=st.get("holo_bin") or "",
            fix="pip install holo-desktop-cli")
    except Exception as e:
        add("holo_desktop", False, detail=str(e)[:80])

    # Env credentials (presence only)
    for key in ("NVD_API_KEY", "OLLAMA_CLOUD_TOKEN", "SHODAN_API_KEY"):
        add(f"env_{key}", bool((os.environ.get(key) or "").strip()),
            detail="set" if (os.environ.get(key) or "").strip() else "missing")

    try:
        from core.db import sqlstore
        h = sqlstore.init()
        add("sqlstore", bool(h.get("ok", True) if isinstance(h, dict) else True))
    except Exception as e:
        add("sqlstore", False, detail=str(e)[:80])

    ok_all = all(c["ok"] for c in checks if c["name"] in (
        "python_env", "sqlstore",
    ))
    # Soft readiness: critical path tools for domain
    if domain == "wifi":
        critical = all(
            c["ok"] for c in checks if c["name"] in ("airodump-ng", "iw")
        )
    elif domain == "ble":
        critical = any(c["ok"] for c in checks if c["name"] == "bluetoothctl")
    else:
        critical = True

    return {
        "ok": ok_all and critical,
        "critical_ok": critical,
        "checks": checks,
        "domain": domain,
        "full_auto": (os.environ.get("KFIOSA_FULL_AUTO") or "0") in ("1", "true", "yes"),
        "model": "ready_check_v1",
    }
