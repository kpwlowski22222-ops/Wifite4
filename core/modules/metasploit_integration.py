"""Metasploit integration for KFIOSA.

Replaces the previous one-line placeholder. Thin, honest wrapper around
:mod:`metasploit_post_exploit` + local binary/RPC probes.

Never fabricates sessions, loot, or shell output. Offensive actions require
a ``confirm_fn`` (ACCEPT/CANCEL). Missing tools return ``ok=False`` with an
install hint.
"""
from __future__ import annotations

import logging
import shutil
import socket
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)

MSFRPC_HOST = "127.0.0.1"
MSFRPC_PORT = 55553


def _which(name: str) -> Optional[str]:
    return shutil.which(name)


def check_msf_toolchain() -> Dict[str, Any]:
    """Probe msfconsole / msfvenom / optional msfrpcd port.

    Returns a status envelope — never invents tool versions.
    """
    console = _which("msfconsole")
    venom = _which("msfvenom")
    rpc_open = False
    try:
        with socket.create_connection((MSFRPC_HOST, MSFRPC_PORT), timeout=0.4):
            rpc_open = True
    except OSError:
        rpc_open = False
    return {
        "ok": bool(console and venom),
        "msfconsole": console or "",
        "msfvenom": venom or "",
        "msfrpcd_open": rpc_open,
        "msfrpcd": f"{MSFRPC_HOST}:{MSFRPC_PORT}",
        "install_hint": (
            "apt install metasploit-framework"
            if not (console and venom)
            else ""
        ),
    }


class MetasploitIntegration:
    """Gated Metasploit driver used by modules / planners.

    Args:
        confirm_fn: operator gate; required for any execute path.
        engine: optional AI engine for plan text (defaults to project engine).
    """

    def __init__(
        self,
        confirm_fn: Optional[Callable[[str], bool]] = None,
        engine: Any = None,
        config: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.confirm_fn = confirm_fn
        self.engine = engine
        self.config = config or {}
        self._driver = None
        self._status = check_msf_toolchain()

    def status(self) -> Dict[str, Any]:
        """Fresh toolchain probe."""
        self._status = check_msf_toolchain()
        return dict(self._status)

    def _driver_or_none(self):
        if self._driver is not None:
            return self._driver
        try:
            from metasploit_post_exploit import MetasploitPostExploit
            self._driver = MetasploitPostExploit(
                engine=self.engine,
                confirm_fn=self.confirm_fn,
            )
            return self._driver
        except Exception as e:  # noqa: BLE001
            logger.warning("MetasploitPostExploit unavailable: %s", e)
            return None

    def plan(
        self,
        session: Dict[str, Any],
        target_profile: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Plan post-exploitation steps for a live session.

        Honest degrade when MSF or the AI engine is missing.
        """
        st = self.status()
        if not st.get("ok"):
            return {
                "ok": False,
                "error": "metasploit-framework not on PATH",
                "status": st,
                "steps": [],
            }
        drv = self._driver_or_none()
        if drv is None:
            # Deterministic heuristic plan without inventing loot
            os_name = str((session or {}).get("os") or "linux").lower()
            steps: List[Dict[str, Any]] = [
                {
                    "module": "post/multi/recon/local_exploit_suggester",
                    "options": {},
                    "rationale": "Enumerate local privesc candidates on session",
                },
            ]
            if "win" in os_name:
                steps.append({
                    "module": "post/windows/gather/hashdump",
                    "options": {},
                    "rationale": "Windows hash dump (gated)",
                })
            else:
                steps.append({
                    "module": "post/linux/gather/enum_system",
                    "options": {},
                    "rationale": "Linux system enumeration (gated)",
                })
            return {
                "ok": True,
                "steps": steps,
                "source": "heuristic",
                "status": st,
            }
        try:
            plan = drv.plan(session or {}, target_profile=target_profile)
            return {
                "ok": True,
                "steps": list(plan.get("steps") or []),
                "payload": plan.get("payload"),
                "post_modules": plan.get("post_modules"),
                "raw": plan.get("raw") or "",
                "source": "metasploit_post_exploit",
                "status": st,
            }
        except Exception as e:  # noqa: BLE001
            return {
                "ok": False,
                "error": f"plan failed: {e}",
                "steps": [],
                "status": st,
            }

    def generate_payload(
        self,
        payload: str,
        lhost: str,
        lport: int,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """Generate a real payload via msfvenom (confirm-gated)."""
        st = self.status()
        if not st.get("msfvenom"):
            return {
                "ok": False,
                "error": "msfvenom not on PATH",
                "install_hint": st.get("install_hint"),
            }
        if self.confirm_fn is not None:
            ok = self.confirm_fn(
                f"ACCEPT msfvenom payload={payload} LHOST={lhost} LPORT={lport}?"
            )
            if not ok:
                return {"ok": False, "error": "operator CANCELLED payload generation"}
        else:
            return {
                "ok": False,
                "error": "no confirm_fn — payload generation blocked (default-deny)",
            }
        drv = self._driver_or_none()
        if drv is None:
            return {"ok": False, "error": "MetasploitPostExploit driver unavailable"}
        try:
            blob = drv.generate_payload(payload, lhost, int(lport), **kwargs)
            return {
                "ok": True,
                "payload": payload,
                "size": len(blob) if isinstance(blob, (bytes, bytearray)) else 0,
                "data": blob if isinstance(blob, (bytes, bytearray)) else b"",
            }
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "error": str(e)}

    def run_script(
        self,
        script: str,
        *,
        timeout: int = 600,
    ) -> Dict[str, Any]:
        """Run an msfconsole -x script (confirm-gated)."""
        st = self.status()
        if not st.get("msfconsole"):
            return {
                "ok": False,
                "error": "msfconsole not on PATH",
                "install_hint": st.get("install_hint"),
            }
        if not script or not str(script).strip():
            return {"ok": False, "error": "empty msf script"}
        if self.confirm_fn is not None:
            preview = str(script)[:200].replace("\n", "; ")
            if not self.confirm_fn(f"ACCEPT msfconsole -x script? preview={preview!r}"):
                return {"ok": False, "error": "operator CANCELLED msfconsole run"}
        else:
            return {
                "ok": False,
                "error": "no confirm_fn — msfconsole blocked (default-deny)",
            }
        drv = self._driver_or_none()
        if drv is None:
            return {"ok": False, "error": "MetasploitPostExploit driver unavailable"}
        try:
            if hasattr(drv, "run_msfconsole_script"):
                out = drv.run_msfconsole_script(script, timeout=timeout)
            else:
                return {"ok": False, "error": "driver missing run_msfconsole_script"}
            if isinstance(out, dict):
                return {"ok": True, **out}
            return {"ok": True, "output": out}
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "error": str(e)}


# Back-compat alias used by older import sites
MetasploitTools = MetasploitIntegration

__all__ = [
    "MetasploitIntegration",
    "MetasploitTools",
    "check_msf_toolchain",
]
