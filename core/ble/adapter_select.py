"""core.ble.adapter_select — Phase 3 expansion addendum.

Enumerate HCI controllers and pick the canonical **external** one
(the operator's U4000 BLUETOOTH adapter). Mirrors the way the
WiFi side hard-codes ``wlan0mon`` for the external MediaTek MT7922
— the operator wants BLE selection to "show only the external
bluetooth adapter" and to be **overridable** like the WiFi side.

The selection algorithm is intentionally simple and **honest**:

* ``list_adapters()`` runs ``hciconfig -a`` and parses every
  ``hciN:`` block. Returns ``[{"name": "hci0", "bus": "USB",
  "address": "...", "up": bool, "acl_mtu": int|None, ...}, ...]``
  sorted by ``name``. Never fabricates a controller that isn't
  in the real output — if ``hciconfig`` is missing or returns
  no blocks, returns ``[]`` and records the error.
* ``select_external_adapter(prefer="external", override=None)``
  filters the list by ``bus == prefer`` (default: USB) and
  returns the **lowest-indexed** matching controller. ``override``
  wins if it matches one of the parsed controllers; if it does
  not match, returns an envelope with ``ok=False``.
* ``resolve_default_adapter(override=None)`` is the small
  wrapper the runners call in their ``__init__``. It honours
  the ``KFIOSA_BLE_ADAPTER`` env var (the operator's chosen
  escape hatch), then falls back to ``select_external_adapter``.

The helper is **opt-in**: the runners' public constructors still
accept an explicit ``adapter=`` kwarg. Only the default (when
``adapter is None``) uses this code path. Existing tests that
pass ``adapter="hci1"`` explicitly are unaffected.

Never fabricates. If no controller satisfies the filter, the
runner falls back to ``None`` (its existing behaviour) and emits
a warning.
"""
from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Public env-var name (operator's escape hatch)
# ---------------------------------------------------------------------------

#: Override the BLE adapter pick. Set this in the operator's
#: shell to point the runners at a specific hciN even if the
#: USB filter would pick another. Honoured by
#: :func:`resolve_default_adapter`.
BLE_ADAPTER_ENV: str = "KFIOSA_BLE_ADAPTER"


# ---------------------------------------------------------------------------
# hciconfig parser
# ---------------------------------------------------------------------------


# Example block (real output from a Kali box with two USB dongles):
#   hci0:	Type: Primary  Bus: USB
#   	BD Address: 50:BB:B5:0A:D6:35  ACL MTU: 1021:6  SCO MTU: 240:8
#   	DOWN
#   	...
_HCI_HEADER_RE = re.compile(
    r"^(?P<name>hci\d+):\s*Type:\s*(?P<type>\S+)\s+Bus:\s*(?P<bus>\S+)\s*$"
)
_BD_ADDR_RE = re.compile(
    r"BD Address:\s*(?P<addr>[0-9A-Fa-f:]{17})"
    r"(?:.*?ACL MTU:\s*(?P<acl_mtu>\d+))?",
)
_UP_DOWN_RE = re.compile(r"^\s*(?P<state>UP(?:\s+RUNNING)?|DOWN)\s*$",
                         re.MULTILINE)


def _parse_hciconfig(text: str) -> List[Dict[str, Any]]:
    """Parse the textual output of ``hciconfig -a`` into a list of
    adapter dicts. Empty blocks / unrecognized lines are silently
    dropped (this is best-effort; we never invent fields)."""
    out: List[Dict[str, Any]] = []
    blocks: List[str] = []
    cur: List[str] = []
    for line in (text or "").splitlines():
        if _HCI_HEADER_RE.match(line):
            if cur:
                blocks.append("\n".join(cur))
                cur = []
            cur.append(line)
        elif cur:
            cur.append(line)
    if cur:
        blocks.append("\n".join(cur))

    for block in blocks:
        m = _HCI_HEADER_RE.match(block.splitlines()[0])
        if not m:
            continue
        name = m.group("name")
        bus = m.group("bus")
        ctype = m.group("type")
        addr = ""
        acl_mtu: Optional[int] = None
        bd = _BD_ADDR_RE.search(block)
        if bd:
            addr = bd.group("addr")
            if bd.group("acl_mtu"):
                try:
                    acl_mtu = int(bd.group("acl_mtu"))
                except ValueError:
                    acl_mtu = None
        up_state = _UP_DOWN_RE.search(block)
        up = bool(up_state and up_state.group("state").startswith("UP"))
        out.append({
            "name": name,
            "type": ctype,
            "bus": bus,
            "address": addr,
            "up": up,
            "acl_mtu": acl_mtu,
        })
    # Sort by hci-name numerically so hci0 < hci1 < hci10
    def _key(a: Dict[str, Any]) -> int:
        m2 = re.search(r"hci(\d+)", a.get("name", ""))
        return int(m2.group(1)) if m2 else 9999
    out.sort(key=_key)
    return out


def list_adapters(timeout_s: int = 5) -> Dict[str, Any]:
    """Enumerate HCI controllers via ``hciconfig -a``.

    Returns ``{ok, data: {adapters: [...]}, error, source}``.
    Never fabricates; returns ``data.adapters == []`` when
    ``hciconfig`` is missing or produces no output.
    """
    if not shutil.which("hciconfig"):
        return {
            "ok": False,
            "data": {"adapters": []},
            "error": "hciconfig not installed (apt install bluez)",
            "source": "adapter_select",
        }
    try:
        p = subprocess.run(
            ["hciconfig", "-a"],
            capture_output=True, text=True, timeout=timeout_s,
        )
    except subprocess.TimeoutExpired:
        return {
            "ok": False,
            "data": {"adapters": []},
            "error": f"hciconfig -a timed out after {timeout_s}s",
            "source": "adapter_select",
        }
    except Exception as e:  # noqa: BLE001
        return {
            "ok": False,
            "data": {"adapters": []},
            "error": f"hciconfig -a failed: {e}",
            "source": "adapter_select",
        }

    adapters = _parse_hciconfig(p.stdout or "")
    if not adapters:
        return {
            "ok": False,
            "data": {"adapters": []},
            "error": "no HCI controllers found",
            "source": "adapter_select",
        }
    return {
        "ok": True,
        "data": {"adapters": adapters, "count": len(adapters)},
        "error": "",
        "source": "hciconfig",
    }


# ---------------------------------------------------------------------------
# Picker
# ---------------------------------------------------------------------------


def select_external_adapter(
    prefer: str = "external",
    override: Optional[str] = None,
    timeout_s: int = 5,
) -> Dict[str, Any]:
    """Pick the canonical external BLE adapter.

    Args:
        prefer: ``"external"`` (default) → keep only ``Bus: USB``
            entries. ``"any"`` → no bus filter. ``"builtin"`` →
            exclude USB (for completeness; the operator's case is
            always ``external``).
        override: if set and matches one of the parsed controllers,
            wins outright. If it does not match any controller, the
            envelope is ``ok=False`` (we never invent an hciX that
            isn't in the real output).
        timeout_s: passed to :func:`list_adapters`.

    Returns ``{ok, data: {pick, rationale, candidates, prefer,
    override}, error}``.
    """
    prefer_normal = (prefer or "external").lower()
    inv = list_adapters(timeout_s=timeout_s)
    if not inv.get("ok") or not (inv.get("data") or {}).get("adapters"):
        return {
            "ok": False,
            "data": {"pick": None, "candidates": [],
                     "prefer": prefer_normal,
                     "override": override or ""},
            "error": inv.get("error") or "no adapters",
            "source": "adapter_select",
        }
    adapters: List[Dict[str, Any]] = inv["data"]["adapters"]
    names = [a["name"] for a in adapters]

    if override:
        if override in names:
            return {
                "ok": True,
                "data": {
                    "pick": override,
                    "rationale": (f"operator override "
                                  f"{BLE_ADAPTER_ENV}={override}"),
                    "candidates": names,
                    "prefer": prefer_normal,
                    "override": override,
                },
                "error": "",
                "source": "override",
            }
        return {
            "ok": False,
            "data": {"pick": None, "candidates": names,
                     "prefer": prefer_normal,
                     "override": override},
            "error": (f"override {override!r} not in parsed "
                      f"controllers {names!r}"),
            "source": "override",
        }

    if prefer_normal == "external":
        candidates = [a for a in adapters if a.get("bus") == "USB"]
        filter_label = "Bus: USB"
    elif prefer_normal == "builtin":
        candidates = [a for a in adapters if a.get("bus") != "USB"]
        filter_label = "non-USB (built-in)"
    elif prefer_normal == "any":
        candidates = list(adapters)
        filter_label = "any bus"
    else:
        return {
            "ok": False,
            "data": {"pick": None, "candidates": names,
                     "prefer": prefer_normal, "override": ""},
            "error": f"unknown prefer value {prefer!r}",
            "source": "adapter_select",
        }

    if not candidates:
        return {
            "ok": False,
            "data": {"pick": None, "candidates": names,
                     "prefer": prefer_normal, "override": ""},
            "error": f"no HCI controllers match filter {filter_label!r}",
            "source": "adapter_select",
        }
    pick = candidates[0]["name"]
    return {
        "ok": True,
        "data": {
            "pick": pick,
            "rationale": f"lowest-indexed {filter_label} controller",
            "candidates": [c["name"] for c in candidates],
            "all_adapters": names,
            "prefer": prefer_normal,
            "override": "",
        },
        "error": "",
        "source": "filter",
    }


# ---------------------------------------------------------------------------
# Runner-facing wrapper
# ---------------------------------------------------------------------------


def resolve_default_adapter(
    prefer: str = "external",
    override: Optional[str] = None,
    fallback: str = "hci0",
    use_heuristic: bool = False,
) -> Optional[str]:
    """The single entry-point BLE runners call from their ``__init__``.

    Order:
      1. ``override`` kwarg (highest priority — testable).
      2. ``$KFIOSA_BLE_ADAPTER`` env var.
      3. If ``use_heuristic=True``, run
         :func:`select_external_adapter` (which spawns
         ``hciconfig -a``) and return its pick.
      4. Otherwise return ``fallback`` (default ``"hci0"``).

    The heuristic path is opt-in via ``use_heuristic=True`` because
    it spawns a subprocess. Runners that construct hundreds of
    objects in a test suite (BLEAttackRunner / BLEProbeRunner) can
    pay the cost once at module load; constructors that should
    never spawn subprocesses during tests pass the default
    (``use_heuristic=False``) and rely on the ``fallback`` arg.

    The ``fallback`` preserves the historic ``None → hci0``
    behaviour for systems where the helper fails (no
    ``hciconfig`` etc.).
    """
    # 1. explicit kwarg
    if override:
        return str(override)
    # 2. env var
    env_override = os.environ.get(BLE_ADAPTER_ENV, "").strip()
    if env_override:
        return env_override
    # 3. heuristic (opt-in subprocess)
    if use_heuristic:
        pick_envelope = select_external_adapter(prefer=prefer)
        if pick_envelope.get("ok"):
            return pick_envelope["data"]["pick"]
        logger.debug(
            "BLE adapter_select could not resolve: %s; "
            "falling back to %r", pick_envelope.get("error"), fallback,
        )
    # 4. fallback — log + return
    return fallback
