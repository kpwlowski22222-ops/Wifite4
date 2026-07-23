"""Anomaly detect → deep-think class → polymorphic / OS reaction.

Creative recovery without fabricating success. Keyboard/mouse actions go
through holo when available and gated.
"""
from __future__ import annotations

import os
import time
from typing import Any, Callable, Dict, List, Optional


def _slow_s() -> float:
    try:
        return float(os.environ.get("KFIOSA_ANOMALY_SLOW_S") or "45")
    except ValueError:
        return 45.0


def classify_anomaly(
    event: Dict[str, Any],
) -> Dict[str, Any]:
    """Classify a raw event into an anomaly kind."""
    err = str(event.get("error") or event.get("msg") or "").lower()
    elapsed = float(event.get("elapsed_s") or 0)
    kind = "unknown"
    if elapsed >= _slow_s() or event.get("hang") or "timeout" in err:
        kind = "slow_or_hang"
    elif "address already in use" in err or "bind" in err:
        kind = "port_in_use"
    elif "not found" in err or "no such file" in err or event.get("missing_binary"):
        kind = "missing_tool"
    elif "429" in err or "rate limit" in err:
        kind = "rate_limit"
    elif (
        event.get("permission")
        or "permission" in err
        or "operation not permitted" in err
        or "adapter_blocked" in err
        or "rfkill" in err
        or "blocked" in err and "adapter" in err
    ):
        kind = "permission"
    elif event.get("empty_scan") or "no ap" in err or "no device" in err:
        kind = "empty_scan"
    elif "failed" in err or event.get("ok") is False:
        kind = "step_failed"
    return {
        "ok": True,
        "kind": kind,
        "error": event.get("error") or event.get("msg") or "",
        "elapsed_s": elapsed,
        "domain": event.get("domain") or "",
    }


def design_reaction(anomaly: Dict[str, Any]) -> Dict[str, Any]:
    """Deep-think flavoured playbook (heuristic + optional type tag)."""
    kind = anomaly.get("kind") or "unknown"
    domain = (anomaly.get("domain") or "wifi").lower()

    # Map anomaly → deep_thinking type preference + concrete moves
    playbooks = {
        "slow_or_hang": {
            "deep_think": "reflexion",
            "moves": [
                {"type": "kill_retry", "why": "stuck process — free resources"},
                {"type": "poly_alternate", "why": "try different attack variant"},
                {"type": "headless_fallback", "why": "skip heavy external UI"},
            ],
        },
        "port_in_use": {
            "deep_think": "react_grounded",
            "moves": [
                {"type": "kill_kismet_or_port", "why": "clear stale bind"},
                {"type": "retry", "why": "restart service cleanly"},
            ],
        },
        "missing_tool": {
            "deep_think": "plan_and_solve",
            "moves": [
                {"type": "install_hint", "why": "operator must install package"},
                {"type": "holo_open_terminal", "why": "show install command on desktop"},
            ],
        },
        "rate_limit": {
            "deep_think": "least_to_most",
            "moves": [
                {"type": "backoff", "why": "wait before next cloud call"},
                {"type": "local_model_fallback", "why": "use local Ollama tier"},
            ],
        },
        "permission": {
            "deep_think": "react_grounded",
            "moves": [
                {"type": "holo_wifi_or_ble_prep", "why": "OS prep for monitor/BLE"},
                {"type": "suggest_sudo", "why": "need elevated path"},
            ],
        },
        "empty_scan": {
            "deep_think": "tree_of_thought",
            "moves": [
                {"type": "poly_scan_window", "why": "longer/wider scan"},
                {"type": "holo_adapter_prep", "why": "power adapter / unblock rfkill"},
            ],
        },
        "step_failed": {
            "deep_think": "self_critique",
            "moves": [
                {"type": "poly_alternate", "why": "live_adapt re-pick method"},
                {"type": "memory_lesson", "why": "store failure for next run"},
            ],
        },
    }
    pb = playbooks.get(kind) or {
        "deep_think": "chain_of_thought",
        "moves": [{"type": "retry", "why": "generic recovery"}],
    }
    # Domain-coloured first move
    moves = list(pb["moves"])
    if domain == "ble" and kind in ("empty_scan", "permission"):
        moves.insert(0, {
            "type": "holo_preset",
            "preset": "ble_long_range_prep",
            "why": "BLE adapter range/power prep",
        })
    if domain == "wifi" and kind in ("empty_scan", "permission"):
        moves.insert(0, {
            "type": "holo_preset",
            "preset": "wifi_monitor_prep",
            "why": "WiFi monitor readiness",
        })
    return {
        "ok": True,
        "anomaly": anomaly,
        "deep_think_type": pb["deep_think"],
        "moves": moves,
        "predictable": (
            f"On {kind}, apply {len(moves)} recovery move(s) in order; "
            "stop on first clear success; never claim access without evidence."
        ),
    }


def execute_move(
    move: Dict[str, Any],
    *,
    confirm_fn: Optional[Callable[[str], bool]] = None,
    dry_run: bool = False,
) -> Dict[str, Any]:
    """Execute one recovery move (best-effort, honest)."""
    mtype = move.get("type") or "retry"
    if dry_run:
        return {"ok": True, "dry_run": True, "type": mtype, "why": move.get("why")}

    if mtype == "backoff":
        time.sleep(min(15.0, float(move.get("seconds") or 3)))
        return {"ok": True, "type": mtype}

    if mtype == "local_model_fallback":
        os.environ.setdefault("USE_OFFLINE_FIRST", "1")
        return {"ok": True, "type": mtype, "detail": "USE_OFFLINE_FIRST=1"}

    if mtype == "headless_fallback":
        os.environ["KFIOSA_SCAN_FONT_SCALE"] = "1.0"
        return {"ok": True, "type": mtype}

    if mtype in ("holo_open_terminal", "holo_wifi_or_ble_prep", "holo_adapter_prep", "holo_preset"):
        preset = move.get("preset") or (
            "open_terminal" if mtype == "holo_open_terminal"
            else "wifi_monitor_prep"
        )
        try:
            from core.desktop.holo_agent import run_holo_task, TASK_PRESETS
            task = TASK_PRESETS.get(preset) or preset
            if confirm_fn and not confirm_fn(f"OS agent move: {preset}?"):
                return {"ok": False, "cancelled": True, "type": mtype}
            return run_holo_task(task, confirm_fn=confirm_fn, dry_run=False)
        except Exception as e:
            return {"ok": False, "type": mtype, "error": str(e)}

    if mtype == "poly_alternate":
        try:
            from core.poly.live_adapt import react
            r = react(move.get("domain") or "wifi", move.get("target") or {},
                      {"ok": False, "error": move.get("why")})
            return {"ok": True, "type": mtype, "pick": r}
        except Exception as e:
            return {"ok": False, "type": mtype, "error": str(e)}

    if mtype == "memory_lesson":
        try:
            from core.memory.store import ingest
            ingest(
                "lesson",
                f"anomaly recovery: {move.get('why')}",
                domain=str(move.get("domain") or ""),
                tags=["anomaly"],
            )
            return {"ok": True, "type": mtype}
        except Exception as e:
            return {"ok": False, "type": mtype, "error": str(e)}

    if mtype == "install_hint":
        return {
            "ok": True,
            "type": mtype,
            "detail": move.get("detail") or "install missing package via apt",
        }

    if mtype == "kill_kismet_or_port":
        import subprocess
        try:
            subprocess.run(["pkill", "-x", "kismet"], capture_output=True, timeout=3)
            return {"ok": True, "type": mtype}
        except Exception as e:
            return {"ok": False, "type": mtype, "error": str(e)}

    return {"ok": True, "type": mtype, "detail": "no-op retry"}


def react_to_anomaly(
    event: Dict[str, Any],
    *,
    confirm_fn: Optional[Callable[[str], bool]] = None,
    dry_run: bool = False,
    max_moves: int = 3,
) -> Dict[str, Any]:
    """Full pipeline: classify → design → execute up to max_moves."""
    anomaly = classify_anomaly(event)
    design = design_reaction(anomaly)
    results: List[Dict[str, Any]] = []
    for move in (design.get("moves") or [])[: max(1, max_moves)]:
        move = dict(move)
        move.setdefault("domain", event.get("domain"))
        move.setdefault("target", event.get("target"))
        res = execute_move(move, confirm_fn=confirm_fn, dry_run=dry_run)
        results.append(res)
        if res.get("ok") and not res.get("cancelled"):
            # continue applying remaining soft fixes unless fatal
            if move.get("type") in ("poly_alternate", "holo_preset", "kill_kismet_or_port"):
                break
    # Memory of the incident
    try:
        from core.memory.store import ingest
        ingest(
            "lesson",
            f"anomaly={anomaly.get('kind')} moves={[r.get('type') for r in results]}",
            domain=str(event.get("domain") or ""),
            tags=["anomaly", anomaly.get("kind") or ""],
        )
    except Exception:
        pass
    return {
        "ok": True,
        "anomaly": anomaly,
        "design": design,
        "results": results,
        "narrative": (
            f"Detected {anomaly.get('kind')}: {anomaly.get('error') or 'issue'}. "
            f"Deep-think={design.get('deep_think_type')}. "
            f"Tried {len(results)} recovery move(s)."
        ),
    }
