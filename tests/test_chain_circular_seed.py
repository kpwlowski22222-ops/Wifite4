"""Regression: seed/recon cycles must not kill AI chain planning.

Historically CatalogRecon stored ``recon["target"] = self.target`` (live
ref). After the TUI did ``target["recon"] = recon_report``, the seed
became cyclic and ``json.dumps(target)`` in AIChainPlanner raised
``ValueError: Circular reference detected``, forcing the legacy ladder
and making every re-plan fail with the same error.
"""
from __future__ import annotations

import json

import pytest


def test_target_identity_snapshot_is_detached():
    from core.modules.catalog_recon import _target_identity_snapshot

    seed = {"bssid": "AA:BB", "ssid": "lab", "channel": 6, "extra_blob": {"x": 1}}
    snap = _target_identity_snapshot(seed)
    assert snap["bssid"] == "AA:BB"
    assert snap is not seed
    assert "extra_blob" not in snap  # nested blobs deliberately dropped


def test_catalog_recon_report_does_not_cycle_after_seed_merge():
    from core.modules.catalog_recon import CatalogRecon

    seed = {"bssid": "44:AD:B1:BD:70:DC", "ssid": "<hidden>",
            "channel": 5, "interface": "wlan0mon"}
    recon = CatalogRecon(seed)
    assert recon.recon["target"] is not seed
    seed["recon"] = recon.recon
    # Must be JSON-serializable after the merge the TUI performs.
    json.dumps(seed, default=str)


def test_safe_json_dumps_marks_cycles():
    from core.ai_backend.chain import _safe_json_dumps

    seed = {"bssid": "AA"}
    recon = {"target": seed, "wps": {"ok": True}}
    seed["recon"] = recon
    with pytest.raises(ValueError, match="Circular reference"):
        json.dumps(seed)
    text = _safe_json_dumps(seed)
    assert "<circular>" in text
    assert "AA" in text


def test_plan_survives_cyclic_seed_and_prior_results():
    from core.ai_backend.chain import AIChainPlanner

    seed = {"bssid": "AA:BB:CC:DD:EE:FF", "ssid": "lab",
            "channel": 1, "interface": "wlan0mon"}
    # Classic cycle: recon.target is the live seed.
    seed["recon"] = {"target": seed, "wps": {"ok": False}}
    prior = [{"desc": "airodump", "kind": "real", "result": seed}]

    events = []
    planner = AIChainPlanner(ai_backend=None, on_event=events.append)
    steps = planner.plan(
        domain="wifi", target=seed, cves=[], kb_tools=[],
        prior_results=prior,
    )
    assert steps, "heuristic chain must still emit steps"
    assert planner._last_context.get("chain_source") == "heuristic"
