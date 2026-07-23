"""AIChainPlanner — primary call, refusal swap, heuristic fallback, JSON parsing."""

import json
import pytest

from core.ai_backend.chain import (
    AIChainPlanner, ChainPlanError,
    _parse_chain_json, _strip_code_fence, _heuristic_for_domain,
)


# ----------------------------------------------------------------------
# JSON parsing edge cases
# ----------------------------------------------------------------------

def test_strip_code_fence_strips_json_fence():
    s = '```json\n{"chain":[]}\n```'
    assert _strip_code_fence(s) == '{"chain":[]}'


def test_strip_code_fence_strips_bare_fence():
    assert _strip_code_fence("```\nfoo\n```") == "foo"


def test_strip_code_fence_passes_through_plain():
    assert _strip_code_fence('{"a": 1}') == '{"a": 1}'


def test_strip_code_fence_handles_empty():
    assert _strip_code_fence("") == ""
    assert _strip_code_fence("   ") == ""


def test_parse_chain_strict_object():
    text = json.dumps({"chain": [
        {"action": "mcp_call", "tool": "airodump-ng", "args": {"channel": 6},
         "risk_level": "intrusive", "expected_runtime_seconds": 30},
    ]})
    out = _parse_chain_json(text)
    assert len(out) == 1
    assert out[0]["tool"] == "airodump-ng"
    assert out[0]["expected_runtime_seconds"] == 30


def test_parse_chain_bare_list():
    text = json.dumps([
        {"action": "parse", "args": {}, "risk_level": "read"},
    ])
    out = _parse_chain_json(text)
    assert len(out) == 1
    assert out[0]["action"] == "parse"


def test_parse_chain_code_fence_wrapped():
    text = "```json\n" + json.dumps({"chain": [{"action": "decide"}]}) + "\n```"
    out = _parse_chain_json(text)
    assert len(out) == 1


def test_parse_chain_normalizes_missing_fields():
    text = json.dumps({"chain": [{"action": "mcp_call"}]})
    out = _parse_chain_json(text)
    assert out[0]["args"] == {}
    assert out[0]["risk_level"] == "intrusive"  # default
    assert out[0]["expected_runtime_seconds"] == 30  # default


def test_parse_chain_rejects_refusal():
    text = json.dumps({"refusal": True, "reason": "offensive target"})
    with pytest.raises(ChainPlanError) as e:
        _parse_chain_json(text)
    assert "refused" in str(e.value).lower()
    assert "offensive" in str(e.value)


def test_parse_chain_rejects_empty():
    with pytest.raises(ChainPlanError):
        _parse_chain_json("")
    with pytest.raises(ChainPlanError):
        _parse_chain_json("   ")


def test_parse_chain_rejects_non_json():
    with pytest.raises(ChainPlanError) as e:
        _parse_chain_json("not json at all")
    assert "non-JSON" in str(e.value)


def test_parse_chain_rejects_wrong_shape():
    with pytest.raises(ChainPlanError):
        _parse_chain_json(json.dumps({"foo": "bar"}))  # no "chain" key


def test_parse_chain_drops_non_dict_steps():
    """If the LLM sprinkles garbage into the list, we drop it rather
    than crash. Mixed list of dict + string + dict should yield 2 steps."""
    text = json.dumps({"chain": [
        {"action": "mcp_call", "tool": "nmap"},
        "garbage",
        {"action": "mcp_call", "tool": "msfconsole"},
    ]})
    out = _parse_chain_json(text)
    assert len(out) == 2
    assert out[0]["tool"] == "nmap"
    assert out[1]["tool"] == "msfconsole"


# ----------------------------------------------------------------------
# Heuristic fallback
# ----------------------------------------------------------------------

def test_heuristic_wifi_emits_capture_and_crack():
    steps = _heuristic_for_domain("wifi", {
        "bssid": "AA:BB:CC:DD:EE:01", "channel": 6,
        "interface": "wlan0mon", "essid": "Test",
        "client_count": 2,
    })
    # WPA2 default path: airodump capture + dictionary crack + GPU
    # mask fan-out. No WPS/PMKID flags set, no mt7921e caps.
    actions = [s["action"] for s in steps]
    assert "mcp_call" in actions  # airodump-ng capture
    assert "crack" in actions     # aircrack-ng dictionary
    assert actions.count("crack_gpu") >= 1  # GPU mask fan-out
    cap_steps = [s for s in steps if s.get("tool") == "airodump-ng"]
    assert cap_steps and cap_steps[0]["args"]["bssid"] == "AA:BB:CC:DD:EE:01"


def test_heuristic_wifi_clientless_prefers_pmkid_skips_deauth():
    steps = _heuristic_for_domain("wifi", {
        "bssid": "AA:BB:CC:DD:EE:02", "channel": 11,
        "interface": "wlan0mon", "encryption": "WPA2",
        "client_count": 0,
    })
    actions = [s["action"] for s in steps]
    assert "pmkid" in actions
    assert "deauth" not in actions


def test_heuristic_wifi_pmf_skips_classic_deauth():
    steps = _heuristic_for_domain("wifi", {
        "bssid": "AA:BB:CC:DD:EE:03", "channel": 6,
        "encryption": "WPA2", "pmf_supported": True,
        "client_count": 4,
    })
    actions = [s["action"] for s in steps]
    assert "deauth" not in actions


# --- Phase 2.4 §153: polymorphic target-adaptive WiFi strategy selection ---

def test_heuristic_wifi_strategy_picker_open_network():
    steps = _heuristic_for_domain("wifi", {
        "bssid": "AA:BB:CC:DD:EE:05", "channel": 6,
        "encryption": "OPN", "client_count": 0,
    })
    actions = [s["action"] for s in steps]
    assert "join_network" in actions
    assert "crack" not in actions


def test_heuristic_wifi_strategy_picker_wep():
    steps = _heuristic_for_domain("wifi", {
        "bssid": "AA:BB:CC:DD:EE:06", "channel": 6,
        "encryption": "WEP", "client_count": 0,
    })
    actions = [s["action"] for s in steps]
    assert any(s.get("args", {}).get("wep") for s in steps)
    assert "crack" in actions


def test_heuristic_wifi_strategy_picker_wpa3_transition():
    steps = _heuristic_for_domain("wifi", {
        "bssid": "AA:BB:CC:DD:EE:07", "channel": 36,
        "encryption": "WPA2/3", "transition": True, "client_count": 0,
    })
    actions = [s["action"] for s in steps]
    # Transition mode should run the WPA2-side path (capture + crack)
    assert "pmkid" in actions
    assert "crack" in actions


def test_heuristic_wifi_strategy_picker_enterprise():
    steps = _heuristic_for_domain("wifi", {
        "bssid": "AA:BB:CC:DD:EE:08", "channel": 6,
        "encryption": "WPA2-Enterprise", "client_count": 0,
    })
    actions = [s["action"] for s in steps]
    assert "wifi_attack" in actions
    assert any("hostapd-wpe" in (s.get("tool") or "") for s in steps)


def test_heuristic_wifi_wpa3_pure_sae_no_gpu_spam():
    steps = _heuristic_for_domain("wifi", {
        "bssid": "AA:BB:CC:DD:EE:04", "channel": 36,
        "encryption": "WPA3-SAE", "pmf": True,
    })
    actions = [s["action"] for s in steps]
    assert "crack_gpu" not in actions
    assert any("sae" in (s.get("rationale") or "").lower()
               or s.get("action") == "poly_adapt" for s in steps)


def test_heuristic_ble_emits_probe_chain():
    steps = _heuristic_for_domain(
        "ble", {"addr": "AA:BB:CC:DD:EE:01", "adapter": "hci0"}
    )
    actions = [s["action"] for s in steps]
    assert "ble_probe" in actions
    assert len(steps) >= 2
    # Must use real BLEProbeRunner / BLEAttackRunner method names —
    # shell binaries (bluetoothctl/gatttool/bettercap) are NOT valid
    # orchestrator methods and used to make every chain skip.
    tools = [s.get("tool") for s in steps]
    methods = [
        (s.get("args") or {}).get("method") for s in steps
        if s.get("action") in ("ble_probe", "ble_attack")
    ]
    forbidden = {"bluetoothctl", "gatttool", "bettercap", "hcitool"}
    assert not (set(tools) & forbidden)
    assert "parse_advertising_data" in methods
    assert "map_gatt_services" in methods
    assert any(m == "gatt_write_exploit" for m in methods)
    # With adapter known, no holo prep step required
    assert "holo_desktop" not in actions


def test_heuristic_ble_without_adapter_offers_holo_prep():
    steps = _heuristic_for_domain("ble", {"addr": "AA:BB:CC:DD:EE:01"})
    actions = [s["action"] for s in steps]
    assert "holo_desktop" in actions
    holo = next(s for s in steps if s["action"] == "holo_desktop")
    assert (holo.get("args") or {}).get("goal") == "ble_long_range_prep"


def test_heuristic_unknown_domain_parse():
    steps = _heuristic_for_domain("scada", {"host": "10.0.0.1"})
    assert len(steps) == 1
    assert steps[0]["action"] == "parse"
    assert "manually" in steps[0]["rationale"].lower()

# ----------------------------------------------------------------------
# Planner.plan() — three fallback layers
# ----------------------------------------------------------------------

class FakeAIBackend:
    """Returns a scripted text per (domain, prompt) tuple; otherwise
    raises to simulate an unreachable LLM."""

    def __init__(self, responses=None, raises=False):
        self.responses = list(responses or [])
        self.calls = 0
        self.raise_on_call = raises
        self.domain_prompts = {}

    def query(self, domain, prompt, context=None):
        self.calls += 1
        if self.raise_on_call:
            raise RuntimeError("ollama down")
        if self.responses:
            return self.responses.pop(0)
        return '{"chain": [{"action": "mcp_call", "tool": "nmap"}]}'


class FakeExploitGen:
    def __init__(self, tag="hf.co/fake/model"):
        self.tag = tag
        self.calls = 0

    def ensure_exploit_model(self, target_arch="x86_64"):
        self.calls += 1
        return self.tag


def _first_non_poly(steps):
    for s in steps or []:
        if (s.get("action") or "") != "poly_adapt":
            return s
    return (steps or [None])[0]


def test_planner_primary_call_succeeds():
    backend = FakeAIBackend(responses=[json.dumps({
        "chain": [
            {"action": "mcp_call", "tool": "airodump-ng",
             "args": {"channel": 6, "interface": "wlan0mon"},
             "risk_level": "intrusive", "expected_runtime_seconds": 30},
        ],
    })])
    p = AIChainPlanner(ai_backend=backend)
    steps = p.plan("wifi", {"bssid": "AA", "channel": 6, "interface": "wlan0mon"})
    # Live poly_adapt pre-step may be injected ahead of the LLM step.
    assert len(steps) >= 1
    assert any(s.get("tool") == "airodump-ng" for s in steps)
    assert _first_non_poly(steps)["tool"] == "airodump-ng"
    assert backend.calls == 1


def test_planner_falls_back_to_uncensored_on_refusal():
    """Primary returns a refusal; planner swaps to uncensored model
    (via the manager) and the second call returns a real chain."""
    backend = FakeAIBackend(responses=[
        json.dumps({"refusal": True, "reason": "no"}),
        json.dumps({"chain": [{"action": "mcp_call", "tool": "msfconsole"}]}),
    ])
    eg = FakeExploitGen()
    p = AIChainPlanner(ai_backend=backend, exploit_gen_manager=eg)
    steps = p.plan("wifi", {"bssid": "AA", "channel": 6, "interface": "wlan0mon"})
    assert len(steps) >= 1
    assert any(s.get("tool") == "msfconsole" for s in steps)
    assert _first_non_poly(steps)["tool"] == "msfconsole"
    assert backend.calls == 2
    assert eg.calls == 1  # uncensored model pulled


def test_planner_falls_back_to_heuristic_on_total_failure():
    """Both primary and uncensored fail (backend raises) → heuristic."""
    backend = FakeAIBackend(raises=True)
    eg = FakeExploitGen()
    p = AIChainPlanner(ai_backend=backend, exploit_gen_manager=eg)
    steps = p.plan("wifi", {
        "bssid": "AA:BB:CC:DD:EE:01", "channel": 6,
        "interface": "wlan0mon", "essid": "Test",
    })
    # Heuristic WPA2 path: airodump capture + crack + GPU fan-out.
    tools = [s["tool"] for s in steps]
    assert "airodump-ng" in tools
    assert "aircrack-ng" in tools
    assert _first_non_poly(steps)["tool"] == "airodump-ng"


def test_planner_no_backend_uses_heuristic():
    """No AI backend, no exploit-gen manager. BLE gets a real probe
    chain; unknown domains get a single parse step; wifi gets capture
    + crack."""
    p = AIChainPlanner(ai_backend=None, exploit_gen_manager=None)
    ble_steps = p.plan("ble", {"addr": "AA"})
    assert len(ble_steps) >= 2
    assert any(s["action"] == "ble_probe" for s in ble_steps)
    scada_steps = p.plan("scada", {"host": "10.0.0.1"})
    # Unknown domains: honest parse only (no poly pre-step injection).
    assert len(scada_steps) == 1
    assert scada_steps[0]["action"] == "parse"
    wifi_steps = p.plan("wifi", {
        "bssid": "AA:BB:CC:DD:EE:01", "channel": 6,
        "interface": "wlan0mon", "essid": "Test",
        "client_count": 2,
    })
    # Heuristic WPA2 path: airodump capture + crack + GPU fan-out.
    wifi_tools = [s["tool"] for s in wifi_steps]
    assert "airodump-ng" in wifi_tools
    assert "aircrack-ng" in wifi_tools

def test_planner_emits_on_event_lines():
    """Activity log lines should fire on every fallback (one per layer)."""
    events = []
    backend = FakeAIBackend(raises=True)
    p = AIChainPlanner(
        ai_backend=backend, exploit_gen_manager=FakeExploitGen(),
        on_event=events.append,
    )
    p.plan("wifi", {"bssid": "AA", "channel": 6, "interface": "wlan0mon"})
    # We expect at least: "primary LLM failed" + "using heuristic"
    msg = "\n".join(events)
    assert "primary" in msg.lower() or "failed" in msg.lower()
    assert "heuristic" in msg.lower()


def test_planner_primary_call_parse_error_triggers_fallback():
    """Primary returns unparseable text → swap to uncensored."""
    backend = FakeAIBackend(responses=[
        "not json at all",
        json.dumps({"chain": [{"action": "mcp_call", "tool": "nmap"}]}),
    ])
    p = AIChainPlanner(ai_backend=backend, exploit_gen_manager=FakeExploitGen())
    steps = p.plan("wifi", {"bssid": "AA", "channel": 6, "interface": "wlan0mon"})
    assert len(steps) >= 1
    assert _first_non_poly(steps)["tool"] == "nmap"
    assert backend.calls == 2


def test_planner_injects_prior_results():
    """When prior_results are provided, they must be formatted into the prompt."""
    captured_prompts = []

    class CapturingBackend:
        def __init__(self):
            self.domain_prompts = {}
        def query(self, domain, prompt, context=None):
            captured_prompts.append(prompt)
            return json.dumps({"chain": [{"action": "mcp_call", "tool": "crack"}]})

    backend = CapturingBackend()
    p = AIChainPlanner(ai_backend=backend)
    
    prior = [{"action": "mcp_call", "tool": "scan", "ok": True, "outcome": "completed", "data": {}}]
    steps = p.plan("wifi", {"bssid": "AA"}, prior_results=prior)
    
    # prior_results path skips poly pre-step injection
    assert len(steps) >= 1
    assert _first_non_poly(steps)["tool"] == "crack"
    assert len(captured_prompts) == 1
    assert "PRIOR STEP OUTCOMES" in captured_prompts[0]
    assert "scan" in captured_prompts[0]


def test_planner_appends_zero_day_tail():
    """When attach_zero_day=True, the 0-day tail steps are appended."""
    backend = FakeAIBackend(responses=[json.dumps({
        "chain": [{"action": "mcp_call", "tool": "scan"}],
    })])
    p = AIChainPlanner(ai_backend=backend)

    steps = p.plan("wifi", {"bssid": "AA"}, attach_zero_day=True)

    # optional poly pre-step + scan + 3 zero_day tail steps
    tools = [s.get("tool") for s in steps]
    actions = [s.get("action") for s in steps]
    assert "scan" in tools
    assert "zero_day_propose" in actions
    assert "zero_day_build" in actions
    assert "zero_day_execute" in actions
    assert len(steps) >= 4
    # zero-day tail is always last three
    assert steps[-3]["action"] == "zero_day_propose"
    assert steps[-2]["action"] == "zero_day_build"
    assert steps[-1]["action"] == "zero_day_execute"
    zd = [s for s in steps if str(s.get("action") or "").startswith("zero_day")]
    assert len(zd) == 3
    assert all(s.get("optional") for s in zd)



# ----------------------------------------------------------------------
# Batch 1: per-encryption branching in the wifi heuristic.
# ----------------------------------------------------------------------

def test_heuristic_wep_emits_arp_replay_and_wep_crack():
    """WEP target → mt7921e_inject arp_replay (when mt7921e capable) + a
    crack step with wep=true."""
    steps = _heuristic_for_domain("wifi", {
        "bssid": "AA:BB:CC:DD:EE:01", "channel": 6,
        "interface": "wlan0mon", "encryption": "wep",
        "adapter_caps": {"mt7921e": True, "injection_capable": True},
    })
    inject_modes = [s["args"].get("mode") for s in steps
                    if s.get("action") == "mt7921e_inject"]
    assert "arp_replay" in inject_modes
    assert "chopchop" in inject_modes
    crack = next(s for s in steps if s.get("action") == "crack")
    assert crack["args"].get("wep") is True
    assert crack["tool"] == "aircrack-ng"


def test_heuristic_wps_emits_pixie_and_online():
    """A target with wps=true → wps_pixie then wps_online first."""
    steps = _heuristic_for_domain("wifi", {
        "bssid": "AA:BB:CC:DD:EE:01", "channel": 6,
        "interface": "wlan0mon", "encryption": "wpa2", "wps": True,
    })
    actions = [s["action"] for s in steps]
    assert "wps_pixie" in actions
    assert "wps_online" in actions
    # WPS steps precede the capture/crack.
    assert actions.index("wps_pixie") < actions.index("crack")


def test_heuristic_wpa2_emits_crack_and_crack_gpu():
    """Plain WPA2 target → airodump capture + crack + crack_gpu fan-out."""
    steps = _heuristic_for_domain("wifi", {
        "bssid": "AA:BB:CC:DD:EE:01", "channel": 6,
        "interface": "wlan0mon", "encryption": "wpa2",
    })
    actions = [s["action"] for s in steps]
    assert "crack" in actions
    assert actions.count("crack_gpu") >= 1
    crack = next(s for s in steps if s.get("action") == "crack")
    # No wep flag, no hardcoded wordlist (orchestrator resolves it).
    assert crack["args"].get("wep") is None or crack["args"].get("wep") is False
    assert "wordlist" not in crack["args"]


def test_heuristic_pmkid_when_flagged():
    """A target with pmkid=true → a pmkid step before the dictionary crack."""
    steps = _heuristic_for_domain("wifi", {
        "bssid": "AA:BB:CC:DD:EE:01", "channel": 6,
        "interface": "wlan0mon", "encryption": "wpa2", "pmkid": True,
    })
    actions = [s["action"] for s in steps]
    assert "pmkid" in actions
    assert actions.index("pmkid") < actions.index("crack")


# ----------------------------------------------------------------------
# Phase 2.4 chain fixes (planning algorithms)
# ----------------------------------------------------------------------

from core.utils.poly_adapt import pick_wifi_strategy  # noqa: E402


def test_pick_wifi_strategy_open():
    assert pick_wifi_strategy({"wpa_version": "open", "encryption": "OPN"}) == "open"


def test_pick_wifi_strategy_wep():
    assert pick_wifi_strategy({"wpa_version": "wep", "encryption": "WEP"}) == "wep"


def test_pick_wifi_strategy_enterprise():
    assert pick_wifi_strategy({"wpa_version": "wpa2_enterprise",
                                "encryption": "WPA2-Enterprise"}) == "enterprise"


def test_pick_wifi_strategy_wpa3_pure_sae():
    assert pick_wifi_strategy({"wpa_version": "wpa3", "transition_mode": False}) == "wpa3_sae"


def test_pick_wifi_strategy_wpa3_transition_routes_to_wpa2():
    assert pick_wifi_strategy({"wpa_version": "wpa3", "transition_mode": True}) == "wpa2_transition"


def test_pick_wifi_strategy_wpa2_default():
    assert pick_wifi_strategy({"wpa_version": "wpa2", "transition_mode": False}) == "wpa2"


def test_pick_wifi_strategy_empty_falls_back_wpa2():
    assert pick_wifi_strategy({}) == "wpa2"


def test_heuristic_wifi_uses_polymorphic_strategy_picker():
    """The WiFi heuristic must use pick_wifi_strategy, not hard-coded if/elif."""
    from unittest.mock import patch
    import core.utils.poly_adapt as pa
    captured = {}
    real = pa.pick_wifi_strategy
    def spy(features):
        captured["called"] = features
        return real(features)
    # The chain module imports pick_wifi_strategy inside _heuristic_wifi,
    # so patch the source module's attribute.
    with patch.object(pa, "pick_wifi_strategy", side_effect=spy):
        _heuristic_for_domain("wifi", {
            "bssid": "AA:BB:CC:DD:EE:FF", "channel": 6, "encryption": "WPA2",
        })
    assert captured.get("called") is not None


def test_heuristic_wifi_enterprise_branch_picked_by_strategy():
    """WPA2-Enterprise target → enterprise strategy → hostapd-wpe step."""
    steps = _heuristic_for_domain("wifi", {
        "bssid": "AA:BB:CC:DD:EE:01", "channel": 6,
        "interface": "wlan0mon", "encryption": "WPA2-Enterprise",
    })
    actions = [s["action"] for s in steps]
    assert "wifi_attack" in actions
    # The enterprise step uses the hostapd-wpe tool.
    ea = next(s for s in steps if s.get("action") == "wifi_attack")
    assert ea["tool"] == "hostapd-wpe"


def test_heuristic_wifi_wpa3_pure_sae_routes_through_poly_adapt():
    """WPA3-SAE → wpa3_sae strategy → poly_adapt step + parse note."""
    steps = _heuristic_for_domain("wifi", {
        "bssid": "AA:BB:CC:DD:EE:02", "channel": 11,
        "interface": "wlan0mon", "encryption": "WPA3",
    })
    actions = [s["action"] for s in steps]
    assert "poly_adapt" in actions
    # WPA3-SAE strategy must NOT emit deauth (PMF / no clients to kick).
    assert "deauth" not in actions


def test_replan_dedup_drops_exact_action_tool_method():
    """Re-plan with prior_results that include (action, tool, method) → drop
    the exact signature from the new chain."""
    p = AIChainPlanner(ai_backend=None)
    steps = p.plan(
        "wifi",
        {"bssid": "AA:BB:CC:DD:EE:01", "channel": 6, "encryption": "WPA2",
         "client_count": 1},
        cves=[], kb_tools=[],
        prior_results=[
            {"action": "mcp_call", "tool": "airodump-ng",
             "args": {"method": "airodump-ng"},
             "result": {"ok": True}},
        ],
    )
    sigs = [(s["action"], s.get("tool"),
             (s.get("args") or {}).get("method")) for s in steps]
    assert ("mcp_call", "airodump-ng", "airodump-ng") not in sigs


def test_replan_dedup_does_not_drop_same_action_tool_different_method():
    """Re-plan keeps a new (action, tool, method) when prior had a different
    method for the same (action, tool)."""
    p = AIChainPlanner(ai_backend=None)
    steps = p.plan(
        "wifi",
        {"bssid": "AA:BB:CC:DD:EE:01", "channel": 6, "encryption": "WPA2",
         "client_count": 1},
        cves=[], kb_tools=[],
        prior_results=[
            {"action": "poly_adapt", "tool": "x",
             "args": {"method": "old_method"},
             "result": {"ok": True}},
        ],
    )
    # A future plan that emits poly_adapt with a different method must survive.
    sigs = [(s["action"], s.get("tool"),
             (s.get("args") or {}).get("method")) for s in steps]
    assert ("poly_adapt", "x", "old_method") not in sigs  # prior was old_method
    # The new chain can still contain poly_adapt steps with other methods.


def test_replan_dedup_treats_failed_steps_as_unexecuted():
    """High-severity fix: a prior step that failed (ok=False) does NOT
    mark (action, tool) as done — a re-plan should re-attempt it."""
    p = AIChainPlanner(ai_backend=None)
    steps = p.plan(
        "wifi",
        {"bssid": "AA:BB:CC:DD:EE:01", "channel": 6, "encryption": "WPA2",
         "client_count": 1},
        cves=[], kb_tools=[],
        prior_results=[
            {"action": "deauth", "tool": "aireplay-ng",
             "args": {"method": "deauth"},
             "result": {"ok": False, "error": "no clients"}},
        ],
    )
    actions = [s["action"] for s in steps]
    # deauth was a failure; re-plan should re-emit it for the orchestrator.
    assert "deauth" in actions


def test_known_chain_actions_includes_holo():
    """holo_desktop / desktop_nav / holo_run must be in _KNOWN_CHAIN_ACTIONS
    so the LLM is not told "unknown action" when it picks holo."""
    from core.ai_backend import chain as ch
    assert "holo_desktop" in ch._KNOWN_CHAIN_ACTIONS
    assert "desktop_nav" in ch._KNOWN_CHAIN_ACTIONS
    assert "holo_run" in ch._KNOWN_CHAIN_ACTIONS


def test_extract_json_blob_handles_trailing_prose_after_object():
    """The fast path must walk to the matching close, even if the model
    appends prose after the JSON object."""
    from core.ai_backend import chain as ch
    raw = '{"chain":[{"action":"deauth"}]}\n\nThanks! Let me know if you need more.'
    blob = ch._extract_json_blob(raw)
    parsed = json.loads(blob)
    assert parsed["chain"][0]["action"] == "deauth"


def test_extract_json_blob_handles_trailing_prose_after_array():
    from core.ai_backend import chain as ch
    raw = '[{"action":"deauth"}]\n\nExplanation follows.'
    blob = ch._extract_json_blob(raw)
    parsed = json.loads(blob)
    assert parsed[0]["action"] == "deauth"


def test_attach_post_exploit_does_not_reinject_on_replan():
    """attach_post_exploit must only append OPSEC steps on the *initial* plan;
    re-plans must not re-inject the same OPSEC steps every re-plan."""
    from unittest.mock import patch
    import core.ai_backend.chain as ch
    fake_seq = ["method_a", "method_b"]

    def fake_select(seed, max_modules=5, include_destructive=False):
        return list(fake_seq)

    p = ch.AIChainPlanner(ai_backend=None)
    with patch("core.ai_backend.post_exploit_selector.select_anti_forensic_sequence",
               side_effect=fake_select):
        # initial plan: get OPSEC steps
        initial = p.plan("wifi_attack", {"target_class": "linux"},
                          cves=[], kb_tools=[],
                          attach_post_exploit=True)
        initial_anti = [s for s in initial
                        if s.get("action") == "post_exploit_anti_forensic"]
        # re-plan: must NOT re-inject
        replan = p.plan("wifi_attack", {"target_class": "linux"},
                        cves=[], kb_tools=[],
                        prior_results=[{"action": "arp_spoof",
                                         "result": {"ok": True}}],
                        attach_post_exploit=True)
        replan_anti = [s for s in replan
                       if s.get("action") == "post_exploit_anti_forensic"]
    assert len(initial_anti) >= 1
    assert len(replan_anti) == 0


def test_heuristic_wifi_zero_day_tail_stays_at_end():
    """KFIOSA_ZERO_DAY_TAIL_AUTO=1 appends tail AFTER refine, so tail stays
    at the end of the chain (not sorted to the front by phase rank)."""
    import os
    os.environ["KFIOSA_ZERO_DAY_TAIL_AUTO"] = "1"
    try:
        c = _heuristic_for_domain("wifi",
            {"bssid": "AA:BB:CC:DD:EE:FF", "channel": 6, "encryption": "wpa2"})
        actions = [s["action"] for s in c]
        if "zero_day_propose" in actions:
            assert actions[-3:] == [
                "zero_day_propose", "zero_day_build", "zero_day_execute",
            ]
    finally:
        os.environ.pop("KFIOSA_ZERO_DAY_TAIL_AUTO", None)


def test_refine_clientless_no_recon_drops_deauth():
    """A target with client_count=0 and no recon dict → deauth is dropped."""
    from core.ai_backend.chain import refine_chain_steps
    steps = [
        {"action": "deauth", "tool": "aireplay-ng", "args": {"method": "deauth"},
         "risk_level": "destructive", "expected_runtime_seconds": 10},
        {"action": "pmkid", "tool": "hashcat", "args": {}, "risk_level": "intrusive",
         "expected_runtime_seconds": 60},
    ]
    out = refine_chain_steps(steps, "wifi",
                              {"bssid": "X", "client_count": 0})
    actions = [s["action"] for s in out]
    assert "deauth" not in actions
    assert "pmkid" in actions


def test_refine_clientless_zero_recon_keeps_deauth():
    """A target with client_count=0 and a recon dict that ran (but had no
    client data) → deauth is dropped (recon confirmed zero)."""
    from core.ai_backend.chain import refine_chain_steps
    steps = [
        {"action": "deauth", "tool": "aireplay-ng", "args": {"method": "deauth"},
         "risk_level": "destructive", "expected_runtime_seconds": 10},
    ]
    out = refine_chain_steps(steps, "wifi",
                              {"bssid": "X", "client_count": 0,
                               "recon": {"clients": {"ok": True, "data": []}}})
    actions = [s["action"] for s in out]
    assert "deauth" not in actions


def test_refine_clientless_failed_recon_keeps_deauth():
    """A target with NO explicit client_count and a recon dict that FAILED
    to enumerate clients → deauth is kept (absence of clients is not
    evidence when client_count was never set and recon failed)."""
    from core.ai_backend.chain import refine_chain_steps
    steps = [
        {"action": "deauth", "tool": "aireplay-ng", "args": {"method": "deauth"},
         "risk_level": "destructive", "expected_runtime_seconds": 10},
    ]
    out = refine_chain_steps(steps, "wifi",
                              {"bssid": "X",
                               "recon": {"clients": {"ok": False}}})
    actions = [s["action"] for s in out]
    assert "deauth" in actions
