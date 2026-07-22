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
    })
    # WPA2 default path: airodump capture + dictionary crack + GPU
    # mask fan-out. No WPS/PMKID flags set, no mt7921e caps.
    actions = [s["action"] for s in steps]
    assert "mcp_call" in actions  # airodump-ng capture
    assert "crack" in actions     # aircrack-ng dictionary
    assert actions.count("crack_gpu") >= 1  # GPU mask fan-out
    cap_steps = [s for s in steps if s.get("tool") == "airodump-ng"]
    assert cap_steps and cap_steps[0]["args"]["bssid"] == "AA:BB:CC:DD:EE:01"


def test_heuristic_non_wifi_emits_single_parse_step():
    steps = _heuristic_for_domain("ble", {"addr": "AA:BB:CC:DD:EE:01"})
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
    assert len(steps) == 1
    assert steps[0]["tool"] == "airodump-ng"
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
    assert len(steps) == 1
    assert steps[0]["tool"] == "msfconsole"
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
    assert steps[0]["tool"] == "airodump-ng"


def test_planner_no_backend_uses_heuristic():
    """No AI backend, no exploit-gen manager. For non-wifi domains the
    heuristic returns a single 'parse' step (operator-driven). For
    wifi it returns a real chain."""
    p = AIChainPlanner(ai_backend=None, exploit_gen_manager=None)
    ble_steps = p.plan("ble", {"addr": "AA"})
    assert len(ble_steps) == 1
    assert ble_steps[0]["action"] == "parse"
    wifi_steps = p.plan("wifi", {
        "bssid": "AA:BB:CC:DD:EE:01", "channel": 6,
        "interface": "wlan0mon", "essid": "Test",
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
    assert len(steps) == 1
    assert steps[0]["tool"] == "nmap"
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
    
    assert len(steps) == 1
    assert steps[0]["tool"] == "crack"
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

    # 1 scan step + 3 zero_day tail steps = 4 steps
    assert len(steps) == 4
    assert steps[0]["tool"] == "scan"
    assert steps[1]["action"] == "zero_day_propose"
    assert steps[2]["action"] == "zero_day_build"
    assert steps[3]["action"] == "zero_day_execute"
    assert all(s.get("optional") for s in steps[1:])



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
