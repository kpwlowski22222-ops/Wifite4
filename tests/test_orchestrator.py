"""AutonomousOrchestrator — step building, gating, info vs real steps."""

import pytest

from core.orchestrator.autonomous_orchestrator import AutonomousOrchestrator
from tests.fakes import FakeAIBackend, FakeKB


def _make(confirm_fn, log):
    return AutonomousOrchestrator(
        ai_backend=FakeAIBackend(),
        kb=FakeKB(),
        confirm_fn=confirm_fn,
        on_event=log.append,
    )


def test_build_steps_wifi():
    o = _make(lambda p: True, [])
    steps = o._build_steps("wifi", {"bssid": "AA", "channel": 6, "ssid": "AP", "interface": "wlan0"}, {})
    kinds = [s["kind"] for s in steps]
    assert "real" in kinds and "info" in kinds
    assert any(s["action"] == "airodump" for s in steps)
    assert any(s["action"] == "deauth" for s in steps)
    assert sum(1 for k in kinds if k == "info") == 3  # stego, domain-front, anti-forensics


def test_build_steps_ble():
    o = _make(lambda p: True, [])
    steps = o._build_steps("ble", {"address": "AA:BB"}, {})
    actions = [s["action"] for s in steps]
    assert "gatt_enum" in actions and "bettercap_mitm" in actions
    assert any(s["kind"] == "info" for s in steps)


def test_build_steps_osint():
    o = _make(lambda p: True, [])
    steps = o._build_steps("osint", {"target": "example.com"}, {})
    actions = [s["action"] for s in steps]
    assert "shodan" in actions and "nvd" in actions and "msf_exploit" in actions
    # phishing is info-only
    ph = next(s for s in steps if s["action"] == "info")
    assert "Phishing" in ph["desc"]


def test_run_accept_all_executes_real_and_logs_info(monkeypatch):
    log = []
    o = _make(lambda p: True, log)
    # Avoid real subprocesses: fake _execute_step.
    monkeypatch.setattr(o, "_execute_step", lambda step, seed: f"fake-{step['action']}-ok")
    rep = o.run("wifi", {"bssid": "AA", "channel": 6, "ssid": "AP", "interface": "wlan0"})
    assert rep["ai_plan"]
    assert any("AI Attack Chain" in l for l in log)
    # info steps are logged but not executed
    assert any("(info, not executed)" in l for l in log)
    assert all(e["kind"] in ("real", "info") for e in rep["executed"])
    assert rep["post_plan"] and rep["c2_plan"]


def test_run_deny_all_skips_steps(monkeypatch):
    log = []
    o = _make(lambda p: False, log)
    monkeypatch.setattr(o, "_execute_step", lambda step, seed: "should-not-run")
    rep = o.run("wifi", {"bssid": "AA", "channel": 6, "ssid": "AP", "interface": "wlan0"})
    assert len(rep["skipped"]) > 0
    assert rep["executed"] == []
    # confirm_fn was prompted for each step
    assert any("CANCELLED" in l for l in log)


def test_run_confirm_fn_called_per_step(monkeypatch):
    prompts = []
    o = _make(lambda p: (prompts.append(p) or True), [])
    monkeypatch.setattr(o, "_execute_step", lambda step, seed: "ok")
    o.run("ble", {"address": "AA:BB"})
    # one prompt per step (real + info)
    assert len(prompts) >= 5
    assert all(p.startswith("ACCEPT step?") for p in prompts)


# ----------------------------------------------------------------------
# AI-driven chain path (new in plan: splendid-launching-eagle.md)
# ----------------------------------------------------------------------

class FakeChainPlanner:
    """Minimal stand-in for AIChainPlanner. Returns a scripted chain
    and tracks call count."""

    def __init__(self, steps=None):
        self.steps = steps or []
        self.plan_calls = 0

    def plan(self, domain, target, cves=None, kb_tools=None,
             context=None, attach_zero_day=False, **kwargs):
        self.plan_calls += 1
        self.last_attach_zero_day = attach_zero_day
        self.last_cves = cves
        self.last_kb_tools = kb_tools
        return list(self.steps)


class FakeZeroDayProposer:
    def __init__(self):
        self.propose_calls = 0

    def propose(self, target, recon=None, draft_id=None):
        self.propose_calls += 1
        from core.ai_backend.zero_day import ZeroDayConcept
        return ZeroDayConcept(
            draft_id=draft_id or "zd-1",
            target=target,
            title="cmd injection in /cgi-bin/luci",
            hypothesis="admin password concatenated into shell call unescaped",
            vulnerability_class="command injection",
            technique="fuzzing + source review",
            indicators=["/cgi-bin/luci", "admin_pwd"],
            entry_point="httpd request handler",
            tooling=["ffuf", "gdb"],
            draft_poc_outline="1) Map endpoints 2) Inject `;id` 3) Capture",
            risk_notes="may brick device",
            cve_hint="CVE-2027-12345",
            confidence="medium",
            status="pending",
        )


def test_ai_chain_path_uses_planner(monkeypatch):
    """use_ai_chain=True + chain_planner wired → planner.plan is
    called and its steps show up in the report."""
    planner = FakeChainPlanner(steps=[
        {"action": "mcp_call", "tool": "airodump-ng",
         "args": {"channel": 6, "interface": "wlan0mon"},
         "risk_level": "intrusive", "rationale": "capture",
         "expected_outcome": "handshake", "expected_runtime_seconds": 30},
    ])
    o = AutonomousOrchestrator(
        ai_backend=FakeAIBackend(),
        confirm_fn=lambda p: True,
        on_event=lambda m: None,
        chain_planner=planner,
    )
    monkeypatch.setattr(o, "_execute_step", lambda s, seed: "fake-ok")
    rep = o.run("wifi", {"bssid": "AA", "channel": 6, "interface": "wlan0mon"},
                use_ai_chain=True)
    # The initial plan call always happens; the polymorphic re-plan loop
    # (Part B) then re-queries the planner after each executed step. With
    # a FakeChainPlanner that returns the same step, dedup collapses the
    # re-plan to nothing new and the loop stops — so plan_calls is the
    # initial call plus one bounded re-plan per executed step (>= 1).
    assert planner.plan_calls >= 1
    assert rep["ai_chain_source"] == "llm"
    assert len(rep["ai_chain"]) == 1
    # The step was executed.
    assert any(e["tool"] == "airodump-ng" for e in rep["executed"])


def test_ai_chain_path_zero_day_propose(monkeypatch):
    """A zero_day_propose step drafts a concept via the proposer;
    the draft is in the report as 'pending'."""
    planner = FakeChainPlanner(steps=[
        {"action": "zero_day_propose", "tool": None,
         "args": {"vendor": "TP-Link"},
         "risk_level": "read", "rationale": "no CVE worked",
         "expected_outcome": "concept draft",
         "expected_runtime_seconds": 5},
    ])
    zd = FakeZeroDayProposer()
    o = AutonomousOrchestrator(
        ai_backend=FakeAIBackend(),
        confirm_fn=lambda p: True,
        on_event=lambda m: None,
        chain_planner=planner,
        zero_day_proposer=zd,
    )
    rep = o.run("wifi", {"bssid": "AA", "channel": 6, "interface": "wlan0mon"},
                use_ai_chain=True)
    assert zd.propose_calls == 1
    assert len(rep["zero_day_drafts"]) == 1
    assert rep["zero_day_drafts"][0]["status"] == "pending"
    # The executed entry points at the draft.
    assert rep["executed"][0]["action"] == "zero_day_propose"
    assert rep["executed"][0]["result"]["status"] == "pending"


def test_ai_chain_path_accept_prompt_includes_risk_level(monkeypatch):
    """The per-step ACCEPT prompt for AI steps includes the
    risk_level (so the operator sees the class before ACKing)."""
    prompts = []
    planner = FakeChainPlanner(steps=[
        {"action": "mcp_call", "tool": "aircrack-ng",
         "args": {}, "risk_level": "destructive",
         "rationale": "online brute", "expected_outcome": "psk",
         "expected_runtime_seconds": 60},
    ])
    o = AutonomousOrchestrator(
        ai_backend=FakeAIBackend(),
        confirm_fn=lambda p: (prompts.append(p) or True),
        on_event=lambda m: None,
        chain_planner=planner,
    )
    monkeypatch.setattr(o, "_execute_step", lambda s, seed: "ok")
    o.run("wifi", {"bssid": "AA", "channel": 6, "interface": "wlan0mon"},
          use_ai_chain=True)
    assert any("DESTRUCTIVE" in p for p in prompts)


def test_ai_chain_path_cancel_skips_step(monkeypatch):
    """confirm_fn=False on an AI step → step is skipped, not executed."""
    planner = FakeChainPlanner(steps=[
        {"action": "mcp_call", "tool": "airodump-ng",
         "args": {}, "risk_level": "intrusive",
         "rationale": "capture", "expected_outcome": "cap",
         "expected_runtime_seconds": 30},
    ])
    executed_calls = []
    o = AutonomousOrchestrator(
        ai_backend=FakeAIBackend(),
        confirm_fn=lambda p: False,  # cancel everything
        on_event=lambda m: None,
        chain_planner=planner,
    )
    monkeypatch.setattr(o, "_execute_step",
                        lambda s, seed: executed_calls.append(s) or "ok")
    rep = o.run("wifi", {"bssid": "AA", "channel": 6, "interface": "wlan0mon"},
                use_ai_chain=True)
    assert executed_calls == []
    assert len(rep["skipped"]) == 1
    assert rep["executed"] == []


def test_ai_chain_path_recon_probe_cancel_skips_step(monkeypatch):
    """recon_probe is a passive (risk=read) AI step, but the per-step
    ACCEPT/CANCEL gate still fires BEFORE dispatch — a CANCEL must
    skip it, never run run_probe, and never record an execution.

    This locks the gate invariant for the recon_probe action: a
    regression that hoisted _dispatch_recon_probe above the gate would
    flip this test red. Mirrors test_ai_chain_path_cancel_skips_step
    for the mcp_call action."""
    planner = FakeChainPlanner(steps=[
        {"action": "recon_probe",
         "args": {"method": "beacon_parse"},
         "risk_level": "read",
         "rationale": "enrich target",
         "expected_outcome": "is_wpa3",
         "expected_runtime_seconds": 10},
    ])
    dispatch_calls = []
    prompts = []
    o = AutonomousOrchestrator(
        ai_backend=FakeAIBackend(),
        confirm_fn=lambda p: (prompts.append(p) or False),  # cancel
        on_event=lambda m: None,
        chain_planner=planner,
    )
    monkeypatch.setattr(o, "_dispatch_recon_probe",
                        lambda s, seed, report: dispatch_calls.append(s))
    monkeypatch.setattr(o, "_execute_step",
                        lambda s, seed: "should-not-run")
    rep = o.run("wifi", {"bssid": "AA", "channel": 6, "interface": "wlan0mon"},
                use_ai_chain=True)
    # Gate fired (prompt offered the operator the recon_probe step).
    assert prompts, "recon_probe step was never offered to the gate"
    assert any("recon_probe" in p for p in prompts)
    # But cancel → dispatch never ran.
    assert dispatch_calls == []
    # Report records the skip, no execution.
    assert rep["executed"] == []
    assert any("recon_probe" in s for s in rep["skipped"])


def test_ai_chain_path_ble_probe_cancel_skips_step(monkeypatch):
    """ble_probe is a passive (risk=read) AI step; the per-step
    ACCEPT/CANCEL gate fires BEFORE _dispatch_ble_probe — a CANCEL must
    skip it and never run the BLE probe. Locks the gate invariant for
    the ble_probe action (mirrors the recon_probe gate test)."""
    planner = FakeChainPlanner(steps=[
        {"action": "ble_probe",
         "args": {"method": "manufacturer_oracle", "adapter": "hci0"},
         "risk_level": "read",
         "rationale": "enrich BLE target",
         "expected_outcome": "vendor + ibeacon",
         "expected_runtime_seconds": 10},
    ])
    dispatch_calls = []
    prompts = []
    o = AutonomousOrchestrator(
        ai_backend=FakeAIBackend(),
        confirm_fn=lambda p: (prompts.append(p) or False),  # cancel
        on_event=lambda m: None,
        chain_planner=planner,
    )
    monkeypatch.setattr(o, "_dispatch_ble_probe",
                        lambda s, seed, report: dispatch_calls.append(s))
    monkeypatch.setattr(o, "_execute_step",
                        lambda s, seed: "should-not-run")
    rep = o.run("ble", {"address": "AA:BB:CC:DD:EE:01"}, use_ai_chain=True)
    assert prompts, "ble_probe step was never offered to the gate"
    assert any("ble_probe" in p for p in prompts)
    assert dispatch_calls == []
    assert rep["executed"] == []
    assert any("ble_probe" in s for s in rep["skipped"])


def test_ai_chain_path_ble_probe_runs_and_merges(monkeypatch):
    """An ACCEPTed ble_probe step routes to _dispatch_ble_probe, which
    calls core.ble.runner.run_probe and merges the probe data into
    seed['ble_recon'] so the re-planner sees the new signal."""
    from core.ble import runner as blerunner

    planner = FakeChainPlanner(steps=[
        {"action": "ble_probe",
         "args": {"method": "manufacturer_oracle", "adapter": "hci0"},
         "risk_level": "read",
         "rationale": "enrich BLE target",
         "expected_outcome": "vendor + ibeacon",
         "expected_runtime_seconds": 10},
    ])
    o = AutonomousOrchestrator(
        ai_backend=FakeAIBackend(),
        confirm_fn=lambda p: True,  # accept
        on_event=lambda m: None,
        chain_planner=planner,
    )
    captured = {}

    def fake_run_probe(method=None, adapter=None, **kw):
        captured["method"] = method
        captured["adapter"] = adapter
        return {"ok": True, "data": {"devices": [{"address": "AA"}]},
                "error": None}

    monkeypatch.setattr(blerunner, "run_probe", fake_run_probe)
    monkeypatch.setattr(o, "_execute_step", lambda s, seed: "should-not-run")
    seed_in = {"address": "AA:BB:CC:DD:EE:01"}
    rep = o.run("ble", seed_in, use_ai_chain=True)
    assert captured["method"] == "manufacturer_oracle"
    assert captured["adapter"] == "hci0"
    assert any(e.get("action") == "ble_probe" and e.get("ok") for e in rep["executed"])
    # Probe data merged into seed for the re-planner.
    assert seed_in.get("ble_recon", {}).get("manufacturer_oracle") == \
        {"devices": [{"address": "AA"}]}


def test_ai_chain_path_osint_probe_cancel_skips_step(monkeypatch):
    """osint_probe is gated like every AI chain step; CANCEL must skip
    _dispatch_osint_probe and never run the algorithm."""
    from core.algorithm_registry import algo_registry
    calls = []

    planner = FakeChainPlanner(steps=[
        {"action": "osint_probe",
         "args": {"method": "username_patterns", "target": "admin"},
         "risk_level": "read",
         "rationale": "enrich subject",
         "expected_outcome": "username variants",
         "expected_runtime_seconds": 5},
    ])
    prompts = []
    o = AutonomousOrchestrator(
        ai_backend=FakeAIBackend(),
        confirm_fn=lambda p: (prompts.append(p) or False),  # cancel
        on_event=lambda m: None,
        chain_planner=planner,
    )
    monkeypatch.setattr(o, "_dispatch_osint_probe",
                        lambda s, seed, report: calls.append(s))
    monkeypatch.setattr(o, "_execute_step", lambda s, seed: "should-not-run")
    rep = o.run("osint", {"target": "admin"}, use_ai_chain=True)
    assert any("osint_probe" in p for p in prompts)
    assert calls == []
    assert rep["executed"] == []
    assert any("osint_probe" in s for s in rep["skipped"])


def test_ai_chain_path_osint_probe_runs_and_merges(monkeypatch):
    """An ACCEPTed osint_probe step routes to the registered algorithm
    and merges the result into seed['osint_recon']."""
    planner = FakeChainPlanner(steps=[
        {"action": "osint_probe",
         "args": {"method": "username_patterns", "target": "admin"},
         "risk_level": "read",
         "rationale": "enrich subject",
         "expected_outcome": "username variants",
         "expected_runtime_seconds": 5},
    ])
    o = AutonomousOrchestrator(
        ai_backend=FakeAIBackend(),
        confirm_fn=lambda p: True,
        on_event=lambda m: None,
        chain_planner=planner,
    )
    monkeypatch.setattr(o, "_execute_step", lambda s, seed: "should-not-run")
    seed_in = {"target": "admin"}
    rep = o.run("osint", seed_in, use_ai_chain=True)
    assert any(e.get("action") == "osint_probe" and e.get("ok")
               for e in rep["executed"])
    merged = seed_in.get("osint_recon", {}).get("username_patterns")
    assert merged and merged["type"] == "username_patterns"


def test_ai_chain_path_post_exploit_probe_runs_and_merges(monkeypatch):
    """An ACCEPTed post_exploit_probe step routes to the registered
    algorithm and merges the result into seed['post_exploit_recon']."""
    planner = FakeChainPlanner(steps=[
        {"action": "post_exploit_probe",
         "args": {"method": "priv_esc_check"},
         "risk_level": "read",
         "rationale": "post-access privesc survey",
         "expected_outcome": "privesc vectors",
         "expected_runtime_seconds": 5},
    ])
    o = AutonomousOrchestrator(
        ai_backend=FakeAIBackend(),
        confirm_fn=lambda p: True,
        on_event=lambda m: None,
        chain_planner=planner,
    )
    monkeypatch.setattr(o, "_execute_step", lambda s, seed: "should-not-run")
    seed_in = {"target": "host", "details": {"os": "linux"}}
    rep = o.run("post_exploitation", seed_in, use_ai_chain=True)
    assert any(e.get("action") == "post_exploit_probe" and e.get("ok")
               for e in rep["executed"])
    assert "priv_esc_check" in seed_in.get("post_exploit_recon", {})


def test_legacy_path_still_works_without_planner(monkeypatch):
    """No chain_planner, use_ai_chain=False → legacy hardcoded ladder."""
    o = _make(lambda p: True, [])
    monkeypatch.setattr(o, "_execute_step", lambda s, seed: "ok")
    rep = o.run("wifi", {"bssid": "AA", "channel": 6, "interface": "wlan0mon"},
                use_ai_chain=False)
    assert rep["ai_chain_source"] is None
    assert rep["ai_chain"] is None
    # The legacy ladder still runs.
    assert any(e.get("kind") == "real" for e in rep["executed"])


def test_ai_chain_planner_failure_falls_back_to_legacy(monkeypatch):
    """If the planner raises, the orchestrator logs the error and
    falls back to the legacy ladder (no crash)."""

    class BrokenPlanner:
        def plan(self, **kw):
            raise RuntimeError("LLM on fire")

    log = []
    o = AutonomousOrchestrator(
        ai_backend=FakeAIBackend(),
        confirm_fn=lambda p: True,
        on_event=log.append,
        chain_planner=BrokenPlanner(),
    )
    monkeypatch.setattr(o, "_execute_step", lambda s, seed: "ok")
    rep = o.run("wifi", {"bssid": "AA", "channel": 6, "interface": "wlan0mon"},
                use_ai_chain=True)
    # Planner raised → empty ai_chain, legacy ladder ran under the
    # polymorphic re-plan walk (source marked legacy_fallback_from_*).
    assert rep["ai_chain_source"] == "legacy_fallback_from_failed"
    assert rep["ai_chain"] == []
    assert any(e.get("kind") == "real" for e in rep["executed"])


def test_ai_chain_dispatch_post_exploit(monkeypatch):
    """A post_exploit step dispatches to run_auto_post_exploit_chain."""
    planner = FakeChainPlanner(steps=[
        {"action": "post_exploit",
         "args": {"session_id": 7, "os": "linux", "lhost": "10.0.0.1", "lport": 4444},
         "risk_level": "destructive", "rationale": "auto post-exploit",
         "expected_outcome": "meterpreter session",
         "expected_runtime_seconds": 60},
    ])

    class FakePostExploitRunner:
        def __init__(self):
            self.calls = []
        def run_auto_post_exploit_chain(self, session_info, lhost, lport,
                                        target_descriptor, external_terminal,
                                        on_event):
            self.calls.append({
                "session_id": session_info.get("session_id"),
                "lhost": lhost, "lport": lport,
            })
            return {"payload": None, "script": "fake msf script",
                    "modules": ["sysinfo"], "terminal_popen": None,
                    "inline_result": None, "error": None}

    runner = FakePostExploitRunner()
    o = AutonomousOrchestrator(
        ai_backend=FakeAIBackend(),
        confirm_fn=lambda p: True,
        on_event=lambda m: None,
        chain_planner=planner,
        post_exploit_runner=runner,
    )
    rep = o.run("wifi", {"bssid": "AA", "channel": 6, "interface": "wlan0mon"},
                use_ai_chain=True)
    assert len(runner.calls) == 1
    assert runner.calls[0]["session_id"] == 7
    assert any(e["action"] == "post_exploit" for e in rep["executed"])


def test_ai_chain_dispatch_external_terminal(monkeypatch):
    """An external_terminal step calls launch_step with the step dict."""
    planner = FakeChainPlanner(steps=[
        {"action": "external_terminal",
         "tool": "airodump-ng",
         "cmd": ["airodump-ng", "-c", "6", "wlan0mon"],
         "bssid": "AA:BB:CC:DD:EE:01",
         "risk_level": "intrusive", "rationale": "long capture",
         "expected_outcome": "cap file",
         "expected_runtime_seconds": 60},
    ])

    class FakeTerminal:
        def __init__(self):
            self.launched = []
        def launch_step(self, step):
            self.launched.append(step)
            # Return a fake Popen-like object.
            class FakePopen:
                pid = 12345
            return FakePopen()

    term = FakeTerminal()
    o = AutonomousOrchestrator(
        ai_backend=FakeAIBackend(),
        confirm_fn=lambda p: True,
        on_event=lambda m: None,
        chain_planner=planner,
        external_terminal=term,
    )
    rep = o.run("wifi", {"bssid": "AA", "channel": 6, "interface": "wlan0mon"},
                use_ai_chain=True)
    assert len(term.launched) == 1
    assert term.launched[0]["tool"] == "airodump-ng"
    assert any(e["action"] == "external_terminal" for e in rep["executed"])


# ----------------------------------------------------------------------
# Zero-day build / execute path (Stage 4)
# ----------------------------------------------------------------------

class _FakeStore:
    """Generic fake store: get(id) returns the scripted object when the
    id matches the object's draft_id or exploit_id."""

    def __init__(self, obj=None):
        self.obj = obj

    def get(self, item_id):
        if self.obj is None:
            return None
        if getattr(self.obj, "draft_id", None) == item_id:
            return self.obj
        if getattr(self.obj, "exploit_id", None) == item_id:
            return self.obj
        return None


class FakeZeroDayExploitBuilder:
    """Minimal stand-in for ZeroDayExploitBuilder. Records build calls
    and returns a valid ZeroDayExploit (or the scripted one)."""

    def __init__(self, exploit=None, store=None):
        self.build_calls = []
        self._exploit = exploit
        self.store = store

    def build(self, concept, recon=None, exploit_id=None,
              tools=None, unique=True, max_variations=2, **kwargs):
        self.build_calls.append({
            "concept": concept, "recon": recon, "exploit_id": exploit_id,
            "tools": tools,
        })
        if self._exploit is not None:
            return self._exploit
        from core.ai_backend.zero_day_exploit import ZeroDayExploit
        return ZeroDayExploit(
            exploit_id=exploit_id or "exp-1",
            draft_id=concept.draft_id,
            target=getattr(concept, "target", {}) or {},
            title="cmd inj PoC",
            language="python",
            code="print('x')",
            expected_effect="shell",
            safety_notes="lab only",
        )


class FakeZeroDayExploitRunner:
    """Minimal stand-in for ZeroDayExploitRunner. Records run calls and
    mimics the mandatory confirm_fn gate: if confirm_fn denies, the run
    is cancelled and no subprocess is spawned."""

    def __init__(self, store=None):
        self.run_calls = []
        self.last_result = None
        self.store = store

    def run(self, exploit, target, confirm_fn):
        self.run_calls.append({
            "exploit": exploit, "target": target, "confirm_fn": confirm_fn,
        })
        gate = False
        if confirm_fn is not None:
            gate = confirm_fn(f"EXECUTE 0-day exploit {exploit.exploit_id}?")
        if not gate:
            exploit.status = "cancelled"
            self.last_result = {
                "executed": False, "cancelled": True,
                "exit_code": None, "stdout": "", "stderr": "",
            }
            return self.last_result
        exploit.status = "executed"
        self.last_result = {
            "executed": True, "cancelled": False,
            "exit_code": 0, "stdout": "ok", "stderr": "",
        }
        return self.last_result


def _acked_concept(draft_id="zd-ack"):
    from core.ai_backend.zero_day import ZeroDayConcept
    c = ZeroDayConcept(
        draft_id=draft_id, target={"bssid": "AA"},
        title="cmd injection in /cgi-bin/luci",
        hypothesis="admin password concatenated into shell call unescaped",
        vulnerability_class="command injection",
        technique="fuzzing + source review",
        indicators=["/cgi-bin/luci", "admin_pwd"],
        entry_point="httpd request handler",
        tooling=["ffuf", "gdb"],
        draft_poc_outline="1) Map endpoints 2) Inject `;id` 3) Capture",
        risk_notes="may brick device",
        cve_hint="CVE-2027-12345",
        confidence="medium",
        status="acked",
    )
    return c


def test_ai_chain_path_zero_day_build(monkeypatch):
    """A zero_day_build step builds an exploit from an ACK'd concept
    (builder.build called, report['zero_day_drafts'] gets an entry). A
    build step for a non-acked concept is skipped — build NOT called."""
    # --- ACK'd concept: build is called ---
    acked = _acked_concept("zd-ack")
    concept_store = _FakeStore(acked)
    proposer = FakeZeroDayProposer()
    proposer.store = concept_store
    builder = FakeZeroDayExploitBuilder(store=_FakeStore(acked))

    planner = FakeChainPlanner(steps=[
        {"action": "zero_day_build", "tool": None,
         "args": {"draft_id": "zd-ack"},
         "risk_level": "intrusive", "rationale": "build PoC",
         "expected_outcome": "exploit draft",
         "expected_runtime_seconds": 30},
    ])
    o = AutonomousOrchestrator(
        ai_backend=FakeAIBackend(),
        confirm_fn=lambda p: True,
        on_event=lambda m: None,
        chain_planner=planner,
        zero_day_proposer=proposer,
        zero_day_exploit_builder=builder,
    )
    rep = o.run("wifi", {"bssid": "AA", "channel": 6, "interface": "wlan0mon"},
                use_ai_chain=True)
    assert len(builder.build_calls) == 1
    assert builder.build_calls[0]["concept"].draft_id == "zd-ack"
    assert len(rep["zero_day_drafts"]) == 1

    # --- Non-acked concept: build NOT called, step skipped ---
    from core.ai_backend.zero_day import ZeroDayConcept
    pending = ZeroDayConcept(
        draft_id="zd-pending", target={"bssid": "AA"},
        title="cmd injection", hypothesis="h",
        vulnerability_class="command injection", technique="fuzzing",
        indicators=["x"], entry_point="httpd", tooling=["ffuf"],
        draft_poc_outline="1) ...", risk_notes="may brick",
        cve_hint="", confidence="low", status="pending",
    )
    concept_store2 = _FakeStore(pending)
    proposer2 = FakeZeroDayProposer()
    proposer2.store = concept_store2
    builder2 = FakeZeroDayExploitBuilder(store=_FakeStore(pending))

    planner2 = FakeChainPlanner(steps=[
        {"action": "zero_day_build", "tool": None,
         "args": {"draft_id": "zd-pending"},
         "risk_level": "intrusive", "rationale": "build PoC",
         "expected_outcome": "exploit draft",
         "expected_runtime_seconds": 30},
    ])
    o2 = AutonomousOrchestrator(
        ai_backend=FakeAIBackend(),
        confirm_fn=lambda p: True,
        on_event=lambda m: None,
        chain_planner=planner2,
        zero_day_proposer=proposer2,
        zero_day_exploit_builder=builder2,
    )
    rep2 = o2.run("wifi", {"bssid": "AA", "channel": 6, "interface": "wlan0mon"},
                  use_ai_chain=True)
    assert len(builder2.build_calls) == 0
    assert len(rep2["zero_day_drafts"]) == 0


def test_ai_chain_path_zero_day_execute_cancelled(monkeypatch):
    """A zero_day_execute step with risk_level=destructive presents a
    DESTRUCTIVE ACCEPT prompt; the runner is called with confirm_fn and
    returns cancelled when the runner's internal gate denies.

    The per-step ACCEPT at line ~419 uses confirm_fn (first answer True
    → proceeds, capturing the DESTRUCTIVE wording). The runner's own
    mandatory confirm gate then denies (second answer False → cancelled).
    """
    from core.ai_backend.zero_day_exploit import ZeroDayExploit
    from tests.fakes import FakeConfirmFn

    exploit = ZeroDayExploit(
        exploit_id="exp-1", draft_id="zd-ack",
        target={"bssid": "AA"}, title="cmd inj PoC",
        language="python", code="print('x')",
        expected_effect="shell", safety_notes="lab only",
        status="drafted",
    )
    exploit_store = _FakeStore(exploit)
    builder = FakeZeroDayExploitBuilder(store=exploit_store)
    runner = FakeZeroDayExploitRunner(store=exploit_store)

    # First confirm: per-step ACCEPT gate (True → proceed). Second
    # confirm: runner's internal gate (False → cancelled).
    confirm = FakeConfirmFn([True, False])

    planner = FakeChainPlanner(steps=[
        {"action": "zero_day_execute", "tool": None,
         "args": {"exploit_id": "exp-1"},
         "risk_level": "destructive", "rationale": "run PoC",
         "expected_outcome": "shell",
         "expected_runtime_seconds": 60},
    ])
    o = AutonomousOrchestrator(
        ai_backend=FakeAIBackend(),
        confirm_fn=confirm,
        on_event=lambda m: None,
        chain_planner=planner,
        zero_day_exploit_builder=builder,
        zero_day_exploit_runner=runner,
    )
    o.run("wifi", {"bssid": "AA", "channel": 6, "interface": "wlan0mon"},
          use_ai_chain=True)

    # The destructive-risk ACCEPT prompt was presented.
    assert any("DESTRUCTIVE" in p for p in confirm.prompts)
    # The runner was called with confirm_fn.
    assert len(runner.run_calls) == 1
    assert runner.run_calls[0]["confirm_fn"] is confirm
    # The runner returned cancelled.
    assert runner.last_result is not None
    assert runner.last_result["cancelled"] is True
    assert runner.last_result["executed"] is False
    # The exploit status reflects the cancellation.
    assert exploit.status == "cancelled"


# ----------------------------------------------------------------------
# Vuln-driven chain handoff (Part 1) + optional-step semantics (Part 4)
# + mt7921e dispatch (Part 5)
# ----------------------------------------------------------------------

def test_vuln_driven_chain_handoff_cves_and_kb_hits(monkeypatch):
    """A seed carrying ``cves`` + ``kb_hits`` (merged from recon by the
    caller) reaches the chain planner verbatim — NOT the empty list /
    domain-level fallback. Back-compat: a seed without those keys still
    yields ``cves == []`` and the domain-level kb_tools."""
    planner = FakeChainPlanner(steps=[
        {"action": "mcp_call", "tool": "airodump-ng",
         "args": {}, "risk_level": "intrusive", "rationale": "capture",
         "expected_outcome": "cap", "expected_runtime_seconds": 30},
    ])
    o = AutonomousOrchestrator(
        ai_backend=FakeAIBackend(),
        confirm_fn=lambda p: True,
        on_event=lambda m: None,
        chain_planner=planner,
        kb=FakeKB(),
    )
    monkeypatch.setattr(o, "_execute_step", lambda s, seed: "ok")
    seed = {
        "bssid": "AA", "channel": 6, "interface": "wlan0mon",
        "cves": [{"id": "CVE-2027-1"}],
        "kb_hits": [{"name": "reaver"}],
    }
    o.run("wifi", seed, use_ai_chain=True)
    assert planner.last_cves == [{"id": "CVE-2027-1"}]
    assert planner.last_kb_tools == [{"name": "reaver"}]

    # Back-compat: a seed without cves/kb_hits → [] / domain-level tools.
    planner2 = FakeChainPlanner(steps=[])
    o2 = AutonomousOrchestrator(
        ai_backend=FakeAIBackend(),
        confirm_fn=lambda p: True,
        on_event=lambda m: None,
        chain_planner=planner2,
        kb=FakeKB(),
    )
    monkeypatch.setattr(o2, "_execute_step", lambda s, seed: "ok")
    o2.run("wifi", {"bssid": "AA", "channel": 6, "interface": "wlan0mon"},
           use_ai_chain=True)
    assert planner2.last_cves == []
    # kb_tools falls back to the domain-level KB slice (FakeKB returns
    # its tool list for the wifi domain).
    assert planner2.last_kb_tools is not None


def test_optional_step_prompt_and_decline(monkeypatch):
    """An ``optional: True`` step shows (OPTIONAL) in the ACCEPT prompt
    (alongside the risk class) and, on decline, lands in both
    ``skipped`` and ``optional_declined``. A non-optional step's prompt
    does NOT contain (OPTIONAL)."""
    # --- Optional step, declined ---
    prompts = []
    planner = FakeChainPlanner(steps=[
        {"action": "mcp_call", "tool": "zero_day_gen",
         "args": {}, "risk_level": "destructive", "optional": True,
         "rationale": "optional 0-day tail",
         "expected_outcome": "concept", "expected_runtime_seconds": 30},
    ])
    o = AutonomousOrchestrator(
        ai_backend=FakeAIBackend(),
        confirm_fn=lambda p: (prompts.append(p) or False),  # decline
        on_event=lambda m: None,
        chain_planner=planner,
    )
    monkeypatch.setattr(o, "_execute_step", lambda s, seed: "ok")
    rep = o.run("wifi", {"bssid": "AA", "channel": 6, "interface": "wlan0mon"},
                use_ai_chain=True)
    # Prompt carries both (OPTIONAL) and DESTRUCTIVE.
    opt_prompts = [p for p in prompts if "(OPTIONAL)" in p]
    assert len(opt_prompts) == 1
    assert "DESTRUCTIVE" in opt_prompts[0]
    # Declined optional step lands in both lists.
    assert len(rep["optional_declined"]) == 1
    assert len(rep["skipped"]) == 1
    # Nothing executed.
    assert rep["executed"] == []

    # --- Non-optional step: prompt must NOT contain (OPTIONAL) ---
    prompts2 = []
    planner2 = FakeChainPlanner(steps=[
        {"action": "mcp_call", "tool": "airodump-ng",
         "args": {}, "risk_level": "destructive",
         "rationale": "capture", "expected_outcome": "cap",
         "expected_runtime_seconds": 30},
    ])
    o2 = AutonomousOrchestrator(
        ai_backend=FakeAIBackend(),
        confirm_fn=lambda p: (prompts2.append(p) or True),
        on_event=lambda m: None,
        chain_planner=planner2,
    )
    monkeypatch.setattr(o2, "_execute_step", lambda s, seed: "ok")
    o2.run("wifi", {"bssid": "AA", "channel": 6, "interface": "wlan0mon"},
           use_ai_chain=True)
    assert prompts2, "expected at least one prompt for the non-optional step"
    assert all("(OPTIONAL)" not in p for p in prompts2)
    # Risk class still present.
    assert any("DESTRUCTIVE" in p for p in prompts2)


def test_attach_zero_day_runtime_override(monkeypatch):
    """``attach_zero_day`` runtime arg overrides the settings flag.
    Explicit True/False win; None falls back to settings."""
    from tests.fakes import FakeSettingsManager

    # Settings have attach_to_chain=True, so None → True.
    settings = FakeSettingsManager(settings={"zero_day": {"attach_to_chain": True}})

    def make_planner():
        planner = FakeChainPlanner(steps=[
            {"action": "mcp_call", "tool": "airodump-ng",
             "args": {}, "risk_level": "intrusive", "rationale": "x",
             "expected_outcome": "x", "expected_runtime_seconds": 1},
        ])
        return planner

    def run_with(attach):
        planner = make_planner()
        o = AutonomousOrchestrator(
            ai_backend=FakeAIBackend(),
            confirm_fn=lambda p: True,
            on_event=lambda m: None,
            chain_planner=planner,
            settings=settings,
        )
        monkeypatch.setattr(o, "_execute_step", lambda s, seed: "ok")
        o.run("wifi", {"bssid": "AA", "channel": 6, "interface": "wlan0mon"},
              use_ai_chain=True, attach_zero_day=attach)
        return planner

    # Explicit True → True.
    assert run_with(True).last_attach_zero_day is True
    # Explicit False → False (override of settings True).
    assert run_with(False).last_attach_zero_day is False
    # None → settings (True).
    assert run_with(None).last_attach_zero_day is True

    # Settings off (no zero_day key) + None → False.
    settings_off = FakeSettingsManager(settings={})
    planner_off = make_planner()
    o_off = AutonomousOrchestrator(
        ai_backend=FakeAIBackend(),
        confirm_fn=lambda p: True,
        on_event=lambda m: None,
        chain_planner=planner_off,
        settings=settings_off,
    )
    monkeypatch.setattr(o_off, "_execute_step", lambda s, seed: "ok")
    o_off.run("wifi", {"bssid": "AA", "channel": 6, "interface": "wlan0mon"},
              use_ai_chain=True)
    assert planner_off.last_attach_zero_day is False


def test_mt7921e_test_injection_dispatch(monkeypatch):
    """``mt7921e_test_injection`` step calls
    ``core.modules.mt7921e_tools.test_injection`` with the monitor iface
    and records the quality in ``report["executed"]``. Without
    adapter_caps the step is skipped and test_injection is NOT called."""
    import core.modules.mt7921e_tools as mt7921e_tools

    calls = []

    def fake_test_injection(iface, bssid="FF:FF:FF:FF:FF:FF", timeout=15):
        calls.append({"iface": iface, "bssid": bssid})
        return {"ok": True, "quality": 90, "stdout": "", "stderr": "",
                "error": ""}

    monkeypatch.setattr(mt7921e_tools, "test_injection", fake_test_injection)

    # --- With mt7921e caps: dispatched ---
    planner = FakeChainPlanner(steps=[
        {"action": "mt7921e_test_injection", "tool": None,
         "args": {}, "risk_level": "read", "rationale": "injection test",
         "expected_outcome": "quality reading",
         "expected_runtime_seconds": 15},
    ])
    o = AutonomousOrchestrator(
        ai_backend=FakeAIBackend(),
        confirm_fn=lambda p: True,
        on_event=lambda m: None,
        chain_planner=planner,
    )
    seed = {
        "bssid": "AA:BB:CC:DD:EE:01", "channel": 6,
        "adapter_caps": {"mt7921e": True, "monitor_iface": "wlan0mon",
                         "injection_capable": True},
    }
    rep = o.run("wifi", seed, use_ai_chain=True)
    assert calls == [{"iface": "wlan0mon", "bssid": "AA:BB:CC:DD:EE:01"}]
    mt7921e_entries = [e for e in rep["executed"]
                     if e.get("action") == "mt7921e_test_injection"]
    assert len(mt7921e_entries) == 1
    assert mt7921e_entries[0]["quality"] == 90
    assert mt7921e_entries[0]["ok"] is True

    # --- Without adapter_caps: skipped, not called ---
    calls.clear()
    planner2 = FakeChainPlanner(steps=[
        {"action": "mt7921e_test_injection", "tool": None,
         "args": {}, "risk_level": "read", "rationale": "injection test",
         "expected_outcome": "quality reading",
         "expected_runtime_seconds": 15},
    ])
    o2 = AutonomousOrchestrator(
        ai_backend=FakeAIBackend(),
        confirm_fn=lambda p: True,
        on_event=lambda m: None,
        chain_planner=planner2,
    )
    rep2 = o2.run("wifi", {"bssid": "AA", "channel": 6,
                           "interface": "wlan0mon"},
                  use_ai_chain=True)
    assert calls == []
    assert any("mt7921e_test_injection" in s for s in rep2["skipped"])


def test_mt7921e_inject_dispatch_deauth(monkeypatch):
    """``mt7921e_inject`` step without ``frame_b64`` runs the deauth path
    via ``mt7921e_tools.inject_deauth`` and records the result."""
    import core.modules.mt7921e_tools as mt7921e_tools

    calls = []

    def fake_inject_deauth(iface, bssid, channel=None, count=10,
                           station="FF:FF:FF:FF:FF:FF", reason=7,
                           timeout=20):
        calls.append({"iface": iface, "bssid": bssid, "channel": channel,
                      "count": count})
        return {"ok": True, "method": "scapy", "count": count, "error": ""}

    monkeypatch.setattr(mt7921e_tools, "inject_deauth", fake_inject_deauth)

    planner = FakeChainPlanner(steps=[
        {"action": "mt7921e_inject", "tool": None,
         "args": {"bssid": "AA:BB:CC:DD:EE:01", "count": 5},
         "risk_level": "intrusive", "rationale": "deauth",
         "expected_outcome": "clients disconnected",
         "expected_runtime_seconds": 20},
    ])
    o = AutonomousOrchestrator(
        ai_backend=FakeAIBackend(),
        confirm_fn=lambda p: True,
        on_event=lambda m: None,
        chain_planner=planner,
    )
    seed = {
        "bssid": "AA:BB:CC:DD:EE:01", "channel": 6,
        "adapter_caps": {"mt7921e": True, "monitor_iface": "wlan0mon",
                         "injection_capable": True},
    }
    rep = o.run("wifi", seed, use_ai_chain=True)
    assert calls == [{"iface": "wlan0mon", "bssid": "AA:BB:CC:DD:EE:01",
                      "channel": 6, "count": 5}]
    entries = [e for e in rep["executed"] if e.get("action") == "mt7921e_inject"]
    assert len(entries) == 1
    assert entries[0]["ok"] is True
    assert entries[0]["method"] == "scapy"


def test_deauth_helper_prefers_mt7921e_when_caps_present(monkeypatch):
    """``_deauth`` routes through ``mt7921e_tools.inject_deauth`` when the
    seed reports an mt7921e injection-capable adapter, and falls back to
    ``WiFiScanner.deauth_attack`` otherwise. Tested directly on the
    helper so neither path needs a real subprocess."""
    import core.modules.mt7921e_tools as mt7921e_tools
    import core.scanners.wifi_scanner as wifi_mod

    inject_calls = []
    monkeypatch.setattr(
        mt7921e_tools, "inject_deauth",
        lambda iface, bssid, channel=None, count=10, **kw: (
            inject_calls.append({"iface": iface, "bssid": bssid,
                                 "channel": channel}) or
            {"ok": True, "method": "scapy", "count": count, "error": ""}
        ),
    )

    deauth_calls = []

    class FakeWS:
        def __init__(self, *a, **kw):
            pass
        def initialize(self):
            pass
        def deauth_attack(self, bssid, iface):
            deauth_calls.append({"bssid": bssid, "iface": iface})
            return {"status": "aireplay-done"}

    monkeypatch.setattr(wifi_mod, "WiFiScanner", FakeWS)

    o = AutonomousOrchestrator(
        ai_backend=FakeAIBackend(),
        confirm_fn=lambda p: True,
        on_event=lambda m: None,
        interface="wlan0mon",
    )

    # --- mt7921e caps present → inject_deauth used, WiFiScanner NOT ---
    seed_mt7921e = {
        "bssid": "AA:BB:CC:DD:EE:01", "channel": 6,
        "adapter_caps": {"mt7921e": True, "monitor_iface": "wlan0mon",
                         "injection_capable": True},
    }
    out = o._deauth("wlan0mon", "AA:BB:CC:DD:EE:01", 6, seed_mt7921e)
    assert inject_calls == [{"iface": "wlan0mon",
                             "bssid": "AA:BB:CC:DD:EE:01", "channel": 6}]
    assert deauth_calls == []
    assert "scapy" in out

    # --- mt7921e caps absent → WiFiScanner.deauth_attack used, inject NOT ---
    inject_calls.clear()
    seed_plain = {"bssid": "AA:BB:CC:DD:EE:01", "channel": 6}
    out2 = o._deauth("wlan0mon", "AA:BB:CC:DD:EE:01", 6, seed_plain)
    assert inject_calls == []
    assert deauth_calls == [{"bssid": "AA:BB:CC:DD:EE:01",
                             "iface": "wlan0mon"}]
    assert out2 == "aireplay-done"

    # --- mt7921e cap present but NOT injection_capable → aireplay path ---
    inject_calls.clear()
    deauth_calls.clear()
    seed_no_inj = {
        "bssid": "AA:BB:CC:DD:EE:01", "channel": 6,
        "adapter_caps": {"mt7921e": True, "monitor_iface": "wlan0mon",
                         "injection_capable": False},
    }
    o._deauth("wlan0mon", "AA:BB:CC:DD:EE:01", 6, seed_no_inj)
    assert inject_calls == []
    assert deauth_calls == [{"bssid": "AA:BB:CC:DD:EE:01",
                             "iface": "wlan0mon"}]

# + external_inject dispatch (external injection toolbox)
def test_external_inject_dispatch_nemesis(monkeypatch):
    """``external_inject`` step with tool=nemesis_inject calls
    ``external_injection.nemesis_inject`` and records the result."""
    import core.modules.external_injection as ext

    calls = []

    def fake_nemesis(protocol, *, iface=None, args=None, timeout=30):
        calls.append({"protocol": protocol, "iface": iface, "args": args})
        return {"ok": True, "method": "nemesis", "protocol": protocol,
                "cmd": "nemesis arp -d eth0", "error": ""}

    monkeypatch.setattr(ext, "nemesis_inject", fake_nemesis)

    planner = FakeChainPlanner(steps=[
        {"action": "external_inject", "tool": "nemesis_inject",
         "args": {"protocol": "arp", "iface": "eth0",
                  "args": {"src_ip": "1.2.3.4", "dst_ip": "10.0.0.1"}},
         "risk_level": "destructive", "rationale": "arp spoof on evil-twin",
         "expected_outcome": "client cache poisoned",
         "expected_runtime_seconds": 10},
    ])
    o = AutonomousOrchestrator(
        ai_backend=FakeAIBackend(),
        confirm_fn=lambda p: True,
        on_event=lambda m: None,
        chain_planner=planner,
    )
    rep = o.run("wifi", {"bssid": "AA", "channel": 6,
                         "interface": "wlan0mon"},
                use_ai_chain=True)
    assert calls == [{"protocol": "arp", "iface": "eth0",
                      "args": {"src_ip": "1.2.3.4", "dst_ip": "10.0.0.1"}}]
    entries = [e for e in rep["executed"]
               if e.get("action") == "external_inject"]
    assert len(entries) == 1
    assert entries[0]["ok"] is True
    assert entries[0]["tool"] == "nemesis_inject"
    assert entries[0]["method"] == "nemesis"


def test_external_inject_unknown_tool_skipped(monkeypatch):
    """An ``external_inject`` step naming an unknown tool is skipped
    with a clear error, not crashed."""
    planner = FakeChainPlanner(steps=[
        {"action": "external_inject", "tool": "no_such_tool",
         "args": {}, "risk_level": "destructive", "rationale": "x",
         "expected_outcome": "x", "expected_runtime_seconds": 1},
    ])
    o = AutonomousOrchestrator(
        ai_backend=FakeAIBackend(),
        confirm_fn=lambda p: True,
        on_event=lambda m: None,
        chain_planner=planner,
    )
    rep = o.run("wifi", {"bssid": "AA", "channel": 6,
                         "interface": "wlan0mon"},
                use_ai_chain=True)
    assert rep["executed"] == []
    assert any("external_inject" in s for s in rep["skipped"])


def test_external_inject_cancelled_skipped(monkeypatch):
    """A CANCELLED ``external_inject`` step does not call the tool."""
    import core.modules.external_injection as ext

    calls = []
    monkeypatch.setattr(ext, "inject_tool_inject",
                        lambda *a, **k: calls.append(k) or {"ok": True})
    planner = FakeChainPlanner(steps=[
        {"action": "external_inject", "tool": "inject_tool_inject",
         "args": {"protocol": "tcp", "iface": "eth0"},
         "risk_level": "destructive", "rationale": "tcp rst",
         "expected_outcome": "x", "expected_runtime_seconds": 1},
    ])
    o = AutonomousOrchestrator(
        ai_backend=FakeAIBackend(),
        confirm_fn=lambda p: False,  # CANCEL
        on_event=lambda m: None,
        chain_planner=planner,
    )
    rep = o.run("wifi", {"bssid": "AA", "channel": 6,
                         "interface": "wlan0mon"},
                use_ai_chain=True)
    assert calls == []
    assert rep["executed"] == []
    assert any("CANCELLED" in s or "external_inject" in s
               for s in rep["skipped"])


# ----------------------------------------------------------------------
# Polymorphic re-plan loop + gain-access → shell (Parts B & C)
# ----------------------------------------------------------------------

class _ReplanPlanner:
    """Stateful planner whose output depends on how many steps have
    already executed (``len(prior_results)``). Used to exercise the
    re-plan loop's branching + dedup + bounds."""

    def __init__(self):
        self.calls = []  # each entry: the prior_results list seen

    def plan(self, domain, target, cves=None, kb_tools=None,
             prior_results=None, attach_zero_day=False, **kw):
        self.calls.append(list(prior_results or []))
        n = len(prior_results or [])
        base = {"args": {}, "risk_level": "read",
                "rationale": "r", "expected_outcome": "o",
                "expected_runtime_seconds": 1}
        if n == 0:
            return [dict(base, action="mcp_call", tool="scan")]
        if n == 1:
            return [dict(base, action="mcp_call", tool="crack")]
        return []  # nothing new → loop stops


def test_replan_loop_branches_on_prior_results(monkeypatch):
    """After step 1 executes, the planner is re-queried with the live
    prior_results and its NEXT step (``crack``) is spliced + run."""
    planner = _ReplanPlanner()
    o = AutonomousOrchestrator(
        ai_backend=FakeAIBackend(),
        confirm_fn=lambda p: True,
        on_event=lambda m: None,
        chain_planner=planner,
    )
    monkeypatch.setattr(o, "_execute_step", lambda s, seed: "ok")
    rep = o.run("wifi", {"bssid": "AA", "channel": 6,
                         "interface": "wlan0mon"},
                use_ai_chain=True)
    tools = [e.get("tool") for e in rep["executed"]]
    assert "scan" in tools and "crack" in tools
    # The re-plan call (2nd plan call) received the structured scan entry.
    assert len(planner.calls) >= 2
    prior = planner.calls[1]
    assert len(prior) == 1
    assert prior[0].get("action") == "mcp_call"
    assert prior[0].get("result") == "ok"
    assert rep["replans"] >= 1


def test_replan_loop_bound_stops_infinite_loop(monkeypatch):
    """A planner that always proposes a NOVEL step must still stop at
    MAX_REPLANS — no infinite loop, executions bounded."""
    class InfinitePlanner:
        def __init__(self):
            self.calls = 0
        def plan(self, domain, target, cves=None, kb_tools=None,
                 prior_results=None, attach_zero_day=False, **kw):
            self.calls += 1
            n = len(prior_results or [])
            return [{"action": "mcp_call", "tool": f"t{n}",
                     "args": {}, "risk_level": "read",
                     "rationale": "r", "expected_outcome": "o",
                     "expected_runtime_seconds": 1}]

    planner = InfinitePlanner()
    o = AutonomousOrchestrator(
        ai_backend=FakeAIBackend(),
        confirm_fn=lambda p: True,
        on_event=lambda m: None,
        chain_planner=planner,
    )
    monkeypatch.setattr(o, "_execute_step", lambda s, seed: "ok")
    rep = o.run("wifi", {"bssid": "AA", "channel": 6,
                         "interface": "wlan0mon"},
                use_ai_chain=True)
    # 1 initial plan + up to MAX_REPLANS(50) re-plans → bounded.
    from core.replan import MAX_REPLANS
    assert planner.calls <= MAX_REPLANS + 1
    assert rep["replans"] <= MAX_REPLANS
    assert len(rep["executed"]) <= MAX_REPLANS + 1


def test_replan_loop_cancelled_step_not_replanned(monkeypatch):
    """A cancelled (non-executed) step does NOT trigger a re-plan."""
    planner = _ReplanPlanner()
    o = AutonomousOrchestrator(
        ai_backend=FakeAIBackend(),
        confirm_fn=lambda p: False,  # cancel everything
        on_event=lambda m: None,
        chain_planner=planner,
    )
    monkeypatch.setattr(o, "_execute_step", lambda s, seed: "ok")
    rep = o.run("wifi", {"bssid": "AA", "channel": 6,
                         "interface": "wlan0mon"},
                use_ai_chain=True)
    # Only the initial plan call (no re-plan since nothing executed).
    assert len(planner.calls) == 1
    assert rep["executed"] == []
    assert rep["replans"] == 0


def _real_term():
    """A fake terminal backend that ``is_real_backend`` treats as real
    (``term != "tail"``); tests monkeypatch ``launch_real_step`` to
    capture the command instead of spawning a process."""
    class FakeRealTerm:
        term = "xterm"
    return FakeRealTerm()


def test_access_session_triggers_post_exploit_and_interactive_shell(monkeypatch):
    """A step whose result carries ``session_id`` flips access → the
    end-of-chain hook runs auto post-exploit AND spawns an interactive
    ``msfconsole sessions -i <id>`` window (no trailing ``exit``)."""
    import core.utils.external_terminal as ext

    launched = []

    def fake_launch_real_step(step, cmd, log_path=None):
        launched.append({"step": step, "cmd": list(cmd)})
        return {"ok": True, "pid": 4242}

    monkeypatch.setattr(ext, "launch_real_step", fake_launch_real_step)

    class FakeMcpClient:
        def call(self, tool, args):
            return {"ok": True, "session_id": 7}

    class FakePostRunner:
        def __init__(self):
            self.calls = []
        def run_auto_post_exploit_chain(self, session_info, lhost, lport,
                                        target_descriptor, external_terminal,
                                        on_event):
            self.calls.append(session_info.get("session_id"))
            return {"modules": ["sysinfo"], "terminal_popen": None}

    runner = FakePostRunner()
    planner = FakeChainPlanner(steps=[
        {"action": "mcp_call", "tool": "exploit",
         "args": {}, "risk_level": "intrusive",
         "rationale": "gain access", "expected_outcome": "session",
         "expected_runtime_seconds": 30},
    ])
    o = AutonomousOrchestrator(
        ai_backend=FakeAIBackend(),
        confirm_fn=lambda p: True,
        on_event=lambda m: None,
        chain_planner=planner,
        mcp_client=FakeMcpClient(),
        post_exploit_runner=runner,
        external_terminal=_real_term(),
    )
    rep = o.run("wifi", {"bssid": "AA", "channel": 6,
                         "interface": "wlan0mon"},
                use_ai_chain=True)
    # Access achieved with session 7.
    assert rep["access"]["achieved"] is True
    assert rep["access"]["session_id"] == 7
    # Auto post-exploit ran exactly once with the real session id.
    assert runner.calls == [7]
    # Interactive shell spawned with sessions -i 7 and NO exit.
    assert launched, "interactive session window was not launched"
    cmd = launched[0]["cmd"]
    joined = " ".join(cmd)
    assert "msfconsole" in joined
    assert "sessions -i 7" in joined
    assert "exit" not in joined


def test_no_auto_post_exploit_when_access_not_achieved(monkeypatch):
    """A chain that never yields creds/session does NOT trigger the
    end-of-chain post-exploit / interactive-shell hooks."""
    class FakePostRunner:
        def __init__(self):
            self.calls = []
        def run_auto_post_exploit_chain(self, *a, **k):
            self.calls.append(1)
            return {"modules": []}

    runner = FakePostRunner()
    planner = FakeChainPlanner(steps=[
        {"action": "mcp_call", "tool": "scan",
         "args": {}, "risk_level": "read",
         "rationale": "r", "expected_outcome": "o",
         "expected_runtime_seconds": 1},
    ])
    o = AutonomousOrchestrator(
        ai_backend=FakeAIBackend(),
        confirm_fn=lambda p: True,
        on_event=lambda m: None,
        chain_planner=planner,
        post_exploit_runner=runner,
    )
    monkeypatch.setattr(o, "_execute_step", lambda s, seed: "ok")
    rep = o.run("wifi", {"bssid": "AA", "channel": 6,
                         "interface": "wlan0mon"},
                use_ai_chain=True)
    assert rep["access"]["achieved"] is False
    assert runner.calls == []


@pytest.mark.parametrize("protocol,expect", [
    ("ssh", "ssh"),
    ("telnet", "telnet"),
    ("http", "curl"),
    ("nc", "nc"),
])
def test_open_shell_dispatch_spawns_client_window(monkeypatch, protocol, expect):
    """An AI ``open_shell`` step builds the per-protocol client argv and
    spawns it in an external window via ``launch_real_step``."""
    import core.utils.external_terminal as ext

    launched = []

    def fake_launch_real_step(step, cmd, log_path=None):
        launched.append(list(cmd))
        return {"ok": True, "pid": 1111}

    monkeypatch.setattr(ext, "launch_real_step", fake_launch_real_step)
    planner = FakeChainPlanner(steps=[
        {"action": "open_shell", "tool": protocol,
         "args": {"protocol": protocol, "host": "10.0.0.5",
                  "user": "root", "cred": "pw", "port": 22},
         "risk_level": "intrusive", "rationale": "use creds",
         "expected_outcome": "shell", "expected_runtime_seconds": 1},
    ])
    o = AutonomousOrchestrator(
        ai_backend=FakeAIBackend(),
        confirm_fn=lambda p: True,
        on_event=lambda m: None,
        chain_planner=planner,
        external_terminal=_real_term(),
    )
    rep = o.run("wifi", {"bssid": "AA", "channel": 6,
                         "interface": "wlan0mon"},
                use_ai_chain=True)
    assert launched, f"{protocol} window was not launched"
    joined = " ".join(launched[0])
    assert expect in joined
    assert "10.0.0.5" in joined
    assert any(e["action"] == "open_shell" for e in rep["executed"])


def test_open_shell_no_terminal_logs_manual_command(monkeypatch):
    """With no real terminal backend, ``open_shell`` does NOT spawn but
    logs the exact manual command (operator runs it by hand)."""
    planner = FakeChainPlanner(steps=[
        {"action": "open_shell", "tool": "ssh",
         "args": {"protocol": "ssh", "host": "10.0.0.5", "user": "root"},
         "risk_level": "intrusive", "rationale": "r",
         "expected_outcome": "shell", "expected_runtime_seconds": 1},
    ])
    log = []
    o = AutonomousOrchestrator(
        ai_backend=FakeAIBackend(),
        confirm_fn=lambda p: True,
        on_event=log.append,
        chain_planner=planner,
        # no external_terminal → is_real_backend False → manual fallback
    )
    rep = o.run("wifi", {"bssid": "AA", "channel": 6,
                         "interface": "wlan0mon"},
                use_ai_chain=True)
    assert any("ssh" in l and "10.0.0.5" in l and "manually" in l
               for l in log)
    entry = next(e for e in rep["executed"] if e["action"] == "open_shell")
    assert entry["result"]["manual"]
    assert "ssh" in entry["result"]["manual"]


# ----------------------------------------------------------------------
# Batch 1: gain-access completion — crack / crack_gpu / pmkid dispatchers
# propagate creds and flip report["access"]; _resolve_wordlist prefers
# weakpass. Hermetic: subprocess.run + filesystem faked.
# ----------------------------------------------------------------------

import types as _types
import core.orchestrator.autonomous_orchestrator as _orch_mod


def _crack_step(cap_path, **extra):
    args = {"cap_file": str(cap_path), "bssid": "AA:BB:CC:DD:EE:01"}
    args.update(extra)
    return {"action": "crack", "tool": "aircrack-ng", "args": args,
            "risk_level": "intrusive", "rationale": "r", "expected_outcome": "psk",
            "expected_runtime_seconds": 60}


def test_crack_dispatch_propagates_creds_and_flips_access(monkeypatch, tmp_path):
    """A `crack` step that recovers a PSK flips report["access"] and the
    re-plan loop stops early (not MAX_REPLANS)."""
    import subprocess
    pcap = tmp_path / "cap-01.cap"; pcap.write_text("pcap")
    wl = tmp_path / "rockyou.txt"; wl.write_text("pass\n")
    monkeypatch.setattr(_orch_mod.AutonomousOrchestrator, "_resolve_wordlist",
                        lambda self, *a, **k: str(wl))

    def fake_run(cmd, **kw):
        return _types.SimpleNamespace(
            stdout="KEY FOUND! [ mypsk ]\n", stderr="", returncode=0)

    monkeypatch.setattr(subprocess, "run", fake_run)
    planner = FakeChainPlanner(steps=[_crack_step(pcap)])
    o = AutonomousOrchestrator(ai_backend=FakeAIBackend(),
                               confirm_fn=lambda p: True,
                               on_event=lambda m: None,
                               chain_planner=planner)
    rep = o.run("wifi", {"bssid": "AA:BB:CC:DD:EE:01", "channel": 6,
                         "interface": "wlan0mon"}, use_ai_chain=True)
    assert rep["access"]["achieved"] is True
    assert rep["access"]["creds"] == "mypsk"
    # The re-plan loop recognized access and did NOT run to the bound.
    assert rep["replans"] < 25


def test_crack_no_key_does_not_flip_access(monkeypatch, tmp_path):
    """aircrack finds nothing → access stays False (no fake creds)."""
    import subprocess
    pcap = tmp_path / "cap-01.cap"; pcap.write_text("pcap")
    wl = tmp_path / "rockyou.txt"; wl.write_text("pass\n")
    monkeypatch.setattr(_orch_mod.AutonomousOrchestrator, "_resolve_wordlist",
                        lambda self, *a, **k: str(wl))
    monkeypatch.setattr(subprocess, "run",
                        lambda cmd, **k: _types.SimpleNamespace(
                            stdout="KEY NOT FOUND\n", stderr="", returncode=1))
    planner = FakeChainPlanner(steps=[_crack_step(pcap)])
    o = AutonomousOrchestrator(ai_backend=FakeAIBackend(),
                               confirm_fn=lambda p: True,
                               on_event=lambda m: None,
                               chain_planner=planner)
    rep = o.run("wifi", {"bssid": "AA", "channel": 6, "interface": "wlan0mon"},
                use_ai_chain=True)
    assert rep["access"]["achieved"] is False


def test_resolve_wordlist_prefers_weakpass(monkeypatch, tmp_path):
    """When a weakpass file exists, _resolve_wordlist returns it in
    preference to rockyou."""
    import os
    fake_cwd = tmp_path
    logs = fake_cwd / "logs" / "recon"
    logs.mkdir(parents=True)
    (logs / "weakpass_001.txt").write_text("weak\n")
    monkeypatch.chdir(str(fake_cwd))
    o = AutonomousOrchestrator(ai_backend=FakeAIBackend(),
                               confirm_fn=lambda p: True, on_event=lambda m: None)
    wl = o._resolve_wordlist({})
    assert wl.endswith("weakpass_001.txt")


def test_resolve_wordlist_operator_preferred_over_weakpass(monkeypatch, tmp_path):
    """An operator-provided wordlist wins over weakpass."""
    logs = tmp_path / "logs" / "recon"; logs.mkdir(parents=True)
    (logs / "weakpass_001.txt").write_text("weak\n")
    op = tmp_path / "custom.txt"; op.write_text("custom\n")
    monkeypatch.chdir(str(tmp_path))
    o = AutonomousOrchestrator(ai_backend=FakeAIBackend(),
                               confirm_fn=lambda p: True, on_event=lambda m: None)
    wl = o._resolve_wordlist({}, prefer=str(op))
    assert wl == str(op)


def test_crack_gpu_dispatch_builds_hashcat_mask(monkeypatch, tmp_path):
    """`crack_gpu` runs hashcat -m 22000 -a 3 with the GPU device flag and
    the given mask; a recovered PSK propagates as creds."""
    import subprocess
    hashf = tmp_path / "cap.hc22000"; hashf.write_text("WPA*02*x*AA*BB*ESSID\n")
    captured = []

    def fake_run(cmd, **kw):
        captured.append(list(cmd))
        if "--show" in cmd:
            # hashcat --show prints hash:password for a cracked hash.
            return _types.SimpleNamespace(
                stdout=f"WPA*02*x*AA*BB*ESSID:recoveredpw\n", stderr="",
                returncode=0)
        return _types.SimpleNamespace(stdout="", stderr="", returncode=0)

    monkeypatch.setattr(subprocess, "run", fake_run)
    planner = FakeChainPlanner(steps=[{
        "action": "crack_gpu", "tool": "hashcat",
        "args": {"hash_file": str(hashf), "mask": "?d?d?d?d?d?d?d?d"},
        "risk_level": "intrusive", "rationale": "r", "expected_outcome": "psk",
        "expected_runtime_seconds": 300,
    }])
    o = AutonomousOrchestrator(ai_backend=FakeAIBackend(),
                               confirm_fn=lambda p: True,
                               on_event=lambda m: None,
                               chain_planner=planner)
    rep = o.run("wifi", {"bssid": "AA", "channel": 6, "interface": "wlan0mon"},
                use_ai_chain=True)
    # The crack run (not the --show lookup) carries the mask + -a 3 -D 2.
    crack_cmd = next(c for c in captured if "--show" not in c)
    assert "hashcat" in crack_cmd
    assert "-m" in crack_cmd and "22000" in crack_cmd
    assert "-a" in crack_cmd and "3" in crack_cmd
    assert "-D" in crack_cmd and "2" in crack_cmd
    assert "?d?d?d?d?d?d?d?d" in crack_cmd
    assert rep["access"]["achieved"] is True
    assert rep["access"]["creds"] == "recoveredpw"


def test_pmkid_dispatch_uses_22000_and_propagates_creds(monkeypatch, tmp_path):
    """`pmkid` converts via hcxpcapngtool then runs hashcat -m 22000 and
    propagates a recovered PSK."""
    import subprocess
    pcap = tmp_path / "cap-01.cap"; pcap.write_text("pcap")
    modes = []

    def fake_run(cmd, **kw):
        modes.append(cmd[0])
        if cmd[0] == "hcxpcapngtool":
            out = str(pcap).replace(".cap", ".hc22000")
            with open(out, "w") as f:
                f.write("WPA*02*x*AA*BB*ESSID\n")
            return _types.SimpleNamespace(stdout="", stderr="", returncode=0)
        if "--show" in cmd:
            return _types.SimpleNamespace(
                stdout="WPA*02*x*AA*BB*ESSID:pmkidpsk\n", stderr="",
                returncode=0)
        return _types.SimpleNamespace(stdout="", stderr="", returncode=0)

    monkeypatch.setattr(subprocess, "run", fake_run)
    wl = tmp_path / "wl.txt"; wl.write_text("x\n")
    monkeypatch.setattr(_orch_mod.AutonomousOrchestrator, "_resolve_wordlist",
                        lambda self, *a, **k: str(wl))
    planner = FakeChainPlanner(steps=[{
        "action": "pmkid", "tool": "hashcat",
        "args": {"cap_file": str(pcap), "bssid": "AA"},
        "risk_level": "intrusive", "rationale": "r", "expected_outcome": "psk",
        "expected_runtime_seconds": 120,
    }])
    o = AutonomousOrchestrator(ai_backend=FakeAIBackend(),
                               confirm_fn=lambda p: True,
                               on_event=lambda m: None,
                               chain_planner=planner)
    rep = o.run("wifi", {"bssid": "AA", "channel": 6, "interface": "wlan0mon"},
                use_ai_chain=True)
    assert "hcxpcapngtool" in modes
    assert "hashcat" in modes
    assert rep["access"]["achieved"] is True
    assert rep["access"]["creds"] == "pmkidpsk"


# ----------------------------------------------------------------------
# Batch 3: post-access lateral movement — join_network, host_discovery,
# deploy_payload. Hermetic: subprocess.run + post runner faked.
# ----------------------------------------------------------------------

def test_join_network_builds_wpa_config_and_propagates_lhost(monkeypatch, tmp_path):
    """join_network writes a wpa_supplicant.conf with the recovered PSK,
    runs wpa_supplicant+dhclient, reads the assigned lhost from `ip`, and
    stashes it on report['access']['lhost']."""
    import subprocess
    calls = []

    def fake_run(cmd, **kw):
        calls.append(list(cmd))
        if cmd[0] == "wpa_supplicant":
            return _types.SimpleNamespace(stdout="", stderr="", returncode=0)
        if cmd[0] == "dhclient":
            return _types.SimpleNamespace(stdout="", stderr="", returncode=0)
        if cmd[0:2] == ["ip", "-4"]:
            return _types.SimpleNamespace(
                stdout="2: wlan0    inet 10.0.0.42/24 ...\n", stderr="",
                returncode=0)
        return _types.SimpleNamespace(stdout="", stderr="", returncode=0)

    monkeypatch.setattr(subprocess, "run", fake_run)
    planner = FakeChainPlanner(steps=[{
        "action": "join_network", "tool": "wpa_supplicant",
        "args": {"ssid": "HomeNet", "interface": "wlan0", "psk": "s3cret"},
        "risk_level": "intrusive", "rationale": "r", "expected_outcome": "join",
        "expected_runtime_seconds": 30,
    }])
    o = AutonomousOrchestrator(ai_backend=FakeAIBackend(),
                               confirm_fn=lambda p: True,
                               on_event=lambda m: None,
                               chain_planner=planner)
    rep = o.run("wifi", {"bssid": "AA", "channel": 6, "interface": "wlan0mon"},
                use_ai_chain=True)
    # wpa_supplicant.conf written with the PSK.
    wpa_call = next(c for c in calls if c[0] == "wpa_supplicant")
    conf_path = wpa_call[wpa_call.index("-c") + 1]
    conf_text = open(conf_path).read()
    assert 'ssid="HomeNet"' in conf_text
    assert 'psk="s3cret"' in conf_text
    assert rep["access"]["lhost"] == "10.0.0.42"
    assert rep["access"]["achieved"] is True


def test_join_network_needs_creds(monkeypatch):
    """No recovered PSK → join_network is skipped (no fake join)."""
    planner = FakeChainPlanner(steps=[{
        "action": "join_network", "tool": "wpa_supplicant",
        "args": {"ssid": "HomeNet"},
        "risk_level": "intrusive", "rationale": "r", "expected_outcome": "join",
        "expected_runtime_seconds": 30,
    }])
    o = AutonomousOrchestrator(ai_backend=FakeAIBackend(),
                               confirm_fn=lambda p: True,
                               on_event=lambda m: None,
                               chain_planner=planner)
    rep = o.run("wifi", {"bssid": "AA", "channel": 6, "interface": "wlan0mon"},
                use_ai_chain=True)
    assert any("no creds" in s for s in rep["skipped"])


def test_host_discovery_parses_arp_scan_into_devices(monkeypatch, tmp_path):
    """host_discovery runs arp-scan and parses IP/MAC/vendor rows into
    report['access']['devices']."""
    import subprocess
    monkeypatch.setattr(subprocess, "run", lambda cmd, **k: _types.SimpleNamespace(
        stdout="10.0.0.5\t00:11:22:33:44:55\tVendorA\n"
               "10.0.0.6\tAA:BB:CC:DD:EE:FF\tVendorB\n", stderr="",
        returncode=0))
    # Pre-seed access so host_discovery has a subnet.
    planner = FakeChainPlanner(steps=[{
        "action": "host_discovery", "tool": "nmap",
        "args": {"subnet": "10.0.0.0/24"},
        "risk_level": "intrusive", "rationale": "r", "expected_outcome": "hosts",
        "expected_runtime_seconds": 60,
    }])
    o = AutonomousOrchestrator(ai_backend=FakeAIBackend(),
                               confirm_fn=lambda p: True,
                               on_event=lambda m: None,
                               chain_planner=planner)
    rep = o.run("wifi", {"bssid": "AA", "channel": 6, "interface": "wlan0mon"},
                use_ai_chain=True)
    devices = rep["access"]["devices"]
    assert len(devices) == 2
    assert devices[0] == {"ip": "10.0.0.5", "mac": "00:11:22:33:44:55",
                          "vendor": "VendorA"}


def test_parse_hosts_nmap_format():
    o = AutonomousOrchestrator(ai_backend=FakeAIBackend(),
                               confirm_fn=lambda p: True, on_event=lambda m: None)
    out = ("Nmap scan report for 10.0.0.7\n"
           "Host is up.\n"
           "MAC Address: 11:22:33:44:55:66 (SomeVendor)\n")
    hosts = o._parse_hosts(out)
    assert hosts == [{"ip": "10.0.0.7", "mac": "11:22:33:44:55:66",
                      "vendor": "SomeVendor"}]


def test_deploy_payload_runs_per_device(monkeypatch, tmp_path):
    """deploy_payload calls run_per_device_chain with the discovered
    devices, one ACCEPT per device, one window per device."""
    class FakePerDeviceRunner:
        def __init__(self):
            self.calls = []
        def run_per_device_chain(self, devices, lhost="0.0.0.0", lport=4444,
                                 external_terminal=None, on_event=None,
                                 payload=None, **kw):
            self.calls.append({"n": len(devices), "lhost": lhost,
                               "lport": lport, "payload": payload})
            return {"staged": len(devices), "declined": 0,
                    "devices": [{"mac": d["mac"], "staged": True}
                                for d in devices]}
    runner = FakePerDeviceRunner()
    planner = FakeChainPlanner(steps=[{
        "action": "deploy_payload", "tool": "post_exploit_runner",
        "args": {"lhost": "10.0.0.42", "lport": 4444},
        "risk_level": "destructive", "rationale": "r", "expected_outcome": "rats",
        "expected_runtime_seconds": 60,
    }])
    o = AutonomousOrchestrator(ai_backend=FakeAIBackend(),
                               confirm_fn=lambda p: True,
                               on_event=lambda m: None,
                               chain_planner=planner,
                               post_exploit_runner=runner)
    # Seed access with discovered devices so deploy_payload picks them up.
    def _run(self, *a, **k):
        # bypass; we drive the report manually below via a thin override
        return None
    # Drive the dispatcher directly with a seeded report to keep the test
    # focused (run() would re-plan and consume the single step anyway).
    report = {"executed": [], "skipped": [], "optional_declined": [],
              "zero_day_drafts": [], "access": {"achieved": True,
              "creds": "psk", "session_id": None,
              "devices": [{"ip": "10.0.0.5", "mac": "00:11:22:33:44:55",
                            "vendor": "V"}]}}
    o._dispatch_deploy_payload(planner.steps[0], {}, report)
    assert runner.calls and runner.calls[0]["n"] == 1
    assert runner.calls[0]["lhost"] == "10.0.0.42"
    assert report["executed"][-1]["result"]["staged"] == 1


def test_deploy_payload_no_devices_skipped():
    o = AutonomousOrchestrator(ai_backend=FakeAIBackend(),
                               confirm_fn=lambda p: True, on_event=lambda m: None,
                               post_exploit_runner=object())
    report = {"executed": [], "skipped": [], "optional_declined": [],
              "zero_day_drafts": [], "access": {"achieved": True}}
    o._dispatch_deploy_payload({"args": {}}, {}, report)
    assert any("no devices" in s for s in report["skipped"])


# ---------------------------------------------------------------------------
# Phase 1.6.E: orchestrator routes the 9 new recon methods through
# core.recon.runner.
# ---------------------------------------------------------------------------
def test_dispatch_recon_probe_routes_new_methods(monkeypatch):
    """The orchestrator's _dispatch_recon_probe must dispatch the 9
    new methods (e.g. ema_smoothed_rssi_with_trend_arrows) to
    core.recon.runner.run_probe, and merge the data into seed.recon."""
    from core.recon import runner as rrunner

    o = AutonomousOrchestrator(
        ai_backend=FakeAIBackend(),
        confirm_fn=lambda p: True,
        on_event=lambda m: None,
    )
    seed: dict = {}
    report = {"executed": [], "skipped": []}
    o._dispatch_recon_probe(
        {"action": "recon_probe",
         "args": {"method": "ema_smoothed_rssi_with_trend_arrows",
                  "rssi": [-60, -58, -55]}},
        seed, report,
    )
    # The new method must have been recorded as executed.
    assert report["executed"], "new recon method was not executed"
    e = report["executed"][-1]
    assert e["tool"] == "core.recon.runner.ema_smoothed_rssi_with_trend_arrows"
    assert e["ok"] is True
    # And the data must be merged into seed.recon.
    assert "recon" in seed
    assert "ema_smoothed_rssi_with_trend_arrows" in seed["recon"]


def test_dispatch_recon_probe_unknown_method_skipped(monkeypatch):
    """A method that is not in either catalog_recon or core.recon.runner
    must be reported in report['skipped'] and not crash."""
    o = AutonomousOrchestrator(
        ai_backend=FakeAIBackend(),
        confirm_fn=lambda p: True,
        on_event=lambda m: None,
    )
    seed: dict = {}
    report = {"executed": [], "skipped": []}
    o._dispatch_recon_probe(
        {"action": "recon_probe",
         "args": {"method": "definitely_not_a_real_method"}},
        seed, report,
    )
    assert not report["executed"]
    assert any("unknown method" in s for s in report["skipped"])
