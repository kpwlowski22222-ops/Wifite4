"""Test fakes for KFIOSA screen/orchestrator/runner unit tests.

Each fake mirrors the real collaborator's call surface as used by the TUI
screens and orchestrator — no network, no curses, no disk, no subprocess.
Unit tests inject these so every screen action is curses-free and synchronous.
"""

from typing import Any, Callable, Dict, List, Optional


def sync_thread_runner(fn: Callable) -> None:
    """Run the action body inline instead of spawning a thread. Tests assert
    on ``activity_log`` immediately after calling the action."""
    fn()


class FakeInput:
    """Queue-backed ``input_fn``. Returns queued answers in order; ``""`` when
    empty (simulates the operator pressing ENTER on an empty field)."""

    def __init__(self, answers: Optional[List[str]] = None):
        self.answers: List[str] = list(answers or [])
        self.prompts: List[str] = []

    def __call__(self, prompt: str) -> str:
        self.prompts.append(prompt)
        if self.answers:
            return self.answers.pop(0)
        return ""


class _OllamaNS:
    def __init__(self, endpoint="http://127.0.0.1:11434"):
        self.endpoint = endpoint


class FakeAIBackend:
    """Canned AI backend. ``query`` returns a short plan string per domain."""

    def __init__(self, plans: Optional[Dict[str, str]] = None,
                 models: Optional[List[str]] = None):
        self.plans = plans or {
            "wifi": "1. airodump-ng\n2. aireplay-ng deauth\n3. hashcat",
            "ble": "1. gatttool enum\n2. char read/write\n3. bettercap",
            "osint": "1. shodan\n2. nvd\n3. msf exploit",
            "post_exploitation": "1. privesc\n2. cred dump\n3. persist",
            "c2": "1. beacon register\n2. poll loop",
        }
        self.ollama = _OllamaNS()
        self.models = models or [
            "xploiter/pentester:latest",
            "huihui_ai/phi4-abliterated:latest",
        ]
        self.queries: List[Dict[str, Any]] = []
        self.tool_seqs: Dict[str, List[str]] = {
            "osint": ["shodan", "nvd", "sherlock"],
            "wifi": ["airodump-ng", "aireplay-ng", "hashcat"],
        }

    def query(self, domain: str, prompt: str, context: Any = None) -> str:
        self.queries.append({"domain": domain, "prompt": prompt, "context": context})
        return self.plans.get(domain, "generic plan")

    def status(self) -> Dict[str, Any]:
        return {
            "ollama": True,
            "ollama_endpoint": self.ollama.endpoint,
            "ollama_models": list(self.models),
            "active": "ollama",
        }

    def autonomous_tool_selection(self, domain: str, target_info: Dict[str, Any]) -> List[str]:
        return list(self.tool_seqs.get(domain, ["tool-a", "tool-b"]))


class FakeKB:
    def __init__(self, tools: Optional[List[Dict[str, Any]]] = None):
        self.tools = tools or [
            {"owner": "ac1", "repo_name": "exploit-x", "category": "wifi"},
            {"owner": "ac2", "repo_name": "ble-tool", "category": "ble"},
        ]
        self.searches: List[Dict[str, Any]] = []

    def get_tools_for_domain(self, domain: str) -> List[Dict[str, Any]]:
        return [t for t in self.tools if t.get("category") == domain] or list(self.tools)

    def search(self, query: str, category: Optional[str] = None,
                limit: int = 5) -> List[Dict[str, Any]]:
        self.searches.append({"query": query, "category": category, "limit": limit})
        return [{"repo_name": f"match-{query}", "owner": "o", "category": category or "wifi"}]

    def get_cve_repos(self, cve_id: Optional[str] = None,
                       limit: int = 5) -> List[Dict[str, Any]]:
        return [{"owner": "o", "repo_name": f"poc-{cve_id}"}]

    def count(self) -> int:
        return len(self.tools)


class FakeWiFiScanner:
    def __init__(self, networks: Optional[List[Dict[str, Any]]] = None,
                 error: Optional[str] = None,
                 ensure_monitor_result: Optional[Dict[str, Any]] = None,
                 ensure_managed_result: Optional[Dict[str, Any]] = None):
        self._nets = networks if networks is not None else [
            {"ssid": "AP1", "bssid": "AA:BB:CC:DD:EE:01", "channel": 6,
             "encryption": "WPA2", "vendor": "VendorA"},
            {"ssid": "AP2", "bssid": "AA:BB:CC:DD:EE:02", "channel": 11,
             "encryption": "WEP", "vendor": "VendorB"},
        ]
        self._error = error
        self.init_called = False
        # Default: airmon-ng success producing <iface>mon. Tests can
        # override per-instance to exercise the failure / iw-fallback paths.
        self._ensure_monitor_result = ensure_monitor_result
        self._ensure_managed_result = ensure_managed_result
        self.ensure_monitor_calls: List[str] = []
        self.ensure_managed_calls: List[str] = []
        self.calls: List[tuple] = []  # method-name + arg tuples
        self.scan_calls: List[str] = []

    def initialize(self):
        self.init_called = True

    def ensure_monitor(self, iface: str) -> Dict[str, Any]:
        self.ensure_monitor_calls.append(iface)
        self.calls.append(("ensure_monitor", iface))
        if self._ensure_monitor_result is not None:
            return dict(self._ensure_monitor_result)
        # Default behavior: pretend airmon-ng produced <iface>mon.
        return {
            "ok": True,
            "interface": f"{iface}mon",
            "mode": "monitor",
            "method": "airmon",
        }

    def ensure_managed(self, iface: str) -> Dict[str, Any]:
        self.ensure_managed_calls.append(iface)
        self.calls.append(("ensure_managed", iface))
        if self._ensure_managed_result is not None:
            return dict(self._ensure_managed_result)
        # Default behavior: pretend the in-place iw+ip flip succeeded.
        return {
            "ok": True,
            "interface": iface,
            "mode": "managed",
            "method": "iw",
        }

    def restore_managed(self, iface: str):
        """No-op mirror of :meth:`WiFiScanner.restore_managed` for tests.

        ``WiFiScanner.restore_managed`` is fire-and-forget (no return
        value); the fake records the call so tests can assert the
        iw-fallback path was taken. Override the method on the
        instance to simulate a failure.
        """
        self.calls.append(("restore_managed", iface))

    def scan(self, iface, timeout=10):
        self.scan_calls.append(iface)
        return {"networks": list(self._nets), "error": self._error}


class FakeBLEScanner:
    def __init__(self, devices: Optional[List[Dict[str, Any]]] = None,
                 error: Optional[str] = None):
        self._devs = devices if devices is not None else [
            {"name": "Bandage-1", "address": "AA:BB:CC:DD:EE:F1",
             "rssi": -60, "services": ["180d"], "company": "Acme"},
            {"name": "Sensor-2", "address": "AA:BB:CC:DD:EE:F2",
             "rssi": -75, "services": [], "company": "Foo"},
        ]
        self._error = error
        self.init_called = False

    def initialize(self):
        self.init_called = True

    def scan(self, duration=8):
        return {"devices": list(self._devs), "error": self._error}


class FakeConfirmFn:
    """Scripted confirm callable with a ``.confirm`` attribute (for screens
    that call ``self.tui_confirm.confirm``) and direct callability (for the
    orchestrator's ``confirm_fn``)."""

    def __init__(self, answers: Optional[List[bool]] = None, default: bool = False):
        self.answers: List[bool] = list(answers or [])
        self.default = default
        self.prompts: List[str] = []

    def confirm(self, prompt: str, timeout: float = 300.0) -> bool:
        self.prompts.append(prompt)
        if self.answers:
            return self.answers.pop(0)
        return self.default

    __call__ = confirm


class FakePostRunner:
    def __init__(self, ai_plan: str = "1. privesc\n2. credump",
                 msf_steps: Optional[List[Dict[str, Any]]] = None,
                 payload: bytes = b"\x90" * 128,
                 mutated: Optional[bytes] = b"\xcc" * 140):
        self.ai_plan = ai_plan
        self.msf_steps = msf_steps or []
        self.payload = payload
        self.mutated = mutated
        self.plans: List[Dict[str, Any]] = []
        self.executes: List[Dict[str, Any]] = []
        self.payloads: List[Dict[str, Any]] = []

    def plan(self, domain, target, session=None):
        plan = {
            "ai_plan": self.ai_plan,
            "kb_tools": [{"repo_name": "tool-1", "owner": "o"},
                          {"repo_name": "tool-2", "owner": "o"}],
            "msf_plan": {"steps": list(self.msf_steps)} if (session or self.msf_steps) else None,
            "payload_suggestion": None,
            "error": None,
        }
        if not session and not self.msf_steps:
            plan["error"] = "no live session: pass a real session id to build executable msf steps"
        self.plans.append({"domain": domain, "target": target, "session": session})
        return plan

    def execute(self, plan):
        self.executes.append(plan)
        if not plan.get("msf_plan") or not plan["msf_plan"].get("steps"):
            return [{"status": "no executable msf steps — plan only"}]
        return [{"desc": s.get("desc", "step"), "status": "ok"} for s in plan["msf_plan"]["steps"]]

    def generate_payload(self, payload, lhost, lport, encoder="x86/shikata_ga_nai",
                          iterations=5, fmt="raw", use_polymorphic=True):
        self.payloads.append({"payload": payload, "lhost": lhost, "lport": lport})
        return {
            "base": self.payload, "base_len": len(self.payload),
            "encoder": encoder, "iterations": iterations,
            "mutated": self.mutated if use_polymorphic else None,
            "techniques": ["nop_sled", "instruction_substitution", "code_rearrange"]
                          if use_polymorphic else [],
        }


class FakeOSINTRunner:
    def __init__(self, people: Optional[Dict[str, Any]] = None):
        self._people = people or {
            "categories": {
                "username": {"findings": [{"type": "profile", "value": "x.com/alice"}],
                              "ran_tool": "sherlock", "error": None},
                "email": {"findings": [{"type": "email", "value": "alice@x.com"}],
                           "ran_tool": "holehe", "error": None},
            }
        }
        self.people_calls: List[str] = []

    def run_people(self, target, timeout=90):
        self.people_calls.append(target)
        return self._people

    def run_email(self, target, timeout=90):
        return self._people

    def run_username(self, target, timeout=90):
        return self._people


class FakeOrchestrator:
    def __init__(self):
        self.runs: List[Dict[str, Any]] = []
        self.interface = None

    def run(self, domain, target, **kw):
        self.runs.append({"domain": domain, "target": target, "kw": kw})
        return {"domain": domain, "executed": [], "skipped": []}

    def _build_steps(self, domain, seed, report):
        return [{"action": f"{domain}_attack", "tool": "fake_tool"}]

    def _walk_static_step(self, step, seed, report, autonomous=False):
        self.runs.append({"domain": seed.get("domain", "wifi"), "target": seed, "step": step})

    def _maybe_run_gain_access_hooks(self, domain, seed, report, autonomous=False):
        pass


class FakeSettingsManager:
    def __init__(self, settings: Optional[Dict[str, Any]] = None):
        self._settings = settings or {
            "ollama": {"endpoint": "http://127.0.0.1:11434",
                        "domain_models": {"wifi": "xploiter/pentester:latest"}},
            "ai_models": {},
            "scanning": {"wifi_timeout": 10, "ble_timeout": 8},
            "nvd": {"api_key": ""},
        }
        self.updates: List[Dict[str, Any]] = []
        self.resets = 0

    def load_settings(self):
        return self._settings

    def get_settings(self):
        return self._settings

    def update_setting(self, key_path, value):
        self.updates.append({"key": key_path, "value": value})
        # naive nested write so the value is observable
        node = self._settings
        parts = key_path.split(".")
        for p in parts[:-1]:
            node = node.setdefault(p, {})
        node[parts[-1]] = value
        return True

    def get_setting(self, key_path, default=None):
        node = self._settings
        for p in key_path.split("."):
            if not isinstance(node, dict) or p not in node:
                return default
            node = node[p]
        return node

    def reset_to_defaults(self):
        self.resets += 1
        return True

class FakeTerminalRun:
    """Stub return value for FakeExternalTerminal.launch(). Records nothing
    more than the fact that the call happened; tests can inspect
    ``fake.calls`` to see what was launched."""

    def __init__(self, cmd, log_path, term, title=None):
        self.cmd = list(cmd) if cmd else []
        self.log_path = log_path
        self.term = term
        self.title = title or (cmd[0] if cmd else "<cmd>")
        self.returncode = 0
        self.finished = False

    def wait(self, timeout=None):
        self.finished = True
        return 0

    def abort(self):
        self.finished = True
        self.returncode = 130


class FakeExternalTerminal:
    """Drop-in replacement for ExternalTerminalBackend that records every
    ``launch`` call and returns a FakeTerminalRun. Never spawns a real
    process. Injected into WiFiScreen via ``tests/conftest.py`` so the
    curses-free unit tests can assert that the recon pass wires the
    external terminal correctly without ever spawning xterm."""

    def __init__(self, term: str = "xterm"):
        self.term = term
        self.calls: List[Dict[str, Any]] = []

    def detect(self, settings=None) -> str:
        return self.term

    def launch(self, cmd, log_path, settings=None, title=None):
        self.calls.append({
            "cmd": list(cmd) if cmd else [],
            "log_path": log_path,
            "title": title,
        })
        return FakeTerminalRun(cmd, log_path, self.term, title=title)

    def list_available(self):
        return [self.term]

    def __repr__(self):
        return f"FakeExternalTerminal(term={self.term!r})"


class FakeCatalogRecon:
    """Drop-in replacement for CatalogRecon.run() that returns a canned
    recon report. Tests assert on the activity-log lines emitted by
    WiFiScreen.run_attack_chain without actually running wash/airodump
    /hcxpsktool/NVD/KB/catalog."""

    def __init__(self, report: Optional[Dict[str, Any]] = None):
        self.report = report or {
            "wps":         {"ok": True,  "error": None, "data": {"enabled": True,  "locked": False}, "duration_s": 0.4},
            "clients":     {"ok": True,  "error": None, "data": {"count": 2, "clients": []},       "duration_s": 11.0},
            "cves":        {"ok": True,  "error": None, "data": {"count": 3, "cves": []},          "duration_s": 0.8},
            "weakpass":    {"ok": True,  "error": None, "data": {"bytes": 1024, "path": "/tmp/x"},  "duration_s": 5.2},
            "kb_hits":     {"ok": True,  "error": None, "data": {"count": 4, "hits": []},          "duration_s": 0.1},
            "catalog_runs":{"ok": True,  "error": None, "data": {"count": 2, "runs": []},          "duration_s": 0.05},
            "vendor":      "TP-Link",
            "bssid":       "EC:08:6B:11:22:33",
            "ssid":        "TestNet",
            "channel":     "6",
        }
        self.calls: List[Dict[str, Any]] = []

    def run(self):
        self.calls.append({"ran": True})
        return self.report
