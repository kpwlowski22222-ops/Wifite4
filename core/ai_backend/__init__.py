#!/usr/bin/env python3
"""
AI Backend
============
Routes pentesting queries to a local Ollama instance (offline models) as the
PRIMARY provider, falling back to the Groq cloud API, and finally to a real
computed heuristic planner. No canned "AI" strings and no fabricated model
output — if every provider is unreachable, an explicit error is returned.

Ollama models (the operator's pulled set) are mapped per domain:

    wifi            -> xploiter/pentester:latest
    ble             -> xploiter/pentester:latest
    osint           -> huihui_ai/phi4-abliterated:latest
    post_exploitation -> huihui_ai/foundation-sec-abliterated:8b-fp16
    c2              -> supergoatscriptguy/mythos-sec:24b
    fallback        -> wizard-vicuna-uncensored:latest   (used on per-domain 404)
    legacy_fallback -> llama2-uncensored:latest

The Ollama client is synchronous (``requests``) so it can be driven from
curses threads without an asyncio event loop.
"""

import os
import json
import logging
import requests
from typing import Dict, Any, List, Optional

# python-dotenv is optional — the TUI must still boot if it is not installed.
try:
    from dotenv import load_dotenv  # type: ignore
    _HAVE_DOTENV = True
except Exception:  # pragma: no cover - depends on env
    _HAVE_DOTENV = False

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# NVD API key resolution — single source of truth.
# ---------------------------------------------------------------------------
def get_nvd_key(settings=None) -> str:
    """Return the NVD API key with a single, well-defined precedence.

    Order: settings.nvd.api_key → $NVD_API_KEY → "".

    All call sites in the repo go through this function. Never raises
    on a missing key — returns "" so callers can branch on truthiness.
    """
    try:
        if settings is not None:
            v = settings.get_setting("nvd.api_key", "")
            if v:
                return v
        from core.settings import settings_manager  # local import to avoid cycle
        v = settings_manager.get_setting("nvd.api_key", "")
        if v:
            return v
    except Exception:
        pass
    return os.environ.get("NVD_API_KEY", "") or ""


# ---------------------------------------------------------------------------
# Hugging Face token resolution — single source of truth.
# ---------------------------------------------------------------------------
def get_hf_token(settings=None) -> str:
    """Return the Hugging Face token with a single, well-defined precedence.

    Order: settings.hf.token → $HF_TOKEN → "".

    Best-effort: returns "" when absent so callers can branch on truthiness.
    Needed only to pull gated HuggingFace repos; the 0-day triage classifier
    cpranavsharma/Zero-Day-Agent is ungated, so this is usually unneeded.
    """
    try:
        if settings is not None:
            v = settings.get_setting("hf.token", "")
            if v:
                return v
        from core.settings import settings_manager  # local import to avoid cycle
        v = settings_manager.get_setting("hf.token", "")
        if v:
            return v
    except Exception:
        pass
    return os.environ.get("HF_TOKEN", "") or ""


# ---------------------------------------------------------------------------
# Kismet API key resolution — single source of truth.
# ---------------------------------------------------------------------------
# The operator runs the local Kismet server on http://localhost:2501
# (via ``sudo kismet``). The API key is read from
# ``KISMET_API_KEY`` env var. NEVER inline in prompts/argv/logs.
# Pattern matches [[kfiosa-kismet-api-key]] and follows the same
# shape as ``get_nvd_key`` / ``get_hf_token``.
def get_kismet_key(settings=None) -> str:
    """Return the Kismet API key with a single, well-defined precedence.

    Order: settings.kismet.api_key → $KISMET_API_KEY → "".

    Best-effort: returns "" when absent so callers can branch on
    truthiness. The local Kismet server is reachable at
    http://localhost:2501 when the operator has run ``sudo kismet``.
    """
    try:
        if settings is not None:
            v = settings.get_setting("kismet.api_key", "")
            if v:
                return v
        from core.settings import settings_manager  # local import to avoid cycle
        v = settings_manager.get_setting("kismet.api_key", "")
        if v:
            return v
    except Exception:
        pass
    return os.environ.get("KISMET_API_KEY", "") or ""


# ---------------------------------------------------------------------------
# Ollama model catalog (exact pulled tags)
# ---------------------------------------------------------------------------
# Operator instruction 2026-07-22: primary is now ``minimax-m3:cloud``
# (cloud-routed). The previous Qwen2.5-Coder-14B is the local Tier-1
# fallback (handles "ollama cloud unreachable" gracefully). The chain
# order is:
#
#   Tier 0 (primary, cloud)        minimax-m3:cloud
#   Tier 1 (local fallback)         Qwen2.5-Coder-14B-Instruct-Uncensored
#   Tier 2 (planning overlay)       HERETIC 9B
#   Tier 3 (MoE last-resort)        Qwen3-Coder-30B-A3B
#   Tier 4 (legacy fallback)        wizard-vicuna-uncensored
#
# The per-step ACCEPT/CANCEL gate is unchanged. The picker changes
# ONLY the model tag (not the gate, not the prompt safety stance,
# not the chain-stanza catalog).
MODEL_CATALOG: Dict[str, str] = {
    "primary":                "minimax-m3:cloud",
    "tier1_local_fallback":   (
        "roleplaiapp/Qwen2.5-Coder-14B-Instruct-"
        "Uncensored-Q4_K_M-GGUF:Q4_K_M"
    ),
    "tier2_planning_overlay": (
        "mradermacher/Qwen3.5-9B-Claude-4.6-HighIQ-"
        "THINKING-HERETIC-UNCENSORED-GGUF:latest"
    ),
    "tier3_moe_last_resort":  (
        "mradermacher/Qwen3-Coder-30B-A3B-Instruct-"
        "uncensored-i1-GGUF:latest"
    ),
    "wifi":                   "xploiter/pentester:latest",
    "ble":                    "xploiter/pentester:latest",
    "osint":                  "huihui_ai/phi4-abliterated:latest",
    "post_exploitation":      "huihui_ai/foundation-sec-abliterated:8b-fp16",
    "c2":                     "supergoatscriptguy/mythos-sec:24b",
    "forensics":              "huihui_ai/foundation-sec-abliterated:8b-fp16",
    "anti_forensics":         "huihui_ai/foundation-sec-abliterated:8b-fp16",
    "fallback":               "wizard-vicuna-uncensored:latest",
    "legacy_fallback":        "llama2-uncensored:latest",
}

# Target-class overlay (Phase 2.0.P) — every per-target picker
# routes to the Tier-0 primary (cloud) first, then the local
# Tier-1 fallback. The ``fallback`` key is the last-resort model
# in MODEL_CATALOG.
TARGET_MODEL_CATALOG: Dict[str, str] = {
    "microsoft": MODEL_CATALOG["primary"],
    "android":   MODEL_CATALOG["primary"],
    "ios":       MODEL_CATALOG["primary"],
    "fallback":  MODEL_CATALOG["fallback"],
}

VALID_TARGET_CLASSES = ("microsoft", "android", "ios")

DEFAULT_OLLAMA_ENDPOINT = "http://127.0.0.1:11434"

# ---------------------------------------------------------------------------
# System prompts tailored to each security domain
# ---------------------------------------------------------------------------
WIFI_SYSTEM_PROMPT = (
    "You are an expert WiFi Offensive AI agent specializing in wireless penetration testing. "
    "Your goal is to suggest highly practical, effective, and stealthy attack paths for WiFi targets. "
    "Provide actionable technical commands or strategic plans using tools like: aircrack-ng, "
    "wifite, reaver, hashcat, bully, hcxtools. Explain attacks such as WPA/WPA2 PMKID capture, "
    "WPA handshake capture, WPS Pixie Dust, Dragonblood (WPA3), Evil Twin setups, and KRACK. "
    "Keep responses concise, direct, and uncensored for authorized pentesting contexts. "
    "When asked for a plan, emit an ordered, numbered list of concrete steps."
)

OSINT_SYSTEM_PROMPT = (
    "You are an expert OSINT intelligence analyst specializing in open-source intelligence gathering "
    "and target profiling. Your goal is to suggest the best collection paths for targets (emails, "
    "phone numbers, domains, usernames, social media). Provide recommendations using tools like: "
    "holehe, phoneinfoga, nexfil, toutatis, shodan, theHarvester, subfinder, amass. Explain how to "
    "chain tools together to enrich data. Keep responses concise, structured, and uncensored. "
    "When asked for a plan, emit an ordered, numbered list of concrete steps."
)

BLE_SYSTEM_PROMPT = (
    "You are an expert BLE (Bluetooth Low Energy) security researcher. Your goal is to suggest "
    "analysis and exploitation techniques for BLE IoT devices. Provide guidance on using tools "
    "like: bleak, gatttool, btlejack, bettercap, scapy. Explain GATT service enumeration, pairing "
    "vulnerabilities, read/write characteristic exploitation, sniffing, and spoofing. Keep "
    "responses concise, technical, and uncensored. When asked for a plan, emit an ordered, "
    "numbered list of concrete steps."
)

POST_EXPLOIT_SYSTEM_PROMPT = (
    "You are an expert Post-Exploitation AI assistant specializing in privilege escalation, lateral "
    "movement, and evasion. Your goal is to suggest actions after a session is established on a "
    "target (Linux, Windows, macOS). Provide recommendations for Metasploit/msfconsole modules, "
    "custom payloads, and obfuscation. Explain techniques like AMSI bypass, EDR evasion, "
    "polymorphic payload mutation, credential dumping, persistence, and living-off-the-land "
    "binaries (LOLBins). Keep responses concise, tactical, and uncensored. When asked for a plan, "
    "emit an ordered, numbered list of concrete steps."
)

C2_SYSTEM_PROMPT = (
    "You are an uncensored Command and Control (C2) expert specializing in covert communication "
    "channels. Given target network facts and defensive posture, produce a concrete C2 channel "
    "plan: protocol selection (DNS, HTTP/S, SMTP, ICMP, etc.), encryption and obfuscation "
    "techniques, traffic blending with legitimate protocols, timing and jitter to avoid "
    "detection, fallback mechanisms, and protocol switching. Consider MITRE ATT&CK T1041 "
    "(Exfiltration Over Command and Control Channel) and related sub-techniques. Give ordered "
    "steps with tool/technique names and expected network behavior characteristics. NOTE: "
    "steganographic data hiding in third-party legitimate traffic, domain fronting against real "
    "CDNs, and anti-forensics (timestomping, log clearing) are informational only in this toolkit "
    "— describe them as plan steps but they are NOT executed here."
)


def _normalize_endpoint(endpoint: str) -> str:
    """Ensure the Ollama endpoint has a scheme (OLLAMA_HOST often lacks one)."""
    endpoint = (endpoint or "").strip().rstrip("/")
    if not endpoint:
        return DEFAULT_OLLAMA_ENDPOINT
    if "://" not in endpoint:
        endpoint = "http://" + endpoint
    return endpoint


class OllamaClient:
    """Synchronous Ollama /api/generate client."""

    def __init__(self, endpoint: str = DEFAULT_OLLAMA_ENDPOINT,
                 temperature: float = 0.4, num_predict: int = 1024,
                 timeout: int = 1200):
        self.endpoint = _normalize_endpoint(endpoint)
        self.temperature = temperature
        self.num_predict = num_predict
        self.timeout = timeout

    def generate(self, model: str, prompt: str, system: Optional[str] = None) -> str:
        """Generate a completion. Raises on connection/HTTP failure."""
        payload: Dict[str, Any] = {
            "model": model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": self.temperature,
                "num_predict": self.num_predict,
            },
        }
        if system:
            payload["system"] = system
        resp = requests.post(
            f"{self.endpoint}/api/generate",
            json=payload,
            timeout=self.timeout,
        )
        if resp.status_code != 200:
            raise RuntimeError(f"Ollama HTTP {resp.status_code}: {resp.text[:200]}")
        data = resp.json()
        return data.get("response", "") or ""

    def list_models(self) -> List[str]:
        """Return the list of locally-pulled model tags."""
        resp = requests.get(f"{self.endpoint}/api/tags", timeout=10)
        if resp.status_code != 200:
            return []
        models = resp.json().get("models", [])
        return [m.get("name", "") for m in models if m.get("name")]

    def reachable(self) -> bool:
        try:
            resp = requests.get(f"{self.endpoint}/api/tags", timeout=5)
            return resp.status_code == 200
        except Exception:
            return False


class AIBackend:
    """Ollama-first AI backend with Groq fallback and a real heuristic planner."""

    def __init__(self, config: Optional[Dict[str, Any]] = None,
                 settings: Optional[Any] = None):
        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

        # Optional .env loading — must never crash the TUI.
        if _HAVE_DOTENV:
            try:
                load_dotenv(os.path.join(project_root, ".env"))
            except Exception as e:  # pragma: no cover
                logger.warning(f"dotenv load failed: {e}")

        # Read the Ollama block from settings if provided.
        ollama_cfg: Dict[str, Any] = {}
        if settings is not None:
            try:
                ollama_cfg = settings.get_setting("ollama", {}) or {}
            except Exception:
                ollama_cfg = {}
        if not ollama_cfg and isinstance(config, dict):
            ollama_cfg = config.get("ollama", {}) or {}

        endpoint = (
            ollama_cfg.get("endpoint")
            or os.getenv("OLLAMA_HOST")
            or DEFAULT_OLLAMA_ENDPOINT
        )
        self.ollama = OllamaClient(
            endpoint=endpoint,
            temperature=float(ollama_cfg.get("temperature", 0.4)),
            num_predict=int(ollama_cfg.get("num_predict", 1024)),
        )
        # Per-domain model overrides from settings; fall back to the catalog.
        self.domain_models: Dict[str, str] = dict(ollama_cfg.get("domain_models", {}))
        self.settings = settings

        # NVIDIA API / NIM (secondary / offload provider)
        nvidia_cfg = {}
        if settings is not None:
            try:
                nvidia_cfg = settings.get_setting("nvidia", {}) or {}
            except Exception:
                nvidia_cfg = {}
        if not nvidia_cfg and isinstance(config, dict):
            nvidia_cfg = config.get("nvidia", {}) or {}

        self.nvidia_api_key = (
            os.getenv("NVIDIA_API_KEY")
            or os.getenv("NGC_API_KEY")
            or nvidia_cfg.get("api_key")
            or "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"
        )
        self.nvidia_base_url = (
            os.getenv("NVIDIA_BASE_URL")
            or os.getenv("NVIDIA_NIM_ENDPOINT")
            or nvidia_cfg.get("base_url")
            or "https://integrate.api.nvidia.com/v1"
        )
        # Determine model based on whether we query a local NIM endpoint or remote API
        is_local_nim = "127.0.0.1" in self.nvidia_base_url or "0.0.0.0" in self.nvidia_base_url or "localhost" in self.nvidia_base_url
        default_model = "zai-org/GLM-5.2" if is_local_nim else "z-ai/glm-5.2"
        self.nvidia_model = (
            os.getenv("NVIDIA_MODEL")
            or nvidia_cfg.get("model")
            or default_model
        )

        # Groq fallback (cloud) — only used if Ollama and NVIDIA are unreachable.
        self.groq_api_key = (
            os.getenv("GROQ_API_KEY")
            or (config.get("groq_api_key") if isinstance(config, dict) else None)
            or ""
        )
        self.groq_model = (
            os.getenv("GROQ_MODEL")
            or (config.get("groq_model") if isinstance(config, dict) else None)
            or "openai/gpt-oss-120b"
        )
        self.groq_endpoint = "https://api.groq.com/openai/v1/chat/completions"

        self.domain_prompts = {
            "wifi": WIFI_SYSTEM_PROMPT,
            "osint": OSINT_SYSTEM_PROMPT,
            "ble": BLE_SYSTEM_PROMPT,
            "post_exploitation": POST_EXPLOIT_SYSTEM_PROMPT,
            "c2": C2_SYSTEM_PROMPT,
        }

    # ------------------------------------------------------------------
    # Model resolution
    # ------------------------------------------------------------------
    def _model_for(self, domain: str) -> str:
        """Resolve the Ollama model for a domain (settings override → catalog)."""
        m = self.domain_models.get(domain) or MODEL_CATALOG.get(domain)
        return m or MODEL_CATALOG["fallback"]

    def _pick_model_for_target(self, target_class: str) -> str:
        """Pick the AI model for a target_class. Pure. Returns
        ``TARGET_MODEL_CATALOG[target_class]`` for a valid class
        and ``MODEL_CATALOG['fallback']`` otherwise. Does NOT
        bypass the per-step ACCEPT/CANCEL gate (single-gate
        invariant) or any refusal-safety stance; it only chooses
        which model tag to call.

        Recognised target classes: ``"microsoft"``, ``"android"``,
        ``"ios"``. Anything else returns the fallback model.
        """
        tc = (target_class or "").strip().lower()
        if tc in VALID_TARGET_CLASSES:
            return TARGET_MODEL_CATALOG.get(tc,
                                              MODEL_CATALOG["fallback"])
        return MODEL_CATALOG["fallback"]

    def status(self) -> Dict[str, Any]:
        """Report backend availability for the status line / settings screen."""
        ollama_ok = self.ollama.reachable()
        ollama_models = self.ollama.list_models() if ollama_ok else []
        groq_ok = bool(self.groq_api_key)
        nvidia_ok = bool(self.nvidia_api_key)
        
        if ollama_ok:
            active = "ollama"
        elif nvidia_ok:
            active = "nvidia"
        elif groq_ok:
            active = "groq"
        else:
            active = "heuristic"
            
        return {
            "ollama": ollama_ok,
            "ollama_endpoint": self.ollama.endpoint,
            "ollama_models": ollama_models,
            "nvidia": nvidia_ok,
            "nvidia_endpoint": self.nvidia_base_url,
            "nvidia_model": self.nvidia_model,
            "groq": groq_ok,
            "active": active,
        }

    # ------------------------------------------------------------------
    # Tool availability (so the model knows what it can call)
    # ------------------------------------------------------------------
    _tool_registry = None

    def _tool_context_block(self, domain: Optional[str] = None) -> str:
        """Return a compact 'AVAILABLE TOOLS' block from the live registry.

        Built from ``toolboxes/`` + installed Kali packages + ``.venv`` libs.
        Best-effort: any failure returns "" so the AI path is never blocked.
        """
        try:
            if AIBackend._tool_registry is None:
                from core.tool_registry import ToolRegistry
                AIBackend._tool_registry = ToolRegistry()
                AIBackend._tool_registry.load()
            return AIBackend._tool_registry.context_block(domain, limit=20)
        except Exception as e:
            logger.debug(f"tool context block failed: {e}")
            return ""

    def _catalog_context_block(self, domain: Optional[str] = None) -> str:
        """Return a compact 'AVAILABLE KALI PACKAGES' block from the
        offline ``catalog/`` directory (1,130+ entries parsed lazily).

        Best-effort: any failure returns "" so the AI path is never blocked.
        Capped at 20 entries × 240 chars each to keep the prompt small.
        """
        try:
            from core.utils.catalog_loader import get_catalog
            return get_catalog().context_block(domain=domain, limit=20, chars=240)
        except Exception as e:
            logger.debug(f"catalog context block failed: {e}")
            return ""

    # ------------------------------------------------------------------
    # Query
    # ------------------------------------------------------------------
    def query(self, domain: str, user_prompt: str,
              context: Optional[Dict[str, Any]] = None) -> str:
        """Query the AI engine using the specialized domain prompt.

        Routing: Ollama (primary) → Groq (cloud) → heuristic (real computed
        planner). Never returns fabricated/canned model text; on total failure
        returns an explicit error string.
        """
        system_prompt = self.domain_prompts.get(
            domain, "You are a helpful penetration testing assistant."
        )

        context_str = ""
        if context:
            try:
                context_str = "\n[CONTEXT FOR THIS REQUEST]:\n" + json.dumps(
                    context, indent=2, default=str
                )
            except Exception:
                context_str = "\n[CONTEXT]: <unserializable>"

        # Inject the live tool registry so the model knows which tools are
        # actually on this host (cloned toolboxes + Kali packages + venv libs)
        # and can recommend real commands. Best-effort — never blocks the query.
        tools_block = self._tool_context_block(domain)
        if tools_block:
            context_str = f"\n{tools_block}{context_str}"

        # Inject a second block from the offline catalog/ directory: more
        # detailed (apt install, metapackage, summary) than the live
        # registry, so the model can recommend the *right* tool with
        # the right install command. Best-effort.
        catalog_block = self._catalog_context_block(domain)
        if catalog_block:
            context_str = f"\n{catalog_block}{context_str}"

        full_user_prompt = f"{user_prompt}{context_str}"

        logger.info(f"Querying AI Backend for domain: {domain}")

        # 1) Ollama (primary)
        if self.ollama.reachable():
            models = self.ollama.list_models()
            # Try the domain model, then the catalog fallback, then legacy.
            candidates: List[str] = []
            primary = self._model_for(domain)
            candidates.append(primary)
            if primary != MODEL_CATALOG["fallback"]:
                candidates.append(MODEL_CATALOG["fallback"])
            if MODEL_CATALOG["legacy_fallback"] not in candidates:
                candidates.append(MODEL_CATALOG["legacy_fallback"])

            # If we know what's pulled, prefer candidates actually installed;
            # otherwise try them in order (Ollama will 404 the missing ones).
            installed = [c for c in candidates if c in models]
            ordered = installed + [c for c in candidates if c not in installed]

            for model in ordered:
                try:
                    reply = self.ollama.generate(
                        model=model, prompt=full_user_prompt, system=system_prompt
                    )
                    if reply.strip():
                        logger.info(f"Ollama responded with model: {model}")
                        return reply
                except Exception as e:
                    logger.warning(f"Ollama model {model} failed: {e}")
                    continue

        # 2) NVIDIA API / NIM offloader
        if self.nvidia_api_key:
            try:
                # Format url: strip slash and ensure it ends with /chat/completions
                url = self.nvidia_base_url.rstrip("/")
                if not url.endswith("/chat/completions") and not url.endswith("/completions"):
                    url = f"{url}/chat/completions"

                headers = {
                    "Content-Type": "application/json",
                    "accept": "application/json",
                }
                # Remote calls require authentication
                if "integrate.api.nvidia.com" in url or self.nvidia_api_key != "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":
                    headers["Authorization"] = f"Bearer {self.nvidia_api_key}"

                payload = {
                    "model": self.nvidia_model,
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": full_user_prompt},
                    ],
                    "temperature": 0.4,
                    "max_tokens": 1024,
                }
                logger.info(f"Querying NVIDIA API/NIM: {url} (model: {self.nvidia_model})")
                response = requests.post(url, headers=headers, json=payload, timeout=45)
                if response.status_code == 200:
                    reply = response.json()["choices"][0]["message"]["content"]
                    if reply.strip():
                        logger.info(f"NVIDIA API/NIM responded with model: {self.nvidia_model}")
                        return reply
                else:
                    logger.warning(f"NVIDIA API/NIM returned status {response.status_code}: {response.text[:200]}")
            except Exception as e:
                logger.error(f"NVIDIA API/NIM query failed: {e}")

        # 3) Groq fallback
        if self.groq_api_key:
            for model in (
                self.groq_model,
                "llama-3.3-70b-versatile",
                "llama-3.1-8b-instant",
                "mixtral-8x7b-32768",
                "gemma2-9b-it",
            ):
                try:
                    headers = {
                        "Content-Type": "application/json",
                        "Authorization": f"Bearer {self.groq_api_key}",
                    }
                    payload = {
                        "model": model,
                        "messages": [
                            {"role": "system", "content": system_prompt},
                            {"role": "user", "content": full_user_prompt},
                        ],
                        "temperature": 0.4,
                        "max_tokens": 1024,
                    }
                    response = requests.post(
                        self.groq_endpoint, headers=headers, json=payload, timeout=30
                    )
                    if response.status_code == 200:
                        reply = response.json()["choices"][0]["message"]["content"]
                        logger.info(f"Groq responded with model: {model}")
                        return reply
                    logger.warning(
                        f"Groq model {model} failed status {response.status_code}"
                    )
                except Exception as e:
                    logger.error(f"Groq model {model} failed: {e}")

        # 3) Real heuristic planner — NOT canned fake text; computed from target.
        heuristic = self._heuristic(domain, context or {})
        if heuristic:
            return heuristic

        return (
            f"[!] AI backend unavailable: Ollama not reachable at "
            f"{self.ollama.endpoint} and Groq API key not configured. "
            f"Start Ollama (`ollama serve`) and pull a model, or set GROQ_API_KEY."
        )

    # ------------------------------------------------------------------
    # Heuristic planner (last-resort REAL planner, clearly labeled)
    # ------------------------------------------------------------------
    def _heuristic(self, domain: str, target: Dict[str, Any]) -> str:
        """Emit a real, computed plan from the target's actual fields.

        This is a deterministic planner — not fabricated model text. It is
        only reached when both Ollama and Groq are unreachable. Output is
        prefixed with [heuristic] so callers can tell it apart from model
        output.
        """
        if domain == "wifi":
            ssid = target.get("ssid") or target.get("essid") or "unknown"
            bssid = target.get("bssid") or "00:00:00:00:00:00"
            enc = str(
                target.get("encryption") or target.get("privacy") or ""
            ).upper()
            ch = target.get("channel") or "?"
            wps = bool(target.get("wps"))
            iface = target.get("interface") or "<monitor_iface>"
            lines = [
                f"[heuristic] WiFi attack chain for '{ssid}' ({bssid}) ch={ch} enc={enc or '?'} wps={wps}",
                f"1. Start capture: airodump-ng -c {ch} --bssid {bssid} -w cap {iface}",
            ]
            if wps:
                lines.append(f"2. WPS Pixie Dust: reaver -i {iface} -b {bssid} -vv -K 1")
                lines.append("3. If Pixie fails: bully -i {iface} -b {bssid} -v 3")
            else:
                lines.append(
                    f"2. Deauth to force handshake: aireplay-ng -0 5 -a {bssid} {iface}"
                )
                lines.append("3. Crack handshake: hashcat -m 22000 cap.cap wordlist.txt")
            lines.extend([
                "4. Evil twin / captive portal: hostapd + dnsmasq on same channel/SSID",
                "5. Pivot to associated clients with Metasploit (gated, on ACCEPT)",
                "6. Post-exploit: privesc + cred dump + C2 beacon",
            ])
            return "\n".join(lines)

        if domain == "ble":
            addr = target.get("address") or target.get("mac") or "unknown"
            name = target.get("name") or "?"
            lines = [
                f"[heuristic] BLE attack chain for '{name}' ({addr})",
                f"1. GATT enumeration: gatttool -b {addr} -I (primary services/characteristics)",
                f"2. Characteristic read/write abuse: gatttool -b {addr} --char-read/--char-write",
                "3. Pairing downgrade / MITM relay: bettercap -eval 'ble.recon on; ble.enum <addr>'",
                "4. Known-CVE exploitation: KB get_cve_repos + Metasploit (gated, on ACCEPT)",
                "5. Post-exploit + C2 beacon",
            ]
            return "\n".join(lines)

        if domain == "osint":
            tgt = target.get("target") or target.get("query") or "unknown"
            lines = [
                f"[heuristic] OSINT attack chain for '{tgt}'",
                "1. Shodan enrichment: shodan host <ip> / shodan search <query>",
                "2. NVD CVE lookup for exposed services",
                "3. Metasploit exploitation of exposed services (gated, on ACCEPT)",
                "4. Phishing / initial-access plan (informational)",
                "5. Post-exploit + C2 beacon",
            ]
            return "\n".join(lines)

        if domain in ("post_exploitation", "c2"):
            session = target.get("session") or "?"
            lines = [
                f"[heuristic] {'post-exploitation' if domain == 'post_exploitation' else 'C2'} plan for session {session}",
                "1. Local enum: run post/multi/recon/local_exploit_suggester",
                "2. Privilege escalation via suggested module (gated, on ACCEPT)",
                "3. Credential dump: post/windows/gather/credentials or /linux/*",
                "4. Persistence: registry run key / scheduled task / cron (gated)",
                "5. C2 beacon: core/c2/lab_beacon.py (authorized lab only)",
            ]
            return "\n".join(lines)

        return ""

    # ------------------------------------------------------------------
    # Autonomous tool selection (kept for compatibility)
    # ------------------------------------------------------------------
    def autonomous_tool_selection(self, domain: str, target_info: Dict[str, Any]) -> List[str]:
        """AI determines the best sequence of tools based on target info."""
        prompt = (
            "Analyze this target and list ONLY the exact tool/command names to run, "
            "comma-separated, in order: " + json.dumps(target_info, default=str)
        )
        ai_response = self.query(domain, prompt)

        known_tools = [
            "wifite", "aircrack-ng", "reaver", "bully", "hashcat", "hcxdumptool",
            "hcxpcapngtool", "pixiewps", "wash", "hostapd", "dnsmasq",
            "holehe", "phoneinfoga", "sherlock", "toutatis", "theHarvester",
            "subfinder", "amass", "shodan", "nvd", "nmap",
            "bleak", "gatttool", "btlejack", "bettercap", "bluetoothctl", "scapy",
            "msfconsole", "meterpreter", "mimikatz", "msfvenom",
        ]
        selected = [t for t in known_tools if t.lower() in ai_response.lower()]
        if not selected:
            defaults = {
                "wifi": ["airodump-ng", "aireplay-ng", "hashcat"],
                "osint": ["shodan", "theHarvester", "holehe"],
                "ble": ["bleak", "bettercap", "gatttool"],
                "post_exploitation": ["msfconsole", "msfvenom"],
                "c2": ["msfconsole", "msfvenom"],
            }
            selected = defaults.get(domain, ["nmap"])
        return selected


# ---------------------------------------------------------------------------
# Re-exports for the 10 specialized 0-day algorithms
# (Phase 2.2.G+) — keeping them at package root so callers can do
# ``from core.ai_backend import analyze_crash_triager, ZERO_DAY_ALGORITHMS``.
# Imports are best-effort: if the optional module is absent, the
# package still imports cleanly.
# ---------------------------------------------------------------------------
try:
    from .zero_day_algorithms import (
        ZERO_DAY_ALGORITHMS,
        list_algorithms,
        dispatch,
        analyze_crash_triager,
        analyze_side_channel_finder,
        analyze_fuzz_harness_gen,
        analyze_control_flow_surfer,
        analyze_patch_differ,
        analyze_memory_class_predictor,
        analyze_auth_path_auditor,
        analyze_crypto_weakness_finder,
        analyze_race_analyzer,
        analyze_logic_flaw_heuristic,
    )
except Exception:  # pragma: no cover - depends on import order
    pass


# ---------------------------------------------------------------------------
# Phase 2.4: 280 new v3 methods (40 × 7 categories). Re-exported so
# callers can ``from core.ai_backend import V3_REGISTRY``.
# ---------------------------------------------------------------------------
try:
    from .v3_methods import (
        V3_REGISTRY,
        V3_PROMPT_STANZA,
        WIFI_ATTACK_V3_METHODS,
        WIFI_RECON_V3_METHODS,
        BLE_ATTACK_V3_METHODS,
        BLE_RECON_V3_METHODS,
        OSINT_WEB_V3_METHODS,
        OSINT_PEOPLE_V3_METHODS,
        POST_EXPLOIT_V3_METHODS,
        list_v3_methods,
        describe_v3_method,
        describe_v3_category,
        all_v3_method_names,
        total_v3_count,
        build_v3_prompt_stanza,
    )
except Exception:  # pragma: no cover - depends on import order
    pass


# ---------------------------------------------------------------------------
# 4-touchpoint pattern: explicit public surface.
#
# This is the canonical list of symbols the package exports
# via ``from core.ai_backend import X``. Anything not in this
# list is implementation detail and may change without notice.
#
# Modules (re-exported by the try/except above) and submodule
# attributes (``zero_day``, ``zero_day_algorithms``) are listed
# so that ``import core.ai_backend; core.ai_backend.X`` works
# uniformly.
# ---------------------------------------------------------------------------
__all__ = [
    # Constants
    "BLE_SYSTEM_PROMPT",
    "C2_SYSTEM_PROMPT",
    "DEFAULT_OLLAMA_ENDPOINT",
    "MODEL_CATALOG",
    "OSINT_SYSTEM_PROMPT",
    "POST_EXPLOIT_SYSTEM_PROMPT",
    "TARGET_MODEL_CATALOG",
    "VALID_TARGET_CLASSES",
    "WIFI_SYSTEM_PROMPT",
    # Classes
    "AIBackend",
    "OllamaClient",
    # Functions
    "analyze_auth_path_auditor",
    "analyze_control_flow_surfer",
    "analyze_crash_triager",
    "analyze_crypto_weakness_finder",
    "analyze_fuzz_harness_gen",
    "analyze_logic_flaw_heuristic",
    "analyze_memory_class_predictor",
    "analyze_patch_differ",
    "analyze_race_analyzer",
    "analyze_side_channel_finder",
    "dispatch",
    "get_hf_token",
    "get_nvd_key",
    "list_algorithms",
    # Zero-day registry
    "ZERO_DAY_ALGORITHMS",
    # v3 method registry (Phase 2.4)
    "V3_REGISTRY",
    "V3_PROMPT_STANZA",
    "WIFI_ATTACK_V3_METHODS",
    "WIFI_RECON_V3_METHODS",
    "BLE_ATTACK_V3_METHODS",
    "BLE_RECON_V3_METHODS",
    "OSINT_WEB_V3_METHODS",
    "OSINT_PEOPLE_V3_METHODS",
    "POST_EXPLOIT_V3_METHODS",
    "list_v3_methods",
    "describe_v3_method",
    "describe_v3_category",
    "all_v3_method_names",
    "total_v3_count",
    "build_v3_prompt_stanza",
    # Submodules
    "zero_day",
    "zero_day_algorithms",
    "v3_methods",
]
