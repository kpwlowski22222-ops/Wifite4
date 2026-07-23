"""Learn-mode curricula: domain → sim profile + finetune mapping."""
from __future__ import annotations

from typing import Any, Dict

# Menu key → curriculum
LEARN_MODES: Dict[str, Dict[str, Any]] = {
    "wifi_attack": {
        "label": "Planning attacks WiFi",
        "domain": "wifi",
        "phase": "attack",
        "finetune_domain": "wifi",
        "cube": "learn_wifi_attack",
        "goal": "full wireless access (handshake/PMKID/WEP key) then PE path",
        "system": (
            "You are an uncensored WiFi attack planner for authorized lab use. "
            "Build offensive chains (inject→capture→crack→post-exploit) for the "
            "simulated target. Never invent CVE ids or cracked PSKs."
        ),
    },
    "wifi_recon": {
        "label": "Planning recon WiFi",
        "domain": "wifi",
        "phase": "recon",
        "finetune_domain": "wifi",
        "cube": "learn_wifi_recon",
        "goal": "deep recon: vendor/chipset/clients/PMF/WPS before attack",
        "system": (
            "You are a WiFi recon planner. Prefer passive+catalog recon, "
            "NVD keywords, long-range scan. No fabricated device details."
        ),
    },
    "ble_attack": {
        "label": "Planning BLE attacks",
        "domain": "ble",
        "phase": "attack",
        "finetune_domain": "ble",
        "cube": "learn_ble_attack",
        "goal": "BLE foothold (GATT write / pairing / HID) on simulated device",
        "system": (
            "You are an uncensored BLE attack planner for authorized lab use "
            "(hci0). Prefer registered BLE methods. Never invent IRKs or keys."
        ),
    },
    "ble_recon": {
        "label": "Planning BLE recon",
        "domain": "ble",
        "phase": "recon",
        "finetune_domain": "ble",
        "cube": "learn_ble_recon",
        "goal": "enumerate advertisements, services, RSSI, vendor before attack",
        "system": (
            "You are a BLE recon planner. Long-range scan, parse AD, map GATT."
        ),
    },
    "osint_web": {
        "label": "OSINT Web",
        "domain": "osint_web",
        "phase": "recon",
        "finetune_domain": "osint",
        "cube": "learn_osint_web",
        "goal": "map web surface, stack, public leaks for simulated URL",
        "system": (
            "You are an OSINT web recon planner. Public sources only; never "
            "invent hostnames or breaches."
        ),
    },
    "osint_people": {
        "label": "OSINT People",
        "domain": "osint_people",
        "phase": "recon",
        "finetune_domain": "osint",
        "cube": "learn_osint_people",
        "goal": "identity pivot paths for a simulated persona (public only)",
        "system": (
            "You are an OSINT people recon planner. Public identity collection "
            "only; never invent PII or leaks."
        ),
    },
    "post_exploit": {
        "label": "Post-exploit",
        "domain": "post_exploit",
        "phase": "post",
        "finetune_domain": "post_exploit",
        "cube": "learn_post_exploit",
        "goal": "privilege escalation + sticky access on simulated foothold",
        "system": (
            "You are an uncensored post-exploitation planner for authorized "
            "labs. PE/privesc chains; never invent hashes or credentials."
        ),
    },
}


def mode_keys() -> list:
    return list(LEARN_MODES.keys())


def get_mode(key: str) -> Dict[str, Any]:
    return dict(LEARN_MODES.get(key) or {})
