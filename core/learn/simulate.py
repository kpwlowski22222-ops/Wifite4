"""Polymorphic simulated targets for Learn-mode fine-tuning."""
from __future__ import annotations

import random
import time
import uuid
from typing import Any, Dict, List

# Lab-only synthetic identities — never claimed as real devices/people.
_VENDORS = ("MediaTek", "Broadcom", "Intel", "Realtek", "Qualcomm", "Espressif")
_SSID_PREFIX = ("LabNet", "SimAP", "Range", "CorpSim", "IoT-Lab", "Guest-SIM")
_BLE_NAMES = ("SimBand", "LabBeacon", "PolyTag", "SimLock", "RangeSensor")
_OS_HINTS = ("linux", "windows", "android", "embedded")


def _mac(rng: random.Random) -> str:
    return ":".join(f"{rng.randint(0, 255):02X}" for _ in range(6))


def simulate_target(mode_key: str, *, seed: int = 0) -> Dict[str, Any]:
    """Build one polymorphic simulated target for the learn curriculum."""
    rng = random.Random(seed or (time.time_ns() % (2**32)))
    mid = uuid.uuid4().hex[:8]
    base = {
        "simulated": True,
        "learn_mode": mode_key,
        "sim_id": f"sim-{mid}",
        "injection_capable": True,
        "polymorphic": True,
        "target_adaptive": True,
        "use_ai_chain": True,
        "attach_post_exploit": True,
        "full_auto": False,  # learn path is plan-only unless operator enables
    }

    if mode_key.startswith("wifi"):
        enc = rng.choice(["WPA2", "WPA2", "WPA3", "WEP", "OPEN", "WPA2"])
        clients = rng.randint(0, 6)
        vendor = rng.choice(_VENDORS)
        t = {
            **base,
            "domain": "wifi",
            "bssid": _mac(rng),
            "ssid": f"{rng.choice(_SSID_PREFIX)}-{rng.randint(1, 99)}",
            "channel": rng.choice([1, 6, 11, 36, 40, 44]),
            "encryption": enc,
            "enc": enc,
            "vendor": vendor,
            "chipset": vendor.lower() + "-sim",
            "pmf": enc == "WPA3" or rng.random() < 0.2,
            "wps": enc not in ("WPA3", "OPEN") and rng.random() < 0.35,
            "client_count": clients,
            "clients": [_mac(rng) for _ in range(clients)],
            "power": rng.randint(-85, -35),
            "interface": "wlan0mon",
            "adapter_caps": {
                "mt7921e": True,
                "injection_capable": True,
                "quality": rng.randint(40, 95),
            },
        }
        return t

    if mode_key.startswith("ble"):
        addr = _mac(rng)
        return {
            **base,
            "domain": "ble",
            "address": addr,
            "addr": addr,
            "name": f"{rng.choice(_BLE_NAMES)}-{rng.randint(10, 99)}",
            "rssi": rng.randint(-95, -40),
            "vendor": rng.choice(_VENDORS),
            "connectable": rng.random() < 0.7,
            "adapter": "hci0",
        }

    if mode_key == "osint_web":
        host = f"sim-{mid}.lab.local"
        return {
            **base,
            "domain": "osint_web",
            "url": f"https://{host}/",
            "query": host,
            "name": host,
        }

    if mode_key == "osint_people":
        return {
            **base,
            "domain": "osint_people",
            "query": f"Sim Person {mid.upper()}",
            "name": f"Sim Person {mid.upper()}",
            "email": f"sim.{mid}@lab.example",
        }

    # post_exploit foothold
    return {
        **base,
        "domain": "post_exploit",
        "host": f"10.0.{rng.randint(0, 20)}.{rng.randint(2, 250)}",
        "os": rng.choice(_OS_HINTS),
        "uid": rng.choice(["1000", "1000", "0"]),
        "session_id": f"sim-sess-{mid}",
        "access_achieved": True,
        "transport": "sim",
        "achieved": ["shell", "recon"],
    }


def simulate_batch(mode_key: str, n: int = 3, *, base_seed: int = 0) -> List[Dict[str, Any]]:
    n = max(1, min(int(n or 3), 12))
    out = []
    for i in range(n):
        t = simulate_target(mode_key, seed=(base_seed or 1) * 10007 + i * 97)
        if t.get("domain") == "ble":
            t["addr"] = t.get("address")
        out.append(t)
    return out
