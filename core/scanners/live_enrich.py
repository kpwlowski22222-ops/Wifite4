"""Live-time polymorphic background recon for scan targets.

While the operator browses ONLINE/OFFLINE tables, this module quietly
enriches each target with every field we can derive honestly:

  * encryption flags (WPA3/SAE/PMF/WPS/enterprise/open/WEP)
  * band from channel, hidden-SSID detection
  * OUI vendor (AP + associated clients)
  * optional deeper probes (CatalogRecon) chosen polymorphically:
      hidden_ssid, wps, probe_profile, beacon_parse, clients, signal_map

Deep probes are throttled, one-at-a-time, and prefer passive methods.
Never fabricates PSKs/CVEs/access. Disable with ``KFIOSA_LIVE_ENRICH=0``.
"""
from __future__ import annotations

import logging
import os
import re
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Sequence, Set, Tuple

logger = logging.getLogger(__name__)

# Probe cost tiers — cheaper first, polymorphic pick upgrades when gaps remain
_WIFI_PASSIVE = ("flags", "oui", "clients_oui", "band")
_WIFI_DEEP = (
    "hidden_ssid", "wps", "beacon_parse", "probe_profile",
    "clients", "signal_map", "channel_plan",
)
_BLE_PASSIVE = ("flags", "oui", "adv_parse")
_BLE_DEEP = ("services_hint",)


def enrich_enabled() -> bool:
    raw = (os.environ.get("KFIOSA_LIVE_ENRICH") or "1").strip().lower()
    return raw not in ("0", "false", "off", "no")


def _is_hidden_ssid(ssid: Any) -> bool:
    s = str(ssid or "").strip()
    if not s or s in ("<hidden>", "hidden", "?", "null", "None"):
        return True
    # airodump sometimes emits hex \x00…
    if re.fullmatch(r"(\\x00)+", s):
        return True
    return False


def parse_wifi_flags(enc: str) -> Dict[str, Any]:
    """Derive security flags from airodump encryption string (passive)."""
    e = (enc or "").upper()
    flags = {
        "is_open": False,
        "is_wep": False,
        "is_wpa": False,
        "is_wpa2": False,
        "is_wpa3": False,
        "is_sae": False,
        "is_enterprise": False,
        "pmf_supported": False,
        "wps_hint": False,
        "opn": False,
    }
    if not e or e in ("?", "UNKNOWN"):
        return flags
    if "OPN" in e or e.strip() == "OPEN" or "OPEN" in e:
        flags["is_open"] = True
        flags["opn"] = True
    if "WEP" in e:
        flags["is_wep"] = True
    if "WPA3" in e or "SAE" in e:
        flags["is_wpa3"] = True
        flags["is_sae"] = "SAE" in e or "WPA3" in e
    if "WPA2" in e or "CCMP" in e or "RSN" in e:
        flags["is_wpa2"] = True
    if "WPA" in e and not flags["is_wpa2"] and not flags["is_wpa3"]:
        flags["is_wpa"] = True
    if any(x in e for x in ("MGT", "EAP", "802.1X", "ENTERPRISE")):
        flags["is_enterprise"] = True
    # PMF often not in airodump CSV; SAE/WPA3 implies PMF required
    if flags["is_wpa3"] or flags["is_sae"] or "PMF" in e or "MFPC" in e or "MFPR" in e:
        flags["pmf_supported"] = True
    if "WPS" in e:
        flags["wps_hint"] = True
    return flags


def band_from_channel(ch: Any) -> str:
    try:
        c = int(ch)
    except (TypeError, ValueError):
        return ""
    if 1 <= c <= 14:
        return "2.4GHz"
    if 32 <= c <= 196:
        return "5GHz"
    if c >= 1 and c <= 233:  # 6 GHz PSC-ish range
        return "6GHz?"
    return ""


def _oui_vendor(mac: str) -> str:
    mac = (mac or "").upper().replace("-", ":")
    if len(mac) < 8:
        return ""
    try:
        from core.tui.wifi_scan_external import _get_oui_vendor
        v = _get_oui_vendor(mac)
        if v and "Unknown" not in v:
            return v
    except Exception:
        pass
    try:
        from core.ble.runner import _oui_vendor as ov
        v = ov(mac)
        if v and v != "Unknown":
            return str(v)
    except Exception:
        pass
    return ""


def passive_enrich_wifi(ap: Dict[str, Any]) -> Dict[str, Any]:
    """Always-safe local enrichment (no subprocess). Mutates and returns ap.

    Cheap skip when recently enriched with the same encryption/ssid fingerprint
    so the scan UI never pays full OUI/client re-walk every tick.
    """
    # Fast path: skip if enriched recently and key fields unchanged
    try:
        last = float(ap.get("live_enrich_ts") or 0)
        if last and (time.time() - last) < 2.5:
            fp = (
                str(ap.get("encryption") or ap.get("enc") or ""),
                str(ap.get("ssid") or ""),
                int(ap.get("clients_count") or 0),
                str(ap.get("channel") or ""),
            )
            if ap.get("_enrich_fp") == fp:
                return ap
            ap["_enrich_fp"] = fp
        else:
            ap["_enrich_fp"] = (
                str(ap.get("encryption") or ap.get("enc") or ""),
                str(ap.get("ssid") or ""),
                int(ap.get("clients_count") or 0),
                str(ap.get("channel") or ""),
            )
    except Exception:
        pass

    enc = str(ap.get("encryption") or ap.get("enc") or "")
    flags = parse_wifi_flags(enc)
    for k, v in flags.items():
        if k == "pmf_supported":
            if v and not ap.get("pmf") and not ap.get("pmf_supported"):
                ap["pmf"] = True
                ap["pmf_supported"] = True
        elif v and not ap.get(k):
            ap[k] = v
    if flags.get("pmf_supported"):
        ap["pmf"] = True
        ap["pmf_supported"] = True

    ch = ap.get("channel")
    band = band_from_channel(ch)
    if band:
        ap["band"] = band

    ssid = ap.get("ssid")
    hidden = _is_hidden_ssid(ssid)
    ap["hidden"] = hidden
    if hidden and not ap.get("ssid_display"):
        ap["ssid_display"] = "<hidden>"
    elif not hidden:
        ap["ssid_display"] = str(ssid)

    bssid = str(ap.get("bssid") or "").upper()
    if bssid and not ap.get("vendor"):
        v = _oui_vendor(bssid)
        if v:
            ap["vendor"] = v

    # Expand clients to dicts with OUI
    clients = ap.get("clients") or []
    enriched_cli: List[Dict[str, Any]] = []
    for c in clients:
        if isinstance(c, dict):
            entry = dict(c)
            mac = str(entry.get("mac") or entry.get("addr") or "")
        else:
            mac = str(c)
            entry = {"mac": mac}
        if mac and not entry.get("vendor"):
            cv = _oui_vendor(mac)
            if cv:
                entry["vendor"] = cv
        enriched_cli.append(entry)
    if enriched_cli:
        ap["clients"] = enriched_cli
        ap["clients_count"] = len(enriched_cli)
        # Collect unique client vendors
        cvs = sorted({
            str(c.get("vendor")) for c in enriched_cli
            if c.get("vendor")
        })
        if cvs:
            ap["client_vendors"] = cvs[:8]

    # Compact recon badge for list rows
    badges = []
    if ap.get("hidden") and not ap.get("revealed_ssid"):
        badges.append("HID")
    if ap.get("revealed_ssid"):
        badges.append(f"ESSID={str(ap['revealed_ssid'])[:12]}")
        ap["ssid"] = ap["revealed_ssid"]
        ap["ssid_display"] = ap["revealed_ssid"]
        ap["hidden"] = False
    if ap.get("is_wpa3") or ap.get("is_sae"):
        badges.append("WPA3")
    if ap.get("pmf") or ap.get("pmf_supported"):
        badges.append("PMF")
    if ap.get("is_enterprise"):
        badges.append("EAP")
    if ap.get("is_open") or ap.get("opn"):
        badges.append("OPEN")
    if ap.get("is_wep"):
        badges.append("WEP")
    if ap.get("wps") or ap.get("wps_enabled") or ap.get("wps_hint"):
        badges.append("WPS")
    if ap.get("band"):
        badges.append(str(ap["band"]))
    if ap.get("vendor"):
        badges.append(str(ap["vendor"])[:10])
    ap["recon_badges"] = badges
    ap["live_enrich_ts"] = time.time()
    ap.setdefault("enrich_methods", [])
    if "flags" not in ap["enrich_methods"]:
        ap["enrich_methods"] = list(ap["enrich_methods"]) + ["flags", "oui"]
    return ap


def passive_enrich_ble(dev: Dict[str, Any]) -> Dict[str, Any]:
    # Fast skip when recently enriched with same name/rssi fingerprint
    try:
        last = float(dev.get("live_enrich_ts") or 0)
        if last and (time.time() - last) < 2.5:
            fp = (
                str(dev.get("name") or ""),
                int(dev.get("uuid_count") or 0),
                bool(dev.get("connectable")),
            )
            if dev.get("_enrich_fp") == fp:
                return dev
            dev["_enrich_fp"] = fp
    except Exception:
        pass

    addr = str(dev.get("address") or dev.get("addr") or "").upper()
    if addr and not dev.get("vendor"):
        v = _oui_vendor(addr)
        if v:
            dev["vendor"] = v
    name = dev.get("name") or dev.get("local_name") or ""
    if not name or name in ("?", "Unknown", "None"):
        dev["name_missing"] = True
    else:
        dev["name_missing"] = False
    # Manufacturer / service hints already on device
    mfg = dev.get("manufacturer_data") or dev.get("manufacturer")
    if mfg and not dev.get("mfg_note"):
        dev["mfg_note"] = str(mfg)[:40]
    uuids = dev.get("service_uuids") or dev.get("uuids") or []
    if uuids and not dev.get("uuid_count"):
        try:
            dev["uuid_count"] = len(uuids)
        except Exception:
            pass
    badges = []
    if dev.get("connectable"):
        badges.append("CONN")
    if dev.get("vendor"):
        badges.append(str(dev["vendor"])[:10])
    if dev.get("uuid_count"):
        badges.append(f"svc={dev['uuid_count']}")
    if dev.get("name_missing"):
        badges.append("NONAME")
    dev["recon_badges"] = badges
    dev["live_enrich_ts"] = time.time()
    dev.setdefault("enrich_methods", [])
    if "flags" not in (dev.get("enrich_methods") or []):
        dev["enrich_methods"] = list(dev.get("enrich_methods") or []) + ["flags", "oui"]
    return dev


def pick_wifi_deep_probes(ap: Dict[str, Any]) -> List[str]:
    """Polymorphic choice of which deep CatalogRecon probes to run next."""
    done = set(ap.get("enrich_methods") or [])
    missing: List[Tuple[float, str]] = []
    # Score probes by how much value they add for this target shape
    if _is_hidden_ssid(ap.get("ssid")) and "hidden_ssid" not in done:
        missing.append((10.0, "hidden_ssid"))
    if not ap.get("wps") and not ap.get("wps_enabled") and "wps" not in done:
        # open/WPA2 more likely to have WPS
        score = 6.0 if ap.get("is_wpa2") or ap.get("is_wep") else 3.0
        if ap.get("is_wpa3"):
            score = 1.5
        missing.append((score, "wps"))
    if (ap.get("clients_count") or 0) == 0 and "clients" not in done:
        missing.append((5.0, "clients"))
    if "beacon_parse" not in done:
        missing.append((4.0, "beacon_parse"))
    if (ap.get("clients_count") or 0) >= 1 and "probe_profile" not in done:
        missing.append((5.5, "probe_profile"))
    if ap.get("power") is not None and "signal_map" not in done:
        missing.append((3.0, "signal_map"))
    if ap.get("channel") and "channel_plan" not in done:
        missing.append((2.5, "channel_plan"))

    # Poly ensemble soft boost (optional)
    try:
        from core.poly.multi_engine import ensemble_adapt
        env = ensemble_adapt(ap, domain="wifi")
        focus = str(env.get("focus") or "")
        if focus == "sae" and "beacon_parse" in dict(missing).values():
            missing = [(s + 1.0 if m == "beacon_parse" else s, m) for s, m in missing]
        if focus == "pmkid" and "clients" in [m for _, m in missing]:
            missing = [(s + 1.0 if m == "clients" else s, m) for s, m in missing]
    except Exception:
        pass

    missing.sort(key=lambda t: -t[0])
    return [m for _, m in missing[:3]]


def apply_probe_result(ap: Dict[str, Any], method: str, step: Dict[str, Any]) -> None:
    """Merge a CatalogRecon probe step into the live AP dict."""
    data = step.get("data") if isinstance(step.get("data"), dict) else {}
    methods = list(ap.get("enrich_methods") or [])
    if method not in methods:
        methods.append(method)
    ap["enrich_methods"] = methods
    ap["live_enrich_ts"] = time.time()
    if not step.get("ok"):
        errs = dict(ap.get("enrich_errors") or {})
        errs[method] = str(step.get("error") or "failed")[:120]
        ap["enrich_errors"] = errs
        return

    if method == "hidden_ssid":
        if data.get("revealed_ssid"):
            ap["revealed_ssid"] = data["revealed_ssid"]
            ap["ssid"] = data["revealed_ssid"]
            ap["ssid_display"] = data["revealed_ssid"]
            ap["hidden"] = False
            ap["ssid_source"] = data.get("source_frame") or "passive"
        elif data.get("hidden") is True:
            ap["hidden"] = True
    elif method == "wps":
        ap["wps"] = data
        ap["wps_enabled"] = bool(data.get("enabled"))
        ap["wps_locked"] = bool(data.get("locked"))
    elif method == "clients":
        cl = data.get("clients") or data.get("stations") or []
        if cl:
            ap["clients"] = cl
            ap["clients_count"] = len(cl)
        if data.get("aps"):
            ap["recon_aps_snapshot"] = len(data["aps"])
    elif method == "beacon_parse":
        ap["beacon"] = data
        for k in ("pmf", "pmf_supported", "rsn", "vendor_ies", "channel_width"):
            if data.get(k) is not None and ap.get(k) in (None, "", False):
                ap[k] = data[k]
    elif method == "probe_profile":
        ap["probe_profile"] = {
            "watchlist_hits": data.get("watchlist_hits"),
            "shared_ownership_clusters": data.get("shared_ownership_clusters"),
            "client_count": data.get("client_count") or data.get("stations"),
        }
    elif method == "signal_map":
        ap["signal_map"] = data
        if data.get("distance_m") is not None:
            ap["est_distance_m"] = data.get("distance_m")
    elif method == "channel_plan":
        ap["channel_plan"] = data
    # refresh badges after deep merge
    passive_enrich_wifi(ap)


def run_wifi_deep_probe(
    ap: Dict[str, Any],
    *,
    interface: str,
    method: str,
) -> Dict[str, Any]:
    """Run one CatalogRecon probe; returns step dict. Never raises."""
    try:
        from core.modules.catalog_recon import CatalogRecon
        target = dict(ap)
        target["interface"] = interface or target.get("interface") or ""
        target["bssid"] = (target.get("bssid") or "").upper()
        recon = CatalogRecon(target)
        step = recon.run_probe(method)
        apply_probe_result(ap, method, step if isinstance(step, dict) else {})
        return step if isinstance(step, dict) else {"ok": False}
    except Exception as e:  # noqa: BLE001
        apply_probe_result(ap, method, {"ok": False, "error": str(e)[:120]})
        return {"ok": False, "error": str(e)[:120]}


class LiveTargetEnricher:
    """Background worker: passive always, deep probes polymorphic + throttled."""

    def __init__(
        self,
        *,
        domain: str = "wifi",
        interface: str = "",
        get_targets: Optional[Callable[[], List[Dict[str, Any]]]] = None,
        deep_interval_s: float = 4.0,
        max_deep_per_tick: int = 1,
        max_deep_total: int = 40,
    ):
        self.domain = (domain or "wifi").lower()
        self.interface = interface
        self.get_targets = get_targets or (lambda: [])
        self.deep_interval_s = float(deep_interval_s)
        # 0 = passive-only (BLE live UI); >=1 enables deep CatalogRecon probes
        self.max_deep_per_tick = max(0, int(max_deep_per_tick))
        self.max_deep_total = max(0, int(max_deep_total))
        self._thread: Optional[threading.Thread] = None
        self._running = False
        self._lock = threading.RLock()
        self._deep_done: Set[str] = set()  # target_id:method
        self._deep_count = 0
        self.last_error = ""
        self.stats = {
            "passive_ticks": 0,
            "deep_ok": 0,
            "deep_fail": 0,
            "targets_seen": 0,
        }

    def start(self) -> None:
        if not enrich_enabled():
            return
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True, name="live-enrich")
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        t = self._thread
        if t and t.is_alive():
            try:
                t.join(timeout=1.5)
            except Exception:
                pass
        self._thread = None

    def _target_id(self, t: Dict[str, Any]) -> str:
        if self.domain == "ble":
            return str(t.get("address") or t.get("addr") or "").upper()
        return str(t.get("bssid") or "").upper()

    def _loop(self) -> None:
        while self._running:
            try:
                self._tick_passive()
                self._tick_deep()
            except Exception as e:  # noqa: BLE001
                self.last_error = str(e)[:160]
                logger.debug("live enrich tick: %s", e)
            # Responsive stop
            for _ in range(int(max(1, self.deep_interval_s * 4))):
                if not self._running:
                    return
                time.sleep(0.25)

    def _tick_passive(self) -> None:
        targets = list(self.get_targets() or [])
        self.stats["targets_seen"] = max(self.stats["targets_seen"], len(targets))
        # Bound work per tick so huge catalogs never freeze the UI thread
        # (enricher is a daemon; still keep CPU headroom for airodump/curses).
        budget = 48
        for t in targets[:budget]:
            if not isinstance(t, dict):
                continue
            try:
                if self.domain == "ble":
                    passive_enrich_ble(t)
                else:
                    passive_enrich_wifi(t)
            except Exception as e:  # noqa: BLE001
                self.last_error = str(e)[:120]
        self.stats["passive_ticks"] = int(self.stats["passive_ticks"]) + 1

    def _tick_deep(self) -> None:
        if self.max_deep_per_tick <= 0 or self.max_deep_total <= 0:
            return
        if self._deep_count >= self.max_deep_total:
            return
        if self.domain != "wifi":
            # BLE deep stays light — passive is enough for live UI
            return
        targets = [t for t in (self.get_targets() or []) if isinstance(t, dict)]
        # Prefer stronger signal / more clients / hidden first
        def _prio(t: Dict[str, Any]) -> float:
            s = 0.0
            if _is_hidden_ssid(t.get("ssid")) and not t.get("revealed_ssid"):
                s += 50
            try:
                s += max(0, 100 + int(t.get("power") or -100))
            except Exception:
                pass
            s += min(20, int(t.get("clients_count") or 0) * 3)
            done = len(t.get("enrich_methods") or [])
            s -= done * 2  # prefer under-enriched
            return s

        targets.sort(key=_prio, reverse=True)
        launched = 0
        for t in targets:
            if launched >= self.max_deep_per_tick:
                break
            if self._deep_count >= self.max_deep_total:
                break
            tid = self._target_id(t)
            if not tid:
                continue
            probes = pick_wifi_deep_probes(t)
            for method in probes:
                key = f"{tid}:{method}"
                if key in self._deep_done:
                    continue
                # Skip expensive hidden_ssid if no iface
                if method == "hidden_ssid" and not (self.interface or t.get("interface")):
                    continue
                self._deep_done.add(key)
                step = run_wifi_deep_probe(
                    t,
                    interface=str(self.interface or t.get("interface") or ""),
                    method=method,
                )
                self._deep_count += 1
                if step.get("ok"):
                    self.stats["deep_ok"] = int(self.stats["deep_ok"]) + 1
                else:
                    self.stats["deep_fail"] = int(self.stats["deep_fail"]) + 1
                launched += 1
                break  # one probe per target per tick

    def snapshot_stats(self) -> Dict[str, Any]:
        return {
            "ok": True,
            "domain": self.domain,
            "running": self._running,
            "enabled": enrich_enabled(),
            "deep_count": self._deep_count,
            "last_error": self.last_error,
            **self.stats,
        }


def format_enrich_detail(item: Dict[str, Any], kind: str = "wifi") -> str:
    """Extra detail line fragments for the scan UI footer."""
    if not item:
        return ""
    bits: List[str] = []
    badges = item.get("recon_badges") or []
    if badges:
        bits.append("[" + " ".join(str(b) for b in badges[:8]) + "]")
    methods = item.get("enrich_methods") or []
    if methods:
        bits.append("recon=" + ",".join(str(m) for m in methods[-6:]))
    if item.get("revealed_ssid"):
        bits.append(f"revealed={item['revealed_ssid']}")
    if item.get("wps_enabled") is True:
        bits.append("wps=on" + ("/locked" if item.get("wps_locked") else ""))
    if item.get("est_distance_m") is not None:
        bits.append(f"~{item['est_distance_m']}m")
    if item.get("client_vendors"):
        bits.append("cliVend=" + ",".join(item["client_vendors"][:3]))
    if kind.startswith("ble") and item.get("mfg_note"):
        bits.append(f"mfg={item['mfg_note']}")
    return "  ".join(bits)


__all__ = [
    "LiveTargetEnricher",
    "passive_enrich_wifi",
    "passive_enrich_ble",
    "pick_wifi_deep_probes",
    "parse_wifi_flags",
    "format_enrich_detail",
    "enrich_enabled",
    "run_wifi_deep_probe",
]
