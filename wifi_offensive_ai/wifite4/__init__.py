"""WiFite4 Integration Module (legacy shim, retained for import safety).

Historical note: this package previously hosted a ``packet_injection``
facade (``EnhancedPacketInjection``) that imported a now-deleted
``core.modules.ath9k_tools``. The ath9k stack was migrated to the
MediaTek MT7922 / ``mt7921e`` driver, and the canonical packet-injection
implementation now lives in :mod:`core.modules.mt7921e_tools`
(``inject(mode=...)``, ``craft_deauth_frame`` / ``craft_fakeauth_frame``
/ ``craft_beacon_frame`` / ``craft_cts_frame``, ``choose_injection_strategy``).

The other historical modules (``engine``, ``ai_chains``, ``zero_day``,
``adapter_handler``) are not present in this tree — their functionality
was absorbed into :mod:`core.ai_backend.chain` (AI-driven chains, re-plan
loop), :mod:`core.post_exploit.runner` + :mod:`metasploit_post_exploit`
(post-exploit), and :mod:`core.modules.mt7921e_tools` (adapter handling).
This file is kept as an import-safe, empty shim so that any stray
``import wifi_offensive_ai.wifite4`` does not raise.
"""

__all__: list[str] = []