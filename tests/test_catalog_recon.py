"""Catalog-recon tests (``core.modules.catalog_recon``) + catalog-loader
tests (``core.utils.catalog_loader``).

The recon class is exercised end-to-end against a fake target. We mock
``shutil.which`` and ``subprocess.run`` so no real tools are invoked.
The catalog loader test parses the real ``catalog/`` directory but
tolerates whatever the user has materialized on disk.
"""

import json
from unittest import mock

import pytest


# ---------------------------------------------------------------------------
# Catalog loader
# ---------------------------------------------------------------------------

def test_catalog_load_parses_real_files():
    from core.utils.catalog_loader import load_catalog, CATALOG_DIR
    if not CATALOG_DIR.exists():
        pytest.skip("catalog/ directory not present")
    entries = load_catalog()
    assert len(entries) > 100
    # All entries have an id and kind.
    for e in entries[:50]:
        assert e.id
        assert e.kind


def test_catalog_wifi_entries_filters_by_keyword():
    from core.utils.catalog_loader import get_catalog, WIFI_KEYWORDS
    c = get_catalog()
    wifi = c.wifi_entries(limit=50)
    assert 0 < len(wifi) <= 50
    # Every entry matches at least one WiFi token (use the canonical
    # WIFI_KEYWORDS list — the implementation does the same).
    for e in wifi:
        assert e.matches(list(WIFI_KEYWORDS))


def test_catalog_context_block_wifi():
    from core.utils.catalog_loader import get_catalog
    block = get_catalog().context_block(domain="wifi", limit=5)
    assert "AVAILABLE KALI PACKAGES" in block
    assert "WiFi subset" in block
    assert len(block.splitlines()) >= 5  # header + 5 entries + footer


def test_catalog_context_block_unknown_domain():
    from core.utils.catalog_loader import get_catalog
    block = get_catalog().context_block(domain="unknown_domain_xyz", limit=3)
    # Falls back to "first N entries", still a valid block.
    assert "AVAILABLE KALI PACKAGES" in block
    assert len(block.splitlines()) >= 3


def test_catalog_entry_prompt_line_truncates():
    from core.utils.catalog_loader import CatalogEntry
    e = CatalogEntry(
        id_="kali:test", kind="kali_source_package", name="test",
        title="test", summary="x" * 500, metapackages=[],
        install_apt="sudo apt install test", commands=[],
        source_path="dummy", extra={},
    )
    line = e.prompt_line(chars=120)
    assert len(line) <= 200  # well under the chars cap (we add some metadata)


def test_catalog_entry_matches():
    from core.utils.catalog_loader import CatalogEntry
    e = CatalogEntry(
        id_="kali:aircrack-ng", kind="kali_source_package", name="aircrack-ng",
        title="aircrack-ng", summary="WPA/WPA2 cracking", metapackages=[],
        install_apt="sudo apt install aircrack-ng", commands=[],
        source_path="dummy", extra={},
    )
    # Token in summary (WPA), token in name (aircrack-ng).
    assert e.matches(["wpa"])
    assert e.matches(["aircrack-ng"])
    assert not e.matches(["bluetooth"])


# ---------------------------------------------------------------------------
# Phase 5+ enrichment: matches() searches use_cases +
# command_examples + tags
# ---------------------------------------------------------------------------

def test_catalog_entry_matches_searches_use_cases():
    """Phase 5+ contract: a token that only appears in
    ``use_cases`` (not in name/summary) must still match. The
    operator's curated 'describe as much as possible' requires
    that the LLM can search the catalog by what a tool does."""
    from core.utils.catalog_loader import CatalogEntry
    e = CatalogEntry(
        id_="github:some/repo", kind="external_repository",
        name="repo", title="repo", summary="short summary",
        metapackages=[], install_apt="",
        commands=[], source_path="dummy",
        extra={
            "use_cases": [
                "default-credential scan of an exposed router",
                "fingerprint the device firmware",
            ],
        },
    )
    assert e.matches(["default-credential"])
    assert e.matches(["fingerprint"])
    assert e.matches(["router"])


def test_catalog_entry_matches_searches_command_examples():
    """A token that only appears in ``command_examples`` must
    still match — the LLM can find a tool by its argv shape."""
    from core.utils.catalog_loader import CatalogEntry
    e = CatalogEntry(
        id_="github:some/repo", kind="external_repository",
        name="repo", title="repo", summary="short summary",
        metapackages=[], install_apt="",
        commands=[], source_path="dummy",
        extra={
            "command_examples": [
                "sqlmap -u http://target/?id=1 --dbs",
                "sqlmap -r req.txt --os-shell",
            ],
        },
    )
    assert e.matches(["sqlmap"])
    assert e.matches(["--os-shell"])
    assert e.matches(["req.txt"])


def test_catalog_entry_matches_searches_tags():
    """A token that only appears in ``tags`` must still match —
    the LLM can find a tool by its searchable tag."""
    from core.utils.catalog_loader import CatalogEntry
    e = CatalogEntry(
        id_="github:some/repo", kind="external_repository",
        name="repo", title="repo", summary="short summary",
        metapackages=[], install_apt="",
        commands=[], source_path="dummy",
        extra={"tags": ["pupy", "pythonrat", "c2"]},
    )
    assert e.matches(["pupy"])
    assert e.matches(["c2"])
    assert e.matches(["pythonrat"])


def test_catalog_entry_prompt_line_includes_use_cases():
    """The prompt line must surface the curated ``use_cases``
    block so the LLM sees when to use the tool."""
    from core.utils.catalog_loader import CatalogEntry
    e = CatalogEntry(
        id_="github:some/repo", kind="external_repository",
        name="repo", title="repo", summary="short summary",
        metapackages=[], install_apt="",
        commands=[], source_path="dummy",
        extra={
            "use_cases": [
                "default-credential scan of an exposed router",
            ],
        },
    )
    line = e.prompt_line(chars=200)
    assert "use_cases" in line
    assert "default-credential" in line


def test_catalog_entry_prompt_line_includes_command_examples():
    """The prompt line must surface the curated
    ``command_examples`` block so the LLM sees how to invoke."""
    from core.utils.catalog_loader import CatalogEntry
    e = CatalogEntry(
        id_="github:some/repo", kind="external_repository",
        name="repo", title="repo", summary="short summary",
        metapackages=[], install_apt="",
        commands=[], source_path="dummy",
        extra={
            "command_examples": ["python rsf.py --target <ip>"],
        },
    )
    line = e.prompt_line(chars=200)
    assert "commands" in line
    assert "rsf.py" in line


def test_catalog_real_files_have_enriched_fields():
    """Phase 5+ contract: the on-disk catalog/github_*.json
    entries from the phase5+ emit include ``use_cases`` and
    ``command_examples``."""
    from core.utils.catalog_loader import load_catalog, CATALOG_DIR
    if not CATALOG_DIR.exists():
        pytest.skip("catalog/ directory not present")
    # A subset of entries are auto-emitted from the curated fetch
    # lists (those with documentation.source_list set). We
    # expect >= 50% of those to have use_cases + command_examples.
    entries = load_catalog()
    curated = []
    for e in entries:
        src = e.extra.get("documentation", {}).get("source_list") \
            if isinstance(e.extra, dict) else None
        if src in (
            "fresh_cves.txt", "kali_frameworks.txt", "phase3_more.txt",
            "phase4_offensive.txt", "phase5_more.txt",
            "wireless_ble_ext.txt",
        ):
            curated.append(e)
    if not curated:
        pytest.skip("no curated entries in catalog/")
    with_use_cases = sum(
        1 for e in curated
        if isinstance(e.extra.get("use_cases"), list) and e.extra["use_cases"]
    )
    with_commands = sum(
        1 for e in curated
        if isinstance(e.extra.get("command_examples"), list)
        and e.extra["command_examples"]
    )
    assert with_use_cases >= len(curated) * 0.9, (
        f"only {with_use_cases}/{len(curated)} curated entries "
        f"have use_cases; expected >= 90%"
    )
    assert with_commands >= len(curated) * 0.9, (
        f"only {with_commands}/{len(curated)} curated entries "
        f"have command_examples; expected >= 90%"
    )


# ---------------------------------------------------------------------------
# CatalogRecon
# ---------------------------------------------------------------------------

def _empty_target():
    return {
        "ssid": "TestNet", "bssid": "EC:08:6B:11:22:33",
        "channel": "6", "interface": "wlan0mon",
        "encryption": "WPA2",
    }


def test_recon_constructor_with_no_target_keeps_going():
    from core.modules.catalog_recon import CatalogRecon
    r = CatalogRecon(target={}, nvd_cfg={"api_key": ""},
                     weakpass_outdir="/tmp")
    assert r.bssid == ""
    assert r.ssid == ""
    assert r.vendor == "unknown"


def test_recon_vendor_lookup_known_prefixes():
    from core.modules.catalog_recon import _vendor_for_bssid
    assert _vendor_for_bssid("EC:08:6B:11:22:33") == "TP-Link"
    assert _vendor_for_bssid("00:1A:11:22:33:44") == "Google"
    assert _vendor_for_bssid("00:00:00:00:00:00") == "unknown"
    assert _vendor_for_bssid("") == "unknown"


def test_recon_wps_probe_handles_missing_wash():
    from core.modules.catalog_recon import CatalogRecon
    r = CatalogRecon(target=_empty_target(), nvd_cfg={"api_key": ""},
                     weakpass_outdir="/tmp")
    with mock.patch("core.modules.catalog_recon.shutil.which", return_value=None):
        r._wps_probe()
    assert r.recon["wps"]["ok"] is False
    assert "wash" in (r.recon["wps"]["error"] or "")


def test_recon_wps_probe_handles_wash_output():
    from core.modules.catalog_recon import CatalogRecon
    r = CatalogRecon(target=_empty_target(), nvd_cfg={"api_key": ""},
                     weakpass_outdir="/tmp")
    fake_proc = mock.MagicMock()
    fake_proc.returncode = 0
    fake_proc.stdout = (
        "BSSID Ch dBm WPS Lck Vendor ESSID\n"
        "EC:08:6B:11:22:33  6 -45  2.0  No  TP-Link  TestNet\n"
    )
    fake_proc.stderr = ""
    with mock.patch("core.modules.catalog_recon.shutil.which", return_value="/usr/bin/wash"), \
         mock.patch("core.modules.catalog_recon.subprocess.run", return_value=fake_proc):
        r._wps_probe()
    assert r.recon["wps"]["ok"] is True
    assert r.recon["wps"]["data"]["enabled"] is True
    assert r.recon["wps"]["data"]["locked"] is False


def test_recon_weakpass_skipped_for_open_network():
    from core.modules.catalog_recon import CatalogRecon
    t = _empty_target()
    t["encryption"] = "Open"
    r = CatalogRecon(target=t, nvd_cfg={"api_key": ""},
                     weakpass_outdir="/tmp")
    r._weakpass_wordlist()
    assert r.recon["weakpass"]["ok"] is True
    assert r.recon["weakpass"]["data"].get("count") == 0
    assert "not WPA" in r.recon["weakpass"]["data"].get("note", "")


def test_recon_kb_search_with_no_kb():
    from core.modules.catalog_recon import CatalogRecon
    r = CatalogRecon(target=_empty_target(), nvd_cfg={"api_key": ""},
                     weakpass_outdir="/tmp", kb=None)
    r._kb_search()
    assert r.recon["kb_hits"]["ok"] is True
    assert r.recon["kb_hits"]["data"].get("count") == 0


def test_recon_kb_search_with_fake_kb():
    from core.modules.catalog_recon import CatalogRecon
    fake_kb = mock.MagicMock()
    fake_kb.search = mock.MagicMock(return_value=[
        {"name": "wifi_test_repo", "url": "https://example.com/repo",
         "description": "test repo for wifi"},
    ])
    r = CatalogRecon(target=_empty_target(), nvd_cfg={"api_key": ""},
                     weakpass_outdir="/tmp", kb=fake_kb)
    r._kb_search()
    assert r.recon["kb_hits"]["ok"] is True
    assert r.recon["kb_hits"]["data"]["count"] >= 1
    # The KB was called with both the SSID and the vendor as queries.
    called_with = [c.args[0] for c in fake_kb.search.call_args_list]
    assert "TestNet" in called_with
    assert "TP-Link" in called_with


def test_recon_run_executes_all_six_steps():
    from core.modules.catalog_recon import CatalogRecon
    r = CatalogRecon(target=_empty_target(), nvd_cfg={"api_key": ""},
                     weakpass_outdir="/tmp", kb=None)
    # Mock every step to avoid real subprocess calls.
    for name in ("_wps_probe", "_client_enum", "_cve_search",
                 "_weakpass_wordlist", "_kb_search", "_catalog_iter"):
        setattr(r, name, mock.MagicMock())
    report = r.run()
    # Every step was called.
    for name in ("_wps_probe", "_client_enum", "_cve_search",
                 "_weakpass_wordlist", "_kb_search", "_catalog_iter"):
        getattr(r, name).assert_called_once()
    # Report has the standard shape.
    assert "wps" in report
    assert "clients" in report
    assert "cves" in report
    assert "weakpass" in report
    assert "kb_hits" in report
    assert "catalog_runs" in report
    assert "vendor" in report


def test_recon_persists_json(tmp_path):
    from core.modules.catalog_recon import CatalogRecon
    outdir = tmp_path / "recon"
    r = CatalogRecon(target=_empty_target(), nvd_cfg={"api_key": ""},
                     weakpass_outdir=outdir, kb=None)
    for name in ("_wps_probe", "_client_enum", "_cve_search",
                 "_weakpass_wordlist", "_kb_search", "_catalog_iter"):
        setattr(r, name, mock.MagicMock())
    r.run()
    files = list(outdir.glob("EC086B*.json"))
    assert files, "recon report was not written"
    blob = json.loads(files[0].read_text())
    assert blob["bssid"] == "EC:08:6B:11:22:33"
    assert blob["vendor"] == "TP-Link"
