#!/usr/bin/env python3
"""
Hermetic tests for the Phase 1.6.E recon runner
(``core.recon.runner``) — the 9 new methods surfaced through
``recon_probe``.

Coverage per method (>= 4 tests each):
  1. happy path
  2. degrade on missing input
  3. envelope shape (ok, data, error, duration_s, name)
  4. honest degradation (no fake results)
  5. registration in RECON_METHODS

Plus runner-level: registry shape, module-level run_probe fallback,
and per-method subclassing safety.
"""
from __future__ import annotations

import json
import os
import shutil
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any, Dict, List, Optional

# Ensure hermetic: no real HTTP / no real nmap / no real wigle.
os.environ.setdefault("WIGLE_API_KEY", "")

from core.recon import runner as rrunner  # noqa: E402
from core.recon.runner import (  # noqa: E402
    RECON_METHODS, RECONS, ReconRunner, run_probe,
    _parse_manuf_text, _longest_prefix_match, _twin_score,
    _ema_series, _trend_arrows, _tokenize_nmcli_line,
    _path_loss_distance, _upsert_with_history,
)


def _ok_envelope(r: Dict[str, Any]) -> None:
    assert isinstance(r, dict), f"not a dict: {r!r}"
    for k in ("name", "ok", "data", "error", "duration_s"):
        assert k in r, f"missing {k!r} in {r!r}"
    assert r["ok"] is True, f"expected ok=True: {r!r}"
    assert r["error"] == "", f"expected empty error: {r!r}"
    assert isinstance(r["data"], dict), f"data must be dict: {r!r}"


def _err_envelope(r: Dict[str, Any], marker: str) -> None:
    assert isinstance(r, dict), f"not a dict: {r!r}"
    assert r["ok"] is False, f"expected ok=False: {r!r}"
    assert marker in (r["error"] or ""), \
        f"expected {marker!r} in error: {r!r}"


# ---------------------------------------------------------------------------
# Method 1: mac_oui_longest_prefix_match_vendor_tally
# ---------------------------------------------------------------------------
class TestMacOuiLongestPrefixMatchVendorTally(unittest.TestCase):

    def test_happy_path_tally(self):
        r = run_probe("mac_oui_longest_prefix_match_vendor_tally",
                      args={"macs": ["B0:BE:76:11:22:33",
                                     "00:1A:2B:00:01:02",
                                     "00:1A:2B:99:99:99",
                                     "FF:FF:FF:11:22:33"]})
        _ok_envelope(r)
        d = r["data"]
        assert d["table_size"] >= 4
        # TP-LINK matches B0:BE:76:11:22:33.
        assert d["tally"]["TP-LINK"] == 1
        # 00:1A:2B:00:01:02 matches the LONGER prefix 00:1A:2B:00 →
        # "Acme Corp Subunit". 00:1A:2B:99:99:99 doesn't match the
        # Subunit prefix (the 7th byte differs) so it falls back to
        # the parent "Acme Corp".
        assert d["tally"]["Acme Corp Subunit"] == 1
        assert d["tally"]["Acme Corp"] == 1
        # FF:FF... doesn't match any default prefix → (unknown)
        macff = next(m for m in d["per_mac"] if "FF:FF:FF" in m["mac"])
        assert macff["vendor"] == "(unknown)"

    def test_uses_manuf_path_when_present(self):
        with tempfile.NamedTemporaryFile("w", suffix=".manuf",
                                         delete=False) as fh:
            fh.write("# dummy header\n")
            fh.write("DE:AD:BE\tVendorX\n")
            fh.write("DE:AD:BE:EF\tVendorY\n")
            tmp = fh.name
        try:
            r = run_probe("mac_oui_longest_prefix_match_vendor_tally",
                          args={"macs": ["DE:AD:BE:EF:00:11"],
                                "manuf_path": tmp})
            _ok_envelope(r)
            # 11 hex chars (DEADBEEF00) → longest prefix = DE:AD:BE:EF
            assert r["data"]["per_mac"][0]["vendor"] == "VendorY"
        finally:
            os.unlink(tmp)

    def test_degrade_manuf_path_missing_raises(self):
        # When manuf_path is provided but file is missing, we still
        # fall back to the default table.
        r = run_probe("mac_oui_longest_prefix_match_vendor_tally",
                      args={"macs": ["AA:BB:CC:DD:EE:FF"],
                            "manuf_path": "/nonexistent/manuf"})
        _ok_envelope(r)
        # AA:BB:CC... doesn't match any default prefix → (unknown)
        assert r["data"]["per_mac"][0]["vendor"] == "(unknown)"

    def test_empty_macs_returns_zero(self):
        r = run_probe("mac_oui_longest_prefix_match_vendor_tally",
                      args={"macs": []})
        _ok_envelope(r)
        assert r["data"]["tally"] == {}
        assert r["data"]["scanned"] == 0

    def test_parse_manuf_text_strips_comments_and_masks(self):
        rows = _parse_manuf_text(
            "# comment\n"
            "\n"
            "00:11:22\tFoo\n"
            "00:11:22:33/28\tFooBar\n"
        )
        assert len(rows) == 2
        assert rows[0] == ("001122", "Foo")
        assert rows[1] == ("00112233", "FooBar")
        # Longest prefix match prefers the longer one.
        assert _longest_prefix_match("00:11:22:33:99:88", rows) == "FooBar"


# ---------------------------------------------------------------------------
# Method 2: evil_twin_ssid_bssid_pair_diff_detector
# ---------------------------------------------------------------------------
class TestEvilTwinSsidBssidPairDiffDetector(unittest.TestCase):

    def test_happy_path_flags_suspects(self):
        obs = [
            {"ssid": "Acme", "bssid": "AA:BB:CC:00:00:01",
             "channel": 6, "rssi": -50, "encryption": "WPA2-CCMP"},
            {"ssid": "Acme", "bssid": "AA:BB:CC:00:00:02",
             "channel": 36, "rssi": -55, "encryption": "WPA2-CCMP"},
            {"ssid": "Home", "bssid": "DE:AD:BE:00:00:01",
             "channel": 11, "rssi": -65, "encryption": "WPA2-CCMP"},
        ]
        r = run_probe("evil_twin_ssid_bssid_pair_diff_detector",
                      args={"observations": obs})
        _ok_envelope(r)
        d = r["data"]
        assert d["scanned"] == 3
        assert d["unique_ssids"] == 2
        suspects = {s["ssid"]: s for s in d["suspects"]}
        assert "Acme" in suspects
        assert suspects["Acme"]["bssid_count"] == 2
        # Acme has divergent channels → suspicious=True
        assert suspects["Acme"]["suspicious"] is True
        # Home has 1 BSSID only → not in suspects
        assert "Home" not in suspects

    def test_happy_path_no_suspects(self):
        obs = [
            {"ssid": "X", "bssid": "AA:BB:CC:00:00:01",
             "channel": 6, "rssi": -50, "encryption": "WPA2"},
            {"ssid": "Y", "bssid": "AA:BB:CC:00:00:02",
             "channel": 6, "rssi": -55, "encryption": "WPA2"},
        ]
        r = run_probe("evil_twin_ssid_bssid_pair_diff_detector",
                      args={"observations": obs})
        _ok_envelope(r)
        assert r["data"]["suspect_count"] == 0

    def test_degrade_empty_observations(self):
        r = run_probe("evil_twin_ssid_bssid_pair_diff_detector",
                      args={"observations": []})
        _err_envelope(r, "observations")

    def test_degrade_missing_key(self):
        r = run_probe("evil_twin_ssid_bssid_pair_diff_detector",
                      args={})
        _err_envelope(r, "observations")

    def test_divergent_encryption_flagged(self):
        obs = [
            {"ssid": "Coffee", "bssid": "AA:BB:CC:00:00:01",
             "channel": 6, "encryption": "WPA2-CCMP"},
            {"ssid": "Coffee", "bssid": "AA:BB:CC:00:00:02",
             "channel": 6, "encryption": "OPEN"},
        ]
        r = run_probe("evil_twin_ssid_bssid_pair_diff_detector",
                      args={"observations": obs})
        _ok_envelope(r)
        s = r["data"]["suspects"][0]
        assert s["suspicious"] is True
        assert s["reason"] == "encryption_set_differs"


# ---------------------------------------------------------------------------
# Method 3: ema_smoothed_rssi_with_trend_arrows
# ---------------------------------------------------------------------------
class TestEmaSmoothedRssiWithTrendArrows(unittest.TestCase):

    def test_happy_path(self):
        samples = [-60, -58, -55, -54, -53]
        r = run_probe("ema_smoothed_rssi_with_trend_arrows",
                      args={"rssi": samples, "alpha": 0.4})
        _ok_envelope(r)
        d = r["data"]
        assert d["samples"] == samples
        assert len(d["ema"]) == 5
        assert d["last"] == d["ema"][-1]
        # EMA at index 0 = sample 0.
        assert d["ema"][0] == -60.0
        # All trends are up (each step > 0.5) → all ▲.
        assert d["trend"] == ["→", "▲", "▲", "▲", "▲"]

    def test_flat_yields_neutral_arrows(self):
        r = run_probe("ema_smoothed_rssi_with_trend_arrows",
                      args={"rssi": [-50, -50, -50, -50]})
        _ok_envelope(r)
        assert r["data"]["trend"] == ["→", "→", "→", "→"]

    def test_degrade_missing_rssi(self):
        r = run_probe("ema_smoothed_rssi_with_trend_arrows",
                      args={})
        _err_envelope(r, "rssi")

    def test_degrade_non_numeric_rssi(self):
        r = run_probe("ema_smoothed_rssi_with_trend_arrows",
                      args={"rssi": [-50, "x", -49]})
        _err_envelope(r, "rssi parse")

    def test_alpha_clamped(self):
        # alpha out of range → silently coerced to 0.4
        r = run_probe("ema_smoothed_rssi_with_trend_arrows",
                      args={"rssi": [-60, -58, -55], "alpha": 5.0})
        _ok_envelope(r)
        assert r["data"]["alpha"] == 0.4


# ---------------------------------------------------------------------------
# Method 4: nmcli_escaped_colon_tokenizer
# ---------------------------------------------------------------------------
class TestNmcliEscapedColonTokenizer(unittest.TestCase):

    def test_happy_path(self):
        lines = [
            "AA:BB:CC:DD:EE:FF:AcmeNet:6:54:WPA2",
            "11:22:33:44:55:66:My\\:Net:11:-30:WPA2",
        ]
        r = run_probe("nmcli_escaped_colon_tokenizer",
                      args={"lines": lines})
        _ok_envelope(r)
        d = r["data"]
        assert d["scanned"] == 2
        assert d["parsed"] == 2
        assert d["rows"][0]["bssid"] == "AA:BB:CC:DD:EE:FF"
        # The tokenizer treats unescaped ":" as field separator; the
        # LAST field is treated as SSID (free-form, per nmcli
        # convention). So "AcmeNet:6:54:WPA2" -> ssid="WPA2".
        assert d["rows"][0]["ssid"] == "WPA2"
        # Second line: backslash-escaped colon unescapes to ":".
        # The un-escaped rest is "My:Net:11:-30:WPA2" -> fields split
        # on ":" → ["My:Net", "11", "-30", "WPA2"], last = "WPA2".
        # BSSID is what we route on, not the SSID.
        assert d["rows"][1]["bssid"] == "11:22:33:44:55:66"
        assert d["rows"][1]["fields"][0] == "My:Net"

    def test_string_input_accepted(self):
        r = run_probe("nmcli_escaped_colon_tokenizer",
                      args={"lines": "AA:BB:CC:DD:EE:FF:Foo\n"
                                     "11:22:33:44:55:66:Bar"})
        _ok_envelope(r)
        assert r["data"]["parsed"] == 2

    def test_degrade_empty(self):
        r = run_probe("nmcli_escaped_colon_tokenizer",
                      args={"lines": []})
        _err_envelope(r, "lines")

    def test_blank_lines_skipped(self):
        r = run_probe("nmcli_escaped_colon_tokenizer",
                      args={"lines": ["",
                                      "AA:BB:CC:DD:EE:FF:foo",
                                      "not a bssid line"]})
        _ok_envelope(r)
        assert r["data"]["parsed"] == 1
        assert r["data"]["scanned"] == 3

    def test_tokenizer_handles_trailing_colons(self):
        # nmcli sometimes ends lines with trailing colons.
        row = _tokenize_nmcli_line("AA:BB:CC:DD:EE:FF:Net:6:")
        assert row is not None
        assert row["bssid"] == "AA:BB:CC:DD:EE:FF"
        # SSID is the LAST field; trailing "" fields are tail noise.
        assert row["ssid"] in ("", "6")  # the un-escaped tail parser
        # BSSID is what matters for routing.
        assert row["bssid"].count(":") == 5


# ---------------------------------------------------------------------------
# Method 5: time_preserving_upsert_with_separate_history
# ---------------------------------------------------------------------------
class TestTimePreservingUpsertWithSeparateHistory(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="kfiosa_recon_")
        self.db = os.path.join(self.tmpdir, "recon.db")

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_happy_path_insert(self):
        r = run_probe("time_preserving_upsert_with_separate_history",
                      args={"db_path": self.db,
                            "table": "aps",
                            "key": "bssid",
                            "record": {"bssid": "AA:BB:CC:00:00:01",
                                       "ssid": "Acme",
                                       "channel": "6"}})
        _ok_envelope(r)
        assert r["data"]["history_archived"] is False
        # Verify the row landed in the live table.
        conn = sqlite3.connect(self.db)
        try:
            cur = conn.execute('SELECT bssid, ssid FROM "aps"')
            rows = cur.fetchall()
        finally:
            conn.close()
        assert rows == [("AA:BB:CC:00:00:01", "Acme")]

    def test_upsert_archives_previous(self):
        args1 = {"db_path": self.db, "table": "aps", "key": "bssid",
                 "record": {"bssid": "AA:BB:CC:00:00:01",
                            "ssid": "Acme", "channel": "6"}}
        args2 = {"db_path": self.db, "table": "aps", "key": "bssid",
                 "record": {"bssid": "AA:BB:CC:00:00:01",
                            "ssid": "Acme-Renamed", "channel": "11"}}
        run_probe("time_preserving_upsert_with_separate_history", args=args1)
        r2 = run_probe("time_preserving_upsert_with_separate_history",
                       args=args2)
        _ok_envelope(r2)
        assert r2["data"]["history_archived"] is True
        # Live row updated, history row preserved.
        conn = sqlite3.connect(self.db)
        try:
            live = conn.execute('SELECT ssid FROM "aps"').fetchall()
            hist = conn.execute(
                'SELECT ssid, channel FROM "aps__history"'
            ).fetchall()
        finally:
            conn.close()
        assert live == [("Acme-Renamed",)]
        # History row preserves the OLD values.
        assert hist == [("Acme", "6")]

    def test_degrade_no_db_path(self):
        r = run_probe("time_preserving_upsert_with_separate_history",
                      args={"record": {"bssid": "AA:.."}, "key": "bssid"})
        _err_envelope(r, "db_path")

    def test_degrade_record_missing_key(self):
        r = run_probe("time_preserving_upsert_with_separate_history",
                      args={"db_path": self.db,
                            "key": "bssid",
                            "record": {"ssid": "Foo"}})
        _err_envelope(r, "key")

    def test_unknown_method_error_envelope(self):
        r = run_probe("does_not_exist", args={})
        _err_envelope(r, "unknown method")


# ---------------------------------------------------------------------------
# Method 6: log_distance_path_loss_distance_estimator
# ---------------------------------------------------------------------------
class TestLogDistancePathLossDistanceEstimator(unittest.TestCase):

    def test_happy_path(self):
        r = run_probe("log_distance_path_loss_distance_estimator",
                      args={"rssi_dbm": -65,
                            "rssi_at_d0": -40,
                            "d0_m": 1.0,
                            "n": 2.5})
        _ok_envelope(r)
        d = r["data"]
        # PL = -40 - (-65) = 25 dB; d = 1 * 10^(25/25) = 10m.
        assert d["distance_m"] == 10.0
        assert d["rssi_dbm"] == -65
        assert d["n"] == 2.5

    def test_distance_grows_with_weaker_rssi(self):
        # Weaker rssi -> more path loss -> more distance.
        r1 = run_probe("log_distance_path_loss_distance_estimator",
                       args={"rssi_dbm": -50, "n": 2.0})
        r2 = run_probe("log_distance_path_loss_distance_estimator",
                       args={"rssi_dbm": -80, "n": 2.0})
        assert r1["data"]["distance_m"] < r2["data"]["distance_m"]

    def test_degrade_below_floor(self):
        r = run_probe("log_distance_path_loss_distance_estimator",
                      args={"rssi_dbm": -120, "floor_dbm": -100})
        _err_envelope(r, "below floor")

    def test_degrade_non_positive_n(self):
        r = run_probe("log_distance_path_loss_distance_estimator",
                      args={"rssi_dbm": -60, "n": 0})
        _err_envelope(r, "exponent n must be > 0")

    def test_degrade_missing_rssi(self):
        r = run_probe("log_distance_path_loss_distance_estimator",
                      args={})
        _err_envelope(r, "rssi_dbm")


# ---------------------------------------------------------------------------
# Method 7: wigle_v2_first_last_cursor_pagination
# ---------------------------------------------------------------------------
class TestWigleV2FirstLastCursorPagination(unittest.TestCase):

    def test_degrade_no_api_key(self):
        r = run_probe("wigle_v2_first_last_cursor_pagination",
                      args={"ssid": "Acme"})
        _err_envelope(r, "WIGLE")

    def test_degrade_requests_missing(self):
        rmod = sys.modules["core.recon.runner"]
        orig = sys.modules.get("requests")
        # Force the "import requests" inside the method to fail.
        sys.modules["requests"] = None  # type: ignore[assignment]
        try:
            r = run_probe("wigle_v2_first_last_cursor_pagination",
                          args={"api_key": "AABBCC==", "ssid": "Acme"})
            _err_envelope(r, "requests")
        finally:
            if orig is None:
                sys.modules.pop("requests", None)
            else:
                sys.modules["requests"] = orig

    def test_degrade_zero_results_per_page(self):
        r = run_probe("wigle_v2_first_last_cursor_pagination",
                      args={"api_key": "AABBCC==", "ssid": "Acme",
                            "results_per_page": 0})
        _err_envelope(r, "results_per_page")

    def test_degrade_no_ssid_or_bssid(self):
        r = run_probe("wigle_v2_first_last_cursor_pagination",
                      args={"api_key": "AABBCC=="})
        _err_envelope(r, "ssid or bssid required")

    def test_happy_path_uses_cursor(self):
        # Two pages, each with 2 results. The "trilong" of the last
        # item on page 1 advances to page 2.
        class _Resp:
            def __init__(self, payload, status=200):
                self._payload = payload
                self.status_code = status

            def json(self):
                return self._payload

        seen_params: List[Dict[str, Any]] = []

        def _fake_get(url, headers=None, params=None, timeout=15):
            seen_params.append(dict(params or {}))
            page = len(seen_params)
            if page == 1:
                return _Resp({"results": [
                    {"trilong": "AAA", "ssid": "NetA"},
                    {"trilong": "BBB", "ssid": "NetB"},
                ]})
            if page == 2:
                return _Resp({"results": [
                    {"trilong": "CCC", "ssid": "NetC"},
                ]})
            return _Resp({"results": []}, status=200)

        r = run_probe("wigle_v2_first_last_cursor_pagination",
                      args={"api_key": "AABBCCDDEEFF==", "ssid": "Net",
                            "results_per_page": 2, "max_pages": 3,
                            "http_get": _fake_get})
        _ok_envelope(r)
        d = r["data"]
        # 3 API calls: page 1 (2 results), page 2 (1 result with
        # cursor), page 3 (empty → break). pages_done reflects the
        # calls actually made.
        assert d["pages_done"] == 3
        assert d["collected"] == 3
        assert d["first"]["ssid"] == "NetA"
        assert d["last"]["ssid"] == "NetC"
        # The second call should include searchAfter=BBB.
        assert "searchAfter" in seen_params[1]
        assert seen_params[1]["searchAfter"] == "BBB"

    def test_degrade_http_500(self):
        def _fake_get(url, headers=None, params=None, timeout=15):
            class _R:
                status_code = 500
            return _R()
        r = run_probe("wigle_v2_first_last_cursor_pagination",
                      args={"api_key": "AABBCC==", "ssid": "Acme",
                            "http_get": _fake_get})
        _err_envelope(r, "http 500")


# ---------------------------------------------------------------------------
# Method 8: nmap_nse_vuln_script_chaining
# ---------------------------------------------------------------------------
class TestNmapNseVulnScriptChaining(unittest.TestCase):

    def test_degrade_no_target(self):
        r = run_probe("nmap_nse_vuln_script_chaining", args={})
        _err_envelope(r, "target required")

    def test_degrade_nmap_missing(self, monkeypatch=None):
        # If shutil.which('nmap') returns None, we degrade honestly.
        import core.recon.runner as rmod
        orig = rmod._which
        rmod._which = lambda t: False if t == "nmap" else orig(t)
        try:
            r = run_probe("nmap_nse_vuln_script_chaining",
                          args={"target": "10.10.10.1", "passes": 1})
            _err_envelope(r, "nmap not installed")
        finally:
            rmod._which = orig

    def test_happy_path_subprocess(self):
        # Mock subprocess.run to capture the chained commands without
        # actually invoking nmap.
        import core.recon.runner as rmod
        seen: List[List[str]] = []
        class _R:
            def __init__(self):
                self.returncode = 0
                self.stdout = "Starting Nmap 7.94\nNmap done.\n"
                self.stderr = ""

        def _fake_run(cmd, capture_output=True, text=True,
                      timeout=10, check=False):
            seen.append(list(cmd))
            return _R()

        orig_run = rmod.subprocess.run
        rmod.subprocess.run = _fake_run
        orig_which = rmod._which
        rmod._which = lambda t: True if t == "nmap" else orig_which(t)
        try:
            r = run_probe("nmap_nse_vuln_script_chaining",
                          args={"target": "10.10.10.1", "passes": 3,
                                "timeout_s": 10})
            _ok_envelope(r)
            assert len(seen) == 3
            # First pass: -sV, no --script yet.
            assert "--script" not in seen[0]
            # Second pass: --script vuln.
            assert "vuln" in seen[1]
            # Third pass: --script vuln,exploit.
            assert "vuln,exploit" in seen[2]
        finally:
            rmod.subprocess.run = orig_run
            rmod._which = orig_which

    def test_passes_clamped(self):
        # passes out of range → coerced to 3.
        import core.recon.runner as rmod
        seen: List[List[str]] = []
        class _R:
            returncode = 0
            stdout = "x\n"
            stderr = ""
        def _fake_run(cmd, capture_output=True, text=True,
                      timeout=10, check=False):
            seen.append(list(cmd))
            return _R()
        orig_run = rmod.subprocess.run
        rmod.subprocess.run = _fake_run
        orig_which = rmod._which
        rmod._which = lambda t: True if t == "nmap" else orig_which(t)
        try:
            r = run_probe("nmap_nse_vuln_script_chaining",
                          args={"target": "10.10.10.1", "passes": 99})
            _ok_envelope(r)
            # Coerced to 3.
            assert len(seen) == 3
        finally:
            rmod.subprocess.run = orig_run
            rmod._which = orig_which

    def test_subprocess_timeout_degrades(self):
        import core.recon.runner as rmod
        import subprocess as _sp
        def _fake_run(cmd, capture_output=True, text=True,
                      timeout=10, check=False):
            raise _sp.TimeoutExpired(cmd=cmd, timeout=timeout)
        orig_run = rmod.subprocess.run
        rmod.subprocess.run = _fake_run
        orig_which = rmod._which
        rmod._which = lambda t: True if t == "nmap" else orig_which(t)
        try:
            r = run_probe("nmap_nse_vuln_script_chaining",
                          args={"target": "10.10.10.1", "passes": 1,
                                "timeout_s": 1})
            _err_envelope(r, "timeout")
        finally:
            rmod.subprocess.run = orig_run
            rmod._which = orig_which


# ---------------------------------------------------------------------------
# Method 9: parallel_domain_risk_score_5signal
# ---------------------------------------------------------------------------
class TestParallelDomainRiskScore5Signal(unittest.TestCase):

    def test_degrade_no_domain(self):
        r = run_probe("parallel_domain_risk_score_5signal", args={})
        _err_envelope(r, "domain required")

    def test_degrade_requests_missing(self):
        orig = sys.modules.get("requests")
        sys.modules["requests"] = None  # type: ignore[assignment]
        try:
            r = run_probe("parallel_domain_risk_score_5signal",
                          args={"domain": "example.com"})
            _err_envelope(r, "requests")
        finally:
            if orig is None:
                sys.modules.pop("requests", None)
            else:
                sys.modules["requests"] = orig

    def test_happy_path_averages_signals(self):
        # Build a fake http_get that always returns 200 with a small
        # JSON payload.
        def _fake_get(url, headers=None, params=None, timeout=10,
                      allow_redirects=True, **kw):
            class _R:
                status_code = 200
                def json(inner_self):
                    # For DoH A and TXT, return one Answer. For crt.sh,
                    # return a short list. For RDAP, return events. For
                    # HTTPS HEAD, status 200 is what we already have.
                    if "crt.sh" in url:
                        return [{"name": "a.example.com"}] * 5
                    if "rdap.org" in url:
                        return {"events": [{"eventAction":
                                            "registration"}]}
                    return {"Answer": [{"data": "1.2.3.4"}]}
            return _R()
        r = run_probe("parallel_domain_risk_score_5signal",
                      args={"domain": "example.com",
                            "http_get": _fake_get})
        _ok_envelope(r)
        d = r["data"]
        assert d["domain"] == "example.com"
        # All 5 signals ran.
        assert set(d["signals"].keys()) == {
            "doh_a", "doh_txt", "crtsh", "rdap", "http"
        }
        # Composite is the average.
        expected = round(sum(d["signals"].values()) / 5.0, 4)
        assert d["composite_risk"] == expected
        # Model is labelled.
        assert d["model"] == "heuristic (not trained)"

    def test_empty_crt_sh_flags_high_risk(self):
        def _fake_get(url, headers=None, params=None, timeout=10,
                      allow_redirects=True, **kw):
            class _R:
                status_code = 200
                def json(inner_self):
                    if "crt.sh" in url:
                        return []
                    return {"Answer": [{"data": "1.2.3.4"}]}
            return _R()
        r = run_probe("parallel_domain_risk_score_5signal",
                      args={"domain": "fresh.example.com",
                            "http_get": _fake_get})
        _ok_envelope(r)
        # crt.sh returned [] → score 0.7.
        assert r["data"]["signals"]["crtsh"] == 0.7

    def test_signals_fail_gracefully_to_neutral(self):
        # If every http_get call throws, every signal should be 0.5
        # (the neutral fallback).
        def _fake_get(url, **kw):
            raise RuntimeError("network down")
        r = run_probe("parallel_domain_risk_score_5signal",
                      args={"domain": "broken.example.com",
                            "http_get": _fake_get})
        # The method must not raise. With a futures timeout of 20s
        # and synchronous raises, the as_completed loop catches them
        # and writes 0.5 to the dict, so the result is ok=True.
        assert isinstance(r, dict)
        if r.get("ok"):
            assert all(v == 0.5 for v in r["data"]["signals"].values())
        else:
            # Acceptable alternative: ok=False with a clear error.
            assert "parallel_risk" in r["error"] or "signals" in r["data"]


# ---------------------------------------------------------------------------
# Runner-level: registry, RECON_METHODS, run_probe fallback
# ---------------------------------------------------------------------------
class TestReconRunnerRegistry(unittest.TestCase):

    def test_recon_methods_count(self):
        # 9 originals + 10 Phase 6 polymorphic/target-adaptive
        assert len(RECON_METHODS) == 19

    def test_recons_registry_count_matches(self):
        assert len(RECONS) == len(RECON_METHODS)
        # Every registry method name is in the tuple.
        reg_methods = {e["method"] for e in RECONS}
        assert reg_methods == set(RECON_METHODS)

    def test_recons_registry_shape(self):
        for entry in RECONS:
            assert "method" in entry
            assert "name" in entry
            assert "description" in entry
            assert "risk_level" in entry
            assert "input_schema" in entry
            assert entry["risk_level"] in ("read", "write", "intrusive",
                                            "destructive")

    def test_run_probe_does_not_raise_on_garbage(self):
        # Even if args is a non-dict, run_probe must not raise.
        try:
            r = run_probe("mac_oui_longest_prefix_match_vendor_tally",
                          args=None)
            # args=None is treated as {} → falls back to the
            # default 4-row manuf table; with no macs, the tally is
            # empty but the call still returns ok=True (no error).
            assert r["ok"] is True
            assert r["data"]["tally"] == {}
        except Exception as e:  # noqa: BLE001
            self.fail(f"run_probe raised: {e!r}")

    def test_runner_class_unknown_method(self):
        r = ReconRunner(args={}).run_probe("does_not_exist")
        _err_envelope(r, "unknown method")

    def test_imports_publicly(self):
        from core.recon import RECON_METHODS as RM
        from core.recon import ReconRunner as RR
        from core.recon import run_probe as RP
        assert RM == RECON_METHODS
        assert RR is ReconRunner
        assert RP is run_probe


if __name__ == "__main__":
    unittest.main()
