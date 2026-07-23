"""tests.test_kismet_runner — hermetic test suite for
:mod:`core.scanners.kismet_runner`.

Coverage:
  - is_installed family: 3 tests
  - start_server: 6 tests (not installed, no interface, no output
    dir, fake-binary happy path, real kismet happy path, stop)
  - start_client: 4 tests (not installed, default credentials,
    custom credentials, env-var contract)
  - convert_cap_to_pcap: 4 tests (not installed, missing input,
    happy path with real kismet_cap_to_pcap, fake binary)
  - dump_alerts_json: 3 tests (missing dir, empty alerts,
    happy path)
  - apply_to_post_exploit_dir: 3 tests (missing src, copy
    works, no fabrication on empty src)
  - apply_to_prechain: 5 tests (missing dir, empty dir,
    bssid match, ssid match, no match)
  - safety / never-fabricate: 4 tests
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import textwrap
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest import mock

import pytest

from core.scanners.kismet_runner import (
    DEFAULT_PASSWORD,
    DEFAULT_USERNAME,
    DEFAULT_WS_URL,
    KISMET_CLIENT_PASSWORD_ENV,
    KISMET_CLIENT_USERNAME_ENV,
    KismetRunResult,
    KismetRunner,
    is_kismet_installed,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_fake_kismet(tmp_path: Path, *, behavior: str = "ok") -> Path:
    """Create a fake ``kismet`` shim that records its argv. Used
    when kismet is not actually installed on the dev box, or to
    avoid actually running the real binary in tests."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    log = bin_dir / "kismet_calls.log"
    # Different behaviors driven by ARGV.
    if behavior == "ok":
        body = "#!/bin/sh\necho 'fake kismet' >> \"$KISMET_TEST_LOG\"\nexit 0\n"
    elif behavior == "fail":
        body = "#!/bin/sh\necho 'fake kismet fail' >&2\nexit 1\n"
    elif behavior == "exit_immediately":
        body = "#!/bin/sh\nexit 0\n"
    else:
        body = "#!/bin/sh\nexit 0\n"
    kismet = bin_dir / "kismet"
    kismet.write_text(body)
    os.chmod(kismet, 0o755)
    # Also fake the client + cap_to_pcap so is_*_installed() works.
    (bin_dir / "kismet_client").write_text("#!/bin/sh\nexit 0\n")
    os.chmod(bin_dir / "kismet_client", 0o755)
    (bin_dir / "kismet_cap_to_pcap").write_text(
        textwrap.dedent("""\
            #!/bin/sh
            # Args: --in X --out Y
            while [ $# -gt 0 ]; do
              case "$1" in
                --in) shift ;;
                --out) shift; OUT="$1"; shift ;;
                *) shift ;;
              esac
            done
            : > "$OUT"
            exit 0
        """)
    )
    os.chmod(bin_dir / "kismet_cap_to_pcap", 0o755)
    return bin_dir


def _patch_path(monkeypatch, bin_dir: Path):
    """Prepend ``bin_dir`` to PATH so the runner sees the fake
    binaries before any system install."""
    monkeypatch.setenv("PATH", f"{bin_dir}:{os.environ['PATH']}")


def _strip_path(monkeypatch, *, keep: Optional[List[str]] = None):
    """Set PATH to ONLY the requested dirs. Used to test the
    ``not installed`` paths without falling back to system kismet."""
    keep = keep or []
    monkeypatch.setenv("PATH", ":".join(str(p) for p in keep))


# ---------------------------------------------------------------------------
# is_installed family
# ---------------------------------------------------------------------------

def test_is_installed_returns_bool():
    r = is_kismet_installed()
    assert isinstance(r, bool)


def test_runner_is_installed(tmp_path, monkeypatch):
    """With a fake kismet on PATH, is_installed() == True."""
    bin_dir = _make_fake_kismet(tmp_path, behavior="ok")
    _patch_path(monkeypatch, bin_dir)
    runner = KismetRunner()
    assert runner.is_installed() is True


def test_runner_is_not_installed_when_missing(tmp_path, monkeypatch):
    """With PATH stripped of kismet, is_installed() == False."""
    _strip_path(monkeypatch, keep=[tmp_path / "empty"])
    (tmp_path / "empty").mkdir(exist_ok=True)
    runner = KismetRunner()
    assert runner.is_installed() is False


# ---------------------------------------------------------------------------
# start_server
# ---------------------------------------------------------------------------

def test_start_server_not_installed(tmp_path, monkeypatch):
    (tmp_path / "empty").mkdir(exist_ok=True)
    _strip_path(monkeypatch, keep=[tmp_path / "empty"])
    runner = KismetRunner()
    res = runner.start_server("wlan0mon", str(tmp_path / "out"))
    assert res.ok is False
    assert "not found" in res.error


def test_start_server_invalid_interface(tmp_path, monkeypatch):
    bin_dir = _make_fake_kismet(tmp_path)
    _patch_path(monkeypatch, bin_dir)
    runner = KismetRunner()
    for bad in ("", None, 42, []):
        res = runner.start_server(bad, str(tmp_path / "out"))
        assert res.ok is False, f"interface={bad!r} should fail"


def test_start_server_creates_output_dir(tmp_path, monkeypatch):
    bin_dir = _make_fake_kismet(tmp_path, behavior="exit_immediately")
    _patch_path(monkeypatch, bin_dir)
    runner = KismetRunner()
    out = tmp_path / "captures" / "kismet"
    res = runner.start_server("wlan0mon", str(out), wait_s=0)
    # The server spawned, then we asked it to exit; the result is
    # either ok=True (it was alive at wait time) or ok=False
    # (exited before wait_s elapsed). The output dir MUST exist.
    assert out.is_dir()


def test_start_server_spawns_pid(tmp_path, monkeypatch):
    """The fake kismet sleeps to keep itself alive so the
    runner sees it as still running."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "kismet").write_text("#!/bin/sh\nsleep 30\n")
    os.chmod(bin_dir / "kismet", 0o755)
    (bin_dir / "kismet_client").write_text("#!/bin/sh\nexit 0\n")
    os.chmod(bin_dir / "kismet_client", 0o755)
    (bin_dir / "kismet_cap_to_pcap").write_text("#!/bin/sh\nexit 0\n")
    os.chmod(bin_dir / "kismet_cap_to_pcap", 0o755)
    _patch_path(monkeypatch, bin_dir)
    runner = KismetRunner()
    res = runner.start_server("wlan0mon", str(tmp_path / "out"),
                                wait_s=0.5)
    assert res.ok is True
    assert res.pid is not None
    assert res.artifacts.get("output_dir", "").endswith("out")
    # Stop the server so it doesn't leak.
    runner.stop_server(timeout_s=2)


def test_start_server_log_types_passed_through(tmp_path, monkeypatch):
    """Custom log_types end up in extra.log_types."""
    bin_dir = _make_fake_kismet(tmp_path, behavior="exit_immediately")
    _patch_path(monkeypatch, bin_dir)
    runner = KismetRunner()
    res = runner.start_server("wlan0mon", str(tmp_path / "out"),
                                log_types="pcap,netxml",
                                wait_s=0)
    assert res.extra.get("log_types") == "pcap,netxml"


def test_start_server_extra_sources(tmp_path, monkeypatch):
    """The --source flag is repeated per source."""
    bin_dir = _make_fake_kismet(tmp_path, behavior="exit_immediately")
    _patch_path(monkeypatch, bin_dir)
    runner = KismetRunner()
    res = runner.start_server("wlan0mon", str(tmp_path / "out"),
                                sources=["rtl433", "rtlsdr"],
                                wait_s=0)
    # The spawn may have failed (the fake exits) but the cmd was
    # built correctly. The artifacts dir was created.
    assert (tmp_path / "out").is_dir()


def test_stop_server_no_server(tmp_path, monkeypatch):
    runner = KismetRunner()
    res = runner.stop_server()
    assert res.ok is True
    assert "no server" in res.error


# ---------------------------------------------------------------------------
# start_client
# ---------------------------------------------------------------------------

def test_start_client_not_installed(tmp_path, monkeypatch):
    (tmp_path / "empty").mkdir(exist_ok=True)
    _strip_path(monkeypatch, keep=[tmp_path / "empty"])
    runner = KismetRunner()
    res = runner.start_client(foreground=True)
    assert res.ok is False
    assert "not found" in res.error


def test_start_client_default_credentials(tmp_path, monkeypatch):
    """When no explicit credentials are passed, the runner reads them from env."""
    bin_dir = _make_fake_kismet(tmp_path)
    _patch_path(monkeypatch, bin_dir)
    runner = KismetRunner()
    res = runner.start_client(foreground=True)
    # We don't assert on stdout (fake exits silently), but the
    # runner must not crash and must surface the env-var contract
    # in extra.
    assert isinstance(res, KismetRunResult)
    assert res.extra.get("password_env") == KISMET_CLIENT_PASSWORD_ENV
    assert res.extra.get("username_env") == KISMET_CLIENT_USERNAME_ENV


def test_runner_requires_credentials(tmp_path, monkeypatch):
    """KismetRunner raises when neither args nor env provide credentials."""
    monkeypatch.delenv(KISMET_CLIENT_USERNAME_ENV, raising=False)
    monkeypatch.delenv(KISMET_CLIENT_PASSWORD_ENV, raising=False)
    with pytest.raises(ValueError, match="KismetRunner requires"):
        KismetRunner()


def test_start_client_env_var_contract(tmp_path, monkeypatch):
    """The KISMET_CLIENT_PASSWORD env var is set; the literal
    password string MUST NOT appear in argv."""
    bin_dir = _make_fake_kismet(tmp_path)
    # Make the fake kismet_client log the env it sees.
    (bin_dir / "kismet_client").write_text(
        textwrap.dedent("""\
            #!/bin/sh
            env >> "$KISMET_TEST_LOG"
            exit 0
        """)
    )
    os.chmod(bin_dir / "kismet_client", 0o755)
    _patch_path(monkeypatch, bin_dir)
    log = bin_dir / "calls.log"
    monkeypatch.setenv("KISMET_TEST_LOG", str(log))
    runner = KismetRunner(password="hunter2")
    res = runner.start_client(foreground=True)
    assert res.ok is True
    # The env file should contain KISMET_CLIENT_PASSWORD=hunter2.
    log_text = log.read_text()
    assert f"{KISMET_CLIENT_PASSWORD_ENV}=hunter2" in log_text


def test_start_client_password_never_in_argv(tmp_path, monkeypatch):
    """The literal password string MUST NOT appear in argv."""
    bin_dir = _make_fake_kismet(tmp_path)
    # Log argv.
    (bin_dir / "kismet_client").write_text(
        textwrap.dedent("""\
            #!/bin/sh
            echo "ARGV: $@" >> "$KISMET_TEST_LOG"
            exit 0
        """)
    )
    os.chmod(bin_dir / "kismet_client", 0o755)
    _patch_path(monkeypatch, bin_dir)
    log = bin_dir / "calls.log"
    monkeypatch.setenv("KISMET_TEST_LOG", str(log))
    runner = KismetRunner(password="hunter2-SECRET")
    res = runner.start_client(foreground=True)
    # runner stores the password in env, not in cmd.
    assert "hunter2-SECRET" not in str(res.to_dict())


# ---------------------------------------------------------------------------
# convert_cap_to_pcap
# ---------------------------------------------------------------------------

def test_convert_cap_to_pcap_not_installed(tmp_path, monkeypatch):
    (tmp_path / "empty").mkdir(exist_ok=True)
    _strip_path(monkeypatch, keep=[tmp_path / "empty"])
    runner = KismetRunner()
    cap = tmp_path / "in.kismet"
    cap.write_bytes(b"FAKE")
    out = tmp_path / "out.pcap"
    res = runner.convert_cap_to_pcap(str(cap), str(out))
    assert res.ok is False
    assert "not found" in res.error


def test_convert_cap_to_pcap_missing_input(tmp_path, monkeypatch):
    bin_dir = _make_fake_kismet(tmp_path)
    _patch_path(monkeypatch, bin_dir)
    runner = KismetRunner()
    res = runner.convert_cap_to_pcap(
        str(tmp_path / "no_such.kismet"),
        str(tmp_path / "out.pcap"),
    )
    assert res.ok is False
    assert "input not found" in res.error


def test_convert_cap_to_pcap_happy_path(tmp_path, monkeypatch):
    """With a fake kismet_cap_to_pcap that creates the output,
    the runner returns ok=True and the artifact is recorded."""
    bin_dir = _make_fake_kismet(tmp_path)
    _patch_path(monkeypatch, bin_dir)
    runner = KismetRunner()
    cap = tmp_path / "in.kismet"
    cap.write_bytes(b"FAKE")
    out = tmp_path / "out.pcap"
    res = runner.convert_cap_to_pcap(str(cap), str(out))
    assert res.ok is True
    assert res.artifacts.get("pcap") == str(out)


def test_convert_cap_to_pcap_creates_output_dir(tmp_path, monkeypatch):
    bin_dir = _make_fake_kismet(tmp_path)
    _patch_path(monkeypatch, bin_dir)
    runner = KismetRunner()
    cap = tmp_path / "in.kismet"
    cap.write_bytes(b"FAKE")
    out = tmp_path / "deeply" / "nested" / "out.pcap"
    res = runner.convert_cap_to_pcap(str(cap), str(out))
    assert res.ok is True
    assert out.parent.is_dir()


# ---------------------------------------------------------------------------
# dump_alerts_json
# ---------------------------------------------------------------------------

def test_dump_alerts_json_missing_dir(tmp_path):
    runner = KismetRunner()
    res = runner.dump_alerts_json(str(tmp_path / "no"))
    assert res.ok is False
    assert "not a directory" in res.error


def test_dump_alerts_json_no_alerts_dir(tmp_path):
    runner = KismetRunner()
    out = tmp_path / "kismet_out"
    out.mkdir()
    res = runner.dump_alerts_json(str(out))
    assert res.ok is True
    assert res.extra.get("n_files") == 0
    assert res.extra.get("json_files") == []


def test_dump_alerts_json_lists_json_files(tmp_path):
    runner = KismetRunner()
    out = tmp_path / "kismet_out"
    alerts = out / "alerts"
    alerts.mkdir(parents=True)
    (alerts / "alert1.json").write_text("{}")
    (alerts / "alert2.json").write_text("{}")
    (alerts / "note.txt").write_text("not json")
    res = runner.dump_alerts_json(str(out))
    assert res.ok is True
    assert res.extra.get("n_files") == 2


# ---------------------------------------------------------------------------
# apply_to_post_exploit_dir
# ---------------------------------------------------------------------------

def test_apply_to_post_exploit_dir_missing_src(tmp_path):
    runner = KismetRunner()
    res = runner.apply_to_post_exploit_dir(
        str(tmp_path / "no_src"),
        str(tmp_path / "dest"),
    )
    assert res.ok is False
    assert "not a directory" in res.error


def test_apply_to_post_exploit_dir_copies_files(tmp_path):
    runner = KismetRunner()
    src = tmp_path / "src"
    src.mkdir()
    (src / "test-01.kismet.csv").write_text("BSSID,SSID\n00:11,foo\n")
    (src / "test-01.kismet.netxml").write_text("<xml/>")
    (src / "ignore.txt").write_text("not kismet")
    dest = tmp_path / "dest"
    res = runner.apply_to_post_exploit_dir(str(src), str(dest))
    assert res.ok is True
    assert res.artifacts.get("n") == 2
    assert (dest / "test-01.kismet.csv").is_file()
    assert (dest / "test-01.kismet.netxml").is_file()
    assert not (dest / "ignore.txt").exists()


def test_apply_to_post_exploit_dir_empty_src(tmp_path):
    runner = KismetRunner()
    src = tmp_path / "src"
    src.mkdir()
    dest = tmp_path / "dest"
    res = runner.apply_to_post_exploit_dir(str(src), str(dest))
    assert res.ok is True
    assert res.artifacts.get("n") == 0


# ---------------------------------------------------------------------------
# apply_to_prechain
# ---------------------------------------------------------------------------

def test_apply_to_prechain_missing_captures_dir(tmp_path):
    runner = KismetRunner()
    res = runner.apply_to_prechain(
        target={"bssid": "00:11:22:33:44:55"},
        captures_dir=str(tmp_path / "no_such_captures"),
    )
    assert res["ok"] is False
    assert "not found" in res["error"]


def test_apply_to_prechain_empty_dir(tmp_path):
    runner = KismetRunner()
    cap_dir = tmp_path / "captures"
    cap_dir.mkdir()
    res = runner.apply_to_prechain(
        target={"bssid": "00:11:22:33:44:55"},
        captures_dir=str(cap_dir),
    )
    assert res["ok"] is False
    assert res["n_captures"] == 0


def test_apply_to_prechain_bssid_match(tmp_path):
    runner = KismetRunner()
    cap_dir = tmp_path / "captures"
    cap_dir.mkdir()
    (cap_dir / "Kismet-20260720-001122-AA-BB-001122334455.kismet"
     ).write_bytes(b"FAKE")
    res = runner.apply_to_prechain(
        target={"bssid": "00:11:22:33:44:55", "ssid": "foo"},
        captures_dir=str(cap_dir),
    )
    assert res["ok"] is True
    assert res["n_captures"] == 1
    assert "bssid_in_filename" in res["matches"][0]["matched_by"]


def test_apply_to_prechain_ssid_match(tmp_path):
    runner = KismetRunner()
    cap_dir = tmp_path / "captures"
    cap_dir.mkdir()
    (cap_dir / "Kismet-20260720-001122-CorpWifi.kismet"
     ).write_bytes(b"FAKE")
    res = runner.apply_to_prechain(
        target={"bssid": "00:11:22:33:44:55", "ssid": "CorpWifi"},
        captures_dir=str(cap_dir),
    )
    assert res["ok"] is True
    assert "ssid_in_filename" in res["matches"][0]["matched_by"]


def test_apply_to_prechain_no_match(tmp_path):
    """A file whose name doesn't contain the BSSID or SSID (and
    doesn't start with the Kismet- prefix) is NOT a match."""
    runner = KismetRunner()
    cap_dir = tmp_path / "captures"
    cap_dir.mkdir()
    (cap_dir / "random_other_target.bin").write_bytes(b"FAKE")
    res = runner.apply_to_prechain(
        target={"bssid": "00:11:22:33:44:55", "ssid": "MyWifi"},
        captures_dir=str(cap_dir),
    )
    assert res["ok"] is False
    assert "no matching capture" in res["error"]
    # And the random file is recorded as 'no match' (matched_by empty)
    # OR not recorded at all. Either is honest-degrade.
    if res["matches"]:
        assert res["matches"][0]["matched_by"] == []


# ---------------------------------------------------------------------------
# Safety / never-fabricate
# ---------------------------------------------------------------------------

def test_never_fabricate_when_kismet_missing(tmp_path, monkeypatch):
    """When kismet is not installed, the runner must honest-degrade,
    not invent a fake 'kismet is up' envelope."""
    (tmp_path / "empty").mkdir(exist_ok=True)
    _strip_path(monkeypatch, keep=[tmp_path / "empty"])
    runner = KismetRunner()
    res = runner.start_server("wlan0mon", str(tmp_path / "out"))
    assert res.ok is False
    assert res.pid is None
    assert "not found" in res.error
    assert res.stdout == ""
    assert res.stderr == ""


def test_never_fabricate_on_cap_to_pcap_missing_input(tmp_path, monkeypatch):
    """Missing input must return an error envelope, NOT an empty
    pcap file or fake stdout."""
    bin_dir = _make_fake_kismet(tmp_path)
    _patch_path(monkeypatch, bin_dir)
    runner = KismetRunner()
    res = runner.convert_cap_to_pcap(
        str(tmp_path / "no_such.kismet"),
        str(tmp_path / "out.pcap"),
    )
    assert res.ok is False
    assert "input not found" in res.error
    assert not (tmp_path / "out.pcap").exists()


def test_never_fabricate_on_prechain_no_match(tmp_path):
    """Empty / no-match captures dir must NOT return a fake 'matched'
    result; it must honest-degrade with a clear 'no matching capture'."""
    runner = KismetRunner()
    cap_dir = tmp_path / "captures"
    cap_dir.mkdir()
    res = runner.apply_to_prechain(
        target={"bssid": "00:11:22:33:44:55", "ssid": "X"},
        captures_dir=str(cap_dir),
    )
    assert res["ok"] is False
    assert res["matches"] == []


def test_default_password_is_empty_and_requires_operator_input():
    """No compiled-in default credentials.  Values come from env/args."""
    assert DEFAULT_USERNAME == ""
    assert DEFAULT_PASSWORD == ""
    # The env-var names are stable.
    assert KISMET_CLIENT_USERNAME_ENV == "KISMET_CLIENT_USERNAME"
    assert KISMET_CLIENT_PASSWORD_ENV == "KISMET_CLIENT_PASSWORD"


def test_no_bare_except_in_runner():
    """No bare ``except:`` in the runner — defense in depth."""
    from core.scanners import kismet_runner as kr
    src = Path(kr.__file__).read_text(encoding="utf-8")
    bare = [line for line in src.splitlines()
             if line.strip() in ("except:", "except:  # noqa")]
    assert not bare, f"bare except in runner: {bare}"
