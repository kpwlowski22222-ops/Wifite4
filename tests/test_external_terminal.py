"""Tests for ``core.utils.external_terminal`` — auto-detect chain +
launcher. No real terminal is spawned; we only verify the detection
chain, persistence, and that :class:`FakeExternalTerminal` records
calls correctly.
"""

import shutil
from unittest import mock

import pytest

from core.utils.external_terminal import (
    FakeExternalTerminal, NO_TERMINAL, TERMINAL_CHAIN, TerminalRun,
    detect, launch, list_available,
)


def test_terminal_chain_order():
    # First hit wins; the chain ends with the ``tail`` fallback.
    assert TERMINAL_CHAIN[0] == "xterm"
    assert TERMINAL_CHAIN[-1] == NO_TERMINAL


def test_list_available_returns_installed_terminals():
    # At least one of xterm/gnome-terminal/tmux is on this dev box.
    installed = list_available()
    assert isinstance(installed, list)
    assert NO_TERMINAL in installed  # the sentinel is always "available"
    # Sanity: no duplicates.
    assert len(installed) == len(set(installed))


def test_detect_returns_string_from_chain():
    term = detect(None)
    assert term in TERMINAL_CHAIN


def test_detect_persists_choice_to_settings():
    # Mock shutil.which so we control the chain.
    fake_settings = mock.MagicMock()
    fake_settings.get_setting.return_value = None
    with mock.patch("core.utils.external_terminal.shutil.which") as mw:
        mw.side_effect = lambda t: True if t == "xterm" else None
        result = detect(fake_settings)
    assert result == "xterm"
    fake_settings.update_setting.assert_called_with("terminal", "xterm")


def test_detect_revalidates_persisted_choice():
    fake_settings = mock.MagicMock()
    # Saved choice is xterm, but it's no longer on PATH.
    fake_settings.get_setting.return_value = "xterm"
    with mock.patch("core.utils.external_terminal.shutil.which") as mw:
        # Only tmux is installed; xterm vanished.
        mw.side_effect = lambda t: True if t == "tmux" else None
        result = detect(fake_settings)
    assert result == "tmux"
    fake_settings.update_setting.assert_called_with("terminal", "tmux")


def test_detect_falls_back_to_tail_when_nothing_installed():
    fake_settings = mock.MagicMock()
    fake_settings.get_setting.return_value = None
    with mock.patch("core.utils.external_terminal.shutil.which") as mw:
        mw.return_value = None  # nothing installed at all
        result = detect(fake_settings)
    assert result == NO_TERMINAL
    fake_settings.update_setting.assert_called_with("terminal", NO_TERMINAL)


def test_detect_keeps_tail_persisted_choice():
    fake_settings = mock.MagicMock()
    fake_settings.get_setting.return_value = "tail"
    # No need to call shutil.which at all when saved is ``tail``.
    result = detect(fake_settings)
    assert result == NO_TERMINAL
    fake_settings.update_setting.assert_not_called()


def test_fake_external_terminal_records_launches():
    fake = FakeExternalTerminal(term="xterm")
    r = fake.launch(["hashcat", "-m", "22000", "x.hc22000"], "/tmp/x.log",
                    title="hashcat")
    assert isinstance(r, TerminalRun)
    assert fake.calls == [{"cmd": ["hashcat", "-m", "22000", "x.hc22000"],
                           "log_path": "/tmp/x.log", "title": "hashcat",
                           "font_scale": None,
                           "geometry": None, "position": None}]
    assert r.term == "xterm"
    assert r.title == "hashcat"


def test_terminal_run_wait_and_abort():
    r = TerminalRun(["airodump-ng", "wlan0mon"], "/tmp/y.log", "xterm")
    rc = r.wait(timeout=5)
    assert rc == 0
    assert r.finished
    r.abort()
    assert r.returncode == 130


def test_launch_uses_tail_fallback_when_only_tail_available(monkeypatch, tmp_path):
    fake_settings = mock.MagicMock()
    fake_settings.get_setting.return_value = "tail"
    # Mock Popen to capture the argv without spawning anything.
    captured = {}
    def fake_popen(argv, **kwargs):
        captured["argv"] = argv
        m = mock.MagicMock()
        m.returncode = 0
        return m
    monkeypatch.setattr("core.utils.external_terminal.subprocess.Popen", fake_popen)
    log = str(tmp_path / "log.txt")
    p = launch(["true"], log, settings=fake_settings)
    assert "tail" in captured["argv"] or "-f" in captured["argv"]


def test_wrap_for_terminal_keep_open_suffix(monkeypatch, tmp_path):
    """Real-terminal windows get a keep-open suffix so the operator can
    review output before closing; the tail fallback path is unaffected."""
    from core.utils.external_terminal import _wrap_for_terminal
    log = str(tmp_path / "log.txt")
    wrapped = _wrap_for_terminal("xterm", ["airodump-ng", "wlan0mon"], log)
    assert wrapped[0] == "bash" and wrapped[1] == "-c"
    inner = wrapped[2]
    assert "tee -a" in inner
    assert "exec bash" in inner
    assert "close this window" in inner
    # Disabling restores the auto-close behaviour.
    wrapped_off = _wrap_for_terminal("xterm", ["airodump-ng", "wlan0mon"],
                                     log, keep_open=False)
    assert "exec bash" not in wrapped_off[2]


# --- font_scale (4x bigger scanner windows) ---

def test_font_argv_no_scale_is_empty():
    from core.utils.external_terminal import font_argv
    assert font_argv("xterm", None) == []
    assert font_argv("xterm", 1.0) == []
    assert font_argv("xterm", 0.0) == []


def test_font_argv_xterm_4x():
    from core.utils.external_terminal import font_argv
    out = font_argv("xterm", 4.0)
    # xterm default base is 8 -> 4x = 32
    assert out == ["-fa", "Mono", "-fs", "32"]


def test_font_argv_kitty_foot_alacritty_4x():
    from core.utils.external_terminal import font_argv
    assert font_argv("kitty", 4.0) == ["-o", "font_size=44"]
    assert font_argv("foot", 4.0) == ["--font", "Mono:size=48"]
    assert font_argv("alacritty", 4.0) == ["-o", "font.size=48"]


def test_font_argv_unsupported_terminal_is_empty():
    # gnome-terminal / konsole / xfce4-terminal / tmux have no stable
    # CLI font-size knob -> inherit the host font (empty == no change).
    from core.utils.external_terminal import font_argv
    for t in ("gnome-terminal", "konsole", "xfce4-terminal", "tmux", "tail"):
        assert font_argv(t, 4.0) == []


def test_launch_passes_font_scale_into_xterm_argv(monkeypatch, tmp_path):
    from core.utils import external_terminal as et
    captured = {}

    def fake_popen(argv, *a, **kw):
        captured["argv"] = list(argv)
        class _P:
            pid = 12345
        return _P()

    monkeypatch.setattr(et.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(et.shutil, "which", lambda t: True if t == "xterm" else None)
    monkeypatch.setattr(et, "detect", lambda s=None: "xterm")
    log = str(tmp_path / "log.txt")
    et.launch(["echo", "hi"], log, title="Scan", font_scale=4.0)
    av = captured["argv"]
    assert av[0] == "xterm"
    assert "-fa" in av and "-fs" in av
    assert av[av.index("-fs") + 1] == "32"
    # the -e wrapper must still come after the font flags
    assert "-e" in av and av.index("-e") > av.index("-fs")


def test_launch_placed_passes_geometry_and_font(monkeypatch, tmp_path):
    """launch_placed must combine slot geometry with font_scale argv."""
    from core.utils import external_terminal as et
    captured = {}

    def fake_popen(argv, *a, **kw):
        captured["argv"] = list(argv)
        class _P:
            pid = 99
        return _P()

    monkeypatch.setattr(et.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(et.shutil, "which", lambda t: True if t == "xterm" else None)
    monkeypatch.setattr(et, "detect", lambda s=None: "xterm")
    monkeypatch.setattr(et, "screen_size", lambda: (1920, 1080))
    log = str(tmp_path / "log.txt")
    et.launch_placed(
        ["echo", "hi"], log, title="APs", position="topright", font_scale=4.0,
    )
    av = captured["argv"]
    assert av[0] == "xterm"
    assert "-geometry" in av
    geom = av[av.index("-geometry") + 1]
    # topright starts at half width
    assert geom.endswith("+960+0")
    assert "-fs" in av and av[av.index("-fs") + 1] == "32"


def test_launch_without_font_scale_is_unchanged(monkeypatch, tmp_path):
    from core.utils import external_terminal as et
    captured = {}
    def fake_popen(argv, *a, **kw):
        captured["argv"] = list(argv)
        class _P:
            pid = 12345
        return _P()
    monkeypatch.setattr(et.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(et.shutil, "which", lambda t: True if t == "xterm" else None)
    monkeypatch.setattr(et, "detect", lambda s=None: "xterm")
    log = str(tmp_path / "log.txt")
    et.launch(["echo", "hi"], log, title="Scan")
    av = captured["argv"]
    assert "-fa" not in av and "-fs" not in av


def test_backend_launch_records_font_scale():
    from core.utils.external_terminal import FakeExternalTerminal, SCAN_WINDOW_FONT_SCALE
    fake = FakeExternalTerminal(term="xterm")
    fake.launch(["bash", "-c", "x"], "/tmp/x.log", title="Scan",
                font_scale=SCAN_WINDOW_FONT_SCALE)
    # Round-trip: the scale passed in is the scale recorded.
    assert fake.calls[-1]["font_scale"] == SCAN_WINDOW_FONT_SCALE
    # Default is now 1.0 (matches the main TUI density; the operator
    # reversed the earlier 4.0 "bigger font" request because windows were
    # too large to show more than a few words). KFIOSA_SCAN_FONT_SCALE
    # overrides at import time, so assert the no-env default explicitly.
    import core.utils.external_terminal as et
    assert et.SCAN_WINDOW_FONT_SCALE == float(
        __import__("os").environ.get("KFIOSA_SCAN_FONT_SCALE", "1.0")
    )


def test_launch_script_in_project_root_builds_root_command(monkeypatch, tmp_path):
    """The helper builds a shell command that cds to the project root and
    exports PYTHONPATH/TERM before running the argv."""
    from core.utils import external_terminal as et
    captured = {}

    def fake_popen(argv, *a, **kw):
        captured["argv"] = list(argv)
        class _P:
            pid = 12345
        return _P()

    monkeypatch.setattr(et.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(et.shutil, "which", lambda t: True if t == "xterm" else None)
    monkeypatch.setattr(et, "detect", lambda s=None: "xterm")
    log = str(tmp_path / "log.txt")
    cmd_argv = ["python", "-m", "core.tui.wifi_scan_external", "--iface", "wlan0"]
    et.launch_script_in_project_root(cmd_argv, log, title="WiFi Scan", wait_prompt=True)
    av = captured["argv"]
    assert av[0] == "xterm"
    # The actual command is wrapped in bash -lc inside the xterm -e argument.
    inner = " ".join(av)
    assert "cd " in inner
    assert "TERM=xterm-256color" in inner
    assert "PYTHONPATH=" in inner
    assert "wifi_scan_external" in inner
    assert "close window or press Enter" in inner


def test_fake_external_terminal_launch_script_in_project_root_records_call():
    from core.utils.external_terminal import (
        FakeExternalTerminal, SCAN_WINDOW_FONT_SCALE, TerminalRun,
    )
    fake = FakeExternalTerminal(term="xterm")
    cmd_argv = ["python", "-m", "core.tui.ble_scan_external"]
    r = fake.launch_script_in_project_root(
        cmd_argv,
        "/tmp/ble.log",
        title="BLE Scan",
        font_scale=SCAN_WINDOW_FONT_SCALE,
        wait_prompt=True,
    )
    assert isinstance(r, TerminalRun)
    assert r.term == "xterm"
    assert r.title == "BLE Scan"
    assert fake.calls[-1] == {
        "cmd": cmd_argv,
        "log_path": "/tmp/ble.log",
        "title": "BLE Scan",
        "font_scale": SCAN_WINDOW_FONT_SCALE,
        "wait_prompt": True,
        "position": None,
    }


def test_launch_script_forwards_position(monkeypatch, tmp_path):
    from core.utils import external_terminal as et
    captured = {}

    def fake_popen(argv, *a, **kw):
        captured["argv"] = list(argv)
        class _P:
            pid = 7
        return _P()

    monkeypatch.setattr(et.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(et.shutil, "which", lambda t: True if t == "xterm" else None)
    monkeypatch.setattr(et, "detect", lambda s=None: "xterm")
    monkeypatch.setattr(et, "screen_size", lambda: (1920, 1080))
    log = str(tmp_path / "log.txt")
    et.launch_script_in_project_root(
        ["python", "-m", "core.tui.wifi_scan_external"],
        log,
        title="WiFi Scan",
        wait_prompt=False,
        position="topleft",
        font_scale=2.0,
    )
    av = captured["argv"]
    assert "-geometry" in av
    geom = av[av.index("-geometry") + 1]
    assert geom.endswith("+0+0")
    assert "-fs" in av
