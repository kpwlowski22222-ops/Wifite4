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
                           "log_path": "/tmp/x.log", "title": "hashcat"}]
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
