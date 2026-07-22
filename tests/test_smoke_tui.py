"""Pty-based full-TUI smoke test.

Skipped unless ``KFIOSA_SMOKE=1``. Spawns the real ``main.py`` in a pty,
walks the main menu into the OSINT screen and back, then quits, asserting
the banner + OSINT header render and the process exits cleanly. No root,
no Ollama, no action triggered (pure navigation)."""

import os
import select
import struct
import sys
import fcntl
import termios
import time
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
SMOKE = os.environ.get("KFIOSA_SMOKE", "0") == "1"
pytestmark = [pytest.mark.smoke, pytest.mark.skipif(not SMOKE,
              reason="set KFIOSA_SMOKE=1 to run the pty full-TUI smoke test")]


def _drain(master, timeout=0.6):
    """Accumulate any pending output for up to ``timeout`` seconds."""
    out = b""
    end = time.time() + timeout
    while time.time() < end:
        r, _, _ = select.select([master], [], [], 0.05)
        if r:
            try:
                data = os.read(master, 65536)
            except OSError:
                break
            if not data:
                break
            out += data
    return out


def _wait_for(master, needle, timeout=8.0):
    """Read until ``needle`` appears or ``timeout`` elapses."""
    out = b""
    end = time.time() + timeout
    while time.time() < end:
        r, _, _ = select.select([master], [], [], 0.1)
        if r:
            try:
                data = os.read(master, 65536)
            except OSError:
                break
            if not data:
                break
            out += data
            if needle in out:
                return out
    return out


def _send(master, data):
    os.write(master, data)
    time.sleep(0.4)


def test_tui_boots_navigates_and_quits():
    master, slave = pty_import()
    # 80x24 window so the "too small" guard never trips.
    winsize = struct.pack("HHHH", 24, 80, 0, 0)
    fcntl.ioctl(slave, termios.TIOCSWINSZ, winsize)
    env = os.environ.copy()
    env.update({
        "TERM": "xterm-256color",
        "KFIOSA_MCP_AUTOSTART": "0",
        "GROQ_API_KEY": "", "NVD_API_KEY": "", "SHODAN_API_KEY": "",
        "GEMINI_API_KEY": "", "GOOGLE_PROJECT_ID": "",
        "PYTHONPATH": str(REPO),
    })
    proc = subprocess.Popen(
        [sys.executable, "main.py"], stdin=slave, stdout=slave, stderr=slave,
        env=env, cwd=str(REPO), start_new_session=True,
    )
    os.close(slave)
    try:
        banner = _wait_for(master, b"KFIOSA", timeout=8.0)
        assert b"KFIOSA" in banner, f"banner missing; got: {banner!r}"

        # DOWN x2 -> OSINT (index 2), ENTER.
        _send(master, b"\x1b[B\x1b[B\r")
        osint = _wait_for(master, b"OSINT", timeout=4.0)
        assert b"OSINT" in osint, f"OSINT header not rendered; got: {osint!r}"

        # Leave the sub-screen and quit. 'q' returns from a sub-screen to the
        # main menu (handle_input returns "back") AND quits from the main menu
        # (handle_main_menu_input sets running=False), so two 'q' presses cover
        # either starting state without relying on arrow-key decoding.
        _send(master, b"q")
        _drain(master, 0.6)
        _send(master, b"q")
        tail = _wait_for(master, b"closed cleanly", timeout=8.0)
        try:
            rc = proc.wait(timeout=8)
        except subprocess.TimeoutExpired:
            proc.kill()
            pytest.fail(f"TUI did not quit; tail={tail!r}")
        assert rc == 0
        assert b"closed cleanly" in tail, f"no clean exit message; tail={tail!r}"
    finally:
        if proc.poll() is None:
            proc.kill()
        try:
            os.close(master)
        except OSError:
            pass


def pty_import():
    import pty
    return pty.openpty()