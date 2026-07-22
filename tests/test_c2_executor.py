"""Hermetic tests for ``core/c2/executor.py`` — the TUI/PTY
executor for cloned C2 frameworks (Sliver, Empire, Havoc, ...).

The executor uses a real subprocess to a real C2 framework
binary. The tests are hermetic by:
  1. Always running against a non-installed framework name
     (``definitely_not_a_c2_binary_xyzzy`` is registered via
     the spec for the test, not via the global C2_FRAMEWORKS).
  2. Using a fake binary script written to tmp_path and
     prepending it to PATH. The fake script just prints a
     prompt and reads stdin; the executor's prompt-watcher
     picks it up.

Never-fabricate contract:
  * The executor must NEVER claim a session / beacon / task
    result that didn't come from the real subprocess.
  * If the binary is not on PATH, ``start()`` returns
    ``{ok: False, error: "..."}`` and the executor stays in
    a not-started state.
  * The executor must NEVER inline harvested credentials
    into the command string; it always uses env vars.
"""
import os
import shutil
import textwrap
from pathlib import Path

import pytest

from core.c2.executor import (
    C2_FRAMEWORKS, C2Executor, C2FrameworkSpec, list_frameworks,
    run_c2_framework,
)


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------
EXPECTED_FRAMEWORKS = {
    "sliver", "empire", "havoc", "merlin", "covenant",
    "mythic", "adaptix", "villain",
}


def test_all_8_frameworks_registered():
    assert set(C2_FRAMEWORKS.keys()) == EXPECTED_FRAMEWORKS


def test_list_frameworks_sorted():
    listed = list_frameworks()
    assert listed == sorted(EXPECTED_FRAMEWORKS)
    assert len(listed) == 8


def test_every_framework_has_risk_intrusive():
    """All C2 frameworks are intrusive by definition."""
    for name, spec in C2_FRAMEWORKS.items():
        assert spec.risk_level == "intrusive", name


def test_every_framework_has_cleanup_command():
    for spec in C2_FRAMEWORKS.values():
        assert spec.cleanup_command, spec.name


def test_every_framework_has_ready_prompt_regex():
    for spec in C2_FRAMEWORKS.values():
        assert spec.ready_prompt, spec.name


# ---------------------------------------------------------------------------
# Executor: missing binary → honest degrade
# ---------------------------------------------------------------------------
def test_start_with_missing_binary(monkeypatch, tmp_path):
    # Make the binary un-findable
    monkeypatch.setenv("PATH", str(tmp_path))
    ex = C2Executor("sliver")
    assert ex.is_binary_available() is False
    res = ex.start()
    assert res["ok"] is False
    assert "not installed" in res["error"]
    assert ex.started is False


def test_close_when_never_started():
    ex = C2Executor("sliver")
    res = ex.close()
    assert res["ok"] is True
    assert res.get("already_closed") is True


def test_send_command_before_start():
    ex = C2Executor("sliver")
    res = ex.send_command("help")
    assert res["ok"] is False
    assert "not started" in res["error"]


def test_unknown_framework_raises():
    with pytest.raises(ValueError) as exc:
        C2Executor("not_a_real_c2_framework")
    assert "unknown C2 framework" in str(exc.value)


# ---------------------------------------------------------------------------
# Module-level entrypoint: unknown framework
# ---------------------------------------------------------------------------
def test_run_c2_framework_unknown():
    res = run_c2_framework("not_a_real_c2_framework")
    assert res["ok"] is False
    assert "unknown C2 framework" in res["error"]


# ---------------------------------------------------------------------------
# Executor: hermetic end-to-end with a fake binary
# ---------------------------------------------------------------------------
@pytest.fixture
def fake_c2_binary(tmp_path: Path, monkeypatch):
    """Write a fake C2 framework binary that prints a ready
    prompt + echoes each stdin line. Prepend tmp_path to PATH
    so shutil.which finds it."""
    bin_path = tmp_path / "fake-c2"
    bin_path.write_text(textwrap.dedent("""\
        #!/usr/bin/env python3
        import sys
        # Print banner
        print("fake-c2 v0.1")
        # Print the ready prompt
        print("FAKE> ", end="", flush=True)
        # Echo each command, then re-print the prompt
        for line in sys.stdin:
            cmd = line.rstrip("\\n")
            print(f"ECHO: {cmd}")
            print("FAKE> ", end="", flush=True)
        """))
    bin_path.chmod(0o755)
    monkeypatch.setenv("PATH", str(tmp_path) + os.pathsep +
                       os.environ.get("PATH", ""))
    # Register a custom spec pointing at the fake binary
    spec = C2FrameworkSpec(
        name="fake",
        binary="fake-c2",
        ready_prompt=r"FAKE>\s*$",
        default_argv=[],
        cleanup_command="exit",
        description="Hermetic fake C2 framework for tests.",
        risk_level="intrusive",
    )
    original = C2_FRAMEWORKS.copy()
    C2_FRAMEWORKS["fake"] = spec
    yield "fake"
    C2_FRAMEWORKS.clear()
    C2_FRAMEWORKS.update(original)


def test_hermetic_start_with_fake_binary(fake_c2_binary):
    ex = C2Executor("fake")
    assert ex.is_binary_available() is True
    res = ex.start()
    assert res["ok"] is True
    assert "FAKE>" in res["ready_output"]
    assert ex.started is True
    ex.close()


def test_hermetic_send_command(fake_c2_binary):
    ex = C2Executor("fake")
    ex.start()
    res = ex.send_command("help")
    assert res["ok"] is True
    assert "ECHO: help" in res["output"]
    assert "FAKE>" in res["output"]
    ex.close()


def test_hermetic_run_c2_framework(fake_c2_binary):
    res = run_c2_framework("fake", commands=["help", "sessions"])
    assert res["ok"] is True
    assert len(res["results"]) == 2
    assert "ECHO: help" in res["results"][0]["output"]
    assert "ECHO: sessions" in res["results"][1]["output"]


def test_hermetic_command_count_tracked(fake_c2_binary):
    ex = C2Executor("fake")
    ex.start()
    ex.send_command("cmd1")
    ex.send_command("cmd2")
    ex.send_command("cmd3")
    res = ex.close()
    assert res["command_count"] == 3


def test_hermetic_idempotent_close(fake_c2_binary):
    ex = C2Executor("fake")
    ex.start()
    res1 = ex.close()
    res2 = ex.close()
    assert res1["ok"] is True
    assert res2["ok"] is True
    assert res2.get("already_closed") is True


# ---------------------------------------------------------------------------
# Never-fabricate: the executor must NEVER claim success for a
# missing binary. The only "ok" path is real subprocess output.
# ---------------------------------------------------------------------------
def test_never_fabricates_session(monkeypatch, tmp_path):
    monkeypatch.setenv("PATH", str(tmp_path))
    ex = C2Executor("sliver")
    res = ex.start()
    assert res["ok"] is False
    # No session/beacon/implant fields should be present
    assert "session" not in res
    assert "beacon" not in res
    assert "implant" not in res
