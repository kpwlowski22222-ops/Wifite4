"""Pytest configuration for KFIOSA.

- Pins cwd to the repo root and puts it on sys.path so ``core.*`` imports.
- Disables network-dependent env (empty GROQ/NVD keys) and the MCP autostart.
- Provides screen-construction fixtures wired with fakes + the sync thread
  runner so every action is curses-free and synchronous.
"""

import os
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
os.chdir(REPO_ROOT)

# Keep the unit tests hermetic: no real AI/CVE network, no MCP autostart.
os.environ.setdefault("KFIOSA_MCP_AUTOSTART", "0")
os.environ.setdefault("KFIOSA_SMOKE", "0")
os.environ.setdefault("KFIOSA_SKIP_NVD", "1")  # adaptive engagement: no live NVD
os.environ.setdefault("GROQ_API_KEY", "")
os.environ.setdefault("NVD_API_KEY", "")
# KismetRunner requires operator-provided credentials; give tests a fake pair.
os.environ.setdefault("KISMET_CLIENT_USERNAME", "unit-test-user")
os.environ.setdefault("KISMET_CLIENT_PASSWORD", "unit-test-password")
# Isolate dashboard roster/SQL/jobs from the operator's live ~/.kfiosa state.
os.environ.setdefault("KFIOSA_DASHBOARD_MERGE_SQL", "0")
os.environ.setdefault("KFIOSA_DASHBOARD_MERGE_JOBS", "0")
# Per-test job dirs still override via fixtures; default away from home.
if "KFIOSA_RAT_JOBS" not in os.environ:
    _jobs = REPO_ROOT / ".pytest_rat_jobs"
    _jobs.mkdir(exist_ok=True)
    os.environ["KFIOSA_RAT_JOBS"] = str(_jobs)

from tests.fakes import (  # noqa: E402
    FakeAIBackend, FakeBLEScanner, FakeCatalogRecon, FakeConfirmFn,
    FakeExternalTerminal, FakeInput, FakeKB, FakeOSINTRunner, FakeOrchestrator,
    FakePostRunner, FakeSettingsManager, FakeWiFiScanner, sync_thread_runner,
)


def _make_screen(cls, activity_log, **overrides):
    """Construct a screen with stdscr=None and the standard fakes, letting
    the caller override any collaborator or seam."""
    kwargs = dict(
        ai_backend=FakeAIBackend(),
        kb=FakeKB(),
        post_runner=FakePostRunner(),
        orchestrator=FakeOrchestrator(),
        osint_runner=FakeOSINTRunner(),
        tui_confirm=FakeConfirmFn(),
        settings_manager=FakeSettingsManager(),
        scanner_cls=None,
        thread_runner=sync_thread_runner,
        input_fn=FakeInput(),
        # Adaptive WiFi pentest: external terminal + recon pass.
        # The recon factory returns a fresh FakeCatalogRecon each call so
        # tests that need to assert on the recon report can grab the
        # instance via the factory's ``last_instance`` attribute.
        external_terminal=FakeExternalTerminal(),
        catalog_recon_factory=lambda target: FakeCatalogRecon({"target": target}),
    )
    kwargs.update(overrides)
    return cls(None, lambda: None, activity_log, **kwargs)


@pytest.fixture
def log():
    return []


@pytest.fixture
def wifi_screen(log):
    from core.tui.wifi_screen import WiFiScreen
    return _make_screen(WiFiScreen, log)


@pytest.fixture
def ble_screen(log):
    from core.tui.ble_screen import BLEScreen
    return _make_screen(BLEScreen, log)


@pytest.fixture
def osint_screen(log):
    from core.tui.osint_screen import OSINTScreen
    return _make_screen(OSINTScreen, log)


@pytest.fixture
def settings_screen(log):
    from core.tui.settings_screen import SettingsScreen
    return _make_screen(SettingsScreen, log)


# Re-export fakes for direct use in tests.
__all__ = [
    "FakeAIBackend", "FakeBLEScanner", "FakeCatalogRecon", "FakeConfirmFn",
    "FakeExternalTerminal", "FakeInput", "FakeKB", "FakeOSINTRunner",
    "FakeOrchestrator", "FakePostRunner", "FakeSettingsManager",
    "FakeWiFiScanner", "sync_thread_runner", "_make_screen",
]