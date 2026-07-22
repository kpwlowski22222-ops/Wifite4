#!/usr/bin/env python3
"""
Unit tests for core/tui/ui_theme.py

Tests run WITHOUT a real curses terminal using mocked curses primitives,
so they can pass in any CI environment.
"""
import os
import sys
import types
import unittest.mock as mock
import pytest


# ---------------------------------------------------------------------------
# Stub curses module so tests don't need a real TTY
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def fake_curses(monkeypatch):
    """Patch curses with enough stubs to exercise ui_theme without a TTY."""
    # Constants needed by ui_theme
    c = types.SimpleNamespace(
        COLOR_GREEN=2,
        COLOR_RED=1,
        COLOR_YELLOW=3,
        COLOR_CYAN=6,
        COLOR_MAGENTA=5,
        COLOR_WHITE=7,
        COLOR_BLACK=0,
        A_BOLD=2097152,
        A_REVERSE=262144,
        error=Exception,
    )
    c.has_colors = mock.Mock(return_value=True)
    c.start_color = mock.Mock()
    c.use_default_colors = mock.Mock()
    c.init_pair = mock.Mock()
    c.color_pair = mock.Mock(return_value=0)
    c.color_pair.side_effect = lambda n: n  # return pair id for easy inspection

    monkeypatch.setitem(sys.modules, "curses", c)

    # Also patch the already-imported curses reference in ui_theme if loaded
    import importlib
    if "core.tui.ui_theme" in sys.modules:
        del sys.modules["core.tui.ui_theme"]

    yield c


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _import_theme():
    """Fresh import of ui_theme after stubbing."""
    import importlib
    if "core.tui.ui_theme" in sys.modules:
        del sys.modules["core.tui.ui_theme"]
    import core.tui.ui_theme as t
    return t


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestThemePairs:
    def test_pair_ids_are_stable_integers(self, fake_curses):
        theme = _import_theme()
        for pair_id in theme.ThemePair:
            assert 1 <= int(pair_id) <= 16

    def test_pair_dict_maps_all_roles(self, fake_curses):
        theme = _import_theme()
        expected_roles = {
            "SUCCESS", "DANGER", "WARN", "INFO",
            "ACCENT", "MUTED", "HEADER", "SELECTED", "CRITICAL",
        }
        actual = {p.name for p in theme.ThemePair}
        assert expected_roles == actual

    def test_pair_convenience_dict_matches_enum(self, fake_curses):
        theme = _import_theme()
        for role, pid in theme.PAIR.items():
            assert pid == int(role)


class TestApplyTheme:
    def test_apply_standard_calls_init_pair_for_all_nine_pairs(self, fake_curses):
        theme = _import_theme()
        win = mock.MagicMock()
        result = theme.apply_theme(win, theme.UITheme.STANDARD)
        assert result is True
        # At minimum 9 pairs should be initialised
        assert fake_curses.init_pair.call_count >= 9

    def test_apply_focus_mode_uses_cyan_for_success(self, fake_curses):
        theme = _import_theme()
        win = mock.MagicMock()
        theme.apply_theme(win, theme.UITheme.FOCUS_MODE)
        # In focus mode SUCCESS (pair 1) should be COLOR_CYAN (6)
        calls = {call[0][0]: call[0][1]
                 for call in fake_curses.init_pair.call_args_list}
        # pair 1 (SUCCESS) should map to cyan
        assert calls.get(1) == fake_curses.COLOR_CYAN

    def test_apply_returns_false_when_terminal_has_no_colors(self, fake_curses):
        fake_curses.has_colors.return_value = False
        theme = _import_theme()
        win = mock.MagicMock()
        result = theme.apply_theme(win, theme.UITheme.STANDARD)
        assert result is False

    def test_apply_theme_sets_current_theme_name(self, fake_curses):
        theme = _import_theme()
        win = mock.MagicMock()
        theme.apply_theme(win, theme.UITheme.FOCUS_MODE)
        assert theme.get_current_theme() == theme.UITheme.FOCUS_MODE


class TestFocusModeState:
    def test_is_focus_mode_false_by_default(self, fake_curses):
        theme = _import_theme()
        win = mock.MagicMock()
        theme.apply_theme(win, theme.UITheme.STANDARD)
        assert theme.is_focus_mode() is False

    def test_is_focus_mode_true_after_focus_apply(self, fake_curses):
        theme = _import_theme()
        win = mock.MagicMock()
        theme.apply_theme(win, theme.UITheme.FOCUS_MODE)
        assert theme.is_focus_mode() is True

    def test_toggle_focus_mode_cycles_standard_to_focus(self, fake_curses):
        theme = _import_theme()
        win = mock.MagicMock()
        theme.apply_theme(win, theme.UITheme.STANDARD)
        new = theme.toggle_focus_mode(win)
        assert new == theme.UITheme.FOCUS_MODE
        assert theme.is_focus_mode() is True

    def test_toggle_focus_mode_cycles_focus_to_standard(self, fake_curses):
        theme = _import_theme()
        win = mock.MagicMock()
        theme.apply_theme(win, theme.UITheme.FOCUS_MODE)
        new = theme.toggle_focus_mode(win)
        assert new == theme.UITheme.STANDARD
        assert theme.is_focus_mode() is False


class TestEnvPersistence:
    def test_load_theme_from_env_default_is_standard(self, monkeypatch, fake_curses):
        monkeypatch.delenv("KFIOSA_FOCUS_MODE", raising=False)
        theme = _import_theme()
        assert theme.load_theme_from_env() == theme.UITheme.STANDARD

    def test_load_theme_from_env_1_is_focus_mode(self, monkeypatch, fake_curses):
        monkeypatch.setenv("KFIOSA_FOCUS_MODE", "1")
        theme = _import_theme()
        assert theme.load_theme_from_env() == theme.UITheme.FOCUS_MODE

    def test_save_theme_to_env_sets_env_var_focus(self, monkeypatch, fake_curses):
        monkeypatch.delenv("KFIOSA_FOCUS_MODE", raising=False)
        theme = _import_theme()
        theme.save_theme_to_env(theme.UITheme.FOCUS_MODE)
        assert os.environ.get("KFIOSA_FOCUS_MODE") == "1"

    def test_save_theme_to_env_sets_env_var_standard(self, monkeypatch, fake_curses):
        monkeypatch.setenv("KFIOSA_FOCUS_MODE", "1")
        theme = _import_theme()
        theme.save_theme_to_env(theme.UITheme.STANDARD)
        assert os.environ.get("KFIOSA_FOCUS_MODE") == "0"


class TestDrawHelpers:
    def _make_win(self, height=24, width=80):
        win = mock.MagicMock()
        win.getmaxyx.return_value = (height, width)
        win.addstr = mock.MagicMock()
        win.attron = mock.MagicMock()
        win.attroff = mock.MagicMock()
        return win

    def test_safe_addstr_does_not_raise_on_boundary_error(self, fake_curses):
        import curses
        theme = _import_theme()
        win = self._make_win()
        win.addstr.side_effect = curses.error("test")
        # Should not propagate
        theme.safe_addstr(win, 0, 0, "hello")

    def test_safe_addstr_truncates_long_text(self, fake_curses):
        theme = _import_theme()
        win = self._make_win(height=24, width=20)
        long_text = "A" * 100
        theme.safe_addstr(win, 0, 0, long_text)
        # The text passed to addstr must fit
        if win.addstr.called:
            called_text = win.addstr.call_args[0][2]
            assert len(called_text) <= 19

    def test_draw_header_fills_row_zero(self, fake_curses):
        theme = _import_theme()
        win = self._make_win()
        theme.draw_header(win, "KFIOSA v3", right_label="FOCUS")
        # addstr must have been called at least once on row 0
        calls_on_row0 = [c for c in win.addstr.call_args_list
                         if c[0][0] == 0]
        assert len(calls_on_row0) >= 1

    def test_draw_focus_badge_only_when_focus_mode(self, fake_curses):
        theme = _import_theme()
        win = mock.MagicMock()
        win.getmaxyx.return_value = (24, 80)
        # Standard mode — no badge
        theme.apply_theme(win, theme.UITheme.STANDARD)
        win.addstr = mock.MagicMock()
        theme.draw_focus_badge(win)
        assert not win.addstr.called

    def test_draw_focus_badge_visible_in_focus_mode(self, fake_curses):
        theme = _import_theme()
        win = mock.MagicMock()
        win.getmaxyx.return_value = (24, 80)
        theme.apply_theme(win, theme.UITheme.FOCUS_MODE)
        win.addstr = mock.MagicMock()
        theme.draw_focus_badge(win)
        assert win.addstr.called


class TestAttrFor:
    def test_attr_for_returns_int(self, fake_curses):
        theme = _import_theme()
        attr = theme.attr_for(theme.ThemePair.SUCCESS)
        assert isinstance(attr, int)

    def test_attr_for_bold_adds_bold_flag(self, fake_curses):
        import curses
        theme = _import_theme()
        attr_plain = theme.attr_for(theme.ThemePair.INFO)
        attr_bold = theme.attr_for(theme.ThemePair.INFO, bold=True)
        assert (attr_bold & curses.A_BOLD) != 0
