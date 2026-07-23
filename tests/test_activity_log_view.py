"""Tests for improved TUI activity log rendering helpers."""
from __future__ import annotations

from core.tui.activity_log_view import (
    MAX_ACTIVITY_LINES,
    append_log,
    classify_line,
    handle_log_scroll_key,
    visible_rows,
    wrap_text,
)


def test_append_log_caps_and_timestamp():
    buf: list = []
    append_log(buf, "[+] hello", timestamp=True)
    assert len(buf) == 1
    assert "[+] hello" in buf[0]
    # timestamp prefix HH:MM:SS
    assert buf[0][:2].isdigit() or buf[0].startswith("[+]")
    for i in range(MAX_ACTIVITY_LINES + 50):
        append_log(buf, f"[i] line {i}", timestamp=False, cap=100)
    assert len(buf) <= 100


def test_classify_success_error_info():
    p, b, pref, body = classify_line("[+] ok")
    assert p == 1 and b is True and "[+]" in pref
    p, b, pref, body = classify_line("[!] boom")
    assert p == 2
    p, b, pref, body = classify_line("[i] note")
    assert p == 4
    p, b, pref, body = classify_line("[AIO] go")
    assert p == 5
    p, b, pref, body = classify_line("[recon] ▶ clients")
    assert p == 3


def test_classify_with_timestamp():
    p, b, pref, body = classify_line("12:34:56 [+] done")
    assert p == 1
    assert "12:34:56" in pref
    assert "done" in body


def test_wrap_text_soft_break():
    long = "word " * 40
    rows = wrap_text(long, 40)
    assert len(rows) > 1
    assert all(len(r) <= 40 for r in rows)


def test_visible_rows_scroll_and_tail():
    lines = [f"[i] line {i}" for i in range(30)]
    rows, total, scroll = visible_rows(
        lines, width=80, max_rows=5, scroll_from_end=0,
    )
    assert len(rows) == 5
    assert "line 29" in rows[-1][3] or "29" in rows[-1][3]
    rows2, total2, scroll2 = visible_rows(
        lines, width=80, max_rows=5, scroll_from_end=10,
    )
    assert scroll2 == 10
    assert total2 >= 30


def test_handle_log_scroll_keys():
    import curses
    assert handle_log_scroll_key(curses.KEY_PPAGE, 0, page=5) == 5
    assert handle_log_scroll_key(curses.KEY_NPAGE, 8, page=5) == 3
    assert handle_log_scroll_key(curses.KEY_END, 99) == 0
    assert handle_log_scroll_key(ord("x"), 3) is None
