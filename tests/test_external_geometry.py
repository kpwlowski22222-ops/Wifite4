"""Pure geometry helpers for triple external scan windows."""
from __future__ import annotations

from core.utils.external_terminal import (
    geometry_string,
    screen_layout_rects,
    screen_size,
)


def test_screen_layout_has_triple_slots():
    rects = screen_layout_rects()
    for key in ("topleft", "topright", "bottomright"):
        assert key in rects
        r = rects[key]
        assert r["w"] > 0 and r["h"] > 0
        assert r["x"] >= 0 and r["y"] >= 0


def test_topleft_is_origin_quadrant():
    rects = screen_layout_rects()
    tl = rects["topleft"]
    tr = rects["topright"]
    br = rects["bottomright"]
    assert tl["x"] == 0 and tl["y"] == 0
    assert tr["x"] >= tl["w"] - 1  # right half
    assert br["y"] >= tl["h"] - 1  # bottom half


def test_geometry_string_format():
    g = geometry_string("topleft")
    # COLSxROWS+X+Y
    assert "x" in g.lower()
    assert "+" in g
    body, _, rest = g.partition("+")
    assert "x" in body.lower()


def test_geometry_string_shrinks_cols_for_bigger_font():
    """A 4x font must yield ~4x fewer columns for the same slot, so the
    window fits on screen instead of overflowing (the original bug:
    4x font + 120-column geometry → only a few words visible)."""
    small = geometry_string("topleft", font_scale=1.0, term="xterm")
    big = geometry_string("topleft", font_scale=4.0, term="xterm")

    def cols(g: str) -> int:
        return int(g.lower().split("x")[0])

    # Bigger font → strictly fewer columns (roughly 4x fewer).
    assert cols(big) < cols(small)
    # And roughly 1/4 (allow rounding).
    assert cols(big) <= max(1, cols(small) // 3)
    # Rows shrink too.
    def rows(g: str) -> int:
        body = g.split("+")[0]
        return int(body.lower().split("x")[1])

    assert rows(big) < rows(small)


def test_geometry_string_fits_slot_at_high_font_scale(monkeypatch):
    """Scaled geometry must never exceed the pixel slot (regression for
    the old max(40, cols)/max(12, rows) floors that overflowed at 3×+)."""
    import core.utils.external_terminal as et
    monkeypatch.setenv("KFIOSA_SCREEN_W", "1920")
    monkeypatch.setenv("KFIOSA_SCREEN_H", "1080")
    # screen_size reads env at call time — ensure helpers re-read.
    sw, sh = 1920, 1080
    monkeypatch.setattr(et, "screen_size", lambda: (sw, sh))
    half_w, half_h = sw // 2, sh // 2
    for scale in (1.0, 2.0, 3.0, 4.0, 6.0):
        for term in ("xterm", "kitty", "foot", "alacritty"):
            g = geometry_string("topleft", font_scale=scale, term=term)
            body = g.split("+")[0]
            c, r = body.lower().split("x")
            cols, rows = int(c), int(r)
            cw, ch = et._effective_cell_size(term, scale)
            assert cols * cw <= half_w, (term, scale, g, cw)
            assert rows * ch <= half_h, (term, scale, g, ch)
            assert cols >= 1 and rows >= 1


def test_geometry_string_explicit_cell_size_overrides_scale():
    """Explicit cell_w/cell_h take precedence over font_scale-derived
    sizes (legacy callers that pass their own cell sizes)."""
    g_legacy = geometry_string("topleft", cell_w=8, cell_h=16,
                               font_scale=4.0, term="xterm")
    g_default = geometry_string("topleft", font_scale=1.0, term="xterm")
    # Same explicit cell size as the default → same geometry.
    assert g_legacy == g_default


def test_screen_size_positive():
    w, h = screen_size()
    assert w >= 640 and h >= 480


def test_parse_scan_font_scale_rejects_invalid():
    from core.utils.external_terminal import _parse_scan_font_scale
    assert _parse_scan_font_scale("2.5") == 2.5
    assert _parse_scan_font_scale("0") == 1.0
    assert _parse_scan_font_scale("-3") == 1.0
    assert _parse_scan_font_scale("nope") == 1.0
    assert _parse_scan_font_scale("nan") == 1.0
    assert _parse_scan_font_scale(None) == 1.0


def test_get_scan_font_scale_prefers_env_over_settings(monkeypatch):
    from core.utils.external_terminal import get_scan_font_scale
    from tests.fakes import FakeSettingsManager

    sm = FakeSettingsManager({"scanning": {"font_scale": 3.0}})
    monkeypatch.delenv("KFIOSA_SCAN_FONT_SCALE", raising=False)
    assert get_scan_font_scale(sm) == 3.0
    monkeypatch.setenv("KFIOSA_SCAN_FONT_SCALE", "1.5")
    assert get_scan_font_scale(sm) == 1.5


def test_set_scan_font_scale_persists(monkeypatch):
    from core.utils import external_terminal as et
    from tests.fakes import FakeSettingsManager

    monkeypatch.delenv("KFIOSA_SCAN_FONT_SCALE", raising=False)
    sm = FakeSettingsManager()
    applied = et.set_scan_font_scale(2.0, sm)
    assert applied == 2.0
    assert sm.get_setting("scanning.font_scale") == 2.0
    assert et.SCAN_WINDOW_FONT_SCALE == 2.0
    # reset for other tests
    et.set_scan_font_scale(1.0, sm)
