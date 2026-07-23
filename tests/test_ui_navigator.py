"""Tests for core.utils.ui_navigator (HostVisionNavigator OS Navigation & Auto-Labeling)."""

import pytest

from core.utils.ui_navigator import HostVisionNavigator


def test_ui_navigator_init(tmp_path):
    nav = HostVisionNavigator(cache_dir=tmp_path)
    assert nav.cache_dir == tmp_path
    assert nav.regions_dir == tmp_path / "regions"
    assert nav.labels_index_path == tmp_path / "ui_labels_index.json"


def test_navigate_os_step(tmp_path):
    nav = HostVisionNavigator(cache_dir=tmp_path)
    step_res = nav.navigate_os_step(step_idx=1)

    assert step_res["step"] == 1
    assert "window" in step_res
    assert "labels_discovered" in step_res
    assert step_res["labels_discovered"] >= 0
    assert "screenshot" in step_res


def test_start_learning_session(tmp_path):
    nav = HostVisionNavigator(cache_dir=tmp_path)
    logs = []

    def cb(msg):
        logs.append(msg)

    summary = nav.start_learning_session(steps=2, callback=cb)

    assert summary["steps_completed"] == 2
    assert "total_labels" in summary
    assert "total_cropped_regions" in summary
    assert len(summary["steps"]) == 2
    assert any("Starting AI Vision OS Navigation" in l for l in logs)
    assert any("Vision Learning Complete" in l for l in logs)
    assert nav.labels_index_path.is_file()


def test_local_vision_fallback(tmp_path):
    nav = HostVisionNavigator(cache_dir=tmp_path)
    img_path = tmp_path / "sample_screen.png"

    # Create dummy image
    try:
        from PIL import Image
        img = Image.new("RGB", (800, 600), color=(200, 200, 200))
        img.save(img_path)
    except ImportError:
        pytest.skip("PIL not installed")

    discovered = nav.extract_labels_via_local_vision(img_path)
    assert len(discovered) > 0
    assert any("OS_Top_Menu_Bar" in d.get("label", "") or d.get("label") for d in discovered)
    assert nav.labels_index_path.is_file()


def test_navigate_os_step_honest_degrade_when_capture_fails(tmp_path):
    """When no screenshot tool works, navigate_os_step must NOT fabricate
    a blank placeholder image or default OS regions."""
    nav = HostVisionNavigator(cache_dir=tmp_path)
    nav.capture_fullscreen = lambda *a, **k: None
    step_res = nav.navigate_os_step(step_idx=1)
    assert step_res["ok"] is False
    assert step_res["screenshot"] == ""
    assert step_res["labels_discovered"] == 0
    assert step_res["regions_cropped"] == 0
    assert "capture unavailable" in step_res["error"].lower()


def test_read_screen_content_honest_degrade_when_capture_fails(tmp_path):
    nav = HostVisionNavigator(cache_dir=tmp_path)
    nav.capture_fullscreen = lambda *a, **k: None
    res = nav.read_screen_content()
    assert res["ok"] is False
    assert res["screenshot"] == ""
    assert res["labels"] == []
    assert "screen capture unavailable" in res["error"].lower()


def test_label_screen_live_honest_degrade_when_capture_fails(tmp_path):
    nav = HostVisionNavigator(cache_dir=tmp_path)
    nav.capture_fullscreen = lambda *a, **k: None
    res = nav.label_screen_live(duration_s=0.2)
    assert res["ok"] is False
    assert res["labels"] == []
    assert res["labels_count"] == 0
    assert "no screen labels" in res["error"].lower()


def test_click_label_unknown(tmp_path):
    nav = HostVisionNavigator(cache_dir=tmp_path)
    res = nav.click_label("DoesNotExist")
    assert res["ok"] is False
    assert "not indexed" in res["error"].lower()


def test_click_label_no_box(tmp_path):
    nav = HostVisionNavigator(cache_dir=tmp_path)
    nav._labels_index["BadLabel"] = {"label": "BadLabel"}
    res = nav.click_label("BadLabel")
    assert res["ok"] is False
    assert "bounding box" in res["error"].lower()


def test_click_label_no_xdotool(monkeypatch, tmp_path):
    nav = HostVisionNavigator(cache_dir=tmp_path)
    nav._labels_index["OK"] = {"label": "OK", "box": [100, 200, 300, 400]}

    def _missing(*a, **k):
        raise FileNotFoundError("xdotool")

    monkeypatch.setattr("core.utils.ui_navigator.subprocess.run", _missing)
    res = nav.click_label("OK")
    assert res["ok"] is False
    assert "xdotool not installed" in res["error"].lower()


def test_click_label_success(monkeypatch, tmp_path):
    nav = HostVisionNavigator(cache_dir=tmp_path)
    nav._labels_index["OK"] = {"label": "OK", "box": [100, 200, 300, 400]}
    calls = []

    def _fake_run(argv, **kw):
        calls.append(argv)
        class _R:
            returncode = 0
            stderr = b""
        return _R()

    monkeypatch.setattr("core.utils.ui_navigator.subprocess.run", _fake_run)
    res = nav.click_label("OK")
    assert res["ok"] is True
    assert res["click"] == [200, 300]
    assert calls[0] == ["xdotool", "mousemove", "200", "300", "click", "1"]
