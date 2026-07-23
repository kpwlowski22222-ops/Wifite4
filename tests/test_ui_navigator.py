"""Tests for core.utils.ui_navigator (HostVisionNavigator OS Navigation & Auto-Labeling)."""

import json
from pathlib import Path
import pytest

from core.utils.ui_navigator import HostVisionNavigator, navigator


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
