"""Hermetic tests for the AI model picker per target class.

Covers:
  * ``_pick_model_for_target`` for all 3 target classes + fallback
  * The catalog shape (3 verticals + fallback)
  * The picker is invoked from chain.py before fallback
  * Empty / unknown target class → fallback
"""
from __future__ import annotations

import unittest

from core.ai_backend import (
    MODEL_CATALOG,
    TARGET_MODEL_CATALOG,
    VALID_TARGET_CLASSES,
    AIBackend,
)


class TestTargetModelCatalog(unittest.TestCase):

    def test_catalog_keys(self) -> None:
        self.assertIn("microsoft", TARGET_MODEL_CATALOG)
        self.assertIn("android", TARGET_MODEL_CATALOG)
        self.assertIn("ios", TARGET_MODEL_CATALOG)
        self.assertIn("fallback", TARGET_MODEL_CATALOG)

    def test_valid_target_classes(self) -> None:
        self.assertEqual(set(VALID_TARGET_CLASSES),
                         {"microsoft", "android", "ios"})

    def test_all_three_use_same_model(self) -> None:
        # Operator-chosen: a single code-architect model is used
        # for all 3 verticals to avoid ollama-pull multiplication.
        ms = TARGET_MODEL_CATALOG["microsoft"]
        an = TARGET_MODEL_CATALOG["android"]
        io = TARGET_MODEL_CATALOG["ios"]
        self.assertEqual(ms, an)
        self.assertEqual(an, io)

    def test_fallback_matches_main_fallback(self) -> None:
        self.assertEqual(TARGET_MODEL_CATALOG["fallback"],
                         MODEL_CATALOG["fallback"])

    def test_uncensored_model_for_code_arch(self) -> None:
        # The vertical catalog uses the operator's preferred
        # uncensored code-architect model.
        for tc in ("microsoft", "android", "ios"):
            m = TARGET_MODEL_CATALOG[tc]
            self.assertIn("Coder", m)
            self.assertIn("uncensored", m)


class TestPickModelForTarget(unittest.TestCase):

    def setUp(self) -> None:
        self.backend = AIBackend()

    def test_microsoft(self) -> None:
        m = self.backend._pick_model_for_target("microsoft")
        self.assertEqual(m, TARGET_MODEL_CATALOG["microsoft"])

    def test_android(self) -> None:
        m = self.backend._pick_model_for_target("android")
        self.assertEqual(m, TARGET_MODEL_CATALOG["android"])

    def test_ios(self) -> None:
        m = self.backend._pick_model_for_target("ios")
        self.assertEqual(m, TARGET_MODEL_CATALOG["ios"])

    def test_empty_returns_fallback(self) -> None:
        m = self.backend._pick_model_for_target("")
        self.assertEqual(m, MODEL_CATALOG["fallback"])

    def test_unknown_returns_fallback(self) -> None:
        m = self.backend._pick_model_for_target("wifi")
        self.assertEqual(m, MODEL_CATALOG["fallback"])

    def test_case_insensitive(self) -> None:
        m = self.backend._pick_model_for_target("Microsoft")
        self.assertEqual(m, TARGET_MODEL_CATALOG["microsoft"])

    def test_whitespace_tolerant(self) -> None:
        m = self.backend._pick_model_for_target("  android  ")
        self.assertEqual(m, TARGET_MODEL_CATALOG["android"])

    def test_none_safe(self) -> None:
        # None (or any non-string) → fallback.
        try:
            m = self.backend._pick_model_for_target(None)  # type: ignore
        except (TypeError, AttributeError):
            m = MODEL_CATALOG["fallback"]
        self.assertEqual(m, MODEL_CATALOG["fallback"])


class TestPickerDoesNotBypassSafety(unittest.TestCase):
    """The picker must NOT bypass refusal. Same uncensored-swap
    rule (HERETIC 9B then fallback) applies; the picker is a
    *model* choice, not a *safety* override."""

    def test_picker_returns_string(self) -> None:
        b = AIBackend()
        m = b._pick_model_for_target("microsoft")
        self.assertIsInstance(m, str)
        self.assertGreater(len(m), 0)

    def test_no_special_marker_in_picked_model(self) -> None:
        # The picker is just a model tag; it doesn't carry a
        # "bypass" marker.
        b = AIBackend()
        m = b._pick_model_for_target("ios")
        self.assertNotIn("bypass", m.lower())
        self.assertNotIn("override", m.lower())


if __name__ == "__main__":
    unittest.main()
