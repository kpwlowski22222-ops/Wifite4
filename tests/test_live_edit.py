"""Hermetic tests for core.live_edit — AST validator, apply, revert, reload."""
from __future__ import annotations

import ast
import json
import sys
from pathlib import Path

import pytest


# ---------------------------------------------------------------------------
# Validator
# ---------------------------------------------------------------------------

class TestValidator:
    def test_valid_assign_passes(self):
        from core.live_edit import PatchSpec
        from core.live_edit.patch import validate_patch

        # simple: x = 1
        node = ast.parse("x = 1").body[0]
        spec = PatchSpec(
            target_runner="core.wifi_attack.runner",
            target_method="_foo",
            patch_id="add_logging",
            params={},
            rationale="bump x",
        )
        ok, reason = validate_patch(spec, node)
        assert ok, reason

    def test_forbidden_shell_meta_NOT_blocked_in_string(self):
        """Shell metas in ordinary string literals are NOT blocked (the
        protection is the Call rule that blocks os.system / subprocess.call
        / __import__ / eval / exec). The patched method is a Python
        function, not a shell command — backticks/pipes are just chars."""
        from core.live_edit import PatchSpec
        from core.live_edit.patch import validate_patch

        # This is a legitimate string literal that happens to contain a
        # semicolon (a docstring, a comment, a regex). It is NOT a shell
        # injection. The validator should let it through.
        node = ast.parse('x = "a; rm -rf /"').body[0]
        spec = PatchSpec(
            target_runner="core.wifi_attack.runner",
            target_method="_foo",
            patch_id="add_logging",
            params={},
            rationale="x",
        )
        ok, reason = validate_patch(spec, node)
        assert ok, reason

    def test_forbidden_os_system_rejected(self):
        from core.live_edit import PatchSpec
        from core.live_edit.patch import validate_patch

        node = ast.parse("os.system('rm -rf /')").body[0]
        spec = PatchSpec(
            target_runner="core.wifi_attack.runner",
            target_method="_foo",
            patch_id="add_logging",
            params={},
            rationale="x",
        )
        ok, reason = validate_patch(spec, node)
        assert not ok
        assert "os.system" in reason or "os.*" in reason

    def test_forbidden_subprocess_call_rejected(self):
        from core.live_edit import PatchSpec
        from core.live_edit.patch import validate_patch

        node = ast.parse("subprocess.call(['ls'])").body[0]
        spec = PatchSpec(
            target_runner="core.wifi_attack.runner",
            target_method="_foo",
            patch_id="add_logging",
            params={},
            rationale="x",
        )
        ok, reason = validate_patch(spec, node)
        assert not ok

    def test_forbidden_eval_rejected(self):
        from core.live_edit import PatchSpec
        from core.live_edit.patch import validate_patch

        node = ast.parse("eval('1+1')").body[0]
        spec = PatchSpec(
            target_runner="core.wifi_attack.runner",
            target_method="_foo",
            patch_id="add_logging",
            params={},
            rationale="x",
        )
        ok, reason = validate_patch(spec, node)
        assert not ok
        assert "eval" in reason

    def test_forbidden_dunder_import_rejected(self):
        from core.live_edit import PatchSpec
        from core.live_edit.patch import validate_patch

        node = ast.parse("x = __import__('os')").body[0]
        spec = PatchSpec(
            target_runner="core.wifi_attack.runner",
            target_method="_foo",
            patch_id="add_logging",
            params={},
            rationale="x",
        )
        ok, reason = validate_patch(spec, node)
        assert not ok

    def test_unknown_patch_id_rejected(self):
        from core.live_edit import PatchSpec
        from core.live_edit.patch import validate_patch

        node = ast.parse("x = 1").body[0]
        spec = PatchSpec(
            target_runner="core.wifi_attack.runner",
            target_method="_foo",
            patch_id="not_a_real_patch",
            params={},
            rationale="x",
        )
        ok, reason = validate_patch(spec, node)
        assert not ok
        assert "unknown patch_id" in reason

    def test_empty_rationale_rejected(self):
        from core.live_edit import PatchSpec
        from core.live_edit.patch import validate_patch

        node = ast.parse("x = 1").body[0]
        spec = PatchSpec(
            target_runner="core.wifi_attack.runner",
            target_method="_foo",
            patch_id="add_logging",
            params={},
            rationale="   ",
        )
        ok, reason = validate_patch(spec, node)
        assert not ok
        assert "rationale" in reason

    def test_target_method_must_underscore(self):
        from core.live_edit import PatchSpec
        from core.live_edit.patch import validate_patch

        node = ast.parse("x = 1").body[0]
        spec = PatchSpec(
            target_runner="core.wifi_attack.runner",
            target_method="foo",  # no underscore
            patch_id="add_logging",
            params={},
            rationale="x",
        )
        ok, reason = validate_patch(spec, node)
        assert not ok
        assert "_" in reason or "underscore" in reason


# ---------------------------------------------------------------------------
# Built-in patches
# ---------------------------------------------------------------------------

class TestBuiltinPatches:
    def test_add_logging_inserts_assign(self):
        from core.live_edit.test_patches import _add_logging

        method = ast.parse("def _foo(self, args):\n    return None\n").body[0]
        out = _add_logging(method)
        assert isinstance(out, ast.FunctionDef)
        assert out.name == "_foo"
        # first body stmt should be an assign to data["live_edited"]
        first = out.body[0]
        assert isinstance(first, ast.Assign)

    def test_add_optional_arg_appends(self):
        from core.live_edit.test_patches import _add_optional_arg

        method = ast.parse("def _foo(self, args):\n    return None\n").body[0]
        out = _add_optional_arg(method, "max_retries", 5)
        assert isinstance(out, ast.FunctionDef)
        arg_names = [a.arg for a in out.args.args]
        assert "max_retries" in arg_names

    def test_swap_retry_count_bumps_range(self):
        from core.live_edit.test_patches import _swap_retry_count

        method = ast.parse(
            "def _foo(self, args):\n    for i in range(3):\n        pass\n"
        ).body[0]
        out = _swap_retry_count(method, 10)
        for node in ast.walk(out):
            if isinstance(node, ast.For) and isinstance(node.iter, ast.Call):
                upper = node.iter.args[0]
                # BinOp(Constant(3) * Constant(10))
                assert isinstance(upper, ast.BinOp)
                break

    def test_set_which_fail_to_real_inserts_guard(self):
        from core.live_edit.test_patches import _set_which_fail_to_real

        method = ast.parse(
            "def _foo(self, args):\n    return None\n"
        ).body[0]
        out = _set_which_fail_to_real(method, "gatttool", "/usr/bin/gatttool")
        assert isinstance(out, ast.FunctionDef)
        # first stmt should be an If
        assert isinstance(out.body[0], ast.If)


# ---------------------------------------------------------------------------
# list_available_patches
# ---------------------------------------------------------------------------

def test_list_available_patches_includes_builtins():
    from core.live_edit.patch import list_available_patches
    p = list_available_patches()
    assert "add_logging" in p
    assert "add_optional_arg" in p
    assert "swap_retry_count" in p
    assert "set_which_fail_to_real" in p


# ---------------------------------------------------------------------------
# Apply / revert end-to-end (uses a tiny throwaway runner module)
# ---------------------------------------------------------------------------

@pytest.fixture
def tiny_runner_path(tmp_path, monkeypatch):
    """Write a throwaway runner module to tmp_path and return its import path.

    Registers both the package and the leaf module in sys.modules so that
    `importlib.import_module` and `importlib.reload` both work.
    """
    import sys
    import importlib.util
    import types
    pkg = tmp_path / "tiny_live_edit_pkg"
    pkg.mkdir()
    pkg_init = pkg / "__init__.py"
    pkg_init.write_text("")
    mod = pkg / "tiny_runner.py"
    mod.write_text(
        "class TinyRunner:\n"
        "    def _foo(self, args):\n"
        "        return {'ok': True, 'data': {'value': 1}}\n"
    )
    # Register the parent package and the leaf module
    pkg_mod = types.ModuleType("tiny_live_edit_pkg")
    pkg_mod.__path__ = [str(pkg)]
    sys.modules["tiny_live_edit_pkg"] = pkg_mod

    spec = importlib.util.spec_from_file_location(
        "tiny_live_edit_pkg.tiny_runner", str(mod)
    )
    mod_obj = importlib.util.module_from_spec(spec)
    sys.modules["tiny_live_edit_pkg.tiny_runner"] = mod_obj
    spec.loader.exec_module(mod_obj)

    yield ("tiny_live_edit_pkg.tiny_runner", "TinyRunner", mod)

    # cleanup
    sys.modules.pop("tiny_live_edit_pkg.tiny_runner", None)
    sys.modules.pop("tiny_live_edit_pkg", None)


class TestApplyRevert:
    def test_apply_writes_overlay(self, tiny_runner_path):
        from core.live_edit import PatchSpec
        from core.live_edit.apply import apply_patch, revert_patch

        runner_path, class_name, _ = tiny_runner_path
        spec = PatchSpec(
            target_runner=runner_path,
            target_method="_foo",
            patch_id="add_logging",
            params={},
            rationale="hermetic test",
        )
        out_path = apply_patch(spec, confirm_fn=None)
        assert out_path is not None
        p = Path(out_path)
        assert p.exists()
        # cleanup
        revert_patch(out_path)

    def test_apply_then_revert_removes_file(self, tiny_runner_path):
        from core.live_edit import PatchSpec
        from core.live_edit.apply import apply_patch, revert_patch

        runner_path, _, _ = tiny_runner_path
        spec = PatchSpec(
            target_runner=runner_path,
            target_method="_foo",
            patch_id="add_logging",
            params={},
            rationale="hermetic test",
        )
        out_path = apply_patch(spec, confirm_fn=None)
        assert out_path is not None
        ok = revert_patch(out_path)
        assert ok
        assert not Path(out_path).exists()

    def test_apply_cancelled_by_confirm(self, tiny_runner_path):
        from core.live_edit import PatchSpec
        from core.live_edit.apply import apply_patch

        runner_path, _, _ = tiny_runner_path
        spec = PatchSpec(
            target_runner=runner_path,
            target_method="_foo",
            patch_id="add_logging",
            params={},
            rationale="hermetic test",
        )
        out = apply_patch(spec, confirm_fn=lambda msg: False)
        assert out is None

    def test_apply_accepted_by_confirm(self, tiny_runner_path):
        from core.live_edit import PatchSpec
        from core.live_edit.apply import apply_patch, revert_patch

        runner_path, _, _ = tiny_runner_path
        spec = PatchSpec(
            target_runner=runner_path,
            target_method="_foo",
            patch_id="add_logging",
            params={},
            rationale="hermetic test",
        )
        out = apply_patch(spec, confirm_fn=lambda msg: True)
        assert out is not None
        revert_patch(out)

    def test_unknown_target_method_refused(self, tiny_runner_path):
        from core.live_edit import PatchSpec
        from core.live_edit.apply import apply_patch

        runner_path, _, _ = tiny_runner_path
        spec = PatchSpec(
            target_runner=runner_path,
            target_method="_does_not_exist",
            patch_id="add_logging",
            params={},
            rationale="x",
        )
        out = apply_patch(spec, confirm_fn=None)
        assert out is None

    def test_unknown_runner_refused(self):
        from core.live_edit import PatchSpec
        from core.live_edit.apply import apply_patch

        spec = PatchSpec(
            target_runner="core.no_such_module_x_y_z",
            target_method="_foo",
            patch_id="add_logging",
            params={},
            rationale="x",
        )
        out = apply_patch(spec, confirm_fn=None)
        assert out is None

    def test_revert_missing_path_returns_false(self):
        from core.live_edit.apply import revert_patch
        assert revert_patch("/tmp/definitely_not_here_overlay.py") is False


# ---------------------------------------------------------------------------
# Reload
# ---------------------------------------------------------------------------

class TestReload:
    def test_reload_no_overlay_returns_module(self, tiny_runner_path):
        from core.live_edit.reload import reload_runner_with_overlays
        runner_path, _, _ = tiny_runner_path
        mod = reload_runner_with_overlays(runner_path)
        assert mod is not None

    def test_reload_with_overlay_returns_class(self, tiny_runner_path):
        from core.live_edit import PatchSpec
        from core.live_edit.apply import apply_patch, revert_patch
        from core.live_edit.reload import reload_runner_with_overlays

        runner_path, _, _ = tiny_runner_path
        spec = PatchSpec(
            target_runner=runner_path,
            target_method="_foo",
            patch_id="add_logging",
            params={},
            rationale="x",
        )
        out = apply_patch(spec, confirm_fn=None)
        try:
            cls = reload_runner_with_overlays(runner_path)
            assert cls is not None
        finally:
            revert_patch(out)


# ---------------------------------------------------------------------------
# Log
# ---------------------------------------------------------------------------

def test_log_appends():
    from core.live_edit.log import _append_log, get_patch_log, _LOG_PATH
    before = len(get_patch_log())
    _append_log({"event": "test_marker", "x": 1})
    after = len(get_patch_log())
    assert after == before + 1


def test_log_file_is_jsonl():
    """Verify the log file is valid JSONL when written."""
    from core.live_edit.log import _append_log, _LOG_PATH

    _append_log({"event": "jsonl_test", "n": 42})
    text = _LOG_PATH.read_text()
    last_line = text.strip().splitlines()[-1]
    parsed = json.loads(last_line)
    assert parsed["event"] == "jsonl_test"
    assert parsed["n"] == 42


# ---------------------------------------------------------------------------
# Adversarial
# ---------------------------------------------------------------------------

class TestAdversarial:
    def test_dunder_getattr_attr_access_blocked(self):
        """`getattr(os, 'system')` is caught because it has `os` as attr root."""
        from core.live_edit import PatchSpec
        from core.live_edit.patch import validate_patch

        node = ast.parse("getattr(os, 'system')('ls')").body[0]
        spec = PatchSpec(
            target_runner="x",
            target_method="_foo",
            patch_id="add_logging",
            params={},
            rationale="x",
        )
        ok, reason = validate_patch(spec, node)
        assert not ok

    def test_pipe_in_string_NOT_blocked(self):
        """Pipes/backticks/dollars in plain string literals are NOT
        blocked — the patch writes Python source, not a shell command.
        The real protection is the `Call` rule (no os.system, etc.)."""
        from core.live_edit import PatchSpec
        from core.live_edit.patch import validate_patch

        node = ast.parse('x = "ls | grep foo"').body[0]
        spec = PatchSpec(
            target_runner="x",
            target_method="_foo",
            patch_id="add_logging",
            params={},
            rationale="x",
        )
        ok, _ = validate_patch(spec, node)
        assert ok  # plain string literal is allowed

    def test_dollar_subshell_NOT_blocked_in_string(self):
        from core.live_edit import PatchSpec
        from core.live_edit.patch import validate_patch

        node = ast.parse('x = "$(rm -rf /)"').body[0]
        spec = PatchSpec(
            target_runner="x",
            target_method="_foo",
            patch_id="add_logging",
            params={},
            rationale="x",
        )
        ok, _ = validate_patch(spec, node)
        assert ok

    def test_dollar_subshell_BLOCKED_in_call(self):
        """The protection lives in the Call rule: this expression calls
        `__import__('os').system('$(rm -rf /)')` — that IS blocked."""
        from core.live_edit import PatchSpec
        from core.live_edit.patch import validate_patch

        node = ast.parse("__import__('os').system('$(rm -rf /)')").body[0]
        spec = PatchSpec(
            target_runner="x",
            target_method="_foo",
            patch_id="add_logging",
            params={},
            rationale="x",
        )
        ok, reason = validate_patch(spec, node)
        assert not ok
