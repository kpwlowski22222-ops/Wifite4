"""core.live_edit.test_patches — the safe-patch catalog the AI can name by id.

These are small, parameterized, auditable AST transforms. They are NOT a way
for the AI to inject arbitrary code. The validator in `patch.py` enforces
whitelist-only AST.

Each patch function takes:
    method_node: ast.FunctionDef (the original `_method` AST node)
    params:      dict (from the PatchSpec)

and returns:
    ast.FunctionDef (a transformed copy of the method, never the original)

A patch the validator rejects is never applied. A patch the operator's gate
rejects is never applied.
"""
from __future__ import annotations

import ast
import copy
from typing import Any

from .patch import register_patch


def _ensure_args(method: ast.FunctionDef) -> ast.arguments:
    """Return the method's arguments; create defaults if missing."""
    return method.args


def _add_optional_arg(method: ast.FunctionDef, arg_name: str, default: Any) -> ast.FunctionDef:
    """Append `arg_name` to the method's args with the given default (a literal)."""
    new = copy.deepcopy(method)
    args = new.args
    # insert as a positional-or-keyword arg at the end
    new_arg = ast.arg(arg=arg_name, annotation=None)
    args.args.append(new_arg)
    # ensure defaults list is the right length for the args list
    # (defaults align with the LAST len(defaults) args)
    if not isinstance(default, ast.AST):
        default_node: ast.expr = ast.Constant(value=default)
    else:
        default_node = default
    args.defaults.append(default_node)
    ast.fix_missing_locations(new)
    return new


def _set_which_fail_to_real(method: ast.FunctionDef, tool_name: str, real_path: str) -> ast.FunctionDef:
    """Find a `_which(tool)` call returning False and short-circuit to True.

    Pattern looked for (heuristic): any `if not self._which(...):` or
    `if not _which(...):` line. The patch replaces the predicate's return
    by inserting an early `return True` for `tool_name` at the very top of
    the method.

    This is intentionally conservative: it does not modify the existing
    control flow; it ADDS a guard at the top.
    """
    new = copy.deepcopy(method)
    guard = ast.If(
        test=ast.Compare(
            left=ast.Constant(value=tool_name),
            ops=[ast.Eq()],
            comparators=[ast.Attribute(
                value=ast.Name(id="args", ctx=ast.Load()),
                attr="tool",
                ctx=ast.Load(),
            )],
        ),
        body=[ast.Return(value=ast.Constant(value=True))],
        orelse=[],
    )
    ast.copy_location(guard, new)
    new.body.insert(0, guard)
    ast.fix_missing_locations(new)
    return new


def _swap_retry_count(method: ast.FunctionDef, new_count: int) -> ast.FunctionDef:
    """Multiply the literal int `1` or `0` in the method's body by new_count.

    This is a toy example: it finds `for i in range(N):` patterns and replaces
    `N` with `N * new_count`. Used for things like "bump the retry loop N
    times without rewriting the rest of the method".
    """
    new = copy.deepcopy(method)
    for node in ast.walk(new):
        if isinstance(node, ast.For) and isinstance(node.iter, ast.Call):
            func = node.iter.func
            if isinstance(func, ast.Name) and func.id == "range":
                # bump the upper bound
                if node.iter.args:
                    upper = node.iter.args[0]
                    if isinstance(upper, ast.Constant) and isinstance(upper.value, int):
                        new_upper = ast.BinOp(
                            left=ast.Constant(value=upper.value),
                            op=ast.Mult(),
                            right=ast.Constant(value=new_count),
                        )
                        ast.copy_location(new_upper, upper)
                        node.iter.args[0] = new_upper
                        break  # only the first range() — the first loop
    ast.fix_missing_locations(new)
    return new


def _add_logging(method: ast.FunctionDef) -> ast.FunctionDef:
    """Prepend a `data["live_edited"] = True` line to the method body.

    Useful for tagging that the method has been live-edited when it runs.
    """
    new = copy.deepcopy(method)
    stmt = ast.Assign(
        targets=[ast.Subscript(
            value=ast.Name(id="data", ctx=ast.Load()),
            slice=ast.Constant(value="live_edited"),
            ctx=ast.Store(),
        )],
        value=ast.Constant(value=True),
    )
    ast.copy_location(stmt, new.body[0] if new.body else new)
    new.body.insert(0, stmt)
    ast.fix_missing_locations(new)
    return new


# Register
register_patch("add_optional_arg", _add_optional_arg)
register_patch("set_which_fail_to_real", _set_which_fail_to_real)
register_patch("swap_retry_count", _swap_retry_count)
register_patch("add_logging", _add_logging)
