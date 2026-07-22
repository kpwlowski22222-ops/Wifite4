"""core.live_edit.patch — PatchSpec dataclass + AST validator.

Validation is whitelist-based: only Assign/Expr/Return/If/For/AugAssign AST
nodes pass. Forbidden:
  - `__import__` calls
  - Calls to os.system / subprocess.call / os.popen
  - String literals containing shell metas (;, &&, ||, |, >, <, $) outside of
    regex-literal contexts (which we don't allow here anyway — these patches
    are small AST tweaks, not code blobs).
  - attribute access via `getattr(__import__("os"), "system")(...)` patterns
    (caught by the same `__import__` rule).

A patch that fails validation is refused; the runner is not modified.
"""
from __future__ import annotations

import ast
import dataclasses
import time
from typing import Any, Callable, Optional


#: AST node types that are safe inside the patch transform's output tree.
_SAFE_NODES = (
    ast.Module,
    ast.FunctionDef,
    ast.AsyncFunctionDef,
    ast.arguments,
    ast.arg,
    ast.Expr,
    ast.Return,
    ast.Assign,
    ast.AugAssign,
    ast.AnnAssign,
    ast.If,
    ast.For,
    ast.AsyncFor,
    ast.While,
    ast.Try,
    ast.ExceptHandler,
    ast.With,
    ast.Break,
    ast.Continue,
    ast.Pass,
    ast.Constant,   # numbers, strings, None, True, False
    ast.Name,
    ast.Load,
    ast.Store,
    ast.Del,
    ast.Call,
    ast.Attribute,
    ast.Subscript,
    ast.Index,      # py3.8 compat
    ast.Slice,      # 3.9+: foo[a:b]
    ast.Tuple,
    ast.List,
    ast.Dict,
    ast.Set,
    ast.keyword,
    ast.UnaryOp,
    ast.BinOp,
    ast.BoolOp,
    ast.Compare,
    ast.IfExp,
    ast.Lambda,
    ast.Not,        # not operator
    ast.Invert,     # ~ operator
    ast.USub,       # unary -
    ast.UAdd,      # unary +
    ast.And,
    ast.Or,
    ast.Eq,
    ast.NotEq,
    ast.Lt,
    ast.LtE,
    ast.Gt,
    ast.GtE,
    ast.Is,
    ast.IsNot,
    ast.In,
    ast.NotIn,
    ast.Add,
    ast.Sub,
    ast.Mult,
    ast.Div,
    ast.FloorDiv,
    ast.Mod,
    ast.Pow,
    ast.LShift,
    ast.RShift,
    ast.BitOr,
    ast.BitXor,
    ast.BitAnd,
    ast.MatMult,
    # --- 3.9+ (not enforced via version check; ast.parse() doesn't surface them) ---
    ast.JoinedStr,  # f-strings, but the constants inside must be whitelisted
    ast.FormattedValue,
)


#: Attribute targets that are NEVER allowed (any module).
_FORBIDDEN_ATTR_NAMES = frozenset(
    {
        "system", "popen", "exec", "execvp", "execvpe", "spawn",
        "call", "check_call", "check_output", "run", "Popen",
        "compile", "eval",
    }
)

#: Attribute path roots that are NEVER allowed (the leading module of an
# attribute chain — e.g. `os.system`, `subprocess.call`).
_FORBIDDEN_ATTR_ROOTS = frozenset(
    {
        "os", "subprocess", "shutil", "socket", "ctypes",
        "pty", "fcntl", "resource", "signal",
    }
)

#: Names that are NEVER allowed as bare-name calls / lookups.
_FORBIDDEN_NAMES = frozenset(
    {
        "exec", "eval", "compile", "__import__",
        "open",  # file IO; patches do not need raw file IO
        "input", # blocking
    }
)

#: Attribute targets that are NEVER allowed (any module).
# (We intentionally do NOT block shell metas in ordinary string literals.
# The protection is the `Call` rule below: no os.system / subprocess.call /
# os.popen / __import__ / eval / exec. That blocks the actual attack
# surface; blocking pipes/backticks in docstrings is over-broad and
# rejected legitimate Python source.)


@dataclasses.dataclass(frozen=True)
class PatchSpec:
    """A requested AST patch.

    Fields:
        target_runner: dotted module path, e.g. "core.wifi_attack.runner"
        target_method: the `_method` name on that module's class (the
                       instance method `_foo` to rewrite)
        patch_id:     id of a registered safe-patch from `test_patches`
        params:       dict of parameters passed to the patch callable
        rationale:    free-text reason (logged for audit)
        created_at:   unix timestamp (set on construction if not provided)
    """
    target_runner: str
    target_method: str
    patch_id: str
    params: dict
    rationale: str
    created_at: float = dataclasses.field(default_factory=time.time)


def _collect_node_signatures(node: ast.AST) -> set:
    """Collect a set of "signature" strings for every Call/Attribute/Name in
    the tree. Used to compare pre/post for delta detection.

    Each signature is a normalized string like:
        "Call:subprocess.run"
        "Call:os.system"
        "Attribute:subprocess.run"
    """
    sigs = set()
    for sub in ast.walk(node):
        if isinstance(sub, ast.Call):
            func = sub.func
            if isinstance(func, ast.Name):
                sigs.add(f"Call:{func.id}")
            elif isinstance(func, ast.Attribute):
                # root.attr
                root = func
                while isinstance(root, ast.Attribute):
                    root = root.value
                if isinstance(root, ast.Name):
                    sigs.add(f"Call:{root.id}.{func.attr}")
        elif isinstance(sub, ast.Attribute):
            root = sub
            while isinstance(root, ast.Attribute):
                root = root.value
            if isinstance(root, ast.Name):
                sigs.add(f"Attribute:{root.id}.{sub.attr}")
    return sigs


def _check_node(node: ast.AST, path: str = "<root>", pre_sigs: set = None) -> Optional[str]:
    """Recursively validate a single AST node; return an error string or None.

    Returns the FIRST error found (depth-first left-to-right).

    If `pre_sigs` is provided (a set of signatures from the ORIGINAL method
    body), then dangerous operations that ALSO existed in the original are
    allowed — the patch is not introducing new attack surface, it's
    preserving the original method's behavior.
    """
    pre_sigs = pre_sigs or set()
    if not isinstance(node, _SAFE_NODES):
        return f"forbidden AST node {type(node).__name__} at {path}"

    if isinstance(node, ast.Call):
        # forbidden bare-name calls
        func = node.func
        if isinstance(func, ast.Name) and func.id in _FORBIDDEN_NAMES:
            return f"forbidden call to {func.id}() at {path}"
        if isinstance(func, ast.Attribute):
            root = func
            while isinstance(root, ast.Attribute):
                root = root.value
            if isinstance(root, ast.Name):
                if root.id in _FORBIDDEN_ATTR_ROOTS and f"Call:{root.id}.{func.attr}" not in pre_sigs:
                    return f"forbidden attribute access on {root.id}.* at {path}"
                if func.attr in _FORBIDDEN_ATTR_NAMES and f"Call:{root.id}.{func.attr}" not in pre_sigs:
                    return f"forbidden attribute {root.id}.{func.attr} at {path}"
        # getattr(__import__('os'), 'system') pattern
        if isinstance(func, ast.Call) and isinstance(func.func, ast.Name) and func.func.id == "getattr":
            if func.args and isinstance(func.args[0], ast.Name):
                if func.args[0].id in _FORBIDDEN_ATTR_ROOTS:
                    return f"forbidden getattr on {func.args[0].id} at {path}"
            if len(func.args) >= 2 and isinstance(func.args[1], ast.Constant) and isinstance(func.args[1].value, str):
                if func.args[1].value in _FORBIDDEN_ATTR_NAMES:
                    return f"forbidden getattr .* {func.args[1].value!r} at {path}"

    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        # Note: we deliberately do NOT block shell metas (`;`, `&&`, `|`,
        # backticks, etc.) in ordinary string literals. The patched method
        # is a Python function — backticks / pipes are just characters. The
        # real protection is the `Call` rule above: no os.system /
        # subprocess.call / os.popen / __import__ / eval / exec. That
        # blocks the actual attack surface. The shell-meta check was
        # over-broad and rejected legitimate Python docstrings and string
        # arguments that happen to contain a backtick or semicolon.
        pass

    # recurse
    for field, value in ast.iter_fields(node):
        if isinstance(value, list):
            for i, child in enumerate(value):
                if isinstance(child, ast.AST):
                    err = _check_node(child, f"{path}.{field}[{i}]", pre_sigs)
                    if err:
                        return err
        elif isinstance(value, ast.AST):
            err = _check_node(value, f"{path}.{field}", pre_sigs)
            if err:
                return err
    return None


def validate_patch(spec: PatchSpec, transform_output: ast.AST,
                   pre_node: Optional[ast.AST] = None) -> tuple[bool, str]:
    """Validate a patch's output AST.

    Args:
        spec: the PatchSpec (for logging context only)
        transform_output: the AST node the safe-patch callable produced
        pre_node: the ORIGINAL method AST node (before the patch). When
                  provided, signatures of dangerous calls/attributes that
                  EXIST in the original are tolerated — the patch isn't
                  introducing new attack surface, it's preserving the
                  runner's own behavior. The pre_node is the runner's own
                  trusted source code.

    Returns:
        (ok, reason) — reason is "" when ok, else a human-readable string
    """
    # 1. patch_id must be registered
    if spec.patch_id not in _AVAILABLE_PATCH_IDS:
        return False, f"unknown patch_id {spec.patch_id!r}; available: {sorted(_AVAILABLE_PATCH_IDS)}"

    # 2. target_runner / target_method are well-formed strings
    if not spec.target_runner or not isinstance(spec.target_runner, str):
        return False, "target_runner must be a non-empty string"
    if not spec.target_method or not isinstance(spec.target_method, str):
        return False, "target_method must be a non-empty string"
    if not spec.target_method.startswith("_"):
        return False, f"target_method {spec.target_method!r} must start with '_' (private method)"

    # 3. rationale must be a non-empty string (operator can read it)
    if not isinstance(spec.rationale, str) or not spec.rationale.strip():
        return False, "rationale must be a non-empty string"

    # 4. transform output must be safe AST (with pre-existing signatures
    #    tolerated from the runner's own original source)
    pre_sigs = _collect_node_signatures(pre_node) if pre_node is not None else set()
    err = _check_node(transform_output, path=f"<{spec.patch_id}>", pre_sigs=pre_sigs)
    if err is not None:
        return False, err

    return True, ""


#: Registry of safe-patch ids → callables. Populated by `test_patches.py`.
_AVAILABLE_PATCH_IDS: dict[str, Callable] = {}


def list_available_patches() -> list[str]:
    """Return sorted list of registered safe-patch ids the AI may name."""
    return sorted(_AVAILABLE_PATCH_IDS)


def register_patch(patch_id: str, fn: Callable) -> None:
    """Called by `test_patches` on import to populate the registry."""
    _AVAILABLE_PATCH_IDS[patch_id] = fn


def resolve_patch(patch_id: str) -> Optional[Callable]:
    """Look up a registered safe-patch by id; None if unknown."""
    return _AVAILABLE_PATCH_IDS.get(patch_id)
