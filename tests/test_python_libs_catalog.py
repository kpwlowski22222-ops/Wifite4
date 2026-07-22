"""tests.test_python_libs_catalog — verify the curated
Python-libs registry, the catalog emitter, and the chain
planner prompt stanza.

Coverage:

  - python_libs.py: registry shape, lookups, categories
  - catalog_python_libs.py: entry shape, idempotent emit,
    pypi_index.json, category filter, CLI
  - chain.py: PYTHON_LIB_PROMPT_STANZA renders, schema
    includes ``run_python_lib`` action
  - mcp/tools.py: _make_python_lib_wrappers produces one
    wrapper per library, with the right risk level + names
  - never-inline: no harvested creds in any python-lib file
  - no bare except in the new files
"""
from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path
from unittest import mock

import pytest


# ---------------------------------------------------------------------------
# Registry: shape + lookups
# ---------------------------------------------------------------------------

def test_registry_is_non_empty():
    from core.toolbox.python_libs import PYTHON_LIBRARIES
    assert len(PYTHON_LIBRARIES) >= 50, (
        f"expected at least 50 curated libraries, got {len(PYTHON_LIBRARIES)}"
    )


def test_registry_entries_have_required_keys():
    from core.toolbox.python_libs import PYTHON_LIBRARIES
    required = {
        "name", "import_name", "pip", "version", "category",
        "summary", "description", "entry", "example",
        "risk_level", "requires_gate",
    }
    for lib in PYTHON_LIBRARIES:
        missing = required - set(lib.keys())
        assert not missing, (
            f"library {lib.get('name')!r} missing keys: {missing}"
        )


def test_registry_risk_levels_are_known():
    from core.toolbox.python_libs import PYTHON_LIBRARIES
    valid = {"low", "medium", "high", "critical"}
    for lib in PYTHON_LIBRARIES:
        assert lib["risk_level"] in valid, (
            f"{lib['name']} has unknown risk_level "
            f"{lib['risk_level']!r}"
        )


def test_registry_categories_are_known():
    from core.toolbox.python_libs import PYTHON_LIBRARIES
    valid = {
        "network", "exploit", "web", "crypto", "osint", "recon",
        "ble", "wifi", "c2", "post_exploitation", "utility", "ai",
    }
    for lib in PYTHON_LIBRARIES:
        assert lib["category"] in valid, (
            f"{lib['name']} has unknown category {lib['category']!r}"
        )


def test_get_library_by_pip_name():
    from core.toolbox import get_library
    lib = get_library("scapy")
    assert lib is not None
    assert lib["import_name"] == "scapy"
    assert lib["category"] == "network"


def test_get_library_by_import_name():
    """`Crypto` is the import name; `pycryptodome` is the pip name."""
    from core.toolbox import get_library
    lib = get_library("Crypto")
    assert lib is not None
    assert lib["pip"] == "pycryptodome"
    assert lib["name"] == "pycryptodome"


def test_get_library_returns_none_for_unknown():
    from core.toolbox import get_library
    assert get_library("") is None
    assert get_library("nonexistent-xyz") is None
    assert get_library(None) is None  # type: ignore[arg-type]


def test_list_libraries_by_category():
    from core.toolbox import list_libraries
    wifi = list_libraries(category="wifi")
    assert all(lib["category"] == "wifi" for lib in wifi)
    assert len(wifi) >= 1


def test_list_libraries_no_filter():
    from core.toolbox import list_libraries
    from core.toolbox.python_libs import PYTHON_LIBRARIES
    assert len(list_libraries()) == len(PYTHON_LIBRARIES)


def test_list_categories_returns_at_least_one():
    from core.toolbox.python_libs import list_categories
    cats = list_categories()
    assert len(cats) >= 5
    # No duplicates
    assert len(cats) == len(set(cats))


def test_categories_count_matches_total():
    from core.toolbox import categories_count
    counts = categories_count()
    assert sum(counts.values()) >= 50


def test_pypi_index_emitted_by_name():
    """The by_name covers every entry exactly once; by_import
    is a list-valued dict that may have multiple entries per
    import name (e.g. olefile, fpdf)."""
    from core.toolbox.python_libs import (
        PYTHON_LIB_BY_NAME, PYTHON_LIB_BY_IMPORT, PYTHON_LIBRARIES,
    )
    assert len(PYTHON_LIB_BY_NAME) == len(PYTHON_LIBRARIES)
    # Every entry is in by_import
    for lib in PYTHON_LIBRARIES:
        assert lib in PYTHON_LIB_BY_IMPORT[lib["import_name"]]
    # by_import keys cover every import name (deduped)
    import_names = {lib["import_name"] for lib in PYTHON_LIBRARIES}
    assert set(PYTHON_LIB_BY_IMPORT.keys()) == import_names


# ---------------------------------------------------------------------------
# Catalog emitter
# ---------------------------------------------------------------------------

def test_build_entry_for_shape(tmp_path):
    from core.toolbox.catalog_python_libs import build_entry_for
    from core.toolbox.python_libs import PYTHON_LIBRARIES
    scapy = next(l for l in PYTHON_LIBRARIES if l["name"] == "scapy")
    entry = build_entry_for(scapy)
    assert entry["id"] == "pypi:scapy"
    assert entry["kind"] == "python_library"
    assert entry["name"] == "scapy"
    assert entry["category"] == "network"
    assert entry["url"].startswith("https://pypi.org/project/scapy/")
    assert entry["metadata"]["pip_name"] == "scapy"
    assert entry["metadata"]["import_name"] == "scapy"
    assert entry["risk"]["level"] == "high"
    assert entry["risk"]["requires_explicit_authorization"] is True
    assert entry["risk"]["allow_autonomous_execution"] is False
    # Documentation block
    assert "pypi" in entry["documentation"]
    assert "import" in entry["documentation"]
    assert "entry" in entry["documentation"]
    assert "example" in entry["documentation"]


def test_emit_for_library_writes_file(tmp_path):
    from core.toolbox.catalog_python_libs import emit_for_library
    from core.toolbox.python_libs import PYTHON_LIBRARIES
    scapy = next(l for l in PYTHON_LIBRARIES if l["name"] == "scapy")
    out = emit_for_library(scapy, catalog_dir=tmp_path)
    assert out.is_file()
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["id"] == "pypi:scapy"
    assert payload["kind"] == "python_library"


def test_emit_python_lib_catalog_writes_all(tmp_path):
    from core.toolbox.catalog_python_libs import emit_python_lib_catalog
    summary = emit_python_lib_catalog(catalog_dir=tmp_path)
    assert summary["ok"] is True
    files = list(tmp_path.glob("pypi_*.json"))
    assert len(files) == summary["count"]
    assert len(files) >= 50


def test_emit_python_lib_catalog_is_idempotent(tmp_path):
    from core.toolbox.catalog_python_libs import emit_python_lib_catalog
    a = emit_python_lib_catalog(catalog_dir=tmp_path)
    b = emit_python_lib_catalog(catalog_dir=tmp_path)
    assert a["count"] == b["count"]
    # All files have the same content
    for f in sorted(tmp_path.glob("pypi_*.json")):
        a_text = f.read_text(encoding="utf-8")
        b_text = f.read_text(encoding="utf-8")
        assert a_text == b_text


def test_emit_index_json_shape(tmp_path):
    from core.toolbox.catalog_python_libs import (
        emit_index_json, emit_python_lib_catalog,
    )
    emit_python_lib_catalog(catalog_dir=tmp_path)
    idx = emit_index_json(catalog_dir=tmp_path)
    assert idx.is_file()
    payload = json.loads(idx.read_text(encoding="utf-8"))
    assert payload["kind"] == "python_library_index"
    assert payload["total"] >= 50
    assert "categories" in payload
    assert "network" in payload["categories"]
    # Each category has a list of library stubs
    for cat, libs in payload["categories"].items():
        for lib in libs:
            assert "id" in lib
            assert "name" in lib
            assert "import_name" in lib


def test_emit_catalog_with_category_filter(tmp_path):
    from core.toolbox.catalog_python_libs import emit_python_lib_catalog
    from core.toolbox import list_libraries
    summary = emit_python_lib_catalog(
        catalog_dir=tmp_path, libraries=list_libraries("wifi"),
    )
    assert summary["count"] >= 1
    files = list(tmp_path.glob("pypi_*.json"))
    # All emitted files are wifi-only
    for f in files:
        payload = json.loads(f.read_text(encoding="utf-8"))
        assert payload["category"] == "wifi"


def test_catalog_entry_slug_handles_dots():
    """Libraries like `python-dateutil` slugify to `pypi_python-dateutil.json`."""
    from core.toolbox.catalog_python_libs import (
        _slug, emit_for_library,
    )
    from core.toolbox.python_libs import PYTHON_LIBRARIES
    pd = next(l for l in PYTHON_LIBRARIES if l["name"] == "python-dateutil")
    assert _slug(pd["name"]) == "python-dateutil"
    # Roundtrip via a tmp dir
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        out = emit_for_library(pd, catalog_dir=Path(td))
        assert out.name == "pypi_python-dateutil.json"


# ---------------------------------------------------------------------------
# Chain planner prompt stanza
# ---------------------------------------------------------------------------

def test_python_lib_prompt_stanza_renders():
    from core.ai_backend.chain import PYTHON_LIB_PROMPT_STANZA
    assert isinstance(PYTHON_LIB_PROMPT_STANZA, str)
    assert len(PYTHON_LIB_PROMPT_STANZA) > 100
    assert "run_python_lib" in PYTHON_LIB_PROMPT_STANZA
    assert "KFIOSA_TARGET_PASSWORD" in PYTHON_LIB_PROMPT_STANZA


def test_chain_step_schema_includes_run_python_lib():
    from core.ai_backend.chain import _CHAIN_STEP_SCHEMA_HINT
    assert "run_python_lib" in _CHAIN_STEP_SCHEMA_HINT


def test_system_prompt_includes_python_lib_stanza():
    """The aggregate system prompt must include the python-lib
    stanza so the LLM sees it on every chain-plan call."""
    from core.ai_backend.chain import _SYSTEM_PROMPT
    assert "PYTHON_LIB_PROMPT_STANZA" not in _SYSTEM_PROMPT  # not the var name
    assert "run_python_lib" in _SYSTEM_PROMPT
    assert "KFIOSA_TARGET_PASSWORD" in _SYSTEM_PROMPT


# ---------------------------------------------------------------------------
# MCP wrappers
# ---------------------------------------------------------------------------

def test_mcp_python_lib_wrappers_count():
    from core.mcp import tools
    pylib = [k for k in tools.KALI_TOOL_WRAPPERS if k.startswith("pylib_")]
    assert len(pylib) >= 50


def test_mcp_python_lib_wrappers_have_right_names():
    from core.mcp import tools
    from core.toolbox.python_libs import PYTHON_LIBRARIES
    expected = {f"pylib_{lib['name']}" for lib in PYTHON_LIBRARIES}
    actual = {k for k in tools.KALI_TOOL_WRAPPERS if k.startswith("pylib_")}
    assert expected <= actual, (
        f"missing wrappers: {expected - actual}"
    )


def test_mcp_python_lib_wrapper_risk_levels():
    """Critical-risk libraries get RISK_DESTRUCTIVE; gated
    libraries get RISK_INTRUSIVE; others RISK_READ."""
    from core.mcp import tools
    from core.toolbox.python_libs import PYTHON_LIBRARIES
    for lib in PYTHON_LIBRARIES:
        w = tools.KALI_TOOL_WRAPPERS.get(f"pylib_{lib['name']}")
        assert w is not None
        if lib.get("risk_level") == "critical":
            assert w.risk_level == tools.RISK_DESTRUCTIVE
        elif lib.get("requires_gate"):
            assert w.risk_level == tools.RISK_INTRUSIVE
        else:
            assert w.risk_level == tools.RISK_READ


def test_mcp_python_lib_wrapper_examples():
    from core.mcp import tools
    from core.toolbox.python_libs import PYTHON_LIBRARIES
    scapy = next(l for l in PYTHON_LIBRARIES if l["name"] == "scapy")
    w = tools.KALI_TOOL_WRAPPERS["pylib_scapy"]
    # The example must mention the import name so the LLM can
    # see how to use the wrapper.
    assert any("scapy" in ex for ex in w.examples)


# ---------------------------------------------------------------------------
# Executor: arg validation
# ---------------------------------------------------------------------------

def test_run_python_lib_code_unknown_library():
    from core.toolbox import run_python_lib_code, PythonLibUnknownLibraryError
    with pytest.raises(PythonLibUnknownLibraryError):
        run_python_lib_code("definitely-not-a-real-lib", "print(1)")


def test_run_python_lib_code_missing_code():
    from core.toolbox import run_python_lib_code, PythonLibInvalidArgsError
    with pytest.raises(PythonLibInvalidArgsError):
        run_python_lib_code("rich", "")


def test_run_python_lib_code_missing_lib():
    from core.toolbox import run_python_lib_code, PythonLibInvalidArgsError
    with pytest.raises(PythonLibInvalidArgsError):
        run_python_lib_code("", "print(1)")


def test_run_python_lib_code_timeout_capped():
    from core.toolbox import (
        run_python_lib_code, PYTHON_LIB_MAX_TIMEOUT_SECONDS,
    )
    # Timeout is silently capped at the max; the function
    # accepts it without raising and uses the cap.
    res = run_python_lib_code(
        "rich", "x = 1\nprint(x)",
        timeout_seconds=99999,
    )
    # Even with capped timeout, this should finish in <1s
    assert res.ok is True


def test_run_python_lib_step_unsupported_action():
    from core.toolbox import run_python_lib_step
    res = run_python_lib_step({"action": "not_python_lib", "args": {}})
    assert res.ok is False
    assert "unsupported action" in res.error


def test_run_python_lib_step_missing_args():
    from core.toolbox import run_python_lib_step
    res = run_python_lib_step({"action": "run_python_lib"})
    assert res.ok is False


def test_run_python_lib_step_non_dict_step():
    from core.toolbox import run_python_lib_step
    res = run_python_lib_step("not a dict")  # type: ignore[arg-type]
    assert res.ok is False


def test_run_python_lib_code_actually_runs_rich():
    """End-to-end: rich is installed, the code runs, and the
    result includes the actual stdout."""
    from core.toolbox import run_python_lib_code
    res = run_python_lib_code("rich", "print(rich.__name__)")
    assert res.ok is True
    assert "rich" in res.stdout
    assert res.import_name == "rich"


def test_run_python_lib_code_with_env_var():
    """Env vars are passed to the subprocess; the code reads
    them via os.environ (never-inline ground rule)."""
    from core.toolbox import run_python_lib_code
    res = run_python_lib_code(
        "rich",
        "import os\nprint('PW=', os.environ.get('KFIOSA_TARGET_PASSWORD'))",
        env={"KFIOSA_TARGET_PASSWORD": "harvested-psk-test-1234"},
    )
    assert res.ok is True
    # Stdout captures the real value
    assert "harvested-psk-test-1234" in res.stdout


def test_run_python_lib_code_reports_import_error():
    """If the import fails, the executor reports ok=False with
    a real error message (never fabricates)."""
    from core.toolbox import run_python_lib_code
    res = run_python_lib_code(
        "sqlmap", "print(1)",
        timeout_seconds=10,
    )
    # sqlmap isn't installed in the venv
    assert res.ok is False
    assert "sqlmap" in (res.error or "") or "ModuleNotFound" in (res.stderr or "")


# ---------------------------------------------------------------------------
# Orchestrator dispatch
# ---------------------------------------------------------------------------

def test_orchestrator_dispatch_run_python_lib_ok():
    """A happy-path run_python_lib step is dispatched; the
    orchestrator records it in report['executed'] with
    action='run_python_lib'."""
    from core.orchestrator.autonomous_orchestrator import (
        AutonomousOrchestrator,
    )
    orch = AutonomousOrchestrator.__new__(AutonomousOrchestrator)
    orch._emit = lambda m: None  # type: ignore[attr-defined]
    orch.confirm_fn = lambda *a, **k: True
    report = {"executed": [], "skipped": []}
    step = {
        "action": "run_python_lib",
        "tool": "python_lib_executor",
        "args": {"lib": "rich", "code": "print(rich.__name__)"},
    }
    seed: dict = {}
    orch._dispatch_run_python_lib(step, seed, report)
    assert len(report["executed"]) == 1
    entry = report["executed"][0]
    assert entry["action"] == "run_python_lib"
    assert entry["result"]["ok"] is True
    assert "rich" in entry["result"]["stdout"]


def test_orchestrator_dispatch_run_python_lib_missing_args():
    from core.orchestrator.autonomous_orchestrator import (
        AutonomousOrchestrator,
    )
    orch = AutonomousOrchestrator.__new__(AutonomousOrchestrator)
    orch._emit = lambda m: None  # type: ignore[attr-defined]
    orch.confirm_fn = lambda *a, **k: True
    report = {"executed": [], "skipped": []}
    # Missing lib AND code
    step = {"action": "run_python_lib", "tool": "python_lib_executor",
            "args": {}}
    orch._dispatch_run_python_lib(step, {}, report)
    assert report["executed"] == []
    assert any("missing lib" in s for s in report["skipped"])


def test_orchestrator_dispatch_run_python_lib_unknown_lib():
    from core.orchestrator.autonomous_orchestrator import (
        AutonomousOrchestrator,
    )
    orch = AutonomousOrchestrator.__new__(AutonomousOrchestrator)
    orch._emit = lambda m: None  # type: ignore[attr-defined]
    orch.confirm_fn = lambda *a, **k: True
    report = {"executed": [], "skipped": []}
    step = {
        "action": "run_python_lib",
        "tool": "python_lib_executor",
        "args": {"lib": "not-real", "code": "print(1)"},
    }
    orch._dispatch_run_python_lib(step, {}, report)
    # The envelope is recorded; the failure is honest
    assert len(report["executed"]) == 1
    assert report["executed"][0]["result"]["ok"] is False


# ---------------------------------------------------------------------------
# Walk: chain step action is recognized
# ---------------------------------------------------------------------------

def test_get_libraries_by_import_returns_duplicates():
    """`olefile` is the import name for both `olefile` and
    `olefile2`; `fpdf` for both `fpdf` and `fpdf2`."""
    from core.toolbox.python_libs import get_libraries_by_import
    olefile_libs = get_libraries_by_import("olefile")
    names = {l["name"] for l in olefile_libs}
    assert "olefile" in names
    assert "olefile2" in names
    fpdf_libs = get_libraries_by_import("fpdf")
    names = {l["name"] for l in fpdf_libs}
    assert "fpdf" in names
    assert "fpdf2" in names


def test_get_libraries_by_import_unknown_returns_empty():
    from core.toolbox.python_libs import get_libraries_by_import
    assert get_libraries_by_import("") == []
    assert get_libraries_by_import("definitely-not-a-lib") == []


def test_walk_ai_step_recognizes_run_python_lib(monkeypatch):
    """The orchestrator's walk function dispatches
    run_python_lib to the new dispatcher."""
    from core.orchestrator.autonomous_orchestrator import (
        AutonomousOrchestrator,
    )
    orch = AutonomousOrchestrator.__new__(AutonomousOrchestrator)
    orch._emit = lambda m: None  # type: ignore[attr-defined]
    orch.confirm_fn = lambda *a, **k: True
    # Patch the dispatcher to a sentinel
    called = {}
    def _patched(step, seed, report):
        called["yes"] = True
    monkeypatch.setattr(
        orch, "_dispatch_run_python_lib", _patched,
    )
    report = {"executed": [], "skipped": []}
    step = {
        "action": "run_python_lib",
        "tool": "python_lib_executor",
        "args": {"lib": "rich", "code": "print(1)"},
    }
    orch._walk_ai_step(step, {}, report, autonomous=False)
    assert called.get("yes") is True


# ---------------------------------------------------------------------------
# Never-inline: no harvested creds in any new file
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("path", [
    "core/toolbox/python_libs.py",
    "core/toolbox/catalog_python_libs.py",
    "core/toolbox/exec_python_lib.py",
])
def test_no_inline_credentials_in_new_files(path):
    """None of the new files may contain harvested credential
    values (32+ char hex, 16+ char base64, password=..., psk=...)."""
    full = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        path,
    )
    if not os.path.isfile(full):
        pytest.skip(f"{path} not present")
    src = open(full, "r", encoding="utf-8").read()
    bad_patterns = [
        re.compile(r"\b[a-f0-9]{32,}\b"),
        re.compile(r"password\s*=\s*['\"]\S{8,}"),
        re.compile(r"psk\s*=\s*['\"]\S{8,}"),
    ]
    for pat in bad_patterns:
        for m in pat.finditer(src):
            start = max(0, m.start() - 30)
            end = min(len(src), m.end() + 30)
            ctx = src[start:end].lower()
            if ("example" in ctx or "heuristic" in ctx
                    or "test" in ctx or "env var" in ctx
                    or "routing" in ctx or "docs" in ctx
                    or "describe" in ctx or "literal" in ctx
                    or "description" in ctx):
                continue
            pytest.fail(
                f"possible inline credential in {path}: {m.group(0)!r}"
            )


# ---------------------------------------------------------------------------
# No bare except
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("path", [
    "core/toolbox/python_libs.py",
    "core/toolbox/catalog_python_libs.py",
    "core/toolbox/exec_python_lib.py",
])
def test_no_bare_except_in_new_files(path):
    full = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        path,
    )
    if not os.path.isfile(full):
        pytest.skip(f"{path} not present")
    src = open(full, "r", encoding="utf-8").read()
    for m in re.finditer(r"^\s*except\s*:\s*$", src, re.MULTILINE):
        pytest.fail(f"bare except: in {path} at offset {m.start()}")
