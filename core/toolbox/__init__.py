"""core.toolbox — cloned GitHub repository surface for the AI.

See :mod:`core.toolbox.executor` for the primary API:
  - :func:`run_toolbox_repo` for a single repo invocation
  - :func:`run_toolbox_step` for chain-step dispatch
  - :func:`get_repo_index` / :func:`list_repos` / :func:`list_categories`
    for the live index
  - :func:`detect_entry_script` for the entry-point detector

Phase 2.2.A: :mod:`core.toolbox.fetch` is the operator-gated
CLI that clones repos into ``toolboxes/<category>/<owner>__<name>/``
and re-emits ``catalog/`` JSON entries.
"""
from __future__ import annotations

from .executor import (
    ALLOWED_CATEGORIES,
    CATALOG_DIR,
    DEFAULT_TIMEOUT_SECONDS,
    ENV_VAR_PREFIX,
    MAX_TIMEOUT_SECONDS,
    NoEntryScriptError,
    PathTraversalError,
    RepoEntry,
    RepoNotFoundError,
    RunResult,
    ToolboxError,
    TOOLBOXES_DIR,
    UnknownCategoryError,
    build_repo_index,
    detect_entry_script,
    find_repo,
    get_repo_index,
    list_categories,
    list_repos,
    run_toolbox_repo,
    run_toolbox_step,
    touch_index_mtime,
)
from .fetch import (
    is_allowed_category as fetch_is_allowed_category,
    main as fetch_main,
    parse_github_url,
    parse_list,
    plan_fetches,
    run_fetches,
    target_dir,
)
from .python_libs import (
    PYTHON_LIBRARIES,
    PYTHON_LIB_BY_IMPORT,
    PYTHON_LIB_BY_NAME,
    categories_count,
    get_libraries_by_import,
    get_library,
    list_categories as list_python_lib_categories,
    list_libraries,
)
from .catalog_python_libs import (
    build_entry_for as build_python_lib_entry,
    emit_index_json as emit_python_lib_index,
    emit_python_lib_catalog,
    main as catalog_python_libs_main,
)
from .exec_python_lib import (
    DEFAULT_TIMEOUT_SECONDS as PYTHON_LIB_DEFAULT_TIMEOUT_SECONDS,
    MAX_TIMEOUT_SECONDS as PYTHON_LIB_MAX_TIMEOUT_SECONDS,
    InvalidArgsError as PythonLibInvalidArgsError,
    PythonLibError,
    PythonLibResult,
    UnknownLibraryError as PythonLibUnknownLibraryError,
    main as exec_python_lib_main,
    run_python_lib_code,
    run_python_lib_step,
)
from .curated_list import (
    ALL_TOOLS, get_tools_by_category, total,
    WIFI_TOOLS, BLE_TOOLS, OSINT_WEB_TOOLS, POST_EXPLOIT_TOOLS,
)
from .populate import (
    populate, dir_name, CATEGORY_TO_TOOLBOX_DIR,
)

__all__ = [
    # executor.py
    "ALLOWED_CATEGORIES",
    "CATALOG_DIR",
    "DEFAULT_TIMEOUT_SECONDS",
    "ENV_VAR_PREFIX",
    "MAX_TIMEOUT_SECONDS",
    "NoEntryScriptError",
    "PathTraversalError",
    "RepoEntry",
    "RepoNotFoundError",
    "RunResult",
    "ToolboxError",
    "TOOLBOXES_DIR",
    "UnknownCategoryError",
    "build_repo_index",
    "detect_entry_script",
    "find_repo",
    "get_repo_index",
    "list_categories",
    "list_repos",
    "run_toolbox_repo",
    "run_toolbox_step",
    "touch_index_mtime",
    # fetch.py
    "fetch_is_allowed_category",
    "fetch_main",
    "parse_github_url",
    "parse_list",
    "plan_fetches",
    "run_fetches",
    "target_dir",
    # python_libs.py
    "PYTHON_LIBRARIES",
    "PYTHON_LIB_BY_IMPORT",
    "PYTHON_LIB_BY_NAME",
    "categories_count",
    "get_libraries_by_import",
    "get_library",
    "list_python_lib_categories",
    "list_libraries",
    # catalog_python_libs.py
    "build_python_lib_entry",
    "catalog_python_libs_main",
    "emit_python_lib_catalog",
    "emit_python_lib_index",
    # exec_python_lib.py
    "PYTHON_LIB_DEFAULT_TIMEOUT_SECONDS",
    "PYTHON_LIB_MAX_TIMEOUT_SECONDS",
    "PythonLibError",
    "PythonLibInvalidArgsError",
    "PythonLibResult",
    "PythonLibUnknownLibraryError",
    "exec_python_lib_main",
    "run_python_lib_code",
    "run_python_lib_step",
    # curated_list.py
    "ALL_TOOLS", "get_tools_by_category", "total",
    "WIFI_TOOLS", "BLE_TOOLS", "OSINT_WEB_TOOLS", "POST_EXPLOIT_TOOLS",
    # populate.py
    "populate", "dir_name", "CATEGORY_TO_TOOLBOX_DIR",
]
