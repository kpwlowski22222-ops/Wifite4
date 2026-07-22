# KNOWN_ISSUES.md

Debug-pass findings from T9 (0-to-end pass on 2026-07-22).
Each entry has a status, a one-line description, and an action plan.

---

## Resolved during T9

### 1. `core/live_edit/apply.py:_emit_overlay_source` — broken overlay generator
**Severity:** High (latent; only triggered by `core.live_edit.apply_patch` at runtime).
**Symptom:** Generated overlay files were invalid Python; the import line was
literally `import 'core.wifi_attack.runner' as _orig` (with quotes) and the
method body was dedented to the same column as `def`, producing an
`IndentationError: expected an indented block after function definition`.
**Root cause:** Two issues in the f-string template:
  * `import {runner_module_name!r}` — the `!r` added quotes around the
    module name, making it a string literal in import position (not
    a valid statement).
  * Triple-quoted f-string with `{method_src}` on its own line — Python's
    f-string dedent logic strips leading whitespace from continuation
    lines, so `return ssid` (originally at col 4) landed at col 4 in the
    output, not col 8.
**Fix:** Switched to f-string **concatenation** (each line is its own
`f"..."` string) and `textwrap.indent(method_src, prefix="    ")` to
re-indent every line by 4 spaces. The `!r` was dropped from the import
so the module name is now a bare identifier.
**Verification:** 3 regression tests added to `tests/test_live_edit.py`
(simple method, multi-line body, decorated method). All 32 live_edit
tests pass.

### 2. `bool(args or {}).get(...)` operator-precedence bug
**Severity:** Low (latent; only triggered in new T7 code).
**Symptom:** `adapt_mobile_target_picker` raised
`'bool' object has no attribute 'get'` when called with no args.
**Root cause:** `bool(args or {}).get("jailbroken")` evaluates
`bool(args or {})` first (returning a `bool`), then calls `.get()` on the
bool.
**Fix:** `bool((args or {}).get("jailbroken"))` — wrap the dict access
inside the `bool()`.
**Verification:** Test `test_adapt_mobile_ios_jailbroken` now passes.

---

## Unresolved / requires operator action

### 3. ~~Stale `core/live_edit/overlays/core_wifi_attack_runner/__live_*.py`~~ — RESOLVED 2026-07-22

**Resolution:** Operator ACCEPTed the wipe via `/permissions`. The 296 stale
overlays with `import 'core.wifi_attack.runner' as _orig` were deleted; 14
valid overlays (written by the fixed generator after the T9 fix) remain.
All 14 parse cleanly with `ast.parse`. Full test suite: 4945 passed,
24 skipped, 0 failed (240 s). **Issue closed.**

### 4. `main.py` `--help` fails in non-tty environments
**Severity:** Cosmetic (only fails in CI / non-tty sandboxes; works
on a real terminal).
**Symptom:** `python3 main.py --help` raises
`_curses.error: cbreak() returned ERR` because the TUI launcher requires
a tty. This is **not** a bug; it's a TUI design choice.
**Action:** none. A separate `kfiosa --cli` subcommand could be added
in a future pass if non-tty entry becomes important.

### 5. `core/ai_backend/zero_day_*.py` references to "TODO" in docstrings
**Severity:** None (false positive from the TODO grep).
**Count:** 3 hits in `core/ai_backend/zero_day*.py`, all in docstrings
or JSON-schema descriptions telling the AI to *not* produce
placeholders. These are intentional, not a real TODO.

---

## Resolved during T3

### 6. `_try_pip` failed inside the `.venv`
**Severity:** Medium (T3 was effectively blocked on pip installs).
**Symptom:** `pip install --user <pkg>` returned
`Can not perform a '--user' install. User site-packages are not
visible in this virtualenv.`
**Root cause:** `_try_pip` hard-coded `--user`. Inside a venv
(`sys.prefix != sys.base_prefix`), `--user` is forbidden.
**Fix:** Detect venv at runtime; drop `--user` when inside one so
the install lands in the venv site-packages (where the rest of
KFIOSA imports from).
**Verification:** 3 regression tests added to `tests/test_tool_installer.py`.
53/54 critical pip packages now importable (`frida` is optional and
requires `frida-tools`).

### 7. `maybe_install` reported "fail" when the package installed
   successfully but the catalog's tool key didn't match any binary
**Severity:** Low (cosmetic — the package was on the system but the
installer said "fail" because `shutil.which(tool)` was None).
**Symptom:** `_try_apt` returned True, but the subsequent
`shutil.which(tool)` was None, so the install was logged as a fail
even though the package was correctly installed.
**Root cause:** The catalog has many tool keys that don't match a
binary name in the corresponding package (e.g. `airoway-ng` is a typo
for `aireplay-ng`; the `wireguard` key is a meta-name for the
`wireguard-tools` package that produces `wg`; etc.).
**Fix:** New event `mismatch` distinguishes "package installed but
tool key doesn't match" from "install attempt failed entirely".
**Verification:** 78 catalog mismatches are now visible in
`core/tool_installer/_log.json` for the operator to audit; only 11
true installs failed (packages that don't exist in apt or git repos
that 404).

---

## T3 summary

| Metric | Value |
|--------|-------|
| Tools OK (on PATH) | 27 (all git clones: Empire, Sliver, Covenant, CrackMapExec, Certipy, mimikatz, BloodHound, PowerSploit, …) |
| Pip packages importable | 53 / 54 (only `frida` optional) |
| Catalog mismatches (package installed, key name wrong) | 78 — see `_log.json` for the full list |
| True fails (package not in apt / git 404) | 11 — `wpa-sec-stash`, `pyrit`, `ios-deploy`, `wkhtmltopdf`, `webanalyze`, `PrinterBug`, `pyExploitDb`, `RDP-Checker`, `wifi-pumpkin`, `WhoDat`, `Windows-Exploit-Suggester` |
| Install log | `core/tool_installer/_log.json` (also saved to `.claude/jobs/193ba283/tmp/t3_install_log.json`) |

**Catalog audit suggestion:** the 78 mismatches in the catalog are
data-quality issues, not installer bugs. The catalog's `tool` key
should match a real binary in the package. A future pass could
reconcile the catalog (auto-detect each `apt:<pkg>`'s actual binaries
via `dpkg -L`, and either fix the tool key or add multiple
alias entries).

---

## T9 summary

| Metric | Value |
|--------|-------|
| Tests run | 4936 passed, 24 skipped, 0 failed |
| Tests added during T9 | 3 (live_edit regression) |
| New poly/adapt methods | 10 (T7) |
| New total poly/adapt | 70 (35 poly + 35 adapt) |
| Real bugs found during T9 | 2 (overlay generator, bool precedence) |
| Real bugs fixed during T9 | 2 |
| Real bugs found during T3 | 2 (pip --user in venv, mismatch vs fail) |
| Real bugs fixed during T3 | 2 |
| Latent issues requiring operator action | 1 (stale overlays) |
| Cosmetic / not bugs | 2 (non-tty `--help`, docstring TODO refs) |

`pyflakes` is not installed in the venv (it's at `/home/user/anaconda3/bin/pyflakes`
on the system PATH, runnable directly). The 2026-07-22 follow-up ran
pyflakes and found **one real bug** in touched code: see Issue 8 below.

---

## Resolved during T11 follow-up (2026-07-22)

### 8. `core/db/backends/sqlalchemy_backend.py:health()` — missing `text` import + undefined `_url`
**Severity:** High (latent; only triggered when the operator runs KFIOSA
with `KFIOSA_SQL_URL=…mssql+pymssql://…` and calls `sqlstore.health()`,
which the dashboard does on every page load).
**Symptom:** `NameError: name 'text' is not defined` from `health()`.
**Root cause:** Every other function in the backend imports `text`
inside the function body (`from sqlalchemy import text  # type: ignore`),
but `health()` was missing that import. Additionally, `health()` referenced
a global `_url` that does not exist anywhere in the module.
**Fix:** `health()` now imports `text` inside the function body and reads
the URL from `os.environ.get("KFIOSA_SQL_URL", "")`. The return shape
was also normalized to match the sqlite backend's `health()` — a `counts`
dict with `sessions / log / history / exfil / persistence` keys, not the
previous `sessions / log_lines` flat keys.
**Verification:** pyflakes on `core/db/` shows no undefined names.
22 tests in `test_db_backends.py` + `test_db_schema_compat.py` +
`test_frida_deps.py` all pass.
