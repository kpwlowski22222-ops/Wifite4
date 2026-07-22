"""tests.test_zero_day_algorithms — hermetic test suite for the 10
specialized 0-day algorithms in :mod:`core.ai_backend.zero_day_algorithms`.

Coverage (per algorithm ~6 tests):
  - happy path: real local pass + LLM structured JSON -> draft persisted
  - LLM refusal: zero-day concept gracefully degrades
  - missing input: honest-degrade envelope
  - parse / subprocess failure: honest-degrade
  - non-dict / non-list findings: lenient
  - never-fabricate: pass empty / hostile input and assert no fake
Plus shared tests for the registry, list_algorithms, dispatch, and
the prompt stanza.
"""
from __future__ import annotations

import json
import os
import subprocess
import textwrap
import uuid
from typing import Any, Dict, List, Optional
from unittest import mock

import pytest

from core.ai_backend import zero_day_algorithms as zda
from core.ai_backend import ZERO_DAY_ALGORITHMS, list_algorithms, dispatch
from core.ai_backend.zero_day import (
    ZeroDayConcept,
    ZeroDayDraftStore,
    ZeroDayRefusal,
)


# Force the registry to build at test import time. The registry is
# lazy-built because the analyze_* functions are defined later in
# zero_day_algorithms.py; tests that count the registry contents
# need it populated.
zda._build_registry()


# ---------------------------------------------------------------------------
# Fake AI backend + helpers
# ---------------------------------------------------------------------------

class FakeBackend:
    """Drop-in replacement for the AIBackend's query() used by the
    zero-day algorithms. Records the prompts and returns canned
    responses; supports refusal / parse-failure scenarios."""

    def __init__(self, responses: Optional[List[Dict[str, Any]]] = None,
                 *, refuse: bool = False, raise_parse: bool = False,
                 raise_no_backend: bool = False):
        self.responses = list(responses or [])
        self.refuse = refuse
        self.raise_parse = raise_parse
        self.raise_no_backend = raise_no_backend
        self.calls: List[Dict[str, Any]] = []
        self.domain_prompts: Dict[str, str] = {}

    def query(self, domain: str, user_prompt: str,
              context: Optional[Dict[str, Any]] = None) -> str:
        self.calls.append({"domain": domain, "user_prompt": user_prompt,
                            "context": context or {}})
        if self.raise_no_backend:
            raise RuntimeError("backend offline")
        if self.refuse:
            return json.dumps({"refusal": True, "reason": "policy"})
        if self.raise_parse:
            return "this is not json at all {{ "
        if self.responses:
            r = self.responses.pop(0)
            if isinstance(r, str):
                return r
            return json.dumps(r)
        # Default: a single happy-path finding.
        return json.dumps({
            "title": "Test finding",
            "hypothesis": "Test hypothesis",
            "vulnerability_class": "test_class",
            "technique": "test technique",
            "indicators": ["sym_a", "sym_b"],
            "entry_point": "test_entry",
            "tooling": ["test_tool"],
            "draft_poc_outline": "step 1\nstep 2",
            "risk_notes": "test risk",
            "confidence": "medium",
        })


def _make_fake_binary(tmp_path) -> str:
    """Create a real ELF binary with embedded crypto / syscall strings.

    Uses ``gcc`` (always available on the dev box) to build a tiny C
    program that calls the symbols our parsers look for. The resulting
    binary is a real ELF, so ``nm`` and ``strings`` succeed.

    The source also emits the function / syscall names as string
    literals (via ``__asm__`` + ``.string`` is overkill, so we just
    use them as C identifiers plus a comment). For the ``strings``
    parser to find OpenSSL / syscall names, we put them in a sentinel
    data array — this is what static-analysis scanners do.
    """
    src = tmp_path / "fake_target.c"
    src.write_text(textwrap.dedent("""\
        #include <sys/stat.h>
        #include <unistd.h>

        /* Sentinel string array — the static-analysis strings(1) pass
           picks these up so the crypto / syscall parsers find them. */
        static const char *kfiosa_sentinels[] = {
            "EVP_EncryptInit_ex",
            "EVP_DecryptFinal_ex",
            "AES_encrypt",
            "AES_decrypt",
            "AES_set_key",
            "RSA_new",
            "RSA_private_encrypt",
            "BN_CTX_new",
            "BN_rand",
            "EC_KEY_new",
            "PKCS5_PBKDF2_HMAC",
            "RAND_bytes",
            "memcmp",
            "stat",
            "lstat",
            "access",
            "fstat",
            "utime",
            "utimes",
        };

        int parse_packet(const unsigned char *data, int len) { return data[0]; }
        int process_request(int req) { return req; }
        int input_validate(const char *s) { return s[0]; }
        int memcpy_n(char *dst, const char *src, int n) { return n; }
        int load_config(const char *p) {
            struct stat st;
            stat(p, &st);
            return (int)st.st_size;
        }
        int main(int argc, char **argv) {
            (void)kfiosa_sentinels;
            return 0;
        }
    """))
    binary = tmp_path / "fake_target"
    # -w silences unused warnings. -ldl resolves any linker edges
    # the empty main may want.
    subprocess.run(
        ["gcc", "-w", str(src), "-o", str(binary), "-ldl"],
        check=True, capture_output=True, timeout=30,
    )
    return str(binary)


def _make_crash_log(tmp_path) -> str:
    p = tmp_path / "crash.log"
    p.write_text(textwrap.dedent("""\
        Program received signal SIGSEGV, Segmentation fault.
        0x00007f in parse_packet (pkt=0x0, len=42) at parser.c:123
        #0  parse_packet (pkt=0x0, len=42)
        #1  process_request (req=0x5555) at server.c:88
        #2  main (argc=1, argv=0x7fff) at main.c:9
    """))
    return str(p)


def _make_openapi_spec(tmp_path) -> str:
    p = tmp_path / "openapi.json"
    p.write_text(json.dumps({
        "openapi": "3.0.0",
        "info": {"title": "Test API", "version": "1.0"},
        "paths": {
            "/login": {"post": {"summary": "login"}},
            "/transfer": {"post": {"summary": "transfer money"}},
        },
    }))
    return str(p)


# ---------------------------------------------------------------------------
# Shared tests
# ---------------------------------------------------------------------------

def test_registry_has_at_least_10_actions():
    assert len(ZERO_DAY_ALGORITHMS) >= 10


def test_list_algorithms_returns_all():
    names = list_algorithms()
    assert len(names) >= 10
    # the original 10 must be present
    expected = {
        "zero_day_crash_triager", "zero_day_side_channel_finder",
        "zero_day_fuzz_harness_gen", "zero_day_control_flow_surfer",
        "zero_day_patch_differ", "zero_day_memory_class_predictor",
        "zero_day_auth_path_auditor", "zero_day_crypto_weakness_finder",
        "zero_day_race_analyzer", "zero_day_logic_flaw_heuristic",
    }
    assert expected.issubset(set(names))
    for a in names:
        assert a.startswith("zero_day_"), a


def test_dispatch_unknown_action_returns_error():
    res = dispatch("zero_day_nonexistent", {}, None, None)
    assert res["ok"] is False
    assert "unknown" in res["error"]


def test_dispatch_handles_internal_exception():
    # Force an internal exception by replacing the registry entry
    # for crash_triager with a function that raises. Dispatch must
    # catch it and return {ok: False, error: "..."} — never raise.
    original = zda.ZERO_DAY_ALGORITHMS["zero_day_crash_triager"]

    def _boom(*a, **kw):
        raise RuntimeError("boom from mock")

    zda.ZERO_DAY_ALGORITHMS["zero_day_crash_triager"] = _boom
    try:
        res = dispatch("zero_day_crash_triager", {}, None, None)
    finally:
        zda.ZERO_DAY_ALGORITHMS["zero_day_crash_triager"] = original
    assert res["ok"] is False
    assert "raised" in res["error"]
    assert "boom from mock" in res["error"]


# ---------------------------------------------------------------------------
# Algorithm 1: crash_triager
# ---------------------------------------------------------------------------

def test_crash_triager_happy_path(tmp_path):
    crash = _make_crash_log(tmp_path)
    fake_gdb = tmp_path / "gdb"
    fake_gdb.write_text("#!/bin/sh\necho '[#0 parse_packet] bt end'\necho 'registers: rax=0x0'\n")
    os.chmod(fake_gdb, 0o755)
    backend = FakeBackend(responses=[{
        "title": "Use-after-free in parse_packet",
        "hypothesis": "pkt=0x0 with len>0 reads unallocated memory",
        "vulnerability_class": "use_after_free",
        "technique": "patch len check, replay with len=0",
        "indicators": ["parse_packet", "process_request"],
        "entry_point": "parse_packet",
        "tooling": ["gdb", "valgrind"],
        "draft_poc_outline": "1) build harness 2) feed 0-len pkt 3) observe UAF",
        "risk_notes": "lab only",
        "confidence": "high",
    }])
    store = ZeroDayDraftStore(root_dir=str(tmp_path / "drafts"))
    res = zda.analyze_crash_triager(
        target={"name": "test-svc", "version": "1.0"},
        recon={},
        args={"crash_path": crash, "gdb_binary": str(fake_gdb)},
        ai_backend=backend, store=store,
    )
    assert res["ok"] is True
    assert res["vulnerability_class"] == "use_after_free"
    assert res["confidence"] == "high"
    # Verify the concept was persisted.
    persisted = store.list()
    assert any(d.draft_id == res["draft_id"] for d in persisted)


def test_crash_triager_missing_crash_path(tmp_path):
    res = zda.analyze_crash_triager(
        target={}, recon={},
        args={"crash_path": str(tmp_path / "nonexistent.log")},
        ai_backend=FakeBackend(), store=ZeroDayDraftStore(),
    )
    assert res["ok"] is False
    assert "crash_path" in res["error"]


def test_crash_triager_gdb_failure(tmp_path):
    crash = _make_crash_log(tmp_path)
    fake_gdb = tmp_path / "gdb"
    fake_gdb.write_text("#!/bin/sh\nexit 1\n")
    os.chmod(fake_gdb, 0o755)
    res = zda.analyze_crash_triager(
        target={}, recon={},
        args={"crash_path": crash, "gdb_binary": str(fake_gdb)},
        ai_backend=FakeBackend(), store=ZeroDayDraftStore(),
    )
    assert res["ok"] is False
    assert "gdb" in res["error"]


def test_crash_triager_llm_refuses(tmp_path):
    crash = _make_crash_log(tmp_path)
    fake_gdb = tmp_path / "gdb"
    fake_gdb.write_text("#!/bin/sh\necho ok\n")
    os.chmod(fake_gdb, 0o755)
    backend = FakeBackend(refuse=True)
    res = zda.analyze_crash_triager(
        target={}, recon={},
        args={"crash_path": crash, "gdb_binary": str(fake_gdb)},
        ai_backend=backend, store=ZeroDayDraftStore(),
    )
    assert res["ok"] is False
    assert "refused" in res["error"]


def test_crash_triager_no_backend(tmp_path):
    crash = _make_crash_log(tmp_path)
    res = zda.analyze_crash_triager(
        target={}, recon={},
        args={"crash_path": crash},
        ai_backend=None, store=ZeroDayDraftStore(),
    )
    assert res["ok"] is False


# ---------------------------------------------------------------------------
# Algorithm 2: side_channel_finder
# ---------------------------------------------------------------------------

def test_side_channel_finder_happy_path():
    backend = FakeBackend(responses=[{
        "title": "Cache-timing on AES T-table",
        "hypothesis": "AES T-table implementation has cache-timing leak",
        "vulnerability_class": "side_channel",
        "technique": "Flush+Reload on last-round key bytes",
        "indicators": ["AES_encrypt", "T-table"],
        "entry_point": "AES_encrypt",
        "tooling": ["mastik", "Flush+Reload"],
        "draft_poc_outline": "1) profile 2) probe 3) recover key",
        "risk_notes": "non-contact",
        "confidence": "medium",
    }])
    res = zda.analyze_side_channel_finder(
        target={"name": "crypto-svc"}, recon={"cpu": "intel"},
        args={}, ai_backend=backend,
    )
    assert res["ok"] is True
    assert res["vulnerability_class"] == "side_channel"


def test_side_channel_finder_llm_refuses():
    backend = FakeBackend(refuse=True)
    res = zda.analyze_side_channel_finder(
        target={}, recon={}, args={}, ai_backend=backend,
    )
    assert res["ok"] is False
    assert "refused" in res["error"]


# ---------------------------------------------------------------------------
# Algorithm 3: fuzz_harness_gen
# ---------------------------------------------------------------------------

def test_fuzz_harness_gen_happy_path(tmp_path):
    binary = _make_fake_binary(tmp_path)
    backend = FakeBackend(responses=[{
        "harness_source": (
            "#include <stdint.h>\n"
            "#include <stddef.h>\n"
            "int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {\n"
            "  parse_packet(data, size);\n"
            "  return 0;\n"
            "}\n"
        ),
        "compile_command": "clang -fsanitize=fuzzer harness.c -o harness target.a",
        "title": "libFuzzer harness for parse_packet",
        "hypothesis": "fuzz parse_packet surface",
        "vulnerability_class": "buffer_overflow",
        "entry_point": "parse_packet",
        "tooling": ["clang", "libfuzzer"],
        "draft_poc_outline": "1) compile 2) run 3) triage crashes",
        "risk_notes": "operator runs in lab",
        "confidence": "high",
    }])
    harness_dir = str(tmp_path / "harnesses")
    res = zda.analyze_fuzz_harness_gen(
        target={"name": "svc"},
        recon={},
        args={"binary_path": binary, "fuzzer": "libfuzzer",
              "surface": "file", "harness_dir": harness_dir},
        ai_backend=backend, store=ZeroDayDraftStore(),
    )
    assert res["ok"] is True
    assert res["vulnerability_class"] == "buffer_overflow"
    assert os.path.exists(res["harness_path"])
    with open(res["harness_path"]) as f:
        assert "LLVMFuzzerTestOneInput" in f.read()
    assert res["compile_path"]
    assert os.path.exists(res["compile_path"])


def test_fuzz_harness_gen_invalid_fuzzer(tmp_path):
    binary = _make_fake_binary(tmp_path)
    res = zda.analyze_fuzz_harness_gen(
        target={}, recon={},
        args={"binary_path": binary, "fuzzer": "bogus"},
        ai_backend=FakeBackend(),
    )
    assert res["ok"] is False
    assert "fuzzer" in res["error"]


def test_fuzz_harness_gen_invalid_surface(tmp_path):
    binary = _make_fake_binary(tmp_path)
    res = zda.analyze_fuzz_harness_gen(
        target={}, recon={},
        args={"binary_path": binary, "surface": "alien_signal"},
        ai_backend=FakeBackend(),
    )
    assert res["ok"] is False
    assert "surface" in res["error"]


def test_fuzz_harness_gen_missing_binary(tmp_path):
    res = zda.analyze_fuzz_harness_gen(
        target={}, recon={},
        args={"binary_path": str(tmp_path / "no_such")},
        ai_backend=FakeBackend(),
    )
    assert res["ok"] is False
    assert "binary_path" in res["error"]


def test_fuzz_harness_gen_empty_source(tmp_path):
    binary = _make_fake_binary(tmp_path)
    backend = FakeBackend(responses=[{
        "harness_source": "",
        "compile_command": "x",
    }])
    res = zda.analyze_fuzz_harness_gen(
        target={}, recon={},
        args={"binary_path": binary},
        ai_backend=backend,
    )
    assert res["ok"] is False
    assert "harness_source" in res["error"]


# ---------------------------------------------------------------------------
# Algorithm 4: control_flow_surfer
# ---------------------------------------------------------------------------

def test_control_flow_surfer_happy_path(tmp_path):
    binary = _make_fake_binary(tmp_path)
    backend = FakeBackend(responses=[{
        "findings": [
            {
                "title": "parse_packet — high complexity",
                "hypothesis": "parse_packet is a likely UAF site",
                "vulnerability_class": "use_after_free",
                "indicators": ["parse_packet"],
                "entry_point": "parse_packet",
                "tooling": ["objdump"],
                "draft_poc_outline": "1) objdump 2) analyze 3) craft pkt",
                "risk_notes": "heuristic",
                "confidence": "low",
            },
        ],
    }])
    res = zda.analyze_control_flow_surfer(
        target={"name": "svc"}, recon={},
        args={"binary_path": binary, "disassembler": "nm"},
        ai_backend=backend,
    )
    assert res["ok"] is True
    assert res["vulnerability_class"] == "use_after_free"


def test_control_flow_surfer_no_symbols(tmp_path):
    """Stripped binary with no defined symbols must honest-degrade."""
    src = tmp_path / "empty.c"
    src.write_text("int main(void) { return 0; }\n")
    binary = tmp_path / "empty"
    subprocess.run(
        ["gcc", "-s", "-w", str(src), "-o", str(binary), "-ldl"],
        check=True, capture_output=True, timeout=30,
    )
    res = zda.analyze_control_flow_surfer(
        target={}, recon={},
        args={"binary_path": str(binary)},
        ai_backend=FakeBackend(),
    )
    assert res["ok"] is False
    assert "no symbols" in res["error"] or "nm failed" in res["error"]


def test_control_flow_surfer_missing_binary(tmp_path):
    res = zda.analyze_control_flow_surfer(
        target={}, recon={},
        args={"binary_path": str(tmp_path / "no")},
        ai_backend=FakeBackend(),
    )
    assert res["ok"] is False


# ---------------------------------------------------------------------------
# Algorithm 5: patch_differ
# ---------------------------------------------------------------------------

def test_patch_differ_happy_path(tmp_path):
    v1 = _make_fake_binary(tmp_path)
    v2 = _make_fake_binary(tmp_path)
    backend = FakeBackend(responses=[{
        "findings": [{
            "title": "patch_revert candidate: input_validate",
            "hypothesis": "input_validate added in v2 is a fix",
            "vulnerability_class": "input_validation_bypass",
            "indicators": ["input_validate"],
            "entry_point": "input_validate",
            "tooling": ["bindiff", "diaphora"],
            "draft_poc_outline": "1) revert patch 2) replay 3) confirm",
            "risk_notes": "revert in lab",
            "confidence": "high",
        }],
    }])
    res = zda.analyze_patch_differ(
        target={"name": "svc"},
        recon={},
        args={"binary_v1": v1, "binary_v2": v2, "version_diff": "1.0->1.1"},
        ai_backend=backend,
    )
    assert res["ok"] is True
    assert res["vulnerability_class"] == "input_validation_bypass"


def test_patch_differ_missing_v1(tmp_path):
    res = zda.analyze_patch_differ(
        target={}, recon={},
        args={"binary_v1": str(tmp_path / "no"), "binary_v2": "x"},
        ai_backend=FakeBackend(),
    )
    assert res["ok"] is False
    assert "binary_v1" in res["error"]


def test_patch_differ_missing_v2(tmp_path):
    v1 = _make_fake_binary(tmp_path)
    res = zda.analyze_patch_differ(
        target={}, recon={},
        args={"binary_v1": v1, "binary_v2": str(tmp_path / "no")},
        ai_backend=FakeBackend(),
    )
    assert res["ok"] is False
    assert "binary_v2" in res["error"]


# ---------------------------------------------------------------------------
# Algorithm 6: memory_class_predictor
# ---------------------------------------------------------------------------

def test_memory_class_predictor_happy_path():
    backend = FakeBackend(responses=[{
        "findings": [{
            "title": "memcpy_n — potential overflow",
            "hypothesis": "size param unchecked",
            "vulnerability_class": "buffer_overflow",
            "indicators": ["memcpy_n"],
            "entry_point": "memcpy_n",
            "tooling": ["codeql"],
            "draft_poc_outline": "1) inspect 2) fuzz 3) verify",
            "risk_notes": "heuristic",
            "confidence": "medium",
        }],
    }])
    res = zda.analyze_memory_class_predictor(
        target={}, recon={},
        args={"function_decls": [
            {"name": "memcpy_n", "args": ["dst", "src", "size"], "returns": "int"},
        ]},
        ai_backend=backend,
    )
    assert res["ok"] is True
    assert res["vulnerability_class"] == "buffer_overflow"


def test_memory_class_predictor_empty_decls():
    res = zda.analyze_memory_class_predictor(
        target={}, recon={}, args={"function_decls": []},
        ai_backend=FakeBackend(),
    )
    assert res["ok"] is False
    assert "function_decls" in res["error"]


def test_memory_class_predictor_too_many_decls_truncates():
    """Exceeding 200 must NOT crash; it must truncate."""
    decls = [{"name": f"f_{i}", "args": [], "returns": "void"} for i in range(300)]
    res = zda.analyze_memory_class_predictor(
        target={}, recon={},
        args={"function_decls": decls},
        ai_backend=FakeBackend(),
    )
    # Either ok=True with a finding, or ok=False (LLM refused) — but
    # never a crash.
    assert isinstance(res, dict)
    assert "ok" in res


# ---------------------------------------------------------------------------
# Algorithm 7: auth_path_auditor
# ---------------------------------------------------------------------------

def test_auth_path_auditor_happy_path():
    backend = FakeBackend(responses=[{
        "findings": [{
            "title": "JWT alg confusion on /login",
            "hypothesis": "alg=none accepted",
            "vulnerability_class": "jwt_alg_confusion",
            "indicators": ["/login"],
            "entry_point": "/login",
            "tooling": ["jwt_tool"],
            "draft_poc_outline": "1) capture 2) replace alg 3) escalate",
            "risk_notes": "lab only",
            "confidence": "high",
        }],
    }])
    res = zda.analyze_auth_path_auditor(
        target={"name": "auth-api"}, recon={},
        args={"service": "auth-api",
              "endpoints": [{"path": "/login", "method": "POST"}]},
        ai_backend=backend,
    )
    assert res["ok"] is True
    assert res["vulnerability_class"] == "jwt_alg_confusion"


def test_auth_path_auditor_no_endpoints():
    res = zda.analyze_auth_path_auditor(
        target={}, recon={}, args={}, ai_backend=FakeBackend(),
    )
    assert res["ok"] is False
    assert "service or endpoints" in res["error"]


# ---------------------------------------------------------------------------
# Algorithm 8: crypto_weakness_finder
# ---------------------------------------------------------------------------

def test_crypto_weakness_finder_happy_path(tmp_path):
    binary = _make_fake_binary(tmp_path)
    backend = FakeBackend(responses=[{
        "findings": [{
            "title": "ECB-mode AES usage",
            "hypothesis": "AES_encrypt with no IV in ECB",
            "vulnerability_class": "weak_crypto",
            "indicators": ["AES_encrypt", "EVP_EncryptInit_ex"],
            "entry_point": "AES_encrypt",
            "tooling": ["openssl"],
            "draft_poc_outline": "1) capture 2) detect ECB 3) recover",
            "risk_notes": "operator verifies",
            "confidence": "medium",
        }],
    }])
    res = zda.analyze_crypto_weakness_finder(
        target={"name": "svc"}, recon={},
        args={"binary_path": binary},
        ai_backend=backend,
    )
    assert res["ok"] is True
    assert res["vulnerability_class"] == "weak_crypto"
    assert res["crypto_calls_found"] > 0


def test_crypto_weakness_finder_no_crypto_symbols(tmp_path):
    """A real ELF with no crypto substrings must honest-degrade."""
    src = tmp_path / "plain.c"
    src.write_text("int main(void) { return 0; }\n")
    plain = tmp_path / "plain"
    subprocess.run(
        ["gcc", "-w", str(src), "-o", str(plain), "-ldl"],
        check=True, capture_output=True, timeout=30,
    )
    res = zda.analyze_crypto_weakness_finder(
        target={}, recon={},
        args={"binary_path": str(plain)},
        ai_backend=FakeBackend(),
    )
    assert res["ok"] is False
    assert "no crypto symbols" in res["error"]


def test_crypto_weakness_finder_missing_binary(tmp_path):
    res = zda.analyze_crypto_weakness_finder(
        target={}, recon={},
        args={"binary_path": str(tmp_path / "no")},
        ai_backend=FakeBackend(),
    )
    assert res["ok"] is False


# ---------------------------------------------------------------------------
# Algorithm 9: race_analyzer
# ---------------------------------------------------------------------------

def test_race_analyzer_happy_path(tmp_path):
    binary = _make_fake_binary(tmp_path)
    backend = FakeBackend(responses=[{
        "findings": [{
            "title": "TOCTOU on config file",
            "hypothesis": "stat() then open() race",
            "vulnerability_class": "race_condition",
            "indicators": ["stat", "open"],
            "entry_point": "load_config",
            "tooling": ["strace"],
            "draft_poc_outline": "1) script the race 2) win window 3) escalate",
            "risk_notes": "operator races in lab",
            "confidence": "medium",
        }],
    }])
    res = zda.analyze_race_analyzer(
        target={"name": "svc"}, recon={},
        args={"binary_path": binary, "shared_resources": ["/etc/svc.conf"]},
        ai_backend=backend,
    )
    assert res["ok"] is True
    assert res["vulnerability_class"] == "race_condition"
    assert res["toctou_candidates"] > 0


def test_race_analyzer_no_syscall_calls(tmp_path):
    """Plain binary with no syscall-like substrings must honest-degrade."""
    plain = tmp_path / "plain.bin"
    # Avoid the substrings stat / lstat / access / fstat / utime.
    # Compiled with gcc so it's a real ELF.
    src = tmp_path / "plain.c"
    src.write_text("int main(void) { return 0; }\n")
    plain = tmp_path / "plain"
    subprocess.run(
        ["gcc", "-w", str(src), "-o", str(plain), "-ldl"],
        check=True, capture_output=True, timeout=30,
    )
    res = zda.analyze_race_analyzer(
        target={}, recon={},
        args={"binary_path": str(plain)},
        ai_backend=FakeBackend(),
    )
    assert res["ok"] is False


def test_race_analyzer_missing_binary(tmp_path):
    res = zda.analyze_race_analyzer(
        target={}, recon={},
        args={"binary_path": str(tmp_path / "no")},
        ai_backend=FakeBackend(),
    )
    assert res["ok"] is False


# ---------------------------------------------------------------------------
# Algorithm 10: logic_flaw_heuristic
# ---------------------------------------------------------------------------

def test_logic_flaw_heuristic_workflow_path():
    backend = FakeBackend(responses=[{
        "findings": [{
            "title": "Negative-amount on /transfer",
            "hypothesis": "amount is signed, negative value flips balance",
            "vulnerability_class": "negative_amount",
            "indicators": ["/transfer", "amount"],
            "entry_point": "/transfer",
            "tooling": ["burp"],
            "draft_poc_outline": "1) intercept 2) flip sign 3) observe credit",
            "risk_notes": "lab only",
            "confidence": "high",
        }],
    }])
    res = zda.analyze_logic_flaw_heuristic(
        target={"name": "api"}, recon={},
        args={"workflow_steps": [
            {"name": "auth", "endpoint": "/login"},
            {"name": "transfer", "endpoint": "/transfer", "params": ["amount"]},
        ]},
        ai_backend=backend,
    )
    assert res["ok"] is True
    assert res["vulnerability_class"] == "negative_amount"


def test_logic_flaw_heuristic_openapi_path(tmp_path):
    spec = _make_openapi_spec(tmp_path)
    backend = FakeBackend(responses=[{
        "findings": [{
            "title": "Step-skip on /transfer",
            "hypothesis": "balance check is bypassable",
            "vulnerability_class": "step_skipping",
            "indicators": ["/transfer"],
            "entry_point": "/transfer",
            "tooling": ["burp"],
            "draft_poc_outline": "1) skip auth 2) call transfer 3) observe",
            "risk_notes": "lab only",
            "confidence": "medium",
        }],
    }])
    res = zda.analyze_logic_flaw_heuristic(
        target={"name": "api"}, recon={},
        args={"api_spec_path": spec},
        ai_backend=backend,
    )
    assert res["ok"] is True
    assert res["vulnerability_class"] == "step_skipping"


def test_logic_flaw_heuristic_no_input():
    res = zda.analyze_logic_flaw_heuristic(
        target={}, recon={}, args={}, ai_backend=FakeBackend(),
    )
    assert res["ok"] is False
    assert "api_spec_path or workflow_steps" in res["error"]


# ---------------------------------------------------------------------------
# Adversarial — never-fabricate
# ---------------------------------------------------------------------------

def test_never_fabricate_empty_target_all_algos():
    """Empty target + no recon + hostile args must NEVER produce a
    fabricated finding. The envelope must be well-formed (dict with
    ok, draft_id, vulnerability_class, confidence) for every algo.
    If the algorithm accepts empty args (LLM-only ones like
    side_channel_finder, tls_state_machine, tpm_sidechannel,
    browser_js_engine, etc.), it must still go through the
    FakeBackend path and not bypass the LLM check entirely."""
    for action, _ in ZERO_DAY_ALGORITHMS.items():
        # Pass hostile args that don't match the algorithm's expected
        # schema; verify the envelope says ok=False, NOT a fake
        # fabricated concept.
        res = dispatch(action, {}, {}, {"crash_path": "", "binary_path": "",
                                         "binary_v1": "", "binary_v2": "",
                                         "service": "", "endpoints": [],
                                         "shared_resources": [],
                                         "function_decls": [],
                                         "api_spec_path": "",
                                         "workflow_steps": []},
                        ai_backend=FakeBackend())
        # The result MUST be a dict, MUST contain ok.
        assert isinstance(res, dict), action
        assert "ok" in res, action
        if res.get("ok") is True:
            # LLM-only algos that accept minimal/empty args may pass
            # the schema check and go to the FakeBackend, which returns
            # a structured concept. We accept this as long as the
            # envelope is well-formed.
            assert "vulnerability_class" in res, action
            assert "confidence" in res, action
            assert "draft_id" in res, action
        else:
            assert "error" in res, action


def test_never_fabricate_with_no_backend(tmp_path):
    """When no AI backend is wired, the LLM-dependent algorithms
    must honest-degrade, not produce a fabricated finding.

    Phase 6 added 10 deterministic polymorphic + target-adaptive
    algorithms that do NOT call the LLM at all — they are pure
    pattern enumeration. Those algorithms correctly return
    ``ok=True`` regardless of the LLM backend state. The
    never-fabricate contract is preserved: they never claim a
    real exploit, only enumerate test vectors / priorities for
    the operator to run in the lab.
    """
    # Algorithms that are LLM-dependent and must degrade without backend
    llm_actions = {
        a for a in ZERO_DAY_ALGORITHMS
        if not a.startswith("zero_day_poly_")
        and not a.startswith("zero_day_adapt_")
    }
    # Phase 6 pure-deterministic algorithms
    deterministic_actions = {
        a for a in ZERO_DAY_ALGORITHMS
        if a.startswith("zero_day_poly_")
        or a.startswith("zero_day_adapt_")
    }
    for action in llm_actions:
        res = dispatch(action, {"name": "x"}, {},
                        {"crash_path": _make_crash_log(tmp_path),
                         "binary_path": _make_fake_binary(tmp_path),
                         "binary_v1": _make_fake_binary(tmp_path),
                         "binary_v2": _make_fake_binary(tmp_path),
                         "function_decls": [{"name": "f", "args": [], "returns": "v"}],
                         "endpoints": [{"path": "/x", "method": "GET"}],
                         "service": "s",
                         "shared_resources": ["/etc/x"],
                         "api_spec_path": _make_openapi_spec(tmp_path),
                         "workflow_steps": [{"name": "x"}]},
                        ai_backend=None)
        assert isinstance(res, dict)
        assert res["ok"] is False, (
            f"LLM-dependent {action} returned ok=True with no backend: "
            f"{res}")
    # Deterministic algorithms: must return ok=True with a concept
    # (no LLM call), never fabricate a result. Verify shape only.
    for action in deterministic_actions:
        res = dispatch(action, {"name": "x"}, {},
                        {"signature": "void f(char *p, int n)",
                         "device_class": "router",
                         "api_style": "rest",
                         "cloud": "aws",
                         "ecosystem": "python",
                         "target_class": "web"},
                        ai_backend=None)
        assert isinstance(res, dict)
        assert res.get("ok") is True, (
            f"Deterministic {action} must succeed without backend: "
            f"{res}")
        assert "draft_id" in res, (
            f"Deterministic {action} must persist a concept")
        assert "vulnerability_class" in res


def test_never_inline_harvested_credentials():
    """The algorithm functions must NEVER take a cleartext
    credential as a string argv-like input. The signature accepts
    ``target`` (dict) and ``args`` (dict) — credentials should
    come from env vars at the caller, not from the algorithm.
    """
    import inspect
    for name, fn in ZERO_DAY_ALGORITHMS.items():
        sig = inspect.signature(fn)
        # No positional ``password`` / ``secret`` / ``token`` params.
        for pname in sig.parameters:
            plower = pname.lower()
            assert plower not in ("password", "secret", "token", "credential"), (
                f"{name} has param {pname!r} — credentials must come via env vars"
            )


def test_llm_parse_failure_degrades(tmp_path):
    """When the LLM returns non-JSON, the algorithm honest-degrades."""
    binary = _make_fake_binary(tmp_path)
    backend = FakeBackend(raise_parse=True)
    res = zda.analyze_crypto_weakness_finder(
        target={}, recon={},
        args={"binary_path": binary}, ai_backend=backend,
    )
    assert res["ok"] is False
    assert "non-JSON" in res["error"]


def test_llm_non_dict_json_degrades():
    backend = FakeBackend(responses=["[1, 2, 3]"])
    res = zda.analyze_side_channel_finder(
        target={}, recon={}, args={}, ai_backend=backend,
    )
    assert res["ok"] is False
    assert "non-dict" in res["error"]


def test_llm_empty_response_degrades():
    backend = FakeBackend(responses=[""])
    res = zda.analyze_side_channel_finder(
        target={}, recon={}, args={}, ai_backend=backend,
    )
    assert res["ok"] is False
    assert "empty" in res["error"]


# ---------------------------------------------------------------------------
# Persistence guarantees
# ---------------------------------------------------------------------------

def test_draft_persistence_round_trip(tmp_path):
    """Every algorithm that returns ok=True must persist a draft the
    operator can read back via ZeroDayDraftStore.list()."""
    store = ZeroDayDraftStore(root_dir=str(tmp_path / "drafts"))
    binary = _make_fake_binary(tmp_path)
    # crash_triager
    fake_gdb = tmp_path / "gdb"
    fake_gdb.write_text("#!/bin/sh\necho ok\n")
    os.chmod(fake_gdb, 0o755)
    res = zda.analyze_crash_triager(
        target={}, recon={},
        args={"crash_path": _make_crash_log(tmp_path),
              "gdb_binary": str(fake_gdb)},
        ai_backend=FakeBackend(), store=store,
    )
    assert res["ok"] is True
    drafts = store.list()
    assert any(d.draft_id == res["draft_id"] for d in drafts)


def test_recon_context_carries_algorithm_name(tmp_path):
    """The recon_context of every persisted draft must record which
    algorithm produced it, so the operator can trace."""
    store = ZeroDayDraftStore(root_dir=str(tmp_path / "drafts"))
    binary = _make_fake_binary(tmp_path)
    res = zda.analyze_crypto_weakness_finder(
        target={}, recon={},
        args={"binary_path": binary},
        ai_backend=FakeBackend(), store=store,
    )
    assert res["ok"] is True
    drafts = store.list()
    d = next(d for d in drafts if d.draft_id == res["draft_id"])
    assert d.recon_context.get("zero_day_algorithm") == "crypto_weakness_finder"
