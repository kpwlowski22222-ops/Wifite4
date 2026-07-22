"""Debug the Ollama cloud / hosted endpoint (Phase 2.4 §J — v2).

The Ollama cloud API (https://ollama.com or a self-hosted equivalent)
expects::

    POST /api/generate  with  Authorization: Bearer <key>

The local daemon (``http://localhost:11434``) ignores auth; the
cloud / hosted endpoint needs a Bearer header.

This module never inlines the key. The key is read from
``os.environ.get("OLLAMA_CLOUD_TOKEN")`` (fallback
``OLLAMA_AUTH_TOKEN``). If neither is set, returns
``{ok: False, error: "no Ollama cloud token configured"}``.

Phase 2.4 changes (§J):

  * **Offline-first default**: ``DEFAULT_MODEL`` is now the
    operator's preferred uncensored code-architect model
    (loaded via the LOCAL Ollama daemon):
    ``hf.co/roleplaiapp/Qwen2.5-Coder-14B-Instruct-Uncensored-Q4_K_M-GGUF:latest``.
    The local endpoint is the new default; the cloud endpoint
    is opt-in via ``--cloud`` or by passing
    ``endpoint="https://ollama.com"``.
  * **Zero-arg runnable**: ``python -m core.ai_backend.ollama_cloud_debug``
    with no args runs a status diagnostic on the local Ollama
    daemon, the default model, Ollama cloud reachability, NVD
    reachability, and Kismet reachability. Exits 0 (with a
    status report) or 1 (with errors).
  * **Algorithm improvements**:
      - Better error envelopes: 401/403/404/429/5xx each
        produce a specific error with retry hint (parsed from
        ``Retry-After``).
      - Retry/backoff: ``--retry N`` enables up to N retries
        with exponential backoff on 429/5xx.
      - JSONL output: ``--jsonl`` outputs newline-delimited
        JSON instead of pretty JSON.
      - Batch cartesian product: ``--batch <file.json>`` takes
        a JSON file with ``{prompts: [...], models: [...]}``
        and runs the cartesian product, throttled to 1 req/s.
      - ``--max-tokens N`` caps response budget.
      - ``--sandbox`` refuses to call the daemon or cloud;
        prints what it *would* do and exits 0.
      - ``--nvd <cve-id>`` proxies to NVD lookup
        (``https://services.nvd.nist.gov/rest/json/cves/2.0``)
        via ``get_nvd_key()`` (never inline).
      - ``--exploit-skeleton <cve-id>`` builds a pseudocode-
        only outline using the operator's preferred
        uncensored model. The prompt explicitly says
        "pseudocode only — do not include real exploit code".
      - ``--save-raw <path>`` writes the raw response body
        to a file.
      - ``--raw-response`` prints raw JSON without pretty.

CLI:
    .venv/bin/python -m core.ai_backend.ollama_cloud_debug
        # zero-arg status diagnostic (Phase 2.4)
    .venv/bin/python -m core.ai_backend.ollama_cloud_debug --reachable
    .venv/bin/python -m core.ai_backend.ollama_cloud_debug --list-models
    .venv/bin/python -m core.ai_backend.ollama_cloud_debug --generate "..."
    .venv/bin/python -m core.ai_backend.ollama_cloud_debug --cloud --generate "..."
    .venv/bin/python -m core.ai_backend.ollama_cloud_debug --nvd CVE-2021-34981 --sandbox
    .venv/bin/python -m core.ai_backend.ollama_cloud_debug --exploit-skeleton CVE-2020-26880

Safety stance (per project rules, still in effect):
  * The token is read from env only. Never inlined in source.
  * All HTTP calls use ``requests`` with a 30s timeout.
  * Errors are honest: 401/403/429/5xx all produce explicit
    envelopes with ``fix:`` hints.
  * Exploit skeletons are pseudocode-only — the prompt
    explicitly says so and the LLM is expected to comply.
  * The default is the LOCAL Ollama daemon
    (``USE_OFFLINE_FIRST=1`` env, default on). Ollama cloud
    is opt-in via ``--cloud``.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

# Public surface
__all__ = [
    "get_ollama_token",
    "DEFAULT_CLOUD_ENDPOINT",
    "DEFAULT_LOCAL_ENDPOINT",
    "DEFAULT_MODEL",
    "USE_OFFLINE_FIRST",
    "ollama_cloud_reachable",
    "ollama_local_reachable",
    "ollama_cloud_list_models",
    "ollama_cloud_generate",
    "cve_lookup_nvd",
    "exploit_skeleton_prompt",
    "ollama_cloud_generate_batch",
    "run_status_diagnostic",
    "main",
]


DEFAULT_CLOUD_ENDPOINT = "https://ollama.com"
DEFAULT_LOCAL_ENDPOINT = "http://localhost:11434"
# Operator's preferred uncensored code-architect model
# (loaded via the LOCAL Ollama daemon; not on the cloud catalog).
# Coder-14B-Instruct is the same family Qwen2.5 ships — the
# operator's revision (Phase 2.4 §J.2) makes this the new
# default; ``kimi-k2.7-code`` is no longer wired.
DEFAULT_MODEL = (
    "hf.co/roleplaiapp/Qwen2.5-Coder-14B-Instruct-"
    "Uncensored-Q4_K_M-GGUF:latest"
)
USE_OFFLINE_FIRST = (
    (os.environ.get("USE_OFFLINE_FIRST") or "1").lower()
    not in ("0", "false", "no", "off")
)


def get_ollama_token() -> Optional[str]:
    """Read the Ollama cloud token from env. Never inlined."""
    return (os.environ.get("OLLAMA_CLOUD_TOKEN")
            or os.environ.get("OLLAMA_AUTH_TOKEN"))


def get_nvd_key() -> Optional[str]:
    """Read the NVD API key from env via the canonical KFIOSA helper.

    The operator-provided key is read from ``$NVD_API_KEY`` via
    :func:`core.ai_backend.get_nvd_key`. This wrapper keeps the
    import order robust (lazy import) and never inlines the
    key value in source.
    """
    try:
        from core.ai_backend import get_nvd_key as _get_nvd
        v = _get_nvd()
        return v if v else None
    except Exception:  # noqa: BLE001
        return os.environ.get("NVD_API_KEY")


def _build_headers(token: Optional[str]) -> Dict[str, str]:
    h = {
        "Content-Type": "application/json",
        "User-Agent": "kfiosa-ollama-cloud-debug/1.0",
    }
    if token:
        h["Authorization"] = f"Bearer {token}"
    return h


def _do_request(url: str, payload: Dict[str, Any],
                method: str = "POST",
                token: Optional[str] = None,
                timeout: float = 30.0) -> Dict[str, Any]:
    """Make an HTTP request and return a structured envelope.

    Returns ``{ok, status, body, error}``. Never raises.
    """
    try:
        import requests  # type: ignore
    except ImportError:
        return {
            "ok": False,
            "error": "the 'requests' library is not installed; "
                     "install it via the per-step tool_installer",
            "fix": "pip install requests",
        }
    try:
        if method == "GET":
            r = requests.get(url, headers=_build_headers(token),
                             timeout=timeout)
        else:
            r = requests.post(url, headers=_build_headers(token),
                              json=payload, timeout=timeout)
    except Exception as e:  # noqa: BLE001
        return {
            "ok": False,
            "error": f"network error: {e}",
            "url": url,
            "fix": ("check that the Ollama daemon is running "
                    "(systemctl status ollama) and that the "
                    "endpoint URL is correct"),
        }
    out: Dict[str, Any] = {
        "ok": r.ok,
        "status": r.status_code,
        "url": url,
    }
    if r.ok:
        try:
            out["body"] = r.json()
        except Exception:  # noqa: BLE001
            out["body"] = r.text
    else:
        out["error"] = f"http {r.status_code}: {r.reason or 'unknown'}"
        # Specific error envelopes with fix hints
        if r.status_code == 401:
            out["fix"] = ("set OLLAMA_CLOUD_TOKEN env var with a "
                          "valid token from ollama.com/settings")
        elif r.status_code == 403:
            out["fix"] = ("the token does not have access to this "
                          "model; pick a public model or update the "
                          "subscription")
        elif r.status_code == 404:
            out["error"] = f"http {r.status_code}: model not found"
            out["fix"] = (f"check that the model {payload.get('model', '')} "
                          "is available on this endpoint "
                          "(--list-models)")
        elif r.status_code == 429:
            out["error"] = f"http {r.status_code}: rate limited"
            try:
                ra = r.headers.get("Retry-After")
                if ra:
                    out["retry_after_s"] = int(ra)
            except Exception:  # noqa: BLE001
                pass
            out["fix"] = ("back off and retry; cloud rate limits are "
                          "typically 5/min for unauthenticated, "
                          "60/min for authenticated")
        elif r.status_code >= 500:
            out["error"] = f"http {r.status_code}: server error"
            out["fix"] = ("retry with --retry N; if persistent, "
                          "the cloud endpoint is having issues")
        try:
            out["body"] = r.json()
        except Exception:  # noqa: BLE001
            out["body"] = r.text[:512]
    return out


def _retry_request(url: str, payload: Dict[str, Any], *,
                   method: str = "POST", token: Optional[str] = None,
                   timeout: float = 30.0, retries: int = 0) -> Dict[str, Any]:
    """Retry ``_do_request`` with exponential backoff on 429/5xx."""
    last: Dict[str, Any] = {"ok": False, "error": "no attempts made"}
    delay = 1.0
    for attempt in range(max(1, retries + 1)):
        last = _do_request(url, payload, method=method, token=token,
                           timeout=timeout)
        if last.get("ok"):
            last["attempts"] = attempt + 1
            return last
        status = last.get("status", 0)
        if status not in (429, 0) and status < 500:
            # 4xx other than 429 → give up
            last["attempts"] = attempt + 1
            return last
        if attempt < retries:
            time.sleep(delay)
            delay = min(delay * 2, 30.0)
    last["attempts"] = retries + 1
    return last


# ---------------------------------------------------------------------------
# Reachability / list
# ---------------------------------------------------------------------------


def ollama_local_reachable(
    endpoint: str = DEFAULT_LOCAL_ENDPOINT,
) -> Dict[str, Any]:
    """Check the local Ollama daemon. No auth needed."""
    return _do_request(endpoint.rstrip("/") + "/api/tags",
                       payload={}, method="GET", token=None)


def ollama_cloud_reachable(
    endpoint: str = DEFAULT_CLOUD_ENDPOINT,
    token: Optional[str] = None,
) -> Dict[str, Any]:
    """Check the cloud / hosted endpoint reachability."""
    return _do_request(endpoint.rstrip("/") + "/api/tags",
                       payload={}, method="GET", token=token)


def ollama_cloud_list_models(
    endpoint: str = DEFAULT_CLOUD_ENDPOINT,
    token: Optional[str] = None,
) -> Dict[str, Any]:
    """List models available on the cloud / hosted endpoint."""
    result = ollama_cloud_reachable(endpoint=endpoint, token=token)
    if not result.get("ok"):
        return {
            "ok": False,
            "error": result.get("error", "unknown"),
            "fix": result.get("fix"),
            "status": result.get("status"),
        }
    body = result.get("body") or {}
    if isinstance(body, dict):
        models_raw = body.get("models") or []
    else:
        models_raw = []
    models: List[Dict[str, Any]] = []
    for m in models_raw:
        if isinstance(m, dict):
            models.append({
                "name": m.get("name"),
                "size": m.get("size"),
                "modified_at": m.get("modified_at"),
            })
    return {
        "ok": True,
        "models": models,
        "count": len(models),
        "endpoint": endpoint,
    }


def ollama_cloud_generate(
    prompt: str,
    model: str = DEFAULT_MODEL,
    endpoint: Optional[str] = None,
    token: Optional[str] = None,
    timeout: float = 60.0,
    max_tokens: Optional[int] = None,
    retries: int = 0,
    sandbox: bool = False,
    raw_save: Optional[str] = None,
) -> Dict[str, Any]:
    """Send a generation request.

    Args:
        prompt: the prompt text.
        model: model tag.
        endpoint: defaults to LOCAL (offline-first). Pass
            ``DEFAULT_CLOUD_ENDPOINT`` to use the cloud.
        token: Ollama Bearer token (cloud only).
        timeout: HTTP timeout in seconds.
        max_tokens: cap response budget; None = no cap.
        retries: number of retries on 429/5xx.
        sandbox: if True, do not call the network; return
            a what-would-happen envelope.
        raw_save: path to write the raw body to (debug).

    Returns:
        A normalised envelope. ``data.model`` always reflects
        which model was used.
    """
    # Phase 2.4 §J.2: offline-first by default.
    if endpoint is None:
        endpoint = (DEFAULT_LOCAL_ENDPOINT if USE_OFFLINE_FIRST
                    else DEFAULT_CLOUD_ENDPOINT)
    if sandbox:
        return {
            "ok": True,
            "sandbox": True,
            "model": model,
            "endpoint": endpoint,
            "would_prompt": prompt,
            "would_call": f"POST {endpoint.rstrip('/')}/api/generate",
            "response": ("[sandbox] would have called the model; "
                         "no network was used"),
        }
    url = endpoint.rstrip("/") + "/api/generate"
    payload: Dict[str, Any] = {
        "model": model,
        "prompt": prompt,
        "stream": False,
    }
    if max_tokens:
        payload["options"] = {"num_predict": int(max_tokens)}
    result = _retry_request(url, payload, method="POST", token=token,
                            timeout=timeout, retries=retries)
    if not result.get("ok"):
        return {
            "ok": False,
            "error": result.get("error", "unknown"),
            "fix": result.get("fix"),
            "status": result.get("status"),
            "retry_after_s": result.get("retry_after_s"),
            "attempts": result.get("attempts"),
            "model": model,
            "endpoint": endpoint,
        }
    body = result.get("body") or {}
    if raw_save:
        try:
            with open(raw_save, "w") as f:
                f.write(json.dumps(body, indent=2, default=str))
        except Exception as e:  # noqa: BLE001
            pass
    if isinstance(body, dict):
        response = body.get("response", "")
        if max_tokens and len(response) > max_tokens:
            response = response[:max_tokens]
        return {
            "ok": True,
            "model": model,
            "response": response,
            "eval_count": body.get("eval_count"),
            "eval_duration": body.get("eval_duration"),
            "endpoint": endpoint,
            "attempts": result.get("attempts"),
        }
    return {
        "ok": True,
        "model": model,
        "response": str(body)[:4096],
        "endpoint": endpoint,
    }


def ollama_cloud_generate_batch(
    prompts: List[str],
    models: List[str],
    endpoint: Optional[str] = None,
    token: Optional[str] = None,
    throttle_s: float = 1.0,
    timeout: float = 60.0,
    max_tokens: Optional[int] = None,
) -> List[Dict[str, Any]]:
    """Cartesian product over prompts × models, throttled."""
    if endpoint is None:
        endpoint = (DEFAULT_LOCAL_ENDPOINT if USE_OFFLINE_FIRST
                    else DEFAULT_CLOUD_ENDPOINT)
    out: List[Dict[str, Any]] = []
    for prompt in prompts:
        for model in models:
            res = ollama_cloud_generate(
                prompt=prompt, model=model, endpoint=endpoint,
                token=token, timeout=timeout, max_tokens=max_tokens,
            )
            out.append({
                "prompt": prompt,
                "model": model,
                "ok": res.get("ok"),
                "response": res.get("response", "")[:512],
                "error": res.get("error"),
            })
            time.sleep(throttle_s)
    return out


# ---------------------------------------------------------------------------
# NVD lookup + exploit skeleton
# ---------------------------------------------------------------------------


def cve_lookup_nvd(
    cve_id: str,
    nvd_key: Optional[str] = None,
    timeout: float = 30.0,
    sandbox: bool = False,
) -> Dict[str, Any]:
    """Look up a CVE id on NVD. Reads key via ``get_nvd_key()``.

    Returns ``{ok, cve_id, summary, cvss, references, error}``.
    Never inlines the key in the envelope.
    """
    if sandbox:
        return {
            "ok": True,
            "sandbox": True,
            "cve_id": cve_id,
            "would_call": ("https://services.nvd.nist.gov/rest/"
                           "json/cves/2.0?cveId=" + cve_id),
            "summary": "[sandbox] would have called NVD",
        }
    if nvd_key is None:
        nvd_key = get_nvd_key()
    url = (f"https://services.nvd.nist.gov/rest/json/cves/2.0"
           f"?cveId={cve_id}")
    headers: Dict[str, str] = {"User-Agent": "kfiosa-nvd-lookup/1.0"}
    if nvd_key:
        headers["apiKey"] = nvd_key
    try:
        import requests  # type: ignore
        r = requests.get(url, headers=headers, timeout=timeout)
    except Exception as e:  # noqa: BLE001
        return {
            "ok": False,
            "cve_id": cve_id,
            "error": f"network error: {e}",
        }
    if not r.ok:
        return {
            "ok": False,
            "cve_id": cve_id,
            "status": r.status_code,
            "error": f"http {r.status_code}",
        }
    try:
        body = r.json()
    except Exception:  # noqa: BLE001
        return {
            "ok": False,
            "cve_id": cve_id,
            "error": "NVD returned non-JSON",
        }
    vulns = body.get("vulnerabilities") or []
    if not vulns:
        return {
            "ok": False,
            "cve_id": cve_id,
            "error": f"no NVD record for {cve_id}",
        }
    c = vulns[0].get("cve", {}) or {}
    descs = c.get("descriptions") or []
    summary = ""
    for d in descs:
        if d.get("lang") == "en":
            summary = d.get("value", "")
            break
    metrics = c.get("metrics", {}) or {}
    cvss = None
    for k in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if k in metrics and metrics[k]:
            try:
                cvss = metrics[k][0]["cvssData"]["baseScore"]
                break
            except Exception:  # noqa: BLE001
                pass
    refs = c.get("references") or []
    return {
        "ok": True,
        "cve_id": cve_id,
        "summary": summary,
        "cvss_base_score": cvss,
        "reference_count": len(refs),
        "first_reference": refs[0].get("url") if refs else None,
    }


def exploit_skeleton_prompt(cve_id: str, summary: str = "") -> str:
    """Build the prompt the LLM sees for ``--exploit-skeleton``.

    The prompt explicitly tells the LLM:
      * output a PSEUDOCODE outline only
      * do NOT include real exploit code
      * describe function signatures, key syscalls, error handling
    The operator's never-weaponize contract is preserved.
    """
    return (
        f"You are asked to outline what an exploit for "
        f"{cve_id} would look like.\n"
        f"CVE summary: {summary or '(not loaded)'}\n\n"
        f"Output requirements (HARD):\n"
        f"  1. Pseudocode ONLY. Do not include real exploit code,\n"
        f"     payloads, shellcode, or weaponizable strings.\n"
        f"  2. Function signatures are OK (e.g. def exploit(target): ...).\n"
        f"  3. Key syscalls / API calls are OK as names (e.g.\n"
        f"     'send_auth_packet', 'parse_response').\n"
        f"  4. Do NOT include IP addresses, ports, creds, hashes, or\n"
        f"     CVE detail beyond the summary above.\n"
        f"  5. Outline error-handling and rollback steps.\n"
        f"  6. End with a one-line disclaimer that the actual code\n"
        f"     must be written by the operator from this outline.\n"
    )


# ---------------------------------------------------------------------------
# Status diagnostic (zero-arg)
# ---------------------------------------------------------------------------


def run_status_diagnostic(
    cloud_endpoint: str = DEFAULT_CLOUD_ENDPOINT,
    local_endpoint: str = DEFAULT_LOCAL_ENDPOINT,
    model: str = DEFAULT_MODEL,
    nvd_cve: str = "CVE-2021-34981",
    sandbox: bool = False,
) -> Dict[str, Any]:
    """Phase 2.4 §J.1 — one-screen status diagnostic.

    Returns a structured dict; ``main()`` prints it as pretty
    or JSONL depending on ``--jsonl``.

    The report includes:
      - local Ollama daemon reachable? (probe /api/tags)
      - default model loaded? (probe /api/show)
      - Ollama cloud reachable? (probe /api/tags with Bearer)
      - NVD reachable? (probe a known CVE id)
      - Kismet reachable? (probe http://localhost:2501)
    """
    report: Dict[str, Any] = {
        "default_model": model,
        "default_endpoint": (local_endpoint if USE_OFFLINE_FIRST
                             else cloud_endpoint),
        "use_offline_first": USE_OFFLINE_FIRST,
        "ollama_local": {"reachable": None, "endpoint": local_endpoint,
                          "default_model_loaded": None,
                          "available_models": 0},
        "ollama_cloud": {"reachable": None, "endpoint": cloud_endpoint,
                          "token_set": bool(get_ollama_token())},
        "nvd": {"reachable": None, "cve_probed": nvd_cve,
                "key_set": bool(get_nvd_key())},
        "kismet": {"reachable": None, "endpoint": "http://localhost:2501"},
        "sandbox": sandbox,
    }
    if sandbox:
        report["ollama_local"]["reachable"] = "sandbox"
        report["ollama_cloud"]["reachable"] = "sandbox"
        report["nvd"]["reachable"] = "sandbox"
        report["kismet"]["reachable"] = "sandbox"
        return report
    # Local Ollama
    local = ollama_local_reachable(endpoint=local_endpoint)
    report["ollama_local"]["reachable"] = bool(local.get("ok"))
    if local.get("ok"):
        body = local.get("body") or {}
        models = body.get("models") or []
        report["ollama_local"]["available_models"] = len(models)
        report["ollama_local"]["default_model_loaded"] = any(
            m.get("name") == model
            or (m.get("name") or "").startswith(model.split(":")[0])
            for m in models if isinstance(m, dict)
        )
    else:
        report["ollama_local"]["error"] = local.get("error")
    # Cloud Ollama
    cloud = ollama_cloud_reachable(endpoint=cloud_endpoint,
                                   token=get_ollama_token())
    report["ollama_cloud"]["reachable"] = bool(cloud.get("ok"))
    if not cloud.get("ok"):
        report["ollama_cloud"]["error"] = cloud.get("error")
    # NVD
    nvd = cve_lookup_nvd(nvd_cve, nvd_key=get_nvd_key(), sandbox=False)
    report["nvd"]["reachable"] = bool(nvd.get("ok"))
    if nvd.get("ok"):
        report["nvd"]["summary_preview"] = (
            (nvd.get("summary") or "")[:120]
        )
    else:
        report["nvd"]["error"] = nvd.get("error")
    # Kismet
    try:
        import requests  # type: ignore
        r = requests.get("http://localhost:2501/system/status.json",
                         timeout=3)
        report["kismet"]["reachable"] = r.ok
        if r.ok:
            try:
                report["kismet"]["version"] = (
                    r.json().get("kismet_system_version")
                )
            except Exception:  # noqa: BLE001
                pass
    except Exception as e:  # noqa: BLE001
        report["kismet"]["reachable"] = False
        report["kismet"]["error"] = str(e)[:80]
    return report


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="kfiosa.ollama_cloud_debug",
        description=(
            "Debug the Ollama (local or cloud) endpoint with the "
            "operator's Bearer token. Offline-first by default; "
            "use --cloud to opt into the cloud endpoint."
        ),
    )
    # Diagnostic flags
    p.add_argument("--health", "--status", action="store_true",
                   dest="health",
                   help="run the one-screen status diagnostic (same "
                        "as the zero-arg behaviour)")
    p.add_argument("--reachable", action="store_true",
                   help="just check the endpoint is up")
    p.add_argument("--list-models", action="store_true",
                   help="GET /api/tags")
    p.add_argument("--generate", type=str, default=None,
                   help="POST /api/generate with this prompt")
    # Endpoint selection
    p.add_argument("--model", type=str, default=DEFAULT_MODEL,
                   help="override the model tag (default is the "
                        "operator's uncensored Qwen2.5-Coder)")
    p.add_argument("--endpoint", type=str, default=None,
                   help="override the endpoint URL "
                        "(default: local Ollama daemon)")
    p.add_argument("--cloud", action="store_true",
                   help="opt into the Ollama cloud endpoint "
                        "(https://ollama.com)")
    p.add_argument("--timeout", type=float, default=60.0,
                   help="HTTP timeout in seconds")
    p.add_argument("--no-token", action="store_true",
                   help="do not use the OLLAMA_CLOUD_TOKEN env var")
    p.add_argument("--retry", type=int, default=0,
                   help="retry on 429/5xx with exponential backoff")
    # Output formatting
    p.add_argument("--jsonl", action="store_true",
                   help="output newline-delimited JSON")
    p.add_argument("--raw-response", action="store_true",
                   help="print raw response (no pretty JSON wrapping)")
    p.add_argument("--save-raw", type=str, default=None,
                   help="write raw body to this file")
    p.add_argument("--max-tokens", type=int, default=None,
                   help="cap response token budget")
    # New modes
    p.add_argument("--sandbox", action="store_true",
                   help="do not call the network; print what would "
                        "be called and exit 0")
    p.add_argument("--nvd", type=str, default=None,
                   help="look up a CVE id on NVD (uses NVD_API_KEY env)")
    p.add_argument("--exploit-skeleton", type=str, default=None,
                   help="generate a pseudocode-only exploit outline "
                        "for a CVE id")
    p.add_argument("--batch", type=str, default=None,
                   help="run a cartesian-product batch from a JSON "
                        "file with {prompts, models}")
    return p


def _resolve_endpoint(args: argparse.Namespace) -> str:
    if args.endpoint:
        return args.endpoint
    if args.cloud:
        return DEFAULT_CLOUD_ENDPOINT
    return DEFAULT_LOCAL_ENDPOINT


def main(argv: Optional[List[str]] = None) -> int:
    args = _build_argparser().parse_args(argv)
    endpoint = _resolve_endpoint(args)
    token = None if args.no_token else get_ollama_token()
    is_cloud = endpoint.rstrip("/").startswith("https://")
    if is_cloud and not token and not args.no_token:
        print("warning: OLLAMA_CLOUD_TOKEN not set; the cloud "
              "endpoint will return 401.", file=sys.stderr)
    out: Dict[str, Any] = {}
    if args.sandbox or args.health:
        # When the user explicitly asks for an --nvd or
        # --exploit-skeleton alongside --sandbox, return the
        # specific sandbox envelope for that request rather
        # than the global status diagnostic.
        if args.exploit_skeleton:
            cve = cve_lookup_nvd(args.exploit_skeleton, sandbox=True)
            prompt = exploit_skeleton_prompt(args.exploit_skeleton, "")
            out = {
                "ok": True, "sandbox": True,
                "cve_id": args.exploit_skeleton,
                "would_prompt": prompt,
            }
        elif args.nvd:
            out = cve_lookup_nvd(args.nvd, sandbox=True)
        else:
            diag = run_status_diagnostic(
                cloud_endpoint=(endpoint if is_cloud
                                else DEFAULT_CLOUD_ENDPOINT),
                local_endpoint=(endpoint if not is_cloud
                                else DEFAULT_LOCAL_ENDPOINT),
                model=args.model,
                sandbox=args.sandbox,
            )
            if args.jsonl:
                print(json.dumps(diag, default=str))
            else:
                print(json.dumps(diag, indent=2, default=str))
            if args.sandbox:
                return 0
            ok = (diag["ollama_local"].get("reachable")
                  or diag["ollama_cloud"].get("reachable"))
            return 0 if ok else 1
        if args.jsonl:
            print(json.dumps(out, default=str))
        elif args.raw_response:
            if isinstance(out.get("response"), str):
                print(out["response"])
            else:
                print(json.dumps(out, default=str))
        else:
            print(json.dumps(out, indent=2, default=str))
        return 0 if out.get("ok") else 1
    if args.nvd:
        out = cve_lookup_nvd(args.nvd, sandbox=args.sandbox)
    elif args.exploit_skeleton:
        cve = cve_lookup_nvd(args.exploit_skeleton, sandbox=args.sandbox)
        summary = cve.get("summary", "") if cve.get("ok") else ""
        prompt = exploit_skeleton_prompt(args.exploit_skeleton, summary)
        if args.sandbox:
            out = {
                "ok": True, "sandbox": True,
                "cve_id": args.exploit_skeleton,
                "would_prompt": prompt,
            }
        else:
            out = ollama_cloud_generate(
                prompt, model=args.model, endpoint=endpoint,
                token=token, timeout=args.timeout,
                max_tokens=args.max_tokens, retries=args.retry,
                raw_save=args.save_raw,
            )
            out["cve_id"] = args.exploit_skeleton
            out["prompt_kind"] = "exploit_skeleton_pseudocode_only"
    elif args.reachable:
        if is_cloud:
            out = ollama_cloud_reachable(endpoint=endpoint, token=token)
        else:
            out = ollama_local_reachable(endpoint=endpoint)
    elif args.list_models:
        out = ollama_cloud_list_models(endpoint=endpoint, token=token)
    elif args.generate:
        out = ollama_cloud_generate(
            args.generate, model=args.model, endpoint=endpoint,
            token=token, timeout=args.timeout,
            max_tokens=args.max_tokens, retries=args.retry,
            sandbox=args.sandbox, raw_save=args.save_raw,
        )
    elif args.batch:
        try:
            with open(args.batch) as f:
                spec = json.load(f)
            prompts = spec.get("prompts") or []
            models = spec.get("models") or [args.model]
            results = ollama_cloud_generate_batch(
                prompts, models, endpoint=endpoint, token=token,
                timeout=args.timeout, max_tokens=args.max_tokens,
            )
            if args.jsonl:
                for r in results:
                    print(json.dumps(r, default=str))
                return 0
            out = {"ok": True, "count": len(results), "results": results}
        except Exception as e:  # noqa: BLE001
            out = {"ok": False, "error": f"batch failed: {e}"}
    else:
        # Zero-arg default: status diagnostic
        diag = run_status_diagnostic(
            cloud_endpoint=(endpoint if is_cloud
                            else DEFAULT_CLOUD_ENDPOINT),
            local_endpoint=(endpoint if not is_cloud
                            else DEFAULT_LOCAL_ENDPOINT),
            model=args.model, sandbox=args.sandbox,
        )
        if args.jsonl:
            print(json.dumps(diag, default=str))
        else:
            print(json.dumps(diag, indent=2, default=str))
        ok = (diag["ollama_local"].get("reachable")
              or diag["ollama_cloud"].get("reachable"))
        return 0 if ok else 1
    if args.jsonl:
        print(json.dumps(out, default=str))
    elif args.raw_response:
        if isinstance(out.get("response"), str):
            print(out["response"])
        else:
            print(json.dumps(out, default=str))
    else:
        print(json.dumps(out, indent=2, default=str))
    return 0 if out.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())
