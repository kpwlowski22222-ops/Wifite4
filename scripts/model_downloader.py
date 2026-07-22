#!/usr/bin/env python3
"""
Model Downloader
=================
Pull / list the operator's Ollama model set, and optionally fetch GGUF files
from Hugging Face. Real `ollama pull` / `/api/pull` and `huggingface_hub`;
degrades gracefully if `huggingface_hub` is absent.
"""

import argparse
import logging
import subprocess
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.ai_backend import MODEL_CATALOG

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)


def list_installed(endpoint: str = "http://127.0.0.1:11434") -> list:
    import requests
    ep = endpoint if "://" in endpoint else "http://" + endpoint
    r = requests.get(f"{ep.rstrip('/')}/api/tags", timeout=10)
    if r.status_code != 200:
        return []
    return [m.get("name", "") for m in r.json().get("models", []) if m.get("name")]


def pull_ollama_models(models, endpoint: str = "http://127.0.0.1:11434"):
    """Pull models via `ollama pull` (real). Returns {model: ok}."""
    results = {}
    for m in models:
        try:
            p = subprocess.run(["ollama", "pull", m], timeout=1800)
            results[m] = (p.returncode == 0)
        except FileNotFoundError:
            # fall back to the REST pull API
            try:
                import requests
                ep = endpoint if "://" in endpoint else "http://" + endpoint
                r = requests.post(f"{ep.rstrip('/')}/api/pull",
                                   json={"name": m, "stream": False}, timeout=1800)
                results[m] = (r.status_code == 200)
            except Exception as e:
                results[m] = False
                logger.error(f"pull {m}: {e}")
        except Exception as e:
            results[m] = False
            logger.error(f"pull {m}: {e}")
    return results


def fetch_hf_gguf(repo_id: str, dest: str = "models/hf"):
    """Fetch a GGUF file from Hugging Face (real, via huggingface_hub)."""
    try:
        from huggingface_hub import hf_hub_download  # type: ignore
    except Exception:
        return {"error": "huggingface_hub not installed (pip install huggingface_hub)"}
    try:
        os.makedirs(dest, exist_ok=True)
        path = hf_hub_download(repo_id=repo_id, filename=None, local_dir=dest)
        return {"ok": True, "path": path}
    except Exception as e:
        return {"error": str(e)}


def main(argv=None):
    ap = argparse.ArgumentParser(description="Ollama model pull/list + HF GGUF fetch")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list", help="list installed ollama models")
    p_pull = sub.add_parser("pull", help="pull the operator's MODEL_CATALOG set")
    p_pull.add_argument("--endpoint", default="http://127.0.0.1:11434")
    p_pull.add_argument("models", nargs="*", help="optional explicit model tags")
    p_fetch = sub.add_parser("fetch-hf", help="fetch a GGUF from Hugging Face")
    p_fetch.add_argument("repo_id")
    p_fetch.add_argument("--dest", default="models/hf")
    a = ap.parse_args(argv)

    if a.cmd == "list":
        for m in list_installed():
            print(m)
    elif a.cmd == "pull":
        models = a.models or list(MODEL_CATALOG.values())
        print(f"Pulling {len(models)} models...")
        res = pull_ollama_models(models, endpoint=a.endpoint)
        for m, ok in res.items():
            print(f"  {'OK' if ok else 'FAIL'}  {m}")
    elif a.cmd == "fetch-hf":
        print(fetch_hf_gguf(a.repo_id, dest=a.dest))


if __name__ == "__main__":
    main()