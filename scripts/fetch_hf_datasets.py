#!/usr/bin/env python3
"""Fetch Hugging Face datasets for KFIOSA LoRA/QLoRA fine-tunes.

Hardware-aware for the operator notebook:
  * RTX 5070 Ti Laptop 12 GB VRAM
  * 32 GB DDR5 system RAM
  * AMD/Intel NPU present (not used for QLoRA; GPU path only)
  * Linux + local Ollama / HF transformers stack

Goals map to MODEL_CATALOG + pentest_hf_registry domains:
  wifi / ble / osint / post_exploit / code_architect (uncensored
  Qwen2.5-Coder + HERETIC Qwen3.5) / general pentest SFT.

Never downloads multi-GB corpora whole. Large sets are streamed and
capped (``--max-rows`` / profile sample budgets). Gated repos are
skipped with an honest envelope (no fake data).

Usage:
  .venv/bin/python scripts/fetch_hf_datasets.py --list
  .venv/bin/python scripts/fetch_hf_datasets.py --profile notebook_12gb
  .venv/bin/python scripts/fetch_hf_datasets.py --only wifi,osint --max-rows 5000
  .venv/bin/python scripts/fetch_hf_datasets.py --dry-run
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

REGISTRY_PATH = ROOT / "pentest_hf_registry.json"
DEFAULT_OUT = ROOT / "data" / "finetune" / "hf"


# ---------------------------------------------------------------------------
# Hardware profiles (VRAM-aware sample budgets + QLoRA knobs)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class HwProfile:
    name: str
    vram_gb: int
    ram_gb: int
    # Max rows per dataset download (streamed)
    max_rows_small: int   # < 50 MB catalog estimate
    max_rows_medium: int  # 50–400 MB
    max_rows_large: int   # > 400 MB or million-row dumps
    # Recommended QLoRA defaults for this box
    base_model: str
    base_model_fast: str
    lora_r: int
    lora_alpha: int
    lora_dropout: float
    learning_rate: float
    epochs: int
    batch_size: int
    grad_accum: int
    max_seq_length: int
    use_4bit: bool
    gradient_checkpointing: bool
    notes: str


NOTEBOOK_12GB = HwProfile(
    name="notebook_12gb",
    vram_gb=12,
    ram_gb=32,
    max_rows_small=50_000,
    max_rows_medium=20_000,
    max_rows_large=8_000,
    # 9B QLoRA-4bit fits 12 GB with seq≈1536, bs=1, grad ckpt
    base_model=(
        "DavidAU/Qwen3.5-9B-Claude-4.6-HighIQ-THINKING-HERETIC-UNCENSORED"
    ),
    # Fast adapter iteration (~1–3B)
    base_model_fast=(
        "DavidAU/gemma-3-1b-it-heretic-extreme-uncensored-abliterated"
    ),
    lora_r=16,
    lora_alpha=32,
    lora_dropout=0.05,
    learning_rate=2e-4,
    epochs=2,
    batch_size=1,
    grad_accum=8,
    max_seq_length=1536,
    use_4bit=True,
    gradient_checkpointing=True,
    notes=(
        "RTX 5070 Ti 12 GB: prefer QLoRA 4-bit, batch=1, grad_accum=8, "
        "max_seq=1536 for 9B; use base_model_fast (1B) for smoke loops. "
        "NPU is not used for training — keep Ollama inference on GPU/CPU. "
        "Avoid full SFT of 14B+; use GGUF Q4 via Ollama for serving."
    ),
)

PROFILES: Dict[str, HwProfile] = {
    "notebook_12gb": NOTEBOOK_12GB,
    "default": NOTEBOOK_12GB,
}


# Curated picks: (repo_id, domain, priority, goal)
# priority: 1 = always fetch for notebook profile, 2 = optional, 3 = skip unless --all
CURATED: List[Dict[str, Any]] = [
    # --- WiFi / wireless (MODEL_CATALOG wifi + chain heuristics) ---
    {
        "id": "Esteban527/raft-wifi-dataset-v2",
        "domain": "wifi",
        "priority": 1,
        "goal": "802.11 RAFT CoT for wifi pentest assistant SFT",
        "size_class": "small",
    },
    {
        "id": "ictrun/wireless-vendor-identifiers",
        "domain": "wifi",
        "priority": 1,
        "goal": "OUI/MAC vendor recon fingerprints",
        "size_class": "small",
        "config": "vendor_identifiers",
    },
    # --- BLE (sparse on HF; keep small) ---
    {
        "id": "electricsheepafrica/africa-hospital-iot-security",
        "domain": "ble",
        "priority": 2,
        "goal": "IoT/BLE-adjacent security scenarios for recon prompts",
        "size_class": "small",
    },
    # --- OSINT ---
    {
        "id": "nadiCR7/Intelligence_Osint_Final",
        "domain": "osint",
        "priority": 1,
        "goal": "OSINT intelligence instruction reasoning",
        "size_class": "small",
    },
    {
        "id": "Yemen-JPT/OSINT-ToolDB",
        "domain": "osint",
        "priority": 1,
        "goal": "OSINT tool recommendation for recon chains",
        "size_class": "small",
    },
    {
        "id": "mrmoor/cyber-threat-intelligence",
        "domain": "osint",
        "priority": 1,
        "goal": "CTI NER / IOC extraction support",
        "size_class": "small",
    },
    {
        "id": "Inforensics/missing-persons-clue-analysis-osint",
        "domain": "osint",
        "priority": 2,
        "goal": "Person/clue analysis OSINT instructions",
        "size_class": "small",
    },
    # --- Post-exploit / red-team / general pentest SFT ---
    {
        "id": "Vanessasml/cybersecurity_32k_instruction_input_output",
        "domain": "post_exploitation",
        "priority": 1,
        "goal": "32k cyber instruction triples for pentest assistant",
        "size_class": "small",
    },
    {
        "id": "detoxioai/exploit_db_train_v1",
        "domain": "post_exploitation",
        "priority": 1,
        "goal": "Exploit-DB style prompt/response for code-aware SFT",
        "size_class": "small",
    },
    {
        "id": "oyildirim/cyberstrike-sft-120k",
        "domain": "post_exploitation",
        "priority": 1,
        "goal": "CyberStrike OffSec SFT chat (sample-capped on 12 GB)",
        "size_class": "medium",
    },
    {
        "id": "7h3-R3v3n4n7/pentest-agent-dataset-alpaca",
        "domain": "post_exploitation",
        "priority": 1,
        "goal": "Alpaca pentest-agent instructions (sample-capped)",
        "size_class": "medium",
    },
    {
        "id": "Trendyol/Trendyol-Cybersecurity-Instruction-Tuning-Dataset",
        "domain": "post_exploitation",
        "priority": 1,
        "goal": "BaronLLM-family cyber instruction tuning set",
        "size_class": "medium",
    },
    {
        "id": "AlicanKiraz0/Cybersecurity-Dataset-Fenrir-v2.1",
        "domain": "post_exploitation",
        "priority": 1,
        "goal": "Cybersecurity conversation SFT (Fenrir)",
        "size_class": "medium",
    },
    {
        "id": "ChaoticNeutrals/Cybersecurity-ShareGPT",
        "domain": "post_exploitation",
        "priority": 2,
        "goal": "ShareGPT cyber chat alignment",
        "size_class": "medium",
    },
    # --- Uncensored / non-refusal coverage (backbone adapter) ---
    {
        "id": "jondurbin/airoboros-uncensored",
        "domain": "uncensored_base",
        "priority": 1,
        "goal": "Uncensored instruct foundation for HERETIC/Qwen adapters",
        "size_class": "medium",
    },
    {
        "id": "diwank/orca_minis_uncensored-chatml",
        "domain": "uncensored_base",
        "priority": 2,
        "goal": "ChatML orca uncensored (modern template)",
        "size_class": "medium",
    },
    {
        "id": "pankajmathur/orca_minis_uncensored_dataset",
        "domain": "uncensored_base",
        "priority": 2,
        "goal": "Classic orca_mini uncensored blend",
        "size_class": "medium",
    },
    # Large dumps — sample only, never full mirror on notebook
    {
        "id": "QuixiAI/open-instruct-uncensored",
        "domain": "uncensored_base",
        "priority": 3,
        "goal": "Huge uncensored open-instruct (stream sample only)",
        "size_class": "large",
    },
]


def _load_registry() -> Dict[str, Any]:
    if not REGISTRY_PATH.is_file():
        return {}
    try:
        return json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def _row_budget(profile: HwProfile, size_class: str) -> int:
    return {
        "small": profile.max_rows_small,
        "medium": profile.max_rows_medium,
        "large": profile.max_rows_large,
    }.get(size_class, profile.max_rows_medium)


def _slug(repo_id: str) -> str:
    return repo_id.replace("/", "__")


def _safe_to_jsonable(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {str(k): _safe_to_jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_safe_to_jsonable(v) for v in obj]
    if isinstance(obj, (str, int, float, bool)) or obj is None:
        return obj
    return str(obj)


def _parse_config_names(err: BaseException) -> List[str]:
    """Extract available configs from a datasets 'Config name is missing' error."""
    msg = str(err)
    # Example: Please pick one among the available configs: ['a', 'b']
    if "available configs" not in msg.lower():
        return []
    try:
        start = msg.index("[")
        end = msg.rindex("]") + 1
        import ast
        names = ast.literal_eval(msg[start:end])
        if isinstance(names, (list, tuple)):
            return [str(n) for n in names]
    except Exception:
        pass
    return []


def _write_stream(ds: Any, jsonl_path: Path, max_rows: int) -> int:
    written = 0
    with jsonl_path.open("w", encoding="utf-8") as fh:
        for row in ds:
            fh.write(json.dumps(_safe_to_jsonable(row), ensure_ascii=False) + "\n")
            written += 1
            if written >= max_rows:
                break
    return written


def _write_map_style(full: Any, jsonl_path: Path, max_rows: int) -> int:
    n = min(len(full), max_rows)
    written = 0
    with jsonl_path.open("w", encoding="utf-8") as fh:
        for i in range(n):
            fh.write(json.dumps(_safe_to_jsonable(full[i]), ensure_ascii=False) + "\n")
            written += 1
    return written


def fetch_one(
    repo_id: str,
    *,
    out_dir: Path,
    max_rows: int,
    dry_run: bool = False,
    trust_remote_code: bool = False,
    config_name: Optional[str] = None,
) -> Dict[str, Any]:
    """Stream-download up to ``max_rows`` into out_dir as JSONL."""
    dest = out_dir / _slug(repo_id)
    dest.mkdir(parents=True, exist_ok=True)
    meta_path = dest / "fetch_meta.json"
    jsonl_path = dest / "train.sample.jsonl"

    envelope: Dict[str, Any] = {
        "ok": False,
        "id": repo_id,
        "path": str(dest),
        "max_rows": max_rows,
        "rows_written": 0,
        "dry_run": dry_run,
        "error": None,
        "config": config_name,
        "source": "huggingface.co",
        "model": "hf-dataset-fetch (streamed sample)",
    }

    if dry_run:
        envelope["ok"] = True
        envelope["would_write"] = str(jsonl_path)
        return envelope

    try:
        from datasets import load_dataset  # type: ignore
    except Exception as e:
        envelope["error"] = f"datasets package missing: {e}"
        return envelope

    t0 = time.time()
    configs_to_try: List[Optional[str]] = [config_name] if config_name else [None]
    last_err: Optional[BaseException] = None

    for cfg in configs_to_try:
        try:
            kwargs: Dict[str, Any] = {
                "path": repo_id,
                "split": "train",
                "streaming": True,
                "trust_remote_code": trust_remote_code,
            }
            if cfg:
                kwargs["name"] = cfg
            ds = load_dataset(**kwargs)
            written = _write_stream(ds, jsonl_path, max_rows)
            envelope.update({
                "ok": True,
                "rows_written": written,
                "split": "train",
                "streaming": True,
                "config": cfg,
                "seconds": round(time.time() - t0, 2),
            })
            meta_path.write_text(json.dumps(envelope, indent=2), encoding="utf-8")
            return envelope
        except Exception as e:
            last_err = e
            names = _parse_config_names(e)
            if names and not config_name:
                # Prefer vendor_identifiers / train-like configs first
                prefer = [
                    n for n in names
                    if any(k in n.lower() for k in (
                        "vendor", "train", "default", "main", "all",
                    ))
                ]
                ordered = prefer + [n for n in names if n not in prefer]
                for name in ordered:
                    try:
                        ds = load_dataset(
                            repo_id,
                            name,
                            split="train",
                            streaming=True,
                            trust_remote_code=trust_remote_code,
                        )
                        written = _write_stream(ds, jsonl_path, max_rows)
                        envelope.update({
                            "ok": True,
                            "rows_written": written,
                            "split": "train",
                            "streaming": True,
                            "config": name,
                            "seconds": round(time.time() - t0, 2),
                        })
                        meta_path.write_text(
                            json.dumps(envelope, indent=2), encoding="utf-8"
                        )
                        return envelope
                    except Exception as e_cfg:
                        last_err = e_cfg
                        continue
            break

    # Non-streaming fallback (default or discovered config)
    try:
        load_kwargs: Dict[str, Any] = {"path": repo_id, "trust_remote_code": trust_remote_code}
        if config_name:
            load_kwargs["name"] = config_name
        try:
            ds_dict = load_dataset(**load_kwargs)
        except Exception as e_cfg_missing:
            names = _parse_config_names(e_cfg_missing)
            if not names:
                raise
            name = names[0]
            ds_dict = load_dataset(
                repo_id, name, trust_remote_code=trust_remote_code,
            )
            envelope["config"] = name
        split = "train" if "train" in ds_dict else list(ds_dict.keys())[0]
        written = _write_map_style(ds_dict[split], jsonl_path, max_rows)
        envelope.update({
            "ok": True,
            "rows_written": written,
            "split": split,
            "streaming": False,
            "seconds": round(time.time() - t0, 2),
        })
    except Exception as e2:
        envelope["error"] = f"load failed: {e2}"
        if last_err is not None:
            envelope["first_error"] = str(last_err)

    meta_path.write_text(json.dumps(envelope, indent=2), encoding="utf-8")
    return envelope


def write_qlora_config(out_dir: Path, profile: HwProfile) -> Path:
    """Persist hardware-aware QLoRA defaults next to the datasets."""
    cfg = {
        "profile": asdict(profile),
        "serving_note": (
            "Serve adapters via Ollama GGUF where possible; 14B "
            "Qwen2.5-Coder stays Q4_K_M for inference, not full SFT."
        ),
        "recommended_train_stack": [
            "transformers",
            "peft",
            "bitsandbytes",
            "trl",
            "accelerate",
            "datasets",
        ],
        "qlora_example_flags": {
            "load_in_4bit": True,
            "bnb_4bit_compute_dtype": "bfloat16",
            "bnb_4bit_quant_type": "nf4",
            "bnb_4bit_use_double_quant": True,
            "target_modules": "all-linear",
            "optim": "paged_adamw_8bit",
        },
        "vram_fit_guidance": {
            "1B_fast": "fits easily; use for smoke + NPU-time accuracy loops",
            "3B-4B": "comfortable QLoRA on 12 GB, seq 2048 possible",
            "7B-9B": "QLoRA 4bit, bs=1, seq 1024-1536, grad_ckpt on",
            "14B": "prefer GGUF inference only; LoRA only if seq<=1024 and r<=8",
            "30B_MoE": "do not train locally; Ollama GGUF last-resort serve",
        },
        "npu_note": (
            "Acer Nitro 16s AI NPU is for OS/edge inference demos only; "
            "QLoRA training path stays on CUDA (RTX 5070 Ti)."
        ),
    }
    path = out_dir / "qlora_notebook_12gb.json"
    path.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    return path


def write_manifest(
    out_dir: Path,
    profile: HwProfile,
    results: List[Dict[str, Any]],
    curated: Sequence[Dict[str, Any]],
) -> Path:
    by_id = {c["id"]: c for c in curated}
    rows = []
    for r in results:
        c = by_id.get(r["id"], {})
        rows.append({
            **r,
            "domain": c.get("domain"),
            "goal": c.get("goal"),
            "priority": c.get("priority"),
            "size_class": c.get("size_class"),
        })
    manifest = {
        "created_unix": int(time.time()),
        "profile": profile.name,
        "out_dir": str(out_dir),
        "registry": str(REGISTRY_PATH),
        "results": rows,
        "ok_count": sum(1 for r in results if r.get("ok")),
        "fail_count": sum(1 for r in results if not r.get("ok")),
        "total_rows": sum(int(r.get("rows_written") or 0) for r in results),
    }
    path = out_dir / "manifest.json"
    path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return path


def select_curated(
    *,
    domains: Optional[Sequence[str]] = None,
    only_ids: Optional[Sequence[str]] = None,
    priority_max: int = 2,
    include_all: bool = False,
) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    domain_set = {d.lower() for d in domains} if domains else None
    only_set = set(only_ids) if only_ids else None
    for c in CURATED:
        if only_set and c["id"] not in only_set:
            continue
        if domain_set and c["domain"].lower() not in domain_set:
            continue
        if not include_all and c["priority"] > priority_max:
            continue
        out.append(c)
    return out


def main(argv: Optional[Sequence[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        description="Fetch HF datasets for KFIOSA LoRA/QLoRA (12 GB notebook profile)",
    )
    ap.add_argument(
        "--profile",
        default="notebook_12gb",
        choices=sorted(PROFILES.keys()),
        help="Hardware profile (default: notebook_12gb for RTX 5070 Ti 12 GB)",
    )
    ap.add_argument(
        "--out",
        type=Path,
        default=DEFAULT_OUT,
        help=f"Output directory (default: {DEFAULT_OUT})",
    )
    ap.add_argument(
        "--domains",
        type=str,
        default="",
        help="Comma list: wifi,ble,osint,post_exploitation,uncensored_base",
    )
    ap.add_argument(
        "--only",
        type=str,
        default="",
        help="Comma list of exact HF repo ids to fetch",
    )
    ap.add_argument(
        "--max-rows",
        type=int,
        default=0,
        help="Override per-dataset row cap (0 = use profile size_class budget)",
    )
    ap.add_argument(
        "--priority-max",
        type=int,
        default=2,
        help="Include curated entries with priority <= N (1=core, 2=+optional, 3=+large)",
    )
    ap.add_argument(
        "--all",
        action="store_true",
        help="Include priority-3 large corpora (still sample-capped)",
    )
    ap.add_argument("--list", action="store_true", help="List curated plan and exit")
    ap.add_argument("--dry-run", action="store_true", help="Plan only, no network writes")
    ap.add_argument(
        "--update-registry-defaults",
        action="store_true",
        help="Rewrite pentest_hf_registry.json defaults for 12 GB notebook QLoRA",
    )
    args = ap.parse_args(list(argv) if argv is not None else None)

    profile = PROFILES[args.profile]
    domains = [d.strip() for d in args.domains.split(",") if d.strip()] or None
    only = [x.strip() for x in args.only.split(",") if x.strip()] or None
    curated = select_curated(
        domains=domains,
        only_ids=only,
        priority_max=3 if args.all else args.priority_max,
        include_all=args.all,
    )

    if args.list:
        print(json.dumps({
            "profile": asdict(profile),
            "n": len(curated),
            "items": curated,
        }, indent=2))
        return 0

    if args.update_registry_defaults:
        reg = _load_registry()
        reg["defaults"] = {
            "base_model": profile.base_model,
            "base_model_small": profile.base_model_fast,
            "base_model_code": (
                "roleplaiapp/Qwen2.5-Coder-14B-Instruct-Uncensored-Q4_K_M-GGUF"
            ),
            "lora_r": profile.lora_r,
            "lora_alpha": profile.lora_alpha,
            "lora_dropout": profile.lora_dropout,
            "learning_rate": profile.learning_rate,
            "epochs": profile.epochs,
            "batch_size": profile.batch_size,
            "grad_accum": profile.grad_accum,
            "max_seq_length": profile.max_seq_length,
            "use_4bit": profile.use_4bit,
            "gradient_checkpointing": profile.gradient_checkpointing,
            "hardware_profile": profile.name,
            "vram_gb": profile.vram_gb,
            "ram_gb": profile.ram_gb,
            "notes": profile.notes,
        }
        REGISTRY_PATH.write_text(json.dumps(reg, indent=2) + "\n", encoding="utf-8")
        print(f"updated registry defaults → {REGISTRY_PATH}")

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    cfg_path = write_qlora_config(out_dir, profile)
    print(f"qlora config → {cfg_path}")

    results: List[Dict[str, Any]] = []
    for c in curated:
        budget = args.max_rows or _row_budget(profile, c.get("size_class", "medium"))
        print(f"fetch {c['id']}  domain={c['domain']}  max_rows={budget} ...")
        r = fetch_one(
            c["id"],
            out_dir=out_dir,
            max_rows=budget,
            dry_run=args.dry_run,
            config_name=c.get("config"),
        )
        results.append(r)
        status = "OK" if r.get("ok") else "FAIL"
        print(
            f"  {status}  rows={r.get('rows_written')}  "
            f"err={r.get('error')}"
        )

    man = write_manifest(out_dir, profile, results, curated)
    print(f"manifest → {man}")
    ok = sum(1 for r in results if r.get("ok"))
    fail = len(results) - ok
    total_rows = sum(int(r.get("rows_written") or 0) for r in results)
    print(json.dumps({
        "ok": fail == 0,
        "fetched_ok": ok,
        "fetched_fail": fail,
        "total_rows": total_rows,
        "out": str(out_dir),
        "profile": profile.name,
    }, indent=2))
    return 0 if fail == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
