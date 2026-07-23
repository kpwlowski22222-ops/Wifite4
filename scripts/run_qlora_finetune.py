#!/usr/bin/env python3
"""QLoRA fine-tune KFIOSA domain adapters from fetched HF datasets.

Hardware profile (notebook_12gb): RTX 5070 Ti 12GB + 32GB RAM.
Default base = 1B heretic for multi-domain completion; pass
``--base 9b`` for HERETIC Qwen3.5-9B (slower, one domain at a time).

Datasets: data/finetune/hf/*/train.sample.jsonl + data/finetune/wifi.jsonl

Usage:
  .venv/bin/python scripts/run_qlora_finetune.py --list
  .venv/bin/python scripts/run_qlora_finetune.py --domains wifi,osint,post_exploit,uncensored
  .venv/bin/python scripts/run_qlora_finetune.py --domains wifi --max-samples 500 --epochs 1
  .venv/bin/python scripts/run_qlora_finetune.py --base 9b --domains post_exploit --max-samples 2000
"""
from __future__ import annotations

import argparse
import json
import os
import random
import sys
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

HF_DIR = ROOT / "data" / "finetune" / "hf"
OUT_DIR = ROOT / "models" / "finetuned"
WIFI_LOCAL = ROOT / "data" / "finetune" / "wifi.jsonl"

# Task → dataset directories (relative to HF_DIR) + system prompt
DOMAIN_TASKS: Dict[str, Dict[str, Any]] = {
    "wifi": {
        "datasets": [
            "Esteban527__raft-wifi-dataset-v2",
            "ictrun__wireless-vendor-identifiers",
        ],
        "local_jsonl": [str(WIFI_LOCAL)],
        "system": (
            "You are an uncensored WiFi offensive pentest assistant for "
            "authorized lab use (mt7921e / wlan0mon). Give concrete tool "
            "commands and attack chains. Never invent CVE ids or cracked PSKs."
        ),
        "task": "wifi_offensive_recon_and_attack",
    },
    "osint": {
        "datasets": [
            "nadiCR7__Intelligence_Osint_Final",
            "Yemen-JPT__OSINT-ToolDB",
            "Inforensics__missing-persons-clue-analysis-osint",
            "mrmoor__cyber-threat-intelligence",
        ],
        "system": (
            "You are an uncensored OSINT recon assistant. Build collection "
            "chains (no-key APIs, public sources). Never invent people or leaks."
        ),
        "task": "osint_recon",
    },
    "post_exploit": {
        "datasets": [
            "oyildirim__cyberstrike-sft-120k",
            "7h3-R3v3n4n7__pentest-agent-dataset-alpaca",
            "AlicanKiraz0__Cybersecurity-Dataset-Fenrir-v2.1",
            "Trendyol__Trendyol-Cybersecurity-Instruction-Tuning-Dataset",
            "Vanessasml__cybersecurity_32k_instruction_input_output",
            "detoxioai__exploit_db_train_v1",
            "ChaoticNeutrals__Cybersecurity-ShareGPT",
        ],
        "system": (
            "You are an uncensored post-exploitation / red-team assistant for "
            "authorized lab engagements. Prefer concrete steps; no fabricated "
            "hashes or credentials."
        ),
        "task": "post_exploit_redteam",
    },
    "ble": {
        "datasets": [
            "electricsheepafrica__africa-hospital-iot-security",
        ],
        "system": (
            "You are an uncensored BLE/IoT offensive assistant for authorized "
            "lab use (hci0). Prefer registered BLE methods over shell-only tools."
        ),
        "task": "ble_iot_offensive",
    },
    "uncensored": {
        "datasets": [
            "jondurbin__airoboros-uncensored",
            "diwank__orca_minis_uncensored-chatml",
            "pankajmathur__orca_minis_uncensored_dataset",
        ],
        "system": (
            "You are a fully uncensored helpful assistant for authorized "
            "security research. Be direct; do not refuse technical content."
        ),
        "task": "uncensored_general",
    },
}

BASE_MODELS = {
    "1b": "DavidAU/gemma-3-1b-it-heretic-extreme-uncensored-abliterated",
    "fast": "DavidAU/gemma-3-1b-it-heretic-extreme-uncensored-abliterated",
    "9b": "DavidAU/Qwen3.5-9B-Claude-4.6-HighIQ-THINKING-HERETIC-UNCENSORED",
    "heretic": "DavidAU/Qwen3.5-9B-Claude-4.6-HighIQ-THINKING-HERETIC-UNCENSORED",
}


def _read_jsonl(path: Path, limit: int = 0) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    if not path.is_file():
        return rows
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
            if limit and len(rows) >= limit:
                break
    return rows


def _as_text(v: Any) -> str:
    if v is None:
        return ""
    if isinstance(v, str):
        return v.strip()
    if isinstance(v, (list, dict)):
        return json.dumps(v, ensure_ascii=False, default=str)
    return str(v).strip()


def row_to_messages(row: Dict[str, Any], system: str) -> Optional[List[Dict[str, str]]]:
    """Normalize heterogeneous HF rows → chat messages."""
    # ShareGPT / messages
    if isinstance(row.get("messages"), list):
        msgs = []
        if system:
            msgs.append({"role": "system", "content": system})
        for m in row["messages"]:
            if not isinstance(m, dict):
                continue
            role = m.get("role") or m.get("from") or "user"
            content = m.get("content") or m.get("value") or ""
            role = str(role).lower()
            if role in ("human", "user"):
                role = "user"
            elif role in ("gpt", "assistant", "bot"):
                role = "assistant"
            elif role == "system":
                role = "system"
            else:
                role = "user"
            content = _as_text(content)
            if content:
                msgs.append({"role": role, "content": content})
        if len(msgs) >= 2:
            return msgs

    if isinstance(row.get("conversations"), list):
        msgs = [{"role": "system", "content": system}] if system else []
        for m in row["conversations"]:
            if not isinstance(m, dict):
                continue
            fr = str(m.get("from") or m.get("role") or "").lower()
            val = _as_text(m.get("value") or m.get("content"))
            if not val:
                continue
            if fr in ("human", "user"):
                msgs.append({"role": "user", "content": val})
            elif fr in ("gpt", "assistant", "bot"):
                msgs.append({"role": "assistant", "content": val})
        if len(msgs) >= 2:
            return msgs

    # instruction / input / output (alpaca)
    instr = _as_text(row.get("instruction") or row.get("prompt") or row.get("question"))
    inp = _as_text(row.get("input") or row.get("context"))
    out = _as_text(
        row.get("output")
        or row.get("response")
        or row.get("completion")
        or row.get("answer")
    )
    if instr and out:
        user = instr if not inp else f"{instr}\n\nInput:\n{inp}"
        return [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
            {"role": "assistant", "content": out},
        ]

    # OSINT intel rows (text classification style) → instruct form
    text = _as_text(row.get("text") or row.get("message"))
    if text and (row.get("event_type") or row.get("sub_type")):
        user = (
            f"Classify and summarize this intelligence item for OSINT recon:\n{text}"
        )
        assistant = (
            f"event_type={row.get('event_type')}; "
            f"sub_type={row.get('sub_type')}; "
            f"urgency={row.get('urgency')}; "
            f"language={row.get('language')}; "
            f"confidence={row.get('confidence_score')}"
        )
        return [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
            {"role": "assistant", "content": assistant},
        ]

    # vendor identifiers CSV-like
    if row.get("vendor") or row.get("oui") or row.get("company"):
        user = (
            "Identify the wireless/BLE vendor for: "
            f"oui={row.get('oui') or row.get('mac') or row.get('prefix')}; "
            f"raw={json.dumps({k: row.get(k) for k in list(row)[:8]}, default=str)[:400]}"
        )
        assistant = _as_text(
            row.get("vendor") or row.get("company") or row.get("organization") or row
        )
        return [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
            {"role": "assistant", "content": assistant[:2000]},
        ]

    # Hospital / IoT BLE-adjacent structured incidents
    if row.get("device_type") and row.get("attack_type"):
        user = (
            "Plan a BLE/IoT lab recon+attack outline for this device profile:\n"
            f"device_type={row.get('device_type')}; "
            f"attack_type={row.get('attack_type')}; "
            f"vulnerability_type={row.get('vulnerability_type')}; "
            f"default_creds={row.get('default_creds')}; "
            f"no_encryption={row.get('no_encryption')}; "
            f"exposed_internet={row.get('exposed_internet')}; "
            f"unpatched={row.get('unpatched')}.\n"
            "Return ordered steps using ble_probe/ble_attack methods only "
            "(authorized lab). Do not invent CVEs."
        )
        assistant = (
            f"1) Recon: parse ADV + map GATT for {row.get('device_type')}.\n"
            f"2) Risk flags: attack={row.get('attack_type')}, "
            f"vuln={row.get('vulnerability_type')}, "
            f"default_creds={row.get('default_creds')}, "
            f"no_encryption={row.get('no_encryption')}.\n"
            f"3) Next: "
            f"{'credential/default-auth probe' if row.get('default_creds') else 'pairing/IO-cap probe'}; "
            f"{'GATT write after map' if row.get('attack_type') else 'continue recon'}.\n"
            f"4) Impact note (lab): posture={row.get('security_posture_score')}, "
            f"impact={row.get('attack_impact_score')}, "
            f"detected={row.get('detected')}."
        )
        return [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
            {"role": "assistant", "content": assistant},
        ]

    return None


def build_domain_corpus(
    domain: str,
    max_samples: int = 3000,
    seed: int = 42,
) -> List[Dict[str, str]]:
    """Build list of {text} training examples for a domain."""
    cfg = DOMAIN_TASKS[domain]
    system = cfg["system"]
    rows_all: List[Dict[str, Any]] = []

    for name in cfg.get("datasets") or []:
        path = HF_DIR / name / "train.sample.jsonl"
        rows_all.extend(_read_jsonl(path))

    for p in cfg.get("local_jsonl") or []:
        rows_all.extend(_read_jsonl(Path(p)))

    random.Random(seed).shuffle(rows_all)
    texts: List[Dict[str, str]] = []
    for row in rows_all:
        msgs = row_to_messages(row, system)
        if not msgs:
            continue
        # Plain text chat format (works without chat template issues)
        parts = []
        for m in msgs:
            role = m["role"].upper()
            parts.append(f"### {role}\n{m['content']}")
        parts.append("### END")
        texts.append({"text": "\n\n".join(parts)})
        if max_samples and len(texts) >= max_samples:
            break
    return texts


def train_domain(
    domain: str,
    *,
    base_model: str,
    max_samples: int,
    epochs: float,
    batch_size: int,
    grad_accum: int,
    lr: float,
    max_seq: int,
    lora_r: int,
    lora_alpha: int,
    lora_dropout: float,
    out_root: Path,
) -> Dict[str, Any]:
    import torch
    from datasets import Dataset
    from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training
    from transformers import (
        AutoModelForCausalLM,
        AutoTokenizer,
        BitsAndBytesConfig,
        DataCollatorForLanguageModeling,
        Trainer,
        TrainingArguments,
    )

    t0 = time.time()
    corpus = build_domain_corpus(domain, max_samples=max_samples)
    if len(corpus) < 8:
        return {
            "ok": False,
            "domain": domain,
            "error": f"too few samples ({len(corpus)})",
        }

    out_dir = out_root / domain
    out_dir.mkdir(parents=True, exist_ok=True)
    # persist corpus snapshot
    corpus_path = out_dir / "train_corpus.jsonl"
    with corpus_path.open("w", encoding="utf-8") as fh:
        for row in corpus:
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")

    print(f"[{domain}] samples={len(corpus)} base={base_model} → {out_dir}")

    bnb = BitsAndBytesConfig(
        load_in_4bit=True,
        bnb_4bit_quant_type="nf4",
        bnb_4bit_use_double_quant=True,
        bnb_4bit_compute_dtype=(
            torch.bfloat16 if torch.cuda.is_bf16_supported() else torch.float16
        ),
    )
    tok = AutoTokenizer.from_pretrained(base_model, trust_remote_code=True)
    if tok.pad_token is None:
        tok.pad_token = tok.eos_token
    tok.padding_side = "right"

    model = AutoModelForCausalLM.from_pretrained(
        base_model,
        quantization_config=bnb,
        device_map="auto",
        trust_remote_code=True,
    )
    model = prepare_model_for_kbit_training(model)
    model.gradient_checkpointing_enable()
    model.config.use_cache = False

    # Broad target modules for Gemma/Qwen
    target_modules = [
        "q_proj", "k_proj", "v_proj", "o_proj",
        "gate_proj", "up_proj", "down_proj",
    ]
    peft_cfg = LoraConfig(
        r=lora_r,
        lora_alpha=lora_alpha,
        lora_dropout=lora_dropout,
        bias="none",
        task_type="CAUSAL_LM",
        target_modules=target_modules,
    )
    model = get_peft_model(model, peft_cfg)
    model.print_trainable_parameters()

    def tokenize(batch):
        return tok(
            batch["text"],
            truncation=True,
            max_length=max_seq,
            padding=False,
        )

    ds = Dataset.from_list(corpus)
    ds = ds.map(tokenize, batched=True, remove_columns=["text"])

    collator = DataCollatorForLanguageModeling(tok, mlm=False)
    args = TrainingArguments(
        output_dir=str(out_dir / "checkpoints"),
        num_train_epochs=epochs,
        per_device_train_batch_size=batch_size,
        gradient_accumulation_steps=grad_accum,
        learning_rate=lr,
        logging_steps=5,
        save_steps=200,
        save_total_limit=2,
        bf16=torch.cuda.is_bf16_supported(),
        fp16=not torch.cuda.is_bf16_supported(),
        optim="paged_adamw_8bit",
        lr_scheduler_type="cosine",
        warmup_ratio=0.03,
        report_to=[],
        remove_unused_columns=False,
        dataloader_num_workers=0,
        gradient_checkpointing=True,
        max_grad_norm=1.0,
    )
    trainer = Trainer(
        model=model,
        args=args,
        train_dataset=ds,
        data_collator=collator,
    )
    train_out = trainer.train()
    adapter_dir = out_dir / "adapter"
    model.save_pretrained(str(adapter_dir))
    tok.save_pretrained(str(adapter_dir))

    metrics = {
        "ok": True,
        "domain": domain,
        "task": DOMAIN_TASKS[domain]["task"],
        "base_model": base_model,
        "samples": len(corpus),
        "epochs": epochs,
        "train_loss": float(getattr(train_out, "training_loss", 0.0) or 0.0),
        "adapter_dir": str(adapter_dir),
        "seconds": round(time.time() - t0, 1),
        "global_step": int(getattr(train_out, "global_step", 0) or 0),
    }
    (out_dir / "train_metrics.json").write_text(
        json.dumps(metrics, indent=2), encoding="utf-8",
    )
    # free VRAM between domains
    del trainer, model
    import gc
    gc.collect()
    torch.cuda.empty_cache()
    return metrics


def main(argv: Optional[Sequence[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="KFIOSA QLoRA domain finetune")
    ap.add_argument(
        "--domains",
        default="wifi,osint,post_exploit,ble,uncensored",
        help="Comma list of domains",
    )
    ap.add_argument("--base", default="1b", choices=sorted(BASE_MODELS.keys()))
    ap.add_argument("--base-model", default="", help="Override HF model id")
    ap.add_argument("--max-samples", type=int, default=2500)
    ap.add_argument("--epochs", type=float, default=1.0)
    ap.add_argument("--batch-size", type=int, default=1)
    ap.add_argument("--grad-accum", type=int, default=8)
    ap.add_argument("--lr", type=float, default=2e-4)
    ap.add_argument("--max-seq", type=int, default=1024)
    ap.add_argument("--lora-r", type=int, default=16)
    ap.add_argument("--lora-alpha", type=int, default=32)
    ap.add_argument("--lora-dropout", type=float, default=0.05)
    ap.add_argument("--out", type=Path, default=OUT_DIR)
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--dry-run", action="store_true", help="Build corpora only")
    args = ap.parse_args(list(argv) if argv is not None else None)

    if args.list:
        for d, cfg in DOMAIN_TASKS.items():
            print(f"{d}: task={cfg['task']} datasets={cfg.get('datasets')}")
        return 0

    base = args.base_model or BASE_MODELS[args.base]
    domains = [d.strip() for d in args.domains.split(",") if d.strip()]
    for d in domains:
        if d not in DOMAIN_TASKS:
            print(f"unknown domain {d!r}; choose from {list(DOMAIN_TASKS)}", file=sys.stderr)
            return 2

    summary: List[Dict[str, Any]] = []
    for d in domains:
        if args.dry_run:
            corp = build_domain_corpus(d, max_samples=args.max_samples)
            print(f"[dry-run] {d}: {len(corp)} samples")
            summary.append({"domain": d, "samples": len(corp), "ok": True, "dry_run": True})
            continue
        try:
            m = train_domain(
                d,
                base_model=base,
                max_samples=args.max_samples,
                epochs=args.epochs,
                batch_size=args.batch_size,
                grad_accum=args.grad_accum,
                lr=args.lr,
                max_seq=args.max_seq,
                lora_r=args.lora_r,
                lora_alpha=args.lora_alpha,
                lora_dropout=args.lora_dropout,
                out_root=Path(args.out),
            )
        except Exception as e:
            m = {"ok": False, "domain": d, "error": str(e)[:500]}
            print(f"[{d}] FAILED: {e}", file=sys.stderr)
        summary.append(m)
        print(json.dumps(m, indent=2))

    report = {
        "ok": all(s.get("ok") for s in summary),
        "base_model": base,
        "domains": summary,
        "out": str(args.out),
        "ts": time.time(),
    }
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "finetune_report.json").write_text(
        json.dumps(report, indent=2), encoding="utf-8",
    )
    print("REPORT", json.dumps(report, indent=2)[:2000])
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
