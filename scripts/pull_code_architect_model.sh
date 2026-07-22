#!/usr/bin/env bash
# scripts/pull_code_architect_model.sh
# Pull the operator-preferred uncensored code-architect model for the
# NVD-keyed CVE -> exploit generation pipeline. This model is selected
# by ExploitGenModelManager (core.ai_backend.exploit_generator) and
# is also the default entry in pentest_hf_registry.json defaults.base_model.
#
# Hardware profile (operator's Acer Nitro 16S AI):
#   - RTX 5070 Ti 12GB
#   - 32GB system RAM
#   - Recommendation: load the ~9B Q4_K_M hybrid GPU+CPU (not pure-GPU);
#     the model fits the 12GB VRAM with offloaded layers.
#
# Usage:
#   ./scripts/pull_code_architect_model.sh                # default model
#   MODEL=... ./scripts/pull_code_architect_model.sh     # override
#
# Refusal stance:
#   - The pipeline that uses this model is AI-driven CVE -> exploit
#     generation, gated by the per-step ACCEPT/CANCEL prompt in the
#     orchestrator (default-deny 300s).
#   - The model NEVER auto-executes its own output. The orchestrator
#     treats the output as a draft only; the post-exploitation that
#     uses the draft is itself a separate gated step.
#   - Output is logged in the chain report under report["exploits"]
#     and surfaced in the dashboard's "EXPLOIT" status pill.
set -euo pipefail

# Default: the curated uncensored code-architect for the operator's
# hardware (12GB VRAM + 32GB RAM, hybrid load).
#
# The bare ``DavidAU/Qwen3.5-9B-...-HERETIC-UNCENSORED`` repo on HF
# is safetensors-only (NOT GGUF-compatible) — ollama pull fails with
# "Repository is not GGUF". The mradermacher redistribution is a
# GGUF pack (21,980 downloads, same base model, apache-2.0).
MODEL="${MODEL:-hf.co/mradermacher/Qwen3.5-9B-Claude-4.6-HighIQ-THINKING-HERETIC-UNCENSORED-GGUF}"

echo "[*] Pulling uncensored code-architect model: ${MODEL}"
echo "    (12GB VRAM + 32GB RAM; hybrid GPU+CPU load recommended)"
echo ""

# Use the ollama binary; ollama understands the hf.co/<org>/<repo>[:tag] syntax.
if ! command -v ollama >/dev/null 2>&1; then
  echo "[!] ollama not on PATH. Install it: https://ollama.com/download" >&2
  exit 1
fi

ollama pull "${MODEL}"

echo ""
echo "[+] Done. The model is now available to the CVE -> exploit pipeline."
echo "    Confirm via: ollama list | grep ${MODEL}"
