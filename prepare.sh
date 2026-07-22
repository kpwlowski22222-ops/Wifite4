#!/usr/bin/env bash
# prepare.sh — Robust, idempotent Kali Linux setup for kfiosa
# Installs deps, Ollama, models, dataset structure, and fine-tune helper.
# Safe to re-run end-to-end.

set -euo pipefail

# -----------------------------------------------------------------------------
# Color logging
# -----------------------------------------------------------------------------
if [[ -t 1 ]]; then
    CLR_RED=$'\033[0;31m'
    CLR_GREEN=$'\033[0;32m'
    CLR_YELLOW=$'\033[0;33m'
    CLR_BLUE=$'\033[0;34m'
    CLR_MAGENTA=$'\033[0;35m'
    CLR_CYAN=$'\033[0;36m'
    CLR_BOLD=$'\033[1m'
    CLR_RESET=$'\033[0m'
else
    CLR_RED=""
    CLR_GREEN=""
    CLR_YELLOW=""
    CLR_BLUE=""
    CLR_MAGENTA=""
    CLR_CYAN=""
    CLR_BOLD=""
    CLR_RESET=""
fi

log_info()  { printf '%s[INFO]%s %s\n' "${CLR_BLUE}"   "${CLR_RESET}" "$*"; }
log_ok()    { printf '%s[ OK ]%s %s\n' "${CLR_GREEN}"  "${CLR_RESET}" "$*"; }
log_warn()  { printf '%s[WARN]%s %s\n' "${CLR_YELLOW}" "${CLR_RESET}" "$*"; }
log_error() { printf '%s[ERR ]%s %s\n' "${CLR_RED}"    "${CLR_RESET}" "$*"; }
log_step()  { printf '%s[STEP]%s %s\n' "${CLR_CYAN}"   "${CLR_RESET}" "$*"; }

banner() {
    local msg="$1"
    local bar
    bar=$(printf '%*s' "${#msg}" '' | tr ' ' '=')
    printf '\n%s%s\n%s\n%s%s\n' "${CLR_BOLD}" "${bar}" "${msg}" "${bar}" "${CLR_RESET}"
}

# -----------------------------------------------------------------------------
# Root check
# -----------------------------------------------------------------------------
require_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (it manages apt, systemd, and /etc)."
        log_error "Try: sudo ./prepare.sh"
        exit 1
    fi
}
require_root

# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------
pkg_installed() { dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q "install ok installed"; }

# Resolve workspace dir relative to this script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_DIR="${SCRIPT_DIR}/workspace"

# =============================================================================
banner "STEP 1: Install apt dependencies"
# =============================================================================
DEPS=(aircrack-ng reaver bully hashcat iproute2 iw pciutils curl jq python3 python3-pip python3-venv python3-dev hcxdumptool hcxtools mdk4 upower)

log_info "Running apt-get update ..."
apt-get update -y

missing=()
for dep in "${DEPS[@]}"; do
    if pkg_installed "$dep"; then
        log_ok "${dep} already installed"
    else
        missing+=("$dep")
    fi
done

if [[ ${#missing[@]} -gt 0 ]]; then
    log_info "Installing missing packages: ${missing[*]}"
    DEBIAN_FRONTEND=noninteractive apt-get install -y "${missing[@]}"
else
    log_ok "All required apt packages already installed"
fi

# Spot-check commands on PATH (some packages provide differently-named binaries)
for dep in "${DEPS[@]}"; do
    if ! command -v "$dep" >/dev/null 2>&1; then
        case "$dep" in
            iproute2) command -v ip     >/dev/null 2>&1 || log_warn "iproute2: 'ip' not on PATH" ;;
            pciutils) command -v lspci >/dev/null 2>&1 || log_warn "pciutils: 'lspci' not on PATH" ;;
            *)        log_warn "${dep} installed but not found on PATH" ;;
        esac
    fi
done

log_ok "Step 1 complete"

# =============================================================================
banner "STEP 2: Install Ollama"
# =============================================================================
if command -v ollama >/dev/null 2>&1; then
    log_ok "Ollama already on PATH — skipping install"
else
    log_info "Installing Ollama via official install script ..."
    curl -fsSL https://ollama.com/install.sh | sh
    # Ensure on PATH for this session if installed somewhere unusual
    if ! command -v ollama >/dev/null 2>&1; then
        for cand in /usr/local/bin/ollama /usr/bin/ollama "${HOME}/.ollama/bin/ollama"; do
            if [[ -x "$cand" ]]; then
                export PATH="$PATH:$(dirname "$cand")"
                break
            fi
        done
    fi
    if command -v ollama >/dev/null 2>&1; then
        log_ok "Ollama installed: $(ollama --version 2>/dev/null || echo 'version unknown')"
    else
        log_error "Ollama install failed or not on PATH"
        exit 1
    fi
fi

log_ok "Step 2 complete"

# =============================================================================
banner "STEP 3: Configure Ollama networking — loopback-only (non-destructive)"
# =============================================================================
# The dashboard proxies sudo/airodump/hashcat through the Express server and
# talks to Ollama over loopback. Binding Ollama to 127.0.0.1 keeps it (and the
# models it serves) off the LAN — it must never be reachable from other hosts.
#
# NON-DESTRUCTIVE: if an operator has already configured a secure bind (any
# OLLAMA_HOST that is NOT 0.0.0.0 — e.g. a WireGuard IP like 10.10.0.1, or an
# existing 127.0.0.1), we PRESERVE it. We only enforce 127.0.0.1 when the
# current bind is 0.0.0.0 (LAN-reachable) or absent. Never clobber an
# operator-authorized security-critical override.
OVERRIDE_DIR="/etc/systemd/system/ollama.service.d"
OVERRIDE_CONF="${OVERRIDE_DIR}/override.conf"

log_info "Ensuring override directory: ${OVERRIDE_DIR}"
mkdir -p "$OVERRIDE_DIR"

# Discover the effective OLLAMA_HOST across the systemd unit + drop-ins.
CURRENT_HOST="$(systemctl show ollama -p Environment 2>/dev/null | grep -oE 'OLLAMA_HOST=[^ ]]+' | cut -d= -f2 || true)"
log_info "Effective OLLAMA_HOST: ${CURRENT_HOST:-(unset)}"

DESIRED_OVERRIDE='[Service]
Environment="OLLAMA_HOST=127.0.0.1:11434"
Environment="OLLAMA_ORIGINS=127.0.0.1,localhost"
'

NEED_WRITE=1
if [[ -f "$OVERRIDE_CONF" ]]; then
    CURRENT=$(cat "$OVERRIDE_CONF" 2>/dev/null || true)
    if [[ "$CURRENT" == "$DESIRED_OVERRIDE" ]]; then
        NEED_WRITE=0
        log_ok "${OVERRIDE_CONF} already correct (127.0.0.1)"
    elif [[ "$CURRENT_HOST" == 0.0.0.0* ]]; then
        log_warn "${OVERRIDE_CONF} binds 0.0.0.0 (LAN-reachable) — replacing with 127.0.0.1"
        NEED_WRITE=1
    else
        # Existing bind is already non-0.0.0.0 (loopback or VPN IP): preserve it.
        NEED_WRITE=0
        log_ok "Existing OLLAMA_HOST='${CURRENT_HOST}' is already non-0.0.0.0 — preserving operator override"
    fi
elif [[ -z "$CURRENT_HOST" || "$CURRENT_HOST" == 0.0.0.0* ]]; then
    log_info "No secure override present (host=${CURRENT_HOST:-unset}) — writing 127.0.0.1 bind"
    NEED_WRITE=1
else
    log_ok "Ollama already bound to '${CURRENT_HOST}' (non-0.0.0.0) — no override file needed"
    NEED_WRITE=0
fi
if [[ $NEED_WRITE -eq 1 ]]; then
    printf '%s' "$DESIRED_OVERRIDE" > "$OVERRIDE_CONF"
    log_ok "Wrote ${OVERRIDE_CONF} (127.0.0.1 only)"
fi

log_info "systemctl daemon-reload"
systemctl daemon-reload

log_info "systemctl enable --now ollama"
systemctl enable --now ollama || {
    log_warn "systemctl enable --now ollama returned non-zero; attempting restart"
    systemctl restart ollama || true
}

# Defense-in-depth: if ufw is active, deny 11434 from the outside explicitly.
# (The 127.0.0.1 bind already prevents binding on LAN interfaces; this is a
# documented fallback for hosts where the systemd override may be reverted.)
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
    ufw deny 11434/tcp 2>/dev/null || true
    log_ok "ufw: denied 11434/tcp from external hosts (loopback still allowed)"
else
    log_info "ufw not active — relying on 127.0.0.1 bind alone"
fi

log_info "Waiting for Ollama API on port 11434 (up to ~30s) ..."
API_READY=0
for _ in $(seq 1 30); do
    if curl -sf http://localhost:11434/api/tags >/dev/null 2>&1; then
        API_READY=1
        break
    fi
    sleep 1
done
if [[ $API_READY -eq 1 ]]; then
    log_ok "Ollama API responding on http://localhost:11434"
else
    log_warn "Ollama API not responding yet on :11434 — it may still be starting."
    log_warn "Check: systemctl status ollama  /  journalctl -u ollama -n 50"
fi

log_ok "Step 3 complete"

# =============================================================================
banner "STEP 4: Pull Ollama models (llama3, mistral)"
# =============================================================================
MODELS_WANT=(llama3 mistral)

INSTALLED_MODELS=$(ollama list 2>/dev/null | awk 'NR>1 {print $1}' || true)

for model in "${MODELS_WANT[@]}"; do
    # 'ollama list' prints names with a :tag suffix (e.g. llama3:latest), so match the
    # base name as a prefix followed by ':' or end-of-line.
    if printf '%s\n' "$INSTALLED_MODELS" | grep -Eq "^${model}(:|\$)"; then
        log_ok "Model '${model}' already present — skipping pull"
    else
        log_info "Pulling model '${model}' ..."
        ollama pull "$model"
        log_ok "Pulled model '${model}'"
    fi
done

log_ok "Step 4 complete"

# =============================================================================
banner "STEP 5: Create dataset/workspace directory structure"
# =============================================================================
DIRS=(
    "${WORKSPACE_DIR}/dataset/raw"
    "${WORKSPACE_DIR}/dataset/processed"
    "${WORKSPACE_DIR}/dataset/checkpoints"
    "${WORKSPACE_DIR}/models"
    "${WORKSPACE_DIR}/output"
    "${WORKSPACE_DIR}/finetune"
    "${WORKSPACE_DIR}/captures"
)

for d in "${DIRS[@]}"; do
    if [[ -d "$d" ]]; then
        log_ok "Dir exists: ${d}"
    else
        mkdir -p "$d"
        log_ok "Created:   ${d}"
    fi
done

log_ok "Step 5 complete"

# =============================================================================
banner "STEP 6: Initialize finetune_status.json"
# =============================================================================
# Default status reflects the real Unsloth/QLoRA run (1 epoch, 60 steps) written
# by workspace/train.py. The old simulated script wrote totalEpochs=3; we keep
# the file idempotent and only seed it when absent/different.
STATUS_FILE="${WORKSPACE_DIR}/finetune_status.json"
DESIRED_STATUS='{"active":false,"status":"idle","epoch":0,"totalEpochs":1,"totalSteps":60,"step":0,"loss":0,"progress":0,"model":"unsloth/llama-3-8b-Instruct","gpuMemMib":0,"logs":[]}'

NEED_WRITE=1
if [[ -f "$STATUS_FILE" ]]; then
    CURRENT=$(cat "$STATUS_FILE" 2>/dev/null || true)
    if [[ "$CURRENT" == "$DESIRED_STATUS" ]]; then
        NEED_WRITE=0
        log_ok "${STATUS_FILE} already initialized"
    else
        log_warn "${STATUS_FILE} exists with different content — leaving as-is"
        NEED_WRITE=0
    fi
fi
if [[ $NEED_WRITE -eq 1 ]]; then
    printf '%s\n' "$DESIRED_STATUS" > "$STATUS_FILE"
    log_ok "Wrote ${STATUS_FILE}"
fi

log_ok "Step 6 complete"

# =============================================================================
banner "STEP 7A: GPU probe + Python venv for the real fine-tune"
# =============================================================================
# Probe the Blackwell GPU, then build the workspace venv with the ML stack
# (cu128 torch for sm_120, bitsandbytes >=0.45, unsloth from git). setup_env.sh
# is idempotent — re-running prepare.sh only tops up missing packages.
if command -v nvidia-smi >/dev/null 2>&1; then
    GPU_NAME=$(nvidia-smi --query-gpu=name --format=csv,noheader 2>/dev/null | head -1 || true)
    GPU_CC=$(nvidia-smi --query-gpu=compute_cap --format=csv,noheader 2>/dev/null | head -1 || true)
    GPU_VRAM=$(nvidia-smi --query-gpu=memory.total --format=csv,noheader,nounits 2>/dev/null | head -1 || true)
    log_ok "GPU detected: ${GPU_NAME:-unknown} (compute_cap ${GPU_CC:-?}, ${GPU_VRAM:-?} MiB VRAM)"
    if [[ "${GPU_CC}" == "12.0" ]]; then
        log_ok "Blackwell sm_120 confirmed — cu128 torch wheels + SDPA attention will be used."
    else
        log_warn "compute_cap is '${GPU_CC:-unknown}' (not 12.0/sm_120). setup_env.sh still installs cu128 wheels; verify compatibility."
    fi
else
    log_warn "nvidia-smi not found — fine-tune needs a CUDA GPU (RTX 5070 Ti / sm_120). setup_env.sh will still prepare the venv."
fi

if [[ -x "${WORKSPACE_DIR}/setup_env.sh" ]]; then
    log_info "Running workspace/setup_env.sh (creates .venv + installs torch/unsloth/bitsandbytes) ..."
    log_info "  This is the heavy step (~15-25 min, ~6GB). It is idempotent and safe to re-run."
    bash "${WORKSPACE_DIR}/setup_env.sh" || log_warn "setup_env.sh returned non-zero — the venv may be incomplete; re-run to retry."
    log_ok "Python venv prepared at ${WORKSPACE_DIR}/.venv"
else
    log_warn "${WORKSPACE_DIR}/setup_env.sh missing — pipeline files were not materialized. Check the repo."
fi

log_ok "Step 7A complete"

# =============================================================================
banner "STEP 7B: Verify pipeline files + generate Ollama Modelfile"
# =============================================================================
# The real fine-tune pipeline lives as committed repo files under workspace/.
# Make them executable and generate the Ollama Modelfile from the shared
# orchestrator_system.txt — single source of truth shared with train.py and
# server.ts, so the fine-tuned model drops straight into the agentic loop with
# no prompt drift.
PIPELINE_FILES=(
    "${WORKSPACE_DIR}/setup_env.sh"
    "${WORKSPACE_DIR}/download_hf_assets.sh"
    "${WORKSPACE_DIR}/dataset/generate_custom_data.py"
    "${WORKSPACE_DIR}/train.py"
    "${WORKSPACE_DIR}/convert_to_gguf.sh"
    "${WORKSPACE_DIR}/run_full_pipeline.sh"
    "${WORKSPACE_DIR}/run_finetune_simulated.sh"
    "${WORKSPACE_DIR}/orchestrator_system.txt"
)
for f in "${PIPELINE_FILES[@]}"; do
    if [[ -f "$f" ]]; then
        chmod +x "$f" 2>/dev/null || true
        log_ok "present: $(basename "$f")"
    else
        log_warn "MISSING: ${f}"
    fi
done

# Generate workspace/Modelfile from orchestrator_system.txt + the quantized
# GGUF path. The llama3 GGUF bakes in the chat template, so we omit TEMPLATE
# and rely on the embedded template (matches train.py's apply_chat_template).
MODELFILE="${WORKSPACE_DIR}/Modelfile"
if [[ -f "${WORKSPACE_DIR}/orchestrator_system.txt" ]]; then
    {
        echo '# Wifite v4 Agentic orchestrator model (fine-tuned Llama-3-8B Q4_K_M).'
        echo '# Generated by prepare.sh from orchestrator_system.txt — do not hand-edit.'
        echo 'FROM ./output/wifite_agent_q4_k_m.gguf'
        echo 'PARAMETER temperature 0.2'
        echo 'PARAMETER format json'
        echo 'PARAMETER stop "### Instruction:"'
        echo 'SYSTEM """'
        cat "${WORKSPACE_DIR}/orchestrator_system.txt"
        echo '"""'
    } > "$MODELFILE"
    log_ok "Wrote ${MODELFILE} (SYSTEM synced from orchestrator_system.txt)"
else
    log_warn "orchestrator_system.txt missing — Modelfile not generated"
fi

log_ok "Step 7B complete"

# =============================================================================
banner "SUMMARY"
# =============================================================================
printf '%sSetup complete.%s\n\n' "${CLR_BOLD}" "${CLR_RESET}"

printf '%sInstalled / verified apt packages:%s\n' "${CLR_CYAN}" "${CLR_RESET}"
for dep in "${DEPS[@]}"; do
    if pkg_installed "$dep" || command -v "$dep" >/dev/null 2>&1; then
        printf '  - %s%s%s\n' "${CLR_GREEN}" "$dep" "${CLR_RESET}"
    else
        printf '  - %s%s (missing)%s\n' "${CLR_RED}" "$dep" "${CLR_RESET}"
    fi
done

printf '\n%sOllama:%s %s\n' "${CLR_CYAN}" "${CLR_RESET}" "$(command -v ollama || echo 'not found')"
printf '%sOllama API:%s http://127.0.0.1:11434 (loopback only — not LAN-reachable)\n' "${CLR_CYAN}" "${CLR_RESET}"

printf '\n%sAvailable Ollama models:%s\n' "${CLR_CYAN}" "${CLR_RESET}"
if command -v ollama >/dev/null 2>&1; then
    ollama list 2>/dev/null | awk 'NR>1 {printf "  - %s (%s)\n", $1, $2}' || echo "  (unable to list models)"
else
    echo "  (ollama not on PATH in this session)"
fi

printf '\n%sWorkspace structure:%s\n' "${CLR_CYAN}" "${CLR_RESET}"
printf '  %s/\n' "$WORKSPACE_DIR"
printf '    .venv/                      # ML venv (torch cu128, unsloth, bitsandbytes) — created by setup_env.sh\n'
printf '    dataset/                    # generate_custom_data.py builds wifite_agent_dataset.jsonl\n'
printf '    models/                     # downloaded base model (llama-3-8b-Instruct 4-bit)\n'
printf '    output/                     # LoRA adapter + merged model + GGUF (wifite_agent_q4_k_m.gguf)\n'
printf '    captures/                   # airodump/wash/hcxdumptool output (scan-*.csv, hash.hc22000)\n'
printf '    train.py                    # real Unsloth/QLoRA trainer (sm_120 SDPA/bf16/adamw_8bit)\n'
printf '    convert_to_gguf.sh          # merge LoRA -> GGUF f16 -> quantize Q4_K_M\n'
printf '    Modelfile                   # generated; SYSTEM synced from orchestrator_system.txt\n'
printf '    run_full_pipeline.sh        # end-to-end: setup -> download -> dataset -> train -> export -> ollama create\n'
printf '    run_finetune_simulated.sh   # UI smoke-test loss loop (NOT real training)\n'
printf '    finetune_status.json\n'

printf '\n%sNext steps:%s\n' "${CLR_BOLD}" "${CLR_RESET}"
printf '  1. %snpm run dev%s                              — start the dashboard (bound 127.0.0.1:3000)\n' "${CLR_GREEN}" "${CLR_RESET}"
printf '  2. %sbash workspace/download_hf_assets.sh%s     — fetch base model + cyber dataset\n' "${CLR_GREEN}" "${CLR_RESET}"
printf '  3. %s./workspace/dataset/generate_custom_data.py%s (via .venv python) — build the training set\n' "${CLR_GREEN}" "${CLR_RESET}"
printf '  4. %sPOST /api/finetune/start%s                 — real training run (live loss in the UI monitor)\n' "${CLR_GREEN}" "${CLR_RESET}"
printf '     OR %sbash workspace/run_full_pipeline.sh%s   — full CLI pipeline incl. GGUF export + ollama create\n' "${CLR_GREEN}" "${CLR_RESET}"
printf '  5. %s./workspace/run_finetune_simulated.sh%s    — UI smoke test only (no GPU needed)\n' "${CLR_GREEN}" "${CLR_RESET}"

printf '\n%sDone. Re-running this script is safe.%s\n' "${CLR_GREEN}" "${CLR_RESET}"