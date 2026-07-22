#!/bin/bash

set -e
set -x

# ------------------------------------------------------------
# DISK CONFIGURATION
# ------------------------------------------------------------
AVAILABLE_SPACE_GB=$(df -BG /home/user | awk 'NR==2 {print $4}' | sed 's/G//')
THRESHOLD_GB=50

NVME_WORKSPACE="/home/user/pipeline_workspace"
export HF_HOME="/home/user/.cache/huggingface"
export MODEL_DIR="${NVME_WORKSPACE}/models"

HDD_WORKSPACE="/run/media/user/f1b2d897-fa36-4c2c-90f0-06c14b7431a5/workspace"
HDD_HF_CACHE="/run/media/user/f1b2d897-fa36-4c2c-90f0-06c14b7431a5/hf_cache"

if [ -d "${HDD_WORKSPACE}/models/base" ] && [ ! -d "${MODEL_DIR}/base" ]; then
    echo "Copying base model from second disk to NVMe..."
    mkdir -p "${MODEL_DIR}"
    cp -r "${HDD_WORKSPACE}/models/base" "${MODEL_DIR}/"
fi

if [ "$AVAILABLE_SPACE_GB" -ge "$THRESHOLD_GB" ]; then
    echo "✔ NVMe has enough space ($AVAILABLE_SPACE_GB GB free). Running fully on NVMe."
    WORKSPACE="${NVME_WORKSPACE}"
    export DATASET_DIR="${WORKSPACE}/dataset"
    OUTPUT_DIR="${WORKSPACE}/output"
else
    echo "⚠ NVMe has low space ($AVAILABLE_SPACE_GB GB free). Using second disk for datasets and outputs, but keeping models on NVMe."
    WORKSPACE="${HDD_WORKSPACE}"
    export DATASET_DIR="${WORKSPACE}/dataset"
    OUTPUT_DIR="${WORKSPACE}/output"
fi

# Copy datasets if needed
for src_dataset_dir in "/home/user/Pulpit/kfiosa/workspace/dataset" "${HDD_WORKSPACE}/dataset"; do
    if [ -d "$src_dataset_dir" ]; then
        for cat in wifi ble post_exploit osint; do
            if [ -f "${src_dataset_dir}/${cat}_dataset.jsonl" ] && [ ! -f "${DATASET_DIR}/${cat}_dataset.jsonl" ]; then
                echo "Copying ${cat} dataset from ${src_dataset_dir} to ${DATASET_DIR}..."
                mkdir -p "${DATASET_DIR}"
                cp "${src_dataset_dir}/${cat}_dataset.jsonl" "${DATASET_DIR}/"
                [ -f "${src_dataset_dir}/${cat}_manifest.json" ] && cp "${src_dataset_dir}/${cat}_manifest.json" "${DATASET_DIR}/"
            fi
        done
    fi
done

HF_TOKEN="${HF_TOKEN:-}"

mkdir -p "${WORKSPACE}/logs" "${DATASET_DIR}" "${OUTPUT_DIR}" "${HF_HOME}" "${MODEL_DIR}"
LOG_FILE="${WORKSPACE}/logs/pipeline_final.log"

log_step() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] STEP $1/$2: $3" | tee -a "$LOG_FILE"
}

# ------------------------------------------------------------
# 0. Python 3.10
# ------------------------------------------------------------
log_step 0 9 "Checking for Python 3.10..."
PYTHON_CMD="python"
for p in python3.10 python3.10 python310; do
    if command -v $p &> /dev/null; then
        PYTHON_CMD=$p
        break
    fi
done
if [ -z "$PYTHON_CMD" ]; then
    echo "❌ Python 3.10 not found! Please install Python 3.10 first." | tee -a "$LOG_FILE"
    exit 1
fi
echo "✔ Using Python: $($PYTHON_CMD --version)" | tee -a "$LOG_FILE"

# ------------------------------------------------------------
# 1. System dependencies
# ------------------------------------------------------------
log_step 1 9 "Checking system dependencies..."
DEPS_MISSING=0
for cmd in cmake git wget curl; do
    if ! command -v "$cmd" &> /dev/null; then
        DEPS_MISSING=1
    fi
done
if ! command -v make &> /dev/null; then
    DEPS_MISSING=1
fi
if [ "$DEPS_MISSING" -eq 1 ]; then
    echo "Installing missing dependencies..." | tee -a "$LOG_FILE"
    sudo apt update && sudo apt install -y build-essential cmake git wget curl
else
    echo "✔ All system dependencies are already installed." | tee -a "$LOG_FILE"
fi

if ! command -v nvcc &> /dev/null; then
    echo "❌ CUDA not found! Install CUDA 12.4+ first." | tee -a "$LOG_FILE"
    exit 1
fi
echo "CUDA: $(nvcc --version | head -n1)" | tee -a "$LOG_FILE"

# ------------------------------------------------------------
# 2. Python environment
# ------------------------------------------------------------
log_step 2 9 "Setting up Python 3.10 environment..."
export TORCH_CUDA_ARCH_LIST="8.0;8.6;8.9;9.0;10.0;11.0;11.8;12.0;12.4;12.8;12.9;13.0;13.1;13.2;13.3;13.5"

if [ ! -d ".venv" ]; then
    echo "Creating virtual environment .venv..." | tee -a "$LOG_FILE"
    $PYTHON_CMD -m venv .venv
fi
source .venv/bin/activate

if python3 -c "import torch, unsloth, transformers, datasets, accelerate, peft, bitsandbytes, trl, torchao" &>/dev/null; then
    echo "✔ Python dependencies already satisfied. Skipping installation." | tee -a "$LOG_FILE"
else
    echo "Installing/updating Python dependencies..." | tee -a "$LOG_FILE"
    pip install --upgrade pip
    pip install --upgrade --pre torch torchvision --index-url https://download.pytorch.org/whl/nightly/cu121
    pip install torchao
    pip install transformers==5.5.0
    pip install unsloth
    pip install datasets accelerate peft bitsandbytes trl huggingface-hub
fi

# ------------------------------------------------------------
# 3. Base model selection
# ------------------------------------------------------------
log_step 3 9 "Selecting and downloading uncensored base models for each task..."

get_base_model_for_task() {
    local task=$1
    local selected_model=""
    local models=()
    if [ "$task" = "wifi" ]; then
        models=("VextLabsinc/pentest-7b" "Canstralian/pentest_ai" "NousResearch/Nous-Hermes-2-Mistral-7B-DPO" "teknium/OpenHermes-2.5-Mistral-7B")
    elif [ "$task" = "ble" ]; then
        models=("Canstralian/pentest_ai" "VextLabsinc/pentest-7b" "NousResearch/Nous-Hermes-2-Mistral-7B-DPO" "teknium/OpenHermes-2.5-Mistral-7B")
    elif [ "$task" = "post_exploit" ]; then
        models=("VextLabsinc/pentest-7b" "TheBloke/Wizard-Vicuna-13B-Uncensored-HF" "NousResearch/Nous-Hermes-2-Mistral-7B-DPO" "teknium/OpenHermes-2.5-Mistral-7B")
    elif [ "$task" = "osint" ]; then
        models=("ansulev/Ornith-1.0-9B-Uncensored" "NousResearch/Nous-Hermes-2-Mistral-7B-DPO" "teknium/OpenHermes-2.5-Mistral-7B")
    fi

    # Check local NVMe
    if [ -d "${MODEL_DIR}/base_${task}" ] && [ -f "${MODEL_DIR}/base_${task}/config.json" ]; then
        local name_in_config=$(grep '"_name_or_path":' "${MODEL_DIR}/base_${task}/config.json" | head -n1 | cut -d'"' -f4)
        if [ -n "$name_in_config" ]; then
            selected_model="$name_in_config"
            echo "✔ Found local base model for $task in ${MODEL_DIR}/base_${task}. Using: $selected_model" >&2
        else
            for model in "${models[@]}"; do
                selected_model="$model"
                echo "✔ Found local base model for $task in ${MODEL_DIR}/base_${task}. Using: $selected_model" >&2
                break
            done
        fi
    fi

    # Copy from HDD if needed
    if [ -z "$selected_model" ]; then
        for model in "${models[@]}"; do
            if [ "$model" = "teknium/OpenHermes-2.5-Mistral-7B" ] && [ -d "${HDD_WORKSPACE}/models/base" ]; then
                echo "Copying teknium/OpenHermes-2.5-Mistral-7B from HDD to NVMe for task $task..." >&2
                mkdir -p "${MODEL_DIR}/base_${task}"
                cp -r "${HDD_WORKSPACE}/models/base/"* "${MODEL_DIR}/base_${task}/"
                selected_model="$model"
                break
            fi
        done
    fi

    # Check online and download
    if [ -z "$selected_model" ]; then
        for model in "${models[@]}"; do
            echo "Checking online availability for task $task: $model" >&2
            if python3 -c "from huggingface_hub import model_info; model_info('$model')" 2>/dev/null; then
                selected_model="$model"
                break
            fi
        done
    fi

    if [ -n "$selected_model" ]; then
        if [ ! -d "${MODEL_DIR}/base_${task}" ] || [ ! -f "${MODEL_DIR}/base_${task}/config.json" ]; then
            echo "Downloading uncensored base model for $task: $selected_model..." >&2
            python3 -c "
from huggingface_hub import snapshot_download
import os
os.makedirs('${MODEL_DIR}/base_${task}', exist_ok=True)
snapshot_download(
    repo_id='${selected_model}',
    local_dir='${MODEL_DIR}/base_${task}',
    ignore_patterns=['*.gguf', '*.bin'],
)
"
        fi
        echo "$selected_model"
    else
        echo ""
    fi
}

declare -A SELECTED_BASE_MODELS
for cat in wifi ble post_exploit osint; do
    model=$(get_base_model_for_task "$cat")
    if [ -z "$model" ]; then
        echo "❌ No base model available for task $cat!" | tee -a "$LOG_FILE"
        exit 1
    fi
    SELECTED_BASE_MODELS[$cat]="$model"
    echo "✔ Active base model for $cat: $model" | tee -a "$LOG_FILE"
done

# ------------------------------------------------------------
# 4. Dataset aggregation (skip if already present)
# ------------------------------------------------------------
log_step 4 9 "Checking for existing aggregated datasets..."
DATASETS_EXIST=1
for cat in wifi ble post_exploit osint; do
    if [ ! -f "${DATASET_DIR}/${cat}_dataset.jsonl" ]; then
        DATASETS_EXIST=0
    fi
done

if [ "$DATASETS_EXIST" -eq 1 ]; then
    echo "✔ All datasets found in ${DATASET_DIR}. Skipping download/aggregation." | tee -a "$LOG_FILE"
else
    log_step 5 9 "Aggregating and normalizing datasets from 20+ sources (this might take a while)..."

    python3 <<PYAGG
import json, os, sys, hashlib
from datasets import load_dataset
from huggingface_hub import login
from collections import defaultdict

DATASET_DIR = os.getenv('DATASET_DIR', './workspace/dataset')

if os.getenv('HF_TOKEN'):
    login(token=os.getenv('HF_TOKEN'))

CATEGORIES = {
    'wifi': ['wifi', 'wireless', 'wpa', 'wep', 'handshake', 'aircrack', 'airmon', 'deauth', 'crack', 'password', 'psk'],
    'ble': ['bluetooth', 'ble', 'bluetooth low energy', 'gatt', 'hcitool', 'gatttool', 'nrf', 'sniff', 'spoof'],
    'post_exploit': ['post-exploit', 'privilege escalation', 'persistence', 'lateral movement', 'mimikatz', 'meterpreter', 'shell', 'hashdump', 'exploit', 'payload', 'reverse shell', 'buffer overflow', 'cve', 'vulnerability'],
    'osint': ['osint', 'reconnaissance', 'social media', 'username', 'email', 'phone number', 'shodan', 'maltego', 'theharvester', 'doxx', 'people search']
}

SOURCES = [
    "ICEPVP8977/Uncensored_mini",
    "teknium/OpenHermes-2.5",
    "WizardLM/WizardLM_evol_instruct_V2_196k",
    "garage-bAInd/Open-Platypus",
    "Intel/orca_dpo_pairs",
    "microsoft/orca-math-word-problems-200k",
    "nomic-ai/gpt4all-j-prompt-generations",
    "infinite-dataset-hub/PenTestingScenarioSimulation",
    "Open-Orca/OpenOrca",
    "HuggingFaceH4/ultrachat_200k",
    "OpenAssistant/oasst1",
    "databricks/databricks-dolly-15k",
    "yahma/alpaca-cleaned",
    "tatsu-lab/alpaca",
    "bigcode/the-stack",
    "glaiveai/glaive-code-assistant",
    "theblackcat102/exploit-db",
    "nayak/exploit-db",
    "cve/cve",
    "johnowhitaker/cve"
]

def normalize_example(example):
    if 'instruction' in example:
        return {
            'instruction': str(example.get('instruction', '')),
            'input': str(example.get('input', '')),
            'output': str(example.get('output', ''))
        }
    if 'conversations' in example:
        conv = example.get('conversations', [])
        if conv and isinstance(conv, list):
            user_msgs = [c for c in conv if c.get('from') == 'human' or c.get('role') == 'user']
            assistant_msgs = [c for c in conv if c.get('from') == 'gpt' or c.get('role') == 'assistant']
            if user_msgs and assistant_msgs:
                return {
                    'instruction': user_msgs[-1].get('value', ''),
                    'input': '',
                    'output': assistant_msgs[-1].get('value', '')
                }
    if 'prompt' in example and 'completion' in example:
        return {
            'instruction': str(example.get('prompt', '')),
            'input': '',
            'output': str(example.get('completion', ''))
        }
    if 'text' in example and 'chosen' in example:
        return {
            'instruction': str(example.get('text', '')),
            'input': '',
            'output': str(example.get('chosen', ''))
        }
    if 'system' in example and 'messages' in example:
        msgs = example.get('messages', [])
        if msgs and isinstance(msgs, list):
            user_msgs = [m for m in msgs if m.get('role') == 'user']
            assistant_msgs = [m for m in msgs if m.get('role') == 'assistant']
            if user_msgs and assistant_msgs:
                return {
                    'instruction': user_msgs[-1].get('content', ''),
                    'input': '',
                    'output': assistant_msgs[-1].get('content', '')
                }
    if 'description' in example and 'code' in example:
        return {
            'instruction': str(example.get('title', '')) + " " + str(example.get('description', '')),
            'input': '',
            'output': str(example.get('code', ''))
        }
    if 'cve_id' in example and 'description' in example:
        return {
            'instruction': f"CVE: {example.get('cve_id', '')} - {example.get('description', '')}",
            'input': '',
            'output': example.get('solution', '') or example.get('references', '')
        }
    instr = example.get('text', '') or example.get('instruction', '') or example.get('prompt', '') or ''
    output = example.get('response', '') or example.get('output', '') or example.get('completion', '') or example.get('chosen', '') or ''
    if instr and output:
        return {'instruction': instr, 'input': '', 'output': output}
    return None

def fetch_and_filter(repo_id, category_keywords):
    print(f"Processing: {repo_id} for {category_keywords}")
    try:
        if repo_id == "HuggingFaceH4/ultrachat_200k":
            split = 'train_sft'
        elif repo_id == "Open-Orca/OpenOrca":
            split = 'train'
        elif repo_id in ["OpenAssistant/oasst1", "databricks/databricks-dolly-15k", "yahma/alpaca-cleaned",
                         "tatsu-lab/alpaca", "bigcode/the-stack", "glaiveai/glaive-code-assistant",
                         "theblackcat102/exploit-db", "nayak/exploit-db", "cve/cve", "johnowhitaker/cve"]:
            split = 'train'
        else:
            split = 'train'
        dataset = load_dataset(repo_id, split=split, trust_remote_code=False, streaming=True)
        results = []
        for ex in dataset:
            norm = normalize_example(ex)
            if norm and norm['instruction'] and norm['output']:
                text = (norm['instruction'] + ' ' + norm.get('input', '')).lower()
                if any(k in text for k in category_keywords):
                    results.append(norm)
            if len(results) >= 500:
                break
        return results
    except Exception as e:
        print(f"⚠️ Failed to load {repo_id}: {e}")
        return []

aggregated = {cat: [] for cat in CATEGORIES}
manifest = {cat: [] for cat in CATEGORIES}

for repo in SOURCES:
    if not repo:
        continue
    for cat, keywords in CATEGORIES.items():
        samples = fetch_and_filter(repo, keywords)
        if samples:
            aggregated[cat].extend(samples)
            manifest[cat].append({
                'source': repo,
                'samples': len(samples),
                'status': 'success'
            })
        else:
            manifest[cat].append({
                'source': repo,
                'samples': 0,
                'status': 'no_data'
            })

for cat, samples in aggregated.items():
    if not samples:
        print(f"❌ No samples for {cat}, exiting.")
        sys.exit(1)
    seen = set()
    unique = []
    for ex in samples:
        key = hashlib.sha256(json.dumps(ex, sort_keys=True).encode()).hexdigest()
        if key not in seen:
            seen.add(key)
            unique.append(ex)
    print(f"✅ {cat}: {len(unique)} unique samples after dedup")
    
    train_path = f"{DATASET_DIR}/{cat}_dataset.jsonl"
    with open(train_path, 'w') as f:
        for ex in unique[:1000]:
            f.write(json.dumps(ex) + '\n')
    
    with open(f"{DATASET_DIR}/{cat}_manifest.json", 'w') as f:
        json.dump({
            'category': cat,
            'total_samples': len(unique),
            'used_samples': min(len(unique), 1000),
            'sources': manifest[cat]
        }, f, indent=2)

print("✅ Dataset aggregation complete.")
PYAGG
fi

# ------------------------------------------------------------
# 6. Validate datasets
# ------------------------------------------------------------
log_step 6 9 "Validating aggregated datasets..."
for cat in wifi ble post_exploit osint; do
    file="${DATASET_DIR}/${cat}_dataset.jsonl"
    if [ ! -f "$file" ]; then
        echo "❌ Missing: $file" >&2
        exit 1
    fi
    count=$(wc -l < "$file")
    if [ "$count" -lt 5 ]; then
        echo "❌ Too few samples ($count) in $file" >&2
        exit 1
    fi
    echo "✔ $cat dataset ready ($count samples)" | tee -a "$LOG_FILE"
done

# ------------------------------------------------------------
# 7. Fine‑tuning + GGUF export
# ------------------------------------------------------------
log_step 7 9 "Fine-tuning models with QLoRA and exporting to GGUF..."

# Stop Ollama if running to free GPU memory
if systemctl is-active --quiet ollama; then
    echo "Stopping Ollama to free GPU memory..." | tee -a "$LOG_FILE"
    sudo systemctl stop ollama || true
    sleep 3
fi

export TRANSFORMERS_NO_TORCHAO=1
export TORCH_CUDA_ARCH_LIST="8.0;8.6;8.9;9.0;10.0;11.0;11.8;12.0;12.4;12.8;12.9;13.0;13.1;13.2;13.3;13.5"

# Write the fine‑tuning script that also exports GGUF
cat > "${WORKSPACE}/fine_tune_export_gguf.py" << 'EOF'
import os, sys, json, torch
from unsloth import FastLanguageModel
from transformers import TrainingArguments
from trl import SFTTrainer
from datasets import load_dataset

def fine_tune_and_export(category, data_path, output_dir, base_model_path):
    print(f"Fine-tuning for {category}...")
    model, tokenizer = FastLanguageModel.from_pretrained(
        model_name=base_model_path,
        max_seq_length=2048,
        load_in_4bit=True,
        dtype=torch.float16,
    )
    model = FastLanguageModel.get_peft_model(
        model,
        r=16,
        lora_alpha=16,
        lora_dropout=0,
        target_modules=["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"],
        use_rslora=True,
        use_gradient_checkpointing="unsloth",
    )

    dataset = load_dataset("json", data_files=data_path, split="train")
    if len(dataset) < 3:
        print(f"⚠ Not enough data for {category}, skipping.")
        return

    def format_example(ex):
        return f"### Instruction:\n{ex['instruction']}\n### Input:\n{ex.get('input', '')}\n### Response:\n{ex['output']}"

    dataset = dataset.map(lambda x: {"text": format_example(x)})

    trainer = SFTTrainer(
        model=model,
        tokenizer=tokenizer,
        train_dataset=dataset,
        args=TrainingArguments(
            per_device_train_batch_size=2,
            gradient_accumulation_steps=4,
            warmup_steps=5,
            max_steps=150,
            learning_rate=2e-4,
            fp16=True,
            logging_steps=1,
            output_dir=output_dir,
            save_strategy="no",
            report_to="none",
        ),
        dataset_text_field="text",
        max_seq_length=2048,
    )
    trainer.train()

    # Merge adapter and export to GGUF
    print("Merging adapter and exporting to GGUF...")
    model = model.merge_and_unload()
    # Save GGUF with Q4_K_M quantization (you can change method)
    model.save_pretrained_gguf(output_dir, tokenizer, quantization_method = "q4_k_m")
    print(f"✔ GGUF model saved to {output_dir}")

if __name__ == "__main__":
    if len(sys.argv) != 5:
        print("Usage: fine_tune_export_gguf.py <category> <data_path> <output_dir> <base_model_path>")
        sys.exit(1)
    fine_tune_and_export(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4])
EOF

# Loop over categories
for cat in wifi ble post_exploit osint; do
    DATA="${DATASET_DIR}/${cat}_dataset.jsonl"
    OUT="${OUTPUT_DIR}/${cat}_lora_adapter"
    mkdir -p "$OUT"

    # Check if GGUF already exists (skip fine‑tuning)
    if [ -f "${OUT}/unsloth.Q4_K_M.gguf" ]; then
        echo "✔ GGUF for $cat already exists. Skipping fine‑tuning." | tee -a "$LOG_FILE"
        continue
    fi

    log_step "7-${cat}" 9 "Fine-tuning $cat and exporting GGUF..."
    python3 "${WORKSPACE}/fine_tune_export_gguf.py" "$cat" "$DATA" "$OUT" "${MODEL_DIR}/base_${cat}"

    # Validate GGUF exists
    if [ ! -f "${OUT}/unsloth.Q4_K_M.gguf" ]; then
        echo "❌ GGUF export failed for $cat" | tee -a "$LOG_FILE"
        exit 1
    fi
    echo "✔ GGUF for $cat validated." | tee -a "$LOG_FILE"
done

# ------------------------------------------------------------
# 8. Create Ollama models from local GGUF
# ------------------------------------------------------------
log_step 8 9 "Creating Ollama models from GGUF files..."

ensure_ollama_running() {
    if command -v ollama &> /dev/null; then
        if systemctl is-active --quiet ollama; then
            echo "Ollama service is already running." | tee -a "$LOG_FILE"
            return 0
        elif systemctl start ollama 2>/dev/null; then
            echo "Started Ollama via systemctl." | tee -a "$LOG_FILE"
            sleep 3
            return 0
        else
            echo "Starting Ollama manually (ollama serve)..." | tee -a "$LOG_FILE"
            ollama serve &
            sleep 5
            if ollama list &> /dev/null; then
                return 0
            else
                echo "❌ Failed to start Ollama." | tee -a "$LOG_FILE"
                return 1
            fi
        fi
    else
        echo "❌ Ollama not installed. Installing..." | tee -a "$LOG_FILE"
        curl -fsSL https://ollama.com/install.sh | sh
        ensure_ollama_running
    fi
}

# Stop Ollama if running (we'll start it after fine‑tuning)
if systemctl is-active --quiet ollama; then
    echo "Stopping Ollama before starting model creation..." | tee -a "$LOG_FILE"
    sudo systemctl stop ollama || true
    sleep 2
fi

ensure_ollama_running || exit 1

declare -A MODEL_NAMES=(
    ["wifi"]="wifi_pentesting"
    ["ble"]="ble_pentesting"
    ["osint"]="osint_model"
    ["post_exploit"]="post_exploitation"
)

# Create each model from the GGUF
for cat in wifi ble post_exploit osint; do
    MODEL_NAME="${MODEL_NAMES[$cat]}"
    GGUF_PATH="${OUTPUT_DIR}/${cat}_lora_adapter/unsloth.Q4_K_M.gguf"
    MODELFILE="${WORKSPACE}/Modelfile_${cat}"

    if [ ! -f "$GGUF_PATH" ]; then
        echo "❌ GGUF file not found for $cat: $GGUF_PATH" | tee -a "$LOG_FILE"
        exit 1
    fi

    cat > "$MODELFILE" << EOF
FROM ${GGUF_PATH}
TEMPLATE """{{ .Prompt }}"""
PARAMETER temperature 0.7
PARAMETER top_p 0.9
EOF

    echo "Creating model $MODEL_NAME from $GGUF_PATH..." | tee -a "$LOG_FILE"
    if ollama create "$MODEL_NAME" -f "$MODELFILE" 2>&1 | tee -a "$LOG_FILE"; then
        if ollama list | grep -q "^$MODEL_NAME"; then
            echo "✔ Model $MODEL_NAME created successfully." | tee -a "$LOG_FILE"
        else
            echo "❌ Model $MODEL_NAME was not found after creation." | tee -a "$LOG_FILE"
            exit 1
        fi
    else
        echo "❌ Failed to create model $MODEL_NAME" | tee -a "$LOG_FILE"
        exit 1
    fi
done

# ------------------------------------------------------------
# 9. Final summary
# ------------------------------------------------------------
log_step 9 9 "Pipeline completed successfully!"
echo "======================================================================"
echo " ✅ All models are ready:"
for cat in wifi ble post_exploit osint; do
    echo "  - ${MODEL_NAMES[$cat]}"
done
echo " Datasets aggregated from 20+ verified sources"
echo " Usage:"
for cat in wifi ble post_exploit osint; do
    echo "   ollama run ${MODEL_NAMES[$cat]}"
done
echo " Logs: ${LOG_FILE}"
echo "======================================================================"
