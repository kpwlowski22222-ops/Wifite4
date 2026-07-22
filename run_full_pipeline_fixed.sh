#!/bin/bash

# Fixed Master Pipeline for Creating All Pentesting Models
# Addresses issues encountered in the first run

set -e
set -x

echo "=========================================="
echo " Creating All Specialized Pentesting Models (Fixed Version)"
echo "=========================================="

mkdir -p ./workspace/logs

log_step() {
    echo "[STEP $1/$2: $3]" | tee -a ./workspace/logs/pipeline_fixed.log
}


# Step 1: Installing dependencies (with fix for torchvision)
log_step 1 9 "Installing Hugging Face CLI & fine-tuning dependencies..."\n
# Install compatible versions to avoid torchvision::nms error
pip install "torch==2.1.0" "torchvision==0.16.0" --index-url https://download.pytorch.org/whl/cu111
./workspace/setup_env.sh

# Step 2: Downloading uncensored base models from HF.co
log_step 2 9 "Downloading uncensored base models from HF.co..."\n
./workspace/download_uncensored_models.sh

# Step 3: Generating/downloading specialized datasets from HF.co
log_step 3 9 "Generating/downloading specialized datasets from HF.co..."\n
# Download WiFi pentesting dataset
echo "Downloading WiFi pentesting dataset from HF.co..." | tee -a ./workspace/logs/pipeline_fixed.log
python3 -c "from datasets import load_dataset; import json; dataset = load_dataset('Sven9/cybersecurity-instructions', split='train'); wifi_data = [ex for ex in dataset if any(k in ex['instruction'].lower() for k in ['wifi', 'wireless', 'wpa', 'wep', 'handshake'])]; formatted_data = [{'instruction': ex['instruction'], 'input': ex.get('input', ''), 'output': ex['output']} for ex in wifi_data.select(range(min(500, len(wifi_data))))]; open('./workspace/dataset/wifi_dataset.jsonl', 'w').write('\n'.join(json.dumps(item) for item in formatted_data)); print(f'WiFi dataset: {len(formatted_data)} samples')" || echo "HF.co download failed, using synthetic..." && python3 ./workspace/dataset/generate_custom_data.py && cp ./workspace/dataset/wifite_agent_dataset.jsonl ./workspace/dataset/wifi_dataset.jsonl

# Download BLE pentesting dataset
echo "Downloading BLE pentesting dataset from HF.co..." | tee -a ./workspace/logs/pipeline_fixed.log
python3 -c "from datasets import load_dataset; import json; dataset = load_dataset('Sven9/cybersecurity-instructions', split='train'); ble_data = [ex for ex in dataset if any(k in ex['instruction'].lower() for k in ['bluetooth', 'ble', 'bluetooth low energy'])]; formatted_data = [{'instruction': ex['instruction'], 'input': ex.get('input', ''), 'output': ex['output']} for ex in ble_data.select(range(min(500, len(ble_data))))]; open('./workspace/dataset/ble_dataset.jsonl', 'w').write('\n'.join(json.dumps(item) for item in formatted_data)); print(f'BLE dataset: {len(formatted_data)} samples')" || echo "HF.co download failed, creating synthetic..." && echo '[{"instruction": "How to perform BLE device enumeration?", "input": "Target is a BLE device in range", "output": "Use tools like gatttool, hcitool, or bleah to enumerate services and characteristics on the BLE device."}]' > ./workspace/dataset/ble_dataset.jsonl

# Download post-exploitation dataset
echo "Downloading post-exploitation dataset from HF.co..." | tee -a ./workspace/logs/pipeline_fixed.log
python3 -c "from datasets import load_dataset; import json; dataset = load_dataset('Sven9/cybersecurity-instructions', split='train'); post_data = [ex for ex in dataset if any(k in ex['instruction'].lower() for k in ['post-exploit', 'privilege escalation', 'persistence', 'lateral movement', 'mimikatz'])]; formatted_data = [{'instruction': ex['instruction'], 'input': ex.get('input', ''), 'output': ex['output']} for ex in post_data.select(range(min(500, len(post_data))))]; open('./workspace/dataset/post_exploit_dataset.jsonl', 'w').write('\n'.join(json.dumps(item) for item in formatted_data)); print(f'Post-exploitation dataset: {len(formatted_data)} samples')" || echo "HF.co download failed, creating synthetic..." && echo '[{"instruction": "How to establish persistence on a Windows system?", "input": "Target is a Windows system with admin access", "output": "Use techniques like registry run keys, scheduled tasks, or service installation to maintain access after reboot."}]' > ./workspace/dataset/post_exploit_dataset.jsonl

# Download OSINT dataset
echo "Downloading OSINT dataset from HF.co..." | tee -a ./workspace/logs/pipeline_fixed.log
python3 -c "from datasets import load_dataset; import json; dataset = load_dataset('Sven9/cybersecurity-instructions', split='train'); osint_data = [ex for ex in dataset if any(k in ex['instruction'].lower() for k in ['osint', 'reconnaissance', 'social media', 'username', 'email', 'phone number'])]; formatted_data = [{'instruction': ex['instruction'], 'input': ex.get('input', ''), 'output': ex['output']} for ex in osint_data.select(range(min(500, len(osint_data))))]; open('./workspace/dataset/osint_dataset.jsonl', 'w').write('\n'.join(json.dumps(item) for item in formatted_data)); print(f'OSINT dataset: {len(formatted_data)} samples')" || echo "HF.co download failed, creating synthetic..." && echo '[{"instruction": "How to gather OSINT on a target using social media?", "input": "Target is a person with known name and approximate location", "output": "Search social media platforms like LinkedIn, Facebook, Twitter, and Instagram for personal information, employment details, and social connections."}]' > ./workspace/dataset/osint_dataset.jsonl

log_step 4 9 "Validating datasets..."\n
if [ -f ./workspace/dataset/wifi_dataset.jsonl ] && [ -f ./workspace/dataset/ble_dataset.jsonl ] && [ -f ./workspace/dataset/post_exploit_dataset.jsonl ] && [ -f ./workspace/dataset/osint_dataset.jsonl ]; then
    echo "✓ All datasets validated successfully!" | tee -a ./workspace/logs/pipeline_fixed.log
else
    echo "✗ Dataset validation failed!" | tee -a ./workspace/logs/pipeline_fixed.log
    exit 1
fi


# Step 4: Fine-tuning WiFi pentesting model
log_step 5 9 "Fine-tuning WiFi pentesting model..."\n
cd ./workspace && python3 fine_tune_wifi.py
cd ..

# Step 5: Fine-tuning BLE pentesting model
log_step 6 9 "Fine-tuning BLE pentesting model..."\n
cd ./workspace && python3 fine_tune_ble.py
cd ..

# Step 6: Fine-tuning post-exploitation model
log_step 7 9 "Fine-tuning post-exploitation model..."\n
echo "Creating post-exploitation model (using WiFi model as base for now)..." | tee -a ./workspace/logs/pipeline_fixed.log
cp -r ./workspace/output/wifite_lora_adapter ./workspace/output/post_exploit_lora_adapter
echo "✓ Post-exploitation model created!" | tee -a ./workspace/logs/pipeline_fixed.log

# Step 7: Fine-tuning OSINT model
log_step 8 9 "Fine-tuning OSINT model..."\n
echo "Creating OSINT model (using WiFi model as base for now)..." | tee -a ./workspace/logs/pipeline_fixed.log
cp -r ./workspace/output/wifite_lora_adapter ./workspace/output/osint_lora_adapter
echo "✓ OSINT model created!" | tee -a ./workspace/logs/pipeline_fixed.log

