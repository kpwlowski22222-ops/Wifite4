# KFIOSA / Wifite4

**AI-driven offensive-security TUI** for authorized wireless, BLE, and OSINT work.  
Pure Python + **curses** (wifite-style), Linux-first, Kali-friendly.

```
python main.py
# or
./run_tui.sh
```

Main menu: **WiFi Scan · BLE Scan · OSINT · Settings · Quit**.

> **Legal:** Use only on systems and networks you own or are explicitly authorized to test. Active WiFi/BLE modules can disrupt services.

---

## What it is

KFIOSA plans attack/recon **chains with local/cloud LLMs**, then runs **real tools** (airodump-ng, hashcat, gatttool, holehe, NVD, …) behind a per-step **ACCEPT / CANCEL** gate. Missing tools produce **honest errors** — not fake “success.”

| Surface | What you get |
|---------|----------------|
| **WiFi** | Scan → target → one-click / AIO / AI chain; MT7922/`mt7921e` injection; 80+ attack modules + 60 extended 802.11 modules |
| **BLE** | Bleak scan, GATT recon, 50+ probe modules, 60+ attack modules |
| **OSINT** | People/email/username/domain/social, 90+ tool modules, Polish registries, Shodan/NVD |
| **Post-access** | After shell/creds: Post-Access TUI (shell, files, portfwd/SOCKS, persistence) |
| **Catalog** | ~5 100 tool entries (GitHub + Kali) with chain examples and install metadata |

---

## Quick start

```bash
git clone https://github.com/kpwlowski22222-ops/Wifite4.git
cd Wifite4

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# optional: copy and fill only the keys you need
cp .env.example .env

# Ollama recommended (primary AI path)
# ollama serve && ollama pull minimax-m3:cloud   # or a local tag

python main.py
# or: ./run_tui.sh
```

**Requirements:** Python **3.10+**, Linux (monitor-mode WiFi + BlueZ for BLE). Root/capabilities for injection and some scanners.

---

## AI models

Providers (in order): **Ollama** → DeepSeek → Groq → NVIDIA → Gemini → **heuristic planner**.

### Tier ladder (Ollama)

| Tier | Role | Model tag |
|------|------|-----------|
| 0 | Primary (cloud) | `minimax-m3:cloud` |
| 1 | Local fallback | `roleplaiapp/Qwen2.5-Coder-14B-Instruct-Uncensored-Q4_K_M-GGUF:Q4_K_M` |
| 2 | Planning overlay | `mradermacher/Qwen3.5-9B-Claude-4.6-HighIQ-THINKING-HERETIC-UNCENSORED-GGUF:latest` |
| 3 | MoE last resort | `mradermacher/Qwen3-Coder-30B-A3B-Instruct-uncensored-i1-GGUF:latest` |
| 4 | Legacy | `wizard-vicuna-uncensored:latest` / `llama2-uncensored:latest` |

### Per-domain defaults

| Domain | Model |
|--------|--------|
| WiFi / BLE | `xploiter/pentester:latest` |
| OSINT | `huihui_ai/phi4-abliterated:latest` |
| Post-exploit / forensics | `huihui_ai/foundation-sec-abliterated:8b-fp16` |
| C2 | `supergoatscriptguy/mythos-sec:24b` |

### Other ML

- **0-day triage classifier:** `cpranavsharma/Zero-Day-Agent` (Hugging Face; scores hypotheses only)
- **Exploit-body generation:** uncensored Ollama ladder via `ExploitGenModelManager`
- Override primary tag with `OLLAMA_DEFAULT_MODEL` / enable cloud with `OLLAMA_CLOUD_TOKEN`

---

## WiFi capabilities

**Hardware focus:** MediaTek **MT7922 / `mt7921e`** + generic mac80211 (`airmon-ng` / `iw`).

### Scan & recon

- `airodump-ng` scan, interface/monitor management, WPS probe  
- Enhanced scan + **NVD CVE** keyword correlation  
- **Kismet** server/client helpers (`KISMET_API_KEY`)  
- Catalog recon: clients, hidden SSID, signal map, handshake/EAPOL, channel plan, wardrive fuse, weakpass wordlists  

### Attack engine (`core/wifi_attack` + `core/extended_wifi`)

Examples (not exhaustive):

- Evil twin / karma-mana / captive portal  
- Handshake + **PMKID** (hashcat 16800/22001), live **hcxdumptool**  
- Deauth, MDK3/4, beacon flood, SAE/Dragonblood, WPA3/OWE/PMF  
- Enterprise EAP/PEAP paths, WPS, KR00K  
- Wi‑Fi **6 / 6E / 7** (OFDMA, MLO, HE/EHT-related modules)  
- Adaptive pickers (vendor, congestion, client count, PMF)  

**Tools commonly driven:** airodump-ng, aireplay-ng, aircrack-ng, hashcat, hcxtools, reaver, bully, mdk3/4, hostapd, scapy, iw.

### WiFi screen flow

1. Advanced → pick interface → monitor mode  
2. Scan → select AP  
3. One-click / AIO / **AI attack chain**  
4. Optional 0-day attach, post-exploit, Metasploit, C2 beacon  

---

## BLE capabilities

**Adapter:** HCI (`hci0` default); picker in `core/ble/adapter_select.py`.

### Probe (`BLEProbeRunner`)

AD parse, manufacturer/OUI, GATT map, pairing risk, OTA recon, MITM feasibility, health profiles, **mesh**, LE Audio, Find My / Fast Pair / Swift Pair, privacy (RPA, churn, randomization), presence/dwell classifiers.

### Attack (`BLEAttackRunner`)

GATT read/write/firmware dump, pairing PIN, ADV injection, connection hijack/MITM helpers, HID injection, energy drain, L2CAP/ISO/mesh-related modules, auto-attack orchestration — all with **honest degrade** if `btmgmt` / `gatttool` / scapy are missing.

**Libs/tools:** bleak, bluetoothctl, hcitool, gatttool, btmgmt.

---

## OSINT capabilities

Three layers:

1. **Catalog runner** — accept-gated CLI tools by category (people, email, username, domain, phone, social).  
2. **Module library** (~90 functions) — holehe, sherlock, maigret, whois, amass/subfinder, nmap/masscan, httpx, trufflehog/gitleaks, cloud enum, Shodan/Censys-style helpers, WiGLE, etc.  
3. **Extension runner** — deep graphing, dorks, leak/CT helpers, and a large **Poland-specific** stack (CEIDG, KRS, GUS, KNF, Allegro, PL social, PESEL/NIP/REGON validators).

Optional APIs: `SHODAN_API_KEY`, `NVD_API_KEY`.

---

## Platform modules

| Area | Path / notes |
|------|----------------|
| Dashboard / TUI | `core/tui/` |
| AI backend + chain planner | `core/ai_backend/` |
| Autonomous orchestrator | `core/orchestrator/` |
| Post-exploit + anti-forensics | `core/post_exploit/` |
| Post-access TUI / RAT ext | `core/post_access_tui/` |
| C2 lab beacon | `core/c2/` |
| Android / iOS / Microsoft | `core/android`, `core/ios`, `core/microsoft` (+ Frida) |
| Tool catalog + installer | `catalog/`, `core/tool_installer/`, `core/toolbox/` |
| Exploit knowledge base | `data/exploit_knowledge.db`, `core/exploit_knowledge_base.py` |
| MCP (in-process / loopback) | `core/mcp/` — agents can call tools while the TUI runs |
| Settings | `config/dashboard_settings.json`, `.env` |

---

## Configuration

Copy `.env.example` → `.env`. All keys optional; the TUI reports **MISSING** when a feature cannot run.

| Variable | Purpose |
|----------|---------|
| `OLLAMA_CLOUD_TOKEN` | Cloud primary (`minimax-m3:cloud`) |
| `OLLAMA_DEFAULT_MODEL` | Override Ollama model tag |
| `GROQ_API_KEY` / `GROQ_MODEL` | Groq fallback |
| `DEEPSEEK_API_KEY` / `DEEPSEEK_MODEL` | DeepSeek |
| `GEMINI_API_KEY` | Gemini routes |
| `SHODAN_API_KEY` | Shodan OSINT |
| `NVD_API_KEY` | NVD rate limits |
| `HF_TOKEN` | Gated Hugging Face pulls |
| `KISMET_API_KEY` | Local Kismet API |
| Metasploit host/port/user/pass | Via settings JSON |

Never commit `.env`, OAuth client secrets, or live capture databases.

---

## Project layout

```
main.py                 # curses dashboard entry
run_tui.sh / run.sh     # launch helpers
core/
  tui/                  # WiFi / BLE / OSINT / Settings screens
  wifi_attack/          # WiFi attack runner
  extended_wifi/        # Wi‑Fi 6/7 + advanced modules
  ble/                  # BLE probe + attack
  extended_ble/         # BLE 5.x extended attacks
  osint/                # OSINT runners + Polish modules
  ai_backend/           # Ollama, chain planner, 0-day path
  orchestrator/         # autonomous chain execution
  scanners/             # wifi / BLE / Kismet
  modules/              # mt7921e, CVE lookup, recon, MSF, …
  post_exploit/         # post-access modules
  post_access_tui/      # interactive session UI
  catalog/ tool_installer/ toolbox/
catalog/                # ~5k tool JSON entries
tests/                  # pytest suite
requirements.txt
.env.example
```

---

## Safety model

1. Offensive steps are **default-deny** until the operator ACCEPTs.  
2. Nested tools share the outer ACCEPT (`pre_accepted`) so you are not double-prompted.  
3. Monitor interfaces are torn down on quit.  
4. No fabricated scan/CVE/breach “success” for missing tools — empty results + explicit errors.

---

## Development

```bash
source .venv/bin/activate
pip install -r requirements.txt
pytest tests/ -q          # full suite is large; use -k for focus
```

Known issues and phase status: `KNOWN_ISSUES.md`, `TODO.md`.

---

## License

See [LICENSE](LICENSE).

---

## Disclaimer

This software is for **education and authorized penetration testing** only.  
You are solely responsible for compliance with local law and engagement rules of engagement.
