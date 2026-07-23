<![CDATA[<div align="center">

# 🛡️ KFIOSA / Wifite4

**AI-Driven Offensive Security TUI for WiFi, BLE, OSINT & Post-Exploitation**

[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![Platform: Linux](https://img.shields.io/badge/Platform-Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black)](https://kernel.org)
[![Kali Friendly](https://img.shields.io/badge/Kali-Friendly-557C94?style=for-the-badge&logo=kalilinux&logoColor=white)](https://kali.org)

Pure Python + **curses** • wifite-style interface • AI-powered attack chains  
Local & cloud LLM support • 5,100+ cataloged tools • ACCEPT/CANCEL safety gates

```
sudo python main.py          # launch dashboard
./run_tui.sh                  # alternative launcher
```

**Main Menu:** WiFi Scan · BLE Scan · OSINT · Settings · Quit

---

> **⚠️ Legal Notice:** This software is intended **exclusively** for authorized security testing and education.
> Use only on systems and networks you own or have explicit written authorization to test.
> Active WiFi/BLE modules can disrupt services. You are solely responsible for compliance with local law.

</div>

---

## 📋 Table of Contents

- [What is KFIOSA](#-what-is-kfiosa)
- [Feature Matrix](#-feature-matrix)
- [Architecture Overview](#-architecture-overview)
- [Quick Start](#-quick-start)
- [AI Models & Providers](#-ai-models--providers)
- [WiFi Capabilities](#-wifi-capabilities)
- [BLE Capabilities](#-ble-capabilities)
- [OSINT Capabilities](#-osint-capabilities)
- [Post-Exploitation & Post-Access](#-post-exploitation--post-access)
- [CVE-to-Exploit Pipeline](#-cve-to-exploit-pipeline)
- [Polymorphic Evasion Engine](#-polymorphic-evasion-engine)
- [Autonomous Orchestrator](#-autonomous-orchestrator)
- [MCP Server](#-mcp-server)
- [Holographic Desktop Agent](#-holographic-desktop-agent)
- [Tool Catalog](#-tool-catalog)
- [Configuration](#%EF%B8%8F-configuration)
- [Project Layout](#-project-layout)
- [Safety Model](#-safety-model)
- [Development & Testing](#-development--testing)
- [Known Issues & Roadmap](#-known-issues--roadmap)
- [License](#-license)
- [Disclaimer](#%EF%B8%8F-disclaimer)

---

## 🔍 What is KFIOSA

KFIOSA (also known as **Wifite4**) is a next-generation, AI-driven offensive security platform that combines:

1. **LLM-powered attack planning** — Local/cloud LLMs analyze targets and generate multi-step attack chains with tool selection, parameter tuning, and adaptive replanning.
2. **Real tool execution** — Actually runs `airodump-ng`, `hashcat`, `gatttool`, `holehe`, NVD queries, Metasploit, and hundreds more — behind per-step safety gates.
3. **Honest results** — No fabricated "success" output. Missing tools produce explicit errors and status degradation, never fake data.
4. **wifite-style TUI** — A full-screen curses dashboard with keyboard navigation, live scan visualization, color-coded status, and interactive menus.

### Core Design Principles

| Principle | Implementation |
|-----------|---------------|
| **Default-deny execution** | Every offensive step requires ACCEPT before running |
| **Graceful degradation** | Missing tools/APIs → honest errors, not fake success |
| **Multi-model AI** | 5-tier Ollama ladder + DeepSeek, Groq, NVIDIA, Gemini fallbacks |
| **Domain-specific models** | WiFi, BLE, OSINT, post-exploit each use specialized models |
| **Extensible catalog** | ~5,100 tool entries with install metadata and chain examples |

---

## 🎯 Feature Matrix

| Attack Surface | Capabilities | Module Count |
|---------------|-------------|-------------|
| **WiFi** | Scan → target → one-click / AIO / AI chain; MT7922/`mt7921e` injection; deauth, evil twin, PMKID, WPA3, Wi-Fi 6/7 | 80+ attack modules + 60 extended 802.11 modules |
| **BLE** | Bleak scan, GATT recon, pairing attacks, HID injection, mesh, LE Audio, Find My/Fast Pair | 50+ probe modules + 60+ attack modules |
| **OSINT** | People/email/username/domain/social/phone; Shodan/NVD; Polish registries (CEIDG, KRS, GUS) | 90+ tool modules |
| **Post-Access** | Interactive shell, file browser, port forwarding/SOCKS, persistence, privilege escalation | Post-Access TUI with RAT extensions |
| **Post-Exploit** | Anti-forensics, log cleaning, artifact wiping, OPSEC modules | 60+ anti-forensic modules |
| **CVE Pipeline** | NVD lookup → exploit match → PoC generation → 0-day triage | Automated pipeline |
| **C2 Lab** | DNS/HTTP beacon, encrypted channels, session management | C2 lab framework |
| **Mobile** | Android/iOS instrumentation via Frida, Microsoft-specific modules | Platform-specific modules |
| **Catalog** | ~5,100 tool entries (GitHub + Kali) with chain examples and install metadata | JSON catalog database |

---

## 🏗 Architecture Overview

```
┌──────────────────────────────────────────────────────────────┐
│                        main.py                                │
│              Preflight → Ollama bootstrap → curses             │
├──────────────────────────────────────────────────────────────┤
│                    core/tui/dashboard.py                       │
│          ┌────────┬──────────┬────────┬──────────┐            │
│          │ WiFi   │   BLE    │ OSINT  │ Settings │            │
│          │ Screen │  Screen  │ Screen │  Screen  │            │
│          └───┬────┴────┬─────┴───┬────┴────┬─────┘            │
├──────────────┼─────────┼─────────┼─────────┼─────────────────┤
│              │         │         │         │                  │
│  ┌───────────▼───┐ ┌───▼───┐ ┌──▼──┐  ┌──▼──────────┐       │
│  │ wifi_attack/  │ │ ble/  │ │osint│  │  settings    │       │
│  │ extended_wifi/│ │ext_ble│ │     │  │  bootstrap   │       │
│  └───────┬───────┘ └───┬───┘ └──┬──┘  └─────────────┘       │
│          │             │        │                             │
├──────────▼─────────────▼────────▼────────────────────────────┤
│                  core/ai_backend/                             │
│     chain.py (ChainPlanner) + __init__.py (AIBackend)         │
│     Ollama → DeepSeek → Groq → NVIDIA → Gemini → Heuristic   │
├──────────────────────────────────────────────────────────────┤
│               core/orchestrator/                              │
│    autonomous_orchestrator.py + adaptive_engagement.py         │
├──────────────────────────────────────────────────────────────┤
│  core/modules/                                                │
│  ┌─────────────┬───────────────┬──────────────────┐           │
│  │ ai_planner   │ cve_lookup    │ reconnaissance   │           │
│  │ polymorphic  │ metasploit    │ kali_tools       │           │
│  │ post_exploit │               │                  │           │
│  └─────────────┴───────────────┴──────────────────┘           │
├──────────────────────────────────────────────────────────────┤
│  Catalog (~5100 entries) │ Tool Installer │ Exploit KB (SQLite)│
└──────────────────────────────────────────────────────────────┘
```

### Key Subsystems

| Subsystem | Path | Responsibility |
|-----------|------|----------------|
| **TUI Dashboard** | `core/tui/` | Curses-based full-screen interface with 5-item menu |
| **AI Backend** | `core/ai_backend/` | Multi-provider LLM chain planner with domain routing |
| **Chain Planner** | `core/ai_backend/chain.py` | Multi-step attack chain generation, step execution, replanning |
| **Autonomous Orchestrator** | `core/orchestrator/` | Self-directed chain execution with adaptive engagement |
| **WiFi Attack Engine** | `core/wifi_attack/` + `core/extended_wifi/` | 140+ WiFi attack/scan modules |
| **BLE Engine** | `core/ble/` + `core/extended_ble/` | BLE probe, attack, and GATT exploration |
| **OSINT Engine** | `core/osint/` | Multi-layer OSINT with Polish-specific modules |
| **Post-Exploit** | `core/post_exploit/` | 60+ anti-forensic and OPSEC modules |
| **Post-Access TUI** | `core/post_access_tui/` | Interactive session management with RAT extensions |
| **CVE Pipeline** | `core/cve_to_exploit/` | NVD → exploit matching → PoC generation |
| **Polymorphic Engine** | `core/modules/polymorphic_evasion.py` | Payload mutation, encoding chains, signature evasion |
| **Exploit Knowledge Base** | `core/exploit_knowledge_base.py` | SQLite DB with exploit metadata and chain patterns |
| **Tool Catalog** | `catalog/` + `core/catalog/` | ~5,100 tool entries with install/chain metadata |
| **Tool Installer** | `core/tool_installer/` | Auto-install missing dependencies |
| **Scanners** | `core/scanners/` | WiFi, BLE, and Kismet scan backends |
| **C2 Lab** | `core/c2/` | DNS/HTTP beacon framework for testing |
| **Mobile** | `core/android/`, `core/ios/`, `core/microsoft/` | Frida-based mobile instrumentation |
| **MCP Server** | `core/mcp/` | Model Context Protocol for agent tool access |
| **Desktop Agent** | `core/desktop/` | Holographic desktop agent integration |
| **Database** | `core/db/` | SQLite backend with optimized indexes |
| **Live Edit/Target** | `core/live_edit/`, `core/live_target/` | Runtime overlay and live target management |
| **Recon** | `core/recon/` | Reconnaissance primitives |
| **Replan** | `core/replan/` | Chain replanning logic |
| **Forensics** | `core/forensics/` | Digital forensics modules |
| **Neuroscience** | `core/neuroscience/` | Experimental behavioral analysis modules |
| **Settings** | `core/settings.py` | Runtime configuration manager |

---

## 🚀 Quick Start

### Prerequisites

- **OS:** Linux (Kali Linux recommended)
- **Python:** 3.10 or higher
- **Hardware (WiFi):** MediaTek MT7922 / `mt7921e` or any mac80211 adapter for monitor mode
- **Hardware (BLE):** Any BlueZ-compatible HCI adapter
- **Root/sudo:** Required for monitor mode, injection, and some scanners

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/kpwlowski22222-ops/Wifite4.git
cd Wifite4

# 2. Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 3. Install Python dependencies
pip install -r requirements.txt

# 4. Copy environment template (all keys optional)
cp .env.example .env
# Edit .env and fill in API keys you want to use

# 5. (Recommended) Install Ollama for AI features
curl -fsSL https://ollama.com/install.sh | sh
ollama serve &
ollama pull minimax-m3:cloud    # primary cloud model
# Or pull a local model:
# ollama pull qwen2.5-coder:14b
```

### Launch

```bash
# Launch the TUI dashboard (recommended)
sudo python main.py

# Alternative launcher script
sudo ./run_tui.sh

# Run the full pipeline (advanced)
sudo ./run_full_pipeline.sh
```

### First Run

On first launch, KFIOSA will:
1. Expand `PATH` for common tool locations (`/usr/local/bin`, etc.)
2. Load settings from `config/dashboard_settings.json`
3. Probe/start `ollama serve` if available
4. Run preflight checks for dependencies
5. Launch the curses dashboard

---

## 🤖 AI Models & Providers

KFIOSA uses a sophisticated multi-provider AI backend with automatic fallback:

### Provider Chain (priority order)

```
Ollama (local/cloud) → DeepSeek → Groq → NVIDIA → Gemini → Heuristic Planner
```

If the top provider is unavailable, the system cascades to the next. The final fallback is a rule-based heuristic planner that works without any AI provider.

### Ollama Tier Ladder

| Tier | Role | Model Tag | Notes |
|------|------|-----------|-------|
| **0** | Primary (cloud) | `minimax-m3:cloud` | Cloud-routed, requires `OLLAMA_CLOUD_TOKEN` |
| **1** | Local fallback | `roleplaiapp/Qwen2.5-Coder-14B-Instruct-Uncensored-Q4_K_M-GGUF:Q4_K_M` | ~9GB VRAM hybrid |
| **2** | Planning overlay | `mradermacher/Qwen3.5-9B-Claude-4.6-HighIQ-THINKING-HERETIC-UNCENSORED-GGUF:latest` | High-IQ reasoning |
| **3** | MoE last resort | `mradermacher/Qwen3-Coder-30B-A3B-Instruct-uncensored-i1-GGUF:latest` | Mixture of Experts |
| **4** | Legacy | `wizard-vicuna-uncensored:latest` / `llama2-uncensored:latest` | Compatibility layer |

### Domain-Specific Models

Each attack surface uses a specialized model for optimal results:

| Domain | Model | Purpose |
|--------|-------|---------|
| **WiFi / BLE** | `xploiter/pentester:latest` | Wireless-specific attack reasoning |
| **OSINT** | `huihui_ai/phi4-abliterated:latest` | Open-source intelligence analysis |
| **Post-exploit / Forensics** | `huihui_ai/foundation-sec-abliterated:8b-fp16` | Post-access operations |
| **C2** | `supergoatscriptguy/mythos-sec:24b` | Command & Control reasoning |

### Additional ML Components

| Component | Model/Source | Role |
|-----------|-------------|------|
| **Zero-Day Triage Classifier** | `cpranavsharma/Zero-Day-Agent` (Hugging Face) | Scores 0-day hypotheses — classification only |
| **Exploit Body Generator** | Uncensored Ollama ladder via `ExploitGenModelManager` | PoC code generation |
| **Chain Planner** | Primary Ollama model | Multi-step attack chain reasoning |

Override the primary model: set `OLLAMA_DEFAULT_MODEL` in `.env`.

---

## 📡 WiFi Capabilities

**Hardware focus:** MediaTek **MT7922 / `mt7921e`** + generic mac80211 adapters (`airmon-ng` / `iw`).

### Scan & Reconnaissance

- `airodump-ng` scan with live parsing and target selection
- Interface management and monitor mode toggling
- WPS probe and status detection
- Enhanced scan with **NVD CVE** keyword correlation
- **Kismet** server/client helpers (requires `KISMET_API_KEY`)
- Catalog-based recon: client enumeration, hidden SSID detection, signal mapping, handshake/EAPOL capture, channel planning, wardrive data fusion, weakpass wordlists

### Attack Engine

Located in `core/wifi_attack/` and `core/extended_wifi/` — **140+ modules** including:

| Category | Examples |
|----------|---------|
| **Evil Twin / Rogue AP** | Evil twin, karma-MANA, captive portal generation |
| **Handshake Capture** | WPA/WPA2 handshake + **PMKID** (hashcat modes 16800/22001) |
| **Packet Capture** | Live `hcxdumptool` integration |
| **Deauthentication** | Targeted/broadcast deauth, MDK3/MDK4 attacks |
| **Flooding** | Beacon flood, authentication flood |
| **WPA3/SAE** | SAE/Dragonblood attacks, OWE, PMF bypass |
| **Enterprise** | EAP/PEAP credential harvesting paths |
| **WPS** | Reaver, Bully, pixie-dust attacks |
| **KR00K** | CVE-2019-15126 exploitation |
| **Wi-Fi 6/6E/7** | OFDMA, MLO, HE/EHT-related attack modules |
| **Adaptive Selection** | Vendor-aware, congestion-aware, client-count, PMF-aware pickers |

**External tools commonly driven:** airodump-ng, aireplay-ng, aircrack-ng, hashcat, hcxtools, hcxdumptool, reaver, bully, mdk3/mdk4, hostapd, scapy, iw.

### WiFi Screen Flow

```
1. Advanced → pick wireless interface → enable monitor mode
2. Scan → view discovered APs → select target
3. Choose attack mode:
   ├── One-click attack (fastest single attack)
   ├── AIO (All-In-One — tries multiple attacks)
   └── AI attack chain (LLM plans multi-step campaign)
4. Optional extensions:
   ├── 0-day hypothesis attach
   ├── Post-exploit pivot
   ├── Metasploit integration
   └── C2 beacon deployment
```

---

## 📶 BLE Capabilities

**Adapter:** Any BlueZ-compatible HCI adapter (`hci0` default); interface picker in `core/ble/adapter_select.py`.

### Probe Engine (`BLEProbeRunner`) — 50+ Modules

| Category | Capabilities |
|----------|-------------|
| **Discovery** | AD type parsing, manufacturer/OUI lookup, service UUID resolution |
| **GATT Exploration** | Full GATT map, characteristic read/write, descriptor enumeration |
| **Pairing Analysis** | Pairing risk assessment, PIN analysis, bonding state detection |
| **OTA Recon** | Over-the-air reconnaissance, firmware version detection |
| **MITM Feasibility** | Man-in-the-middle attack surface analysis |
| **Health Profiles** | Medical device protocol identification |
| **Mesh Networks** | Bluetooth Mesh topology mapping |
| **LE Audio** | Low Energy Audio capability detection |
| **Tracker Detection** | Find My, Fast Pair, Swift Pair identification |
| **Privacy Analysis** | RPA detection, address churn, randomization assessment |
| **Presence** | Dwell time classification, occupancy analysis |

### Attack Engine (`BLEAttackRunner`) — 60+ Modules

| Category | Capabilities |
|----------|-------------|
| **GATT Attacks** | Read/write/notify abuse, firmware dump, characteristic injection |
| **Pairing** | PIN brute force, Just Works exploitation, LESC downgrade |
| **ADV Injection** | Advertisement spoofing, beacon injection |
| **Connection** | Hijack helpers, MITM relay, connection parameter manipulation |
| **HID Injection** | Keyboard/mouse injection via BLE HID profile |
| **Energy Drain** | Battery exhaustion attacks |
| **L2CAP/ISO** | Low-level protocol attacks |
| **Mesh** | Mesh network provisioning and disruption |
| **Auto-orchestration** | AI-directed multi-step BLE campaigns |

All modules feature **honest degradation** — if `btmgmt`, `gatttool`, or scapy are missing, the module reports the error explicitly instead of faking results.

**Libraries/tools:** bleak, bluetoothctl, hcitool, gatttool, btmgmt, scapy.

---

## 🔎 OSINT Capabilities

Three-layer architecture with ~90+ integrated tool modules:

### Layer 1: Catalog Runner
Accept-gated CLI tool execution by category:
- **People** — identity resolution, social graph mapping
- **Email** — holehe, breach lookup, mail server analysis
- **Username** — sherlock, maigret, cross-platform enumeration
- **Domain** — whois, DNS recon, subfinder, amass, certificate transparency
- **Phone** — carrier lookup, HLR query helpers
- **Social** — platform-specific scrapers and analyzers

### Layer 2: Module Library (~90 Functions)

| Tool/Integration | Purpose |
|-----------------|---------|
| **holehe** | Email-to-account discovery |
| **sherlock / maigret** | Username cross-platform search |
| **whois** | Domain/IP registration lookup |
| **amass / subfinder** | Subdomain enumeration |
| **nmap / masscan** | Port scanning and service detection |
| **httpx** | HTTP probing and tech fingerprinting |
| **trufflehog / gitleaks** | Secret/credential detection in repos |
| **Cloud enum** | AWS/GCP/Azure resource enumeration |
| **Shodan / Censys** | Internet-wide host intelligence |
| **WiGLE** | Wireless network geolocation |
| **NVD** | CVE/vulnerability correlation |

### Layer 3: Extension Runner (Poland-Specific Stack)

| Registry | Data Source |
|----------|-----------|
| **CEIDG** | Polish business registry (sole proprietors) |
| **KRS** | National Court Register (companies) |
| **GUS (REGON)** | Central Statistical Office |
| **KNF** | Financial Supervision Authority |
| **Allegro** | Polish marketplace intelligence |
| **PL Social** | Polish social media platform scrapers |
| **PESEL/NIP/REGON** | National ID number validators |

Additional: deep graphing, Google dorks, leak/CT helpers, data correlation engine.

**Optional API keys:** `SHODAN_API_KEY`, `NVD_API_KEY`.

---

## 🔓 Post-Exploitation & Post-Access

### Post-Exploit Modules (`core/post_exploit/`)

60+ anti-forensic and OPSEC modules organized by category:

| Category | Examples |
|----------|---------|
| **Log Cleaning** | syslog wipe, auth log sanitization, journal tampering |
| **Artifact Wiping** | bash history, file timestamps, temp file removal |
| **Anti-Forensics** | Disk artifact destruction, memory scrubbing |
| **Persistence** | Cron jobs, systemd services, SSH key injection |
| **Privilege Escalation** | SUID/capability abuse, kernel exploit wrappers |
| **Credential Harvesting** | `/etc/shadow` extraction, SSH key collection |
| **Network Pivoting** | Port forwarding, SOCKS proxy, tunnel setup |
| **OPSEC** | MAC randomization, traffic obfuscation |

### Post-Access TUI (`core/post_access_tui/`)

Interactive session management interface after gaining access:

- **Shell panel** — Interactive shell on compromised host
- **File browser** — Remote filesystem navigation and exfiltration
- **Port forwarding / SOCKS** — Network tunneling setup
- **Persistence manager** — Deploy/manage persistence mechanisms
- **WiFi panel** — Wireless operations from compromised host
- **BLE panel** — BLE operations from compromised host
- **RAT extensions** — Remote Access Toolkit with JWT authentication and dynamic payload generation (`v5_enhancements`)

---

## 🔬 CVE-to-Exploit Pipeline

Located in `core/cve_to_exploit/`:

```
NVD Query → CVE Match → Exploit Database Correlation → PoC Template Selection
    ↓              ↓                  ↓                         ↓
 CVSS Score    Affected         ExploitDB /              AI-Generated
 Assessment    Products         GitHub Match              Exploit Body
    ↓              ↓                  ↓                         ↓
    └──────── Ranked Exploit Candidates ──────── 0-Day Triage ──┘
                                                 (HF classifier)
```

### Zero-Day Research

- **Draft storage:** `data/zero_day_drafts/` — JSON-serialized 0-day hypotheses
- **Triage classifier:** `cpranavsharma/Zero-Day-Agent` from Hugging Face — scores plausibility
- **Exploit body generation:** Uses uncensored Ollama models via `ExploitGenModelManager`
- **Knowledge base:** SQLite DB at `data/exploit_knowledge.db` with indexed exploit metadata

---

## 🎭 Polymorphic Evasion Engine

`core/modules/polymorphic_evasion.py` + `core/refactors/poly_adapt_companions.py`

The polymorphic engine mutates payloads to evade signature-based detection:

| Feature | Description |
|---------|-------------|
| **Encoding chains** | Multi-layer encoding (base64, XOR, AES, custom) |
| **Dead code injection** | Random NOPs and junk instructions |
| **Variable renaming** | Randomized identifier substitution |
| **Control flow obfuscation** | Opaque predicates, CFG flattening |
| **String encryption** | Runtime string decryption stubs |
| **Target-adaptive methods** | 20+ polymorphic + 20 target-adaptive mutation strategies |
| **Companion modules** | Poly-adapt companion helpers for complex transformations |

---

## 🤖 Autonomous Orchestrator

`core/orchestrator/autonomous_orchestrator.py` + `core/orchestrator/adaptive_engagement.py`

The orchestrator enables fully autonomous or semi-autonomous attack campaigns:

| Feature | Description |
|---------|-------------|
| **Chain execution** | Executes AI-planned multi-step attack chains |
| **Replanning** | Dynamically adjusts plan based on step results |
| **Adaptive engagement** | Adjusts attack intensity and technique selection based on target responses |
| **Step gating** | ACCEPT/CANCEL gates at configurable granularity |
| **Result aggregation** | Collects and correlates results across chain steps |
| **Error recovery** | Graceful handling of tool failures with fallback strategies |

---

## 🔌 MCP Server

`core/mcp/` — Model Context Protocol server for agent tool access.

Enables external AI agents to invoke KFIOSA's tools programmatically while the TUI runs. This allows:
- Multi-agent collaboration on complex engagements
- Programmatic access to scan, attack, and OSINT functions
- Integration with other MCP-compatible AI frameworks

---

## 🖥️ Holographic Desktop Agent

`core/desktop/holo_agent.py` — Experimental desktop agent integration for extended UI capabilities beyond the terminal TUI.

---

## 📚 Tool Catalog

Located in `catalog/` with ~5,100 entries spanning GitHub repositories and Kali Linux packages.

### Catalog Schema (v1.1.0)

Each entry includes:
- **Tool name and description**
- **Source URL** (GitHub/package)
- **Install commands** (apt, pip, git clone, etc.)
- **Attack surface tags** (`wifi`, `ble`, `osint`, `exploit`, etc.)
- **Phase hints** (`recon`, `exploit`, `post-exploit`, etc.)
- **Hardware requirements** (`requires_hardware`)
- **Chain examples** — Pre-built usage patterns for the AI planner
- **Status** — Verified/unverified clone status

### Catalog Components

| Component | Path | Purpose |
|-----------|------|---------|
| Tool entries | `catalog/` | JSON tool definitions |
| Catalog loader | `core/utils/catalog_loader.py` | Runtime catalog parsing |
| Tool installer | `core/tool_installer/catalog.py` | Auto-install from catalog |
| Tool registry | `core/tool_registry.py` | Runtime tool registration |
| Algorithm registry | `core/algorithm_registry.py` | Attack algorithm indexing |
| HF registry | `pentest_hf_registry.py` | Hugging Face model catalog |

---

## ⚙️ Configuration

### Environment Variables (`.env`)

Copy `.env.example` → `.env`. **All keys are optional** — the TUI reports `MISSING` when a feature cannot run.

| Variable | Purpose | Required |
|----------|---------|----------|
| `OLLAMA_CLOUD_TOKEN` | Cloud primary model (`minimax-m3:cloud`) | No |
| `OLLAMA_DEFAULT_MODEL` | Override Ollama model tag | No |
| `GROQ_API_KEY` / `GROQ_MODEL` | Groq cloud fallback | No |
| `DEEPSEEK_API_KEY` / `DEEPSEEK_MODEL` | DeepSeek cloud fallback | No |
| `GEMINI_API_KEY` | Gemini routes | No |
| `SHODAN_API_KEY` | Shodan host/port enrichment (OSINT) | No |
| `NVD_API_KEY` | NVD CVE API (raises rate limit from 5/30s) | Recommended |
| `HF_TOKEN` | Gated Hugging Face model pulls | No |
| `KISMET_API_KEY` | Local Kismet server API | No |
| `GOOGLE_PROJECT_ID` | Google Cloud integration | No |
| `APP_URL` | Public URL for deployments | No |

### Dashboard Settings

Runtime configuration stored in `config/dashboard_settings.json`:
- Metasploit connection (host/port/user/pass)
- UI preferences
- Default scan parameters
- MCP configuration (`config/grok_mcp_config.json`)

### Security Notes

> **Never commit:** `.env`, OAuth client secrets (`client_secret_*.json`, `oauthadmin.json`), PEM/key files, or live capture databases (Kismet `.kismet` files).

---

## 📁 Project Layout

```
kfiosa/
├── main.py                          # Curses dashboard entry point
├── run.sh                           # CLI launcher script
├── run_tui.sh                       # TUI launcher script
├── run_full_pipeline.sh             # Full pipeline runner
├── run_full_pipeline_v2.sh          # Pipeline v2 (enhanced)
├── prepare.sh                       # Environment preparation script
├── prepare_ollama_finetune.sh       # Ollama fine-tune preparation
├── setup.py                         # Package setup (pip installable)
├── requirements.txt                 # Python dependencies
├── .env.example                     # Environment template
├── .gitignore                       # Git ignore rules
├── LICENSE                          # MIT License
├── README.md                        # This file
├── KNOWN_ISSUES.md                  # Known bugs and limitations
├── TODO.md                          # Development roadmap
├── pytest.ini                       # Test configuration
├── metadata.json                    # Project metadata
│
├── core/                            # Main source code
│   ├── tui/                         # Terminal UI screens
│   │   ├── dashboard.py             #   Main dashboard (5-item menu)
│   │   ├── wifi_screen.py           #   WiFi scan/attack screen
│   │   ├── ble_screen.py            #   BLE scan/attack screen
│   │   ├── osint_screen.py          #   OSINT screen
│   │   ├── settings_screen.py       #   Settings management
│   │   ├── device_screen.py         #   Device details view
│   │   ├── interface_picker.py      #   Network interface selector
│   │   ├── wifi_scan_external.py    #   External WiFi scan viewer
│   │   └── base_screen.py           #   Base screen class
│   │
│   ├── ai_backend/                  # AI/LLM integration
│   │   ├── __init__.py              #   AIBackend provider chain
│   │   └── chain.py                 #   ChainPlanner (multi-step reasoning)
│   │
│   ├── orchestrator/                # Autonomous execution
│   │   ├── __init__.py              #   Orchestrator initialization
│   │   ├── autonomous_orchestrator.py #   Self-directed chain runner
│   │   └── adaptive_engagement.py   #   Dynamic technique adaptation
│   │
│   ├── modules/                     # Core attack/recon modules
│   │   ├── ai_planner.py            #   AI-powered attack planning
│   │   ├── reconnaissance.py        #   Recon primitives
│   │   ├── cve_lookup.py            #   NVD CVE querying
│   │   ├── metasploit_integration.py#   Metasploit RPC integration
│   │   ├── kali_tools_integration.py#   Kali tool wrappers
│   │   ├── polymorphic_evasion.py   #   Payload mutation engine
│   │   └── post_exploitation.py     #   Post-exploit modules
│   │
│   ├── scanners/                    # Scan backends
│   │   ├── wifi_scanner.py          #   WiFi scanning (airodump-ng)
│   │   ├── enhanced_wifi_scanner.py #   Enhanced WiFi + CVE correlation
│   │   ├── enhanced_ble_scanner.py  #   Enhanced BLE scanning
│   │   ├── wifi_radio.py            #   Radio-level WiFi control
│   │   └── scan_limits.py           #   Scan rate limiting
│   │
│   ├── wifi_attack/                 # WiFi attack runners
│   ├── extended_wifi/               # Wi-Fi 6/7 + advanced modules
│   ├── ble/                         # BLE probe + attack
│   ├── extended_ble/                # BLE 5.x extended attacks
│   ├── osint/                       # OSINT runners + Polish modules
│   ├── post_exploit/                # 60+ post-exploit modules
│   ├── post_access_tui/             # Post-access interactive UI
│   │   ├── cli.py                   #   CLI interface
│   │   ├── menu_loop.py             #   Menu navigation
│   │   ├── wifi_panel.py            #   WiFi from compromised host
│   │   ├── ble_panel.py             #   BLE from compromised host
│   │   └── rat_ext/                 #   RAT extensions (auth, dynamic)
│   │
│   ├── cve_to_exploit/              # CVE → exploit pipeline
│   ├── c2/                          # C2 lab (DNS/HTTP beacon)
│   ├── mcp/                         # MCP server for agent access
│   ├── desktop/                     # Holographic desktop agent
│   ├── db/                          # SQLite database layer
│   ├── catalog/                     # Catalog management
│   ├── tool_installer/              # Auto-install from catalog
│   ├── toolbox/                     # Toolbox management
│   ├── integrations/                # External service integrations
│   ├── live_edit/                   # Runtime overlay system
│   ├── live_target/                 # Live target management
│   ├── recon/                       # Reconnaissance primitives
│   ├── replan/                      # Chain replanning logic
│   ├── refactors/                   # Poly-adapt companions
│   ├── forensics/                   # Digital forensics
│   ├── neuroscience/                # Experimental behavioral analysis
│   ├── android/                     # Android instrumentation (Frida)
│   ├── ios/                         # iOS instrumentation (Frida)
│   ├── microsoft/                   # Microsoft platform modules
│   ├── utils/                       # Shared utilities
│   │   ├── catalog_loader.py        #   Catalog file parser
│   │   ├── exploit_parser.py        #   Exploit output parser
│   │   ├── poly_adapt.py            #   Polymorphic adaptation helpers
│   │   └── ui_navigator.py          #   UI navigation utilities
│   │
│   ├── settings.py                  # Runtime settings manager
│   ├── bootstrap.py                 # Preflight + Ollama bootstrap
│   ├── optimizations.py             # Performance optimizations
│   ├── exploit_knowledge_base.py    # SQLite exploit KB
│   ├── tool_registry.py             # Runtime tool registration
│   ├── algorithm_registry.py        # Attack algorithm index
│   ├── osint_catalog.py             # OSINT tool catalog
│   └── mcp_server.py                # MCP server entry
│
├── catalog/                         # ~5,100 tool JSON entries
├── config/                          # Configuration files
│   ├── dashboard_settings.json      #   Dashboard preferences
│   └── grok_mcp_config.json         #   MCP configuration
│
├── data/                            # Runtime data
│   ├── exploit_knowledge.db         #   SQLite exploit database
│   └── zero_day_drafts/             #   0-day hypothesis drafts
│
├── datasets/                        # Training/reference datasets
├── docs/                            # Documentation
├── assets/                          # Project assets
├── scripts/                         # Helper scripts
│   ├── grok_mcp_bridge.py           #   MCP bridge for Grok
│   └── setup_grok_cowork.py         #   Grok co-working setup
│
├── tests/                           # pytest test suite
│   ├── conftest.py                  #   Test fixtures
│   ├── fakes.py                     #   Mock/fake objects
│   ├── test_bootstrap.py            #   Bootstrap tests
│   ├── test_chain_planner.py        #   Chain planner tests
│   ├── test_catalog_chain_examples.py #  Catalog chain tests
│   ├── test_poly_adapt_*.py         #   Polymorphic engine tests
│   ├── test_settings_screen_actions.py # Settings UI tests
│   ├── test_wifi_screen_actions.py  #   WiFi UI tests
│   ├── test_adaptive_engagement.py  #   Orchestrator tests
│   ├── test_scan_limits.py          #   Scan limiter tests
│   └── ...                          #   Additional test modules
│
├── wifi_offensive_ai/               # WiFi Offensive AI engine
│   └── core/engine.py               #   Core WiFi AI engine
│
├── ai_pentest_engine.py             # Standalone AI pentest engine
├── metasploit_post_exploit.py       # Metasploit post-exploit runner
├── pentest_hf_registry.py           # HuggingFace pentest model registry
└── pentest_hf_registry.json         # HF registry data
```

---

## 🛡 Safety Model

KFIOSA implements a defense-in-depth safety architecture:

### 1. ACCEPT / CANCEL Gate (Default-Deny)

Every offensive step requires explicit operator approval before execution. The TUI presents each planned action and waits for ACCEPT or CANCEL.

### 2. Nested Gate Inheritance (`pre_accepted`)

When a parent step is accepted, nested sub-tools inherit the acceptance flag to avoid double-prompting while maintaining the safety boundary.

### 3. Clean Teardown

Monitor-mode interfaces are automatically torn down on quit. Temporary processes (beacon, deauth, etc.) are killed on exit.

### 4. Honest Error Reporting

No fabricated results. If a tool is missing, unavailable, or fails:
- Empty result sets + explicit error messages
- `MISSING` status in the TUI for unconfigured features
- Error propagation to the orchestrator for replanning

### 5. Sensitive Data Protection

- `.env` and credentials excluded via `.gitignore`
- No API keys in source code
- OAuth secrets pattern-matched in `.gitignore`

---

## 🧪 Development & Testing

### Setup

```bash
source .venv/bin/activate
pip install -r requirements.txt
```

### Running Tests

```bash
# Full test suite (can be large)
pytest tests/ -q

# Focused testing
pytest tests/ -k "test_chain_planner" -v
pytest tests/ -k "test_bootstrap" -v
pytest tests/ -k "test_poly_adapt" -v

# With coverage
pytest tests/ --cov=core -q
```

### Test Configuration (`pytest.ini`)

```ini
[pytest]
testpaths = tests
python_files = test_*.py
python_functions = test_*
```

### Key Test Modules

| Test File | Coverage |
|-----------|----------|
| `test_bootstrap.py` | Preflight and Ollama bootstrap |
| `test_chain_planner.py` | AI chain planning logic |
| `test_catalog_chain_examples.py` | Catalog chain examples validation |
| `test_poly_adapt_*.py` | Polymorphic evasion engine |
| `test_settings_screen_actions.py` | Settings TUI actions |
| `test_wifi_screen_actions.py` | WiFi TUI actions |
| `test_adaptive_engagement.py` | Orchestrator adaptive engagement |
| `test_scan_limits.py` | Scan rate limiting |
| `test_holo_desktop.py` | Desktop agent |
| `test_wifi_radio.py` | WiFi radio control |

---

## 📋 Known Issues & Roadmap

See [KNOWN_ISSUES.md](KNOWN_ISSUES.md) for current bugs and limitations.

See [TODO.md](TODO.md) for the development roadmap, organized by phases:

- **Phase 1:** Core TUI + WiFi/BLE scan
- **Phase 2:** AI chain planner + exploit pipeline + catalog expansion
- **Phase 3:** SQL backends, extended BLE, polymorphic v4, dashboard v3
- **Phase 4:** Catalog enhancement, model upgrades, performance optimization
- **Phase 5+:** MCP server, desktop agent, adaptive engagement

---

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

```
MIT License — Copyright (c) 2026 WiFi Offensive AI Toolkit
```

---

## ⚖️ Disclaimer

> **This software is provided for education and authorized penetration testing only.**
>
> - You must have explicit, written authorization before testing any system or network.
> - Active wireless attacks (deauth, beacon flood, evil twin) can disrupt real services.
> - BLE attacks can interfere with medical and safety-critical devices.
> - OSINT operations must comply with privacy regulations (GDPR, local laws).
> - You are solely responsible for compliance with all applicable laws and rules of engagement.
>
> The authors and contributors assume **no liability** for misuse of this software.

---

<div align="center">

**Built with 🐍 Python • 🤖 AI-Powered • 📡 Wireless-Native • 🛡️ Ethically Gated**

</div>
]]>
