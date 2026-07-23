<div align="center">

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

**Main Menu:** WiFi · BLE · OSINT People · OSINT Web · Settings · Quit  
*(Post-exploit is auto-attached to engagement chains — not a separate menu mode.)*

---

> **⚠️ Legal Notice:** This software is intended **exclusively** for authorized security testing and education.
> Use only on systems and networks you own or have explicit written authorization to test.
> Active WiFi/BLE modules can disrupt services. You are solely responsible for compliance with local law.

</div>

---

## Table of Contents

- [What is KFIOSA](#what-is-kfiosa)
- [Feature Matrix](#feature-matrix)
- [Architecture Overview](#architecture-overview)
- [Dependencies](#dependencies)
- [Quick Start](#quick-start)
- [Large Archives (multi-part restore)](#large-archives-multi-part-restore)
- [AI Models & Providers](#ai-models--providers)
- [WiFi Capabilities](#wifi-capabilities)
- [BLE Capabilities](#ble-capabilities)
- [External Scan Windows & Terminal](#external-scan-windows--terminal)
- [Kismet Integration](#kismet-integration)
- [OSINT Capabilities](#osint-capabilities)
- [Post-Exploitation & Post-Access](#post-exploitation--post-access)
- [CVE-to-Exploit Pipeline](#cve-to-exploit-pipeline)
- [Polymorphic Evasion Engine](#polymorphic-evasion-engine)
- [Autonomous Orchestrator](#autonomous-orchestrator)
- [MCP Server](#mcp-server)
- [Holographic Desktop Agent](#holographic-desktop-agent)
- [Tool Catalog](#tool-catalog)
- [Configuration](#configuration)
- [Project Layout](#project-layout)
- [Safety Model](#safety-model)
- [Development & Testing](#development--testing)
- [Known Issues & Roadmap](#known-issues--roadmap)
- [License](#license)
- [Disclaimer](#disclaimer)

---

---

<a id="what-is-kfiosa"></a>
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

<a id="feature-matrix"></a>
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

<a id="architecture-overview"></a>
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

<a id="dependencies"></a>
## 📦 Dependencies

KFIOSA is a **Linux-first** stack. Missing tools degrade to honest errors — install only what you need for your engagement surface.

### Platform

| Requirement | Notes |
|-------------|--------|
| **OS** | Linux (Kali / Debian / Ubuntu recommended) |
| **Python** | **3.10+** (3.11+ recommended for newer Frida) |
| **Shell** | `bash` / `zsh`; `sudo` for monitor mode & injection |
| **Display** | X11 (or Wayland with XWayland) for external scan terminals |
| **Disk** | ≥2 GB for clone + venv; multi-GB if restoring `archives/toolboxes*` |
| **RAM / VRAM** | 8 GB+ for TUI alone; 12–32 GB VRAM for local 14B–30B Ollama models |

### Python (pip) — `requirements.txt`

Install into a virtualenv (never system-wide on Kali if you can avoid it):

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -U pip wheel
pip install -r requirements.txt
```

| Package | Role |
|---------|------|
| `requests`, `python-dotenv`, `aiohttp` | HTTP, env loading, async scanners |
| `torch`, `transformers`, `datasets`, `huggingface_hub` | Local ML / HF models / 0-day triage |
| `bleak` | BLE GATT / scan |
| `shodan` | OSINT Shodan API |
| `dnslib`, `pycryptodome` | C2 lab DNS/crypto |
| `pymetasploit3` | Metasploit RPC |
| `frida`, `frida-tools` | Mobile instrumentation (pinned for Py3.10) |
| `google-cloud-aiplatform`, `google-auth*`, `google-api-python-client` | Optional Google Cloud |
| `windows-curses` | **Windows only** (curses is stdlib on Linux) |

Optional extras used by advanced paths (install if you hit ImportError):

```bash
pip install scapy rich prompt-toolkit selenium playwright opencv-python-headless
pip install holo-desktop-cli   # OS desktop agent (Holo)
```

### System packages (apt / Kali)

**Core WiFi / radio**

```bash
sudo apt update
sudo apt install -y \
  aircrack-ng hashcat hcxtools hcxdumptool reaver bully mdk4 \
  hostapd dnsmasq iw wireless-tools net-tools \
  tcpdump wireshark-common tshark
```

**BLE**

```bash
sudo apt install -y bluez bluez-tools bluetooth rfkill
# optional long-range / HCI tools
sudo apt install -y bluez-hcidump || true
```

**OSINT / recon / general**

```bash
sudo apt install -y \
  nmap masscan nikto sqlmap whatweb \
  git curl wget jq zstd tar \
  python3-venv python3-dev build-essential \
  libffi-dev libssl-dev
```

**Metasploit / exploitation (optional)**

```bash
sudo apt install -y metasploit-framework
# or use official MSF installer
```

**Kismet (optional wireless IDS)**

```bash
sudo apt install -y kismet
# Web UI: http://127.0.0.1:2501  (default operator login often admin/admin
# after first-run config in /root/.kismet/kismet_httpd.conf)
```

**External terminal emulators** (for triple live scan windows)

```bash
sudo apt install -y xterm   # default; also supported: kitty foot alacritty
# optional: gnome-terminal xfce4-terminal konsole
```

### External services (optional)

| Service | Used for | Install / account |
|---------|----------|-------------------|
| **Ollama** | Primary LLM chain planner | https://ollama.com — `curl -fsSL https://ollama.com/install.sh \| sh` |
| **Groq / DeepSeek / Gemini** | Cloud LLM fallbacks | API keys in `.env` |
| **Shodan** | Host/port OSINT | `SHODAN_API_KEY` |
| **NVD** | CVE lookup rate limits | `NVD_API_KEY` (recommended) |
| **Hugging Face** | Gated models | `HF_TOKEN` |
| **Kismet** | Live wireless spectrum UI/API | local server + optional API token |

### Hardware

| Surface | Recommended hardware |
|---------|----------------------|
| **WiFi** | MediaTek **MT7922 / `mt7921e`** (injection-capable); any mac80211 NIC for monitor mode |
| **BLE** | BlueZ-compatible HCI (`hci0`); USB long-range adapters for field work |
| **GPU** | NVIDIA (CUDA) optional for local torch / large Ollama models |

### What is **not** committed (reinstall / restore)

| Path | How to obtain |
|------|----------------|
| `.venv/` | `python3 -m venv .venv && pip install -r requirements.txt` |
| `models/` | Restore from `archives/models.tar.zst.part_*` or pull via Ollama/HF |
| `toolboxes/` | Restore from `archives/toolboxes.tar.zst.part_*` or `scripts/fetch_toolboxes.py` |
| `data/finetune/` | Restore from `archives/data-finetune.tar.zst.part_*` |
| `workspace/` | Local-only finetune scratch (not shipped) |
| `.env` | `cp .env.example .env` — **never commit real secrets** |

---

<a id="quick-start"></a>
## 🚀 Quick Start

### Installation

```bash
# 1. Clone
git clone https://github.com/kpwlowski22222-ops/Wifite4.git
cd Wifite4

# 2. (If using Git LFS for multi-part archives)
git lfs install
git lfs pull   # downloads archives/* large objects

# 3. Restore large assets (optional — see Archives section)
cat archives/models.tar.zst.part_* | zstd -d | tar -xf -
cat archives/toolboxes.tar.zst.part_* | zstd -d | tar -xf -
# or rebuild toolboxes from catalog:
# python scripts/fetch_toolboxes.py --all --limit 15

# 4. Virtualenv + Python deps
python3 -m venv .venv
source .venv/bin/activate
pip install -U pip wheel
pip install -r requirements.txt

# 5. Environment template (all keys optional)
cp .env.example .env
# Edit .env — OLLAMA_CLOUD_TOKEN, NVD_API_KEY, SHODAN_API_KEY, …

# 6. System tools (example — Kali)
sudo apt install -y aircrack-ng hashcat bluez zstd xterm

# 7. Ollama (recommended for AI chains)
curl -fsSL https://ollama.com/install.sh | sh
ollama serve &
ollama pull minimax-m3:cloud    # cloud primary (needs OLLAMA_CLOUD_TOKEN)
# ollama pull qwen2.5-coder:14b  # local alternative
```

### Launch

```bash
# TUI dashboard (recommended)
sudo -E env PATH="$PATH" .venv/bin/python main.py
# or
sudo ./run_tui.sh

# Full pipeline (advanced)
sudo ./run_full_pipeline.sh

# CLI helpers
python main.py --cli holo status
python main.py --cli ble-scan --text --seconds 20
python main.py --cli wifi-scan --iface wlan0mon --text
```

### First Run

On first launch, KFIOSA will:
1. Expand `PATH` for common tool locations (`/usr/local/bin`, Kali paths, …)
2. Load settings from `config/dashboard_settings.json`
3. Probe/start `ollama serve` if available
4. Run preflight checks for dependencies
5. Launch the curses dashboard (WiFi · BLE · OSINT · Settings · Quit)

### Settings TUI highlights

| Setting | Purpose |
|---------|---------|
| **External Terminal** | Detect/pick `xterm`, `kitty`, `foot`, `alacritty`, … or `tail` |
| **Scan Window Font Scale** | `1.0` = TUI density; `2.0` = larger external windows (geometry shrinks to fit) |
| Ollama endpoint / domain models | Per-domain model mapping |
| Scan timeouts | WiFi / BLE scan duration defaults |

Env override for scan font: `KFIOSA_SCAN_FONT_SCALE=2.0`.

---

<a id="large-archives-multi-part-restore"></a>
## 📚 Large Archives (multi-part restore)

GitHub hard-limits files at **100 MB**. Multi-gigabyte trees are stored under **`archives/`** as **zstd tar streams split into ≤90 MB parts**, tracked with **Git LFS** when available.

| Prefix | Restores | Typical size |
|--------|----------|--------------|
| `models.tar.zst.part_*` | `models/` | ~0.5–1 GB compressed |
| `data-finetune.tar.zst.part_*` | `data/finetune/` | hundreds of MB |
| `toolboxes.tar.zst.part_*` | `toolboxes/` | multi-GB |
| `wordlists.tar.zst` | `wordlists/` | small |
| `datasets.tar.zst` | `datasets/` | small |

**Restore** (from repo root; needs `zstd` + `tar`):

```bash
# Integrity (optional)
cd archives && sha256sum -c MANIFEST.sha256 && cd ..

cat archives/models.tar.zst.part_*        | zstd -d | tar -xf -
cat archives/data-finetune.tar.zst.part_* | zstd -d | tar -xf -
cat archives/toolboxes.tar.zst.part_*     | zstd -d | tar -xf -
zstd -d -c archives/wordlists.tar.zst | tar -xf -
zstd -d -c archives/datasets.tar.zst  | tar -xf -
```

Full maintainer notes: [`archives/README.md`](archives/README.md).

**Without archives** — rebuild toolboxes from the catalog:

```bash
python scripts/fetch_toolboxes.py --all --limit 15
python scripts/prepare_toolboxes.py --all
```

---

<a id="ai-models--providers"></a>
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
| **Deep Thinking** | Auto-selected prompt layer (`core/ai_backend/deep_thinking.py`) | One of 4 reasoning types on every `AIBackend.query` |

### Deep-Thinking Algorithms (auto-choice)

Every AI model call auto-selects one of **ten** deep-thinking types (plus a named sub-algorithm). Override with `context["deep_thinking_type"]` / `context["deep_thinking_algorithm"]`. Disable with `KFIOSA_DEEP_THINKING=0` or `context["deep_thinking_enabled"]=False`.

| Type | Pattern | Auto-picked when | Source inspiration |
|------|---------|------------------|--------------------|
| **`chain_of_thought`** | Sequential CoT | Chain/plan requests; post-exploit / C2 | CoT (Wei et al.) |
| **`tree_of_thought`** | Branch & score | Choose/compare tools or attacks; WiFi/BLE | ToT (Yao et al.) |
| **`self_critique`** | Propose → critique → revise | Replan-on-failure; zero-day hypotheses | Self-refine / critique |
| **`react_grounded`** | Observe → reason → act | OSINT / recon; evidence-first | ReAct (Yao et al.) |
| **`graph_of_thought`** | Merge / refine sub-results | Correlate recon+CVE+tools; subgoal reuse | GoT (Besta et al.) |
| **`self_consistency`** | Multi-path majority vote | Consensus, cross-check, high stakes | CoT-SC (Wang et al.) |
| **`least_to_most`** | Easy → hard decomposition | Break down complex goals / compound Qs | LtM (Zhou et al.) |
| **`plan_and_solve`** | Plan phase then execute | Plan-then-execute; missing-step fill | Plan-and-Solve |
| **`reflexion`** | Verbal RL from history | Engagement history, stuck strategy | Reflexion (Shinn et al.) |
| **`multi_agent_debate`** | Red/blue / panel debate | Debate, pros/cons, specialist panel | Multi-agent debate |

Sub-algorithms: **3 per type (30 total)** — see `core/ai_backend/deep_thinking.py`.

**Enhancements:** structured scratch/budget/checklist protocol (JSON-safe for chain schemas); ToT score rubrics; GoT generate→link→aggregate→refine→distill; PS+ variable extract + missing-step audit; universal self-consistency synthesize on vote split; Reflexion lesson templates; debate judges must address Blue’s objections; complexity-aware auto-select + optional hybrid PS+/near-tie enhancers for high-complexity CoT/ToT.

Heavier / high-intensity types **soft-prefer** the Tier-2 THINKING overlay model when it is installed; light types (most ReAct) do not. The domain primary model is still tried first.

Override the primary model: set `OLLAMA_DEFAULT_MODEL` in `.env`.

---

<a id="wifi-capabilities"></a>
## 📡 WiFi Capabilities

**Hardware focus:** MediaTek **MT7922 / `mt7921e`** + generic mac80211 adapters (`airmon-ng` / `iw`).

### Scan & Reconnaissance

- `airodump-ng` scan with live parsing and target selection
- Interface management and monitor mode toggling
- WPS probe and status detection
- Enhanced scan with **NVD CVE** keyword correlation
- **Kismet** server/client helpers (HTTP API + optional API token; see [Kismet Integration](#kismet-integration))
- **Triple external scan windows** (UL APs / UR clients / BR offline) with scale-aware geometry
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

<a id="ble-capabilities"></a>
## 📶 BLE Capabilities

**Adapter:** Any BlueZ-compatible HCI adapter (`hci0` default); interface picker in `core/ble/adapter_select.py`.

### Live Scan (external TUI)

Same pattern as WiFi: **Scan Devices** opens a dedicated external terminal with a live long-range BLE scanner (`core/tui/ble_scan_external.py`):

| Control | Action |
|---------|--------|
| **↑ / ↓** | Move selection |
| **TAB** | Switch online ↔ disappeared tables |
| **ENTER / SPACE** | Select target |
| **A** | Queue **AIO ATTACK** (writes selection JSON + closes) |
| **r** | Rescan / reset catalog |
| **q** | Quit (keeps selection if any) |

**Long-range defaults:** multi-backend merge (bleak → bluetoothctl → hcitool), LE Coded PHY when supported, max HCI scan duty cycle (`0x4000`), RSSI floor −127, active scan, no service filter. Override duration with `KFIOSA_BLE_SCAN_S`.

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

<a id="osint-capabilities"></a>
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

<a id="post-exploitation--post-access"></a>
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

<a id="cve-to-exploit-pipeline"></a>
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

<a id="polymorphic-evasion-engine"></a>
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

<a id="autonomous-orchestrator"></a>
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

<a id="external-scan-windows--terminal"></a>
## 🖥 External Scan Windows & Terminal

Live WiFi/BLE scans can open **external terminal windows** so the operator watches dense live lists while the main dashboard stays free.

### Triple layout (default when available)

| Slot | WiFi | BLE |
|------|------|-----|
| **Top-left** | APs online | Devices online |
| **Top-right** | Clients of focused AP | Device detail |
| **Bottom-right** | Offline APs + timestamps | Offline devices |

Selection in a window writes to a **scan bus** directory; the main TUI polls and can auto-start **engagement** (ACCEPT-gated chain).

### Font scale & geometry

- Default scale **1.0** (same information density as the main TUI).
- Override: env `KFIOSA_SCAN_FONT_SCALE` or Settings → **Scan Window Font Scale**.
- `geometry_string()` shrinks `COLSxROWS` with font size so 2×–4× fonts **still fit** the half-screen slot (no overflow).
- Screen size: `xdpyinfo` or `KFIOSA_SCREEN_W` / `KFIOSA_SCREEN_H`.

### Terminal backend

Detection order: `xterm` → `gnome-terminal` → `konsole` → `xfce4-terminal` → `alacritty` → `kitty` → `foot` → `tmux` → `tail` (log-only fallback).  
Persisted in `config/dashboard_settings.json` key `terminal`. CLI font knobs work for xterm/kitty/foot/alacritty.

Implementation: `core/utils/external_terminal.py`, `core/tui/wifi_scan_bus.py`, `core/tui/ble_scan_bus.py`.

---

<a id="kismet-integration"></a>
## 📡 Kismet Integration

| Item | Detail |
|------|--------|
| **Package** | `kismet` (apt) — binary `/usr/bin/kismet` |
| **Web UI** | `http://127.0.0.1:2501` |
| **Remote capture** | `127.0.0.1:3501` |
| **Auth file (root)** | `/root/.kismet/kismet_httpd.conf` (`httpd_username` / `httpd_password`) |
| **API tokens** | `GET /auth/apikey/list.json` (HTTP basic) |
| **KFIOSA client** | `core/scanners/kismet_runner.py` — env `KISMET_CLIENT_USERNAME` / `KISMET_CLIENT_PASSWORD` (defaults often `admin`/`admin`) |

**Start**

```bash
sudo kismet --no-ncurses --daemonize
# or interactive:
sudo kismet
```

**If start fails with “Address already in use”**

An old/stopped instance still holds ports 2501/3501:

```bash
sudo pkill -x kismet || true
sudo pkill -9 -x kismet || true
sudo ss -ltnp | grep -E '2501|3501'   # should be empty
sudo kismet --no-ncurses --daemonize
```

**Smoke-test API**

```bash
curl -s -u admin:admin http://127.0.0.1:2501/system/status.json | head
curl -s -u admin:admin http://127.0.0.1:2501/auth/apikey/list.json
```

Live capture DBs (`Kismet-*.kismet`) are **gitignored** (operator noise).

---

<a id="mcp-server"></a>
## 🔌 MCP Server

`core/mcp/` — Model Context Protocol server for agent tool access.

Enables external AI agents to invoke KFIOSA's tools programmatically while the TUI runs. This allows:
- Multi-agent collaboration on complex engagements
- Programmatic access to scan, attack, and OSINT functions
- Integration with other MCP-compatible AI frameworks

---

<a id="holographic-desktop-agent"></a>
## 🖥️ Holographic Desktop Agent (OS Agentic CLI)

KFIOSA integrates **[holo-desktop-cli](https://github.com/hcompai/holo-desktop-cli)** (H Company Holo3) so the AI chain and operator can drive the **real OS desktop** when terminal tools alone are not enough — Bluetooth system settings, WiFi monitor prep, Ollama model pulls, browser UIs.

| Surface | How |
|---------|-----|
| **Chain action** | `holo_desktop` / `desktop_nav` (ACCEPT-gated, default-deny) |
| **Settings TUI** | OS Agentic CLI — status / dry-run / enable toggle |
| **BLE Advanced** | Long-range prep, Bluetooth system settings, stack diagnose |
| **CLI** | `python main.py --cli holo …` |

### CLI examples

```bash
# Probe install / login (no desktop control)
python main.py --cli holo status
python main.py --cli holo presets

# Dry-run (print argv only)
python main.py --cli holo run --goal ble_long_range_prep --dry-run

# Real desktop control (explicit ACCEPT on this CLI call)
python main.py --cli holo run --goal ble_long_range_prep --yes
python main.py --cli holo run --goal ble_scan_cli --yes
python main.py --cli holo run --goal wifi_monitor_prep --yes

# Kill switch
python main.py --cli holo stop

# Long-range scanners without the dashboard
python main.py --cli ble-scan --text --seconds 20
python main.py --cli wifi-scan --iface wlan0mon --text
```

**Presets** (partial): `ble_long_range_prep`, `ble_scan_cli`, `ble_adapter_help`, `ble_system_settings`, `wifi_monitor_prep`, `wifi_scan_cli`, `ollama_list`, `ollama_serve`, `install_holo`, `open_terminal`.

**Safety:** real desktop control is default-deny without a confirm gate (`--yes` on CLI, ACCEPT/CANCEL in the TUI). Missing `holo` binary → honest error + install hint — never fake success.

**Install:** `pip install holo-desktop-cli` or the upstream installer; binary is also looked up under `~/.holo/bin` (including under `sudo` via `SUDO_USER`).

Bridge code: `core/desktop/holo_agent.py`.

---

<a id="tool-catalog"></a>
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

<a id="configuration"></a>
## ⚙️ Configuration

### Environment Variables (`.env`)

Copy `.env.example` → `.env` and fill credentials once. **All keys are optional** unless a feature needs them — the TUI reports `MISSING` when a feature cannot run.

**Python tools** (any script under the repo):

```python
from core.env_loader import load_project_env, env, require_env, credentials_status

load_project_env()                    # loads repo-root .env into os.environ
nvd = env("NVD_API_KEY")              # "" if unset
# shodan = require_env("SHODAN_API_KEY")  # raises if blank
print(credentials_status()["present"])  # booleans only — never prints secrets
```

`main.py` and `AIBackend` also load `.env` automatically at startup.

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
| `KISMET_API_KEY` | Optional Kismet API token (if not using session/basic) | No |
| `KISMET_CLIENT_USERNAME` / `KISMET_CLIENT_PASSWORD` | Kismet HTTP basic (often `admin`/`admin`) | No |
| `KFIOSA_SCAN_FONT_SCALE` | External scan window font multiplier (default `1.0`) | No |
| `KFIOSA_SCREEN_W` / `KFIOSA_SCREEN_H` | Override screen pixels for window placement | No |
| `KFIOSA_PYTHON` | Python used inside external scan windows | No |
| `KFIOSA_DEEP_THINKING` | Set `0` to disable deep-thinking prompt layer | No |
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

<a id="project-layout"></a>
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
│   │   ├── ble_scan_external.py     #   External live BLE scan TUI
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
│   ├── dashboard_settings.json      #   Dashboard preferences (terminal, models, …)
│   └── grok_mcp_config.json         #   MCP configuration
│
├── archives/                        # Multi-part ≤90MB zstd archives (Git LFS)
│   ├── README.md                    #   Restore / recreate instructions
│   ├── MANIFEST.sha256              #   Checksums
│   ├── models.tar.zst.part_*        #   → models/
│   ├── data-finetune.tar.zst.part_* #   → data/finetune/
│   ├── toolboxes.tar.zst.part_*     #   → toolboxes/
│   ├── wordlists.tar.zst            #   → wordlists/
│   └── datasets.tar.zst             #   → datasets/
│
├── data/                            # Runtime data (finetune via archive)
│   ├── exploit_knowledge.db         #   SQLite exploit database
│   ├── tool_registry.json           #   Built tool registry snapshot
│   ├── zero_day_drafts/             #   0-day hypothesis drafts
│   └── finetune/                    #   (restore from archives/)
│
├── models/                          # Local/finetuned weights (restore from archives/)
├── toolboxes/                       # Cloned tools (restore from archives/ or fetch script)
├── wordlists/                       # Wordlists (archive or local)
├── datasets/                        # Training/reference datasets
├── docs/                            # Documentation
├── assets/                          # Project assets
├── scripts/                         # Helper scripts
│   ├── fetch_toolboxes.py           #   Clone catalog tools into toolboxes/
│   ├── prepare_toolboxes.py         #   pip/chmod prepare cloned tools
│   ├── model_downloader.py          #   HF/Ollama model helper
│   ├── fetch_hf_datasets.py         #   HF dataset fetch
│   ├── run_qlora_finetune.py        #   QLoRA finetune entry
│   ├── grok_mcp_bridge.py           #   MCP bridge for Grok
│   └── setup_grok_cowork.py         #   Grok co-working setup
│
├── tests/                           # pytest test suite
│   ├── conftest.py / fakes.py       #   Fixtures + fakes
│   ├── test_external_geometry.py    #   Scale-aware window geometry
│   ├── test_external_terminal.py    #   Terminal launch / font scale
│   ├── test_scan_bus.py             #   WiFi/BLE scan bus + placement
│   ├── test_wifi_screen_actions.py  #   WiFi TUI
│   ├── test_ble_screen_actions.py   #   BLE TUI
│   ├── test_settings_screen_actions.py
│   ├── test_chain_planner.py        #   AI chain planning
│   ├── test_poly_adapt_*.py         #   Polymorphic engine
│   └── ...                          #   Many more modules
│
├── wifi_offensive_ai/               # WiFi Offensive AI engine
│   └── core/engine.py
│
├── ai_pentest_engine.py             # Standalone AI pentest engine
├── metasploit_post_exploit.py       # Metasploit post-exploit runner
├── pentest_hf_registry.py           # HuggingFace pentest model registry
└── pentest_hf_registry.json         # HF registry data
```

---

<a id="safety-model"></a>
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

<a id="development--testing"></a>
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
| `test_settings_screen_actions.py` | Settings TUI (terminal, font scale, …) |
| `test_wifi_screen_actions.py` | WiFi TUI actions |
| `test_ble_screen_actions.py` | BLE TUI actions |
| `test_external_geometry.py` | Scale-aware external window geometry |
| `test_external_terminal.py` | Font scale argv, placement, script launch |
| `test_scan_bus.py` | Triple-window placement + bus selection |
| `test_wifi_scan_external.py` / `test_ble_scan_external.py` | External scan UIs |
| `test_adaptive_engagement.py` | Orchestrator adaptive engagement |
| `test_scan_limits.py` | Scan rate limiting |
| `test_holo_desktop.py` | Desktop agent |
| `test_wifi_radio.py` | WiFi radio control |

Focused external-scan / geometry suite:

```bash
.venv/bin/python -m pytest \
  tests/test_external_geometry.py \
  tests/test_external_terminal.py \
  tests/test_scan_bus.py \
  tests/test_wifi_screen_actions.py \
  tests/test_settings_screen_actions.py -q
```

---

<a id="known-issues--roadmap"></a>
## 📋 Known Issues & Roadmap

See [KNOWN_ISSUES.md](KNOWN_ISSUES.md) for current bugs and limitations.

See [TODO.md](TODO.md) for the development roadmap, organized by phases:

- **Phase 1:** Core TUI + WiFi/BLE scan
- **Phase 2:** AI chain planner + exploit pipeline + catalog expansion
- **Phase 3:** SQL backends, extended BLE, polymorphic v4, dashboard v3
- **Phase 4:** Catalog enhancement, model upgrades, performance optimization
- **Phase 5+:** MCP server, desktop agent, adaptive engagement

---

<a id="license"></a>
## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

```
MIT License — Copyright (c) 2026 WiFi Offensive AI Toolkit
```

---

<a id="disclaimer"></a>
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
