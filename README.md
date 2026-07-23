<div align="center">

🛡️ KFIOSA / Wifite4

AI-Driven Offensive Security TUI for Wi-Fi, BLE, OSINT, and Post-Exploitation



Pure Python + curses · Wifite-style interface · AI-assisted workflowsLocal and cloud LLM support · 5,100+ cataloged tools · ACCEPT/CANCEL safety gates

Main menu: Wi-Fi Scan · BLE Scan · OSINT · Settings · Quit

</div>

sudo python main.py          # Launch the dashboard
sudo ./run_tui.sh            # Alternative launcher

[!CAUTION]This software is intended exclusively for authorized security testing and education. Use it only on systems and networks you own or have explicit written authorization to test. Active Wi-Fi and BLE modules may disrupt services. You are solely responsible for complying with applicable law and the agreed rules of engagement.

[!NOTE]This README intentionally avoids wide Markdown tables and oversized ASCII trees. Long reference sections use vertical cards and collapsible blocks so GitHub can display them cleanly on narrow browser windows and mobile screens.

📋 Table of Contents

What is KFIOSA

Feature Matrix

Universal Workflow Model

Architecture Overview

Recursive Component Contract

Quick Start

AI Models & Providers

Wi-Fi Capabilities

BLE Capabilities

OSINT Capabilities

Post-Exploitation & Post-Access

CVE-to-Exploit Pipeline

Polymorphic Evasion Engine

Autonomous Orchestrator

MCP Server

Holographic Desktop Agent

Tool Catalog

Configuration

Project Layout

Safety Model

Development & Testing

Known Issues & Roadmap

License

Disclaimer

🔍 What is KFIOSA

KFIOSA (also known as Wifite4) is a next-generation, AI-driven offensive security platform that combines:

LLM-powered attack planning — Local/cloud LLMs analyze targets and generate multi-step attack chains with tool selection, parameter tuning, and adaptive replanning.

Real tool execution — Actually runs airodump-ng, hashcat, gatttool, holehe, NVD queries, Metasploit, and hundreds more — behind per-step safety gates.

Honest results — No fabricated "success" output. Missing tools produce explicit errors and status degradation, never fake data.

wifite-style TUI — A full-screen curses dashboard with keyboard navigation, live scan visualization, color-coded status, and interactive menus.

Universal Workflow Model

KFIOSA uses one reusable workflow across domains:

Discover — collect observations from a scanner, API, catalog, session, or operator input.

Normalize — convert results into stable fields so unrelated tools can cooperate.

Enrich — add vendor, protocol, vulnerability, device, or registry context when available.

Plan — choose a single action or generate a nested child workflow.

Approve — require the configured safety decision before an active step.

Execute — call the selected adapter or tool with bounded parameters.

Verify — distinguish confirmed results, partial results, failures, and hypotheses.

Persist — store only the metadata and artifacts allowed by configuration.

Recurse or stop — replan with a narrower goal, use a fallback, or finish cleanly.

The same sequence can describe a complete engagement, a single screen action, one scanner, one provider call, or one catalog entry. This makes the documentation useful even when modules are replaced or extended.

Core Design Principles

<details>
<summary><strong>Default-deny execution</strong></summary>

Implementation: Every offensive step requires ACCEPT before running

</details>

<details>
<summary><strong>Graceful degradation</strong></summary>

Implementation: Missing tools/APIs → honest errors, not fake success

</details>

<details>
<summary><strong>Multi-model AI</strong></summary>

Implementation: 5-tier Ollama ladder + DeepSeek, Groq, NVIDIA, Gemini fallbacks

</details>

<details>
<summary><strong>Domain-specific models</strong></summary>

Implementation: Wi-Fi, BLE, OSINT, post-exploit each use specialized models

</details>

<details>
<summary><strong>Extensible catalog</strong></summary>

Implementation: ~5,100 tool entries with install metadata and chain examples

</details>

🎯 Feature Matrix

<details>
<summary><strong>Wi-Fi</strong></summary>

Capabilities: Scan → target → one-click / AIO / AI chain; MT7922/mt7921e injection; deauth, evil twin, PMKID, WPA3, Wi-Fi 6/7

Module Count: 80+ attack modules + 60 extended 802.11 modules

</details>

<details>
<summary><strong>BLE</strong></summary>

Capabilities: Bleak scan, GATT recon, pairing attacks, HID injection, mesh, LE Audio, Find My/Fast Pair

Module Count: 50+ probe modules + 60+ attack modules

</details>

<details>
<summary><strong>OSINT</strong></summary>

Capabilities: People/email/username/domain/social/phone; Shodan/NVD; Polish registries (CEIDG, KRS, GUS)

Module Count: 90+ tool modules

</details>

<details>
<summary><strong>Post-Access</strong></summary>

Capabilities: Interactive shell, file browser, port forwarding/SOCKS, persistence, privilege escalation

Module Count: Post-Access TUI with RAT extensions

</details>

<details>
<summary><strong>Post-Exploit</strong></summary>

Capabilities: Anti-forensics, log cleaning, artifact wiping, OPSEC modules

Module Count: 60+ anti-forensic modules

</details>

<details>
<summary><strong>CVE Pipeline</strong></summary>

Capabilities: NVD lookup → exploit match → PoC generation → 0-day triage

Module Count: Automated pipeline

</details>

<details>
<summary><strong>C2 Lab</strong></summary>

Capabilities: DNS/HTTP beacon, encrypted channels, session management

Module Count: C2 lab framework

</details>

<details>
<summary><strong>Mobile</strong></summary>

Capabilities: Android/iOS instrumentation via Frida, Microsoft-specific modules

Module Count: Platform-specific modules

</details>

<details>
<summary><strong>Catalog</strong></summary>

Capabilities: ~5,100 tool entries (GitHub + Kali) with chain examples and install metadata

Module Count: JSON catalog database

</details>

🏗 Architecture Overview

The platform is organized as a vertical pipeline. Each stage can call the same pipeline again for a narrower subtask, which keeps the architecture recursive and extensible.

flowchart TD
    A[main.py] --> B[Preflight and bootstrap]
    B --> C[curses TUI]
    C --> D[Wi-Fi screen]
    C --> E[BLE screen]
    C --> F[OSINT screen]
    C --> G[Settings]

    D --> H[Domain modules]
    E --> H
    F --> H

    H --> I[AI backend]
    I --> J[Chain planner]
    J --> K[Operator approval gate]
    K --> L[Tool execution]
    L --> M[Result normalization]
    M --> N{Goal complete?}
    N -- No --> O[Replan or create sub-chain]
    O --> J
    N -- Yes --> P[Store results and clean up]

    L --> Q[Catalog and installer]
    L --> R[Knowledge base and database]

Recursive Component Contract

Every major component can be understood with the same reusable contract:

Input — receives normalized target data, configuration, prior results, or an operator request.

Validation — checks permissions, dependencies, hardware, API availability, and required parameters.

Planning — selects a local action or creates a smaller child workflow using the same contract.

Approval — sends gated actions through the configured ACCEPT/CANCEL boundary.

Execution — invokes an adapter, library, model, or external tool.

Normalization — converts output into a stable internal result format.

Verification — records success, partial success, failure, uncertainty, and evidence.

Recursion — retries, falls back, or creates a narrower sub-chain when the goal is incomplete.

Cleanup — closes processes, restores interfaces, and persists only approved artifacts.

This contract applies to screens, scanners, AI providers, catalog entries, orchestration steps, and test fixtures. New modules can therefore be added without changing the overall mental model.

Key Subsystems

<details>
<summary><strong>TUI Dashboard</strong></summary>

Path: core/tui/

Responsibility: Curses-based full-screen interface with 5-item menu

</details>

<details>
<summary><strong>AI Backend</strong></summary>

Path: core/ai_backend/

Responsibility: Multi-provider LLM chain planner with domain routing

</details>

<details>
<summary><strong>Chain Planner</strong></summary>

Path: core/ai_backend/chain.py

Responsibility: Multi-step attack chain generation, step execution, replanning

</details>

<details>
<summary><strong>Autonomous Orchestrator</strong></summary>

Path: core/orchestrator/

Responsibility: Self-directed chain execution with adaptive engagement

</details>

<details>
<summary><strong>Wi-Fi Attack Engine</strong></summary>

Path: core/wifi_attack/ + core/extended_wifi/

Responsibility: 140+ Wi-Fi attack/scan modules

</details>

<details>
<summary><strong>BLE Engine</strong></summary>

Path: core/ble/ + core/extended_ble/

Responsibility: BLE probe, attack, and GATT exploration

</details>

<details>
<summary><strong>OSINT Engine</strong></summary>

Path: core/osint/

Responsibility: Multi-layer OSINT with Polish-specific modules

</details>

<details>
<summary><strong>Post-Exploit</strong></summary>

Path: core/post_exploit/

Responsibility: 60+ anti-forensic and OPSEC modules

</details>

<details>
<summary><strong>Post-Access TUI</strong></summary>

Path: core/post_access_tui/

Responsibility: Interactive session management with RAT extensions

</details>

<details>
<summary><strong>CVE Pipeline</strong></summary>

Path: core/cve_to_exploit/

Responsibility: NVD → exploit matching → PoC generation

</details>

<details>
<summary><strong>Polymorphic Engine</strong></summary>

Path: core/modules/polymorphic_evasion.py

Responsibility: Payload mutation, encoding chains, signature evasion

</details>

<details>
<summary><strong>Exploit Knowledge Base</strong></summary>

Path: core/exploit_knowledge_base.py

Responsibility: SQLite DB with exploit metadata and chain patterns

</details>

<details>
<summary><strong>Tool Catalog</strong></summary>

Path: catalog/ + core/catalog/

Responsibility: ~5,100 tool entries with install/chain metadata

</details>

<details>
<summary><strong>Tool Installer</strong></summary>

Path: core/tool_installer/

Responsibility: Auto-install missing dependencies

</details>

<details>
<summary><strong>Scanners</strong></summary>

Path: core/scanners/

Responsibility: Wi-Fi, BLE, and Kismet scan backends

</details>

<details>
<summary><strong>C2 Lab</strong></summary>

Path: core/c2/

Responsibility: DNS/HTTP beacon framework for testing

</details>

<details>
<summary><strong>Mobile</strong></summary>

Path: core/android/, core/ios/, core/microsoft/

Responsibility: Frida-based mobile instrumentation

</details>

<details>
<summary><strong>MCP Server</strong></summary>

Path: core/mcp/

Responsibility: Model Context Protocol for agent tool access

</details>

<details>
<summary><strong>Desktop Agent</strong></summary>

Path: core/desktop/

Responsibility: Holographic desktop agent integration

</details>

<details>
<summary><strong>Database</strong></summary>

Path: core/db/

Responsibility: SQLite backend with optimized indexes

</details>

<details>
<summary><strong>Live Edit/Target</strong></summary>

Path: core/live_edit/, core/live_target/

Responsibility: Runtime overlay and live target management

</details>

<details>
<summary><strong>Recon</strong></summary>

Path: core/recon/

Responsibility: Reconnaissance primitives

</details>

<details>
<summary><strong>Replan</strong></summary>

Path: core/replan/

Responsibility: Chain replanning logic

</details>

<details>
<summary><strong>Forensics</strong></summary>

Path: core/forensics/

Responsibility: Digital forensics modules

</details>

<details>
<summary><strong>Neuroscience</strong></summary>

Path: core/neuroscience/

Responsibility: Experimental behavioral analysis modules

</details>

<details>
<summary><strong>Settings</strong></summary>

Path: core/settings.py

Responsibility: Runtime configuration manager

</details>

🚀 Quick Start

Prerequisites

OS: Linux (Kali Linux recommended)

Python: 3.10 or higher

Hardware (Wi-Fi): MediaTek MT7922 / mt7921e or any mac80211 adapter for monitor mode

Hardware (BLE): Any BlueZ-compatible HCI adapter

Root/sudo: Required for monitor mode, injection, and some scanners

Installation

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

Launch

# Launch the TUI dashboard (recommended)
sudo python main.py

# Alternative launcher script
sudo ./run_tui.sh

# Run the full pipeline (advanced)
sudo ./run_full_pipeline.sh

First Run

On first launch, KFIOSA will:

Expand PATH for common tool locations (/usr/local/bin, etc.)

Load settings from config/dashboard_settings.json

Probe/start ollama serve if available

Run preflight checks for dependencies

Launch the curses dashboard

🤖 AI Models & Providers

KFIOSA uses a sophisticated multi-provider AI backend with automatic fallback:

Provider Chain (priority order)

Ollama (local/cloud) → DeepSeek → Groq → NVIDIA → Gemini → Heuristic Planner

If the top provider is unavailable, the system cascades to the next. The final fallback is a rule-based heuristic planner that works without any AI provider.

Ollama Tier Ladder

<details>
<summary><strong>0</strong></summary>

Role: Primary (cloud)

Model Tag: minimax-m3:cloud

Notes: Cloud-routed, requires OLLAMA_CLOUD_TOKEN

</details>

<details>
<summary><strong>1</strong></summary>

Role: Local fallback

Model Tag: roleplaiapp/Qwen2.5-Coder-14B-Instruct-Uncensored-Q4_K_M-GGUF:Q4_K_M

Notes: ~9GB VRAM hybrid

</details>

<details>
<summary><strong>2</strong></summary>

Role: Planning overlay

Model Tag: mradermacher/Qwen3.5-9B-Claude-4.6-HighIQ-THINKING-HERETIC-UNCENSORED-GGUF:latest

Notes: High-IQ reasoning

</details>

<details>
<summary><strong>3</strong></summary>

Role: MoE last resort

Model Tag: mradermacher/Qwen3-Coder-30B-A3B-Instruct-uncensored-i1-GGUF:latest

Notes: Mixture of Experts

</details>

<details>
<summary><strong>4</strong></summary>

Role: Legacy

Model Tag: wizard-vicuna-uncensored:latest / llama2-uncensored:latest

Notes: Compatibility layer

</details>

Domain-Specific Models

Each attack surface uses a specialized model for optimal results:

<details>
<summary><strong>Wi-Fi / BLE</strong></summary>

Model: xploiter/pentester:latest

Purpose: Wireless-specific attack reasoning

</details>

<details>
<summary><strong>OSINT</strong></summary>

Model: huihui_ai/phi4-abliterated:latest

Purpose: Open-source intelligence analysis

</details>

<details>
<summary><strong>Post-exploit / Forensics</strong></summary>

Model: huihui_ai/foundation-sec-abliterated:8b-fp16

Purpose: Post-access operations

</details>

<details>
<summary><strong>C2</strong></summary>

Model: supergoatscriptguy/mythos-sec:24b

Purpose: Command & Control reasoning

</details>

Additional ML Components

<details>
<summary><strong>Zero-Day Triage Classifier</strong></summary>

Model/Source: cpranavsharma/Zero-Day-Agent (Hugging Face)

Role: Scores 0-day hypotheses — classification only

</details>

<details>
<summary><strong>Exploit Body Generator</strong></summary>

Model/Source: Uncensored Ollama ladder via ExploitGenModelManager

Role: PoC code generation

</details>

<details>
<summary><strong>Chain Planner</strong></summary>

Model/Source: Primary Ollama model

Role: Multi-step attack chain reasoning

</details>

Override the primary model: set OLLAMA_DEFAULT_MODEL in .env.

📡 Wi-Fi Capabilities

Hardware focus: MediaTek MT7922 / mt7921e + generic mac80211 adapters (airmon-ng / iw).

Scan & Reconnaissance

airodump-ng scan with live parsing and target selection

Interface management and monitor mode toggling

WPS probe and status detection

Enhanced scan with NVD CVE keyword correlation

Kismet server/client helpers (requires KISMET_API_KEY)

Catalog-based recon: client enumeration, hidden SSID detection, signal mapping, handshake/EAPOL capture, channel planning, wardrive data fusion, weakpass wordlists

Attack Engine

Located in core/wifi_attack/ and core/extended_wifi/ — 140+ modules including:

<details>
<summary><strong>Evil Twin / Rogue AP</strong></summary>

Examples: Evil twin, karma-MANA, captive portal generation

</details>

<details>
<summary><strong>Handshake Capture</strong></summary>

Examples: WPA/WPA2 handshake + PMKID (hashcat modes 16800/22001)

</details>

<details>
<summary><strong>Packet Capture</strong></summary>

Examples: Live hcxdumptool integration

</details>

<details>
<summary><strong>Deauthentication</strong></summary>

Examples: Targeted/broadcast deauth, MDK3/MDK4 attacks

</details>

<details>
<summary><strong>Flooding</strong></summary>

Examples: Beacon flood, authentication flood

</details>

<details>
<summary><strong>WPA3/SAE</strong></summary>

Examples: SAE/Dragonblood attacks, OWE, PMF bypass

</details>

<details>
<summary><strong>Enterprise</strong></summary>

Examples: EAP/PEAP credential harvesting paths

</details>

<details>
<summary><strong>WPS</strong></summary>

Examples: Reaver, Bully, pixie-dust attacks

</details>

<details>
<summary><strong>KR00K</strong></summary>

Examples: CVE-2019-15126 exploitation

</details>

<details>
<summary><strong>Wi-Fi 6/6E/7</strong></summary>

Examples: OFDMA, MLO, HE/EHT-related attack modules

</details>

<details>
<summary><strong>Adaptive Selection</strong></summary>

Examples: Vendor-aware, congestion-aware, client-count, PMF-aware pickers

</details>

External tools commonly driven: airodump-ng, aireplay-ng, aircrack-ng, hashcat, hcxtools, hcxdumptool, reaver, bully, mdk3/mdk4, hostapd, scapy, iw.

Wi-Fi Screen Flow

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

📶 BLE Capabilities

Adapter: Any BlueZ-compatible HCI adapter (hci0 default); interface picker in core/ble/adapter_select.py.

Probe Engine (BLEProbeRunner) — 50+ Modules

<details>
<summary><strong>Discovery</strong></summary>

Capabilities: AD type parsing, manufacturer/OUI lookup, service UUID resolution

</details>

<details>
<summary><strong>GATT Exploration</strong></summary>

Capabilities: Full GATT map, characteristic read/write, descriptor enumeration

</details>

<details>
<summary><strong>Pairing Analysis</strong></summary>

Capabilities: Pairing risk assessment, PIN analysis, bonding state detection

</details>

<details>
<summary><strong>OTA Recon</strong></summary>

Capabilities: Over-the-air reconnaissance, firmware version detection

</details>

<details>
<summary><strong>MITM Feasibility</strong></summary>

Capabilities: Man-in-the-middle attack surface analysis

</details>

<details>
<summary><strong>Health Profiles</strong></summary>

Capabilities: Medical device protocol identification

</details>

<details>
<summary><strong>Mesh Networks</strong></summary>

Capabilities: Bluetooth Mesh topology mapping

</details>

<details>
<summary><strong>LE Audio</strong></summary>

Capabilities: Low Energy Audio capability detection

</details>

<details>
<summary><strong>Tracker Detection</strong></summary>

Capabilities: Find My, Fast Pair, Swift Pair identification

</details>

<details>
<summary><strong>Privacy Analysis</strong></summary>

Capabilities: RPA detection, address churn, randomization assessment

</details>

<details>
<summary><strong>Presence</strong></summary>

Capabilities: Dwell time classification, occupancy analysis

</details>

Attack Engine (BLEAttackRunner) — 60+ Modules

<details>
<summary><strong>GATT Attacks</strong></summary>

Capabilities: Read/write/notify abuse, firmware dump, characteristic injection

</details>

<details>
<summary><strong>Pairing</strong></summary>

Capabilities: PIN brute force, Just Works exploitation, LESC downgrade

</details>

<details>
<summary><strong>ADV Injection</strong></summary>

Capabilities: Advertisement spoofing, beacon injection

</details>

<details>
<summary><strong>Connection</strong></summary>

Capabilities: Hijack helpers, MITM relay, connection parameter manipulation

</details>

<details>
<summary><strong>HID Injection</strong></summary>

Capabilities: Keyboard/mouse injection via BLE HID profile

</details>

<details>
<summary><strong>Energy Drain</strong></summary>

Capabilities: Battery exhaustion attacks

</details>

<details>
<summary><strong>L2CAP/ISO</strong></summary>

Capabilities: Low-level protocol attacks

</details>

<details>
<summary><strong>Mesh</strong></summary>

Capabilities: Mesh network provisioning and disruption

</details>

<details>
<summary><strong>Auto-orchestration</strong></summary>

Capabilities: AI-directed multi-step BLE campaigns

</details>

All modules feature honest degradation — if btmgmt, gatttool, or scapy are missing, the module reports the error explicitly instead of faking results.

Libraries/tools: bleak, bluetoothctl, hcitool, gatttool, btmgmt, scapy.

🔎 OSINT Capabilities

Three-layer architecture with ~90+ integrated tool modules:

Layer 1: Catalog Runner

Accept-gated CLI tool execution by category:

People — identity resolution, social graph mapping

Email — holehe, breach lookup, mail server analysis

Username — sherlock, maigret, cross-platform enumeration

Domain — whois, DNS recon, subfinder, amass, certificate transparency

Phone — carrier lookup, HLR query helpers

Social — platform-specific scrapers and analyzers

Layer 2: Module Library (~90 Functions)

<details>
<summary><strong>holehe</strong></summary>

Purpose: Email-to-account discovery

</details>

<details>
<summary><strong>sherlock / maigret</strong></summary>

Purpose: Username cross-platform search

</details>

<details>
<summary><strong>whois</strong></summary>

Purpose: Domain/IP registration lookup

</details>

<details>
<summary><strong>amass / subfinder</strong></summary>

Purpose: Subdomain enumeration

</details>

<details>
<summary><strong>nmap / masscan</strong></summary>

Purpose: Port scanning and service detection

</details>

<details>
<summary><strong>httpx</strong></summary>

Purpose: HTTP probing and tech fingerprinting

</details>

<details>
<summary><strong>trufflehog / gitleaks</strong></summary>

Purpose: Secret/credential detection in repos

</details>

<details>
<summary><strong>Cloud enum</strong></summary>

Purpose: AWS/GCP/Azure resource enumeration

</details>

<details>
<summary><strong>Shodan / Censys</strong></summary>

Purpose: Internet-wide host intelligence

</details>

<details>
<summary><strong>WiGLE</strong></summary>

Purpose: Wireless network geolocation

</details>

<details>
<summary><strong>NVD</strong></summary>

Purpose: CVE/vulnerability correlation

</details>

Layer 3: Extension Runner (Poland-Specific Stack)

<details>
<summary><strong>CEIDG</strong></summary>

Data Source: Polish business registry (sole proprietors)

</details>

<details>
<summary><strong>KRS</strong></summary>

Data Source: National Court Register (companies)

</details>

<details>
<summary><strong>GUS (REGON)</strong></summary>

Data Source: Central Statistical Office

</details>

<details>
<summary><strong>KNF</strong></summary>

Data Source: Financial Supervision Authority

</details>

<details>
<summary><strong>Allegro</strong></summary>

Data Source: Polish marketplace intelligence

</details>

<details>
<summary><strong>PL Social</strong></summary>

Data Source: Polish social media platform scrapers

</details>

<details>
<summary><strong>PESEL/NIP/REGON</strong></summary>

Data Source: National ID number validators

</details>

Additional: deep graphing, Google dorks, leak/CT helpers, data correlation engine.

Optional API keys: SHODAN_API_KEY, NVD_API_KEY.

🔓 Post-Exploitation & Post-Access

Post-Exploit Modules (core/post_exploit/)

60+ anti-forensic and OPSEC modules organized by category:

<details>
<summary><strong>Log Cleaning</strong></summary>

Examples: syslog wipe, auth log sanitization, journal tampering

</details>

<details>
<summary><strong>Artifact Wiping</strong></summary>

Examples: bash history, file timestamps, temp file removal

</details>

<details>
<summary><strong>Anti-Forensics</strong></summary>

Examples: Disk artifact destruction, memory scrubbing

</details>

<details>
<summary><strong>Persistence</strong></summary>

Examples: Cron jobs, systemd services, SSH key injection

</details>

<details>
<summary><strong>Privilege Escalation</strong></summary>

Examples: SUID/capability abuse, kernel exploit wrappers

</details>

<details>
<summary><strong>Credential Harvesting</strong></summary>

Examples: /etc/shadow extraction, SSH key collection

</details>

<details>
<summary><strong>Network Pivoting</strong></summary>

Examples: Port forwarding, SOCKS proxy, tunnel setup

</details>

<details>
<summary><strong>OPSEC</strong></summary>

Examples: MAC randomization, traffic obfuscation

</details>

Post-Access TUI (core/post_access_tui/)

Interactive session management interface after gaining access:

Shell panel — Interactive shell on compromised host

File browser — Remote filesystem navigation and exfiltration

Port forwarding / SOCKS — Network tunneling setup

Persistence manager — Deploy/manage persistence mechanisms

Wi-Fi panel — Wireless operations from compromised host

BLE panel — BLE operations from compromised host

RAT extensions — Remote Access Toolkit with JWT authentication and dynamic payload generation (v5_enhancements)

🔬 CVE-to-Exploit Pipeline

Located in core/cve_to_exploit/:

The pipeline uses a narrow, repeatable sequence instead of a fixed one-shot path:

Collect — receive product, version, service, vendor, and protocol observations.

Normalize — convert inconsistent scanner output into stable identifiers and searchable keywords.

Correlate — query vulnerability metadata and match affected products conservatively.

Rank — order candidates by confidence, severity, exploit maturity, and environment fit.

Validate — separate confirmed matches from hypotheses and incomplete observations.

Attach evidence — keep source metadata, timestamps, tool output, and confidence notes together.

Select next action — stop, request more reconnaissance, or create a smaller validation sub-chain.

Record outcome — save the result in the knowledge base for later reuse and replanning.

Each child validation task follows the same sequence recursively. This prevents one weak match from being treated as a confirmed result and keeps the workflow reusable across Wi-Fi, BLE, mobile, operating-system, and service-level findings.

Zero-Day Research

Draft storage: data/zero_day_drafts/ — JSON-serialized 0-day hypotheses

Triage classifier: cpranavsharma/Zero-Day-Agent from Hugging Face — scores plausibility

Exploit body generation: Uses uncensored Ollama models via ExploitGenModelManager

Knowledge base: SQLite DB at data/exploit_knowledge.db with indexed exploit metadata

🎭 Polymorphic Evasion Engine

core/modules/polymorphic_evasion.py + core/refactors/poly_adapt_companions.py

The polymorphic engine mutates payloads to evade signature-based detection:

<details>
<summary><strong>Encoding chains</strong></summary>

Description: Multi-layer encoding (base64, XOR, AES, custom)

</details>

<details>
<summary><strong>Dead code injection</strong></summary>

Description: Random NOPs and junk instructions

</details>

<details>
<summary><strong>Variable renaming</strong></summary>

Description: Randomized identifier substitution

</details>

<details>
<summary><strong>Control flow obfuscation</strong></summary>

Description: Opaque predicates, CFG flattening

</details>

<details>
<summary><strong>String encryption</strong></summary>

Description: Runtime string decryption stubs

</details>

<details>
<summary><strong>Target-adaptive methods</strong></summary>

Description: 20+ polymorphic + 20 target-adaptive mutation strategies

</details>

<details>
<summary><strong>Companion modules</strong></summary>

Description: Poly-adapt companion helpers for complex transformations

</details>

🤖 Autonomous Orchestrator

core/orchestrator/autonomous_orchestrator.py + core/orchestrator/adaptive_engagement.py

The orchestrator enables fully autonomous or semi-autonomous attack campaigns:

<details>
<summary><strong>Chain execution</strong></summary>

Description: Executes AI-planned multi-step attack chains

</details>

<details>
<summary><strong>Replanning</strong></summary>

Description: Dynamically adjusts plan based on step results

</details>

<details>
<summary><strong>Adaptive engagement</strong></summary>

Description: Adjusts attack intensity and technique selection based on target responses

</details>

<details>
<summary><strong>Step gating</strong></summary>

Description: ACCEPT/CANCEL gates at configurable granularity

</details>

<details>
<summary><strong>Result aggregation</strong></summary>

Description: Collects and correlates results across chain steps

</details>

<details>
<summary><strong>Error recovery</strong></summary>

Description: Graceful handling of tool failures with fallback strategies

</details>

🔌 MCP Server

core/mcp/ — Model Context Protocol server for agent tool access.

Enables external AI agents to invoke KFIOSA's tools programmatically while the TUI runs. This allows:

Multi-agent collaboration on complex engagements

Programmatic access to scan, attack, and OSINT functions

Integration with other MCP-compatible AI frameworks

🖥️ Holographic Desktop Agent

core/desktop/holo_agent.py — Experimental desktop agent integration for extended UI capabilities beyond the terminal TUI.

📚 Tool Catalog

Located in catalog/ with ~5,100 entries spanning GitHub repositories and Kali Linux packages.

Catalog Schema (v1.1.0)

Each entry includes:

Tool name and description

Source URL (GitHub/package)

Install commands (apt, pip, git clone, etc.)

Attack surface tags (wifi, ble, osint, exploit, etc.)

Phase hints (recon, exploit, post-exploit, etc.)

Hardware requirements (requires_hardware)

Chain examples — Pre-built usage patterns for the AI planner

Status — Verified/unverified clone status

Catalog Components

<details>
<summary><strong>Tool entries</strong></summary>

Path: catalog/

Purpose: JSON tool definitions

</details>

<details>
<summary><strong>Catalog loader</strong></summary>

Path: core/utils/catalog_loader.py

Purpose: Runtime catalog parsing

</details>

<details>
<summary><strong>Tool installer</strong></summary>

Path: core/tool_installer/catalog.py

Purpose: Auto-install from catalog

</details>

<details>
<summary><strong>Tool registry</strong></summary>

Path: core/tool_registry.py

Purpose: Runtime tool registration

</details>

<details>
<summary><strong>Algorithm registry</strong></summary>

Path: core/algorithm_registry.py

Purpose: Attack algorithm indexing

</details>

<details>
<summary><strong>HF registry</strong></summary>

Path: pentest_hf_registry.py

Purpose: Hugging Face model catalog

</details>

⚙️ Configuration

Environment Variables (.env)

Copy .env.example → .env. All keys are optional — the TUI reports MISSING when a feature cannot run.

<details>
<summary><strong>`OLLAMA_CLOUD_TOKEN`</strong></summary>

Purpose: Cloud primary model (minimax-m3:cloud)

Required: No

</details>

<details>
<summary><strong>`OLLAMA_DEFAULT_MODEL`</strong></summary>

Purpose: Override Ollama model tag

Required: No

</details>

<details>
<summary><strong>`GROQ_API_KEY` / `GROQ_MODEL`</strong></summary>

Purpose: Groq cloud fallback

Required: No

</details>

<details>
<summary><strong>`DEEPSEEK_API_KEY` / `DEEPSEEK_MODEL`</strong></summary>

Purpose: DeepSeek cloud fallback

Required: No

</details>

<details>
<summary><strong>`GEMINI_API_KEY`</strong></summary>

Purpose: Gemini routes

Required: No

</details>

<details>
<summary><strong>`SHODAN_API_KEY`</strong></summary>

Purpose: Shodan host/port enrichment (OSINT)

Required: No

</details>

<details>
<summary><strong>`NVD_API_KEY`</strong></summary>

Purpose: NVD CVE API (raises rate limit from 5/30s)

Required: Recommended

</details>

<details>
<summary><strong>`HF_TOKEN`</strong></summary>

Purpose: Gated Hugging Face model pulls

Required: No

</details>

<details>
<summary><strong>`KISMET_API_KEY`</strong></summary>

Purpose: Local Kismet server API

Required: No

</details>

<details>
<summary><strong>`GOOGLE_PROJECT_ID`</strong></summary>

Purpose: Google Cloud integration

Required: No

</details>

<details>
<summary><strong>`APP_URL`</strong></summary>

Purpose: Public URL for deployments

Required: No

</details>

Dashboard Settings

Runtime configuration stored in config/dashboard_settings.json:

Metasploit connection (host/port/user/pass)

UI preferences

Default scan parameters

MCP configuration (config/grok_mcp_config.json)

Security Notes

Never commit: .env, OAuth client secrets (client_secret_*.json, oauthadmin.json), PEM/key files, or live capture databases (Kismet .kismet files).

📁 Project Layout

The repository is described by responsibility rather than by one very wide directory tree. Open only the group you need.

How to Read the Layout Recursively

For any directory, apply the same questions:

Where is the entry point? Look for __init__.py, cli.py, main.py, runner.py, or a screen/controller module.

What does it accept? Identify configuration, normalized targets, prior results, sessions, or catalog entries.

What does it produce? Look for normalized result objects, events, files, database rows, or UI updates.

Which adapters does it use? Follow wrappers around external tools, APIs, hardware, models, and storage.

How does it fail? Check explicit error states, fallback paths, missing-dependency handling, and cleanup.

How is it extended? Add a sibling module that follows the same input/output contract and register it in the nearest registry or catalog.

Where is it tested? Search tests/ for the same module or subsystem name.

<details>
<summary><strong>Repository root</strong></summary>

main.py — primary curses-dashboard entry point.

run.sh — general command-line launcher.

run_tui.sh — focused TUI launcher.

run_full_pipeline.sh — full workflow launcher.

run_full_pipeline_v2.sh — enhanced workflow variant.

prepare.sh — environment preparation.

prepare_ollama_finetune.sh — local model preparation helper.

setup.py — Python package metadata and installation.

requirements.txt — Python dependencies.

.env.example — optional environment-variable template.

.gitignore — generated files and sensitive-data exclusions.

LICENSE — project license.

README.md — primary project documentation.

KNOWN_ISSUES.md — known bugs and limitations.

TODO.md — development roadmap.

pytest.ini — test discovery configuration.

metadata.json — project metadata.

</details>

<details>
<summary><strong>core/ — application runtime</strong></summary>

core/ contains runtime behavior. Its children follow the same pattern: entry point, adapters, normalized results, error handling, registration, and tests.

tui/ — screens, navigation, selectors, and live views.

ai_backend/ — provider routing and chain planning.

orchestrator/ — workflow execution, replanning, and adaptive control.

modules/ — shared planning, reconnaissance, CVE, tool, and post-access integrations.

scanners/ — Wi-Fi, BLE, Kismet, radio, and scan-limit backends.

wifi_attack/ and extended_wifi/ — Wi-Fi-specific module families.

ble/ and extended_ble/ — BLE discovery, GATT, and module families.

osint/ — generic and Poland-specific open-source intelligence modules.

post_exploit/ — post-access module collection.

post_access_tui/ — interactive session-management interface.

cve_to_exploit/ — vulnerability correlation and validation pipeline.

c2/ — authorized laboratory communication framework.

mcp/ — Model Context Protocol exposure for external agents.

desktop/ — extended desktop-agent integration.

db/ — SQLite storage and indexes.

catalog/ — runtime catalog management.

tool_installer/ — dependency and tool installation adapters.

toolbox/ — toolbox discovery and lifecycle management.

integrations/ — external services and provider adapters.

live_edit/ and live_target/ — runtime overlays and live target state.

recon/ — reusable reconnaissance primitives.

replan/ — workflow replanning logic.

refactors/ — compatibility and migration helpers.

forensics/ — digital-forensics modules.

neuroscience/ — experimental behavioral-analysis modules.

android/, ios/, and microsoft/ — platform-specific instrumentation.

utils/ — shared parsers, loaders, adapters, and navigation utilities.

settings.py — runtime settings manager.

bootstrap.py — preflight checks and model bootstrap.

optimizations.py — performance-oriented helpers.

exploit_knowledge_base.py — indexed SQLite knowledge base.

tool_registry.py — runtime tool registration.

algorithm_registry.py — algorithm indexing.

osint_catalog.py — OSINT catalog access.

mcp_server.py — MCP server entry point.

</details>

<details>
<summary><strong>core/tui/ — recursive screen model</strong></summary>

Each screen should follow the same lifecycle:

Load settings and current state.

Validate terminal size and required dependencies.

Render a compact view that can degrade to narrower widths.

Handle navigation and operator decisions.

Dispatch work to a domain service rather than embedding tool logic in the UI.

Receive normalized events and refresh only affected regions.

Restore terminal and interface state on exit.

Important files include:

dashboard.py — top-level menu and screen routing.

wifi_screen.py — Wi-Fi workflow view.

ble_screen.py — BLE workflow view.

osint_screen.py — OSINT workflow view.

settings_screen.py — configuration UI.

device_screen.py — device details.

interface_picker.py — network-interface selection.

wifi_scan_external.py — external scan viewer.

base_screen.py — reusable screen behavior.

</details>

<details>
<summary><strong>core/ai_backend/ and core/orchestrator/</strong></summary>

These directories implement the recursive planning loop:

ai_backend/__init__.py — provider selection and fallback routing.

ai_backend/chain.py — chain creation, step representation, and result-aware planning.

orchestrator/autonomous_orchestrator.py — executes approved steps and records outcomes.

orchestrator/adaptive_engagement.py — adjusts the next plan using normalized observations.

A parent chain may create a child chain. The child receives a narrower goal, returns a normalized result, and never bypasses the parent approval and cleanup boundaries.

</details>

<details>
<summary><strong>Data, catalogs, configuration, and documentation</strong></summary>

catalog/ — tool definitions and reusable chain metadata.

config/ — dashboard and MCP configuration.

data/ — runtime databases and generated research drafts.

datasets/ — training and reference datasets.

docs/ — extended documentation.

assets/ — images and project resources.

scripts/ — setup, migration, and bridge utilities.

Treat data directories as outputs, catalogs as declarative inputs, and core/ as executable behavior. This separation makes modules easier to test and replace.

</details>

<details>
<summary><strong>tests/ — mirrored validation structure</strong></summary>

tests/ mirrors runtime responsibilities rather than duplicating implementation details.

conftest.py — shared fixtures.

fakes.py — controlled fake objects and adapters.

test_bootstrap.py — preflight and startup behavior.

test_chain_planner.py — planning and replanning contracts.

test_catalog_chain_examples.py — catalog consistency.

test_poly_adapt_*.py — transformation-engine behavior.

test_settings_screen_actions.py — settings UI actions.

test_wifi_screen_actions.py — Wi-Fi UI actions.

test_adaptive_engagement.py — adaptive orchestration.

test_scan_limits.py — scan boundaries and rate limits.

When adding a runtime module, add a test with the same responsibility and verify success, partial success, failure, fallback, and cleanup paths.

</details>

<details>
<summary><strong>Standalone and compatibility modules</strong></summary>

wifi_offensive_ai/core/engine.py — standalone Wi-Fi AI engine.

ai_pentest_engine.py — standalone AI-assisted security-testing engine.

metasploit_post_exploit.py — external integration runner.

pentest_hf_registry.py — Hugging Face model registry logic.

pentest_hf_registry.json — registry data.

Standalone modules should use the same normalized results and approval boundaries as core/ so they can later be absorbed into the main runtime without a breaking rewrite.

</details>

🛡 Safety Model

KFIOSA implements a defense-in-depth safety architecture:

1. ACCEPT / CANCEL Gate (Default-Deny)

Every offensive step requires explicit operator approval before execution. The TUI presents each planned action and waits for ACCEPT or CANCEL.

2. Nested Gate Inheritance (pre_accepted)

When a parent step is accepted, nested sub-tools inherit the acceptance flag to avoid double-prompting while maintaining the safety boundary.

3. Clean Teardown

Monitor-mode interfaces are automatically torn down on quit. Temporary processes (beacon, deauth, etc.) are killed on exit.

4. Honest Error Reporting

No fabricated results. If a tool is missing, unavailable, or fails:

Empty result sets + explicit error messages

MISSING status in the TUI for unconfigured features

Error propagation to the orchestrator for replanning

5. Sensitive Data Protection

.env and credentials excluded via .gitignore

No API keys in source code

OAuth secrets pattern-matched in .gitignore

🧪 Development & Testing

Setup

source .venv/bin/activate
pip install -r requirements.txt

Running Tests

# Full test suite (can be large)
pytest tests/ -q

# Focused testing
pytest tests/ -k "test_chain_planner" -v
pytest tests/ -k "test_bootstrap" -v
pytest tests/ -k "test_poly_adapt" -v

# With coverage
pytest tests/ --cov=core -q

Test Configuration (pytest.ini)

[pytest]
testpaths = tests
python_files = test_*.py
python_functions = test_*

Key Test Modules

<details>
<summary><strong>`test_bootstrap.py`</strong></summary>

Coverage: Preflight and Ollama bootstrap

</details>

<details>
<summary><strong>`test_chain_planner.py`</strong></summary>

Coverage: AI chain planning logic

</details>

<details>
<summary><strong>`test_catalog_chain_examples.py`</strong></summary>

Coverage: Catalog chain examples validation

</details>

<details>
<summary><strong>`test_poly_adapt_*.py`</strong></summary>

Coverage: Polymorphic evasion engine

</details>

<details>
<summary><strong>`test_settings_screen_actions.py`</strong></summary>

Coverage: Settings TUI actions

</details>

<details>
<summary><strong>`test_wifi_screen_actions.py`</strong></summary>

Coverage: Wi-Fi TUI actions

</details>

<details>
<summary><strong>`test_adaptive_engagement.py`</strong></summary>

Coverage: Orchestrator adaptive engagement

</details>

<details>
<summary><strong>`test_scan_limits.py`</strong></summary>

Coverage: Scan rate limiting

</details>

<details>
<summary><strong>`test_holo_desktop.py`</strong></summary>

Coverage: Desktop agent

</details>

<details>
<summary><strong>`test_wifi_radio.py`</strong></summary>

Coverage: Wi-Fi radio control

</details>

📋 Known Issues & Roadmap

See KNOWN_ISSUES.md for current bugs and limitations.

See TODO.md for the development roadmap, organized by phases:

Phase 1: Core TUI + Wi-Fi/BLE scan

Phase 2: AI chain planner + exploit pipeline + catalog expansion

Phase 3: SQL backends, extended BLE, polymorphic v4, dashboard v3

Phase 4: Catalog enhancement, model upgrades, performance optimization

Phase 5+: MCP server, desktop agent, adaptive engagement

📄 License

This project is licensed under the MIT License — see the LICENSE file for details.

MIT License — Copyright (c) 2026 Wi-Fi Offensive AI Toolkit

⚖️ Disclaimer

[!WARNING]This software is provided for education and authorized penetration testing only.

You must have explicit, written authorization before testing any system or network.

Active wireless attacks (deauth, beacon flood, evil twin) can disrupt real services.

BLE attacks can interfere with medical and safety-critical devices.

OSINT operations must comply with privacy regulations (GDPR, local laws).

You are solely responsible for compliance with all applicable laws and rules of engagement.

The authors and contributors assume no liability for misuse of this software.

<div align="center">

Built with 🐍 Python • 🤖 AI-Powered • 📡 Wireless-Native • 🛡️ Ethically Gated

</div><div align="center">
🛡️ KFIOSA / Wifite4
AI-Driven Offensive Security TUI for Wi-Fi, BLE, OSINT, and Post-Exploitation




Pure Python + curses · Wifite-style interface · AI-assisted workflows
Local and cloud LLM support · 5,100+ cataloged tools · ACCEPT/CANCEL safety gates

Main menu: Wi-Fi Scan · BLE Scan · OSINT · Settings · Quit

</div>

sudo python main.py          # Launch the dashboard
sudo ./run_tui.sh            # Alternative launcher

    [!CAUTION]
    This software is intended exclusively for authorized security testing and education. Use it only on systems and networks you own or have explicit written authorization to test. Active Wi-Fi and BLE modules may disrupt services. You are solely responsible for complying with applicable law and the agreed rules of engagement.

    [!NOTE]
    This README intentionally avoids wide Markdown tables and oversized ASCII trees. Long reference sections use vertical cards and collapsible blocks so GitHub can display them cleanly on narrow browser windows and mobile screens.

📋 Table of Contents

    What is KFIOSA

    Feature Matrix

    Universal Workflow Model

    Architecture Overview

        Recursive Component Contract

    Quick Start

    AI Models & Providers

    Wi-Fi Capabilities

    BLE Capabilities

    OSINT Capabilities

    Post-Exploitation & Post-Access

    CVE-to-Exploit Pipeline

    Polymorphic Evasion Engine

    Autonomous Orchestrator

    MCP Server

    Holographic Desktop Agent

    Tool Catalog

    Configuration

    Project Layout

    Safety Model

    Development & Testing

    Known Issues & Roadmap

    License

    Disclaimer

🔍 What is KFIOSA

KFIOSA (also known as Wifite4) is a next-generation, AI-driven offensive security platform that combines:

    LLM-powered attack planning — Local/cloud LLMs analyze targets and generate multi-step attack chains with tool selection, parameter tuning, and adaptive replanning.

    Real tool execution — Actually runs airodump-ng, hashcat, gatttool, holehe, NVD queries, Metasploit, and hundreds more — behind per-step safety gates.

    Honest results — No fabricated "success" output. Missing tools produce explicit errors and status degradation, never fake data.

    wifite-style TUI — A full-screen curses dashboard with keyboard navigation, live scan visualization, color-coded status, and interactive menus.

Universal Workflow Model

KFIOSA uses one reusable workflow across domains:

    Discover — collect observations from a scanner, API, catalog, session, or operator input.

    Normalize — convert results into stable fields so unrelated tools can cooperate.

    Enrich — add vendor, protocol, vulnerability, device, or registry context when available.

    Plan — choose a single action or generate a nested child workflow.

    Approve — require the configured safety decision before an active step.

    Execute — call the selected adapter or tool with bounded parameters.

    Verify — distinguish confirmed results, partial results, failures, and hypotheses.

    Persist — store only the metadata and artifacts allowed by configuration.

    Recurse or stop — replan with a narrower goal, use a fallback, or finish cleanly.

The same sequence can describe a complete engagement, a single screen action, one scanner, one provider call, or one catalog entry. This makes the documentation useful even when modules are replaced or extended.
Core Design Principles

<details> <summary><strong>Default-deny execution</strong></summary>

    Implementation: Every offensive step requires ACCEPT before running

</details>

<details> <summary><strong>Graceful degradation</strong></summary>

    Implementation: Missing tools/APIs → honest errors, not fake success

</details>

<details> <summary><strong>Multi-model AI</strong></summary>

    Implementation: 5-tier Ollama ladder + DeepSeek, Groq, NVIDIA, Gemini fallbacks

</details>

<details> <summary><strong>Domain-specific models</strong></summary>

    Implementation: Wi-Fi, BLE, OSINT, post-exploit each use specialized models

</details>

<details> <summary><strong>Extensible catalog</strong></summary>

    Implementation: ~5,100 tool entries with install metadata and chain examples

</details>
🎯 Feature Matrix

<details> <summary><strong>Wi-Fi</strong></summary>

    Capabilities: Scan → target → one-click / AIO / AI chain; MT7922/mt7921e injection; deauth, evil twin, PMKID, WPA3, Wi-Fi 6/7

    Module Count: 80+ attack modules + 60 extended 802.11 modules

</details>

<details> <summary><strong>BLE</strong></summary>

    Capabilities: Bleak scan, GATT recon, pairing attacks, HID injection, mesh, LE Audio, Find My/Fast Pair

    Module Count: 50+ probe modules + 60+ attack modules

</details>

<details> <summary><strong>OSINT</strong></summary>

    Capabilities: People/email/username/domain/social/phone; Shodan/NVD; Polish registries (CEIDG, KRS, GUS)

    Module Count: 90+ tool modules

</details>

<details> <summary><strong>Post-Access</strong></summary>

    Capabilities: Interactive shell, file browser, port forwarding/SOCKS, persistence, privilege escalation

    Module Count: Post-Access TUI with RAT extensions

</details>

<details> <summary><strong>Post-Exploit</strong></summary>

    Capabilities: Anti-forensics, log cleaning, artifact wiping, OPSEC modules

    Module Count: 60+ anti-forensic modules

</details>

<details> <summary><strong>CVE Pipeline</strong></summary>

    Capabilities: NVD lookup → exploit match → PoC generation → 0-day triage

    Module Count: Automated pipeline

</details>

<details> <summary><strong>C2 Lab</strong></summary>

    Capabilities: DNS/HTTP beacon, encrypted channels, session management

    Module Count: C2 lab framework

</details>

<details> <summary><strong>Mobile</strong></summary>

    Capabilities: Android/iOS instrumentation via Frida, Microsoft-specific modules

    Module Count: Platform-specific modules

</details>

<details> <summary><strong>Catalog</strong></summary>

    Capabilities: ~5,100 tool entries (GitHub + Kali) with chain examples and install metadata

    Module Count: JSON catalog database

</details>
🏗 Architecture Overview

The platform is organized as a vertical pipeline. Each stage can call the same pipeline again for a narrower subtask, which keeps the architecture recursive and extensible.

flowchart TD
    A[main.py] --> B[Preflight and bootstrap]
    B --> C[curses TUI]
    C --> D[Wi-Fi screen]
    C --> E[BLE screen]
    C --> F[OSINT screen]
    C --> G[Settings]

    D --> H[Domain modules]
    E --> H
    F --> H

    H --> I[AI backend]
    I --> J[Chain planner]
    J --> K[Operator approval gate]
    K --> L[Tool execution]
    L --> M[Result normalization]
    M --> N{Goal complete?}
    N -- No --> O[Replan or create sub-chain]
    O --> J
    N -- Yes --> P[Store results and clean up]

    L --> Q[Catalog and installer]
    L --> R[Knowledge base and database]

Recursive Component Contract

Every major component can be understood with the same reusable contract:

    Input — receives normalized target data, configuration, prior results, or an operator request.

    Validation — checks permissions, dependencies, hardware, API availability, and required parameters.

    Planning — selects a local action or creates a smaller child workflow using the same contract.

    Approval — sends gated actions through the configured ACCEPT/CANCEL boundary.

    Execution — invokes an adapter, library, model, or external tool.

    Normalization — converts output into a stable internal result format.

    Verification — records success, partial success, failure, uncertainty, and evidence.

    Recursion — retries, falls back, or creates a narrower sub-chain when the goal is incomplete.

    Cleanup — closes processes, restores interfaces, and persists only approved artifacts.

This contract applies to screens, scanners, AI providers, catalog entries, orchestration steps, and test fixtures. New modules can therefore be added without changing the overall mental model.
Key Subsystems

<details> <summary><strong>TUI Dashboard</strong></summary>

    Path: core/tui/

    Responsibility: Curses-based full-screen interface with 5-item menu

</details>

<details> <summary><strong>AI Backend</strong></summary>

    Path: core/ai_backend/

    Responsibility: Multi-provider LLM chain planner with domain routing

</details>

<details> <summary><strong>Chain Planner</strong></summary>

    Path: core/ai_backend/chain.py

    Responsibility: Multi-step attack chain generation, step execution, replanning

</details>

<details> <summary><strong>Autonomous Orchestrator</strong></summary>

    Path: core/orchestrator/

    Responsibility: Self-directed chain execution with adaptive engagement

</details>

<details> <summary><strong>Wi-Fi Attack Engine</strong></summary>

    Path: core/wifi_attack/ + core/extended_wifi/

    Responsibility: 140+ Wi-Fi attack/scan modules

</details>

<details> <summary><strong>BLE Engine</strong></summary>

    Path: core/ble/ + core/extended_ble/

    Responsibility: BLE probe, attack, and GATT exploration

</details>

<details> <summary><strong>OSINT Engine</strong></summary>

    Path: core/osint/

    Responsibility: Multi-layer OSINT with Polish-specific modules

</details>

<details> <summary><strong>Post-Exploit</strong></summary>

    Path: core/post_exploit/

    Responsibility: 60+ anti-forensic and OPSEC modules

</details>

<details> <summary><strong>Post-Access TUI</strong></summary>

    Path: core/post_access_tui/

    Responsibility: Interactive session management with RAT extensions

</details>

<details> <summary><strong>CVE Pipeline</strong></summary>

    Path: core/cve_to_exploit/

    Responsibility: NVD → exploit matching → PoC generation

</details>

<details> <summary><strong>Polymorphic Engine</strong></summary>

    Path: core/modules/polymorphic_evasion.py

    Responsibility: Payload mutation, encoding chains, signature evasion

</details>

<details> <summary><strong>Exploit Knowledge Base</strong></summary>

    Path: core/exploit_knowledge_base.py

    Responsibility: SQLite DB with exploit metadata and chain patterns

</details>

<details> <summary><strong>Tool Catalog</strong></summary>

    Path: catalog/ + core/catalog/

    Responsibility: ~5,100 tool entries with install/chain metadata

</details>

<details> <summary><strong>Tool Installer</strong></summary>

    Path: core/tool_installer/

    Responsibility: Auto-install missing dependencies

</details>

<details> <summary><strong>Scanners</strong></summary>

    Path: core/scanners/

    Responsibility: Wi-Fi, BLE, and Kismet scan backends

</details>

<details> <summary><strong>C2 Lab</strong></summary>

    Path: core/c2/

    Responsibility: DNS/HTTP beacon framework for testing

</details>

<details> <summary><strong>Mobile</strong></summary>

    Path: core/android/, core/ios/, core/microsoft/

    Responsibility: Frida-based mobile instrumentation

</details>

<details> <summary><strong>MCP Server</strong></summary>

    Path: core/mcp/

    Responsibility: Model Context Protocol for agent tool access

</details>

<details> <summary><strong>Desktop Agent</strong></summary>

    Path: core/desktop/

    Responsibility: Holographic desktop agent integration

</details>

<details> <summary><strong>Database</strong></summary>

    Path: core/db/

    Responsibility: SQLite backend with optimized indexes

</details>

<details> <summary><strong>Live Edit/Target</strong></summary>

    Path: core/live_edit/, core/live_target/

    Responsibility: Runtime overlay and live target management

</details>

<details> <summary><strong>Recon</strong></summary>

    Path: core/recon/

    Responsibility: Reconnaissance primitives

</details>

<details> <summary><strong>Replan</strong></summary>

    Path: core/replan/

    Responsibility: Chain replanning logic

</details>

<details> <summary><strong>Forensics</strong></summary>

    Path: core/forensics/

    Responsibility: Digital forensics modules

</details>

<details> <summary><strong>Neuroscience</strong></summary>

    Path: core/neuroscience/

    Responsibility: Experimental behavioral analysis modules

</details>

<details> <summary><strong>Settings</strong></summary>

    Path: core/settings.py

    Responsibility: Runtime configuration manager

</details>
🚀 Quick Start
Prerequisites

    OS: Linux (Kali Linux recommended)

    Python: 3.10 or higher

    Hardware (Wi-Fi): MediaTek MT7922 / mt7921e or any mac80211 adapter for monitor mode

    Hardware (BLE): Any BlueZ-compatible HCI adapter

    Root/sudo: Required for monitor mode, injection, and some scanners

Installation

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

Launch

# Launch the TUI dashboard (recommended)
sudo python main.py

# Alternative launcher script
sudo ./run_tui.sh

# Run the full pipeline (advanced)
sudo ./run_full_pipeline.sh

First Run

On first launch, KFIOSA will:

    Expand PATH for common tool locations (/usr/local/bin, etc.)

    Load settings from config/dashboard_settings.json

    Probe/start ollama serve if available

    Run preflight checks for dependencies

    Launch the curses dashboard

🤖 AI Models & Providers

KFIOSA uses a sophisticated multi-provider AI backend with automatic fallback:
Provider Chain (priority order)

Ollama (local/cloud) → DeepSeek → Groq → NVIDIA → Gemini → Heuristic Planner

If the top provider is unavailable, the system cascades to the next. The final fallback is a rule-based heuristic planner that works without any AI provider.
Ollama Tier Ladder

<details> <summary><strong>0</strong></summary>

    Role: Primary (cloud)

    Model Tag: minimax-m3:cloud

    Notes: Cloud-routed, requires OLLAMA_CLOUD_TOKEN

</details>

<details> <summary><strong>1</strong></summary>

    Role: Local fallback

    Model Tag: roleplaiapp/Qwen2.5-Coder-14B-Instruct-Uncensored-Q4_K_M-GGUF:Q4_K_M

    Notes: ~9GB VRAM hybrid

</details>

<details> <summary><strong>2</strong></summary>

    Role: Planning overlay

    Model Tag: mradermacher/Qwen3.5-9B-Claude-4.6-HighIQ-THINKING-HERETIC-UNCENSORED-GGUF:latest

    Notes: High-IQ reasoning

</details>

<details> <summary><strong>3</strong></summary>

    Role: MoE last resort

    Model Tag: mradermacher/Qwen3-Coder-30B-A3B-Instruct-uncensored-i1-GGUF:latest

    Notes: Mixture of Experts

</details>

<details> <summary><strong>4</strong></summary>

    Role: Legacy

    Model Tag: wizard-vicuna-uncensored:latest / llama2-uncensored:latest

    Notes: Compatibility layer

</details>
Domain-Specific Models

Each attack surface uses a specialized model for optimal results:

<details> <summary><strong>Wi-Fi / BLE</strong></summary>

    Model: xploiter/pentester:latest

    Purpose: Wireless-specific attack reasoning

</details>

<details> <summary><strong>OSINT</strong></summary>

    Model: huihui_ai/phi4-abliterated:latest

    Purpose: Open-source intelligence analysis

</details>

<details> <summary><strong>Post-exploit / Forensics</strong></summary>

    Model: huihui_ai/foundation-sec-abliterated:8b-fp16

    Purpose: Post-access operations

</details>

<details> <summary><strong>C2</strong></summary>

    Model: supergoatscriptguy/mythos-sec:24b

    Purpose: Command & Control reasoning

</details>
Additional ML Components

<details> <summary><strong>Zero-Day Triage Classifier</strong></summary>

    Model/Source: cpranavsharma/Zero-Day-Agent (Hugging Face)

    Role: Scores 0-day hypotheses — classification only

</details>

<details> <summary><strong>Exploit Body Generator</strong></summary>

    Model/Source: Uncensored Ollama ladder via ExploitGenModelManager

    Role: PoC code generation

</details>

<details> <summary><strong>Chain Planner</strong></summary>

    Model/Source: Primary Ollama model

    Role: Multi-step attack chain reasoning

</details>

Override the primary model: set OLLAMA_DEFAULT_MODEL in .env.
📡 Wi-Fi Capabilities

Hardware focus: MediaTek MT7922 / mt7921e + generic mac80211 adapters (airmon-ng / iw).
Scan & Reconnaissance

    airodump-ng scan with live parsing and target selection

    Interface management and monitor mode toggling

    WPS probe and status detection

    Enhanced scan with NVD CVE keyword correlation

    Kismet server/client helpers (requires KISMET_API_KEY)

    Catalog-based recon: client enumeration, hidden SSID detection, signal mapping, handshake/EAPOL capture, channel planning, wardrive data fusion, weakpass wordlists

Attack Engine

Located in core/wifi_attack/ and core/extended_wifi/ — 140+ modules including:

<details> <summary><strong>Evil Twin / Rogue AP</strong></summary>

    Examples: Evil twin, karma-MANA, captive portal generation

</details>

<details> <summary><strong>Handshake Capture</strong></summary>

    Examples: WPA/WPA2 handshake + PMKID (hashcat modes 16800/22001)

</details>

<details> <summary><strong>Packet Capture</strong></summary>

    Examples: Live hcxdumptool integration

</details>

<details> <summary><strong>Deauthentication</strong></summary>

    Examples: Targeted/broadcast deauth, MDK3/MDK4 attacks

</details>

<details> <summary><strong>Flooding</strong></summary>

    Examples: Beacon flood, authentication flood

</details>

<details> <summary><strong>WPA3/SAE</strong></summary>

    Examples: SAE/Dragonblood attacks, OWE, PMF bypass

</details>

<details> <summary><strong>Enterprise</strong></summary>

    Examples: EAP/PEAP credential harvesting paths

</details>

<details> <summary><strong>WPS</strong></summary>

    Examples: Reaver, Bully, pixie-dust attacks

</details>

<details> <summary><strong>KR00K</strong></summary>

    Examples: CVE-2019-15126 exploitation

</details>

<details> <summary><strong>Wi-Fi 6/6E/7</strong></summary>

    Examples: OFDMA, MLO, HE/EHT-related attack modules

</details>

<details> <summary><strong>Adaptive Selection</strong></summary>

    Examples: Vendor-aware, congestion-aware, client-count, PMF-aware pickers

</details>

External tools commonly driven: airodump-ng, aireplay-ng, aircrack-ng, hashcat, hcxtools, hcxdumptool, reaver, bully, mdk3/mdk4, hostapd, scapy, iw.
Wi-Fi Screen Flow

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

📶 BLE Capabilities

Adapter: Any BlueZ-compatible HCI adapter (hci0 default); interface picker in core/ble/adapter_select.py.
Probe Engine (BLEProbeRunner) — 50+ Modules

<details> <summary><strong>Discovery</strong></summary>

    Capabilities: AD type parsing, manufacturer/OUI lookup, service UUID resolution

</details>

<details> <summary><strong>GATT Exploration</strong></summary>

    Capabilities: Full GATT map, characteristic read/write, descriptor enumeration

</details>

<details> <summary><strong>Pairing Analysis</strong></summary>

    Capabilities: Pairing risk assessment, PIN analysis, bonding state detection

</details>

<details> <summary><strong>OTA Recon</strong></summary>

    Capabilities: Over-the-air reconnaissance, firmware version detection

</details>

<details> <summary><strong>MITM Feasibility</strong></summary>

    Capabilities: Man-in-the-middle attack surface analysis

</details>

<details> <summary><strong>Health Profiles</strong></summary>

    Capabilities: Medical device protocol identification

</details>

<details> <summary><strong>Mesh Networks</strong></summary>

    Capabilities: Bluetooth Mesh topology mapping

</details>

<details> <summary><strong>LE Audio</strong></summary>

    Capabilities: Low Energy Audio capability detection

</details>

<details> <summary><strong>Tracker Detection</strong></summary>

    Capabilities: Find My, Fast Pair, Swift Pair identification

</details>

<details> <summary><strong>Privacy Analysis</strong></summary>

    Capabilities: RPA detection, address churn, randomization assessment

</details>

<details> <summary><strong>Presence</strong></summary>

    Capabilities: Dwell time classification, occupancy analysis

</details>
Attack Engine (BLEAttackRunner) — 60+ Modules

<details> <summary><strong>GATT Attacks</strong></summary>

    Capabilities: Read/write/notify abuse, firmware dump, characteristic injection

</details>

<details> <summary><strong>Pairing</strong></summary>

    Capabilities: PIN brute force, Just Works exploitation, LESC downgrade

</details>

<details> <summary><strong>ADV Injection</strong></summary>

    Capabilities: Advertisement spoofing, beacon injection

</details>

<details> <summary><strong>Connection</strong></summary>

    Capabilities: Hijack helpers, MITM relay, connection parameter manipulation

</details>

<details> <summary><strong>HID Injection</strong></summary>

    Capabilities: Keyboard/mouse injection via BLE HID profile

</details>

<details> <summary><strong>Energy Drain</strong></summary>

    Capabilities: Battery exhaustion attacks

</details>

<details> <summary><strong>L2CAP/ISO</strong></summary>

    Capabilities: Low-level protocol attacks

</details>

<details> <summary><strong>Mesh</strong></summary>

    Capabilities: Mesh network provisioning and disruption

</details>

<details> <summary><strong>Auto-orchestration</strong></summary>

    Capabilities: AI-directed multi-step BLE campaigns

</details>

All modules feature honest degradation — if btmgmt, gatttool, or scapy are missing, the module reports the error explicitly instead of faking results.

Libraries/tools: bleak, bluetoothctl, hcitool, gatttool, btmgmt, scapy.
🔎 OSINT Capabilities

Three-layer architecture with ~90+ integrated tool modules:
Layer 1: Catalog Runner

Accept-gated CLI tool execution by category:

    People — identity resolution, social graph mapping

    Email — holehe, breach lookup, mail server analysis

    Username — sherlock, maigret, cross-platform enumeration

    Domain — whois, DNS recon, subfinder, amass, certificate transparency

    Phone — carrier lookup, HLR query helpers

    Social — platform-specific scrapers and analyzers

Layer 2: Module Library (~90 Functions)

<details> <summary><strong>holehe</strong></summary>

    Purpose: Email-to-account discovery

</details>

<details> <summary><strong>sherlock / maigret</strong></summary>

    Purpose: Username cross-platform search

</details>

<details> <summary><strong>whois</strong></summary>

    Purpose: Domain/IP registration lookup

</details>

<details> <summary><strong>amass / subfinder</strong></summary>

    Purpose: Subdomain enumeration

</details>

<details> <summary><strong>nmap / masscan</strong></summary>

    Purpose: Port scanning and service detection

</details>

<details> <summary><strong>httpx</strong></summary>

    Purpose: HTTP probing and tech fingerprinting

</details>

<details> <summary><strong>trufflehog / gitleaks</strong></summary>

    Purpose: Secret/credential detection in repos

</details>

<details> <summary><strong>Cloud enum</strong></summary>

    Purpose: AWS/GCP/Azure resource enumeration

</details>

<details> <summary><strong>Shodan / Censys</strong></summary>

    Purpose: Internet-wide host intelligence

</details>

<details> <summary><strong>WiGLE</strong></summary>

    Purpose: Wireless network geolocation

</details>

<details> <summary><strong>NVD</strong></summary>

    Purpose: CVE/vulnerability correlation

</details>
Layer 3: Extension Runner (Poland-Specific Stack)

<details> <summary><strong>CEIDG</strong></summary>

    Data Source: Polish business registry (sole proprietors)

</details>

<details> <summary><strong>KRS</strong></summary>

    Data Source: National Court Register (companies)

</details>

<details> <summary><strong>GUS (REGON)</strong></summary>

    Data Source: Central Statistical Office

</details>

<details> <summary><strong>KNF</strong></summary>

    Data Source: Financial Supervision Authority

</details>

<details> <summary><strong>Allegro</strong></summary>

    Data Source: Polish marketplace intelligence

</details>

<details> <summary><strong>PL Social</strong></summary>

    Data Source: Polish social media platform scrapers

</details>

<details> <summary><strong>PESEL/NIP/REGON</strong></summary>

    Data Source: National ID number validators

</details>

Additional: deep graphing, Google dorks, leak/CT helpers, data correlation engine.

Optional API keys: SHODAN_API_KEY, NVD_API_KEY.
🔓 Post-Exploitation & Post-Access
Post-Exploit Modules (core/post_exploit/)

60+ anti-forensic and OPSEC modules organized by category:

<details> <summary><strong>Log Cleaning</strong></summary>

    Examples: syslog wipe, auth log sanitization, journal tampering

</details>

<details> <summary><strong>Artifact Wiping</strong></summary>

    Examples: bash history, file timestamps, temp file removal

</details>

<details> <summary><strong>Anti-Forensics</strong></summary>

    Examples: Disk artifact destruction, memory scrubbing

</details>

<details> <summary><strong>Persistence</strong></summary>

    Examples: Cron jobs, systemd services, SSH key injection

</details>

<details> <summary><strong>Privilege Escalation</strong></summary>

    Examples: SUID/capability abuse, kernel exploit wrappers

</details>

<details> <summary><strong>Credential Harvesting</strong></summary>

    Examples: /etc/shadow extraction, SSH key collection

</details>

<details> <summary><strong>Network Pivoting</strong></summary>

    Examples: Port forwarding, SOCKS proxy, tunnel setup

</details>

<details> <summary><strong>OPSEC</strong></summary>

    Examples: MAC randomization, traffic obfuscation

</details>
Post-Access TUI (core/post_access_tui/)

Interactive session management interface after gaining access:

    Shell panel — Interactive shell on compromised host

    File browser — Remote filesystem navigation and exfiltration

    Port forwarding / SOCKS — Network tunneling setup

    Persistence manager — Deploy/manage persistence mechanisms

    Wi-Fi panel — Wireless operations from compromised host

    BLE panel — BLE operations from compromised host

    RAT extensions — Remote Access Toolkit with JWT authentication and dynamic payload generation (v5_enhancements)

🔬 CVE-to-Exploit Pipeline

Located in core/cve_to_exploit/:

The pipeline uses a narrow, repeatable sequence instead of a fixed one-shot path:

    Collect — receive product, version, service, vendor, and protocol observations.

    Normalize — convert inconsistent scanner output into stable identifiers and searchable keywords.

    Correlate — query vulnerability metadata and match affected products conservatively.

    Rank — order candidates by confidence, severity, exploit maturity, and environment fit.

    Validate — separate confirmed matches from hypotheses and incomplete observations.

    Attach evidence — keep source metadata, timestamps, tool output, and confidence notes together.

    Select next action — stop, request more reconnaissance, or create a smaller validation sub-chain.

    Record outcome — save the result in the knowledge base for later reuse and replanning.

Each child validation task follows the same sequence recursively. This prevents one weak match from being treated as a confirmed result and keeps the workflow reusable across Wi-Fi, BLE, mobile, operating-system, and service-level findings.
Zero-Day Research

    Draft storage: data/zero_day_drafts/ — JSON-serialized 0-day hypotheses

    Triage classifier: cpranavsharma/Zero-Day-Agent from Hugging Face — scores plausibility

    Exploit body generation: Uses uncensored Ollama models via ExploitGenModelManager

    Knowledge base: SQLite DB at data/exploit_knowledge.db with indexed exploit metadata

🎭 Polymorphic Evasion Engine

core/modules/polymorphic_evasion.py + core/refactors/poly_adapt_companions.py

The polymorphic engine mutates payloads to evade signature-based detection:

<details> <summary><strong>Encoding chains</strong></summary>

    Description: Multi-layer encoding (base64, XOR, AES, custom)

</details>

<details> <summary><strong>Dead code injection</strong></summary>

    Description: Random NOPs and junk instructions

</details>

<details> <summary><strong>Variable renaming</strong></summary>

    Description: Randomized identifier substitution

</details>

<details> <summary><strong>Control flow obfuscation</strong></summary>

    Description: Opaque predicates, CFG flattening

</details>

<details> <summary><strong>String encryption</strong></summary>

    Description: Runtime string decryption stubs

</details>

<details> <summary><strong>Target-adaptive methods</strong></summary>

    Description: 20+ polymorphic + 20 target-adaptive mutation strategies

</details>

<details> <summary><strong>Companion modules</strong></summary>

    Description: Poly-adapt companion helpers for complex transformations

</details>
🤖 Autonomous Orchestrator

core/orchestrator/autonomous_orchestrator.py + core/orchestrator/adaptive_engagement.py

The orchestrator enables fully autonomous or semi-autonomous attack campaigns:

<details> <summary><strong>Chain execution</strong></summary>

    Description: Executes AI-planned multi-step attack chains

</details>

<details> <summary><strong>Replanning</strong></summary>

    Description: Dynamically adjusts plan based on step results

</details>

<details> <summary><strong>Adaptive engagement</strong></summary>

    Description: Adjusts attack intensity and technique selection based on target responses

</details>

<details> <summary><strong>Step gating</strong></summary>

    Description: ACCEPT/CANCEL gates at configurable granularity

</details>

<details> <summary><strong>Result aggregation</strong></summary>

    Description: Collects and correlates results across chain steps

</details>

<details> <summary><strong>Error recovery</strong></summary>

    Description: Graceful handling of tool failures with fallback strategies

</details>
🔌 MCP Server

core/mcp/ — Model Context Protocol server for agent tool access.

Enables external AI agents to invoke KFIOSA's tools programmatically while the TUI runs. This allows:

    Multi-agent collaboration on complex engagements

    Programmatic access to scan, attack, and OSINT functions

    Integration with other MCP-compatible AI frameworks

🖥️ Holographic Desktop Agent

core/desktop/holo_agent.py — Experimental desktop agent integration for extended UI capabilities beyond the terminal TUI.
📚 Tool Catalog

Located in catalog/ with ~5,100 entries spanning GitHub repositories and Kali Linux packages.
Catalog Schema (v1.1.0)

Each entry includes:

    Tool name and description

    Source URL (GitHub/package)

    Install commands (apt, pip, git clone, etc.)

    Attack surface tags (wifi, ble, osint, exploit, etc.)

    Phase hints (recon, exploit, post-exploit, etc.)

    Hardware requirements (requires_hardware)

    Chain examples — Pre-built usage patterns for the AI planner

    Status — Verified/unverified clone status

Catalog Components

<details> <summary><strong>Tool entries</strong></summary>

    Path: catalog/

    Purpose: JSON tool definitions

</details>

<details> <summary><strong>Catalog loader</strong></summary>

    Path: core/utils/catalog_loader.py

    Purpose: Runtime catalog parsing

</details>

<details> <summary><strong>Tool installer</strong></summary>

    Path: core/tool_installer/catalog.py

    Purpose: Auto-install from catalog

</details>

<details> <summary><strong>Tool registry</strong></summary>

    Path: core/tool_registry.py

    Purpose: Runtime tool registration

</details>

<details> <summary><strong>Algorithm registry</strong></summary>

    Path: core/algorithm_registry.py

    Purpose: Attack algorithm indexing

</details>

<details> <summary><strong>HF registry</strong></summary>

    Path: pentest_hf_registry.py

    Purpose: Hugging Face model catalog

</details>
⚙️ Configuration
Environment Variables (.env)

Copy .env.example → .env. All keys are optional — the TUI reports MISSING when a feature cannot run.

<details> <summary><strong>`OLLAMA_CLOUD_TOKEN`</strong></summary>

    Purpose: Cloud primary model (minimax-m3:cloud)

    Required: No

</details>

<details> <summary><strong>`OLLAMA_DEFAULT_MODEL`</strong></summary>

    Purpose: Override Ollama model tag

    Required: No

</details>

<details> <summary><strong>`GROQ_API_KEY` / `GROQ_MODEL`</strong></summary>

    Purpose: Groq cloud fallback

    Required: No

</details>

<details> <summary><strong>`DEEPSEEK_API_KEY` / `DEEPSEEK_MODEL`</strong></summary>

    Purpose: DeepSeek cloud fallback

    Required: No

</details>

<details> <summary><strong>`GEMINI_API_KEY`</strong></summary>

    Purpose: Gemini routes

    Required: No

</details>

<details> <summary><strong>`SHODAN_API_KEY`</strong></summary>

    Purpose: Shodan host/port enrichment (OSINT)

    Required: No

</details>

<details> <summary><strong>`NVD_API_KEY`</strong></summary>

    Purpose: NVD CVE API (raises rate limit from 5/30s)

    Required: Recommended

</details>

<details> <summary><strong>`HF_TOKEN`</strong></summary>

    Purpose: Gated Hugging Face model pulls

    Required: No

</details>

<details> <summary><strong>`KISMET_API_KEY`</strong></summary>

    Purpose: Local Kismet server API

    Required: No

</details>

<details> <summary><strong>`GOOGLE_PROJECT_ID`</strong></summary>

    Purpose: Google Cloud integration

    Required: No

</details>

<details> <summary><strong>`APP_URL`</strong></summary>

    Purpose: Public URL for deployments

    Required: No

</details>
Dashboard Settings

Runtime configuration stored in config/dashboard_settings.json:

    Metasploit connection (host/port/user/pass)

    UI preferences

    Default scan parameters

    MCP configuration (config/grok_mcp_config.json)

Security Notes

    Never commit: .env, OAuth client secrets (client_secret_*.json, oauthadmin.json), PEM/key files, or live capture databases (Kismet .kismet files).

📁 Project Layout

The repository is described by responsibility rather than by one very wide directory tree. Open only the group you need.
How to Read the Layout Recursively

For any directory, apply the same questions:

    Where is the entry point? Look for __init__.py, cli.py, main.py, runner.py, or a screen/controller module.

    What does it accept? Identify configuration, normalized targets, prior results, sessions, or catalog entries.

    What does it produce? Look for normalized result objects, events, files, database rows, or UI updates.

    Which adapters does it use? Follow wrappers around external tools, APIs, hardware, models, and storage.

    How does it fail? Check explicit error states, fallback paths, missing-dependency handling, and cleanup.

    How is it extended? Add a sibling module that follows the same input/output contract and register it in the nearest registry or catalog.

    Where is it tested? Search tests/ for the same module or subsystem name.

<details> <summary><strong>Repository root</strong></summary>

    main.py — primary curses-dashboard entry point.

    run.sh — general command-line launcher.

    run_tui.sh — focused TUI launcher.

    run_full_pipeline.sh — full workflow launcher.

    run_full_pipeline_v2.sh — enhanced workflow variant.

    prepare.sh — environment preparation.

    prepare_ollama_finetune.sh — local model preparation helper.

    setup.py — Python package metadata and installation.

    requirements.txt — Python dependencies.

    .env.example — optional environment-variable template.

    .gitignore — generated files and sensitive-data exclusions.

    LICENSE — project license.

    README.md — primary project documentation.

    KNOWN_ISSUES.md — known bugs and limitations.

    TODO.md — development roadmap.

    pytest.ini — test discovery configuration.

    metadata.json — project metadata.

</details>

<details> <summary><strong>core/ — application runtime</strong></summary>

core/ contains runtime behavior. Its children follow the same pattern: entry point, adapters, normalized results, error handling, registration, and tests.

    tui/ — screens, navigation, selectors, and live views.

    ai_backend/ — provider routing and chain planning.

    orchestrator/ — workflow execution, replanning, and adaptive control.

    modules/ — shared planning, reconnaissance, CVE, tool, and post-access integrations.

    scanners/ — Wi-Fi, BLE, Kismet, radio, and scan-limit backends.

    wifi_attack/ and extended_wifi/ — Wi-Fi-specific module families.

    ble/ and extended_ble/ — BLE discovery, GATT, and module families.

    osint/ — generic and Poland-specific open-source intelligence modules.

    post_exploit/ — post-access module collection.

    post_access_tui/ — interactive session-management interface.

    cve_to_exploit/ — vulnerability correlation and validation pipeline.

    c2/ — authorized laboratory communication framework.

    mcp/ — Model Context Protocol exposure for external agents.

    desktop/ — extended desktop-agent integration.

    db/ — SQLite storage and indexes.

    catalog/ — runtime catalog management.

    tool_installer/ — dependency and tool installation adapters.

    toolbox/ — toolbox discovery and lifecycle management.

    integrations/ — external services and provider adapters.

    live_edit/ and live_target/ — runtime overlays and live target state.

    recon/ — reusable reconnaissance primitives.

    replan/ — workflow replanning logic.

    refactors/ — compatibility and migration helpers.

    forensics/ — digital-forensics modules.

    neuroscience/ — experimental behavioral-analysis modules.

    android/, ios/, and microsoft/ — platform-specific instrumentation.

    utils/ — shared parsers, loaders, adapters, and navigation utilities.

    settings.py — runtime settings manager.

    bootstrap.py — preflight checks and model bootstrap.

    optimizations.py — performance-oriented helpers.

    exploit_knowledge_base.py — indexed SQLite knowledge base.

    tool_registry.py — runtime tool registration.

    algorithm_registry.py — algorithm indexing.

    osint_catalog.py — OSINT catalog access.

    mcp_server.py — MCP server entry point.

</details>

<details> <summary><strong>core/tui/ — recursive screen model</strong></summary>

Each screen should follow the same lifecycle:

    Load settings and current state.

    Validate terminal size and required dependencies.

    Render a compact view that can degrade to narrower widths.

    Handle navigation and operator decisions.

    Dispatch work to a domain service rather than embedding tool logic in the UI.

    Receive normalized events and refresh only affected regions.

    Restore terminal and interface state on exit.

Important files include:

    dashboard.py — top-level menu and screen routing.

    wifi_screen.py — Wi-Fi workflow view.

    ble_screen.py — BLE workflow view.

    osint_screen.py — OSINT workflow view.

    settings_screen.py — configuration UI.

    device_screen.py — device details.

    interface_picker.py — network-interface selection.

    wifi_scan_external.py — external scan viewer.

    base_screen.py — reusable screen behavior.

</details>

<details> <summary><strong>core/ai_backend/ and core/orchestrator/</strong></summary>

These directories implement the recursive planning loop:

    ai_backend/__init__.py — provider selection and fallback routing.

    ai_backend/chain.py — chain creation, step representation, and result-aware planning.

    orchestrator/autonomous_orchestrator.py — executes approved steps and records outcomes.

    orchestrator/adaptive_engagement.py — adjusts the next plan using normalized observations.

A parent chain may create a child chain. The child receives a narrower goal, returns a normalized result, and never bypasses the parent approval and cleanup boundaries.

</details>

<details> <summary><strong>Data, catalogs, configuration, and documentation</strong></summary>

    catalog/ — tool definitions and reusable chain metadata.

    config/ — dashboard and MCP configuration.

    data/ — runtime databases and generated research drafts.

    datasets/ — training and reference datasets.

    docs/ — extended documentation.

    assets/ — images and project resources.

    scripts/ — setup, migration, and bridge utilities.

Treat data directories as outputs, catalogs as declarative inputs, and core/ as executable behavior. This separation makes modules easier to test and replace.

</details>

<details> <summary><strong>tests/ — mirrored validation structure</strong></summary>

tests/ mirrors runtime responsibilities rather than duplicating implementation details.

    conftest.py — shared fixtures.

    fakes.py — controlled fake objects and adapters.

    test_bootstrap.py — preflight and startup behavior.

    test_chain_planner.py — planning and replanning contracts.

    test_catalog_chain_examples.py — catalog consistency.

    test_poly_adapt_*.py — transformation-engine behavior.

    test_settings_screen_actions.py — settings UI actions.

    test_wifi_screen_actions.py — Wi-Fi UI actions.

    test_adaptive_engagement.py — adaptive orchestration.

    test_scan_limits.py — scan boundaries and rate limits.

When adding a runtime module, add a test with the same responsibility and verify success, partial success, failure, fallback, and cleanup paths.

</details>

<details> <summary><strong>Standalone and compatibility modules</strong></summary>

    wifi_offensive_ai/core/engine.py — standalone Wi-Fi AI engine.

    ai_pentest_engine.py — standalone AI-assisted security-testing engine.

    metasploit_post_exploit.py — external integration runner.

    pentest_hf_registry.py — Hugging Face model registry logic.

    pentest_hf_registry.json — registry data.

Standalone modules should use the same normalized results and approval boundaries as core/ so they can later be absorbed into the main runtime without a breaking rewrite.

</details>
🛡 Safety Model

KFIOSA implements a defense-in-depth safety architecture:
1. ACCEPT / CANCEL Gate (Default-Deny)

Every offensive step requires explicit operator approval before execution. The TUI presents each planned action and waits for ACCEPT or CANCEL.
2. Nested Gate Inheritance (pre_accepted)

When a parent step is accepted, nested sub-tools inherit the acceptance flag to avoid double-prompting while maintaining the safety boundary.
3. Clean Teardown

Monitor-mode interfaces are automatically torn down on quit. Temporary processes (beacon, deauth, etc.) are killed on exit.
4. Honest Error Reporting

No fabricated results. If a tool is missing, unavailable, or fails:

    Empty result sets + explicit error messages

    MISSING status in the TUI for unconfigured features

    Error propagation to the orchestrator for replanning

5. Sensitive Data Protection

    .env and credentials excluded via .gitignore

    No API keys in source code

    OAuth secrets pattern-matched in .gitignore

🧪 Development & Testing
Setup

source .venv/bin/activate
pip install -r requirements.txt

Running Tests

# Full test suite (can be large)
pytest tests/ -q

# Focused testing
pytest tests/ -k "test_chain_planner" -v
pytest tests/ -k "test_bootstrap" -v
pytest tests/ -k "test_poly_adapt" -v

# With coverage
pytest tests/ --cov=core -q

Test Configuration (pytest.ini)

[pytest]
testpaths = tests
python_files = test_*.py
python_functions = test_*

Key Test Modules

<details> <summary><strong>`test_bootstrap.py`</strong></summary>

    Coverage: Preflight and Ollama bootstrap

</details>

<details> <summary><strong>`test_chain_planner.py`</strong></summary>

    Coverage: AI chain planning logic

</details>

<details> <summary><strong>`test_catalog_chain_examples.py`</strong></summary>

    Coverage: Catalog chain examples validation

</details>

<details> <summary><strong>`test_poly_adapt_*.py`</strong></summary>

    Coverage: Polymorphic evasion engine

</details>

<details> <summary><strong>`test_settings_screen_actions.py`</strong></summary>

    Coverage: Settings TUI actions

</details>

<details> <summary><strong>`test_wifi_screen_actions.py`</strong></summary>

    Coverage: Wi-Fi TUI actions

</details>

<details> <summary><strong>`test_adaptive_engagement.py`</strong></summary>

    Coverage: Orchestrator adaptive engagement

</details>

<details> <summary><strong>`test_scan_limits.py`</strong></summary>

    Coverage: Scan rate limiting

</details>

<details> <summary><strong>`test_holo_desktop.py`</strong></summary>

    Coverage: Desktop agent

</details>

<details> <summary><strong>`test_wifi_radio.py`</strong></summary>

    Coverage: Wi-Fi radio control

</details>
📋 Known Issues & Roadmap

See KNOWN_ISSUES.md for current bugs and limitations.

See TODO.md for the development roadmap, organized by phases:

    Phase 1: Core TUI + Wi-Fi/BLE scan

    Phase 2: AI chain planner + exploit pipeline + catalog expansion

    Phase 3: SQL backends, extended BLE, polymorphic v4, dashboard v3

    Phase 4: Catalog enhancement, model upgrades, performance optimization

    Phase 5+: MCP server, desktop agent, adaptive engagement

📄 License

This project is licensed under the MIT License — see the LICENSE file for details.

MIT License — Copyright (c) 2026 Wi-Fi Offensive AI Toolkit

⚖️ Disclaimer

    [!WARNING]
    This software is provided for education and authorized penetration testing only.

        You must have explicit, written authorization before testing any system or network.

        Active wireless attacks (deauth, beacon flood, evil twin) can disrupt real services.

        BLE attacks can interfere with medical and safety-critical devices.

        OSINT operations must comply with privacy regulations (GDPR, local laws).

        You are solely responsible for compliance with all applicable laws and rules of engagement.

    The authors and contributors assume no liability for misuse of this software.

<div align="center">

Built with 🐍 Python • 🤖 AI-Powered • 📡 Wireless-Native • 🛡️ Ethically Gated

</div><div align="center">
🛡️ KFIOSA / Wifite4
AI-Driven Offensive Security TUI for Wi-Fi, BLE, OSINT, and Post-Exploitation




Pure Python + curses · Wifite-style interface · AI-assisted workflows
Local and cloud LLM support · 5,100+ cataloged tools · ACCEPT/CANCEL safety gates

Main menu: Wi-Fi Scan · BLE Scan · OSINT · Settings · Quit

</div>

sudo python main.py          # Launch the dashboard
sudo ./run_tui.sh            # Alternative launcher

    [!CAUTION]
    This software is intended exclusively for authorized security testing and education. Use it only on systems and networks you own or have explicit written authorization to test. Active Wi-Fi and BLE modules may disrupt services. You are solely responsible for complying with applicable law and the agreed rules of engagement.

    [!NOTE]
    This README intentionally avoids wide Markdown tables and oversized ASCII trees. Long reference sections use vertical cards and collapsible blocks so GitHub can display them cleanly on narrow browser windows and mobile screens.

📋 Table of Contents

    What is KFIOSA

    Feature Matrix

    Universal Workflow Model

    Architecture Overview

        Recursive Component Contract

    Quick Start

    AI Models & Providers

    Wi-Fi Capabilities

    BLE Capabilities

    OSINT Capabilities

    Post-Exploitation & Post-Access

    CVE-to-Exploit Pipeline

    Polymorphic Evasion Engine

    Autonomous Orchestrator

    MCP Server

    Holographic Desktop Agent

    Tool Catalog

    Configuration

    Project Layout

    Safety Model

    Development & Testing

    Known Issues & Roadmap

    License

    Disclaimer

🔍 What is KFIOSA

KFIOSA (also known as Wifite4) is a next-generation, AI-driven offensive security platform that combines:

    LLM-powered attack planning — Local/cloud LLMs analyze targets and generate multi-step attack chains with tool selection, parameter tuning, and adaptive replanning.

    Real tool execution — Actually runs airodump-ng, hashcat, gatttool, holehe, NVD queries, Metasploit, and hundreds more — behind per-step safety gates.

    Honest results — No fabricated "success" output. Missing tools produce explicit errors and status degradation, never fake data.

    wifite-style TUI — A full-screen curses dashboard with keyboard navigation, live scan visualization, color-coded status, and interactive menus.

Universal Workflow Model

KFIOSA uses one reusable workflow across domains:

    Discover — collect observations from a scanner, API, catalog, session, or operator input.

    Normalize — convert results into stable fields so unrelated tools can cooperate.

    Enrich — add vendor, protocol, vulnerability, device, or registry context when available.

    Plan — choose a single action or generate a nested child workflow.

    Approve — require the configured safety decision before an active step.

    Execute — call the selected adapter or tool with bounded parameters.

    Verify — distinguish confirmed results, partial results, failures, and hypotheses.

    Persist — store only the metadata and artifacts allowed by configuration.

    Recurse or stop — replan with a narrower goal, use a fallback, or finish cleanly.

The same sequence can describe a complete engagement, a single screen action, one scanner, one provider call, or one catalog entry. This makes the documentation useful even when modules are replaced or extended.
Core Design Principles

<details> <summary><strong>Default-deny execution</strong></summary>

    Implementation: Every offensive step requires ACCEPT before running

</details>

<details> <summary><strong>Graceful degradation</strong></summary>

    Implementation: Missing tools/APIs → honest errors, not fake success

</details>

<details> <summary><strong>Multi-model AI</strong></summary>

    Implementation: 5-tier Ollama ladder + DeepSeek, Groq, NVIDIA, Gemini fallbacks

</details>

<details> <summary><strong>Domain-specific models</strong></summary>

    Implementation: Wi-Fi, BLE, OSINT, post-exploit each use specialized models

</details>

<details> <summary><strong>Extensible catalog</strong></summary>

    Implementation: ~5,100 tool entries with install metadata and chain examples

</details>
🎯 Feature Matrix

<details> <summary><strong>Wi-Fi</strong></summary>

    Capabilities: Scan → target → one-click / AIO / AI chain; MT7922/mt7921e injection; deauth, evil twin, PMKID, WPA3, Wi-Fi 6/7

    Module Count: 80+ attack modules + 60 extended 802.11 modules

</details>

<details> <summary><strong>BLE</strong></summary>

    Capabilities: Bleak scan, GATT recon, pairing attacks, HID injection, mesh, LE Audio, Find My/Fast Pair

    Module Count: 50+ probe modules + 60+ attack modules

</details>

<details> <summary><strong>OSINT</strong></summary>

    Capabilities: People/email/username/domain/social/phone; Shodan/NVD; Polish registries (CEIDG, KRS, GUS)

    Module Count: 90+ tool modules

</details>

<details> <summary><strong>Post-Access</strong></summary>

    Capabilities: Interactive shell, file browser, port forwarding/SOCKS, persistence, privilege escalation

    Module Count: Post-Access TUI with RAT extensions

</details>

<details> <summary><strong>Post-Exploit</strong></summary>

    Capabilities: Anti-forensics, log cleaning, artifact wiping, OPSEC modules

    Module Count: 60+ anti-forensic modules

</details>

<details> <summary><strong>CVE Pipeline</strong></summary>

    Capabilities: NVD lookup → exploit match → PoC generation → 0-day triage

    Module Count: Automated pipeline

</details>

<details> <summary><strong>C2 Lab</strong></summary>

    Capabilities: DNS/HTTP beacon, encrypted channels, session management

    Module Count: C2 lab framework

</details>

<details> <summary><strong>Mobile</strong></summary>

    Capabilities: Android/iOS instrumentation via Frida, Microsoft-specific modules

    Module Count: Platform-specific modules

</details>

<details> <summary><strong>Catalog</strong></summary>

    Capabilities: ~5,100 tool entries (GitHub + Kali) with chain examples and install metadata

    Module Count: JSON catalog database

</details>
🏗 Architecture Overview

The platform is organized as a vertical pipeline. Each stage can call the same pipeline again for a narrower subtask, which keeps the architecture recursive and extensible.

flowchart TD
    A[main.py] --> B[Preflight and bootstrap]
    B --> C[curses TUI]
    C --> D[Wi-Fi screen]
    C --> E[BLE screen]
    C --> F[OSINT screen]
    C --> G[Settings]

    D --> H[Domain modules]
    E --> H
    F --> H

    H --> I[AI backend]
    I --> J[Chain planner]
    J --> K[Operator approval gate]
    K --> L[Tool execution]
    L --> M[Result normalization]
    M --> N{Goal complete?}
    N -- No --> O[Replan or create sub-chain]
    O --> J
    N -- Yes --> P[Store results and clean up]

    L --> Q[Catalog and installer]
    L --> R[Knowledge base and database]

Recursive Component Contract

Every major component can be understood with the same reusable contract:

    Input — receives normalized target data, configuration, prior results, or an operator request.

    Validation — checks permissions, dependencies, hardware, API availability, and required parameters.

    Planning — selects a local action or creates a smaller child workflow using the same contract.

    Approval — sends gated actions through the configured ACCEPT/CANCEL boundary.

    Execution — invokes an adapter, library, model, or external tool.

    Normalization — converts output into a stable internal result format.

    Verification — records success, partial success, failure, uncertainty, and evidence.

    Recursion — retries, falls back, or creates a narrower sub-chain when the goal is incomplete.

    Cleanup — closes processes, restores interfaces, and persists only approved artifacts.

This contract applies to screens, scanners, AI providers, catalog entries, orchestration steps, and test fixtures. New modules can therefore be added without changing the overall mental model.
Key Subsystems

<details> <summary><strong>TUI Dashboard</strong></summary>

    Path: core/tui/

    Responsibility: Curses-based full-screen interface with 5-item menu

</details>

<details> <summary><strong>AI Backend</strong></summary>

    Path: core/ai_backend/

    Responsibility: Multi-provider LLM chain planner with domain routing

</details>

<details> <summary><strong>Chain Planner</strong></summary>

    Path: core/ai_backend/chain.py

    Responsibility: Multi-step attack chain generation, step execution, replanning

</details>

<details> <summary><strong>Autonomous Orchestrator</strong></summary>

    Path: core/orchestrator/

    Responsibility: Self-directed chain execution with adaptive engagement

</details>

<details> <summary><strong>Wi-Fi Attack Engine</strong></summary>

    Path: core/wifi_attack/ + core/extended_wifi/

    Responsibility: 140+ Wi-Fi attack/scan modules

</details>

<details> <summary><strong>BLE Engine</strong></summary>

    Path: core/ble/ + core/extended_ble/

    Responsibility: BLE probe, attack, and GATT exploration

</details>

<details> <summary><strong>OSINT Engine</strong></summary>

    Path: core/osint/

    Responsibility: Multi-layer OSINT with Polish-specific modules

</details>

<details> <summary><strong>Post-Exploit</strong></summary>

    Path: core/post_exploit/

    Responsibility: 60+ anti-forensic and OPSEC modules

</details>

<details> <summary><strong>Post-Access TUI</strong></summary>

    Path: core/post_access_tui/

    Responsibility: Interactive session management with RAT extensions

</details>

<details> <summary><strong>CVE Pipeline</strong></summary>

    Path: core/cve_to_exploit/

    Responsibility: NVD → exploit matching → PoC generation

</details>

<details> <summary><strong>Polymorphic Engine</strong></summary>

    Path: core/modules/polymorphic_evasion.py

    Responsibility: Payload mutation, encoding chains, signature evasion

</details>

<details> <summary><strong>Exploit Knowledge Base</strong></summary>

    Path: core/exploit_knowledge_base.py

    Responsibility: SQLite DB with exploit metadata and chain patterns

</details>

<details> <summary><strong>Tool Catalog</strong></summary>

    Path: catalog/ + core/catalog/

    Responsibility: ~5,100 tool entries with install/chain metadata

</details>

<details> <summary><strong>Tool Installer</strong></summary>

    Path: core/tool_installer/

    Responsibility: Auto-install missing dependencies

</details>

<details> <summary><strong>Scanners</strong></summary>

    Path: core/scanners/

    Responsibility: Wi-Fi, BLE, and Kismet scan backends

</details>

<details> <summary><strong>C2 Lab</strong></summary>

    Path: core/c2/

    Responsibility: DNS/HTTP beacon framework for testing

</details>

<details> <summary><strong>Mobile</strong></summary>

    Path: core/android/, core/ios/, core/microsoft/

    Responsibility: Frida-based mobile instrumentation

</details>

<details> <summary><strong>MCP Server</strong></summary>

    Path: core/mcp/

    Responsibility: Model Context Protocol for agent tool access

</details>

<details> <summary><strong>Desktop Agent</strong></summary>

    Path: core/desktop/

    Responsibility: Holographic desktop agent integration

</details>

<details> <summary><strong>Database</strong></summary>

    Path: core/db/

    Responsibility: SQLite backend with optimized indexes

</details>

<details> <summary><strong>Live Edit/Target</strong></summary>

    Path: core/live_edit/, core/live_target/

    Responsibility: Runtime overlay and live target management

</details>

<details> <summary><strong>Recon</strong></summary>

    Path: core/recon/

    Responsibility: Reconnaissance primitives

</details>

<details> <summary><strong>Replan</strong></summary>

    Path: core/replan/

    Responsibility: Chain replanning logic

</details>

<details> <summary><strong>Forensics</strong></summary>

    Path: core/forensics/

    Responsibility: Digital forensics modules

</details>

<details> <summary><strong>Neuroscience</strong></summary>

    Path: core/neuroscience/

    Responsibility: Experimental behavioral analysis modules

</details>

<details> <summary><strong>Settings</strong></summary>

    Path: core/settings.py

    Responsibility: Runtime configuration manager

</details>
🚀 Quick Start
Prerequisites

    OS: Linux (Kali Linux recommended)

    Python: 3.10 or higher

    Hardware (Wi-Fi): MediaTek MT7922 / mt7921e or any mac80211 adapter for monitor mode

    Hardware (BLE): Any BlueZ-compatible HCI adapter

    Root/sudo: Required for monitor mode, injection, and some scanners

Installation

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

Launch

# Launch the TUI dashboard (recommended)
sudo python main.py

# Alternative launcher script
sudo ./run_tui.sh

# Run the full pipeline (advanced)
sudo ./run_full_pipeline.sh

First Run

On first launch, KFIOSA will:

    Expand PATH for common tool locations (/usr/local/bin, etc.)

    Load settings from config/dashboard_settings.json

    Probe/start ollama serve if available

    Run preflight checks for dependencies

    Launch the curses dashboard

🤖 AI Models & Providers

KFIOSA uses a sophisticated multi-provider AI backend with automatic fallback:
Provider Chain (priority order)

Ollama (local/cloud) → DeepSeek → Groq → NVIDIA → Gemini → Heuristic Planner

If the top provider is unavailable, the system cascades to the next. The final fallback is a rule-based heuristic planner that works without any AI provider.
Ollama Tier Ladder

<details> <summary><strong>0</strong></summary>

    Role: Primary (cloud)

    Model Tag: minimax-m3:cloud

    Notes: Cloud-routed, requires OLLAMA_CLOUD_TOKEN

</details>

<details> <summary><strong>1</strong></summary>

    Role: Local fallback

    Model Tag: roleplaiapp/Qwen2.5-Coder-14B-Instruct-Uncensored-Q4_K_M-GGUF:Q4_K_M

    Notes: ~9GB VRAM hybrid

</details>

<details> <summary><strong>2</strong></summary>

    Role: Planning overlay

    Model Tag: mradermacher/Qwen3.5-9B-Claude-4.6-HighIQ-THINKING-HERETIC-UNCENSORED-GGUF:latest

    Notes: High-IQ reasoning

</details>

<details> <summary><strong>3</strong></summary>

    Role: MoE last resort

    Model Tag: mradermacher/Qwen3-Coder-30B-A3B-Instruct-uncensored-i1-GGUF:latest

    Notes: Mixture of Experts

</details>

<details> <summary><strong>4</strong></summary>

    Role: Legacy

    Model Tag: wizard-vicuna-uncensored:latest / llama2-uncensored:latest

    Notes: Compatibility layer

</details>
Domain-Specific Models

Each attack surface uses a specialized model for optimal results:

<details> <summary><strong>Wi-Fi / BLE</strong></summary>

    Model: xploiter/pentester:latest

    Purpose: Wireless-specific attack reasoning

</details>

<details> <summary><strong>OSINT</strong></summary>

    Model: huihui_ai/phi4-abliterated:latest

    Purpose: Open-source intelligence analysis

</details>

<details> <summary><strong>Post-exploit / Forensics</strong></summary>

    Model: huihui_ai/foundation-sec-abliterated:8b-fp16

    Purpose: Post-access operations

</details>

<details> <summary><strong>C2</strong></summary>

    Model: supergoatscriptguy/mythos-sec:24b

    Purpose: Command & Control reasoning

</details>
Additional ML Components

<details> <summary><strong>Zero-Day Triage Classifier</strong></summary>

    Model/Source: cpranavsharma/Zero-Day-Agent (Hugging Face)

    Role: Scores 0-day hypotheses — classification only

</details>

<details> <summary><strong>Exploit Body Generator</strong></summary>

    Model/Source: Uncensored Ollama ladder via ExploitGenModelManager

    Role: PoC code generation

</details>

<details> <summary><strong>Chain Planner</strong></summary>

    Model/Source: Primary Ollama model

    Role: Multi-step attack chain reasoning

</details>

Override the primary model: set OLLAMA_DEFAULT_MODEL in .env.
📡 Wi-Fi Capabilities

Hardware focus: MediaTek MT7922 / mt7921e + generic mac80211 adapters (airmon-ng / iw).
Scan & Reconnaissance

    airodump-ng scan with live parsing and target selection

    Interface management and monitor mode toggling

    WPS probe and status detection

    Enhanced scan with NVD CVE keyword correlation

    Kismet server/client helpers (requires KISMET_API_KEY)

    Catalog-based recon: client enumeration, hidden SSID detection, signal mapping, handshake/EAPOL capture, channel planning, wardrive data fusion, weakpass wordlists

Attack Engine

Located in core/wifi_attack/ and core/extended_wifi/ — 140+ modules including:

<details> <summary><strong>Evil Twin / Rogue AP</strong></summary>

    Examples: Evil twin, karma-MANA, captive portal generation

</details>

<details> <summary><strong>Handshake Capture</strong></summary>

    Examples: WPA/WPA2 handshake + PMKID (hashcat modes 16800/22001)

</details>

<details> <summary><strong>Packet Capture</strong></summary>

    Examples: Live hcxdumptool integration

</details>

<details> <summary><strong>Deauthentication</strong></summary>

    Examples: Targeted/broadcast deauth, MDK3/MDK4 attacks

</details>

<details> <summary><strong>Flooding</strong></summary>

    Examples: Beacon flood, authentication flood

</details>

<details> <summary><strong>WPA3/SAE</strong></summary>

    Examples: SAE/Dragonblood attacks, OWE, PMF bypass

</details>

<details> <summary><strong>Enterprise</strong></summary>

    Examples: EAP/PEAP credential harvesting paths

</details>

<details> <summary><strong>WPS</strong></summary>

    Examples: Reaver, Bully, pixie-dust attacks

</details>

<details> <summary><strong>KR00K</strong></summary>

    Examples: CVE-2019-15126 exploitation

</details>

<details> <summary><strong>Wi-Fi 6/6E/7</strong></summary>

    Examples: OFDMA, MLO, HE/EHT-related attack modules

</details>

<details> <summary><strong>Adaptive Selection</strong></summary>

    Examples: Vendor-aware, congestion-aware, client-count, PMF-aware pickers

</details>

External tools commonly driven: airodump-ng, aireplay-ng, aircrack-ng, hashcat, hcxtools, hcxdumptool, reaver, bully, mdk3/mdk4, hostapd, scapy, iw.
Wi-Fi Screen Flow

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

📶 BLE Capabilities

Adapter: Any BlueZ-compatible HCI adapter (hci0 default); interface picker in core/ble/adapter_select.py.
Probe Engine (BLEProbeRunner) — 50+ Modules

<details> <summary><strong>Discovery</strong></summary>

    Capabilities: AD type parsing, manufacturer/OUI lookup, service UUID resolution

</details>

<details> <summary><strong>GATT Exploration</strong></summary>

    Capabilities: Full GATT map, characteristic read/write, descriptor enumeration

</details>

<details> <summary><strong>Pairing Analysis</strong></summary>

    Capabilities: Pairing risk assessment, PIN analysis, bonding state detection

</details>

<details> <summary><strong>OTA Recon</strong></summary>

    Capabilities: Over-the-air reconnaissance, firmware version detection

</details>

<details> <summary><strong>MITM Feasibility</strong></summary>

    Capabilities: Man-in-the-middle attack surface analysis

</details>

<details> <summary><strong>Health Profiles</strong></summary>

    Capabilities: Medical device protocol identification

</details>

<details> <summary><strong>Mesh Networks</strong></summary>

    Capabilities: Bluetooth Mesh topology mapping

</details>

<details> <summary><strong>LE Audio</strong></summary>

    Capabilities: Low Energy Audio capability detection

</details>

<details> <summary><strong>Tracker Detection</strong></summary>

    Capabilities: Find My, Fast Pair, Swift Pair identification

</details>

<details> <summary><strong>Privacy Analysis</strong></summary>

    Capabilities: RPA detection, address churn, randomization assessment

</details>

<details> <summary><strong>Presence</strong></summary>

    Capabilities: Dwell time classification, occupancy analysis

</details>
Attack Engine (BLEAttackRunner) — 60+ Modules

<details> <summary><strong>GATT Attacks</strong></summary>

    Capabilities: Read/write/notify abuse, firmware dump, characteristic injection

</details>

<details> <summary><strong>Pairing</strong></summary>

    Capabilities: PIN brute force, Just Works exploitation, LESC downgrade

</details>

<details> <summary><strong>ADV Injection</strong></summary>

    Capabilities: Advertisement spoofing, beacon injection

</details>

<details> <summary><strong>Connection</strong></summary>

    Capabilities: Hijack helpers, MITM relay, connection parameter manipulation

</details>

<details> <summary><strong>HID Injection</strong></summary>

    Capabilities: Keyboard/mouse injection via BLE HID profile

</details>

<details> <summary><strong>Energy Drain</strong></summary>

    Capabilities: Battery exhaustion attacks

</details>

<details> <summary><strong>L2CAP/ISO</strong></summary>

    Capabilities: Low-level protocol attacks

</details>

<details> <summary><strong>Mesh</strong></summary>

    Capabilities: Mesh network provisioning and disruption

</details>

<details> <summary><strong>Auto-orchestration</strong></summary>

    Capabilities: AI-directed multi-step BLE campaigns

</details>

All modules feature honest degradation — if btmgmt, gatttool, or scapy are missing, the module reports the error explicitly instead of faking results.

Libraries/tools: bleak, bluetoothctl, hcitool, gatttool, btmgmt, scapy.
🔎 OSINT Capabilities

Three-layer architecture with ~90+ integrated tool modules:
Layer 1: Catalog Runner

Accept-gated CLI tool execution by category:

    People — identity resolution, social graph mapping

    Email — holehe, breach lookup, mail server analysis

    Username — sherlock, maigret, cross-platform enumeration

    Domain — whois, DNS recon, subfinder, amass, certificate transparency

    Phone — carrier lookup, HLR query helpers

    Social — platform-specific scrapers and analyzers

Layer 2: Module Library (~90 Functions)

<details> <summary><strong>holehe</strong></summary>

    Purpose: Email-to-account discovery

</details>

<details> <summary><strong>sherlock / maigret</strong></summary>

    Purpose: Username cross-platform search

</details>

<details> <summary><strong>whois</strong></summary>

    Purpose: Domain/IP registration lookup

</details>

<details> <summary><strong>amass / subfinder</strong></summary>

    Purpose: Subdomain enumeration

</details>

<details> <summary><strong>nmap / masscan</strong></summary>

    Purpose: Port scanning and service detection

</details>

<details> <summary><strong>httpx</strong></summary>

    Purpose: HTTP probing and tech fingerprinting

</details>

<details> <summary><strong>trufflehog / gitleaks</strong></summary>

    Purpose: Secret/credential detection in repos

</details>

<details> <summary><strong>Cloud enum</strong></summary>

    Purpose: AWS/GCP/Azure resource enumeration

</details>

<details> <summary><strong>Shodan / Censys</strong></summary>

    Purpose: Internet-wide host intelligence

</details>

<details> <summary><strong>WiGLE</strong></summary>

    Purpose: Wireless network geolocation

</details>

<details> <summary><strong>NVD</strong></summary>

    Purpose: CVE/vulnerability correlation

</details>
Layer 3: Extension Runner (Poland-Specific Stack)

<details> <summary><strong>CEIDG</strong></summary>

    Data Source: Polish business registry (sole proprietors)

</details>

<details> <summary><strong>KRS</strong></summary>

    Data Source: National Court Register (companies)

</details>

<details> <summary><strong>GUS (REGON)</strong></summary>

    Data Source: Central Statistical Office

</details>

<details> <summary><strong>KNF</strong></summary>

    Data Source: Financial Supervision Authority

</details>

<details> <summary><strong>Allegro</strong></summary>

    Data Source: Polish marketplace intelligence

</details>

<details> <summary><strong>PL Social</strong></summary>

    Data Source: Polish social media platform scrapers

</details>

<details> <summary><strong>PESEL/NIP/REGON</strong></summary>

    Data Source: National ID number validators

</details>

Additional: deep graphing, Google dorks, leak/CT helpers, data correlation engine.

Optional API keys: SHODAN_API_KEY, NVD_API_KEY.
🔓 Post-Exploitation & Post-Access
Post-Exploit Modules (core/post_exploit/)

60+ anti-forensic and OPSEC modules organized by category:

<details> <summary><strong>Log Cleaning</strong></summary>

    Examples: syslog wipe, auth log sanitization, journal tampering

</details>

<details> <summary><strong>Artifact Wiping</strong></summary>

    Examples: bash history, file timestamps, temp file removal

</details>

<details> <summary><strong>Anti-Forensics</strong></summary>

    Examples: Disk artifact destruction, memory scrubbing

</details>

<details> <summary><strong>Persistence</strong></summary>

    Examples: Cron jobs, systemd services, SSH key injection

</details>

<details> <summary><strong>Privilege Escalation</strong></summary>

    Examples: SUID/capability abuse, kernel exploit wrappers

</details>

<details> <summary><strong>Credential Harvesting</strong></summary>

    Examples: /etc/shadow extraction, SSH key collection

</details>

<details> <summary><strong>Network Pivoting</strong></summary>

    Examples: Port forwarding, SOCKS proxy, tunnel setup

</details>

<details> <summary><strong>OPSEC</strong></summary>

    Examples: MAC randomization, traffic obfuscation

</details>
Post-Access TUI (core/post_access_tui/)

Interactive session management interface after gaining access:

    Shell panel — Interactive shell on compromised host

    File browser — Remote filesystem navigation and exfiltration

    Port forwarding / SOCKS — Network tunneling setup

    Persistence manager — Deploy/manage persistence mechanisms

    Wi-Fi panel — Wireless operations from compromised host

    BLE panel — BLE operations from compromised host

    RAT extensions — Remote Access Toolkit with JWT authentication and dynamic payload generation (v5_enhancements)

🔬 CVE-to-Exploit Pipeline

Located in core/cve_to_exploit/:

The pipeline uses a narrow, repeatable sequence instead of a fixed one-shot path:

    Collect — receive product, version, service, vendor, and protocol observations.

    Normalize — convert inconsistent scanner output into stable identifiers and searchable keywords.

    Correlate — query vulnerability metadata and match affected products conservatively.

    Rank — order candidates by confidence, severity, exploit maturity, and environment fit.

    Validate — separate confirmed matches from hypotheses and incomplete observations.

    Attach evidence — keep source metadata, timestamps, tool output, and confidence notes together.

    Select next action — stop, request more reconnaissance, or create a smaller validation sub-chain.

    Record outcome — save the result in the knowledge base for later reuse and replanning.

Each child validation task follows the same sequence recursively. This prevents one weak match from being treated as a confirmed result and keeps the workflow reusable across Wi-Fi, BLE, mobile, operating-system, and service-level findings.
Zero-Day Research

    Draft storage: data/zero_day_drafts/ — JSON-serialized 0-day hypotheses

    Triage classifier: cpranavsharma/Zero-Day-Agent from Hugging Face — scores plausibility

    Exploit body generation: Uses uncensored Ollama models via ExploitGenModelManager

    Knowledge base: SQLite DB at data/exploit_knowledge.db with indexed exploit metadata

🎭 Polymorphic Evasion Engine

core/modules/polymorphic_evasion.py + core/refactors/poly_adapt_companions.py

The polymorphic engine mutates payloads to evade signature-based detection:

<details> <summary><strong>Encoding chains</strong></summary>

    Description: Multi-layer encoding (base64, XOR, AES, custom)

</details>

<details> <summary><strong>Dead code injection</strong></summary>

    Description: Random NOPs and junk instructions

</details>

<details> <summary><strong>Variable renaming</strong></summary>

    Description: Randomized identifier substitution

</details>

<details> <summary><strong>Control flow obfuscation</strong></summary>

    Description: Opaque predicates, CFG flattening

</details>

<details> <summary><strong>String encryption</strong></summary>

    Description: Runtime string decryption stubs

</details>

<details> <summary><strong>Target-adaptive methods</strong></summary>

    Description: 20+ polymorphic + 20 target-adaptive mutation strategies

</details>

<details> <summary><strong>Companion modules</strong></summary>

    Description: Poly-adapt companion helpers for complex transformations

</details>
🤖 Autonomous Orchestrator

core/orchestrator/autonomous_orchestrator.py + core/orchestrator/adaptive_engagement.py

The orchestrator enables fully autonomous or semi-autonomous attack campaigns:

<details> <summary><strong>Chain execution</strong></summary>

    Description: Executes AI-planned multi-step attack chains

</details>

<details> <summary><strong>Replanning</strong></summary>

    Description: Dynamically adjusts plan based on step results

</details>

<details> <summary><strong>Adaptive engagement</strong></summary>

    Description: Adjusts attack intensity and technique selection based on target responses

</details>

<details> <summary><strong>Step gating</strong></summary>

    Description: ACCEPT/CANCEL gates at configurable granularity

</details>

<details> <summary><strong>Result aggregation</strong></summary>

    Description: Collects and correlates results across chain steps

</details>

<details> <summary><strong>Error recovery</strong></summary>

    Description: Graceful handling of tool failures with fallback strategies

</details>
🔌 MCP Server

core/mcp/ — Model Context Protocol server for agent tool access.

Enables external AI agents to invoke KFIOSA's tools programmatically while the TUI runs. This allows:

    Multi-agent collaboration on complex engagements

    Programmatic access to scan, attack, and OSINT functions

    Integration with other MCP-compatible AI frameworks

🖥️ Holographic Desktop Agent

core/desktop/holo_agent.py — Experimental desktop agent integration for extended UI capabilities beyond the terminal TUI.
📚 Tool Catalog

Located in catalog/ with ~5,100 entries spanning GitHub repositories and Kali Linux packages.
Catalog Schema (v1.1.0)

Each entry includes:

    Tool name and description

    Source URL (GitHub/package)

    Install commands (apt, pip, git clone, etc.)

    Attack surface tags (wifi, ble, osint, exploit, etc.)

    Phase hints (recon, exploit, post-exploit, etc.)

    Hardware requirements (requires_hardware)

    Chain examples — Pre-built usage patterns for the AI planner

    Status — Verified/unverified clone status

Catalog Components

<details> <summary><strong>Tool entries</strong></summary>

    Path: catalog/

    Purpose: JSON tool definitions

</details>

<details> <summary><strong>Catalog loader</strong></summary>

    Path: core/utils/catalog_loader.py

    Purpose: Runtime catalog parsing

</details>

<details> <summary><strong>Tool installer</strong></summary>

    Path: core/tool_installer/catalog.py

    Purpose: Auto-install from catalog

</details>

<details> <summary><strong>Tool registry</strong></summary>

    Path: core/tool_registry.py

    Purpose: Runtime tool registration

</details>

<details> <summary><strong>Algorithm registry</strong></summary>

    Path: core/algorithm_registry.py

    Purpose: Attack algorithm indexing

</details>

<details> <summary><strong>HF registry</strong></summary>

    Path: pentest_hf_registry.py

    Purpose: Hugging Face model catalog

</details>
⚙️ Configuration
Environment Variables (.env)

Copy .env.example → .env. All keys are optional — the TUI reports MISSING when a feature cannot run.

<details> <summary><strong>`OLLAMA_CLOUD_TOKEN`</strong></summary>

    Purpose: Cloud primary model (minimax-m3:cloud)

    Required: No

</details>

<details> <summary><strong>`OLLAMA_DEFAULT_MODEL`</strong></summary>

    Purpose: Override Ollama model tag

    Required: No

</details>

<details> <summary><strong>`GROQ_API_KEY` / `GROQ_MODEL`</strong></summary>

    Purpose: Groq cloud fallback

    Required: No

</details>

<details> <summary><strong>`DEEPSEEK_API_KEY` / `DEEPSEEK_MODEL`</strong></summary>

    Purpose: DeepSeek cloud fallback

    Required: No

</details>

<details> <summary><strong>`GEMINI_API_KEY`</strong></summary>

    Purpose: Gemini routes

    Required: No

</details>

<details> <summary><strong>`SHODAN_API_KEY`</strong></summary>

    Purpose: Shodan host/port enrichment (OSINT)

    Required: No

</details>

<details> <summary><strong>`NVD_API_KEY`</strong></summary>

    Purpose: NVD CVE API (raises rate limit from 5/30s)

    Required: Recommended

</details>

<details> <summary><strong>`HF_TOKEN`</strong></summary>

    Purpose: Gated Hugging Face model pulls

    Required: No

</details>

<details> <summary><strong>`KISMET_API_KEY`</strong></summary>

    Purpose: Local Kismet server API

    Required: No

</details>

<details> <summary><strong>`GOOGLE_PROJECT_ID`</strong></summary>

    Purpose: Google Cloud integration

    Required: No

</details>

<details> <summary><strong>`APP_URL`</strong></summary>

    Purpose: Public URL for deployments

    Required: No

</details>
Dashboard Settings

Runtime configuration stored in config/dashboard_settings.json:

    Metasploit connection (host/port/user/pass)

    UI preferences

    Default scan parameters

    MCP configuration (config/grok_mcp_config.json)

Security Notes

    Never commit: .env, OAuth client secrets (client_secret_*.json, oauthadmin.json), PEM/key files, or live capture databases (Kismet .kismet files).

📁 Project Layout

The repository is described by responsibility rather than by one very wide directory tree. Open only the group you need.
How to Read the Layout Recursively

For any directory, apply the same questions:

    Where is the entry point? Look for __init__.py, cli.py, main.py, runner.py, or a screen/controller module.

    What does it accept? Identify configuration, normalized targets, prior results, sessions, or catalog entries.

    What does it produce? Look for normalized result objects, events, files, database rows, or UI updates.

    Which adapters does it use? Follow wrappers around external tools, APIs, hardware, models, and storage.

    How does it fail? Check explicit error states, fallback paths, missing-dependency handling, and cleanup.

    How is it extended? Add a sibling module that follows the same input/output contract and register it in the nearest registry or catalog.

    Where is it tested? Search tests/ for the same module or subsystem name.

<details> <summary><strong>Repository root</strong></summary>

    main.py — primary curses-dashboard entry point.

    run.sh — general command-line launcher.

    run_tui.sh — focused TUI launcher.

    run_full_pipeline.sh — full workflow launcher.

    run_full_pipeline_v2.sh — enhanced workflow variant.

    prepare.sh — environment preparation.

    prepare_ollama_finetune.sh — local model preparation helper.

    setup.py — Python package metadata and installation.

    requirements.txt — Python dependencies.

    .env.example — optional environment-variable template.

    .gitignore — generated files and sensitive-data exclusions.

    LICENSE — project license.

    README.md — primary project documentation.

    KNOWN_ISSUES.md — known bugs and limitations.

    TODO.md — development roadmap.

    pytest.ini — test discovery configuration.

    metadata.json — project metadata.

</details>

<details> <summary><strong>core/ — application runtime</strong></summary>

core/ contains runtime behavior. Its children follow the same pattern: entry point, adapters, normalized results, error handling, registration, and tests.

    tui/ — screens, navigation, selectors, and live views.

    ai_backend/ — provider routing and chain planning.

    orchestrator/ — workflow execution, replanning, and adaptive control.

    modules/ — shared planning, reconnaissance, CVE, tool, and post-access integrations.

    scanners/ — Wi-Fi, BLE, Kismet, radio, and scan-limit backends.

    wifi_attack/ and extended_wifi/ — Wi-Fi-specific module families.

    ble/ and extended_ble/ — BLE discovery, GATT, and module families.

    osint/ — generic and Poland-specific open-source intelligence modules.

    post_exploit/ — post-access module collection.

    post_access_tui/ — interactive session-management interface.

    cve_to_exploit/ — vulnerability correlation and validation pipeline.

    c2/ — authorized laboratory communication framework.

    mcp/ — Model Context Protocol exposure for external agents.

    desktop/ — extended desktop-agent integration.

    db/ — SQLite storage and indexes.

    catalog/ — runtime catalog management.

    tool_installer/ — dependency and tool installation adapters.

    toolbox/ — toolbox discovery and lifecycle management.

    integrations/ — external services and provider adapters.

    live_edit/ and live_target/ — runtime overlays and live target state.

    recon/ — reusable reconnaissance primitives.

    replan/ — workflow replanning logic.

    refactors/ — compatibility and migration helpers.

    forensics/ — digital-forensics modules.

    neuroscience/ — experimental behavioral-analysis modules.

    android/, ios/, and microsoft/ — platform-specific instrumentation.

    utils/ — shared parsers, loaders, adapters, and navigation utilities.

    settings.py — runtime settings manager.

    bootstrap.py — preflight checks and model bootstrap.

    optimizations.py — performance-oriented helpers.

    exploit_knowledge_base.py — indexed SQLite knowledge base.

    tool_registry.py — runtime tool registration.

    algorithm_registry.py — algorithm indexing.

    osint_catalog.py — OSINT catalog access.

    mcp_server.py — MCP server entry point.

</details>

<details> <summary><strong>core/tui/ — recursive screen model</strong></summary>

Each screen should follow the same lifecycle:

    Load settings and current state.

    Validate terminal size and required dependencies.

    Render a compact view that can degrade to narrower widths.

    Handle navigation and operator decisions.

    Dispatch work to a domain service rather than embedding tool logic in the UI.

    Receive normalized events and refresh only affected regions.

    Restore terminal and interface state on exit.

Important files include:

    dashboard.py — top-level menu and screen routing.

    wifi_screen.py — Wi-Fi workflow view.

    ble_screen.py — BLE workflow view.

    osint_screen.py — OSINT workflow view.

    settings_screen.py — configuration UI.

    device_screen.py — device details.

    interface_picker.py — network-interface selection.

    wifi_scan_external.py — external scan viewer.

    base_screen.py — reusable screen behavior.

</details>

<details> <summary><strong>core/ai_backend/ and core/orchestrator/</strong></summary>

These directories implement the recursive planning loop:

    ai_backend/__init__.py — provider selection and fallback routing.

    ai_backend/chain.py — chain creation, step representation, and result-aware planning.

    orchestrator/autonomous_orchestrator.py — executes approved steps and records outcomes.

    orchestrator/adaptive_engagement.py — adjusts the next plan using normalized observations.

A parent chain may create a child chain. The child receives a narrower goal, returns a normalized result, and never bypasses the parent approval and cleanup boundaries.

</details>

<details> <summary><strong>Data, catalogs, configuration, and documentation</strong></summary>

    catalog/ — tool definitions and reusable chain metadata.

    config/ — dashboard and MCP configuration.

    data/ — runtime databases and generated research drafts.

    datasets/ — training and reference datasets.

    docs/ — extended documentation.

    assets/ — images and project resources.

    scripts/ — setup, migration, and bridge utilities.

Treat data directories as outputs, catalogs as declarative inputs, and core/ as executable behavior. This separation makes modules easier to test and replace.

</details>

<details> <summary><strong>tests/ — mirrored validation structure</strong></summary>

tests/ mirrors runtime responsibilities rather than duplicating implementation details.

    conftest.py — shared fixtures.

    fakes.py — controlled fake objects and adapters.

    test_bootstrap.py — preflight and startup behavior.

    test_chain_planner.py — planning and replanning contracts.

    test_catalog_chain_examples.py — catalog consistency.

    test_poly_adapt_*.py — transformation-engine behavior.

    test_settings_screen_actions.py — settings UI actions.

    test_wifi_screen_actions.py — Wi-Fi UI actions.

    test_adaptive_engagement.py — adaptive orchestration.

    test_scan_limits.py — scan boundaries and rate limits.

When adding a runtime module, add a test with the same responsibility and verify success, partial success, failure, fallback, and cleanup paths.

</details>

<details> <summary><strong>Standalone and compatibility modules</strong></summary>

    wifi_offensive_ai/core/engine.py — standalone Wi-Fi AI engine.

    ai_pentest_engine.py — standalone AI-assisted security-testing engine.

    metasploit_post_exploit.py — external integration runner.

    pentest_hf_registry.py — Hugging Face model registry logic.

    pentest_hf_registry.json — registry data.

Standalone modules should use the same normalized results and approval boundaries as core/ so they can later be absorbed into the main runtime without a breaking rewrite.

</details>
🛡 Safety Model

KFIOSA implements a defense-in-depth safety architecture:
1. ACCEPT / CANCEL Gate (Default-Deny)

Every offensive step requires explicit operator approval before execution. The TUI presents each planned action and waits for ACCEPT or CANCEL.
2. Nested Gate Inheritance (pre_accepted)

When a parent step is accepted, nested sub-tools inherit the acceptance flag to avoid double-prompting while maintaining the safety boundary.
3. Clean Teardown

Monitor-mode interfaces are automatically torn down on quit. Temporary processes (beacon, deauth, etc.) are killed on exit.
4. Honest Error Reporting

No fabricated results. If a tool is missing, unavailable, or fails:

    Empty result sets + explicit error messages

    MISSING status in the TUI for unconfigured features

    Error propagation to the orchestrator for replanning

5. Sensitive Data Protection

    .env and credentials excluded via .gitignore

    No API keys in source code

    OAuth secrets pattern-matched in .gitignore

🧪 Development & Testing
Setup

source .venv/bin/activate
pip install -r requirements.txt

Running Tests

# Full test suite (can be large)
pytest tests/ -q

# Focused testing
pytest tests/ -k "test_chain_planner" -v
pytest tests/ -k "test_bootstrap" -v
pytest tests/ -k "test_poly_adapt" -v

# With coverage
pytest tests/ --cov=core -q

Test Configuration (pytest.ini)

[pytest]
testpaths = tests
python_files = test_*.py
python_functions = test_*

Key Test Modules

<details> <summary><strong>`test_bootstrap.py`</strong></summary>

    Coverage: Preflight and Ollama bootstrap

</details>

<details> <summary><strong>`test_chain_planner.py`</strong></summary>

    Coverage: AI chain planning logic

</details>

<details> <summary><strong>`test_catalog_chain_examples.py`</strong></summary>

    Coverage: Catalog chain examples validation

</details>

<details> <summary><strong>`test_poly_adapt_*.py`</strong></summary>

    Coverage: Polymorphic evasion engine

</details>

<details> <summary><strong>`test_settings_screen_actions.py`</strong></summary>

    Coverage: Settings TUI actions

</details>

<details> <summary><strong>`test_wifi_screen_actions.py`</strong></summary>

    Coverage: Wi-Fi TUI actions

</details>

<details> <summary><strong>`test_adaptive_engagement.py`</strong></summary>

    Coverage: Orchestrator adaptive engagement

</details>

<details> <summary><strong>`test_scan_limits.py`</strong></summary>

    Coverage: Scan rate limiting

</details>

<details> <summary><strong>`test_holo_desktop.py`</strong></summary>

    Coverage: Desktop agent

</details>

<details> <summary><strong>`test_wifi_radio.py`</strong></summary>

    Coverage: Wi-Fi radio control

</details>
📋 Known Issues & Roadmap

See KNOWN_ISSUES.md for current bugs and limitations.

See TODO.md for the development roadmap, organized by phases:

    Phase 1: Core TUI + Wi-Fi/BLE scan

    Phase 2: AI chain planner + exploit pipeline + catalog expansion

    Phase 3: SQL backends, extended BLE, polymorphic v4, dashboard v3

    Phase 4: Catalog enhancement, model upgrades, performance optimization

    Phase 5+: MCP server, desktop agent, adaptive engagement

📄 License

This project is licensed under the MIT License — see the LICENSE file for details.

MIT License — Copyright (c) 2026 Wi-Fi Offensive AI Toolkit

⚖️ Disclaimer

    [!WARNING]
    This software is provided for education and authorized penetration testing only.

        You must have explicit, written authorization before testing any system or network.

        Active wireless attacks (deauth, beacon flood, evil twin) can disrupt real services.

        BLE attacks can interfere with medical and safety-critical devices.

        OSINT operations must comply with privacy regulations (GDPR, local laws).

        You are solely responsible for compliance with all applicable laws and rules of engagement.

    The authors and contributors assume no liability for misuse of this software.

<div align="center">

Built with 🐍 Python • 🤖 AI-Powered • 📡 Wireless-Native • 🛡️ Ethically Gated

</div>
