# WiFi Offensive AI Toolkit - Pure Python/TUI Version

A comprehensive wireless penetration testing framework converted to a pure Python/TUI (Text User Interface) version similar to wifite4, with Google Cloud Compute Engine integration for AI model training and usage.

## Features

- **Pure Python/TUI Interface**: No web GUI dependencies - runs entirely in terminal using curses
- **Similar to wifite4**: Familiar menu-driven interface for wireless security testing
- **Google Cloud Integration**: Train and deploy AI models on AI Platform for smart wordlist generation and attack optimization
- **Modular Design**: Leverages existing Python tools (wifi_tools.py, mt7921e_tools.py, exploitation_tools.py)
- **AI/ML Capabilities**: Smart wordlist generation, attack parameter optimization, success prediction
- **First-Run Setup**: Automatic virtual environment creation and dependency installation

## Components

### Core Files
- `main.py` - Main TUI application with menu-driven interface
- `run.sh` - Script to activate virtual environment and launch the toolkit
- `requirements.txt` - Python dependencies including Google Cloud libraries
- `config.py` - Configuration management
- `model_manager.py` - AI/ML model handling for smart wordlists and attack optimization
- `google_cloud_integration.py` - Google Cloud AI Platform and Compute Engine integration

### Existing Tools (Updated for TUI Compatibility)
- `wifi_tools.py` - Wrapper functions for Kali Linux WiFi exploitation tools
- `mt7921e_tools.py` - Specialized tools for mt7921e driver packet injection
- `exploitation_tools.py` - Network exploitation and post-exploitation tools

## Menu System

The TUI features a simple menu system:

1. **Scan Networks** - Discover wireless networks using airodump-ng
2. **Capture Handshake** - Capture WPA/WPA2 handshakes
3. **Run Attacks** - Execute various attack types (deauth, WPS, etc.)
4. **Post-Exploitation** - Network pivoting, data exfiltration, persistence
5. **AI/ML Models** - Smart wordlist generation and attack optimization
6. **Google Cloud** - Model training and deployment on AI Platform
7. **Configuration** - Set targets and adjust settings
8. **Help** - Display help information
0. **Exit** - Quit the application

When a chain step achieves access (captured creds or a Meterpreter
`session_id`), the orchestrator auto-prompts to open the
**Post-Access TUI** — a separate curses window for shell, file
transfer, network ops (portfwd / SOCKS), persistence, and module
re-runs against the active session. Detach with `F12` / `Esc` /
`X`; the main chain keeps running. The AI can also request the
post-access TUI explicitly via the `open_post_access_tui` action
or the `open_post_access_tui` MCP wrapper.

## Installation & Usage

### Quick Start
```bash
# Make the run script executable
chmod +x run.sh

# Run the toolkit (will automatically set up virtual environment)
./run.sh
```

### Manual Setup
```bash
# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run the toolkit
python main.py
```

### First-Run Configuration
On first run, the toolkit will:
1. Create a Python virtual environment (if not exists)
2. Install required dependencies
3. Prompt for configuration (targets, API keys, etc.)
4. Set up Google Cloud integration if credentials are provided

## Google Cloud Integration

To enable Google Cloud features:

1. Create a Google Cloud project and enable:
   - AI Platform Training & Prediction API
   - Compute Engine API
   - Cloud Storage API

2. Create a service account and download the JSON key file

3. Set environment variables:
   ```bash
   export GCP_PROJECT_ID="your-project-id"
   export GCP_APPLICATION_CREDENTIALS="path/to/your/keyfile.json"
   ```

4. The toolkit will then be able to:
   - Train models on AI Platform for smart wordlist generation
   - Deploy models for online prediction
   - Use cloud-based computing for intensive ML tasks
   - Store training data and models in Cloud Storage

## Architecture

The toolkit follows a modular architecture:

```
main.py
├── TUI Interface (curses-based)
├── Core Modules:
│   ├── wifi_tools.py          # Wireless attack tools
│   ├── mt7921e_tools.py         # mt7921e-specific packet injection
│   ├── exploitation_tools.py  # Network exploitation
│   ├── config.py              # Configuration management
│   ├── model_manager.py       # AI/ML model handling
│   └── google_cloud_integration.py  # GCP services
└── Support Systems:
    ├── Logging
    ├── Activity tracking
    └── Threaded operations (to prevent UI blocking)
```

## Security Notes

- This toolkit is intended for authorized security testing only
- Ensure you have explicit permission before testing any networks
- Follow all applicable laws and regulations
- The Google Cloud integration requires proper security configuration of your GCP project

## Dependencies

See `requirements.txt` for complete list. Key dependencies include:
- `curses` / `windows-curses` - Terminal UI
- `google-cloud-aiplatform` - AI Platform integration
- `google-auth` - Google Cloud authentication
- `requests` - HTTP client for API calls
- `python-dotenv` - Environment variable management

## Customization

Edit `config.py` or set environment variables to customize:
- Default wireless interface
- Scan durations and timeouts
- Google Cloud project and region
- Model storage locations
- AI/ML feature toggles

## Contributing

This is a conversion project to create a pure Python/TUI version of the WiFi Offensive AI Toolkit. Contributions are welcome for:
- Improving the TUI interface
- Enhancing AI/ML model integration
- Adding new attack modules
- Improving Google Cloud integration
- Bug fixes and performance improvements

## License

See LICENSE file for licensing information.