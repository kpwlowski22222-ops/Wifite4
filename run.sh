#!/bin/bash
# run.sh - Start the WiFi Offensive AI Toolkit with Python virtual environment
# Includes first-run detection and setup workflow
# Launches the TUI (Text User Interface) dashboard with arrow key navigation

echo "Starting WiFi Offensive AI Toolkit TUI Dashboard..."
echo "Use arrow keys to navigate, Enter to select, Backspace/q to go back"

# First-run detection and setup
FIRST_RUN_FILE=".first_run_complete"

if [ ! -f "$FIRST_RUN_FILE" ]; then
    echo "First run detected - performing setup..."
    
    # Create necessary directories
    mkdir -p models wordlists logs output
    
    # Activate virtual environment (create if needed)
    if [ -f "./wifi_offensive_venv/bin/activate" ]; then
        echo "Activating Python virtual environment..."
        source ./wifi_offensive_venv/bin/activate
    elif [ -f "./.venv/bin/activate" ]; then
        echo "Activating Python virtual environment..."
        source ./.venv/bin/activate
    else
        echo "Creating Python virtual environment..."
        python3 -m venv .venv
        source .venv/bin/activate
        
        # Install requirements
        echo "Installing Python dependencies..."
        pip install -r requirements.txt
    fi
    
    # Check for required system tools
    echo "Checking for required system tools..."
    REQUIRED_TOOLS=("aircrack-ng" "airmon-ng" "airodump-ng" "aireplay-ng" "wash" "mdk4" "nmap" "searchsploit" "msfconsole")
    MISSING_TOOLS=()
    
    for tool in "${REQUIRED_TOOLS[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            MISSING_TOOLS+=("$tool")
        fi
    done
    
    if [ ${#MISSING_TOOLS[@]} -gt 0 ]; then
        echo "Warning: The following tools are missing or not in PATH:"
        for tool in "${MISSING_TOOLS[@]}"; do
            echo "  - $tool"
        done
        echo "Please install these tools for full functionality."
        echo "On Kali Linux: sudo apt install aircrack-ng mdk4 nmap searchsploit metasploit-framework"
    else
        echo "All required system tools are available."
    fi
    
    # Run initial configuration if config.py exists
    if [ -f "config.py" ]; then
        echo "Running initial configuration check..."
        python -c "
import sys
sys.path.insert(0, '.')
from config import Config
config = Config()
print('Configuration loaded successfully')
print(f'Debug mode: {config.get(\"debug\", False)}')
print(f'ML optimization: {config.get(\"enable_ml_optimization\", True)}')
"
    fi
    
    # Mark first run as complete
    touch "$FIRST_RUN_FILE"
    echo "First-run setup completed."
else
    # Not first run - just activate environment
    if [ -f "./wifi_offensive_venv/bin/activate" ]; then
        echo "Activating Python virtual environment..."
        source ./wifi_offensive_venv/bin/activate
    elif [ -f "./.venv/bin/activate" ]; then
        echo "Activating Python virtual environment..."
        source ./.venv/bin/activate
    else
        echo "Creating Python virtual environment..."
        python3 -m venv .venv
        source .venv/bin/activate
        
        # Install requirements
        echo "Installing Python dependencies..."
        pip install -r requirements.txt
    fi
fi

# Check if we're in the right directory
cd /home/user/Pulpit/kfiosa

# Set terminal properties for optimal TUI experience
export TERM=xterm-256color
stty sane  # Reset terminal to sane state

# Start the WiFi Offensive AI Toolkit TUI Dashboard
echo "Launching WiFi Offensive AI Toolkit TUI Dashboard..."
echo "Controls: ↑↓ Arrow Keys to navigate, Enter to select, Backspace/q to go back"
python main.py "$@"

# Deactivate virtual environment when done
deactivate
echo "WiFi Offensive AI Toolkit TUI Dashboard terminated."