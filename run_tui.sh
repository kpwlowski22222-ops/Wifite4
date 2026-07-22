#!/bin/bash
# =============================================================================
# KFIOSA launcher — wifite-style curses dashboard.
#
# Before launching, this script runs a REAL preflight:
#   1. Ensures a user-owned Python venv exists (creates one if missing).
#   2. Checks Python dependencies (hard + optional) from requirements.txt.
#   3. Checks the external offensive CLI toolchain (aircrack-ng, bluez,
#      Metasploit, OSINT CLIs, ...) via `core.bootstrap.check_tools`.
#   4. Checks Ollama reachability + pulled models.
#   5. Offers to `pip install -r requirements.txt` when hard deps are missing.
# Only then does it hand off to `python main.py` (core.tui.dashboard).
#
# Quit the dashboard with `q`; go back with Backspace.
# =============================================================================

set -u

# Resolve the project directory from the script location so it runs from anywhere.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

PY="${PY:-python3}"

# -----------------------------------------------------------------------------
# 1. Virtualenv
# -----------------------------------------------------------------------------
if [ ! -d ".venv" ]; then
    echo "[*] Creating a user-owned virtualenv at .venv ..."
    "$PY" -m venv .venv || { echo "[!] Failed to create .venv"; exit 1; }
fi

# shellcheck disable=SC1091
source .venv/bin/activate
PY=python

# Fix ownership if the venv was accidentally created by root (pip Errno 13).
OWNER="$(stat -c '%U' .venv 2>/dev/null || true)"
if [ "$OWNER" = "root" ] && [ "$(id -u)" -ne 0 ] && [ "$(sudo -n true 2>/dev/null; echo $?)" = "0" ]; then
    echo "[*] .venv is owned by root — fixing ownership to $(whoami) ..."
    sudo chown -R "$(whoami)":"$(id -gn)" .venv || true
fi

# -----------------------------------------------------------------------------
# 2/3/4. Preflight: deps + tools + Ollama
# -----------------------------------------------------------------------------
run_preflight() {
    "$PY" - <<'PYEOF'
import sys
from core.bootstrap import preflight
report = preflight()
sys.exit(1 if report.get("hard_missing") else 0)
PYEOF
}

echo "[*] Running preflight (Python deps + offensive toolchain + Ollama) ..."
if ! run_preflight; then
    echo ""
    echo "[!] Some REQUIRED Python dependencies are missing."
    if [ -t 0 ]; then
        read -r -p "    Install/upgrade from requirements.txt now? [y/N] " ans
        case "$ans" in
            y|Y|yes|YES)
                "$PY" -m pip install --upgrade pip >/dev/null 2>&1 || true
                "$PY" -m pip install -r requirements.txt || {
                    echo "[!] pip install failed — resolve the error above, then re-run."
                    exit 1
                }
                echo "[+] Dependencies installed. Re-running preflight ..."
                run_preflight || {
                    echo "[!] Preflight still failing after install. Launching anyway; some features may error honestly."
                }
                ;;
            *)
                echo "[i] Skipping install. Hard deps missing — the TUI may fail to start."
                ;;
        esac
    else
        echo "[!] Non-interactive shell — cannot prompt. Run:  $PY -m pip install -r requirements.txt"
        echo "    Then re-run this script."
        exit 1
    fi
fi

# -----------------------------------------------------------------------------
# 5. Launch the wifite-style curses dashboard
# -----------------------------------------------------------------------------
echo ""
echo "[*] Launching KFIOSA dashboard  (menu: wifi scan / ble scan / osint / settings / quit)"
echo "    Navigate: arrow keys · Select: Enter · Back: Backspace · Quit: q"
echo ""
exec "$PY" main.py