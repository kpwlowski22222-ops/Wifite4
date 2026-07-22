#!/usr/bin/env bash
# prepare_injection_toolbox.sh — build the standalone injection tools
# fetched into toolboxes/wifi/ so the AI chain can drive them via
# core/modules/external_injection.py.
#
# Safe-by-default: builds only the tools whose build is self-contained
# on a Kali host (fksvs/inject `make`, nemesis autotools). The heavier
# builds (WiFiPacketRadio needs libcodec2/libasound; mt7921e firmware
# needs a Debian-11 Docker toolchain) are NOT auto-run — they are
# documented below and in toolboxes/wifi/INJECTION_TOOLBOX.md so the
# operator can opt in per tool.
#
# Usage:
#   ./scripts/prepare_injection_toolbox.sh            # build the easy two
#   ./scripts/prepare_injection_toolbox.sh --all      # also attempt wpr_tx
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TB="$ROOT/toolboxes/wifi"
ok=0; fail=0

have() { command -v "$1" >/dev/null 2>&1; }

build_inject() {
  local d="$TB/fksvs__inject"
  echo "=== [1] fksvs/inject (L2/L3 craft+inject+sniff) ==="
  if [ ! -d "$d" ]; then echo "  SKIP: $d missing"; fail=$((fail+1)); return; fi
  if ! have gcc; then echo "  SKIP: gcc not installed (apt install build-essential)"; fail=$((fail+1)); return; fi
  ( cd "$d" && make -j1 ) && { echo "  OK: $d/inject built"; ok=$((ok+1)); } \
    || { echo "  FAIL: inject build"; fail=$((fail+1)); }
}

build_nemesis() {
  local d="$TB/libnet__nemesis"
  echo "=== [2] libnet/nemesis (L2/L3 packet crafter) ==="
  if [ ! -d "$d" ]; then echo "  SKIP: $d missing"; fail=$((fail+1)); return; fi
  if ! have gcc; then echo "  SKIP: gcc not installed"; fail=$((fail+1)); return; fi
  # nemesis needs libnet (runtime + dev). On Kali: apt install libnet1 libnet1-dev.
  if ! have pkg-config || ! pkg-config --exists libnet-1.1 2>/dev/null; then
    echo "  NOTE: libnet not found — try: apt install libnet1 libnet1-dev autoconf automake libtool"
  fi
  ( cd "$d" && { [ -f configure ] || ./autogen.sh; } && ./configure && make -j1 ) \
    && { echo "  OK: $d/nemesis built"; ok=$((ok+1)); } \
    || { echo "  FAIL: nemesis build (see NOTE above)"; fail=$((fail+1)); }
}

build_wpr() {
  local d="$TB/RuhanSA079__WiFiPacketRadio"
  echo "=== [3] WiFiPacketRadio wpr_tx_rx (radiotap raw 802.11 TX) ==="
  if [ ! -d "$d" ]; then echo "  SKIP: $d missing"; fail=$((fail+1)); return; fi
  if ! have gcc; then echo "  SKIP: gcc not installed"; fail=$((fail+1)); return; fi
  if ! have pkg-config || ! (pkg-config --exists codec2 2>/dev/null && pkg-config --exists libpcap 2>/dev/null); then
    echo "  NOTE: needs libcodec2 + libpcap + libasound — try: apt install libcodec2-dev libpcap-dev libasound2-dev"
  fi
  ( cd "$d" && ./build.sh ) && { echo "  OK: $d/bin/wpr_tx_rx built"; ok=$((ok+1)); } \
    || { echo "  FAIL: wpr_tx_rx build (see NOTE above)"; fail=$((fail+1)); }
}

echo "prepare_injection_toolbox.sh — building standalone injection tools"
echo "toolbox: $TB"
echo
build_inject
echo
build_nemesis
if [ "${1:-}" = "--all" ]; then
  echo
  build_wpr
fi
echo
echo "=== summary: ok=$ok fail=$fail ==="
echo
echo "Not auto-built (opt in manually — see toolboxes/wifi/INJECTION_TOOLBOX.md):"
echo "  - cse508 DNS inject  : pure Python (scapy) — no build; pip install scapy netifaces"
echo "  - mt7921e firmware research: clone mt76/mt7921e driver + linux-firmware blob (closed MediaTek FW; offline RE only)"
exit $(( fail > 0 ? fail : 0 ))