#!/usr/bin/env bash
# Fetch the WiFi recon toolbox repos into toolboxes/recon/<owner>__<repo>/.
#
# Mirrors scripts/prepare_injection_toolbox.sh: --depth 1 clones, skips
# repos already cloned, logs failures, and updates MANIFEST.txt. The repos
# are fetched "ready to run" — per-repo build/usage notes are written by the
# classify workflow output + this script's per-repo README pointer.
#
# Safe to re-run: existing dirs are left untouched.
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEST="$ROOT/toolboxes/recon"
mkdir -p "$DEST"

REPOS=(
  "thomasbuilds/Spectre"
  "CipherX1802/DisAPster"
  "lsna91/WIFIREWONV1"
  "jib1337/blockade-recon"
  "edonsec/wifi-hawk"
  "AidoP/blockade-recon"
  "justuswilhelm/wifi-recon"
  "demonCoder95/wifi-recon"
  "Kr1spyDotCom/Recon"
  "Nasim7045/Wifi-Reconaissance-Program"
  "Ayush19-01/GCI-Wifi-Recon"
  "YashKarthik/wifi_Network_recon"
  "SaMi-bits/wifi-recon-attack"
  "coderkrupal/Wavescout-wifi_recon"
  "kpratheesh/AI-WiFi-Recon-Tool"
  "xransum/phantex"
  "Anonymous40443/SCAN-X"
  "sergioamsilva/wifi-security-toolkit"
  "Danielmolina5/-WiFi-Network-Attack-Intrusion-Reconnaissance-Monitoring"
  "HikmatAsifli/wifi_auth_tool"
  "ahirankush771/netprobe"
  "pittisl/AiFi_PHY_Reconstruct"
  "haxorthematrix/iSniff-GPS-ng"
  "karanhacker98/PROTOCOL-X-Framework"
  "bernisnukic/airprowl"
  "n3twork5/xharvester"
  "BettridgeKameron/Engr100-Pentesting-Demo"
  "ChrisRyanKelly/airspace-mapper"
  "iaghapour/WiFi-Reconnector"
  "momenbasel/AutoWIFI"
  "hkm/whoishere.py"
  "bad-antics/nullsec-pineapple-suite"
)

ok=0; fail=0; skip=0
fail_log="$DEST/.clone_failures.log"
: > "$fail_log"

for full in "${REPOS[@]}"; do
  owner="${full%%/*}"
  repo="${full#*/}"
  dir="${owner}__${repo}"
  target="$DEST/$dir"
  if [ -d "$target" ] && [ -n "$(ls -A "$target" 2>/dev/null)" ]; then
    echo "[skip] $dir (already present)"
    skip=$((skip+1))
    continue
  fi
  url="https://github.com/${full}.git"
  echo "[clone] $dir <- $url"
  if git clone --depth 1 -- "$url" "$target" >/dev/null 2>"$DEST/.clone_err.$$"; then
    ok=$((ok+1))
  else
    fail=$((fail+1))
    echo "  FAILED: $(head -1 "$DEST/.clone_err.$$")"
    echo "$dir :: $(head -1 "$DEST/.clone_err.$$")" >> "$fail_log"
    rm -rf "$target"
  fi
  rm -f "$DEST/.clone_err.$$"
done

# Rewrite MANIFEST.txt: preserve the header comment + the existing fetched
# list, append any newly fetched dirs that aren't already listed (sorted,
# deduped). We keep it a simple sorted dir-name list with a header.
{
  echo "# KFIOSA toolboxes/recon — fetched recon repos"
  echo "# Auto-managed by scripts/prepare_recon_toolbox.sh"
  echo
  ls -1 "$DEST" | grep '__' | sort -u
} > "$DEST/MANIFEST.txt"

echo
echo "done: cloned=$ok skipped=$skip failed=$fail"
if [ "$fail" -gt 0 ]; then
  echo "failures logged in $fail_log"
  exit 1
fi
exit 0