#!/usr/bin/env bash
# scripts/clone_search_tools.sh — clone the deduped GitHub tools
# from .claude/jobs/search_results/_clone_plan.tsv into toolboxes/.
# Idempotent: skips repos whose target dir already exists & non-empty.
# Logs every outcome to .claude/jobs/search_results/_clone_log.tsv
set -u
cd "$(dirname "$0")/.." || exit 1
PLAN=".claude/jobs/search_results/_clone_plan.tsv"
LOG=".claude/jobs/search_results/_clone_log.tsv"
: > "$LOG"
n=0; ok=0; skip=0; fail=0
# skip header
tail -n +2 "$PLAN" | while IFS=$'\t' read -r owner repo toolbox_dir url desc; do
  [ -z "${owner:-}" ] && continue
  n=$((n+1))
  target="toolboxes/${toolbox_dir}/${owner}__${repo}"
  if [ -d "$target" ] && [ -n "$(ls -A "$target" 2>/dev/null)" ]; then
    skip=$((skip+1))
    printf '%s\t%s\tskip\texists\n' "$owner/$repo" "$toolbox_dir" >> "$LOG"
    continue
  fi
  mkdir -p "toolboxes/${toolbox_dir}"
  if timeout 90 git clone --depth 1 --quiet "$url" "$target" 2>/tmp/clone_err_$$; then
    ok=$((ok+1))
    printf '%s\t%s\tok\n' "$owner/$repo" "$toolbox_dir" >> "$LOG"
  else
    fail=$((fail+1))
    err=$(head -c 200 /tmp/clone_err_$$ | tr '\t\n' '  ')
    printf '%s\t%s\tfail\t%s\n' "$owner/$repo" "$toolbox_dir" "$err" >> "$LOG"
    rm -rf "$target"
  fi
  rm -f /tmp/clone_err_$$
done
echo "done"