#!/usr/bin/env bash
# kali_run.sh — ask omniscience-cyber for the right Kali command, review it, then run it.
# The API's /tool endpoint returns command-only output (no prose) so it feeds straight into
# a shell. This wrapper adds a confirm-before-exec safety step (never blind-pipes to bash).
#
# Usage:
#   ./kali_run.sh "directory brute force the target with ffuf"
#   API=http://192.168.1.5:8600 ./kali_run.sh "nuclei scan the target"
#   ./kali_run.sh -y "nmap service scan"      # -y = auto-run without prompt (careful)
set -uo pipefail

API="${API:-http://127.0.0.1:8600}"
AUTO=0
[ "${1:-}" = "-y" ] && { AUTO=1; shift; }
TASK="$*"
[ -z "$TASK" ] && { echo "usage: $0 [-y] \"<task>\""; exit 2; }

# get command(s) — plain text, one per line
CMDS=$(curl -sS --get "$API/tool" --data-urlencode "task=$TASK" 2>/dev/null)
if [ -z "$CMDS" ]; then echo "# no response from $API (is 'python rag/api.py' running?)"; exit 1; fi

echo "=== suggested command(s) for: $TASK ==="
echo "$CMDS"
echo "==========================================="
echo "REVIEW: fill any <TARGET>/<WORDLIST>/<COOKIE> placeholders and confirm scope before running."

if [ "$AUTO" = "1" ]; then
  echo "[auto-run]"; echo "$CMDS" | bash
else
  read -r -p "Run these now? [y/N] " ans
  case "$ans" in
    y|Y) echo "$CMDS" | bash ;;
    *)   echo "not run. Copy/edit the commands above." ;;
  esac
fi
