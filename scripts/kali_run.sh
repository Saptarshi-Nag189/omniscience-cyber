#!/usr/bin/env bash
# kali_run.sh — ask omniscience-cyber for the right Kali command, review it, then run it.
# The API's /tool endpoint returns command-only output (no prose) so it feeds straight into
# a shell. This wrapper adds a confirm-before-exec safety step (never blind-pipes to bash).
#
# Usage:
#   ./kali_run.sh "directory brute force the target with ffuf"
#   API=http://192.168.1.5:8600 ./kali_run.sh "nuclei scan the target"
#   OMNISCIENCE_API_TOKEN=... ./kali_run.sh "nmap service scan"   # token for a LAN API
#   ./kali_run.sh -y "nmap service scan"      # -y = auto-run without prompt (careful)
#
# Commands the API's scope_guard BLOCKS (out-of-scope / DoS / bulk-exfil) come back as
# `# BLOCKED: <reason>` comment lines — harmless if piped to bash, but read them.
set -uo pipefail

API="${API:-http://127.0.0.1:8600}"
AUTO=0
[ "${1:-}" = "-y" ] && { AUTO=1; shift; }
TASK="$*"
[ -z "$TASK" ] && { echo "usage: $0 [-y] \"<task>\""; exit 2; }

# send the bearer token if one is configured (required for a non-loopback API)
AUTH=()
[ -n "${OMNISCIENCE_API_TOKEN:-}" ] && AUTH=(-H "Authorization: Bearer ${OMNISCIENCE_API_TOKEN}")

# get command(s) — plain text, one per line
CMDS=$(curl -sS "${AUTH[@]}" --get "$API/tool" --data-urlencode "task=$TASK" 2>/dev/null)
if [ -z "$CMDS" ]; then echo "# no response from $API (is 'python rag/api.py' running?)"; exit 1; fi

echo "=== suggested command(s) for: $TASK ==="
echo "$CMDS"
echo "==========================================="
if echo "$CMDS" | grep -q "^# BLOCKED"; then
  echo "[!] One or more commands were BLOCKED by scope_guard (see reasons above)."
fi
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
