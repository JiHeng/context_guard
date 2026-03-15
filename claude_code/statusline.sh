#!/usr/bin/env bash
# context guard status line for Claude Code

set -euo pipefail

PID_FILE="$HOME/.context_guard/proxy.pid"
CONFIG_FILE="$HOME/.context_guard/config.json"
LOCAL_CONFIG="$(dirname "$(dirname "$0")")/config.json"

if [[ -f "$PID_FILE" ]] && kill -0 "$(<"$PID_FILE")" 2>/dev/null; then
    # Check enabled flag from config.json
    ENABLED=true
    for cfg in "$CONFIG_FILE" "$LOCAL_CONFIG"; do
        if [[ -f "$cfg" ]]; then
            val=$(python3 -c "import json; print(json.load(open('$cfg')).get('enabled', True))" 2>/dev/null || echo "True")
            if [[ "$val" == "False" ]]; then
                ENABLED=false
            fi
            break
        fi
    done

    if [[ "$ENABLED" == "false" ]]; then
        echo "[cg: PAUSED]"
    else
        # Count today's redacted entries from daily audit log
        TODAY=$(date +%Y-%m-%d)
        AUDIT="$HOME/.context_guard/audit-${TODAY}.log"
        if [[ -f "$AUDIT" ]]; then
            COUNT=$(grep -c '| redacted |' "$AUDIT" 2>/dev/null || true)
        else
            COUNT=0
        fi
        echo "[cg: ON, ${COUNT} filtered]"
    fi
else
    echo "[cg: OFF]"
fi
