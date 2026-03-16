#!/usr/bin/env bash
# context guard uninstaller — complete cleanup
# This script is also copied to ~/.context_guard/ so uninstall works without the source repo.

set -e

# Portable in-place sed (BSD vs GNU)
_sed_i() { if sed --version 2>/dev/null | grep -q GNU; then sed -i "$@"; else sed -i '' "$@"; fi; }

INSTALL_DIR="$HOME/.context_guard"
CLAUDE_DIR="$HOME/.claude"
CLAUDE_SETTINGS="$CLAUDE_DIR/settings.json"

echo "[context_guard] Uninstalling ..."

# --- 1. Stop proxy if running ---
PID_FILE="$INSTALL_DIR/proxy.pid"
if [ -f "$PID_FILE" ]; then
    PID="$(cat "$PID_FILE" 2>/dev/null || true)"
    if [ -n "$PID" ] && kill -0 "$PID" 2>/dev/null; then
        kill "$PID" 2>/dev/null || true
        echo "[context_guard] Stopped proxy (pid $PID)"
    fi
fi

# --- 1b. Warn about active Claude Code sessions ---
SESSIONS_DIR="$INSTALL_DIR/sessions"
if [ -d "$SESSIONS_DIR" ]; then
    LIVE=0
    for f in "$SESSIONS_DIR"/*; do
        [ -f "$f" ] || continue
        PID="$(basename "$f")"
        kill -0 "$PID" 2>/dev/null && LIVE=$((LIVE + 1))
    done
    if [ "$LIVE" -gt 0 ]; then
        echo "[context_guard] Warning: $LIVE active Claude Code session(s) detected."
        echo "[context_guard] Session hooks will show errors after uninstall."
        printf "[context_guard] Continue? [y/N] "
        read -r CONFIRM
        [ "$CONFIRM" = "y" ] || [ "$CONFIRM" = "Y" ] || { echo "[context_guard] Cancelled."; exit 0; }
    fi
fi

# --- 2. Remove shell RC block ---
for RC_FILE in "$HOME/.bashrc" "$HOME/.zshrc"; do
    if [ -f "$RC_FILE" ] && grep -qF '# BEGIN context_guard' "$RC_FILE" 2>/dev/null; then
        _sed_i '/^# BEGIN context_guard$/,/^# END context_guard$/d' "$RC_FILE"
        # Remove trailing blank line left behind
        _sed_i -e :a -e '/^\n*$/{$d;N;ba' -e '}' "$RC_FILE"
        echo "[context_guard] Cleaned $RC_FILE"
    fi
done

# --- 3. Remove hooks from ~/.claude/settings.json ---
if [ -f "$CLAUDE_SETTINGS" ] && command -v python3 &>/dev/null; then
    python3 -c "
import json, sys

path = '$CLAUDE_SETTINGS'
with open(path) as f:
    data = json.load(f)

changed = False

# Remove context guard hooks
hooks = data.get('hooks', {})
for event in list(hooks.keys()):
    original = hooks[event]
    filtered = [h for h in original if 'context_guard' not in json.dumps(h)]
    if len(filtered) != len(original):
        changed = True
        if filtered:
            hooks[event] = filtered
        else:
            del hooks[event]
if not hooks and 'hooks' in data:
    del data['hooks']
    changed = True

# Remove statusLine if it references context guard
sl = data.get('statusLine', {})
if 'context_guard' in json.dumps(sl):
    del data['statusLine']
    changed = True

if changed:
    with open(path, 'w') as f:
        json.dump(data, f, indent=2)
        f.write('\n')
" 2>/dev/null && echo "[context_guard] Cleaned $CLAUDE_SETTINGS"
fi

# --- 4. Remove Claude Code files ---
for f in \
    "$CLAUDE_DIR/commands/cg.md" \
    "$CLAUDE_DIR/statusline_context_guard.sh" \
    "$CLAUDE_DIR/statusline_merged.sh"; do
    if [ -f "$f" ]; then
        rm -f "$f"
        echo "[context_guard] Removed $f"
    fi
done

# --- 5. Delete install directory, optionally preserve rules ---
if [ -d "$INSTALL_DIR" ]; then
    HAS_RULES=false
    for f in config.json allow.txt; do
        if [ -f "$INSTALL_DIR/$f" ]; then
            HAS_RULES=true
            break
        fi
    done

    if [ "$HAS_RULES" = true ]; then
        printf "[context_guard] Keep your rules (config.json, allow.txt) for next install? [Y/n] "
        read -r KEEP_RULES
        KEEP_RULES="${KEEP_RULES:-Y}"
        if [ "$KEEP_RULES" = "n" ] || [ "$KEEP_RULES" = "N" ]; then
            rm -rf "$INSTALL_DIR"
            echo "[context_guard] Removed $INSTALL_DIR (rules deleted)"
        else
            BACKUP_DIR="$HOME/.context_guard_backup"
            mkdir -p "$BACKUP_DIR"
            for f in config.json allow.txt; do
                [ -f "$INSTALL_DIR/$f" ] && cp "$INSTALL_DIR/$f" "$BACKUP_DIR/$f"
            done
            rm -rf "$INSTALL_DIR"
            echo "[context_guard] Removed $INSTALL_DIR"
            echo "[context_guard] Rules saved to $BACKUP_DIR/ — restored automatically on next install."
        fi
    else
        rm -rf "$INSTALL_DIR"
        echo "[context_guard] Removed $INSTALL_DIR"
    fi
fi

echo ""
echo "[context_guard] Uninstall complete!"
echo ""
echo "Run this in your current shell to clear the proxy URL:"
echo ""
echo "  unset ANTHROPIC_BASE_URL"
echo ""
echo "Or reload your shell (exec \$SHELL) / open a new terminal."
echo "Claude Code will then connect directly to the Anthropic API."
