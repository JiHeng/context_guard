#!/usr/bin/env bash
# context guard uninstaller — complete cleanup
# This script is also copied to ~/.context_guard/ so uninstall works without the source repo.

set -e

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

# --- 2. Remove shell RC block ---
for RC_FILE in "$HOME/.bashrc" "$HOME/.zshrc"; do
    if [ -f "$RC_FILE" ] && grep -qF '# BEGIN context_guard' "$RC_FILE" 2>/dev/null; then
        sed -i '/^# BEGIN context_guard$/,/^# END context_guard$/d' "$RC_FILE"
        # Remove trailing blank line left behind
        sed -i -e :a -e '/^\n*$/{$d;N;ba' -e '}' "$RC_FILE"
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

# --- 5. Delete install directory ---
if [ -d "$INSTALL_DIR" ]; then
    rm -rf "$INSTALL_DIR"
    echo "[context_guard] Removed $INSTALL_DIR"
fi

echo ""
echo "[context_guard] Uninstall complete!"
echo ""
echo "Please reload your shell (exec \$SHELL) or open a new terminal."
echo "Claude Code will now connect directly to the Anthropic API."
