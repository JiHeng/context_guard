#!/usr/bin/env bash
# context guard installer
# Copies files to ~/.context_guard/ and adds a cg shell function to your shell RC.

set -e

# Portable in-place sed (BSD vs GNU)
_sed_i() { if sed --version 2>/dev/null | grep -q GNU; then sed -i "$@"; else sed -i '' "$@"; fi; }

INSTALL_DIR="$HOME/.context_guard"
REPO_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "[context_guard] Installing to $INSTALL_DIR ..."
mkdir -p "$INSTALL_DIR"

# Restore user rules from backup if available (left by uninstall)
BACKUP_DIR="$HOME/.context_guard_backup"
if [ -d "$BACKUP_DIR" ]; then
    for f in config.json allow.txt; do
        if [ -f "$BACKUP_DIR/$f" ] && [ ! -f "$INSTALL_DIR/$f" ]; then
            cp "$BACKUP_DIR/$f" "$INSTALL_DIR/$f"
        fi
    done
    rm -rf "$BACKUP_DIR"
    echo "[context_guard] Restored rules from previous installation"
fi

# Copy all source files
cp -r "$REPO_DIR/engine"           "$INSTALL_DIR/"
cp -r "$REPO_DIR/proxy"            "$INSTALL_DIR/"
cp    "$REPO_DIR/context_guard.py"  "$INSTALL_DIR/"

# Copy default config only if not already present (preserve user customisations)
if [ ! -f "$INSTALL_DIR/config.json" ]; then
    cp "$REPO_DIR/config.json" "$INSTALL_DIR/"
    echo "[context_guard] Created default config.json"
fi

cp    "$REPO_DIR/cg"               "$INSTALL_DIR/"
cp    "$REPO_DIR/uninstall.sh"     "$INSTALL_DIR/"
chmod +x "$INSTALL_DIR/uninstall.sh"
chmod +x "$INSTALL_DIR/context_guard.py" "$INSTALL_DIR/cg"

# --- Claude Code integration: /cg command + status line ---
CLAUDE_DIR="$HOME/.claude"
mkdir -p "$CLAUDE_DIR/commands"

# Install /cg command — handle conflict if user already has a /cg
CMD_NAME="cg"
TARGET="$CLAUDE_DIR/commands/${CMD_NAME}.md"

if [ -f "$TARGET" ] && ! grep -q 'context_guard' "$TARGET" 2>/dev/null; then
    echo "[context_guard] ⚠ /cg command already exists in ~/.claude/commands/."
    printf "  Enter an alternative command name (e.g. guard, cguard): "
    read -r CMD_NAME
    CMD_NAME="${CMD_NAME:-cguard}"
    TARGET="$CLAUDE_DIR/commands/${CMD_NAME}.md"
    echo "  Will install as /${CMD_NAME}"
fi

cp "$REPO_DIR/claude_code/commands/cg.md" "$TARGET"
if [ "$CMD_NAME" != "cg" ]; then
    _sed_i "s|/cg\`|/${CMD_NAME}\`|g" "$TARGET"
fi
echo "[context_guard] Installed /${CMD_NAME} command → $TARGET"

cp "$REPO_DIR/claude_code/statusline.sh"  "$CLAUDE_DIR/statusline_context_guard.sh"
chmod +x "$CLAUDE_DIR/statusline_context_guard.sh"

# Add statusLine to ~/.claude/settings.json (create if missing, merge if exists)
CLAUDE_SETTINGS="$CLAUDE_DIR/settings.json"
python3 -c "
import json, os, sys

settings_path = os.path.expanduser('$CLAUDE_SETTINGS')

# Load existing settings or start fresh
if os.path.isfile(settings_path):
    with open(settings_path) as f:
        data = json.load(f)
else:
    data = {}

sl = data.get('statusLine', {})
sl_json = json.dumps(sl)

if 'context_guard' in sl_json:
    print('[context_guard] statusLine already configured, skipping.')
    sys.exit(0)

CG_CMD = 'bash ~/.claude/statusline_context_guard.sh'

if sl and sl.get('command'):
    # Existing statusLine from another tool — merge via wrapper script
    existing_cmd = sl['command']
    merged_path = os.path.expanduser('~/.claude/statusline_merged.sh')
    with open(merged_path, 'w') as f:
        f.write('#!/usr/bin/env bash\n')
        f.write('# Auto-generated: merges user statusline + context guard statusline\n')
        f.write(f'# Original: {existing_cmd}\n\n')
        f.write('# Original user status line\n')
        f.write(f'{existing_cmd} 2>/dev/null\n\n')
        f.write('# context guard status line\n')
        f.write(f'{CG_CMD}\n')
    os.chmod(merged_path, 0o755)
    data['statusLine'] = {'type': 'command', 'command': 'bash ~/.claude/statusline_merged.sh'}
    print('[context_guard] Merged statusLine with existing config → statusline_merged.sh')
else:
    # No statusLine yet — set ours
    data['statusLine'] = {'type': 'command', 'command': CG_CMD}
    print(f'[context_guard] Added statusLine to {settings_path}')

with open(settings_path, 'w') as f:
    json.dump(data, f, indent=2)
    f.write('\n')
"

# --- Add permission for cg rules commands ---
python3 -c "
import json, os

settings_path = os.path.expanduser('$CLAUDE_SETTINGS')
with open(settings_path) as f:
    data = json.load(f)

perms = data.get('permissions', {})
allow = perms.get('allow', [])

cg_perm = 'Bash(python3 ~/.context_guard/cg rules*)'
if cg_perm not in allow:
    allow.append(cg_perm)
    perms['allow'] = allow
    data['permissions'] = perms
    with open(settings_path, 'w') as f:
        json.dump(data, f, indent=2)
        f.write('\n')
    print('[context_guard] Added Bash permission for cg rules commands')
else:
    print('[context_guard] Bash permission for cg rules already configured')
"

# --- Inject SessionStart / SessionEnd hooks ---
python3 -c "
import json, os

settings_path = os.path.expanduser('$CLAUDE_SETTINGS')
with open(settings_path) as f:
    data = json.load(f)

hooks = data.get('hooks', {})

cg_acquire = {'hooks': [{'type': 'command', 'command': 'python3 ~/.context_guard/cg _acquire \$PPID'}]}
cg_release = {'hooks': [{'type': 'command', 'command': 'python3 ~/.context_guard/cg _release \$PPID'}]}

changed = False
for event, entry in [('SessionStart', cg_acquire), ('SessionEnd', cg_release)]:
    existing = hooks.get(event, [])
    already = any('context_guard' in str(h) for h in existing)
    if not already:
        existing.append(entry)
        changed = True
    hooks[event] = existing

if changed:
    data['hooks'] = hooks
    with open(settings_path, 'w') as f:
        json.dump(data, f, indent=2)
        f.write('\n')
    print('[context_guard] Added SessionStart/SessionEnd hooks to settings.json')
else:
    print('[context_guard] Hooks already configured, skipping.')
"

echo "[context_guard] Claude Code integration installed:"
echo "  /${CMD_NAME} command → $CLAUDE_DIR/commands/${CMD_NAME}.md"
echo "  status line  → $CLAUDE_DIR/statusline_context_guard.sh"
echo "  hooks        → SessionStart/_acquire, SessionEnd/_release"

# Determine shell RC file
RC_FILE=""
if [ -n "$ZSH_VERSION" ] || [ "$(basename "$SHELL")" = "zsh" ]; then
    RC_FILE="$HOME/.zshrc"
elif [ -n "$BASH_VERSION" ] || [ "$(basename "$SHELL")" = "bash" ]; then
    RC_FILE="$HOME/.bashrc"
fi

# Shell function block — ANTHROPIC_BASE_URL is always set so Claude uses the proxy
read -r -d '' CG_FUNCTION << 'SHELL_FUNC' || true
# BEGIN context_guard
export ANTHROPIC_BASE_URL="http://127.0.0.1:8765"
cg() {
    case "$1" in
        stop)      python3 "$HOME/.context_guard/cg" stop && unset ANTHROPIC_BASE_URL ;;
        uninstall) python3 "$HOME/.context_guard/cg" uninstall; unset ANTHROPIC_BASE_URL ;;
        no-guard)  shift; (unset ANTHROPIC_BASE_URL; claude "$@") ;;
        *)         python3 "$HOME/.context_guard/cg" "$@" ;;
    esac
}
# END context_guard
SHELL_FUNC

if [ -n "$RC_FILE" ]; then
    # Remove old-style block if present (upgrade path)
    if grep -qF 'context_guard — redacting proxy' "$RC_FILE" 2>/dev/null; then
        _sed_i '/# context_guard — redacting proxy/,/^}$/d' "$RC_FILE"
        echo "[context_guard] Removed old shell function from $RC_FILE"
    fi

    # Remove existing BEGIN/END block if present (re-install)
    if grep -qF '# BEGIN context_guard' "$RC_FILE" 2>/dev/null; then
        _sed_i '/^# BEGIN context_guard$/,/^# END context_guard$/d' "$RC_FILE"
        echo "[context_guard] Removed previous shell block from $RC_FILE"
    fi

    echo "" >> "$RC_FILE"
    echo "$CG_FUNCTION" >> "$RC_FILE"
    echo "[context_guard] Added cg shell function to $RC_FILE"
else
    echo "[context_guard] Could not detect shell RC file. Add this manually to your RC:"
    echo "$CG_FUNCTION"
fi

echo ""
echo "[context_guard] Installation complete!"
echo ""

# If sourced, export directly; otherwise give a one-liner
if [[ "${BASH_SOURCE[0]}" != "${0}" ]] 2>/dev/null || [[ "$ZSH_EVAL_CONTEXT" == *:file:* ]] 2>/dev/null; then
    export ANTHROPIC_BASE_URL="http://127.0.0.1:8765"
    echo "[context_guard] ANTHROPIC_BASE_URL activated in current shell."
    echo ""
    echo "Just run 'claude' — the proxy starts automatically."
else
    echo "To activate now, run:"
    echo ""
    echo "  source ${RC_FILE:-~/.bashrc}"
    echo ""
    echo "Then just run 'claude' — the proxy starts automatically."
fi
echo ""
echo "  cg status   # show proxy state and today's stats"
echo "  cg stop     # manually stop proxy"
echo "  cg no-guard # run claude without the proxy"
