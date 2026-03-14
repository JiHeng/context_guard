"""
Tests for install.sh settings.json handling.

Extracts the Python logic from install.sh and tests it in isolation
to verify that existing Claude settings are never overridden.
"""

import json
import os
import stat
import textwrap
from pathlib import Path

import pytest


# ---------------------------------------------------------------------------
# Helpers: replicate the install.sh Python logic as callable functions
# ---------------------------------------------------------------------------

def apply_statusline(settings_path: str, claude_dir: str) -> str:
    """Replicate the statusLine logic from install.sh. Returns status message."""
    if os.path.isfile(settings_path):
        with open(settings_path) as f:
            data = json.load(f)
    else:
        data = {}

    sl = data.get("statusLine", {})
    sl_json = json.dumps(sl)

    if "context_guard" in sl_json:
        return "already configured"

    CG_CMD = "bash ~/.claude/statusline_context_guard.sh"

    if sl and sl.get("command"):
        existing_cmd = sl["command"]
        merged_path = os.path.join(claude_dir, "statusline_merged.sh")
        with open(merged_path, "w") as f:
            f.write("#!/usr/bin/env bash\n")
            f.write(f"{existing_cmd} 2>/dev/null\n")
            f.write(f"{CG_CMD}\n")
        os.chmod(merged_path, 0o755)
        data["statusLine"] = {"type": "command", "command": "bash ~/.claude/statusline_merged.sh"}
        result = "merged"
    else:
        data["statusLine"] = {"type": "command", "command": CG_CMD}
        result = "added"

    with open(settings_path, "w") as f:
        json.dump(data, f, indent=2)
        f.write("\n")

    return result


def apply_permissions(settings_path: str) -> str:
    """Replicate the permissions logic from install.sh."""
    with open(settings_path) as f:
        data = json.load(f)

    perms = data.get("permissions", {})
    allow = perms.get("allow", [])

    cg_perm = "Bash(python3 ~/.context_guard/cg rules*)"
    if cg_perm not in allow:
        allow.append(cg_perm)
        perms["allow"] = allow
        data["permissions"] = perms
        with open(settings_path, "w") as f:
            json.dump(data, f, indent=2)
            f.write("\n")
        return "added"
    return "already configured"


def apply_hooks(settings_path: str) -> str:
    """Replicate the hooks logic from install.sh."""
    with open(settings_path) as f:
        data = json.load(f)

    hooks = data.get("hooks", {})

    cg_acquire = {"hooks": [{"type": "command", "command": "python3 ~/.context_guard/cg _acquire $PPID"}]}
    cg_release = {"hooks": [{"type": "command", "command": "python3 ~/.context_guard/cg _release $PPID"}]}

    changed = False
    for event, entry in [("SessionStart", cg_acquire), ("SessionEnd", cg_release)]:
        existing = hooks.get(event, [])
        already = any("context_guard" in str(h) for h in existing)
        if not already:
            existing.append(entry)
            changed = True
        hooks[event] = existing

    if changed:
        data["hooks"] = hooks
        with open(settings_path, "w") as f:
            json.dump(data, f, indent=2)
            f.write("\n")
        return "added"
    return "already configured"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def claude_dir(tmp_path):
    d = tmp_path / ".claude"
    d.mkdir()
    return d


@pytest.fixture
def settings_path(claude_dir):
    return str(claude_dir / "settings.json")


# ---------------------------------------------------------------------------
# statusLine tests
# ---------------------------------------------------------------------------

class TestStatusLine:
    def test_creates_new_settings_file(self, settings_path, claude_dir):
        """When settings.json doesn't exist, creates it with statusLine only."""
        result = apply_statusline(settings_path, str(claude_dir))
        assert result == "added"

        data = json.loads(Path(settings_path).read_text())
        assert data["statusLine"]["command"] == "bash ~/.claude/statusline_context_guard.sh"

    def test_adds_statusline_to_existing_settings(self, settings_path, claude_dir):
        """Existing settings.json with other fields but no statusLine — add without overwriting."""
        existing = {
            "permissions": {"allow": ["WebSearch"]},
            "someCustomField": True,
        }
        Path(settings_path).write_text(json.dumps(existing))

        apply_statusline(settings_path, str(claude_dir))
        data = json.loads(Path(settings_path).read_text())

        # Original fields preserved
        assert data["permissions"] == {"allow": ["WebSearch"]}
        assert data["someCustomField"] is True
        # statusLine added
        assert "context_guard" in data["statusLine"]["command"]

    def test_merges_with_existing_statusline(self, settings_path, claude_dir):
        """Existing statusLine from another tool — merges into wrapper script."""
        existing = {
            "statusLine": {"type": "command", "command": "echo [other-tool: OK]"},
        }
        Path(settings_path).write_text(json.dumps(existing))

        result = apply_statusline(settings_path, str(claude_dir))
        assert result == "merged"

        data = json.loads(Path(settings_path).read_text())
        assert "merged" in data["statusLine"]["command"]

        # Merged script contains both commands
        merged_script = (claude_dir / "statusline_merged.sh").read_text()
        assert "echo [other-tool: OK]" in merged_script
        assert "statusline_context_guard.sh" in merged_script

    def test_skips_if_already_configured(self, settings_path, claude_dir):
        """If statusLine already references context_guard, skip."""
        existing = {
            "statusLine": {"type": "command", "command": "bash ~/.claude/statusline_context_guard.sh"},
        }
        Path(settings_path).write_text(json.dumps(existing))

        result = apply_statusline(settings_path, str(claude_dir))
        assert result == "already configured"

    def test_idempotent_on_double_install(self, settings_path, claude_dir):
        """Running install twice doesn't duplicate or break anything."""
        apply_statusline(settings_path, str(claude_dir))
        data1 = json.loads(Path(settings_path).read_text())

        apply_statusline(settings_path, str(claude_dir))
        data2 = json.loads(Path(settings_path).read_text())

        assert data1 == data2

    def test_handles_statusline_without_command_key(self, settings_path, claude_dir):
        """statusLine with type 'text' (no command key) — treat as no existing statusLine."""
        existing = {
            "statusLine": {"type": "text", "text": "my status"},
        }
        Path(settings_path).write_text(json.dumps(existing))

        result = apply_statusline(settings_path, str(claude_dir))
        # No .get('command') so sl.get('command') is None → treated as fresh
        assert result == "added"

        data = json.loads(Path(settings_path).read_text())
        assert "context_guard" in data["statusLine"]["command"]


# ---------------------------------------------------------------------------
# Permissions tests
# ---------------------------------------------------------------------------

class TestPermissions:
    def test_adds_permission_to_empty_settings(self, settings_path):
        Path(settings_path).write_text("{}")
        result = apply_permissions(settings_path)
        assert result == "added"

        data = json.loads(Path(settings_path).read_text())
        assert "Bash(python3 ~/.context_guard/cg rules*)" in data["permissions"]["allow"]

    def test_preserves_existing_permissions(self, settings_path):
        existing = {
            "permissions": {
                "allow": ["WebSearch", "Bash(git status)"],
                "deny": ["Bash(rm -rf *)"],
            }
        }
        Path(settings_path).write_text(json.dumps(existing))

        apply_permissions(settings_path)
        data = json.loads(Path(settings_path).read_text())

        # Existing entries preserved
        assert "WebSearch" in data["permissions"]["allow"]
        assert "Bash(git status)" in data["permissions"]["allow"]
        assert data["permissions"]["deny"] == ["Bash(rm -rf *)"]
        # New entry appended
        assert "Bash(python3 ~/.context_guard/cg rules*)" in data["permissions"]["allow"]

    def test_idempotent(self, settings_path):
        Path(settings_path).write_text("{}")
        apply_permissions(settings_path)
        apply_permissions(settings_path)

        data = json.loads(Path(settings_path).read_text())
        cg_perms = [p for p in data["permissions"]["allow"] if "context_guard" in p]
        assert len(cg_perms) == 1, "Permission should not be duplicated"


# ---------------------------------------------------------------------------
# Hooks tests
# ---------------------------------------------------------------------------

class TestHooks:
    def test_adds_hooks_to_empty_settings(self, settings_path):
        Path(settings_path).write_text("{}")
        result = apply_hooks(settings_path)
        assert result == "added"

        data = json.loads(Path(settings_path).read_text())
        assert "SessionStart" in data["hooks"]
        assert "SessionEnd" in data["hooks"]
        # Verify hook content
        ss = data["hooks"]["SessionStart"]
        assert any("_acquire" in json.dumps(h) for h in ss)

    def test_preserves_existing_hooks(self, settings_path):
        """User has hooks from another tool — ours are appended, theirs are untouched."""
        existing = {
            "hooks": {
                "SessionStart": [
                    {"hooks": [{"type": "command", "command": "echo other-tool-start"}]}
                ],
                "PreToolUse": [
                    {"hooks": [{"type": "command", "command": "echo lint-check"}]}
                ],
            }
        }
        Path(settings_path).write_text(json.dumps(existing))

        apply_hooks(settings_path)
        data = json.loads(Path(settings_path).read_text())

        # Other tool's SessionStart hook preserved
        ss = data["hooks"]["SessionStart"]
        assert len(ss) == 2  # original + ours
        assert any("other-tool-start" in json.dumps(h) for h in ss)
        assert any("context_guard" in json.dumps(h) for h in ss)

        # PreToolUse hook untouched
        assert "PreToolUse" in data["hooks"]
        assert any("lint-check" in json.dumps(h) for h in data["hooks"]["PreToolUse"])

        # SessionEnd added
        assert "SessionEnd" in data["hooks"]

    def test_idempotent(self, settings_path):
        Path(settings_path).write_text("{}")
        apply_hooks(settings_path)
        apply_hooks(settings_path)

        data = json.loads(Path(settings_path).read_text())
        ss = data["hooks"]["SessionStart"]
        cg_hooks = [h for h in ss if "context_guard" in json.dumps(h)]
        assert len(cg_hooks) == 1, "Hook should not be duplicated"

    def test_adds_hooks_when_context_guard_exists_elsewhere(self, settings_path):
        """Regression: context_guard in permissions should NOT prevent hook addition."""
        existing = {
            "permissions": {"allow": ["Bash(python3 ~/.context_guard/cg rules*)"]},
            "hooks": {
                "PreToolUse": [
                    {"hooks": [{"type": "command", "command": "echo check"}]}
                ],
            },
        }
        Path(settings_path).write_text(json.dumps(existing))

        result = apply_hooks(settings_path)
        assert result == "added"

        data = json.loads(Path(settings_path).read_text())
        assert "SessionStart" in data["hooks"]
        assert "SessionEnd" in data["hooks"]
        # PreToolUse preserved
        assert "PreToolUse" in data["hooks"]


# ---------------------------------------------------------------------------
# Full pipeline test
# ---------------------------------------------------------------------------

class TestFullInstallPipeline:
    def test_full_pipeline_on_empty(self, settings_path, claude_dir):
        """Simulate full install on fresh system — all three steps on empty settings."""
        apply_statusline(settings_path, str(claude_dir))
        apply_permissions(settings_path)
        apply_hooks(settings_path)

        data = json.loads(Path(settings_path).read_text())
        assert "statusLine" in data
        assert "permissions" in data
        assert "hooks" in data
        assert "context_guard" in data["statusLine"]["command"]

    def test_full_pipeline_preserves_rich_existing_settings(self, settings_path, claude_dir):
        """Simulate install on a user with existing settings — nothing lost."""
        existing = {
            "statusLine": {"type": "command", "command": "echo [my-tool: OK]"},
            "permissions": {
                "allow": ["WebSearch", "Read"],
                "deny": ["Bash(rm *)"],
            },
            "hooks": {
                "PreToolUse": [
                    {"hooks": [{"type": "command", "command": "echo pre-check"}]}
                ],
            },
            "theme": "dark",
            "customKey": [1, 2, 3],
        }
        Path(settings_path).write_text(json.dumps(existing))

        apply_statusline(settings_path, str(claude_dir))
        apply_permissions(settings_path)
        apply_hooks(settings_path)

        data = json.loads(Path(settings_path).read_text())

        # All original fields preserved
        assert data["theme"] == "dark"
        assert data["customKey"] == [1, 2, 3]
        assert "WebSearch" in data["permissions"]["allow"]
        assert "Read" in data["permissions"]["allow"]
        assert data["permissions"]["deny"] == ["Bash(rm *)"]
        assert any("pre-check" in json.dumps(h) for h in data["hooks"]["PreToolUse"])

        # context_guard added
        assert "merged" in data["statusLine"]["command"]
        assert any("context_guard" in p for p in data["permissions"]["allow"])
        assert "SessionStart" in data["hooks"]
        assert "SessionEnd" in data["hooks"]

    def test_double_install_is_noop(self, settings_path, claude_dir):
        """Running install twice produces identical settings."""
        apply_statusline(settings_path, str(claude_dir))
        apply_permissions(settings_path)
        apply_hooks(settings_path)
        data1 = json.loads(Path(settings_path).read_text())

        apply_statusline(settings_path, str(claude_dir))
        apply_permissions(settings_path)
        apply_hooks(settings_path)
        data2 = json.loads(Path(settings_path).read_text())

        assert data1 == data2
