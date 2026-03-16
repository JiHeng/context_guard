"""
Tests for CLI commands: cg block/unblock/list and context_guard.py --test / --redact-pipe.
"""

import json
import os
import re
import sys
import pytest
from pathlib import Path
from unittest.mock import patch
from io import StringIO


# ---------------------------------------------------------------------------
# cg rules command tests
# ---------------------------------------------------------------------------

# We test the internal functions from cg directly rather than spawning subprocesses.
# This avoids needing the proxy running and keeps tests fast.

@pytest.fixture
def cg_env(tmp_path, monkeypatch):
    """Set up a temporary config environment for cg tests."""
    config_file = tmp_path / "config.json"
    allow_file = tmp_path / "allow.txt"
    config_file.write_text(json.dumps({
        "enabled": True,
        "port": 8765,
        "disabled_rules": [],
        "enabled_rules": [],
        "keyword_rules": [],
        "extra_patterns": [],
    }))

    # Add repo root to path so cg can import engine
    repo_root = Path(__file__).parent.parent
    if str(repo_root) not in sys.path:
        sys.path.insert(0, str(repo_root))

    # Import cg module (no .py extension — set __file__ before exec)
    import importlib.util
    import importlib.machinery
    cg_path = repo_root / "cg"
    loader = importlib.machinery.SourceFileLoader("cg_module", str(cg_path))
    spec = importlib.util.spec_from_loader("cg_module", loader, origin=str(cg_path))
    cg_mod = importlib.util.module_from_spec(spec)
    cg_mod.__file__ = str(cg_path)
    spec.loader.exec_module(cg_mod)

    # Patch paths
    monkeypatch.setattr(cg_mod, "_CONFIG_FILE", config_file)
    monkeypatch.setattr(cg_mod, "_LOCAL_CONFIG", config_file)
    monkeypatch.setattr(cg_mod, "_ALLOW_FILE", allow_file)

    return cg_mod, config_file, allow_file


class TestRulesEnable:
    def test_enable_catalog_rule(self, cg_env):
        cg_mod, config_file, _ = cg_env
        cg_mod._rules_enable("credit_card")
        data = json.loads(config_file.read_text())
        assert "credit_card" in data["enabled_rules"]

    def test_enable_already_enabled(self, cg_env, capsys):
        cg_mod, config_file, _ = cg_env
        # Enable twice
        cg_mod._rules_enable("credit_card")
        cg_mod._rules_enable("credit_card")
        data = json.loads(config_file.read_text())
        assert data["enabled_rules"].count("credit_card") == 1

    def test_enable_unknown_rule_exits(self, cg_env):
        cg_mod, _, _ = cg_env
        with pytest.raises(SystemExit):
            cg_mod._rules_enable("nonexistent_rule")


class TestRulesDisable:
    def test_disable_base_rule(self, cg_env):
        cg_mod, config_file, _ = cg_env
        cg_mod._rules_disable("email")
        data = json.loads(config_file.read_text())
        assert "email" in data["disabled_rules"]

    def test_disable_already_disabled(self, cg_env, capsys):
        cg_mod, config_file, _ = cg_env
        cg_mod._rules_disable("email")
        cg_mod._rules_disable("email")
        data = json.loads(config_file.read_text())
        assert data["disabled_rules"].count("email") == 1

    def test_disable_unknown_rule_exits(self, cg_env):
        cg_mod, _, _ = cg_env
        with pytest.raises(SystemExit):
            cg_mod._rules_disable("nonexistent_rule")


class TestRulesKeyword:
    def test_add_keyword(self, cg_env):
        cg_mod, config_file, _ = cg_env
        cg_mod._rules_add_keyword("Project Apollo", "high")
        data = json.loads(config_file.read_text())
        assert any(kr["keyword"] == "Project Apollo" for kr in data["keyword_rules"])

    def test_add_duplicate_keyword_noop(self, cg_env, capsys):
        cg_mod, config_file, _ = cg_env
        cg_mod._rules_add_keyword("Project Apollo", "high")
        cg_mod._rules_add_keyword("Project Apollo", "high")
        data = json.loads(config_file.read_text())
        count = sum(1 for kr in data["keyword_rules"] if kr["keyword"] == "Project Apollo")
        assert count == 1

    def test_remove_keyword(self, cg_env):
        cg_mod, config_file, _ = cg_env
        cg_mod._rules_add_keyword("Project Apollo", "high")
        cg_mod._rules_remove_keyword("Project Apollo")
        data = json.loads(config_file.read_text())
        assert not any(kr["keyword"] == "Project Apollo" for kr in data["keyword_rules"])

    def test_remove_nonexistent_keyword_exits(self, cg_env):
        cg_mod, _, _ = cg_env
        with pytest.raises(SystemExit):
            cg_mod._rules_remove_keyword("nonexistent")


class TestRulesPattern:
    def test_add_pattern(self, cg_env):
        cg_mod, config_file, _ = cg_env
        cg_mod._rules_add_pattern("internal_id", r"INT-\d+", "high")
        data = json.loads(config_file.read_text())
        assert any(ep["category"] == "internal_id" for ep in data["extra_patterns"])

    def test_add_invalid_regex_exits(self, cg_env):
        cg_mod, _, _ = cg_env
        with pytest.raises(SystemExit):
            cg_mod._rules_add_pattern("bad", "[invalid", "high")

    def test_remove_pattern(self, cg_env):
        cg_mod, config_file, _ = cg_env
        cg_mod._rules_add_pattern("internal_id", r"INT-\d+", "high")
        cg_mod._rules_remove_pattern("internal_id")
        data = json.loads(config_file.read_text())
        assert not any(ep["category"] == "internal_id" for ep in data["extra_patterns"])

    def test_remove_nonexistent_pattern_exits(self, cg_env):
        cg_mod, _, _ = cg_env
        with pytest.raises(SystemExit):
            cg_mod._rules_remove_pattern("nonexistent")


class TestRulesAllowlist:
    def test_allow_value(self, cg_env):
        cg_mod, _, allow_file = cg_env
        cg_mod._rules_allow("alice@company.com")
        assert "alice@company.com" in allow_file.read_text()

    def test_allow_duplicate_noop(self, cg_env, capsys):
        cg_mod, _, allow_file = cg_env
        cg_mod._rules_allow("alice@company.com")
        cg_mod._rules_allow("alice@company.com")
        entries = [l for l in allow_file.read_text().splitlines() if l.strip()]
        assert entries.count("alice@company.com") == 1

    def test_deny_value(self, cg_env):
        cg_mod, _, allow_file = cg_env
        cg_mod._rules_allow("alice@company.com")
        cg_mod._rules_deny("alice@company.com")
        content = allow_file.read_text()
        assert "alice@company.com" not in content

    def test_deny_nonexistent_exits(self, cg_env):
        cg_mod, _, _ = cg_env
        with pytest.raises(SystemExit):
            cg_mod._rules_deny("not_in_list")


class TestCmdBlock:
    def test_block_keyword(self, cg_env):
        cg_mod, config_file, _ = cg_env
        cg_mod.cmd_block(["keyword", "Titan"])
        data = json.loads(config_file.read_text())
        assert any(kr["keyword"] == "Titan" for kr in data["keyword_rules"])

    def test_block_regex(self, cg_env):
        cg_mod, config_file, _ = cg_env
        cg_mod.cmd_block(["regex", r"PROJ-\d+"])
        data = json.loads(config_file.read_text())
        assert any(ep["pattern"] == r"PROJ-\d+" for ep in data["extra_patterns"])
        assert any(ep["category"] == "custom_regex" for ep in data["extra_patterns"])

    def test_block_known_rule_enables(self, cg_env):
        cg_mod, config_file, _ = cg_env
        # First disable it, then block should re-enable
        cg_mod._rules_disable("email")
        data = json.loads(config_file.read_text())
        assert "email" in data["disabled_rules"]
        cg_mod.cmd_block(["email"])
        data = json.loads(config_file.read_text())
        assert "email" not in data["disabled_rules"]

    def test_block_catalog_rule_enables(self, cg_env):
        cg_mod, config_file, _ = cg_env
        cg_mod.cmd_block(["credit_card"])
        data = json.loads(config_file.read_text())
        assert "credit_card" in data["enabled_rules"]

    def test_block_allowlisted_value_removes(self, cg_env):
        cg_mod, _, allow_file = cg_env
        cg_mod._rules_allow("abc@test.com")
        cg_mod.cmd_block(["abc@test.com"])
        assert "abc@test.com" not in allow_file.read_text()

    def test_block_unknown_value_errors(self, cg_env):
        cg_mod, _, _ = cg_env
        with pytest.raises(SystemExit):
            cg_mod.cmd_block(["some_random_value"])

    def test_block_no_args_exits(self, cg_env):
        cg_mod, _, _ = cg_env
        with pytest.raises(SystemExit):
            cg_mod.cmd_block([])


class TestCmdUnblock:
    def test_unblock_keyword(self, cg_env):
        cg_mod, config_file, _ = cg_env
        cg_mod._rules_add_keyword("Titan")
        cg_mod.cmd_unblock(["keyword", "Titan"])
        data = json.loads(config_file.read_text())
        assert not any(kr["keyword"] == "Titan" for kr in data["keyword_rules"])

    def test_unblock_regex(self, cg_env):
        cg_mod, config_file, _ = cg_env
        cg_mod._rules_add_pattern("custom_regex", r"PROJ-\d+")
        cg_mod.cmd_unblock(["regex", r"PROJ-\d+"])
        data = json.loads(config_file.read_text())
        assert not any(ep["pattern"] == r"PROJ-\d+" for ep in data["extra_patterns"])

    def test_unblock_known_rule_disables(self, cg_env):
        cg_mod, config_file, _ = cg_env
        cg_mod.cmd_unblock(["email"])
        data = json.loads(config_file.read_text())
        assert "email" in data["disabled_rules"]

    def test_unblock_catalog_rule_disables(self, cg_env):
        cg_mod, config_file, _ = cg_env
        cg_mod._rules_enable("credit_card")
        cg_mod.cmd_unblock(["credit_card"])
        data = json.loads(config_file.read_text())
        assert "credit_card" in data["disabled_rules"]

    def test_unblock_bare_value_adds_to_allowlist(self, cg_env):
        cg_mod, _, allow_file = cg_env
        cg_mod.cmd_unblock(["abc@test.com"])
        assert "abc@test.com" in allow_file.read_text()

    def test_unblock_already_allowed_noop(self, cg_env, capsys):
        cg_mod, _, _ = cg_env
        cg_mod._rules_allow("abc@test.com")
        cg_mod.cmd_unblock(["abc@test.com"])
        out = capsys.readouterr().out
        assert "already in allowlist" in out

    def test_unblock_no_args_exits(self, cg_env):
        cg_mod, _, _ = cg_env
        with pytest.raises(SystemExit):
            cg_mod.cmd_unblock([])


class TestCmdList:
    def test_list_runs(self, cg_env, capsys):
        cg_mod, _, _ = cg_env
        cg_mod.cmd_list([])
        out = capsys.readouterr().out
        assert "Base rules" in out


class TestRemovePatternByRegex:
    def test_remove_by_regex_string(self, cg_env):
        cg_mod, config_file, _ = cg_env
        cg_mod._rules_add_pattern("custom_regex", r"PROJ-\d+")
        cg_mod._rules_remove_pattern_by_regex(r"PROJ-\d+")
        data = json.loads(config_file.read_text())
        assert not any(ep["pattern"] == r"PROJ-\d+" for ep in data["extra_patterns"])

    def test_remove_nonexistent_regex_exits(self, cg_env):
        cg_mod, _, _ = cg_env
        with pytest.raises(SystemExit):
            cg_mod._rules_remove_pattern_by_regex("nonexistent")


# ---------------------------------------------------------------------------
# context_guard.py --test command
# ---------------------------------------------------------------------------

class TestContextGuardTestCommand:
    def test_detects_api_key(self, capsys):
        from context_guard import _cmd_test
        _cmd_test(["sk-ant-api03-abcdefghijklmnopqrstuvwxyz"])
        out = capsys.readouterr().out
        assert "api_key" in out

    def test_clean_text(self, capsys):
        from context_guard import _cmd_test
        _cmd_test(["hello world nothing sensitive"])
        out = capsys.readouterr().out
        assert "clean" in out

    def test_detects_email(self, capsys):
        from context_guard import _cmd_test
        _cmd_test(["contact alice@realcompany.io"])
        out = capsys.readouterr().out
        assert "email" in out


class TestContextGuardRedactPipe:
    def test_redacts_stdin(self, monkeypatch, capsys):
        from context_guard import _cmd_redact_pipe
        monkeypatch.setattr("sys.stdin", StringIO("key: sk-ant-api03-abcdefghijklmnopqrstuvwxyz"))
        _cmd_redact_pipe()
        out = capsys.readouterr().out
        assert "[REDACTED:api_key]" in out


# ---------------------------------------------------------------------------
# cmd_rules dispatch tests
# ---------------------------------------------------------------------------

class TestCmdRulesDispatch:
    """Test cmd_rules routes sub-commands correctly."""

    def test_rules_list(self, cg_env, capsys):
        cg_mod, _, _ = cg_env
        cg_mod.cmd_rules(["list"])
        out = capsys.readouterr().out
        assert "Base rules" in out

    def test_rules_enable(self, cg_env):
        cg_mod, config_file, _ = cg_env
        cg_mod.cmd_rules(["enable", "credit_card"])
        data = json.loads(config_file.read_text())
        assert "credit_card" in data["enabled_rules"]

    def test_rules_disable(self, cg_env):
        cg_mod, config_file, _ = cg_env
        cg_mod.cmd_rules(["disable", "email"])
        data = json.loads(config_file.read_text())
        assert "email" in data["disabled_rules"]

    def test_rules_add_keyword(self, cg_env):
        cg_mod, config_file, _ = cg_env
        cg_mod.cmd_rules(["add", "keyword", "Secret"])
        data = json.loads(config_file.read_text())
        assert any(kr["keyword"] == "Secret" for kr in data["keyword_rules"])

    def test_rules_remove_keyword(self, cg_env):
        cg_mod, config_file, _ = cg_env
        cg_mod._rules_add_keyword("Secret")
        cg_mod.cmd_rules(["remove", "keyword", "Secret"])
        data = json.loads(config_file.read_text())
        assert not any(kr["keyword"] == "Secret" for kr in data["keyword_rules"])

    def test_rules_add_pattern(self, cg_env):
        cg_mod, config_file, _ = cg_env
        cg_mod.cmd_rules(["add", "pattern", "ticket", r"TICK-\d+"])
        data = json.loads(config_file.read_text())
        assert any(ep["category"] == "ticket" for ep in data["extra_patterns"])

    def test_rules_remove_pattern(self, cg_env):
        cg_mod, config_file, _ = cg_env
        cg_mod._rules_add_pattern("ticket", r"TICK-\d+")
        cg_mod.cmd_rules(["remove", "pattern", "ticket"])
        data = json.loads(config_file.read_text())
        assert not any(ep["category"] == "ticket" for ep in data["extra_patterns"])

    def test_rules_allow(self, cg_env):
        cg_mod, _, allow_file = cg_env
        cg_mod.cmd_rules(["allow", "safe@company.com"])
        assert "safe@company.com" in allow_file.read_text()

    def test_rules_deny(self, cg_env):
        cg_mod, _, allow_file = cg_env
        cg_mod._rules_allow("safe@company.com")
        cg_mod.cmd_rules(["deny", "safe@company.com"])
        assert "safe@company.com" not in allow_file.read_text()

    def test_rules_invalid_subcommand_exits(self, cg_env):
        cg_mod, _, _ = cg_env
        with pytest.raises(SystemExit):
            cg_mod.cmd_rules(["bogus"])

    def test_rules_enable_missing_arg_exits(self, cg_env):
        cg_mod, _, _ = cg_env
        with pytest.raises(SystemExit):
            cg_mod.cmd_rules(["enable"])


# ---------------------------------------------------------------------------
# End-to-end rule lifecycle: add → verify active → remove → verify gone
# ---------------------------------------------------------------------------

class TestRuleLifecycle:
    """Test that adding/removing rules actually affects redaction."""

    def test_keyword_lifecycle(self, cg_env):
        cg_mod, config_file, _ = cg_env
        # Add keyword
        cg_mod._rules_add_keyword("TopSecret")
        data = json.loads(config_file.read_text())
        assert any(kr["keyword"] == "TopSecret" for kr in data["keyword_rules"])

        # Verify it actually redacts
        from engine.config import load as load_config
        from engine.rules import build_rules
        from engine.redactor import Redactor
        config = load_config(path=config_file)
        redactor = Redactor(rules=build_rules(config))
        result, cats = redactor.redact("This is TopSecret info")
        assert "topsecret" in cats
        assert "[REDACTED:topsecret]" in result

        # Remove keyword
        cg_mod._rules_remove_keyword("TopSecret")

        # Verify it no longer redacts
        config = load_config(path=config_file)
        redactor = Redactor(rules=build_rules(config))
        result, cats = redactor.redact("This is TopSecret info")
        assert cats == []
        assert "TopSecret" in result

    def test_pattern_lifecycle(self, cg_env):
        cg_mod, config_file, _ = cg_env
        # Add pattern
        cg_mod._rules_add_pattern("project_id", r"PROJ-\d{4}")
        data = json.loads(config_file.read_text())
        assert any(ep["category"] == "project_id" for ep in data["extra_patterns"])

        # Verify it redacts
        from engine.config import load as load_config
        from engine.rules import build_rules
        from engine.redactor import Redactor
        config = load_config(path=config_file)
        redactor = Redactor(rules=build_rules(config))
        result, cats = redactor.redact("Working on PROJ-1234")
        assert "project_id" in cats
        assert "[REDACTED:project_id]" in result

        # Remove pattern
        cg_mod._rules_remove_pattern("project_id")

        # Verify it no longer redacts
        config = load_config(path=config_file)
        redactor = Redactor(rules=build_rules(config))
        result, cats = redactor.redact("Working on PROJ-1234")
        assert "project_id" not in cats
        assert "PROJ-1234" in result

    def test_enable_disable_lifecycle(self, cg_env):
        cg_mod, config_file, _ = cg_env
        # Disable email
        cg_mod._rules_disable("email")

        from engine.config import load as load_config
        from engine.rules import build_rules
        from engine.redactor import Redactor
        config = load_config(path=config_file)
        redactor = Redactor(rules=build_rules(config))
        result, cats = redactor.redact("Contact alice@realco.io")
        assert "email" not in cats
        assert "alice@realco.io" in result

        # Re-enable email
        cg_mod._rules_enable("email")
        config = load_config(path=config_file)
        redactor = Redactor(rules=build_rules(config))
        result, cats = redactor.redact("Contact alice@realco.io")
        assert "email" in cats
        assert "[REDACTED:email]" in result

    def test_allowlist_lifecycle(self, cg_env):
        cg_mod, config_file, allow_file = cg_env
        from engine.config import load as load_config
        from engine.rules import build_rules
        from engine.redactor import Redactor
        from engine.allowlist import Allowlist

        # Without allowlist, email is redacted
        config = load_config(path=config_file)
        redactor = Redactor(rules=build_rules(config))
        result, cats = redactor.redact("Contact team@ourco.io")
        assert "email" in cats

        # Add to allowlist
        cg_mod._rules_allow("team@ourco.io")
        allowlist = Allowlist(path=allow_file)
        redactor = Redactor(rules=build_rules(config), allowlist=allowlist)
        result, cats = redactor.redact("Contact team@ourco.io")
        assert "email" not in cats
        assert "team@ourco.io" in result

        # Remove from allowlist
        cg_mod._rules_deny("team@ourco.io")
        allowlist = Allowlist(path=allow_file)
        redactor = Redactor(rules=build_rules(config), allowlist=allowlist)
        result, cats = redactor.redact("Contact team@ourco.io")
        assert "email" in cats


# ---------------------------------------------------------------------------
# cmd_list output details
# ---------------------------------------------------------------------------

class TestCmdListOutput:
    def test_shows_disabled_rules(self, cg_env, capsys):
        cg_mod, _, _ = cg_env
        cg_mod._rules_disable("email")
        cg_mod.cmd_list([])
        out = capsys.readouterr().out
        assert "email" in out
        assert "disabled" in out

    def test_shows_enabled_catalog_rules(self, cg_env, capsys):
        cg_mod, _, _ = cg_env
        cg_mod._rules_enable("credit_card")
        cg_mod.cmd_list([])
        out = capsys.readouterr().out
        assert "credit_card" in out
        assert "enabled" in out

    def test_shows_keyword_rules(self, cg_env, capsys):
        cg_mod, _, _ = cg_env
        cg_mod._rules_add_keyword("Classified")
        cg_mod.cmd_list([])
        out = capsys.readouterr().out
        assert "Classified" in out
        assert "Keyword" in out

    def test_shows_custom_patterns(self, cg_env, capsys):
        cg_mod, _, _ = cg_env
        cg_mod._rules_add_pattern("ticket_id", r"TIX-\d+")
        cg_mod.cmd_list([])
        out = capsys.readouterr().out
        assert "ticket_id" in out
        assert "Custom" in out

    def test_shows_allowlist_entries(self, cg_env, capsys):
        cg_mod, _, _ = cg_env
        cg_mod._rules_allow("safe@internal.com")
        cg_mod.cmd_list([])
        out = capsys.readouterr().out
        assert "safe@internal.com" in out
        assert "Allowlist" in out


# ---------------------------------------------------------------------------
# main() dispatch and edge cases
# ---------------------------------------------------------------------------

class TestMainDispatch:
    def test_no_args_exits(self, cg_env):
        cg_mod, _, _ = cg_env
        import sys as _sys
        original_argv = _sys.argv
        try:
            _sys.argv = ["cg"]
            with pytest.raises(SystemExit):
                cg_mod.main()
        finally:
            _sys.argv = original_argv

    def test_unknown_command_exits(self, cg_env):
        cg_mod, _, _ = cg_env
        import sys as _sys
        original_argv = _sys.argv
        try:
            _sys.argv = ["cg", "bogus"]
            with pytest.raises(SystemExit):
                cg_mod.main()
        finally:
            _sys.argv = original_argv
