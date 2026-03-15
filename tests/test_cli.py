"""
Tests for CLI commands: cg rules (non-interactive) and context_guard.py --test / --redact-pipe.
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
