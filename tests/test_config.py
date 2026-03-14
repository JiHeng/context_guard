"""Tests for engine.config — config loading and validation."""

import json
import pytest
from pathlib import Path
from engine.config import load, Config


@pytest.fixture
def config_file(tmp_path):
    path = tmp_path / "config.json"
    return path


class TestLoadDefaults:
    def test_missing_file_returns_defaults(self, tmp_path):
        # load() only returns defaults when path=None and no config files exist.
        # When an explicit path is given, it opens it directly.
        # So test with None but patch the global paths to nonexistent locations.
        from unittest.mock import patch
        from engine import config as cfg_mod
        fake = tmp_path / "nope.json"
        with patch.object(cfg_mod, "CONFIG_PATH", fake), \
             patch.object(cfg_mod, "_LOCAL_CONFIG", fake):
            cfg = load(None)
        assert cfg.port == 8765
        assert cfg.enabled is True
        assert cfg.disabled_rules == []
        assert cfg.enabled_rules == []


class TestLoadFromFile:
    def test_basic_config(self, config_file):
        config_file.write_text(json.dumps({
            "port": 9000,
            "enabled": False,
            "disabled_rules": ["email"],
        }))
        cfg = load(config_file)
        assert cfg.port == 9000
        assert cfg.enabled is False
        assert cfg.disabled_rules == ["email"]

    def test_enabled_rules_validated(self, config_file):
        config_file.write_text(json.dumps({
            "enabled_rules": ["credit_card", "nonexistent_rule"],
        }))
        cfg = load(config_file)
        assert "credit_card" in cfg.enabled_rules
        assert "nonexistent_rule" not in cfg.enabled_rules
        assert any("nonexistent_rule" in w for w in cfg.warnings)

    def test_typo_suggestion(self, config_file):
        config_file.write_text(json.dumps({
            "enabled_rules": ["credid_card"],  # typo
        }))
        cfg = load(config_file)
        assert any("credit_card" in w for w in cfg.warnings)

    def test_keyword_rules(self, config_file):
        config_file.write_text(json.dumps({
            "keyword_rules": [
                {"keyword": "Project X", "severity": "high"},
                {"keyword": "Secret Name"},
            ],
        }))
        cfg = load(config_file)
        assert len(cfg.keyword_rules) == 2
        assert cfg.keyword_rules[0].keyword == "Project X"
        assert cfg.keyword_rules[1].severity == "high"  # default

    def test_empty_keyword_skipped_with_warning(self, config_file):
        config_file.write_text(json.dumps({
            "keyword_rules": [{"keyword": ""}],
        }))
        cfg = load(config_file)
        assert len(cfg.keyword_rules) == 0
        assert len(cfg.warnings) == 1

    def test_extra_patterns(self, config_file):
        config_file.write_text(json.dumps({
            "extra_patterns": [
                {"category": "internal", "pattern": r"INT-\d+", "severity": "high"},
            ],
        }))
        cfg = load(config_file)
        assert len(cfg.extra_patterns) == 1
        assert cfg.extra_patterns[0].category == "internal"
        assert cfg.extra_patterns[0].pattern.search("INT-12345")

    def test_invalid_regex_skipped_with_warning(self, config_file):
        config_file.write_text(json.dumps({
            "extra_patterns": [
                {"category": "bad", "pattern": "[invalid"},
            ],
        }))
        cfg = load(config_file)
        assert len(cfg.extra_patterns) == 0
        assert any("invalid regex" in w for w in cfg.warnings)

    def test_openai_upstream(self, config_file):
        config_file.write_text(json.dumps({
            "openai_upstream": "https://custom.openai.proxy",
        }))
        cfg = load(config_file)
        assert cfg.openai_upstream == "https://custom.openai.proxy"
