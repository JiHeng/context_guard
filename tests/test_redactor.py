"""Tests for engine.redactor — text redaction."""

import re
import pytest
from engine.redactor import Redactor
from engine.rules import build_rules, Rule
from engine.allowlist import Allowlist


@pytest.fixture
def redactor():
    return Redactor(rules=build_rules())


class TestBasicRedaction:
    def test_redacts_api_key(self, redactor):
        text = "my key is sk-ant-api03-abcdefghijklmnopqrstuvwxyz"
        result, cats = redactor.redact(text)
        assert "[REDACTED:api_key]" in result
        assert "api_key" in cats
        assert "sk-ant" not in result

    def test_redacts_email(self, redactor):
        text = "email me at alice@realcompany.io"
        result, cats = redactor.redact(text)
        assert "[REDACTED:email]" in result
        assert "email" in cats

    def test_redacts_multiple_categories(self, redactor):
        text = "key: sk-ant-api03-abcdefghijklmnopqrstuvwxyz, email: alice@realcompany.io"
        result, cats = redactor.redact(text)
        assert "[REDACTED:api_key]" in result
        assert "[REDACTED:email]" in result
        assert "api_key" in cats
        assert "email" in cats

    def test_clean_text_unchanged(self, redactor):
        text = "Just normal text, nothing sensitive."
        result, cats = redactor.redact(text)
        assert result == text
        assert cats == []

    def test_categories_deduplicated(self, redactor):
        text = "sk-ant-api03-aaaaaaaaaaaaaaaaaaaaaa and sk-ant-api03-bbbbbbbbbbbbbbbbbbbbbb"
        result, cats = redactor.redact(text)
        assert cats.count("api_key") == 1


class TestAllowlist:
    def test_allowlisted_value_not_redacted(self, tmp_path):
        allow_file = tmp_path / "allow.txt"
        allow_file.write_text("alice@realcompany.io\n")
        allowlist = Allowlist(path=allow_file)
        redactor = Redactor(rules=build_rules(), allowlist=allowlist)

        text = "email: alice@realcompany.io"
        result, cats = redactor.redact(text)
        assert "alice@realcompany.io" in result
        assert "email" not in cats

    def test_regex_allowlist(self, tmp_path):
        allow_file = tmp_path / "allow.txt"
        allow_file.write_text("re:.*@internal\\.corp\n")
        allowlist = Allowlist(path=allow_file)
        redactor = Redactor(rules=build_rules(), allowlist=allowlist)

        text = "email: bob@internal.corp"
        result, cats = redactor.redact(text)
        assert "bob@internal.corp" in result

    def test_non_allowlisted_still_redacted(self, tmp_path):
        allow_file = tmp_path / "allow.txt"
        allow_file.write_text("alice@realcompany.io\n")
        allowlist = Allowlist(path=allow_file)
        redactor = Redactor(rules=build_rules(), allowlist=allowlist)

        text = "alice@realcompany.io and bob@realcompany.io"
        result, cats = redactor.redact(text)
        assert "alice@realcompany.io" in result
        assert "[REDACTED:email]" in result



class TestCustomRules:
    def test_custom_regex_rule(self):
        custom_rule = Rule(
            category="project_id",
            severity="sensitive",
            pattern=re.compile(r"PROJ-\d{4,}"),
            source="custom",
        )
        redactor = Redactor(rules=[custom_rule])
        text = "see PROJ-12345 for details"
        result, cats = redactor.redact(text)
        assert "[REDACTED:project_id]" in result
        assert "project_id" in cats
