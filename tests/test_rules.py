"""Tests for engine.rules — rule building and keyword rules."""

import re
import pytest
from engine.rules import build_rules, keyword_to_rule, Rule, _BASE_RULES, _CATALOG_RULES
from engine.config import Config, KeywordRule, PatternEntry


class TestBuildRules:
    def test_default_rules_not_empty(self):
        rules = build_rules()
        assert len(rules) > 0

    def test_default_rules_match_base(self):
        rules = build_rules()
        assert len(rules) == len(_BASE_RULES)

    def test_disabled_rules_excluded(self):
        config = Config(disabled_rules=["email"])
        rules = build_rules(config)
        cats = {r.category for r in rules}
        assert "email" not in cats

    def test_enabled_catalog_rule(self):
        config = Config(enabled_rules=["credit_card"])
        rules = build_rules(config)
        cats = {r.category for r in rules}
        assert "credit_card" in cats

    def test_disabled_catalog_rule(self):
        config = Config(enabled_rules=["credit_card"], disabled_rules=["credit_card"])
        rules = build_rules(config)
        cats = {r.category for r in rules}
        assert "credit_card" not in cats

    def test_keyword_rule_added(self):
        config = Config(keyword_rules=[KeywordRule(keyword="Project Titan")])
        rules = build_rules(config)
        cats = {r.category for r in rules}
        assert "project_titan" in cats

    def test_extra_pattern_added(self):
        config = Config(extra_patterns=[
            PatternEntry(category="internal_id", severity="high", pattern=re.compile(r"INT-\d+"))
        ])
        rules = build_rules(config)
        cats = {r.category for r in rules}
        assert "internal_id" in cats

    def test_validators_attached(self):
        config = Config(enabled_rules=["credit_card", "ssn"])
        rules = build_rules(config)
        cc_rules = [r for r in rules if r.category == "credit_card"]
        assert cc_rules and cc_rules[0].validator is not None

    def test_phone_skip_code_fences(self):
        rules = build_rules()
        phone_rules = [r for r in rules if r.category == "phone"]
        assert phone_rules and all(r.skip_code_fences for r in phone_rules)


class TestKeywordToRule:
    def test_basic_keyword(self):
        rule = keyword_to_rule("Project Titan")
        assert rule.category == "project_titan"
        assert rule.source == "keyword"
        assert rule.pattern.search("about Project Titan here")
        assert rule.pattern.search("about project titan here")  # case insensitive

    def test_keyword_no_partial_match(self):
        rule = keyword_to_rule("secret")
        # Should match whole word only
        assert rule.pattern.search("the secret is out")
        assert not rule.pattern.search("secretariat")

    def test_keyword_with_special_chars(self):
        rule = keyword_to_rule("$INTERNAL")
        assert rule.pattern.search("value is $INTERNAL here")

    def test_keyword_severity(self):
        rule = keyword_to_rule("test", severity="critical")
        assert rule.severity == "critical"
