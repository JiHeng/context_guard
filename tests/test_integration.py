"""
Integration tests: full pipeline from payload → redaction → audit log.
Also covers false-positive validation through the complete stack.
"""
from __future__ import annotations

import json
import re
import pytest
from pathlib import Path
from unittest.mock import patch

from engine.config import Config, KeywordRule, PatternEntry
from engine.rules import build_rules
from engine.redactor import Redactor
from engine.detector import Detector
from engine.allowlist import Allowlist
from engine.audit import AuditLogger
from proxy.message_filter import MessageFilter
from proxy.openai_filter import OpenAIFilter


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _anthropic_payload(user_text: str, system: str | None = None) -> dict:
    payload = {"messages": [{"role": "user", "content": user_text}]}
    if system:
        payload["system"] = system
    return payload


def _openai_payload(user_text: str) -> dict:
    return {"messages": [{"role": "user", "content": user_text}]}


def _make_filter(config: Config | None = None, allowlist: Allowlist | None = None):
    config = config or Config()
    rules = build_rules(config)
    redactor = Redactor(rules=rules, allowlist=allowlist)
    return MessageFilter(redactor=redactor), OpenAIFilter(redactor=redactor)


# ---------------------------------------------------------------------------
# E2E: detection → redaction → audit
# ---------------------------------------------------------------------------

class TestE2EAnthropicRedactAndLog:
    def test_api_key_and_email(self, tmp_path):
        anthr, _ = _make_filter()
        payload = _anthropic_payload(
            "key: sk-ant-api03-abcdefghijklmnopqrstuvwxyz, mail: alice@realco.io"
        )
        result, cats, diffs = anthr.process(payload)

        assert "[REDACTED:api_key]" in result["messages"][0]["content"]
        assert "[REDACTED:email]" in result["messages"][0]["content"]
        assert "api_key" in cats
        assert "email" in cats
        assert len(diffs) == 1  # one message → one diff

        # Audit log
        with patch.object(AuditLogger, "LOG_DIR", tmp_path):
            logger = AuditLogger()
            logger.log("api_request", cats)
            log_file = list(tmp_path.glob("audit-*.log"))[0]
            content = log_file.read_text()
            assert "redacted" in content
            assert "api_key" in content
            assert "email" in content

    def test_clean_payload_logs_clean(self, tmp_path):
        anthr, _ = _make_filter()
        payload = _anthropic_payload("just normal code")
        result, cats, diffs = anthr.process(payload)

        assert cats == []
        assert diffs == []
        assert result["messages"][0]["content"] == "just normal code"

        with patch.object(AuditLogger, "LOG_DIR", tmp_path):
            logger = AuditLogger()
            logger.log("api_request", cats)
            log_file = list(tmp_path.glob("audit-*.log"))[0]
            assert "clean" in log_file.read_text()


class TestE2EOpenAIRedactAndLog:
    def test_api_key_redacted(self, tmp_path):
        _, oai = _make_filter()
        payload = _openai_payload("key: sk-ant-api03-abcdefghijklmnopqrstuvwxyz")
        result, cats, diffs = oai.process(payload)

        assert "[REDACTED:api_key]" in result["messages"][0]["content"]
        assert "api_key" in cats


class TestE2EAllowlist:
    def test_allowlisted_email_not_redacted(self, tmp_path):
        allow_file = tmp_path / "allow.txt"
        allow_file.write_text("alice@realco.io\n")
        allowlist = Allowlist(path=allow_file)
        anthr, _ = _make_filter(allowlist=allowlist)

        payload = _anthropic_payload("email: alice@realco.io")
        result, cats, diffs = anthr.process(payload)

        assert "alice@realco.io" in result["messages"][0]["content"]
        assert "email" not in cats


class TestE2EConfigDisabledRule:
    def test_disabled_email_not_redacted(self):
        config = Config(disabled_rules=["email"])
        anthr, _ = _make_filter(config=config)

        payload = _anthropic_payload("email: alice@realco.io")
        result, cats, diffs = anthr.process(payload)

        assert "alice@realco.io" in result["messages"][0]["content"]
        assert "email" not in cats


class TestE2EConfigEnabledCatalog:
    def test_credit_card_redacted(self):
        config = Config(enabled_rules=["credit_card"])
        anthr, _ = _make_filter(config=config)

        # 4111111111111111 passes Luhn
        payload = _anthropic_payload("card: 4111111111111111")
        result, cats, diffs = anthr.process(payload)

        assert "[REDACTED:credit_card]" in result["messages"][0]["content"]
        assert "credit_card" in cats


class TestE2EConfigKeywordRule:
    def test_keyword_redacted(self):
        config = Config(keyword_rules=[KeywordRule(keyword="Project Apollo")])
        anthr, _ = _make_filter(config=config)

        payload = _anthropic_payload("we are working on Project Apollo")
        result, cats, diffs = anthr.process(payload)

        assert "[REDACTED:project_apollo]" in result["messages"][0]["content"]
        assert "project_apollo" in cats


# ---------------------------------------------------------------------------
# False-positive integration tests (full pipeline)
# ---------------------------------------------------------------------------

class TestFalsePositiveIntegration:
    """These use Detector with full config to verify validators work end-to-end."""

    @pytest.fixture
    def full_detector(self):
        config = Config(enabled_rules=["credit_card", "ssn", "cn_id", "iban", "ip_address"])
        return Detector(rules=build_rules(config))

    @pytest.fixture
    def full_redactor(self):
        config = Config(enabled_rules=["credit_card", "ssn", "cn_id", "iban", "ip_address"])
        return Redactor(rules=build_rules(config))

    def test_fp_bare_digits_not_phone(self, full_detector):
        findings = full_detector.scan("I have 1234567890 items")
        cats = {f.category for f in findings}
        assert "phone" not in cats

    def test_fp_bare_digits_not_ssn(self, full_detector):
        findings = full_detector.scan("row 123456789")
        cats = {f.category for f in findings}
        assert "ssn" not in cats

    def test_fp_bad_luhn_not_credit_card(self, full_detector):
        findings = full_detector.scan("version 4111111111111112")
        cats = {f.category for f in findings}
        assert "credit_card" not in cats

    def test_fp_private_ip_not_redacted(self, full_redactor):
        text, cats = full_redactor.redact("ip is 192.168.1.1")
        assert "192.168.1.1" in text
        assert "ip_address" not in cats

    def test_fp_loopback_ip_not_redacted(self, full_redactor):
        text, cats = full_redactor.redact("localhost is 127.0.0.1")
        assert "127.0.0.1" in text
        assert "ip_address" not in cats

    def test_fp_10_network_not_redacted(self, full_redactor):
        text, cats = full_redactor.redact("server at 10.0.0.1")
        assert "10.0.0.1" in text
        assert "ip_address" not in cats

    def test_fp_example_email_not_redacted(self, full_redactor):
        text, cats = full_redactor.redact("send to user@example.com")
        assert "user@example.com" in text
        assert "email" not in cats

    def test_fp_invalid_cn_id_not_redacted(self, full_detector):
        # Valid format but wrong checksum
        findings = full_detector.scan("id 110101199003078571")
        cats = {f.category for f in findings}
        assert "cn_id" not in cats

    def test_fp_invalid_iban_not_redacted(self, full_detector):
        # Wrong check digits
        findings = full_detector.scan("iban GB29NWBK60161331926818")
        cats = {f.category for f in findings}
        assert "iban" not in cats

    def test_fp_code_fence_phone_not_redacted(self, full_redactor):
        text = "```\n555-123-4567\n```"
        result, cats = full_redactor.redact(text)
        assert "555-123-4567" in result
        assert "phone" not in cats

    def test_fp_code_fence_ssn_not_redacted(self):
        config = Config(enabled_rules=["ssn"])
        redactor = Redactor(rules=build_rules(config))
        text = "```\n123-45-6789\n```"
        result, cats = redactor.redact(text)
        assert "123-45-6789" in result
        assert "ssn" not in cats

    def test_fp_code_fence_api_key_still_redacted(self, full_redactor):
        text = "```\nsk-ant-api03-abcdefghijklmnopqrstuvwxyz\n```"
        result, cats = full_redactor.redact(text)
        assert "[REDACTED:api_key]" in result

    def test_fp_code_fence_valid_cc_still_redacted(self):
        config = Config(enabled_rules=["credit_card"])
        redactor = Redactor(rules=build_rules(config))
        text = "```\n4111111111111111\n```"
        result, cats = redactor.redact(text)
        assert "[REDACTED:credit_card]" in result


# ---------------------------------------------------------------------------
# Edge cases and boundary conditions
# ---------------------------------------------------------------------------

class TestEdgeCases:
    @pytest.fixture
    def redactor(self):
        return Redactor(rules=build_rules())

    @pytest.fixture
    def detector(self):
        return Detector(rules=build_rules())

    def test_empty_string(self, redactor, detector):
        text, cats = redactor.redact("")
        assert text == ""
        assert cats == []
        assert detector.scan("") == []

    def test_unicode_chinese(self, redactor):
        text = "这是一段普通中文文本，没有敏感信息"
        result, cats = redactor.redact(text)
        assert result == text
        assert cats == []

    def test_unicode_emoji(self, redactor):
        text = "Hello 🎉👋 world! No secrets here 🔑"
        result, cats = redactor.redact(text)
        assert result == text
        assert cats == []

    def test_mixed_unicode_with_secret(self, redactor):
        text = "密钥是 sk-ant-api03-abcdefghijklmnopqrstuvwxyz 请勿泄漏"
        result, cats = redactor.redact(text)
        assert "[REDACTED:api_key]" in result
        assert "密钥是" in result
        assert "请勿泄漏" in result

    def test_very_long_input(self, redactor):
        # 100KB of normal text with one secret buried inside
        filler = "This is normal text. " * 5000  # ~105KB
        text = filler + "sk-ant-api03-abcdefghijklmnopqrstuvwxyz" + filler
        result, cats = redactor.redact(text)
        assert "[REDACTED:api_key]" in result
        assert "api_key" in cats

    def test_multiple_secrets_same_line(self, redactor):
        text = "sk-ant-api03-aaaaaaaaaaaaaaaaaaaaaa sk-proj-bbbbbbbbbbbbbbbbbbbbbb"
        result, cats = redactor.redact(text)
        assert result.count("[REDACTED:api_key]") == 2

    def test_redacted_tag_in_input_not_confused(self, redactor):
        text = "the output was [REDACTED:email] and that's fine"
        result, cats = redactor.redact(text)
        assert cats == []  # nothing new to redact

    def test_newlines_and_tabs(self, redactor):
        text = "line1\nsk-ant-api03-abcdefghijklmnopqrstuvwxyz\n\tline3"
        result, cats = redactor.redact(text)
        assert "[REDACTED:api_key]" in result
        assert "line1\n" in result
        assert "\n\tline3" in result


class TestMessageFilterEdgeCases:
    def test_no_messages_key(self):
        mf = MessageFilter(redactor=Redactor(rules=build_rules()))
        payload = {"model": "claude-3"}
        result, cats, diffs = mf.process(payload)
        assert cats == []
        assert result == {"model": "claude-3"}

    def test_empty_messages(self):
        mf = MessageFilter(redactor=Redactor(rules=build_rules()))
        payload = {"messages": []}
        result, cats, diffs = mf.process(payload)
        assert cats == []

    def test_message_without_content(self):
        mf = MessageFilter(redactor=Redactor(rules=build_rules()))
        payload = {"messages": [{"role": "user"}]}
        result, cats, diffs = mf.process(payload)
        assert cats == []

    def test_content_is_number(self):
        mf = MessageFilter(redactor=Redactor(rules=build_rules()))
        payload = {"messages": [{"role": "user", "content": 42}]}
        result, cats, diffs = mf.process(payload)
        assert cats == []

    def test_system_prompt_redacted(self):
        mf = MessageFilter(redactor=Redactor(rules=build_rules()))
        payload = {
            "system": "My key is sk-ant-api03-abcdefghijklmnopqrstuvwxyz",
            "messages": [],
        }
        result, cats, diffs = mf.process(payload)
        assert "[REDACTED:api_key]" in result["system"]


class TestOpenAIFilterEdgeCases:
    def test_no_messages_key(self):
        oai = OpenAIFilter(redactor=Redactor(rules=build_rules()))
        payload = {"model": "gpt-4"}
        result, cats, diffs = oai.process(payload)
        assert cats == []

    def test_content_list_with_non_text(self):
        oai = OpenAIFilter(redactor=Redactor(rules=build_rules()))
        payload = {
            "messages": [{
                "role": "user",
                "content": [
                    {"type": "image_url", "image_url": {"url": "http://example.com/img.png"}},
                    {"type": "text", "text": "key: sk-ant-api03-abcdefghijklmnopqrstuvwxyz"},
                ],
            }]
        }
        result, cats, diffs = oai.process(payload)
        assert "api_key" in cats
        # image block untouched
        assert result["messages"][0]["content"][0]["type"] == "image_url"
