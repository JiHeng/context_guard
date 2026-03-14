"""Tests for proxy.message_filter — Anthropic API payload redaction."""

import pytest
from proxy.message_filter import MessageFilter
from engine.redactor import Redactor
from engine.rules import build_rules


@pytest.fixture
def mf():
    return MessageFilter(redactor=Redactor(rules=build_rules()))


class TestAnthropicFilter:
    def test_redacts_user_message_string(self, mf):
        payload = {
            "messages": [{"role": "user", "content": "my key is sk-ant-api03-abcdefghijklmnopqrstuvwxyz"}]
        }
        result, cats, diffs = mf.process(payload)
        assert "[REDACTED:api_key]" in result["messages"][0]["content"]
        assert "api_key" in cats

    def test_redacts_system_prompt(self, mf):
        payload = {
            "system": "secret: sk-ant-api03-abcdefghijklmnopqrstuvwxyz",
            "messages": [{"role": "user", "content": "hello"}],
        }
        result, cats, diffs = mf.process(payload)
        assert "[REDACTED:api_key]" in result["system"]

    def test_redacts_content_blocks(self, mf):
        payload = {
            "messages": [{
                "role": "user",
                "content": [
                    {"type": "text", "text": "key: sk-ant-api03-abcdefghijklmnopqrstuvwxyz"},
                ],
            }]
        }
        result, cats, diffs = mf.process(payload)
        assert "[REDACTED:api_key]" in result["messages"][0]["content"][0]["text"]

    def test_redacts_tool_result_string(self, mf):
        payload = {
            "messages": [{
                "role": "user",
                "content": [
                    {"type": "tool_result", "content": "key: sk-ant-api03-abcdefghijklmnopqrstuvwxyz"},
                ],
            }]
        }
        result, cats, diffs = mf.process(payload)
        assert "[REDACTED:api_key]" in result["messages"][0]["content"][0]["content"]

    def test_redacts_tool_result_blocks(self, mf):
        payload = {
            "messages": [{
                "role": "user",
                "content": [{
                    "type": "tool_result",
                    "content": [
                        {"type": "text", "text": "email: alice@realcompany.io"},
                    ],
                }],
            }]
        }
        result, cats, diffs = mf.process(payload)
        inner = result["messages"][0]["content"][0]["content"][0]["text"]
        assert "[REDACTED:email]" in inner

    def test_clean_payload_unchanged(self, mf):
        payload = {
            "messages": [{"role": "user", "content": "What is 2+2?"}]
        }
        result, cats, diffs = mf.process(payload)
        assert result["messages"][0]["content"] == "What is 2+2?"
        assert cats == []
        assert diffs == []

    def test_categories_deduplicated(self, mf):
        payload = {
            "messages": [
                {"role": "user", "content": "sk-ant-api03-aaaaaaaaaaaaaaaaaaaaaa"},
                {"role": "user", "content": "sk-ant-api03-bbbbbbbbbbbbbbbbbbbbbb"},
            ]
        }
        _, cats, _ = mf.process(payload)
        assert cats.count("api_key") == 1

    def test_diffs_recorded(self, mf):
        payload = {
            "messages": [{"role": "user", "content": "key: sk-ant-api03-abcdefghijklmnopqrstuvwxyz"}]
        }
        _, _, diffs = mf.process(payload)
        assert len(diffs) == 1
        original, redacted = diffs[0]
        assert "sk-ant" in original
        assert "[REDACTED" in redacted

    def test_non_text_blocks_ignored(self, mf):
        payload = {
            "messages": [{
                "role": "user",
                "content": [
                    {"type": "image", "source": {"data": "base64data"}},
                ],
            }]
        }
        result, cats, diffs = mf.process(payload)
        assert cats == []
