"""Tests for proxy.openai_filter — OpenAI API payload redaction."""

import pytest
from proxy.openai_filter import OpenAIFilter
from engine.redactor import Redactor
from engine.rules import build_rules


@pytest.fixture
def of():
    return OpenAIFilter(redactor=Redactor(rules=build_rules()))


class TestOpenAIFilter:
    def test_redacts_string_content(self, of):
        payload = {
            "messages": [{"role": "user", "content": "key: sk-ant-api03-abcdefghijklmnopqrstuvwxyz"}]
        }
        result, cats, diffs = of.process(payload)
        assert "[REDACTED:api_key]" in result["messages"][0]["content"]
        assert "api_key" in cats

    def test_redacts_content_blocks(self, of):
        payload = {
            "messages": [{
                "role": "user",
                "content": [
                    {"type": "text", "text": "email: alice@realcompany.io"},
                ],
            }]
        }
        result, cats, diffs = of.process(payload)
        assert "[REDACTED:email]" in result["messages"][0]["content"][0]["text"]

    def test_clean_payload_unchanged(self, of):
        payload = {
            "messages": [{"role": "user", "content": "hello world"}]
        }
        result, cats, diffs = of.process(payload)
        assert result["messages"][0]["content"] == "hello world"
        assert cats == []

    def test_multiple_messages(self, of):
        payload = {
            "messages": [
                {"role": "system", "content": "You are helpful"},
                {"role": "user", "content": "key: sk-ant-api03-abcdefghijklmnopqrstuvwxyz"},
            ]
        }
        result, cats, diffs = of.process(payload)
        assert result["messages"][0]["content"] == "You are helpful"
        assert "[REDACTED:api_key]" in result["messages"][1]["content"]

    def test_non_dict_content_ignored(self, of):
        payload = {
            "messages": [{
                "role": "user",
                "content": [42, None, "not a dict"],
            }]
        }
        # Should not crash
        result, cats, diffs = of.process(payload)
        assert cats == []

    def test_no_content_field(self, of):
        payload = {"messages": [{"role": "user"}]}
        result, cats, diffs = of.process(payload)
        assert cats == []
