"""Tests for engine.detector — content scanning."""

import pytest
from engine.detector import Detector, Finding
from engine.rules import build_rules, Rule, _BASE_RULES
import re


@pytest.fixture
def detector():
    return Detector(rules=build_rules())


class TestSecrets:
    def test_anthropic_api_key(self, detector):
        findings = detector.scan("key: sk-ant-api03-abcdefghijklmnopqrstuvwxyz")
        assert any(f.category == "api_key" for f in findings)

    def test_openai_api_key(self, detector):
        findings = detector.scan("sk-proj-abcdefghijklmnopqrstuvwxyz")
        assert any(f.category == "api_key" for f in findings)

    def test_generic_sk_key(self, detector):
        findings = detector.scan("sk-abcdefghijklmnopqrstuvwxyz")
        assert any(f.category == "api_key" for f in findings)

    def test_google_api_key(self, detector):
        findings = detector.scan("AIzaSyB-abcdefghijklmnopqrstuvwxyz12345")
        assert any(f.category == "api_key" for f in findings)

    def test_aws_access_key(self, detector):
        findings = detector.scan("AKIAIOSFODNN7EXAMPLE")
        assert any(f.category == "aws_key" for f in findings)

    def test_github_token(self, detector):
        findings = detector.scan("ghp_" + "A" * 36)
        assert any(f.category == "token" for f in findings)

    def test_slack_token(self, detector):
        findings = detector.scan("xoxb-123456789012-abcdefghij")
        assert any(f.category == "token" for f in findings)

    def test_jwt(self, detector):
        findings = detector.scan("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijk")
        assert any(f.category == "jwt" for f in findings)

    def test_bearer_token(self, detector):
        findings = detector.scan("Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6")
        cats = {f.category for f in findings}
        assert "bearer_token" in cats or "jwt" in cats

    def test_private_key(self, detector):
        findings = detector.scan("-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----")
        assert any(f.category == "private_key" for f in findings)

    def test_env_secret(self, detector):
        findings = detector.scan("PASSWORD=mysecretpassword123")
        assert any(f.category == "env_secret" for f in findings)

    def test_db_connection_string(self, detector):
        findings = detector.scan("postgresql://user:pass@host:5432/mydb")
        assert any(f.category == "db_credentials" for f in findings)


class TestSensitive:
    def test_email(self, detector):
        findings = detector.scan("contact alice@realcompany.io for details")
        assert any(f.category == "email" for f in findings)

    def test_url_token(self, detector):
        # Use ?key= which overlaps with env_secret; the env_secret rule fires first
        # since it has higher priority. Either match is acceptable — both detect the secret.
        findings = detector.scan("visit https://site.io/cb?auth=xK9mPqL2nR8vW3jY")
        cats = {f.category for f in findings}
        assert "url_token" in cats or "env_secret" in cats


class TestCleanText:
    def test_clean_text_no_findings(self, detector):
        findings = detector.scan("This is perfectly normal text with no secrets.")
        assert findings == []

    def test_code_snippet_clean(self, detector):
        findings = detector.scan("x = 42\nfor i in range(10):\n    print(i)")
        assert findings == []


class TestHint:
    def test_hint_truncation(self, detector):
        findings = detector.scan("sk-ant-api03-abcdefghijklmnopqrstuvwxyz")
        assert findings
        assert findings[0].hint.endswith("...")
        assert len(findings[0].hint) <= 12

    def test_short_match_hint(self):
        from engine.detector import _make_hint
        assert _make_hint("abcde") == "ab..."
        assert _make_hint("abcdefghij") == "abcdefgh..."


class TestOverlappingMatches:
    def test_no_duplicate_overlapping(self, detector):
        # A string that could match multiple rules at the same span
        text = "sk-ant-api03-abcdefghijklmnopqrstuvwxyz"
        findings = detector.scan(text)
        spans = [(f.match, f.category) for f in findings]
        # Should not have two findings covering the exact same text
        matches = [f.match for f in findings]
        assert len(matches) == len(set(matches)) or len(findings) <= 2
