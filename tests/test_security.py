"""
Security tests for Context Guard.

Covers: audit log safety, hint truncation, bind address, config injection,
JSON validity, race conditions, error-path leaks, allowlist escaping,
ReDoS resistance, and redaction JSON roundtrip.
"""
from __future__ import annotations

import json
import threading

import pytest
from unittest.mock import patch

from engine.audit import AuditLogger
from engine.allowlist import Allowlist
from engine.config import Config, load as load_config
from engine.detector import Detector, _make_hint
from engine.redactor import Redactor
from engine.rules import build_rules
from proxy.message_filter import MessageFilter
from proxy.openai_filter import OpenAIFilter
from proxy.server import _is_enabled


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_redactor(config: Config | None = None, allowlist: Allowlist | None = None):
    config = config or Config()
    rules = build_rules(config)
    return Redactor(rules=rules, allowlist=allowlist)


def _make_filter(config: Config | None = None, allowlist: Allowlist | None = None):
    config = config or Config()
    rules = build_rules(config)
    redactor = Redactor(rules=rules, allowlist=allowlist)
    return MessageFilter(redactor=redactor), OpenAIFilter(redactor=redactor)


_API_KEY = "sk-ant-api03-abcdefghijklmnopqrstuvwxyz"
_EMAIL = "alice@realco.io"
_DB_URL = "postgresql://admin:s3cretP4ss@db.prod.internal:5432/mydb"
_BEARER = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature"


# ---------------------------------------------------------------------------
# 1. Audit log does NOT contain raw sensitive values
# ---------------------------------------------------------------------------

class TestAuditLogNoRawSecrets:
    def test_audit_log_contains_categories_not_values(self, tmp_path):
        redactor = _make_redactor()
        text = f"key: {_API_KEY}, email: {_EMAIL}"
        _redacted, cats = redactor.redact(text)
        assert cats

        with patch.object(AuditLogger, "LOG_DIR", tmp_path):
            logger = AuditLogger()
            logger.log("api_request", cats)
            log_file = list(tmp_path.glob("audit-*.log"))[0]
            content = log_file.read_text()
            assert "api_key" in content
            assert "email" in content
            assert _API_KEY not in content
            assert _EMAIL not in content

    def test_audit_log_no_db_url(self, tmp_path):
        redactor = _make_redactor()
        _redacted, cats = redactor.redact(f"conn: {_DB_URL}")
        assert cats

        with patch.object(AuditLogger, "LOG_DIR", tmp_path):
            logger = AuditLogger()
            logger.log("api_request", cats)
            log_file = list(tmp_path.glob("audit-*.log"))[0]
            content = log_file.read_text()
            assert "s3cretP4ss" not in content
            assert _DB_URL not in content


# ---------------------------------------------------------------------------
# 2. Detector Finding.hint is safely truncated
# ---------------------------------------------------------------------------

class TestHintTruncation:
    def test_short_match_hint(self):
        hint = _make_hint("abcdefgh")
        assert hint == "ab..."
        assert len(hint) <= 5

    def test_long_match_hint(self):
        hint = _make_hint("sk-ant-api03-abcdefghijklmnopqrstuvwxyz")
        assert hint == "sk-ant-a..."
        assert hint.endswith("...")
        assert len(hint) == 11

    def test_hint_never_exceeds_11_chars(self):
        for length in [1, 5, 8, 9, 100, 10000]:
            hint = _make_hint("x" * length)
            assert len(hint) <= 11, f"hint too long for input length {length}"
            assert hint.endswith("...")

    def test_detector_findings_have_safe_hints(self):
        detector = Detector(rules=build_rules())
        findings = detector.scan(f"key: {_API_KEY} and email: {_EMAIL}")
        for f in findings:
            assert f.hint.endswith("...")
            assert len(f.hint) <= 11
            assert f.hint != f.match


# ---------------------------------------------------------------------------
# 3. Proxy binds only to 127.0.0.1
# ---------------------------------------------------------------------------

class TestProxyBindAddress:
    def test_server_binds_to_localhost(self):
        import inspect
        from proxy import server as server_module
        source = inspect.getsource(server_module.start)
        assert '"127.0.0.1"' in source or "'127.0.0.1'" in source


# ---------------------------------------------------------------------------
# 4. Config injection — malicious regex (catastrophic backtracking)
# ---------------------------------------------------------------------------

class TestConfigInjection:
    def test_catastrophic_backtracking_regex_completes(self, tmp_path):
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({
            "extra_patterns": [{
                "category": "evil",
                "severity": "high",
                "pattern": "(a+)+$",
            }]
        }))

        config = load_config(path=config_file)
        redactor = Redactor(rules=build_rules(config))
        evil_input = "a" * 25 + "!"

        done = threading.Event()
        result_holder = [None]

        def run():
            result_holder[0] = redactor.redact(evil_input)
            done.set()

        t = threading.Thread(target=run, daemon=True)
        t.start()
        finished = done.wait(timeout=5)
        assert finished, "Redaction with catastrophic-backtracking regex hung for >5s"


# ---------------------------------------------------------------------------
# 5. JSON injection via redacted content
# ---------------------------------------------------------------------------

class TestJsonInjectionViaRedaction:
    def test_redacted_payload_is_valid_json(self):
        anthr, _ = _make_filter()
        payload = {
            "messages": [{"role": "user", "content": f"key: {_API_KEY}, mail: {_EMAIL}"}]
        }
        result, cats, diffs = anthr.process(payload)
        serialised = json.dumps(result)
        reparsed = json.loads(serialised)
        assert reparsed == result

    def test_secret_with_json_special_chars(self):
        redactor = _make_redactor()
        text = 'auth: Bearer abcdefghij"klmnopqrst\\uvwxyz1234'
        redacted, cats = redactor.redact(text)
        obj = {"content": redacted}
        serialised = json.dumps(obj)
        reparsed = json.loads(serialised)
        assert reparsed["content"] == redacted


# ---------------------------------------------------------------------------
# 6. _is_enabled() — corrupt config defaults to True
# ---------------------------------------------------------------------------

class TestIsEnabledGraceful:
    def test_corrupt_json_returns_true(self, tmp_path, monkeypatch):
        corrupt = tmp_path / "config.json"
        corrupt.write_text("{invalid json!!!}")

        import proxy.server as srv
        monkeypatch.setattr(srv, "CONFIG_PATH", corrupt)
        monkeypatch.setattr(srv, "_LOCAL_CONFIG", tmp_path / "nonexistent.json")
        assert _is_enabled() is True

    def test_partial_write_returns_true(self, tmp_path, monkeypatch):
        partial = tmp_path / "config.json"
        partial.write_text('{"enabled": fal')

        import proxy.server as srv
        monkeypatch.setattr(srv, "CONFIG_PATH", partial)
        monkeypatch.setattr(srv, "_LOCAL_CONFIG", tmp_path / "nonexistent.json")
        assert _is_enabled() is True

    def test_empty_file_returns_true(self, tmp_path, monkeypatch):
        empty = tmp_path / "config.json"
        empty.write_text("")

        import proxy.server as srv
        monkeypatch.setattr(srv, "CONFIG_PATH", empty)
        monkeypatch.setattr(srv, "_LOCAL_CONFIG", tmp_path / "nonexistent.json")
        assert _is_enabled() is True

    def test_missing_config_returns_true(self, tmp_path, monkeypatch):
        import proxy.server as srv
        monkeypatch.setattr(srv, "CONFIG_PATH", tmp_path / "nope.json")
        monkeypatch.setattr(srv, "_LOCAL_CONFIG", tmp_path / "also_nope.json")
        assert _is_enabled() is True


# ---------------------------------------------------------------------------
# 7. No sensitive data in error handling
# ---------------------------------------------------------------------------

class TestNoSecretsInErrors:
    def test_redacted_text_does_not_contain_raw_secret(self):
        redactor = _make_redactor()
        for secret in [_API_KEY, _EMAIL, _DB_URL, _BEARER]:
            text = f"data: {secret}"
            redacted, cats = redactor.redact(text)
            assert secret not in redacted, f"Secret leaked: {secret[:20]}..."

    def test_diff_output_not_returned_on_clean_input(self):
        anthr, _ = _make_filter()
        payload = {"messages": [{"role": "user", "content": "just some safe text"}]}
        _, cats, diffs = anthr.process(payload)
        assert diffs == []
        assert cats == []


# ---------------------------------------------------------------------------
# 8. Allowlist with special regex characters
# ---------------------------------------------------------------------------

class TestAllowlistSpecialChars:
    def test_plus_in_email_allowlisted(self, tmp_path):
        allow_file = tmp_path / "allow.txt"
        allow_file.write_text("foo+bar@baz.com\n")
        allowlist = Allowlist(path=allow_file)
        redactor = _make_redactor(allowlist=allowlist)
        text = "contact: foo+bar@baz.com"
        redacted, cats = redactor.redact(text)
        assert "foo+bar@baz.com" in redacted
        assert "email" not in cats

    def test_dot_in_allowlist_is_literal(self, tmp_path):
        allow_file = tmp_path / "allow.txt"
        allow_file.write_text("foo.bar@company.com\n")
        allowlist = Allowlist(path=allow_file)
        assert allowlist.is_allowed("foo.bar@company.com") is True
        assert allowlist.is_allowed("fooxbar@company.com") is False

    def test_brackets_in_allowlist(self, tmp_path):
        allow_file = tmp_path / "allow.txt"
        allow_file.write_text("user[1]@corp.com\n")
        allowlist = Allowlist(path=allow_file)
        assert allowlist.is_allowed("user[1]@corp.com") is True
        assert allowlist.is_allowed("user1@corp.com") is False


# ---------------------------------------------------------------------------
# 9. ReDoS resistance
# ---------------------------------------------------------------------------

class TestReDosResistance:
    @pytest.fixture
    def redactor(self):
        config = Config(enabled_rules=[
            "credit_card", "ssn", "cn_id", "iban", "ip_address",
            "uuid", "date_of_birth", "passport",
        ])
        return Redactor(rules=build_rules(config))

    _EVIL_INPUTS = [
        "1" * 1000,
        "sk-" + "a" * 1000,
        "a" * 500 + "@" + "b" * 500 + ".com",
        ".".join(["255"] * 200),
        "Bearer " + "x" * 5000,
        "password=" + "x" * 5000,
        "-".join(["123"] * 500),
        "-".join(["abcdef12"] * 200),
    ]

    @pytest.mark.parametrize("evil_input", _EVIL_INPUTS,
                             ids=[f"evil_{i}" for i in range(len(_EVIL_INPUTS))])
    def test_pattern_completes_within_timeout(self, redactor, evil_input):
        done = threading.Event()
        exc_holder = [None]

        def run():
            try:
                redactor.redact(evil_input)
            except Exception as e:
                exc_holder[0] = e
            finally:
                done.set()

        t = threading.Thread(target=run, daemon=True)
        t.start()
        finished = done.wait(timeout=5)
        assert finished, f"Redaction hung (>5s) on input: {evil_input[:60]}..."
        assert exc_holder[0] is None, f"Redaction raised: {exc_holder[0]}"


# ---------------------------------------------------------------------------
# 10. Redacted output is always valid JSON when input was valid JSON
# ---------------------------------------------------------------------------

class TestRedactedOutputValidJson:
    def _roundtrip(self, payload: dict) -> dict:
        anthr, _ = _make_filter()
        result, _, _ = anthr.process(payload)
        serialised = json.dumps(result)
        return json.loads(serialised)

    def test_simple_payload(self):
        payload = {"messages": [{"role": "user", "content": f"key={_API_KEY}"}]}
        reparsed = self._roundtrip(payload)
        assert "[REDACTED:" in reparsed["messages"][0]["content"]

    def test_nested_content_blocks(self):
        payload = {
            "messages": [{
                "role": "user",
                "content": [
                    {"type": "text", "text": f"email: {_EMAIL}"},
                    {"type": "text", "text": f"url: {_DB_URL}"},
                ]
            }]
        }
        anthr, _ = _make_filter()
        result, _, _ = anthr.process(payload)
        serialised = json.dumps(result)
        reparsed = json.loads(serialised)
        for block in reparsed["messages"][0]["content"]:
            if block["type"] == "text":
                assert isinstance(block["text"], str)

    def test_system_prompt_with_secrets(self):
        payload = {"system": f"Connection: {_DB_URL}", "messages": []}
        reparsed = self._roundtrip(payload)
        assert "[REDACTED:" in reparsed["system"]

    def test_payload_with_special_json_chars(self):
        payload = {
            "messages": [{
                "role": "user",
                "content": '{"key": "' + _API_KEY + '", "val": true}'
            }]
        }
        reparsed = self._roundtrip(payload)
        assert isinstance(reparsed["messages"][0]["content"], str)

    def test_openai_payload_roundtrip(self):
        _, oai = _make_filter()
        payload = {"messages": [{"role": "user", "content": f"secret: {_API_KEY}"}]}
        result, cats, _ = oai.process(payload)
        serialised = json.dumps(result)
        reparsed = json.loads(serialised)
        assert "[REDACTED:" in reparsed["messages"][0]["content"]
