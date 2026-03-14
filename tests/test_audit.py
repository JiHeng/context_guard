"""Tests for engine.audit — audit logging."""

import datetime
from pathlib import Path
from unittest.mock import patch

import pytest
from engine.audit import AuditLogger


@pytest.fixture
def audit(tmp_path):
    with patch.object(AuditLogger, "LOG_DIR", tmp_path):
        yield AuditLogger()


class TestAuditLogger:
    def test_log_clean(self, audit, tmp_path):
        audit.log("api_request", [])
        log_file = AuditLogger.log_path_for_date()
        assert log_file.exists()
        content = log_file.read_text()
        assert "| clean" in content

    def test_log_redacted(self, audit, tmp_path):
        audit.log("api_request", ["email", "api_key"])
        log_file = AuditLogger.log_path_for_date()
        content = log_file.read_text()
        assert "| redacted |" in content
        assert "email" in content
        assert "api_key" in content

    def test_log_path_uses_date(self):
        d = datetime.date(2026, 3, 14)
        path = AuditLogger.log_path_for_date(d)
        assert "audit-2026-03-14.log" in str(path)

    def test_multiple_entries_append(self, audit):
        audit.log("req1", [])
        audit.log("req2", ["email"])
        audit.log("req3", [])
        log_file = AuditLogger.log_path_for_date()
        lines = log_file.read_text().strip().splitlines()
        assert len(lines) == 3
