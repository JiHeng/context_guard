"""Tests for engine.allowlist — exact and regex allowlisting."""

import pytest
from engine.allowlist import Allowlist


@pytest.fixture
def allow_file(tmp_path):
    return tmp_path / "allow.txt"


class TestAllowlist:
    def test_empty_allowlist(self, tmp_path):
        al = Allowlist(path=tmp_path / "nonexistent.txt")
        assert len(al) == 0
        assert al.is_allowed("anything") is False

    def test_exact_match(self, allow_file):
        allow_file.write_text("alice@company.com\nbob@company.com\n")
        al = Allowlist(path=allow_file)
        assert al.is_allowed("alice@company.com") is True
        assert al.is_allowed("eve@company.com") is False

    def test_regex_match(self, allow_file):
        allow_file.write_text("re:.*@internal\\.corp\n")
        al = Allowlist(path=allow_file)
        assert al.is_allowed("anyone@internal.corp") is True
        assert al.is_allowed("anyone@external.corp") is False

    def test_comments_and_blanks_ignored(self, allow_file):
        allow_file.write_text("# this is a comment\n\nalice@company.com\n  \n")
        al = Allowlist(path=allow_file)
        assert len(al) == 1
        assert al.is_allowed("alice@company.com") is True

    def test_invalid_regex_silently_skipped(self, allow_file):
        allow_file.write_text("re:[invalid\nalice@company.com\n")
        al = Allowlist(path=allow_file)
        assert al.is_allowed("alice@company.com") is True

    def test_len_counts_both(self, allow_file):
        allow_file.write_text("exact_value\nre:pattern\n")
        al = Allowlist(path=allow_file)
        assert len(al) == 2

    def test_mixed_entries(self, allow_file):
        allow_file.write_text("10.0.0.1\nre:192\\.168\\.\\d+\\.\\d+\n")
        al = Allowlist(path=allow_file)
        assert al.is_allowed("10.0.0.1") is True
        assert al.is_allowed("192.168.1.100") is True
        assert al.is_allowed("172.16.0.1") is False
