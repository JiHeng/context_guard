"""Tests for engine.validators — false positive reduction."""

import re
import pytest
from engine.validators import (
    validate_credit_card,
    validate_cn_id,
    validate_iban,
    validate_phone,
    validate_ssn,
    validate_ip_address,
    validate_email,
)


class TestCreditCard:
    def test_valid_visa(self):
        assert validate_credit_card("4111111111111111", "", None) is True

    def test_valid_mastercard(self):
        assert validate_credit_card("5500000000000004", "", None) is True

    def test_invalid_luhn(self):
        assert validate_credit_card("4111111111111112", "", None) is False

    def test_too_short(self):
        assert validate_credit_card("411111", "", None) is False


class TestCnId:
    def test_valid_id(self):
        # 11010519491231002X is a well-known test ID
        assert validate_cn_id("11010519491231002X", "", None) is True

    def test_invalid_checksum(self):
        assert validate_cn_id("110105194912310021", "", None) is False

    def test_wrong_length(self):
        assert validate_cn_id("1101051949123100", "", None) is False


class TestIban:
    def test_valid_gb_iban(self):
        assert validate_iban("GB29NWBK60161331926819", "", None) is True

    def test_valid_de_iban(self):
        assert validate_iban("DE89370400440532013000", "", None) is True

    def test_invalid_iban(self):
        assert validate_iban("GB29NWBK60161331926818", "", None) is False

    def test_too_short(self):
        assert validate_iban("GB29NWBK601613", "", None) is False


class TestPhone:
    def test_formatted_phone_passes(self):
        assert validate_phone("555-123-4567", "", None) is True
        assert validate_phone("(555) 123-4567", "", None) is True
        assert validate_phone("+1 555 123 4567", "", None) is True

    def test_bare_digits_rejected(self):
        assert validate_phone("5551234567", "", None) is False


class TestSsn:
    def test_formatted_ssn_passes(self):
        assert validate_ssn("123-45-6789", "", None) is True
        assert validate_ssn("123 45 6789", "", None) is True

    def test_bare_digits_rejected(self):
        assert validate_ssn("123456789", "", None) is False


class TestIpAddress:
    def test_public_ip_passes(self):
        assert validate_ip_address("8.8.8.8", "", None) is True
        assert validate_ip_address("203.0.113.1", "", None) is True

    def test_loopback_rejected(self):
        assert validate_ip_address("127.0.0.1", "", None) is False

    def test_private_10_rejected(self):
        assert validate_ip_address("10.0.0.1", "", None) is False

    def test_private_192_168_rejected(self):
        assert validate_ip_address("192.168.1.1", "", None) is False

    def test_private_172_rejected(self):
        assert validate_ip_address("172.16.0.1", "", None) is False

    def test_link_local_rejected(self):
        assert validate_ip_address("169.254.1.1", "", None) is False

    def test_all_zeros_rejected(self):
        assert validate_ip_address("0.0.0.0", "", None) is False


class TestEmail:
    def test_real_domain_passes(self):
        assert validate_email("alice@realcompany.io", "", None) is True

    def test_example_domain_rejected(self):
        assert validate_email("test@example.com", "", None) is False
        assert validate_email("foo@test.com", "", None) is False
        assert validate_email("bar@example.org", "", None) is False


