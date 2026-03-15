"""
Validators for matched PII/secret patterns — reduce false positives.

Each validator returns True if the match looks like a real sensitive value,
False if it's likely a false positive that should be skipped.
"""

import re
from typing import Callable


# ---------------------------------------------------------------------------
# Code fence utilities
# ---------------------------------------------------------------------------

_CODE_FENCE_RE = re.compile(r"^```", re.MULTILINE)


def find_code_fence_ranges(text: str) -> list[tuple[int, int]]:
    """Return a list of (start, end) byte-offset ranges for fenced code blocks."""
    fences = list(_CODE_FENCE_RE.finditer(text))
    ranges: list[tuple[int, int]] = []
    i = 0
    while i + 1 < len(fences):
        start = fences[i].start()
        end = fences[i + 1].end()
        ranges.append((start, end))
        i += 2
    return ranges


def is_in_code_fence(pos: int, ranges: list[tuple[int, int]]) -> bool:
    """Return True if *pos* falls inside any code fence range."""
    for start, end in ranges:
        if start <= pos < end:
            return True
    return False


# ---------------------------------------------------------------------------
# Individual validators
# ---------------------------------------------------------------------------

def validate_credit_card(text: str, full: str, m: re.Match) -> bool:
    """Luhn algorithm — real credit card numbers always pass."""
    digits = [int(d) for d in text if d.isdigit()]
    if len(digits) < 13:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def validate_cn_id(text: str, full: str, m: re.Match) -> bool:
    """Chinese national ID weighted checksum (GB 11643-1999)."""
    if len(text) != 18:
        return False
    weights = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]
    check_chars = "10X98765432"
    try:
        total = sum(int(text[i]) * weights[i] for i in range(17))
    except ValueError:
        return False
    expected = check_chars[total % 11]
    return text[17].upper() == expected


def validate_iban(text: str, full: str, m: re.Match) -> bool:
    """ISO 7064 mod-97 check for IBAN."""
    iban = text.upper().replace(" ", "")
    if len(iban) < 15:
        return False
    # Move first 4 chars to end
    rearranged = iban[4:] + iban[:4]
    # Convert letters to numbers (A=10, B=11, ...)
    numeric = ""
    for ch in rearranged:
        if ch.isdigit():
            numeric += ch
        elif ch.isalpha():
            numeric += str(ord(ch) - ord("A") + 10)
        else:
            return False
    try:
        return int(numeric) % 97 == 1
    except ValueError:
        return False


def validate_phone(text: str, full: str, m: re.Match) -> bool:
    """Require at least one formatting character (-, space, parens, +, dot)."""
    return bool(re.search(r"[-\s()+.]", text))


def validate_ssn(text: str, full: str, m: re.Match) -> bool:
    """Require separator (dash or space) between groups."""
    digits_only = re.sub(r"\D", "", text)
    # If the matched text is all digits with no separators, it's likely not a real SSN
    if text == digits_only:
        return False
    return True


def validate_ip_address(text: str, full: str, m: re.Match) -> bool:
    """Skip private/loopback addresses — they're dev artifacts, not PII."""
    parts = text.split(".")
    if len(parts) != 4:
        return False
    try:
        octets = [int(p) for p in parts]
    except ValueError:
        return False
    first, second = octets[0], octets[1]
    # Loopback
    if first == 127:
        return False
    # 10.0.0.0/8
    if first == 10:
        return False
    # 192.168.0.0/16
    if first == 192 and second == 168:
        return False
    # 172.16.0.0/12
    if first == 172 and 16 <= second <= 31:
        return False
    # 0.0.0.0
    if all(o == 0 for o in octets):
        return False
    # 169.254.0.0/16 (link-local)
    if first == 169 and second == 254:
        return False
    return True


def validate_email(text: str, full: str, m: re.Match) -> bool:
    """Skip test/example domains."""
    _TEST_DOMAINS = {
        "example.com", "example.org", "example.net",
        "test.com", "test.org", "test.net",
        "localhost", "localhost.localdomain",
        "invalid",
    }
    at_idx = text.rfind("@")
    if at_idx < 0:
        return True
    domain = text[at_idx + 1:].lower()
    return domain not in _TEST_DOMAINS


# ---------------------------------------------------------------------------
# Registry: rule category -> validator function
# ---------------------------------------------------------------------------

VALIDATORS: dict[str, Callable[[str, str, re.Match], bool]] = {
    "credit_card": validate_credit_card,
    "cn_id": validate_cn_id,
    "iban": validate_iban,
    "phone": validate_phone,
    "ssn": validate_ssn,
    "ip_address": validate_ip_address,
    "email": validate_email,
}
