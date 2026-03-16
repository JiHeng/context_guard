"""
Detection rules: regex patterns for secrets and sensitive data.
Each rule is a Rule object: (category, severity, pattern, source, description).

Use build_rules(config) to get the active rule list.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable


@dataclass
class Rule:
    category: str
    severity: str
    pattern: re.Pattern
    source: str = "builtin"   # builtin | catalog | keyword | custom
    description: str = ""
    validator: Callable | None = None       # post-match validator (return True = real hit)
    skip_code_fences: bool = False          # skip matches inside ``` blocks


def _r(cat: str, sev: str, pat: re.Pattern, desc: str = "") -> Rule:
    return Rule(category=cat, severity=sev, pattern=pat, source="builtin", description=desc)


_BASE_RULES: list[Rule] = [
    # === SECRETS (strong redaction) ===
    _r("api_key", "secret", re.compile(r"sk-ant-[a-zA-Z0-9\-_]{20,}"), "API keys and tokens"),
    _r("api_key", "secret", re.compile(r"sk-proj-[a-zA-Z0-9\-_]{20,}"), "API keys and tokens"),
    _r("api_key", "secret", re.compile(r"sk-[a-zA-Z0-9]{20,}"), "API keys and tokens"),
    _r("api_key", "secret", re.compile(r"AIza[0-9A-Za-z\-_]{35}"), "API keys and tokens"),
    _r("aws_key", "secret", re.compile(r"AKIA[0-9A-Z]{16}"), "AWS access keys"),
    _r("token",   "secret", re.compile(r"gh[pousr]_[A-Za-z0-9_]{36,}"), "OAuth and service tokens"),
    _r("token",   "secret", re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}"), "OAuth and service tokens"),
    _r("jwt",     "secret", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"), "JSON Web Tokens"),
    _r("bearer_token", "secret", re.compile(r"(?i)bearer\s+[a-zA-Z0-9_\-.]{20,}"), "Bearer auth tokens"),
    _r("private_key", "secret", re.compile(r"-----BEGIN\s+.*?PRIVATE KEY-----", re.DOTALL), "Private key blocks"),
    _r("env_secret", "secret", re.compile(r"(?i)(password|api_key|secret|token|auth)\s*=\s*\S{8,}"), "Env-style secret assignments"),
    _r("db_credentials", "secret", re.compile(r"(?i)(postgresql|mysql|mongodb|redis)://\S{10,}"), "Database connection strings"),

    # === SENSITIVE (redact) ===
    _r("email",     "sensitive", re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"), "Email addresses"),
    _r("phone",     "sensitive", re.compile(r"\b(\+?1[\s.\-]?)?\(?\d{3}\)?[\s.\-]?\d{3}[\s.\-]?\d{4}\b"), "Phone numbers (US/CN)"),
    _r("phone",     "sensitive", re.compile(r"\b1[3-9]\d[\s.\-]?\d{4}[\s.\-]?\d{4}\b"), "Phone numbers (US/CN)"),
    _r("url_token", "sensitive", re.compile(r"(?i)[?&](token|key|secret|auth|api_key)=[a-zA-Z0-9_\-.%+]{8,}"), "URL query params with tokens"),
]


# Catalog rules: name → (description, severity, compiled_pattern)
# Each catalog rule's category equals its name.
_CATALOG_RULES: dict[str, tuple[str, str, re.Pattern]] = {
    "credit_card": (
        "Credit card numbers (Visa, MC, Amex, UnionPay)",
        "high",
        re.compile(
            r"\b(?:4[0-9]{12}(?:[0-9]{3})?(?:[0-9]{3})?"
            r"|5[1-5][0-9]{14}|2[2-7][0-9]{14}"
            r"|3[47][0-9]{13}"
            r"|62[0-9]{14,17})\b"
        ),
    ),
    "ssn": (
        "US Social Security Numbers",
        "high",
        re.compile(r"\b(?!000|666|9\d\d)\d{3}[-\s]?(?!00)\d{2}[-\s]?(?!0000)\d{4}\b"),
    ),
    "cn_id": (
        "Chinese national ID (18-digit)",
        "high",
        re.compile(
            r"\b[1-9]\d{5}(?:19|20)\d{2}"
            r"(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])"
            r"\d{3}[\dXx]\b"
        ),
    ),
    "passport": (
        "Passport numbers (common formats)",
        "high",
        re.compile(r"\b[A-Z]{1,2}[0-9]{6,9}\b"),
    ),
    "iban": (
        "International bank account numbers (IBAN)",
        "high",
        re.compile(r"\b[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}\b"),
    ),
    "ip_address": (
        "IP addresses (IPv4)",
        "medium",
        re.compile(
            r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
            r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
        ),
    ),
    "uuid": (
        "UUID/GUID identifiers",
        "medium",
        re.compile(
            r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}"
            r"-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
        ),
    ),
    "date_of_birth": (
        "Date of birth patterns",
        "high",
        re.compile(
            r"(?i)(?:dob|date[\s_-]?of[\s_-]?birth|birth[\s_-]?date|birthdate)"
            r"\s*[:\-]?\s*\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4}"
        ),
    ),
    "employee_id": (
        "Employee ID patterns",
        "medium",
        re.compile(r"(?i)\bEMP[-_]?\d{4,8}\b"),
    ),
}


def keyword_to_rule(keyword: str, severity: str = "high") -> Rule:
    """Convert a plain keyword/phrase to a Rule with case-insensitive whole-word matching."""
    escaped = re.escape(keyword)
    # Use word boundaries only when keyword starts/ends with word characters
    left  = r"\b" if (keyword[0].isalnum()  or keyword[0]  == "_") else r"(?<!\w)"
    right = r"\b" if (keyword[-1].isalnum() or keyword[-1] == "_") else r"(?!\w)"
    pattern = re.compile(f"(?i){left}{escaped}{right}")
    category = keyword.lower().replace(" ", "_")[:40]
    return Rule(
        category=category,
        severity=severity,
        pattern=pattern,
        source="keyword",
        description=f'Keyword match: "{keyword}"',
    )


def build_rules(config=None) -> list[Rule]:
    """Return the active rules list based on config."""
    disabled = set(config.disabled_rules) if config else set()

    rules: list[Rule] = [r for r in _BASE_RULES if r.category not in disabled]

    if config:
        for name in config.enabled_rules:
            if name in _CATALOG_RULES and name not in disabled:
                desc, sev, pat = _CATALOG_RULES[name]
                rules.append(Rule(name, sev, pat, "catalog", desc))

        for kr in config.keyword_rules:
            cat = kr.keyword.lower().replace(" ", "_")[:40]
            if cat not in disabled:
                rules.append(keyword_to_rule(kr.keyword, kr.severity))

        for ep in config.extra_patterns:
            if ep.category not in disabled:
                rules.append(Rule(ep.category, ep.severity, ep.pattern, "custom", "Custom regex"))

    # Attach validators and code-fence skip flags
    from engine.validators import VALIDATORS
    _SKIP_CODE_FENCES = {"phone", "ssn"}
    for rule in rules:
        if rule.category in VALIDATORS and rule.validator is None:
            rule.validator = VALIDATORS[rule.category]
        if rule.category in _SKIP_CODE_FENCES:
            rule.skip_code_fences = True

    return rules
