"""
Content scanner: scans text and returns a list of Finding objects.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from engine.rules import build_rules


@dataclass
class Finding:
    category: str   # "api_key", "email", ...
    severity: str   # "secret" | "sensitive"
    match: str      # full matched value (used by redactor, NOT written to logs)
    hint: str       # log-safe prefix hint, e.g. "sk-ant-ab..."


def _make_hint(match: str) -> str:
    """Return a safe prefix of the matched value for logging."""
    if len(match) <= 8:
        return match[:2] + "..."
    return match[:8] + "..."


class Detector:
    def __init__(self, rules: list | None = None):
        self._rules = rules if rules is not None else build_rules()

    def scan(self, text: str) -> list[Finding]:
        findings = []
        seen_spans = []  # track (start, end) to avoid duplicate overlapping matches

        for rule in self._rules:
            category, severity, pattern = rule.category, rule.severity, rule.pattern
            for m in pattern.finditer(text):
                start, end = m.start(), m.end()
                # skip if this span is already covered by a previous match
                overlapping = any(s <= start < e or s < end <= e for s, e in seen_spans)
                if overlapping:
                    continue
                matched = m.group(0)
                # Structural validator
                if rule.validator and not rule.validator(matched, text, m):
                    continue
                seen_spans.append((start, end))
                findings.append(Finding(
                    category=category,
                    severity=severity,
                    match=matched,
                    hint=_make_hint(matched),
                ))

        return findings
