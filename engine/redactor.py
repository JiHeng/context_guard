"""
Redactor: replaces detected sensitive values with [REDACTED:category].
Supports allowlist to skip redaction for whitelisted values.
"""
from __future__ import annotations

from engine.rules import build_rules


class Redactor:
    def __init__(self, rules: list | None = None, allowlist=None):
        self._rules = rules if rules is not None else build_rules()
        self._allowlist = allowlist  # optional Allowlist instance

    def redact(self, text: str) -> tuple[str, list[str]]:
        """
        Returns (redacted_text, list_of_hit_categories).
        Each matched value is replaced with [REDACTED:category].
        Allowlisted values are left unchanged.
        """
        categories_hit = []

        for rule in self._rules:
            category, pattern = rule.category, rule.pattern

            def _replace(m, _rule=rule, cat=category):
                matched = m.group(0)
                if self._allowlist and self._allowlist.is_allowed(matched):
                    return matched
                # Structural validator
                if _rule.validator and not _rule.validator(matched, text, m):
                    return matched
                categories_hit.append(cat)
                return f"[REDACTED:{cat}]"

            new_text = pattern.sub(_replace, text)
            if new_text != text:
                text = new_text

        # Deduplicate categories while preserving order
        seen = set()
        unique_cats = []
        for c in categories_hit:
            if c not in seen:
                seen.add(c)
                unique_cats.append(c)

        return text, unique_cats
