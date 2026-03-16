"""
MessageFilter: traverses Anthropic API request payload and redacts all text content.
"""
from __future__ import annotations

from engine.redactor import Redactor


class MessageFilter:
    def __init__(self, redactor: Redactor | None = None):
        self._redactor = redactor or Redactor()

    def process(self, payload: dict) -> tuple[dict, list[str], list[tuple[str, str]]]:
        """
        Walk all text fields in messages and system prompt, redact in place.
        Returns (modified_payload, list_of_hit_categories, list_of_(before, after)_diffs).
        """
        all_categories: list[str] = []
        all_diffs: list[tuple[str, str]] = []

        # Redact system prompt if present
        if isinstance(payload.get("system"), str):
            original = payload["system"]
            redacted, cats = self._redactor.redact(original)
            payload["system"] = redacted
            all_categories.extend(cats)
            if cats:
                all_diffs.append((original, redacted))

        for msg in payload.get("messages", []):
            cats, diffs = self._process_content(msg)
            all_categories.extend(cats)
            all_diffs.extend(diffs)

        # Deduplicate
        seen = set()
        unique = []
        for c in all_categories:
            if c not in seen:
                seen.add(c)
                unique.append(c)

        return payload, unique, all_diffs

    def _process_content(self, msg: dict) -> tuple[list[str], list[tuple[str, str]]]:
        content = msg.get("content", "")
        cats: list[str] = []
        diffs: list[tuple[str, str]] = []

        if isinstance(content, str):
            original = content
            redacted, c = self._redactor.redact(original)
            msg["content"] = redacted
            cats.extend(c)
            if c:
                diffs.append((original, redacted))
            return cats, diffs

        if not isinstance(content, list):
            return cats, diffs

        for block in content:
            if not isinstance(block, dict):
                continue

            btype = block.get("type")

            if btype == "text":
                original = block.get("text", "")
                redacted, c = self._redactor.redact(original)
                block["text"] = redacted
                cats.extend(c)
                if c:
                    diffs.append((original, redacted))

            elif btype == "tool_result":
                tr = block.get("content", "")
                if isinstance(tr, str):
                    original = tr
                    redacted, c = self._redactor.redact(original)
                    block["content"] = redacted
                    cats.extend(c)
                    if c:
                        diffs.append((original, redacted))
                elif isinstance(tr, list):
                    for tb in tr:
                        if isinstance(tb, dict) and tb.get("type") == "text":
                            original = tb.get("text", "")
                            redacted, c = self._redactor.redact(original)
                            tb["text"] = redacted
                            cats.extend(c)
                            if c:
                                diffs.append((original, redacted))

        return cats, diffs
