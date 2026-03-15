"""
OpenAIFilter: traverses OpenAI /v1/chat/completions request payload and redacts text content.

OpenAI message content can be:
  - a plain string: {"role": "user", "content": "..."}
  - a list of blocks: {"role": "user", "content": [{"type": "text", "text": "..."}]}
"""

from engine.redactor import Redactor


class OpenAIFilter:
    def __init__(self, redactor: Redactor | None = None):
        self._redactor = redactor or Redactor()

    def process(self, payload: dict) -> tuple[dict, list[str], list[tuple[str, str]]]:
        """
        Walk all text fields in messages, redact in place.
        Returns (modified_payload, list_of_hit_categories, list_of_(before, after)_diffs).
        """
        all_categories: list[str] = []
        all_diffs: list[tuple[str, str]] = []

        for msg in payload.get("messages", []):
            cats, diffs = self._process_message(msg)
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

    def _process_message(self, msg: dict) -> tuple[list[str], list[tuple[str, str]]]:
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
            if block.get("type") == "text":
                original = block.get("text", "")
                redacted, c = self._redactor.redact(original)
                block["text"] = redacted
                cats.extend(c)
                if c:
                    diffs.append((original, redacted))

        return cats, diffs
