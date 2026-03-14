"""
Allowlist: skip redaction for whitelisted exact strings or regex patterns.
Loaded from ~/.context_guard/allow.txt at startup.

Format (one entry per line):
  exact string      — literal match skips redaction
  re:<pattern>      — regex match skips redaction
  # comment lines and blank lines are ignored
"""

import re
from pathlib import Path

ALLOW_PATH = Path.home() / ".context_guard" / "allow.txt"


class Allowlist:
    def __init__(self, path: Path = ALLOW_PATH):
        self._exact: set[str] = set()
        self._patterns: list[re.Pattern] = []
        if path.exists():
            self._load(path)

    def _load(self, path: Path) -> None:
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if line.startswith("re:"):
                    try:
                        self._patterns.append(re.compile(line[3:]))
                    except re.error:
                        pass  # silently skip invalid regex
                else:
                    self._exact.add(line)

    def is_allowed(self, text: str) -> bool:
        """Return True if this text should NOT be redacted."""
        if text in self._exact:
            return True
        return any(p.search(text) for p in self._patterns)

    def __len__(self) -> int:
        return len(self._exact) + len(self._patterns)
