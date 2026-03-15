"""
Local audit logger. Records redaction events without storing raw sensitive data.
"""

import datetime
from pathlib import Path


class AuditLogger:
    LOG_DIR = Path.home() / ".context_guard"

    def __init__(self):
        self.LOG_DIR.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def log_path_for_date(date: datetime.date | None = None) -> Path:
        if date is None:
            date = datetime.date.today()
        return AuditLogger.LOG_DIR / f"audit-{date.isoformat()}.log"

    def log(self, source: str, categories: list[str]) -> None:
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        if categories:
            cats_str = ", ".join(categories)
            line = f"{timestamp} | {source} | redacted | {cats_str}\n"
        else:
            line = f"{timestamp} | {source} | clean\n"

        with open(self.log_path_for_date(), "a", encoding="utf-8") as f:
            f.write(line)
