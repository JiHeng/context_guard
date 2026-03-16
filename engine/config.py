"""
Config loader: reads config.json and returns a validated Config object.
"""
from __future__ import annotations

import difflib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_PATH = Path.home() / ".context_guard" / "config.json"
_LOCAL_CONFIG = Path(__file__).parent.parent / "config.json"


@dataclass
class PatternEntry:
    category: str
    severity: str
    pattern: re.Pattern


@dataclass
class KeywordRule:
    keyword: str
    severity: str = "high"


@dataclass
class Config:
    port: int = 8765
    enabled: bool = True
    disabled_rules: list[str] = field(default_factory=list)
    enabled_rules: list[str] = field(default_factory=list)
    keyword_rules: list[KeywordRule] = field(default_factory=list)
    extra_patterns: list[PatternEntry] = field(default_factory=list)
    internal_domains: list[str] = field(default_factory=list)
    openai_upstream: str = "https://api.openai.com"
    warnings: list[str] = field(default_factory=list)


def load(path: Path | None = None) -> Config:
    """Load config.json; fall back to defaults if file missing."""
    if path is None:
        if CONFIG_PATH.exists():
            path = CONFIG_PATH
        elif _LOCAL_CONFIG.exists():
            path = _LOCAL_CONFIG
        else:
            return Config()

    with open(path, encoding="utf-8") as f:
        data = json.load(f)

    cfg = Config()
    cfg.enabled = bool(data.get("enabled", True))
    cfg.port = int(data.get("port", 8765))
    cfg.disabled_rules = [str(r) for r in data.get("disabled_rules", [])]
    cfg.internal_domains = [str(d) for d in data.get("internal_domains", [])]
    cfg.openai_upstream = str(data.get("openai_upstream", "https://api.openai.com"))

    # enabled_rules: validate against known catalog names
    from engine.rules import _CATALOG_RULES
    known_names = list(_CATALOG_RULES.keys())
    for name in data.get("enabled_rules", []):
        name = str(name)
        if name in _CATALOG_RULES:
            cfg.enabled_rules.append(name)
        else:
            close = difflib.get_close_matches(name, known_names, n=1, cutoff=0.6)
            if close:
                cfg.warnings.append(
                    f'"enabled_rules" contains unknown rule "{name}". '
                    f'Did you mean "{close[0]}"?'
                )
            else:
                cfg.warnings.append(
                    f'"enabled_rules" contains unknown rule "{name}".'
                )

    # keyword_rules
    for i, kr in enumerate(data.get("keyword_rules", [])):
        kw = str(kr.get("keyword", "")).strip()
        if not kw:
            cfg.warnings.append(f"keyword_rules[{i}] missing \"keyword\" field — skipped.")
            continue
        sev = str(kr.get("severity", "high"))
        cfg.keyword_rules.append(KeywordRule(keyword=kw, severity=sev))

    # extra_patterns: warn on invalid regex instead of silently skipping
    for i, ep in enumerate(data.get("extra_patterns", [])):
        category = str(ep.get("category", "custom"))
        severity = str(ep.get("severity", "sensitive"))
        raw_pattern = str(ep.get("pattern", ""))
        try:
            compiled = re.compile(raw_pattern)
            cfg.extra_patterns.append(PatternEntry(category, severity, compiled))
        except re.error as exc:
            cfg.warnings.append(
                f'extra_patterns[{i}] has invalid regex "{raw_pattern}" — skipped. ({exc})'
            )

    return cfg
