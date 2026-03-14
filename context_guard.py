#!/usr/bin/env python3
"""
context_guard — local API proxy that redacts PII and secrets before they
reach api.anthropic.com (and api.openai.com).

Usage:
  context_guard.py serve [PORT]       Start proxy (default port 8765)
  context_guard.py status             Show proxy status and today's stats
  context_guard.py list-rules         Show all active rules
  context_guard.py add-rule           Interactive wizard to add a new rule
  context_guard.py --redact-pipe      Read stdin, write redacted text to stdout
  context_guard.py --test [TEXT]      Scan TEXT (or stdin) and print findings
"""

import sys
import os
import json
from pathlib import Path

# Allow running from any directory by ensuring the repo root is on sys.path
_ROOT = os.path.dirname(os.path.abspath(__file__))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)


def _cmd_serve(args: list[str]) -> None:
    from engine.config import load as load_config
    from engine.allowlist import Allowlist
    from proxy.server import start, DEFAULT_PORT
    port = int(args[0]) if args else DEFAULT_PORT
    config = load_config()
    allowlist = Allowlist()
    start(port, config=config, allowlist=allowlist)


def _cmd_status() -> None:
    import datetime
    from engine.config import load as load_config
    from engine.allowlist import Allowlist
    from engine.rules import build_rules
    from proxy.server import PID_PATH
    from engine.audit import AuditLogger

    config = load_config()
    for w in config.warnings:
        print(f"⚠ Config warning: {w}", file=sys.stderr)

    allowlist = Allowlist()
    rules = build_rules(config)
    n_rules = len(rules)
    n_disabled = len(config.disabled_rules)
    n_allow = len(allowlist)

    print("[context_guard] status")

    # Check proxy liveness via PID file
    pid = None
    port = config.port
    if PID_PATH.exists():
        try:
            pid = int(PID_PATH.read_text().strip())
            os.kill(pid, 0)  # raises if process is dead
            print(f"  proxy    : running on http://127.0.0.1:{port} (pid {pid})")
        except (ProcessLookupError, PermissionError, ValueError):
            pid = None

    if pid is None:
        print("  proxy    : not running")
        print(f"  start    : python3 {os.path.abspath(__file__)} serve")

    # Rules info
    disabled_str = f" ({', '.join(config.disabled_rules)})" if config.disabled_rules else ""
    print(f"  rules    : {n_rules} active, {n_disabled} disabled{disabled_str}")
    print(f"  allowlist: {n_allow} entries")

    # Parse today's daily audit log
    log_path = AuditLogger.log_path_for_date()
    total_requests = 0
    total_redacted = 0
    category_counts: dict[str, int] = {}

    if log_path.exists():
        with open(log_path, encoding="utf-8") as f:
            for line in f:
                total_requests += 1
                parts = line.strip().split(" | ")
                if len(parts) >= 3 and parts[2].strip() == "redacted":
                    total_redacted += 1
                    if len(parts) >= 4:
                        for cat in parts[3].split(", "):
                            cat = cat.strip()
                            if cat:
                                category_counts[cat] = category_counts.get(cat, 0) + 1

    # Session count
    sessions_dir = Path.home() / ".context_guard" / "sessions"
    live_sessions = 0
    if sessions_dir.exists():
        for sf in sessions_dir.iterdir():
            try:
                spid = int(sf.name)
                os.kill(spid, 0)
                live_sessions += 1
            except (ValueError, ProcessLookupError, PermissionError):
                sf.unlink(missing_ok=True)
    print(f"  sessions : {live_sessions} active")

    cat_str = ""
    if category_counts:
        cat_str = " — " + ", ".join(f"{c}×{n}" for c, n in category_counts.items())
    print(f"  today    : {total_requests} requests — {total_redacted} redacted{cat_str}")
    print(f"  log      : {log_path}")


def _cmd_list_rules() -> None:
    from engine.config import load as load_config
    from engine.rules import build_rules, _CATALOG_RULES

    config = load_config()
    for w in config.warnings:
        print(f"⚠ Config warning: {w}", file=sys.stderr)

    rules = build_rules(config)

    # Deduplicate by (source, category) — keep first occurrence (highest-priority entry)
    seen: set[tuple[str, str]] = set()
    unique: list = []
    for r in rules:
        key = (r.source, r.category)
        if key not in seen:
            seen.add(key)
            unique.append(r)

    print(f"\nActive rules ({len(rules)}):")
    for r in unique:
        src_tag = f"[{r.source}]"
        print(f"  {src_tag:<12} {r.category:<20} {r.severity:<8} – {r.description}")

    # Show what catalog rules exist but are not enabled
    active_catalog = set(config.enabled_rules)
    available = [n for n in _CATALOG_RULES if n not in active_catalog]
    if available:
        print(f"\nAvailable (not enabled): {', '.join(available)}")
        print("  Enable with: context_guard add-rule  (or add to enabled_rules in config.json)")

    if config.disabled_rules:
        print(f"\nDisabled: {', '.join(config.disabled_rules)}")


def _get_config_path() -> Path:
    """Return the config file path to read/write, creating parent dir if needed."""
    from engine.config import CONFIG_PATH, _LOCAL_CONFIG
    if CONFIG_PATH.exists():
        return CONFIG_PATH
    if _LOCAL_CONFIG.exists():
        return _LOCAL_CONFIG
    return CONFIG_PATH  # will be created on write


def _read_config_raw(path: Path) -> dict:
    if path.exists():
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    return {}


def _write_config_raw(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.write("\n")


def _cmd_add_rule() -> None:
    from engine.rules import _CATALOG_RULES

    print("\nWhat do you want to protect?")
    print("  1. Choose from catalog  (credit cards, SSN, IDs...)")
    print("  2. Block specific keywords or phrases")
    print("  3. Advanced: enter a regex pattern")

    choice = input("\n> ").strip()

    config_path = _get_config_path()
    data = _read_config_raw(config_path)

    if choice == "1":
        catalog_items = list(_CATALOG_RULES.items())
        print("\nAvailable rules:")
        for i, (name, (desc, sev, _)) in enumerate(catalog_items, 1):
            print(f"  [{i}] {name:<20} – {desc}")

        sel = input("\n> ").strip()
        try:
            idx = int(sel) - 1
            if idx < 0:
                raise IndexError
            name, (desc, sev, _) = catalog_items[idx]
        except (ValueError, IndexError):
            print("Invalid selection.")
            return

        enabled_rules: list = data.get("enabled_rules", [])
        if name in enabled_rules:
            print(f"\n{name} is already enabled.")
            return
        enabled_rules.append(name)
        data["enabled_rules"] = enabled_rules
        _write_config_raw(config_path, data)
        print(f"\nAdded: {name}  →  {config_path} updated. Restart context_guard to apply.")

    elif choice == "2":
        kw = input("\nEnter keyword or phrase: ").strip()
        if not kw:
            print("No keyword entered.")
            return

        kw_rules: list = data.get("keyword_rules", [])
        kw_rules.append({"keyword": kw})
        data["keyword_rules"] = kw_rules
        _write_config_raw(config_path, data)
        print(f'\nAdded keyword: "{kw}"  →  {config_path} updated. Restart context_guard to apply.')

    elif choice == "3":
        raw = input("\nEnter regex pattern: ").strip()
        if not raw:
            print("No pattern entered.")
            return
        import re
        try:
            re.compile(raw)
        except re.error as exc:
            print(f"Invalid regex: {exc}")
            return

        category = input("Category name (e.g. my_secret) [custom]: ").strip() or "custom"

        extra: list = data.get("extra_patterns", [])
        extra.append({"category": category, "pattern": raw})
        data["extra_patterns"] = extra
        _write_config_raw(config_path, data)
        print(f"\nAdded pattern: {category}  →  {config_path} updated. Restart context_guard to apply.")

    else:
        print("Invalid choice.")


def _cmd_redact_pipe() -> None:
    from engine.config import load as load_config
    from engine.allowlist import Allowlist
    from engine.rules import build_rules
    from engine.redactor import Redactor
    config = load_config()
    allowlist = Allowlist()
    rules = build_rules(config)
    text = sys.stdin.read()
    redacted, cats = Redactor(rules=rules, allowlist=allowlist).redact(text)
    sys.stdout.write(redacted)
    if cats:
        print(f"\n[context_guard] redacted: {', '.join(cats)}", file=sys.stderr)


def _cmd_test(args: list[str]) -> None:
    from engine.config import load as load_config
    from engine.rules import build_rules
    from engine.detector import Detector
    config = load_config()
    rules = build_rules(config)
    if args:
        text = " ".join(args)
    else:
        text = sys.stdin.read()

    findings = Detector(rules=rules).scan(text)
    if findings:
        for f in findings:
            print(f"  {f.category} ({f.severity}): {f.hint}")
    else:
        print("  clean")


def main() -> None:
    argv = sys.argv[1:]

    if not argv or argv[0] == "serve":
        _cmd_serve(argv[1:])
    elif argv[0] == "status":
        _cmd_status()
    elif argv[0] == "list-rules":
        _cmd_list_rules()
    elif argv[0] == "add-rule":
        _cmd_add_rule()
    elif argv[0] == "--redact-pipe":
        _cmd_redact_pipe()
    elif argv[0] == "--test":
        _cmd_test(argv[1:])
    else:
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
