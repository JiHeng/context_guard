---
allowed-tools: Bash
description: Control the context guard proxy (start/stop/pause/resume/status/rules/update/uninstall)
---

# context guard control — `/cg`

Subcommand: `$ARGUMENTS`

## Instructions

Run the matching command below. If `$ARGUMENTS` is empty, treat it as `status`.

| Subcommand | Command |
|------------|---------|
| `start`    | `python3 ~/.context_guard/cg start` |
| `stop`     | Tell the user: stopping the proxy inside Claude Code would break this session. Use `cg pause` to disable filtering, or exit Claude Code and run `cg stop` from the shell. |
| `pause`    | `python3 ~/.context_guard/cg pause` |
| `resume`   | `python3 ~/.context_guard/cg resume` |
| `status`   | `python3 ~/.context_guard/cg status` |
| `block ...`| `python3 ~/.context_guard/cg block ...` (pass all arguments) |
| `unblock ...`| `python3 ~/.context_guard/cg unblock ...` (pass all arguments) |
| `list`     | `python3 ~/.context_guard/cg list` |
| `rules`    | `python3 ~/.context_guard/cg rules list` |
| `rules ...`| `python3 ~/.context_guard/cg rules ...` (pass all sub-arguments) |
| `update`   | `python3 ~/.context_guard/cg update` |
| `no-guard`   | Tell the user: `cg no-guard` runs Claude without the proxy — use it from the shell, not from within Claude Code. |
| `uninstall`  | Tell the user: uninstall requires interactive prompts (active session warning, rules backup) — run `cg uninstall` from the terminal outside Claude Code. |

## Natural language rule configuration

If `$ARGUMENTS` does not match any subcommand above but expresses a rule-configuration intent, interpret the user's intent and translate it into the corresponding `cg block` / `cg unblock` / `cg list` command.

Examples:
- "block email" → `python3 ~/.context_guard/cg block email`
- "unblock email" → `python3 ~/.context_guard/cg unblock email`
- "block keyword Project Titan" → `python3 ~/.context_guard/cg block keyword "Project Titan"`
- "unblock keyword Project Titan" → `python3 ~/.context_guard/cg unblock keyword "Project Titan"`
- "block regex PROJ-\d+" → `python3 ~/.context_guard/cg block regex "PROJ-\d+"`
- "unblock 10.0.0.1" → `python3 ~/.context_guard/cg unblock "10.0.0.1"`
- "block 10.0.0.1" → `python3 ~/.context_guard/cg block "10.0.0.1"`
- "enable credit card detection" → `python3 ~/.context_guard/cg block credit_card`
- "disable email detection" → `python3 ~/.context_guard/cg unblock email`
- "allow 12345" → `python3 ~/.context_guard/cg unblock "12345"`
- "show rules" / "list rules" → `python3 ~/.context_guard/cg list`

Show the command output to the user after execution.

## Redacted values

The proxy may redact secrets/PII in the user's message before you see it. If the user's argument contains a `[REDACTED:…]` placeholder (e.g. `"block keyword [REDACTED:api_key]"`), you **cannot** know the original value. In this case:

1. **Do NOT run the command** — it would store the literal placeholder string, which is useless.
2. Instead, give the user the ready-to-run CLI command with `<VALUE>` in place of the redacted token and tell them to replace `<VALUE>` with the actual value and run it in their terminal.

Example — user says: `block keyword [REDACTED:api_key]`
→ Respond:
> The value was redacted by the proxy, so I can't see it. Run this in your terminal with the actual value filled in:
> ```
> cg block keyword "<VALUE>"
> ```

This applies to `block keyword`, `block regex`, `unblock`, and `block` with bare values — any command where the argument itself is a sensitive value that may have been redacted.

If the subcommand is not in the table above and does not express a rule-configuration intent, show the list of available subcommands.

## Current proxy state

```
$(!python3 ~/.context_guard/cg status 2>&1)
```
