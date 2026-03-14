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
| `rules`    | `python3 ~/.context_guard/cg rules list` |
| `rules ...`| `python3 ~/.context_guard/cg rules ...` (pass all sub-arguments) |
| `update`   | `python3 ~/.context_guard/cg update` |
| `no-guard`   | Tell the user: `cg no-guard` runs Claude without the proxy — use it from the shell, not from within Claude Code. |
| `uninstall`  | `python3 ~/.context_guard/cg uninstall` — **warn the user first** that this will completely remove context guard (proxy, shell config, Claude hooks). Only proceed if they confirm. |

## Natural language rule configuration

If `$ARGUMENTS` does not match any subcommand above but expresses a rule-configuration intent, interpret the user's intent and translate it into the corresponding `cg rules` command.

Examples:
- "allow 12345" → `python3 ~/.context_guard/cg rules allow "12345"`
- "deny 12-34" → `python3 ~/.context_guard/cg rules deny "12-34"`
- "enable credit card detection" → `python3 ~/.context_guard/cg rules enable credit_card`
- "disable email detection" → `python3 ~/.context_guard/cg rules disable email`
- "add keyword Project Titan" → `python3 ~/.context_guard/cg rules add keyword "Project Titan"`
- "remove keyword Project Titan" → `python3 ~/.context_guard/cg rules remove keyword "Project Titan"`
- "show rules" / "list rules" → `python3 ~/.context_guard/cg rules list`
- "add pattern internal_id PROJ-\d+" → `python3 ~/.context_guard/cg rules add pattern "internal_id" "PROJ-\d+"`

Show the command output to the user after execution.

If the subcommand is not in the table above and does not express a rule-configuration intent, show the list of available subcommands.

## Current proxy state

```
$(!python3 ~/.context_guard/cg status 2>&1)
```
