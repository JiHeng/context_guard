# Context Guard

> Let Claude Code read your files, not your secrets.

Context Guard selectively redacts sensitive information—such as SSNs, email addresses, phone numbers, and anything else you define—before it enters model context.

One-command installation and set up in Claude. No custom hooks, scripts, configuration.

## Quick install

**macOS / Linux / WSL:**

```bash
curl -fsSL https://raw.githubusercontent.com/JiHeng/context_guard/main/install-remote.sh | bash
```

To install a specific version:
```bash
VERSION=0.0.1 curl -fsSL https://raw.githubusercontent.com/JiHeng/context_guard/main/install-remote.sh | bash
```

The installer:
1. Copies files to `~/.context_guard/`
2. Adds a `cg` shell function and sets `ANTHROPIC_BASE_URL` in your shell RC
3. Installs a `/cg` slash command and status line in Claude Code
4. Registers session hooks so the proxy starts/stops automatically

After installation, reload your shell to activate:
```bash
source ~/.bashrc   # or ~/.zshrc
```

**Then just run `claude` as normal. The proxy starts automatically.**

## How it works

```
Claude Code
    |  ANTHROPIC_BASE_URL=http://127.0.0.1:8765
context guard proxy  <--  scans & redacts
    |  forwarded (clean)
api.anthropic.com
```

Every outbound message is scanned against a rule set. Matches are replaced with tokens like `[REDACTED:email]` before the request reaches the API. The model sees the redacted version — your real data never leaves your machine.

## What gets redacted

**On by default:** API keys, AWS keys, tokens, JWTs, bearer tokens, private keys, env secrets, database credentials, email addresses, phone numbers, URL tokens.

**Available to enable:** Credit cards, SSNs, Chinese national IDs, passports, IBANs, IP addresses, UUIDs, dates of birth.

You can also define your own deny and allow list.

## How-to guide

### Manage rules with `/cg`

Context Guard is managed with `/cg` inside Claude Code (or the alternative name you picked if `/cg` was already taken). Just `/cg` followed by what you want to do.

**Want to manage it in terminal?** Just remove the `/`, and run `cg`

**Examples**

```
/cg enable credit card detection
/cg add keyword Project Titan
/cg allow 10.0.0.1
/cg show rules
```

**Full command reference:**
```
/cg rules                          # interactive rule manager
/cg rules list                     # show all rules
/cg rules enable credit_card       # enable a rule
/cg rules disable email            # disable a rule
/cg rules add keyword "Project X"  # block a keyword
/cg rules remove keyword "Project X"
/cg rules allow "10.0.0.1"         # allowlist a value
/cg rules deny "10.0.0.1"          # remove from allowlist
/cg rules add pattern "internal_id" "PROJ-\d+"  # custom regex
```

**Add custom keyword rules**

Block specific words or phrases from being sent to the API:

```bash
/cg rules add keyword "Project Titan"
/cg rules add keyword "Confidential"
```

Keywords are matched case-insensitively with word boundaries.

**Add custom regex patterns**

```
/cg rules add pattern "employee_id" "EMP-\d{6}"
```

**Allowlist values**

If a legitimate value is being redacted, add it to the allowlist:

```
/cg rules allow "alice@yourcompany.com"
```

Regex allowlist entries:
```
/cg rules allow "re:.*@yourcompany\.com"
```


### Check status

```
/cg status
```

The status line in Claude Code also shows the current state: `[cg: ON, 3 filtered]`, `[cg: PAUSED]`, or `[cg: OFF]`.

### Start and stop the proxy

```
/cg start       # start in background
/cg pause       # disable filtering, proxy stays up
/cg resume      # re-enable filtering
```

To stop the proxy, exit Claude Code first, then run from the terminal:
```bash
cg stop
```

### Uninstall

From the terminal:
```bash
cg uninstall
```

## Disclaimer

This is a personal project provided as-is, with no warranties of any kind. The author is not responsible for any damages, data loss, or security incidents arising from its use. Use at your own risk.

