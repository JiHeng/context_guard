# Context Guard — Privacy Proxy for Claude Code

> Let Claude Code read your files, not your secrets.

**Context Guard** selectively redacts sensitive information — such as SSNs, email addresses, phone numbers, and anything else you define — before it enters model context.

One-command installation. No custom hooks, scripts, or configuration required.

* * *

## 🚀 Quick Install

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

After installation, reload your shell to activate the `cg` command:
```bash
source ~/.bashrc   # or ~/.zshrc
```
Or simply open a new terminal tab/window.

**Then just run `claude` as normal. The proxy starts automatically.**

* * *

## 🧩 How It Works

```
Claude Code
    |  ANTHROPIC_BASE_URL=http://127.0.0.1:8765
context guard proxy  <--  scans & redacts
    |  forwarded (clean)
api.anthropic.com
```

Every outbound message is scanned against a rule set. Matches are replaced with tokens like `[REDACTED:email]` before the request reaches the API. The model sees the redacted version — your real data never leaves your machine.

* * *

## 🔒 What Gets Redacted

| Category | Rules | Default |
|----------|-------|---------|
| **Credentials** | API keys, AWS keys, tokens, JWTs, bearer tokens, private keys, env secrets, database credentials | ✅ On |
| **Personal Info** | Email addresses, phone numbers | ✅ On |
| **URL Tokens** | Tokens embedded in URLs | ✅ On |
| **Financial** | Credit cards, IBANs | ⚙️ Opt-in |
| **Identity Docs** | SSNs, Chinese national IDs, passports | ⚙️ Opt-in |
| **Network / IDs** | IP addresses, UUIDs | ⚙️ Opt-in |
| **Dates** | Dates of birth | ⚙️ Opt-in |

You can also define your own **block list** and **allow list**.

* * *

## 🛠 How-To Guide

### Manage rules with `/cg`

Context Guard is managed with `/cg` inside Claude Code (or the alternative name you picked if `/cg` was already taken). Just `/cg` followed by what you want to do.

**Want to manage it in terminal?** Just remove the `/`, and run `cg`.

**Examples:**

```
/cg block credit_card
/cg block keyword "Project Titan"
/cg unblock 10.0.0.1
/cg list
```

**Full command reference:**
```
/cg block email                    # enable a rule (redact)
/cg unblock email                  # disable a rule (stop redacting)
/cg block keyword "Project X"      # block a keyword
/cg unblock keyword "Project X"    # remove keyword
/cg block regex "PROJ-\d+"         # block a custom regex pattern
/cg unblock regex "PROJ-\d+"       # remove custom regex pattern
/cg unblock "10.0.0.1"             # allowlist a value
/cg block "10.0.0.1"               # remove from allowlist
/cg list                           # show all rules
/cg rules                          # interactive rule manager
```

* * *

### 💡 Tips

- **Custom keywords** — block specific words or phrases from being sent to the API:
  ```bash
  /cg block keyword "Project Titan"
  /cg block keyword "Confidential"
  ```
  Keywords are matched case-insensitively with word boundaries.

- **Custom regex patterns** — match structured data:
  ```
  /cg block regex "EMP-\d{6}"
  ```

- **Allowlist values** — if a legitimate value is being redacted:
  ```
  /cg unblock "user@example.com"
  ```

- **Regex allowlist** — allowlist by pattern (use interactive mode):
  ```
  /cg rules
  ```

* * *

### 📊 Check Status

```
/cg status
```

The status line in Claude Code shows the current state: `[cg: ON, 3 filtered]`, `[cg: PAUSED]`, or `[cg: OFF]`.

* * *

### ⚙️ Start and Stop the Proxy

```
/cg start       # start in background
/cg pause       # disable filtering, proxy stays up
/cg resume      # re-enable filtering
```

To stop the proxy, exit Claude Code first, then run from the terminal:
```bash
cg stop
```

* * *

### 🗑 Uninstall

From the terminal:
```bash
cg uninstall
```

## Known issues

- **Status line shows `cg: OFF` until the first message.** The status line renders before the SessionStart hook has started the proxy. After the first message, the status updates correctly.


## ❓ FAQ

**`cg` triggers an Xcode Command Line Tools install dialog on macOS**

On macOS, the system `python3` binary is a stub provided by Xcode Command Line Tools. Without the tools installed, any `cg` command triggers this prompt:

```
xcode-select: note: No developer tools were found, requesting install.
```

**Fix:** Install the Command Line Tools, then retry:

```bash
xcode-select --install
# follow the dialog, then verify:
python3 --version
cg status
```

If Xcode is installed at a non-default path:

```bash
sudo xcode-select --switch /path/to/Xcode.app
```

* * *

## ⚠️ Disclaimer

This is a personal project provided as-is, with no warranties of any kind. The author is not responsible for any damages, data loss, or security incidents arising from its use. Use at your own risk.
