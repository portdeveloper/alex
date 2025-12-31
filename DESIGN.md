# alex - Keep Secrets Out of AI Agent Scope

> Run commands with secrets that AI agents can't see.

## The Problem

AI coding assistants (Claude Code, GitHub Copilot, Cursor, etc.) have access to:
- Your shell environment variables
- Files in your project (including `.env`)
- Command output

This means your secrets are exposed:
```bash
$ cat .env
DATABASE_URL=postgres://user:password@prod.db.com/myapp
STRIPE_KEY=sk_live_xxxxxxxxxxxxx

$ echo $OPENAI_API_KEY
sk-xxxxxxxxxxxxxxxxxxxxxxxx
```

The AI can see all of this.

## The Solution

alex stores secrets separately and injects them only when running commands:

```bash
# Your shell - AI sees nothing
$ echo $DATABASE_URL
(empty)

$ cat .env
cat: .env: No such file or directory

# Run your app - secrets injected
$ alex run npm start
Connected to database ✓
Server running on :3000
```

## How It Works

```
┌─────────────────────────────────────────────────────────────┐
│                                                             │
│  ~/.alex/secrets.enc                                        │
│  (encrypted, AI can't read)                                 │
│                                                             │
│         │                                                   │
│         ▼                                                   │
│  ┌─────────────┐      ┌─────────────────────────────────┐  │
│  │ alex run    │ ───► │ subprocess with secrets in env  │  │
│  └─────────────┘      └─────────────────────────────────┘  │
│         │                        │                          │
│         │                        ▼                          │
│   AI's shell              npm/python/cargo                  │
│   (no secrets)            (has secrets)                     │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## Commands

### Set a secret
```bash
$ alex set DATABASE_URL "postgres://user:pass@host/db"
✓ Secret 'DATABASE_URL' saved

$ alex set STRIPE_KEY "sk_live_xxxxx"
✓ Secret 'STRIPE_KEY' saved
```

### List secrets (names only, values hidden)
```bash
$ alex list
DATABASE_URL    (set 2 hours ago)
STRIPE_KEY      (set 2 hours ago)
OPENAI_API_KEY  (set 5 days ago)
```

### Run a command with secrets
```bash
$ alex run npm start
$ alex run pytest
$ alex run cargo run
$ alex run python manage.py runserver
```

### Remove a secret
```bash
$ alex unset DATABASE_URL
✓ Secret 'DATABASE_URL' removed
```

### Import from .env file (then delete the file)
```bash
$ alex import .env
Imported 5 secrets from .env
Delete .env file? [Y/n] y
✓ .env deleted
```

### Export (for debugging, requires confirmation)
```bash
$ alex export
⚠ This will display all secrets in plain text.
Type 'yes' to continue: yes

DATABASE_URL=postgres://...
STRIPE_KEY=sk_live_...
```

---

## Security Model

### Protected Against

| Threat | Protection |
|--------|------------|
| AI reads `.env` file | No `.env` file exists |
| AI runs `echo $SECRET` | Secrets not in shell env |
| AI runs `env` command | Secrets not in shell env |
| AI reads secrets file | File is encrypted |
| AI runs `alex run env` | Interactive prompt required |

### Interactive Prompts for Suspicious Commands

Certain commands could expose secrets in their output. alex requires human confirmation:

```bash
$ alex run env
⚠ This command may expose secrets. Allow? [y/N]

$ alex run printenv
⚠ This command may expose secrets. Allow? [y/N]

$ alex run sh -c "..."
⚠ Shell commands may expose secrets. Allow? [y/N]
```

The AI cannot answer these prompts. A human must approve.

### Blocked Command Patterns

These patterns trigger interactive confirmation:
- `env` (standalone)
- `printenv`
- `export` (standalone)
- `sh -c`, `bash -c`, `zsh -c`
- Commands containing `$` (variable expansion)
- Commands containing `process.env`, `os.environ`, `ENV[`

### NOT Protected Against

alex does not protect against:
- AI constructing elaborate ways to print env vars in allowed commands
- Malicious code in dependencies that exfiltrates secrets
- AI with direct network access sending secrets elsewhere


---

## Storage

### Location
```
~/.alex/
├── config.json      # Settings
├── secrets.enc      # Encrypted secrets
└── audit.log        # Command history (optional)
```

### Encryption

Secrets are encrypted using [age](https://age-encryption.org/):
- Modern, simple encryption
- Key derived from machine-specific identifier + optional passphrase
- No secrets ever stored in plain text

### Config File
```json
{
  "version": 1,
  "require_passphrase": false,
  "audit_logging": true,
  "blocked_patterns": [
    "^env$",
    "^printenv",
    "^export$",
    "\\$\\{?[A-Z_]+\\}?"
  ]
}
```

---

## Project Scoping

alex supports project-specific secrets:

```bash
# Global secrets (available everywhere)
$ alex set ANTHROPIC_API_KEY "sk-ant-xxx"

# Project secrets (only in this directory tree)
$ alex set --project DATABASE_URL "postgres://..."

# List shows scope
$ alex list
ANTHROPIC_API_KEY   global   (set 5 days ago)
DATABASE_URL        project  (set 2 hours ago)
```

Project secrets are stored in `.alex/secrets.enc` in the project root (gitignored).

---

## Installation

```bash
# macOS
brew install alex

# Linux
curl -fsSL https://get.alex.dev | sh

# From source
go install github.com/portdeveloper/alex@latest
```

---

## Usage Examples

### Node.js / npm
```bash
$ alex set DATABASE_URL "postgres://localhost/myapp"
$ alex set STRIPE_KEY "sk_test_xxx"

$ alex run npm start
$ alex run npm test
```

### Python
```bash
$ alex set DJANGO_SECRET_KEY "xxx"
$ alex set DATABASE_URL "postgres://localhost/myapp"

$ alex run python manage.py runserver
$ alex run pytest
```

### Docker
```bash
$ alex run docker-compose up
# Secrets passed as env vars to containers
```

### Arbitrary commands
```bash
$ alex run -- ./my-script.sh --flag value
```

---

## Migrating from .env

```bash
# 1. Import existing .env
$ alex import .env
Imported 8 secrets

# 2. Verify everything works
$ alex run npm start

# 3. Delete .env and update .gitignore
$ rm .env
$ echo ".alex/" >> .gitignore

# 4. Update README for teammates
```

---

## CI/CD

alex is designed for local development. For CI/CD:
- Use your CI's native secrets management
- Or export secrets for CI: `alex export > .env` (in secure CI environment)

---

## FAQ

### Why not just use .env files?
AI agents can read files in your project directory, including `.env`.

### Why not use 1Password CLI / Doppler / etc?
Those work great! alex is simpler and purpose-built for the AI agent threat model.

### Does this work with [AI Tool]?
Yes. alex works with any AI coding assistant that runs in your terminal:
- Claude Code
- GitHub Copilot
- Cursor
- Aider
- Continue
- etc.

### Can I use this without AI tools?
Yes! alex is useful anytime you want to keep secrets out of your shell environment.

---

## Project Structure

```
alex/
├── cmd/
│   ├── root.go          # CLI setup
│   ├── set.go           # alex set
│   ├── unset.go         # alex unset
│   ├── list.go          # alex list
│   ├── run.go           # alex run
│   ├── import.go        # alex import
│   └── export.go        # alex export
├── internal/
│   ├── secrets/
│   │   ├── store.go     # Encrypted storage
│   │   ├── encrypt.go   # age encryption
│   │   └── project.go   # Project-scoped secrets
│   ├── runner/
│   │   ├── exec.go      # Command execution
│   │   └── filter.go    # Suspicious command detection
│   └── config/
│       └── config.go    # Configuration
├── main.go
├── go.mod
├── go.sum
├── README.md
├── LICENSE              # MIT
└── .goreleaser.yaml     # Release automation
```

---

## Implementation Notes

### Command Filtering

```go
var suspiciousPatterns = []string{
    `^env$`,
    `^printenv`,
    `^export$`,
    `set\s*$`,
    `\bprocess\.env\b`,
    `\bos\.environ\b`,
    `\bENV\[`,
    `\$\{?[A-Z_]+\}?`,
    `^sh\s+-c`,
    `^bash\s+-c`,
    `^zsh\s+-c`,
}

func isSuspicious(cmd string) bool {
    for _, pattern := range suspiciousPatterns {
        if regexp.MustCompile(pattern).MatchString(cmd) {
            return true
        }
    }
    return false
}
```

### Encryption with age

```go
import "filippo.io/age"

func encrypt(secrets map[string]string, passphrase string) ([]byte, error) {
    recipient, err := age.NewScryptRecipient(passphrase)
    // ...
}

func decrypt(data []byte, passphrase string) (map[string]string, error) {
    identity, err := age.NewScryptIdentity(passphrase)
    // ...
}
```

### Machine-Specific Key Derivation

If no passphrase is set, derive key from:
- macOS: Hardware UUID from `ioreg`
- Linux: `/etc/machine-id`
- Fallback: Prompt for passphrase

This means secrets are tied to the machine and can't be copied elsewhere.

---

## Roadmap

### v0.1 (MVP)
- [x] Basic set/unset/list/run commands
- [x] Encrypted local storage
- [x] Suspicious command detection
- [x] Interactive prompts

### v0.2
- [ ] Project-scoped secrets
- [ ] Import from .env
- [ ] Shell completions (bash, zsh, fish)

### v0.3
- [ ] Audit logging
- [ ] Team sharing (encrypted, via git)
- [ ] VS Code extension

### Future
- [ ] Integration with Arms Length
- [ ] Biometric unlock (Touch ID, etc.)
