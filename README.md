# alex

> Keep secrets out of AI agent scope

alex stores secrets separately and injects them only when running commands, keeping them invisible to AI coding assistants.

## The Problem

AI coding assistants (Claude Code, GitHub Copilot, Cursor, etc.) have access to:
- Your shell environment variables
- Files in your project (including `.env`)
- Command output

This means your secrets are exposed:

```bash
$ cat .env
DATABASE_URL=postgres://user:password@prod.db.com/myapp

$ echo $STRIPE_KEY
sk_live_xxxxxxxxxxxxx
```

The AI can see all of this.

## The Solution

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

## Installation

```bash
curl -fsSL https://raw.githubusercontent.com/portdeveloper/alex/main/install.sh | sh
```

### Other Methods

```bash
# With Go installed
go install github.com/portdeveloper/alex@latest

# Build from source
git clone https://github.com/portdeveloper/alex.git
cd alex && go build -o alex . && sudo mv alex /usr/local/bin/
```

## Usage

### Store a secret

```bash
# Secrets are stored per-project (identified by git remote URL)
alex set DATABASE_URL "postgres://user:pass@host/db"
alex set STRIPE_KEY "sk_live_xxxxx"

# Prompt for value (doesn't appear in shell history)
alex set API_KEY

# Hide input while typing
alex set --hidden PASSWORD

# Store globally for secrets shared across projects (~/.alex/)
alex set --global OPENAI_KEY "sk-xxx"
```

### List secrets

```bash
alex list

# Output shows both project and global secrets:
# GLOBAL:
#   NAME                         UPDATED
#   ----                         -------
#   OPENAI_KEY                   2 hours ago
#
# PROJECT:
#   NAME                         UPDATED
#   ----                         -------
#   DATABASE_URL                 just now
#
# 2 secret(s) stored (1 global, 1 project)
```

### Run a command with secrets

```bash
alex run npm start
alex run pytest
alex run cargo run
alex run docker-compose up

# Output shows which secrets are used:
# Using 1 global, 1 project secret(s)
```

Project secrets override global secrets with the same name.

### Remove a secret

```bash
alex unset DATABASE_URL           # Remove from project
alex unset --global OPENAI_KEY    # Remove from global
```

## Security

### How It Works

1. Project is identified by **git remote URL** (survives moves/renames)
2. Falls back to git root path if no remote (note: secrets won't survive moving the project)
3. Secrets are stored encrypted in `~/.alex/projects/<hash>/secrets.enc` (project) or `~/.alex/secrets.enc` (global)
4. **No secrets in your repo** - everything is stored in `~/.alex/`
5. Encryption uses [age](https://age-encryption.org/) with a key derived from your machine ID
6. When you run `alex run <command>`, both project and global secrets are merged and injected
7. Project secrets override global secrets with the same name
8. Your shell never has the secrets - only the subprocess does

> **Tip:** For portable project secrets that survive moves, add a git remote: `git remote add origin <url>`

### Suspicious Command Detection

Commands that could expose secrets trigger a confirmation prompt:

```bash
$ alex run env
⚠ Warning: This command displays environment variables
Command: env

Allow this command? [y/N]
```

AI agents cannot answer interactive prompts, so they cannot extract secrets this way.

Blocked patterns include:
- `env`, `printenv`, `export`, `set`
- `sh -c`, `bash -c` (shell commands)
- Variable expansion (`$VAR`, `${VAR}`)
- Language-specific env access (`process.env`, `os.environ`)

### What's Protected

| Threat | Protection |
|--------|------------|
| AI reads `.env` file | ✓ No `.env` file needed |
| AI reads secrets file | ✓ Secrets stored outside repo in `~/.alex/` |
| AI runs `echo $SECRET` | ✓ Secrets not in shell env |
| AI runs `env` | ✓ Secrets not in shell env |
| AI runs `alex run env` | ✓ Interactive prompt blocks |

### Encryption Key

By default, alex derives an encryption key from your machine's unique identifier:
- **macOS**: Hardware UUID from `ioreg`
- **Linux**: `/etc/machine-id`

This means:
- No passphrase needed for daily use
- Secrets are tied to your machine
- Copying `~/.alex/secrets.enc` to another machine won't work

For additional security, use a passphrase:

```bash
alex set --passphrase DATABASE_URL "postgres://..."
alex run --passphrase npm start
```

## Pairing with Claude Code Sandbox

For maximum protection, use alex with Claude Code's sandbox mode:

```bash
# Enable sandbox in Claude Code
/sandbox

# Now Claude Code has:
# - File system: restricted to current repo
# - Network: allowlisted domains only
# - Environment: no secrets (thanks to alex)
```

This combination provides:
1. **alex**: Secrets not visible to AI
2. **Sandbox**: AI can't exfiltrate even if it finds secrets

## Commands

| Command | Description |
|---------|-------------|
| `alex set KEY [VALUE]` | Store a secret |
| `alex unset KEY` | Remove a secret |
| `alex list` | List stored secrets (names only) |
| `alex import FILE` | Import secrets from .env file |
| `alex run COMMAND` | Run command with secrets injected |

### Flags

| Flag | Commands | Description |
|------|----------|-------------|
| `--global`, `-g` | set, unset, import | Use global scope (~/.alex/) instead of project |
| `--passphrase` | all | Use passphrase instead of machine ID |
| `--hidden` | set | Hide input when prompting |
| `--prefix` | import | Only import vars with this prefix |
| `--force`, `-f` | run | Skip suspicious command confirmation |

## Migration from .env

```bash
# Import all secrets from .env (into project scope)
alex import .env

# Or import only specific prefixes
alex import .env --prefix DB_

# Verify your app works
alex run npm start

# Delete .env - secrets are now safely stored outside the repo
rm .env
```

## Troubleshooting

### Secrets disappeared after moving project

If your project doesn't have a git remote, secrets are tied to the project's path. Moving the project breaks this link.

**Fix:** Add a git remote, then re-import your secrets:
```bash
git remote add origin git@github.com:you/project.git
alex import .env
```

### "secret not found" error

The secret wasn't stored. Check `alex list` to see stored secrets.

### "opening secret store" error

The secrets file may be corrupted or encrypted with a different key.

If you used `--passphrase` to store secrets, you need `--passphrase` to access them.

If you're on a different machine, secrets won't decrypt (tied to machine ID).

### Command not running with secrets

Make sure you're using `alex run`:

```bash
# Wrong - secrets not injected
npm start

# Right - secrets injected
alex run npm start
```

## Contributing

Contributions welcome! Please open an issue or a discussion.

## License

MIT
