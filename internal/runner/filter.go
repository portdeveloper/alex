package runner

import (
	"regexp"
	"strings"
)

// suspiciousPatterns are commands that could expose secrets
var suspiciousPatterns = []*regexp.Regexp{
	// Direct environment inspection
	regexp.MustCompile(`^env$`),
	regexp.MustCompile(`^printenv`),
	regexp.MustCompile(`^export$`),
	regexp.MustCompile(`^set$`),

	// Shell commands that might be used to extract env
	regexp.MustCompile(`^sh\s+-c`),
	regexp.MustCompile(`^bash\s+-c`),
	regexp.MustCompile(`^zsh\s+-c`),

	// Variable expansion patterns (both uppercase and lowercase)
	regexp.MustCompile(`\$\{?[A-Za-z_][A-Za-z0-9_]*\}?`),

	// Language-specific env access (literal patterns - can be bypassed with obfuscation)
	regexp.MustCompile(`process\.env`),
	regexp.MustCompile(`os\.environ`),
	regexp.MustCompile(`ENV\[`),
	regexp.MustCompile(`getenv\(`),

	// Commands that echo/print
	regexp.MustCompile(`^echo\s+\$`),
	regexp.MustCompile(`^printf.*\$`),
}

// codeExecutionPatterns detect inline code execution which can bypass pattern matching
// via obfuscation (e.g., process['en'+'v'], atob('ZW52'), eval, etc.)
// These are ALWAYS suspicious regardless of the code content
var codeExecutionPatterns = []*regexp.Regexp{
	// ========================================
	// EXPLICIT INTERPRETER PATTERNS (most reliable)
	// ========================================
	// Node.js
	regexp.MustCompile(`(?i)^node\s+(-e|--eval|-p|--print)\s`),
	regexp.MustCompile(`(?i)^node\s+(-e|--eval|-p|--print)$`),

	// Python
	regexp.MustCompile(`(?i)^python[23]?\s+(-c|--command)\s`),
	regexp.MustCompile(`(?i)^python[23]?\s+(-c|--command)$`),

	// Ruby
	regexp.MustCompile(`(?i)^ruby\s+(-e|--execute)\s`),

	// Perl
	regexp.MustCompile(`(?i)^perl\s+(-e|-E|--execute)\s`),

	// PHP
	regexp.MustCompile(`(?i)^php\s+(-r|--run)\s`),

	// Swift
	regexp.MustCompile(`(?i)^swift\s+(-e)\s`),

	// Lua
	regexp.MustCompile(`(?i)^lua\s+(-e)\s`),

	// Shells
	regexp.MustCompile(`(?i)^(sh|bash|zsh|dash|ksh|fish)\s+(-c)\s`),

	// Deno/Bun
	regexp.MustCompile(`(?i)^deno\s+(eval)\s`),
	regexp.MustCompile(`(?i)^bun\s+(-e|--eval)\s`),

	// ========================================
	// UNIVERSAL FLAG DETECTION (backup for unknown interpreters)
	// ========================================
	// Only -e is safe to universally block (almost always means "execute")
	// -c and -p have too many false positives (grep -c, mkdir -p, etc.)
	regexp.MustCompile(`\s+-e\s+.`),   // -e followed by anything
	regexp.MustCompile(`\s+-e'.`),     // -e'code'
	regexp.MustCompile(`\s+-e".`),     // -e"code"
	regexp.MustCompile(`\s+-E\s+.`),   // -E (perl)

	// Long form flags are unambiguous
	regexp.MustCompile(`\s+--eval\s`),
	regexp.MustCompile(`\s+--exec\s`),
	regexp.MustCompile(`\s+--execute\s`),
	regexp.MustCompile(`\s+--run\s`),
	regexp.MustCompile(`\s+--print\s`),
	regexp.MustCompile(`\s+--command\s`),

	// awk/gawk/mawk/nawk - can access env via ENVIRON["VAR"]
	// Any awk with inline program is suspicious
	regexp.MustCompile(`(?i)^[gmnl]?awk\s+'`),
	regexp.MustCompile(`(?i)^[gmnl]?awk\s+"`),
	regexp.MustCompile(`(?i)^[gmnl]?awk\s+-f`), // awk script file
	regexp.MustCompile(`\bENVIRON\s*\[`),       // awk's ENVIRON array

	// Generic eval patterns in arguments
	regexp.MustCompile(`\beval\s*\(`),
	regexp.MustCompile(`\bexec\s*\(`),
	regexp.MustCompile(`\bFunction\s*\(`),

	// Package manager script execution (runs arbitrary code from package.json/etc.)
	// These can execute ANY code defined in the project's config files
	regexp.MustCompile(`(?i)^npm\s+(run|start|test|exec|explore)\b`),
	regexp.MustCompile(`(?i)^yarn\s+(run|start|test|exec|dlx)\b`),
	regexp.MustCompile(`(?i)^pnpm\s+(run|start|test|exec|dlx)\b`),
	regexp.MustCompile(`(?i)^bun\s+(run|start|test|x)\b`),
	regexp.MustCompile(`(?i)^npx\b`),  // npx always executes packages
	regexp.MustCompile(`(?i)^bunx\b`), // bunx always executes packages
}

// suspiciousCommands are exact command names that are suspicious
var suspiciousCommands = map[string]bool{
	"env":      true,
	"printenv": true,
	"export":   true,
	"set":      true,
}

// IsSuspicious checks if a command might expose secrets
// Uses an ALLOWLIST approach: only known-safe commands pass without confirmation
func IsSuspicious(args []string) (bool, string) {
	if len(args) == 0 {
		return false, ""
	}

	// Check exact command name - these are ALWAYS blocked
	cmd := strings.ToLower(args[0])
	if suspiciousCommands[cmd] {
		return true, "This command displays environment variables"
	}

	// Check full command string against patterns
	fullCmd := strings.Join(args, " ")

	// Check for inline code execution (highest priority - these can bypass all other checks)
	for _, pattern := range codeExecutionPatterns {
		if pattern.MatchString(fullCmd) {
			return true, "This command executes inline code which could access environment variables"
		}
	}

	// Check for direct env access patterns
	for _, pattern := range suspiciousPatterns {
		if pattern.MatchString(fullCmd) {
			return true, "This command may expose environment variables"
		}
	}

	// ALLOWLIST CHECK: If command is not in the safe list, require confirmation
	// This catches ALL unknown commands (jq, custom scripts, etc.)
	if !isAllowedCommand(cmd) {
		return true, "This command is not in the allowlist and may access environment variables"
	}

	return false, ""
}

// isAllowedCommand checks if the base command is in the allowlist
func isAllowedCommand(cmd string) bool {
	// Strip path to get just the command name
	if idx := strings.LastIndex(cmd, "/"); idx >= 0 {
		cmd = cmd[idx+1:]
	}
	return allowedCommands[strings.ToLower(cmd)]
}

// allowedCommands is the ALLOWLIST of commands that can run without confirmation.
// Any command NOT in this list will require user confirmation.
// This is the primary security mechanism - we only allow known-safe commands.
var allowedCommands = map[string]bool{
	// Package managers & build tools
	"npm":       true,
	"yarn":      true,
	"pnpm":      true,
	"npx":       true,
	"bun":       true,
	"deno":      true,
	"pip":       true,
	"pip3":      true,
	"pipx":      true,
	"poetry":    true,
	"pdm":       true,
	"uv":        true,
	"go":        true,
	"cargo":     true,
	"rustup":    true,
	"bundle":    true,
	"gem":       true,
	"composer":  true,
	"maven":     true,
	"mvn":       true,
	"gradle":    true,
	"ant":       true,
	"make":      true,
	"cmake":     true,
	"ninja":     true,
	"meson":     true,
	"bazel":     true,

	// Compilers & interpreters (without inline exec flags)
	"node":      true,
	"python":    true,
	"python3":   true,
	"ruby":      true,
	"rustc":     true,
	"gcc":       true,
	"g++":       true,
	"clang":     true,
	"clang++":   true,
	"javac":     true,
	"java":      true,
	"dotnet":    true,
	"swift":     true, // swift without -e is safe (compiling)
	"swiftc":    true,
	"tsc":       true,
	"esbuild":   true,
	"vite":      true,
	"webpack":   true,
	"rollup":    true,
	"parcel":    true,

	// Version control
	"git":       true,
	"gh":        true,
	"hub":       true,
	"svn":       true,
	"hg":        true,

	// Containers & cloud
	"docker":    true,
	"podman":    true,
	"kubectl":   true,
	"helm":      true,
	"terraform": true,
	"pulumi":    true,
	"aws":       true,
	"gcloud":    true,
	"az":        true,
	"flyctl":    true,
	"vercel":    true,
	"netlify":   true,
	"railway":   true,
	"heroku":    true,

	// File operations (safe ones)
	"ls":        true,
	"cat":       true,
	"head":      true,
	"tail":      true,
	"less":      true,
	"more":      true,
	"cp":        true,
	"mv":        true,
	"rm":        true,
	"mkdir":     true,
	"rmdir":     true,
	"touch":     true,
	"chmod":     true,
	"chown":     true,
	"ln":        true,
	"find":      true,
	"grep":      true,
	"rg":        true, // ripgrep
	"fd":        true, // fd-find
	"ag":        true, // silver searcher
	"wc":        true,
	"sort":      true,
	"uniq":      true,
	"diff":      true,
	"patch":     true,
	"tar":       true,
	"zip":       true,
	"unzip":     true,
	"gzip":      true,
	"gunzip":    true,
	"bzip2":     true,
	"xz":        true,

	// Network tools
	"curl":      true,
	"wget":      true,
	"ssh":       true,
	"scp":       true,
	"rsync":     true,
	"ping":      true,
	"dig":       true,
	"nslookup":  true,
	"nc":        true,
	"netcat":    true,

	// Editors
	"vim":       true,
	"nvim":      true,
	"nano":      true,
	"emacs":     true,
	"code":      true,
	"subl":      true,

	// Testing frameworks
	"pytest":    true,
	"jest":      true,
	"mocha":     true,
	"vitest":    true,
	"rspec":     true,
	"phpunit":   true,
	"go-test":   true,

	// Linters & formatters
	"eslint":    true,
	"prettier":  true,
	"black":     true,
	"ruff":      true,
	"mypy":      true,
	"pylint":    true,
	"flake8":    true,
	"rubocop":   true,
	"gofmt":     true,
	"rustfmt":   true,
	"clippy":    true,
	"shellcheck": true,

	// Shell builtins (commonly used)
	"echo":      true,
	"printf":    true,
	"read":      true,
	"test":      true,
	"[":         true,

	// Other common dev tools
	"man":       true,
	"which":     true,
	"whereis":   true,
	"file":      true,
	"stat":      true,
	"du":        true,
	"df":        true,
	"top":       true,
	"htop":      true,
	"ps":        true,
	"kill":      true,
	"pkill":     true,
	"killall":   true,
	"date":      true,
	"cal":       true,
	"bc":        true,
	"sleep":     true,
	"true":      true,
	"false":     true,
	"yes":       true,
	"seq":       true,
	"basename":  true,
	"dirname":   true,
	"realpath":  true,
	"pwd":       true,
	"whoami":    true,
	"id":        true,
	"groups":    true,
	"uname":     true,
	"hostname":  true,
	"uptime":    true,
	"free":      true,
	"lsof":      true,
	"strace":    true,
	"time":      true,
	"xargs":     true,
	"tee":       true,
	"cut":       true,
	"tr":        true,
	"rev":       true,
	"column":    true,
	"paste":     true,
	"join":      true,
	"comm":      true,
	"cmp":       true,
	"md5sum":    true,
	"sha256sum": true,
	"base64":    true,
	"od":        true,
	"xxd":       true,
	"hexdump":   true,
}
