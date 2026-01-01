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
	// Node.js inline execution
	regexp.MustCompile(`(?i)^node\s+(-e|--eval|--print|-p)\b`),
	regexp.MustCompile(`(?i)^node\s+.*\s+(-e|--eval|--print|-p)\b`),

	// Python inline execution
	regexp.MustCompile(`(?i)^python[23]?\s+(-c|--command)\b`),
	regexp.MustCompile(`(?i)^python[23]?\s+.*\s+(-c|--command)\b`),

	// Ruby inline execution
	regexp.MustCompile(`(?i)^ruby\s+(-e|--execute)\b`),
	regexp.MustCompile(`(?i)^ruby\s+.*\s+(-e|--execute)\b`),

	// Perl inline execution
	regexp.MustCompile(`(?i)^perl\s+(-e|--execute|-E)\b`),
	regexp.MustCompile(`(?i)^perl\s+.*\s+(-e|--execute|-E)\b`),

	// PHP inline execution
	regexp.MustCompile(`(?i)^php\s+(-r|--run)\b`),
	regexp.MustCompile(`(?i)^php\s+.*\s+(-r|--run)\b`),

	// Lua inline execution
	regexp.MustCompile(`(?i)^lua\s+-e\b`),

	// Deno inline execution
	regexp.MustCompile(`(?i)^deno\s+(eval|run\s+-e)\b`),

	// Bun inline execution
	regexp.MustCompile(`(?i)^bun\s+(-e|--eval)\b`),

	// awk/gawk/mawk/nawk - can access env via ENVIRON["VAR"]
	// Any awk with inline program is suspicious
	regexp.MustCompile(`(?i)^[gmnl]?awk\s+'`),
	regexp.MustCompile(`(?i)^[gmnl]?awk\s+"`),
	regexp.MustCompile(`(?i)^[gmnl]?awk\s+-f`), // awk script file
	regexp.MustCompile(`\bENVIRON\s*\[`),       // awk's ENVIRON array

	// sed with -e can execute commands (limited but possible)
	regexp.MustCompile(`(?i)^sed\s+.*-e\s*'`),
	regexp.MustCompile(`(?i)^sed\s+.*-e\s*"`),

	// Generic eval patterns in arguments
	regexp.MustCompile(`\beval\s*\(`),
	regexp.MustCompile(`\bexec\s*\(`),
	regexp.MustCompile(`\bFunction\s*\(`),
}

// suspiciousCommands are exact command names that are suspicious
var suspiciousCommands = map[string]bool{
	"env":      true,
	"printenv": true,
	"export":   true,
	"set":      true,
}

// IsSuspicious checks if a command might expose secrets
func IsSuspicious(args []string) (bool, string) {
	if len(args) == 0 {
		return false, ""
	}

	// Check exact command name
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

	return false, ""
}

// commonSafeCommands are commands that are typically safe
// even though they might match some patterns
var commonSafeCommands = map[string]bool{
	"npm":      true,
	"yarn":     true,
	"pnpm":     true,
	"bun":      true,
	"node":     true,
	"python":   true,
	"python3":  true,
	"pip":      true,
	"pip3":     true,
	"go":       true,
	"cargo":    true,
	"rustc":    true,
	"make":     true,
	"cmake":    true,
	"gcc":      true,
	"clang":    true,
	"ruby":     true,
	"bundle":   true,
	"gem":      true,
	"docker":   true,
	"kubectl":  true,
	"terraform": true,
	"git":      true,
	"curl":     true,
	"wget":     true,
	"grep":     true,
	"find":     true,
	"ls":       true,
	"cat":      true,
	"less":     true,
	"more":     true,
	"head":     true,
	"tail":     true,
	"vim":      true,
	"nvim":     true,
	"nano":     true,
	"code":     true,
	"pytest":   true,
	"jest":     true,
	"mocha":    true,
	"rspec":    true,
}
