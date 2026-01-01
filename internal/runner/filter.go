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
	// UNIVERSAL FLAG DETECTION (catches ALL languages)
	// ========================================
	// -e is almost universally "execute/eval" across languages
	// This catches: node -e, ruby -e, perl -e, swift -e, lua -e, etc.
	regexp.MustCompile(`\s+-e\s+`),  // -e followed by code
	regexp.MustCompile(`\s+-e'`),    // -e'code'
	regexp.MustCompile(`\s+-e"`),    // -e"code"
	regexp.MustCompile(`\s+-E\s+`),  // -E (perl uses this too)

	// Long form flags are unambiguous
	regexp.MustCompile(`\s+--eval\b`),
	regexp.MustCompile(`\s+--exec\b`),
	regexp.MustCompile(`\s+--execute\b`),
	regexp.MustCompile(`\s+--run\b`),
	regexp.MustCompile(`\s+--print\b`),
	regexp.MustCompile(`\s+--command\b`),

	// Shell inline execution (sh -c, bash -c, etc.)
	regexp.MustCompile(`(?i)^(sh|bash|zsh|dash|ksh|fish)\s+.*-c\s+`),

	// Python -c (specific to python to avoid grep -c false positive)
	regexp.MustCompile(`(?i)^python[23]?\s+.*-c\s+`),

	// PHP -r (run)
	regexp.MustCompile(`(?i)^php\s+.*-r\s+`),

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
