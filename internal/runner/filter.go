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

	// Language-specific env access
	regexp.MustCompile(`process\.env`),
	regexp.MustCompile(`os\.environ`),
	regexp.MustCompile(`ENV\[`),
	regexp.MustCompile(`getenv\(`),

	// Commands that echo/print
	regexp.MustCompile(`^echo\s+\$`),
	regexp.MustCompile(`^printf.*\$`),
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
