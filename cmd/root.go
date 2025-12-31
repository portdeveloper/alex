package cmd

import (
	"fmt"
	"os"
	"regexp"

	"github.com/spf13/cobra"
)

// validKeyPattern matches valid environment variable names
var validKeyPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

var rootCmd = &cobra.Command{
	Use:   "alex",
	Short: "Keep secrets out of AI agent scope",
	Long: `alex - Run commands with secrets that AI agents can't see.

alex stores secrets separately and injects them only when running commands,
keeping them invisible to AI coding assistants like Claude Code, GitHub Copilot,
Cursor, and others.

Examples:
  alex set DATABASE_URL "postgres://user:pass@host/db"
  alex set STRIPE_KEY "sk_live_xxxxx"
  alex list
  alex run npm start
  alex run pytest`,
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.CompletionOptions.DisableDefaultCmd = true
}

// Helper to print errors consistently
func exitWithError(msg string, err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s: %v\n", msg, err)
	} else {
		fmt.Fprintf(os.Stderr, "Error: %s\n", msg)
	}
	os.Exit(1)
}

// isValidKey checks if a key is a valid environment variable name
func isValidKey(key string) bool {
	return validKeyPattern.MatchString(key)
}
