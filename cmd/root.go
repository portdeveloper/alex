package cmd

import (
	"fmt"
	"os"
	"regexp"

	"github.com/portdeveloper/alex/internal/secrets"
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
	Run: func(cmd *cobra.Command, args []string) {
		// Check if user has any secrets stored
		if !hasAnySecrets() {
			printQuickStart()
			return
		}
		// Otherwise show default help
		cmd.Help()
	},
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

// hasAnySecrets checks if user has any secrets stored (global or project)
func hasAnySecrets() bool {
	// Check global secrets
	if secrets.GlobalStoreExists() {
		return true
	}
	// Check project secrets
	exists, _ := secrets.ProjectStoreExists()
	return exists
}

// printQuickStart shows a helpful guide for new users
func printQuickStart() {
	fmt.Println(`alex - Keep secrets out of AI agent scope

No secrets stored yet. Here's how to get started:

  1. Store a secret (or import from .env):
     alex set DATABASE_URL "postgres://user:pass@host/db"
     alex import .env

  2. Run a command with secrets injected:
     alex run npm start

  3. List your secrets:
     alex list

Your secrets are encrypted and stored separately from your shell
environment, keeping them invisible to AI coding assistants.

Run 'alex help' for all commands.`)
}
