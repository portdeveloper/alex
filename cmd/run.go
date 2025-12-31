package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/portdeveloper/alex/internal/runner"
	"github.com/portdeveloper/alex/internal/secrets"
	"github.com/spf13/cobra"
)

var (
	runPassphrase bool
	runForce      bool
)

var runCmd = &cobra.Command{
	Use:   "run [--] COMMAND [ARGS...]",
	Short: "Run a command with secrets injected",
	Long: `Run a command with all stored secrets available as environment variables.

The secrets are injected into the command's environment only - they are not
visible in your shell's environment.

Merges secrets from both global (~/.alex/) and project scopes.
Project is auto-detected from git root. Project secrets override global.

Use -- to separate alex flags from command arguments.

Examples:
  alex run npm start
  alex run pytest
  alex run -- docker-compose up -d
  alex run --force env   # Skip confirmation for suspicious commands`,
	Args:               cobra.MinimumNArgs(1),
	DisableFlagParsing: false,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			exitWithError("no command specified", nil)
		}

		// Check for suspicious commands
		if !runForce {
			if suspicious, reason := runner.IsSuspicious(args); suspicious {
				fmt.Fprintf(os.Stderr, "⚠ Warning: %s\n", reason)
				fmt.Fprintf(os.Stderr, "Command: %s\n\n", strings.Join(args, " "))

				if !confirmAction("Allow this command?") {
					fmt.Println("Cancelled.")
					os.Exit(1)
				}
				fmt.Println()
			}
		}

		passphrase, err := getPassphrase(runPassphrase)
		if err != nil {
			exitWithError("getting passphrase", err)
		}

		// Load global secrets
		globalStore, err := secrets.NewGlobalStore(passphrase)
		if err != nil {
			exitWithError("opening global secret store", err)
		}
		globalSecrets := globalStore.GetAll()

		// Load project secrets if they exist
		var projectSecrets map[string]string
		projectExists, projectErr := secrets.ProjectStoreExists()
		if projectErr != nil {
			fmt.Fprintf(os.Stderr, "Warning: %v\n", projectErr)
		} else if projectExists {
			projectStore, err := secrets.NewProjectStore(passphrase)
			if err != nil {
				exitWithError("opening project secret store", err)
			}
			projectSecrets = projectStore.GetAll()
		}

		// Merge secrets (project overrides global)
		secretMap := make(map[string]string)
		for k, v := range globalSecrets {
			secretMap[k] = v
		}
		for k, v := range projectSecrets {
			secretMap[k] = v
		}

		if len(secretMap) == 0 {
			fmt.Fprintln(os.Stderr, "Note: No secrets stored. Running command without injected secrets.")
		} else {
			// Print summary
			globalCount := len(globalSecrets)
			projectCount := len(projectSecrets)
			if projectCount > 0 {
				fmt.Fprintf(os.Stderr, "Using %d global, %d project secret(s)\n", globalCount, projectCount)
			} else {
				fmt.Fprintf(os.Stderr, "Using %d global secret(s)\n", globalCount)
			}
		}

		// Run replaces the current process, so this won't return on success
		if err := runner.Run(args, secretMap); err != nil {
			exitWithError("running command", err)
		}
	},
}

func init() {
	rootCmd.AddCommand(runCmd)
	runCmd.Flags().BoolVar(&runPassphrase, "passphrase", false, "Use a passphrase instead of machine ID")
	runCmd.Flags().BoolVarP(&runForce, "force", "f", false, "Skip confirmation for suspicious commands")
}

// confirmAction prompts the user for yes/no confirmation
func confirmAction(prompt string) bool {
	fmt.Printf("%s [y/N] ", prompt)

	reader := bufio.NewReader(os.Stdin)
	response, err := reader.ReadString('\n')
	if err != nil {
		return false
	}

	response = strings.ToLower(strings.TrimSpace(response))
	return response == "y" || response == "yes"
}
