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

		store, err := secrets.NewStore(passphrase)
		if err != nil {
			exitWithError("opening secret store", err)
		}

		secretMap := store.GetAll()
		if len(secretMap) == 0 {
			fmt.Fprintln(os.Stderr, "Note: No secrets stored. Running command without injected secrets.")
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
