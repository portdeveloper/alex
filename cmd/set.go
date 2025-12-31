package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"syscall"

	"github.com/portdeveloper/alex/internal/secrets"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var (
	setPassphrase bool
	setHidden     bool
)

var setCmd = &cobra.Command{
	Use:   "set KEY [VALUE]",
	Short: "Store a secret",
	Long: `Store a secret that will be available via 'alex run'.

If VALUE is not provided, you will be prompted to enter it (useful for
sensitive values you don't want in shell history).

Examples:
  alex set DATABASE_URL "postgres://user:pass@host/db"
  alex set STRIPE_KEY    # Will prompt for value
  alex set --hidden API_KEY    # Hide input while typing`,
	Args: cobra.RangeArgs(1, 2),
	Run: func(cmd *cobra.Command, args []string) {
		key := args[0]
		var value string

		if len(args) == 2 {
			value = args[1]
		} else {
			// Prompt for value
			var err error
			if setHidden {
				value, err = readHiddenInput(fmt.Sprintf("Enter value for %s: ", key))
			} else {
				value, err = readInput(fmt.Sprintf("Enter value for %s: ", key))
			}
			if err != nil {
				exitWithError("reading input", err)
			}
		}

		if value == "" {
			exitWithError("value cannot be empty", nil)
		}

		// Get passphrase (from flag or machine ID)
		passphrase, err := getPassphrase(setPassphrase)
		if err != nil {
			exitWithError("getting passphrase", err)
		}

		store, err := secrets.NewStore(passphrase)
		if err != nil {
			exitWithError("opening secret store", err)
		}

		if err := store.Set(key, value); err != nil {
			exitWithError("saving secret", err)
		}

		fmt.Printf("✓ Secret '%s' saved\n", key)
	},
}

func init() {
	rootCmd.AddCommand(setCmd)
	setCmd.Flags().BoolVar(&setPassphrase, "passphrase", false, "Use a passphrase instead of machine ID")
	setCmd.Flags().BoolVar(&setHidden, "hidden", false, "Hide input when prompting for value")
}

// readInput reads a line from stdin
func readInput(prompt string) (string, error) {
	fmt.Print(prompt)
	reader := bufio.NewReader(os.Stdin)
	input, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(input), nil
}

// readHiddenInput reads input without echoing (for passwords)
func readHiddenInput(prompt string) (string, error) {
	fmt.Print(prompt)
	bytes, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println() // Print newline after hidden input
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

// getPassphrase returns the passphrase to use for encryption
func getPassphrase(usePassphrase bool) (string, error) {
	if usePassphrase {
		return readHiddenInput("Enter passphrase: ")
	}
	return secrets.DerivePassphrase("")
}
