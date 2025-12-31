package cmd

import (
	"fmt"

	"github.com/portdeveloper/alex/internal/secrets"
	"github.com/spf13/cobra"
)

var unsetPassphrase bool

var unsetCmd = &cobra.Command{
	Use:   "unset KEY",
	Short: "Remove a secret",
	Long: `Remove a stored secret.

Example:
  alex unset DATABASE_URL`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		key := args[0]

		passphrase, err := getPassphrase(unsetPassphrase)
		if err != nil {
			exitWithError("getting passphrase", err)
		}

		store, err := secrets.NewStore(passphrase)
		if err != nil {
			exitWithError("opening secret store", err)
		}

		if err := store.Delete(key); err != nil {
			exitWithError(fmt.Sprintf("removing secret '%s'", key), err)
		}

		fmt.Printf("✓ Secret '%s' removed\n", key)
	},
}

func init() {
	rootCmd.AddCommand(unsetCmd)
	unsetCmd.Flags().BoolVar(&unsetPassphrase, "passphrase", false, "Use a passphrase instead of machine ID")
}
