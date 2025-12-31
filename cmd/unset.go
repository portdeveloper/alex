package cmd

import (
	"fmt"

	"github.com/portdeveloper/alex/internal/secrets"
	"github.com/spf13/cobra"
)

var (
	unsetPassphrase bool
	unsetGlobal     bool
)

var unsetCmd = &cobra.Command{
	Use:   "unset KEY",
	Short: "Remove a secret",
	Long: `Remove a stored secret.

Removes from project scope by default.
Use --global to remove from global scope.

Examples:
  alex unset DATABASE_URL
  alex unset --global OPENAI_KEY  # Remove from global scope`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		key := args[0]

		passphrase, err := getPassphrase(unsetPassphrase)
		if err != nil {
			exitWithError("getting passphrase", err)
		}

		var store *secrets.Store
		var scope string

		if unsetGlobal {
			store, err = secrets.NewGlobalStore(passphrase)
			scope = "global"
		} else {
			store, err = secrets.NewProjectStore(passphrase)
			scope = "project"
		}
		if err != nil {
			exitWithError("opening secret store", err)
		}

		if err := store.Delete(key); err != nil {
			exitWithError(fmt.Sprintf("removing secret '%s'", key), err)
		}

		fmt.Printf("✓ Secret '%s' removed (%s)\n", key, scope)
	},
}

func init() {
	rootCmd.AddCommand(unsetCmd)
	unsetCmd.Flags().BoolVar(&unsetPassphrase, "passphrase", false, "Use a passphrase instead of machine ID")
	unsetCmd.Flags().BoolVarP(&unsetGlobal, "global", "g", false, "Remove from global scope (~/.alex/) instead of project")
}
