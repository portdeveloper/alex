package cmd

import (
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/portdeveloper/alex/internal/secrets"
	"github.com/spf13/cobra"
)

var listPassphrase bool

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List stored secrets (names only)",
	Long: `List all stored secrets. Only shows names, not values.

Shows both global (~/.alex/) and project secrets.
Project is auto-detected from git root or current directory.

Example:
  alex list`,
	Args: cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		passphrase, err := getPassphrase(listPassphrase)
		if err != nil {
			exitWithError("getting passphrase", err)
		}

		// Load global store
		globalStore, err := secrets.NewGlobalStore(passphrase)
		if err != nil {
			exitWithError("opening global secret store", err)
		}
		globalSecrets := globalStore.List()

		// Load project store if it exists
		var projectSecrets map[string]secrets.Secret
		projectExists, projectErr := secrets.ProjectStoreExists()
		if projectErr != nil {
			fmt.Fprintf(os.Stderr, "Warning: %v\n", projectErr)
		} else if projectExists {
			projectStore, err := secrets.NewProjectStore(passphrase)
			if err != nil {
				exitWithError("opening project secret store", err)
			}
			projectSecrets = projectStore.List()
		}

		totalCount := len(globalSecrets) + len(projectSecrets)
		if totalCount == 0 {
			fmt.Println("No secrets stored. Use 'alex set KEY VALUE' to add one.")
			return
		}

		// Print global secrets
		if len(globalSecrets) > 0 {
			fmt.Println("GLOBAL:")
			printSecretList(globalSecrets)
		}

		// Print project secrets
		if len(projectSecrets) > 0 {
			if len(globalSecrets) > 0 {
				fmt.Println()
			}
			fmt.Println("PROJECT:")
			printSecretList(projectSecrets)
		}

		fmt.Printf("\n%d secret(s) stored", totalCount)
		if len(globalSecrets) > 0 && len(projectSecrets) > 0 {
			fmt.Printf(" (%d global, %d project)", len(globalSecrets), len(projectSecrets))
		}
		fmt.Println()
	},
}

func printSecretList(secretList map[string]secrets.Secret) {
	keys := make([]string, 0, len(secretList))
	for k := range secretList {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	fmt.Printf("  %-28s %s\n", "NAME", "UPDATED")
	fmt.Printf("  %-28s %s\n", "----", "-------")
	for _, key := range keys {
		secret := secretList[key]
		age := formatTimeAgo(secret.UpdatedAt)
		fmt.Printf("  %-28s %s\n", key, age)
	}
}

func init() {
	rootCmd.AddCommand(listCmd)
	listCmd.Flags().BoolVar(&listPassphrase, "passphrase", false, "Use a passphrase instead of machine ID")
}

// formatTimeAgo formats a time as a human-readable "time ago" string
func formatTimeAgo(t time.Time) string {
	duration := time.Since(t)

	switch {
	case duration < time.Minute:
		return "just now"
	case duration < time.Hour:
		mins := int(duration.Minutes())
		if mins == 1 {
			return "1 minute ago"
		}
		return fmt.Sprintf("%d minutes ago", mins)
	case duration < 24*time.Hour:
		hours := int(duration.Hours())
		if hours == 1 {
			return "1 hour ago"
		}
		return fmt.Sprintf("%d hours ago", hours)
	case duration < 7*24*time.Hour:
		days := int(duration.Hours() / 24)
		if days == 1 {
			return "1 day ago"
		}
		return fmt.Sprintf("%d days ago", days)
	default:
		weeks := int(duration.Hours() / 24 / 7)
		if weeks == 1 {
			return "1 week ago"
		}
		return fmt.Sprintf("%d weeks ago", weeks)
	}
}
