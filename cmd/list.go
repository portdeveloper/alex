package cmd

import (
	"fmt"
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

Example:
  alex list`,
	Args: cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		passphrase, err := getPassphrase(listPassphrase)
		if err != nil {
			exitWithError("getting passphrase", err)
		}

		store, err := secrets.NewStore(passphrase)
		if err != nil {
			exitWithError("opening secret store", err)
		}

		secretList := store.List()
		if len(secretList) == 0 {
			fmt.Println("No secrets stored. Use 'alex set KEY VALUE' to add one.")
			return
		}

		// Sort keys for consistent output
		keys := make([]string, 0, len(secretList))
		for k := range secretList {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		fmt.Printf("%-30s %s\n", "NAME", "UPDATED")
		fmt.Printf("%-30s %s\n", "----", "-------")
		for _, key := range keys {
			secret := secretList[key]
			age := formatTimeAgo(secret.UpdatedAt)
			fmt.Printf("%-30s %s\n", key, age)
		}
		fmt.Printf("\n%d secret(s) stored\n", len(keys))
	},
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
