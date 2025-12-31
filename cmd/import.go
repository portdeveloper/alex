package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/portdeveloper/alex/internal/secrets"
	"github.com/spf13/cobra"
)

var (
	importPassphrase bool
	importPrefix     string
)

var importCmd = &cobra.Command{
	Use:   "import FILE",
	Short: "Import secrets from a .env file",
	Long: `Import secrets from a .env file into alex.

Parses KEY=VALUE pairs from the file, skipping comments (#) and empty lines.
Supports quoted values (single and double quotes).

Examples:
  alex import .env                    # Import all secrets
  alex import .env --prefix DB_       # Only import vars starting with DB_
  alex import config/.env.local       # Import from specific path`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		filePath := args[0]

		// Parse the .env file
		envVars, err := parseEnvFile(filePath)
		if err != nil {
			exitWithError("parsing env file", err)
		}

		if len(envVars) == 0 {
			fmt.Println("No secrets found in file")
			return
		}

		// Filter by prefix if specified
		if importPrefix != "" {
			filtered := make(map[string]string)
			for k, v := range envVars {
				if strings.HasPrefix(k, importPrefix) {
					filtered[k] = v
				}
			}
			envVars = filtered
		}

		if len(envVars) == 0 {
			fmt.Printf("No secrets found with prefix '%s'\n", importPrefix)
			return
		}

		// Get passphrase
		passphrase, err := getPassphrase(importPassphrase)
		if err != nil {
			exitWithError("getting passphrase", err)
		}

		store, err := secrets.NewStore(passphrase)
		if err != nil {
			exitWithError("opening secret store", err)
		}

		// Import each secret
		var imported, updated int
		for key, value := range envVars {
			_, exists := store.Get(key)
			if err := store.Set(key, value); err != nil {
				exitWithError(fmt.Sprintf("saving secret '%s'", key), err)
			}
			if exists {
				updated++
			} else {
				imported++
			}
		}

		// Report results
		if imported > 0 && updated > 0 {
			fmt.Printf("✓ Imported %d new, updated %d existing secrets\n", imported, updated)
		} else if imported > 0 {
			fmt.Printf("✓ Imported %d secrets\n", imported)
		} else {
			fmt.Printf("✓ Updated %d secrets\n", updated)
		}
	},
}

func init() {
	rootCmd.AddCommand(importCmd)
	importCmd.Flags().BoolVar(&importPassphrase, "passphrase", false, "Use a passphrase instead of machine ID")
	importCmd.Flags().StringVar(&importPrefix, "prefix", "", "Only import variables with this prefix")
}

// parseEnvFile reads a .env file and returns key-value pairs
func parseEnvFile(path string) (map[string]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	result := make(map[string]string)
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Find the first = sign
		idx := strings.Index(line, "=")
		if idx == -1 {
			continue
		}

		key := strings.TrimSpace(line[:idx])
		value := strings.TrimSpace(line[idx+1:])

		// Skip if key is empty
		if key == "" {
			continue
		}

		// Remove surrounding quotes from value
		value = unquote(value)

		result[key] = value
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return result, nil
}

// unquote removes surrounding quotes from a string
func unquote(s string) string {
	if len(s) < 2 {
		return s
	}

	// Check for matching quotes
	first, last := s[0], s[len(s)-1]
	if (first == '"' && last == '"') || (first == '\'' && last == '\'') {
		return s[1 : len(s)-1]
	}

	return s
}
