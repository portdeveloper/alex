package cmd

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/portdeveloper/alex/internal/secrets"
	"github.com/spf13/cobra"
)

var (
	importPassphrase bool
	importPrefix     string
	importGlobal     bool
)

var importCmd = &cobra.Command{
	Use:   "import FILE",
	Short: "Import secrets from a .env file",
	Long: `Import secrets from a .env file into alex.

Parses KEY=VALUE pairs from the file, skipping comments (#) and empty lines.
Supports quoted values (single and double quotes).

Imports to project scope by default.
Use --global to import to global scope.

After importing, consider deleting the .env file to keep secrets out of
your repository and away from AI agents.

Examples:
  alex import .env                    # Import from .env
  alex import .env.local              # Import from .env.local (Next.js/React)
  alex import .env --global           # Import to global scope
  alex import .env --prefix DB_       # Only import vars starting with DB_`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		filePath := args[0]

		// Parse the .env file
		parsed, err := parseEnvFile(filePath)
		if err != nil {
			exitWithError("parsing env file", err)
		}

		// Warn about skipped lines
		if len(parsed.skipped) > 0 {
			fmt.Fprintf(os.Stderr, "Warning: skipped %d line(s):\n", len(parsed.skipped))
			for _, msg := range parsed.skipped {
				fmt.Fprintf(os.Stderr, "  - %s\n", msg)
			}
		}

		envVars := parsed.vars
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

		var store *secrets.Store
		var scope string

		if importGlobal {
			store, err = secrets.NewGlobalStore(passphrase)
			scope = "global"
		} else {
			store, err = secrets.NewProjectStore(passphrase)
			scope = "project"
		}
		if err != nil {
			exitWithError("opening secret store", err)
		}

		// Import each secret
		var importedKeys, updatedKeys []string
		for key, value := range envVars {
			_, exists := store.Get(key)
			if err := store.Set(key, value); err != nil {
				exitWithError(fmt.Sprintf("saving secret '%s'", key), err)
			}
			if exists {
				updatedKeys = append(updatedKeys, key)
			} else {
				importedKeys = append(importedKeys, key)
			}
		}

		// Sort for consistent output
		sort.Strings(importedKeys)
		sort.Strings(updatedKeys)

		// Report results
		if len(importedKeys) > 0 && len(updatedKeys) > 0 {
			fmt.Printf("✓ Imported %d new, updated %d existing secrets (%s):\n", len(importedKeys), len(updatedKeys), scope)
			printKeyList("  new: ", importedKeys)
			printKeyList("  updated: ", updatedKeys)
		} else if len(importedKeys) > 0 {
			fmt.Printf("✓ Imported %d secrets (%s):\n", len(importedKeys), scope)
			printKeyList("  ", importedKeys)
		} else {
			fmt.Printf("✓ Updated %d secrets (%s):\n", len(updatedKeys), scope)
			printKeyList("  ", updatedKeys)
		}

		// Suggest deleting the source file
		fmt.Printf("\nNext steps:\n")
		fmt.Printf("  rm %s              # Delete the file to keep secrets safe\n", filePath)
		fmt.Printf("  alex run <command>    # Run commands with secrets injected\n")
	},
}

func init() {
	rootCmd.AddCommand(importCmd)
	importCmd.Flags().BoolVar(&importPassphrase, "passphrase", false, "Use a passphrase instead of machine ID")
	importCmd.Flags().StringVar(&importPrefix, "prefix", "", "Only import variables with this prefix")
	importCmd.Flags().BoolVarP(&importGlobal, "global", "g", false, "Import into global scope (~/.alex/) instead of project")
}

// parseResult holds parsed env vars and any skipped entries
type parseResult struct {
	vars    map[string]string
	skipped []string
}

// parseEnvFile reads a .env file and returns key-value pairs
func parseEnvFile(path string) (*parseResult, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	result := &parseResult{
		vars:    make(map[string]string),
		skipped: []string{},
	}
	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Find the first = sign
		idx := strings.Index(line, "=")
		if idx == -1 {
			result.skipped = append(result.skipped, fmt.Sprintf("line %d: no '=' found", lineNum))
			continue
		}

		key := strings.TrimSpace(line[:idx])
		value := strings.TrimSpace(line[idx+1:])

		// Skip if key is empty
		if key == "" {
			result.skipped = append(result.skipped, fmt.Sprintf("line %d: empty key", lineNum))
			continue
		}

		// Validate key format
		if !isValidKey(key) {
			result.skipped = append(result.skipped, fmt.Sprintf("line %d: invalid key '%s'", lineNum, key))
			continue
		}

		// Skip empty values
		value = unquote(value)
		if value == "" {
			result.skipped = append(result.skipped, fmt.Sprintf("line %d: empty value for '%s'", lineNum, key))
			continue
		}

		result.vars[key] = value
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

// printKeyList prints a list of keys with a prefix, capping at maxShow
func printKeyList(prefix string, keys []string) {
	const maxShow = 5
	if len(keys) <= maxShow {
		fmt.Printf("%s%s\n", prefix, strings.Join(keys, ", "))
	} else {
		shown := strings.Join(keys[:maxShow], ", ")
		fmt.Printf("%s%s, ... and %d more\n", prefix, shown, len(keys)-maxShow)
	}
}
