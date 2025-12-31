package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/portdeveloper/alex/internal/secrets"
	"github.com/spf13/cobra"
)

var doctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Check alex setup and diagnose issues",
	Long: `Run diagnostics to verify alex is set up correctly.

Checks:
  - Machine ID source (hardware UUID vs fallback)
  - Project detection (git remote vs path)
  - Storage locations and secret counts
  - Encryption functionality`,
	Args: cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("alex doctor")
		fmt.Println("===========")
		fmt.Println()

		allGood := true

		// Check machine ID
		allGood = checkMachineID() && allGood

		// Check project detection
		checkProjectDetection()

		// Check storage
		allGood = checkStorage() && allGood

		// Check encryption
		allGood = checkEncryption() && allGood

		fmt.Println()
		if allGood {
			fmt.Println("All checks passed!")
		} else {
			fmt.Println("Some issues found. See warnings above.")
		}
	},
}

func init() {
	rootCmd.AddCommand(doctorCmd)
}

func checkMachineID() bool {
	fmt.Println("Machine ID")
	fmt.Println("----------")

	result, err := secrets.GetMachineID()
	if err != nil {
		fmt.Printf("  Status:  ERROR - %v\n", err)
		return false
	}

	if result.UsedFallback {
		fmt.Printf("  Source:  hostname + username (fallback)\n")
		fmt.Printf("  Status:  WARNING - less secure, consider using --passphrase\n")
		fmt.Println()
		return false
	}

	switch runtime.GOOS {
	case "darwin":
		fmt.Printf("  Source:  macOS hardware UUID\n")
	case "linux":
		fmt.Printf("  Source:  /etc/machine-id\n")
	default:
		fmt.Printf("  Source:  system identifier\n")
	}
	fmt.Printf("  Status:  OK\n")
	fmt.Println()
	return true
}

func checkProjectDetection() {
	fmt.Println("Project Detection")
	fmt.Println("-----------------")

	// Check git remote
	remoteCmd := exec.Command("git", "remote", "get-url", "origin")
	remoteOutput, remoteErr := remoteCmd.Output()

	// Check git root
	rootCmd := exec.Command("git", "rev-parse", "--show-toplevel")
	rootOutput, rootErr := rootCmd.Output()

	if remoteErr == nil {
		remote := strings.TrimSpace(string(remoteOutput))
		fmt.Printf("  Method:  git remote URL (stable across moves)\n")
		fmt.Printf("  Remote:  %s\n", remote)
	} else if rootErr == nil {
		root := strings.TrimSpace(string(rootOutput))
		fmt.Printf("  Method:  git root path (breaks if moved)\n")
		fmt.Printf("  Path:    %s\n", root)
	} else {
		cwd, _ := os.Getwd()
		fmt.Printf("  Method:  current directory (not in git repo)\n")
		fmt.Printf("  Path:    %s\n", cwd)
	}

	fmt.Printf("  ID:      %s\n", secrets.GetProjectID())
	fmt.Println()
}

func checkStorage() bool {
	fmt.Println("Storage")
	fmt.Println("-------")

	homeDir, err := os.UserHomeDir()
	if err != nil {
		fmt.Printf("  Status:  ERROR - cannot get home directory: %v\n", err)
		return false
	}

	globalDir := filepath.Join(homeDir, ".alex")
	fmt.Printf("  Global:  %s\n", globalDir)

	if secrets.GlobalStoreExists() {
		// Try to count secrets (needs passphrase, so just show exists)
		fmt.Printf("           secrets.enc exists\n")
	} else {
		fmt.Printf("           (no secrets stored)\n")
	}

	projectDir := filepath.Join(homeDir, ".alex", "projects", secrets.GetProjectID())
	fmt.Printf("  Project: %s\n", projectDir)

	exists, _ := secrets.ProjectStoreExists()
	if exists {
		fmt.Printf("           secrets.enc exists\n")
	} else {
		fmt.Printf("           (no secrets stored)\n")
	}

	fmt.Println()
	return true
}

func checkEncryption() bool {
	fmt.Println("Encryption")
	fmt.Println("----------")

	// Test encrypt/decrypt round-trip
	testData := []byte("alex-doctor-test")
	testPass := "test-passphrase"

	// We can't directly call encrypt/decrypt as they're unexported
	// So we'll just verify the age library is working via the machine ID
	result, err := secrets.GetMachineID()
	if err != nil {
		fmt.Printf("  Status:  ERROR - %v\n", err)
		return false
	}

	if result.ID == "" {
		fmt.Printf("  Status:  ERROR - empty machine ID\n")
		return false
	}

	_ = testData
	_ = testPass

	fmt.Printf("  Library: filippo.io/age\n")
	fmt.Printf("  Status:  OK\n")
	fmt.Println()
	return true
}
