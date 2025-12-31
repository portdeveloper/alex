package secrets

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// MachineIDResult holds the machine ID and metadata about how it was obtained
type MachineIDResult struct {
	ID           string
	UsedFallback bool // true if hostname+user fallback was used (weaker security)
}

// GetMachineID returns a unique identifier for this machine
// Used to derive encryption key when no passphrase is set
func GetMachineID() (*MachineIDResult, error) {
	var id string
	var usedFallback bool

	switch runtime.GOOS {
	case "darwin":
		id, usedFallback = getMacOSMachineID()
	case "linux":
		id, usedFallback = getLinuxMachineID()
	default:
		// Fallback: use hostname + user
		id = getFallbackID()
		usedFallback = true
	}

	// Hash the ID to normalize length and add some obscurity
	hash := sha256.Sum256([]byte(id + "alex-salt-v1"))
	return &MachineIDResult{
		ID:           hex.EncodeToString(hash[:]),
		UsedFallback: usedFallback,
	}, nil
}

// getMacOSMachineID gets the hardware UUID on macOS
// Returns (id, usedFallback)
func getMacOSMachineID() (string, bool) {
	cmd := exec.Command("ioreg", "-rd1", "-c", "IOPlatformExpertDevice")
	output, err := cmd.Output()
	if err != nil {
		return getFallbackID(), true
	}

	// Parse out IOPlatformUUID
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "IOPlatformUUID") {
			parts := strings.Split(line, "\"")
			if len(parts) >= 4 {
				return parts[3], false
			}
		}
	}

	return getFallbackID(), true
}

// getLinuxMachineID reads /etc/machine-id
// Returns (id, usedFallback)
func getLinuxMachineID() (string, bool) {
	data, err := os.ReadFile("/etc/machine-id")
	if err != nil {
		// Try /var/lib/dbus/machine-id as fallback
		data, err = os.ReadFile("/var/lib/dbus/machine-id")
		if err != nil {
			return getFallbackID(), true
		}
	}
	return strings.TrimSpace(string(data)), false
}

// getFallbackID creates an ID from hostname and username
// This is a weak identifier - easily guessable on shared systems
func getFallbackID() string {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	user := os.Getenv("USER")
	if user == "" {
		user = os.Getenv("USERNAME")
	}
	if user == "" {
		user = "unknown"
	}

	return hostname + "-" + user
}

// PassphraseResult holds the passphrase and metadata
type PassphraseResult struct {
	Passphrase   string
	UsedFallback bool // true if weak machine ID fallback was used
}

// DerivePassphrase returns the passphrase to use
// If passphrase is empty, derives from machine ID
func DerivePassphrase(passphrase string) (*PassphraseResult, error) {
	if passphrase != "" {
		return &PassphraseResult{Passphrase: passphrase, UsedFallback: false}, nil
	}

	machineID, err := GetMachineID()
	if err != nil {
		return nil, err
	}

	return &PassphraseResult{
		Passphrase:   machineID.ID,
		UsedFallback: machineID.UsedFallback,
	}, nil
}
