package secrets

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// GetMachineID returns a unique identifier for this machine
// Used to derive encryption key when no passphrase is set
func GetMachineID() (string, error) {
	var id string
	var err error

	switch runtime.GOOS {
	case "darwin":
		id, err = getMacOSMachineID()
	case "linux":
		id, err = getLinuxMachineID()
	default:
		// Fallback: use hostname + user
		id, err = getFallbackID()
	}

	if err != nil {
		return "", err
	}

	// Hash the ID to normalize length and add some obscurity
	hash := sha256.Sum256([]byte(id + "alex-salt-v1"))
	return hex.EncodeToString(hash[:]), nil
}

// getMacOSMachineID gets the hardware UUID on macOS
func getMacOSMachineID() (string, error) {
	cmd := exec.Command("ioreg", "-rd1", "-c", "IOPlatformExpertDevice")
	output, err := cmd.Output()
	if err != nil {
		return getFallbackID()
	}

	// Parse out IOPlatformUUID
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "IOPlatformUUID") {
			parts := strings.Split(line, "\"")
			if len(parts) >= 4 {
				return parts[3], nil
			}
		}
	}

	return getFallbackID()
}

// getLinuxMachineID reads /etc/machine-id
func getLinuxMachineID() (string, error) {
	data, err := os.ReadFile("/etc/machine-id")
	if err != nil {
		// Try /var/lib/dbus/machine-id as fallback
		data, err = os.ReadFile("/var/lib/dbus/machine-id")
		if err != nil {
			return getFallbackID()
		}
	}
	return strings.TrimSpace(string(data)), nil
}

// getFallbackID creates an ID from hostname and username
func getFallbackID() (string, error) {
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

	return hostname + "-" + user, nil
}

// DerivePassphrase returns the passphrase to use
// If passphrase is empty, derives from machine ID
func DerivePassphrase(passphrase string) (string, error) {
	if passphrase != "" {
		return passphrase, nil
	}

	machineID, err := GetMachineID()
	if err != nil {
		return "", err
	}

	return machineID, nil
}
