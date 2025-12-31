package secrets

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	alexDir     = ".alex"
	secretsFile = "secrets.enc"
	configFile  = "config.json"
	projectsDir = "projects"
)

// Secret represents a stored secret with metadata
type Secret struct {
	Value     string    `json:"value"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Store manages encrypted secret storage
type Store struct {
	path       string
	passphrase string
	secrets    map[string]Secret
}

// Config holds alex configuration
type Config struct {
	UsePassphrase bool `json:"use_passphrase"`
}

// NewStore creates a new global secret store (backwards compatible)
func NewStore(passphrase string) (*Store, error) {
	return NewGlobalStore(passphrase)
}

// NewGlobalStore creates a store at ~/.alex/
func NewGlobalStore(passphrase string) (*Store, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	return NewStoreAt(passphrase, filepath.Join(homeDir, alexDir))
}

// NewProjectStore creates a store at ~/.alex/projects/<hash>/ based on project root
func NewProjectStore(passphrase string) (*Store, error) {
	projectID := GetProjectID()

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}

	projectPath := filepath.Join(homeDir, alexDir, projectsDir, projectID)
	return NewStoreAt(passphrase, projectPath)
}

// NewStoreAt creates a store at a specific path
func NewStoreAt(passphrase string, basePath string) (*Store, error) {
	if err := os.MkdirAll(basePath, 0700); err != nil {
		return nil, err
	}

	store := &Store{
		path:       basePath,
		passphrase: passphrase,
		secrets:    make(map[string]Secret),
	}

	// Load existing secrets if they exist
	if err := store.load(); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	return store, nil
}

// GlobalStoreExists checks if global secrets exist
func GlobalStoreExists() bool {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return false
	}
	globalPath := filepath.Join(homeDir, alexDir, secretsFile)
	_, err = os.Stat(globalPath)
	return err == nil
}

// ProjectStoreExists checks if project secrets exist for the current directory.
// Returns (exists, error) where error indicates a problem checking (not just missing file).
func ProjectStoreExists() (bool, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return false, fmt.Errorf("cannot get home directory: %w", err)
	}
	projectPath := filepath.Join(homeDir, alexDir, projectsDir, GetProjectID(), secretsFile)
	_, err = os.Stat(projectPath)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	// Permission error or other issue
	return false, fmt.Errorf("cannot access project secrets: %w", err)
}

// GetProjectID returns a unique identifier for the current project.
// Uses git remote URL if available (stable across moves), otherwise uses path.
// Returns a short hash to use as directory name.
func GetProjectID() string {
	identifier := getProjectIdentifier()
	hash := sha256.Sum256([]byte(identifier))
	// Use first 12 chars of hex hash (like git short hashes)
	return hex.EncodeToString(hash[:])[:12]
}

// GetProjectRoot returns the root directory of the current project
func GetProjectRoot() string {
	return getGitRoot()
}

// getProjectIdentifier returns a stable identifier for the project.
// Prefers git remote URL (survives moves), falls back to git root path.
func getProjectIdentifier() string {
	// Try git remote origin URL first (most stable - survives moves)
	cmd := exec.Command("git", "remote", "get-url", "origin")
	output, err := cmd.Output()
	if err == nil {
		return strings.TrimSpace(string(output))
	}

	// Fall back to git root path
	root := getGitRoot()
	if root != "" {
		return root
	}

	// Last resort: current directory
	cwd, err := os.Getwd()
	if err != nil {
		return "."
	}
	return cwd
}

// getGitRoot returns the git repository root, or empty string if not in a git repo
func getGitRoot() string {
	cmd := exec.Command("git", "rev-parse", "--show-toplevel")
	output, err := cmd.Output()
	if err == nil {
		return strings.TrimSpace(string(output))
	}
	return ""
}

// GetGlobalDir returns the path to the global alex directory
func GetGlobalDir() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(homeDir, alexDir), nil
}

// GetAlexDir is an alias for GetGlobalDir (backwards compatible)
func GetAlexDir() (string, error) {
	return GetGlobalDir()
}


// secretsFilePath returns the full path to the secrets file
func (s *Store) secretsFilePath() string {
	return filepath.Join(s.path, secretsFile)
}

// load reads and decrypts secrets from disk
func (s *Store) load() error {
	data, err := os.ReadFile(s.secretsFilePath())
	if err != nil {
		return err
	}

	decrypted, err := decrypt(data, s.passphrase)
	if err != nil {
		return err
	}

	if err := json.Unmarshal(decrypted, &s.secrets); err != nil {
		return fmt.Errorf("corrupted secrets data (invalid JSON): %w", err)
	}
	return nil
}

// save encrypts and writes secrets to disk
func (s *Store) save() error {
	data, err := json.Marshal(s.secrets)
	if err != nil {
		return err
	}

	encrypted, err := encrypt(data, s.passphrase)
	if err != nil {
		return err
	}

	return os.WriteFile(s.secretsFilePath(), encrypted, 0600)
}

// Set stores a secret
func (s *Store) Set(key, value string) error {
	now := time.Now()
	existing, exists := s.secrets[key]

	secret := Secret{
		Value:     value,
		UpdatedAt: now,
	}

	if exists {
		secret.CreatedAt = existing.CreatedAt
	} else {
		secret.CreatedAt = now
	}

	s.secrets[key] = secret
	return s.save()
}

// Get retrieves a secret value
func (s *Store) Get(key string) (string, bool) {
	secret, exists := s.secrets[key]
	if !exists {
		return "", false
	}
	return secret.Value, true
}

// Delete removes a secret
func (s *Store) Delete(key string) error {
	if _, exists := s.secrets[key]; !exists {
		return errors.New("secret not found")
	}
	delete(s.secrets, key)
	return s.save()
}

// List returns all secret names with metadata (not values)
func (s *Store) List() map[string]Secret {
	// Return a copy without values
	result := make(map[string]Secret)
	for k, v := range s.secrets {
		result[k] = Secret{
			CreatedAt: v.CreatedAt,
			UpdatedAt: v.UpdatedAt,
		}
	}
	return result
}

// GetAll returns all secrets with values (for injection)
func (s *Store) GetAll() map[string]string {
	result := make(map[string]string)
	for k, v := range s.secrets {
		result[k] = v.Value
	}
	return result
}

// Count returns the number of stored secrets
func (s *Store) Count() int {
	return len(s.secrets)
}
