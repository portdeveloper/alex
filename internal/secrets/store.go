package secrets

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"
)

const (
	alexDir     = ".alex"
	secretsFile = "secrets.enc"
	configFile  = "config.json"
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

// NewStore creates a new secret store
func NewStore(passphrase string) (*Store, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}

	alexPath := filepath.Join(homeDir, alexDir)
	if err := os.MkdirAll(alexPath, 0700); err != nil {
		return nil, err
	}

	store := &Store{
		path:       alexPath,
		passphrase: passphrase,
		secrets:    make(map[string]Secret),
	}

	// Load existing secrets if they exist
	if err := store.load(); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	return store, nil
}

// GetAlexDir returns the path to the alex config directory
func GetAlexDir() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(homeDir, alexDir), nil
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

	return json.Unmarshal(decrypted, &s.secrets)
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
