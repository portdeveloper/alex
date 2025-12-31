package secrets

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"

	"filippo.io/age"
)

// ErrWrongPassphrase indicates the passphrase was incorrect
var ErrWrongPassphrase = errors.New("wrong passphrase or corrupted secrets file")

// encrypt encrypts data using age with a passphrase
func encrypt(data []byte, passphrase string) ([]byte, error) {
	recipient, err := age.NewScryptRecipient(passphrase)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	writer, err := age.Encrypt(&buf, recipient)
	if err != nil {
		return nil, err
	}

	if _, err := writer.Write(data); err != nil {
		return nil, err
	}

	if err := writer.Close(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// decrypt decrypts data using age with a passphrase
func decrypt(data []byte, passphrase string) ([]byte, error) {
	identity, err := age.NewScryptIdentity(passphrase)
	if err != nil {
		return nil, fmt.Errorf("invalid passphrase format: %w", err)
	}

	reader, err := age.Decrypt(bytes.NewReader(data), identity)
	if err != nil {
		// age returns generic errors, make them more user-friendly
		errStr := err.Error()
		if strings.Contains(errStr, "no identity matched") ||
			strings.Contains(errStr, "incorrect passphrase") ||
			strings.Contains(errStr, "failed to decrypt") {
			return nil, ErrWrongPassphrase
		}
		if strings.Contains(errStr, "unknown format") ||
			strings.Contains(errStr, "header") {
			return nil, fmt.Errorf("corrupted secrets file (not a valid encrypted file): %w", err)
		}
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	result, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read decrypted data: %w", err)
	}

	return result, nil
}
