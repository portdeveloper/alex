package secrets

import (
	"bytes"
	"errors"
	"testing"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	tests := []struct {
		name       string
		data       []byte
		passphrase string
	}{
		{"simple text", []byte("hello world"), "password123"},
		{"empty data", []byte(""), "password123"},
		{"json data", []byte(`{"key": "value", "secret": "12345"}`), "complex-pass!@#"},
		{"unicode data", []byte("日本語テスト 🔐"), "pass"},
		{"binary-like data", []byte{0x00, 0x01, 0x02, 0xff, 0xfe}, "binary-pass"},
		{"long passphrase", []byte("data"), "this-is-a-very-long-passphrase-that-should-still-work"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Encrypt
			encrypted, err := encrypt(tc.data, tc.passphrase)
			if err != nil {
				t.Fatalf("encrypt() error = %v", err)
			}

			// Verify encrypted data is different from original (unless empty)
			if len(tc.data) > 0 && bytes.Equal(encrypted, tc.data) {
				t.Error("encrypted data should be different from original")
			}

			// Decrypt
			decrypted, err := decrypt(encrypted, tc.passphrase)
			if err != nil {
				t.Fatalf("decrypt() error = %v", err)
			}

			// Verify round-trip
			if !bytes.Equal(decrypted, tc.data) {
				t.Errorf("decrypt(encrypt(data)) = %v, want %v", decrypted, tc.data)
			}
		})
	}
}

func TestDecryptWrongPassphrase(t *testing.T) {
	data := []byte("secret data")
	passphrase := "correct-password"

	// Encrypt with correct passphrase
	encrypted, err := encrypt(data, passphrase)
	if err != nil {
		t.Fatalf("encrypt() error = %v", err)
	}

	// Try to decrypt with wrong passphrase
	_, err = decrypt(encrypted, "wrong-password")
	if err == nil {
		t.Error("decrypt() with wrong passphrase should return error")
	}

	// Should return our user-friendly error
	if !errors.Is(err, ErrWrongPassphrase) {
		t.Errorf("expected ErrWrongPassphrase, got %v", err)
	}
}

func TestDecryptCorruptedData(t *testing.T) {
	// Try to decrypt random/corrupted data
	corruptedData := []byte("this is not encrypted data at all")

	_, err := decrypt(corruptedData, "any-passphrase")
	if err == nil {
		t.Error("decrypt() with corrupted data should return error")
	}
}
