package cmd

import "testing"

func TestIsValidKey(t *testing.T) {
	tests := []struct {
		key   string
		valid bool
	}{
		// Valid keys
		{"DATABASE_URL", true},
		{"API_KEY", true},
		{"_PRIVATE", true},
		{"a", true},
		{"A", true},
		{"_", true},
		{"myVar", true},
		{"MY_VAR_123", true},
		{"_123", true},

		// Invalid keys
		{"", false},
		{"123_VAR", false},      // Can't start with digit
		{"MY-VAR", false},       // Hyphen not allowed
		{"MY.VAR", false},       // Dot not allowed
		{"MY VAR", false},       // Space not allowed
		{"KEY=VALUE", false},    // Equals not allowed
		{"$VAR", false},         // Dollar sign not allowed
		{"@VAR", false},         // At sign not allowed
		{"foo/bar", false},      // Slash not allowed
		{"émoji", false},        // Non-ASCII not allowed
	}

	for _, tc := range tests {
		t.Run(tc.key, func(t *testing.T) {
			result := isValidKey(tc.key)
			if result != tc.valid {
				t.Errorf("isValidKey(%q) = %v, want %v", tc.key, result, tc.valid)
			}
		})
	}
}
