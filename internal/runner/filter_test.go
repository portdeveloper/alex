package runner

import "testing"

func TestIsSuspicious(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		suspicious bool
	}{
		// Suspicious: direct env inspection
		{"env command", []string{"env"}, true},
		{"printenv command", []string{"printenv"}, true},
		{"printenv with var", []string{"printenv", "PATH"}, true},
		{"export command", []string{"export"}, true},
		{"set command", []string{"set"}, true},

		// Suspicious: shell commands
		{"sh -c", []string{"sh", "-c", "echo hello"}, true},
		{"bash -c", []string{"bash", "-c", "echo hello"}, true},
		{"zsh -c", []string{"zsh", "-c", "echo hello"}, true},

		// Suspicious: variable expansion (uppercase)
		{"echo uppercase var", []string{"echo", "$DATABASE_URL"}, true},
		{"echo braced var", []string{"echo", "${API_KEY}"}, true},

		// Suspicious: variable expansion (lowercase) - this is the fix we made
		{"echo lowercase var", []string{"echo", "$my_secret"}, true},
		{"echo lowercase braced", []string{"echo", "${password}"}, true},

		// Suspicious: language-specific
		{"node process.env", []string{"node", "-e", "console.log(process.env)"}, true},
		{"python os.environ", []string{"python", "-c", "import os; print(os.environ)"}, true},

		// Suspicious: echo/printf patterns
		{"echo $VAR", []string{"echo", "$VAR"}, true},
		{"printf $VAR", []string{"printf", "%s", "$VAR"}, true},

		// Safe commands
		{"npm start", []string{"npm", "start"}, false},
		{"npm run build", []string{"npm", "run", "build"}, false},
		{"go build", []string{"go", "build"}, false},
		{"pytest", []string{"pytest"}, false},
		{"docker run", []string{"docker", "run", "alpine"}, false},
		{"git status", []string{"git", "status"}, false},
		{"ls -la", []string{"ls", "-la"}, false},
		{"cat file.txt", []string{"cat", "file.txt"}, false},

		// Edge cases
		{"empty args", []string{}, false},
		{"uppercase ENV in path", []string{"ls", "/var/ENV"}, false}, // ENV in path isn't a variable
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			suspicious, _ := IsSuspicious(tc.args)
			if suspicious != tc.suspicious {
				t.Errorf("IsSuspicious(%v) = %v, want %v", tc.args, suspicious, tc.suspicious)
			}
		})
	}
}
