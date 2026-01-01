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

		// Suspicious: language-specific literal patterns
		{"node process.env", []string{"node", "-e", "console.log(process.env)"}, true},
		{"python os.environ", []string{"python", "-c", "import os; print(os.environ)"}, true},

		// Suspicious: inline code execution (blocks obfuscation attacks)
		// These bypass literal pattern matching via string concatenation, base64, etc.
		{"node -e obfuscated", []string{"node", "-e", "console.log(process['en'+'v'])"}, true},
		{"node --eval obfuscated", []string{"node", "--eval", "Reflect.get(process, atob('ZW52'))"}, true},
		{"node -p", []string{"node", "-p", "process.env"}, true},
		{"node --print", []string{"node", "--print", "Object.keys(process.env)"}, true},
		{"python -c obfuscated", []string{"python", "-c", "exec('print(os.environ)')"}, true},
		{"python3 -c", []string{"python3", "-c", "import os; print(os.environ)"}, true},
		{"ruby -e", []string{"ruby", "-e", "puts ENV"}, true},
		{"perl -e", []string{"perl", "-e", "print %ENV"}, true},
		{"php -r", []string{"php", "-r", "print_r($_ENV);"}, true},
		{"bun -e", []string{"bun", "-e", "console.log(process.env)"}, true},

		// Suspicious: eval/exec patterns in arguments (catch obfuscation in any context)
		{"contains eval", []string{"something", "eval('code')"}, true},
		{"contains exec", []string{"something", "exec('code')"}, true},
		{"contains Function", []string{"something", "new Function('return process.env')"}, true},

		// Suspicious: awk/gawk/mawk with inline programs (can access ENVIRON)
		{"awk BEGIN block", []string{"awk", "BEGIN{print ENVIRON[\"SECRET\"]}"}, true},
		{"awk single quotes", []string{"awk", "'{print $1}'"}, true},
		{"awk double quotes", []string{"awk", "\"{print $1}\""}, true},
		{"gawk inline", []string{"gawk", "'BEGIN{print 1}'"}, true},
		{"mawk inline", []string{"mawk", "'BEGIN{print 1}'"}, true},
		{"awk -f script", []string{"awk", "-f", "script.awk"}, true},
		{"contains ENVIRON", []string{"something", "ENVIRON[\"KEY\"]"}, true},

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

		// Safe: running script files (not inline code)
		{"node script.js", []string{"node", "script.js"}, false},
		{"node ./app.js", []string{"node", "./app.js"}, false},
		{"python script.py", []string{"python", "script.py"}, false},
		{"python3 ./app.py", []string{"python3", "./app.py"}, false},
		{"ruby script.rb", []string{"ruby", "script.rb"}, false},

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
