package runner

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

// Run executes a command with the given secrets injected into the environment
func Run(args []string, secrets map[string]string) error {
	if len(args) == 0 {
		return fmt.Errorf("no command specified")
	}

	// Find the executable
	executable, err := exec.LookPath(args[0])
	if err != nil {
		return fmt.Errorf("command not found: %s", args[0])
	}

	// Build environment: current env + secrets
	env := os.Environ()
	for key, value := range secrets {
		env = append(env, fmt.Sprintf("%s=%s", key, value))
	}

	// Use syscall.Exec to replace current process
	// This is cleaner than exec.Command as it doesn't create a child process
	return syscall.Exec(executable, args, env)
}

// RunWithOutput executes a command and returns its output
// Used for testing or when we need to capture output
func RunWithOutput(args []string, secrets map[string]string) ([]byte, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("no command specified")
	}

	cmd := exec.Command(args[0], args[1:]...)

	// Build environment
	env := os.Environ()
	for key, value := range secrets {
		env = append(env, fmt.Sprintf("%s=%s", key, value))
	}
	cmd.Env = env

	return cmd.CombinedOutput()
}
