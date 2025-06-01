package cmd

import (
	"syscall"
)

// getEnv retrieves the value of the environment variable named by the key `name`.
// If the variable is present in the environment, the value (which may be empty) is returned.
// Otherwise, it returns the default value `def`.
//
// Parameters:
//   - name: The name of the environment variable to retrieve.
//   - def: The default value to return if the environment variable is not set.
//
// Returns:
//
//	The value of the environment variable if it is set, otherwise the default value `def`.
func getEnv(name string, def string) string {
	v, err := syscall.Getenv(name)
	if !err || v == "" {
		return def
	}

	return v
}
