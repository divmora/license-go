package helpers

import (
	"os"
	"strings"
)

// ResolveEnvFromProcess checks process environment variables DIVMORA_ENV and DIVMORA_ENVIRONMENT,
// returning the trimmed environment name if set.
func ResolveEnvFromProcess() string {
	env := os.Getenv("DIVMORA_ENV")
	if env == "" {
		env = os.Getenv("DIVMORA_ENVIRONMENT")
	}
	return strings.TrimSpace(env)
}
