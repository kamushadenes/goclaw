// Package crypto — env_denylist.go provides env-key validation for grant env overrides.
// Reusable across HTTP handlers and any future validation layer.
package crypto

import (
	"fmt"
	"strings"
)

// deniedExact is the exhaustive set of env keys that are rejected (case-insensitive, stored uppercase).
var deniedExact = map[string]struct{}{
	"PATH":              {},
	"HOME":              {},
	"USER":              {},
	"SHELL":             {},
	"PWD":               {},
	"LD_PRELOAD":        {},
	"LD_LIBRARY_PATH":   {},
	"LD_AUDIT":          {},
	"NODE_OPTIONS":      {},
	"NODE_PATH":         {},
	"PYTHONPATH":        {},
	"PYTHONHOME":        {},
	"PYTHONSTARTUP":     {},
	"GIT_SSH_COMMAND":   {},
	"GIT_SSH":           {},
	"GIT_EXEC_PATH":     {},
	"GIT_CONFIG_SYSTEM": {},
	"SSH_AUTH_SOCK":     {},
}

// deniedPrefixes is the set of uppercase key prefixes that are rejected.
var deniedPrefixes = []string{
	"DYLD_",
	"GOCLAW_",
	"LD_",
}

// maxGrantEnvKeys is the maximum number of env keys allowed per grant.
const maxGrantEnvKeys = 50

// maxGrantEnvValueBytes is the maximum byte length for a single env value.
const maxGrantEnvValueBytes = 4096

// IsDeniedEnvKey reports whether key is on the grant env denylist.
// Comparison is case-insensitive.
func IsDeniedEnvKey(key string) bool {
	upper := strings.ToUpper(key)
	if _, ok := deniedExact[upper]; ok {
		return true
	}
	for _, pfx := range deniedPrefixes {
		if strings.HasPrefix(upper, pfx) {
			return true
		}
	}
	return false
}

// ValidateGrantEnvVars checks all keys and values in envVars against the denylist
// and value constraints.
//
// Returns rejectedKeys (non-nil when any key is denied) and valueErr (first value violation).
// Callers should check rejectedKeys before valueErr.
//
// Rules:
//   - Key count ≤ maxGrantEnvKeys
//   - Key not on denylist (case-insensitive)
//   - Value: no NUL byte, no newline, max maxGrantEnvValueBytes bytes
func ValidateGrantEnvVars(envVars map[string]string) (rejectedKeys []string, valueErr error) {
	if len(envVars) > maxGrantEnvKeys {
		return nil, fmt.Errorf("too many env keys: max %d, got %d", maxGrantEnvKeys, len(envVars))
	}
	var denied []string
	for k, v := range envVars {
		if IsDeniedEnvKey(k) {
			denied = append(denied, k)
		}
		if err := validateGrantEnvValue(v); err != nil {
			return nil, err
		}
	}
	return denied, nil
}

func validateGrantEnvValue(v string) error {
	if len(v) > maxGrantEnvValueBytes {
		return fmt.Errorf("env value exceeds %d bytes", maxGrantEnvValueBytes)
	}
	for _, c := range v {
		if c == 0 {
			return fmt.Errorf("env value must not contain NUL bytes")
		}
		if c == '\n' || c == '\r' {
			return fmt.Errorf("env value must not contain newlines")
		}
	}
	return nil
}
