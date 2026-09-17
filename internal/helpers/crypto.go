package helpers

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"strings"
)

// ConstantTimeFingerprintMatch performs a constant-time case-insensitive string comparison
// between two fingerprints to prevent timing side-channel attacks.
func ConstantTimeFingerprintMatch(a, b string) bool {
	if len(a) == 0 || len(b) == 0 {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(strings.ToLower(a)), []byte(strings.ToLower(b))) == 1
}

// GenerateRandomID produces a secure 16-byte random hex string using cryptographic randomness.
func GenerateRandomID() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate random ID: %w", err)
	}
	return hex.EncodeToString(bytes), nil
}
