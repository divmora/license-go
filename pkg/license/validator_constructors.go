package license

import (
	"crypto/ed25519"
	"strings"
)

// NewValidator creates a new Validator with the given primary Ed25519 public key and options.
func NewValidator(publicKey ed25519.PublicKey, opts ...ValidatorOption) (*Validator, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return nil, ErrMissingPublicKey
	}
	v := &Validator{
		keyRing:   NewKeyRing(publicKey),
		clockSkew: DefaultClockSkew,
	}
	for _, opt := range opts {
		opt(v)
	}
	if v.initErr != nil {
		return nil, v.initErr
	}
	return v, nil
}

// NewValidatorWithKeyRing creates a Validator using an existing KeyRing containing one or more trusted keys.
func NewValidatorWithKeyRing(ring *KeyRing, opts ...ValidatorOption) (*Validator, error) {
	if ring == nil || ring.Count() == 0 {
		return nil, ErrMissingPublicKey
	}
	v := &Validator{
		keyRing:   ring,
		clockSkew: DefaultClockSkew,
	}
	for _, opt := range opts {
		opt(v)
	}
	if v.initErr != nil {
		return nil, v.initErr
	}
	return v, nil
}

// NewValidatorFromPEM creates a Validator from PKIX PEM-encoded public key bytes.
// If the PEM data contains multiple public key blocks, all keys are loaded into the KeyRing,
// with the first key designated as Primary and subsequent keys designated as Retiring.
func NewValidatorFromPEM(pemBytes []byte, opts ...ValidatorOption) (*Validator, error) {
	ring, err := NewKeyRingFromPEM(pemBytes)
	if err != nil {
		return nil, err
	}
	return NewValidatorWithKeyRing(ring, opts...)
}

// NewValidatorFromPEMFile creates a Validator by loading Ed25519 public keys from a PEM file.
// If the file contains multiple public key blocks, all keys are loaded into the KeyRing.
func NewValidatorFromPEMFile(filePath string, opts ...ValidatorOption) (*Validator, error) {
	ring, err := NewKeyRingFromPEMFile(filePath)
	if err != nil {
		return nil, err
	}
	return NewValidatorWithKeyRing(ring, opts...)
}

// NewValidatorFromBase64 creates a Validator from a base64-encoded raw or PKIX public key string.
func NewValidatorFromBase64(pubB64 string, opts ...ValidatorOption) (*Validator, error) {
	pubKey, err := ParsePublicKeyFromBase64(pubB64)
	if err != nil {
		return nil, err
	}
	return NewValidator(pubKey, opts...)
}

// NewValidatorFromEmbeddedPEM creates a Validator using embedded PKIX PEM public key bytes.
// This is an alias/helper for NewValidatorFromPEM designed for compile-time //go:embed directives.
func NewValidatorFromEmbeddedPEM(pemBytes []byte, opts ...ValidatorOption) (*Validator, error) {
	return NewValidatorFromPEM(pemBytes, opts...)
}

// NewValidatorFromEnv creates a Validator by automatically resolving public verification keys
// from the environment (DIVMORA_PUBLIC_KEYS_PEM, DIVMORA_PUBLIC_KEY, DIVMORA_PUBLIC_KEY_FILE, /etc/divmora/public.pem),
// and applying any ValidatorOptions.
func NewValidatorFromEnv(opts ...ValidatorOption) (*Validator, error) {
	ring, err := ResolveKeyRing()
	if err != nil {
		return nil, err
	}
	return NewValidatorWithKeyRing(ring, opts...)
}

// NewValidatorWithFallbackKey creates a Validator using the specified fallback key (base64, PEM, or file path).
// By default, explicit fallback keys are treated as an immutable root of trust and cannot be overridden
// by environment variables (DIVMORA_PUBLIC_KEY, etc.) or default file paths, preventing trust root spoofing.
//
// To allow environment variables or system key files to override the fallback key, configure WithAllowEnvKeyOverride(true).
func NewValidatorWithFallbackKey(fallbackKey string, opts ...ValidatorOption) (*Validator, error) {
	// Programmatic override check (for test mocks)
	overrideKeyRingLock.RLock()
	override := overrideKeyRing
	overrideKeyRingLock.RUnlock()
	if override != nil {
		return NewValidatorWithKeyRing(override, opts...)
	}

	// Create temporary validator to inspect options (such as WithAllowEnvKeyOverride)
	tempV := &Validator{
		clockSkew: DefaultClockSkew,
	}
	for _, opt := range opts {
		opt(tempV)
	}
	if tempV.initErr != nil {
		return nil, tempV.initErr
	}

	allowOverride := tempV.allowEnvKeyOverride || IsAllowEnvKeyOverride()
	var fallbacks []string
	if strings.TrimSpace(fallbackKey) != "" {
		fallbacks = append(fallbacks, strings.TrimSpace(fallbackKey))
	}

	resolved, err := resolveKeyRingInternal(allowOverride, fallbacks...)
	if err != nil {
		return nil, err
	}
	return NewValidatorWithKeyRing(resolved.KeyRing, opts...)
}
