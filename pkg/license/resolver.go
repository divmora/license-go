package license

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
)

const (
	// EnvLicenseKey is the environment variable containing the raw compact token or armored PEM block.
	EnvLicenseKey = "DIVMORA_LICENSE_KEY"

	// EnvLicenseFile is the environment variable containing the path to a license file on disk.
	EnvLicenseFile = "DIVMORA_LICENSE_FILE"

	// DefaultLicensePath is the standard Linux/container filesystem path for Divmora licenses.
	DefaultLicensePath = "/etc/divmora/license.key"

	// EnvPublicKeysPEM is the environment variable containing a multi-key or single-key PKIX PEM bundle,
	// or a filesystem path to a PEM bundle file on disk.
	EnvPublicKeysPEM = "DIVMORA_PUBLIC_KEYS_PEM"

	// EnvPublicKey is the environment variable containing a single Ed25519 public key (base64-encoded raw
	// 32-byte key, base64 PKIX DER, or PKIX PEM string), or a filesystem path to a public key file on disk.
	EnvPublicKey = "DIVMORA_PUBLIC_KEY"

	// EnvPublicKeyFile is the environment variable containing a filesystem path to a public key or PEM bundle file on disk.
	EnvPublicKeyFile = "DIVMORA_PUBLIC_KEY_FILE"

	// DefaultPublicKeyPath is the standard Linux/container filesystem path for Divmora trusted public keys.
	DefaultPublicKeyPath = "/etc/divmora/public.pem"
)

var (
	overrideKeyRingLock sync.RWMutex
	overrideKeyRing     *KeyRing
)

// SetVerificationKeyRing configures an in-memory programmatic override KeyRing.
// When set, ResolveKeyRing and ResolvePublicKey return keys from this KeyRing immediately
// without checking environment variables or fallbacks. Primarily used in automated tests and embedded runtimes.
func SetVerificationKeyRing(ring *KeyRing) {
	overrideKeyRingLock.Lock()
	defer overrideKeyRingLock.Unlock()
	overrideKeyRing = ring
}

// SetVerificationPublicKey configures an in-memory programmatic single public key override.
// When set, ResolveKeyRing and ResolvePublicKey return a KeyRing containing this key.
func SetVerificationPublicKey(pub ed25519.PublicKey) {
	if len(pub) != ed25519.PublicKeySize {
		return
	}
	SetVerificationKeyRing(NewKeyRing(pub))
}

// ResetVerificationKeyRing clears any in-memory programmatic KeyRing override,
// returning resolution to environment variables and embedded fallbacks.
func ResetVerificationKeyRing() {
	overrideKeyRingLock.Lock()
	defer overrideKeyRingLock.Unlock()
	overrideKeyRing = nil
}

// ResetVerificationPublicKey clears any in-memory programmatic public key override.
func ResetVerificationPublicKey() {
	ResetVerificationKeyRing()
}

var (
	allowEnvKeyOverrideLock sync.RWMutex
	globalAllowEnvOverride  bool
)

// SetAllowEnvKeyOverride configures whether environment variables (e.g., DIVMORA_PUBLIC_KEY)
// or default system paths are permitted to override explicit fallback public keys globally.
// By default (false), explicit fallback keys are treated as an immutable root of trust
// to prevent public key trust root spoofing in untrusted deployment environments.
func SetAllowEnvKeyOverride(allow bool) {
	allowEnvKeyOverrideLock.Lock()
	defer allowEnvKeyOverrideLock.Unlock()
	globalAllowEnvOverride = allow
}

// IsAllowEnvKeyOverride returns whether environment variables are permitted to override explicit fallback keys.
func IsAllowEnvKeyOverride() bool {
	allowEnvKeyOverrideLock.RLock()
	defer allowEnvKeyOverrideLock.RUnlock()
	return globalAllowEnvOverride
}

// ResetAllowEnvKeyOverride resets the global environment key override setting to the secure default (false).
func ResetAllowEnvKeyOverride() {
	SetAllowEnvKeyOverride(false)
}

// ResolvedKeyRing contains the resolved KeyRing alongside origin metadata.
type ResolvedKeyRing struct {
	// KeyRing holds the collection of trusted public keys.
	KeyRing *KeyRing

	// Source identifies how the key was located (e.g., "programmatic_override",
	// "env:DIVMORA_PUBLIC_KEYS_PEM", "env:DIVMORA_PUBLIC_KEY", "env:DIVMORA_PUBLIC_KEY_FILE",
	// "default_file", "fallback").
	Source string

	// FilePath is non-empty if the key was resolved from a file on disk.
	FilePath string
}

// Primary returns the primary public key of the resolved KeyRing, or nil if empty.
func (r *ResolvedKeyRing) Primary() ed25519.PublicKey {
	if r != nil && r.KeyRing != nil && r.KeyRing.Primary() != nil {
		return r.KeyRing.Primary().PublicKey
	}
	return nil
}

// ResolvedLicense contains the resolved license contents and origin metadata.
type ResolvedLicense struct {
	// Content contains the raw compact token or armored PEM block text.
	Content string

	// FilePath is non-empty if the license was resolved from a file on disk (enabling hot-reloading).
	FilePath string

	// Source identifies how the license was located (e.g., "explicit_file", "explicit_token", "env:DIVMORA_LICENSE_KEY", "env:DIVMORA_LICENSE_FILE", "default_file").
	Source string
}

// ResolveLicense locates and reads a Divmora license following a standardized resolution hierarchy:
//  1. Explicit source argument (if provided and non-empty):
//     - If it points to an existing file, reads the file content (populating FilePath).
//     - If it starts with "DIV1." or "-----BEGIN", treats it as an inline token string.
//     - If it is neither, returns a file not found error.
//  2. DIVMORA_LICENSE_KEY environment variable (raw token or armored text string).
//  3. DIVMORA_LICENSE_FILE environment variable (path to license file on disk).
//  4. Default system license path (/etc/divmora/license.key) if it exists.
//  5. If none of the above succeed, returns ErrLicenseNotFound.
func ResolveLicense(explicitSource ...string) (*ResolvedLicense, error) {
	// 1. Check explicit source arguments in order
	for _, rawSrc := range explicitSource {
		src := strings.TrimSpace(rawSrc)
		if src == "" {
			continue
		}

		if fi, err := os.Lstat(src); err == nil && !fi.IsDir() {
			if fi.Mode()&os.ModeSymlink != 0 {
				return nil, fmt.Errorf("%w: license file %s is a symlink", ErrSymlinkNotAllowed, src)
			}
			data, err := os.ReadFile(src)
			if err != nil {
				return nil, fmt.Errorf("failed to read license file %s: %w", src, err)
			}
			return &ResolvedLicense{
				Content:  string(data),
				FilePath: src,
				Source:   "explicit_file",
			}, nil
		}

		if strings.HasPrefix(src, VersionPrefix+".") || strings.Contains(src, ArmoredHeader) {
			return &ResolvedLicense{
				Content:  src,
				FilePath: "",
				Source:   "explicit_token",
			}, nil
		}

		return nil, fmt.Errorf("license file %q not found: %w", src, os.ErrNotExist)
	}

	// 2. Check DIVMORA_LICENSE_KEY environment variable
	if envKey := strings.TrimSpace(os.Getenv(EnvLicenseKey)); envKey != "" {
		return &ResolvedLicense{
			Content:  envKey,
			FilePath: "",
			Source:   "env:" + EnvLicenseKey,
		}, nil
	}

	// 3. Check DIVMORA_LICENSE_FILE environment variable
	if envFile := strings.TrimSpace(os.Getenv(EnvLicenseFile)); envFile != "" {
		if fi, err := os.Lstat(envFile); err == nil {
			if fi.Mode()&os.ModeSymlink != 0 {
				return nil, fmt.Errorf("%w: license file %s is a symlink", ErrSymlinkNotAllowed, envFile)
			}
		}
		data, err := os.ReadFile(envFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read license file from %s (%s): %w", EnvLicenseFile, envFile, err)
		}
		return &ResolvedLicense{
			Content:  string(data),
			FilePath: envFile,
			Source:   "env:" + EnvLicenseFile,
		}, nil
	}

	// 4. Check DefaultLicensePath (/etc/divmora/license.key)
	if fi, err := os.Lstat(DefaultLicensePath); err == nil && !fi.IsDir() {
		if fi.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("%w: default license file %s is a symlink", ErrSymlinkNotAllowed, DefaultLicensePath)
		}
		data, err := os.ReadFile(DefaultLicensePath)
		if err == nil {
			return &ResolvedLicense{
				Content:  string(data),
				FilePath: DefaultLicensePath,
				Source:   "default_file",
			}, nil
		}
	}

	return nil, ErrLicenseNotFound
}

// ResolveToken returns the license token content string using the standard resolution hierarchy.
func ResolveToken(explicitSource ...string) (string, error) {
	resolved, err := ResolveLicense(explicitSource...)
	if err != nil {
		return "", err
	}
	return resolved.Content, nil
}

// ParseKeyRingFromString parses public key(s) from a string that may contain PEM blocks,
// base64-encoded raw/DER keys, or a filesystem path to a key file.
func ParseKeyRingFromString(s string) (*KeyRing, error) {
	trimmed := strings.TrimSpace(s)
	if trimmed == "" {
		return nil, ErrMissingPublicKey
	}

	// 1. If it contains PEM header
	if strings.Contains(trimmed, "-----BEGIN") {
		return NewKeyRingFromPEM([]byte(trimmed))
	}

	// 2. If it points to an existing file on disk
	if fi, err := os.Stat(trimmed); err == nil && !fi.IsDir() {
		data, err := os.ReadFile(trimmed)
		if err != nil {
			return nil, fmt.Errorf("failed to read key file %s: %w", trimmed, err)
		}
		// Try PEM first
		if ring, err := NewKeyRingFromPEM(data); err == nil {
			return ring, nil
		}
		// Try Base64
		pub, err := ParsePublicKeyFromBase64(strings.TrimSpace(string(data)))
		if err == nil {
			return NewKeyRing(pub), nil
		}
		return nil, fmt.Errorf("failed to parse public key from file %s: invalid PEM or Base64 format", trimmed)
	}

	// 3. Try base64 decoding (raw 32-byte Ed25519 or PKIX DER)
	pub, err := ParsePublicKeyFromBase64(trimmed)
	if err == nil {
		return NewKeyRing(pub), nil
	}

	return nil, fmt.Errorf("unable to parse public key: %w", err)
}

// ParsePublicKeyFromString parses an Ed25519 public key from a string which can be a filesystem path,
// a PKIX PEM block, or a base64-encoded string.
func ParsePublicKeyFromString(s string) (ed25519.PublicKey, error) {
	ring, err := ParseKeyRingFromString(s)
	if err != nil {
		return nil, err
	}
	if ring.Primary() == nil {
		return nil, ErrMissingPublicKey
	}
	return ring.Primary().PublicKey, nil
}

// ResolveKeyRingWithSource locates and resolves trusted public verification keys following a standardized hierarchy:
//  0. In-memory programmatic override (via SetVerificationKeyRing or SetVerificationPublicKey).
//  1. Explicit fallback keys (when provided and !IsAllowEnvKeyOverride()), treating explicit keys as the authoritative
//     root of trust to prevent environment-based trust root spoofing.
//  2. DIVMORA_PUBLIC_KEYS_PEM environment variable (multi-key PKIX PEM bundle string or file path).
//  3. DIVMORA_PUBLIC_KEY environment variable (base64-encoded raw/DER key, inline PEM string, or file path).
//  4. DIVMORA_PUBLIC_KEY_FILE environment variable (path to public key file on disk).
//  5. Default system public key path (/etc/divmora/public.pem) if it exists.
//  6. Fallback keys (if IsAllowEnvKeyOverride() is true and no environment key was configured).
//  7. If none succeed, returns ErrPublicKeyNotFound wrapping ErrMissingPublicKey.
func ResolveKeyRingWithSource(fallbackKeys ...string) (*ResolvedKeyRing, error) {
	return resolveKeyRingInternal(IsAllowEnvKeyOverride(), fallbackKeys...)
}

// ResolveKeyRingWithEnvPrecedence resolves trusted keys giving precedence to environment variables
// (DIVMORA_PUBLIC_KEYS_PEM, DIVMORA_PUBLIC_KEY, DIVMORA_PUBLIC_KEY_FILE, /etc/divmora/public.pem)
// before falling back to any provided fallbackKeys.
func ResolveKeyRingWithEnvPrecedence(fallbackKeys ...string) (*ResolvedKeyRing, error) {
	return resolveKeyRingInternal(true, fallbackKeys...)
}

func resolveKeyRingInternal(allowEnvOverride bool, fallbackKeys ...string) (*ResolvedKeyRing, error) {
	// 0. Programmatic in-memory override (for automated tests and runtime mocks)
	overrideKeyRingLock.RLock()
	if overrideKeyRing != nil {
		ring := overrideKeyRing
		overrideKeyRingLock.RUnlock()
		return &ResolvedKeyRing{
			KeyRing: ring,
			Source:  "programmatic_override",
		}, nil
	}
	overrideKeyRingLock.RUnlock()

	var nonBlankFallbacks []string
	for _, fb := range fallbackKeys {
		if trimmed := strings.TrimSpace(fb); trimmed != "" {
			nonBlankFallbacks = append(nonBlankFallbacks, trimmed)
		}
	}

	// 1. If explicit fallback keys are provided and env override is disabled (default):
	// Embedded keys take immediate precedence as the authoritative root of trust.
	if len(nonBlankFallbacks) > 0 && !allowEnvOverride {
		return parseFallbackKeys(nonBlankFallbacks)
	}

	// 2. Check environment variables and default system path
	resolvedEnv, err := resolveKeyRingFromEnv()
	if err == nil {
		return resolvedEnv, nil
	}
	if !errors.Is(err, ErrPublicKeyNotFound) {
		return nil, err
	}

	// 3. Fallback keys when env override is enabled but no environment key was configured
	if len(nonBlankFallbacks) > 0 {
		return parseFallbackKeys(nonBlankFallbacks)
	}

	return nil, fmt.Errorf("%w: %w (pass public key or set %s / %s)", ErrPublicKeyNotFound, ErrMissingPublicKey, EnvPublicKey, EnvPublicKeysPEM)
}

func parseFallbackKeys(fallbacks []string) (*ResolvedKeyRing, error) {
	var allFallbackKeys []ed25519.PublicKey
	for _, fb := range fallbacks {
		ring, err := ParseKeyRingFromString(fb)
		if err != nil {
			return nil, fmt.Errorf("failed to parse fallback public key %q: %w", fb, err)
		}
		for _, entry := range ring.Keys() {
			allFallbackKeys = append(allFallbackKeys, entry.PublicKey)
		}
	}

	if len(allFallbackKeys) > 0 {
		ring := NewKeyRing(allFallbackKeys[0], allFallbackKeys[1:]...)
		return &ResolvedKeyRing{
			KeyRing: ring,
			Source:  "fallback",
		}, nil
	}

	return nil, fmt.Errorf("%w: %w (no valid fallback keys provided)", ErrPublicKeyNotFound, ErrMissingPublicKey)
}

func resolveKeyRingFromEnv() (*ResolvedKeyRing, error) {
	// 1. DIVMORA_PUBLIC_KEYS_PEM (multi-key PKIX PEM bundle or file path)
	if pemVal := strings.TrimSpace(os.Getenv(EnvPublicKeysPEM)); pemVal != "" {
		if fi, err := os.Lstat(pemVal); err == nil && !fi.IsDir() {
			if fi.Mode()&os.ModeSymlink != 0 {
				return nil, fmt.Errorf("%w: public key bundle file %s is a symlink", ErrSymlinkNotAllowed, pemVal)
			}
			data, err := os.ReadFile(pemVal)
			if err != nil {
				return nil, fmt.Errorf("failed to read key bundle file from %s (%s): %w", EnvPublicKeysPEM, pemVal, err)
			}
			ring, err := NewKeyRingFromPEM(data)
			if err != nil {
				return nil, fmt.Errorf("failed to parse key bundle file from %s (%s): %w", EnvPublicKeysPEM, pemVal, err)
			}
			return &ResolvedKeyRing{
				KeyRing:  ring,
				Source:   "env:" + EnvPublicKeysPEM,
				FilePath: pemVal,
			}, nil
		}
		ring, err := NewKeyRingFromPEM([]byte(pemVal))
		if err != nil {
			return nil, fmt.Errorf("failed to parse PEM bundle from %s: %w", EnvPublicKeysPEM, err)
		}
		return &ResolvedKeyRing{
			KeyRing: ring,
			Source:  "env:" + EnvPublicKeysPEM,
		}, nil
	}

	// 2. DIVMORA_PUBLIC_KEY (base64 single key, PEM block, or file path)
	if keyVal := strings.TrimSpace(os.Getenv(EnvPublicKey)); keyVal != "" {
		if fi, err := os.Lstat(keyVal); err == nil && !fi.IsDir() {
			if fi.Mode()&os.ModeSymlink != 0 {
				return nil, fmt.Errorf("%w: public key file %s is a symlink", ErrSymlinkNotAllowed, keyVal)
			}
			ring, err := ParseKeyRingFromString(keyVal)
			if err != nil {
				return nil, fmt.Errorf("failed to parse key file from %s (%s): %w", EnvPublicKey, keyVal, err)
			}
			return &ResolvedKeyRing{
				KeyRing:  ring,
				Source:   "env:" + EnvPublicKey,
				FilePath: keyVal,
			}, nil
		}
		ring, err := ParseKeyRingFromString(keyVal)
		if err != nil {
			return nil, fmt.Errorf("failed to parse public key from %s: %w", EnvPublicKey, err)
		}
		return &ResolvedKeyRing{
			KeyRing: ring,
			Source:  "env:" + EnvPublicKey,
		}, nil
	}

	// 3. DIVMORA_PUBLIC_KEY_FILE (path to public key or PEM bundle on disk)
	if fileVal := strings.TrimSpace(os.Getenv(EnvPublicKeyFile)); fileVal != "" {
		if fi, err := os.Lstat(fileVal); err == nil {
			if fi.Mode()&os.ModeSymlink != 0 {
				return nil, fmt.Errorf("%w: public key file %s is a symlink", ErrSymlinkNotAllowed, fileVal)
			}
		}
		data, err := os.ReadFile(fileVal)
		if err != nil {
			return nil, fmt.Errorf("failed to read public key file from %s (%s): %w", EnvPublicKeyFile, fileVal, err)
		}
		ring, err := ParseKeyRingFromString(string(data))
		if err != nil {
			return nil, fmt.Errorf("failed to parse public key file from %s (%s): %w", EnvPublicKeyFile, fileVal, err)
		}
		return &ResolvedKeyRing{
			KeyRing:  ring,
			Source:   "env:" + EnvPublicKeyFile,
			FilePath: fileVal,
		}, nil
	}

	// 4. Default Linux/container system path (/etc/divmora/public.pem)
	if fi, err := os.Lstat(DefaultPublicKeyPath); err == nil && !fi.IsDir() {
		if fi.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("%w: default public key file %s is a symlink", ErrSymlinkNotAllowed, DefaultPublicKeyPath)
		}
		data, err := os.ReadFile(DefaultPublicKeyPath)
		if err == nil {
			if ring, err := NewKeyRingFromPEM(data); err == nil {
				return &ResolvedKeyRing{
					KeyRing:  ring,
					Source:   "default_file",
					FilePath: DefaultPublicKeyPath,
				}, nil
			}
		}
	}

	return nil, ErrPublicKeyNotFound
}

// ResolveKeyRing resolves the KeyRing containing trusted public verification keys using the standard resolution hierarchy.
func ResolveKeyRing(fallbackKeys ...string) (*KeyRing, error) {
	resolved, err := ResolveKeyRingWithSource(fallbackKeys...)
	if err != nil {
		return nil, err
	}
	return resolved.KeyRing, nil
}

// ResolvePublicKey resolves the primary Ed25519 public verification key using the standard resolution hierarchy.
func ResolvePublicKey(fallbackKeys ...string) (ed25519.PublicKey, error) {
	ring, err := ResolveKeyRing(fallbackKeys...)
	if err != nil {
		return nil, err
	}
	if ring.Primary() == nil {
		return nil, ErrMissingPublicKey
	}
	return ring.Primary().PublicKey, nil
}
