package license

import (
	"errors"
	"fmt"
)

var (
	// ErrInvalidLicenseFormat is returned when the raw license string cannot be parsed or decoded.
	ErrInvalidLicenseFormat = errors.New("license: invalid license format")

	// ErrInvalidSignature is returned when the cryptographic signature does not match the payload.
	ErrInvalidSignature = errors.New("license: invalid signature")

	// ErrExpired is returned when the license expiration date has passed.
	ErrExpired = errors.New("license: license has expired")

	// ErrNotYetValid is returned when the license NotBefore date is in the future.
	ErrNotYetValid = errors.New("license: license is not yet valid")

	// ErrProductMismatch is returned when the license product does not match the expected product.
	ErrProductMismatch = errors.New("license: product mismatch")

	// ErrFeatureNotEntitled is returned when a requested feature is not granted by the license.
	ErrFeatureNotEntitled = errors.New("license: feature not entitled")

	// ErrLimitExceeded is returned when resource usage exceeds the maximum allowed quota.
	ErrLimitExceeded = errors.New("license: limit exceeded")

	// ErrMissingPublicKey is returned when public key is nil or invalid for verification.
	ErrMissingPublicKey = errors.New("license: missing public key")

	// ErrMissingPrivateKey is returned when private key is nil or invalid for signing.
	ErrMissingPrivateKey = errors.New("license: missing private key")

	// ErrFingerprintMismatch is returned when the license node/cluster fingerprint does not match the host.
	ErrFingerprintMismatch = errors.New("license: node fingerprint mismatch")

	// ErrLicenseNotFound is returned when no license data is found in the specified source or file.
	ErrLicenseNotFound = errors.New("license: license not found")

	// ErrScopeMismatch is returned when an environment, account, region, cluster, namespace, or host is not authorized by the license scope.
	ErrScopeMismatch = errors.New("license: scope mismatch")

	// ErrKeyRevoked is returned when a license was signed by a key that has been marked as revoked.
	ErrKeyRevoked = errors.New("license: signing key has been revoked")

	// ErrKeyNotFound is returned when a requested Key ID is not found in the KeyRing.
	ErrKeyNotFound = errors.New("license: key not found in keyring")
)

// LimitExceededError provides structured detail when a quota is exceeded.
type LimitExceededError struct {
	LimitName string
	Current   int64
	Allowed   int64
}

func (e *LimitExceededError) Error() string {
	return fmt.Sprintf("license: limit '%s' exceeded (current: %d, allowed: %d)", e.LimitName, e.Current, e.Allowed)
}

func (e *LimitExceededError) Is(target error) bool {
	return target == ErrLimitExceeded
}

// FeatureNotEntitledError provides detail when an unentitled feature is checked.
type FeatureNotEntitledError struct {
	Feature string
}

func (e *FeatureNotEntitledError) Error() string {
	return fmt.Sprintf("license: feature '%s' is not entitled in this license", e.Feature)
}

func (e *FeatureNotEntitledError) Is(target error) bool {
	return target == ErrFeatureNotEntitled
}

// ScopeMismatchError provides structured details when a scope constraint check fails.
type ScopeMismatchError struct {
	Dimension string
	Allowed   []string
	Target    string
}

func (e *ScopeMismatchError) Error() string {
	if e.Target == "" {
		return fmt.Sprintf("license: scope mismatch on %s: license restricted to %v, but no target was configured or detected on host", e.Dimension, e.Allowed)
	}
	return fmt.Sprintf("license: scope mismatch on %s: target %q is not authorized by %v", e.Dimension, e.Target, e.Allowed)
}

func (e *ScopeMismatchError) Is(target error) bool {
	return target == ErrScopeMismatch
}
