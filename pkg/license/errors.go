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

	// ErrVersionNotEntitled is returned when the running software version is not authorized by the license.
	ErrVersionNotEntitled = errors.New("license: software version not entitled")

	// ErrMaintenanceExpired is returned when the running binary release/build date is past the maintenance entitlement period.
	ErrMaintenanceExpired = errors.New("license: software maintenance/update period has expired")

	// ErrClockTamperingDetected is returned when local system clock contradicts authoritative server time.
	ErrClockTamperingDetected = errors.New("license: clock tampering detected; local clock contradicts authoritative server time")

	// ErrDegradedMode is returned when an operation is restricted because the license manager is operating in degraded mode.
	ErrDegradedMode = errors.New("license: operating in degraded mode")

	// ErrDegradedReadOnly is returned when a mutation or write operation is attempted while in degraded read-only mode.
	ErrDegradedReadOnly = errors.New("license: operating in degraded read-only mode; mutations not permitted")
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

// VersionNotEntitledError provides structured details when a version authorization check fails.
type VersionNotEntitledError struct {
	CurrentVersion string
	MaxVersion     string
	Allowed        []string
}

func (e *VersionNotEntitledError) Error() string {
	if e.MaxVersion != "" {
		return fmt.Sprintf("license: software version %q is not entitled (maximum authorized version is %q)", e.CurrentVersion, e.MaxVersion)
	}
	if len(e.Allowed) > 0 {
		return fmt.Sprintf("license: software version %q is not entitled (authorized versions: %v)", e.CurrentVersion, e.Allowed)
	}
	return fmt.Sprintf("license: software version %q is not entitled under this license", e.CurrentVersion)
}

func (e *VersionNotEntitledError) Is(target error) bool {
	return target == ErrVersionNotEntitled
}

// MaintenanceExpiredError provides structured details when a binary release date exceeds the maintenance cutoff.
type MaintenanceExpiredError struct {
	BuildDate            string
	MaintenanceExpiresAt string
}

func (e *MaintenanceExpiredError) Error() string {
	return fmt.Sprintf("license: software build date %s exceeds maintenance cutoff date %s; upgrades not entitled", e.BuildDate, e.MaintenanceExpiresAt)
}

func (e *MaintenanceExpiredError) Is(target error) bool {
	return target == ErrMaintenanceExpired
}
