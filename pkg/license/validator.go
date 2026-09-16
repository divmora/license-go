package license

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

// DefaultClockSkew provides 5 minutes tolerance for system clock discrepancies.
const DefaultClockSkew = 5 * time.Minute

// Validator validates license tokens against an Ed25519 public key and evaluates claims.
type Validator struct {
	publicKey           ed25519.PublicKey
	expectedProduct     string
	clockSkew           time.Duration
	gracePeriod         time.Duration
	expectedFingerprint string
	requireFingerprint  bool
	currentEnvironment  string
	currentAccount      string
	currentRegion       string
	currentCluster      string
	currentNamespace    string
	currentHost         string
	currentCustomScope  map[string]string
	allowExpired        bool
	allowInactive       bool
}

// ValidatorOption is a functional option for configuring a Validator.
type ValidatorOption func(*Validator)

// WithProduct enforces that the license was issued for the specified product name.
func WithProduct(product string) ValidatorOption {
	return func(v *Validator) {
		v.expectedProduct = product
	}
}

// WithClockSkew configures the tolerance duration for clock drift between server and client.
func WithClockSkew(skew time.Duration) ValidatorOption {
	return func(v *Validator) {
		v.clockSkew = skew
	}
}

// WithGracePeriod allows a grace period duration after the expiration date before failing.
func WithGracePeriod(grace time.Duration) ValidatorOption {
	return func(v *Validator) {
		v.gracePeriod = grace
	}
}

// WithExpectedFingerprint enforces that the license fingerprint matches the node/cluster fingerprint.
func WithExpectedFingerprint(fingerprint string) ValidatorOption {
	return func(v *Validator) {
		v.expectedFingerprint = fingerprint
	}
}

// WithRequireFingerprint mandates that the license must be node-locked (rejects floating licenses).
func WithRequireFingerprint(require bool) ValidatorOption {
	return func(v *Validator) {
		v.requireFingerprint = require
	}
}

// WithCurrentEnvironment asserts that the current deployment environment matches Scope.Environments.
func WithCurrentEnvironment(env string) ValidatorOption {
	return func(v *Validator) {
		v.currentEnvironment = env
	}
}

// WithCurrentAccount asserts that the current cloud tenant or account ID matches Scope.Accounts.
func WithCurrentAccount(account string) ValidatorOption {
	return func(v *Validator) {
		v.currentAccount = account
	}
}

// WithCurrentRegion asserts that the current cloud/geographic region matches Scope.Regions.
func WithCurrentRegion(region string) ValidatorOption {
	return func(v *Validator) {
		v.currentRegion = region
	}
}

// WithCurrentCluster asserts that the current cluster identifier matches Scope.Clusters.
func WithCurrentCluster(cluster string) ValidatorOption {
	return func(v *Validator) {
		v.currentCluster = cluster
	}
}

// WithCurrentNamespace asserts that the current project/group hierarchy matches Scope.Namespaces.
func WithCurrentNamespace(namespace string) ValidatorOption {
	return func(v *Validator) {
		v.currentNamespace = namespace
	}
}

// WithCurrentHost asserts that the current hostname or domain matches Scope.Hosts.
func WithCurrentHost(host string) ValidatorOption {
	return func(v *Validator) {
		v.currentHost = host
	}
}

// WithCurrentCustomScope asserts that a custom dimension value matches Scope.Custom.
func WithCurrentCustomScope(dimension, value string) ValidatorOption {
	return func(v *Validator) {
		if v.currentCustomScope == nil {
			v.currentCustomScope = make(map[string]string)
		}
		v.currentCustomScope[dimension] = value
	}
}

// WithAllowExpired allows validating the cryptographic signature even if the license is expired.
func WithAllowExpired(allow bool) ValidatorOption {
	return func(v *Validator) {
		v.allowExpired = allow
	}
}

// WithAllowInactive allows validating the cryptographic signature even if NotBefore is in the future.
func WithAllowInactive(allow bool) ValidatorOption {
	return func(v *Validator) {
		v.allowInactive = allow
	}
}

// NewValidator creates a new Validator with the given Ed25519 public key and options.
func NewValidator(publicKey ed25519.PublicKey, opts ...ValidatorOption) (*Validator, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return nil, ErrMissingPublicKey
	}
	v := &Validator{
		publicKey: publicKey,
		clockSkew: DefaultClockSkew,
	}
	for _, opt := range opts {
		opt(v)
	}
	return v, nil
}

// NewValidatorFromPEM creates a Validator from PKIX PEM-encoded public key bytes.
func NewValidatorFromPEM(pemBytes []byte, opts ...ValidatorOption) (*Validator, error) {
	pubKey, err := ParsePublicKeyFromPEM(pemBytes)
	if err != nil {
		return nil, err
	}
	return NewValidator(pubKey, opts...)
}

// NewValidatorFromPEMFile creates a Validator by loading an Ed25519 public key from a PEM file.
func NewValidatorFromPEMFile(filePath string, opts ...ValidatorOption) (*Validator, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read public key file: %w", err)
	}
	return NewValidatorFromPEM(data, opts...)
}

// NewValidatorFromBase64 creates a Validator from a base64-encoded raw or PKIX public key string.
func NewValidatorFromBase64(pubB64 string, opts ...ValidatorOption) (*Validator, error) {
	pubKey, err := ParsePublicKeyFromBase64(pubB64)
	if err != nil {
		return nil, err
	}
	return NewValidator(pubKey, opts...)
}

// Verify decodes, verifies the cryptographic signature, and checks all claims against current time.
func (v *Validator) Verify(rawLicense string) (*Claims, error) {
	return v.VerifyAt(rawLicense, time.Now())
}

// VerifyFromFile loads a license from file and verifies it.
func (v *Validator) VerifyFromFile(filePath string) (*Claims, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read license file: %w", err)
	}
	return v.Verify(string(data))
}

// VerifyEnv resolves the license automatically from standard environment variables
// (DIVMORA_LICENSE_KEY, DIVMORA_LICENSE_FILE, or /etc/divmora/license.key) and validates it.
func (v *Validator) VerifyEnv() (*Claims, error) {
	resolved, err := ResolveLicense()
	if err != nil {
		return nil, err
	}
	return v.Verify(resolved.Content)
}

// VerifyResolved resolves a license from an explicit input (file path or token string)
// or falls back to standard environment variables, then verifies it.
func (v *Validator) VerifyResolved(explicitSource ...string) (*Claims, error) {
	resolved, err := ResolveLicense(explicitSource...)
	if err != nil {
		return nil, err
	}
	return v.Verify(resolved.Content)
}

// VerifyAt validates the license against the specified reference time `now`.
func (v *Validator) VerifyAt(rawLicense string, now time.Time) (*Claims, error) {
	if v.publicKey == nil {
		return nil, ErrMissingPublicKey
	}

	payloadJSON, sig, signedData, err := ParseToken(rawLicense)
	if err != nil {
		return nil, err
	}

	// 1. Verify cryptographic signature
	if !ed25519.Verify(v.publicKey, signedData, sig) {
		return nil, ErrInvalidSignature
	}

	// 2. Decode claims
	var claims Claims
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		return nil, fmt.Errorf("%w: failed to parse claims json: %v", ErrInvalidLicenseFormat, err)
	}

	// 3. Product match check
	if v.expectedProduct != "" && !claims.IsValidForProduct(v.expectedProduct) {
		return nil, fmt.Errorf("%w: expected %q, got %q", ErrProductMismatch, v.expectedProduct, claims.Product)
	}

	// 4. Fingerprint check
	if claims.Fingerprint != "" {
		if v.expectedFingerprint == "" {
			return nil, fmt.Errorf("%w: license is bound to node fingerprint %q, but no expected fingerprint was configured on validator", ErrFingerprintMismatch, claims.Fingerprint)
		}
		if !strings.EqualFold(claims.Fingerprint, v.expectedFingerprint) {
			return nil, fmt.Errorf("%w: expected %q, license bound to %q", ErrFingerprintMismatch, v.expectedFingerprint, claims.Fingerprint)
		}
	} else if v.requireFingerprint {
		return nil, fmt.Errorf("%w: validator requires node-locked license, but license has no fingerprint", ErrFingerprintMismatch)
	}

	// 5. NotBefore check (with clock skew)
	if !v.allowInactive && !claims.NotBefore.IsZero() {
		effectiveNotBefore := claims.NotBefore.Add(-v.clockSkew)
		if now.Before(effectiveNotBefore) {
			return nil, ErrNotYetValid
		}
	}

	// 6. Expiration check (with clock skew and grace period)
	if !v.allowExpired && !claims.IsPerpetual() {
		effectiveGrace := v.gracePeriod
		if claims.GracePeriodDays > 0 {
			claimGrace := time.Duration(claims.GracePeriodDays) * 24 * time.Hour
			if claimGrace > effectiveGrace {
				effectiveGrace = claimGrace
			}
		}

		effectiveExpiry := claims.ExpiresAt.Add(v.clockSkew).Add(effectiveGrace)
		if now.After(effectiveExpiry) {
			return nil, ErrExpired
		}
	}

	// 7. Scope constraints check
	if err := v.checkScope(&claims); err != nil {
		return nil, err
	}

	return &claims, nil
}

func (v *Validator) checkScope(claims *Claims) error {
	if claims.Scope != nil {
		// 1. Environments
		if len(claims.Scope.Environments) > 0 {
			targetEnv := v.currentEnvironment
			if targetEnv == "" {
				targetEnv = resolveEnvFromProcess()
			}
			if targetEnv == "" || !claims.IsEnvironmentAllowed(targetEnv) {
				return &ScopeMismatchError{Dimension: "environments", Allowed: claims.Scope.Environments, Target: targetEnv}
			}
		}

		// 2. Accounts
		if len(claims.Scope.Accounts) > 0 {
			targetAccount := v.currentAccount
			if targetAccount == "" {
				targetAccount = os.Getenv("AWS_ACCOUNT_ID")
			}
			if targetAccount == "" || !claims.IsAccountAllowed(targetAccount) {
				return &ScopeMismatchError{Dimension: "accounts", Allowed: claims.Scope.Accounts, Target: targetAccount}
			}
		}

		// 3. Regions
		if len(claims.Scope.Regions) > 0 {
			targetRegion := v.currentRegion
			if targetRegion == "" {
				targetRegion = resolveRegionFromProcess()
			}
			if targetRegion == "" || !claims.IsRegionAllowed(targetRegion) {
				return &ScopeMismatchError{Dimension: "regions", Allowed: claims.Scope.Regions, Target: targetRegion}
			}
		}

		// 4. Clusters
		if len(claims.Scope.Clusters) > 0 {
			if v.currentCluster == "" || !claims.IsClusterAllowed(v.currentCluster) {
				return &ScopeMismatchError{Dimension: "clusters", Allowed: claims.Scope.Clusters, Target: v.currentCluster}
			}
		}

		// 5. Namespaces
		if len(claims.Scope.Namespaces) > 0 {
			if v.currentNamespace == "" || !claims.IsNamespaceAllowed(v.currentNamespace) {
				return &ScopeMismatchError{Dimension: "namespaces", Allowed: claims.Scope.Namespaces, Target: v.currentNamespace}
			}
		}

		// 6. Hosts
		if len(claims.Scope.Hosts) > 0 {
			targetHost := v.currentHost
			if targetHost == "" {
				if h, err := os.Hostname(); err == nil {
					targetHost = h
				}
			}
			if targetHost == "" || !claims.IsHostAllowed(targetHost) {
				return &ScopeMismatchError{Dimension: "hosts", Allowed: claims.Scope.Hosts, Target: targetHost}
			}
		}

		// 7. Custom dimensions
		if claims.Scope.Custom != nil {
			for dim, allowed := range claims.Scope.Custom {
				if len(allowed) > 0 {
					target := v.currentCustomScope[dim]
					if target == "" || !matchesScopeSlice(allowed, target) {
						return &ScopeMismatchError{Dimension: dim, Allowed: allowed, Target: target}
					}
				}
			}
		}
	} else if claims.Environment != "" && v.currentEnvironment != "" {
		if !claims.IsEnvironmentAllowed(v.currentEnvironment) {
			return &ScopeMismatchError{Dimension: "environments", Allowed: []string{claims.Environment}, Target: v.currentEnvironment}
		}
	}
	return nil
}

func resolveEnvFromProcess() string {
	for _, k := range []string{"DIVMORA_ENV", "ENV", "ENVIRONMENT", "APP_ENV"} {
		if val := strings.TrimSpace(os.Getenv(k)); val != "" {
			return val
		}
	}
	return ""
}

func resolveRegionFromProcess() string {
	for _, k := range []string{"AWS_REGION", "AWS_DEFAULT_REGION"} {
		if val := strings.TrimSpace(os.Getenv(k)); val != "" {
			return val
		}
	}
	return ""
}

// VerificationResult encapsulates verified license claims alongside explicit grace period dynamics.
type VerificationResult struct {
	// Claims contains the verified payload fields.
	Claims *Claims

	// Status indicates the current operational status (ACTIVE, GRACE_PERIOD, EXPIRED, NOT_YET_VALID).
	Status Status

	// InGracePeriod reports whether the license is currently operating in grace period.
	InGracePeriod bool

	// GraceDaysRemaining indicates full days remaining in grace period before hard shutoff.
	GraceDaysRemaining int

	// EffectiveExpiry is the final cutoff timestamp including grace period.
	EffectiveExpiry time.Time
}

// VerifyWithResult validates the license and returns a detailed VerificationResult exposing grace period dynamics.
func (v *Validator) VerifyWithResult(rawLicense string) (*VerificationResult, error) {
	return v.VerifyWithResultAt(rawLicense, time.Now())
}

// VerifyWithResultAt validates the license against reference time `now` and returns a detailed VerificationResult.
func (v *Validator) VerifyWithResultAt(rawLicense string, now time.Time) (*VerificationResult, error) {
	claims, err := v.VerifyAt(rawLicense, now)
	if err != nil {
		return nil, err
	}

	return &VerificationResult{
		Claims:             claims,
		Status:             claims.StatusAt(now),
		InGracePeriod:      claims.IsInGracePeriodAt(now),
		GraceDaysRemaining: claims.GraceDaysRemainingAt(now),
		EffectiveExpiry:    claims.EffectiveExpiration(),
	}, nil
}

// Inspect decodes and returns the Claims from a raw or armored license string
// without verifying the cryptographic signature. Useful for diagnosis, logging, and metadata inspection.
func Inspect(rawLicense string) (*Claims, error) {
	payloadJSON, _, _, err := ParseToken(rawLicense)
	if err != nil {
		return nil, err
	}

	var claims Claims
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		return nil, fmt.Errorf("%w: failed to parse claims json: %v", ErrInvalidLicenseFormat, err)
	}

	if claims.Customer.Name == "" || claims.Product == "" {
		return nil, errors.New("license: malformed claims payload missing required fields")
	}

	return &claims, nil
}

// InspectFromFile reads a license file and unpacks the claims without verifying signature.
func InspectFromFile(filePath string) (*Claims, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read license file: %w", err)
	}
	return Inspect(string(data))
}
