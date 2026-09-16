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

// Validator validates license tokens against trusted Ed25519 public keys in a KeyRing and evaluates claims.
type Validator struct {
	keyRing             *KeyRing
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
	currentVersion      string
	buildDate           time.Time
	bslPolicy           *BSLPolicy
	authoritativeTime   time.Time
	maxClockDrift       time.Duration
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

// WithCurrentVersion asserts that the running software version satisfies the license version constraints (MaxVersion / AllowedVersions).
func WithCurrentVersion(version string) ValidatorOption {
	return func(v *Validator) {
		v.currentVersion = strings.TrimSpace(version)
	}
}

// WithBuildDate asserts that the binary build/release date is within the license maintenance window (MaintenanceExpiresAt).
func WithBuildDate(buildDate time.Time) ValidatorOption {
	return func(v *Validator) {
		v.buildDate = buildDate
	}
}

// WithBSLPolicy configures Business Source License (BSL 1.1) terms and automatic open-source conversion.
func WithBSLPolicy(policy BSLPolicy) ValidatorOption {
	return func(v *Validator) {
		v.bslPolicy = &policy
	}
}

// WithAuthoritativeTime sets an authoritative reference time (e.g., from an HTTP Date header or cloud API)
// to defend against local system clock manipulation and false BSL conversion claims.
func WithAuthoritativeTime(t time.Time) ValidatorOption {
	return func(v *Validator) {
		v.authoritativeTime = t
	}
}

// WithMaxClockDrift configures the tolerance threshold before the local clock is anchored to authoritative time (default: 1 hour).
func WithMaxClockDrift(drift time.Duration) ValidatorOption {
	return func(v *Validator) {
		v.maxClockDrift = drift
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

// WithKeyRing configures the validator to use a custom KeyRing containing trusted keys.
func WithKeyRing(ring *KeyRing) ValidatorOption {
	return func(v *Validator) {
		if ring != nil {
			v.keyRing = ring
		}
	}
}

// WithAdditionalPublicKeys registers secondary or fallback public keys in the validator's KeyRing.
func WithAdditionalPublicKeys(keys ...ed25519.PublicKey) ValidatorOption {
	return func(v *Validator) {
		if v.keyRing == nil {
			v.keyRing = NewKeyRing(nil)
		}
		for _, k := range keys {
			_, _ = v.keyRing.AddKey(k, WithKeyStatus(KeyStatusRetiring))
		}
	}
}

// WithAdditionalPublicKeyPEM parses and registers all public keys from a PEM bundle byte slice into the validator's KeyRing.
func WithAdditionalPublicKeyPEM(pemBytes []byte) ValidatorOption {
	return func(v *Validator) {
		keys, err := ParsePublicKeysFromPEM(pemBytes)
		if err == nil {
			for _, k := range keys {
				if v.keyRing == nil {
					v.keyRing = NewKeyRing(k)
				} else {
					_, _ = v.keyRing.AddKey(k, WithKeyStatus(KeyStatusRetiring))
				}
			}
		}
	}
}

// WithRevokedKeyIDs marks the specified Key IDs or fingerprints as REVOKED in the validator's KeyRing.
func WithRevokedKeyIDs(ids ...string) ValidatorOption {
	return func(v *Validator) {
		if v.keyRing != nil {
			for _, id := range ids {
				_ = v.keyRing.Revoke(id)
			}
		}
	}
}

// PublicKey returns the primary public key in the validator's KeyRing, or nil if none is configured.
func (v *Validator) PublicKey() ed25519.PublicKey {
	if v.keyRing != nil && v.keyRing.Primary() != nil {
		return v.keyRing.Primary().PublicKey
	}
	return nil
}

// KeyRing returns the KeyRing instance used by the validator.
func (v *Validator) KeyRing() *KeyRing {
	return v.keyRing
}

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

// NewValidatorWithFallbackKey creates a Validator by automatically resolving public verification keys
// from the environment, falling back to the specified key string (base64, PEM, or file path) if no environment variable is set.
func NewValidatorWithFallbackKey(fallbackKey string, opts ...ValidatorOption) (*Validator, error) {
	var fallbacks []string
	if strings.TrimSpace(fallbackKey) != "" {
		fallbacks = append(fallbacks, strings.TrimSpace(fallbackKey))
	}
	ring, err := ResolveKeyRing(fallbacks...)
	if err != nil {
		return nil, err
	}
	return NewValidatorWithKeyRing(ring, opts...)
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

// resolveEvaluationTime reconciles the local reference time with any configured authoritative time,
// detecting forward clock tampering attempts while respecting clock drift boundaries.
func (v *Validator) resolveEvaluationTime(localNow time.Time) (evalTime time.Time, tampered bool) {
	evalTime = localNow
	if v.authoritativeTime.IsZero() {
		return evalTime, false
	}

	authTime := v.authoritativeTime.UTC()
	localUTC := localNow.UTC()

	// 1. Forward Clock Tampering Detection:
	// Local clock claims BSL Change Date has arrived, but authoritative server clock attests it has not!
	if v.bslPolicy != nil && v.bslPolicy.IsConverted(localUTC) && !v.bslPolicy.IsConverted(authTime) {
		return authTime, true
	}

	// 2. Significant Clock Drift Check:
	driftLimit := v.maxClockDrift
	if driftLimit <= 0 {
		driftLimit = time.Hour
	}
	drift := localUTC.Sub(authTime)
	if drift < -driftLimit || drift > driftLimit {
		return authTime, false
	}

	return evalTime, false
}

// VerifyEnv resolves the license automatically from standard environment variables
// (DIVMORA_LICENSE_KEY, DIVMORA_LICENSE_FILE, or /etc/divmora/license.key) and validates it.
// If the BSL 1.1 Change Date has arrived, open-source entitlements are granted automatically.
func (v *Validator) VerifyEnv() (*Claims, error) {
	evalTime, _ := v.resolveEvaluationTime(time.Now())
	if v.bslPolicy != nil && v.bslPolicy.IsConverted(evalTime) {
		return &Claims{
			Product:  v.expectedProduct,
			Plan:     "open-source",
			Customer: Customer{Name: "Open Source Community"},
			Features: []string{"*"},
			Limits:   map[string]int64{},
		}, nil
	}

	resolved, err := ResolveLicense()
	if err != nil {
		return nil, err
	}
	return v.VerifyAt(resolved.Content, time.Now())
}

// VerifyResolved resolves a license from an explicit input (file path or token string)
// or falls back to standard environment variables, then verifies it.
func (v *Validator) VerifyResolved(explicitSource ...string) (*Claims, error) {
	evalTime, _ := v.resolveEvaluationTime(time.Now())
	if v.bslPolicy != nil && v.bslPolicy.IsConverted(evalTime) {
		resolved, err := ResolveLicense(explicitSource...)
		if err == nil {
			return v.VerifyAt(resolved.Content, time.Now())
		}
		return &Claims{
			Product:  v.expectedProduct,
			Plan:     "open-source",
			Customer: Customer{Name: "Open Source Community"},
			Features: []string{"*"},
			Limits:   map[string]int64{},
		}, nil
	}

	resolved, err := ResolveLicense(explicitSource...)
	if err != nil {
		return nil, err
	}
	return v.VerifyAt(resolved.Content, time.Now())
}

// VerifyAt validates the license against the specified reference time `now`.
func (v *Validator) VerifyAt(rawLicense string, now time.Time) (*Claims, error) {
	evalTime, _ := v.resolveEvaluationTime(now)

	// 0. Automatic BSL 1.1 Change Date Check (Apache 2.0 Conversion)
	if v.bslPolicy != nil && v.bslPolicy.IsConverted(evalTime) {
		if strings.TrimSpace(rawLicense) == "" {
			return &Claims{
				Product:  v.expectedProduct,
				Plan:     "open-source",
				Customer: Customer{Name: "Open Source Community"},
				Features: []string{"*"},
				Limits:   map[string]int64{},
			}, nil
		}

		vCopy := *v
		vCopy.allowExpired = true
		claims, err := vCopy.verifyTokenPayload(rawLicense, evalTime)
		if err == nil {
			return claims, nil
		}
		return &Claims{
			Product:  v.expectedProduct,
			Plan:     "open-source",
			Customer: Customer{Name: "Open Source Community"},
			Features: []string{"*"},
			Limits:   map[string]int64{},
		}, nil
	}

	if strings.TrimSpace(rawLicense) == "" {
		return nil, ErrLicenseNotFound
	}

	return v.verifyTokenPayload(rawLicense, evalTime)
}

func (v *Validator) verifyTokenPayload(rawLicense string, evalTime time.Time) (*Claims, error) {
	if v.keyRing == nil || v.keyRing.Count() == 0 {
		return nil, ErrMissingPublicKey
	}

	payloadJSON, sig, signedData, err := ParseToken(rawLicense)
	if err != nil {
		return nil, err
	}

	var kidHint string
	var peekClaims struct {
		KeyID string `json:"kid"`
	}
	if err := json.Unmarshal(payloadJSON, &peekClaims); err == nil {
		kidHint = peekClaims.KeyID
	}

	// 1. Verify cryptographic signature against KeyRing
	if _, err := v.keyRing.VerifySignature(signedData, sig, kidHint); err != nil {
		return nil, err
	}

	// 2-9. Evaluate claims
	return v.verifyClaims(payloadJSON, evalTime)
}

func (v *Validator) verifyClaims(payloadJSON []byte, now time.Time) (*Claims, error) {
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

	// 8. Version constraints check
	if v.currentVersion != "" && !claims.IsVersionAllowed(v.currentVersion) {
		return nil, &VersionNotEntitledError{
			CurrentVersion: v.currentVersion,
			MaxVersion:     claims.MaxVersion,
			Allowed:        claims.AllowedVersions,
		}
	}

	// 9. Maintenance / Support update cutoff check
	if !v.buildDate.IsZero() && claims.HasMaintenanceExpired(v.buildDate) {
		return nil, &MaintenanceExpiredError{
			BuildDate:            v.buildDate.Format(time.RFC3339),
			MaintenanceExpiresAt: claims.MaintenanceExpiresAt.Format(time.RFC3339),
		}
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

// VerificationResult encapsulates verified license claims alongside explicit grace period dynamics,
// key rotation metadata, and BSL 1.1 open-source transition state.
type VerificationResult struct {
	// Claims contains the verified payload fields.
	Claims *Claims

	// Status indicates the current operational status (ACTIVE, GRACE_PERIOD, EXPIRED, NOT_YET_VALID).
	Status Status

	// VerifiedByKeyID identifies the Key ID or fingerprint that successfully verified the cryptographic signature.
	VerifiedByKeyID string

	// VerifiedByKeyStatus indicates the lifecycle status (ACTIVE, RETIRING) of the verifying key.
	VerifiedByKeyStatus KeyStatus

	// InGracePeriod reports whether the license is currently operating in grace period.
	InGracePeriod bool

	// GraceDaysRemaining indicates full days remaining in grace period before hard shutoff.
	GraceDaysRemaining int

	// EffectiveExpiry is the final cutoff timestamp including grace period.
	EffectiveExpiry time.Time

	// BSLConverted indicates whether the software has automatically transitioned to open-source under BSL terms.
	BSLConverted bool

	// EffectiveLicense indicates the governing license identifier ("BSL-1.1" or "Apache-2.0").
	EffectiveLicense string

	// ChangeDate is the timestamp when the software converts to open source under BSL terms.
	ChangeDate time.Time

	// ClockTampered indicates that local system clock contradicted authoritative server time.
	ClockTampered bool
}

// VerifyWithResult validates the license and returns a detailed VerificationResult exposing grace period dynamics.
func (v *Validator) VerifyWithResult(rawLicense string) (*VerificationResult, error) {
	return v.VerifyWithResultAt(rawLicense, time.Now())
}

// VerifyWithResultAt validates the license against reference time `now` and returns a detailed VerificationResult.
func (v *Validator) VerifyWithResultAt(rawLicense string, now time.Time) (*VerificationResult, error) {
	evalTime, tampered := v.resolveEvaluationTime(now)

	var changeDate time.Time
	effectiveLic := DefaultBSLLicense
	if v.bslPolicy != nil {
		changeDate = v.bslPolicy.ChangeDate()
		effectiveLic = v.bslPolicy.EffectiveLicense(evalTime)
	}

	// 0. Automatic BSL 1.1 Change Date Check
	if v.bslPolicy != nil && v.bslPolicy.IsConverted(evalTime) {
		if strings.TrimSpace(rawLicense) == "" {
			claims := &Claims{
				Product:  v.expectedProduct,
				Plan:     "open-source",
				Customer: Customer{Name: "Open Source Community"},
				Features: []string{"*"},
				Limits:   map[string]int64{},
			}
			return &VerificationResult{
				Claims:           claims,
				Status:           StatusActive,
				BSLConverted:     true,
				EffectiveLicense: effectiveLic,
				ChangeDate:       changeDate,
				ClockTampered:    tampered,
			}, nil
		}

		vCopy := *v
		vCopy.allowExpired = true
		claims, err := vCopy.verifyTokenPayload(rawLicense, evalTime)
		if err == nil {
			return &VerificationResult{
				Claims:           claims,
				Status:           StatusActive,
				BSLConverted:     true,
				EffectiveLicense: effectiveLic,
				ChangeDate:       changeDate,
				ClockTampered:    tampered,
			}, nil
		}

		claims = &Claims{
			Product:  v.expectedProduct,
			Plan:     "open-source",
			Customer: Customer{Name: "Open Source Community"},
			Features: []string{"*"},
			Limits:   map[string]int64{},
		}
		return &VerificationResult{
			Claims:           claims,
			Status:           StatusActive,
			BSLConverted:     true,
			EffectiveLicense: effectiveLic,
			ChangeDate:       changeDate,
			ClockTampered:    tampered,
		}, nil
	}

	if strings.TrimSpace(rawLicense) == "" {
		return nil, ErrLicenseNotFound
	}

	if v.keyRing == nil || v.keyRing.Count() == 0 {
		return nil, ErrMissingPublicKey
	}

	payloadJSON, sig, signedData, err := ParseToken(rawLicense)
	if err != nil {
		return nil, err
	}

	var kidHint string
	var peekClaims struct {
		KeyID string `json:"kid"`
	}
	if err := json.Unmarshal(payloadJSON, &peekClaims); err == nil {
		kidHint = peekClaims.KeyID
	}

	matchedKey, err := v.keyRing.VerifySignature(signedData, sig, kidHint)
	if err != nil {
		return nil, err
	}

	claims, err := v.verifyClaims(payloadJSON, evalTime)
	if err != nil {
		return nil, err
	}

	return &VerificationResult{
		Claims:              claims,
		Status:              claims.StatusAt(evalTime),
		VerifiedByKeyID:     matchedKey.ID,
		VerifiedByKeyStatus: matchedKey.Status,
		InGracePeriod:       claims.IsInGracePeriodAt(evalTime),
		GraceDaysRemaining:  claims.GraceDaysRemainingAt(evalTime),
		EffectiveExpiry:     claims.EffectiveExpiration(),
		BSLConverted:        false,
		EffectiveLicense:    effectiveLic,
		ChangeDate:          changeDate,
		ClockTampered:       tampered,
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

// ExpectedProduct returns the expected product name configured for this validator.
func (v *Validator) ExpectedProduct() string {
	return v.expectedProduct
}

// BSLPolicy returns the BSL 1.1 policy configured for this validator, or nil if none is configured.
func (v *Validator) BSLPolicy() *BSLPolicy {
	return v.bslPolicy
}
