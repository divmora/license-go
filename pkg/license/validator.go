package license

import (
	"context"
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
	keyRing                   *KeyRing
	expectedProduct           string
	clockSkew                 time.Duration
	gracePeriod               time.Duration
	expectedFingerprint       string
	requireFingerprint        bool
	autoFingerprint           bool
	fingerprintResolver       FingerprintResolver
	currentEnvironment        string
	currentAccount            string
	currentRegion             string
	currentCluster            string
	currentNamespace          string
	currentHost               string
	currentCustomScope        map[string]string
	currentVersion            string
	buildDate                 time.Time
	bslPolicy                 *BSLPolicy
	authoritativeTime         time.Time
	maxClockDrift             time.Duration
	serverTimeAttested        bool
	strictClockDefense        bool
	allowExpired              bool
	allowInactive             bool
	releaseAttestation        string
	requireReleaseAttestation bool
	releaseGitCommit          string
	binaryPath                string
	binaryBytes               []byte
	currentUsage              map[string]int64
	currentFeatures           []string
	allowEnvKeyOverride       bool
	initErr                   error
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

// WithAutoFingerprint enables automated machine fingerprint resolution when evaluating node-locked licenses.
func WithAutoFingerprint(auto bool) ValidatorOption {
	return func(v *Validator) {
		v.autoFingerprint = auto
	}
}

// WithFingerprintResolver sets a custom FingerprintResolver for auto-fingerprint resolution.
func WithFingerprintResolver(resolver FingerprintResolver) ValidatorOption {
	return func(v *Validator) {
		v.fingerprintResolver = resolver
	}
}

// WithCurrentEnvironment asserts that the current deployment environment matches Scope.Environments.
func WithCurrentEnvironment(env string) ValidatorOption {
	return func(v *Validator) {
		v.currentEnvironment = env
	}
}

// WithEnvironment is an alias for WithCurrentEnvironment.
func WithEnvironment(env string) ValidatorOption {
	return WithCurrentEnvironment(env)
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

// WithBSLGrants appends one or more Additional Use Grants to the validator's BSLPolicy.
func WithBSLGrants(grants ...BSLAdditionalUseGrant) ValidatorOption {
	return func(v *Validator) {
		if v.bslPolicy == nil {
			v.bslPolicy = &BSLPolicy{}
		}
		v.bslPolicy.AdditionalUseGrants = append(v.bslPolicy.AdditionalUseGrants, grants...)
	}
}

// WithCurrentUsage configures active runtime resource usage to evaluate against BSL Additional Use Grants or license quotas.
func WithCurrentUsage(usage map[string]int64) ValidatorOption {
	return func(v *Validator) {
		v.currentUsage = make(map[string]int64, len(usage))
		for k, val := range usage {
			v.currentUsage[k] = val
		}
	}
}

// WithCurrentFeatures configures the features currently requested or enabled by the application.
func WithCurrentFeatures(features ...string) ValidatorOption {
	return func(v *Validator) {
		v.currentFeatures = append(v.currentFeatures, features...)
	}
}

// ParseServerTimeHeader parses an authoritative server timestamp string.
// It supports standard HTTP Date header formats (RFC 1123, RFC 1123Z, RFC 850, ANSI C)
// as well as ISO 8601 / RFC 3339 timestamps and standard SQL dates.
func ParseServerTimeHeader(dateStr string) (time.Time, error) {
	s := strings.TrimSpace(dateStr)
	if s == "" {
		return time.Time{}, errors.New("license: empty server time header")
	}

	formats := []string{
		time.RFC1123,          // "Wed, 16 Sep 2026 10:00:00 GMT" (standard HTTP Date)
		time.RFC1123Z,         // "Wed, 16 Sep 2026 10:00:00 +0000"
		time.RFC3339,          // "2026-09-16T10:00:00Z"
		time.RFC3339Nano,      // "2026-09-16T10:00:00.999999999Z"
		time.RFC850,           // "Wednesday, 16-Sep-26 10:00:00 GMT"
		time.ANSIC,            // "Wed Sep 16 10:00:00 2026"
		"2006-01-02 15:04:05", // "2026-09-16 10:00:00"
		"2006-01-02",          // "2026-09-16"
	}

	for _, format := range formats {
		if t, err := time.Parse(format, s); err == nil {
			return t.UTC(), nil
		}
	}

	return time.Time{}, fmt.Errorf("license: unable to parse server time header %q", dateStr)
}

// WithAuthoritativeTime sets an authoritative reference time (e.g., from an HTTP Date header or cloud API)
// to defend against local system clock manipulation and false BSL conversion claims.
func WithAuthoritativeTime(t time.Time) ValidatorOption {
	return func(v *Validator) {
		v.authoritativeTime = t
	}
}

// WithServerTimeAttestation validates licenses against an authoritative external server timestamp
// (e.g., from an HTTP response Date header, cloud metadata API, or central licensing service)
// with a configurable maximum allowed clock skew threshold.
//
// When clock skew between local host time and server time exceeds maxAllowedSkew, or if forward or backward
// clock tampering is detected, the validator anchors claims evaluation to the authoritative server time
// and flags clock tampering. If WithStrictClockDefense(true) is configured, verification fails immediately
// with ErrClockTamperingDetected.
func WithServerTimeAttestation(serverTime time.Time, maxAllowedSkew time.Duration) ValidatorOption {
	return func(v *Validator) {
		v.authoritativeTime = serverTime
		if maxAllowedSkew > 0 {
			v.maxClockDrift = maxAllowedSkew
		}
		v.serverTimeAttested = true
	}
}

// WithServerTimeHeader parses an authoritative server timestamp from an HTTP Date header or
// ISO 8601 string and configures WithServerTimeAttestation. If headerValue cannot be parsed,
// it records an error on the validator to fail closed.
func WithServerTimeHeader(headerValue string, maxAllowedSkew time.Duration) ValidatorOption {
	return func(v *Validator) {
		t, err := ParseServerTimeHeader(headerValue)
		if err != nil {
			v.initErr = fmt.Errorf("%w: %v", ErrClockTamperingDetected, err)
			return
		}
		v.authoritativeTime = t
		if maxAllowedSkew > 0 {
			v.maxClockDrift = maxAllowedSkew
		}
		v.serverTimeAttested = true
	}
}

// WithStrictClockDefense controls whether clock tampering or excessive skew returns ErrClockTamperingDetected
// immediately rather than anchoring evaluation to the authoritative server time (default: false).
func WithStrictClockDefense(strict bool) ValidatorOption {
	return func(v *Validator) {
		v.strictClockDefense = strict
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

// WithAllowEnvKeyOverride configures whether environment variables (DIVMORA_PUBLIC_KEYS_PEM,
// DIVMORA_PUBLIC_KEY, DIVMORA_PUBLIC_KEY_FILE) or default system key files (/etc/divmora/public.pem)
// are permitted to override explicit fallback public keys.
//
// By default (false), explicit fallback keys are treated as an immutable root of trust to prevent
// public key trust root spoofing in untrusted deployment environments.
func WithAllowEnvKeyOverride(allow bool) ValidatorOption {
	return func(v *Validator) {
		v.allowEnvKeyOverride = allow
	}
}

// WithReleaseAttestation provides an Ed25519 cryptographic release attestation token or armored PEM block.
func WithReleaseAttestation(tokenOrPEM string) ValidatorOption {
	return func(v *Validator) {
		v.releaseAttestation = strings.TrimSpace(tokenOrPEM)
	}
}

// WithReleaseAttestationFile loads the release attestation from a file on disk (e.g. "release.sig").
func WithReleaseAttestationFile(filePath string) ValidatorOption {
	return func(v *Validator) {
		data, err := os.ReadFile(filePath)
		if err != nil {
			v.initErr = fmt.Errorf("failed to read release attestation file %s: %w", filePath, err)
			return
		}
		v.releaseAttestation = strings.TrimSpace(string(data))
	}
}

// WithRequireReleaseAttestation enforces that binaries must have a valid cryptographic release attestation.
// If true and no attestation is provided, or if attestation is invalid, validation fails.
func WithRequireReleaseAttestation(require bool) ValidatorOption {
	return func(v *Validator) {
		v.requireReleaseAttestation = require
	}
}

// WithCurrentGitCommit sets the current git commit to cross-check against release attestation.
func WithCurrentGitCommit(commit string) ValidatorOption {
	return func(v *Validator) {
		v.releaseGitCommit = commit
	}
}

// WithBinaryPath sets the executable path on disk to verify binary SHA-256 digest against release attestation.
func WithBinaryPath(filePath string) ValidatorOption {
	return func(v *Validator) {
		v.binaryPath = filePath
	}
}

// WithBinaryBytes sets executable bytes to verify binary SHA-256 digest against release attestation.
func WithBinaryBytes(data []byte) ValidatorOption {
	return func(v *Validator) {
		v.binaryBytes = data
	}
}

// EvaluateProvenance evaluates the binary release authenticity and provenance against the validator's KeyRing.
func (v *Validator) EvaluateProvenance() (*ReleaseProvenance, error) {
	if v.initErr != nil {
		return nil, v.initErr
	}

	if IsPlaceholderAttestation(v.releaseAttestation) {
		if v.requireReleaseAttestation {
			return nil, ErrReleaseAttestationMissing
		}
		return &ReleaseProvenance{Attested: false}, nil
	}

	var releaseDate time.Time
	if v.bslPolicy != nil {
		releaseDate = v.bslPolicy.ReleaseDate
	}

	params := ProvenanceParams{
		ExpectedProduct:    v.expectedProduct,
		CurrentVersion:     v.currentVersion,
		CurrentCommit:      v.releaseGitCommit,
		CurrentBuildDate:   v.buildDate,
		CurrentReleaseDate: releaseDate,
		BinaryPath:         v.binaryPath,
		BinaryBytes:        v.binaryBytes,
	}

	return EvaluateProvenance(v.releaseAttestation, v.keyRing, params)
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

// AllowEnvKeyOverride reports whether environment variables are permitted to override explicit fallback keys.
func (v *Validator) AllowEnvKeyOverride() bool {
	return v.allowEnvKeyOverride
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

func (v *Validator) effectiveBuildDate() time.Time {
	return v.effectiveBuildDateWithProv(nil)
}

func (v *Validator) effectiveBuildDateWithProv(prov *ReleaseProvenance) time.Time {
	if !v.buildDate.IsZero() {
		return v.buildDate
	}
	if prov != nil && prov.Attested && prov.Claims != nil {
		if !prov.Claims.BuildDate.IsZero() {
			return prov.Claims.BuildDate
		}
		if !prov.Claims.ReleaseDate.IsZero() {
			return prov.Claims.ReleaseDate
		}
	}
	if !IsPlaceholderAttestation(v.releaseAttestation) {
		if p, err := v.EvaluateProvenance(); err == nil && p != nil && p.Attested && p.Claims != nil {
			if !p.Claims.BuildDate.IsZero() {
				return p.Claims.BuildDate
			}
			if !p.Claims.ReleaseDate.IsZero() {
				return p.Claims.ReleaseDate
			}
		}
	}
	return time.Time{}
}

// resolveEvaluationTime reconciles the local reference time with any configured authoritative time,
// detecting forward and backward clock tampering attempts while respecting clock drift boundaries.
func (v *Validator) resolveEvaluationTime(localNow time.Time) (evalTime time.Time, tampered bool, skew time.Duration, err error) {
	return v.resolveEvaluationTimeWithProv(localNow, nil)
}

func (v *Validator) resolveEvaluationTimeWithProv(localNow time.Time, prov *ReleaseProvenance) (evalTime time.Time, tampered bool, skew time.Duration, err error) {
	evalTime = localNow
	localUTC := localNow.UTC()

	buildTime := v.effectiveBuildDateWithProv(prov)
	skewTolerance := v.clockSkew
	if skewTolerance < 0 {
		skewTolerance = 0
	}

	if v.authoritativeTime.IsZero() {
		// Offline / air-gapped clock defense: local evaluation time cannot be physically prior to binary build date
		if !buildTime.IsZero() {
			earliest := buildTime.Add(-skewTolerance)
			if localUTC.Before(earliest) {
				drift := buildTime.Sub(localUTC)
				return localNow, true, drift, &ClockTamperingError{
					LocalTime:      localUTC,
					ServerTime:     buildTime.UTC(),
					Skew:           drift,
					MaxAllowedSkew: skewTolerance,
					Reason:         fmt.Sprintf("offline backward clock tampering detected: evaluation time %s is physically prior to binary build date %s", localUTC.Format(time.RFC3339), buildTime.UTC().Format(time.RFC3339)),
				}
			}
		}
		return evalTime, false, 0, nil
	}

	authTime := v.authoritativeTime.UTC()

	drift := localUTC.Sub(authTime)
	skew = drift
	if skew < 0 {
		skew = -drift
	}

	driftLimit := v.maxClockDrift
	if driftLimit <= 0 {
		driftLimit = time.Hour
	}

	// 1. Forward Clock Tampering Detection:
	// Local clock claims BSL Change Date has arrived, but authoritative server clock attests it has not!
	if v.bslPolicy != nil && v.bslPolicy.IsConverted(localUTC) && !v.bslPolicy.IsConverted(authTime) {
		tampered = true
		evalTime = authTime
		if v.strictClockDefense {
			return authTime, true, skew, &ClockTamperingError{
				LocalTime:      localUTC,
				ServerTime:     authTime,
				Skew:           skew,
				MaxAllowedSkew: driftLimit,
				Reason:         "local clock advanced past BSL Change Date before authoritative server time",
			}
		}
		return evalTime, tampered, skew, nil
	}

	// 2. Significant Clock Drift / Tampering Check (Forward or Backward):
	if skew > driftLimit {
		tampered = true
		evalTime = authTime
		if v.strictClockDefense {
			reason := "local clock advanced too far ahead of server time"
			if drift < 0 {
				reason = "local clock set back in time behind server time"
			}
			return authTime, true, skew, &ClockTamperingError{
				LocalTime:      localUTC,
				ServerTime:     authTime,
				Skew:           skew,
				MaxAllowedSkew: driftLimit,
				Reason:         reason,
			}
		}
		return evalTime, tampered, skew, nil
	}

	// 3. When server time is explicitly attested, always evaluate against the authoritative server time
	if v.serverTimeAttested {
		evalTime = authTime
	}

	// 4. Binary Build Date check: evaluation time cannot be physically prior to binary build date
	if !buildTime.IsZero() {
		earliest := buildTime.Add(-skewTolerance)
		if evalTime.Before(earliest) {
			drift := buildTime.Sub(evalTime)
			return evalTime, true, drift, &ClockTamperingError{
				LocalTime:      localUTC,
				ServerTime:     buildTime.UTC(),
				Skew:           drift,
				MaxAllowedSkew: skewTolerance,
				Reason:         fmt.Sprintf("backward clock tampering detected: evaluation time %s is physically prior to binary build date %s", evalTime.UTC().Format(time.RFC3339), buildTime.UTC().Format(time.RFC3339)),
			}
		}
	}

	return evalTime, tampered, skew, nil
}

// VerifyWithResultEnv resolves the license automatically from standard environment variables
// (DIVMORA_LICENSE_KEY, DIVMORA_LICENSE_FILE, or /etc/divmora/license.key) and returns a detailed VerificationResult.
// If the BSL 1.1 Change Date has arrived or operational usage is authorized under an Additional Use Grant,
// entitlements are granted automatically.
func (v *Validator) VerifyWithResultEnv() (*VerificationResult, error) {
	evalTime, _, _, err := v.resolveEvaluationTime(time.Now())
	if err != nil {
		return nil, err
	}
	resolved, err := ResolveLicense()
	if err != nil {
		return v.VerifyWithResultAt("", evalTime)
	}
	return v.VerifyWithResultAt(resolved.Content, evalTime)
}

// VerifyEnv resolves the license automatically from standard environment variables
// (DIVMORA_LICENSE_KEY, DIVMORA_LICENSE_FILE, or /etc/divmora/license.key) and validates it.
// If the BSL 1.1 Change Date has arrived or operational usage is authorized under an Additional Use Grant,
// entitlements are granted automatically.
func (v *Validator) VerifyEnv() (*Claims, error) {
	res, err := v.VerifyWithResultEnv()
	if err != nil {
		return nil, err
	}
	return res.Claims, nil
}

// VerifyResolved resolves a license from an explicit input (file path or token string)
// or falls back to standard environment variables, then verifies it.
func (v *Validator) VerifyResolved(explicitSource ...string) (*Claims, error) {
	evalTime, _, _, err := v.resolveEvaluationTime(time.Now())
	if err != nil {
		return nil, err
	}
	resolved, err := ResolveLicense(explicitSource...)
	if err != nil {
		return v.VerifyAt("", evalTime)
	}
	return v.VerifyAt(resolved.Content, evalTime)
}

// VerifyAt validates the license against the specified reference time `now`.
func (v *Validator) VerifyAt(rawLicense string, now time.Time) (*Claims, error) {
	res, err := v.VerifyWithResultAt(rawLicense, now)
	if err != nil {
		return nil, err
	}
	return res.Claims, nil
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
	claims, _, _, err := v.verifyClaimsWithDetails(payloadJSON, now)
	return claims, err
}

func (v *Validator) verifyClaimsWithDetails(payloadJSON []byte, now time.Time) (*Claims, *MachineFingerprint, bool, error) {
	// 1. Backward clock tampering check against binary build date
	buildTime := v.effectiveBuildDate()
	if !buildTime.IsZero() {
		skewTolerance := v.clockSkew
		if skewTolerance < 0 {
			skewTolerance = 0
		}
		earliest := buildTime.Add(-skewTolerance)
		if now.Before(earliest) {
			drift := buildTime.Sub(now)
			return nil, nil, false, &ClockTamperingError{
				LocalTime:      now.UTC(),
				ServerTime:     buildTime.UTC(),
				Skew:           drift,
				MaxAllowedSkew: skewTolerance,
				Reason:         fmt.Sprintf("backward clock tampering detected: evaluation time %s is physically prior to binary build date %s", now.UTC().Format(time.RFC3339), buildTime.UTC().Format(time.RFC3339)),
			}
		}
	}

	// 2. Decode claims
	var claims Claims
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		return nil, nil, false, fmt.Errorf("%w: failed to parse claims json: %v", ErrInvalidLicenseFormat, err)
	}

	// 3. Product match check
	if v.expectedProduct != "" && !claims.IsValidForProduct(v.expectedProduct) {
		return nil, nil, false, fmt.Errorf("%w: expected %q, got %q", ErrProductMismatch, v.expectedProduct, claims.Product)
	}

	// 4. Fingerprint check
	var resolvedFP *MachineFingerprint
	fingerprintMatched := false
	if claims.Fingerprint != "" {
		if v.expectedFingerprint != "" {
			if strings.EqualFold(claims.Fingerprint, v.expectedFingerprint) {
				fingerprintMatched = true
			} else {
				return nil, nil, false, fmt.Errorf("%w: expected %q, license bound to %q", ErrFingerprintMismatch, v.expectedFingerprint, claims.Fingerprint)
			}
		} else if v.autoFingerprint {
			resolver := v.fingerprintResolver
			if resolver == nil {
				resolver = NewDefaultCompositeResolver()
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()

			fp, err := resolver.Resolve(ctx)
			if err != nil {
				return nil, nil, false, fmt.Errorf("%w: failed to auto-resolve machine fingerprint: %v", ErrFingerprintMismatch, err)
			}
			resolvedFP = fp
			if !fp.Matches(claims.Fingerprint) {
				return nil, resolvedFP, false, fmt.Errorf("%w: local machine %q (%s) does not match license bound to %q", ErrFingerprintMismatch, fp.Primary, fp.Platform, claims.Fingerprint)
			}
			fingerprintMatched = true
		} else {
			return nil, nil, false, fmt.Errorf("%w: license is bound to node fingerprint %q, but no expected fingerprint was configured on validator", ErrFingerprintMismatch, claims.Fingerprint)
		}
	} else if v.requireFingerprint {
		return nil, nil, false, fmt.Errorf("%w: validator requires node-locked license, but license has no fingerprint", ErrFingerprintMismatch)
	}

	// 5. NotBefore check (with clock skew)
	if !v.allowInactive && !claims.NotBefore.IsZero() {
		effectiveNotBefore := claims.NotBefore.Add(-v.clockSkew)
		if now.Before(effectiveNotBefore) {
			return nil, resolvedFP, fingerprintMatched, ErrNotYetValid
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
			return nil, resolvedFP, fingerprintMatched, ErrExpired
		}
	}

	// 7. Scope constraints check
	if err := v.checkScope(&claims); err != nil {
		return nil, resolvedFP, fingerprintMatched, err
	}

	// 8. Version constraints check
	if v.currentVersion != "" && !claims.IsVersionAllowed(v.currentVersion) {
		return nil, resolvedFP, fingerprintMatched, &VersionNotEntitledError{
			CurrentVersion: v.currentVersion,
			MaxVersion:     claims.MaxVersion,
			Allowed:        claims.AllowedVersions,
		}
	}

	// 9. Maintenance / Support update cutoff check
	if !v.buildDate.IsZero() && claims.HasMaintenanceExpired(v.buildDate) {
		return nil, resolvedFP, fingerprintMatched, &MaintenanceExpiredError{
			BuildDate:            v.buildDate.Format(time.RFC3339),
			MaintenanceExpiresAt: claims.MaintenanceExpiresAt.Format(time.RFC3339),
		}
	}

	return &claims, resolvedFP, fingerprintMatched, nil
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

	// BSLGrantAuthorized reports whether the result was authorized under a BSL 1.1 Additional Use Grant.
	BSLGrantAuthorized bool

	// BSLGrantName identifies the specific Additional Use Grant that authorized usage.
	BSLGrantName string

	// BSLEntitlement contains the detailed BSL entitlement evaluation result, if evaluated.
	BSLEntitlement *BSLEntitlementResult

	// EffectiveLicense indicates the governing license identifier ("BSL-1.1" or "Apache-2.0").
	EffectiveLicense string

	// ChangeDate is the timestamp when the software converts to open source under BSL terms.
	ChangeDate time.Time

	// ClockTampered indicates that local system clock contradicted authoritative server time.
	ClockTampered bool

	// ServerTimeAttested indicates whether an authoritative server timestamp was configured for validation.
	ServerTimeAttested bool

	// ServerTime contains the authoritative server timestamp, if attested.
	ServerTime time.Time

	// ClockSkew is the measured difference between local system clock and authoritative server time.
	ClockSkew time.Duration

	// EvaluationTime records the exact timestamp (local or authoritative) used for evaluation.
	EvaluationTime time.Time

	// Provenance contains the evaluation of the binary's release attestation and build authenticity.
	Provenance *ReleaseProvenance

	// ResolvedFingerprint contains the machine fingerprint resolved during validation, if resolved.
	ResolvedFingerprint *MachineFingerprint

	// FingerprintMatched reports whether the license's node-lock fingerprint was matched.
	FingerprintMatched bool
}

// StatusMessage returns a standardized human-readable description of the verification result.
// It accounts for BSL 1.1 open-source conversion, perpetual status, active days remaining,
// post-expiration grace period status, future validity windows, and expired states.
func (r *VerificationResult) StatusMessage() string {
	if r == nil {
		return "No verification result"
	}

	if r.BSLConverted {
		effectiveLic := r.EffectiveLicense
		if effectiveLic == "" {
			effectiveLic = "Apache-2.0"
		}
		if !r.ChangeDate.IsZero() {
			return fmt.Sprintf("Open source license (BSL 1.1 converted to %s on %s)",
				effectiveLic, r.ChangeDate.Format("2006-01-02"))
		}
		return fmt.Sprintf("Open source license (BSL 1.1 converted to %s)", effectiveLic)
	}

	if r.BSLGrantAuthorized {
		if r.BSLGrantName != "" {
			return fmt.Sprintf("Authorized under BSL 1.1 Additional Use Grant (%s)", r.BSLGrantName)
		}
		return "Authorized under BSL 1.1 Additional Use Grant"
	}

	if r.Claims == nil {
		return string(r.Status)
	}

	evalTime := r.EvaluationTime
	if evalTime.IsZero() {
		evalTime = time.Now()
	}

	if r.InGracePeriod || r.Status == StatusGracePeriod {
		graceDays := r.GraceDaysRemaining
		cutoff := r.EffectiveExpiry
		if cutoff.IsZero() {
			cutoff = r.Claims.EffectiveExpiration()
		}
		expires := r.Claims.ExpiresAt
		cutoffStr := cutoff.Format(time.RFC3339)
		expiresStr := expires.Format(time.RFC3339)
		if graceDays == 1 {
			return fmt.Sprintf("Operating in grace period (1 grace day remaining until %s, expired on %s)", cutoffStr, expiresStr)
		}
		if graceDays == 0 {
			return fmt.Sprintf("Operating in grace period (less than 1 grace day remaining until %s, expired on %s)", cutoffStr, expiresStr)
		}
		return fmt.Sprintf("Operating in grace period (%d grace days remaining until %s, expired on %s)", graceDays, cutoffStr, expiresStr)
	}

	return r.Claims.StatusMessageAt(evalTime)
}

// VerifyWithResult validates the license and returns a detailed VerificationResult exposing grace period dynamics.
func (v *Validator) VerifyWithResult(rawLicense string) (*VerificationResult, error) {
	return v.VerifyWithResultAt(rawLicense, time.Now())
}

// VerifyWithResultAt validates the license against reference time `now` and returns a detailed VerificationResult.
func (v *Validator) VerifyWithResultAt(rawLicense string, now time.Time) (*VerificationResult, error) {
	if v.initErr != nil {
		return nil, v.initErr
	}

	prov, err := v.EvaluateProvenance()
	if err != nil {
		return nil, err
	}

	evalTime, tampered, skew, err := v.resolveEvaluationTimeWithProv(now, prov)
	if err != nil {
		return nil, err
	}

	var changeDate time.Time
	effectiveLic := DefaultBSLLicense
	effectiveBSL := v.bslPolicy
	if effectiveBSL != nil {
		if prov != nil && prov.Attested && prov.Claims != nil && !prov.Claims.ReleaseDate.IsZero() {
			policyCopy := *effectiveBSL
			policyCopy.ReleaseDate = prov.Claims.ReleaseDate
			effectiveBSL = &policyCopy
		}
		changeDate = effectiveBSL.ChangeDate()
		effectiveLic = effectiveBSL.EffectiveLicense(evalTime)
	}

	// 0. Automatic BSL 1.1 Change Date Check
	if effectiveBSL != nil && effectiveBSL.IsConverted(evalTime) {
		if strings.TrimSpace(rawLicense) == "" {
			claims := &Claims{
				Product:  v.expectedProduct,
				Plan:     "open-source",
				Customer: Customer{Name: "Open Source Community"},
				Features: []string{"*"},
				Limits:   map[string]int64{},
			}
			return &VerificationResult{
				Claims:             claims,
				Status:             StatusActive,
				BSLConverted:       true,
				EffectiveLicense:   effectiveLic,
				ChangeDate:         changeDate,
				ClockTampered:      tampered,
				ServerTimeAttested: v.serverTimeAttested || !v.authoritativeTime.IsZero(),
				ServerTime:         v.authoritativeTime.UTC(),
				ClockSkew:          skew,
				EvaluationTime:     evalTime,
				Provenance:         prov,
			}, nil
		}

		vCopy := *v
		vCopy.allowExpired = true
		claims, err := vCopy.verifyTokenPayload(rawLicense, evalTime)
		if err == nil {
			return &VerificationResult{
				Claims:             claims,
				Status:             StatusActive,
				BSLConverted:       true,
				EffectiveLicense:   effectiveLic,
				ChangeDate:         changeDate,
				ClockTampered:      tampered,
				ServerTimeAttested: v.serverTimeAttested || !v.authoritativeTime.IsZero(),
				ServerTime:         v.authoritativeTime.UTC(),
				ClockSkew:          skew,
				EvaluationTime:     evalTime,
				Provenance:         prov,
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
			Claims:             claims,
			Status:             StatusActive,
			BSLConverted:       true,
			EffectiveLicense:   effectiveLic,
			ChangeDate:         changeDate,
			ClockTampered:      tampered,
			ServerTimeAttested: v.serverTimeAttested || !v.authoritativeTime.IsZero(),
			ServerTime:         v.authoritativeTime.UTC(),
			ClockSkew:          skew,
			EvaluationTime:     evalTime,
			Provenance:         prov,
		}, nil
	}

	if strings.TrimSpace(rawLicense) == "" {
		if effectiveBSL != nil && len(effectiveBSL.AdditionalUseGrants) > 0 {
			req := BSLUsageRequest{
				Environment: v.currentEnvironment,
				Usage:       v.currentUsage,
				Features:    v.currentFeatures,
				Time:        evalTime,
			}
			if req.Environment == "" {
				req.Environment = resolveEnvFromProcess()
			}
			policyCopy := *effectiveBSL
			if policyCopy.Product == "" {
				policyCopy.Product = v.expectedProduct
			}
			ent := policyCopy.EvaluateEntitlement(req)
			if ent.Authorized {
				return &VerificationResult{
					Claims:             ent.Claims,
					Status:             StatusActive,
					BSLConverted:       false,
					BSLGrantAuthorized: true,
					BSLGrantName:       ent.MatchingGrant,
					BSLEntitlement:     ent,
					EffectiveLicense:   ent.EffectiveLicense,
					ChangeDate:         changeDate,
					ClockTampered:      tampered,
					ServerTimeAttested: v.serverTimeAttested || !v.authoritativeTime.IsZero(),
					ServerTime:         v.authoritativeTime.UTC(),
					ClockSkew:          skew,
					EvaluationTime:     evalTime,
					Provenance:         prov,
				}, nil
			}
			return nil, &CommercialLicenseRequiredError{
				Product:      v.expectedProduct,
				Environment:  req.Environment,
				EffectiveBSL: ent.EffectiveLicense,
				ChangeDate:   ent.ChangeDate,
				Reason:       ent.Reason,
			}
		}
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

	claims, resolvedFP, fpMatched, err := v.verifyClaimsWithDetails(payloadJSON, evalTime)
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
		ServerTimeAttested:  v.serverTimeAttested || !v.authoritativeTime.IsZero(),
		ServerTime:          v.authoritativeTime.UTC(),
		ClockSkew:           skew,
		EvaluationTime:      evalTime,
		Provenance:          prov,
		ResolvedFingerprint: resolvedFP,
		FingerprintMatched:  fpMatched,
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

// EvaluateBSLEntitlement evaluates operational usage against the validator's BSL policy and Additional Use Grants.
// It incorporates authoritative reference time, clock skew defense, and certified release provenance.
func (v *Validator) EvaluateBSLEntitlement(req BSLUsageRequest) (*BSLEntitlementResult, error) {
	if v.initErr != nil {
		return nil, v.initErr
	}
	if v.bslPolicy == nil {
		return nil, errors.New("license: validator has no BSL policy configured")
	}

	prov, err := v.EvaluateProvenance()
	if err != nil {
		return nil, err
	}

	evalTime := req.Time
	if evalTime.IsZero() {
		evalTime = time.Now()
	}

	evalTime, _, _, err = v.resolveEvaluationTimeWithProv(evalTime, prov)
	if err != nil {
		return nil, err
	}

	effectiveBSL := v.bslPolicy
	if prov != nil && prov.Attested && prov.Claims != nil && !prov.Claims.ReleaseDate.IsZero() {
		policyCopy := *effectiveBSL
		policyCopy.ReleaseDate = prov.Claims.ReleaseDate
		effectiveBSL = &policyCopy
	}

	reqCopy := req
	reqCopy.Time = evalTime
	if reqCopy.Environment == "" {
		reqCopy.Environment = v.currentEnvironment
		if reqCopy.Environment == "" {
			reqCopy.Environment = resolveEnvFromProcess()
		}
	}
	if len(reqCopy.Usage) == 0 && len(v.currentUsage) > 0 {
		reqCopy.Usage = v.currentUsage
	}
	if len(reqCopy.Features) == 0 && len(v.currentFeatures) > 0 {
		reqCopy.Features = v.currentFeatures
	}

	policyCopy := *effectiveBSL
	if policyCopy.Product == "" {
		policyCopy.Product = v.expectedProduct
	}

	return policyCopy.EvaluateEntitlement(reqCopy), nil
}
