package license

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
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
	requireScopeDimensions    []string
	currentVersion            string
	buildDate                 time.Time
	bslPolicy                 *BSLPolicy
	authoritativeTime         time.Time
	requireAuthoritativeTime  bool
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
	maxBuildDateSkew          time.Duration
	requireStrictBuildDate    bool
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

// WithGracePeriod configures an additional runtime grace period past expiration before hard shutoff.
func WithGracePeriod(grace time.Duration) ValidatorOption {
	return func(v *Validator) {
		v.gracePeriod = grace
	}
}

// WithExpectedFingerprint locks license verification to a specific machine/hardware fingerprint.
func WithExpectedFingerprint(fingerprint string) ValidatorOption {
	return func(v *Validator) {
		v.expectedFingerprint = fingerprint
	}
}

// WithRequireFingerprint enforces that any validated license MUST contain a machine fingerprint.
func WithRequireFingerprint(require bool) ValidatorOption {
	return func(v *Validator) {
		v.requireFingerprint = require
	}
}

// WithAutoFingerprint enables automatic machine fingerprint resolution and matching during validation.
func WithAutoFingerprint(auto bool) ValidatorOption {
	return func(v *Validator) {
		v.autoFingerprint = auto
	}
}

// WithFingerprintResolver injects a custom fingerprint resolver for testing or specialized hardware.
func WithFingerprintResolver(resolver FingerprintResolver) ValidatorOption {
	return func(v *Validator) {
		v.fingerprintResolver = resolver
	}
}

// WithCurrentEnvironment configures the local runtime environment (e.g., "production", "staging", "dev").
func WithCurrentEnvironment(env string) ValidatorOption {
	return func(v *Validator) {
		v.currentEnvironment = env
	}
}

// WithEnvironment is an alias for WithCurrentEnvironment.
func WithEnvironment(env string) ValidatorOption {
	return WithCurrentEnvironment(env)
}

// WithCurrentAccount configures the local account or tenant identifier (e.g. AWS account ID).
func WithCurrentAccount(account string) ValidatorOption {
	return func(v *Validator) {
		v.currentAccount = account
	}
}

// WithCurrentRegion configures the local deployment region (e.g., "us-east-1").
func WithCurrentRegion(region string) ValidatorOption {
	return func(v *Validator) {
		v.currentRegion = region
	}
}

// WithCurrentCluster configures the local Kubernetes or compute cluster name.
func WithCurrentCluster(cluster string) ValidatorOption {
	return func(v *Validator) {
		v.currentCluster = cluster
	}
}

// WithCurrentNamespace configures the local Kubernetes namespace or deployment domain.
func WithCurrentNamespace(namespace string) ValidatorOption {
	return func(v *Validator) {
		v.currentNamespace = namespace
	}
}

// WithCurrentHost configures the local hostname.
func WithCurrentHost(host string) ValidatorOption {
	return func(v *Validator) {
		v.currentHost = host
	}
}

// WithCurrentCustomScope sets a custom scope dimension and value for multi-tenant boundary checks.
func WithCurrentCustomScope(dimension, value string) ValidatorOption {
	return func(v *Validator) {
		if v.currentCustomScope == nil {
			v.currentCustomScope = make(map[string]string)
		}
		v.currentCustomScope[dimension] = value
	}
}

// WithRequireScope enforces that validated licenses must explicitly declare the specified scope dimensions.
// If a license does not declare or leaves empty any required dimension, verification fails with ErrScopeMismatch.
func WithRequireScope(dimensions ...string) ValidatorOption {
	return func(v *Validator) {
		v.requireScopeDimensions = append(v.requireScopeDimensions, dimensions...)
	}
}

// WithCurrentVersion sets the application's running semantic version to validate against MaxVersion.
func WithCurrentVersion(version string) ValidatorOption {
	return func(v *Validator) {
		v.currentVersion = version
	}
}

// WithBuildDate sets the application's compilation timestamp to enforce MaintenanceExpiresAt.
func WithBuildDate(buildDate time.Time) ValidatorOption {
	return func(v *Validator) {
		v.buildDate = buildDate
	}
}

// WithBSLPolicy configures Business Source License (BSL 1.1) Change Date policy for open-source transition.
func WithBSLPolicy(policy BSLPolicy) ValidatorOption {
	return func(v *Validator) {
		v.bslPolicy = &policy
	}
}

// WithBSLGrants registers Additional Use Grants onto the validator's BSL policy.
// If the validator does not already have a BSL policy, a default policy is initialized with the grants.
func WithBSLGrants(grants ...BSLAdditionalUseGrant) ValidatorOption {
	return func(v *Validator) {
		if v.bslPolicy == nil {
			v.bslPolicy = &BSLPolicy{
				Product:             v.expectedProduct,
				AdditionalUseGrants: grants,
			}
			return
		}
		v.bslPolicy.AdditionalUseGrants = append(v.bslPolicy.AdditionalUseGrants, grants...)
	}
}

// WithCurrentUsage configures the current operational metrics (e.g., active runner or seat count)
// to validate against BSL Additional Use Grant quota limits.
func WithCurrentUsage(usage map[string]int64) ValidatorOption {
	return func(v *Validator) {
		v.currentUsage = make(map[string]int64, len(usage))
		for k, val := range usage {
			v.currentUsage[k] = val
		}
	}
}

// WithCurrentFeatures configures the features actively exercised by the runtime service
// to evaluate against BSL Additional Use Grant feature entitlements.
func WithCurrentFeatures(features ...string) ValidatorOption {
	return func(v *Validator) {
		v.currentFeatures = append(v.currentFeatures, features...)
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

// WithKeyRing configures an existing KeyRing containing one or more trusted verification keys.
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

// WithAllowEnvKeyOverride allows environment variables (such as DIVMORA_PUBLIC_KEY)
// or system key files to override an explicit fallback key configured on the validator.
// When false (default), explicit fallback keys are treated as an immutable root of trust.
func WithAllowEnvKeyOverride(allow bool) ValidatorOption {
	return func(v *Validator) {
		v.allowEnvKeyOverride = allow
	}
}

// WithReleaseAttestation attaches a certified release attestation token or armored PEM block
// to establish binary provenance and verify authentic build origin.
func WithReleaseAttestation(tokenOrPEM string) ValidatorOption {
	return func(v *Validator) {
		v.releaseAttestation = tokenOrPEM
	}
}

// WithReleaseAttestationFile loads a release attestation from disk.
// If the file is missing, a symlink, or cannot be read, an initialization error is recorded.
func WithReleaseAttestationFile(filePath string) ValidatorOption {
	return func(v *Validator) {
		fi, err := os.Lstat(filePath)
		if err != nil {
			v.initErr = fmt.Errorf("failed to stat release attestation file: %w", err)
			return
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			v.initErr = fmt.Errorf("%w: release attestation file %s is a symlink", ErrSymlinkNotAllowed, filePath)
			return
		}
		data, err := os.ReadFile(filePath)
		if err != nil {
			v.initErr = fmt.Errorf("failed to read release attestation file: %w", err)
			return
		}
		v.releaseAttestation = string(data)
	}
}

// WithRequireReleaseAttestation enforces that valid binary provenance must be cryptographically verified
// before accepting commercial licenses or granting BSL conversions.
func WithRequireReleaseAttestation(require bool) ValidatorOption {
	return func(v *Validator) {
		v.requireReleaseAttestation = require
	}
}

// WithCurrentGitCommit sets the current git commit SHA of the running binary to verify against provenance.
func WithCurrentGitCommit(commit string) ValidatorOption {
	return func(v *Validator) {
		v.releaseGitCommit = commit
	}
}

// WithBinaryPath sets the filesystem path of the running executable to calculate SHA-256 for provenance check.
func WithBinaryPath(filePath string) ValidatorOption {
	return func(v *Validator) {
		v.binaryPath = filePath
	}
}

// WithBinaryBytes provides raw executable bytes directly for binary SHA-256 verification against provenance.
func WithBinaryBytes(data []byte) ValidatorOption {
	return func(v *Validator) {
		v.binaryBytes = data
	}
}

// WithMaxBuildDateSkew configures the allowable clock skew tolerance between
// claims.BuildDate and running binary build date.
func WithMaxBuildDateSkew(skew time.Duration) ValidatorOption {
	return func(v *Validator) {
		v.maxBuildDateSkew = skew
	}
}

// WithRequireStrictBuildDate enforces exact or tight build date matching (defaults to 1 minute tolerance if unset).
func WithRequireStrictBuildDate(strict bool) ValidatorOption {
	return func(v *Validator) {
		v.requireStrictBuildDate = strict
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
		ExpectedProduct:           v.expectedProduct,
		CurrentVersion:            v.currentVersion,
		CurrentCommit:             v.releaseGitCommit,
		CurrentBuildDate:          v.buildDate,
		CurrentReleaseDate:        releaseDate,
		BinaryPath:                v.binaryPath,
		BinaryBytes:               v.binaryBytes,
		RequireReleaseAttestation: v.requireReleaseAttestation,
		MaxBuildDateSkew:          v.maxBuildDateSkew,
		RequireStrictBuildDate:    v.requireStrictBuildDate,
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

// ClockSkew returns the configured clock skew tolerance duration.
func (v *Validator) ClockSkew() time.Duration {
	return v.clockSkew
}

// GracePeriod returns the configured grace period duration.
func (v *Validator) GracePeriod() time.Duration {
	return v.gracePeriod
}

// RequireAuthoritativeTime reports whether authoritative time is strictly required.
func (v *Validator) RequireAuthoritativeTime() bool {
	return v.requireAuthoritativeTime
}

// ResolveEvaluationTime reconciles local reference time with authoritative time sources and clock defense.
func (v *Validator) ResolveEvaluationTime(localNow time.Time) (evalTime time.Time, tampered bool, skew time.Duration, err error) {
	return v.resolveEvaluationTime(localNow)
}

// VerificationResult encapsulates verified license claims alongside explicit grace period dynamics,
// BSL 1.1 open-source transition details, and cryptographic key attribution.
type VerificationResult struct {
	// Claims contains the unpacked and verified license claims.
	Claims *Claims

	// Status indicates the operational lifecycle status (ACTIVE, GRACE_PERIOD, EXPIRED, NOT_YET_VALID).
	Status Status

	// VerifiedByKeyID is the identifier of the KeyRing key that signed the license.
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

	// ClockSkewTolerance is the configured tolerance duration for clock drift.
	ClockSkewTolerance time.Duration

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

	skewTol := r.ClockSkewTolerance
	if skewTol == 0 && r.ClockSkew > 0 {
		skewTol = r.ClockSkew
	}
	return r.Claims.StatusMessageAt(evalTime, skewTol)
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
