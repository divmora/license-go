package license

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

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

	// 2. Validate and decode claims
	if err := ValidateClaimsPayloadJSON(payloadJSON); err != nil {
		return nil, nil, false, err
	}

	var claims Claims
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		return nil, nil, false, fmt.Errorf("%w: failed to parse claims json: %v", ErrInvalidLicenseFormat, err)
	}

	if err := claims.ValidateClaimsSchema(); err != nil {
		return nil, nil, false, err
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
			if constantTimeFingerprintMatch(claims.Fingerprint, v.expectedFingerprint) {
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
	// 0. Enforce required scope dimensions if configured
	if len(v.requireScopeDimensions) > 0 {
		for _, dim := range v.requireScopeDimensions {
			if !claims.HasScopeDimension(dim) {
				return &ScopeMismatchError{
					Dimension: dim,
					Allowed:   nil,
					Target:    "",
				}
			}
		}
	}

	// 1. Environments: assert modern Scope.Environments, or fallback to legacy Claims.Environment
	var allowedEnvs []string
	if claims.Scope != nil && len(claims.Scope.Environments) > 0 {
		allowedEnvs = claims.Scope.Environments
	} else if claims.Environment != "" {
		allowedEnvs = []string{claims.Environment}
	}

	if len(allowedEnvs) > 0 {
		targetEnv := v.currentEnvironment
		if targetEnv == "" {
			targetEnv = resolveEnvFromProcess()
		}
		if targetEnv == "" || !claims.IsEnvironmentAllowed(targetEnv) {
			return &ScopeMismatchError{Dimension: "environments", Allowed: allowedEnvs, Target: targetEnv}
		}
	}

	if claims.Scope != nil {
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
	}
	return nil
}

func resolveEnvFromProcess() string {
	for _, k := range []string{"DIVMORA_ENV", "DIVMORA_ENVIRONMENT"} {
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
				ClockSkewTolerance: v.clockSkew,
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
				ClockSkewTolerance: v.clockSkew,
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
			ClockSkewTolerance: v.clockSkew,
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
					ClockSkewTolerance: v.clockSkew,
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

	effectiveGrace := v.gracePeriod
	if claims.GracePeriodDays > 0 {
		claimGrace := time.Duration(claims.GracePeriodDays) * 24 * time.Hour
		if claimGrace > effectiveGrace {
			effectiveGrace = claimGrace
		}
	}
	effectiveExpiry := claims.EffectiveExpiration()
	if effectiveGrace > 0 && (claims.GracePeriodDays == 0 || effectiveGrace > time.Duration(claims.GracePeriodDays)*24*time.Hour) {
		effectiveExpiry = claims.ExpiresAt.Add(effectiveGrace)
	}

	status := claims.StatusWithTolerance(evalTime, v.clockSkew, effectiveGrace)
	inGracePeriod := (status == StatusGracePeriod)

	graceDaysRemaining := 0
	if inGracePeriod {
		cutoff := claims.ExpiresAt.Add(effectiveGrace).Add(v.clockSkew)
		if diff := cutoff.Sub(evalTime); diff > 0 {
			graceDaysRemaining = int(diff.Hours() / 24)
		}
	}

	return &VerificationResult{
		Claims:              claims,
		Status:              status,
		VerifiedByKeyID:     matchedKey.ID,
		VerifiedByKeyStatus: matchedKey.Status,
		InGracePeriod:       inGracePeriod,
		GraceDaysRemaining:  graceDaysRemaining,
		EffectiveExpiry:     effectiveExpiry,
		BSLConverted:        false,
		EffectiveLicense:    effectiveLic,
		ChangeDate:          changeDate,
		ClockTampered:       tampered,
		ServerTimeAttested:  v.serverTimeAttested || !v.authoritativeTime.IsZero(),
		ServerTime:          v.authoritativeTime.UTC(),
		ClockSkew:           skew,
		ClockSkewTolerance:  v.clockSkew,
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

	if err := ValidateClaimsPayloadJSON(payloadJSON); err != nil {
		return nil, err
	}

	var claims Claims
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		return nil, fmt.Errorf("%w: failed to parse claims json: %v", ErrInvalidLicenseFormat, err)
	}

	if err := claims.ValidateClaimsSchema(); err != nil {
		return nil, err
	}

	return &claims, nil
}

// InspectFromFile reads a license file and unpacks the claims without verifying signature.
func InspectFromFile(filePath string) (*Claims, error) {
	fi, err := os.Lstat(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to stat license file: %w", err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%w: license file %s is a symlink", ErrSymlinkNotAllowed, filePath)
	}
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read license file: %w", err)
	}
	return Inspect(string(data))
}
