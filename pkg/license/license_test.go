package license

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func sampleClaims() Claims {
	now := time.Now().UTC()
	return Claims{
		ID: "lic-12345-abcde",
		Customer: Customer{
			Name:  "Divmora Testing Corp",
			Email: "admin@divmora.io",
			OrgID: "org_divmora_test_01",
		},
		Product:   "gitlab-fleet-governor",
		Plan:      "enterprise",
		IssuedAt:  now,
		ExpiresAt: now.Add(30 * 24 * time.Hour),
		Features:  []string{"ha", "audit-logs", "sso"},
		Limits: map[string]int64{
			"max_runners": 100,
			"max_nodes":   10,
			"unlimited_q": -1,
		},
		Metadata: map[string]string{
			"tier":   "gold",
			"region": "us-east-1",
		},
	}
}

func TestSignAndVerify_CompactAndArmored(t *testing.T) {
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	signer, err := NewSigner(priv)
	if err != nil {
		t.Fatalf("NewSigner failed: %v", err)
	}

	validator, err := NewValidator(pub, WithProduct("gitlab-fleet-governor"))
	if err != nil {
		t.Fatalf("NewValidator failed: %v", err)
	}

	claims := sampleClaims()

	// 1. Test Compact token
	compactToken, err := signer.Sign(claims)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	if !strings.HasPrefix(compactToken, "DIV1.") {
		t.Fatalf("expected compact token to start with DIV1., got %s", compactToken)
	}

	verifiedClaims, err := validator.Verify(compactToken)
	if err != nil {
		t.Fatalf("Verify(compactToken) failed: %v", err)
	}
	if verifiedClaims.Customer != claims.Customer {
		t.Errorf("customer mismatch: got %+v, want %+v", verifiedClaims.Customer, claims.Customer)
	}
	if verifiedClaims.Customer.Name != "Divmora Testing Corp" || verifiedClaims.Customer.OrgID != "org_divmora_test_01" {
		t.Errorf("unexpected customer fields: %+v", verifiedClaims.Customer)
	}
	if verifiedClaims.Product != claims.Product {
		t.Errorf("product mismatch: got %s, want %s", verifiedClaims.Product, claims.Product)
	}
	if verifiedClaims.Plan != claims.Plan {
		t.Errorf("plan mismatch: got %s, want %s", verifiedClaims.Plan, claims.Plan)
	}

	// 2. Test Armored token
	armoredToken, err := signer.SignArmored(claims)
	if err != nil {
		t.Fatalf("SignArmored failed: %v", err)
	}
	if !strings.Contains(armoredToken, ArmoredHeader) || !strings.Contains(armoredToken, ArmoredFooter) {
		t.Fatalf("armoredToken missing header/footer markers:\n%s", armoredToken)
	}

	verifiedArmored, err := validator.Verify(armoredToken)
	if err != nil {
		t.Fatalf("Verify(armoredToken) failed: %v", err)
	}
	if verifiedArmored.ID != claims.ID {
		t.Errorf("ID mismatch: got %s, want %s", verifiedArmored.ID, claims.ID)
	}
}

func TestProductMismatch(t *testing.T) {
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	signer, _ := NewSigner(priv)
	claims := sampleClaims()
	claims.Product = "otel-aws-log-processor"

	token, err := signer.Sign(claims)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	// Validator expecting gitlab-fleet-governor
	validator, _ := NewValidator(pub, WithProduct("gitlab-fleet-governor"))
	_, err = validator.Verify(token)
	if err == nil {
		t.Fatal("expected error for product mismatch, got nil")
	}
	if !errors.Is(err, ErrProductMismatch) {
		t.Errorf("expected ErrProductMismatch, got %v", err)
	}

	// Validator with matching product
	matchingValidator, _ := NewValidator(pub, WithProduct("otel-aws-log-processor"))
	c, err := matchingValidator.Verify(token)
	if err != nil {
		t.Fatalf("Verify with matching product failed: %v", err)
	}
	if c.Product != "otel-aws-log-processor" {
		t.Errorf("expected product otel-aws-log-processor, got %s", c.Product)
	}
}

func TestProductWildcardAndSuiteMatching(t *testing.T) {
	pub, priv, _ := GenerateKeyPair()
	signer, _ := NewSigner(priv)

	// 1. Universal Wildcard "*"
	starClaims := sampleClaims()
	starClaims.Product = "*"
	starToken, _ := signer.Sign(starClaims)

	vGitlab, _ := NewValidator(pub, WithProduct("gitlab-fleet-governor"))
	if _, err := vGitlab.Verify(starToken); err != nil {
		t.Fatalf("expected Product='*' to validate for gitlab-fleet-governor, got %v", err)
	}
	vOtel, _ := NewValidator(pub, WithProduct("otel-aws-log-processor"))
	if _, err := vOtel.Verify(starToken); err != nil {
		t.Fatalf("expected Product='*' to validate for otel-aws-log-processor, got %v", err)
	}

	// 2. "all" Wildcard
	allClaims := sampleClaims()
	allClaims.Product = "ALL"
	allToken, _ := signer.Sign(allClaims)
	if _, err := vGitlab.Verify(allToken); err != nil {
		t.Fatalf("expected Product='ALL' to validate for gitlab-fleet-governor, got %v", err)
	}

	// 3. Suite Bundles: "divmora-suite" & "suite"
	suiteClaims := sampleClaims()
	suiteClaims.Product = "divmora-suite"
	suiteToken, _ := signer.Sign(suiteClaims)
	if _, err := vGitlab.Verify(suiteToken); err != nil {
		t.Fatalf("expected Product='divmora-suite' to validate for gitlab, got %v", err)
	}
	if _, err := vOtel.Verify(suiteToken); err != nil {
		t.Fatalf("expected Product='divmora-suite' to validate for otel, got %v", err)
	}

	shortSuiteClaims := sampleClaims()
	shortSuiteClaims.Product = "suite"
	shortSuiteToken, _ := signer.Sign(shortSuiteClaims)
	if _, err := vGitlab.Verify(shortSuiteToken); err != nil {
		t.Fatalf("expected Product='suite' to validate, got %v", err)
	}

	// 4. Multi-Product comma-separated list
	multiClaims := sampleClaims()
	multiClaims.Product = "gitlab-fleet-governor, otel-aws-log-processor"
	multiToken, _ := signer.Sign(multiClaims)
	if _, err := vGitlab.Verify(multiToken); err != nil {
		t.Fatalf("expected multi-product license to validate for gitlab, got %v", err)
	}
	if _, err := vOtel.Verify(multiToken); err != nil {
		t.Fatalf("expected multi-product license to validate for otel, got %v", err)
	}

	vOther, _ := NewValidator(pub, WithProduct("unrelated-product"))
	_, err := vOther.Verify(multiToken)
	if err == nil || !errors.Is(err, ErrProductMismatch) {
		t.Fatalf("expected ErrProductMismatch for unrelated-product, got %v", err)
	}

	// 5. Glob pattern matching: "gitlab-*"
	globClaims := sampleClaims()
	globClaims.Product = "gitlab-*"
	globToken, _ := signer.Sign(globClaims)
	if _, err := vGitlab.Verify(globToken); err != nil {
		t.Fatalf("expected Product='gitlab-*' to validate for gitlab-fleet-governor, got %v", err)
	}
	_, err = vOtel.Verify(globToken)
	if err == nil || !errors.Is(err, ErrProductMismatch) {
		t.Fatalf("expected ErrProductMismatch for otel with pattern 'gitlab-*', got %v", err)
	}
}

func TestFingerprintValidation(t *testing.T) {
	pub, priv, _ := GenerateKeyPair()
	signer, _ := NewSigner(priv)

	lockedClaims := sampleClaims()
	lockedClaims.Fingerprint = "node-cluster-xyz-789"
	lockedToken, _ := signer.Sign(lockedClaims)

	// 1. Validator with matching fingerprint -> SUCCESS
	vMatch, _ := NewValidator(pub, WithExpectedFingerprint("node-cluster-xyz-789"))
	if _, err := vMatch.Verify(lockedToken); err != nil {
		t.Fatalf("expected fingerprint match to succeed, got %v", err)
	}

	// 2. Case-insensitive matching -> SUCCESS
	vCaseInsensitive, _ := NewValidator(pub, WithExpectedFingerprint("NODE-CLUSTER-XYZ-789"))
	if _, err := vCaseInsensitive.Verify(lockedToken); err != nil {
		t.Fatalf("expected case-insensitive fingerprint match to succeed, got %v", err)
	}

	// 3. Validator with mismatching fingerprint -> FAIL with ErrFingerprintMismatch
	vMismatch, _ := NewValidator(pub, WithExpectedFingerprint("node-cluster-different"))
	_, err := vMismatch.Verify(lockedToken)
	if err == nil || !errors.Is(err, ErrFingerprintMismatch) {
		t.Fatalf("expected ErrFingerprintMismatch for mismatching host, got %v", err)
	}

	// 4. Security Bug Fix: Locked license verified WITHOUT host fingerprint -> MUST FAIL
	vNoFingerprint, _ := NewValidator(pub)
	_, err = vNoFingerprint.Verify(lockedToken)
	if err == nil || !errors.Is(err, ErrFingerprintMismatch) {
		t.Fatalf("expected ErrFingerprintMismatch when locked license verified without host fingerprint, got %v", err)
	}

	// 5. Floating license (Fingerprint == "") on validator with host fingerprint -> SUCCESS
	floatingClaims := sampleClaims()
	floatingToken, _ := signer.Sign(floatingClaims)
	if _, err := vMatch.Verify(floatingToken); err != nil {
		t.Fatalf("expected floating license to be accepted by host with fingerprint, got %v", err)
	}

	// 6. Floating license on validator with WithRequireFingerprint(true) -> FAIL
	vStrict, _ := NewValidator(pub, WithRequireFingerprint(true))
	_, err = vStrict.Verify(floatingToken)
	if err == nil || !errors.Is(err, ErrFingerprintMismatch) {
		t.Fatalf("expected ErrFingerprintMismatch when floating license rejected by strict validator, got %v", err)
	}

	// 7. Helper methods
	if !lockedClaims.IsBoundToFingerprint() {
		t.Error("expected lockedClaims.IsBoundToFingerprint() to be true")
	}
	if floatingClaims.IsBoundToFingerprint() {
		t.Error("expected floatingClaims.IsBoundToFingerprint() to be false")
	}
	if !lockedClaims.MatchesFingerprint("node-cluster-xyz-789") {
		t.Error("expected MatchesFingerprint to be true for exact match")
	}
	if lockedClaims.MatchesFingerprint("wrong-node") {
		t.Error("expected MatchesFingerprint to be false for mismatch")
	}
	if lockedClaims.MatchesFingerprint("") {
		t.Error("expected MatchesFingerprint to be false for empty host on locked license")
	}
	if !floatingClaims.MatchesFingerprint("any-host") {
		t.Error("expected MatchesFingerprint to be true for any host on floating license")
	}
}

func TestTamperingDetection(t *testing.T) {
	pub, priv, _ := GenerateKeyPair()
	signer, _ := NewSigner(priv)
	validator, _ := NewValidator(pub)

	claims := sampleClaims()
	token, err := signer.Sign(claims)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("invalid token format")
	}

	// 1. Tamper payload: flip a character in base64 payload
	tamperedPayload := []byte(parts[1])
	if tamperedPayload[0] == 'A' {
		tamperedPayload[0] = 'B'
	} else {
		tamperedPayload[0] = 'A'
	}
	tamperedToken := strings.Join([]string{parts[0], string(tamperedPayload), parts[2]}, ".")

	_, err = validator.Verify(tamperedToken)
	if err == nil {
		t.Fatal("expected error on tampered payload, got nil")
	}

	// 2. Tamper signature
	tamperedSig := []byte(parts[2])
	if tamperedSig[0] == 'A' {
		tamperedSig[0] = 'B'
	} else {
		tamperedSig[0] = 'A'
	}
	tamperedSigToken := strings.Join([]string{parts[0], parts[1], string(tamperedSig)}, ".")

	_, err = validator.Verify(tamperedSigToken)
	if err == nil || !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected ErrInvalidSignature on tampered signature, got %v", err)
	}
}

func TestExpirationAndClockSkew(t *testing.T) {
	pub, priv, _ := GenerateKeyPair()
	signer, _ := NewSigner(priv)

	now := time.Now().UTC()

	// 1. Expired license (expired 10 minutes ago)
	expiredClaims := sampleClaims()
	expiredClaims.ExpiresAt = now.Add(-10 * time.Minute)

	token, _ := signer.Sign(expiredClaims)

	// Without clock skew / grace period -> fails
	validatorNoSkew, _ := NewValidator(pub, WithClockSkew(0))
	_, err := validatorNoSkew.Verify(token)
	if err == nil || !errors.Is(err, ErrExpired) {
		t.Fatalf("expected ErrExpired, got %v", err)
	}

	// With 15 minutes clock skew -> succeeds
	validatorWithSkew, _ := NewValidator(pub, WithClockSkew(15*time.Minute))
	if _, err := validatorWithSkew.Verify(token); err != nil {
		t.Fatalf("expected verification to succeed with clock skew, got %v", err)
	}

	// With 15 minutes grace period -> succeeds
	validatorWithGrace, _ := NewValidator(pub, WithClockSkew(0), WithGracePeriod(15*time.Minute))
	if _, err := validatorWithGrace.Verify(token); err != nil {
		t.Fatalf("expected verification to succeed with grace period, got %v", err)
	}

	// With AllowExpired -> succeeds
	validatorAllowExpired, _ := NewValidator(pub, WithClockSkew(0), WithAllowExpired(true))
	if _, err := validatorAllowExpired.Verify(token); err != nil {
		t.Fatalf("expected verification to succeed with allowExpired, got %v", err)
	}

	// 2. Not yet valid license (valid in 10 minutes)
	futureClaims := sampleClaims()
	futureClaims.NotBefore = now.Add(10 * time.Minute)
	futureClaims.ExpiresAt = now.Add(1 * time.Hour)

	futureToken, _ := signer.Sign(futureClaims)
	_, err = validatorNoSkew.Verify(futureToken)
	if err == nil || !errors.Is(err, ErrNotYetValid) {
		t.Fatalf("expected ErrNotYetValid, got %v", err)
	}
}

func TestClaimsHelpers(t *testing.T) {
	now := time.Now().UTC()
	c := Claims{
		ID: "lic-helpers",
		Customer: Customer{
			Name:  "Acme Corp",
			Email: "admin@acme.com",
			OrgID: "org_acme_123",
		},
		Product:   "otel-aws-log-processor",
		Plan:      "Enterprise",
		IssuedAt:  now,
		ExpiresAt: now.Add(48 * time.Hour),
		Features:  []string{"high_throughput", "s3_archive", "metrics"},
		Limits: map[string]int64{
			"max_nodes":   50,
			"unlimited_x": -1,
		},
		Metadata: map[string]string{
			"Env": "Production",
		},
	}

	// Features
	if !c.HasFeature("high_throughput") {
		t.Error("expected HasFeature(high_throughput) to be true")
	}
	if !c.HasFeature("HIGH_THROUGHPUT") {
		t.Error("expected case-insensitive feature check to succeed")
	}
	if c.HasFeature("non_existent") {
		t.Error("expected HasFeature(non_existent) to be false")
	}
	if err := c.AssertFeature("high_throughput"); err != nil {
		t.Errorf("AssertFeature failed: %v", err)
	}
	if err := c.AssertFeature("non_existent"); err == nil || !errors.Is(err, ErrFeatureNotEntitled) {
		t.Errorf("expected ErrFeatureNotEntitled, got %v", err)
	}

	// Limits
	if err := c.CheckLimit("max_nodes", 40); err != nil {
		t.Errorf("CheckLimit(40 <= 50) failed: %v", err)
	}
	if err := c.CheckLimit("max_nodes", 50); err != nil {
		t.Errorf("CheckLimit(50 <= 50) failed: %v", err)
	}
	err := c.CheckLimit("max_nodes", 51)
	if err == nil || !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("expected ErrLimitExceeded for 51 > 50, got %v", err)
	}
	var limErr *LimitExceededError
	if !errors.As(err, &limErr) {
		t.Fatalf("expected *LimitExceededError, got %T", err)
	}
	if limErr.Current != 51 || limErr.Allowed != 50 {
		t.Errorf("unexpected LimitExceededError fields: %+v", limErr)
	}

	// Unlimited limit
	if err := c.CheckLimit("unlimited_x", 100000); err != nil {
		t.Errorf("CheckLimit for unlimited failed: %v", err)
	}

	// Non-existent limit (defaults to no restriction)
	if err := c.CheckLimit("undefined_limit", 1000); err != nil {
		t.Errorf("CheckLimit for undefined limit failed: %v", err)
	}

	// Expiration & Days
	if c.IsExpired() {
		t.Error("expected license not to be expired")
	}
	days := c.DaysRemaining()
	if days < 1 || days > 2 {
		t.Errorf("expected days remaining ~2, got %d", days)
	}

	// Metadata
	val, ok := c.GetMetadata("env")
	if !ok || val != "Production" {
		t.Errorf("GetMetadata(env) failed, got %q, %v", val, ok)
	}

	// Perpetual license check
	perp := Claims{
		Customer: Customer{
			Name: "Acme",
		},
		Product: "otel-aws-log-processor",
	}
	if !perp.IsPerpetual() {
		t.Error("expected IsPerpetual() to be true for zero ExpiresAt")
	}
	if perp.DaysRemaining() != -1 {
		t.Errorf("expected DaysRemaining() == -1 for perpetual, got %d", perp.DaysRemaining())
	}
}

func TestInspect(t *testing.T) {
	_, priv, _ := GenerateKeyPair()
	signer, _ := NewSigner(priv)

	claims := sampleClaims()
	armored, err := signer.SignArmored(claims)
	if err != nil {
		t.Fatalf("SignArmored failed: %v", err)
	}

	// Inspect without any public key
	inspected, err := Inspect(armored)
	if err != nil {
		t.Fatalf("Inspect failed: %v", err)
	}
	if inspected.Customer != claims.Customer {
		t.Errorf("inspected customer mismatch: %+v != %+v", inspected.Customer, claims.Customer)
	}
	if inspected.Product != claims.Product {
		t.Errorf("inspected product mismatch: %s != %s", inspected.Product, claims.Product)
	}
}

func TestUnwrapTokenFormatting(t *testing.T) {
	rawToken := "DIV1.payload.signature"
	armored := "-----BEGIN DIVMORA LICENSE KEY-----\r\nDIV1.\r\npayload.\r\nsignature\r\n-----END DIVMORA LICENSE KEY-----\r\n"

	unwrapped, err := UnwrapToken(armored)
	if err != nil {
		t.Fatalf("UnwrapToken failed: %v", err)
	}
	if unwrapped != rawToken {
		t.Errorf("expected unwrapped token %q, got %q", rawToken, unwrapped)
	}
}

func TestFeatureWildcardMatching(t *testing.T) {
	// 1. Star wildcard: "*" grants all features
	starClaims := Claims{
		Features: []string{"*"},
	}
	if !starClaims.HasFeature("ha") {
		t.Error("expected '*' to match 'ha'")
	}
	if !starClaims.HasFeature("audit:logs") {
		t.Error("expected '*' to match 'audit:logs'")
	}
	if !starClaims.HasFeature("nested/path/feature") {
		t.Error("expected '*' to match 'nested/path/feature'")
	}
	if err := starClaims.AssertFeature("anything"); err != nil {
		t.Errorf("expected AssertFeature to pass for '*', got %v", err)
	}

	// 2. "all" wildcard (case-insensitive)
	allClaims := Claims{
		Features: []string{"ALL"},
	}
	if !allClaims.HasFeature("ha") {
		t.Error("expected 'ALL' to match 'ha'")
	}
	if !allClaims.HasFeature("s3_export") {
		t.Error("expected 'ALL' to match 's3_export'")
	}

	// 3. Glob pattern matching
	patternClaims := Claims{
		Features: []string{"audit:*", "s3_*", "report-*-monthly"},
	}
	if !patternClaims.HasFeature("audit:read") {
		t.Error("expected 'audit:*' to match 'audit:read'")
	}
	if !patternClaims.HasFeature("audit:write") {
		t.Error("expected 'audit:*' to match 'audit:write'")
	}
	if patternClaims.HasFeature("metrics:read") {
		t.Error("expected 'metrics:read' NOT to match 'audit:*'")
	}
	if !patternClaims.HasFeature("s3_archive") {
		t.Error("expected 's3_*' to match 's3_archive'")
	}
	if patternClaims.HasFeature("gcs_archive") {
		t.Error("expected 'gcs_archive' NOT to match 's3_*'")
	}
	if !patternClaims.HasFeature("report-finance-monthly") {
		t.Error("expected 'report-*-monthly' to match 'report-finance-monthly'")
	}
	if patternClaims.HasFeature("report-finance-daily") {
		t.Error("expected 'report-finance-daily' NOT to match 'report-*-monthly'")
	}

	// 4. Empty features
	emptyClaims := Claims{}
	if emptyClaims.HasFeature("any") {
		t.Error("expected empty features NOT to match 'any'")
	}
}

func TestGracePeriodDynamics(t *testing.T) {
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	signer, _ := NewSigner(priv)
	validator, _ := NewValidator(pub, WithProduct("gitlab-fleet-governor"), WithClockSkew(0))

	now := time.Now().UTC()

	// 1. Issue license expiring 2 days ago, but with 10 days GracePeriodDays
	claims := sampleClaims()
	claims.IssuedAt = now.Add(-30 * 24 * time.Hour)
	claims.ExpiresAt = now.Add(-2 * 24 * time.Hour)
	claims.GracePeriodDays = 10

	token, err := signer.Sign(claims)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	// 2. Direct Claims check
	if !claims.IsExpired() {
		t.Error("expected IsExpired() == true because ExpiresAt has passed")
	}
	if !claims.IsInGracePeriod() {
		t.Error("expected IsInGracePeriod() == true because within 10 days grace")
	}
	if !claims.IsActive() {
		t.Error("expected IsActive() == true while operating in grace period")
	}
	if claims.Status() != StatusGracePeriod {
		t.Errorf("expected Status == GRACE_PERIOD, got %s", claims.Status())
	}
	graceDays := claims.GraceDaysRemaining()
	if graceDays < 7 || graceDays > 8 {
		t.Errorf("expected ~7-8 grace days remaining, got %d", graceDays)
	}

	// 3. VerifyWithResult should succeed and expose grace period
	result, err := validator.VerifyWithResult(token)
	if err != nil {
		t.Fatalf("VerifyWithResult failed during grace period: %v", err)
	}
	if !result.InGracePeriod {
		t.Error("expected result.InGracePeriod == true")
	}
	if result.Status != StatusGracePeriod {
		t.Errorf("expected result.Status == GRACE_PERIOD, got %s", result.Status)
	}
	if result.GraceDaysRemaining < 7 || result.GraceDaysRemaining > 8 {
		t.Errorf("expected result.GraceDaysRemaining ~7-8, got %d", result.GraceDaysRemaining)
	}
	expectedEffectiveCutoff := claims.ExpiresAt.Add(10 * 24 * time.Hour)
	if !result.EffectiveExpiry.Equal(expectedEffectiveCutoff) {
		t.Errorf("expected EffectiveExpiry %v, got %v", expectedEffectiveCutoff, result.EffectiveExpiry)
	}

	// 4. Verify past grace period (e.g. 12 days past ExpiresAt)
	futureTime := claims.ExpiresAt.Add(12 * 24 * time.Hour)
	if claims.IsInGracePeriodAt(futureTime) {
		t.Error("expected IsInGracePeriodAt to be false past grace cutoff")
	}
	if claims.IsActiveAt(futureTime) {
		t.Error("expected IsActiveAt to be false past grace cutoff")
	}
	if claims.StatusAt(futureTime) != StatusExpired {
		t.Errorf("expected StatusAt == EXPIRED past grace cutoff, got %s", claims.StatusAt(futureTime))
	}

	_, err = validator.VerifyAt(token, futureTime)
	if err == nil || !errors.Is(err, ErrExpired) {
		t.Fatalf("expected ErrExpired past grace cutoff, got %v", err)
	}

	// 5. Active license before expiration
	activeClaims := sampleClaims()
	activeClaims.ExpiresAt = now.Add(10 * 24 * time.Hour)
	activeClaims.GracePeriodDays = 7
	if activeClaims.IsInGracePeriod() {
		t.Error("expected IsInGracePeriod == false before expiration")
	}
	if activeClaims.Status() != StatusActive {
		t.Errorf("expected Status == ACTIVE before expiration, got %s", activeClaims.Status())
	}
}

func TestValidator_VerifyEnvAndResolved(t *testing.T) {
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	signer, _ := NewSigner(priv)
	validator, _ := NewValidator(pub, WithProduct("gitlab-fleet-governor"))

	claims := sampleClaims()
	token, err := signer.SignArmored(claims)
	if err != nil {
		t.Fatalf("SignArmored failed: %v", err)
	}

	// 1. VerifyEnv via DIVMORA_LICENSE_KEY
	t.Setenv(EnvLicenseKey, token)
	t.Setenv(EnvLicenseFile, "")

	verifiedKey, err := validator.VerifyEnv()
	if err != nil {
		t.Fatalf("VerifyEnv failed: %v", err)
	}
	if verifiedKey.ID != claims.ID {
		t.Errorf("expected ID %q, got %q", claims.ID, verifiedKey.ID)
	}

	// 2. VerifyResolved with explicit file
	tempDir := t.TempDir()
	licFile := filepath.Join(tempDir, "test.lic")
	if err := os.WriteFile(licFile, []byte(token), 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	verifiedFile, err := validator.VerifyResolved(licFile)
	if err != nil {
		t.Fatalf("VerifyResolved failed: %v", err)
	}
	if verifiedFile.ID != claims.ID {
		t.Errorf("expected ID %q, got %q", claims.ID, verifiedFile.ID)
	}

	// 3. VerifyResolved with fallback to env
	verifiedFallback, err := validator.VerifyResolved("")
	if err != nil {
		t.Fatalf("VerifyResolved fallback failed: %v", err)
	}
	if verifiedFallback.ID != claims.ID {
		t.Errorf("expected ID %q, got %q", claims.ID, verifiedFallback.ID)
	}
}

func TestClaims_FeatureSlashIsolation(t *testing.T) {
	t.Parallel()

	claims := Claims{
		Features: []string{
			"audit:*",
			"*-export",
			"sec/**/report",
		},
	}

	// 1. Single wildcard '*' within a segment
	if !claims.HasFeature("audit:read") {
		t.Error("expected 'audit:*' to match 'audit:read'")
	}
	if !claims.HasFeature("audit:write") {
		t.Error("expected 'audit:*' to match 'audit:write'")
	}
	// Slash traversal must be blocked
	if claims.HasFeature("audit:read/unauthorized") {
		t.Error("expected 'audit:*' to NOT match 'audit:read/unauthorized'")
	}

	// 2. Trailing wildcard '*-export'
	if !claims.HasFeature("s3-export") {
		t.Error("expected '*-export' to match 's3-export'")
	}
	if claims.HasFeature("unauthorized/s3-export") {
		t.Error("expected '*-export' to NOT match 'unauthorized/s3-export'")
	}

	// 3. Globstar '**' recursive feature matching
	if !claims.HasFeature("sec/report") {
		t.Error("expected 'sec/**/report' to match 'sec/report'")
	}
	if !claims.HasFeature("sec/finance/report") {
		t.Error("expected 'sec/**/report' to match 'sec/finance/report'")
	}
	if !claims.HasFeature("sec/finance/monthly/report") {
		t.Error("expected 'sec/**/report' to match 'sec/finance/monthly/report'")
	}
	if claims.HasFeature("other/sec/report") {
		t.Error("expected 'sec/**/report' to NOT match 'other/sec/report'")
	}
}

func TestValidator_ClockSkewStatusAlignment(t *testing.T) {
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	signer, err := NewSigner(priv)
	if err != nil {
		t.Fatalf("NewSigner failed: %v", err)
	}

	baseTime := time.Date(2026, time.June, 15, 12, 0, 0, 0, time.UTC)
	clockSkew := 5 * time.Minute

	// 1. Post-expiration within clock skew (ExpiresAt + 2m with 5m skew tolerance)
	t.Run("post-expiration within clock skew tolerance", func(t *testing.T) {
		claims := Claims{
			Product:   "gitlab-fleet-governor",
			Customer:  Customer{Name: "Acme Corp"},
			ExpiresAt: baseTime,
		}
		token, err := signer.Sign(claims)
		if err != nil {
			t.Fatalf("Sign failed: %v", err)
		}

		validator, err := NewValidator(pub,
			WithProduct("gitlab-fleet-governor"),
			WithClockSkew(clockSkew),
		)
		if err != nil {
			t.Fatalf("NewValidator failed: %v", err)
		}

		evalTime := baseTime.Add(2 * time.Minute)
		res, err := validator.VerifyWithResultAt(token, evalTime)
		if err != nil {
			t.Fatalf("expected verification to succeed within clock skew tolerance, got: %v", err)
		}

		// Status must be ACTIVE, NOT EXPIRED!
		if res.Status != StatusActive {
			t.Errorf("expected Status %v, got %v", StatusActive, res.Status)
		}
		if res.InGracePeriod {
			t.Errorf("expected InGracePeriod to be false")
		}
		if !res.Claims.IsActiveAt(evalTime, clockSkew) {
			t.Errorf("expected Claims.IsActiveAt to be true within clock skew")
		}
		if res.Claims.IsExpiredAt(evalTime, clockSkew) {
			t.Errorf("expected Claims.IsExpiredAt to be false within clock skew")
		}
		if !strings.HasPrefix(res.StatusMessage(), "Active (less than 1 day remaining") {
			t.Errorf("expected Active status message, got: %q", res.StatusMessage())
		}
	})

	// 2. Pre-NotBefore within clock skew (NotBefore - 2m with 5m skew tolerance)
	t.Run("pre-NotBefore within clock skew tolerance", func(t *testing.T) {
		claims := Claims{
			Product:   "gitlab-fleet-governor",
			Customer:  Customer{Name: "Acme Corp"},
			NotBefore: baseTime,
			ExpiresAt: baseTime.Add(30 * 24 * time.Hour),
		}
		token, err := signer.Sign(claims)
		if err != nil {
			t.Fatalf("Sign failed: %v", err)
		}

		validator, err := NewValidator(pub,
			WithProduct("gitlab-fleet-governor"),
			WithClockSkew(clockSkew),
		)
		if err != nil {
			t.Fatalf("NewValidator failed: %v", err)
		}

		evalTime := baseTime.Add(-2 * time.Minute)
		res, err := validator.VerifyWithResultAt(token, evalTime)
		if err != nil {
			t.Fatalf("expected verification to succeed within NotBefore clock skew tolerance, got: %v", err)
		}

		if res.Status != StatusActive {
			t.Errorf("expected Status %v, got %v", StatusActive, res.Status)
		}
		if !res.Claims.IsActiveAt(evalTime, clockSkew) {
			t.Errorf("expected Claims.IsActiveAt to be true")
		}
		if res.Claims.StatusAt(evalTime, clockSkew) != StatusActive {
			t.Errorf("expected Claims.StatusAt to be StatusActive with skew")
		}
	})

	// 3. Grace period cutoff with clock skew (Grace cutoff + 2m with 5m skew tolerance)
	t.Run("grace period cutoff with clock skew tolerance", func(t *testing.T) {
		claims := Claims{
			Product:         "gitlab-fleet-governor",
			Customer:        Customer{Name: "Acme Corp"},
			ExpiresAt:       baseTime.Add(-7 * 24 * time.Hour),
			GracePeriodDays: 7,
		}
		token, err := signer.Sign(claims)
		if err != nil {
			t.Fatalf("Sign failed: %v", err)
		}

		validator, err := NewValidator(pub,
			WithProduct("gitlab-fleet-governor"),
			WithClockSkew(clockSkew),
		)
		if err != nil {
			t.Fatalf("NewValidator failed: %v", err)
		}

		// baseTime is exactly the grace cutoff (ExpiresAt + 7 days)
		evalTime := baseTime.Add(2 * time.Minute) // 2 minutes past grace cutoff, within 5m skew
		res, err := validator.VerifyWithResultAt(token, evalTime)
		if err != nil {
			t.Fatalf("expected verification to succeed within grace cutoff clock skew tolerance, got: %v", err)
		}

		if res.Status != StatusGracePeriod {
			t.Errorf("expected Status %v, got %v", StatusGracePeriod, res.Status)
		}
		if !res.InGracePeriod {
			t.Errorf("expected InGracePeriod to be true")
		}
		if !strings.Contains(res.StatusMessage(), "Operating in grace period") {
			t.Errorf("expected grace period status message, got: %q", res.StatusMessage())
		}
	})

	// 4. Hard expiration exceeding clock skew (ExpiresAt + 6m with 5m skew tolerance)
	t.Run("hard expiration beyond clock skew tolerance", func(t *testing.T) {
		claims := Claims{
			Product:   "gitlab-fleet-governor",
			Customer:  Customer{Name: "Acme Corp"},
			ExpiresAt: baseTime,
		}
		token, err := signer.Sign(claims)
		if err != nil {
			t.Fatalf("Sign failed: %v", err)
		}

		validator, err := NewValidator(pub,
			WithProduct("gitlab-fleet-governor"),
			WithClockSkew(clockSkew),
		)
		if err != nil {
			t.Fatalf("NewValidator failed: %v", err)
		}

		evalTime := baseTime.Add(6 * time.Minute)
		_, err = validator.VerifyWithResultAt(token, evalTime)
		if !errors.Is(err, ErrExpired) {
			t.Fatalf("expected ErrExpired when exceeding clock skew, got: %v", err)
		}

		// With WithAllowExpired(true)
		valAllow, _ := NewValidator(pub,
			WithProduct("gitlab-fleet-governor"),
			WithClockSkew(clockSkew),
			WithAllowExpired(true),
		)
		resExpired, err := valAllow.VerifyWithResultAt(token, evalTime)
		if err != nil {
			t.Fatalf("expected WithAllowExpired to succeed, got: %v", err)
		}
		if resExpired.Status != StatusExpired {
			t.Errorf("expected StatusExpired, got %v", resExpired.Status)
		}
		if resExpired.Claims.IsActiveAt(evalTime, clockSkew) {
			t.Errorf("expected Claims.IsActiveAt to be false beyond clock skew")
		}
		if !resExpired.Claims.IsExpiredAt(evalTime, clockSkew) {
			t.Errorf("expected Claims.IsExpiredAt to be true beyond clock skew")
		}
		if !strings.HasPrefix(resExpired.StatusMessage(), "License expired on") {
			t.Errorf("expected expired status message, got: %q", resExpired.StatusMessage())
		}
	})
}
