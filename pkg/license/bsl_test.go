package license_test

import (
	"errors"
	"testing"
	"time"

	"github.com/divmora/license-go/pkg/license"
)

func TestBSLPolicy_ChangeDateAndConversion(t *testing.T) {
	t.Parallel()

	releaseDate := time.Date(2025, time.January, 1, 0, 0, 0, 0, time.UTC)
	policy := license.BSLPolicy{
		ReleaseDate:       releaseDate,
		ChangePeriodYears: 3,
	}

	expectedChangeDate := time.Date(2028, time.January, 1, 0, 0, 0, 0, time.UTC)
	if policy.ChangeDate() != expectedChangeDate {
		t.Fatalf("expected ChangeDate %v, got %v", expectedChangeDate, policy.ChangeDate())
	}

	// 1 day before conversion
	beforeTime := expectedChangeDate.Add(-24 * time.Hour)
	if policy.IsConverted(beforeTime) {
		t.Fatalf("expected IsConverted to be false before ChangeDate")
	}
	if lic := policy.EffectiveLicense(beforeTime); lic != "BSL-1.1" {
		t.Fatalf("expected effective license BSL-1.1, got %s", lic)
	}
	if days := policy.DaysUntilConversion(beforeTime); days != 1 {
		t.Fatalf("expected 1 day until conversion, got %d", days)
	}

	// Exactly on ChangeDate
	if !policy.IsConverted(expectedChangeDate) {
		t.Fatalf("expected IsConverted to be true on ChangeDate")
	}
	if lic := policy.EffectiveLicense(expectedChangeDate); lic != "Apache-2.0" {
		t.Fatalf("expected effective license Apache-2.0, got %s", lic)
	}
	if days := policy.DaysUntilConversion(expectedChangeDate); days != 0 {
		t.Fatalf("expected 0 days until conversion on ChangeDate, got %d", days)
	}

	// After ChangeDate
	afterTime := expectedChangeDate.AddDate(1, 0, 0)
	if !policy.IsConverted(afterTime) {
		t.Fatalf("expected IsConverted to be true after ChangeDate")
	}
	if lic := policy.EffectiveLicense(afterTime); lic != "Apache-2.0" {
		t.Fatalf("expected effective license Apache-2.0, got %s", lic)
	}
}

func TestBSLPolicy_CustomAndExplicitSettings(t *testing.T) {
	t.Parallel()

	// Default 3 years when ChangePeriodYears is 0
	releaseDate := time.Date(2024, time.June, 15, 12, 0, 0, 0, time.UTC)
	defaultPolicy := license.BSLPolicy{
		ReleaseDate: releaseDate,
	}
	if defaultPolicy.ChangeDate() != releaseDate.AddDate(3, 0, 0) {
		t.Fatalf("expected default 3 years, got %v", defaultPolicy.ChangeDate())
	}

	// Explicit cutoff timestamp overrides ReleaseDate + Years
	explicitDate := time.Date(2026, time.December, 31, 23, 59, 59, 0, time.UTC)
	explicitPolicy := license.BSLPolicy{
		ReleaseDate:        releaseDate,
		ChangePeriodYears:  5,
		ExplicitChangeDate: explicitDate,
		ChangeLicense:      "MIT",
	}
	if explicitPolicy.ChangeDate() != explicitDate {
		t.Fatalf("expected explicit ChangeDate %v, got %v", explicitDate, explicitPolicy.ChangeDate())
	}
	if lic := explicitPolicy.EffectiveLicense(explicitDate.Add(time.Hour)); lic != "MIT" {
		t.Fatalf("expected MIT license, got %s", lic)
	}

	// Zero ReleaseDate returns zero time
	emptyPolicy := license.BSLPolicy{}
	if !emptyPolicy.ChangeDate().IsZero() {
		t.Fatalf("expected zero ChangeDate for empty policy")
	}
	if emptyPolicy.IsConverted(time.Now()) {
		t.Fatalf("expected IsConverted to be false for empty policy")
	}
	if emptyPolicy.DaysUntilConversion(time.Now()) != 0 {
		t.Fatalf("expected 0 days until conversion for empty policy")
	}
}

func TestValidator_BSLConversionWorkflow(t *testing.T) {
	t.Parallel()

	pub, priv, err := license.GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}

	signer, err := license.NewSigner(priv)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	releaseDate := time.Date(2025, time.January, 1, 0, 0, 0, 0, time.UTC)
	changeDate := releaseDate.AddDate(3, 0, 0) // 2028-01-01

	bslPolicy := license.BSLPolicy{
		ReleaseDate:       releaseDate,
		ChangePeriodYears: 3,
	}

	validator, err := license.NewValidator(pub,
		license.WithProduct("gitlab-fleet-governor"),
		license.WithBSLPolicy(bslPolicy),
	)
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}

	// 1. Before Change Date: Missing license fails
	beforeDate := releaseDate.AddDate(1, 0, 0) // 2026-01-01
	_, err = validator.VerifyAt("", beforeDate)
	if !errors.Is(err, license.ErrLicenseNotFound) {
		t.Fatalf("expected ErrLicenseNotFound before Change Date, got: %v", err)
	}

	// 2. Before Change Date: Valid commercial token succeeds
	commercialClaims := license.Claims{
		Product:  "gitlab-fleet-governor",
		Plan:     "enterprise",
		Customer: license.Customer{Name: "Acme Corp"},
		IssuedAt: releaseDate,
		// Valid for 2 years (expires 2027-01-01)
		ExpiresAt: releaseDate.AddDate(2, 0, 0),
		Features:  []string{"high-availability"},
	}
	token, err := signer.Sign(commercialClaims)
	if err != nil {
		t.Fatalf("failed to sign license: %v", err)
	}

	res, err := validator.VerifyWithResultAt(token, beforeDate)
	if err != nil {
		t.Fatalf("expected verification to succeed before Change Date, got: %v", err)
	}
	if res.BSLConverted {
		t.Fatalf("expected BSLConverted to be false before Change Date")
	}
	if res.EffectiveLicense != "BSL-1.1" {
		t.Fatalf("expected EffectiveLicense BSL-1.1, got %s", res.EffectiveLicense)
	}
	if !res.Claims.HasFeature("high-availability") {
		t.Fatalf("expected commercial feature to be present")
	}

	// 3. After Change Date: Empty license token automatically succeeds with open-source entitlements
	afterDate := changeDate.AddDate(0, 1, 0) // 2028-02-01
	openRes, err := validator.VerifyWithResultAt("", afterDate)
	if err != nil {
		t.Fatalf("expected empty license to succeed after Change Date, got: %v", err)
	}
	if !openRes.BSLConverted {
		t.Fatalf("expected BSLConverted to be true after Change Date")
	}
	if openRes.EffectiveLicense != "Apache-2.0" {
		t.Fatalf("expected EffectiveLicense Apache-2.0, got %s", openRes.EffectiveLicense)
	}
	if openRes.Claims.Plan != "open-source" {
		t.Fatalf("expected plan open-source, got %s", openRes.Claims.Plan)
	}
	if !openRes.Claims.HasFeature("any-feature-whatsoever") {
		t.Fatalf("expected wildcard features in open-source claims")
	}

	// 4. After Change Date: Even an expired commercial token succeeds
	expiredRes, err := validator.VerifyWithResultAt(token, afterDate)
	if err != nil {
		t.Fatalf("expected expired token to succeed after Change Date, got: %v", err)
	}
	if !expiredRes.BSLConverted {
		t.Fatalf("expected BSLConverted to be true")
	}
	if expiredRes.EffectiveLicense != "Apache-2.0" {
		t.Fatalf("expected EffectiveLicense Apache-2.0, got %s", expiredRes.EffectiveLicense)
	}
}

func TestValidator_ClockTamperingDefense(t *testing.T) {
	t.Parallel()

	pub, priv, err := license.GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}

	signer, err := license.NewSigner(priv)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	releaseDate := time.Date(2025, time.January, 1, 0, 0, 0, 0, time.UTC)
	bslPolicy := license.BSLPolicy{
		ReleaseDate:       releaseDate,
		ChangePeriodYears: 3,
	}

	// Attacker tampers host clock to 2029 (4 years in future, claiming Apache 2.0 conversion!)
	tamperedHostTime := releaseDate.AddDate(4, 0, 0) // 2029-01-01

	// Authoritative server clock (e.g. from GitLab/AWS HTTP Date header) says it is only 2026-06-01 (1.5 years in)
	authoritativeServerTime := releaseDate.AddDate(1, 6, 0) // 2026-07-01

	validator, err := license.NewValidator(pub,
		license.WithProduct("gitlab-fleet-governor"),
		license.WithBSLPolicy(bslPolicy),
		license.WithAuthoritativeTime(authoritativeServerTime),
	)
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}

	// 1. Attacker tries to run without a license relying on forward clock tampering:
	// Because authoritative server clock proves Change Date has not arrived, validator MUST reject!
	_, err = validator.VerifyAt("", tamperedHostTime)
	if !errors.Is(err, license.ErrLicenseNotFound) {
		t.Fatalf("expected ErrLicenseNotFound when clock tampering detected and license missing, got: %v", err)
	}

	// 2. Attacker runs with a valid license issued for the authoritative period:
	validClaims := license.Claims{
		Product:   "gitlab-fleet-governor",
		Plan:      "enterprise",
		Customer:  license.Customer{Name: "Target Corp"},
		IssuedAt:  releaseDate,
		ExpiresAt: authoritativeServerTime.AddDate(1, 0, 0), // Valid in 2026
	}
	token, err := signer.Sign(validClaims)
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}

	res, err := validator.VerifyWithResultAt(token, tamperedHostTime)
	if err != nil {
		t.Fatalf("expected verification with valid token to succeed despite clock tampering, got: %v", err)
	}
	if !res.ClockTampered {
		t.Fatalf("expected ClockTampered flag to be true")
	}
	if res.BSLConverted {
		t.Fatalf("expected BSLConverted to be false because authoritative time anchored evaluation to before Change Date")
	}
	if res.EffectiveLicense != "BSL-1.1" {
		t.Fatalf("expected BSL-1.1 license, got %s", res.EffectiveLicense)
	}
}
