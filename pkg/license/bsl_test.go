package license_test

import (
	"errors"
	"strings"
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

	// 3. After Change Date: Empty license token automatically succeeds with open-source entitlements when authoritative time is attested!
	afterDate := changeDate.AddDate(0, 1, 0) // 2028-02-01
	validatorAttested, err := license.NewValidator(pub,
		license.WithProduct("gitlab-fleet-governor"),
		license.WithBSLPolicy(bslPolicy),
		license.WithServerTimeAttestation(afterDate, 1*time.Hour),
	)
	if err != nil {
		t.Fatalf("failed to create attested validator: %v", err)
	}

	openRes, err := validatorAttested.VerifyWithResultAt("", afterDate)
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

	// 4. After Change Date: Even an expired commercial token succeeds with attested time
	expiredRes, err := validatorAttested.VerifyWithResultAt(token, afterDate)
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

func TestValidator_ForwardClockTamperingBSLConversionDefeated(t *testing.T) {
	t.Parallel()

	pub, _, err := license.GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}

	releaseDate := time.Date(2025, time.January, 1, 0, 0, 0, 0, time.UTC)
	bslPolicy := license.BSLPolicy{
		ReleaseDate:       releaseDate,
		ChangePeriodYears: 3,
	}

	// 1. Unauthenticated forward clock tampering without authoritative time:
	// Attacker advances local host clock to 2029 (4 years in future, claiming BSL conversion)
	tamperedHostTime := releaseDate.AddDate(4, 0, 0) // 2029-01-01

	validatorUnauthenticated, err := license.NewValidator(pub,
		license.WithProduct("gitlab-fleet-governor"),
		license.WithBSLPolicy(bslPolicy),
	)
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}

	// Evaluating empty license token when local clock is tampered forward past ChangeDate:
	// Validator MUST reject with ClockTamperingError!
	_, err = validatorUnauthenticated.VerifyWithResultAt("", tamperedHostTime)
	if !errors.Is(err, license.ErrClockTamperingDetected) {
		t.Fatalf("expected ErrClockTamperingDetected on forward clock tampering, got: %v", err)
	}

	var clockErr *license.ClockTamperingError
	if !errors.As(err, &clockErr) {
		t.Fatalf("expected error to be *ClockTamperingError, got: %T", err)
	}
	if !strings.Contains(clockErr.Reason, "offline forward clock tampering detected") {
		t.Errorf("unexpected clock tampering reason: %s", clockErr.Reason)
	}

	// 2. Legitimate BSL conversion when server time is attested past ChangeDate:
	validatorAttested, err := license.NewValidator(pub,
		license.WithProduct("gitlab-fleet-governor"),
		license.WithBSLPolicy(bslPolicy),
		license.WithServerTimeAttestation(tamperedHostTime, 1*time.Hour),
	)
	if err != nil {
		t.Fatalf("failed to create attested validator: %v", err)
	}

	res, err := validatorAttested.VerifyWithResultAt("", tamperedHostTime)
	if err != nil {
		t.Fatalf("expected BSL conversion to succeed with attested server time, got: %v", err)
	}
	if !res.BSLConverted {
		t.Fatalf("expected BSLConverted to be true when server time is attested")
	}
	if res.EffectiveLicense != "Apache-2.0" {
		t.Errorf("expected EffectiveLicense Apache-2.0, got %s", res.EffectiveLicense)
	}
}

func TestBSLAdditionalUseGrant_NonProduction(t *testing.T) {
	t.Parallel()

	grant := license.NewNonProductionGrant("Non-Production Exemption")

	// 1. Permitted non-production environments
	nonProdEnvs := []string{"staging", "development", "dev", "test", "demo", "sandbox", "qa", "ci"}
	for _, env := range nonProdEnvs {
		eval := grant.Evaluate(license.BSLUsageRequest{
			Environment: env,
			Usage:       map[string]int64{"max_nodes": 1000}, // Unlimited in non-prod
		})
		if !eval.Matched {
			t.Errorf("expected environment %q to match non-production grant, got: %s", env, eval.Reason)
		}
	}

	// 2. Production environment must be rejected
	for _, prodEnv := range []string{"production", "prod", "Production", "PROD"} {
		eval := grant.Evaluate(license.BSLUsageRequest{
			Environment: prodEnv,
		})
		if eval.Matched {
			t.Errorf("expected production environment %q to be rejected, but matched", prodEnv)
		}
	}

	// 3. Unspecified environment must be rejected
	evalEmpty := grant.Evaluate(license.BSLUsageRequest{Environment: ""})
	if evalEmpty.Matched {
		t.Errorf("expected empty environment to be rejected, but matched")
	}
}

func TestBSLAdditionalUseGrant_FreeTier(t *testing.T) {
	t.Parallel()

	grant := license.NewFreeTierGrant(
		"Community Free Tier",
		map[string]int64{"max_nodes": 5, "max_runners": 20},
		"sso", "audit-logs",
	)

	// 1. Within quota, non-excluded features
	evalValid := grant.Evaluate(license.BSLUsageRequest{
		Environment: "production",
		Usage:       map[string]int64{"max_nodes": 4, "max_runners": 18},
		Features:    []string{"basic-ingest", "metrics"},
	})
	if !evalValid.Matched {
		t.Fatalf("expected usage within limits to match, got: %s", evalValid.Reason)
	}

	// 2. Exceeds quota (max_nodes = 6 > 5)
	evalExceeded := grant.Evaluate(license.BSLUsageRequest{
		Environment: "production",
		Usage:       map[string]int64{"max_nodes": 6, "max_runners": 10},
	})
	if evalExceeded.Matched {
		t.Fatalf("expected over-quota usage to be rejected")
	}
	if evalExceeded.ExceededLimits["max_nodes"] != 6 {
		t.Errorf("expected exceeded metric max_nodes = 6, got %v", evalExceeded.ExceededLimits)
	}

	// 3. Excluded feature requested ("sso")
	evalExcludedFeat := grant.Evaluate(license.BSLUsageRequest{
		Environment: "production",
		Usage:       map[string]int64{"max_nodes": 2, "max_runners": 5},
		Features:    []string{"basic-ingest", "sso"},
	})
	if evalExcludedFeat.Matched {
		t.Fatalf("expected excluded feature 'sso' to be rejected")
	}
	if len(evalExcludedFeat.DisallowedFeatures) == 0 || evalExcludedFeat.DisallowedFeatures[0] != "sso" {
		t.Errorf("expected disallowed feature 'sso', got %v", evalExcludedFeat.DisallowedFeatures)
	}

	// 4. Feature whitelist (AllowedFeatures)
	restrictedGrant := license.BSLAdditionalUseGrant{
		Name:            "Restricted Tier",
		AllowedFeatures: []string{"read-only", "export"},
	}
	evalDisallowedFeat := restrictedGrant.Evaluate(license.BSLUsageRequest{
		Features: []string{"read-only", "mutation"},
	})
	if evalDisallowedFeat.Matched {
		t.Fatalf("expected unentitled feature 'mutation' to be rejected")
	}
}

func TestBSLPolicy_EvaluateEntitlement_CombinedAndSuperseded(t *testing.T) {
	t.Parallel()

	releaseDate := time.Date(2025, time.January, 1, 0, 0, 0, 0, time.UTC)
	policy := license.BSLPolicy{
		ReleaseDate:       releaseDate,
		ChangePeriodYears: 3,
		Product:           "gitlab-fleet-governor",
		AdditionalUseGrants: []license.BSLAdditionalUseGrant{
			license.NewNonProductionGrant("Non-Production Exemption"),
			license.NewFreeTierGrant("Community Free Tier", map[string]int64{"max_nodes": 10, "max_runners": 50}, "sso"),
		},
	}

	refTime := time.Date(2026, time.June, 1, 0, 0, 0, 0, time.UTC)

	// 1. Staging with 100 nodes -> matches Non-Production Exemption
	stagingReq := license.BSLUsageRequest{
		Environment: "staging",
		Usage:       map[string]int64{"max_nodes": 100, "max_runners": 500},
		Time:        refTime,
	}
	resStaging := policy.EvaluateEntitlement(stagingReq)
	if !resStaging.Authorized {
		t.Fatalf("expected staging usage to be authorized, got: %s", resStaging.Reason)
	}
	if resStaging.GrantType != license.BSLGrantTypeAdditionalUseGrant {
		t.Errorf("expected grant type ADDITIONAL_USE_GRANT, got %s", resStaging.GrantType)
	}
	if resStaging.MatchingGrant != "Non-Production Exemption" {
		t.Errorf("expected matching grant 'Non-Production Exemption', got %s", resStaging.MatchingGrant)
	}
	if resStaging.Claims == nil || resStaging.Claims.Product != "gitlab-fleet-governor" {
		t.Errorf("expected synthetic claims for product, got %v", resStaging.Claims)
	}

	// 2. Production with 8 nodes -> matches Community Free Tier
	prodFreeReq := license.BSLUsageRequest{
		Environment: "production",
		Usage:       map[string]int64{"max_nodes": 8, "max_runners": 30},
		Time:        refTime,
	}
	resProdFree := policy.EvaluateEntitlement(prodFreeReq)
	if !resProdFree.Authorized {
		t.Fatalf("expected production free tier to be authorized, got: %s", resProdFree.Reason)
	}
	if resProdFree.MatchingGrant != "Community Free Tier" {
		t.Errorf("expected matching grant 'Community Free Tier', got %s", resProdFree.MatchingGrant)
	}
	if resProdFree.Claims.Limits["max_nodes"] != 10 {
		t.Errorf("expected claim limits max_nodes = 10, got %d", resProdFree.Claims.Limits["max_nodes"])
	}

	// 3. Production with 25 nodes -> rejected across all grants, commercial license required
	prodExceededReq := license.BSLUsageRequest{
		Environment: "production",
		Usage:       map[string]int64{"max_nodes": 25, "max_runners": 100},
		Time:        refTime,
	}
	resProdExceeded := policy.EvaluateEntitlement(prodExceededReq)
	if resProdExceeded.Authorized {
		t.Fatalf("expected commercial license required, but was authorized")
	}
	if resProdExceeded.GrantType != license.BSLGrantTypeRequiresCommercial {
		t.Errorf("expected grant type COMMERCIAL_LICENSE_REQUIRED, got %s", resProdExceeded.GrantType)
	}
	if len(resProdExceeded.Evaluations) != 2 {
		t.Errorf("expected 2 grant evaluations, got %d", len(resProdExceeded.Evaluations))
	}

	// 4. Once converted to open source (2028-01-01) -> full open source access supersedes all grants!
	convertedTime := time.Date(2028, time.January, 2, 0, 0, 0, 0, time.UTC)
	convertedReq := license.BSLUsageRequest{
		Environment: "production",
		Usage:       map[string]int64{"max_nodes": 1000000},
		Features:    []string{"sso", "audit-logs", "custom"},
		Time:        convertedTime,
	}
	resConverted := policy.EvaluateEntitlement(convertedReq)
	if !resConverted.Authorized {
		t.Fatalf("expected open-source converted usage to be authorized, got: %s", resConverted.Reason)
	}
	if resConverted.GrantType != license.BSLGrantTypeConverted {
		t.Errorf("expected grant type CONVERTED_OPEN_SOURCE, got %s", resConverted.GrantType)
	}
	if resConverted.EffectiveLicense != "Apache-2.0" {
		t.Errorf("expected effective license Apache-2.0, got %s", resConverted.EffectiveLicense)
	}
	if resConverted.DaysUntilConversion != 0 {
		t.Errorf("expected 0 days until conversion, got %d", resConverted.DaysUntilConversion)
	}
}

func TestBSLPolicy_EvaluateEntitlement_CustomMatchFunc(t *testing.T) {
	t.Parallel()

	policy := license.BSLPolicy{
		ReleaseDate:       time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		ChangePeriodYears: 3,
		AdditionalUseGrants: []license.BSLAdditionalUseGrant{
			{
				Name: "Academic Research Grant",
				MatchFunc: func(req license.BSLUsageRequest) (bool, string) {
					if req.Metadata != nil && req.Metadata["institution_type"] == "academic" {
						return true, "academic research exemption granted"
					}
					return false, "only certified academic institutions are entitled"
				},
			},
		},
	}

	// Academic request
	resAcademic := policy.EvaluateEntitlement(license.BSLUsageRequest{
		Metadata: map[string]string{"institution_type": "academic"},
		Time:     time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	})
	if !resAcademic.Authorized {
		t.Fatalf("expected academic request to be authorized: %s", resAcademic.Reason)
	}

	// Commercial request
	resCommercial := policy.EvaluateEntitlement(license.BSLUsageRequest{
		Metadata: map[string]string{"institution_type": "commercial"},
		Time:     time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	})
	if resCommercial.Authorized {
		t.Fatalf("expected commercial request to be rejected under academic grant")
	}
}

func TestValidator_BSLAdditionalUseGrant_Integration(t *testing.T) {
	t.Parallel()

	pub, _, err := license.GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}

	releaseDate := time.Date(2025, time.January, 1, 0, 0, 0, 0, time.UTC)
	bslPolicy := license.BSLPolicy{
		ReleaseDate:       releaseDate,
		ChangePeriodYears: 3,
		Product:           "gitlab-fleet-governor",
		AdditionalUseGrants: []license.BSLAdditionalUseGrant{
			license.NewNonProductionGrant("Non-Production Exemption"),
			license.NewFreeTierGrant("Community Free Tier", map[string]int64{"max_nodes": 10}, "sso"),
		},
	}

	// 1. Validator in staging environment without commercial license -> Authorized under Non-Production Grant
	stagingVal, err := license.NewValidator(pub,
		license.WithProduct("gitlab-fleet-governor"),
		license.WithBSLPolicy(bslPolicy),
		license.WithEnvironment("staging"),
		license.WithCurrentUsage(map[string]int64{"max_nodes": 50}),
	)
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}

	resStaging, err := stagingVal.VerifyWithResultAt("", releaseDate.AddDate(1, 0, 0))
	if err != nil {
		t.Fatalf("expected staging verification to succeed under BSL grant: %v", err)
	}
	if !resStaging.BSLGrantAuthorized {
		t.Fatalf("expected BSLGrantAuthorized to be true")
	}
	if resStaging.BSLGrantName != "Non-Production Exemption" {
		t.Errorf("expected BSLGrantName 'Non-Production Exemption', got %s", resStaging.BSLGrantName)
	}
	if resStaging.Status != license.StatusActive {
		t.Errorf("expected status StatusActive, got %s", resStaging.Status)
	}
	if statusMsg := resStaging.StatusMessage(); statusMsg != "Authorized under BSL 1.1 Additional Use Grant (Non-Production Exemption)" {
		t.Errorf("unexpected status message: %s", statusMsg)
	}

	// Format status banner check
	banner := resStaging.FormatStatus()
	if !strings.Contains(banner, "BSL ADDITIONAL USE GRANT") || !strings.Contains(banner, "Non-Production Exemption") {
		t.Errorf("expected status banner to contain BSL grant details, got:\n%s", banner)
	}

	// 2. Validator in production exceeding free tier -> Fails with CommercialLicenseRequiredError
	prodVal, err := license.NewValidator(pub,
		license.WithProduct("gitlab-fleet-governor"),
		license.WithBSLPolicy(bslPolicy),
		license.WithEnvironment("production"),
		license.WithCurrentUsage(map[string]int64{"max_nodes": 20}), // Exceeds limit 10
	)
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}

	_, err = prodVal.VerifyWithResultAt("", releaseDate.AddDate(1, 0, 0))
	if err == nil {
		t.Fatalf("expected verification to fail when exceeding free tier in production")
	}

	// Verify structured error and sentinel error unwrapping
	if !errors.Is(err, license.ErrCommercialLicenseRequired) {
		t.Errorf("expected error to match ErrCommercialLicenseRequired, got: %v", err)
	}
	if !errors.Is(err, license.ErrLicenseNotFound) {
		t.Errorf("expected error to match ErrLicenseNotFound for backward compatibility, got: %v", err)
	}

	var commErr *license.CommercialLicenseRequiredError
	if !errors.As(err, &commErr) {
		t.Fatalf("expected error to be *CommercialLicenseRequiredError, got: %T", err)
	}
	if commErr.Product != "gitlab-fleet-governor" {
		t.Errorf("expected error product 'gitlab-fleet-governor', got %s", commErr.Product)
	}

	// 3. Direct EvaluateBSLEntitlement check
	entResult, err := prodVal.EvaluateBSLEntitlement(license.BSLUsageRequest{
		Environment: "production",
		Usage:       map[string]int64{"max_nodes": 5}, // 5 nodes is within free tier!
		Time:        releaseDate.AddDate(1, 0, 0),
	})
	if err != nil {
		t.Fatalf("EvaluateBSLEntitlement failed: %v", err)
	}
	if !entResult.Authorized {
		t.Fatalf("expected 5 nodes in production to be authorized under free tier: %s", entResult.Reason)
	}
	if entResult.MatchingGrant != "Community Free Tier" {
		t.Errorf("expected grant 'Community Free Tier', got %s", entResult.MatchingGrant)
	}
}

func TestBSLAdditionalUseGrant_DryRunAndSimulation(t *testing.T) {
	t.Parallel()

	grant := license.NewNonProductionGrant("Non-Production Exemption")

	// 1. Production request without dry-run -> Rejected by ExcludedEnvironments
	evalProd := grant.Evaluate(license.BSLUsageRequest{
		Environment: "production",
	})
	if evalProd.Matched {
		t.Error("expected production request without dry-run to be rejected")
	}

	// 2. Production request with DryRun: true -> Authorized
	evalDryRun := grant.Evaluate(license.BSLUsageRequest{
		Environment: "production",
		DryRun:      true,
	})
	if !evalDryRun.Matched {
		t.Fatalf("expected DryRun: true in production to be authorized, got: %s", evalDryRun.Reason)
	}
	if !strings.Contains(evalDryRun.Reason, "dry-run/simulation mode") {
		t.Errorf("expected reason to mention dry-run/simulation mode, got: %s", evalDryRun.Reason)
	}

	// 3. Production request with Simulation: true -> Authorized
	evalSim := grant.Evaluate(license.BSLUsageRequest{
		Environment: "production",
		Simulation:  true,
	})
	if !evalSim.Matched {
		t.Fatalf("expected Simulation: true in production to be authorized, got: %s", evalSim.Reason)
	}

	// 4. Production request with metadata["dry_run"] = "true" -> Authorized
	evalMetaDryRun := grant.Evaluate(license.BSLUsageRequest{
		Environment: "production",
		Metadata:    map[string]string{"dry_run": "true"},
	})
	if !evalMetaDryRun.Matched {
		t.Fatalf("expected metadata dry_run: true in production to be authorized, got: %s", evalMetaDryRun.Reason)
	}

	// 5. Production request with metadata["simulation"] = "true" -> Authorized
	evalMetaSim := grant.Evaluate(license.BSLUsageRequest{
		Environment: "production",
		Metadata:    map[string]string{"simulation": "true"},
	})
	if !evalMetaSim.Matched {
		t.Fatalf("expected metadata simulation: true in production to be authorized, got: %s", evalMetaSim.Reason)
	}
}

func TestBSLAdditionalUseGrant_MatchFuncPriorityAndOverride(t *testing.T) {
	t.Parallel()

	// Consumer configures MatchFunc on NewNonProductionGrant to authorize dry-run simulation against production
	nonProdGrant := license.NewNonProductionGrant("Non-Production & Simulation Exemption")
	nonProdGrant.MatchFunc = func(req license.BSLUsageRequest) (bool, string) {
		if req.Metadata != nil && req.Metadata["dry_run"] == "true" {
			return true, "Execution is in non-destructive dry-run simulation mode"
		}
		return false, ""
	}

	policy := license.BSLPolicy{
		ReleaseDate:       time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		ChangePeriodYears: 3,
		AdditionalUseGrants: []license.BSLAdditionalUseGrant{
			nonProdGrant,
		},
	}

	// 1. Production with dry_run metadata -> MatchFunc authorizes, overriding ExcludedEnvironments
	resDryRunProd := policy.EvaluateEntitlement(license.BSLUsageRequest{
		Environment: "production",
		Metadata:    map[string]string{"dry_run": "true"},
		Time:        time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	})
	if !resDryRunProd.Authorized {
		t.Fatalf("expected dry-run simulation against production to be authorized via MatchFunc, got: %s", resDryRunProd.Reason)
	}
	if !strings.Contains(resDryRunProd.Reason, "Execution is in non-destructive dry-run simulation mode") {
		t.Errorf("expected reason to reflect MatchFunc output, got: %s", resDryRunProd.Reason)
	}

	// 2. Production WITHOUT dry_run metadata -> Rejected by ExcludedEnvironments
	resProd := policy.EvaluateEntitlement(license.BSLUsageRequest{
		Environment: "production",
		Time:        time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	})
	if resProd.Authorized {
		t.Fatalf("expected standard production usage to be rejected without dry-run metadata")
	}

	// 3. Staging WITHOUT dry_run metadata -> Authorized under standard AllowedEnvironments
	resStaging := policy.EvaluateEntitlement(license.BSLUsageRequest{
		Environment: "staging",
		Time:        time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	})
	if !resStaging.Authorized {
		t.Fatalf("expected staging to be authorized under AllowedEnvironments: %s", resStaging.Reason)
	}

	// 4. Custom MatchFunc with explicit rejection reason
	rejectingGrant := license.NewNonProductionGrant("Strict Security Grant")
	rejectingGrant.MatchFunc = func(req license.BSLUsageRequest) (bool, string) {
		if req.Metadata != nil && req.Metadata["compromised"] == "true" {
			return false, "host machine failed security compliance check"
		}
		return false, ""
	}

	evalCompromised := rejectingGrant.Evaluate(license.BSLUsageRequest{
		Environment: "staging",
		Metadata:    map[string]string{"compromised": "true"},
	})
	if evalCompromised.Matched {
		t.Error("expected compromised host to be rejected")
	}
	if !strings.Contains(evalCompromised.Reason, "host machine failed security compliance check") {
		t.Errorf("expected explicit rejection reason, got: %s", evalCompromised.Reason)
	}
}

func TestBSLPolicy_AddGrantAndStatusMessage(t *testing.T) {
	policy := license.BSLPolicy{
		ReleaseDate:       time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		ChangePeriodYears: 3,
	}

	grant1 := license.NewNonProductionGrant("Non-Prod")
	grant2 := license.NewFreeTierGrant("Free Tier", map[string]int64{"nodes": 5})

	// Test AddGrant
	policy.AddGrant(grant1)
	if len(policy.AdditionalUseGrants) != 1 {
		t.Errorf("expected 1 grant, got %d", len(policy.AdditionalUseGrants))
	}

	// Test WithGrants
	updatedPolicy := policy.WithGrants(grant2)
	if len(updatedPolicy.AdditionalUseGrants) != 2 {
		t.Errorf("expected 2 grants, got %d", len(updatedPolicy.AdditionalUseGrants))
	}

	// Test StatusMessage
	res := updatedPolicy.EvaluateEntitlement(license.BSLUsageRequest{
		Environment: "staging",
		Time:        time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	})
	msg := res.StatusMessage()
	if !strings.Contains(msg, "Authorized under BSL 1.1 Additional Use Grant") {
		t.Errorf("unexpected StatusMessage: %s", msg)
	}

	resUnauthorized := updatedPolicy.EvaluateEntitlement(license.BSLUsageRequest{
		Environment: "production",
		Usage:       map[string]int64{"nodes": 100},
		Time:        time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	})
	msgUnauth := resUnauthorized.StatusMessage()
	if !strings.Contains(msgUnauth, "Commercial license required") {
		t.Errorf("unexpected unauthorized StatusMessage: %s", msgUnauth)
	}

	// Exhaustive StatusMessage branch coverage
	var nilRes *license.BSLEntitlementResult
	if got := nilRes.StatusMessage(); got != "No entitlement evaluation result" {
		t.Errorf("expected 'No entitlement evaluation result', got %q", got)
	}

	resConvertedNoDate := &license.BSLEntitlementResult{
		GrantType:        license.BSLGrantTypeConverted,
		EffectiveLicense: "Apache-2.0",
	}
	if got := resConvertedNoDate.StatusMessage(); !strings.Contains(got, "converted to Apache-2.0") {
		t.Errorf("expected converted message, got %q", got)
	}

	resAuthNoGrant := &license.BSLEntitlementResult{
		Authorized: true,
	}
	if got := resAuthNoGrant.StatusMessage(); got != "Authorized under BSL 1.1 Additional Use Grant" {
		t.Errorf("expected generic auth message, got %q", got)
	}

	resCommercialZeroDays := &license.BSLEntitlementResult{
		Authorized:          false,
		DaysUntilConversion: 0,
	}
	if got := resCommercialZeroDays.StatusMessage(); got != "Commercial license required (BSL 1.1)" {
		t.Errorf("expected commercial license required, got %q", got)
	}
}
