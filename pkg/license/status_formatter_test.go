package license

import (
	"strings"
	"testing"
	"time"
)

func TestVerificationResult_FormatStatus_ActiveWithQuotasAndUsage(t *testing.T) {
	evalTime := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	expiresAt := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC) // 30 days remaining

	claims := &Claims{
		Product:  "gitlab-fleet-governor",
		Plan:     "enterprise",
		Customer: Customer{Name: "Acme Corp", OrgID: "org_acme_123"},
		Features: []string{"ha", "audit-logs", "auto-scaling"},
		Limits: map[string]int64{
			"max_runners":     200,
			"max_nodes":       10,
			"max_concurrency": -1,
		},
		ExpiresAt: expiresAt,
		Scope: &Scope{
			Environments: []string{"production", "staging"},
			Namespaces:   []string{"gitlab.com/acme/*"},
			Hosts:        []string{"*.acme.corp"},
		},
	}

	result := &VerificationResult{
		Claims:              claims,
		Status:              StatusActive,
		VerifiedByKeyID:     "key-prod-2026",
		VerifiedByKeyStatus: KeyStatusActive,
		EvaluationTime:      evalTime,
	}

	// 1. Static table (no live usage)
	outputStatic := result.FormatStatus()
	if !strings.Contains(outputStatic, "DIVMORA SOFTWARE LICENSE STATUS") ||
		!strings.Contains(outputStatic, "Status:                  ACTIVE [✓ Valid & Cryptographically Verified]") ||
		!strings.Contains(outputStatic, "Subscription Tier:       ENTERPRISE") ||
		!strings.Contains(outputStatic, "Acme Corp (Org: org_acme_123)") ||
		!strings.Contains(outputStatic, "max_runners") ||
		!strings.Contains(outputStatic, "Unlimited (-1)") {
		t.Fatalf("unexpected static FormatStatus output:\n%s", outputStatic)
	}

	// 2. Table with live usage overlay
	usage := map[string]int64{
		"max_runners": 142,
		"max_nodes":   6,
	}

	outputUsage := result.FormatStatus(
		WithStatusUsage(usage),
		WithStatusTime(evalTime),
		WithStatusBannerTitle("FLEET GOVERNOR LICENSE STATUS"),
	)

	if !strings.Contains(outputUsage, "FLEET GOVERNOR LICENSE STATUS") ||
		!strings.Contains(outputUsage, "142") ||
		!strings.Contains(outputUsage, "71%") ||
		!strings.Contains(outputUsage, "58 available") ||
		!strings.Contains(outputUsage, "60%") ||
		!strings.Contains(outputUsage, "4 available") {
		t.Fatalf("unexpected usage FormatStatus output:\n%s", outputUsage)
	}
}

func TestVerificationResult_FormatStatus_OverQuotaAndEdgeCases(t *testing.T) {
	evalTime := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)

	claims := &Claims{
		Product:  "otel-aws-log-processor",
		Plan:     "pro",
		Customer: Customer{Name: "Beta Corp"},
		Limits: map[string]int64{
			"max_streams": 50,
			"zero_quota":  0,
		},
	}

	result := &VerificationResult{
		Claims:         claims,
		Status:         StatusActive,
		EvaluationTime: evalTime,
	}

	usage := map[string]int64{
		"max_streams": 65, // Exceeded by 15
		"zero_quota":  2,  // Exceeded by 2
	}

	output := result.FormatStatus(
		WithStatusUsage(usage),
		WithStatusTime(evalTime),
	)

	if !strings.Contains(output, "130% [EXCEEDED]") ||
		!strings.Contains(output, "OVER QUOTA (+15)") ||
		!strings.Contains(output, "OVER QUOTA (+2)") {
		t.Fatalf("expected over-quota warnings in output:\n%s", output)
	}
}

func TestVerificationResult_FormatStatus_BSL11AndGracePeriod(t *testing.T) {
	evalTime := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	changeDateFuture := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)

	// 1. Pending BSL Conversion Countdown
	claims := &Claims{
		Product:   "gitlab-fleet-governor",
		Customer:  Customer{Name: "Acme"},
		ExpiresAt: time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC),
	}
	resPending := &VerificationResult{
		Claims:           claims,
		Status:           StatusActive,
		BSLConverted:     false,
		EffectiveLicense: "BSL-1.1",
		ChangeDate:       changeDateFuture,
		EvaluationTime:   evalTime,
	}

	outPending := resPending.FormatStatus(WithStatusTime(evalTime))
	if !strings.Contains(outPending, "BSL 1.1 Transition:") ||
		!strings.Contains(outPending, "Converts to Apache-2.0 in") {
		t.Fatalf("expected BSL transition countdown, got:\n%s", outPending)
	}

	// 2. Converted BSL Open-Source Status
	resConverted := &VerificationResult{
		Claims: &Claims{
			Product:  "gitlab-fleet-governor",
			Plan:     "open-source",
			Customer: Customer{Name: "Open Source Community"},
		},
		Status:           StatusActive,
		BSLConverted:     true,
		EffectiveLicense: "Apache-2.0",
		ChangeDate:       time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		EvaluationTime:   evalTime,
	}

	outConverted := resConverted.FormatStatus(WithStatusTime(evalTime))
	if !strings.Contains(outConverted, "OPEN SOURCE [✓ Converted to Apache-2.0]") ||
		!strings.Contains(outConverted, "Subscription Tier:       OPEN-SOURCE COMMUNITY") ||
		!strings.Contains(outConverted, "Governing License:       Apache-2.0 (Change Date reached 2026-01-01)") {
		t.Fatalf("expected open source conversion badge, got:\n%s", outConverted)
	}

	// 3. Grace Period Display
	claimsGrace := &Claims{
		Product:         "gitlab-fleet-governor",
		Customer:        Customer{Name: "Acme Corp"},
		ExpiresAt:       time.Date(2026, 6, 10, 0, 0, 0, 0, time.UTC),
		GracePeriodDays: 14,
	}
	resGrace := &VerificationResult{
		Claims:             claimsGrace,
		Status:             StatusGracePeriod,
		InGracePeriod:      true,
		GraceDaysRemaining: 9,
		EffectiveExpiry:    time.Date(2026, 6, 24, 0, 0, 0, 0, time.UTC),
		EvaluationTime:     evalTime,
	}

	outGrace := resGrace.FormatStatus(WithStatusTime(evalTime))
	if !strings.Contains(outGrace, "GRACE PERIOD [⚠️ Operating under active grace buffer - 9 days remaining]") ||
		!strings.Contains(outGrace, "Operating under 14-day grace period") ||
		!strings.Contains(outGrace, "2026-06-24") {
		t.Fatalf("expected grace period details in output:\n%s", outGrace)
	}
}

func TestVerificationResult_FormatStatus_WithProvenanceAndOptions(t *testing.T) {
	evalTime := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)

	claims := &Claims{
		Product:  "gitlab-fleet-governor",
		Plan:     "enterprise",
		Customer: Customer{Name: "Acme"},
		Features: []string{"audit-logs", "ha"},
		Limits:   map[string]int64{"runners": 100},
		Scope:    &Scope{Environments: []string{"prod"}},
	}

	prov := &ReleaseProvenance{
		Attested:      true,
		DigestMatched: true,
		Claims: &ReleaseClaims{
			Product:      "gitlab-fleet-governor",
			Version:      "v2.5.0",
			GitCommit:    "897f05812345",
			BinaryDigest: "sha256:abc12345",
		},
	}

	res := &VerificationResult{
		Claims:         claims,
		Status:         StatusActive,
		Provenance:     prov,
		EvaluationTime: evalTime,
	}

	// Full output
	fullOutput := res.FormatStatus(WithStatusTime(evalTime))
	if !strings.Contains(fullOutput, "Release Provenance:      Certified Release v2.5.0 (Checksum: Verified)") ||
		!strings.Contains(fullOutput, "Attested Git Commit:     897f05812345") ||
		!strings.Contains(fullOutput, "ENTITLED FEATURES (2)") ||
		!strings.Contains(fullOutput, "OPERATIONAL SCOPE") {
		t.Fatalf("unexpected full output:\n%s", fullOutput)
	}

	// Compact output
	compactOutput := res.FormatStatus(WithStatusCompact(true), WithStatusTime(evalTime))
	if strings.Contains(compactOutput, "ENTITLED FEATURES") ||
		strings.Contains(compactOutput, "OPERATIONAL SCOPE") {
		t.Fatalf("compact output should omit verbose features/scope lists:\n%s", compactOutput)
	}

	// Custom UsageFunc callback
	lookupCalled := false
	usageFunc := func(key string) (int64, bool) {
		if key == "runners" {
			lookupCalled = true
			return 45, true
		}
		return 0, false
	}

	fnOutput := res.FormatStatus(WithStatusUsageFunc(usageFunc), WithStatusTime(evalTime))
	if !lookupCalled || !strings.Contains(fnOutput, "45") || !strings.Contains(fnOutput, "45%") {
		t.Fatalf("usageFunc was not called or output missing:\n%s", fnOutput)
	}
}

func TestClaims_FormatStatus_Inspection(t *testing.T) {
	evalTime := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	claims := &Claims{
		Product:  "otel-aws-log-processor",
		Plan:     "trial",
		Customer: Customer{Name: "Tester", Email: "tester@example.com"},
		Features: []string{"*"},
		Limits:   map[string]int64{"streams": 10},
	}

	out := claims.FormatStatus(WithStatusTime(evalTime))
	if !strings.Contains(out, "DIVMORA SOFTWARE LICENSE STATUS") ||
		!strings.Contains(out, "Status:                  ACTIVE [✓ Valid Claims]") ||
		!strings.Contains(out, "Subscription Tier:       TRIAL") ||
		!strings.Contains(out, "Tester <tester@example.com>") ||
		!strings.Contains(out, "• * (All features entitled)") {
		t.Fatalf("unexpected claims FormatStatus output:\n%s", out)
	}

	// Nil safety
	var nilRes *VerificationResult
	if !strings.Contains(nilRes.FormatStatus(), "No verification result available") {
		t.Fatalf("expected nil result message")
	}

	var nilClaims *Claims
	if !strings.Contains(nilClaims.FormatStatus(), "No license claims available") {
		t.Fatalf("expected nil claims message")
	}
}

func TestStatusFormatter_OptionsAndBanners(t *testing.T) {
	evalTime := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	claims := &Claims{
		Product:   "gitlab-fleet-governor",
		Plan:      "pro",
		Customer:  Customer{Name: "Acme Corp"},
		Features:  []string{"sso"},
		Limits:    map[string]int64{"runners": 10},
		ExpiresAt: evalTime.Add(24 * time.Hour),
		Scope: &Scope{
			Environments: []string{"production"},
		},
	}

	result := &VerificationResult{
		Claims:         claims,
		Status:         StatusActive,
		EvaluationTime: evalTime,
	}

	// 1. FormatStatusBanner alias on result and claims
	banner1 := result.FormatStatusBanner()
	if !strings.Contains(banner1, "DIVMORA SOFTWARE LICENSE STATUS") {
		t.Error("expected FormatStatusBanner to return status card")
	}
	banner2 := claims.FormatStatusBanner()
	if !strings.Contains(banner2, "DIVMORA SOFTWARE LICENSE STATUS") {
		t.Error("expected Claims.FormatStatusBanner to return status card")
	}

	// 2. Standalone FormatStatus and FormatClaimsStatus functions
	fnOut1 := FormatStatus(result)
	if !strings.Contains(fnOut1, "DIVMORA SOFTWARE LICENSE STATUS") {
		t.Error("expected FormatStatus function to format result")
	}
	fnOut2 := FormatClaimsStatus(claims)
	if !strings.Contains(fnOut2, "DIVMORA SOFTWARE LICENSE STATUS") {
		t.Error("expected FormatClaimsStatus function to format claims")
	}

	// 3. Options toggles: width, exclude quotas, exclude features, exclude scopes, exclude provenance
	customOut := FormatStatus(result,
		WithStatusWidth(100),
		WithStatusIncludeQuotas(false),
		WithStatusIncludeFeatures(false),
		WithStatusIncludeScopes(false),
		WithStatusIncludeProvenance(false),
	)
	if strings.Contains(customOut, "RESOURCE QUOTAS & CAPACITY") {
		t.Error("expected quotas to be excluded")
	}
	if strings.Contains(customOut, "ENTITLED FEATURES") {
		t.Error("expected features to be excluded")
	}
	if strings.Contains(customOut, "OPERATIONAL INFRASTRUCTURE SCOPE") {
		t.Error("expected scopes to be excluded")
	}

	// 4. Badges across different plans and statuses
	planTests := []struct {
		plan     string
		status   Status
		expected string
	}{
		{"community", StatusActive, "COMMUNITY"},
		{"starter", StatusActive, "STARTER"},
		{"pro", StatusGracePeriod, "GRACE PERIOD"},
		{"trial", StatusExpired, "EXPIRED"},
		{"standard", StatusNotYetValid, "PENDING"},
	}

	for _, pt := range planTests {
		c := &Claims{
			Product:  "test-product",
			Plan:     pt.plan,
			Customer: Customer{Name: "Tester"},
		}
		res := &VerificationResult{
			Claims:         c,
			Status:         pt.status,
			EvaluationTime: evalTime,
		}
		out := res.FormatStatus()
		if !strings.Contains(out, pt.expected) {
			t.Errorf("expected status output to contain %q for plan %s / status %v", pt.expected, pt.plan, pt.status)
		}
	}
}
