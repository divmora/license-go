package license

import (
	"errors"
	"testing"
	"time"
)

func TestParseServerTimeHeader(t *testing.T) {
	tests := []struct {
		name      string
		header    string
		expectErr bool
		expected  time.Time
	}{
		{
			name:     "RFC1123 HTTP Date",
			header:   "Wed, 16 Sep 2026 12:30:00 GMT",
			expected: time.Date(2026, time.September, 16, 12, 30, 0, 0, time.UTC),
		},
		{
			name:     "RFC1123Z HTTP Date",
			header:   "Wed, 16 Sep 2026 12:30:00 +0000",
			expected: time.Date(2026, time.September, 16, 12, 30, 0, 0, time.UTC),
		},
		{
			name:     "RFC3339 timestamp",
			header:   "2026-09-16T12:30:00Z",
			expected: time.Date(2026, time.September, 16, 12, 30, 0, 0, time.UTC),
		},
		{
			name:     "RFC850 HTTP Date",
			header:   "Wednesday, 16-Sep-26 12:30:00 GMT",
			expected: time.Date(2026, time.September, 16, 12, 30, 0, 0, time.UTC),
		},
		{
			name:     "ANSIC Date",
			header:   "Wed Sep 16 12:30:00 2026",
			expected: time.Date(2026, time.September, 16, 12, 30, 0, 0, time.UTC),
		},
		{
			name:     "SQL Date",
			header:   "2026-09-16 12:30:00",
			expected: time.Date(2026, time.September, 16, 12, 30, 0, 0, time.UTC),
		},
		{
			name:     "Date only",
			header:   "2026-09-16",
			expected: time.Date(2026, time.September, 16, 0, 0, 0, 0, time.UTC),
		},
		{
			name:      "empty string",
			header:    "",
			expectErr: true,
		},
		{
			name:      "whitespace only",
			header:    "   ",
			expectErr: true,
		},
		{
			name:      "invalid date string",
			header:    "not-a-valid-date",
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed, err := ParseServerTimeHeader(tt.header)
			if tt.expectErr {
				if err == nil {
					t.Errorf("expected error parsing %q, got nil", tt.header)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error parsing %q: %v", tt.header, err)
			}
			if !parsed.Equal(tt.expected) {
				t.Errorf("ParseServerTimeHeader(%q) = %v, want %v", tt.header, parsed, tt.expected)
			}
		})
	}
}

func TestValidator_ServerTimeAttestation_WithinSkew(t *testing.T) {
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	signer, err := NewSigner(priv)
	if err != nil {
		t.Fatalf("NewSigner failed: %v", err)
	}

	serverTime := time.Date(2026, time.September, 16, 12, 0, 0, 0, time.UTC)
	claims := Claims{
		Customer:  Customer{Name: "Acme Corp"},
		Product:   "gitlab-fleet-governor",
		IssuedAt:  serverTime.AddDate(0, -1, 0),
		ExpiresAt: serverTime.AddDate(0, 1, 0), // Valid for 1 more month
	}
	token, err := signer.Sign(claims)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	// Local clock is 1 minute ahead of server time (well within 5 minutes allowed skew)
	localTime := serverTime.Add(1 * time.Minute)

	v, err := NewValidator(pub,
		WithProduct("gitlab-fleet-governor"),
		WithServerTimeAttestation(serverTime, 5*time.Minute),
	)
	if err != nil {
		t.Fatalf("NewValidator failed: %v", err)
	}

	res, err := v.VerifyWithResultAt(token, localTime)
	if err != nil {
		t.Fatalf("VerifyWithResultAt failed: %v", err)
	}

	if !res.ServerTimeAttested {
		t.Error("expected ServerTimeAttested to be true")
	}
	if res.ClockTampered {
		t.Error("expected ClockTampered to be false when within skew threshold")
	}
	if !res.ServerTime.Equal(serverTime) {
		t.Errorf("expected ServerTime %v, got %v", serverTime, res.ServerTime)
	}
	if res.ClockSkew != 1*time.Minute {
		t.Errorf("expected ClockSkew 1m, got %v", res.ClockSkew)
	}
	if res.Status != StatusActive {
		t.Errorf("expected StatusActive, got %s", res.Status)
	}
}

func TestValidator_ServerTimeAttestation_BackwardTamperingDefeated(t *testing.T) {
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	signer, err := NewSigner(priv)
	if err != nil {
		t.Fatalf("NewSigner failed: %v", err)
	}

	// Real server time is September 2026
	serverTime := time.Date(2026, time.September, 16, 12, 0, 0, 0, time.UTC)

	// License expired in June 2026
	expiredClaims := Claims{
		Customer:  Customer{Name: "Acme Corp"},
		Product:   "gitlab-fleet-governor",
		IssuedAt:  time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC),
		ExpiresAt: time.Date(2026, time.June, 1, 0, 0, 0, 0, time.UTC), // Expired!
	}
	token, err := signer.Sign(expiredClaims)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	// Attacker manipulates local host clock back to May 2026 (before expiration)
	tamperedLocalTime := time.Date(2026, time.May, 1, 0, 0, 0, 0, time.UTC)

	// 1. Without server time attestation, local check incorrectly believes license is valid:
	vUnprotected, _ := NewValidator(pub, WithProduct("gitlab-fleet-governor"))
	if _, err := vUnprotected.VerifyAt(token, tamperedLocalTime); err != nil {
		t.Errorf("unprotected validator with manipulated clock was expected to be fooled, but returned: %v", err)
	}

	// 2. WITH server time attestation, validator anchors to server time and detects license is EXPIRED:
	vProtected, err := NewValidator(pub,
		WithProduct("gitlab-fleet-governor"),
		WithServerTimeAttestation(serverTime, 10*time.Minute),
	)
	if err != nil {
		t.Fatalf("NewValidator failed: %v", err)
	}

	_, err = vProtected.VerifyAt(token, tamperedLocalTime)
	if !errors.Is(err, ErrExpired) {
		t.Fatalf("expected ErrExpired when backward clock tampering is defeated, got: %v", err)
	}

	// 3. For a token valid under server time, VerifyWithResultAt succeeds and flags ClockTampered:
	validClaims := Claims{
		Customer:  Customer{Name: "Acme Corp"},
		Product:   "gitlab-fleet-governor",
		IssuedAt:  serverTime.AddDate(0, -1, 0),
		ExpiresAt: serverTime.AddDate(0, 6, 0), // Valid in September 2026
	}
	validToken, err := signer.Sign(validClaims)
	if err != nil {
		t.Fatalf("Sign validToken failed: %v", err)
	}

	res, err := vProtected.VerifyWithResultAt(validToken, tamperedLocalTime)
	if err != nil {
		t.Fatalf("expected verification with valid token to succeed at server time, got: %v", err)
	}
	if !res.ClockTampered {
		t.Fatal("expected ClockTampered to be true when local clock drifted by months")
	}
	if !res.ServerTimeAttested {
		t.Fatal("expected ServerTimeAttested to be true")
	}
	if res.ClockSkew < 24*time.Hour {
		t.Errorf("expected ClockSkew > 24h, got %v", res.ClockSkew)
	}
}

func TestValidator_ServerTimeAttestation_StrictClockDefense(t *testing.T) {
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	signer, err := NewSigner(priv)
	if err != nil {
		t.Fatalf("NewSigner failed: %v", err)
	}

	serverTime := time.Date(2026, time.September, 16, 12, 0, 0, 0, time.UTC)
	claims := Claims{
		Customer:  Customer{Name: "Acme Corp"},
		Product:   "gitlab-fleet-governor",
		IssuedAt:  serverTime.AddDate(0, -1, 0),
		ExpiresAt: serverTime.AddDate(0, 1, 0),
	}
	token, err := signer.Sign(claims)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	// Local clock is 1 hour behind server time, but max allowed skew is 5 minutes
	tamperedTime := serverTime.Add(-1 * time.Hour)

	vStrict, err := NewValidator(pub,
		WithProduct("gitlab-fleet-governor"),
		WithServerTimeAttestation(serverTime, 5*time.Minute),
		WithStrictClockDefense(true),
	)
	if err != nil {
		t.Fatalf("NewValidator failed: %v", err)
	}

	// Strict mode MUST return ErrClockTamperingDetected immediately
	_, err = vStrict.VerifyAt(token, tamperedTime)
	if err == nil || !errors.Is(err, ErrClockTamperingDetected) {
		t.Fatalf("expected ErrClockTamperingDetected in strict mode, got: %v", err)
	}

	var clockErr *ClockTamperingError
	if !errors.As(err, &clockErr) {
		t.Fatalf("expected error to be *ClockTamperingError, got %T", err)
	}
	if clockErr.Skew != 1*time.Hour {
		t.Errorf("expected Skew 1h, got %v", clockErr.Skew)
	}
	if clockErr.MaxAllowedSkew != 5*time.Minute {
		t.Errorf("expected MaxAllowedSkew 5m, got %v", clockErr.MaxAllowedSkew)
	}
}

func TestValidator_WithServerTimeHeader(t *testing.T) {
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	signer, err := NewSigner(priv)
	if err != nil {
		t.Fatalf("NewSigner failed: %v", err)
	}

	httpDate := "Wed, 16 Sep 2026 14:00:00 GMT"
	serverTime, _ := ParseServerTimeHeader(httpDate)

	claims := Claims{
		Customer:  Customer{Name: "Acme Corp"},
		Product:   "gitlab-fleet-governor",
		IssuedAt:  serverTime.AddDate(0, -1, 0),
		ExpiresAt: serverTime.AddDate(0, 1, 0),
	}
	token, err := signer.Sign(claims)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	// 1. Valid HTTP Date header string
	v, err := NewValidator(pub,
		WithProduct("gitlab-fleet-governor"),
		WithServerTimeHeader(httpDate, 15*time.Minute),
	)
	if err != nil {
		t.Fatalf("NewValidator failed: %v", err)
	}

	res, err := v.VerifyWithResultAt(token, serverTime)
	if err != nil {
		t.Fatalf("VerifyWithResultAt failed: %v", err)
	}
	if !res.ServerTimeAttested {
		t.Error("expected ServerTimeAttested to be true")
	}

	// 2. Invalid HTTP Date header causes NewValidator to fail
	_, err = NewValidator(pub,
		WithProduct("gitlab-fleet-governor"),
		WithServerTimeHeader("invalid-date-string", 15*time.Minute),
	)
	if err == nil || !errors.Is(err, ErrClockTamperingDetected) {
		t.Fatalf("expected ErrClockTamperingDetected for invalid date header, got %v", err)
	}
}

func TestValidator_OfflineBackwardClockTampering_BuildDate(t *testing.T) {
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	signer, err := NewSigner(priv)
	if err != nil {
		t.Fatalf("NewSigner failed: %v", err)
	}

	buildDate := time.Date(2026, time.June, 1, 12, 0, 0, 0, time.UTC)
	issuedAt := time.Date(2026, time.June, 1, 0, 0, 0, 0, time.UTC)
	expiresAt := time.Date(2026, time.December, 31, 23, 59, 59, 0, time.UTC)

	token, err := signer.Sign(Claims{
		Customer:  Customer{Name: "Acme Airgap"},
		Product:   "gitlab-fleet-governor",
		IssuedAt:  issuedAt,
		ExpiresAt: expiresAt,
	})
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	v, err := NewValidator(pub,
		WithProduct("gitlab-fleet-governor"),
		WithBuildDate(buildDate),
		WithClockSkew(5*time.Minute),
	)
	if err != nil {
		t.Fatalf("NewValidator failed: %v", err)
	}

	// 1. Local clock is set prior to binary build date (e.g. 2025-01-01) -> MUST FAIL with ErrClockTamperingDetected
	tamperedTime := time.Date(2025, time.January, 1, 0, 0, 0, 0, time.UTC)
	_, err = v.VerifyAt(token, tamperedTime)
	if !errors.Is(err, ErrClockTamperingDetected) {
		t.Fatalf("expected ErrClockTamperingDetected when evaluating prior to build date, got: %v", err)
	}

	var clockErr *ClockTamperingError
	if !errors.As(err, &clockErr) {
		t.Fatalf("expected error to be *ClockTamperingError, got: %T", err)
	}
	if !clockErr.ServerTime.Equal(buildDate) {
		t.Errorf("expected ServerTime anchor to be build date %v, got %v", buildDate, clockErr.ServerTime)
	}
	if clockErr.Skew <= 0 {
		t.Errorf("expected positive skew drift, got %v", clockErr.Skew)
	}
	if clockErr.MaxAllowedSkew != 5*time.Minute {
		t.Errorf("expected MaxAllowedSkew 5m, got %v", clockErr.MaxAllowedSkew)
	}

	// 2. VerifyWithResultAt also rejects with ErrClockTamperingDetected
	_, err = v.VerifyWithResultAt(token, tamperedTime)
	if !errors.Is(err, ErrClockTamperingDetected) {
		t.Fatalf("expected VerifyWithResultAt to reject with ErrClockTamperingDetected, got: %v", err)
	}

	// 3. Legitimate evaluation time after build date -> SUCCESS
	legitTime := time.Date(2026, time.July, 15, 12, 0, 0, 0, time.UTC)
	res, err := v.VerifyWithResultAt(token, legitTime)
	if err != nil {
		t.Fatalf("expected legitimate verification after build date to succeed, got: %v", err)
	}
	if res.Status != StatusActive {
		t.Errorf("expected StatusActive, got %v", res.Status)
	}
}

func TestValidator_OfflineBackwardClockTampering_ClockSkewTolerance(t *testing.T) {
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	signer, err := NewSigner(priv)
	if err != nil {
		t.Fatalf("NewSigner failed: %v", err)
	}

	buildDate := time.Date(2026, time.June, 1, 12, 0, 0, 0, time.UTC)
	token, err := signer.Sign(Claims{
		Customer:  Customer{Name: "Acme Corp"},
		Product:   "gitlab-fleet-governor",
		ExpiresAt: time.Date(2027, time.January, 1, 0, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	v, err := NewValidator(pub,
		WithProduct("gitlab-fleet-governor"),
		WithBuildDate(buildDate),
		WithClockSkew(10*time.Minute),
	)
	if err != nil {
		t.Fatalf("NewValidator failed: %v", err)
	}

	// Evaluation time is 8 minutes prior to build date (within 10m skew) -> ALLOWED
	withinSkewTime := buildDate.Add(-8 * time.Minute)
	if _, err := v.VerifyAt(token, withinSkewTime); err != nil {
		t.Fatalf("expected evaluation within clock skew tolerance to succeed, got: %v", err)
	}

	// Evaluation time is 12 minutes prior to build date (exceeds 10m skew) -> REJECTED
	beyondSkewTime := buildDate.Add(-12 * time.Minute)
	_, err = v.VerifyAt(token, beyondSkewTime)
	if !errors.Is(err, ErrClockTamperingDetected) {
		t.Fatalf("expected ErrClockTamperingDetected when exceeding clock skew before build date, got: %v", err)
	}
}

func TestValidator_OfflineBackwardClockTampering_ReleaseAttestation(t *testing.T) {
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	signer, err := NewSigner(priv)
	if err != nil {
		t.Fatalf("NewSigner failed: %v", err)
	}

	attestationBuildDate := time.Date(2026, time.June, 1, 12, 0, 0, 0, time.UTC)
	attestationToken, err := SignRelease(ReleaseClaims{
		Product:   "gitlab-fleet-governor",
		Version:   "1.5.0",
		BuildDate: attestationBuildDate,
		Authority: "divmora.com/release",
	}, priv)
	if err != nil {
		t.Fatalf("SignRelease failed: %v", err)
	}

	token, err := signer.Sign(Claims{
		Customer:  Customer{Name: "Airgap Military"},
		Product:   "gitlab-fleet-governor",
		ExpiresAt: time.Date(2027, time.January, 1, 0, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	// Validator has NO explicit WithBuildDate, but has WithReleaseAttestation
	v, err := NewValidator(pub,
		WithProduct("gitlab-fleet-governor"),
		WithCurrentVersion("1.5.0"),
		WithReleaseAttestation(attestationToken),
	)
	if err != nil {
		t.Fatalf("NewValidator failed: %v", err)
	}

	// 1. Clock tampered prior to attested build date -> REJECT
	tamperedTime := time.Date(2025, time.December, 1, 0, 0, 0, 0, time.UTC)
	_, err = v.VerifyAt(token, tamperedTime)
	if !errors.Is(err, ErrClockTamperingDetected) {
		t.Fatalf("expected ErrClockTamperingDetected anchored to attested build date, got: %v", err)
	}

	// 2. Legitimate clock after attested build date -> PASS
	legitTime := time.Date(2026, time.July, 1, 0, 0, 0, 0, time.UTC)
	res, err := v.VerifyWithResultAt(token, legitTime)
	if err != nil {
		t.Fatalf("expected successful verification after attested build date, got: %v", err)
	}
	if res.Provenance == nil || !res.Provenance.Attested {
		t.Errorf("expected Provenance.Attested == true")
	}
}

func TestValidator_BSLEntitlement_OfflineBackwardClockTampering(t *testing.T) {
	pub, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	buildDate := time.Date(2026, time.June, 1, 12, 0, 0, 0, time.UTC)
	policy := BSLPolicy{
		Product:           "gitlab-fleet-governor",
		ReleaseDate:       buildDate,
		ChangePeriodYears: 3,
		AdditionalUseGrants: []BSLAdditionalUseGrant{
			{
				Name:                "Non-Production Testing",
				AllowedEnvironments: []string{"test"},
			},
		},
	}

	v, err := NewValidator(pub,
		WithProduct("gitlab-fleet-governor"),
		WithBSLPolicy(policy),
		WithBuildDate(buildDate),
	)
	if err != nil {
		t.Fatalf("NewValidator failed: %v", err)
	}

	// Request with evaluation time prior to binary build date -> REJECT with ErrClockTamperingDetected
	_, err = v.EvaluateBSLEntitlement(BSLUsageRequest{
		Environment: "test",
		Time:        time.Date(2025, time.January, 1, 0, 0, 0, 0, time.UTC),
	})
	if !errors.Is(err, ErrClockTamperingDetected) {
		t.Fatalf("expected ErrClockTamperingDetected for BSL request prior to build date, got: %v", err)
	}

	// Request after build date -> SUCCESS
	ent, err := v.EvaluateBSLEntitlement(BSLUsageRequest{
		Environment: "test",
		Time:        time.Date(2026, time.June, 15, 0, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("expected successful BSL evaluation after build date, got: %v", err)
	}
	if !ent.Authorized {
		t.Errorf("expected entitlement to be authorized under test grant")
	}
}

func TestValidator_OnlineFallback_WhenLocalClockPriorToBuildDate(t *testing.T) {
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	signer, err := NewSigner(priv)
	if err != nil {
		t.Fatalf("NewSigner failed: %v", err)
	}

	buildDate := time.Date(2026, time.June, 1, 12, 0, 0, 0, time.UTC)
	authoritativeServerTime := time.Date(2026, time.June, 15, 12, 0, 0, 0, time.UTC)
	tamperedHostClock := time.Date(2025, time.January, 1, 0, 0, 0, 0, time.UTC)

	token, err := signer.Sign(Claims{
		Customer:  Customer{Name: "Hybrid Cloud Corp"},
		Product:   "gitlab-fleet-governor",
		ExpiresAt: time.Date(2027, time.January, 1, 0, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	// 1. Non-strict mode: detects clock tampering, falls back to trusted server time, succeeds
	vPermissive, err := NewValidator(pub,
		WithProduct("gitlab-fleet-governor"),
		WithBuildDate(buildDate),
		WithAuthoritativeTime(authoritativeServerTime),
		WithStrictClockDefense(false),
	)
	if err != nil {
		t.Fatalf("NewValidator failed: %v", err)
	}

	res, err := vPermissive.VerifyWithResultAt(token, tamperedHostClock)
	if err != nil {
		t.Fatalf("expected non-strict validator to succeed by falling back to server time, got: %v", err)
	}
	if !res.ClockTampered {
		t.Errorf("expected res.ClockTampered to be true")
	}
	if !res.EvaluationTime.Equal(authoritativeServerTime) {
		t.Errorf("expected EvaluationTime to be server time %v, got %v", authoritativeServerTime, res.EvaluationTime)
	}

	// 2. Strict mode: rejects immediately with ErrClockTamperingDetected
	vStrict, err := NewValidator(pub,
		WithProduct("gitlab-fleet-governor"),
		WithBuildDate(buildDate),
		WithAuthoritativeTime(authoritativeServerTime),
		WithStrictClockDefense(true),
	)
	if err != nil {
		t.Fatalf("NewValidator failed: %v", err)
	}

	_, err = vStrict.VerifyWithResultAt(token, tamperedHostClock)
	if !errors.Is(err, ErrClockTamperingDetected) {
		t.Fatalf("expected strict validator to reject with ErrClockTamperingDetected, got: %v", err)
	}
}

func TestValidator_WithRequireAuthoritativeTime(t *testing.T) {
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	signer, _ := NewSigner(priv)
	now := time.Now().UTC()

	claims := sampleClaims()
	claims.Product = "gitlab-fleet-governor"
	claims.IssuedAt = now.Add(-1 * time.Hour)
	claims.ExpiresAt = now.Add(24 * time.Hour)
	token, err := signer.SignArmored(claims)
	if err != nil {
		t.Fatalf("SignArmored failed: %v", err)
	}

	// 1. Validator configured with WithRequireAuthoritativeTime(true) but NO authoritative time source
	vMissingAuth, err := NewValidator(pub,
		WithProduct("gitlab-fleet-governor"),
		WithRequireAuthoritativeTime(true),
	)
	if err != nil {
		t.Fatalf("NewValidator failed: %v", err)
	}
	if !vMissingAuth.RequireAuthoritativeTime() {
		t.Error("expected RequireAuthoritativeTime() == true")
	}

	_, err = vMissingAuth.Verify(token)
	if !errors.Is(err, ErrMissingAuthoritativeTime) {
		t.Fatalf("expected ErrMissingAuthoritativeTime when authoritative time required but not configured, got: %v", err)
	}

	// 2. Validator configured with WithRequireAuthoritativeTime(true) AND authoritative time source
	vWithAuth, err := NewValidator(pub,
		WithProduct("gitlab-fleet-governor"),
		WithRequireAuthoritativeTime(true),
		WithAuthoritativeTime(now),
	)
	if err != nil {
		t.Fatalf("NewValidator failed: %v", err)
	}

	res, err := vWithAuth.VerifyWithResult(token)
	if err != nil {
		t.Fatalf("expected verification to succeed with authoritative time, got: %v", err)
	}
	if res.Status != StatusActive {
		t.Errorf("expected StatusActive, got %s", res.Status)
	}
}
