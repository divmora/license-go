package license

import (
	"strings"
	"testing"
	"time"
)

func TestClaims_StatusMessage(t *testing.T) {
	refTime := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)

	t.Run("nil claims", func(t *testing.T) {
		var c *Claims
		msg := c.StatusMessageAt(refTime)
		if msg != "No license claims" {
			t.Errorf("expected 'No license claims', got %q", msg)
		}
	})

	t.Run("perpetual license", func(t *testing.T) {
		c := &Claims{
			Product: "gitlab-fleet-governor",
		}
		msg := c.StatusMessageAt(refTime)
		if msg != "Perpetual license (does not expire)" {
			t.Errorf("expected 'Perpetual license (does not expire)', got %q", msg)
		}
		// Also test StatusMessage() at current time
		if c.StatusMessage() != "Perpetual license (does not expire)" {
			t.Errorf("expected StatusMessage() to be perpetual, got %q", c.StatusMessage())
		}
	})

	t.Run("not yet valid", func(t *testing.T) {
		futureStart := refTime.Add(48 * time.Hour)
		c := &Claims{
			Product:   "gitlab-fleet-governor",
			NotBefore: futureStart,
			ExpiresAt: refTime.Add(365 * 24 * time.Hour),
		}
		msg := c.StatusMessageAt(refTime)
		expectedPrefix := "License is not yet valid (valid starting " + futureStart.Format(time.RFC3339) + ")"
		if msg != expectedPrefix {
			t.Errorf("expected %q, got %q", expectedPrefix, msg)
		}
	})

	t.Run("active multiple days remaining", func(t *testing.T) {
		expires := refTime.Add(10 * 24 * time.Hour)
		c := &Claims{
			Product:   "gitlab-fleet-governor",
			ExpiresAt: expires,
		}
		msg := c.StatusMessageAt(refTime)
		expected := "Active (10 days remaining, expires " + expires.Format(time.RFC3339) + ")"
		if msg != expected {
			t.Errorf("expected %q, got %q", expected, msg)
		}
	})

	t.Run("active exactly 1 day remaining", func(t *testing.T) {
		expires := refTime.Add(30 * time.Hour) // 1 day and 6 hours
		c := &Claims{
			Product:   "gitlab-fleet-governor",
			ExpiresAt: expires,
		}
		msg := c.StatusMessageAt(refTime)
		expected := "Active (1 day remaining, expires " + expires.Format(time.RFC3339) + ")"
		if msg != expected {
			t.Errorf("expected %q, got %q", expected, msg)
		}
	})

	t.Run("active less than 1 day remaining", func(t *testing.T) {
		expires := refTime.Add(12 * time.Hour)
		c := &Claims{
			Product:   "gitlab-fleet-governor",
			ExpiresAt: expires,
		}
		msg := c.StatusMessageAt(refTime)
		expected := "Active (less than 1 day remaining, expires " + expires.Format(time.RFC3339) + ")"
		if msg != expected {
			t.Errorf("expected %q, got %q", expected, msg)
		}
	})

	t.Run("in grace period multiple days remaining", func(t *testing.T) {
		expiredAt := refTime.Add(-2 * 24 * time.Hour)
		c := &Claims{
			Product:         "gitlab-fleet-governor",
			ExpiresAt:       expiredAt,
			GracePeriodDays: 14,
		}
		// 14 - 2 = 12 days remaining
		msg := c.StatusMessageAt(refTime)
		cutoff := c.EffectiveExpiration().Format(time.RFC3339)
		expStr := expiredAt.Format(time.RFC3339)
		expected := "Operating in grace period (12 grace days remaining until " + cutoff + ", expired on " + expStr + ")"
		if msg != expected {
			t.Errorf("expected %q, got %q", expected, msg)
		}
	})

	t.Run("in grace period 1 day remaining", func(t *testing.T) {
		expiredAt := refTime.Add(-13 * 24 * time.Hour)
		c := &Claims{
			Product:         "gitlab-fleet-governor",
			ExpiresAt:       expiredAt,
			GracePeriodDays: 14,
		}
		// 14 - 13 = 1 day remaining
		msg := c.StatusMessageAt(refTime)
		cutoff := c.EffectiveExpiration().Format(time.RFC3339)
		expStr := expiredAt.Format(time.RFC3339)
		expected := "Operating in grace period (1 grace day remaining until " + cutoff + ", expired on " + expStr + ")"
		if msg != expected {
			t.Errorf("expected %q, got %q", expected, msg)
		}
	})

	t.Run("in grace period less than 1 day remaining", func(t *testing.T) {
		expiredAt := refTime.Add(-14*24*time.Hour + 6*time.Hour)
		c := &Claims{
			Product:         "gitlab-fleet-governor",
			ExpiresAt:       expiredAt,
			GracePeriodDays: 14,
		}
		// 6 hours left
		msg := c.StatusMessageAt(refTime)
		cutoff := c.EffectiveExpiration().Format(time.RFC3339)
		expStr := expiredAt.Format(time.RFC3339)
		expected := "Operating in grace period (less than 1 grace day remaining until " + cutoff + ", expired on " + expStr + ")"
		if msg != expected {
			t.Errorf("expected %q, got %q", expected, msg)
		}
	})

	t.Run("expired without grace period", func(t *testing.T) {
		expiredAt := refTime.Add(-24 * time.Hour)
		c := &Claims{
			Product:   "gitlab-fleet-governor",
			ExpiresAt: expiredAt,
		}
		msg := c.StatusMessageAt(refTime)
		expected := "License expired on " + expiredAt.Format(time.RFC3339)
		if msg != expected {
			t.Errorf("expected %q, got %q", expected, msg)
		}
	})

	t.Run("expired with past grace period", func(t *testing.T) {
		expiredAt := refTime.Add(-30 * 24 * time.Hour)
		c := &Claims{
			Product:         "gitlab-fleet-governor",
			ExpiresAt:       expiredAt,
			GracePeriodDays: 14,
		}
		msg := c.StatusMessageAt(refTime)
		cutoff := c.EffectiveExpiration().Format(time.RFC3339)
		expected := "License expired on " + expiredAt.Format(time.RFC3339) + " (grace period ended " + cutoff + ")"
		if msg != expected {
			t.Errorf("expected %q, got %q", expected, msg)
		}
	})
}

func TestVerificationResult_StatusMessage(t *testing.T) {
	refTime := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)

	t.Run("nil result", func(t *testing.T) {
		var r *VerificationResult
		if r.StatusMessage() != "No verification result" {
			t.Errorf("expected 'No verification result', got %q", r.StatusMessage())
		}
	})

	t.Run("BSL converted with change date", func(t *testing.T) {
		changeDate := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
		r := &VerificationResult{
			BSLConverted:     true,
			EffectiveLicense: "Apache-2.0",
			ChangeDate:       changeDate,
		}
		expected := "Open source license (BSL 1.1 converted to Apache-2.0 on 2026-01-01)"
		if r.StatusMessage() != expected {
			t.Errorf("expected %q, got %q", expected, r.StatusMessage())
		}
	})

	t.Run("BSL converted without change date", func(t *testing.T) {
		r := &VerificationResult{
			BSLConverted:     true,
			EffectiveLicense: "Apache-2.0",
		}
		expected := "Open source license (BSL 1.1 converted to Apache-2.0)"
		if r.StatusMessage() != expected {
			t.Errorf("expected %q, got %q", expected, r.StatusMessage())
		}
	})

	t.Run("BSL converted default license fallback", func(t *testing.T) {
		r := &VerificationResult{
			BSLConverted: true,
		}
		expected := "Open source license (BSL 1.1 converted to Apache-2.0)"
		if r.StatusMessage() != expected {
			t.Errorf("expected %q, got %q", expected, r.StatusMessage())
		}
	})

	t.Run("nil claims in result falls back to Status string", func(t *testing.T) {
		r := &VerificationResult{
			Status: StatusExpired,
		}
		if r.StatusMessage() != "EXPIRED" {
			t.Errorf("expected 'EXPIRED', got %q", r.StatusMessage())
		}
	})

	t.Run("active verified result with evaluation time", func(t *testing.T) {
		expires := refTime.Add(45 * 24 * time.Hour)
		claims := &Claims{
			Product:   "gitlab-fleet-governor",
			ExpiresAt: expires,
		}
		r := &VerificationResult{
			Claims:         claims,
			Status:         StatusActive,
			EvaluationTime: refTime,
		}
		expected := "Active (45 days remaining, expires " + expires.Format(time.RFC3339) + ")"
		if r.StatusMessage() != expected {
			t.Errorf("expected %q, got %q", expected, r.StatusMessage())
		}
	})

	t.Run("in grace period via result fields", func(t *testing.T) {
		expiredAt := refTime.Add(-5 * 24 * time.Hour)
		claims := &Claims{
			Product:         "gitlab-fleet-governor",
			ExpiresAt:       expiredAt,
			GracePeriodDays: 14,
		}
		r := &VerificationResult{
			Claims:             claims,
			Status:             StatusGracePeriod,
			InGracePeriod:      true,
			GraceDaysRemaining: 9,
			EffectiveExpiry:    claims.EffectiveExpiration(),
			EvaluationTime:     refTime,
		}
		cutoff := claims.EffectiveExpiration().Format(time.RFC3339)
		expected := "Operating in grace period (9 grace days remaining until " + cutoff + ", expired on " + expiredAt.Format(time.RFC3339) + ")"
		if r.StatusMessage() != expected {
			t.Errorf("expected %q, got %q", expected, r.StatusMessage())
		}
	})
}

func TestValidator_VerifyWithResult_StatusMessageRoundTrip(t *testing.T) {
	pubKey, privKey, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	signer, err := NewSigner(privKey)
	if err != nil {
		t.Fatalf("NewSigner failed: %v", err)
	}

	validator, err := NewValidator(pubKey, WithProduct("gitlab-fleet-governor"), WithAllowExpired(true))
	if err != nil {
		t.Fatalf("NewValidator failed: %v", err)
	}

	refTime := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)

	// 1. Active license
	activeClaims := Claims{
		Product:   "gitlab-fleet-governor",
		Plan:      "enterprise",
		Customer:  Customer{Name: "Acme"},
		ExpiresAt: refTime.Add(30 * 24 * time.Hour),
	}
	token, err := signer.Sign(activeClaims)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	res, err := validator.VerifyWithResultAt(token, refTime)
	if err != nil {
		t.Fatalf("VerifyWithResultAt failed: %v", err)
	}
	if !strings.HasPrefix(res.StatusMessage(), "Active (30 days remaining") {
		t.Errorf("expected Active status message, got %q", res.StatusMessage())
	}

	// 2. Grace period license
	graceClaims := Claims{
		Product:         "gitlab-fleet-governor",
		Plan:            "enterprise",
		Customer:        Customer{Name: "Acme"},
		ExpiresAt:       refTime.Add(-3 * 24 * time.Hour),
		GracePeriodDays: 14,
	}
	graceToken, err := signer.Sign(graceClaims)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	resGrace, err := validator.VerifyWithResultAt(graceToken, refTime)
	if err != nil {
		t.Fatalf("VerifyWithResultAt failed: %v", err)
	}
	if !strings.HasPrefix(resGrace.StatusMessage(), "Operating in grace period (11 grace days remaining") {
		t.Errorf("expected Grace period status message, got %q", resGrace.StatusMessage())
	}

	// 3. Perpetual license
	perpetualClaims := Claims{
		Product:  "gitlab-fleet-governor",
		Plan:     "enterprise",
		Customer: Customer{Name: "Acme"},
	}
	perpToken, err := signer.Sign(perpetualClaims)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	resPerp, err := validator.VerifyWithResultAt(perpToken, refTime)
	if err != nil {
		t.Fatalf("VerifyWithResultAt failed: %v", err)
	}
	if resPerp.StatusMessage() != "Perpetual license (does not expire)" {
		t.Errorf("expected Perpetual status message, got %q", resPerp.StatusMessage())
	}

	// 4. BSL converted
	bslEvalTime := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	bslValidator, err := NewValidator(pubKey,
		WithProduct("gitlab-fleet-governor"),
		WithBSLPolicy(BSLPolicy{
			ReleaseDate:       time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC),
			ChangePeriodYears: 3,
		}),
		WithServerTimeAttestation(bslEvalTime, 1*time.Hour),
	)
	if err != nil {
		t.Fatalf("NewValidator failed: %v", err)
	}

	resBSL, err := bslValidator.VerifyWithResultAt("", bslEvalTime)
	if err != nil {
		t.Fatalf("VerifyWithResultAt BSL failed: %v", err)
	}
	if !strings.Contains(resBSL.StatusMessage(), "BSL 1.1 converted to Apache-2.0 on 2026-01-01") {
		t.Errorf("expected BSL converted status message, got %q", resBSL.StatusMessage())
	}
}
