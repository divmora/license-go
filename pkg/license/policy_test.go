package license_test

import (
	"context"
	"errors"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/divmora/license-go/pkg/license"
)

func TestManager_PolicyStrict_InitialFailure(t *testing.T) {
	t.Parallel()

	pub, _, err := license.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	validator, err := license.NewValidator(pub, license.WithProduct("gitlab-fleet-governor"))
	if err != nil {
		t.Fatalf("NewValidator failed: %v", err)
	}

	// Non-existent file under PolicyStrict must fail closed immediately
	_, err = license.NewManager(license.ManagerConfig{
		Validator:   validator,
		LicenseFile: "/non/existent/path/to/license.key",
		Policy:      license.PolicyStrict,
	})
	if err == nil {
		t.Fatal("expected NewManager to fail with missing file in PolicyStrict mode")
	}

	// Invalid token string under PolicyStrict must fail closed immediately
	_, err = license.NewManager(license.ManagerConfig{
		Validator:     validator,
		LicenseString: "DIV1.invalid.payload",
		Policy:        license.PolicyStrict,
	})
	if err == nil {
		t.Fatal("expected NewManager to fail with invalid token in PolicyStrict mode")
	}
}

func TestManager_PolicyDegraded_InitialFailure(t *testing.T) {
	t.Parallel()

	pub, _, err := license.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	validator, err := license.NewValidator(pub, license.WithProduct("gitlab-fleet-governor"))
	if err != nil {
		t.Fatalf("NewValidator failed: %v", err)
	}

	var degradedCalled int32
	var capturedReason error

	customFallback := &license.Claims{
		Product:  "gitlab-fleet-governor",
		Plan:     "community-fallback",
		Customer: license.Customer{Name: "Fallback Corp"},
		Features: []string{"basic-runner"},
		Limits:   map[string]int64{"max_runners": 5},
	}

	// Missing license under PolicyDegraded must NOT fail NewManager; it degrades gracefully
	mgr, err := license.NewManager(license.ManagerConfig{
		Validator:        validator,
		LicenseFile:      "/non/existent/license.key",
		Policy:           license.PolicyDegraded,
		FallbackClaims:   customFallback,
		DegradedReadOnly: true,
		OnDegraded: func(reason error, claims *license.Claims) {
			atomic.AddInt32(&degradedCalled, 1)
			capturedReason = reason
		},
	})
	if err != nil {
		t.Fatalf("expected NewManager to succeed under PolicyDegraded, got: %v", err)
	}

	if !mgr.IsDegraded() {
		t.Fatal("expected manager.IsDegraded() == true")
	}
	if mgr.DegradedReason() == nil {
		t.Fatal("expected DegradedReason() to not be nil")
	}
	if atomic.LoadInt32(&degradedCalled) != 1 {
		t.Fatalf("expected OnDegraded callback to be called once, got %d", degradedCalled)
	}
	if capturedReason == nil {
		t.Fatal("expected capturedReason to be set")
	}

	// Claims should be fallback claims
	claims := mgr.Claims()
	if claims.Plan != "community-fallback" {
		t.Fatalf("expected plan community-fallback, got %s", claims.Plan)
	}
	if !mgr.HasFeature("basic-runner") {
		t.Fatal("expected HasFeature('basic-runner') to be true")
	}
	if mgr.HasFeature("enterprise-ha") {
		t.Fatal("expected enterprise-ha to NOT be entitled in degraded mode")
	}

	// Limits should be evaluated against fallback limits
	if err := mgr.CheckLimit("max_runners", 3); err != nil {
		t.Fatalf("expected limit 3 to pass under max 5: %v", err)
	}
	if err := mgr.CheckLimit("max_runners", 10); !errors.Is(err, license.ErrLimitExceeded) {
		t.Fatalf("expected ErrLimitExceeded for usage 10 against fallback limit 5, got: %v", err)
	}

	// Read-only enforcement
	if !mgr.IsReadOnly() {
		t.Fatal("expected IsReadOnly() to be true")
	}
	if err := mgr.CanMutate(); !errors.Is(err, license.ErrDegradedReadOnly) {
		t.Fatalf("expected ErrDegradedReadOnly, got: %v", err)
	}

	// IsActive is true for service continuity; IsCommercialActive is false
	if !mgr.IsActive() {
		t.Fatal("expected IsActive() == true under PolicyDegraded")
	}
	if mgr.IsCommercialActive() {
		t.Fatal("expected IsCommercialActive() == false when degraded")
	}
}

func TestManager_PolicyDegraded_RuntimeExpirationAndRecovery(t *testing.T) {
	t.Parallel()

	pub, priv, err := license.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	signer, err := license.NewSigner(priv)
	if err != nil {
		t.Fatalf("NewSigner failed: %v", err)
	}

	validator, err := license.NewValidator(pub, license.WithProduct("otel-aws-log-processor"))
	if err != nil {
		t.Fatalf("NewValidator failed: %v", err)
	}

	tempDir := t.TempDir()
	licPath := filepath.Join(tempDir, "runtime-policy.key")

	now := time.Now().UTC()

	// Initial valid commercial license (valid for 1 year)
	activeClaims := license.Claims{
		ID: "lic-corp-001",
		Customer: license.Customer{
			Name: "Enterprise Corp",
		},
		Product:   "otel-aws-log-processor",
		Plan:      "enterprise",
		IssuedAt:  now,
		ExpiresAt: now.Add(365 * 24 * time.Hour),
		Features:  []string{"s3-archive", "cross-account"},
		Limits:    map[string]int64{"max_streams": 500},
	}

	if err := signer.SignToFile(activeClaims, licPath, true); err != nil {
		t.Fatalf("SignToFile failed: %v", err)
	}

	var degradedCalls int32
	var recoveredCalls int32

	mgr, err := license.NewManager(license.ManagerConfig{
		Validator:   validator,
		LicenseFile: licPath,
		Policy:      license.PolicyDegraded,
		FallbackClaims: &license.Claims{
			Product:  "otel-aws-log-processor",
			Plan:     "community",
			Customer: license.Customer{Name: "Community Fallback"},
			Features: []string{"basic-stream"},
			Limits:   map[string]int64{"max_streams": 10},
		},
		OnDegraded: func(reason error, claims *license.Claims) {
			atomic.AddInt32(&degradedCalls, 1)
		},
		OnRecovered: func(newClaims *license.Claims) {
			atomic.AddInt32(&recoveredCalls, 1)
		},
	})
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	// Initial state: Active commercial license
	if mgr.IsDegraded() {
		t.Fatal("expected manager to NOT be degraded initially")
	}
	if !mgr.HasFeature("s3-archive") {
		t.Fatal("expected feature 's3-archive' to be present")
	}
	if err := mgr.CheckLimit("max_streams", 300); err != nil {
		t.Fatalf("expected limit check for 300 to pass: %v", err)
	}

	// 1. Simulate license expiration: Replace file with an expired license
	time.Sleep(100 * time.Millisecond) // Ensure mtime changes
	expiredClaims := license.Claims{
		ID:        "lic-corp-expired",
		Customer:  license.Customer{Name: "Enterprise Corp"},
		Product:   "otel-aws-log-processor",
		Plan:      "enterprise",
		IssuedAt:  now.Add(-60 * 24 * time.Hour),
		ExpiresAt: now.Add(-1 * 24 * time.Hour), // Expired yesterday
		Features:  []string{"s3-archive"},
	}
	if err := signer.SignToFile(expiredClaims, licPath, true); err != nil {
		t.Fatalf("SignToFile expired failed: %v", err)
	}

	// Trigger inspection cycle
	mgr.Check()

	if !mgr.IsDegraded() {
		t.Fatal("expected manager to transition to degraded mode after expired license reload")
	}
	if atomic.LoadInt32(&degradedCalls) != 1 {
		t.Fatalf("expected OnDegraded to be called once, got %d", degradedCalls)
	}
	if mgr.HasFeature("s3-archive") {
		t.Fatal("expected commercial feature s3-archive to be deactivated in degraded mode")
	}
	if !mgr.HasFeature("basic-stream") {
		t.Fatal("expected fallback feature basic-stream to be active")
	}
	if err := mgr.CheckLimit("max_streams", 20); !errors.Is(err, license.ErrLimitExceeded) {
		t.Fatalf("expected ErrLimitExceeded against fallback limit 10, got: %v", err)
	}

	// 2. Recover by writing a renewed valid license
	time.Sleep(100 * time.Millisecond)
	renewedClaims := license.Claims{
		ID:        "lic-corp-renewed-002",
		Customer:  license.Customer{Name: "Enterprise Corp"},
		Product:   "otel-aws-log-processor",
		Plan:      "enterprise",
		IssuedAt:  now,
		ExpiresAt: now.Add(365 * 24 * time.Hour),
		Features:  []string{"s3-archive", "ai-analytics"},
		Limits:    map[string]int64{"max_streams": 1000},
	}
	if err := signer.SignToFile(renewedClaims, licPath, true); err != nil {
		t.Fatalf("SignToFile renewed failed: %v", err)
	}

	// Trigger inspection cycle
	mgr.Check()

	if mgr.IsDegraded() {
		t.Fatal("expected manager to recover from degraded mode")
	}
	if atomic.LoadInt32(&recoveredCalls) != 1 {
		t.Fatalf("expected OnRecovered to be called once, got %d", recoveredCalls)
	}
	if !mgr.HasFeature("ai-analytics") {
		t.Fatal("expected new renewed feature ai-analytics to be active")
	}
	if err := mgr.CheckLimit("max_streams", 800); err != nil {
		t.Fatalf("expected limit 800 to pass under renewed quota 1000: %v", err)
	}
}

func TestManager_PolicyWarnOnly(t *testing.T) {
	t.Parallel()

	pub, _, err := license.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	validator, err := license.NewValidator(pub, license.WithProduct("gitlab-fleet-governor"))
	if err != nil {
		t.Fatalf("NewValidator failed: %v", err)
	}

	mgr, err := license.NewManager(license.ManagerConfig{
		Validator:     validator,
		LicenseString: "invalid-license-content",
		Policy:        license.PolicyWarnOnly,
	})
	if err != nil {
		t.Fatalf("NewManager should succeed under PolicyWarnOnly: %v", err)
	}

	// PolicyWarnOnly never restricts features or limits
	if !mgr.HasFeature("any-enterprise-feature") {
		t.Fatal("expected HasFeature to unconditionally return true in PolicyWarnOnly")
	}
	if err := mgr.CheckLimit("any_quota", 999999); err != nil {
		t.Fatalf("expected CheckLimit to return nil under PolicyWarnOnly, got: %v", err)
	}
	if err := mgr.CanMutate(); err != nil {
		t.Fatalf("expected CanMutate to return nil under PolicyWarnOnly: %v", err)
	}
}

func TestManager_PolicyDegraded_BSLConversionRecovery(t *testing.T) {
	t.Parallel()

	pub, _, err := license.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	// Release date 4 years ago (BSL Change Date arrived 1 year ago!)
	releaseDate := time.Now().AddDate(-4, 0, 0)
	bslPolicy := license.BSLPolicy{
		ReleaseDate:       releaseDate,
		ChangePeriodYears: 3,
	}

	validator, err := license.NewValidator(pub,
		license.WithProduct("gitlab-fleet-governor"),
		license.WithBSLPolicy(bslPolicy),
	)
	if err != nil {
		t.Fatalf("NewValidator failed: %v", err)
	}

	var bslCallbackCalled int32
	var recoveredCalled int32

	mgr, err := license.NewManager(license.ManagerConfig{
		Validator:   validator,
		LicenseFile: "/non/existent/license.key",
		Policy:      license.PolicyDegraded,
		OnBSLConverted: func(claims *license.Claims) {
			atomic.AddInt32(&bslCallbackCalled, 1)
		},
		OnRecovered: func(claims *license.Claims) {
			atomic.AddInt32(&recoveredCalled, 1)
		},
	})
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	// Initially degraded due to missing license
	if !mgr.IsDegraded() {
		t.Fatal("expected manager to be degraded initially before BSL evaluation")
	}

	// Trigger inspection cycle where BSL Change Date is evaluated
	mgr.Check()

	if mgr.IsDegraded() {
		t.Fatal("expected manager to recover from degraded mode upon BSL open-source conversion")
	}
	if atomic.LoadInt32(&bslCallbackCalled) != 1 {
		t.Fatalf("expected OnBSLConverted to be called once, got %d", bslCallbackCalled)
	}
	if atomic.LoadInt32(&recoveredCalled) != 1 {
		t.Fatalf("expected OnRecovered to be called once, got %d", recoveredCalled)
	}

	claims := mgr.Claims()
	if claims.Plan != "open-source" {
		t.Fatalf("expected plan 'open-source', got %s", claims.Plan)
	}
	if !mgr.HasFeature("unrestricted-feature") {
		t.Fatal("expected wildcard feature support after BSL conversion")
	}
}

func TestManager_StopIdempotent(t *testing.T) {
	t.Parallel()

	pub, _, _ := license.GenerateKeyPair()
	validator, _ := license.NewValidator(pub)

	mgr, err := license.NewManager(license.ManagerConfig{
		Validator: validator,
		Policy:    license.PolicyDegraded,
	})
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mgr.Start(ctx)
	mgr.Stop()
	// Calling Stop again should not panic or hang
	mgr.Stop()
}
