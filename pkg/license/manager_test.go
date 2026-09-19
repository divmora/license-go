package license

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestManager_StaticString(t *testing.T) {
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

	mgr, err := NewManager(ManagerConfig{
		Validator:     validator,
		LicenseString: token,
	})
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	if mgr.Claims().Customer != claims.Customer {
		t.Errorf("customer mismatch: got %+v, want %+v", mgr.Claims().Customer, claims.Customer)
	}
	if !mgr.HasFeature("ha") {
		t.Error("expected HasFeature(ha) to be true")
	}
	if err := mgr.CheckLimit("max_runners", 50); err != nil {
		t.Errorf("CheckLimit failed: %v", err)
	}
	if err := mgr.CheckLimit("max_runners", 150); err == nil {
		t.Error("expected error for exceeding limit 150 > 100")
	}
}

func TestManager_FileReloadAndExpiry(t *testing.T) {
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	signer, _ := NewSigner(priv)
	validator, _ := NewValidator(pub, WithProduct("otel-aws-log-processor"))

	tempDir := t.TempDir()
	licFile := filepath.Join(tempDir, "license.key")

	now := time.Now().UTC()

	// Initial license: expires in 5 days (triggers warning <= 14 days)
	claims1 := Claims{
		ID: "lic-001",
		Customer: Customer{
			Name: "Divmora",
		},
		Product:   "otel-aws-log-processor",
		Plan:      "enterprise",
		IssuedAt:  now,
		ExpiresAt: now.Add(5 * 24 * time.Hour),
		Features:  []string{"metrics"},
	}

	if err := signer.SignToFile(claims1, licFile, true); err != nil {
		t.Fatalf("SignToFile failed: %v", err)
	}

	var warningCount int32
	var reloadCount int32

	warningDone := make(chan struct{}, 1)
	reloadDone := make(chan struct{}, 1)

	mgr, err := NewManager(ManagerConfig{
		Validator:         validator,
		LicenseFile:       licFile,
		CheckInterval:     20 * time.Millisecond,
		ExpiryWarningDays: 14,
		OnExpiringSoon: func(c *Claims, days int) {
			atomic.AddInt32(&warningCount, 1)
			select {
			case warningDone <- struct{}{}:
			default:
			}
		},
		OnReloaded: func(newC *Claims, oldC *Claims) {
			atomic.AddInt32(&reloadCount, 1)
			select {
			case reloadDone <- struct{}{}:
			default:
			}
		},
	})
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mgr.Start(ctx)
	defer mgr.Stop()

	// Wait for expiration warning
	select {
	case <-warningDone:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for OnExpiringSoon")
	}

	// Now update file with new renewed license
	// Sleep briefly to ensure mtime changes
	time.Sleep(100 * time.Millisecond)

	claims2 := Claims{
		ID: "lic-002-renewed",
		Customer: Customer{
			Name: "Divmora",
		},
		Product:   "otel-aws-log-processor",
		Plan:      "enterprise",
		IssuedAt:  now,
		ExpiresAt: now.Add(365 * 24 * time.Hour),
		Features:  []string{"metrics", "s3_archive"},
	}

	token2, _ := signer.SignArmored(claims2)
	if err := os.WriteFile(licFile, []byte(token2), 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	select {
	case <-reloadDone:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for OnReloaded")
	}

	if mgr.Claims().ID != "lic-002-renewed" {
		t.Errorf("expected renewed ID lic-002-renewed, got %s", mgr.Claims().ID)
	}
	if !mgr.HasFeature("s3_archive") {
		t.Error("expected new feature s3_archive to be present after reload")
	}
}

func TestManager_ConcurrentAccess(t *testing.T) {
	pub, priv, _ := GenerateKeyPair()
	signer, _ := NewSigner(priv)
	validator, _ := NewValidator(pub)

	token, _ := signer.Sign(sampleClaims())

	mgr, err := NewManager(ManagerConfig{
		Validator:     validator,
		LicenseString: token,
		CheckInterval: 5 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mgr.Start(ctx)
	defer mgr.Stop()

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 500; j++ {
				_ = mgr.Claims()
				_ = mgr.HasFeature("ha")
				_ = mgr.CheckLimit("max_runners", 10)
				_ = mgr.IsActive()
			}
		}()
	}
	wg.Wait()
}

func TestManager_GracePeriod(t *testing.T) {
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	signer, _ := NewSigner(priv)
	validator, _ := NewValidator(pub, WithProduct("gitlab-fleet-governor"))

	now := time.Now().UTC()
	claims := sampleClaims()
	claims.IssuedAt = now.Add(-30 * 24 * time.Hour)
	claims.ExpiresAt = now.Add(-1 * 24 * time.Hour)
	claims.GracePeriodDays = 7

	token, err := signer.SignArmored(claims)
	if err != nil {
		t.Fatalf("SignArmored failed: %v", err)
	}

	graceDone := make(chan int, 1)
	mgr, err := NewManager(ManagerConfig{
		Validator:     validator,
		LicenseString: token,
		CheckInterval: 10 * time.Millisecond,
		OnGracePeriod: func(c *Claims, graceDays int) {
			select {
			case graceDone <- graceDays:
			default:
			}
		},
	})
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mgr.Start(ctx)
	defer mgr.Stop()

	select {
	case days := <-graceDone:
		if days < 5 || days > 6 {
			t.Errorf("expected ~5-6 grace days remaining, got %d", days)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for OnGracePeriod")
	}

	if !mgr.IsActive() {
		t.Error("expected manager.IsActive() == true while in grace period")
	}
}

func TestManager_AutoResolveEnv(t *testing.T) {
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

	// 1. Test auto-resolution via DIVMORA_LICENSE_KEY
	t.Setenv(EnvLicenseKey, token)
	t.Setenv(EnvLicenseFile, "")

	mgrKey, err := NewManager(ManagerConfig{
		Validator: validator,
	})
	if err != nil {
		t.Fatalf("NewManager with EnvLicenseKey failed: %v", err)
	}
	if mgrKey.Claims().ID != claims.ID {
		t.Errorf("expected claims ID %q, got %q", claims.ID, mgrKey.Claims().ID)
	}

	// 2. Test auto-resolution via DIVMORA_LICENSE_FILE with hot-reloading capability
	tempDir := t.TempDir()
	licPath := filepath.Join(tempDir, "auto-license.key")
	if err := os.WriteFile(licPath, []byte(token), 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	t.Setenv(EnvLicenseKey, "")
	t.Setenv(EnvLicenseFile, licPath)

	mgrFile, err := NewManager(ManagerConfig{
		Validator: validator,
	})
	if err != nil {
		t.Fatalf("NewManager with EnvLicenseFile failed: %v", err)
	}
	if mgrFile.cfg.LicenseFile != licPath {
		t.Errorf("expected manager cfg.LicenseFile %q, got %q", licPath, mgrFile.cfg.LicenseFile)
	}
	if mgrFile.Claims().ID != claims.ID {
		t.Errorf("expected claims ID %q, got %q", claims.ID, mgrFile.Claims().ID)
	}
}

func TestManager_BSLConversionClockDefense(t *testing.T) {
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	signer, _ := NewSigner(priv)
	now := time.Now().UTC()

	// ChangeDate is in the future
	changeDate := now.Add(365 * 24 * time.Hour)
	bslPolicy := BSLPolicy{
		Product:            "gitlab-fleet-governor",
		ExplicitChangeDate: changeDate,
	}

	// Authoritative time is current time (now), strictly before changeDate
	authTime := now
	validator, err := NewValidator(pub,
		WithProduct("gitlab-fleet-governor"),
		WithBSLPolicy(bslPolicy),
		WithServerTimeAttestation(authTime, 1*time.Hour),
		WithStrictClockDefense(false),
	)
	if err != nil {
		t.Fatalf("NewValidator failed: %v", err)
	}

	claims := sampleClaims()
	claims.Product = "gitlab-fleet-governor"
	claims.ExpiresAt = now.Add(30 * 24 * time.Hour)
	token, _ := signer.SignArmored(claims)

	var bslConvertedCalled bool
	mgr, err := NewManager(ManagerConfig{
		Validator:     validator,
		LicenseString: token,
		OnBSLConverted: func(c *Claims) {
			bslConvertedCalled = true
		},
	})
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	// Run check: authoritative time defends against premature conversion
	mgr.check()

	if bslConvertedCalled {
		t.Error("expected BSL conversion NOT to trigger because authoritative time is before changeDate")
	}
	if mgr.Claims().Plan == "open-source" {
		t.Error("claims should not have converted to open-source")
	}

	// Now update validator with authoritative time PAST changeDate and unexpired token
	claimsValidConverted := sampleClaims()
	claimsValidConverted.Product = "gitlab-fleet-governor"
	claimsValidConverted.ExpiresAt = changeDate.Add(48 * time.Hour)
	tokenValidConverted, _ := signer.SignArmored(claimsValidConverted)
	validatorConverted, _ := NewValidator(pub,
		WithProduct("gitlab-fleet-governor"),
		WithBSLPolicy(bslPolicy),
		WithServerTimeAttestation(changeDate.Add(24*time.Hour), 1*time.Hour),
	)
	mgrConverted, err := NewManager(ManagerConfig{
		Validator:     validatorConverted,
		LicenseString: tokenValidConverted,
		OnBSLConverted: func(c *Claims) {
			bslConvertedCalled = true
		},
	})
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	mgrConverted.check()

	if !bslConvertedCalled {
		t.Error("expected BSL conversion to trigger when authoritative time is past changeDate")
	}
	if mgrConverted.Claims().Plan != "open-source" {
		t.Errorf("expected plan 'open-source', got %q", mgrConverted.Claims().Plan)
	}
}

func TestManager_ExpirationClockDefense(t *testing.T) {
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	signer, _ := NewSigner(priv)
	now := time.Now().UTC()

	claims := sampleClaims()
	claims.Product = "gitlab-fleet-governor"
	// License expired 1 day ago according to authoritative time
	claims.ExpiresAt = now.Add(-24 * time.Hour)
	claims.GracePeriodDays = 0
	token, _ := signer.SignArmored(claims)

	// Authoritative server time is now (past expiration)
	validator, err := NewValidator(pub,
		WithProduct("gitlab-fleet-governor"),
		WithServerTimeAttestation(now, 1*time.Hour),
		WithAllowExpired(true),
	)
	if err != nil {
		t.Fatalf("NewValidator failed: %v", err)
	}

	var expiredNotified bool
	mgr, err := NewManager(ManagerConfig{
		Validator:     validator,
		LicenseString: token,
		Policy:        PolicyStrict,
		OnExpired: func(c *Claims) {
			expiredNotified = true
		},
	})
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	mgr.check()

	if !expiredNotified {
		t.Error("expected OnExpired notification when authoritative time shows license is expired")
	}
	if mgr.IsActive() {
		t.Error("expected mgr.IsActive() == false when license is expired according to authoritative time")
	}
}

func TestManager_SymlinkAttackDefense(t *testing.T) {
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	signer, _ := NewSigner(priv)
	validator, _ := NewValidator(pub, WithProduct("gitlab-fleet-governor"))

	tempDir := t.TempDir()
	realLicFile := filepath.Join(tempDir, "real_license.key")
	symlinkLicFile := filepath.Join(tempDir, "symlink_license.key")

	claims := sampleClaims()
	claims.Product = "gitlab-fleet-governor"
	token, err := signer.SignArmored(claims)
	if err != nil {
		t.Fatalf("SignArmored failed: %v", err)
	}

	if err := os.WriteFile(realLicFile, []byte(token), 0600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	if err := os.Symlink(realLicFile, symlinkLicFile); err != nil {
		t.Fatalf("Symlink failed: %v", err)
	}

	// 1. ResolveLicense must reject symlink
	_, err = ResolveLicense(symlinkLicFile)
	if !errors.Is(err, ErrSymlinkNotAllowed) {
		t.Fatalf("expected ResolveLicense to reject symlink with ErrSymlinkNotAllowed, got: %v", err)
	}

	// 2. InspectFromFile must reject symlink
	_, err = InspectFromFile(symlinkLicFile)
	if !errors.Is(err, ErrSymlinkNotAllowed) {
		t.Fatalf("expected InspectFromFile to reject symlink with ErrSymlinkNotAllowed, got: %v", err)
	}

	// 3. Manager with AllowSymlinks: false (default) in PolicyStrict must fail with ErrSymlinkNotAllowed
	_, err = NewManager(ManagerConfig{
		Validator:   validator,
		LicenseFile: symlinkLicFile,
		Policy:      PolicyStrict,
	})
	if !errors.Is(err, ErrSymlinkNotAllowed) {
		t.Fatalf("expected NewManager to reject symlink with ErrSymlinkNotAllowed, got: %v", err)
	}

	// 4. Manager with AllowSymlinks: true must succeed
	mgrAllowed, err := NewManager(ManagerConfig{
		Validator:     validator,
		LicenseFile:   symlinkLicFile,
		AllowSymlinks: true,
	})
	if err != nil {
		t.Fatalf("expected NewManager with AllowSymlinks:true to succeed, got: %v", err)
	}
	if mgrAllowed.Claims().ID != claims.ID {
		t.Errorf("expected claims ID %q, got %q", claims.ID, mgrAllowed.Claims().ID)
	}
}

func TestManager_DegradedModeDefaultsAndDefense(t *testing.T) {
	pub, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	validator, _ := NewValidator(pub, WithProduct("gitlab-fleet-governor"))

	// 1. Default PolicyDegraded without explicit DegradedReadOnly must default to DegradedReadOnly == true
	mgrDefault, err := NewManager(ManagerConfig{
		Validator: validator,
		Policy:    PolicyDegraded,
		// No license provided -> triggers degraded fallback
	})
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}
	if !mgrDefault.IsDegraded() {
		t.Error("expected manager to be in degraded mode")
	}
	if !mgrDefault.IsReadOnly() {
		t.Error("expected DegradedReadOnly to default to true under PolicyDegraded")
	}
	if err := mgrDefault.CanMutate(); !errors.Is(err, ErrDegradedReadOnly) {
		t.Errorf("expected CanMutate to return ErrDegradedReadOnly, got: %v", err)
	}

	// 2. PolicyDegraded with AllowDegradedMutations: true must allow mutations
	mgrMutable, err := NewManager(ManagerConfig{
		Validator:              validator,
		Policy:                 PolicyDegraded,
		AllowDegradedMutations: true,
	})
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}
	if !mgrMutable.IsDegraded() {
		t.Error("expected manager to be in degraded mode")
	}
	if mgrMutable.IsReadOnly() {
		t.Error("expected IsReadOnly() == false when AllowDegradedMutations is true")
	}
	if err := mgrMutable.CanMutate(); err != nil {
		t.Errorf("expected CanMutate to succeed when AllowDegradedMutations is true, got: %v", err)
	}
}
