package license

import (
	"context"
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
