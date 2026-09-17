package license_test

import (
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/divmora/license-go/pkg/license"
)

func TestKeyRing_MultiKeyPEMParsingAndEncoding(t *testing.T) {
	pub1, _, err := license.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair 1 failed: %v", err)
	}
	pub2, _, err := license.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair 2 failed: %v", err)
	}
	pub3, _, err := license.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair 3 failed: %v", err)
	}

	keys := []ed25519.PublicKey{pub1, pub2, pub3}
	bundlePEM, err := license.EncodePublicKeysToPEM(keys)
	if err != nil {
		t.Fatalf("EncodePublicKeysToPEM failed: %v", err)
	}

	parsedKeys, err := license.ParsePublicKeysFromPEM(bundlePEM)
	if err != nil {
		t.Fatalf("ParsePublicKeysFromPEM failed: %v", err)
	}
	if len(parsedKeys) != 3 {
		t.Fatalf("expected 3 parsed keys, got %d", len(parsedKeys))
	}

	ring, err := license.NewKeyRingFromPEM(bundlePEM)
	if err != nil {
		t.Fatalf("NewKeyRingFromPEM failed: %v", err)
	}
	if ring.Count() != 3 {
		t.Fatalf("expected 3 keys in keyring, got %d", ring.Count())
	}

	if ring.Primary() == nil || !pub1.Equal(ring.Primary().PublicKey) {
		t.Errorf("expected primary key to match pub1")
	}

	// Test file roundtrip
	tmpDir := t.TempDir()
	bundlePath := filepath.Join(tmpDir, "trusted_keys.pem")
	if err := os.WriteFile(bundlePath, bundlePEM, 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	fileKeys, err := license.LoadPublicKeysFromPEMFile(bundlePath)
	if err != nil {
		t.Fatalf("LoadPublicKeysFromPEMFile failed: %v", err)
	}
	if len(fileKeys) != 3 {
		t.Fatalf("expected 3 file keys, got %d", len(fileKeys))
	}

	fileRing, err := license.NewKeyRingFromPEMFile(bundlePath)
	if err != nil {
		t.Fatalf("NewKeyRingFromPEMFile failed: %v", err)
	}
	if fileRing.Count() != 3 {
		t.Fatalf("expected 3 keys in file ring, got %d", fileRing.Count())
	}
}

func TestKeyRing_ZeroDowntimeRotation(t *testing.T) {
	// 2025 signing key
	pub2025, priv2025, err := license.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair 2025 failed: %v", err)
	}
	signer2025, err := license.NewSigner(priv2025, license.WithSignerKeyID("divmora-2025-root"))
	if err != nil {
		t.Fatalf("NewSigner 2025 failed: %v", err)
	}

	// 2026 signing key
	pub2026, priv2026, err := license.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair 2026 failed: %v", err)
	}
	signer2026, err := license.NewSigner(priv2026, license.WithSignerKeyID("divmora-2026-root"))
	if err != nil {
		t.Fatalf("NewSigner 2026 failed: %v", err)
	}

	// Issue Token A with 2025 key
	token2025, err := signer2025.Sign(license.Claims{
		Product: "gitlab-fleet-governor",
		Customer: license.Customer{
			Name: "Acme Corp (2025 License)",
		},
		Plan: "enterprise",
	})
	if err != nil {
		t.Fatalf("Sign 2025 failed: %v", err)
	}

	// Issue Token B with 2026 key
	token2026, err := signer2026.Sign(license.Claims{
		Product: "gitlab-fleet-governor",
		Customer: license.Customer{
			Name: "Acme Corp (2026 Renewal)",
		},
		Plan: "enterprise",
	})
	if err != nil {
		t.Fatalf("Sign 2026 failed: %v", err)
	}

	// Configure Validator with 2026 as Primary and 2025 as Fallback
	validator, err := license.NewValidator(pub2026,
		license.WithAdditionalPublicKeys(pub2025),
		license.WithProduct("gitlab-fleet-governor"),
	)
	if err != nil {
		t.Fatalf("NewValidator failed: %v", err)
	}

	// 1. Verify 2026 token
	res2026, err := validator.VerifyWithResult(token2026)
	if err != nil {
		t.Fatalf("expected token2026 to verify, got: %v", err)
	}
	if res2026.Claims.Customer.Name != "Acme Corp (2026 Renewal)" {
		t.Errorf("unexpected customer name: %s", res2026.Claims.Customer.Name)
	}
	if res2026.VerifiedByKeyStatus != license.KeyStatusActive {
		t.Errorf("expected KeyStatusActive, got %s", res2026.VerifiedByKeyStatus)
	}

	// 2. Verify 2025 legacy token (zero-downtime rotation)
	res2025, err := validator.VerifyWithResult(token2025)
	if err != nil {
		t.Fatalf("expected token2025 to verify seamlessly under fallback key, got: %v", err)
	}
	if res2025.Claims.Customer.Name != "Acme Corp (2025 License)" {
		t.Errorf("unexpected customer name: %s", res2025.Claims.Customer.Name)
	}
	if res2025.VerifiedByKeyStatus != license.KeyStatusRetiring {
		t.Errorf("expected KeyStatusRetiring for legacy key, got %s", res2025.VerifiedByKeyStatus)
	}
}

func TestKeyRing_EmergencyRevocation(t *testing.T) {
	// Compromised key
	pubCompromised, privCompromised, err := license.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair compromised failed: %v", err)
	}
	compromisedSigner, _ := license.NewSigner(privCompromised, license.WithSignerKeyID("compromised-key-01"))

	// Good key
	pubGood, privGood, err := license.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair good failed: %v", err)
	}
	goodSigner, _ := license.NewSigner(privGood, license.WithSignerKeyID("good-key-01"))

	badToken, err := compromisedSigner.Sign(license.Claims{
		Product:  "otel-aws-log-processor",
		Customer: license.Customer{Name: "Hacked Tenant"},
	})
	if err != nil {
		t.Fatalf("Sign bad token failed: %v", err)
	}

	goodToken, err := goodSigner.Sign(license.Claims{
		Product:  "otel-aws-log-processor",
		Customer: license.Customer{Name: "Legit Tenant"},
	})
	if err != nil {
		t.Fatalf("Sign good token failed: %v", err)
	}

	// KeyRing with good as primary, compromised key added
	ring := license.NewKeyRing(pubGood)
	entryCompromised, err := ring.AddKeyWithID("compromised-key-01", pubCompromised, license.KeyStatusActive)
	if err != nil {
		t.Fatalf("AddKeyWithID failed: %v", err)
	}

	// Revoke the compromised key
	if err := ring.Revoke(entryCompromised.ID); err != nil {
		t.Fatalf("Revoke failed: %v", err)
	}

	validator, err := license.NewValidatorWithKeyRing(ring, license.WithProduct("otel-aws-log-processor"))
	if err != nil {
		t.Fatalf("NewValidatorWithKeyRing failed: %v", err)
	}

	// 1. Verify bad token fails with ErrKeyRevoked
	_, err = validator.Verify(badToken)
	if !errors.Is(err, license.ErrKeyRevoked) {
		t.Fatalf("expected ErrKeyRevoked, got: %v", err)
	}

	// 2. Verify good token succeeds
	claims, err := validator.Verify(goodToken)
	if err != nil {
		t.Fatalf("expected good token to verify, got: %v", err)
	}
	if claims.Customer.Name != "Legit Tenant" {
		t.Errorf("unexpected customer name: %s", claims.Customer.Name)
	}
}

func TestKeyRing_UntrustedKeyRejection(t *testing.T) {
	pubTrusted, _, _ := license.GenerateKeyPair()
	_, privUntrusted, _ := license.GenerateKeyPair()

	untrustedSigner, _ := license.NewSigner(privUntrusted)
	token, err := untrustedSigner.Sign(license.Claims{
		Product:  "gitlab-fleet-governor",
		Customer: license.Customer{Name: "Rogue Issuer"},
	})
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	validator, err := license.NewValidator(pubTrusted)
	if err != nil {
		t.Fatalf("NewValidator failed: %v", err)
	}

	_, err = validator.Verify(token)
	if !errors.Is(err, license.ErrInvalidSignature) {
		t.Fatalf("expected ErrInvalidSignature, got: %v", err)
	}
}

func TestKeyRing_WithRevokedKeyIDsOption(t *testing.T) {
	pub, priv, _ := license.GenerateKeyPair()
	signer, _ := license.NewSigner(priv)

	token, _ := signer.Sign(license.Claims{
		Product:  "gitlab-fleet-governor",
		Customer: license.Customer{Name: "Acme"},
	})

	fp := license.KeyFingerprint(pub)
	// Create validator and revoke the key via fingerprint
	validator, err := license.NewValidator(pub, license.WithRevokedKeyIDs(fp))
	if err != nil {
		t.Fatalf("NewValidator failed: %v", err)
	}

	_, err = validator.Verify(token)
	if !errors.Is(err, license.ErrKeyRevoked) {
		t.Fatalf("expected ErrKeyRevoked, got: %v", err)
	}
}

func TestKeyRing_ConcurrentAccess(t *testing.T) {
	pub1, priv1, _ := license.GenerateKeyPair()
	pub2, priv2, _ := license.GenerateKeyPair()

	signer1, _ := license.NewSigner(priv1)
	signer2, _ := license.NewSigner(priv2)

	token1, _ := signer1.Sign(license.Claims{
		Product:  "gitlab-fleet-governor",
		Customer: license.Customer{Name: "Worker 1"},
	})
	token2, _ := signer2.Sign(license.Claims{
		Product:  "gitlab-fleet-governor",
		Customer: license.Customer{Name: "Worker 2"},
	})

	validator, err := license.NewValidator(pub1,
		license.WithAdditionalPublicKeys(pub2),
		license.WithProduct("gitlab-fleet-governor"),
	)
	if err != nil {
		t.Fatalf("NewValidator failed: %v", err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			_, err := validator.Verify(token1)
			if err != nil {
				t.Errorf("token1 verification failed: %v", err)
			}
		}()
		go func() {
			defer wg.Done()
			_, err := validator.Verify(token2)
			if err != nil {
				t.Errorf("token2 verification failed: %v", err)
			}
		}()
	}
	wg.Wait()
}

func TestKeyRing_FingerprintCollisionDefense(t *testing.T) {
	pub1, _, err := license.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair 1 failed: %v", err)
	}
	pub2, _, err := license.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair 2 failed: %v", err)
	}

	fp1 := license.KeyFingerprint(pub1)
	fp2 := license.KeyFingerprint(pub2)

	ring := license.NewKeyRing(pub1)

	// Register key 2 with a custom ID that intentionally matches key 1's fingerprint!
	entry2, err := ring.AddKey(pub2, license.WithCustomKeyID(fp1))
	if err != nil {
		t.Fatalf("AddKey with colliding custom ID failed: %v", err)
	}

	// 1. Finding by fingerprint should return key 1, NOT key 2
	foundFP, ok := ring.FindKeyByFingerprint(fp1)
	if !ok || foundFP == nil {
		t.Fatalf("expected FindKeyByFingerprint(%q) to find key 1", fp1)
	}
	if !foundFP.PublicKey.Equal(pub1) {
		t.Fatalf("expected FindKeyByFingerprint to return pub1, got: %v", foundFP.PublicKey)
	}

	// 2. Finding by ID should return key 2 (which registered that custom ID)
	foundID, ok := ring.FindKeyByID(fp1)
	if !ok || foundID == nil {
		t.Fatalf("expected FindKeyByID(%q) to find key 2", fp1)
	}
	if !foundID.PublicKey.Equal(pub2) {
		t.Fatalf("expected FindKeyByID to return pub2, got: %v", foundID.PublicKey)
	}

	// 3. FindKey with "sha256:" prefix prioritizes fingerprint map
	foundGeneral, ok := ring.FindKey(fp1)
	if !ok || !foundGeneral.PublicKey.Equal(pub1) {
		t.Fatalf("expected FindKey(%q) to return key 1", fp1)
	}

	// 4. Revoking fp1 must revoke key 1, NOT key 2
	if err := ring.Revoke(fp1); err != nil {
		t.Fatalf("Revoke failed: %v", err)
	}

	foundFPAfter, _ := ring.FindKeyByFingerprint(fp1)
	if foundFPAfter.Status != license.KeyStatusRevoked {
		t.Fatalf("expected key 1 to be revoked, got status: %s", foundFPAfter.Status)
	}

	if entry2.Status != license.KeyStatusActive {
		t.Fatalf("expected key 2 to remain active after revoking key 1's fingerprint, got: %s", entry2.Status)
	}

	// 5. Verify finding key 2 by its genuine fingerprint
	foundFP2, ok := ring.FindKeyByFingerprint(fp2)
	if !ok || !foundFP2.PublicKey.Equal(pub2) {
		t.Fatalf("expected FindKeyByFingerprint(%q) to find key 2", fp2)
	}
}
