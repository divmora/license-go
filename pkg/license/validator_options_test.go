package license

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestValidator_OptionsAndGetters(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	pemBytes, err := EncodePublicKeyToPEM(pub)
	if err != nil {
		t.Fatal(err)
	}

	// 1. NewValidatorFromPEMFile
	tmpDir := t.TempDir()
	pubFile := filepath.Join(tmpDir, "pub.pem")
	if err := SavePublicKeyToPEMFile(pub, pubFile, 0644); err != nil {
		t.Fatal(err)
	}

	ring := NewKeyRing(pub)
	grant := NewNonProductionGrant("Non-Prod")

	val, err := NewValidatorFromPEMFile(pubFile,
		WithProduct("test-prod"),
		WithClockSkew(2*time.Minute),
		WithGracePeriod(48*time.Hour),
		WithBSLGrants(grant),
		WithCurrentFeatures("sso", "audit"),
		WithAllowInactive(true),
		WithKeyRing(ring),
		WithAdditionalPublicKeyPEM(pemBytes),
		WithMaxClockDrift(5*time.Minute),
	)
	if err != nil {
		t.Fatalf("NewValidatorFromPEMFile failed: %v", err)
	}

	// 2. Test Getters
	if !val.PublicKey().Equal(pub) {
		t.Error("PublicKey() does not match expected pub key")
	}
	if val.KeyRing() == nil {
		t.Error("KeyRing() returned nil")
	}
	if val.ClockSkew() != 2*time.Minute {
		t.Errorf("ClockSkew() = %v, want 2m", val.ClockSkew())
	}
	if val.GracePeriod() != 48*time.Hour {
		t.Errorf("GracePeriod() = %v, want 48h", val.GracePeriod())
	}

	evalTime, tampered, _, err := val.ResolveEvaluationTime(time.Now().UTC())
	if err != nil || tampered || evalTime.IsZero() {
		t.Errorf("ResolveEvaluationTime error=%v, tampered=%v, evalTime=%v", err, tampered, evalTime)
	}

	_ = priv
}

func TestValidator_FileOperationsAndRegionEnv(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	signer, err := NewSigner(priv)
	if err != nil {
		t.Fatal(err)
	}

	claims := Claims{
		Customer: Customer{Name: "Acme Corp"},
		Product:  "gitlab-fleet-governor",
		Scope: &Scope{
			Regions: []string{"us-west-2"},
		},
	}
	token, err := signer.SignArmored(claims)
	if err != nil {
		t.Fatal(err)
	}

	tmpDir := t.TempDir()
	licPath := filepath.Join(tmpDir, "license.key")
	if err := os.WriteFile(licPath, []byte(token), 0644); err != nil {
		t.Fatal(err)
	}

	// 1. InspectFromFile
	inspected, err := InspectFromFile(licPath)
	if err != nil || inspected.Customer.Name != "Acme Corp" {
		t.Fatalf("InspectFromFile failed: %v", err)
	}

	// Symlink check on InspectFromFile
	symPath := filepath.Join(tmpDir, "symlink.key")
	if err := os.Symlink(licPath, symPath); err == nil {
		_, err = InspectFromFile(symPath)
		if err == nil {
			t.Error("expected error for symlink in InspectFromFile, got nil")
		}
	}

	// 2. WithCurrentRegion configuration
	valRegion, err := NewValidator(pub, WithProduct("gitlab-fleet-governor"), WithCurrentRegion("us-west-2"))
	if err != nil {
		t.Fatal(err)
	}
	verified, err := valRegion.VerifyFromFile(licPath)
	if err != nil {
		t.Fatalf("VerifyFromFile with WithCurrentRegion failed: %v", err)
	}
	if verified.Customer.Name != "Acme Corp" {
		t.Errorf("customer mismatch: got %s", verified.Customer.Name)
	}

	// Missing file
	if _, err := valRegion.VerifyFromFile(filepath.Join(tmpDir, "nonexistent")); err == nil {
		t.Error("expected error for nonexistent file, got nil")
	}

	// 3. ParsePublicKeyFromString
	pemBytes, err := EncodePublicKeyToPEM(pub)
	if err != nil {
		t.Fatal(err)
	}
	pubParsed, err := ParsePublicKeyFromString(string(pemBytes))
	if err != nil || !pubParsed.Equal(pub) {
		t.Errorf("ParsePublicKeyFromString(PEM) failed: %v", err)
	}

	// Parse from file
	pubFile := filepath.Join(tmpDir, "pub.pem")
	if err := os.WriteFile(pubFile, pemBytes, 0644); err != nil {
		t.Fatal(err)
	}
	pubFromFile, err := ParsePublicKeyFromString(pubFile)
	if err != nil || !pubFromFile.Equal(pub) {
		t.Errorf("ParsePublicKeyFromString(file) failed: %v", err)
	}

	// 4. WithReleaseAttestationFile & WithBinaryPath
	relClaims := ReleaseClaims{
		Product:   "gitlab-fleet-governor",
		Version:   "v1.0.0",
		BuildDate: time.Now().UTC(),
	}
	relToken, err := SignReleaseArmored(relClaims, priv)
	if err != nil {
		t.Fatal(err)
	}
	relPath := filepath.Join(tmpDir, "release.sig")
	if err := os.WriteFile(relPath, []byte(relToken), 0644); err != nil {
		t.Fatal(err)
	}
	binPath := filepath.Join(tmpDir, "app.bin")
	if err := os.WriteFile(binPath, []byte("app-bytes"), 0755); err != nil {
		t.Fatal(err)
	}

	valProv, err := NewValidator(pub,
		WithProduct("gitlab-fleet-governor"),
		WithCurrentVersion("v1.0.0"),
		WithCurrentRegion("us-west-2"),
		WithReleaseAttestationFile(relPath),
		WithBinaryPath(binPath),
	)
	if err != nil {
		t.Fatalf("NewValidator with attestation file and binary path failed: %v", err)
	}
	if _, err := valProv.Verify(token); err != nil {
		t.Fatalf("Verify with attestation file failed: %v", err)
	}

	// WithReleaseAttestationFile with symlink should return ErrSymlinkNotAllowed
	if err := os.Symlink(relPath, filepath.Join(tmpDir, "rel_sym.sig")); err == nil {
		_, err := NewValidator(pub, WithReleaseAttestationFile(filepath.Join(tmpDir, "rel_sym.sig")))
		if err == nil || !errors.Is(err, ErrSymlinkNotAllowed) {
			t.Errorf("expected ErrSymlinkNotAllowed for symlink attestation file, got: %v", err)
		}
	}
}

func TestValidator_InspectAndBSLEntitlement(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	signer, err := NewSigner(priv)
	if err != nil {
		t.Fatal(err)
	}

	claims := Claims{
		Customer: Customer{Name: "Acme Corp"},
		Product:  "gitlab-fleet-governor",
	}
	token, err := signer.Sign(claims)
	if err != nil {
		t.Fatal(err)
	}

	// 1. Inspect valid token
	inspected, err := Inspect(token)
	if err != nil || inspected.Customer.Name != "Acme Corp" {
		t.Fatalf("Inspect failed: %v", err)
	}

	// 2. Inspect invalid token format
	if _, err := Inspect("invalid.token"); err == nil {
		t.Error("expected error for invalid token format")
	}

	// 3. Inspect invalid json
	badJSONToken := "DIV1.e2ludmFsaWQganNvbn0.YWJj"
	if _, err := Inspect(badJSONToken); err == nil {
		t.Error("expected error for invalid json token")
	}

	// 4. Validator.EvaluateBSLEntitlement without BSLPolicy
	valNoBSL, err := NewValidator(pub, WithProduct("gitlab-fleet-governor"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := valNoBSL.EvaluateBSLEntitlement(BSLUsageRequest{}); err == nil {
		t.Error("expected error from EvaluateBSLEntitlement without policy")
	}

	// 5. Validator.EvaluateBSLEntitlement with BSLPolicy
	valWithBSL, err := NewValidator(pub,
		WithProduct("gitlab-fleet-governor"),
		WithBSLPolicy(BSLPolicy{
			Product:     "gitlab-fleet-governor",
			ReleaseDate: time.Now().Add(-4 * 365 * 24 * time.Hour), // 4 years ago -> converted
		}),
		WithCurrentEnvironment("staging"),
		WithCurrentUsage(map[string]int64{"nodes": 10}),
		WithCurrentFeatures("sso"),
	)
	if err != nil {
		t.Fatal(err)
	}

	if valWithBSL.BSLPolicy() == nil {
		t.Error("expected non-nil BSLPolicy()")
	}

	res, err := valWithBSL.EvaluateBSLEntitlement(BSLUsageRequest{})
	if err != nil {
		t.Fatalf("EvaluateBSLEntitlement failed: %v", err)
	}
	if !res.Authorized {
		t.Error("expected 4-year old release to be authorized under converted BSL")
	}
}

func TestValidator_ConstructorsAndKeysErrorBranches(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	pemBytes, err := EncodePublicKeyToPEM(pub)
	if err != nil {
		t.Fatal(err)
	}

	// 1. NewValidatorWithKeyRing with nil and empty ring
	if _, err := NewValidatorWithKeyRing(nil); !errors.Is(err, ErrMissingPublicKey) {
		t.Errorf("expected ErrMissingPublicKey for nil ring, got: %v", err)
	}
	emptyRing := &KeyRing{}
	if _, err := NewValidatorWithKeyRing(emptyRing); !errors.Is(err, ErrMissingPublicKey) {
		t.Errorf("expected ErrMissingPublicKey for empty ring, got: %v", err)
	}

	// 2. NewValidatorFromPEM with invalid PEM
	if _, err := NewValidatorFromPEM([]byte("invalid pem")); err == nil {
		t.Error("expected error for NewValidatorFromPEM with invalid pem")
	}

	// 3. NewValidatorFromPEMFile with non-existent file
	if _, err := NewValidatorFromPEMFile("/non/existent/file.pem"); err == nil {
		t.Error("expected error for NewValidatorFromPEMFile with missing file")
	}

	// 4. NewValidatorFromBase64 with invalid base64
	if _, err := NewValidatorFromBase64("invalid-base64!!!"); err == nil {
		t.Error("expected error for NewValidatorFromBase64 with invalid base64")
	}

	// 5. NewValidatorFromEmbeddedPEM
	valEmbedded, err := NewValidatorFromEmbeddedPEM(pemBytes)
	if err != nil || valEmbedded == nil {
		t.Fatalf("NewValidatorFromEmbeddedPEM failed: %v", err)
	}

	// 6. Keys file operations with invalid paths / inputs
	tmpDir := t.TempDir()
	if err := SavePublicKeyToPEMFile(nil, filepath.Join(tmpDir, "bad.pem"), 0644); err == nil {
		t.Error("expected error for SavePublicKeyToPEMFile with nil key")
	}
	if _, err := LoadPublicKeyFromPEMFile(filepath.Join(tmpDir, "missing.pem")); err == nil {
		t.Error("expected error for LoadPublicKeyFromPEMFile with missing file")
	}
	if _, err := LoadPublicKeysFromPEMFile(filepath.Join(tmpDir, "missing.pem")); err == nil {
		t.Error("expected error for LoadPublicKeysFromPEMFile with missing file")
	}

	// 7. InspectReleaseFromFile with missing file
	if _, err := InspectReleaseFromFile(filepath.Join(tmpDir, "missing_rel.sig")); err == nil {
		t.Error("expected error for InspectReleaseFromFile with missing file")
	}

	// 8. ParseLicenseRequest and ParseLicenseRequestFile error branches
	if _, err := ParseLicenseRequest([]byte("not-a-request")); err == nil {
		t.Error("expected error for ParseLicenseRequest with invalid data")
	}
	if _, err := ParseLicenseRequestFile(filepath.Join(tmpDir, "missing_req.divreq")); err == nil {
		t.Error("expected error for ParseLicenseRequestFile with missing file")
	}
}
