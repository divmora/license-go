package issuer

import (
	"encoding/pem"
	"path/filepath"
	"testing"
	"time"

	"github.com/divmora/license-go/pkg/license"
)

func TestIssuer_GenerateKeyPairAndPEM(t *testing.T) {
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	pemBytes, err := EncodePrivateKeyToPEM(priv)
	if err != nil {
		t.Fatalf("EncodePrivateKeyToPEM failed: %v", err)
	}

	parsedPriv, err := ParsePrivateKeyFromPEM(pemBytes)
	if err != nil {
		t.Fatalf("ParsePrivateKeyFromPEM failed: %v", err)
	}

	if !priv.Equal(parsedPriv) {
		t.Fatal("private keys do not match after PEM round trip")
	}

	// Test file saving and loading
	tmpDir := t.TempDir()
	keyFile := filepath.Join(tmpDir, "test.pem")
	if err := SavePrivateKeyToPEMFile(priv, keyFile, 0600); err != nil {
		t.Fatalf("SavePrivateKeyToPEMFile failed: %v", err)
	}

	loadedPriv, err := LoadPrivateKeyFromPEMFile(keyFile)
	if err != nil {
		t.Fatalf("LoadPrivateKeyFromPEMFile failed: %v", err)
	}

	if !priv.Equal(loadedPriv) {
		t.Fatal("private keys do not match after file round trip")
	}

	_ = pub
}

func TestIssuer_SignAndVerifyLicense(t *testing.T) {
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	signer, err := NewSigner(priv, WithSignerKeyID("key-1"))
	if err != nil {
		t.Fatalf("NewSigner failed: %v", err)
	}

	claims := license.Claims{
		Product:  "gitlab-fleet-governor",
		Customer: license.Customer{Name: "Acme Corp"},
		Plan:     "enterprise",
	}

	token, err := signer.Sign(claims)
	if err != nil {
		t.Fatalf("signer.Sign failed: %v", err)
	}

	validator, err := license.NewValidator(pub, license.WithProduct("gitlab-fleet-governor"))
	if err != nil {
		t.Fatalf("NewValidator failed: %v", err)
	}
	verified, err := validator.Verify(token)
	if err != nil {
		t.Fatalf("validator.Verify failed: %v", err)
	}

	if verified.Customer.Name != "Acme Corp" {
		t.Errorf("customer mismatch: got %s, want Acme Corp", verified.Customer.Name)
	}
	if verified.KeyID != "key-1" {
		t.Errorf("key ID mismatch: got %s, want key-1", verified.KeyID)
	}
}

func TestIssuer_SignRelease(t *testing.T) {
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	releaseClaims := license.ReleaseClaims{
		Product:     "gitlab-fleet-governor",
		Version:     "v1.0.0",
		BuildDate:   time.Now().UTC(),
		ReleaseDate: time.Now().UTC(),
	}

	token, err := SignReleaseArmored(releaseClaims, priv, WithSignerKeyID("rel-key-1"))
	if err != nil {
		t.Fatalf("SignReleaseArmored failed: %v", err)
	}

	ring := license.NewKeyRing(pub)
	verified, _, err := license.VerifyRelease(token, ring)
	if err != nil {
		t.Fatalf("VerifyRelease failed: %v", err)
	}

	if verified.Product != "gitlab-fleet-governor" {
		t.Errorf("product mismatch: got %s", verified.Product)
	}
}

func TestIssuer_SignReleaseCompact(t *testing.T) {
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	releaseClaims := license.ReleaseClaims{
		Product:     "otel-aws-log-processor",
		Version:     "v2.0.0",
		BuildDate:   time.Now().UTC(),
		ReleaseDate: time.Now().UTC(),
	}

	token, err := SignRelease(releaseClaims, priv, WithSignerKeyID("rel-compact-1"))
	if err != nil {
		t.Fatalf("SignRelease failed: %v", err)
	}

	ring := license.NewKeyRing(pub)
	verified, _, err := license.VerifyRelease(token, ring)
	if err != nil {
		t.Fatalf("VerifyRelease failed: %v", err)
	}

	if verified.Product != "otel-aws-log-processor" {
		t.Errorf("product mismatch: got %s", verified.Product)
	}
}

func TestIssuer_SignerMethodsAndErrors(t *testing.T) {
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	// Invalid private key size
	if _, err := NewSigner([]byte("too-short")); err == nil {
		t.Error("expected error for short private key, got nil")
	}

	// PEM encoding round-trip via NewSignerFromPEM
	pemBytes, err := EncodePrivateKeyToPEM(priv)
	if err != nil {
		t.Fatal(err)
	}
	signerFromPEM, err := NewSignerFromPEM(pemBytes, WithSignerKeyID("pem-kid"))
	if err != nil {
		t.Fatalf("NewSignerFromPEM failed: %v", err)
	}

	// Test NewSignerFromPEMFile
	tmpDir := t.TempDir()
	pemFile := filepath.Join(tmpDir, "priv.pem")
	if err := SavePrivateKeyToPEMFile(priv, pemFile, 0600); err != nil {
		t.Fatal(err)
	}
	signerFromFile, err := NewSignerFromPEMFile(pemFile)
	if err != nil {
		t.Fatalf("NewSignerFromPEMFile failed: %v", err)
	}

	// Test WithKeyID
	signerWithKID := signerFromFile.WithKeyID("custom-kid")

	// Missing customer
	_, err = signerFromPEM.Sign(license.Claims{Product: "my-prod"})
	if err == nil {
		t.Error("expected error for empty customer name, got nil")
	}

	// Missing product
	_, err = signerFromPEM.Sign(license.Claims{Customer: license.Customer{Name: "Acme"}})
	if err == nil {
		t.Error("expected error for empty product name, got nil")
	}

	// Valid claims with SignArmored
	claims := license.Claims{
		Customer: license.Customer{Name: "Acme Corp"},
		Product:  "gitlab-fleet-governor",
	}
	armoredToken, err := signerWithKID.SignArmored(claims)
	if err != nil {
		t.Fatalf("SignArmored failed: %v", err)
	}

	validator, err := license.NewValidator(pub, license.WithProduct("gitlab-fleet-governor"))
	if err != nil {
		t.Fatal(err)
	}
	vRes, err := validator.Verify(armoredToken)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if vRes.KeyID != "custom-kid" {
		t.Errorf("expected KeyID custom-kid, got %s", vRes.KeyID)
	}

	// Test SignToFile
	outFileArmored := filepath.Join(tmpDir, "license.armored")
	if err := signerWithKID.SignToFile(claims, outFileArmored, true); err != nil {
		t.Fatalf("SignToFile (armored) failed: %v", err)
	}
	outFileCompact := filepath.Join(tmpDir, "license.compact")
	if err := signerWithKID.SignToFile(claims, outFileCompact, false); err != nil {
		t.Fatalf("SignToFile (compact) failed: %v", err)
	}

	// Verify from files
	if _, err := validator.VerifyFromFile(outFileArmored); err != nil {
		t.Fatalf("VerifyFromFile (armored) failed: %v", err)
	}
	if _, err := validator.VerifyFromFile(outFileCompact); err != nil {
		t.Fatalf("VerifyFromFile (compact) failed: %v", err)
	}
}

func TestIssuer_ErrorBranches(t *testing.T) {
	_, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	// 1. EncodePrivateKeyToPEM with nil / empty
	if _, err := EncodePrivateKeyToPEM(nil); err == nil {
		t.Error("expected error for nil private key")
	}

	// 2. ParsePrivateKeyFromPEM with non-PEM bytes
	if _, err := ParsePrivateKeyFromPEM([]byte("not a pem")); err == nil {
		t.Error("expected error for invalid PEM bytes")
	}

	// 3. ParsePrivateKeyFromPEM with non-PKCS8 DER bytes
	invalidBlock := &pem.Block{Type: PEMTypePrivateKey, Bytes: []byte("invalid-der")}
	if _, err := ParsePrivateKeyFromPEM(pem.EncodeToMemory(invalidBlock)); err == nil {
		t.Error("expected error for invalid PKCS#8 DER")
	}

	// 4. SavePrivateKeyToPEMFile with nil key
	tmpDir := t.TempDir()
	if err := SavePrivateKeyToPEMFile(nil, filepath.Join(tmpDir, "bad.pem"), 0600); err == nil {
		t.Error("expected error for SavePrivateKeyToPEMFile with nil key")
	}

	// 5. LoadPrivateKeyFromPEMFile with non-existent file
	if _, err := LoadPrivateKeyFromPEMFile(filepath.Join(tmpDir, "missing.pem")); err == nil {
		t.Error("expected error for LoadPrivateKeyFromPEMFile with missing file")
	}

	// 6. NewSignerFromPEM with invalid PEM
	if _, err := NewSignerFromPEM([]byte("bad pem")); err == nil {
		t.Error("expected error for NewSignerFromPEM with bad pem")
	}

	// 7. NewSignerFromPEMFile with non-existent file
	if _, err := NewSignerFromPEMFile(filepath.Join(tmpDir, "missing.pem")); err == nil {
		t.Error("expected error for NewSignerFromPEMFile with missing file")
	}

	// 8. SignRelease with nil private key
	relClaims := license.ReleaseClaims{
		Product:     "test",
		Version:     "v1.0.0",
		BuildDate:   time.Now(),
		ReleaseDate: time.Now(),
	}
	if _, err := SignRelease(relClaims, nil); err == nil {
		t.Error("expected error for SignRelease with nil key")
	}

	// 9. SignRelease with invalid claims
	if _, err := SignRelease(license.ReleaseClaims{}, priv); err == nil {
		t.Error("expected error for SignRelease with empty claims")
	}

	// 10. SignReleaseArmored with invalid claims
	if _, err := SignReleaseArmored(license.ReleaseClaims{}, priv); err == nil {
		t.Error("expected error for SignReleaseArmored with empty claims")
	}

	// 11. Signer with nil private key
	nilSigner := &Signer{}
	validClaims := license.Claims{
		Customer: license.Customer{Name: "Acme Corp"},
		Product:  "test-prod",
	}
	if _, err := nilSigner.Sign(validClaims); err == nil {
		t.Error("expected error for Signer.Sign with nil key")
	}

	// 12. Signer.Sign with invalid schema
	signer, err := NewSigner(priv)
	if err != nil {
		t.Fatal(err)
	}
	invalidSchemaClaims := license.Claims{
		Customer: license.Customer{Name: "Acme Corp", Email: "not-an-email"},
		Product:  "test-prod",
	}
	if _, err := signer.Sign(invalidSchemaClaims); err == nil {
		t.Error("expected error for invalid schema email")
	}
}
