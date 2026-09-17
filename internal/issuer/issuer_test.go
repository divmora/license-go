package issuer

import (
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
